package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"api-gateway/domain/entity"
)

// RateLimitMiddleware handles rate limiting and throttling
type RateLimitMiddleware struct {
	logger      *zap.Logger
	redisClient *redis.Client
	
	// In-memory rate limiters for when Redis is not available
	limiters    map[string]*rate.Limiter
	limitersMu  sync.RWMutex
	
	// Configuration
	fallbackToMemory bool
	cleanupInterval  time.Duration
	
	// Metrics
	requestsBlocked  int64
	requestsAllowed  int64
}

// RateLimitResult represents the result of rate limit check
type RateLimitResult struct {
	Allowed         bool          `json:"allowed"`
	Limit           int           `json:"limit"`
	Remaining       int           `json:"remaining"`
	ResetTime       time.Time     `json:"reset_time"`
	RetryAfter      time.Duration `json:"retry_after"`
	WindowRemaining time.Duration `json:"window_remaining"`
}

// RateLimitKey represents a rate limit key with metadata
type RateLimitKey struct {
	Key        string            `json:"key"`
	Identifier string            `json:"identifier"`
	Type       string            `json:"type"`
	Route      string            `json:"route"`
	Metadata   map[string]string `json:"metadata"`
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(logger *zap.Logger, redisClient *redis.Client) *RateLimitMiddleware {
	middleware := &RateLimitMiddleware{
		logger:           logger,
		redisClient:      redisClient,
		limiters:         make(map[string]*rate.Limiter),
		fallbackToMemory: true,
		cleanupInterval:  5 * time.Minute,
	}

	// Start cleanup goroutine for in-memory limiters
	go middleware.cleanupLimiters()

	return middleware
}

// RateLimitRoute creates rate limiting middleware for a specific route
func (m *RateLimitMiddleware) RateLimitRoute(route *entity.Route) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip rate limiting if not configured
		if route.RateLimit == nil {
			c.Next()
			return
		}

		// Extract rate limit key
		rateLimitKey, err := m.extractRateLimitKey(c, route)
		if err != nil {
			m.logger.Error("Failed to extract rate limit key",
				zap.String("route", route.Name),
				zap.Error(err),
			)
			// Continue without rate limiting on key extraction error
			c.Next()
			return
		}

		// Check rate limit
		result, err := m.checkRateLimit(c, rateLimitKey, route.RateLimit)
		if err != nil {
			m.logger.Error("Rate limit check failed",
				zap.String("route", route.Name),
				zap.String("key", rateLimitKey.Key),
				zap.Error(err),
			)
			// Continue without rate limiting on check error
			c.Next()
			return
		}

		// Set rate limit headers
		m.setRateLimitHeaders(c, result)

		// Block request if rate limit exceeded
		if !result.Allowed {
			m.requestsBlocked++
			m.logger.Warn("Request blocked by rate limit",
				zap.String("route", route.Name),
				zap.String("key", rateLimitKey.Key),
				zap.String("identifier", rateLimitKey.Identifier),
				zap.Int("limit", result.Limit),
				zap.Int("remaining", result.Remaining),
			)

			errorMessage := "Rate limit exceeded"
			if route.RateLimit.ErrorMessage != "" {
				errorMessage = route.RateLimit.ErrorMessage
			}

			statusCode := http.StatusTooManyRequests
			if route.RateLimit.ErrorCode != 0 {
				statusCode = route.RateLimit.ErrorCode
			}

			c.JSON(statusCode, gin.H{
				"error":         "Rate Limit Exceeded",
				"message":       errorMessage,
				"code":          "RATE_LIMIT_001",
				"limit":         result.Limit,
				"remaining":     result.Remaining,
				"reset_time":    result.ResetTime.Unix(),
				"retry_after":   int(result.RetryAfter.Seconds()),
			})
			c.Abort()
			return
		}

		m.requestsAllowed++
		m.logger.Debug("Request allowed by rate limit",
			zap.String("route", route.Name),
			zap.String("key", rateLimitKey.Key),
			zap.Int("remaining", result.Remaining),
		)

		c.Next()
	}
}

// extractRateLimitKey extracts the rate limiting key from the request
func (m *RateLimitMiddleware) extractRateLimitKey(c *gin.Context, route *entity.Route) (*RateLimitKey, error) {
	var identifier string
	var keyType string

	switch route.RateLimit.KeyExtractor {
	case "ip":
		identifier = c.ClientIP()
		keyType = "ip"
		
	case "user":
		if authCtx, exists := GetAuthContext(c); exists && authCtx.Authenticated {
			identifier = authCtx.UserID
			keyType = "user"
		} else {
			// Fallback to IP if user not authenticated
			identifier = c.ClientIP()
			keyType = "ip"
		}
		
	case "api_key":
		if authCtx, exists := GetAuthContext(c); exists && authCtx.APIKey != nil {
			identifier = authCtx.APIKey.Key
			keyType = "api_key"
		} else {
			// Fallback to IP if API key not present
			identifier = c.ClientIP()
			keyType = "ip"
		}
		
	case "custom":
		if route.RateLimit.CustomKeyHeader != "" {
			identifier = c.GetHeader(route.RateLimit.CustomKeyHeader)
			keyType = "custom"
		}
		if identifier == "" {
			// Fallback to IP if custom header not present
			identifier = c.ClientIP()
			keyType = "ip"
		}
		
	case "tenant":
		if authCtx, exists := GetAuthContext(c); exists && authCtx.TenantID != "" {
			identifier = authCtx.TenantID
			keyType = "tenant"
		} else {
			// Fallback to IP if tenant not available
			identifier = c.ClientIP()
			keyType = "ip"
		}
		
	default:
		identifier = c.ClientIP()
		keyType = "ip"
	}

	if identifier == "" {
		return nil, fmt.Errorf("unable to extract rate limit identifier")
	}

	// Create rate limit key
	key := fmt.Sprintf("ratelimit:%s:%s:%s", route.Name, keyType, identifier)

	return &RateLimitKey{
		Key:        key,
		Identifier: identifier,
		Type:       keyType,
		Route:      route.Name,
		Metadata: map[string]string{
			"route":      route.Name,
			"key_type":   keyType,
			"identifier": identifier,
		},
	}, nil
}

// checkRateLimit checks if the request should be allowed based on rate limits
func (m *RateLimitMiddleware) checkRateLimit(c *gin.Context, key *RateLimitKey, config *entity.RateLimitConfig) (*RateLimitResult, error) {
	// Try Redis-based rate limiting first
	if m.redisClient != nil {
		result, err := m.checkRedisRateLimit(c, key, config)
		if err == nil {
			return result, nil
		}
		
		m.logger.Warn("Redis rate limiting failed, falling back to memory",
			zap.String("key", key.Key),
			zap.Error(err),
		)
	}

	// Fallback to in-memory rate limiting
	if m.fallbackToMemory {
		return m.checkMemoryRateLimit(key, config), nil
	}

	return nil, fmt.Errorf("rate limiting not available")
}

// checkRedisRateLimit implements Redis-based sliding window rate limiting
func (m *RateLimitMiddleware) checkRedisRateLimit(c *gin.Context, key *RateLimitKey, config *entity.RateLimitConfig) (*RateLimitResult, error) {
	ctx := c.Request.Context()
	now := time.Now()
	windowStart := now.Add(-config.WindowSize)

	// Use Redis sorted set for sliding window
	pipe := m.redisClient.Pipeline()

	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, key.Key, "0", strconv.FormatInt(windowStart.UnixNano(), 10))

	// Count current requests in window
	countCmd := pipe.ZCard(ctx, key.Key)

	// Add current request
	pipe.ZAdd(ctx, key.Key, &redis.Z{
		Score:  float64(now.UnixNano()),
		Member: fmt.Sprintf("%d-%s", now.UnixNano(), c.GetHeader("X-Request-ID")),
	})

	// Set expiration for cleanup
	pipe.Expire(ctx, key.Key, config.WindowSize+time.Minute)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("Redis pipeline failed: %w", err)
	}

	currentCount := countCmd.Val()
	limit := int64(config.RequestsPerSecond) * int64(config.WindowSize.Seconds())

	// Check if limit exceeded (account for burst)
	effectiveLimit := limit + int64(config.BurstSize)
	allowed := currentCount <= effectiveLimit

	// Calculate reset time (next window)
	resetTime := now.Add(config.WindowSize)
	remaining := int(effectiveLimit - currentCount)
	if remaining < 0 {
		remaining = 0
	}

	retryAfter := time.Duration(0)
	if !allowed {
		// Calculate when the oldest request in window will expire
		oldestCmd := m.redisClient.ZRange(ctx, key.Key, 0, 0)
		if len(oldestCmd.Val()) > 0 {
			if oldest := oldestCmd.Val()[0]; oldest != "" {
				if parts := strings.Split(oldest, "-"); len(parts) > 0 {
					if oldestTime, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
						oldestRequestTime := time.Unix(0, oldestTime)
						retryAfter = oldestRequestTime.Add(config.WindowSize).Sub(now)
						if retryAfter < 0 {
							retryAfter = time.Second
						}
					}
				}
			}
		}
		if retryAfter == 0 {
			retryAfter = config.WindowSize
		}
	}

	return &RateLimitResult{
		Allowed:         allowed,
		Limit:           int(effectiveLimit),
		Remaining:       remaining,
		ResetTime:       resetTime,
		RetryAfter:      retryAfter,
		WindowRemaining: config.WindowSize - time.Since(windowStart),
	}, nil
}

// checkMemoryRateLimit implements in-memory token bucket rate limiting
func (m *RateLimitMiddleware) checkMemoryRateLimit(key *RateLimitKey, config *entity.RateLimitConfig) *RateLimitResult {
	m.limitersMu.Lock()
	defer m.limitersMu.Unlock()

	// Get or create limiter for this key
	limiter, exists := m.limiters[key.Key]
	if !exists {
		// Create token bucket limiter
		// Rate: requests per second, Burst: burst size
		limiter = rate.NewLimiter(rate.Limit(config.RequestsPerSecond), config.BurstSize)
		m.limiters[key.Key] = limiter
	}

	// Check if request is allowed
	allowed := limiter.Allow()
	
	// Calculate remaining tokens (approximate)
	burst := limiter.Burst()
	tokens := int(limiter.Tokens())
	
	resetTime := time.Now().Add(time.Second) // Approximate reset time
	retryAfter := time.Duration(0)
	
	if !allowed {
		// Calculate retry after based on token refill rate
		retryAfter = time.Duration(float64(time.Second) / float64(config.RequestsPerSecond))
	}

	return &RateLimitResult{
		Allowed:         allowed,
		Limit:           burst,
		Remaining:       tokens,
		ResetTime:       resetTime,
		RetryAfter:      retryAfter,
		WindowRemaining: time.Second, // Token bucket refills continuously
	}
}

// setRateLimitHeaders sets standard rate limiting headers
func (m *RateLimitMiddleware) setRateLimitHeaders(c *gin.Context, result *RateLimitResult) {
	c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
	
	if !result.Allowed {
		c.Header("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
	}
}

// cleanupLimiters periodically cleans up unused in-memory limiters
func (m *RateLimitMiddleware) cleanupLimiters() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.limitersMu.Lock()
		
		// In a production implementation, you would track last access time
		// and remove limiters that haven't been used recently
		// For now, we'll keep all limiters to maintain rate limiting state
		
		m.logger.Debug("Rate limiter cleanup",
			zap.Int("active_limiters", len(m.limiters)),
		)
		
		m.limitersMu.Unlock()
	}
}

// GetMetrics returns rate limiting metrics
func (m *RateLimitMiddleware) GetMetrics() map[string]interface{} {
	m.limitersMu.RLock()
	defer m.limitersMu.RUnlock()

	return map[string]interface{}{
		"requests_allowed":    m.requestsAllowed,
		"requests_blocked":    m.requestsBlocked,
		"active_limiters":     len(m.limiters),
		"redis_available":     m.redisClient != nil,
		"fallback_to_memory":  m.fallbackToMemory,
	}
}

// ResetLimiter resets the rate limiter for a specific key
func (m *RateLimitMiddleware) ResetLimiter(key string) error {
	// Reset Redis limiter
	if m.redisClient != nil {
		ctx := context.Background()
		err := m.redisClient.Del(ctx, key).Err()
		if err != nil {
			m.logger.Error("Failed to reset Redis rate limiter",
				zap.String("key", key),
				zap.Error(err),
			)
		}
	}

	// Reset in-memory limiter
	m.limitersMu.Lock()
	delete(m.limiters, key)
	m.limitersMu.Unlock()

	m.logger.Info("Rate limiter reset", zap.String("key", key))
	return nil
}

// SetLimiterConfig updates the configuration for rate limiting
func (m *RateLimitMiddleware) SetLimiterConfig(fallbackToMemory bool, cleanupInterval time.Duration) {
	m.fallbackToMemory = fallbackToMemory
	m.cleanupInterval = cleanupInterval
}

// GlobalRateLimit creates a global rate limiting middleware
func (m *RateLimitMiddleware) GlobalRateLimit(requestsPerSecond int, burstSize int, windowSize time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		config := &entity.RateLimitConfig{
			RequestsPerSecond: requestsPerSecond,
			BurstSize:         burstSize,
			WindowSize:        windowSize,
			KeyExtractor:      "ip",
		}

		key := &RateLimitKey{
			Key:        fmt.Sprintf("global:ratelimit:ip:%s", c.ClientIP()),
			Identifier: c.ClientIP(),
			Type:       "ip",
			Route:      "global",
		}

		result, err := m.checkRateLimit(c, key, config)
		if err != nil {
			m.logger.Error("Global rate limit check failed", zap.Error(err))
			c.Next()
			return
		}

		m.setRateLimitHeaders(c, result)

		if !result.Allowed {
			m.requestsBlocked++
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate Limit Exceeded",
				"message":     "Global rate limit exceeded",
				"code":        "RATE_LIMIT_GLOBAL",
				"limit":       result.Limit,
				"remaining":   result.Remaining,
				"reset_time":  result.ResetTime.Unix(),
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			c.Abort()
			return
		}

		m.requestsAllowed++
		c.Next()
	}
}

// PerUserRateLimit creates a per-user rate limiting middleware
func (m *RateLimitMiddleware) PerUserRateLimit(requestsPerSecond int, burstSize int, windowSize time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := GetAuthContext(c)
		if !exists || !authCtx.Authenticated {
			// Skip rate limiting for unauthenticated users
			c.Next()
			return
		}

		config := &entity.RateLimitConfig{
			RequestsPerSecond: requestsPerSecond,
			BurstSize:         burstSize,
			WindowSize:        windowSize,
			KeyExtractor:      "user",
		}

		key := &RateLimitKey{
			Key:        fmt.Sprintf("user:ratelimit:%s", authCtx.UserID),
			Identifier: authCtx.UserID,
			Type:       "user",
			Route:      "per_user",
		}

		result, err := m.checkRateLimit(c, key, config)
		if err != nil {
			m.logger.Error("Per-user rate limit check failed", zap.Error(err))
			c.Next()
			return
		}

		m.setRateLimitHeaders(c, result)

		if !result.Allowed {
			m.requestsBlocked++
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate Limit Exceeded",
				"message":     "Per-user rate limit exceeded",
				"code":        "RATE_LIMIT_USER",
				"limit":       result.Limit,
				"remaining":   result.Remaining,
				"reset_time":  result.ResetTime.Unix(),
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			c.Abort()
			return
		}

		m.requestsAllowed++
		c.Next()
	}
}

// GetLimiterStatus returns the current status of a rate limiter
func (m *RateLimitMiddleware) GetLimiterStatus(key string) (*RateLimitResult, error) {
	// For in-memory limiters
	m.limitersMu.RLock()
	limiter, exists := m.limiters[key]
	m.limitersMu.RUnlock()

	if exists {
		burst := limiter.Burst()
		tokens := int(limiter.Tokens())
		
		return &RateLimitResult{
			Allowed:   tokens > 0,
			Limit:     burst,
			Remaining: tokens,
			ResetTime: time.Now().Add(time.Second),
		}, nil
	}

	// For Redis limiters, we would need to query Redis
	if m.redisClient != nil {
		ctx := context.Background()
		count, err := m.redisClient.ZCard(ctx, key).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to get Redis limiter status: %w", err)
		}

		return &RateLimitResult{
			Allowed:   true, // Simplified
			Limit:     100,  // Would need to be stored/calculated
			Remaining: 100 - int(count),
			ResetTime: time.Now().Add(time.Minute),
		}, nil
	}

	return nil, fmt.Errorf("limiter not found: %s", key)
}