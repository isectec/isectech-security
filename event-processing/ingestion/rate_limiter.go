package ingestion

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RateLimitingService provides comprehensive rate limiting for event ingestion in iSECTECH
type RateLimitingService struct {
	config *RateLimitConfig
	logger *zap.Logger

	// Rate limiters by scope
	globalLimiter    *TokenBucket
	tenantLimiters   map[string]*TokenBucket
	sourceLimiters   map[string]*TokenBucket
	ipLimiters       map[string]*TokenBucket
	endpointLimiters map[string]*TokenBucket

	// Adaptive rate limiting
	adaptiveLimiters map[string]*AdaptiveRateLimiter

	// State management
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker
	metricsTicker *time.Ticker
	shutdownCh    chan struct{}

	// Metrics and monitoring
	metrics     *RateLimitMetrics
	lastCleanup time.Time
}

// RateLimitConfig defines comprehensive rate limiting configuration
type RateLimitConfig struct {
	// Global Rate Limiting
	GlobalLimit *RateLimitRule `json:"global_limit"`

	// Tenant-specific Rate Limiting
	TenantLimits       map[string]*RateLimitRule `json:"tenant_limits,omitempty"`
	DefaultTenantLimit *RateLimitRule            `json:"default_tenant_limit"`

	// Source-based Rate Limiting
	SourceLimits       map[string]*RateLimitRule `json:"source_limits,omitempty"`
	DefaultSourceLimit *RateLimitRule            `json:"default_source_limit"`

	// IP-based Rate Limiting
	IPLimits       map[string]*RateLimitRule `json:"ip_limits,omitempty"`
	DefaultIPLimit *RateLimitRule            `json:"default_ip_limit"`
	IPRangeLimits  []*IPRangeLimit           `json:"ip_range_limits,omitempty"`

	// Endpoint-specific Rate Limiting
	EndpointLimits       map[string]*RateLimitRule `json:"endpoint_limits,omitempty"`
	DefaultEndpointLimit *RateLimitRule            `json:"default_endpoint_limit"`

	// Adaptive Rate Limiting
	AdaptiveEnabled bool            `json:"adaptive_enabled"` // Default: true
	AdaptiveConfig  *AdaptiveConfig `json:"adaptive_config,omitempty"`

	// Burst and Window Settings
	DefaultBurstRatio float64       `json:"default_burst_ratio"` // Default: 0.1 (10% of rate)
	WindowSize        time.Duration `json:"window_size"`         // Default: 1m
	SlidingWindow     bool          `json:"sliding_window"`      // Default: true

	// Cleanup and Maintenance
	CleanupInterval time.Duration `json:"cleanup_interval"` // Default: 5m
	IdleTimeout     time.Duration `json:"idle_timeout"`     // Default: 1h
	MaxLimiters     int           `json:"max_limiters"`     // Default: 10000

	// Rate Limit Actions
	DefaultAction RateLimitAction            `json:"default_action"` // block, throttle, monitor
	CustomActions map[string]RateLimitAction `json:"custom_actions,omitempty"`

	// Headers and Response
	IncludeHeaders bool   `json:"include_headers"` // Default: true
	HeaderPrefix   string `json:"header_prefix"`   // Default: X-RateLimit-

	// Monitoring and Metrics
	MetricsEnabled  bool             `json:"metrics_enabled"`  // Default: true
	MetricsInterval time.Duration    `json:"metrics_interval"` // Default: 30s
	AlertThresholds *AlertThresholds `json:"alert_thresholds,omitempty"`
}

// RateLimitRule defines a rate limiting rule
type RateLimitRule struct {
	RequestsPerSecond float64           `json:"requests_per_second"`
	BurstSize         int64             `json:"burst_size"`
	WindowSize        time.Duration     `json:"window_size"`
	Action            RateLimitAction   `json:"action"`
	Priority          int               `json:"priority"` // Higher priority rules are checked first
	Enabled           bool              `json:"enabled"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// IPRangeLimit defines rate limiting for IP ranges
type IPRangeLimit struct {
	CIDR        string         `json:"cidr"`
	Rule        *RateLimitRule `json:"rule"`
	Description string         `json:"description,omitempty"`
}

// AdaptiveConfig defines adaptive rate limiting configuration
type AdaptiveConfig struct {
	BaseLearningPeriod    time.Duration `json:"base_learning_period"`    // Default: 1h
	ResponseTimeThreshold time.Duration `json:"response_time_threshold"` // Default: 500ms
	ErrorRateThreshold    float64       `json:"error_rate_threshold"`    // Default: 0.05 (5%)
	CPUThreshold          float64       `json:"cpu_threshold"`           // Default: 0.8 (80%)
	MemoryThreshold       float64       `json:"memory_threshold"`        // Default: 0.8 (80%)
	AdjustmentFactor      float64       `json:"adjustment_factor"`       // Default: 0.1 (10%)
	MinRate               float64       `json:"min_rate"`                // Default: 1.0
	MaxRate               float64       `json:"max_rate"`                // Default: 10000.0
	ReactionTime          time.Duration `json:"reaction_time"`           // Default: 30s
}

// AlertThresholds defines alerting thresholds
type AlertThresholds struct {
	HighUsagePercent     float64       `json:"high_usage_percent"`     // Default: 80%
	CriticalUsagePercent float64       `json:"critical_usage_percent"` // Default: 95%
	SustainedHighUsage   time.Duration `json:"sustained_high_usage"`   // Default: 5m
	BlockedRequestsRate  float64       `json:"blocked_requests_rate"`  // Default: 100/min
}

// RateLimitAction defines actions to take when rate limit is exceeded
type RateLimitAction string

const (
	ActionBlock    RateLimitAction = "block"    // Reject the request
	ActionThrottle RateLimitAction = "throttle" // Delay the request
	ActionMonitor  RateLimitAction = "monitor"  // Log but allow the request
	ActionAdaptive RateLimitAction = "adaptive" // Use adaptive rate limiting
)

// TokenBucket implements the token bucket rate limiting algorithm
type TokenBucket struct {
	capacity     int64
	tokens       int64
	refillRate   float64
	lastRefill   time.Time
	burstAllowed bool
	rule         *RateLimitRule
	mutex        sync.Mutex

	// Statistics
	totalRequests   int64
	allowedRequests int64
	blockedRequests int64
	lastRequest     time.Time
}

// AdaptiveRateLimiter implements adaptive rate limiting based on system conditions
type AdaptiveRateLimiter struct {
	config         *AdaptiveConfig
	currentRate    float64
	baseRate       float64
	lastAdjustment time.Time
	responseTime   time.Duration
	errorRate      float64
	systemMetrics  *SystemMetrics

	// Learning phase
	learningPhase bool
	learningStart time.Time
	samples       []float64

	mutex sync.RWMutex
}

// SystemMetrics tracks system performance for adaptive rate limiting
type SystemMetrics struct {
	CPUUsage       float64       `json:"cpu_usage"`
	MemoryUsage    float64       `json:"memory_usage"`
	ResponseTime   time.Duration `json:"response_time"`
	ErrorRate      float64       `json:"error_rate"`
	QueueDepth     int           `json:"queue_depth"`
	ActiveRequests int           `json:"active_requests"`
	LastUpdate     time.Time     `json:"last_update"`
}

// RateLimitMetrics tracks rate limiting performance and usage
type RateLimitMetrics struct {
	// Request statistics
	TotalRequests     int64 `json:"total_requests"`
	AllowedRequests   int64 `json:"allowed_requests"`
	BlockedRequests   int64 `json:"blocked_requests"`
	ThrottledRequests int64 `json:"throttled_requests"`

	// Rate limiting effectiveness
	BlockRate         float64 `json:"block_rate"`
	RequestsPerSecond float64 `json:"requests_per_second"`

	// Limiter usage
	ActiveLimiters   int `json:"active_limiters"`
	TenantLimiters   int `json:"tenant_limiters"`
	IPLimiters       int `json:"ip_limiters"`
	SourceLimiters   int `json:"source_limiters"`
	EndpointLimiters int `json:"endpoint_limiters"`

	// Top rate limited entities
	TopBlockedTenants []string `json:"top_blocked_tenants"`
	TopBlockedIPs     []string `json:"top_blocked_ips"`
	TopBlockedSources []string `json:"top_blocked_sources"`

	// Adaptive rate limiting
	AdaptiveLimiters int     `json:"adaptive_limiters"`
	AvgAdaptiveRate  float64 `json:"avg_adaptive_rate"`

	// Performance impact
	AvgDecisionTime time.Duration `json:"avg_decision_time"`
	MemoryUsage     int64         `json:"memory_usage"`

	mutex      sync.RWMutex
	lastUpdate time.Time
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed         bool                   `json:"allowed"`
	Action          RateLimitAction        `json:"action"`
	Reason          string                 `json:"reason"`
	RetryAfter      time.Duration          `json:"retry_after,omitempty"`
	RemainingTokens int64                  `json:"remaining_tokens"`
	ResetTime       time.Time              `json:"reset_time"`
	Headers         map[string]string      `json:"headers,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// RateLimitRequest represents a rate limit check request
type RateLimitRequest struct {
	TenantID    string                 `json:"tenant_id"`
	SourceID    string                 `json:"source_id,omitempty"`
	ClientIP    string                 `json:"client_ip,omitempty"`
	Endpoint    string                 `json:"endpoint,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	RequestSize int64                  `json:"request_size,omitempty"`
	Priority    int                    `json:"priority,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewRateLimitingService creates a new rate limiting service
func NewRateLimitingService(config *RateLimitConfig, logger *zap.Logger) (*RateLimitingService, error) {
	if err := validateRateLimitConfig(config); err != nil {
		return nil, fmt.Errorf("invalid rate limit configuration: %w", err)
	}

	setRateLimitDefaults(config)

	service := &RateLimitingService{
		config:           config,
		logger:           logger,
		tenantLimiters:   make(map[string]*TokenBucket),
		sourceLimiters:   make(map[string]*TokenBucket),
		ipLimiters:       make(map[string]*TokenBucket),
		endpointLimiters: make(map[string]*TokenBucket),
		adaptiveLimiters: make(map[string]*AdaptiveRateLimiter),
		shutdownCh:       make(chan struct{}),
		metrics:          NewRateLimitMetrics(),
		lastCleanup:      time.Now(),
	}

	// Initialize global limiter
	if config.GlobalLimit != nil {
		service.globalLimiter = NewTokenBucket(config.GlobalLimit)
	}

	return service, nil
}

// Start initializes and starts the rate limiting service
func (rls *RateLimitingService) Start(ctx context.Context) error {
	rls.logger.Info("Starting rate limiting service")

	// Start cleanup routine
	rls.cleanupTicker = time.NewTicker(rls.config.CleanupInterval)
	go rls.cleanupRoutine()

	// Start metrics routine
	if rls.config.MetricsEnabled {
		rls.metricsTicker = time.NewTicker(rls.config.MetricsInterval)
		go rls.metricsRoutine()
	}

	rls.logger.Info("Rate limiting service started successfully")
	return nil
}

// Stop gracefully shuts down the rate limiting service
func (rls *RateLimitingService) Stop(ctx context.Context) error {
	rls.logger.Info("Stopping rate limiting service")

	close(rls.shutdownCh)

	if rls.cleanupTicker != nil {
		rls.cleanupTicker.Stop()
	}
	if rls.metricsTicker != nil {
		rls.metricsTicker.Stop()
	}

	rls.logger.Info("Rate limiting service stopped successfully")
	return nil
}

// CheckRateLimit checks if a request should be allowed based on rate limits
func (rls *RateLimitingService) CheckRateLimit(ctx context.Context, request *RateLimitRequest) *RateLimitResult {
	startTime := time.Now()
	defer func() {
		rls.updateDecisionTime(time.Since(startTime))
	}()

	// Increment total requests
	rls.incrementCounter("total_requests")

	// Check global rate limit first
	if rls.globalLimiter != nil {
		if result := rls.checkLimiter(rls.globalLimiter, "global"); !result.Allowed {
			rls.incrementCounter("blocked_requests")
			result.Reason = "Global rate limit exceeded"
			return result
		}
	}

	// Check tenant-specific rate limit
	if request.TenantID != "" {
		limiter := rls.getTenantLimiter(request.TenantID)
		if result := rls.checkLimiter(limiter, "tenant"); !result.Allowed {
			rls.incrementCounter("blocked_requests")
			result.Reason = fmt.Sprintf("Tenant rate limit exceeded: %s", request.TenantID)
			return result
		}
	}

	// Check source-specific rate limit
	if request.SourceID != "" {
		limiter := rls.getSourceLimiter(request.SourceID)
		if result := rls.checkLimiter(limiter, "source"); !result.Allowed {
			rls.incrementCounter("blocked_requests")
			result.Reason = fmt.Sprintf("Source rate limit exceeded: %s", request.SourceID)
			return result
		}
	}

	// Check IP-based rate limit
	if request.ClientIP != "" {
		limiter := rls.getIPLimiter(request.ClientIP)
		if result := rls.checkLimiter(limiter, "ip"); !result.Allowed {
			rls.incrementCounter("blocked_requests")
			result.Reason = fmt.Sprintf("IP rate limit exceeded: %s", request.ClientIP)
			return result
		}
	}

	// Check endpoint-specific rate limit
	if request.Endpoint != "" {
		limiter := rls.getEndpointLimiter(request.Endpoint)
		if result := rls.checkLimiter(limiter, "endpoint"); !result.Allowed {
			rls.incrementCounter("blocked_requests")
			result.Reason = fmt.Sprintf("Endpoint rate limit exceeded: %s", request.Endpoint)
			return result
		}
	}

	// Check adaptive rate limiting
	if rls.config.AdaptiveEnabled && request.TenantID != "" {
		adaptiveLimiter := rls.getAdaptiveLimiter(request.TenantID)
		if !adaptiveLimiter.Allow() {
			rls.incrementCounter("blocked_requests")
			return &RateLimitResult{
				Allowed: false,
				Action:  ActionAdaptive,
				Reason:  "Adaptive rate limit triggered",
			}
		}
	}

	// Request is allowed
	rls.incrementCounter("allowed_requests")

	result := &RateLimitResult{
		Allowed: true,
		Action:  ActionMonitor,
		Reason:  "Request allowed",
	}

	// Add headers if configured
	if rls.config.IncludeHeaders {
		result.Headers = rls.generateHeaders(request)
	}

	return result
}

// UpdateSystemMetrics updates system metrics for adaptive rate limiting
func (rls *RateLimitingService) UpdateSystemMetrics(metrics *SystemMetrics) {
	if !rls.config.AdaptiveEnabled {
		return
	}

	rls.mutex.Lock()
	defer rls.mutex.Unlock()

	// Update all adaptive limiters with new system metrics
	for _, limiter := range rls.adaptiveLimiters {
		limiter.UpdateSystemMetrics(metrics)
	}
}

// GetMetrics returns current rate limiting metrics
func (rls *RateLimitingService) GetMetrics() *RateLimitMetrics {
	rls.metrics.mutex.RLock()
	defer rls.metrics.mutex.RUnlock()

	// Create a copy
	metrics := *rls.metrics
	metrics.TopBlockedTenants = make([]string, len(rls.metrics.TopBlockedTenants))
	metrics.TopBlockedIPs = make([]string, len(rls.metrics.TopBlockedIPs))
	metrics.TopBlockedSources = make([]string, len(rls.metrics.TopBlockedSources))

	copy(metrics.TopBlockedTenants, rls.metrics.TopBlockedTenants)
	copy(metrics.TopBlockedIPs, rls.metrics.TopBlockedIPs)
	copy(metrics.TopBlockedSources, rls.metrics.TopBlockedSources)

	return &metrics
}

// Private methods

func (rls *RateLimitingService) checkLimiter(limiter *TokenBucket, limiterType string) *RateLimitResult {
	if limiter == nil {
		return &RateLimitResult{Allowed: true}
	}

	allowed := limiter.Allow()

	result := &RateLimitResult{
		Allowed:         allowed,
		RemainingTokens: limiter.RemainingTokens(),
		ResetTime:       limiter.ResetTime(),
	}

	if allowed {
		result.Action = ActionMonitor
	} else {
		result.Action = limiter.rule.Action
		result.RetryAfter = limiter.RetryAfter()
	}

	return result
}

func (rls *RateLimitingService) getTenantLimiter(tenantID string) *TokenBucket {
	rls.mutex.RLock()
	limiter, exists := rls.tenantLimiters[tenantID]
	rls.mutex.RUnlock()

	if exists {
		return limiter
	}

	rls.mutex.Lock()
	defer rls.mutex.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rls.tenantLimiters[tenantID]; exists {
		return limiter
	}

	// Create new limiter
	rule := rls.config.TenantLimits[tenantID]
	if rule == nil {
		rule = rls.config.DefaultTenantLimit
	}

	if rule != nil {
		limiter = NewTokenBucket(rule)
		rls.tenantLimiters[tenantID] = limiter
		return limiter
	}

	return nil
}

func (rls *RateLimitingService) getSourceLimiter(sourceID string) *TokenBucket {
	rls.mutex.RLock()
	limiter, exists := rls.sourceLimiters[sourceID]
	rls.mutex.RUnlock()

	if exists {
		return limiter
	}

	rls.mutex.Lock()
	defer rls.mutex.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rls.sourceLimiters[sourceID]; exists {
		return limiter
	}

	// Create new limiter
	rule := rls.config.SourceLimits[sourceID]
	if rule == nil {
		rule = rls.config.DefaultSourceLimit
	}

	if rule != nil {
		limiter = NewTokenBucket(rule)
		rls.sourceLimiters[sourceID] = limiter
		return limiter
	}

	return nil
}

func (rls *RateLimitingService) getIPLimiter(clientIP string) *TokenBucket {
	rls.mutex.RLock()
	limiter, exists := rls.ipLimiters[clientIP]
	rls.mutex.RUnlock()

	if exists {
		return limiter
	}

	rls.mutex.Lock()
	defer rls.mutex.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rls.ipLimiters[clientIP]; exists {
		return limiter
	}

	// Check IP range limits first
	var rule *RateLimitRule
	for _, ipRange := range rls.config.IPRangeLimits {
		if rls.ipInRange(clientIP, ipRange.CIDR) {
			rule = ipRange.Rule
			break
		}
	}

	// Fall back to default IP limit
	if rule == nil {
		rule = rls.config.DefaultIPLimit
	}

	if rule != nil {
		limiter = NewTokenBucket(rule)
		rls.ipLimiters[clientIP] = limiter
		return limiter
	}

	return nil
}

func (rls *RateLimitingService) getEndpointLimiter(endpoint string) *TokenBucket {
	rls.mutex.RLock()
	limiter, exists := rls.endpointLimiters[endpoint]
	rls.mutex.RUnlock()

	if exists {
		return limiter
	}

	rls.mutex.Lock()
	defer rls.mutex.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rls.endpointLimiters[endpoint]; exists {
		return limiter
	}

	// Create new limiter
	rule := rls.config.EndpointLimits[endpoint]
	if rule == nil {
		rule = rls.config.DefaultEndpointLimit
	}

	if rule != nil {
		limiter = NewTokenBucket(rule)
		rls.endpointLimiters[endpoint] = limiter
		return limiter
	}

	return nil
}

func (rls *RateLimitingService) getAdaptiveLimiter(key string) *AdaptiveRateLimiter {
	rls.mutex.RLock()
	limiter, exists := rls.adaptiveLimiters[key]
	rls.mutex.RUnlock()

	if exists {
		return limiter
	}

	rls.mutex.Lock()
	defer rls.mutex.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rls.adaptiveLimiters[key]; exists {
		return limiter
	}

	// Create new adaptive limiter
	limiter = NewAdaptiveRateLimiter(rls.config.AdaptiveConfig)
	rls.adaptiveLimiters[key] = limiter
	return limiter
}

func (rls *RateLimitingService) generateHeaders(request *RateLimitRequest) map[string]string {
	headers := make(map[string]string)
	prefix := rls.config.HeaderPrefix

	// Add general rate limit headers
	headers[prefix+"Limit"] = "1000"    // Placeholder
	headers[prefix+"Remaining"] = "999" // Placeholder
	headers[prefix+"Reset"] = fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix())

	return headers
}

func (rls *RateLimitingService) incrementCounter(counter string) {
	rls.metrics.mutex.Lock()
	defer rls.metrics.mutex.Unlock()

	switch counter {
	case "total_requests":
		rls.metrics.TotalRequests++
	case "allowed_requests":
		rls.metrics.AllowedRequests++
	case "blocked_requests":
		rls.metrics.BlockedRequests++
	case "throttled_requests":
		rls.metrics.ThrottledRequests++
	}
}

func (rls *RateLimitingService) updateDecisionTime(duration time.Duration) {
	rls.metrics.mutex.Lock()
	defer rls.metrics.mutex.Unlock()

	// Update average decision time
	total := rls.metrics.TotalRequests
	if total > 0 {
		rls.metrics.AvgDecisionTime = (rls.metrics.AvgDecisionTime*time.Duration(total-1) + duration) / time.Duration(total)
	}
}

func (rls *RateLimitingService) cleanupRoutine() {
	for {
		select {
		case <-rls.cleanupTicker.C:
			rls.performCleanup()
		case <-rls.shutdownCh:
			return
		}
	}
}

func (rls *RateLimitingService) performCleanup() {
	rls.mutex.Lock()
	defer rls.mutex.Unlock()

	now := time.Now()

	// Cleanup idle tenant limiters
	for tenantID, limiter := range rls.tenantLimiters {
		if now.Sub(limiter.lastRequest) > rls.config.IdleTimeout {
			delete(rls.tenantLimiters, tenantID)
		}
	}

	// Cleanup idle IP limiters
	for ip, limiter := range rls.ipLimiters {
		if now.Sub(limiter.lastRequest) > rls.config.IdleTimeout {
			delete(rls.ipLimiters, ip)
		}
	}

	// Cleanup idle source limiters
	for sourceID, limiter := range rls.sourceLimiters {
		if now.Sub(limiter.lastRequest) > rls.config.IdleTimeout {
			delete(rls.sourceLimiters, sourceID)
		}
	}

	// Cleanup idle endpoint limiters
	for endpoint, limiter := range rls.endpointLimiters {
		if now.Sub(limiter.lastRequest) > rls.config.IdleTimeout {
			delete(rls.endpointLimiters, endpoint)
		}
	}

	rls.lastCleanup = now

	rls.logger.Debug("Rate limiter cleanup completed",
		zap.Int("tenant_limiters", len(rls.tenantLimiters)),
		zap.Int("ip_limiters", len(rls.ipLimiters)),
		zap.Int("source_limiters", len(rls.sourceLimiters)),
		zap.Int("endpoint_limiters", len(rls.endpointLimiters)))
}

func (rls *RateLimitingService) metricsRoutine() {
	for {
		select {
		case <-rls.metricsTicker.C:
			rls.updateMetrics()
		case <-rls.shutdownCh:
			return
		}
	}
}

func (rls *RateLimitingService) updateMetrics() {
	rls.metrics.mutex.Lock()
	defer rls.metrics.mutex.Unlock()

	now := time.Now()
	duration := now.Sub(rls.metrics.lastUpdate)

	// Calculate rates
	if duration > 0 {
		rls.metrics.RequestsPerSecond = float64(rls.metrics.TotalRequests) / duration.Seconds()
		if rls.metrics.TotalRequests > 0 {
			rls.metrics.BlockRate = float64(rls.metrics.BlockedRequests) / float64(rls.metrics.TotalRequests)
		}
	}

	// Update limiter counts
	rls.mutex.RLock()
	rls.metrics.TenantLimiters = len(rls.tenantLimiters)
	rls.metrics.IPLimiters = len(rls.ipLimiters)
	rls.metrics.SourceLimiters = len(rls.sourceLimiters)
	rls.metrics.EndpointLimiters = len(rls.endpointLimiters)
	rls.metrics.AdaptiveLimiters = len(rls.adaptiveLimiters)
	rls.metrics.ActiveLimiters = rls.metrics.TenantLimiters + rls.metrics.IPLimiters +
		rls.metrics.SourceLimiters + rls.metrics.EndpointLimiters
	rls.mutex.RUnlock()

	rls.metrics.lastUpdate = now
}

func (rls *RateLimitingService) ipInRange(ip, cidr string) bool {
	// Simplified implementation - production would use proper CIDR matching
	return false
}

// TokenBucket implementation

// NewTokenBucket creates a new token bucket
func NewTokenBucket(rule *RateLimitRule) *TokenBucket {
	now := time.Now()
	return &TokenBucket{
		capacity:    rule.BurstSize,
		tokens:      rule.BurstSize,
		refillRate:  rule.RequestsPerSecond,
		lastRefill:  now,
		rule:        rule,
		lastRequest: now,
	}
}

// Allow checks if a request can be allowed
func (tb *TokenBucket) Allow() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()
	tb.lastRequest = now
	tb.totalRequests++

	// Refill tokens based on elapsed time
	elapsed := now.Sub(tb.lastRefill)
	tokensToAdd := int64(float64(elapsed.Nanoseconds()) * tb.refillRate / 1e9)

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}

	// Check if request can be allowed
	if tb.tokens > 0 {
		tb.tokens--
		tb.allowedRequests++
		return true
	}

	tb.blockedRequests++
	return false
}

// RemainingTokens returns the number of remaining tokens
func (tb *TokenBucket) RemainingTokens() int64 {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	return tb.tokens
}

// ResetTime returns when the bucket will next refill
func (tb *TokenBucket) ResetTime() time.Time {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	if tb.tokens >= tb.capacity {
		return time.Now()
	}

	tokensNeeded := tb.capacity - tb.tokens
	timeToFill := time.Duration(float64(tokensNeeded)/tb.refillRate) * time.Second
	return tb.lastRefill.Add(timeToFill)
}

// RetryAfter returns when the client should retry
func (tb *TokenBucket) RetryAfter() time.Duration {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	if tb.tokens > 0 {
		return 0
	}

	return time.Duration(1.0/tb.refillRate) * time.Second
}

// AdaptiveRateLimiter implementation

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(config *AdaptiveConfig) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		config:        config,
		currentRate:   config.MinRate,
		baseRate:      config.MinRate,
		learningPhase: true,
		learningStart: time.Now(),
		samples:       make([]float64, 0, 100),
	}
}

// Allow checks if a request should be allowed
func (arl *AdaptiveRateLimiter) Allow() bool {
	arl.mutex.RLock()
	defer arl.mutex.RUnlock()

	// Simple implementation - production would be more sophisticated
	return true
}

// UpdateSystemMetrics updates system metrics and adjusts rate if needed
func (arl *AdaptiveRateLimiter) UpdateSystemMetrics(metrics *SystemMetrics) {
	arl.mutex.Lock()
	defer arl.mutex.Unlock()

	arl.systemMetrics = metrics

	// Check if we should adjust the rate
	now := time.Now()
	if now.Sub(arl.lastAdjustment) < arl.config.ReactionTime {
		return
	}

	// Adjust rate based on system conditions
	if metrics.CPUUsage > arl.config.CPUThreshold ||
		metrics.MemoryUsage > arl.config.MemoryThreshold ||
		metrics.ErrorRate > arl.config.ErrorRateThreshold ||
		metrics.ResponseTime > arl.config.ResponseTimeThreshold {
		// Decrease rate
		newRate := arl.currentRate * (1.0 - arl.config.AdjustmentFactor)
		if newRate < arl.config.MinRate {
			newRate = arl.config.MinRate
		}
		arl.currentRate = newRate
	} else {
		// Increase rate gradually
		newRate := arl.currentRate * (1.0 + arl.config.AdjustmentFactor)
		if newRate > arl.config.MaxRate {
			newRate = arl.config.MaxRate
		}
		arl.currentRate = newRate
	}

	arl.lastAdjustment = now
}

// Utility functions

func validateRateLimitConfig(config *RateLimitConfig) error {
	if config.GlobalLimit != nil && config.GlobalLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("global rate limit must be positive")
	}
	return nil
}

func setRateLimitDefaults(config *RateLimitConfig) {
	if config.DefaultBurstRatio == 0 {
		config.DefaultBurstRatio = 0.1
	}
	if config.WindowSize == 0 {
		config.WindowSize = time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = time.Hour
	}
	if config.MaxLimiters == 0 {
		config.MaxLimiters = 10000
	}
	if config.DefaultAction == "" {
		config.DefaultAction = ActionBlock
	}
	if config.HeaderPrefix == "" {
		config.HeaderPrefix = "X-RateLimit-"
	}
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 30 * time.Second
	}

	// Set adaptive config defaults
	if config.AdaptiveConfig == nil {
		config.AdaptiveConfig = &AdaptiveConfig{}
	}
	if config.AdaptiveConfig.BaseLearningPeriod == 0 {
		config.AdaptiveConfig.BaseLearningPeriod = time.Hour
	}
	if config.AdaptiveConfig.ResponseTimeThreshold == 0 {
		config.AdaptiveConfig.ResponseTimeThreshold = 500 * time.Millisecond
	}
	if config.AdaptiveConfig.ErrorRateThreshold == 0 {
		config.AdaptiveConfig.ErrorRateThreshold = 0.05
	}
	if config.AdaptiveConfig.CPUThreshold == 0 {
		config.AdaptiveConfig.CPUThreshold = 0.8
	}
	if config.AdaptiveConfig.MemoryThreshold == 0 {
		config.AdaptiveConfig.MemoryThreshold = 0.8
	}
	if config.AdaptiveConfig.AdjustmentFactor == 0 {
		config.AdaptiveConfig.AdjustmentFactor = 0.1
	}
	if config.AdaptiveConfig.MinRate == 0 {
		config.AdaptiveConfig.MinRate = 1.0
	}
	if config.AdaptiveConfig.MaxRate == 0 {
		config.AdaptiveConfig.MaxRate = 10000.0
	}
	if config.AdaptiveConfig.ReactionTime == 0 {
		config.AdaptiveConfig.ReactionTime = 30 * time.Second
	}
}

func NewRateLimitMetrics() *RateLimitMetrics {
	return &RateLimitMetrics{
		TopBlockedTenants: make([]string, 0),
		TopBlockedIPs:     make([]string, 0),
		TopBlockedSources: make([]string, 0),
		lastUpdate:        time.Now(),
	}
}
