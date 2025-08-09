package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sony/gobreaker"
	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// Client represents a Redis client for iSECTECH cybersecurity platform
type Client struct {
	config         *Config
	client         redis.Cmdable
	clusterClient  *redis.ClusterClient
	sentinelClient *redis.Client
	streams        *StreamsManager
	cache          *CacheManager
	logger         *zap.Logger
	circuitBreaker *gobreaker.CircuitBreaker
	encryptor      *Encryptor
	mu             sync.RWMutex
	closed         bool
}

// TenantContext represents tenant information for multi-tenancy
type TenantContext struct {
	TenantID        string
	UserID          string
	Role            string
	SecurityTags    map[string]string
	Permissions     []string
}

// CacheOptions represents options for cache operations
type CacheOptions struct {
	Tenant     *TenantContext
	TTL        time.Duration
	Compress   bool
	Encrypt    bool
	Prefix     string
}

// StreamMessage represents a message in Redis Streams
type StreamMessage struct {
	ID        string
	Stream    string
	TenantID  string
	EventType string
	Data      map[string]interface{}
	Metadata  map[string]interface{}
	Timestamp time.Time
}

// SecurityEvent represents a cybersecurity event for streaming
type SecurityEvent struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	Source      map[string]interface{} `json:"source"`
	Target      map[string]interface{} `json:"target"`
	Description string                 `json:"description"`
	Indicators  []ThreatIndicator      `json:"indicators"`
	Timestamp   time.Time              `json:"timestamp"`
	RiskScore   int                    `json:"risk_score"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Type       string      `json:"type"`
	Value      interface{} `json:"value"`
	Confidence float64     `json:"confidence"`
	Source     string      `json:"source"`
	Context    string      `json:"context,omitempty"`
}

// AuditEvent represents an audit event for streaming
type AuditEvent struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	UserID        string                 `json:"user_id"`
	Action        string                 `json:"action"`
	ResourceType  string                 `json:"resource_type"`
	ResourceID    string                 `json:"resource_id"`
	SourceIP      string                 `json:"source_ip"`
	UserAgent     string                 `json:"user_agent"`
	Details       map[string]interface{} `json:"details"`
	Timestamp     time.Time              `json:"timestamp"`
	Status        string                 `json:"status"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
}

// NewClient creates a new Redis client for iSECTECH
func NewClient(config *Config, logger *zap.Logger) (*Client, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	client := &Client{
		config: config,
		logger: logger,
	}

	// Create circuit breaker
	client.circuitBreaker = gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "redis-client",
		MaxRequests: config.CircuitBreaker.MaxRequests,
		Interval:    config.CircuitBreaker.Interval,
		Timeout:     config.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= config.CircuitBreaker.FailureThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("Circuit breaker state changed",
				zap.String("name", name),
				zap.String("from", from.String()),
				zap.String("to", to.String()))
		},
	})

	// Initialize encryptor if encryption is enabled
	if config.Security.EnableEncryption {
		encryptor, err := NewEncryptor(config.Security.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		client.encryptor = encryptor
	}

	// Create Redis client based on configuration
	if err := client.initializeRedisClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize Redis client: %w", err)
	}

	// Initialize streams manager
	if config.Streams.Enabled {
		streams, err := NewStreamsManager(client.client, config, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create streams manager: %w", err)
		}
		client.streams = streams
	}

	// Initialize cache manager
	cache, err := NewCacheManager(client, config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache manager: %w", err)
	}
	client.cache = cache

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	logger.Info("Redis client initialized successfully",
		zap.Bool("cluster_mode", config.IsClusterMode()),
		zap.Bool("sentinel_mode", config.IsSentinelMode()),
		zap.Bool("streams_enabled", config.Streams.Enabled),
		zap.Bool("encryption_enabled", config.Security.EnableEncryption))

	return client, nil
}

// initializeRedisClient creates the appropriate Redis client based on configuration
func (c *Client) initializeRedisClient() error {
	if c.config.IsClusterMode() {
		return c.initializeClusterClient()
	} else if c.config.IsSentinelMode() {
		return c.initializeSentinelClient()
	} else {
		return c.initializeStandaloneClient()
	}
}

// initializeClusterClient creates a Redis Cluster client
func (c *Client) initializeClusterClient() error {
	opts := &redis.ClusterOptions{
		Addrs:        c.config.Addresses,
		Password:     c.config.Password,
		DialTimeout:  c.config.DialTimeout,
		ReadTimeout:  c.config.ReadTimeout,
		WriteTimeout: c.config.WriteTimeout,
		PoolSize:     c.config.PoolSize,
		MinIdleConns: c.config.MinIdleConns,
		MaxConnAge:   c.config.ConnMaxLifetime,
		PoolTimeout:  c.config.PoolTimeout,
		IdleTimeout:  c.config.ConnMaxIdleTime,
		MaxRedirects: c.config.Cluster.MaxRedirects,
		ReadOnly:     c.config.Cluster.ReadOnly,
		RouteByLatency: c.config.Cluster.RouteByLatency,
		RouteRandomly:  c.config.Cluster.RouteRandomly,
	}

	// Configure TLS if enabled
	if c.config.Security.EnableTLS {
		tlsConfig, err := c.createTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	clusterClient := redis.NewClusterClient(opts)
	c.clusterClient = clusterClient
	c.client = clusterClient

	c.logger.Info("Redis cluster client initialized",
		zap.Strings("addresses", c.config.Addresses),
		zap.Bool("tls_enabled", c.config.Security.EnableTLS))

	return nil
}

// initializeSentinelClient creates a Redis Sentinel client
func (c *Client) initializeSentinelClient() error {
	opts := &redis.FailoverOptions{
		MasterName:       c.config.Sentinel.MasterName,
		SentinelAddrs:    c.config.Sentinel.SentinelAddrs,
		SentinelPassword: c.config.Sentinel.SentinelPassword,
		Password:         c.config.Password,
		DB:               c.config.DB,
		DialTimeout:      c.config.DialTimeout,
		ReadTimeout:      c.config.ReadTimeout,
		WriteTimeout:     c.config.WriteTimeout,
		PoolSize:         c.config.PoolSize,
		MinIdleConns:     c.config.MinIdleConns,
		MaxConnAge:       c.config.ConnMaxLifetime,
		PoolTimeout:      c.config.PoolTimeout,
		IdleTimeout:      c.config.ConnMaxIdleTime,
	}

	// Configure TLS if enabled
	if c.config.Security.EnableTLS {
		tlsConfig, err := c.createTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	sentinelClient := redis.NewFailoverClient(opts)
	c.sentinelClient = sentinelClient
	c.client = sentinelClient

	c.logger.Info("Redis sentinel client initialized",
		zap.String("master_name", c.config.Sentinel.MasterName),
		zap.Strings("sentinel_addrs", c.config.Sentinel.SentinelAddrs),
		zap.Bool("tls_enabled", c.config.Security.EnableTLS))

	return nil
}

// initializeStandaloneClient creates a standalone Redis client
func (c *Client) initializeStandaloneClient() error {
	if len(c.config.Addresses) == 0 {
		return fmt.Errorf("no Redis addresses configured")
	}

	opts := &redis.Options{
		Addr:         c.config.Addresses[0],
		Password:     c.config.Password,
		DB:           c.config.DB,
		DialTimeout:  c.config.DialTimeout,
		ReadTimeout:  c.config.ReadTimeout,
		WriteTimeout: c.config.WriteTimeout,
		PoolSize:     c.config.PoolSize,
		MinIdleConns: c.config.MinIdleConns,
		MaxConnAge:   c.config.ConnMaxLifetime,
		PoolTimeout:  c.config.PoolTimeout,
		IdleTimeout:  c.config.ConnMaxIdleTime,
	}

	// Configure TLS if enabled
	if c.config.Security.EnableTLS {
		tlsConfig, err := c.createTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	standaloneClient := redis.NewClient(opts)
	c.client = standaloneClient

	c.logger.Info("Redis standalone client initialized",
		zap.String("address", c.config.Addresses[0]),
		zap.Bool("tls_enabled", c.config.Security.EnableTLS))

	return nil
}

// createTLSConfig creates TLS configuration
func (c *Client) createTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.config.Security.TLSConfig.InsecureSkipVerify,
	}

	// Load certificates if provided
	if c.config.Security.TLSConfig.CertFile != "" && c.config.Security.TLSConfig.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(
			c.config.Security.TLSConfig.CertFile,
			c.config.Security.TLSConfig.KeyFile,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificates: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// Ping tests the connection to Redis
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		return c.client.Ping(ctx).Result()
	})
	return err
}

// Get retrieves a value from Redis with optional decryption
func (c *Client) Get(ctx context.Context, key string, opts *CacheOptions) (string, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		// Apply tenant isolation
		if opts != nil && opts.Tenant != nil {
			key = c.config.GetCacheKey(opts.Prefix, key, opts.Tenant.TenantID)
		}

		value, err := c.client.Get(ctx, key).Result()
		if err != nil {
			return "", err
		}

		// Decrypt if needed
		if opts != nil && opts.Encrypt && c.encryptor != nil {
			decrypted, err := c.encryptor.Decrypt(value)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt value: %w", err)
			}
			return decrypted, nil
		}

		return value, nil
	})

	if err != nil {
		return "", err
	}

	return result.(string), nil
}

// Set stores a value in Redis with optional encryption
func (c *Client) Set(ctx context.Context, key string, value interface{}, opts *CacheOptions) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		// Apply tenant isolation
		if opts != nil && opts.Tenant != nil {
			key = c.config.GetCacheKey(opts.Prefix, key, opts.Tenant.TenantID)
		}

		// Convert value to string
		var strValue string
		switch v := value.(type) {
		case string:
			strValue = v
		case []byte:
			strValue = string(v)
		default:
			strValue = fmt.Sprintf("%v", v)
		}

		// Encrypt if needed
		if opts != nil && opts.Encrypt && c.encryptor != nil {
			encrypted, err := c.encryptor.Encrypt(strValue)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt value: %w", err)
			}
			strValue = encrypted
		}

		// Determine TTL
		ttl := c.config.Cache.DefaultTTL
		if opts != nil && opts.TTL > 0 {
			ttl = opts.TTL
		} else if opts != nil && opts.Prefix != "" {
			if prefixConfig, exists := c.config.Cache.Prefixes[opts.Prefix]; exists {
				ttl = prefixConfig.TTL
			}
		}

		return nil, c.client.Set(ctx, key, strValue, ttl).Err()
	})

	return err
}

// Del deletes one or more keys from Redis
func (c *Client) Del(ctx context.Context, keys ...string) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		return nil, c.client.Del(ctx, keys...).Err()
	})
	return err
}

// Exists checks if keys exist in Redis
func (c *Client) Exists(ctx context.Context, keys ...string) (int64, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		return c.client.Exists(ctx, keys...).Result()
	})

	if err != nil {
		return 0, err
	}

	return result.(int64), nil
}

// Expire sets a timeout on a key
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		return nil, c.client.Expire(ctx, key, ttl).Err()
	})
	return err
}

// PublishSecurityEvent publishes a security event to Redis Streams
func (c *Client) PublishSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	if !c.config.Streams.Enabled || c.streams == nil {
		return fmt.Errorf("streams are not enabled")
	}

	streamMessage := &StreamMessage{
		Stream:    "security:events",
		TenantID:  event.TenantID,
		EventType: event.EventType,
		Data: map[string]interface{}{
			"id":          event.ID,
			"severity":    event.Severity,
			"source":      event.Source,
			"target":      event.Target,
			"description": event.Description,
			"indicators":  event.Indicators,
			"risk_score":  event.RiskScore,
			"tags":        event.Tags,
		},
		Metadata: event.Metadata,
		Timestamp: event.Timestamp,
	}

	return c.streams.PublishMessage(ctx, streamMessage)
}

// PublishAuditEvent publishes an audit event to Redis Streams
func (c *Client) PublishAuditEvent(ctx context.Context, event *AuditEvent) error {
	if !c.config.Streams.Enabled || c.streams == nil {
		return fmt.Errorf("streams are not enabled")
	}

	streamMessage := &StreamMessage{
		Stream:    "audit:events",
		TenantID:  event.TenantID,
		EventType: "audit",
		Data: map[string]interface{}{
			"id":            event.ID,
			"user_id":       event.UserID,
			"action":        event.Action,
			"resource_type": event.ResourceType,
			"resource_id":   event.ResourceID,
			"source_ip":     event.SourceIP,
			"user_agent":    event.UserAgent,
			"details":       event.Details,
			"status":        event.Status,
			"error_message": event.ErrorMessage,
		},
		Metadata: map[string]interface{}{
			"tenant_id": event.TenantID,
			"user_id":   event.UserID,
			"action":    event.Action,
		},
		Timestamp: event.Timestamp,
	}

	return c.streams.PublishMessage(ctx, streamMessage)
}

// GetStreamsManager returns the streams manager
func (c *Client) GetStreamsManager() *StreamsManager {
	return c.streams
}

// GetCacheManager returns the cache manager
func (c *Client) GetCacheManager() *CacheManager {
	return c.cache
}

// Health checks the health of the Redis connection
func (c *Client) Health(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return false
	}

	err := c.Ping(ctx)
	return err == nil
}

// GetStats returns Redis statistics
func (c *Client) GetStats(ctx context.Context) (map[string]interface{}, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		info, err := c.client.Info(ctx).Result()
		if err != nil {
			return nil, err
		}
		
		stats := map[string]interface{}{
			"info": info,
		}

		// Add memory usage
		memInfo, err := c.client.Info(ctx, "memory").Result()
		if err == nil {
			stats["memory"] = memInfo
		}

		// Add client info
		clientInfo, err := c.client.Info(ctx, "clients").Result()
		if err == nil {
			stats["clients"] = clientInfo
		}

		return stats, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(map[string]interface{}), nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	var err error
	if c.clusterClient != nil {
		err = c.clusterClient.Close()
	} else if c.sentinelClient != nil {
		err = c.sentinelClient.Close()
	} else if c.client != nil {
		if redisClient, ok := c.client.(*redis.Client); ok {
			err = redisClient.Close()
		}
	}

	if err != nil {
		return fmt.Errorf("failed to close Redis client: %w", err)
	}

	c.logger.Info("Redis client closed")
	return nil
}