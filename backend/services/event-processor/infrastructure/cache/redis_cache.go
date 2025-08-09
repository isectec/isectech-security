package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/types"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
)

// RedisCache implements caching using Redis
type RedisCache struct {
	client  redis.UniversalClient
	logger  *logging.Logger
	metrics *metrics.Collector
	config  *RedisCacheConfig
}

// RedisCacheConfig contains Redis cache configuration
type RedisCacheConfig struct {
	// Connection settings
	Addresses          []string      `json:"addresses"`
	Username           string        `json:"username"`
	Password           string        `json:"password"`
	Database           int           `json:"database"`
	PoolSize           int           `json:"pool_size"`
	MinIdleConnections int           `json:"min_idle_connections"`
	
	// Cluster settings
	ClusterMode        bool          `json:"cluster_mode"`
	MasterName         string        `json:"master_name"`
	SentinelAddresses  []string      `json:"sentinel_addresses"`
	
	// Performance settings
	DialTimeout        time.Duration `json:"dial_timeout"`
	ReadTimeout        time.Duration `json:"read_timeout"`
	WriteTimeout       time.Duration `json:"write_timeout"`
	ConnMaxLifetime    time.Duration `json:"conn_max_lifetime"`
	ConnMaxIdleTime    time.Duration `json:"conn_max_idle_time"`
	
	// Cache settings
	DefaultTTL         time.Duration `json:"default_ttl"`
	MaxKeySize         int           `json:"max_key_size"`
	MaxValueSize       int           `json:"max_value_size"`
	KeyPrefix          string        `json:"key_prefix"`
	Namespace          string        `json:"namespace"`
	
	// Compression and serialization
	EnableCompression  bool          `json:"enable_compression"`
	CompressionLevel   int           `json:"compression_level"`
	SerializationFormat string       `json:"serialization_format"` // "json", "msgpack", "protobuf"
	
	// Reliability settings
	MaxRetries         int           `json:"max_retries"`
	RetryBackoff       time.Duration `json:"retry_backoff"`
	CircuitBreakerEnabled bool       `json:"circuit_breaker_enabled"`
	
	// Monitoring
	EnableMetrics      bool          `json:"enable_metrics"`
	EnableTracing      bool          `json:"enable_tracing"`
}

// CacheEntry represents a cached item
type CacheEntry struct {
	Key       string      `json:"key"`
	Value     interface{} `json:"value"`
	TTL       time.Duration `json:"ttl"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Metadata  map[string]string `json:"metadata"`
}

// CacheStats represents cache statistics
type CacheStats struct {
	Hits              int64   `json:"hits"`
	Misses            int64   `json:"misses"`
	HitRate           float64 `json:"hit_rate"`
	TotalOperations   int64   `json:"total_operations"`
	Errors            int64   `json:"errors"`
	AvgResponseTime   time.Duration `json:"avg_response_time"`
	ConnectionsActive int     `json:"connections_active"`
	ConnectionsTotal  int     `json:"connections_total"`
	MemoryUsage       int64   `json:"memory_usage"`
	KeyCount          int64   `json:"key_count"`
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(logger *logging.Logger, metrics *metrics.Collector, config *RedisCacheConfig) (*RedisCache, error) {
	if config == nil {
		config = &RedisCacheConfig{
			Addresses:           []string{"localhost:6379"},
			Database:            0,
			PoolSize:            10,
			MinIdleConnections:  2,
			DialTimeout:         5 * time.Second,
			ReadTimeout:         3 * time.Second,
			WriteTimeout:        3 * time.Second,
			ConnMaxLifetime:     30 * time.Minute,
			ConnMaxIdleTime:     5 * time.Minute,
			DefaultTTL:          15 * time.Minute,
			MaxKeySize:          250,
			MaxValueSize:        1024 * 1024, // 1MB
			KeyPrefix:           "isectech:",
			Namespace:           "event_processor",
			EnableCompression:   true,
			CompressionLevel:    6,
			SerializationFormat: "json",
			MaxRetries:          3,
			RetryBackoff:        100 * time.Millisecond,
			CircuitBreakerEnabled: true,
			EnableMetrics:       true,
			EnableTracing:       false,
		}
	}

	// Create Redis client
	var client redis.UniversalClient

	if config.ClusterMode {
		// Cluster mode
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:              config.Addresses,
			Username:           config.Username,
			Password:           config.Password,
			PoolSize:           config.PoolSize,
			MinIdleConns:       config.MinIdleConnections,
			DialTimeout:        config.DialTimeout,
			ReadTimeout:        config.ReadTimeout,
			WriteTimeout:       config.WriteTimeout,
			ConnMaxLifetime:    config.ConnMaxLifetime,
			ConnMaxIdleTime:    config.ConnMaxIdleTime,
			MaxRetries:         config.MaxRetries,
			MinRetryBackoff:    config.RetryBackoff,
		})
	} else if len(config.SentinelAddresses) > 0 {
		// Sentinel mode
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:         config.MasterName,
			SentinelAddrs:      config.SentinelAddresses,
			Username:           config.Username,
			Password:           config.Password,
			DB:                 config.Database,
			PoolSize:           config.PoolSize,
			MinIdleConns:       config.MinIdleConnections,
			DialTimeout:        config.DialTimeout,
			ReadTimeout:        config.ReadTimeout,
			WriteTimeout:       config.WriteTimeout,
			ConnMaxLifetime:    config.ConnMaxLifetime,
			ConnMaxIdleTime:    config.ConnMaxIdleTime,
			MaxRetries:         config.MaxRetries,
			MinRetryBackoff:    config.RetryBackoff,
		})
	} else {
		// Single instance or simple setup
		if len(config.Addresses) == 1 {
			client = redis.NewClient(&redis.Options{
				Addr:               config.Addresses[0],
				Username:           config.Username,
				Password:           config.Password,
				DB:                 config.Database,
				PoolSize:           config.PoolSize,
				MinIdleConns:       config.MinIdleConnections,
				DialTimeout:        config.DialTimeout,
				ReadTimeout:        config.ReadTimeout,
				WriteTimeout:       config.WriteTimeout,
				ConnMaxLifetime:    config.ConnMaxLifetime,
				ConnMaxIdleTime:    config.ConnMaxIdleTime,
				MaxRetries:         config.MaxRetries,
				MinRetryBackoff:    config.RetryBackoff,
			})
		} else {
			// Ring (multiple independent instances)
			ringOptions := &redis.RingOptions{
				Username:           config.Username,
				Password:           config.Password,
				DB:                 config.Database,
				PoolSize:           config.PoolSize,
				MinIdleConns:       config.MinIdleConnections,
				DialTimeout:        config.DialTimeout,
				ReadTimeout:        config.ReadTimeout,
				WriteTimeout:       config.WriteTimeout,
				ConnMaxLifetime:    config.ConnMaxLifetime,
				ConnMaxIdleTime:    config.ConnMaxIdleTime,
				MaxRetries:         config.MaxRetries,
				MinRetryBackoff:    config.RetryBackoff,
			}

			ringOptions.Addrs = make(map[string]string)
			for i, addr := range config.Addresses {
				ringOptions.Addrs["server"+strconv.Itoa(i)] = addr
			}

			client = redis.NewRing(ringOptions)
		}
	}

	cache := &RedisCache{
		client:  client,
		logger:  logger,
		metrics: metrics,
		config:  config,
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := cache.Ping(ctx); err != nil {
		return nil, common.WrapError(err, common.ErrCodeExternalService, "failed to connect to Redis")
	}

	logger.Info("Redis cache initialized successfully",
		logging.Strings("addresses", config.Addresses),
		logging.Bool("cluster_mode", config.ClusterMode),
		logging.String("namespace", config.Namespace),
	)

	return cache, nil
}

// Get retrieves a value from cache
func (rc *RedisCache) Get(ctx context.Context, key string) (interface{}, error) {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "get", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)
	
	// Validate key size
	if len(fullKey) > rc.config.MaxKeySize {
		return nil, common.NewAppError(common.ErrCodeInvalidInput, "key too long")
	}

	result := rc.client.Get(ctx, fullKey)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			// Cache miss
			if rc.config.EnableMetrics {
				rc.metrics.RecordCacheMiss("redis")
			}
			return nil, common.ErrNotFound("cache key")
		}
		
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_get_error", "redis")
		}
		return nil, common.WrapError(err, common.ErrCodeExternalService, "cache get failed")
	}

	// Cache hit
	if rc.config.EnableMetrics {
		rc.metrics.RecordCacheHit("redis")
	}

	data, err := result.Bytes()
	if err != nil {
		return nil, common.WrapError(err, common.ErrCodeInternal, "failed to read cache data")
	}

	// Deserialize
	value, err := rc.deserialize(data)
	if err != nil {
		rc.logger.Warn("Failed to deserialize cached value",
			logging.String("key", key),
			logging.String("error", err.Error()),
		)
		// Delete corrupted cache entry
		go rc.Delete(context.Background(), key)
		return nil, common.WrapError(err, common.ErrCodeInternal, "failed to deserialize cache data")
	}

	rc.logger.Debug("Cache hit",
		logging.String("key", key),
		logging.Duration("duration", time.Since(start)),
	)

	return value, nil
}

// Set stores a value in cache
func (rc *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "set", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)
	
	// Validate key size
	if len(fullKey) > rc.config.MaxKeySize {
		return common.NewAppError(common.ErrCodeInvalidInput, "key too long")
	}

	// Use default TTL if not specified
	if ttl <= 0 {
		ttl = rc.config.DefaultTTL
	}

	// Serialize value
	data, err := rc.serialize(value)
	if err != nil {
		return common.WrapError(err, common.ErrCodeInternal, "failed to serialize cache data")
	}

	// Validate value size
	if len(data) > rc.config.MaxValueSize {
		return common.NewAppError(common.ErrCodeInvalidInput, "value too large")
	}

	// Store in Redis
	result := rc.client.Set(ctx, fullKey, data, ttl)
	if err := result.Err(); err != nil {
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_set_error", "redis")
		}
		return common.WrapError(err, common.ErrCodeExternalService, "cache set failed")
	}

	rc.logger.Debug("Cache set",
		logging.String("key", key),
		logging.Duration("ttl", ttl),
		logging.Int("size", len(data)),
		logging.Duration("duration", time.Since(start)),
	)

	return nil
}

// Delete removes a value from cache
func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "delete", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)

	result := rc.client.Del(ctx, fullKey)
	if err := result.Err(); err != nil {
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_delete_error", "redis")
		}
		return common.WrapError(err, common.ErrCodeExternalService, "cache delete failed")
	}

	rc.logger.Debug("Cache delete",
		logging.String("key", key),
		logging.Duration("duration", time.Since(start)),
	)

	return nil
}

// Exists checks if a key exists in cache
func (rc *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "exists", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)

	result := rc.client.Exists(ctx, fullKey)
	if err := result.Err(); err != nil {
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_exists_error", "redis")
		}
		return false, common.WrapError(err, common.ErrCodeExternalService, "cache exists check failed")
	}

	exists := result.Val() > 0
	return exists, nil
}

// SetNX sets a value only if the key doesn't exist (atomic)
func (rc *RedisCache) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "setnx", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)

	if ttl <= 0 {
		ttl = rc.config.DefaultTTL
	}

	data, err := rc.serialize(value)
	if err != nil {
		return false, common.WrapError(err, common.ErrCodeInternal, "failed to serialize cache data")
	}

	result := rc.client.SetNX(ctx, fullKey, data, ttl)
	if err := result.Err(); err != nil {
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_setnx_error", "redis")
		}
		return false, common.WrapError(err, common.ErrCodeExternalService, "cache setnx failed")
	}

	success := result.Val()
	return success, nil
}

// Increment atomically increments a counter
func (rc *RedisCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "incr", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)

	var result *redis.IntCmd
	if delta == 1 {
		result = rc.client.Incr(ctx, fullKey)
	} else {
		result = rc.client.IncrBy(ctx, fullKey, delta)
	}

	if err := result.Err(); err != nil {
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_incr_error", "redis")
		}
		return 0, common.WrapError(err, common.ErrCodeExternalService, "cache increment failed")
	}

	return result.Val(), nil
}

// SetTTL updates the TTL of an existing key
func (rc *RedisCache) SetTTL(ctx context.Context, key string, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "expire", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)

	result := rc.client.Expire(ctx, fullKey, ttl)
	if err := result.Err(); err != nil {
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_expire_error", "redis")
		}
		return common.WrapError(err, common.ErrCodeExternalService, "cache expire failed")
	}

	return nil
}

// GetTTL returns the remaining TTL of a key
func (rc *RedisCache) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "ttl", time.Since(start))
		}
	}()

	fullKey := rc.buildKey(key)

	result := rc.client.TTL(ctx, fullKey)
	if err := result.Err(); err != nil {
		if rc.config.EnableMetrics {
			rc.metrics.RecordError("cache_ttl_error", "redis")
		}
		return 0, common.WrapError(err, common.ErrCodeExternalService, "cache ttl check failed")
	}

	return result.Val(), nil
}

// Clear removes all keys matching a pattern
func (rc *RedisCache) Clear(ctx context.Context, pattern string) error {
	start := time.Now()
	defer func() {
		if rc.config.EnableMetrics {
			rc.metrics.RecordCacheOperation("redis", "clear", time.Since(start))
		}
	}()

	fullPattern := rc.buildKey(pattern)

	// Scan for keys matching pattern
	iter := rc.client.Scan(ctx, 0, fullPattern, 0).Iterator()
	
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return common.WrapError(err, common.ErrCodeExternalService, "cache scan failed")
	}

	if len(keys) == 0 {
		return nil
	}

	// Delete keys in batches
	batchSize := 100
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}

		batch := keys[i:end]
		result := rc.client.Del(ctx, batch...)
		if err := result.Err(); err != nil {
			rc.logger.Error("Failed to delete cache batch",
				logging.String("error", err.Error()),
				logging.Int("batch_size", len(batch)),
			)
		}
	}

	rc.logger.Info("Cache cleared",
		logging.String("pattern", pattern),
		logging.Int("keys_deleted", len(keys)),
		logging.Duration("duration", time.Since(start)),
	)

	return nil
}

// GetStats returns cache statistics
func (rc *RedisCache) GetStats(ctx context.Context) (*CacheStats, error) {
	result := rc.client.Info(ctx, "stats", "memory")
	if err := result.Err(); err != nil {
		return nil, common.WrapError(err, common.ErrCodeExternalService, "failed to get Redis stats")
	}

	info := result.Val()
	stats := &CacheStats{}

	// Parse Redis INFO output (simplified)
	lines := strings.Split(info, "\r\n")
	for _, line := range lines {
		if strings.Contains(line, "keyspace_hits:") {
			fmt.Sscanf(line, "keyspace_hits:%d", &stats.Hits)
		} else if strings.Contains(line, "keyspace_misses:") {
			fmt.Sscanf(line, "keyspace_misses:%d", &stats.Misses)
		} else if strings.Contains(line, "used_memory:") {
			fmt.Sscanf(line, "used_memory:%d", &stats.MemoryUsage)
		}
	}

	// Calculate derived stats
	stats.TotalOperations = stats.Hits + stats.Misses
	if stats.TotalOperations > 0 {
		stats.HitRate = float64(stats.Hits) / float64(stats.TotalOperations)
	}

	// Get key count for our namespace
	keyCount := rc.client.Eval(ctx, `
		local keys = redis.call('KEYS', ARGV[1])
		return #keys
	`, []string{}, rc.buildKey("*"))
	
	if keyCount.Err() == nil {
		if count, ok := keyCount.Val().(int64); ok {
			stats.KeyCount = count
		}
	}

	return stats, nil
}

// Ping tests the connection to Redis
func (rc *RedisCache) Ping(ctx context.Context) error {
	result := rc.client.Ping(ctx)
	if err := result.Err(); err != nil {
		return common.WrapError(err, common.ErrCodeExternalService, "Redis ping failed")
	}
	return nil
}

// Close closes the Redis connection
func (rc *RedisCache) Close() error {
	if rc.client != nil {
		return rc.client.Close()
	}
	return nil
}

// Helper methods

func (rc *RedisCache) buildKey(key string) string {
	if rc.config.Namespace != "" {
		return fmt.Sprintf("%s%s:%s", rc.config.KeyPrefix, rc.config.Namespace, key)
	}
	return rc.config.KeyPrefix + key
}

func (rc *RedisCache) serialize(value interface{}) ([]byte, error) {
	switch rc.config.SerializationFormat {
	case "json":
		return json.Marshal(value)
	default:
		return json.Marshal(value)
	}
}

func (rc *RedisCache) deserialize(data []byte) (interface{}, error) {
	var value interface{}
	
	switch rc.config.SerializationFormat {
	case "json":
		err := json.Unmarshal(data, &value)
		return value, err
	default:
		err := json.Unmarshal(data, &value)
		return value, err
	}
}

// Event-specific cache methods

// CacheEventValidation caches event validation results
func (rc *RedisCache) CacheEventValidation(ctx context.Context, eventID types.EventID, result bool, ttl time.Duration) error {
	key := fmt.Sprintf("validation:%s", eventID.String())
	return rc.Set(ctx, key, result, ttl)
}

// GetCachedEventValidation retrieves cached event validation result
func (rc *RedisCache) GetCachedEventValidation(ctx context.Context, eventID types.EventID) (bool, error) {
	key := fmt.Sprintf("validation:%s", eventID.String())
	result, err := rc.Get(ctx, key)
	if err != nil {
		return false, err
	}
	
	if valid, ok := result.(bool); ok {
		return valid, nil
	}
	
	return false, common.NewAppError(common.ErrCodeInternal, "invalid cached validation result")
}

// CacheEventEnrichment caches event enrichment data
func (rc *RedisCache) CacheEventEnrichment(ctx context.Context, indicator string, indicatorType string, data interface{}, ttl time.Duration) error {
	key := fmt.Sprintf("enrichment:%s:%s", indicatorType, indicator)
	return rc.Set(ctx, key, data, ttl)
}

// GetCachedEventEnrichment retrieves cached event enrichment data
func (rc *RedisCache) GetCachedEventEnrichment(ctx context.Context, indicator string, indicatorType string) (interface{}, error) {
	key := fmt.Sprintf("enrichment:%s:%s", indicatorType, indicator)
	return rc.Get(ctx, key)
}

// CacheRiskAssessment caches risk assessment results
func (rc *RedisCache) CacheRiskAssessment(ctx context.Context, eventHash string, riskScore float64, confidence float64, ttl time.Duration) error {
	key := fmt.Sprintf("risk:%s", eventHash)
	data := map[string]interface{}{
		"score":      riskScore,
		"confidence": confidence,
		"cached_at":  time.Now().UTC(),
	}
	return rc.Set(ctx, key, data, ttl)
}

// GetCachedRiskAssessment retrieves cached risk assessment result
func (rc *RedisCache) GetCachedRiskAssessment(ctx context.Context, eventHash string) (float64, float64, error) {
	key := fmt.Sprintf("risk:%s", eventHash)
	result, err := rc.Get(ctx, key)
	if err != nil {
		return 0, 0, err
	}
	
	if data, ok := result.(map[string]interface{}); ok {
		score, _ := data["score"].(float64)
		confidence, _ := data["confidence"].(float64)
		return score, confidence, nil
	}
	
	return 0, 0, common.NewAppError(common.ErrCodeInternal, "invalid cached risk assessment result")
}

// Event frequency tracking methods

// IncrementEventFrequency increments the frequency counter for an event pattern
func (rc *RedisCache) IncrementEventFrequency(ctx context.Context, pattern string, window time.Duration) (int64, error) {
	key := fmt.Sprintf("freq:%s", pattern)
	
	// Increment counter
	count, err := rc.Increment(ctx, key, 1)
	if err != nil {
		return 0, err
	}
	
	// Set TTL for the window if this is the first increment
	if count == 1 {
		rc.SetTTL(ctx, key, window)
	}
	
	return count, nil
}

// GetEventFrequency gets the current frequency count for an event pattern
func (rc *RedisCache) GetEventFrequency(ctx context.Context, pattern string) (int64, error) {
	key := fmt.Sprintf("freq:%s", pattern)
	result, err := rc.Get(ctx, key)
	if err != nil {
		if common.IsNotFoundError(err) {
			return 0, nil
		}
		return 0, err
	}
	
	if count, ok := result.(int64); ok {
		return count, nil
	}
	
	return 0, nil
}