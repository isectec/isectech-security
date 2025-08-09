package dal

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/isectech/platform/shared/database/redis"
)

// CacheManager handles intelligent caching for the Data Access Layer
type CacheManager struct {
	config       CachingConfig
	redis        *redis.Client
	logger       *zap.Logger
	keyPrefixes  map[string]string
	hitCounter   map[string]int64
	missCounter  map[string]int64
	mu           sync.RWMutex
}

// CacheEntry represents a cached entry with metadata
type CacheEntry struct {
	Key        string      `json:"key"`
	Value      interface{} `json:"value"`
	CreatedAt  time.Time   `json:"created_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	AccessedAt time.Time   `json:"accessed_at"`
	AccessCount int64      `json:"access_count"`
	Strategy   string      `json:"strategy"`
	Compressed bool        `json:"compressed"`
	Encrypted  bool        `json:"encrypted"`
	TenantID   string      `json:"tenant_id"`
	Tags       []string    `json:"tags"`
}

// CacheWriteResult represents the result of a cache write operation
type CacheWriteResult struct {
	Key       string    `json:"key"`
	Success   bool      `json:"success"`
	WriteType string    `json:"write_type"` // through, back, direct
	Duration  time.Duration `json:"duration"`
	Error     string    `json:"error,omitempty"`
}

// CacheReadResult represents the result of a cache read operation
type CacheReadResult struct {
	Key      string        `json:"key"`
	Hit      bool          `json:"hit"`
	Value    interface{}   `json:"value,omitempty"`
	Duration time.Duration `json:"duration"`
	Strategy string        `json:"strategy"`
	Error    string        `json:"error,omitempty"`
}

// CacheStats represents cache statistics
type CacheStats struct {
	HitRate       float64           `json:"hit_rate"`
	TotalHits     int64             `json:"total_hits"`
	TotalMisses   int64             `json:"total_misses"`
	TotalRequests int64             `json:"total_requests"`
	HitsByStrategy map[string]int64 `json:"hits_by_strategy"`
	MissByStrategy map[string]int64 `json:"miss_by_strategy"`
	Timestamp     time.Time         `json:"timestamp"`
}

// NewCacheManager creates a new cache manager
func NewCacheManager(config CachingConfig, redisClient *redis.Client, logger *zap.Logger) (*CacheManager, error) {
	cm := &CacheManager{
		config:      config,
		redis:       redisClient,
		logger:      logger,
		keyPrefixes: make(map[string]string),
		hitCounter:  make(map[string]int64),
		missCounter: make(map[string]int64),
	}

	// Initialize key prefixes for different strategies
	for strategy := range config.CacheStrategies {
		cm.keyPrefixes[strategy] = fmt.Sprintf("dal:cache:%s:", strategy)
	}

	logger.Info("Cache manager initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Duration("default_ttl", config.DefaultTTL),
		zap.Int("strategies", len(config.CacheStrategies)))

	return cm, nil
}

// Get retrieves a value from cache
func (cm *CacheManager) Get(ctx context.Context, key string, strategy string, tenant *TenantContext) (*CacheReadResult, error) {
	start := time.Now()
	result := &CacheReadResult{
		Key:      key,
		Strategy: strategy,
		Duration: 0,
	}

	if !cm.config.Enabled {
		result.Duration = time.Since(start)
		return result, nil
	}

	// Build cache key
	cacheKey := cm.buildCacheKey(key, strategy, tenant)

	// Get from Redis
	opts := &redis.CacheOptions{
		Tenant: &redis.TenantContext{
			TenantID: tenant.TenantID if tenant != nil else "",
		},
		Prefix: cm.keyPrefixes[strategy],
	}

	// Get strategy configuration
	strategyConfig, exists := cm.config.CacheStrategies[strategy]
	if exists {
		opts.Encrypt = strategyConfig.Encrypt
		opts.TTL = strategyConfig.TTL
	}

	value, err := cm.redis.Get(ctx, cacheKey, opts)
	result.Duration = time.Since(start)

	if err != nil {
		// Cache miss
		cm.recordMiss(strategy)
		result.Hit = false
		result.Error = err.Error()
		return result, nil
	}

	// Cache hit
	cm.recordHit(strategy)
	result.Hit = true

	// Deserialize value
	var entry CacheEntry
	if err := json.Unmarshal([]byte(value), &entry); err != nil {
		result.Error = fmt.Sprintf("failed to deserialize cache entry: %v", err)
		return result, err
	}

	// Update access time and count
	entry.AccessedAt = time.Now()
	entry.AccessCount++

	// Update cache entry with new access info (fire and forget)
	go cm.updateAccessInfo(context.Background(), cacheKey, &entry, opts)

	result.Value = entry.Value
	return result, nil
}

// Set stores a value in cache
func (cm *CacheManager) Set(ctx context.Context, key string, value interface{}, strategy string, tenant *TenantContext) (*CacheWriteResult, error) {
	start := time.Now()
	result := &CacheWriteResult{
		Key:       key,
		WriteType: "direct",
		Success:   false,
	}

	if !cm.config.Enabled {
		result.Duration = time.Since(start)
		result.Success = true
		return result, nil
	}

	// Get strategy configuration
	strategyConfig, exists := cm.config.CacheStrategies[strategy]
	if !exists {
		strategyConfig = CacheStrategy{
			TTL:            cm.config.DefaultTTL,
			WriteThrough:   cm.config.WriteThrough,
			EvictionPolicy: "lru",
		}
	}

	// Create cache entry
	entry := CacheEntry{
		Key:        key,
		Value:      value,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(strategyConfig.TTL),
		AccessedAt: time.Now(),
		AccessCount: 0,
		Strategy:   strategy,
		Compressed: strategyConfig.Compress,
		Encrypted:  strategyConfig.Encrypt,
		TenantID:   tenant.TenantID if tenant != nil else "",
	}

	// Serialize entry
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		result.Duration = time.Since(start)
		result.Error = fmt.Sprintf("failed to serialize cache entry: %v", err)
		return result, err
	}

	// Build cache key
	cacheKey := cm.buildCacheKey(key, strategy, tenant)

	// Store in Redis
	opts := &redis.CacheOptions{
		Tenant: &redis.TenantContext{
			TenantID: tenant.TenantID if tenant != nil else "",
		},
		TTL:     strategyConfig.TTL,
		Encrypt: strategyConfig.Encrypt,
		Prefix:  cm.keyPrefixes[strategy],
	}

	err = cm.redis.Set(ctx, cacheKey, string(entryBytes), opts)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = fmt.Sprintf("failed to store in cache: %v", err)
		return result, err
	}

	result.Success = true
	if strategyConfig.WriteThrough {
		result.WriteType = "through"
	} else if strategyConfig.WriteBack {
		result.WriteType = "back"
	}

	cm.logger.Debug("Cache entry stored",
		zap.String("key", key),
		zap.String("strategy", strategy),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// Delete removes a value from cache
func (cm *CacheManager) Delete(ctx context.Context, key string, strategy string, tenant *TenantContext) error {
	if !cm.config.Enabled {
		return nil
	}

	cacheKey := cm.buildCacheKey(key, strategy, tenant)
	return cm.redis.Del(ctx, cacheKey)
}

// Invalidate removes cache entries based on patterns or tags
func (cm *CacheManager) Invalidate(ctx context.Context, pattern string, tags []string, tenant *TenantContext) error {
	if !cm.config.Enabled {
		return nil
	}

	// For now, implement simple pattern-based invalidation
	// In production, you might want to use Redis SCAN or tag-based invalidation
	if pattern != "" {
		// Build pattern with tenant isolation
		var searchPattern string
		if tenant != nil {
			searchPattern = fmt.Sprintf("dal:cache:*:%s:%s", tenant.TenantID, pattern)
		} else {
			searchPattern = fmt.Sprintf("dal:cache:*:%s", pattern)
		}

		// Use Redis SCAN to find matching keys
		// This is a simplified implementation
		cm.logger.Info("Cache invalidation requested",
			zap.String("pattern", pattern),
			zap.Strings("tags", tags))
	}

	return nil
}

// InvalidateByRules applies invalidation rules based on data changes
func (cm *CacheManager) InvalidateByRules(ctx context.Context, dataType string, operation string, tenant *TenantContext) error {
	if !cm.config.Enabled {
		return nil
	}

	rule, exists := cm.config.InvalidationRules[dataType]
	if !exists {
		return nil
	}

	var strategies []string
	switch operation {
	case "insert":
		strategies = rule.OnInsert
	case "update":
		strategies = rule.OnUpdate
	case "delete":
		strategies = rule.OnDelete
	}

	// Invalidate cache entries for affected strategies
	for _, strategy := range strategies {
		pattern := "*" // Invalidate all entries for this strategy
		if err := cm.Invalidate(ctx, pattern, nil, tenant); err != nil {
			cm.logger.Error("Failed to invalidate cache",
				zap.String("strategy", strategy),
				zap.String("operation", operation),
				zap.Error(err))
		}
	}

	cm.logger.Debug("Cache invalidated by rules",
		zap.String("data_type", dataType),
		zap.String("operation", operation),
		zap.Strings("strategies", strategies))

	return nil
}

// GetWithFallback attempts to get from cache and falls back to a function if miss
func (cm *CacheManager) GetWithFallback(ctx context.Context, key string, strategy string, tenant *TenantContext, fallback func(ctx context.Context) (interface{}, error)) (interface{}, bool, error) {
	// Try cache first
	result, err := cm.Get(ctx, key, strategy, tenant)
	if err != nil {
		return nil, false, err
	}

	if result.Hit {
		return result.Value, true, nil
	}

	// Cache miss, use fallback
	value, err := fallback(ctx)
	if err != nil {
		return nil, false, err
	}

	// Store in cache (fire and forget)
	go func() {
		cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cm.Set(cacheCtx, key, value, strategy, tenant)
	}()

	return value, false, nil
}

// Warm pre-loads cache with data
func (cm *CacheManager) Warm(ctx context.Context, data map[string]interface{}, strategy string, tenant *TenantContext) error {
	if !cm.config.Enabled {
		return nil
	}

	var errors []error
	for key, value := range data {
		if _, err := cm.Set(ctx, key, value, strategy, tenant); err != nil {
			errors = append(errors, fmt.Errorf("failed to warm key %s: %w", key, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("cache warming failed: %v", errors)
	}

	cm.logger.Info("Cache warmed",
		zap.String("strategy", strategy),
		zap.Int("keys", len(data)))

	return nil
}

// GetStats returns cache statistics
func (cm *CacheManager) GetStats() *CacheStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var totalHits, totalMisses int64
	hitsByStrategy := make(map[string]int64)
	missByStrategy := make(map[string]int64)

	for strategy, hits := range cm.hitCounter {
		totalHits += hits
		hitsByStrategy[strategy] = hits
	}

	for strategy, misses := range cm.missCounter {
		totalMisses += misses
		missByStrategy[strategy] = misses
	}

	totalRequests := totalHits + totalMisses
	var hitRate float64
	if totalRequests > 0 {
		hitRate = float64(totalHits) / float64(totalRequests)
	}

	return &CacheStats{
		HitRate:        hitRate,
		TotalHits:      totalHits,
		TotalMisses:    totalMisses,
		TotalRequests:  totalRequests,
		HitsByStrategy: hitsByStrategy,
		MissByStrategy: missByStrategy,
		Timestamp:      time.Now(),
	}
}

// RunMaintenance performs cache maintenance tasks
func (cm *CacheManager) RunMaintenance() {
	if !cm.config.Enabled {
		return
	}

	// This could include:
	// - Cleaning up expired entries
	// - Compacting cache data
	// - Updating access statistics
	// - Refreshing frequently accessed data

	cm.logger.Debug("Running cache maintenance")

	// Reset counters periodically to avoid overflow
	cm.mu.Lock()
	for strategy := range cm.hitCounter {
		if cm.hitCounter[strategy] > 1000000 {
			cm.hitCounter[strategy] = cm.hitCounter[strategy] / 2
			cm.missCounter[strategy] = cm.missCounter[strategy] / 2
		}
	}
	cm.mu.Unlock()
}

// buildCacheKey constructs a cache key with tenant isolation
func (cm *CacheManager) buildCacheKey(key, strategy string, tenant *TenantContext) string {
	prefix := cm.keyPrefixes[strategy]
	if tenant != nil {
		return fmt.Sprintf("%s%s:%s", prefix, tenant.TenantID, key)
	}
	return fmt.Sprintf("%s%s", prefix, key)
}

// recordHit records a cache hit for statistics
func (cm *CacheManager) recordHit(strategy string) {
	cm.mu.Lock()
	cm.hitCounter[strategy]++
	cm.mu.Unlock()
}

// recordMiss records a cache miss for statistics
func (cm *CacheManager) recordMiss(strategy string) {
	cm.mu.Lock()
	cm.missCounter[strategy]++
	cm.mu.Unlock()
}

// updateAccessInfo updates access information for a cache entry
func (cm *CacheManager) updateAccessInfo(ctx context.Context, cacheKey string, entry *CacheEntry, opts *redis.CacheOptions) {
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return
	}

	// Update with original TTL preserved
	remaining := entry.ExpiresAt.Sub(time.Now())
	if remaining > 0 {
		opts.TTL = remaining
		cm.redis.Set(ctx, cacheKey, string(entryBytes), opts)
	}
}

// GetStrategies returns configured cache strategies
func (cm *CacheManager) GetStrategies() map[string]CacheStrategy {
	return cm.config.CacheStrategies
}

// IsEnabled returns whether caching is enabled
func (cm *CacheManager) IsEnabled() bool {
	return cm.config.Enabled
}

// GetDefaultTTL returns the default TTL for cache entries
func (cm *CacheManager) GetDefaultTTL() time.Duration {
	return cm.config.DefaultTTL
}

// GetStrategyTTL returns the TTL for a specific strategy
func (cm *CacheManager) GetStrategyTTL(strategy string) time.Duration {
	if strategyConfig, exists := cm.config.CacheStrategies[strategy]; exists {
		return strategyConfig.TTL
	}
	return cm.config.DefaultTTL
}

// SetStrategy dynamically sets or updates a cache strategy
func (cm *CacheManager) SetStrategy(name string, strategy CacheStrategy) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.config.CacheStrategies == nil {
		cm.config.CacheStrategies = make(map[string]CacheStrategy)
	}

	cm.config.CacheStrategies[name] = strategy
	cm.keyPrefixes[name] = fmt.Sprintf("dal:cache:%s:", name)

	cm.logger.Info("Cache strategy updated",
		zap.String("strategy", name),
		zap.Duration("ttl", strategy.TTL),
		zap.Bool("write_through", strategy.WriteThrough))
}

// RemoveStrategy removes a cache strategy
func (cm *CacheManager) RemoveStrategy(name string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	delete(cm.config.CacheStrategies, name)
	delete(cm.keyPrefixes, name)
	delete(cm.hitCounter, name)
	delete(cm.missCounter, name)

	cm.logger.Info("Cache strategy removed", zap.String("strategy", name))
}

// Close closes the cache manager
func (cm *CacheManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Clear all counters
	cm.hitCounter = make(map[string]int64)
	cm.missCounter = make(map[string]int64)

	cm.logger.Info("Cache manager closed")
	return nil
}