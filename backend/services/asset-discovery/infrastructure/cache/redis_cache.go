package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"asset-discovery/domain/entity"
)

// RedisCache implements caching for asset discovery operations
type RedisCache struct {
	client *redis.Client
	logger *zap.Logger
	
	// Cache configuration
	defaultTTL        time.Duration
	assetTTL          time.Duration
	discoveryTTL      time.Duration
	aggregationTTL    time.Duration
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(client *redis.Client, logger *zap.Logger) *RedisCache {
	return &RedisCache{
		client:         client,
		logger:         logger,
		defaultTTL:     1 * time.Hour,
		assetTTL:       30 * time.Minute,
		discoveryTTL:   10 * time.Minute,
		aggregationTTL: 5 * time.Minute,
	}
}

// Asset caching methods

// GetAsset retrieves an asset from cache
func (c *RedisCache) GetAsset(ctx context.Context, assetID uuid.UUID) (*entity.Asset, error) {
	key := c.assetKey(assetID)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		c.logger.Error("Failed to get asset from cache", zap.String("asset_id", assetID.String()), zap.Error(err))
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	var asset entity.Asset
	if err := json.Unmarshal([]byte(data), &asset); err != nil {
		c.logger.Error("Failed to unmarshal asset from cache", zap.String("asset_id", assetID.String()), zap.Error(err))
		return nil, fmt.Errorf("cache unmarshal failed: %w", err)
	}

	c.logger.Debug("Asset retrieved from cache", zap.String("asset_id", assetID.String()))
	return &asset, nil
}

// SetAsset stores an asset in cache
func (c *RedisCache) SetAsset(ctx context.Context, asset *entity.Asset) error {
	key := c.assetKey(asset.ID)
	
	data, err := json.Marshal(asset)
	if err != nil {
		c.logger.Error("Failed to marshal asset for cache", zap.String("asset_id", asset.ID.String()), zap.Error(err))
		return fmt.Errorf("cache marshal failed: %w", err)
	}

	err = c.client.Set(ctx, key, data, c.assetTTL).Err()
	if err != nil {
		c.logger.Error("Failed to set asset in cache", zap.String("asset_id", asset.ID.String()), zap.Error(err))
		return fmt.Errorf("cache set failed: %w", err)
	}

	c.logger.Debug("Asset stored in cache", zap.String("asset_id", asset.ID.String()))
	return nil
}

// DeleteAsset removes an asset from cache
func (c *RedisCache) DeleteAsset(ctx context.Context, assetID uuid.UUID) error {
	key := c.assetKey(assetID)
	
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		c.logger.Error("Failed to delete asset from cache", zap.String("asset_id", assetID.String()), zap.Error(err))
		return fmt.Errorf("cache delete failed: %w", err)
	}

	c.logger.Debug("Asset deleted from cache", zap.String("asset_id", assetID.String()))
	return nil
}

// GetAssetsByTenant retrieves multiple assets for a tenant from cache
func (c *RedisCache) GetAssetsByTenant(ctx context.Context, tenantID uuid.UUID, limit int) ([]*entity.Asset, error) {
	pattern := c.tenantAssetPattern(tenantID)
	
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		c.logger.Error("Failed to get tenant asset keys from cache", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return nil, fmt.Errorf("cache keys failed: %w", err)
	}

	if len(keys) == 0 {
		return []*entity.Asset{}, nil
	}

	// Limit the number of keys if specified
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}

	// Get all assets in a pipeline for efficiency
	pipe := c.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.Get(ctx, key)
	}

	_, err = pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		c.logger.Error("Failed to execute pipeline for tenant assets", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return nil, fmt.Errorf("cache pipeline failed: %w", err)
	}

	var assets []*entity.Asset
	for i, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil {
			if err == redis.Nil {
				continue // Skip missing keys
			}
			c.logger.Warn("Failed to get asset from pipeline", zap.String("key", keys[i]), zap.Error(err))
			continue
		}

		var asset entity.Asset
		if err := json.Unmarshal([]byte(data), &asset); err != nil {
			c.logger.Warn("Failed to unmarshal asset from pipeline", zap.String("key", keys[i]), zap.Error(err))
			continue
		}

		assets = append(assets, &asset)
	}

	c.logger.Debug("Retrieved tenant assets from cache", 
		zap.String("tenant_id", tenantID.String()), 
		zap.Int("count", len(assets)))

	return assets, nil
}

// SetAssetBatch stores multiple assets in cache using a pipeline
func (c *RedisCache) SetAssetBatch(ctx context.Context, assets []*entity.Asset) error {
	if len(assets) == 0 {
		return nil
	}

	pipe := c.client.Pipeline()
	
	for _, asset := range assets {
		key := c.assetKey(asset.ID)
		
		data, err := json.Marshal(asset)
		if err != nil {
			c.logger.Warn("Failed to marshal asset for batch cache", zap.String("asset_id", asset.ID.String()), zap.Error(err))
			continue
		}

		pipe.Set(ctx, key, data, c.assetTTL)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		c.logger.Error("Failed to execute asset batch pipeline", zap.Int("count", len(assets)), zap.Error(err))
		return fmt.Errorf("cache batch set failed: %w", err)
	}

	c.logger.Debug("Asset batch stored in cache", zap.Int("count", len(assets)))
	return nil
}

// Discovery result caching

// GetDiscoveryResult retrieves a discovery result from cache
func (c *RedisCache) GetDiscoveryResult(ctx context.Context, requestID uuid.UUID) (map[string]interface{}, error) {
	key := c.discoveryResultKey(requestID)
	
	data, err := c.client.HGetAll(ctx, key).Result()
	if err != nil {
		c.logger.Error("Failed to get discovery result from cache", zap.String("request_id", requestID.String()), zap.Error(err))
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	if len(data) == 0 {
		return nil, nil // Cache miss
	}

	result := make(map[string]interface{})
	for field, value := range data {
		var jsonValue interface{}
		if err := json.Unmarshal([]byte(value), &jsonValue); err != nil {
			result[field] = value // Store as string if not JSON
		} else {
			result[field] = jsonValue
		}
	}

	c.logger.Debug("Discovery result retrieved from cache", zap.String("request_id", requestID.String()))
	return result, nil
}

// SetDiscoveryResult stores a discovery result in cache
func (c *RedisCache) SetDiscoveryResult(ctx context.Context, requestID uuid.UUID, result map[string]interface{}) error {
	key := c.discoveryResultKey(requestID)
	
	// Convert all values to JSON strings
	fields := make(map[string]interface{})
	for field, value := range result {
		if data, err := json.Marshal(value); err == nil {
			fields[field] = string(data)
		} else {
			fields[field] = fmt.Sprintf("%v", value)
		}
	}

	err := c.client.HMSet(ctx, key, fields).Err()
	if err != nil {
		c.logger.Error("Failed to set discovery result in cache", zap.String("request_id", requestID.String()), zap.Error(err))
		return fmt.Errorf("cache set failed: %w", err)
	}

	// Set expiration
	c.client.Expire(ctx, key, c.discoveryTTL)

	c.logger.Debug("Discovery result stored in cache", zap.String("request_id", requestID.String()))
	return nil
}

// UpdateDiscoveryProgress updates discovery progress in cache
func (c *RedisCache) UpdateDiscoveryProgress(ctx context.Context, requestID uuid.UUID, progress map[string]interface{}) error {
	key := c.discoveryProgressKey(requestID)
	
	// Convert progress to JSON
	data, err := json.Marshal(progress)
	if err != nil {
		c.logger.Error("Failed to marshal discovery progress", zap.String("request_id", requestID.String()), zap.Error(err))
		return fmt.Errorf("marshal failed: %w", err)
	}

	err = c.client.Set(ctx, key, data, c.discoveryTTL).Err()
	if err != nil {
		c.logger.Error("Failed to update discovery progress in cache", zap.String("request_id", requestID.String()), zap.Error(err))
		return fmt.Errorf("cache update failed: %w", err)
	}

	c.logger.Debug("Discovery progress updated in cache", zap.String("request_id", requestID.String()))
	return nil
}

// GetDiscoveryProgress retrieves discovery progress from cache
func (c *RedisCache) GetDiscoveryProgress(ctx context.Context, requestID uuid.UUID) (map[string]interface{}, error) {
	key := c.discoveryProgressKey(requestID)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		c.logger.Error("Failed to get discovery progress from cache", zap.String("request_id", requestID.String()), zap.Error(err))
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	var progress map[string]interface{}
	if err := json.Unmarshal([]byte(data), &progress); err != nil {
		c.logger.Error("Failed to unmarshal discovery progress", zap.String("request_id", requestID.String()), zap.Error(err))
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	c.logger.Debug("Discovery progress retrieved from cache", zap.String("request_id", requestID.String()))
	return progress, nil
}

// Aggregation caching

// GetAggregation retrieves aggregation data from cache
func (c *RedisCache) GetAggregation(ctx context.Context, tenantID uuid.UUID, aggregationType string) (map[string]interface{}, error) {
	key := c.aggregationKey(tenantID, aggregationType)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		c.logger.Error("Failed to get aggregation from cache", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("type", aggregationType), 
			zap.Error(err))
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	var aggregation map[string]interface{}
	if err := json.Unmarshal([]byte(data), &aggregation); err != nil {
		c.logger.Error("Failed to unmarshal aggregation", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("type", aggregationType), 
			zap.Error(err))
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	c.logger.Debug("Aggregation retrieved from cache", 
		zap.String("tenant_id", tenantID.String()), 
		zap.String("type", aggregationType))
	
	return aggregation, nil
}

// SetAggregation stores aggregation data in cache
func (c *RedisCache) SetAggregation(ctx context.Context, tenantID uuid.UUID, aggregationType string, data map[string]interface{}) error {
	key := c.aggregationKey(tenantID, aggregationType)
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		c.logger.Error("Failed to marshal aggregation", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("type", aggregationType), 
			zap.Error(err))
		return fmt.Errorf("marshal failed: %w", err)
	}

	err = c.client.Set(ctx, key, jsonData, c.aggregationTTL).Err()
	if err != nil {
		c.logger.Error("Failed to set aggregation in cache", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("type", aggregationType), 
			zap.Error(err))
		return fmt.Errorf("cache set failed: %w", err)
	}

	c.logger.Debug("Aggregation stored in cache", 
		zap.String("tenant_id", tenantID.String()), 
		zap.String("type", aggregationType))
	
	return nil
}

// Search result caching

// GetSearchResults retrieves search results from cache
func (c *RedisCache) GetSearchResults(ctx context.Context, tenantID uuid.UUID, query string, filters string) ([]*entity.Asset, error) {
	key := c.searchResultKey(tenantID, query, filters)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		c.logger.Error("Failed to get search results from cache", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("query", query), 
			zap.Error(err))
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	var assets []*entity.Asset
	if err := json.Unmarshal([]byte(data), &assets); err != nil {
		c.logger.Error("Failed to unmarshal search results", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("query", query), 
			zap.Error(err))
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	c.logger.Debug("Search results retrieved from cache", 
		zap.String("tenant_id", tenantID.String()), 
		zap.String("query", query),
		zap.Int("count", len(assets)))
	
	return assets, nil
}

// SetSearchResults stores search results in cache
func (c *RedisCache) SetSearchResults(ctx context.Context, tenantID uuid.UUID, query string, filters string, assets []*entity.Asset) error {
	key := c.searchResultKey(tenantID, query, filters)
	
	data, err := json.Marshal(assets)
	if err != nil {
		c.logger.Error("Failed to marshal search results", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("query", query), 
			zap.Error(err))
		return fmt.Errorf("marshal failed: %w", err)
	}

	// Search results have shorter TTL since they can become stale quickly
	searchTTL := c.aggregationTTL
	err = c.client.Set(ctx, key, data, searchTTL).Err()
	if err != nil {
		c.logger.Error("Failed to set search results in cache", 
			zap.String("tenant_id", tenantID.String()), 
			zap.String("query", query), 
			zap.Error(err))
		return fmt.Errorf("cache set failed: %w", err)
	}

	c.logger.Debug("Search results stored in cache", 
		zap.String("tenant_id", tenantID.String()), 
		zap.String("query", query),
		zap.Int("count", len(assets)))
	
	return nil
}

// Network topology caching

// GetNetworkTopology retrieves network topology data from cache
func (c *RedisCache) GetNetworkTopology(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	key := c.networkTopologyKey(tenantID)
	
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Cache miss
		}
		c.logger.Error("Failed to get network topology from cache", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	var topology map[string]interface{}
	if err := json.Unmarshal([]byte(data), &topology); err != nil {
		c.logger.Error("Failed to unmarshal network topology", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	c.logger.Debug("Network topology retrieved from cache", zap.String("tenant_id", tenantID.String()))
	return topology, nil
}

// SetNetworkTopology stores network topology data in cache
func (c *RedisCache) SetNetworkTopology(ctx context.Context, tenantID uuid.UUID, topology map[string]interface{}) error {
	key := c.networkTopologyKey(tenantID)
	
	data, err := json.Marshal(topology)
	if err != nil {
		c.logger.Error("Failed to marshal network topology", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return fmt.Errorf("marshal failed: %w", err)
	}

	// Network topology changes infrequently, so longer TTL
	topologyTTL := c.defaultTTL * 2
	err = c.client.Set(ctx, key, data, topologyTTL).Err()
	if err != nil {
		c.logger.Error("Failed to set network topology in cache", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return fmt.Errorf("cache set failed: %w", err)
	}

	c.logger.Debug("Network topology stored in cache", zap.String("tenant_id", tenantID.String()))
	return nil
}

// Cache invalidation methods

// InvalidateAsset removes an asset from cache
func (c *RedisCache) InvalidateAsset(ctx context.Context, assetID uuid.UUID) error {
	return c.DeleteAsset(ctx, assetID)
}

// InvalidateTenantAssets removes all assets for a tenant from cache
func (c *RedisCache) InvalidateTenantAssets(ctx context.Context, tenantID uuid.UUID) error {
	pattern := c.tenantAssetPattern(tenantID)
	
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		c.logger.Error("Failed to get tenant asset keys for invalidation", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return fmt.Errorf("cache keys failed: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	err = c.client.Del(ctx, keys...).Err()
	if err != nil {
		c.logger.Error("Failed to invalidate tenant assets", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return fmt.Errorf("cache delete failed: %w", err)
	}

	c.logger.Debug("Tenant assets invalidated from cache", 
		zap.String("tenant_id", tenantID.String()), 
		zap.Int("count", len(keys)))
	
	return nil
}

// InvalidateDiscoveryResult removes a discovery result from cache
func (c *RedisCache) InvalidateDiscoveryResult(ctx context.Context, requestID uuid.UUID) error {
	key := c.discoveryResultKey(requestID)
	
	err := c.client.Del(ctx, key).Err()
	if err != nil {
		c.logger.Error("Failed to invalidate discovery result", zap.String("request_id", requestID.String()), zap.Error(err))
		return fmt.Errorf("cache delete failed: %w", err)
	}

	// Also invalidate progress
	progressKey := c.discoveryProgressKey(requestID)
	c.client.Del(ctx, progressKey)

	c.logger.Debug("Discovery result invalidated from cache", zap.String("request_id", requestID.String()))
	return nil
}

// InvalidateAggregations removes all aggregation data for a tenant
func (c *RedisCache) InvalidateAggregations(ctx context.Context, tenantID uuid.UUID) error {
	pattern := c.aggregationPattern(tenantID)
	
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		c.logger.Error("Failed to get aggregation keys for invalidation", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return fmt.Errorf("cache keys failed: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	err = c.client.Del(ctx, keys...).Err()
	if err != nil {
		c.logger.Error("Failed to invalidate aggregations", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		return fmt.Errorf("cache delete failed: %w", err)
	}

	c.logger.Debug("Aggregations invalidated from cache", 
		zap.String("tenant_id", tenantID.String()), 
		zap.Int("count", len(keys)))
	
	return nil
}

// Cache management methods

// GetCacheStats returns cache statistics
func (c *RedisCache) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	info, err := c.client.Info(ctx, "memory", "stats").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache stats: %w", err)
	}

	// Parse Redis INFO output (simplified)
	stats := make(map[string]interface{})
	lines := strings.Split(info, "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				stats[key] = value
			}
		}
	}

	return stats, nil
}

// ClearCache clears all cache data (use with caution)
func (c *RedisCache) ClearCache(ctx context.Context) error {
	err := c.client.FlushDB(ctx).Err()
	if err != nil {
		c.logger.Error("Failed to clear cache", zap.Error(err))
		return fmt.Errorf("cache clear failed: %w", err)
	}

	c.logger.Warn("Cache cleared")
	return nil
}

// HealthCheck checks if the cache is accessible
func (c *RedisCache) HealthCheck(ctx context.Context) error {
	_, err := c.client.Ping(ctx).Result()
	if err != nil {
		c.logger.Error("Cache health check failed", zap.Error(err))
		return fmt.Errorf("cache health check failed: %w", err)
	}

	return nil
}

// Close closes the cache connection
func (c *RedisCache) Close() error {
	return c.client.Close()
}

// Key generation methods

func (c *RedisCache) assetKey(assetID uuid.UUID) string {
	return fmt.Sprintf("asset:%s", assetID.String())
}

func (c *RedisCache) tenantAssetPattern(tenantID uuid.UUID) string {
	return fmt.Sprintf("asset:*:tenant:%s", tenantID.String())
}

func (c *RedisCache) discoveryResultKey(requestID uuid.UUID) string {
	return fmt.Sprintf("discovery:result:%s", requestID.String())
}

func (c *RedisCache) discoveryProgressKey(requestID uuid.UUID) string {
	return fmt.Sprintf("discovery:progress:%s", requestID.String())
}

func (c *RedisCache) aggregationKey(tenantID uuid.UUID, aggregationType string) string {
	return fmt.Sprintf("aggregation:%s:%s", tenantID.String(), aggregationType)
}

func (c *RedisCache) aggregationPattern(tenantID uuid.UUID) string {
	return fmt.Sprintf("aggregation:%s:*", tenantID.String())
}

func (c *RedisCache) searchResultKey(tenantID uuid.UUID, query string, filters string) string {
	// Create a hash of the query and filters for the key
	queryHash := fmt.Sprintf("%x", []byte(query+filters))
	return fmt.Sprintf("search:%s:%s", tenantID.String(), queryHash)
}

func (c *RedisCache) networkTopologyKey(tenantID uuid.UUID) string {
	return fmt.Sprintf("topology:%s", tenantID.String())
}