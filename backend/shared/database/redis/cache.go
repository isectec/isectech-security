package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// CacheManager handles intelligent caching operations for iSECTECH
type CacheManager struct {
	client    *Client
	config    *Config
	logger    *zap.Logger
	encryptor *Encryptor
}

// CacheEntry represents a cached entry with metadata
type CacheEntry struct {
	Key        string                 `json:"key"`
	Value      interface{}            `json:"value"`
	TTL        time.Duration          `json:"ttl"`
	CreatedAt  time.Time              `json:"created_at"`
	AccessedAt time.Time              `json:"accessed_at"`
	Metadata   map[string]interface{} `json:"metadata"`
	Compressed bool                   `json:"compressed"`
	Encrypted  bool                   `json:"encrypted"`
	TenantID   string                 `json:"tenant_id"`
}

// SessionData represents user session data
type SessionData struct {
	UserID        string                 `json:"user_id"`
	TenantID      string                 `json:"tenant_id"`
	Role          string                 `json:"role"`
	Permissions   []string               `json:"permissions"`
	SecurityTags  map[string]string      `json:"security_tags"`
	LoginTime     time.Time              `json:"login_time"`
	LastActivity  time.Time              `json:"last_activity"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	MFAVerified   bool                   `json:"mfa_verified"`
	SessionToken  string                 `json:"session_token"`
	RefreshToken  string                 `json:"refresh_token"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ThreatData represents cached threat intelligence data
type ThreatData struct {
	ThreatID      string                 `json:"threat_id"`
	TenantID      string                 `json:"tenant_id"`
	ThreatType    string                 `json:"threat_type"`
	Severity      string                 `json:"severity"`
	Indicators    []ThreatIndicator      `json:"indicators"`
	MITREAttack   []string               `json:"mitre_attack"`
	Confidence    float64                `json:"confidence"`
	Source        string                 `json:"source"`
	LastUpdated   time.Time              `json:"last_updated"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// AssetData represents cached asset information
type AssetData struct {
	AssetID       string                 `json:"asset_id"`
	TenantID      string                 `json:"tenant_id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	IPAddresses   []string               `json:"ip_addresses"`
	Criticality   string                 `json:"criticality"`
	LastScanTime  time.Time              `json:"last_scan_time"`
	SecurityState string                 `json:"security_state"`
	Vulnerabilities []string             `json:"vulnerabilities"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ComplianceData represents cached compliance assessment data
type ComplianceData struct {
	AssessmentID  string                 `json:"assessment_id"`
	TenantID      string                 `json:"tenant_id"`
	Framework     string                 `json:"framework"`
	Status        string                 `json:"status"`
	Score         int                    `json:"score"`
	LastAssessed  time.Time              `json:"last_assessed"`
	NextDue       time.Time              `json:"next_due"`
	Findings      []string               `json:"findings"`
	Remediation   []string               `json:"remediation"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// MetricsData represents cached performance metrics
type MetricsData struct {
	ServiceName   string                 `json:"service_name"`
	Timestamp     time.Time              `json:"timestamp"`
	Metrics       map[string]float64     `json:"metrics"`
	Tags          map[string]string      `json:"tags"`
	Environment   string                 `json:"environment"`
	Instance      string                 `json:"instance"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// NewCacheManager creates a new cache manager
func NewCacheManager(client *Client, config *Config, logger *zap.Logger) (*CacheManager, error) {
	cm := &CacheManager{
		client:    client,
		config:    config,
		logger:    logger,
		encryptor: client.encryptor,
	}

	// Initialize cache configuration in Redis
	if err := cm.initializeCacheConfig(); err != nil {
		return nil, fmt.Errorf("failed to initialize cache config: %w", err)
	}

	logger.Info("Cache manager initialized",
		zap.String("eviction_policy", config.Cache.EvictionPolicy),
		zap.String("max_memory", config.Cache.MaxMemory),
		zap.Duration("default_ttl", config.Cache.DefaultTTL))

	return cm, nil
}

// initializeCacheConfig sets up Redis configuration for caching
func (cm *CacheManager) initializeCacheConfig() error {
	ctx := context.Background()

	// Set max memory policy
	if cm.config.Cache.MaxMemory != "" {
		err := cm.client.client.ConfigSet(ctx, "maxmemory", cm.config.Cache.MaxMemory).Err()
		if err != nil {
			cm.logger.Warn("Failed to set maxmemory config", zap.Error(err))
		}
	}

	// Set eviction policy
	err := cm.client.client.ConfigSet(ctx, "maxmemory-policy", cm.config.Cache.EvictionPolicy).Err()
	if err != nil {
		cm.logger.Warn("Failed to set eviction policy", zap.Error(err))
	}

	return nil
}

// StoreSession stores user session data with encryption
func (cm *CacheManager) StoreSession(ctx context.Context, sessionID string, session *SessionData) error {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: session.TenantID,
			UserID:   session.UserID,
		},
		TTL:     cm.getPrefixTTL("session:"),
		Encrypt: true,
		Prefix:  "session:",
	}

	return cm.storeObject(ctx, sessionID, session, opts)
}

// GetSession retrieves user session data
func (cm *CacheManager) GetSession(ctx context.Context, sessionID string, tenantID string) (*SessionData, error) {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: tenantID,
		},
		Encrypt: true,
		Prefix:  "session:",
	}

	var session SessionData
	err := cm.getObject(ctx, sessionID, &session, opts)
	if err != nil {
		return nil, err
	}

	// Update last activity
	session.LastActivity = time.Now()
	cm.StoreSession(ctx, sessionID, &session)

	return &session, nil
}

// StoreThreatData stores threat intelligence data
func (cm *CacheManager) StoreThreatData(ctx context.Context, threatID string, threat *ThreatData) error {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: threat.TenantID,
		},
		TTL:      cm.getPrefixTTL("threat:"),
		Compress: true,
		Encrypt:  true,
		Prefix:   "threat:",
	}

	return cm.storeObject(ctx, threatID, threat, opts)
}

// GetThreatData retrieves threat intelligence data
func (cm *CacheManager) GetThreatData(ctx context.Context, threatID string, tenantID string) (*ThreatData, error) {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: tenantID,
		},
		Compress: true,
		Encrypt:  true,
		Prefix:   "threat:",
	}

	var threat ThreatData
	err := cm.getObject(ctx, threatID, &threat, opts)
	if err != nil {
		return nil, err
	}

	return &threat, nil
}

// StoreAssetData stores asset information
func (cm *CacheManager) StoreAssetData(ctx context.Context, assetID string, asset *AssetData) error {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: asset.TenantID,
		},
		TTL:      cm.getPrefixTTL("asset:"),
		Compress: true,
		Prefix:   "asset:",
	}

	return cm.storeObject(ctx, assetID, asset, opts)
}

// GetAssetData retrieves asset information
func (cm *CacheManager) GetAssetData(ctx context.Context, assetID string, tenantID string) (*AssetData, error) {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: tenantID,
		},
		Compress: true,
		Prefix:   "asset:",
	}

	var asset AssetData
	err := cm.getObject(ctx, assetID, &asset, opts)
	if err != nil {
		return nil, err
	}

	return &asset, nil
}

// StoreComplianceData stores compliance assessment data
func (cm *CacheManager) StoreComplianceData(ctx context.Context, assessmentID string, compliance *ComplianceData) error {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: compliance.TenantID,
		},
		TTL:      cm.getPrefixTTL("compliance:"),
		Compress: true,
		Encrypt:  true,
		Prefix:   "compliance:",
	}

	return cm.storeObject(ctx, assessmentID, compliance, opts)
}

// GetComplianceData retrieves compliance assessment data
func (cm *CacheManager) GetComplianceData(ctx context.Context, assessmentID string, tenantID string) (*ComplianceData, error) {
	opts := &CacheOptions{
		Tenant: &TenantContext{
			TenantID: tenantID,
		},
		Compress: true,
		Encrypt:  true,
		Prefix:   "compliance:",
	}

	var compliance ComplianceData
	err := cm.getObject(ctx, assessmentID, &compliance, opts)
	if err != nil {
		return nil, err
	}

	return &compliance, nil
}

// StoreMetrics stores performance metrics with short TTL
func (cm *CacheManager) StoreMetrics(ctx context.Context, key string, metrics *MetricsData) error {
	opts := &CacheOptions{
		TTL:    cm.getPrefixTTL("metrics:"),
		Prefix: "metrics:",
	}

	return cm.storeObject(ctx, key, metrics, opts)
}

// GetMetrics retrieves performance metrics
func (cm *CacheManager) GetMetrics(ctx context.Context, key string) (*MetricsData, error) {
	opts := &CacheOptions{
		Prefix: "metrics:",
	}

	var metrics MetricsData
	err := cm.getObject(ctx, key, &metrics, opts)
	if err != nil {
		return nil, err
	}

	return &metrics, nil
}

// InvalidateSession removes a user session
func (cm *CacheManager) InvalidateSession(ctx context.Context, sessionID string, tenantID string) error {
	key := cm.config.GetCacheKey("session:", sessionID, tenantID)
	return cm.client.Del(ctx, key)
}

// InvalidateTenant removes all cached data for a tenant
func (cm *CacheManager) InvalidateTenant(ctx context.Context, tenantID string) error {
	patterns := []string{
		fmt.Sprintf("session:%s:*", tenantID),
		fmt.Sprintf("threat:%s:*", tenantID),
		fmt.Sprintf("asset:%s:*", tenantID),
		fmt.Sprintf("compliance:%s:*", tenantID),
	}

	for _, pattern := range patterns {
		keys, err := cm.scanKeys(ctx, pattern)
		if err != nil {
			cm.logger.Error("Failed to scan keys for pattern",
				zap.String("pattern", pattern),
				zap.Error(err))
			continue
		}

		if len(keys) > 0 {
			err = cm.client.Del(ctx, keys...)
			if err != nil {
				cm.logger.Error("Failed to delete keys",
					zap.Strings("keys", keys),
					zap.Error(err))
			} else {
				cm.logger.Info("Invalidated tenant cache",
					zap.String("tenant_id", tenantID),
					zap.String("pattern", pattern),
					zap.Int("key_count", len(keys)))
			}
		}
	}

	return nil
}

// GetCacheStats returns cache statistics
func (cm *CacheManager) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	info, err := cm.client.client.Info(ctx, "memory").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}

	stats := map[string]interface{}{
		"memory_info": info,
	}

	// Get key counts by prefix
	prefixCounts := make(map[string]int)
	for prefix := range cm.config.Cache.Prefixes {
		pattern := fmt.Sprintf("%s*", prefix)
		keys, err := cm.scanKeys(ctx, pattern)
		if err != nil {
			cm.logger.Warn("Failed to count keys for prefix",
				zap.String("prefix", prefix),
				zap.Error(err))
			continue
		}
		prefixCounts[prefix] = len(keys)
	}
	stats["prefix_counts"] = prefixCounts

	return stats, nil
}

// storeObject stores an object in cache with serialization and optional compression/encryption
func (cm *CacheManager) storeObject(ctx context.Context, key string, obj interface{}, opts *CacheOptions) error {
	// Serialize object
	data, err := SerializeObject(obj, cm.config.Cache.Serialization)
	if err != nil {
		return fmt.Errorf("failed to serialize object: %w", err)
	}

	// Compress if enabled
	if opts.Compress && cm.config.Cache.Compression.Enabled {
		if len(data) >= cm.config.Cache.Compression.Threshold {
			compressed, err := CompressData(data, cm.config.Cache.Compression)
			if err != nil {
				cm.logger.Warn("Failed to compress data", zap.Error(err))
			} else {
				data = compressed
			}
		}
	}

	// Encrypt if enabled
	if opts.Encrypt && cm.encryptor != nil {
		encrypted, err := cm.encryptor.Encrypt(string(data))
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
		data = []byte(encrypted)
	}

	// Store in Redis
	return cm.client.Set(ctx, key, data, opts)
}

// getObject retrieves and deserializes an object from cache
func (cm *CacheManager) getObject(ctx context.Context, key string, obj interface{}, opts *CacheOptions) error {
	// Get from Redis
	data, err := cm.client.Get(ctx, key, opts)
	if err != nil {
		return err
	}

	dataBytes := []byte(data)

	// Decrypt if enabled
	if opts.Encrypt && cm.encryptor != nil {
		decrypted, err := cm.encryptor.Decrypt(data)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}
		dataBytes = []byte(decrypted)
	}

	// Decompress if needed
	if opts.Compress && cm.config.Cache.Compression.Enabled {
		decompressed, err := DecompressData(dataBytes, cm.config.Cache.Compression)
		if err != nil {
			cm.logger.Warn("Failed to decompress data, using as-is", zap.Error(err))
		} else {
			dataBytes = decompressed
		}
	}

	// Deserialize object
	return DeserializeObject(dataBytes, obj, cm.config.Cache.Serialization)
}

// scanKeys scans for keys matching a pattern
func (cm *CacheManager) scanKeys(ctx context.Context, pattern string) ([]string, error) {
	var keys []string
	var cursor uint64

	for {
		scanKeys, nextCursor, err := cm.client.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, err
		}

		keys = append(keys, scanKeys...)
		cursor = nextCursor

		if cursor == 0 {
			break
		}
	}

	return keys, nil
}

// getPrefixTTL returns the TTL for a specific prefix
func (cm *CacheManager) getPrefixTTL(prefix string) time.Duration {
	if prefixConfig, exists := cm.config.Cache.Prefixes[prefix]; exists {
		return prefixConfig.TTL
	}
	return cm.config.Cache.DefaultTTL
}

// CleanupExpired removes expired entries (mainly for development/testing)
func (cm *CacheManager) CleanupExpired(ctx context.Context) error {
	// Redis automatically handles TTL expiration, but this can be used for manual cleanup
	info, err := cm.client.client.Info(ctx, "keyspace").Result()
	if err != nil {
		return fmt.Errorf("failed to get keyspace info: %w", err)
	}

	cm.logger.Info("Cache cleanup completed", zap.String("keyspace_info", info))
	return nil
}