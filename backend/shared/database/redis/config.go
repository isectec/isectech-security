package redis

import (
	"fmt"
	"time"

	"github.com/isectech/platform/shared/common"
)

// Config represents Redis configuration for iSECTECH cybersecurity platform
type Config struct {
	// Connection settings
	Addresses         []string      `yaml:"addresses" json:"addresses"`
	Password          string        `yaml:"password" json:"password"`
	DB                int           `yaml:"db" json:"db"`
	DialTimeout       time.Duration `yaml:"dial_timeout" json:"dial_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout" json:"write_timeout"`
	
	// Connection pool settings
	PoolSize        int           `yaml:"pool_size" json:"pool_size"`
	MinIdleConns    int           `yaml:"min_idle_conns" json:"min_idle_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" json:"conn_max_idle_time"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	PoolTimeout     time.Duration `yaml:"pool_timeout" json:"pool_timeout"`
	
	// Cluster configuration
	Cluster         ClusterConfig  `yaml:"cluster" json:"cluster"`
	
	// Sentinel configuration
	Sentinel        SentinelConfig `yaml:"sentinel" json:"sentinel"`
	
	// Streams configuration
	Streams         StreamsConfig  `yaml:"streams" json:"streams"`
	
	// Cache configuration
	Cache           CacheConfig    `yaml:"cache" json:"cache"`
	
	// Security settings
	Security        SecurityConfig `yaml:"security" json:"security"`
	
	// Monitoring and observability
	EnableMetrics   bool           `yaml:"enable_metrics" json:"enable_metrics"`
	EnableTracing   bool           `yaml:"enable_tracing" json:"enable_tracing"`
	SlowLogThreshold time.Duration `yaml:"slow_log_threshold" json:"slow_log_threshold"`
	
	// Circuit breaker settings
	CircuitBreaker  CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
	
	// Retry settings
	RetryConfig     RetryConfig    `yaml:"retry_config" json:"retry_config"`
}

// ClusterConfig defines Redis Cluster configuration
type ClusterConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	MaxRedirects      int      `yaml:"max_redirects" json:"max_redirects"`
	ReadOnly          bool     `yaml:"read_only" json:"read_only"`
	RouteByLatency    bool     `yaml:"route_by_latency" json:"route_by_latency"`
	RouteRandomly     bool     `yaml:"route_randomly" json:"route_randomly"`
	ClusterSlots      []string `yaml:"cluster_slots" json:"cluster_slots"`
}

// SentinelConfig defines Redis Sentinel configuration for high availability
type SentinelConfig struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	MasterName      string   `yaml:"master_name" json:"master_name"`
	SentinelAddrs   []string `yaml:"sentinel_addrs" json:"sentinel_addrs"`
	SentinelPassword string  `yaml:"sentinel_password" json:"sentinel_password"`
	FailoverTimeout time.Duration `yaml:"failover_timeout" json:"failover_timeout"`
}

// StreamsConfig defines Redis Streams configuration for event processing
type StreamsConfig struct {
	Enabled           bool                    `yaml:"enabled" json:"enabled"`
	ConsumerGroups    map[string]ConsumerGroupConfig `yaml:"consumer_groups" json:"consumer_groups"`
	MaxLength         int64                   `yaml:"max_length" json:"max_length"`
	ApproxMaxLength   bool                    `yaml:"approx_max_length" json:"approx_max_length"`
	BlockingTimeout   time.Duration           `yaml:"blocking_timeout" json:"blocking_timeout"`
	ProcessingTimeout time.Duration           `yaml:"processing_timeout" json:"processing_timeout"`
}

// ConsumerGroupConfig defines configuration for Redis Stream consumer groups
type ConsumerGroupConfig struct {
	StreamName    string        `yaml:"stream_name" json:"stream_name"`
	GroupName     string        `yaml:"group_name" json:"group_name"`
	ConsumerName  string        `yaml:"consumer_name" json:"consumer_name"`
	BatchSize     int64         `yaml:"batch_size" json:"batch_size"`
	IdleTimeout   time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
	RetryInterval time.Duration `yaml:"retry_interval" json:"retry_interval"`
	MaxRetries    int           `yaml:"max_retries" json:"max_retries"`
}

// CacheConfig defines caching behavior and eviction policies
type CacheConfig struct {
	DefaultTTL       time.Duration            `yaml:"default_ttl" json:"default_ttl"`
	MaxMemory        string                   `yaml:"max_memory" json:"max_memory"`
	EvictionPolicy   string                   `yaml:"eviction_policy" json:"eviction_policy"`
	Prefixes         map[string]PrefixConfig  `yaml:"prefixes" json:"prefixes"`
	Compression      CompressionConfig        `yaml:"compression" json:"compression"`
	Serialization    string                   `yaml:"serialization" json:"serialization"`
}

// PrefixConfig defines configuration for specific cache key prefixes
type PrefixConfig struct {
	TTL           time.Duration `yaml:"ttl" json:"ttl"`
	MaxSize       int64         `yaml:"max_size" json:"max_size"`
	Compress      bool          `yaml:"compress" json:"compress"`
	Encrypt       bool          `yaml:"encrypt" json:"encrypt"`
	TenantIsolated bool         `yaml:"tenant_isolated" json:"tenant_isolated"`
}

// CompressionConfig defines compression settings
type CompressionConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Algorithm   string `yaml:"algorithm" json:"algorithm"` // gzip, lz4, snappy
	Threshold   int    `yaml:"threshold" json:"threshold"` // Minimum size to compress
	Level       int    `yaml:"level" json:"level"`         // Compression level
}

// SecurityConfig defines security settings for Redis
type SecurityConfig struct {
	EnableTLS        bool          `yaml:"enable_tls" json:"enable_tls"`
	TLSConfig        TLSConfig     `yaml:"tls_config" json:"tls_config"`
	EnableEncryption bool          `yaml:"enable_encryption" json:"enable_encryption"`
	EncryptionKey    string        `yaml:"encryption_key" json:"encryption_key"`
	TenantIsolation  bool          `yaml:"tenant_isolation" json:"tenant_isolation"`
	ACLConfig        ACLConfig     `yaml:"acl_config" json:"acl_config"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	CertFile           string `yaml:"cert_file" json:"cert_file"`
	KeyFile            string `yaml:"key_file" json:"key_file"`
	CAFile             string `yaml:"ca_file" json:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// ACLConfig defines Access Control List configuration
type ACLConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Users     map[string]ACLUser `yaml:"users" json:"users"`
	Rules     []ACLRule         `yaml:"rules" json:"rules"`
}

// ACLUser defines Redis ACL user configuration
type ACLUser struct {
	Password   string   `yaml:"password" json:"password"`
	Categories []string `yaml:"categories" json:"categories"`
	Commands   []string `yaml:"commands" json:"commands"`
	Keys       []string `yaml:"keys" json:"keys"`
	Channels   []string `yaml:"channels" json:"channels"`
}

// ACLRule defines Redis ACL rules
type ACLRule struct {
	User       string   `yaml:"user" json:"user"`
	TenantID   string   `yaml:"tenant_id" json:"tenant_id"`
	KeyPattern string   `yaml:"key_pattern" json:"key_pattern"`
	Commands   []string `yaml:"commands" json:"commands"`
}

// CircuitBreakerConfig defines circuit breaker settings
type CircuitBreakerConfig struct {
	MaxRequests      uint32        `yaml:"max_requests" json:"max_requests"`
	Interval         time.Duration `yaml:"interval" json:"interval"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	FailureThreshold uint32        `yaml:"failure_threshold" json:"failure_threshold"`
}

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxAttempts     int           `yaml:"max_attempts" json:"max_attempts"`
	InitialInterval time.Duration `yaml:"initial_interval" json:"initial_interval"`
	MaxInterval     time.Duration `yaml:"max_interval" json:"max_interval"`
	Multiplier      float64       `yaml:"multiplier" json:"multiplier"`
}

// DefaultConfig returns a production-ready Redis configuration for iSECTECH
func DefaultConfig() *Config {
	return &Config{
		Addresses:       []string{"localhost:6379"},
		Password:        "",
		DB:              0,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		PoolSize:        100,
		MinIdleConns:    10,
		MaxIdleConns:    30,
		ConnMaxIdleTime: 30 * time.Minute,
		ConnMaxLifetime: time.Hour,
		PoolTimeout:     30 * time.Second,
		
		Cluster: ClusterConfig{
			Enabled:        false,
			MaxRedirects:   3,
			ReadOnly:       false,
			RouteByLatency: true,
			RouteRandomly:  false,
		},
		
		Sentinel: SentinelConfig{
			Enabled:         false,
			MasterName:      "isectech-master",
			SentinelAddrs:   []string{"localhost:26379"},
			FailoverTimeout: 3 * time.Second,
		},
		
		Streams: StreamsConfig{
			Enabled: true,
			ConsumerGroups: map[string]ConsumerGroupConfig{
				"security-events": {
					StreamName:    "security:events",
					GroupName:     "security-processors",
					ConsumerName:  "processor-1",
					BatchSize:     10,
					IdleTimeout:   5 * time.Minute,
					RetryInterval: 30 * time.Second,
					MaxRetries:    3,
				},
				"threat-intel": {
					StreamName:    "threat:intelligence",
					GroupName:     "threat-processors",
					ConsumerName:  "threat-processor-1",
					BatchSize:     5,
					IdleTimeout:   10 * time.Minute,
					RetryInterval: time.Minute,
					MaxRetries:    5,
				},
				"audit-events": {
					StreamName:    "audit:events",
					GroupName:     "audit-processors",
					ConsumerName:  "audit-processor-1",
					BatchSize:     20,
					IdleTimeout:   time.Minute,
					RetryInterval: 10 * time.Second,
					MaxRetries:    2,
				},
			},
			MaxLength:         10000,
			ApproxMaxLength:   true,
			BlockingTimeout:   5 * time.Second,
			ProcessingTimeout: 30 * time.Second,
		},
		
		Cache: CacheConfig{
			DefaultTTL:     time.Hour,
			MaxMemory:      "2gb",
			EvictionPolicy: "allkeys-lru",
			Prefixes: map[string]PrefixConfig{
				"session:": {
					TTL:            30 * time.Minute,
					MaxSize:        1024 * 1024, // 1MB
					Compress:       false,
					Encrypt:        true,
					TenantIsolated: true,
				},
				"threat:": {
					TTL:            24 * time.Hour,
					MaxSize:        10 * 1024 * 1024, // 10MB
					Compress:       true,
					Encrypt:        true,
					TenantIsolated: true,
				},
				"asset:": {
					TTL:            6 * time.Hour,
					MaxSize:        5 * 1024 * 1024, // 5MB
					Compress:       true,
					Encrypt:        false,
					TenantIsolated: true,
				},
				"compliance:": {
					TTL:            7 * 24 * time.Hour, // 1 week
					MaxSize:        2 * 1024 * 1024,   // 2MB
					Compress:       true,
					Encrypt:        true,
					TenantIsolated: true,
				},
				"metrics:": {
					TTL:            15 * time.Minute,
					MaxSize:        512 * 1024, // 512KB
					Compress:       false,
					Encrypt:        false,
					TenantIsolated: false,
				},
			},
			Compression: CompressionConfig{
				Enabled:   true,
				Algorithm: "lz4",
				Threshold: 1024, // 1KB
				Level:     1,
			},
			Serialization: "msgpack",
		},
		
		Security: SecurityConfig{
			EnableTLS: true,
			TLSConfig: TLSConfig{
				CertFile:           "/etc/redis/certs/redis.crt",
				KeyFile:            "/etc/redis/certs/redis.key",
				CAFile:             "/etc/redis/certs/ca.crt",
				InsecureSkipVerify: false,
			},
			EnableEncryption: true,
			TenantIsolation:  true,
			ACLConfig: ACLConfig{
				Enabled: true,
				Users: map[string]ACLUser{
					"isectech-api": {
						Categories: []string{"+@all", "-@dangerous"},
						Commands:   []string{"+get", "+set", "+del", "+exists", "+expire", "+ttl"},
						Keys:       []string{"~*"},
						Channels:   []string{"&*"},
					},
					"isectech-readonly": {
						Categories: []string{"+@read"},
						Commands:   []string{"+get", "+exists", "+ttl", "+scan"},
						Keys:       []string{"~*"},
						Channels:   []string{"&*"},
					},
				},
			},
		},
		
		EnableMetrics:    true,
		EnableTracing:    true,
		SlowLogThreshold: 100 * time.Millisecond,
		
		CircuitBreaker: CircuitBreakerConfig{
			MaxRequests:      10,
			Interval:         30 * time.Second,
			Timeout:          60 * time.Second,
			FailureThreshold: 5,
		},
		
		RetryConfig: RetryConfig{
			MaxAttempts:     3,
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     5 * time.Second,
			Multiplier:      2.0,
		},
	}
}

// LoadConfig loads Redis configuration from various sources
func LoadConfig() (*Config, error) {
	config := DefaultConfig()
	
	// Load from environment variables and config files
	if err := common.LoadConfigFromSources("redis", config); err != nil {
		return nil, fmt.Errorf("failed to load Redis config: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid Redis config: %w", err)
	}
	
	return config, nil
}

// Validate validates the Redis configuration
func (c *Config) Validate() error {
	if len(c.Addresses) == 0 {
		return fmt.Errorf("at least one Redis address is required")
	}
	
	if c.PoolSize <= 0 {
		return fmt.Errorf("pool size must be positive")
	}
	
	if c.MinIdleConns < 0 {
		return fmt.Errorf("min idle connections must be non-negative")
	}
	
	if c.MinIdleConns > c.PoolSize {
		return fmt.Errorf("min idle connections cannot exceed pool size")
	}
	
	// Validate cluster configuration
	if c.Cluster.Enabled && c.Sentinel.Enabled {
		return fmt.Errorf("cluster and sentinel cannot be enabled simultaneously")
	}
	
	// Validate sentinel configuration
	if c.Sentinel.Enabled {
		if c.Sentinel.MasterName == "" {
			return fmt.Errorf("sentinel master name is required when sentinel is enabled")
		}
		if len(c.Sentinel.SentinelAddrs) == 0 {
			return fmt.Errorf("sentinel addresses are required when sentinel is enabled")
		}
	}
	
	// Validate streams configuration
	if c.Streams.Enabled {
		for name, group := range c.Streams.ConsumerGroups {
			if group.StreamName == "" {
				return fmt.Errorf("stream name is required for consumer group %s", name)
			}
			if group.GroupName == "" {
				return fmt.Errorf("group name is required for consumer group %s", name)
			}
			if group.ConsumerName == "" {
				return fmt.Errorf("consumer name is required for consumer group %s", name)
			}
		}
	}
	
	// Validate cache configuration
	if c.Cache.DefaultTTL <= 0 {
		return fmt.Errorf("default TTL must be positive")
	}
	
	validEvictionPolicies := map[string]bool{
		"noeviction":     true,
		"allkeys-lru":    true,
		"allkeys-lfu":    true,
		"allkeys-random": true,
		"volatile-lru":   true,
		"volatile-lfu":   true,
		"volatile-random": true,
		"volatile-ttl":   true,
	}
	
	if !validEvictionPolicies[c.Cache.EvictionPolicy] {
		return fmt.Errorf("invalid eviction policy: %s", c.Cache.EvictionPolicy)
	}
	
	return nil
}

// GetCacheKey generates a cache key with tenant isolation if enabled
func (c *Config) GetCacheKey(prefix, key, tenantID string) string {
	prefixConfig, exists := c.Cache.Prefixes[prefix]
	if exists && prefixConfig.TenantIsolated && tenantID != "" {
		return fmt.Sprintf("%s%s:%s", prefix, tenantID, key)
	}
	return fmt.Sprintf("%s%s", prefix, key)
}

// GetStreamName returns the full stream name for a consumer group
func (c *Config) GetStreamName(consumerGroup string) string {
	if group, exists := c.Streams.ConsumerGroups[consumerGroup]; exists {
		return group.StreamName
	}
	return ""
}

// IsClusterMode returns true if Redis is configured in cluster mode
func (c *Config) IsClusterMode() bool {
	return c.Cluster.Enabled
}

// IsSentinelMode returns true if Redis is configured with Sentinel
func (c *Config) IsSentinelMode() bool {
	return c.Sentinel.Enabled
}