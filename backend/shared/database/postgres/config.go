package postgres

import (
	"fmt"
	"time"

	"github.com/isectech/platform/shared/common"
)

// ShardConfig represents configuration for a PostgreSQL shard
type ShardConfig struct {
	Name            string        `yaml:"name" json:"name"`
	Host            string        `yaml:"host" json:"host"`
	Port            int           `yaml:"port" json:"port"`
	Database        string        `yaml:"database" json:"database"`
	Username        string        `yaml:"username" json:"username"`
	Password        string        `yaml:"password" json:"password"`
	SSLMode         string        `yaml:"ssl_mode" json:"ssl_mode"`
	MaxConns        int           `yaml:"max_conns" json:"max_conns"`
	MinConns        int           `yaml:"min_conns" json:"min_conns"`
	MaxConnLifetime time.Duration `yaml:"max_conn_lifetime" json:"max_conn_lifetime"`
	MaxConnIdleTime time.Duration `yaml:"max_conn_idle_time" json:"max_conn_idle_time"`
	ShardKey        string        `yaml:"shard_key" json:"shard_key"`
	ShardRange      ShardRange    `yaml:"shard_range" json:"shard_range"`
	ReadReplicas    []ReplicaConfig `yaml:"read_replicas" json:"read_replicas"`
}

// ShardRange defines the range of values this shard handles
type ShardRange struct {
	Min interface{} `yaml:"min" json:"min"`
	Max interface{} `yaml:"max" json:"max"`
}

// ReplicaConfig represents configuration for a read replica
type ReplicaConfig struct {
	Name     string `yaml:"name" json:"name"`
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	Priority int    `yaml:"priority" json:"priority"` // Lower number = higher priority
	Weight   int    `yaml:"weight" json:"weight"`     // Load balancing weight
}

// Config represents the complete PostgreSQL configuration
type Config struct {
	// Sharding configuration
	Shards []ShardConfig `yaml:"shards" json:"shards"`
	
	// Global connection settings
	ConnectionTimeout   time.Duration `yaml:"connection_timeout" json:"connection_timeout"`
	QueryTimeout        time.Duration `yaml:"query_timeout" json:"query_timeout"`
	
	// Security settings
	EnableRowLevelSecurity bool   `yaml:"enable_row_level_security" json:"enable_row_level_security"`
	EncryptionKey          string `yaml:"encryption_key" json:"encryption_key"`
	
	// Monitoring and observability
	EnableMetrics      bool `yaml:"enable_metrics" json:"enable_metrics"`
	EnableTracing      bool `yaml:"enable_tracing" json:"enable_tracing"`
	SlowQueryThreshold time.Duration `yaml:"slow_query_threshold" json:"slow_query_threshold"`
	
	// Circuit breaker settings
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
	
	// Retry settings
	RetryConfig RetryConfig `yaml:"retry_config" json:"retry_config"`
}

// CircuitBreakerConfig defines circuit breaker settings for database connections
type CircuitBreakerConfig struct {
	MaxRequests      uint32        `yaml:"max_requests" json:"max_requests"`
	Interval         time.Duration `yaml:"interval" json:"interval"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	FailureThreshold uint32        `yaml:"failure_threshold" json:"failure_threshold"`
}

// RetryConfig defines retry behavior for database operations
type RetryConfig struct {
	MaxAttempts     int           `yaml:"max_attempts" json:"max_attempts"`
	InitialInterval time.Duration `yaml:"initial_interval" json:"initial_interval"`
	MaxInterval     time.Duration `yaml:"max_interval" json:"max_interval"`
	Multiplier      float64       `yaml:"multiplier" json:"multiplier"`
}

// DefaultConfig returns a production-ready PostgreSQL configuration
func DefaultConfig() *Config {
	return &Config{
		ConnectionTimeout: 30 * time.Second,
		QueryTimeout:      60 * time.Second,
		EnableRowLevelSecurity: true,
		EnableMetrics:     true,
		EnableTracing:     true,
		SlowQueryThreshold: 1 * time.Second,
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

// LoadConfig loads PostgreSQL configuration from various sources
func LoadConfig() (*Config, error) {
	config := DefaultConfig()
	
	// Load from environment variables and config files
	if err := common.LoadConfigFromSources("postgres", config); err != nil {
		return nil, fmt.Errorf("failed to load PostgreSQL config: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid PostgreSQL config: %w", err)
	}
	
	return config, nil
}

// Validate validates the PostgreSQL configuration
func (c *Config) Validate() error {
	if len(c.Shards) == 0 {
		return fmt.Errorf("at least one shard must be configured")
	}
	
	for i, shard := range c.Shards {
		if err := shard.Validate(); err != nil {
			return fmt.Errorf("shard %d validation failed: %w", i, err)
		}
	}
	
	if c.ConnectionTimeout <= 0 {
		return fmt.Errorf("connection timeout must be positive")
	}
	
	if c.QueryTimeout <= 0 {
		return fmt.Errorf("query timeout must be positive")
	}
	
	return nil
}

// Validate validates a shard configuration
func (sc *ShardConfig) Validate() error {
	if sc.Name == "" {
		return fmt.Errorf("shard name is required")
	}
	
	if sc.Host == "" {
		return fmt.Errorf("shard host is required")
	}
	
	if sc.Port <= 0 || sc.Port > 65535 {
		return fmt.Errorf("shard port must be between 1 and 65535")
	}
	
	if sc.Database == "" {
		return fmt.Errorf("shard database is required")
	}
	
	if sc.Username == "" {
		return fmt.Errorf("shard username is required")
	}
	
	if sc.MaxConns <= 0 {
		return fmt.Errorf("max connections must be positive")
	}
	
	if sc.MinConns < 0 {
		return fmt.Errorf("min connections must be non-negative")
	}
	
	if sc.MinConns > sc.MaxConns {
		return fmt.Errorf("min connections cannot exceed max connections")
	}
	
	return nil
}

// DSN generates a PostgreSQL DSN for the shard
func (sc *ShardConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		sc.Host, sc.Port, sc.Username, sc.Password, sc.Database, sc.SSLMode,
	)
}

// GetShardForKey determines which shard should handle a given key
func (c *Config) GetShardForKey(key interface{}) (*ShardConfig, error) {
	// Implement hash-based sharding for strings
	if strKey, ok := key.(string); ok {
		return c.getShardForStringKey(strKey)
	}
	
	// Implement range-based sharding for numeric keys
	if numKey, ok := key.(int64); ok {
		return c.getShardForNumericKey(numKey)
	}
	
	return nil, fmt.Errorf("unsupported key type for sharding: %T", key)
}

// getShardForStringKey implements consistent hashing for string keys
func (c *Config) getShardForStringKey(key string) (*ShardConfig, error) {
	if len(c.Shards) == 0 {
		return nil, fmt.Errorf("no shards configured")
	}
	
	// Simple hash-based distribution
	hash := fnv32Hash(key)
	shardIndex := int(hash) % len(c.Shards)
	return &c.Shards[shardIndex], nil
}

// getShardForNumericKey implements range-based sharding for numeric keys
func (c *Config) getShardForNumericKey(key int64) (*ShardConfig, error) {
	for _, shard := range c.Shards {
		if shard.ShardRange.Min != nil && shard.ShardRange.Max != nil {
			if min, ok := shard.ShardRange.Min.(int64); ok {
				if max, ok := shard.ShardRange.Max.(int64); ok {
					if key >= min && key <= max {
						return &shard, nil
					}
				}
			}
		}
	}
	
	// Fallback to hash-based if no range matches
	return c.getShardForStringKey(fmt.Sprintf("%d", key))
}

// fnv32Hash implements FNV-1a 32-bit hash
func fnv32Hash(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	hash := uint32(offset32)
	for _, b := range []byte(s) {
		hash ^= uint32(b)
		hash *= prime32
	}
	return hash
}