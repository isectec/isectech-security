package dal

import (
	"fmt"
	"time"

	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/database/elasticsearch"
	"github.com/isectech/platform/shared/database/encryption"
	"github.com/isectech/platform/shared/database/mongodb"
	"github.com/isectech/platform/shared/database/postgres"
	"github.com/isectech/platform/shared/database/redis"
)

// Config represents the Data Access Layer configuration for iSECTECH
type Config struct {
	// Database configurations
	PostgreSQL    *postgres.Config    `yaml:"postgresql" json:"postgresql"`
	MongoDB       *mongodb.Config     `yaml:"mongodb" json:"mongodb"`
	Redis         *redis.Config       `yaml:"redis" json:"redis"`
	Elasticsearch *elasticsearch.Config `yaml:"elasticsearch" json:"elasticsearch"`
	
	// DAL-specific settings
	ConnectionPooling ConnectionPoolConfig `yaml:"connection_pooling" json:"connection_pooling"`
	Resilience       ResilienceConfig     `yaml:"resilience" json:"resilience"`
	Caching          CachingConfig        `yaml:"caching" json:"caching"`
	Monitoring       MonitoringConfig     `yaml:"monitoring" json:"monitoring"`
	Transactions     TransactionConfig    `yaml:"transactions" json:"transactions"`
	Encryption       *encryption.Config   `yaml:"encryption" json:"encryption"`
	
	// Performance settings
	MaxConcurrentOperations int           `yaml:"max_concurrent_operations" json:"max_concurrent_operations"`
	OperationTimeout        time.Duration `yaml:"operation_timeout" json:"operation_timeout"`
	BatchSize               int           `yaml:"batch_size" json:"batch_size"`
	
	// Security settings
	EnableEncryption    bool   `yaml:"enable_encryption" json:"enable_encryption"`
	EncryptionKey       string `yaml:"encryption_key" json:"encryption_key"`
	EnableAuditLogging  bool   `yaml:"enable_audit_logging" json:"enable_audit_logging"`
}

// ConnectionPoolConfig defines connection pooling settings
type ConnectionPoolConfig struct {
	PostgreSQL PostgreSQLPoolConfig `yaml:"postgresql" json:"postgresql"`
	MongoDB    MongoDBPoolConfig    `yaml:"mongodb" json:"mongodb"`
	Redis      RedisPoolConfig      `yaml:"redis" json:"redis"`
	Elasticsearch ElasticsearchPoolConfig `yaml:"elasticsearch" json:"elasticsearch"`
	
	// Global pool settings
	MaxIdleConnections    int           `yaml:"max_idle_connections" json:"max_idle_connections"`
	MaxOpenConnections    int           `yaml:"max_open_connections" json:"max_open_connections"`
	ConnectionMaxLifetime time.Duration `yaml:"connection_max_lifetime" json:"connection_max_lifetime"`
	ConnectionMaxIdleTime time.Duration `yaml:"connection_max_idle_time" json:"connection_max_idle_time"`
}

// PostgreSQLPoolConfig defines PostgreSQL-specific pooling
type PostgreSQLPoolConfig struct {
	MaxConnections       int           `yaml:"max_connections" json:"max_connections"`
	MinConnections       int           `yaml:"min_connections" json:"min_connections"`
	AcquireTimeout       time.Duration `yaml:"acquire_timeout" json:"acquire_timeout"`
	MaxConnLifetime      time.Duration `yaml:"max_conn_lifetime" json:"max_conn_lifetime"`
	MaxConnIdleTime      time.Duration `yaml:"max_conn_idle_time" json:"max_conn_idle_time"`
	HealthCheckPeriod    time.Duration `yaml:"health_check_period" json:"health_check_period"`
}

// MongoDBPoolConfig defines MongoDB-specific pooling
type MongoDBPoolConfig struct {
	MaxPoolSize        uint64        `yaml:"max_pool_size" json:"max_pool_size"`
	MinPoolSize        uint64        `yaml:"min_pool_size" json:"min_pool_size"`
	MaxConnIdleTime    time.Duration `yaml:"max_conn_idle_time" json:"max_conn_idle_time"`
	MaxConnLifetime    time.Duration `yaml:"max_conn_lifetime" json:"max_conn_lifetime"`
	ServerSelectionTimeout time.Duration `yaml:"server_selection_timeout" json:"server_selection_timeout"`
}

// RedisPoolConfig defines Redis-specific pooling
type RedisPoolConfig struct {
	PoolSize      int           `yaml:"pool_size" json:"pool_size"`
	MinIdleConns  int           `yaml:"min_idle_conns" json:"min_idle_conns"`
	MaxIdleConns  int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	PoolTimeout   time.Duration `yaml:"pool_timeout" json:"pool_timeout"`
	IdleTimeout   time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
}

// ElasticsearchPoolConfig defines Elasticsearch-specific pooling
type ElasticsearchPoolConfig struct {
	MaxIdleConns        int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	MaxIdleConnsPerHost int           `yaml:"max_idle_conns_per_host" json:"max_idle_conns_per_host"`
	KeepAlive           time.Duration `yaml:"keep_alive" json:"keep_alive"`
	RequestTimeout      time.Duration `yaml:"request_timeout" json:"request_timeout"`
}

// ResilienceConfig defines resilience patterns
type ResilienceConfig struct {
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
	Retry          RetryConfig          `yaml:"retry" json:"retry"`
	Timeout        TimeoutConfig        `yaml:"timeout" json:"timeout"`
	Bulkhead       BulkheadConfig       `yaml:"bulkhead" json:"bulkhead"`
	Fallback       FallbackConfig       `yaml:"fallback" json:"fallback"`
}

// CircuitBreakerConfig defines circuit breaker settings per database
type CircuitBreakerConfig struct {
	PostgreSQL    DatabaseCircuitBreaker `yaml:"postgresql" json:"postgresql"`
	MongoDB       DatabaseCircuitBreaker `yaml:"mongodb" json:"mongodb"`
	Redis         DatabaseCircuitBreaker `yaml:"redis" json:"redis"`
	Elasticsearch DatabaseCircuitBreaker `yaml:"elasticsearch" json:"elasticsearch"`
}

// DatabaseCircuitBreaker defines circuit breaker for a specific database
type DatabaseCircuitBreaker struct {
	Enabled              bool          `yaml:"enabled" json:"enabled"`
	FailureThreshold     uint32        `yaml:"failure_threshold" json:"failure_threshold"`
	SuccessThreshold     uint32        `yaml:"success_threshold" json:"success_threshold"`
	Timeout              time.Duration `yaml:"timeout" json:"timeout"`
	MaxRequests          uint32        `yaml:"max_requests" json:"max_requests"`
	Interval             time.Duration `yaml:"interval" json:"interval"`
	OnStateChangeEnabled bool          `yaml:"on_state_change_enabled" json:"on_state_change_enabled"`
}

// RetryConfig defines retry policies
type RetryConfig struct {
	PostgreSQL    DatabaseRetry `yaml:"postgresql" json:"postgresql"`
	MongoDB       DatabaseRetry `yaml:"mongodb" json:"mongodb"`
	Redis         DatabaseRetry `yaml:"redis" json:"redis"`
	Elasticsearch DatabaseRetry `yaml:"elasticsearch" json:"elasticsearch"`
}

// DatabaseRetry defines retry settings for a specific database
type DatabaseRetry struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	MaxAttempts     int           `yaml:"max_attempts" json:"max_attempts"`
	InitialInterval time.Duration `yaml:"initial_interval" json:"initial_interval"`
	MaxInterval     time.Duration `yaml:"max_interval" json:"max_interval"`
	Multiplier      float64       `yaml:"multiplier" json:"multiplier"`
	Jitter          bool          `yaml:"jitter" json:"jitter"`
	RetryableErrors []string      `yaml:"retryable_errors" json:"retryable_errors"`
}

// TimeoutConfig defines timeout settings
type TimeoutConfig struct {
	DefaultTimeout    time.Duration            `yaml:"default_timeout" json:"default_timeout"`
	OperationTimeouts map[string]time.Duration `yaml:"operation_timeouts" json:"operation_timeouts"`
}

// BulkheadConfig defines bulkhead isolation patterns
type BulkheadConfig struct {
	Enabled                bool `yaml:"enabled" json:"enabled"`
	MaxConcurrentPostgreSQL int  `yaml:"max_concurrent_postgresql" json:"max_concurrent_postgresql"`
	MaxConcurrentMongoDB   int  `yaml:"max_concurrent_mongodb" json:"max_concurrent_mongodb"`
	MaxConcurrentRedis     int  `yaml:"max_concurrent_redis" json:"max_concurrent_redis"`
	MaxConcurrentElasticsearch int `yaml:"max_concurrent_elasticsearch" json:"max_concurrent_elasticsearch"`
}

// FallbackConfig defines fallback strategies
type FallbackConfig struct {
	Enabled                  bool          `yaml:"enabled" json:"enabled"`
	CacheOnDatabaseFailure   bool          `yaml:"cache_on_database_failure" json:"cache_on_database_failure"`
	ReadFromSecondaryOnFailure bool        `yaml:"read_from_secondary_on_failure" json:"read_from_secondary_on_failure"`
	FallbackTimeout          time.Duration `yaml:"fallback_timeout" json:"fallback_timeout"`
}

// CachingConfig defines caching strategies
type CachingConfig struct {
	Enabled           bool                      `yaml:"enabled" json:"enabled"`
	DefaultTTL        time.Duration             `yaml:"default_ttl" json:"default_ttl"`
	WriteThrough      bool                      `yaml:"write_through" json:"write_through"`
	WriteBack         bool                      `yaml:"write_back" json:"write_back"`
	ReadThrough       bool                      `yaml:"read_through" json:"read_through"`
	CacheStrategies   map[string]CacheStrategy  `yaml:"cache_strategies" json:"cache_strategies"`
	InvalidationRules map[string]InvalidationRule `yaml:"invalidation_rules" json:"invalidation_rules"`
}

// CacheStrategy defines caching strategy for specific data types
type CacheStrategy struct {
	TTL            time.Duration `yaml:"ttl" json:"ttl"`
	WriteThrough   bool          `yaml:"write_through" json:"write_through"`
	WriteBack      bool          `yaml:"write_back" json:"write_back"`
	ReadThrough    bool          `yaml:"read_through" json:"read_through"`
	Compress       bool          `yaml:"compress" json:"compress"`
	Encrypt        bool          `yaml:"encrypt" json:"encrypt"`
	MaxSize        int64         `yaml:"max_size" json:"max_size"`
	EvictionPolicy string        `yaml:"eviction_policy" json:"eviction_policy"`
}

// InvalidationRule defines cache invalidation rules
type InvalidationRule struct {
	OnUpdate   []string `yaml:"on_update" json:"on_update"`
	OnDelete   []string `yaml:"on_delete" json:"on_delete"`
	OnInsert   []string `yaml:"on_insert" json:"on_insert"`
	TimeToLive time.Duration `yaml:"time_to_live" json:"time_to_live"`
}

// MonitoringConfig defines monitoring and observability
type MonitoringConfig struct {
	Enabled              bool          `yaml:"enabled" json:"enabled"`
	MetricsInterval      time.Duration `yaml:"metrics_interval" json:"metrics_interval"`
	HealthCheckInterval  time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	SlowQueryThreshold   time.Duration `yaml:"slow_query_threshold" json:"slow_query_threshold"`
	TraceSlowQueries     bool          `yaml:"trace_slow_queries" json:"trace_slow_queries"`
	ConnectionPoolMetrics bool         `yaml:"connection_pool_metrics" json:"connection_pool_metrics"`
	QueryMetrics         bool          `yaml:"query_metrics" json:"query_metrics"`
	ErrorMetrics         bool          `yaml:"error_metrics" json:"error_metrics"`
}

// TransactionConfig defines transaction coordination
type TransactionConfig struct {
	Enabled              bool          `yaml:"enabled" json:"enabled"`
	DefaultIsolationLevel string       `yaml:"default_isolation_level" json:"default_isolation_level"`
	TransactionTimeout   time.Duration `yaml:"transaction_timeout" json:"transaction_timeout"`
	MaxRetries           int           `yaml:"max_retries" json:"max_retries"`
	EnableDistributed    bool          `yaml:"enable_distributed" json:"enable_distributed"`
	CoordinatorTimeout   time.Duration `yaml:"coordinator_timeout" json:"coordinator_timeout"`
}

// DefaultConfig returns a production-ready DAL configuration for iSECTECH
func DefaultConfig() *Config {
	return &Config{
		ConnectionPooling: ConnectionPoolConfig{
			PostgreSQL: PostgreSQLPoolConfig{
				MaxConnections:    50,
				MinConnections:    10,
				AcquireTimeout:    30 * time.Second,
				MaxConnLifetime:   time.Hour,
				MaxConnIdleTime:   30 * time.Minute,
				HealthCheckPeriod: 5 * time.Minute,
			},
			MongoDB: MongoDBPoolConfig{
				MaxPoolSize:        100,
				MinPoolSize:        10,
				MaxConnIdleTime:    30 * time.Minute,
				MaxConnLifetime:    time.Hour,
				ServerSelectionTimeout: 30 * time.Second,
			},
			Redis: RedisPoolConfig{
				PoolSize:     50,
				MinIdleConns: 10,
				MaxIdleConns: 30,
				PoolTimeout:  30 * time.Second,
				IdleTimeout:  30 * time.Minute,
			},
			Elasticsearch: ElasticsearchPoolConfig{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				KeepAlive:           30 * time.Second,
				RequestTimeout:      90 * time.Second,
			},
			MaxIdleConnections:    200,
			MaxOpenConnections:    500,
			ConnectionMaxLifetime: time.Hour,
			ConnectionMaxIdleTime: 30 * time.Minute,
		},
		
		Resilience: ResilienceConfig{
			CircuitBreaker: CircuitBreakerConfig{
				PostgreSQL: DatabaseCircuitBreaker{
					Enabled:              true,
					FailureThreshold:     5,
					SuccessThreshold:     3,
					Timeout:              60 * time.Second,
					MaxRequests:          10,
					Interval:             30 * time.Second,
					OnStateChangeEnabled: true,
				},
				MongoDB: DatabaseCircuitBreaker{
					Enabled:              true,
					FailureThreshold:     5,
					SuccessThreshold:     3,
					Timeout:              60 * time.Second,
					MaxRequests:          10,
					Interval:             30 * time.Second,
					OnStateChangeEnabled: true,
				},
				Redis: DatabaseCircuitBreaker{
					Enabled:              true,
					FailureThreshold:     5,
					SuccessThreshold:     3,
					Timeout:              60 * time.Second,
					MaxRequests:          10,
					Interval:             30 * time.Second,
					OnStateChangeEnabled: true,
				},
				Elasticsearch: DatabaseCircuitBreaker{
					Enabled:              true,
					FailureThreshold:     5,
					SuccessThreshold:     3,
					Timeout:              60 * time.Second,
					MaxRequests:          10,
					Interval:             30 * time.Second,
					OnStateChangeEnabled: true,
				},
			},
			Retry: RetryConfig{
				PostgreSQL: DatabaseRetry{
					Enabled:         true,
					MaxAttempts:     3,
					InitialInterval: 100 * time.Millisecond,
					MaxInterval:     5 * time.Second,
					Multiplier:      2.0,
					Jitter:          true,
					RetryableErrors: []string{"connection", "timeout", "temporary"},
				},
				MongoDB: DatabaseRetry{
					Enabled:         true,
					MaxAttempts:     3,
					InitialInterval: 100 * time.Millisecond,
					MaxInterval:     5 * time.Second,
					Multiplier:      2.0,
					Jitter:          true,
					RetryableErrors: []string{"network", "timeout", "not master"},
				},
				Redis: DatabaseRetry{
					Enabled:         true,
					MaxAttempts:     3,
					InitialInterval: 50 * time.Millisecond,
					MaxInterval:     2 * time.Second,
					Multiplier:      2.0,
					Jitter:          true,
					RetryableErrors: []string{"connection", "timeout", "readonly"},
				},
				Elasticsearch: DatabaseRetry{
					Enabled:         true,
					MaxAttempts:     3,
					InitialInterval: 200 * time.Millisecond,
					MaxInterval:     10 * time.Second,
					Multiplier:      2.0,
					Jitter:          true,
					RetryableErrors: []string{"429", "502", "503", "504"},
				},
			},
			Timeout: TimeoutConfig{
				DefaultTimeout: 30 * time.Second,
				OperationTimeouts: map[string]time.Duration{
					"read":        10 * time.Second,
					"write":       30 * time.Second,
					"bulk":        60 * time.Second,
					"search":      15 * time.Second,
					"aggregation": 45 * time.Second,
				},
			},
			Bulkhead: BulkheadConfig{
				Enabled:                    true,
				MaxConcurrentPostgreSQL:    50,
				MaxConcurrentMongoDB:       50,
				MaxConcurrentRedis:         100,
				MaxConcurrentElasticsearch: 30,
			},
			Fallback: FallbackConfig{
				Enabled:                    true,
				CacheOnDatabaseFailure:     true,
				ReadFromSecondaryOnFailure: true,
				FallbackTimeout:            5 * time.Second,
			},
		},
		
		Caching: CachingConfig{
			Enabled:      true,
			DefaultTTL:   time.Hour,
			WriteThrough: true,
			WriteBack:    false,
			ReadThrough:  true,
			CacheStrategies: map[string]CacheStrategy{
				"session": {
					TTL:            30 * time.Minute,
					WriteThrough:   true,
					ReadThrough:    true,
					Encrypt:        true,
					MaxSize:        1024 * 1024, // 1MB
					EvictionPolicy: "lru",
				},
				"threat": {
					TTL:            24 * time.Hour,
					WriteThrough:   true,
					ReadThrough:    true,
					Compress:       true,
					Encrypt:        true,
					MaxSize:        10 * 1024 * 1024, // 10MB
					EvictionPolicy: "lru",
				},
				"asset": {
					TTL:            6 * time.Hour,
					WriteThrough:   true,
					ReadThrough:    true,
					Compress:       true,
					MaxSize:        5 * 1024 * 1024, // 5MB
					EvictionPolicy: "lru",
				},
				"user": {
					TTL:            2 * time.Hour,
					WriteThrough:   true,
					ReadThrough:    true,
					Encrypt:        true,
					MaxSize:        512 * 1024, // 512KB
					EvictionPolicy: "lru",
				},
			},
			InvalidationRules: map[string]InvalidationRule{
				"user": {
					OnUpdate:   []string{"session", "user"},
					OnDelete:   []string{"session", "user"},
					TimeToLive: time.Hour,
				},
				"asset": {
					OnUpdate:   []string{"asset", "threat"},
					OnDelete:   []string{"asset"},
					TimeToLive: 6 * time.Hour,
				},
			},
		},
		
		Monitoring: MonitoringConfig{
			Enabled:               true,
			MetricsInterval:       30 * time.Second,
			HealthCheckInterval:   10 * time.Second,
			SlowQueryThreshold:    1 * time.Second,
			TraceSlowQueries:      true,
			ConnectionPoolMetrics: true,
			QueryMetrics:          true,
			ErrorMetrics:          true,
		},
		
		Transactions: TransactionConfig{
			Enabled:               true,
			DefaultIsolationLevel: "READ_COMMITTED",
			TransactionTimeout:    30 * time.Second,
			MaxRetries:            3,
			EnableDistributed:     false, // Complex for initial implementation
			CoordinatorTimeout:    10 * time.Second,
		},
		
		MaxConcurrentOperations: 1000,
		OperationTimeout:        30 * time.Second,
		BatchSize:               100,
		EnableEncryption:        true,
		EnableAuditLogging:      true,
		Encryption:              encryption.DefaultConfig(),
	}
}

// LoadConfig loads DAL configuration from various sources
func LoadConfig() (*Config, error) {
	config := DefaultConfig()
	
	// Load database configurations
	pgConfig, err := postgres.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load PostgreSQL config: %w", err)
	}
	config.PostgreSQL = pgConfig
	
	mongoConfig, err := mongodb.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load MongoDB config: %w", err)
	}
	config.MongoDB = mongoConfig
	
	redisConfig, err := redis.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Redis config: %w", err)
	}
	config.Redis = redisConfig
	
	esConfig, err := elasticsearch.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Elasticsearch config: %w", err)
	}
	config.Elasticsearch = esConfig
	
	// Load DAL-specific configuration
	if err := common.LoadConfigFromSources("dal", config); err != nil {
		return nil, fmt.Errorf("failed to load DAL config: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid DAL config: %w", err)
	}
	
	return config, nil
}

// Validate validates the DAL configuration
func (c *Config) Validate() error {
	if c.MaxConcurrentOperations <= 0 {
		return fmt.Errorf("max concurrent operations must be positive")
	}
	
	if c.OperationTimeout <= 0 {
		return fmt.Errorf("operation timeout must be positive")
	}
	
	if c.BatchSize <= 0 {
		return fmt.Errorf("batch size must be positive")
	}
	
	// Validate connection pooling
	if c.ConnectionPooling.MaxOpenConnections < c.ConnectionPooling.MaxIdleConnections {
		return fmt.Errorf("max open connections must be >= max idle connections")
	}
	
	// Validate timeout configurations
	if c.Resilience.Timeout.DefaultTimeout <= 0 {
		return fmt.Errorf("default timeout must be positive")
	}
	
	// Validate retry configurations
	for dbName, retry := range map[string]DatabaseRetry{
		"postgresql":    c.Resilience.Retry.PostgreSQL,
		"mongodb":       c.Resilience.Retry.MongoDB,
		"redis":         c.Resilience.Retry.Redis,
		"elasticsearch": c.Resilience.Retry.Elasticsearch,
	} {
		if retry.Enabled {
			if retry.MaxAttempts <= 0 {
				return fmt.Errorf("%s retry max attempts must be positive", dbName)
			}
			if retry.InitialInterval <= 0 {
				return fmt.Errorf("%s retry initial interval must be positive", dbName)
			}
			if retry.Multiplier <= 1.0 {
				return fmt.Errorf("%s retry multiplier must be > 1.0", dbName)
			}
		}
	}
	
	// Validate circuit breaker configurations
	for dbName, cb := range map[string]DatabaseCircuitBreaker{
		"postgresql":    c.Resilience.CircuitBreaker.PostgreSQL,
		"mongodb":       c.Resilience.CircuitBreaker.MongoDB,
		"redis":         c.Resilience.CircuitBreaker.Redis,
		"elasticsearch": c.Resilience.CircuitBreaker.Elasticsearch,
	} {
		if cb.Enabled {
			if cb.FailureThreshold == 0 {
				return fmt.Errorf("%s circuit breaker failure threshold must be positive", dbName)
			}
			if cb.Timeout <= 0 {
				return fmt.Errorf("%s circuit breaker timeout must be positive", dbName)
			}
		}
	}
	
	// Validate caching configuration
	if c.Caching.Enabled {
		if c.Caching.DefaultTTL <= 0 {
			return fmt.Errorf("default cache TTL must be positive")
		}
		
		for strategy, config := range c.Caching.CacheStrategies {
			if config.TTL <= 0 {
				return fmt.Errorf("cache strategy %s TTL must be positive", strategy)
			}
			if config.MaxSize <= 0 {
				return fmt.Errorf("cache strategy %s max size must be positive", strategy)
			}
		}
	}
	
	return nil
}