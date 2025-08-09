package mongodb

import (
	"fmt"
	"time"

	"github.com/isectech/platform/shared/common"
)

// Config represents MongoDB configuration for iSECTECH
type Config struct {
	// Connection settings
	URI               string        `yaml:"uri" json:"uri"`
	Database          string        `yaml:"database" json:"database"`
	ConnectTimeout    time.Duration `yaml:"connect_timeout" json:"connect_timeout"`
	ServerSelectionTimeout time.Duration `yaml:"server_selection_timeout" json:"server_selection_timeout"`
	SocketTimeout     time.Duration `yaml:"socket_timeout" json:"socket_timeout"`
	
	// Connection pool settings
	MaxPoolSize     uint64 `yaml:"max_pool_size" json:"max_pool_size"`
	MinPoolSize     uint64 `yaml:"min_pool_size" json:"min_pool_size"`
	MaxIdleTime     time.Duration `yaml:"max_idle_time" json:"max_idle_time"`
	MaxConnIdleTime time.Duration `yaml:"max_conn_idle_time" json:"max_conn_idle_time"`
	
	// Replica set configuration
	ReplicaSet      string              `yaml:"replica_set" json:"replica_set"`
	ReadPreference  string              `yaml:"read_preference" json:"read_preference"`
	ReadConcern     string              `yaml:"read_concern" json:"read_concern"`
	WriteConcern    WriteConcernConfig  `yaml:"write_concern" json:"write_concern"`
	
	// Sharding configuration
	Sharding        ShardingConfig      `yaml:"sharding" json:"sharding"`
	
	// Security settings
	Security        SecurityConfig      `yaml:"security" json:"security"`
	
	// Time-series collections configuration
	TimeSeries      TimeSeriesConfig    `yaml:"time_series" json:"time_series"`
	
	// Monitoring and observability
	EnableMetrics   bool                `yaml:"enable_metrics" json:"enable_metrics"`
	EnableTracing   bool                `yaml:"enable_tracing" json:"enable_tracing"`
	SlowQueryThreshold time.Duration    `yaml:"slow_query_threshold" json:"slow_query_threshold"`
	
	// Circuit breaker settings
	CircuitBreaker  CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
	
	// Retry settings
	RetryConfig     RetryConfig         `yaml:"retry_config" json:"retry_config"`
}

// WriteConcernConfig defines write concern settings
type WriteConcernConfig struct {
	W        interface{} `yaml:"w" json:"w"`           // Can be int or string
	WTimeout time.Duration `yaml:"wtimeout" json:"wtimeout"`
	Journal  bool        `yaml:"journal" json:"journal"`
}

// ShardingConfig defines MongoDB sharding configuration
type ShardingConfig struct {
	Enabled       bool               `yaml:"enabled" json:"enabled"`
	ShardKey      string             `yaml:"shard_key" json:"shard_key"`
	Chunks        ChunkConfig        `yaml:"chunks" json:"chunks"`
	Balancer      BalancerConfig     `yaml:"balancer" json:"balancer"`
	ConfigServers []string           `yaml:"config_servers" json:"config_servers"`
	Mongos        []MongosConfig     `yaml:"mongos" json:"mongos"`
}

// ChunkConfig defines chunk management settings
type ChunkConfig struct {
	Size           int64 `yaml:"size" json:"size"`             // Chunk size in MB
	MaxChunkSize   int64 `yaml:"max_chunk_size" json:"max_chunk_size"`
	SplitThreshold int64 `yaml:"split_threshold" json:"split_threshold"`
}

// BalancerConfig defines balancer settings
type BalancerConfig struct {
	Enabled         bool `yaml:"enabled" json:"enabled"`
	ActiveWindow    ActiveWindowConfig `yaml:"active_window" json:"active_window"`
	ChunkMigrations int  `yaml:"chunk_migrations" json:"chunk_migrations"`
}

// ActiveWindowConfig defines when balancer is active
type ActiveWindowConfig struct {
	Start string `yaml:"start" json:"start"` // HH:MM format
	Stop  string `yaml:"stop" json:"stop"`   // HH:MM format
}

// MongosConfig defines mongos router configuration
type MongosConfig struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

// SecurityConfig defines security settings
type SecurityConfig struct {
	EnableEncryption     bool     `yaml:"enable_encryption" json:"enable_encryption"`
	EncryptionKeyFile    string   `yaml:"encryption_key_file" json:"encryption_key_file"`
	TLS                  TLSConfig `yaml:"tls" json:"tls"`
	Authentication       AuthConfig `yaml:"authentication" json:"authentication"`
	Authorization        AuthzConfig `yaml:"authorization" json:"authorization"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled            bool   `yaml:"enabled" json:"enabled"`
	CertificateFile    string `yaml:"certificate_file" json:"certificate_file"`
	PrivateKeyFile     string `yaml:"private_key_file" json:"private_key_file"`
	CAFile             string `yaml:"ca_file" json:"ca_file"`
	AllowInvalidCerts  bool   `yaml:"allow_invalid_certs" json:"allow_invalid_certs"`
}

// AuthConfig defines authentication settings
type AuthConfig struct {
	Mechanism string `yaml:"mechanism" json:"mechanism"`
	Source    string `yaml:"source" json:"source"`
	Username  string `yaml:"username" json:"username"`
	Password  string `yaml:"password" json:"password"`
}

// AuthzConfig defines authorization settings
type AuthzConfig struct {
	EnableRBAC       bool     `yaml:"enable_rbac" json:"enable_rbac"`
	DefaultRoles     []string `yaml:"default_roles" json:"default_roles"`
	TenantIsolation  bool     `yaml:"tenant_isolation" json:"tenant_isolation"`
}

// TimeSeriesConfig defines time-series collection settings
type TimeSeriesConfig struct {
	Collections map[string]TimeSeriesCollectionConfig `yaml:"collections" json:"collections"`
}

// TimeSeriesCollectionConfig defines configuration for a time-series collection
type TimeSeriesCollectionConfig struct {
	TimeField        string            `yaml:"time_field" json:"time_field"`
	MetaField        string            `yaml:"meta_field" json:"meta_field"`
	Granularity      string            `yaml:"granularity" json:"granularity"` // seconds, minutes, hours
	BucketMaxSpan    time.Duration     `yaml:"bucket_max_span" json:"bucket_max_span"`
	BucketRounding   string            `yaml:"bucket_rounding" json:"bucket_rounding"`
	ExpireAfterSeconds int64           `yaml:"expire_after_seconds" json:"expire_after_seconds"`
	Indexes          []IndexConfig     `yaml:"indexes" json:"indexes"`
}

// IndexConfig defines index configuration
type IndexConfig struct {
	Keys    map[string]int `yaml:"keys" json:"keys"`
	Options IndexOptions   `yaml:"options" json:"options"`
}

// IndexOptions defines index options
type IndexOptions struct {
	Name       string        `yaml:"name" json:"name"`
	Background bool          `yaml:"background" json:"background"`
	Unique     bool          `yaml:"unique" json:"unique"`
	Sparse     bool          `yaml:"sparse" json:"sparse"`
	TTL        time.Duration `yaml:"ttl" json:"ttl"`
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

// DefaultConfig returns a production-ready MongoDB configuration
func DefaultConfig() *Config {
	return &Config{
		URI:                    "mongodb://localhost:27017",
		Database:               "isectech",
		ConnectTimeout:         30 * time.Second,
		ServerSelectionTimeout: 30 * time.Second,
		SocketTimeout:          60 * time.Second,
		MaxPoolSize:            100,
		MinPoolSize:            5,
		MaxIdleTime:            30 * time.Minute,
		MaxConnIdleTime:        30 * time.Minute,
		ReplicaSet:             "",
		ReadPreference:         "primaryPreferred",
		ReadConcern:            "majority",
		WriteConcern: WriteConcernConfig{
			W:        "majority",
			WTimeout: 10 * time.Second,
			Journal:  true,
		},
		Sharding: ShardingConfig{
			Enabled:  false,
			ShardKey: "tenant_id",
			Chunks: ChunkConfig{
				Size:           64, // 64MB
				MaxChunkSize:   1024, // 1GB
				SplitThreshold: 512,  // 512MB
			},
			Balancer: BalancerConfig{
				Enabled: true,
				ActiveWindow: ActiveWindowConfig{
					Start: "02:00",
					Stop:  "06:00",
				},
				ChunkMigrations: 10,
			},
		},
		Security: SecurityConfig{
			EnableEncryption: true,
			TLS: TLSConfig{
				Enabled: true,
			},
			Authentication: AuthConfig{
				Mechanism: "SCRAM-SHA-256",
				Source:    "admin",
			},
			Authorization: AuthzConfig{
				EnableRBAC:      true,
				TenantIsolation: true,
				DefaultRoles:    []string{"readWrite"},
			},
		},
		TimeSeries: TimeSeriesConfig{
			Collections: map[string]TimeSeriesCollectionConfig{
				"security_events": {
					TimeField:          "timestamp",
					MetaField:          "metadata",
					Granularity:        "minutes",
					BucketMaxSpan:      time.Hour,
					BucketRounding:     "minutes",
					ExpireAfterSeconds: 2592000, // 30 days
					Indexes: []IndexConfig{
						{
							Keys:    map[string]int{"metadata.tenant_id": 1, "timestamp": 1},
							Options: IndexOptions{Name: "tenant_time_idx"},
						},
						{
							Keys:    map[string]int{"metadata.severity": 1},
							Options: IndexOptions{Name: "severity_idx"},
						},
					},
				},
				"performance_metrics": {
					TimeField:          "timestamp",
					MetaField:          "metadata",
					Granularity:        "seconds",
					BucketMaxSpan:      time.Hour,
					BucketRounding:     "seconds",
					ExpireAfterSeconds: 604800, // 7 days
					Indexes: []IndexConfig{
						{
							Keys:    map[string]int{"metadata.service": 1, "timestamp": 1},
							Options: IndexOptions{Name: "service_time_idx"},
						},
					},
				},
				"audit_events": {
					TimeField:          "timestamp",
					MetaField:          "metadata",
					Granularity:        "minutes",
					BucketMaxSpan:      time.Hour * 24,
					BucketRounding:     "minutes",
					ExpireAfterSeconds: 31536000, // 1 year
					Indexes: []IndexConfig{
						{
							Keys:    map[string]int{"metadata.tenant_id": 1, "metadata.user_id": 1, "timestamp": 1},
							Options: IndexOptions{Name: "tenant_user_time_idx"},
						},
					},
				},
			},
		},
		EnableMetrics:      true,
		EnableTracing:      true,
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

// LoadConfig loads MongoDB configuration from various sources
func LoadConfig() (*Config, error) {
	config := DefaultConfig()
	
	// Load from environment variables and config files
	if err := common.LoadConfigFromSources("mongodb", config); err != nil {
		return nil, fmt.Errorf("failed to load MongoDB config: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid MongoDB config: %w", err)
	}
	
	return config, nil
}

// Validate validates the MongoDB configuration
func (c *Config) Validate() error {
	if c.URI == "" {
		return fmt.Errorf("MongoDB URI is required")
	}
	
	if c.Database == "" {
		return fmt.Errorf("database name is required")
	}
	
	if c.ConnectTimeout <= 0 {
		return fmt.Errorf("connect timeout must be positive")
	}
	
	if c.ServerSelectionTimeout <= 0 {
		return fmt.Errorf("server selection timeout must be positive")
	}
	
	if c.MaxPoolSize == 0 {
		return fmt.Errorf("max pool size must be positive")
	}
	
	if c.MinPoolSize > c.MaxPoolSize {
		return fmt.Errorf("min pool size cannot exceed max pool size")
	}
	
	// Validate sharding configuration
	if c.Sharding.Enabled {
		if c.Sharding.ShardKey == "" {
			return fmt.Errorf("shard key is required when sharding is enabled")
		}
		
		if len(c.Sharding.ConfigServers) == 0 {
			return fmt.Errorf("config servers are required when sharding is enabled")
		}
		
		if len(c.Sharding.Mongos) == 0 {
			return fmt.Errorf("mongos routers are required when sharding is enabled")
		}
	}
	
	// Validate time-series collections
	for name, tsConfig := range c.TimeSeries.Collections {
		if tsConfig.TimeField == "" {
			return fmt.Errorf("time field is required for time-series collection %s", name)
		}
		
		validGranularities := map[string]bool{
			"seconds": true,
			"minutes": true,
			"hours":   true,
		}
		
		if !validGranularities[tsConfig.Granularity] {
			return fmt.Errorf("invalid granularity %s for collection %s", tsConfig.Granularity, name)
		}
	}
	
	return nil
}

// GetShardConnectionString returns the connection string for sharded setup
func (c *Config) GetShardConnectionString() string {
	if !c.Sharding.Enabled || len(c.Sharding.Mongos) == 0 {
		return c.URI
	}
	
	hosts := make([]string, len(c.Sharding.Mongos))
	for i, mongos := range c.Sharding.Mongos {
		hosts[i] = fmt.Sprintf("%s:%d", mongos.Host, mongos.Port)
	}
	
	return fmt.Sprintf("mongodb://%s/%s", 
		fmt.Sprintf("%s", hosts[0]), // Simplified for single mongos
		c.Database)
}

// GetTimeSeriesCollectionConfig returns configuration for a time-series collection
func (c *Config) GetTimeSeriesCollectionConfig(collectionName string) (TimeSeriesCollectionConfig, bool) {
	config, exists := c.TimeSeries.Collections[collectionName]
	return config, exists
}