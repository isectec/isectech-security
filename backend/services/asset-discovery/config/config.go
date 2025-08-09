package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the asset discovery service
type Config struct {
	// Service configuration
	Service ServiceConfig `mapstructure:"service"`
	
	// Server configurations
	HTTP HTTPConfig `mapstructure:"http"`
	GRPC GRPCConfig `mapstructure:"grpc"`
	
	// Database configurations
	Database DatabaseConfig `mapstructure:"database"`
	Cache    CacheConfig    `mapstructure:"cache"`
	
	// External services
	External ExternalConfig `mapstructure:"external"`
	
	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging"`
	
	// Metrics configuration
	Metrics MetricsConfig `mapstructure:"metrics"`
	
	// Security configuration
	Security SecurityConfig `mapstructure:"security"`
	
	// Discovery configuration
	Discovery DiscoveryConfig `mapstructure:"discovery"`
}

// ServiceConfig contains general service configuration
type ServiceConfig struct {
	Name        string `mapstructure:"name"`
	Version     string `mapstructure:"version"`
	Environment string `mapstructure:"environment"`
	Debug       bool   `mapstructure:"debug"`
	
	// Graceful shutdown
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	
	// Health check configuration
	HealthCheck HealthCheckConfig `mapstructure:"health_check"`
}

// HealthCheckConfig contains health check configuration
type HealthCheckConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// HTTPConfig contains HTTP server configuration
type HTTPConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	Host         string        `mapstructure:"host"`
	Port         string        `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	
	// CORS configuration
	CORS CORSConfig `mapstructure:"cors"`
	
	// Rate limiting
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
}

// CORSConfig contains CORS configuration
type CORSConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	ExposedHeaders   []string `mapstructure:"exposed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	RequestsPerMinute int     `mapstructure:"requests_per_minute"`
	BurstSize   int           `mapstructure:"burst_size"`
	WindowSize  time.Duration `mapstructure:"window_size"`
}

// GRPCConfig contains gRPC server configuration
type GRPCConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	Host            string        `mapstructure:"host"`
	Port            string        `mapstructure:"port"`
	MaxReceiveSize  int           `mapstructure:"max_receive_size"`
	MaxSendSize     int           `mapstructure:"max_send_size"`
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
	
	// TLS configuration
	TLS TLSConfig `mapstructure:"tls"`
	
	// Reflection
	Reflection bool `mapstructure:"reflection"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	CAFile   string `mapstructure:"ca_file"`
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	// PostgreSQL configuration
	PostgreSQL PostgreSQLConfig `mapstructure:"postgresql"`
	
	// MongoDB configuration
	MongoDB MongoDBConfig `mapstructure:"mongodb"`
	
	// Connection pooling
	Pool PoolConfig `mapstructure:"pool"`
	
	// Migration configuration
	Migration MigrationConfig `mapstructure:"migration"`
}

// PostgreSQLConfig contains PostgreSQL configuration
type PostgreSQLConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
	
	// Connection settings
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
	
	// Query settings
	QueryTimeout time.Duration `mapstructure:"query_timeout"`
	
	// Retry settings
	RetryAttempts int           `mapstructure:"retry_attempts"`
	RetryDelay    time.Duration `mapstructure:"retry_delay"`
}

// MongoDBConfig contains MongoDB configuration
type MongoDBConfig struct {
	URI      string `mapstructure:"uri"`
	Database string `mapstructure:"database"`
	
	// Connection settings
	MaxPoolSize    uint64        `mapstructure:"max_pool_size"`
	MinPoolSize    uint64        `mapstructure:"min_pool_size"`
	ConnectTimeout time.Duration `mapstructure:"connect_timeout"`
	ServerTimeout  time.Duration `mapstructure:"server_timeout"`
	
	// Retry settings
	RetryAttempts int           `mapstructure:"retry_attempts"`
	RetryDelay    time.Duration `mapstructure:"retry_delay"`
}

// PoolConfig contains connection pool configuration
type PoolConfig struct {
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// MigrationConfig contains database migration configuration
type MigrationConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
	Version int    `mapstructure:"version"`
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	// Redis configuration
	Redis RedisConfig `mapstructure:"redis"`
	
	// Cache TTL settings
	TTL TTLConfig `mapstructure:"ttl"`
}

// RedisConfig contains Redis configuration
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	Password string `mapstructure:"password"`
	Database int    `mapstructure:"database"`
	
	// Connection settings
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	
	// Cluster settings
	Cluster ClusterConfig `mapstructure:"cluster"`
	
	// Sentinel settings
	Sentinel SentinelConfig `mapstructure:"sentinel"`
}

// ClusterConfig contains Redis cluster configuration
type ClusterConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Addresses []string `mapstructure:"addresses"`
}

// SentinelConfig contains Redis Sentinel configuration
type SentinelConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	MasterName string   `mapstructure:"master_name"`
	Addresses  []string `mapstructure:"addresses"`
}

// TTLConfig contains cache TTL configuration
type TTLConfig struct {
	Default     time.Duration `mapstructure:"default"`
	Assets      time.Duration `mapstructure:"assets"`
	Discovery   time.Duration `mapstructure:"discovery"`
	Aggregation time.Duration `mapstructure:"aggregation"`
}

// ExternalConfig contains external service configuration
type ExternalConfig struct {
	// Network scanning tools
	Nmap NmapConfig `mapstructure:"nmap"`
	
	// Cloud providers
	AWS   AWSConfig   `mapstructure:"aws"`
	Azure AzureConfig `mapstructure:"azure"`
	GCP   GCPConfig   `mapstructure:"gcp"`
	
	// Vulnerability scanners
	VulnScanners VulnScannersConfig `mapstructure:"vuln_scanners"`
	
	// Threat intelligence
	ThreatIntel ThreatIntelConfig `mapstructure:"threat_intel"`
}

// NmapConfig contains Nmap configuration
type NmapConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Path       string `mapstructure:"path"`
	Timeout    time.Duration `mapstructure:"timeout"`
	MaxTargets int    `mapstructure:"max_targets"`
}

// AWSConfig contains AWS configuration
type AWSConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Region    string `mapstructure:"region"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
	Profile   string `mapstructure:"profile"`
}

// AzureConfig contains Azure configuration
type AzureConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	TenantID       string `mapstructure:"tenant_id"`
	ClientID       string `mapstructure:"client_id"`
	ClientSecret   string `mapstructure:"client_secret"`
	SubscriptionID string `mapstructure:"subscription_id"`
}

// GCPConfig contains GCP configuration
type GCPConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	ProjectID         string `mapstructure:"project_id"`
	CredentialsFile   string `mapstructure:"credentials_file"`
	CredentialsJSON   string `mapstructure:"credentials_json"`
}

// VulnScannersConfig contains vulnerability scanner configuration
type VulnScannersConfig struct {
	Enabled       bool            `mapstructure:"enabled"`
	OpenVAS       OpenVASConfig   `mapstructure:"openvas"`
	Nessus        NessusConfig    `mapstructure:"nessus"`
	QualysVMDR    QualysConfig    `mapstructure:"qualys"`
}

// OpenVASConfig contains OpenVAS configuration
type OpenVASConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// NessusConfig contains Nessus configuration
type NessusConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Host      string `mapstructure:"host"`
	Port      int    `mapstructure:"port"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
}

// QualysConfig contains Qualys configuration
type QualysConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Host     string `mapstructure:"host"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// ThreatIntelConfig contains threat intelligence configuration
type ThreatIntelConfig struct {
	Enabled       bool                    `mapstructure:"enabled"`
	Sources       []ThreatIntelSource     `mapstructure:"sources"`
	UpdateInterval time.Duration          `mapstructure:"update_interval"`
}

// ThreatIntelSource contains threat intelligence source configuration
type ThreatIntelSource struct {
	Name    string `mapstructure:"name"`
	Type    string `mapstructure:"type"`
	URL     string `mapstructure:"url"`
	APIKey  string `mapstructure:"api_key"`
	Enabled bool   `mapstructure:"enabled"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	Filename   string `mapstructure:"filename"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
	
	// Structured logging
	Structured bool              `mapstructure:"structured"`
	Fields     map[string]string `mapstructure:"fields"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Host      string `mapstructure:"host"`
	Port      string `mapstructure:"port"`
	Path      string `mapstructure:"path"`
	Namespace string `mapstructure:"namespace"`
	
	// Prometheus configuration
	Prometheus PrometheusConfig `mapstructure:"prometheus"`
	
	// Custom metrics
	Custom CustomMetricsConfig `mapstructure:"custom"`
}

// PrometheusConfig contains Prometheus configuration
type PrometheusConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	PushGateway string       `mapstructure:"push_gateway"`
	Job        string        `mapstructure:"job"`
	Instance   string        `mapstructure:"instance"`
	Interval   time.Duration `mapstructure:"interval"`
}

// CustomMetricsConfig contains custom metrics configuration
type CustomMetricsConfig struct {
	Enabled bool                   `mapstructure:"enabled"`
	Metrics []CustomMetricConfig   `mapstructure:"metrics"`
}

// CustomMetricConfig contains individual custom metric configuration
type CustomMetricConfig struct {
	Name        string            `mapstructure:"name"`
	Type        string            `mapstructure:"type"`
	Description string            `mapstructure:"description"`
	Labels      []string          `mapstructure:"labels"`
	Buckets     []float64         `mapstructure:"buckets"`
}

// SecurityConfig contains security configuration
type SecurityConfig struct {
	// API Security
	API APISecurityConfig `mapstructure:"api"`
	
	// Encryption
	Encryption EncryptionConfig `mapstructure:"encryption"`
	
	// Authentication
	Authentication AuthenticationConfig `mapstructure:"authentication"`
	
	// Authorization
	Authorization AuthorizationConfig `mapstructure:"authorization"`
}

// APISecurityConfig contains API security configuration
type APISecurityConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	AllowedHosts  []string `mapstructure:"allowed_hosts"`
	TrustedProxies []string `mapstructure:"trusted_proxies"`
	APIKeys       []string `mapstructure:"api_keys"`
	
	// Request validation
	MaxRequestSize int64 `mapstructure:"max_request_size"`
	RequestTimeout time.Duration `mapstructure:"request_timeout"`
}

// EncryptionConfig contains encryption configuration
type EncryptionConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Algorithm  string `mapstructure:"algorithm"`
	KeyFile    string `mapstructure:"key_file"`
	SecretKey  string `mapstructure:"secret_key"`
	
	// Data at rest encryption
	AtRest AtRestEncryptionConfig `mapstructure:"at_rest"`
	
	// Data in transit encryption
	InTransit InTransitEncryptionConfig `mapstructure:"in_transit"`
}

// AtRestEncryptionConfig contains at-rest encryption configuration
type AtRestEncryptionConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Algorithm string `mapstructure:"algorithm"`
	KeySize   int    `mapstructure:"key_size"`
}

// InTransitEncryptionConfig contains in-transit encryption configuration
type InTransitEncryptionConfig struct {
	Enabled bool      `mapstructure:"enabled"`
	TLS     TLSConfig `mapstructure:"tls"`
}

// AuthenticationConfig contains authentication configuration
type AuthenticationConfig struct {
	Enabled bool              `mapstructure:"enabled"`
	Type    string            `mapstructure:"type"`
	JWT     JWTConfig         `mapstructure:"jwt"`
	OAuth   OAuthConfig       `mapstructure:"oauth"`
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	SecretKey      string        `mapstructure:"secret_key"`
	Issuer         string        `mapstructure:"issuer"`
	Audience       string        `mapstructure:"audience"`
	TokenLifetime  time.Duration `mapstructure:"token_lifetime"`
	RefreshLifetime time.Duration `mapstructure:"refresh_lifetime"`
}

// OAuthConfig contains OAuth configuration
type OAuthConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	ProviderURL  string `mapstructure:"provider_url"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
	Scopes       []string `mapstructure:"scopes"`
}

// AuthorizationConfig contains authorization configuration
type AuthorizationConfig struct {
	Enabled bool        `mapstructure:"enabled"`
	Type    string      `mapstructure:"type"`
	RBAC    RBACConfig  `mapstructure:"rbac"`
	ABAC    ABACConfig  `mapstructure:"abac"`
}

// RBACConfig contains RBAC configuration
type RBACConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	PolicyFile string `mapstructure:"policy_file"`
}

// ABACConfig contains ABAC configuration
type ABACConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	PolicyFile string `mapstructure:"policy_file"`
}

// DiscoveryConfig contains discovery-specific configuration
type DiscoveryConfig struct {
	// Default scan options
	DefaultScanOptions DefaultScanOptionsConfig `mapstructure:"default_scan_options"`
	
	// Concurrency limits
	Concurrency ConcurrencyConfig `mapstructure:"concurrency"`
	
	// Timeouts
	Timeouts TimeoutsConfig `mapstructure:"timeouts"`
	
	// Rate limiting
	RateLimiting RateLimitingConfig `mapstructure:"rate_limiting"`
	
	// Asset lifecycle
	AssetLifecycle AssetLifecycleConfig `mapstructure:"asset_lifecycle"`
}

// DefaultScanOptionsConfig contains default scan options
type DefaultScanOptionsConfig struct {
	PortRanges       []string `mapstructure:"port_ranges"`
	ServiceDetection bool     `mapstructure:"service_detection"`
	VersionDetection bool     `mapstructure:"version_detection"`
	OSDetection      bool     `mapstructure:"os_detection"`
	DeepInspection   bool     `mapstructure:"deep_inspection"`
}

// ConcurrencyConfig contains concurrency configuration
type ConcurrencyConfig struct {
	MaxConcurrentScans int `mapstructure:"max_concurrent_scans"`
	MaxConcurrentTargets int `mapstructure:"max_concurrent_targets"`
	WorkerPoolSize     int `mapstructure:"worker_pool_size"`
}

// TimeoutsConfig contains timeout configuration
type TimeoutsConfig struct {
	ScanTimeout    time.Duration `mapstructure:"scan_timeout"`
	TargetTimeout  time.Duration `mapstructure:"target_timeout"`
	ServiceTimeout time.Duration `mapstructure:"service_timeout"`
}

// RateLimitingConfig contains rate limiting configuration
type RateLimitingConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	RequestsPerSecond  int           `mapstructure:"requests_per_second"`
	BurstSize          int           `mapstructure:"burst_size"`
	WindowSize         time.Duration `mapstructure:"window_size"`
}

// AssetLifecycleConfig contains asset lifecycle configuration
type AssetLifecycleConfig struct {
	StaleThreshold    time.Duration `mapstructure:"stale_threshold"`
	ArchiveThreshold  time.Duration `mapstructure:"archive_threshold"`
	CleanupInterval   time.Duration `mapstructure:"cleanup_interval"`
	EnableAutoCleanup bool          `mapstructure:"enable_auto_cleanup"`
}

// LoadConfig loads configuration from various sources
func LoadConfig() (*Config, error) {
	// Set default config file name and paths
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/asset-discovery")
	
	// Set environment variable prefix
	viper.SetEnvPrefix("ASSET_DISCOVERY")
	viper.AutomaticEnv()
	
	// Set default values
	setDefaults()
	
	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; use defaults and environment variables
		} else {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}
	
	// Override with environment variables
	overrideWithEnv()
	
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Service defaults
	viper.SetDefault("service.name", "asset-discovery")
	viper.SetDefault("service.version", "1.0.0")
	viper.SetDefault("service.environment", "development")
	viper.SetDefault("service.debug", false)
	viper.SetDefault("service.shutdown_timeout", "30s")
	
	// Health check defaults
	viper.SetDefault("service.health_check.enabled", true)
	viper.SetDefault("service.health_check.interval", "30s")
	viper.SetDefault("service.health_check.timeout", "5s")
	
	// HTTP defaults
	viper.SetDefault("http.enabled", true)
	viper.SetDefault("http.host", "0.0.0.0")
	viper.SetDefault("http.port", "8080")
	viper.SetDefault("http.read_timeout", "30s")
	viper.SetDefault("http.write_timeout", "30s")
	viper.SetDefault("http.idle_timeout", "120s")
	
	// CORS defaults
	viper.SetDefault("http.cors.enabled", true)
	viper.SetDefault("http.cors.allowed_origins", []string{"*"})
	viper.SetDefault("http.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("http.cors.allowed_headers", []string{"*"})
	viper.SetDefault("http.cors.allow_credentials", true)
	viper.SetDefault("http.cors.max_age", 3600)
	
	// gRPC defaults
	viper.SetDefault("grpc.enabled", true)
	viper.SetDefault("grpc.host", "0.0.0.0")
	viper.SetDefault("grpc.port", "9090")
	viper.SetDefault("grpc.max_receive_size", 4*1024*1024) // 4MB
	viper.SetDefault("grpc.max_send_size", 4*1024*1024)    // 4MB
	viper.SetDefault("grpc.connection_timeout", "30s")
	viper.SetDefault("grpc.reflection", true)
	
	// Database defaults
	viper.SetDefault("database.postgresql.host", "localhost")
	viper.SetDefault("database.postgresql.port", 5432)
	viper.SetDefault("database.postgresql.database", "asset_discovery")
	viper.SetDefault("database.postgresql.username", "postgres")
	viper.SetDefault("database.postgresql.ssl_mode", "disable")
	viper.SetDefault("database.postgresql.max_open_conns", 25)
	viper.SetDefault("database.postgresql.max_idle_conns", 10)
	viper.SetDefault("database.postgresql.conn_max_lifetime", "1h")
	viper.SetDefault("database.postgresql.conn_max_idle_time", "30m")
	viper.SetDefault("database.postgresql.query_timeout", "30s")
	viper.SetDefault("database.postgresql.retry_attempts", 3)
	viper.SetDefault("database.postgresql.retry_delay", "1s")
	
	// MongoDB defaults
	viper.SetDefault("database.mongodb.uri", "mongodb://localhost:27017")
	viper.SetDefault("database.mongodb.database", "asset_discovery")
	viper.SetDefault("database.mongodb.max_pool_size", 100)
	viper.SetDefault("database.mongodb.min_pool_size", 5)
	viper.SetDefault("database.mongodb.connect_timeout", "10s")
	viper.SetDefault("database.mongodb.server_timeout", "30s")
	viper.SetDefault("database.mongodb.retry_attempts", 3)
	viper.SetDefault("database.mongodb.retry_delay", "1s")
	
	// Cache defaults
	viper.SetDefault("cache.redis.host", "localhost")
	viper.SetDefault("cache.redis.port", "6379")
	viper.SetDefault("cache.redis.database", 0)
	viper.SetDefault("cache.redis.pool_size", 10)
	viper.SetDefault("cache.redis.min_idle_conns", 5)
	viper.SetDefault("cache.redis.dial_timeout", "5s")
	viper.SetDefault("cache.redis.read_timeout", "3s")
	viper.SetDefault("cache.redis.write_timeout", "3s")
	viper.SetDefault("cache.redis.idle_timeout", "5m")
	
	// TTL defaults
	viper.SetDefault("cache.ttl.default", "1h")
	viper.SetDefault("cache.ttl.assets", "30m")
	viper.SetDefault("cache.ttl.discovery", "10m")
	viper.SetDefault("cache.ttl.aggregation", "5m")
	
	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.structured", true)
	
	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.host", "0.0.0.0")
	viper.SetDefault("metrics.port", "2112")
	viper.SetDefault("metrics.path", "/metrics")
	viper.SetDefault("metrics.namespace", "asset_discovery")
	
	// Discovery defaults
	viper.SetDefault("discovery.default_scan_options.port_ranges", []string{"1-1000", "8000-9000"})
	viper.SetDefault("discovery.default_scan_options.service_detection", true)
	viper.SetDefault("discovery.default_scan_options.version_detection", false)
	viper.SetDefault("discovery.default_scan_options.os_detection", false)
	viper.SetDefault("discovery.default_scan_options.deep_inspection", false)
	
	viper.SetDefault("discovery.concurrency.max_concurrent_scans", 10)
	viper.SetDefault("discovery.concurrency.max_concurrent_targets", 100)
	viper.SetDefault("discovery.concurrency.worker_pool_size", 50)
	
	viper.SetDefault("discovery.timeouts.scan_timeout", "30m")
	viper.SetDefault("discovery.timeouts.target_timeout", "5m")
	viper.SetDefault("discovery.timeouts.service_timeout", "30s")
	
	viper.SetDefault("discovery.rate_limiting.enabled", true)
	viper.SetDefault("discovery.rate_limiting.requests_per_second", 100)
	viper.SetDefault("discovery.rate_limiting.burst_size", 200)
	viper.SetDefault("discovery.rate_limiting.window_size", "1m")
	
	viper.SetDefault("discovery.asset_lifecycle.stale_threshold", "7d")
	viper.SetDefault("discovery.asset_lifecycle.archive_threshold", "30d")
	viper.SetDefault("discovery.asset_lifecycle.cleanup_interval", "24h")
	viper.SetDefault("discovery.asset_lifecycle.enable_auto_cleanup", false)
}

// overrideWithEnv overrides configuration with environment variables
func overrideWithEnv() {
	// Database credentials
	if val := os.Getenv("POSTGRES_PASSWORD"); val != "" {
		viper.Set("database.postgresql.password", val)
	}
	if val := os.Getenv("MONGODB_URI"); val != "" {
		viper.Set("database.mongodb.uri", val)
	}
	if val := os.Getenv("REDIS_PASSWORD"); val != "" {
		viper.Set("cache.redis.password", val)
	}
	
	// Service configuration
	if val := os.Getenv("SERVICE_PORT"); val != "" {
		viper.Set("http.port", val)
	}
	if val := os.Getenv("GRPC_PORT"); val != "" {
		viper.Set("grpc.port", val)
	}
	
	// External service credentials
	if val := os.Getenv("AWS_ACCESS_KEY_ID"); val != "" {
		viper.Set("external.aws.access_key", val)
	}
	if val := os.Getenv("AWS_SECRET_ACCESS_KEY"); val != "" {
		viper.Set("external.aws.secret_key", val)
	}
	if val := os.Getenv("AZURE_CLIENT_SECRET"); val != "" {
		viper.Set("external.azure.client_secret", val)
	}
	if val := os.Getenv("GCP_CREDENTIALS_JSON"); val != "" {
		viper.Set("external.gcp.credentials_json", val)
	}
	
	// Security settings
	if val := os.Getenv("JWT_SECRET_KEY"); val != "" {
		viper.Set("security.authentication.jwt.secret_key", val)
	}
	if val := os.Getenv("ENCRYPTION_SECRET_KEY"); val != "" {
		viper.Set("security.encryption.secret_key", val)
	}
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate required fields
	if config.Service.Name == "" {
		return fmt.Errorf("service name is required")
	}
	
	// Validate ports
	if config.HTTP.Enabled {
		if _, err := strconv.Atoi(config.HTTP.Port); err != nil {
			return fmt.Errorf("invalid HTTP port: %s", config.HTTP.Port)
		}
	}
	
	if config.GRPC.Enabled {
		if _, err := strconv.Atoi(config.GRPC.Port); err != nil {
			return fmt.Errorf("invalid gRPC port: %s", config.GRPC.Port)
		}
	}
	
	// Validate database configuration
	if config.Database.PostgreSQL.Host == "" {
		return fmt.Errorf("PostgreSQL host is required")
	}
	
	// Validate discovery configuration
	if config.Discovery.Concurrency.MaxConcurrentScans <= 0 {
		return fmt.Errorf("max_concurrent_scans must be greater than 0")
	}
	
	return nil
}

// GetDSN returns the PostgreSQL DSN string
func (c *PostgreSQLConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.Username, c.Password, c.Database, c.SSLMode)
}

// GetRedisAddr returns the Redis address string
func (c *RedisConfig) GetRedisAddr() string {
	return fmt.Sprintf("%s:%s", c.Host, c.Port)
}