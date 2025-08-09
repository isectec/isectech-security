package common

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/viper"
)

// Config represents application configuration
type Config struct {
	// Service configuration
	Service ServiceConfig `mapstructure:"service"`
	
	// Server configuration
	Server ServerConfig `mapstructure:"server"`
	
	// Database configurations
	Database DatabaseConfig `mapstructure:"database"`
	
	// Cache configuration
	Cache CacheConfig `mapstructure:"cache"`
	
	// Message queue configuration
	MessageQueue MessageQueueConfig `mapstructure:"messagequeue"`
	
	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging"`
	
	// Metrics configuration
	Metrics MetricsConfig `mapstructure:"metrics"`
	
	// Tracing configuration
	Tracing TracingConfig `mapstructure:"tracing"`
	
	// Security configuration
	Security SecurityConfig `mapstructure:"security"`
	
	// Service discovery configuration
	ServiceDiscovery ServiceDiscoveryConfig `mapstructure:"servicediscovery"`
}

// ServiceConfig contains service-specific configuration
type ServiceConfig struct {
	Name        string `mapstructure:"name"`
	Version     string `mapstructure:"version"`
	Environment string `mapstructure:"environment"`
	BuildTime   string `mapstructure:"build_time"`
	GitCommit   string `mapstructure:"git_commit"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	GRPCPort     int           `mapstructure:"grpc_port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	TLS          TLSConfig     `mapstructure:"tls"`
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
	PostgreSQL PostgreSQLConfig `mapstructure:"postgresql"`
	MongoDB    MongoDBConfig    `mapstructure:"mongodb"`
}

// PostgreSQLConfig contains PostgreSQL configuration
type PostgreSQLConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Database        string        `mapstructure:"database"`
	Username        string        `mapstructure:"username"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// MongoDBConfig contains MongoDB configuration
type MongoDBConfig struct {
	URI            string        `mapstructure:"uri"`
	Database       string        `mapstructure:"database"`
	Username       string        `mapstructure:"username"`
	Password       string        `mapstructure:"password"`
	MaxPoolSize    int           `mapstructure:"max_pool_size"`
	MinPoolSize    int           `mapstructure:"min_pool_size"`
	ConnectTimeout time.Duration `mapstructure:"connect_timeout"`
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	Redis RedisConfig `mapstructure:"redis"`
}

// RedisConfig contains Redis configuration
type RedisConfig struct {
	Host        string        `mapstructure:"host"`
	Port        int           `mapstructure:"port"`
	Password    string        `mapstructure:"password"`
	Database    int           `mapstructure:"database"`
	MaxRetries  int           `mapstructure:"max_retries"`
	PoolSize    int           `mapstructure:"pool_size"`
	IdleTimeout time.Duration `mapstructure:"idle_timeout"`
}

// MessageQueueConfig contains message queue configuration
type MessageQueueConfig struct {
	Kafka KafkaConfig `mapstructure:"kafka"`
}

// KafkaConfig contains Kafka configuration
type KafkaConfig struct {
	Brokers       []string      `mapstructure:"brokers"`
	GroupID       string        `mapstructure:"group_id"`
	ClientID      string        `mapstructure:"client_id"`
	Version       string        `mapstructure:"version"`
	RetryMax      int           `mapstructure:"retry_max"`
	RetryBackoff  time.Duration `mapstructure:"retry_backoff"`
	FlushMessages int           `mapstructure:"flush_messages"`
	FlushBytes    int           `mapstructure:"flush_bytes"`
	FlushTime     time.Duration `mapstructure:"flush_time"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	Structured bool   `mapstructure:"structured"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Host      string `mapstructure:"host"`
	Port      int    `mapstructure:"port"`
	Path      string `mapstructure:"path"`
	Namespace string `mapstructure:"namespace"`
}

// TracingConfig contains tracing configuration
type TracingConfig struct {
	Enabled     bool    `mapstructure:"enabled"`
	ServiceName string  `mapstructure:"service_name"`
	Endpoint    string  `mapstructure:"endpoint"`
	SampleRate  float64 `mapstructure:"sample_rate"`
}

// SecurityConfig contains security configuration
type SecurityConfig struct {
	JWT         JWTConfig         `mapstructure:"jwt"`
	Encryption  EncryptionConfig  `mapstructure:"encryption"`
	RateLimit   RateLimitConfig   `mapstructure:"rate_limit"`
	CORS        CORSConfig        `mapstructure:"cors"`
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Secret         string        `mapstructure:"secret"`
	Issuer         string        `mapstructure:"issuer"`
	Audience       string        `mapstructure:"audience"`
	ExpirationTime time.Duration `mapstructure:"expiration_time"`
	RefreshTime    time.Duration `mapstructure:"refresh_time"`
}

// EncryptionConfig contains encryption configuration
type EncryptionConfig struct {
	Key    string `mapstructure:"key"`
	Method string `mapstructure:"method"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled bool  `mapstructure:"enabled"`
	RPS     int   `mapstructure:"rps"`
	Burst   int   `mapstructure:"burst"`
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

// ServiceDiscoveryConfig contains service discovery configuration
type ServiceDiscoveryConfig struct {
	Consul ConsulConfig `mapstructure:"consul"`
}

// ConsulConfig contains Consul configuration
type ConsulConfig struct {
	Address    string        `mapstructure:"address"`
	Datacenter string        `mapstructure:"datacenter"`
	Token      string        `mapstructure:"token"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

// LoadConfig loads configuration from various sources
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}
	
	// Set default values
	setDefaults()
	
	// Set configuration paths
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/isectech")
	viper.AddConfigPath(".")
	
	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("ISECTECH")
	
	// Bind environment variables
	bindEnvironmentVariables()
	
	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}
	
	// Unmarshal configuration
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Service defaults
	viper.SetDefault("service.name", "isectech-service")
	viper.SetDefault("service.version", "1.0.0")
	viper.SetDefault("service.environment", "development")
	
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.grpc_port", 9090)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")
	
	// Database defaults
	viper.SetDefault("database.postgresql.host", "localhost")
	viper.SetDefault("database.postgresql.port", 5432)
	viper.SetDefault("database.postgresql.database", "isectech")
	viper.SetDefault("database.postgresql.username", "isectech_app")
	viper.SetDefault("database.postgresql.ssl_mode", "disable")
	viper.SetDefault("database.postgresql.max_open_conns", 25)
	viper.SetDefault("database.postgresql.max_idle_conns", 5)
	viper.SetDefault("database.postgresql.conn_max_lifetime", "5m")
	
	viper.SetDefault("database.mongodb.uri", "mongodb://localhost:27017")
	viper.SetDefault("database.mongodb.database", "isectech")
	viper.SetDefault("database.mongodb.max_pool_size", 100)
	viper.SetDefault("database.mongodb.min_pool_size", 5)
	viper.SetDefault("database.mongodb.connect_timeout", "10s")
	
	// Cache defaults
	viper.SetDefault("cache.redis.host", "localhost")
	viper.SetDefault("cache.redis.port", 6379)
	viper.SetDefault("cache.redis.database", 0)
	viper.SetDefault("cache.redis.max_retries", 3)
	viper.SetDefault("cache.redis.pool_size", 10)
	viper.SetDefault("cache.redis.idle_timeout", "5m")
	
	// Message queue defaults
	viper.SetDefault("messagequeue.kafka.brokers", []string{"localhost:9092"})
	viper.SetDefault("messagequeue.kafka.group_id", "isectech-platform")
	viper.SetDefault("messagequeue.kafka.client_id", "isectech-client")
	viper.SetDefault("messagequeue.kafka.version", "2.8.0")
	viper.SetDefault("messagequeue.kafka.retry_max", 3)
	viper.SetDefault("messagequeue.kafka.retry_backoff", "250ms")
	viper.SetDefault("messagequeue.kafka.flush_messages", 100)
	viper.SetDefault("messagequeue.kafka.flush_bytes", 1048576) // 1MB
	viper.SetDefault("messagequeue.kafka.flush_time", "1s")
	
	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.structured", true)
	
	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.host", "0.0.0.0")
	viper.SetDefault("metrics.port", 8081)
	viper.SetDefault("metrics.path", "/metrics")
	viper.SetDefault("metrics.namespace", "isectech")
	
	// Tracing defaults
	viper.SetDefault("tracing.enabled", true)
	viper.SetDefault("tracing.service_name", "isectech-service")
	viper.SetDefault("tracing.endpoint", "http://localhost:14268/api/traces")
	viper.SetDefault("tracing.sample_rate", 0.1)
	
	// Security defaults
	viper.SetDefault("security.jwt.issuer", "isectech")
	viper.SetDefault("security.jwt.audience", "isectech-api")
	viper.SetDefault("security.jwt.expiration_time", "1h")
	viper.SetDefault("security.jwt.refresh_time", "24h")
	viper.SetDefault("security.encryption.method", "AES-256")
	viper.SetDefault("security.rate_limit.enabled", true)
	viper.SetDefault("security.rate_limit.rps", 100)
	viper.SetDefault("security.rate_limit.burst", 200)
	viper.SetDefault("security.cors.enabled", true)
	viper.SetDefault("security.cors.allowed_origins", []string{"*"})
	viper.SetDefault("security.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("security.cors.allowed_headers", []string{"*"})
	viper.SetDefault("security.cors.max_age", 3600)
	
	// Service discovery defaults
	viper.SetDefault("servicediscovery.consul.address", "localhost:8500")
	viper.SetDefault("servicediscovery.consul.datacenter", "dc1")
	viper.SetDefault("servicediscovery.consul.timeout", "10s")
}

// bindEnvironmentVariables binds environment variables to configuration keys
func bindEnvironmentVariables() {
	// Service
	viper.BindEnv("service.name", "SERVICE_NAME")
	viper.BindEnv("service.version", "SERVICE_VERSION")
	viper.BindEnv("service.environment", "ENVIRONMENT")
	
	// Server
	viper.BindEnv("server.host", "SERVER_HOST")
	viper.BindEnv("server.port", "SERVER_PORT")
	viper.BindEnv("server.grpc_port", "GRPC_PORT")
	
	// Database
	viper.BindEnv("database.postgresql.host", "POSTGRES_HOST")
	viper.BindEnv("database.postgresql.port", "POSTGRES_PORT")
	viper.BindEnv("database.postgresql.database", "POSTGRES_DB")
	viper.BindEnv("database.postgresql.username", "POSTGRES_USER")
	viper.BindEnv("database.postgresql.password", "POSTGRES_PASSWORD")
	viper.BindEnv("database.postgresql.ssl_mode", "POSTGRES_SSL_MODE")
	
	viper.BindEnv("database.mongodb.uri", "MONGODB_URI")
	viper.BindEnv("database.mongodb.database", "MONGODB_DATABASE")
	viper.BindEnv("database.mongodb.username", "MONGODB_USERNAME")
	viper.BindEnv("database.mongodb.password", "MONGODB_PASSWORD")
	
	// Cache
	viper.BindEnv("cache.redis.host", "REDIS_HOST")
	viper.BindEnv("cache.redis.port", "REDIS_PORT")
	viper.BindEnv("cache.redis.password", "REDIS_PASSWORD")
	viper.BindEnv("cache.redis.database", "REDIS_DB")
	
	// Message queue
	viper.BindEnv("messagequeue.kafka.brokers", "KAFKA_BROKERS")
	viper.BindEnv("messagequeue.kafka.group_id", "KAFKA_GROUP_ID")
	viper.BindEnv("messagequeue.kafka.client_id", "KAFKA_CLIENT_ID")
	
	// Security
	viper.BindEnv("security.jwt.secret", "JWT_SECRET")
	viper.BindEnv("security.encryption.key", "ENCRYPTION_KEY")
	
	// Service discovery
	viper.BindEnv("servicediscovery.consul.address", "CONSUL_ADDRESS")
	viper.BindEnv("servicediscovery.consul.token", "CONSUL_TOKEN")
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate required fields
	if config.Service.Name == "" {
		return fmt.Errorf("service name is required")
	}
	
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}
	
	if config.Server.GRPCPort <= 0 || config.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", config.Server.GRPCPort)
	}
	
	if config.Security.JWT.Secret == "" {
		return fmt.Errorf("JWT secret is required")
	}
	
	if config.Security.Encryption.Key == "" {
		return fmt.Errorf("encryption key is required")
	}
	
	return nil
}

// GetEnv gets an environment variable with a fallback default
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvAsInt gets an environment variable as integer with a fallback default
func GetEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetEnvAsBool gets an environment variable as boolean with a fallback default
func GetEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// GetEnvAsDuration gets an environment variable as duration with a fallback default
func GetEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}