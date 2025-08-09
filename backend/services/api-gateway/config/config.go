package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config represents the application configuration
type Config struct {
	Environment string         `yaml:"environment" json:"environment"`
	Server      ServerConfig   `yaml:"server" json:"server"`
	Database    DatabaseConfig `yaml:"database" json:"database"`
	Redis       RedisConfig    `yaml:"redis" json:"redis"`
	Auth        AuthConfig     `yaml:"auth" json:"auth"`
	CORS        CORSConfig     `yaml:"cors" json:"cors"`
	RateLimit   RateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
	Monitoring  MonitoringConfig `yaml:"monitoring" json:"monitoring"`
	Tracing     TracingConfig  `yaml:"tracing" json:"tracing"`
	Logging     LoggingConfig  `yaml:"logging" json:"logging"`
	Security    SecurityConfig `yaml:"security" json:"security"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Port           int `yaml:"port" json:"port"`
	ReadTimeout    int `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout   int `yaml:"write_timeout" json:"write_timeout"`
	IdleTimeout    int `yaml:"idle_timeout" json:"idle_timeout"`
	MaxHeaderBytes int `yaml:"max_header_bytes" json:"max_header_bytes"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	Driver          string `yaml:"driver" json:"driver"`
	Host            string `yaml:"host" json:"host"`
	Port            int    `yaml:"port" json:"port"`
	Database        string `yaml:"database" json:"database"`
	Username        string `yaml:"username" json:"username"`
	Password        string `yaml:"password" json:"password"`
	SSLMode         string `yaml:"ssl_mode" json:"ssl_mode"`
	MaxOpenConns    int    `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime int    `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Host         string `yaml:"host" json:"host"`
	Port         int    `yaml:"port" json:"port"`
	Password     string `yaml:"password" json:"password"`
	Database     int    `yaml:"database" json:"database"`
	PoolSize     int    `yaml:"pool_size" json:"pool_size"`
	MinIdleConns int    `yaml:"min_idle_conns" json:"min_idle_conns"`
	MaxRetries   int    `yaml:"max_retries" json:"max_retries"`
	DialTimeout  int    `yaml:"dial_timeout" json:"dial_timeout"`
	ReadTimeout  int    `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout" json:"write_timeout"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	JWT    JWTConfig    `yaml:"jwt" json:"jwt"`
	APIKey APIKeyConfig `yaml:"api_key" json:"api_key"`
	OAuth  OAuthConfig  `yaml:"oauth" json:"oauth"`
}

// JWTConfig represents JWT configuration
type JWTConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Secret     string `yaml:"secret" json:"secret"`
	PublicKey  string `yaml:"public_key" json:"public_key"`
	PrivateKey string `yaml:"private_key" json:"private_key"`
	Algorithm  string `yaml:"algorithm" json:"algorithm"`
	Issuer     string `yaml:"issuer" json:"issuer"`
	Audience   string `yaml:"audience" json:"audience"`
	TTL        int    `yaml:"ttl" json:"ttl"`
}

// APIKeyConfig represents API key configuration
type APIKeyConfig struct {
	Enabled     bool `yaml:"enabled" json:"enabled"`
	HeaderName  string `yaml:"header_name" json:"header_name"`
	QueryParam  string `yaml:"query_param" json:"query_param"`
}

// OAuthConfig represents OAuth configuration
type OAuthConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	Provider     string `yaml:"provider" json:"provider"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
	RedirectURL  string `yaml:"redirect_url" json:"redirect_url"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	AllowedOrigins   []string `yaml:"allowed_origins" json:"allowed_origins"`
	AllowedMethods   []string `yaml:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders   []string `yaml:"allowed_headers" json:"allowed_headers"`
	ExposedHeaders   []string `yaml:"exposed_headers" json:"exposed_headers"`
	AllowCredentials bool     `yaml:"allow_credentials" json:"allow_credentials"`
	MaxAge           int      `yaml:"max_age" json:"max_age"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool    `yaml:"enabled" json:"enabled"`
	RequestsPerSecond int     `yaml:"requests_per_second" json:"requests_per_second"`
	BurstSize         int     `yaml:"burst_size" json:"burst_size"`
	WindowSize        int     `yaml:"window_size" json:"window_size"`
	KeyExtractor      string  `yaml:"key_extractor" json:"key_extractor"`
	SkipSuccessful    bool    `yaml:"skip_successful" json:"skip_successful"`
	SkipClientErrors  bool    `yaml:"skip_client_errors" json:"skip_client_errors"`
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	MetricsPath    string `yaml:"metrics_path" json:"metrics_path"`
	HealthPath     string `yaml:"health_path" json:"health_path"`
	PrometheusAddr string `yaml:"prometheus_addr" json:"prometheus_addr"`
}

// TracingConfig represents tracing configuration
type TracingConfig struct {
	Enabled     bool    `yaml:"enabled" json:"enabled"`
	ServiceName string  `yaml:"service_name" json:"service_name"`
	Endpoint    string  `yaml:"endpoint" json:"endpoint"`
	SampleRate  float64 `yaml:"sample_rate" json:"sample_rate"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	AllowedIPs      []string `yaml:"allowed_ips" json:"allowed_ips"`
	BlockedIPs      []string `yaml:"blocked_ips" json:"blocked_ips"`
	RequireHTTPS    bool     `yaml:"require_https" json:"require_https"`
	CSPHeader       string   `yaml:"csp_header" json:"csp_header"`
	HSTSMaxAge      int      `yaml:"hsts_max_age" json:"hsts_max_age"`
	RequestSizeLimit int64   `yaml:"request_size_limit" json:"request_size_limit"`
}

// Load loads configuration from environment variables and defaults
func Load() (*Config, error) {
	config := &Config{
		Environment: getEnvOrDefault("ENVIRONMENT", "development"),
		
		Server: ServerConfig{
			Port:           getIntEnvOrDefault("SERVER_PORT", 8080),
			ReadTimeout:    getIntEnvOrDefault("SERVER_READ_TIMEOUT", 10),
			WriteTimeout:   getIntEnvOrDefault("SERVER_WRITE_TIMEOUT", 10),
			IdleTimeout:    getIntEnvOrDefault("SERVER_IDLE_TIMEOUT", 60),
			MaxHeaderBytes: getIntEnvOrDefault("SERVER_MAX_HEADER_BYTES", 1048576), // 1MB
		},
		
		Database: DatabaseConfig{
			Enabled:         getBoolEnvOrDefault("DATABASE_ENABLED", false),
			Driver:          getEnvOrDefault("DATABASE_DRIVER", "postgres"),
			Host:            getEnvOrDefault("DATABASE_HOST", "localhost"),
			Port:            getIntEnvOrDefault("DATABASE_PORT", 5432),
			Database:        getEnvOrDefault("DATABASE_NAME", "isectech_gateway"),
			Username:        getEnvOrDefault("DATABASE_USERNAME", "postgres"),
			Password:        getEnvOrDefault("DATABASE_PASSWORD", ""),
			SSLMode:         getEnvOrDefault("DATABASE_SSL_MODE", "disable"),
			MaxOpenConns:    getIntEnvOrDefault("DATABASE_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getIntEnvOrDefault("DATABASE_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getIntEnvOrDefault("DATABASE_CONN_MAX_LIFETIME", 300),
		},
		
		Redis: RedisConfig{
			Host:         getEnvOrDefault("REDIS_HOST", "localhost"),
			Port:         getIntEnvOrDefault("REDIS_PORT", 6379),
			Password:     getEnvOrDefault("REDIS_PASSWORD", ""),
			Database:     getIntEnvOrDefault("REDIS_DATABASE", 0),
			PoolSize:     getIntEnvOrDefault("REDIS_POOL_SIZE", 10),
			MinIdleConns: getIntEnvOrDefault("REDIS_MIN_IDLE_CONNS", 2),
			MaxRetries:   getIntEnvOrDefault("REDIS_MAX_RETRIES", 3),
			DialTimeout:  getIntEnvOrDefault("REDIS_DIAL_TIMEOUT", 5),
			ReadTimeout:  getIntEnvOrDefault("REDIS_READ_TIMEOUT", 3),
			WriteTimeout: getIntEnvOrDefault("REDIS_WRITE_TIMEOUT", 3),
		},
		
		Auth: AuthConfig{
			JWT: JWTConfig{
				Enabled:   getBoolEnvOrDefault("JWT_ENABLED", true),
				Secret:    getEnvOrDefault("JWT_SECRET", "isectech-jwt-secret-key"),
				PublicKey: getEnvOrDefault("JWT_PUBLIC_KEY", ""),
				Algorithm: getEnvOrDefault("JWT_ALGORITHM", "HS256"),
				Issuer:    getEnvOrDefault("JWT_ISSUER", "isectech-api-gateway"),
				Audience:  getEnvOrDefault("JWT_AUDIENCE", "isectech-platform"),
				TTL:       getIntEnvOrDefault("JWT_TTL", 3600), // 1 hour
			},
			APIKey: APIKeyConfig{
				Enabled:    getBoolEnvOrDefault("API_KEY_ENABLED", true),
				HeaderName: getEnvOrDefault("API_KEY_HEADER", "X-API-Key"),
				QueryParam: getEnvOrDefault("API_KEY_QUERY_PARAM", "api_key"),
			},
			OAuth: OAuthConfig{
				Enabled:      getBoolEnvOrDefault("OAUTH_ENABLED", false),
				Provider:     getEnvOrDefault("OAUTH_PROVIDER", "google"),
				ClientID:     getEnvOrDefault("OAUTH_CLIENT_ID", ""),
				ClientSecret: getEnvOrDefault("OAUTH_CLIENT_SECRET", ""),
				RedirectURL:  getEnvOrDefault("OAUTH_REDIRECT_URL", ""),
				Scopes:       getStringSliceEnv("OAUTH_SCOPES", []string{"openid", "email", "profile"}),
			},
		},
		
		CORS: CORSConfig{
			Enabled:          getBoolEnvOrDefault("CORS_ENABLED", true),
			AllowedOrigins:   getStringSliceEnv("CORS_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods:   getStringSliceEnv("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
			AllowedHeaders:   getStringSliceEnv("CORS_ALLOWED_HEADERS", []string{"*"}),
			ExposedHeaders:   getStringSliceEnv("CORS_EXPOSED_HEADERS", []string{}),
			AllowCredentials: getBoolEnvOrDefault("CORS_ALLOW_CREDENTIALS", true),
			MaxAge:           getIntEnvOrDefault("CORS_MAX_AGE", 3600),
		},
		
		RateLimit: RateLimitConfig{
			Enabled:           getBoolEnvOrDefault("RATE_LIMIT_ENABLED", true),
			RequestsPerSecond: getIntEnvOrDefault("RATE_LIMIT_RPS", 100),
			BurstSize:         getIntEnvOrDefault("RATE_LIMIT_BURST", 200),
			WindowSize:        getIntEnvOrDefault("RATE_LIMIT_WINDOW", 60),
			KeyExtractor:      getEnvOrDefault("RATE_LIMIT_KEY_EXTRACTOR", "ip"),
			SkipSuccessful:    getBoolEnvOrDefault("RATE_LIMIT_SKIP_SUCCESSFUL", false),
			SkipClientErrors:  getBoolEnvOrDefault("RATE_LIMIT_SKIP_CLIENT_ERRORS", false),
		},
		
		Monitoring: MonitoringConfig{
			Enabled:        getBoolEnvOrDefault("MONITORING_ENABLED", true),
			MetricsPath:    getEnvOrDefault("MONITORING_METRICS_PATH", "/metrics"),
			HealthPath:     getEnvOrDefault("MONITORING_HEALTH_PATH", "/health"),
			PrometheusAddr: getEnvOrDefault("PROMETHEUS_ADDR", ""),
		},
		
		Tracing: TracingConfig{
			Enabled:     getBoolEnvOrDefault("TRACING_ENABLED", false),
			ServiceName: getEnvOrDefault("TRACING_SERVICE_NAME", "isectech-api-gateway"),
			Endpoint:    getEnvOrDefault("TRACING_ENDPOINT", ""),
			SampleRate:  getFloatEnvOrDefault("TRACING_SAMPLE_RATE", 0.1),
		},
		
		Logging: LoggingConfig{
			Level:  getEnvOrDefault("LOG_LEVEL", "info"),
			Format: getEnvOrDefault("LOG_FORMAT", "json"),
		},
		
		Security: SecurityConfig{
			AllowedIPs:       getStringSliceEnv("SECURITY_ALLOWED_IPS", []string{}),
			BlockedIPs:       getStringSliceEnv("SECURITY_BLOCKED_IPS", []string{}),
			RequireHTTPS:     getBoolEnvOrDefault("SECURITY_REQUIRE_HTTPS", false),
			CSPHeader:        getEnvOrDefault("SECURITY_CSP_HEADER", "default-src 'self'"),
			HSTSMaxAge:       getIntEnvOrDefault("SECURITY_HSTS_MAX_AGE", 31536000), // 1 year
			RequestSizeLimit: getInt64EnvOrDefault("SECURITY_REQUEST_SIZE_LIMIT", 10485760), // 10MB
		},
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	
	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	
	// Validate database configuration
	if c.Database.Enabled {
		if c.Database.Host == "" {
			return fmt.Errorf("database host is required when database is enabled")
		}
		if c.Database.Database == "" {
			return fmt.Errorf("database name is required when database is enabled")
		}
	}
	
	// Validate Redis configuration
	if c.Redis.Host == "" {
		return fmt.Errorf("redis host is required")
	}
	if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
		return fmt.Errorf("invalid redis port: %d", c.Redis.Port)
	}
	
	// Validate JWT configuration
	if c.Auth.JWT.Enabled && c.Auth.JWT.Secret == "" && c.Auth.JWT.PublicKey == "" {
		return fmt.Errorf("JWT secret or public key is required when JWT is enabled")
	}
	
	// Validate tracing configuration
	if c.Tracing.Enabled && c.Tracing.Endpoint == "" {
		return fmt.Errorf("tracing endpoint is required when tracing is enabled")
	}
	
	return nil
}

// GetDatabaseDSN returns the database connection string
func (c *Config) GetDatabaseDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.Username,
		c.Database.Password,
		c.Database.Database,
		c.Database.SSLMode,
	)
}

// GetRedisAddr returns the Redis address
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}

// Helper functions for environment variables

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnvOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getInt64EnvOrDefault(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnvOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getFloatEnvOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getStringSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsStaging returns true if running in staging environment
func (c *Config) IsStaging() bool {
	return c.Environment == "staging"
}