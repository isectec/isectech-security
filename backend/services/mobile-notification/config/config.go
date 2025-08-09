package config

import (
	"fmt"
	"mobile-notification/infrastructure/batching"
	"mobile-notification/infrastructure/priority"
	"mobile-notification/infrastructure/push"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config represents the complete configuration for the mobile notification service
type Config struct {
	Server   ServerConfig             `yaml:"server"`
	Database DatabaseConfig           `yaml:"database"`
	Redis    RedisConfig              `yaml:"redis"`
	Push     push.PushConfig          `yaml:"push"`
	Batching batching.BatchingConfig  `yaml:"batching"`
	Priority priority.PriorityConfig  `yaml:"priority"`
	Logging  LoggingConfig            `yaml:"logging"`
	Metrics  MetricsConfig            `yaml:"metrics"`
	Security SecurityConfig           `yaml:"security"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Port            int    `yaml:"port"`
	Host            string `yaml:"host"`
	ReadTimeout     int    `yaml:"read_timeout"`
	WriteTimeout    int    `yaml:"write_timeout"`
	IdleTimeout     int    `yaml:"idle_timeout"`
	ShutdownTimeout int    `yaml:"shutdown_timeout"`
	EnableTLS       bool   `yaml:"enable_tls"`
	CertFile        string `yaml:"cert_file"`
	KeyFile         string `yaml:"key_file"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	Database        string `yaml:"database"`
	SSLMode         string `yaml:"ssl_mode"`
	MaxOpenConns    int    `yaml:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns"`
	ConnMaxLifetime int    `yaml:"conn_max_lifetime"`
	MigrationsPath  string `yaml:"migrations_path"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Password    string `yaml:"password"`
	Database    int    `yaml:"database"`
	PoolSize    int    `yaml:"pool_size"`
	MinIdleConns int   `yaml:"min_idle_conns"`
	MaxRetries  int    `yaml:"max_retries"`
	DialTimeout int    `yaml:"dial_timeout"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	Structured bool   `yaml:"structured"`
}

// MetricsConfig represents metrics and monitoring configuration
type MetricsConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Port           int    `yaml:"port"`
	Path           string `yaml:"path"`
	EnablePprof    bool   `yaml:"enable_pprof"`
	CollectRuntime bool   `yaml:"collect_runtime"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	EnableRateLimit     bool     `yaml:"enable_rate_limit"`
	RateLimit           int      `yaml:"rate_limit"`
	RateLimitWindow     int      `yaml:"rate_limit_window"`
	EnableTenantIsolation bool   `yaml:"enable_tenant_isolation"`
	AllowedOrigins      []string `yaml:"allowed_origins"`
	EnableAPIKeys       bool     `yaml:"enable_api_keys"`
	APIKeys             []string `yaml:"api_keys"`
	JWTSecret           string   `yaml:"jwt_secret"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:            8080,
			Host:            "0.0.0.0",
			ReadTimeout:     30,
			WriteTimeout:    30,
			IdleTimeout:     120,
			ShutdownTimeout: 30,
			EnableTLS:       false,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            5432,
			Username:        "postgres",
			Password:        "password",
			Database:        "mobile_notifications",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 3600,
			MigrationsPath:  "./infrastructure/database/migrations",
		},
		Redis: RedisConfig{
			Host:         "localhost",
			Port:         6379,
			Database:     0,
			PoolSize:     10,
			MinIdleConns: 5,
			MaxRetries:   3,
			DialTimeout:  5,
		},
		Push: push.PushConfig{
			FCM: push.FCMConfig{
				DefaultTTL:             3600,
				MaxRetries:             3,
				RetryDelay:             5,
				BatchSize:              500,
				EnableDeliveryReceipts: true,
			},
			APNS: push.APNSConfig{
				AuthType:    "certificate",
				Production:  false,
				MaxRetries:  3,
				RetryDelay:  5,
				BatchSize:   100,
				DefaultTTL:  3600,
			},
		},
		Batching: batching.BatchingConfig{
			CriticalBatchInterval:      0,    // Immediate
			WarningBatchInterval:       300,  // 5 minutes
			InformationalBatchInterval: 3600, // 1 hour
			MaxBatchSize:               100,
			MaxCriticalBatchSize:       50,
			QuietHoursBatchInterval:    21600, // 6 hours
			RespectQuietHours:          true,
			MaxNotificationsPerUser:    20,
			FatigueWindowHours:         24,
			ProcessingInterval:         60,
			EnableBatching:             true,
		},
		Priority: priority.PriorityConfig{
			CriticalRateLimit:             1000,
			WarningRateLimit:              500,
			InformationalRateLimit:        100,
			MaxCriticalQueueSize:          10000,
			MaxWarningQueueSize:           5000,
			MaxInformationalQueueSize:     2000,
			EnableEscalation:              true,
			WarningToEscalationTime:       1800, // 30 minutes
			InfoToWarningTime:             3600, // 1 hour
			EnableSuppression:             true,
			DuplicateWindow:               300, // 5 minutes
			MaxDuplicatesPerWindow:        3,
			EnableCircuitBreaker:          true,
			FailureThreshold:              50,
			CircuitBreakerWindow:          300, // 5 minutes
			CircuitBreakerRecoveryTime:    600, // 10 minutes
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			Structured: true,
		},
		Metrics: MetricsConfig{
			Enabled:        true,
			Port:           9090,
			Path:           "/metrics",
			EnablePprof:    false,
			CollectRuntime: true,
		},
		Security: SecurityConfig{
			EnableRateLimit:       true,
			RateLimit:            1000,
			RateLimitWindow:      60,
			EnableTenantIsolation: true,
			AllowedOrigins:       []string{"*"},
			EnableAPIKeys:        true,
			APIKeys:              []string{},
		},
	}
}

// LoadConfig loads configuration from a YAML file with environment variable overrides
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Load from file if provided
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	// Override with environment variables
	overrideWithEnvVars(config)

	return config, nil
}

// overrideWithEnvVars overrides configuration with environment variables
func overrideWithEnvVars(config *Config) {
	// Server config
	if val := os.Getenv("SERVER_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.Server.Port = port
		}
	}
	if val := os.Getenv("SERVER_HOST"); val != "" {
		config.Server.Host = val
	}

	// Database config
	if val := os.Getenv("DB_HOST"); val != "" {
		config.Database.Host = val
	}
	if val := os.Getenv("DB_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.Database.Port = port
		}
	}
	if val := os.Getenv("DB_USERNAME"); val != "" {
		config.Database.Username = val
	}
	if val := os.Getenv("DB_PASSWORD"); val != "" {
		config.Database.Password = val
	}
	if val := os.Getenv("DB_DATABASE"); val != "" {
		config.Database.Database = val
	}
	if val := os.Getenv("DB_SSL_MODE"); val != "" {
		config.Database.SSLMode = val
	}

	// Redis config
	if val := os.Getenv("REDIS_HOST"); val != "" {
		config.Redis.Host = val
	}
	if val := os.Getenv("REDIS_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			config.Redis.Port = port
		}
	}
	if val := os.Getenv("REDIS_PASSWORD"); val != "" {
		config.Redis.Password = val
	}

	// FCM config
	if val := os.Getenv("FCM_PROJECT_ID"); val != "" {
		config.Push.FCM.ProjectID = val
	}
	if val := os.Getenv("FCM_CREDENTIALS_FILE"); val != "" {
		config.Push.FCM.CredentialsFile = val
	}
	if val := os.Getenv("FCM_CREDENTIALS_JSON"); val != "" {
		config.Push.FCM.CredentialsJSON = val
	}

	// APNS config
	if val := os.Getenv("APNS_AUTH_TYPE"); val != "" {
		config.Push.APNS.AuthType = val
	}
	if val := os.Getenv("APNS_CERTIFICATE_FILE"); val != "" {
		config.Push.APNS.CertificateFile = val
	}
	if val := os.Getenv("APNS_CERTIFICATE_PASS"); val != "" {
		config.Push.APNS.CertificatePass = val
	}
	if val := os.Getenv("APNS_KEY_ID"); val != "" {
		config.Push.APNS.KeyID = val
	}
	if val := os.Getenv("APNS_TEAM_ID"); val != "" {
		config.Push.APNS.TeamID = val
	}
	if val := os.Getenv("APNS_PRIVATE_KEY_FILE"); val != "" {
		config.Push.APNS.PrivateKeyFile = val
	}
	if val := os.Getenv("APNS_TOPIC"); val != "" {
		config.Push.APNS.Topic = val
	}
	if val := os.Getenv("APNS_PRODUCTION"); val != "" {
		if production, err := strconv.ParseBool(val); err == nil {
			config.Push.APNS.Production = production
		}
	}

	// Logging config
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		config.Logging.Level = val
	}
	if val := os.Getenv("LOG_FORMAT"); val != "" {
		config.Logging.Format = val
	}

	// Security config
	if val := os.Getenv("JWT_SECRET"); val != "" {
		config.Security.JWTSecret = val
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server config
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// Validate database config
	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if c.Database.Username == "" {
		return fmt.Errorf("database username is required")
	}
	if c.Database.Database == "" {
		return fmt.Errorf("database name is required")
	}

	// Validate push config
	if c.Push.FCM.ProjectID == "" && c.Push.APNS.Topic == "" {
		return fmt.Errorf("at least one push service (FCM or APNS) must be configured")
	}

	// Validate FCM config if enabled
	if c.Push.FCM.ProjectID != "" {
		if c.Push.FCM.CredentialsFile == "" && c.Push.FCM.CredentialsJSON == "" {
			return fmt.Errorf("FCM credentials_file or credentials_json is required")
		}
	}

	// Validate APNS config if enabled
	if c.Push.APNS.Topic != "" {
		switch c.Push.APNS.AuthType {
		case "certificate":
			if c.Push.APNS.CertificateFile == "" {
				return fmt.Errorf("APNS certificate_file is required for certificate auth")
			}
		case "token":
			if c.Push.APNS.KeyID == "" || c.Push.APNS.TeamID == "" || c.Push.APNS.PrivateKeyFile == "" {
				return fmt.Errorf("APNS key_id, team_id, and private_key_file are required for token auth")
			}
		default:
			return fmt.Errorf("invalid APNS auth_type: %s (must be 'certificate' or 'token')", c.Push.APNS.AuthType)
		}
	}

	// Validate batching config
	if c.Batching.EnableBatching {
		if c.Batching.MaxBatchSize <= 0 {
			return fmt.Errorf("max_batch_size must be greater than 0")
		}
		if c.Batching.ProcessingInterval <= 0 {
			return fmt.Errorf("processing_interval must be greater than 0")
		}
	}

	// Validate priority config
	if c.Priority.MaxCriticalQueueSize <= 0 {
		return fmt.Errorf("max_critical_queue_size must be greater than 0")
	}

	return nil
}

// GetDSN returns the database connection string
func (c *Config) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.Username,
		c.Database.Password,
		c.Database.Database,
		c.Database.SSLMode,
	)
}

// GetRedisAddr returns the Redis connection address
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}