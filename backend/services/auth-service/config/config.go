package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	httpDelivery "isectech/auth-service/delivery/http"
	"isectech/auth-service/infrastructure/database/postgres"
	"isectech/auth-service/usecase"
)

// Config represents the complete application configuration
type Config struct {
	// Service configuration
	Service usecase.ServiceConfig `yaml:"service"`

	// Database configuration
	Database postgres.DatabaseConfig `yaml:"database"`

	// HTTP server configuration
	HTTP httpDelivery.RouterConfig `yaml:"http"`

	// Middleware configuration
	Middleware httpDelivery.MiddlewareConfig `yaml:"middleware"`

	// External services
	Email          EmailConfig          `yaml:"email"`
	SMS            SMSConfig            `yaml:"sms"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	Security       SecurityConfig       `yaml:"security"`
	RiskEvaluation RiskEvaluationConfig `yaml:"risk_evaluation"`

	// Application settings
	LogLevel    string `yaml:"log_level" default:"info"`
	Environment string `yaml:"environment" default:"production"`
}

// EmailConfig holds email service configuration
type EmailConfig struct {
	Provider string `yaml:"provider" default:"smtp"`

	// SMTP settings
	SMTPHost     string `yaml:"smtp_host"`
	SMTPPort     int    `yaml:"smtp_port" default:"587"`
	SMTPUsername string `yaml:"smtp_username"`
	SMTPPassword string `yaml:"smtp_password"`
	SMTPUseTLS   bool   `yaml:"smtp_use_tls" default:"true"`

	// Email settings
	FromAddress string `yaml:"from_address"`
	FromName    string `yaml:"from_name" default:"iSECTECH Security"`

	// Templates
	TemplateDir string `yaml:"template_dir" default:"./templates/email"`

	// Provider-specific (SendGrid, SES, etc.)
	APIKey   string `yaml:"api_key"`
	Region   string `yaml:"region"`
	Endpoint string `yaml:"endpoint"`

	// Retry settings
	MaxRetries    int           `yaml:"max_retries" default:"3"`
	RetryInterval time.Duration `yaml:"retry_interval" default:"5s"`
}

// SMSConfig holds SMS service configuration
type SMSConfig struct {
	Provider string `yaml:"provider" default:"twilio"`

	// Twilio settings
	AccountSID string `yaml:"account_sid"`
	AuthToken  string `yaml:"auth_token"`
	FromNumber string `yaml:"from_number"`

	// AWS SNS settings
	AWSRegion    string `yaml:"aws_region"`
	AWSAccessKey string `yaml:"aws_access_key"`
	AWSSecretKey string `yaml:"aws_secret_key"`

	// Provider-agnostic settings
	APIKey   string `yaml:"api_key"`
	Endpoint string `yaml:"endpoint"`

	// Retry settings
	MaxRetries    int           `yaml:"max_retries" default:"3"`
	RetryInterval time.Duration `yaml:"retry_interval" default:"5s"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Provider string `yaml:"provider" default:"redis"`

	// Redis settings
	RedisHost     string `yaml:"redis_host" default:"localhost"`
	RedisPort     int    `yaml:"redis_port" default:"6379"`
	RedisPassword string `yaml:"redis_password"`
	RedisDB       int    `yaml:"redis_db" default:"0"`

	// Rate limit settings
	DefaultLimit        int           `yaml:"default_limit" default:"100"`
	DefaultWindow       time.Duration `yaml:"default_window" default:"1m"`
	LoginLimit          int           `yaml:"login_limit" default:"5"`
	LoginWindow         time.Duration `yaml:"login_window" default:"15m"`
	MFALimit            int           `yaml:"mfa_limit" default:"10"`
	MFAWindow           time.Duration `yaml:"mfa_window" default:"5m"`
	PasswordResetLimit  int           `yaml:"password_reset_limit" default:"3"`
	PasswordResetWindow time.Duration `yaml:"password_reset_window" default:"1h"`

	// Advanced settings
	EnableDistributed bool `yaml:"enable_distributed" default:"true"`
	BurstMultiplier   int  `yaml:"burst_multiplier" default:"2"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	// IP blocking
	EnableIPBlocking  bool          `yaml:"enable_ip_blocking" default:"true"`
	MaxFailedAttempts int           `yaml:"max_failed_attempts" default:"10"`
	BlockDuration     time.Duration `yaml:"block_duration" default:"1h"`
	WhitelistIPs      []string      `yaml:"whitelist_ips"`

	// Geo-blocking
	EnableGeoBlocking bool     `yaml:"enable_geo_blocking" default:"false"`
	BlockedCountries  []string `yaml:"blocked_countries"`
	AllowedCountries  []string `yaml:"allowed_countries"`

	// Device tracking
	EnableDeviceTracking bool `yaml:"enable_device_tracking" default:"true"`
	MaxDevicesPerUser    int  `yaml:"max_devices_per_user" default:"10"`

	// Advanced threat protection
	EnableThreatIntel   bool   `yaml:"enable_threat_intel" default:"false"`
	ThreatIntelProvider string `yaml:"threat_intel_provider"`
	ThreatIntelAPIKey   string `yaml:"threat_intel_api_key"`

	// Security headers and policies
	EnableCSP  bool   `yaml:"enable_csp" default:"true"`
	CSPPolicy  string `yaml:"csp_policy"`
	EnableHSTS bool   `yaml:"enable_hsts" default:"true"`
	HSTSMaxAge int    `yaml:"hsts_max_age" default:"31536000"`
}

// RiskEvaluationConfig holds risk evaluation configuration
type RiskEvaluationConfig struct {
	Provider string `yaml:"provider" default:"internal"`

	// Risk scoring thresholds
	LowRiskThreshold      float64 `yaml:"low_risk_threshold" default:"3.0"`
	MediumRiskThreshold   float64 `yaml:"medium_risk_threshold" default:"6.0"`
	HighRiskThreshold     float64 `yaml:"high_risk_threshold" default:"8.0"`
	CriticalRiskThreshold float64 `yaml:"critical_risk_threshold" default:"9.5"`

	// Risk factors configuration
	EnableLocationAnalysis bool `yaml:"enable_location_analysis" default:"true"`
	EnableDeviceAnalysis   bool `yaml:"enable_device_analysis" default:"true"`
	EnableBehaviorAnalysis bool `yaml:"enable_behavior_analysis" default:"true"`
	EnableThreatIntel      bool `yaml:"enable_threat_intel" default:"false"`

	// External risk providers
	RiskProviderAPIKey   string `yaml:"risk_provider_api_key"`
	RiskProviderEndpoint string `yaml:"risk_provider_endpoint"`

	// Machine learning model settings
	ModelPath           string        `yaml:"model_path"`
	ModelUpdateInterval time.Duration `yaml:"model_update_interval" default:"24h"`
	EnableModelTraining bool          `yaml:"enable_model_training" default:"false"`

	// Response actions
	AutoBlockHighRisk    bool `yaml:"auto_block_high_risk" default:"false"`
	RequireMFAMediumRisk bool `yaml:"require_mfa_medium_risk" default:"true"`
	RequireMFAHighRisk   bool `yaml:"require_mfa_high_risk" default:"true"`
}

// LoadConfig loads configuration from file with environment variable overrides
func LoadConfig(configFile string) (*Config, error) {
	// Set default values
	config := &Config{
		LogLevel:    "info",
		Environment: "production",
	}

	// Load from file if it exists
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			data, err := os.ReadFile(configFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}

			if err := yaml.Unmarshal(data, config); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables
	if err := loadFromEnvironment(config); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// loadFromEnvironment loads configuration from environment variables
func loadFromEnvironment(config *Config) error {
	// Application settings
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		config.Environment = env
	}

	// Database settings
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		config.Database.Host = dbHost
	}
	if dbPort := os.Getenv("DB_PORT"); dbPort != "" {
		// Parse port number
		config.Database.Port = 5432 // default, could parse from string
	}
	if dbName := os.Getenv("DB_NAME"); dbName != "" {
		config.Database.Database = dbName
	}
	if dbUser := os.Getenv("DB_USER"); dbUser != "" {
		config.Database.Username = dbUser
	}
	if dbPass := os.Getenv("DB_PASSWORD"); dbPass != "" {
		config.Database.Password = dbPass
	}

	// Service settings
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		config.Service.JWTSecret = jwtSecret
	}
	if encKey := os.Getenv("ENCRYPTION_KEY"); encKey != "" {
		config.Service.EncryptionKey = encKey
	}

	// HTTP settings
	if httpPort := os.Getenv("HTTP_PORT"); httpPort != "" {
		config.HTTP.Port = 8080 // default, could parse from string
	}
	if httpHost := os.Getenv("HTTP_HOST"); httpHost != "" {
		config.HTTP.Host = httpHost
	}

	// Email settings
	if smtpHost := os.Getenv("SMTP_HOST"); smtpHost != "" {
		config.Email.SMTPHost = smtpHost
	}
	if smtpUser := os.Getenv("SMTP_USERNAME"); smtpUser != "" {
		config.Email.SMTPUsername = smtpUser
	}
	if smtpPass := os.Getenv("SMTP_PASSWORD"); smtpPass != "" {
		config.Email.SMTPPassword = smtpPass
	}
	if fromAddr := os.Getenv("EMAIL_FROM_ADDRESS"); fromAddr != "" {
		config.Email.FromAddress = fromAddr
	}

	// SMS settings
	if twilioSID := os.Getenv("TWILIO_ACCOUNT_SID"); twilioSID != "" {
		config.SMS.AccountSID = twilioSID
	}
	if twilioToken := os.Getenv("TWILIO_AUTH_TOKEN"); twilioToken != "" {
		config.SMS.AuthToken = twilioToken
	}
	if twilioFrom := os.Getenv("TWILIO_FROM_NUMBER"); twilioFrom != "" {
		config.SMS.FromNumber = twilioFrom
	}

	// Redis settings
	if redisHost := os.Getenv("REDIS_HOST"); redisHost != "" {
		config.RateLimit.RedisHost = redisHost
	}
	if redisPass := os.Getenv("REDIS_PASSWORD"); redisPass != "" {
		config.RateLimit.RedisPassword = redisPass
	}

	return nil
}

// validateConfig validates the configuration for required fields and consistency
func validateConfig(config *Config) error {
	// Validate JWT secret
	if config.Service.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}
	if len(config.Service.JWTSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}

	// Validate encryption key
	if config.Service.EncryptionKey == "" {
		return fmt.Errorf("ENCRYPTION_KEY is required")
	}
	if len(config.Service.EncryptionKey) != 32 {
		return fmt.Errorf("ENCRYPTION_KEY must be exactly 32 characters")
	}

	// Validate database configuration
	if config.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if config.Database.Database == "" {
		return fmt.Errorf("database name is required")
	}
	if config.Database.Username == "" {
		return fmt.Errorf("database username is required")
	}

	// Validate HTTP configuration
	if config.HTTP.Port <= 0 || config.HTTP.Port > 65535 {
		return fmt.Errorf("HTTP port must be between 1 and 65535")
	}

	// Validate TLS configuration
	if config.HTTP.EnableTLS {
		if config.HTTP.TLSCertFile == "" {
			return fmt.Errorf("TLS certificate file is required when TLS is enabled")
		}
		if config.HTTP.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file is required when TLS is enabled")
		}
	}

	// Validate email configuration if email notifications are enabled
	if config.Email.Provider == "smtp" {
		if config.Email.SMTPHost == "" {
			return fmt.Errorf("SMTP host is required for email provider 'smtp'")
		}
		if config.Email.FromAddress == "" {
			return fmt.Errorf("from address is required for email notifications")
		}
	}

	// Validate SMS configuration if SMS is enabled
	if config.SMS.Provider == "twilio" {
		if config.SMS.AccountSID == "" || config.SMS.AuthToken == "" {
			return fmt.Errorf("Twilio credentials are required for SMS provider 'twilio'")
		}
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

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development" || c.Environment == "dev"
}

// IsDebug returns true if debug logging is enabled
func (c *Config) IsDebug() bool {
	return c.LogLevel == "debug"
}
