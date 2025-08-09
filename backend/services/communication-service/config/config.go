package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// CommunicationServiceConfig holds all configuration for the communication service
type CommunicationServiceConfig struct {
	// Server configuration
	Server ServerConfig `json:"server"`

	// Database configuration
	Database DatabaseConfig `json:"database"`

	// Email provider configurations
	EmailProviders EmailProvidersConfig `json:"email_providers"`

	// Template management configuration
	Templates TemplateConfig `json:"templates"`

	// Analytics configuration
	Analytics AnalyticsConfig `json:"analytics"`

	// Scheduling and automation
	Scheduler SchedulerConfig `json:"scheduler"`

	// A/B testing configuration
	ABTesting ABTestingConfig `json:"ab_testing"`

	// Rate limiting configuration
	RateLimit RateLimitConfig `json:"rate_limit"`

	// Localization configuration
	Localization LocalizationConfig `json:"localization"`

	// Security configuration
	Security SecurityConfig `json:"security"`
}

// ServerConfig holds server-specific settings
type ServerConfig struct {
	Port            string        `json:"port"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout"`
	MaxHeaderBytes  int           `json:"max_header_bytes"`
}

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	Host                 string        `json:"host"`
	Port                 string        `json:"port"`
	Database             string        `json:"database"`
	Username             string        `json:"username"`
	Password             string        `json:"password"`
	SSLMode              string        `json:"ssl_mode"`
	MaxOpenConnections   int           `json:"max_open_connections"`
	MaxIdleConnections   int           `json:"max_idle_connections"`
	ConnectionMaxLifetime time.Duration `json:"connection_max_lifetime"`
	MigrationPath        string        `json:"migration_path"`
}

// EmailProvidersConfig holds configurations for all email providers
type EmailProvidersConfig struct {
	SendGrid SendGridConfig `json:"sendgrid"`
	AWSSES   AWSSESConfig   `json:"aws_ses"`
	Mailgun  MailgunConfig  `json:"mailgun"`
	Default  string         `json:"default"` // Default provider name
}

// SendGridConfig holds SendGrid-specific configuration
type SendGridConfig struct {
	APIKey              string `json:"api_key"`
	FromEmail           string `json:"from_email"`
	FromName            string `json:"from_name"`
	WebhookSecret       string `json:"webhook_secret"`
	TrackingEnabled     bool   `json:"tracking_enabled"`
	ClickTrackingEnabled bool   `json:"click_tracking_enabled"`
	OpenTrackingEnabled bool   `json:"open_tracking_enabled"`
	MaxDailyEmails      int    `json:"max_daily_emails"`
	MaxHourlyEmails     int    `json:"max_hourly_emails"`
}

// AWSSESConfig holds AWS SES configuration
type AWSSESConfig struct {
	Region              string `json:"region"`
	AccessKeyID         string `json:"access_key_id"`
	SecretAccessKey     string `json:"secret_access_key"`
	ConfigurationSet    string `json:"configuration_set"`
	FromEmail           string `json:"from_email"`
	FromName            string `json:"from_name"`
	MaxSendRate         int    `json:"max_send_rate"`         // Per second
	Max24HourSend       int    `json:"max_24_hour_send"`      // Per day
	BounceNotificationTopic string `json:"bounce_notification_topic"`
	ComplaintNotificationTopic string `json:"complaint_notification_topic"`
}

// MailgunConfig holds Mailgun configuration
type MailgunConfig struct {
	APIKey        string `json:"api_key"`
	Domain        string `json:"domain"`
	Region        string `json:"region"` // us, eu
	FromEmail     string `json:"from_email"`
	FromName      string `json:"from_name"`
	WebhookSecret string `json:"webhook_secret"`
}

// TemplateConfig holds template management settings
type TemplateConfig struct {
	DefaultLanguage     string        `json:"default_language"`
	CacheEnabled        bool          `json:"cache_enabled"`
	CacheTTL            time.Duration `json:"cache_ttl"`
	TemplateStoragePath string        `json:"template_storage_path"`
	ValidationEnabled   bool          `json:"validation_enabled"`
	MinificationEnabled bool          `json:"minification_enabled"`
}

// AnalyticsConfig holds analytics configuration
type AnalyticsConfig struct {
	Enabled                bool          `json:"enabled"`
	TrackOpens            bool          `json:"track_opens"`
	TrackClicks           bool          `json:"track_clicks"`
	TrackUnsubscribes     bool          `json:"track_unsubscribes"`
	TrackBounces          bool          `json:"track_bounces"`
	TrackComplaints       bool          `json:"track_complaints"`
	RetentionPeriodDays   int           `json:"retention_period_days"`
	BatchSize             int           `json:"batch_size"`
	FlushInterval         time.Duration `json:"flush_interval"`
	ExportEnabled         bool          `json:"export_enabled"`
}

// SchedulerConfig holds scheduling and automation settings
type SchedulerConfig struct {
	Enabled                 bool          `json:"enabled"`
	ProcessingInterval      time.Duration `json:"processing_interval"`
	MaxRetryAttempts        int           `json:"max_retry_attempts"`
	RetryBackoffMultiplier  float64       `json:"retry_backoff_multiplier"`
	BaseRetryDelay          time.Duration `json:"base_retry_delay"`
	MaxRetryDelay           time.Duration `json:"max_retry_delay"`
	BatchSize               int           `json:"batch_size"`
	WorkerPoolSize          int           `json:"worker_pool_size"`
	DeadLetterQueueEnabled  bool          `json:"dead_letter_queue_enabled"`
	ScheduledCleanupEnabled bool          `json:"scheduled_cleanup_enabled"`
	CleanupInterval         time.Duration `json:"cleanup_interval"`
	MaxQueueSize            int           `json:"max_queue_size"`
}

// ABTestingConfig holds A/B testing configuration
type ABTestingConfig struct {
	Enabled                   bool    `json:"enabled"`
	MinimumSampleSize         int     `json:"minimum_sample_size"`
	MinimumConfidenceLevel    float64 `json:"minimum_confidence_level"`
	MaxTestDurationDays       int     `json:"max_test_duration_days"`
	AutoPromoteWinner         bool    `json:"auto_promote_winner"`
	StatisticalSignificanceThreshold float64 `json:"statistical_significance_threshold"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	GlobalEnabled       bool `json:"global_enabled"`
	GlobalRatePerSecond int  `json:"global_rate_per_second"`
	GlobalBurstSize     int  `json:"global_burst_size"`
	
	PerTenantEnabled       bool `json:"per_tenant_enabled"`
	PerTenantRatePerSecond int  `json:"per_tenant_rate_per_second"`
	PerTenantBurstSize     int  `json:"per_tenant_burst_size"`
	
	PerUserEnabled       bool `json:"per_user_enabled"`
	PerUserRatePerSecond int  `json:"per_user_rate_per_second"`
	PerUserBurstSize     int  `json:"per_user_burst_size"`
}

// LocalizationConfig holds localization settings
type LocalizationConfig struct {
	DefaultLocale         string   `json:"default_locale"`
	SupportedLocales      []string `json:"supported_locales"`
	FallbackLocale        string   `json:"fallback_locale"`
	TranslationServiceURL string   `json:"translation_service_url"`
	CacheTranslations     bool     `json:"cache_translations"`
	AutoDetectLocale      bool     `json:"auto_detect_locale"`
}

// SecurityConfig holds security-related settings
type SecurityConfig struct {
	EncryptPII            bool   `json:"encrypt_pii"`
	PIIEncryptionKey      string `json:"pii_encryption_key"`
	AuditLogEnabled       bool   `json:"audit_log_enabled"`
	DataResidencyRegions  []string `json:"data_residency_regions"`
	IPWhitelistEnabled    bool   `json:"ip_whitelist_enabled"`
	IPWhitelist           []string `json:"ip_whitelist"`
	RequireHTTPS          bool   `json:"require_https"`
	CSRFProtectionEnabled bool   `json:"csrf_protection_enabled"`
	CSRFSecretKey         string `json:"csrf_secret_key"`
	JWTSecretKey          string `json:"jwt_secret_key"`
	JWTExpirationTime     time.Duration `json:"jwt_expiration_time"`
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*CommunicationServiceConfig, error) {
	config := &CommunicationServiceConfig{
		Server: ServerConfig{
			Port:            getEnv("SERVER_PORT", "8080"),
			ReadTimeout:     parseDuration("SERVER_READ_TIMEOUT", "30s"),
			WriteTimeout:    parseDuration("SERVER_WRITE_TIMEOUT", "30s"),
			IdleTimeout:     parseDuration("SERVER_IDLE_TIMEOUT", "60s"),
			ShutdownTimeout: parseDuration("SERVER_SHUTDOWN_TIMEOUT", "15s"),
			MaxHeaderBytes:  parseInt("SERVER_MAX_HEADER_BYTES", "1048576"), // 1MB
		},
		Database: DatabaseConfig{
			Host:                  getEnv("DB_HOST", "localhost"),
			Port:                  getEnv("DB_PORT", "5432"),
			Database:              getEnv("DB_NAME", "communication_service"),
			Username:              getEnv("DB_USERNAME", "postgres"),
			Password:              getEnv("DB_PASSWORD", ""),
			SSLMode:               getEnv("DB_SSL_MODE", "prefer"),
			MaxOpenConnections:    parseInt("DB_MAX_OPEN_CONNECTIONS", "25"),
			MaxIdleConnections:    parseInt("DB_MAX_IDLE_CONNECTIONS", "5"),
			ConnectionMaxLifetime: parseDuration("DB_CONNECTION_MAX_LIFETIME", "1h"),
			MigrationPath:         getEnv("DB_MIGRATION_PATH", "file://migrations"),
		},
		EmailProviders: EmailProvidersConfig{
			SendGrid: SendGridConfig{
				APIKey:              getEnv("SENDGRID_API_KEY", ""),
				FromEmail:           getEnv("SENDGRID_FROM_EMAIL", "noreply@isectech.com"),
				FromName:            getEnv("SENDGRID_FROM_NAME", "iSECTECH Protect"),
				WebhookSecret:       getEnv("SENDGRID_WEBHOOK_SECRET", ""),
				TrackingEnabled:     parseBool("SENDGRID_TRACKING_ENABLED", "true"),
				ClickTrackingEnabled: parseBool("SENDGRID_CLICK_TRACKING_ENABLED", "true"),
				OpenTrackingEnabled: parseBool("SENDGRID_OPEN_TRACKING_ENABLED", "true"),
				MaxDailyEmails:      parseInt("SENDGRID_MAX_DAILY_EMAILS", "40000"),
				MaxHourlyEmails:     parseInt("SENDGRID_MAX_HOURLY_EMAILS", "3000"),
			},
			AWSSES: AWSSESConfig{
				Region:                     getEnv("AWS_SES_REGION", "us-east-1"),
				AccessKeyID:                getEnv("AWS_SES_ACCESS_KEY_ID", ""),
				SecretAccessKey:            getEnv("AWS_SES_SECRET_ACCESS_KEY", ""),
				ConfigurationSet:           getEnv("AWS_SES_CONFIGURATION_SET", ""),
				FromEmail:                  getEnv("AWS_SES_FROM_EMAIL", "noreply@isectech.com"),
				FromName:                   getEnv("AWS_SES_FROM_NAME", "iSECTECH Protect"),
				MaxSendRate:                parseInt("AWS_SES_MAX_SEND_RATE", "14"),
				Max24HourSend:             parseInt("AWS_SES_MAX_24_HOUR_SEND", "200"),
				BounceNotificationTopic:    getEnv("AWS_SES_BOUNCE_NOTIFICATION_TOPIC", ""),
				ComplaintNotificationTopic: getEnv("AWS_SES_COMPLAINT_NOTIFICATION_TOPIC", ""),
			},
			Mailgun: MailgunConfig{
				APIKey:        getEnv("MAILGUN_API_KEY", ""),
				Domain:        getEnv("MAILGUN_DOMAIN", ""),
				Region:        getEnv("MAILGUN_REGION", "us"),
				FromEmail:     getEnv("MAILGUN_FROM_EMAIL", "noreply@isectech.com"),
				FromName:      getEnv("MAILGUN_FROM_NAME", "iSECTECH Protect"),
				WebhookSecret: getEnv("MAILGUN_WEBHOOK_SECRET", ""),
			},
			Default: getEnv("EMAIL_DEFAULT_PROVIDER", "sendgrid"),
		},
		Templates: TemplateConfig{
			DefaultLanguage:     getEnv("TEMPLATES_DEFAULT_LANGUAGE", "en"),
			CacheEnabled:        parseBool("TEMPLATES_CACHE_ENABLED", "true"),
			CacheTTL:            parseDuration("TEMPLATES_CACHE_TTL", "10m"),
			TemplateStoragePath: getEnv("TEMPLATES_STORAGE_PATH", "./templates"),
			ValidationEnabled:   parseBool("TEMPLATES_VALIDATION_ENABLED", "true"),
			MinificationEnabled: parseBool("TEMPLATES_MINIFICATION_ENABLED", "true"),
		},
		Analytics: AnalyticsConfig{
			Enabled:             parseBool("ANALYTICS_ENABLED", "true"),
			TrackOpens:         parseBool("ANALYTICS_TRACK_OPENS", "true"),
			TrackClicks:        parseBool("ANALYTICS_TRACK_CLICKS", "true"),
			TrackUnsubscribes:  parseBool("ANALYTICS_TRACK_UNSUBSCRIBES", "true"),
			TrackBounces:       parseBool("ANALYTICS_TRACK_BOUNCES", "true"),
			TrackComplaints:    parseBool("ANALYTICS_TRACK_COMPLAINTS", "true"),
			RetentionPeriodDays: parseInt("ANALYTICS_RETENTION_PERIOD_DAYS", "365"),
			BatchSize:          parseInt("ANALYTICS_BATCH_SIZE", "100"),
			FlushInterval:      parseDuration("ANALYTICS_FLUSH_INTERVAL", "30s"),
			ExportEnabled:      parseBool("ANALYTICS_EXPORT_ENABLED", "true"),
		},
		Scheduler: SchedulerConfig{
			Enabled:                 parseBool("SCHEDULER_ENABLED", "true"),
			ProcessingInterval:      parseDuration("SCHEDULER_PROCESSING_INTERVAL", "1m"),
			MaxRetryAttempts:        parseInt("SCHEDULER_MAX_RETRY_ATTEMPTS", "3"),
			RetryBackoffMultiplier:  parseFloat("SCHEDULER_RETRY_BACKOFF_MULTIPLIER", "2.0"),
			BaseRetryDelay:          parseDuration("SCHEDULER_BASE_RETRY_DELAY", "1m"),
			MaxRetryDelay:           parseDuration("SCHEDULER_MAX_RETRY_DELAY", "1h"),
			BatchSize:               parseInt("SCHEDULER_BATCH_SIZE", "50"),
			WorkerPoolSize:          parseInt("SCHEDULER_WORKER_POOL_SIZE", "10"),
			DeadLetterQueueEnabled:  parseBool("SCHEDULER_DEAD_LETTER_QUEUE_ENABLED", "true"),
			ScheduledCleanupEnabled: parseBool("SCHEDULER_SCHEDULED_CLEANUP_ENABLED", "true"),
			CleanupInterval:         parseDuration("SCHEDULER_CLEANUP_INTERVAL", "24h"),
			MaxQueueSize:            parseInt("SCHEDULER_MAX_QUEUE_SIZE", "10000"),
		},
		ABTesting: ABTestingConfig{
			Enabled:                   parseBool("AB_TESTING_ENABLED", "true"),
			MinimumSampleSize:         parseInt("AB_TESTING_MINIMUM_SAMPLE_SIZE", "100"),
			MinimumConfidenceLevel:    parseFloat("AB_TESTING_MINIMUM_CONFIDENCE_LEVEL", "95.0"),
			MaxTestDurationDays:       parseInt("AB_TESTING_MAX_TEST_DURATION_DAYS", "30"),
			AutoPromoteWinner:         parseBool("AB_TESTING_AUTO_PROMOTE_WINNER", "false"),
			StatisticalSignificanceThreshold: parseFloat("AB_TESTING_STATISTICAL_SIGNIFICANCE_THRESHOLD", "95.0"),
		},
		RateLimit: RateLimitConfig{
			GlobalEnabled:       parseBool("RATE_LIMIT_GLOBAL_ENABLED", "true"),
			GlobalRatePerSecond: parseInt("RATE_LIMIT_GLOBAL_RATE_PER_SECOND", "100"),
			GlobalBurstSize:     parseInt("RATE_LIMIT_GLOBAL_BURST_SIZE", "200"),
			
			PerTenantEnabled:       parseBool("RATE_LIMIT_PER_TENANT_ENABLED", "true"),
			PerTenantRatePerSecond: parseInt("RATE_LIMIT_PER_TENANT_RATE_PER_SECOND", "10"),
			PerTenantBurstSize:     parseInt("RATE_LIMIT_PER_TENANT_BURST_SIZE", "20"),
			
			PerUserEnabled:       parseBool("RATE_LIMIT_PER_USER_ENABLED", "true"),
			PerUserRatePerSecond: parseInt("RATE_LIMIT_PER_USER_RATE_PER_SECOND", "5"),
			PerUserBurstSize:     parseInt("RATE_LIMIT_PER_USER_BURST_SIZE", "10"),
		},
		Localization: LocalizationConfig{
			DefaultLocale:         getEnv("LOCALIZATION_DEFAULT_LOCALE", "en-US"),
			SupportedLocales:      parseStringSlice("LOCALIZATION_SUPPORTED_LOCALES", "en-US,es-ES,fr-FR,de-DE,ja-JP"),
			FallbackLocale:        getEnv("LOCALIZATION_FALLBACK_LOCALE", "en-US"),
			TranslationServiceURL: getEnv("LOCALIZATION_TRANSLATION_SERVICE_URL", ""),
			CacheTranslations:     parseBool("LOCALIZATION_CACHE_TRANSLATIONS", "true"),
			AutoDetectLocale:      parseBool("LOCALIZATION_AUTO_DETECT_LOCALE", "true"),
		},
		Security: SecurityConfig{
			EncryptPII:            parseBool("SECURITY_ENCRYPT_PII", "true"),
			PIIEncryptionKey:      getEnv("SECURITY_PII_ENCRYPTION_KEY", ""),
			AuditLogEnabled:       parseBool("SECURITY_AUDIT_LOG_ENABLED", "true"),
			DataResidencyRegions:  parseStringSlice("SECURITY_DATA_RESIDENCY_REGIONS", "US,EU"),
			IPWhitelistEnabled:    parseBool("SECURITY_IP_WHITELIST_ENABLED", "false"),
			IPWhitelist:           parseStringSlice("SECURITY_IP_WHITELIST", ""),
			RequireHTTPS:          parseBool("SECURITY_REQUIRE_HTTPS", "true"),
			CSRFProtectionEnabled: parseBool("SECURITY_CSRF_PROTECTION_ENABLED", "true"),
			CSRFSecretKey:         getEnv("SECURITY_CSRF_SECRET_KEY", ""),
			JWTSecretKey:          getEnv("SECURITY_JWT_SECRET_KEY", ""),
			JWTExpirationTime:     parseDuration("SECURITY_JWT_EXPIRATION_TIME", "1h"),
		},
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// Validate validates the configuration
func (c *CommunicationServiceConfig) Validate() error {
	// Validate database configuration
	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if c.Database.Database == "" {
		return fmt.Errorf("database name is required")
	}

	// Validate at least one email provider is configured
	hasProvider := false
	if c.EmailProviders.SendGrid.APIKey != "" {
		hasProvider = true
	}
	if c.EmailProviders.AWSSES.AccessKeyID != "" && c.EmailProviders.AWSSES.SecretAccessKey != "" {
		hasProvider = true
	}
	if c.EmailProviders.Mailgun.APIKey != "" && c.EmailProviders.Mailgun.Domain != "" {
		hasProvider = true
	}
	
	if !hasProvider {
		return fmt.Errorf("at least one email provider must be configured")
	}

	// Validate security settings
	if c.Security.EncryptPII && c.Security.PIIEncryptionKey == "" {
		return fmt.Errorf("PII encryption key is required when PII encryption is enabled")
	}
	
	if c.Security.CSRFProtectionEnabled && c.Security.CSRFSecretKey == "" {
		return fmt.Errorf("CSRF secret key is required when CSRF protection is enabled")
	}
	
	if c.Security.JWTSecretKey == "" {
		return fmt.Errorf("JWT secret key is required")
	}

	return nil
}

// GetDatabaseConnectionString returns the database connection string
func (c *CommunicationServiceConfig) GetDatabaseConnectionString() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.Username,
		c.Database.Password,
		c.Database.Database,
		c.Database.SSLMode,
	)
}

// Helper functions for parsing environment variables
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseInt(key string, defaultValue string) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	defaultInt, _ := strconv.Atoi(defaultValue)
	return defaultInt
}

func parseFloat(key string, defaultValue string) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	defaultFloat, _ := strconv.ParseFloat(defaultValue, 64)
	return defaultFloat
}

func parseBool(key string, defaultValue string) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	defaultBool, _ := strconv.ParseBool(defaultValue)
	return defaultBool
}

func parseDuration(key string, defaultValue string) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	defaultDuration, _ := time.ParseDuration(defaultValue)
	return defaultDuration
}

func parseStringSlice(key string, defaultValue string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	if defaultValue != "" {
		return strings.Split(defaultValue, ",")
	}
	return []string{}
}