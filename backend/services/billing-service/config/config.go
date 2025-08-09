package config

import (
	"os"
	"strconv"
	"time"
)

// Config represents the billing service configuration
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Database   DatabaseConfig   `yaml:"database"`
	Stripe     StripeConfig     `yaml:"stripe"`
	Webhook    WebhookConfig    `yaml:"webhook"`
	Security   SecurityConfig   `yaml:"security"`
	Compliance ComplianceConfig `yaml:"compliance"`
	Tax        TaxConfig        `yaml:"tax"`
	Email      EmailConfig      `yaml:"email"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Cache      CacheConfig      `yaml:"cache"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Host         string        `yaml:"host" env:"SERVER_HOST" default:"0.0.0.0"`
	Port         int           `yaml:"port" env:"SERVER_PORT" default:"8080"`
	ReadTimeout  time.Duration `yaml:"read_timeout" env:"SERVER_READ_TIMEOUT" default:"30s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"SERVER_WRITE_TIMEOUT" default:"30s"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" env:"SERVER_IDLE_TIMEOUT" default:"120s"`
	
	// TLS Configuration
	TLSEnabled  bool   `yaml:"tls_enabled" env:"SERVER_TLS_ENABLED" default:"true"`
	TLSCertFile string `yaml:"tls_cert_file" env:"SERVER_TLS_CERT_FILE"`
	TLSKeyFile  string `yaml:"tls_key_file" env:"SERVER_TLS_KEY_FILE"`
	
	// Security headers
	EnableHSTS           bool `yaml:"enable_hsts" env:"SERVER_ENABLE_HSTS" default:"true"`
	EnableCSP            bool `yaml:"enable_csp" env:"SERVER_ENABLE_CSP" default:"true"`
	EnableFrameOptions   bool `yaml:"enable_frame_options" env:"SERVER_ENABLE_FRAME_OPTIONS" default:"true"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Host     string `yaml:"host" env:"DB_HOST" default:"localhost"`
	Port     int    `yaml:"port" env:"DB_PORT" default:"5432"`
	Name     string `yaml:"name" env:"DB_NAME" default:"isectech_billing"`
	User     string `yaml:"user" env:"DB_USER" default:"postgres"`
	Password string `yaml:"password" env:"DB_PASSWORD"`
	
	// Connection pool settings
	MaxOpenConns    int           `yaml:"max_open_conns" env:"DB_MAX_OPEN_CONNS" default:"25"`
	MaxIdleConns    int           `yaml:"max_idle_conns" env:"DB_MAX_IDLE_CONNS" default:"5"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" env:"DB_CONN_MAX_LIFETIME" default:"1h"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" env:"DB_CONN_MAX_IDLE_TIME" default:"15m"`
	
	// SSL configuration
	SSLMode        string `yaml:"ssl_mode" env:"DB_SSL_MODE" default:"require"`
	SSLCert        string `yaml:"ssl_cert" env:"DB_SSL_CERT"`
	SSLKey         string `yaml:"ssl_key" env:"DB_SSL_KEY"`
	SSLRootCert    string `yaml:"ssl_root_cert" env:"DB_SSL_ROOT_CERT"`
	
	// Migration settings
	AutoMigrate    bool   `yaml:"auto_migrate" env:"DB_AUTO_MIGRATE" default:"false"`
	MigrationPath  string `yaml:"migration_path" env:"DB_MIGRATION_PATH" default:"./migrations"`
	
	// Audit and compliance
	EnableAuditLog bool `yaml:"enable_audit_log" env:"DB_ENABLE_AUDIT_LOG" default:"true"`
	EnableRLS      bool `yaml:"enable_rls" env:"DB_ENABLE_RLS" default:"true"`
}

// StripeConfig represents Stripe API configuration
type StripeConfig struct {
	SecretKey      string `yaml:"secret_key" env:"STRIPE_SECRET_KEY"`
	PublishableKey string `yaml:"publishable_key" env:"STRIPE_PUBLISHABLE_KEY"`
	WebhookSecret  string `yaml:"webhook_secret" env:"STRIPE_WEBHOOK_SECRET"`
	
	// Connect settings for multi-tenant
	ConnectAccountID string `yaml:"connect_account_id" env:"STRIPE_CONNECT_ACCOUNT_ID"`
	
	// Environment settings
	Environment string `yaml:"environment" env:"STRIPE_ENVIRONMENT" default:"sandbox"`
	APIVersion  string `yaml:"api_version" env:"STRIPE_API_VERSION" default:"2022-11-15"`
	
	// Security and compliance settings
	RequireStatementDescriptor bool   `yaml:"require_statement_descriptor" env:"STRIPE_REQUIRE_STATEMENT_DESCRIPTOR" default:"true"`
	StatementDescriptor        string `yaml:"statement_descriptor" env:"STRIPE_STATEMENT_DESCRIPTOR" default:"ISECTECH"`
	Require3DSecure           bool   `yaml:"require_3d_secure" env:"STRIPE_REQUIRE_3D_SECURE" default:"true"`
	EnableMetadata            bool   `yaml:"enable_metadata" env:"STRIPE_ENABLE_METADATA" default:"true"`
	
	// Compliance settings
	PCICompliant   bool `yaml:"pci_compliant" env:"STRIPE_PCI_COMPLIANT" default:"true"`
	SOXCompliant   bool `yaml:"sox_compliant" env:"STRIPE_SOX_COMPLIANT" default:"true"`
	HIPAACompliant bool `yaml:"hipaa_compliant" env:"STRIPE_HIPAA_COMPLIANT" default:"false"`
	
	// Rate limiting and retry settings
	MaxRequestsPerMinute     int           `yaml:"max_requests_per_minute" env:"STRIPE_MAX_REQUESTS_PER_MINUTE" default:"100"`
	MaxPaymentAttemptsPerDay int           `yaml:"max_payment_attempts_per_day" env:"STRIPE_MAX_PAYMENT_ATTEMPTS_PER_DAY" default:"10"`
	MaxRetries               int           `yaml:"max_retries" env:"STRIPE_MAX_RETRIES" default:"3"`
	RetryDelay               time.Duration `yaml:"retry_delay" env:"STRIPE_RETRY_DELAY" default:"1s"`
	BackoffMultiplier        float64       `yaml:"backoff_multiplier" env:"STRIPE_BACKOFF_MULTIPLIER" default:"2.0"`
	
	// Timeout settings
	ConnectTimeout time.Duration `yaml:"connect_timeout" env:"STRIPE_CONNECT_TIMEOUT" default:"30s"`
	RequestTimeout time.Duration `yaml:"request_timeout" env:"STRIPE_REQUEST_TIMEOUT" default:"60s"`
}

// WebhookConfig represents webhook configuration
type WebhookConfig struct {
	Enabled         bool          `yaml:"enabled" env:"WEBHOOK_ENABLED" default:"true"`
	Path            string        `yaml:"path" env:"WEBHOOK_PATH" default:"/webhooks/stripe"`
	WebhookSecret   string        `yaml:"webhook_secret" env:"WEBHOOK_SECRET"`
	Environment     string        `yaml:"environment" env:"WEBHOOK_ENVIRONMENT" default:"production"`
	
	// Security settings
	SecurityEnabled       bool          `yaml:"security_enabled" env:"WEBHOOK_SECURITY_ENABLED" default:"true"`
	EnableIPWhitelist     bool          `yaml:"enable_ip_whitelist" env:"WEBHOOK_ENABLE_IP_WHITELIST" default:"true"`
	IPWhitelist          []string      `yaml:"ip_whitelist" env:"WEBHOOK_IP_WHITELIST"`
	TimestampTolerance   time.Duration `yaml:"timestamp_tolerance" env:"WEBHOOK_TIMESTAMP_TOLERANCE" default:"300s"`
	
	// Rate limiting
	RateLimitEnabled     bool `yaml:"rate_limit_enabled" env:"WEBHOOK_RATE_LIMIT_ENABLED" default:"true"`
	MaxRequestsPerMinute int  `yaml:"max_requests_per_minute" env:"WEBHOOK_MAX_REQUESTS_PER_MINUTE" default:"1000"`
	MaxRequestsPerHour   int  `yaml:"max_requests_per_hour" env:"WEBHOOK_MAX_REQUESTS_PER_HOUR" default:"10000"`
	
	// Processing settings
	MaxConcurrentHandlers int           `yaml:"max_concurrent_handlers" env:"WEBHOOK_MAX_CONCURRENT_HANDLERS" default:"10"`
	ProcessingTimeout     time.Duration `yaml:"processing_timeout" env:"WEBHOOK_PROCESSING_TIMEOUT" default:"30s"`
	RetryAttempts         int           `yaml:"retry_attempts" env:"WEBHOOK_RETRY_ATTEMPTS" default:"3"`
	RetryDelay            time.Duration `yaml:"retry_delay" env:"WEBHOOK_RETRY_DELAY" default:"5s"`
	
	// Monitoring and logging
	EnableMetrics     bool `yaml:"enable_metrics" env:"WEBHOOK_ENABLE_METRICS" default:"true"`
	EnableAuditLog    bool `yaml:"enable_audit_log" env:"WEBHOOK_ENABLE_AUDIT_LOG" default:"true"`
	LogRequestBodies  bool `yaml:"log_request_bodies" env:"WEBHOOK_LOG_REQUEST_BODIES" default:"false"`
	LogResponseBodies bool `yaml:"log_response_bodies" env:"WEBHOOK_LOG_RESPONSE_BODIES" default:"false"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	// Encryption settings
	EncryptionKey         string `yaml:"encryption_key" env:"SECURITY_ENCRYPTION_KEY"`
	EncryptionAlgorithm   string `yaml:"encryption_algorithm" env:"SECURITY_ENCRYPTION_ALGORITHM" default:"AES-256-GCM"`
	
	// Token settings
	JWTSecret             string        `yaml:"jwt_secret" env:"SECURITY_JWT_SECRET"`
	JWTExpiration         time.Duration `yaml:"jwt_expiration" env:"SECURITY_JWT_EXPIRATION" default:"1h"`
	RefreshTokenExpiration time.Duration `yaml:"refresh_token_expiration" env:"SECURITY_REFRESH_TOKEN_EXPIRATION" default:"168h"`
	
	// API Key settings
	APIKeyPrefix          string        `yaml:"api_key_prefix" env:"SECURITY_API_KEY_PREFIX" default:"sk_"`
	APIKeyExpiration      time.Duration `yaml:"api_key_expiration" env:"SECURITY_API_KEY_EXPIRATION" default:"8760h"`
	
	// Security clearance requirements
	RequireSecurityClearance bool     `yaml:"require_security_clearance" env:"SECURITY_REQUIRE_SECURITY_CLEARANCE" default:"true"`
	DefaultSecurityClearance string   `yaml:"default_security_clearance" env:"SECURITY_DEFAULT_SECURITY_CLEARANCE" default:"unclassified"`
	ValidSecurityClearances  []string `yaml:"valid_security_clearances" env:"SECURITY_VALID_SECURITY_CLEARANCES"`
	
	// Rate limiting
	EnableRateLimit       bool `yaml:"enable_rate_limit" env:"SECURITY_ENABLE_RATE_LIMIT" default:"true"`
	DefaultRateLimit      int  `yaml:"default_rate_limit" env:"SECURITY_DEFAULT_RATE_LIMIT" default:"100"`
	BurstLimit           int  `yaml:"burst_limit" env:"SECURITY_BURST_LIMIT" default:"200"`
	
	// CORS settings
	EnableCORS           bool     `yaml:"enable_cors" env:"SECURITY_ENABLE_CORS" default:"true"`
	AllowedOrigins       []string `yaml:"allowed_origins" env:"SECURITY_ALLOWED_ORIGINS"`
	AllowedMethods       []string `yaml:"allowed_methods" env:"SECURITY_ALLOWED_METHODS"`
	AllowedHeaders       []string `yaml:"allowed_headers" env:"SECURITY_ALLOWED_HEADERS"`
	AllowCredentials     bool     `yaml:"allow_credentials" env:"SECURITY_ALLOW_CREDENTIALS" default:"true"`
	
	// Content Security Policy
	CSPDirectives        map[string]string `yaml:"csp_directives" env:"SECURITY_CSP_DIRECTIVES"`
	EnableCSPReporting   bool              `yaml:"enable_csp_reporting" env:"SECURITY_ENABLE_CSP_REPORTING" default:"true"`
	CSPReportURI         string            `yaml:"csp_report_uri" env:"SECURITY_CSP_REPORT_URI"`
}

// ComplianceConfig represents compliance configuration
type ComplianceConfig struct {
	// General compliance settings
	EnableCompliance     bool     `yaml:"enable_compliance" env:"COMPLIANCE_ENABLE_COMPLIANCE" default:"true"`
	ComplianceFrameworks []string `yaml:"compliance_frameworks" env:"COMPLIANCE_FRAMEWORKS"`
	
	// PCI DSS settings
	PCIDSSEnabled        bool `yaml:"pci_dss_enabled" env:"COMPLIANCE_PCI_DSS_ENABLED" default:"true"`
	PCIDSSLevel          int  `yaml:"pci_dss_level" env:"COMPLIANCE_PCI_DSS_LEVEL" default:"1"`
	
	// SOX 404 settings
	SOX404Enabled        bool `yaml:"sox_404_enabled" env:"COMPLIANCE_SOX_404_ENABLED" default:"true"`
	SOX404AuditRequired  bool `yaml:"sox_404_audit_required" env:"COMPLIANCE_SOX_404_AUDIT_REQUIRED" default:"true"`
	
	// GDPR settings
	GDPREnabled          bool `yaml:"gdpr_enabled" env:"COMPLIANCE_GDPR_ENABLED" default:"true"`
	DataRetentionPeriod  time.Duration `yaml:"data_retention_period" env:"COMPLIANCE_DATA_RETENTION_PERIOD" default:"2160h"`
	
	// HIPAA settings
	HIPAAEnabled         bool `yaml:"hipaa_enabled" env:"COMPLIANCE_HIPAA_ENABLED" default:"false"`
	
	// Audit settings
	EnableAuditTrail     bool          `yaml:"enable_audit_trail" env:"COMPLIANCE_ENABLE_AUDIT_TRAIL" default:"true"`
	AuditLogRetention    time.Duration `yaml:"audit_log_retention" env:"COMPLIANCE_AUDIT_LOG_RETENTION" default:"2190h"`
	EnableDataMasking    bool          `yaml:"enable_data_masking" env:"COMPLIANCE_ENABLE_DATA_MASKING" default:"true"`
}

// TaxConfig represents tax calculation configuration
type TaxConfig struct {
	Provider             string `yaml:"provider" env:"TAX_PROVIDER" default:"avalara"`
	
	// Avalara settings
	AvalaraAccountID     string `yaml:"avalara_account_id" env:"TAX_AVALARA_ACCOUNT_ID"`
	AvalaraLicenseKey    string `yaml:"avalara_license_key" env:"TAX_AVALARA_LICENSE_KEY"`
	AvalaraEnvironment   string `yaml:"avalara_environment" env:"TAX_AVALARA_ENVIRONMENT" default:"sandbox"`
	AvalaraCompanyCode   string `yaml:"avalara_company_code" env:"TAX_AVALARA_COMPANY_CODE"`
	
	// TaxJar settings
	TaxJarAPIToken       string `yaml:"taxjar_api_token" env:"TAX_TAXJAR_API_TOKEN"`
	TaxJarEnvironment    string `yaml:"taxjar_environment" env:"TAX_TAXJAR_ENVIRONMENT" default:"sandbox"`
	
	// General tax settings
	EnableTaxCalculation bool     `yaml:"enable_tax_calculation" env:"TAX_ENABLE_TAX_CALCULATION" default:"true"`
	DefaultTaxRate       float64  `yaml:"default_tax_rate" env:"TAX_DEFAULT_TAX_RATE" default:"0.0"`
	TaxExemptCountries   []string `yaml:"tax_exempt_countries" env:"TAX_EXEMPT_COUNTRIES"`
	
	// Cache settings
	EnableTaxCache       bool          `yaml:"enable_tax_cache" env:"TAX_ENABLE_TAX_CACHE" default:"true"`
	TaxCacheTTL          time.Duration `yaml:"tax_cache_ttl" env:"TAX_CACHE_TTL" default:"24h"`
}

// EmailConfig represents email service configuration
type EmailConfig struct {
	Provider             string `yaml:"provider" env:"EMAIL_PROVIDER" default:"sendgrid"`
	
	// SendGrid settings
	SendGridAPIKey       string `yaml:"sendgrid_api_key" env:"EMAIL_SENDGRID_API_KEY"`
	SendGridFromEmail    string `yaml:"sendgrid_from_email" env:"EMAIL_SENDGRID_FROM_EMAIL"`
	SendGridFromName     string `yaml:"sendgrid_from_name" env:"EMAIL_SENDGRID_FROM_NAME" default:"iSECTECH Billing"`
	
	// AWS SES settings
	AWSRegion            string `yaml:"aws_region" env:"EMAIL_AWS_REGION"`
	AWSAccessKeyID       string `yaml:"aws_access_key_id" env:"EMAIL_AWS_ACCESS_KEY_ID"`
	AWSSecretAccessKey   string `yaml:"aws_secret_access_key" env:"EMAIL_AWS_SECRET_ACCESS_KEY"`
	
	// Email templates
	TemplateBasePath     string `yaml:"template_base_path" env:"EMAIL_TEMPLATE_BASE_PATH" default:"./templates/email"`
	EnableTemplateCache  bool   `yaml:"enable_template_cache" env:"EMAIL_ENABLE_TEMPLATE_CACHE" default:"true"`
	
	// Email settings
	EnableEmailSending   bool          `yaml:"enable_email_sending" env:"EMAIL_ENABLE_EMAIL_SENDING" default:"true"`
	MaxRetries           int           `yaml:"max_retries" env:"EMAIL_MAX_RETRIES" default:"3"`
	RetryDelay           time.Duration `yaml:"retry_delay" env:"EMAIL_RETRY_DELAY" default:"30s"`
	
	// Invoice email settings
	InvoiceSubjectTemplate string `yaml:"invoice_subject_template" env:"EMAIL_INVOICE_SUBJECT_TEMPLATE" default:"Invoice {{.InvoiceNumber}} from iSECTECH"`
	PaymentSuccessSubject  string `yaml:"payment_success_subject" env:"EMAIL_PAYMENT_SUCCESS_SUBJECT" default:"Payment confirmation from iSECTECH"`
	PaymentFailedSubject   string `yaml:"payment_failed_subject" env:"EMAIL_PAYMENT_FAILED_SUBJECT" default:"Payment failed - Action required"`
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	Enabled              bool   `yaml:"enabled" env:"MONITORING_ENABLED" default:"true"`
	
	// Prometheus settings
	PrometheusEnabled    bool   `yaml:"prometheus_enabled" env:"MONITORING_PROMETHEUS_ENABLED" default:"true"`
	PrometheusPath       string `yaml:"prometheus_path" env:"MONITORING_PROMETHEUS_PATH" default:"/metrics"`
	PrometheusPort       int    `yaml:"prometheus_port" env:"MONITORING_PROMETHEUS_PORT" default:"9090"`
	
	// Jaeger tracing settings
	JaegerEnabled        bool   `yaml:"jaeger_enabled" env:"MONITORING_JAEGER_ENABLED" default:"true"`
	JaegerEndpoint       string `yaml:"jaeger_endpoint" env:"MONITORING_JAEGER_ENDPOINT"`
	JaegerServiceName    string `yaml:"jaeger_service_name" env:"MONITORING_JAEGER_SERVICE_NAME" default:"billing-service"`
	
	// Log settings
	LogLevel             string `yaml:"log_level" env:"MONITORING_LOG_LEVEL" default:"info"`
	LogFormat            string `yaml:"log_format" env:"MONITORING_LOG_FORMAT" default:"json"`
	LogOutput            string `yaml:"log_output" env:"MONITORING_LOG_OUTPUT" default:"stdout"`
	
	// Health check settings
	HealthCheckPath      string        `yaml:"health_check_path" env:"MONITORING_HEALTH_CHECK_PATH" default:"/health"`
	HealthCheckInterval  time.Duration `yaml:"health_check_interval" env:"MONITORING_HEALTH_CHECK_INTERVAL" default:"30s"`
	
	// Performance monitoring
	EnableProfiling      bool `yaml:"enable_profiling" env:"MONITORING_ENABLE_PROFILING" default:"false"`
	ProfilingPath        string `yaml:"profiling_path" env:"MONITORING_PROFILING_PATH" default:"/debug/pprof"`
}

// CacheConfig represents cache configuration
type CacheConfig struct {
	Provider             string        `yaml:"provider" env:"CACHE_PROVIDER" default:"redis"`
	
	// Redis settings
	RedisAddress         string        `yaml:"redis_address" env:"CACHE_REDIS_ADDRESS" default:"localhost:6379"`
	RedisPassword        string        `yaml:"redis_password" env:"CACHE_REDIS_PASSWORD"`
	RedisDB              int           `yaml:"redis_db" env:"CACHE_REDIS_DB" default:"0"`
	RedisMaxRetries      int           `yaml:"redis_max_retries" env:"CACHE_REDIS_MAX_RETRIES" default:"3"`
	RedisPoolSize        int           `yaml:"redis_pool_size" env:"CACHE_REDIS_POOL_SIZE" default:"10"`
	RedisDialTimeout     time.Duration `yaml:"redis_dial_timeout" env:"CACHE_REDIS_DIAL_TIMEOUT" default:"5s"`
	RedisReadTimeout     time.Duration `yaml:"redis_read_timeout" env:"CACHE_REDIS_READ_TIMEOUT" default:"3s"`
	RedisWriteTimeout    time.Duration `yaml:"redis_write_timeout" env:"CACHE_REDIS_WRITE_TIMEOUT" default:"3s"`
	
	// Cache settings
	DefaultTTL           time.Duration `yaml:"default_ttl" env:"CACHE_DEFAULT_TTL" default:"1h"`
	PaymentMethodTTL     time.Duration `yaml:"payment_method_ttl" env:"CACHE_PAYMENT_METHOD_TTL" default:"30m"`
	CustomerTTL          time.Duration `yaml:"customer_ttl" env:"CACHE_CUSTOMER_TTL" default:"1h"`
	SubscriptionTTL      time.Duration `yaml:"subscription_ttl" env:"CACHE_SUBSCRIPTION_TTL" default:"15m"`
	InvoiceTTL           time.Duration `yaml:"invoice_ttl" env:"CACHE_INVOICE_TTL" default:"1h"`
	
	// Cache key prefixes
	KeyPrefix            string `yaml:"key_prefix" env:"CACHE_KEY_PREFIX" default:"isectech:billing:"`
}

// LoadConfig loads configuration from environment variables and files
func LoadConfig() (*Config, error) {
	config := &Config{}
	
	// Load default values
	config.setDefaults()
	
	// Load from environment variables
	config.loadFromEnv()
	
	return config, nil
}

// setDefaults sets default configuration values
func (c *Config) setDefaults() {
	// Set default valid security clearances
	c.Security.ValidSecurityClearances = []string{
		"unclassified",
		"cui",
		"confidential",
		"secret",
		"top_secret",
	}
	
	// Set default compliance frameworks
	c.Compliance.ComplianceFrameworks = []string{
		"pci_dss",
		"sox_404",
		"gdpr",
	}
	
	// Set default allowed origins for CORS
	c.Security.AllowedOrigins = []string{
		"https://app.isectech.org",
		"https://admin.isectech.org",
	}
	
	// Set default allowed methods
	c.Security.AllowedMethods = []string{
		"GET",
		"POST",
		"PUT",
		"PATCH",
		"DELETE",
		"OPTIONS",
	}
	
	// Set default allowed headers
	c.Security.AllowedHeaders = []string{
		"Content-Type",
		"Authorization",
		"X-Requested-With",
		"X-API-Key",
		"X-Tenant-ID",
		"X-Security-Clearance",
	}
	
	// Set default CSP directives
	c.Security.CSPDirectives = map[string]string{
		"default-src": "'self'",
		"script-src":  "'self' 'unsafe-inline' https://js.stripe.com",
		"style-src":   "'self' 'unsafe-inline'",
		"img-src":     "'self' data: https:",
		"connect-src": "'self' https://api.stripe.com",
		"frame-src":   "https://js.stripe.com https://hooks.stripe.com",
	}
	
	// Set default Stripe IP whitelist (Stripe webhook IPs)
	c.Webhook.IPWhitelist = []string{
		"3.18.12.63",
		"3.130.192.231",
		"13.235.14.237",
		"13.235.122.149",
		"18.211.135.69",
		"35.154.171.200",
		"52.15.183.38",
		"54.88.130.119",
		"54.88.130.237",
		"54.187.174.169",
		"54.187.205.235",
		"54.187.216.72",
	}
}

// loadFromEnv loads configuration from environment variables
func (c *Config) loadFromEnv() {
	// Server configuration
	if host := os.Getenv("SERVER_HOST"); host != "" {
		c.Server.Host = host
	}
	if port := os.Getenv("SERVER_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			c.Server.Port = p
		}
	}
	
	// Database configuration
	if host := os.Getenv("DB_HOST"); host != "" {
		c.Database.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			c.Database.Port = p
		}
	}
	if name := os.Getenv("DB_NAME"); name != "" {
		c.Database.Name = name
	}
	if user := os.Getenv("DB_USER"); user != "" {
		c.Database.User = user
	}
	if password := os.Getenv("DB_PASSWORD"); password != "" {
		c.Database.Password = password
	}
	
	// Stripe configuration
	if secretKey := os.Getenv("STRIPE_SECRET_KEY"); secretKey != "" {
		c.Stripe.SecretKey = secretKey
	}
	if publishableKey := os.Getenv("STRIPE_PUBLISHABLE_KEY"); publishableKey != "" {
		c.Stripe.PublishableKey = publishableKey
	}
	if webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET"); webhookSecret != "" {
		c.Stripe.WebhookSecret = webhookSecret
	}
	
	// Security configuration
	if encryptionKey := os.Getenv("SECURITY_ENCRYPTION_KEY"); encryptionKey != "" {
		c.Security.EncryptionKey = encryptionKey
	}
	if jwtSecret := os.Getenv("SECURITY_JWT_SECRET"); jwtSecret != "" {
		c.Security.JWTSecret = jwtSecret
	}
}