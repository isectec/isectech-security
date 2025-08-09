// iSECTECH Asset Inventory Service - Configuration
// Production-grade configuration management
// Copyright (c) 2024 iSECTECH. All rights reserved.

package config

import (
	"time"

	"github.com/isectech/backend/services/asset-inventory/domain/repository"
)

// Configuration holds all service configuration
type Configuration struct {
	// Service information
	Service ServiceConfig `mapstructure:"service" json:"service"`

	// Server configuration
	Server ServerConfig `mapstructure:"server" json:"server"`

	// Database configuration
	Database DatabaseConfig `mapstructure:"database" json:"database"`

	// Repository configuration
	Repository repository.AssetRepositoryConfiguration `mapstructure:"repository" json:"repository"`

	// Discovery configuration
	Discovery DiscoveryConfig `mapstructure:"discovery" json:"discovery"`

	// Classification configuration
	Classification ClassificationConfig `mapstructure:"classification" json:"classification"`

	// Security configuration
	Security SecurityConfig `mapstructure:"security" json:"security"`

	// Metrics and monitoring
	Metrics MetricsConfig `mapstructure:"metrics" json:"metrics"`

	// Logging configuration
	LogLevel string `mapstructure:"log_level" json:"log_level"`

	// Maintenance configuration
	Maintenance MaintenanceConfig `mapstructure:"maintenance" json:"maintenance"`

	// Integration configuration
	Integrations IntegrationsConfig `mapstructure:"integrations" json:"integrations"`
}

// ServiceConfig holds service metadata
type ServiceConfig struct {
	Name        string `mapstructure:"name" json:"name"`
	Version     string `mapstructure:"version" json:"version"`
	Environment string `mapstructure:"environment" json:"environment"`
	Region      string `mapstructure:"region" json:"region"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port         int           `mapstructure:"port" json:"port"`
	Host         string        `mapstructure:"host" json:"host"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" json:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" json:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" json:"idle_timeout"`
	TLS          TLSConfig     `mapstructure:"tls" json:"tls"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled" json:"enabled"`
	CertFile string `mapstructure:"cert_file" json:"cert_file"`
	KeyFile  string `mapstructure:"key_file" json:"key_file"`
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host     string `mapstructure:"host" json:"host"`
	Port     int    `mapstructure:"port" json:"port"`
	User     string `mapstructure:"user" json:"user"`
	Password string `mapstructure:"password" json:"password"`
	Name     string `mapstructure:"name" json:"name"`
	SSLMode  string `mapstructure:"ssl_mode" json:"ssl_mode"`
}

// DiscoveryConfig holds asset discovery configuration
type DiscoveryConfig struct {
	// Scheduler settings
	SchedulerEnabled  bool          `mapstructure:"scheduler_enabled" json:"scheduler_enabled"`
	HeartbeatInterval time.Duration `mapstructure:"heartbeat_interval" json:"heartbeat_interval"`
	OfflineThreshold  time.Duration `mapstructure:"offline_threshold" json:"offline_threshold"`

	// Network discovery
	NetworkRanges   []string      `mapstructure:"network_ranges" json:"network_ranges"`
	ExcludedRanges  []string      `mapstructure:"excluded_ranges" json:"excluded_ranges"`
	PortScanEnabled bool          `mapstructure:"port_scan_enabled" json:"port_scan_enabled"`
	PortScanTimeout time.Duration `mapstructure:"port_scan_timeout" json:"port_scan_timeout"`

	// Performance settings
	MaxConcurrentScans int           `mapstructure:"max_concurrent_scans" json:"max_concurrent_scans"`
	ScanTimeout        time.Duration `mapstructure:"scan_timeout" json:"scan_timeout"`
	RateLimitRPS       int           `mapstructure:"rate_limit_rps" json:"rate_limit_rps"`

	// Cloud discovery
	CloudProviders map[string]CloudProviderConfig `mapstructure:"cloud_providers" json:"cloud_providers"`

	// Agent discovery
	AgentSettings AgentDiscoverySettings `mapstructure:"agent_settings" json:"agent_settings"`
}

// CloudProviderConfig holds cloud provider discovery settings
type CloudProviderConfig struct {
	Enabled       bool              `mapstructure:"enabled" json:"enabled"`
	Regions       []string          `mapstructure:"regions" json:"regions"`
	ResourceTypes []string          `mapstructure:"resource_types" json:"resource_types"`
	Tags          map[string]string `mapstructure:"tags" json:"tags"`
	Credentials   CredentialsConfig `mapstructure:"credentials" json:"credentials"`
}

// CredentialsConfig holds credentials configuration
type CredentialsConfig struct {
	Type            string            `mapstructure:"type" json:"type"` // "env", "file", "iam"
	AccessKeyID     string            `mapstructure:"access_key_id" json:"access_key_id"`
	SecretKey       string            `mapstructure:"secret_key" json:"secret_key"`
	Region          string            `mapstructure:"region" json:"region"`
	Profile         string            `mapstructure:"profile" json:"profile"`
	CredentialsFile string            `mapstructure:"credentials_file" json:"credentials_file"`
	Environment     map[string]string `mapstructure:"environment" json:"environment"`
}

// AgentDiscoverySettings holds agent-based discovery settings
type AgentDiscoverySettings struct {
	RequiredCapabilities []string      `mapstructure:"required_capabilities" json:"required_capabilities"`
	CollectionFrequency  time.Duration `mapstructure:"collection_frequency" json:"collection_frequency"`
	DataRetention        time.Duration `mapstructure:"data_retention" json:"data_retention"`
}

// ClassificationConfig holds asset classification configuration
type ClassificationConfig struct {
	// Auto-classification settings
	AutoClassificationEnabled bool          `mapstructure:"auto_classification_enabled" json:"auto_classification_enabled"`
	ClassificationInterval    time.Duration `mapstructure:"classification_interval" json:"classification_interval"`

	// Criticality matrix configuration
	CriticalityMatrix CriticalityMatrixConfig `mapstructure:"criticality_matrix" json:"criticality_matrix"`

	// Business function mapping
	BusinessFunctions []BusinessFunctionConfig `mapstructure:"business_functions" json:"business_functions"`

	// Compliance framework mapping
	ComplianceFrameworks []ComplianceFrameworkConfig `mapstructure:"compliance_frameworks" json:"compliance_frameworks"`

	// Custom classification rules
	CustomRules []ClassificationRuleConfig `mapstructure:"custom_rules" json:"custom_rules"`
}

// CriticalityMatrixConfig holds criticality assessment configuration
type CriticalityMatrixConfig struct {
	DataClassificationWeights map[string]int `mapstructure:"data_classification_weights" json:"data_classification_weights"`
	AssetTypeWeights          map[string]int `mapstructure:"asset_type_weights" json:"asset_type_weights"`
	BusinessFunctionWeights   map[string]int `mapstructure:"business_function_weights" json:"business_function_weights"`
	NetworkSegmentWeights     map[string]int `mapstructure:"network_segment_weights" json:"network_segment_weights"`
	ServiceWeights            map[string]int `mapstructure:"service_weights" json:"service_weights"`
	ThresholdCritical         int            `mapstructure:"threshold_critical" json:"threshold_critical"`
	ThresholdHigh             int            `mapstructure:"threshold_high" json:"threshold_high"`
	ThresholdMedium           int            `mapstructure:"threshold_medium" json:"threshold_medium"`
}

// BusinessFunctionConfig holds business function configuration
type BusinessFunctionConfig struct {
	Name        string   `mapstructure:"name" json:"name"`
	Description string   `mapstructure:"description" json:"description"`
	Criticality string   `mapstructure:"criticality" json:"criticality"`
	Owner       string   `mapstructure:"owner" json:"owner"`
	Keywords    []string `mapstructure:"keywords" json:"keywords"`
}

// ComplianceFrameworkConfig holds compliance framework configuration
type ComplianceFrameworkConfig struct {
	Name         string   `mapstructure:"name" json:"name"`
	Description  string   `mapstructure:"description" json:"description"`
	Requirements []string `mapstructure:"requirements" json:"requirements"`
	AssetTypes   []string `mapstructure:"asset_types" json:"asset_types"`
	Keywords     []string `mapstructure:"keywords" json:"keywords"`
}

// ClassificationRuleConfig holds custom classification rule configuration
type ClassificationRuleConfig struct {
	ID          string                          `mapstructure:"id" json:"id"`
	Name        string                          `mapstructure:"name" json:"name"`
	Description string                          `mapstructure:"description" json:"description"`
	Priority    int                             `mapstructure:"priority" json:"priority"`
	Enabled     bool                            `mapstructure:"enabled" json:"enabled"`
	Conditions  []ClassificationConditionConfig `mapstructure:"conditions" json:"conditions"`
	Actions     []ClassificationActionConfig    `mapstructure:"actions" json:"actions"`
}

// ClassificationConditionConfig holds classification condition configuration
type ClassificationConditionConfig struct {
	Field         string      `mapstructure:"field" json:"field"`
	Operator      string      `mapstructure:"operator" json:"operator"`
	Value         interface{} `mapstructure:"value" json:"value"`
	CaseSensitive bool        `mapstructure:"case_sensitive" json:"case_sensitive"`
}

// ClassificationActionConfig holds classification action configuration
type ClassificationActionConfig struct {
	Action string      `mapstructure:"action" json:"action"`
	Field  string      `mapstructure:"field" json:"field"`
	Value  interface{} `mapstructure:"value" json:"value"`
	Reason string      `mapstructure:"reason" json:"reason"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	// Authentication
	Authentication AuthenticationConfig `mapstructure:"authentication" json:"authentication"`

	// Authorization
	Authorization AuthorizationConfig `mapstructure:"authorization" json:"authorization"`

	// API security
	APIKey    APIKeyConfig    `mapstructure:"api_key" json:"api_key"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit" json:"rate_limit"`
	CORS      CORSConfig      `mapstructure:"cors" json:"cors"`

	// Data protection
	Encryption    EncryptionConfig    `mapstructure:"encryption" json:"encryption"`
	DataRetention DataRetentionConfig `mapstructure:"data_retention" json:"data_retention"`
}

// AuthenticationConfig holds authentication configuration
type AuthenticationConfig struct {
	Enabled  bool              `mapstructure:"enabled" json:"enabled"`
	Type     string            `mapstructure:"type" json:"type"` // "jwt", "oauth2", "api_key"
	Settings map[string]string `mapstructure:"settings" json:"settings"`
}

// AuthorizationConfig holds authorization configuration
type AuthorizationConfig struct {
	Enabled     bool              `mapstructure:"enabled" json:"enabled"`
	Type        string            `mapstructure:"type" json:"type"` // "rbac", "abac"
	DefaultRole string            `mapstructure:"default_role" json:"default_role"`
	Settings    map[string]string `mapstructure:"settings" json:"settings"`
}

// APIKeyConfig holds API key configuration
type APIKeyConfig struct {
	Enabled    bool   `mapstructure:"enabled" json:"enabled"`
	HeaderName string `mapstructure:"header_name" json:"header_name"`
	QueryParam string `mapstructure:"query_param" json:"query_param"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool          `mapstructure:"enabled" json:"enabled"`
	RequestsPerSecond int           `mapstructure:"requests_per_second" json:"requests_per_second"`
	BurstSize         int           `mapstructure:"burst_size" json:"burst_size"`
	WindowSize        time.Duration `mapstructure:"window_size" json:"window_size"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	Enabled        bool     `mapstructure:"enabled" json:"enabled"`
	AllowedOrigins []string `mapstructure:"allowed_origins" json:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods" json:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers" json:"allowed_headers"`
	MaxAge         int      `mapstructure:"max_age" json:"max_age"`
}

// EncryptionConfig holds encryption configuration
type EncryptionConfig struct {
	Enabled   bool   `mapstructure:"enabled" json:"enabled"`
	Algorithm string `mapstructure:"algorithm" json:"algorithm"`
	KeyFile   string `mapstructure:"key_file" json:"key_file"`
}

// DataRetentionConfig holds data retention configuration
type DataRetentionConfig struct {
	AssetHistory    time.Duration `mapstructure:"asset_history" json:"asset_history"`
	DiscoveryLogs   time.Duration `mapstructure:"discovery_logs" json:"discovery_logs"`
	AuditLogs       time.Duration `mapstructure:"audit_logs" json:"audit_logs"`
	BackupRetention time.Duration `mapstructure:"backup_retention" json:"backup_retention"`
}

// MetricsConfig holds metrics and monitoring configuration
type MetricsConfig struct {
	Enabled   bool   `mapstructure:"enabled" json:"enabled"`
	Port      int    `mapstructure:"port" json:"port"`
	Path      string `mapstructure:"path" json:"path"`
	Namespace string `mapstructure:"namespace" json:"namespace"`
	Subsystem string `mapstructure:"subsystem" json:"subsystem"`
}

// MaintenanceConfig holds maintenance task configuration
type MaintenanceConfig struct {
	Enabled           bool          `mapstructure:"enabled" json:"enabled"`
	Schedule          string        `mapstructure:"schedule" json:"schedule"` // Cron expression
	DatabaseCleanup   bool          `mapstructure:"database_cleanup" json:"database_cleanup"`
	IndexOptimization bool          `mapstructure:"index_optimization" json:"index_optimization"`
	BackupEnabled     bool          `mapstructure:"backup_enabled" json:"backup_enabled"`
	BackupRetention   time.Duration `mapstructure:"backup_retention" json:"backup_retention"`
}

// IntegrationsConfig holds external integration configuration
type IntegrationsConfig struct {
	// CMDB integrations
	CMDB CMDBIntegrationConfig `mapstructure:"cmdb" json:"cmdb"`

	// SIEM integrations
	SIEM SIEMIntegrationConfig `mapstructure:"siem" json:"siem"`

	// Vulnerability scanner integrations
	VulnerabilityScanning VulnScanningConfig `mapstructure:"vulnerability_scanning" json:"vulnerability_scanning"`

	// Notification integrations
	Notifications NotificationConfig `mapstructure:"notifications" json:"notifications"`

	// Ticketing system integrations
	Ticketing TicketingConfig `mapstructure:"ticketing" json:"ticketing"`
}

// CMDBIntegrationConfig holds CMDB integration configuration
type CMDBIntegrationConfig struct {
	Enabled      bool              `mapstructure:"enabled" json:"enabled"`
	Type         string            `mapstructure:"type" json:"type"` // "servicenow", "remedy", "jira"
	Endpoint     string            `mapstructure:"endpoint" json:"endpoint"`
	Credentials  CredentialsConfig `mapstructure:"credentials" json:"credentials"`
	SyncInterval time.Duration     `mapstructure:"sync_interval" json:"sync_interval"`
	FieldMapping map[string]string `mapstructure:"field_mapping" json:"field_mapping"`
}

// SIEMIntegrationConfig holds SIEM integration configuration
type SIEMIntegrationConfig struct {
	Enabled       bool              `mapstructure:"enabled" json:"enabled"`
	Type          string            `mapstructure:"type" json:"type"` // "splunk", "qradar", "sentinel"
	Endpoint      string            `mapstructure:"endpoint" json:"endpoint"`
	Credentials   CredentialsConfig `mapstructure:"credentials" json:"credentials"`
	EventTypes    []string          `mapstructure:"event_types" json:"event_types"`
	BatchSize     int               `mapstructure:"batch_size" json:"batch_size"`
	FlushInterval time.Duration     `mapstructure:"flush_interval" json:"flush_interval"`
}

// VulnScanningConfig holds vulnerability scanning integration configuration
type VulnScanningConfig struct {
	Enabled    bool                         `mapstructure:"enabled" json:"enabled"`
	Scanners   map[string]VulnScannerConfig `mapstructure:"scanners" json:"scanners"`
	Schedule   string                       `mapstructure:"schedule" json:"schedule"`
	RetryCount int                          `mapstructure:"retry_count" json:"retry_count"`
}

// VulnScannerConfig holds individual vulnerability scanner configuration
type VulnScannerConfig struct {
	Enabled     bool              `mapstructure:"enabled" json:"enabled"`
	Type        string            `mapstructure:"type" json:"type"` // "nessus", "openvas", "qualys"
	Endpoint    string            `mapstructure:"endpoint" json:"endpoint"`
	Credentials CredentialsConfig `mapstructure:"credentials" json:"credentials"`
	Settings    map[string]string `mapstructure:"settings" json:"settings"`
}

// NotificationConfig holds notification configuration
type NotificationConfig struct {
	Enabled  bool                           `mapstructure:"enabled" json:"enabled"`
	Channels map[string]NotificationChannel `mapstructure:"channels" json:"channels"`
	Rules    []NotificationRule             `mapstructure:"rules" json:"rules"`
}

// NotificationChannel holds notification channel configuration
type NotificationChannel struct {
	Type     string            `mapstructure:"type" json:"type"` // "email", "slack", "teams", "webhook"
	Enabled  bool              `mapstructure:"enabled" json:"enabled"`
	Settings map[string]string `mapstructure:"settings" json:"settings"`
}

// NotificationRule holds notification rule configuration
type NotificationRule struct {
	Name     string            `mapstructure:"name" json:"name"`
	Enabled  bool              `mapstructure:"enabled" json:"enabled"`
	Events   []string          `mapstructure:"events" json:"events"`
	Filters  map[string]string `mapstructure:"filters" json:"filters"`
	Channels []string          `mapstructure:"channels" json:"channels"`
	Template string            `mapstructure:"template" json:"template"`
}

// TicketingConfig holds ticketing system integration configuration
type TicketingConfig struct {
	Enabled      bool              `mapstructure:"enabled" json:"enabled"`
	Type         string            `mapstructure:"type" json:"type"` // "jira", "servicenow", "remedy"
	Endpoint     string            `mapstructure:"endpoint" json:"endpoint"`
	Credentials  CredentialsConfig `mapstructure:"credentials" json:"credentials"`
	ProjectKey   string            `mapstructure:"project_key" json:"project_key"`
	IssueType    string            `mapstructure:"issue_type" json:"issue_type"`
	FieldMapping map[string]string `mapstructure:"field_mapping" json:"field_mapping"`
	AutoCreate   bool              `mapstructure:"auto_create" json:"auto_create"`
	AutoUpdate   bool              `mapstructure:"auto_update" json:"auto_update"`
}
