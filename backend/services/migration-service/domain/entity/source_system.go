package entity

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SourceSystemVendor represents the vendor of the source system
type SourceSystemVendor string

const (
	// SIEM Vendors
	VendorSplunk      SourceSystemVendor = "splunk"
	VendorIBMQRadar   SourceSystemVendor = "ibm_qradar"
	VendorArcSight    SourceSystemVendor = "arcsight"
	VendorLogRhythm   SourceSystemVendor = "logrhythm"
	VendorElastic     SourceSystemVendor = "elastic"
	VendorSumoLogic   SourceSystemVendor = "sumo_logic"
	VendorAlienVault  SourceSystemVendor = "alienvault"
	
	// Endpoint Protection Vendors
	VendorCrowdStrike SourceSystemVendor = "crowdstrike"
	VendorSentinelOne SourceSystemVendor = "sentinelone"
	VendorCarbonBlack SourceSystemVendor = "carbon_black"
	VendorCylance     SourceSystemVendor = "cylance"
	VendorTrendMicro  SourceSystemVendor = "trend_micro"
	VendorSymantec    SourceSystemVendor = "symantec"
	VendorMcAfee      SourceSystemVendor = "mcafee"
	VendorKaspersky   SourceSystemVendor = "kaspersky"
	VendorSophos      SourceSystemVendor = "sophos"
	VendorBitdefender SourceSystemVendor = "bitdefender"
	
	// Vulnerability Management Vendors
	VendorTenable     SourceSystemVendor = "tenable"
	VendorQualys      SourceSystemVendor = "qualys"
	VendorRapid7      SourceSystemVendor = "rapid7"
	VendorGreenbone   SourceSystemVendor = "greenbone"
	VendorNessus      SourceSystemVendor = "nessus"
	VendorOpenVAS     SourceSystemVendor = "openvas"
	
	// Network Security Vendors
	VendorPaloAlto    SourceSystemVendor = "palo_alto"
	VendorFortinet    SourceSystemVendor = "fortinet"
	VendorCisco       SourceSystemVendor = "cisco"
	VendorCheckPoint  SourceSystemVendor = "checkpoint"
	VendorJuniper     SourceSystemVendor = "juniper"
	VendorSonicWall   SourceSystemVendor = "sonicwall"
	
	// Cloud Security Vendors
	VendorPrismaCloud SourceSystemVendor = "prisma_cloud"
	VendorLacework    SourceSystemVendor = "lacework"
	VendorCloudFlare  SourceSystemVendor = "cloudflare"
	VendorAWS         SourceSystemVendor = "aws"
	VendorAzure       SourceSystemVendor = "azure"
	VendorGCP         SourceSystemVendor = "gcp"
	
	// Identity and Access Management Vendors
	VendorOkta        SourceSystemVendor = "okta"
	VendorPingIdentity SourceSystemVendor = "ping_identity"
	VendorCyberArk    SourceSystemVendor = "cyberark"
	VendorSailPoint   SourceSystemVendor = "sailpoint"
	
	// Custom/Generic
	VendorCustom      SourceSystemVendor = "custom"
	VendorGeneric     SourceSystemVendor = "generic"
)

// AuthenticationType represents the authentication method for the source system
type AuthenticationType string

const (
	AuthTypeAPIKey       AuthenticationType = "api_key"
	AuthTypeBasicAuth    AuthenticationType = "basic_auth"
	AuthTypeOAuth2       AuthenticationType = "oauth2"
	AuthTypeJWT          AuthenticationType = "jwt"
	AuthTypeCertificate  AuthenticationType = "certificate"
	AuthTypeKerberos     AuthenticationType = "kerberos"
	AuthTypeSAML         AuthenticationType = "saml"
	AuthTypeCustom       AuthenticationType = "custom"
)

// ConnectionStatus represents the connection status of the source system
type ConnectionStatus string

const (
	ConnectionStatusUnknown      ConnectionStatus = "unknown"
	ConnectionStatusConnected    ConnectionStatus = "connected"
	ConnectionStatusDisconnected ConnectionStatus = "disconnected"
	ConnectionStatusError        ConnectionStatus = "error"
	ConnectionStatusTesting      ConnectionStatus = "testing"
	ConnectionStatusMaintenance  ConnectionStatus = "maintenance"
)

// APICapability represents API capabilities of the source system
type APICapability struct {
	Name         string                 `json:"name"`
	Supported    bool                   `json:"supported"`
	Version      string                 `json:"version,omitempty"`
	Limitations  []string               `json:"limitations,omitempty"`
	RateLimit    *RateLimit             `json:"rate_limit,omitempty"`
	DataTypes    []DataType             `json:"data_types,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

// RateLimit represents API rate limiting information
type RateLimit struct {
	RequestsPerSecond int32  `json:"requests_per_second"`
	RequestsPerMinute int32  `json:"requests_per_minute"`
	RequestsPerHour   int32  `json:"requests_per_hour"`
	RequestsPerDay    int32  `json:"requests_per_day"`
	BurstLimit        int32  `json:"burst_limit"`
	ResetPeriod       string `json:"reset_period"`
}

// AuthenticationConfig contains authentication configuration
type AuthenticationConfig struct {
	Type         AuthenticationType     `json:"type"`
	Credentials  map[string]interface{} `json:"credentials"`
	TokenURL     string                 `json:"token_url,omitempty"`
	RefreshURL   string                 `json:"refresh_url,omitempty"`
	Scopes       []string               `json:"scopes,omitempty"`
	ExpiresIn    *int32                 `json:"expires_in,omitempty"`
	
	// Security settings
	EncryptCredentials bool   `json:"encrypt_credentials"`
	UseMTLS           bool   `json:"use_mtls"`
	CertificatePath   string `json:"certificate_path,omitempty"`
	KeyPath           string `json:"key_path,omitempty"`
	
	// Token refresh settings
	AutoRefresh       bool   `json:"auto_refresh"`
	RefreshBuffer     int32  `json:"refresh_buffer"` // seconds before expiry to refresh
}

// ConnectionConfig contains connection configuration
type ConnectionConfig struct {
	BaseURL         string            `json:"base_url"`
	APIVersion      string            `json:"api_version,omitempty"`
	Port            int32             `json:"port,omitempty"`
	UseSSL          bool              `json:"use_ssl"`
	VerifySSL       bool              `json:"verify_ssl"`
	Timeout         int32             `json:"timeout"`
	MaxRetries      int32             `json:"max_retries"`
	RetryDelay      int32             `json:"retry_delay"`
	
	// Headers and parameters
	DefaultHeaders  map[string]string `json:"default_headers,omitempty"`
	QueryParameters map[string]string `json:"query_parameters,omitempty"`
	
	// Proxy settings
	ProxyURL        string            `json:"proxy_url,omitempty"`
	ProxyAuth       bool              `json:"proxy_auth"`
	
	// Connection pooling
	MaxConnections  int32             `json:"max_connections"`
	KeepAlive       bool              `json:"keep_alive"`
	
	// Regional settings
	Region          string            `json:"region,omitempty"`
	DataCenter      string            `json:"data_center,omitempty"`
}

// DataExtractionConfig contains data extraction configuration
type DataExtractionConfig struct {
	SupportedDataTypes   []DataType             `json:"supported_data_types"`
	DefaultBatchSize     int32                  `json:"default_batch_size"`
	MaxBatchSize         int32                  `json:"max_batch_size"`
	SupportsIncremental  bool                   `json:"supports_incremental"`
	SupportsDateFiltering bool                  `json:"supports_date_filtering"`
	
	// Pagination settings
	PaginationType       string                 `json:"pagination_type"` // offset, cursor, page
	MaxPageSize          int32                  `json:"max_page_size"`
	DefaultPageSize      int32                  `json:"default_page_size"`
	
	// Data format settings
	OutputFormats        []string               `json:"output_formats"`
	DefaultFormat        string                 `json:"default_format"`
	CompressionSupported bool                   `json:"compression_supported"`
	
	// Field mappings and transformations
	FieldMappings        map[string]string      `json:"field_mappings,omitempty"`
	RequiredFields       []string               `json:"required_fields,omitempty"`
	OptionalFields       []string               `json:"optional_fields,omitempty"`
	
	// Performance settings
	ParallelExtraction   bool                   `json:"parallel_extraction"`
	MaxParallelRequests  int32                  `json:"max_parallel_requests"`
	
	// Quality and validation
	ValidateData         bool                   `json:"validate_data"`
	SkipInvalidRecords   bool                   `json:"skip_invalid_records"`
	DeduplicateRecords   bool                   `json:"deduplicate_records"`
}

// SystemCapabilities represents the capabilities of the source system
type SystemCapabilities struct {
	APICapabilities      map[string]APICapability `json:"api_capabilities"`
	SupportedOperations  []string                  `json:"supported_operations"`
	SupportsSearch       bool                      `json:"supports_search"`
	SupportsAggregation  bool                      `json:"supports_aggregation"`
	SupportsExport       bool                      `json:"supports_export"`
	SupportsStreaming    bool                      `json:"supports_streaming"`
	
	// Metadata capabilities
	SupportsMetadata     bool                      `json:"supports_metadata"`
	MetadataFields       []string                  `json:"metadata_fields,omitempty"`
	
	// Advanced features
	SupportsWebhooks     bool                      `json:"supports_webhooks"`
	SupportsGraphQL      bool                      `json:"supports_graphql"`
	SupportsCustomFields bool                      `json:"supports_custom_fields"`
	
	// Performance characteristics
	TypicalResponseTime  int32                     `json:"typical_response_time"` // milliseconds
	MaxRequestSize       int64                     `json:"max_request_size"`      // bytes
	MaxResponseSize      int64                     `json:"max_response_size"`     // bytes
}

// HealthCheckConfig contains health check configuration
type HealthCheckConfig struct {
	Enabled         bool   `json:"enabled"`
	Endpoint        string `json:"endpoint,omitempty"`
	Method          string `json:"method"`
	IntervalSeconds int32  `json:"interval_seconds"`
	TimeoutSeconds  int32  `json:"timeout_seconds"`
	RetryAttempts   int32  `json:"retry_attempts"`
	
	// Health check criteria
	ExpectedStatusCode  int32  `json:"expected_status_code"`
	ExpectedResponse    string `json:"expected_response,omitempty"`
	
	// Alerting
	AlertOnFailure      bool   `json:"alert_on_failure"`
	AlertThreshold      int32  `json:"alert_threshold"`
}

// SourceSystem represents a source system for data migration
type SourceSystem struct {
	// Core fields
	ID                  uuid.UUID            `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID            uuid.UUID            `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Name                string               `gorm:"not null" json:"name"`
	Description         *string              `json:"description,omitempty"`
	
	// System identification
	Vendor              SourceSystemVendor   `gorm:"not null" json:"vendor"`
	ProductName         string               `gorm:"not null" json:"product_name"`
	ProductVersion      string               `json:"product_version,omitempty"`
	SystemType          SourceSystemType     `gorm:"not null" json:"system_type"`
	
	// Connection and authentication
	ConnectionConfig    ConnectionConfig     `gorm:"type:jsonb" json:"connection_config"`
	AuthConfig          AuthenticationConfig `gorm:"type:jsonb" json:"auth_config"`
	
	// System capabilities
	Capabilities        SystemCapabilities   `gorm:"type:jsonb" json:"capabilities"`
	DataExtractionConfig DataExtractionConfig `gorm:"type:jsonb" json:"data_extraction_config"`
	
	// Status and monitoring
	Status              ConnectionStatus     `gorm:"not null;default:'unknown'" json:"status"`
	LastHealthCheck     *time.Time           `json:"last_health_check,omitempty"`
	HealthCheckConfig   HealthCheckConfig    `gorm:"type:jsonb" json:"health_check_config"`
	
	// Statistics
	TotalMigrations     int32                `gorm:"default:0" json:"total_migrations"`
	SuccessfulMigrations int32               `gorm:"default:0" json:"successful_migrations"`
	FailedMigrations    int32                `gorm:"default:0" json:"failed_migrations"`
	LastMigrationAt     *time.Time           `json:"last_migration_at,omitempty"`
	
	// Performance metrics
	AverageResponseTime int32                `gorm:"default:0" json:"average_response_time"` // milliseconds
	UpTimePercentage    float64              `gorm:"default:0" json:"uptime_percentage"`
	ErrorRate           float64              `gorm:"default:0" json:"error_rate"`
	
	// Configuration and management
	IsActive            bool                 `gorm:"default:true" json:"is_active"`
	IsDefault           bool                 `gorm:"default:false" json:"is_default"`
	ConfigurationHash   string               `json:"configuration_hash,omitempty"`
	
	// Security and compliance
	SecurityClearance   string               `gorm:"not null;default:'unclassified'" json:"security_clearance"`
	ComplianceFrameworks []string            `gorm:"type:text[]" json:"compliance_frameworks,omitempty"`
	DataClassification  string               `gorm:"default:'internal'" json:"data_classification"`
	
	// Metadata and tags
	Tags                []string             `gorm:"type:text[]" json:"tags,omitempty"`
	Metadata            map[string]interface{} `gorm:"type:jsonb" json:"metadata,omitempty"`
	
	// Audit fields
	CreatedBy           uuid.UUID            `gorm:"type:uuid;not null" json:"created_by"`
	UpdatedBy           *uuid.UUID           `gorm:"type:uuid" json:"updated_by,omitempty"`
	CreatedAt           time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt           time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt           *time.Time           `gorm:"index" json:"deleted_at,omitempty"`
	
	// Relationships
	MigrationJobs       []MigrationJob       `gorm:"foreignKey:SourceSystemID" json:"migration_jobs,omitempty"`
}

// TableName returns the table name for GORM
func (SourceSystem) TableName() string {
	return "source_systems"
}

// IsConnected returns true if the source system is connected
func (s *SourceSystem) IsConnected() bool {
	return s.Status == ConnectionStatusConnected
}

// IsHealthy returns true if the source system is healthy
func (s *SourceSystem) IsHealthy() bool {
	return s.Status == ConnectionStatusConnected && 
		   s.LastHealthCheck != nil && 
		   time.Since(*s.LastHealthCheck) < time.Duration(s.HealthCheckConfig.IntervalSeconds*2)*time.Second
}

// CanPerformMigration returns true if the source system can perform migration
func (s *SourceSystem) CanPerformMigration() bool {
	return s.IsActive && s.IsConnected() && s.Capabilities.SupportsExport
}

// GetSuccessRate returns the success rate of migrations for this source system
func (s *SourceSystem) GetSuccessRate() float64 {
	if s.TotalMigrations == 0 {
		return 0.0
	}
	return float64(s.SuccessfulMigrations) / float64(s.TotalMigrations) * 100.0
}

// GetSupportedDataTypes returns the supported data types for migration
func (s *SourceSystem) GetSupportedDataTypes() []DataType {
	return s.DataExtractionConfig.SupportedDataTypes
}

// SupportsDataType returns true if the source system supports the given data type
func (s *SourceSystem) SupportsDataType(dataType DataType) bool {
	for _, dt := range s.DataExtractionConfig.SupportedDataTypes {
		if dt == dataType {
			return true
		}
	}
	return false
}

// GetOptimalBatchSize returns the optimal batch size for the source system
func (s *SourceSystem) GetOptimalBatchSize() int32 {
	if s.DataExtractionConfig.DefaultBatchSize > 0 {
		return s.DataExtractionConfig.DefaultBatchSize
	}
	return 1000 // Default fallback
}

// GetRateLimit returns the rate limit for the source system
func (s *SourceSystem) GetRateLimit() *RateLimit {
	// Check if there's a global rate limit in capabilities
	for _, capability := range s.Capabilities.APICapabilities {
		if capability.RateLimit != nil {
			return capability.RateLimit
		}
	}
	return nil
}

// UpdateStatus updates the connection status and related metrics
func (s *SourceSystem) UpdateStatus(status ConnectionStatus, responseTime int32) {
	s.Status = status
	s.LastHealthCheck = &time.Time{}
	*s.LastHealthCheck = time.Now()
	
	// Update average response time (rolling average)
	if s.AverageResponseTime == 0 {
		s.AverageResponseTime = responseTime
	} else {
		s.AverageResponseTime = (s.AverageResponseTime + responseTime) / 2
	}
}

// IncrementMigrationStats increments migration statistics
func (s *SourceSystem) IncrementMigrationStats(success bool) {
	s.TotalMigrations++
	if success {
		s.SuccessfulMigrations++
	} else {
		s.FailedMigrations++
	}
	
	now := time.Now()
	s.LastMigrationAt = &now
	
	// Update error rate
	s.ErrorRate = float64(s.FailedMigrations) / float64(s.TotalMigrations) * 100.0
}

// GenerateConfigurationHash generates a hash of the configuration
func (s *SourceSystem) GenerateConfigurationHash() string {
	configData := struct {
		ConnectionConfig     ConnectionConfig     `json:"connection_config"`
		AuthConfig          AuthenticationConfig `json:"auth_config"`
		DataExtractionConfig DataExtractionConfig `json:"data_extraction_config"`
	}{
		ConnectionConfig:     s.ConnectionConfig,
		AuthConfig:          s.AuthConfig,
		DataExtractionConfig: s.DataExtractionConfig,
	}
	
	data, _ := json.Marshal(configData)
	return fmt.Sprintf("%x", data)
}

// Validate validates the source system configuration
func (s *SourceSystem) Validate() error {
	if s.TenantID == uuid.Nil {
		return NewMigrationError(MigrationErrorTypeValidation, "tenant_id is required", nil)
	}
	
	if s.Name == "" {
		return NewMigrationError(MigrationErrorTypeValidation, "name is required", nil)
	}
	
	if s.ConnectionConfig.BaseURL == "" {
		return NewMigrationError(MigrationErrorTypeValidation, "base_url is required in connection config", nil)
	}
	
	if s.AuthConfig.Type == "" {
		return NewMigrationError(MigrationErrorTypeValidation, "authentication type is required", nil)
	}
	
	if len(s.DataExtractionConfig.SupportedDataTypes) == 0 {
		return NewMigrationError(MigrationErrorTypeValidation, "at least one supported data type is required", nil)
	}
	
	// Set defaults
	if s.ConnectionConfig.Timeout <= 0 {
		s.ConnectionConfig.Timeout = 30
	}
	
	if s.ConnectionConfig.MaxRetries <= 0 {
		s.ConnectionConfig.MaxRetries = 3
	}
	
	if s.DataExtractionConfig.DefaultBatchSize <= 0 {
		s.DataExtractionConfig.DefaultBatchSize = 1000
	}
	
	return nil
}

// Clone creates a deep copy of the source system
func (s *SourceSystem) Clone() *SourceSystem {
	data, _ := json.Marshal(s)
	var clone SourceSystem
	json.Unmarshal(data, &clone)
	clone.ID = uuid.New() // Generate new ID for clone
	return &clone
}

// ToAuditData returns audit data for the source system
func (s *SourceSystem) ToAuditData() map[string]interface{} {
	return map[string]interface{}{
		"source_system_id":    s.ID,
		"tenant_id":          s.TenantID,
		"name":               s.Name,
		"vendor":             s.Vendor,
		"product_name":       s.ProductName,
		"product_version":    s.ProductVersion,
		"system_type":        s.SystemType,
		"status":             s.Status,
		"is_active":          s.IsActive,
		"total_migrations":   s.TotalMigrations,
		"success_rate":       s.GetSuccessRate(),
		"uptime_percentage":  s.UpTimePercentage,
		"error_rate":         s.ErrorRate,
		"security_clearance": s.SecurityClearance,
		"data_classification": s.DataClassification,
		"created_by":         s.CreatedBy,
		"created_at":         s.CreatedAt,
		"updated_at":         s.UpdatedAt,
	}
}