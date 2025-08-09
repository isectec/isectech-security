package connectors

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/domain/entity"
)

// DataExtractor defines the interface for extracting data from source systems
type DataExtractor interface {
	// Connect establishes connection to the source system
	Connect(ctx context.Context) error
	
	// Disconnect closes connection to the source system
	Disconnect(ctx context.Context) error
	
	// TestConnection tests the connection to the source system
	TestConnection(ctx context.Context) error
	
	// GetSystemInfo retrieves system information and capabilities
	GetSystemInfo(ctx context.Context) (*SystemInfo, error)
	
	// ValidateConfiguration validates the connector configuration
	ValidateConfiguration() error
	
	// ExtractData extracts data based on the provided parameters
	ExtractData(ctx context.Context, params *ExtractionParams) (*ExtractionResult, error)
	
	// GetSchema returns the data schema for a specific data type
	GetSchema(ctx context.Context, dataType entity.DataType) (*DataSchema, error)
	
	// EstimateRecordCount estimates the number of records for extraction
	EstimateRecordCount(ctx context.Context, params *ExtractionParams) (int64, error)
	
	// SupportsPagination returns true if the connector supports pagination
	SupportsPagination() bool
	
	// SupportsIncremental returns true if the connector supports incremental extraction
	SupportsIncremental() bool
	
	// GetRateLimit returns the rate limit information
	GetRateLimit() *entity.RateLimit
}

// AuthenticationHandler defines the interface for authentication handling
type AuthenticationHandler interface {
	// Authenticate performs authentication with the source system
	Authenticate(ctx context.Context) error
	
	// RefreshToken refreshes the authentication token if applicable
	RefreshToken(ctx context.Context) error
	
	// IsAuthenticated returns true if currently authenticated
	IsAuthenticated() bool
	
	// GetAuthHeaders returns authentication headers for API requests
	GetAuthHeaders() map[string]string
	
	// GetAuthToken returns the current authentication token
	GetAuthToken() *AuthToken
}

// HealthMonitor defines the interface for health monitoring
type HealthMonitor interface {
	// CheckHealth performs a health check on the source system
	CheckHealth(ctx context.Context) (*HealthStatus, error)
	
	// GetHealthMetrics returns current health metrics
	GetHealthMetrics() *HealthMetrics
	
	// StartHealthMonitoring starts continuous health monitoring
	StartHealthMonitoring(ctx context.Context, interval time.Duration) error
	
	// StopHealthMonitoring stops health monitoring
	StopHealthMonitoring()
}

// DataTransformer defines the interface for data transformation
type DataTransformer interface {
	// TransformRecord transforms a single record to iSECTECH format
	TransformRecord(ctx context.Context, record map[string]interface{}, dataType entity.DataType) (*TransformedRecord, error)
	
	// TransformBatch transforms a batch of records
	TransformBatch(ctx context.Context, batch []map[string]interface{}, dataType entity.DataType) ([]*TransformedRecord, error)
	
	// GetFieldMappings returns field mappings for a data type
	GetFieldMappings(dataType entity.DataType) map[string]string
	
	// ValidateRecord validates a record against the schema
	ValidateRecord(ctx context.Context, record map[string]interface{}, dataType entity.DataType) (*ValidationResult, error)
}

// SystemInfo contains information about the source system
type SystemInfo struct {
	SystemID           uuid.UUID                    `json:"system_id"`
	Name               string                       `json:"name"`
	Version            string                       `json:"version"`
	Vendor             entity.SourceSystemVendor   `json:"vendor"`
	SystemType         entity.SourceSystemType     `json:"system_type"`
	SupportedDataTypes []entity.DataType            `json:"supported_data_types"`
	Capabilities       entity.SystemCapabilities   `json:"capabilities"`
	APIVersion         string                       `json:"api_version,omitempty"`
	ServerInfo         map[string]interface{}       `json:"server_info,omitempty"`
	LicenseInfo        *LicenseInfo                 `json:"license_info,omitempty"`
	InstanceInfo       *InstanceInfo                `json:"instance_info,omitempty"`
}

// LicenseInfo contains licensing information
type LicenseInfo struct {
	Type              string     `json:"type"`
	ExpirationDate    *time.Time `json:"expiration_date,omitempty"`
	MaxUsers          *int32     `json:"max_users,omitempty"`
	MaxDataVolume     *int64     `json:"max_data_volume,omitempty"`
	Features          []string   `json:"features,omitempty"`
	IsValid           bool       `json:"is_valid"`
	ValidationMessage string     `json:"validation_message,omitempty"`
}

// InstanceInfo contains instance-specific information
type InstanceInfo struct {
	InstanceID        string                 `json:"instance_id"`
	Region            string                 `json:"region,omitempty"`
	DataCenter        string                 `json:"data_center,omitempty"`
	Timezone          string                 `json:"timezone,omitempty"`
	Environment       string                 `json:"environment,omitempty"` // prod, staging, dev
	CustomProperties  map[string]interface{} `json:"custom_properties,omitempty"`
}

// ExtractionParams defines parameters for data extraction
type ExtractionParams struct {
	DataType        entity.DataType            `json:"data_type"`
	DateRange       *entity.DateRange          `json:"date_range,omitempty"`
	Filters         map[string]interface{}     `json:"filters,omitempty"`
	BatchSize       int32                      `json:"batch_size"`
	MaxRecords      *int64                     `json:"max_records,omitempty"`
	
	// Pagination parameters
	PageToken       *string                    `json:"page_token,omitempty"`
	Offset          *int64                     `json:"offset,omitempty"`
	Limit           *int32                     `json:"limit,omitempty"`
	
	// Incremental extraction
	LastSyncTime    *time.Time                 `json:"last_sync_time,omitempty"`
	CheckpointData  map[string]interface{}     `json:"checkpoint_data,omitempty"`
	
	// Field selection
	IncludeFields   []string                   `json:"include_fields,omitempty"`
	ExcludeFields   []string                   `json:"exclude_fields,omitempty"`
	
	// Performance tuning
	ParallelRequests bool                      `json:"parallel_requests"`
	RateLimit       *int32                     `json:"rate_limit,omitempty"`
	Timeout         *time.Duration             `json:"timeout,omitempty"`
	
	// Quality options
	ValidateData    bool                       `json:"validate_data"`
	SkipInvalid     bool                       `json:"skip_invalid"`
	Deduplicate     bool                       `json:"deduplicate"`
}

// ExtractionResult contains the result of data extraction
type ExtractionResult struct {
	Records         []map[string]interface{}   `json:"records"`
	TotalRecords    int64                      `json:"total_records"`
	ExtractedCount  int64                      `json:"extracted_count"`
	SkippedCount    int64                      `json:"skipped_count"`
	
	// Pagination info
	HasMore         bool                       `json:"has_more"`
	NextPageToken   *string                    `json:"next_page_token,omitempty"`
	NextOffset      *int64                     `json:"next_offset,omitempty"`
	
	// Checkpointing
	CheckpointData  map[string]interface{}     `json:"checkpoint_data,omitempty"`
	LastSyncTime    *time.Time                 `json:"last_sync_time,omitempty"`
	
	// Metadata
	ExtractionTime  time.Duration              `json:"extraction_time"`
	DataSize        int64                      `json:"data_size"`
	Errors          []string                   `json:"errors,omitempty"`
	Warnings        []string                   `json:"warnings,omitempty"`
	
	// Quality metrics
	QualityMetrics  *DataQualityMetrics        `json:"quality_metrics,omitempty"`
	Schema          *DataSchema                `json:"schema,omitempty"`
}

// DataSchema defines the schema for extracted data
type DataSchema struct {
	DataType        entity.DataType            `json:"data_type"`
	Version         string                     `json:"version"`
	Fields          []FieldSchema              `json:"fields"`
	RequiredFields  []string                   `json:"required_fields"`
	PrimaryKey      []string                   `json:"primary_key,omitempty"`
	Indexes         []string                   `json:"indexes,omitempty"`
	Constraints     []SchemaConstraint         `json:"constraints,omitempty"`
	LastUpdated     time.Time                  `json:"last_updated"`
}

// FieldSchema defines schema for a field
type FieldSchema struct {
	Name            string                     `json:"name"`
	Type            string                     `json:"type"`
	Required        bool                       `json:"required"`
	Description     string                     `json:"description,omitempty"`
	Format          string                     `json:"format,omitempty"`
	Pattern         string                     `json:"pattern,omitempty"`
	MinLength       *int32                     `json:"min_length,omitempty"`
	MaxLength       *int32                     `json:"max_length,omitempty"`
	MinValue        *float64                   `json:"min_value,omitempty"`
	MaxValue        *float64                   `json:"max_value,omitempty"`
	DefaultValue    interface{}                `json:"default_value,omitempty"`
	AllowedValues   []interface{}              `json:"allowed_values,omitempty"`
	Deprecated      bool                       `json:"deprecated"`
	Tags            []string                   `json:"tags,omitempty"`
}

// SchemaConstraint defines schema constraints
type SchemaConstraint struct {
	Name            string                     `json:"name"`
	Type            string                     `json:"type"` // unique, foreign_key, check, etc.
	Fields          []string                   `json:"fields"`
	ReferenceTable  string                     `json:"reference_table,omitempty"`
	ReferenceFields []string                   `json:"reference_fields,omitempty"`
	Expression      string                     `json:"expression,omitempty"`
}

// DataQualityMetrics contains data quality metrics
type DataQualityMetrics struct {
	TotalRecords        int64                  `json:"total_records"`
	ValidRecords        int64                  `json:"valid_records"`
	InvalidRecords      int64                  `json:"invalid_records"`
	DuplicateRecords    int64                  `json:"duplicate_records"`
	NullValues          map[string]int64       `json:"null_values"`
	
	// Quality scores
	CompletenessScore   float64                `json:"completeness_score"`
	AccuracyScore       float64                `json:"accuracy_score"`
	ConsistencyScore    float64                `json:"consistency_score"`
	ValidityScore       float64                `json:"validity_score"`
	UniquenessScore     float64                `json:"uniqueness_score"`
	OverallScore        float64                `json:"overall_score"`
	
	// Data profile
	DataProfile         map[string]interface{} `json:"data_profile,omitempty"`
	ValidationErrors    []ValidationError      `json:"validation_errors,omitempty"`
}

// ValidationResult contains validation results
type ValidationResult struct {
	IsValid         bool                       `json:"is_valid"`
	Errors          []ValidationError          `json:"errors,omitempty"`
	Warnings        []ValidationWarning        `json:"warnings,omitempty"`
	Score           float64                    `json:"score"`
	FieldResults    map[string]FieldValidation `json:"field_results,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field           string                     `json:"field"`
	ErrorType       string                     `json:"error_type"`
	Message         string                     `json:"message"`
	Value           interface{}                `json:"value,omitempty"`
	ExpectedValue   interface{}                `json:"expected_value,omitempty"`
	Severity        string                     `json:"severity"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field           string                     `json:"field"`
	WarningType     string                     `json:"warning_type"`
	Message         string                     `json:"message"`
	Value           interface{}                `json:"value,omitempty"`
	Recommendation  string                     `json:"recommendation,omitempty"`
}

// FieldValidation contains field-level validation results
type FieldValidation struct {
	IsValid         bool                       `json:"is_valid"`
	Score           float64                    `json:"score"`
	Errors          []ValidationError          `json:"errors,omitempty"`
	Warnings        []ValidationWarning        `json:"warnings,omitempty"`
}

// TransformedRecord contains a transformed record
type TransformedRecord struct {
	OriginalData    map[string]interface{}     `json:"original_data"`
	TransformedData map[string]interface{}     `json:"transformed_data"`
	DataType        entity.DataType            `json:"data_type"`
	TransformationApplied []string             `json:"transformation_applied"`
	ValidationResult *ValidationResult         `json:"validation_result,omitempty"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// AuthToken contains authentication token information
type AuthToken struct {
	Token           string                     `json:"token"`
	TokenType       string                     `json:"token_type"`
	ExpiresAt       *time.Time                 `json:"expires_at,omitempty"`
	RefreshToken    string                     `json:"refresh_token,omitempty"`
	Scope           []string                   `json:"scope,omitempty"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// HealthStatus contains health status information
type HealthStatus struct {
	IsHealthy       bool                       `json:"is_healthy"`
	Status          string                     `json:"status"`
	Message         string                     `json:"message,omitempty"`
	ResponseTime    time.Duration              `json:"response_time"`
	LastChecked     time.Time                  `json:"last_checked"`
	
	// Component health
	Components      map[string]ComponentHealth `json:"components,omitempty"`
	
	// System metrics
	SystemMetrics   *SystemMetrics             `json:"system_metrics,omitempty"`
	
	// Connectivity tests
	ConnectivityTests []ConnectivityTest       `json:"connectivity_tests,omitempty"`
}

// ComponentHealth contains health information for a component
type ComponentHealth struct {
	Name            string                     `json:"name"`
	IsHealthy       bool                       `json:"is_healthy"`
	Status          string                     `json:"status"`
	Message         string                     `json:"message,omitempty"`
	ResponseTime    time.Duration              `json:"response_time"`
	LastChecked     time.Time                  `json:"last_checked"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// SystemMetrics contains system-level metrics
type SystemMetrics struct {
	CPUUsage        float64                    `json:"cpu_usage"`
	MemoryUsage     float64                    `json:"memory_usage"`
	DiskUsage       float64                    `json:"disk_usage"`
	NetworkLatency  time.Duration              `json:"network_latency"`
	ActiveConnections int32                    `json:"active_connections"`
	RequestsPerSecond float64                  `json:"requests_per_second"`
	ErrorRate       float64                    `json:"error_rate"`
	UpTime          time.Duration              `json:"uptime"`
}

// ConnectivityTest contains connectivity test results
type ConnectivityTest struct {
	TestName        string                     `json:"test_name"`
	Success         bool                       `json:"success"`
	ResponseTime    time.Duration              `json:"response_time"`
	Message         string                     `json:"message,omitempty"`
	Details         map[string]interface{}     `json:"details,omitempty"`
}

// HealthMetrics contains aggregated health metrics
type HealthMetrics struct {
	UpTimePercentage    float64                `json:"uptime_percentage"`
	AverageResponseTime time.Duration          `json:"average_response_time"`
	ErrorRate           float64                `json:"error_rate"`
	SuccessfulRequests  int64                  `json:"successful_requests"`
	FailedRequests      int64                  `json:"failed_requests"`
	TotalRequests       int64                  `json:"total_requests"`
	LastSuccessfulCheck time.Time              `json:"last_successful_check"`
	LastFailedCheck     *time.Time             `json:"last_failed_check,omitempty"`
	ConsecutiveFailures int32                  `json:"consecutive_failures"`
}

// ConnectorError represents a connector-specific error
type ConnectorError struct {
	Type        string                     `json:"type"`
	Message     string                     `json:"message"`
	Details     map[string]interface{}     `json:"details,omitempty"`
	Timestamp   time.Time                  `json:"timestamp"`
	Retryable   bool                       `json:"retryable"`
	ErrorCode   string                     `json:"error_code,omitempty"`
	HTTPStatus  *int                       `json:"http_status,omitempty"`
}

// Error implements the error interface
func (e *ConnectorError) Error() string {
	return e.Message
}

// ConnectorFactory defines the interface for creating connectors
type ConnectorFactory interface {
	// CreateConnector creates a new connector instance
	CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error)
	
	// GetSupportedVendors returns the list of supported vendors
	GetSupportedVendors() []entity.SourceSystemVendor
	
	// GetSupportedSystemTypes returns the list of supported system types
	GetSupportedSystemTypes() []entity.SourceSystemType
	
	// ValidateConfiguration validates connector configuration
	ValidateConfiguration(config map[string]interface{}) error
}

// ConnectorRegistry manages connector factories
type ConnectorRegistry interface {
	// RegisterFactory registers a connector factory
	RegisterFactory(vendor entity.SourceSystemVendor, factory ConnectorFactory) error
	
	// GetFactory returns a connector factory for the given vendor
	GetFactory(vendor entity.SourceSystemVendor) (ConnectorFactory, error)
	
	// ListVendors returns all registered vendors
	ListVendors() []entity.SourceSystemVendor
	
	// CreateConnector creates a connector for the given source system
	CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error)
}