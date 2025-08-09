package entity

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MigrationErrorType represents the type of migration error
type MigrationErrorType string

const (
	MigrationErrorTypeConnection    MigrationErrorType = "connection"
	MigrationErrorTypeAuthentication MigrationErrorType = "authentication"
	MigrationErrorTypeAuthorization MigrationErrorType = "authorization"
	MigrationErrorTypeValidation    MigrationErrorType = "validation"
	MigrationErrorTypeTransformation MigrationErrorType = "transformation"
	MigrationErrorTypeRateLimit     MigrationErrorType = "rate_limit"
	MigrationErrorTypeTimeout       MigrationErrorType = "timeout"
	MigrationErrorTypeDataFormat    MigrationErrorType = "data_format"
	MigrationErrorTypeDataQuality   MigrationErrorType = "data_quality"
	MigrationErrorTypeSystemOverload MigrationErrorType = "system_overload"
	MigrationErrorTypeConfiguration MigrationErrorType = "configuration"
	MigrationErrorTypeNetwork       MigrationErrorType = "network"
	MigrationErrorTypeDatabase      MigrationErrorType = "database"
	MigrationErrorTypeStorage       MigrationErrorType = "storage"
	MigrationErrorTypeInternal      MigrationErrorType = "internal"
	MigrationErrorTypeExternal      MigrationErrorType = "external"
	MigrationErrorTypeUnknown       MigrationErrorType = "unknown"
)

// MigrationErrorSeverity represents the severity of migration error
type MigrationErrorSeverity string

const (
	MigrationErrorSeverityLow      MigrationErrorSeverity = "low"
	MigrationErrorSeverityMedium   MigrationErrorSeverity = "medium"
	MigrationErrorSeverityHigh     MigrationErrorSeverity = "high"
	MigrationErrorSeverityCritical MigrationErrorSeverity = "critical"
)

// MigrationError represents an error that occurred during migration
type MigrationError struct {
	Type        MigrationErrorType      `json:"type"`
	Message     string                  `json:"message"`
	Details     map[string]interface{}  `json:"details,omitempty"`
	Code        string                  `json:"code,omitempty"`
	Severity    MigrationErrorSeverity  `json:"severity"`
	Timestamp   time.Time               `json:"timestamp"`
	StackTrace  string                  `json:"stack_trace,omitempty"`
	
	// Context information
	TenantID         *uuid.UUID         `json:"tenant_id,omitempty"`
	MigrationJobID   *uuid.UUID         `json:"migration_job_id,omitempty"`
	SourceSystemID   *uuid.UUID         `json:"source_system_id,omitempty"`
	DataType         *DataType          `json:"data_type,omitempty"`
	RecordID         *string            `json:"record_id,omitempty"`
	
	// Retry information
	Retryable        bool               `json:"retryable"`
	RetryAttempts    int32              `json:"retry_attempts"`
	MaxRetries       int32              `json:"max_retries"`
	NextRetryAt      *time.Time         `json:"next_retry_at,omitempty"`
	
	// Resolution information
	Resolved         bool               `json:"resolved"`
	ResolvedAt       *time.Time         `json:"resolved_at,omitempty"`
	ResolvedBy       *uuid.UUID         `json:"resolved_by,omitempty"`
	Resolution       *string            `json:"resolution,omitempty"`
	
	// Impact assessment
	AffectedRecords  int64              `json:"affected_records"`
	BusinessImpact   string             `json:"business_impact,omitempty"`
	
	// Related errors
	RelatedErrors    []string           `json:"related_errors,omitempty"`
	RootCauseID      *string            `json:"root_cause_id,omitempty"`
}

// Error implements the error interface
func (e *MigrationError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

// NewMigrationError creates a new migration error
func NewMigrationError(errorType MigrationErrorType, message string, details map[string]interface{}) *MigrationError {
	return &MigrationError{
		Type:        errorType,
		Message:     message,
		Details:     details,
		Severity:    DetermineSeverity(errorType),
		Timestamp:   time.Now(),
		Retryable:   IsRetryable(errorType),
		MaxRetries:  GetMaxRetries(errorType),
	}
}

// WithCode adds an error code to the migration error
func (e *MigrationError) WithCode(code string) *MigrationError {
	e.Code = code
	return e
}

// WithSeverity sets the severity of the migration error
func (e *MigrationError) WithSeverity(severity MigrationErrorSeverity) *MigrationError {
	e.Severity = severity
	return e
}

// WithContext adds context information to the migration error
func (e *MigrationError) WithContext(tenantID, migrationJobID, sourceSystemID *uuid.UUID, dataType *DataType, recordID *string) *MigrationError {
	e.TenantID = tenantID
	e.MigrationJobID = migrationJobID
	e.SourceSystemID = sourceSystemID
	e.DataType = dataType
	e.RecordID = recordID
	return e
}

// WithRetryInfo sets retry information for the migration error
func (e *MigrationError) WithRetryInfo(retryable bool, attempts, maxRetries int32, nextRetryAt *time.Time) *MigrationError {
	e.Retryable = retryable
	e.RetryAttempts = attempts
	e.MaxRetries = maxRetries
	e.NextRetryAt = nextRetryAt
	return e
}

// WithImpact sets impact information for the migration error
func (e *MigrationError) WithImpact(affectedRecords int64, businessImpact string) *MigrationError {
	e.AffectedRecords = affectedRecords
	e.BusinessImpact = businessImpact
	return e
}

// CanRetry returns true if the error can be retried
func (e *MigrationError) CanRetry() bool {
	return e.Retryable && e.RetryAttempts < e.MaxRetries
}

// ShouldRetryNow returns true if the error should be retried now
func (e *MigrationError) ShouldRetryNow() bool {
	if !e.CanRetry() {
		return false
	}
	if e.NextRetryAt == nil {
		return true
	}
	return time.Now().After(*e.NextRetryAt)
}

// MarkResolved marks the error as resolved
func (e *MigrationError) MarkResolved(resolvedBy uuid.UUID, resolution string) {
	e.Resolved = true
	now := time.Now()
	e.ResolvedAt = &now
	e.ResolvedBy = &resolvedBy
	e.Resolution = &resolution
}

// DetermineSeverity determines the severity based on error type
func DetermineSeverity(errorType MigrationErrorType) MigrationErrorSeverity {
	switch errorType {
	case MigrationErrorTypeConnection, MigrationErrorTypeAuthentication, MigrationErrorTypeAuthorization:
		return MigrationErrorSeverityCritical
	case MigrationErrorTypeConfiguration, MigrationErrorTypeDatabase, MigrationErrorTypeStorage:
		return MigrationErrorSeverityHigh
	case MigrationErrorTypeValidation, MigrationErrorTypeTransformation, MigrationErrorTypeDataFormat:
		return MigrationErrorSeverityMedium
	case MigrationErrorTypeDataQuality, MigrationErrorTypeRateLimit, MigrationErrorTypeTimeout:
		return MigrationErrorSeverityLow
	default:
		return MigrationErrorSeverityMedium
	}
}

// IsRetryable determines if an error type is retryable
func IsRetryable(errorType MigrationErrorType) bool {
	switch errorType {
	case MigrationErrorTypeRateLimit, MigrationErrorTypeTimeout, MigrationErrorTypeNetwork:
		return true
	case MigrationErrorTypeSystemOverload, MigrationErrorTypeExternal:
		return true
	case MigrationErrorTypeConnection:
		return true
	case MigrationErrorTypeValidation, MigrationErrorTypeAuthentication, MigrationErrorTypeAuthorization:
		return false
	case MigrationErrorTypeConfiguration, MigrationErrorTypeDataFormat:
		return false
	default:
		return true // Default to retryable for unknown errors
	}
}

// GetMaxRetries returns the maximum number of retries for an error type
func GetMaxRetries(errorType MigrationErrorType) int32 {
	switch errorType {
	case MigrationErrorTypeRateLimit:
		return 10 // Rate limits may require more retries
	case MigrationErrorTypeTimeout, MigrationErrorTypeNetwork:
		return 5
	case MigrationErrorTypeConnection, MigrationErrorTypeSystemOverload:
		return 3
	case MigrationErrorTypeExternal:
		return 2
	default:
		return 3 // Default retry count
	}
}

// Common migration errors
var (
	ErrConnectionFailed = &MigrationError{
		Type:     MigrationErrorTypeConnection,
		Message:  "Failed to connect to source system",
		Severity: MigrationErrorSeverityCritical,
		Retryable: true,
	}
	
	ErrAuthenticationFailed = &MigrationError{
		Type:     MigrationErrorTypeAuthentication,
		Message:  "Authentication failed",
		Severity: MigrationErrorSeverityCritical,
		Retryable: false,
	}
	
	ErrAuthorizationFailed = &MigrationError{
		Type:     MigrationErrorTypeAuthorization,
		Message:  "Authorization failed - insufficient permissions",
		Severity: MigrationErrorSeverityCritical,
		Retryable: false,
	}
	
	ErrRateLimitExceeded = &MigrationError{
		Type:     MigrationErrorTypeRateLimit,
		Message:  "Rate limit exceeded",
		Severity: MigrationErrorSeverityLow,
		Retryable: true,
	}
	
	ErrTimeout = &MigrationError{
		Type:     MigrationErrorTypeTimeout,
		Message:  "Request timeout",
		Severity: MigrationErrorSeverityMedium,
		Retryable: true,
	}
	
	ErrDataValidationFailed = &MigrationError{
		Type:     MigrationErrorTypeValidation,
		Message:  "Data validation failed",
		Severity: MigrationErrorSeverityMedium,
		Retryable: false,
	}
	
	ErrDataTransformationFailed = &MigrationError{
		Type:     MigrationErrorTypeTransformation,
		Message:  "Data transformation failed",
		Severity: MigrationErrorSeverityMedium,
		Retryable: false,
	}
	
	ErrInvalidDataFormat = &MigrationError{
		Type:     MigrationErrorTypeDataFormat,
		Message:  "Invalid data format",
		Severity: MigrationErrorSeverityMedium,
		Retryable: false,
	}
	
	ErrSystemOverload = &MigrationError{
		Type:     MigrationErrorTypeSystemOverload,
		Message:  "System overload detected",
		Severity: MigrationErrorSeverityHigh,
		Retryable: true,
	}
)

// ErrorCategory represents a category of errors for grouping and analysis
type ErrorCategory struct {
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	ErrorTypes      []MigrationErrorType `json:"error_types"`
	DefaultSeverity MigrationErrorSeverity `json:"default_severity"`
	DefaultRetryable bool              `json:"default_retryable"`
	TroubleshootingSteps []string      `json:"troubleshooting_steps,omitempty"`
}

// Common error categories
var (
	ConnectivityErrorCategory = ErrorCategory{
		Name:        "Connectivity",
		Description: "Errors related to network connectivity and connection establishment",
		ErrorTypes:  []MigrationErrorType{MigrationErrorTypeConnection, MigrationErrorTypeNetwork, MigrationErrorTypeTimeout},
		DefaultSeverity: MigrationErrorSeverityHigh,
		DefaultRetryable: true,
		TroubleshootingSteps: []string{
			"Check network connectivity",
			"Verify firewall rules",
			"Test DNS resolution",
			"Validate SSL certificates",
		},
	}
	
	AuthenticationErrorCategory = ErrorCategory{
		Name:        "Authentication",
		Description: "Errors related to authentication and authorization",
		ErrorTypes:  []MigrationErrorType{MigrationErrorTypeAuthentication, MigrationErrorTypeAuthorization},
		DefaultSeverity: MigrationErrorSeverityCritical,
		DefaultRetryable: false,
		TroubleshootingSteps: []string{
			"Verify credentials",
			"Check API key validity",
			"Validate permissions",
			"Review access policies",
		},
	}
	
	DataQualityErrorCategory = ErrorCategory{
		Name:        "Data Quality",
		Description: "Errors related to data validation and transformation",
		ErrorTypes:  []MigrationErrorType{MigrationErrorTypeValidation, MigrationErrorTypeTransformation, MigrationErrorTypeDataFormat, MigrationErrorTypeDataQuality},
		DefaultSeverity: MigrationErrorSeverityMedium,
		DefaultRetryable: false,
		TroubleshootingSteps: []string{
			"Review data validation rules",
			"Check field mappings",
			"Validate data formats",
			"Review transformation logic",
		},
	}
	
	PerformanceErrorCategory = ErrorCategory{
		Name:        "Performance",
		Description: "Errors related to system performance and resource limits",
		ErrorTypes:  []MigrationErrorType{MigrationErrorTypeRateLimit, MigrationErrorTypeSystemOverload, MigrationErrorTypeTimeout},
		DefaultSeverity: MigrationErrorSeverityMedium,
		DefaultRetryable: true,
		TroubleshootingSteps: []string{
			"Reduce batch size",
			"Implement rate limiting",
			"Increase timeout values",
			"Add retry delays",
		},
	}
)

// GetErrorCategory returns the category for a given error type
func GetErrorCategory(errorType MigrationErrorType) *ErrorCategory {
	categories := []*ErrorCategory{
		&ConnectivityErrorCategory,
		&AuthenticationErrorCategory,
		&DataQualityErrorCategory,
		&PerformanceErrorCategory,
	}
	
	for _, category := range categories {
		for _, et := range category.ErrorTypes {
			if et == errorType {
				return category
			}
		}
	}
	
	return nil // No category found
}

// ErrorStatistics represents error statistics for analysis
type ErrorStatistics struct {
	TotalErrors        int64                            `json:"total_errors"`
	ErrorsByType       map[MigrationErrorType]int64     `json:"errors_by_type"`
	ErrorsBySeverity   map[MigrationErrorSeverity]int64 `json:"errors_by_severity"`
	ErrorsByCategory   map[string]int64                 `json:"errors_by_category"`
	ResolvedErrors     int64                            `json:"resolved_errors"`
	UnresolvedErrors   int64                            `json:"unresolved_errors"`
	RetryableErrors    int64                            `json:"retryable_errors"`
	NonRetryableErrors int64                            `json:"non_retryable_errors"`
	AverageResolutionTime time.Duration                `json:"average_resolution_time"`
	
	// Time-based statistics
	ErrorsLast24Hours  int64                            `json:"errors_last_24_hours"`
	ErrorTrend         string                           `json:"error_trend"` // increasing, decreasing, stable
	
	// Top errors
	TopErrorTypes      []ErrorTypeStat                  `json:"top_error_types"`
	TopErrorMessages   []ErrorMessageStat               `json:"top_error_messages"`
}

// ErrorTypeStat represents statistics for an error type
type ErrorTypeStat struct {
	ErrorType    MigrationErrorType `json:"error_type"`
	Count        int64              `json:"count"`
	Percentage   float64            `json:"percentage"`
	LastOccurred time.Time          `json:"last_occurred"`
}

// ErrorMessageStat represents statistics for an error message
type ErrorMessageStat struct {
	Message      string    `json:"message"`
	Count        int64     `json:"count"`
	Percentage   float64   `json:"percentage"`
	LastOccurred time.Time `json:"last_occurred"`
}