package entity

import (
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
)

// MigrationResultStatus represents the status of a migration result
type MigrationResultStatus string

const (
	MigrationResultStatusPending   MigrationResultStatus = "pending"
	MigrationResultStatusSuccess   MigrationResultStatus = "success"
	MigrationResultStatusFailed    MigrationResultStatus = "failed"
	MigrationResultStatusSkipped   MigrationResultStatus = "skipped"
	MigrationResultStatusPartial   MigrationResultStatus = "partial"
	MigrationResultStatusValidating MigrationResultStatus = "validating"
)

// QualityScore represents data quality metrics
type QualityScore struct {
	Overall        float64            `json:"overall"`
	Completeness   float64            `json:"completeness"`
	Accuracy       float64            `json:"accuracy"`
	Consistency    float64            `json:"consistency"`
	Validity       float64            `json:"validity"`
	Uniqueness     float64            `json:"uniqueness"`
	Details        map[string]float64 `json:"details,omitempty"`
}

// DataMapping represents field mapping between source and target
type DataMapping struct {
	SourceField    string                 `json:"source_field"`
	TargetField    string                 `json:"target_field"`
	DataType       string                 `json:"data_type"`
	Required       bool                   `json:"required"`
	DefaultValue   interface{}            `json:"default_value,omitempty"`
	Transformation string                 `json:"transformation,omitempty"`
	Validation     string                 `json:"validation,omitempty"`
	Mapped         bool                   `json:"mapped"`
	MappingNotes   string                 `json:"mapping_notes,omitempty"`
}

// ValidationResult represents data validation results
type ValidationResult struct {
	IsValid        bool                   `json:"is_valid"`
	Errors         []string               `json:"errors,omitempty"`
	Warnings       []string               `json:"warnings,omitempty"`
	ValidationRules []ValidationRuleResult `json:"validation_rules,omitempty"`
	QualityScore   QualityScore           `json:"quality_score"`
}

// ValidationRuleResult represents the result of a validation rule
type ValidationRuleResult struct {
	RuleName       string      `json:"rule_name"`
	RuleType       string      `json:"rule_type"`
	Field          string      `json:"field"`
	Passed         bool        `json:"passed"`
	ErrorMessage   string      `json:"error_message,omitempty"`
	Value          interface{} `json:"value,omitempty"`
	ExpectedValue  interface{} `json:"expected_value,omitempty"`
}

// TransformationResult represents data transformation results
type TransformationResult struct {
	TransformationApplied bool                   `json:"transformation_applied"`
	TransformationRules   []string               `json:"transformation_rules,omitempty"`
	FieldsTransformed     []string               `json:"fields_transformed,omitempty"`
	TransformationErrors  []string               `json:"transformation_errors,omitempty"`
	OriginalValues        map[string]interface{} `json:"original_values,omitempty"`
	TransformedValues     map[string]interface{} `json:"transformed_values,omitempty"`
}

// PerformanceMetrics represents performance metrics for the migration result
type PerformanceMetrics struct {
	ProcessingTimeMs      int64     `json:"processing_time_ms"`
	ExtractionTimeMs      int64     `json:"extraction_time_ms"`
	TransformationTimeMs  int64     `json:"transformation_time_ms"`
	ValidationTimeMs      int64     `json:"validation_time_ms"`
	IngestionTimeMs       int64     `json:"ingestion_time_ms"`
	TotalTimeMs           int64     `json:"total_time_ms"`
	
	// Throughput metrics
	RecordsPerSecond      float64   `json:"records_per_second"`
	BytesPerSecond        float64   `json:"bytes_per_second"`
	
	// Resource usage
	CPUUsagePercent       float64   `json:"cpu_usage_percent,omitempty"`
	MemoryUsageMB         float64   `json:"memory_usage_mb,omitempty"`
	NetworkBytesTransferred int64   `json:"network_bytes_transferred,omitempty"`
	
	// Retry metrics
	RetryAttempts         int32     `json:"retry_attempts"`
	SuccessfulRetries     int32     `json:"successful_retries"`
	FailedRetries         int32     `json:"failed_retries"`
}

// DataStatistics represents statistics about the migrated data
type DataStatistics struct {
	RecordCount           int64                  `json:"record_count"`
	ByteSize              int64                  `json:"byte_size"`
	FieldCount            int32                  `json:"field_count"`
	NullValueCount        int64                  `json:"null_value_count"`
	DuplicateCount        int64                  `json:"duplicate_count"`
	UniqueValueCount      int64                  `json:"unique_value_count"`
	
	// Data type distribution
	DataTypeDistribution  map[string]int64       `json:"data_type_distribution,omitempty"`
	
	// Value distributions
	FieldStatistics       map[string]FieldStats  `json:"field_statistics,omitempty"`
	
	// Date range information
	DateRange             *DateRangeStats        `json:"date_range,omitempty"`
	
	// Size distribution
	RecordSizeStats       SizeStats              `json:"record_size_stats"`
}

// FieldStats represents statistics for a specific field
type FieldStats struct {
	FieldName         string                 `json:"field_name"`
	DataType          string                 `json:"data_type"`
	NullCount         int64                  `json:"null_count"`
	UniqueCount       int64                  `json:"unique_count"`
	MinValue          interface{}            `json:"min_value,omitempty"`
	MaxValue          interface{}            `json:"max_value,omitempty"`
	AvgValue          interface{}            `json:"avg_value,omitempty"`
	CommonValues      []ValueCount           `json:"common_values,omitempty"`
	PatternMatches    map[string]int64       `json:"pattern_matches,omitempty"`
}

// ValueCount represents a value and its count
type ValueCount struct {
	Value interface{} `json:"value"`
	Count int64       `json:"count"`
}

// DateRangeStats represents date range statistics
type DateRangeStats struct {
	EarliestDate time.Time `json:"earliest_date"`
	LatestDate   time.Time `json:"latest_date"`
	DateCount    int64     `json:"date_count"`
	DateSpanDays int64     `json:"date_span_days"`
}

// SizeStats represents size-related statistics
type SizeStats struct {
	MinSize     int64   `json:"min_size"`
	MaxSize     int64   `json:"max_size"`
	AvgSize     float64 `json:"avg_size"`
	MedianSize  int64   `json:"median_size"`
	TotalSize   int64   `json:"total_size"`
}

// ComplianceResult represents compliance validation results
type ComplianceResult struct {
	IsCompliant           bool                   `json:"is_compliant"`
	ComplianceFrameworks  []string               `json:"compliance_frameworks"`
	ComplianceChecks      []ComplianceCheck      `json:"compliance_checks"`
	ComplianceScore       float64                `json:"compliance_score"`
	NonCompliantFields    []string               `json:"non_compliant_fields,omitempty"`
	ComplianceNotes       string                 `json:"compliance_notes,omitempty"`
}

// ComplianceCheck represents a single compliance check
type ComplianceCheck struct {
	Framework     string `json:"framework"`
	CheckName     string `json:"check_name"`
	CheckType     string `json:"check_type"`
	Passed        bool   `json:"passed"`
	Description   string `json:"description"`
	Requirement   string `json:"requirement,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
}

// MigrationResult represents the result of migrating a specific record or batch
type MigrationResult struct {
	// Core fields
	ID                    uuid.UUID                `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID              uuid.UUID                `gorm:"type:uuid;not null;index" json:"tenant_id"`
	MigrationJobID        uuid.UUID                `gorm:"type:uuid;not null;index" json:"migration_job_id"`
	SourceSystemID        uuid.UUID                `gorm:"type:uuid;not null;index" json:"source_system_id"`
	
	// Record identification
	SourceRecordID        string                   `gorm:"not null;index" json:"source_record_id"`
	TargetRecordID        *string                  `gorm:"index" json:"target_record_id,omitempty"`
	DataType              DataType                 `gorm:"not null;index" json:"data_type"`
	BatchID               *string                  `gorm:"index" json:"batch_id,omitempty"`
	
	// Migration status and outcome
	Status                MigrationResultStatus   `gorm:"not null;index" json:"status"`
	Message               *string                  `json:"message,omitempty"`
	
	// Data content
	SourceData            map[string]interface{}   `gorm:"type:jsonb" json:"source_data,omitempty"`
	TransformedData       map[string]interface{}   `gorm:"type:jsonb" json:"transformed_data,omitempty"`
	TargetData            map[string]interface{}   `gorm:"type:jsonb" json:"target_data,omitempty"`
	
	// Data mapping and transformation
	DataMappings          []DataMapping            `gorm:"type:jsonb" json:"data_mappings,omitempty"`
	TransformationResult  *TransformationResult    `gorm:"type:jsonb" json:"transformation_result,omitempty"`
	
	// Validation and quality
	ValidationResult      *ValidationResult        `gorm:"type:jsonb" json:"validation_result,omitempty"`
	QualityScore          *QualityScore            `gorm:"type:jsonb" json:"quality_score,omitempty"`
	
	// Performance metrics
	PerformanceMetrics    PerformanceMetrics       `gorm:"type:jsonb" json:"performance_metrics"`
	
	// Data statistics
	DataStatistics        *DataStatistics          `gorm:"type:jsonb" json:"data_statistics,omitempty"`
	
	// Compliance validation
	ComplianceResult      *ComplianceResult        `gorm:"type:jsonb" json:"compliance_result,omitempty"`
	
	// Error handling
	ErrorCount            int32                    `gorm:"default:0" json:"error_count"`
	ErrorDetails          []MigrationError         `gorm:"type:jsonb" json:"error_details,omitempty"`
	WarningCount          int32                    `gorm:"default:0" json:"warning_count"`
	WarningDetails        []string                 `json:"warning_details,omitempty"`
	
	// Retry information
	RetryAttempts         int32                    `gorm:"default:0" json:"retry_attempts"`
	MaxRetries            int32                    `gorm:"default:3" json:"max_retries"`
	LastRetryAt           *time.Time               `json:"last_retry_at,omitempty"`
	NextRetryAt           *time.Time               `json:"next_retry_at,omitempty"`
	
	// Checkpointing
	CheckpointData        map[string]interface{}   `gorm:"type:jsonb" json:"checkpoint_data,omitempty"`
	LastCheckpoint        *time.Time               `json:"last_checkpoint,omitempty"`
	
	// Security and compliance
	SecurityClearance     string                   `gorm:"not null;default:'unclassified'" json:"security_clearance"`
	DataClassification    string                   `gorm:"default:'internal'" json:"data_classification"`
	EncryptionApplied     bool                     `gorm:"default:false" json:"encryption_applied"`
	
	// Metadata and tracking
	CorrelationID         *string                  `json:"correlation_id,omitempty"`
	Tags                  []string                 `gorm:"type:text[]" json:"tags,omitempty"`
	Metadata              map[string]interface{}   `gorm:"type:jsonb" json:"metadata,omitempty"`
	
	// Timing information
	StartedAt             time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP" json:"started_at"`
	CompletedAt           *time.Time               `json:"completed_at,omitempty"`
	ProcessingDuration    *time.Duration           `json:"processing_duration,omitempty"`
	
	// Audit fields
	CreatedAt             time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt             time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	
	// Relationships
	MigrationJob          *MigrationJob            `gorm:"foreignKey:MigrationJobID" json:"migration_job,omitempty"`
	SourceSystem          *SourceSystem            `gorm:"foreignKey:SourceSystemID" json:"source_system,omitempty"`
}

// TableName returns the table name for GORM
func (MigrationResult) TableName() string {
	return "migration_results"
}

// IsSuccessful returns true if the migration result is successful
func (m *MigrationResult) IsSuccessful() bool {
	return m.Status == MigrationResultStatusSuccess
}

// IsFailed returns true if the migration result failed
func (m *MigrationResult) IsFailed() bool {
	return m.Status == MigrationResultStatusFailed
}

// IsPartial returns true if the migration result is partial
func (m *MigrationResult) IsPartial() bool {
	return m.Status == MigrationResultStatusPartial
}

// CanRetry returns true if the migration result can be retried
func (m *MigrationResult) CanRetry() bool {
	return m.IsFailed() && m.RetryAttempts < m.MaxRetries
}

// ShouldRetryNow returns true if the migration should be retried now
func (m *MigrationResult) ShouldRetryNow() bool {
	if !m.CanRetry() {
		return false
	}
	if m.NextRetryAt == nil {
		return true
	}
	return time.Now().After(*m.NextRetryAt)
}

// MarkCompleted marks the migration result as completed
func (m *MigrationResult) MarkCompleted(status MigrationResultStatus, targetRecordID *string) {
	m.Status = status
	m.TargetRecordID = targetRecordID
	now := time.Now()
	m.CompletedAt = &now
	
	if m.StartedAt.IsZero() {
		m.StartedAt = now
	} else {
		duration := now.Sub(m.StartedAt)
		m.ProcessingDuration = &duration
		m.PerformanceMetrics.TotalTimeMs = duration.Milliseconds()
	}
}

// AddError adds an error to the migration result
func (m *MigrationResult) AddError(migrationError *MigrationError) {
	m.ErrorCount++
	if m.ErrorDetails == nil {
		m.ErrorDetails = make([]MigrationError, 0)
	}
	m.ErrorDetails = append(m.ErrorDetails, *migrationError)
	
	if m.Status == MigrationResultStatusPending || m.Status == MigrationResultStatusSuccess {
		m.Status = MigrationResultStatusFailed
	}
}

// AddWarning adds a warning to the migration result
func (m *MigrationResult) AddWarning(warning string) {
	m.WarningCount++
	if m.WarningDetails == nil {
		m.WarningDetails = make([]string, 0)
	}
	m.WarningDetails = append(m.WarningDetails, warning)
}

// SetValidationResult sets the validation result
func (m *MigrationResult) SetValidationResult(result *ValidationResult) {
	m.ValidationResult = result
	if result != nil {
		m.QualityScore = &result.QualityScore
	}
}

// SetTransformationResult sets the transformation result
func (m *MigrationResult) SetTransformationResult(result *TransformationResult) {
	m.TransformationResult = result
}

// SetComplianceResult sets the compliance result
func (m *MigrationResult) SetComplianceResult(result *ComplianceResult) {
	m.ComplianceResult = result
}

// UpdatePerformanceMetrics updates performance metrics
func (m *MigrationResult) UpdatePerformanceMetrics(extractionTime, transformationTime, validationTime, ingestionTime time.Duration) {
	metrics := &m.PerformanceMetrics
	metrics.ExtractionTimeMs = extractionTime.Milliseconds()
	metrics.TransformationTimeMs = transformationTime.Milliseconds()
	metrics.ValidationTimeMs = validationTime.Milliseconds()
	metrics.IngestionTimeMs = ingestionTime.Milliseconds()
	metrics.ProcessingTimeMs = metrics.ExtractionTimeMs + metrics.TransformationTimeMs + metrics.ValidationTimeMs + metrics.IngestionTimeMs
	
	// Calculate throughput if we have data statistics
	if m.DataStatistics != nil && metrics.ProcessingTimeMs > 0 {
		processingSeconds := float64(metrics.ProcessingTimeMs) / 1000.0
		metrics.RecordsPerSecond = float64(m.DataStatistics.RecordCount) / processingSeconds
		metrics.BytesPerSecond = float64(m.DataStatistics.ByteSize) / processingSeconds
	}
}

// IncrementRetry increments the retry count and updates retry timing
func (m *MigrationResult) IncrementRetry(nextRetryDelay time.Duration) {
	m.RetryAttempts++
	now := time.Now()
	m.LastRetryAt = &now
	nextRetry := now.Add(nextRetryDelay)
	m.NextRetryAt = &nextRetry
}

// SetCheckpoint sets checkpoint data for the migration result
func (m *MigrationResult) SetCheckpoint(checkpointData map[string]interface{}) {
	m.CheckpointData = checkpointData
	now := time.Now()
	m.LastCheckpoint = &now
}

// GetOverallQualityScore returns the overall quality score
func (m *MigrationResult) GetOverallQualityScore() float64 {
	if m.QualityScore != nil {
		return m.QualityScore.Overall
	}
	return 0.0
}

// GetSuccessRate returns the success rate based on errors and warnings
func (m *MigrationResult) GetSuccessRate() float64 {
	totalIssues := m.ErrorCount + m.WarningCount
	if totalIssues == 0 {
		return 100.0
	}
	
	// Weight errors more heavily than warnings
	errorWeight := float64(m.ErrorCount) * 1.0
	warningWeight := float64(m.WarningCount) * 0.3
	totalWeight := errorWeight + warningWeight
	
	return math.Max(0, 100.0 - (totalWeight * 10.0))
}

// ToSummary returns a summary of the migration result
func (m *MigrationResult) ToSummary() map[string]interface{} {
	return map[string]interface{}{
		"id":                     m.ID.String(),
		"source_record_id":       m.SourceRecordID,
		"target_record_id":       m.TargetRecordID,
		"data_type":              m.DataType,
		"status":                 m.Status,
		"error_count":            m.ErrorCount,
		"warning_count":          m.WarningCount,
		"retry_attempts":         m.RetryAttempts,
		"quality_score":          m.GetOverallQualityScore(),
		"success_rate":           m.GetSuccessRate(),
		"processing_time_ms":     m.PerformanceMetrics.ProcessingTimeMs,
		"records_per_second":     m.PerformanceMetrics.RecordsPerSecond,
		"started_at":             m.StartedAt,
		"completed_at":           m.CompletedAt,
		"is_successful":          m.IsSuccessful(),
		"can_retry":              m.CanRetry(),
	}
}

// Clone creates a deep copy of the migration result
func (m *MigrationResult) Clone() *MigrationResult {
	data, _ := json.Marshal(m)
	var clone MigrationResult
	json.Unmarshal(data, &clone)
	clone.ID = uuid.New() // Generate new ID for clone
	return &clone
}

// Validate validates the migration result
func (m *MigrationResult) Validate() error {
	if m.TenantID == uuid.Nil {
		return NewMigrationError(MigrationErrorTypeValidation, "tenant_id is required", nil)
	}
	
	if m.MigrationJobID == uuid.Nil {
		return NewMigrationError(MigrationErrorTypeValidation, "migration_job_id is required", nil)
	}
	
	if m.SourceSystemID == uuid.Nil {
		return NewMigrationError(MigrationErrorTypeValidation, "source_system_id is required", nil)
	}
	
	if m.SourceRecordID == "" {
		return NewMigrationError(MigrationErrorTypeValidation, "source_record_id is required", nil)
	}
	
	if m.MaxRetries <= 0 {
		m.MaxRetries = 3 // Default max retries
	}
	
	return nil
}