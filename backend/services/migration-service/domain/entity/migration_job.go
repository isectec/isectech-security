package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// MigrationJobStatus represents the status of a migration job
type MigrationJobStatus string

const (
	MigrationJobStatusPending     MigrationJobStatus = "pending"
	MigrationJobStatusRunning     MigrationJobStatus = "running"
	MigrationJobStatusPaused      MigrationJobStatus = "paused"
	MigrationJobStatusCompleted   MigrationJobStatus = "completed"
	MigrationJobStatusFailed      MigrationJobStatus = "failed"
	MigrationJobStatusCancelled   MigrationJobStatus = "cancelled"
	MigrationJobStatusValidating  MigrationJobStatus = "validating"
	MigrationJobStatusRollingBack MigrationJobStatus = "rolling_back"
)

// MigrationJobPriority represents the priority of a migration job
type MigrationJobPriority string

const (
	MigrationJobPriorityLow      MigrationJobPriority = "low"
	MigrationJobPriorityMedium   MigrationJobPriority = "medium"
	MigrationJobPriorityHigh     MigrationJobPriority = "high"
	MigrationJobPriorityCritical MigrationJobPriority = "critical"
)

// DataType represents the type of data being migrated
type DataType string

const (
	DataTypeAlerts         DataType = "alerts"
	DataTypeLogs           DataType = "logs"
	DataTypeIncidents      DataType = "incidents"
	DataTypeVulnerabilities DataType = "vulnerabilities"
	DataTypeAssets         DataType = "assets"
	DataTypeUsers          DataType = "users"
	DataTypePolicies       DataType = "policies"
	DataTypeReports        DataType = "reports"
	DataTypeThreats        DataType = "threats"
	DataTypeEvents         DataType = "events"
	DataTypeDashboards     DataType = "dashboards"
	DataTypeCustom         DataType = "custom"
)

// SourceSystemType represents the type of source system
type SourceSystemType string

const (
	SourceSystemTypeSIEM                 SourceSystemType = "siem"
	SourceSystemTypeEndpointProtection   SourceSystemType = "endpoint_protection"
	SourceSystemTypeVulnerabilityMgmt    SourceSystemType = "vulnerability_management"
	SourceSystemTypeNetworkSecurity      SourceSystemType = "network_security"
	SourceSystemTypeCloudSecurity        SourceSystemType = "cloud_security"
	SourceSystemTypeIdentityAccessMgmt   SourceSystemType = "identity_access_management"
	SourceSystemTypeThreatIntelligence   SourceSystemType = "threat_intelligence"
	SourceSystemTypeIncidentResponse     SourceSystemType = "incident_response"
	SourceSystemTypeComplianceGRC        SourceSystemType = "compliance_grc"
	SourceSystemTypeCustom              SourceSystemType = "custom"
)

// MigrationScope defines what data to migrate
type MigrationScope struct {
	DataTypes    []DataType            `json:"data_types"`
	DateRange    *DateRange            `json:"date_range,omitempty"`
	Filters      map[string]interface{} `json:"filters,omitempty"`
	MaxRecords   *int64                `json:"max_records,omitempty"`
	IncludeUsers []string              `json:"include_users,omitempty"`
	ExcludeUsers []string              `json:"exclude_users,omitempty"`
	
	// Advanced filtering
	SeverityLevels []string              `json:"severity_levels,omitempty"`
	Categories     []string              `json:"categories,omitempty"`
	Status         []string              `json:"status,omitempty"`
	Tags           []string              `json:"tags,omitempty"`
	
	// Performance tuning
	BatchSize      int32                 `json:"batch_size"`
	RateLimit      int32                 `json:"rate_limit"`
	RetryAttempts  int32                 `json:"retry_attempts"`
	TimeoutSeconds int32                 `json:"timeout_seconds"`
}

// DateRange represents a date range for migration
type DateRange struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// MigrationProgress tracks the progress of migration
type MigrationProgress struct {
	TotalRecords     int64             `json:"total_records"`
	ProcessedRecords int64             `json:"processed_records"`
	SuccessfulRecords int64            `json:"successful_records"`
	FailedRecords    int64             `json:"failed_records"`
	SkippedRecords   int64             `json:"skipped_records"`
	
	// Detailed breakdown by data type
	DataTypeProgress map[DataType]*DataTypeProgress `json:"data_type_progress"`
	
	// Performance metrics
	RecordsPerSecond float64           `json:"records_per_second"`
	EstimatedTimeRemaining *time.Duration `json:"estimated_time_remaining,omitempty"`
	LastCheckpoint   *time.Time        `json:"last_checkpoint,omitempty"`
	
	// Error tracking
	ErrorSummary     map[string]int64  `json:"error_summary"`
	RecentErrors     []string          `json:"recent_errors"`
	
	// Quality metrics
	DataQualityScore float64           `json:"data_quality_score"`
	ValidationErrors int64             `json:"validation_errors"`
	DuplicateRecords int64             `json:"duplicate_records"`
}

// DataTypeProgress tracks progress for specific data type
type DataTypeProgress struct {
	DataType          DataType  `json:"data_type"`
	TotalRecords      int64     `json:"total_records"`
	ProcessedRecords  int64     `json:"processed_records"`
	SuccessfulRecords int64     `json:"successful_records"`
	FailedRecords     int64     `json:"failed_records"`
	LastProcessedID   *string   `json:"last_processed_id,omitempty"`
	LastProcessedAt   *time.Time `json:"last_processed_at,omitempty"`
}

// MigrationConfiguration contains migration-specific settings
type MigrationConfiguration struct {
	// Data transformation settings
	TransformationRules map[string]interface{} `json:"transformation_rules,omitempty"`
	FieldMappings       map[string]string      `json:"field_mappings,omitempty"`
	DefaultValues       map[string]interface{} `json:"default_values,omitempty"`
	
	// Validation settings
	EnableValidation    bool                   `json:"enable_validation"`
	ValidationRules     []ValidationRule       `json:"validation_rules,omitempty"`
	StrictMode          bool                   `json:"strict_mode"`
	
	// Performance settings
	ParallelWorkers     int32                  `json:"parallel_workers"`
	BatchSize           int32                  `json:"batch_size"`
	MaxRetries          int32                  `json:"max_retries"`
	RetryDelaySeconds   int32                  `json:"retry_delay_seconds"`
	
	// Checkpointing settings
	CheckpointInterval  time.Duration          `json:"checkpoint_interval"`
	EnableCheckpointing bool                   `json:"enable_checkpointing"`
	
	// Security settings
	EncryptInTransit    bool                   `json:"encrypt_in_transit"`
	EncryptAtRest       bool                   `json:"encrypt_at_rest"`
	AuditAllOperations  bool                   `json:"audit_all_operations"`
	
	// Compliance settings
	RetentionPeriod     *time.Duration         `json:"retention_period,omitempty"`
	ComplianceFrameworks []string              `json:"compliance_frameworks,omitempty"`
	DataClassification  string                 `json:"data_classification,omitempty"`
}

// ValidationRule defines a data validation rule
type ValidationRule struct {
	Field       string                 `json:"field"`
	Type        string                 `json:"type"`        // required, format, range, enum, custom
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	ErrorMessage string                `json:"error_message,omitempty"`
	Severity    string                 `json:"severity"`    // error, warning, info
}

// MigrationJob represents a data migration job
type MigrationJob struct {
	// Core fields
	ID               uuid.UUID                `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID         uuid.UUID                `gorm:"type:uuid;not null;index" json:"tenant_id"`
	Name             string                   `gorm:"not null" json:"name"`
	Description      *string                  `json:"description,omitempty"`
	
	// Job configuration
	SourceSystemID   uuid.UUID                `gorm:"type:uuid;not null;index" json:"source_system_id"`
	SourceSystemType SourceSystemType         `gorm:"not null" json:"source_system_type"`
	Status           MigrationJobStatus       `gorm:"not null;default:'pending'" json:"status"`
	Priority         MigrationJobPriority     `gorm:"not null;default:'medium'" json:"priority"`
	
	// Migration scope and configuration
	Scope            MigrationScope           `gorm:"type:jsonb" json:"scope"`
	Configuration    MigrationConfiguration   `gorm:"type:jsonb" json:"configuration"`
	
	// Progress tracking
	Progress         MigrationProgress        `gorm:"type:jsonb" json:"progress"`
	
	// Scheduling
	ScheduledAt      *time.Time               `json:"scheduled_at,omitempty"`
	StartedAt        *time.Time               `json:"started_at,omitempty"`
	CompletedAt      *time.Time               `json:"completed_at,omitempty"`
	EstimatedDuration *time.Duration          `json:"estimated_duration,omitempty"`
	
	// Error handling
	ErrorCount       int32                    `gorm:"default:0" json:"error_count"`
	LastError        *string                  `json:"last_error,omitempty"`
	ErrorDetails     map[string]interface{}   `gorm:"type:jsonb" json:"error_details,omitempty"`
	
	// Metadata and tracking
	CreatedBy        uuid.UUID                `gorm:"type:uuid;not null" json:"created_by"`
	UpdatedBy        *uuid.UUID               `gorm:"type:uuid" json:"updated_by,omitempty"`
	Version          int32                    `gorm:"default:1" json:"version"`
	Tags             []string                 `gorm:"type:text[]" json:"tags,omitempty"`
	
	// Security and compliance
	SecurityClearance string                  `gorm:"not null;default:'unclassified'" json:"security_clearance"`
	ComplianceFrameworks []string             `gorm:"type:text[]" json:"compliance_frameworks,omitempty"`
	DataClassification string                 `gorm:"default:'internal'" json:"data_classification"`
	
	// Audit fields
	CreatedAt        time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt        time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	DeletedAt        *time.Time               `gorm:"index" json:"deleted_at,omitempty"`
	
	// Relationships
	SourceSystem     *SourceSystem            `gorm:"foreignKey:SourceSystemID" json:"source_system,omitempty"`
	MigrationLogs    []MigrationLog           `gorm:"foreignKey:MigrationJobID" json:"migration_logs,omitempty"`
	MigrationResults []MigrationResult        `gorm:"foreignKey:MigrationJobID" json:"migration_results,omitempty"`
}

// TableName returns the table name for GORM
func (MigrationJob) TableName() string {
	return "migration_jobs"
}

// IsActive returns true if the migration job is currently active
func (m *MigrationJob) IsActive() bool {
	return m.Status == MigrationJobStatusRunning || 
		   m.Status == MigrationJobStatusValidating ||
		   m.Status == MigrationJobStatusRollingBack
}

// IsCompleted returns true if the migration job is completed
func (m *MigrationJob) IsCompleted() bool {
	return m.Status == MigrationJobStatusCompleted
}

// IsFailed returns true if the migration job has failed
func (m *MigrationJob) IsFailed() bool {
	return m.Status == MigrationJobStatusFailed || m.Status == MigrationJobStatusCancelled
}

// CanBeStarted returns true if the migration job can be started
func (m *MigrationJob) CanBeStarted() bool {
	return m.Status == MigrationJobStatusPending
}

// CanBePaused returns true if the migration job can be paused
func (m *MigrationJob) CanBePaused() bool {
	return m.Status == MigrationJobStatusRunning
}

// CanBeResumed returns true if the migration job can be resumed
func (m *MigrationJob) CanBeResumed() bool {
	return m.Status == MigrationJobStatusPaused
}

// CanBeCancelled returns true if the migration job can be cancelled
func (m *MigrationJob) CanBeCancelled() bool {
	return m.Status == MigrationJobStatusPending || 
		   m.Status == MigrationJobStatusRunning || 
		   m.Status == MigrationJobStatusPaused
}

// GetProgressPercentage returns the migration progress as a percentage
func (m *MigrationJob) GetProgressPercentage() float64 {
	if m.Progress.TotalRecords == 0 {
		return 0.0
	}
	return float64(m.Progress.ProcessedRecords) / float64(m.Progress.TotalRecords) * 100.0
}

// GetSuccessRate returns the success rate of the migration
func (m *MigrationJob) GetSuccessRate() float64 {
	if m.Progress.ProcessedRecords == 0 {
		return 0.0
	}
	return float64(m.Progress.SuccessfulRecords) / float64(m.Progress.ProcessedRecords) * 100.0
}

// EstimateTimeRemaining estimates the remaining time for migration completion
func (m *MigrationJob) EstimateTimeRemaining() *time.Duration {
	if m.Progress.RecordsPerSecond <= 0 || m.Progress.TotalRecords <= m.Progress.ProcessedRecords {
		return nil
	}
	
	remainingRecords := m.Progress.TotalRecords - m.Progress.ProcessedRecords
	estimatedSeconds := float64(remainingRecords) / m.Progress.RecordsPerSecond
	estimated := time.Duration(estimatedSeconds) * time.Second
	
	return &estimated
}

// UpdateProgress updates the migration progress
func (m *MigrationJob) UpdateProgress(processed, successful, failed, skipped int64) {
	m.Progress.ProcessedRecords = processed
	m.Progress.SuccessfulRecords = successful
	m.Progress.FailedRecords = failed
	m.Progress.SkippedRecords = skipped
	
	// Calculate records per second if we have timing data
	if m.StartedAt != nil {
		elapsed := time.Since(*m.StartedAt)
		if elapsed.Seconds() > 0 {
			m.Progress.RecordsPerSecond = float64(processed) / elapsed.Seconds()
		}
	}
	
	// Update data quality score
	if processed > 0 {
		qualityFactor := float64(successful) / float64(processed)
		errorFactor := 1.0 - (float64(m.Progress.ValidationErrors) / float64(processed))
		duplicateFactor := 1.0 - (float64(m.Progress.DuplicateRecords) / float64(processed))
		
		m.Progress.DataQualityScore = (qualityFactor + errorFactor + duplicateFactor) / 3.0 * 100.0
	}
	
	// Update estimated time remaining
	estimated := m.EstimateTimeRemaining()
	m.Progress.EstimatedTimeRemaining = estimated
}

// AddError adds an error to the migration job
func (m *MigrationJob) AddError(errorMsg string, errorType string) {
	m.ErrorCount++
	m.LastError = &errorMsg
	
	// Initialize error summary if needed
	if m.Progress.ErrorSummary == nil {
		m.Progress.ErrorSummary = make(map[string]int64)
	}
	m.Progress.ErrorSummary[errorType]++
	
	// Add to recent errors (keep last 10)
	m.Progress.RecentErrors = append(m.Progress.RecentErrors, errorMsg)
	if len(m.Progress.RecentErrors) > 10 {
		m.Progress.RecentErrors = m.Progress.RecentErrors[1:]
	}
}

// SetCheckpoint sets a checkpoint for the migration
func (m *MigrationJob) SetCheckpoint() {
	now := time.Now()
	m.Progress.LastCheckpoint = &now
}

// Validate validates the migration job configuration
func (m *MigrationJob) Validate() error {
	if m.TenantID == uuid.Nil {
		return NewMigrationError(MigrationErrorTypeValidation, "tenant_id is required", nil)
	}
	
	if m.Name == "" {
		return NewMigrationError(MigrationErrorTypeValidation, "name is required", nil)
	}
	
	if m.SourceSystemID == uuid.Nil {
		return NewMigrationError(MigrationErrorTypeValidation, "source_system_id is required", nil)
	}
	
	if len(m.Scope.DataTypes) == 0 {
		return NewMigrationError(MigrationErrorTypeValidation, "at least one data type must be specified in scope", nil)
	}
	
	if m.Scope.BatchSize <= 0 {
		m.Scope.BatchSize = 1000 // Default batch size
	}
	
	if m.Scope.RateLimit <= 0 {
		m.Scope.RateLimit = 100 // Default rate limit
	}
	
	if m.Configuration.ParallelWorkers <= 0 {
		m.Configuration.ParallelWorkers = 4 // Default parallel workers
	}
	
	return nil
}

// Clone creates a deep copy of the migration job
func (m *MigrationJob) Clone() *MigrationJob {
	data, _ := json.Marshal(m)
	var clone MigrationJob
	json.Unmarshal(data, &clone)
	clone.ID = uuid.New() // Generate new ID for clone
	return &clone
}

// ToAuditData returns audit data for the migration job
func (m *MigrationJob) ToAuditData() map[string]interface{} {
	return map[string]interface{}{
		"migration_job_id":    m.ID,
		"tenant_id":          m.TenantID,
		"name":               m.Name,
		"source_system_id":   m.SourceSystemID,
		"source_system_type": m.SourceSystemType,
		"status":             m.Status,
		"priority":           m.Priority,
		"progress":           m.GetProgressPercentage(),
		"success_rate":       m.GetSuccessRate(),
		"error_count":        m.ErrorCount,
		"security_clearance": m.SecurityClearance,
		"data_classification": m.DataClassification,
		"created_by":         m.CreatedBy,
		"created_at":         m.CreatedAt,
		"updated_at":         m.UpdatedAt,
	}
}