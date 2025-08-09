package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// LogLevel represents the level of the log entry
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// LogEventType represents the type of log event
type LogEventType string

const (
	LogEventTypeJobStarted         LogEventType = "job_started"
	LogEventTypeJobCompleted       LogEventType = "job_completed"
	LogEventTypeJobPaused          LogEventType = "job_paused"
	LogEventTypeJobResumed         LogEventType = "job_resumed"
	LogEventTypeJobCancelled       LogEventType = "job_cancelled"
	LogEventTypeJobFailed          LogEventType = "job_failed"
	
	LogEventTypeDataExtracted      LogEventType = "data_extracted"
	LogEventTypeDataTransformed    LogEventType = "data_transformed"
	LogEventTypeDataValidated      LogEventType = "data_validated"
	LogEventTypeDataIngested       LogEventType = "data_ingested"
	
	LogEventTypeConnectionEstablished LogEventType = "connection_established"
	LogEventTypeConnectionLost     LogEventType = "connection_lost"
	LogEventTypeAuthenticationSuccess LogEventType = "authentication_success"
	LogEventTypeAuthenticationFailed LogEventType = "authentication_failed"
	
	LogEventTypeRateLimitHit       LogEventType = "rate_limit_hit"
	LogEventTypeRetryAttempt       LogEventType = "retry_attempt"
	LogEventTypeCheckpointCreated  LogEventType = "checkpoint_created"
	LogEventTypeProgressUpdate     LogEventType = "progress_update"
	
	LogEventTypeError              LogEventType = "error"
	LogEventTypeWarning            LogEventType = "warning"
	LogEventTypeSystemEvent        LogEventType = "system_event"
	LogEventTypeCustom             LogEventType = "custom"
)

// MigrationLog represents a log entry for migration operations
type MigrationLog struct {
	// Core fields
	ID               uuid.UUID                `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID         uuid.UUID                `gorm:"type:uuid;not null;index" json:"tenant_id"`
	MigrationJobID   uuid.UUID                `gorm:"type:uuid;not null;index" json:"migration_job_id"`
	SourceSystemID   *uuid.UUID               `gorm:"type:uuid;index" json:"source_system_id,omitempty"`
	
	// Log details
	Level            LogLevel                 `gorm:"not null;index" json:"level"`
	EventType        LogEventType             `gorm:"not null;index" json:"event_type"`
	Message          string                   `gorm:"not null" json:"message"`
	Details          map[string]interface{}   `gorm:"type:jsonb" json:"details,omitempty"`
	
	// Context information
	DataType         *DataType                `json:"data_type,omitempty"`
	RecordID         *string                  `json:"record_id,omitempty"`
	BatchID          *string                  `json:"batch_id,omitempty"`
	WorkerID         *string                  `json:"worker_id,omitempty"`
	
	// Performance metrics
	Duration         *time.Duration           `json:"duration,omitempty"`
	RecordsProcessed *int64                   `json:"records_processed,omitempty"`
	BytesProcessed   *int64                   `json:"bytes_processed,omitempty"`
	
	// Error information
	ErrorType        *MigrationErrorType      `json:"error_type,omitempty"`
	ErrorCode        *string                  `json:"error_code,omitempty"`
	ErrorDetails     map[string]interface{}   `gorm:"type:jsonb" json:"error_details,omitempty"`
	StackTrace       *string                  `json:"stack_trace,omitempty"`
	
	// Source information
	SourceFile       *string                  `json:"source_file,omitempty"`
	SourceFunction   *string                  `json:"source_function,omitempty"`
	SourceLine       *int32                   `json:"source_line,omitempty"`
	
	// Correlation and tracing
	CorrelationID    *string                  `json:"correlation_id,omitempty"`
	TraceID          *string                  `json:"trace_id,omitempty"`
	SpanID           *string                  `json:"span_id,omitempty"`
	ParentSpanID     *string                  `json:"parent_span_id,omitempty"`
	
	// Metadata
	Tags             []string                 `gorm:"type:text[]" json:"tags,omitempty"`
	Metadata         map[string]interface{}   `gorm:"type:jsonb" json:"metadata,omitempty"`
	
	// Audit fields
	Timestamp        time.Time                `gorm:"not null;default:CURRENT_TIMESTAMP;index" json:"timestamp"`
	
	// Relationships
	MigrationJob     *MigrationJob            `gorm:"foreignKey:MigrationJobID" json:"migration_job,omitempty"`
	SourceSystem     *SourceSystem            `gorm:"foreignKey:SourceSystemID" json:"source_system,omitempty"`
}

// TableName returns the table name for GORM
func (MigrationLog) TableName() string {
	return "migration_logs"
}

// IsError returns true if the log entry is an error
func (m *MigrationLog) IsError() bool {
	return m.Level == LogLevelError || m.Level == LogLevelFatal
}

// IsWarning returns true if the log entry is a warning
func (m *MigrationLog) IsWarning() bool {
	return m.Level == LogLevelWarn
}

// HasError returns true if the log entry contains error information
func (m *MigrationLog) HasError() bool {
	return m.ErrorType != nil || m.ErrorCode != nil
}

// AddTag adds a tag to the log entry
func (m *MigrationLog) AddTag(tag string) {
	if m.Tags == nil {
		m.Tags = make([]string, 0)
	}
	m.Tags = append(m.Tags, tag)
}

// SetCorrelationID sets the correlation ID for request tracing
func (m *MigrationLog) SetCorrelationID(correlationID string) {
	m.CorrelationID = &correlationID
}

// SetTracing sets distributed tracing information
func (m *MigrationLog) SetTracing(traceID, spanID, parentSpanID string) {
	m.TraceID = &traceID
	m.SpanID = &spanID
	if parentSpanID != "" {
		m.ParentSpanID = &parentSpanID
	}
}

// SetPerformanceMetrics sets performance metrics for the log entry
func (m *MigrationLog) SetPerformanceMetrics(duration time.Duration, recordsProcessed, bytesProcessed int64) {
	m.Duration = &duration
	m.RecordsProcessed = &recordsProcessed
	m.BytesProcessed = &bytesProcessed
}

// SetError sets error information for the log entry
func (m *MigrationLog) SetError(errorType MigrationErrorType, errorCode string, errorDetails map[string]interface{}, stackTrace string) {
	m.ErrorType = &errorType
	m.ErrorCode = &errorCode
	m.ErrorDetails = errorDetails
	m.StackTrace = &stackTrace
	m.Level = LogLevelError
}

// SetSource sets source code information for debugging
func (m *MigrationLog) SetSource(file, function string, line int32) {
	m.SourceFile = &file
	m.SourceFunction = &function
	m.SourceLine = &line
}

// ToStructuredLog converts the log entry to a structured log format
func (m *MigrationLog) ToStructuredLog() map[string]interface{} {
	log := map[string]interface{}{
		"id":                m.ID.String(),
		"tenant_id":         m.TenantID.String(),
		"migration_job_id":  m.MigrationJobID.String(),
		"level":            m.Level,
		"event_type":       m.EventType,
		"message":          m.Message,
		"timestamp":        m.Timestamp,
	}
	
	if m.SourceSystemID != nil {
		log["source_system_id"] = m.SourceSystemID.String()
	}
	
	if m.DataType != nil {
		log["data_type"] = *m.DataType
	}
	
	if m.RecordID != nil {
		log["record_id"] = *m.RecordID
	}
	
	if m.BatchID != nil {
		log["batch_id"] = *m.BatchID
	}
	
	if m.WorkerID != nil {
		log["worker_id"] = *m.WorkerID
	}
	
	if m.Duration != nil {
		log["duration_ms"] = m.Duration.Milliseconds()
	}
	
	if m.RecordsProcessed != nil {
		log["records_processed"] = *m.RecordsProcessed
	}
	
	if m.BytesProcessed != nil {
		log["bytes_processed"] = *m.BytesProcessed
	}
	
	if m.ErrorType != nil {
		log["error_type"] = *m.ErrorType
	}
	
	if m.ErrorCode != nil {
		log["error_code"] = *m.ErrorCode
	}
	
	if m.CorrelationID != nil {
		log["correlation_id"] = *m.CorrelationID
	}
	
	if m.TraceID != nil {
		log["trace_id"] = *m.TraceID
	}
	
	if m.SpanID != nil {
		log["span_id"] = *m.SpanID
	}
	
	if len(m.Tags) > 0 {
		log["tags"] = m.Tags
	}
	
	if m.Details != nil {
		for k, v := range m.Details {
			log[k] = v
		}
	}
	
	if m.Metadata != nil {
		log["metadata"] = m.Metadata
	}
	
	return log
}

// LogBuilder helps build migration log entries
type LogBuilder struct {
	log *MigrationLog
}

// NewLogBuilder creates a new log builder
func NewLogBuilder(tenantID, migrationJobID uuid.UUID) *LogBuilder {
	return &LogBuilder{
		log: &MigrationLog{
			ID:             uuid.New(),
			TenantID:       tenantID,
			MigrationJobID: migrationJobID,
			Timestamp:      time.Now(),
			Details:        make(map[string]interface{}),
			Metadata:       make(map[string]interface{}),
		},
	}
}

// WithLevel sets the log level
func (b *LogBuilder) WithLevel(level LogLevel) *LogBuilder {
	b.log.Level = level
	return b
}

// WithEventType sets the event type
func (b *LogBuilder) WithEventType(eventType LogEventType) *LogBuilder {
	b.log.EventType = eventType
	return b
}

// WithMessage sets the log message
func (b *LogBuilder) WithMessage(message string) *LogBuilder {
	b.log.Message = message
	return b
}

// WithSourceSystem sets the source system ID
func (b *LogBuilder) WithSourceSystem(sourceSystemID uuid.UUID) *LogBuilder {
	b.log.SourceSystemID = &sourceSystemID
	return b
}

// WithDataType sets the data type
func (b *LogBuilder) WithDataType(dataType DataType) *LogBuilder {
	b.log.DataType = &dataType
	return b
}

// WithRecordID sets the record ID
func (b *LogBuilder) WithRecordID(recordID string) *LogBuilder {
	b.log.RecordID = &recordID
	return b
}

// WithBatchID sets the batch ID
func (b *LogBuilder) WithBatchID(batchID string) *LogBuilder {
	b.log.BatchID = &batchID
	return b
}

// WithWorkerID sets the worker ID
func (b *LogBuilder) WithWorkerID(workerID string) *LogBuilder {
	b.log.WorkerID = &workerID
	return b
}

// WithDuration sets the operation duration
func (b *LogBuilder) WithDuration(duration time.Duration) *LogBuilder {
	b.log.Duration = &duration
	return b
}

// WithRecordsProcessed sets the number of records processed
func (b *LogBuilder) WithRecordsProcessed(count int64) *LogBuilder {
	b.log.RecordsProcessed = &count
	return b
}

// WithBytesProcessed sets the number of bytes processed
func (b *LogBuilder) WithBytesProcessed(bytes int64) *LogBuilder {
	b.log.BytesProcessed = &bytes
	return b
}

// WithError sets error information
func (b *LogBuilder) WithError(errorType MigrationErrorType, errorCode string, errorDetails map[string]interface{}) *LogBuilder {
	b.log.ErrorType = &errorType
	b.log.ErrorCode = &errorCode
	b.log.ErrorDetails = errorDetails
	b.log.Level = LogLevelError
	return b
}

// WithStackTrace sets the stack trace
func (b *LogBuilder) WithStackTrace(stackTrace string) *LogBuilder {
	b.log.StackTrace = &stackTrace
	return b
}

// WithCorrelationID sets the correlation ID
func (b *LogBuilder) WithCorrelationID(correlationID string) *LogBuilder {
	b.log.CorrelationID = &correlationID
	return b
}

// WithTracing sets distributed tracing information
func (b *LogBuilder) WithTracing(traceID, spanID, parentSpanID string) *LogBuilder {
	b.log.TraceID = &traceID
	b.log.SpanID = &spanID
	if parentSpanID != "" {
		b.log.ParentSpanID = &parentSpanID
	}
	return b
}

// WithTags sets tags
func (b *LogBuilder) WithTags(tags ...string) *LogBuilder {
	b.log.Tags = tags
	return b
}

// WithDetail adds a detail key-value pair
func (b *LogBuilder) WithDetail(key string, value interface{}) *LogBuilder {
	if b.log.Details == nil {
		b.log.Details = make(map[string]interface{})
	}
	b.log.Details[key] = value
	return b
}

// WithMetadata adds metadata key-value pair
func (b *LogBuilder) WithMetadata(key string, value interface{}) *LogBuilder {
	if b.log.Metadata == nil {
		b.log.Metadata = make(map[string]interface{})
	}
	b.log.Metadata[key] = value
	return b
}

// Build returns the constructed log entry
func (b *LogBuilder) Build() *MigrationLog {
	return b.log
}

// Common log entry creators
func NewJobStartedLog(tenantID, migrationJobID uuid.UUID, sourceSystemID uuid.UUID) *MigrationLog {
	return NewLogBuilder(tenantID, migrationJobID).
		WithLevel(LogLevelInfo).
		WithEventType(LogEventTypeJobStarted).
		WithMessage("Migration job started").
		WithSourceSystem(sourceSystemID).
		Build()
}

func NewJobCompletedLog(tenantID, migrationJobID uuid.UUID, duration time.Duration, recordsProcessed int64) *MigrationLog {
	return NewLogBuilder(tenantID, migrationJobID).
		WithLevel(LogLevelInfo).
		WithEventType(LogEventTypeJobCompleted).
		WithMessage("Migration job completed successfully").
		WithDuration(duration).
		WithRecordsProcessed(recordsProcessed).
		Build()
}

func NewJobFailedLog(tenantID, migrationJobID uuid.UUID, errorType MigrationErrorType, errorMsg string) *MigrationLog {
	return NewLogBuilder(tenantID, migrationJobID).
		WithLevel(LogLevelError).
		WithEventType(LogEventTypeJobFailed).
		WithMessage("Migration job failed: " + errorMsg).
		WithError(errorType, "", nil).
		Build()
}

func NewDataExtractedLog(tenantID, migrationJobID uuid.UUID, dataType DataType, recordCount int64, batchID string) *MigrationLog {
	return NewLogBuilder(tenantID, migrationJobID).
		WithLevel(LogLevelInfo).
		WithEventType(LogEventTypeDataExtracted).
		WithMessage("Data extracted successfully").
		WithDataType(dataType).
		WithRecordsProcessed(recordCount).
		WithBatchID(batchID).
		Build()
}

func NewConnectionEstablishedLog(tenantID, migrationJobID, sourceSystemID uuid.UUID) *MigrationLog {
	return NewLogBuilder(tenantID, migrationJobID).
		WithLevel(LogLevelInfo).
		WithEventType(LogEventTypeConnectionEstablished).
		WithMessage("Connection established to source system").
		WithSourceSystem(sourceSystemID).
		Build()
}

func NewRateLimitHitLog(tenantID, migrationJobID uuid.UUID, retryAfter time.Duration) *MigrationLog {
	return NewLogBuilder(tenantID, migrationJobID).
		WithLevel(LogLevelWarn).
		WithEventType(LogEventTypeRateLimitHit).
		WithMessage("Rate limit exceeded, will retry").
		WithDetail("retry_after_seconds", retryAfter.Seconds()).
		Build()
}

func NewProgressUpdateLog(tenantID, migrationJobID uuid.UUID, progress float64, recordsProcessed int64) *MigrationLog {
	return NewLogBuilder(tenantID, migrationJobID).
		WithLevel(LogLevelInfo).
		WithEventType(LogEventTypeProgressUpdate).
		WithMessage("Migration progress update").
		WithRecordsProcessed(recordsProcessed).
		WithDetail("progress_percentage", progress).
		Build()
}