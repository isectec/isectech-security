package engine

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/domain/entity"
)

// MigrationEngine defines the core migration orchestration interface
type MigrationEngine interface {
	// StartMigration initiates a migration job
	StartMigration(ctx context.Context, job *entity.MigrationJob) error
	
	// StopMigration stops a running migration job
	StopMigration(ctx context.Context, jobID uuid.UUID) error
	
	// PauseMigration pauses a running migration job
	PauseMigration(ctx context.Context, jobID uuid.UUID) error
	
	// ResumeMigration resumes a paused migration job
	ResumeMigration(ctx context.Context, jobID uuid.UUID) error
	
	// GetMigrationStatus returns the current status of a migration job
	GetMigrationStatus(ctx context.Context, jobID uuid.UUID) (*MigrationStatus, error)
	
	// GetMigrationProgress returns detailed progress information
	GetMigrationProgress(ctx context.Context, jobID uuid.UUID) (*MigrationProgress, error)
	
	// ListActiveMigrations returns all active migration jobs
	ListActiveMigrations(ctx context.Context, tenantID uuid.UUID) ([]*entity.MigrationJob, error)
	
	// ValidateMigrationJob validates a migration job configuration
	ValidateMigrationJob(ctx context.Context, job *entity.MigrationJob) (*ValidationResult, error)
}

// WorkflowEngine manages migration workflows and pipeline execution
type WorkflowEngine interface {
	// ExecuteWorkflow executes a complete migration workflow
	ExecuteWorkflow(ctx context.Context, workflow *MigrationWorkflow) (*WorkflowResult, error)
	
	// CreateWorkflow creates a workflow from a migration job
	CreateWorkflow(ctx context.Context, job *entity.MigrationJob) (*MigrationWorkflow, error)
	
	// GetWorkflowStatus returns the status of a workflow execution
	GetWorkflowStatus(ctx context.Context, workflowID uuid.UUID) (*WorkflowStatus, error)
	
	// RegisterStage registers a custom workflow stage
	RegisterStage(stageName string, stage WorkflowStage) error
	
	// GetRegisteredStages returns all registered workflow stages
	GetRegisteredStages() map[string]WorkflowStage
}

// SchemaMapper handles schema mapping between source and target systems
type SchemaMapper interface {
	// CreateMapping creates a schema mapping for a data type
	CreateMapping(ctx context.Context, mapping *SchemaMapping) error
	
	// GetMapping retrieves a schema mapping
	GetMapping(ctx context.Context, sourceSystem entity.SourceSystemVendor, dataType entity.DataType) (*SchemaMapping, error)
	
	// UpdateMapping updates an existing schema mapping
	UpdateMapping(ctx context.Context, mapping *SchemaMapping) error
	
	// DeleteMapping deletes a schema mapping
	DeleteMapping(ctx context.Context, mappingID uuid.UUID) error
	
	// ListMappings lists all schema mappings for a tenant
	ListMappings(ctx context.Context, tenantID uuid.UUID) ([]*SchemaMapping, error)
	
	// ValidateMapping validates a schema mapping configuration
	ValidateMapping(ctx context.Context, mapping *SchemaMapping) (*ValidationResult, error)
	
	// ApplyMapping applies a schema mapping to transform data
	ApplyMapping(ctx context.Context, mapping *SchemaMapping, sourceData map[string]interface{}) (map[string]interface{}, error)
}

// TransformationEngine handles data transformation operations
type TransformationEngine interface {
	// CreatePipeline creates a transformation pipeline
	CreatePipeline(ctx context.Context, pipeline *TransformationPipeline) error
	
	// ExecutePipeline executes a transformation pipeline on data
	ExecutePipeline(ctx context.Context, pipelineID uuid.UUID, data []map[string]interface{}) (*TransformationResult, error)
	
	// GetPipeline retrieves a transformation pipeline
	GetPipeline(ctx context.Context, pipelineID uuid.UUID) (*TransformationPipeline, error)
	
	// UpdatePipeline updates a transformation pipeline
	UpdatePipeline(ctx context.Context, pipeline *TransformationPipeline) error
	
	// DeletePipeline deletes a transformation pipeline
	DeletePipeline(ctx context.Context, pipelineID uuid.UUID) error
	
	// ListPipelines lists transformation pipelines for a tenant
	ListPipelines(ctx context.Context, tenantID uuid.UUID) ([]*TransformationPipeline, error)
	
	// RegisterTransformer registers a custom data transformer
	RegisterTransformer(name string, transformer DataTransformer) error
	
	// GetRegisteredTransformers returns all registered transformers
	GetRegisteredTransformers() map[string]DataTransformer
}

// ValidationEngine handles data validation and quality assessment
type ValidationEngine interface {
	// CreateValidationRules creates validation rules for a data type
	CreateValidationRules(ctx context.Context, rules *ValidationRules) error
	
	// ValidateData validates data against rules
	ValidateData(ctx context.Context, rulesID uuid.UUID, data []map[string]interface{}) (*ValidationResult, error)
	
	// GetValidationRules retrieves validation rules
	GetValidationRules(ctx context.Context, rulesID uuid.UUID) (*ValidationRules, error)
	
	// UpdateValidationRules updates validation rules
	UpdateValidationRules(ctx context.Context, rules *ValidationRules) error
	
	// DeleteValidationRules deletes validation rules
	DeleteValidationRules(ctx context.Context, rulesID uuid.UUID) error
	
	// ListValidationRules lists validation rules for a tenant
	ListValidationRules(ctx context.Context, tenantID uuid.UUID) ([]*ValidationRules, error)
	
	// AnalyzeDataQuality performs comprehensive data quality analysis
	AnalyzeDataQuality(ctx context.Context, data []map[string]interface{}, config *QualityAnalysisConfig) (*DataQualityReport, error)
	
	// RegisterValidator registers a custom data validator
	RegisterValidator(name string, validator DataValidator) error
}

// WorkflowStage represents a single stage in a migration workflow
type WorkflowStage interface {
	// GetName returns the stage name
	GetName() string
	
	// GetDescription returns the stage description
	GetDescription() string
	
	// GetDependencies returns the stages this stage depends on
	GetDependencies() []string
	
	// Execute executes the workflow stage
	Execute(ctx context.Context, input *StageInput) (*StageOutput, error)
	
	// Validate validates the stage configuration
	Validate(ctx context.Context, config map[string]interface{}) error
	
	// GetMetadata returns stage metadata
	GetMetadata() *StageMetadata
}

// DataTransformer handles individual data transformation operations
type DataTransformer interface {
	// GetName returns the transformer name
	GetName() string
	
	// GetDescription returns the transformer description
	GetDescription() string
	
	// Transform transforms input data
	Transform(ctx context.Context, input interface{}, config map[string]interface{}) (interface{}, error)
	
	// Validate validates the transformer configuration
	Validate(config map[string]interface{}) error
	
	// GetInputSchema returns the expected input schema
	GetInputSchema() *TransformerSchema
	
	// GetOutputSchema returns the output schema
	GetOutputSchema() *TransformerSchema
}

// DataValidator handles individual data validation operations
type DataValidator interface {
	// GetName returns the validator name
	GetName() string
	
	// GetDescription returns the validator description
	GetDescription() string
	
	// Validate validates input data
	Validate(ctx context.Context, data interface{}, config map[string]interface{}) (*FieldValidationResult, error)
	
	// GetSupportedTypes returns supported data types
	GetSupportedTypes() []string
	
	// GetConfigSchema returns the configuration schema
	GetConfigSchema() *ValidatorConfigSchema
}

// Data structures

// MigrationStatus represents the current status of a migration
type MigrationStatus struct {
	JobID               uuid.UUID                    `json:"job_id"`
	TenantID            uuid.UUID                    `json:"tenant_id"`
	Status              entity.MigrationJobStatus   `json:"status"`
	Progress            *MigrationProgress          `json:"progress"`
	CurrentStage        string                       `json:"current_stage"`
	StartedAt           *time.Time                   `json:"started_at,omitempty"`
	CompletedAt         *time.Time                   `json:"completed_at,omitempty"`
	EstimatedCompletion *time.Time                   `json:"estimated_completion,omitempty"`
	LastUpdated         time.Time                    `json:"last_updated"`
	ErrorCount          int32                        `json:"error_count"`
	WarningCount        int32                        `json:"warning_count"`
	LastError           *entity.MigrationError      `json:"last_error,omitempty"`
	WorkflowID          *uuid.UUID                   `json:"workflow_id,omitempty"`
	Metrics             *MigrationMetrics           `json:"metrics,omitempty"`
}

// MigrationProgress provides detailed progress information
type MigrationProgress struct {
	entity.MigrationProgress
	
	// Extended progress information
	StageProgress         map[string]*StageProgress    `json:"stage_progress"`
	CurrentBatch          *BatchProgress               `json:"current_batch,omitempty"`
	Throughput            *ThroughputMetrics           `json:"throughput"`
	QualityMetrics        *QualityMetrics              `json:"quality_metrics"`
	PerformanceMetrics    *PerformanceMetrics          `json:"performance_metrics"`
	ResourceUtilization   *ResourceUtilization         `json:"resource_utilization"`
}

// MigrationWorkflow represents a complete migration workflow
type MigrationWorkflow struct {
	ID                    uuid.UUID                    `json:"id"`
	TenantID              uuid.UUID                    `json:"tenant_id"`
	MigrationJobID        uuid.UUID                    `json:"migration_job_id"`
	Name                  string                       `json:"name"`
	Description           string                       `json:"description,omitempty"`
	
	// Workflow definition
	Stages                []WorkflowStageConfig        `json:"stages"`
	Dependencies          map[string][]string          `json:"dependencies"`
	Configuration         map[string]interface{}       `json:"configuration"`
	
	// Execution settings
	MaxRetries            int32                        `json:"max_retries"`
	RetryDelay            time.Duration                `json:"retry_delay"`
	Timeout               time.Duration                `json:"timeout"`
	ParallelExecution     bool                         `json:"parallel_execution"`
	MaxParallelStages     int32                        `json:"max_parallel_stages"`
	
	// Security and compliance
	SecurityClearance     string                       `json:"security_clearance"`
	ComplianceFrameworks  []string                     `json:"compliance_frameworks"`
	AuditRequired         bool                         `json:"audit_required"`
	
	// Metadata
	CreatedBy             uuid.UUID                    `json:"created_by"`
	CreatedAt             time.Time                    `json:"created_at"`
	UpdatedAt             time.Time                    `json:"updated_at"`
	Version               int32                        `json:"version"`
}

// WorkflowStageConfig represents the configuration for a workflow stage
type WorkflowStageConfig struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	Description           string                       `json:"description,omitempty"`
	Configuration         map[string]interface{}       `json:"configuration"`
	Dependencies          []string                     `json:"dependencies"`
	RetryPolicy           *RetryPolicy                 `json:"retry_policy,omitempty"`
	Timeout               *time.Duration               `json:"timeout,omitempty"`
	Required              bool                         `json:"required"`
	Order                 int32                        `json:"order"`
}

// SchemaMapping represents a mapping between source and target schemas
type SchemaMapping struct {
	ID                    uuid.UUID                    `json:"id"`
	TenantID              uuid.UUID                    `json:"tenant_id"`
	Name                  string                       `json:"name"`
	Description           string                       `json:"description,omitempty"`
	
	// Source information
	SourceVendor          entity.SourceSystemVendor   `json:"source_vendor"`
	SourceSystemType      entity.SourceSystemType     `json:"source_system_type"`
	SourceDataType        entity.DataType              `json:"source_data_type"`
	SourceSchema          *DataSchema                  `json:"source_schema"`
	
	// Target information
	TargetDataType        entity.DataType              `json:"target_data_type"`
	TargetSchema          *DataSchema                  `json:"target_schema"`
	
	// Mapping configuration
	FieldMappings         []FieldMapping               `json:"field_mappings"`
	TransformationRules   []TransformationRule         `json:"transformation_rules"`
	ValidationRules       []ValidationRule             `json:"validation_rules"`
	DefaultValues         map[string]interface{}       `json:"default_values"`
	
	// Settings
	StrictMode            bool                         `json:"strict_mode"`
	IgnoreUnmappedFields  bool                         `json:"ignore_unmapped_fields"`
	PreserveOriginalData  bool                         `json:"preserve_original_data"`
	
	// Audit fields
	CreatedBy             uuid.UUID                    `json:"created_by"`
	CreatedAt             time.Time                    `json:"created_at"`
	UpdatedAt             time.Time                    `json:"updated_at"`
	Version               int32                        `json:"version"`
}

// TransformationPipeline represents a data transformation pipeline
type TransformationPipeline struct {
	ID                    uuid.UUID                    `json:"id"`
	TenantID              uuid.UUID                    `json:"tenant_id"`
	Name                  string                       `json:"name"`
	Description           string                       `json:"description,omitempty"`
	
	// Pipeline configuration
	DataType              entity.DataType              `json:"data_type"`
	InputSchema           *DataSchema                  `json:"input_schema"`
	OutputSchema          *DataSchema                  `json:"output_schema"`
	
	// Transformation steps
	Steps                 []TransformationStep         `json:"steps"`
	Configuration         map[string]interface{}       `json:"configuration"`
	
	// Processing settings
	BatchSize             int32                        `json:"batch_size"`
	ParallelProcessing    bool                         `json:"parallel_processing"`
	MaxWorkers            int32                        `json:"max_workers"`
	
	// Error handling
	ErrorHandling         ErrorHandlingPolicy          `json:"error_handling"`
	MaxErrors             int32                        `json:"max_errors"`
	SkipInvalidRecords    bool                         `json:"skip_invalid_records"`
	
	// Audit fields
	CreatedBy             uuid.UUID                    `json:"created_by"`
	CreatedAt             time.Time                    `json:"created_at"`
	UpdatedAt             time.Time                    `json:"updated_at"`
	Version               int32                        `json:"version"`
}

// ValidationRules represents validation rules for data
type ValidationRules struct {
	ID                    uuid.UUID                    `json:"id"`
	TenantID              uuid.UUID                    `json:"tenant_id"`
	Name                  string                       `json:"name"`
	Description           string                       `json:"description,omitempty"`
	
	// Rule configuration
	DataType              entity.DataType              `json:"data_type"`
	Schema                *DataSchema                  `json:"schema"`
	Rules                 []ValidationRule             `json:"rules"`
	
	// Validation settings
	StrictMode            bool                         `json:"strict_mode"`
	FailFast              bool                         `json:"fail_fast"`
	MaxErrors             int32                        `json:"max_errors"`
	
	// Compliance
	ComplianceFrameworks  []string                     `json:"compliance_frameworks"`
	SecurityRequirements  []string                     `json:"security_requirements"`
	
	// Audit fields
	CreatedBy             uuid.UUID                    `json:"created_by"`
	CreatedAt             time.Time                    `json:"created_at"`
	UpdatedAt             time.Time                    `json:"updated_at"`
	Version               int32                        `json:"version"`
}

// Supporting data structures

// DataSchema represents a data schema
type DataSchema struct {
	Name                  string                       `json:"name"`
	Version               string                       `json:"version"`
	Description           string                       `json:"description,omitempty"`
	Fields                []SchemaField                `json:"fields"`
	RequiredFields        []string                     `json:"required_fields"`
	OptionalFields        []string                     `json:"optional_fields"`
	Constraints           []SchemaConstraint           `json:"constraints"`
	Metadata              map[string]interface{}       `json:"metadata,omitempty"`
}

// SchemaField represents a field in a schema
type SchemaField struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	Format                string                       `json:"format,omitempty"`
	Description           string                       `json:"description,omitempty"`
	Required              bool                         `json:"required"`
	DefaultValue          interface{}                  `json:"default_value,omitempty"`
	MinLength             *int32                       `json:"min_length,omitempty"`
	MaxLength             *int32                       `json:"max_length,omitempty"`
	MinValue              *float64                     `json:"min_value,omitempty"`
	MaxValue              *float64                     `json:"max_value,omitempty"`
	Pattern               string                       `json:"pattern,omitempty"`
	AllowedValues         []interface{}                `json:"allowed_values,omitempty"`
	Tags                  []string                     `json:"tags,omitempty"`
	Metadata              map[string]interface{}       `json:"metadata,omitempty"`
}

// SchemaConstraint represents a schema constraint
type SchemaConstraint struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	Fields                []string                     `json:"fields"`
	Expression            string                       `json:"expression,omitempty"`
	ErrorMessage          string                       `json:"error_message,omitempty"`
}

// FieldMapping represents a mapping between source and target fields
type FieldMapping struct {
	SourceField           string                       `json:"source_field"`
	TargetField           string                       `json:"target_field"`
	DataType              string                       `json:"data_type,omitempty"`
	Required              bool                         `json:"required"`
	DefaultValue          interface{}                  `json:"default_value,omitempty"`
	TransformationRule    string                       `json:"transformation_rule,omitempty"`
	ValidationRules       []string                     `json:"validation_rules,omitempty"`
	Description           string                       `json:"description,omitempty"`
}

// TransformationRule represents a data transformation rule
type TransformationRule struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	Expression            string                       `json:"expression"`
	Configuration         map[string]interface{}       `json:"configuration,omitempty"`
	ApplyToFields         []string                     `json:"apply_to_fields,omitempty"`
	Condition             string                       `json:"condition,omitempty"`
	Order                 int32                        `json:"order"`
	Description           string                       `json:"description,omitempty"`
}

// ValidationRule represents a data validation rule  
type ValidationRule struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	Field                 string                       `json:"field"`
	Expression            string                       `json:"expression,omitempty"`
	Configuration         map[string]interface{}       `json:"configuration,omitempty"`
	ErrorMessage          string                       `json:"error_message,omitempty"`
	Severity              string                       `json:"severity"`
	Required              bool                         `json:"required"`
	Order                 int32                        `json:"order"`
}

// TransformationStep represents a step in a transformation pipeline
type TransformationStep struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	TransformerName       string                       `json:"transformer_name"`
	Configuration         map[string]interface{}       `json:"configuration"`
	Condition             string                       `json:"condition,omitempty"`
	OnError               string                       `json:"on_error"`
	Order                 int32                        `json:"order"`
	Description           string                       `json:"description,omitempty"`
}

// Result and status structures

// ValidationResult represents validation results
type ValidationResult struct {
	IsValid               bool                         `json:"is_valid"`
	Score                 float64                      `json:"score"`
	Errors                []ValidationError            `json:"errors,omitempty"`
	Warnings              []ValidationWarning          `json:"warnings,omitempty"`
	FieldResults          map[string]*FieldValidationResult `json:"field_results,omitempty"`
	Summary               *ValidationSummary           `json:"summary,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field                 string                       `json:"field"`
	RuleName              string                       `json:"rule_name"`
	ErrorType             string                       `json:"error_type"`
	Message               string                       `json:"message"`
	Value                 interface{}                  `json:"value,omitempty"`
	ExpectedValue         interface{}                  `json:"expected_value,omitempty"`
	Severity              string                       `json:"severity"`
	Path                  string                       `json:"path,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field                 string                       `json:"field"`
	RuleName              string                       `json:"rule_name"`
	WarningType           string                       `json:"warning_type"`
	Message               string                       `json:"message"`
	Value                 interface{}                  `json:"value,omitempty"`
	Recommendation        string                       `json:"recommendation,omitempty"`
	Path                  string                       `json:"path,omitempty"`
}

// TransformationResult represents transformation results
type TransformationResult struct {
	Success               bool                         `json:"success"`
	ProcessedRecords      int64                        `json:"processed_records"`
	TransformedRecords    int64                        `json:"transformed_records"`
	SkippedRecords        int64                        `json:"skipped_records"`
	ErrorCount            int64                        `json:"error_count"`
	
	// Results
	TransformedData       []map[string]interface{}     `json:"transformed_data,omitempty"`
	Errors                []TransformationError        `json:"errors,omitempty"`
	Warnings              []TransformationWarning      `json:"warnings,omitempty"`
	
	// Metrics
	ProcessingTime        time.Duration                `json:"processing_time"`
	ThroughputRate        float64                      `json:"throughput_rate"`
	QualityScore          float64                      `json:"quality_score"`
	
	// Metadata
	PipelineID            uuid.UUID                    `json:"pipeline_id"`
	ExecutionID           uuid.UUID                    `json:"execution_id"`
	Timestamp             time.Time                    `json:"timestamp"`
}

// WorkflowResult represents workflow execution results
type WorkflowResult struct {
	WorkflowID            uuid.UUID                    `json:"workflow_id"`
	Success               bool                         `json:"success"`
	Status                WorkflowStatus               `json:"status"`
	StageResults          map[string]*StageResult      `json:"stage_results"`
	TotalDuration         time.Duration                `json:"total_duration"`
	ErrorCount            int32                        `json:"error_count"`
	WarningCount          int32                        `json:"warning_count"`
	CompletedAt           time.Time                    `json:"completed_at"`
}

// Additional supporting structures
type WorkflowStatus string
const (
	WorkflowStatusPending   WorkflowStatus = "pending"
	WorkflowStatusRunning   WorkflowStatus = "running"
	WorkflowStatusCompleted WorkflowStatus = "completed"
	WorkflowStatusFailed    WorkflowStatus = "failed"
	WorkflowStatusCancelled WorkflowStatus = "cancelled"
)

type StageProgress struct {
	StageName             string                       `json:"stage_name"`
	Status                string                       `json:"status"`
	Progress              float64                      `json:"progress"`
	StartedAt             *time.Time                   `json:"started_at,omitempty"`
	CompletedAt           *time.Time                   `json:"completed_at,omitempty"`
	Duration              *time.Duration               `json:"duration,omitempty"`
	ErrorCount            int32                        `json:"error_count"`
	RecordsProcessed      int64                        `json:"records_processed"`
}

type BatchProgress struct {
	BatchID               string                       `json:"batch_id"`
	TotalBatches          int64                        `json:"total_batches"`
	ProcessedBatches      int64                        `json:"processed_batches"`
	CurrentBatchSize      int32                        `json:"current_batch_size"`
	StartedAt             time.Time                    `json:"started_at"`
	EstimatedCompletion   *time.Time                   `json:"estimated_completion,omitempty"`
}

// Additional metrics and utility structures
type ThroughputMetrics struct {
	RecordsPerSecond      float64                      `json:"records_per_second"`
	BytesPerSecond        float64                      `json:"bytes_per_second"`
	BatchesPerMinute      float64                      `json:"batches_per_minute"`
	AverageBatchSize      float64                      `json:"average_batch_size"`
}

type QualityMetrics struct {
	OverallScore          float64                      `json:"overall_score"`
	CompletenessScore     float64                      `json:"completeness_score"`
	AccuracyScore         float64                      `json:"accuracy_score"`
	ConsistencyScore      float64                      `json:"consistency_score"`
	ValidityScore         float64                      `json:"validity_score"`
	UniquenessScore       float64                      `json:"uniqueness_score"`
}

type PerformanceMetrics struct {
	CPUUsage              float64                      `json:"cpu_usage"`
	MemoryUsage           float64                      `json:"memory_usage"`
	DiskIORate            float64                      `json:"disk_io_rate"`
	NetworkIORate         float64                      `json:"network_io_rate"`
	AverageLatency        time.Duration                `json:"average_latency"`
}

type ResourceUtilization struct {
	ActiveWorkers         int32                        `json:"active_workers"`
	QueuedTasks           int64                        `json:"queued_tasks"`
	CompletedTasks        int64                        `json:"completed_tasks"`
	FailedTasks           int64                        `json:"failed_tasks"`
	MemoryAllocated       int64                        `json:"memory_allocated"`
	DiskSpaceUsed         int64                        `json:"disk_space_used"`
}

type MigrationMetrics struct {
	StartTime             time.Time                    `json:"start_time"`
	EndTime               *time.Time                   `json:"end_time,omitempty"`
	TotalDuration         *time.Duration               `json:"total_duration,omitempty"`
	DataTransferred       int64                        `json:"data_transferred"`
	RecordsExtracted      int64                        `json:"records_extracted"`
	RecordsTransformed    int64                        `json:"records_transformed"`
	RecordsValidated      int64                        `json:"records_validated"`
	RecordsLoaded         int64                        `json:"records_loaded"`
	ErrorRate             float64                      `json:"error_rate"`
	SuccessRate           float64                      `json:"success_rate"`
}

// Configuration and policy structures
type RetryPolicy struct {
	MaxRetries            int32                        `json:"max_retries"`
	RetryDelay            time.Duration                `json:"retry_delay"`
	BackoffMultiplier     float64                      `json:"backoff_multiplier"`
	MaxRetryDelay         time.Duration                `json:"max_retry_delay"`
	RetryableErrors       []string                     `json:"retryable_errors"`
}

type ErrorHandlingPolicy string
const (
	ErrorHandlingStop     ErrorHandlingPolicy = "stop"
	ErrorHandlingSkip     ErrorHandlingPolicy = "skip"
	ErrorHandlingRetry    ErrorHandlingPolicy = "retry"
	ErrorHandlingLog      ErrorHandlingPolicy = "log"
)

type QualityAnalysisConfig struct {
	EnableProfiling       bool                         `json:"enable_profiling"`
	EnableStatistics      bool                         `json:"enable_statistics"`
	EnableDuplicateCheck  bool                         `json:"enable_duplicate_check"`
	EnableNullCheck       bool                         `json:"enable_null_check"`
	EnableFormatCheck     bool                         `json:"enable_format_check"`
	SampleSize            int64                        `json:"sample_size"`
	MaxAnalysisTime       time.Duration                `json:"max_analysis_time"`
}

// Additional result and status structures
type StageInput struct {
	Data                  []map[string]interface{}     `json:"data"`
	Configuration         map[string]interface{}       `json:"configuration"`
	Context               map[string]interface{}       `json:"context"`
	WorkflowID            uuid.UUID                    `json:"workflow_id"`
	StageID               string                       `json:"stage_id"`
}

type StageOutput struct {
	Data                  []map[string]interface{}     `json:"data"`
	Metadata              map[string]interface{}       `json:"metadata"`
	Metrics               map[string]interface{}       `json:"metrics"`
	Success               bool                         `json:"success"`
	Errors                []error                      `json:"errors,omitempty"`
	Warnings              []string                     `json:"warnings,omitempty"`
}

type StageResult struct {
	StageName             string                       `json:"stage_name"`
	Success               bool                         `json:"success"`
	Duration              time.Duration                `json:"duration"`
	RecordsProcessed      int64                        `json:"records_processed"`
	ErrorCount            int32                        `json:"error_count"`
	WarningCount          int32                        `json:"warning_count"`
	Output                *StageOutput                 `json:"output,omitempty"`
	Metrics               map[string]interface{}       `json:"metrics,omitempty"`
}

type StageMetadata struct {
	Name                  string                       `json:"name"`
	Description           string                       `json:"description"`
	Version               string                       `json:"version"`
	Author                string                       `json:"author"`
	Category              string                       `json:"category"`
	Tags                  []string                     `json:"tags"`
	InputSchema           *DataSchema                  `json:"input_schema,omitempty"`
	OutputSchema          *DataSchema                  `json:"output_schema,omitempty"`
	ConfigurationSchema   *DataSchema                  `json:"configuration_schema,omitempty"`
	Dependencies          []string                     `json:"dependencies"`
	Requirements          []string                     `json:"requirements"`
}

type TransformerSchema struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	Description           string                       `json:"description"`
	Fields                []SchemaField                `json:"fields"`
	Required              []string                     `json:"required"`
	Examples              []interface{}                `json:"examples,omitempty"`
}

type ValidatorConfigSchema struct {
	Name                  string                       `json:"name"`
	Type                  string                       `json:"type"`
	Description           string                       `json:"description"`
	Properties            map[string]*SchemaField     `json:"properties"`
	Required              []string                     `json:"required"`
	Examples              []map[string]interface{}     `json:"examples,omitempty"`
}

type FieldValidationResult struct {
	Field                 string                       `json:"field"`
	IsValid               bool                         `json:"is_valid"`
	Score                 float64                      `json:"score"`
	Errors                []ValidationError            `json:"errors,omitempty"`
	Warnings              []ValidationWarning          `json:"warnings,omitempty"`
	Value                 interface{}                  `json:"value,omitempty"`
	TransformedValue      interface{}                  `json:"transformed_value,omitempty"`
}

type ValidationSummary struct {
	TotalFields           int32                        `json:"total_fields"`
	ValidFields           int32                        `json:"valid_fields"`
	InvalidFields         int32                        `json:"invalid_fields"`
	FieldsWithWarnings    int32                        `json:"fields_with_warnings"`
	OverallScore          float64                      `json:"overall_score"`
	ComplianceStatus      string                       `json:"compliance_status"`
	RecommendedActions    []string                     `json:"recommended_actions,omitempty"`
}

type TransformationError struct {
	RecordIndex           int64                        `json:"record_index"`
	Field                 string                       `json:"field"`
	StepName              string                       `json:"step_name"`
	ErrorType             string                       `json:"error_type"`
	Message               string                       `json:"message"`
	OriginalValue         interface{}                  `json:"original_value,omitempty"`
	StackTrace            string                       `json:"stack_trace,omitempty"`
}

type TransformationWarning struct {
	RecordIndex           int64                        `json:"record_index"`
	Field                 string                       `json:"field"`
	StepName              string                       `json:"step_name"`
	WarningType           string                       `json:"warning_type"`
	Message               string                       `json:"message"`
	Recommendation        string                       `json:"recommendation,omitempty"`
}

type DataQualityReport struct {
	ReportID              uuid.UUID                    `json:"report_id"`
	TenantID              uuid.UUID                    `json:"tenant_id"`
	DataType              entity.DataType              `json:"data_type"`
	
	// Summary metrics
	TotalRecords          int64                        `json:"total_records"`
	AnalyzedRecords       int64                        `json:"analyzed_records"`
	QualityScore          *QualityMetrics              `json:"quality_score"`
	
	// Detailed analysis
	FieldAnalysis         map[string]*FieldAnalysis    `json:"field_analysis"`
	PatternAnalysis       *PatternAnalysis             `json:"pattern_analysis,omitempty"`
	StatisticalAnalysis   *StatisticalAnalysis         `json:"statistical_analysis,omitempty"`
	
	// Issues and recommendations
	QualityIssues         []QualityIssue               `json:"quality_issues"`
	Recommendations       []QualityRecommendation      `json:"recommendations"`
	
	// Metadata
	AnalysisConfig        *QualityAnalysisConfig       `json:"analysis_config"`
	GeneratedAt           time.Time                    `json:"generated_at"`
	ProcessingTime        time.Duration                `json:"processing_time"`
}

type FieldAnalysis struct {
	FieldName             string                       `json:"field_name"`
	DataType              string                       `json:"data_type"`
	ValueCount            int64                        `json:"value_count"`
	UniqueValues          int64                        `json:"unique_values"`
	NullValues            int64                        `json:"null_values"`
	BlankValues           int64                        `json:"blank_values"`
	MinLength             int32                        `json:"min_length"`
	MaxLength             int32                        `json:"max_length"`
	AvgLength             float64                      `json:"avg_length"`
	CommonValues          []ValueFrequency             `json:"common_values,omitempty"`
	FormatPatterns        []PatternFrequency           `json:"format_patterns,omitempty"`
	QualityScore          float64                      `json:"quality_score"`
}

type ValueFrequency struct {
	Value                 interface{}                  `json:"value"`
	Frequency             int64                        `json:"frequency"`
	Percentage            float64                      `json:"percentage"`
}

type PatternFrequency struct {
	Pattern               string                       `json:"pattern"`
	Frequency             int64                        `json:"frequency"`
	Percentage            float64                      `json:"percentage"`
	Example               string                       `json:"example,omitempty"`
}

type PatternAnalysis struct {
	DetectedPatterns      []DataPattern                `json:"detected_patterns"`
	AnomalousRecords      []AnomalousRecord            `json:"anomalous_records,omitempty"`
	ConsistencyScore      float64                      `json:"consistency_score"`
}

type DataPattern struct {
	Name                  string                       `json:"name"`
	Description           string                       `json:"description"`
	Pattern               string                       `json:"pattern"`
	Confidence            float64                      `json:"confidence"`
	Coverage              float64                      `json:"coverage"`
	Examples              []string                     `json:"examples,omitempty"`
}

type AnomalousRecord struct {
	RecordIndex           int64                        `json:"record_index"`
	Field                 string                       `json:"field"`
	Value                 interface{}                  `json:"value"`
	AnomalyType           string                       `json:"anomaly_type"`
	Confidence            float64                      `json:"confidence"`
	Description           string                       `json:"description"`
}

type StatisticalAnalysis struct {
	NumericFields         map[string]*NumericStats     `json:"numeric_fields,omitempty"`
	DateFields            map[string]*DateStats         `json:"date_fields,omitempty"`
	StringFields          map[string]*StringStats       `json:"string_fields,omitempty"`
	CorrelationMatrix     map[string]map[string]float64 `json:"correlation_matrix,omitempty"`
}

type NumericStats struct {
	Count                 int64                        `json:"count"`
	Min                   float64                      `json:"min"`
	Max                   float64                      `json:"max"`
	Mean                  float64                      `json:"mean"`
	Median                float64                      `json:"median"`
	StandardDeviation     float64                      `json:"standard_deviation"`
	Variance              float64                      `json:"variance"`
	Percentiles           map[string]float64           `json:"percentiles"`
	Outliers              []float64                    `json:"outliers,omitempty"`
}

type DateStats struct {
	Count                 int64                        `json:"count"`
	EarliestDate          time.Time                    `json:"earliest_date"`
	LatestDate            time.Time                    `json:"latest_date"`
	DateRange             time.Duration                `json:"date_range"`
	CommonFormats         []PatternFrequency           `json:"common_formats"`
	TimeZones             []string                     `json:"time_zones,omitempty"`
}

type StringStats struct {
	Count                 int64                        `json:"count"`
	MinLength             int32                        `json:"min_length"`
	MaxLength             int32                        `json:"max_length"`
	AvgLength             float64                      `json:"avg_length"`
	Encoding              string                       `json:"encoding"`
	Languages             []string                     `json:"languages,omitempty"`
	SpecialCharacters     []string                     `json:"special_characters,omitempty"`
}

type QualityIssue struct {
	Type                  string                       `json:"type"`
	Severity              string                       `json:"severity"`
	Field                 string                       `json:"field,omitempty"`
	Description           string                       `json:"description"`
	AffectedRecords       int64                        `json:"affected_records"`
	Impact                string                       `json:"impact"`
	Examples              []interface{}                `json:"examples,omitempty"`
}

type QualityRecommendation struct {
	Type                  string                       `json:"type"`
	Priority              string                       `json:"priority"`
	Field                 string                       `json:"field,omitempty"`
	Description           string                       `json:"description"`
	Action                string                       `json:"action"`
	ExpectedImprovement   string                       `json:"expected_improvement"`
	Implementation        string                       `json:"implementation,omitempty"`
}