package service

import (
	"context"
	"time"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/shared/types"
)

// EventProcessorService defines the core business logic for event processing
type EventProcessorService interface {
	// Core processing operations
	ProcessEvent(ctx context.Context, event *entity.Event) error
	ProcessEventBatch(ctx context.Context, events []*entity.Event) error
	ReprocessEvent(ctx context.Context, tenantID types.TenantID, eventID types.EventID) error
	ReprocessFailedEvents(ctx context.Context, tenantID types.TenantID, limit int) error
	
	// Event validation and normalization
	ValidateEvent(ctx context.Context, event *entity.Event) error
	NormalizeEvent(ctx context.Context, event *entity.Event) error
	EnrichEvent(ctx context.Context, event *entity.Event) error
	
	// Risk assessment
	AssessRisk(ctx context.Context, event *entity.Event) (*RiskAssessment, error)
	UpdateRiskScore(ctx context.Context, tenantID types.TenantID, eventID types.EventID, score float64, confidence float64) error
	
	// Event correlation
	CorrelatEvents(ctx context.Context, event *entity.Event) ([]*entity.Event, error)
	FindRelatedEvents(ctx context.Context, tenantID types.TenantID, eventID types.EventID) ([]*entity.Event, error)
	CreateEventChain(ctx context.Context, parentEvent *entity.Event, childEvents []*entity.Event) error
	
	// Asset correlation
	CorrelateWithAssets(ctx context.Context, event *entity.Event) error
	GetAssetEvents(ctx context.Context, tenantID types.TenantID, assetID types.AssetID, timeRange TimeRange) ([]*entity.Event, error)
	
	// User correlation
	CorrelateWithUsers(ctx context.Context, event *entity.Event) error
	GetUserEvents(ctx context.Context, tenantID types.TenantID, userID types.UserID, timeRange TimeRange) ([]*entity.Event, error)
	
	// Pattern detection
	DetectPatterns(ctx context.Context, events []*entity.Event) ([]*Pattern, error)
	DetectAnomalies(ctx context.Context, tenantID types.TenantID, timeRange TimeRange) ([]*Anomaly, error)
	
	// Event aggregation
	AggregateEvents(ctx context.Context, filter *entity.EventFilter, aggregationType AggregationType) (*AggregationResult, error)
	GetEventTimeline(ctx context.Context, tenantID types.TenantID, timeRange TimeRange, granularity time.Duration) ([]*TimelinePoint, error)
	
	// Compliance and retention
	ApplyComplianceRules(ctx context.Context, event *entity.Event) error
	GetComplianceViolations(ctx context.Context, tenantID types.TenantID, timeRange TimeRange) ([]*ComplianceViolation, error)
	ApplyRetentionPolicy(ctx context.Context, tenantID types.TenantID, policy RetentionPolicy) (*RetentionResult, error)
	
	// Event lifecycle management
	ArchiveEvent(ctx context.Context, tenantID types.TenantID, eventID types.EventID) error
	ArchiveOldEvents(ctx context.Context, tenantID types.TenantID, olderThan time.Time) (*ArchiveResult, error)
	PurgeEvent(ctx context.Context, tenantID types.TenantID, eventID types.EventID) error
	
	// Performance and monitoring
	GetProcessingStats(ctx context.Context, tenantID types.TenantID, timeRange TimeRange) (*ProcessingStats, error)
	GetSystemHealth(ctx context.Context) (*SystemHealth, error)
	GetThroughputMetrics(ctx context.Context, tenantID types.TenantID, timeRange TimeRange) (*ThroughputMetrics, error)
}

// RiskAssessment represents the result of risk assessment
type RiskAssessment struct {
	EventID     types.EventID `json:"event_id"`
	Score       float64       `json:"score"`
	Confidence  float64       `json:"confidence"`
	Factors     []RiskFactor  `json:"factors"`
	Severity    types.Severity `json:"severity"`
	Reasoning   string        `json:"reasoning"`
	AssessedAt  time.Time     `json:"assessed_at"`
	AssessedBy  string        `json:"assessed_by"`
}

// RiskFactor represents a factor contributing to risk assessment
type RiskFactor struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	Value       float64 `json:"value"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
}

// Pattern represents a detected pattern in events
type Pattern struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        PatternType           `json:"type"`
	Confidence  float64               `json:"confidence"`
	Events      []types.EventID       `json:"events"`
	Attributes  map[string]interface{} `json:"attributes"`
	DetectedAt  time.Time             `json:"detected_at"`
	Description string                `json:"description"`
	Severity    types.Severity        `json:"severity"`
}

// PatternType represents the type of pattern
type PatternType string

const (
	PatternTypeSequential  PatternType = "sequential"
	PatternTypeConcurrent  PatternType = "concurrent"
	PatternTypeFrequency   PatternType = "frequency"
	PatternTypeBehavioral  PatternType = "behavioral"
	PatternTypeAnomaly     PatternType = "anomaly"
	PatternTypeCorrelation PatternType = "correlation"
)

// Anomaly represents a detected anomaly
type Anomaly struct {
	ID           string                 `json:"id"`
	Type         AnomalyType           `json:"type"`
	Description  string                `json:"description"`
	Severity     types.Severity        `json:"severity"`
	Confidence   float64               `json:"confidence"`
	Events       []types.EventID       `json:"events"`
	Baseline     map[string]interface{} `json:"baseline"`
	Deviation    map[string]interface{} `json:"deviation"`
	DetectedAt   time.Time             `json:"detected_at"`
	TimeRange    TimeRange             `json:"time_range"`
}

// AnomalyType represents the type of anomaly
type AnomalyType string

const (
	AnomalyTypeVolume      AnomalyType = "volume"
	AnomalyTypeFrequency   AnomalyType = "frequency"
	AnomalyTypeBehavior    AnomalyType = "behavior"
	AnomalyTypeContent     AnomalyType = "content"
	AnomalyTypeGeoLocation AnomalyType = "geo_location"
	AnomalyTypeTiming      AnomalyType = "timing"
)

// AggregationType represents the type of aggregation
type AggregationType string

const (
	AggregationTypeCount       AggregationType = "count"
	AggregationTypeSum         AggregationType = "sum"
	AggregationTypeAverage     AggregationType = "average"
	AggregationTypeMin         AggregationType = "min"
	AggregationTypeMax         AggregationType = "max"
	AggregationTypeGroupBy     AggregationType = "group_by"
	AggregationTypeTimeSeries  AggregationType = "time_series"
)

// AggregationResult represents the result of event aggregation
type AggregationResult struct {
	Type       AggregationType        `json:"type"`
	Value      interface{}            `json:"value"`
	GroupBy    map[string]interface{} `json:"group_by,omitempty"`
	TimeSeries []TimeSeriesPoint      `json:"time_series,omitempty"`
	Filter     *entity.EventFilter    `json:"filter"`
	ProcessedAt time.Time             `json:"processed_at"`
}

// TimeSeriesPoint represents a point in a time series
type TimeSeriesPoint struct {
	Timestamp time.Time   `json:"timestamp"`
	Value     interface{} `json:"value"`
	Count     int64       `json:"count"`
}

// TimelinePoint represents a point in an event timeline
type TimelinePoint struct {
	Timestamp    time.Time                     `json:"timestamp"`
	EventCount   int64                         `json:"event_count"`
	SeverityBreakdown map[types.Severity]int64 `json:"severity_breakdown"`
	TypeBreakdown     map[types.EventType]int64 `json:"type_breakdown"`
	AvgRiskScore float64                       `json:"avg_risk_score"`
}

// TimeRange represents a time range
type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID           string         `json:"id"`
	Rule         string         `json:"rule"`
	Framework    string         `json:"framework"`
	Severity     types.Severity `json:"severity"`
	Events       []types.EventID `json:"events"`
	Description  string         `json:"description"`
	Remediation  string         `json:"remediation"`
	DetectedAt   time.Time      `json:"detected_at"`
	Status       string         `json:"status"`
}

// RetentionPolicy represents a data retention policy
type RetentionPolicy struct {
	Name        string        `json:"name"`
	Duration    time.Duration `json:"duration"`
	Criteria    map[string]interface{} `json:"criteria"`
	Action      RetentionAction `json:"action"`
	Priority    int           `json:"priority"`
}

// RetentionAction represents the action to take for retention
type RetentionAction string

const (
	RetentionActionArchive RetentionAction = "archive"
	RetentionActionPurge   RetentionAction = "purge"
	RetentionActionCompress RetentionAction = "compress"
)

// RetentionResult represents the result of applying a retention policy
type RetentionResult struct {
	Policy       RetentionPolicy `json:"policy"`
	EventsAffected int64         `json:"events_affected"`
	DataSize     int64           `json:"data_size_bytes"`
	ProcessedAt  time.Time       `json:"processed_at"`
	Duration     time.Duration   `json:"duration"`
	Success      bool            `json:"success"`
	Error        string          `json:"error,omitempty"`
}

// ArchiveResult represents the result of archiving events
type ArchiveResult struct {
	EventsArchived int64         `json:"events_archived"`
	DataSize       int64         `json:"data_size_bytes"`
	ArchiveLocation string       `json:"archive_location"`
	ProcessedAt    time.Time     `json:"processed_at"`
	Duration       time.Duration `json:"duration"`
	Success        bool          `json:"success"`
	Error          string        `json:"error,omitempty"`
}

// ProcessingStats represents event processing statistics
type ProcessingStats struct {
	TenantID           types.TenantID `json:"tenant_id"`
	TimeRange          TimeRange      `json:"time_range"`
	EventsProcessed    int64          `json:"events_processed"`
	EventsFailed       int64          `json:"events_failed"`
	AvgProcessingTime  time.Duration  `json:"avg_processing_time"`
	MaxProcessingTime  time.Duration  `json:"max_processing_time"`
	MinProcessingTime  time.Duration  `json:"min_processing_time"`
	ThroughputPerSecond float64       `json:"throughput_per_second"`
	ErrorRate          float64        `json:"error_rate"`
	ProcessingSteps    map[string]*StepStats `json:"processing_steps"`
}

// StepStats represents statistics for a processing step
type StepStats struct {
	Step           string        `json:"step"`
	EventsProcessed int64        `json:"events_processed"`
	EventsFailed   int64         `json:"events_failed"`
	AvgDuration    time.Duration `json:"avg_duration"`
	MaxDuration    time.Duration `json:"max_duration"`
	SuccessRate    float64       `json:"success_rate"`
}

// SystemHealth represents the health of the event processing system
type SystemHealth struct {
	Status           string               `json:"status"`
	Timestamp        time.Time            `json:"timestamp"`
	Components       map[string]*ComponentHealth `json:"components"`
	EventsInQueue    int64                `json:"events_in_queue"`
	ProcessingRate   float64              `json:"processing_rate_per_second"`
	MemoryUsage      MemoryUsage          `json:"memory_usage"`
	CPUUsage         float64              `json:"cpu_usage_percent"`
	DiskUsage        DiskUsage            `json:"disk_usage"`
	ActiveGoroutines int                  `json:"active_goroutines"`
}

// ComponentHealth represents the health of a system component
type ComponentHealth struct {
	Name         string        `json:"name"`
	Status       string        `json:"status"`
	LastCheck    time.Time     `json:"last_check"`
	ResponseTime time.Duration `json:"response_time"`
	ErrorCount   int64         `json:"error_count"`
	LastError    string        `json:"last_error,omitempty"`
}

// MemoryUsage represents memory usage statistics
type MemoryUsage struct {
	Allocated      uint64  `json:"allocated_bytes"`
	TotalAllocated uint64  `json:"total_allocated_bytes"`
	System         uint64  `json:"system_bytes"`
	GCCount        uint32  `json:"gc_count"`
	UsagePercent   float64 `json:"usage_percent"`
}

// DiskUsage represents disk usage statistics
type DiskUsage struct {
	Total        uint64  `json:"total_bytes"`
	Used         uint64  `json:"used_bytes"`
	Available    uint64  `json:"available_bytes"`
	UsagePercent float64 `json:"usage_percent"`
}

// ThroughputMetrics represents throughput metrics
type ThroughputMetrics struct {
	TenantID        types.TenantID      `json:"tenant_id"`
	TimeRange       TimeRange           `json:"time_range"`
	EventsPerSecond []ThroughputPoint   `json:"events_per_second"`
	BytesPerSecond  []ThroughputPoint   `json:"bytes_per_second"`
	PeakThroughput  float64             `json:"peak_throughput"`
	AvgThroughput   float64             `json:"avg_throughput"`
	TotalEvents     int64               `json:"total_events"`
	TotalBytes      int64               `json:"total_bytes"`
}

// ThroughputPoint represents a throughput measurement point
type ThroughputPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	Value      float64   `json:"value"`
	EventCount int64     `json:"event_count"`
	ByteCount  int64     `json:"byte_count"`
}

// EventEnrichmentService defines the interface for event enrichment
type EventEnrichmentService interface {
	EnrichWithAssetInfo(ctx context.Context, event *entity.Event) error
	EnrichWithUserInfo(ctx context.Context, event *entity.Event) error
	EnrichWithGeoLocation(ctx context.Context, event *entity.Event) error
	EnrichWithThreatIntelligence(ctx context.Context, event *entity.Event) error
	EnrichWithNetworkInfo(ctx context.Context, event *entity.Event) error
}

// EventValidationService defines the interface for event validation
type EventValidationService interface {
	ValidateSchema(ctx context.Context, event *entity.Event) error
	ValidateBusinessRules(ctx context.Context, event *entity.Event) error
	ValidateDataIntegrity(ctx context.Context, event *entity.Event) error
	ValidateCompliance(ctx context.Context, event *entity.Event) error
}

// EventNormalizationService defines the interface for event normalization
type EventNormalizationService interface {
	NormalizeTimestamps(ctx context.Context, event *entity.Event) error
	NormalizeIPAddresses(ctx context.Context, event *entity.Event) error
	NormalizeFieldNames(ctx context.Context, event *entity.Event) error
	NormalizeValues(ctx context.Context, event *entity.Event) error
	ApplyFieldMappings(ctx context.Context, event *entity.Event) error
}

// RiskAssessmentService defines the interface for risk assessment
type RiskAssessmentService interface {
	CalculateRiskScore(ctx context.Context, event *entity.Event) (*RiskAssessment, error)
	UpdateRiskModel(ctx context.Context, tenantID types.TenantID, model *RiskModel) error
	GetRiskModel(ctx context.Context, tenantID types.TenantID) (*RiskModel, error)
	TrainRiskModel(ctx context.Context, tenantID types.TenantID, trainingData []*entity.Event) error
}

// RiskModel represents a risk assessment model
type RiskModel struct {
	ID           string                 `json:"id"`
	TenantID     types.TenantID        `json:"tenant_id"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Algorithm    string                 `json:"algorithm"`
	Parameters   map[string]interface{} `json:"parameters"`
	Features     []string               `json:"features"`
	Weights      map[string]float64     `json:"weights"`
	Thresholds   map[string]float64     `json:"thresholds"`
	TrainedAt    time.Time              `json:"trained_at"`
	Accuracy     float64                `json:"accuracy"`
	IsActive     bool                   `json:"is_active"`
}

// ProcessingPipeline represents an event processing pipeline
type ProcessingPipeline struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	TenantID    types.TenantID        `json:"tenant_id"`
	Steps       []ProcessingStep       `json:"steps"`
	Filters     []PipelineFilter       `json:"filters"`
	IsEnabled   bool                   `json:"is_enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Stats       *PipelineStats         `json:"stats,omitempty"`
}

// ProcessingStep represents a step in the processing pipeline
type ProcessingStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Order        int                    `json:"order"`
	Config       map[string]interface{} `json:"config"`
	IsEnabled    bool                   `json:"is_enabled"`
	OnFailure    string                 `json:"on_failure"` // "continue", "stop", "retry"
	RetryCount   int                    `json:"retry_count"`
	Timeout      time.Duration          `json:"timeout"`
}

// PipelineFilter represents a filter for pipeline execution
type PipelineFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// PipelineStats represents statistics for a processing pipeline
type PipelineStats struct {
	EventsProcessed   int64         `json:"events_processed"`
	EventsSuccessful  int64         `json:"events_successful"`
	EventsFailed      int64         `json:"events_failed"`
	AvgProcessingTime time.Duration `json:"avg_processing_time"`
	LastExecuted      time.Time     `json:"last_executed"`
	SuccessRate       float64       `json:"success_rate"`
}

// EventProcessingConfiguration represents configuration for event processing
type EventProcessingConfiguration struct {
	TenantID           types.TenantID        `json:"tenant_id"`
	MaxBatchSize       int                   `json:"max_batch_size"`
	ProcessingTimeout  time.Duration         `json:"processing_timeout"`
	RetryAttempts      int                   `json:"retry_attempts"`
	RetryBackoff       time.Duration         `json:"retry_backoff"`
	EnableEnrichment   bool                  `json:"enable_enrichment"`
	EnableRiskAssessment bool                `json:"enable_risk_assessment"`
	EnableCorrelation  bool                  `json:"enable_correlation"`
	RiskThresholds     map[string]float64    `json:"risk_thresholds"`
	ProcessingRules    []ProcessingRule      `json:"processing_rules"`
	NotificationRules  []NotificationRule    `json:"notification_rules"`
}

// ProcessingRule represents a rule for event processing
type ProcessingRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Conditions  []RuleCondition        `json:"conditions"`
	Actions     []RuleAction           `json:"actions"`
	IsEnabled   bool                   `json:"is_enabled"`
	Priority    int                    `json:"priority"`
}

// RuleCondition represents a condition in a processing rule
type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// RuleAction represents an action in a processing rule
type RuleAction struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// NotificationRule represents a rule for event notifications
type NotificationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Triggers    []NotificationTrigger  `json:"triggers"`
	Recipients  []string               `json:"recipients"`
	Template    string                 `json:"template"`
	IsEnabled   bool                   `json:"is_enabled"`
	Cooldown    time.Duration          `json:"cooldown"`
}

// NotificationTrigger represents a trigger for notifications
type NotificationTrigger struct {
	Type       string                 `json:"type"`
	Conditions []RuleCondition        `json:"conditions"`
	Threshold  map[string]interface{} `json:"threshold,omitempty"`
}