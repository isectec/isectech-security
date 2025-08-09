package ingestion

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// EventType defines the types of security events
type EventType string

const (
	// Security Events
	EventTypeEndpointSecurity    EventType = "endpoint_security"
	EventTypeNetworkSecurity     EventType = "network_security"
	EventTypeWebSecurity         EventType = "web_security"
	EventTypeCloudSecurity       EventType = "cloud_security"
	EventTypeEmailSecurity       EventType = "email_security"
	EventTypeVulnerability       EventType = "vulnerability"
	EventTypeThreatIntelligence  EventType = "threat_intelligence"
	EventTypeCompliance          EventType = "compliance"
	EventTypeIncident            EventType = "incident"
	EventTypeAuthentication      EventType = "authentication"
	EventTypeAuthorization       EventType = "authorization"
	EventTypeDataLoss            EventType = "data_loss"
	EventTypeAnomalyDetection    EventType = "anomaly_detection"
	EventTypeBehaviorAnalysis    EventType = "behavior_analysis"
	EventTypeForensics           EventType = "forensics"

	// System Events
	EventTypeAgent               EventType = "agent"
	EventTypeHeartbeat           EventType = "heartbeat"
	EventTypeConfiguration       EventType = "configuration"
	EventTypeSystem              EventType = "system"
	EventTypeAudit               EventType = "audit"
)

// EventSeverity defines event criticality levels
type EventSeverity string

const (
	SeverityCritical EventSeverity = "critical"
	SeverityHigh     EventSeverity = "high"
	SeverityMedium   EventSeverity = "medium"
	SeverityLow      EventSeverity = "low"
	SeverityInfo     EventSeverity = "info"
)

// EventStatus defines processing status
type EventStatus string

const (
	StatusReceived   EventStatus = "received"
	StatusValidated  EventStatus = "validated"
	StatusEnriched   EventStatus = "enriched"
	StatusCorrelated EventStatus = "correlated"
	StatusProcessed  EventStatus = "processed"
	StatusArchived   EventStatus = "archived"
	StatusFailed     EventStatus = "failed"
)

// SecurityEvent represents the unified event structure for iSECTECH
type SecurityEvent struct {
	// Core Event Metadata
	ID           string                 `json:"id" validate:"required"`
	TenantID     string                 `json:"tenant_id" validate:"required"`
	Type         EventType              `json:"type" validate:"required"`
	Severity     EventSeverity          `json:"severity" validate:"required"`
	Status       EventStatus            `json:"status" validate:"required"`
	Timestamp    time.Time              `json:"timestamp" validate:"required"`
	ReceivedAt   time.Time              `json:"received_at"`
	ProcessedAt  *time.Time             `json:"processed_at,omitempty"`
	
	// Source Information
	Source       *EventSource           `json:"source" validate:"required"`
	Agent        *AgentInfo             `json:"agent,omitempty"`
	
	// Event Content
	Title        string                 `json:"title" validate:"required"`
	Description  string                 `json:"description"`
	Category     string                 `json:"category"`
	Tags         []string               `json:"tags,omitempty"`
	
	// Security Context
	Assets       []AssetReference       `json:"assets,omitempty"`
	Indicators   []ThreatIndicator      `json:"indicators,omitempty"`
	MITRE        *MITREMapping          `json:"mitre,omitempty"`
	RiskScore    float64                `json:"risk_score"`
	Confidence   float64                `json:"confidence"`
	
	// Technical Details
	Raw          map[string]interface{} `json:"raw,omitempty"`
	Normalized   map[string]interface{} `json:"normalized,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
	
	// Correlation and Enrichment
	CorrelationID string                `json:"correlation_id,omitempty"`
	ParentID      string                `json:"parent_id,omitempty"`
	ChildIDs      []string              `json:"child_ids,omitempty"`
	RelatedEvents []string              `json:"related_events,omitempty"`
	
	// Processing Metadata
	Pipeline     *ProcessingPipeline    `json:"pipeline,omitempty"`
	Checksums    *EventChecksums        `json:"checksums,omitempty"`
	Encryption   *EncryptionMetadata    `json:"encryption,omitempty"`
	
	// Compliance and Audit
	Compliance   []ComplianceTag        `json:"compliance,omitempty"`
	Retention    *RetentionPolicy       `json:"retention,omitempty"`
	
	// Performance Tracking
	Metrics      *EventMetrics          `json:"metrics,omitempty"`
}

// EventSource defines the origin of the event
type EventSource struct {
	ID           string                 `json:"id" validate:"required"`
	Type         string                 `json:"type" validate:"required"` // agent, api, integration, import
	Name         string                 `json:"name" validate:"required"`
	Version      string                 `json:"version"`
	Location     *SourceLocation        `json:"location,omitempty"`
	Vendor       string                 `json:"vendor,omitempty"`
	Product      string                 `json:"product,omitempty"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
}

// SourceLocation defines geographical and network location
type SourceLocation struct {
	Country      string  `json:"country,omitempty"`
	Region       string  `json:"region,omitempty"`
	City         string  `json:"city,omitempty"`
	Datacenter   string  `json:"datacenter,omitempty"`
	Network      string  `json:"network,omitempty"`
	IPAddress    string  `json:"ip_address,omitempty"`
	Latitude     float64 `json:"latitude,omitempty"`
	Longitude    float64 `json:"longitude,omitempty"`
}

// AgentInfo contains security agent specific information
type AgentInfo struct {
	ID           string                 `json:"id" validate:"required"`
	Version      string                 `json:"version" validate:"required"`
	Platform     string                 `json:"platform" validate:"required"`
	Architecture string                 `json:"architecture"`
	Hostname     string                 `json:"hostname"`
	InstanceID   string                 `json:"instance_id"`
	DeploymentID string                 `json:"deployment_id"`
	LastSeen     time.Time              `json:"last_seen"`
	Health       *AgentHealth           `json:"health,omitempty"`
	Capabilities []string               `json:"capabilities,omitempty"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
}

// AgentHealth represents agent operational status
type AgentHealth struct {
	Status       string    `json:"status"` // online, offline, degraded, error
	CPUUsage     float64   `json:"cpu_usage"`
	MemoryUsage  float64   `json:"memory_usage"`
	DiskUsage    float64   `json:"disk_usage"`
	NetworkLatency time.Duration `json:"network_latency"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	ErrorCount   int       `json:"error_count"`
	QueueDepth   int       `json:"queue_depth"`
}

// AssetReference links events to managed assets
type AssetReference struct {
	ID           string                 `json:"id" validate:"required"`
	Type         string                 `json:"type" validate:"required"`
	Name         string                 `json:"name"`
	Criticality  string                 `json:"criticality"`
	Owner        string                 `json:"owner,omitempty"`
	Environment  string                 `json:"environment,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatIndicator contains IoC and threat information
type ThreatIndicator struct {
	Type         string                 `json:"type" validate:"required"` // ip, domain, hash, url, etc.
	Value        string                 `json:"value" validate:"required"`
	Confidence   float64                `json:"confidence"`
	Source       string                 `json:"source"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	Tags         []string               `json:"tags,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// MITREMapping links events to MITRE ATT&CK framework
type MITREMapping struct {
	TacticID     string   `json:"tactic_id,omitempty"`
	TacticName   string   `json:"tactic_name,omitempty"`
	TechniqueID  string   `json:"technique_id,omitempty"`
	TechniqueName string  `json:"technique_name,omitempty"`
	SubTechnique string   `json:"sub_technique,omitempty"`
	Procedures   []string `json:"procedures,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Software     []string `json:"software,omitempty"`
}

// ProcessingPipeline tracks event processing journey
type ProcessingPipeline struct {
	Stages       []ProcessingStage      `json:"stages"`
	CurrentStage string                 `json:"current_stage"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Duration     time.Duration          `json:"duration"`
	Errors       []ProcessingError      `json:"errors,omitempty"`
}

// ProcessingStage represents a pipeline stage
type ProcessingStage struct {
	Name         string                 `json:"name"`
	Status       string                 `json:"status"` // pending, processing, completed, failed
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Duration     time.Duration          `json:"duration"`
	Input        map[string]interface{} `json:"input,omitempty"`
	Output       map[string]interface{} `json:"output,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ProcessingError captures pipeline errors
type ProcessingError struct {
	Stage        string    `json:"stage"`
	Code         string    `json:"code"`
	Message      string    `json:"message"`
	Details      string    `json:"details,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Retryable    bool      `json:"retryable"`
	RetryCount   int       `json:"retry_count"`
}

// EventChecksums for integrity verification
type EventChecksums struct {
	SHA256       string `json:"sha256"`
	MD5          string `json:"md5"`
	CRC32        string `json:"crc32"`
	ContentHash  string `json:"content_hash"`
}

// EncryptionMetadata for encrypted event content
type EncryptionMetadata struct {
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"key_id"`
	IV           string `json:"iv,omitempty"`
	Encrypted    bool   `json:"encrypted"`
	EncryptedFields []string `json:"encrypted_fields,omitempty"`
}

// ComplianceTag for regulatory compliance tracking
type ComplianceTag struct {
	Framework    string                 `json:"framework"` // GDPR, HIPAA, SOX, PCI-DSS, etc.
	Control      string                 `json:"control"`
	Requirement  string                 `json:"requirement"`
	Classification string               `json:"classification"`
	Sensitivity  string                 `json:"sensitivity"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// RetentionPolicy defines data lifecycle
type RetentionPolicy struct {
	Category     string    `json:"category"`
	RetainDays   int       `json:"retain_days"`
	ArchiveDays  int       `json:"archive_days"`
	DeleteAfter  time.Time `json:"delete_after"`
	LegalHold    bool      `json:"legal_hold"`
	Reason       string    `json:"reason,omitempty"`
}

// EventMetrics for performance tracking
type EventMetrics struct {
	IngestLatency    time.Duration `json:"ingest_latency"`
	ProcessLatency   time.Duration `json:"process_latency"`
	QueueTime        time.Duration `json:"queue_time"`
	StorageSize      int64         `json:"storage_size"`
	NetworkBytes     int64         `json:"network_bytes"`
	CompressionRatio float64       `json:"compression_ratio"`
	ValidationTime   time.Duration `json:"validation_time"`
	EnrichmentTime   time.Duration `json:"enrichment_time"`
}

// EventBatch represents a collection of events for batch processing
type EventBatch struct {
	ID           string           `json:"id" validate:"required"`
	TenantID     string           `json:"tenant_id" validate:"required"`
	Events       []*SecurityEvent `json:"events" validate:"required"`
	Size         int              `json:"size"`
	CreatedAt    time.Time        `json:"created_at"`
	ProcessedAt  *time.Time       `json:"processed_at,omitempty"`
	Compression  string           `json:"compression,omitempty"`
	Checksum     string           `json:"checksum"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// EventFilter defines filtering criteria for event processing
type EventFilter struct {
	TenantID     string        `json:"tenant_id,omitempty"`
	Types        []EventType   `json:"types,omitempty"`
	Severities   []EventSeverity `json:"severities,omitempty"`
	Sources      []string      `json:"sources,omitempty"`
	TimeRange    *TimeRange    `json:"time_range,omitempty"`
	Tags         []string      `json:"tags,omitempty"`
	Assets       []string      `json:"assets,omitempty"`
	Correlation  string        `json:"correlation,omitempty"`
	MinRiskScore float64       `json:"min_risk_score,omitempty"`
	MaxRiskScore float64       `json:"max_risk_score,omitempty"`
}

// TimeRange defines time boundaries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Event factory methods

// NewSecurityEvent creates a new security event with required fields
func NewSecurityEvent(tenantID string, eventType EventType, severity EventSeverity, title string, source *EventSource) *SecurityEvent {
	now := time.Now()
	return &SecurityEvent{
		ID:          uuid.New().String(),
		TenantID:    tenantID,
		Type:        eventType,
		Severity:    severity,
		Status:      StatusReceived,
		Timestamp:   now,
		ReceivedAt:  now,
		Title:       title,
		Source:      source,
		RiskScore:   0.0,
		Confidence:  1.0,
		Raw:         make(map[string]interface{}),
		Normalized:  make(map[string]interface{}),
		Context:     make(map[string]interface{}),
		Pipeline: &ProcessingPipeline{
			Stages:       []ProcessingStage{},
			CurrentStage: "ingestion",
			StartTime:    now,
		},
		Metrics: &EventMetrics{},
	}
}

// NewEventBatch creates a new event batch
func NewEventBatch(tenantID string, events []*SecurityEvent) *EventBatch {
	return &EventBatch{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		Events:    events,
		Size:      len(events),
		CreatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
}

// Event validation methods

// Validate performs comprehensive event validation
func (e *SecurityEvent) Validate() error {
	if e.ID == "" {
		return NewValidationError("id", "event ID is required")
	}
	if e.TenantID == "" {
		return NewValidationError("tenant_id", "tenant ID is required")
	}
	if e.Type == "" {
		return NewValidationError("type", "event type is required")
	}
	if e.Severity == "" {
		return NewValidationError("severity", "event severity is required")
	}
	if e.Title == "" {
		return NewValidationError("title", "event title is required")
	}
	if e.Source == nil {
		return NewValidationError("source", "event source is required")
	}
	if err := e.Source.Validate(); err != nil {
		return err
	}
	
	// Validate severity values
	validSeverities := map[EventSeverity]bool{
		SeverityCritical: true,
		SeverityHigh:     true,
		SeverityMedium:   true,
		SeverityLow:      true,
		SeverityInfo:     true,
	}
	if !validSeverities[e.Severity] {
		return NewValidationError("severity", "invalid severity value")
	}
	
	// Validate risk score range
	if e.RiskScore < 0.0 || e.RiskScore > 10.0 {
		return NewValidationError("risk_score", "risk score must be between 0.0 and 10.0")
	}
	
	// Validate confidence range
	if e.Confidence < 0.0 || e.Confidence > 1.0 {
		return NewValidationError("confidence", "confidence must be between 0.0 and 1.0")
	}
	
	return nil
}

// Validate validates event source
func (s *EventSource) Validate() error {
	if s.ID == "" {
		return NewValidationError("source.id", "source ID is required")
	}
	if s.Type == "" {
		return NewValidationError("source.type", "source type is required")
	}
	if s.Name == "" {
		return NewValidationError("source.name", "source name is required")
	}
	return nil
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// Event serialization methods

// ToJSON converts event to JSON
func (e *SecurityEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// FromJSON creates event from JSON
func FromJSON(data []byte) (*SecurityEvent, error) {
	var event SecurityEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	
	// Validate after deserialization
	if err := event.Validate(); err != nil {
		return nil, err
	}
	
	return &event, nil
}

// ToCompactJSON converts event to compact JSON (without raw data)
func (e *SecurityEvent) ToCompactJSON() ([]byte, error) {
	// Create a copy without large fields for efficient transport
	compact := *e
	compact.Raw = nil
	if len(compact.Context) > 10 {
		compact.Context = make(map[string]interface{})
		compact.Context["size"] = len(e.Context)
	}
	
	return json.Marshal(compact)
}

// Event utility methods

// IsExpired checks if event has exceeded retention policy
func (e *SecurityEvent) IsExpired() bool {
	if e.Retention == nil {
		return false
	}
	return time.Now().After(e.Retention.DeleteAfter)
}

// ShouldArchive checks if event should be archived
func (e *SecurityEvent) ShouldArchive() bool {
	if e.Retention == nil {
		return false
	}
	archiveTime := e.Timestamp.AddDate(0, 0, e.Retention.ArchiveDays)
	return time.Now().After(archiveTime)
}

// GetProcessingDuration returns total processing time
func (e *SecurityEvent) GetProcessingDuration() time.Duration {
	if e.ProcessedAt == nil {
		return time.Since(e.ReceivedAt)
	}
	return e.ProcessedAt.Sub(e.ReceivedAt)
}

// AddProcessingStage adds a new processing stage
func (e *SecurityEvent) AddProcessingStage(name string) *ProcessingStage {
	stage := ProcessingStage{
		Name:      name,
		Status:    "processing",
		StartTime: time.Now(),
	}
	
	if e.Pipeline == nil {
		e.Pipeline = &ProcessingPipeline{
			Stages:       []ProcessingStage{},
			CurrentStage: name,
			StartTime:    time.Now(),
		}
	}
	
	e.Pipeline.Stages = append(e.Pipeline.Stages, stage)
	e.Pipeline.CurrentStage = name
	
	return &e.Pipeline.Stages[len(e.Pipeline.Stages)-1]
}

// CompleteCurrentStage marks current processing stage as complete
func (e *SecurityEvent) CompleteCurrentStage() {
	if e.Pipeline == nil || len(e.Pipeline.Stages) == 0 {
		return
	}
	
	currentStage := &e.Pipeline.Stages[len(e.Pipeline.Stages)-1]
	now := time.Now()
	currentStage.EndTime = &now
	currentStage.Duration = now.Sub(currentStage.StartTime)
	currentStage.Status = "completed"
}

// AddProcessingError adds a processing error
func (e *SecurityEvent) AddProcessingError(stage, code, message string, retryable bool) {
	if e.Pipeline == nil {
		return
	}
	
	error := ProcessingError{
		Stage:     stage,
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
		Retryable: retryable,
	}
	
	e.Pipeline.Errors = append(e.Pipeline.Errors, error)
}

// CalculateChecksum calculates event integrity checksum
func (e *SecurityEvent) CalculateChecksum() error {
	// Serialize without checksums for calculation
	temp := *e
	temp.Checksums = nil
	
	data, err := json.Marshal(temp)
	if err != nil {
		return err
	}
	
	// Calculate checksums
	sha256Hash := calculateSHA256(data)
	md5Hash := calculateMD5(data)
	crc32Hash := calculateCRC32(data)
	
	e.Checksums = &EventChecksums{
		SHA256:      sha256Hash,
		MD5:         md5Hash,
		CRC32:       crc32Hash,
		ContentHash: sha256Hash, // Use SHA256 as primary content hash
	}
	
	return nil
}

// Utility functions for checksum calculation
func calculateSHA256(data []byte) string {
	// Implementation would use crypto/sha256
	return "sha256_placeholder"
}

func calculateMD5(data []byte) string {
	// Implementation would use crypto/md5
	return "md5_placeholder"
}

func calculateCRC32(data []byte) string {
	// Implementation would use hash/crc32
	return "crc32_placeholder"
}