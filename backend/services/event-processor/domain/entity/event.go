package entity

import (
	"time"

	"github.com/isectech/platform/shared/types"
)

// Event represents a security event in the system
type Event struct {
	// Identity
	ID       types.EventID `json:"id" bson:"_id"`
	TenantID types.TenantID `json:"tenant_id" bson:"tenant_id"`
	
	// Core event data
	Type        types.EventType `json:"type" bson:"type"`
	Source      string          `json:"source" bson:"source"`
	Category    string          `json:"category" bson:"category"`
	Title       string          `json:"title" bson:"title"`
	Description string          `json:"description" bson:"description"`
	Severity    types.Severity  `json:"severity" bson:"severity"`
	
	// Content
	Payload    map[string]interface{} `json:"payload" bson:"payload"`
	Metadata   map[string]interface{} `json:"metadata" bson:"metadata"`
	Tags       []string               `json:"tags" bson:"tags"`
	
	// Network information
	SourceIP      string `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
	DestinationIP string `json:"destination_ip,omitempty" bson:"destination_ip,omitempty"`
	SourcePort    int    `json:"source_port,omitempty" bson:"source_port,omitempty"`
	DestinationPort int  `json:"destination_port,omitempty" bson:"destination_port,omitempty"`
	Protocol      string `json:"protocol,omitempty" bson:"protocol,omitempty"`
	
	// Asset correlation
	AssetID     *types.AssetID `json:"asset_id,omitempty" bson:"asset_id,omitempty"`
	AssetType   string         `json:"asset_type,omitempty" bson:"asset_type,omitempty"`
	AssetName   string         `json:"asset_name,omitempty" bson:"asset_name,omitempty"`
	
	// User correlation
	UserID       *types.UserID `json:"user_id,omitempty" bson:"user_id,omitempty"`
	Username     string        `json:"username,omitempty" bson:"username,omitempty"`
	UserAgent    string        `json:"user_agent,omitempty" bson:"user_agent,omitempty"`
	SessionID    string        `json:"session_id,omitempty" bson:"session_id,omitempty"`
	
	// Correlation and tracking
	CorrelationID types.CorrelationID `json:"correlation_id" bson:"correlation_id"`
	ParentEventID *types.EventID      `json:"parent_event_id,omitempty" bson:"parent_event_id,omitempty"`
	RootEventID   *types.EventID      `json:"root_event_id,omitempty" bson:"root_event_id,omitempty"`
	
	// Processing state
	Status        EventStatus    `json:"status" bson:"status"`
	ProcessingLog []ProcessingEntry `json:"processing_log" bson:"processing_log"`
	
	// Risk assessment
	RiskScore     float64         `json:"risk_score" bson:"risk_score"`
	RiskFactors   []string        `json:"risk_factors" bson:"risk_factors"`
	Confidence    float64         `json:"confidence" bson:"confidence"`
	
	// Compliance and regulatory
	ComplianceFlags []string `json:"compliance_flags" bson:"compliance_flags"`
	RetentionPolicy string   `json:"retention_policy" bson:"retention_policy"`
	
	// Timestamps
	OccurredAt  time.Time  `json:"occurred_at" bson:"occurred_at"`
	ReceivedAt  time.Time  `json:"received_at" bson:"received_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty" bson:"processed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" bson:"updated_at"`
}

// EventStatus represents the processing status of an event
type EventStatus string

const (
	EventStatusReceived   EventStatus = "received"
	EventStatusProcessing EventStatus = "processing"
	EventStatusProcessed  EventStatus = "processed"
	EventStatusEnriched   EventStatus = "enriched"
	EventStatusAnalyzed   EventStatus = "analyzed"
	EventStatusArchived   EventStatus = "archived"
	EventStatusFailed     EventStatus = "failed"
	EventStatusIgnored    EventStatus = "ignored"
)

// ProcessingEntry represents a processing step in the event lifecycle
type ProcessingEntry struct {
	Step        string                 `json:"step" bson:"step"`
	Processor   string                 `json:"processor" bson:"processor"`
	Status      string                 `json:"status" bson:"status"`
	StartedAt   time.Time              `json:"started_at" bson:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty" bson:"completed_at,omitempty"`
	Duration    *time.Duration         `json:"duration,omitempty" bson:"duration,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty" bson:"result,omitempty"`
	Error       string                 `json:"error,omitempty" bson:"error,omitempty"`
}

// EventFilter represents filtering criteria for events
type EventFilter struct {
	TenantID    *types.TenantID  `json:"tenant_id,omitempty"`
	EventTypes  []types.EventType `json:"event_types,omitempty"`
	Sources     []string         `json:"sources,omitempty"`
	Categories  []string         `json:"categories,omitempty"`
	Severities  []types.Severity `json:"severities,omitempty"`
	Statuses    []EventStatus    `json:"statuses,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
	
	// Time range
	FromTime *time.Time `json:"from_time,omitempty"`
	ToTime   *time.Time `json:"to_time,omitempty"`
	
	// Network filters
	SourceIPs      []string `json:"source_ips,omitempty"`
	DestinationIPs []string `json:"destination_ips,omitempty"`
	Protocols      []string `json:"protocols,omitempty"`
	
	// Asset filters
	AssetIDs   []types.AssetID `json:"asset_ids,omitempty"`
	AssetTypes []string        `json:"asset_types,omitempty"`
	
	// User filters
	UserIDs   []types.UserID `json:"user_ids,omitempty"`
	Usernames []string       `json:"usernames,omitempty"`
	
	// Risk filters
	MinRiskScore *float64 `json:"min_risk_score,omitempty"`
	MaxRiskScore *float64 `json:"max_risk_score,omitempty"`
	RiskFactors  []string `json:"risk_factors,omitempty"`
	
	// Search
	SearchQuery string `json:"search_query,omitempty"`
	
	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// NewEvent creates a new event
func NewEvent(tenantID types.TenantID, eventType types.EventType, source string) *Event {
	now := time.Now().UTC()
	
	return &Event{
		ID:            types.NewEventID(),
		TenantID:      tenantID,
		Type:          eventType,
		Source:        source,
		Status:        EventStatusReceived,
		CorrelationID: types.NewCorrelationID(),
		Payload:       make(map[string]interface{}),
		Metadata:      make(map[string]interface{}),
		Tags:          make([]string, 0),
		ProcessingLog: make([]ProcessingEntry, 0),
		RiskFactors:   make([]string, 0),
		ComplianceFlags: make([]string, 0),
		OccurredAt:    now,
		ReceivedAt:    now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// AddProcessingStep adds a processing step to the event
func (e *Event) AddProcessingStep(step, processor string) {
	entry := ProcessingEntry{
		Step:      step,
		Processor: processor,
		Status:    "started",
		StartedAt: time.Now().UTC(),
	}
	
	e.ProcessingLog = append(e.ProcessingLog, entry)
	e.UpdatedAt = time.Now().UTC()
}

// CompleteProcessingStep completes the latest processing step
func (e *Event) CompleteProcessingStep(result map[string]interface{}, err error) {
	if len(e.ProcessingLog) == 0 {
		return
	}
	
	// Get the latest entry
	lastIndex := len(e.ProcessingLog) - 1
	entry := &e.ProcessingLog[lastIndex]
	
	now := time.Now().UTC()
	entry.CompletedAt = &now
	duration := now.Sub(entry.StartedAt)
	entry.Duration = &duration
	entry.Result = result
	
	if err != nil {
		entry.Status = "failed"
		entry.Error = err.Error()
	} else {
		entry.Status = "completed"
	}
	
	e.UpdatedAt = now
}

// SetStatus sets the event status
func (e *Event) SetStatus(status EventStatus) {
	e.Status = status
	e.UpdatedAt = time.Now().UTC()
	
	if status == EventStatusProcessed && e.ProcessedAt == nil {
		now := time.Now().UTC()
		e.ProcessedAt = &now
	}
}

// AddTag adds a tag to the event
func (e *Event) AddTag(tag string) {
	for _, t := range e.Tags {
		if t == tag {
			return // Tag already exists
		}
	}
	e.Tags = append(e.Tags, tag)
	e.UpdatedAt = time.Now().UTC()
}

// AddRiskFactor adds a risk factor to the event
func (e *Event) AddRiskFactor(factor string) {
	for _, f := range e.RiskFactors {
		if f == factor {
			return // Factor already exists
		}
	}
	e.RiskFactors = append(e.RiskFactors, factor)
	e.UpdatedAt = time.Now().UTC()
}

// SetRiskScore sets the risk score
func (e *Event) SetRiskScore(score float64, confidence float64) {
	e.RiskScore = score
	e.Confidence = confidence
	e.UpdatedAt = time.Now().UTC()
}

// AddComplianceFlag adds a compliance flag
func (e *Event) AddComplianceFlag(flag string) {
	for _, f := range e.ComplianceFlags {
		if f == flag {
			return // Flag already exists
		}
	}
	e.ComplianceFlags = append(e.ComplianceFlags, flag)
	e.UpdatedAt = time.Now().UTC()
}

// IsProcessed returns true if the event has been processed
func (e *Event) IsProcessed() bool {
	return e.Status == EventStatusProcessed || 
		   e.Status == EventStatusEnriched || 
		   e.Status == EventStatusAnalyzed ||
		   e.Status == EventStatusArchived
}

// IsFailed returns true if the event processing failed
func (e *Event) IsFailed() bool {
	return e.Status == EventStatusFailed
}

// IsHighRisk returns true if the event is considered high risk
func (e *Event) IsHighRisk() bool {
	return e.RiskScore >= 7.0 || e.Severity == types.SeverityCritical || e.Severity == types.SeverityHigh
}

// GetProcessingDuration returns the total processing duration
func (e *Event) GetProcessingDuration() time.Duration {
	if e.ProcessedAt == nil {
		return 0
	}
	return e.ProcessedAt.Sub(e.ReceivedAt)
}

// GetLatestProcessingStep returns the latest processing step
func (e *Event) GetLatestProcessingStep() *ProcessingEntry {
	if len(e.ProcessingLog) == 0 {
		return nil
	}
	return &e.ProcessingLog[len(e.ProcessingLog)-1]
}

// HasTag returns true if the event has the specified tag
func (e *Event) HasTag(tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// HasRiskFactor returns true if the event has the specified risk factor
func (e *Event) HasRiskFactor(factor string) bool {
	for _, f := range e.RiskFactors {
		if f == factor {
			return true
		}
	}
	return false
}

// Validate validates the event
func (e *Event) Validate() error {
	if e.ID == (types.EventID{}) {
		return ErrInvalidEventID
	}
	
	if e.TenantID == (types.TenantID{}) {
		return ErrInvalidTenantID
	}
	
	if e.Type == "" {
		return ErrInvalidEventType
	}
	
	if e.Source == "" {
		return ErrInvalidEventSource
	}
	
	if e.OccurredAt.IsZero() {
		return ErrInvalidOccurredAt
	}
	
	if e.ReceivedAt.IsZero() {
		return ErrInvalidReceivedAt
	}
	
	return nil
}

// Domain errors
var (
	ErrInvalidEventID     = NewDomainError("INVALID_EVENT_ID", "event ID is required")
	ErrInvalidTenantID    = NewDomainError("INVALID_TENANT_ID", "tenant ID is required")
	ErrInvalidEventType   = NewDomainError("INVALID_EVENT_TYPE", "event type is required")
	ErrInvalidEventSource = NewDomainError("INVALID_EVENT_SOURCE", "event source is required")
	ErrInvalidOccurredAt  = NewDomainError("INVALID_OCCURRED_AT", "occurred at timestamp is required")
	ErrInvalidReceivedAt  = NewDomainError("INVALID_RECEIVED_AT", "received at timestamp is required")
)

// DomainError represents a domain-specific error
type DomainError struct {
	Code    string
	Message string
}

// Error implements the error interface
func (e *DomainError) Error() string {
	return e.Message
}

// NewDomainError creates a new domain error
func NewDomainError(code, message string) *DomainError {
	return &DomainError{
		Code:    code,
		Message: message,
	}
}