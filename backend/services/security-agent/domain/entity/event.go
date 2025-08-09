package entity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SecurityEvent represents a security event captured by the agent
type SecurityEvent struct {
	ID          string                 `json:"id" db:"id"`
	AgentID     string                 `json:"agent_id" db:"agent_id"`
	Type        EventType              `json:"type" db:"type"`
	Category    EventCategory          `json:"category" db:"category"`
	Severity    EventSeverity          `json:"severity" db:"severity"`
	Source      EventSource            `json:"source" db:"source"`
	Title       string                 `json:"title" db:"title"`
	Description string                 `json:"description" db:"description"`
	Details     map[string]interface{} `json:"details" db:"details"`
	Metadata    EventMetadata          `json:"metadata" db:"metadata"`
	Context     EventContext           `json:"context" db:"context"`
	Timestamp   time.Time              `json:"timestamp" db:"timestamp"`
	ProcessedAt *time.Time             `json:"processed_at,omitempty" db:"processed_at"`
	Status      EventStatus            `json:"status" db:"status"`
	Risk        RiskAssessment         `json:"risk" db:"risk"`
	Actions     []EventAction          `json:"actions" db:"actions"`
	Hash        string                 `json:"hash" db:"hash"`
	Tags        []string               `json:"tags" db:"tags"`
}

// EventType represents the type of security event
type EventType string

const (
	EventTypeProcessCreated      EventType = "process_created"
	EventTypeProcessTerminated   EventType = "process_terminated"
	EventTypeFileAccessed        EventType = "file_accessed"
	EventTypeFileModified        EventType = "file_modified"
	EventTypeFileDeleted         EventType = "file_deleted"
	EventTypeNetworkConnection   EventType = "network_connection"
	EventTypeNetworkBlocked      EventType = "network_blocked"
	EventTypeRegistryModified    EventType = "registry_modified"
	EventTypeUserLogin           EventType = "user_login"
	EventTypeUserLogout          EventType = "user_logout"
	EventTypePrivilegeEscalation EventType = "privilege_escalation"
	EventTypeMalwareDetected     EventType = "malware_detected"
	EventTypeAnomalyDetected     EventType = "anomaly_detected"
	EventTypePolicyViolation     EventType = "policy_violation"
	EventTypeConfigurationChange EventType = "configuration_change"
	EventTypeSystemStartup       EventType = "system_startup"
	EventTypeSystemShutdown      EventType = "system_shutdown"
	EventTypeSecurityAlert       EventType = "security_alert"
)

// EventCategory represents the category of the event
type EventCategory string

const (
	EventCategoryProcess  EventCategory = "process"
	EventCategoryFile     EventCategory = "file"
	EventCategoryNetwork  EventCategory = "network"
	EventCategoryRegistry EventCategory = "registry"
	EventCategoryUser     EventCategory = "user"
	EventCategorySecurity EventCategory = "security"
	EventCategorySystem   EventCategory = "system"
	EventCategoryPolicy   EventCategory = "policy"
)

// EventSeverity represents the severity of the event
type EventSeverity string

const (
	EventSeverityCritical EventSeverity = "critical"
	EventSeverityHigh     EventSeverity = "high"
	EventSeverityMedium   EventSeverity = "medium"
	EventSeverityLow      EventSeverity = "low"
	EventSeverityInfo     EventSeverity = "info"
)

// EventSource represents the source of the event
type EventSource struct {
	Type       SourceType `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Component  string     `json:"component"`
	Platform   string     `json:"platform"`
	InstanceID string     `json:"instance_id"`
}

// SourceType represents the type of event source
type SourceType string

const (
	SourceTypeAgent    SourceType = "agent"
	SourceTypeKernel   SourceType = "kernel"
	SourceTypeETW      SourceType = "etw"
	SourceTypeEBPF     SourceType = "ebpf"
	SourceTypeEndpoint SourceType = "endpoint"
	SourceTypeSystem   SourceType = "system"
	SourceTypeCustom   SourceType = "custom"
)

// EventMetadata contains metadata about the event
type EventMetadata struct {
	CorrelationID    string                 `json:"correlation_id"`
	ParentEventID    string                 `json:"parent_event_id,omitempty"`
	ChildEventIDs    []string               `json:"child_event_ids,omitempty"`
	SessionID        string                 `json:"session_id,omitempty"`
	ThreadID         string                 `json:"thread_id,omitempty"`
	ProcessID        string                 `json:"process_id,omitempty"`
	UserID           string                 `json:"user_id,omitempty"`
	OriginalFormat   string                 `json:"original_format"`
	ParsedFields     map[string]interface{} `json:"parsed_fields"`
	EnrichmentData   map[string]interface{} `json:"enrichment_data"`
	CollectionMethod string                 `json:"collection_method"`
}

// EventContext provides context about the event
type EventContext struct {
	System      SystemContext       `json:"system"`
	Process     *ProcessContext     `json:"process,omitempty"`
	User        *UserContext        `json:"user,omitempty"`
	Network     *NetworkContext     `json:"network,omitempty"`
	File        *FileContext        `json:"file,omitempty"`
	Registry    *RegistryContext    `json:"registry,omitempty"`
	Certificate *CertificateContext `json:"certificate,omitempty"`
}

// SystemContext provides system-level context
type SystemContext struct {
	Hostname     string    `json:"hostname"`
	Platform     string    `json:"platform"`
	OSVersion    string    `json:"os_version"`
	Architecture string    `json:"architecture"`
	Domain       string    `json:"domain,omitempty"`
	TimeZone     string    `json:"timezone"`
	BootTime     time.Time `json:"boot_time"`
	Uptime       int64     `json:"uptime"`
}

// ProcessContext provides process-level context
type ProcessContext struct {
	PID                int               `json:"pid"`
	Name               string            `json:"name"`
	Path               string            `json:"path"`
	CommandLine        string            `json:"command_line"`
	Hash               string            `json:"hash,omitempty"`
	ParentPID          int               `json:"parent_pid,omitempty"`
	ParentName         string            `json:"parent_name,omitempty"`
	StartTime          time.Time         `json:"start_time"`
	User               string            `json:"user"`
	Environment        map[string]string `json:"environment,omitempty"`
	WorkingDir         string            `json:"working_dir"`
	ModulesLoaded      []ModuleInfo      `json:"modules_loaded,omitempty"`
	NetworkConnections []ConnectionInfo  `json:"network_connections,omitempty"`
	IsSigned           bool              `json:"is_signed"`
	SignatureInfo      *SignatureInfo    `json:"signature_info,omitempty"`
}

// UserContext provides user-level context
type UserContext struct {
	Username    string    `json:"username"`
	UserID      string    `json:"user_id"`
	Domain      string    `json:"domain,omitempty"`
	Groups      []string  `json:"groups"`
	Privileges  []string  `json:"privileges"`
	SessionID   string    `json:"session_id"`
	SessionType string    `json:"session_type"`
	LoginTime   time.Time `json:"login_time,omitempty"`
	IsElevated  bool      `json:"is_elevated"`
	AuthMethod  string    `json:"auth_method,omitempty"`
}

// NetworkContext provides network-level context
type NetworkContext struct {
	SourceIP        string            `json:"source_ip"`
	SourcePort      int               `json:"source_port"`
	DestIP          string            `json:"dest_ip"`
	DestPort        int               `json:"dest_port"`
	Protocol        string            `json:"protocol"`
	Direction       string            `json:"direction"`
	BytesSent       int64             `json:"bytes_sent"`
	BytesReceived   int64             `json:"bytes_received"`
	PacketsSent     int64             `json:"packets_sent"`
	PacketsReceived int64             `json:"packets_received"`
	DNSQuery        string            `json:"dns_query,omitempty"`
	HTTPDetails     *HTTPDetails      `json:"http_details,omitempty"`
	TLSDetails      *TLSDetails       `json:"tls_details,omitempty"`
	GeoLocation     *GeoLocationInfo  `json:"geo_location,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
}

// FileContext provides file-level context
type FileContext struct {
	Path          string            `json:"path"`
	Name          string            `json:"name"`
	Extension     string            `json:"extension"`
	Size          int64             `json:"size"`
	Hash          string            `json:"hash,omitempty"`
	Permissions   string            `json:"permissions"`
	Owner         string            `json:"owner"`
	Group         string            `json:"group,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	ModifiedAt    time.Time         `json:"modified_at"`
	AccessedAt    time.Time         `json:"accessed_at"`
	MimeType      string            `json:"mime_type,omitempty"`
	IsSigned      bool              `json:"is_signed"`
	SignatureInfo *SignatureInfo    `json:"signature_info,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// RegistryContext provides Windows registry context
type RegistryContext struct {
	Hive      string            `json:"hive"`
	Key       string            `json:"key"`
	ValueName string            `json:"value_name,omitempty"`
	ValueType string            `json:"value_type,omitempty"`
	OldValue  interface{}       `json:"old_value,omitempty"`
	NewValue  interface{}       `json:"new_value,omitempty"`
	Operation string            `json:"operation"`
	User      string            `json:"user"`
	Process   string            `json:"process"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// CertificateContext provides certificate context
type CertificateContext struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	Thumbprint    string    `json:"thumbprint"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidTo       time.Time `json:"valid_to"`
	Algorithm     string    `json:"algorithm"`
	KeySize       int       `json:"key_size"`
	IsValid       bool      `json:"is_valid"`
	IsTrusted     bool      `json:"is_trusted"`
	Purpose       string    `json:"purpose"`
	StoreName     string    `json:"store_name,omitempty"`
	StoreLocation string    `json:"store_location,omitempty"`
}

// EventStatus represents the status of event processing
type EventStatus string

const (
	EventStatusPending    EventStatus = "pending"
	EventStatusProcessed  EventStatus = "processed"
	EventStatusFiltered   EventStatus = "filtered"
	EventStatusCorrelated EventStatus = "correlated"
	EventStatusAlerting   EventStatus = "alerting"
	EventStatusArchived   EventStatus = "archived"
	EventStatusError      EventStatus = "error"
)

// RiskAssessment provides risk assessment for the event
type RiskAssessment struct {
	Score      float64              `json:"score"`
	Level      RiskLevel            `json:"level"`
	Factors    []RiskFactor         `json:"factors"`
	Indicators []ThreatIndicator    `json:"indicators"`
	Mitigation []MitigationStrategy `json:"mitigation"`
	Confidence float64              `json:"confidence"`
	Source     string               `json:"source"`
	UpdatedAt  time.Time            `json:"updated_at"`
}

// RiskLevel represents risk levels
type RiskLevel string

const (
	RiskLevelNone     RiskLevel = "none"
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// RiskFactor represents a factor contributing to risk
type RiskFactor struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
	Value       float64 `json:"value"`
	Impact      string  `json:"impact"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Source      string    `json:"source"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Description string    `json:"description"`
	IOCType     string    `json:"ioc_type"`
}

// MitigationStrategy represents a mitigation strategy
type MitigationStrategy struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
	Automated   bool                   `json:"automated"`
}

// EventAction represents an action taken in response to an event
type EventAction struct {
	ID          string                 `json:"id"`
	Type        ActionType             `json:"type"`
	Status      ActionStatus           `json:"status"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Result      *ActionResult          `json:"result,omitempty"`
	ExecutedAt  time.Time              `json:"executed_at"`
	ExecutedBy  string                 `json:"executed_by"`
}

// Additional helper types
type ModuleInfo struct {
	Name          string         `json:"name"`
	Path          string         `json:"path"`
	Version       string         `json:"version"`
	Hash          string         `json:"hash,omitempty"`
	BaseAddress   string         `json:"base_address"`
	Size          int64          `json:"size"`
	IsSigned      bool           `json:"is_signed"`
	SignatureInfo *SignatureInfo `json:"signature_info,omitempty"`
}

type SignatureInfo struct {
	IsSigned    bool      `json:"is_signed"`
	IsValid     bool      `json:"is_valid"`
	SignerName  string    `json:"signer_name,omitempty"`
	SignedAt    time.Time `json:"signed_at,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	Algorithm   string    `json:"algorithm,omitempty"`
}

type HTTPDetails struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	UserAgent   string            `json:"user_agent,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
}

type TLSDetails struct {
	Version       string   `json:"version"`
	CipherSuite   string   `json:"cipher_suite"`
	ServerName    string   `json:"server_name,omitempty"`
	Certificates  []string `json:"certificates,omitempty"`
	IsValidCert   bool     `json:"is_valid_cert"`
	CertErrors    []string `json:"cert_errors,omitempty"`
	HandshakeTime float64  `json:"handshake_time,omitempty"`
}

type GeoLocationInfo struct {
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Organization string  `json:"organization,omitempty"`
	ISP          string  `json:"isp,omitempty"`
	ASN          string  `json:"asn,omitempty"`
}

// NewSecurityEvent creates a new SecurityEvent instance
func NewSecurityEvent(agentID string, eventType EventType, category EventCategory, severity EventSeverity) *SecurityEvent {
	now := time.Now()
	event := &SecurityEvent{
		ID:        uuid.New().String(),
		AgentID:   agentID,
		Type:      eventType,
		Category:  category,
		Severity:  severity,
		Timestamp: now,
		Status:    EventStatusPending,
		Details:   make(map[string]interface{}),
		Tags:      make([]string, 0),
		Actions:   make([]EventAction, 0),
		Risk: RiskAssessment{
			Factors:    make([]RiskFactor, 0),
			Indicators: make([]ThreatIndicator, 0),
			Mitigation: make([]MitigationStrategy, 0),
		},
	}

	// Generate hash
	event.generateHash()

	return event
}

// generateHash generates a hash for the event
func (e *SecurityEvent) generateHash() {
	data, _ := json.Marshal(struct {
		AgentID   string                 `json:"agent_id"`
		Type      EventType              `json:"type"`
		Timestamp time.Time              `json:"timestamp"`
		Details   map[string]interface{} `json:"details"`
	}{
		AgentID:   e.AgentID,
		Type:      e.Type,
		Timestamp: e.Timestamp,
		Details:   e.Details,
	})

	hash := sha256.Sum256(data)
	e.Hash = hex.EncodeToString(hash[:])
}

// AddDetail adds a detail to the event
func (e *SecurityEvent) AddDetail(key string, value interface{}) {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	e.generateHash() // Regenerate hash when details change
}

// AddTag adds a tag to the event
func (e *SecurityEvent) AddTag(tag string) {
	for _, existingTag := range e.Tags {
		if existingTag == tag {
			return // Tag already exists
		}
	}
	e.Tags = append(e.Tags, tag)
}

// AddAction adds an action to the event
func (e *SecurityEvent) AddAction(action EventAction) {
	e.Actions = append(e.Actions, action)
}

// MarkProcessed marks the event as processed
func (e *SecurityEvent) MarkProcessed() {
	now := time.Now()
	e.ProcessedAt = &now
	e.Status = EventStatusProcessed
}

// Validate validates the event
func (e *SecurityEvent) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("event ID is required")
	}
	if e.AgentID == "" {
		return fmt.Errorf("agent ID is required")
	}
	if e.Type == "" {
		return fmt.Errorf("event type is required")
	}
	if e.Category == "" {
		return fmt.Errorf("event category is required")
	}
	if e.Severity == "" {
		return fmt.Errorf("event severity is required")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("event timestamp is required")
	}
	return nil
}
