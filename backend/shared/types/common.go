package types

import (
	"time"

	"github.com/google/uuid"
)

// TenantID represents a unique tenant identifier
type TenantID uuid.UUID

// UserID represents a unique user identifier
type UserID uuid.UUID

// ServiceID represents a unique service identifier
type ServiceID string

// CorrelationID represents a unique request correlation identifier
type CorrelationID uuid.UUID

// AssetID represents a unique asset identifier
type AssetID uuid.UUID

// ThreatID represents a unique threat identifier
type ThreatID uuid.UUID

// EventID represents a unique event identifier
type EventID uuid.UUID

// String returns the string representation of TenantID
func (t TenantID) String() string {
	return uuid.UUID(t).String()
}

// String returns the string representation of UserID
func (u UserID) String() string {
	return uuid.UUID(u).String()
}

// String returns the string representation of CorrelationID
func (c CorrelationID) String() string {
	return uuid.UUID(c).String()
}

// String returns the string representation of AssetID
func (a AssetID) String() string {
	return uuid.UUID(a).String()
}

// String returns the string representation of ThreatID
func (t ThreatID) String() string {
	return uuid.UUID(t).String()
}

// String returns the string representation of EventID
func (e EventID) String() string {
	return uuid.UUID(e).String()
}

// Severity levels for threats, alerts, and vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status represents the status of various entities
type Status string

const (
	StatusPending    Status = "pending"
	StatusActive     Status = "active"
	StatusInactive   Status = "inactive"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusCancelled  Status = "cancelled"
	StatusSuspended  Status = "suspended"
)

// EventType represents different types of security events
type EventType string

const (
	EventTypeAuthentication   EventType = "authentication"
	EventTypeAuthorization    EventType = "authorization"
	EventTypeNetworkAccess    EventType = "network_access"
	EventTypeThreatDetection  EventType = "threat_detection"
	EventTypeVulnerability    EventType = "vulnerability"
	EventTypeCompliance       EventType = "compliance"
	EventTypeAssetDiscovery   EventType = "asset_discovery"
	EventTypeSystemHealth     EventType = "system_health"
	EventTypeUserActivity     EventType = "user_activity"
	EventTypeDataAccess       EventType = "data_access"
)

// ThreatType represents different types of security threats
type ThreatType string

const (
	ThreatTypeMalware           ThreatType = "malware"
	ThreatTypePhishing          ThreatType = "phishing"
	ThreatTypeBruteForce        ThreatType = "brute_force"
	ThreatTypeDDoS              ThreatType = "ddos"
	ThreatTypeAnomalousActivity ThreatType = "anomalous_activity"
	ThreatTypeDataExfiltration  ThreatType = "data_exfiltration"
	ThreatTypePrivilegeEscalation ThreatType = "privilege_escalation"
	ThreatTypeLateralMovement   ThreatType = "lateral_movement"
	ThreatTypeCommandInjection  ThreatType = "command_injection"
	ThreatTypeSQLInjection      ThreatType = "sql_injection"
)

// AssetType represents different types of network assets
type AssetType string

const (
	AssetTypeServer       AssetType = "server"
	AssetTypeWorkstation  AssetType = "workstation"
	AssetTypeNetworkDevice AssetType = "network_device"
	AssetTypeMobileDevice AssetType = "mobile_device"
	AssetTypeIoTDevice    AssetType = "iot_device"
	AssetTypeContainer    AssetType = "container"
	AssetTypeVirtualMachine AssetType = "virtual_machine"
	AssetTypeCloudResource AssetType = "cloud_resource"
	AssetTypeDatabase     AssetType = "database"
	AssetTypeApplication  AssetType = "application"
)

// BaseEntity represents common fields for all entities
type BaseEntity struct {
	ID        uuid.UUID `json:"id" bson:"_id" db:"id"`
	TenantID  TenantID  `json:"tenant_id" bson:"tenant_id" db:"tenant_id"`
	CreatedAt time.Time `json:"created_at" bson:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at" db:"updated_at"`
}

// AuditableEntity extends BaseEntity with audit fields
type AuditableEntity struct {
	BaseEntity
	CreatedBy *UserID    `json:"created_by,omitempty" bson:"created_by,omitempty" db:"created_by"`
	UpdatedBy *UserID    `json:"updated_by,omitempty" bson:"updated_by,omitempty" db:"updated_by"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" bson:"deleted_at,omitempty" db:"deleted_at"`
}

// RequestContext contains common request context information
type RequestContext struct {
	CorrelationID CorrelationID `json:"correlation_id"`
	TenantID      TenantID      `json:"tenant_id"`
	UserID        *UserID       `json:"user_id,omitempty"`
	ServiceID     ServiceID     `json:"service_id"`
	TraceID       string        `json:"trace_id,omitempty"`
	SpanID        string        `json:"span_id,omitempty"`
	Timestamp     time.Time     `json:"timestamp"`
	IPAddress     string        `json:"ip_address,omitempty"`
	UserAgent     string        `json:"user_agent,omitempty"`
}

// HealthStatus represents the health status of a service
type HealthStatus struct {
	Status      string            `json:"status"`
	Timestamp   time.Time         `json:"timestamp"`
	Version     string            `json:"version"`
	Uptime      time.Duration     `json:"uptime"`
	Dependencies map[string]bool   `json:"dependencies"`
	Metrics     map[string]interface{} `json:"metrics"`
}

// HealthCheck represents a health check configuration
type HealthCheck struct {
	Name     string        `json:"name"`
	Endpoint string        `json:"endpoint"`
	Timeout  time.Duration `json:"timeout"`
	Interval time.Duration `json:"interval"`
	Retries  int           `json:"retries"`
}

// PaginationRequest represents pagination parameters
type PaginationRequest struct {
	Page     int    `json:"page" query:"page" validate:"min=1"`
	PageSize int    `json:"page_size" query:"page_size" validate:"min=1,max=100"`
	Sort     string `json:"sort" query:"sort"`
	Order    string `json:"order" query:"order" validate:"oneof=asc desc"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalItems int64 `json:"total_items"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// FilterRequest represents common filtering parameters
type FilterRequest struct {
	TenantID  *TenantID `json:"tenant_id,omitempty" query:"tenant_id"`
	Status    *Status   `json:"status,omitempty" query:"status"`
	Severity  *Severity `json:"severity,omitempty" query:"severity"`
	DateFrom  *time.Time `json:"date_from,omitempty" query:"date_from"`
	DateTo    *time.Time `json:"date_to,omitempty" query:"date_to"`
	Search    string    `json:"search,omitempty" query:"search"`
}

// APIResponse represents a standard API response structure
type APIResponse struct {
	Success    bool        `json:"success"`
	Data       interface{} `json:"data,omitempty"`
	Error      *APIError   `json:"error,omitempty"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
	Meta       map[string]interface{} `json:"meta,omitempty"`
}

// APIError represents a standard API error structure
type APIError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Details    string `json:"details,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// ConfigurationSetting represents a configuration setting
type ConfigurationSetting struct {
	Key         string      `json:"key" db:"key"`
	Value       interface{} `json:"value" db:"value"`
	Category    string      `json:"category" db:"category"`
	Description string      `json:"description" db:"description"`
	IsEncrypted bool        `json:"is_encrypted" db:"is_encrypted"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`
}

// ServiceInfo represents information about a service
type ServiceInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Environment string            `json:"environment"`
	StartTime   time.Time         `json:"start_time"`
	BuildTime   string            `json:"build_time"`
	GitCommit   string            `json:"git_commit"`
	Config      map[string]string `json:"config"`
}

// NewCorrelationID generates a new correlation ID
func NewCorrelationID() CorrelationID {
	return CorrelationID(uuid.New())
}

// NewTenantID generates a new tenant ID
func NewTenantID() TenantID {
	return TenantID(uuid.New())
}

// NewUserID generates a new user ID
func NewUserID() UserID {
	return UserID(uuid.New())
}

// NewAssetID generates a new asset ID
func NewAssetID() AssetID {
	return AssetID(uuid.New())
}

// NewThreatID generates a new threat ID
func NewThreatID() ThreatID {
	return ThreatID(uuid.New())
}

// NewEventID generates a new event ID
func NewEventID() EventID {
	return EventID(uuid.New())
}

// NewRequestContext creates a new request context
func NewRequestContext(tenantID TenantID, serviceID ServiceID) *RequestContext {
	return &RequestContext{
		CorrelationID: NewCorrelationID(),
		TenantID:      tenantID,
		ServiceID:     serviceID,
		Timestamp:     time.Now().UTC(),
	}
}

// WithUser adds user information to the request context
func (rc *RequestContext) WithUser(userID UserID) *RequestContext {
	rc.UserID = &userID
	return rc
}

// WithTrace adds tracing information to the request context
func (rc *RequestContext) WithTrace(traceID, spanID string) *RequestContext {
	rc.TraceID = traceID
	rc.SpanID = spanID
	return rc
}

// WithClient adds client information to the request context
func (rc *RequestContext) WithClient(ipAddress, userAgent string) *RequestContext {
	rc.IPAddress = ipAddress
	rc.UserAgent = userAgent
	return rc
}