package usecase

import (
	"context"
	"time"

	"github.com/isectech/security-agent/domain/entity"
)

// UseCases contains all use case implementations
type UseCases struct {
	AgentManagement   AgentManagementUseCase
	EventProcessing   EventProcessingUseCase
	PolicyEnforcement PolicyEnforcementUseCase
	DataCollection    DataCollectionUseCase
	Communication     CommunicationUseCase
	Security          SecurityUseCase
	Update            UpdateUseCase
	Monitoring        MonitoringUseCase
}

// AgentManagementUseCase handles agent management operations
type AgentManagementUseCase interface {
	RegisterAgent(ctx context.Context, agent *entity.Agent) error
	UpdateAgent(ctx context.Context, agent *entity.Agent) error
	GetAgent(ctx context.Context, agentID string) (*entity.Agent, error)
	DecommissionAgent(ctx context.Context, agentID string) error
	SendHeartbeat(ctx context.Context, agentID string) error
	UpdateHealth(ctx context.Context, agentID string, health entity.AgentHealth) error
	UpdateResourceUsage(ctx context.Context, agentID string, usage entity.ResourceUsage) error
	GetAgentStatus(ctx context.Context, agentID string) (entity.AgentStatus, error)
}

// EventProcessingUseCase handles security event processing
type EventProcessingUseCase interface {
	ProcessEvent(ctx context.Context, event *entity.SecurityEvent) error
	CreateEvent(ctx context.Context, event *entity.SecurityEvent) error
	GetEvent(ctx context.Context, eventID string) (*entity.SecurityEvent, error)
	GetEventsByAgent(ctx context.Context, agentID string, filters EventFilters) ([]*entity.SecurityEvent, error)
	CorrelateEvents(ctx context.Context, events []*entity.SecurityEvent) ([]*entity.SecurityEvent, error)
	EnrichEvent(ctx context.Context, event *entity.SecurityEvent) error
	ArchiveEvent(ctx context.Context, eventID string) error
}

// PolicyEnforcementUseCase handles policy enforcement
type PolicyEnforcementUseCase interface {
	EnforcePolicy(ctx context.Context, agentID string, policyID string, params map[string]interface{}) error
	ValidatePolicy(ctx context.Context, policy *SecurityPolicy) error
	GetPolicies(ctx context.Context, agentID string) ([]*SecurityPolicy, error)
	UpdatePolicyConfiguration(ctx context.Context, agentID string, config entity.PolicySettings) error
	ExecuteAction(ctx context.Context, action *entity.RemediationAction) (*entity.ActionResult, error)
	GetPolicyViolations(ctx context.Context, agentID string) ([]entity.PolicyViolation, error)
}

// DataCollectionUseCase handles data collection operations
type DataCollectionUseCase interface {
	StartDataCollection(ctx context.Context, agentID string, collectors []CollectorType) error
	StopDataCollection(ctx context.Context, agentID string, collectors []CollectorType) error
	GetCollectorStatus(ctx context.Context, agentID string) (map[CollectorType]CollectorStatus, error)
	ConfigureCollector(ctx context.Context, agentID string, collectorType CollectorType, config interface{}) error
	GetCollectedData(ctx context.Context, agentID string, filters DataFilters) ([]CollectedData, error)
}

// CommunicationUseCase handles backend communication
type CommunicationUseCase interface {
	EstablishConnection(ctx context.Context, agentID string) error
	SendTelemetry(ctx context.Context, agentID string, data []byte) error
	ReceiveCommands(ctx context.Context, agentID string) ([]Command, error)
	SendHeartbeat(ctx context.Context, agentID string, status entity.AgentHealth) error
	UploadEvents(ctx context.Context, agentID string, events []*entity.SecurityEvent) error
	DownloadPolicies(ctx context.Context, agentID string) ([]*SecurityPolicy, error)
	ReportIncident(ctx context.Context, agentID string, incident *SecurityIncident) error
}

// SecurityUseCase handles security operations
type SecurityUseCase interface {
	ValidateIntegrity(ctx context.Context, agentID string) (bool, error)
	DetectTamper(ctx context.Context, agentID string) ([]entity.SecurityViolation, error)
	PerformSecurityScan(ctx context.Context, agentID string) (*SecurityScanResult, error)
	EncryptData(ctx context.Context, data []byte) ([]byte, error)
	DecryptData(ctx context.Context, encryptedData []byte) ([]byte, error)
	ValidateCertificate(ctx context.Context, certData []byte) (bool, error)
	GenerateSecurityReport(ctx context.Context, agentID string) (*SecurityReport, error)
}

// UpdateUseCase handles agent updates
type UpdateUseCase interface {
	CheckForUpdates(ctx context.Context, agentID string, currentVersion string) (*UpdateInfo, error)
	DownloadUpdate(ctx context.Context, agentID string, updateInfo *UpdateInfo) ([]byte, error)
	ValidateUpdate(ctx context.Context, updateData []byte) (bool, error)
	ApplyUpdate(ctx context.Context, agentID string, updateData []byte) error
	RollbackUpdate(ctx context.Context, agentID string, targetVersion string) error
	GetUpdateHistory(ctx context.Context, agentID string) ([]*UpdateRecord, error)
}

// MonitoringUseCase handles monitoring and metrics
type MonitoringUseCase interface {
	CollectMetrics(ctx context.Context, agentID string) (*PerformanceMetrics, error)
	RecordMetric(ctx context.Context, agentID string, metric Metric) error
	GetMetrics(ctx context.Context, agentID string, timeRange TimeRange) ([]*PerformanceMetrics, error)
	GenerateHealthReport(ctx context.Context, agentID string) (*HealthReport, error)
	SetAlert(ctx context.Context, agentID string, alert Alert) error
	GetAlerts(ctx context.Context, agentID string) ([]Alert, error)
}

// Supporting types and structures

// EventFilters represents filters for event queries
type EventFilters struct {
	StartTime  *time.Time             `json:"start_time,omitempty"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	EventTypes []entity.EventType     `json:"event_types,omitempty"`
	Severities []entity.EventSeverity `json:"severities,omitempty"`
	Categories []entity.EventCategory `json:"categories,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Offset     int                    `json:"offset,omitempty"`
}

// SecurityPolicy represents a security policy
type SecurityPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Rules       []PolicyRule           `json:"rules"`
	Actions     []PolicyAction         `json:"actions"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Conditions []PolicyCondition      `json:"conditions"`
	Action     string                 `json:"action"`
	Severity   entity.RuleSeverity    `json:"severity"`
	Parameters map[string]interface{} `json:"parameters"`
	IsEnabled  bool                   `json:"is_enabled"`
}

// PolicyCondition represents a condition in a policy rule
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Type     string      `json:"type"`
}

// PolicyAction represents an action in a policy
type PolicyAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

// CollectorType represents different types of data collectors
type CollectorType string

const (
	CollectorTypeProcess       CollectorType = "process"
	CollectorTypeNetwork       CollectorType = "network"
	CollectorTypeFile          CollectorType = "file"
	CollectorTypeRegistry      CollectorType = "registry"
	CollectorTypeUser          CollectorType = "user"
	CollectorTypeApplication   CollectorType = "application"
	CollectorTypeVulnerability CollectorType = "vulnerability"
)

// CollectorStatus represents the status of a data collector
type CollectorStatus struct {
	Type       CollectorType          `json:"type"`
	IsRunning  bool                   `json:"is_running"`
	IsHealthy  bool                   `json:"is_healthy"`
	LastUpdate time.Time              `json:"last_update"`
	ErrorCount int                    `json:"error_count"`
	LastError  string                 `json:"last_error,omitempty"`
	Metrics    map[string]interface{} `json:"metrics"`
}

// DataFilters represents filters for collected data queries
type DataFilters struct {
	StartTime      *time.Time      `json:"start_time,omitempty"`
	EndTime        *time.Time      `json:"end_time,omitempty"`
	CollectorTypes []CollectorType `json:"collector_types,omitempty"`
	Limit          int             `json:"limit,omitempty"`
	Offset         int             `json:"offset,omitempty"`
}

// CollectedData represents collected data from agents
type CollectedData struct {
	ID            string                 `json:"id"`
	AgentID       string                 `json:"agent_id"`
	CollectorType CollectorType          `json:"collector_type"`
	DataType      string                 `json:"data_type"`
	Data          map[string]interface{} `json:"data"`
	Timestamp     time.Time              `json:"timestamp"`
	Hash          string                 `json:"hash"`
}

// Command represents a command to be executed by an agent
type Command struct {
	ID         string                 `json:"id"`
	Type       CommandType            `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   CommandPriority        `json:"priority"`
	CreatedAt  time.Time              `json:"created_at"`
	ExpiresAt  *time.Time             `json:"expires_at,omitempty"`
	Status     CommandStatus          `json:"status"`
}

// CommandType represents different types of commands
type CommandType string

const (
	CommandTypeUpdateConfiguration CommandType = "update_configuration"
	CommandTypeRestartService      CommandType = "restart_service"
	CommandTypeCollectData         CommandType = "collect_data"
	CommandTypeEnforcePolicy       CommandType = "enforce_policy"
	CommandTypePerformScan         CommandType = "perform_scan"
	CommandTypeUpdateAgent         CommandType = "update_agent"
	CommandTypeIsolateEndpoint     CommandType = "isolate_endpoint"
)

// CommandPriority represents command priority levels
type CommandPriority string

const (
	CommandPriorityLow      CommandPriority = "low"
	CommandPriorityMedium   CommandPriority = "medium"
	CommandPriorityHigh     CommandPriority = "high"
	CommandPriorityCritical CommandPriority = "critical"
)

// CommandStatus represents command execution status
type CommandStatus string

const (
	CommandStatusPending   CommandStatus = "pending"
	CommandStatusExecuting CommandStatus = "executing"
	CommandStatusCompleted CommandStatus = "completed"
	CommandStatusFailed    CommandStatus = "failed"
	CommandStatusExpired   CommandStatus = "expired"
)

// SecurityIncident represents a security incident
type SecurityIncident struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    entity.EventSeverity   `json:"severity"`
	Events      []string               `json:"events"`
	Evidence    map[string]interface{} `json:"evidence"`
	Status      IncidentStatus         `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// IncidentStatus represents incident status
type IncidentStatus string

const (
	IncidentStatusOpen          IncidentStatus = "open"
	IncidentStatusInvestigating IncidentStatus = "investigating"
	IncidentStatusContained     IncidentStatus = "contained"
	IncidentStatusResolved      IncidentStatus = "resolved"
	IncidentStatusClosed        IncidentStatus = "closed"
)

// SecurityScanResult represents the result of a security scan
type SecurityScanResult struct {
	ScanID          string                 `json:"scan_id"`
	ScanType        string                 `json:"scan_type"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         time.Time              `json:"end_time"`
	Status          string                 `json:"status"`
	Findings        []SecurityFinding      `json:"findings"`
	Statistics      map[string]interface{} `json:"statistics"`
	Recommendations []string               `json:"recommendations"`
}

// SecurityFinding represents a security finding
type SecurityFinding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    entity.EventSeverity   `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Remediation string                 `json:"remediation"`
	Risk        float64                `json:"risk"`
}

// SecurityReport represents a comprehensive security report
type SecurityReport struct {
	ReportID        string                 `json:"report_id"`
	AgentID         string                 `json:"agent_id"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Period          TimeRange              `json:"period"`
	Summary         ReportSummary          `json:"summary"`
	Sections        []ReportSection        `json:"sections"`
	Metrics         map[string]interface{} `json:"metrics"`
	Recommendations []string               `json:"recommendations"`
}

// UpdateInfo represents update information
type UpdateInfo struct {
	Version     string                 `json:"version"`
	ReleaseDate time.Time              `json:"release_date"`
	DownloadURL string                 `json:"download_url"`
	Checksum    string                 `json:"checksum"`
	Size        int64                  `json:"size"`
	Changelog   string                 `json:"changelog"`
	IsRequired  bool                   `json:"is_required"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// UpdateRecord represents an update record
type UpdateRecord struct {
	ID              string                 `json:"id"`
	Version         string                 `json:"version"`
	PreviousVersion string                 `json:"previous_version"`
	Status          UpdateStatus           `json:"status"`
	StartedAt       time.Time              `json:"started_at"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// UpdateStatus represents update status
type UpdateStatus string

const (
	UpdateStatusPending     UpdateStatus = "pending"
	UpdateStatusDownloading UpdateStatus = "downloading"
	UpdateStatusInstalling  UpdateStatus = "installing"
	UpdateStatusCompleted   UpdateStatus = "completed"
	UpdateStatusFailed      UpdateStatus = "failed"
	UpdateStatusRolledBack  UpdateStatus = "rolled_back"
)

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	AgentID   string                 `json:"agent_id"`
	Timestamp time.Time              `json:"timestamp"`
	CPU       entity.CPUUsage        `json:"cpu"`
	Memory    entity.MemoryUsage     `json:"memory"`
	Disk      entity.DiskUsage       `json:"disk"`
	Network   entity.NetworkUsage    `json:"network"`
	Custom    map[string]interface{} `json:"custom"`
}

// Metric represents a single metric
type Metric struct {
	Name      string                 `json:"name"`
	Value     float64                `json:"value"`
	Unit      string                 `json:"unit"`
	Tags      map[string]string      `json:"tags"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// HealthReport represents a health report
type HealthReport struct {
	AgentID         string                         `json:"agent_id"`
	GeneratedAt     time.Time                      `json:"generated_at"`
	OverallHealth   entity.HealthStatus            `json:"overall_health"`
	Components      map[string]entity.HealthStatus `json:"components"`
	Issues          []entity.HealthIssue           `json:"issues"`
	Metrics         PerformanceMetrics             `json:"metrics"`
	Recommendations []string                       `json:"recommendations"`
}

// Alert represents an alert
type Alert struct {
	ID         string                 `json:"id"`
	Type       AlertType              `json:"type"`
	Severity   entity.EventSeverity   `json:"severity"`
	Title      string                 `json:"title"`
	Message    string                 `json:"message"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
	Status     AlertStatus            `json:"status"`
	Conditions []AlertCondition       `json:"conditions"`
	Actions    []AlertAction          `json:"actions"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// AlertType represents alert types
type AlertType string

const (
	AlertTypePerformance AlertType = "performance"
	AlertTypeSecurity    AlertType = "security"
	AlertTypeHealth      AlertType = "health"
	AlertTypePolicy      AlertType = "policy"
	AlertTypeSystem      AlertType = "system"
)

// AlertStatus represents alert status
type AlertStatus string

const (
	AlertStatusActive       AlertStatus = "active"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusSuppressed   AlertStatus = "suppressed"
)

// AlertCondition represents an alert condition
type AlertCondition struct {
	Metric    string  `json:"metric"`
	Operator  string  `json:"operator"`
	Threshold float64 `json:"threshold"`
	Duration  string  `json:"duration"`
}

// AlertAction represents an action to take when an alert fires
type AlertAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ReportSummary represents a report summary
type ReportSummary struct {
	TotalEvents       int                    `json:"total_events"`
	CriticalEvents    int                    `json:"critical_events"`
	SecurityIncidents int                    `json:"security_incidents"`
	PolicyViolations  int                    `json:"policy_violations"`
	ThreatLevel       entity.ThreatLevel     `json:"threat_level"`
	HealthScore       float64                `json:"health_score"`
	ComplianceScore   float64                `json:"compliance_score"`
	TopThreats        []string               `json:"top_threats"`
	Trends            map[string]interface{} `json:"trends"`
}

// ReportSection represents a section in a report
type ReportSection struct {
	Title   string                 `json:"title"`
	Type    string                 `json:"type"`
	Content map[string]interface{} `json:"content"`
	Charts  []ChartData            `json:"charts,omitempty"`
}

// ChartData represents chart data for reports
type ChartData struct {
	Type   string                 `json:"type"`
	Title  string                 `json:"title"`
	Data   map[string]interface{} `json:"data"`
	Config map[string]interface{} `json:"config"`
}
