package entity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Agent represents the security agent instance
type Agent struct {
	ID            string                 `json:"id" db:"id"`
	Name          string                 `json:"name" db:"name"`
	Version       string                 `json:"version" db:"version"`
	Platform      string                 `json:"platform" db:"platform"`
	Architecture  string                 `json:"architecture" db:"architecture"`
	OSVersion     string                 `json:"os_version" db:"os_version"`
	Hostname      string                 `json:"hostname" db:"hostname"`
	IPAddress     string                 `json:"ip_address" db:"ip_address"`
	MACAddress    string                 `json:"mac_address" db:"mac_address"`
	InstallPath   string                 `json:"install_path" db:"install_path"`
	ConfigHash    string                 `json:"config_hash" db:"config_hash"`
	Status        AgentStatus            `json:"status" db:"status"`
	Health        AgentHealth            `json:"health" db:"health"`
	LastSeen      time.Time              `json:"last_seen" db:"last_seen"`
	LastHeartbeat time.Time              `json:"last_heartbeat" db:"last_heartbeat"`
	RegisteredAt  time.Time              `json:"registered_at" db:"registered_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
	Tags          []string               `json:"tags" db:"tags"`
	Metadata      map[string]interface{} `json:"metadata" db:"metadata"`
	SecurityState SecurityState          `json:"security_state" db:"security_state"`
	Capabilities  AgentCapabilities      `json:"capabilities" db:"capabilities"`
	ResourceUsage ResourceUsage          `json:"resource_usage" db:"resource_usage"`
	Configuration AgentConfiguration     `json:"configuration" db:"configuration"`
	Certificates  CertificateInfo        `json:"certificates" db:"certificates"`
}

// AgentStatus represents the current status of the agent
type AgentStatus string

const (
	AgentStatusActive         AgentStatus = "active"
	AgentStatusInactive       AgentStatus = "inactive"
	AgentStatusUpdating       AgentStatus = "updating"
	AgentStatusError          AgentStatus = "error"
	AgentStatusRegistering    AgentStatus = "registering"
	AgentStatusDecommissioned AgentStatus = "decommissioned"
	AgentStatusQuarantined    AgentStatus = "quarantined"
)

// AgentHealth represents the health status of the agent
type AgentHealth struct {
	Overall         HealthStatus            `json:"overall"`
	Components      map[string]HealthStatus `json:"components"`
	LastHealthCheck time.Time               `json:"last_health_check"`
	HealthScore     float64                 `json:"health_score"`
	Issues          []HealthIssue           `json:"issues"`
	Performance     PerformanceMetrics      `json:"performance"`
}

// HealthStatus represents health status values
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// HealthIssue represents a health issue
type HealthIssue struct {
	ID         string            `json:"id"`
	Component  string            `json:"component"`
	Severity   IssueSeverity     `json:"severity"`
	Message    string            `json:"message"`
	Details    map[string]string `json:"details"`
	DetectedAt time.Time         `json:"detected_at"`
	ResolvedAt *time.Time        `json:"resolved_at,omitempty"`
}

// IssueSeverity represents the severity of a health issue
type IssueSeverity string

const (
	IssueSeverityCritical IssueSeverity = "critical"
	IssueSeverityHigh     IssueSeverity = "high"
	IssueSeverityMedium   IssueSeverity = "medium"
	IssueSeverityLow      IssueSeverity = "low"
	IssueSeverityInfo     IssueSeverity = "info"
)

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	CPUUsagePercent float64   `json:"cpu_usage_percent"`
	MemoryUsageMB   float64   `json:"memory_usage_mb"`
	DiskUsageMB     float64   `json:"disk_usage_mb"`
	NetworkBytesIn  uint64    `json:"network_bytes_in"`
	NetworkBytesOut uint64    `json:"network_bytes_out"`
	EventsProcessed uint64    `json:"events_processed"`
	EventsPerSecond float64   `json:"events_per_second"`
	ErrorCount      uint64    `json:"error_count"`
	UptimeSeconds   uint64    `json:"uptime_seconds"`
	LastUpdated     time.Time `json:"last_updated"`
}

// SecurityState represents the security state of the agent
type SecurityState struct {
	IsCompromised      bool                   `json:"is_compromised"`
	TamperDetected     bool                   `json:"tamper_detected"`
	IntegrityValid     bool                   `json:"integrity_valid"`
	CertificateValid   bool                   `json:"certificate_valid"`
	LastIntegrityCheck time.Time              `json:"last_integrity_check"`
	SecurityViolations []SecurityViolation    `json:"security_violations"`
	ThreatLevel        ThreatLevel            `json:"threat_level"`
	SecurityScore      float64                `json:"security_score"`
	PolicyCompliance   PolicyComplianceStatus `json:"policy_compliance"`
	EncryptionStatus   EncryptionStatus       `json:"encryption_status"`
}

// SecurityViolation represents a security violation
type SecurityViolation struct {
	ID          string                 `json:"id"`
	Type        ViolationType          `json:"type"`
	Severity    ViolationSeverity      `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	DetectedAt  time.Time              `json:"detected_at"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Actions     []RemediationAction    `json:"actions"`
}

// ViolationType represents types of security violations
type ViolationType string

const (
	ViolationTypeTamper       ViolationType = "tamper"
	ViolationTypeIntegrity    ViolationType = "integrity"
	ViolationTypeUnauthorized ViolationType = "unauthorized"
	ViolationTypePolicyBreach ViolationType = "policy_breach"
	ViolationTypeAnomaly      ViolationType = "anomaly"
	ViolationTypeMalware      ViolationType = "malware"
	ViolationTypeDataLeak     ViolationType = "data_leak"
)

// ViolationSeverity represents violation severity levels
type ViolationSeverity string

const (
	ViolationSeverityCritical ViolationSeverity = "critical"
	ViolationSeverityHigh     ViolationSeverity = "high"
	ViolationSeverityMedium   ViolationSeverity = "medium"
	ViolationSeverityLow      ViolationSeverity = "low"
)

// RemediationAction represents an action taken to remediate a violation
type RemediationAction struct {
	ID          string                 `json:"id"`
	Type        ActionType             `json:"type"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Status      ActionStatus           `json:"status"`
	ExecutedAt  time.Time              `json:"executed_at"`
	Result      ActionResult           `json:"result"`
}

// ActionType represents types of remediation actions
type ActionType string

const (
	ActionTypeQuarantine      ActionType = "quarantine"
	ActionTypeKillProcess     ActionType = "kill_process"
	ActionTypeBlockNetwork    ActionType = "block_network"
	ActionTypeIsolateUser     ActionType = "isolate_user"
	ActionTypeRestart         ActionType = "restart"
	ActionTypeNotify          ActionType = "notify"
	ActionTypeCollectEvidence ActionType = "collect_evidence"
)

// ActionStatus represents the status of an action
type ActionStatus string

const (
	ActionStatusPending   ActionStatus = "pending"
	ActionStatusExecuting ActionStatus = "executing"
	ActionStatusCompleted ActionStatus = "completed"
	ActionStatusFailed    ActionStatus = "failed"
	ActionStatusSkipped   ActionStatus = "skipped"
)

// ActionResult represents the result of an action
type ActionResult struct {
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	ErrorCode   string                 `json:"error_code,omitempty"`
	CompletedAt time.Time              `json:"completed_at"`
}

// ThreatLevel represents threat levels
type ThreatLevel string

const (
	ThreatLevelNone     ThreatLevel = "none"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// PolicyComplianceStatus represents policy compliance status
type PolicyComplianceStatus struct {
	IsCompliant     bool                    `json:"is_compliant"`
	ComplianceScore float64                 `json:"compliance_score"`
	Violations      []PolicyViolation       `json:"violations"`
	LastAssessment  time.Time               `json:"last_assessment"`
	Policies        map[string]PolicyStatus `json:"policies"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID    string                 `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	Severity    ViolationSeverity      `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	DetectedAt  time.Time              `json:"detected_at"`
}

// PolicyStatus represents the status of a policy
type PolicyStatus struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	IsActive     bool      `json:"is_active"`
	IsCompliant  bool      `json:"is_compliant"`
	LastChecked  time.Time `json:"last_checked"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// EncryptionStatus represents encryption status
type EncryptionStatus struct {
	LocalDataEncrypted     bool      `json:"local_data_encrypted"`
	CommunicationEncrypted bool      `json:"communication_encrypted"`
	KeyRotationCurrent     bool      `json:"key_rotation_current"`
	LastKeyRotation        time.Time `json:"last_key_rotation"`
	EncryptionAlgorithm    string    `json:"encryption_algorithm"`
	KeyStrength            int       `json:"key_strength"`
}

// AgentCapabilities represents the capabilities of the agent
type AgentCapabilities struct {
	DataCollection     DataCollectionCapabilities `json:"data_collection"`
	PolicyEnforcement  EnforcementCapabilities    `json:"policy_enforcement"`
	PlatformFeatures   PlatformCapabilities       `json:"platform_features"`
	IntegrationSupport IntegrationCapabilities    `json:"integration_support"`
	SecurityFeatures   SecurityCapabilities       `json:"security_features"`
}

// DataCollectionCapabilities represents data collection capabilities
type DataCollectionCapabilities struct {
	ProcessMonitoring      bool `json:"process_monitoring"`
	NetworkMonitoring      bool `json:"network_monitoring"`
	FileSystemMonitoring   bool `json:"filesystem_monitoring"`
	RegistryMonitoring     bool `json:"registry_monitoring"`
	UserActivityMonitoring bool `json:"user_activity_monitoring"`
	ApplicationInventory   bool `json:"application_inventory"`
	VulnerabilityScanning  bool `json:"vulnerability_scanning"`
	MemoryAnalysis         bool `json:"memory_analysis"`
	NetworkAnalysis        bool `json:"network_analysis"`
	BehavioralAnalysis     bool `json:"behavioral_analysis"`
}

// EnforcementCapabilities represents enforcement capabilities
type EnforcementCapabilities struct {
	ProcessControl       bool `json:"process_control"`
	NetworkControl       bool `json:"network_control"`
	FileControl          bool `json:"file_control"`
	UserSessionControl   bool `json:"user_session_control"`
	ApplicationControl   bool `json:"application_control"`
	DeviceControl        bool `json:"device_control"`
	RemoteIsolation      bool `json:"remote_isolation"`
	AutomaticRemediation bool `json:"automatic_remediation"`
}

// PlatformCapabilities represents platform-specific capabilities
type PlatformCapabilities struct {
	KernelLevelAccess     bool     `json:"kernel_level_access"`
	HardwareMonitoring    bool     `json:"hardware_monitoring"`
	VirtualizationSupport bool     `json:"virtualization_support"`
	ContainerSupport      bool     `json:"container_support"`
	CloudIntegration      bool     `json:"cloud_integration"`
	SupportedPlatforms    []string `json:"supported_platforms"`
	RequiredPrivileges    []string `json:"required_privileges"`
}

// IntegrationCapabilities represents integration capabilities
type IntegrationCapabilities struct {
	SIEMIntegration     bool     `json:"siem_integration"`
	SOARIntegration     bool     `json:"soar_integration"`
	ThreatIntelligence  bool     `json:"threat_intelligence"`
	EndpointProtection  bool     `json:"endpoint_protection"`
	IdentityProviders   []string `json:"identity_providers"`
	APISupport          []string `json:"api_support"`
	StandardsCompliance []string `json:"standards_compliance"`
}

// SecurityCapabilities represents security capabilities
type SecurityCapabilities struct {
	TamperResistance      bool     `json:"tamper_resistance"`
	AntiDebugging         bool     `json:"anti_debugging"`
	CodeSigning           bool     `json:"code_signing"`
	MemoryProtection      bool     `json:"memory_protection"`
	CommunicationSecurity bool     `json:"communication_security"`
	LocalDataEncryption   bool     `json:"local_data_encryption"`
	ZeroTrustSupport      bool     `json:"zero_trust_support"`
	SupportedAlgorithms   []string `json:"supported_algorithms"`
}

// ResourceUsage represents resource usage information
type ResourceUsage struct {
	CPU        CPUUsage        `json:"cpu"`
	Memory     MemoryUsage     `json:"memory"`
	Disk       DiskUsage       `json:"disk"`
	Network    NetworkUsage    `json:"network"`
	Threads    ThreadUsage     `json:"threads"`
	LastUpdate time.Time       `json:"last_update"`
	History    []UsageSnapshot `json:"history"`
}

// CPUUsage represents CPU usage information
type CPUUsage struct {
	CurrentPercent float64 `json:"current_percent"`
	AveragePercent float64 `json:"average_percent"`
	PeakPercent    float64 `json:"peak_percent"`
	CoreCount      int     `json:"core_count"`
	ThreadCount    int     `json:"thread_count"`
}

// MemoryUsage represents memory usage information
type MemoryUsage struct {
	CurrentMB       float64 `json:"current_mb"`
	PeakMB          float64 `json:"peak_mb"`
	VirtualMB       float64 `json:"virtual_mb"`
	WorkingSetMB    float64 `json:"working_set_mb"`
	PrivateBytesMB  float64 `json:"private_bytes_mb"`
	PageFaults      uint64  `json:"page_faults"`
	PageFileUsageMB float64 `json:"page_file_usage_mb"`
}

// DiskUsage represents disk usage information
type DiskUsage struct {
	CurrentMB    float64 `json:"current_mb"`
	TotalReadMB  float64 `json:"total_read_mb"`
	TotalWriteMB float64 `json:"total_write_mb"`
	ReadOps      uint64  `json:"read_ops"`
	WriteOps     uint64  `json:"write_ops"`
	IOWaitTime   float64 `json:"io_wait_time"`
}

// NetworkUsage represents network usage information
type NetworkUsage struct {
	BytesIn           uint64           `json:"bytes_in"`
	BytesOut          uint64           `json:"bytes_out"`
	PacketsIn         uint64           `json:"packets_in"`
	PacketsOut        uint64           `json:"packets_out"`
	ConnectionCount   int              `json:"connection_count"`
	ActiveConnections []ConnectionInfo `json:"active_connections"`
	ThroughputMbps    float64          `json:"throughput_mbps"`
}

// ConnectionInfo represents network connection information
type ConnectionInfo struct {
	LocalAddress  string    `json:"local_address"`
	RemoteAddress string    `json:"remote_address"`
	Protocol      string    `json:"protocol"`
	State         string    `json:"state"`
	ProcessID     int       `json:"process_id"`
	ProcessName   string    `json:"process_name"`
	EstablishedAt time.Time `json:"established_at"`
}

// ThreadUsage represents thread usage information
type ThreadUsage struct {
	ThreadCount   int     `json:"thread_count"`
	ActiveThreads int     `json:"active_threads"`
	CPUTime       float64 `json:"cpu_time"`
	UserTime      float64 `json:"user_time"`
	KernelTime    float64 `json:"kernel_time"`
}

// UsageSnapshot represents a point-in-time usage snapshot
type UsageSnapshot struct {
	Timestamp    time.Time `json:"timestamp"`
	CPUPercent   float64   `json:"cpu_percent"`
	MemoryMB     float64   `json:"memory_mb"`
	DiskMB       float64   `json:"disk_mb"`
	NetworkMbps  float64   `json:"network_mbps"`
	ThreadCount  int       `json:"thread_count"`
	EventsPerSec float64   `json:"events_per_sec"`
}

// AgentConfiguration represents agent configuration
type AgentConfiguration struct {
	Version        string                 `json:"version"`
	Hash           string                 `json:"hash"`
	LastUpdated    time.Time              `json:"last_updated"`
	UpdatedBy      string                 `json:"updated_by"`
	Settings       map[string]interface{} `json:"settings"`
	PolicySettings PolicySettings         `json:"policy_settings"`
	FeatureFlags   map[string]bool        `json:"feature_flags"`
	CustomSettings map[string]interface{} `json:"custom_settings"`
}

// PolicySettings represents policy configuration
type PolicySettings struct {
	EnabledPolicies []string               `json:"enabled_policies"`
	PolicyConfig    map[string]interface{} `json:"policy_config"`
	EnforcementMode string                 `json:"enforcement_mode"`
	AlertThresholds map[string]float64     `json:"alert_thresholds"`
	CustomRules     []CustomRule           `json:"custom_rules"`
}

// CustomRule represents a custom security rule
type CustomRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    RuleSeverity           `json:"severity"`
	Conditions  []RuleCondition        `json:"conditions"`
	Actions     []RuleAction           `json:"actions"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RuleSeverity represents rule severity levels
type RuleSeverity string

const (
	RuleSeverityCritical RuleSeverity = "critical"
	RuleSeverityHigh     RuleSeverity = "high"
	RuleSeverityMedium   RuleSeverity = "medium"
	RuleSeverityLow      RuleSeverity = "low"
	RuleSeverityInfo     RuleSeverity = "info"
)

// RuleCondition represents a rule condition
type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Type     string      `json:"type"`
}

// RuleAction represents a rule action
type RuleAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

// CertificateInfo represents certificate information
type CertificateInfo struct {
	ClientCertificate ClientCertInfo `json:"client_certificate"`
	TrustedCerts      []TrustedCert  `json:"trusted_certs"`
	CertificateChain  []CertInfo     `json:"certificate_chain"`
	LastValidation    time.Time      `json:"last_validation"`
	ExpirationAlert   bool           `json:"expiration_alert"`
}

// ClientCertInfo represents client certificate information
type ClientCertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	Fingerprint        string    `json:"fingerprint"`
	ValidFrom          time.Time `json:"valid_from"`
	ValidTo            time.Time `json:"valid_to"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	IsValid            bool      `json:"is_valid"`
	Path               string    `json:"path"`
}

// TrustedCert represents a trusted certificate
type TrustedCert struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	ValidTo     time.Time `json:"valid_to"`
	Purpose     string    `json:"purpose"`
	TrustLevel  string    `json:"trust_level"`
	IsActive    bool      `json:"is_active"`
}

// CertInfo represents general certificate information
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Fingerprint string    `json:"fingerprint"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidTo     time.Time `json:"valid_to"`
	IsValidNow  bool      `json:"is_valid_now"`
}

// NewAgent creates a new Agent instance
func NewAgent(name, platform, architecture, hostname string) *Agent {
	now := time.Now()
	return &Agent{
		ID:           uuid.New().String(),
		Name:         name,
		Platform:     platform,
		Architecture: architecture,
		Hostname:     hostname,
		Status:       AgentStatusRegistering,
		RegisteredAt: now,
		UpdatedAt:    now,
		Tags:         make([]string, 0),
		Metadata:     make(map[string]interface{}),
		Health: AgentHealth{
			Overall:    HealthStatusUnknown,
			Components: make(map[string]HealthStatus),
			Issues:     make([]HealthIssue, 0),
		},
		SecurityState: SecurityState{
			SecurityViolations: make([]SecurityViolation, 0),
			ThreatLevel:        ThreatLevelNone,
		},
		Capabilities: AgentCapabilities{},
		ResourceUsage: ResourceUsage{
			History: make([]UsageSnapshot, 0),
		},
	}
}

// UpdateStatus updates the agent status
func (a *Agent) UpdateStatus(status AgentStatus) {
	a.Status = status
	a.UpdatedAt = time.Now()
}

// UpdateHealth updates the agent health information
func (a *Agent) UpdateHealth(health AgentHealth) {
	a.Health = health
	a.UpdatedAt = time.Now()
}

// AddSecurityViolation adds a new security violation
func (a *Agent) AddSecurityViolation(violation SecurityViolation) {
	a.SecurityState.SecurityViolations = append(a.SecurityState.SecurityViolations, violation)
	a.UpdatedAt = time.Now()

	// Update threat level based on violation severity
	a.updateThreatLevel()
}

// updateThreatLevel updates the threat level based on active violations
func (a *Agent) updateThreatLevel() {
	highestLevel := ThreatLevelNone

	for _, violation := range a.SecurityState.SecurityViolations {
		if violation.ResolvedAt != nil {
			continue // Skip resolved violations
		}

		var level ThreatLevel
		switch violation.Severity {
		case ViolationSeverityCritical:
			level = ThreatLevelCritical
		case ViolationSeverityHigh:
			level = ThreatLevelHigh
		case ViolationSeverityMedium:
			level = ThreatLevelMedium
		case ViolationSeverityLow:
			level = ThreatLevelLow
		}

		if level > highestLevel {
			highestLevel = level
		}
	}

	a.SecurityState.ThreatLevel = highestLevel
}

// UpdateResourceUsage updates the resource usage information
func (a *Agent) UpdateResourceUsage(usage ResourceUsage) {
	// Add current usage to history
	snapshot := UsageSnapshot{
		Timestamp:   time.Now(),
		CPUPercent:  usage.CPU.CurrentPercent,
		MemoryMB:    usage.Memory.CurrentMB,
		DiskMB:      usage.Disk.CurrentMB,
		NetworkMbps: usage.Network.ThroughputMbps,
		ThreadCount: usage.Threads.ThreadCount,
	}

	// Keep only last 100 snapshots
	a.ResourceUsage.History = append(a.ResourceUsage.History, snapshot)
	if len(a.ResourceUsage.History) > 100 {
		a.ResourceUsage.History = a.ResourceUsage.History[1:]
	}

	a.ResourceUsage = usage
	a.UpdatedAt = time.Now()
}

// IsOnline returns true if the agent is considered online
func (a *Agent) IsOnline() bool {
	return a.Status == AgentStatusActive &&
		time.Since(a.LastHeartbeat) < 5*time.Minute
}

// IsHealthy returns true if the agent is healthy
func (a *Agent) IsHealthy() bool {
	return a.Health.Overall == HealthStatusHealthy
}

// HasActiveViolations returns true if there are unresolved security violations
func (a *Agent) HasActiveViolations() bool {
	for _, violation := range a.SecurityState.SecurityViolations {
		if violation.ResolvedAt == nil {
			return true
		}
	}
	return false
}

// GetActiveViolations returns all unresolved security violations
func (a *Agent) GetActiveViolations() []SecurityViolation {
	var active []SecurityViolation
	for _, violation := range a.SecurityState.SecurityViolations {
		if violation.ResolvedAt == nil {
			active = append(active, violation)
		}
	}
	return active
}

// UpdateConfigHash updates the configuration hash
func (a *Agent) UpdateConfigHash(config []byte) {
	hash := sha256.Sum256(config)
	a.ConfigHash = hex.EncodeToString(hash[:])
	a.UpdatedAt = time.Now()
}

// Heartbeat updates the last heartbeat timestamp
func (a *Agent) Heartbeat() {
	a.LastHeartbeat = time.Now()
	a.LastSeen = time.Now()
	if a.Status == AgentStatusInactive {
		a.Status = AgentStatusActive
	}
	a.UpdatedAt = time.Now()
}

// Validate validates the agent entity
func (a *Agent) Validate() error {
	if a.ID == "" {
		return ErrInvalidAgentID
	}
	if a.Name == "" {
		return ErrInvalidAgentName
	}
	if a.Platform == "" {
		return ErrInvalidPlatform
	}
	if a.Hostname == "" {
		return ErrInvalidHostname
	}
	return nil
}

// Custom errors
var (
	ErrInvalidAgentID   = fmt.Errorf("invalid agent ID")
	ErrInvalidAgentName = fmt.Errorf("invalid agent name")
	ErrInvalidPlatform  = fmt.Errorf("invalid platform")
	ErrInvalidHostname  = fmt.Errorf("invalid hostname")
)
