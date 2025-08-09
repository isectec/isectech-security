package entity

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ThreatType represents different types of threats
type ThreatType string

const (
	ThreatTypeMalware              ThreatType = "malware"
	ThreatTypePhishing             ThreatType = "phishing"
	ThreatTypeExfiltration         ThreatType = "data_exfiltration"
	ThreatTypeLateralMovement      ThreatType = "lateral_movement"
	ThreatTypePrivilegeEscalation  ThreatType = "privilege_escalation"
	ThreatTypePersistence          ThreatType = "persistence"
	ThreatTypeCommandControl       ThreatType = "command_control"
	ThreatTypeReconnaissance       ThreatType = "reconnaissance"
	ThreatTypeImpact               ThreatType = "impact"
	ThreatTypeDenialOfService      ThreatType = "denial_of_service"
	ThreatTypeAnomalousActivity    ThreatType = "anomalous_activity"
	ThreatTypeUnauthorizedAccess   ThreatType = "unauthorized_access"
	ThreatTypeSuspiciousNetwork    ThreatType = "suspicious_network"
	ThreatTypeVulnerabilityExploit ThreatType = "vulnerability_exploit"
	ThreatTypeInsiderThreat        ThreatType = "insider_threat"
	ThreatTypeUnknown              ThreatType = "unknown"
)

// ThreatSeverity represents the severity level of a threat
type ThreatSeverity string

const (
	ThreatSeverityCritical ThreatSeverity = "critical"
	ThreatSeverityHigh     ThreatSeverity = "high"
	ThreatSeverityMedium   ThreatSeverity = "medium"
	ThreatSeverityLow      ThreatSeverity = "low"
	ThreatSeverityInfo     ThreatSeverity = "info"
)

// ThreatStatus represents the current status of a threat
type ThreatStatus string

const (
	ThreatStatusActive      ThreatStatus = "active"
	ThreatStatusInvestigating ThreatStatus = "investigating"
	ThreatStatusContained   ThreatStatus = "contained"
	ThreatStatusMitigated   ThreatStatus = "mitigated"
	ThreatStatusResolved    ThreatStatus = "resolved"
	ThreatStatusFalsePositive ThreatStatus = "false_positive"
	ThreatStatusSuppressed  ThreatStatus = "suppressed"
)

// ThreatConfidence represents the confidence level in threat detection
type ThreatConfidence string

const (
	ThreatConfidenceHigh   ThreatConfidence = "high"
	ThreatConfidenceMedium ThreatConfidence = "medium"
	ThreatConfidenceLow    ThreatConfidence = "low"
)

// Threat represents a security threat detected in the system
type Threat struct {
	ID          uuid.UUID        `json:"id" bson:"_id"`
	TenantID    uuid.UUID        `json:"tenant_id" bson:"tenant_id"`
	Name        string           `json:"name" bson:"name"`
	Description string           `json:"description" bson:"description"`
	Type        ThreatType       `json:"type" bson:"type"`
	Severity    ThreatSeverity   `json:"severity" bson:"severity"`
	Status      ThreatStatus     `json:"status" bson:"status"`
	Confidence  ThreatConfidence `json:"confidence" bson:"confidence"`

	// Risk Assessment
	RiskScore         float64 `json:"risk_score" bson:"risk_score"`
	ImpactScore       float64 `json:"impact_score" bson:"impact_score"`
	LikelihoodScore   float64 `json:"likelihood_score" bson:"likelihood_score"`
	BusinessImpact    string  `json:"business_impact" bson:"business_impact"`

	// Detection Information
	DetectionEngine   string    `json:"detection_engine" bson:"detection_engine"`
	DetectionRule     string    `json:"detection_rule" bson:"detection_rule"`
	DetectionMethod   string    `json:"detection_method" bson:"detection_method"`
	DetectedAt        time.Time `json:"detected_at" bson:"detected_at"`
	FirstSeen         time.Time `json:"first_seen" bson:"first_seen"`
	LastSeen          time.Time `json:"last_seen" bson:"last_seen"`

	// MITRE ATT&CK Framework
	MITREAttack *MITREAttackInfo `json:"mitre_attack,omitempty" bson:"mitre_attack,omitempty"`

	// Source Information
	SourceInfo *ThreatSourceInfo `json:"source_info,omitempty" bson:"source_info,omitempty"`

	// Target Information
	TargetInfo *ThreatTargetInfo `json:"target_info,omitempty" bson:"target_info,omitempty"`

	// IOCs (Indicators of Compromise)
	IOCs []IndicatorOfCompromise `json:"iocs,omitempty" bson:"iocs,omitempty"`

	// Network Information
	NetworkInfo *ThreatNetworkInfo `json:"network_info,omitempty" bson:"network_info,omitempty"`

	// Evidence and Artifacts
	Evidence []ThreatEvidence `json:"evidence,omitempty" bson:"evidence,omitempty"`

	// Related Events and Entities
	RelatedEvents []RelatedEvent `json:"related_events,omitempty" bson:"related_events,omitempty"`
	RelatedAssets []uuid.UUID    `json:"related_assets,omitempty" bson:"related_assets,omitempty"`
	
	// Timeline and Context
	Timeline []ThreatTimelineEvent `json:"timeline,omitempty" bson:"timeline,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`

	// Response Information
	ResponseActions []ResponseAction `json:"response_actions,omitempty" bson:"response_actions,omitempty"`
	AssignedTo      string          `json:"assigned_to,omitempty" bson:"assigned_to,omitempty"`
	IncidentID      *uuid.UUID      `json:"incident_id,omitempty" bson:"incident_id,omitempty"`

	// Metadata
	Tags        []string          `json:"tags,omitempty" bson:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" bson:"labels,omitempty"`
	Source      string            `json:"source" bson:"source"`
	Fingerprint string            `json:"fingerprint" bson:"fingerprint"`
	
	// Timestamps
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
	
	// Versioning and Concurrency
	Version int `json:"version" bson:"version"`
}

// MITREAttackInfo contains MITRE ATT&CK framework information
type MITREAttackInfo struct {
	TacticIDs    []string `json:"tactic_ids" bson:"tactic_ids"`
	TacticNames  []string `json:"tactic_names" bson:"tactic_names"`
	TechniqueIDs []string `json:"technique_ids" bson:"technique_ids"`
	TechniqueNames []string `json:"technique_names" bson:"technique_names"`
	SubTechniqueIDs []string `json:"sub_technique_ids,omitempty" bson:"sub_technique_ids,omitempty"`
	KillChainPhases []string `json:"kill_chain_phases" bson:"kill_chain_phases"`
}

// ThreatSourceInfo contains information about the threat source
type ThreatSourceInfo struct {
	SourceIP     string   `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
	SourcePort   int      `json:"source_port,omitempty" bson:"source_port,omitempty"`
	SourceHosts  []string `json:"source_hosts,omitempty" bson:"source_hosts,omitempty"`
	SourceUser   string   `json:"source_user,omitempty" bson:"source_user,omitempty"`
	SourceAsset  *uuid.UUID `json:"source_asset,omitempty" bson:"source_asset,omitempty"`
	Country      string   `json:"country,omitempty" bson:"country,omitempty"`
	Organization string   `json:"organization,omitempty" bson:"organization,omitempty"`
	ISP          string   `json:"isp,omitempty" bson:"isp,omitempty"`
	ASN          string   `json:"asn,omitempty" bson:"asn,omitempty"`
	Reputation   *ReputationInfo `json:"reputation,omitempty" bson:"reputation,omitempty"`
}

// ThreatTargetInfo contains information about the threat target
type ThreatTargetInfo struct {
	TargetIP     string     `json:"target_ip,omitempty" bson:"target_ip,omitempty"`
	TargetPort   int        `json:"target_port,omitempty" bson:"target_port,omitempty"`
	TargetHosts  []string   `json:"target_hosts,omitempty" bson:"target_hosts,omitempty"`
	TargetUser   string     `json:"target_user,omitempty" bson:"target_user,omitempty"`
	TargetAsset  *uuid.UUID `json:"target_asset,omitempty" bson:"target_asset,omitempty"`
	Service      string     `json:"service,omitempty" bson:"service,omitempty"`
	Protocol     string     `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Application  string     `json:"application,omitempty" bson:"application,omitempty"`
}

// ReputationInfo contains reputation information for IPs, domains, etc.
type ReputationInfo struct {
	Score         float64   `json:"score" bson:"score"`
	Provider      string    `json:"provider" bson:"provider"`
	Categories    []string  `json:"categories,omitempty" bson:"categories,omitempty"`
	LastUpdated   time.Time `json:"last_updated" bson:"last_updated"`
	IsMalicious   bool      `json:"is_malicious" bson:"is_malicious"`
	IsSuspicious  bool      `json:"is_suspicious" bson:"is_suspicious"`
}

// IndicatorOfCompromise represents an IOC
type IndicatorOfCompromise struct {
	ID           uuid.UUID     `json:"id" bson:"id"`
	Type         IOCType       `json:"type" bson:"type"`
	Value        string        `json:"value" bson:"value"`
	Description  string        `json:"description,omitempty" bson:"description,omitempty"`
	Confidence   float64       `json:"confidence" bson:"confidence"`
	FirstSeen    time.Time     `json:"first_seen" bson:"first_seen"`
	LastSeen     time.Time     `json:"last_seen" bson:"last_seen"`
	Source       string        `json:"source" bson:"source"`
	Tags         []string      `json:"tags,omitempty" bson:"tags,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
}

// IOCType represents different types of IOCs
type IOCType string

const (
	IOCTypeIP           IOCType = "ip_address"
	IOCTypeDomain       IOCType = "domain"
	IOCTypeURL          IOCType = "url"
	IOCTypeFileHash     IOCType = "file_hash"
	IOCTypeFileName     IOCType = "file_name"
	IOCTypeFilePath     IOCType = "file_path"
	IOCTypeRegistry     IOCType = "registry_key"
	IOCTypeMutex        IOCType = "mutex"
	IOCTypeEmail        IOCType = "email"
	IOCTypeUserAgent    IOCType = "user_agent"
	IOCTypeCertificate  IOCType = "certificate"
	IOCTypeJA3          IOCType = "ja3_fingerprint"
	IOCTypeYARA         IOCType = "yara_rule"
	IOCTypeSigma        IOCType = "sigma_rule"
)

// ThreatNetworkInfo contains network-related threat information
type ThreatNetworkInfo struct {
	Protocol         string            `json:"protocol,omitempty" bson:"protocol,omitempty"`
	SourceIP         string            `json:"source_ip,omitempty" bson:"source_ip,omitempty"`
	DestinationIP    string            `json:"destination_ip,omitempty" bson:"destination_ip,omitempty"`
	SourcePort       int               `json:"source_port,omitempty" bson:"source_port,omitempty"`
	DestinationPort  int               `json:"destination_port,omitempty" bson:"destination_port,omitempty"`
	BytesTransferred int64             `json:"bytes_transferred,omitempty" bson:"bytes_transferred,omitempty"`
	PacketCount      int64             `json:"packet_count,omitempty" bson:"packet_count,omitempty"`
	Duration         time.Duration     `json:"duration,omitempty" bson:"duration,omitempty"`
	Direction        string            `json:"direction,omitempty" bson:"direction,omitempty"`
	ConnectionState  string            `json:"connection_state,omitempty" bson:"connection_state,omitempty"`
	DNSQueries       []string          `json:"dns_queries,omitempty" bson:"dns_queries,omitempty"`
	HTTPDetails      *HTTPDetails      `json:"http_details,omitempty" bson:"http_details,omitempty"`
	TLSDetails       *TLSDetails       `json:"tls_details,omitempty" bson:"tls_details,omitempty"`
	Payloads         []NetworkPayload  `json:"payloads,omitempty" bson:"payloads,omitempty"`
}

// HTTPDetails contains HTTP-specific threat information
type HTTPDetails struct {
	Method     string            `json:"method,omitempty" bson:"method,omitempty"`
	URI        string            `json:"uri,omitempty" bson:"uri,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty" bson:"user_agent,omitempty"`
	Referer    string            `json:"referer,omitempty" bson:"referer,omitempty"`
	StatusCode int               `json:"status_code,omitempty" bson:"status_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty" bson:"headers,omitempty"`
	Body       string            `json:"body,omitempty" bson:"body,omitempty"`
}

// TLSDetails contains TLS-specific threat information
type TLSDetails struct {
	Version           string   `json:"version,omitempty" bson:"version,omitempty"`
	CipherSuite       string   `json:"cipher_suite,omitempty" bson:"cipher_suite,omitempty"`
	SNI               string   `json:"sni,omitempty" bson:"sni,omitempty"`
	Certificate       *TLSCert `json:"certificate,omitempty" bson:"certificate,omitempty"`
	JA3Fingerprint    string   `json:"ja3_fingerprint,omitempty" bson:"ja3_fingerprint,omitempty"`
	JA3SFingerprint   string   `json:"ja3s_fingerprint,omitempty" bson:"ja3s_fingerprint,omitempty"`
}

// TLSCert contains TLS certificate information
type TLSCert struct {
	Subject      string    `json:"subject,omitempty" bson:"subject,omitempty"`
	Issuer       string    `json:"issuer,omitempty" bson:"issuer,omitempty"`
	SerialNumber string    `json:"serial_number,omitempty" bson:"serial_number,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty" bson:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty" bson:"not_after,omitempty"`
	Fingerprint  string    `json:"fingerprint,omitempty" bson:"fingerprint,omitempty"`
}

// NetworkPayload contains network payload information
type NetworkPayload struct {
	Size        int64     `json:"size" bson:"size"`
	Hash        string    `json:"hash" bson:"hash"`
	Encoding    string    `json:"encoding,omitempty" bson:"encoding,omitempty"`
	ContentType string    `json:"content_type,omitempty" bson:"content_type,omitempty"`
	Data        []byte    `json:"data,omitempty" bson:"data,omitempty"`
	Timestamp   time.Time `json:"timestamp" bson:"timestamp"`
}

// ThreatEvidence represents evidence associated with a threat
type ThreatEvidence struct {
	ID          uuid.UUID              `json:"id" bson:"id"`
	Type        EvidenceType           `json:"type" bson:"type"`
	Description string                 `json:"description" bson:"description"`
	Value       string                 `json:"value" bson:"value"`
	Source      string                 `json:"source" bson:"source"`
	CollectedAt time.Time              `json:"collected_at" bson:"collected_at"`
	Hash        string                 `json:"hash,omitempty" bson:"hash,omitempty"`
	Size        int64                  `json:"size,omitempty" bson:"size,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// EvidenceType represents different types of evidence
type EvidenceType string

const (
	EvidenceTypeLog          EvidenceType = "log"
	EvidenceTypeFile         EvidenceType = "file"
	EvidenceTypeMemoryDump   EvidenceType = "memory_dump"
	EvidenceTypeNetworkPcap  EvidenceType = "network_pcap"
	EvidenceTypeRegistry     EvidenceType = "registry"
	EvidenceTypeProcess      EvidenceType = "process"
	EvidenceTypeDiskImage    EvidenceType = "disk_image"
	EvidenceTypeScreenshot   EvidenceType = "screenshot"
	EvidenceTypeConfig       EvidenceType = "configuration"
	EvidenceTypeMetrics      EvidenceType = "metrics"
)

// RelatedEvent represents events related to a threat
type RelatedEvent struct {
	EventID     uuid.UUID              `json:"event_id" bson:"event_id"`
	EventType   string                 `json:"event_type" bson:"event_type"`
	Source      string                 `json:"source" bson:"source"`
	Timestamp   time.Time              `json:"timestamp" bson:"timestamp"`
	Correlation float64                `json:"correlation" bson:"correlation"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// ThreatTimelineEvent represents an event in the threat timeline
type ThreatTimelineEvent struct {
	Timestamp   time.Time              `json:"timestamp" bson:"timestamp"`
	Action      string                 `json:"action" bson:"action"`
	Actor       string                 `json:"actor" bson:"actor"`
	Description string                 `json:"description" bson:"description"`
	Details     map[string]interface{} `json:"details,omitempty" bson:"details,omitempty"`
}

// ResponseAction represents an action taken in response to a threat
type ResponseAction struct {
	ID          uuid.UUID              `json:"id" bson:"id"`
	Type        ResponseActionType     `json:"type" bson:"type"`
	Status      ResponseActionStatus   `json:"status" bson:"status"`
	Description string                 `json:"description" bson:"description"`
	PerformedBy string                 `json:"performed_by" bson:"performed_by"`
	PerformedAt time.Time              `json:"performed_at" bson:"performed_at"`
	Result      string                 `json:"result,omitempty" bson:"result,omitempty"`
	Evidence    []uuid.UUID            `json:"evidence,omitempty" bson:"evidence,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// ResponseActionType represents different types of response actions
type ResponseActionType string

const (
	ResponseActionBlock      ResponseActionType = "block"
	ResponseActionQuarantine ResponseActionType = "quarantine"
	ResponseActionIsolate    ResponseActionType = "isolate"
	ResponseActionKill       ResponseActionType = "kill_process"
	ResponseActionSandbox    ResponseActionType = "sandbox"
	ResponseActionNotify     ResponseActionType = "notify"
	ResponseActionEscalate   ResponseActionType = "escalate"
	ResponseActionCollect    ResponseActionType = "collect_evidence"
	ResponseActionAnalyze    ResponseActionType = "analyze"
	ResponseActionPatch      ResponseActionType = "patch"
	ResponseActionReset      ResponseActionType = "reset_credentials"
	ResponseActionMonitor    ResponseActionType = "monitor"
)

// ResponseActionStatus represents the status of a response action
type ResponseActionStatus string

const (
	ResponseActionStatusPending   ResponseActionStatus = "pending"
	ResponseActionStatusExecuting ResponseActionStatus = "executing"
	ResponseActionStatusCompleted ResponseActionStatus = "completed"
	ResponseActionStatusFailed    ResponseActionStatus = "failed"
	ResponseActionStatusCancelled ResponseActionStatus = "cancelled"
)

// Validation methods

// Validate validates the threat entity
func (t *Threat) Validate() error {
	if t.ID == uuid.Nil {
		return fmt.Errorf("threat ID is required")
	}
	
	if t.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}
	
	if t.Name == "" {
		return fmt.Errorf("threat name is required")
	}
	
	if t.Type == "" {
		return fmt.Errorf("threat type is required")
	}
	
	if t.Severity == "" {
		return fmt.Errorf("threat severity is required")
	}
	
	if t.Status == "" {
		return fmt.Errorf("threat status is required")
	}
	
	if t.DetectedAt.IsZero() {
		return fmt.Errorf("detection time is required")
	}
	
	if t.RiskScore < 0 || t.RiskScore > 10 {
		return fmt.Errorf("risk score must be between 0 and 10")
	}
	
	return nil
}

// CalculateRiskScore calculates the risk score based on impact and likelihood
func (t *Threat) CalculateRiskScore() {
	// Risk Score = Impact Score × Likelihood Score
	t.RiskScore = t.ImpactScore * t.LikelihoodScore
	
	// Normalize to 0-10 scale
	if t.RiskScore > 10 {
		t.RiskScore = 10
	}
}

// UpdateStatus updates the threat status and adds a timeline event
func (t *Threat) UpdateStatus(newStatus ThreatStatus, actor, reason string) {
	oldStatus := t.Status
	t.Status = newStatus
	t.UpdatedAt = time.Now()
	t.Version++
	
	// Add timeline event
	event := ThreatTimelineEvent{
		Timestamp:   time.Now(),
		Action:      "status_update",
		Actor:       actor,
		Description: fmt.Sprintf("Status changed from %s to %s: %s", oldStatus, newStatus, reason),
		Details: map[string]interface{}{
			"old_status": string(oldStatus),
			"new_status": string(newStatus),
			"reason":     reason,
		},
	}
	
	t.Timeline = append(t.Timeline, event)
}

// AddEvidence adds evidence to the threat
func (t *Threat) AddEvidence(evidence ThreatEvidence) {
	t.Evidence = append(t.Evidence, evidence)
	t.UpdatedAt = time.Now()
	t.Version++
	
	// Add timeline event
	event := ThreatTimelineEvent{
		Timestamp:   time.Now(),
		Action:      "evidence_added",
		Actor:       "system",
		Description: fmt.Sprintf("Evidence added: %s", evidence.Description),
		Details: map[string]interface{}{
			"evidence_id":   evidence.ID.String(),
			"evidence_type": string(evidence.Type),
		},
	}
	
	t.Timeline = append(t.Timeline, event)
}

// AddResponseAction adds a response action to the threat
func (t *Threat) AddResponseAction(action ResponseAction) {
	t.ResponseActions = append(t.ResponseActions, action)
	t.UpdatedAt = time.Now()
	t.Version++
	
	// Add timeline event
	event := ThreatTimelineEvent{
		Timestamp:   time.Now(),
		Action:      "response_action_added",
		Actor:       action.PerformedBy,
		Description: fmt.Sprintf("Response action added: %s", action.Description),
		Details: map[string]interface{}{
			"action_id":   action.ID.String(),
			"action_type": string(action.Type),
			"status":      string(action.Status),
		},
	}
	
	t.Timeline = append(t.Timeline, event)
}

// GetSeverityNumeric returns a numeric representation of severity for scoring
func (t *Threat) GetSeverityNumeric() float64 {
	switch t.Severity {
	case ThreatSeverityCritical:
		return 5.0
	case ThreatSeverityHigh:
		return 4.0
	case ThreatSeverityMedium:
		return 3.0
	case ThreatSeverityLow:
		return 2.0
	case ThreatSeverityInfo:
		return 1.0
	default:
		return 1.0
	}
}

// GetConfidenceNumeric returns a numeric representation of confidence
func (t *Threat) GetConfidenceNumeric() float64 {
	switch t.Confidence {
	case ThreatConfidenceHigh:
		return 1.0
	case ThreatConfidenceMedium:
		return 0.7
	case ThreatConfidenceLow:
		return 0.4
	default:
		return 0.4
	}
}

// IsActive returns true if the threat is currently active
func (t *Threat) IsActive() bool {
	return t.Status == ThreatStatusActive || t.Status == ThreatStatusInvestigating
}

// GetAge returns the age of the threat since first detection
func (t *Threat) GetAge() time.Duration {
	return time.Since(t.FirstSeen)
}

// ToJSON converts the threat to JSON
func (t *Threat) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

// FromJSON creates a threat from JSON
func (t *Threat) FromJSON(data []byte) error {
	return json.Unmarshal(data, t)
}

// GetFingerprint generates a unique fingerprint for the threat
func (t *Threat) GetFingerprint() string {
	if t.Fingerprint != "" {
		return t.Fingerprint
	}
	
	// Generate fingerprint based on key threat characteristics
	fingerprint := fmt.Sprintf("%s:%s:%s:%s",
		t.Type,
		t.SourceInfo.SourceIP,
		t.TargetInfo.TargetIP,
		t.DetectionRule,
	)
	
	return fingerprint
}

// Merge merges another threat with this one (for correlation)
func (t *Threat) Merge(other *Threat) {
	// Update last seen
	if other.LastSeen.After(t.LastSeen) {
		t.LastSeen = other.LastSeen
	}
	
	// Merge IOCs
	for _, ioc := range other.IOCs {
		exists := false
		for _, existingIOC := range t.IOCs {
			if existingIOC.Value == ioc.Value && existingIOC.Type == ioc.Type {
				exists = true
				break
			}
		}
		if !exists {
			t.IOCs = append(t.IOCs, ioc)
		}
	}
	
	// Merge evidence
	for _, evidence := range other.Evidence {
		exists := false
		for _, existingEvidence := range t.Evidence {
			if existingEvidence.ID == evidence.ID {
				exists = true
				break
			}
		}
		if !exists {
			t.Evidence = append(t.Evidence, evidence)
		}
	}
	
	// Merge related events
	for _, event := range other.RelatedEvents {
		exists := false
		for _, existingEvent := range t.RelatedEvents {
			if existingEvent.EventID == event.EventID {
				exists = true
				break
			}
		}
		if !exists {
			t.RelatedEvents = append(t.RelatedEvents, event)
		}
	}
	
	// Update metadata
	t.UpdatedAt = time.Now()
	t.Version++
	
	// Add timeline event
	event := ThreatTimelineEvent{
		Timestamp:   time.Now(),
		Action:      "threat_merged",
		Actor:       "system",
		Description: fmt.Sprintf("Threat merged with %s", other.ID.String()),
		Details: map[string]interface{}{
			"merged_threat_id": other.ID.String(),
		},
	}
	
	t.Timeline = append(t.Timeline, event)
}