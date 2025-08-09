package entity

import (
	"time"

	"github.com/google/uuid"
)

// TenantType represents the type of tenant organization
type TenantType string

const (
	TenantTypeEnterprise    TenantType = "enterprise"     // Large enterprise organization
	TenantTypeGovernment    TenantType = "government"     // Government agency
	TenantTypeDefense       TenantType = "defense"        // Defense contractor/military
	TenantTypeCriticalInfra TenantType = "critical_infra" // Critical infrastructure provider
	TenantTypeFinancial     TenantType = "financial"      // Financial services
	TenantTypeHealthcare    TenantType = "healthcare"     // Healthcare organization
	TenantTypeMSP           TenantType = "msp"            // Managed Security Service Provider
	TenantTypeStartup       TenantType = "startup"        // Small business/startup
)

// TenantTier represents the service tier and feature access level
type TenantTier string

const (
	TenantTierEssential  TenantTier = "essential"  // Basic cybersecurity features
	TenantTierAdvanced   TenantTier = "advanced"   // Advanced threat detection
	TenantTierEnterprise TenantTier = "enterprise" // Full enterprise features
	TenantTierGovernment TenantTier = "government" // Government/defense features
)

// TenantStatus represents the current status of a tenant
type TenantStatus string

const (
	TenantStatusActive          TenantStatus = "active"          // Fully operational
	TenantStatusSuspended       TenantStatus = "suspended"       // Temporarily suspended
	TenantStatusDisabled        TenantStatus = "disabled"        // Disabled/deactivated
	TenantStatusProvisioning    TenantStatus = "provisioning"    // Being set up
	TenantStatusMigrating       TenantStatus = "migrating"       // Data migration in progress
	TenantStatusDecommissioning TenantStatus = "decommissioning" // Being decommissioned
)

// ComplianceFramework represents compliance requirements for the tenant
type ComplianceFramework string

const (
	ComplianceSOC2     ComplianceFramework = "soc2"
	ComplianceISO27001 ComplianceFramework = "iso27001"
	ComplianceNIST     ComplianceFramework = "nist"
	ComplianceFedRAMP  ComplianceFramework = "fedramp"
	ComplianceHIPAA    ComplianceFramework = "hipaa"
	CompliancePCI      ComplianceFramework = "pci"
	ComplianceGDPR     ComplianceFramework = "gdpr"
	ComplianceCCPA     ComplianceFramework = "ccpa"
	ComplianceFISMA    ComplianceFramework = "fisma"
)

// Tenant represents a multi-tenant organization in the iSECTECH platform
type Tenant struct {
	ID          uuid.UUID    `json:"id" db:"id"`
	Name        string       `json:"name" db:"name"`
	DisplayName string       `json:"display_name" db:"display_name"`
	Description string       `json:"description" db:"description"`
	Type        TenantType   `json:"type" db:"type"`
	Tier        TenantTier   `json:"tier" db:"tier"`
	Status      TenantStatus `json:"status" db:"status"`

	// Organization details
	Domain            string   `json:"domain" db:"domain"`                         // Primary domain (e.g., company.com)
	AdditionalDomains []string `json:"additional_domains" db:"additional_domains"` // Additional verified domains
	Industry          string   `json:"industry" db:"industry"`                     // Industry classification
	Country           string   `json:"country" db:"country"`                       // Primary country
	Timezone          string   `json:"timezone" db:"timezone"`                     // Default timezone

	// Security classification and clearance
	MaxSecurityClearance SecurityClearanceLevel `json:"max_security_clearance" db:"max_security_clearance"`
	DefaultClearance     SecurityClearanceLevel `json:"default_clearance" db:"default_clearance"`
	SecurityContext      *TenantSecurityContext `json:"security_context" db:"security_context"`

	// Compliance and regulatory requirements
	ComplianceFrameworks   []ComplianceFramework   `json:"compliance_frameworks" db:"compliance_frameworks"`
	DataResidencyRegions   []string                `json:"data_residency_regions" db:"data_residency_regions"`
	RetentionPolicies      *RetentionPolicies      `json:"retention_policies" db:"retention_policies"`
	EncryptionRequirements *EncryptionRequirements `json:"encryption_requirements" db:"encryption_requirements"`

	// Resource limits and quotas
	ResourceQuotas *TenantResourceQuotas `json:"resource_quotas" db:"resource_quotas"`
	FeatureFlags   map[string]bool       `json:"feature_flags" db:"feature_flags"`
	APIRateLimits  *APIRateLimits        `json:"api_rate_limits" db:"api_rate_limits"`

	// Customization and branding
	BrandingConfig      *TenantBrandingConfig  `json:"branding_config" db:"branding_config"`
	CustomSettings      map[string]interface{} `json:"custom_settings" db:"custom_settings"`
	IntegrationSettings *IntegrationSettings   `json:"integration_settings" db:"integration_settings"`

	// Network and access controls
	AllowedIPRanges  []string `json:"allowed_ip_ranges" db:"allowed_ip_ranges"`
	BlockedIPRanges  []string `json:"blocked_ip_ranges" db:"blocked_ip_ranges"`
	RequireVPN       bool     `json:"require_vpn" db:"require_vpn"`
	AllowedCountries []string `json:"allowed_countries" db:"allowed_countries"`

	// Billing and subscription
	SubscriptionID    *string    `json:"subscription_id" db:"subscription_id"`
	BillingEmail      string     `json:"billing_email" db:"billing_email"`
	ContractStartDate time.Time  `json:"contract_start_date" db:"contract_start_date"`
	ContractEndDate   *time.Time `json:"contract_end_date" db:"contract_end_date"`

	// Operational settings
	MaintenanceWindow *MaintenanceWindow `json:"maintenance_window" db:"maintenance_window"`
	SupportLevel      string             `json:"support_level" db:"support_level"`
	EmergencyContacts []EmergencyContact `json:"emergency_contacts" db:"emergency_contacts"`

	// Parent-child relationships for sub-organizations
	ParentTenantID    *uuid.UUID  `json:"parent_tenant_id" db:"parent_tenant_id"`
	ChildTenants      []uuid.UUID `json:"child_tenants" db:"child_tenants"`
	IsSubOrganization bool        `json:"is_sub_organization" db:"is_sub_organization"`

	// Audit and lifecycle
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
	ActivatedAt   *time.Time `json:"activated_at" db:"activated_at"`
	SuspendedAt   *time.Time `json:"suspended_at" db:"suspended_at"`
	DeactivatedAt *time.Time `json:"deactivated_at" db:"deactivated_at"`
	CreatedBy     uuid.UUID  `json:"created_by" db:"created_by"`
	UpdatedBy     uuid.UUID  `json:"updated_by" db:"updated_by"`
	Version       int        `json:"version" db:"version"`
}

// TenantSecurityContext represents security-specific configuration for a tenant
type TenantSecurityContext struct {
	ThreatIntelligenceLevel string                 `json:"threat_intelligence_level"` // basic, advanced, premium
	IncidentResponseTier    string                 `json:"incident_response_tier"`    // standard, priority, critical
	SecurityPolicies        map[string]interface{} `json:"security_policies"`         // Custom security policies
	RiskTolerance           string                 `json:"risk_tolerance"`            // low, medium, high
	AutoResponseEnabled     bool                   `json:"auto_response_enabled"`     // Enable automated response
	ThreatHuntingEnabled    bool                   `json:"threat_hunting_enabled"`    // Enable threat hunting
	ForensicsRetention      time.Duration          `json:"forensics_retention"`       // Forensics data retention
	AlertThresholds         map[string]float64     `json:"alert_thresholds"`          // Custom alert thresholds
}

// RetentionPolicies defines data retention requirements
type RetentionPolicies struct {
	AuditLogs       time.Duration `json:"audit_logs"`       // Audit log retention
	SecurityEvents  time.Duration `json:"security_events"`  // Security event retention
	ThreatData      time.Duration `json:"threat_data"`      // Threat intelligence retention
	IncidentData    time.Duration `json:"incident_data"`    // Incident response data retention
	ForensicsData   time.Duration `json:"forensics_data"`   // Digital forensics data retention
	BackupRetention time.Duration `json:"backup_retention"` // Backup data retention
	ArchivePolicy   string        `json:"archive_policy"`   // Archive policy (local, cloud, hybrid)
}

// EncryptionRequirements defines encryption standards for the tenant
type EncryptionRequirements struct {
	EncryptionAtRest       string `json:"encryption_at_rest"`       // AES-256, ChaCha20-Poly1305
	EncryptionInTransit    string `json:"encryption_in_transit"`    // TLS 1.3, FIPS 140-2
	KeyManagement          string `json:"key_management"`           // HSM, KMS, local
	CertificateAuthority   string `json:"certificate_authority"`    // Internal CA, public CA
	HardwareSecurityModule bool   `json:"hardware_security_module"` // Require HSM
	FIPSCompliance         bool   `json:"fips_compliance"`          // FIPS 140-2 compliance required
	QuantumResistant       bool   `json:"quantum_resistant"`        // Quantum-resistant algorithms
}

// TenantResourceQuotas defines resource limits for the tenant
type TenantResourceQuotas struct {
	MaxUsers           int   `json:"max_users"`            // Maximum user accounts
	MaxDevices         int   `json:"max_devices"`          // Maximum monitored devices
	MaxAlerts          int   `json:"max_alerts"`           // Maximum alerts per day
	MaxIncidents       int   `json:"max_incidents"`        // Maximum open incidents
	StorageQuotaGB     int64 `json:"storage_quota_gb"`     // Storage quota in GB
	BandwidthQuotaGB   int64 `json:"bandwidth_quota_gb"`   // Monthly bandwidth quota
	ComputeUnits       int   `json:"compute_units"`        // Allocated compute units
	ThreatIntelFeeds   int   `json:"threat_intel_feeds"`   // Max threat intel feeds
	CustomRules        int   `json:"custom_rules"`         // Max custom detection rules
	APICallsPerMinute  int   `json:"api_calls_per_minute"` // API rate limit
	ConcurrentSessions int   `json:"concurrent_sessions"`  // Max concurrent user sessions
}

// APIRateLimits defines API usage limits
type APIRateLimits struct {
	RequestsPerMinute  int `json:"requests_per_minute"` // Requests per minute
	RequestsPerHour    int `json:"requests_per_hour"`   // Requests per hour
	RequestsPerDay     int `json:"requests_per_day"`    // Requests per day
	BurstLimit         int `json:"burst_limit"`         // Burst request limit
	ConcurrentRequests int `json:"concurrent_requests"` // Max concurrent requests
}

// TenantBrandingConfig defines custom branding options
type TenantBrandingConfig struct {
	LogoURL              string            `json:"logo_url"`               // Custom logo URL
	FaviconURL           string            `json:"favicon_url"`            // Custom favicon URL
	PrimaryColor         string            `json:"primary_color"`          // Primary brand color
	SecondaryColor       string            `json:"secondary_color"`        // Secondary brand color
	CustomCSS            string            `json:"custom_css"`             // Custom CSS overrides
	CustomDomain         string            `json:"custom_domain"`          // Custom domain for portal
	CustomEmailTemplates map[string]string `json:"custom_email_templates"` // Custom email templates
	WhiteLabeling        bool              `json:"white_labeling"`         // Full white label mode
}

// IntegrationSettings defines external system integration configuration
type IntegrationSettings struct {
	SIEMIntegration      *SIEMIntegration      `json:"siem_integration"`      // SIEM integration settings
	SOARIntegration      *SOARIntegration      `json:"soar_integration"`      // SOAR platform integration
	TicketingIntegration *TicketingIntegration `json:"ticketing_integration"` // Ticketing system integration
	NotificationSettings *NotificationSettings `json:"notification_settings"` // Notification preferences
	WebhookEndpoints     []WebhookEndpoint     `json:"webhook_endpoints"`     // Custom webhook endpoints
}

// SIEMIntegration represents SIEM platform integration settings
type SIEMIntegration struct {
	Enabled      bool              `json:"enabled"`
	Platform     string            `json:"platform"` // splunk, qradar, sentinel, etc.
	Endpoint     string            `json:"endpoint"`
	APIKey       string            `json:"api_key"` // Encrypted
	Settings     map[string]string `json:"settings"`
	EventFilters []string          `json:"event_filters"` // Which events to forward
}

// SOARIntegration represents SOAR platform integration settings
type SOARIntegration struct {
	Enabled          bool              `json:"enabled"`
	Platform         string            `json:"platform"` // phantom, demisto, etc.
	Endpoint         string            `json:"endpoint"`
	APICredentials   string            `json:"api_credentials"`   // Encrypted
	PlaybookMappings map[string]string `json:"playbook_mappings"` // Incident type to playbook mapping
	AutoExecution    bool              `json:"auto_execution"`    // Auto-execute playbooks
}

// TicketingIntegration represents ticketing system integration
type TicketingIntegration struct {
	Enabled      bool              `json:"enabled"`
	Platform     string            `json:"platform"` // jira, servicenow, etc.
	Endpoint     string            `json:"endpoint"`
	Credentials  string            `json:"credentials"` // Encrypted
	ProjectKey   string            `json:"project_key"`
	IssueMapping map[string]string `json:"issue_mapping"` // Severity to issue type mapping
	AutoCreation bool              `json:"auto_creation"` // Auto-create tickets
}

// NotificationSettings defines notification preferences
type NotificationSettings struct {
	EmailNotifications  bool               `json:"email_notifications"`
	SlackIntegration    *SlackIntegration  `json:"slack_integration"`
	TeamsIntegration    *TeamsIntegration  `json:"teams_integration"`
	SMSNotifications    bool               `json:"sms_notifications"`
	PushNotifications   bool               `json:"push_notifications"`
	NotificationFilters []string           `json:"notification_filters"` // Which events to notify
	EscalationPolicies  []EscalationPolicy `json:"escalation_policies"`
}

// SlackIntegration represents Slack notification settings
type SlackIntegration struct {
	Enabled      bool     `json:"enabled"`
	WebhookURL   string   `json:"webhook_url"` // Encrypted
	Channels     []string `json:"channels"`
	UserMentions []string `json:"user_mentions"`
}

// TeamsIntegration represents Microsoft Teams notification settings
type TeamsIntegration struct {
	Enabled    bool     `json:"enabled"`
	WebhookURL string   `json:"webhook_url"` // Encrypted
	Channels   []string `json:"channels"`
}

// EscalationPolicy defines incident escalation rules
type EscalationPolicy struct {
	TriggerCondition    string   `json:"trigger_condition"`    // Condition that triggers escalation
	DelayMinutes        int      `json:"delay_minutes"`        // Minutes before escalation
	EscalateTo          []string `json:"escalate_to"`          // User IDs or groups to escalate to
	NotificationMethods []string `json:"notification_methods"` // email, sms, voice, etc.
}

// WebhookEndpoint represents a custom webhook endpoint
type WebhookEndpoint struct {
	ID          uuid.UUID         `json:"id"`
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Secret      string            `json:"secret"`  // Webhook secret for verification
	Events      []string          `json:"events"`  // Which events to send
	Headers     map[string]string `json:"headers"` // Custom headers
	Enabled     bool              `json:"enabled"`
	RetryPolicy *RetryPolicy      `json:"retry_policy"`
}

// RetryPolicy defines retry behavior for webhooks
type RetryPolicy struct {
	MaxRetries        int           `json:"max_retries"`
	RetryDelay        time.Duration `json:"retry_delay"`
	BackoffMultiplier float64       `json:"backoff_multiplier"`
}

// MaintenanceWindow defines scheduled maintenance periods
type MaintenanceWindow struct {
	DayOfWeek time.Weekday  `json:"day_of_week"` // Day of the week
	StartTime string        `json:"start_time"`  // Start time (HH:MM)
	EndTime   string        `json:"end_time"`    // End time (HH:MM)
	Timezone  string        `json:"timezone"`    // Timezone for the window
	Duration  time.Duration `json:"duration"`    // Maximum maintenance duration
	Enabled   bool          `json:"enabled"`     // Whether maintenance windows are enabled
}

// EmergencyContact represents an emergency contact for the tenant
type EmergencyContact struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Title          string    `json:"title"`
	Email          string    `json:"email"`
	Phone          string    `json:"phone"`
	AlternatePhone string    `json:"alternate_phone"`
	IsPrimary      bool      `json:"is_primary"`
	ContactType    string    `json:"contact_type"` // technical, business, legal, etc.
	Available24x7  bool      `json:"available_24x7"`
}

// TenantContext represents runtime context for tenant operations
type TenantContext struct {
	TenantID        uuid.UUID              `json:"tenant_id"`
	Tenant          *Tenant                `json:"tenant"`
	SecurityContext *TenantSecurityContext `json:"security_context"`
	UserID          *uuid.UUID             `json:"user_id"`
	SessionID       string                 `json:"session_id"`
	RequestID       string                 `json:"request_id"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent"`
	Timestamp       time.Time              `json:"timestamp"`
	FeatureFlags    map[string]bool        `json:"feature_flags"`
	ResourceQuotas  *TenantResourceQuotas  `json:"resource_quotas"`
}

// Methods for Tenant entity

// IsActive checks if the tenant is currently active
func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// IsGovernmentTenant checks if this is a government/defense tenant
func (t *Tenant) IsGovernmentTenant() bool {
	return t.Type == TenantTypeGovernment || t.Type == TenantTypeDefense
}

// HasComplianceFramework checks if the tenant requires a specific compliance framework
func (t *Tenant) HasComplianceFramework(framework ComplianceFramework) bool {
	for _, f := range t.ComplianceFrameworks {
		if f == framework {
			return true
		}
	}
	return false
}

// RequiresFIPSCompliance checks if the tenant requires FIPS compliance
func (t *Tenant) RequiresFIPSCompliance() bool {
	return t.EncryptionRequirements != nil && t.EncryptionRequirements.FIPSCompliance
}

// GetMaxSecurityClearance returns the maximum security clearance for the tenant
func (t *Tenant) GetMaxSecurityClearance() SecurityClearanceLevel {
	return t.MaxSecurityClearance
}

// IsIPAllowed checks if an IP address is allowed for this tenant
func (t *Tenant) IsIPAllowed(ipAddress string) bool {
	// Check blocked ranges first
	for _, blocked := range t.BlockedIPRanges {
		if ipInRange(ipAddress, blocked) {
			return false
		}
	}

	// If no allowed ranges specified, allow all (except blocked)
	if len(t.AllowedIPRanges) == 0 {
		return true
	}

	// Check if IP is in allowed ranges
	for _, allowed := range t.AllowedIPRanges {
		if ipInRange(ipAddress, allowed) {
			return true
		}
	}

	return false
}

// IsCountryAllowed checks if access from a country is allowed
func (t *Tenant) IsCountryAllowed(country string) bool {
	if len(t.AllowedCountries) == 0 {
		return true // No restrictions
	}

	for _, allowed := range t.AllowedCountries {
		if allowed == country {
			return true
		}
	}

	return false
}

// GetFeatureFlag returns the value of a feature flag
func (t *Tenant) GetFeatureFlag(flag string) bool {
	if t.FeatureFlags == nil {
		return false
	}
	return t.FeatureFlags[flag]
}

// IsInMaintenanceWindow checks if current time is within maintenance window
func (t *Tenant) IsInMaintenanceWindow(currentTime time.Time) bool {
	if t.MaintenanceWindow == nil || !t.MaintenanceWindow.Enabled {
		return false
	}

	// Load timezone
	loc, err := time.LoadLocation(t.MaintenanceWindow.Timezone)
	if err != nil {
		loc = time.UTC
	}

	localTime := currentTime.In(loc)

	// Check if it's the right day of week
	if localTime.Weekday() != t.MaintenanceWindow.DayOfWeek {
		return false
	}

	// Check if it's within the time window
	timeStr := localTime.Format("15:04")
	return timeStr >= t.MaintenanceWindow.StartTime && timeStr <= t.MaintenanceWindow.EndTime
}

// GetPrimaryEmergencyContact returns the primary emergency contact
func (t *Tenant) GetPrimaryEmergencyContact() *EmergencyContact {
	for _, contact := range t.EmergencyContacts {
		if contact.IsPrimary {
			return &contact
		}
	}
	return nil
}

// UpdateResourceUsage updates resource usage tracking
func (t *Tenant) UpdateResourceUsage(metric string, value int64) {
	// Implementation would update usage tracking
	// This is a placeholder for resource usage monitoring
}

// Helper functions

// ipInRange checks if an IP address is within a CIDR range
func ipInRange(ipAddress, cidrRange string) bool {
	// Simplified implementation - in production, use net.ParseCIDR
	// This is a placeholder for proper CIDR checking
	return ipAddress == cidrRange
}

// Validation functions

// ValidateTenantType checks if the tenant type is valid
func ValidateTenantType(tenantType string) bool {
	switch TenantType(tenantType) {
	case TenantTypeEnterprise, TenantTypeGovernment, TenantTypeDefense,
		TenantTypeCriticalInfra, TenantTypeFinancial, TenantTypeHealthcare,
		TenantTypeMSP, TenantTypeStartup:
		return true
	default:
		return false
	}
}

// ValidateTenantTier checks if the tenant tier is valid
func ValidateTenantTier(tier string) bool {
	switch TenantTier(tier) {
	case TenantTierEssential, TenantTierAdvanced, TenantTierEnterprise, TenantTierGovernment:
		return true
	default:
		return false
	}
}

// ValidateTenantStatus checks if the tenant status is valid
func ValidateTenantStatus(status string) bool {
	switch TenantStatus(status) {
	case TenantStatusActive, TenantStatusSuspended, TenantStatusDisabled,
		TenantStatusProvisioning, TenantStatusMigrating, TenantStatusDecommissioning:
		return true
	default:
		return false
	}
}

// ValidateComplianceFramework checks if the compliance framework is valid
func ValidateComplianceFramework(framework string) bool {
	switch ComplianceFramework(framework) {
	case ComplianceSOC2, ComplianceISO27001, ComplianceNIST, ComplianceFedRAMP,
		ComplianceHIPAA, CompliancePCI, ComplianceGDPR, ComplianceCCPA, ComplianceFISMA:
		return true
	default:
		return false
	}
}
