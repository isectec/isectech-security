package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
)

// TenantService defines the interface for tenant management operations
type TenantService interface {
	// Tenant lifecycle management
	CreateTenant(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error)
	UpdateTenant(ctx context.Context, req *UpdateTenantRequest) error
	DeleteTenant(ctx context.Context, tenantID uuid.UUID) error
	GetTenant(ctx context.Context, tenantID uuid.UUID) (*entity.Tenant, error)
	GetTenantByDomain(ctx context.Context, domain string) (*entity.Tenant, error)
	ListTenants(ctx context.Context, filters *TenantFilters) ([]*entity.Tenant, error)

	// Tenant status management
	ActivateTenant(ctx context.Context, req *ActivateTenantRequest) error
	SuspendTenant(ctx context.Context, req *SuspendTenantRequest) error
	DeactivateTenant(ctx context.Context, req *DeactivateTenantRequest) error

	// Tenant context and isolation
	ValidateTenantContext(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (*entity.TenantContext, error)
	GetTenantContext(ctx context.Context, tenantID uuid.UUID) (*entity.TenantContext, error)
	ValidateResourceAccess(ctx context.Context, tenantCtx *entity.TenantContext, resourceID string) error
	EnforceTenantIsolation(ctx context.Context, tenantID uuid.UUID, operation string) error

	// Security and compliance
	ValidateSecurityRequirements(ctx context.Context, tenantID uuid.UUID, req *SecurityValidationRequest) (*SecurityValidationResponse, error)
	UpdateSecurityContext(ctx context.Context, req *UpdateSecurityContextRequest) error
	ValidateComplianceRequirements(ctx context.Context, tenantID uuid.UUID) (*ComplianceValidationResponse, error)

	// Resource management and quotas
	CheckResourceQuota(ctx context.Context, tenantID uuid.UUID, resource string, requestedAmount int64) (*QuotaCheckResponse, error)
	UpdateResourceUsage(ctx context.Context, tenantID uuid.UUID, resource string, amount int64) error
	GetResourceUsage(ctx context.Context, tenantID uuid.UUID) (*ResourceUsageResponse, error)
	ResetResourceUsage(ctx context.Context, tenantID uuid.UUID, resource string) error

	// Configuration management
	UpdateTenantConfiguration(ctx context.Context, req *UpdateConfigurationRequest) error
	GetTenantConfiguration(ctx context.Context, tenantID uuid.UUID) (*TenantConfigurationResponse, error)
	UpdateFeatureFlags(ctx context.Context, req *UpdateFeatureFlagsRequest) error
	GetFeatureFlags(ctx context.Context, tenantID uuid.UUID) (map[string]bool, error)

	// Branding and customization
	UpdateBrandingConfiguration(ctx context.Context, req *UpdateBrandingRequest) error
	GetBrandingConfiguration(ctx context.Context, tenantID uuid.UUID) (*entity.TenantBrandingConfig, error)
	ValidateCustomDomain(ctx context.Context, tenantID uuid.UUID, domain string) (*DomainValidationResponse, error)

	// Integration management
	UpdateIntegrationSettings(ctx context.Context, req *UpdateIntegrationRequest) error
	GetIntegrationSettings(ctx context.Context, tenantID uuid.UUID) (*entity.IntegrationSettings, error)
	TestIntegration(ctx context.Context, tenantID uuid.UUID, integrationType string) (*IntegrationTestResponse, error)

	// Network and access controls
	ValidateIPAccess(ctx context.Context, tenantID uuid.UUID, ipAddress string) error
	ValidateCountryAccess(ctx context.Context, tenantID uuid.UUID, country string) error
	UpdateNetworkPolicies(ctx context.Context, req *UpdateNetworkPoliciesRequest) error

	// Audit and monitoring
	GetTenantAuditLog(ctx context.Context, tenantID uuid.UUID, filters *AuditLogFilters) ([]*TenantAuditEvent, error)
	GetTenantMetrics(ctx context.Context, tenantID uuid.UUID, timeRange *TimeRange) (*TenantMetricsResponse, error)
	GetTenantHealthStatus(ctx context.Context, tenantID uuid.UUID) (*TenantHealthResponse, error)

	// Hierarchical tenant management
	CreateSubTenant(ctx context.Context, req *CreateSubTenantRequest) (*CreateTenantResponse, error)
	GetChildTenants(ctx context.Context, parentTenantID uuid.UUID) ([]*entity.Tenant, error)
	TransferTenant(ctx context.Context, req *TransferTenantRequest) error

	// Emergency and incident response
	EnableEmergencyMode(ctx context.Context, req *EmergencyModeRequest) error
	DisableEmergencyMode(ctx context.Context, tenantID uuid.UUID) error
	GetEmergencyContacts(ctx context.Context, tenantID uuid.UUID) ([]entity.EmergencyContact, error)
	UpdateEmergencyContacts(ctx context.Context, req *UpdateEmergencyContactsRequest) error
}

// TenantIsolationService defines the interface for tenant isolation enforcement
type TenantIsolationService interface {
	// Data isolation
	EnforceDataIsolation(ctx context.Context, tenantID uuid.UUID, query string) (string, error)
	ValidateDataAccess(ctx context.Context, tenantID uuid.UUID, resourceType string, resourceID string) error
	ApplyTenantFilter(ctx context.Context, tenantID uuid.UUID, filters map[string]interface{}) map[string]interface{}

	// Network isolation
	ValidateNetworkAccess(ctx context.Context, tenantCtx *entity.TenantContext, targetService string) error
	ApplyNetworkPolicies(ctx context.Context, tenantID uuid.UUID, connectionInfo *NetworkConnectionInfo) error

	// Resource isolation
	ValidateResourceAccess(ctx context.Context, tenantID uuid.UUID, resourceType string, operation string) error
	ApplyResourceLimits(ctx context.Context, tenantID uuid.UUID, resourceType string, usage int64) error

	// Security isolation
	ValidateSecurityContext(ctx context.Context, tenantCtx *entity.TenantContext, securityLevel entity.SecurityClearanceLevel) error
	ApplySecurityPolicies(ctx context.Context, tenantID uuid.UUID, operation string) error

	// Cross-tenant validation
	ValidateCrossTenantAccess(ctx context.Context, sourceTenantID, targetTenantID uuid.UUID, operation string) error
	GetCrossTenantPermissions(ctx context.Context, sourceTenantID, targetTenantID uuid.UUID) (*CrossTenantPermissions, error)
}

// Request/Response types

// CreateTenantRequest represents a request to create a new tenant
type CreateTenantRequest struct {
	Name                 string                        `json:"name"`
	DisplayName          string                        `json:"display_name"`
	Description          string                        `json:"description"`
	Type                 entity.TenantType             `json:"type"`
	Tier                 entity.TenantTier             `json:"tier"`
	Domain               string                        `json:"domain"`
	AdditionalDomains    []string                      `json:"additional_domains,omitempty"`
	Industry             string                        `json:"industry"`
	Country              string                        `json:"country"`
	Timezone             string                        `json:"timezone"`
	MaxSecurityClearance entity.SecurityClearanceLevel `json:"max_security_clearance"`
	DefaultClearance     entity.SecurityClearanceLevel `json:"default_clearance"`
	ComplianceFrameworks []entity.ComplianceFramework  `json:"compliance_frameworks,omitempty"`
	DataResidencyRegions []string                      `json:"data_residency_regions,omitempty"`
	ResourceQuotas       *entity.TenantResourceQuotas  `json:"resource_quotas,omitempty"`
	FeatureFlags         map[string]bool               `json:"feature_flags,omitempty"`
	AllowedIPRanges      []string                      `json:"allowed_ip_ranges,omitempty"`
	AllowedCountries     []string                      `json:"allowed_countries,omitempty"`
	BillingEmail         string                        `json:"billing_email"`
	ContractStartDate    time.Time                     `json:"contract_start_date"`
	ContractEndDate      *time.Time                    `json:"contract_end_date,omitempty"`
	ParentTenantID       *uuid.UUID                    `json:"parent_tenant_id,omitempty"`
	CreatedBy            uuid.UUID                     `json:"created_by"`
}

// CreateTenantResponse represents the response to tenant creation
type CreateTenantResponse struct {
	TenantID   uuid.UUID           `json:"tenant_id"`
	CreatedAt  time.Time           `json:"created_at"`
	Status     entity.TenantStatus `json:"status"`
	SetupTasks []string            `json:"setup_tasks"`
}

// UpdateTenantRequest represents a request to update tenant information
type UpdateTenantRequest struct {
	TenantID             uuid.UUID                      `json:"tenant_id"`
	Name                 *string                        `json:"name,omitempty"`
	DisplayName          *string                        `json:"display_name,omitempty"`
	Description          *string                        `json:"description,omitempty"`
	Type                 *entity.TenantType             `json:"type,omitempty"`
	Tier                 *entity.TenantTier             `json:"tier,omitempty"`
	Industry             *string                        `json:"industry,omitempty"`
	Country              *string                        `json:"country,omitempty"`
	Timezone             *string                        `json:"timezone,omitempty"`
	MaxSecurityClearance *entity.SecurityClearanceLevel `json:"max_security_clearance,omitempty"`
	DefaultClearance     *entity.SecurityClearanceLevel `json:"default_clearance,omitempty"`
	ComplianceFrameworks []entity.ComplianceFramework   `json:"compliance_frameworks,omitempty"`
	DataResidencyRegions []string                       `json:"data_residency_regions,omitempty"`
	AllowedIPRanges      []string                       `json:"allowed_ip_ranges,omitempty"`
	BlockedIPRanges      []string                       `json:"blocked_ip_ranges,omitempty"`
	AllowedCountries     []string                       `json:"allowed_countries,omitempty"`
	BillingEmail         *string                        `json:"billing_email,omitempty"`
	ContractEndDate      *time.Time                     `json:"contract_end_date,omitempty"`
	UpdatedBy            uuid.UUID                      `json:"updated_by"`
}

// ActivateTenantRequest represents a request to activate a tenant
type ActivateTenantRequest struct {
	TenantID         uuid.UUID `json:"tenant_id"`
	ActivatedBy      uuid.UUID `json:"activated_by"`
	ActivationReason string    `json:"activation_reason"`
}

// SuspendTenantRequest represents a request to suspend a tenant
type SuspendTenantRequest struct {
	TenantID           uuid.UUID      `json:"tenant_id"`
	SuspendedBy        uuid.UUID      `json:"suspended_by"`
	SuspensionReason   string         `json:"suspension_reason"`
	SuspensionDuration *time.Duration `json:"suspension_duration,omitempty"`
}

// DeactivateTenantRequest represents a request to deactivate a tenant
type DeactivateTenantRequest struct {
	TenantID           uuid.UUID     `json:"tenant_id"`
	DeactivatedBy      uuid.UUID     `json:"deactivated_by"`
	DeactivationReason string        `json:"deactivation_reason"`
	DataRetention      time.Duration `json:"data_retention"`
}

// SecurityValidationRequest represents a request to validate security requirements
type SecurityValidationRequest struct {
	TenantID          uuid.UUID                     `json:"tenant_id"`
	Operation         string                        `json:"operation"`
	ResourceType      string                        `json:"resource_type"`
	ResourceID        string                        `json:"resource_id,omitempty"`
	SecurityLevel     entity.SecurityClearanceLevel `json:"security_level"`
	UserID            uuid.UUID                     `json:"user_id"`
	IPAddress         string                        `json:"ip_address"`
	UserAgent         string                        `json:"user_agent"`
	AdditionalContext map[string]interface{}        `json:"additional_context,omitempty"`
}

// SecurityValidationResponse represents the response to security validation
type SecurityValidationResponse struct {
	Allowed           bool                          `json:"allowed"`
	Reason            string                        `json:"reason,omitempty"`
	RequiredClearance entity.SecurityClearanceLevel `json:"required_clearance,omitempty"`
	AdditionalChecks  []string                      `json:"additional_checks,omitempty"`
	ValidatedAt       time.Time                     `json:"validated_at"`
}

// UpdateSecurityContextRequest represents a request to update tenant security context
type UpdateSecurityContextRequest struct {
	TenantID                uuid.UUID              `json:"tenant_id"`
	ThreatIntelligenceLevel *string                `json:"threat_intelligence_level,omitempty"`
	IncidentResponseTier    *string                `json:"incident_response_tier,omitempty"`
	SecurityPolicies        map[string]interface{} `json:"security_policies,omitempty"`
	RiskTolerance           *string                `json:"risk_tolerance,omitempty"`
	AutoResponseEnabled     *bool                  `json:"auto_response_enabled,omitempty"`
	ThreatHuntingEnabled    *bool                  `json:"threat_hunting_enabled,omitempty"`
	ForensicsRetention      *time.Duration         `json:"forensics_retention,omitempty"`
	AlertThresholds         map[string]float64     `json:"alert_thresholds,omitempty"`
	UpdatedBy               uuid.UUID              `json:"updated_by"`
}

// ComplianceValidationResponse represents compliance validation results
type ComplianceValidationResponse struct {
	Compliant       bool                         `json:"compliant"`
	Frameworks      []entity.ComplianceFramework `json:"frameworks"`
	Violations      []ComplianceViolation        `json:"violations,omitempty"`
	Recommendations []string                     `json:"recommendations,omitempty"`
	LastAuditDate   *time.Time                   `json:"last_audit_date,omitempty"`
	NextAuditDue    *time.Time                   `json:"next_audit_due,omitempty"`
	ValidatedAt     time.Time                    `json:"validated_at"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	Framework   entity.ComplianceFramework `json:"framework"`
	Requirement string                     `json:"requirement"`
	Severity    string                     `json:"severity"`
	Description string                     `json:"description"`
	Remediation string                     `json:"remediation"`
}

// QuotaCheckResponse represents the response to a quota check
type QuotaCheckResponse struct {
	Allowed         bool       `json:"allowed"`
	CurrentUsage    int64      `json:"current_usage"`
	QuotaLimit      int64      `json:"quota_limit"`
	RemainingQuota  int64      `json:"remaining_quota"`
	RequestedAmount int64      `json:"requested_amount"`
	WouldExceed     bool       `json:"would_exceed"`
	ResetTime       *time.Time `json:"reset_time,omitempty"`
}

// ResourceUsageResponse represents current resource usage
type ResourceUsageResponse struct {
	TenantID     uuid.UUID          `json:"tenant_id"`
	UsageData    map[string]int64   `json:"usage_data"`
	QuotaLimits  map[string]int64   `json:"quota_limits"`
	UsagePercent map[string]float64 `json:"usage_percent"`
	LastUpdated  time.Time          `json:"last_updated"`
}

// UpdateConfigurationRequest represents a request to update tenant configuration
type UpdateConfigurationRequest struct {
	TenantID               uuid.UUID                      `json:"tenant_id"`
	ResourceQuotas         *entity.TenantResourceQuotas   `json:"resource_quotas,omitempty"`
	APIRateLimits          *entity.APIRateLimits          `json:"api_rate_limits,omitempty"`
	RetentionPolicies      *entity.RetentionPolicies      `json:"retention_policies,omitempty"`
	EncryptionRequirements *entity.EncryptionRequirements `json:"encryption_requirements,omitempty"`
	MaintenanceWindow      *entity.MaintenanceWindow      `json:"maintenance_window,omitempty"`
	CustomSettings         map[string]interface{}         `json:"custom_settings,omitempty"`
	UpdatedBy              uuid.UUID                      `json:"updated_by"`
}

// TenantConfigurationResponse represents tenant configuration
type TenantConfigurationResponse struct {
	TenantID               uuid.UUID                      `json:"tenant_id"`
	ResourceQuotas         *entity.TenantResourceQuotas   `json:"resource_quotas"`
	APIRateLimits          *entity.APIRateLimits          `json:"api_rate_limits"`
	RetentionPolicies      *entity.RetentionPolicies      `json:"retention_policies"`
	EncryptionRequirements *entity.EncryptionRequirements `json:"encryption_requirements"`
	MaintenanceWindow      *entity.MaintenanceWindow      `json:"maintenance_window"`
	CustomSettings         map[string]interface{}         `json:"custom_settings"`
	LastUpdated            time.Time                      `json:"last_updated"`
}

// UpdateFeatureFlagsRequest represents a request to update feature flags
type UpdateFeatureFlagsRequest struct {
	TenantID     uuid.UUID       `json:"tenant_id"`
	FeatureFlags map[string]bool `json:"feature_flags"`
	UpdatedBy    uuid.UUID       `json:"updated_by"`
}

// UpdateBrandingRequest represents a request to update branding configuration
type UpdateBrandingRequest struct {
	TenantID       uuid.UUID                    `json:"tenant_id"`
	BrandingConfig *entity.TenantBrandingConfig `json:"branding_config"`
	UpdatedBy      uuid.UUID                    `json:"updated_by"`
}

// DomainValidationResponse represents domain validation results
type DomainValidationResponse struct {
	Valid            bool        `json:"valid"`
	Domain           string      `json:"domain"`
	ValidationMethod string      `json:"validation_method"`
	DNSRecords       []DNSRecord `json:"dns_records,omitempty"`
	Verified         bool        `json:"verified"`
	ValidatedAt      time.Time   `json:"validated_at"`
}

// DNSRecord represents a DNS record for domain validation
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// UpdateIntegrationRequest represents a request to update integration settings
type UpdateIntegrationRequest struct {
	TenantID            uuid.UUID                   `json:"tenant_id"`
	IntegrationSettings *entity.IntegrationSettings `json:"integration_settings"`
	UpdatedBy           uuid.UUID                   `json:"updated_by"`
}

// IntegrationTestResponse represents integration test results
type IntegrationTestResponse struct {
	IntegrationType string       `json:"integration_type"`
	TestStatus      string       `json:"test_status"` // success, failure, partial
	TestResults     []TestResult `json:"test_results"`
	TestedAt        time.Time    `json:"tested_at"`
}

// TestResult represents a single test result
type TestResult struct {
	TestName string                 `json:"test_name"`
	Status   string                 `json:"status"`
	Message  string                 `json:"message,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// UpdateNetworkPoliciesRequest represents a request to update network policies
type UpdateNetworkPoliciesRequest struct {
	TenantID         uuid.UUID `json:"tenant_id"`
	AllowedIPRanges  []string  `json:"allowed_ip_ranges,omitempty"`
	BlockedIPRanges  []string  `json:"blocked_ip_ranges,omitempty"`
	RequireVPN       *bool     `json:"require_vpn,omitempty"`
	AllowedCountries []string  `json:"allowed_countries,omitempty"`
	UpdatedBy        uuid.UUID `json:"updated_by"`
}

// TenantAuditEvent represents an audit event for tenant operations
type TenantAuditEvent struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	EventType    string                 `json:"event_type"`
	UserID       *uuid.UUID             `json:"user_id,omitempty"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	Operation    string                 `json:"operation"`
	Success      bool                   `json:"success"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// TenantMetricsResponse represents tenant metrics
type TenantMetricsResponse struct {
	TenantID           uuid.UUID             `json:"tenant_id"`
	TimeRange          *TimeRange            `json:"time_range"`
	UserActivity       *UserActivityMetrics  `json:"user_activity"`
	ResourceUsage      *ResourceUsageMetrics `json:"resource_usage"`
	SecurityMetrics    *SecurityMetrics      `json:"security_metrics"`
	PerformanceMetrics *PerformanceMetrics   `json:"performance_metrics"`
	GeneratedAt        time.Time             `json:"generated_at"`
}

// UserActivityMetrics represents user activity metrics
type UserActivityMetrics struct {
	ActiveUsers        int64         `json:"active_users"`
	TotalSessions      int64         `json:"total_sessions"`
	AvgSessionDuration time.Duration `json:"avg_session_duration"`
	LoginAttempts      int64         `json:"login_attempts"`
	FailedLogins       int64         `json:"failed_logins"`
	ActivityByHour     map[int]int64 `json:"activity_by_hour"`
}

// ResourceUsageMetrics represents resource usage metrics
type ResourceUsageMetrics struct {
	StorageUsed      int64 `json:"storage_used"`
	BandwidthUsed    int64 `json:"bandwidth_used"`
	APICallsCount    int64 `json:"api_calls_count"`
	ComputeUnitsUsed int64 `json:"compute_units_used"`
	AlertsGenerated  int64 `json:"alerts_generated"`
	IncidentsCreated int64 `json:"incidents_created"`
}

// SecurityMetrics represents security-related metrics
type SecurityMetrics struct {
	ThreatDetections     int64   `json:"threat_detections"`
	BlockedAttacks       int64   `json:"blocked_attacks"`
	SecurityIncidents    int64   `json:"security_incidents"`
	ComplianceScore      float64 `json:"compliance_score"`
	RiskScore            float64 `json:"risk_score"`
	VulnerabilitiesFound int64   `json:"vulnerabilities_found"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	AvgResponseTime time.Duration `json:"avg_response_time"`
	Uptime          float64       `json:"uptime"`
	ErrorRate       float64       `json:"error_rate"`
	ThroughputRPS   float64       `json:"throughput_rps"`
}

// TenantHealthResponse represents tenant health status
type TenantHealthResponse struct {
	TenantID      uuid.UUID     `json:"tenant_id"`
	OverallHealth string        `json:"overall_health"` // healthy, degraded, unhealthy
	HealthChecks  []HealthCheck `json:"health_checks"`
	LastChecked   time.Time     `json:"last_checked"`
}

// HealthCheck represents a single health check
type HealthCheck struct {
	Name        string                 `json:"name"`
	Status      string                 `json:"status"` // healthy, degraded, unhealthy
	Message     string                 `json:"message,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
}

// CreateSubTenantRequest represents a request to create a sub-tenant
type CreateSubTenantRequest struct {
	CreateTenantRequest
	ParentTenantID  uuid.UUID `json:"parent_tenant_id"`
	InheritSettings bool      `json:"inherit_settings"`
}

// TransferTenantRequest represents a request to transfer tenant ownership
type TransferTenantRequest struct {
	TenantID       uuid.UUID  `json:"tenant_id"`
	NewParentID    *uuid.UUID `json:"new_parent_id,omitempty"`
	TransferReason string     `json:"transfer_reason"`
	TransferredBy  uuid.UUID  `json:"transferred_by"`
}

// EmergencyModeRequest represents a request to enable emergency mode
type EmergencyModeRequest struct {
	TenantID       uuid.UUID     `json:"tenant_id"`
	EnabledBy      uuid.UUID     `json:"enabled_by"`
	Reason         string        `json:"reason"`
	Duration       time.Duration `json:"duration"`
	EmergencyLevel string        `json:"emergency_level"` // low, medium, high, critical
	OverrideFlags  []string      `json:"override_flags,omitempty"`
}

// UpdateEmergencyContactsRequest represents a request to update emergency contacts
type UpdateEmergencyContactsRequest struct {
	TenantID          uuid.UUID                 `json:"tenant_id"`
	EmergencyContacts []entity.EmergencyContact `json:"emergency_contacts"`
	UpdatedBy         uuid.UUID                 `json:"updated_by"`
}

// TenantFilters represents filters for tenant queries
type TenantFilters struct {
	Type           entity.TenantType             `json:"type,omitempty"`
	Tier           entity.TenantTier             `json:"tier,omitempty"`
	Status         entity.TenantStatus           `json:"status,omitempty"`
	Country        string                        `json:"country,omitempty"`
	Industry       string                        `json:"industry,omitempty"`
	MaxClearance   entity.SecurityClearanceLevel `json:"max_clearance,omitempty"`
	ParentTenantID *uuid.UUID                    `json:"parent_tenant_id,omitempty"`
	HasSubTenants  *bool                         `json:"has_sub_tenants,omitempty"`
	CreatedAfter   *time.Time                    `json:"created_after,omitempty"`
	CreatedBefore  *time.Time                    `json:"created_before,omitempty"`
	Limit          int                           `json:"limit"`
	Offset         int                           `json:"offset"`
}

// TimeRange represents a time range for queries
type TimeRange struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// NetworkConnectionInfo represents network connection information
type NetworkConnectionInfo struct {
	SourceIP        string `json:"source_ip"`
	SourcePort      int    `json:"source_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port"`
	Protocol        string `json:"protocol"`
	UserAgent       string `json:"user_agent,omitempty"`
}

// CrossTenantPermissions represents permissions for cross-tenant access
type CrossTenantPermissions struct {
	SourceTenantID       uuid.UUID                     `json:"source_tenant_id"`
	TargetTenantID       uuid.UUID                     `json:"target_tenant_id"`
	AllowedOperations    []string                      `json:"allowed_operations"`
	RequiredClearance    entity.SecurityClearanceLevel `json:"required_clearance"`
	AdditionalConditions map[string]interface{}        `json:"additional_conditions,omitempty"`
	ExpiresAt            *time.Time                    `json:"expires_at,omitempty"`
}
