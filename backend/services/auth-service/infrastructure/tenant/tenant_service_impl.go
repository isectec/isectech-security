package tenant

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// TenantServiceImpl implements the tenant service interface
type TenantServiceImpl struct {
	tenantRepo       TenantRepository
	auditLogger      TenantAuditLogger
	isolationService *TenantIsolationServiceImpl
	configService    TenantConfigurationService
	metricsCollector TenantMetricsCollector
	config           *TenantServiceConfig
}

// TenantServiceConfig holds tenant service configuration
type TenantServiceConfig struct {
	DefaultQuotas            *entity.TenantResourceQuotas `yaml:"default_quotas"`
	MaxTenantsPerParent      int                          `yaml:"max_tenants_per_parent" default:"100"`
	TenantNameMinLength      int                          `yaml:"tenant_name_min_length" default:"3"`
	TenantNameMaxLength      int                          `yaml:"tenant_name_max_length" default:"64"`
	DomainValidationRequired bool                         `yaml:"domain_validation_required" default:"true"`
	EnableResourceMonitoring bool                         `yaml:"enable_resource_monitoring" default:"true"`
	EnableComplianceChecks   bool                         `yaml:"enable_compliance_checks" default:"true"`
	DefaultRetentionPeriod   time.Duration                `yaml:"default_retention_period" default:"2555h"` // 90 days
	EmergencyModeTimeout     time.Duration                `yaml:"emergency_mode_timeout" default:"24h"`
	HealthCheckInterval      time.Duration                `yaml:"health_check_interval" default:"5m"`
}

// Repository interfaces
type TenantRepository interface {
	Create(ctx context.Context, tenant *entity.Tenant) error
	Update(ctx context.Context, tenant *entity.Tenant) error
	Delete(ctx context.Context, tenantID uuid.UUID) error
	GetByID(ctx context.Context, tenantID uuid.UUID) (*entity.Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*entity.Tenant, error)
	GetByName(ctx context.Context, name string) (*entity.Tenant, error)
	ListByFilters(ctx context.Context, filters *service.TenantFilters) ([]*entity.Tenant, error)
	GetChildTenants(ctx context.Context, parentTenantID uuid.UUID) ([]*entity.Tenant, error)
	UpdateStatus(ctx context.Context, tenantID uuid.UUID, status entity.TenantStatus) error
	UpdateResourceUsage(ctx context.Context, tenantID uuid.UUID, resource string, usage int64) error
	GetResourceUsage(ctx context.Context, tenantID uuid.UUID) (map[string]int64, error)
	CleanupExpiredTenants(ctx context.Context) (int64, error)
}

type TenantAuditLogger interface {
	LogTenantEvent(ctx context.Context, event *service.TenantAuditEvent) error
	GetAuditLog(ctx context.Context, tenantID uuid.UUID, filters *service.AuditLogFilters) ([]*service.TenantAuditEvent, error)
}

type TenantConfigurationService interface {
	GetConfiguration(ctx context.Context, tenantID uuid.UUID) (*service.TenantConfigurationResponse, error)
	UpdateConfiguration(ctx context.Context, req *service.UpdateConfigurationRequest) error
	ValidateConfiguration(ctx context.Context, tenantID uuid.UUID) error
	GetFeatureFlags(ctx context.Context, tenantID uuid.UUID) (map[string]bool, error)
	UpdateFeatureFlags(ctx context.Context, req *service.UpdateFeatureFlagsRequest) error
}

type TenantMetricsCollector interface {
	CollectMetrics(ctx context.Context, tenantID uuid.UUID, timeRange *service.TimeRange) (*service.TenantMetricsResponse, error)
	UpdateResourceMetrics(ctx context.Context, tenantID uuid.UUID, resource string, value int64) error
	GetHealthStatus(ctx context.Context, tenantID uuid.UUID) (*service.TenantHealthResponse, error)
}

// NewTenantService creates a new tenant service implementation
func NewTenantService(
	tenantRepo TenantRepository,
	auditLogger TenantAuditLogger,
	isolationService *TenantIsolationServiceImpl,
	configService TenantConfigurationService,
	metricsCollector TenantMetricsCollector,
	config *TenantServiceConfig,
) *TenantServiceImpl {
	return &TenantServiceImpl{
		tenantRepo:       tenantRepo,
		auditLogger:      auditLogger,
		isolationService: isolationService,
		configService:    configService,
		metricsCollector: metricsCollector,
		config:           config,
	}
}

// Tenant Lifecycle Management

func (s *TenantServiceImpl) CreateTenant(ctx context.Context, req *service.CreateTenantRequest) (*service.CreateTenantResponse, error) {
	// Validate request
	if err := s.validateCreateTenantRequest(req); err != nil {
		return nil, fmt.Errorf("invalid tenant request: %w", err)
	}

	// Check for name and domain conflicts
	if err := s.checkTenantConflicts(ctx, req.Name, req.Domain); err != nil {
		return nil, fmt.Errorf("tenant conflicts: %w", err)
	}

	// Validate parent tenant if specified
	if req.ParentTenantID != nil {
		if err := s.validateParentTenant(ctx, *req.ParentTenantID); err != nil {
			return nil, fmt.Errorf("invalid parent tenant: %w", err)
		}
	}

	// Generate tenant ID and create entity
	tenantID := uuid.New()
	tenant := &entity.Tenant{
		ID:                   tenantID,
		Name:                 req.Name,
		DisplayName:          req.DisplayName,
		Description:          req.Description,
		Type:                 req.Type,
		Tier:                 req.Tier,
		Status:               entity.TenantStatusProvisioning,
		Domain:               req.Domain,
		AdditionalDomains:    req.AdditionalDomains,
		Industry:             req.Industry,
		Country:              req.Country,
		Timezone:             req.Timezone,
		MaxSecurityClearance: req.MaxSecurityClearance,
		DefaultClearance:     req.DefaultClearance,
		ComplianceFrameworks: req.ComplianceFrameworks,
		DataResidencyRegions: req.DataResidencyRegions,
		ResourceQuotas:       s.getResourceQuotas(req.ResourceQuotas),
		FeatureFlags:         s.getDefaultFeatureFlags(req.FeatureFlags, req.Tier),
		AllowedIPRanges:      req.AllowedIPRanges,
		AllowedCountries:     req.AllowedCountries,
		BillingEmail:         req.BillingEmail,
		ContractStartDate:    req.ContractStartDate,
		ContractEndDate:      req.ContractEndDate,
		ParentTenantID:       req.ParentTenantID,
		IsSubOrganization:    req.ParentTenantID != nil,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
		CreatedBy:            req.CreatedBy,
		UpdatedBy:            req.CreatedBy,
		Version:              1,
	}

	// Set default security context
	tenant.SecurityContext = s.createDefaultSecurityContext(req.Type, req.Tier)

	// Set default retention policies
	tenant.RetentionPolicies = s.createDefaultRetentionPolicies(req.ComplianceFrameworks)

	// Set default encryption requirements
	tenant.EncryptionRequirements = s.createDefaultEncryptionRequirements(req.Type, req.ComplianceFrameworks)

	// Set default API rate limits
	tenant.APIRateLimits = s.createDefaultAPIRateLimits(req.Tier)

	// Create tenant in repository
	if err := s.tenantRepo.Create(ctx, tenant); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	// Initialize tenant isolation
	if err := s.isolationService.InitializeTenantIsolation(ctx, tenantID); err != nil {
		// Rollback tenant creation
		s.tenantRepo.Delete(ctx, tenantID)
		return nil, fmt.Errorf("failed to initialize tenant isolation: %w", err)
	}

	// Generate setup tasks
	setupTasks := s.generateSetupTasks(tenant)

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "tenant_created",
		UserID:    &req.CreatedBy,
		Operation: "create_tenant",
		Success:   true,
		Context: map[string]interface{}{
			"tenant_name": req.Name,
			"tenant_type": req.Type,
			"tenant_tier": req.Tier,
		},
		CreatedAt: time.Now(),
	})

	return &service.CreateTenantResponse{
		TenantID:   tenantID,
		CreatedAt:  tenant.CreatedAt,
		Status:     tenant.Status,
		SetupTasks: setupTasks,
	}, nil
}

func (s *TenantServiceImpl) UpdateTenant(ctx context.Context, req *service.UpdateTenantRequest) error {
	// Get existing tenant
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Validate tenant is in updatable state
	if tenant.Status == entity.TenantStatusDecommissioning {
		return fmt.Errorf("cannot update tenant in decommissioning state")
	}

	// Track changes for audit
	changes := make(map[string]interface{})

	// Update fields
	if req.Name != nil && *req.Name != tenant.Name {
		// Check for name conflicts
		existing, _ := s.tenantRepo.GetByName(ctx, *req.Name)
		if existing != nil && existing.ID != tenant.ID {
			return fmt.Errorf("tenant with name '%s' already exists", *req.Name)
		}
		changes["name"] = map[string]string{"old": tenant.Name, "new": *req.Name}
		tenant.Name = *req.Name
	}

	if req.DisplayName != nil && *req.DisplayName != tenant.DisplayName {
		changes["display_name"] = map[string]string{"old": tenant.DisplayName, "new": *req.DisplayName}
		tenant.DisplayName = *req.DisplayName
	}

	if req.Description != nil && *req.Description != tenant.Description {
		changes["description"] = map[string]string{"old": tenant.Description, "new": *req.Description}
		tenant.Description = *req.Description
	}

	if req.Type != nil && *req.Type != tenant.Type {
		changes["type"] = map[string]entity.TenantType{"old": tenant.Type, "new": *req.Type}
		tenant.Type = *req.Type

		// Update security context based on new type
		tenant.SecurityContext = s.createDefaultSecurityContext(*req.Type, tenant.Tier)
	}

	if req.Tier != nil && *req.Tier != tenant.Tier {
		changes["tier"] = map[string]entity.TenantTier{"old": tenant.Tier, "new": *req.Tier}
		tenant.Tier = *req.Tier

		// Update feature flags and quotas based on new tier
		tenant.FeatureFlags = s.getDefaultFeatureFlags(nil, *req.Tier)
		tenant.ResourceQuotas = s.getResourceQuotas(nil)
		tenant.APIRateLimits = s.createDefaultAPIRateLimits(*req.Tier)
	}

	if req.Industry != nil && *req.Industry != tenant.Industry {
		changes["industry"] = map[string]string{"old": tenant.Industry, "new": *req.Industry}
		tenant.Industry = *req.Industry
	}

	if req.Country != nil && *req.Country != tenant.Country {
		changes["country"] = map[string]string{"old": tenant.Country, "new": *req.Country}
		tenant.Country = *req.Country
	}

	if req.Timezone != nil && *req.Timezone != tenant.Timezone {
		changes["timezone"] = map[string]string{"old": tenant.Timezone, "new": *req.Timezone}
		tenant.Timezone = *req.Timezone
	}

	if req.MaxSecurityClearance != nil && *req.MaxSecurityClearance != tenant.MaxSecurityClearance {
		changes["max_security_clearance"] = map[string]entity.SecurityClearanceLevel{
			"old": tenant.MaxSecurityClearance,
			"new": *req.MaxSecurityClearance,
		}
		tenant.MaxSecurityClearance = *req.MaxSecurityClearance
	}

	if req.DefaultClearance != nil && *req.DefaultClearance != tenant.DefaultClearance {
		changes["default_clearance"] = map[string]entity.SecurityClearanceLevel{
			"old": tenant.DefaultClearance,
			"new": *req.DefaultClearance,
		}
		tenant.DefaultClearance = *req.DefaultClearance
	}

	if req.ComplianceFrameworks != nil {
		changes["compliance_frameworks"] = map[string][]entity.ComplianceFramework{
			"old": tenant.ComplianceFrameworks,
			"new": req.ComplianceFrameworks,
		}
		tenant.ComplianceFrameworks = req.ComplianceFrameworks

		// Update retention policies and encryption requirements
		tenant.RetentionPolicies = s.createDefaultRetentionPolicies(req.ComplianceFrameworks)
		tenant.EncryptionRequirements = s.createDefaultEncryptionRequirements(tenant.Type, req.ComplianceFrameworks)
	}

	if req.DataResidencyRegions != nil {
		changes["data_residency_regions"] = map[string][]string{
			"old": tenant.DataResidencyRegions,
			"new": req.DataResidencyRegions,
		}
		tenant.DataResidencyRegions = req.DataResidencyRegions
	}

	if req.AllowedIPRanges != nil {
		changes["allowed_ip_ranges"] = map[string][]string{
			"old": tenant.AllowedIPRanges,
			"new": req.AllowedIPRanges,
		}
		tenant.AllowedIPRanges = req.AllowedIPRanges
	}

	if req.BlockedIPRanges != nil {
		changes["blocked_ip_ranges"] = map[string][]string{
			"old": tenant.BlockedIPRanges,
			"new": req.BlockedIPRanges,
		}
		tenant.BlockedIPRanges = req.BlockedIPRanges
	}

	if req.AllowedCountries != nil {
		changes["allowed_countries"] = map[string][]string{
			"old": tenant.AllowedCountries,
			"new": req.AllowedCountries,
		}
		tenant.AllowedCountries = req.AllowedCountries
	}

	if req.BillingEmail != nil && *req.BillingEmail != tenant.BillingEmail {
		changes["billing_email"] = map[string]string{"old": tenant.BillingEmail, "new": *req.BillingEmail}
		tenant.BillingEmail = *req.BillingEmail
	}

	if req.ContractEndDate != nil {
		oldDate := ""
		if tenant.ContractEndDate != nil {
			oldDate = tenant.ContractEndDate.String()
		}
		newDate := ""
		if req.ContractEndDate != nil {
			newDate = req.ContractEndDate.String()
		}
		changes["contract_end_date"] = map[string]string{"old": oldDate, "new": newDate}
		tenant.ContractEndDate = req.ContractEndDate
	}

	// Update metadata
	tenant.UpdatedAt = time.Now()
	tenant.UpdatedBy = req.UpdatedBy
	tenant.Version++

	// Save tenant
	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "tenant_updated",
		UserID:    &req.UpdatedBy,
		Operation: "update_tenant",
		Success:   true,
		Context:   map[string]interface{}{"changes": changes, "version": tenant.Version},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantServiceImpl) DeleteTenant(ctx context.Context, tenantID uuid.UUID) error {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Check for child tenants
	children, err := s.tenantRepo.GetChildTenants(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check child tenants: %w", err)
	}

	if len(children) > 0 {
		return fmt.Errorf("cannot delete tenant with %d child tenants", len(children))
	}

	// Validate tenant can be deleted
	if tenant.Status == entity.TenantStatusActive {
		return fmt.Errorf("cannot delete active tenant - must be deactivated first")
	}

	// Cleanup tenant isolation
	if err := s.isolationService.CleanupTenantIsolation(ctx, tenantID); err != nil {
		return fmt.Errorf("failed to cleanup tenant isolation: %w", err)
	}

	// Delete tenant
	if err := s.tenantRepo.Delete(ctx, tenantID); err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "tenant_deleted",
		Operation: "delete_tenant",
		Success:   true,
		Context:   map[string]interface{}{"tenant_name": tenant.Name},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantServiceImpl) GetTenant(ctx context.Context, tenantID uuid.UUID) (*entity.Tenant, error) {
	return s.tenantRepo.GetByID(ctx, tenantID)
}

func (s *TenantServiceImpl) GetTenantByDomain(ctx context.Context, domain string) (*entity.Tenant, error) {
	return s.tenantRepo.GetByDomain(ctx, domain)
}

func (s *TenantServiceImpl) ListTenants(ctx context.Context, filters *service.TenantFilters) ([]*entity.Tenant, error) {
	return s.tenantRepo.ListByFilters(ctx, filters)
}

// Tenant Status Management

func (s *TenantServiceImpl) ActivateTenant(ctx context.Context, req *service.ActivateTenantRequest) error {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Validate tenant can be activated
	if tenant.Status == entity.TenantStatusActive {
		return fmt.Errorf("tenant is already active")
	}

	if tenant.Status == entity.TenantStatusDecommissioning {
		return fmt.Errorf("cannot activate tenant in decommissioning state")
	}

	// Perform activation checks
	if err := s.validateTenantActivation(ctx, tenant); err != nil {
		return fmt.Errorf("tenant activation validation failed: %w", err)
	}

	// Activate tenant isolation
	if err := s.isolationService.ActivateTenantIsolation(ctx, req.TenantID); err != nil {
		return fmt.Errorf("failed to activate tenant isolation: %w", err)
	}

	// Update tenant status
	if err := s.tenantRepo.UpdateStatus(ctx, req.TenantID, entity.TenantStatusActive); err != nil {
		return fmt.Errorf("failed to update tenant status: %w", err)
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "tenant_activated",
		UserID:    &req.ActivatedBy,
		Operation: "activate_tenant",
		Success:   true,
		Context:   map[string]interface{}{"reason": req.ActivationReason},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantServiceImpl) SuspendTenant(ctx context.Context, req *service.SuspendTenantRequest) error {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Validate tenant can be suspended
	if tenant.Status != entity.TenantStatusActive {
		return fmt.Errorf("can only suspend active tenants")
	}

	// Suspend tenant isolation (block access)
	if err := s.isolationService.SuspendTenantIsolation(ctx, req.TenantID); err != nil {
		return fmt.Errorf("failed to suspend tenant isolation: %w", err)
	}

	// Update tenant status
	if err := s.tenantRepo.UpdateStatus(ctx, req.TenantID, entity.TenantStatusSuspended); err != nil {
		return fmt.Errorf("failed to update tenant status: %w", err)
	}

	// Schedule automatic reactivation if duration specified
	if req.SuspensionDuration != nil {
		// Implementation would schedule reactivation task
		// This is a placeholder for scheduled task functionality
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "tenant_suspended",
		UserID:    &req.SuspendedBy,
		Operation: "suspend_tenant",
		Success:   true,
		Context: map[string]interface{}{
			"reason":   req.SuspensionReason,
			"duration": req.SuspensionDuration,
		},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantServiceImpl) DeactivateTenant(ctx context.Context, req *service.DeactivateTenantRequest) error {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Validate tenant can be deactivated
	if tenant.Status == entity.TenantStatusDecommissioning {
		return fmt.Errorf("tenant is already being decommissioned")
	}

	// Start decommissioning process
	if err := s.tenantRepo.UpdateStatus(ctx, req.TenantID, entity.TenantStatusDecommissioning); err != nil {
		return fmt.Errorf("failed to update tenant status: %w", err)
	}

	// Deactivate tenant isolation
	if err := s.isolationService.DeactivateTenantIsolation(ctx, req.TenantID); err != nil {
		return fmt.Errorf("failed to deactivate tenant isolation: %w", err)
	}

	// Schedule data cleanup based on retention policy
	s.scheduleDataCleanup(ctx, req.TenantID, req.DataRetention)

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "tenant_deactivated",
		UserID:    &req.DeactivatedBy,
		Operation: "deactivate_tenant",
		Success:   true,
		Context: map[string]interface{}{
			"reason":         req.DeactivationReason,
			"data_retention": req.DataRetention.String(),
		},
		CreatedAt: time.Now(),
	})

	return nil
}

// Tenant Context and Isolation

func (s *TenantServiceImpl) ValidateTenantContext(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (*entity.TenantContext, error) {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	// Validate tenant is active
	if !tenant.IsActive() {
		return nil, fmt.Errorf("tenant is not active")
	}

	// Create tenant context
	tenantCtx := &entity.TenantContext{
		TenantID:        tenantID,
		Tenant:          tenant,
		SecurityContext: tenant.SecurityContext,
		UserID:          &userID,
		SessionID:       generateSessionID(),
		RequestID:       generateRequestID(),
		Timestamp:       time.Now(),
		FeatureFlags:    tenant.FeatureFlags,
		ResourceQuotas:  tenant.ResourceQuotas,
	}

	// Validate IP access if available in context
	// This would be enhanced with actual request context

	return tenantCtx, nil
}

func (s *TenantServiceImpl) GetTenantContext(ctx context.Context, tenantID uuid.UUID) (*entity.TenantContext, error) {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	// Create basic tenant context
	tenantCtx := &entity.TenantContext{
		TenantID:        tenantID,
		Tenant:          tenant,
		SecurityContext: tenant.SecurityContext,
		Timestamp:       time.Now(),
		FeatureFlags:    tenant.FeatureFlags,
		ResourceQuotas:  tenant.ResourceQuotas,
	}

	return tenantCtx, nil
}

func (s *TenantServiceImpl) ValidateResourceAccess(ctx context.Context, tenantCtx *entity.TenantContext, resourceID string) error {
	return s.isolationService.ValidateResourceAccess(ctx, tenantCtx.TenantID, "resource", "access")
}

func (s *TenantServiceImpl) EnforceTenantIsolation(ctx context.Context, tenantID uuid.UUID, operation string) error {
	return s.isolationService.ApplySecurityPolicies(ctx, tenantID, operation)
}

// Security and Compliance

func (s *TenantServiceImpl) ValidateSecurityRequirements(ctx context.Context, tenantID uuid.UUID, req *service.SecurityValidationRequest) (*service.SecurityValidationResponse, error) {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	// Validate IP access
	if req.IPAddress != "" && !tenant.IsIPAllowed(req.IPAddress) {
		return &service.SecurityValidationResponse{
			Allowed:     false,
			Reason:      "IP address not allowed",
			ValidatedAt: time.Now(),
		}, nil
	}

	// Validate security clearance
	if req.SecurityLevel < tenant.MaxSecurityClearance {
		return &service.SecurityValidationResponse{
			Allowed:           false,
			Reason:            "insufficient security clearance",
			RequiredClearance: tenant.MaxSecurityClearance,
			ValidatedAt:       time.Now(),
		}, nil
	}

	// Additional security checks based on tenant type
	additionalChecks := make([]string, 0)
	if tenant.IsGovernmentTenant() {
		additionalChecks = append(additionalChecks, "government_clearance_verification")
	}
	if tenant.RequiresFIPSCompliance() {
		additionalChecks = append(additionalChecks, "fips_compliance_check")
	}

	return &service.SecurityValidationResponse{
		Allowed:          true,
		Reason:           "security requirements satisfied",
		AdditionalChecks: additionalChecks,
		ValidatedAt:      time.Now(),
	}, nil
}

func (s *TenantServiceImpl) UpdateSecurityContext(ctx context.Context, req *service.UpdateSecurityContextRequest) error {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	// Update security context
	if tenant.SecurityContext == nil {
		tenant.SecurityContext = &entity.TenantSecurityContext{}
	}

	updated := false
	changes := make(map[string]interface{})

	if req.ThreatIntelligenceLevel != nil && *req.ThreatIntelligenceLevel != tenant.SecurityContext.ThreatIntelligenceLevel {
		changes["threat_intelligence_level"] = map[string]string{
			"old": tenant.SecurityContext.ThreatIntelligenceLevel,
			"new": *req.ThreatIntelligenceLevel,
		}
		tenant.SecurityContext.ThreatIntelligenceLevel = *req.ThreatIntelligenceLevel
		updated = true
	}

	if req.IncidentResponseTier != nil && *req.IncidentResponseTier != tenant.SecurityContext.IncidentResponseTier {
		changes["incident_response_tier"] = map[string]string{
			"old": tenant.SecurityContext.IncidentResponseTier,
			"new": *req.IncidentResponseTier,
		}
		tenant.SecurityContext.IncidentResponseTier = *req.IncidentResponseTier
		updated = true
	}

	if req.SecurityPolicies != nil {
		changes["security_policies"] = map[string]map[string]interface{}{
			"old": tenant.SecurityContext.SecurityPolicies,
			"new": req.SecurityPolicies,
		}
		tenant.SecurityContext.SecurityPolicies = req.SecurityPolicies
		updated = true
	}

	if req.RiskTolerance != nil && *req.RiskTolerance != tenant.SecurityContext.RiskTolerance {
		changes["risk_tolerance"] = map[string]string{
			"old": tenant.SecurityContext.RiskTolerance,
			"new": *req.RiskTolerance,
		}
		tenant.SecurityContext.RiskTolerance = *req.RiskTolerance
		updated = true
	}

	if req.AutoResponseEnabled != nil && *req.AutoResponseEnabled != tenant.SecurityContext.AutoResponseEnabled {
		changes["auto_response_enabled"] = map[string]bool{
			"old": tenant.SecurityContext.AutoResponseEnabled,
			"new": *req.AutoResponseEnabled,
		}
		tenant.SecurityContext.AutoResponseEnabled = *req.AutoResponseEnabled
		updated = true
	}

	if req.ThreatHuntingEnabled != nil && *req.ThreatHuntingEnabled != tenant.SecurityContext.ThreatHuntingEnabled {
		changes["threat_hunting_enabled"] = map[string]bool{
			"old": tenant.SecurityContext.ThreatHuntingEnabled,
			"new": *req.ThreatHuntingEnabled,
		}
		tenant.SecurityContext.ThreatHuntingEnabled = *req.ThreatHuntingEnabled
		updated = true
	}

	if req.ForensicsRetention != nil && *req.ForensicsRetention != tenant.SecurityContext.ForensicsRetention {
		changes["forensics_retention"] = map[string]string{
			"old": tenant.SecurityContext.ForensicsRetention.String(),
			"new": req.ForensicsRetention.String(),
		}
		tenant.SecurityContext.ForensicsRetention = *req.ForensicsRetention
		updated = true
	}

	if req.AlertThresholds != nil {
		changes["alert_thresholds"] = map[string]map[string]float64{
			"old": tenant.SecurityContext.AlertThresholds,
			"new": req.AlertThresholds,
		}
		tenant.SecurityContext.AlertThresholds = req.AlertThresholds
		updated = true
	}

	if !updated {
		return nil // No changes
	}

	// Update metadata
	tenant.UpdatedAt = time.Now()
	tenant.UpdatedBy = req.UpdatedBy
	tenant.Version++

	// Save tenant
	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return fmt.Errorf("failed to update tenant security context: %w", err)
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "security_context_updated",
		UserID:    &req.UpdatedBy,
		Operation: "update_security_context",
		Success:   true,
		Context:   map[string]interface{}{"changes": changes},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantServiceImpl) ValidateComplianceRequirements(ctx context.Context, tenantID uuid.UUID) (*service.ComplianceValidationResponse, error) {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	violations := make([]service.ComplianceViolation, 0)
	recommendations := make([]string, 0)

	// Check each compliance framework
	for _, framework := range tenant.ComplianceFrameworks {
		frameworkViolations := s.validateComplianceFramework(tenant, framework)
		violations = append(violations, frameworkViolations...)
	}

	// Generate recommendations
	if len(violations) > 0 {
		recommendations = s.generateComplianceRecommendations(violations)
	}

	// Determine overall compliance status
	compliant := len(violations) == 0

	return &service.ComplianceValidationResponse{
		Compliant:       compliant,
		Frameworks:      tenant.ComplianceFrameworks,
		Violations:      violations,
		Recommendations: recommendations,
		ValidatedAt:     time.Now(),
	}, nil
}

// Resource Management

func (s *TenantServiceImpl) CheckResourceQuota(ctx context.Context, tenantID uuid.UUID, resource string, requestedAmount int64) (*service.QuotaCheckResponse, error) {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	// Get current usage
	currentUsage, err := s.tenantRepo.GetResourceUsage(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource usage: %w", err)
	}

	// Get quota limit for resource
	quotaLimit := s.getResourceQuotaLimit(tenant.ResourceQuotas, resource)
	currentResourceUsage := currentUsage[resource]
	remainingQuota := quotaLimit - currentResourceUsage
	wouldExceed := currentResourceUsage+requestedAmount > quotaLimit

	return &service.QuotaCheckResponse{
		Allowed:         !wouldExceed,
		CurrentUsage:    currentResourceUsage,
		QuotaLimit:      quotaLimit,
		RemainingQuota:  remainingQuota,
		RequestedAmount: requestedAmount,
		WouldExceed:     wouldExceed,
	}, nil
}

func (s *TenantServiceImpl) UpdateResourceUsage(ctx context.Context, tenantID uuid.UUID, resource string, amount int64) error {
	if err := s.tenantRepo.UpdateResourceUsage(ctx, tenantID, resource, amount); err != nil {
		return fmt.Errorf("failed to update resource usage: %w", err)
	}

	// Update metrics
	if s.config.EnableResourceMonitoring {
		s.metricsCollector.UpdateResourceMetrics(ctx, tenantID, resource, amount)
	}

	return nil
}

func (s *TenantServiceImpl) GetResourceUsage(ctx context.Context, tenantID uuid.UUID) (*service.ResourceUsageResponse, error) {
	// Get tenant
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	// Get current usage
	usageData, err := s.tenantRepo.GetResourceUsage(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource usage: %w", err)
	}

	// Calculate quota limits and percentages
	quotaLimits := make(map[string]int64)
	usagePercent := make(map[string]float64)

	for resource, usage := range usageData {
		limit := s.getResourceQuotaLimit(tenant.ResourceQuotas, resource)
		quotaLimits[resource] = limit

		if limit > 0 {
			usagePercent[resource] = float64(usage) / float64(limit) * 100
		} else {
			usagePercent[resource] = 0
		}
	}

	return &service.ResourceUsageResponse{
		TenantID:     tenantID,
		UsageData:    usageData,
		QuotaLimits:  quotaLimits,
		UsagePercent: usagePercent,
		LastUpdated:  time.Now(),
	}, nil
}

// Helper methods

func (s *TenantServiceImpl) validateCreateTenantRequest(req *service.CreateTenantRequest) error {
	if req.Name == "" {
		return fmt.Errorf("tenant name is required")
	}
	if len(req.Name) < s.config.TenantNameMinLength || len(req.Name) > s.config.TenantNameMaxLength {
		return fmt.Errorf("tenant name must be between %d and %d characters", s.config.TenantNameMinLength, s.config.TenantNameMaxLength)
	}
	if req.DisplayName == "" {
		return fmt.Errorf("tenant display name is required")
	}
	if !entity.ValidateTenantType(string(req.Type)) {
		return fmt.Errorf("invalid tenant type: %s", req.Type)
	}
	if !entity.ValidateTenantTier(string(req.Tier)) {
		return fmt.Errorf("invalid tenant tier: %s", req.Tier)
	}
	if req.Domain == "" {
		return fmt.Errorf("tenant domain is required")
	}
	if req.BillingEmail == "" {
		return fmt.Errorf("billing email is required")
	}
	return nil
}

func (s *TenantServiceImpl) checkTenantConflicts(ctx context.Context, name, domain string) error {
	// Check name conflict
	existing, _ := s.tenantRepo.GetByName(ctx, name)
	if existing != nil {
		return fmt.Errorf("tenant with name '%s' already exists", name)
	}

	// Check domain conflict
	existing, _ = s.tenantRepo.GetByDomain(ctx, domain)
	if existing != nil {
		return fmt.Errorf("tenant with domain '%s' already exists", domain)
	}

	return nil
}

func (s *TenantServiceImpl) validateParentTenant(ctx context.Context, parentTenantID uuid.UUID) error {
	parent, err := s.tenantRepo.GetByID(ctx, parentTenantID)
	if err != nil {
		return fmt.Errorf("parent tenant not found: %w", err)
	}

	if !parent.IsActive() {
		return fmt.Errorf("parent tenant is not active")
	}

	// Check child tenant limit
	children, err := s.tenantRepo.GetChildTenants(ctx, parentTenantID)
	if err != nil {
		return fmt.Errorf("failed to check child tenant count: %w", err)
	}

	if len(children) >= s.config.MaxTenantsPerParent {
		return fmt.Errorf("parent tenant has reached maximum child tenant limit (%d)", s.config.MaxTenantsPerParent)
	}

	return nil
}

func (s *TenantServiceImpl) getResourceQuotas(provided *entity.TenantResourceQuotas) *entity.TenantResourceQuotas {
	if provided != nil {
		return provided
	}
	return s.config.DefaultQuotas
}

func (s *TenantServiceImpl) getDefaultFeatureFlags(provided map[string]bool, tier entity.TenantTier) map[string]bool {
	flags := make(map[string]bool)

	// Set tier-based feature flags
	switch tier {
	case entity.TenantTierEssential:
		flags["basic_threat_detection"] = true
		flags["advanced_analytics"] = false
		flags["custom_rules"] = false
		flags["api_access"] = true
		flags["siem_integration"] = false
	case entity.TenantTierAdvanced:
		flags["basic_threat_detection"] = true
		flags["advanced_analytics"] = true
		flags["custom_rules"] = true
		flags["api_access"] = true
		flags["siem_integration"] = true
		flags["threat_hunting"] = false
	case entity.TenantTierEnterprise:
		flags["basic_threat_detection"] = true
		flags["advanced_analytics"] = true
		flags["custom_rules"] = true
		flags["api_access"] = true
		flags["siem_integration"] = true
		flags["threat_hunting"] = true
		flags["white_labeling"] = true
		flags["custom_integrations"] = true
	case entity.TenantTierGovernment:
		flags["basic_threat_detection"] = true
		flags["advanced_analytics"] = true
		flags["custom_rules"] = true
		flags["api_access"] = true
		flags["siem_integration"] = true
		flags["threat_hunting"] = true
		flags["white_labeling"] = true
		flags["custom_integrations"] = true
		flags["fips_compliance"] = true
		flags["government_cloud"] = true
	}

	// Override with provided flags
	if provided != nil {
		for key, value := range provided {
			flags[key] = value
		}
	}

	return flags
}

func (s *TenantServiceImpl) createDefaultSecurityContext(tenantType entity.TenantType, tier entity.TenantTier) *entity.TenantSecurityContext {
	context := &entity.TenantSecurityContext{
		RiskTolerance:        "medium",
		AutoResponseEnabled:  false,
		ThreatHuntingEnabled: false,
		ForensicsRetention:   24 * time.Hour * 90, // 90 days
		AlertThresholds:      make(map[string]float64),
		SecurityPolicies:     make(map[string]interface{}),
	}

	// Set threat intelligence level based on tier
	switch tier {
	case entity.TenantTierEssential:
		context.ThreatIntelligenceLevel = "basic"
		context.IncidentResponseTier = "standard"
	case entity.TenantTierAdvanced:
		context.ThreatIntelligenceLevel = "advanced"
		context.IncidentResponseTier = "priority"
		context.ThreatHuntingEnabled = true
	case entity.TenantTierEnterprise:
		context.ThreatIntelligenceLevel = "premium"
		context.IncidentResponseTier = "critical"
		context.ThreatHuntingEnabled = true
		context.AutoResponseEnabled = true
	case entity.TenantTierGovernment:
		context.ThreatIntelligenceLevel = "premium"
		context.IncidentResponseTier = "critical"
		context.ThreatHuntingEnabled = true
		context.AutoResponseEnabled = true
		context.RiskTolerance = "low"
		context.ForensicsRetention = 24 * time.Hour * 2555 // 7 years
	}

	// Adjust based on tenant type
	if tenantType == entity.TenantTypeGovernment || tenantType == entity.TenantTypeDefense {
		context.RiskTolerance = "low"
		context.ForensicsRetention = 24 * time.Hour * 2555 // 7 years
	}

	// Set default alert thresholds
	context.AlertThresholds["high_severity"] = 0.8
	context.AlertThresholds["critical_severity"] = 0.9
	context.AlertThresholds["failed_login_rate"] = 0.1

	return context
}

func (s *TenantServiceImpl) createDefaultRetentionPolicies(frameworks []entity.ComplianceFramework) *entity.RetentionPolicies {
	policies := &entity.RetentionPolicies{
		AuditLogs:       24 * time.Hour * 90,  // 90 days default
		SecurityEvents:  24 * time.Hour * 365, // 1 year default
		ThreatData:      24 * time.Hour * 180, // 6 months default
		IncidentData:    24 * time.Hour * 730, // 2 years default
		ForensicsData:   24 * time.Hour * 365, // 1 year default
		BackupRetention: 24 * time.Hour * 30,  // 30 days default
		ArchivePolicy:   "cloud",
	}

	// Adjust for compliance frameworks
	for _, framework := range frameworks {
		switch framework {
		case entity.ComplianceSOC2:
			policies.AuditLogs = 24 * time.Hour * 365 // 1 year
		case entity.ComplianceISO27001:
			policies.SecurityEvents = 24 * time.Hour * 1095 // 3 years
		case entity.ComplianceFedRAMP:
			policies.AuditLogs = 24 * time.Hour * 2555      // 7 years
			policies.SecurityEvents = 24 * time.Hour * 2555 // 7 years
			policies.ForensicsData = 24 * time.Hour * 2555  // 7 years
		case entity.ComplianceHIPAA:
			policies.AuditLogs = 24 * time.Hour * 2190 // 6 years
		case entity.CompliancePCI:
			policies.AuditLogs = 24 * time.Hour * 365 // 1 year
		}
	}

	return policies
}

func (s *TenantServiceImpl) createDefaultEncryptionRequirements(tenantType entity.TenantType, frameworks []entity.ComplianceFramework) *entity.EncryptionRequirements {
	requirements := &entity.EncryptionRequirements{
		EncryptionAtRest:       "AES-256",
		EncryptionInTransit:    "TLS 1.3",
		KeyManagement:          "KMS",
		CertificateAuthority:   "public",
		HardwareSecurityModule: false,
		FIPSCompliance:         false,
		QuantumResistant:       false,
	}

	// Adjust for tenant type
	if tenantType == entity.TenantTypeGovernment || tenantType == entity.TenantTypeDefense {
		requirements.FIPSCompliance = true
		requirements.HardwareSecurityModule = true
		requirements.KeyManagement = "HSM"
		requirements.CertificateAuthority = "internal"
	}

	// Adjust for compliance frameworks
	for _, framework := range frameworks {
		switch framework {
		case entity.ComplianceFedRAMP:
			requirements.FIPSCompliance = true
			requirements.HardwareSecurityModule = true
			requirements.KeyManagement = "HSM"
		case entity.ComplianceFISMA:
			requirements.FIPSCompliance = true
			requirements.HardwareSecurityModule = true
		}
	}

	return requirements
}

func (s *TenantServiceImpl) createDefaultAPIRateLimits(tier entity.TenantTier) *entity.APIRateLimits {
	switch tier {
	case entity.TenantTierEssential:
		return &entity.APIRateLimits{
			RequestsPerMinute:  100,
			RequestsPerHour:    1000,
			RequestsPerDay:     10000,
			BurstLimit:         50,
			ConcurrentRequests: 10,
		}
	case entity.TenantTierAdvanced:
		return &entity.APIRateLimits{
			RequestsPerMinute:  500,
			RequestsPerHour:    10000,
			RequestsPerDay:     100000,
			BurstLimit:         250,
			ConcurrentRequests: 50,
		}
	case entity.TenantTierEnterprise, entity.TenantTierGovernment:
		return &entity.APIRateLimits{
			RequestsPerMinute:  2000,
			RequestsPerHour:    50000,
			RequestsPerDay:     1000000,
			BurstLimit:         1000,
			ConcurrentRequests: 200,
		}
	default:
		return &entity.APIRateLimits{
			RequestsPerMinute:  100,
			RequestsPerHour:    1000,
			RequestsPerDay:     10000,
			BurstLimit:         50,
			ConcurrentRequests: 10,
		}
	}
}

func (s *TenantServiceImpl) generateSetupTasks(tenant *entity.Tenant) []string {
	tasks := []string{
		"domain_verification",
		"ssl_certificate_setup",
		"initial_user_creation",
		"branding_configuration",
	}

	// Add compliance-specific tasks
	for _, framework := range tenant.ComplianceFrameworks {
		switch framework {
		case entity.ComplianceFedRAMP:
			tasks = append(tasks, "fedramp_configuration", "boundary_protection_setup")
		case entity.ComplianceSOC2:
			tasks = append(tasks, "soc2_controls_setup", "access_review_configuration")
		}
	}

	// Add tier-specific tasks
	switch tenant.Tier {
	case entity.TenantTierEnterprise, entity.TenantTierGovernment:
		tasks = append(tasks, "sso_integration", "advanced_monitoring_setup")
	}

	return tasks
}

func (s *TenantServiceImpl) validateTenantActivation(ctx context.Context, tenant *entity.Tenant) error {
	// Check if all required setup tasks are completed
	// This would integrate with a task tracking system

	// Validate domain ownership
	if s.config.DomainValidationRequired {
		// Implementation would verify domain ownership
	}

	// Validate security configuration
	if tenant.SecurityContext == nil {
		return fmt.Errorf("security context not configured")
	}

	// Validate compliance requirements
	if s.config.EnableComplianceChecks && len(tenant.ComplianceFrameworks) > 0 {
		// Implementation would validate compliance setup
	}

	return nil
}

func (s *TenantServiceImpl) validateComplianceFramework(tenant *entity.Tenant, framework entity.ComplianceFramework) []service.ComplianceViolation {
	violations := make([]service.ComplianceViolation, 0)

	switch framework {
	case entity.ComplianceSOC2:
		// Check SOC2 requirements
		if tenant.EncryptionRequirements == nil || tenant.EncryptionRequirements.EncryptionAtRest != "AES-256" {
			violations = append(violations, service.ComplianceViolation{
				Framework:   framework,
				Requirement: "Encryption at rest",
				Severity:    "high",
				Description: "SOC2 requires AES-256 encryption at rest",
				Remediation: "Configure AES-256 encryption for data at rest",
			})
		}
	case entity.ComplianceFedRAMP:
		// Check FedRAMP requirements
		if tenant.EncryptionRequirements == nil || !tenant.EncryptionRequirements.FIPSCompliance {
			violations = append(violations, service.ComplianceViolation{
				Framework:   framework,
				Requirement: "FIPS compliance",
				Severity:    "critical",
				Description: "FedRAMP requires FIPS 140-2 compliance",
				Remediation: "Enable FIPS compliance in encryption settings",
			})
		}
	case entity.ComplianceHIPAA:
		// Check HIPAA requirements
		if tenant.RetentionPolicies == nil || tenant.RetentionPolicies.AuditLogs < 24*time.Hour*2190 {
			violations = append(violations, service.ComplianceViolation{
				Framework:   framework,
				Requirement: "Audit log retention",
				Severity:    "medium",
				Description: "HIPAA requires audit logs to be retained for 6 years",
				Remediation: "Update audit log retention policy to 6 years",
			})
		}
	}

	return violations
}

func (s *TenantServiceImpl) generateComplianceRecommendations(violations []service.ComplianceViolation) []string {
	recommendations := make([]string, 0)

	for _, violation := range violations {
		recommendations = append(recommendations, violation.Remediation)
	}

	// Add general recommendations
	recommendations = append(recommendations, "Review compliance documentation")
	recommendations = append(recommendations, "Schedule compliance audit")

	return recommendations
}

func (s *TenantServiceImpl) getResourceQuotaLimit(quotas *entity.TenantResourceQuotas, resource string) int64 {
	if quotas == nil {
		return 0
	}

	switch resource {
	case "users":
		return int64(quotas.MaxUsers)
	case "devices":
		return int64(quotas.MaxDevices)
	case "alerts":
		return int64(quotas.MaxAlerts)
	case "incidents":
		return int64(quotas.MaxIncidents)
	case "storage":
		return quotas.StorageQuotaGB
	case "bandwidth":
		return quotas.BandwidthQuotaGB
	case "compute":
		return int64(quotas.ComputeUnits)
	case "threat_feeds":
		return int64(quotas.ThreatIntelFeeds)
	case "custom_rules":
		return int64(quotas.CustomRules)
	case "api_calls":
		return int64(quotas.APICallsPerMinute)
	case "sessions":
		return int64(quotas.ConcurrentSessions)
	default:
		return 0
	}
}

func (s *TenantServiceImpl) scheduleDataCleanup(ctx context.Context, tenantID uuid.UUID, retention time.Duration) {
	// Implementation would schedule background cleanup tasks
	// This is a placeholder for data cleanup scheduling
}

// Helper functions

func generateSessionID() string {
	return uuid.New().String()
}

func generateRequestID() string {
	return uuid.New().String()
}

func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func normalizeIPRange(ipRange string) string {
	// Normalize IP range format
	if !strings.Contains(ipRange, "/") {
		// Single IP, add /32 for IPv4 or /128 for IPv6
		if net.ParseIP(ipRange).To4() != nil {
			return ipRange + "/32"
		}
		return ipRange + "/128"
	}
	return ipRange
}
