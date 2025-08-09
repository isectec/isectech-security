package tenant

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// TenantIsolationServiceImpl implements strict tenant isolation for the iSECTECH platform
type TenantIsolationServiceImpl struct {
	dataIsolationEngine     DataIsolationEngine
	networkIsolationEngine  NetworkIsolationEngine
	resourceIsolationEngine ResourceIsolationEngine
	securityIsolationEngine SecurityIsolationEngine
	auditLogger             TenantAuditLogger
	config                  *TenantIsolationConfig
}

// TenantIsolationConfig holds isolation service configuration
type TenantIsolationConfig struct {
	EnableRowLevelSecurity       bool          `yaml:"enable_row_level_security" default:"true"`
	EnableNetworkPolicies        bool          `yaml:"enable_network_policies" default:"true"`
	EnableResourceLimits         bool          `yaml:"enable_resource_limits" default:"true"`
	EnableSecurityBoundaries     bool          `yaml:"enable_security_boundaries" default:"true"`
	StrictIsolationMode          bool          `yaml:"strict_isolation_mode" default:"true"`
	CrossTenantAccessEnabled     bool          `yaml:"cross_tenant_access_enabled" default:"false"`
	IsolationValidationLevel     string        `yaml:"isolation_validation_level" default:"strict"`
	DefaultIsolationTimeout      time.Duration `yaml:"default_isolation_timeout" default:"30s"`
	ResourceQuotaEnforcement     bool          `yaml:"resource_quota_enforcement" default:"true"`
	SecurityClearanceEnforcement bool          `yaml:"security_clearance_enforcement" default:"true"`
}

// Isolation engine interfaces
type DataIsolationEngine interface {
	ApplyTenantFilter(ctx context.Context, tenantID uuid.UUID, query string) (string, error)
	ValidateDataAccess(ctx context.Context, tenantID uuid.UUID, resourceType string, resourceID string) error
	CreateTenantSchema(ctx context.Context, tenantID uuid.UUID) error
	DropTenantSchema(ctx context.Context, tenantID uuid.UUID) error
	EnableRowLevelSecurity(ctx context.Context, tenantID uuid.UUID, tableName string) error
	DisableRowLevelSecurity(ctx context.Context, tenantID uuid.UUID, tableName string) error
	EncryptTenantData(ctx context.Context, tenantID uuid.UUID, data []byte) ([]byte, error)
	DecryptTenantData(ctx context.Context, tenantID uuid.UUID, encryptedData []byte) ([]byte, error)
}

type NetworkIsolationEngine interface {
	CreateTenantNetworkPolicy(ctx context.Context, tenantID uuid.UUID, policy *NetworkPolicy) error
	ValidateNetworkAccess(ctx context.Context, tenantID uuid.UUID, connection *service.NetworkConnectionInfo) error
	ApplyNetworkSegmentation(ctx context.Context, tenantID uuid.UUID) error
	EnableTenantFirewall(ctx context.Context, tenantID uuid.UUID, rules []FirewallRule) error
	DisableTenantFirewall(ctx context.Context, tenantID uuid.UUID) error
	MonitorNetworkTraffic(ctx context.Context, tenantID uuid.UUID) (*NetworkTrafficMetrics, error)
}

type ResourceIsolationEngine interface {
	CreateResourceNamespace(ctx context.Context, tenantID uuid.UUID) error
	DeleteResourceNamespace(ctx context.Context, tenantID uuid.UUID) error
	ApplyResourceQuotas(ctx context.Context, tenantID uuid.UUID, quotas *entity.TenantResourceQuotas) error
	ValidateResourceAccess(ctx context.Context, tenantID uuid.UUID, resourceType string, operation string) error
	EnforceResourceLimits(ctx context.Context, tenantID uuid.UUID, resourceType string, usage int64) error
	GetResourceUtilization(ctx context.Context, tenantID uuid.UUID) (*ResourceUtilizationMetrics, error)
	IsolateComputeResources(ctx context.Context, tenantID uuid.UUID) error
	IsolateStorageResources(ctx context.Context, tenantID uuid.UUID) error
}

type SecurityIsolationEngine interface {
	CreateSecurityBoundary(ctx context.Context, tenantID uuid.UUID, clearanceLevel entity.SecurityClearanceLevel) error
	ValidateSecurityClearance(ctx context.Context, tenantID uuid.UUID, userClearance entity.SecurityClearanceLevel, resourceClearance entity.SecurityClearanceLevel) error
	ApplySecurityPolicies(ctx context.Context, tenantID uuid.UUID, operation string) error
	CreateTenantKeyspace(ctx context.Context, tenantID uuid.UUID) error
	RotateTenantKeys(ctx context.Context, tenantID uuid.UUID) error
	ValidateCrossTenantAccess(ctx context.Context, sourceTenantID, targetTenantID uuid.UUID, operation string) error
	EnableThreatIsolation(ctx context.Context, tenantID uuid.UUID) error
	DisableThreatIsolation(ctx context.Context, tenantID uuid.UUID) error
}

// Supporting types
type NetworkPolicy struct {
	TenantID         uuid.UUID     `json:"tenant_id"`
	Name             string        `json:"name"`
	AllowedPorts     []int         `json:"allowed_ports"`
	AllowedProtocols []string      `json:"allowed_protocols"`
	AllowedCIDRs     []string      `json:"allowed_cidrs"`
	DeniedCIDRs      []string      `json:"denied_cidrs"`
	SecurityGroups   []string      `json:"security_groups"`
	Ingress          []NetworkRule `json:"ingress"`
	Egress           []NetworkRule `json:"egress"`
	CreatedAt        time.Time     `json:"created_at"`
}

type NetworkRule struct {
	Protocol     string   `json:"protocol"`
	Ports        []int    `json:"ports"`
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"`
	Action       string   `json:"action"` // allow, deny
}

type FirewallRule struct {
	RuleID      string    `json:"rule_id"`
	Priority    int       `json:"priority"`
	Direction   string    `json:"direction"` // inbound, outbound
	Action      string    `json:"action"`    // allow, deny, log
	Protocol    string    `json:"protocol"`
	SourceIP    string    `json:"source_ip"`
	SourcePort  string    `json:"source_port"`
	DestIP      string    `json:"dest_ip"`
	DestPort    string    `json:"dest_port"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type NetworkTrafficMetrics struct {
	TenantID          uuid.UUID        `json:"tenant_id"`
	InboundBytes      int64            `json:"inbound_bytes"`
	OutboundBytes     int64            `json:"outbound_bytes"`
	InboundPackets    int64            `json:"inbound_packets"`
	OutboundPackets   int64            `json:"outbound_packets"`
	ConnectionCount   int64            `json:"connection_count"`
	BlockedAttempts   int64            `json:"blocked_attempts"`
	TrafficByProtocol map[string]int64 `json:"traffic_by_protocol"`
	TrafficByPort     map[int]int64    `json:"traffic_by_port"`
	Timestamp         time.Time        `json:"timestamp"`
}

type ResourceUtilizationMetrics struct {
	TenantID        uuid.UUID        `json:"tenant_id"`
	CPUUsage        float64          `json:"cpu_usage"`
	MemoryUsage     int64            `json:"memory_usage"`
	StorageUsage    int64            `json:"storage_usage"`
	NetworkUsage    int64            `json:"network_usage"`
	ActiveSessions  int64            `json:"active_sessions"`
	ResourcesByType map[string]int64 `json:"resources_by_type"`
	Timestamp       time.Time        `json:"timestamp"`
}

// NewTenantIsolationService creates a new tenant isolation service
func NewTenantIsolationService(
	dataEngine DataIsolationEngine,
	networkEngine NetworkIsolationEngine,
	resourceEngine ResourceIsolationEngine,
	securityEngine SecurityIsolationEngine,
	auditLogger TenantAuditLogger,
	config *TenantIsolationConfig,
) *TenantIsolationServiceImpl {
	return &TenantIsolationServiceImpl{
		dataIsolationEngine:     dataEngine,
		networkIsolationEngine:  networkEngine,
		resourceIsolationEngine: resourceEngine,
		securityIsolationEngine: securityEngine,
		auditLogger:             auditLogger,
		config:                  config,
	}
}

// Tenant Isolation Lifecycle

func (s *TenantIsolationServiceImpl) InitializeTenantIsolation(ctx context.Context, tenantID uuid.UUID) error {
	// Create data isolation
	if s.config.EnableRowLevelSecurity {
		if err := s.dataIsolationEngine.CreateTenantSchema(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to create tenant schema: %w", err)
		}
	}

	// Create resource isolation
	if s.config.EnableResourceLimits {
		if err := s.resourceIsolationEngine.CreateResourceNamespace(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to create resource namespace: %w", err)
		}

		if err := s.resourceIsolationEngine.IsolateComputeResources(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to isolate compute resources: %w", err)
		}

		if err := s.resourceIsolationEngine.IsolateStorageResources(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to isolate storage resources: %w", err)
		}
	}

	// Create network isolation
	if s.config.EnableNetworkPolicies {
		if err := s.networkIsolationEngine.ApplyNetworkSegmentation(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to apply network segmentation: %w", err)
		}
	}

	// Create security isolation
	if s.config.EnableSecurityBoundaries {
		if err := s.securityIsolationEngine.CreateSecurityBoundary(ctx, tenantID, entity.SecurityClearanceUnclassified); err != nil {
			return fmt.Errorf("failed to create security boundary: %w", err)
		}

		if err := s.securityIsolationEngine.CreateTenantKeyspace(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to create tenant keyspace: %w", err)
		}

		if err := s.securityIsolationEngine.EnableThreatIsolation(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to enable threat isolation: %w", err)
		}
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "isolation_initialized",
		Operation: "initialize_tenant_isolation",
		Success:   true,
		Context:   map[string]interface{}{"isolation_level": s.config.IsolationValidationLevel},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantIsolationServiceImpl) ActivateTenantIsolation(ctx context.Context, tenantID uuid.UUID) error {
	// Enable all isolation mechanisms
	if s.config.EnableRowLevelSecurity {
		// Enable RLS for all relevant tables
		tables := []string{"users", "sessions", "audit_logs", "alerts", "incidents", "threat_data"}
		for _, table := range tables {
			if err := s.dataIsolationEngine.EnableRowLevelSecurity(ctx, tenantID, table); err != nil {
				return fmt.Errorf("failed to enable RLS for table %s: %w", table, err)
			}
		}
	}

	// Activate network policies
	if s.config.EnableNetworkPolicies {
		// Create default network policy
		policy := &NetworkPolicy{
			TenantID:         tenantID,
			Name:             "default-tenant-policy",
			AllowedProtocols: []string{"tcp", "udp"},
			AllowedPorts:     []int{80, 443, 8080, 8443},
			Ingress: []NetworkRule{
				{
					Protocol: "tcp",
					Ports:    []int{443},
					Action:   "allow",
				},
			},
			Egress: []NetworkRule{
				{
					Protocol: "tcp",
					Ports:    []int{80, 443},
					Action:   "allow",
				},
			},
			CreatedAt: time.Now(),
		}

		if err := s.networkIsolationEngine.CreateTenantNetworkPolicy(ctx, tenantID, policy); err != nil {
			return fmt.Errorf("failed to create network policy: %w", err)
		}
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "isolation_activated",
		Operation: "activate_tenant_isolation",
		Success:   true,
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantIsolationServiceImpl) SuspendTenantIsolation(ctx context.Context, tenantID uuid.UUID) error {
	// Block all network access
	if s.config.EnableNetworkPolicies {
		denyAllRules := []FirewallRule{
			{
				RuleID:      fmt.Sprintf("suspend-%s", tenantID.String()),
				Priority:    1,
				Direction:   "inbound",
				Action:      "deny",
				Protocol:    "all",
				SourceIP:    "any",
				DestIP:      "any",
				Description: "Suspend tenant access",
				CreatedAt:   time.Now(),
			},
		}

		if err := s.networkIsolationEngine.EnableTenantFirewall(ctx, tenantID, denyAllRules); err != nil {
			return fmt.Errorf("failed to enable firewall for suspension: %w", err)
		}
	}

	// Block resource access
	if s.config.EnableResourceLimits {
		zeroQuotas := &entity.TenantResourceQuotas{
			MaxUsers:           0,
			MaxDevices:         0,
			MaxAlerts:          0,
			MaxIncidents:       0,
			StorageQuotaGB:     0,
			BandwidthQuotaGB:   0,
			ComputeUnits:       0,
			APICallsPerMinute:  0,
			ConcurrentSessions: 0,
		}

		if err := s.resourceIsolationEngine.ApplyResourceQuotas(ctx, tenantID, zeroQuotas); err != nil {
			return fmt.Errorf("failed to apply suspension quotas: %w", err)
		}
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "isolation_suspended",
		Operation: "suspend_tenant_isolation",
		Success:   true,
		Context:   map[string]interface{}{"reason": "tenant_suspension"},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantIsolationServiceImpl) DeactivateTenantIsolation(ctx context.Context, tenantID uuid.UUID) error {
	// Disable network isolation
	if s.config.EnableNetworkPolicies {
		if err := s.networkIsolationEngine.DisableTenantFirewall(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to disable tenant firewall: %w", err)
		}
	}

	// Disable security isolation
	if s.config.EnableSecurityBoundaries {
		if err := s.securityIsolationEngine.DisableThreatIsolation(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to disable threat isolation: %w", err)
		}
	}

	// Disable data isolation (keep schema for cleanup)
	if s.config.EnableRowLevelSecurity {
		tables := []string{"users", "sessions", "audit_logs", "alerts", "incidents", "threat_data"}
		for _, table := range tables {
			if err := s.dataIsolationEngine.DisableRowLevelSecurity(ctx, tenantID, table); err != nil {
				// Log error but continue with deactivation
				s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
					ID:           uuid.New(),
					TenantID:     tenantID,
					EventType:    "isolation_deactivation_warning",
					Operation:    "disable_row_level_security",
					Success:      false,
					ErrorMessage: err.Error(),
					Context:      map[string]interface{}{"table": table},
					CreatedAt:    time.Now(),
				})
			}
		}
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "isolation_deactivated",
		Operation: "deactivate_tenant_isolation",
		Success:   true,
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantIsolationServiceImpl) CleanupTenantIsolation(ctx context.Context, tenantID uuid.UUID) error {
	// Cleanup data isolation
	if s.config.EnableRowLevelSecurity {
		if err := s.dataIsolationEngine.DropTenantSchema(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to drop tenant schema: %w", err)
		}
	}

	// Cleanup resource isolation
	if s.config.EnableResourceLimits {
		if err := s.resourceIsolationEngine.DeleteResourceNamespace(ctx, tenantID); err != nil {
			return fmt.Errorf("failed to delete resource namespace: %w", err)
		}
	}

	// Cleanup security isolation
	if s.config.EnableSecurityBoundaries {
		// Rotate keys before cleanup to ensure no residual access
		if err := s.securityIsolationEngine.RotateTenantKeys(ctx, tenantID); err != nil {
			// Log error but continue cleanup
			s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
				ID:           uuid.New(),
				TenantID:     tenantID,
				EventType:    "isolation_cleanup_warning",
				Operation:    "rotate_tenant_keys",
				Success:      false,
				ErrorMessage: err.Error(),
				CreatedAt:    time.Now(),
			})
		}
	}

	// Audit log
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "isolation_cleaned_up",
		Operation: "cleanup_tenant_isolation",
		Success:   true,
		CreatedAt: time.Now(),
	})

	return nil
}

// Data Isolation

func (s *TenantIsolationServiceImpl) EnforceDataIsolation(ctx context.Context, tenantID uuid.UUID, query string) (string, error) {
	if !s.config.EnableRowLevelSecurity {
		return query, nil
	}

	filteredQuery, err := s.dataIsolationEngine.ApplyTenantFilter(ctx, tenantID, query)
	if err != nil {
		return "", fmt.Errorf("failed to apply tenant filter: %w", err)
	}

	// Audit data access
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "data_access_filtered",
		Operation: "enforce_data_isolation",
		Success:   true,
		Context:   map[string]interface{}{"query_hash": hashQuery(query)},
		CreatedAt: time.Now(),
	})

	return filteredQuery, nil
}

func (s *TenantIsolationServiceImpl) ValidateDataAccess(ctx context.Context, tenantID uuid.UUID, resourceType string, resourceID string) error {
	if !s.config.EnableRowLevelSecurity {
		return nil
	}

	if err := s.dataIsolationEngine.ValidateDataAccess(ctx, tenantID, resourceType, resourceID); err != nil {
		// Audit access violation
		s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
			ID:           uuid.New(),
			TenantID:     tenantID,
			EventType:    "data_access_violation",
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Operation:    "validate_data_access",
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now(),
		})

		return fmt.Errorf("data access validation failed: %w", err)
	}

	return nil
}

func (s *TenantIsolationServiceImpl) ApplyTenantFilter(ctx context.Context, tenantID uuid.UUID, filters map[string]interface{}) map[string]interface{} {
	// Add tenant ID filter
	if filters == nil {
		filters = make(map[string]interface{})
	}

	filters["tenant_id"] = tenantID.String()

	// Apply additional security filters based on configuration
	if s.config.StrictIsolationMode {
		// In strict mode, only allow access to tenant's own data
		filters["isolation_mode"] = "strict"
	}

	return filters
}

// Network Isolation

func (s *TenantIsolationServiceImpl) ValidateNetworkAccess(ctx context.Context, tenantCtx *entity.TenantContext, targetService string) error {
	if !s.config.EnableNetworkPolicies {
		return nil
	}

	connectionInfo := &service.NetworkConnectionInfo{
		SourceIP:  tenantCtx.IPAddress,
		UserAgent: tenantCtx.UserAgent,
		Protocol:  "tcp",
	}

	if err := s.networkIsolationEngine.ValidateNetworkAccess(ctx, tenantCtx.TenantID, connectionInfo); err != nil {
		// Audit network access violation
		s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
			ID:           uuid.New(),
			TenantID:     tenantCtx.TenantID,
			EventType:    "network_access_violation",
			Operation:    "validate_network_access",
			Success:      false,
			ErrorMessage: err.Error(),
			IPAddress:    tenantCtx.IPAddress,
			UserAgent:    tenantCtx.UserAgent,
			Context:      map[string]interface{}{"target_service": targetService},
			CreatedAt:    time.Now(),
		})

		return fmt.Errorf("network access validation failed: %w", err)
	}

	return nil
}

func (s *TenantIsolationServiceImpl) ApplyNetworkPolicies(ctx context.Context, tenantID uuid.UUID, connectionInfo *service.NetworkConnectionInfo) error {
	if !s.config.EnableNetworkPolicies {
		return nil
	}

	if err := s.networkIsolationEngine.ValidateNetworkAccess(ctx, tenantID, connectionInfo); err != nil {
		return fmt.Errorf("network policy validation failed: %w", err)
	}

	return nil
}

// Resource Isolation

func (s *TenantIsolationServiceImpl) ValidateResourceAccess(ctx context.Context, tenantID uuid.UUID, resourceType string, operation string) error {
	if !s.config.EnableResourceLimits {
		return nil
	}

	if err := s.resourceIsolationEngine.ValidateResourceAccess(ctx, tenantID, resourceType, operation); err != nil {
		// Audit resource access violation
		s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
			ID:           uuid.New(),
			TenantID:     tenantID,
			EventType:    "resource_access_violation",
			ResourceType: resourceType,
			Operation:    operation,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now(),
		})

		return fmt.Errorf("resource access validation failed: %w", err)
	}

	return nil
}

func (s *TenantIsolationServiceImpl) ApplyResourceLimits(ctx context.Context, tenantID uuid.UUID, resourceType string, usage int64) error {
	if !s.config.ResourceQuotaEnforcement {
		return nil
	}

	if err := s.resourceIsolationEngine.EnforceResourceLimits(ctx, tenantID, resourceType, usage); err != nil {
		// Audit resource limit violation
		s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
			ID:           uuid.New(),
			TenantID:     tenantID,
			EventType:    "resource_limit_violation",
			ResourceType: resourceType,
			Operation:    "apply_resource_limits",
			Success:      false,
			ErrorMessage: err.Error(),
			Context:      map[string]interface{}{"usage": usage},
			CreatedAt:    time.Now(),
		})

		return fmt.Errorf("resource limit enforcement failed: %w", err)
	}

	return nil
}

// Security Isolation

func (s *TenantIsolationServiceImpl) ValidateSecurityContext(ctx context.Context, tenantCtx *entity.TenantContext, securityLevel entity.SecurityClearanceLevel) error {
	if !s.config.SecurityClearanceEnforcement {
		return nil
	}

	// Get tenant's maximum security clearance
	tenantMaxClearance := tenantCtx.Tenant.MaxSecurityClearance

	if err := s.securityIsolationEngine.ValidateSecurityClearance(ctx, tenantCtx.TenantID, securityLevel, tenantMaxClearance); err != nil {
		// Audit security clearance violation
		s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
			ID:           uuid.New(),
			TenantID:     tenantCtx.TenantID,
			EventType:    "security_clearance_violation",
			UserID:       tenantCtx.UserID,
			Operation:    "validate_security_context",
			Success:      false,
			ErrorMessage: err.Error(),
			Context: map[string]interface{}{
				"requested_clearance":  securityLevel,
				"tenant_max_clearance": tenantMaxClearance,
			},
			CreatedAt: time.Now(),
		})

		return fmt.Errorf("security clearance validation failed: %w", err)
	}

	return nil
}

func (s *TenantIsolationServiceImpl) ApplySecurityPolicies(ctx context.Context, tenantID uuid.UUID, operation string) error {
	if !s.config.EnableSecurityBoundaries {
		return nil
	}

	if err := s.securityIsolationEngine.ApplySecurityPolicies(ctx, tenantID, operation); err != nil {
		return fmt.Errorf("security policy application failed: %w", err)
	}

	return nil
}

// Cross-Tenant Validation

func (s *TenantIsolationServiceImpl) ValidateCrossTenantAccess(ctx context.Context, sourceTenantID, targetTenantID uuid.UUID, operation string) error {
	// In strict isolation mode, cross-tenant access is generally denied
	if s.config.StrictIsolationMode && !s.config.CrossTenantAccessEnabled {
		return fmt.Errorf("cross-tenant access denied in strict isolation mode")
	}

	if !s.config.CrossTenantAccessEnabled {
		return fmt.Errorf("cross-tenant access is disabled")
	}

	if err := s.securityIsolationEngine.ValidateCrossTenantAccess(ctx, sourceTenantID, targetTenantID, operation); err != nil {
		// Audit cross-tenant access violation
		s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
			ID:           uuid.New(),
			TenantID:     sourceTenantID,
			EventType:    "cross_tenant_access_violation",
			Operation:    operation,
			Success:      false,
			ErrorMessage: err.Error(),
			Context: map[string]interface{}{
				"source_tenant": sourceTenantID,
				"target_tenant": targetTenantID,
			},
			CreatedAt: time.Now(),
		})

		return fmt.Errorf("cross-tenant access validation failed: %w", err)
	}

	// Audit successful cross-tenant access
	s.auditLogger.LogTenantEvent(ctx, &service.TenantAuditEvent{
		ID:        uuid.New(),
		TenantID:  sourceTenantID,
		EventType: "cross_tenant_access_granted",
		Operation: operation,
		Success:   true,
		Context: map[string]interface{}{
			"source_tenant": sourceTenantID,
			"target_tenant": targetTenantID,
		},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *TenantIsolationServiceImpl) GetCrossTenantPermissions(ctx context.Context, sourceTenantID, targetTenantID uuid.UUID) (*service.CrossTenantPermissions, error) {
	if !s.config.CrossTenantAccessEnabled {
		return &service.CrossTenantPermissions{
			SourceTenantID:       sourceTenantID,
			TargetTenantID:       targetTenantID,
			AllowedOperations:    []string{},
			RequiredClearance:    entity.SecurityClearanceTopSecret,
			AdditionalConditions: map[string]interface{}{"access_denied": true},
		}, nil
	}

	// Get permissions based on tenant types and clearance levels
	// This would integrate with a more complex permission system
	permissions := &service.CrossTenantPermissions{
		SourceTenantID:    sourceTenantID,
		TargetTenantID:    targetTenantID,
		AllowedOperations: []string{"read_public_data"},
		RequiredClearance: entity.SecurityClearanceConfidential,
		AdditionalConditions: map[string]interface{}{
			"audit_required":    true,
			"approval_required": true,
		},
	}

	return permissions, nil
}

// Monitoring and Metrics

func (s *TenantIsolationServiceImpl) GetIsolationMetrics(ctx context.Context, tenantID uuid.UUID) (*IsolationMetrics, error) {
	metrics := &IsolationMetrics{
		TenantID:  tenantID,
		Timestamp: time.Now(),
	}

	// Get network traffic metrics
	if s.config.EnableNetworkPolicies {
		networkMetrics, err := s.networkIsolationEngine.MonitorNetworkTraffic(ctx, tenantID)
		if err == nil {
			metrics.NetworkMetrics = networkMetrics
		}
	}

	// Get resource utilization metrics
	if s.config.EnableResourceLimits {
		resourceMetrics, err := s.resourceIsolationEngine.GetResourceUtilization(ctx, tenantID)
		if err == nil {
			metrics.ResourceMetrics = resourceMetrics
		}
	}

	return metrics, nil
}

// Supporting types and methods

type IsolationMetrics struct {
	TenantID        uuid.UUID                     `json:"tenant_id"`
	NetworkMetrics  *NetworkTrafficMetrics        `json:"network_metrics"`
	ResourceMetrics *ResourceUtilizationMetrics   `json:"resource_metrics"`
	IsolationStatus string                        `json:"isolation_status"`
	SecurityLevel   entity.SecurityClearanceLevel `json:"security_level"`
	Timestamp       time.Time                     `json:"timestamp"`
}

// Helper functions

func hashQuery(query string) string {
	// Simple hash implementation for audit purposes
	// In production, use proper cryptographic hash
	return fmt.Sprintf("%x", len(query))
}

func normalizeResourceType(resourceType string) string {
	return strings.ToLower(strings.TrimSpace(resourceType))
}

func validateTenantOperation(operation string) bool {
	allowedOperations := []string{
		"create", "read", "update", "delete",
		"list", "search", "aggregate",
		"backup", "restore", "export", "import",
	}

	for _, allowed := range allowedOperations {
		if operation == allowed {
			return true
		}
	}

	return false
}

func isHighPrivilegeOperation(operation string) bool {
	highPrivilegeOps := []string{
		"delete", "backup", "restore",
		"export", "import", "admin",
		"configure", "manage",
	}

	for _, highPrivOp := range highPrivilegeOps {
		if operation == highPrivOp {
			return true
		}
	}

	return false
}
