package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// AuthorizationServiceImpl implements the unified authorization service
type AuthorizationServiceImpl struct {
	rbacService *RBACService
	abacService *ABACService
	auditLogger AuthorizationAuditLogger
	config      *AuthorizationConfig
}

// AuthorizationConfig holds authorization service configuration
type AuthorizationConfig struct {
	PreferRBAC           bool          `yaml:"prefer_rbac" default:"true"`
	EnableABACFallback   bool          `yaml:"enable_abac_fallback" default:"true"`
	RequireBothApprovals bool          `yaml:"require_both_approvals" default:"false"`
	CachePermissions     bool          `yaml:"cache_permissions" default:"true"`
	CacheTimeout         time.Duration `yaml:"cache_timeout" default:"300s"`
	EnableRiskBasedAuth  bool          `yaml:"enable_risk_based_auth" default:"true"`
	EnableAuditLogging   bool          `yaml:"enable_audit_logging" default:"true"`
	MaxPermissionChecks  int           `yaml:"max_permission_checks" default:"100"`
	EnableMetrics        bool          `yaml:"enable_metrics" default:"true"`
}

// NewAuthorizationService creates a new unified authorization service
func NewAuthorizationService(
	rbacService *RBACService,
	abacService *ABACService,
	auditLogger AuthorizationAuditLogger,
	config *AuthorizationConfig,
) *AuthorizationServiceImpl {
	return &AuthorizationServiceImpl{
		rbacService: rbacService,
		abacService: abacService,
		auditLogger: auditLogger,
		config:      config,
	}
}

// Permission Evaluation

func (s *AuthorizationServiceImpl) CheckPermission(ctx context.Context, req *service.PermissionCheckRequest) (*service.PermissionCheckResponse, error) {
	startTime := time.Now()

	// Initialize response
	response := &service.PermissionCheckResponse{
		Allowed:         false,
		EvaluatedAt:     startTime,
		PolicyDecisions: make([]*service.PolicyDecision, 0),
	}

	// First, try RBAC evaluation
	rbacResponse, rbacErr := s.rbacService.CheckPermission(ctx, req)
	if rbacErr != nil && !s.config.EnableABACFallback {
		return nil, fmt.Errorf("RBAC evaluation failed: %w", rbacErr)
	}

	var abacResponse *service.PolicyEvaluationResponse
	var abacErr error

	// Evaluate with ABAC if configured
	if s.config.EnableABACFallback || !s.config.PreferRBAC {
		// Get active policies for the tenant
		policies, err := s.abacService.policyRepo.GetActivePolicies(ctx, req.TenantID)
		if err == nil && len(policies) > 0 {
			// Evaluate with each policy
			for _, policy := range policies {
				evalReq := &service.PolicyEvaluationRequest{
					PolicyID: policy.ID,
					Input: map[string]interface{}{
						"resource":      req.Resource,
						"action":        req.Action,
						"resource_path": req.ResourcePath,
					},
					Context: req.Context,
				}

				policyResult, err := s.abacService.EvaluatePolicy(ctx, evalReq)
				if err == nil {
					response.PolicyDecisions = append(response.PolicyDecisions, &service.PolicyDecision{
						PolicyID: policy.ID,
						Decision: policyResult.Decision,
						Reason:   policyResult.Explanation,
					})

					if policyResult.Decision {
						abacResponse = policyResult
						break // First allowing policy wins
					}
				}
			}
		}
	}

	// Combine results based on configuration
	if s.config.PreferRBAC {
		if rbacErr == nil && rbacResponse.Allowed {
			// RBAC allowed
			response.Allowed = true
			response.Reason = "RBAC authorization granted"
			response.RequiredClearance = rbacResponse.RequiredClearance
			response.RequiresMFA = rbacResponse.RequiresMFA
			response.RequiresApproval = rbacResponse.RequiresApproval
			response.ApplicableRoles = rbacResponse.ApplicableRoles
			response.ApplicablePermissions = rbacResponse.ApplicablePermissions
		} else if s.config.EnableABACFallback && abacResponse != nil && abacResponse.Decision {
			// RBAC denied but ABAC allowed
			response.Allowed = true
			response.Reason = "ABAC policy authorization granted (RBAC fallback)"
		} else {
			// Both denied or failed
			if rbacErr == nil {
				response.Reason = rbacResponse.Reason
				response.RequiredClearance = rbacResponse.RequiredClearance
			} else {
				response.Reason = "authorization denied"
			}
		}
	} else {
		// ABAC preferred
		if abacResponse != nil && abacResponse.Decision {
			response.Allowed = true
			response.Reason = "ABAC policy authorization granted"
		} else if rbacErr == nil && rbacResponse.Allowed {
			response.Allowed = true
			response.Reason = "RBAC authorization granted (ABAC fallback)"
			response.RequiredClearance = rbacResponse.RequiredClearance
			response.RequiresMFA = rbacResponse.RequiresMFA
			response.RequiresApproval = rbacResponse.RequiresApproval
			response.ApplicableRoles = rbacResponse.ApplicableRoles
			response.ApplicablePermissions = rbacResponse.ApplicablePermissions
		} else {
			response.Reason = "authorization denied"
		}
	}

	// Apply additional security checks
	if response.Allowed {
		response.Allowed = s.applyAdditionalSecurityChecks(ctx, req, response)
		if !response.Allowed {
			response.Reason = "additional security checks failed"
		}
	}

	// Add evaluation context
	response.EvaluationContext = map[string]interface{}{
		"rbac_evaluated":  rbacErr == nil,
		"rbac_allowed":    rbacErr == nil && rbacResponse.Allowed,
		"abac_evaluated":  abacResponse != nil,
		"abac_allowed":    abacResponse != nil && abacResponse.Decision,
		"evaluation_time": time.Since(startTime).String(),
	}

	// Audit log
	if s.config.EnableAuditLogging {
		s.auditLogger.LogAccessEvent(ctx, &service.AuthorizationAuditEvent{
			ID:        uuid.New(),
			TenantID:  req.TenantID,
			EventType: "permission_evaluated",
			UserID:    &req.UserID,
			Success:   response.Allowed,
			Reason:    response.Reason,
			IPAddress: req.Context.IPAddress,
			Context:   response.EvaluationContext,
			CreatedAt: time.Now(),
		})
	}

	return response, nil
}

func (s *AuthorizationServiceImpl) CheckMultiplePermissions(ctx context.Context, req *service.MultiplePermissionCheckRequest) (*service.MultiplePermissionCheckResponse, error) {
	if len(req.Permissions) > s.config.MaxPermissionChecks {
		return nil, fmt.Errorf("too many permission checks requested (max: %d)", s.config.MaxPermissionChecks)
	}

	startTime := time.Now()
	results := make([]*service.PermissionCheckResponse, 0, len(req.Permissions))
	overallAllowed := true

	for _, permReq := range req.Permissions {
		checkReq := &service.PermissionCheckRequest{
			UserID:       req.UserID,
			TenantID:     req.TenantID,
			Resource:     permReq.Resource,
			Action:       permReq.Action,
			ResourcePath: permReq.ResourcePath,
			Context:      req.Context,
			Attributes:   permReq.Attributes,
		}

		result, err := s.CheckPermission(ctx, checkReq)
		if err != nil {
			return nil, fmt.Errorf("permission check failed for resource %s: %w", permReq.Resource, err)
		}

		results = append(results, result)

		if !result.Allowed {
			overallAllowed = false
		}
	}

	return &service.MultiplePermissionCheckResponse{
		Results:        results,
		OverallAllowed: overallAllowed,
		EvaluatedAt:    startTime,
	}, nil
}

func (s *AuthorizationServiceImpl) GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.Permission, error) {
	// Get permissions from RBAC
	userRoles, err := s.rbacService.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	permissionMap := make(map[uuid.UUID]*entity.Permission)

	for _, userRole := range userRoles {
		if !userRole.IsEffective() {
			continue
		}

		rolePermissions, err := s.rbacService.permissionRepo.GetByRole(ctx, userRole.RoleID, tenantID)
		if err != nil {
			continue
		}

		for _, permission := range rolePermissions {
			if permission.IsEffective() {
				permissionMap[permission.ID] = permission
			}
		}
	}

	// Convert map to slice
	permissions := make([]*entity.Permission, 0, len(permissionMap))
	for _, permission := range permissionMap {
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (s *AuthorizationServiceImpl) GetEffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID, permCtx *entity.PermissionContext) ([]*entity.Permission, error) {
	// Get all user permissions
	allPermissions, err := s.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	// Filter permissions based on context
	effectivePermissions := make([]*entity.Permission, 0)

	for _, permission := range allPermissions {
		if permCtx != nil {
			// Check security clearance
			if permission.RequiredClearance > permCtx.SecurityClearance {
				continue
			}

			// Check time constraints
			if !permission.CheckTimeConstraints(permCtx.RequestTime, permCtx.Location) {
				continue
			}

			// Check IP constraints
			if !permission.CheckIPConstraints(permCtx.IPAddress) {
				continue
			}

			// Check location constraints
			if !permission.CheckLocationConstraints(permCtx.Location) {
				continue
			}
		}

		effectivePermissions = append(effectivePermissions, permission)
	}

	return effectivePermissions, nil
}

// Role Management (delegated to RBAC service)

func (s *AuthorizationServiceImpl) CreateRole(ctx context.Context, req *service.CreateRoleRequest) (*service.CreateRoleResponse, error) {
	return s.rbacService.CreateRole(ctx, req)
}

func (s *AuthorizationServiceImpl) UpdateRole(ctx context.Context, req *service.UpdateRoleRequest) error {
	return s.rbacService.UpdateRole(ctx, req)
}

func (s *AuthorizationServiceImpl) DeleteRole(ctx context.Context, roleID, tenantID uuid.UUID) error {
	return s.rbacService.DeleteRole(ctx, roleID, tenantID)
}

func (s *AuthorizationServiceImpl) GetRole(ctx context.Context, roleID, tenantID uuid.UUID) (*entity.Role, error) {
	return s.rbacService.GetRole(ctx, roleID, tenantID)
}

func (s *AuthorizationServiceImpl) ListRoles(ctx context.Context, tenantID uuid.UUID, filters *service.RoleFilters) ([]*entity.Role, error) {
	return s.rbacService.ListRoles(ctx, tenantID, filters)
}

func (s *AuthorizationServiceImpl) GetRoleHierarchy(ctx context.Context, tenantID uuid.UUID) (*entity.RoleHierarchy, error) {
	return s.rbacService.GetRoleHierarchy(ctx, tenantID)
}

// Role Assignment (delegated to RBAC service)

func (s *AuthorizationServiceImpl) AssignRole(ctx context.Context, req *service.RoleAssignmentRequest) (*service.RoleAssignmentResponse, error) {
	return s.rbacService.AssignRole(ctx, req)
}

func (s *AuthorizationServiceImpl) RevokeRole(ctx context.Context, req *service.RoleRevocationRequest) error {
	return s.rbacService.RevokeRole(ctx, req)
}

func (s *AuthorizationServiceImpl) GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.UserRole, error) {
	return s.rbacService.GetUserRoles(ctx, userID, tenantID)
}

func (s *AuthorizationServiceImpl) GetRoleUsers(ctx context.Context, roleID, tenantID uuid.UUID) ([]*entity.UserRole, error) {
	return s.rbacService.GetRoleUsers(ctx, roleID, tenantID)
}

// Permission Management (delegated to RBAC service)

func (s *AuthorizationServiceImpl) CreatePermission(ctx context.Context, req *service.CreatePermissionRequest) (*service.CreatePermissionResponse, error) {
	// Validate permission data
	if err := s.validatePermissionRequest(req); err != nil {
		return nil, fmt.Errorf("invalid permission request: %w", err)
	}

	permission := &entity.Permission{
		ID:                  uuid.New(),
		TenantID:            req.TenantID,
		Name:                req.Name,
		DisplayName:         req.DisplayName,
		Description:         req.Description,
		Type:                req.Type,
		Scope:               req.Scope,
		Resource:            req.Resource,
		Action:              req.Action,
		ResourcePath:        req.ResourcePath,
		RequiredClearance:   req.RequiredClearance,
		RequiresMFA:         req.RequiresMFA,
		RequiresApproval:    req.RequiresApproval,
		Constraints:         req.Constraints,
		TimeConstraints:     req.TimeConstraints,
		IPConstraints:       req.IPConstraints,
		LocationConstraints: req.LocationConstraints,
		Inheritable:         req.Inheritable,
		Delegatable:         req.Delegatable,
		MaxDelegationDepth:  req.MaxDelegationDepth,
		IsActive:            true,
		ExpiresAt:           req.ExpiresAt,
		EffectiveFrom:       req.EffectiveFrom,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		CreatedBy:           req.CreatedBy,
		UpdatedBy:           req.CreatedBy,
		Version:             1,
	}

	if err := s.rbacService.permissionRepo.Create(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return &service.CreatePermissionResponse{
		PermissionID: permission.ID,
		CreatedAt:    permission.CreatedAt,
	}, nil
}

func (s *AuthorizationServiceImpl) UpdatePermission(ctx context.Context, req *service.UpdatePermissionRequest) error {
	// Implementation similar to role update...
	return fmt.Errorf("not implemented yet")
}

func (s *AuthorizationServiceImpl) DeletePermission(ctx context.Context, permissionID, tenantID uuid.UUID) error {
	return s.rbacService.permissionRepo.Delete(ctx, permissionID, tenantID)
}

func (s *AuthorizationServiceImpl) GetPermission(ctx context.Context, permissionID, tenantID uuid.UUID) (*entity.Permission, error) {
	return s.rbacService.permissionRepo.GetByID(ctx, permissionID, tenantID)
}

func (s *AuthorizationServiceImpl) ListPermissions(ctx context.Context, tenantID uuid.UUID, filters *service.PermissionFilters) ([]*entity.Permission, error) {
	return s.rbacService.permissionRepo.ListByTenant(ctx, tenantID, filters)
}

// Role-Permission Association

func (s *AuthorizationServiceImpl) GrantPermissionToRole(ctx context.Context, req *service.GrantPermissionRequest) error {
	// Get role and permission to validate
	role, err := s.rbacService.roleRepo.GetByID(ctx, req.RoleID, req.TenantID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	permission, err := s.rbacService.permissionRepo.GetByID(ctx, req.PermissionID, req.TenantID)
	if err != nil {
		return fmt.Errorf("permission not found: %w", err)
	}

	// Check if permission is already granted
	if role.HasPermission(req.PermissionID) {
		return fmt.Errorf("permission already granted to role")
	}

	// Add permission to role
	role.Permissions = append(role.Permissions, req.PermissionID)
	role.UpdatedAt = time.Now()
	role.Version++

	if err := s.rbacService.roleRepo.Update(ctx, role); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:           uuid.New(),
		TenantID:     req.TenantID,
		EventType:    "permission_granted_to_role",
		UserID:       &req.GrantedBy,
		RoleID:       &req.RoleID,
		PermissionID: &req.PermissionID,
		Success:      true,
		Context: map[string]interface{}{
			"role_name":       role.Name,
			"permission_name": permission.Name,
		},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *AuthorizationServiceImpl) RevokePermissionFromRole(ctx context.Context, req *service.RevokePermissionRequest) error {
	// Get role
	role, err := s.rbacService.roleRepo.GetByID(ctx, req.RoleID, req.TenantID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Remove permission from role
	newPermissions := make([]uuid.UUID, 0)
	found := false
	for _, permID := range role.Permissions {
		if permID != req.PermissionID {
			newPermissions = append(newPermissions, permID)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("permission not granted to role")
	}

	role.Permissions = newPermissions
	role.UpdatedAt = time.Now()
	role.Version++

	if err := s.rbacService.roleRepo.Update(ctx, role); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:           uuid.New(),
		TenantID:     req.TenantID,
		EventType:    "permission_revoked_from_role",
		UserID:       &req.RevokedBy,
		RoleID:       &req.RoleID,
		PermissionID: &req.PermissionID,
		Success:      true,
		CreatedAt:    time.Now(),
	})

	return nil
}

func (s *AuthorizationServiceImpl) GetRolePermissions(ctx context.Context, roleID, tenantID uuid.UUID) ([]*entity.Permission, error) {
	return s.rbacService.permissionRepo.GetByRole(ctx, roleID, tenantID)
}

// Policy Management (delegated to ABAC service)

func (s *AuthorizationServiceImpl) EvaluatePolicy(ctx context.Context, req *service.PolicyEvaluationRequest) (*service.PolicyEvaluationResponse, error) {
	return s.abacService.EvaluatePolicy(ctx, req)
}

func (s *AuthorizationServiceImpl) CreatePolicy(ctx context.Context, req *service.CreatePolicyRequest) (*service.CreatePolicyResponse, error) {
	return s.abacService.CreatePolicy(ctx, req)
}

func (s *AuthorizationServiceImpl) UpdatePolicy(ctx context.Context, req *service.UpdatePolicyRequest) error {
	return s.abacService.UpdatePolicy(ctx, req)
}

func (s *AuthorizationServiceImpl) DeletePolicy(ctx context.Context, policyID string, tenantID uuid.UUID) error {
	return s.abacService.DeletePolicy(ctx, policyID, tenantID)
}

// Additional methods would be implemented...

// Helper methods

func (s *AuthorizationServiceImpl) applyAdditionalSecurityChecks(ctx context.Context, req *service.PermissionCheckRequest, response *service.PermissionCheckResponse) bool {
	// Risk-based authentication
	if s.config.EnableRiskBasedAuth && req.Context != nil && req.Context.SessionInfo != nil {
		if req.Context.SessionInfo.RiskScore > 0.8 {
			return false // High risk score
		}
	}

	// MFA requirement check
	if response.RequiresMFA && req.Context != nil && req.Context.SessionInfo != nil {
		if !req.Context.SessionInfo.MFAVerified {
			return false
		}

		// Check MFA timestamp (require recent MFA for sensitive operations)
		if req.Context.SessionInfo.MFATimestamp != nil {
			mfaAge := time.Since(*req.Context.SessionInfo.MFATimestamp)
			if mfaAge > time.Hour { // Require MFA within last hour for sensitive operations
				return false
			}
		}
	}

	return true
}

func (s *AuthorizationServiceImpl) validatePermissionRequest(req *service.CreatePermissionRequest) error {
	if req.Name == "" {
		return fmt.Errorf("permission name is required")
	}
	if req.DisplayName == "" {
		return fmt.Errorf("permission display name is required")
	}
	if !entity.ValidatePermissionType(string(req.Type)) {
		return fmt.Errorf("invalid permission type: %s", req.Type)
	}
	if !entity.ValidatePermissionScope(string(req.Scope)) {
		return fmt.Errorf("invalid permission scope: %s", req.Scope)
	}
	if !entity.ValidateAction(string(req.Action)) {
		return fmt.Errorf("invalid action: %s", req.Action)
	}
	if req.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	return nil
}

// Additional methods for delegation, clearance checks, audit, etc. would be implemented here...
