package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// RBACService implements Role-Based Access Control
type RBACService struct {
	roleRepo       RoleRepository
	permissionRepo PermissionRepository
	userRoleRepo   UserRoleRepository
	auditLogger    AuthorizationAuditLogger
	config         *RBACConfig
}

// RBACConfig holds RBAC service configuration
type RBACConfig struct {
	MaxRolesPerUser             int           `yaml:"max_roles_per_user" default:"10"`
	MaxPermissionsPerRole       int           `yaml:"max_permissions_per_role" default:"100"`
	EnableRoleHierarchy         bool          `yaml:"enable_role_hierarchy" default:"true"`
	EnablePermissionInheritance bool          `yaml:"enable_permission_inheritance" default:"true"`
	MaxDelegationDepth          int           `yaml:"max_delegation_depth" default:"3"`
	DefaultRoleExpiration       time.Duration `yaml:"default_role_expiration" default:"8760h"` // 1 year
	EnableTimeConstraints       bool          `yaml:"enable_time_constraints" default:"true"`
	EnableLocationConstraints   bool          `yaml:"enable_location_constraints" default:"true"`
	CacheTimeout                time.Duration `yaml:"cache_timeout" default:"300s"`
}

// Repository interfaces
type RoleRepository interface {
	Create(ctx context.Context, role *entity.Role) error
	Update(ctx context.Context, role *entity.Role) error
	Delete(ctx context.Context, roleID, tenantID uuid.UUID) error
	GetByID(ctx context.Context, roleID, tenantID uuid.UUID) (*entity.Role, error)
	GetByName(ctx context.Context, name string, tenantID uuid.UUID) (*entity.Role, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, filters *service.RoleFilters) ([]*entity.Role, error)
	GetRoleHierarchy(ctx context.Context, tenantID uuid.UUID) (*entity.RoleHierarchy, error)
	GetChildRoles(ctx context.Context, parentRoleID, tenantID uuid.UUID) ([]*entity.Role, error)
	GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]*entity.Role, error)
	IncrementUserCount(ctx context.Context, roleID, tenantID uuid.UUID) error
	DecrementUserCount(ctx context.Context, roleID, tenantID uuid.UUID) error
}

type PermissionRepository interface {
	Create(ctx context.Context, permission *entity.Permission) error
	Update(ctx context.Context, permission *entity.Permission) error
	Delete(ctx context.Context, permissionID, tenantID uuid.UUID) error
	GetByID(ctx context.Context, permissionID, tenantID uuid.UUID) (*entity.Permission, error)
	GetByName(ctx context.Context, name string, tenantID uuid.UUID) (*entity.Permission, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, filters *service.PermissionFilters) ([]*entity.Permission, error)
	GetByResource(ctx context.Context, resource string, action entity.Action, tenantID uuid.UUID) ([]*entity.Permission, error)
	GetByRole(ctx context.Context, roleID, tenantID uuid.UUID) ([]*entity.Permission, error)
}

type UserRoleRepository interface {
	Create(ctx context.Context, userRole *entity.UserRole) error
	Update(ctx context.Context, userRole *entity.UserRole) error
	Delete(ctx context.Context, userRoleID, tenantID uuid.UUID) error
	GetByID(ctx context.Context, userRoleID, tenantID uuid.UUID) (*entity.UserRole, error)
	GetByUser(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.UserRole, error)
	GetByRole(ctx context.Context, roleID, tenantID uuid.UUID) ([]*entity.UserRole, error)
	GetByUserAndRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) (*entity.UserRole, error)
	DeleteByUserAndRole(ctx context.Context, userID, roleID, tenantID uuid.UUID) error
	GetEffectiveRoles(ctx context.Context, userID, tenantID uuid.UUID, context *entity.PermissionContext) ([]*entity.UserRole, error)
	GetDelegations(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.UserRole, error)
	CleanupExpiredRoles(ctx context.Context) (int64, error)
}

type AuthorizationAuditLogger interface {
	LogRoleEvent(ctx context.Context, event *service.AuthorizationAuditEvent) error
	LogPermissionEvent(ctx context.Context, event *service.AuthorizationAuditEvent) error
	LogAccessEvent(ctx context.Context, event *service.AuthorizationAuditEvent) error
}

// NewRBACService creates a new RBAC service
func NewRBACService(
	roleRepo RoleRepository,
	permissionRepo PermissionRepository,
	userRoleRepo UserRoleRepository,
	auditLogger AuthorizationAuditLogger,
	config *RBACConfig,
) *RBACService {
	return &RBACService{
		roleRepo:       roleRepo,
		permissionRepo: permissionRepo,
		userRoleRepo:   userRoleRepo,
		auditLogger:    auditLogger,
		config:         config,
	}
}

// Role Management

func (s *RBACService) CreateRole(ctx context.Context, req *service.CreateRoleRequest) (*service.CreateRoleResponse, error) {
	// Validate request
	if err := s.validateCreateRoleRequest(req); err != nil {
		return nil, fmt.Errorf("invalid role request: %w", err)
	}

	// Check for name conflicts
	existing, _ := s.roleRepo.GetByName(ctx, req.Name, req.TenantID)
	if existing != nil {
		return nil, fmt.Errorf("role with name '%s' already exists", req.Name)
	}

	// Check parent role if specified
	if req.ParentRoleID != nil {
		parentRole, err := s.roleRepo.GetByID(ctx, *req.ParentRoleID, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("parent role not found: %w", err)
		}
		if !parentRole.IsEffective() {
			return nil, fmt.Errorf("parent role is not active or effective")
		}
	}

	// Create role entity
	role := &entity.Role{
		ID:                 uuid.New(),
		TenantID:           req.TenantID,
		Name:               req.Name,
		DisplayName:        req.DisplayName,
		Description:        req.Description,
		Type:               req.Type,
		Scope:              req.Scope,
		ParentRoleID:       req.ParentRoleID,
		Level:              s.calculateRoleLevel(ctx, req.ParentRoleID, req.TenantID),
		InheritPermissions: req.InheritPermissions,
		RequiredClearance:  req.RequiredClearance,
		MaxClearance:       req.MaxClearance,
		Permissions:        req.Permissions,
		PermissionDenials:  req.PermissionDenials,
		MaxUsers:           req.MaxUsers,
		RequiresMFA:        req.RequiresMFA,
		RequiresApproval:   req.RequiresApproval,
		CanDelegate:        req.CanDelegate,
		CanAssign:          req.CanAssign,
		AutoAssignable:     req.AutoAssignable,
		TimeConstraints:    req.TimeConstraints,
		MaxSessionDuration: req.MaxSessionDuration,
		AssignmentRules:    req.AssignmentRules,
		ConflictingRoles:   req.ConflictingRoles,
		RequiredRoles:      req.RequiredRoles,
		IsActive:           true,
		IsDefault:          req.IsDefault,
		ExpiresAt:          req.ExpiresAt,
		EffectiveFrom:      req.EffectiveFrom,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		CreatedBy:          req.CreatedBy,
		UpdatedBy:          req.CreatedBy,
		Version:            1,
		UserCount:          0,
	}

	// Validate permissions exist
	if err := s.validatePermissions(ctx, role.Permissions, req.TenantID); err != nil {
		return nil, fmt.Errorf("invalid permissions: %w", err)
	}

	// Save role
	if err := s.roleRepo.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "role_created",
		UserID:    &req.CreatedBy,
		RoleID:    &role.ID,
		Success:   true,
		Context:   map[string]interface{}{"role_name": role.Name, "role_type": role.Type},
		CreatedAt: time.Now(),
	})

	return &service.CreateRoleResponse{
		RoleID:    role.ID,
		CreatedAt: role.CreatedAt,
	}, nil
}

func (s *RBACService) UpdateRole(ctx context.Context, req *service.UpdateRoleRequest) error {
	// Get existing role
	role, err := s.roleRepo.GetByID(ctx, req.RoleID, req.TenantID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Update fields
	updated := false
	if req.Name != "" && req.Name != role.Name {
		// Check for name conflicts
		existing, _ := s.roleRepo.GetByName(ctx, req.Name, req.TenantID)
		if existing != nil && existing.ID != role.ID {
			return fmt.Errorf("role with name '%s' already exists", req.Name)
		}
		role.Name = req.Name
		updated = true
	}

	if req.DisplayName != "" && req.DisplayName != role.DisplayName {
		role.DisplayName = req.DisplayName
		updated = true
	}

	if req.Description != "" && req.Description != role.Description {
		role.Description = req.Description
		updated = true
	}

	if req.RequiredClearance != nil && *req.RequiredClearance != role.RequiredClearance {
		role.RequiredClearance = *req.RequiredClearance
		updated = true
	}

	if req.MaxClearance != nil && *req.MaxClearance != role.MaxClearance {
		role.MaxClearance = *req.MaxClearance
		updated = true
	}

	if req.MaxUsers != nil && *req.MaxUsers != role.MaxUsers {
		role.MaxUsers = *req.MaxUsers
		updated = true
	}

	if req.RequiresMFA != nil && *req.RequiresMFA != role.RequiresMFA {
		role.RequiresMFA = *req.RequiresMFA
		updated = true
	}

	if req.RequiresApproval != nil && *req.RequiresApproval != role.RequiresApproval {
		role.RequiresApproval = *req.RequiresApproval
		updated = true
	}

	if req.CanDelegate != nil && *req.CanDelegate != role.CanDelegate {
		role.CanDelegate = *req.CanDelegate
		updated = true
	}

	if req.CanAssign != nil && *req.CanAssign != role.CanAssign {
		role.CanAssign = *req.CanAssign
		updated = true
	}

	if req.AutoAssignable != nil && *req.AutoAssignable != role.AutoAssignable {
		role.AutoAssignable = *req.AutoAssignable
		updated = true
	}

	if req.TimeConstraints != nil {
		role.TimeConstraints = req.TimeConstraints
		updated = true
	}

	if req.MaxSessionDuration != nil && *req.MaxSessionDuration != role.MaxSessionDuration {
		role.MaxSessionDuration = *req.MaxSessionDuration
		updated = true
	}

	if req.AssignmentRules != nil {
		role.AssignmentRules = req.AssignmentRules
		updated = true
	}

	if req.ConflictingRoles != nil {
		role.ConflictingRoles = req.ConflictingRoles
		updated = true
	}

	if req.RequiredRoles != nil {
		role.RequiredRoles = req.RequiredRoles
		updated = true
	}

	if req.IsActive != nil && *req.IsActive != role.IsActive {
		role.IsActive = *req.IsActive
		updated = true
	}

	if req.IsDefault != nil && *req.IsDefault != role.IsDefault {
		role.IsDefault = *req.IsDefault
		updated = true
	}

	if req.ExpiresAt != nil {
		role.ExpiresAt = req.ExpiresAt
		updated = true
	}

	if !updated {
		return nil // No changes
	}

	// Update metadata
	role.UpdatedAt = time.Now()
	role.UpdatedBy = req.UpdatedBy
	role.Version++

	// Save role
	if err := s.roleRepo.Update(ctx, role); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "role_updated",
		UserID:    &req.UpdatedBy,
		RoleID:    &role.ID,
		Success:   true,
		Context:   map[string]interface{}{"role_name": role.Name, "version": role.Version},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *RBACService) DeleteRole(ctx context.Context, roleID, tenantID uuid.UUID) error {
	// Get role
	role, err := s.roleRepo.GetByID(ctx, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Check if role has users
	users, err := s.userRoleRepo.GetByRole(ctx, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check role users: %w", err)
	}

	if len(users) > 0 {
		return fmt.Errorf("cannot delete role with %d assigned users", len(users))
	}

	// Check if role has child roles
	children, err := s.roleRepo.GetChildRoles(ctx, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check child roles: %w", err)
	}

	if len(children) > 0 {
		return fmt.Errorf("cannot delete role with %d child roles", len(children))
	}

	// Delete role
	if err := s.roleRepo.Delete(ctx, roleID, tenantID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "role_deleted",
		RoleID:    &roleID,
		Success:   true,
		Context:   map[string]interface{}{"role_name": role.Name},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *RBACService) GetRole(ctx context.Context, roleID, tenantID uuid.UUID) (*entity.Role, error) {
	return s.roleRepo.GetByID(ctx, roleID, tenantID)
}

func (s *RBACService) ListRoles(ctx context.Context, tenantID uuid.UUID, filters *service.RoleFilters) ([]*entity.Role, error) {
	return s.roleRepo.ListByTenant(ctx, tenantID, filters)
}

func (s *RBACService) GetRoleHierarchy(ctx context.Context, tenantID uuid.UUID) (*entity.RoleHierarchy, error) {
	return s.roleRepo.GetRoleHierarchy(ctx, tenantID)
}

// Role Assignment

func (s *RBACService) AssignRole(ctx context.Context, req *service.RoleAssignmentRequest) (*service.RoleAssignmentResponse, error) {
	// Get role
	role, err := s.roleRepo.GetByID(ctx, req.RoleID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	if !role.IsEffective() {
		return nil, fmt.Errorf("role is not active or effective")
	}

	// Check if user already has this role
	existing, _ := s.userRoleRepo.GetByUserAndRole(ctx, req.UserID, req.RoleID, req.TenantID)
	if existing != nil && existing.IsEffective() {
		return nil, fmt.Errorf("user already has this role")
	}

	// Check role limits
	if role.MaxUsers > 0 {
		currentUsers, err := s.userRoleRepo.GetByRole(ctx, req.RoleID, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to check role user count: %w", err)
		}

		activeUsers := 0
		for _, userRole := range currentUsers {
			if userRole.IsEffective() {
				activeUsers++
			}
		}

		if activeUsers >= role.MaxUsers {
			return nil, fmt.Errorf("role has reached maximum user limit (%d)", role.MaxUsers)
		}
	}

	// Check user role limits
	userRoles, err := s.userRoleRepo.GetByUser(ctx, req.UserID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to check user roles: %w", err)
	}

	activeRoles := 0
	userRoleIDs := make([]uuid.UUID, 0)
	for _, userRole := range userRoles {
		if userRole.IsEffective() {
			activeRoles++
			userRoleIDs = append(userRoleIDs, userRole.RoleID)
		}
	}

	if activeRoles >= s.config.MaxRolesPerUser {
		return nil, fmt.Errorf("user has reached maximum role limit (%d)", s.config.MaxRolesPerUser)
	}

	// Check role conflicts
	conflicts := role.CheckConflicts(userRoleIDs)
	if len(conflicts) > 0 {
		return nil, fmt.Errorf("role conflicts with existing roles: %v", conflicts)
	}

	// Check role prerequisites
	missing := role.CheckPrerequisites(userRoleIDs)
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required roles: %v", missing)
	}

	// Create user role assignment
	userRole := &entity.UserRole{
		ID:               uuid.New(),
		UserID:           req.UserID,
		RoleID:           req.RoleID,
		TenantID:         req.TenantID,
		AssignmentType:   req.AssignmentType,
		AssignedBy:       req.AssignedBy,
		AssignmentReason: req.AssignmentReason,
		Scope:            req.Scope,
		ResourceID:       req.ResourceID,
		ProjectID:        req.ProjectID,
		TeamID:           req.TeamID,
		Conditions:       req.Conditions,
		IPConstraints:    req.IPConstraints,
		TimeConstraints:  req.TimeConstraints,
		IsDelegated:      req.AssignmentType == entity.AssignmentTypeDelegated,
		IsActive:         true,
		IsTemporary:      req.IsTemporary,
		ExpiresAt:        req.ExpiresAt,
		EffectiveFrom:    req.EffectiveFrom,
		RequiresApproval: role.RequiresApproval,
		ApprovalStatus:   entity.ApprovalStatusPending,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Set approval status
	if !role.RequiresApproval {
		userRole.ApprovalStatus = entity.ApprovalStatusApproved
		userRole.ApprovedBy = &req.AssignedBy
		userRole.ApprovedAt = &userRole.CreatedAt
	}

	// Save assignment
	if err := s.userRoleRepo.Create(ctx, userRole); err != nil {
		return nil, fmt.Errorf("failed to assign role: %w", err)
	}

	// Update role user count
	if err := s.roleRepo.IncrementUserCount(ctx, req.RoleID, req.TenantID); err != nil {
		// Log error but don't fail the operation
		// Could implement retry logic here
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "role_assigned",
		UserID:    &req.UserID,
		RoleID:    &req.RoleID,
		Success:   true,
		Context: map[string]interface{}{
			"assignment_type":   req.AssignmentType,
			"assigned_by":       req.AssignedBy,
			"requires_approval": role.RequiresApproval,
		},
		CreatedAt: time.Now(),
	})

	return &service.RoleAssignmentResponse{
		UserRoleID:       userRole.ID,
		RequiresApproval: role.RequiresApproval,
		AssignedAt:       userRole.CreatedAt,
	}, nil
}

func (s *RBACService) RevokeRole(ctx context.Context, req *service.RoleRevocationRequest) error {
	// Get user role assignment
	userRole, err := s.userRoleRepo.GetByUserAndRole(ctx, req.UserID, req.RoleID, req.TenantID)
	if err != nil {
		return fmt.Errorf("role assignment not found: %w", err)
	}

	// Delete assignment
	if err := s.userRoleRepo.Delete(ctx, userRole.ID, req.TenantID); err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	// Update role user count
	if err := s.roleRepo.DecrementUserCount(ctx, req.RoleID, req.TenantID); err != nil {
		// Log error but don't fail the operation
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "role_revoked",
		UserID:    &req.UserID,
		RoleID:    &req.RoleID,
		Success:   true,
		Context: map[string]interface{}{
			"revoked_by":        req.RevokedBy,
			"revocation_reason": req.RevocationReason,
		},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *RBACService) GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.UserRole, error) {
	return s.userRoleRepo.GetByUser(ctx, userID, tenantID)
}

func (s *RBACService) GetRoleUsers(ctx context.Context, roleID, tenantID uuid.UUID) ([]*entity.UserRole, error) {
	return s.userRoleRepo.GetByRole(ctx, roleID, tenantID)
}

// Permission evaluation

func (s *RBACService) CheckPermission(ctx context.Context, req *service.PermissionCheckRequest) (*service.PermissionCheckResponse, error) {
	// Get user's effective roles
	userRoles, err := s.userRoleRepo.GetEffectiveRoles(ctx, req.UserID, req.TenantID, req.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Check permissions for each role
	allowed := false
	var applicableRoles []uuid.UUID
	var applicablePermissions []uuid.UUID
	var requiredClearance entity.SecurityClearanceLevel
	requiresMFA := false
	requiresApproval := false

	for _, userRole := range userRoles {
		if !userRole.IsEffective() {
			continue
		}

		// Check time and location constraints
		if req.Context != nil {
			if !userRole.CheckTimeConstraints(req.Context.RequestTime, req.Context.Location) {
				continue
			}
			if !userRole.CheckIPConstraints(req.Context.IPAddress) {
				continue
			}
		}

		// Get role
		role, err := s.roleRepo.GetByID(ctx, userRole.RoleID, req.TenantID)
		if err != nil || !role.IsEffective() {
			continue
		}

		// Get role permissions
		permissions, err := s.permissionRepo.GetByRole(ctx, role.ID, req.TenantID)
		if err != nil {
			continue
		}

		// Check each permission
		for _, permission := range permissions {
			if !permission.IsEffective() {
				continue
			}

			if permission.Matches(req.Resource, req.Action, req.ResourcePath) {
				// Check security clearance
				if req.Context != nil && permission.RequiredClearance > req.Context.SecurityClearance {
					requiredClearance = permission.RequiredClearance
					continue
				}

				// Check time constraints
				if req.Context != nil && !permission.CheckTimeConstraints(req.Context.RequestTime, req.Context.Location) {
					continue
				}

				// Check IP constraints
				if req.Context != nil && !permission.CheckIPConstraints(req.Context.IPAddress) {
					continue
				}

				// Check location constraints
				if req.Context != nil && !permission.CheckLocationConstraints(req.Context.Location) {
					continue
				}

				// Permission matched
				allowed = true
				applicableRoles = append(applicableRoles, role.ID)
				applicablePermissions = append(applicablePermissions, permission.ID)

				if permission.RequiresMFA {
					requiresMFA = true
				}
				if permission.RequiresApproval {
					requiresApproval = true
				}
			}
		}
	}

	reason := ""
	if !allowed {
		if requiredClearance > 0 {
			reason = fmt.Sprintf("insufficient security clearance (required: %s)", requiredClearance)
		} else {
			reason = "permission denied"
		}
	}

	// Audit log
	s.auditLogger.LogAccessEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "permission_check",
		UserID:    &req.UserID,
		Success:   allowed,
		Reason:    reason,
		IPAddress: req.Context.IPAddress,
		UserAgent: req.Context.SessionInfo.AuthenticationMethod, // Use as proxy for user agent
		Context: map[string]interface{}{
			"resource":      req.Resource,
			"action":        req.Action,
			"resource_path": req.ResourcePath,
		},
		CreatedAt: time.Now(),
	})

	return &service.PermissionCheckResponse{
		Allowed:               allowed,
		Reason:                reason,
		RequiredClearance:     requiredClearance,
		RequiresMFA:           requiresMFA,
		RequiresApproval:      requiresApproval,
		ApplicableRoles:       applicableRoles,
		ApplicablePermissions: applicablePermissions,
		EvaluatedAt:           time.Now(),
	}, nil
}

// Helper methods

func (s *RBACService) validateCreateRoleRequest(req *service.CreateRoleRequest) error {
	if req.Name == "" {
		return fmt.Errorf("role name is required")
	}
	if req.DisplayName == "" {
		return fmt.Errorf("role display name is required")
	}
	if !entity.ValidateRoleType(string(req.Type)) {
		return fmt.Errorf("invalid role type: %s", req.Type)
	}
	if !entity.ValidateRoleScope(string(req.Scope)) {
		return fmt.Errorf("invalid role scope: %s", req.Scope)
	}
	if req.MaxUsers < 0 {
		return fmt.Errorf("max users cannot be negative")
	}
	return nil
}

func (s *RBACService) validatePermissions(ctx context.Context, permissionIDs []uuid.UUID, tenantID uuid.UUID) error {
	for _, permID := range permissionIDs {
		_, err := s.permissionRepo.GetByID(ctx, permID, tenantID)
		if err != nil {
			return fmt.Errorf("permission %s not found", permID)
		}
	}
	return nil
}

func (s *RBACService) calculateRoleLevel(ctx context.Context, parentRoleID *uuid.UUID, tenantID uuid.UUID) int {
	if parentRoleID == nil {
		return 0
	}

	parentRole, err := s.roleRepo.GetByID(ctx, *parentRoleID, tenantID)
	if err != nil {
		return 0
	}

	return parentRole.Level + 1
}
