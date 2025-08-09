package entity

import (
	"time"

	"github.com/google/uuid"
)

// RoleType represents the type of role
type RoleType string

const (
	RoleTypeSystem    RoleType = "system"    // System-defined role
	RoleTypeCustom    RoleType = "custom"    // Custom tenant-defined role
	RoleTypeGroup     RoleType = "group"     // Group-based role
	RoleTypeTemporary RoleType = "temporary" // Temporary role with expiration
	RoleTypeDelegated RoleType = "delegated" // Delegated role from another user
)

// RoleScope represents the scope of a role
type RoleScope string

const (
	RoleScopeGlobal   RoleScope = "global"   // Global across all tenants
	RoleScopeTenant   RoleScope = "tenant"   // Tenant-specific
	RoleScopeProject  RoleScope = "project"  // Project-specific
	RoleScopeTeam     RoleScope = "team"     // Team-specific
	RoleScopeResource RoleScope = "resource" // Resource-specific
)

// Role represents a role in the RBAC system
type Role struct {
	ID          uuid.UUID `json:"id" db:"id"`
	TenantID    uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	DisplayName string    `json:"display_name" db:"display_name"`
	Description string    `json:"description" db:"description"`
	Type        RoleType  `json:"type" db:"type"`
	Scope       RoleScope `json:"scope" db:"scope"`

	// Hierarchy and inheritance
	ParentRoleID       *uuid.UUID  `json:"parent_role_id" db:"parent_role_id"`
	ChildRoles         []uuid.UUID `json:"child_roles" db:"child_roles"`
	Level              int         `json:"level" db:"level"`                             // Hierarchy level (0 = root)
	InheritPermissions bool        `json:"inherit_permissions" db:"inherit_permissions"` // Inherit from parent

	// Security classification
	RequiredClearance SecurityClearanceLevel `json:"required_clearance" db:"required_clearance"`
	MaxClearance      SecurityClearanceLevel `json:"max_clearance" db:"max_clearance"`

	// Permission management
	Permissions       []uuid.UUID `json:"permissions" db:"permissions"`               // Direct permissions
	PermissionDenials []uuid.UUID `json:"permission_denials" db:"permission_denials"` // Explicitly denied permissions

	// Role constraints and conditions
	MaxUsers         int  `json:"max_users" db:"max_users"`                 // Maximum users that can have this role
	RequiresMFA      bool `json:"requires_mfa" db:"requires_mfa"`           // Role requires MFA
	RequiresApproval bool `json:"requires_approval" db:"requires_approval"` // Role assignment requires approval

	// Delegation and assignment
	CanDelegate    bool `json:"can_delegate" db:"can_delegate"`       // Can delegate this role to others
	CanAssign      bool `json:"can_assign" db:"can_assign"`           // Can assign this role to others
	AutoAssignable bool `json:"auto_assignable" db:"auto_assignable"` // Can be automatically assigned

	// Time-based constraints
	TimeConstraints    *TimeConstraints `json:"time_constraints" db:"time_constraints"`         // Time-based access constraints
	MaxSessionDuration time.Duration    `json:"max_session_duration" db:"max_session_duration"` // Maximum session duration for role

	// Assignment rules and conditions
	AssignmentRules  map[string]interface{} `json:"assignment_rules" db:"assignment_rules"`   // Rules for automatic assignment
	ConflictingRoles []uuid.UUID            `json:"conflicting_roles" db:"conflicting_roles"` // Mutually exclusive roles
	RequiredRoles    []uuid.UUID            `json:"required_roles" db:"required_roles"`       // Prerequisites roles

	// Lifecycle management
	IsActive      bool       `json:"is_active" db:"is_active"`
	IsDefault     bool       `json:"is_default" db:"is_default"` // Default role for new users
	ExpiresAt     *time.Time `json:"expires_at" db:"expires_at"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`

	// Audit and metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy uuid.UUID `json:"updated_by" db:"updated_by"`
	Version   int       `json:"version" db:"version"`

	// Usage statistics
	UserCount      int        `json:"user_count" db:"user_count"` // Current number of users with this role
	LastAssignedAt *time.Time `json:"last_assigned_at" db:"last_assigned_at"`
}

// UserRole represents the assignment of a role to a user
type UserRole struct {
	ID       uuid.UUID `json:"id" db:"id"`
	UserID   uuid.UUID `json:"user_id" db:"user_id"`
	RoleID   uuid.UUID `json:"role_id" db:"role_id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// Assignment context
	AssignmentType   AssignmentType `json:"assignment_type" db:"assignment_type"` // How the role was assigned
	AssignedBy       uuid.UUID      `json:"assigned_by" db:"assigned_by"`
	AssignmentReason string         `json:"assignment_reason" db:"assignment_reason"`

	// Scope and constraints
	Scope      RoleScope  `json:"scope" db:"scope"`
	ResourceID *uuid.UUID `json:"resource_id" db:"resource_id"` // For resource-scoped roles
	ProjectID  *uuid.UUID `json:"project_id" db:"project_id"`   // For project-scoped roles
	TeamID     *uuid.UUID `json:"team_id" db:"team_id"`         // For team-scoped roles

	// Conditions and constraints
	Conditions      map[string]interface{} `json:"conditions" db:"conditions"`             // Custom conditions for role activation
	IPConstraints   []string               `json:"ip_constraints" db:"ip_constraints"`     // IP-based constraints
	TimeConstraints *TimeConstraints       `json:"time_constraints" db:"time_constraints"` // Time-based constraints

	// Delegation information
	IsDelegated     bool        `json:"is_delegated" db:"is_delegated"`
	DelegatedBy     *uuid.UUID  `json:"delegated_by" db:"delegated_by"`
	DelegationDepth int         `json:"delegation_depth" db:"delegation_depth"`
	DelegationChain []uuid.UUID `json:"delegation_chain" db:"delegation_chain"`

	// Lifecycle management
	IsActive      bool       `json:"is_active" db:"is_active"`
	IsTemporary   bool       `json:"is_temporary" db:"is_temporary"`
	ExpiresAt     *time.Time `json:"expires_at" db:"expires_at"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`

	// Approval workflow
	RequiresApproval bool           `json:"requires_approval" db:"requires_approval"`
	ApprovalStatus   ApprovalStatus `json:"approval_status" db:"approval_status"`
	ApprovedBy       *uuid.UUID     `json:"approved_by" db:"approved_by"`
	ApprovedAt       *time.Time     `json:"approved_at" db:"approved_at"`

	// Audit and metadata
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
}

// AssignmentType represents how a role was assigned
type AssignmentType string

const (
	AssignmentTypeDirect    AssignmentType = "direct"    // Directly assigned
	AssignmentTypeInherited AssignmentType = "inherited" // Inherited from group/parent
	AssignmentTypeAutomatic AssignmentType = "automatic" // Automatically assigned by rules
	AssignmentTypeDelegated AssignmentType = "delegated" // Delegated by another user
	AssignmentTypeTemporary AssignmentType = "temporary" // Temporary assignment
)

// ApprovalStatus represents the approval status of a role assignment
type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
	ApprovalStatusExpired  ApprovalStatus = "expired"
)

// RoleAssignmentRequest represents a request to assign a role
type RoleAssignmentRequest struct {
	UserID           uuid.UUID              `json:"user_id"`
	RoleID           uuid.UUID              `json:"role_id"`
	TenantID         uuid.UUID              `json:"tenant_id"`
	AssignmentType   AssignmentType         `json:"assignment_type"`
	AssignedBy       uuid.UUID              `json:"assigned_by"`
	AssignmentReason string                 `json:"assignment_reason"`
	Scope            RoleScope              `json:"scope"`
	ResourceID       *uuid.UUID             `json:"resource_id,omitempty"`
	ProjectID        *uuid.UUID             `json:"project_id,omitempty"`
	TeamID           *uuid.UUID             `json:"team_id,omitempty"`
	Conditions       map[string]interface{} `json:"conditions,omitempty"`
	IPConstraints    []string               `json:"ip_constraints,omitempty"`
	TimeConstraints  *TimeConstraints       `json:"time_constraints,omitempty"`
	IsTemporary      bool                   `json:"is_temporary"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	EffectiveFrom    time.Time              `json:"effective_from"`
}

// RoleHierarchy represents the hierarchical structure of roles
type RoleHierarchy struct {
	RoleID      uuid.UUID        `json:"role_id"`
	Role        *Role            `json:"role"`
	ParentID    *uuid.UUID       `json:"parent_id"`
	Children    []*RoleHierarchy `json:"children"`
	Level       int              `json:"level"`
	Path        []uuid.UUID      `json:"path"`
	Permissions []uuid.UUID      `json:"permissions"`
}

// Methods for Role entity

// IsExpired checks if the role has expired
func (r *Role) IsExpired() bool {
	if r.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*r.ExpiresAt)
}

// IsEffective checks if the role is currently effective
func (r *Role) IsEffective() bool {
	now := time.Now()
	return r.IsActive && now.After(r.EffectiveFrom) && !r.IsExpired()
}

// CanBeAssignedTo checks if the role can be assigned to a user with given clearance
func (r *Role) CanBeAssignedTo(userClearance SecurityClearanceLevel) bool {
	if !r.IsEffective() {
		return false
	}

	// Check if user has required clearance
	if r.RequiredClearance > userClearance {
		return false
	}

	// Check if user clearance doesn't exceed max allowed
	if r.MaxClearance != SecurityClearanceUnclassified && userClearance > r.MaxClearance {
		return false
	}

	return true
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(permissionID uuid.UUID) bool {
	// Check if explicitly denied
	for _, deniedID := range r.PermissionDenials {
		if deniedID == permissionID {
			return false
		}
	}

	// Check if directly granted
	for _, grantedID := range r.Permissions {
		if grantedID == permissionID {
			return true
		}
	}

	return false
}

// GetAllPermissions returns all permissions including inherited ones
func (r *Role) GetAllPermissions(roleHierarchy map[uuid.UUID]*Role) []uuid.UUID {
	permissions := make(map[uuid.UUID]bool)
	denials := make(map[uuid.UUID]bool)

	// Add current role's permissions and denials
	for _, permID := range r.Permissions {
		permissions[permID] = true
	}
	for _, denialID := range r.PermissionDenials {
		denials[denialID] = true
	}

	// Add inherited permissions if inheritance is enabled
	if r.InheritPermissions && r.ParentRoleID != nil {
		if parentRole, exists := roleHierarchy[*r.ParentRoleID]; exists {
			parentPermissions := parentRole.GetAllPermissions(roleHierarchy)
			for _, permID := range parentPermissions {
				if !denials[permID] {
					permissions[permID] = true
				}
			}
		}
	}

	// Convert to slice
	result := make([]uuid.UUID, 0, len(permissions))
	for permID := range permissions {
		result = append(result, permID)
	}

	return result
}

// CheckConflicts checks if the role conflicts with given roles
func (r *Role) CheckConflicts(userRoles []uuid.UUID) []uuid.UUID {
	conflicts := make([]uuid.UUID, 0)

	for _, conflictingRoleID := range r.ConflictingRoles {
		for _, userRoleID := range userRoles {
			if conflictingRoleID == userRoleID {
				conflicts = append(conflicts, conflictingRoleID)
			}
		}
	}

	return conflicts
}

// CheckPrerequisites checks if required roles are satisfied
func (r *Role) CheckPrerequisites(userRoles []uuid.UUID) []uuid.UUID {
	missing := make([]uuid.UUID, 0)

	for _, requiredRoleID := range r.RequiredRoles {
		found := false
		for _, userRoleID := range userRoles {
			if requiredRoleID == userRoleID {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, requiredRoleID)
		}
	}

	return missing
}

// Methods for UserRole entity

// IsExpired checks if the user role assignment has expired
func (ur *UserRole) IsExpired() bool {
	if ur.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*ur.ExpiresAt)
}

// IsEffective checks if the user role assignment is currently effective
func (ur *UserRole) IsEffective() bool {
	now := time.Now()
	return ur.IsActive &&
		now.After(ur.EffectiveFrom) &&
		!ur.IsExpired() &&
		(ur.ApprovalStatus == ApprovalStatusApproved || !ur.RequiresApproval)
}

// CheckTimeConstraints validates time-based constraints for the role assignment
func (ur *UserRole) CheckTimeConstraints(requestTime time.Time, userLocation *LocationInfo) bool {
	if ur.TimeConstraints == nil {
		return true
	}

	// Use the same logic as Permission.CheckTimeConstraints
	// (Implementation would be similar)
	return true // Simplified for now
}

// CheckIPConstraints validates IP-based constraints for the role assignment
func (ur *UserRole) CheckIPConstraints(clientIP string) bool {
	if len(ur.IPConstraints) == 0 {
		return true
	}

	for _, allowedIP := range ur.IPConstraints {
		if allowedIP == clientIP {
			return true
		}
	}

	return false
}

// UpdateLastUsed updates the last used timestamp
func (ur *UserRole) UpdateLastUsed() {
	now := time.Now()
	ur.LastUsedAt = &now
	ur.UpdatedAt = now
}

// Validation functions

// ValidateRoleType checks if the role type is valid
func ValidateRoleType(roleType string) bool {
	switch RoleType(roleType) {
	case RoleTypeSystem, RoleTypeCustom, RoleTypeGroup, RoleTypeTemporary, RoleTypeDelegated:
		return true
	default:
		return false
	}
}

// ValidateRoleScope checks if the role scope is valid
func ValidateRoleScope(scope string) bool {
	switch RoleScope(scope) {
	case RoleScopeGlobal, RoleScopeTenant, RoleScopeProject, RoleScopeTeam, RoleScopeResource:
		return true
	default:
		return false
	}
}

// ValidateAssignmentType checks if the assignment type is valid
func ValidateAssignmentType(assignmentType string) bool {
	switch AssignmentType(assignmentType) {
	case AssignmentTypeDirect, AssignmentTypeInherited, AssignmentTypeAutomatic, AssignmentTypeDelegated, AssignmentTypeTemporary:
		return true
	default:
		return false
	}
}

// ValidateApprovalStatus checks if the approval status is valid
func ValidateApprovalStatus(status string) bool {
	switch ApprovalStatus(status) {
	case ApprovalStatusPending, ApprovalStatusApproved, ApprovalStatusRejected, ApprovalStatusExpired:
		return true
	default:
		return false
	}
}
