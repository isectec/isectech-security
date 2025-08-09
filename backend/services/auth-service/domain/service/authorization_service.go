package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
)

// AuthorizationService defines the interface for authorization operations
type AuthorizationService interface {
	// Permission evaluation
	CheckPermission(ctx context.Context, req *PermissionCheckRequest) (*PermissionCheckResponse, error)
	CheckMultiplePermissions(ctx context.Context, req *MultiplePermissionCheckRequest) (*MultiplePermissionCheckResponse, error)
	GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.Permission, error)
	GetEffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID, context *entity.PermissionContext) ([]*entity.Permission, error)

	// Role management
	CreateRole(ctx context.Context, req *CreateRoleRequest) (*CreateRoleResponse, error)
	UpdateRole(ctx context.Context, req *UpdateRoleRequest) error
	DeleteRole(ctx context.Context, roleID, tenantID uuid.UUID) error
	GetRole(ctx context.Context, roleID, tenantID uuid.UUID) (*entity.Role, error)
	ListRoles(ctx context.Context, tenantID uuid.UUID, filters *RoleFilters) ([]*entity.Role, error)
	GetRoleHierarchy(ctx context.Context, tenantID uuid.UUID) (*entity.RoleHierarchy, error)

	// Role assignment
	AssignRole(ctx context.Context, req *RoleAssignmentRequest) (*RoleAssignmentResponse, error)
	RevokeRole(ctx context.Context, req *RoleRevocationRequest) error
	GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.UserRole, error)
	GetRoleUsers(ctx context.Context, roleID, tenantID uuid.UUID) ([]*entity.UserRole, error)

	// Permission management
	CreatePermission(ctx context.Context, req *CreatePermissionRequest) (*CreatePermissionResponse, error)
	UpdatePermission(ctx context.Context, req *UpdatePermissionRequest) error
	DeletePermission(ctx context.Context, permissionID, tenantID uuid.UUID) error
	GetPermission(ctx context.Context, permissionID, tenantID uuid.UUID) (*entity.Permission, error)
	ListPermissions(ctx context.Context, tenantID uuid.UUID, filters *PermissionFilters) ([]*entity.Permission, error)

	// Role-Permission association
	GrantPermissionToRole(ctx context.Context, req *GrantPermissionRequest) error
	RevokePermissionFromRole(ctx context.Context, req *RevokePermissionRequest) error
	GetRolePermissions(ctx context.Context, roleID, tenantID uuid.UUID) ([]*entity.Permission, error)

	// Policy evaluation (ABAC)
	EvaluatePolicy(ctx context.Context, req *PolicyEvaluationRequest) (*PolicyEvaluationResponse, error)
	CreatePolicy(ctx context.Context, req *CreatePolicyRequest) (*CreatePolicyResponse, error)
	UpdatePolicy(ctx context.Context, req *UpdatePolicyRequest) error
	DeletePolicy(ctx context.Context, policyID, tenantID uuid.UUID) error

	// Delegation
	DelegateRole(ctx context.Context, req *DelegationRequest) (*DelegationResponse, error)
	RevokeDelegation(ctx context.Context, req *RevokeDelegationRequest) error
	GetDelegations(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.UserRole, error)

	// Security clearance integration
	CheckClearanceRequirement(ctx context.Context, req *ClearanceCheckRequest) (*ClearanceCheckResponse, error)
	UpdateUserClearance(ctx context.Context, req *UpdateClearanceRequest) error

	// Audit and monitoring
	GetAuthorizationAuditLog(ctx context.Context, filters *AuditLogFilters) ([]*AuthorizationAuditEvent, error)
	GetAccessStatistics(ctx context.Context, req *AccessStatisticsRequest) (*AccessStatisticsResponse, error)
}

// ABACService defines the interface for Attribute-Based Access Control
type ABACService interface {
	// Policy management
	CreatePolicy(ctx context.Context, req *CreatePolicyRequest) (*CreatePolicyResponse, error)
	UpdatePolicy(ctx context.Context, req *UpdatePolicyRequest) error
	DeletePolicy(ctx context.Context, policyID string) error
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)
	ListPolicies(ctx context.Context, filters *PolicyFilters) ([]*Policy, error)

	// Policy evaluation
	EvaluatePolicy(ctx context.Context, req *PolicyEvaluationRequest) (*PolicyEvaluationResponse, error)
	EvaluateMultiplePolicies(ctx context.Context, req *MultipleEvaluationRequest) (*MultipleEvaluationResponse, error)

	// Attribute management
	SetUserAttributes(ctx context.Context, userID uuid.UUID, attributes map[string]interface{}) error
	GetUserAttributes(ctx context.Context, userID uuid.UUID) (map[string]interface{}, error)
	SetResourceAttributes(ctx context.Context, resourceID string, attributes map[string]interface{}) error
	GetResourceAttributes(ctx context.Context, resourceID string) (map[string]interface{}, error)

	// Policy compilation and validation
	ValidatePolicy(ctx context.Context, policyContent string) (*PolicyValidationResult, error)
	CompilePolicy(ctx context.Context, policyContent string) (*CompiledPolicy, error)
}

// OPAService defines the interface for Open Policy Agent integration
type OPAService interface {
	// Policy management
	DeployPolicy(ctx context.Context, policyID string, policyContent string) error
	RemovePolicy(ctx context.Context, policyID string) error

	// Data management
	SetData(ctx context.Context, path string, data interface{}) error
	GetData(ctx context.Context, path string) (interface{}, error)
	DeleteData(ctx context.Context, path string) error

	// Query evaluation
	Query(ctx context.Context, query string, input interface{}) (*OPAQueryResult, error)
	QueryWithDecision(ctx context.Context, path string, input interface{}) (*OPADecisionResult, error)

	// Health and status
	HealthCheck(ctx context.Context) (*OPAHealthStatus, error)
	GetPolicyStatus(ctx context.Context) (*OPAPolicyStatus, error)
}

// Request/Response types

// PermissionCheckRequest represents a permission check request
type PermissionCheckRequest struct {
	UserID       uuid.UUID                 `json:"user_id"`
	TenantID     uuid.UUID                 `json:"tenant_id"`
	Resource     string                    `json:"resource"`
	Action       entity.Action             `json:"action"`
	ResourcePath string                    `json:"resource_path,omitempty"`
	Context      *entity.PermissionContext `json:"context,omitempty"`
	Attributes   map[string]interface{}    `json:"attributes,omitempty"`
}

// PermissionCheckResponse represents a permission check response
type PermissionCheckResponse struct {
	Allowed               bool                          `json:"allowed"`
	Reason                string                        `json:"reason,omitempty"`
	RequiredClearance     entity.SecurityClearanceLevel `json:"required_clearance,omitempty"`
	RequiresMFA           bool                          `json:"requires_mfa"`
	RequiresApproval      bool                          `json:"requires_approval"`
	ApplicableRoles       []uuid.UUID                   `json:"applicable_roles,omitempty"`
	ApplicablePermissions []uuid.UUID                   `json:"applicable_permissions,omitempty"`
	EvaluationContext     map[string]interface{}        `json:"evaluation_context,omitempty"`
	PolicyDecisions       []*PolicyDecision             `json:"policy_decisions,omitempty"`
	EvaluatedAt           time.Time                     `json:"evaluated_at"`
}

// MultiplePermissionCheckRequest represents a request to check multiple permissions
type MultiplePermissionCheckRequest struct {
	UserID      uuid.UUID                   `json:"user_id"`
	TenantID    uuid.UUID                   `json:"tenant_id"`
	Permissions []*entity.PermissionRequest `json:"permissions"`
	Context     *entity.PermissionContext   `json:"context,omitempty"`
}

// MultiplePermissionCheckResponse represents a response for multiple permission checks
type MultiplePermissionCheckResponse struct {
	Results        []*PermissionCheckResponse `json:"results"`
	OverallAllowed bool                       `json:"overall_allowed"`
	EvaluatedAt    time.Time                  `json:"evaluated_at"`
}

// CreateRoleRequest represents a request to create a new role
type CreateRoleRequest struct {
	TenantID           uuid.UUID                     `json:"tenant_id"`
	Name               string                        `json:"name"`
	DisplayName        string                        `json:"display_name"`
	Description        string                        `json:"description"`
	Type               entity.RoleType               `json:"type"`
	Scope              entity.RoleScope              `json:"scope"`
	ParentRoleID       *uuid.UUID                    `json:"parent_role_id,omitempty"`
	RequiredClearance  entity.SecurityClearanceLevel `json:"required_clearance"`
	MaxClearance       entity.SecurityClearanceLevel `json:"max_clearance"`
	Permissions        []uuid.UUID                   `json:"permissions,omitempty"`
	PermissionDenials  []uuid.UUID                   `json:"permission_denials,omitempty"`
	InheritPermissions bool                          `json:"inherit_permissions"`
	MaxUsers           int                           `json:"max_users"`
	RequiresMFA        bool                          `json:"requires_mfa"`
	RequiresApproval   bool                          `json:"requires_approval"`
	CanDelegate        bool                          `json:"can_delegate"`
	CanAssign          bool                          `json:"can_assign"`
	AutoAssignable     bool                          `json:"auto_assignable"`
	TimeConstraints    *entity.TimeConstraints       `json:"time_constraints,omitempty"`
	MaxSessionDuration time.Duration                 `json:"max_session_duration"`
	AssignmentRules    map[string]interface{}        `json:"assignment_rules,omitempty"`
	ConflictingRoles   []uuid.UUID                   `json:"conflicting_roles,omitempty"`
	RequiredRoles      []uuid.UUID                   `json:"required_roles,omitempty"`
	IsDefault          bool                          `json:"is_default"`
	ExpiresAt          *time.Time                    `json:"expires_at,omitempty"`
	EffectiveFrom      time.Time                     `json:"effective_from"`
	CreatedBy          uuid.UUID                     `json:"created_by"`
}

// CreateRoleResponse represents a response to role creation
type CreateRoleResponse struct {
	RoleID    uuid.UUID `json:"role_id"`
	CreatedAt time.Time `json:"created_at"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	RoleID             uuid.UUID                      `json:"role_id"`
	TenantID           uuid.UUID                      `json:"tenant_id"`
	Name               string                         `json:"name,omitempty"`
	DisplayName        string                         `json:"display_name,omitempty"`
	Description        string                         `json:"description,omitempty"`
	RequiredClearance  *entity.SecurityClearanceLevel `json:"required_clearance,omitempty"`
	MaxClearance       *entity.SecurityClearanceLevel `json:"max_clearance,omitempty"`
	MaxUsers           *int                           `json:"max_users,omitempty"`
	RequiresMFA        *bool                          `json:"requires_mfa,omitempty"`
	RequiresApproval   *bool                          `json:"requires_approval,omitempty"`
	CanDelegate        *bool                          `json:"can_delegate,omitempty"`
	CanAssign          *bool                          `json:"can_assign,omitempty"`
	AutoAssignable     *bool                          `json:"auto_assignable,omitempty"`
	TimeConstraints    *entity.TimeConstraints        `json:"time_constraints,omitempty"`
	MaxSessionDuration *time.Duration                 `json:"max_session_duration,omitempty"`
	AssignmentRules    map[string]interface{}         `json:"assignment_rules,omitempty"`
	ConflictingRoles   []uuid.UUID                    `json:"conflicting_roles,omitempty"`
	RequiredRoles      []uuid.UUID                    `json:"required_roles,omitempty"`
	IsActive           *bool                          `json:"is_active,omitempty"`
	IsDefault          *bool                          `json:"is_default,omitempty"`
	ExpiresAt          *time.Time                     `json:"expires_at,omitempty"`
	UpdatedBy          uuid.UUID                      `json:"updated_by"`
}

// RoleAssignmentRequest represents a request to assign a role to a user
type RoleAssignmentRequest struct {
	UserID           uuid.UUID               `json:"user_id"`
	RoleID           uuid.UUID               `json:"role_id"`
	TenantID         uuid.UUID               `json:"tenant_id"`
	AssignmentType   entity.AssignmentType   `json:"assignment_type"`
	AssignedBy       uuid.UUID               `json:"assigned_by"`
	AssignmentReason string                  `json:"assignment_reason"`
	Scope            entity.RoleScope        `json:"scope"`
	ResourceID       *uuid.UUID              `json:"resource_id,omitempty"`
	ProjectID        *uuid.UUID              `json:"project_id,omitempty"`
	TeamID           *uuid.UUID              `json:"team_id,omitempty"`
	Conditions       map[string]interface{}  `json:"conditions,omitempty"`
	IPConstraints    []string                `json:"ip_constraints,omitempty"`
	TimeConstraints  *entity.TimeConstraints `json:"time_constraints,omitempty"`
	IsTemporary      bool                    `json:"is_temporary"`
	ExpiresAt        *time.Time              `json:"expires_at,omitempty"`
	EffectiveFrom    time.Time               `json:"effective_from"`
}

// RoleAssignmentResponse represents a response to role assignment
type RoleAssignmentResponse struct {
	UserRoleID       uuid.UUID  `json:"user_role_id"`
	RequiresApproval bool       `json:"requires_approval"`
	ApprovalID       *uuid.UUID `json:"approval_id,omitempty"`
	AssignedAt       time.Time  `json:"assigned_at"`
}

// RoleRevocationRequest represents a request to revoke a role from a user
type RoleRevocationRequest struct {
	UserRoleID       uuid.UUID `json:"user_role_id"`
	UserID           uuid.UUID `json:"user_id"`
	RoleID           uuid.UUID `json:"role_id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	RevokedBy        uuid.UUID `json:"revoked_by"`
	RevocationReason string    `json:"revocation_reason"`
}

// CreatePermissionRequest represents a request to create a new permission
type CreatePermissionRequest struct {
	TenantID            uuid.UUID                     `json:"tenant_id"`
	Name                string                        `json:"name"`
	DisplayName         string                        `json:"display_name"`
	Description         string                        `json:"description"`
	Type                entity.PermissionType         `json:"type"`
	Scope               entity.PermissionScope        `json:"scope"`
	Resource            string                        `json:"resource"`
	Action              entity.Action                 `json:"action"`
	ResourcePath        string                        `json:"resource_path,omitempty"`
	RequiredClearance   entity.SecurityClearanceLevel `json:"required_clearance"`
	RequiresMFA         bool                          `json:"requires_mfa"`
	RequiresApproval    bool                          `json:"requires_approval"`
	Constraints         map[string]interface{}        `json:"constraints,omitempty"`
	TimeConstraints     *entity.TimeConstraints       `json:"time_constraints,omitempty"`
	IPConstraints       []string                      `json:"ip_constraints,omitempty"`
	LocationConstraints []string                      `json:"location_constraints,omitempty"`
	Inheritable         bool                          `json:"inheritable"`
	Delegatable         bool                          `json:"delegatable"`
	MaxDelegationDepth  int                           `json:"max_delegation_depth"`
	ExpiresAt           *time.Time                    `json:"expires_at,omitempty"`
	EffectiveFrom       time.Time                     `json:"effective_from"`
	CreatedBy           uuid.UUID                     `json:"created_by"`
}

// CreatePermissionResponse represents a response to permission creation
type CreatePermissionResponse struct {
	PermissionID uuid.UUID `json:"permission_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// UpdatePermissionRequest represents a request to update a permission
type UpdatePermissionRequest struct {
	PermissionID        uuid.UUID                      `json:"permission_id"`
	TenantID            uuid.UUID                      `json:"tenant_id"`
	Name                string                         `json:"name,omitempty"`
	DisplayName         string                         `json:"display_name,omitempty"`
	Description         string                         `json:"description,omitempty"`
	RequiredClearance   *entity.SecurityClearanceLevel `json:"required_clearance,omitempty"`
	RequiresMFA         *bool                          `json:"requires_mfa,omitempty"`
	RequiresApproval    *bool                          `json:"requires_approval,omitempty"`
	Constraints         map[string]interface{}         `json:"constraints,omitempty"`
	TimeConstraints     *entity.TimeConstraints        `json:"time_constraints,omitempty"`
	IPConstraints       []string                       `json:"ip_constraints,omitempty"`
	LocationConstraints []string                       `json:"location_constraints,omitempty"`
	Inheritable         *bool                          `json:"inheritable,omitempty"`
	Delegatable         *bool                          `json:"delegatable,omitempty"`
	MaxDelegationDepth  *int                           `json:"max_delegation_depth,omitempty"`
	IsActive            *bool                          `json:"is_active,omitempty"`
	ExpiresAt           *time.Time                     `json:"expires_at,omitempty"`
	UpdatedBy           uuid.UUID                      `json:"updated_by"`
}

// Policy types

// Policy represents an ABAC policy
type Policy struct {
	ID          string                 `json:"id"`
	TenantID    uuid.UUID              `json:"tenant_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Content     string                 `json:"content"`  // Rego policy content
	Compiled    *CompiledPolicy        `json:"compiled"` // Compiled policy
	Metadata    map[string]interface{} `json:"metadata"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   uuid.UUID              `json:"created_by"`
	UpdatedBy   uuid.UUID              `json:"updated_by"`
}

// CompiledPolicy represents a compiled OPA policy
type CompiledPolicy struct {
	PolicyID     string                 `json:"policy_id"`
	Content      string                 `json:"content"`
	Modules      []string               `json:"modules"`
	Functions    []string               `json:"functions"`
	Rules        []string               `json:"rules"`
	Dependencies []string               `json:"dependencies"`
	Metadata     map[string]interface{} `json:"metadata"`
	CompiledAt   time.Time              `json:"compiled_at"`
}

// PolicyEvaluationRequest represents a policy evaluation request
type PolicyEvaluationRequest struct {
	PolicyID string                    `json:"policy_id"`
	Input    map[string]interface{}    `json:"input"`
	Query    string                    `json:"query,omitempty"`
	Context  *entity.PermissionContext `json:"context,omitempty"`
}

// PolicyEvaluationResponse represents a policy evaluation response
type PolicyEvaluationResponse struct {
	PolicyID    string              `json:"policy_id"`
	Decision    bool                `json:"decision"`
	Result      interface{}         `json:"result"`
	Explanation string              `json:"explanation,omitempty"`
	Trace       []*PolicyTraceEvent `json:"trace,omitempty"`
	EvaluatedAt time.Time           `json:"evaluated_at"`
	Duration    time.Duration       `json:"duration"`
}

// PolicyDecision represents a policy decision
type PolicyDecision struct {
	PolicyID   string                 `json:"policy_id"`
	Decision   bool                   `json:"decision"`
	Reason     string                 `json:"reason"`
	Rule       string                 `json:"rule,omitempty"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
}

// PolicyTraceEvent represents a trace event from policy evaluation
type PolicyTraceEvent struct {
	Type      string                 `json:"type"`
	Location  string                 `json:"location"`
	Message   string                 `json:"message"`
	Binding   map[string]interface{} `json:"binding,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// Other types

// RoleFilters represents filters for role queries
type RoleFilters struct {
	Type              entity.RoleType               `json:"type,omitempty"`
	Scope             entity.RoleScope              `json:"scope,omitempty"`
	RequiredClearance entity.SecurityClearanceLevel `json:"required_clearance,omitempty"`
	IsActive          *bool                         `json:"is_active,omitempty"`
	IsDefault         *bool                         `json:"is_default,omitempty"`
	CanDelegate       *bool                         `json:"can_delegate,omitempty"`
	ParentRoleID      *uuid.UUID                    `json:"parent_role_id,omitempty"`
	IncludeExpired    bool                          `json:"include_expired"`
	Limit             int                           `json:"limit"`
	Offset            int                           `json:"offset"`
}

// PermissionFilters represents filters for permission queries
type PermissionFilters struct {
	Type              entity.PermissionType         `json:"type,omitempty"`
	Scope             entity.PermissionScope        `json:"scope,omitempty"`
	Resource          string                        `json:"resource,omitempty"`
	Action            entity.Action                 `json:"action,omitempty"`
	RequiredClearance entity.SecurityClearanceLevel `json:"required_clearance,omitempty"`
	IsActive          *bool                         `json:"is_active,omitempty"`
	Inheritable       *bool                         `json:"inheritable,omitempty"`
	Delegatable       *bool                         `json:"delegatable,omitempty"`
	IncludeExpired    bool                          `json:"include_expired"`
	Limit             int                           `json:"limit"`
	Offset            int                           `json:"offset"`
}

// Additional types for various operations...

// GrantPermissionRequest represents a request to grant permission to a role
type GrantPermissionRequest struct {
	RoleID       uuid.UUID `json:"role_id"`
	PermissionID uuid.UUID `json:"permission_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	GrantedBy    uuid.UUID `json:"granted_by"`
}

// RevokePermissionRequest represents a request to revoke permission from a role
type RevokePermissionRequest struct {
	RoleID       uuid.UUID `json:"role_id"`
	PermissionID uuid.UUID `json:"permission_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	RevokedBy    uuid.UUID `json:"revoked_by"`
}

// Delegation types

// DelegationRequest represents a request to delegate a role
type DelegationRequest struct {
	DelegatorID      uuid.UUID               `json:"delegator_id"`
	DelegateID       uuid.UUID               `json:"delegate_id"`
	RoleID           uuid.UUID               `json:"role_id"`
	TenantID         uuid.UUID               `json:"tenant_id"`
	DelegationReason string                  `json:"delegation_reason"`
	Scope            entity.RoleScope        `json:"scope"`
	ResourceID       *uuid.UUID              `json:"resource_id,omitempty"`
	ProjectID        *uuid.UUID              `json:"project_id,omitempty"`
	TeamID           *uuid.UUID              `json:"team_id,omitempty"`
	Conditions       map[string]interface{}  `json:"conditions,omitempty"`
	TimeConstraints  *entity.TimeConstraints `json:"time_constraints,omitempty"`
	ExpiresAt        *time.Time              `json:"expires_at,omitempty"`
	MaxDepth         int                     `json:"max_depth"`
}

// DelegationResponse represents a response to delegation request
type DelegationResponse struct {
	DelegationID     uuid.UUID  `json:"delegation_id"`
	RequiresApproval bool       `json:"requires_approval"`
	ApprovalID       *uuid.UUID `json:"approval_id,omitempty"`
	DelegatedAt      time.Time  `json:"delegated_at"`
}

// RevokeDelegationRequest represents a request to revoke delegation
type RevokeDelegationRequest struct {
	DelegationID     uuid.UUID `json:"delegation_id"`
	DelegatorID      uuid.UUID `json:"delegator_id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	RevokedBy        uuid.UUID `json:"revoked_by"`
	RevocationReason string    `json:"revocation_reason"`
}

// Security clearance types

// ClearanceCheckRequest represents a security clearance check request
type ClearanceCheckRequest struct {
	UserID            uuid.UUID                     `json:"user_id"`
	TenantID          uuid.UUID                     `json:"tenant_id"`
	RequiredClearance entity.SecurityClearanceLevel `json:"required_clearance"`
	Resource          string                        `json:"resource,omitempty"`
	Context           *entity.PermissionContext     `json:"context,omitempty"`
}

// ClearanceCheckResponse represents a security clearance check response
type ClearanceCheckResponse struct {
	Allowed           bool                          `json:"allowed"`
	UserClearance     entity.SecurityClearanceLevel `json:"user_clearance"`
	RequiredClearance entity.SecurityClearanceLevel `json:"required_clearance"`
	ClearanceGap      int                           `json:"clearance_gap"`
	Reason            string                        `json:"reason,omitempty"`
	EvaluatedAt       time.Time                     `json:"evaluated_at"`
}

// UpdateClearanceRequest represents a request to update user security clearance
type UpdateClearanceRequest struct {
	UserID        uuid.UUID                     `json:"user_id"`
	TenantID      uuid.UUID                     `json:"tenant_id"`
	NewClearance  entity.SecurityClearanceLevel `json:"new_clearance"`
	UpdatedBy     uuid.UUID                     `json:"updated_by"`
	UpdateReason  string                        `json:"update_reason"`
	EffectiveFrom time.Time                     `json:"effective_from"`
	ExpiresAt     *time.Time                    `json:"expires_at,omitempty"`
}

// Audit and monitoring types

// AuthorizationAuditEvent represents an authorization audit event
type AuthorizationAuditEvent struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	EventType    string                 `json:"event_type"`
	UserID       *uuid.UUID             `json:"user_id,omitempty"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty"`
	RoleID       *uuid.UUID             `json:"role_id,omitempty"`
	PermissionID *uuid.UUID             `json:"permission_id,omitempty"`
	PolicyID     *string                `json:"policy_id,omitempty"`
	Success      bool                   `json:"success"`
	Reason       string                 `json:"reason,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// AuditLogFilters represents filters for audit log queries
type AuditLogFilters struct {
	EventType string     `json:"event_type,omitempty"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	Success   *bool      `json:"success,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	IPAddress string     `json:"ip_address,omitempty"`
	Limit     int        `json:"limit"`
	Offset    int        `json:"offset"`
}

// AccessStatisticsRequest represents a request for access statistics
type AccessStatisticsRequest struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	UserID      *uuid.UUID `json:"user_id,omitempty"`
	ResourceID  *uuid.UUID `json:"resource_id,omitempty"`
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	Granularity string     `json:"granularity"` // hour, day, week, month
}

// AccessStatisticsResponse represents access statistics
type AccessStatisticsResponse struct {
	TotalRequests   int64                  `json:"total_requests"`
	AllowedRequests int64                  `json:"allowed_requests"`
	DeniedRequests  int64                  `json:"denied_requests"`
	TopUsers        []*UserAccessStats     `json:"top_users"`
	TopResources    []*ResourceAccessStats `json:"top_resources"`
	TopRoles        []*RoleAccessStats     `json:"top_roles"`
	TimeSeriesData  []*TimeSeriesDataPoint `json:"time_series_data"`
	SecurityMetrics *SecurityMetrics       `json:"security_metrics"`
	GeneratedAt     time.Time              `json:"generated_at"`
}

// UserAccessStats represents user access statistics
type UserAccessStats struct {
	UserID          uuid.UUID `json:"user_id"`
	TotalRequests   int64     `json:"total_requests"`
	AllowedRequests int64     `json:"allowed_requests"`
	DeniedRequests  int64     `json:"denied_requests"`
}

// ResourceAccessStats represents resource access statistics
type ResourceAccessStats struct {
	Resource        string `json:"resource"`
	TotalRequests   int64  `json:"total_requests"`
	AllowedRequests int64  `json:"allowed_requests"`
	DeniedRequests  int64  `json:"denied_requests"`
}

// RoleAccessStats represents role access statistics
type RoleAccessStats struct {
	RoleID          uuid.UUID `json:"role_id"`
	TotalRequests   int64     `json:"total_requests"`
	AllowedRequests int64     `json:"allowed_requests"`
	DeniedRequests  int64     `json:"denied_requests"`
}

// TimeSeriesDataPoint represents a time series data point
type TimeSeriesDataPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	TotalRequests   int64     `json:"total_requests"`
	AllowedRequests int64     `json:"allowed_requests"`
	DeniedRequests  int64     `json:"denied_requests"`
}

// SecurityMetrics represents security-related metrics
type SecurityMetrics struct {
	HighPrivilegeAccess int64   `json:"high_privilege_access"`
	ClearanceViolations int64   `json:"clearance_violations"`
	PolicyViolations    int64   `json:"policy_violations"`
	SuspiciousActivity  int64   `json:"suspicious_activity"`
	AverageRiskScore    float64 `json:"average_risk_score"`
}

// OPA-specific types

// OPAQueryResult represents the result of an OPA query
type OPAQueryResult struct {
	Result   interface{}            `json:"result"`
	Bindings map[string]interface{} `json:"bindings,omitempty"`
	Metrics  *OPAMetrics            `json:"metrics,omitempty"`
	Trace    []*OPATraceEvent       `json:"trace,omitempty"`
}

// OPADecisionResult represents the result of an OPA decision query
type OPADecisionResult struct {
	DecisionID string                 `json:"decision_id"`
	Result     bool                   `json:"result"`
	Reason     string                 `json:"reason,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Metrics    *OPAMetrics            `json:"metrics,omitempty"`
}

// OPAMetrics represents OPA evaluation metrics
type OPAMetrics struct {
	TimerRegoQueryEvalNs  int64 `json:"timer_rego_query_eval_ns"`
	TimerRegoLoadBundleNs int64 `json:"timer_rego_load_bundle_ns"`
	CounterRegoQueryEval  int   `json:"counter_rego_query_eval"`
}

// OPATraceEvent represents an OPA trace event
type OPATraceEvent struct {
	Op       string                 `json:"op"`
	Query    string                 `json:"query"`
	Locals   map[string]interface{} `json:"locals,omitempty"`
	Location string                 `json:"location"`
}

// OPAHealthStatus represents OPA health status
type OPAHealthStatus struct {
	Healthy   bool      `json:"healthy"`
	Version   string    `json:"version"`
	Uptime    string    `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
}

// OPAPolicyStatus represents OPA policy status
type OPAPolicyStatus struct {
	Policies    []string          `json:"policies"`
	Data        map[string]string `json:"data"`
	Bundles     []string          `json:"bundles"`
	Health      bool              `json:"health"`
	LastUpdated time.Time         `json:"last_updated"`
}

// Additional request/response types...

// CreatePolicyRequest represents a request to create a policy
type CreatePolicyRequest struct {
	TenantID    uuid.UUID              `json:"tenant_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Content     string                 `json:"content"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedBy   uuid.UUID              `json:"created_by"`
}

// CreatePolicyResponse represents a response to policy creation
type CreatePolicyResponse struct {
	PolicyID  string    `json:"policy_id"`
	CreatedAt time.Time `json:"created_at"`
}

// UpdatePolicyRequest represents a request to update a policy
type UpdatePolicyRequest struct {
	PolicyID    string                 `json:"policy_id"`
	TenantID    uuid.UUID              `json:"tenant_id"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Content     string                 `json:"content,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IsActive    *bool                  `json:"is_active,omitempty"`
	UpdatedBy   uuid.UUID              `json:"updated_by"`
}

// PolicyFilters represents filters for policy queries
type PolicyFilters struct {
	TenantID uuid.UUID `json:"tenant_id"`
	IsActive *bool     `json:"is_active,omitempty"`
	Version  string    `json:"version,omitempty"`
	Limit    int       `json:"limit"`
	Offset   int       `json:"offset"`
}

// PolicyValidationResult represents the result of policy validation
type PolicyValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// MultipleEvaluationRequest represents a request to evaluate multiple policies
type MultipleEvaluationRequest struct {
	PolicyIDs []string                  `json:"policy_ids"`
	Input     map[string]interface{}    `json:"input"`
	Context   *entity.PermissionContext `json:"context,omitempty"`
}

// MultipleEvaluationResponse represents a response to multiple policy evaluation
type MultipleEvaluationResponse struct {
	Results       []*PolicyEvaluationResponse `json:"results"`
	OverallResult bool                        `json:"overall_result"`
	EvaluatedAt   time.Time                   `json:"evaluated_at"`
}
