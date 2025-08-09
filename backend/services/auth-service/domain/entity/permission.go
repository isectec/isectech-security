package entity

import (
	"time"

	"github.com/google/uuid"
)

// PermissionType represents the type of permission
type PermissionType string

const (
	PermissionTypeResource PermissionType = "resource" // Resource-specific permission
	PermissionTypeAction   PermissionType = "action"   // Action-based permission
	PermissionTypeData     PermissionType = "data"     // Data access permission
	PermissionTypeSystem   PermissionType = "system"   // System-level permission
	PermissionTypeAPI      PermissionType = "api"      // API endpoint permission
)

// PermissionScope represents the scope of a permission
type PermissionScope string

const (
	PermissionScopeGlobal   PermissionScope = "global"   // Global across all tenants
	PermissionScopeTenant   PermissionScope = "tenant"   // Tenant-specific
	PermissionScopeResource PermissionScope = "resource" // Resource-specific
	PermissionScopeOwner    PermissionScope = "owner"    // Owner-only
	PermissionScopeDelegate PermissionScope = "delegate" // Delegated access
)

// Action represents the action that can be performed
type Action string

const (
	ActionRead    Action = "read"
	ActionWrite   Action = "write"
	ActionCreate  Action = "create"
	ActionUpdate  Action = "update"
	ActionDelete  Action = "delete"
	ActionExecute Action = "execute"
	ActionApprove Action = "approve"
	ActionAudit   Action = "audit"
	ActionManage  Action = "manage"
	ActionAdmin   Action = "admin"
)

// Permission represents a specific permission in the system
type Permission struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	TenantID    uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	Name        string          `json:"name" db:"name"`
	DisplayName string          `json:"display_name" db:"display_name"`
	Description string          `json:"description" db:"description"`
	Type        PermissionType  `json:"type" db:"type"`
	Scope       PermissionScope `json:"scope" db:"scope"`

	// Resource and action specification
	Resource     string `json:"resource" db:"resource"`           // Resource identifier (e.g., "alerts", "users", "reports")
	Action       Action `json:"action" db:"action"`               // Action (read, write, delete, etc.)
	ResourcePath string `json:"resource_path" db:"resource_path"` // Specific resource path (e.g., "/api/v1/alerts/*")

	// Security context requirements
	RequiredClearance SecurityClearanceLevel `json:"required_clearance" db:"required_clearance"`
	RequiresMFA       bool                   `json:"requires_mfa" db:"requires_mfa"`
	RequiresApproval  bool                   `json:"requires_approval" db:"requires_approval"`

	// Constraints and conditions
	Constraints         map[string]interface{} `json:"constraints" db:"constraints"`                   // JSON constraints for ABAC
	TimeConstraints     *TimeConstraints       `json:"time_constraints" db:"time_constraints"`         // Time-based access constraints
	IPConstraints       []string               `json:"ip_constraints" db:"ip_constraints"`             // IP address constraints
	LocationConstraints []string               `json:"location_constraints" db:"location_constraints"` // Geographic constraints

	// Inheritance and delegation
	Inheritable        bool `json:"inheritable" db:"inheritable"`                   // Can be inherited by sub-roles
	Delegatable        bool `json:"delegatable" db:"delegatable"`                   // Can be delegated to others
	MaxDelegationDepth int  `json:"max_delegation_depth" db:"max_delegation_depth"` // Maximum delegation depth

	// Lifecycle management
	IsActive      bool       `json:"is_active" db:"is_active"`
	ExpiresAt     *time.Time `json:"expires_at" db:"expires_at"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`

	// Audit and metadata
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy uuid.UUID `json:"updated_by" db:"updated_by"`
	Version   int       `json:"version" db:"version"`
}

// TimeConstraints represents time-based access constraints
type TimeConstraints struct {
	AllowedDays        []time.Weekday `json:"allowed_days"`         // Days of week when access is allowed
	AllowedTimeStart   string         `json:"allowed_time_start"`   // Start time (HH:MM format)
	AllowedTimeEnd     string         `json:"allowed_time_end"`     // End time (HH:MM format)
	Timezone           string         `json:"timezone"`             // Timezone for time constraints
	MaxSessionDuration time.Duration  `json:"max_session_duration"` // Maximum session duration
}

// PermissionContext represents the context for permission evaluation
type PermissionContext struct {
	UserID            uuid.UUID              `json:"user_id"`
	TenantID          uuid.UUID              `json:"tenant_id"`
	SecurityClearance SecurityClearanceLevel `json:"security_clearance"`
	Roles             []string               `json:"roles"`
	Attributes        map[string]interface{} `json:"attributes"`
	IPAddress         string                 `json:"ip_address"`
	Location          *LocationInfo          `json:"location"`
	RequestTime       time.Time              `json:"request_time"`
	SessionInfo       *SessionInfo           `json:"session_info"`
	RequestContext    map[string]interface{} `json:"request_context"`
}

// LocationInfo represents geographic location information
type LocationInfo struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timezone  string  `json:"timezone"`
}

// SessionInfo represents session-related information for authorization
type SessionInfo struct {
	SessionID            string     `json:"session_id"`
	LoginTime            time.Time  `json:"login_time"`
	LastActivity         time.Time  `json:"last_activity"`
	MFAVerified          bool       `json:"mfa_verified"`
	MFATimestamp         *time.Time `json:"mfa_timestamp"`
	AuthenticationMethod string     `json:"authentication_method"`
	RiskScore            float64    `json:"risk_score"`
}

// PermissionEvaluation represents the result of permission evaluation
type PermissionEvaluation struct {
	Allowed           bool                   `json:"allowed"`
	Permission        *Permission            `json:"permission"`
	DenialReason      string                 `json:"denial_reason,omitempty"`
	RequiredClearance SecurityClearanceLevel `json:"required_clearance,omitempty"`
	RequiresMFA       bool                   `json:"requires_mfa"`
	RequiresApproval  bool                   `json:"requires_approval"`
	Constraints       []string               `json:"constraints,omitempty"`
	ExpiresAt         *time.Time             `json:"expires_at,omitempty"`
	EvaluatedAt       time.Time              `json:"evaluated_at"`
	EvaluationContext map[string]interface{} `json:"evaluation_context"`
}

// PermissionRequest represents a request for permission evaluation
type PermissionRequest struct {
	UserID       uuid.UUID              `json:"user_id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	Resource     string                 `json:"resource"`
	Action       Action                 `json:"action"`
	ResourcePath string                 `json:"resource_path,omitempty"`
	Context      *PermissionContext     `json:"context"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

// Methods for Permission entity

// IsExpired checks if the permission has expired
func (p *Permission) IsExpired() bool {
	if p.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*p.ExpiresAt)
}

// IsEffective checks if the permission is currently effective
func (p *Permission) IsEffective() bool {
	now := time.Now()
	return p.IsActive && now.After(p.EffectiveFrom) && !p.IsExpired()
}

// CanDelegate checks if the permission can be delegated
func (p *Permission) CanDelegate(currentDepth int) bool {
	return p.Delegatable && (p.MaxDelegationDepth == 0 || currentDepth < p.MaxDelegationDepth)
}

// CheckTimeConstraints validates time-based constraints
func (p *Permission) CheckTimeConstraints(requestTime time.Time, userLocation *LocationInfo) bool {
	if p.TimeConstraints == nil {
		return true
	}

	// Load timezone
	var loc *time.Location
	var err error
	if p.TimeConstraints.Timezone != "" {
		loc, err = time.LoadLocation(p.TimeConstraints.Timezone)
		if err != nil {
			// Fallback to user location timezone or UTC
			if userLocation != nil && userLocation.Timezone != "" {
				loc, _ = time.LoadLocation(userLocation.Timezone)
			}
			if loc == nil {
				loc = time.UTC
			}
		}
	} else {
		loc = time.UTC
	}

	localTime := requestTime.In(loc)

	// Check day of week
	if len(p.TimeConstraints.AllowedDays) > 0 {
		dayAllowed := false
		for _, allowedDay := range p.TimeConstraints.AllowedDays {
			if localTime.Weekday() == allowedDay {
				dayAllowed = true
				break
			}
		}
		if !dayAllowed {
			return false
		}
	}

	// Check time range
	if p.TimeConstraints.AllowedTimeStart != "" && p.TimeConstraints.AllowedTimeEnd != "" {
		currentTime := localTime.Format("15:04")
		if currentTime < p.TimeConstraints.AllowedTimeStart || currentTime > p.TimeConstraints.AllowedTimeEnd {
			return false
		}
	}

	return true
}

// CheckIPConstraints validates IP-based constraints
func (p *Permission) CheckIPConstraints(clientIP string) bool {
	if len(p.IPConstraints) == 0 {
		return true
	}

	for _, allowedIP := range p.IPConstraints {
		// Support for CIDR notation and exact IP matching
		if allowedIP == clientIP {
			return true
		}
		// TODO: Add CIDR matching logic
	}

	return false
}

// CheckLocationConstraints validates location-based constraints
func (p *Permission) CheckLocationConstraints(userLocation *LocationInfo) bool {
	if len(p.LocationConstraints) == 0 {
		return true
	}

	if userLocation == nil {
		return false
	}

	for _, allowedLocation := range p.LocationConstraints {
		// Simple country matching (can be extended for more granular matching)
		if allowedLocation == userLocation.Country {
			return true
		}
	}

	return false
}

// Matches checks if the permission matches the given resource and action
func (p *Permission) Matches(resource string, action Action, resourcePath string) bool {
	// Check resource match
	if p.Resource != "*" && p.Resource != resource {
		return false
	}

	// Check action match
	if string(p.Action) != "*" && p.Action != action {
		return false
	}

	// Check resource path match (if specified)
	if p.ResourcePath != "" && resourcePath != "" {
		// Support wildcard matching
		if p.ResourcePath == "*" {
			return true
		}
		// Exact match or prefix match for paths ending with /*
		if p.ResourcePath == resourcePath {
			return true
		}
		if len(p.ResourcePath) > 2 && p.ResourcePath[len(p.ResourcePath)-2:] == "/*" {
			prefix := p.ResourcePath[:len(p.ResourcePath)-2]
			if len(resourcePath) >= len(prefix) && resourcePath[:len(prefix)] == prefix {
				return true
			}
		}
	}

	return true
}

// ValidatePermissionType checks if the permission type is valid
func ValidatePermissionType(permType string) bool {
	switch PermissionType(permType) {
	case PermissionTypeResource, PermissionTypeAction, PermissionTypeData, PermissionTypeSystem, PermissionTypeAPI:
		return true
	default:
		return false
	}
}

// ValidatePermissionScope checks if the permission scope is valid
func ValidatePermissionScope(scope string) bool {
	switch PermissionScope(scope) {
	case PermissionScopeGlobal, PermissionScopeTenant, PermissionScopeResource, PermissionScopeOwner, PermissionScopeDelegate:
		return true
	default:
		return false
	}
}

// ValidateAction checks if the action is valid
func ValidateAction(action string) bool {
	switch Action(action) {
	case ActionRead, ActionWrite, ActionCreate, ActionUpdate, ActionDelete, ActionExecute, ActionApprove, ActionAudit, ActionManage, ActionAdmin:
		return true
	default:
		return false
	}
}
