package entity

import (
	"time"

	"github.com/google/uuid"
)

// SecurityClearanceLevel represents the security clearance level for iSECTECH
type SecurityClearanceLevel string

const (
	ClearanceUnclassified SecurityClearanceLevel = "UNCLASSIFIED"
	ClearanceConfidential SecurityClearanceLevel = "CONFIDENTIAL"
	ClearanceSecret       SecurityClearanceLevel = "SECRET"
	ClearanceTopSecret    SecurityClearanceLevel = "TOP_SECRET"
)

// UserStatus represents the current status of a user account
type UserStatus string

const (
	UserStatusActive    UserStatus = "ACTIVE"
	UserStatusInactive  UserStatus = "INACTIVE"
	UserStatusSuspended UserStatus = "SUSPENDED"
	UserStatusLocked    UserStatus = "LOCKED"
	UserStatusPending   UserStatus = "PENDING"
)

// User represents a user entity in the iSECTECH system
type User struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	TenantID          uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Username          string                 `json:"username" db:"username"`
	Email             string                 `json:"email" db:"email"`
	PasswordHash      string                 `json:"-" db:"password_hash"` // Never expose in JSON
	FirstName         string                 `json:"first_name" db:"first_name"`
	LastName          string                 `json:"last_name" db:"last_name"`
	Status            UserStatus             `json:"status" db:"status"`
	SecurityClearance SecurityClearanceLevel `json:"security_clearance" db:"security_clearance"`
	MFAEnabled        bool                   `json:"mfa_enabled" db:"mfa_enabled"`
	MFAEnforced       bool                   `json:"mfa_enforced" db:"mfa_enforced"`
	FailedAttempts    int                    `json:"failed_attempts" db:"failed_attempts"`
	LastFailedAttempt *time.Time             `json:"last_failed_attempt" db:"last_failed_attempt"`
	LockedUntil       *time.Time             `json:"locked_until" db:"locked_until"`
	PasswordChangedAt time.Time              `json:"password_changed_at" db:"password_changed_at"`
	LastLoginAt       *time.Time             `json:"last_login_at" db:"last_login_at"`
	LastLoginIP       string                 `json:"last_login_ip" db:"last_login_ip"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy         uuid.UUID              `json:"created_by" db:"created_by"`
	UpdatedBy         uuid.UUID              `json:"updated_by" db:"updated_by"`

	// Relationships
	MFADevices []MFADevice `json:"mfa_devices,omitempty"`
	Roles      []Role      `json:"roles,omitempty"`
}

// IsLocked checks if the user account is currently locked
func (u *User) IsLocked() bool {
	if u.Status == UserStatusLocked {
		return true
	}
	if u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
		return true
	}
	return false
}

// CanAuthenticate checks if the user can perform authentication
func (u *User) CanAuthenticate() bool {
	return u.Status == UserStatusActive && !u.IsLocked()
}

// RequiresMFA checks if MFA is required for this user
func (u *User) RequiresMFA() bool {
	return u.MFAEnabled || u.MFAEnforced
}

// HasSecurityClearance checks if user has the required security clearance level
func (u *User) HasSecurityClearance(required SecurityClearanceLevel) bool {
	clearanceLevels := map[SecurityClearanceLevel]int{
		ClearanceUnclassified: 1,
		ClearanceConfidential: 2,
		ClearanceSecret:       3,
		ClearanceTopSecret:    4,
	}

	userLevel, userExists := clearanceLevels[u.SecurityClearance]
	requiredLevel, requiredExists := clearanceLevels[required]

	if !userExists || !requiredExists {
		return false
	}

	return userLevel >= requiredLevel
}

// IncrementFailedAttempts increments the failed login attempts counter
func (u *User) IncrementFailedAttempts() {
	u.FailedAttempts++
	now := time.Now()
	u.LastFailedAttempt = &now
	u.UpdatedAt = now

	// Lock account after 5 failed attempts for increasing duration
	if u.FailedAttempts >= 5 {
		lockDuration := time.Duration(u.FailedAttempts-4) * 15 * time.Minute
		lockUntil := now.Add(lockDuration)
		u.LockedUntil = &lockUntil

		// Set status to locked if too many attempts
		if u.FailedAttempts >= 10 {
			u.Status = UserStatusLocked
		}
	}
}

// ResetFailedAttempts resets the failed attempts counter after successful login
func (u *User) ResetFailedAttempts() {
	u.FailedAttempts = 0
	u.LastFailedAttempt = nil
	u.LockedUntil = nil
	if u.Status == UserStatusLocked && u.FailedAttempts == 0 {
		u.Status = UserStatusActive
	}
}

// UpdateLastLogin updates the last login timestamp and IP
func (u *User) UpdateLastLogin(ip string) {
	now := time.Now()
	u.LastLoginAt = &now
	u.LastLoginIP = ip
	u.UpdatedAt = now
}

// PasswordNeedsChange checks if password needs to be changed (90 days policy)
func (u *User) PasswordNeedsChange() bool {
	return time.Since(u.PasswordChangedAt) > 90*24*time.Hour
}

// GetFullName returns the user's full name
func (u *User) GetFullName() string {
	if u.FirstName == "" && u.LastName == "" {
		return u.Username
	}
	return u.FirstName + " " + u.LastName
}

// NewUser creates a new user with default values
func NewUser(tenantID uuid.UUID, username, email, firstName, lastName string, createdBy uuid.UUID) *User {
	now := time.Now()
	return &User{
		ID:                uuid.New(),
		TenantID:          tenantID,
		Username:          username,
		Email:             email,
		FirstName:         firstName,
		LastName:          lastName,
		Status:            UserStatusPending,
		SecurityClearance: ClearanceUnclassified,
		MFAEnabled:        false,
		MFAEnforced:       false,
		FailedAttempts:    0,
		PasswordChangedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
		CreatedBy:         createdBy,
		UpdatedBy:         createdBy,
	}
}
