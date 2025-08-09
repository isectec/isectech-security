package entity

import (
	"time"

	"github.com/google/uuid"
)

// SessionStatus represents the status of a user session
type SessionStatus string

const (
	SessionStatusActive    SessionStatus = "ACTIVE"
	SessionStatusExpired   SessionStatus = "EXPIRED"
	SessionStatusRevoked   SessionStatus = "REVOKED"
	SessionStatusSuspended SessionStatus = "SUSPENDED"
)

// SessionType represents the type of session
type SessionType string

const (
	SessionTypeWeb     SessionType = "WEB"
	SessionTypeMobile  SessionType = "MOBILE"
	SessionTypeAPI     SessionType = "API"
	SessionTypeDesktop SessionType = "DESKTOP"
	SessionTypeSSO     SessionType = "SSO"
)

// Session represents a user authentication session in iSECTECH
type Session struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	UserID            uuid.UUID              `json:"user_id" db:"user_id"`
	TenantID          uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	SessionToken      string                 `json:"-" db:"session_token"` // Never expose in JSON
	RefreshToken      string                 `json:"-" db:"refresh_token"` // Never expose in JSON
	Status            SessionStatus          `json:"status" db:"status"`
	SessionType       SessionType            `json:"session_type" db:"session_type"`
	IPAddress         string                 `json:"ip_address" db:"ip_address"`
	UserAgent         string                 `json:"user_agent" db:"user_agent"`
	DeviceFingerprint string                 `json:"device_fingerprint" db:"device_fingerprint"`
	Location          string                 `json:"location,omitempty" db:"location"`
	MFAVerified       bool                   `json:"mfa_verified" db:"mfa_verified"`
	MFAVerifiedAt     *time.Time             `json:"mfa_verified_at" db:"mfa_verified_at"`
	SecurityClearance SecurityClearanceLevel `json:"security_clearance" db:"security_clearance"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
	LastActivityAt    time.Time              `json:"last_activity_at" db:"last_activity_at"`
	ExpiresAt         time.Time              `json:"expires_at" db:"expires_at"`
	RefreshExpiresAt  time.Time              `json:"refresh_expires_at" db:"refresh_expires_at"`

	// Session-specific settings
	MaxInactivityMinutes int               `json:"max_inactivity_minutes" db:"max_inactivity_minutes"`
	RequireMFAReauth     bool              `json:"require_mfa_reauth" db:"require_mfa_reauth"`
	AllowedResources     []string          `json:"allowed_resources" db:"allowed_resources"`
	DeniedResources      []string          `json:"denied_resources" db:"denied_resources"`
	SessionData          map[string]string `json:"session_data,omitempty" db:"session_data"`

	// Relationships
	User *User `json:"user,omitempty"`
}

// AuthenticationAttempt represents an authentication attempt
type AuthenticationAttempt struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	UserID         *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	TenantID       uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Username       string     `json:"username" db:"username"`
	IPAddress      string     `json:"ip_address" db:"ip_address"`
	UserAgent      string     `json:"user_agent" db:"user_agent"`
	AttemptType    string     `json:"attempt_type" db:"attempt_type"` // LOGIN, MFA, PASSWORD_RESET
	Success        bool       `json:"success" db:"success"`
	FailureReason  string     `json:"failure_reason,omitempty" db:"failure_reason"`
	MFARequired    bool       `json:"mfa_required" db:"mfa_required"`
	MFAVerified    bool       `json:"mfa_verified" db:"mfa_verified"`
	SecurityEvents []string   `json:"security_events" db:"security_events"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`

	// Risk assessment
	RiskScore      float64           `json:"risk_score" db:"risk_score"`
	RiskFactors    []string          `json:"risk_factors" db:"risk_factors"`
	RequiresReview bool              `json:"requires_review" db:"requires_review"`
	Metadata       map[string]string `json:"metadata,omitempty" db:"metadata"`
}

// IsValid checks if the session is valid and active
func (s *Session) IsValid() bool {
	now := time.Now()

	// Check status
	if s.Status != SessionStatusActive {
		return false
	}

	// Check expiration
	if now.After(s.ExpiresAt) {
		return false
	}

	// Check inactivity timeout
	if s.MaxInactivityMinutes > 0 {
		inactivityLimit := s.LastActivityAt.Add(time.Duration(s.MaxInactivityMinutes) * time.Minute)
		if now.After(inactivityLimit) {
			return false
		}
	}

	return true
}

// IsExpired checks if the session is expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsInactive checks if the session has been inactive too long
func (s *Session) IsInactive() bool {
	if s.MaxInactivityMinutes <= 0 {
		return false
	}

	inactivityLimit := s.LastActivityAt.Add(time.Duration(s.MaxInactivityMinutes) * time.Minute)
	return time.Now().After(inactivityLimit)
}

// NeedsMFAReauth checks if the session requires MFA re-authentication
func (s *Session) NeedsMFAReauth() bool {
	if !s.RequireMFAReauth {
		return false
	}

	if !s.MFAVerified {
		return true
	}

	// Require MFA re-auth every 30 minutes for high-security sessions
	if s.SecurityClearance == ClearanceSecret || s.SecurityClearance == ClearanceTopSecret {
		if s.MFAVerifiedAt != nil {
			reauthInterval := 30 * time.Minute
			return time.Since(*s.MFAVerifiedAt) > reauthInterval
		}
		return true
	}

	return false
}

// UpdateActivity updates the last activity timestamp
func (s *Session) UpdateActivity() {
	s.LastActivityAt = time.Now()
	s.UpdatedAt = time.Now()
}

// VerifyMFA marks the session as MFA verified
func (s *Session) VerifyMFA() {
	now := time.Now()
	s.MFAVerified = true
	s.MFAVerifiedAt = &now
	s.UpdatedAt = now
}

// Revoke revokes the session
func (s *Session) Revoke() {
	s.Status = SessionStatusRevoked
	s.UpdatedAt = time.Now()
}

// Suspend suspends the session
func (s *Session) Suspend() {
	s.Status = SessionStatusSuspended
	s.UpdatedAt = time.Now()
}

// Expire expires the session
func (s *Session) Expire() {
	s.Status = SessionStatusExpired
	s.UpdatedAt = time.Now()
}

// CanAccessResource checks if the session can access a specific resource
func (s *Session) CanAccessResource(resource string) bool {
	// Check if resource is explicitly denied
	for _, denied := range s.DeniedResources {
		if denied == resource || denied == "*" {
			return false
		}
	}

	// If no allowed resources specified, allow all (except denied)
	if len(s.AllowedResources) == 0 {
		return true
	}

	// Check if resource is explicitly allowed
	for _, allowed := range s.AllowedResources {
		if allowed == resource || allowed == "*" {
			return true
		}
	}

	return false
}

// ExtendSession extends the session expiration time
func (s *Session) ExtendSession(duration time.Duration) {
	s.ExpiresAt = s.ExpiresAt.Add(duration)
	s.UpdatedAt = time.Now()
}

// GetTimeRemaining returns the time remaining before session expires
func (s *Session) GetTimeRemaining() time.Duration {
	return time.Until(s.ExpiresAt)
}

// GetInactivityTimeRemaining returns the time remaining before inactivity timeout
func (s *Session) GetInactivityTimeRemaining() time.Duration {
	if s.MaxInactivityMinutes <= 0 {
		return 0
	}

	inactivityDeadline := s.LastActivityAt.Add(time.Duration(s.MaxInactivityMinutes) * time.Minute)
	return time.Until(inactivityDeadline)
}

// NewSession creates a new session
func NewSession(userID, tenantID uuid.UUID, sessionType SessionType, ipAddress, userAgent string, securityClearance SecurityClearanceLevel) *Session {
	now := time.Now()

	// Set session duration based on type and security clearance
	var sessionDuration time.Duration
	var refreshDuration time.Duration
	var maxInactivity int

	switch sessionType {
	case SessionTypeAPI:
		sessionDuration = 1 * time.Hour
		refreshDuration = 24 * time.Hour
		maxInactivity = 0 // No inactivity timeout for API
	case SessionTypeSSO:
		sessionDuration = 8 * time.Hour
		refreshDuration = 30 * 24 * time.Hour // 30 days
		maxInactivity = 60                    // 1 hour
	default:
		sessionDuration = 8 * time.Hour
		refreshDuration = 7 * 24 * time.Hour // 7 days
		maxInactivity = 30                   // 30 minutes
	}

	// Adjust based on security clearance
	switch securityClearance {
	case ClearanceTopSecret:
		sessionDuration = sessionDuration / 2
		refreshDuration = refreshDuration / 2
		maxInactivity = maxInactivity / 2
	case ClearanceSecret:
		sessionDuration = sessionDuration * 3 / 4
		refreshDuration = refreshDuration * 3 / 4
		maxInactivity = maxInactivity * 3 / 4
	}

	return &Session{
		ID:                   uuid.New(),
		UserID:               userID,
		TenantID:             tenantID,
		SessionToken:         uuid.New().String(), // Will be replaced with proper JWT
		RefreshToken:         uuid.New().String(), // Will be replaced with proper refresh token
		Status:               SessionStatusActive,
		SessionType:          sessionType,
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		MFAVerified:          false,
		SecurityClearance:    securityClearance,
		CreatedAt:            now,
		UpdatedAt:            now,
		LastActivityAt:       now,
		ExpiresAt:            now.Add(sessionDuration),
		RefreshExpiresAt:     now.Add(refreshDuration),
		MaxInactivityMinutes: maxInactivity,
		RequireMFAReauth:     securityClearance == ClearanceSecret || securityClearance == ClearanceTopSecret,
		AllowedResources:     []string{},
		DeniedResources:      []string{},
		SessionData:          make(map[string]string),
	}
}

// NewAuthenticationAttempt creates a new authentication attempt record
func NewAuthenticationAttempt(tenantID uuid.UUID, username, ipAddress, userAgent, attemptType string) *AuthenticationAttempt {
	return &AuthenticationAttempt{
		ID:             uuid.New(),
		TenantID:       tenantID,
		Username:       username,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		AttemptType:    attemptType,
		Success:        false,
		MFARequired:    false,
		MFAVerified:    false,
		SecurityEvents: []string{},
		CreatedAt:      time.Now(),
		RiskScore:      0.0,
		RiskFactors:    []string{},
		RequiresReview: false,
		Metadata:       make(map[string]string),
	}
}
