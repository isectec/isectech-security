package http

import (
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// Request Models

// LoginRequest represents user login request
type LoginRequest struct {
	Username      string                `json:"username" binding:"required"`
	Password      string                `json:"password" binding:"required"`
	TenantID      uuid.UUID             `json:"tenant_id" binding:"required"`
	SessionType   entity.SessionType    `json:"session_type,omitempty"`
	RememberMe    bool                  `json:"remember_me,omitempty"`
	IPAddress     string                `json:"-"` // Set from request context
	UserAgent     string                `json:"-"` // Set from request context
}

// MFAVerificationRequest represents MFA verification request
type MFAVerificationRequest struct {
	UserID       uuid.UUID `json:"user_id" binding:"required"`
	TenantID     uuid.UUID `json:"tenant_id" binding:"required"`
	ChallengeID  string    `json:"challenge_id" binding:"required"`
	Code         string    `json:"code" binding:"required"`
	DeviceID     uuid.UUID `json:"device_id,omitempty"`
	IPAddress    string    `json:"-"` // Set from request context
	UserAgent    string    `json:"-"` // Set from request context
}

// PasswordChangeRequest represents password change request
type PasswordChangeRequest struct {
	UserID          uuid.UUID `json:"user_id" binding:"required"`
	TenantID        uuid.UUID `json:"tenant_id" binding:"required"`
	CurrentPassword string    `json:"current_password" binding:"required"`
	NewPassword     string    `json:"new_password" binding:"required"`
}

// PasswordResetRequest represents password reset request
type PasswordResetRequest struct {
	Email    string    `json:"email" binding:"required,email"`
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
}

// PasswordResetCompleteRequest represents password reset completion
type PasswordResetCompleteRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// RefreshTokenRequest represents token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest represents logout request
type LogoutRequest struct {
	SessionToken string    `json:"session_token,omitempty"`
	UserID       uuid.UUID `json:"user_id" binding:"required"`
	TenantID     uuid.UUID `json:"tenant_id" binding:"required"`
	LogoutAll    bool      `json:"logout_all,omitempty"`
}

// MFAEnrollmentRequest represents MFA device enrollment request
type MFAEnrollmentRequest struct {
	UserID     uuid.UUID               `json:"user_id" binding:"required"`
	TenantID   uuid.UUID               `json:"tenant_id" binding:"required"`
	DeviceType entity.MFADeviceType    `json:"device_type" binding:"required"`
	DeviceName string                  `json:"device_name" binding:"required"`
	Metadata   map[string]interface{}  `json:"metadata,omitempty"`
}

// SessionValidationRequest represents session validation request
type SessionValidationRequest struct {
	AccessToken        string `json:"access_token" binding:"required"`
	RequiredClearance  string `json:"required_clearance,omitempty"`
	IPAddress          string `json:"-"` // Set from request context
}

// UserRegistrationRequest represents user registration request
type UserRegistrationRequest struct {
	Username          string                        `json:"username" binding:"required"`
	Email             string                        `json:"email" binding:"required,email"`
	Password          string                        `json:"password" binding:"required"`
	FirstName         string                        `json:"first_name" binding:"required"`
	LastName          string                        `json:"last_name" binding:"required"`
	TenantID          uuid.UUID                     `json:"tenant_id" binding:"required"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance,omitempty"`
	InitialRoles      []string                      `json:"initial_roles,omitempty"`
}

// Response Models

// LoginResponse represents successful login response
type LoginResponse struct {
	Success           bool                          `json:"success"`
	UserID            uuid.UUID                     `json:"user_id,omitempty"`
	Username          string                        `json:"username,omitempty"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance,omitempty"`
	AccessToken       string                        `json:"access_token,omitempty"`
	RefreshToken      string                        `json:"refresh_token,omitempty"`
	TokenType         string                        `json:"token_type,omitempty"`
	ExpiresIn         int64                         `json:"expires_in,omitempty"`
	SessionID         uuid.UUID                     `json:"session_id,omitempty"`
	
	// MFA-related fields
	RequiresMFA       bool                          `json:"requires_mfa,omitempty"`
	MFAChallenge      *MFAChallengeResponse         `json:"mfa_challenge,omitempty"`
	
	// Password-related fields
	PasswordExpired   bool                          `json:"password_expired,omitempty"`
	MustChangePassword bool                         `json:"must_change_password,omitempty"`
	
	// Error fields
	FailureReason     string                        `json:"failure_reason,omitempty"`
	RetryAfter        *time.Time                    `json:"retry_after,omitempty"`
}

// MFAChallengeResponse represents MFA challenge response
type MFAChallengeResponse struct {
	ChallengeID   string                `json:"challenge_id"`
	DeviceType    entity.MFADeviceType  `json:"device_type"`
	DeviceName    string                `json:"device_name,omitempty"`
	QRCode        string                `json:"qr_code,omitempty"`
	BackupCodes   []string              `json:"backup_codes,omitempty"`
	ExpiresAt     time.Time             `json:"expires_at"`
	Instructions  string                `json:"instructions,omitempty"`
}

// SessionValidationResponse represents session validation response
type SessionValidationResponse struct {
	Valid             bool                          `json:"valid"`
	UserID            uuid.UUID                     `json:"user_id,omitempty"`
	Username          string                        `json:"username,omitempty"`
	TenantID          uuid.UUID                     `json:"tenant_id,omitempty"`
	SessionID         uuid.UUID                     `json:"session_id,omitempty"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance,omitempty"`
	ExpiresIn         int64                         `json:"expires_in,omitempty"`
	RequiresMFA       bool                          `json:"requires_mfa,omitempty"`
	Roles             []string                      `json:"roles,omitempty"`
	Permissions       []string                      `json:"permissions,omitempty"`
	FailureReason     string                        `json:"failure_reason,omitempty"`
}

// MFAEnrollmentResponse represents MFA enrollment response
type MFAEnrollmentResponse struct {
	Success       bool                  `json:"success"`
	DeviceID      uuid.UUID             `json:"device_id,omitempty"`
	DeviceType    entity.MFADeviceType  `json:"device_type,omitempty"`
	QRCode        string                `json:"qr_code,omitempty"`
	Secret        string                `json:"secret,omitempty"`
	BackupCodes   []string              `json:"backup_codes,omitempty"`
	Instructions  string                `json:"instructions,omitempty"`
	FailureReason string                `json:"failure_reason,omitempty"`
}

// TokenRefreshResponse represents token refresh response
type TokenRefreshResponse struct {
	Success      bool   `json:"success"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// UserResponse represents user information response
type UserResponse struct {
	ID                uuid.UUID                     `json:"id"`
	Username          string                        `json:"username"`
	Email             string                        `json:"email"`
	FirstName         string                        `json:"first_name"`
	LastName          string                        `json:"last_name"`
	TenantID          uuid.UUID                     `json:"tenant_id"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance"`
	Status            entity.UserStatus             `json:"status"`
	MFAEnabled        bool                          `json:"mfa_enabled"`
	MFAEnforced       bool                          `json:"mfa_enforced"`
	LastLoginAt       *time.Time                    `json:"last_login_at,omitempty"`
	CreatedAt         time.Time                     `json:"created_at"`
	UpdatedAt         time.Time                     `json:"updated_at"`
}

// MFADeviceResponse represents MFA device information
type MFADeviceResponse struct {
	ID            uuid.UUID               `json:"id"`
	UserID        uuid.UUID               `json:"user_id"`
	DeviceType    entity.MFADeviceType    `json:"device_type"`
	DeviceName    string                  `json:"device_name"`
	Status        entity.MFADeviceStatus  `json:"status"`
	IsPrimary     bool                    `json:"is_primary"`
	LastUsedAt    *time.Time              `json:"last_used_at,omitempty"`
	CreatedAt     time.Time               `json:"created_at"`
	FailureCount  int                     `json:"failure_count"`
	BackupCodesRemaining int              `json:"backup_codes_remaining,omitempty"`
}

// SessionResponse represents session information
type SessionResponse struct {
	ID                uuid.UUID                     `json:"id"`
	UserID            uuid.UUID                     `json:"user_id"`
	SessionType       entity.SessionType            `json:"session_type"`
	Status            entity.SessionStatus          `json:"status"`
	IPAddress         string                        `json:"ip_address"`
	UserAgent         string                        `json:"user_agent"`
	Location          string                        `json:"location,omitempty"`
	DeviceFingerprint string                        `json:"device_fingerprint,omitempty"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance"`
	MFAVerified       bool                          `json:"mfa_verified"`
	CreatedAt         time.Time                     `json:"created_at"`
	LastActivityAt    time.Time                     `json:"last_activity_at"`
	ExpiresAt         time.Time                     `json:"expires_at"`
}

// ErrorResponse represents API error response
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message,omitempty"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// SuccessResponse represents generic success response
type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// PasswordStrengthResponse represents password strength validation
type PasswordStrengthResponse struct {
	Valid       bool     `json:"valid"`
	Score       int      `json:"score"`
	Strength    string   `json:"strength"`
	Violations  []string `json:"violations,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
}

// HealthResponse represents service health status
type HealthResponse struct {
	Status      string                 `json:"status"`
	Version     string                 `json:"version"`
	Timestamp   time.Time              `json:"timestamp"`
	Components  map[string]interface{} `json:"components,omitempty"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}

// Helper functions for response conversion

// ToUserResponse converts entity.User to UserResponse
func ToUserResponse(user *entity.User) *UserResponse {
	return &UserResponse{
		ID:                user.ID,
		Username:          user.Username,
		Email:             user.Email,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		TenantID:          user.TenantID,
		SecurityClearance: user.SecurityClearance,
		Status:            user.Status,
		MFAEnabled:        user.MFAEnabled,
		MFAEnforced:       user.MFAEnforced,
		LastLoginAt:       user.LastLoginAt,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
	}
}

// ToMFADeviceResponse converts entity.MFADevice to MFADeviceResponse
func ToMFADeviceResponse(device *entity.MFADevice) *MFADeviceResponse {
	backupCodesRemaining := 0
	if device.DeviceType == entity.MFADeviceBackupCodes && device.BackupCodes != nil {
		for _, code := range device.BackupCodes {
			if !code.Used {
				backupCodesRemaining++
			}
		}
	}

	return &MFADeviceResponse{
		ID:                   device.ID,
		UserID:               device.UserID,
		DeviceType:           device.DeviceType,
		DeviceName:           device.DeviceName,
		Status:               device.Status,
		IsPrimary:            device.IsPrimary,
		LastUsedAt:           device.LastUsedAt,
		CreatedAt:            device.CreatedAt,
		FailureCount:         device.FailureCount,
		BackupCodesRemaining: backupCodesRemaining,
	}
}

// ToSessionResponse converts entity.Session to SessionResponse
func ToSessionResponse(session *entity.Session) *SessionResponse {
	return &SessionResponse{
		ID:                session.ID,
		UserID:            session.UserID,
		SessionType:       session.SessionType,
		Status:            session.Status,
		IPAddress:         session.IPAddress.String(),
		UserAgent:         session.UserAgent,
		Location:          session.Location,
		DeviceFingerprint: session.DeviceFingerprint,
		SecurityClearance: session.SecurityClearance,
		MFAVerified:       session.MFAVerified,
		CreatedAt:         session.CreatedAt,
		LastActivityAt:    session.LastActivityAt,
		ExpiresAt:         session.ExpiresAt,
	}
}