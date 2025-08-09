package service

import (
	"context"
	"time"

	"../entity"
	"github.com/google/uuid"
)

// LoginRequest represents a login request
type LoginRequest struct {
	TenantID          uuid.UUID          `json:"tenant_id"`
	Username          string             `json:"username"`
	Password          string             `json:"password"`
	IPAddress         string             `json:"ip_address"`
	UserAgent         string             `json:"user_agent"`
	DeviceFingerprint string             `json:"device_fingerprint,omitempty"`
	RememberMe        bool               `json:"remember_me"`
	SessionType       entity.SessionType `json:"session_type"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Success            bool                  `json:"success"`
	UserID             uuid.UUID             `json:"user_id,omitempty"`
	SessionID          uuid.UUID             `json:"session_id,omitempty"`
	AccessToken        string                `json:"access_token,omitempty"`
	RefreshToken       string                `json:"refresh_token,omitempty"`
	TokenType          string                `json:"token_type"`
	ExpiresIn          int64                 `json:"expires_in,omitempty"`
	RequiresMFA        bool                  `json:"requires_mfa"`
	MFAChallenge       *MFAChallengeResponse `json:"mfa_challenge,omitempty"`
	PasswordExpired    bool                  `json:"password_expired"`
	MustChangePassword bool                  `json:"must_change_password"`
	FailureReason      string                `json:"failure_reason,omitempty"`
	RetryAfter         *time.Time            `json:"retry_after,omitempty"`
	User               *entity.User          `json:"user,omitempty"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
}

// RefreshTokenResponse represents a token refresh response
type RefreshTokenResponse struct {
	Success       bool   `json:"success"`
	AccessToken   string `json:"access_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int64  `json:"expires_in,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	SessionID    uuid.UUID `json:"session_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	LogoutAll    bool      `json:"logout_all"` // Logout from all sessions
}

// PasswordChangeRequest represents a password change request
type PasswordChangeRequest struct {
	UserID          uuid.UUID `json:"user_id"`
	TenantID        uuid.UUID `json:"tenant_id"`
	CurrentPassword string    `json:"current_password"`
	NewPassword     string    `json:"new_password"`
	IPAddress       string    `json:"ip_address"`
	UserAgent       string    `json:"user_agent"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// PasswordResetConfirmRequest represents a password reset confirmation
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
}

// UserRegistrationRequest represents a user registration request
type UserRegistrationRequest struct {
	TenantID          uuid.UUID                     `json:"tenant_id"`
	Username          string                        `json:"username"`
	Email             string                        `json:"email"`
	Password          string                        `json:"password"`
	FirstName         string                        `json:"first_name"`
	LastName          string                        `json:"last_name"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance"`
	InitialRoles      []uuid.UUID                   `json:"initial_roles,omitempty"`
	IPAddress         string                        `json:"ip_address"`
	UserAgent         string                        `json:"user_agent"`
	InvitationToken   string                        `json:"invitation_token,omitempty"`
}

// UserRegistrationResponse represents a user registration response
type UserRegistrationResponse struct {
	Success              bool         `json:"success"`
	UserID               uuid.UUID    `json:"user_id,omitempty"`
	RequiresVerification bool         `json:"requires_verification"`
	VerificationToken    string       `json:"verification_token,omitempty"`
	FailureReason        string       `json:"failure_reason,omitempty"`
	User                 *entity.User `json:"user,omitempty"`
}

// SessionValidationRequest represents a session validation request
type SessionValidationRequest struct {
	SessionID           uuid.UUID                     `json:"session_id"`
	AccessToken         string                        `json:"access_token"`
	RequiredClearance   entity.SecurityClearanceLevel `json:"required_clearance,omitempty"`
	RequiredPermissions []string                      `json:"required_permissions,omitempty"`
	Resource            string                        `json:"resource,omitempty"`
	Action              string                        `json:"action,omitempty"`
	IPAddress           string                        `json:"ip_address"`
	UserAgent           string                        `json:"user_agent"`
}

// SessionValidationResponse represents a session validation response
type SessionValidationResponse struct {
	Valid             bool                          `json:"valid"`
	UserID            uuid.UUID                     `json:"user_id,omitempty"`
	TenantID          uuid.UUID                     `json:"tenant_id,omitempty"`
	SessionID         uuid.UUID                     `json:"session_id,omitempty"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance,omitempty"`
	Permissions       []string                      `json:"permissions,omitempty"`
	ExpiresIn         int64                         `json:"expires_in,omitempty"`
	RequiresMFA       bool                          `json:"requires_mfa"`
	FailureReason     string                        `json:"failure_reason,omitempty"`
	User              *entity.User                  `json:"user,omitempty"`
	Session           *entity.Session               `json:"session,omitempty"`
}

// AuthService defines the interface for authentication operations
type AuthService interface {
	// Authentication Operations
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)
	LoginWithMFA(ctx context.Context, sessionID uuid.UUID, mfaReq *MFAVerificationRequest) (*LoginResponse, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error)
	Logout(ctx context.Context, req *LogoutRequest) error
	LogoutAll(ctx context.Context, userID, tenantID uuid.UUID) error

	// Session Management
	ValidateSession(ctx context.Context, req *SessionValidationRequest) (*SessionValidationResponse, error)
	ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) error
	GetActiveSessionsCount(ctx context.Context, userID, tenantID uuid.UUID) (int, error)
	GetActiveSessions(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.Session, error)
	RevokeSession(ctx context.Context, sessionID, userID, tenantID uuid.UUID) error
	CleanupExpiredSessions(ctx context.Context) (int, error)

	// User Management
	RegisterUser(ctx context.Context, req *UserRegistrationRequest) (*UserRegistrationResponse, error)
	VerifyUserEmail(ctx context.Context, token string) error
	ResendVerificationEmail(ctx context.Context, email string, tenantID uuid.UUID) error

	// Password Management
	ChangePassword(ctx context.Context, req *PasswordChangeRequest) error
	RequestPasswordReset(ctx context.Context, req *PasswordResetRequest) error
	ConfirmPasswordReset(ctx context.Context, req *PasswordResetConfirmRequest) error
	ValidatePasswordStrength(ctx context.Context, password string) (bool, []string, error)
	ForcePasswordChange(ctx context.Context, userID, tenantID uuid.UUID) error

	// Account Management
	LockAccount(ctx context.Context, userID, tenantID uuid.UUID, reason string) error
	UnlockAccount(ctx context.Context, userID, tenantID uuid.UUID) error
	SuspendAccount(ctx context.Context, userID, tenantID uuid.UUID, reason string) error
	ActivateAccount(ctx context.Context, userID, tenantID uuid.UUID) error
	DeleteAccount(ctx context.Context, userID, tenantID uuid.UUID) error

	// Security Operations
	CheckRateLimit(ctx context.Context, identifier, action string) (bool, time.Duration, error)
	RecordLoginAttempt(ctx context.Context, attempt *entity.AuthenticationAttempt) error
	AnalyzeRisk(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (float64, []string, error)
	DetectAnomalousLogin(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (bool, []string, error)
	RequireStepUpAuth(ctx context.Context, sessionID uuid.UUID, reason string) error

	// Administrative Operations
	GetUserByID(ctx context.Context, userID, tenantID uuid.UUID) (*entity.User, error)
	GetUserByUsername(ctx context.Context, username string, tenantID uuid.UUID) (*entity.User, error)
	GetUserByEmail(ctx context.Context, email string, tenantID uuid.UUID) (*entity.User, error)
	ListUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]entity.User, int, error)
	UpdateUserSecurityClearance(ctx context.Context, userID, tenantID uuid.UUID, clearance entity.SecurityClearanceLevel) error
	GetLoginHistory(ctx context.Context, userID, tenantID uuid.UUID, limit int) ([]entity.AuthenticationAttempt, error)
	GetSecurityEvents(ctx context.Context, userID, tenantID uuid.UUID, from, to time.Time) ([]SecurityEvent, error)

	// Health and Monitoring
	HealthCheck(ctx context.Context) error
	GetMetrics(ctx context.Context) (*AuthMetrics, error)
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID          uuid.UUID              `json:"id"`
	UserID      uuid.UUID              `json:"user_id"`
	TenantID    uuid.UUID              `json:"tenant_id"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	RiskScore   float64                `json:"risk_score"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
}

// AuthMetrics represents authentication metrics
type AuthMetrics struct {
	TotalUsers             int           `json:"total_users"`
	ActiveUsers24h         int           `json:"active_users_24h"`
	ActiveSessions         int           `json:"active_sessions"`
	LoginAttempts24h       int           `json:"login_attempts_24h"`
	SuccessfulLogins24h    int           `json:"successful_logins_24h"`
	FailedLogins24h        int           `json:"failed_logins_24h"`
	MFAVerifications24h    int           `json:"mfa_verifications_24h"`
	PasswordResets24h      int           `json:"password_resets_24h"`
	AccountLockouts24h     int           `json:"account_lockouts_24h"`
	SecurityEvents24h      int           `json:"security_events_24h"`
	AverageSessionDuration time.Duration `json:"average_session_duration"`
	LastUpdated            time.Time     `json:"last_updated"`
}
