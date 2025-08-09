package usecase

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
	"isectech/auth-service/infrastructure/database/postgres"
)

// AuthenticationServiceImpl implements the authentication service interface
type AuthenticationServiceImpl struct {
	userRepo     *postgres.UserRepository
	sessionRepo  SessionRepository
	auditRepo    *postgres.AuditRepository
	mfaService   service.MFAService
	emailService EmailService
	smsService   SMSService

	// Configuration
	config *AuthConfig

	// Rate limiting and security
	rateLimiter   RateLimiter
	ipBlocker     IPBlocker
	riskEvaluator RiskEvaluator
}

// AuthConfig holds authentication service configuration
type AuthConfig struct {
	// Password policy
	MinPasswordLength     int           `yaml:"min_password_length" default:"12"`
	MaxPasswordLength     int           `yaml:"max_password_length" default:"128"`
	RequireUppercase      bool          `yaml:"require_uppercase" default:"true"`
	RequireLowercase      bool          `yaml:"require_lowercase" default:"true"`
	RequireNumbers        bool          `yaml:"require_numbers" default:"true"`
	RequireSpecialChars   bool          `yaml:"require_special_chars" default:"true"`
	ForbidCommonPasswords bool          `yaml:"forbid_common_passwords" default:"true"`
	PasswordHistoryCount  int           `yaml:"password_history_count" default:"12"`
	PasswordMaxAge        time.Duration `yaml:"password_max_age" default:"90d"`

	// Argon2 parameters
	Argon2Time    uint32 `yaml:"argon2_time" default:"3"`
	Argon2Memory  uint32 `yaml:"argon2_memory" default:"65536"`
	Argon2Threads uint8  `yaml:"argon2_threads" default:"4"`
	Argon2KeyLen  uint32 `yaml:"argon2_keylen" default:"32"`

	// Session configuration
	SessionTimeout        time.Duration `yaml:"session_timeout" default:"30m"`
	MaxConcurrentSessions int           `yaml:"max_concurrent_sessions" default:"5"`
	SessionSecureFlag     bool          `yaml:"session_secure_flag" default:"true"`
	SessionSameSite       string        `yaml:"session_samesite" default:"strict"`

	// Security settings
	MaxFailedAttempts   int           `yaml:"max_failed_attempts" default:"5"`
	LockoutDuration     time.Duration `yaml:"lockout_duration" default:"15m"`
	EnableTwoFactorAuth bool          `yaml:"enable_2fa" default:"true"`
	RequireMFAForAdmin  bool          `yaml:"require_mfa_admin" default:"true"`

	// Token settings
	JWTSecret       string        `yaml:"jwt_secret"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl" default:"15m"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" default:"7d"`
	TokenIssuer     string        `yaml:"token_issuer" default:"iSECTECH"`

	// Risk evaluation
	EnableRiskEvaluation  bool    `yaml:"enable_risk_evaluation" default:"true"`
	HighRiskThreshold     float64 `yaml:"high_risk_threshold" default:"7.0"`
	CriticalRiskThreshold float64 `yaml:"critical_risk_threshold" default:"9.0"`

	// Notification settings
	NotifyOnLogin         bool `yaml:"notify_on_login" default:"true"`
	NotifyOnMFAEnrollment bool `yaml:"notify_on_mfa_enrollment" default:"true"`
	NotifyOnRiskEvent     bool `yaml:"notify_on_risk_event" default:"true"`
}

// External service interfaces
type SessionRepository interface {
	Create(ctx context.Context, session *entity.Session) error
	GetByToken(ctx context.Context, token string) (*entity.Session, error)
	GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.Session, error)
	Update(ctx context.Context, session *entity.Session) error
	Delete(ctx context.Context, sessionID uuid.UUID) error
	DeleteAllByUserID(ctx context.Context, userID, tenantID uuid.UUID) error
	CleanupExpired(ctx context.Context) (int, error)
}

type EmailService interface {
	SendWelcomeEmail(ctx context.Context, user *entity.User) error
	SendPasswordResetEmail(ctx context.Context, user *entity.User, token string) error
	SendLoginNotification(ctx context.Context, user *entity.User, loginInfo *LoginInfo) error
	SendSecurityAlert(ctx context.Context, user *entity.User, alert *SecurityAlert) error
}

type SMSService interface {
	SendWelcomeSMS(ctx context.Context, phoneNumber string, user *entity.User) error
	SendSecurityAlert(ctx context.Context, phoneNumber string, alert *SecurityAlert) error
}

type RateLimiter interface {
	CheckLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error)
	ResetLimit(ctx context.Context, key string) error
}

type IPBlocker interface {
	IsBlocked(ctx context.Context, ipAddress string) (bool, time.Duration, error)
	BlockIP(ctx context.Context, ipAddress string, duration time.Duration, reason string) error
	UnblockIP(ctx context.Context, ipAddress string) error
}

type RiskEvaluator interface {
	EvaluateLoginRisk(ctx context.Context, req *service.LoginRequest, user *entity.User) (*RiskAssessment, error)
	EvaluateRegistrationRisk(ctx context.Context, req *service.UserRegistrationRequest) (*RiskAssessment, error)
}

// Supporting types
type LoginInfo struct {
	IPAddress   string
	UserAgent   string
	Location    string
	DeviceInfo  string
	LoginTime   time.Time
	SessionType entity.SessionType
}

type SecurityAlert struct {
	Type        string
	Description string
	Severity    string
	IPAddress   string
	UserAgent   string
	Timestamp   time.Time
	Metadata    map[string]interface{}
}

type RiskAssessment struct {
	Score           float64
	Level           string
	Factors         []string
	Recommendations []string
	RequiresMFA     bool
	BlockAccess     bool
}

// NewAuthenticationService creates a new authentication service
func NewAuthenticationService(
	userRepo *postgres.UserRepository,
	sessionRepo SessionRepository,
	auditRepo *postgres.AuditRepository,
	mfaService service.MFAService,
	emailService EmailService,
	smsService SMSService,
	rateLimiter RateLimiter,
	ipBlocker IPBlocker,
	riskEvaluator RiskEvaluator,
	config *AuthConfig,
) *AuthenticationServiceImpl {
	return &AuthenticationServiceImpl{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		auditRepo:     auditRepo,
		mfaService:    mfaService,
		emailService:  emailService,
		smsService:    smsService,
		rateLimiter:   rateLimiter,
		ipBlocker:     ipBlocker,
		riskEvaluator: riskEvaluator,
		config:        config,
	}
}

// Login implements user authentication with comprehensive security features
func (a *AuthenticationServiceImpl) Login(ctx context.Context, req *service.LoginRequest) (*service.LoginResponse, error) {
	// Step 1: Input validation
	if err := a.validateLoginRequest(req); err != nil {
		return &service.LoginResponse{
			Success:       false,
			FailureReason: fmt.Sprintf("Invalid request: %v", err),
		}, nil
	}

	// Step 2: Rate limiting check
	rateLimitKey := fmt.Sprintf("login:%s:%s", req.TenantID, req.IPAddress)
	allowed, retryAfter, err := a.rateLimiter.CheckLimit(ctx, rateLimitKey, a.config.MaxFailedAttempts, a.config.LockoutDuration)
	if err != nil {
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}
	if !allowed {
		retryAt := time.Now().Add(retryAfter)
		return &service.LoginResponse{
			Success:       false,
			FailureReason: "Too many failed attempts",
			RetryAfter:    &retryAt,
		}, nil
	}

	// Step 3: IP blocking check
	blocked, blockDuration, err := a.ipBlocker.IsBlocked(ctx, req.IPAddress)
	if err != nil {
		return nil, fmt.Errorf("IP block check failed: %w", err)
	}
	if blocked {
		retryAt := time.Now().Add(blockDuration)
		return &service.LoginResponse{
			Success:       false,
			FailureReason: "IP address blocked",
			RetryAfter:    &retryAt,
		}, nil
	}

	// Step 4: Retrieve user
	user, err := a.userRepo.GetByUsername(ctx, req.Username, req.TenantID)
	if err != nil {
		a.logFailedAttempt(ctx, req, nil, "User not found")
		return &service.LoginResponse{
			Success:       false,
			FailureReason: "Invalid credentials",
		}, nil
	}

	// Step 5: Check user status
	if !user.IsActive() {
		a.logFailedAttempt(ctx, req, user, "Account inactive")
		return &service.LoginResponse{
			Success:       false,
			FailureReason: "Account inactive",
		}, nil
	}

	// Step 6: Check if account is locked
	if user.IsLocked() {
		a.logFailedAttempt(ctx, req, user, "Account locked")
		lockUntil := user.LockedUntil
		return &service.LoginResponse{
			Success:       false,
			FailureReason: "Account locked",
			RetryAfter:    lockUntil,
		}, nil
	}

	// Step 7: Password verification
	valid, err := a.verifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("password verification failed: %w", err)
	}
	if !valid {
		// Increment failed attempts
		a.userRepo.IncrementFailedAttempts(ctx, user.ID, user.TenantID)
		a.logFailedAttempt(ctx, req, user, "Invalid password")

		return &service.LoginResponse{
			Success:       false,
			FailureReason: "Invalid credentials",
		}, nil
	}

	// Step 8: Risk evaluation
	var riskAssessment *RiskAssessment
	if a.config.EnableRiskEvaluation {
		riskAssessment, err = a.riskEvaluator.EvaluateLoginRisk(ctx, req, user)
		if err != nil {
			return nil, fmt.Errorf("risk evaluation failed: %w", err)
		}

		// Block if risk is too high
		if riskAssessment.BlockAccess {
			a.logFailedAttempt(ctx, req, user, "High risk login blocked")

			// Send security alert
			alert := &SecurityAlert{
				Type:        "HIGH_RISK_LOGIN_BLOCKED",
				Description: "Login attempt blocked due to high risk score",
				Severity:    "HIGH",
				IPAddress:   req.IPAddress,
				UserAgent:   req.UserAgent,
				Timestamp:   time.Now(),
				Metadata: map[string]interface{}{
					"risk_score": riskAssessment.Score,
					"factors":    riskAssessment.Factors,
				},
			}

			if a.config.NotifyOnRiskEvent {
				a.emailService.SendSecurityAlert(ctx, user, alert)
			}

			return &service.LoginResponse{
				Success:       false,
				FailureReason: "Login blocked for security reasons",
			}, nil
		}
	}

	// Step 9: Reset failed attempts on successful login
	if user.FailedAttempts > 0 {
		a.userRepo.ResetFailedAttempts(ctx, user.ID, user.TenantID)
	}

	// Step 10: Check if password needs to be changed
	passwordExpired := a.isPasswordExpired(user)
	if passwordExpired {
		return &service.LoginResponse{
			Success:            true,
			UserID:             user.ID,
			PasswordExpired:    true,
			MustChangePassword: true,
			User:               user,
		}, nil
	}

	// Step 11: Check MFA requirements
	requiresMFA := a.requiresMFA(user, riskAssessment)
	if requiresMFA {
		// Generate MFA challenge
		challengeReq := &service.MFAChallengeRequest{
			UserID:     user.ID,
			TenantID:   user.TenantID,
			DeviceType: a.getPrimaryMFADeviceType(ctx, user),
			IPAddress:  req.IPAddress,
			UserAgent:  req.UserAgent,
		}

		mfaChallenge, err := a.mfaService.SendMFAChallenge(ctx, challengeReq)
		if err != nil {
			return nil, fmt.Errorf("MFA challenge generation failed: %w", err)
		}

		return &service.LoginResponse{
			Success:      true,
			UserID:       user.ID,
			RequiresMFA:  true,
			MFAChallenge: mfaChallenge,
			User:         user,
		}, nil
	}

	// Step 12: Create session
	session, accessToken, refreshToken, err := a.createSession(ctx, user, req)
	if err != nil {
		return nil, fmt.Errorf("session creation failed: %w", err)
	}

	// Step 13: Update last login info
	a.userRepo.UpdateLastLogin(ctx, user.ID, user.TenantID, req.IPAddress)

	// Step 14: Log successful login
	a.logSuccessfulLogin(ctx, req, user, session)

	// Step 15: Send notifications
	if a.config.NotifyOnLogin {
		loginInfo := &LoginInfo{
			IPAddress:   req.IPAddress,
			UserAgent:   req.UserAgent,
			Location:    a.getLocationFromIP(req.IPAddress),
			DeviceInfo:  a.getDeviceInfo(req.UserAgent),
			LoginTime:   time.Now(),
			SessionType: req.SessionType,
		}

		go a.emailService.SendLoginNotification(ctx, user, loginInfo)
	}

	return &service.LoginResponse{
		Success:      true,
		UserID:       user.ID,
		SessionID:    session.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(a.config.AccessTokenTTL.Seconds()),
		User:         user,
	}, nil
}

// Logout implements secure session termination
func (a *AuthenticationServiceImpl) Logout(ctx context.Context, req *service.LogoutRequest) error {
	// Validate session
	session, err := a.sessionRepo.GetByToken(ctx, req.SessionToken)
	if err != nil {
		return fmt.Errorf("session lookup failed: %w", err)
	}

	if session == nil || session.UserID != req.UserID || session.TenantID != req.TenantID {
		return fmt.Errorf("invalid session")
	}

	// Terminate session
	err = a.sessionRepo.Delete(ctx, session.ID)
	if err != nil {
		return fmt.Errorf("session termination failed: %w", err)
	}

	// Log logout event
	a.logLogoutEvent(ctx, req, session)

	return nil
}

// LogoutAll terminates all sessions for a user
func (a *AuthenticationServiceImpl) LogoutAll(ctx context.Context, userID, tenantID uuid.UUID) error {
	err := a.sessionRepo.DeleteAllByUserID(ctx, userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to terminate all sessions: %w", err)
	}

	// Log logout all event
	a.logLogoutAllEvent(ctx, userID, tenantID)

	return nil
}

// ValidateSession validates and returns session information
func (a *AuthenticationServiceImpl) ValidateSession(ctx context.Context, req *service.SessionValidationRequest) (*service.SessionValidationResponse, error) {
	// Get session by token
	session, err := a.sessionRepo.GetByToken(ctx, req.AccessToken)
	if err != nil {
		return &service.SessionValidationResponse{
			Valid:         false,
			FailureReason: "Session lookup failed",
		}, nil
	}

	if session == nil {
		return &service.SessionValidationResponse{
			Valid:         false,
			FailureReason: "Session not found",
		}, nil
	}

	// Check session expiration
	if session.IsExpired() {
		a.sessionRepo.Delete(ctx, session.ID)
		return &service.SessionValidationResponse{
			Valid:         false,
			FailureReason: "Session expired",
		}, nil
	}

	// Check if session is active
	if session.Status != entity.SessionStatusActive {
		return &service.SessionValidationResponse{
			Valid:         false,
			FailureReason: "Session inactive",
		}, nil
	}

	// Validate IP address if required
	if req.IPAddress != "" && session.IPAddress.String() != req.IPAddress {
		// Log suspicious activity
		a.logSuspiciousActivity(ctx, session, "IP address mismatch", map[string]interface{}{
			"session_ip": session.IPAddress.String(),
			"request_ip": req.IPAddress,
		})

		return &service.SessionValidationResponse{
			Valid:         false,
			FailureReason: "IP address mismatch",
		}, nil
	}

	// Check required security clearance
	if req.RequiredClearance != "" {
		if !session.HasRequiredClearance(entity.SecurityClearanceLevel(req.RequiredClearance)) {
			return &service.SessionValidationResponse{
				Valid:         false,
				FailureReason: "Insufficient security clearance",
			}, nil
		}
	}

	// Update last activity
	session.UpdateLastActivity()
	a.sessionRepo.Update(ctx, session)

	// Get user info
	user, err := a.userRepo.GetByID(ctx, session.UserID, session.TenantID)
	if err != nil {
		return &service.SessionValidationResponse{
			Valid:         false,
			FailureReason: "User not found",
		}, nil
	}

	// Check if user is still active
	if !user.IsActive() {
		a.sessionRepo.Delete(ctx, session.ID)
		return &service.SessionValidationResponse{
			Valid:         false,
			FailureReason: "User account inactive",
		}, nil
	}

	// Calculate remaining session time
	expiresIn := int64(session.ExpiresAt.Sub(time.Now()).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	return &service.SessionValidationResponse{
		Valid:             true,
		UserID:            session.UserID,
		TenantID:          session.TenantID,
		SessionID:         session.ID,
		SecurityClearance: session.SecurityClearance,
		ExpiresIn:         expiresIn,
		RequiresMFA:       session.RequiresMFA,
		User:              user,
		Session:           session,
	}, nil
}

// Helper methods for password management
func (a *AuthenticationServiceImpl) hashPassword(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		a.config.Argon2Time,
		a.config.Argon2Memory,
		a.config.Argon2Threads,
		a.config.Argon2KeyLen,
	)

	// Encode with parameters and salt
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.config.Argon2Memory,
		a.config.Argon2Time,
		a.config.Argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

func (a *AuthenticationServiceImpl) verifyPassword(password, hash string) (bool, error) {
	// Parse hash format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	// Extract parameters
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("invalid version: %w", err)
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("invalid parameters: %w", err)
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("invalid hash: %w", err)
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expectedHash)))

	// Compare hashes in constant time
	return subtle.ConstantTimeCompare(expectedHash, computedHash) == 1, nil
}

// Additional helper methods would continue here...
// (Implementation of session creation, validation helpers, logging, etc.)

func (a *AuthenticationServiceImpl) validateLoginRequest(req *service.LoginRequest) error {
	if req.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if req.IPAddress == "" {
		return fmt.Errorf("IP address is required")
	}
	return nil
}

func (a *AuthenticationServiceImpl) requiresMFA(user *entity.User, riskAssessment *RiskAssessment) bool {
	// Always require MFA if enforced for user
	if user.MFAEnforced {
		return true
	}

	// Require MFA if user has it enabled
	if user.MFAEnabled {
		return true
	}

	// Require MFA for admin users if configured
	if a.config.RequireMFAForAdmin {
		// Check if user has admin roles (implementation depends on role structure)
		// This would need to be implemented based on the role system
	}

	// Require MFA based on risk assessment
	if riskAssessment != nil && riskAssessment.RequiresMFA {
		return true
	}

	return false
}

// Placeholder implementations for remaining methods...
func (a *AuthenticationServiceImpl) getPrimaryMFADeviceType(ctx context.Context, user *entity.User) entity.MFADeviceType {
	// Implementation would query user's MFA devices and return primary type
	return entity.MFADeviceTOTP // Default fallback
}

func (a *AuthenticationServiceImpl) isPasswordExpired(user *entity.User) bool {
	if a.config.PasswordMaxAge == 0 {
		return false
	}
	return time.Since(user.PasswordChangedAt) > a.config.PasswordMaxAge
}

func (a *AuthenticationServiceImpl) createSession(ctx context.Context, user *entity.User, req *service.LoginRequest) (*entity.Session, string, string, error) {
	// Implementation would create JWT tokens and session record
	// This is a placeholder - full implementation would be more complex
	session := &entity.Session{
		ID:       uuid.New(),
		UserID:   user.ID,
		TenantID: user.TenantID,
		// ... other session fields
	}

	return session, "access_token", "refresh_token", nil
}

func (a *AuthenticationServiceImpl) getLocationFromIP(ipAddress string) string {
	// Implementation would use IP geolocation service
	return "Unknown"
}

func (a *AuthenticationServiceImpl) getDeviceInfo(userAgent string) string {
	// Implementation would parse user agent
	return "Unknown Device"
}

// Logging helper methods
func (a *AuthenticationServiceImpl) logFailedAttempt(ctx context.Context, req *service.LoginRequest, user *entity.User, reason string) {
	// Implementation for audit logging
}

func (a *AuthenticationServiceImpl) logSuccessfulLogin(ctx context.Context, req *service.LoginRequest, user *entity.User, session *entity.Session) {
	// Implementation for audit logging
}

func (a *AuthenticationServiceImpl) logLogoutEvent(ctx context.Context, req *service.LogoutRequest, session *entity.Session) {
	// Implementation for audit logging
}

func (a *AuthenticationServiceImpl) logLogoutAllEvent(ctx context.Context, userID, tenantID uuid.UUID) {
	// Implementation for audit logging
}

func (a *AuthenticationServiceImpl) logSuspiciousActivity(ctx context.Context, session *entity.Session, activity string, metadata map[string]interface{}) {
	// Implementation for security event logging
}
