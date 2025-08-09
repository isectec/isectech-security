package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/infrastructure/database/postgres"
)

// SessionServiceImpl implements session management operations
type SessionServiceImpl struct {
	sessionRepo SessionRepository
	userRepo    *postgres.UserRepository
	auditRepo   *postgres.AuditRepository
	config      *SessionConfig
	jwtSecret   []byte
}

// SessionConfig holds session management configuration
type SessionConfig struct {
	// Session timeouts
	DefaultTimeout    time.Duration `yaml:"default_timeout" default:"30m"`
	MaxTimeout        time.Duration `yaml:"max_timeout" default:"24h"`
	InactivityTimeout time.Duration `yaml:"inactivity_timeout" default:"15m"`
	ExtendableTimeout time.Duration `yaml:"extendable_timeout" default:"2h"`

	// Session limits
	MaxConcurrentSessions int  `yaml:"max_concurrent_sessions" default:"5"`
	MaxSessionsPerIP      int  `yaml:"max_sessions_per_ip" default:"10"`
	EnableSessionSharing  bool `yaml:"enable_session_sharing" default:"false"`

	// Security settings
	RequireIPValidation bool   `yaml:"require_ip_validation" default:"true"`
	RequireUAValidation bool   `yaml:"require_ua_validation" default:"false"`
	SecureCookieFlag    bool   `yaml:"secure_cookie_flag" default:"true"`
	SameSiteCookieMode  string `yaml:"samesite_cookie_mode" default:"strict"`
	HTTPOnlyCookieFlag  bool   `yaml:"httponly_cookie_flag" default:"true"`

	// Token settings
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl" default:"15m"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" default:"7d"`
	TokenIssuer     string        `yaml:"token_issuer" default:"iSECTECH"`
	TokenAudience   string        `yaml:"token_audience" default:"iSECTECH-API"`

	// Step-up authentication
	RequireStepUpForAdmin bool          `yaml:"require_stepup_admin" default:"true"`
	StepUpTimeout         time.Duration `yaml:"stepup_timeout" default:"10m"`

	// Session monitoring
	EnableSessionLogging      bool `yaml:"enable_session_logging" default:"true"`
	LogSessionActivity        bool `yaml:"log_session_activity" default:"true"`
	MonitorConcurrentSessions bool `yaml:"monitor_concurrent_sessions" default:"true"`
}

// SessionTokens holds JWT access and refresh tokens
type SessionTokens struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
}

// SessionClaims represents JWT claims for session tokens
type SessionClaims struct {
	UserID            uuid.UUID                     `json:"user_id"`
	TenantID          uuid.UUID                     `json:"tenant_id"`
	SessionID         uuid.UUID                     `json:"session_id"`
	Username          string                        `json:"username"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance"`
	Roles             []string                      `json:"roles"`
	Permissions       []string                      `json:"permissions"`
	MFAVerified       bool                          `json:"mfa_verified"`
	TokenType         string                        `json:"token_type"` // "access" or "refresh"
	IPAddress         string                        `json:"ip_address"`
	UserAgent         string                        `json:"user_agent"`
	DeviceFingerprint string                        `json:"device_fingerprint,omitempty"`

	jwt.RegisteredClaims
}

// NewSessionService creates a new session service
func NewSessionService(
	sessionRepo SessionRepository,
	userRepo *postgres.UserRepository,
	auditRepo *postgres.AuditRepository,
	config *SessionConfig,
	jwtSecret string,
) *SessionServiceImpl {
	return &SessionServiceImpl{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		auditRepo:   auditRepo,
		config:      config,
		jwtSecret:   []byte(jwtSecret),
	}
}

// CreateSession creates a new authenticated session
func (s *SessionServiceImpl) CreateSession(ctx context.Context, user *entity.User, req *CreateSessionRequest) (*entity.Session, *SessionTokens, error) {
	// Step 1: Validate session limits
	err := s.validateSessionLimits(ctx, user, req)
	if err != nil {
		return nil, nil, fmt.Errorf("session limit validation failed: %w", err)
	}

	// Step 2: Create session entity
	session := &entity.Session{
		ID:                uuid.New(),
		UserID:            user.ID,
		TenantID:          user.TenantID,
		Status:            entity.SessionStatusActive,
		SessionType:       req.SessionType,
		IPAddress:         net.ParseIP(req.IPAddress),
		UserAgent:         req.UserAgent,
		DeviceFingerprint: req.DeviceFingerprint,
		Location:          s.getLocationFromIP(req.IPAddress),
		MFAVerified:       req.MFAVerified,
		SecurityClearance: user.SecurityClearance,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		LastActivityAt:    time.Now(),
		ExpiresAt:         time.Now().Add(s.config.DefaultTimeout),
		RefreshExpiresAt:  time.Now().Add(s.config.RefreshTokenTTL),
		SessionData:       make(map[string]interface{}),
	}

	// Set timeout based on session type and user role
	timeout := s.calculateSessionTimeout(user, req.SessionType)
	session.ExpiresAt = time.Now().Add(timeout)

	// Step 3: Generate session tokens
	sessionToken, err := s.generateSessionToken()
	if err != nil {
		return nil, nil, fmt.Errorf("session token generation failed: %w", err)
	}
	session.SessionToken = sessionToken

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, nil, fmt.Errorf("refresh token generation failed: %w", err)
	}
	session.RefreshToken = refreshToken

	// Step 4: Generate JWT tokens
	accessToken, err := s.generateAccessToken(user, session)
	if err != nil {
		return nil, nil, fmt.Errorf("access token generation failed: %w", err)
	}

	refreshJWT, err := s.generateRefreshJWT(user, session)
	if err != nil {
		return nil, nil, fmt.Errorf("refresh JWT generation failed: %w", err)
	}

	// Step 5: Store session in database
	err = s.sessionRepo.Create(ctx, session)
	if err != nil {
		return nil, nil, fmt.Errorf("session storage failed: %w", err)
	}

	// Step 6: Log session creation
	s.logSessionEvent(ctx, session, "SESSION_CREATED", map[string]interface{}{
		"session_type": req.SessionType,
		"ip_address":   req.IPAddress,
		"user_agent":   req.UserAgent,
		"mfa_verified": req.MFAVerified,
	})

	tokens := &SessionTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshJWT,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenTTL.Seconds()),
	}

	return session, tokens, nil
}

// ValidateSession validates a session token and returns session info
func (s *SessionServiceImpl) ValidateSession(ctx context.Context, sessionToken string) (*entity.Session, error) {
	// Step 1: Get session from database
	session, err := s.sessionRepo.GetByToken(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("session lookup failed: %w", err)
	}

	if session == nil {
		return nil, fmt.Errorf("session not found")
	}

	// Step 2: Check session status
	if session.Status != entity.SessionStatusActive {
		return nil, fmt.Errorf("session is not active")
	}

	// Step 3: Check expiration
	if session.IsExpired() {
		s.terminateSession(ctx, session, "SESSION_EXPIRED")
		return nil, fmt.Errorf("session expired")
	}

	// Step 4: Check inactivity timeout
	if s.config.InactivityTimeout > 0 {
		if time.Since(session.LastActivityAt) > s.config.InactivityTimeout {
			s.terminateSession(ctx, session, "SESSION_INACTIVE")
			return nil, fmt.Errorf("session inactive")
		}
	}

	// Step 5: Update last activity
	session.UpdateLastActivity()
	err = s.sessionRepo.Update(ctx, session)
	if err != nil {
		// Log error but don't fail validation
		s.logSessionEvent(ctx, session, "SESSION_UPDATE_FAILED", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return session, nil
}

// ValidateJWT validates a JWT access token
func (s *SessionServiceImpl) ValidateJWT(ctx context.Context, tokenString string) (*SessionClaims, error) {
	// Parse and validate JWT
	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	// Additional validation
	if claims.TokenType != "access" {
		return nil, fmt.Errorf("invalid token type")
	}

	if claims.Issuer != s.config.TokenIssuer {
		return nil, fmt.Errorf("invalid token issuer")
	}

	// Validate session is still active (optional - depends on architecture)
	session, err := s.sessionRepo.GetByToken(ctx, claims.SessionID.String())
	if err == nil && session != nil && session.Status != entity.SessionStatusActive {
		return nil, fmt.Errorf("session is no longer active")
	}

	return claims, nil
}

// RefreshSession creates new tokens for an existing session
func (s *SessionServiceImpl) RefreshSession(ctx context.Context, refreshToken string) (*SessionTokens, error) {
	// Step 1: Validate refresh token
	claims, err := s.validateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token validation failed: %w", err)
	}

	// Step 2: Get session
	session, err := s.sessionRepo.GetByToken(ctx, claims.SessionID.String())
	if err != nil {
		return nil, fmt.Errorf("session lookup failed: %w", err)
	}

	if session == nil || session.Status != entity.SessionStatusActive {
		return nil, fmt.Errorf("session is not active")
	}

	// Step 3: Check refresh token expiration
	if session.RefreshExpiresAt.Before(time.Now()) {
		s.terminateSession(ctx, session, "REFRESH_TOKEN_EXPIRED")
		return nil, fmt.Errorf("refresh token expired")
	}

	// Step 4: Get updated user info
	user, err := s.userRepo.GetByID(ctx, session.UserID, session.TenantID)
	if err != nil {
		return nil, fmt.Errorf("user lookup failed: %w", err)
	}

	if !user.IsActive() {
		s.terminateSession(ctx, session, "USER_INACTIVE")
		return nil, fmt.Errorf("user is not active")
	}

	// Step 5: Generate new tokens
	newAccessToken, err := s.generateAccessToken(user, session)
	if err != nil {
		return nil, fmt.Errorf("access token generation failed: %w", err)
	}

	newRefreshToken, err := s.generateRefreshJWT(user, session)
	if err != nil {
		return nil, fmt.Errorf("refresh token generation failed: %w", err)
	}

	// Step 6: Update session
	session.RefreshExpiresAt = time.Now().Add(s.config.RefreshTokenTTL)
	session.UpdateLastActivity()

	err = s.sessionRepo.Update(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("session update failed: %w", err)
	}

	// Step 7: Log token refresh
	s.logSessionEvent(ctx, session, "TOKEN_REFRESHED", map[string]interface{}{
		"old_refresh_expires": claims.ExpiresAt.Time,
		"new_refresh_expires": session.RefreshExpiresAt,
	})

	tokens := &SessionTokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenTTL.Seconds()),
	}

	return tokens, nil
}

// TerminateSession terminates a specific session
func (s *SessionServiceImpl) TerminateSession(ctx context.Context, sessionID uuid.UUID) error {
	session, err := s.sessionRepo.GetByToken(ctx, sessionID.String())
	if err != nil {
		return fmt.Errorf("session lookup failed: %w", err)
	}

	if session == nil {
		return fmt.Errorf("session not found")
	}

	return s.terminateSession(ctx, session, "USER_LOGOUT")
}

// TerminateAllSessions terminates all sessions for a user
func (s *SessionServiceImpl) TerminateAllSessions(ctx context.Context, userID, tenantID uuid.UUID) error {
	sessions, err := s.sessionRepo.GetByUserID(ctx, userID, tenantID)
	if err != nil {
		return fmt.Errorf("session lookup failed: %w", err)
	}

	for _, session := range sessions {
		if session.Status == entity.SessionStatusActive {
			s.terminateSession(ctx, &session, "LOGOUT_ALL")
		}
	}

	return nil
}

// Helper methods

func (s *SessionServiceImpl) validateSessionLimits(ctx context.Context, user *entity.User, req *CreateSessionRequest) error {
	// Check concurrent session limit
	if s.config.MaxConcurrentSessions > 0 {
		sessions, err := s.sessionRepo.GetByUserID(ctx, user.ID, user.TenantID)
		if err != nil {
			return fmt.Errorf("session count check failed: %w", err)
		}

		activeSessions := 0
		for _, session := range sessions {
			if session.Status == entity.SessionStatusActive && !session.IsExpired() {
				activeSessions++
			}
		}

		if activeSessions >= s.config.MaxConcurrentSessions {
			return fmt.Errorf("maximum concurrent sessions reached")
		}
	}

	// Check IP-based session limit
	if s.config.MaxSessionsPerIP > 0 {
		// Implementation would count sessions by IP
		// This is a placeholder
	}

	return nil
}

func (s *SessionServiceImpl) calculateSessionTimeout(user *entity.User, sessionType entity.SessionType) time.Duration {
	// Base timeout
	timeout := s.config.DefaultTimeout

	// Adjust based on session type
	switch sessionType {
	case entity.SessionTypeAPI:
		timeout = s.config.AccessTokenTTL
	case entity.SessionTypeMobile:
		timeout = s.config.ExtendableTimeout
	case entity.SessionTypeDesktop:
		timeout = s.config.DefaultTimeout
	}

	// Adjust based on user security clearance
	switch user.SecurityClearance {
	case entity.SecurityClearanceTopSecret:
		timeout = min(timeout, 1*time.Hour)
	case entity.SecurityClearanceSecret:
		timeout = min(timeout, 2*time.Hour)
	case entity.SecurityClearanceConfidential:
		timeout = min(timeout, 4*time.Hour)
	}

	// Ensure it doesn't exceed maximum
	return min(timeout, s.config.MaxTimeout)
}

func (s *SessionServiceImpl) generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *SessionServiceImpl) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *SessionServiceImpl) generateAccessToken(user *entity.User, session *entity.Session) (string, error) {
	claims := &SessionClaims{
		UserID:            user.ID,
		TenantID:          user.TenantID,
		SessionID:         session.ID,
		Username:          user.Username,
		SecurityClearance: user.SecurityClearance,
		MFAVerified:       session.MFAVerified,
		TokenType:         "access",
		IPAddress:         session.IPAddress.String(),
		UserAgent:         session.UserAgent,
		DeviceFingerprint: session.DeviceFingerprint,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.TokenIssuer,
			Audience:  jwt.ClaimStrings{s.config.TokenAudience},
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *SessionServiceImpl) generateRefreshJWT(user *entity.User, session *entity.Session) (string, error) {
	claims := &SessionClaims{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		SessionID: session.ID,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.TokenIssuer,
			Audience:  jwt.ClaimStrings{s.config.TokenAudience},
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(session.RefreshExpiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *SessionServiceImpl) validateRefreshToken(tokenString string) (*SessionClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("invalid token type")
	}

	return claims, nil
}

func (s *SessionServiceImpl) terminateSession(ctx context.Context, session *entity.Session, reason string) error {
	session.Status = entity.SessionStatusRevoked
	session.UpdatedAt = time.Now()

	err := s.sessionRepo.Update(ctx, session)
	if err != nil {
		return fmt.Errorf("session termination failed: %w", err)
	}

	s.logSessionEvent(ctx, session, "SESSION_TERMINATED", map[string]interface{}{
		"reason": reason,
	})

	return nil
}

func (s *SessionServiceImpl) getLocationFromIP(ipAddress string) string {
	// Implementation would use IP geolocation service
	return "Unknown"
}

func (s *SessionServiceImpl) logSessionEvent(ctx context.Context, session *entity.Session, eventType string, metadata map[string]interface{}) {
	// Implementation for session event logging
}

// CreateSessionRequest represents a session creation request
type CreateSessionRequest struct {
	SessionType       entity.SessionType
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	MFAVerified       bool
	Location          string
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
