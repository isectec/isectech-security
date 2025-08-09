package http

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
	"isectech/auth-service/usecase"
)

// AuthHandlers contains all authentication-related HTTP handlers
type AuthHandlers struct {
	authService     *usecase.AuthenticationServiceImpl
	passwordService *usecase.PasswordServiceImpl
	sessionService  *usecase.SessionServiceImpl
	mfaService      service.MFAService
	serviceManager  *usecase.ServiceManager
}

// NewAuthHandlers creates a new authentication handlers instance
func NewAuthHandlers(serviceManager *usecase.ServiceManager) *AuthHandlers {
	return &AuthHandlers{
		authService:     serviceManager.GetAuthService(),
		passwordService: serviceManager.GetPasswordService(),
		sessionService:  serviceManager.GetSessionService(),
		mfaService:      serviceManager.GetMFAService(),
		serviceManager:  serviceManager,
	}
}

// Login handles user authentication
func (h *AuthHandlers) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
			Details: map[string]interface{}{
				"validation_error": err.Error(),
			},
		})
		return
	}

	// Set client information
	req.IPAddress = GetClientIP(c)
	req.UserAgent = GetUserAgent(c)

	// Convert to service request
	loginReq := &service.LoginRequest{
		Username:    req.Username,
		Password:    req.Password,
		TenantID:    req.TenantID,
		SessionType: req.SessionType,
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
	}

	// Perform authentication
	loginResp, err := h.authService.Login(c.Request.Context(), loginReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "authentication_error",
			Message: "Authentication failed",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		})
		return
	}

	// Convert response
	response := &LoginResponse{
		Success: loginResp.Success,
	}

	if loginResp.Success {
		response.UserID = loginResp.UserID
		response.AccessToken = loginResp.AccessToken
		response.RefreshToken = loginResp.RefreshToken
		response.TokenType = loginResp.TokenType
		response.ExpiresIn = loginResp.ExpiresIn
		response.SessionID = loginResp.SessionID
		response.RequiresMFA = loginResp.RequiresMFA
		response.PasswordExpired = loginResp.PasswordExpired
		response.MustChangePassword = loginResp.MustChangePassword

		if loginResp.User != nil {
			response.Username = loginResp.User.Username
			response.SecurityClearance = loginResp.User.SecurityClearance
		}

		if loginResp.MFAChallenge != nil {
			response.MFAChallenge = &MFAChallengeResponse{
				ChallengeID:  loginResp.MFAChallenge.ChallengeID,
				DeviceType:   loginResp.MFAChallenge.DeviceType,
				DeviceName:   loginResp.MFAChallenge.DeviceName,
				QRCode:       loginResp.MFAChallenge.QRCode,
				BackupCodes:  loginResp.MFAChallenge.BackupCodes,
				ExpiresAt:    loginResp.MFAChallenge.ExpiresAt,
				Instructions: loginResp.MFAChallenge.Instructions,
			}
		}
	} else {
		response.FailureReason = loginResp.FailureReason
		response.RetryAfter = loginResp.RetryAfter
	}

	statusCode := http.StatusOK
	if !loginResp.Success {
		if loginResp.FailureReason == "Too many failed attempts" || loginResp.RetryAfter != nil {
			statusCode = http.StatusTooManyRequests
		} else {
			statusCode = http.StatusUnauthorized
		}
	}

	c.JSON(statusCode, response)
}

// VerifyMFA handles MFA code verification
func (h *AuthHandlers) VerifyMFA(c *gin.Context) {
	var req MFAVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
			Details: map[string]interface{}{
				"validation_error": err.Error(),
			},
		})
		return
	}

	// Set client information
	req.IPAddress = GetClientIP(c)
	req.UserAgent = GetUserAgent(c)

	// Convert to service request
	verifyReq := &service.MFAVerificationRequest{
		UserID:      req.UserID,
		TenantID:    req.TenantID,
		ChallengeID: req.ChallengeID,
		Code:        req.Code,
		DeviceID:    req.DeviceID,
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
	}

	// Verify MFA
	verifyResp, err := h.mfaService.VerifyMFACode(c.Request.Context(), verifyReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "verification_error",
			Message: "MFA verification failed",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		})
		return
	}

	// Return verification result
	statusCode := http.StatusOK
	if !verifyResp.Success {
		statusCode = http.StatusUnauthorized
	}

	c.JSON(statusCode, gin.H{
		"success":        verifyResp.Success,
		"access_token":   verifyResp.AccessToken,
		"refresh_token":  verifyResp.RefreshToken,
		"token_type":     verifyResp.TokenType,
		"expires_in":     verifyResp.ExpiresIn,
		"failure_reason": verifyResp.FailureReason,
	})
}

// Logout handles user logout
func (h *AuthHandlers) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	// Convert to service request
	logoutReq := &service.LogoutRequest{
		SessionToken: req.SessionToken,
		UserID:       req.UserID,
		TenantID:     req.TenantID,
	}

	var err error
	if req.LogoutAll {
		err = h.authService.LogoutAll(c.Request.Context(), req.UserID, req.TenantID)
	} else {
		err = h.authService.Logout(c.Request.Context(), logoutReq)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "logout_error",
			Message: "Logout failed",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Logged out successfully",
	})
}

// RefreshToken handles token refresh
func (h *AuthHandlers) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	// Refresh session tokens
	tokens, err := h.sessionService.RefreshSession(c.Request.Context(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "refresh_failed",
			Message: "Token refresh failed",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		})
		return
	}

	response := &TokenRefreshResponse{
		Success:      true,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	}

	c.JSON(http.StatusOK, response)
}

// ValidateSession handles session validation
func (h *AuthHandlers) ValidateSession(c *gin.Context) {
	var req SessionValidationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	req.IPAddress = GetClientIP(c)

	// Convert to service request
	validationReq := &service.SessionValidationRequest{
		AccessToken:       req.AccessToken,
		RequiredClearance: req.RequiredClearance,
		IPAddress:         req.IPAddress,
	}

	// Validate session
	validationResp, err := h.authService.ValidateSession(c.Request.Context(), validationReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "validation_error",
			Message: "Session validation failed",
		})
		return
	}

	response := &SessionValidationResponse{
		Valid:             validationResp.Valid,
		UserID:            validationResp.UserID,
		TenantID:          validationResp.TenantID,
		SessionID:         validationResp.SessionID,
		SecurityClearance: validationResp.SecurityClearance,
		ExpiresIn:         validationResp.ExpiresIn,
		RequiresMFA:       validationResp.RequiresMFA,
		FailureReason:     validationResp.FailureReason,
	}

	if validationResp.User != nil {
		response.Username = validationResp.User.Username
	}

	statusCode := http.StatusOK
	if !validationResp.Valid {
		statusCode = http.StatusUnauthorized
	}

	c.JSON(statusCode, response)
}

// ChangePassword handles password change
func (h *AuthHandlers) ChangePassword(c *gin.Context) {
	var req PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	// Convert to service request
	changeReq := &service.PasswordChangeRequest{
		UserID:          req.UserID,
		TenantID:        req.TenantID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}

	// Change password
	err := h.passwordService.ChangePassword(c.Request.Context(), changeReq)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "password_change_failed",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Password changed successfully",
	})
}

// RequestPasswordReset handles password reset request
func (h *AuthHandlers) RequestPasswordReset(c *gin.Context) {
	var req PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	// Request password reset
	err := h.passwordService.ResetPassword(c.Request.Context(), req.Email, req.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "reset_request_failed",
			Message: "Password reset request failed",
		})
		return
	}

	// Always return success to prevent email enumeration
	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "If the email exists, a password reset link has been sent",
	})
}

// CompletePasswordReset handles password reset completion
func (h *AuthHandlers) CompletePasswordReset(c *gin.Context) {
	var req PasswordResetCompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	// Complete password reset
	err := h.passwordService.CompletePasswordReset(c.Request.Context(), req.Token, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "reset_completion_failed",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Password reset completed successfully",
	})
}

// ValidatePasswordStrength validates password strength
func (h *AuthHandlers) ValidatePasswordStrength(c *gin.Context) {
	type PasswordValidationRequest struct {
		Password string    `json:"password" binding:"required"`
		UserID   uuid.UUID `json:"user_id,omitempty"`
		TenantID uuid.UUID `json:"tenant_id,omitempty"`
	}

	var req PasswordValidationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	// Get user if provided for context
	var user *entity.User
	if req.UserID != uuid.Nil && req.TenantID != uuid.Nil {
		userRepo := h.serviceManager.GetRepositoryManager().GetUserRepository()
		var err error
		user, err = userRepo.GetByID(c.Request.Context(), req.UserID, req.TenantID)
		if err != nil {
			// Continue without user context
			user = nil
		}
	}

	// Validate password strength
	validation := h.passwordService.ValidatePasswordStrength(c.Request.Context(), req.Password, user)

	// Convert strength score to string
	strengthLevels := []string{"Weak", "Fair", "Good", "Strong", "Very Strong"}
	strengthIndex := validation.Score / 20
	if strengthIndex >= len(strengthLevels) {
		strengthIndex = len(strengthLevels) - 1
	}

	response := &PasswordStrengthResponse{
		Valid:       validation.Valid,
		Score:       validation.Score,
		Strength:    strengthLevels[strengthIndex],
		Violations:  validation.Violations,
		Suggestions: validation.Suggestions,
	}

	c.JSON(http.StatusOK, response)
}

// EnrollMFADevice handles MFA device enrollment
func (h *AuthHandlers) EnrollMFADevice(c *gin.Context) {
	var req MFAEnrollmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request format",
		})
		return
	}

	// Convert to service request
	enrollReq := &service.MFAEnrollmentRequest{
		UserID:     req.UserID,
		TenantID:   req.TenantID,
		DeviceType: req.DeviceType,
		DeviceName: req.DeviceName,
		Metadata:   req.Metadata,
		IPAddress:  GetClientIP(c),
		UserAgent:  GetUserAgent(c),
	}

	// Enroll device
	enrollResp, err := h.mfaService.EnrollMFADevice(c.Request.Context(), enrollReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "enrollment_failed",
			Message: "MFA device enrollment failed",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		})
		return
	}

	response := &MFAEnrollmentResponse{
		Success:       enrollResp.Success,
		DeviceID:      enrollResp.DeviceID,
		DeviceType:    enrollResp.DeviceType,
		QRCode:        enrollResp.QRCode,
		Secret:        enrollResp.Secret,
		BackupCodes:   enrollResp.BackupCodes,
		Instructions:  enrollResp.Instructions,
		FailureReason: enrollResp.FailureReason,
	}

	statusCode := http.StatusOK
	if !enrollResp.Success {
		statusCode = http.StatusBadRequest
	}

	c.JSON(statusCode, response)
}

// GetUserMFADevices returns user's MFA devices
func (h *AuthHandlers) GetUserMFADevices(c *gin.Context) {
	userID, exists := GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "User ID not found in context",
		})
		return
	}

	tenantID, exists := GetTenantID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Tenant ID not found in context",
		})
		return
	}

	// Get user's MFA devices
	deviceRepo := h.serviceManager.GetRepositoryManager().GetMFADeviceRepository()
	devices, err := deviceRepo.GetByUserID(c.Request.Context(), userID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "query_failed",
			Message: "Failed to retrieve MFA devices",
		})
		return
	}

	// Convert to response format
	deviceResponses := make([]*MFADeviceResponse, len(devices))
	for i, device := range devices {
		deviceResponses[i] = ToMFADeviceResponse(&device)
	}

	c.JSON(http.StatusOK, gin.H{
		"devices": deviceResponses,
		"count":   len(deviceResponses),
	})
}

// GetUserSessions returns user's active sessions
func (h *AuthHandlers) GetUserSessions(c *gin.Context) {
	userID, exists := GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "User ID not found in context",
		})
		return
	}

	tenantID, exists := GetTenantID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Tenant ID not found in context",
		})
		return
	}

	// Get session repository
	sessionRepo := usecase.NewDatabaseSessionRepository(h.serviceManager.GetRepositoryManager().GetDB())
	sessions, err := sessionRepo.GetByUserID(c.Request.Context(), userID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "query_failed",
			Message: "Failed to retrieve sessions",
		})
		return
	}

	// Convert to response format
	sessionResponses := make([]*SessionResponse, len(sessions))
	for i, session := range sessions {
		sessionResponses[i] = ToSessionResponse(&session)
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessionResponses,
		"count":    len(sessionResponses),
	})
}

// TerminateSession terminates a specific session
func (h *AuthHandlers) TerminateSession(c *gin.Context) {
	sessionIDParam := c.Param("session_id")
	sessionID, err := uuid.Parse(sessionIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_session_id",
			Message: "Invalid session ID format",
		})
		return
	}

	err = h.sessionService.TerminateSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "termination_failed",
			Message: "Session termination failed",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Success: true,
		Message: "Session terminated successfully",
	})
}

// GetUserProfile returns user profile information
func (h *AuthHandlers) GetUserProfile(c *gin.Context) {
	userID, exists := GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "User ID not found in context",
		})
		return
	}

	tenantID, exists := GetTenantID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:   "unauthorized",
			Message: "Tenant ID not found in context",
		})
		return
	}

	userRepo := h.serviceManager.GetRepositoryManager().GetUserRepository()
	user, err := userRepo.GetByID(c.Request.Context(), userID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "query_failed",
			Message: "Failed to retrieve user profile",
		})
		return
	}

	response := ToUserResponse(user)
	c.JSON(http.StatusOK, response)
}

// HealthCheck returns service health status
func (h *AuthHandlers) HealthCheck(c *gin.Context) {
	health := h.serviceManager.HealthCheck(c.Request.Context())

	// Determine overall status
	status := "healthy"
	if dbHealth, ok := health["database"].(map[string]interface{}); ok {
		if healthy, ok := dbHealth["healthy"].(bool); ok && !healthy {
			status = "unhealthy"
		}
	}

	response := &HealthResponse{
		Status:     status,
		Version:    "1.0.0", // Would come from build info
		Timestamp:  time.Now(),
		Components: health,
	}

	statusCode := http.StatusOK
	if status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, response)
}

// GetMetrics returns service metrics
func (h *AuthHandlers) GetMetrics(c *gin.Context) {
	metrics, err := h.serviceManager.GetMetrics(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "metrics_failed",
			Message: "Failed to retrieve metrics",
		})
		return
	}

	c.JSON(http.StatusOK, metrics)
}