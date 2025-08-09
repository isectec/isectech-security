package http

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// SSOHandlers contains all SSO-related HTTP handlers
type SSOHandlers struct {
	ssoService  service.SSOService
	samlService service.SAMLService
	oidcService service.OIDCService
}

// NewSSOHandlers creates a new SSO handlers instance
func NewSSOHandlers(
	ssoService service.SSOService,
	samlService service.SAMLService,
	oidcService service.OIDCService,
) *SSOHandlers {
	return &SSOHandlers{
		ssoService:  ssoService,
		samlService: samlService,
		oidcService: oidcService,
	}
}

// Provider Management Handlers

// CreateProvider creates a new identity provider
func (h *SSOHandlers) CreateProvider(c *gin.Context) {
	var req CreateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed", "details": err.Error()})
		return
	}

	// Get tenant and user from context
	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Create service request
	serviceReq := &service.CreateProviderRequest{
		TenantID:         tenantUUID,
		Name:             req.Name,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		Type:             req.Type,
		Configuration:    req.Configuration,
		AttributeMapping: req.AttributeMapping,
		EnableJIT:        req.EnableJIT,
		IsDefault:        req.IsDefault,
		CreatedBy:        userUUID,
	}

	// Create provider
	response, err := h.ssoService.CreateProvider(c.Request.Context(), serviceReq)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "maximum number") {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create provider", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// GetProvider retrieves a specific identity provider
func (h *SSOHandlers) GetProvider(c *gin.Context) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	provider, err := h.ssoService.GetProvider(c.Request.Context(), providerID, tenantUUID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provider", "details": err.Error()})
		return
	}

	response := h.convertProviderToResponse(provider)
	c.JSON(http.StatusOK, response)
}

// ListProviders retrieves all identity providers for a tenant
func (h *SSOHandlers) ListProviders(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Parse query parameters
	activeOnly := c.Query("active_only") == "true"

	providers, err := h.ssoService.ListProviders(c.Request.Context(), tenantUUID, activeOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list providers", "details": err.Error()})
		return
	}

	// Convert to response format
	responses := make([]ProviderResponse, len(providers))
	for i, provider := range providers {
		responses[i] = h.convertProviderToResponse(provider)
	}

	c.JSON(http.StatusOK, ProvidersListResponse{
		Providers: responses,
		Total:     len(responses),
	})
}

// UpdateProvider updates an existing identity provider
func (h *SSOHandlers) UpdateProvider(c *gin.Context) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	var req UpdateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	tenantID := c.GetString("tenant_id")
	userID := c.GetString("user_id")

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Create service request
	serviceReq := &service.UpdateProviderRequest{
		ProviderID:       providerID,
		TenantID:         tenantUUID,
		Name:             req.Name,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		Configuration:    req.Configuration,
		AttributeMapping: req.AttributeMapping,
		Status:           req.Status,
		EnableJIT:        req.EnableJIT,
		IsDefault:        req.IsDefault,
		UpdatedBy:        userUUID,
	}

	// Update provider
	err = h.ssoService.UpdateProvider(c.Request.Context(), serviceReq)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update provider", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider updated successfully"})
}

// DeleteProvider deletes an identity provider
func (h *SSOHandlers) DeleteProvider(c *gin.Context) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	err = h.ssoService.DeleteProvider(c.Request.Context(), providerID, tenantUUID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete provider", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider deleted successfully"})
}

// TestProvider tests an identity provider configuration
func (h *SSOHandlers) TestProvider(c *gin.Context) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	result, err := h.ssoService.TestProvider(c.Request.Context(), providerID, tenantUUID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to test provider", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Authentication Flow Handlers

// InitiateLogin initiates SSO login flow
func (h *SSOHandlers) InitiateLogin(c *gin.Context) {
	var req InitiateLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Get client information
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Create service request
	serviceReq := &service.InitiateLoginRequest{
		ProviderID: req.ProviderID,
		TenantID:   tenantUUID,
		RelayState: req.RelayState,
		ForceAuthn: req.ForceAuthn,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	response, err := h.ssoService.InitiateLogin(c.Request.Context(), serviceReq)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not available") {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate login", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, InitiateLoginResponse{
		RedirectURL:   response.RedirectURL,
		RequestID:     response.RequestID,
		State:         response.State,
		CodeChallenge: response.CodeChallenge,
		ExpiresAt:     response.ExpiresAt,
	})
}

// HandleCallback handles SSO callback
func (h *SSOHandlers) HandleCallback(c *gin.Context) {
	var req SSOCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Get client information
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Prepare callback data
	callbackData := make(map[string]interface{})
	if req.SAMLResponse != "" {
		callbackData["saml_response"] = req.SAMLResponse
		callbackData["relay_state"] = req.RelayState
	}
	if req.Code != "" {
		callbackData["code"] = req.Code
		callbackData["state"] = req.State
		callbackData["code_verifier"] = req.CodeVerifier
	}
	// Merge additional callback data
	for k, v := range req.CallbackData {
		callbackData[k] = v
	}

	// Create service request
	serviceReq := &service.CallbackRequest{
		ProviderID:   req.ProviderID,
		TenantID:     tenantUUID,
		CallbackData: callbackData,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}

	response, err := h.ssoService.HandleCallback(c.Request.Context(), serviceReq)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Callback failed", "details": err.Error()})
		return
	}

	if !response.Success {
		c.JSON(http.StatusUnauthorized, SSOCallbackResponse{
			Success:          false,
			ErrorCode:        response.ErrorCode,
			ErrorDescription: response.ErrorDescription,
		})
		return
	}

	// Convert user and federated user to response format
	var userResponse *UserProfileResponse
	var federatedUserResponse *FederatedUserResponse

	if response.User != nil {
		userResponse = &UserProfileResponse{
			ID:                response.User.ID,
			Email:             response.User.Email,
			FirstName:         response.User.FirstName,
			LastName:          response.User.LastName,
			SecurityClearance: response.User.SecurityClearance,
			Roles:             []string{}, // TODO: Get user roles
			IsActive:          response.User.IsActive,
		}
	}

	if response.FederatedUser != nil {
		federatedUserResponse = &FederatedUserResponse{
			ID:               response.FederatedUser.ID,
			ExternalID:       response.FederatedUser.ExternalID,
			ExternalUsername: response.FederatedUser.ExternalUsername,
			ExternalEmail:    response.FederatedUser.ExternalEmail,
			ProviderID:       response.FederatedUser.ProviderID,
			MappedRoles:      response.FederatedUser.MappedRoles,
			MappedClearance:  response.FederatedUser.MappedClearance,
			LastLoginAt:      response.FederatedUser.LastLoginAt,
			LoginCount:       response.FederatedUser.LoginCount,
		}
	}

	c.JSON(http.StatusOK, SSOCallbackResponse{
		Success:       true,
		UserID:        response.UserID,
		SessionID:     response.SessionID,
		AccessToken:   response.AccessToken,
		RefreshToken:  response.RefreshToken,
		ExpiresIn:     response.ExpiresIn,
		User:          userResponse,
		FederatedUser: federatedUserResponse,
		IsNewUser:     response.IsNewUser,
		RequiresMFA:   response.RequiresMFA,
	})
}

// Session Management Handlers

// ValidateSession validates an SSO session
func (h *SSOHandlers) ValidateSession(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID is required"})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	response, err := h.ssoService.ValidateSSOSession(c.Request.Context(), sessionID, tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate session", "details": err.Error()})
		return
	}

	var sessionResponse *SSOSessionResponse
	var userResponse *UserProfileResponse

	if response.Session != nil {
		sessionResponse = &SSOSessionResponse{
			ID:                response.Session.ID,
			SessionID:         response.Session.SessionID,
			UserID:            response.Session.UserID,
			ProviderID:        response.Session.ProviderID,
			ExternalSessionID: response.Session.ExternalSessionID,
			LoginMethod:       response.Session.LoginMethod,
			IPAddress:         response.Session.IPAddress,
			UserAgent:         response.Session.UserAgent,
			Location:          response.Session.Location,
			IsActive:          response.Session.IsActive,
			ExpiresAt:         response.Session.ExpiresAt,
			LastActivityAt:    response.Session.LastActivityAt,
			CreatedAt:         response.Session.CreatedAt,
		}
	}

	if response.User != nil {
		userResponse = &UserProfileResponse{
			ID:                response.User.ID,
			Email:             response.User.Email,
			FirstName:         response.User.FirstName,
			LastName:          response.User.LastName,
			SecurityClearance: response.User.SecurityClearance,
			Roles:             []string{}, // TODO: Get user roles
			IsActive:          response.User.IsActive,
		}
	}

	c.JSON(http.StatusOK, SSOSessionValidationResponse{
		Valid:             response.Valid,
		Session:           sessionResponse,
		User:              userResponse,
		SecurityClearance: response.SecurityClearance,
		ErrorReason:       response.ErrorReason,
	})
}

// GetUserSessions retrieves SSO sessions for a user
func (h *SSOHandlers) GetUserSessions(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	sessions, err := h.ssoService.ListUserSSOSessions(c.Request.Context(), userID, tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user sessions", "details": err.Error()})
		return
	}

	responses := make([]SSOSessionResponse, len(sessions))
	for i, session := range sessions {
		responses[i] = SSOSessionResponse{
			ID:                session.ID,
			SessionID:         session.SessionID,
			UserID:            session.UserID,
			ProviderID:        session.ProviderID,
			ExternalSessionID: session.ExternalSessionID,
			LoginMethod:       session.LoginMethod,
			IPAddress:         session.IPAddress,
			UserAgent:         session.UserAgent,
			Location:          session.Location,
			IsActive:          session.IsActive,
			ExpiresAt:         session.ExpiresAt,
			LastActivityAt:    session.LastActivityAt,
			CreatedAt:         session.CreatedAt,
		}
	}

	c.JSON(http.StatusOK, SSOSessionsListResponse{
		Sessions: responses,
		Total:    len(responses),
	})
}

// TerminateSession terminates an SSO session
func (h *SSOHandlers) TerminateSession(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID is required"})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	err = h.ssoService.TerminateSSOSession(c.Request.Context(), sessionID, tenantUUID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate session", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session terminated successfully"})
}

// SAML-specific Handlers

// GetSAMLMetadata returns SAML service provider metadata
func (h *SSOHandlers) GetSAMLMetadata(c *gin.Context) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider ID"})
		return
	}

	tenantID := c.GetString("tenant_id")
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	metadata, err := h.ssoService.GetSAMLMetadata(c.Request.Context(), providerID, tenantUUID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get SAML metadata", "details": err.Error()})
		return
	}

	// Return XML metadata with proper content type
	c.Header("Content-Type", "application/samlmetadata+xml")
	c.String(http.StatusOK, metadata)
}

// Helper functions

func (h *SSOHandlers) convertProviderToResponse(provider *entity.IdentityProvider) ProviderResponse {
	return ProviderResponse{
		ID:               provider.ID,
		Name:             provider.Name,
		DisplayName:      provider.DisplayName,
		Description:      provider.Description,
		Type:             provider.Type,
		Status:           provider.Status,
		LoginURL:         provider.LoginURL,
		CallbackURL:      provider.CallbackURL,
		MetadataURL:      provider.MetadataURL,
		IsDefault:        provider.IsDefault,
		Priority:         provider.Priority,
		EnableJIT:        provider.EnableJIT,
		AttributeMapping: provider.AttributeMapping,
		SessionTimeout:   provider.SessionTimeout,
		LastUsedAt:       provider.LastUsedAt,
		UsageCount:       provider.UsageCount,
		ErrorCount:       provider.ErrorCount,
		CreatedAt:        provider.CreatedAt,
		UpdatedAt:        provider.UpdatedAt,
	}
}

func (h *SSOHandlers) getIntQueryParam(c *gin.Context, param string, defaultValue int) int {
	if value := c.Query(param); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
