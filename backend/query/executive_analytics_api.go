package query

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ExecutiveAnalyticsAPI provides secure endpoints for executive dashboard data
type ExecutiveAnalyticsAPI struct {
	logger               *zap.Logger
	integration          *ExecutiveAnalyticsIntegration
	securityControls     *ExecutiveSecurityControls
	config               *ExecutiveAPIConfig
}

// ExecutiveAPIConfig defines configuration for the executive analytics API
type ExecutiveAPIConfig struct {
	RequireMFA           bool          `yaml:"require_mfa" default:"true"`
	RequireSSO           bool          `yaml:"require_sso" default:"true"`
	RateLimitPerMinute   int           `yaml:"rate_limit_per_minute" default:"60"`
	MaxSessionDuration   time.Duration `yaml:"max_session_duration" default:"8h"`
	RequiredClearance    string        `yaml:"required_clearance" default:"SECRET"`
	EnableAuditLogging   bool          `yaml:"enable_audit_logging" default:"true"`
	EncryptResponses     bool          `yaml:"encrypt_responses" default:"true"`
	EnableCORS           bool          `yaml:"enable_cors" default:"false"`
	TrustedOrigins       []string      `yaml:"trusted_origins"`
}

// API request/response structures
type ExecutiveDashboardRequest struct {
	UserID            UUID                   `json:"user_id"`
	UserRole          string                 `json:"user_role"`
	TenantID          UUID                   `json:"tenant_id"`
	SessionToken      string                 `json:"session_token"`
	RequestedWidgets  []string               `json:"requested_widgets,omitempty"`
	TimeRange         *APITimeRange          `json:"time_range,omitempty"`
	RefreshMode       string                 `json:"refresh_mode,omitempty"` // "real_time", "cached", "force_refresh"
	Format            string                 `json:"format,omitempty"` // "json", "encrypted"
	Context           map[string]interface{} `json:"context,omitempty"`
	IPAddress         string                 `json:"ip_address"`
	UserAgent         string                 `json:"user_agent"`
	DeviceID          string                 `json:"device_id,omitempty"`
	Location          *SessionLocation       `json:"location,omitempty"`
}

type APITimeRange struct {
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Preset   string    `json:"preset,omitempty"` // "1h", "24h", "7d", "30d"
}

type ExecutiveDashboardResponse struct {
	Success           bool                   `json:"success"`
	Data              interface{}            `json:"data,omitempty"`
	EncryptedData     *EncryptedData         `json:"encrypted_data,omitempty"`
	Metadata          *ResponseMetadata      `json:"metadata"`
	SecurityContext   *SecurityContext       `json:"security_context,omitempty"`
	Timestamp         time.Time              `json:"timestamp"`
	RequestID         string                 `json:"request_id"`
	Error             *APIError              `json:"error,omitempty"`
}

type ResponseMetadata struct {
	DataFreshness        time.Duration          `json:"data_freshness"`
	CalculationDuration  time.Duration          `json:"calculation_duration"`
	CacheHit             bool                   `json:"cache_hit"`
	ComplianceFlags      []string               `json:"compliance_flags"`
	SecurityLevel        string                 `json:"security_level"`
	AuditID              string                 `json:"audit_id"`
	NextRefresh          time.Time              `json:"next_refresh"`
	AvailableWidgets     []string               `json:"available_widgets,omitempty"`
}

type SecurityContext struct {
	SessionID           string    `json:"session_id"`
	ThreatScore         float64   `json:"threat_score"`
	AnomalyScore        float64   `json:"anomaly_score"`
	SecurityClearance   string    `json:"security_clearance"`
	AuthenticationLevel string    `json:"authentication_level"`
	DataMaskingApplied  bool      `json:"data_masking_applied"`
	AccessGranted       time.Time `json:"access_granted"`
	AccessExpiresAt     time.Time `json:"access_expires_at"`
}

type APIError struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	RetryAfter  *time.Duration         `json:"retry_after,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// NewExecutiveAnalyticsAPI creates a new secure executive analytics API
func NewExecutiveAnalyticsAPI(
	logger *zap.Logger,
	integration *ExecutiveAnalyticsIntegration,
	securityControls *ExecutiveSecurityControls,
	config *ExecutiveAPIConfig,
) (*ExecutiveAnalyticsAPI, error) {
	
	if config == nil {
		config = &ExecutiveAPIConfig{}
		setExecutiveAPIDefaults(config)
	}
	
	api := &ExecutiveAnalyticsAPI{
		logger:           logger.With(zap.String("component", "executive-analytics-api")),
		integration:      integration,
		securityControls: securityControls,
		config:           config,
	}
	
	logger.Info("Executive analytics API initialized",
		zap.Bool("mfa_required", config.RequireMFA),
		zap.Bool("sso_required", config.RequireSSO),
		zap.String("required_clearance", config.RequiredClearance),
		zap.Bool("encrypt_responses", config.EncryptResponses),
	)
	
	return api, nil
}

// GetExecutiveDashboardData retrieves secure executive dashboard data
func (api *ExecutiveAnalyticsAPI) GetExecutiveDashboardData(ctx context.Context, req *ExecutiveDashboardRequest) (*ExecutiveDashboardResponse, error) {
	start := time.Now()
	requestID, _ := generateSecureSessionID()
	
	// Create response template
	response := &ExecutiveDashboardResponse{
		RequestID: requestID,
		Timestamp: time.Now(),
		Metadata:  &ResponseMetadata{},
	}
	
	// Validate executive access
	accessReq := &ExecutiveAccessRequest{
		AccessRequest: AccessRequest{
			UserID:    req.UserID,
			Resource:  "executive_analytics",
			Action:    "read",
			IPAddress: req.IPAddress,
			UserAgent: req.UserAgent,
			DeviceID:  req.DeviceID,
			Location:  req.Location,
		},
		SecurityClearance:     api.config.RequiredClearance,
		ExecutiveRole:         req.UserRole,
		BusinessJustification: "Executive dashboard access",
		RequestedAt:           time.Now(),
		UrgencyLevel:         "normal",
	}
	
	// Perform comprehensive access validation
	accessDecision, err := api.securityControls.ValidateExecutiveAccess(ctx, accessReq)
	if err != nil {
		api.logger.Error("Executive access validation failed", 
			zap.Error(err),
			zap.String("user_id", req.UserID.String()),
			zap.String("request_id", requestID),
		)
		
		response.Success = false
		response.Error = &APIError{
			Code:      "ACCESS_VALIDATION_FAILED",
			Message:   "Executive access validation failed",
			Timestamp: time.Now(),
		}
		return response, nil
	}
	
	if !accessDecision.Allowed {
		api.logger.Warn("Executive access denied",
			zap.String("user_id", req.UserID.String()),
			zap.String("reason", accessDecision.Reason),
			zap.String("request_id", requestID),
		)
		
		response.Success = false
		response.Error = &APIError{
			Code:      "ACCESS_DENIED",
			Message:   accessDecision.Reason,
			Details: map[string]interface{}{
				"required_actions":         accessDecision.RequiredActions,
				"supervisor_notification":  accessDecision.SupervisorNotification,
				"audit_required":          accessDecision.AuditRequired,
			},
			Timestamp: time.Now(),
		}
		return response, nil
	}
	
	// Validate or create executive session
	session, err := api.validateOrCreateSession(ctx, req, accessDecision)
	if err != nil {
		api.logger.Error("Session validation failed",
			zap.Error(err),
			zap.String("request_id", requestID),
		)
		
		response.Success = false
		response.Error = &APIError{
			Code:      "SESSION_VALIDATION_FAILED",
			Message:   "Failed to validate executive session",
			Timestamp: time.Now(),
		}
		return response, nil
	}
	
	// Get executive KPI snapshot
	kpiSnapshot, err := api.integration.GetExecutiveKPISnapshot(ctx)
	if err != nil {
		api.logger.Error("Failed to get executive KPI snapshot",
			zap.Error(err),
			zap.String("request_id", requestID),
		)
		
		response.Success = false
		response.Error = &APIError{
			Code:      "DATA_RETRIEVAL_FAILED",
			Message:   "Failed to retrieve executive analytics data",
			Timestamp: time.Now(),
		}
		return response, nil
	}
	
	// Apply data masking if required
	if accessDecision.DataMaskingRequired {
		kpiSnapshot = api.applyDataMasking(kpiSnapshot, req.UserRole)
	}
	
	// Prepare response data
	var responseData interface{}
	var encryptedData *EncryptedData
	
	if api.config.EncryptResponses || req.Format == "encrypted" {
		// Encrypt the response data
		encryptedBytes, err := api.securityControls.EncryptExecutiveData(ctx, kpiSnapshot, req.UserID, req.TenantID)
		if err != nil {
			api.logger.Error("Failed to encrypt response data",
				zap.Error(err),
				zap.String("request_id", requestID),
			)
			
			response.Success = false
			response.Error = &APIError{
				Code:      "ENCRYPTION_FAILED",
				Message:   "Failed to encrypt response data",
				Timestamp: time.Now(),
			}
			return response, nil
		}
		
		// Parse encrypted data for response
		err = json.Unmarshal(encryptedBytes, &encryptedData)
		if err != nil {
			api.logger.Error("Failed to parse encrypted data", zap.Error(err))
		}
	} else {
		responseData = kpiSnapshot
	}
	
	// Build security context
	securityContext := &SecurityContext{
		SessionID:           session.ID,
		ThreatScore:         session.ThreatScore,
		AnomalyScore:        session.AnomalyScore,
		SecurityClearance:   session.SecurityClearance,
		AuthenticationLevel: fmt.Sprintf("%d-factor", len(session.AuthMethod)),
		DataMaskingApplied:  accessDecision.DataMaskingRequired,
		AccessGranted:       time.Now(),
		AccessExpiresAt:     session.ExpiresAt,
	}
	
	// Build metadata
	response.Metadata = &ResponseMetadata{
		DataFreshness:       time.Since(kpiSnapshot.Timestamp),
		CalculationDuration: kpiSnapshot.CalculationDuration,
		CacheHit:           false, // Would be determined by caching layer
		ComplianceFlags:    []string{"EXECUTIVE_ACCESS", "CONFIDENTIAL", "AUDIT_LOGGED"},
		SecurityLevel:      api.config.RequiredClearance,
		AuditID:           requestID,
		NextRefresh:       time.Now().Add(15 * time.Second), // Based on refresh interval
		AvailableWidgets:  api.getAvailableWidgets(req.UserRole),
	}
	
	// Set response data
	response.Success = true
	response.Data = responseData
	response.EncryptedData = encryptedData
	response.SecurityContext = securityContext
	
	// Log successful access
	api.logger.Info("Executive dashboard data provided",
		zap.String("user_id", req.UserID.String()),
		zap.String("user_role", req.UserRole),
		zap.String("session_id", session.ID),
		zap.Duration("processing_time", time.Since(start)),
		zap.Bool("data_masked", accessDecision.DataMaskingRequired),
		zap.Bool("encrypted", encryptedData != nil),
		zap.String("request_id", requestID),
	)
	
	return response, nil
}

// GetComplianceReport generates executive compliance reports
func (api *ExecutiveAnalyticsAPI) GetComplianceReport(ctx context.Context, req *ComplianceReportRequest) (*ComplianceReportResponse, error) {
	// Similar structure to GetExecutiveDashboardData but for compliance reports
	// Implementation would follow the same security validation pattern
	return nil, fmt.Errorf("compliance report endpoint not yet implemented")
}

// GetSecurityMetrics provides executive security metrics
func (api *ExecutiveAnalyticsAPI) GetSecurityMetrics(ctx context.Context, req *SecurityMetricsRequest) (*SecurityMetricsResponse, error) {
	// Similar structure with additional security validation for threat data
	return nil, fmt.Errorf("security metrics endpoint not yet implemented")
}

// Private helper methods

func (api *ExecutiveAnalyticsAPI) validateOrCreateSession(ctx context.Context, req *ExecutiveDashboardRequest, accessDecision *ExecutiveAccessDecision) (*ExecutiveSession, error) {
	// If session token provided, validate existing session
	if req.SessionToken != "" {
		session, err := api.securityControls.ValidateExecutiveSession(ctx, req.SessionToken)
		if err == nil {
			return session, nil
		}
		api.logger.Debug("Existing session validation failed", zap.Error(err))
	}
	
	// Create new executive session
	sessionReq := &CreateSessionRequest{
		UserID:            req.UserID.String(),
		UserRole:          req.UserRole,
		TenantID:          req.TenantID.String(),
		AuthMethods:       []string{"sso", "mfa"}, // Would be determined by actual auth
		SecurityClearance: api.config.RequiredClearance,
		IPAddress:         req.IPAddress,
		UserAgent:         req.UserAgent,
		DeviceID:          req.DeviceID,
		Location:          req.Location,
		RequestedDuration: &api.config.MaxSessionDuration,
	}
	
	return api.securityControls.CreateExecutiveSession(ctx, sessionReq)
}

func (api *ExecutiveAnalyticsAPI) applyDataMasking(snapshot *ExecutiveKPISnapshot, userRole string) *ExecutiveKPISnapshot {
	// Create a copy for masking
	masked := *snapshot
	
	// Apply role-based data masking
	switch userRole {
	case "board_member":
		// Board members see high-level metrics only
		masked.BusinessDisruptionEvents = 0 // Mask specific incident counts
		if len(masked.DataFreshness) > 0 {
			// Mask detailed freshness data
			masked.DataFreshness = map[string]time.Duration{
				"overall": masked.DataFreshness["strategic_security_health"],
			}
		}
		
	case "executive_assistant":
		// Executive assistants see summary data
		masked.SecurityPostureScore = 0   // Mask detailed security scores
		masked.RiskExposureIndex = 0      // Mask risk details
		masked.RevenueAtRisk = 0          // Mask financial impact
		
	default:
		// Other roles (CEO, CISO) see full data
		// No masking applied
	}
	
	return &masked
}

func (api *ExecutiveAnalyticsAPI) getAvailableWidgets(userRole string) []string {
	baseWidgets := []string{
		"security_posture",
		"threat_level",
		"compliance_status",
		"security_roi",
	}
	
	// Role-specific widget availability
	switch userRole {
	case "ceo":
		return append(baseWidgets, "business_impact", "financial_metrics", "strategic_overview")
	case "ciso":
		return append(baseWidgets, "threat_details", "incident_management", "security_operations", "vulnerability_management")
	case "board_member":
		return []string{"security_posture", "compliance_status", "strategic_overview"}
	case "executive_assistant":
		return []string{"security_posture", "compliance_status"}
	default:
		return baseWidgets
	}
}

func setExecutiveAPIDefaults(config *ExecutiveAPIConfig) {
	if config.RateLimitPerMinute == 0 {
		config.RateLimitPerMinute = 60
	}
	if config.MaxSessionDuration == 0 {
		config.MaxSessionDuration = 8 * time.Hour
	}
	if config.RequiredClearance == "" {
		config.RequiredClearance = "SECRET"
	}
	if len(config.TrustedOrigins) == 0 {
		config.TrustedOrigins = []string{"https://dashboard.isectech.com"}
	}
}

// HTTP handler wrappers (would be implemented based on web framework)
func (api *ExecutiveAnalyticsAPI) HandleExecutiveDashboard(w http.ResponseWriter, r *http.Request) {
	// HTTP wrapper for GetExecutiveDashboardData
	// Implementation would depend on chosen web framework
}

func (api *ExecutiveAnalyticsAPI) HandleComplianceReport(w http.ResponseWriter, r *http.Request) {
	// HTTP wrapper for GetComplianceReport
}

func (api *ExecutiveAnalyticsAPI) HandleSecurityMetrics(w http.ResponseWriter, r *http.Request) {
	// HTTP wrapper for GetSecurityMetrics
}

// Additional request/response types for other endpoints
type ComplianceReportRequest struct {
	UserID      UUID      `json:"user_id"`
	TenantID    UUID      `json:"tenant_id"`
	Framework   string    `json:"framework"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`
	ReportType  string    `json:"report_type"`
	Format      string    `json:"format"`
}

type ComplianceReportResponse struct {
	Success   bool            `json:"success"`
	Report    *ComplianceReport `json:"report,omitempty"`
	Error     *APIError       `json:"error,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

type SecurityMetricsRequest struct {
	UserID     UUID               `json:"user_id"`
	TenantID   UUID               `json:"tenant_id"`
	MetricType string             `json:"metric_type"`
	TimeRange  *APITimeRange      `json:"time_range"`
	Filters    map[string]string  `json:"filters,omitempty"`
}

type SecurityMetricsResponse struct {
	Success   bool                   `json:"success"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
	Error     *APIError              `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}