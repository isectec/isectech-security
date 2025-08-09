package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/usecase"
)

// MiddlewareManager handles HTTP middleware for authentication service
type MiddlewareManager struct {
	sessionService *usecase.SessionServiceImpl
	authService    *usecase.AuthenticationServiceImpl
	config         *MiddlewareConfig
}

// MiddlewareConfig holds middleware configuration
type MiddlewareConfig struct {
	// CORS settings
	AllowOrigins     []string `yaml:"allow_origins"`
	AllowMethods     []string `yaml:"allow_methods"`
	AllowHeaders     []string `yaml:"allow_headers"`
	ExposeHeaders    []string `yaml:"expose_headers"`
	AllowCredentials bool     `yaml:"allow_credentials"`
	MaxAge           int      `yaml:"max_age"`

	// Security headers
	EnableSecurityHeaders bool   `yaml:"enable_security_headers"`
	ContentSecurityPolicy string `yaml:"content_security_policy"`
	XFrameOptions         string `yaml:"x_frame_options"`
	XContentTypeOptions   string `yaml:"x_content_type_options"`

	// Rate limiting
	EnableRateLimit   bool          `yaml:"enable_rate_limit"`
	RequestsPerMinute int           `yaml:"requests_per_minute"`
	BurstLimit        int           `yaml:"burst_limit"`
	
	// Request tracking
	EnableRequestID   bool `yaml:"enable_request_id"`
	EnableAccessLog   bool `yaml:"enable_access_log"`
	
	// Timeout settings
	RequestTimeout    time.Duration `yaml:"request_timeout"`
}

// NewMiddlewareManager creates a new middleware manager
func NewMiddlewareManager(
	sessionService *usecase.SessionServiceImpl,
	authService *usecase.AuthenticationServiceImpl,
	config *MiddlewareConfig,
) *MiddlewareManager {
	return &MiddlewareManager{
		sessionService: sessionService,
		authService:    authService,
		config:         config,
	}
}

// CORS handles Cross-Origin Resource Sharing
func (m *MiddlewareManager) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Check if origin is allowed
		allowedOrigin := "*"
		if len(m.config.AllowOrigins) > 0 {
			allowed := false
			for _, allowedOrig := range m.config.AllowOrigins {
				if allowedOrig == origin || allowedOrig == "*" {
					allowed = true
					allowedOrigin = origin
					break
				}
			}
			if !allowed {
				c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
					Error:   "forbidden",
					Message: "Origin not allowed",
				})
				return
			}
		}

		c.Header("Access-Control-Allow-Origin", allowedOrigin)
		c.Header("Access-Control-Allow-Methods", strings.Join(m.config.AllowMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(m.config.AllowHeaders, ", "))
		c.Header("Access-Control-Expose-Headers", strings.Join(m.config.ExposeHeaders, ", "))
		
		if m.config.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		
		if m.config.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", string(rune(m.config.MaxAge)))
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SecurityHeaders adds security headers to responses
func (m *MiddlewareManager) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.config.EnableSecurityHeaders {
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("X-Frame-Options", "DENY")
			c.Header("X-XSS-Protection", "1; mode=block")
			c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
			c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			
			if m.config.ContentSecurityPolicy != "" {
				c.Header("Content-Security-Policy", m.config.ContentSecurityPolicy)
			}
			
			// HSTS header for HTTPS
			if c.Request.TLS != nil {
				c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
		}
		
		c.Next()
	}
}

// RequestID adds a unique request ID to each request
func (m *MiddlewareManager) RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.config.EnableRequestID {
			requestID := c.GetHeader("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
			}
			
			c.Header("X-Request-ID", requestID)
			c.Set("request_id", requestID)
		}
		
		c.Next()
	}
}

// RequestLogger logs HTTP requests
func (m *MiddlewareManager) RequestLogger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		if !m.config.EnableAccessLog {
			return ""
		}

		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// RequestTimeout sets a timeout for requests
func (m *MiddlewareManager) RequestTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.config.RequestTimeout > 0 {
			ctx, cancel := context.WithTimeout(c.Request.Context(), m.config.RequestTimeout)
			defer cancel()
			
			c.Request = c.Request.WithContext(ctx)
		}
		
		c.Next()
	}
}

// ExtractClientInfo extracts client information from request
func (m *MiddlewareManager) ExtractClientInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract IP address
		clientIP := c.ClientIP()
		if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
			clientIP = realIP
		} else if forwardedFor := c.GetHeader("X-Forwarded-For"); forwardedFor != "" {
			ips := strings.Split(forwardedFor, ",")
			if len(ips) > 0 {
				clientIP = strings.TrimSpace(ips[0])
			}
		}
		
		// Extract User Agent
		userAgent := c.GetHeader("User-Agent")
		
		// Store in context
		c.Set("client_ip", clientIP)
		c.Set("user_agent", userAgent)
		
		c.Next()
	}
}

// AuthenticationRequired validates JWT tokens and session
func (m *MiddlewareManager) AuthenticationRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Authorization header required",
				Code:    "MISSING_AUTH_HEADER",
			})
			return
		}

		// Check Bearer token format
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Invalid authorization header format",
				Code:    "INVALID_AUTH_FORMAT",
			})
			return
		}

		token := tokenParts[1]

		// Validate JWT token
		claims, err := m.sessionService.ValidateJWT(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Invalid or expired token",
				Code:    "INVALID_TOKEN",
				Details: map[string]interface{}{
					"validation_error": err.Error(),
				},
			})
			return
		}

		// Additional session validation
		clientIP, _ := c.Get("client_ip")
		sessionValidationReq := &usecase.SessionValidationRequest{
			AccessToken: token,
			IPAddress:   clientIP.(string),
		}

		sessionResp, err := m.authService.ValidateSession(c.Request.Context(), sessionValidationReq)
		if err != nil || !sessionResp.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{
				Error:   "unauthorized",
				Message: "Session validation failed",
				Code:    "SESSION_INVALID",
				Details: map[string]interface{}{
					"failure_reason": sessionResp.FailureReason,
				},
			})
			return
		}

		// Store user information in context
		c.Set("user_id", claims.UserID)
		c.Set("tenant_id", claims.TenantID)
		c.Set("session_id", claims.SessionID)
		c.Set("username", claims.Username)
		c.Set("security_clearance", claims.SecurityClearance)
		c.Set("mfa_verified", claims.MFAVerified)
		c.Set("user_roles", claims.Roles)
		c.Set("user_permissions", claims.Permissions)

		c.Next()
	}
}

// RequireSecurityClearance validates minimum security clearance
func (m *MiddlewareManager) RequireSecurityClearance(minClearance entity.SecurityClearanceLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		userClearance, exists := c.Get("security_clearance")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Security clearance information not available",
				Code:    "CLEARANCE_UNAVAILABLE",
			})
			return
		}

		clearance := userClearance.(entity.SecurityClearanceLevel)
		if !clearance.HasAccess(minClearance) {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Insufficient security clearance",
				Code:    "INSUFFICIENT_CLEARANCE",
				Details: map[string]interface{}{
					"required_clearance": minClearance,
					"user_clearance":     clearance,
				},
			})
			return
		}

		c.Next()
	}
}

// RequireRole validates user has required role
func (m *MiddlewareManager) RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("user_roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Role information not available",
				Code:    "ROLES_UNAVAILABLE",
			})
			return
		}

		roles := userRoles.([]string)
		hasRole := false
		for _, role := range roles {
			if role == requiredRole {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Required role not found",
				Code:    "INSUFFICIENT_ROLE",
				Details: map[string]interface{}{
					"required_role": requiredRole,
					"user_roles":    roles,
				},
			})
			return
		}

		c.Next()
	}
}

// RequirePermission validates user has required permission
func (m *MiddlewareManager) RequirePermission(requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userPermissions, exists := c.Get("user_permissions")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Permission information not available",
				Code:    "PERMISSIONS_UNAVAILABLE",
			})
			return
		}

		permissions := userPermissions.([]string)
		hasPermission := false
		for _, permission := range permissions {
			if permission == requiredPermission {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Required permission not found",
				Code:    "INSUFFICIENT_PERMISSION",
				Details: map[string]interface{}{
					"required_permission": requiredPermission,
					"user_permissions":    permissions,
				},
			})
			return
		}

		c.Next()
	}
}

// RequireMFA validates that the session has MFA verification
func (m *MiddlewareManager) RequireMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		mfaVerified, exists := c.Get("mfa_verified")
		if !exists || !mfaVerified.(bool) {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "MFA verification required",
				Code:    "MFA_REQUIRED",
			})
			return
		}

		c.Next()
	}
}

// ErrorHandler handles panics and errors
func (m *MiddlewareManager) ErrorHandler() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "internal_server_error",
				Message: "An unexpected error occurred",
				Code:    "INTERNAL_ERROR",
				Details: map[string]interface{}{
					"recovered": err,
				},
			})
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

// TenantIsolation ensures tenant-specific data access
func (m *MiddlewareManager) TenantIsolation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract tenant ID from JWT claims (already verified)
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Tenant information not available",
				Code:    "TENANT_UNAVAILABLE",
			})
			return
		}

		// For routes that include tenant_id in path or query
		pathTenantID := c.Param("tenant_id")
		queryTenantID := c.Query("tenant_id")

		// Validate tenant ID matches if provided in request
		userTenantID := tenantID.(uuid.UUID)
		
		if pathTenantID != "" {
			requestTenantID, err := uuid.Parse(pathTenantID)
			if err != nil || requestTenantID != userTenantID {
				c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
					Error:   "forbidden",
					Message: "Tenant access denied",
					Code:    "TENANT_ACCESS_DENIED",
				})
				return
			}
		}

		if queryTenantID != "" {
			requestTenantID, err := uuid.Parse(queryTenantID)
			if err != nil || requestTenantID != userTenantID {
				c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
					Error:   "forbidden",
					Message: "Tenant access denied",
					Code:    "TENANT_ACCESS_DENIED",
				})
				return
			}
		}

		c.Next()
	}
}

// Helper functions

// GetUserID extracts user ID from context
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, false
	}
	return userID.(uuid.UUID), true
}

// GetTenantID extracts tenant ID from context
func GetTenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		return uuid.Nil, false
	}
	return tenantID.(uuid.UUID), true
}

// GetSecurityClearance extracts security clearance from context
func GetSecurityClearance(c *gin.Context) (entity.SecurityClearanceLevel, bool) {
	clearance, exists := c.Get("security_clearance")
	if !exists {
		return entity.SecurityClearanceUnclassified, false
	}
	return clearance.(entity.SecurityClearanceLevel), true
}

// GetClientIP extracts client IP from context
func GetClientIP(c *gin.Context) string {
	if ip, exists := c.Get("client_ip"); exists {
		return ip.(string)
	}
	return c.ClientIP()
}

// GetUserAgent extracts user agent from context
func GetUserAgent(c *gin.Context) string {
	if ua, exists := c.Get("user_agent"); exists {
		return ua.(string)
	}
	return c.GetHeader("User-Agent")
}