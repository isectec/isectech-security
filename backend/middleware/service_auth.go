package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// ServiceAuthConfig holds configuration for service-to-service authentication
type ServiceAuthConfig struct {
	ServiceAPIKey     string
	JWTAccessSecret   string
	JWTRefreshSecret  string
	TokenExpiry       time.Duration
	RequiredScopes    []string
	TrustedServices   []string
	EnableMTLS        bool
	EnableServiceMesh bool
}

// ServiceAuthMiddleware provides service-to-service authentication
type ServiceAuthMiddleware struct {
	config *ServiceAuthConfig
	logger *logrus.Logger
}

// ServiceClaims represents JWT claims for service authentication
type ServiceClaims struct {
	ServiceName string   `json:"service_name"`
	ServiceID   string   `json:"service_id"`
	Scopes      []string `json:"scopes"`
	IssueTime   int64    `json:"iat"`
	jwt.RegisteredClaims
}

// NewServiceAuthMiddleware creates a new service authentication middleware
func NewServiceAuthMiddleware(logger *logrus.Logger) *ServiceAuthMiddleware {
	config := &ServiceAuthConfig{
		ServiceAPIKey:     os.Getenv("SERVICE_API_KEY"),
		JWTAccessSecret:   os.Getenv("JWT_ACCESS_SECRET"),
		JWTRefreshSecret:  os.Getenv("JWT_REFRESH_SECRET"),
		TokenExpiry:       15 * time.Minute,
		RequiredScopes:    []string{"api:read", "api:write"},
		TrustedServices:   []string{"isectech-frontend", "isectech-api-gateway", "isectech-backend-services"},
		EnableMTLS:        os.Getenv("ENABLE_MTLS") == "true",
		EnableServiceMesh: os.Getenv("ENABLE_SERVICE_MESH") == "true",
	}

	return &ServiceAuthMiddleware{
		config: config,
		logger: logger,
	}
}

// AuthenticateService validates service-to-service requests
func (m *ServiceAuthMiddleware) AuthenticateService() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		
		// Log authentication attempt
		m.logger.WithFields(logrus.Fields{
			"remote_addr":    c.ClientIP(),
			"user_agent":     c.GetHeader("User-Agent"),
			"request_id":     c.GetHeader("X-Request-ID"),
			"path":          c.Request.URL.Path,
			"method":        c.Request.Method,
		}).Info("Service authentication attempt")

		// Skip authentication for health checks
		if m.isHealthCheckRequest(c) {
			c.Next()
			return
		}

		// Try different authentication methods
		var authResult *AuthResult
		var err error

		// 1. Try JWT token authentication
		if authResult, err = m.authenticateWithJWT(c); err == nil && authResult.Authenticated {
			m.logSuccessfulAuth(c, authResult, "JWT", startTime)
			c.Set("auth_method", "jwt")
			c.Set("service_name", authResult.ServiceName)
			c.Set("service_id", authResult.ServiceID)
			c.Set("scopes", authResult.Scopes)
			c.Next()
			return
		}

		// 2. Try API key authentication
		if authResult, err = m.authenticateWithAPIKey(c); err == nil && authResult.Authenticated {
			m.logSuccessfulAuth(c, authResult, "API_KEY", startTime)
			c.Set("auth_method", "api_key")
			c.Set("service_name", authResult.ServiceName)
			c.Set("service_id", authResult.ServiceID)
			c.Next()
			return
		}

		// 3. Try mTLS authentication (if enabled)
		if m.config.EnableMTLS {
			if authResult, err = m.authenticateWithMTLS(c); err == nil && authResult.Authenticated {
				m.logSuccessfulAuth(c, authResult, "MTLS", startTime)
				c.Set("auth_method", "mtls")
				c.Set("service_name", authResult.ServiceName)
				c.Set("service_id", authResult.ServiceID)
				c.Next()
				return
			}
		}

		// Authentication failed
		m.logFailedAuth(c, err, startTime)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":     "authentication_failed",
			"message":   "Invalid or missing authentication credentials",
			"timestamp": time.Now().Unix(),
			"request_id": c.GetHeader("X-Request-ID"),
		})
		c.Abort()
	}
}

// AuthResult holds the result of authentication
type AuthResult struct {
	Authenticated bool
	ServiceName   string
	ServiceID     string
	Scopes        []string
	Method        string
	ExpiresAt     time.Time
}

// authenticateWithJWT validates JWT tokens
func (m *ServiceAuthMiddleware) authenticateWithJWT(c *gin.Context) (*AuthResult, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return &AuthResult{Authenticated: false}, fmt.Errorf("missing authorization header")
	}

	// Extract token from Bearer header
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return &AuthResult{Authenticated: false}, fmt.Errorf("invalid authorization header format")
	}

	tokenString := parts[1]

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &ServiceClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.config.JWTAccessSecret), nil
	})

	if err != nil {
		return &AuthResult{Authenticated: false}, fmt.Errorf("token validation failed: %v", err)
	}

	claims, ok := token.Claims.(*ServiceClaims)
	if !ok || !token.Valid {
		return &AuthResult{Authenticated: false}, fmt.Errorf("invalid token claims")
	}

	// Validate service is trusted
	if !m.isServiceTrusted(claims.ServiceName) {
		return &AuthResult{Authenticated: false}, fmt.Errorf("untrusted service: %s", claims.ServiceName)
	}

	// Validate scopes
	if !m.hasRequiredScopes(claims.Scopes) {
		return &AuthResult{Authenticated: false}, fmt.Errorf("insufficient scopes")
	}

	return &AuthResult{
		Authenticated: true,
		ServiceName:   claims.ServiceName,
		ServiceID:     claims.ServiceID,
		Scopes:        claims.Scopes,
		Method:        "JWT",
		ExpiresAt:     claims.ExpiresAt.Time,
	}, nil
}

// authenticateWithAPIKey validates API key authentication
func (m *ServiceAuthMiddleware) authenticateWithAPIKey(c *gin.Context) (*AuthResult, error) {
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		return &AuthResult{Authenticated: false}, fmt.Errorf("missing API key")
	}

	serviceName := c.GetHeader("X-Service-Name")
	if serviceName == "" {
		return &AuthResult{Authenticated: false}, fmt.Errorf("missing service name")
	}

	// Validate API key using HMAC
	expectedSignature := m.generateAPIKeySignature(serviceName)
	if !hmac.Equal([]byte(apiKey), []byte(expectedSignature)) {
		return &AuthResult{Authenticated: false}, fmt.Errorf("invalid API key")
	}

	// Validate service is trusted
	if !m.isServiceTrusted(serviceName) {
		return &AuthResult{Authenticated: false}, fmt.Errorf("untrusted service: %s", serviceName)
	}

	return &AuthResult{
		Authenticated: true,
		ServiceName:   serviceName,
		ServiceID:     fmt.Sprintf("%s-%d", serviceName, time.Now().Unix()),
		Scopes:        m.config.RequiredScopes,
		Method:        "API_KEY",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}, nil
}

// authenticateWithMTLS validates mutual TLS authentication
func (m *ServiceAuthMiddleware) authenticateWithMTLS(c *gin.Context) (*AuthResult, error) {
	if c.Request.TLS == nil {
		return &AuthResult{Authenticated: false}, fmt.Errorf("TLS connection required")
	}

	// Check if client certificate is present
	if len(c.Request.TLS.PeerCertificates) == 0 {
		return &AuthResult{Authenticated: false}, fmt.Errorf("client certificate required")
	}

	clientCert := c.Request.TLS.PeerCertificates[0]
	
	// Extract service name from certificate subject
	serviceName := clientCert.Subject.CommonName
	if serviceName == "" {
		return &AuthResult{Authenticated: false}, fmt.Errorf("service name not found in certificate")
	}

	// Validate service is trusted
	if !m.isServiceTrusted(serviceName) {
		return &AuthResult{Authenticated: false}, fmt.Errorf("untrusted service: %s", serviceName)
	}

	// Validate certificate is not expired
	if time.Now().After(clientCert.NotAfter) {
		return &AuthResult{Authenticated: false}, fmt.Errorf("client certificate expired")
	}

	return &AuthResult{
		Authenticated: true,
		ServiceName:   serviceName,
		ServiceID:     fmt.Sprintf("%s-mtls-%s", serviceName, hex.EncodeToString(clientCert.SerialNumber.Bytes())),
		Scopes:        m.config.RequiredScopes,
		Method:        "MTLS",
		ExpiresAt:     clientCert.NotAfter,
	}, nil
}

// GenerateServiceToken creates a JWT token for service authentication
func (m *ServiceAuthMiddleware) GenerateServiceToken(serviceName, serviceID string, scopes []string) (string, error) {
	now := time.Now()
	claims := &ServiceClaims{
		ServiceName: serviceName,
		ServiceID:   serviceID,
		Scopes:      scopes,
		IssueTime:   now.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "isectech-platform",
			Subject:   serviceName,
			Audience:  []string{"isectech-services"},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.config.TokenExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        fmt.Sprintf("%s-%d", serviceID, now.Unix()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.config.JWTAccessSecret))
}

// GenerateAPIKeySignature creates an API key signature for a service
func (m *ServiceAuthMiddleware) generateAPIKeySignature(serviceName string) string {
	h := hmac.New(sha256.New, []byte(m.config.ServiceAPIKey))
	h.Write([]byte(serviceName))
	return hex.EncodeToString(h.Sum(nil))
}

// Helper functions
func (m *ServiceAuthMiddleware) isHealthCheckRequest(c *gin.Context) bool {
	path := c.Request.URL.Path
	return path == "/health" || path == "/ready" || path == "/startup" || 
		   strings.HasPrefix(path, "/health/") || 
		   c.GetHeader("User-Agent") == "GoogleHC/1.0"
}

func (m *ServiceAuthMiddleware) isServiceTrusted(serviceName string) bool {
	for _, trusted := range m.config.TrustedServices {
		if trusted == serviceName {
			return true
		}
	}
	return false
}

func (m *ServiceAuthMiddleware) hasRequiredScopes(scopes []string) bool {
	scopeMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeMap[scope] = true
	}

	for _, required := range m.config.RequiredScopes {
		if !scopeMap[required] {
			return false
		}
	}
	return true
}

func (m *ServiceAuthMiddleware) logSuccessfulAuth(c *gin.Context, result *AuthResult, method string, startTime time.Time) {
	duration := time.Since(startTime)
	m.logger.WithFields(logrus.Fields{
		"auth_method":    method,
		"service_name":   result.ServiceName,
		"service_id":     result.ServiceID,
		"scopes":         result.Scopes,
		"remote_addr":    c.ClientIP(),
		"user_agent":     c.GetHeader("User-Agent"),
		"request_id":     c.GetHeader("X-Request-ID"),
		"path":          c.Request.URL.Path,
		"method":        c.Request.Method,
		"duration_ms":   duration.Milliseconds(),
		"expires_at":    result.ExpiresAt.Unix(),
	}).Info("Service authentication successful")
}

func (m *ServiceAuthMiddleware) logFailedAuth(c *gin.Context, err error, startTime time.Time) {
	duration := time.Since(startTime)
	m.logger.WithFields(logrus.Fields{
		"error":         err.Error(),
		"remote_addr":   c.ClientIP(),
		"user_agent":    c.GetHeader("User-Agent"),
		"request_id":    c.GetHeader("X-Request-ID"),
		"path":         c.Request.URL.Path,
		"method":       c.Request.Method,
		"duration_ms":  duration.Milliseconds(),
	}).Warn("Service authentication failed")
	
	// Increment failed authentication metrics
	// In a real implementation, this would increment Prometheus metrics
}

// RequireScopes middleware to check specific scopes for endpoints
func (m *ServiceAuthMiddleware) RequireScopes(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopes, exists := c.Get("scopes")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "authentication_required",
				"message": "Authentication required to access this resource",
			})
			c.Abort()
			return
		}

		scopeList, ok := scopes.([]string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "scope_validation_error",
				"message": "Unable to validate scopes",
			})
			c.Abort()
			return
		}

		scopeMap := make(map[string]bool)
		for _, scope := range scopeList {
			scopeMap[scope] = true
		}

		for _, required := range requiredScopes {
			if !scopeMap[required] {
				c.JSON(http.StatusForbidden, gin.H{
					"error":        "insufficient_scope",
					"message":      "Insufficient permissions to access this resource",
					"required":     requiredScopes,
					"provided":     scopeList,
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// ServiceAuthClient provides methods for making authenticated service calls
type ServiceAuthClient struct {
	middleware *ServiceAuthMiddleware
	httpClient *http.Client
}

// NewServiceAuthClient creates a new authenticated HTTP client
func NewServiceAuthClient(middleware *ServiceAuthMiddleware) *ServiceAuthClient {
	return &ServiceAuthClient{
		middleware: middleware,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MakeAuthenticatedRequest makes an HTTP request with service authentication
func (c *ServiceAuthClient) MakeAuthenticatedRequest(ctx context.Context, method, url, serviceName, serviceID string, scopes []string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Generate JWT token for authentication
	token, err := c.middleware.GenerateServiceToken(serviceName, serviceID, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %v", err)
	}

	// Set authentication headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Service-Name", serviceName)
	req.Header.Set("X-Service-ID", serviceID)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("iSECTECH-Service/%s", serviceName))

	// Add request ID for tracing
	if requestID := ctx.Value("request_id"); requestID != nil {
		req.Header.Set("X-Request-ID", requestID.(string))
	}

	return c.httpClient.Do(req)
}