package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"api-gateway/domain/entity"
)

// AuthMiddleware handles authentication and authorization
type AuthMiddleware struct {
	logger       *zap.Logger
	jwtSecretKey []byte
	jwtPublicKey *rsa.PublicKey
	apiKeys      map[string]*APIKeyInfo
	oauthConfig  *entity.OAuthConfig
}

// APIKeyInfo represents API key information
type APIKeyInfo struct {
	ID          uuid.UUID         `json:"id"`
	Key         string            `json:"key"`
	Name        string            `json:"name"`
	UserID      string            `json:"user_id"`
	Roles       []string          `json:"roles"`
	Scopes      []string          `json:"scopes"`
	RateLimit   int               `json:"rate_limit"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at"`
	LastUsed    time.Time         `json:"last_used"`
	Enabled     bool              `json:"enabled"`
}

// AuthContext represents authentication context
type AuthContext struct {
	UserID       string            `json:"user_id"`
	Username     string            `json:"username"`
	Email        string            `json:"email"`
	Roles        []string          `json:"roles"`
	Scopes       []string          `json:"scopes"`
	Claims       map[string]interface{} `json:"claims"`
	AuthType     entity.AuthType   `json:"auth_type"`
	TokenType    string            `json:"token_type"`
	APIKey       *APIKeyInfo       `json:"api_key,omitempty"`
	JWTClaims    *JWTClaims        `json:"jwt_claims,omitempty"`
	Authenticated bool             `json:"authenticated"`
	Authorized   bool              `json:"authorized"`
	TenantID     string            `json:"tenant_id,omitempty"`
	SessionID    string            `json:"session_id,omitempty"`
}

// JWTClaims represents JWT claims
type JWTClaims struct {
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes"`
	TenantID  string   `json:"tenant_id,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	jwt.RegisteredClaims
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(logger *zap.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		logger:  logger,
		apiKeys: make(map[string]*APIKeyInfo),
	}
}

// SetJWTSecret sets the JWT secret key for HMAC algorithms
func (m *AuthMiddleware) SetJWTSecret(secret []byte) {
	m.jwtSecretKey = secret
}

// SetJWTPublicKey sets the JWT public key for RSA algorithms
func (m *AuthMiddleware) SetJWTPublicKey(publicKeyPEM []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	m.jwtPublicKey = rsaPublicKey
	return nil
}

// AddAPIKey adds an API key to the middleware
func (m *AuthMiddleware) AddAPIKey(keyInfo *APIKeyInfo) {
	m.apiKeys[keyInfo.Key] = keyInfo
}

// RemoveAPIKey removes an API key from the middleware
func (m *AuthMiddleware) RemoveAPIKey(key string) {
	delete(m.apiKeys, key)
}

// AuthenticateRoute creates authentication middleware for a specific route
func (m *AuthMiddleware) AuthenticateRoute(route *entity.Route) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication if not required
		if !route.AuthRequired {
			c.Next()
			return
		}

		authCtx := &AuthContext{
			Authenticated: false,
			Authorized:    false,
		}

		var err error

		// Attempt authentication based on configured type
		switch route.AuthType {
		case entity.AuthTypeJWT:
			err = m.authenticateJWT(c, authCtx, route)
		case entity.AuthTypeAPIKey:
			err = m.authenticateAPIKey(c, authCtx, route)
		case entity.AuthTypeOAuth:
			err = m.authenticateOAuth(c, authCtx, route)
		case entity.AuthTypeBasic:
			err = m.authenticateBasic(c, authCtx, route)
		case entity.AuthTypeCustom:
			err = m.authenticateCustom(c, authCtx, route)
		default:
			err = fmt.Errorf("unsupported authentication type: %s", route.AuthType)
		}

		if err != nil {
			m.logger.Warn("Authentication failed",
				zap.String("route", route.Name),
				zap.String("auth_type", string(route.AuthType)),
				zap.Error(err),
			)
			m.respondUnauthorized(c, "Authentication failed: "+err.Error())
			return
		}

		if !authCtx.Authenticated {
			m.respondUnauthorized(c, "Authentication required")
			return
		}

		// Perform authorization checks
		if err := m.authorize(c, authCtx, route); err != nil {
			m.logger.Warn("Authorization failed",
				zap.String("route", route.Name),
				zap.String("user_id", authCtx.UserID),
				zap.Error(err),
			)
			m.respondForbidden(c, "Authorization failed: "+err.Error())
			return
		}

		// Store auth context in gin context
		c.Set("auth_context", authCtx)
		c.Set("user_id", authCtx.UserID)
		c.Set("username", authCtx.Username)
		c.Set("roles", authCtx.Roles)
		c.Set("scopes", authCtx.Scopes)
		c.Set("tenant_id", authCtx.TenantID)

		m.logger.Debug("Authentication and authorization successful",
			zap.String("route", route.Name),
			zap.String("user_id", authCtx.UserID),
			zap.String("auth_type", string(route.AuthType)),
		)

		c.Next()
	}
}

// authenticateJWT handles JWT authentication
func (m *AuthMiddleware) authenticateJWT(c *gin.Context, authCtx *AuthContext, route *entity.Route) error {
	// Extract token from request
	tokenString, err := m.extractJWTToken(c)
	if err != nil {
		return err
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		switch token.Method.Alg() {
		case "HS256", "HS384", "HS512":
			if m.jwtSecretKey == nil {
				return nil, fmt.Errorf("JWT secret key not configured")
			}
			return m.jwtSecretKey, nil
		case "RS256", "RS384", "RS512":
			if m.jwtPublicKey == nil {
				return nil, fmt.Errorf("JWT public key not configured")
			}
			return m.jwtPublicKey, nil
		default:
			return nil, fmt.Errorf("unsupported signing method: %s", token.Method.Alg())
		}
	})

	if err != nil {
		return fmt.Errorf("invalid JWT token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return fmt.Errorf("invalid JWT claims")
	}

	// Validate issuer and audience if configured
	// (implementation would check against route configuration)

	// Populate auth context
	authCtx.UserID = claims.UserID
	authCtx.Username = claims.Username
	authCtx.Email = claims.Email
	authCtx.Roles = claims.Roles
	authCtx.Scopes = claims.Scopes
	authCtx.TenantID = claims.TenantID
	authCtx.SessionID = claims.SessionID
	authCtx.AuthType = entity.AuthTypeJWT
	authCtx.TokenType = "jwt"
	authCtx.JWTClaims = claims
	authCtx.Authenticated = true

	// Convert claims to map for easier access
	authCtx.Claims = make(map[string]interface{})
	authCtx.Claims["user_id"] = claims.UserID
	authCtx.Claims["username"] = claims.Username
	authCtx.Claims["email"] = claims.Email
	authCtx.Claims["roles"] = claims.Roles
	authCtx.Claims["scopes"] = claims.Scopes
	authCtx.Claims["tenant_id"] = claims.TenantID
	authCtx.Claims["session_id"] = claims.SessionID
	authCtx.Claims["iss"] = claims.Issuer
	authCtx.Claims["aud"] = claims.Audience
	authCtx.Claims["exp"] = claims.ExpiresAt.Time
	authCtx.Claims["iat"] = claims.IssuedAt.Time
	authCtx.Claims["sub"] = claims.Subject

	return nil
}

// authenticateAPIKey handles API key authentication
func (m *AuthMiddleware) authenticateAPIKey(c *gin.Context, authCtx *AuthContext, route *entity.Route) error {
	// Extract API key from request
	apiKey, err := m.extractAPIKey(c)
	if err != nil {
		return err
	}

	// Validate API key
	keyInfo, exists := m.apiKeys[apiKey]
	if !exists {
		return fmt.Errorf("invalid API key")
	}

	if !keyInfo.Enabled {
		return fmt.Errorf("API key is disabled")
	}

	if keyInfo.ExpiresAt != nil && time.Now().After(*keyInfo.ExpiresAt) {
		return fmt.Errorf("API key has expired")
	}

	// Update last used time
	keyInfo.LastUsed = time.Now()

	// Populate auth context
	authCtx.UserID = keyInfo.UserID
	authCtx.Username = keyInfo.Name
	authCtx.Roles = keyInfo.Roles
	authCtx.Scopes = keyInfo.Scopes
	authCtx.AuthType = entity.AuthTypeAPIKey
	authCtx.TokenType = "api_key"
	authCtx.APIKey = keyInfo
	authCtx.Authenticated = true

	// Add API key metadata to claims
	authCtx.Claims = make(map[string]interface{})
	for k, v := range keyInfo.Metadata {
		authCtx.Claims[k] = v
	}

	return nil
}

// authenticateOAuth handles OAuth authentication
func (m *AuthMiddleware) authenticateOAuth(c *gin.Context, authCtx *AuthContext, route *entity.Route) error {
	// Extract OAuth token from request
	tokenString, err := m.extractOAuthToken(c)
	if err != nil {
		return err
	}

	// Validate OAuth token with provider
	// This would typically involve calling the OAuth provider's userinfo endpoint
	// For now, we'll implement a simplified version

	// In a real implementation, you would:
	// 1. Call the OAuth provider's userinfo endpoint with the token
	// 2. Validate the response
	// 3. Extract user information

	// Placeholder implementation
	authCtx.UserID = "oauth_user"
	authCtx.Username = "oauth_user"
	authCtx.AuthType = entity.AuthTypeOAuth
	authCtx.TokenType = "oauth"
	authCtx.Authenticated = true

	return nil
}

// authenticateBasic handles basic authentication
func (m *AuthMiddleware) authenticateBasic(c *gin.Context, authCtx *AuthContext, route *entity.Route) error {
	username, password, ok := c.Request.BasicAuth()
	if !ok {
		return fmt.Errorf("basic auth credentials not provided")
	}

	// Validate credentials
	// This would typically involve checking against a user database
	// For now, we'll implement a simplified version

	if username == "" || password == "" {
		return fmt.Errorf("invalid credentials")
	}

	// Placeholder validation
	// In a real implementation, you would hash the password and compare
	if username == "admin" && password == "password" {
		authCtx.UserID = username
		authCtx.Username = username
		authCtx.Roles = []string{"admin"}
		authCtx.AuthType = entity.AuthTypeBasic
		authCtx.TokenType = "basic"
		authCtx.Authenticated = true
		return nil
	}

	return fmt.Errorf("invalid credentials")
}

// authenticateCustom handles custom authentication
func (m *AuthMiddleware) authenticateCustom(c *gin.Context, authCtx *AuthContext, route *entity.Route) error {
	// Custom authentication logic would go here
	// This could involve calling external authentication services,
	// validating custom tokens, etc.

	return fmt.Errorf("custom authentication not implemented")
}

// authorize performs authorization checks
func (m *AuthMiddleware) authorize(c *gin.Context, authCtx *AuthContext, route *entity.Route) error {
	// Check required roles
	if len(route.RequiredRoles) > 0 {
		if !m.hasAnyRole(authCtx.Roles, route.RequiredRoles) {
			return fmt.Errorf("insufficient roles")
		}
	}

	// Check required scopes
	if len(route.RequiredScopes) > 0 {
		if !m.hasAnyScope(authCtx.Scopes, route.RequiredScopes) {
			return fmt.Errorf("insufficient scopes")
		}
	}

	// Check required claims
	if len(route.RequiredClaims) > 0 {
		for claimKey, expectedValue := range route.RequiredClaims {
			if actualValue, exists := authCtx.Claims[claimKey]; !exists || actualValue != expectedValue {
				return fmt.Errorf("required claim %s not satisfied", claimKey)
			}
		}
	}

	authCtx.Authorized = true
	return nil
}

// Helper methods for token extraction

func (m *AuthMiddleware) extractJWTToken(c *gin.Context) (string, error) {
	// Try Authorization header first
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer "), nil
		}
	}

	// Try query parameter
	if token := c.Query("token"); token != "" {
		return token, nil
	}

	// Try cookie
	if token, err := c.Cookie("jwt_token"); err == nil && token != "" {
		return token, nil
	}

	return "", fmt.Errorf("JWT token not found")
}

func (m *AuthMiddleware) extractAPIKey(c *gin.Context) (string, error) {
	// Try X-API-Key header
	if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
		return apiKey, nil
	}

	// Try Authorization header with API key scheme
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "ApiKey ") {
		return strings.TrimPrefix(authHeader, "ApiKey "), nil
	}

	// Try query parameter
	if apiKey := c.Query("api_key"); apiKey != "" {
		return apiKey, nil
	}

	return "", fmt.Errorf("API key not found")
}

func (m *AuthMiddleware) extractOAuthToken(c *gin.Context) (string, error) {
	// Try Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer "), nil
		}
	}

	// Try query parameter
	if token := c.Query("access_token"); token != "" {
		return token, nil
	}

	return "", fmt.Errorf("OAuth token not found")
}

// Helper methods for authorization

func (m *AuthMiddleware) hasAnyRole(userRoles, requiredRoles []string) bool {
	for _, required := range requiredRoles {
		for _, userRole := range userRoles {
			if userRole == required {
				return true
			}
		}
	}
	return false
}

func (m *AuthMiddleware) hasAnyScope(userScopes, requiredScopes []string) bool {
	for _, required := range requiredScopes {
		for _, userScope := range userScopes {
			if userScope == required {
				return true
			}
		}
	}
	return false
}

// Response helpers

func (m *AuthMiddleware) respondUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, gin.H{
		"error":   "Unauthorized",
		"message": message,
		"code":    "AUTH_001",
	})
	c.Abort()
}

func (m *AuthMiddleware) respondForbidden(c *gin.Context, message string) {
	c.JSON(http.StatusForbidden, gin.H{
		"error":   "Forbidden",
		"message": message,
		"code":    "AUTH_002",
	})
	c.Abort()
}

// GetAuthContext extracts authentication context from gin context
func GetAuthContext(c *gin.Context) (*AuthContext, bool) {
	if authCtx, exists := c.Get("auth_context"); exists {
		if ctx, ok := authCtx.(*AuthContext); ok {
			return ctx, true
		}
	}
	return nil, false
}

// RequireAuth is a helper middleware that requires authentication
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := GetAuthContext(c)
		if !exists || !authCtx.Authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
				"code":    "AUTH_001",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireRole is a helper middleware that requires specific roles
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := GetAuthContext(c)
		if !exists || !authCtx.Authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
				"code":    "AUTH_001",
			})
			c.Abort()
			return
		}

		hasRole := false
		for _, requiredRole := range roles {
			for _, userRole := range authCtx.Roles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient permissions",
				"code":    "AUTH_002",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireScope is a helper middleware that requires specific scopes
func RequireScope(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authCtx, exists := GetAuthContext(c)
		if !exists || !authCtx.Authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
				"code":    "AUTH_001",
			})
			c.Abort()
			return
		}

		hasScope := false
		for _, requiredScope := range scopes {
			for _, userScope := range authCtx.Scopes {
				if userScope == requiredScope {
					hasScope = true
					break
				}
			}
			if hasScope {
				break
			}
		}

		if !hasScope {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient scopes",
				"code":    "AUTH_003",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}