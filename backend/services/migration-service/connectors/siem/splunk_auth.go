package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/isectech/migration-service/connectors"
	"github.com/isectech/migration-service/domain/entity"
)

// NewSplunkAuthHandler creates a new Splunk authentication handler
func NewSplunkAuthHandler(connector *SplunkConnector, authConfig entity.AuthenticationConfig) (*SplunkAuthHandler, error) {
	handler := &SplunkAuthHandler{
		connector: connector,
	}

	// Extract credentials based on authentication type
	switch authConfig.Type {
	case entity.AuthTypeBasicAuth:
		username, ok := authConfig.Credentials["username"].(string)
		if !ok {
			return nil, fmt.Errorf("username is required for basic authentication")
		}
		password, ok := authConfig.Credentials["password"].(string)
		if !ok {
			return nil, fmt.Errorf("password is required for basic authentication")
		}
		handler.username = username
		handler.password = password

	case entity.AuthTypeAPIKey:
		// For API key authentication, the key is typically used as a session key
		sessionKey, ok := authConfig.Credentials["api_key"].(string)
		if !ok {
			return nil, fmt.Errorf("api_key is required for API key authentication")
		}
		handler.sessionKey = sessionKey

	default:
		return nil, fmt.Errorf("authentication type %s not supported for Splunk", authConfig.Type)
	}

	return handler, nil
}

// Authenticate performs authentication with Splunk
func (s *SplunkAuthHandler) Authenticate(ctx context.Context) error {
	// If we already have a session key (from API key auth), validate it
	if s.sessionKey != "" {
		if err := s.validateSessionKey(ctx); err == nil {
			return nil
		}
		// If validation fails, continue with login
	}

	// Perform login authentication
	return s.login(ctx)
}

// RefreshToken refreshes the authentication token
func (s *SplunkAuthHandler) RefreshToken(ctx context.Context) error {
	// For Splunk, we re-authenticate rather than refresh
	return s.Authenticate(ctx)
}

// IsAuthenticated returns true if currently authenticated
func (s *SplunkAuthHandler) IsAuthenticated() bool {
	return s.sessionKey != "" && (s.tokenExpiry == nil || time.Now().Before(*s.tokenExpiry))
}

// GetAuthHeaders returns authentication headers for API requests
func (s *SplunkAuthHandler) GetAuthHeaders() map[string]string {
	if s.sessionKey == "" {
		return make(map[string]string)
	}

	return map[string]string{
		"Authorization": fmt.Sprintf("Splunk %s", s.sessionKey),
	}
}

// GetAuthToken returns the current authentication token
func (s *SplunkAuthHandler) GetAuthToken() *connectors.AuthToken {
	if s.sessionKey == "" {
		return nil
	}

	return &connectors.AuthToken{
		Token:     s.sessionKey,
		TokenType: "Splunk",
		ExpiresAt: s.tokenExpiry,
	}
}

// login performs login authentication with username/password
func (s *SplunkAuthHandler) login(ctx context.Context) error {
	endpoint := "/services/auth/login"
	baseURL := s.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	// Prepare login data
	data := url.Values{}
	data.Set("username", s.username)
	data.Set("password", s.password)
	data.Set("output_mode", "json")

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Make the request using the connector's HTTP client
	resp, err := s.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	// Parse the response
	var loginResponse struct {
		SessionKey string `json:"sessionKey"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&loginResponse); err != nil {
		return fmt.Errorf("failed to decode login response: %w", err)
	}

	if loginResponse.SessionKey == "" {
		return fmt.Errorf("no session key returned from login")
	}

	// Store the session key
	s.sessionKey = loginResponse.SessionKey
	s.connector.sessionKey = loginResponse.SessionKey

	// Set expiry time (Splunk sessions typically last 24 hours by default)
	expiry := time.Now().Add(24 * time.Hour)
	s.tokenExpiry = &expiry

	return nil
}

// validateSessionKey validates the current session key
func (s *SplunkAuthHandler) validateSessionKey(ctx context.Context) error {
	endpoint := "/services/authentication/current-context"
	baseURL := s.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", s.sessionKey))
	req.Header.Set("Accept", "application/json")

	// Add query parameter for JSON output
	q := req.URL.Query()
	q.Set("output_mode", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := s.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("session validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil // Session is valid
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Session is invalid
		s.sessionKey = ""
		s.tokenExpiry = nil
		return fmt.Errorf("session key is invalid or expired")
	}

	return fmt.Errorf("session validation failed with status %d", resp.StatusCode)
}

// logout performs logout (optional cleanup)
func (s *SplunkAuthHandler) logout(ctx context.Context) error {
	if s.sessionKey == "" {
		return nil // Already logged out
	}

	endpoint := "/services/auth/logout"
	baseURL := s.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", s.sessionKey))

	resp, err := s.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("logout request failed: %w", err)
	}
	defer resp.Body.Close()

	// Clear session data regardless of response
	s.sessionKey = ""
	s.tokenExpiry = nil
	s.connector.sessionKey = ""

	return nil
}

// SplunkTokenAuthHandler handles token-based authentication for Splunk
type SplunkTokenAuthHandler struct {
	connector *SplunkConnector
	token     string
	expiry    *time.Time
}

// NewSplunkTokenAuthHandler creates a new token-based auth handler
func NewSplunkTokenAuthHandler(connector *SplunkConnector, token string) *SplunkTokenAuthHandler {
	return &SplunkTokenAuthHandler{
		connector: connector,
		token:     token,
	}
}

// Authenticate performs token authentication
func (s *SplunkTokenAuthHandler) Authenticate(ctx context.Context) error {
	// Token authentication is validated on first use
	return s.validateToken(ctx)
}

// RefreshToken refreshes the authentication token
func (s *SplunkTokenAuthHandler) RefreshToken(ctx context.Context) error {
	// Tokens in Splunk cannot be refreshed, they need to be recreated
	return fmt.Errorf("token refresh not supported for Splunk tokens")
}

// IsAuthenticated returns true if currently authenticated
func (s *SplunkTokenAuthHandler) IsAuthenticated() bool {
	return s.token != "" && (s.expiry == nil || time.Now().Before(*s.expiry))
}

// GetAuthHeaders returns authentication headers for API requests
func (s *SplunkTokenAuthHandler) GetAuthHeaders() map[string]string {
	if s.token == "" {
		return make(map[string]string)
	}

	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", s.token),
	}
}

// GetAuthToken returns the current authentication token
func (s *SplunkTokenAuthHandler) GetAuthToken() *connectors.AuthToken {
	if s.token == "" {
		return nil
	}

	return &connectors.AuthToken{
		Token:     s.token,
		TokenType: "Bearer",
		ExpiresAt: s.expiry,
	}
}

// validateToken validates the authentication token
func (s *SplunkTokenAuthHandler) validateToken(ctx context.Context) error {
	endpoint := "/services/authentication/current-context"
	baseURL := s.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create token validation request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.token))
	req.Header.Set("Accept", "application/json")

	// Add query parameter for JSON output
	q := req.URL.Query()
	q.Set("output_mode", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := s.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil // Token is valid
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication token is invalid or expired")
	}

	return fmt.Errorf("token validation failed with status %d", resp.StatusCode)
}

// SplunkCertificateAuthHandler handles certificate-based authentication
type SplunkCertificateAuthHandler struct {
	connector    *SplunkConnector
	certPath     string
	keyPath      string
	authenticated bool
}

// NewSplunkCertificateAuthHandler creates a new certificate-based auth handler
func NewSplunkCertificateAuthHandler(connector *SplunkConnector, certPath, keyPath string) *SplunkCertificateAuthHandler {
	return &SplunkCertificateAuthHandler{
		connector: connector,
		certPath:  certPath,
		keyPath:   keyPath,
	}
}

// Authenticate performs certificate authentication
func (s *SplunkCertificateAuthHandler) Authenticate(ctx context.Context) error {
	// Certificate authentication is handled at the TLS level
	// We just need to verify the connection works
	endpoint := "/services/server/info"
	baseURL := s.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create cert auth test request: %w", err)
	}

	resp, err := s.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("certificate authentication failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		s.authenticated = true
		return nil
	}

	return fmt.Errorf("certificate authentication failed with status %d", resp.StatusCode)
}

// RefreshToken refreshes the authentication token (N/A for certificates)
func (s *SplunkCertificateAuthHandler) RefreshToken(ctx context.Context) error {
	return nil // No token refresh needed for certificates
}

// IsAuthenticated returns true if currently authenticated
func (s *SplunkCertificateAuthHandler) IsAuthenticated() bool {
	return s.authenticated
}

// GetAuthHeaders returns authentication headers (none for certificate auth)
func (s *SplunkCertificateAuthHandler) GetAuthHeaders() map[string]string {
	return make(map[string]string) // Certificate auth is handled at TLS level
}

// GetAuthToken returns the current authentication token (N/A for certificates)
func (s *SplunkCertificateAuthHandler) GetAuthToken() *connectors.AuthToken {
	return nil // No token for certificate authentication
}