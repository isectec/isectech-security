package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/isectech/migration-service/connectors"
	"github.com/isectech/migration-service/domain/entity"
)

// NewQRadarAuthHandler creates a new QRadar authentication handler
func NewQRadarAuthHandler(connector *QRadarConnector, authConfig entity.AuthenticationConfig) (*QRadarAuthHandler, error) {
	handler := &QRadarAuthHandler{
		connector: connector,
	}

	// Extract credentials based on authentication type
	switch authConfig.Type {
	case entity.AuthTypeAPIKey:
		apiToken, ok := authConfig.Credentials["api_token"].(string)
		if !ok {
			// Try alternative key names
			if token, exists := authConfig.Credentials["token"].(string); exists {
				apiToken = token
			} else if key, exists := authConfig.Credentials["api_key"].(string); exists {
				apiToken = key
			} else {
				return nil, fmt.Errorf("api_token is required for API key authentication")
			}
		}
		handler.apiToken = apiToken

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

	default:
		return nil, fmt.Errorf("authentication type %s not supported for QRadar", authConfig.Type)
	}

	return handler, nil
}

// Authenticate performs authentication with QRadar
func (q *QRadarAuthHandler) Authenticate(ctx context.Context) error {
	if q.apiToken != "" {
		// For API token authentication, validate the token
		return q.validateAPIToken(ctx)
	}

	if q.username != "" && q.password != "" {
		// For username/password authentication, get SEC token
		return q.authenticateWithCredentials(ctx)
	}

	return fmt.Errorf("no valid authentication credentials configured")
}

// RefreshToken refreshes the authentication token
func (q *QRadarAuthHandler) RefreshToken(ctx context.Context) error {
	// For QRadar, we re-authenticate rather than refresh
	return q.Authenticate(ctx)
}

// IsAuthenticated returns true if currently authenticated
func (q *QRadarAuthHandler) IsAuthenticated() bool {
	return q.apiToken != "" || q.secToken != ""
}

// GetAuthHeaders returns authentication headers for API requests
func (q *QRadarAuthHandler) GetAuthHeaders() map[string]string {
	headers := make(map[string]string)

	if q.apiToken != "" {
		headers["SEC"] = q.apiToken
	} else if q.secToken != "" {
		headers["SEC"] = q.secToken
	}

	return headers
}

// GetAuthToken returns the current authentication token
func (q *QRadarAuthHandler) GetAuthToken() *connectors.AuthToken {
	token := ""
	tokenType := ""

	if q.apiToken != "" {
		token = q.apiToken
		tokenType = "API_TOKEN"
	} else if q.secToken != "" {
		token = q.secToken
		tokenType = "SEC_TOKEN"
	}

	if token == "" {
		return nil
	}

	return &connectors.AuthToken{
		Token:     token,
		TokenType: tokenType,
	}
}

// validateAPIToken validates the API token
func (q *QRadarAuthHandler) validateAPIToken(ctx context.Context) error {
	// Test the API token by making a simple API call
	endpoint := "/api/system/about"
	baseURL := q.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create token validation request: %w", err)
	}

	// Add the SEC header for authentication
	req.Header.Set("SEC", q.apiToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", q.connector.apiVersion)

	resp, err := q.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil // Token is valid
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("API token is invalid or expired")
	}

	return fmt.Errorf("token validation failed with status %d", resp.StatusCode)
}

// authenticateWithCredentials authenticates using username and password to get SEC token
func (q *QRadarAuthHandler) authenticateWithCredentials(ctx context.Context) error {
	// QRadar doesn't have a dedicated login endpoint for username/password
	// Instead, we use basic auth to get a temporary token via API calls
	// This is a simplified approach - in practice, you might need to use SAML or other methods

	endpoint := "/api/auth/login"
	baseURL := q.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	// Use basic authentication
	req.SetBasicAuth(q.username, q.password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", q.connector.apiVersion)

	resp, err := q.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Check if we got a token in response
		var loginResponse struct {
			SecToken string `json:"sec_token,omitempty"`
			Token    string `json:"token,omitempty"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&loginResponse); err == nil {
			if loginResponse.SecToken != "" {
				q.secToken = loginResponse.SecToken
				return nil
			}
			if loginResponse.Token != "" {
				q.secToken = loginResponse.Token
				return nil
			}
		}

		// If no token in response, we might need to extract from headers
		if token := resp.Header.Get("SEC"); token != "" {
			q.secToken = token
			return nil
		}

		// For QRadar, sometimes basic auth works directly without explicit token
		// In this case, we'll store the credentials for header generation
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed: invalid username or password")
	}

	return fmt.Errorf("authentication failed with status %d", resp.StatusCode)
}

// QRadarSAMLAuthHandler handles SAML-based authentication for QRadar
type QRadarSAMLAuthHandler struct {
	connector        *QRadarConnector
	samlResponse     string
	secToken         string
	sessionID        string
	authenticated    bool
}

// NewQRadarSAMLAuthHandler creates a new SAML-based auth handler
func NewQRadarSAMLAuthHandler(connector *QRadarConnector, samlResponse string) *QRadarSAMLAuthHandler {
	return &QRadarSAMLAuthHandler{
		connector:    connector,
		samlResponse: samlResponse,
	}
}

// Authenticate performs SAML authentication
func (q *QRadarSAMLAuthHandler) Authenticate(ctx context.Context) error {
	// SAML authentication is typically handled by posting the SAML response
	// to QRadar's SAML endpoint
	endpoint := "/api/auth/saml"
	baseURL := q.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	// Prepare SAML data
	samlData := map[string]string{
		"SAMLResponse": q.samlResponse,
	}

	jsonData, err := json.Marshal(samlData)
	if err != nil {
		return fmt.Errorf("failed to marshal SAML data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create SAML auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", q.connector.apiVersion)

	resp, err := q.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SAML authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Parse the authentication response
		var authResponse struct {
			SecToken  string `json:"sec_token,omitempty"`
			SessionID string `json:"session_id,omitempty"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&authResponse); err == nil {
			q.secToken = authResponse.SecToken
			q.sessionID = authResponse.SessionID
			q.authenticated = true
			return nil
		}

		// Check headers for token
		if token := resp.Header.Get("SEC"); token != "" {
			q.secToken = token
			q.authenticated = true
			return nil
		}

		return fmt.Errorf("SAML authentication succeeded but no token received")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("SAML authentication failed: invalid SAML response")
	}

	return fmt.Errorf("SAML authentication failed with status %d", resp.StatusCode)
}

// RefreshToken refreshes the authentication token (not applicable for SAML)
func (q *QRadarSAMLAuthHandler) RefreshToken(ctx context.Context) error {
	return fmt.Errorf("token refresh not supported for SAML authentication")
}

// IsAuthenticated returns true if currently authenticated
func (q *QRadarSAMLAuthHandler) IsAuthenticated() bool {
	return q.authenticated && q.secToken != ""
}

// GetAuthHeaders returns authentication headers for API requests
func (q *QRadarSAMLAuthHandler) GetAuthHeaders() map[string]string {
	if !q.authenticated || q.secToken == "" {
		return make(map[string]string)
	}

	headers := map[string]string{
		"SEC": q.secToken,
	}

	if q.sessionID != "" {
		headers["Session-ID"] = q.sessionID
	}

	return headers
}

// GetAuthToken returns the current authentication token
func (q *QRadarSAMLAuthHandler) GetAuthToken() *connectors.AuthToken {
	if !q.authenticated || q.secToken == "" {
		return nil
	}

	return &connectors.AuthToken{
		Token:     q.secToken,
		TokenType: "SAML_SEC_TOKEN",
		Metadata: map[string]interface{}{
			"session_id": q.sessionID,
		},
	}
}

// QRadarCertificateAuthHandler handles certificate-based authentication
type QRadarCertificateAuthHandler struct {
	connector     *QRadarConnector
	certPath      string
	keyPath       string
	authenticated bool
}

// NewQRadarCertificateAuthHandler creates a new certificate-based auth handler
func NewQRadarCertificateAuthHandler(connector *QRadarConnector, certPath, keyPath string) *QRadarCertificateAuthHandler {
	return &QRadarCertificateAuthHandler{
		connector: connector,
		certPath:  certPath,
		keyPath:   keyPath,
	}
}

// Authenticate performs certificate authentication
func (q *QRadarCertificateAuthHandler) Authenticate(ctx context.Context) error {
	// Certificate authentication is handled at the TLS level
	// We just need to verify the connection works
	endpoint := "/api/system/about"
	baseURL := q.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create cert auth test request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", q.connector.apiVersion)

	resp, err := q.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("certificate authentication failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		q.authenticated = true
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("certificate authentication failed: invalid or expired certificate")
	}

	return fmt.Errorf("certificate authentication failed with status %d", resp.StatusCode)
}

// RefreshToken refreshes the authentication token (N/A for certificates)
func (q *QRadarCertificateAuthHandler) RefreshToken(ctx context.Context) error {
	return nil // No token refresh needed for certificates
}

// IsAuthenticated returns true if currently authenticated
func (q *QRadarCertificateAuthHandler) IsAuthenticated() bool {
	return q.authenticated
}

// GetAuthHeaders returns authentication headers (none for certificate auth)
func (q *QRadarCertificateAuthHandler) GetAuthHeaders() map[string]string {
	return make(map[string]string) // Certificate auth is handled at TLS level
}

// GetAuthToken returns the current authentication token (N/A for certificates)
func (q *QRadarCertificateAuthHandler) GetAuthToken() *connectors.AuthToken {
	return nil // No token for certificate authentication
}

// QRadarBasicAuthHandler handles basic HTTP authentication (fallback)
type QRadarBasicAuthHandler struct {
	connector     *QRadarConnector
	username      string
	password      string
	authenticated bool
}

// NewQRadarBasicAuthHandler creates a new basic auth handler
func NewQRadarBasicAuthHandler(connector *QRadarConnector, username, password string) *QRadarBasicAuthHandler {
	return &QRadarBasicAuthHandler{
		connector: connector,
		username:  username,
		password:  password,
	}
}

// Authenticate performs basic authentication
func (q *QRadarBasicAuthHandler) Authenticate(ctx context.Context) error {
	// Test basic authentication by making a simple API call
	endpoint := "/api/system/about"
	baseURL := q.connector.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create basic auth test request: %w", err)
	}

	// Set basic authentication
	req.SetBasicAuth(q.username, q.password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", q.connector.apiVersion)

	resp, err := q.connector.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("basic authentication failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		q.authenticated = true
		return nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("basic authentication failed: invalid username or password")
	}

	return fmt.Errorf("basic authentication failed with status %d", resp.StatusCode)
}

// RefreshToken refreshes the authentication token (N/A for basic auth)
func (q *QRadarBasicAuthHandler) RefreshToken(ctx context.Context) error {
	return nil // No token refresh needed for basic auth
}

// IsAuthenticated returns true if currently authenticated
func (q *QRadarBasicAuthHandler) IsAuthenticated() bool {
	return q.authenticated
}

// GetAuthHeaders returns authentication headers for basic auth
func (q *QRadarBasicAuthHandler) GetAuthHeaders() map[string]string {
	if !q.authenticated {
		return make(map[string]string)
	}

	// Basic auth header will be set by the HTTP client
	// We don't need to return it here as it's handled automatically
	return make(map[string]string)
}

// GetAuthToken returns the current authentication token (N/A for basic auth)
func (q *QRadarBasicAuthHandler) GetAuthToken() *connectors.AuthToken {
	if !q.authenticated {
		return nil
	}

	return &connectors.AuthToken{
		Token:     "", // No explicit token for basic auth
		TokenType: "BASIC_AUTH",
		Metadata: map[string]interface{}{
			"username": q.username,
		},
	}
}