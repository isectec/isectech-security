package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// OIDCProvider implements OpenID Connect authentication functionality
type OIDCProvider struct {
	config     *OIDCConfig
	providers  map[string]*OIDCProviderClient // keyed by provider ID
	httpClient *http.Client
}

// OIDCConfig holds OIDC provider configuration
type OIDCConfig struct {
	BaseURL                string        `yaml:"base_url"`
	DefaultScopes          []string      `yaml:"default_scopes" default:"openid,profile,email"`
	PKCEEnabled            bool          `yaml:"pkce_enabled" default:"true"`
	StateTimeout           time.Duration `yaml:"state_timeout" default:"10m"`
	TokenTimeout           time.Duration `yaml:"token_timeout" default:"30s"`
	UserInfoTimeout        time.Duration `yaml:"userinfo_timeout" default:"10s"`
	DiscoveryTimeout       time.Duration `yaml:"discovery_timeout" default:"30s"`
	SkipIssuerVerification bool          `yaml:"skip_issuer_verification" default:"false"`
	HTTPTimeout            time.Duration `yaml:"http_timeout" default:"30s"`
}

// OIDCProviderClient represents a configured OIDC provider
type OIDCProviderClient struct {
	Provider     *oidc.Provider
	OAuth2Config *oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	Config       *entity.IdentityProvider
}

// SocialProviderConfig contains predefined configurations for social providers
var SocialProviderConfigs = map[entity.IdentityProviderType]SocialProviderInfo{
	entity.IdentityProviderGoogle: {
		Name:        "Google",
		IssuerURL:   "https://accounts.google.com",
		Scopes:      []string{"openid", "profile", "email"},
		UserInfoURL: "https://www.googleapis.com/oauth2/v1/userinfo",
	},
	entity.IdentityProviderMicrosoft: {
		Name:        "Microsoft",
		IssuerURL:   "https://login.microsoftonline.com/common/v2.0",
		Scopes:      []string{"openid", "profile", "email"},
		UserInfoURL: "",
	},
	entity.IdentityProviderGitHub: {
		Name:        "GitHub",
		IssuerURL:   "", // GitHub doesn't support OIDC discovery
		Scopes:      []string{"user:email"},
		UserInfoURL: "https://api.github.com/user",
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
	},
}

// SocialProviderInfo contains information about social providers
type SocialProviderInfo struct {
	Name        string
	IssuerURL   string
	Scopes      []string
	UserInfoURL string
	AuthURL     string
	TokenURL    string
}

// NewOIDCProvider creates a new OIDC provider
func NewOIDCProvider(config *OIDCConfig) *OIDCProvider {
	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
	}

	return &OIDCProvider{
		config:     config,
		providers:  make(map[string]*OIDCProviderClient),
		httpClient: httpClient,
	}
}

// GenerateAuthorizationURL generates an OIDC authorization URL
func (p *OIDCProvider) GenerateAuthorizationURL(ctx context.Context, req *service.OIDCAuthorizationRequest) (*service.OIDCAuthorizationResponse, error) {
	client, err := p.getProviderClient(ctx, req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider client: %w", err)
	}

	// Generate state parameter
	state := req.State
	if state == "" {
		state = p.generateRandomString(32)
	}

	// Prepare OAuth2 config options
	var opts []oauth2.AuthCodeOption

	// Add PKCE if enabled
	var codeVerifier string
	if p.config.PKCEEnabled {
		codeVerifier = p.generateCodeVerifier()
		codeChallenge := p.generateCodeChallenge(codeVerifier)
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	// Add nonce if provided
	if req.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", req.Nonce))
	}

	// Custom scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = client.OAuth2Config.Scopes
	}

	// Generate authorization URL
	authURL := client.OAuth2Config.AuthCodeURL(state, opts...)

	return &service.OIDCAuthorizationResponse{
		AuthorizationURL: authURL,
		State:            state,
		CodeVerifier:     codeVerifier,
	}, nil
}

// ExchangeCodeForToken exchanges authorization code for tokens
func (p *OIDCProvider) ExchangeCodeForToken(ctx context.Context, req *service.OIDCTokenRequest) (*service.OIDCTokenResponse, error) {
	client, err := p.getProviderClient(ctx, req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider client: %w", err)
	}

	// Prepare token exchange options
	var opts []oauth2.AuthCodeOption
	if req.CodeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", req.CodeVerifier))
	}

	// Exchange code for token
	token, err := client.OAuth2Config.Exchange(ctx, req.Code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in oauth2 token")
	}

	return &service.OIDCTokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      rawIDToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int64(time.Until(token.Expiry).Seconds()),
		Scope:        strings.Join(client.OAuth2Config.Scopes, " "),
	}, nil
}

// ValidateIDToken validates an OIDC ID token
func (p *OIDCProvider) ValidateIDToken(ctx context.Context, req *service.OIDCTokenValidationRequest) (*service.OIDCTokenValidationResponse, error) {
	client, err := p.getProviderClient(ctx, req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider client: %w", err)
	}

	// Verify ID token
	idToken, err := client.Verifier.Verify(ctx, req.IDToken)
	if err != nil {
		return &service.OIDCTokenValidationResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("failed to verify ID token: %v", err),
		}, nil
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return &service.OIDCTokenValidationResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("failed to extract claims: %v", err),
		}, nil
	}

	// Validate nonce if provided
	if req.Nonce != "" {
		if nonce, ok := claims["nonce"].(string); !ok || nonce != req.Nonce {
			return &service.OIDCTokenValidationResponse{
				Valid:        false,
				ErrorMessage: "nonce validation failed",
			}, nil
		}
	}

	// Extract standard claims
	subject := idToken.Subject
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)

	return &service.OIDCTokenValidationResponse{
		Valid:         true,
		Claims:        claims,
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
	}, nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func (p *OIDCProvider) RefreshAccessToken(ctx context.Context, req *service.OIDCRefreshRequest) (*service.OIDCRefreshResponse, error) {
	client, err := p.getProviderClient(ctx, req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider client: %w", err)
	}

	// Create token source with refresh token
	token := &oauth2.Token{
		RefreshToken: req.RefreshToken,
	}

	// Refresh the token
	tokenSource := client.OAuth2Config.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	response := &service.OIDCRefreshResponse{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		TokenType:    newToken.TokenType,
		ExpiresIn:    int64(time.Until(newToken.Expiry).Seconds()),
	}

	// Include new ID token if present
	if rawIDToken, ok := newToken.Extra("id_token").(string); ok {
		response.IDToken = rawIDToken
	}

	return response, nil
}

// GetUserInfo retrieves user information using an access token
func (p *OIDCProvider) GetUserInfo(ctx context.Context, req *service.OIDCUserInfoRequest) (*service.OIDCUserInfoResponse, error) {
	client, err := p.getProviderClient(ctx, req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider client: %w", err)
	}

	// For social providers that don't support OIDC UserInfo, use custom endpoints
	providerType := entity.IdentityProviderType(client.Config.Type)
	if providerType == entity.IdentityProviderGitHub {
		return p.getGitHubUserInfo(ctx, req.AccessToken)
	}

	// Standard OIDC UserInfo endpoint
	userInfo, err := client.Provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: req.AccessToken,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract user info claims: %w", err)
	}

	// Extract standard fields
	subject := userInfo.Subject
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)

	return &service.OIDCUserInfoResponse{
		UserInfo:      claims,
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
	}, nil
}

// GetProviderConfiguration retrieves OIDC provider configuration
func (p *OIDCProvider) GetProviderConfiguration(ctx context.Context, issuerURL string) (*service.OIDCProviderConfiguration, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider configuration: %w", err)
	}

	endpoint := provider.Endpoint()

	var claims struct {
		Issuer                           string   `json:"issuer"`
		AuthURL                          string   `json:"authorization_endpoint"`
		TokenURL                         string   `json:"token_endpoint"`
		UserInfoURL                      string   `json:"userinfo_endpoint"`
		JWKSURL                          string   `json:"jwks_uri"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
		ScopesSupported                  []string `json:"scopes_supported"`
		ClaimsSupported                  []string `json:"claims_supported"`
		EndSessionEndpoint               string   `json:"end_session_endpoint"`
	}

	if err := provider.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to get provider claims: %w", err)
	}

	return &service.OIDCProviderConfiguration{
		Issuer:                           claims.Issuer,
		AuthorizationEndpoint:            endpoint.AuthURL,
		TokenEndpoint:                    endpoint.TokenURL,
		UserInfoEndpoint:                 claims.UserInfoURL,
		JWKSUri:                          claims.JWKSURL,
		ResponseTypesSupported:           claims.ResponseTypesSupported,
		SubjectTypesSupported:            claims.SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported: claims.IDTokenSigningAlgValuesSupported,
		ScopesSupported:                  claims.ScopesSupported,
		ClaimsSupported:                  claims.ClaimsSupported,
		EndSessionEndpoint:               claims.EndSessionEndpoint,
	}, nil
}

// ValidateProviderConfiguration validates OIDC provider configuration
func (p *OIDCProvider) ValidateProviderConfiguration(ctx context.Context, config *service.OIDCProviderConfiguration) error {
	// Validate required endpoints
	if config.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if config.AuthorizationEndpoint == "" {
		return fmt.Errorf("authorization endpoint is required")
	}
	if config.TokenEndpoint == "" {
		return fmt.Errorf("token endpoint is required")
	}
	if config.JWKSUri == "" {
		return fmt.Errorf("JWKS URI is required")
	}

	// Validate that endpoints are HTTPS in production
	endpoints := []string{
		config.AuthorizationEndpoint,
		config.TokenEndpoint,
		config.JWKSUri,
	}

	for _, endpoint := range endpoints {
		if u, err := url.Parse(endpoint); err != nil {
			return fmt.Errorf("invalid endpoint URL %s: %w", endpoint, err)
		} else if u.Scheme != "https" {
			return fmt.Errorf("endpoint must use HTTPS: %s", endpoint)
		}
	}

	return nil
}

// Helper methods

func (p *OIDCProvider) getProviderClient(ctx context.Context, providerID string, tenantID uuid.UUID) (*OIDCProviderClient, error) {
	key := fmt.Sprintf("%s:%s", tenantID.String(), providerID)

	client, exists := p.providers[key]
	if !exists {
		// Create new client for this provider/tenant combination
		var err error
		client, err = p.createProviderClient(ctx, tenantID, providerID)
		if err != nil {
			return nil, err
		}
		p.providers[key] = client
	}

	return client, nil
}

func (p *OIDCProvider) createProviderClient(ctx context.Context, tenantID uuid.UUID, providerID string) (*OIDCProviderClient, error) {
	// This would typically fetch the provider configuration from the database
	// For now, we'll use a placeholder implementation
	providerConfig := &entity.IdentityProvider{
		ID:       uuid.MustParse(providerID),
		TenantID: tenantID,
		Type:     entity.IdentityProviderGoogle, // Example
	}

	// Get social provider info if applicable
	socialInfo, isSocial := SocialProviderConfigs[providerConfig.Type]

	var provider *oidc.Provider
	var oauth2Config *oauth2.Config
	var err error

	if isSocial && socialInfo.IssuerURL != "" {
		// Standard OIDC provider
		provider, err = oidc.NewProvider(ctx, socialInfo.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}

		oauth2Config = &oauth2.Config{
			ClientID:     p.getClientID(providerConfig),
			ClientSecret: p.getClientSecret(providerConfig),
			RedirectURL:  fmt.Sprintf("%s/auth/sso/callback/%s", p.config.BaseURL, providerConfig.ID.String()),
			Endpoint:     provider.Endpoint(),
			Scopes:       socialInfo.Scopes,
		}
	} else if isSocial {
		// Custom OAuth2 provider (like GitHub)
		oauth2Config = &oauth2.Config{
			ClientID:     p.getClientID(providerConfig),
			ClientSecret: p.getClientSecret(providerConfig),
			RedirectURL:  fmt.Sprintf("%s/auth/sso/callback/%s", p.config.BaseURL, providerConfig.ID.String()),
			Scopes:       socialInfo.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  socialInfo.AuthURL,
				TokenURL: socialInfo.TokenURL,
			},
		}
	} else {
		// Custom OIDC provider
		issuerURL, _ := providerConfig.GetConfigValue("issuer_url")
		if issuerURL == nil {
			return nil, fmt.Errorf("issuer_url not configured for provider")
		}

		provider, err = oidc.NewProvider(ctx, issuerURL.(string))
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}

		oauth2Config = &oauth2.Config{
			ClientID:     p.getClientID(providerConfig),
			ClientSecret: p.getClientSecret(providerConfig),
			RedirectURL:  fmt.Sprintf("%s/auth/sso/callback/%s", p.config.BaseURL, providerConfig.ID.String()),
			Endpoint:     provider.Endpoint(),
			Scopes:       p.config.DefaultScopes,
		}
	}

	// Create ID token verifier
	var verifier *oidc.IDTokenVerifier
	if provider != nil {
		verifierConfig := &oidc.Config{
			ClientID:          oauth2Config.ClientID,
			SkipClientIDCheck: false,
			SkipExpiryCheck:   false,
			SkipIssuerCheck:   p.config.SkipIssuerVerification,
		}
		verifier = provider.Verifier(verifierConfig)
	}

	return &OIDCProviderClient{
		Provider:     provider,
		OAuth2Config: oauth2Config,
		Verifier:     verifier,
		Config:       providerConfig,
	}, nil
}

func (p *OIDCProvider) getClientID(config *entity.IdentityProvider) string {
	clientID, _ := config.GetConfigValue("client_id")
	if clientID != nil {
		return clientID.(string)
	}
	return ""
}

func (p *OIDCProvider) getClientSecret(config *entity.IdentityProvider) string {
	clientSecret, _ := config.GetConfigValue("client_secret")
	if clientSecret != nil {
		return clientSecret.(string)
	}
	return ""
}

func (p *OIDCProvider) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func (p *OIDCProvider) generateCodeVerifier() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.WithoutPadding().EncodeToString(bytes)
}

func (p *OIDCProvider) generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithoutPadding().EncodeToString(hash[:])
}

// GitHub-specific user info retrieval
func (p *OIDCProvider) getGitHubUserInfo(ctx context.Context, accessToken string) (*service.OIDCUserInfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Extract email separately if needed
	email, _ := userInfo["email"].(string)
	if email == "" {
		email = p.getGitHubPrimaryEmail(ctx, accessToken)
	}

	return &service.OIDCUserInfoResponse{
		UserInfo:      userInfo,
		Subject:       fmt.Sprintf("%v", userInfo["id"]),
		Email:         email,
		EmailVerified: true, // GitHub emails are typically verified
	}, nil
}

func (p *OIDCProvider) getGitHubPrimaryEmail(ctx context.Context, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return ""
	}

	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var emails []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return ""
	}

	// Find primary verified email
	for _, email := range emails {
		if primary, ok := email["primary"].(bool); ok && primary {
			if verified, ok := email["verified"].(bool); ok && verified {
				if emailAddr, ok := email["email"].(string); ok {
					return emailAddr
				}
			}
		}
	}

	return ""
}
