package entity

import (
	"time"

	"github.com/google/uuid"
)

// IdentityProviderType represents the type of identity provider
type IdentityProviderType string

const (
	IdentityProviderSAML      IdentityProviderType = "saml"
	IdentityProviderOIDC      IdentityProviderType = "oidc"
	IdentityProviderGoogle    IdentityProviderType = "google"
	IdentityProviderMicrosoft IdentityProviderType = "microsoft"
	IdentityProviderGitHub    IdentityProviderType = "github"
	IdentityProviderOkta      IdentityProviderType = "okta"
	IdentityProviderAuth0     IdentityProviderType = "auth0"
	IdentityProviderAzureAD   IdentityProviderType = "azure_ad"
	IdentityProviderADFS      IdentityProviderType = "adfs"
	IdentityProviderPingID    IdentityProviderType = "ping_identity"
)

// IdentityProviderStatus represents the status of an identity provider
type IdentityProviderStatus string

const (
	IdentityProviderStatusActive     IdentityProviderStatus = "active"
	IdentityProviderStatusInactive   IdentityProviderStatus = "inactive"
	IdentityProviderStatusTesting    IdentityProviderStatus = "testing"
	IdentityProviderStatusDeprecated IdentityProviderStatus = "deprecated"
	IdentityProviderStatusError      IdentityProviderStatus = "error"
)

// IdentityProvider represents an external identity provider configuration
type IdentityProvider struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Name        string                 `json:"name" db:"name"`
	DisplayName string                 `json:"display_name" db:"display_name"`
	Description string                 `json:"description" db:"description"`
	Type        IdentityProviderType   `json:"type" db:"type"`
	Status      IdentityProviderStatus `json:"status" db:"status"`

	// Provider configuration
	Configuration map[string]interface{} `json:"configuration" db:"configuration"`

	// Metadata and certificates
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
	Certificate string                 `json:"certificate,omitempty" db:"certificate"`
	PrivateKey  string                 `json:"-" db:"private_key"` // Never expose in JSON

	// Endpoints
	LoginURL    string `json:"login_url" db:"login_url"`
	LogoutURL   string `json:"logout_url" db:"logout_url"`
	CallbackURL string `json:"callback_url" db:"callback_url"`
	MetadataURL string `json:"metadata_url" db:"metadata_url"`

	// Settings
	IsDefault bool `json:"is_default" db:"is_default"`
	Priority  int  `json:"priority" db:"priority"`
	EnableJIT bool `json:"enable_jit" db:"enable_jit"` // Just-In-Time provisioning

	// Attribute mapping
	AttributeMapping map[string]string `json:"attribute_mapping" db:"attribute_mapping"`

	// Security settings
	RequireSecureCert bool `json:"require_secure_cert" db:"require_secure_cert"`
	ValidateSignature bool `json:"validate_signature" db:"validate_signature"`
	EncryptAssertions bool `json:"encrypt_assertions" db:"encrypt_assertions"`

	// Session management
	SessionTimeout time.Duration `json:"session_timeout" db:"session_timeout"`
	ForceLogout    bool          `json:"force_logout" db:"force_logout"`

	// Audit and monitoring
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty" db:"last_error_at"`
	LastError   string     `json:"last_error,omitempty" db:"last_error"`
	UsageCount  int64      `json:"usage_count" db:"usage_count"`
	ErrorCount  int64      `json:"error_count" db:"error_count"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy uuid.UUID `json:"created_by" db:"created_by"`
	UpdatedBy uuid.UUID `json:"updated_by" db:"updated_by"`
}

// FederatedUser represents a user from an external identity provider
type FederatedUser struct {
	ID         uuid.UUID `json:"id" db:"id"`
	UserID     uuid.UUID `json:"user_id" db:"user_id"`
	TenantID   uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ProviderID uuid.UUID `json:"provider_id" db:"provider_id"`

	// External identity information
	ExternalID       string `json:"external_id" db:"external_id"`
	ExternalUsername string `json:"external_username" db:"external_username"`
	ExternalEmail    string `json:"external_email" db:"external_email"`

	// Claims and attributes from the provider
	Claims     map[string]interface{} `json:"claims" db:"claims"`
	Attributes map[string]string      `json:"attributes" db:"attributes"`

	// Session information
	LastLoginAt     *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	LastTokenAt     *time.Time `json:"last_token_at,omitempty" db:"last_token_at"`
	TokenExpiration *time.Time `json:"token_expiration,omitempty" db:"token_expiration"`

	// Mapping information
	MappedRoles     []string               `json:"mapped_roles" db:"mapped_roles"`
	MappedClearance SecurityClearanceLevel `json:"mapped_clearance" db:"mapped_clearance"`

	// Status and audit
	IsActive   bool  `json:"is_active" db:"is_active"`
	LoginCount int64 `json:"login_count" db:"login_count"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SSOSession represents an SSO session
type SSOSession struct {
	ID         uuid.UUID `json:"id" db:"id"`
	UserID     uuid.UUID `json:"user_id" db:"user_id"`
	TenantID   uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ProviderID uuid.UUID `json:"provider_id" db:"provider_id"`
	SessionID  string    `json:"session_id" db:"session_id"`

	// External session information
	ExternalSessionID string `json:"external_session_id" db:"external_session_id"`
	SAMLSessionIndex  string `json:"saml_session_index,omitempty" db:"saml_session_index"`
	OIDCIdToken       string `json:"-" db:"oidc_id_token"` // Encrypted in DB

	// Session metadata
	LoginMethod IdentityProviderType   `json:"login_method" db:"login_method"`
	AuthContext map[string]interface{} `json:"auth_context" db:"auth_context"`

	// Security context
	IPAddress string `json:"ip_address" db:"ip_address"`
	UserAgent string `json:"user_agent" db:"user_agent"`
	Location  string `json:"location" db:"location"`

	// Session lifecycle
	IsActive       bool      `json:"is_active" db:"is_active"`
	ExpiresAt      time.Time `json:"expires_at" db:"expires_at"`
	LastActivityAt time.Time `json:"last_activity_at" db:"last_activity_at"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// AttributeMapping represents how external attributes map to internal user properties
type AttributeMapping struct {
	ID         uuid.UUID `json:"id" db:"id"`
	ProviderID uuid.UUID `json:"provider_id" db:"provider_id"`
	TenantID   uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// Mapping configuration
	ExternalAttribute string `json:"external_attribute" db:"external_attribute"`
	InternalAttribute string `json:"internal_attribute" db:"internal_attribute"`
	AttributeType     string `json:"attribute_type" db:"attribute_type"` // user, role, clearance, etc.

	// Transformation rules
	TransformRule string `json:"transform_rule,omitempty" db:"transform_rule"`
	DefaultValue  string `json:"default_value,omitempty" db:"default_value"`
	Required      bool   `json:"required" db:"required"`

	// Validation
	ValidationRegex string   `json:"validation_regex,omitempty" db:"validation_regex"`
	AllowedValues   []string `json:"allowed_values,omitempty" db:"allowed_values"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Methods for IdentityProvider

// IsActive returns whether the provider is active
func (p *IdentityProvider) IsActive() bool {
	return p.Status == IdentityProviderStatusActive
}

// IsTesting returns whether the provider is in testing mode
func (p *IdentityProvider) IsTesting() bool {
	return p.Status == IdentityProviderStatusTesting
}

// CanAuthenticate returns whether the provider can be used for authentication
func (p *IdentityProvider) CanAuthenticate() bool {
	return p.Status == IdentityProviderStatusActive || p.Status == IdentityProviderStatusTesting
}

// GetConfigValue retrieves a configuration value
func (p *IdentityProvider) GetConfigValue(key string) (interface{}, bool) {
	value, exists := p.Configuration[key]
	return value, exists
}

// SetConfigValue sets a configuration value
func (p *IdentityProvider) SetConfigValue(key string, value interface{}) {
	if p.Configuration == nil {
		p.Configuration = make(map[string]interface{})
	}
	p.Configuration[key] = value
}

// GetMetadataValue retrieves a metadata value
func (p *IdentityProvider) GetMetadataValue(key string) (interface{}, bool) {
	value, exists := p.Metadata[key]
	return value, exists
}

// IncrementUsage increments the usage counter
func (p *IdentityProvider) IncrementUsage() {
	p.UsageCount++
	p.LastUsedAt = &time.Time{}
	*p.LastUsedAt = time.Now()
	p.UpdatedAt = time.Now()
}

// RecordError records an error
func (p *IdentityProvider) RecordError(errorMsg string) {
	p.ErrorCount++
	p.LastError = errorMsg
	p.LastErrorAt = &time.Time{}
	*p.LastErrorAt = time.Now()
	p.UpdatedAt = time.Now()
}

// GetAttributeMapping returns the mapping for a specific attribute
func (p *IdentityProvider) GetAttributeMapping(externalAttribute string) (string, bool) {
	internalAttribute, exists := p.AttributeMapping[externalAttribute]
	return internalAttribute, exists
}

// Methods for FederatedUser

// IsActive returns whether the federated user is active
func (u *FederatedUser) IsActive() bool {
	return u.IsActive
}

// GetClaim retrieves a claim value
func (u *FederatedUser) GetClaim(claim string) (interface{}, bool) {
	value, exists := u.Claims[claim]
	return value, exists
}

// GetAttribute retrieves an attribute value
func (u *FederatedUser) GetAttribute(attribute string) (string, bool) {
	value, exists := u.Attributes[attribute]
	return value, exists
}

// UpdateLoginInfo updates login information
func (u *FederatedUser) UpdateLoginInfo() {
	u.LoginCount++
	now := time.Now()
	u.LastLoginAt = &now
	u.UpdatedAt = now
}

// Methods for SSOSession

// IsExpired returns whether the session is expired
func (s *SSOSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive returns whether the session is active and not expired
func (s *SSOSession) IsActive() bool {
	return s.IsActive && !s.IsExpired()
}

// UpdateActivity updates the last activity timestamp
func (s *SSOSession) UpdateActivity() {
	s.LastActivityAt = time.Now()
	s.UpdatedAt = time.Now()
}

// Terminate terminates the session
func (s *SSOSession) Terminate() {
	s.IsActive = false
	s.UpdatedAt = time.Now()
}

// GetAuthContextValue retrieves a value from the auth context
func (s *SSOSession) GetAuthContextValue(key string) (interface{}, bool) {
	value, exists := s.AuthContext[key]
	return value, exists
}

// SetAuthContextValue sets a value in the auth context
func (s *SSOSession) SetAuthContextValue(key string, value interface{}) {
	if s.AuthContext == nil {
		s.AuthContext = make(map[string]interface{})
	}
	s.AuthContext[key] = value
}

// Helper functions

// ValidateIdentityProviderType validates the identity provider type
func ValidateIdentityProviderType(providerType string) bool {
	validTypes := []IdentityProviderType{
		IdentityProviderSAML,
		IdentityProviderOIDC,
		IdentityProviderGoogle,
		IdentityProviderMicrosoft,
		IdentityProviderGitHub,
		IdentityProviderOkta,
		IdentityProviderAuth0,
		IdentityProviderAzureAD,
		IdentityProviderADFS,
		IdentityProviderPingID,
	}

	for _, validType := range validTypes {
		if string(validType) == providerType {
			return true
		}
	}

	return false
}

// GetProviderTypeFromString converts string to IdentityProviderType
func GetProviderTypeFromString(providerType string) (IdentityProviderType, bool) {
	if ValidateIdentityProviderType(providerType) {
		return IdentityProviderType(providerType), true
	}
	return "", false
}

// IsSAMLProvider returns whether the provider type is SAML-based
func IsSAMLProvider(providerType IdentityProviderType) bool {
	return providerType == IdentityProviderSAML ||
		providerType == IdentityProviderADFS ||
		providerType == IdentityProviderPingID
}

// IsOIDCProvider returns whether the provider type is OIDC-based
func IsOIDCProvider(providerType IdentityProviderType) bool {
	return providerType == IdentityProviderOIDC ||
		providerType == IdentityProviderGoogle ||
		providerType == IdentityProviderMicrosoft ||
		providerType == IdentityProviderGitHub ||
		providerType == IdentityProviderOkta ||
		providerType == IdentityProviderAuth0 ||
		providerType == IdentityProviderAzureAD
}

// IsSocialProvider returns whether the provider is a social login provider
func IsSocialProvider(providerType IdentityProviderType) bool {
	return providerType == IdentityProviderGoogle ||
		providerType == IdentityProviderMicrosoft ||
		providerType == IdentityProviderGitHub
}
