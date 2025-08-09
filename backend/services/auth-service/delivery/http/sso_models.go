package http

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
)

// SSO Provider Management Models

type CreateProviderRequest struct {
	Name             string                      `json:"name" binding:"required,min=1,max=100"`
	DisplayName      string                      `json:"display_name" binding:"required,min=1,max=200"`
	Description      string                      `json:"description,omitempty"`
	Type             entity.IdentityProviderType `json:"type" binding:"required"`
	Configuration    map[string]interface{}      `json:"configuration" binding:"required"`
	AttributeMapping map[string]string           `json:"attribute_mapping,omitempty"`
	EnableJIT        bool                        `json:"enable_jit"`
	IsDefault        bool                        `json:"is_default"`
}

type UpdateProviderRequest struct {
	Name             string                        `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	DisplayName      string                        `json:"display_name,omitempty" binding:"omitempty,min=1,max=200"`
	Description      string                        `json:"description,omitempty"`
	Configuration    map[string]interface{}        `json:"configuration,omitempty"`
	AttributeMapping map[string]string             `json:"attribute_mapping,omitempty"`
	Status           entity.IdentityProviderStatus `json:"status,omitempty"`
	EnableJIT        *bool                         `json:"enable_jit,omitempty"`
	IsDefault        *bool                         `json:"is_default,omitempty"`
}

type ProviderResponse struct {
	ID               uuid.UUID                     `json:"id"`
	Name             string                        `json:"name"`
	DisplayName      string                        `json:"display_name"`
	Description      string                        `json:"description"`
	Type             entity.IdentityProviderType   `json:"type"`
	Status           entity.IdentityProviderStatus `json:"status"`
	LoginURL         string                        `json:"login_url"`
	CallbackURL      string                        `json:"callback_url"`
	MetadataURL      string                        `json:"metadata_url,omitempty"`
	IsDefault        bool                          `json:"is_default"`
	Priority         int                           `json:"priority"`
	EnableJIT        bool                          `json:"enable_jit"`
	AttributeMapping map[string]string             `json:"attribute_mapping,omitempty"`
	SessionTimeout   time.Duration                 `json:"session_timeout"`
	LastUsedAt       *time.Time                    `json:"last_used_at,omitempty"`
	UsageCount       int64                         `json:"usage_count"`
	ErrorCount       int64                         `json:"error_count"`
	CreatedAt        time.Time                     `json:"created_at"`
	UpdatedAt        time.Time                     `json:"updated_at"`
}

type ProvidersListResponse struct {
	Providers []ProviderResponse `json:"providers"`
	Total     int                `json:"total"`
}

type ProviderTestResponse struct {
	Success         bool                   `json:"success"`
	TestType        string                 `json:"test_type"`
	TestResults     map[string]interface{} `json:"test_results"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
}

// SSO Authentication Models

type InitiateLoginRequest struct {
	ProviderID  uuid.UUID `json:"provider_id" binding:"required"`
	RelayState  string    `json:"relay_state,omitempty"`
	ForceAuthn  bool      `json:"force_authn"`
	RedirectURL string    `json:"redirect_url,omitempty"`
}

type InitiateLoginResponse struct {
	RedirectURL   string    `json:"redirect_url"`
	RequestID     string    `json:"request_id"`
	State         string    `json:"state,omitempty"`
	CodeChallenge string    `json:"code_challenge,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type SSOCallbackRequest struct {
	ProviderID   uuid.UUID              `json:"provider_id" binding:"required"`
	SAMLResponse string                 `json:"saml_response,omitempty"`
	RelayState   string                 `json:"relay_state,omitempty"`
	Code         string                 `json:"code,omitempty"`
	State        string                 `json:"state,omitempty"`
	CodeVerifier string                 `json:"code_verifier,omitempty"`
	CallbackData map[string]interface{} `json:"callback_data,omitempty"`
}

type SSOCallbackResponse struct {
	Success          bool                   `json:"success"`
	UserID           uuid.UUID              `json:"user_id,omitempty"`
	SessionID        string                 `json:"session_id,omitempty"`
	AccessToken      string                 `json:"access_token,omitempty"`
	RefreshToken     string                 `json:"refresh_token,omitempty"`
	ExpiresIn        int64                  `json:"expires_in,omitempty"`
	User             *UserProfileResponse   `json:"user,omitempty"`
	FederatedUser    *FederatedUserResponse `json:"federated_user,omitempty"`
	IsNewUser        bool                   `json:"is_new_user"`
	RequiresMFA      bool                   `json:"requires_mfa"`
	ErrorCode        string                 `json:"error_code,omitempty"`
	ErrorDescription string                 `json:"error_description,omitempty"`
}

type UserProfileResponse struct {
	ID                uuid.UUID                     `json:"id"`
	Email             string                        `json:"email"`
	FirstName         string                        `json:"first_name"`
	LastName          string                        `json:"last_name"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance"`
	Roles             []string                      `json:"roles"`
	IsActive          bool                          `json:"is_active"`
}

type FederatedUserResponse struct {
	ID               uuid.UUID                     `json:"id"`
	ExternalID       string                        `json:"external_id"`
	ExternalUsername string                        `json:"external_username"`
	ExternalEmail    string                        `json:"external_email"`
	ProviderID       uuid.UUID                     `json:"provider_id"`
	MappedRoles      []string                      `json:"mapped_roles"`
	MappedClearance  entity.SecurityClearanceLevel `json:"mapped_clearance"`
	LastLoginAt      *time.Time                    `json:"last_login_at,omitempty"`
	LoginCount       int64                         `json:"login_count"`
}

// SSO Session Models

type SSOSessionResponse struct {
	ID                uuid.UUID                   `json:"id"`
	SessionID         string                      `json:"session_id"`
	UserID            uuid.UUID                   `json:"user_id"`
	ProviderID        uuid.UUID                   `json:"provider_id"`
	ExternalSessionID string                      `json:"external_session_id,omitempty"`
	LoginMethod       entity.IdentityProviderType `json:"login_method"`
	IPAddress         string                      `json:"ip_address"`
	UserAgent         string                      `json:"user_agent"`
	Location          string                      `json:"location,omitempty"`
	IsActive          bool                        `json:"is_active"`
	ExpiresAt         time.Time                   `json:"expires_at"`
	LastActivityAt    time.Time                   `json:"last_activity_at"`
	CreatedAt         time.Time                   `json:"created_at"`
}

type SSOSessionsListResponse struct {
	Sessions []SSOSessionResponse `json:"sessions"`
	Total    int                  `json:"total"`
}

type SSOSessionValidationResponse struct {
	Valid             bool                          `json:"valid"`
	Session           *SSOSessionResponse           `json:"session,omitempty"`
	User              *UserProfileResponse          `json:"user,omitempty"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance,omitempty"`
	ErrorReason       string                        `json:"error_reason,omitempty"`
}

// User Management Models

type LinkProviderRequest struct {
	ProviderID       uuid.UUID `json:"provider_id" binding:"required"`
	ExternalID       string    `json:"external_id" binding:"required"`
	ExternalUsername string    `json:"external_username,omitempty"`
	ExternalEmail    string    `json:"external_email,omitempty"`
}

type UnlinkProviderRequest struct {
	ProviderID uuid.UUID `json:"provider_id" binding:"required"`
}

type FederatedUsersListResponse struct {
	FederatedUsers []FederatedUserResponse `json:"federated_users"`
	Total          int                     `json:"total"`
}

// Attribute Mapping Models

type CreateAttributeMappingRequest struct {
	ProviderID        uuid.UUID `json:"provider_id" binding:"required"`
	ExternalAttribute string    `json:"external_attribute" binding:"required,min=1,max=255"`
	InternalAttribute string    `json:"internal_attribute" binding:"required,min=1,max=255"`
	AttributeType     string    `json:"attribute_type" binding:"required"`
	TransformRule     string    `json:"transform_rule,omitempty"`
	DefaultValue      string    `json:"default_value,omitempty"`
	Required          bool      `json:"required"`
	ValidationRegex   string    `json:"validation_regex,omitempty"`
	AllowedValues     []string  `json:"allowed_values,omitempty"`
}

type UpdateAttributeMappingRequest struct {
	ExternalAttribute string   `json:"external_attribute,omitempty" binding:"omitempty,min=1,max=255"`
	InternalAttribute string   `json:"internal_attribute,omitempty" binding:"omitempty,min=1,max=255"`
	AttributeType     string   `json:"attribute_type,omitempty"`
	TransformRule     string   `json:"transform_rule,omitempty"`
	DefaultValue      string   `json:"default_value,omitempty"`
	Required          *bool    `json:"required,omitempty"`
	ValidationRegex   string   `json:"validation_regex,omitempty"`
	AllowedValues     []string `json:"allowed_values,omitempty"`
}

type AttributeMappingResponse struct {
	ID                uuid.UUID `json:"id"`
	ProviderID        uuid.UUID `json:"provider_id"`
	ExternalAttribute string    `json:"external_attribute"`
	InternalAttribute string    `json:"internal_attribute"`
	AttributeType     string    `json:"attribute_type"`
	TransformRule     string    `json:"transform_rule,omitempty"`
	DefaultValue      string    `json:"default_value,omitempty"`
	Required          bool      `json:"required"`
	ValidationRegex   string    `json:"validation_regex,omitempty"`
	AllowedValues     []string  `json:"allowed_values,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type AttributeMappingsListResponse struct {
	Mappings []AttributeMappingResponse `json:"mappings"`
	Total    int                        `json:"total"`
}

// SAML-specific Models

type SAMLMetadataRequest struct {
	ServiceName        string `json:"service_name,omitempty"`
	ServiceDescription string `json:"service_description,omitempty"`
	ContactEmail       string `json:"contact_email,omitempty"`
}

type SAMLMetadataResponse struct {
	Metadata string `json:"metadata"`
}

type SAMLAssertionRequest struct {
	SAMLResponse string `json:"saml_response" binding:"required"`
	RelayState   string `json:"relay_state,omitempty"`
}

// OIDC-specific Models

type OIDCConfigurationResponse struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	JWKSUri                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
}

// Error Models

type SSOErrorResponse struct {
	ErrorCode    string `json:"error_code"`
	ErrorMessage string `json:"error_message"`
	Details      string `json:"details,omitempty"`
	Timestamp    string `json:"timestamp"`
}

// Validation helper functions

func (r *CreateProviderRequest) Validate() error {
	if !entity.ValidateIdentityProviderType(string(r.Type)) {
		return fmt.Errorf("invalid provider type: %s", r.Type)
	}

	// Type-specific validation
	if entity.IsSAMLProvider(r.Type) {
		return r.validateSAMLConfiguration()
	} else if entity.IsOIDCProvider(r.Type) {
		return r.validateOIDCConfiguration()
	} else if entity.IsSocialProvider(r.Type) {
		return r.validateSocialConfiguration()
	}

	return nil
}

func (r *CreateProviderRequest) validateSAMLConfiguration() error {
	if _, exists := r.Configuration["idp_metadata_url"]; !exists {
		if _, exists := r.Configuration["idp_metadata"]; !exists {
			return fmt.Errorf("either idp_metadata_url or idp_metadata is required for SAML providers")
		}
	}

	if _, exists := r.Configuration["entity_id"]; !exists {
		return fmt.Errorf("entity_id is required for SAML providers")
	}

	return nil
}

func (r *CreateProviderRequest) validateOIDCConfiguration() error {
	requiredFields := []string{"client_id", "client_secret", "issuer_url"}
	for _, field := range requiredFields {
		if _, exists := r.Configuration[field]; !exists {
			return fmt.Errorf("%s is required for OIDC providers", field)
		}
	}

	return nil
}

func (r *CreateProviderRequest) validateSocialConfiguration() error {
	requiredFields := []string{"client_id", "client_secret"}
	for _, field := range requiredFields {
		if _, exists := r.Configuration[field]; !exists {
			return fmt.Errorf("%s is required for social providers", field)
		}
	}

	return nil
}

func (r *CreateAttributeMappingRequest) Validate() error {
	validTypes := []string{"user", "role", "clearance", "group", "permission", "custom"}
	for _, validType := range validTypes {
		if r.AttributeType == validType {
			return nil
		}
	}

	return fmt.Errorf("invalid attribute type: %s", r.AttributeType)
}
