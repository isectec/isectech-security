package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
)

// SSOService defines the interface for Single Sign-On operations
type SSOService interface {
	// Provider management
	CreateProvider(ctx context.Context, req *CreateProviderRequest) (*CreateProviderResponse, error)
	UpdateProvider(ctx context.Context, req *UpdateProviderRequest) error
	DeleteProvider(ctx context.Context, providerID, tenantID uuid.UUID) error
	GetProvider(ctx context.Context, providerID, tenantID uuid.UUID) (*entity.IdentityProvider, error)
	ListProviders(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]*entity.IdentityProvider, error)
	TestProvider(ctx context.Context, providerID, tenantID uuid.UUID) (*ProviderTestResponse, error)

	// Authentication flows
	InitiateLogin(ctx context.Context, req *InitiateLoginRequest) (*InitiateLoginResponse, error)
	HandleCallback(ctx context.Context, req *CallbackRequest) (*CallbackResponse, error)
	InitiateLogout(ctx context.Context, req *InitiateLogoutRequest) (*InitiateLogoutResponse, error)
	HandleLogoutCallback(ctx context.Context, req *LogoutCallbackRequest) error

	// Session management
	ValidateSSOSession(ctx context.Context, sessionID string, tenantID uuid.UUID) (*SSOSessionValidationResponse, error)
	GetSSOSession(ctx context.Context, sessionID string, tenantID uuid.UUID) (*entity.SSOSession, error)
	TerminateSSOSession(ctx context.Context, sessionID string, tenantID uuid.UUID) error
	ListUserSSOSessions(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.SSOSession, error)

	// User provisioning
	ProvisionUser(ctx context.Context, req *ProvisionUserRequest) (*ProvisionUserResponse, error)
	UpdateFederatedUser(ctx context.Context, req *UpdateFederatedUserRequest) error
	GetFederatedUser(ctx context.Context, externalID string, providerID, tenantID uuid.UUID) (*entity.FederatedUser, error)
	LinkFederatedUser(ctx context.Context, req *LinkFederatedUserRequest) error
	UnlinkFederatedUser(ctx context.Context, userID, providerID, tenantID uuid.UUID) error

	// Attribute mapping
	CreateAttributeMapping(ctx context.Context, req *CreateAttributeMappingRequest) error
	UpdateAttributeMapping(ctx context.Context, req *UpdateAttributeMappingRequest) error
	DeleteAttributeMapping(ctx context.Context, mappingID, tenantID uuid.UUID) error
	ListAttributeMappings(ctx context.Context, providerID, tenantID uuid.UUID) ([]*entity.AttributeMapping, error)

	// Metadata management
	GetSAMLMetadata(ctx context.Context, providerID, tenantID uuid.UUID) (string, error)
	UpdateSAMLMetadata(ctx context.Context, providerID, tenantID uuid.UUID, metadata string) error
	GetOIDCConfiguration(ctx context.Context, providerID, tenantID uuid.UUID) (map[string]interface{}, error)
	RefreshProviderMetadata(ctx context.Context, providerID, tenantID uuid.UUID) error
}

// SAMLService defines SAML-specific operations
type SAMLService interface {
	// SAML authentication flow
	GenerateAuthNRequest(ctx context.Context, req *SAMLAuthNRequest) (*SAMLAuthNResponse, error)
	ValidateAssertion(ctx context.Context, req *SAMLAssertionRequest) (*SAMLAssertionResponse, error)

	// SAML logout flow
	GenerateLogoutRequest(ctx context.Context, req *SAMLLogoutRequest) (*SAMLLogoutResponse, error)
	ValidateLogoutResponse(ctx context.Context, req *SAMLLogoutValidationRequest) (*SAMLLogoutValidationResponse, error)

	// SAML metadata
	GenerateServiceProviderMetadata(ctx context.Context, req *SAMLMetadataRequest) (string, error)
	ValidateIdPMetadata(ctx context.Context, metadata string) (*SAMLMetadataValidationResponse, error)
}

// OIDCService defines OIDC-specific operations
type OIDCService interface {
	// OIDC authentication flow
	GenerateAuthorizationURL(ctx context.Context, req *OIDCAuthorizationRequest) (*OIDCAuthorizationResponse, error)
	ExchangeCodeForToken(ctx context.Context, req *OIDCTokenRequest) (*OIDCTokenResponse, error)
	ValidateIDToken(ctx context.Context, req *OIDCTokenValidationRequest) (*OIDCTokenValidationResponse, error)
	RefreshAccessToken(ctx context.Context, req *OIDCRefreshRequest) (*OIDCRefreshResponse, error)

	// OIDC user info
	GetUserInfo(ctx context.Context, req *OIDCUserInfoRequest) (*OIDCUserInfoResponse, error)

	// OIDC configuration
	GetProviderConfiguration(ctx context.Context, issuerURL string) (*OIDCProviderConfiguration, error)
	ValidateProviderConfiguration(ctx context.Context, config *OIDCProviderConfiguration) error
}

// Request/Response types

// Provider management
type CreateProviderRequest struct {
	TenantID         uuid.UUID                   `json:"tenant_id"`
	Name             string                      `json:"name"`
	DisplayName      string                      `json:"display_name"`
	Description      string                      `json:"description"`
	Type             entity.IdentityProviderType `json:"type"`
	Configuration    map[string]interface{}      `json:"configuration"`
	AttributeMapping map[string]string           `json:"attribute_mapping"`
	EnableJIT        bool                        `json:"enable_jit"`
	IsDefault        bool                        `json:"is_default"`
	CreatedBy        uuid.UUID                   `json:"created_by"`
}

type CreateProviderResponse struct {
	ProviderID  uuid.UUID `json:"provider_id"`
	CallbackURL string    `json:"callback_url"`
	MetadataURL string    `json:"metadata_url,omitempty"`
	LoginURL    string    `json:"login_url"`
}

type UpdateProviderRequest struct {
	ProviderID       uuid.UUID                     `json:"provider_id"`
	TenantID         uuid.UUID                     `json:"tenant_id"`
	Name             string                        `json:"name,omitempty"`
	DisplayName      string                        `json:"display_name,omitempty"`
	Description      string                        `json:"description,omitempty"`
	Configuration    map[string]interface{}        `json:"configuration,omitempty"`
	AttributeMapping map[string]string             `json:"attribute_mapping,omitempty"`
	Status           entity.IdentityProviderStatus `json:"status,omitempty"`
	EnableJIT        *bool                         `json:"enable_jit,omitempty"`
	IsDefault        *bool                         `json:"is_default,omitempty"`
	UpdatedBy        uuid.UUID                     `json:"updated_by"`
}

type ProviderTestResponse struct {
	Success         bool                   `json:"success"`
	TestType        string                 `json:"test_type"`
	TestResults     map[string]interface{} `json:"test_results"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
}

// Authentication flow
type InitiateLoginRequest struct {
	ProviderID uuid.UUID `json:"provider_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	RelayState string    `json:"relay_state,omitempty"`
	ForceAuthn bool      `json:"force_authn,omitempty"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
}

type InitiateLoginResponse struct {
	RedirectURL   string    `json:"redirect_url"`
	RequestID     string    `json:"request_id"`
	State         string    `json:"state,omitempty"`
	CodeChallenge string    `json:"code_challenge,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type CallbackRequest struct {
	ProviderID   uuid.UUID              `json:"provider_id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	CallbackData map[string]interface{} `json:"callback_data"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
}

type CallbackResponse struct {
	Success          bool                  `json:"success"`
	UserID           uuid.UUID             `json:"user_id,omitempty"`
	SessionID        string                `json:"session_id,omitempty"`
	AccessToken      string                `json:"access_token,omitempty"`
	RefreshToken     string                `json:"refresh_token,omitempty"`
	ExpiresIn        int64                 `json:"expires_in,omitempty"`
	User             *entity.User          `json:"user,omitempty"`
	FederatedUser    *entity.FederatedUser `json:"federated_user,omitempty"`
	IsNewUser        bool                  `json:"is_new_user"`
	RequiresMFA      bool                  `json:"requires_mfa"`
	ErrorCode        string                `json:"error_code,omitempty"`
	ErrorDescription string                `json:"error_description,omitempty"`
}

type InitiateLogoutRequest struct {
	ProviderID uuid.UUID `json:"provider_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	SessionID  string    `json:"session_id"`
	UserID     uuid.UUID `json:"user_id"`
}

type InitiateLogoutResponse struct {
	LogoutURL        string `json:"logout_url,omitempty"`
	LogoutRequestID  string `json:"logout_request_id,omitempty"`
	RequiresRedirect bool   `json:"requires_redirect"`
}

type LogoutCallbackRequest struct {
	ProviderID   uuid.UUID              `json:"provider_id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	CallbackData map[string]interface{} `json:"callback_data"`
}

// Session validation
type SSOSessionValidationResponse struct {
	Valid             bool                          `json:"valid"`
	Session           *entity.SSOSession            `json:"session,omitempty"`
	User              *entity.User                  `json:"user,omitempty"`
	SecurityClearance entity.SecurityClearanceLevel `json:"security_clearance,omitempty"`
	ErrorReason       string                        `json:"error_reason,omitempty"`
}

// User provisioning
type ProvisionUserRequest struct {
	ProviderID   uuid.UUID              `json:"provider_id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	ExternalUser map[string]interface{} `json:"external_user"`
	Claims       map[string]interface{} `json:"claims"`
	Attributes   map[string]string      `json:"attributes"`
	ForceCreate  bool                   `json:"force_create"`
}

type ProvisionUserResponse struct {
	User            *entity.User                  `json:"user"`
	FederatedUser   *entity.FederatedUser         `json:"federated_user"`
	IsNewUser       bool                          `json:"is_new_user"`
	MappedRoles     []string                      `json:"mapped_roles"`
	MappedClearance entity.SecurityClearanceLevel `json:"mapped_clearance"`
}

type UpdateFederatedUserRequest struct {
	FederatedUserID uuid.UUID                     `json:"federated_user_id"`
	TenantID        uuid.UUID                     `json:"tenant_id"`
	Claims          map[string]interface{}        `json:"claims,omitempty"`
	Attributes      map[string]string             `json:"attributes,omitempty"`
	MappedRoles     []string                      `json:"mapped_roles,omitempty"`
	MappedClearance entity.SecurityClearanceLevel `json:"mapped_clearance,omitempty"`
}

type LinkFederatedUserRequest struct {
	UserID           uuid.UUID              `json:"user_id"`
	TenantID         uuid.UUID              `json:"tenant_id"`
	ProviderID       uuid.UUID              `json:"provider_id"`
	ExternalID       string                 `json:"external_id"`
	ExternalUsername string                 `json:"external_username"`
	ExternalEmail    string                 `json:"external_email"`
	Claims           map[string]interface{} `json:"claims"`
	Attributes       map[string]string      `json:"attributes"`
}

// Attribute mapping
type CreateAttributeMappingRequest struct {
	ProviderID        uuid.UUID `json:"provider_id"`
	TenantID          uuid.UUID `json:"tenant_id"`
	ExternalAttribute string    `json:"external_attribute"`
	InternalAttribute string    `json:"internal_attribute"`
	AttributeType     string    `json:"attribute_type"`
	TransformRule     string    `json:"transform_rule,omitempty"`
	DefaultValue      string    `json:"default_value,omitempty"`
	Required          bool      `json:"required"`
	ValidationRegex   string    `json:"validation_regex,omitempty"`
	AllowedValues     []string  `json:"allowed_values,omitempty"`
}

type UpdateAttributeMappingRequest struct {
	MappingID         uuid.UUID `json:"mapping_id"`
	TenantID          uuid.UUID `json:"tenant_id"`
	ExternalAttribute string    `json:"external_attribute,omitempty"`
	InternalAttribute string    `json:"internal_attribute,omitempty"`
	AttributeType     string    `json:"attribute_type,omitempty"`
	TransformRule     string    `json:"transform_rule,omitempty"`
	DefaultValue      string    `json:"default_value,omitempty"`
	Required          *bool     `json:"required,omitempty"`
	ValidationRegex   string    `json:"validation_regex,omitempty"`
	AllowedValues     []string  `json:"allowed_values,omitempty"`
}

// SAML-specific types
type SAMLAuthNRequest struct {
	ProviderID                  uuid.UUID `json:"provider_id"`
	TenantID                    uuid.UUID `json:"tenant_id"`
	RelayState                  string    `json:"relay_state,omitempty"`
	ForceAuthn                  bool      `json:"force_authn"`
	AssertionConsumerServiceURL string    `json:"acs_url,omitempty"`
}

type SAMLAuthNResponse struct {
	AuthNRequestURL string `json:"authn_request_url"`
	RequestID       string `json:"request_id"`
	RelayState      string `json:"relay_state,omitempty"`
}

type SAMLAssertionRequest struct {
	ProviderID   uuid.UUID `json:"provider_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	SAMLResponse string    `json:"saml_response"`
	RelayState   string    `json:"relay_state,omitempty"`
}

type SAMLAssertionResponse struct {
	Valid          bool                   `json:"valid"`
	UserAttributes map[string]interface{} `json:"user_attributes,omitempty"`
	SessionIndex   string                 `json:"session_index,omitempty"`
	NameID         string                 `json:"name_id,omitempty"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
}

type SAMLLogoutRequest struct {
	ProviderID   uuid.UUID `json:"provider_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	SessionIndex string    `json:"session_index"`
	NameID       string    `json:"name_id"`
}

type SAMLLogoutResponse struct {
	LogoutRequestURL string `json:"logout_request_url"`
	RequestID        string `json:"request_id"`
}

type SAMLLogoutValidationRequest struct {
	ProviderID   uuid.UUID `json:"provider_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	SAMLResponse string    `json:"saml_response"`
}

type SAMLLogoutValidationResponse struct {
	Valid        bool   `json:"valid"`
	RequestID    string `json:"request_id,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type SAMLMetadataRequest struct {
	ProviderID         uuid.UUID `json:"provider_id"`
	TenantID           uuid.UUID `json:"tenant_id"`
	ServiceName        string    `json:"service_name"`
	ServiceDescription string    `json:"service_description"`
	ContactEmail       string    `json:"contact_email,omitempty"`
}

type SAMLMetadataValidationResponse struct {
	Valid        bool     `json:"valid"`
	EntityID     string   `json:"entity_id,omitempty"`
	SSOEndpoints []string `json:"sso_endpoints,omitempty"`
	SLOEndpoints []string `json:"slo_endpoints,omitempty"`
	Certificates []string `json:"certificates,omitempty"`
	ErrorMessage string   `json:"error_message,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// OIDC-specific types
type OIDCAuthorizationRequest struct {
	ProviderID          uuid.UUID `json:"provider_id"`
	TenantID            uuid.UUID `json:"tenant_id"`
	Scopes              []string  `json:"scopes"`
	State               string    `json:"state"`
	Nonce               string    `json:"nonce,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
}

type OIDCAuthorizationResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
	CodeVerifier     string `json:"code_verifier,omitempty"`
}

type OIDCTokenRequest struct {
	ProviderID   uuid.UUID `json:"provider_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Code         string    `json:"code"`
	State        string    `json:"state"`
	CodeVerifier string    `json:"code_verifier,omitempty"`
}

type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

type OIDCTokenValidationRequest struct {
	ProviderID  uuid.UUID `json:"provider_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	IDToken     string    `json:"id_token"`
	AccessToken string    `json:"access_token,omitempty"`
	Nonce       string    `json:"nonce,omitempty"`
}

type OIDCTokenValidationResponse struct {
	Valid         bool                   `json:"valid"`
	Claims        map[string]interface{} `json:"claims,omitempty"`
	Subject       string                 `json:"subject,omitempty"`
	Email         string                 `json:"email,omitempty"`
	EmailVerified bool                   `json:"email_verified"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
}

type OIDCRefreshRequest struct {
	ProviderID   uuid.UUID `json:"provider_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	RefreshToken string    `json:"refresh_token"`
}

type OIDCRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type OIDCUserInfoRequest struct {
	ProviderID  uuid.UUID `json:"provider_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	AccessToken string    `json:"access_token"`
}

type OIDCUserInfoResponse struct {
	UserInfo      map[string]interface{} `json:"user_info"`
	Subject       string                 `json:"subject"`
	Email         string                 `json:"email,omitempty"`
	EmailVerified bool                   `json:"email_verified"`
}

type OIDCProviderConfiguration struct {
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
