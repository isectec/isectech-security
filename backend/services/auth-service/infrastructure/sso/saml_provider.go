package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"

	"isectech/auth-service/domain/service"
)

// SAMLProvider implements SAML 2.0 authentication functionality
type SAMLProvider struct {
	config      *SAMLConfig
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	providers   map[string]*samlsp.Middleware // keyed by provider ID
}

// SAMLConfig holds SAML provider configuration
type SAMLConfig struct {
	ServiceName        string        `yaml:"service_name" default:"iSECTECH"`
	ServiceDescription string        `yaml:"service_description" default:"iSECTECH Cybersecurity Platform"`
	EntityID           string        `yaml:"entity_id"`
	BaseURL            string        `yaml:"base_url"`
	ContactEmail       string        `yaml:"contact_email"`
	CertificatePath    string        `yaml:"certificate_path"`
	PrivateKeyPath     string        `yaml:"private_key_path"`
	ValidateSignature  bool          `yaml:"validate_signature" default:"true"`
	RequireEncryption  bool          `yaml:"require_encryption" default:"false"`
	SessionTimeout     time.Duration `yaml:"session_timeout" default:"8h"`
	ClockSkewTolerance time.Duration `yaml:"clock_skew_tolerance" default:"5m"`
	MetadataCacheTTL   time.Duration `yaml:"metadata_cache_ttl" default:"24h"`
}

// NewSAMLProvider creates a new SAML provider
func NewSAMLProvider(config *SAMLConfig) (*SAMLProvider, error) {
	provider := &SAMLProvider{
		config:    config,
		providers: make(map[string]*samlsp.Middleware),
	}

	// Load or generate certificate and private key
	if err := provider.initializeCertificate(); err != nil {
		return nil, fmt.Errorf("failed to initialize certificate: %w", err)
	}

	return provider, nil
}

// GenerateAuthNRequest generates a SAML authentication request
func (p *SAMLProvider) GenerateAuthNRequest(ctx context.Context, req *service.SAMLAuthNRequest) (*service.SAMLAuthNResponse, error) {
	provider, err := p.getProviderMiddleware(req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider middleware: %w", err)
	}

	// Create authentication request
	authNRequest := &saml.AuthnRequest{
		ID:                          "_" + uuid.New().String(),
		IssueInstant:                saml.TimeNow(),
		Version:                     "2.0",
		Destination:                 provider.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		AssertionConsumerServiceURL: req.AssertionConsumerServiceURL,
		Issuer: &saml.Issuer{
			Value: provider.ServiceProvider.Metadata().EntityID,
		},
		NameIDPolicy: &saml.NameIDPolicy{
			AllowCreate: &[]bool{true}[0],
			Format:      &[]saml.NameIDFormat{saml.TransientNameIDFormat}[0],
		},
		ForceAuthn: &req.ForceAuthn,
	}

	if req.RelayState != "" {
		authNRequest.RelayState = req.RelayState
	}

	// Build authentication URL
	binding := provider.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	authURL, err := provider.ServiceProvider.MakeRedirectAuthenticationRequest(authNRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication request: %w", err)
	}

	return &service.SAMLAuthNResponse{
		AuthNRequestURL: authURL.String(),
		RequestID:       authNRequest.ID,
		RelayState:      req.RelayState,
	}, nil
}

// ValidateAssertion validates a SAML assertion response
func (p *SAMLProvider) ValidateAssertion(ctx context.Context, req *service.SAMLAssertionRequest) (*service.SAMLAssertionResponse, error) {
	provider, err := p.getProviderMiddleware(req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider middleware: %w", err)
	}

	// Decode SAML response
	samlResponseData, err := base64.StdEncoding.DecodeString(req.SAMLResponse)
	if err != nil {
		return &service.SAMLAssertionResponse{
			Valid:        false,
			ErrorMessage: "Invalid SAML response encoding",
		}, nil
	}

	// Parse SAML response
	var samlResponse saml.Response
	if err := xml.Unmarshal(samlResponseData, &samlResponse); err != nil {
		return &service.SAMLAssertionResponse{
			Valid:        false,
			ErrorMessage: "Failed to parse SAML response",
		}, nil
	}

	// Validate the response
	err = provider.ServiceProvider.ValidateEncodedResponse(req.SAMLResponse)
	if err != nil {
		return &service.SAMLAssertionResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("SAML response validation failed: %v", err),
		}, nil
	}

	// Extract attributes from assertion
	userAttributes := make(map[string]interface{})
	var sessionIndex, nameID string

	if len(samlResponse.Assertions) > 0 {
		assertion := samlResponse.Assertions[0]

		// Extract NameID
		if assertion.Subject != nil && assertion.Subject.NameID != nil {
			nameID = assertion.Subject.NameID.Value
		}

		// Extract session index
		if len(assertion.AuthnStatements) > 0 {
			sessionIndex = assertion.AuthnStatements[0].SessionIndex
		}

		// Extract attributes
		if assertion.AttributeStatement != nil {
			for _, attr := range assertion.AttributeStatement.Attributes {
				if len(attr.AttributeValues) > 0 {
					if len(attr.AttributeValues) == 1 {
						userAttributes[attr.Name] = attr.AttributeValues[0].Value
					} else {
						values := make([]string, len(attr.AttributeValues))
						for i, val := range attr.AttributeValues {
							values[i] = val.Value
						}
						userAttributes[attr.Name] = values
					}
				}
			}
		}
	}

	return &service.SAMLAssertionResponse{
		Valid:          true,
		UserAttributes: userAttributes,
		SessionIndex:   sessionIndex,
		NameID:         nameID,
	}, nil
}

// GenerateLogoutRequest generates a SAML logout request
func (p *SAMLProvider) GenerateLogoutRequest(ctx context.Context, req *service.SAMLLogoutRequest) (*service.SAMLLogoutResponse, error) {
	provider, err := p.getProviderMiddleware(req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider middleware: %w", err)
	}

	// Create logout request
	logoutRequest := &saml.LogoutRequest{
		ID:           "_" + uuid.New().String(),
		IssueInstant: saml.TimeNow(),
		Version:      "2.0",
		Destination:  provider.ServiceProvider.GetSLOBindingLocation(saml.HTTPRedirectBinding),
		Issuer: &saml.Issuer{
			Value: provider.ServiceProvider.Metadata().EntityID,
		},
		NameID: &saml.NameID{
			Value: req.NameID,
		},
		SessionIndex: &req.SessionIndex,
	}

	// Build logout URL
	logoutURL, err := provider.ServiceProvider.MakeRedirectLogoutRequest(logoutRequest, req.SessionIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to create logout request: %w", err)
	}

	return &service.SAMLLogoutResponse{
		LogoutRequestURL: logoutURL.String(),
		RequestID:        logoutRequest.ID,
	}, nil
}

// ValidateLogoutResponse validates a SAML logout response
func (p *SAMLProvider) ValidateLogoutResponse(ctx context.Context, req *service.SAMLLogoutValidationRequest) (*service.SAMLLogoutValidationResponse, error) {
	provider, err := p.getProviderMiddleware(req.ProviderID.String(), req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider middleware: %w", err)
	}

	// Decode and validate logout response
	err = provider.ServiceProvider.ValidateEncodedLogoutResponseForm(req.SAMLResponse)
	if err != nil {
		return &service.SAMLLogoutValidationResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("Logout response validation failed: %v", err),
		}, nil
	}

	return &service.SAMLLogoutValidationResponse{
		Valid: true,
	}, nil
}

// GenerateServiceProviderMetadata generates SP metadata
func (p *SAMLProvider) GenerateServiceProviderMetadata(ctx context.Context, req *service.SAMLMetadataRequest) (string, error) {
	// Create service provider instance for this tenant
	serviceProvider := p.createServiceProvider(req.TenantID)

	// Generate metadata
	metadata := serviceProvider.Metadata()

	// Set additional metadata fields
	metadata.EntityID = fmt.Sprintf("%s/saml/metadata/%s", p.config.BaseURL, req.TenantID.String())

	// Add contact information
	if req.ContactEmail != "" || p.config.ContactEmail != "" {
		contactEmail := req.ContactEmail
		if contactEmail == "" {
			contactEmail = p.config.ContactEmail
		}

		metadata.ContactPerson = []saml.ContactPerson{{
			ContactType:  "technical",
			EmailAddress: []string{contactEmail},
		}}
	}

	// Add organization information
	metadata.Organization = &saml.Organization{
		OrganizationNames: []saml.LocalizedName{{
			Lang:  "en",
			Value: req.ServiceName,
		}},
		OrganizationDisplayNames: []saml.LocalizedName{{
			Lang:  "en",
			Value: req.ServiceDescription,
		}},
		OrganizationURLs: []saml.LocalizedURI{{
			Lang:  "en",
			Value: p.config.BaseURL,
		}},
	}

	// Marshal to XML
	metadataXML, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return xml.Header + string(metadataXML), nil
}

// ValidateIdPMetadata validates IdP metadata
func (p *SAMLProvider) ValidateIdPMetadata(ctx context.Context, metadata string) (*service.SAMLMetadataValidationResponse, error) {
	var entityDescriptor saml.EntityDescriptor
	if err := xml.Unmarshal([]byte(metadata), &entityDescriptor); err != nil {
		return &service.SAMLMetadataValidationResponse{
			Valid:        false,
			ErrorMessage: "Failed to parse metadata XML",
		}, nil
	}

	response := &service.SAMLMetadataValidationResponse{
		Valid:        true,
		EntityID:     entityDescriptor.EntityID,
		SSOEndpoints: make([]string, 0),
		SLOEndpoints: make([]string, 0),
		Certificates: make([]string, 0),
		Warnings:     make([]string, 0),
	}

	// Extract SSO endpoints
	if entityDescriptor.IDPSSODescriptor != nil {
		for _, endpoint := range entityDescriptor.IDPSSODescriptor.SingleSignOnServices {
			response.SSOEndpoints = append(response.SSOEndpoints, endpoint.Location)
		}

		// Extract SLO endpoints
		for _, endpoint := range entityDescriptor.IDPSSODescriptor.SingleLogoutServices {
			response.SLOEndpoints = append(response.SLOEndpoints, endpoint.Location)
		}

		// Extract certificates
		for _, keyDescriptor := range entityDescriptor.IDPSSODescriptor.KeyDescriptors {
			if keyDescriptor.KeyInfo.Certificate != "" {
				response.Certificates = append(response.Certificates, keyDescriptor.KeyInfo.Certificate)
			}
		}
	}

	// Validate endpoints
	if len(response.SSOEndpoints) == 0 {
		response.Warnings = append(response.Warnings, "No SSO endpoints found")
	}

	if len(response.Certificates) == 0 {
		response.Warnings = append(response.Warnings, "No signing certificates found")
	}

	// Check for HTTPS endpoints
	for _, endpoint := range response.SSOEndpoints {
		if u, err := url.Parse(endpoint); err == nil && u.Scheme != "https" {
			response.Warnings = append(response.Warnings, fmt.Sprintf("Non-HTTPS SSO endpoint: %s", endpoint))
		}
	}

	return response, nil
}

// Helper methods

func (p *SAMLProvider) getProviderMiddleware(providerID string, tenantID uuid.UUID) (*samlsp.Middleware, error) {
	key := fmt.Sprintf("%s:%s", tenantID.String(), providerID)

	middleware, exists := p.providers[key]
	if !exists {
		// Create new middleware for this provider/tenant combination
		var err error
		middleware, err = p.createProviderMiddleware(tenantID, providerID)
		if err != nil {
			return nil, err
		}
		p.providers[key] = middleware
	}

	return middleware, nil
}

func (p *SAMLProvider) createProviderMiddleware(tenantID uuid.UUID, providerID string) (*samlsp.Middleware, error) {
	// Create service provider
	serviceProvider := p.createServiceProvider(tenantID)

	// Create middleware options
	opts := samlsp.Options{
		URL:                mustParseURL(fmt.Sprintf("%s/saml/%s", p.config.BaseURL, tenantID.String())),
		Key:                p.privateKey,
		Certificate:        p.certificate,
		AllowIDPInitiated:  true,
		DefaultRedirectURI: fmt.Sprintf("%s/auth/sso/callback", p.config.BaseURL),
	}

	// Create middleware
	middleware, err := samlsp.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML middleware: %w", err)
	}

	return middleware, nil
}

func (p *SAMLProvider) createServiceProvider(tenantID uuid.UUID) saml.ServiceProvider {
	metadataURL := mustParseURL(fmt.Sprintf("%s/saml/metadata/%s", p.config.BaseURL, tenantID.String()))
	acsURL := mustParseURL(fmt.Sprintf("%s/saml/acs/%s", p.config.BaseURL, tenantID.String()))
	sloURL := mustParseURL(fmt.Sprintf("%s/saml/slo/%s", p.config.BaseURL, tenantID.String()))

	return saml.ServiceProvider{
		Key:         p.privateKey,
		Certificate: p.certificate,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		SloURL:      *sloURL,
		IDPMetadata: nil, // Will be set per provider
	}
}

func (p *SAMLProvider) initializeCertificate() error {
	// Try to load existing certificate and key
	if p.config.CertificatePath != "" && p.config.PrivateKeyPath != "" {
		if err := p.loadCertificateFromFiles(); err == nil {
			return nil
		}
	}

	// Generate self-signed certificate if not available
	return p.generateSelfSignedCertificate()
}

func (p *SAMLProvider) loadCertificateFromFiles() error {
	// Implementation for loading certificate from files
	// This would read the certificate and private key from the specified paths
	return fmt.Errorf("certificate loading from files not implemented")
}

func (p *SAMLProvider) generateSelfSignedCertificate() error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{p.config.ServiceName},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{},
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	p.certificate = certificate
	p.privateKey = privateKey

	return nil
}

// GetCertificatePEM returns the certificate in PEM format
func (p *SAMLProvider) GetCertificatePEM() string {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: p.certificate.Raw,
	})
	return string(certPEM)
}

// GetPrivateKeyPEM returns the private key in PEM format
func (p *SAMLProvider) GetPrivateKeyPEM() string {
	privateKeyDER, _ := x509.MarshalPKCS8PrivateKey(p.privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	return string(privateKeyPEM)
}

// Helper function to parse URLs
func mustParseURL(urlStr string) *url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}
	return u
}
