package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// WebAuthnProvider implements WebAuthn/FIDO2 authentication
type WebAuthnProvider struct {
	rpID           string
	rpName         string
	rpOrigin       []string
	timeout        time.Duration
	challenges     map[string]*WebAuthnChallenge // In production, use Redis
	authenticators map[string]*AuthenticatorData // In production, use database
}

// WebAuthnConfig holds WebAuthn configuration
type WebAuthnConfig struct {
	RPID     string        `json:"rp_id"`
	RPName   string        `json:"rp_name"`
	RPOrigin []string      `json:"rp_origin"`
	Timeout  time.Duration `json:"timeout"`
	Debug    bool          `json:"debug"`
}

// WebAuthnChallenge represents a WebAuthn challenge
type WebAuthnChallenge struct {
	ID                string             `json:"id"`
	UserID            uuid.UUID          `json:"user_id"`
	Challenge         string             `json:"challenge"`
	ChallengeType     string             `json:"challenge_type"` // "registration" or "authentication"
	ExpiresAt         time.Time          `json:"expires_at"`
	CreatedAt         time.Time          `json:"created_at"`
	IPAddress         string             `json:"ip_address"`
	UserAgent         string             `json:"user_agent"`
	PublicKeyOptions  *PublicKeyOptions  `json:"public_key_options,omitempty"`
	AuthenticatorData *AuthenticatorData `json:"authenticator_data,omitempty"`
}

// PublicKeyOptions represents WebAuthn PublicKeyCredentialCreationOptions
type PublicKeyOptions struct {
	Challenge              string                          `json:"challenge"`
	RP                     RelyingParty                    `json:"rp"`
	User                   UserEntity                      `json:"user"`
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	AuthenticatorSelection *AuthenticatorSelectionCriteria `json:"authenticatorSelection,omitempty"`
	Timeout                int                             `json:"timeout"`
	Attestation            string                          `json:"attestation"`
}

// RelyingParty represents the WebAuthn relying party
type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntity represents the WebAuthn user entity
type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// PublicKeyCredentialParameters represents supported credential parameters
type PublicKeyCredentialParameters struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// AuthenticatorSelectionCriteria represents authenticator selection criteria
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey"`
	UserVerification        string `json:"userVerification"`
}

// AuthenticatorData represents stored authenticator information
type AuthenticatorData struct {
	CredentialID    []byte     `json:"credential_id"`
	PublicKey       []byte     `json:"public_key"`
	UserID          uuid.UUID  `json:"user_id"`
	Counter         uint32     `json:"counter"`
	DeviceName      string     `json:"device_name"`
	AttestationType string     `json:"attestation_type"`
	Transport       []string   `json:"transport"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
}

// AuthenticationResponse represents the client's authentication response
type AuthenticationResponse struct {
	ID       string                         `json:"id"`
	RawID    string                         `json:"rawId"`
	Response AuthenticatorAssertionResponse `json:"response"`
	Type     string                         `json:"type"`
}

// AuthenticatorAssertionResponse represents the authenticator assertion response
type AuthenticatorAssertionResponse struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// RegistrationResponse represents the client's registration response
type RegistrationResponse struct {
	ID       string                           `json:"id"`
	RawID    string                           `json:"rawId"`
	Response AuthenticatorAttestationResponse `json:"response"`
	Type     string                           `json:"type"`
}

// AuthenticatorAttestationResponse represents the authenticator attestation response
type AuthenticatorAttestationResponse struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

// NewWebAuthnProvider creates a new WebAuthn provider
func NewWebAuthnProvider(config *WebAuthnConfig) *WebAuthnProvider {
	return &WebAuthnProvider{
		rpID:           config.RPID,
		rpName:         config.RPName,
		rpOrigin:       config.RPOrigin,
		timeout:        config.Timeout,
		challenges:     make(map[string]*WebAuthnChallenge),
		authenticators: make(map[string]*AuthenticatorData),
	}
}

// BeginRegistration starts WebAuthn registration process
func (w *WebAuthnProvider) BeginRegistration(ctx context.Context, userID uuid.UUID, username, displayName string) (*WebAuthnChallenge, error) {
	// Generate challenge
	challenge, err := w.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Create user entity
	userEntity := UserEntity{
		ID:          userID.String(),
		Name:        username,
		DisplayName: displayName,
	}

	// Create public key options
	options := &PublicKeyOptions{
		Challenge: challenge,
		RP: RelyingParty{
			ID:   w.rpID,
			Name: w.rpName,
		},
		User: userEntity,
		PubKeyCredParams: []PublicKeyCredentialParameters{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
		AuthenticatorSelection: &AuthenticatorSelectionCriteria{
			RequireResidentKey: false,
			UserVerification:   "preferred",
		},
		Timeout:     int(w.timeout.Milliseconds()),
		Attestation: "none",
	}

	// Create challenge record
	challengeID := uuid.New().String()
	challengeRecord := &WebAuthnChallenge{
		ID:               challengeID,
		UserID:           userID,
		Challenge:        challenge,
		ChallengeType:    "registration",
		ExpiresAt:        time.Now().Add(w.timeout),
		CreatedAt:        time.Now(),
		PublicKeyOptions: options,
	}

	// Store challenge
	w.challenges[challengeID] = challengeRecord

	return challengeRecord, nil
}

// CompleteRegistration completes WebAuthn registration
func (w *WebAuthnProvider) CompleteRegistration(ctx context.Context, challengeID string, response *RegistrationResponse) (*AuthenticatorData, error) {
	// Get challenge
	challenge, exists := w.challenges[challengeID]
	if !exists {
		return nil, fmt.Errorf("invalid or expired challenge")
	}

	// Check expiration
	if time.Now().After(challenge.ExpiresAt) {
		delete(w.challenges, challengeID)
		return nil, fmt.Errorf("challenge expired")
	}

	// Verify registration response (simplified - in production, use a WebAuthn library)
	authenticatorData, err := w.verifyRegistrationResponse(challenge, response)
	if err != nil {
		return nil, fmt.Errorf("registration verification failed: %w", err)
	}

	// Store authenticator data
	credentialKey := base64.URLEncoding.EncodeToString(authenticatorData.CredentialID)
	w.authenticators[credentialKey] = authenticatorData

	// Clean up challenge
	delete(w.challenges, challengeID)

	return authenticatorData, nil
}

// BeginAuthentication starts WebAuthn authentication process
func (w *WebAuthnProvider) BeginAuthentication(ctx context.Context, userID uuid.UUID) (*WebAuthnChallenge, error) {
	// Generate challenge
	challenge, err := w.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Get user's authenticators
	userAuthenticators := w.getUserAuthenticators(userID)
	if len(userAuthenticators) == 0 {
		return nil, fmt.Errorf("no authenticators registered for user")
	}

	// Create challenge record
	challengeID := uuid.New().String()
	challengeRecord := &WebAuthnChallenge{
		ID:            challengeID,
		UserID:        userID,
		Challenge:     challenge,
		ChallengeType: "authentication",
		ExpiresAt:     time.Now().Add(w.timeout),
		CreatedAt:     time.Now(),
	}

	// Store challenge
	w.challenges[challengeID] = challengeRecord

	return challengeRecord, nil
}

// CompleteAuthentication completes WebAuthn authentication
func (w *WebAuthnProvider) CompleteAuthentication(ctx context.Context, challengeID string, response *AuthenticationResponse) (*AuthenticatorData, error) {
	// Get challenge
	challenge, exists := w.challenges[challengeID]
	if !exists {
		return nil, fmt.Errorf("invalid or expired challenge")
	}

	// Check expiration
	if time.Now().After(challenge.ExpiresAt) {
		delete(w.challenges, challengeID)
		return nil, fmt.Errorf("challenge expired")
	}

	// Get authenticator data
	credentialKey := response.ID
	authenticator, exists := w.authenticators[credentialKey]
	if !exists {
		return nil, fmt.Errorf("unknown authenticator")
	}

	// Verify the user owns this authenticator
	if authenticator.UserID != challenge.UserID {
		return nil, fmt.Errorf("authenticator does not belong to user")
	}

	// Verify authentication response (simplified - in production, use a WebAuthn library)
	err := w.verifyAuthenticationResponse(challenge, authenticator, response)
	if err != nil {
		return nil, fmt.Errorf("authentication verification failed: %w", err)
	}

	// Update authenticator usage
	now := time.Now()
	authenticator.LastUsedAt = &now
	authenticator.Counter++ // In real implementation, verify counter from response

	// Clean up challenge
	delete(w.challenges, challengeID)

	return authenticator, nil
}

// GetUserAuthenticators returns authenticators for a user
func (w *WebAuthnProvider) GetUserAuthenticators(userID uuid.UUID) []*AuthenticatorData {
	return w.getUserAuthenticators(userID)
}

// RemoveAuthenticator removes an authenticator
func (w *WebAuthnProvider) RemoveAuthenticator(credentialID []byte) error {
	credentialKey := base64.URLEncoding.EncodeToString(credentialID)
	delete(w.authenticators, credentialKey)
	return nil
}

// generateChallenge generates a cryptographically secure challenge
func (w *WebAuthnProvider) generateChallenge() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// getUserAuthenticators returns all authenticators for a user
func (w *WebAuthnProvider) getUserAuthenticators(userID uuid.UUID) []*AuthenticatorData {
	var authenticators []*AuthenticatorData
	for _, auth := range w.authenticators {
		if auth.UserID == userID {
			authenticators = append(authenticators, auth)
		}
	}
	return authenticators
}

// verifyRegistrationResponse verifies the registration response (simplified)
func (w *WebAuthnProvider) verifyRegistrationResponse(challenge *WebAuthnChallenge, response *RegistrationResponse) (*AuthenticatorData, error) {
	// In a real implementation, this would:
	// 1. Parse and verify the attestation object
	// 2. Verify the client data JSON
	// 3. Verify the challenge matches
	// 4. Verify the origin matches
	// 5. Extract the credential ID and public key
	// 6. Verify the attestation signature

	// For this implementation, we'll create mock data
	credentialID, err := base64.URLEncoding.DecodeString(response.RawID)
	if err != nil {
		return nil, fmt.Errorf("invalid credential ID: %w", err)
	}

	// Mock public key (in real implementation, extract from attestation object)
	publicKey := make([]byte, 65) // Mock ECDSA P-256 public key
	rand.Read(publicKey)

	return &AuthenticatorData{
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		UserID:          challenge.UserID,
		Counter:         0,
		DeviceName:      "Security Key",
		AttestationType: "none",
		Transport:       []string{"usb"},
		CreatedAt:       time.Now(),
	}, nil
}

// verifyAuthenticationResponse verifies the authentication response (simplified)
func (w *WebAuthnProvider) verifyAuthenticationResponse(challenge *WebAuthnChallenge, authenticator *AuthenticatorData, response *AuthenticationResponse) error {
	// In a real implementation, this would:
	// 1. Parse the authenticator data
	// 2. Verify the client data JSON
	// 3. Verify the challenge matches
	// 4. Verify the origin matches
	// 5. Verify the signature using the stored public key
	// 6. Verify the counter has increased

	// For this simplified implementation, just verify the credential ID matches
	if response.ID != base64.URLEncoding.EncodeToString(authenticator.CredentialID) {
		return fmt.Errorf("credential ID mismatch")
	}

	return nil
}

// CleanupExpiredChallenges removes expired challenges
func (w *WebAuthnProvider) CleanupExpiredChallenges() {
	now := time.Now()
	for id, challenge := range w.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(w.challenges, id)
		}
	}
}

// GetChallengeInfo returns challenge information (for testing)
func (w *WebAuthnProvider) GetChallengeInfo(challengeID string) (*WebAuthnChallenge, bool) {
	challenge, exists := w.challenges[challengeID]
	return challenge, exists
}

// HealthCheck performs a health check
func (w *WebAuthnProvider) HealthCheck(ctx context.Context) error {
	// Check if the provider is properly configured
	if w.rpID == "" || w.rpName == "" {
		return fmt.Errorf("WebAuthn provider not properly configured")
	}
	return nil
}

// GetPublicKeyOptions creates public key options for registration
func (w *WebAuthnProvider) GetPublicKeyOptions(challenge *WebAuthnChallenge) (map[string]interface{}, error) {
	if challenge.PublicKeyOptions == nil {
		return nil, fmt.Errorf("no public key options available")
	}

	// Convert to map for JSON serialization
	options := map[string]interface{}{
		"challenge": challenge.PublicKeyOptions.Challenge,
		"rp": map[string]string{
			"id":   challenge.PublicKeyOptions.RP.ID,
			"name": challenge.PublicKeyOptions.RP.Name,
		},
		"user": map[string]string{
			"id":          challenge.PublicKeyOptions.User.ID,
			"name":        challenge.PublicKeyOptions.User.Name,
			"displayName": challenge.PublicKeyOptions.User.DisplayName,
		},
		"pubKeyCredParams": challenge.PublicKeyOptions.PubKeyCredParams,
		"timeout":          challenge.PublicKeyOptions.Timeout,
		"attestation":      challenge.PublicKeyOptions.Attestation,
	}

	if challenge.PublicKeyOptions.AuthenticatorSelection != nil {
		options["authenticatorSelection"] = challenge.PublicKeyOptions.AuthenticatorSelection
	}

	return options, nil
}

// GetAssertionOptions creates assertion options for authentication
func (w *WebAuthnProvider) GetAssertionOptions(challenge *WebAuthnChallenge) (map[string]interface{}, error) {
	// Get user's allowed credentials
	authenticators := w.getUserAuthenticators(challenge.UserID)
	allowCredentials := make([]map[string]interface{}, len(authenticators))

	for i, auth := range authenticators {
		allowCredentials[i] = map[string]interface{}{
			"type":       "public-key",
			"id":         base64.URLEncoding.EncodeToString(auth.CredentialID),
			"transports": auth.Transport,
		}
	}

	options := map[string]interface{}{
		"challenge":        challenge.Challenge,
		"timeout":          int(w.timeout.Milliseconds()),
		"userVerification": "preferred",
		"allowCredentials": allowCredentials,
	}

	return options, nil
}
