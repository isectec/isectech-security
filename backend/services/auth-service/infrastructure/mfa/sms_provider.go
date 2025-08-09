package mfa

import (
	"context"
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SMSProviderType represents different SMS service providers
type SMSProviderType string

const (
	SMSProviderTwilio  SMSProviderType = "twilio"
	SMSProviderAWSSNS  SMSProviderType = "aws_sns"
	SMSProviderMockdev SMSProviderType = "mockdev" // For development/testing
)

// SMSConfig holds SMS provider configuration
type SMSConfig struct {
	Provider      SMSProviderType
	APIKey        string
	APISecret     string
	FromNumber    string
	Region        string // For AWS SNS
	AccountSID    string // For Twilio
	AuthToken     string // For Twilio
	TemplateID    string
	RateLimit     int // Messages per hour per phone number
	RetryAttempts int
	Timeout       time.Duration
}

// SMSChallenge represents an SMS verification challenge
type SMSChallenge struct {
	ID           string    `json:"id"`
	PhoneNumber  string    `json:"phone_number"`
	Code         string    `json:"code"`
	ExpiresAt    time.Time `json:"expires_at"`
	AttemptCount int       `json:"attempt_count"`
	CreatedAt    time.Time `json:"created_at"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
}

// SMSProvider interface defines SMS operations
type SMSProvider interface {
	SendCode(ctx context.Context, phoneNumber, code string) error
	ValidatePhoneNumber(phoneNumber string) (string, error) // Returns normalized number
	GetRemainingRateLimit(phoneNumber string) (int, error)
	HealthCheck(ctx context.Context) error
}

// SMSService manages SMS-based MFA
type SMSService struct {
	provider     SMSProvider
	config       *SMSConfig
	challenges   map[string]*SMSChallenge // In production, use Redis/database
	codeLength   int
	codeLifetime time.Duration
	maxAttempts  int
}

// NewSMSService creates a new SMS service
func NewSMSService(config *SMSConfig) (*SMSService, error) {
	var provider SMSProvider
	var err error

	switch config.Provider {
	case SMSProviderTwilio:
		provider, err = NewTwilioProvider(config)
	case SMSProviderAWSSNS:
		provider, err = NewAWSSNSProvider(config)
	case SMSProviderMockdev:
		provider = NewMockSMSProvider(config)
	default:
		return nil, fmt.Errorf("unsupported SMS provider: %s", config.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create SMS provider: %w", err)
	}

	return &SMSService{
		provider:     provider,
		config:       config,
		challenges:   make(map[string]*SMSChallenge),
		codeLength:   6,
		codeLifetime: 10 * time.Minute,
		maxAttempts:  3,
	}, nil
}

// SendVerificationCode sends an SMS verification code
func (s *SMSService) SendVerificationCode(ctx context.Context, phoneNumber, ipAddress, userAgent string) (string, error) {
	// Normalize phone number
	normalizedPhone, err := s.provider.ValidatePhoneNumber(phoneNumber)
	if err != nil {
		return "", fmt.Errorf("invalid phone number: %w", err)
	}

	// Check rate limits
	remaining, err := s.provider.GetRemainingRateLimit(normalizedPhone)
	if err != nil {
		return "", fmt.Errorf("failed to check rate limits: %w", err)
	}
	if remaining <= 0 {
		return "", fmt.Errorf("rate limit exceeded for phone number")
	}

	// Generate verification code
	code, err := s.generateVerificationCode()
	if err != nil {
		return "", fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Create challenge
	challengeID := s.generateChallengeID()
	challenge := &SMSChallenge{
		ID:           challengeID,
		PhoneNumber:  normalizedPhone,
		Code:         code,
		ExpiresAt:    time.Now().Add(s.codeLifetime),
		AttemptCount: 0,
		CreatedAt:    time.Now(),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}

	// Store challenge (in production, use Redis with TTL)
	s.challenges[challengeID] = challenge

	// Send SMS
	err = s.provider.SendCode(ctx, normalizedPhone, code)
	if err != nil {
		// Clean up failed challenge
		delete(s.challenges, challengeID)
		return "", fmt.Errorf("failed to send SMS: %w", err)
	}

	return challengeID, nil
}

// VerifyCode verifies an SMS verification code
func (s *SMSService) VerifyCode(challengeID, code string) (bool, error) {
	challenge, exists := s.challenges[challengeID]
	if !exists {
		return false, fmt.Errorf("invalid or expired challenge")
	}

	// Check expiration
	if time.Now().After(challenge.ExpiresAt) {
		delete(s.challenges, challengeID)
		return false, fmt.Errorf("verification code expired")
	}

	// Check max attempts
	if challenge.AttemptCount >= s.maxAttempts {
		delete(s.challenges, challengeID)
		return false, fmt.Errorf("maximum verification attempts exceeded")
	}

	// Increment attempt count
	challenge.AttemptCount++

	// Verify code
	if challenge.Code != code {
		return false, fmt.Errorf("invalid verification code")
	}

	// Success - clean up challenge
	delete(s.challenges, challengeID)
	return true, nil
}

// generateVerificationCode generates a random numeric verification code
func (s *SMSService) generateVerificationCode() (string, error) {
	bytes := make([]byte, s.codeLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Convert to digits
	code := make([]byte, s.codeLength)
	for i, b := range bytes {
		code[i] = '0' + (b % 10)
	}

	return string(code), nil
}

// generateChallengeID generates a unique challenge ID
func (s *SMSService) generateChallengeID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// CleanupExpiredChallenges removes expired challenges
func (s *SMSService) CleanupExpiredChallenges() {
	now := time.Now()
	for id, challenge := range s.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
}

// GetChallengeInfo returns information about a challenge (for testing)
func (s *SMSService) GetChallengeInfo(challengeID string) (*SMSChallenge, bool) {
	challenge, exists := s.challenges[challengeID]
	return challenge, exists
}

// MockSMSProvider implements SMSProvider for development/testing
type MockSMSProvider struct {
	config     *SMSConfig
	sentCodes  map[string]string // phone -> code mapping for testing
	rateLimits map[string]int    // phone -> remaining count
}

// NewMockSMSProvider creates a new mock SMS provider
func NewMockSMSProvider(config *SMSConfig) *MockSMSProvider {
	return &MockSMSProvider{
		config:     config,
		sentCodes:  make(map[string]string),
		rateLimits: make(map[string]int),
	}
}

// SendCode sends a mock SMS code
func (m *MockSMSProvider) SendCode(ctx context.Context, phoneNumber, code string) error {
	// In development, just log the code
	fmt.Printf("📱 SMS Code for %s: %s\n", phoneNumber, code)

	// Store for testing verification
	m.sentCodes[phoneNumber] = code

	// Simulate rate limiting
	if count, exists := m.rateLimits[phoneNumber]; exists {
		m.rateLimits[phoneNumber] = count - 1
	} else {
		m.rateLimits[phoneNumber] = m.config.RateLimit - 1
	}

	return nil
}

// ValidatePhoneNumber validates and normalizes a phone number
func (m *MockSMSProvider) ValidatePhoneNumber(phoneNumber string) (string, error) {
	return normalizePhoneNumber(phoneNumber)
}

// GetRemainingRateLimit returns remaining SMS rate limit
func (m *MockSMSProvider) GetRemainingRateLimit(phoneNumber string) (int, error) {
	if count, exists := m.rateLimits[phoneNumber]; exists {
		return count, nil
	}
	return m.config.RateLimit, nil
}

// HealthCheck performs a health check
func (m *MockSMSProvider) HealthCheck(ctx context.Context) error {
	return nil // Always healthy for mock
}

// GetLastSentCode returns the last sent code for testing
func (m *MockSMSProvider) GetLastSentCode(phoneNumber string) (string, bool) {
	code, exists := m.sentCodes[phoneNumber]
	return code, exists
}

// TwilioProvider implements SMS via Twilio
type TwilioProvider struct {
	accountSID string
	authToken  string
	fromNumber string
	config     *SMSConfig
}

// NewTwilioProvider creates a new Twilio SMS provider
func NewTwilioProvider(config *SMSConfig) (*TwilioProvider, error) {
	if config.AccountSID == "" || config.AuthToken == "" {
		return nil, fmt.Errorf("Twilio account SID and auth token required")
	}

	return &TwilioProvider{
		accountSID: config.AccountSID,
		authToken:  config.AuthToken,
		fromNumber: config.FromNumber,
		config:     config,
	}, nil
}

// SendCode sends SMS via Twilio
func (t *TwilioProvider) SendCode(ctx context.Context, phoneNumber, code string) error {
	// In a real implementation, this would use Twilio's API
	// For now, this is a placeholder

	message := fmt.Sprintf("Your iSECTECH verification code is: %s. This code expires in 10 minutes.", code)

	// TODO: Implement actual Twilio API call
	fmt.Printf("📱 Twilio SMS to %s: %s\n", phoneNumber, message)

	return nil
}

// ValidatePhoneNumber validates phone number for Twilio
func (t *TwilioProvider) ValidatePhoneNumber(phoneNumber string) (string, error) {
	return normalizePhoneNumber(phoneNumber)
}

// GetRemainingRateLimit returns remaining rate limit
func (t *TwilioProvider) GetRemainingRateLimit(phoneNumber string) (int, error) {
	// TODO: Implement actual rate limiting with Redis/database
	return t.config.RateLimit, nil
}

// HealthCheck checks Twilio service health
func (t *TwilioProvider) HealthCheck(ctx context.Context) error {
	// TODO: Implement actual Twilio health check
	return nil
}

// AWSSNSProvider implements SMS via AWS SNS
type AWSSNSProvider struct {
	region    string
	accessKey string
	secretKey string
	config    *SMSConfig
}

// NewAWSSNSProvider creates a new AWS SNS provider
func NewAWSSNSProvider(config *SMSConfig) (*AWSSNSProvider, error) {
	if config.APIKey == "" || config.APISecret == "" {
		return nil, fmt.Errorf("AWS access key and secret key required")
	}

	return &AWSSNSProvider{
		region:    config.Region,
		accessKey: config.APIKey,
		secretKey: config.APISecret,
		config:    config,
	}, nil
}

// SendCode sends SMS via AWS SNS
func (a *AWSSNSProvider) SendCode(ctx context.Context, phoneNumber, code string) error {
	// In a real implementation, this would use AWS SNS SDK
	// For now, this is a placeholder

	message := fmt.Sprintf("Your iSECTECH verification code is: %s. This code expires in 10 minutes.", code)

	// TODO: Implement actual AWS SNS API call
	fmt.Printf("📱 AWS SNS to %s: %s\n", phoneNumber, message)

	return nil
}

// ValidatePhoneNumber validates phone number for AWS SNS
func (a *AWSSNSProvider) ValidatePhoneNumber(phoneNumber string) (string, error) {
	return normalizePhoneNumber(phoneNumber)
}

// GetRemainingRateLimit returns remaining rate limit
func (a *AWSSNSProvider) GetRemainingRateLimit(phoneNumber string) (int, error) {
	// TODO: Implement actual rate limiting
	return a.config.RateLimit, nil
}

// HealthCheck checks AWS SNS service health
func (a *AWSSNSProvider) HealthCheck(ctx context.Context) error {
	// TODO: Implement actual AWS SNS health check
	return nil
}

// normalizePhoneNumber normalizes a phone number to E.164 format
func normalizePhoneNumber(phoneNumber string) (string, error) {
	// Remove all non-digit characters
	digits := regexp.MustCompile(`[^\d+]`).ReplaceAllString(phoneNumber, "")

	// Handle different formats
	if strings.HasPrefix(digits, "+") {
		// Already in international format
		digits = digits[1:] // Remove the +
	} else if strings.HasPrefix(digits, "1") && len(digits) == 11 {
		// US number with country code
		// Keep as is
	} else if len(digits) == 10 {
		// US number without country code
		digits = "1" + digits
	} else {
		return "", fmt.Errorf("invalid phone number format")
	}

	// Validate length (should be 10-15 digits after country code)
	if len(digits) < 10 || len(digits) > 15 {
		return "", fmt.Errorf("phone number length invalid")
	}

	// Return in E.164 format
	return "+" + digits, nil
}

// ValidatePhoneNumberFormat validates phone number format
func ValidatePhoneNumberFormat(phoneNumber string) bool {
	_, err := normalizePhoneNumber(phoneNumber)
	return err == nil
}
