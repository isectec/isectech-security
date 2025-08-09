package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPProvider implements TOTP (Time-based One-Time Password) functionality
type TOTPProvider struct {
	issuer     string
	secretSize int
	period     uint
	digits     otp.Digits
	algorithm  otp.Algorithm
}

// NewTOTPProvider creates a new TOTP provider
func NewTOTPProvider(issuer string) *TOTPProvider {
	return &TOTPProvider{
		issuer:     issuer,
		secretSize: 32, // 256 bits
		period:     30, // 30 seconds
		digits:     otp.DigitsSix,
		algorithm:  otp.AlgorithmSHA1,
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (t *TOTPProvider) GenerateSecret(accountName string) (string, error) {
	// Generate random secret
	secret := make([]byte, t.secretSize)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}

	// Encode to base32
	encodedSecret := base32.StdEncoding.EncodeToString(secret)

	// Remove padding
	encodedSecret = strings.TrimRight(encodedSecret, "=")

	return encodedSecret, nil
}

// GenerateQRCode generates a QR code URL for TOTP setup
func (t *TOTPProvider) GenerateQRCode(secret, accountName string) (string, error) {
	// Create TOTP key
	key, err := otp.NewKeyFromURL(t.generateOTPURL(secret, accountName))
	if err != nil {
		return "", fmt.Errorf("failed to create TOTP key: %w", err)
	}

	// Generate QR code image URL (Google Charts API)
	qrURL := fmt.Sprintf("https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=%s",
		url.QueryEscape(key.String()))

	return qrURL, nil
}

// generateOTPURL generates the OTP URL for TOTP setup
func (t *TOTPProvider) generateOTPURL(secret, accountName string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d&digits=%d&algorithm=%s",
		url.QueryEscape(t.issuer),
		url.QueryEscape(accountName),
		secret,
		url.QueryEscape(t.issuer),
		t.period,
		t.digits.Length(),
		strings.ToUpper(t.algorithm.String()))
}

// ValidateCode validates a TOTP code against the secret
func (t *TOTPProvider) ValidateCode(secret, code string, window int) bool {
	// Validate the code with time window (allows for clock skew)
	valid := totp.Validate(code, secret)

	if !valid && window > 0 {
		// Check previous and next time windows
		now := time.Now()
		for i := 1; i <= window; i++ {
			// Check previous windows
			pastTime := now.Add(-time.Duration(i) * time.Duration(t.period) * time.Second)
			if totp.ValidateCustom(code, secret, pastTime, totp.ValidateOpts{
				Period:    t.period,
				Skew:      0,
				Digits:    t.digits,
				Algorithm: t.algorithm,
			}) {
				return true
			}

			// Check future windows
			futureTime := now.Add(time.Duration(i) * time.Duration(t.period) * time.Second)
			if totp.ValidateCustom(code, secret, futureTime, totp.ValidateOpts{
				Period:    t.period,
				Skew:      0,
				Digits:    t.digits,
				Algorithm: t.algorithm,
			}) {
				return true
			}
		}
	}

	return valid
}

// GenerateCode generates a TOTP code for the given secret (for testing purposes)
func (t *TOTPProvider) GenerateCode(secret string) (string, error) {
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    t.period,
		Skew:      0,
		Digits:    t.digits,
		Algorithm: t.algorithm,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}

	return code, nil
}

// GetRemainingTime returns the remaining time in seconds until the next code
func (t *TOTPProvider) GetRemainingTime() int {
	now := time.Now().Unix()
	remaining := int(t.period) - int(now%int64(t.period))
	return remaining
}

// ValidateSecret validates if a secret is properly formatted
func (t *TOTPProvider) ValidateSecret(secret string) bool {
	// Check if secret is valid base32
	_, err := base32.StdEncoding.DecodeString(secret + strings.Repeat("=", (8-len(secret)%8)%8))
	if err != nil {
		return false
	}

	// Check minimum length (should be at least 16 characters for 80 bits)
	if len(secret) < 16 {
		return false
	}

	return true
}

// BackupCodesProvider handles backup recovery codes
type BackupCodesProvider struct {
	codeLength int
	codeCount  int
}

// NewBackupCodesProvider creates a new backup codes provider
func NewBackupCodesProvider() *BackupCodesProvider {
	return &BackupCodesProvider{
		codeLength: 8,  // 8 characters per code
		codeCount:  10, // 10 backup codes
	}
}

// GenerateBackupCodes generates a set of backup recovery codes
func (b *BackupCodesProvider) GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 {
		count = b.codeCount
	}

	codes := make([]string, count)

	for i := 0; i < count; i++ {
		code, err := b.generateSingleCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code %d: %w", i, err)
		}
		codes[i] = code
	}

	return codes, nil
}

// generateSingleCode generates a single backup code
func (b *BackupCodesProvider) generateSingleCode() (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	bytes := make([]byte, b.codeLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	// Format as XXXX-XXXX for readability
	code := string(bytes)
	if len(code) == 8 {
		code = code[:4] + "-" + code[4:]
	}

	return code, nil
}

// ValidateBackupCode validates a backup code format
func (b *BackupCodesProvider) ValidateBackupCode(code string) bool {
	// Remove any spaces or dashes
	cleaned := strings.ReplaceAll(strings.ReplaceAll(code, "-", ""), " ", "")

	// Check length
	if len(cleaned) != b.codeLength {
		return false
	}

	// Check if all characters are alphanumeric
	for _, char := range cleaned {
		if !((char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			return false
		}
	}

	return true
}

// NormalizeBackupCode normalizes a backup code by removing spaces and dashes
func (b *BackupCodesProvider) NormalizeBackupCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(code, "-", ""), " ", ""))
}

// TOTPValidator provides validation utilities for TOTP
type TOTPValidator struct {
	maxAttempts     int
	windowSize      int
	rateLimitPeriod time.Duration
}

// NewTOTPValidator creates a new TOTP validator
func NewTOTPValidator() *TOTPValidator {
	return &TOTPValidator{
		maxAttempts:     5,               // Maximum failed attempts before lockout
		windowSize:      1,               // Allow 1 period window for clock skew
		rateLimitPeriod: 5 * time.Minute, // Rate limit period
	}
}

// ValidateCodeWithRateLimit validates a TOTP code with rate limiting
func (v *TOTPValidator) ValidateCodeWithRateLimit(secret, code string, attempts int, lastAttempt time.Time) (bool, bool, error) {
	// Check rate limiting
	if attempts >= v.maxAttempts && time.Since(lastAttempt) < v.rateLimitPeriod {
		return false, true, fmt.Errorf("rate limit exceeded, try again in %v", v.rateLimitPeriod-time.Since(lastAttempt))
	}

	// Reset attempts if rate limit period has passed
	rateLimited := attempts >= v.maxAttempts && time.Since(lastAttempt) < v.rateLimitPeriod

	// Validate code format
	if !v.validateCodeFormat(code) {
		return false, rateLimited, fmt.Errorf("invalid code format")
	}

	// Create TOTP provider and validate
	provider := NewTOTPProvider("iSECTECH")
	valid := provider.ValidateCode(secret, code, v.windowSize)

	return valid, rateLimited, nil
}

// validateCodeFormat validates the format of a TOTP code
func (v *TOTPValidator) validateCodeFormat(code string) bool {
	// Remove any spaces
	code = strings.ReplaceAll(code, " ", "")

	// Check length (should be 6 or 8 digits)
	if len(code) != 6 && len(code) != 8 {
		return false
	}

	// Check if all characters are digits
	for _, char := range code {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// GetCodeInfo returns information about the current TOTP code period
func (v *TOTPValidator) GetCodeInfo() map[string]interface{} {
	now := time.Now()
	period := 30 // seconds
	elapsed := int(now.Unix()) % period
	remaining := period - elapsed

	return map[string]interface{}{
		"current_time":      now.Unix(),
		"period_seconds":    period,
		"elapsed_seconds":   elapsed,
		"remaining_seconds": remaining,
		"next_code_at":      now.Add(time.Duration(remaining) * time.Second).Unix(),
	}
}
