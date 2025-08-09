package service

import (
	"context"
	"time"

	"../entity"
	"github.com/google/uuid"
)

// TOTPConfig represents TOTP configuration
type TOTPConfig struct {
	Issuer      string
	AccountName string
	SecretSize  int
	Period      uint
	Digits      int
	Algorithm   string
}

// SMSConfig represents SMS configuration
type SMSConfig struct {
	Provider   string
	APIKey     string
	APISecret  string
	FromNumber string
	TemplateID string
	RateLimit  int // Messages per hour
}

// WebAuthnConfig represents WebAuthn configuration
type WebAuthnConfig struct {
	RPDisplayName string
	RPID          string
	RPOrigin      []string
	Timeout       time.Duration
	Debug         bool
}

// MFAEnrollmentRequest represents an MFA enrollment request
type MFAEnrollmentRequest struct {
	UserID       uuid.UUID            `json:"user_id"`
	TenantID     uuid.UUID            `json:"tenant_id"`
	DeviceType   entity.MFADeviceType `json:"device_type"`
	DeviceName   string               `json:"device_name"`
	PhoneNumber  string               `json:"phone_number,omitempty"`
	EmailAddress string               `json:"email_address,omitempty"`
	UserAgent    string               `json:"user_agent,omitempty"`
	IPAddress    string               `json:"ip_address,omitempty"`
}

// MFAEnrollmentResponse represents an MFA enrollment response
type MFAEnrollmentResponse struct {
	DeviceID     uuid.UUID `json:"device_id"`
	QRCodeURL    string    `json:"qr_code_url,omitempty"`  // For TOTP
	Secret       string    `json:"secret,omitempty"`       // For TOTP (temporary)
	BackupCodes  []string  `json:"backup_codes,omitempty"` // For backup codes
	Challenge    string    `json:"challenge,omitempty"`    // For WebAuthn
	PublicKey    string    `json:"public_key,omitempty"`   // For WebAuthn
	EnrollmentID string    `json:"enrollment_id"`          // Temporary enrollment ID
}

// MFAVerificationRequest represents an MFA verification request
type MFAVerificationRequest struct {
	UserID     uuid.UUID            `json:"user_id"`
	TenantID   uuid.UUID            `json:"tenant_id"`
	DeviceID   *uuid.UUID           `json:"device_id,omitempty"`
	DeviceType entity.MFADeviceType `json:"device_type"`
	Code       string               `json:"code,omitempty"`
	Challenge  string               `json:"challenge,omitempty"` // For WebAuthn
	Response   string               `json:"response,omitempty"`  // For WebAuthn
	BackupCode string               `json:"backup_code,omitempty"`
	IPAddress  string               `json:"ip_address"`
	UserAgent  string               `json:"user_agent"`
}

// MFAVerificationResponse represents an MFA verification response
type MFAVerificationResponse struct {
	Success         bool       `json:"success"`
	DeviceID        uuid.UUID  `json:"device_id,omitempty"`
	FailureReason   string     `json:"failure_reason,omitempty"`
	AttemptsLeft    int        `json:"attempts_left,omitempty"`
	NextAttemptAt   *time.Time `json:"next_attempt_at,omitempty"`
	BackupAvailable bool       `json:"backup_available"`
}

// MFAChallengeRequest represents an MFA challenge request
type MFAChallengeRequest struct {
	UserID     uuid.UUID            `json:"user_id"`
	TenantID   uuid.UUID            `json:"tenant_id"`
	DeviceType entity.MFADeviceType `json:"device_type"`
	IPAddress  string               `json:"ip_address"`
	UserAgent  string               `json:"user_agent"`
}

// MFAChallengeResponse represents an MFA challenge response
type MFAChallengeResponse struct {
	ChallengeID    string               `json:"challenge_id"`
	DeviceType     entity.MFADeviceType `json:"device_type"`
	MaskedTarget   string               `json:"masked_target,omitempty"` // Masked phone/email
	ExpiresAt      time.Time            `json:"expires_at"`
	Challenge      string               `json:"challenge,omitempty"` // For WebAuthn
	AllowedDevices []entity.MFADevice   `json:"allowed_devices"`
}

// MFAService defines the interface for multi-factor authentication operations
type MFAService interface {
	// Device Management
	EnrollDevice(ctx context.Context, req *MFAEnrollmentRequest) (*MFAEnrollmentResponse, error)
	ConfirmEnrollment(ctx context.Context, enrollmentID, confirmationCode string) (*entity.MFADevice, error)
	RemoveDevice(ctx context.Context, userID, tenantID, deviceID uuid.UUID) error
	ListUserDevices(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.MFADevice, error)
	GetDevice(ctx context.Context, deviceID, tenantID uuid.UUID) (*entity.MFADevice, error)
	SetPrimaryDevice(ctx context.Context, userID, tenantID, deviceID uuid.UUID) error

	// TOTP Operations
	GenerateTOTPSecret(ctx context.Context, config *TOTPConfig) (string, string, error) // secret, qrcode_url
	ValidateTOTPCode(ctx context.Context, secret, code string, window int) bool
	GenerateBackupCodes(ctx context.Context, count int) ([]string, error)

	// SMS Operations
	SendSMSCode(ctx context.Context, phoneNumber string, config *SMSConfig) (string, error) // challenge_id
	ValidateSMSCode(ctx context.Context, challengeID, code string) bool

	// WebAuthn Operations
	BeginWebAuthnRegistration(ctx context.Context, userID uuid.UUID, config *WebAuthnConfig) (string, error) // challenge
	CompleteWebAuthnRegistration(ctx context.Context, userID uuid.UUID, challenge, response string) (*entity.MFADevice, error)
	BeginWebAuthnAuthentication(ctx context.Context, userID uuid.UUID, config *WebAuthnConfig) (string, error) // challenge
	CompleteWebAuthnAuthentication(ctx context.Context, userID uuid.UUID, challenge, response string) bool

	// Verification Operations
	SendMFAChallenge(ctx context.Context, req *MFAChallengeRequest) (*MFAChallengeResponse, error)
	VerifyMFAResponse(ctx context.Context, req *MFAVerificationRequest) (*MFAVerificationResponse, error)
	VerifyBackupCode(ctx context.Context, userID, tenantID uuid.UUID, backupCode string) (*MFAVerificationResponse, error)

	// Recovery Operations
	GenerateRecoveryCode(ctx context.Context, userID, tenantID uuid.UUID) (string, error)
	ValidateRecoveryCode(ctx context.Context, userID, tenantID uuid.UUID, recoveryCode string) bool
	DisableMFAWithRecovery(ctx context.Context, userID, tenantID uuid.UUID, recoveryCode string) error

	// Security Operations
	CheckRateLimit(ctx context.Context, userID uuid.UUID, action string) (bool, time.Duration, error)
	LogSecurityEvent(ctx context.Context, userID, tenantID uuid.UUID, eventType, details string) error
	DetectAnomalousActivity(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (bool, []string, error)

	// Administration
	ForceMFAEnrollment(ctx context.Context, userID, tenantID uuid.UUID, enforced bool) error
	GetMFAStatistics(ctx context.Context, tenantID uuid.UUID) (*MFAStatistics, error)
	AuditMFAActivity(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]MFAAuditEvent, error)
}

// MFAStatistics represents MFA usage statistics
type MFAStatistics struct {
	TenantID         uuid.UUID                    `json:"tenant_id"`
	TotalUsers       int                          `json:"total_users"`
	MFAEnabledUsers  int                          `json:"mfa_enabled_users"`
	MFAEnforcedUsers int                          `json:"mfa_enforced_users"`
	ActiveDevices    int                          `json:"active_devices"`
	DevicesByType    map[entity.MFADeviceType]int `json:"devices_by_type"`
	SuccessfulAuth   int                          `json:"successful_auth_24h"`
	FailedAuth       int                          `json:"failed_auth_24h"`
	RecoveryUsed     int                          `json:"recovery_used_24h"`
	LastUpdated      time.Time                    `json:"last_updated"`
}

// MFAAuditEvent represents an MFA audit event
type MFAAuditEvent struct {
	ID            uuid.UUID              `json:"id"`
	UserID        uuid.UUID              `json:"user_id"`
	TenantID      uuid.UUID              `json:"tenant_id"`
	DeviceID      *uuid.UUID             `json:"device_id,omitempty"`
	DeviceType    entity.MFADeviceType   `json:"device_type"`
	Action        string                 `json:"action"`
	Success       bool                   `json:"success"`
	FailureReason string                 `json:"failure_reason,omitempty"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	Risk          string                 `json:"risk_level"`
	CreatedAt     time.Time              `json:"created_at"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}
