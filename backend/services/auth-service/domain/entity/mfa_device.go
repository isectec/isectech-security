package entity

import (
	"time"

	"github.com/google/uuid"
)

// MFADeviceType represents the type of MFA device
type MFADeviceType string

const (
	MFADeviceTOTP     MFADeviceType = "TOTP"
	MFADeviceSMS      MFADeviceType = "SMS"
	MFADeviceWebAuthn MFADeviceType = "WEBAUTHN"
	MFADeviceEmail    MFADeviceType = "EMAIL"
	MFADeviceBackup   MFADeviceType = "BACKUP"
)

// MFADeviceStatus represents the status of an MFA device
type MFADeviceStatus string

const (
	MFADeviceStatusActive   MFADeviceStatus = "ACTIVE"
	MFADeviceStatusInactive MFADeviceStatus = "INACTIVE"
	MFADeviceStatusRevoked  MFADeviceStatus = "REVOKED"
	MFADeviceStatusPending  MFADeviceStatus = "PENDING"
)

// MFADevice represents an MFA device registered to a user
type MFADevice struct {
	ID              uuid.UUID       `json:"id" db:"id"`
	UserID          uuid.UUID       `json:"user_id" db:"user_id"`
	TenantID        uuid.UUID       `json:"tenant_id" db:"tenant_id"`
	DeviceType      MFADeviceType   `json:"device_type" db:"device_type"`
	DeviceName      string          `json:"device_name" db:"device_name"`
	Status          MFADeviceStatus `json:"status" db:"status"`
	IsPrimary       bool            `json:"is_primary" db:"is_primary"`
	IsBackup        bool            `json:"is_backup" db:"is_backup"`
	Secret          string          `json:"-" db:"secret"`                              // Encrypted secret, never expose
	PublicKey       []byte          `json:"-" db:"public_key"`                          // For WebAuthn
	CredentialID    []byte          `json:"-" db:"credential_id"`                       // For WebAuthn
	Counter         uint32          `json:"counter" db:"counter"`                       // For WebAuthn
	PhoneNumber     string          `json:"phone_number,omitempty" db:"phone_number"`   // For SMS
	EmailAddress    string          `json:"email_address,omitempty" db:"email_address"` // For Email
	BackupCodes     []string        `json:"-" db:"backup_codes"`                        // Encrypted backup codes
	UsedBackupCodes []string        `json:"-" db:"used_backup_codes"`                   // Track used codes
	FailedAttempts  int             `json:"failed_attempts" db:"failed_attempts"`
	LastUsedAt      *time.Time      `json:"last_used_at" db:"last_used_at"`
	LastVerifiedAt  *time.Time      `json:"last_verified_at" db:"last_verified_at"`
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at" db:"updated_at"`
	ExpiresAt       *time.Time      `json:"expires_at" db:"expires_at"`

	// Device-specific metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// IsActive checks if the MFA device is active and valid
func (m *MFADevice) IsActive() bool {
	if m.Status != MFADeviceStatusActive {
		return false
	}

	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return false
	}

	return true
}

// CanUse checks if the device can be used for authentication
func (m *MFADevice) CanUse() bool {
	return m.IsActive() && m.FailedAttempts < 5
}

// IncrementFailedAttempts increments the failed attempts counter
func (m *MFADevice) IncrementFailedAttempts() {
	m.FailedAttempts++
	m.UpdatedAt = time.Now()

	// Temporarily disable device after 5 failed attempts
	if m.FailedAttempts >= 5 {
		m.Status = MFADeviceStatusInactive
	}
}

// ResetFailedAttempts resets the failed attempts counter
func (m *MFADevice) ResetFailedAttempts() {
	m.FailedAttempts = 0
	if m.Status == MFADeviceStatusInactive && m.FailedAttempts == 0 {
		m.Status = MFADeviceStatusActive
	}
	m.UpdatedAt = time.Now()
}

// MarkAsUsed marks the device as used and updates timestamps
func (m *MFADevice) MarkAsUsed() {
	now := time.Now()
	m.LastUsedAt = &now
	m.LastVerifiedAt = &now
	m.UpdatedAt = now
	m.ResetFailedAttempts()
}

// IsBackupCode checks if this device is for backup codes
func (m *MFADevice) IsBackupCode() bool {
	return m.DeviceType == MFADeviceBackup
}

// HasUnusedBackupCodes checks if there are unused backup codes
func (m *MFADevice) HasUnusedBackupCodes() bool {
	if !m.IsBackupCode() {
		return false
	}

	usedSet := make(map[string]bool)
	for _, used := range m.UsedBackupCodes {
		usedSet[used] = true
	}

	for _, code := range m.BackupCodes {
		if !usedSet[code] {
			return true
		}
	}

	return false
}

// UseBackupCode marks a backup code as used
func (m *MFADevice) UseBackupCode(code string) bool {
	if !m.IsBackupCode() {
		return false
	}

	// Check if code exists and hasn't been used
	found := false
	for _, backupCode := range m.BackupCodes {
		if backupCode == code {
			found = true
			break
		}
	}

	if !found {
		return false
	}

	// Check if already used
	for _, usedCode := range m.UsedBackupCodes {
		if usedCode == code {
			return false
		}
	}

	// Mark as used
	m.UsedBackupCodes = append(m.UsedBackupCodes, code)
	m.MarkAsUsed()

	return true
}

// GetMaskedIdentifier returns a masked version of the device identifier for display
func (m *MFADevice) GetMaskedIdentifier() string {
	switch m.DeviceType {
	case MFADeviceSMS:
		if len(m.PhoneNumber) >= 4 {
			return "***-***-" + m.PhoneNumber[len(m.PhoneNumber)-4:]
		}
		return "***-***-****"
	case MFADeviceEmail:
		if len(m.EmailAddress) > 4 {
			at := len(m.EmailAddress)
			for i := len(m.EmailAddress) - 1; i >= 0; i-- {
				if m.EmailAddress[i] == '@' {
					at = i
					break
				}
			}
			if at > 2 {
				return m.EmailAddress[:2] + "***" + m.EmailAddress[at:]
			}
		}
		return "***@***.***"
	case MFADeviceTOTP:
		return m.DeviceName
	case MFADeviceWebAuthn:
		return m.DeviceName
	case MFADeviceBackup:
		return "Backup Codes"
	default:
		return m.DeviceName
	}
}

// NewMFADevice creates a new MFA device
func NewMFADevice(userID, tenantID uuid.UUID, deviceType MFADeviceType, deviceName string) *MFADevice {
	now := time.Now()
	return &MFADevice{
		ID:             uuid.New(),
		UserID:         userID,
		TenantID:       tenantID,
		DeviceType:     deviceType,
		DeviceName:     deviceName,
		Status:         MFADeviceStatusPending,
		IsPrimary:      false,
		IsBackup:       deviceType == MFADeviceBackup,
		FailedAttempts: 0,
		CreatedAt:      now,
		UpdatedAt:      now,
		Metadata:       make(map[string]interface{}),
	}
}

// NewTOTPDevice creates a new TOTP MFA device
func NewTOTPDevice(userID, tenantID uuid.UUID, deviceName, secret string) *MFADevice {
	device := NewMFADevice(userID, tenantID, MFADeviceTOTP, deviceName)
	device.Secret = secret
	return device
}

// NewSMSDevice creates a new SMS MFA device
func NewSMSDevice(userID, tenantID uuid.UUID, phoneNumber string) *MFADevice {
	device := NewMFADevice(userID, tenantID, MFADeviceSMS, "SMS Device")
	device.PhoneNumber = phoneNumber
	return device
}

// NewWebAuthnDevice creates a new WebAuthn MFA device
func NewWebAuthnDevice(userID, tenantID uuid.UUID, deviceName string, credentialID, publicKey []byte) *MFADevice {
	device := NewMFADevice(userID, tenantID, MFADeviceWebAuthn, deviceName)
	device.CredentialID = credentialID
	device.PublicKey = publicKey
	device.Counter = 0
	return device
}

// NewBackupDevice creates a new backup codes MFA device
func NewBackupDevice(userID, tenantID uuid.UUID, backupCodes []string) *MFADevice {
	device := NewMFADevice(userID, tenantID, MFADeviceBackup, "Backup Codes")
	device.BackupCodes = backupCodes
	device.IsBackup = true
	return device
}
