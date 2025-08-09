package mfa

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// MFAServiceImpl implements the MFA service interface
type MFAServiceImpl struct {
	totpProvider     *TOTPProvider
	smsService       *SMSService
	webauthnProvider *WebAuthnProvider
	backupProvider   *BackupCodesProvider

	// Repositories (interfaces to be implemented)
	userRepo      UserRepository
	mfaDeviceRepo MFADeviceRepository
	auditRepo     AuditRepository

	// Configuration
	config *MFAServiceConfig
}

// MFAServiceConfig holds configuration for the MFA service
type MFAServiceConfig struct {
	TOTPIssuer         string
	SMSConfig          *SMSConfig
	WebAuthnConfig     *WebAuthnConfig
	MaxDevicesPerUser  int
	RequireMFAForRoles []string
	BackupCodesCount   int
	RateLimitWindow    time.Duration
	MaxFailedAttempts  int
}

// Repository interfaces (to be implemented by infrastructure layer)
type UserRepository interface {
	GetByID(ctx context.Context, userID, tenantID uuid.UUID) (*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
}

type MFADeviceRepository interface {
	Create(ctx context.Context, device *entity.MFADevice) error
	GetByID(ctx context.Context, deviceID, tenantID uuid.UUID) (*entity.MFADevice, error)
	GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.MFADevice, error)
	Update(ctx context.Context, device *entity.MFADevice) error
	Delete(ctx context.Context, deviceID, tenantID uuid.UUID) error
	SetPrimary(ctx context.Context, userID, tenantID, deviceID uuid.UUID) error
}

type AuditRepository interface {
	LogMFAEvent(ctx context.Context, event *service.MFAAuditEvent) error
	GetMFAStatistics(ctx context.Context, tenantID uuid.UUID) (*service.MFAStatistics, error)
	GetMFAAuditEvents(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]service.MFAAuditEvent, error)
}

// NewMFAServiceImpl creates a new MFA service implementation
func NewMFAServiceImpl(
	config *MFAServiceConfig,
	userRepo UserRepository,
	mfaDeviceRepo MFADeviceRepository,
	auditRepo AuditRepository,
) (*MFAServiceImpl, error) {

	// Initialize TOTP provider
	totpProvider := NewTOTPProvider(config.TOTPIssuer)

	// Initialize SMS service
	smsService, err := NewSMSService(config.SMSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SMS service: %w", err)
	}

	// Initialize WebAuthn provider
	webauthnProvider := NewWebAuthnProvider(config.WebAuthnConfig)

	// Initialize backup codes provider
	backupProvider := NewBackupCodesProvider()

	return &MFAServiceImpl{
		totpProvider:     totpProvider,
		smsService:       smsService,
		webauthnProvider: webauthnProvider,
		backupProvider:   backupProvider,
		userRepo:         userRepo,
		mfaDeviceRepo:    mfaDeviceRepo,
		auditRepo:        auditRepo,
		config:           config,
	}, nil
}

// EnrollDevice enrolls a new MFA device for a user
func (m *MFAServiceImpl) EnrollDevice(ctx context.Context, req *service.MFAEnrollmentRequest) (*service.MFAEnrollmentResponse, error) {
	// Validate user exists
	user, err := m.userRepo.GetByID(ctx, req.UserID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check device limit
	existingDevices, err := m.mfaDeviceRepo.GetByUserID(ctx, req.UserID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing devices: %w", err)
	}

	if len(existingDevices) >= m.config.MaxDevicesPerUser {
		return nil, fmt.Errorf("maximum number of MFA devices reached")
	}

	var response *service.MFAEnrollmentResponse
	var device *entity.MFADevice

	switch req.DeviceType {
	case entity.MFADeviceTOTP:
		response, device, err = m.enrollTOTPDevice(ctx, req, user)
	case entity.MFADeviceSMS:
		response, device, err = m.enrollSMSDevice(ctx, req, user)
	case entity.MFADeviceWebAuthn:
		response, device, err = m.enrollWebAuthnDevice(ctx, req, user)
	case entity.MFADeviceBackup:
		response, device, err = m.enrollBackupDevice(ctx, req, user)
	default:
		return nil, fmt.Errorf("unsupported device type: %s", req.DeviceType)
	}

	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}

	// Save device to database
	err = m.mfaDeviceRepo.Create(ctx, device)
	if err != nil {
		return nil, fmt.Errorf("failed to save device: %w", err)
	}

	// Log enrollment event
	m.logMFAEvent(ctx, &service.MFAAuditEvent{
		ID:         uuid.New(),
		UserID:     req.UserID,
		TenantID:   req.TenantID,
		DeviceID:   &device.ID,
		DeviceType: req.DeviceType,
		Action:     "ENROLLMENT_STARTED",
		Success:    true,
		IPAddress:  req.IPAddress,
		UserAgent:  req.UserAgent,
		CreatedAt:  time.Now(),
	})

	response.DeviceID = device.ID
	return response, nil
}

// enrollTOTPDevice enrolls a TOTP device
func (m *MFAServiceImpl) enrollTOTPDevice(ctx context.Context, req *service.MFAEnrollmentRequest, user *entity.User) (*service.MFAEnrollmentResponse, *entity.MFADevice, error) {
	// Generate TOTP secret
	secret, err := m.totpProvider.GenerateSecret(user.Email)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Generate QR code URL
	qrCodeURL, err := m.totpProvider.GenerateQRCode(secret, user.Email)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Create device
	device := entity.NewTOTPDevice(req.UserID, req.TenantID, req.DeviceName, secret)
	device.Status = entity.MFADeviceStatusPending // Pending until confirmed

	// Generate enrollment ID for confirmation
	enrollmentID := m.generateEnrollmentID()

	response := &service.MFAEnrollmentResponse{
		QRCodeURL:    qrCodeURL,
		Secret:       secret, // Temporary - will be removed after confirmation
		EnrollmentID: enrollmentID,
	}

	return response, device, nil
}

// enrollSMSDevice enrolls an SMS device
func (m *MFAServiceImpl) enrollSMSDevice(ctx context.Context, req *service.MFAEnrollmentRequest, user *entity.User) (*service.MFAEnrollmentResponse, *entity.MFADevice, error) {
	// Validate phone number
	if req.PhoneNumber == "" {
		return nil, nil, fmt.Errorf("phone number required for SMS device")
	}

	// Create device
	device := entity.NewSMSDevice(req.UserID, req.TenantID, req.PhoneNumber)
	device.Status = entity.MFADeviceStatusPending

	// Send verification SMS
	challengeID, err := m.smsService.SendVerificationCode(ctx, req.PhoneNumber, req.IPAddress, req.UserAgent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send verification SMS: %w", err)
	}

	response := &service.MFAEnrollmentResponse{
		EnrollmentID: challengeID,
	}

	return response, device, nil
}

// enrollWebAuthnDevice enrolls a WebAuthn device
func (m *MFAServiceImpl) enrollWebAuthnDevice(ctx context.Context, req *service.MFAEnrollmentRequest, user *entity.User) (*service.MFAEnrollmentResponse, *entity.MFADevice, error) {
	// Begin WebAuthn registration
	challenge, err := m.webauthnProvider.BeginRegistration(ctx, req.UserID, user.Username, user.GetFullName())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin WebAuthn registration: %w", err)
	}

	// Create device (will be updated after successful registration)
	device := entity.NewWebAuthnDevice(req.UserID, req.TenantID, req.DeviceName, nil, nil)
	device.Status = entity.MFADeviceStatusPending

	response := &service.MFAEnrollmentResponse{
		Challenge:    challenge.Challenge,
		EnrollmentID: challenge.ID,
	}

	return response, device, nil
}

// enrollBackupDevice enrolls backup codes
func (m *MFAServiceImpl) enrollBackupDevice(ctx context.Context, req *service.MFAEnrollmentRequest, user *entity.User) (*service.MFAEnrollmentResponse, *entity.MFADevice, error) {
	// Generate backup codes
	backupCodes, err := m.backupProvider.GenerateBackupCodes(m.config.BackupCodesCount)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Create device
	device := entity.NewBackupDevice(req.UserID, req.TenantID, backupCodes)
	device.Status = entity.MFADeviceStatusActive // Backup codes are immediately active

	response := &service.MFAEnrollmentResponse{
		BackupCodes:  backupCodes,
		EnrollmentID: device.ID.String(),
	}

	return response, device, nil
}

// ConfirmEnrollment confirms MFA device enrollment
func (m *MFAServiceImpl) ConfirmEnrollment(ctx context.Context, enrollmentID, confirmationCode string) (*entity.MFADevice, error) {
	// This is a simplified implementation - in production, you'd track enrollment sessions

	// Try to parse as device ID for backup codes
	if deviceID, err := uuid.Parse(enrollmentID); err == nil {
		device, err := m.mfaDeviceRepo.GetByID(ctx, deviceID, uuid.Nil) // TODO: Get tenant ID
		if err == nil && device.DeviceType == entity.MFADeviceBackup {
			device.Status = entity.MFADeviceStatusActive
			err = m.mfaDeviceRepo.Update(ctx, device)
			return device, err
		}
	}

	// For SMS devices, verify the code
	verified, err := m.smsService.VerifyCode(enrollmentID, confirmationCode)
	if err != nil {
		return nil, fmt.Errorf("failed to verify confirmation code: %w", err)
	}

	if !verified {
		return nil, fmt.Errorf("invalid confirmation code")
	}

	// TODO: Update device status to active
	// This requires additional tracking of enrollment sessions

	return nil, fmt.Errorf("enrollment confirmation not implemented for this device type")
}

// SendMFAChallenge sends an MFA challenge
func (m *MFAServiceImpl) SendMFAChallenge(ctx context.Context, req *service.MFAChallengeRequest) (*service.MFAChallengeResponse, error) {
	// Get user's MFA devices
	devices, err := m.mfaDeviceRepo.GetByUserID(ctx, req.UserID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	// Filter active devices of requested type
	var allowedDevices []entity.MFADevice
	for _, device := range devices {
		if device.DeviceType == req.DeviceType && device.IsActive() {
			allowedDevices = append(allowedDevices, device)
		}
	}

	if len(allowedDevices) == 0 {
		return nil, fmt.Errorf("no active devices of type %s found", req.DeviceType)
	}

	var challengeID string
	var maskedTarget string

	switch req.DeviceType {
	case entity.MFADeviceSMS:
		// Send SMS to primary SMS device
		smsDevice := allowedDevices[0] // TODO: Select primary device
		challengeID, err = m.smsService.SendVerificationCode(ctx, smsDevice.PhoneNumber, req.IPAddress, req.UserAgent)
		if err != nil {
			return nil, fmt.Errorf("failed to send SMS challenge: %w", err)
		}
		maskedTarget = smsDevice.GetMaskedIdentifier()

	case entity.MFADeviceWebAuthn:
		// Begin WebAuthn authentication
		challenge, err := m.webauthnProvider.BeginAuthentication(ctx, req.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to begin WebAuthn challenge: %w", err)
		}
		challengeID = challenge.ID
		maskedTarget = "Security Key"

	default:
		return nil, fmt.Errorf("challenge not supported for device type: %s", req.DeviceType)
	}

	response := &service.MFAChallengeResponse{
		ChallengeID:    challengeID,
		DeviceType:     req.DeviceType,
		MaskedTarget:   maskedTarget,
		ExpiresAt:      time.Now().Add(10 * time.Minute),
		AllowedDevices: allowedDevices,
	}

	return response, nil
}

// VerifyMFAResponse verifies an MFA response
func (m *MFAServiceImpl) VerifyMFAResponse(ctx context.Context, req *service.MFAVerificationRequest) (*service.MFAVerificationResponse, error) {
	var success bool
	var err error
	var deviceID uuid.UUID

	switch req.DeviceType {
	case entity.MFADeviceTOTP:
		success, deviceID, err = m.verifyTOTPCode(ctx, req)
	case entity.MFADeviceSMS:
		success, deviceID, err = m.verifySMSCode(ctx, req)
	case entity.MFADeviceWebAuthn:
		success, deviceID, err = m.verifyWebAuthnResponse(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported device type: %s", req.DeviceType)
	}

	if err != nil {
		// Log failed verification
		m.logMFAEvent(ctx, &service.MFAAuditEvent{
			ID:            uuid.New(),
			UserID:        req.UserID,
			TenantID:      req.TenantID,
			DeviceType:    req.DeviceType,
			Action:        "VERIFICATION_FAILED",
			Success:       false,
			FailureReason: err.Error(),
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			CreatedAt:     time.Now(),
		})

		return &service.MFAVerificationResponse{
			Success:       false,
			FailureReason: err.Error(),
		}, nil
	}

	if success {
		// Log successful verification
		m.logMFAEvent(ctx, &service.MFAAuditEvent{
			ID:         uuid.New(),
			UserID:     req.UserID,
			TenantID:   req.TenantID,
			DeviceID:   &deviceID,
			DeviceType: req.DeviceType,
			Action:     "VERIFICATION_SUCCESS",
			Success:    true,
			IPAddress:  req.IPAddress,
			UserAgent:  req.UserAgent,
			CreatedAt:  time.Now(),
		})
	}

	return &service.MFAVerificationResponse{
		Success:  success,
		DeviceID: deviceID,
	}, nil
}

// verifyTOTPCode verifies a TOTP code
func (m *MFAServiceImpl) verifyTOTPCode(ctx context.Context, req *service.MFAVerificationRequest) (bool, uuid.UUID, error) {
	// Get user's TOTP devices
	devices, err := m.mfaDeviceRepo.GetByUserID(ctx, req.UserID, req.TenantID)
	if err != nil {
		return false, uuid.Nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	// Try to verify with each TOTP device
	for _, device := range devices {
		if device.DeviceType == entity.MFADeviceTOTP && device.IsActive() {
			if req.DeviceID != nil && device.ID != *req.DeviceID {
				continue // Skip if specific device ID requested
			}

			valid := m.totpProvider.ValidateCode(device.Secret, req.Code, 1)
			if valid {
				// Update device usage
				device.MarkAsUsed()
				m.mfaDeviceRepo.Update(ctx, &device)
				return true, device.ID, nil
			}

			// Increment failed attempts
			device.IncrementFailedAttempts()
			m.mfaDeviceRepo.Update(ctx, &device)
		}
	}

	return false, uuid.Nil, fmt.Errorf("invalid TOTP code")
}

// verifySMSCode verifies an SMS code
func (m *MFAServiceImpl) verifySMSCode(ctx context.Context, req *service.MFAVerificationRequest) (bool, uuid.UUID, error) {
	// This assumes the challenge ID is provided from the earlier SendMFAChallenge call
	verified, err := m.smsService.VerifyCode(req.Challenge, req.Code)
	if err != nil {
		return false, uuid.Nil, err
	}

	if verified && req.DeviceID != nil {
		// Update device usage
		device, err := m.mfaDeviceRepo.GetByID(ctx, *req.DeviceID, req.TenantID)
		if err == nil {
			device.MarkAsUsed()
			m.mfaDeviceRepo.Update(ctx, device)
		}
		return true, *req.DeviceID, nil
	}

	return verified, uuid.Nil, nil
}

// verifyWebAuthnResponse verifies a WebAuthn response
func (m *MFAServiceImpl) verifyWebAuthnResponse(ctx context.Context, req *service.MFAVerificationRequest) (bool, uuid.UUID, error) {
	// Parse WebAuthn response (simplified)
	// In production, properly parse the JSON response

	// For now, return success for any non-empty response
	if req.Response != "" {
		if req.DeviceID != nil {
			device, err := m.mfaDeviceRepo.GetByID(ctx, *req.DeviceID, req.TenantID)
			if err == nil {
				device.MarkAsUsed()
				m.mfaDeviceRepo.Update(ctx, device)
			}
			return true, *req.DeviceID, nil
		}
	}

	return false, uuid.Nil, fmt.Errorf("invalid WebAuthn response")
}

// VerifyBackupCode verifies a backup code
func (m *MFAServiceImpl) VerifyBackupCode(ctx context.Context, userID, tenantID uuid.UUID, backupCode string) (*service.MFAVerificationResponse, error) {
	// Normalize backup code
	normalizedCode := m.backupProvider.NormalizeBackupCode(backupCode)

	// Get user's backup device
	devices, err := m.mfaDeviceRepo.GetByUserID(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	for _, device := range devices {
		if device.DeviceType == entity.MFADeviceBackup && device.IsActive() {
			if device.UseBackupCode(normalizedCode) {
				// Update device
				err = m.mfaDeviceRepo.Update(ctx, &device)
				if err != nil {
					return nil, fmt.Errorf("failed to update device: %w", err)
				}

				// Log usage
				m.logMFAEvent(ctx, &service.MFAAuditEvent{
					ID:         uuid.New(),
					UserID:     userID,
					TenantID:   tenantID,
					DeviceID:   &device.ID,
					DeviceType: entity.MFADeviceBackup,
					Action:     "BACKUP_CODE_USED",
					Success:    true,
					CreatedAt:  time.Now(),
				})

				return &service.MFAVerificationResponse{
					Success:         true,
					DeviceID:        device.ID,
					BackupAvailable: device.HasUnusedBackupCodes(),
				}, nil
			}
		}
	}

	return &service.MFAVerificationResponse{
		Success:       false,
		FailureReason: "Invalid backup code",
	}, nil
}

// Helper methods

func (m *MFAServiceImpl) generateEnrollmentID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

func (m *MFAServiceImpl) logMFAEvent(ctx context.Context, event *service.MFAAuditEvent) {
	// Log MFA event (fire and forget)
	go func() {
		m.auditRepo.LogMFAEvent(context.Background(), event)
	}()
}

// Additional interface methods (simplified implementations)

func (m *MFAServiceImpl) RemoveDevice(ctx context.Context, userID, tenantID, deviceID uuid.UUID) error {
	return m.mfaDeviceRepo.Delete(ctx, deviceID, tenantID)
}

func (m *MFAServiceImpl) ListUserDevices(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.MFADevice, error) {
	return m.mfaDeviceRepo.GetByUserID(ctx, userID, tenantID)
}

func (m *MFAServiceImpl) GetDevice(ctx context.Context, deviceID, tenantID uuid.UUID) (*entity.MFADevice, error) {
	return m.mfaDeviceRepo.GetByID(ctx, deviceID, tenantID)
}

func (m *MFAServiceImpl) SetPrimaryDevice(ctx context.Context, userID, tenantID, deviceID uuid.UUID) error {
	return m.mfaDeviceRepo.SetPrimary(ctx, userID, tenantID, deviceID)
}

func (m *MFAServiceImpl) GenerateTOTPSecret(ctx context.Context, config *service.TOTPConfig) (string, string, error) {
	secret, err := m.totpProvider.GenerateSecret(config.AccountName)
	if err != nil {
		return "", "", err
	}

	qrCodeURL, err := m.totpProvider.GenerateQRCode(secret, config.AccountName)
	if err != nil {
		return "", "", err
	}

	return secret, qrCodeURL, nil
}

func (m *MFAServiceImpl) ValidateTOTPCode(ctx context.Context, secret, code string, window int) bool {
	return m.totpProvider.ValidateCode(secret, code, window)
}

func (m *MFAServiceImpl) GenerateBackupCodes(ctx context.Context, count int) ([]string, error) {
	return m.backupProvider.GenerateBackupCodes(count)
}

func (m *MFAServiceImpl) CheckRateLimit(ctx context.Context, userID uuid.UUID, action string) (bool, time.Duration, error) {
	// TODO: Implement rate limiting with Redis or database
	return true, 0, nil
}

func (m *MFAServiceImpl) LogSecurityEvent(ctx context.Context, userID, tenantID uuid.UUID, eventType, details string) error {
	event := &service.MFAAuditEvent{
		ID:        uuid.New(),
		UserID:    userID,
		TenantID:  tenantID,
		Action:    eventType,
		Success:   true,
		CreatedAt: time.Now(),
		Metadata:  map[string]interface{}{"details": details},
	}
	return m.auditRepo.LogMFAEvent(ctx, event)
}

func (m *MFAServiceImpl) DetectAnomalousActivity(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (bool, []string, error) {
	// TODO: Implement anomaly detection
	return false, []string{}, nil
}

func (m *MFAServiceImpl) ForceMFAEnrollment(ctx context.Context, userID, tenantID uuid.UUID, enforced bool) error {
	user, err := m.userRepo.GetByID(ctx, userID, tenantID)
	if err != nil {
		return err
	}

	user.MFAEnforced = enforced
	return m.userRepo.Update(ctx, user)
}

func (m *MFAServiceImpl) GetMFAStatistics(ctx context.Context, tenantID uuid.UUID) (*service.MFAStatistics, error) {
	return m.auditRepo.GetMFAStatistics(ctx, tenantID)
}

func (m *MFAServiceImpl) AuditMFAActivity(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]service.MFAAuditEvent, error) {
	return m.auditRepo.GetMFAAuditEvents(ctx, tenantID, from, to)
}
