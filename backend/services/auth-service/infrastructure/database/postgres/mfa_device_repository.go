package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"isectech/auth-service/domain/entity"
)

// MFADeviceRepository implements the MFA device repository interface for PostgreSQL
type MFADeviceRepository struct {
	db *sqlx.DB
}

// NewMFADeviceRepository creates a new PostgreSQL MFA device repository
func NewMFADeviceRepository(db *sqlx.DB) *MFADeviceRepository {
	return &MFADeviceRepository{
		db: db,
	}
}

// Create creates a new MFA device in the database
func (r *MFADeviceRepository) Create(ctx context.Context, device *entity.MFADevice) error {
	// Convert slices to JSON for storage
	backupCodesJSON, err := json.Marshal(device.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	usedBackupCodesJSON, err := json.Marshal(device.UsedBackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal used backup codes: %w", err)
	}

	metadataJSON, err := json.Marshal(device.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO mfa_devices (
			id, user_id, tenant_id, device_type, device_name, status, is_primary, is_backup,
			secret, public_key, credential_id, counter, phone_number, email_address,
			backup_codes, used_backup_codes, failed_attempts, last_used_at, last_verified_at,
			created_at, updated_at, expires_at, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
		)`

	_, err = r.db.ExecContext(ctx, query,
		device.ID, device.UserID, device.TenantID, device.DeviceType, device.DeviceName,
		device.Status, device.IsPrimary, device.IsBackup, device.Secret, device.PublicKey,
		device.CredentialID, device.Counter, device.PhoneNumber, device.EmailAddress,
		backupCodesJSON, usedBackupCodesJSON, device.FailedAttempts, device.LastUsedAt,
		device.LastVerifiedAt, device.CreatedAt, device.UpdatedAt, device.ExpiresAt, metadataJSON,
	)

	if err != nil {
		if IsUniqueConstraintError(err) {
			return fmt.Errorf("MFA device with this name already exists for user")
		}
		return WrapSQLError(err, "create_mfa_device", query, device)
	}

	return nil
}

// GetByID retrieves an MFA device by ID and tenant ID
func (r *MFADeviceRepository) GetByID(ctx context.Context, deviceID, tenantID uuid.UUID) (*entity.MFADevice, error) {
	var device entity.MFADevice
	var backupCodesJSON, usedBackupCodesJSON, metadataJSON []byte

	query := `
		SELECT 
			id, user_id, tenant_id, device_type, device_name, status, is_primary, is_backup,
			secret, public_key, credential_id, counter, phone_number, email_address,
			backup_codes, used_backup_codes, failed_attempts, last_used_at, last_verified_at,
			created_at, updated_at, expires_at, metadata
		FROM mfa_devices 
		WHERE id = $1 AND tenant_id = $2`

	err := r.db.QueryRowContext(ctx, query, deviceID, tenantID).Scan(
		&device.ID, &device.UserID, &device.TenantID, &device.DeviceType, &device.DeviceName,
		&device.Status, &device.IsPrimary, &device.IsBackup, &device.Secret, &device.PublicKey,
		&device.CredentialID, &device.Counter, &device.PhoneNumber, &device.EmailAddress,
		&backupCodesJSON, &usedBackupCodesJSON, &device.FailedAttempts, &device.LastUsedAt,
		&device.LastVerifiedAt, &device.CreatedAt, &device.UpdatedAt, &device.ExpiresAt, &metadataJSON,
	)

	if err != nil {
		if IsNoRowsError(err) {
			return nil, fmt.Errorf("MFA device not found")
		}
		return nil, WrapSQLError(err, "get_mfa_device_by_id", query, deviceID, tenantID)
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal backup codes: %w", err)
	}

	if err := json.Unmarshal(usedBackupCodesJSON, &device.UsedBackupCodes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal used backup codes: %w", err)
	}

	if err := json.Unmarshal(metadataJSON, &device.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &device, nil
}

// GetByUserID retrieves all MFA devices for a user
func (r *MFADeviceRepository) GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.MFADevice, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, device_type, device_name, status, is_primary, is_backup,
			secret, public_key, credential_id, counter, phone_number, email_address,
			backup_codes, used_backup_codes, failed_attempts, last_used_at, last_verified_at,
			created_at, updated_at, expires_at, metadata
		FROM mfa_devices 
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY is_primary DESC, created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_mfa_devices_by_user", query, userID, tenantID)
	}
	defer rows.Close()

	var devices []entity.MFADevice
	for rows.Next() {
		var device entity.MFADevice
		var backupCodesJSON, usedBackupCodesJSON, metadataJSON []byte

		err := rows.Scan(
			&device.ID, &device.UserID, &device.TenantID, &device.DeviceType, &device.DeviceName,
			&device.Status, &device.IsPrimary, &device.IsBackup, &device.Secret, &device.PublicKey,
			&device.CredentialID, &device.Counter, &device.PhoneNumber, &device.EmailAddress,
			&backupCodesJSON, &usedBackupCodesJSON, &device.FailedAttempts, &device.LastUsedAt,
			&device.LastVerifiedAt, &device.CreatedAt, &device.UpdatedAt, &device.ExpiresAt, &metadataJSON,
		)
		if err != nil {
			return nil, WrapSQLError(err, "scan_mfa_device", query, userID, tenantID)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal backup codes for device %s: %w", device.ID, err)
		}

		if err := json.Unmarshal(usedBackupCodesJSON, &device.UsedBackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal used backup codes for device %s: %w", device.ID, err)
		}

		if err := json.Unmarshal(metadataJSON, &device.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for device %s: %w", device.ID, err)
		}

		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, WrapSQLError(err, "get_mfa_devices_by_user_rows", query, userID, tenantID)
	}

	return devices, nil
}

// Update updates an existing MFA device
func (r *MFADeviceRepository) Update(ctx context.Context, device *entity.MFADevice) error {
	device.UpdatedAt = time.Now()

	// Convert slices to JSON for storage
	backupCodesJSON, err := json.Marshal(device.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	usedBackupCodesJSON, err := json.Marshal(device.UsedBackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal used backup codes: %w", err)
	}

	metadataJSON, err := json.Marshal(device.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE mfa_devices SET
			device_name = $3,
			status = $4,
			is_primary = $5,
			is_backup = $6,
			secret = $7,
			public_key = $8,
			credential_id = $9,
			counter = $10,
			phone_number = $11,
			email_address = $12,
			backup_codes = $13,
			used_backup_codes = $14,
			failed_attempts = $15,
			last_used_at = $16,
			last_verified_at = $17,
			updated_at = $18,
			expires_at = $19,
			metadata = $20
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query,
		device.ID, device.TenantID, device.DeviceName, device.Status, device.IsPrimary,
		device.IsBackup, device.Secret, device.PublicKey, device.CredentialID, device.Counter,
		device.PhoneNumber, device.EmailAddress, backupCodesJSON, usedBackupCodesJSON,
		device.FailedAttempts, device.LastUsedAt, device.LastVerifiedAt, device.UpdatedAt,
		device.ExpiresAt, metadataJSON,
	)

	if err != nil {
		return WrapSQLError(err, "update_mfa_device", query, device)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "update_mfa_device_check_rows", query, device)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("MFA device not found or no changes made")
	}

	return nil
}

// Delete removes an MFA device from the database
func (r *MFADeviceRepository) Delete(ctx context.Context, deviceID, tenantID uuid.UUID) error {
	query := `DELETE FROM mfa_devices WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, deviceID, tenantID)
	if err != nil {
		return WrapSQLError(err, "delete_mfa_device", query, deviceID, tenantID)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "delete_mfa_device_check_rows", query, deviceID, tenantID)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("MFA device not found")
	}

	return nil
}

// SetPrimary sets a device as the primary MFA device for a user
func (r *MFADeviceRepository) SetPrimary(ctx context.Context, userID, tenantID, deviceID uuid.UUID) error {
	// Use a transaction to ensure atomicity
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// First, unset all primary devices for the user
	unsetQuery := `
		UPDATE mfa_devices 
		SET is_primary = false, updated_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2`

	_, err = tx.ExecContext(ctx, unsetQuery, userID, tenantID)
	if err != nil {
		return WrapSQLError(err, "unset_primary_devices", unsetQuery, userID, tenantID)
	}

	// Then set the specified device as primary
	setPrimaryQuery := `
		UPDATE mfa_devices 
		SET is_primary = true, updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND tenant_id = $3`

	result, err := tx.ExecContext(ctx, setPrimaryQuery, deviceID, userID, tenantID)
	if err != nil {
		return WrapSQLError(err, "set_primary_device", setPrimaryQuery, deviceID, userID, tenantID)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "set_primary_device_check_rows", setPrimaryQuery, deviceID, userID, tenantID)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("MFA device not found")
	}

	return tx.Commit()
}

// GetActiveDevices retrieves all active MFA devices for a user
func (r *MFADeviceRepository) GetActiveDevices(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.MFADevice, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, device_type, device_name, status, is_primary, is_backup,
			secret, public_key, credential_id, counter, phone_number, email_address,
			backup_codes, used_backup_codes, failed_attempts, last_used_at, last_verified_at,
			created_at, updated_at, expires_at, metadata
		FROM mfa_devices 
		WHERE user_id = $1 AND tenant_id = $2 AND status = 'ACTIVE' 
		AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY is_primary DESC, created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_active_mfa_devices", query, userID, tenantID)
	}
	defer rows.Close()

	var devices []entity.MFADevice
	for rows.Next() {
		var device entity.MFADevice
		var backupCodesJSON, usedBackupCodesJSON, metadataJSON []byte

		err := rows.Scan(
			&device.ID, &device.UserID, &device.TenantID, &device.DeviceType, &device.DeviceName,
			&device.Status, &device.IsPrimary, &device.IsBackup, &device.Secret, &device.PublicKey,
			&device.CredentialID, &device.Counter, &device.PhoneNumber, &device.EmailAddress,
			&backupCodesJSON, &usedBackupCodesJSON, &device.FailedAttempts, &device.LastUsedAt,
			&device.LastVerifiedAt, &device.CreatedAt, &device.UpdatedAt, &device.ExpiresAt, &metadataJSON,
		)
		if err != nil {
			return nil, WrapSQLError(err, "scan_active_mfa_device", query, userID, tenantID)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal backup codes for device %s: %w", device.ID, err)
		}

		if err := json.Unmarshal(usedBackupCodesJSON, &device.UsedBackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal used backup codes for device %s: %w", device.ID, err)
		}

		if err := json.Unmarshal(metadataJSON, &device.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for device %s: %w", device.ID, err)
		}

		devices = append(devices, device)
	}

	return devices, rows.Err()
}

// GetByDeviceType retrieves MFA devices by type for a user
func (r *MFADeviceRepository) GetByDeviceType(ctx context.Context, userID, tenantID uuid.UUID, deviceType entity.MFADeviceType) ([]entity.MFADevice, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, device_type, device_name, status, is_primary, is_backup,
			secret, public_key, credential_id, counter, phone_number, email_address,
			backup_codes, used_backup_codes, failed_attempts, last_used_at, last_verified_at,
			created_at, updated_at, expires_at, metadata
		FROM mfa_devices 
		WHERE user_id = $1 AND tenant_id = $2 AND device_type = $3
		ORDER BY is_primary DESC, created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID, deviceType)
	if err != nil {
		return nil, WrapSQLError(err, "get_mfa_devices_by_type", query, userID, tenantID, deviceType)
	}
	defer rows.Close()

	var devices []entity.MFADevice
	for rows.Next() {
		var device entity.MFADevice
		var backupCodesJSON, usedBackupCodesJSON, metadataJSON []byte

		err := rows.Scan(
			&device.ID, &device.UserID, &device.TenantID, &device.DeviceType, &device.DeviceName,
			&device.Status, &device.IsPrimary, &device.IsBackup, &device.Secret, &device.PublicKey,
			&device.CredentialID, &device.Counter, &device.PhoneNumber, &device.EmailAddress,
			&backupCodesJSON, &usedBackupCodesJSON, &device.FailedAttempts, &device.LastUsedAt,
			&device.LastVerifiedAt, &device.CreatedAt, &device.UpdatedAt, &device.ExpiresAt, &metadataJSON,
		)
		if err != nil {
			return nil, WrapSQLError(err, "scan_mfa_device_by_type", query, userID, tenantID, deviceType)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal backup codes for device %s: %w", device.ID, err)
		}

		if err := json.Unmarshal(usedBackupCodesJSON, &device.UsedBackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal used backup codes for device %s: %w", device.ID, err)
		}

		if err := json.Unmarshal(metadataJSON, &device.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for device %s: %w", device.ID, err)
		}

		devices = append(devices, device)
	}

	return devices, rows.Err()
}

// CleanupExpired removes expired MFA devices
func (r *MFADeviceRepository) CleanupExpired(ctx context.Context) (int, error) {
	query := `DELETE FROM mfa_devices WHERE expires_at IS NOT NULL AND expires_at <= NOW()`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, WrapSQLError(err, "cleanup_expired_devices", query)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, WrapSQLError(err, "cleanup_expired_devices_check_rows", query)
	}

	return int(rowsAffected), nil
}

// GetDeviceStats returns MFA device statistics for a tenant
func (r *MFADeviceRepository) GetDeviceStats(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	query := `
		SELECT 
			COUNT(*) as total_devices,
			COUNT(CASE WHEN status = 'ACTIVE' THEN 1 END) as active_devices,
			COUNT(CASE WHEN status = 'INACTIVE' THEN 1 END) as inactive_devices,
			COUNT(CASE WHEN device_type = 'TOTP' THEN 1 END) as totp_devices,
			COUNT(CASE WHEN device_type = 'SMS' THEN 1 END) as sms_devices,
			COUNT(CASE WHEN device_type = 'WEBAUTHN' THEN 1 END) as webauthn_devices,
			COUNT(CASE WHEN device_type = 'EMAIL' THEN 1 END) as email_devices,
			COUNT(CASE WHEN device_type = 'BACKUP' THEN 1 END) as backup_devices,
			COUNT(CASE WHEN is_primary = true THEN 1 END) as primary_devices,
			COUNT(CASE WHEN last_used_at > NOW() - INTERVAL '24 hours' THEN 1 END) as used_24h,
			COUNT(CASE WHEN last_used_at > NOW() - INTERVAL '7 days' THEN 1 END) as used_7d,
			COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 1 END) as expired_devices
		FROM mfa_devices 
		WHERE tenant_id = $1`

	var stats struct {
		TotalDevices    int `db:"total_devices"`
		ActiveDevices   int `db:"active_devices"`
		InactiveDevices int `db:"inactive_devices"`
		TOTPDevices     int `db:"totp_devices"`
		SMSDevices      int `db:"sms_devices"`
		WebAuthnDevices int `db:"webauthn_devices"`
		EmailDevices    int `db:"email_devices"`
		BackupDevices   int `db:"backup_devices"`
		PrimaryDevices  int `db:"primary_devices"`
		Used24h         int `db:"used_24h"`
		Used7d          int `db:"used_7d"`
		ExpiredDevices  int `db:"expired_devices"`
	}

	err := r.db.GetContext(ctx, &stats, query, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_device_stats", query, tenantID)
	}

	return map[string]interface{}{
		"total_devices":    stats.TotalDevices,
		"active_devices":   stats.ActiveDevices,
		"inactive_devices": stats.InactiveDevices,
		"totp_devices":     stats.TOTPDevices,
		"sms_devices":      stats.SMSDevices,
		"webauthn_devices": stats.WebAuthnDevices,
		"email_devices":    stats.EmailDevices,
		"backup_devices":   stats.BackupDevices,
		"primary_devices":  stats.PrimaryDevices,
		"used_24h":         stats.Used24h,
		"used_7d":          stats.Used7d,
		"expired_devices":  stats.ExpiredDevices,
	}, nil
}

// BulkUpdateStatus updates the status of multiple devices
func (r *MFADeviceRepository) BulkUpdateStatus(ctx context.Context, deviceIDs []uuid.UUID, tenantID uuid.UUID, status entity.MFADeviceStatus) error {
	if len(deviceIDs) == 0 {
		return nil
	}

	query := `
		UPDATE mfa_devices 
		SET status = $1, updated_at = NOW()
		WHERE tenant_id = $2 AND id = ANY($3)`

	result, err := r.db.ExecContext(ctx, query, status, tenantID, pq.Array(deviceIDs))
	if err != nil {
		return WrapSQLError(err, "bulk_update_device_status", query, status, tenantID, deviceIDs)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "bulk_update_device_status_check_rows", query, status, tenantID, deviceIDs)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no devices updated")
	}

	return nil
}
