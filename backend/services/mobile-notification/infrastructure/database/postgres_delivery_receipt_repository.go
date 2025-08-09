package database

import (
	"context"
	"database/sql"
	"fmt"
	"mobile-notification/domain/entity"
	"mobile-notification/domain/repository"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// PostgresDeliveryReceiptRepository implements delivery receipt repository using PostgreSQL
type PostgresDeliveryReceiptRepository struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewPostgresDeliveryReceiptRepository creates a new PostgreSQL delivery receipt repository
func NewPostgresDeliveryReceiptRepository(db *sql.DB, logger *logrus.Logger) *PostgresDeliveryReceiptRepository {
	return &PostgresDeliveryReceiptRepository{
		db:     db,
		logger: logger,
	}
}

// Create creates a new delivery receipt
func (r *PostgresDeliveryReceiptRepository) Create(ctx context.Context, receipt *entity.NotificationDeliveryReceipt) error {
	query := `
		INSERT INTO notification_delivery_receipts (
			id, notification_id, device_token, platform, status, error_code, 
			error_message, attempt_count, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	if receipt.ID == uuid.Nil {
		receipt.ID = uuid.New()
	}
	
	if receipt.CreatedAt.IsZero() {
		receipt.CreatedAt = time.Now()
	}
	
	if receipt.UpdatedAt.IsZero() {
		receipt.UpdatedAt = receipt.CreatedAt
	}

	_, err := r.db.ExecContext(ctx, query,
		receipt.ID,
		receipt.NotificationID,
		receipt.DeviceToken,
		receipt.Platform,
		receipt.Status,
		receipt.ErrorCode,
		receipt.ErrorMessage,
		receipt.AttemptCount,
		receipt.CreatedAt,
		receipt.UpdatedAt,
	)

	if err != nil {
		r.logger.WithError(err).WithField("receipt_id", receipt.ID).Error("Failed to create delivery receipt")
		return fmt.Errorf("failed to create delivery receipt: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"receipt_id":      receipt.ID,
		"notification_id": receipt.NotificationID,
		"status":          receipt.Status,
		"platform":        receipt.Platform,
	}).Debug("Created delivery receipt")

	return nil
}

// GetByNotificationID gets receipts for a specific notification
func (r *PostgresDeliveryReceiptRepository) GetByNotificationID(ctx context.Context, notificationID uuid.UUID) ([]*entity.NotificationDeliveryReceipt, error) {
	query := `
		SELECT id, notification_id, device_token, platform, status, error_code,
			   error_message, attempt_count, created_at, updated_at
		FROM notification_delivery_receipts 
		WHERE notification_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, notificationID)
	if err != nil {
		return nil, fmt.Errorf("failed to query delivery receipts: %w", err)
	}
	defer rows.Close()

	receipts := make([]*entity.NotificationDeliveryReceipt, 0)

	for rows.Next() {
		receipt := &entity.NotificationDeliveryReceipt{}
		
		err := rows.Scan(
			&receipt.ID,
			&receipt.NotificationID,
			&receipt.DeviceToken,
			&receipt.Platform,
			&receipt.Status,
			&receipt.ErrorCode,
			&receipt.ErrorMessage,
			&receipt.AttemptCount,
			&receipt.CreatedAt,
			&receipt.UpdatedAt,
		)

		if err != nil {
			r.logger.WithError(err).Error("Failed to scan delivery receipt")
			continue
		}

		receipts = append(receipts, receipt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return receipts, nil
}

// Update updates an existing delivery receipt
func (r *PostgresDeliveryReceiptRepository) Update(ctx context.Context, receipt *entity.NotificationDeliveryReceipt) error {
	query := `
		UPDATE notification_delivery_receipts SET
			device_token = $2, platform = $3, status = $4, error_code = $5,
			error_message = $6, attempt_count = $7, updated_at = $8
		WHERE id = $1`

	receipt.UpdatedAt = time.Now()

	result, err := r.db.ExecContext(ctx, query,
		receipt.ID,
		receipt.DeviceToken,
		receipt.Platform,
		receipt.Status,
		receipt.ErrorCode,
		receipt.ErrorMessage,
		receipt.AttemptCount,
		receipt.UpdatedAt,
	)

	if err != nil {
		r.logger.WithError(err).WithField("receipt_id", receipt.ID).Error("Failed to update delivery receipt")
		return fmt.Errorf("failed to update delivery receipt: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("delivery receipt not found: %s", receipt.ID)
	}

	r.logger.WithFields(logrus.Fields{
		"receipt_id":      receipt.ID,
		"notification_id": receipt.NotificationID,
		"status":          receipt.Status,
	}).Debug("Updated delivery receipt")

	return nil
}

// BulkCreate creates multiple delivery receipts in a single transaction
func (r *PostgresDeliveryReceiptRepository) BulkCreate(ctx context.Context, receipts []*entity.NotificationDeliveryReceipt) error {
	if len(receipts) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO notification_delivery_receipts (
			id, notification_id, device_token, platform, status, error_code, 
			error_message, attempt_count, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	now := time.Now()
	
	for _, receipt := range receipts {
		if receipt.ID == uuid.Nil {
			receipt.ID = uuid.New()
		}
		
		if receipt.CreatedAt.IsZero() {
			receipt.CreatedAt = now
		}
		
		if receipt.UpdatedAt.IsZero() {
			receipt.UpdatedAt = receipt.CreatedAt
		}

		_, err = stmt.ExecContext(ctx,
			receipt.ID,
			receipt.NotificationID,
			receipt.DeviceToken,
			receipt.Platform,
			receipt.Status,
			receipt.ErrorCode,
			receipt.ErrorMessage,
			receipt.AttemptCount,
			receipt.CreatedAt,
			receipt.UpdatedAt,
		)
		
		if err != nil {
			r.logger.WithError(err).WithField("receipt_id", receipt.ID).Error("Failed to insert delivery receipt in bulk")
			return fmt.Errorf("failed to insert delivery receipt: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.WithField("count", len(receipts)).Info("Bulk created delivery receipts")
	return nil
}

// GetFailedReceipts gets receipts for failed deliveries that may need retry
func (r *PostgresDeliveryReceiptRepository) GetFailedReceipts(ctx context.Context, limit int) ([]*entity.NotificationDeliveryReceipt, error) {
	query := `
		SELECT id, notification_id, device_token, platform, status, error_code,
			   error_message, attempt_count, created_at, updated_at
		FROM notification_delivery_receipts 
		WHERE status = 'failed' 
		AND attempt_count < 5  -- Max retry attempts
		AND updated_at > NOW() - INTERVAL '24 hours'  -- Only recent failures
		ORDER BY created_at ASC
		LIMIT $1`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query failed receipts: %w", err)
	}
	defer rows.Close()

	receipts := make([]*entity.NotificationDeliveryReceipt, 0)

	for rows.Next() {
		receipt := &entity.NotificationDeliveryReceipt{}
		
		err := rows.Scan(
			&receipt.ID,
			&receipt.NotificationID,
			&receipt.DeviceToken,
			&receipt.Platform,
			&receipt.Status,
			&receipt.ErrorCode,
			&receipt.ErrorMessage,
			&receipt.AttemptCount,
			&receipt.CreatedAt,
			&receipt.UpdatedAt,
		)

		if err != nil {
			r.logger.WithError(err).Error("Failed to scan failed receipt")
			continue
		}

		receipts = append(receipts, receipt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return receipts, nil
}

// GetReceiptsByDeviceToken gets receipts for a specific device token (useful for device health monitoring)
func (r *PostgresDeliveryReceiptRepository) GetReceiptsByDeviceToken(ctx context.Context, deviceToken string, limit int) ([]*entity.NotificationDeliveryReceipt, error) {
	query := `
		SELECT id, notification_id, device_token, platform, status, error_code,
			   error_message, attempt_count, created_at, updated_at
		FROM notification_delivery_receipts 
		WHERE device_token = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.db.QueryContext(ctx, query, deviceToken, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query receipts by device token: %w", err)
	}
	defer rows.Close()

	receipts := make([]*entity.NotificationDeliveryReceipt, 0)

	for rows.Next() {
		receipt := &entity.NotificationDeliveryReceipt{}
		
		err := rows.Scan(
			&receipt.ID,
			&receipt.NotificationID,
			&receipt.DeviceToken,
			&receipt.Platform,
			&receipt.Status,
			&receipt.ErrorCode,
			&receipt.ErrorMessage,
			&receipt.AttemptCount,
			&receipt.CreatedAt,
			&receipt.UpdatedAt,
		)

		if err != nil {
			r.logger.WithError(err).Error("Failed to scan receipt by device token")
			continue
		}

		receipts = append(receipts, receipt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return receipts, nil
}

// GetReceiptStats gets aggregated statistics for delivery receipts
func (r *PostgresDeliveryReceiptRepository) GetReceiptStats(ctx context.Context, from, to time.Time, platform *entity.Platform) (*DeliveryReceiptStats, error) {
	whereClause := "WHERE created_at BETWEEN $1 AND $2"
	args := []interface{}{from, to}
	
	if platform != nil {
		whereClause += " AND platform = $3"
		args = append(args, *platform)
	}

	query := fmt.Sprintf(`
		SELECT 
			COUNT(*) as total_receipts,
			COUNT(CASE WHEN status = 'delivered' THEN 1 END) as delivered_count,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_count,
			COUNT(CASE WHEN status = 'sent' THEN 1 END) as sent_count,
			AVG(attempt_count) as avg_attempts,
			COUNT(DISTINCT device_token) as unique_devices,
			COUNT(DISTINCT notification_id) as unique_notifications
		FROM notification_delivery_receipts %s`, whereClause)

	stats := &DeliveryReceiptStats{}
	
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&stats.TotalReceipts,
		&stats.DeliveredCount,
		&stats.FailedCount,
		&stats.SentCount,
		&stats.AverageAttempts,
		&stats.UniqueDevices,
		&stats.UniqueNotifications,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get receipt stats: %w", err)
	}

	// Calculate rates
	if stats.TotalReceipts > 0 {
		stats.DeliveryRate = float64(stats.DeliveredCount) / float64(stats.TotalReceipts) * 100
		stats.FailureRate = float64(stats.FailedCount) / float64(stats.TotalReceipts) * 100
	}

	return stats, nil
}

// CleanupOldReceipts removes old delivery receipts beyond retention period
func (r *PostgresDeliveryReceiptRepository) CleanupOldReceipts(ctx context.Context, retentionDays int) (int64, error) {
	query := `DELETE FROM notification_delivery_receipts WHERE created_at < $1`
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	result, err := r.db.ExecContext(ctx, query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old receipts: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		r.logger.WithFields(logrus.Fields{
			"deleted_count":   rowsAffected,
			"retention_days":  retentionDays,
			"cutoff_date":     cutoffDate,
		}).Info("Cleaned up old delivery receipts")
	}

	return rowsAffected, nil
}

// GetReceiptsByStatus gets receipts filtered by status
func (r *PostgresDeliveryReceiptRepository) GetReceiptsByStatus(ctx context.Context, status string, from, to time.Time, limit int) ([]*entity.NotificationDeliveryReceipt, error) {
	query := `
		SELECT id, notification_id, device_token, platform, status, error_code,
			   error_message, attempt_count, created_at, updated_at
		FROM notification_delivery_receipts 
		WHERE status = $1 AND created_at BETWEEN $2 AND $3
		ORDER BY created_at DESC
		LIMIT $4`

	rows, err := r.db.QueryContext(ctx, query, status, from, to, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query receipts by status: %w", err)
	}
	defer rows.Close()

	receipts := make([]*entity.NotificationDeliveryReceipt, 0)

	for rows.Next() {
		receipt := &entity.NotificationDeliveryReceipt{}
		
		err := rows.Scan(
			&receipt.ID,
			&receipt.NotificationID,
			&receipt.DeviceToken,
			&receipt.Platform,
			&receipt.Status,
			&receipt.ErrorCode,
			&receipt.ErrorMessage,
			&receipt.AttemptCount,
			&receipt.CreatedAt,
			&receipt.UpdatedAt,
		)

		if err != nil {
			r.logger.WithError(err).Error("Failed to scan receipt by status")
			continue
		}

		receipts = append(receipts, receipt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return receipts, nil
}

// IncrementAttemptCount increments the attempt count for a receipt
func (r *PostgresDeliveryReceiptRepository) IncrementAttemptCount(ctx context.Context, receiptID uuid.UUID) error {
	query := `
		UPDATE notification_delivery_receipts 
		SET attempt_count = attempt_count + 1, updated_at = $2
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, receiptID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to increment attempt count: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("delivery receipt not found: %s", receiptID)
	}

	return nil
}

// DeliveryReceiptStats represents aggregated delivery receipt statistics
type DeliveryReceiptStats struct {
	TotalReceipts       int64   `json:"total_receipts"`
	DeliveredCount      int64   `json:"delivered_count"`
	FailedCount         int64   `json:"failed_count"`
	SentCount           int64   `json:"sent_count"`
	DeliveryRate        float64 `json:"delivery_rate"`        // Percentage
	FailureRate         float64 `json:"failure_rate"`         // Percentage
	AverageAttempts     float64 `json:"average_attempts"`
	UniqueDevices       int64   `json:"unique_devices"`
	UniqueNotifications int64   `json:"unique_notifications"`
}