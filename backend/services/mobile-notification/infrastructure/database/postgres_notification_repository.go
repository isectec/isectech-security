package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mobile-notification/domain/entity"
	"mobile-notification/domain/repository"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
)

// PostgresNotificationRepository implements notification repository using PostgreSQL
type PostgresNotificationRepository struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewPostgresNotificationRepository creates a new PostgreSQL notification repository
func NewPostgresNotificationRepository(db *sql.DB, logger *logrus.Logger) *PostgresNotificationRepository {
	return &PostgresNotificationRepository{
		db:     db,
		logger: logger,
	}
}

// Create creates a new notification
func (r *PostgresNotificationRepository) Create(ctx context.Context, notification *entity.Notification) error {
	query := `
		INSERT INTO notifications (
			id, tenant_id, user_id, title, body, priority, status, platform, 
			device_token, data, image_url, action_url, ttl, batch_id, 
			scheduled_for, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	dataJSON, err := json.Marshal(notification.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		notification.ID,
		notification.TenantID,
		notification.UserID,
		notification.Title,
		notification.Body,
		notification.Priority,
		notification.Status,
		notification.Platform,
		notification.DeviceToken,
		dataJSON,
		notification.ImageURL,
		notification.ActionURL,
		notification.TTL,
		notification.BatchID,
		notification.ScheduledFor,
		notification.CreatedAt,
		notification.UpdatedAt,
	)

	if err != nil {
		r.logger.WithError(err).Error("Failed to create notification")
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return nil
}

// GetByID gets a notification by ID
func (r *PostgresNotificationRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.Notification, error) {
	query := `
		SELECT id, tenant_id, user_id, title, body, priority, status, platform,
			   device_token, data, image_url, action_url, ttl, batch_id,
			   scheduled_for, sent_at, delivered_at, read_at, created_at, updated_at
		FROM notifications WHERE id = $1`

	notification := &entity.Notification{}
	var dataJSON []byte
	var scheduledFor, sentAt, deliveredAt, readAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&notification.ID,
		&notification.TenantID,
		&notification.UserID,
		&notification.Title,
		&notification.Body,
		&notification.Priority,
		&notification.Status,
		&notification.Platform,
		&notification.DeviceToken,
		&dataJSON,
		&notification.ImageURL,
		&notification.ActionURL,
		&notification.TTL,
		&notification.BatchID,
		&scheduledFor,
		&sentAt,
		&deliveredAt,
		&readAt,
		&notification.CreatedAt,
		&notification.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("notification not found")
		}
		return nil, fmt.Errorf("failed to get notification: %w", err)
	}

	// Unmarshal data JSON
	if len(dataJSON) > 0 {
		err = json.Unmarshal(dataJSON, &notification.Data)
		if err != nil {
			r.logger.WithError(err).Warn("Failed to unmarshal notification data")
		}
	}

	// Handle nullable timestamps
	if scheduledFor.Valid {
		notification.ScheduledFor = &scheduledFor.Time
	}
	if sentAt.Valid {
		notification.SentAt = &sentAt.Time
	}
	if deliveredAt.Valid {
		notification.DeliveredAt = &deliveredAt.Time
	}
	if readAt.Valid {
		notification.ReadAt = &readAt.Time
	}

	return notification, nil
}

// Update updates an existing notification
func (r *PostgresNotificationRepository) Update(ctx context.Context, notification *entity.Notification) error {
	query := `
		UPDATE notifications SET
			title = $2, body = $3, priority = $4, status = $5, platform = $6,
			device_token = $7, data = $8, image_url = $9, action_url = $10,
			ttl = $11, batch_id = $12, scheduled_for = $13, sent_at = $14,
			delivered_at = $15, read_at = $16, updated_at = $17
		WHERE id = $1`

	dataJSON, err := json.Marshal(notification.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	notification.UpdatedAt = time.Now()

	_, err = r.db.ExecContext(ctx, query,
		notification.ID,
		notification.Title,
		notification.Body,
		notification.Priority,
		notification.Status,
		notification.Platform,
		notification.DeviceToken,
		dataJSON,
		notification.ImageURL,
		notification.ActionURL,
		notification.TTL,
		notification.BatchID,
		notification.ScheduledFor,
		notification.SentAt,
		notification.DeliveredAt,
		notification.ReadAt,
		notification.UpdatedAt,
	)

	if err != nil {
		r.logger.WithError(err).Error("Failed to update notification")
		return fmt.Errorf("failed to update notification: %w", err)
	}

	return nil
}

// Delete deletes a notification
func (r *PostgresNotificationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM notifications WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete notification: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("notification not found")
	}

	return nil
}

// GetByUserID gets notifications for a specific user
func (r *PostgresNotificationRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*entity.Notification, error) {
	query := `
		SELECT id, tenant_id, user_id, title, body, priority, status, platform,
			   device_token, data, image_url, action_url, ttl, batch_id,
			   scheduled_for, sent_at, delivered_at, read_at, created_at, updated_at
		FROM notifications 
		WHERE user_id = $1 
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query notifications: %w", err)
	}
	defer rows.Close()

	return r.scanNotifications(rows)
}

// GetPendingNotifications gets all pending notifications
func (r *PostgresNotificationRepository) GetPendingNotifications(ctx context.Context, limit int) ([]*entity.Notification, error) {
	query := `
		SELECT id, tenant_id, user_id, title, body, priority, status, platform,
			   device_token, data, image_url, action_url, ttl, batch_id,
			   scheduled_for, sent_at, delivered_at, read_at, created_at, updated_at
		FROM notifications 
		WHERE status = $1 AND (scheduled_for IS NULL OR scheduled_for <= NOW())
		ORDER BY priority DESC, created_at ASC
		LIMIT $2`

	rows, err := r.db.QueryContext(ctx, query, entity.StatusPending, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending notifications: %w", err)
	}
	defer rows.Close()

	return r.scanNotifications(rows)
}

// GetNotificationsByStatus gets notifications by status
func (r *PostgresNotificationRepository) GetNotificationsByStatus(ctx context.Context, status entity.NotificationStatus, limit int) ([]*entity.Notification, error) {
	query := `
		SELECT id, tenant_id, user_id, title, body, priority, status, platform,
			   device_token, data, image_url, action_url, ttl, batch_id,
			   scheduled_for, sent_at, delivered_at, read_at, created_at, updated_at
		FROM notifications 
		WHERE status = $1 
		ORDER BY created_at DESC 
		LIMIT $2`

	rows, err := r.db.QueryContext(ctx, query, status, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query notifications by status: %w", err)
	}
	defer rows.Close()

	return r.scanNotifications(rows)
}

// GetScheduledNotifications gets notifications scheduled for delivery
func (r *PostgresNotificationRepository) GetScheduledNotifications(ctx context.Context, beforeTime time.Time) ([]*entity.Notification, error) {
	query := `
		SELECT id, tenant_id, user_id, title, body, priority, status, platform,
			   device_token, data, image_url, action_url, ttl, batch_id,
			   scheduled_for, sent_at, delivered_at, read_at, created_at, updated_at
		FROM notifications 
		WHERE status = $1 AND scheduled_for <= $2
		ORDER BY scheduled_for ASC`

	rows, err := r.db.QueryContext(ctx, query, entity.StatusPending, beforeTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query scheduled notifications: %w", err)
	}
	defer rows.Close()

	return r.scanNotifications(rows)
}

// UpdateStatus updates notification status
func (r *PostgresNotificationRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status entity.NotificationStatus) error {
	var query string
	var args []interface{}

	switch status {
	case entity.StatusSent:
		query = `UPDATE notifications SET status = $1, sent_at = $2, updated_at = $3 WHERE id = $4`
		args = []interface{}{status, time.Now(), time.Now(), id}
	case entity.StatusDelivered:
		query = `UPDATE notifications SET status = $1, delivered_at = $2, updated_at = $3 WHERE id = $4`
		args = []interface{}{status, time.Now(), time.Now(), id}
	case entity.StatusRead:
		query = `UPDATE notifications SET status = $1, read_at = $2, updated_at = $3 WHERE id = $4`
		args = []interface{}{status, time.Now(), time.Now(), id}
	default:
		query = `UPDATE notifications SET status = $1, updated_at = $2 WHERE id = $3`
		args = []interface{}{status, time.Now(), id}
	}

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update notification status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("notification not found")
	}

	return nil
}

// BulkCreate creates multiple notifications in a single transaction
func (r *PostgresNotificationRepository) BulkCreate(ctx context.Context, notifications []*entity.Notification) error {
	if len(notifications) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO notifications (
			id, tenant_id, user_id, title, body, priority, status, platform, 
			device_token, data, image_url, action_url, ttl, batch_id, 
			scheduled_for, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, notification := range notifications {
		dataJSON, err := json.Marshal(notification.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal data: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			notification.ID,
			notification.TenantID,
			notification.UserID,
			notification.Title,
			notification.Body,
			notification.Priority,
			notification.Status,
			notification.Platform,
			notification.DeviceToken,
			dataJSON,
			notification.ImageURL,
			notification.ActionURL,
			notification.TTL,
			notification.BatchID,
			notification.ScheduledFor,
			notification.CreatedAt,
			notification.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert notification: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetAnalytics gets analytics data for a tenant within a date range
func (r *PostgresNotificationRepository) GetAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*repository.AnalyticsData, error) {
	analytics := &repository.AnalyticsData{
		ByPriority: make(map[entity.NotificationPriority]int64),
		ByPlatform: make(map[entity.Platform]int64),
		ByStatus:   make(map[entity.NotificationStatus]int64),
		ByHour:     make(map[int]repository.HourlyMetrics),
		ByDay:      make(map[string]repository.DailyMetrics),
	}

	// Get overall counts
	query := `
		SELECT 
			COUNT(*) as total_sent,
			COUNT(CASE WHEN status = 'delivered' OR status = 'read' THEN 1 END) as total_delivered,
			COUNT(CASE WHEN status = 'read' THEN 1 END) as total_read,
			COUNT(CASE WHEN status = 'failed' THEN 1 END) as total_failed
		FROM notifications 
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3`

	err := r.db.QueryRowContext(ctx, query, tenantID, from, to).Scan(
		&analytics.TotalSent,
		&analytics.TotalDelivered,
		&analytics.TotalRead,
		&analytics.TotalFailed,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get overall analytics: %w", err)
	}

	// Get by priority
	query = `
		SELECT priority, COUNT(*) 
		FROM notifications 
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY priority`

	rows, err := r.db.QueryContext(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to get priority analytics: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var priority entity.NotificationPriority
		var count int64
		if err := rows.Scan(&priority, &count); err != nil {
			return nil, err
		}
		analytics.ByPriority[priority] = count
	}

	// Get by platform
	query = `
		SELECT platform, COUNT(*) 
		FROM notifications 
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY platform`

	rows, err = r.db.QueryContext(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform analytics: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var platform entity.Platform
		var count int64
		if err := rows.Scan(&platform, &count); err != nil {
			return nil, err
		}
		analytics.ByPlatform[platform] = count
	}

	// Get by status
	query = `
		SELECT status, COUNT(*) 
		FROM notifications 
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY status`

	rows, err = r.db.QueryContext(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to get status analytics: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status entity.NotificationStatus
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		analytics.ByStatus[status] = count
	}

	return analytics, nil
}

// CleanupOldNotifications removes old notifications beyond retention period
func (r *PostgresNotificationRepository) CleanupOldNotifications(ctx context.Context, retentionDays int) (int64, error) {
	query := `DELETE FROM notifications WHERE created_at < $1`
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	result, err := r.db.ExecContext(ctx, query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old notifications: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// scanNotifications scans multiple notification rows
func (r *PostgresNotificationRepository) scanNotifications(rows *sql.Rows) ([]*entity.Notification, error) {
	notifications := make([]*entity.Notification, 0)

	for rows.Next() {
		notification := &entity.Notification{}
		var dataJSON []byte
		var scheduledFor, sentAt, deliveredAt, readAt sql.NullTime

		err := rows.Scan(
			&notification.ID,
			&notification.TenantID,
			&notification.UserID,
			&notification.Title,
			&notification.Body,
			&notification.Priority,
			&notification.Status,
			&notification.Platform,
			&notification.DeviceToken,
			&dataJSON,
			&notification.ImageURL,
			&notification.ActionURL,
			&notification.TTL,
			&notification.BatchID,
			&scheduledFor,
			&sentAt,
			&deliveredAt,
			&readAt,
			&notification.CreatedAt,
			&notification.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan notification: %w", err)
		}

		// Unmarshal data JSON
		if len(dataJSON) > 0 {
			err = json.Unmarshal(dataJSON, &notification.Data)
			if err != nil {
				r.logger.WithError(err).Warn("Failed to unmarshal notification data")
			}
		}

		// Handle nullable timestamps
		if scheduledFor.Valid {
			notification.ScheduledFor = &scheduledFor.Time
		}
		if sentAt.Valid {
			notification.SentAt = &sentAt.Time
		}
		if deliveredAt.Valid {
			notification.DeliveredAt = &deliveredAt.Time
		}
		if readAt.Valid {
			notification.ReadAt = &readAt.Time
		}

		notifications = append(notifications, notification)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return notifications, nil
}