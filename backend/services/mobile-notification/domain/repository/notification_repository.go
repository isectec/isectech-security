package repository

import (
	"context"
	"mobile-notification/domain/entity"
	"time"

	"github.com/google/uuid"
)

// NotificationRepository defines the interface for notification data persistence
type NotificationRepository interface {
	// Create creates a new notification
	Create(ctx context.Context, notification *entity.Notification) error
	
	// GetByID gets a notification by ID
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Notification, error)
	
	// Update updates an existing notification
	Update(ctx context.Context, notification *entity.Notification) error
	
	// Delete deletes a notification
	Delete(ctx context.Context, id uuid.UUID) error
	
	// GetByUserID gets notifications for a specific user
	GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*entity.Notification, error)
	
	// GetPendingNotifications gets all pending notifications
	GetPendingNotifications(ctx context.Context, limit int) ([]*entity.Notification, error)
	
	// GetNotificationsByStatus gets notifications by status
	GetNotificationsByStatus(ctx context.Context, status entity.NotificationStatus, limit int) ([]*entity.Notification, error)
	
	// GetScheduledNotifications gets notifications scheduled for delivery
	GetScheduledNotifications(ctx context.Context, beforeTime time.Time) ([]*entity.Notification, error)
	
	// UpdateStatus updates notification status
	UpdateStatus(ctx context.Context, id uuid.UUID, status entity.NotificationStatus) error
	
	// BulkCreate creates multiple notifications in a single transaction
	BulkCreate(ctx context.Context, notifications []*entity.Notification) error
	
	// GetAnalytics gets analytics data for a tenant within a date range
	GetAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*AnalyticsData, error)
	
	// CleanupOldNotifications removes old notifications beyond retention period
	CleanupOldNotifications(ctx context.Context, retentionDays int) (int64, error)
}

// DeviceRegistrationRepository defines the interface for device registration persistence
type DeviceRegistrationRepository interface {
	// Create creates a new device registration
	Create(ctx context.Context, device *entity.DeviceRegistration) error
	
	// GetByToken gets a device registration by token
	GetByToken(ctx context.Context, token string) (*entity.DeviceRegistration, error)
	
	// GetByUserID gets all device registrations for a user
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*entity.DeviceRegistration, error)
	
	// Update updates an existing device registration
	Update(ctx context.Context, device *entity.DeviceRegistration) error
	
	// Delete deletes a device registration
	Delete(ctx context.Context, id uuid.UUID) error
	
	// DeleteByToken deletes a device registration by token
	DeleteByToken(ctx context.Context, token string) error
	
	// UpdateLastSeen updates the last seen timestamp
	UpdateLastSeen(ctx context.Context, token string, lastSeen time.Time) error
	
	// GetInactiveDevices gets devices that haven't been seen for specified days
	GetInactiveDevices(ctx context.Context, inactiveDays int) ([]*entity.DeviceRegistration, error)
	
	// BulkDelete deletes multiple device registrations
	BulkDelete(ctx context.Context, ids []uuid.UUID) error
	
	// RefreshToken updates a device token
	RefreshToken(ctx context.Context, oldToken, newToken string) error
	
	// GetActiveDeviceCount gets count of active devices
	GetActiveDeviceCount(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// NotificationTemplateRepository defines the interface for template persistence
type NotificationTemplateRepository interface {
	// Create creates a new notification template
	Create(ctx context.Context, template *entity.NotificationTemplate) error
	
	// GetByID gets a template by ID
	GetByID(ctx context.Context, id uuid.UUID) (*entity.NotificationTemplate, error)
	
	// GetByTenantID gets all templates for a tenant
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*entity.NotificationTemplate, error)
	
	// GetByType gets templates by type
	GetByType(ctx context.Context, tenantID uuid.UUID, templateType string) ([]*entity.NotificationTemplate, error)
	
	// Update updates an existing template
	Update(ctx context.Context, template *entity.NotificationTemplate) error
	
	// Delete deletes a template
	Delete(ctx context.Context, id uuid.UUID) error
	
	// GetActiveTemplates gets all active templates for a tenant
	GetActiveTemplates(ctx context.Context, tenantID uuid.UUID) ([]*entity.NotificationTemplate, error)
}

// NotificationPreferencesRepository defines the interface for user preferences persistence
type NotificationPreferencesRepository interface {
	// Create creates new notification preferences
	Create(ctx context.Context, preferences *entity.NotificationPreferences) error
	
	// GetByUserID gets preferences by user ID
	GetByUserID(ctx context.Context, userID uuid.UUID) (*entity.NotificationPreferences, error)
	
	// Update updates existing preferences
	Update(ctx context.Context, preferences *entity.NotificationPreferences) error
	
	// Delete deletes preferences
	Delete(ctx context.Context, userID uuid.UUID) error
	
	// GetUsersInQuietHours gets users currently in quiet hours
	GetUsersInQuietHours(ctx context.Context) ([]uuid.UUID, error)
}

// NotificationBatchRepository defines the interface for batch persistence
type NotificationBatchRepository interface {
	// Create creates a new notification batch
	Create(ctx context.Context, batch *entity.NotificationBatch) error
	
	// GetByID gets a batch by ID
	GetByID(ctx context.Context, id uuid.UUID) (*entity.NotificationBatch, error)
	
	// Update updates an existing batch
	Update(ctx context.Context, batch *entity.NotificationBatch) error
	
	// GetPendingBatches gets all pending batches ready for processing
	GetPendingBatches(ctx context.Context) ([]*entity.NotificationBatch, error)
	
	// UpdateStatus updates batch status
	UpdateStatus(ctx context.Context, id uuid.UUID, status entity.NotificationStatus) error
}

// DeliveryReceiptRepository defines the interface for delivery receipt persistence
type DeliveryReceiptRepository interface {
	// Create creates a new delivery receipt
	Create(ctx context.Context, receipt *entity.NotificationDeliveryReceipt) error
	
	// GetByNotificationID gets receipts for a notification
	GetByNotificationID(ctx context.Context, notificationID uuid.UUID) ([]*entity.NotificationDeliveryReceipt, error)
	
	// Update updates an existing receipt
	Update(ctx context.Context, receipt *entity.NotificationDeliveryReceipt) error
	
	// BulkCreate creates multiple receipts
	BulkCreate(ctx context.Context, receipts []*entity.NotificationDeliveryReceipt) error
	
	// GetFailedReceipts gets receipts for failed deliveries
	GetFailedReceipts(ctx context.Context, limit int) ([]*entity.NotificationDeliveryReceipt, error)
}

// AnalyticsData represents aggregated analytics data from the repository
type AnalyticsData struct {
	TotalSent      int64                                    `json:"total_sent"`
	TotalDelivered int64                                    `json:"total_delivered"`
	TotalRead      int64                                    `json:"total_read"`
	TotalFailed    int64                                    `json:"total_failed"`
	ByPriority     map[entity.NotificationPriority]int64   `json:"by_priority"`
	ByPlatform     map[entity.Platform]int64               `json:"by_platform"`
	ByStatus       map[entity.NotificationStatus]int64     `json:"by_status"`
	ByHour         map[int]HourlyMetrics                   `json:"by_hour"`
	ByDay          map[string]DailyMetrics                 `json:"by_day"`
}

// HourlyMetrics represents hourly aggregated metrics
type HourlyMetrics struct {
	Hour      int   `json:"hour"`
	Sent      int64 `json:"sent"`
	Delivered int64 `json:"delivered"`
	Read      int64 `json:"read"`
	Failed    int64 `json:"failed"`
}

// DailyMetrics represents daily aggregated metrics
type DailyMetrics struct {
	Date      string `json:"date"`
	Sent      int64  `json:"sent"`
	Delivered int64  `json:"delivered"`
	Read      int64  `json:"read"`
	Failed    int64  `json:"failed"`
}

// NotificationFilter represents filtering options for notifications
type NotificationFilter struct {
	UserID       *uuid.UUID                `json:"user_id,omitempty"`
	TenantID     *uuid.UUID                `json:"tenant_id,omitempty"`
	Status       *entity.NotificationStatus `json:"status,omitempty"`
	Priority     *entity.NotificationPriority `json:"priority,omitempty"`
	Platform     *entity.Platform          `json:"platform,omitempty"`
	FromDate     *time.Time                `json:"from_date,omitempty"`
	ToDate       *time.Time                `json:"to_date,omitempty"`
	Category     *string                   `json:"category,omitempty"`
	Limit        int                       `json:"limit"`
	Offset       int                       `json:"offset"`
	SortBy       string                    `json:"sort_by"`
	SortOrder    string                    `json:"sort_order"`
}