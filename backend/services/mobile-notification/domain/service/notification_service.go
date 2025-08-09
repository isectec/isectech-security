package service

import (
	"context"
	"mobile-notification/domain/entity"

	"github.com/google/uuid"
)

// NotificationService defines the business logic interface for notifications
type NotificationService interface {
	// SendNotification sends a notification to a specific user
	SendNotification(ctx context.Context, notification *entity.Notification) error
	
	// SendBatchNotifications sends notifications to multiple users
	SendBatchNotifications(ctx context.Context, notifications []*entity.Notification) error
	
	// ProcessNotificationQueue processes pending notifications from the queue
	ProcessNotificationQueue(ctx context.Context) error
	
	// ValidateNotification validates notification data before sending
	ValidateNotification(notification *entity.Notification) error
	
	// ApplyTemplate applies a template to create a notification
	ApplyTemplate(ctx context.Context, templateID uuid.UUID, userID uuid.UUID, variables map[string]string) (*entity.Notification, error)
	
	// GetNotificationHistory gets notification history for a user
	GetNotificationHistory(ctx context.Context, userID uuid.UUID, limit int, offset int) ([]*entity.Notification, error)
	
	// UpdateNotificationStatus updates the status of a notification
	UpdateNotificationStatus(ctx context.Context, notificationID uuid.UUID, status entity.NotificationStatus) error
	
	// GetNotificationAnalytics gets analytics data for notifications
	GetNotificationAnalytics(ctx context.Context, tenantID uuid.UUID, from, to string) (*NotificationAnalytics, error)
}

// PushNotificationService defines the interface for push notification providers
type PushNotificationService interface {
	// SendFCM sends notification via Firebase Cloud Messaging
	SendFCM(ctx context.Context, notification *entity.Notification) (*PushResult, error)
	
	// SendAPNS sends notification via Apple Push Notification Service
	SendAPNS(ctx context.Context, notification *entity.Notification) (*PushResult, error)
	
	// SendWebPush sends web push notification
	SendWebPush(ctx context.Context, notification *entity.Notification) (*PushResult, error)
	
	// ValidateToken validates a device token for the platform
	ValidateToken(ctx context.Context, token string, platform entity.Platform) error
	
	// GetDeliveryReceipts gets delivery receipts from the push service
	GetDeliveryReceipts(ctx context.Context, notificationIDs []uuid.UUID) ([]*entity.NotificationDeliveryReceipt, error)
}

// DeviceManagementService defines the interface for managing device registrations
type DeviceManagementService interface {
	// RegisterDevice registers a new device for push notifications
	RegisterDevice(ctx context.Context, registration *entity.DeviceRegistration) error
	
	// UnregisterDevice unregisters a device
	UnregisterDevice(ctx context.Context, deviceToken string) error
	
	// GetDevicesForUser gets all registered devices for a user
	GetDevicesForUser(ctx context.Context, userID uuid.UUID) ([]*entity.DeviceRegistration, error)
	
	// UpdateDeviceLastSeen updates the last seen timestamp for a device
	UpdateDeviceLastSeen(ctx context.Context, deviceToken string) error
	
	// CleanupInactiveDevices removes devices that haven't been seen for a specified period
	CleanupInactiveDevices(ctx context.Context, inactiveDays int) error
	
	// RefreshDeviceToken updates a device token (for token refresh scenarios)
	RefreshDeviceToken(ctx context.Context, oldToken, newToken string) error
}

// TemplateService defines the interface for notification templates
type TemplateService interface {
	// CreateTemplate creates a new notification template
	CreateTemplate(ctx context.Context, template *entity.NotificationTemplate) error
	
	// GetTemplate gets a template by ID
	GetTemplate(ctx context.Context, templateID uuid.UUID) (*entity.NotificationTemplate, error)
	
	// GetTemplatesByTenant gets all templates for a tenant
	GetTemplatesByTenant(ctx context.Context, tenantID uuid.UUID) ([]*entity.NotificationTemplate, error)
	
	// UpdateTemplate updates an existing template
	UpdateTemplate(ctx context.Context, template *entity.NotificationTemplate) error
	
	// DeleteTemplate deletes a template
	DeleteTemplate(ctx context.Context, templateID uuid.UUID) error
	
	// RenderTemplate renders a template with variables
	RenderTemplate(template *entity.NotificationTemplate, variables map[string]string, language string) (*entity.Notification, error)
}

// PreferencesService defines the interface for user notification preferences
type PreferencesService interface {
	// GetUserPreferences gets notification preferences for a user
	GetUserPreferences(ctx context.Context, userID uuid.UUID) (*entity.NotificationPreferences, error)
	
	// UpdateUserPreferences updates notification preferences for a user
	UpdateUserPreferences(ctx context.Context, preferences *entity.NotificationPreferences) error
	
	// CheckQuietHours checks if current time is within user's quiet hours
	CheckQuietHours(ctx context.Context, userID uuid.UUID) (bool, error)
	
	// ShouldDeliverNotification checks if notification should be delivered based on preferences
	ShouldDeliverNotification(ctx context.Context, userID uuid.UUID, notification *entity.Notification) (bool, error)
}

// BatchingService defines the interface for notification batching
type BatchingService interface {
	// CreateBatch creates a new notification batch
	CreateBatch(ctx context.Context, batch *entity.NotificationBatch) error
	
	// AddToBatch adds notifications to an existing batch
	AddToBatch(ctx context.Context, batchID uuid.UUID, notifications []*entity.Notification) error
	
	// ProcessBatches processes pending notification batches
	ProcessBatches(ctx context.Context) error
	
	// GetBatchStatus gets the status of a notification batch
	GetBatchStatus(ctx context.Context, batchID uuid.UUID) (*entity.NotificationBatch, error)
}

// PushResult represents the result of a push notification send operation
type PushResult struct {
	Success      bool              `json:"success"`
	MessageID    string            `json:"message_id"`
	ErrorCode    string            `json:"error_code,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Retry        bool              `json:"retry"`
	RetryAfter   int               `json:"retry_after,omitempty"` // seconds
	TokenValid   bool              `json:"token_valid"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// NotificationAnalytics represents analytics data for notifications
type NotificationAnalytics struct {
	TotalSent      int64                            `json:"total_sent"`
	TotalDelivered int64                            `json:"total_delivered"`
	TotalRead      int64                            `json:"total_read"`
	TotalFailed    int64                            `json:"total_failed"`
	DeliveryRate   float64                          `json:"delivery_rate"`
	ReadRate       float64                          `json:"read_rate"`
	ByPriority     map[entity.NotificationPriority]int64 `json:"by_priority"`
	ByPlatform     map[entity.Platform]int64              `json:"by_platform"`
	ByCategory     map[string]int64                 `json:"by_category"`
	Hourly         []HourlyStats                    `json:"hourly"`
}

// HourlyStats represents hourly notification statistics
type HourlyStats struct {
	Hour      int   `json:"hour"`
	Sent      int64 `json:"sent"`
	Delivered int64 `json:"delivered"`
	Read      int64 `json:"read"`
	Failed    int64 `json:"failed"`
}

// RetryPolicy defines the retry policy for failed notifications
type RetryPolicy struct {
	MaxAttempts     int   `json:"max_attempts"`
	BackoffBase     int   `json:"backoff_base"`     // Base backoff time in seconds
	BackoffMultiplier float64 `json:"backoff_multiplier"` // Multiplier for exponential backoff
	MaxBackoff      int   `json:"max_backoff"`     // Maximum backoff time in seconds
}

// NotificationMetrics represents metrics for monitoring
type NotificationMetrics struct {
	TotalNotifications int64 `json:"total_notifications"`
	QueueSize          int64 `json:"queue_size"`
	ProcessingRate     float64 `json:"processing_rate"` // notifications per second
	AverageLatency     float64 `json:"average_latency"` // milliseconds
	ErrorRate          float64 `json:"error_rate"`      // percentage
	ActiveDevices      int64   `json:"active_devices"`
	InactiveDevices    int64   `json:"inactive_devices"`
}