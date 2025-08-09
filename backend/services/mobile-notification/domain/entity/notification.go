package entity

import (
	"time"

	"github.com/google/uuid"
)

// NotificationPriority defines the priority levels for notifications
type NotificationPriority string

const (
	PriorityCritical      NotificationPriority = "critical"
	PriorityWarning       NotificationPriority = "warning"
	PriorityInformational NotificationPriority = "informational"
)

// NotificationStatus defines the status of a notification
type NotificationStatus string

const (
	StatusPending   NotificationStatus = "pending"
	StatusSent      NotificationStatus = "sent"
	StatusDelivered NotificationStatus = "delivered"
	StatusRead      NotificationStatus = "read"
	StatusFailed    NotificationStatus = "failed"
)

// Platform defines the push notification platform
type Platform string

const (
	PlatformFCM  Platform = "fcm"  // Firebase Cloud Messaging (Android)
	PlatformAPNS Platform = "apns" // Apple Push Notification Service (iOS)
	PlatformWeb  Platform = "web"  // Web Push
)

// Notification represents a push notification entity
type Notification struct {
	ID           uuid.UUID            `json:"id" db:"id"`
	TenantID     uuid.UUID            `json:"tenant_id" db:"tenant_id"`
	UserID       uuid.UUID            `json:"user_id" db:"user_id"`
	Title        string               `json:"title" db:"title"`
	Body         string               `json:"body" db:"body"`
	Priority     NotificationPriority `json:"priority" db:"priority"`
	Status       NotificationStatus   `json:"status" db:"status"`
	Platform     Platform             `json:"platform" db:"platform"`
	DeviceToken  string               `json:"device_token" db:"device_token"`
	Data         map[string]string    `json:"data" db:"data"`          // Additional payload data
	ImageURL     string               `json:"image_url" db:"image_url"` // Optional image for rich notifications
	ActionURL    string               `json:"action_url" db:"action_url"` // Deep link URL
	TTL          int                  `json:"ttl" db:"ttl"`              // Time to live in seconds
	BatchID      *uuid.UUID           `json:"batch_id" db:"batch_id"`    // For batched notifications
	ScheduledFor *time.Time           `json:"scheduled_for" db:"scheduled_for"` // For scheduled notifications
	SentAt       *time.Time           `json:"sent_at" db:"sent_at"`
	DeliveredAt  *time.Time           `json:"delivered_at" db:"delivered_at"`
	ReadAt       *time.Time           `json:"read_at" db:"read_at"`
	CreatedAt    time.Time            `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at" db:"updated_at"`
}

// NotificationTemplate represents a notification template entity
type NotificationTemplate struct {
	ID          uuid.UUID                      `json:"id" db:"id"`
	TenantID    uuid.UUID                      `json:"tenant_id" db:"tenant_id"`
	Name        string                         `json:"name" db:"name"`
	Type        string                         `json:"type" db:"type"` // e.g., "security_alert", "system_notification"
	Title       string                         `json:"title" db:"title"`
	Body        string                         `json:"body" db:"body"`
	Priority    NotificationPriority           `json:"priority" db:"priority"`
	Data        map[string]string              `json:"data" db:"data"`
	Variables   []string                       `json:"variables" db:"variables"` // Template variable placeholders
	Platforms   []Platform                     `json:"platforms" db:"platforms"`
	Localization map[string]LocalizedContent  `json:"localization" db:"localization"`
	IsActive    bool                           `json:"is_active" db:"is_active"`
	CreatedAt   time.Time                      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time                      `json:"updated_at" db:"updated_at"`
}

// LocalizedContent represents localized notification content
type LocalizedContent struct {
	Title string            `json:"title"`
	Body  string            `json:"body"`
	Data  map[string]string `json:"data"`
}

// DeviceRegistration represents a registered device for push notifications
type DeviceRegistration struct {
	ID            uuid.UUID `json:"id" db:"id"`
	TenantID      uuid.UUID `json:"tenant_id" db:"tenant_id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`
	DeviceToken   string    `json:"device_token" db:"device_token"`
	Platform      Platform  `json:"platform" db:"platform"`
	AppVersion    string    `json:"app_version" db:"app_version"`
	OSVersion     string    `json:"os_version" db:"os_version"`
	DeviceModel   string    `json:"device_model" db:"device_model"`
	Language      string    `json:"language" db:"language"`
	Timezone      string    `json:"timezone" db:"timezone"`
	IsActive      bool      `json:"is_active" db:"is_active"`
	LastSeenAt    time.Time `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// NotificationPreferences represents user notification preferences
type NotificationPreferences struct {
	ID                    uuid.UUID                      `json:"id" db:"id"`
	TenantID              uuid.UUID                      `json:"tenant_id" db:"tenant_id"`
	UserID                uuid.UUID                      `json:"user_id" db:"user_id"`
	SecurityAlerts        bool                           `json:"security_alerts" db:"security_alerts"`
	SystemNotifications   bool                           `json:"system_notifications" db:"system_notifications"`
	MarketingNotifications bool                          `json:"marketing_notifications" db:"marketing_notifications"`
	QuietHours            *QuietHours                    `json:"quiet_hours" db:"quiet_hours"`
	Categories            map[string]CategoryPreference  `json:"categories" db:"categories"`
	CreatedAt             time.Time                      `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time                      `json:"updated_at" db:"updated_at"`
}

// QuietHours represents user's quiet hours preferences
type QuietHours struct {
	Enabled   bool   `json:"enabled"`
	StartTime string `json:"start_time"` // HH:MM format
	EndTime   string `json:"end_time"`   // HH:MM format
	Timezone  string `json:"timezone"`
}

// CategoryPreference represents preferences for a specific notification category
type CategoryPreference struct {
	Enabled   bool                 `json:"enabled"`
	Priority  NotificationPriority `json:"priority"`
	BatchMode bool                 `json:"batch_mode"`
}

// NotificationBatch represents a batch of notifications
type NotificationBatch struct {
	ID            uuid.UUID `json:"id" db:"id"`
	TenantID      uuid.UUID `json:"tenant_id" db:"tenant_id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`
	Count         int       `json:"count" db:"count"`
	Title         string    `json:"title" db:"title"`
	Body          string    `json:"body" db:"body"`
	Platform      Platform  `json:"platform" db:"platform"`
	Status        NotificationStatus `json:"status" db:"status"`
	ScheduledFor  time.Time `json:"scheduled_for" db:"scheduled_for"`
	SentAt        *time.Time `json:"sent_at" db:"sent_at"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// NotificationDeliveryReceipt represents delivery receipt tracking
type NotificationDeliveryReceipt struct {
	ID             uuid.UUID `json:"id" db:"id"`
	NotificationID uuid.UUID `json:"notification_id" db:"notification_id"`
	DeviceToken    string    `json:"device_token" db:"device_token"`
	Platform       Platform  `json:"platform" db:"platform"`
	Status         string    `json:"status" db:"status"` // success, failed, invalid_token, etc.
	ErrorCode      string    `json:"error_code" db:"error_code"`
	ErrorMessage   string    `json:"error_message" db:"error_message"`
	AttemptCount   int       `json:"attempt_count" db:"attempt_count"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// IsPriorityHigher returns true if the current priority is higher than the compared priority
func (p NotificationPriority) IsPriorityHigher(compared NotificationPriority) bool {
	priorityOrder := map[NotificationPriority]int{
		PriorityCritical:      3,
		PriorityWarning:       2,
		PriorityInformational: 1,
	}
	return priorityOrder[p] > priorityOrder[compared]
}

// IsDelivered returns true if the notification has been delivered
func (n *Notification) IsDelivered() bool {
	return n.Status == StatusDelivered || n.Status == StatusRead
}

// IsExpired returns true if the notification has exceeded its TTL
func (n *Notification) IsExpired() bool {
	if n.TTL == 0 {
		return false
	}
	expiryTime := n.CreatedAt.Add(time.Duration(n.TTL) * time.Second)
	return time.Now().After(expiryTime)
}

// ShouldBatch returns true if the notification should be batched based on priority
func (n *Notification) ShouldBatch() bool {
	return n.Priority == PriorityInformational
}