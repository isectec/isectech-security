package tracking

import (
	"context"
	"fmt"
	"mobile-notification/domain/entity"
	"mobile-notification/domain/repository"
	"mobile-notification/domain/service"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// DeliveryTrackingService manages notification delivery receipts and read tracking
type DeliveryTrackingService struct {
	notificationRepo    repository.NotificationRepository
	deliveryReceiptRepo repository.DeliveryReceiptRepository
	pushService         service.PushNotificationService
	logger              *logrus.Logger
	config              TrackingConfig
	
	// In-memory tracking for active notifications
	activeDeliveries    map[uuid.UUID]*DeliveryContext
	readConfirmations   map[uuid.UUID]*ReadContext
	mu                  sync.RWMutex
	
	// Background processing
	stopCh              chan struct{}
	wg                  sync.WaitGroup
}

// TrackingConfig represents configuration for delivery tracking
type TrackingConfig struct {
	// Receipt processing settings
	ReceiptProcessingInterval int  `yaml:"receipt_processing_interval"` // 30 seconds
	ReceiptBatchSize          int  `yaml:"receipt_batch_size"`           // 100
	EnableDeliveryTracking    bool `yaml:"enable_delivery_tracking"`     // true
	EnableReadTracking        bool `yaml:"enable_read_tracking"`         // true
	
	// Timeout settings
	DeliveryTimeoutMinutes    int  `yaml:"delivery_timeout_minutes"`     // 60 minutes
	ReadTimeoutHours          int  `yaml:"read_timeout_hours"`           // 24 hours
	
	// Retry settings for failed receipts
	MaxReceiptRetries         int  `yaml:"max_receipt_retries"`          // 3
	ReceiptRetryDelay         int  `yaml:"receipt_retry_delay"`          // 300 seconds (5 minutes)
	
	// Webhook settings for receipt callbacks
	EnableWebhooks            bool `yaml:"enable_webhooks"`              // true
	WebhookURL                string `yaml:"webhook_url"`                // Optional external webhook
	WebhookTimeout            int  `yaml:"webhook_timeout"`              // 10 seconds
	WebhookRetries            int  `yaml:"webhook_retries"`              // 2
	
	// Analytics settings
	EnableAnalytics           bool `yaml:"enable_analytics"`             // true
	AnalyticsRetentionDays    int  `yaml:"analytics_retention_days"`     // 90 days
}

// DeliveryContext tracks the delivery state of a notification
type DeliveryContext struct {
	NotificationID   uuid.UUID                          `json:"notification_id"`
	DeviceToken      string                            `json:"device_token"`
	Platform         entity.Platform                   `json:"platform"`
	SentAt           time.Time                         `json:"sent_at"`
	Status           entity.NotificationStatus         `json:"status"`
	DeliveryAttempts int                               `json:"delivery_attempts"`
	LastAttempt      time.Time                         `json:"last_attempt"`
	ErrorMessage     string                            `json:"error_message,omitempty"`
	Metadata         map[string]string                 `json:"metadata"`
}

// ReadContext tracks read confirmations for notifications
type ReadContext struct {
	NotificationID   uuid.UUID         `json:"notification_id"`
	UserID           uuid.UUID         `json:"user_id"`
	DeviceToken      string            `json:"device_token"`
	ReadAt           *time.Time        `json:"read_at,omitempty"`
	InteractionType  string            `json:"interaction_type"` // "opened", "clicked", "dismissed"
	ActionTaken      string            `json:"action_taken,omitempty"`
	Metadata         map[string]string `json:"metadata"`
}

// DeliveryReceipt represents a delivery receipt from push services
type DeliveryReceipt struct {
	NotificationID   uuid.UUID                 `json:"notification_id"`
	MessageID        string                    `json:"message_id"`
	DeviceToken      string                    `json:"device_token"`
	Platform         entity.Platform           `json:"platform"`
	Status           string                    `json:"status"` // "delivered", "failed", "invalid_token", etc.
	DeliveredAt      *time.Time                `json:"delivered_at,omitempty"`
	ErrorCode        string                    `json:"error_code,omitempty"`
	ErrorMessage     string                    `json:"error_message,omitempty"`
	RetryAfter       *time.Duration            `json:"retry_after,omitempty"`
	Metadata         map[string]string         `json:"metadata"`
}

// NewDeliveryTrackingService creates a new delivery tracking service
func NewDeliveryTrackingService(
	notificationRepo repository.NotificationRepository,
	deliveryReceiptRepo repository.DeliveryReceiptRepository,
	pushService service.PushNotificationService,
	logger *logrus.Logger,
	config TrackingConfig,
) *DeliveryTrackingService {
	// Set defaults
	if config.ReceiptProcessingInterval == 0 {
		config.ReceiptProcessingInterval = 30
	}
	if config.ReceiptBatchSize == 0 {
		config.ReceiptBatchSize = 100
	}
	if config.DeliveryTimeoutMinutes == 0 {
		config.DeliveryTimeoutMinutes = 60
	}
	if config.ReadTimeoutHours == 0 {
		config.ReadTimeoutHours = 24
	}

	return &DeliveryTrackingService{
		notificationRepo:    notificationRepo,
		deliveryReceiptRepo: deliveryReceiptRepo,
		pushService:         pushService,
		logger:              logger,
		config:              config,
		activeDeliveries:    make(map[uuid.UUID]*DeliveryContext),
		readConfirmations:   make(map[uuid.UUID]*ReadContext),
		stopCh:              make(chan struct{}),
	}
}

// Start starts the delivery tracking service
func (s *DeliveryTrackingService) Start(ctx context.Context) {
	if !s.config.EnableDeliveryTracking && !s.config.EnableReadTracking {
		s.logger.Info("Delivery tracking is disabled")
		return
	}

	s.logger.Info("Starting delivery tracking service")
	
	s.wg.Add(1)
	go s.processingLoop(ctx)
}

// Stop stops the delivery tracking service
func (s *DeliveryTrackingService) Stop() {
	s.logger.Info("Stopping delivery tracking service")
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("Delivery tracking service stopped")
}

// TrackNotificationSent tracks when a notification is sent
func (s *DeliveryTrackingService) TrackNotificationSent(ctx context.Context, notification *entity.Notification, result *service.PushResult) error {
	if !s.config.EnableDeliveryTracking {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Create delivery context
	deliveryCtx := &DeliveryContext{
		NotificationID:   notification.ID,
		DeviceToken:      notification.DeviceToken,
		Platform:         notification.Platform,
		SentAt:           time.Now(),
		Status:           entity.StatusSent,
		DeliveryAttempts: 1,
		LastAttempt:      time.Now(),
		Metadata:         make(map[string]string),
	}

	// Add result metadata
	if result != nil {
		deliveryCtx.Metadata["message_id"] = result.MessageID
		deliveryCtx.Metadata["success"] = fmt.Sprintf("%t", result.Success)
		if result.ErrorCode != "" {
			deliveryCtx.ErrorMessage = result.ErrorMessage
			deliveryCtx.Metadata["error_code"] = result.ErrorCode
		}
	}

	// Store in active deliveries for tracking
	s.activeDeliveries[notification.ID] = deliveryCtx

	// Create delivery receipt record
	receipt := &entity.NotificationDeliveryReceipt{
		ID:             uuid.New(),
		NotificationID: notification.ID,
		DeviceToken:    notification.DeviceToken,
		Platform:       notification.Platform,
		Status:         "sent",
		AttemptCount:   1,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if result != nil && !result.Success {
		receipt.Status = "failed"
		receipt.ErrorCode = result.ErrorCode
		receipt.ErrorMessage = result.ErrorMessage
	}

	// Save receipt
	if err := s.deliveryReceiptRepo.Create(ctx, receipt); err != nil {
		s.logger.WithError(err).Error("Failed to create delivery receipt")
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"notification_id": notification.ID,
		"device_token":    notification.DeviceToken,
		"platform":        notification.Platform,
		"status":          receipt.Status,
	}).Debug("Tracked notification sent")

	return nil
}

// ProcessDeliveryReceipt processes a delivery receipt from push services
func (s *DeliveryTrackingService) ProcessDeliveryReceipt(ctx context.Context, receipt *DeliveryReceipt) error {
	if !s.config.EnableDeliveryTracking {
		return nil
	}

	// Update notification status
	var newStatus entity.NotificationStatus
	switch receipt.Status {
	case "delivered":
		newStatus = entity.StatusDelivered
	case "failed":
		newStatus = entity.StatusFailed
	default:
		newStatus = entity.StatusSent
	}

	if err := s.notificationRepo.UpdateStatus(ctx, receipt.NotificationID, newStatus); err != nil {
		s.logger.WithError(err).WithField("notification_id", receipt.NotificationID).Error("Failed to update notification status")
		return err
	}

	// Update delivery context
	s.mu.Lock()
	if deliveryCtx, exists := s.activeDeliveries[receipt.NotificationID]; exists {
		deliveryCtx.Status = newStatus
		if receipt.DeliveredAt != nil {
			deliveryCtx.Metadata["delivered_at"] = receipt.DeliveredAt.Format(time.RFC3339)
		}
		if receipt.ErrorCode != "" {
			deliveryCtx.ErrorMessage = receipt.ErrorMessage
			deliveryCtx.Metadata["error_code"] = receipt.ErrorCode
		}
	}
	s.mu.Unlock()

	// Update delivery receipt record
	receiptEntity := &entity.NotificationDeliveryReceipt{
		NotificationID: receipt.NotificationID,
		DeviceToken:    receipt.DeviceToken,
		Platform:       receipt.Platform,
		Status:         receipt.Status,
		ErrorCode:      receipt.ErrorCode,
		ErrorMessage:   receipt.ErrorMessage,
		UpdatedAt:      time.Now(),
	}

	// Try to find existing receipt to update
	existingReceipts, err := s.deliveryReceiptRepo.GetByNotificationID(ctx, receipt.NotificationID)
	if err == nil && len(existingReceipts) > 0 {
		receiptEntity.ID = existingReceipts[0].ID
		if err := s.deliveryReceiptRepo.Update(ctx, receiptEntity); err != nil {
			s.logger.WithError(err).Error("Failed to update delivery receipt")
			return err
		}
	} else {
		// Create new receipt
		receiptEntity.ID = uuid.New()
		receiptEntity.CreatedAt = time.Now()
		receiptEntity.AttemptCount = 1
		if err := s.deliveryReceiptRepo.Create(ctx, receiptEntity); err != nil {
			s.logger.WithError(err).Error("Failed to create delivery receipt")
			return err
		}
	}

	s.logger.WithFields(logrus.Fields{
		"notification_id": receipt.NotificationID,
		"status":          receipt.Status,
		"platform":        receipt.Platform,
	}).Info("Processed delivery receipt")

	return nil
}

// TrackNotificationRead tracks when a notification is read/opened
func (s *DeliveryTrackingService) TrackNotificationRead(ctx context.Context, notificationID uuid.UUID, userID uuid.UUID, deviceToken string, interactionType string, metadata map[string]string) error {
	if !s.config.EnableReadTracking {
		return nil
	}

	readTime := time.Now()

	// Update notification status to read
	if err := s.notificationRepo.UpdateStatus(ctx, notificationID, entity.StatusRead); err != nil {
		s.logger.WithError(err).WithField("notification_id", notificationID).Error("Failed to update notification read status")
		return err
	}

	// Store read context
	s.mu.Lock()
	readCtx := &ReadContext{
		NotificationID:  notificationID,
		UserID:          userID,
		DeviceToken:     deviceToken,
		ReadAt:          &readTime,
		InteractionType: interactionType,
		Metadata:        metadata,
	}
	s.readConfirmations[notificationID] = readCtx
	s.mu.Unlock()

	s.logger.WithFields(logrus.Fields{
		"notification_id":   notificationID,
		"user_id":          userID,
		"interaction_type": interactionType,
		"read_at":          readTime,
	}).Info("Tracked notification read")

	return nil
}

// GetDeliveryStatus gets the delivery status for a notification
func (s *DeliveryTrackingService) GetDeliveryStatus(ctx context.Context, notificationID uuid.UUID) (*DeliveryStatus, error) {
	// Get notification
	notification, err := s.notificationRepo.GetByID(ctx, notificationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get notification: %w", err)
	}

	// Get delivery receipts
	receipts, err := s.deliveryReceiptRepo.GetByNotificationID(ctx, notificationID)
	if err != nil {
		s.logger.WithError(err).Warn("Failed to get delivery receipts")
		receipts = []*entity.NotificationDeliveryReceipt{}
	}

	// Check active delivery context
	s.mu.RLock()
	deliveryCtx, hasActiveDelivery := s.activeDeliveries[notificationID]
	readCtx, hasReadConfirmation := s.readConfirmations[notificationID]
	s.mu.RUnlock()

	status := &DeliveryStatus{
		NotificationID:    notificationID,
		CurrentStatus:     notification.Status,
		SentAt:            notification.SentAt,
		DeliveredAt:       notification.DeliveredAt,
		ReadAt:            notification.ReadAt,
		DeliveryReceipts:  receipts,
		HasActiveTracking: hasActiveDelivery,
		IsRead:            notification.Status == entity.StatusRead,
	}

	if hasActiveDelivery {
		status.ActiveDelivery = deliveryCtx
	}

	if hasReadConfirmation {
		status.ReadConfirmation = readCtx
	}

	return status, nil
}

// GetDeliveryAnalytics gets delivery analytics for a time period
func (s *DeliveryTrackingService) GetDeliveryAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*DeliveryAnalytics, error) {
	if !s.config.EnableAnalytics {
		return nil, fmt.Errorf("analytics are disabled")
	}

	// Get notification analytics from repository
	analyticsData, err := s.notificationRepo.GetAnalytics(ctx, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to get analytics data: %w", err)
	}

	analytics := &DeliveryAnalytics{
		TenantID:       tenantID,
		FromDate:       from,
		ToDate:         to,
		TotalSent:      analyticsData.TotalSent,
		TotalDelivered: analyticsData.TotalDelivered,
		TotalRead:      analyticsData.TotalRead,
		TotalFailed:    analyticsData.TotalFailed,
		ByPlatform:     analyticsData.ByPlatform,
		ByPriority:     analyticsData.ByPriority,
		ByStatus:       analyticsData.ByStatus,
	}

	// Calculate rates
	if analytics.TotalSent > 0 {
		analytics.DeliveryRate = float64(analytics.TotalDelivered) / float64(analytics.TotalSent) * 100
		analytics.FailureRate = float64(analytics.TotalFailed) / float64(analytics.TotalSent) * 100
	}

	if analytics.TotalDelivered > 0 {
		analytics.ReadRate = float64(analytics.TotalRead) / float64(analytics.TotalDelivered) * 100
	}

	// Calculate average delivery time (simplified - would need more detailed tracking)
	analytics.AverageDeliveryTime = 30 // seconds - placeholder

	return analytics, nil
}

// processingLoop handles background processing of delivery tracking
func (s *DeliveryTrackingService) processingLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(time.Duration(s.config.ReceiptProcessingInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.processTimeouts(ctx)
			s.cleanupExpiredTracking()
		}
	}
}

// processTimeouts handles delivery and read timeouts
func (s *DeliveryTrackingService) processTimeouts(ctx context.Context) {
	now := time.Now()
	deliveryTimeout := time.Duration(s.config.DeliveryTimeoutMinutes) * time.Minute
	readTimeout := time.Duration(s.config.ReadTimeoutHours) * time.Hour

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check delivery timeouts
	for notificationID, deliveryCtx := range s.activeDeliveries {
		if deliveryCtx.Status == entity.StatusSent && now.Sub(deliveryCtx.SentAt) > deliveryTimeout {
			// Mark as failed due to timeout
			if err := s.notificationRepo.UpdateStatus(ctx, notificationID, entity.StatusFailed); err != nil {
				s.logger.WithError(err).WithField("notification_id", notificationID).Error("Failed to update timed-out notification")
				continue
			}

			deliveryCtx.Status = entity.StatusFailed
			deliveryCtx.ErrorMessage = "Delivery timeout"

			s.logger.WithFields(logrus.Fields{
				"notification_id": notificationID,
				"timeout_minutes": s.config.DeliveryTimeoutMinutes,
			}).Warn("Notification delivery timed out")
		}
	}

	// Check read timeouts
	for notificationID, readCtx := range s.readConfirmations {
		if readCtx.ReadAt == nil && now.Sub(time.Time{}) > readTimeout {
			// This is a placeholder - in a real implementation you'd track when the notification was delivered
			s.logger.WithField("notification_id", notificationID).Debug("Notification read timeout (placeholder)")
		}
	}
}

// cleanupExpiredTracking removes expired tracking contexts
func (s *DeliveryTrackingService) cleanupExpiredTracking() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expiredDeliveries := make([]uuid.UUID, 0)
	expiredReads := make([]uuid.UUID, 0)

	// Clean up delivery contexts older than 24 hours
	cutoff := now.Add(-24 * time.Hour)
	for notificationID, deliveryCtx := range s.activeDeliveries {
		if deliveryCtx.SentAt.Before(cutoff) {
			expiredDeliveries = append(expiredDeliveries, notificationID)
		}
	}

	for _, notificationID := range expiredDeliveries {
		delete(s.activeDeliveries, notificationID)
	}

	// Clean up read contexts older than 7 days
	readCutoff := now.Add(-7 * 24 * time.Hour)
	for notificationID, readCtx := range s.readConfirmations {
		if readCtx.ReadAt != nil && readCtx.ReadAt.Before(readCutoff) {
			expiredReads = append(expiredReads, notificationID)
		}
	}

	for _, notificationID := range expiredReads {
		delete(s.readConfirmations, notificationID)
	}

	if len(expiredDeliveries) > 0 || len(expiredReads) > 0 {
		s.logger.WithFields(logrus.Fields{
			"expired_deliveries": len(expiredDeliveries),
			"expired_reads":      len(expiredReads),
		}).Debug("Cleaned up expired tracking contexts")
	}
}

// DeliveryStatus represents the delivery status of a notification
type DeliveryStatus struct {
	NotificationID     uuid.UUID                                `json:"notification_id"`
	CurrentStatus      entity.NotificationStatus                `json:"current_status"`
	SentAt             *time.Time                               `json:"sent_at"`
	DeliveredAt        *time.Time                               `json:"delivered_at"`
	ReadAt             *time.Time                               `json:"read_at"`
	DeliveryReceipts   []*entity.NotificationDeliveryReceipt   `json:"delivery_receipts"`
	ActiveDelivery     *DeliveryContext                         `json:"active_delivery,omitempty"`
	ReadConfirmation   *ReadContext                             `json:"read_confirmation,omitempty"`
	HasActiveTracking  bool                                     `json:"has_active_tracking"`
	IsRead             bool                                     `json:"is_read"`
}

// DeliveryAnalytics represents delivery analytics data
type DeliveryAnalytics struct {
	TenantID              uuid.UUID                                  `json:"tenant_id"`
	FromDate              time.Time                                  `json:"from_date"`
	ToDate                time.Time                                  `json:"to_date"`
	TotalSent             int64                                      `json:"total_sent"`
	TotalDelivered        int64                                      `json:"total_delivered"`
	TotalRead             int64                                      `json:"total_read"`
	TotalFailed           int64                                      `json:"total_failed"`
	DeliveryRate          float64                                    `json:"delivery_rate"`
	ReadRate              float64                                    `json:"read_rate"`
	FailureRate           float64                                    `json:"failure_rate"`
	AverageDeliveryTime   float64                                    `json:"average_delivery_time"` // seconds
	ByPlatform            map[entity.Platform]int64                  `json:"by_platform"`
	ByPriority            map[entity.NotificationPriority]int64      `json:"by_priority"`
	ByStatus              map[entity.NotificationStatus]int64        `json:"by_status"`
}