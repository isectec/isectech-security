package batching

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

// BatchingService implements notification batching logic
type BatchingService struct {
	notificationRepo repository.NotificationRepository
	batchRepo        repository.NotificationBatchRepository
	preferencesRepo  repository.NotificationPreferencesRepository
	logger           *logrus.Logger
	config           BatchingConfig
	mu               sync.RWMutex
	activeBatches    map[uuid.UUID]*BatchContext
	stopCh           chan struct{}
	wg               sync.WaitGroup
}

// BatchingConfig represents the configuration for batching service
type BatchingConfig struct {
	// Batching intervals by priority (in seconds)
	CriticalBatchInterval      int `yaml:"critical_batch_interval"`      // 0 = immediate
	WarningBatchInterval       int `yaml:"warning_batch_interval"`       // 300 = 5 minutes
	InformationalBatchInterval int `yaml:"informational_batch_interval"` // 3600 = 1 hour

	// Maximum batch sizes
	MaxBatchSize         int `yaml:"max_batch_size"`          // 100 notifications per batch
	MaxCriticalBatchSize int `yaml:"max_critical_batch_size"` // 50 for critical (smaller for faster delivery)

	// Quiet hours batching
	QuietHoursBatchInterval int  `yaml:"quiet_hours_batch_interval"` // 21600 = 6 hours
	RespectQuietHours       bool `yaml:"respect_quiet_hours"`        // true

	// Anti-fatigue settings
	MaxNotificationsPerUser int `yaml:"max_notifications_per_user"` // 20 per day
	FatigueWindowHours      int `yaml:"fatigue_window_hours"`       // 24 hours

	// Processing settings
	ProcessingInterval int  `yaml:"processing_interval"` // 60 seconds
	EnableBatching     bool `yaml:"enable_batching"`     // true
}

// BatchContext represents the context for an active batch
type BatchContext struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	UserID            uuid.UUID
	Priority          entity.NotificationPriority
	Platform          entity.Platform
	Notifications     []*entity.Notification
	CreatedAt         time.Time
	ScheduledFor      time.Time
	MaxSize           int
	IntervalSeconds   int
	InQuietHours      bool
}

// NewBatchingService creates a new batching service
func NewBatchingService(
	notificationRepo repository.NotificationRepository,
	batchRepo repository.NotificationBatchRepository,
	preferencesRepo repository.NotificationPreferencesRepository,
	logger *logrus.Logger,
	config BatchingConfig,
) *BatchingService {
	// Set default values
	if config.CriticalBatchInterval == 0 && config.EnableBatching {
		config.CriticalBatchInterval = 0 // Immediate for critical
	}
	if config.WarningBatchInterval == 0 {
		config.WarningBatchInterval = 300 // 5 minutes
	}
	if config.InformationalBatchInterval == 0 {
		config.InformationalBatchInterval = 3600 // 1 hour
	}
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = 100
	}
	if config.MaxCriticalBatchSize == 0 {
		config.MaxCriticalBatchSize = 50
	}
	if config.ProcessingInterval == 0 {
		config.ProcessingInterval = 60
	}

	return &BatchingService{
		notificationRepo: notificationRepo,
		batchRepo:        batchRepo,
		preferencesRepo:  preferencesRepo,
		logger:           logger,
		config:           config,
		activeBatches:    make(map[uuid.UUID]*BatchContext),
		stopCh:           make(chan struct{}),
	}
}

// Start starts the batching service background processing
func (s *BatchingService) Start(ctx context.Context) {
	if !s.config.EnableBatching {
		s.logger.Info("Notification batching is disabled")
		return
	}

	s.logger.Info("Starting notification batching service")
	
	s.wg.Add(1)
	go s.processingLoop(ctx)
}

// Stop stops the batching service
func (s *BatchingService) Stop() {
	s.logger.Info("Stopping notification batching service")
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("Notification batching service stopped")
}

// CreateBatch creates a new notification batch
func (s *BatchingService) CreateBatch(ctx context.Context, batch *entity.NotificationBatch) error {
	if batch.ID == uuid.Nil {
		batch.ID = uuid.New()
	}
	batch.CreatedAt = time.Now()
	batch.UpdatedAt = batch.CreatedAt

	if err := s.batchRepo.Create(ctx, batch); err != nil {
		return fmt.Errorf("failed to create batch: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"batch_id":  batch.ID,
		"tenant_id": batch.TenantID,
		"user_id":   batch.UserID,
		"count":     batch.Count,
	}).Info("Created notification batch")

	return nil
}

// AddToBatch adds notifications to an existing batch
func (s *BatchingService) AddToBatch(ctx context.Context, batchID uuid.UUID, notifications []*entity.Notification) error {
	if len(notifications) == 0 {
		return nil
	}

	batch, err := s.batchRepo.GetByID(ctx, batchID)
	if err != nil {
		return fmt.Errorf("failed to get batch: %w", err)
	}

	// Update notifications with batch ID
	for _, notification := range notifications {
		notification.BatchID = &batchID
		if err := s.notificationRepo.Update(ctx, notification); err != nil {
			return fmt.Errorf("failed to update notification with batch ID: %w", err)
		}
	}

	// Update batch count
	batch.Count += len(notifications)
	batch.UpdatedAt = time.Now()

	if err := s.batchRepo.Update(ctx, batch); err != nil {
		return fmt.Errorf("failed to update batch: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"batch_id":         batchID,
		"added_count":      len(notifications),
		"total_batch_count": batch.Count,
	}).Info("Added notifications to batch")

	return nil
}

// ProcessBatches processes pending notification batches
func (s *BatchingService) ProcessBatches(ctx context.Context) error {
	batches, err := s.batchRepo.GetPendingBatches(ctx)
	if err != nil {
		return fmt.Errorf("failed to get pending batches: %w", err)
	}

	if len(batches) == 0 {
		return nil
	}

	s.logger.WithField("batch_count", len(batches)).Info("Processing notification batches")

	processed := 0
	for _, batch := range batches {
		// Check if batch is ready to be sent
		if batch.ScheduledFor.After(time.Now()) {
			continue
		}

		if err := s.processBatch(ctx, batch); err != nil {
			s.logger.WithError(err).WithField("batch_id", batch.ID).Error("Failed to process batch")
			continue
		}
		processed++
	}

	s.logger.WithField("processed_count", processed).Info("Completed batch processing")
	return nil
}

// GetBatchStatus gets the status of a notification batch
func (s *BatchingService) GetBatchStatus(ctx context.Context, batchID uuid.UUID) (*entity.NotificationBatch, error) {
	return s.batchRepo.GetByID(ctx, batchID)
}

// ShouldBatch determines if a notification should be batched
func (s *BatchingService) ShouldBatch(ctx context.Context, notification *entity.Notification) (bool, *BatchingDecision, error) {
	decision := &BatchingDecision{
		ShouldBatch:     false,
		Reason:          "Batching disabled",
		BatchInterval:   0,
		MaxBatchSize:    0,
		InQuietHours:    false,
		FatigueDetected: false,
	}

	if !s.config.EnableBatching {
		return false, decision, nil
	}

	// Critical notifications are never batched (unless in quiet hours)
	if notification.Priority == entity.PriorityCritical {
		inQuietHours, err := s.isInQuietHours(ctx, notification.UserID)
		if err != nil {
			s.logger.WithError(err).Warn("Failed to check quiet hours")
		}
		
		if !inQuietHours || !s.config.RespectQuietHours {
			decision.Reason = "Critical priority - immediate delivery"
			return false, decision, nil
		}
		
		decision.InQuietHours = true
		decision.Reason = "Critical priority but in quiet hours"
	}

	// Check for notification fatigue
	fatigueDetected, err := s.checkNotificationFatigue(ctx, notification.UserID)
	if err != nil {
		s.logger.WithError(err).Warn("Failed to check notification fatigue")
	}
	
	decision.FatigueDetected = fatigueDetected
	if fatigueDetected {
		decision.ShouldBatch = true
		decision.Reason = "User notification fatigue detected"
		decision.BatchInterval = s.config.InformationalBatchInterval * 2 // Double interval for fatigue
		decision.MaxBatchSize = s.config.MaxBatchSize / 2                // Half batch size
		return true, decision, nil
	}

	// Check quiet hours
	inQuietHours, err := s.isInQuietHours(ctx, notification.UserID)
	if err != nil {
		s.logger.WithError(err).Warn("Failed to check quiet hours")
	}
	
	decision.InQuietHours = inQuietHours

	// Determine batching based on priority and quiet hours
	switch notification.Priority {
	case entity.PriorityCritical:
		if inQuietHours && s.config.RespectQuietHours {
			decision.ShouldBatch = true
			decision.BatchInterval = s.config.QuietHoursBatchInterval
			decision.MaxBatchSize = s.config.MaxCriticalBatchSize
			decision.Reason = "Critical priority in quiet hours"
		}
	case entity.PriorityWarning:
		decision.ShouldBatch = true
		if inQuietHours && s.config.RespectQuietHours {
			decision.BatchInterval = s.config.QuietHoursBatchInterval
			decision.Reason = "Warning priority in quiet hours"
		} else {
			decision.BatchInterval = s.config.WarningBatchInterval
			decision.Reason = "Warning priority - standard batching"
		}
		decision.MaxBatchSize = s.config.MaxBatchSize
	case entity.PriorityInformational:
		decision.ShouldBatch = true
		if inQuietHours && s.config.RespectQuietHours {
			decision.BatchInterval = s.config.QuietHoursBatchInterval
			decision.Reason = "Informational priority in quiet hours"
		} else {
			decision.BatchInterval = s.config.InformationalBatchInterval
			decision.Reason = "Informational priority - standard batching"
		}
		decision.MaxBatchSize = s.config.MaxBatchSize
	}

	return decision.ShouldBatch, decision, nil
}

// processingLoop runs the main processing loop
func (s *BatchingService) processingLoop(ctx context.Context) {
	defer s.wg.Done()
	
	ticker := time.NewTicker(time.Duration(s.config.ProcessingInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if err := s.ProcessBatches(ctx); err != nil {
				s.logger.WithError(err).Error("Failed to process batches")
			}
			s.cleanupExpiredBatches(ctx)
		}
	}
}

// processBatch processes a single batch
func (s *BatchingService) processBatch(ctx context.Context, batch *entity.NotificationBatch) error {
	// Get notifications for this batch
	notifications, err := s.getNotificationsForBatch(ctx, batch.ID)
	if err != nil {
		return fmt.Errorf("failed to get notifications for batch: %w", err)
	}

	if len(notifications) == 0 {
		s.logger.WithField("batch_id", batch.ID).Warn("No notifications found for batch")
		return s.batchRepo.UpdateStatus(ctx, batch.ID, entity.StatusSent)
	}

	// Create a summary notification for the batch
	summaryNotification := s.createBatchSummary(batch, notifications)

	// Mark all individual notifications as batched/sent
	for _, notification := range notifications {
		if err := s.notificationRepo.UpdateStatus(ctx, notification.ID, entity.StatusSent); err != nil {
			s.logger.WithError(err).WithField("notification_id", notification.ID).Error("Failed to update notification status")
		}
	}

	// Update batch status
	batch.SentAt = &[]time.Time{time.Now()}[0]
	if err := s.batchRepo.UpdateStatus(ctx, batch.ID, entity.StatusSent); err != nil {
		return fmt.Errorf("failed to update batch status: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"batch_id":           batch.ID,
		"notification_count": len(notifications),
		"summary_title":      summaryNotification.Title,
	}).Info("Processed notification batch")

	return nil
}

// getNotificationsForBatch gets all notifications for a specific batch
func (s *BatchingService) getNotificationsForBatch(ctx context.Context, batchID uuid.UUID) ([]*entity.Notification, error) {
	// This would need to be implemented in the repository
	// For now, we'll use a placeholder implementation
	return []*entity.Notification{}, nil
}

// createBatchSummary creates a summary notification for a batch
func (s *BatchingService) createBatchSummary(batch *entity.NotificationBatch, notifications []*entity.Notification) *entity.Notification {
	count := len(notifications)
	
	var title string
	var body string
	
	if count == 1 {
		// Single notification - use original content
		title = notifications[0].Title
		body = notifications[0].Body
	} else {
		// Multiple notifications - create summary
		title = fmt.Sprintf("%d Security Notifications", count)
		body = fmt.Sprintf("You have %d new security notifications. Tap to view details.", count)
		
		// Categorize notifications
		critical := 0
		warning := 0
		info := 0
		
		for _, n := range notifications {
			switch n.Priority {
			case entity.PriorityCritical:
				critical++
			case entity.PriorityWarning:
				warning++
			case entity.PriorityInformational:
				info++
			}
		}
		
		if critical > 0 {
			title = fmt.Sprintf("%d Critical Security Alerts", critical)
			if warning > 0 || info > 0 {
				title += fmt.Sprintf(" (+%d others)", count-critical)
			}
		}
	}

	return &entity.Notification{
		ID:         uuid.New(),
		TenantID:   batch.TenantID,
		UserID:     batch.UserID,
		Title:      title,
		Body:       body,
		Priority:   s.determineBatchPriority(notifications),
		Status:     entity.StatusPending,
		Platform:   batch.Platform,
		BatchID:    &batch.ID,
		Data: map[string]string{
			"batch_id":         batch.ID.String(),
			"notification_count": fmt.Sprintf("%d", count),
			"type":            "batch_summary",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// determineBatchPriority determines the priority for a batch summary
func (s *BatchingService) determineBatchPriority(notifications []*entity.Notification) entity.NotificationPriority {
	hasCritical := false
	hasWarning := false
	
	for _, notification := range notifications {
		switch notification.Priority {
		case entity.PriorityCritical:
			hasCritical = true
		case entity.PriorityWarning:
			hasWarning = true
		}
	}
	
	if hasCritical {
		return entity.PriorityCritical
	}
	if hasWarning {
		return entity.PriorityWarning
	}
	return entity.PriorityInformational
}

// isInQuietHours checks if the user is currently in quiet hours
func (s *BatchingService) isInQuietHours(ctx context.Context, userID uuid.UUID) (bool, error) {
	preferences, err := s.preferencesRepo.GetByUserID(ctx, userID)
	if err != nil {
		return false, err
	}

	if preferences == nil || preferences.QuietHours == nil || !preferences.QuietHours.Enabled {
		return false, nil
	}

	return s.isCurrentTimeInQuietHours(preferences.QuietHours), nil
}

// isCurrentTimeInQuietHours checks if current time is within quiet hours
func (s *BatchingService) isCurrentTimeInQuietHours(quietHours *entity.QuietHours) bool {
	if quietHours == nil || !quietHours.Enabled {
		return false
	}

	// Parse timezone
	loc, err := time.LoadLocation(quietHours.Timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)
	currentTime := now.Format("15:04")

	// Handle cases where quiet hours span midnight
	if quietHours.StartTime <= quietHours.EndTime {
		return currentTime >= quietHours.StartTime && currentTime <= quietHours.EndTime
	} else {
		return currentTime >= quietHours.StartTime || currentTime <= quietHours.EndTime
	}
}

// checkNotificationFatigue checks if user has notification fatigue
func (s *BatchingService) checkNotificationFatigue(ctx context.Context, userID uuid.UUID) (bool, error) {
	if s.config.MaxNotificationsPerUser == 0 {
		return false, nil
	}

	// Get notification count for the user in the last N hours
	windowStart := time.Now().Add(-time.Duration(s.config.FatigueWindowHours) * time.Hour)
	
	notifications, err := s.notificationRepo.GetByUserID(ctx, userID, s.config.MaxNotificationsPerUser+1, 0)
	if err != nil {
		return false, err
	}

	// Count notifications within the fatigue window
	count := 0
	for _, notification := range notifications {
		if notification.CreatedAt.After(windowStart) {
			count++
		}
	}

	return count >= s.config.MaxNotificationsPerUser, nil
}

// cleanupExpiredBatches removes expired batch contexts
func (s *BatchingService) cleanupExpiredBatches(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiredBatches := make([]uuid.UUID, 0)
	cutoff := time.Now().Add(-24 * time.Hour)

	for batchID, batchCtx := range s.activeBatches {
		if batchCtx.CreatedAt.Before(cutoff) {
			expiredBatches = append(expiredBatches, batchID)
		}
	}

	for _, batchID := range expiredBatches {
		delete(s.activeBatches, batchID)
	}

	if len(expiredBatches) > 0 {
		s.logger.WithField("expired_count", len(expiredBatches)).Debug("Cleaned up expired batch contexts")
	}
}

// BatchingDecision represents the result of batching decision logic
type BatchingDecision struct {
	ShouldBatch     bool                         `json:"should_batch"`
	Reason          string                       `json:"reason"`
	BatchInterval   int                          `json:"batch_interval"`
	MaxBatchSize    int                          `json:"max_batch_size"`
	InQuietHours    bool                         `json:"in_quiet_hours"`
	FatigueDetected bool                         `json:"fatigue_detected"`
	Priority        entity.NotificationPriority `json:"priority"`
}