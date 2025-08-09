package push

import (
	"context"
	"encoding/json"
	"fmt"
	"mobile-notification/domain/entity"
	"mobile-notification/domain/service"
	"strconv"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

// FCMService implements Firebase Cloud Messaging push notifications
type FCMService struct {
	client *messaging.Client
	logger *logrus.Logger
	config FCMConfig
}

// FCMConfig represents Firebase Cloud Messaging configuration
type FCMConfig struct {
	ProjectID           string `yaml:"project_id"`
	CredentialsFile     string `yaml:"credentials_file"`
	CredentialsJSON     string `yaml:"credentials_json"`
	DefaultTTL          int    `yaml:"default_ttl"`
	MaxRetries          int    `yaml:"max_retries"`
	RetryDelay          int    `yaml:"retry_delay"`
	BatchSize           int    `yaml:"batch_size"`
	EnableDeliveryReceipts bool `yaml:"enable_delivery_receipts"`
}

// NewFCMService creates a new FCM service instance
func NewFCMService(config FCMConfig, logger *logrus.Logger) (*FCMService, error) {
	var opt option.ClientOption
	
	if config.CredentialsFile != "" {
		opt = option.WithCredentialsFile(config.CredentialsFile)
	} else if config.CredentialsJSON != "" {
		opt = option.WithCredentialsJSON([]byte(config.CredentialsJSON))
	} else {
		return nil, fmt.Errorf("either credentials_file or credentials_json must be provided")
	}

	firebaseConfig := &firebase.Config{
		ProjectID: config.ProjectID,
	}

	app, err := firebase.NewApp(context.Background(), firebaseConfig, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase app: %w", err)
	}

	client, err := app.Messaging(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Firebase messaging client: %w", err)
	}

	// Set default values
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 3600 // 1 hour
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5
	}
	if config.BatchSize == 0 {
		config.BatchSize = 500
	}

	return &FCMService{
		client: client,
		logger: logger,
		config: config,
	}, nil
}

// SendFCM sends a notification via Firebase Cloud Messaging
func (s *FCMService) SendFCM(ctx context.Context, notification *entity.Notification) (*service.PushResult, error) {
	message, err := s.buildMessage(notification)
	if err != nil {
		s.logger.WithError(err).Error("Failed to build FCM message")
		return &service.PushResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to build message: %v", err),
			TokenValid:   true, // Assume token is valid unless proven otherwise
		}, nil
	}

	// Send the message with retry logic
	return s.sendWithRetry(ctx, message, notification)
}

// SendBatch sends multiple notifications in a batch
func (s *FCMService) SendBatch(ctx context.Context, notifications []*entity.Notification) ([]*service.PushResult, error) {
	if len(notifications) == 0 {
		return []*service.PushResult{}, nil
	}

	results := make([]*service.PushResult, len(notifications))
	
	// Process notifications in batches
	for i := 0; i < len(notifications); i += s.config.BatchSize {
		end := i + s.config.BatchSize
		if end > len(notifications) {
			end = len(notifications)
		}
		
		batch := notifications[i:end]
		batchResults, err := s.processBatch(ctx, batch)
		if err != nil {
			s.logger.WithError(err).Error("Failed to process FCM batch")
			// Fill results with errors
			for j := i; j < end; j++ {
				results[j] = &service.PushResult{
					Success:      false,
					ErrorMessage: fmt.Sprintf("Batch processing failed: %v", err),
					TokenValid:   true,
				}
			}
			continue
		}
		
		// Copy batch results to main results slice
		copy(results[i:end], batchResults)
	}

	return results, nil
}

// ValidateToken validates an FCM device token
func (s *FCMService) ValidateToken(ctx context.Context, token string, platform entity.Platform) error {
	if platform != entity.PlatformFCM {
		return fmt.Errorf("invalid platform for FCM service: %s", platform)
	}

	// Create a test message to validate the token
	message := &messaging.Message{
		Token: token,
		Data: map[string]string{
			"validation": "true",
		},
		Android: &messaging.AndroidConfig{
			Priority: "normal",
			Data: map[string]string{
				"validation": "true",
			},
		},
	}

	// Use dry run to validate without actually sending
	_, err := s.client.SendDryRun(ctx, message)
	if err != nil {
		s.logger.WithError(err).WithField("token", token).Error("FCM token validation failed")
		return fmt.Errorf("invalid FCM token: %w", err)
	}

	return nil
}

// buildMessage constructs an FCM message from a notification entity
func (s *FCMService) buildMessage(notification *entity.Notification) (*messaging.Message, error) {
	if notification.DeviceToken == "" {
		return nil, fmt.Errorf("device token is required")
	}

	message := &messaging.Message{
		Token: notification.DeviceToken,
		Data:  notification.Data,
	}

	// Set notification payload
	if notification.Title != "" || notification.Body != "" {
		message.Notification = &messaging.Notification{
			Title:    notification.Title,
			Body:     notification.Body,
			ImageURL: notification.ImageURL,
		}
	}

	// Configure Android-specific settings
	message.Android = s.buildAndroidConfig(notification)
	
	// Configure WebPush settings (for web platform)
	if notification.Platform == entity.PlatformWeb {
		message.Webpush = s.buildWebpushConfig(notification)
	}

	return message, nil
}

// buildAndroidConfig creates Android-specific configuration
func (s *FCMService) buildAndroidConfig(notification *entity.Notification) *messaging.AndroidConfig {
	config := &messaging.AndroidConfig{
		Data: notification.Data,
	}

	// Set priority based on notification priority
	switch notification.Priority {
	case entity.PriorityCritical:
		config.Priority = "high"
	case entity.PriorityWarning:
		config.Priority = "high"
	case entity.PriorityInformational:
		config.Priority = "normal"
	default:
		config.Priority = "normal"
	}

	// Set TTL
	ttl := notification.TTL
	if ttl == 0 {
		ttl = s.config.DefaultTTL
	}
	config.TTL = &[]time.Duration{time.Duration(ttl) * time.Second}[0]

	// Configure notification settings
	if notification.Title != "" || notification.Body != "" {
		config.Notification = &messaging.AndroidNotification{
			Title:       notification.Title,
			Body:        notification.Body,
			ChannelID:   s.getChannelID(notification.Priority),
			Priority:    s.getAndroidNotificationPriority(notification.Priority),
			Visibility:  "private",
			Image:       notification.ImageURL,
		}

		// Add action button if action URL is provided
		if notification.ActionURL != "" {
			config.Notification.ClickAction = notification.ActionURL
		}
	}

	return config
}

// buildWebpushConfig creates WebPush-specific configuration
func (s *FCMService) buildWebpushConfig(notification *entity.Notification) *messaging.WebpushConfig {
	config := &messaging.WebpushConfig{
		Data: notification.Data,
	}

	// Set headers
	headers := make(map[string]string)
	headers["TTL"] = strconv.Itoa(notification.TTL)
	
	switch notification.Priority {
	case entity.PriorityCritical:
		headers["Urgency"] = "high"
	case entity.PriorityWarning:
		headers["Urgency"] = "normal"
	case entity.PriorityInformational:
		headers["Urgency"] = "low"
	default:
		headers["Urgency"] = "normal"
	}
	
	config.Headers = headers

	// Configure web notification
	if notification.Title != "" || notification.Body != "" {
		webNotification := map[string]interface{}{
			"title": notification.Title,
			"body":  notification.Body,
			"requireInteraction": notification.Priority == entity.PriorityCritical,
		}

		if notification.ImageURL != "" {
			webNotification["image"] = notification.ImageURL
		}

		if notification.ActionURL != "" {
			webNotification["data"] = map[string]string{
				"url": notification.ActionURL,
			}
		}

		notificationJSON, _ := json.Marshal(webNotification)
		config.Notification = (*messaging.WebpushNotification)(&notificationJSON)
	}

	return config
}

// sendWithRetry sends a message with retry logic
func (s *FCMService) sendWithRetry(ctx context.Context, message *messaging.Message, notification *entity.Notification) (*service.PushResult, error) {
	var lastErr error
	
	for attempt := 0; attempt <= s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			time.Sleep(time.Duration(s.config.RetryDelay*(attempt)) * time.Second)
		}

		response, err := s.client.Send(ctx, message)
		if err == nil {
			// Success
			s.logger.WithFields(logrus.Fields{
				"notification_id": notification.ID,
				"message_id":      response,
				"attempt":         attempt + 1,
			}).Info("FCM message sent successfully")

			return &service.PushResult{
				Success:    true,
				MessageID:  response,
				TokenValid: true,
				Metadata: map[string]string{
					"attempt": strconv.Itoa(attempt + 1),
					"platform": string(entity.PlatformFCM),
				},
			}, nil
		}

		lastErr = err
		
		// Check if error is retryable
		if !s.isRetryableError(err) {
			break
		}

		s.logger.WithFields(logrus.Fields{
			"notification_id": notification.ID,
			"attempt":         attempt + 1,
			"error":           err.Error(),
		}).Warn("FCM send failed, will retry")
	}

	// All retries failed
	result := &service.PushResult{
		Success:      false,
		ErrorMessage: lastErr.Error(),
		TokenValid:   !s.isTokenError(lastErr),
		Retry:        s.isRetryableError(lastErr),
	}

	// Extract error code from FCM error
	if fcmErr, ok := lastErr.(*messaging.MessagingError); ok {
		result.ErrorCode = fcmErr.ErrorCode()
	}

	s.logger.WithFields(logrus.Fields{
		"notification_id": notification.ID,
		"error":           lastErr.Error(),
		"token_valid":     result.TokenValid,
	}).Error("FCM message send failed after all retries")

	return result, nil
}

// processBatch processes a batch of notifications
func (s *FCMService) processBatch(ctx context.Context, notifications []*entity.Notification) ([]*service.PushResult, error) {
	messages := make([]*messaging.Message, len(notifications))
	
	for i, notification := range notifications {
		message, err := s.buildMessage(notification)
		if err != nil {
			return nil, fmt.Errorf("failed to build message for notification %s: %w", notification.ID, err)
		}
		messages[i] = message
	}

	batchResponse, err := s.client.SendAll(ctx, messages)
	if err != nil {
		return nil, fmt.Errorf("failed to send FCM batch: %w", err)
	}

	results := make([]*service.PushResult, len(notifications))
	for i, response := range batchResponse.Responses {
		if response.Success {
			results[i] = &service.PushResult{
				Success:   true,
				MessageID: response.MessageID,
				TokenValid: true,
				Metadata: map[string]string{
					"platform": string(entity.PlatformFCM),
				},
			}
		} else {
			results[i] = &service.PushResult{
				Success:      false,
				ErrorMessage: response.Error.Error(),
				TokenValid:   !s.isTokenError(response.Error),
				Retry:        s.isRetryableError(response.Error),
			}
			
			if fcmErr, ok := response.Error.(*messaging.MessagingError); ok {
				results[i].ErrorCode = fcmErr.ErrorCode()
			}
		}
	}

	return results, nil
}

// isRetryableError checks if an error is retryable
func (s *FCMService) isRetryableError(err error) bool {
	if fcmErr, ok := err.(*messaging.MessagingError); ok {
		switch fcmErr.ErrorCode() {
		case "internal-error", "unavailable", "deadline-exceeded":
			return true
		default:
			return false
		}
	}
	return false
}

// isTokenError checks if an error is related to invalid token
func (s *FCMService) isTokenError(err error) bool {
	if fcmErr, ok := err.(*messaging.MessagingError); ok {
		switch fcmErr.ErrorCode() {
		case "invalid-registration-token", "registration-token-not-registered", "unregistered":
			return true
		default:
			return false
		}
	}
	return false
}

// getChannelID returns the appropriate Android notification channel ID
func (s *FCMService) getChannelID(priority entity.NotificationPriority) string {
	switch priority {
	case entity.PriorityCritical:
		return "critical_notifications"
	case entity.PriorityWarning:
		return "warning_notifications"
	case entity.PriorityInformational:
		return "info_notifications"
	default:
		return "default_notifications"
	}
}

// getAndroidNotificationPriority returns the appropriate Android notification priority
func (s *FCMService) getAndroidNotificationPriority(priority entity.NotificationPriority) string {
	switch priority {
	case entity.PriorityCritical:
		return "max"
	case entity.PriorityWarning:
		return "high"
	case entity.PriorityInformational:
		return "default"
	default:
		return "default"
	}
}