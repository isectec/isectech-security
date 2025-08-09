package push

import (
	"context"
	"fmt"
	"mobile-notification/domain/entity"
	"mobile-notification/domain/service"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// PushService implements the unified push notification service
type PushService struct {
	fcmService  *FCMService
	apnsService *APNSService
	logger      *logrus.Logger
	config      PushConfig
}

// PushConfig represents the configuration for the push service
type PushConfig struct {
	FCM  FCMConfig  `yaml:"fcm"`
	APNS APNSConfig `yaml:"apns"`
}

// NewPushService creates a new unified push service
func NewPushService(config PushConfig, logger *logrus.Logger) (*PushService, error) {
	var fcmService *FCMService
	var apnsService *APNSService
	var err error

	// Initialize FCM service if configured
	if config.FCM.ProjectID != "" {
		fcmService, err = NewFCMService(config.FCM, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize FCM service: %w", err)
		}
		logger.Info("FCM service initialized successfully")
	} else {
		logger.Warn("FCM service not configured - FCM notifications will not be available")
	}

	// Initialize APNS service if configured
	if config.APNS.Topic != "" {
		apnsService, err = NewAPNSService(config.APNS, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize APNS service: %w", err)
		}
		logger.Info("APNS service initialized successfully")
	} else {
		logger.Warn("APNS service not configured - APNS notifications will not be available")
	}

	if fcmService == nil && apnsService == nil {
		return nil, fmt.Errorf("at least one push service (FCM or APNS) must be configured")
	}

	return &PushService{
		fcmService:  fcmService,
		apnsService: apnsService,
		logger:      logger,
		config:      config,
	}, nil
}

// SendFCM sends notification via Firebase Cloud Messaging
func (s *PushService) SendFCM(ctx context.Context, notification *entity.Notification) (*service.PushResult, error) {
	if s.fcmService == nil {
		return nil, fmt.Errorf("FCM service not configured")
	}
	
	if notification.Platform != entity.PlatformFCM && notification.Platform != entity.PlatformWeb {
		return nil, fmt.Errorf("invalid platform for FCM: %s", notification.Platform)
	}

	return s.fcmService.SendFCM(ctx, notification)
}

// SendAPNS sends notification via Apple Push Notification Service
func (s *PushService) SendAPNS(ctx context.Context, notification *entity.Notification) (*service.PushResult, error) {
	if s.apnsService == nil {
		return nil, fmt.Errorf("APNS service not configured")
	}
	
	if notification.Platform != entity.PlatformAPNS {
		return nil, fmt.Errorf("invalid platform for APNS: %s", notification.Platform)
	}

	return s.apnsService.SendAPNS(ctx, notification)
}

// SendWebPush sends web push notification (using FCM)
func (s *PushService) SendWebPush(ctx context.Context, notification *entity.Notification) (*service.PushResult, error) {
	if s.fcmService == nil {
		return nil, fmt.Errorf("FCM service required for web push notifications")
	}
	
	// Ensure platform is set correctly for web push
	notification.Platform = entity.PlatformWeb
	
	return s.fcmService.SendFCM(ctx, notification)
}

// Send sends a notification to the appropriate platform
func (s *PushService) Send(ctx context.Context, notification *entity.Notification) (*service.PushResult, error) {
	switch notification.Platform {
	case entity.PlatformFCM:
		return s.SendFCM(ctx, notification)
	case entity.PlatformAPNS:
		return s.SendAPNS(ctx, notification)
	case entity.PlatformWeb:
		return s.SendWebPush(ctx, notification)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", notification.Platform)
	}
}

// SendBatch sends multiple notifications efficiently
func (s *PushService) SendBatch(ctx context.Context, notifications []*entity.Notification) ([]*service.PushResult, error) {
	if len(notifications) == 0 {
		return []*service.PushResult{}, nil
	}

	// Group notifications by platform
	fcmNotifications := make([]*entity.Notification, 0)
	apnsNotifications := make([]*entity.Notification, 0)
	webNotifications := make([]*entity.Notification, 0)
	
	notificationIndexMap := make(map[*entity.Notification]int)
	
	for i, notification := range notifications {
		notificationIndexMap[notification] = i
		
		switch notification.Platform {
		case entity.PlatformFCM:
			fcmNotifications = append(fcmNotifications, notification)
		case entity.PlatformAPNS:
			apnsNotifications = append(apnsNotifications, notification)
		case entity.PlatformWeb:
			webNotifications = append(webNotifications, notification)
		}
	}

	results := make([]*service.PushResult, len(notifications))

	// Send FCM notifications in batch
	if len(fcmNotifications) > 0 && s.fcmService != nil {
		fcmResults, err := s.fcmService.SendBatch(ctx, fcmNotifications)
		if err != nil {
			s.logger.WithError(err).Error("FCM batch send failed")
			// Fill with error results
			for i, notification := range fcmNotifications {
				originalIndex := notificationIndexMap[notification]
				results[originalIndex] = &service.PushResult{
					Success:      false,
					ErrorMessage: fmt.Sprintf("FCM batch failed: %v", err),
					TokenValid:   true,
				}
			}
		} else {
			// Map results back to original positions
			for i, result := range fcmResults {
				originalIndex := notificationIndexMap[fcmNotifications[i]]
				results[originalIndex] = result
			}
		}
	}

	// Send APNS notifications in batch
	if len(apnsNotifications) > 0 && s.apnsService != nil {
		apnsResults, err := s.apnsService.SendBatch(ctx, apnsNotifications)
		if err != nil {
			s.logger.WithError(err).Error("APNS batch send failed")
			// Fill with error results
			for i, notification := range apnsNotifications {
				originalIndex := notificationIndexMap[notification]
				results[originalIndex] = &service.PushResult{
					Success:      false,
					ErrorMessage: fmt.Sprintf("APNS batch failed: %v", err),
					TokenValid:   true,
				}
			}
		} else {
			// Map results back to original positions
			for i, result := range apnsResults {
				originalIndex := notificationIndexMap[apnsNotifications[i]]
				results[originalIndex] = result
			}
		}
	}

	// Send Web Push notifications (using FCM)
	if len(webNotifications) > 0 && s.fcmService != nil {
		webResults, err := s.fcmService.SendBatch(ctx, webNotifications)
		if err != nil {
			s.logger.WithError(err).Error("Web Push batch send failed")
			// Fill with error results
			for i, notification := range webNotifications {
				originalIndex := notificationIndexMap[notification]
				results[originalIndex] = &service.PushResult{
					Success:      false,
					ErrorMessage: fmt.Sprintf("Web Push batch failed: %v", err),
					TokenValid:   true,
				}
			}
		} else {
			// Map results back to original positions
			for i, result := range webResults {
				originalIndex := notificationIndexMap[webNotifications[i]]
				results[originalIndex] = result
			}
		}
	}

	return results, nil
}

// ValidateToken validates a device token for the specified platform
func (s *PushService) ValidateToken(ctx context.Context, token string, platform entity.Platform) error {
	switch platform {
	case entity.PlatformFCM:
		if s.fcmService == nil {
			return fmt.Errorf("FCM service not configured")
		}
		return s.fcmService.ValidateToken(ctx, token, platform)
	case entity.PlatformAPNS:
		if s.apnsService == nil {
			return fmt.Errorf("APNS service not configured")
		}
		return s.apnsService.ValidateToken(ctx, token, platform)
	case entity.PlatformWeb:
		if s.fcmService == nil {
			return fmt.Errorf("FCM service required for web push token validation")
		}
		return s.fcmService.ValidateToken(ctx, token, entity.PlatformFCM)
	default:
		return fmt.Errorf("unsupported platform: %s", platform)
	}
}

// GetDeliveryReceipts gets delivery receipts from push services
func (s *PushService) GetDeliveryReceipts(ctx context.Context, notificationIDs []uuid.UUID) ([]*entity.NotificationDeliveryReceipt, error) {
	receipts := make([]*entity.NotificationDeliveryReceipt, 0)

	// For now, we'll return empty receipts as FCM and APNS have different approaches
	// In a production system, you might implement this through:
	// 1. FCM delivery receipt callbacks
	// 2. APNS feedback service
	// 3. Client-side confirmation mechanisms
	
	s.logger.Info("Delivery receipts requested - implementation depends on platform-specific mechanisms")
	
	return receipts, nil
}

// GetSupportedPlatforms returns the platforms supported by this service
func (s *PushService) GetSupportedPlatforms() []entity.Platform {
	platforms := make([]entity.Platform, 0)
	
	if s.fcmService != nil {
		platforms = append(platforms, entity.PlatformFCM, entity.PlatformWeb)
	}
	
	if s.apnsService != nil {
		platforms = append(platforms, entity.PlatformAPNS)
	}
	
	return platforms
}

// IsHealthy checks the health of push services
func (s *PushService) IsHealthy(ctx context.Context) error {
	healthErrors := make([]error, 0)
	
	// Check FCM health (if configured)
	if s.fcmService != nil {
		// Create a test notification to validate FCM connectivity
		// This is a minimal validation - you might want more comprehensive checks
		testNotification := &entity.Notification{
			ID:          uuid.New(),
			DeviceToken: "test-token-for-health-check",
			Platform:    entity.PlatformFCM,
			Title:       "Health Check",
			Body:        "Service health validation",
		}
		
		_, err := s.fcmService.SendFCM(ctx, testNotification)
		if err != nil && !isExpectedValidationError(err) {
			healthErrors = append(healthErrors, fmt.Errorf("FCM service unhealthy: %w", err))
		}
	}
	
	// Check APNS health (if configured)
	if s.apnsService != nil {
		// Similar health check for APNS
		testNotification := &entity.Notification{
			ID:          uuid.New(),
			DeviceToken: "test-token-for-health-check",
			Platform:    entity.PlatformAPNS,
			Title:       "Health Check",
			Body:        "Service health validation",
		}
		
		_, err := s.apnsService.SendAPNS(ctx, testNotification)
		if err != nil && !isExpectedValidationError(err) {
			healthErrors = append(healthErrors, fmt.Errorf("APNS service unhealthy: %w", err))
		}
	}
	
	if len(healthErrors) > 0 {
		return fmt.Errorf("push service health check failed: %v", healthErrors)
	}
	
	return nil
}

// isExpectedValidationError checks if an error is expected during health validation
// (e.g., invalid token errors are expected when using test tokens)
func isExpectedValidationError(err error) bool {
	// This is a simple implementation - you might want to be more specific
	// about which errors are expected during health checks
	return err != nil && (
		fmt.Sprintf("%v", err) == "invalid FCM token" ||
		fmt.Sprintf("%v", err) == "invalid APNS token" ||
		fmt.Sprintf("%v", err) == "APNS push failed")
}

// GetMetrics returns push service metrics
func (s *PushService) GetMetrics() *PushServiceMetrics {
	return &PushServiceMetrics{
		FCMEnabled:  s.fcmService != nil,
		APNSEnabled: s.apnsService != nil,
		SupportedPlatforms: s.GetSupportedPlatforms(),
	}
}

// PushServiceMetrics represents metrics for the push service
type PushServiceMetrics struct {
	FCMEnabled         bool               `json:"fcm_enabled"`
	APNSEnabled        bool               `json:"apns_enabled"`
	SupportedPlatforms []entity.Platform  `json:"supported_platforms"`
}