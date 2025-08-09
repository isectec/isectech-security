package push

import (
	"context"
	"encoding/json"
	"fmt"
	"mobile-notification/domain/entity"
	"mobile-notification/domain/service"
	"strconv"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	"github.com/sirupsen/logrus"
)

// APNSService implements Apple Push Notification Service
type APNSService struct {
	client *apns2.Client
	logger *logrus.Logger
	config APNSConfig
}

// APNSConfig represents Apple Push Notification Service configuration
type APNSConfig struct {
	AuthType        string `yaml:"auth_type"`        // "certificate" or "token"
	CertificateFile string `yaml:"certificate_file"` // Path to .p12 certificate file
	CertificatePass string `yaml:"certificate_pass"` // Certificate password
	KeyID           string `yaml:"key_id"`           // For token-based auth
	TeamID          string `yaml:"team_id"`          // For token-based auth
	PrivateKeyFile  string `yaml:"private_key_file"` // For token-based auth (.p8 file)
	Topic           string `yaml:"topic"`            // Bundle ID of the app
	Production      bool   `yaml:"production"`       // Use production APNS servers
	MaxRetries      int    `yaml:"max_retries"`
	RetryDelay      int    `yaml:"retry_delay"`
	BatchSize       int    `yaml:"batch_size"`
	DefaultTTL      int    `yaml:"default_ttl"`
}

// NewAPNSService creates a new APNS service instance
func NewAPNSService(config APNSConfig, logger *logrus.Logger) (*APNSService, error) {
	var client *apns2.Client
	var err error

	switch config.AuthType {
	case "certificate":
		if config.CertificateFile == "" {
			return nil, fmt.Errorf("certificate_file is required for certificate-based auth")
		}
		cert, err := certificate.FromP12File(config.CertificateFile, config.CertificatePass)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		client = apns2.NewClient(cert)
	case "token":
		if config.KeyID == "" || config.TeamID == "" || config.PrivateKeyFile == "" {
			return nil, fmt.Errorf("key_id, team_id, and private_key_file are required for token-based auth")
		}
		authKey, err := token.AuthKeyFromFile(config.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		tokenProvider := &token.Token{
			AuthKey: authKey,
			KeyID:   config.KeyID,
			TeamID:  config.TeamID,
		}
		client = apns2.NewTokenClient(tokenProvider)
	default:
		return nil, fmt.Errorf("invalid auth_type: must be 'certificate' or 'token'")
	}

	// Set server environment
	if config.Production {
		client = client.Production()
	} else {
		client = client.Development()
	}

	// Set default values
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 3600
	}

	return &APNSService{
		client: client,
		logger: logger,
		config: config,
	}, nil
}

// SendAPNS sends a notification via Apple Push Notification Service
func (s *APNSService) SendAPNS(ctx context.Context, notification *entity.Notification) (*service.PushResult, error) {
	apnsNotification, err := s.buildNotification(notification)
	if err != nil {
		s.logger.WithError(err).Error("Failed to build APNS notification")
		return &service.PushResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to build notification: %v", err),
			TokenValid:   true,
		}, nil
	}

	// Send with retry logic
	return s.sendWithRetry(ctx, apnsNotification, notification)
}

// SendBatch sends multiple notifications in a batch
func (s *APNSService) SendBatch(ctx context.Context, notifications []*entity.Notification) ([]*service.PushResult, error) {
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
		for j, notification := range batch {
			result, err := s.SendAPNS(ctx, notification)
			if err != nil {
				result = &service.PushResult{
					Success:      false,
					ErrorMessage: err.Error(),
					TokenValid:   true,
				}
			}
			results[i+j] = result
		}
	}

	return results, nil
}

// ValidateToken validates an APNS device token
func (s *APNSService) ValidateToken(ctx context.Context, token string, platform entity.Platform) error {
	if platform != entity.PlatformAPNS {
		return fmt.Errorf("invalid platform for APNS service: %s", platform)
	}

	// Create a test notification to validate the token
	apnsNotification := &apns2.Notification{
		DeviceToken: token,
		Topic:       s.config.Topic,
		Payload: []byte(`{
			"aps": {
				"alert": {
					"title": "Validation",
					"body": "Token validation test"
				},
				"sound": "",
				"badge": 0
			},
			"validation": true
		}`),
	}

	// Send with a very short expiration to minimize impact
	apnsNotification.Expiration = time.Now().Add(1 * time.Second)

	res, err := s.client.Push(apnsNotification)
	if err != nil {
		s.logger.WithError(err).WithField("token", token).Error("APNS token validation failed")
		return fmt.Errorf("APNS push failed: %w", err)
	}

	if res.StatusCode != 200 {
		s.logger.WithFields(logrus.Fields{
			"token":       token,
			"status_code": res.StatusCode,
			"reason":      res.Reason,
		}).Error("APNS token validation failed")
		return fmt.Errorf("invalid APNS token: %s", res.Reason)
	}

	return nil
}

// buildNotification constructs an APNS notification from a notification entity
func (s *APNSService) buildNotification(notification *entity.Notification) (*apns2.Notification, error) {
	if notification.DeviceToken == "" {
		return nil, fmt.Errorf("device token is required")
	}

	if s.config.Topic == "" {
		return nil, fmt.Errorf("APNS topic (bundle ID) is required")
	}

	apnsNotification := &apns2.Notification{
		DeviceToken: notification.DeviceToken,
		Topic:       s.config.Topic,
	}

	// Build payload
	payload, err := s.buildPayload(notification)
	if err != nil {
		return nil, fmt.Errorf("failed to build payload: %w", err)
	}

	apnsNotification.Payload = payload

	// Set priority based on notification priority
	switch notification.Priority {
	case entity.PriorityCritical:
		apnsNotification.Priority = apns2.PriorityHigh
	case entity.PriorityWarning:
		apnsNotification.Priority = apns2.PriorityHigh
	case entity.PriorityInformational:
		apnsNotification.Priority = apns2.PriorityLow
	default:
		apnsNotification.Priority = apns2.PriorityLow
	}

	// Set expiration
	ttl := notification.TTL
	if ttl == 0 {
		ttl = s.config.DefaultTTL
	}
	apnsNotification.Expiration = time.Now().Add(time.Duration(ttl) * time.Second)

	// Set collapse ID for similar notifications
	if notification.BatchID != nil {
		apnsNotification.CollapseID = notification.BatchID.String()
	}

	return apnsNotification, nil
}

// buildPayload creates the APNS payload
func (s *APNSService) buildPayload(notification *entity.Notification) ([]byte, error) {
	p := payload.NewPayload()

	// Set alert content
	if notification.Title != "" && notification.Body != "" {
		p.AlertTitle(notification.Title)
		p.AlertBody(notification.Body)
	} else if notification.Body != "" {
		p.Alert(notification.Body)
	}

	// Set badge (if provided in data)
	if badgeStr, exists := notification.Data["badge"]; exists {
		if badge, err := strconv.Atoi(badgeStr); err == nil {
			p.Badge(badge)
		}
	}

	// Set sound based on priority
	switch notification.Priority {
	case entity.PriorityCritical:
		p.Sound("critical.wav")
		p.Custom("interruption-level", "critical")
	case entity.PriorityWarning:
		p.Sound("default")
		p.Custom("interruption-level", "active")
	case entity.PriorityInformational:
		p.SoundName("") // Silent notification
		p.Custom("interruption-level", "passive")
	default:
		p.Sound("default")
	}

	// Add custom data
	for key, value := range notification.Data {
		if key != "badge" { // badge is handled separately
			p.Custom(key, value)
		}
	}

	// Add notification metadata
	p.Custom("notification_id", notification.ID.String())
	p.Custom("tenant_id", notification.TenantID.String())
	
	// Add action URL if provided
	if notification.ActionURL != "" {
		p.Custom("action_url", notification.ActionURL)
	}

	// Add category for actionable notifications
	if notification.Priority == entity.PriorityCritical {
		p.Category("SECURITY_ALERT")
	}

	// Set content-available for background updates
	if notification.Priority == entity.PriorityInformational {
		p.ContentAvailable()
	}

	// Set mutable-content for rich notifications with images
	if notification.ImageURL != "" {
		p.MutableContent()
		p.Custom("image_url", notification.ImageURL)
	}

	return p.MarshalJSON()
}

// sendWithRetry sends a notification with retry logic
func (s *APNSService) sendWithRetry(ctx context.Context, apnsNotification *apns2.Notification, notification *entity.Notification) (*service.PushResult, error) {
	var lastRes *apns2.Response
	var lastErr error
	
	for attempt := 0; attempt <= s.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			time.Sleep(time.Duration(s.config.RetryDelay*(attempt)) * time.Second)
		}

		res, err := s.client.Push(apnsNotification)
		if err != nil {
			lastErr = err
			s.logger.WithFields(logrus.Fields{
				"notification_id": notification.ID,
				"attempt":         attempt + 1,
				"error":           err.Error(),
			}).Warn("APNS push failed, will retry")
			continue
		}

		lastRes = res

		if res.StatusCode == 200 {
			// Success
			s.logger.WithFields(logrus.Fields{
				"notification_id": notification.ID,
				"apns_id":         res.ApnsID,
				"attempt":         attempt + 1,
			}).Info("APNS notification sent successfully")

			return &service.PushResult{
				Success:   true,
				MessageID: res.ApnsID,
				TokenValid: true,
				Metadata: map[string]string{
					"attempt":     strconv.Itoa(attempt + 1),
					"platform":    string(entity.PlatformAPNS),
					"status_code": strconv.Itoa(res.StatusCode),
				},
			}, nil
		}

		// Check if error is retryable
		if !s.isRetryableStatus(res.StatusCode) {
			break
		}

		s.logger.WithFields(logrus.Fields{
			"notification_id": notification.ID,
			"attempt":         attempt + 1,
			"status_code":     res.StatusCode,
			"reason":          res.Reason,
		}).Warn("APNS push failed, will retry")
	}

	// All retries failed
	result := &service.PushResult{
		Success: false,
		TokenValid: true,
		Retry:   false,
	}

	if lastRes != nil {
		result.ErrorCode = strconv.Itoa(lastRes.StatusCode)
		result.ErrorMessage = lastRes.Reason
		result.TokenValid = !s.isTokenError(lastRes.StatusCode)
		result.Retry = s.isRetryableStatus(lastRes.StatusCode)
		
		if lastRes.ApnsID != "" {
			result.MessageID = lastRes.ApnsID
		}
	} else if lastErr != nil {
		result.ErrorMessage = lastErr.Error()
		result.Retry = true
	}

	s.logger.WithFields(logrus.Fields{
		"notification_id": notification.ID,
		"error_code":      result.ErrorCode,
		"error_message":   result.ErrorMessage,
		"token_valid":     result.TokenValid,
	}).Error("APNS notification send failed after all retries")

	return result, nil
}

// isRetryableStatus checks if an APNS status code indicates a retryable error
func (s *APNSService) isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case 500, 502, 503, 429: // Internal server error, bad gateway, service unavailable, too many requests
		return true
	default:
		return false
	}
}

// isTokenError checks if a status code indicates an invalid token
func (s *APNSService) isTokenError(statusCode int) bool {
	switch statusCode {
	case 400, 410: // Bad request (invalid token format), Gone (invalid token)
		return true
	default:
		return false
	}
}

// GetDeliveryReceipts gets delivery receipts for APNS notifications
// Note: APNS doesn't provide delivery receipts in the same way as FCM
// This method would need to be implemented based on your receipt tracking strategy
func (s *APNSService) GetDeliveryReceipts(ctx context.Context, notificationIDs []string) (map[string]*service.PushResult, error) {
	// APNS doesn't provide delivery receipts directly
	// You would need to implement this based on your tracking mechanism
	// For example, using silent notifications with confirmation responses
	
	s.logger.Info("APNS delivery receipts requested - not directly supported by APNS")
	
	receipts := make(map[string]*service.PushResult)
	for _, id := range notificationIDs {
		receipts[id] = &service.PushResult{
			Success:      true,
			ErrorMessage: "APNS delivery receipts not directly supported",
			TokenValid:   true,
		}
	}
	
	return receipts, nil
}