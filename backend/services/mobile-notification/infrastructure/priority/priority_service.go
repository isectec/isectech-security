package priority

import (
	"context"
	"fmt"
	"mobile-notification/domain/entity"
	"mobile-notification/domain/repository"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// PriorityService manages notification priorities and queuing
type PriorityService struct {
	notificationRepo repository.NotificationRepository
	preferencesRepo  repository.NotificationPreferencesRepository
	logger           *logrus.Logger
	config           PriorityConfig
}

// PriorityConfig represents priority management configuration
type PriorityConfig struct {
	// Processing limits per priority per minute
	CriticalRateLimit      int `yaml:"critical_rate_limit"`      // 1000 per minute
	WarningRateLimit       int `yaml:"warning_rate_limit"`       // 500 per minute
	InformationalRateLimit int `yaml:"informational_rate_limit"` // 100 per minute

	// Queue sizes
	MaxCriticalQueueSize      int `yaml:"max_critical_queue_size"`      // 10000
	MaxWarningQueueSize       int `yaml:"max_warning_queue_size"`       // 5000
	MaxInformationalQueueSize int `yaml:"max_informational_queue_size"` // 2000

	// Escalation settings
	EnableEscalation        bool `yaml:"enable_escalation"`         // true
	WarningToEscalationTime int  `yaml:"warning_escalation_time"`   // 1800 seconds (30 min)
	InfoToWarningTime       int  `yaml:"info_to_warning_time"`      // 3600 seconds (1 hour)

	// Suppression settings
	EnableSuppression       bool `yaml:"enable_suppression"`        // true
	DuplicateWindow         int  `yaml:"duplicate_window"`          // 300 seconds (5 min)
	MaxDuplicatesPerWindow  int  `yaml:"max_duplicates_per_window"` // 3

	// Circuit breaker settings
	EnableCircuitBreaker       bool `yaml:"enable_circuit_breaker"`        // true
	FailureThreshold          int  `yaml:"failure_threshold"`              // 50
	CircuitBreakerWindow      int  `yaml:"circuit_breaker_window"`         // 300 seconds
	CircuitBreakerRecoveryTime int  `yaml:"circuit_breaker_recovery_time"`  // 600 seconds
}

// PriorityQueue represents a priority-based notification queue
type PriorityQueue struct {
	Critical      []*entity.Notification `json:"critical"`
	Warning       []*entity.Notification `json:"warning"`
	Informational []*entity.Notification `json:"informational"`
	TotalSize     int                    `json:"total_size"`
	LastUpdated   time.Time              `json:"last_updated"`
}

// NotificationScore represents a scored notification for prioritization
type NotificationScore struct {
	Notification *entity.Notification `json:"notification"`
	Score        float64              `json:"score"`
	Factors      ScoreFactors         `json:"factors"`
}

// ScoreFactors represents factors that contribute to notification score
type ScoreFactors struct {
	BasePriority    float64 `json:"base_priority"`    // 1.0-3.0
	Urgency         float64 `json:"urgency"`          // 0.0-2.0
	UserPreference  float64 `json:"user_preference"`  // 0.0-1.0
	ContentType     float64 `json:"content_type"`     // 0.0-1.0
	TimeFactors     float64 `json:"time_factors"`     // 0.0-1.0
	DeliveryContext float64 `json:"delivery_context"` // 0.0-1.0
}

// NewPriorityService creates a new priority service
func NewPriorityService(
	notificationRepo repository.NotificationRepository,
	preferencesRepo repository.NotificationPreferencesRepository,
	logger *logrus.Logger,
	config PriorityConfig,
) *PriorityService {
	// Set default values
	if config.CriticalRateLimit == 0 {
		config.CriticalRateLimit = 1000
	}
	if config.WarningRateLimit == 0 {
		config.WarningRateLimit = 500
	}
	if config.InformationalRateLimit == 0 {
		config.InformationalRateLimit = 100
	}
	if config.MaxCriticalQueueSize == 0 {
		config.MaxCriticalQueueSize = 10000
	}
	if config.MaxWarningQueueSize == 0 {
		config.MaxWarningQueueSize = 5000
	}
	if config.MaxInformationalQueueSize == 0 {
		config.MaxInformationalQueueSize = 2000
	}

	return &PriorityService{
		notificationRepo: notificationRepo,
		preferencesRepo:  preferencesRepo,
		logger:           logger,
		config:           config,
	}
}

// GetPriorityQueue gets notifications organized by priority
func (s *PriorityService) GetPriorityQueue(ctx context.Context, limit int) (*PriorityQueue, error) {
	notifications, err := s.notificationRepo.GetPendingNotifications(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending notifications: %w", err)
	}

	queue := &PriorityQueue{
		Critical:      make([]*entity.Notification, 0),
		Warning:       make([]*entity.Notification, 0),
		Informational: make([]*entity.Notification, 0),
		LastUpdated:   time.Now(),
	}

	// Organize by priority
	for _, notification := range notifications {
		switch notification.Priority {
		case entity.PriorityCritical:
			if len(queue.Critical) < s.config.MaxCriticalQueueSize {
				queue.Critical = append(queue.Critical, notification)
			}
		case entity.PriorityWarning:
			if len(queue.Warning) < s.config.MaxWarningQueueSize {
				queue.Warning = append(queue.Warning, notification)
			}
		case entity.PriorityInformational:
			if len(queue.Informational) < s.config.MaxInformationalQueueSize {
				queue.Informational = append(queue.Informational, notification)
			}
		}
	}

	queue.TotalSize = len(queue.Critical) + len(queue.Warning) + len(queue.Informational)

	s.logger.WithFields(logrus.Fields{
		"critical_count":      len(queue.Critical),
		"warning_count":       len(queue.Warning),
		"informational_count": len(queue.Informational),
		"total_size":          queue.TotalSize,
	}).Debug("Retrieved priority queue")

	return queue, nil
}

// ScoreNotifications scores notifications for intelligent prioritization
func (s *PriorityService) ScoreNotifications(ctx context.Context, notifications []*entity.Notification) ([]*NotificationScore, error) {
	if len(notifications) == 0 {
		return []*NotificationScore{}, nil
	}

	scores := make([]*NotificationScore, len(notifications))

	for i, notification := range notifications {
		score, err := s.ScoreNotification(ctx, notification)
		if err != nil {
			s.logger.WithError(err).WithField("notification_id", notification.ID).Warn("Failed to score notification")
			// Use a default score
			score = &NotificationScore{
				Notification: notification,
				Score:        s.getBasePriorityScore(notification.Priority),
				Factors: ScoreFactors{
					BasePriority: s.getBasePriorityScore(notification.Priority),
				},
			}
		}
		scores[i] = score
	}

	// Sort by score (highest first)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})

	return scores, nil
}

// ScoreNotification scores a single notification
func (s *PriorityService) ScoreNotification(ctx context.Context, notification *entity.Notification) (*NotificationScore, error) {
	factors := ScoreFactors{}

	// Base priority score (1.0-3.0)
	factors.BasePriority = s.getBasePriorityScore(notification.Priority)

	// Urgency factors (0.0-2.0)
	factors.Urgency = s.calculateUrgencyScore(notification)

	// User preference factors (0.0-1.0)
	userPreferenceScore, err := s.calculateUserPreferenceScore(ctx, notification)
	if err != nil {
		s.logger.WithError(err).Warn("Failed to calculate user preference score")
		userPreferenceScore = 0.5 // Default neutral score
	}
	factors.UserPreference = userPreferenceScore

	// Content type factors (0.0-1.0)
	factors.ContentType = s.calculateContentTypeScore(notification)

	// Time factors (0.0-1.0)
	factors.TimeFactors = s.calculateTimeFactors(notification)

	// Delivery context factors (0.0-1.0)
	factors.DeliveryContext = s.calculateDeliveryContextScore(notification)

	// Calculate final score
	score := factors.BasePriority +
		factors.Urgency +
		factors.UserPreference +
		factors.ContentType +
		factors.TimeFactors +
		factors.DeliveryContext

	return &NotificationScore{
		Notification: notification,
		Score:        score,
		Factors:      factors,
	}, nil
}

// CheckForDuplicates checks for duplicate notifications within the suppression window
func (s *PriorityService) CheckForDuplicates(ctx context.Context, notification *entity.Notification) (bool, []*entity.Notification, error) {
	if !s.config.EnableSuppression {
		return false, nil, nil
	}

	windowStart := time.Now().Add(-time.Duration(s.config.DuplicateWindow) * time.Second)

	// Get recent notifications for the user
	recentNotifications, err := s.notificationRepo.GetByUserID(ctx, notification.UserID, 100, 0)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get recent notifications: %w", err)
	}

	duplicates := make([]*entity.Notification, 0)

	for _, recent := range recentNotifications {
		if recent.CreatedAt.Before(windowStart) {
			break // Notifications are ordered by creation time desc
		}

		if s.areNotificationsSimilar(notification, recent) {
			duplicates = append(duplicates, recent)
		}
	}

	isDuplicate := len(duplicates) >= s.config.MaxDuplicatesPerWindow

	if isDuplicate {
		s.logger.WithFields(logrus.Fields{
			"notification_id":  notification.ID,
			"user_id":         notification.UserID,
			"duplicate_count": len(duplicates),
			"title":          notification.Title,
		}).Info("Duplicate notification detected")
	}

	return isDuplicate, duplicates, nil
}

// EscalateNotifications escalates notifications based on age and priority
func (s *PriorityService) EscalateNotifications(ctx context.Context) error {
	if !s.config.EnableEscalation {
		return nil
	}

	// Get warning notifications older than escalation threshold
	warningNotifications, err := s.notificationRepo.GetNotificationsByStatus(ctx, entity.StatusPending, 1000)
	if err != nil {
		return fmt.Errorf("failed to get pending notifications: %w", err)
	}

	escalationThreshold := time.Now().Add(-time.Duration(s.config.WarningToEscalationTime) * time.Second)
	warningToInfoThreshold := time.Now().Add(-time.Duration(s.config.InfoToWarningTime) * time.Second)

	escalatedCount := 0

	for _, notification := range warningNotifications {
		if notification.CreatedAt.Before(escalationThreshold) && notification.Priority == entity.PriorityWarning {
			// Escalate warning to critical
			notification.Priority = entity.PriorityCritical
			if err := s.notificationRepo.Update(ctx, notification); err != nil {
				s.logger.WithError(err).WithField("notification_id", notification.ID).Error("Failed to escalate notification to critical")
				continue
			}
			escalatedCount++
			
			s.logger.WithFields(logrus.Fields{
				"notification_id": notification.ID,
				"from_priority":   "warning",
				"to_priority":     "critical",
				"age_minutes":     time.Since(notification.CreatedAt).Minutes(),
			}).Info("Escalated notification priority")
			
		} else if notification.CreatedAt.Before(warningToInfoThreshold) && notification.Priority == entity.PriorityInformational {
			// Escalate informational to warning
			notification.Priority = entity.PriorityWarning
			if err := s.notificationRepo.Update(ctx, notification); err != nil {
				s.logger.WithError(err).WithField("notification_id", notification.ID).Error("Failed to escalate notification to warning")
				continue
			}
			escalatedCount++
			
			s.logger.WithFields(logrus.Fields{
				"notification_id": notification.ID,
				"from_priority":   "informational",
				"to_priority":     "warning",
				"age_minutes":     time.Since(notification.CreatedAt).Minutes(),
			}).Info("Escalated notification priority")
		}
	}

	if escalatedCount > 0 {
		s.logger.WithField("escalated_count", escalatedCount).Info("Completed notification priority escalation")
	}

	return nil
}

// getBasePriorityScore returns the base score for a priority level
func (s *PriorityService) getBasePriorityScore(priority entity.NotificationPriority) float64 {
	switch priority {
	case entity.PriorityCritical:
		return 3.0
	case entity.PriorityWarning:
		return 2.0
	case entity.PriorityInformational:
		return 1.0
	default:
		return 1.0
	}
}

// calculateUrgencyScore calculates urgency based on notification content
func (s *PriorityService) calculateUrgencyScore(notification *entity.Notification) float64 {
	urgencyKeywords := map[string]float64{
		"immediate":   2.0,
		"urgent":      1.8,
		"critical":    1.6,
		"emergency":   2.0,
		"breach":      1.8,
		"attack":      1.6,
		"malware":     1.4,
		"suspicious":  1.2,
		"alert":       1.0,
		"warning":     0.8,
		"info":        0.4,
		"update":      0.2,
	}

	score := 0.0
	title := notification.Title
	body := notification.Body

	for keyword, keywordScore := range urgencyKeywords {
		if containsKeyword(title, keyword) || containsKeyword(body, keyword) {
			if keywordScore > score {
				score = keywordScore
			}
		}
	}

	return score
}

// calculateUserPreferenceScore calculates score based on user preferences
func (s *PriorityService) calculateUserPreferenceScore(ctx context.Context, notification *entity.Notification) (float64, error) {
	preferences, err := s.preferencesRepo.GetByUserID(ctx, notification.UserID)
	if err != nil {
		return 0.5, err // Default neutral score on error
	}

	if preferences == nil {
		return 0.5, nil // Default neutral score if no preferences
	}

	// Check category preferences
	if categoryType, exists := notification.Data["category"]; exists {
		if categoryPref, exists := preferences.Categories[categoryType]; exists {
			if !categoryPref.Enabled {
				return 0.0, nil // User disabled this category
			}
			
			// Boost score based on user's priority preference for this category
			switch categoryPref.Priority {
			case entity.PriorityCritical:
				return 1.0, nil
			case entity.PriorityWarning:
				return 0.7, nil
			case entity.PriorityInformational:
				return 0.4, nil
			}
		}
	}

	// Check general preferences
	switch {
	case notification.Priority == entity.PriorityCritical && preferences.SecurityAlerts:
		return 1.0, nil
	case notification.Priority == entity.PriorityWarning && preferences.SystemNotifications:
		return 0.7, nil
	case notification.Priority == entity.PriorityInformational && preferences.MarketingNotifications:
		return 0.4, nil
	default:
		return 0.5, nil
	}
}

// calculateContentTypeScore calculates score based on content type
func (s *PriorityService) calculateContentTypeScore(notification *entity.Notification) float64 {
	contentTypeScores := map[string]float64{
		"security_alert":     1.0,
		"system_maintenance": 0.6,
		"feature_update":     0.4,
		"marketing":          0.2,
		"newsletter":         0.1,
	}

	if contentType, exists := notification.Data["content_type"]; exists {
		if score, exists := contentTypeScores[contentType]; exists {
			return score
		}
	}

	return 0.5 // Default score
}

// calculateTimeFactors calculates score based on timing factors
func (s *PriorityService) calculateTimeFactors(notification *entity.Notification) float64 {
	now := time.Now()
	
	// Age factor - newer notifications get higher scores
	age := now.Sub(notification.CreatedAt)
	ageScore := 0.0
	
	if age < 5*time.Minute {
		ageScore = 1.0
	} else if age < 15*time.Minute {
		ageScore = 0.8
	} else if age < 30*time.Minute {
		ageScore = 0.6
	} else if age < 60*time.Minute {
		ageScore = 0.4
	} else {
		ageScore = 0.2
	}
	
	// Time of day factor - work hours get slightly higher priority
	hour := now.Hour()
	timeOfDayScore := 0.5 // Default
	
	if hour >= 9 && hour <= 17 {
		timeOfDayScore = 0.7 // Work hours
	} else if hour >= 18 && hour <= 22 {
		timeOfDayScore = 0.6 // Evening
	} else {
		timeOfDayScore = 0.3 // Night/early morning
	}
	
	return (ageScore + timeOfDayScore) / 2
}

// calculateDeliveryContextScore calculates score based on delivery context
func (s *PriorityService) calculateDeliveryContextScore(notification *entity.Notification) float64 {
	score := 0.5 // Default score
	
	// Platform factor
	switch notification.Platform {
	case entity.PlatformAPNS:
		score += 0.1 // iOS users typically have higher engagement
	case entity.PlatformFCM:
		score += 0.05
	case entity.PlatformWeb:
		score += 0.0
	}
	
	// Action URL factor - notifications with actions get higher priority
	if notification.ActionURL != "" {
		score += 0.2
	}
	
	// Rich content factor - notifications with images get slight boost
	if notification.ImageURL != "" {
		score += 0.1
	}
	
	return score
}

// areNotificationsSimilar checks if two notifications are similar enough to be considered duplicates
func (s *PriorityService) areNotificationsSimilar(n1, n2 *entity.Notification) bool {
	// Same user and similar title
	if n1.UserID != n2.UserID {
		return false
	}
	
	// Title similarity (simple check - could be enhanced with fuzzy matching)
	if n1.Title == n2.Title {
		return true
	}
	
	// Check if they're the same type based on data
	if n1Type, exists1 := n1.Data["type"]; exists1 {
		if n2Type, exists2 := n2.Data["type"]; exists2 {
			return n1Type == n2Type
		}
	}
	
	return false
}

// containsKeyword checks if text contains a keyword (case-insensitive)
func containsKeyword(text, keyword string) bool {
	// Simple implementation - could be enhanced with better text processing
	return len(text) > 0 && len(keyword) > 0 // Placeholder implementation
}

// GetPriorityMetrics returns metrics about priority processing
func (s *PriorityService) GetPriorityMetrics(ctx context.Context) (*PriorityMetrics, error) {
	queue, err := s.GetPriorityQueue(ctx, 10000)
	if err != nil {
		return nil, fmt.Errorf("failed to get priority queue: %w", err)
	}
	
	return &PriorityMetrics{
		CriticalQueueSize:      len(queue.Critical),
		WarningQueueSize:       len(queue.Warning),
		InformationalQueueSize: len(queue.Informational),
		TotalQueueSize:         queue.TotalSize,
		QueueUtilization: map[entity.NotificationPriority]float64{
			entity.PriorityCritical:      float64(len(queue.Critical)) / float64(s.config.MaxCriticalQueueSize),
			entity.PriorityWarning:       float64(len(queue.Warning)) / float64(s.config.MaxWarningQueueSize),
			entity.PriorityInformational: float64(len(queue.Informational)) / float64(s.config.MaxInformationalQueueSize),
		},
		LastUpdated: queue.LastUpdated,
	}, nil
}

// PriorityMetrics represents metrics for priority processing
type PriorityMetrics struct {
	CriticalQueueSize      int                                       `json:"critical_queue_size"`
	WarningQueueSize       int                                       `json:"warning_queue_size"`
	InformationalQueueSize int                                       `json:"informational_queue_size"`
	TotalQueueSize         int                                       `json:"total_queue_size"`
	QueueUtilization       map[entity.NotificationPriority]float64  `json:"queue_utilization"`
	LastUpdated            time.Time                                 `json:"last_updated"`
}