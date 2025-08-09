package stream_processing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AlertingSystem manages alerts and notifications for stream processing
type AlertingSystem struct {
	logger *zap.Logger
	config *AlertingConfig
	
	// Alert channels
	webhookChannel    *WebhookChannel
	emailChannel      *EmailChannel
	slackChannel      *SlackChannel
	
	// Alert management
	activeAlerts      map[string]*Alert
	alertHistory      []*Alert
	suppressedAlerts  map[string]time.Time
	mu                sync.RWMutex
	
	// Background processing
	ctx               context.Context
	cancel            context.CancelFunc
	processingTicker  *time.Ticker
	
	// Metrics integration
	metricsCollector  *MetricsCollector
	
	// Health monitoring integration
	healthMonitor     *HealthMonitor
}

// AlertingConfig defines configuration for the alerting system
type AlertingConfig struct {
	Enabled                bool          `json:"enabled"`
	ProcessingInterval     time.Duration `json:"processing_interval"`
	AlertHistoryLimit      int           `json:"alert_history_limit"`
	SuppressionDuration    time.Duration `json:"suppression_duration"`
	
	// Channels
	WebhookURL             string        `json:"webhook_url"`
	EmailSMTPServer        string        `json:"email_smtp_server"`
	EmailSMTPPort          int           `json:"email_smtp_port"`
	EmailUsername          string        `json:"email_username"`
	EmailPassword          string        `json:"email_password"`
	EmailRecipients        []string      `json:"email_recipients"`
	SlackWebhookURL        string        `json:"slack_webhook_url"`
	SlackChannel           string        `json:"slack_channel"`
	
	// Alert rules
	HighLatencyThreshold   time.Duration `json:"high_latency_threshold"`
	LowThroughputThreshold float64       `json:"low_throughput_threshold"`
	HighErrorRateThreshold float64       `json:"high_error_rate_threshold"`
	KafkaLagThreshold      int64         `json:"kafka_lag_threshold"`
	
	// Escalation
	EscalationEnabled      bool          `json:"escalation_enabled"`
	EscalationTimeout      time.Duration `json:"escalation_timeout"`
	EscalationRecipients   []string      `json:"escalation_recipients"`
}

// Alert represents a system alert
type Alert struct {
	ID            string                 `json:"id"`
	Type          AlertType              `json:"type"`
	Severity      AlertSeverity          `json:"severity"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Component     string                 `json:"component"`
	Timestamp     time.Time              `json:"timestamp"`
	Status        AlertStatus            `json:"status"`
	Labels        map[string]string      `json:"labels"`
	Annotations   map[string]string      `json:"annotations"`
	
	// Lifecycle
	FirstSeen     time.Time              `json:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"`
	ResolvedAt    *time.Time             `json:"resolved_at,omitempty"`
	AcknowledgedAt *time.Time            `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string                `json:"acknowledged_by,omitempty"`
	
	// Context
	EventData     map[string]interface{} `json:"event_data,omitempty"`
	MetricValues  map[string]float64     `json:"metric_values,omitempty"`
	
	// Notification tracking
	NotificationsSent []NotificationRecord `json:"notifications_sent"`
	SuppressedUntil   *time.Time          `json:"suppressed_until,omitempty"`
}

// AlertType represents different types of alerts
type AlertType string

const (
	AlertTypePerformance    AlertType = "performance"
	AlertTypeHealth         AlertType = "health"
	AlertTypeSecurity       AlertType = "security"
	AlertTypeInfrastructure AlertType = "infrastructure"
	AlertTypeData           AlertType = "data"
)

// AlertSeverity represents alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertStatus represents alert status
type AlertStatus string

const (
	AlertStatusActive       AlertStatus = "active"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusSuppressed   AlertStatus = "suppressed"
)

// NotificationRecord tracks sent notifications
type NotificationRecord struct {
	Channel   string    `json:"channel"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// WebhookChannel handles webhook notifications
type WebhookChannel struct {
	URL        string
	HTTPClient *http.Client
}

// EmailChannel handles email notifications
type EmailChannel struct {
	SMTPServer  string
	SMTPPort    int
	Username    string
	Password    string
	Recipients  []string
	HTTPClient  *http.Client
}

// SlackChannel handles Slack notifications
type SlackChannel struct {
	WebhookURL string
	Channel    string
	HTTPClient *http.Client
}

// NewAlertingSystem creates a new alerting system
func NewAlertingSystem(logger *zap.Logger, config *AlertingConfig, metricsCollector *MetricsCollector, healthMonitor *HealthMonitor) (*AlertingSystem, error) {
	if config == nil {
		return nil, fmt.Errorf("alerting configuration is required")
	}
	
	// Set defaults
	if config.ProcessingInterval == 0 {
		config.ProcessingInterval = 10 * time.Second
	}
	if config.AlertHistoryLimit == 0 {
		config.AlertHistoryLimit = 1000
	}
	if config.SuppressionDuration == 0 {
		config.SuppressionDuration = 5 * time.Minute
	}
	if config.HighLatencyThreshold == 0 {
		config.HighLatencyThreshold = 5 * time.Second
	}
	if config.LowThroughputThreshold == 0 {
		config.LowThroughputThreshold = 100.0
	}
	if config.HighErrorRateThreshold == 0 {
		config.HighErrorRateThreshold = 0.05
	}
	if config.KafkaLagThreshold == 0 {
		config.KafkaLagThreshold = 10000
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	system := &AlertingSystem{
		logger:           logger.With(zap.String("component", "alerting-system")),
		config:           config,
		activeAlerts:     make(map[string]*Alert),
		alertHistory:     make([]*Alert, 0),
		suppressedAlerts: make(map[string]time.Time),
		metricsCollector: metricsCollector,
		healthMonitor:    healthMonitor,
		ctx:              ctx,
		cancel:           cancel,
	}
	
	// Initialize notification channels
	system.initializeChannels()
	
	// Start background processing
	if config.Enabled {
		system.processingTicker = time.NewTicker(config.ProcessingInterval)
		go system.runAlertProcessing()
	}
	
	logger.Info("Alerting system initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Duration("processing_interval", config.ProcessingInterval),
		zap.Bool("webhook_enabled", config.WebhookURL != ""),
		zap.Bool("email_enabled", config.EmailSMTPServer != ""),
		zap.Bool("slack_enabled", config.SlackWebhookURL != ""),
	)
	
	return system, nil
}

// initializeChannels initializes notification channels
func (a *AlertingSystem) initializeChannels() {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Webhook channel
	if a.config.WebhookURL != "" {
		a.webhookChannel = &WebhookChannel{
			URL:        a.config.WebhookURL,
			HTTPClient: httpClient,
		}
	}
	
	// Email channel
	if a.config.EmailSMTPServer != "" {
		a.emailChannel = &EmailChannel{
			SMTPServer: a.config.EmailSMTPServer,
			SMTPPort:   a.config.EmailSMTPPort,
			Username:   a.config.EmailUsername,
			Password:   a.config.EmailPassword,
			Recipients: a.config.EmailRecipients,
			HTTPClient: httpClient,
		}
	}
	
	// Slack channel
	if a.config.SlackWebhookURL != "" {
		a.slackChannel = &SlackChannel{
			WebhookURL:  a.config.SlackWebhookURL,
			Channel:     a.config.SlackChannel,
			HTTPClient:  httpClient,
		}
	}
}

// CreateAlert creates a new alert
func (a *AlertingSystem) CreateAlert(alertType AlertType, severity AlertSeverity, title, description, component string, labels map[string]string, eventData map[string]interface{}) *Alert {
	now := time.Now()
	
	alertID := fmt.Sprintf("%s-%s-%d", component, alertType, now.Unix())
	
	alert := &Alert{
		ID:              alertID,
		Type:            alertType,
		Severity:        severity,
		Title:           title,
		Description:     description,
		Component:       component,
		Timestamp:       now,
		Status:          AlertStatusActive,
		Labels:          labels,
		Annotations:     make(map[string]string),
		FirstSeen:       now,
		LastSeen:        now,
		EventData:       eventData,
		MetricValues:    make(map[string]float64),
		NotificationsSent: make([]NotificationRecord, 0),
	}
	
	// Set default labels
	if alert.Labels == nil {
		alert.Labels = make(map[string]string)
	}
	alert.Labels["alert_id"] = alertID
	alert.Labels["component"] = component
	alert.Labels["severity"] = string(severity)
	alert.Labels["type"] = string(alertType)
	
	a.mu.Lock()
	defer a.mu.Unlock()
	
	// Check for existing similar alerts
	existingAlert := a.findSimilarAlert(alert)
	if existingAlert != nil {
		// Update existing alert
		existingAlert.LastSeen = now
		existingAlert.EventData = eventData
		a.logger.Debug("Updated existing alert", zap.String("alert_id", existingAlert.ID))
		return existingAlert
	}
	
	// Add new alert
	a.activeAlerts[alertID] = alert
	a.addToHistory(alert)
	
	a.logger.Info("Created new alert",
		zap.String("alert_id", alertID),
		zap.String("type", string(alertType)),
		zap.String("severity", string(severity)),
		zap.String("component", component),
		zap.String("title", title),
	)
	
	// Record metric
	if a.metricsCollector != nil {
		a.metricsCollector.RecordAlertGenerated(string(alertType), string(severity))
	}
	
	return alert
}

// ResolveAlert resolves an active alert
func (a *AlertingSystem) ResolveAlert(alertID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	alert, exists := a.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	now := time.Now()
	alert.Status = AlertStatusResolved
	alert.ResolvedAt = &now
	
	// Remove from active alerts
	delete(a.activeAlerts, alertID)
	
	a.logger.Info("Resolved alert",
		zap.String("alert_id", alertID),
		zap.String("component", alert.Component),
	)
	
	return nil
}

// AcknowledgeAlert acknowledges an alert
func (a *AlertingSystem) AcknowledgeAlert(alertID, acknowledgedBy string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	alert, exists := a.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	now := time.Now()
	alert.Status = AlertStatusAcknowledged
	alert.AcknowledgedAt = &now
	alert.AcknowledgedBy = acknowledgedBy
	
	a.logger.Info("Acknowledged alert",
		zap.String("alert_id", alertID),
		zap.String("acknowledged_by", acknowledgedBy),
	)
	
	return nil
}

// SuppressAlert suppresses an alert for a specified duration
func (a *AlertingSystem) SuppressAlert(alertID string, duration time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	alert, exists := a.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	suppressUntil := time.Now().Add(duration)
	alert.Status = AlertStatusSuppressed
	alert.SuppressedUntil = &suppressUntil
	
	a.suppressedAlerts[alertID] = suppressUntil
	
	a.logger.Info("Suppressed alert",
		zap.String("alert_id", alertID),
		zap.Duration("duration", duration),
	)
	
	return nil
}

// GetActiveAlerts returns all active alerts
func (a *AlertingSystem) GetActiveAlerts() []*Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	alerts := make([]*Alert, 0, len(a.activeAlerts))
	for _, alert := range a.activeAlerts {
		alertCopy := *alert
		alerts = append(alerts, &alertCopy)
	}
	
	return alerts
}

// GetAlertHistory returns alert history
func (a *AlertingSystem) GetAlertHistory(limit int) []*Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	if limit <= 0 || limit > len(a.alertHistory) {
		limit = len(a.alertHistory)
	}
	
	history := make([]*Alert, limit)
	copy(history, a.alertHistory[len(a.alertHistory)-limit:])
	
	return history
}

// runAlertProcessing runs background alert processing
func (a *AlertingSystem) runAlertProcessing() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.processingTicker.C:
			a.processAlerts()
		}
	}
}

// processAlerts processes active alerts for notifications and cleanup
func (a *AlertingSystem) processAlerts() {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	now := time.Now()
	
	// Process active alerts
	for alertID, alert := range a.activeAlerts {
		// Check if suppression has expired
		if alert.Status == AlertStatusSuppressed && alert.SuppressedUntil != nil && now.After(*alert.SuppressedUntil) {
			alert.Status = AlertStatusActive
			alert.SuppressedUntil = nil
			delete(a.suppressedAlerts, alertID)
		}
		
		// Send notifications for active alerts
		if alert.Status == AlertStatusActive {
			a.sendNotifications(alert)
		}
	}
	
	// Clean up old suppression entries
	for alertID, suppressUntil := range a.suppressedAlerts {
		if now.After(suppressUntil) {
			delete(a.suppressedAlerts, alertID)
		}
	}
}

// sendNotifications sends notifications for an alert
func (a *AlertingSystem) sendNotifications(alert *Alert) {
	// Check if we should send notifications (avoid spam)
	if a.shouldSendNotification(alert) {
		// Send webhook notification
		if a.webhookChannel != nil {
			a.sendWebhookNotification(alert)
		}
		
		// Send email notification
		if a.emailChannel != nil {
			a.sendEmailNotification(alert)
		}
		
		// Send Slack notification
		if a.slackChannel != nil {
			a.sendSlackNotification(alert)
		}
	}
}

// shouldSendNotification determines if a notification should be sent
func (a *AlertingSystem) shouldSendNotification(alert *Alert) bool {
	// Don't send if suppressed
	if alert.Status == AlertStatusSuppressed {
		return false
	}
	
	// Don't send if already acknowledged
	if alert.Status == AlertStatusAcknowledged {
		return false
	}
	
	// Check notification history to avoid spam
	lastNotification := a.getLastNotificationTime(alert)
	if !lastNotification.IsZero() {
		timeSinceLastNotification := time.Since(lastNotification)
		if timeSinceLastNotification < a.config.SuppressionDuration {
			return false
		}
	}
	
	return true
}

// findSimilarAlert finds an existing similar alert
func (a *AlertingSystem) findSimilarAlert(newAlert *Alert) *Alert {
	for _, alert := range a.activeAlerts {
		if alert.Component == newAlert.Component &&
			alert.Type == newAlert.Type &&
			alert.Title == newAlert.Title {
			return alert
		}
	}
	return nil
}

// addToHistory adds an alert to the history
func (a *AlertingSystem) addToHistory(alert *Alert) {
	a.alertHistory = append(a.alertHistory, alert)
	
	// Trim history if it exceeds the limit
	if len(a.alertHistory) > a.config.AlertHistoryLimit {
		a.alertHistory = a.alertHistory[len(a.alertHistory)-a.config.AlertHistoryLimit:]
	}
}

// getLastNotificationTime gets the last notification time for an alert
func (a *AlertingSystem) getLastNotificationTime(alert *Alert) time.Time {
	var lastTime time.Time
	for _, notification := range alert.NotificationsSent {
		if notification.Timestamp.After(lastTime) {
			lastTime = notification.Timestamp
		}
	}
	return lastTime
}

// Stop stops the alerting system
func (a *AlertingSystem) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	
	if a.processingTicker != nil {
		a.processingTicker.Stop()
	}
	
	a.logger.Info("Alerting system stopped")
}