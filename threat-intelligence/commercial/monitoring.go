package commercial

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FeedHealthChecker monitors health of commercial feeds
type FeedHealthChecker struct {
	logger         *zap.Logger
	config         *CommercialFeedsConfig
	
	// Health tracking
	feedHealth     map[string]*FeedHealthStatus
	healthMutex    sync.RWMutex
	
	// Monitoring
	healthTicker   *time.Ticker
	alertManager   *AlertManager
	
	// Operational state
	ctx           context.Context
	cancel        context.CancelFunc
}

// AlertManager handles alerts for feed health issues
type AlertManager struct {
	logger           *zap.Logger
	config           *CommercialFeedsConfig
	
	// Alert channels
	emailNotifier    *EmailNotifier
	slackNotifier    *SlackNotifier
	webhookNotifier  *WebhookNotifier
	
	// Alert state
	activeAlerts     map[string]*Alert
	alertMutex       sync.RWMutex
	
	// Alert rules
	alertRules       map[string]*AlertRule
}

type Alert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Provider    string                 `json:"provider"`
	Timestamp   time.Time              `json:"timestamp"`
	Status      string                 `json:"status"`
	Context     map[string]interface{} `json:"context"`
}

type AlertRule struct {
	Name        string        `json:"name"`
	Condition   string        `json:"condition"`
	Threshold   interface{}   `json:"threshold"`
	Severity    string        `json:"severity"`
	Cooldown    time.Duration `json:"cooldown"`
	Enabled     bool          `json:"enabled"`
}

// Notification interfaces
type EmailNotifier struct {
	SMTPServer   string   `json:"smtp_server"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	FromAddress  string   `json:"from_address"`
	ToAddresses  []string `json:"to_addresses"`
	TLSEnabled   bool     `json:"tls_enabled"`
}

type SlackNotifier struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
	IconEmoji  string `json:"icon_emoji"`
}

type WebhookNotifier struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Timeout time.Duration     `json:"timeout"`
}

// CommercialFeedsMetrics collects metrics for commercial feeds
type CommercialFeedsMetrics struct {
	logger         *zap.Logger
	
	// Metrics tracking
	feedLatency         map[string]time.Duration
	indicatorThroughput map[string]int64
	errorRates          map[string]float64
	dataQualityScores   map[string]float64
	apiRequestCounts    map[string]int64
	
	// Time series data
	metricHistory       map[string][]MetricDataPoint
	historyMutex        sync.RWMutex
	
	// Prometheus integration
	prometheusEnabled   bool
	metricsRegistry     interface{}
	
	// Collection settings
	collectionInterval  time.Duration
	retentionPeriod     time.Duration
}

type MetricDataPoint struct {
	Timestamp time.Time   `json:"timestamp"`
	Value     interface{} `json:"value"`
	Labels    map[string]string `json:"labels"`
}

// NewFeedHealthChecker creates a new feed health checker
func NewFeedHealthChecker(logger *zap.Logger, config *CommercialFeedsConfig) (*FeedHealthChecker, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	checker := &FeedHealthChecker{
		logger:       logger.With(zap.String("component", "feed-health-checker")),
		config:       config,
		feedHealth:   make(map[string]*FeedHealthStatus),
		healthTicker: time.NewTicker(30 * time.Second), // Health check every 30 seconds
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Initialize alert manager
	var err error
	checker.alertManager, err = NewAlertManager(logger, config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize alert manager: %w", err)
	}
	
	logger.Info("Feed health checker initialized")
	return checker, nil
}

func (fhc *FeedHealthChecker) StartMonitoring(ctx context.Context) {
	fhc.logger.Info("Starting feed health monitoring")
	
	go func() {
		for {
			select {
			case <-ctx.Done():
				fhc.logger.Info("Feed health monitoring stopped")
				return
			case <-fhc.healthTicker.C:
				fhc.performHealthChecks()
			}
		}
	}()
}

func (fhc *FeedHealthChecker) performHealthChecks() {
	fhc.logger.Debug("Performing feed health checks")
	
	providers := []string{"recorded_future", "digital_shadows", "crowdstrike", "fireeye"}
	
	for _, provider := range providers {
		health := fhc.checkProviderHealth(provider)
		
		fhc.healthMutex.Lock()
		fhc.feedHealth[provider] = health
		fhc.healthMutex.Unlock()
		
		// Check for alert conditions
		fhc.evaluateHealthAlerts(provider, health)
	}
}

func (fhc *FeedHealthChecker) checkProviderHealth(provider string) *FeedHealthStatus {
	health := &FeedHealthStatus{
		Provider:  provider,
		LastCheck: time.Now(),
		IsHealthy: true,
	}
	
	// In a real implementation, this would perform actual health checks
	// For now, we'll simulate health status
	
	// Simulate some health metrics
	health.ResponseTime = time.Duration(100+provider[0]) * time.Millisecond
	health.ErrorRate = 0.05 // 5% error rate
	health.DataFreshness = time.Duration(provider[0]) * time.Minute
	
	// Determine overall health
	if health.ResponseTime > 5*time.Second {
		health.IsHealthy = false
	}
	if health.ErrorRate > 0.1 { // 10% error threshold
		health.IsHealthy = false
	}
	if health.DataFreshness > 2*time.Hour {
		health.IsHealthy = false
	}
	
	return health
}

func (fhc *FeedHealthChecker) evaluateHealthAlerts(provider string, health *FeedHealthStatus) {
	// Check for high error rate
	if health.ErrorRate > 0.1 {
		alert := &Alert{
			ID:          fmt.Sprintf("high-error-rate-%s-%d", provider, time.Now().Unix()),
			Type:        "feed_health",
			Severity:    "warning",
			Title:       fmt.Sprintf("High Error Rate for %s", provider),
			Description: fmt.Sprintf("Error rate is %.2f%% which exceeds the threshold", health.ErrorRate*100),
			Provider:    provider,
			Timestamp:   time.Now(),
			Status:      "active",
			Context: map[string]interface{}{
				"error_rate":     health.ErrorRate,
				"threshold":      0.1,
				"response_time":  health.ResponseTime,
				"data_freshness": health.DataFreshness,
			},
		}
		
		fhc.alertManager.TriggerAlert(alert)
	}
	
	// Check for high response time
	if health.ResponseTime > 5*time.Second {
		alert := &Alert{
			ID:          fmt.Sprintf("high-latency-%s-%d", provider, time.Now().Unix()),
			Type:        "feed_health",
			Severity:    "warning",
			Title:       fmt.Sprintf("High Latency for %s", provider),
			Description: fmt.Sprintf("Response time is %v which exceeds the threshold", health.ResponseTime),
			Provider:    provider,
			Timestamp:   time.Now(),
			Status:      "active",
			Context: map[string]interface{}{
				"response_time": health.ResponseTime,
				"threshold":     5 * time.Second,
				"error_rate":    health.ErrorRate,
			},
		}
		
		fhc.alertManager.TriggerAlert(alert)
	}
}

func (fhc *FeedHealthChecker) GetProviderHealth(provider string) (*FeedHealthStatus, bool) {
	fhc.healthMutex.RLock()
	defer fhc.healthMutex.RUnlock()
	
	health, exists := fhc.feedHealth[provider]
	return health, exists
}

func (fhc *FeedHealthChecker) GetAllProviderHealth() map[string]*FeedHealthStatus {
	fhc.healthMutex.RLock()
	defer fhc.healthMutex.RUnlock()
	
	result := make(map[string]*FeedHealthStatus)
	for provider, health := range fhc.feedHealth {
		result[provider] = health
	}
	
	return result
}

func (fhc *FeedHealthChecker) Close() error {
	fhc.logger.Info("Closing feed health checker")
	
	if fhc.healthTicker != nil {
		fhc.healthTicker.Stop()
	}
	
	if fhc.cancel != nil {
		fhc.cancel()
	}
	
	if fhc.alertManager != nil {
		fhc.alertManager.Close()
	}
	
	return nil
}

// NewAlertManager creates a new alert manager
func NewAlertManager(logger *zap.Logger, config *CommercialFeedsConfig) (*AlertManager, error) {
	manager := &AlertManager{
		logger:       logger.With(zap.String("component", "alert-manager")),
		config:       config,
		activeAlerts: make(map[string]*Alert),
		alertRules:   make(map[string]*AlertRule),
	}
	
	// Initialize default alert rules
	manager.initializeAlertRules()
	
	// Initialize notifiers (simplified implementation)
	manager.emailNotifier = &EmailNotifier{
		SMTPServer:  "smtp.gmail.com",
		SMTPPort:    587,
		TLSEnabled:  true,
		FromAddress: "alerts@isectech.com",
		ToAddresses: []string{"security-team@isectech.com"},
	}
	
	manager.slackNotifier = &SlackNotifier{
		Channel:   "#threat-intel-alerts",
		Username:  "ThreatIntel Bot",
		IconEmoji: ":warning:",
	}
	
	manager.webhookNotifier = &WebhookNotifier{
		Method:  "POST",
		Timeout: 10 * time.Second,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
	
	logger.Info("Alert manager initialized")
	return manager, nil
}

func (am *AlertManager) initializeAlertRules() {
	am.alertRules["high_error_rate"] = &AlertRule{
		Name:      "High Error Rate",
		Condition: "error_rate > threshold",
		Threshold: 0.1, // 10%
		Severity:  "warning",
		Cooldown:  15 * time.Minute,
		Enabled:   true,
	}
	
	am.alertRules["high_latency"] = &AlertRule{
		Name:      "High Response Latency",
		Condition: "response_time > threshold",
		Threshold: 5 * time.Second,
		Severity:  "warning",
		Cooldown:  10 * time.Minute,
		Enabled:   true,
	}
	
	am.alertRules["feed_down"] = &AlertRule{
		Name:      "Feed Unavailable",
		Condition: "consecutive_failures > threshold",
		Threshold: 3,
		Severity:  "critical",
		Cooldown:  5 * time.Minute,
		Enabled:   true,
	}
}

func (am *AlertManager) TriggerAlert(alert *Alert) {
	// Check if this alert is already active (deduplication)
	am.alertMutex.RLock()
	if existingAlert, exists := am.activeAlerts[alert.ID]; exists {
		am.alertMutex.RUnlock()
		am.logger.Debug("Alert already active, skipping",
			zap.String("alert_id", alert.ID),
			zap.Time("existing_timestamp", existingAlert.Timestamp),
		)
		return
	}
	am.alertMutex.RUnlock()
	
	// Add to active alerts
	am.alertMutex.Lock()
	am.activeAlerts[alert.ID] = alert
	am.alertMutex.Unlock()
	
	am.logger.Warn("Alert triggered",
		zap.String("alert_id", alert.ID),
		zap.String("type", alert.Type),
		zap.String("severity", alert.Severity),
		zap.String("provider", alert.Provider),
		zap.String("title", alert.Title),
	)
	
	// Send notifications
	go am.sendNotifications(alert)
}

func (am *AlertManager) sendNotifications(alert *Alert) {
	// Send email notification
	if am.emailNotifier != nil {
		am.sendEmailAlert(alert)
	}
	
	// Send Slack notification
	if am.slackNotifier != nil {
		am.sendSlackAlert(alert)
	}
	
	// Send webhook notification
	if am.webhookNotifier != nil && am.webhookNotifier.URL != "" {
		am.sendWebhookAlert(alert)
	}
}

func (am *AlertManager) sendEmailAlert(alert *Alert) {
	// Simplified email sending implementation
	am.logger.Info("Sending email alert",
		zap.String("alert_id", alert.ID),
		zap.Strings("recipients", am.emailNotifier.ToAddresses),
	)
	
	// In a real implementation, this would send actual emails
}

func (am *AlertManager) sendSlackAlert(alert *Alert) {
	// Simplified Slack notification implementation
	am.logger.Info("Sending Slack alert",
		zap.String("alert_id", alert.ID),
		zap.String("channel", am.slackNotifier.Channel),
	)
	
	// In a real implementation, this would send to Slack webhook
}

func (am *AlertManager) sendWebhookAlert(alert *Alert) {
	// Simplified webhook notification implementation
	am.logger.Info("Sending webhook alert",
		zap.String("alert_id", alert.ID),
		zap.String("url", am.webhookNotifier.URL),
	)
	
	// In a real implementation, this would send HTTP request to webhook
}

func (am *AlertManager) Close() error {
	am.logger.Info("Closing alert manager")
	
	// Clear active alerts
	am.alertMutex.Lock()
	am.activeAlerts = make(map[string]*Alert)
	am.alertMutex.Unlock()
	
	return nil
}

// NewCommercialFeedsMetrics creates a new metrics collector
func NewCommercialFeedsMetrics(logger *zap.Logger) (*CommercialFeedsMetrics, error) {
	metrics := &CommercialFeedsMetrics{
		logger:              logger.With(zap.String("component", "commercial-feeds-metrics")),
		feedLatency:         make(map[string]time.Duration),
		indicatorThroughput: make(map[string]int64),
		errorRates:          make(map[string]float64),
		dataQualityScores:   make(map[string]float64),
		apiRequestCounts:    make(map[string]int64),
		metricHistory:       make(map[string][]MetricDataPoint),
		collectionInterval:  1 * time.Minute,
		retentionPeriod:     24 * time.Hour,
		prometheusEnabled:   false, // Would be enabled with proper Prometheus setup
	}
	
	logger.Info("Commercial feeds metrics collector initialized")
	return metrics, nil
}

func (cfm *CommercialFeedsMetrics) RecordLatency(provider string, latency time.Duration) {
	cfm.feedLatency[provider] = latency
	
	// Add to history
	cfm.historyMutex.Lock()
	key := fmt.Sprintf("%s_latency", provider)
	cfm.metricHistory[key] = append(cfm.metricHistory[key], MetricDataPoint{
		Timestamp: time.Now(),
		Value:     latency,
		Labels:    map[string]string{"provider": provider, "metric": "latency"},
	})
	cfm.historyMutex.Unlock()
	
	cfm.logger.Debug("Recorded latency metric",
		zap.String("provider", provider),
		zap.Duration("latency", latency),
	)
}

func (cfm *CommercialFeedsMetrics) RecordThroughput(provider string, count int64) {
	cfm.indicatorThroughput[provider] = count
	
	// Add to history
	cfm.historyMutex.Lock()
	key := fmt.Sprintf("%s_throughput", provider)
	cfm.metricHistory[key] = append(cfm.metricHistory[key], MetricDataPoint{
		Timestamp: time.Now(),
		Value:     count,
		Labels:    map[string]string{"provider": provider, "metric": "throughput"},
	})
	cfm.historyMutex.Unlock()
	
	cfm.logger.Debug("Recorded throughput metric",
		zap.String("provider", provider),
		zap.Int64("count", count),
	)
}

func (cfm *CommercialFeedsMetrics) RecordErrorRate(provider string, rate float64) {
	cfm.errorRates[provider] = rate
	
	// Add to history
	cfm.historyMutex.Lock()
	key := fmt.Sprintf("%s_error_rate", provider)
	cfm.metricHistory[key] = append(cfm.metricHistory[key], MetricDataPoint{
		Timestamp: time.Now(),
		Value:     rate,
		Labels:    map[string]string{"provider": provider, "metric": "error_rate"},
	})
	cfm.historyMutex.Unlock()
	
	cfm.logger.Debug("Recorded error rate metric",
		zap.String("provider", provider),
		zap.Float64("rate", rate),
	)
}

func (cfm *CommercialFeedsMetrics) GetMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"latency":     cfm.feedLatency,
		"throughput":  cfm.indicatorThroughput,
		"error_rates": cfm.errorRates,
		"quality":     cfm.dataQualityScores,
		"api_calls":   cfm.apiRequestCounts,
	}
	
	return metrics
}

func (cfm *CommercialFeedsMetrics) GetMetricHistory(provider string, metric string) []MetricDataPoint {
	cfm.historyMutex.RLock()
	defer cfm.historyMutex.RUnlock()
	
	key := fmt.Sprintf("%s_%s", provider, metric)
	if history, exists := cfm.metricHistory[key]; exists {
		return history
	}
	
	return []MetricDataPoint{}
}