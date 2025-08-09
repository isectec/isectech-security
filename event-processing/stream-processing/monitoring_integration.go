package stream_processing

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// MonitoringIntegration integrates all monitoring components
type MonitoringIntegration struct {
	logger           *zap.Logger
	config           *MonitoringConfig
	
	// Monitoring components
	metricsCollector *MetricsCollector
	healthMonitor    *HealthMonitor
	alertingSystem   *AlertingSystem
	
	// Integration state
	isInitialized    bool
	ctx              context.Context
	cancel           context.CancelFunc
}

// MonitoringConfig defines configuration for monitoring integration
type MonitoringConfig struct {
	Metrics  *MetricsConfig  `yaml:"metrics"`
	Health   *HealthConfig   `yaml:"health"`
	Alerting *AlertingConfig `yaml:"alerting"`
}

// NewMonitoringIntegration creates a new monitoring integration
func NewMonitoringIntegration(logger *zap.Logger, config *MonitoringConfig) (*MonitoringIntegration, error) {
	if config == nil {
		return nil, fmt.Errorf("monitoring configuration is required")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	integration := &MonitoringIntegration{
		logger: logger.With(zap.String("component", "monitoring-integration")),
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize components
	if err := integration.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize monitoring components: %w", err)
	}
	
	integration.isInitialized = true
	
	logger.Info("Monitoring integration initialized",
		zap.Bool("metrics_enabled", config.Metrics != nil && config.Metrics.Enabled),
		zap.Bool("health_enabled", config.Health != nil && config.Health.Enabled),
		zap.Bool("alerting_enabled", config.Alerting != nil && config.Alerting.Enabled),
	)
	
	return integration, nil
}

// initializeComponents initializes all monitoring components
func (m *MonitoringIntegration) initializeComponents() error {
	// Initialize metrics collector
	if m.config.Metrics != nil && m.config.Metrics.Enabled {
		metricsCollector, err := NewMetricsCollector(m.logger, m.config.Metrics)
		if err != nil {
			return fmt.Errorf("failed to initialize metrics collector: %w", err)
		}
		m.metricsCollector = metricsCollector
	}
	
	// Initialize health monitor
	if m.config.Health != nil && m.config.Health.Enabled {
		healthMonitor, err := NewHealthMonitor(m.logger, m.config.Health, m.metricsCollector)
		if err != nil {
			return fmt.Errorf("failed to initialize health monitor: %w", err)
		}
		m.healthMonitor = healthMonitor
	}
	
	// Initialize alerting system
	if m.config.Alerting != nil && m.config.Alerting.Enabled {
		alertingSystem, err := NewAlertingSystem(m.logger, m.config.Alerting, m.metricsCollector, m.healthMonitor)
		if err != nil {
			return fmt.Errorf("failed to initialize alerting system: %w", err)
		}
		m.alertingSystem = alertingSystem
	}
	
	return nil
}

// GetMetricsCollector returns the metrics collector
func (m *MonitoringIntegration) GetMetricsCollector() *MetricsCollector {
	return m.metricsCollector
}

// GetHealthMonitor returns the health monitor
func (m *MonitoringIntegration) GetHealthMonitor() *HealthMonitor {
	return m.healthMonitor
}

// GetAlertingSystem returns the alerting system
func (m *MonitoringIntegration) GetAlertingSystem() *AlertingSystem {
	return m.alertingSystem
}

// RegisterStreamProcessorHealthChecker registers health checker for stream processor
func (m *MonitoringIntegration) RegisterStreamProcessorHealthChecker(processor *StreamProcessorManager) {
	if m.healthMonitor == nil {
		return
	}
	
	healthChecker := &StreamProcessorHealthChecker{
		processor: processor,
		logger:    m.logger,
	}
	
	m.healthMonitor.RegisterHealthChecker(healthChecker)
}

// RegisterKafkaHealthChecker registers health checker for Kafka
func (m *MonitoringIntegration) RegisterKafkaHealthChecker(kafkaProcessor *KafkaStreamsProcessor) {
	if m.healthMonitor == nil {
		return
	}
	
	healthChecker := &KafkaHealthChecker{
		processor: kafkaProcessor,
		logger:    m.logger,
	}
	
	m.healthMonitor.RegisterHealthChecker(healthChecker)
}

// RegisterEnrichmentHealthChecker registers health checker for enrichment service
func (m *MonitoringIntegration) RegisterEnrichmentHealthChecker(enrichmentService *EventEnrichmentService) {
	if m.healthMonitor == nil {
		return
	}
	
	healthChecker := &EnrichmentHealthChecker{
		service: enrichmentService,
		logger:  m.logger,
	}
	
	m.healthMonitor.RegisterHealthChecker(healthChecker)
}

// MonitorProcessingPipeline monitors the processing pipeline performance
func (m *MonitoringIntegration) MonitorProcessingPipeline(stage string, eventType string, duration time.Duration, success bool) {
	if m.metricsCollector == nil {
		return
	}
	
	status := "success"
	if !success {
		status = "error"
	}
	
	// Record metrics
	m.metricsCollector.RecordEventProcessed(eventType, status, "pipeline")
	m.metricsCollector.RecordProcessingDuration(stage, eventType, duration)
	
	// Check for performance alerts
	if m.alertingSystem != nil {
		m.checkPerformanceThresholds(stage, eventType, duration)
	}
}

// MonitorEnrichmentOperation monitors enrichment operations
func (m *MonitoringIntegration) MonitorEnrichmentOperation(source string, duration time.Duration, success bool, cacheHit bool) {
	if m.metricsCollector == nil {
		return
	}
	
	status := "success"
	if !success {
		status = "error"
	}
	
	m.metricsCollector.RecordEnrichmentMetrics(source, status, duration, cacheHit)
	
	// Check for enrichment alerts
	if m.alertingSystem != nil && !success {
		m.alertingSystem.CreatePerformanceAlert(
			"enrichment-service",
			"enrichment_failure_rate",
			1.0,
			0.05,
			fmt.Sprintf("Enrichment failed for source: %s", source),
		)
	}
}

// MonitorCorrelationOperation monitors correlation operations
func (m *MonitoringIntegration) MonitorCorrelationOperation(correlationType string, duration time.Duration, success bool) {
	if m.metricsCollector == nil {
		return
	}
	
	status := "success"
	if !success {
		status = "error"
	}
	
	m.metricsCollector.RecordCorrelationMetrics(correlationType, status, duration)
}

// MonitorPatternMatching monitors pattern matching operations
func (m *MonitoringIntegration) MonitorPatternMatching(patternType string, severity string, duration time.Duration) {
	if m.metricsCollector == nil {
		return
	}
	
	m.metricsCollector.RecordPatternMatchMetrics(patternType, severity, duration)
	
	// Create security alerts for high-severity patterns
	if m.alertingSystem != nil && (severity == "high" || severity == "critical") {
		m.alertingSystem.CreateSecurityAlert(
			"pattern-matching-engine",
			patternType,
			AlertSeverityWarning,
			fmt.Sprintf("High-severity pattern matched: %s", patternType),
			map[string]interface{}{
				"pattern_type": patternType,
				"severity":     severity,
				"duration":     duration.String(),
			},
		)
	}
}

// MonitorAnomalyDetection monitors anomaly detection operations
func (m *MonitoringIntegration) MonitorAnomalyDetection(anomalyType string, confidenceLevel string, duration time.Duration, anomalyScore float64) {
	if m.metricsCollector == nil {
		return
	}
	
	m.metricsCollector.RecordAnomalyDetectionMetrics(anomalyType, confidenceLevel, duration)
	
	// Create alerts for high-confidence anomalies
	if m.alertingSystem != nil && anomalyScore > 0.8 {
		severity := AlertSeverityWarning
		if anomalyScore > 0.9 {
			severity = AlertSeverityError
		}
		
		m.alertingSystem.CreateSecurityAlert(
			"anomaly-detection-integration",
			anomalyType,
			severity,
			fmt.Sprintf("High-confidence anomaly detected: %s (score: %.2f)", anomalyType, anomalyScore),
			map[string]interface{}{
				"anomaly_type":     anomalyType,
				"confidence_level": confidenceLevel,
				"anomaly_score":    anomalyScore,
				"duration":         duration.String(),
			},
		)
	}
}

// checkPerformanceThresholds checks performance thresholds and creates alerts
func (m *MonitoringIntegration) checkPerformanceThresholds(stage string, eventType string, duration time.Duration) {
	if m.config.Metrics == nil {
		return
	}
	
	// Check latency threshold
	if duration > m.config.Metrics.MaxProcessingLatency {
		m.alertingSystem.CreatePerformanceAlert(
			fmt.Sprintf("%s-stage", stage),
			"processing_latency",
			duration.Seconds(),
			m.config.Metrics.MaxProcessingLatency.Seconds(),
			fmt.Sprintf("High processing latency detected in %s stage for %s events", stage, eventType),
		)
	}
}

// UpdateThroughputMetrics updates throughput metrics
func (m *MonitoringIntegration) UpdateThroughputMetrics(component string, throughput float64) {
	if m.metricsCollector == nil {
		return
	}
	
	m.metricsCollector.throughputGauge.WithLabelValues(component).Set(throughput)
	
	// Check throughput alerts
	if m.alertingSystem != nil && m.config.Metrics != nil && throughput < m.config.Metrics.MinThroughput {
		m.alertingSystem.CreatePerformanceAlert(
			component,
			"throughput",
			throughput,
			m.config.Metrics.MinThroughput,
			fmt.Sprintf("Low throughput detected in %s: %.2f events/sec", component, throughput),
		)
	}
}

// UpdateKafkaLagMetrics updates Kafka lag metrics
func (m *MonitoringIntegration) UpdateKafkaLagMetrics(topic string, partition string, consumerGroup string, lag int64) {
	if m.metricsCollector == nil {
		return
	}
	
	m.metricsCollector.UpdateKafkaLag(topic, partition, consumerGroup, lag)
	
	// Check Kafka lag alerts
	if m.alertingSystem != nil && m.config.Metrics != nil && lag > m.config.Metrics.MaxKafkaLag {
		m.alertingSystem.CreateInfrastructureAlert(
			"kafka-consumer",
			"high_consumer_lag",
			AlertSeverityWarning,
			fmt.Sprintf("High Kafka consumer lag detected: %d messages on topic %s, partition %s", lag, topic, partition),
		)
	}
}

// IsHealthy returns the overall health status
func (m *MonitoringIntegration) IsHealthy() bool {
	if m.healthMonitor == nil {
		return true // No health monitoring configured
	}
	
	return m.healthMonitor.IsHealthy()
}

// Stop stops all monitoring components
func (m *MonitoringIntegration) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	
	if m.metricsCollector != nil {
		m.metricsCollector.Stop()
	}
	
	if m.healthMonitor != nil {
		m.healthMonitor.Stop()
	}
	
	if m.alertingSystem != nil {
		m.alertingSystem.Stop()
	}
	
	m.logger.Info("Monitoring integration stopped")
}

// Health checker implementations

// StreamProcessorHealthChecker checks stream processor health
type StreamProcessorHealthChecker struct {
	processor *StreamProcessorManager
	logger    *zap.Logger
}

func (s *StreamProcessorHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealthStatus, error) {
	if s.processor == nil {
		return &ComponentHealthStatus{
			Name:   "stream-processor-manager",
			Status: HealthStatusUnhealthy,
		}, fmt.Errorf("stream processor is not initialized")
	}
	
	// Check if processor is healthy
	if s.processor.IsHealthy() {
		return &ComponentHealthStatus{
			Name:   "stream-processor-manager",
			Status: HealthStatusHealthy,
			Details: map[string]interface{}{
				"status": "running",
			},
		}, nil
	}
	
	return &ComponentHealthStatus{
		Name:   "stream-processor-manager",
		Status: HealthStatusUnhealthy,
	}, fmt.Errorf("stream processor is unhealthy")
}

func (s *StreamProcessorHealthChecker) GetComponentName() string {
	return "stream-processor-manager"
}

// KafkaHealthChecker checks Kafka connectivity health
type KafkaHealthChecker struct {
	processor *KafkaStreamsProcessor
	logger    *zap.Logger
}

func (k *KafkaHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealthStatus, error) {
	if k.processor == nil {
		return &ComponentHealthStatus{
			Name:   "kafka-streams-processor",
			Status: HealthStatusUnhealthy,
		}, fmt.Errorf("kafka processor is not initialized")
	}
	
	// Check Kafka connectivity
	if k.processor.IsHealthy() {
		return &ComponentHealthStatus{
			Name:   "kafka-streams-processor",
			Status: HealthStatusHealthy,
			Details: map[string]interface{}{
				"connected": true,
			},
		}, nil
	}
	
	return &ComponentHealthStatus{
		Name:   "kafka-streams-processor",
		Status: HealthStatusUnhealthy,
	}, fmt.Errorf("kafka processor is unhealthy")
}

func (k *KafkaHealthChecker) GetComponentName() string {
	return "kafka-streams-processor"
}

// EnrichmentHealthChecker checks enrichment service health
type EnrichmentHealthChecker struct {
	service *EventEnrichmentService
	logger  *zap.Logger
}

func (e *EnrichmentHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealthStatus, error) {
	if e.service == nil {
		return &ComponentHealthStatus{
			Name:   "enrichment-service",
			Status: HealthStatusUnhealthy,
		}, fmt.Errorf("enrichment service is not initialized")
	}
	
	// Check enrichment service health
	if e.service.IsHealthy() {
		return &ComponentHealthStatus{
			Name:   "enrichment-service",
			Status: HealthStatusHealthy,
			Details: map[string]interface{}{
				"cache_size": "healthy",
			},
		}, nil
	}
	
	return &ComponentHealthStatus{
		Name:   "enrichment-service",
		Status: HealthStatusUnhealthy,
	}, fmt.Errorf("enrichment service is unhealthy")
}

func (e *EnrichmentHealthChecker) GetComponentName() string {
	return "enrichment-service"
}