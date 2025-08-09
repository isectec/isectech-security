package stream_processing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"github.com/segmentio/kafka-go"
	"github.com/google/uuid"
)

// StreamProcessorManager orchestrates all stream processing operations for iSECTECH
type StreamProcessorManager struct {
	logger    *zap.Logger
	config    *StreamProcessingConfig
	
	// Core processors
	enrichmentService   *EventEnrichmentService
	correlationEngine   *EventCorrelationEngine
	patternMatcher      *PatternMatchingEngine
	anomalyDetector     *AnomalyDetectionIntegration
	
	// Kafka integration
	kafkaStreams        *KafkaStreamsProcessor
	
	// State management
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	isRunning           bool
	mu                  sync.RWMutex
	
	// Metrics and monitoring
	metrics             *StreamProcessingMetrics
	healthChecker       *HealthChecker
}

// StreamProcessingConfig defines configuration for stream processing
type StreamProcessingConfig struct {
	// Kafka configuration
	KafkaBrokers          []string          `json:"kafka_brokers"`
	InputTopics           []string          `json:"input_topics"`
	OutputTopics          map[string]string `json:"output_topics"` // processing_stage -> topic
	ConsumerGroupID       string            `json:"consumer_group_id"`
	
	// Processing configuration
	EnableEnrichment      bool              `json:"enable_enrichment"`
	EnableCorrelation     bool              `json:"enable_correlation"`
	EnablePatternMatching bool              `json:"enable_pattern_matching"`
	EnableAnomalyDetection bool             `json:"enable_anomaly_detection"`
	
	// Performance settings
	WorkerPoolSize        int               `json:"worker_pool_size"`
	ProcessingTimeout     time.Duration     `json:"processing_timeout"`
	MaxProcessingRetries  int               `json:"max_processing_retries"`
	BufferSize            int               `json:"buffer_size"`
	
	// Context data sources
	ThreatIntelSources    []TISourceConfig  `json:"threat_intel_sources"`
	AssetInventoryURL     string            `json:"asset_inventory_url"`
	UserBehaviorServiceURL string           `json:"user_behavior_service_url"`
	GeolocationServiceURL string            `json:"geolocation_service_url"`
	
	// Pattern matching
	PatternRulesPath      string            `json:"pattern_rules_path"`
	CustomRulesPath       string            `json:"custom_rules_path"`
	RuleUpdateInterval    time.Duration     `json:"rule_update_interval"`
	
	// Correlation settings
	CorrelationWindowSize time.Duration     `json:"correlation_window_size"`
	MaxCorrelationDepth   int               `json:"max_correlation_depth"`
	SessionTimeoutWindow  time.Duration     `json:"session_timeout_window"`
	
	// Monitoring and health
	MetricsEnabled        bool              `json:"metrics_enabled"`
	HealthCheckInterval   time.Duration     `json:"health_check_interval"`
	AlertingEnabled       bool              `json:"alerting_enabled"`
}

// TISourceConfig defines threat intelligence source configuration
type TISourceConfig struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	APIKey   string `json:"api_key"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
}

// ProcessingContext contains context for event processing
type ProcessingContext struct {
	EventID       string                 `json:"event_id"`
	TenantID      string                 `json:"tenant_id"`
	CorrelationID string                 `json:"correlation_id"`
	TraceID       string                 `json:"trace_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ProcessingResult represents the result of stream processing
type ProcessingResult struct {
	ProcessedEvent    map[string]interface{} `json:"processed_event"`
	EnrichmentData    map[string]interface{} `json:"enrichment_data"`
	CorrelatedEvents  []string               `json:"correlated_events"`
	MatchedPatterns   []PatternMatch         `json:"matched_patterns"`
	AnomalyScore      float64                `json:"anomaly_score"`
	ProcessingSteps   []ProcessingStep       `json:"processing_steps"`
	Alerts            []Alert                `json:"alerts"`
	Errors            []ProcessingError      `json:"errors"`
	ProcessingTime    time.Duration          `json:"processing_time"`
	Success           bool                   `json:"success"`
}

// ProcessingStep represents a single processing step
type ProcessingStep struct {
	Name      string                 `json:"name"`
	Status    string                 `json:"status"` // success, failed, skipped
	Duration  time.Duration          `json:"duration"`
	Input     map[string]interface{} `json:"input,omitempty"`
	Output    map[string]interface{} `json:"output,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// PatternMatch represents a matched threat pattern
type PatternMatch struct {
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Alert represents a generated security alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ProcessingError represents an error during processing
type ProcessingError struct {
	Stage     string    `json:"stage"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
	Retryable bool      `json:"retryable"`
}

// NewStreamProcessorManager creates a new stream processor manager
func NewStreamProcessorManager(logger *zap.Logger, config *StreamProcessingConfig) (*StreamProcessorManager, error) {
	if config == nil {
		return nil, fmt.Errorf("stream processing configuration is required")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &StreamProcessorManager{
		logger: logger.With(zap.String("component", "stream-processor-manager")),
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize metrics
	if config.MetricsEnabled {
		manager.metrics = NewStreamProcessingMetrics(logger)
	}
	
	// Initialize health checker
	manager.healthChecker = NewHealthChecker(logger, config.HealthCheckInterval)
	
	return manager, nil
}

// Initialize initializes all stream processing components
func (m *StreamProcessorManager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.isRunning {
		return fmt.Errorf("stream processor manager is already running")
	}
	
	m.logger.Info("Initializing stream processor manager...")
	
	// Initialize enrichment service
	if m.config.EnableEnrichment {
		enrichmentConfig := &EnrichmentServiceConfig{
			ThreatIntelSources:     m.config.ThreatIntelSources,
			AssetInventoryURL:      m.config.AssetInventoryURL,
			UserBehaviorServiceURL: m.config.UserBehaviorServiceURL,
			GeolocationServiceURL:  m.config.GeolocationServiceURL,
		}
		
		var err error
		m.enrichmentService, err = NewEventEnrichmentService(m.logger, enrichmentConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize enrichment service: %w", err)
		}
	}
	
	// Initialize correlation engine
	if m.config.EnableCorrelation {
		correlationConfig := &CorrelationEngineConfig{
			WindowSize:           m.config.CorrelationWindowSize,
			MaxDepth:             m.config.MaxCorrelationDepth,
			SessionTimeoutWindow: m.config.SessionTimeoutWindow,
		}
		
		var err error
		m.correlationEngine, err = NewEventCorrelationEngine(m.logger, correlationConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize correlation engine: %w", err)
		}
	}
	
	// Initialize pattern matcher
	if m.config.EnablePatternMatching {
		patternConfig := &PatternMatchingConfig{
			RulesPath:        m.config.PatternRulesPath,
			CustomRulesPath:  m.config.CustomRulesPath,
			UpdateInterval:   m.config.RuleUpdateInterval,
		}
		
		var err error
		m.patternMatcher, err = NewPatternMatchingEngine(m.logger, patternConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize pattern matcher: %w", err)
		}
	}
	
	// Initialize anomaly detector
	if m.config.EnableAnomalyDetection {
		anomalyConfig := &AnomalyDetectionConfig{
			UserBehaviorServiceURL: m.config.UserBehaviorServiceURL,
		}
		
		var err error
		m.anomalyDetector, err = NewAnomalyDetectionIntegration(m.logger, anomalyConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize anomaly detector: %w", err)
		}
	}
	
	// Initialize Kafka Streams processor
	kafkaConfig := &KafkaStreamsConfig{
		Brokers:         m.config.KafkaBrokers,
		InputTopics:     m.config.InputTopics,
		OutputTopics:    m.config.OutputTopics,
		ConsumerGroupID: m.config.ConsumerGroupID,
		WorkerPoolSize:  m.config.WorkerPoolSize,
		BufferSize:      m.config.BufferSize,
	}
	
	var err error
	m.kafkaStreams, err = NewKafkaStreamsProcessor(m.logger, kafkaConfig, m)
	if err != nil {
		return fmt.Errorf("failed to initialize Kafka streams processor: %w", err)
	}
	
	m.logger.Info("Stream processor manager initialized successfully",
		zap.Bool("enrichment_enabled", m.config.EnableEnrichment),
		zap.Bool("correlation_enabled", m.config.EnableCorrelation),
		zap.Bool("pattern_matching_enabled", m.config.EnablePatternMatching),
		zap.Bool("anomaly_detection_enabled", m.config.EnableAnomalyDetection),
	)
	
	return nil
}

// Start starts the stream processing manager
func (m *StreamProcessorManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.isRunning {
		return fmt.Errorf("stream processor manager is already running")
	}
	
	m.logger.Info("Starting stream processor manager...")
	
	// Start health checker
	m.wg.Add(1)
	go m.runHealthChecker()
	
	// Start metrics reporter if enabled
	if m.config.MetricsEnabled && m.metrics != nil {
		m.wg.Add(1)
		go m.runMetricsReporter()
	}
	
	// Start Kafka streams processor
	if err := m.kafkaStreams.Start(m.ctx); err != nil {
		return fmt.Errorf("failed to start Kafka streams processor: %w", err)
	}
	
	m.isRunning = true
	
	m.logger.Info("Stream processor manager started successfully")
	return nil
}

// Stop stops the stream processing manager
func (m *StreamProcessorManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.isRunning {
		return nil
	}
	
	m.logger.Info("Stopping stream processor manager...")
	
	// Cancel context to signal all goroutines to stop
	m.cancel()
	
	// Stop Kafka streams processor
	if m.kafkaStreams != nil {
		if err := m.kafkaStreams.Stop(); err != nil {
			m.logger.Error("Failed to stop Kafka streams processor", zap.Error(err))
		}
	}
	
	// Wait for all goroutines to finish
	m.wg.Wait()
	
	m.isRunning = false
	
	m.logger.Info("Stream processor manager stopped successfully")
	return nil
}

// ProcessEvent processes a single event through the stream processing pipeline
func (m *StreamProcessorManager) ProcessEvent(ctx context.Context, event map[string]interface{}) (*ProcessingResult, error) {
	start := time.Now()
	
	// Create processing context
	processingCtx := &ProcessingContext{
		EventID:       extractStringField(event, "id", uuid.New().String()),
		TenantID:      extractStringField(event, "tenant_id", ""),
		CorrelationID: extractStringField(event, "correlation_id", uuid.New().String()),
		TraceID:       extractStringField(event, "trace_id", ""),
		Timestamp:     time.Now(),
		Metadata:      make(map[string]interface{}),
	}
	
	// Initialize processing result
	result := &ProcessingResult{
		ProcessedEvent:   make(map[string]interface{}),
		EnrichmentData:   make(map[string]interface{}),
		CorrelatedEvents: []string{},
		MatchedPatterns:  []PatternMatch{},
		ProcessingSteps:  []ProcessingStep{},
		Alerts:          []Alert{},
		Errors:          []ProcessingError{},
		Success:         true,
	}
	
	// Copy original event
	for k, v := range event {
		result.ProcessedEvent[k] = v
	}
	
	// Process through pipeline stages
	m.processEnrichmentStage(ctx, processingCtx, result)
	m.processCorrelationStage(ctx, processingCtx, result)
	m.processPatternMatchingStage(ctx, processingCtx, result)
	m.processAnomalyDetectionStage(ctx, processingCtx, result)
	m.processAlertGeneration(ctx, processingCtx, result)
	
	// Calculate processing time
	result.ProcessingTime = time.Since(start)
	
	// Update metrics
	if m.metrics != nil {
		m.metrics.RecordEventProcessed(result.ProcessingTime, result.Success)
		if len(result.Alerts) > 0 {
			m.metrics.RecordAlertGenerated(len(result.Alerts))
		}
	}
	
	m.logger.Debug("Event processed",
		zap.String("event_id", processingCtx.EventID),
		zap.Duration("processing_time", result.ProcessingTime),
		zap.Bool("success", result.Success),
		zap.Int("alerts_generated", len(result.Alerts)),
		zap.Int("patterns_matched", len(result.MatchedPatterns)),
	)
	
	return result, nil
}

// GetStatus returns the current status of the stream processor manager
func (m *StreamProcessorManager) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	status := map[string]interface{}{
		"running": m.isRunning,
		"health":  "unknown",
	}
	
	if m.healthChecker != nil {
		status["health"] = m.healthChecker.GetOverallHealth()
	}
	
	if m.metrics != nil {
		status["metrics"] = m.metrics.GetCurrentMetrics()
	}
	
	return status
}

// Helper method to extract string field with default
func extractStringField(data map[string]interface{}, field, defaultValue string) string {
	if value, exists := data[field]; exists {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return defaultValue
}

// runHealthChecker runs the health checker in a separate goroutine
func (m *StreamProcessorManager) runHealthChecker() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performHealthCheck()
		}
	}
}

// runMetricsReporter runs the metrics reporter in a separate goroutine
func (m *StreamProcessorManager) runMetricsReporter() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if m.metrics != nil {
				m.metrics.ReportMetrics()
			}
		}
	}
}

// performHealthCheck performs a comprehensive health check
func (m *StreamProcessorManager) performHealthCheck() {
	// Check Kafka connectivity
	if m.kafkaStreams != nil {
		m.healthChecker.CheckComponent("kafka_streams", m.kafkaStreams.IsHealthy())
	}
	
	// Check individual processors
	if m.enrichmentService != nil {
		m.healthChecker.CheckComponent("enrichment_service", m.enrichmentService.IsHealthy())
	}
	
	if m.correlationEngine != nil {
		m.healthChecker.CheckComponent("correlation_engine", m.correlationEngine.IsHealthy())
	}
	
	if m.patternMatcher != nil {
		m.healthChecker.CheckComponent("pattern_matcher", m.patternMatcher.IsHealthy())
	}
	
	if m.anomalyDetector != nil {
		m.healthChecker.CheckComponent("anomaly_detector", m.anomalyDetector.IsHealthy())
	}
}