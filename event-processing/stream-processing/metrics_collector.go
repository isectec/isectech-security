package stream_processing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// MetricsCollector collects and exposes stream processing metrics
type MetricsCollector struct {
	logger *zap.Logger
	config *MetricsConfig
	
	// Prometheus metrics
	eventsProcessed        *prometheus.CounterVec
	eventsEnriched         *prometheus.CounterVec
	eventsCorrelated       *prometheus.CounterVec
	patternsMatched        *prometheus.CounterVec
	anomaliesDetected      *prometheus.CounterVec
	alertsGenerated        *prometheus.CounterVec
	
	processingDuration     *prometheus.HistogramVec
	enrichmentDuration     *prometheus.HistogramVec
	correlationDuration    *prometheus.HistogramVec
	patternMatchingDuration *prometheus.HistogramVec
	anomalyDetectionDuration *prometheus.HistogramVec
	
	kafkaLag               *prometheus.GaugeVec
	workerPoolUtilization  *prometheus.GaugeVec
	cacheHitRate           *prometheus.GaugeVec
	healthStatus           *prometheus.GaugeVec
	
	// Runtime metrics
	enrichmentCacheHits    *prometheus.CounterVec
	enrichmentCacheMisses  *prometheus.CounterVec
	correlationSessions    *prometheus.GaugeVec
	anomalyCache           *prometheus.GaugeVec
	
	// Error metrics
	processingErrors       *prometheus.CounterVec
	enrichmentErrors       *prometheus.CounterVec
	correlationErrors      *prometheus.CounterVec
	patternMatchingErrors  *prometheus.CounterVec
	anomalyDetectionErrors *prometheus.CounterVec
	
	// Performance metrics
	throughputGauge        *prometheus.GaugeVec
	latencyGauge          *prometheus.GaugeVec
	
	// Internal state
	mu                     sync.RWMutex
	registry              *prometheus.Registry
	lastThroughputUpdate  time.Time
	eventCount            int64
	isHealthy             bool
	
	// Background monitoring
	ctx                   context.Context
	cancel                context.CancelFunc
	updateTicker          *time.Ticker
}

// MetricsConfig defines configuration for metrics collection
type MetricsConfig struct {
	Enabled              bool          `json:"enabled"`
	PrometheusPort       int           `json:"prometheus_port"`
	UpdateInterval       time.Duration `json:"update_interval"`
	HistogramBuckets     []float64     `json:"histogram_buckets"`
	EnableDetailedMetrics bool         `json:"enable_detailed_metrics"`
	
	// Alert thresholds
	MaxProcessingLatency time.Duration `json:"max_processing_latency"`
	MinThroughput        float64       `json:"min_throughput"`
	MaxErrorRate         float64       `json:"max_error_rate"`
	MaxKafkaLag          int64         `json:"max_kafka_lag"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(logger *zap.Logger, config *MetricsConfig) (*MetricsCollector, error) {
	if config == nil {
		return nil, fmt.Errorf("metrics configuration is required")
	}
	
	// Set defaults
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 30 * time.Second
	}
	if len(config.HistogramBuckets) == 0 {
		config.HistogramBuckets = []float64{0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0}
	}
	if config.PrometheusPort == 0 {
		config.PrometheusPort = 9090
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	registry := prometheus.NewRegistry()
	
	collector := &MetricsCollector{
		logger:               logger.With(zap.String("component", "metrics-collector")),
		config:               config,
		registry:            registry,
		isHealthy:           true,
		ctx:                 ctx,
		cancel:              cancel,
		lastThroughputUpdate: time.Now(),
	}
	
	// Initialize Prometheus metrics
	if err := collector.initializeMetrics(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}
	
	// Start background monitoring
	collector.updateTicker = time.NewTicker(config.UpdateInterval)
	go collector.runMetricsUpdater()
	
	logger.Info("Metrics collector initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Int("prometheus_port", config.PrometheusPort),
		zap.Duration("update_interval", config.UpdateInterval),
	)
	
	return collector, nil
}

// initializeMetrics initializes Prometheus metrics
func (m *MetricsCollector) initializeMetrics() error {
	// Event processing metrics
	m.eventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_events_total",
		Help: "Total number of events processed by type and status",
	}, []string{"event_type", "status", "topic"})
	
	m.eventsEnriched = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_enriched_events_total",
		Help: "Total number of events enriched by source and status",
	}, []string{"enrichment_source", "status"})
	
	m.eventsCorrelated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_correlated_events_total",
		Help: "Total number of events correlated by type",
	}, []string{"correlation_type", "status"})
	
	m.patternsMatched = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_patterns_matched_total",
		Help: "Total number of patterns matched by type and severity",
	}, []string{"pattern_type", "severity"})
	
	m.anomaliesDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_anomalies_detected_total",
		Help: "Total number of anomalies detected by type and confidence",
	}, []string{"anomaly_type", "confidence_level"})
	
	m.alertsGenerated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_alerts_generated_total",
		Help: "Total number of alerts generated by type and severity",
	}, []string{"alert_type", "severity"})
	
	// Duration metrics
	m.processingDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "stream_processing_duration_seconds",
		Help:    "Time spent processing events by stage",
		Buckets: m.config.HistogramBuckets,
	}, []string{"stage", "event_type"})
	
	m.enrichmentDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "stream_processing_enrichment_duration_seconds",
		Help:    "Time spent enriching events by source",
		Buckets: m.config.HistogramBuckets,
	}, []string{"enrichment_source"})
	
	m.correlationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "stream_processing_correlation_duration_seconds",
		Help:    "Time spent correlating events by type",
		Buckets: m.config.HistogramBuckets,
	}, []string{"correlation_type"})
	
	m.patternMatchingDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "stream_processing_pattern_matching_duration_seconds",
		Help:    "Time spent pattern matching by rule type",
		Buckets: m.config.HistogramBuckets,
	}, []string{"rule_type"})
	
	m.anomalyDetectionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "stream_processing_anomaly_detection_duration_seconds",
		Help:    "Time spent detecting anomalies by analysis type",
		Buckets: m.config.HistogramBuckets,
	}, []string{"analysis_type"})
	
	// Gauge metrics
	m.kafkaLag = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_kafka_lag",
		Help: "Kafka consumer lag by topic and partition",
	}, []string{"topic", "partition", "consumer_group"})
	
	m.workerPoolUtilization = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_worker_pool_utilization",
		Help: "Worker pool utilization by pool type",
	}, []string{"pool_type"})
	
	m.cacheHitRate = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_cache_hit_rate",
		Help: "Cache hit rate by cache type",
	}, []string{"cache_type"})
	
	m.healthStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_health_status",
		Help: "Health status of stream processing components",
	}, []string{"component"})
	
	// Runtime metrics
	m.enrichmentCacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_enrichment_cache_hits_total",
		Help: "Total enrichment cache hits by source",
	}, []string{"source"})
	
	m.enrichmentCacheMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_enrichment_cache_misses_total",
		Help: "Total enrichment cache misses by source",
	}, []string{"source"})
	
	m.correlationSessions = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_correlation_sessions",
		Help: "Active correlation sessions by type",
	}, []string{"session_type"})
	
	m.anomalyCache = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_anomaly_cache_entries",
		Help: "Number of anomaly cache entries",
	}, []string{"cache_type"})
	
	// Error metrics
	m.processingErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_errors_total",
		Help: "Total processing errors by type and component",
	}, []string{"error_type", "component"})
	
	m.enrichmentErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_enrichment_errors_total",
		Help: "Total enrichment errors by source and error type",
	}, []string{"source", "error_type"})
	
	m.correlationErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_correlation_errors_total",
		Help: "Total correlation errors by type",
	}, []string{"error_type"})
	
	m.patternMatchingErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_pattern_matching_errors_total",
		Help: "Total pattern matching errors by rule type",
	}, []string{"rule_type", "error_type"})
	
	m.anomalyDetectionErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "stream_processing_anomaly_detection_errors_total",
		Help: "Total anomaly detection errors by analysis type",
	}, []string{"analysis_type", "error_type"})
	
	// Performance metrics
	m.throughputGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_throughput_events_per_second",
		Help: "Event processing throughput by component",
	}, []string{"component"})
	
	m.latencyGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "stream_processing_latency_seconds",
		Help: "Processing latency by component",
	}, []string{"component", "percentile"})
	
	return nil
}

// RecordEventProcessed records an event processing metric
func (m *MetricsCollector) RecordEventProcessed(eventType, status, topic string) {
	if !m.config.Enabled {
		return
	}
	
	m.eventsProcessed.WithLabelValues(eventType, status, topic).Inc()
	
	m.mu.Lock()
	m.eventCount++
	m.mu.Unlock()
}

// RecordEnrichmentMetrics records enrichment metrics
func (m *MetricsCollector) RecordEnrichmentMetrics(source, status string, duration time.Duration, cacheHit bool) {
	if !m.config.Enabled {
		return
	}
	
	m.eventsEnriched.WithLabelValues(source, status).Inc()
	m.enrichmentDuration.WithLabelValues(source).Observe(duration.Seconds())
	
	if cacheHit {
		m.enrichmentCacheHits.WithLabelValues(source).Inc()
	} else {
		m.enrichmentCacheMisses.WithLabelValues(source).Inc()
	}
}

// RecordCorrelationMetrics records correlation metrics
func (m *MetricsCollector) RecordCorrelationMetrics(correlationType, status string, duration time.Duration) {
	if !m.config.Enabled {
		return
	}
	
	m.eventsCorrelated.WithLabelValues(correlationType, status).Inc()
	m.correlationDuration.WithLabelValues(correlationType).Observe(duration.Seconds())
}

// RecordPatternMatchMetrics records pattern matching metrics
func (m *MetricsCollector) RecordPatternMatchMetrics(patternType, severity string, duration time.Duration) {
	if !m.config.Enabled {
		return
	}
	
	m.patternsMatched.WithLabelValues(patternType, severity).Inc()
	m.patternMatchingDuration.WithLabelValues(patternType).Observe(duration.Seconds())
}

// RecordAnomalyDetectionMetrics records anomaly detection metrics
func (m *MetricsCollector) RecordAnomalyDetectionMetrics(anomalyType, confidenceLevel string, duration time.Duration) {
	if !m.config.Enabled {
		return
	}
	
	m.anomaliesDetected.WithLabelValues(anomalyType, confidenceLevel).Inc()
	m.anomalyDetectionDuration.WithLabelValues(anomalyType).Observe(duration.Seconds())
}

// RecordAlertGenerated records alert generation metrics
func (m *MetricsCollector) RecordAlertGenerated(alertType, severity string) {
	if !m.config.Enabled {
		return
	}
	
	m.alertsGenerated.WithLabelValues(alertType, severity).Inc()
}

// RecordProcessingDuration records processing duration by stage
func (m *MetricsCollector) RecordProcessingDuration(stage, eventType string, duration time.Duration) {
	if !m.config.Enabled {
		return
	}
	
	m.processingDuration.WithLabelValues(stage, eventType).Observe(duration.Seconds())
}

// RecordError records error metrics
func (m *MetricsCollector) RecordError(component, errorType string) {
	if !m.config.Enabled {
		return
	}
	
	m.processingErrors.WithLabelValues(errorType, component).Inc()
}

// UpdateKafkaLag updates Kafka consumer lag metrics
func (m *MetricsCollector) UpdateKafkaLag(topic, partition, consumerGroup string, lag int64) {
	if !m.config.Enabled {
		return
	}
	
	m.kafkaLag.WithLabelValues(topic, partition, consumerGroup).Set(float64(lag))
}

// UpdateWorkerPoolUtilization updates worker pool utilization metrics
func (m *MetricsCollector) UpdateWorkerPoolUtilization(poolType string, utilization float64) {
	if !m.config.Enabled {
		return
	}
	
	m.workerPoolUtilization.WithLabelValues(poolType).Set(utilization)
}

// UpdateCacheHitRate updates cache hit rate metrics
func (m *MetricsCollector) UpdateCacheHitRate(cacheType string, hitRate float64) {
	if !m.config.Enabled {
		return
	}
	
	m.cacheHitRate.WithLabelValues(cacheType).Set(hitRate)
}

// UpdateHealthStatus updates component health status
func (m *MetricsCollector) UpdateHealthStatus(component string, isHealthy bool) {
	if !m.config.Enabled {
		return
	}
	
	status := 0.0
	if isHealthy {
		status = 1.0
	}
	
	m.healthStatus.WithLabelValues(component).Set(status)
}

// UpdateCorrelationSessions updates active correlation session count
func (m *MetricsCollector) UpdateCorrelationSessions(sessionType string, count int) {
	if !m.config.Enabled {
		return
	}
	
	m.correlationSessions.WithLabelValues(sessionType).Set(float64(count))
}

// UpdateAnomalyCache updates anomaly cache metrics
func (m *MetricsCollector) UpdateAnomalyCache(cacheType string, entries int) {
	if !m.config.Enabled {
		return
	}
	
	m.anomalyCache.WithLabelValues(cacheType).Set(float64(entries))
}

// runMetricsUpdater runs periodic metrics updates
func (m *MetricsCollector) runMetricsUpdater() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.updateTicker.C:
			m.updateThroughputMetrics()
		}
	}
}

// updateThroughputMetrics calculates and updates throughput metrics
func (m *MetricsCollector) updateThroughputMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(m.lastThroughputUpdate)
	
	if elapsed > 0 {
		throughput := float64(m.eventCount) / elapsed.Seconds()
		m.throughputGauge.WithLabelValues("total").Set(throughput)
		
		// Reset counters
		m.eventCount = 0
		m.lastThroughputUpdate = now
	}
}

// GetRegistry returns the Prometheus registry
func (m *MetricsCollector) GetRegistry() *prometheus.Registry {
	return m.registry
}

// IsHealthy returns the health status
func (m *MetricsCollector) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isHealthy
}

// Stop stops the metrics collector
func (m *MetricsCollector) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	
	if m.updateTicker != nil {
		m.updateTicker.Stop()
	}
	
	m.logger.Info("Metrics collector stopped")
}