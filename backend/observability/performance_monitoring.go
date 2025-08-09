package observability

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// PerformanceMonitoring manages automated performance and security monitoring
type PerformanceMonitoring struct {
	logger        *zap.Logger
	config        *MonitoringConfig
	
	// Metrics collectors
	systemMetrics    *SystemMetricsCollector
	appMetrics       *ApplicationMetricsCollector
	securityMetrics  *SecurityMetricsCollector
	pipelineMetrics  *PipelineMetricsCollector
	
	// Alerting
	alertManager     *AlertManager
	
	// Health checks
	healthChecks     map[string]HealthCheck
	healthMutex      sync.RWMutex
	
	// Background monitoring
	ctx              context.Context
	cancel           context.CancelFunc
	monitoringTicker *time.Ticker
	
	// Statistics
	stats            *MonitoringStats
	statsMutex       sync.RWMutex
}

// MonitoringConfig defines performance monitoring configuration
type MonitoringConfig struct {
	// Service configuration
	ServiceName       string        `json:"service_name"`
	Environment       string        `json:"environment"`
	
	// Collection intervals
	SystemInterval    time.Duration `json:"system_interval"`
	AppInterval       time.Duration `json:"app_interval"`
	SecurityInterval  time.Duration `json:"security_interval"`
	PipelineInterval  time.Duration `json:"pipeline_interval"`
	
	// Metrics configuration
	MetricsEnabled    bool          `json:"metrics_enabled"`
	MetricsPort       int           `json:"metrics_port"`
	MetricsPath       string        `json:"metrics_path"`
	
	// Alerting configuration
	AlertingEnabled   bool          `json:"alerting_enabled"`
	AlertWebhookURL   string        `json:"alert_webhook_url"`
	SlackWebhookURL   string        `json:"slack_webhook_url"`
	EmailConfig       *EmailAlertConfig `json:"email_config"`
	
	// Performance thresholds
	CPUThreshold      float64       `json:"cpu_threshold"`
	MemoryThreshold   float64       `json:"memory_threshold"`
	DiskThreshold     float64       `json:"disk_threshold"`
	ResponseTimeThreshold time.Duration `json:"response_time_threshold"`
	ErrorRateThreshold float64      `json:"error_rate_threshold"`
	
	// Security thresholds
	FailedLoginThreshold    int           `json:"failed_login_threshold"`
	SuspiciousActivityWindow time.Duration `json:"suspicious_activity_window"`
	ThreatScoreThreshold    float64       `json:"threat_score_threshold"`
	
	// Pipeline thresholds
	ProcessingLatencyThreshold time.Duration `json:"processing_latency_threshold"`
	QueueSizeThreshold        int           `json:"queue_size_threshold"`
	ThroughputThreshold       float64       `json:"throughput_threshold"`
	
	// Health check configuration
	HealthCheckEnabled bool          `json:"health_check_enabled"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	
	// Retention
	MetricsRetention  time.Duration `json:"metrics_retention"`
}

// EmailAlertConfig defines email alerting configuration
type EmailAlertConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	FromAddress  string   `json:"from_address"`
	ToAddresses  []string `json:"to_addresses"`
	TLS          bool     `json:"tls"`
}

// SystemMetricsCollector collects system-level metrics
type SystemMetricsCollector struct {
	logger          *zap.Logger
	
	// Prometheus metrics
	cpuUsage        prometheus.Gauge
	memoryUsage     prometheus.Gauge
	diskUsage       prometheus.Gauge
	networkRx       prometheus.Counter
	networkTx       prometheus.Counter
	loadAverage     prometheus.Gauge
	goroutines      prometheus.Gauge
	fileDescriptors prometheus.Gauge
}

// ApplicationMetricsCollector collects application-level metrics
type ApplicationMetricsCollector struct {
	logger             *zap.Logger
	
	// HTTP metrics
	httpRequests       prometheus.Counter
	httpDuration       prometheus.Histogram
	httpErrors         prometheus.Counter
	
	// Database metrics
	dbConnections      prometheus.Gauge
	dbQueries          prometheus.Counter
	dbQueryDuration    prometheus.Histogram
	dbErrors           prometheus.Counter
	
	// Cache metrics
	cacheHits          prometheus.Counter
	cacheMisses        prometheus.Counter
	cacheSize          prometheus.Gauge
}

// SecurityMetricsCollector collects security-specific metrics
type SecurityMetricsCollector struct {
	logger               *zap.Logger
	
	// Authentication metrics
	loginAttempts        prometheus.Counter
	failedLogins         prometheus.Counter
	successfulLogins     prometheus.Counter
	sessionDuration      prometheus.Histogram
	
	// Security events
	securityEvents       prometheus.Counter
	threatsDetected      prometheus.Counter
	threatScore          prometheus.Histogram
	blockedRequests      prometheus.Counter
	
	// Anomaly detection
	anomaliesDetected    prometheus.Counter
	falsePositives       prometheus.Counter
	modelAccuracy        prometheus.Gauge
}

// PipelineMetricsCollector collects pipeline-specific metrics
type PipelineMetricsCollector struct {
	logger                 *zap.Logger
	
	// Event processing
	eventsIngested         prometheus.Counter
	eventsProcessed        prometheus.Counter
	eventsDropped          prometheus.Counter
	processingLatency      prometheus.Histogram
	
	// Queue metrics
	queueSize              prometheus.Gauge
	queueProcessingRate    prometheus.Gauge
	queueWaitTime          prometheus.Histogram
	
	// Storage metrics
	documentsIndexed       prometheus.Counter
	indexingLatency        prometheus.Histogram
	storageSize            prometheus.Gauge
	queryLatency           prometheus.Histogram
	
	// Stream processing
	streamThroughput       prometheus.Gauge
	correlationsFound      prometheus.Counter
	patternsMatched        prometheus.Counter
}

// AlertManager manages alerting based on metrics and thresholds
type AlertManager struct {
	logger        *zap.Logger
	config        *MonitoringConfig
	
	// Alert channels
	webhookURL    string
	slackURL      string
	emailConfig   *EmailAlertConfig
	
	// Alert state
	activeAlerts     map[string]*Alert
	alertMutex       sync.RWMutex
	alertHistory     []*Alert
	
	// Alert statistics
	totalAlerts      int64
	resolvedAlerts   int64
}

// Alert represents a monitoring alert
type Alert struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"` // performance, security, pipeline
	Severity        string                 `json:"severity"` // low, medium, high, critical
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Metric          string                 `json:"metric"`
	CurrentValue    interface{}            `json:"current_value"`
	ThresholdValue  interface{}            `json:"threshold_value"`
	Timestamp       time.Time              `json:"timestamp"`
	ResolvedAt      time.Time              `json:"resolved_at,omitempty"`
	Status          string                 `json:"status"` // active, resolved, acknowledged
	Annotations     map[string]interface{} `json:"annotations"`
}

// HealthCheck represents a health check
type HealthCheck interface {
	Name() string
	Check(ctx context.Context) error
	IsEnabled() bool
	GetTimeout() time.Duration
}

// MonitoringStats tracks monitoring statistics
type MonitoringStats struct {
	MetricsCollected    int64         `json:"metrics_collected"`
	AlertsGenerated     int64         `json:"alerts_generated"`
	AlertsResolved      int64         `json:"alerts_resolved"`
	HealthChecksPassed  int64         `json:"health_checks_passed"`
	HealthChecksFailed  int64         `json:"health_checks_failed"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	LastMonitoringRun   time.Time     `json:"last_monitoring_run"`
}

// NewPerformanceMonitoring creates a new performance monitoring system
func NewPerformanceMonitoring(logger *zap.Logger, config *MonitoringConfig) (*PerformanceMonitoring, error) {
	if config == nil {
		return nil, fmt.Errorf("monitoring configuration is required")
	}
	
	// Set defaults
	if err := setMonitoringDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pm := &PerformanceMonitoring{
		logger:       logger.With(zap.String("component", "performance-monitoring")),
		config:       config,
		healthChecks: make(map[string]HealthCheck),
		stats:        &MonitoringStats{},
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Initialize metrics collectors
	if err := pm.initializeMetricsCollectors(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize metrics collectors: %w", err)
	}
	
	// Initialize alert manager
	if config.AlertingEnabled {
		alertManager, err := NewAlertManager(logger, config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize alert manager: %w", err)
		}
		pm.alertManager = alertManager
	}
	
	// Initialize default health checks
	if err := pm.initializeHealthChecks(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize health checks: %w", err)
	}
	
	// Start background monitoring
	pm.monitoringTicker = time.NewTicker(time.Minute)
	go pm.runMonitoring()
	
	logger.Info("Performance monitoring initialized",
		zap.String("service_name", config.ServiceName),
		zap.Bool("metrics_enabled", config.MetricsEnabled),
		zap.Bool("alerting_enabled", config.AlertingEnabled),
	)
	
	return pm, nil
}

// setMonitoringDefaults sets configuration defaults
func setMonitoringDefaults(config *MonitoringConfig) error {
	if config.ServiceName == "" {
		config.ServiceName = "isectech-security-pipeline"
	}
	if config.Environment == "" {
		config.Environment = "production"
	}
	if config.SystemInterval == 0 {
		config.SystemInterval = 30 * time.Second
	}
	if config.AppInterval == 0 {
		config.AppInterval = 30 * time.Second
	}
	if config.SecurityInterval == 0 {
		config.SecurityInterval = 1 * time.Minute
	}
	if config.PipelineInterval == 0 {
		config.PipelineInterval = 30 * time.Second
	}
	if config.MetricsPort == 0 {
		config.MetricsPort = 9090
	}
	if config.MetricsPath == "" {
		config.MetricsPath = "/metrics"
	}
	if config.CPUThreshold == 0 {
		config.CPUThreshold = 80.0 // 80%
	}
	if config.MemoryThreshold == 0 {
		config.MemoryThreshold = 80.0 // 80%
	}
	if config.DiskThreshold == 0 {
		config.DiskThreshold = 90.0 // 90%
	}
	if config.ResponseTimeThreshold == 0 {
		config.ResponseTimeThreshold = 5 * time.Second
	}
	if config.ErrorRateThreshold == 0 {
		config.ErrorRateThreshold = 5.0 // 5%
	}
	if config.FailedLoginThreshold == 0 {
		config.FailedLoginThreshold = 10
	}
	if config.SuspiciousActivityWindow == 0 {
		config.SuspiciousActivityWindow = 5 * time.Minute
	}
	if config.ThreatScoreThreshold == 0 {
		config.ThreatScoreThreshold = 8.0
	}
	if config.ProcessingLatencyThreshold == 0 {
		config.ProcessingLatencyThreshold = 1 * time.Second
	}
	if config.QueueSizeThreshold == 0 {
		config.QueueSizeThreshold = 1000
	}
	if config.ThroughputThreshold == 0 {
		config.ThroughputThreshold = 100.0 // events per second
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 1 * time.Minute
	}
	if config.MetricsRetention == 0 {
		config.MetricsRetention = 7 * 24 * time.Hour // 7 days
	}
	
	return nil
}

// initializeMetricsCollectors initializes all metrics collectors
func (pm *PerformanceMonitoring) initializeMetricsCollectors() error {
	// System metrics
	pm.systemMetrics = &SystemMetricsCollector{
		logger: pm.logger.With(zap.String("collector", "system")),
		cpuUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "system_cpu_usage_percent",
			Help: "Current CPU usage percentage",
		}),
		memoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "system_memory_usage_percent",
			Help: "Current memory usage percentage",
		}),
		diskUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "system_disk_usage_percent",
			Help: "Current disk usage percentage",
		}),
		networkRx: promauto.NewCounter(prometheus.CounterOpts{
			Name: "system_network_rx_bytes_total",
			Help: "Total bytes received over network",
		}),
		networkTx: promauto.NewCounter(prometheus.CounterOpts{
			Name: "system_network_tx_bytes_total",
			Help: "Total bytes transmitted over network",
		}),
		loadAverage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "system_load_average",
			Help: "System load average",
		}),
		goroutines: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "go_goroutines",
			Help: "Number of goroutines that currently exist",
		}),
		fileDescriptors: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "process_open_fds",
			Help: "Number of open file descriptors",
		}),
	}
	
	// Application metrics
	pm.appMetrics = &ApplicationMetricsCollector{
		logger: pm.logger.With(zap.String("collector", "application")),
		httpRequests: promauto.NewCounter(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		}),
		httpDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		httpErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "http_errors_total",
			Help: "Total number of HTTP errors",
		}),
		dbConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "database_connections_active",
			Help: "Number of active database connections",
		}),
		dbQueries: promauto.NewCounter(prometheus.CounterOpts{
			Name: "database_queries_total",
			Help: "Total number of database queries",
		}),
		dbQueryDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "database_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		dbErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "database_errors_total",
			Help: "Total number of database errors",
		}),
		cacheHits: promauto.NewCounter(prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits",
		}),
		cacheMisses: promauto.NewCounter(prometheus.CounterOpts{
			Name: "cache_misses_total",
			Help: "Total number of cache misses",
		}),
		cacheSize: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "cache_size_bytes",
			Help: "Current cache size in bytes",
		}),
	}
	
	// Security metrics
	pm.securityMetrics = &SecurityMetricsCollector{
		logger: pm.logger.With(zap.String("collector", "security")),
		loginAttempts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_login_attempts_total",
			Help: "Total number of login attempts",
		}),
		failedLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_failed_logins_total",
			Help: "Total number of failed login attempts",
		}),
		successfulLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_successful_logins_total",
			Help: "Total number of successful logins",
		}),
		sessionDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "security_session_duration_seconds",
			Help:    "User session duration in seconds",
			Buckets: []float64{60, 300, 900, 1800, 3600, 7200, 14400, 28800},
		}),
		securityEvents: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_events_total",
			Help: "Total number of security events",
		}),
		threatsDetected: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_threats_detected_total",
			Help: "Total number of threats detected",
		}),
		threatScore: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "security_threat_score",
			Help:    "Threat score distribution",
			Buckets: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		}),
		blockedRequests: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_blocked_requests_total",
			Help: "Total number of blocked requests",
		}),
		anomaliesDetected: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_anomalies_detected_total",
			Help: "Total number of anomalies detected",
		}),
		falsePositives: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_false_positives_total",
			Help: "Total number of false positives",
		}),
		modelAccuracy: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "security_model_accuracy",
			Help: "Current accuracy of security models",
		}),
	}
	
	// Pipeline metrics
	pm.pipelineMetrics = &PipelineMetricsCollector{
		logger: pm.logger.With(zap.String("collector", "pipeline")),
		eventsIngested: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pipeline_events_ingested_total",
			Help: "Total number of events ingested",
		}),
		eventsProcessed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pipeline_events_processed_total",
			Help: "Total number of events processed",
		}),
		eventsDropped: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pipeline_events_dropped_total",
			Help: "Total number of events dropped",
		}),
		processingLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "pipeline_processing_latency_seconds",
			Help:    "Event processing latency in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5},
		}),
		queueSize: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "pipeline_queue_size",
			Help: "Current queue size",
		}),
		queueProcessingRate: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "pipeline_queue_processing_rate",
			Help: "Queue processing rate per second",
		}),
		queueWaitTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "pipeline_queue_wait_time_seconds",
			Help:    "Time events spend waiting in queue",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5},
		}),
		documentsIndexed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pipeline_documents_indexed_total",
			Help: "Total number of documents indexed",
		}),
		indexingLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "pipeline_indexing_latency_seconds",
			Help:    "Document indexing latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		storageSize: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "pipeline_storage_size_bytes",
			Help: "Current storage size in bytes",
		}),
		queryLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "pipeline_query_latency_seconds",
			Help:    "Query execution latency in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		streamThroughput: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "pipeline_stream_throughput_eps",
			Help: "Stream processing throughput in events per second",
		}),
		correlationsFound: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pipeline_correlations_found_total",
			Help: "Total number of correlations found",
		}),
		patternsMatched: promauto.NewCounter(prometheus.CounterOpts{
			Name: "pipeline_patterns_matched_total",
			Help: "Total number of patterns matched",
		}),
	}
	
	return nil
}

// initializeHealthChecks initializes default health checks
func (pm *PerformanceMonitoring) initializeHealthChecks() error {
	// Database health check
	pm.RegisterHealthCheck("database", &DatabaseHealthCheck{
		name:    "database",
		timeout: 5 * time.Second,
	})
	
	// Storage health check
	pm.RegisterHealthCheck("storage", &StorageHealthCheck{
		name:    "storage",
		timeout: 5 * time.Second,
	})
	
	// External services health check
	pm.RegisterHealthCheck("external_services", &ExternalServicesHealthCheck{
		name:    "external_services",
		timeout: 10 * time.Second,
	})
	
	return nil
}

// runMonitoring runs the main monitoring loop
func (pm *PerformanceMonitoring) runMonitoring() {
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-pm.monitoringTicker.C:
			pm.performMonitoring()
		}
	}
}

// performMonitoring performs all monitoring tasks
func (pm *PerformanceMonitoring) performMonitoring() {
	start := time.Now()
	
	// Collect system metrics
	pm.collectSystemMetrics()
	
	// Collect application metrics
	pm.collectApplicationMetrics()
	
	// Collect security metrics
	pm.collectSecurityMetrics()
	
	// Collect pipeline metrics
	pm.collectPipelineMetrics()
	
	// Run health checks
	if pm.config.HealthCheckEnabled {
		pm.runHealthChecks()
	}
	
	// Check thresholds and generate alerts
	if pm.config.AlertingEnabled && pm.alertManager != nil {
		pm.checkThresholds()
	}
	
	// Update statistics
	duration := time.Since(start)
	pm.statsMutex.Lock()
	pm.stats.MetricsCollected++
	pm.stats.AverageResponseTime = (pm.stats.AverageResponseTime + duration) / 2
	pm.stats.LastMonitoringRun = time.Now()
	pm.statsMutex.Unlock()
}

// collectSystemMetrics collects system-level metrics
func (pm *PerformanceMonitoring) collectSystemMetrics() {
	// CPU usage
	cpuUsage := pm.getCPUUsage()
	pm.systemMetrics.cpuUsage.Set(cpuUsage)
	
	// Memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memoryUsage := float64(m.Sys) / (1024 * 1024 * 1024) // Convert to GB
	pm.systemMetrics.memoryUsage.Set(memoryUsage)
	
	// Goroutines
	pm.systemMetrics.goroutines.Set(float64(runtime.NumGoroutine()))
	
	// Disk usage
	diskUsage := pm.getDiskUsage()
	pm.systemMetrics.diskUsage.Set(diskUsage)
}

// collectApplicationMetrics collects application-level metrics
func (pm *PerformanceMonitoring) collectApplicationMetrics() {
	// Database connections would be collected from actual connection pools
	// Cache metrics would be collected from actual cache implementations
	// HTTP metrics are typically collected by middleware
}

// collectSecurityMetrics collects security-specific metrics
func (pm *PerformanceMonitoring) collectSecurityMetrics() {
	// Security metrics would be collected from security event processors
	// This is a placeholder for integration with actual security components
}

// collectPipelineMetrics collects pipeline-specific metrics
func (pm *PerformanceMonitoring) collectPipelineMetrics() {
	// Pipeline metrics would be collected from actual pipeline components
	// This is a placeholder for integration with actual pipeline components
}

// runHealthChecks runs all registered health checks
func (pm *PerformanceMonitoring) runHealthChecks() {
	pm.healthMutex.RLock()
	healthChecks := make([]HealthCheck, 0, len(pm.healthChecks))
	for _, hc := range pm.healthChecks {
		if hc.IsEnabled() {
			healthChecks = append(healthChecks, hc)
		}
	}
	pm.healthMutex.RUnlock()
	
	for _, hc := range healthChecks {
		ctx, cancel := context.WithTimeout(pm.ctx, hc.GetTimeout())
		
		if err := hc.Check(ctx); err != nil {
			pm.statsMutex.Lock()
			pm.stats.HealthChecksFailed++
			pm.statsMutex.Unlock()
			
			// Generate health check alert
			if pm.alertManager != nil {
				alert := &Alert{
					ID:             fmt.Sprintf("health_check_%s_%d", hc.Name(), time.Now().Unix()),
					Type:           "performance",
					Severity:       "high",
					Title:          fmt.Sprintf("Health Check Failed: %s", hc.Name()),
					Description:    fmt.Sprintf("Health check for %s failed: %s", hc.Name(), err.Error()),
					Metric:         fmt.Sprintf("health_check_%s", hc.Name()),
					CurrentValue:   "failed",
					ThresholdValue: "pass",
					Timestamp:      time.Now(),
					Status:         "active",
					Annotations:    map[string]interface{}{"error": err.Error()},
				}
				pm.alertManager.TriggerAlert(alert)
			}
			
			pm.logger.Warn("Health check failed",
				zap.String("check", hc.Name()),
				zap.Error(err),
			)
		} else {
			pm.statsMutex.Lock()
			pm.stats.HealthChecksPassed++
			pm.statsMutex.Unlock()
		}
		
		cancel()
	}
}

// checkThresholds checks metrics against configured thresholds
func (pm *PerformanceMonitoring) checkThresholds() {
	// CPU threshold
	if cpuUsage := pm.getCPUUsage(); cpuUsage > pm.config.CPUThreshold {
		alert := &Alert{
			ID:             fmt.Sprintf("cpu_high_%d", time.Now().Unix()),
			Type:           "performance",
			Severity:       "high",
			Title:          "High CPU Usage",
			Description:    fmt.Sprintf("CPU usage is %.2f%%, exceeding threshold of %.2f%%", cpuUsage, pm.config.CPUThreshold),
			Metric:         "cpu_usage",
			CurrentValue:   cpuUsage,
			ThresholdValue: pm.config.CPUThreshold,
			Timestamp:      time.Now(),
			Status:         "active",
		}
		pm.alertManager.TriggerAlert(alert)
	}
	
	// Memory threshold
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memoryUsagePercent := (float64(m.Sys) / float64(m.TotalAlloc)) * 100
	if memoryUsagePercent > pm.config.MemoryThreshold {
		alert := &Alert{
			ID:             fmt.Sprintf("memory_high_%d", time.Now().Unix()),
			Type:           "performance",
			Severity:       "high",
			Title:          "High Memory Usage",
			Description:    fmt.Sprintf("Memory usage is %.2f%%, exceeding threshold of %.2f%%", memoryUsagePercent, pm.config.MemoryThreshold),
			Metric:         "memory_usage",
			CurrentValue:   memoryUsagePercent,
			ThresholdValue: pm.config.MemoryThreshold,
			Timestamp:      time.Now(),
			Status:         "active",
		}
		pm.alertManager.TriggerAlert(alert)
	}
	
	// Additional threshold checks would be implemented here
}

// Helper methods for metrics collection

func (pm *PerformanceMonitoring) getCPUUsage() float64 {
	// Placeholder implementation
	// In a real implementation, this would get actual CPU usage
	return 0.0
}

func (pm *PerformanceMonitoring) getDiskUsage() float64 {
	// Placeholder implementation
	// In a real implementation, this would get actual disk usage
	return 0.0
}

// RegisterHealthCheck registers a new health check
func (pm *PerformanceMonitoring) RegisterHealthCheck(name string, check HealthCheck) {
	pm.healthMutex.Lock()
	pm.healthChecks[name] = check
	pm.healthMutex.Unlock()
	
	pm.logger.Info("Health check registered", zap.String("check", name))
}

// UnregisterHealthCheck removes a health check
func (pm *PerformanceMonitoring) UnregisterHealthCheck(name string) {
	pm.healthMutex.Lock()
	delete(pm.healthChecks, name)
	pm.healthMutex.Unlock()
	
	pm.logger.Info("Health check unregistered", zap.String("check", name))
}

// GetMonitoringStats returns monitoring statistics
func (pm *PerformanceMonitoring) GetMonitoringStats() *MonitoringStats {
	pm.statsMutex.RLock()
	defer pm.statsMutex.RUnlock()
	
	stats := *pm.stats
	return &stats
}

// IsHealthy returns the overall health status
func (pm *PerformanceMonitoring) IsHealthy() bool {
	pm.healthMutex.RLock()
	defer pm.healthMutex.RUnlock()
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	for _, hc := range pm.healthChecks {
		if hc.IsEnabled() {
			if err := hc.Check(ctx); err != nil {
				return false
			}
		}
	}
	
	return true
}

// Close closes the performance monitoring system
func (pm *PerformanceMonitoring) Close() error {
	if pm.cancel != nil {
		pm.cancel()
	}
	
	if pm.monitoringTicker != nil {
		pm.monitoringTicker.Stop()
	}
	
	if pm.alertManager != nil {
		pm.alertManager.Close()
	}
	
	pm.logger.Info("Performance monitoring system closed")
	return nil
}

// Supporting components implementations

func NewAlertManager(logger *zap.Logger, config *MonitoringConfig) (*AlertManager, error) {
	return &AlertManager{
		logger:       logger.With(zap.String("component", "alert-manager")),
		config:       config,
		webhookURL:   config.AlertWebhookURL,
		slackURL:     config.SlackWebhookURL,
		emailConfig:  config.EmailConfig,
		activeAlerts: make(map[string]*Alert),
		alertHistory: make([]*Alert, 0),
	}, nil
}

func (am *AlertManager) TriggerAlert(alert *Alert) {
	am.alertMutex.Lock()
	am.activeAlerts[alert.ID] = alert
	am.alertHistory = append(am.alertHistory, alert)
	am.totalAlerts++
	am.alertMutex.Unlock()
	
	// Send alert notifications
	go am.sendAlertNotifications(alert)
	
	am.logger.Warn("Alert triggered",
		zap.String("alert_id", alert.ID),
		zap.String("title", alert.Title),
		zap.String("severity", alert.Severity),
	)
}

func (am *AlertManager) sendAlertNotifications(alert *Alert) {
	// Implementation would send alerts via configured channels
	// Webhook, Slack, Email, etc.
}

func (am *AlertManager) ResolveAlert(alertID string) {
	am.alertMutex.Lock()
	if alert, exists := am.activeAlerts[alertID]; exists {
		alert.Status = "resolved"
		alert.ResolvedAt = time.Now()
		delete(am.activeAlerts, alertID)
		am.resolvedAlerts++
	}
	am.alertMutex.Unlock()
}

func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.alertMutex.RLock()
	defer am.alertMutex.RUnlock()
	
	alerts := make([]*Alert, 0, len(am.activeAlerts))
	for _, alert := range am.activeAlerts {
		alerts = append(alerts, alert)
	}
	return alerts
}

func (am *AlertManager) Close() error {
	return nil
}

// Health check implementations

type DatabaseHealthCheck struct {
	name    string
	timeout time.Duration
}

func (dhc *DatabaseHealthCheck) Name() string {
	return dhc.name
}

func (dhc *DatabaseHealthCheck) Check(ctx context.Context) error {
	// Implementation would check database connectivity
	return nil
}

func (dhc *DatabaseHealthCheck) IsEnabled() bool {
	return true
}

func (dhc *DatabaseHealthCheck) GetTimeout() time.Duration {
	return dhc.timeout
}

type StorageHealthCheck struct {
	name    string
	timeout time.Duration
}

func (shc *StorageHealthCheck) Name() string {
	return shc.name
}

func (shc *StorageHealthCheck) Check(ctx context.Context) error {
	// Implementation would check storage systems
	return nil
}

func (shc *StorageHealthCheck) IsEnabled() bool {
	return true
}

func (shc *StorageHealthCheck) GetTimeout() time.Duration {
	return shc.timeout
}

type ExternalServicesHealthCheck struct {
	name    string
	timeout time.Duration
}

func (eshc *ExternalServicesHealthCheck) Name() string {
	return eshc.name
}

func (eshc *ExternalServicesHealthCheck) Check(ctx context.Context) error {
	// Implementation would check external service dependencies
	return nil
}

func (eshc *ExternalServicesHealthCheck) IsEnabled() bool {
	return true
}

func (eshc *ExternalServicesHealthCheck) GetTimeout() time.Duration {
	return eshc.timeout
}