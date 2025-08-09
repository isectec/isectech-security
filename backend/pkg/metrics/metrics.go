package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config represents metrics configuration
type Config struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Namespace string `json:"namespace" yaml:"namespace"`
	Host      string `json:"host" yaml:"host"`
	Port      int    `json:"port" yaml:"port"`
	Path      string `json:"path" yaml:"path"`
}

// Collector manages all metrics for a service
type Collector struct {
	namespace string
	registry  *prometheus.Registry

	// Common metrics
	RequestsTotal     *prometheus.CounterVec
	RequestDuration   *prometheus.HistogramVec
	RequestsInFlight  *prometheus.GaugeVec
	ErrorsTotal       *prometheus.CounterVec
	
	// System metrics
	SystemInfo        prometheus.Gauge
	StartTime         prometheus.Gauge
	
	// Business metrics
	BusinessOperations *prometheus.CounterVec
	BusinessDuration   *prometheus.HistogramVec
	ActiveSessions     prometheus.Gauge
	
	// Security metrics
	SecurityEvents     *prometheus.CounterVec
	ThreatDetections   *prometheus.CounterVec
	AuthAttempts       *prometheus.CounterVec
	
	// Database metrics
	DatabaseConnections *prometheus.GaugeVec
	DatabaseQueries     *prometheus.CounterVec
	DatabaseDuration    *prometheus.HistogramVec
	
	// Cache metrics
	CacheOperations   *prometheus.CounterVec
	CacheHitRatio     *prometheus.GaugeVec
	
	// Message queue metrics
	MessagesSent      *prometheus.CounterVec
	MessagesReceived  *prometheus.CounterVec
	MessageProcessing *prometheus.HistogramVec
	QueueDepth        *prometheus.GaugeVec
}

// NewCollector creates a new metrics collector
func NewCollector(namespace string) *Collector {
	registry := prometheus.NewRegistry()
	
	c := &Collector{
		namespace: namespace,
		registry:  registry,
	}
	
	c.initializeMetrics()
	c.registerMetrics()
	
	return c
}

// initializeMetrics initializes all metrics
func (c *Collector) initializeMetrics() {
	// HTTP metrics
	c.RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)
	
	c.RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: c.namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "endpoint", "status_code"},
	)
	
	c.RequestsInFlight = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Name:      "http_requests_in_flight",
			Help:      "Number of HTTP requests currently being processed",
		},
		[]string{"method", "endpoint"},
	)
	
	c.ErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "errors_total",
			Help:      "Total number of errors",
		},
		[]string{"error_type", "component"},
	)
	
	// System metrics
	c.SystemInfo = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Name:      "system_info",
			Help:      "System information",
		},
	)
	
	c.StartTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Name:      "start_time_seconds",
			Help:      "Service start time in Unix seconds",
		},
	)
	
	// Business metrics
	c.BusinessOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "business_operations_total",
			Help:      "Total number of business operations",
		},
		[]string{"operation", "tenant_id", "status"},
	)
	
	c.BusinessDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: c.namespace,
			Name:      "business_operation_duration_seconds",
			Help:      "Business operation duration in seconds",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10, 30, 60},
		},
		[]string{"operation", "tenant_id"},
	)
	
	c.ActiveSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Name:      "active_sessions",
			Help:      "Number of active user sessions",
		},
	)
	
	// Security metrics
	c.SecurityEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "security_events_total",
			Help:      "Total number of security events",
		},
		[]string{"event_type", "severity", "tenant_id"},
	)
	
	c.ThreatDetections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "threat_detections_total",
			Help:      "Total number of threat detections",
		},
		[]string{"threat_type", "severity", "tenant_id"},
	)
	
	c.AuthAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "auth_attempts_total",
			Help:      "Total number of authentication attempts",
		},
		[]string{"status", "method", "tenant_id"},
	)
	
	// Database metrics
	c.DatabaseConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Name:      "database_connections",
			Help:      "Number of database connections",
		},
		[]string{"database", "state"},
	)
	
	c.DatabaseQueries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "database_queries_total",
			Help:      "Total number of database queries",
		},
		[]string{"database", "operation", "table"},
	)
	
	c.DatabaseDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: c.namespace,
			Name:      "database_query_duration_seconds",
			Help:      "Database query duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5},
		},
		[]string{"database", "operation", "table"},
	)
	
	// Cache metrics
	c.CacheOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "cache_operations_total",
			Help:      "Total number of cache operations",
		},
		[]string{"operation", "result"},
	)
	
	c.CacheHitRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Name:      "cache_hit_ratio",
			Help:      "Cache hit ratio",
		},
		[]string{"cache_name"},
	)
	
	// Message queue metrics
	c.MessagesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "messages_sent_total",
			Help:      "Total number of messages sent",
		},
		[]string{"topic", "status"},
	)
	
	c.MessagesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: c.namespace,
			Name:      "messages_received_total",
			Help:      "Total number of messages received",
		},
		[]string{"topic", "status"},
	)
	
	c.MessageProcessing = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: c.namespace,
			Name:      "message_processing_duration_seconds",
			Help:      "Message processing duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"topic", "consumer_group"},
	)
	
	c.QueueDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: c.namespace,
			Name:      "queue_depth",
			Help:      "Number of messages in queue",
		},
		[]string{"topic", "partition"},
	)
}

// registerMetrics registers all metrics with the registry
func (c *Collector) registerMetrics() {
	// HTTP metrics
	c.registry.MustRegister(c.RequestsTotal)
	c.registry.MustRegister(c.RequestDuration)
	c.registry.MustRegister(c.RequestsInFlight)
	c.registry.MustRegister(c.ErrorsTotal)
	
	// System metrics
	c.registry.MustRegister(c.SystemInfo)
	c.registry.MustRegister(c.StartTime)
	
	// Business metrics
	c.registry.MustRegister(c.BusinessOperations)
	c.registry.MustRegister(c.BusinessDuration)
	c.registry.MustRegister(c.ActiveSessions)
	
	// Security metrics
	c.registry.MustRegister(c.SecurityEvents)
	c.registry.MustRegister(c.ThreatDetections)
	c.registry.MustRegister(c.AuthAttempts)
	
	// Database metrics
	c.registry.MustRegister(c.DatabaseConnections)
	c.registry.MustRegister(c.DatabaseQueries)
	c.registry.MustRegister(c.DatabaseDuration)
	
	// Cache metrics
	c.registry.MustRegister(c.CacheOperations)
	c.registry.MustRegister(c.CacheHitRatio)
	
	// Message queue metrics
	c.registry.MustRegister(c.MessagesSent)
	c.registry.MustRegister(c.MessagesReceived)
	c.registry.MustRegister(c.MessageProcessing)
	c.registry.MustRegister(c.QueueDepth)
	
	// Set start time
	c.StartTime.SetToCurrentTime()
}

// RecordHTTPRequest records HTTP request metrics
func (c *Collector) RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration) {
	statusStr := strconv.Itoa(statusCode)
	c.RequestsTotal.WithLabelValues(method, endpoint, statusStr).Inc()
	c.RequestDuration.WithLabelValues(method, endpoint, statusStr).Observe(duration.Seconds())
}

// RecordHTTPRequestInFlight records in-flight HTTP requests
func (c *Collector) RecordHTTPRequestInFlight(method, endpoint string, delta float64) {
	c.RequestsInFlight.WithLabelValues(method, endpoint).Add(delta)
}

// RecordError records error metrics
func (c *Collector) RecordError(errorType, component string) {
	c.ErrorsTotal.WithLabelValues(errorType, component).Inc()
}

// RecordBusinessOperation records business operation metrics
func (c *Collector) RecordBusinessOperation(operation, tenantID, status string, duration time.Duration) {
	c.BusinessOperations.WithLabelValues(operation, tenantID, status).Inc()
	c.BusinessDuration.WithLabelValues(operation, tenantID).Observe(duration.Seconds())
}

// RecordSecurityEvent records security event metrics
func (c *Collector) RecordSecurityEvent(eventType, severity, tenantID string) {
	c.SecurityEvents.WithLabelValues(eventType, severity, tenantID).Inc()
}

// RecordThreatDetection records threat detection metrics
func (c *Collector) RecordThreatDetection(threatType, severity, tenantID string) {
	c.ThreatDetections.WithLabelValues(threatType, severity, tenantID).Inc()
}

// RecordAuthAttempt records authentication attempt metrics
func (c *Collector) RecordAuthAttempt(status, method, tenantID string) {
	c.AuthAttempts.WithLabelValues(status, method, tenantID).Inc()
}

// RecordDatabaseConnection records database connection metrics
func (c *Collector) RecordDatabaseConnection(database, state string, count float64) {
	c.DatabaseConnections.WithLabelValues(database, state).Set(count)
}

// RecordDatabaseQuery records database query metrics
func (c *Collector) RecordDatabaseQuery(database, operation, table string, duration time.Duration) {
	c.DatabaseQueries.WithLabelValues(database, operation, table).Inc()
	c.DatabaseDuration.WithLabelValues(database, operation, table).Observe(duration.Seconds())
}

// RecordCacheOperation records cache operation metrics
func (c *Collector) RecordCacheOperation(operation, result string) {
	c.CacheOperations.WithLabelValues(operation, result).Inc()
}

// RecordCacheHitRatio records cache hit ratio metrics
func (c *Collector) RecordCacheHitRatio(cacheName string, ratio float64) {
	c.CacheHitRatio.WithLabelValues(cacheName).Set(ratio)
}

// RecordMessageSent records message sent metrics
func (c *Collector) RecordMessageSent(topic, status string) {
	c.MessagesSent.WithLabelValues(topic, status).Inc()
}

// RecordMessageReceived records message received metrics
func (c *Collector) RecordMessageReceived(topic, status string) {
	c.MessagesReceived.WithLabelValues(topic, status).Inc()
}

// RecordMessageProcessing records message processing metrics
func (c *Collector) RecordMessageProcessing(topic, consumerGroup string, duration time.Duration) {
	c.MessageProcessing.WithLabelValues(topic, consumerGroup).Observe(duration.Seconds())
}

// RecordQueueDepth records queue depth metrics
func (c *Collector) RecordQueueDepth(topic, partition string, depth float64) {
	c.QueueDepth.WithLabelValues(topic, partition).Set(depth)
}

// SetActiveSessions sets the number of active sessions
func (c *Collector) SetActiveSessions(count float64) {
	c.ActiveSessions.Set(count)
}

// GetRegistry returns the metrics registry
func (c *Collector) GetRegistry() *prometheus.Registry {
	return c.registry
}

// CreateHandler creates an HTTP handler for metrics
func (c *Collector) CreateHandler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Server represents a metrics server
type Server struct {
	config    Config
	collector *Collector
	server    *http.Server
}

// NewServer creates a new metrics server
func NewServer(config Config, collector *Collector) *Server {
	if !config.Enabled {
		return &Server{config: config}
	}
	
	mux := http.NewServeMux()
	mux.Handle(config.Path, collector.CreateHandler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	
	return &Server{
		config:    config,
		collector: collector,
		server:    server,
	}
}

// Start starts the metrics server
func (s *Server) Start() error {
	if !s.config.Enabled || s.server == nil {
		return nil
	}
	
	return s.server.ListenAndServe()
}

// Stop stops the metrics server
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}
	return s.server.Close()
}

// Middleware creates HTTP middleware for metrics collection
func (c *Collector) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Record in-flight request
			c.RecordHTTPRequestInFlight(r.Method, r.URL.Path, 1)
			defer c.RecordHTTPRequestInFlight(r.Method, r.URL.Path, -1)
			
			// Wrap response writer to capture status code
			wrapper := &responseWriter{ResponseWriter: w, statusCode: 200}
			
			// Serve request
			next.ServeHTTP(wrapper, r)
			
			// Record metrics
			duration := time.Since(start)
			c.RecordHTTPRequest(r.Method, r.URL.Path, wrapper.statusCode, duration)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code
func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Timer helps measure operation duration
type Timer struct {
	start time.Time
}

// NewTimer creates a new timer
func NewTimer() *Timer {
	return &Timer{start: time.Now()}
}

// Duration returns the elapsed duration
func (t *Timer) Duration() time.Duration {
	return time.Since(t.start)
}

// ObserveDuration observes duration on a histogram
func (t *Timer) ObserveDuration(observer prometheus.Observer) {
	observer.Observe(t.Duration().Seconds())
}

// Global metrics collector
var globalCollector *Collector

// InitGlobalCollector initializes the global metrics collector
func InitGlobalCollector(namespace string) {
	globalCollector = NewCollector(namespace)
}

// GetGlobalCollector returns the global metrics collector
func GetGlobalCollector() *Collector {
	if globalCollector == nil {
		globalCollector = NewCollector("isectech")
	}
	return globalCollector
}

// Convenience functions using global collector

// RecordHTTPRequest records HTTP request using global collector
func RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration) {
	GetGlobalCollector().RecordHTTPRequest(method, endpoint, statusCode, duration)
}

// RecordError records error using global collector
func RecordError(errorType, component string) {
	GetGlobalCollector().RecordError(errorType, component)
}

// RecordBusinessOperation records business operation using global collector
func RecordBusinessOperation(operation, tenantID, status string, duration time.Duration) {
	GetGlobalCollector().RecordBusinessOperation(operation, tenantID, status, duration)
}

// RecordSecurityEvent records security event using global collector
func RecordSecurityEvent(eventType, severity, tenantID string) {
	GetGlobalCollector().RecordSecurityEvent(eventType, severity, tenantID)
}

// RecordThreatDetection records threat detection using global collector
func RecordThreatDetection(threatType, severity, tenantID string) {
	GetGlobalCollector().RecordThreatDetection(threatType, severity, tenantID)
}

// RecordAuthAttempt records authentication attempt using global collector
func RecordAuthAttempt(status, method, tenantID string) {
	GetGlobalCollector().RecordAuthAttempt(status, method, tenantID)
}