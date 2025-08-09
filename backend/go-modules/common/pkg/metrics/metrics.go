package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Config represents metrics configuration
type Config struct {
	// Server settings
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Host    string `yaml:"host" json:"host"`
	Port    int    `yaml:"port" json:"port"`
	Path    string `yaml:"path" json:"path"`
	
	// Service information
	ServiceName    string `yaml:"service_name" json:"service_name"`
	ServiceVersion string `yaml:"service_version" json:"service_version"`
	Environment    string `yaml:"environment" json:"environment"`
	
	// Collection settings
	CollectGoMetrics      bool          `yaml:"collect_go_metrics" json:"collect_go_metrics"`
	CollectProcessMetrics bool          `yaml:"collect_process_metrics" json:"collect_process_metrics"`
	PushInterval          time.Duration `yaml:"push_interval" json:"push_interval"`
	
	// Gateway settings (for Pushgateway)
	PushGateway PushGatewayConfig `yaml:"push_gateway" json:"push_gateway"`
}

// PushGatewayConfig represents Pushgateway configuration
type PushGatewayConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	URL      string `yaml:"url" json:"url"`
	Job      string `yaml:"job" json:"job"`
	Instance string `yaml:"instance" json:"instance"`
}

// Manager manages Prometheus metrics
type Manager struct {
	config   *Config
	registry *prometheus.Registry
	server   *http.Server
	logger   *zap.Logger
	
	// Common metrics
	requestsTotal         *prometheus.CounterVec
	requestDuration       *prometheus.HistogramVec
	requestsInFlight      *prometheus.GaugeVec
	errorTotal            *prometheus.CounterVec
	
	// gRPC metrics
	grpcRequestsTotal     *prometheus.CounterVec
	grpcRequestDuration   *prometheus.HistogramVec
	grpcRequestsInFlight  *prometheus.GaugeVec
	
	// Database metrics
	dbConnectionsActive   *prometheus.GaugeVec
	dbConnectionsIdle     *prometheus.GaugeVec
	dbQueryDuration       *prometheus.HistogramVec
	dbQueriesTotal        *prometheus.CounterVec
	
	// Cache metrics
	cacheOperationsTotal  *prometheus.CounterVec
	cacheHitsTotal        *prometheus.CounterVec
	cacheMissesTotal      *prometheus.CounterVec
	
	// Security metrics
	authAttemptsTotal     *prometheus.CounterVec
	authFailuresTotal     *prometheus.CounterVec
	securityEventsTotal   *prometheus.CounterVec
	
	// Custom metrics
	customCounters     map[string]*prometheus.CounterVec
	customGauges      map[string]*prometheus.GaugeVec
	customHistograms  map[string]*prometheus.HistogramVec
}

// NewManager creates a new metrics manager
func NewManager(config *Config, logger *zap.Logger) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	// Create registry
	registry := prometheus.NewRegistry()
	
	m := &Manager{
		config:           config,
		registry:         registry,
		logger:           logger,
		customCounters:   make(map[string]*prometheus.CounterVec),
		customGauges:     make(map[string]*prometheus.GaugeVec),
		customHistograms: make(map[string]*prometheus.HistogramVec),
	}

	// Initialize metrics
	if err := m.initializeMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return m, nil
}

// initializeMetrics initializes all Prometheus metrics
func (m *Manager) initializeMetrics() error {
	// Common labels
	commonLabels := []string{"service", "version", "environment"}
	
	// Request metrics
	m.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "requests_total",
			Help: "Total number of requests",
		},
		append(commonLabels, "method", "status_code", "endpoint"),
	)
	
	m.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		append(commonLabels, "method", "endpoint"),
	)
	
	m.requestsInFlight = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "requests_in_flight",
			Help: "Number of requests currently being processed",
		},
		append(commonLabels, "method"),
	)
	
	m.errorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "errors_total",
			Help: "Total number of errors",
		},
		append(commonLabels, "type", "code"),
	)
	
	// gRPC metrics
	m.grpcRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_requests_total",
			Help: "Total number of gRPC requests",
		},
		append(commonLabels, "method", "status"),
	)
	
	m.grpcRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_request_duration_seconds",
			Help:    "gRPC request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		append(commonLabels, "method"),
	)
	
	m.grpcRequestsInFlight = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "grpc_requests_in_flight",
			Help: "Number of gRPC requests currently being processed",
		},
		append(commonLabels, "method"),
	)
	
	// Database metrics
	m.dbConnectionsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "db_connections_active",
			Help: "Number of active database connections",
		},
		append(commonLabels, "database"),
	)
	
	m.dbConnectionsIdle = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "db_connections_idle",
			Help: "Number of idle database connections",
		},
		append(commonLabels, "database"),
	)
	
	m.dbQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		append(commonLabels, "database", "operation"),
	)
	
	m.dbQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "db_queries_total",
			Help: "Total number of database queries",
		},
		append(commonLabels, "database", "operation", "status"),
	)
	
	// Cache metrics
	m.cacheOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_operations_total",
			Help: "Total number of cache operations",
		},
		append(commonLabels, "operation", "cache"),
	)
	
	m.cacheHitsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits",
		},
		append(commonLabels, "cache"),
	)
	
	m.cacheMissesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_misses_total",
			Help: "Total number of cache misses",
		},
		append(commonLabels, "cache"),
	)
	
	// Security metrics
	m.authAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		append(commonLabels, "method", "status"),
	)
	
	m.authFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_failures_total",
			Help: "Total number of authentication failures",
		},
		append(commonLabels, "method", "reason"),
	)
	
	m.securityEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "security_events_total",
			Help: "Total number of security events",
		},
		append(commonLabels, "event_type", "severity"),
	)

	// Register all metrics
	collectors := []prometheus.Collector{
		m.requestsTotal,
		m.requestDuration,
		m.requestsInFlight,
		m.errorTotal,
		m.grpcRequestsTotal,
		m.grpcRequestDuration,
		m.grpcRequestsInFlight,
		m.dbConnectionsActive,
		m.dbConnectionsIdle,
		m.dbQueryDuration,
		m.dbQueriesTotal,
		m.cacheOperationsTotal,
		m.cacheHitsTotal,
		m.cacheMissesTotal,
		m.authAttemptsTotal,
		m.authFailuresTotal,
		m.securityEventsTotal,
	}

	for _, collector := range collectors {
		if err := m.registry.Register(collector); err != nil {
			return fmt.Errorf("failed to register metric: %w", err)
		}
	}

	// Register Go and process metrics if enabled
	if m.config.CollectGoMetrics {
		m.registry.MustRegister(prometheus.NewGoCollector())
	}
	
	if m.config.CollectProcessMetrics {
		m.registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	}

	return nil
}

// getCommonLabels returns common labels for metrics
func (m *Manager) getCommonLabels() prometheus.Labels {
	return prometheus.Labels{
		"service":     m.config.ServiceName,
		"version":     m.config.ServiceVersion,
		"environment": m.config.Environment,
	}
}

// Start starts the metrics server
func (m *Manager) Start() error {
	if !m.config.Enabled {
		m.logger.Info("Metrics collection is disabled")
		return nil
	}

	address := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)
	
	mux := http.NewServeMux()
	mux.Handle(m.config.Path, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))
	
	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	m.server = &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m.logger.Info("Starting metrics server",
		zap.String("address", address),
		zap.String("path", m.config.Path),
	)

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			m.logger.Error("Metrics server failed", zap.Error(err))
		}
	}()

	return nil
}

// Stop stops the metrics server
func (m *Manager) Stop(ctx context.Context) error {
	if m.server == nil {
		return nil
	}

	m.logger.Info("Stopping metrics server")
	return m.server.Shutdown(ctx)
}

// RecordRequest records HTTP request metrics
func (m *Manager) RecordRequest(method, endpoint, statusCode string, duration time.Duration) {
	labels := m.getCommonLabels()
	labels["method"] = method
	labels["endpoint"] = endpoint
	labels["status_code"] = statusCode
	
	m.requestsTotal.With(labels).Inc()
	
	delete(labels, "status_code")
	m.requestDuration.With(labels).Observe(duration.Seconds())
}

// IncRequestsInFlight increments in-flight request counter
func (m *Manager) IncRequestsInFlight(method string) {
	labels := m.getCommonLabels()
	labels["method"] = method
	m.requestsInFlight.With(labels).Inc()
}

// DecRequestsInFlight decrements in-flight request counter
func (m *Manager) DecRequestsInFlight(method string) {
	labels := m.getCommonLabels()
	labels["method"] = method
	m.requestsInFlight.With(labels).Dec()
}

// RecordError records error metrics
func (m *Manager) RecordError(errorType, errorCode string) {
	labels := m.getCommonLabels()
	labels["type"] = errorType
	labels["code"] = errorCode
	m.errorTotal.With(labels).Inc()
}

// RecordGRPCRequest records gRPC request metrics
func (m *Manager) RecordGRPCRequest(method, status string, duration time.Duration) {
	labels := m.getCommonLabels()
	labels["method"] = method
	labels["status"] = status
	
	m.grpcRequestsTotal.With(labels).Inc()
	
	delete(labels, "status")
	m.grpcRequestDuration.With(labels).Observe(duration.Seconds())
}

// RecordDatabaseQuery records database query metrics
func (m *Manager) RecordDatabaseQuery(database, operation, status string, duration time.Duration) {
	labels := m.getCommonLabels()
	labels["database"] = database
	labels["operation"] = operation
	labels["status"] = status
	
	m.dbQueriesTotal.With(labels).Inc()
	
	delete(labels, "status")
	m.dbQueryDuration.With(labels).Observe(duration.Seconds())
}

// SetDatabaseConnections sets database connection metrics
func (m *Manager) SetDatabaseConnections(database string, active, idle int) {
	labels := m.getCommonLabels()
	labels["database"] = database
	
	m.dbConnectionsActive.With(labels).Set(float64(active))
	m.dbConnectionsIdle.With(labels).Set(float64(idle))
}

// RecordCacheOperation records cache operation metrics
func (m *Manager) RecordCacheOperation(operation, cache string, hit bool) {
	labels := m.getCommonLabels()
	labels["operation"] = operation
	labels["cache"] = cache
	
	m.cacheOperationsTotal.With(labels).Inc()
	
	delete(labels, "operation")
	if hit {
		m.cacheHitsTotal.With(labels).Inc()
	} else {
		m.cacheMissesTotal.With(labels).Inc()
	}
}

// RecordAuthAttempt records authentication attempt metrics
func (m *Manager) RecordAuthAttempt(method, status string) {
	labels := m.getCommonLabels()
	labels["method"] = method
	labels["status"] = status
	
	m.authAttemptsTotal.With(labels).Inc()
}

// RecordAuthFailure records authentication failure metrics
func (m *Manager) RecordAuthFailure(method, reason string) {
	labels := m.getCommonLabels()
	labels["method"] = method
	labels["reason"] = reason
	
	m.authFailuresTotal.With(labels).Inc()
}

// RecordSecurityEvent records security event metrics
func (m *Manager) RecordSecurityEvent(eventType, severity string) {
	labels := m.getCommonLabels()
	labels["event_type"] = eventType
	labels["severity"] = severity
	
	m.securityEventsTotal.With(labels).Inc()
}

// CreateCounter creates a custom counter metric
func (m *Manager) CreateCounter(name, help string, labelNames []string) *prometheus.CounterVec {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: name,
			Help: help,
		},
		append([]string{"service", "version", "environment"}, labelNames...),
	)
	
	m.registry.MustRegister(counter)
	m.customCounters[name] = counter
	
	return counter
}

// CreateGauge creates a custom gauge metric
func (m *Manager) CreateGauge(name, help string, labelNames []string) *prometheus.GaugeVec {
	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
		append([]string{"service", "version", "environment"}, labelNames...),
	)
	
	m.registry.MustRegister(gauge)
	m.customGauges[name] = gauge
	
	return gauge
}

// CreateHistogram creates a custom histogram metric
func (m *Manager) CreateHistogram(name, help string, buckets []float64, labelNames []string) *prometheus.HistogramVec {
	if buckets == nil {
		buckets = prometheus.DefBuckets
	}
	
	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    name,
			Help:    help,
			Buckets: buckets,
		},
		append([]string{"service", "version", "environment"}, labelNames...),
	)
	
	m.registry.MustRegister(histogram)
	m.customHistograms[name] = histogram
	
	return histogram
}

// GetRegistry returns the Prometheus registry
func (m *Manager) GetRegistry() *prometheus.Registry {
	return m.registry
}

// DefaultConfig returns a default metrics configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: true,
		Host:    "0.0.0.0",
		Port:    9090,
		Path:    "/metrics",
		
		ServiceName:    "unknown",
		ServiceVersion: "unknown",
		Environment:    "development",
		
		CollectGoMetrics:      true,
		CollectProcessMetrics: true,
		PushInterval:          30 * time.Second,
		
		PushGateway: PushGatewayConfig{
			Enabled: false,
		},
	}
}

// GetServiceMetrics creates a configured metrics manager for a service
func GetServiceMetrics(serviceName, version, environment string) (*Manager, error) {
	config := DefaultConfig()
	config.ServiceName = serviceName
	config.ServiceVersion = version
	config.Environment = environment
	
	return NewManager(config, nil)
}