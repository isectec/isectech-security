package ingestion

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// IngestionCoordinator orchestrates all event ingestion components for iSECTECH
type IngestionCoordinator struct {
	config *CoordinatorConfig
	logger *zap.Logger

	// Core ingestion components
	kafkaIngestion      *KafkaIngestionService
	apiEndpoints        *APIEndpointsHandler
	agentProtocol       *AgentProtocolHandler
	batchProcessor      *BatchProcessor
	rateLimiter         *RateLimitingService
	backpressureManager *BackpressureManager

	// Health and monitoring
	healthChecker    *HealthChecker
	metricsCollector *MetricsCollector
	alertManager     *AlertManager

	// State management
	isRunning  int32
	shutdownCh chan struct{}
	wg         sync.WaitGroup

	// Performance monitoring
	metrics         *CoordinatorMetrics
	lastHealthCheck time.Time
	startTime       time.Time
}

// CoordinatorConfig defines configuration for the ingestion coordinator
type CoordinatorConfig struct {
	// Component Configurations
	KafkaConfig          *KafkaConfig          `json:"kafka_config" validate:"required"`
	APIConfig            *APIConfig            `json:"api_config" validate:"required"`
	AgentProtocolConfig  *AgentProtocolConfig  `json:"agent_protocol_config" validate:"required"`
	BatchProcessorConfig *BatchProcessorConfig `json:"batch_processor_config" validate:"required"`
	RateLimitConfig      *RateLimitConfig      `json:"rate_limit_config" validate:"required"`
	BackpressureConfig   *BackpressureConfig   `json:"backpressure_config" validate:"required"`

	// Health Check Configuration
	HealthCheckConfig *HealthCheckConfig `json:"health_check_config,omitempty"`

	// Metrics Configuration
	MetricsConfig *MetricsConfig `json:"metrics_config,omitempty"`

	// Alert Configuration
	AlertConfig *AlertConfig `json:"alert_config,omitempty"`

	// Coordination Settings
	StartupTimeout      time.Duration `json:"startup_timeout"`       // Default: 60s
	ShutdownTimeout     time.Duration `json:"shutdown_timeout"`      // Default: 30s
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Default: 30s
	MetricsInterval     time.Duration `json:"metrics_interval"`      // Default: 10s

	// Component Dependencies
	ComponentDependencies map[string][]string `json:"component_dependencies,omitempty"`
	StartupOrder          []string            `json:"startup_order,omitempty"`

	// Failure Handling
	ComponentRetries  int           `json:"component_retries"`   // Default: 3
	RetryDelay        time.Duration `json:"retry_delay"`         // Default: 5s
	ContinueOnFailure bool          `json:"continue_on_failure"` // Default: false

	// Performance Tuning
	MaxConcurrentEvents int `json:"max_concurrent_events"` // Default: 10000
	EventBufferSize     int `json:"event_buffer_size"`     // Default: 100000

	// Authentication and Authorization
	AuthProvider AuthenticationProvider `json:"-"`

	// Custom event processors
	EventProcessors []EventProcessor `json:"-"`

	// Hooks and callbacks
	StartupHooks  []StartupHook  `json:"-"`
	ShutdownHooks []ShutdownHook `json:"-"`
	EventHooks    []EventHook    `json:"-"`
}

// HealthCheckConfig defines health check configuration
type HealthCheckConfig struct {
	Enabled       bool          `json:"enabled"`        // Default: true
	Port          int           `json:"port"`           // Default: 8081
	Path          string        `json:"path"`           // Default: /health
	Timeout       time.Duration `json:"timeout"`        // Default: 10s
	CheckInterval time.Duration `json:"check_interval"` // Default: 30s

	// Component-specific checks
	ComponentChecks map[string]ComponentHealthConfig `json:"component_checks,omitempty"`

	// Dependency checks
	ExternalDependencies []ExternalDependency `json:"external_dependencies,omitempty"`
}

// ComponentHealthConfig defines health check for a specific component
type ComponentHealthConfig struct {
	Enabled          bool          `json:"enabled"`
	Timeout          time.Duration `json:"timeout"`
	FailureThreshold int           `json:"failure_threshold"`
	CriticalFailures int           `json:"critical_failures"`
}

// ExternalDependency defines external service dependency
type ExternalDependency struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"` // kafka, database, api
	Endpoint string        `json:"endpoint"`
	Timeout  time.Duration `json:"timeout"`
	Critical bool          `json:"critical"`
}

// MetricsConfig defines metrics collection configuration
type MetricsConfig struct {
	Enabled  bool          `json:"enabled"`  // Default: true
	Port     int           `json:"port"`     // Default: 8082
	Path     string        `json:"path"`     // Default: /metrics
	Format   string        `json:"format"`   // prometheus, json
	Interval time.Duration `json:"interval"` // Default: 10s

	// Metric collection settings
	ComponentMetrics bool `json:"component_metrics"` // Default: true
	SystemMetrics    bool `json:"system_metrics"`    // Default: true
	BusinessMetrics  bool `json:"business_metrics"`  // Default: true

	// Retention and storage
	RetentionPeriod time.Duration `json:"retention_period"` // Default: 24h
	StorageBackend  string        `json:"storage_backend"`  // memory, prometheus, influxdb
}

// AlertConfig defines alerting configuration
type AlertConfig struct {
	Enabled         bool                 `json:"enabled"` // Default: false
	AlertManagers   []AlertManagerConfig `json:"alert_managers,omitempty"`
	DefaultSeverity string               `json:"default_severity"` // Default: warning

	// Alert rules
	Rules []AlertRule `json:"rules,omitempty"`

	// Notification settings
	NotificationChannels []NotificationChannel `json:"notification_channels,omitempty"`
}

// AlertManagerConfig defines alert manager configuration
type AlertManagerConfig struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"` // webhook, email, slack
	Endpoint    string            `json:"endpoint"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

// AlertRule defines an alerting rule
type AlertRule struct {
	Name      string        `json:"name"`
	Condition string        `json:"condition"`
	Threshold float64       `json:"threshold"`
	Duration  time.Duration `json:"duration"`
	Severity  string        `json:"severity"`
	Message   string        `json:"message"`
}

// NotificationChannel defines notification channel
type NotificationChannel struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// CoordinatorMetrics tracks coordinator performance and health
type CoordinatorMetrics struct {
	// Component status
	ComponentStatus map[string]ComponentStatus `json:"component_status"`

	// Overall performance
	TotalEventsProcessed int64         `json:"total_events_processed"`
	EventsPerSecond      float64       `json:"events_per_second"`
	AvgProcessingLatency time.Duration `json:"avg_processing_latency"`

	// Error tracking
	TotalErrors       int64            `json:"total_errors"`
	ErrorRate         float64          `json:"error_rate"`
	ErrorsByComponent map[string]int64 `json:"errors_by_component"`

	// Resource utilization
	CPUUsage    float64           `json:"cpu_usage"`
	MemoryUsage float64           `json:"memory_usage"`
	NetworkIO   *NetworkIOMetrics `json:"network_io"`
	DiskIO      *DiskIOMetrics    `json:"disk_io"`

	// Queue metrics
	QueueMetrics map[string]*QueueMetrics `json:"queue_metrics"`

	// Health metrics
	HealthScore     float64   `json:"health_score"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	LastHealthCheck time.Time `json:"last_health_check"`

	mutex      sync.RWMutex
	lastUpdate time.Time
}

// ComponentStatus represents the status of a component
type ComponentStatus struct {
	Name            string                 `json:"name"`
	Status          string                 `json:"status"` // healthy, degraded, unhealthy, stopped
	LastHealthCheck time.Time              `json:"last_health_check"`
	ErrorCount      int64                  `json:"error_count"`
	StartTime       time.Time              `json:"start_time"`
	LastError       string                 `json:"last_error,omitempty"`
	Metrics         map[string]interface{} `json:"metrics,omitempty"`
}

// NetworkIOMetrics tracks network I/O
type NetworkIOMetrics struct {
	BytesIn    int64 `json:"bytes_in"`
	BytesOut   int64 `json:"bytes_out"`
	PacketsIn  int64 `json:"packets_in"`
	PacketsOut int64 `json:"packets_out"`
	ErrorsIn   int64 `json:"errors_in"`
	ErrorsOut  int64 `json:"errors_out"`
}

// DiskIOMetrics tracks disk I/O
type DiskIOMetrics struct {
	ReadBytes    int64         `json:"read_bytes"`
	WriteBytes   int64         `json:"write_bytes"`
	ReadOps      int64         `json:"read_ops"`
	WriteOps     int64         `json:"write_ops"`
	ReadLatency  time.Duration `json:"read_latency"`
	WriteLatency time.Duration `json:"write_latency"`
}

// Component interfaces

// EventProcessor processes events during ingestion
type EventProcessor interface {
	ProcessEvent(ctx context.Context, event *SecurityEvent) error
	GetName() string
	GetMetrics() map[string]interface{}
}

// Hook interfaces
type StartupHook interface {
	OnStartup(ctx context.Context) error
}

type ShutdownHook interface {
	OnShutdown(ctx context.Context) error
}

type EventHook interface {
	OnEvent(ctx context.Context, event *SecurityEvent) error
}

// HealthChecker manages component health checks
type HealthChecker struct {
	config          *HealthCheckConfig
	coordinator     *IngestionCoordinator
	logger          *zap.Logger
	componentHealth map[string]*ComponentHealth
	overallHealth   HealthStatus
	mutex           sync.RWMutex
}

// ComponentHealth tracks individual component health
type ComponentHealth struct {
	Name                string
	Status              HealthStatus
	LastCheck           time.Time
	ConsecutiveFailures int
	LastError           error
	CheckDuration       time.Duration
}

// HealthStatus represents health status
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// MetricsCollector collects and aggregates metrics from all components
type MetricsCollector struct {
	config      *MetricsConfig
	coordinator *IngestionCoordinator
	logger      *zap.Logger
	metrics     map[string]interface{}
	collectors  []MetricCollector
	mutex       sync.RWMutex
}

// MetricCollector interface for component-specific metric collection
type MetricCollector interface {
	CollectMetrics() map[string]interface{}
	GetName() string
}

// AlertManager manages alerts and notifications
type AlertManager struct {
	config        *AlertConfig
	logger        *zap.Logger
	activeAlerts  map[string]*ActiveAlert
	alertManagers []AlertManagerInterface
	mutex         sync.RWMutex
}

// ActiveAlert represents an active alert
type ActiveAlert struct {
	Rule              *AlertRule
	StartTime         time.Time
	LastNotification  time.Time
	NotificationCount int
	Resolved          bool
}

// AlertManagerInterface defines alert manager interface
type AlertManagerInterface interface {
	SendAlert(alert *ActiveAlert) error
	GetName() string
}

// NewIngestionCoordinator creates a new ingestion coordinator
func NewIngestionCoordinator(config *CoordinatorConfig, logger *zap.Logger) (*IngestionCoordinator, error) {
	if err := validateCoordinatorConfig(config); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	setCoordinatorDefaults(config)

	coordinator := &IngestionCoordinator{
		config:     config,
		logger:     logger,
		shutdownCh: make(chan struct{}),
		metrics:    NewCoordinatorMetrics(),
		startTime:  time.Now(),
	}

	// Initialize components
	if err := coordinator.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	return coordinator, nil
}

// Start initializes and starts all ingestion components in the correct order
func (ic *IngestionCoordinator) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&ic.isRunning, 0, 1) {
		return fmt.Errorf("ingestion coordinator is already running")
	}

	ic.logger.Info("Starting ingestion coordinator")

	// Create startup context with timeout
	startupCtx, cancel := context.WithTimeout(ctx, ic.config.StartupTimeout)
	defer cancel()

	// Execute startup hooks
	for _, hook := range ic.config.StartupHooks {
		if err := hook.OnStartup(startupCtx); err != nil {
			return fmt.Errorf("startup hook failed: %w", err)
		}
	}

	// Start components in dependency order
	startupOrder := ic.getStartupOrder()
	for _, componentName := range startupOrder {
		if err := ic.startComponent(startupCtx, componentName); err != nil {
			if !ic.config.ContinueOnFailure {
				ic.stopAllComponents()
				return fmt.Errorf("failed to start component %s: %w", componentName, err)
			}
			ic.logger.Error("Component failed to start, continuing due to configuration",
				zap.String("component", componentName),
				zap.Error(err))
		}
	}

	// Start monitoring routines
	ic.wg.Add(3)
	go ic.healthCheckLoop()
	go ic.metricsLoop()
	go ic.coordinatorLoop()

	ic.logger.Info("Ingestion coordinator started successfully",
		zap.Duration("startup_time", time.Since(ic.startTime)))

	return nil
}

// Stop gracefully shuts down all ingestion components
func (ic *IngestionCoordinator) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&ic.isRunning, 1, 0) {
		return fmt.Errorf("ingestion coordinator is not running")
	}

	ic.logger.Info("Stopping ingestion coordinator")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, ic.config.ShutdownTimeout)
	defer cancel()

	// Signal shutdown
	close(ic.shutdownCh)

	// Execute shutdown hooks
	for _, hook := range ic.config.ShutdownHooks {
		if err := hook.OnShutdown(shutdownCtx); err != nil {
			ic.logger.Warn("Shutdown hook failed", zap.Error(err))
		}
	}

	// Stop components in reverse order
	ic.stopAllComponents()

	// Wait for monitoring routines to finish
	done := make(chan struct{})
	go func() {
		ic.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		ic.logger.Info("Ingestion coordinator stopped successfully")
		return nil
	case <-shutdownCtx.Done():
		ic.logger.Warn("Ingestion coordinator shutdown timed out")
		return shutdownCtx.Err()
	}
}

// IngestEvent processes a single event through the ingestion pipeline
func (ic *IngestionCoordinator) IngestEvent(ctx context.Context, event *SecurityEvent) error {
	if atomic.LoadInt32(&ic.isRunning) == 0 {
		return fmt.Errorf("ingestion coordinator is not running")
	}

	startTime := time.Now()

	// Check backpressure
	if ic.backpressureManager != nil && ic.backpressureManager.ShouldApplyBackpressure() {
		return fmt.Errorf("system under backpressure")
	}

	// Process through event processors
	for _, processor := range ic.config.EventProcessors {
		if err := processor.ProcessEvent(ctx, event); err != nil {
			ic.logger.Error("Event processor failed",
				zap.String("processor", processor.GetName()),
				zap.Error(err))
			return err
		}
	}

	// Execute event hooks
	for _, hook := range ic.config.EventHooks {
		if err := hook.OnEvent(ctx, event); err != nil {
			ic.logger.Warn("Event hook failed", zap.Error(err))
		}
	}

	// Send to batch processor if available
	if ic.batchProcessor != nil {
		if err := ic.batchProcessor.ProcessEvent(ctx, event); err != nil {
			return fmt.Errorf("batch processor failed: %w", err)
		}
	} else if ic.kafkaIngestion != nil {
		// Direct Kafka ingestion if no batch processing
		if err := ic.kafkaIngestion.IngestEvent(ctx, event); err != nil {
			return fmt.Errorf("kafka ingestion failed: %w", err)
		}
	}

	// Update metrics
	ic.updateEventMetrics(time.Since(startTime))

	return nil
}

// IngestBatch processes a batch of events
func (ic *IngestionCoordinator) IngestBatch(ctx context.Context, batch *EventBatch) error {
	if atomic.LoadInt32(&ic.isRunning) == 0 {
		return fmt.Errorf("ingestion coordinator is not running")
	}

	// Check backpressure
	if ic.backpressureManager != nil && ic.backpressureManager.ShouldApplyBackpressure() {
		return fmt.Errorf("system under backpressure")
	}

	// Send to batch processor if available
	if ic.batchProcessor != nil {
		return ic.batchProcessor.ProcessBatch(ctx, batch)
	} else if ic.kafkaIngestion != nil {
		// Direct Kafka ingestion if no batch processing
		return ic.kafkaIngestion.IngestBatch(ctx, batch)
	}

	return fmt.Errorf("no ingestion backend available")
}

// GetMetrics returns current coordinator metrics
func (ic *IngestionCoordinator) GetMetrics() *CoordinatorMetrics {
	ic.metrics.mutex.RLock()
	defer ic.metrics.mutex.RUnlock()

	// Create a copy
	metrics := *ic.metrics

	// Deep copy maps
	metrics.ComponentStatus = make(map[string]ComponentStatus)
	for name, status := range ic.metrics.ComponentStatus {
		metrics.ComponentStatus[name] = status
	}

	metrics.ErrorsByComponent = make(map[string]int64)
	for component, count := range ic.metrics.ErrorsByComponent {
		metrics.ErrorsByComponent[component] = count
	}

	metrics.QueueMetrics = make(map[string]*QueueMetrics)
	for name, qm := range ic.metrics.QueueMetrics {
		queueMetrics := *qm
		metrics.QueueMetrics[name] = &queueMetrics
	}

	if ic.metrics.NetworkIO != nil {
		networkIO := *ic.metrics.NetworkIO
		metrics.NetworkIO = &networkIO
	}

	if ic.metrics.DiskIO != nil {
		diskIO := *ic.metrics.DiskIO
		metrics.DiskIO = &diskIO
	}

	return &metrics
}

// GetHealthStatus returns the overall health status
func (ic *IngestionCoordinator) GetHealthStatus() HealthStatus {
	if ic.healthChecker != nil {
		return ic.healthChecker.GetOverallHealth()
	}
	return HealthStatusUnknown
}

// Private methods

func (ic *IngestionCoordinator) initializeComponents() error {
	var err error

	// Initialize Kafka ingestion service
	ic.kafkaIngestion, err = NewKafkaIngestionService(ic.config.KafkaConfig, ic.logger.Named("kafka"))
	if err != nil {
		return fmt.Errorf("failed to create Kafka ingestion service: %w", err)
	}

	// Initialize API endpoints handler
	ic.apiEndpoints, err = NewAPIEndpointsHandler(ic.config.APIConfig, ic, ic.config.AuthProvider, ic.logger.Named("api"))
	if err != nil {
		return fmt.Errorf("failed to create API endpoints handler: %w", err)
	}

	// Initialize agent protocol handler
	ic.agentProtocol, err = NewAgentProtocolHandler(ic.config.AgentProtocolConfig, ic, ic.logger.Named("agent"))
	if err != nil {
		return fmt.Errorf("failed to create agent protocol handler: %w", err)
	}

	// Initialize batch processor
	ic.batchProcessor, err = NewBatchProcessor(ic.config.BatchProcessorConfig, ic.kafkaIngestion, ic.logger.Named("batch"))
	if err != nil {
		return fmt.Errorf("failed to create batch processor: %w", err)
	}

	// Initialize rate limiter
	ic.rateLimiter, err = NewRateLimitingService(ic.config.RateLimitConfig, ic.logger.Named("ratelimit"))
	if err != nil {
		return fmt.Errorf("failed to create rate limiting service: %w", err)
	}

	// Initialize backpressure manager
	ic.backpressureManager, err = NewBackpressureManager(ic.config.BackpressureConfig, ic.logger.Named("backpressure"))
	if err != nil {
		return fmt.Errorf("failed to create backpressure manager: %w", err)
	}

	// Initialize health checker
	if ic.config.HealthCheckConfig != nil && ic.config.HealthCheckConfig.Enabled {
		ic.healthChecker = NewHealthChecker(ic.config.HealthCheckConfig, ic, ic.logger.Named("health"))
	}

	// Initialize metrics collector
	if ic.config.MetricsConfig != nil && ic.config.MetricsConfig.Enabled {
		ic.metricsCollector = NewMetricsCollector(ic.config.MetricsConfig, ic, ic.logger.Named("metrics"))
	}

	// Initialize alert manager
	if ic.config.AlertConfig != nil && ic.config.AlertConfig.Enabled {
		ic.alertManager = NewAlertManager(ic.config.AlertConfig, ic.logger.Named("alerts"))
	}

	return nil
}

func (ic *IngestionCoordinator) getStartupOrder() []string {
	if len(ic.config.StartupOrder) > 0 {
		return ic.config.StartupOrder
	}

	// Default startup order based on dependencies
	return []string{
		"backpressure_manager",
		"rate_limiter",
		"kafka_ingestion",
		"batch_processor",
		"agent_protocol",
		"api_endpoints",
		"health_checker",
		"metrics_collector",
		"alert_manager",
	}
}

func (ic *IngestionCoordinator) startComponent(ctx context.Context, componentName string) error {
	ic.logger.Info("Starting component", zap.String("component", componentName))

	var err error
	retries := 0

	for retries <= ic.config.ComponentRetries {
		switch componentName {
		case "kafka_ingestion":
			err = ic.kafkaIngestion.Start(ctx)
		case "api_endpoints":
			err = ic.apiEndpoints.Start(ctx)
		case "agent_protocol":
			err = ic.agentProtocol.Start(ctx)
		case "batch_processor":
			err = ic.batchProcessor.Start(ctx)
		case "rate_limiter":
			err = ic.rateLimiter.Start(ctx)
		case "backpressure_manager":
			err = ic.backpressureManager.Start(ctx)
		case "health_checker":
			if ic.healthChecker != nil {
				err = ic.healthChecker.Start(ctx)
			}
		case "metrics_collector":
			if ic.metricsCollector != nil {
				err = ic.metricsCollector.Start(ctx)
			}
		case "alert_manager":
			if ic.alertManager != nil {
				err = ic.alertManager.Start(ctx)
			}
		default:
			return fmt.Errorf("unknown component: %s", componentName)
		}

		if err == nil {
			ic.updateComponentStatus(componentName, "healthy", "")
			ic.logger.Info("Component started successfully", zap.String("component", componentName))
			return nil
		}

		retries++
		if retries <= ic.config.ComponentRetries {
			ic.logger.Warn("Component failed to start, retrying",
				zap.String("component", componentName),
				zap.Int("retry", retries),
				zap.Error(err))

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(ic.config.RetryDelay):
				// Continue to retry
			}
		}
	}

	ic.updateComponentStatus(componentName, "unhealthy", err.Error())
	return err
}

func (ic *IngestionCoordinator) stopAllComponents() {
	components := []string{
		"alert_manager",
		"metrics_collector",
		"health_checker",
		"api_endpoints",
		"agent_protocol",
		"batch_processor",
		"kafka_ingestion",
		"rate_limiter",
		"backpressure_manager",
	}

	ctx, cancel := context.WithTimeout(context.Background(), ic.config.ShutdownTimeout)
	defer cancel()

	for _, componentName := range components {
		ic.stopComponent(ctx, componentName)
	}
}

func (ic *IngestionCoordinator) stopComponent(ctx context.Context, componentName string) {
	ic.logger.Info("Stopping component", zap.String("component", componentName))

	var err error

	switch componentName {
	case "kafka_ingestion":
		if ic.kafkaIngestion != nil {
			err = ic.kafkaIngestion.Stop(ctx)
		}
	case "api_endpoints":
		if ic.apiEndpoints != nil {
			err = ic.apiEndpoints.Stop(ctx)
		}
	case "agent_protocol":
		if ic.agentProtocol != nil {
			err = ic.agentProtocol.Stop(ctx)
		}
	case "batch_processor":
		if ic.batchProcessor != nil {
			err = ic.batchProcessor.Stop(ctx)
		}
	case "rate_limiter":
		if ic.rateLimiter != nil {
			err = ic.rateLimiter.Stop(ctx)
		}
	case "backpressure_manager":
		if ic.backpressureManager != nil {
			err = ic.backpressureManager.Stop(ctx)
		}
	case "health_checker":
		if ic.healthChecker != nil {
			err = ic.healthChecker.Stop(ctx)
		}
	case "metrics_collector":
		if ic.metricsCollector != nil {
			err = ic.metricsCollector.Stop(ctx)
		}
	case "alert_manager":
		if ic.alertManager != nil {
			err = ic.alertManager.Stop(ctx)
		}
	}

	if err != nil {
		ic.logger.Warn("Component failed to stop gracefully",
			zap.String("component", componentName),
			zap.Error(err))
		ic.updateComponentStatus(componentName, "unhealthy", err.Error())
	} else {
		ic.updateComponentStatus(componentName, "stopped", "")
		ic.logger.Info("Component stopped successfully", zap.String("component", componentName))
	}
}

func (ic *IngestionCoordinator) healthCheckLoop() {
	defer ic.wg.Done()

	ticker := time.NewTicker(ic.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ic.performHealthChecks()
		case <-ic.shutdownCh:
			return
		}
	}
}

func (ic *IngestionCoordinator) performHealthChecks() {
	if ic.healthChecker != nil {
		ic.healthChecker.PerformHealthChecks()
	}

	ic.lastHealthCheck = time.Now()
}

func (ic *IngestionCoordinator) metricsLoop() {
	defer ic.wg.Done()

	ticker := time.NewTicker(ic.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ic.collectMetrics()
		case <-ic.shutdownCh:
			return
		}
	}
}

func (ic *IngestionCoordinator) collectMetrics() {
	if ic.metricsCollector != nil {
		ic.metricsCollector.CollectAllMetrics()
	}

	ic.updateCoordinatorMetrics()
}

func (ic *IngestionCoordinator) coordinatorLoop() {
	defer ic.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ic.performCoordinatorTasks()
		case <-ic.shutdownCh:
			return
		}
	}
}

func (ic *IngestionCoordinator) performCoordinatorTasks() {
	// Update system metrics for backpressure manager
	if ic.backpressureManager != nil {
		metrics := ic.collectSystemMetrics()
		ic.backpressureManager.UpdateSystemMetrics(metrics)
	}

	// Update queue metrics for backpressure manager
	if ic.backpressureManager != nil && ic.batchProcessor != nil {
		batchMetrics := ic.batchProcessor.GetMetrics()
		ic.backpressureManager.UpdateQueueMetrics("batch_queue", int64(batchMetrics.BatchQueueDepth), int64(ic.config.BatchProcessorConfig.BatchQueueSize))
		ic.backpressureManager.UpdateQueueMetrics("event_queue", int64(batchMetrics.EventQueueDepth), int64(ic.config.BatchProcessorConfig.EventQueueSize))
	}

	// Check for alerts
	if ic.alertManager != nil {
		ic.alertManager.CheckAlerts(ic.GetMetrics())
	}
}

func (ic *IngestionCoordinator) collectSystemMetrics() *SystemMetrics {
	// Simplified implementation - would collect actual system metrics
	return &SystemMetrics{
		CPUUsage:       0.15, // 15%
		MemoryUsage:    0.35, // 35%
		ResponseTime:   100 * time.Millisecond,
		ErrorRate:      0.01, // 1%
		QueueDepth:     100,
		ActiveRequests: 50,
		LastUpdate:     time.Now(),
	}
}

func (ic *IngestionCoordinator) updateComponentStatus(name, status, lastError string) {
	ic.metrics.mutex.Lock()
	defer ic.metrics.mutex.Unlock()

	if ic.metrics.ComponentStatus == nil {
		ic.metrics.ComponentStatus = make(map[string]ComponentStatus)
	}

	current := ic.metrics.ComponentStatus[name]
	current.Name = name
	current.Status = status
	current.LastHealthCheck = time.Now()
	current.LastError = lastError

	if status != "healthy" {
		current.ErrorCount++
	}

	ic.metrics.ComponentStatus[name] = current
}

func (ic *IngestionCoordinator) updateEventMetrics(processingLatency time.Duration) {
	ic.metrics.mutex.Lock()
	defer ic.metrics.mutex.Unlock()

	ic.metrics.TotalEventsProcessed++

	// Update average processing latency
	if ic.metrics.TotalEventsProcessed > 0 {
		total := ic.metrics.TotalEventsProcessed
		ic.metrics.AvgProcessingLatency = (ic.metrics.AvgProcessingLatency*time.Duration(total-1) + processingLatency) / time.Duration(total)
	}
}

func (ic *IngestionCoordinator) updateCoordinatorMetrics() {
	ic.metrics.mutex.Lock()
	defer ic.metrics.mutex.Unlock()

	now := time.Now()

	// Update uptime
	ic.metrics.UptimeSeconds = int64(now.Sub(ic.startTime).Seconds())

	// Update events per second
	duration := now.Sub(ic.metrics.lastUpdate)
	if duration > 0 {
		ic.metrics.EventsPerSecond = float64(ic.metrics.TotalEventsProcessed) / duration.Seconds()
	}

	// Update error rate
	if ic.metrics.TotalEventsProcessed > 0 {
		ic.metrics.ErrorRate = float64(ic.metrics.TotalErrors) / float64(ic.metrics.TotalEventsProcessed)
	}

	// Calculate health score
	ic.metrics.HealthScore = ic.calculateHealthScore()

	// Update resource metrics
	systemMetrics := ic.collectSystemMetrics()
	ic.metrics.CPUUsage = systemMetrics.CPUUsage
	ic.metrics.MemoryUsage = systemMetrics.MemoryUsage

	ic.metrics.lastUpdate = now
}

func (ic *IngestionCoordinator) calculateHealthScore() float64 {
	if len(ic.metrics.ComponentStatus) == 0 {
		return 0.0
	}

	healthyComponents := 0
	for _, status := range ic.metrics.ComponentStatus {
		if status.Status == "healthy" {
			healthyComponents++
		}
	}

	return float64(healthyComponents) / float64(len(ic.metrics.ComponentStatus)) * 100.0
}

// Utility functions

func validateCoordinatorConfig(config *CoordinatorConfig) error {
	if config.KafkaConfig == nil {
		return fmt.Errorf("kafka configuration is required")
	}
	if config.APIConfig == nil {
		return fmt.Errorf("API configuration is required")
	}
	if config.AgentProtocolConfig == nil {
		return fmt.Errorf("agent protocol configuration is required")
	}
	return nil
}

func setCoordinatorDefaults(config *CoordinatorConfig) {
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 60 * time.Second
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 30 * time.Second
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 10 * time.Second
	}
	if config.ComponentRetries == 0 {
		config.ComponentRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.MaxConcurrentEvents == 0 {
		config.MaxConcurrentEvents = 10000
	}
	if config.EventBufferSize == 0 {
		config.EventBufferSize = 100000
	}
}

func NewCoordinatorMetrics() *CoordinatorMetrics {
	return &CoordinatorMetrics{
		ComponentStatus:   make(map[string]ComponentStatus),
		ErrorsByComponent: make(map[string]int64),
		QueueMetrics:      make(map[string]*QueueMetrics),
		lastUpdate:        time.Now(),
	}
}

// Placeholder implementations for health checker, metrics collector, and alert manager

func NewHealthChecker(config *HealthCheckConfig, coordinator *IngestionCoordinator, logger *zap.Logger) *HealthChecker {
	return &HealthChecker{
		config:          config,
		coordinator:     coordinator,
		logger:          logger,
		componentHealth: make(map[string]*ComponentHealth),
		overallHealth:   HealthStatusUnknown,
	}
}

func (hc *HealthChecker) Start(ctx context.Context) error {
	// Implementation would start health check HTTP server
	return nil
}

func (hc *HealthChecker) Stop(ctx context.Context) error {
	// Implementation would stop health check HTTP server
	return nil
}

func (hc *HealthChecker) PerformHealthChecks() {
	// Implementation would check each component health
}

func (hc *HealthChecker) GetOverallHealth() HealthStatus {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()
	return hc.overallHealth
}

func NewMetricsCollector(config *MetricsConfig, coordinator *IngestionCoordinator, logger *zap.Logger) *MetricsCollector {
	return &MetricsCollector{
		config:      config,
		coordinator: coordinator,
		logger:      logger,
		metrics:     make(map[string]interface{}),
	}
}

func (mc *MetricsCollector) Start(ctx context.Context) error {
	// Implementation would start metrics HTTP server
	return nil
}

func (mc *MetricsCollector) Stop(ctx context.Context) error {
	// Implementation would stop metrics HTTP server
	return nil
}

func (mc *MetricsCollector) CollectAllMetrics() {
	// Implementation would collect metrics from all components
}

func NewAlertManager(config *AlertConfig, logger *zap.Logger) *AlertManager {
	return &AlertManager{
		config:       config,
		logger:       logger,
		activeAlerts: make(map[string]*ActiveAlert),
	}
}

func (am *AlertManager) Start(ctx context.Context) error {
	// Implementation would start alert processing
	return nil
}

func (am *AlertManager) Stop(ctx context.Context) error {
	// Implementation would stop alert processing
	return nil
}

func (am *AlertManager) CheckAlerts(metrics *CoordinatorMetrics) {
	// Implementation would check alert rules against metrics
}
