package ingestion

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// BackpressureManager manages system backpressure to prevent overload in iSECTECH event ingestion
type BackpressureManager struct {
	config *BackpressureConfig
	logger *zap.Logger

	// Circuit breaker components
	circuitBreaker *CircuitBreaker

	// Adaptive backpressure
	adaptiveMonitor *AdaptiveMonitor

	// Pressure indicators
	currentPressure   int64 // 0-100 percentage
	isBackpressure    bool
	lastPressureCheck time.Time

	// System monitoring
	systemMonitor   *SystemMonitor
	queueMonitors   map[string]*QueueMonitor
	resourceMonitor *ResourceMonitor

	// State management
	isRunning  bool
	shutdownCh chan struct{}
	mutex      sync.RWMutex

	// Metrics and thresholds
	metrics    *BackpressureMetrics
	thresholds *BackpressureThresholds

	// Pressure relief strategies
	strategies     []PressureReliefStrategy
	activeStrategy PressureReliefStrategy
}

// BackpressureConfig defines configuration for backpressure management
type BackpressureConfig struct {
	// Enable/Disable Features
	Enabled               bool `json:"enabled"`                 // Default: true
	AdaptiveEnabled       bool `json:"adaptive_enabled"`        // Default: true
	CircuitBreakerEnabled bool `json:"circuit_breaker_enabled"` // Default: true

	// Pressure Thresholds
	LowPressureThreshold      int `json:"low_pressure_threshold"`      // Default: 30%
	MediumPressureThreshold   int `json:"medium_pressure_threshold"`   // Default: 60%
	HighPressureThreshold     int `json:"high_pressure_threshold"`     // Default: 80%
	CriticalPressureThreshold int `json:"critical_pressure_threshold"` // Default: 95%

	// Queue Monitoring
	QueueHighWaterMark int     `json:"queue_high_water_mark"` // Default: 100000
	QueueCriticalMark  int     `json:"queue_critical_mark"`   // Default: 500000
	MaxQueueGrowthRate float64 `json:"max_queue_growth_rate"` // Default: 100/sec

	// Resource Monitoring
	MaxCPUUsage     float64 `json:"max_cpu_usage"`     // Default: 0.85 (85%)
	MaxMemoryUsage  float64 `json:"max_memory_usage"`  // Default: 0.90 (90%)
	MaxDiskUsage    float64 `json:"max_disk_usage"`    // Default: 0.80 (80%)
	MaxNetworkUsage float64 `json:"max_network_usage"` // Default: 0.80 (80%)

	// Response Times
	MaxResponseTime time.Duration `json:"max_response_time"` // Default: 2s
	ResponseTimeP95 time.Duration `json:"response_time_p95"` // Default: 1s
	ResponseTimeP99 time.Duration `json:"response_time_p99"` // Default: 500ms

	// Error Rates
	MaxErrorRate    float64       `json:"max_error_rate"`    // Default: 0.05 (5%)
	ErrorRateWindow time.Duration `json:"error_rate_window"` // Default: 5m

	// Circuit Breaker Settings
	CircuitBreakerConfig *CircuitBreakerConfig `json:"circuit_breaker_config,omitempty"`

	// Adaptive Settings
	AdaptiveConfig *AdaptiveBackpressureConfig `json:"adaptive_config,omitempty"`

	// Monitoring Intervals
	MonitoringInterval  time.Duration `json:"monitoring_interval"`   // Default: 1s
	MetricsInterval     time.Duration `json:"metrics_interval"`      // Default: 10s
	ReliefCheckInterval time.Duration `json:"relief_check_interval"` // Default: 5s

	// Relief Strategies
	ReliefStrategies []ReliefStrategyConfig `json:"relief_strategies,omitempty"`
	DefaultStrategy  string                 `json:"default_strategy"` // Default: "graceful_degradation"

	// Recovery Settings
	RecoveryTimeout   time.Duration `json:"recovery_timeout"`   // Default: 30s
	RecoveryThreshold int           `json:"recovery_threshold"` // Default: 50%
	GradualRecovery   bool          `json:"gradual_recovery"`   // Default: true
	RecoverySteps     int           `json:"recovery_steps"`     // Default: 5

	// Notification Settings
	AlertEnabled    bool   `json:"alert_enabled"`    // Default: true
	AlertThresholds []int  `json:"alert_thresholds"` // Default: [70, 85, 95]
	WebhookURL      string `json:"webhook_url,omitempty"`
}

// CircuitBreakerConfig defines circuit breaker configuration
type CircuitBreakerConfig struct {
	FailureThreshold int           `json:"failure_threshold"` // Default: 10
	SuccessThreshold int           `json:"success_threshold"` // Default: 5
	Timeout          time.Duration `json:"timeout"`           // Default: 60s
	MaxRequests      int           `json:"max_requests"`      // Default: 3
	Interval         time.Duration `json:"interval"`          // Default: 10s
}

// AdaptiveBackpressureConfig defines adaptive backpressure configuration
type AdaptiveBackpressureConfig struct {
	LearningPeriod    time.Duration `json:"learning_period"`    // Default: 10m
	AdjustmentFactor  float64       `json:"adjustment_factor"`  // Default: 0.1
	SensitivityFactor float64       `json:"sensitivity_factor"` // Default: 1.0
	PredictionWindow  time.Duration `json:"prediction_window"`  // Default: 30s
	EnablePrediction  bool          `json:"enable_prediction"`  // Default: true
	MLEnabled         bool          `json:"ml_enabled"`         // Default: false
}

// ReliefStrategyConfig defines pressure relief strategy configuration
type ReliefStrategyConfig struct {
	Name       string                 `json:"name"`
	Type       string                 `json:"type"` // graceful_degradation, load_shedding, throttling
	Priority   int                    `json:"priority"`
	Threshold  int                    `json:"threshold"` // Pressure level to activate
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// BackpressureThresholds defines operational thresholds
type BackpressureThresholds struct {
	QueueDepth   *Threshold `json:"queue_depth"`
	ResponseTime *Threshold `json:"response_time"`
	ErrorRate    *Threshold `json:"error_rate"`
	CPUUsage     *Threshold `json:"cpu_usage"`
	MemoryUsage  *Threshold `json:"memory_usage"`
	NetworkUsage *Threshold `json:"network_usage"`
	DiskUsage    *Threshold `json:"disk_usage"`
}

// Threshold defines a monitoring threshold
type Threshold struct {
	Warning   float64 `json:"warning"`
	Critical  float64 `json:"critical"`
	Emergency float64 `json:"emergency"`
	Unit      string  `json:"unit"`
}

// CircuitBreaker implements circuit breaker pattern for backpressure
type CircuitBreaker struct {
	config          *CircuitBreakerConfig
	state           CircuitBreakerState
	failureCount    int64
	successCount    int64
	lastFailureTime time.Time
	nextAttempt     time.Time
	mutex           sync.RWMutex
}

// CircuitBreakerState represents circuit breaker states
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// AdaptiveMonitor provides adaptive backpressure monitoring
type AdaptiveMonitor struct {
	config            *AdaptiveBackpressureConfig
	pressureHistory   []PressureReading
	predictedPressure float64
	adaptationRate    float64
	learningPhase     bool
	learningStart     time.Time
	mutex             sync.RWMutex
}

// PressureReading represents a pressure measurement
type PressureReading struct {
	Timestamp    time.Time     `json:"timestamp"`
	Pressure     float64       `json:"pressure"`
	QueueDepth   int           `json:"queue_depth"`
	ResponseTime time.Duration `json:"response_time"`
	ErrorRate    float64       `json:"error_rate"`
	CPUUsage     float64       `json:"cpu_usage"`
	MemoryUsage  float64       `json:"memory_usage"`
}

// SystemMonitor monitors overall system health
type SystemMonitor struct {
	cpuUsage     float64
	memoryUsage  float64
	diskUsage    float64
	networkUsage float64
	lastUpdate   time.Time
	mutex        sync.RWMutex
}

// QueueMonitor monitors queue metrics
type QueueMonitor struct {
	name           string
	depth          int64
	growthRate     float64
	maxDepth       int64
	lastUpdate     time.Time
	alertThreshold int64
	mutex          sync.RWMutex
}

// ResourceMonitor monitors system resources
type ResourceMonitor struct {
	metrics     *SystemMetrics
	thresholds  *BackpressureThresholds
	alertActive map[string]bool
	lastAlert   map[string]time.Time
	mutex       sync.RWMutex
}

// BackpressureMetrics tracks backpressure management metrics
type BackpressureMetrics struct {
	CurrentPressure     int   `json:"current_pressure"`
	PressureHistory     []int `json:"pressure_history"`
	BackpressureEvents  int64 `json:"backpressure_events"`
	ReliefActivations   int64 `json:"relief_activations"`
	CircuitBreakerTrips int64 `json:"circuit_breaker_trips"`

	AvgRecoveryTime   time.Duration `json:"avg_recovery_time"`
	MaxPressure       int           `json:"max_pressure"`
	TimeUnderPressure time.Duration `json:"time_under_pressure"`

	QueueMetrics    map[string]*QueueMetrics `json:"queue_metrics"`
	ResourceMetrics *ResourceMetrics         `json:"resource_metrics"`

	AdaptiveMetrics *AdaptiveMetrics `json:"adaptive_metrics,omitempty"`

	mutex      sync.RWMutex
	lastUpdate time.Time
}

// QueueMetrics tracks queue-specific metrics
type QueueMetrics struct {
	Depth             int64   `json:"depth"`
	MaxDepth          int64   `json:"max_depth"`
	GrowthRate        float64 `json:"growth_rate"`
	Throughput        float64 `json:"throughput"`
	BackpressureCount int64   `json:"backpressure_count"`
}

// ResourceMetrics tracks resource utilization
type ResourceMetrics struct {
	CPUUsage     float64       `json:"cpu_usage"`
	MemoryUsage  float64       `json:"memory_usage"`
	DiskUsage    float64       `json:"disk_usage"`
	NetworkUsage float64       `json:"network_usage"`
	ResponseTime time.Duration `json:"response_time"`
	ErrorRate    float64       `json:"error_rate"`
}

// AdaptiveMetrics tracks adaptive backpressure metrics
type AdaptiveMetrics struct {
	PredictionAccuracy float64 `json:"prediction_accuracy"`
	AdaptationRate     float64 `json:"adaptation_rate"`
	LearningProgress   float64 `json:"learning_progress"`
	PredictedPressure  float64 `json:"predicted_pressure"`
}

// PressureReliefStrategy defines interface for pressure relief strategies
type PressureReliefStrategy interface {
	Name() string
	Type() string
	Activate(pressure int) error
	Deactivate() error
	IsActive() bool
	GetMetrics() map[string]interface{}
}

// NewBackpressureManager creates a new backpressure manager
func NewBackpressureManager(config *BackpressureConfig, logger *zap.Logger) (*BackpressureManager, error) {
	if err := validateBackpressureConfig(config); err != nil {
		return nil, fmt.Errorf("invalid backpressure configuration: %w", err)
	}

	setBackpressureDefaults(config)

	manager := &BackpressureManager{
		config:            config,
		logger:            logger,
		shutdownCh:        make(chan struct{}),
		queueMonitors:     make(map[string]*QueueMonitor),
		metrics:           NewBackpressureMetrics(),
		lastPressureCheck: time.Now(),
	}

	// Initialize thresholds
	manager.thresholds = createThresholds(config)

	// Initialize circuit breaker
	if config.CircuitBreakerEnabled {
		manager.circuitBreaker = NewCircuitBreaker(config.CircuitBreakerConfig)
	}

	// Initialize adaptive monitor
	if config.AdaptiveEnabled {
		manager.adaptiveMonitor = NewAdaptiveMonitor(config.AdaptiveConfig)
	}

	// Initialize system monitor
	manager.systemMonitor = NewSystemMonitor()
	manager.resourceMonitor = NewResourceMonitor(manager.thresholds)

	// Initialize relief strategies
	if err := manager.initializeReliefStrategies(); err != nil {
		return nil, fmt.Errorf("failed to initialize relief strategies: %w", err)
	}

	return manager, nil
}

// Start initializes and starts the backpressure manager
func (bm *BackpressureManager) Start(ctx context.Context) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if bm.isRunning {
		return fmt.Errorf("backpressure manager is already running")
	}

	bm.logger.Info("Starting backpressure manager",
		zap.Bool("adaptive_enabled", bm.config.AdaptiveEnabled),
		zap.Bool("circuit_breaker_enabled", bm.config.CircuitBreakerEnabled))

	// Start monitoring routines
	go bm.monitoringLoop()
	go bm.metricsLoop()
	go bm.reliefCheckLoop()

	bm.isRunning = true
	bm.logger.Info("Backpressure manager started successfully")
	return nil
}

// Stop gracefully shuts down the backpressure manager
func (bm *BackpressureManager) Stop(ctx context.Context) error {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if !bm.isRunning {
		return fmt.Errorf("backpressure manager is not running")
	}

	bm.logger.Info("Stopping backpressure manager")

	// Signal shutdown
	close(bm.shutdownCh)

	// Deactivate active relief strategies
	if bm.activeStrategy != nil {
		bm.activeStrategy.Deactivate()
	}

	bm.isRunning = false
	bm.logger.Info("Backpressure manager stopped successfully")
	return nil
}

// ShouldApplyBackpressure checks if backpressure should be applied
func (bm *BackpressureManager) ShouldApplyBackpressure() bool {
	if !bm.config.Enabled {
		return false
	}

	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	return bm.isBackpressure
}

// GetCurrentPressure returns the current pressure level (0-100)
func (bm *BackpressureManager) GetCurrentPressure() int {
	return int(atomic.LoadInt64(&bm.currentPressure))
}

// UpdateQueueMetrics updates queue depth metrics
func (bm *BackpressureManager) UpdateQueueMetrics(queueName string, depth int64, maxDepth int64) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	monitor, exists := bm.queueMonitors[queueName]
	if !exists {
		monitor = &QueueMonitor{
			name:           queueName,
			alertThreshold: int64(float64(maxDepth) * 0.8), // 80% of max
		}
		bm.queueMonitors[queueName] = monitor
	}

	monitor.mutex.Lock()
	oldDepth := monitor.depth
	monitor.depth = depth
	monitor.maxDepth = maxDepth

	// Calculate growth rate
	now := time.Now()
	if !monitor.lastUpdate.IsZero() {
		timeDelta := now.Sub(monitor.lastUpdate).Seconds()
		if timeDelta > 0 {
			monitor.growthRate = float64(depth-oldDepth) / timeDelta
		}
	}
	monitor.lastUpdate = now
	monitor.mutex.Unlock()
}

// UpdateSystemMetrics updates system resource metrics
func (bm *BackpressureManager) UpdateSystemMetrics(metrics *SystemMetrics) {
	bm.systemMonitor.mutex.Lock()
	bm.systemMonitor.cpuUsage = metrics.CPUUsage
	bm.systemMonitor.memoryUsage = metrics.MemoryUsage
	bm.systemMonitor.lastUpdate = time.Now()
	bm.systemMonitor.mutex.Unlock()

	// Update resource monitor
	bm.resourceMonitor.UpdateMetrics(metrics)
}

// GetMetrics returns current backpressure metrics
func (bm *BackpressureManager) GetMetrics() *BackpressureMetrics {
	bm.metrics.mutex.RLock()
	defer bm.metrics.mutex.RUnlock()

	// Create a copy
	metrics := *bm.metrics
	metrics.PressureHistory = make([]int, len(bm.metrics.PressureHistory))
	copy(metrics.PressureHistory, bm.metrics.PressureHistory)

	metrics.QueueMetrics = make(map[string]*QueueMetrics)
	for name, qm := range bm.metrics.QueueMetrics {
		queueMetrics := *qm
		metrics.QueueMetrics[name] = &queueMetrics
	}

	if bm.metrics.ResourceMetrics != nil {
		resourceMetrics := *bm.metrics.ResourceMetrics
		metrics.ResourceMetrics = &resourceMetrics
	}

	if bm.metrics.AdaptiveMetrics != nil {
		adaptiveMetrics := *bm.metrics.AdaptiveMetrics
		metrics.AdaptiveMetrics = &adaptiveMetrics
	}

	return &metrics
}

// Private methods

func (bm *BackpressureManager) monitoringLoop() {
	ticker := time.NewTicker(bm.config.MonitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.calculatePressure()
		case <-bm.shutdownCh:
			return
		}
	}
}

func (bm *BackpressureManager) calculatePressure() {
	now := time.Now()

	// Calculate pressure from multiple factors
	queuePressure := bm.calculateQueuePressure()
	resourcePressure := bm.calculateResourcePressure()
	responsePressure := bm.calculateResponsePressure()
	errorPressure := bm.calculateErrorPressure()

	// Weighted combination of pressure factors
	totalPressure := (queuePressure*0.3 + resourcePressure*0.4 + responsePressure*0.2 + errorPressure*0.1)

	// Apply adaptive adjustments if enabled
	if bm.adaptiveMonitor != nil {
		totalPressure = bm.adaptiveMonitor.AdjustPressure(totalPressure)
	}

	// Ensure pressure is within bounds
	if totalPressure < 0 {
		totalPressure = 0
	} else if totalPressure > 100 {
		totalPressure = 100
	}

	// Update current pressure
	oldPressure := atomic.SwapInt64(&bm.currentPressure, int64(totalPressure))

	// Check if backpressure state should change
	shouldBackpressure := totalPressure >= float64(bm.config.HighPressureThreshold)

	bm.mutex.Lock()
	wasBackpressure := bm.isBackpressure
	bm.isBackpressure = shouldBackpressure
	bm.lastPressureCheck = now
	bm.mutex.Unlock()

	// Log pressure changes
	if shouldBackpressure != wasBackpressure {
		if shouldBackpressure {
			bm.logger.Warn("Backpressure activated",
				zap.Float64("pressure", totalPressure),
				zap.Float64("queue_pressure", queuePressure),
				zap.Float64("resource_pressure", resourcePressure))

			atomic.AddInt64(&bm.metrics.BackpressureEvents, 1)
		} else {
			bm.logger.Info("Backpressure deactivated",
				zap.Float64("pressure", totalPressure))
		}
	}

	// Update pressure history
	bm.updatePressureHistory(int(totalPressure))

	// Record pressure reading for adaptive learning
	if bm.adaptiveMonitor != nil {
		reading := PressureReading{
			Timestamp:    now,
			Pressure:     totalPressure,
			QueueDepth:   bm.getTotalQueueDepth(),
			ResponseTime: bm.getAverageResponseTime(),
			ErrorRate:    bm.getCurrentErrorRate(),
			CPUUsage:     bm.systemMonitor.cpuUsage,
			MemoryUsage:  bm.systemMonitor.memoryUsage,
		}
		bm.adaptiveMonitor.RecordReading(reading)
	}

	// Check circuit breaker if enabled
	if bm.circuitBreaker != nil && shouldBackpressure {
		bm.circuitBreaker.RecordFailure()
	} else if bm.circuitBreaker != nil && !shouldBackpressure {
		bm.circuitBreaker.RecordSuccess()
	}

	// Log significant pressure changes
	if abs(int(totalPressure)-int(oldPressure)) > 10 {
		bm.logger.Debug("Pressure change detected",
			zap.Float64("old_pressure", float64(oldPressure)),
			zap.Float64("new_pressure", totalPressure),
			zap.Float64("queue_pressure", queuePressure),
			zap.Float64("resource_pressure", resourcePressure),
			zap.Float64("response_pressure", responsePressure),
			zap.Float64("error_pressure", errorPressure))
	}
}

func (bm *BackpressureManager) calculateQueuePressure() float64 {
	maxPressure := 0.0

	bm.mutex.RLock()
	for _, monitor := range bm.queueMonitors {
		monitor.mutex.RLock()
		if monitor.maxDepth > 0 {
			utilization := float64(monitor.depth) / float64(monitor.maxDepth)
			pressure := utilization * 100
			if pressure > maxPressure {
				maxPressure = pressure
			}
		}
		monitor.mutex.RUnlock()
	}
	bm.mutex.RUnlock()

	return maxPressure
}

func (bm *BackpressureManager) calculateResourcePressure() float64 {
	bm.systemMonitor.mutex.RLock()
	defer bm.systemMonitor.mutex.RUnlock()

	cpuPressure := bm.systemMonitor.cpuUsage * 100
	memoryPressure := bm.systemMonitor.memoryUsage * 100

	// Return the highest resource pressure
	maxPressure := cpuPressure
	if memoryPressure > maxPressure {
		maxPressure = memoryPressure
	}

	return maxPressure
}

func (bm *BackpressureManager) calculateResponsePressure() float64 {
	// Simplified implementation - would integrate with actual response time metrics
	return 0.0
}

func (bm *BackpressureManager) calculateErrorPressure() float64 {
	// Simplified implementation - would integrate with actual error rate metrics
	return 0.0
}

func (bm *BackpressureManager) getTotalQueueDepth() int {
	total := 0
	bm.mutex.RLock()
	for _, monitor := range bm.queueMonitors {
		monitor.mutex.RLock()
		total += int(monitor.depth)
		monitor.mutex.RUnlock()
	}
	bm.mutex.RUnlock()
	return total
}

func (bm *BackpressureManager) getAverageResponseTime() time.Duration {
	// Simplified implementation
	return 100 * time.Millisecond
}

func (bm *BackpressureManager) getCurrentErrorRate() float64 {
	// Simplified implementation
	return 0.01
}

func (bm *BackpressureManager) updatePressureHistory(pressure int) {
	bm.metrics.mutex.Lock()
	defer bm.metrics.mutex.Unlock()

	bm.metrics.CurrentPressure = pressure
	bm.metrics.PressureHistory = append(bm.metrics.PressureHistory, pressure)

	// Keep only last 100 readings
	if len(bm.metrics.PressureHistory) > 100 {
		bm.metrics.PressureHistory = bm.metrics.PressureHistory[1:]
	}

	// Update max pressure
	if pressure > bm.metrics.MaxPressure {
		bm.metrics.MaxPressure = pressure
	}
}

func (bm *BackpressureManager) reliefCheckLoop() {
	ticker := time.NewTicker(bm.config.ReliefCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.checkReliefStrategies()
		case <-bm.shutdownCh:
			return
		}
	}
}

func (bm *BackpressureManager) checkReliefStrategies() {
	currentPressure := bm.GetCurrentPressure()

	// Check if we need to activate relief strategies
	for _, strategy := range bm.strategies {
		if currentPressure >= strategy.GetThreshold() && !strategy.IsActive() {
			bm.logger.Info("Activating pressure relief strategy",
				zap.String("strategy", strategy.Name()),
				zap.Int("pressure", currentPressure))

			if err := strategy.Activate(currentPressure); err != nil {
				bm.logger.Error("Failed to activate relief strategy",
					zap.String("strategy", strategy.Name()),
					zap.Error(err))
			} else {
				bm.activeStrategy = strategy
				atomic.AddInt64(&bm.metrics.ReliefActivations, 1)
			}
			break
		}
	}

	// Check if we should deactivate current strategy
	if bm.activeStrategy != nil && bm.activeStrategy.IsActive() {
		if currentPressure < bm.config.RecoveryThreshold {
			bm.logger.Info("Deactivating pressure relief strategy",
				zap.String("strategy", bm.activeStrategy.Name()),
				zap.Int("pressure", currentPressure))

			if err := bm.activeStrategy.Deactivate(); err != nil {
				bm.logger.Error("Failed to deactivate relief strategy",
					zap.String("strategy", bm.activeStrategy.Name()),
					zap.Error(err))
			} else {
				bm.activeStrategy = nil
			}
		}
	}
}

func (bm *BackpressureManager) metricsLoop() {
	ticker := time.NewTicker(bm.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.updateMetrics()
		case <-bm.shutdownCh:
			return
		}
	}
}

func (bm *BackpressureManager) updateMetrics() {
	bm.metrics.mutex.Lock()
	defer bm.metrics.mutex.Unlock()

	// Update queue metrics
	bm.metrics.QueueMetrics = make(map[string]*QueueMetrics)
	bm.mutex.RLock()
	for name, monitor := range bm.queueMonitors {
		monitor.mutex.RLock()
		bm.metrics.QueueMetrics[name] = &QueueMetrics{
			Depth:      monitor.depth,
			MaxDepth:   monitor.maxDepth,
			GrowthRate: monitor.growthRate,
		}
		monitor.mutex.RUnlock()
	}
	bm.mutex.RUnlock()

	// Update resource metrics
	bm.systemMonitor.mutex.RLock()
	bm.metrics.ResourceMetrics = &ResourceMetrics{
		CPUUsage:     bm.systemMonitor.cpuUsage,
		MemoryUsage:  bm.systemMonitor.memoryUsage,
		ResponseTime: bm.getAverageResponseTime(),
		ErrorRate:    bm.getCurrentErrorRate(),
	}
	bm.systemMonitor.mutex.RUnlock()

	// Update adaptive metrics if enabled
	if bm.adaptiveMonitor != nil {
		bm.metrics.AdaptiveMetrics = bm.adaptiveMonitor.GetMetrics()
	}

	// Update circuit breaker metrics
	if bm.circuitBreaker != nil {
		bm.metrics.CircuitBreakerTrips = bm.circuitBreaker.GetTripCount()
	}

	bm.metrics.lastUpdate = time.Now()
}

func (bm *BackpressureManager) initializeReliefStrategies() error {
	// Initialize default strategies based on configuration
	for _, strategyConfig := range bm.config.ReliefStrategies {
		strategy, err := createReliefStrategy(strategyConfig)
		if err != nil {
			return fmt.Errorf("failed to create relief strategy %s: %w", strategyConfig.Name, err)
		}
		bm.strategies = append(bm.strategies, strategy)
	}

	// Add default strategy if none configured
	if len(bm.strategies) == 0 {
		defaultStrategy := &GracefulDegradationStrategy{
			threshold: bm.config.HighPressureThreshold,
		}
		bm.strategies = append(bm.strategies, defaultStrategy)
	}

	return nil
}

// Utility functions

func validateBackpressureConfig(config *BackpressureConfig) error {
	if config.HighPressureThreshold <= config.MediumPressureThreshold {
		return fmt.Errorf("high pressure threshold must be greater than medium pressure threshold")
	}
	if config.MediumPressureThreshold <= config.LowPressureThreshold {
		return fmt.Errorf("medium pressure threshold must be greater than low pressure threshold")
	}
	return nil
}

func setBackpressureDefaults(config *BackpressureConfig) {
	if config.LowPressureThreshold == 0 {
		config.LowPressureThreshold = 30
	}
	if config.MediumPressureThreshold == 0 {
		config.MediumPressureThreshold = 60
	}
	if config.HighPressureThreshold == 0 {
		config.HighPressureThreshold = 80
	}
	if config.CriticalPressureThreshold == 0 {
		config.CriticalPressureThreshold = 95
	}
	if config.QueueHighWaterMark == 0 {
		config.QueueHighWaterMark = 100000
	}
	if config.QueueCriticalMark == 0 {
		config.QueueCriticalMark = 500000
	}
	if config.MaxCPUUsage == 0 {
		config.MaxCPUUsage = 0.85
	}
	if config.MaxMemoryUsage == 0 {
		config.MaxMemoryUsage = 0.90
	}
	if config.MaxResponseTime == 0 {
		config.MaxResponseTime = 2 * time.Second
	}
	if config.MaxErrorRate == 0 {
		config.MaxErrorRate = 0.05
	}
	if config.MonitoringInterval == 0 {
		config.MonitoringInterval = time.Second
	}
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 10 * time.Second
	}
	if config.ReliefCheckInterval == 0 {
		config.ReliefCheckInterval = 5 * time.Second
	}
	if config.RecoveryTimeout == 0 {
		config.RecoveryTimeout = 30 * time.Second
	}
	if config.RecoveryThreshold == 0 {
		config.RecoveryThreshold = 50
	}
	if config.RecoverySteps == 0 {
		config.RecoverySteps = 5
	}

	// Circuit breaker defaults
	if config.CircuitBreakerConfig == nil {
		config.CircuitBreakerConfig = &CircuitBreakerConfig{}
	}
	if config.CircuitBreakerConfig.FailureThreshold == 0 {
		config.CircuitBreakerConfig.FailureThreshold = 10
	}
	if config.CircuitBreakerConfig.SuccessThreshold == 0 {
		config.CircuitBreakerConfig.SuccessThreshold = 5
	}
	if config.CircuitBreakerConfig.Timeout == 0 {
		config.CircuitBreakerConfig.Timeout = 60 * time.Second
	}

	// Adaptive defaults
	if config.AdaptiveConfig == nil {
		config.AdaptiveConfig = &AdaptiveBackpressureConfig{}
	}
	if config.AdaptiveConfig.LearningPeriod == 0 {
		config.AdaptiveConfig.LearningPeriod = 10 * time.Minute
	}
	if config.AdaptiveConfig.AdjustmentFactor == 0 {
		config.AdaptiveConfig.AdjustmentFactor = 0.1
	}
	if config.AdaptiveConfig.SensitivityFactor == 0 {
		config.AdaptiveConfig.SensitivityFactor = 1.0
	}
}

func createThresholds(config *BackpressureConfig) *BackpressureThresholds {
	return &BackpressureThresholds{
		QueueDepth: &Threshold{
			Warning:   float64(config.QueueHighWaterMark) * 0.7,
			Critical:  float64(config.QueueHighWaterMark),
			Emergency: float64(config.QueueCriticalMark),
			Unit:      "events",
		},
		ResponseTime: &Threshold{
			Warning:   float64(config.MaxResponseTime.Milliseconds()) * 0.7,
			Critical:  float64(config.MaxResponseTime.Milliseconds()),
			Emergency: float64(config.MaxResponseTime.Milliseconds()) * 1.5,
			Unit:      "ms",
		},
		ErrorRate: &Threshold{
			Warning:   config.MaxErrorRate * 0.5,
			Critical:  config.MaxErrorRate,
			Emergency: config.MaxErrorRate * 2,
			Unit:      "percentage",
		},
		CPUUsage: &Threshold{
			Warning:   config.MaxCPUUsage * 0.8,
			Critical:  config.MaxCPUUsage,
			Emergency: config.MaxCPUUsage * 1.1,
			Unit:      "percentage",
		},
		MemoryUsage: &Threshold{
			Warning:   config.MaxMemoryUsage * 0.8,
			Critical:  config.MaxMemoryUsage,
			Emergency: config.MaxMemoryUsage * 1.05,
			Unit:      "percentage",
		},
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func NewBackpressureMetrics() *BackpressureMetrics {
	return &BackpressureMetrics{
		PressureHistory: make([]int, 0, 100),
		QueueMetrics:    make(map[string]*QueueMetrics),
		lastUpdate:      time.Now(),
	}
}

// Placeholder implementations for referenced types
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount++
	cb.lastFailureTime = time.Now()

	if cb.failureCount >= int64(cb.config.FailureThreshold) {
		cb.state = StateOpen
		cb.nextAttempt = time.Now().Add(cb.config.Timeout)
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.successCount++

	if cb.state == StateHalfOpen && cb.successCount >= int64(cb.config.SuccessThreshold) {
		cb.state = StateClosed
		cb.failureCount = 0
	}
}

func (cb *CircuitBreaker) GetTripCount() int64 {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.failureCount
}

func NewAdaptiveMonitor(config *AdaptiveBackpressureConfig) *AdaptiveMonitor {
	return &AdaptiveMonitor{
		config:          config,
		pressureHistory: make([]PressureReading, 0, 1000),
		learningPhase:   true,
		learningStart:   time.Now(),
	}
}

func (am *AdaptiveMonitor) AdjustPressure(pressure float64) float64 {
	// Simplified implementation
	return pressure
}

func (am *AdaptiveMonitor) RecordReading(reading PressureReading) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.pressureHistory = append(am.pressureHistory, reading)

	// Keep only recent history
	if len(am.pressureHistory) > 1000 {
		am.pressureHistory = am.pressureHistory[1:]
	}
}

func (am *AdaptiveMonitor) GetMetrics() *AdaptiveMetrics {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	return &AdaptiveMetrics{
		PredictionAccuracy: 0.85, // Placeholder
		AdaptationRate:     am.adaptationRate,
		LearningProgress:   0.75, // Placeholder
		PredictedPressure:  am.predictedPressure,
	}
}

func NewSystemMonitor() *SystemMonitor {
	return &SystemMonitor{}
}

func NewResourceMonitor(thresholds *BackpressureThresholds) *ResourceMonitor {
	return &ResourceMonitor{
		thresholds:  thresholds,
		alertActive: make(map[string]bool),
		lastAlert:   make(map[string]time.Time),
	}
}

func (rm *ResourceMonitor) UpdateMetrics(metrics *SystemMetrics) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.metrics = metrics
}

// Placeholder relief strategy implementations
type GracefulDegradationStrategy struct {
	threshold int
	active    bool
	mutex     sync.RWMutex
}

func (gds *GracefulDegradationStrategy) Name() string { return "graceful_degradation" }
func (gds *GracefulDegradationStrategy) Type() string { return "degradation" }

func (gds *GracefulDegradationStrategy) Activate(pressure int) error {
	gds.mutex.Lock()
	defer gds.mutex.Unlock()
	gds.active = true
	return nil
}

func (gds *GracefulDegradationStrategy) Deactivate() error {
	gds.mutex.Lock()
	defer gds.mutex.Unlock()
	gds.active = false
	return nil
}

func (gds *GracefulDegradationStrategy) IsActive() bool {
	gds.mutex.RLock()
	defer gds.mutex.RUnlock()
	return gds.active
}

func (gds *GracefulDegradationStrategy) GetThreshold() int {
	return gds.threshold
}

func (gds *GracefulDegradationStrategy) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"active": gds.IsActive(),
	}
}

func createReliefStrategy(config ReliefStrategyConfig) (PressureReliefStrategy, error) {
	switch config.Type {
	case "graceful_degradation":
		return &GracefulDegradationStrategy{
			threshold: config.Threshold,
		}, nil
	default:
		return nil, fmt.Errorf("unknown relief strategy type: %s", config.Type)
	}
}
