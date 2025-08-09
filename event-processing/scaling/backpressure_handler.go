package scaling

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// BackpressureHandler manages backpressure across the event processing pipeline
type BackpressureHandler struct {
	logger           *zap.Logger
	config           *BackpressureConfig
	
	// Queue management
	queueManagers    map[string]*QueueManager
	queuesMutex      sync.RWMutex
	
	// Rate limiting
	rateLimiters     map[string]*RateLimiter
	limitersMutex    sync.RWMutex
	
	// Pressure monitoring
	pressureMonitor  *PressureMonitor
	thresholdManager *ThresholdManager
	
	// Control mechanisms
	flowController   *FlowController
	loadShedder      *LoadShedder
	
	// Statistics and metrics
	stats            *BackpressureStats
	statsMutex       sync.RWMutex
	
	// Background processes
	ctx              context.Context
	cancel           context.CancelFunc
	monitoringTicker *time.Ticker
}

// BackpressureConfig defines configuration for backpressure handling
type BackpressureConfig struct {
	// Queue configuration
	MaxQueueSize         int           `json:"max_queue_size"`
	QueueDrainRate       int64         `json:"queue_drain_rate"`         // Events per second
	QueueBufferSize      int           `json:"queue_buffer_size"`
	QueueTimeout         time.Duration `json:"queue_timeout"`
	
	// Rate limiting
	GlobalRateLimit      int64         `json:"global_rate_limit"`        // Global events per second limit
	NodeRateLimit        int64         `json:"node_rate_limit"`          // Per-node events per second limit
	BurstSize            int           `json:"burst_size"`               // Burst capacity
	RateLimitWindow      time.Duration `json:"rate_limit_window"`
	
	// Pressure thresholds
	HighPressureThreshold    float64   `json:"high_pressure_threshold"`     // 0.0-1.0
	CriticalPressureThreshold float64  `json:"critical_pressure_threshold"` // 0.0-1.0
	RecoveryThreshold        float64   `json:"recovery_threshold"`          // 0.0-1.0
	
	// Load shedding
	LoadSheddingEnabled      bool      `json:"load_shedding_enabled"`
	LoadSheddingThreshold    float64   `json:"load_shedding_threshold"`     // 0.0-1.0
	LoadSheddingRate         float64   `json:"load_shedding_rate"`          // Percentage of requests to drop
	PriorityLevels           int       `json:"priority_levels"`
	
	// Monitoring and timing
	MonitoringInterval       time.Duration `json:"monitoring_interval"`
	PressureCalculationWindow time.Duration `json:"pressure_calculation_window"`
	BackoffInitialDelay      time.Duration `json:"backoff_initial_delay"`
	BackoffMaxDelay          time.Duration `json:"backoff_max_delay"`
	BackoffMultiplier        float64       `json:"backoff_multiplier"`
}

// QueueManager manages individual queues with backpressure
type QueueManager struct {
	name             string
	logger           *zap.Logger
	config           *BackpressureConfig
	
	// Queue state
	queue            chan interface{}
	queueSize        int64
	maxSize          int64
	droppedEvents    int64
	processedEvents  int64
	
	// Backpressure state
	pressureLevel    PressureLevel
	lastPressureCheck time.Time
	
	// Flow control
	rateLimiter      *RateLimiter
	backoffDelay     time.Duration
	
	// Metrics
	metrics          *QueueMetrics
	metricsMutex     sync.RWMutex
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	name             string
	logger           *zap.Logger
	
	// Token bucket parameters
	tokens           int64
	maxTokens        int64
	refillRate       int64     // Tokens per second
	lastRefill       time.Time
	
	// Statistics
	requestsAllowed  int64
	requestsRejected int64
	
	mutex            sync.Mutex
}

// PressureMonitor monitors system pressure levels
type PressureMonitor struct {
	logger           *zap.Logger
	config           *BackpressureConfig
	
	// Pressure measurements
	currentPressure  float64
	pressureHistory  []float64
	lastCalculation  time.Time
	
	// Component pressures
	queuePressures   map[string]float64
	nodePressures    map[string]float64
	
	mutex            sync.RWMutex
}

// ThresholdManager manages dynamic thresholds based on system state
type ThresholdManager struct {
	logger           *zap.Logger
	config           *BackpressureConfig
	
	// Dynamic thresholds
	currentThresholds map[string]float64
	baselineThresholds map[string]float64
	adaptiveAdjustment bool
	
	mutex            sync.RWMutex
}

// FlowController manages flow control across the pipeline
type FlowController struct {
	logger           *zap.Logger
	config           *BackpressureConfig
	
	// Flow state
	globalFlowRate   int64
	nodeFlowRates    map[string]int64
	flowControlActive bool
	
	// Backoff management
	backoffLevels    map[string]time.Duration
	
	mutex            sync.RWMutex
}

// LoadShedder implements intelligent load shedding
type LoadShedder struct {
	logger           *zap.Logger
	config           *BackpressureConfig
	
	// Load shedding state
	enabled          bool
	currentRate      float64
	sheddingActive   bool
	
	// Priority-based shedding
	priorityWeights  map[int]float64
	sheddingRates    map[int]float64
	
	// Statistics
	totalRequests    int64
	sheddedRequests  int64
	
	mutex            sync.RWMutex
}

// Enums and types
type PressureLevel string

const (
	PressureLevelNormal   PressureLevel = "normal"
	PressureLevelHigh     PressureLevel = "high"
	PressureLevelCritical PressureLevel = "critical"
)

// QueueMetrics contains metrics for a queue
type QueueMetrics struct {
	QueueSize          int64         `json:"queue_size"`
	MaxQueueSize       int64         `json:"max_queue_size"`
	ProcessedEvents    int64         `json:"processed_events"`
	DroppedEvents      int64         `json:"dropped_events"`
	AverageWaitTime    time.Duration `json:"average_wait_time"`
	ThroughputEPS      float64       `json:"throughput_eps"`
	PressureLevel      PressureLevel `json:"pressure_level"`
	LastProcessedTime  time.Time     `json:"last_processed_time"`
}

// BackpressureStats contains global backpressure statistics
type BackpressureStats struct {
	GlobalPressureLevel      PressureLevel     `json:"global_pressure_level"`
	TotalQueueSize          int64             `json:"total_queue_size"`
	GlobalThroughputEPS     float64           `json:"global_throughput_eps"`
	TotalDroppedEvents      int64             `json:"total_dropped_events"`
	TotalProcessedEvents    int64             `json:"total_processed_events"`
	LoadSheddingActive      bool              `json:"load_shedding_active"`
	ActiveRateLimiters      int               `json:"active_rate_limiters"`
	AveragePressure         float64           `json:"average_pressure"`
	QueueUtilization        float64           `json:"queue_utilization"`
	LastStatsUpdate         time.Time         `json:"last_stats_update"`
}

// RequestPriority represents the priority level of a request
type RequestPriority int

const (
	PriorityLow    RequestPriority = 1
	PriorityMedium RequestPriority = 2
	PriorityHigh   RequestPriority = 3
	PriorityCritical RequestPriority = 4
)

// NewBackpressureHandler creates a new backpressure handler
func NewBackpressureHandler(logger *zap.Logger, config *BackpressureConfig) (*BackpressureHandler, error) {
	if config == nil {
		return nil, fmt.Errorf("backpressure configuration is required")
	}
	
	// Set defaults
	if err := setBackpressureDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set backpressure defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	bph := &BackpressureHandler{
		logger:        logger.With(zap.String("component", "backpressure-handler")),
		config:        config,
		queueManagers: make(map[string]*QueueManager),
		rateLimiters:  make(map[string]*RateLimiter),
		stats: &BackpressureStats{
			GlobalPressureLevel: PressureLevelNormal,
			LastStatsUpdate:     time.Now(),
		},
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize components
	if err := bph.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize backpressure components: %w", err)
	}
	
	// Start monitoring
	bph.monitoringTicker = time.NewTicker(config.MonitoringInterval)
	go bph.runMonitoring()
	
	logger.Info("Backpressure handler initialized",
		zap.Int("max_queue_size", config.MaxQueueSize),
		zap.Int64("global_rate_limit", config.GlobalRateLimit),
		zap.Float64("high_pressure_threshold", config.HighPressureThreshold),
		zap.Bool("load_shedding_enabled", config.LoadSheddingEnabled),
	)
	
	return bph, nil
}

func setBackpressureDefaults(config *BackpressureConfig) error {
	if config.MaxQueueSize == 0 {
		config.MaxQueueSize = 10000
	}
	if config.QueueDrainRate == 0 {
		config.QueueDrainRate = 1000 // 1000 events/sec
	}
	if config.QueueBufferSize == 0 {
		config.QueueBufferSize = 1000
	}
	if config.QueueTimeout == 0 {
		config.QueueTimeout = 30 * time.Second
	}
	if config.GlobalRateLimit == 0 {
		config.GlobalRateLimit = 100000 // 100k events/sec
	}
	if config.NodeRateLimit == 0 {
		config.NodeRateLimit = 10000 // 10k events/sec per node
	}
	if config.BurstSize == 0 {
		config.BurstSize = 1000
	}
	if config.RateLimitWindow == 0 {
		config.RateLimitWindow = time.Second
	}
	if config.HighPressureThreshold == 0 {
		config.HighPressureThreshold = 0.7 // 70%
	}
	if config.CriticalPressureThreshold == 0 {
		config.CriticalPressureThreshold = 0.9 // 90%
	}
	if config.RecoveryThreshold == 0 {
		config.RecoveryThreshold = 0.5 // 50%
	}
	if config.LoadSheddingThreshold == 0 {
		config.LoadSheddingThreshold = 0.8 // 80%
	}
	if config.LoadSheddingRate == 0 {
		config.LoadSheddingRate = 0.1 // Drop 10% of requests
	}
	if config.PriorityLevels == 0 {
		config.PriorityLevels = 4
	}
	if config.MonitoringInterval == 0 {
		config.MonitoringInterval = 5 * time.Second
	}
	if config.PressureCalculationWindow == 0 {
		config.PressureCalculationWindow = 60 * time.Second
	}
	if config.BackoffInitialDelay == 0 {
		config.BackoffInitialDelay = time.Millisecond
	}
	if config.BackoffMaxDelay == 0 {
		config.BackoffMaxDelay = time.Second
	}
	if config.BackoffMultiplier == 0 {
		config.BackoffMultiplier = 2.0
	}
	
	return nil
}

func (bph *BackpressureHandler) initializeComponents() error {
	var err error
	
	// Initialize pressure monitor
	bph.pressureMonitor = &PressureMonitor{
		logger:          bph.logger.With(zap.String("component", "pressure-monitor")),
		config:          bph.config,
		pressureHistory: make([]float64, 0, 100),
		queuePressures:  make(map[string]float64),
		nodePressures:   make(map[string]float64),
		lastCalculation: time.Now(),
	}
	
	// Initialize threshold manager
	bph.thresholdManager = &ThresholdManager{
		logger:             bph.logger.With(zap.String("component", "threshold-manager")),
		config:             bph.config,
		currentThresholds:  make(map[string]float64),
		baselineThresholds: make(map[string]float64),
		adaptiveAdjustment: true,
	}
	
	// Set baseline thresholds
	bph.thresholdManager.baselineThresholds["high_pressure"] = bph.config.HighPressureThreshold
	bph.thresholdManager.baselineThresholds["critical_pressure"] = bph.config.CriticalPressureThreshold
	bph.thresholdManager.baselineThresholds["recovery"] = bph.config.RecoveryThreshold
	bph.thresholdManager.currentThresholds = make(map[string]float64)
	for k, v := range bph.thresholdManager.baselineThresholds {
		bph.thresholdManager.currentThresholds[k] = v
	}
	
	// Initialize flow controller
	bph.flowController = &FlowController{
		logger:          bph.logger.With(zap.String("component", "flow-controller")),
		config:          bph.config,
		nodeFlowRates:   make(map[string]int64),
		backoffLevels:   make(map[string]time.Duration),
		globalFlowRate:  bph.config.GlobalRateLimit,
	}
	
	// Initialize load shedder
	bph.loadShedder = &LoadShedder{
		logger:          bph.logger.With(zap.String("component", "load-shedder")),
		config:          bph.config,
		enabled:         bph.config.LoadSheddingEnabled,
		priorityWeights: make(map[int]float64),
		sheddingRates:   make(map[int]float64),
	}
	
	// Set priority weights (lower priority = higher shedding rate)
	for i := 1; i <= bph.config.PriorityLevels; i++ {
		weight := float64(bph.config.PriorityLevels-i+1) / float64(bph.config.PriorityLevels)
		bph.loadShedder.priorityWeights[i] = weight
		bph.loadShedder.sheddingRates[i] = (1.0 - weight) * bph.config.LoadSheddingRate
	}
	
	return err
}

// CreateQueueManager creates a new queue manager with backpressure
func (bph *BackpressureHandler) CreateQueueManager(name string) (*QueueManager, error) {
	bph.queuesMutex.Lock()
	defer bph.queuesMutex.Unlock()
	
	if _, exists := bph.queueManagers[name]; exists {
		return nil, fmt.Errorf("queue manager %s already exists", name)
	}
	
	qm := &QueueManager{
		name:              name,
		logger:            bph.logger.With(zap.String("queue", name)),
		config:            bph.config,
		queue:             make(chan interface{}, bph.config.QueueBufferSize),
		maxSize:           int64(bph.config.MaxQueueSize),
		pressureLevel:     PressureLevelNormal,
		lastPressureCheck: time.Now(),
		backoffDelay:      bph.config.BackoffInitialDelay,
		metrics: &QueueMetrics{
			MaxQueueSize:      int64(bph.config.MaxQueueSize),
			PressureLevel:     PressureLevelNormal,
			LastProcessedTime: time.Now(),
		},
	}
	
	// Create rate limiter for this queue
	rateLimiter, err := bph.CreateRateLimiter(fmt.Sprintf("%s_queue", name), bph.config.NodeRateLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter for queue %s: %w", name, err)
	}
	qm.rateLimiter = rateLimiter
	
	bph.queueManagers[name] = qm
	
	bph.logger.Info("Queue manager created",
		zap.String("name", name),
		zap.Int("buffer_size", bph.config.QueueBufferSize),
		zap.Int("max_size", bph.config.MaxQueueSize),
	)
	
	return qm, nil
}

// CreateRateLimiter creates a new rate limiter
func (bph *BackpressureHandler) CreateRateLimiter(name string, rateLimit int64) (*RateLimiter, error) {
	bph.limitersMutex.Lock()
	defer bph.limitersMutex.Unlock()
	
	if _, exists := bph.rateLimiters[name]; exists {
		return nil, fmt.Errorf("rate limiter %s already exists", name)
	}
	
	rl := &RateLimiter{
		name:       name,
		logger:     bph.logger.With(zap.String("rate_limiter", name)),
		tokens:     rateLimit,
		maxTokens:  rateLimit,
		refillRate: rateLimit,
		lastRefill: time.Now(),
	}
	
	bph.rateLimiters[name] = rl
	
	bph.logger.Info("Rate limiter created",
		zap.String("name", name),
		zap.Int64("rate_limit", rateLimit),
	)
	
	return rl, nil
}

// EnqueueWithBackpressure adds an item to the queue with backpressure handling
func (qm *QueueManager) EnqueueWithBackpressure(ctx context.Context, item interface{}, priority RequestPriority) error {
	// Check rate limiting first
	if !qm.rateLimiter.AllowRequest() {
		return fmt.Errorf("rate limit exceeded for queue %s", qm.name)
	}
	
	// Check queue capacity
	currentSize := atomic.LoadInt64(&qm.queueSize)
	if currentSize >= qm.maxSize {
		atomic.AddInt64(&qm.droppedEvents, 1)
		return fmt.Errorf("queue %s is full, dropping event", qm.name)
	}
	
	// Apply backpressure delay if pressure is high
	if qm.pressureLevel != PressureLevelNormal {
		select {
		case <-time.After(qm.backoffDelay):
			// Backoff applied
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	
	// Try to enqueue
	select {
	case qm.queue <- item:
		atomic.AddInt64(&qm.queueSize, 1)
		qm.updateMetrics()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		atomic.AddInt64(&qm.droppedEvents, 1)
		return fmt.Errorf("queue %s buffer full, dropping event", qm.name)
	}
}

// Dequeue removes an item from the queue
func (qm *QueueManager) Dequeue(ctx context.Context) (interface{}, error) {
	select {
	case item := <-qm.queue:
		atomic.AddInt64(&qm.queueSize, -1)
		atomic.AddInt64(&qm.processedEvents, 1)
		qm.updateMetrics()
		return item, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// AllowRequest checks if a request should be allowed based on rate limiting
func (rl *RateLimiter) AllowRequest() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	tokensToAdd := int64(elapsed.Seconds() * float64(rl.refillRate))
	
	if tokensToAdd > 0 {
		rl.tokens = min(rl.maxTokens, rl.tokens+tokensToAdd)
		rl.lastRefill = now
	}
	
	// Check if request can be allowed
	if rl.tokens > 0 {
		rl.tokens--
		atomic.AddInt64(&rl.requestsAllowed, 1)
		return true
	}
	
	atomic.AddInt64(&rl.requestsRejected, 1)
	return false
}

// ShouldShedLoad determines if a request should be dropped based on load shedding
func (ls *LoadShedder) ShouldShedLoad(priority RequestPriority) bool {
	ls.mutex.RLock()
	defer ls.mutex.RUnlock()
	
	if !ls.enabled || !ls.sheddingActive {
		return false
	}
	
	// Get shedding rate for this priority level
	sheddingRate, exists := ls.sheddingRates[int(priority)]
	if !exists {
		sheddingRate = ls.currentRate
	}
	
	// Probabilistic load shedding
	return time.Now().UnixNano()%1000 < int64(sheddingRate*1000)
}

// UpdatePressure calculates and updates the current system pressure
func (pm *PressureMonitor) UpdatePressure(queueManagers map[string]*QueueManager) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	totalPressure := 0.0
	validQueues := 0
	
	// Calculate pressure for each queue
	for name, qm := range queueManagers {
		queueUtilization := float64(atomic.LoadInt64(&qm.queueSize)) / float64(qm.maxSize)
		pm.queuePressures[name] = queueUtilization
		totalPressure += queueUtilization
		validQueues++
	}
	
	// Calculate average pressure
	if validQueues > 0 {
		pm.currentPressure = totalPressure / float64(validQueues)
	}
	
	// Add to history
	pm.pressureHistory = append(pm.pressureHistory, pm.currentPressure)
	if len(pm.pressureHistory) > 100 {
		pm.pressureHistory = pm.pressureHistory[1:]
	}
	
	pm.lastCalculation = time.Now()
}

// GetCurrentPressure returns the current system pressure level
func (pm *PressureMonitor) GetCurrentPressure() float64 {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.currentPressure
}

// Helper methods
func (qm *QueueManager) updateMetrics() {
	qm.metricsMutex.Lock()
	defer qm.metricsMutex.Unlock()
	
	qm.metrics.QueueSize = atomic.LoadInt64(&qm.queueSize)
	qm.metrics.ProcessedEvents = atomic.LoadInt64(&qm.processedEvents)
	qm.metrics.DroppedEvents = atomic.LoadInt64(&qm.droppedEvents)
	
	// Calculate throughput
	now := time.Now()
	elapsed := now.Sub(qm.metrics.LastProcessedTime).Seconds()
	if elapsed > 0 {
		qm.metrics.ThroughputEPS = float64(qm.metrics.ProcessedEvents) / elapsed
	}
	
	qm.metrics.LastProcessedTime = now
	
	// Update pressure level
	utilization := float64(qm.metrics.QueueSize) / float64(qm.metrics.MaxQueueSize)
	if utilization >= qm.config.CriticalPressureThreshold {
		qm.pressureLevel = PressureLevelCritical
		qm.backoffDelay = min(qm.config.BackoffMaxDelay, qm.backoffDelay*time.Duration(qm.config.BackoffMultiplier))
	} else if utilization >= qm.config.HighPressureThreshold {
		qm.pressureLevel = PressureLevelHigh
		qm.backoffDelay = min(qm.config.BackoffMaxDelay, qm.backoffDelay*time.Duration(qm.config.BackoffMultiplier))
	} else if utilization <= qm.config.RecoveryThreshold {
		qm.pressureLevel = PressureLevelNormal
		qm.backoffDelay = max(qm.config.BackoffInitialDelay, qm.backoffDelay/time.Duration(qm.config.BackoffMultiplier))
	}
	
	qm.metrics.PressureLevel = qm.pressureLevel
}

func (bph *BackpressureHandler) runMonitoring() {
	for {
		select {
		case <-bph.ctx.Done():
			return
		case <-bph.monitoringTicker.C:
			bph.performMonitoring()
		}
	}
}

func (bph *BackpressureHandler) performMonitoring() {
	// Update pressure measurements
	bph.queuesMutex.RLock()
	queueManagers := make(map[string]*QueueManager)
	for name, qm := range bph.queueManagers {
		queueManagers[name] = qm
	}
	bph.queuesMutex.RUnlock()
	
	bph.pressureMonitor.UpdatePressure(queueManagers)
	
	// Update global statistics
	bph.updateGlobalStats()
	
	// Update load shedding state
	bph.updateLoadSheddingState()
	
	// Log monitoring information
	pressure := bph.pressureMonitor.GetCurrentPressure()
	bph.logger.Debug("Backpressure monitoring update",
		zap.Float64("current_pressure", pressure),
		zap.Int("active_queues", len(queueManagers)),
		zap.Bool("load_shedding_active", bph.loadShedder.sheddingActive),
	)
}

func (bph *BackpressureHandler) updateGlobalStats() {
	bph.statsMutex.Lock()
	defer bph.statsMutex.Unlock()
	
	totalQueueSize := int64(0)
	totalProcessed := int64(0)
	totalDropped := int64(0)
	
	bph.queuesMutex.RLock()
	for _, qm := range bph.queueManagers {
		totalQueueSize += atomic.LoadInt64(&qm.queueSize)
		totalProcessed += atomic.LoadInt64(&qm.processedEvents)
		totalDropped += atomic.LoadInt64(&qm.droppedEvents)
	}
	bph.queuesMutex.RUnlock()
	
	bph.stats.TotalQueueSize = totalQueueSize
	bph.stats.TotalProcessedEvents = totalProcessed
	bph.stats.TotalDroppedEvents = totalDropped
	bph.stats.AveragePressure = bph.pressureMonitor.GetCurrentPressure()
	
	// Update global pressure level
	pressure := bph.stats.AveragePressure
	if pressure >= bph.config.CriticalPressureThreshold {
		bph.stats.GlobalPressureLevel = PressureLevelCritical
	} else if pressure >= bph.config.HighPressureThreshold {
		bph.stats.GlobalPressureLevel = PressureLevelHigh
	} else {
		bph.stats.GlobalPressureLevel = PressureLevelNormal
	}
	
	bph.stats.LoadSheddingActive = bph.loadShedder.sheddingActive
	bph.stats.ActiveRateLimiters = len(bph.rateLimiters)
	bph.stats.LastStatsUpdate = time.Now()
}

func (bph *BackpressureHandler) updateLoadSheddingState() {
	if !bph.loadShedder.enabled {
		return
	}
	
	pressure := bph.pressureMonitor.GetCurrentPressure()
	
	bph.loadShedder.mutex.Lock()
	defer bph.loadShedder.mutex.Unlock()
	
	if pressure >= bph.config.LoadSheddingThreshold {
		if !bph.loadShedder.sheddingActive {
			bph.loadShedder.sheddingActive = true
			bph.logger.Warn("Load shedding activated",
				zap.Float64("pressure", pressure),
				zap.Float64("threshold", bph.config.LoadSheddingThreshold),
			)
		}
		bph.loadShedder.currentRate = min(1.0, pressure*bph.config.LoadSheddingRate)
	} else if pressure <= bph.config.RecoveryThreshold {
		if bph.loadShedder.sheddingActive {
			bph.loadShedder.sheddingActive = false
			bph.logger.Info("Load shedding deactivated",
				zap.Float64("pressure", pressure),
				zap.Float64("recovery_threshold", bph.config.RecoveryThreshold),
			)
		}
	}
}

// GetBackpressureStats returns current backpressure statistics
func (bph *BackpressureHandler) GetBackpressureStats() *BackpressureStats {
	bph.statsMutex.RLock()
	defer bph.statsMutex.RUnlock()
	
	stats := *bph.stats
	return &stats
}

// GetQueueManager retrieves a queue manager by name
func (bph *BackpressureHandler) GetQueueManager(name string) (*QueueManager, error) {
	bph.queuesMutex.RLock()
	defer bph.queuesMutex.RUnlock()
	
	qm, exists := bph.queueManagers[name]
	if !exists {
		return nil, fmt.Errorf("queue manager %s not found", name)
	}
	
	return qm, nil
}

// Close gracefully shuts down the backpressure handler
func (bph *BackpressureHandler) Close() error {
	if bph.cancel != nil {
		bph.cancel()
	}
	
	if bph.monitoringTicker != nil {
		bph.monitoringTicker.Stop()
	}
	
	// Close all queues
	bph.queuesMutex.RLock()
	for _, qm := range bph.queueManagers {
		close(qm.queue)
	}
	bph.queuesMutex.RUnlock()
	
	bph.logger.Info("Backpressure handler closed")
	return nil
}

// Utility functions
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}