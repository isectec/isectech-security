package scaling

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// CircuitBreakerManager manages circuit breakers for all system components
type CircuitBreakerManager struct {
	logger           *zap.Logger
	config           *ScalingConfig
	circuitBreakers  map[string]*CircuitBreaker
	breakersMutex    sync.RWMutex
	
	// Global settings
	globalStats      *CircuitBreakerStats
	statsMutex       sync.RWMutex
	
	// Monitoring
	ctx              context.Context
	cancel           context.CancelFunc
	monitoringTicker *time.Ticker
}

// CircuitBreaker implements the circuit breaker pattern for fault tolerance
type CircuitBreaker struct {
	name             string
	logger           *zap.Logger
	config           *CircuitBreakerConfig
	
	// State management
	state            *CircuitBreakerState
	stateMutex       sync.RWMutex
	
	// Request tracking
	requestCount     int64
	successCount     int64
	failureCount     int64
	consecutiveFailures int64
	lastFailureTime  time.Time
	lastSuccessTime  time.Time
	
	// State transition times
	lastStateChange  time.Time
	openStartTime    time.Time
	halfOpenStartTime time.Time
	
	// Metrics and monitoring
	metrics          *CircuitBreakerMetrics
	metricsMutex     sync.RWMutex
}

// CircuitBreakerConfig defines configuration for a circuit breaker
type CircuitBreakerConfig struct {
	Name                    string        `json:"name"`
	FailureThreshold        int           `json:"failure_threshold"`        // Number of failures to trigger open state
	SuccessThreshold        int           `json:"success_threshold"`        // Number of successes to close from half-open
	Timeout                 time.Duration `json:"timeout"`                  // How long to stay in open state
	HalfOpenMaxRequests     int           `json:"half_open_max_requests"`   // Max requests allowed in half-open state
	SlidingWindowSize       int           `json:"sliding_window_size"`      // Size of sliding window for failure rate calculation
	MinimumRequestThreshold int           `json:"minimum_request_threshold"` // Minimum requests before circuit breaker can open
	FailureRateThreshold    float64       `json:"failure_rate_threshold"`   // Failure rate threshold (0.0-1.0)
	ResetTimeout            time.Duration `json:"reset_timeout"`            // Time to reset metrics
}

// CircuitBreakerState represents the current state of the circuit breaker
type CircuitBreakerState struct {
	Current               CircuitState  `json:"current"`
	PreviousState        CircuitState  `json:"previous_state"`
	StateTransitionCount int64         `json:"state_transition_count"`
	OpenCount            int64         `json:"open_count"`
	HalfOpenCount        int64         `json:"half_open_count"`
	LastTransition       time.Time     `json:"last_transition"`
}

// CircuitState represents the three states of a circuit breaker
type CircuitState string

const (
	CircuitStateClosed   CircuitState = "closed"
	CircuitStateOpen     CircuitState = "open"
	CircuitStateHalfOpen CircuitState = "half_open"
)

// CircuitBreakerMetrics contains detailed metrics for a circuit breaker
type CircuitBreakerMetrics struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	RejectedRequests    int64         `json:"rejected_requests"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	FailureRate         float64       `json:"failure_rate"`
	SuccessRate         float64       `json:"success_rate"`
	Uptime              time.Duration `json:"uptime"`
	LastRequestTime     time.Time     `json:"last_request_time"`
	LastSuccessTime     time.Time     `json:"last_success_time"`
	LastFailureTime     time.Time     `json:"last_failure_time"`
}

// CircuitBreakerStats contains global circuit breaker statistics
type CircuitBreakerStats struct {
	TotalCircuitBreakers  int `json:"total_circuit_breakers"`
	OpenCircuitBreakers   int `json:"open_circuit_breakers"`
	ClosedCircuitBreakers int `json:"closed_circuit_breakers"`
	HalfOpenCircuitBreakers int `json:"half_open_circuit_breakers"`
}

// RequestResult represents the result of a request execution
type RequestResult struct {
	Success     bool
	Error       error
	Duration    time.Duration
	Timestamp   time.Time
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager(logger *zap.Logger, config *ScalingConfig) (*CircuitBreakerManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	cbm := &CircuitBreakerManager{
		logger:          logger.With(zap.String("component", "circuit-breaker-manager")),
		config:          config,
		circuitBreakers: make(map[string]*CircuitBreaker),
		globalStats: &CircuitBreakerStats{},
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// Start monitoring
	cbm.monitoringTicker = time.NewTicker(30 * time.Second)
	go cbm.runMonitoring()
	
	logger.Info("Circuit breaker manager initialized")
	return cbm, nil
}

// CreateCircuitBreaker creates a new circuit breaker with the given configuration
func (cbm *CircuitBreakerManager) CreateCircuitBreaker(config *CircuitBreakerConfig) (*CircuitBreaker, error) {
	cbm.breakersMutex.Lock()
	defer cbm.breakersMutex.Unlock()
	
	if _, exists := cbm.circuitBreakers[config.Name]; exists {
		return nil, fmt.Errorf("circuit breaker with name %s already exists", config.Name)
	}
	
	// Set defaults
	if err := cbm.setCircuitBreakerDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set circuit breaker defaults: %w", err)
	}
	
	cb := &CircuitBreaker{
		name:   config.Name,
		logger: cbm.logger.With(zap.String("circuit_breaker", config.Name)),
		config: config,
		state: &CircuitBreakerState{
			Current:        CircuitStateClosed,
			PreviousState:  CircuitStateClosed,
			LastTransition: time.Now(),
		},
		lastStateChange: time.Now(),
		metrics: &CircuitBreakerMetrics{
			LastRequestTime: time.Now(),
		},
	}
	
	cbm.circuitBreakers[config.Name] = cb
	cbm.updateGlobalStats()
	
	cbm.logger.Info("Circuit breaker created",
		zap.String("name", config.Name),
		zap.Int("failure_threshold", config.FailureThreshold),
		zap.Duration("timeout", config.Timeout),
		zap.Float64("failure_rate_threshold", config.FailureRateThreshold),
	)
	
	return cb, nil
}

// GetCircuitBreaker retrieves a circuit breaker by name
func (cbm *CircuitBreakerManager) GetCircuitBreaker(name string) (*CircuitBreaker, error) {
	cbm.breakersMutex.RLock()
	defer cbm.breakersMutex.RUnlock()
	
	cb, exists := cbm.circuitBreakers[name]
	if !exists {
		return nil, fmt.Errorf("circuit breaker %s not found", name)
	}
	
	return cb, nil
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	// Check if request should be allowed
	if !cb.allowRequest() {
		atomic.AddInt64(&cb.metrics.RejectedRequests, 1)
		return fmt.Errorf("circuit breaker %s is open, request rejected", cb.name)
	}
	
	// Execute the function with timing
	start := time.Now()
	err := fn()
	duration := time.Since(start)
	
	// Record the result
	result := &RequestResult{
		Success:   err == nil,
		Error:     err,
		Duration:  duration,
		Timestamp: time.Now(),
	}
	
	cb.recordResult(result)
	
	return err
}

// allowRequest determines if a request should be allowed based on circuit breaker state
func (cb *CircuitBreaker) allowRequest() bool {
	cb.stateMutex.RLock()
	currentState := cb.state.Current
	cb.stateMutex.RUnlock()
	
	switch currentState {
	case CircuitStateClosed:
		return true
	case CircuitStateOpen:
		return cb.shouldAttemptReset()
	case CircuitStateHalfOpen:
		return cb.shouldAllowHalfOpenRequest()
	default:
		return false
	}
}

// shouldAttemptReset checks if enough time has passed to attempt a reset from open state
func (cb *CircuitBreaker) shouldAttemptReset() bool {
	cb.stateMutex.Lock()
	defer cb.stateMutex.Unlock()
	
	if time.Since(cb.openStartTime) >= cb.config.Timeout {
		cb.transitionTo(CircuitStateHalfOpen)
		cb.halfOpenStartTime = time.Now()
		return true
	}
	return false
}

// shouldAllowHalfOpenRequest checks if a request should be allowed in half-open state
func (cb *CircuitBreaker) shouldAllowHalfOpenRequest() bool {
	halfOpenRequests := atomic.LoadInt64(&cb.requestCount) - atomic.LoadInt64(&cb.successCount) - atomic.LoadInt64(&cb.failureCount)
	return int(halfOpenRequests) < cb.config.HalfOpenMaxRequests
}

// recordResult records the result of a request and updates circuit breaker state
func (cb *CircuitBreaker) recordResult(result *RequestResult) {
	atomic.AddInt64(&cb.requestCount, 1)
	
	cb.metricsMutex.Lock()
	cb.metrics.TotalRequests++
	cb.metrics.LastRequestTime = result.Timestamp
	
	// Update average response time
	if cb.metrics.AverageResponseTime == 0 {
		cb.metrics.AverageResponseTime = result.Duration
	} else {
		cb.metrics.AverageResponseTime = (cb.metrics.AverageResponseTime + result.Duration) / 2
	}
	cb.metricsMutex.Unlock()
	
	if result.Success {
		cb.recordSuccess(result)
	} else {
		cb.recordFailure(result)
	}
	
	// Check if state transition is needed
	cb.checkStateTransition()
}

// recordSuccess records a successful request
func (cb *CircuitBreaker) recordSuccess(result *RequestResult) {
	atomic.AddInt64(&cb.successCount, 1)
	atomic.StoreInt64(&cb.consecutiveFailures, 0)
	cb.lastSuccessTime = result.Timestamp
	
	cb.metricsMutex.Lock()
	cb.metrics.SuccessfulRequests++
	cb.metrics.LastSuccessTime = result.Timestamp
	cb.metricsMutex.Unlock()
}

// recordFailure records a failed request
func (cb *CircuitBreaker) recordFailure(result *RequestResult) {
	atomic.AddInt64(&cb.failureCount, 1)
	atomic.AddInt64(&cb.consecutiveFailures, 1)
	cb.lastFailureTime = result.Timestamp
	
	cb.metricsMutex.Lock()
	cb.metrics.FailedRequests++
	cb.metrics.LastFailureTime = result.Timestamp
	cb.metricsMutex.Unlock()
	
	cb.logger.Warn("Circuit breaker recorded failure",
		zap.String("name", cb.name),
		zap.Error(result.Error),
		zap.Int64("consecutive_failures", atomic.LoadInt64(&cb.consecutiveFailures)),
	)
}

// checkStateTransition checks if a state transition is needed
func (cb *CircuitBreaker) checkStateTransition() {
	cb.stateMutex.Lock()
	defer cb.stateMutex.Unlock()
	
	currentState := cb.state.Current
	
	switch currentState {
	case CircuitStateClosed:
		if cb.shouldOpen() {
			cb.transitionTo(CircuitStateOpen)
			cb.openStartTime = time.Now()
		}
	case CircuitStateHalfOpen:
		if cb.shouldCloseFromHalfOpen() {
			cb.transitionTo(CircuitStateClosed)
		} else if cb.shouldOpenFromHalfOpen() {
			cb.transitionTo(CircuitStateOpen)
			cb.openStartTime = time.Now()
		}
	}
}

// shouldOpen determines if the circuit breaker should transition to open state
func (cb *CircuitBreaker) shouldOpen() bool {
	totalRequests := atomic.LoadInt64(&cb.requestCount)
	if totalRequests < int64(cb.config.MinimumRequestThreshold) {
		return false
	}
	
	// Check consecutive failures
	consecutiveFailures := atomic.LoadInt64(&cb.consecutiveFailures)
	if consecutiveFailures >= int64(cb.config.FailureThreshold) {
		return true
	}
	
	// Check failure rate
	failureCount := atomic.LoadInt64(&cb.failureCount)
	failureRate := float64(failureCount) / float64(totalRequests)
	return failureRate >= cb.config.FailureRateThreshold
}

// shouldCloseFromHalfOpen determines if the circuit breaker should close from half-open state
func (cb *CircuitBreaker) shouldCloseFromHalfOpen() bool {
	successCount := atomic.LoadInt64(&cb.successCount)
	halfOpenSuccesses := successCount - cb.getBaselineSuccesses()
	return int(halfOpenSuccesses) >= cb.config.SuccessThreshold
}

// shouldOpenFromHalfOpen determines if the circuit breaker should open from half-open state
func (cb *CircuitBreaker) shouldOpenFromHalfOpen() bool {
	return atomic.LoadInt64(&cb.consecutiveFailures) > 0
}

// getBaselineSuccesses gets the success count baseline for half-open calculations
func (cb *CircuitBreaker) getBaselineSuccesses() int64 {
	// This would typically be stored when transitioning to half-open
	// For simplicity, we'll use current success count minus recent successes
	return atomic.LoadInt64(&cb.successCount) - int64(cb.config.SuccessThreshold)
}

// transitionTo transitions the circuit breaker to a new state
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	oldState := cb.state.Current
	cb.state.PreviousState = oldState
	cb.state.Current = newState
	cb.state.StateTransitionCount++
	cb.state.LastTransition = time.Now()
	cb.lastStateChange = time.Now()
	
	// Update state-specific counters
	switch newState {
	case CircuitStateOpen:
		cb.state.OpenCount++
	case CircuitStateHalfOpen:
		cb.state.HalfOpenCount++
	}
	
	cb.logger.Info("Circuit breaker state transition",
		zap.String("name", cb.name),
		zap.String("from_state", string(oldState)),
		zap.String("to_state", string(newState)),
		zap.Int64("total_requests", atomic.LoadInt64(&cb.requestCount)),
		zap.Int64("failure_count", atomic.LoadInt64(&cb.failureCount)),
		zap.Float64("failure_rate", cb.getCurrentFailureRate()),
	)
}

// getCurrentFailureRate calculates the current failure rate
func (cb *CircuitBreaker) getCurrentFailureRate() float64 {
	totalRequests := atomic.LoadInt64(&cb.requestCount)
	if totalRequests == 0 {
		return 0.0
	}
	failureCount := atomic.LoadInt64(&cb.failureCount)
	return float64(failureCount) / float64(totalRequests)
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.stateMutex.RLock()
	defer cb.stateMutex.RUnlock()
	return cb.state.Current
}

// GetMetrics returns the current metrics of the circuit breaker
func (cb *CircuitBreaker) GetMetrics() *CircuitBreakerMetrics {
	cb.metricsMutex.RLock()
	defer cb.metricsMutex.RUnlock()
	
	metrics := *cb.metrics
	metrics.TotalRequests = atomic.LoadInt64(&cb.requestCount)
	metrics.SuccessfulRequests = atomic.LoadInt64(&cb.successCount)
	metrics.FailedRequests = atomic.LoadInt64(&cb.failureCount)
	metrics.FailureRate = cb.getCurrentFailureRate()
	metrics.SuccessRate = 1.0 - metrics.FailureRate
	metrics.Uptime = time.Since(cb.lastStateChange)
	
	return &metrics
}

// Reset resets the circuit breaker to its initial state
func (cb *CircuitBreaker) Reset() {
	cb.stateMutex.Lock()
	defer cb.stateMutex.Unlock()
	
	atomic.StoreInt64(&cb.requestCount, 0)
	atomic.StoreInt64(&cb.successCount, 0)
	atomic.StoreInt64(&cb.failureCount, 0)
	atomic.StoreInt64(&cb.consecutiveFailures, 0)
	
	cb.transitionTo(CircuitStateClosed)
	
	cb.metricsMutex.Lock()
	cb.metrics = &CircuitBreakerMetrics{
		LastRequestTime: time.Now(),
	}
	cb.metricsMutex.Unlock()
	
	cb.logger.Info("Circuit breaker reset", zap.String("name", cb.name))
}

// Helper methods for CircuitBreakerManager

func (cbm *CircuitBreakerManager) setCircuitBreakerDefaults(config *CircuitBreakerConfig) error {
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 3
	}
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	if config.HalfOpenMaxRequests == 0 {
		config.HalfOpenMaxRequests = 3
	}
	if config.SlidingWindowSize == 0 {
		config.SlidingWindowSize = 100
	}
	if config.MinimumRequestThreshold == 0 {
		config.MinimumRequestThreshold = 10
	}
	if config.FailureRateThreshold == 0 {
		config.FailureRateThreshold = 0.5 // 50%
	}
	if config.ResetTimeout == 0 {
		config.ResetTimeout = 5 * time.Minute
	}
	
	return nil
}

func (cbm *CircuitBreakerManager) runMonitoring() {
	for {
		select {
		case <-cbm.ctx.Done():
			return
		case <-cbm.monitoringTicker.C:
			cbm.performMonitoring()
		}
	}
}

func (cbm *CircuitBreakerManager) performMonitoring() {
	cbm.breakersMutex.RLock()
	defer cbm.breakersMutex.RUnlock()
	
	for name, cb := range cbm.circuitBreakers {
		metrics := cb.GetMetrics()
		state := cb.GetState()
		
		cbm.logger.Debug("Circuit breaker status",
			zap.String("name", name),
			zap.String("state", string(state)),
			zap.Int64("total_requests", metrics.TotalRequests),
			zap.Int64("failed_requests", metrics.FailedRequests),
			zap.Float64("failure_rate", metrics.FailureRate),
			zap.Duration("avg_response_time", metrics.AverageResponseTime),
		)
	}
	
	cbm.updateGlobalStats()
}

func (cbm *CircuitBreakerManager) updateGlobalStats() {
	cbm.statsMutex.Lock()
	defer cbm.statsMutex.Unlock()
	
	openCount := 0
	closedCount := 0
	halfOpenCount := 0
	
	for _, cb := range cbm.circuitBreakers {
		switch cb.GetState() {
		case CircuitStateOpen:
			openCount++
		case CircuitStateClosed:
			closedCount++
		case CircuitStateHalfOpen:
			halfOpenCount++
		}
	}
	
	cbm.globalStats.TotalCircuitBreakers = len(cbm.circuitBreakers)
	cbm.globalStats.OpenCircuitBreakers = openCount
	cbm.globalStats.ClosedCircuitBreakers = closedCount
	cbm.globalStats.HalfOpenCircuitBreakers = halfOpenCount
}

// GetGlobalStats returns global circuit breaker statistics
func (cbm *CircuitBreakerManager) GetGlobalStats() *CircuitBreakerStats {
	cbm.statsMutex.RLock()
	defer cbm.statsMutex.RUnlock()
	
	stats := *cbm.globalStats
	return &stats
}

// GetAllCircuitBreakers returns all circuit breakers
func (cbm *CircuitBreakerManager) GetAllCircuitBreakers() map[string]*CircuitBreaker {
	cbm.breakersMutex.RLock()
	defer cbm.breakersMutex.RUnlock()
	
	breakers := make(map[string]*CircuitBreaker)
	for name, cb := range cbm.circuitBreakers {
		breakers[name] = cb
	}
	return breakers
}

// Close gracefully shuts down the circuit breaker manager
func (cbm *CircuitBreakerManager) Close() error {
	if cbm.cancel != nil {
		cbm.cancel()
	}
	
	if cbm.monitoringTicker != nil {
		cbm.monitoringTicker.Stop()
	}
	
	cbm.logger.Info("Circuit breaker manager closed")
	return nil
}