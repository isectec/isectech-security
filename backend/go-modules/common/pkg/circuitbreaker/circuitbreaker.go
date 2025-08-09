package circuitbreaker

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sony/gobreaker"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Config represents circuit breaker configuration
type Config struct {
	// Basic settings
	Name           string        `yaml:"name" json:"name"`
	MaxRequests    uint32        `yaml:"max_requests" json:"max_requests"`
	Interval       time.Duration `yaml:"interval" json:"interval"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	
	// Failure settings
	FailureThreshold  uint32  `yaml:"failure_threshold" json:"failure_threshold"`
	SuccessThreshold  uint32  `yaml:"success_threshold" json:"success_threshold"`
	FailureRatio      float64 `yaml:"failure_ratio" json:"failure_ratio"`
	
	// Advanced settings
	OnStateChange     bool          `yaml:"on_state_change" json:"on_state_change"`
	IsSuccessful      bool          `yaml:"is_successful" json:"is_successful"`
	ReadyToTrip       bool          `yaml:"ready_to_trip" json:"ready_to_trip"`
	ResetCounts       bool          `yaml:"reset_counts" json:"reset_counts"`
	
	// Metrics settings
	EnableMetrics     bool          `yaml:"enable_metrics" json:"enable_metrics"`
	MetricsInterval   time.Duration `yaml:"metrics_interval" json:"metrics_interval"`
}

// Manager manages multiple circuit breakers
type Manager struct {
	breakers map[string]*CircuitBreaker
	mutex    sync.RWMutex
	logger   *zap.Logger
	
	// Default config for new breakers
	defaultConfig *Config
}

// CircuitBreaker wraps gobreaker.CircuitBreaker with additional functionality
type CircuitBreaker struct {
	*gobreaker.CircuitBreaker
	config  *Config
	logger  *zap.Logger
	metrics *CircuitBreakerMetrics
}

// CircuitBreakerMetrics contains circuit breaker metrics
type CircuitBreakerMetrics struct {
	Name                string    `json:"name"`
	State              string    `json:"state"`
	TotalRequests      uint64    `json:"total_requests"`
	SuccessfulRequests uint64    `json:"successful_requests"`
	FailedRequests     uint64    `json:"failed_requests"`
	ConsecutiveFailures uint32   `json:"consecutive_failures"`
	ConsecutiveSuccesses uint32  `json:"consecutive_successes"`
	LastStateChange    time.Time `json:"last_state_change"`
	
	// Rate metrics
	RequestRate   float64 `json:"request_rate"`
	SuccessRate   float64 `json:"success_rate"`
	FailureRate   float64 `json:"failure_rate"`
}

// NewManager creates a new circuit breaker manager
func NewManager(defaultConfig *Config, logger *zap.Logger) *Manager {
	if defaultConfig == nil {
		defaultConfig = DefaultConfig()
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Manager{
		breakers:      make(map[string]*CircuitBreaker),
		logger:        logger,
		defaultConfig: defaultConfig,
	}
}

// GetOrCreate gets an existing circuit breaker or creates a new one
func (m *Manager) GetOrCreate(name string, config *Config) *CircuitBreaker {
	m.mutex.RLock()
	if cb, exists := m.breakers[name]; exists {
		m.mutex.RUnlock()
		return cb
	}
	m.mutex.RUnlock()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Double-check after acquiring write lock
	if cb, exists := m.breakers[name]; exists {
		return cb
	}

	// Use provided config or default
	if config == nil {
		config = m.defaultConfig
	}
	config.Name = name

	cb := NewCircuitBreaker(config, m.logger)
	m.breakers[name] = cb

	m.logger.Info("Circuit breaker created",
		zap.String("name", name),
		zap.Uint32("failure_threshold", config.FailureThreshold),
		zap.Duration("timeout", config.Timeout),
	)

	return cb
}

// Get gets an existing circuit breaker
func (m *Manager) Get(name string) (*CircuitBreaker, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	cb, exists := m.breakers[name]
	return cb, exists
}

// Remove removes a circuit breaker
func (m *Manager) Remove(name string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	delete(m.breakers, name)
	m.logger.Info("Circuit breaker removed", zap.String("name", name))
}

// List returns all circuit breaker names
func (m *Manager) List() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	names := make([]string, 0, len(m.breakers))
	for name := range m.breakers {
		names = append(names, name)
	}
	return names
}

// GetMetrics returns metrics for all circuit breakers
func (m *Manager) GetMetrics() map[string]*CircuitBreakerMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	metrics := make(map[string]*CircuitBreakerMetrics)
	for name, cb := range m.breakers {
		metrics[name] = cb.GetMetrics()
	}
	return metrics
}

// Reset resets all circuit breakers
func (m *Manager) Reset() {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	for _, cb := range m.breakers {
		cb.Reset()
	}
	
	m.logger.Info("All circuit breakers reset")
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *Config, logger *zap.Logger) *CircuitBreaker {
	if config == nil {
		config = DefaultConfig()
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	// Create gobreaker settings
	settings := gobreaker.Settings{
		Name:        config.Name,
		MaxRequests: config.MaxRequests,
		Interval:    config.Interval,
		Timeout:     config.Timeout,
	}

	cb := &CircuitBreaker{
		config: config,
		logger: logger,
		metrics: &CircuitBreakerMetrics{
			Name:            config.Name,
			LastStateChange: time.Now(),
		},
	}

	// Set up callbacks
	if config.OnStateChange {
		settings.OnStateChange = cb.onStateChange
	}
	
	if config.ReadyToTrip {
		settings.ReadyToTrip = cb.readyToTrip
	}
	
	if config.IsSuccessful {
		settings.IsSuccessful = cb.isSuccessful
	}

	cb.CircuitBreaker = gobreaker.NewCircuitBreaker(settings)

	return cb
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() (interface{}, error)) (interface{}, error) {
	result, err := cb.CircuitBreaker.Execute(fn)
	
	// Update metrics
	cb.updateMetrics(err)
	
	if err != nil {
		cb.logger.Debug("Circuit breaker execution failed",
			zap.String("name", cb.config.Name),
			zap.String("state", cb.State().String()),
			zap.Error(err),
		)
	}
	
	return result, err
}

// ExecuteContext executes a function with context and circuit breaker protection
func (cb *CircuitBreaker) ExecuteContext(ctx context.Context, fn func(context.Context) (interface{}, error)) (interface{}, error) {
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Execute with timeout from context if available
	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}

	result, err := cb.Execute(func() (interface{}, error) {
		return fn(ctx)
	})
	
	return result, err
}

// Call wraps a simple function call
func (cb *CircuitBreaker) Call(fn func() error) error {
	_, err := cb.Execute(func() (interface{}, error) {
		return nil, fn()
	})
	return err
}

// CallContext wraps a simple function call with context
func (cb *CircuitBreaker) CallContext(ctx context.Context, fn func(context.Context) error) error {
	_, err := cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, fn(ctx)
	})
	return err
}

// onStateChange is called when the circuit breaker state changes
func (cb *CircuitBreaker) onStateChange(name string, from, to gobreaker.State) {
	cb.metrics.State = to.String()
	cb.metrics.LastStateChange = time.Now()
	
	cb.logger.Info("Circuit breaker state changed",
		zap.String("name", name),
		zap.String("from", from.String()),
		zap.String("to", to.String()),
	)
}

// readyToTrip determines if the circuit breaker should trip
func (cb *CircuitBreaker) readyToTrip(counts gobreaker.Counts) bool {
	// Use failure threshold
	if counts.ConsecutiveFailures >= cb.config.FailureThreshold {
		return true
	}
	
	// Use failure ratio if configured
	if cb.config.FailureRatio > 0 && counts.Requests >= cb.config.MaxRequests {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return failureRatio >= cb.config.FailureRatio
	}
	
	return false
}

// isSuccessful determines if a request result is successful
func (cb *CircuitBreaker) isSuccessful(err error) bool {
	// Consider nil error as success
	if err == nil {
		return true
	}
	
	// You can add custom logic here to determine what constitutes success
	// For example, certain types of errors might not count as failures
	
	return false
}

// updateMetrics updates internal metrics
func (cb *CircuitBreaker) updateMetrics(err error) {
	cb.metrics.TotalRequests++
	
	if err == nil {
		cb.metrics.SuccessfulRequests++
		cb.metrics.ConsecutiveSuccesses++
		cb.metrics.ConsecutiveFailures = 0
	} else {
		cb.metrics.FailedRequests++
		cb.metrics.ConsecutiveFailures++
		cb.metrics.ConsecutiveSuccesses = 0
	}
	
	// Calculate rates
	if cb.metrics.TotalRequests > 0 {
		cb.metrics.SuccessRate = float64(cb.metrics.SuccessfulRequests) / float64(cb.metrics.TotalRequests)
		cb.metrics.FailureRate = float64(cb.metrics.FailedRequests) / float64(cb.metrics.TotalRequests)
	}
}

// GetMetrics returns current circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() *CircuitBreakerMetrics {
	// Get current counts from gobreaker
	counts := cb.Counts()
	
	metrics := &CircuitBreakerMetrics{
		Name:                 cb.config.Name,
		State:               cb.State().String(),
		TotalRequests:       uint64(counts.Requests),
		SuccessfulRequests:  uint64(counts.TotalSuccesses),
		FailedRequests:      uint64(counts.TotalFailures),
		ConsecutiveFailures: counts.ConsecutiveFailures,
		ConsecutiveSuccesses: counts.ConsecutiveSuccesses,
		LastStateChange:     cb.metrics.LastStateChange,
	}
	
	// Calculate rates
	if metrics.TotalRequests > 0 {
		metrics.SuccessRate = float64(metrics.SuccessfulRequests) / float64(metrics.TotalRequests)
		metrics.FailureRate = float64(metrics.FailedRequests) / float64(metrics.TotalRequests)
	}
	
	return metrics
}

// Reset resets the circuit breaker state and counts
func (cb *CircuitBreaker) Reset() {
	cb.CircuitBreaker.Reset()
	cb.metrics.LastStateChange = time.Now()
	
	cb.logger.Info("Circuit breaker reset", zap.String("name", cb.config.Name))
}

// IsAvailable returns true if the circuit breaker allows requests
func (cb *CircuitBreaker) IsAvailable() bool {
	state := cb.State()
	return state == gobreaker.StateClosed || state == gobreaker.StateHalfOpen
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() string {
	return cb.State().String()
}

// GetConfig returns the circuit breaker configuration
func (cb *CircuitBreaker) GetConfig() *Config {
	return cb.config
}

// HTTPMiddleware returns HTTP middleware for circuit breaker protection
func (cb *CircuitBreaker) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := cb.ExecuteContext(r.Context(), func(ctx context.Context) (interface{}, error) {
			next.ServeHTTP(w, r.WithContext(ctx))
			return nil, nil
		})
		
		if err != nil {
			cb.logger.Error("Circuit breaker HTTP middleware failed",
				zap.String("name", cb.config.Name),
				zap.String("path", r.URL.Path),
				zap.Error(err),
			)
			
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		}
	})
}

// WrapGRPCUnaryClient wraps a gRPC unary client call with circuit breaker
func (cb *CircuitBreaker) WrapGRPCUnaryClient(invoker grpc.UnaryInvoker) grpc.UnaryInvoker {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		_, err := cb.ExecuteContext(ctx, func(ctx context.Context) (interface{}, error) {
			return nil, invoker(ctx, method, req, reply, cc, opts...)
		})
		return err
	}
}

// WrapFunction wraps any function with circuit breaker protection
func (cb *CircuitBreaker) WrapFunction(fn interface{}) interface{} {
	// This is a simplified wrapper - in practice, you'd use reflection
	// or generate specific wrappers for different function signatures
	switch f := fn.(type) {
	case func() error:
		return func() error {
			return cb.Call(f)
		}
	case func(context.Context) error:
		return func(ctx context.Context) error {
			return cb.CallContext(ctx, f)
		}
	default:
		cb.logger.Warn("Unsupported function type for circuit breaker wrapping")
		return fn
	}
}

// DefaultConfig returns a default circuit breaker configuration
func DefaultConfig() *Config {
	return &Config{
		Name:             "default",
		MaxRequests:      5,
		Interval:         60 * time.Second,
		Timeout:          60 * time.Second,
		FailureThreshold: 5,
		SuccessThreshold: 2,
		FailureRatio:     0.5,
		OnStateChange:    true,
		IsSuccessful:     true,
		ReadyToTrip:      true,
		EnableMetrics:    true,
		MetricsInterval:  30 * time.Second,
	}
}

// DatabaseConfig returns a circuit breaker configuration optimized for database operations
func DatabaseConfig(name string) *Config {
	config := DefaultConfig()
	config.Name = name
	config.MaxRequests = 3
	config.Interval = 30 * time.Second
	config.Timeout = 30 * time.Second
	config.FailureThreshold = 3
	config.FailureRatio = 0.6
	return config
}

// HTTPConfig returns a circuit breaker configuration optimized for HTTP operations
func HTTPConfig(name string) *Config {
	config := DefaultConfig()
	config.Name = name
	config.MaxRequests = 10
	config.Interval = 60 * time.Second
	config.Timeout = 30 * time.Second
	config.FailureThreshold = 5
	config.FailureRatio = 0.5
	return config
}

// GRPCConfig returns a circuit breaker configuration optimized for gRPC operations
func GRPCConfig(name string) *Config {
	config := DefaultConfig()
	config.Name = name
	config.MaxRequests = 5
	config.Interval = 45 * time.Second
	config.Timeout = 45 * time.Second
	config.FailureThreshold = 3
	config.FailureRatio = 0.4
	return config
}