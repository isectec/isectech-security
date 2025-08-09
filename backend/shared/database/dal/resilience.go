package dal

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/sony/gobreaker"
	"go.uber.org/zap"
)

// ResilienceManager handles circuit breakers, retries, and other resilience patterns
type ResilienceManager struct {
	config          ResilienceConfig
	logger          *zap.Logger
	circuitBreakers map[string]*gobreaker.CircuitBreaker
	mu              sync.RWMutex
}

// ResilienceRetryPolicy defines retry policy for resilience manager
type ResilienceRetryPolicy struct {
	MaxAttempts     int
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	Jitter          bool
}

// NewResilienceManager creates a new resilience manager
func NewResilienceManager(config ResilienceConfig, logger *zap.Logger) (*ResilienceManager, error) {
	rm := &ResilienceManager{
		config:          config,
		logger:          logger,
		circuitBreakers: make(map[string]*gobreaker.CircuitBreaker),
	}

	// Initialize circuit breakers
	if err := rm.initializeCircuitBreakers(); err != nil {
		return nil, fmt.Errorf("failed to initialize circuit breakers: %w", err)
	}

	logger.Info("Resilience manager initialized")
	return rm, nil
}

// initializeCircuitBreakers creates circuit breakers for each database
func (rm *ResilienceManager) initializeCircuitBreakers() error {
	databases := map[string]DatabaseCircuitBreaker{
		"postgresql":    rm.config.CircuitBreaker.PostgreSQL,
		"mongodb":       rm.config.CircuitBreaker.MongoDB,
		"redis":         rm.config.CircuitBreaker.Redis,
		"elasticsearch": rm.config.CircuitBreaker.Elasticsearch,
	}

	for dbName, dbConfig := range databases {
		if !dbConfig.Enabled {
			continue
		}

		settings := gobreaker.Settings{
			Name:        fmt.Sprintf("%s-circuit-breaker", dbName),
			MaxRequests: dbConfig.MaxRequests,
			Interval:    dbConfig.Interval,
			Timeout:     dbConfig.Timeout,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures >= dbConfig.FailureThreshold
			},
		}

		if dbConfig.OnStateChangeEnabled {
			settings.OnStateChange = func(name string, from gobreaker.State, to gobreaker.State) {
				rm.logger.Warn("Circuit breaker state changed",
					zap.String("name", name),
					zap.String("from", from.String()),
					zap.String("to", to.String()))
			}
		}

		rm.circuitBreakers[dbName] = gobreaker.NewCircuitBreaker(settings)
		
		rm.logger.Info("Circuit breaker initialized",
			zap.String("database", dbName),
			zap.Uint32("failure_threshold", dbConfig.FailureThreshold),
			zap.Duration("timeout", dbConfig.Timeout))
	}

	return nil
}

// ExecuteWithCircuitBreaker executes a function with circuit breaker protection
func (rm *ResilienceManager) ExecuteWithCircuitBreaker(ctx context.Context, database string, operation func(ctx context.Context) (interface{}, error)) (interface{}, error) {
	rm.mu.RLock()
	cb, exists := rm.circuitBreakers[database]
	rm.mu.RUnlock()

	if !exists {
		// No circuit breaker configured, execute directly
		return operation(ctx)
	}

	result, err := cb.Execute(func() (interface{}, error) {
		return operation(ctx)
	})

	if err != nil {
		rm.logger.Debug("Circuit breaker execution failed",
			zap.String("database", database),
			zap.Error(err),
			zap.String("state", cb.State().String()))
	}

	return result, err
}

// ExecuteWithRetry executes a function with retry logic
func (rm *ResilienceManager) ExecuteWithRetry(ctx context.Context, database string, operation func(ctx context.Context) (interface{}, error)) (interface{}, error, int) {
	var retryConfig DatabaseRetry
	
	switch database {
	case "postgresql":
		retryConfig = rm.config.Retry.PostgreSQL
	case "mongodb":
		retryConfig = rm.config.Retry.MongoDB
	case "redis":
		retryConfig = rm.config.Retry.Redis
	case "elasticsearch":
		retryConfig = rm.config.Retry.Elasticsearch
	default:
		return nil, fmt.Errorf("unknown database: %s", database), 0
	}

	if !retryConfig.Enabled {
		result, err := operation(ctx)
		return result, err, 0
	}

	policy := &ResilienceRetryPolicy{
		MaxAttempts:     retryConfig.MaxAttempts,
		InitialInterval: retryConfig.InitialInterval,
		MaxInterval:     retryConfig.MaxInterval,
		Multiplier:      retryConfig.Multiplier,
		Jitter:          retryConfig.Jitter,
	}

	return rm.ExecuteWithCustomRetry(ctx, operation, policy)
}

// ExecuteWithCustomRetry executes a function with custom retry policy
func (rm *ResilienceManager) ExecuteWithCustomRetry(ctx context.Context, operation func(ctx context.Context) (interface{}, error), policy *ResilienceRetryPolicy) (interface{}, error, int) {
	var lastErr error
	var result interface{}

	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err(), attempt
		default:
		}

		// Execute the operation
		result, lastErr = operation(ctx)
		if lastErr == nil {
			// Success
			if attempt > 0 {
				rm.logger.Debug("Operation succeeded after retries",
					zap.Int("attempt", attempt+1),
					zap.Int("total_attempts", policy.MaxAttempts))
			}
			return result, nil, attempt
		}

		// Check if this is the last attempt
		if attempt == policy.MaxAttempts-1 {
			break
		}

		// Calculate backoff duration
		backoffDuration := rm.calculateBackoff(attempt, policy)

		rm.logger.Debug("Operation failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Int("max_attempts", policy.MaxAttempts),
			zap.Duration("backoff", backoffDuration),
			zap.Error(lastErr))

		// Wait before retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err(), attempt + 1
		case <-time.After(backoffDuration):
			// Continue to next attempt
		}
	}

	rm.logger.Error("Operation failed after all retry attempts",
		zap.Int("attempts", policy.MaxAttempts),
		zap.Error(lastErr))

	return nil, lastErr, policy.MaxAttempts
}

// calculateBackoff calculates the backoff duration for retry
func (rm *ResilienceManager) calculateBackoff(attempt int, policy *ResilienceRetryPolicy) time.Duration {
	// Calculate exponential backoff
	backoff := float64(policy.InitialInterval) * math.Pow(policy.Multiplier, float64(attempt))
	
	// Apply maximum interval cap
	if backoff > float64(policy.MaxInterval) {
		backoff = float64(policy.MaxInterval)
	}

	duration := time.Duration(backoff)

	// Add jitter if enabled
	if policy.Jitter {
		jitter := time.Duration(rand.Float64() * float64(duration) * 0.1) // 10% jitter
		duration += jitter
	}

	return duration
}

// ExecuteWithTimeout executes a function with timeout
func (rm *ResilienceManager) ExecuteWithTimeout(ctx context.Context, operation func(ctx context.Context) (interface{}, error), timeout time.Duration) (interface{}, error) {
	if timeout <= 0 {
		timeout = rm.config.Timeout.DefaultTimeout
	}

	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return operation(opCtx)
}

// ExecuteWithTimeoutAndOperation executes a function with operation-specific timeout
func (rm *ResilienceManager) ExecuteWithTimeoutAndOperation(ctx context.Context, operation func(ctx context.Context) (interface{}, error), operationType string) (interface{}, error) {
	timeout := rm.config.Timeout.DefaultTimeout
	
	if opTimeout, exists := rm.config.Timeout.OperationTimeouts[operationType]; exists {
		timeout = opTimeout
	}

	return rm.ExecuteWithTimeout(ctx, operation, timeout)
}

// GetCircuitBreakerState returns the current state of a circuit breaker
func (rm *ResilienceManager) GetCircuitBreakerState(database string) (string, error) {
	rm.mu.RLock()
	cb, exists := rm.circuitBreakers[database]
	rm.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("circuit breaker not found for database: %s", database)
	}

	return cb.State().String(), nil
}

// GetCircuitBreakerCounts returns the current counts of a circuit breaker
func (rm *ResilienceManager) GetCircuitBreakerCounts(database string) (gobreaker.Counts, error) {
	rm.mu.RLock()
	cb, exists := rm.circuitBreakers[database]
	rm.mu.RUnlock()

	if !exists {
		return gobreaker.Counts{}, fmt.Errorf("circuit breaker not found for database: %s", database)
	}

	return cb.Counts(), nil
}

// ResetCircuitBreaker resets a circuit breaker to closed state
func (rm *ResilienceManager) ResetCircuitBreaker(database string) error {
	rm.mu.RLock()
	cb, exists := rm.circuitBreakers[database]
	rm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("circuit breaker not found for database: %s", database)
	}

	// Create a new circuit breaker with the same settings
	var dbConfig DatabaseCircuitBreaker
	switch database {
	case "postgresql":
		dbConfig = rm.config.CircuitBreaker.PostgreSQL
	case "mongodb":
		dbConfig = rm.config.CircuitBreaker.MongoDB
	case "redis":
		dbConfig = rm.config.CircuitBreaker.Redis
	case "elasticsearch":
		dbConfig = rm.config.CircuitBreaker.Elasticsearch
	default:
		return fmt.Errorf("unknown database: %s", database)
	}

	settings := gobreaker.Settings{
		Name:        fmt.Sprintf("%s-circuit-breaker", database),
		MaxRequests: dbConfig.MaxRequests,
		Interval:    dbConfig.Interval,
		Timeout:     dbConfig.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= dbConfig.FailureThreshold
		},
	}

	if dbConfig.OnStateChangeEnabled {
		settings.OnStateChange = func(name string, from gobreaker.State, to gobreaker.State) {
			rm.logger.Warn("Circuit breaker state changed",
				zap.String("name", name),
				zap.String("from", from.String()),
				zap.String("to", to.String()))
		}
	}

	rm.mu.Lock()
	rm.circuitBreakers[database] = gobreaker.NewCircuitBreaker(settings)
	rm.mu.Unlock()

	rm.logger.Info("Circuit breaker reset", zap.String("database", database))
	return nil
}

// GetAllCircuitBreakerStates returns the states of all circuit breakers
func (rm *ResilienceManager) GetAllCircuitBreakerStates() map[string]string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	states := make(map[string]string)
	for database, cb := range rm.circuitBreakers {
		states[database] = cb.State().String()
	}

	return states
}

// GetAllCircuitBreakerCounts returns the counts of all circuit breakers
func (rm *ResilienceManager) GetAllCircuitBreakerCounts() map[string]gobreaker.Counts {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	counts := make(map[string]gobreaker.Counts)
	for database, cb := range rm.circuitBreakers {
		counts[database] = cb.Counts()
	}

	return counts
}

// IsRetryableError checks if an error is retryable for a specific database
func (rm *ResilienceManager) IsRetryableError(database string, err error) bool {
	if err == nil {
		return false
	}

	var retryConfig DatabaseRetry
	switch database {
	case "postgresql":
		retryConfig = rm.config.Retry.PostgreSQL
	case "mongodb":
		retryConfig = rm.config.Retry.MongoDB
	case "redis":
		retryConfig = rm.config.Retry.Redis
	case "elasticsearch":
		retryConfig = rm.config.Retry.Elasticsearch
	default:
		return false
	}

	if !retryConfig.Enabled {
		return false
	}

	errorMsg := err.Error()
	for _, retryableError := range retryConfig.RetryableErrors {
		if contains(errorMsg, retryableError) {
			return true
		}
	}

	return false
}

// GetStats returns resilience statistics
func (rm *ResilienceManager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	// Get circuit breaker stats
	cbStats := make(map[string]interface{})
	for database, cb := range rm.circuitBreakers {
		counts := cb.Counts()
		cbStats[database] = map[string]interface{}{
			"state":               cb.State().String(),
			"requests":            counts.Requests,
			"total_successes":     counts.TotalSuccesses,
			"total_failures":      counts.TotalFailures,
			"consecutive_successes": counts.ConsecutiveSuccesses,
			"consecutive_failures":  counts.ConsecutiveFailures,
		}
	}
	stats["circuit_breakers"] = cbStats

	// Get retry config stats
	retryStats := make(map[string]interface{})
	retryStats["postgresql"] = map[string]interface{}{
		"enabled":      rm.config.Retry.PostgreSQL.Enabled,
		"max_attempts": rm.config.Retry.PostgreSQL.MaxAttempts,
	}
	retryStats["mongodb"] = map[string]interface{}{
		"enabled":      rm.config.Retry.MongoDB.Enabled,
		"max_attempts": rm.config.Retry.MongoDB.MaxAttempts,
	}
	retryStats["redis"] = map[string]interface{}{
		"enabled":      rm.config.Retry.Redis.Enabled,
		"max_attempts": rm.config.Retry.Redis.MaxAttempts,
	}
	retryStats["elasticsearch"] = map[string]interface{}{
		"enabled":      rm.config.Retry.Elasticsearch.Enabled,
		"max_attempts": rm.config.Retry.Elasticsearch.MaxAttempts,
	}
	stats["retry"] = retryStats

	// Get timeout stats
	timeoutStats := map[string]interface{}{
		"default_timeout": rm.config.Timeout.DefaultTimeout.String(),
		"operation_timeouts": rm.config.Timeout.OperationTimeouts,
	}
	stats["timeout"] = timeoutStats

	// Get bulkhead stats
	bulkheadStats := map[string]interface{}{
		"enabled":                     rm.config.Bulkhead.Enabled,
		"max_concurrent_postgresql":   rm.config.Bulkhead.MaxConcurrentPostgreSQL,
		"max_concurrent_mongodb":      rm.config.Bulkhead.MaxConcurrentMongoDB,
		"max_concurrent_redis":        rm.config.Bulkhead.MaxConcurrentRedis,
		"max_concurrent_elasticsearch": rm.config.Bulkhead.MaxConcurrentElasticsearch,
	}
	stats["bulkhead"] = bulkheadStats

	return stats
}

// Close closes the resilience manager
func (rm *ResilienceManager) Close() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Circuit breakers don't need explicit closing
	rm.circuitBreakers = make(map[string]*gobreaker.CircuitBreaker)

	rm.logger.Info("Resilience manager closed")
	return nil
}