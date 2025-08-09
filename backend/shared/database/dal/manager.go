package dal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/isectech/platform/shared/database/elasticsearch"
	"github.com/isectech/platform/shared/database/mongodb"
	"github.com/isectech/platform/shared/database/postgres"
	"github.com/isectech/platform/shared/database/redis"
)

// Manager represents the unified Data Access Layer for iSECTECH
type Manager struct {
	config *Config
	logger *zap.Logger
	
	// Database clients
	postgresql    *postgres.Client
	mongodb       *mongodb.Client
	redis         *redis.Client
	elasticsearch *elasticsearch.Client
	
	// Connection pool managers
	poolManager   *PoolManager
	
	// Resilience components
	resilience    *ResilienceManager
	
	// Caching layer
	cache         *CacheManager
	
	// Monitoring
	monitor       *MonitorManager
	
	// Transaction coordinator
	transactionCoordinator *TransactionCoordinator
	
	// Concurrency control
	semaphores    map[string]*semaphore.Weighted
	
	// Lifecycle management
	mu            sync.RWMutex
	closed        bool
	shutdownCh    chan struct{}
	wg            sync.WaitGroup
}

// TenantContext represents tenant and security context for operations
type TenantContext struct {
	TenantID              string
	UserID                string
	Role                  string
	SecurityClearance     string
	DataClassifications   []string
	Permissions           []string
	RequestID             string
	CorrelationID         string
	SourceIP              string
	UserAgent             string
}

// OperationOptions defines options for database operations
type OperationOptions struct {
	Tenant                *TenantContext
	Timeout               time.Duration
	UseCache              bool
	CacheStrategy         string
	Consistency           ConsistencyLevel
	RetryPolicy           *RetryPolicy
	CircuitBreakerEnabled bool
	EnableAudit           bool
	TransactionID         string
	ReadPreference        ReadPreference
	WritePreference       WritePreference
}

// ConsistencyLevel defines data consistency requirements
type ConsistencyLevel string

const (
	ConsistencyEventual ConsistencyLevel = "eventual"
	ConsistencyStrong   ConsistencyLevel = "strong"
	ConsistencySession  ConsistencyLevel = "session"
)

// ReadPreference defines read preference for database operations
type ReadPreference string

const (
	ReadPrimary           ReadPreference = "primary"
	ReadSecondary         ReadPreference = "secondary"
	ReadSecondaryPreferred ReadPreference = "secondary_preferred"
	ReadNearest           ReadPreference = "nearest"
)

// WritePreference defines write preference for database operations
type WritePreference string

const (
	WriteMajority WritePreference = "majority"
	WriteAcknowledged WritePreference = "acknowledged"
	WriteUnacknowledged WritePreference = "unacknowledged"
)

// RetryPolicy defines custom retry policy for operations
type RetryPolicy struct {
	MaxAttempts     int
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	Jitter          bool
}

// DatabaseHealth represents health status of a database
type DatabaseHealth struct {
	Database      string    `json:"database"`
	Status        string    `json:"status"`
	ResponseTime  time.Duration `json:"response_time"`
	LastChecked   time.Time `json:"last_checked"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// OperationMetrics represents metrics for a database operation
type OperationMetrics struct {
	Database      string        `json:"database"`
	Operation     string        `json:"operation"`
	Duration      time.Duration `json:"duration"`
	Success       bool          `json:"success"`
	Error         string        `json:"error,omitempty"`
	RecordsAffected int64       `json:"records_affected"`
	CacheHit      bool          `json:"cache_hit"`
	RetryCount    int           `json:"retry_count"`
	Timestamp     time.Time     `json:"timestamp"`
}

// NewManager creates a new Data Access Layer manager
func NewManager(config *Config, logger *zap.Logger) (*Manager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	manager := &Manager{
		config:     config,
		logger:     logger,
		semaphores: make(map[string]*semaphore.Weighted),
		shutdownCh: make(chan struct{}),
	}

	// Initialize semaphores for bulkhead pattern
	if config.Resilience.Bulkhead.Enabled {
		manager.semaphores["postgresql"] = semaphore.NewWeighted(int64(config.Resilience.Bulkhead.MaxConcurrentPostgreSQL))
		manager.semaphores["mongodb"] = semaphore.NewWeighted(int64(config.Resilience.Bulkhead.MaxConcurrentMongoDB))
		manager.semaphores["redis"] = semaphore.NewWeighted(int64(config.Resilience.Bulkhead.MaxConcurrentRedis))
		manager.semaphores["elasticsearch"] = semaphore.NewWeighted(int64(config.Resilience.Bulkhead.MaxConcurrentElasticsearch))
	}

	// Initialize database clients
	if err := manager.initializeClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize database clients: %w", err)
	}

	// Initialize managers
	if err := manager.initializeManagers(); err != nil {
		return nil, fmt.Errorf("failed to initialize managers: %w", err)
	}

	// Start background processes
	manager.startBackgroundProcesses()

	logger.Info("Data Access Layer manager initialized successfully")
	return manager, nil
}

// initializeClients initializes all database clients
func (m *Manager) initializeClients() error {
	var err error

	// Initialize PostgreSQL client
	m.postgresql, err = postgres.NewClient(m.config.PostgreSQL, m.logger.With(zap.String("component", "postgresql")))
	if err != nil {
		return fmt.Errorf("failed to initialize PostgreSQL client: %w", err)
	}

	// Initialize MongoDB client
	m.mongodb, err = mongodb.NewClient(m.config.MongoDB, m.logger.With(zap.String("component", "mongodb")))
	if err != nil {
		return fmt.Errorf("failed to initialize MongoDB client: %w", err)
	}

	// Initialize Redis client
	m.redis, err = redis.NewClient(m.config.Redis, m.logger.With(zap.String("component", "redis")))
	if err != nil {
		return fmt.Errorf("failed to initialize Redis client: %w", err)
	}

	// Initialize Elasticsearch client
	m.elasticsearch, err = elasticsearch.NewClient(m.config.Elasticsearch, m.logger.With(zap.String("component", "elasticsearch")))
	if err != nil {
		return fmt.Errorf("failed to initialize Elasticsearch client: %w", err)
	}

	return nil
}

// initializeManagers initializes all sub-managers
func (m *Manager) initializeManagers() error {
	var err error

	// Initialize pool manager
	m.poolManager, err = NewPoolManager(m.config, m.logger.With(zap.String("component", "pool")))
	if err != nil {
		return fmt.Errorf("failed to initialize pool manager: %w", err)
	}

	// Initialize resilience manager
	m.resilience, err = NewResilienceManager(m.config.Resilience, m.logger.With(zap.String("component", "resilience")))
	if err != nil {
		return fmt.Errorf("failed to initialize resilience manager: %w", err)
	}

	// Initialize cache manager
	m.cache, err = NewCacheManager(m.config.Caching, m.redis, m.logger.With(zap.String("component", "cache")))
	if err != nil {
		return fmt.Errorf("failed to initialize cache manager: %w", err)
	}

	// Initialize monitor manager
	m.monitor, err = NewMonitorManager(m.config.Monitoring, m.logger.With(zap.String("component", "monitor")))
	if err != nil {
		return fmt.Errorf("failed to initialize monitor manager: %w", err)
	}

	// Initialize transaction coordinator
	m.transactionCoordinator, err = NewTransactionCoordinator(m.config.Transactions, m.logger.With(zap.String("component", "transaction")))
	if err != nil {
		return fmt.Errorf("failed to initialize transaction coordinator: %w", err)
	}

	return nil
}

// startBackgroundProcesses starts background monitoring and maintenance processes
func (m *Manager) startBackgroundProcesses() {
	// Start health monitoring
	if m.config.Monitoring.Enabled {
		m.wg.Add(1)
		go m.healthMonitorLoop()
	}

	// Start metrics collection
	if m.config.Monitoring.Enabled {
		m.wg.Add(1)
		go m.metricsCollectionLoop()
	}

	// Start cache maintenance
	if m.config.Caching.Enabled {
		m.wg.Add(1)
		go m.cacheMaintenance()
	}

	// Start connection pool maintenance
	m.wg.Add(1)
	go m.poolMaintenance()
}

// ExecuteInDatabase executes an operation in a specific database with full DAL features
func (m *Manager) ExecuteInDatabase(ctx context.Context, database string, operation func(ctx context.Context) (interface{}, error), opts *OperationOptions) (interface{}, error) {
	// Apply defaults
	if opts == nil {
		opts = &OperationOptions{}
	}
	if opts.Timeout == 0 {
		opts.Timeout = m.config.Resilience.Timeout.DefaultTimeout
	}

	// Create operation context with timeout
	opCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Acquire semaphore for bulkhead isolation
	if m.config.Resilience.Bulkhead.Enabled {
		if sem, exists := m.semaphores[database]; exists {
			if err := sem.Acquire(opCtx, 1); err != nil {
				return nil, fmt.Errorf("failed to acquire semaphore for %s: %w", database, err)
			}
			defer sem.Release(1)
		}
	}

	// Start timing for metrics
	startTime := time.Now()
	var result interface{}
	var err error
	var retryCount int

	// Execute with resilience patterns
	if m.config.Resilience.CircuitBreaker.PostgreSQL.Enabled && database == "postgresql" ||
		m.config.Resilience.CircuitBreaker.MongoDB.Enabled && database == "mongodb" ||
		m.config.Resilience.CircuitBreaker.Redis.Enabled && database == "redis" ||
		m.config.Resilience.CircuitBreaker.Elasticsearch.Enabled && database == "elasticsearch" {
		
		result, err = m.resilience.ExecuteWithCircuitBreaker(opCtx, database, operation)
	} else {
		result, err = operation(opCtx)
	}

	// Retry if needed and enabled
	if err != nil && m.shouldRetry(database, err, opts) {
		result, err, retryCount = m.executeWithRetry(opCtx, database, operation, opts)
	}

	// Record metrics
	duration := time.Since(startTime)
	m.recordOperationMetrics(database, "execute", duration, err == nil, err, 0, false, retryCount)

	// Log audit if enabled
	if opts.EnableAudit && opts.Tenant != nil {
		m.logAuditEvent(opts.Tenant, database, "execute", err == nil, duration)
	}

	return result, err
}

// executeWithRetry executes an operation with retry logic
func (m *Manager) executeWithRetry(ctx context.Context, database string, operation func(ctx context.Context) (interface{}, error), opts *OperationOptions) (interface{}, error, int) {
	var retryConfig DatabaseRetry
	
	switch database {
	case "postgresql":
		retryConfig = m.config.Resilience.Retry.PostgreSQL
	case "mongodb":
		retryConfig = m.config.Resilience.Retry.MongoDB
	case "redis":
		retryConfig = m.config.Resilience.Retry.Redis
	case "elasticsearch":
		retryConfig = m.config.Resilience.Retry.Elasticsearch
	default:
		return nil, fmt.Errorf("unknown database: %s", database), 0
	}

	if opts.RetryPolicy != nil {
		// Use custom retry policy
		return m.resilience.ExecuteWithCustomRetry(ctx, operation, &ResilienceRetryPolicy{
			MaxAttempts:     opts.RetryPolicy.MaxAttempts,
			InitialInterval: opts.RetryPolicy.InitialInterval,
			MaxInterval:     opts.RetryPolicy.MaxInterval,
			Multiplier:      opts.RetryPolicy.Multiplier,
			Jitter:          opts.RetryPolicy.Jitter,
		})
	}

	// Use configured retry policy
	return m.resilience.ExecuteWithRetry(ctx, database, operation)
}

// shouldRetry determines if an operation should be retried
func (m *Manager) shouldRetry(database string, err error, opts *OperationOptions) bool {
	if err == nil {
		return false
	}

	var retryConfig DatabaseRetry
	switch database {
	case "postgresql":
		retryConfig = m.config.Resilience.Retry.PostgreSQL
	case "mongodb":
		retryConfig = m.config.Resilience.Retry.MongoDB
	case "redis":
		retryConfig = m.config.Resilience.Retry.Redis
	case "elasticsearch":
		retryConfig = m.config.Resilience.Retry.Elasticsearch
	default:
		return false
	}

	if !retryConfig.Enabled {
		return false
	}

	// Check if error is retryable
	errorMsg := err.Error()
	for _, retryableError := range retryConfig.RetryableErrors {
		if contains(errorMsg, retryableError) {
			return true
		}
	}

	return false
}

// GetPostgreSQL returns the PostgreSQL client
func (m *Manager) GetPostgreSQL() *postgres.Client {
	return m.postgresql
}

// GetMongoDB returns the MongoDB client
func (m *Manager) GetMongoDB() *mongodb.Client {
	return m.mongodb
}

// GetRedis returns the Redis client
func (m *Manager) GetRedis() *redis.Client {
	return m.redis
}

// GetElasticsearch returns the Elasticsearch client
func (m *Manager) GetElasticsearch() *elasticsearch.Client {
	return m.elasticsearch
}

// GetCache returns the cache manager
func (m *Manager) GetCache() *CacheManager {
	return m.cache
}

// GetHealth returns the health status of all databases
func (m *Manager) GetHealth(ctx context.Context) (map[string]DatabaseHealth, error) {
	health := make(map[string]DatabaseHealth)
	
	// Check PostgreSQL health
	pgHealth := m.checkDatabaseHealth(ctx, "postgresql", func(ctx context.Context) error {
		return m.postgresql.Ping(ctx)
	})
	health["postgresql"] = pgHealth
	
	// Check MongoDB health
	mongoHealth := m.checkDatabaseHealth(ctx, "mongodb", func(ctx context.Context) error {
		return m.mongodb.Ping(ctx)
	})
	health["mongodb"] = mongoHealth
	
	// Check Redis health
	redisHealth := m.checkDatabaseHealth(ctx, "redis", func(ctx context.Context) error {
		return m.redis.Ping(ctx)
	})
	health["redis"] = redisHealth
	
	// Check Elasticsearch health
	esHealth := m.checkDatabaseHealth(ctx, "elasticsearch", func(ctx context.Context) error {
		return m.elasticsearch.Ping(ctx)
	})
	health["elasticsearch"] = esHealth
	
	return health, nil
}

// checkDatabaseHealth checks the health of a specific database
func (m *Manager) checkDatabaseHealth(ctx context.Context, database string, healthCheck func(ctx context.Context) error) DatabaseHealth {
	start := time.Now()
	err := healthCheck(ctx)
	duration := time.Since(start)
	
	health := DatabaseHealth{
		Database:     database,
		ResponseTime: duration,
		LastChecked:  start,
	}
	
	if err != nil {
		health.Status = "unhealthy"
		health.ErrorMessage = err.Error()
	} else {
		health.Status = "healthy"
	}
	
	return health
}

// recordOperationMetrics records metrics for a database operation
func (m *Manager) recordOperationMetrics(database, operation string, duration time.Duration, success bool, err error, recordsAffected int64, cacheHit bool, retryCount int) {
	if !m.config.Monitoring.Enabled {
		return
	}

	metrics := OperationMetrics{
		Database:        database,
		Operation:       operation,
		Duration:        duration,
		Success:         success,
		RecordsAffected: recordsAffected,
		CacheHit:        cacheHit,
		RetryCount:      retryCount,
		Timestamp:       time.Now(),
	}

	if err != nil {
		metrics.Error = err.Error()
	}

	// Send to monitor manager
	if m.monitor != nil {
		m.monitor.RecordOperationMetrics(metrics)
	}

	// Log slow queries
	if duration > m.config.Monitoring.SlowQueryThreshold {
		m.logger.Warn("Slow database operation detected",
			zap.String("database", database),
			zap.String("operation", operation),
			zap.Duration("duration", duration),
			zap.Bool("success", success),
			zap.Int("retry_count", retryCount))
	}
}

// logAuditEvent logs an audit event for database operations
func (m *Manager) logAuditEvent(tenant *TenantContext, database, operation string, success bool, duration time.Duration) {
	if !m.config.EnableAuditLogging {
		return
	}

	auditEvent := map[string]interface{}{
		"tenant_id":    tenant.TenantID,
		"user_id":      tenant.UserID,
		"database":     database,
		"operation":    operation,
		"success":      success,
		"duration_ms":  duration.Milliseconds(),
		"timestamp":    time.Now(),
		"request_id":   tenant.RequestID,
		"correlation_id": tenant.CorrelationID,
		"source_ip":    tenant.SourceIP,
		"user_agent":   tenant.UserAgent,
	}

	// Log to structured logger
	if success {
		m.logger.Info("Database operation audit", zap.Any("audit", auditEvent))
	} else {
		m.logger.Warn("Failed database operation audit", zap.Any("audit", auditEvent))
	}

	// TODO: Send to centralized audit system
}

// healthMonitorLoop runs the health monitoring background process
func (m *Manager) healthMonitorLoop() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.Monitoring.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			health, err := m.GetHealth(ctx)
			cancel()
			
			if err != nil {
				m.logger.Error("Health check failed", zap.Error(err))
			} else {
				// Log unhealthy databases
				for db, status := range health {
					if status.Status != "healthy" {
						m.logger.Warn("Database unhealthy",
							zap.String("database", db),
							zap.String("error", status.ErrorMessage),
							zap.Duration("response_time", status.ResponseTime))
					}
				}
			}
		case <-m.shutdownCh:
			return
		}
	}
}

// metricsCollectionLoop runs the metrics collection background process
func (m *Manager) metricsCollectionLoop() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.Monitoring.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Collect and report metrics
			if m.monitor != nil {
				m.monitor.CollectMetrics()
			}
		case <-m.shutdownCh:
			return
		}
	}
}

// cacheMaintenance runs cache maintenance tasks
func (m *Manager) cacheMaintenance() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if m.cache != nil {
				m.cache.RunMaintenance()
			}
		case <-m.shutdownCh:
			return
		}
	}
}

// poolMaintenance runs connection pool maintenance tasks
func (m *Manager) poolMaintenance() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if m.poolManager != nil {
				m.poolManager.RunMaintenance()
			}
		case <-m.shutdownCh:
			return
		}
	}
}

// Close closes the Data Access Layer manager and all database connections
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	close(m.shutdownCh)

	// Wait for background processes to finish
	m.wg.Wait()

	// Close all database clients
	var errors []error

	if m.postgresql != nil {
		if err := m.postgresql.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close PostgreSQL: %w", err))
		}
	}

	if m.mongodb != nil {
		if err := m.mongodb.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close MongoDB: %w", err))
		}
	}

	if m.redis != nil {
		if err := m.redis.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close Redis: %w", err))
		}
	}

	if m.elasticsearch != nil {
		if err := m.elasticsearch.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close Elasticsearch: %w", err))
		}
	}

	// Close sub-managers
	if m.cache != nil {
		if err := m.cache.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close cache manager: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during close: %v", errors)
	}

	m.logger.Info("Data Access Layer manager closed")
	return nil
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		 findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}