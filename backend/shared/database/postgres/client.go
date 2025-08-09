package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/sony/gobreaker"
	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// Client represents a sharded PostgreSQL client for iSECTECH
type Client struct {
	config         *Config
	shards         map[string]*ShardClient
	readReplicas   map[string][]*ReplicaClient
	logger         *zap.Logger
	circuitBreaker *gobreaker.CircuitBreaker
	mu             sync.RWMutex
	closed         bool
}

// ShardClient represents a connection to a specific PostgreSQL shard
type ShardClient struct {
	name     string
	config   *ShardConfig
	primary  *sqlx.DB
	replicas []*ReplicaClient
	cb       *gobreaker.CircuitBreaker
	logger   *zap.Logger
}

// ReplicaClient represents a connection to a read replica
type ReplicaClient struct {
	name   string
	config *ReplicaConfig
	db     *sqlx.DB
	cb     *gobreaker.CircuitBreaker
	logger *zap.Logger
}

// TenantContext represents the tenant context for row-level security
type TenantContext struct {
	TenantID     string
	UserID       string
	Role         string
	Permissions  []string
	SecurityTags map[string]string
}

// QueryOptions represents options for database queries
type QueryOptions struct {
	Tenant       *TenantContext
	ReadOnly     bool
	Timeout      time.Duration
	UseReplica   bool
	ShardKey     interface{}
	Consistency  ConsistencyLevel
}

// ConsistencyLevel defines read consistency requirements
type ConsistencyLevel int

const (
	ConsistencyEventual ConsistencyLevel = iota
	ConsistencyStrong
	ConsistencyLinearizable
)

// NewClient creates a new PostgreSQL client with sharding support
func NewClient(config *Config, logger *zap.Logger) (*Client, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	client := &Client{
		config:       config,
		shards:       make(map[string]*ShardClient),
		readReplicas: make(map[string][]*ReplicaClient),
		logger:       logger,
	}

	// Create circuit breaker for the client
	client.circuitBreaker = gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "postgres-client",
		MaxRequests: config.CircuitBreaker.MaxRequests,
		Interval:    config.CircuitBreaker.Interval,
		Timeout:     config.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= config.CircuitBreaker.FailureThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("Circuit breaker state changed",
				zap.String("name", name),
				zap.String("from", from.String()),
				zap.String("to", to.String()))
		},
	})

	// Initialize shards
	for _, shardConfig := range config.Shards {
		shard, err := client.createShard(&shardConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create shard %s: %w", shardConfig.Name, err)
		}
		client.shards[shardConfig.Name] = shard
	}

	logger.Info("PostgreSQL client initialized",
		zap.Int("shards", len(client.shards)),
		zap.Bool("rls_enabled", config.EnableRowLevelSecurity))

	return client, nil
}

// createShard creates a new shard client
func (c *Client) createShard(config *ShardConfig) (*ShardClient, error) {
	// Create primary connection
	primary, err := c.createConnection(config.DSN(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary connection: %w", err)
	}

	shard := &ShardClient{
		name:    config.Name,
		config:  config,
		primary: primary,
		logger:  c.logger.With(zap.String("shard", config.Name)),
	}

	// Create circuit breaker for this shard
	shard.cb = gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        fmt.Sprintf("postgres-shard-%s", config.Name),
		MaxRequests: c.config.CircuitBreaker.MaxRequests,
		Interval:    c.config.CircuitBreaker.Interval,
		Timeout:     c.config.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= c.config.CircuitBreaker.FailureThreshold
		},
	})

	// Initialize read replicas
	for _, replicaConfig := range config.ReadReplicas {
		replica, err := c.createReplica(&replicaConfig, config)
		if err != nil {
			c.logger.Warn("Failed to create read replica, continuing without it",
				zap.String("replica", replicaConfig.Name),
				zap.Error(err))
			continue
		}
		shard.replicas = append(shard.replicas, replica)
	}

	// Enable row-level security if configured
	if c.config.EnableRowLevelSecurity {
		if err := shard.enableRowLevelSecurity(); err != nil {
			return nil, fmt.Errorf("failed to enable row-level security: %w", err)
		}
	}

	return shard, nil
}

// createConnection creates a new database connection with proper settings
func (c *Client) createConnection(dsn string, config *ShardConfig) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxConns)
	db.SetMaxIdleConns(config.MinConns)
	db.SetConnMaxLifetime(config.MaxConnLifetime)
	db.SetConnMaxIdleTime(config.MaxConnIdleTime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), c.config.ConnectionTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// createReplica creates a new read replica client
func (c *Client) createReplica(config *ReplicaConfig, shardConfig *ShardConfig) (*ReplicaClient, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, shardConfig.Username, shardConfig.Password,
		shardConfig.Database, shardConfig.SSLMode,
	)

	db, err := c.createConnection(dsn, shardConfig)
	if err != nil {
		return nil, err
	}

	replica := &ReplicaClient{
		name:   config.Name,
		config: config,
		db:     db,
		logger: c.logger.With(zap.String("replica", config.Name)),
	}

	// Create circuit breaker for this replica
	replica.cb = gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        fmt.Sprintf("postgres-replica-%s", config.Name),
		MaxRequests: c.config.CircuitBreaker.MaxRequests,
		Interval:    c.config.CircuitBreaker.Interval,
		Timeout:     c.config.CircuitBreaker.Timeout,
	})

	return replica, nil
}

// GetShardClient returns the appropriate shard client for a given key
func (c *Client) GetShardClient(key interface{}) (*ShardClient, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, fmt.Errorf("client is closed")
	}

	shardConfig, err := c.config.GetShardForKey(key)
	if err != nil {
		return nil, err
	}

	shard, exists := c.shards[shardConfig.Name]
	if !exists {
		return nil, fmt.Errorf("shard %s not found", shardConfig.Name)
	}

	return shard, nil
}

// Query executes a query with tenant context and sharding
func (c *Client) Query(ctx context.Context, query string, args []interface{}, opts *QueryOptions) (*sqlx.Rows, error) {
	if opts == nil {
		opts = &QueryOptions{}
	}

	// Get appropriate shard
	shard, err := c.GetShardClient(opts.ShardKey)
	if err != nil {
		return nil, err
	}

	// Set tenant context if provided
	if opts.Tenant != nil {
		ctx = c.setTenantContext(ctx, opts.Tenant)
	}

	// Execute query with circuit breaker
	var rows *sqlx.Rows
	err = c.executeWithRetry(ctx, func() error {
		var execErr error
		rows, execErr = shard.Query(ctx, query, args, opts)
		return execErr
	})

	return rows, err
}

// Exec executes a statement with tenant context and sharding
func (c *Client) Exec(ctx context.Context, query string, args []interface{}, opts *QueryOptions) (sql.Result, error) {
	if opts == nil {
		opts = &QueryOptions{}
	}

	// Get appropriate shard
	shard, err := c.GetShardClient(opts.ShardKey)
	if err != nil {
		return nil, err
	}

	// Set tenant context if provided
	if opts.Tenant != nil {
		ctx = c.setTenantContext(ctx, opts.Tenant)
	}

	// Execute statement with circuit breaker
	var result sql.Result
	err = c.executeWithRetry(ctx, func() error {
		var execErr error
		result, execErr = shard.Exec(ctx, query, args, opts)
		return execErr
	})

	return result, err
}

// Transaction executes a function within a database transaction
func (c *Client) Transaction(ctx context.Context, shardKey interface{}, tenant *TenantContext, fn func(*sqlx.Tx) error) error {
	shard, err := c.GetShardClient(shardKey)
	if err != nil {
		return err
	}

	if tenant != nil {
		ctx = c.setTenantContext(ctx, tenant)
	}

	return c.executeWithRetry(ctx, func() error {
		return shard.Transaction(ctx, fn)
	})
}

// setTenantContext sets the tenant context for row-level security
func (c *Client) setTenantContext(ctx context.Context, tenant *TenantContext) context.Context {
	// Add tenant information to context for RLS
	ctx = context.WithValue(ctx, "tenant_id", tenant.TenantID)
	ctx = context.WithValue(ctx, "user_id", tenant.UserID)
	ctx = context.WithValue(ctx, "role", tenant.Role)
	ctx = context.WithValue(ctx, "permissions", tenant.Permissions)
	ctx = context.WithValue(ctx, "security_tags", tenant.SecurityTags)
	return ctx
}

// executeWithRetry executes a function with retry logic
func (c *Client) executeWithRetry(ctx context.Context, fn func() error) error {
	var lastErr error
	
	for attempt := 0; attempt < c.config.RetryConfig.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Execute function with circuit breaker
		result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
			return nil, fn()
		})
		
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if we should retry
		if !c.shouldRetry(err) || attempt == c.config.RetryConfig.MaxAttempts-1 {
			break
		}

		// Calculate backoff delay
		delay := c.calculateBackoffDelay(attempt)
		
		c.logger.Warn("Database operation failed, retrying",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
			zap.Duration("delay", delay))

		// Wait before retrying
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	return fmt.Errorf("database operation failed after %d attempts: %w", 
		c.config.RetryConfig.MaxAttempts, lastErr)
}

// shouldRetry determines if an error is retryable
func (c *Client) shouldRetry(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		// Retry on specific PostgreSQL errors
		switch pqErr.Code {
		case "08000", // connection_exception
			"08003", // connection_does_not_exist
			"08006", // connection_failure
			"53300", // too_many_connections
			"40001": // serialization_failure
			return true
		}
	}
	return false
}

// calculateBackoffDelay calculates exponential backoff delay
func (c *Client) calculateBackoffDelay(attempt int) time.Duration {
	delay := time.Duration(float64(c.config.RetryConfig.InitialInterval) * 
		(c.config.RetryConfig.Multiplier * float64(attempt)))
	
	if delay > c.config.RetryConfig.MaxInterval {
		delay = c.config.RetryConfig.MaxInterval
	}
	
	return delay
}

// Close closes all database connections
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	var errors []error
	
	for _, shard := range c.shards {
		if err := shard.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	c.closed = true

	if len(errors) > 0 {
		return fmt.Errorf("errors closing shards: %v", errors)
	}

	c.logger.Info("PostgreSQL client closed")
	return nil
}

// Health returns the health status of all shards
func (c *Client) Health(ctx context.Context) map[string]bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := make(map[string]bool)
	
	for name, shard := range c.shards {
		status[name] = shard.Health(ctx)
	}

	return status
}