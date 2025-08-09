package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// PoolConfig represents connection pool configuration
type PoolConfig struct {
	// Pool settings
	MaxConnections    int           `yaml:"max_connections" json:"max_connections"`
	MinConnections    int           `yaml:"min_connections" json:"min_connections"`
	MaxIdleTime       time.Duration `yaml:"max_idle_time" json:"max_idle_time"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout" json:"connection_timeout"`
	
	// Health check settings
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	MaxRetries          int           `yaml:"max_retries" json:"max_retries"`
	
	// Load balancing
	Strategy string `yaml:"strategy" json:"strategy"` // round_robin, random, least_connections
}

// ConnectionPool manages a pool of gRPC client connections
type ConnectionPool struct {
	config      *PoolConfig
	clientConfig *ClientConfig
	logger      *zap.Logger
	
	// Connection management
	connections []*pooledConnection
	available   chan *pooledConnection
	mutex       sync.RWMutex
	closed      bool
	
	// Round robin counter
	roundRobinCounter uint64
	
	// Statistics
	stats *PoolStats
}

// pooledConnection represents a connection in the pool
type pooledConnection struct {
	client    *Client
	conn      *grpc.ClientConn
	createdAt time.Time
	lastUsed  time.Time
	inUse     bool
	id        int
}

// PoolStats contains pool statistics
type PoolStats struct {
	TotalConnections     int           `json:"total_connections"`
	ActiveConnections    int           `json:"active_connections"`
	IdleConnections      int           `json:"idle_connections"`
	TotalRequests        uint64        `json:"total_requests"`
	FailedConnections    uint64        `json:"failed_connections"`
	AverageResponseTime  time.Duration `json:"average_response_time"`
}

// NewConnectionPool creates a new gRPC connection pool
func NewConnectionPool(poolConfig *PoolConfig, clientConfig *ClientConfig, logger *zap.Logger) (*ConnectionPool, error) {
	if poolConfig == nil {
		poolConfig = DefaultPoolConfig()
	}
	
	if clientConfig == nil {
		return nil, fmt.Errorf("client config is required")
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	pool := &ConnectionPool{
		config:      poolConfig,
		clientConfig: clientConfig,
		logger:      logger,
		connections: make([]*pooledConnection, 0, poolConfig.MaxConnections),
		available:   make(chan *pooledConnection, poolConfig.MaxConnections),
		stats:       &PoolStats{},
	}

	// Create minimum connections
	for i := 0; i < poolConfig.MinConnections; i++ {
		conn, err := pool.createConnection(i)
		if err != nil {
			logger.Error("Failed to create initial connection", zap.Int("connection_id", i), zap.Error(err))
			continue
		}
		
		pool.connections = append(pool.connections, conn)
		pool.available <- conn
	}

	// Start health check routine
	go pool.healthCheckRoutine()

	logger.Info("gRPC connection pool created",
		zap.Int("min_connections", poolConfig.MinConnections),
		zap.Int("max_connections", poolConfig.MaxConnections),
		zap.Int("initial_connections", len(pool.connections)),
	)

	return pool, nil
}

// createConnection creates a new pooled connection
func (p *ConnectionPool) createConnection(id int) (*pooledConnection, error) {
	client, err := NewClient(p.clientConfig, p.logger)
	if err != nil {
		p.stats.FailedConnections++
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	conn := &pooledConnection{
		client:    client,
		conn:      client.GetConnection(),
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		inUse:     false,
		id:        id,
	}

	return conn, nil
}

// GetConnection gets a connection from the pool
func (p *ConnectionPool) GetConnection(ctx context.Context) (*grpc.ClientConn, func(), error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.closed {
		return nil, nil, fmt.Errorf("connection pool is closed")
	}

	// Try to get an available connection
	select {
	case conn := <-p.available:
		// Check if connection is still healthy
		if !p.isConnectionHealthy(conn) {
			p.logger.Debug("Removing unhealthy connection", zap.Int("connection_id", conn.id))
			p.removeConnection(conn)
			return p.GetConnection(ctx) // Retry
		}
		
		conn.inUse = true
		conn.lastUsed = time.Now()
		p.stats.TotalRequests++
		
		// Return connection with release function
		release := func() {
			p.releaseConnection(conn)
		}
		
		return conn.conn, release, nil
		
	default:
		// No available connections, try to create a new one
		if len(p.connections) < p.config.MaxConnections {
			newConn, err := p.createConnection(len(p.connections))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create new connection: %w", err)
			}
			
			p.connections = append(p.connections, newConn)
			newConn.inUse = true
			newConn.lastUsed = time.Now()
			p.stats.TotalRequests++
			
			release := func() {
				p.releaseConnection(newConn)
			}
			
			return newConn.conn, release, nil
		}
		
		// Pool is full, wait for a connection with timeout
		select {
		case conn := <-p.available:
			if !p.isConnectionHealthy(conn) {
				p.removeConnection(conn)
				return p.GetConnection(ctx) // Retry
			}
			
			conn.inUse = true
			conn.lastUsed = time.Now()
			p.stats.TotalRequests++
			
			release := func() {
				p.releaseConnection(conn)
			}
			
			return conn.conn, release, nil
			
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

// releaseConnection returns a connection to the pool
func (p *ConnectionPool) releaseConnection(conn *pooledConnection) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.closed {
		p.closeConnection(conn)
		return
	}

	conn.inUse = false
	conn.lastUsed = time.Now()

	// Check if connection should be removed due to age
	if time.Since(conn.createdAt) > p.config.MaxIdleTime {
		p.removeConnection(conn)
		return
	}

	// Return to available pool
	select {
	case p.available <- conn:
		// Successfully returned to pool
	default:
		// Pool is full, close this connection
		p.removeConnection(conn)
	}
}

// isConnectionHealthy checks if a connection is healthy
func (p *ConnectionPool) isConnectionHealthy(conn *pooledConnection) bool {
	if conn.conn == nil {
		return false
	}
	
	state := conn.conn.GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// removeConnection removes a connection from the pool
func (p *ConnectionPool) removeConnection(conn *pooledConnection) {
	// Remove from connections slice
	for i, c := range p.connections {
		if c.id == conn.id {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}
	
	p.closeConnection(conn)
}

// closeConnection closes a single connection
func (p *ConnectionPool) closeConnection(conn *pooledConnection) {
	if conn.client != nil {
		if err := conn.client.Close(); err != nil {
			p.logger.Error("Failed to close connection", zap.Int("connection_id", conn.id), zap.Error(err))
		}
	}
}

// healthCheckRoutine periodically checks connection health
func (p *ConnectionPool) healthCheckRoutine() {
	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.mutex.Lock()
		if p.closed {
			p.mutex.Unlock()
			return
		}
		
		// Check all connections
		for _, conn := range p.connections {
			if !conn.inUse && !p.isConnectionHealthy(conn) {
				p.logger.Debug("Removing unhealthy connection during health check", zap.Int("connection_id", conn.id))
				p.removeConnection(conn)
			}
		}
		
		// Maintain minimum connections
		for len(p.connections) < p.config.MinConnections {
			newConn, err := p.createConnection(len(p.connections))
			if err != nil {
				p.logger.Error("Failed to create replacement connection", zap.Error(err))
				break
			}
			
			p.connections = append(p.connections, newConn)
			p.available <- newConn
		}
		
		p.mutex.Unlock()
	}
}

// GetStats returns current pool statistics
func (p *ConnectionPool) GetStats() *PoolStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	stats := &PoolStats{
		TotalConnections:  len(p.connections),
		TotalRequests:     p.stats.TotalRequests,
		FailedConnections: p.stats.FailedConnections,
	}

	// Count active and idle connections
	for _, conn := range p.connections {
		if conn.inUse {
			stats.ActiveConnections++
		} else {
			stats.IdleConnections++
		}
	}

	return stats
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.available)

	// Close all connections
	for _, conn := range p.connections {
		p.closeConnection(conn)
	}

	p.logger.Info("gRPC connection pool closed", zap.Int("connections_closed", len(p.connections)))
	return nil
}

// DefaultPoolConfig returns a default pool configuration
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxConnections:      10,
		MinConnections:      2,
		MaxIdleTime:         30 * time.Minute,
		ConnectionTimeout:   30 * time.Second,
		HealthCheckInterval: 30 * time.Second,
		MaxRetries:          3,
		Strategy:            "round_robin",
	}
}