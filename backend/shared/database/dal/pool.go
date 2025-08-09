package dal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PoolManager manages connection pools across all databases
type PoolManager struct {
	config     ConnectionPoolConfig
	logger     *zap.Logger
	pools      map[string]*DatabasePool
	mu         sync.RWMutex
	monitoring *PoolMonitoring
	closed     bool
}

// DatabasePool represents a connection pool for a specific database
type DatabasePool struct {
	Name            string
	Type            string // postgresql, mongodb, redis, elasticsearch
	Config          interface{}
	ActiveConns     int
	IdleConns       int
	MaxConns        int
	TotalConns      int
	AcquiredConns   int64
	ReleasedConns   int64
	FailedAcquires  int64
	AcquireTime     time.Duration
	HealthScore     float64
	LastHealthCheck time.Time
	mu              sync.RWMutex
}

// PoolMonitoring handles pool monitoring and alerting
type PoolMonitoring struct {
	config    MonitoringConfig
	logger    *zap.Logger
	alerts    []PoolAlert
	mu        sync.RWMutex
}

// PoolAlert represents a pool-related alert
type PoolAlert struct {
	ID          string
	PoolName    string
	AlertType   string
	Severity    string
	Message     string
	TriggeredAt time.Time
	Resolved    bool
	ResolvedAt  *time.Time
}

// PoolStats represents connection pool statistics
type PoolStats struct {
	PoolName            string        `json:"pool_name"`
	Type                string        `json:"type"`
	ActiveConnections   int           `json:"active_connections"`
	IdleConnections     int           `json:"idle_connections"`
	MaxConnections      int           `json:"max_connections"`
	TotalConnections    int           `json:"total_connections"`
	AcquiredConnections int64         `json:"acquired_connections"`
	ReleasedConnections int64         `json:"released_connections"`
	FailedAcquires      int64         `json:"failed_acquires"`
	UtilizationRate     float64       `json:"utilization_rate"`
	AverageAcquireTime  time.Duration `json:"average_acquire_time"`
	HealthScore         float64       `json:"health_score"`
	LastHealthCheck     time.Time     `json:"last_health_check"`
}

// NewPoolManager creates a new connection pool manager
func NewPoolManager(config *Config, logger *zap.Logger) (*PoolManager, error) {
	pm := &PoolManager{
		config: config.ConnectionPooling,
		logger: logger,
		pools:  make(map[string]*DatabasePool),
		monitoring: &PoolMonitoring{
			config: config.Monitoring,
			logger: logger.With(zap.String("component", "pool-monitoring")),
			alerts: make([]PoolAlert, 0),
		},
	}

	// Initialize database pools
	if err := pm.initializePools(config); err != nil {
		return nil, fmt.Errorf("failed to initialize pools: %w", err)
	}

	logger.Info("Pool manager initialized",
		zap.Int("pools", len(pm.pools)),
		zap.Int("max_open_connections", config.ConnectionPooling.MaxOpenConnections))

	return pm, nil
}

// initializePools initializes pools for each database type
func (pm *PoolManager) initializePools(config *Config) error {
	// PostgreSQL pool
	if config.PostgreSQL != nil {
		pgPool := &DatabasePool{
			Name:        "postgresql",
			Type:        "postgresql",
			Config:      config.PostgreSQL,
			MaxConns:    config.ConnectionPooling.PostgreSQL.MaxConnections,
			HealthScore: 1.0,
		}
		pm.pools["postgresql"] = pgPool
	}

	// MongoDB pool
	if config.MongoDB != nil {
		mongoPool := &DatabasePool{
			Name:        "mongodb",
			Type:        "mongodb",
			Config:      config.MongoDB,
			MaxConns:    int(config.ConnectionPooling.MongoDB.MaxPoolSize),
			HealthScore: 1.0,
		}
		pm.pools["mongodb"] = mongoPool
	}

	// Redis pool
	if config.Redis != nil {
		redisPool := &DatabasePool{
			Name:        "redis",
			Type:        "redis",
			Config:      config.Redis,
			MaxConns:    config.ConnectionPooling.Redis.PoolSize,
			HealthScore: 1.0,
		}
		pm.pools["redis"] = redisPool
	}

	// Elasticsearch pool
	if config.Elasticsearch != nil {
		esPool := &DatabasePool{
			Name:        "elasticsearch",
			Type:        "elasticsearch",
			Config:      config.Elasticsearch,
			MaxConns:    config.ConnectionPooling.Elasticsearch.MaxIdleConns,
			HealthScore: 1.0,
		}
		pm.pools["elasticsearch"] = esPool
	}

	return nil
}

// GetPool returns a specific database pool
func (pm *PoolManager) GetPool(name string) (*DatabasePool, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.closed {
		return nil, fmt.Errorf("pool manager is closed")
	}

	pool, exists := pm.pools[name]
	if !exists {
		return nil, fmt.Errorf("pool %s not found", name)
	}

	return pool, nil
}

// UpdatePoolMetrics updates metrics for a specific pool
func (pm *PoolManager) UpdatePoolMetrics(poolName string, active, idle, total int, acquired, released, failed int64, acquireTime time.Duration) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pool, exists := pm.pools[poolName]
	if !exists {
		return fmt.Errorf("pool %s not found", poolName)
	}

	pool.mu.Lock()
	pool.ActiveConns = active
	pool.IdleConns = idle
	pool.TotalConns = total
	pool.AcquiredConns = acquired
	pool.ReleasedConns = released
	pool.FailedAcquires = failed
	pool.AcquireTime = acquireTime
	pool.mu.Unlock()

	// Check for alerts
	pm.checkPoolHealth(pool)

	return nil
}

// checkPoolHealth checks pool health and generates alerts if needed
func (pm *PoolManager) checkPoolHealth(pool *DatabasePool) {
	utilizationRate := float64(pool.ActiveConns) / float64(pool.MaxConns)
	
	// High utilization alert (>90%)
	if utilizationRate > 0.9 {
		pm.monitoring.generateAlert(pool.Name, "high_utilization", "warning",
			fmt.Sprintf("Connection pool utilization is %.1f%%", utilizationRate*100))
	}

	// Failed acquires alert
	if pool.FailedAcquires > 0 {
		pm.monitoring.generateAlert(pool.Name, "failed_acquires", "critical",
			fmt.Sprintf("Pool has %d failed connection acquisitions", pool.FailedAcquires))
	}

	// Slow acquire time alert (>5 seconds)
	if pool.AcquireTime > 5*time.Second {
		pm.monitoring.generateAlert(pool.Name, "slow_acquire", "warning",
			fmt.Sprintf("Average connection acquire time is %v", pool.AcquireTime))
	}

	// Update health score
	healthScore := 1.0
	if utilizationRate > 0.8 {
		healthScore -= (utilizationRate - 0.8) * 2 // Penalize high utilization
	}
	if pool.FailedAcquires > 0 {
		healthScore -= 0.2 // Penalize failed acquires
	}
	if pool.AcquireTime > time.Second {
		healthScore -= float64(pool.AcquireTime.Milliseconds()) / 10000.0 // Penalize slow acquires
	}

	if healthScore < 0 {
		healthScore = 0
	}

	pool.mu.Lock()
	pool.HealthScore = healthScore
	pool.LastHealthCheck = time.Now()
	pool.mu.Unlock()
}

// GetAllPoolStats returns statistics for all pools
func (pm *PoolManager) GetAllPoolStats() map[string]*PoolStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]*PoolStats)
	
	for name, pool := range pm.pools {
		pool.mu.RLock()
		utilizationRate := float64(pool.ActiveConns) / float64(pool.MaxConns)
		stats[name] = &PoolStats{
			PoolName:            pool.Name,
			Type:                pool.Type,
			ActiveConnections:   pool.ActiveConns,
			IdleConnections:     pool.IdleConns,
			MaxConnections:      pool.MaxConns,
			TotalConnections:    pool.TotalConns,
			AcquiredConnections: pool.AcquiredConns,
			ReleasedConnections: pool.ReleasedConns,
			FailedAcquires:      pool.FailedAcquires,
			UtilizationRate:     utilizationRate,
			AverageAcquireTime:  pool.AcquireTime,
			HealthScore:         pool.HealthScore,
			LastHealthCheck:     pool.LastHealthCheck,
		}
		pool.mu.RUnlock()
	}

	return stats
}

// GetPoolStats returns statistics for a specific pool
func (pm *PoolManager) GetPoolStats(poolName string) (*PoolStats, error) {
	pool, err := pm.GetPool(poolName)
	if err != nil {
		return nil, err
	}

	pool.mu.RLock()
	defer pool.mu.RUnlock()

	utilizationRate := float64(pool.ActiveConns) / float64(pool.MaxConns)
	return &PoolStats{
		PoolName:            pool.Name,
		Type:                pool.Type,
		ActiveConnections:   pool.ActiveConns,
		IdleConnections:     pool.IdleConns,
		MaxConnections:      pool.MaxConns,
		TotalConnections:    pool.TotalConns,
		AcquiredConnections: pool.AcquiredConns,
		ReleasedConnections: pool.ReleasedConns,
		FailedAcquires:      pool.FailedAcquires,
		UtilizationRate:     utilizationRate,
		AverageAcquireTime:  pool.AcquireTime,
		HealthScore:         pool.HealthScore,
		LastHealthCheck:     pool.LastHealthCheck,
	}, nil
}

// OptimizePoolSizes analyzes usage patterns and suggests optimal pool sizes
func (pm *PoolManager) OptimizePoolSizes() map[string]int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	recommendations := make(map[string]int)
	
	for name, pool := range pm.pools {
		pool.mu.RLock()
		utilizationRate := float64(pool.ActiveConns) / float64(pool.MaxConns)
		
		var recommendedSize int
		if utilizationRate > 0.8 {
			// High utilization, recommend increasing pool size
			recommendedSize = int(float64(pool.MaxConns) * 1.5)
		} else if utilizationRate < 0.3 {
			// Low utilization, recommend decreasing pool size
			recommendedSize = int(float64(pool.MaxConns) * 0.8)
		} else {
			// Optimal utilization, keep current size
			recommendedSize = pool.MaxConns
		}
		
		// Ensure minimum pool size
		if recommendedSize < 5 {
			recommendedSize = 5
		}
		
		recommendations[name] = recommendedSize
		pool.mu.RUnlock()
	}

	return recommendations
}

// RunMaintenance performs pool maintenance tasks
func (pm *PoolManager) RunMaintenance() {
	if pm.closed {
		return
	}

	pm.logger.Debug("Running pool maintenance")

	// Update health scores for all pools
	pm.mu.RLock()
	for _, pool := range pm.pools {
		pm.checkPoolHealth(pool)
	}
	pm.mu.RUnlock()

	// Clean up old alerts
	pm.monitoring.cleanupOldAlerts()

	// Log pool statistics
	stats := pm.GetAllPoolStats()
	for name, stat := range stats {
		pm.logger.Debug("Pool statistics",
			zap.String("pool", name),
			zap.Int("active", stat.ActiveConnections),
			zap.Int("idle", stat.IdleConnections),
			zap.Int("max", stat.MaxConnections),
			zap.Float64("utilization", stat.UtilizationRate),
			zap.Float64("health_score", stat.HealthScore))
	}
}

// GetHealthStatus returns overall health status of all pools
func (pm *PoolManager) GetHealthStatus() map[string]interface{} {
	stats := pm.GetAllPoolStats()
	alerts := pm.monitoring.getActiveAlerts()
	
	overallHealth := true
	for _, stat := range stats {
		if stat.HealthScore < 0.7 {
			overallHealth = false
			break
		}
	}

	return map[string]interface{}{
		"healthy":     overallHealth,
		"pools":       stats,
		"active_alerts": len(alerts),
		"alerts":      alerts,
		"timestamp":   time.Now(),
	}
}

// Close closes the pool manager
func (pm *PoolManager) Close() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.closed {
		return nil
	}

	pm.closed = true
	pm.logger.Info("Pool manager closed")
	return nil
}

// PoolMonitoring methods

// generateAlert creates a new pool alert
func (pm *PoolMonitoring) generateAlert(poolName, alertType, severity, message string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	alert := PoolAlert{
		ID:          fmt.Sprintf("%s_%s_%d", poolName, alertType, time.Now().Unix()),
		PoolName:    poolName,
		AlertType:   alertType,
		Severity:    severity,
		Message:     message,
		TriggeredAt: time.Now(),
		Resolved:    false,
	}

	pm.alerts = append(pm.alerts, alert)
	
	pm.logger.Warn("Pool alert generated",
		zap.String("pool", poolName),
		zap.String("type", alertType),
		zap.String("severity", severity),
		zap.String("message", message))
}

// getActiveAlerts returns all active (unresolved) alerts
func (pm *PoolMonitoring) getActiveAlerts() []PoolAlert {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var activeAlerts []PoolAlert
	for _, alert := range pm.alerts {
		if !alert.Resolved {
			activeAlerts = append(activeAlerts, alert)
		}
	}

	return activeAlerts
}

// cleanupOldAlerts removes old resolved alerts
func (pm *PoolMonitoring) cleanupOldAlerts() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour) // Keep alerts for 24 hours
	var cleanAlerts []PoolAlert
	
	for _, alert := range pm.alerts {
		if !alert.Resolved || alert.TriggeredAt.After(cutoff) {
			cleanAlerts = append(cleanAlerts, alert)
		}
	}

	if len(cleanAlerts) < len(pm.alerts) {
		pm.logger.Debug("Cleaned up old pool alerts",
			zap.Int("removed", len(pm.alerts)-len(cleanAlerts)),
			zap.Int("remaining", len(cleanAlerts)))
	}

	pm.alerts = cleanAlerts
}