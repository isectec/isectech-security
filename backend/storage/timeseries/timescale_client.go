package timeseries

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// TimescaleClient provides a production-grade TimescaleDB client for iSECTECH
type TimescaleClient struct {
	db                *sql.DB
	logger            *zap.Logger
	config            *TimescaleConfig
	connectionPool    *ConnectionPool
	writeBuffer       *WriteBuffer
	compressionPolicy *CompressionPolicy
	retentionPolicy   *RetentionPolicy
	
	// Connection management
	mu            sync.RWMutex
	isHealthy     bool
	lastHealthCheck time.Time
	
	// Background maintenance
	ctx           context.Context
	cancel        context.CancelFunc
	maintenanceTicker *time.Ticker
	
	// Statistics
	stats         *ClientStats
}

// TimescaleConfig defines TimescaleDB configuration for iSECTECH
type TimescaleConfig struct {
	// Connection settings
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	Database          string        `json:"database"`
	Username          string        `json:"username"`
	Password          string        `json:"password"`
	SSLMode           string        `json:"ssl_mode"`
	
	// Connection pool settings
	MaxOpenConns      int           `json:"max_open_conns"`
	MaxIdleConns      int           `json:"max_idle_conns"`
	ConnMaxLifetime   time.Duration `json:"conn_max_lifetime"`
	ConnMaxIdleTime   time.Duration `json:"conn_max_idle_time"`
	
	// Performance settings
	WriteBufferSize   int           `json:"write_buffer_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	BatchSize         int           `json:"batch_size"`
	WriteTimeout      time.Duration `json:"write_timeout"`
	ReadTimeout       time.Duration `json:"read_timeout"`
	
	// Time-series settings
	ChunkTimeInterval time.Duration `json:"chunk_time_interval"`
	CompressionAfter  time.Duration `json:"compression_after"`
	RetentionPeriod   time.Duration `json:"retention_period"`
	
	// Security settings
	EnableRowSecurity bool          `json:"enable_row_security"`
	TenantColumn      string        `json:"tenant_column"`
	
	// Maintenance settings
	MaintenanceInterval time.Duration `json:"maintenance_interval"`
	VacuumEnabled      bool          `json:"vacuum_enabled"`
	ReindexEnabled     bool          `json:"reindex_enabled"`
}

// ConnectionPool manages database connections
type ConnectionPool struct {
	primary   *sql.DB
	replicas  []*sql.DB
	balancer  *LoadBalancer
}

// WriteBuffer handles batched writes for better performance
type WriteBuffer struct {
	buffer        []MetricPoint
	mu            sync.Mutex
	maxSize       int
	flushInterval time.Duration
	lastFlush     time.Time
}

// CompressionPolicy defines compression settings
type CompressionPolicy struct {
	Enabled         bool
	CompressionAfter time.Duration
	Algorithms      []CompressionAlgorithm
}

// RetentionPolicy defines data retention settings
type RetentionPolicy struct {
	Enabled         bool
	RetentionPeriod time.Duration
	ArchivePath     string
	CompressionRatio float64
}

// LoadBalancer handles read query distribution
type LoadBalancer struct {
	strategy LoadBalancingStrategy
	mu       sync.RWMutex
	current  int
}

// ClientStats tracks client performance metrics
type ClientStats struct {
	WriteCount       int64
	ReadCount        int64
	ErrorCount       int64
	ConnectionErrors int64
	AverageWriteTime time.Duration
	AverageReadTime  time.Duration
	mu               sync.RWMutex
}

// LoadBalancingStrategy defines read load balancing strategies
type LoadBalancingStrategy string

const (
	LoadBalancingRoundRobin LoadBalancingStrategy = "round_robin"
	LoadBalancingRandom     LoadBalancingStrategy = "random"
	LoadBalancingWeighted   LoadBalancingStrategy = "weighted"
)

// CompressionAlgorithm defines compression algorithms
type CompressionAlgorithm string

const (
	CompressionLZ4    CompressionAlgorithm = "lz4"
	CompressionZSTD   CompressionAlgorithm = "zstd"
	CompressionGZIP   CompressionAlgorithm = "gzip"
)

// MetricPoint represents a time-series data point
type MetricPoint struct {
	Timestamp     time.Time              `json:"timestamp"`
	MetricName    string                 `json:"metric_name"`
	Value         float64                `json:"value"`
	Tags          map[string]string      `json:"tags"`
	TenantID      string                 `json:"tenant_id"`
	ComponentID   string                 `json:"component_id"`
	EventType     string                 `json:"event_type"`
}

// SecurityMetric represents security-specific metric data
type SecurityMetric struct {
	MetricPoint
	ThreatLevel   string                 `json:"threat_level"`
	AttackVector  string                 `json:"attack_vector,omitempty"`
	SourceIP      string                 `json:"source_ip,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	AssetID       string                 `json:"asset_id,omitempty"`
	RiskScore     float64                `json:"risk_score,omitempty"`
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
}

// NewTimescaleClient creates a new TimescaleDB client
func NewTimescaleClient(logger *zap.Logger, config *TimescaleConfig) (*TimescaleClient, error) {
	if config == nil {
		return nil, fmt.Errorf("TimescaleDB configuration is required")
	}
	
	// Set production defaults
	if err := setConfigDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	client := &TimescaleClient{
		logger:  logger.With(zap.String("component", "timescale-client")),
		config:  config,
		ctx:     ctx,
		cancel:  cancel,
		stats:   &ClientStats{},
		isHealthy: false,
	}
	
	// Initialize database connection
	if err := client.initializeConnection(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize connection: %w", err)
	}
	
	// Initialize write buffer
	client.writeBuffer = &WriteBuffer{
		buffer:        make([]MetricPoint, 0, config.WriteBufferSize),
		maxSize:       config.WriteBufferSize,
		flushInterval: config.FlushInterval,
		lastFlush:     time.Now(),
	}
	
	// Initialize policies
	client.compressionPolicy = &CompressionPolicy{
		Enabled:          config.CompressionAfter > 0,
		CompressionAfter: config.CompressionAfter,
		Algorithms:       []CompressionAlgorithm{CompressionZSTD, CompressionLZ4},
	}
	
	client.retentionPolicy = &RetentionPolicy{
		Enabled:         config.RetentionPeriod > 0,
		RetentionPeriod: config.RetentionPeriod,
		ArchivePath:     "/data/timescale/archive",
		CompressionRatio: 0.3,
	}
	
	// Create hypertables and set up compression/retention policies
	if err := client.setupDatabase(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to setup database: %w", err)
	}
	
	// Start background maintenance
	client.maintenanceTicker = time.NewTicker(config.MaintenanceInterval)
	go client.runMaintenance()
	
	// Start write buffer flushing
	go client.runWriteBufferFlusher()
	
	logger.Info("TimescaleDB client initialized",
		zap.String("host", config.Host),
		zap.Int("port", config.Port),
		zap.String("database", config.Database),
		zap.Duration("chunk_interval", config.ChunkTimeInterval),
		zap.Bool("compression_enabled", client.compressionPolicy.Enabled),
		zap.Bool("retention_enabled", client.retentionPolicy.Enabled),
	)
	
	return client, nil
}

// setConfigDefaults sets production defaults for TimescaleDB configuration
func setConfigDefaults(config *TimescaleConfig) error {
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.Port == 0 {
		config.Port = 5432
	}
	if config.Database == "" {
		config.Database = "isectech_metrics"
	}
	if config.SSLMode == "" {
		config.SSLMode = "require"
	}
	
	// Connection pool defaults
	if config.MaxOpenConns == 0 {
		config.MaxOpenConns = 50
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 10
	}
	if config.ConnMaxLifetime == 0 {
		config.ConnMaxLifetime = 1 * time.Hour
	}
	if config.ConnMaxIdleTime == 0 {
		config.ConnMaxIdleTime = 5 * time.Minute
	}
	
	// Performance defaults
	if config.WriteBufferSize == 0 {
		config.WriteBufferSize = 10000
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	
	// Time-series defaults
	if config.ChunkTimeInterval == 0 {
		config.ChunkTimeInterval = 1 * time.Hour
	}
	if config.CompressionAfter == 0 {
		config.CompressionAfter = 24 * time.Hour
	}
	if config.RetentionPeriod == 0 {
		config.RetentionPeriod = 365 * 24 * time.Hour // 1 year
	}
	
	// Security defaults
	if config.TenantColumn == "" {
		config.TenantColumn = "tenant_id"
	}
	
	// Maintenance defaults
	if config.MaintenanceInterval == 0 {
		config.MaintenanceInterval = 1 * time.Hour
	}
	
	return nil
}

// initializeConnection initializes the database connection
func (tc *TimescaleClient) initializeConnection() error {
	// Build connection string with security parameters
	connStr := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s "+
		"connect_timeout=10 statement_timeout=%d idle_in_transaction_session_timeout=30000",
		tc.config.Host,
		tc.config.Port,
		tc.config.Database,
		tc.config.Username,
		tc.config.Password,
		tc.config.SSLMode,
		int(tc.config.WriteTimeout.Milliseconds()),
	)
	
	// Open primary connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}
	
	// Configure connection pool
	db.SetMaxOpenConns(tc.config.MaxOpenConns)
	db.SetMaxIdleConns(tc.config.MaxIdleConns)
	db.SetConnMaxLifetime(tc.config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(tc.config.ConnMaxIdleTime)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}
	
	tc.db = db
	tc.isHealthy = true
	tc.lastHealthCheck = time.Now()
	
	return nil
}

// setupDatabase creates hypertables and sets up policies
func (tc *TimescaleClient) setupDatabase() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Create schema if not exists
	if _, err := tc.db.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS metrics"); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	
	// Create security metrics hypertable
	createSecurityMetricsTable := `
		CREATE TABLE IF NOT EXISTS metrics.security_metrics (
			timestamp TIMESTAMPTZ NOT NULL,
			metric_name TEXT NOT NULL,
			value DOUBLE PRECISION NOT NULL,
			tenant_id TEXT NOT NULL,
			component_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			threat_level TEXT,
			attack_vector TEXT,
			source_ip INET,
			user_id TEXT,
			asset_id TEXT,
			risk_score DOUBLE PRECISION,
			tags JSONB,
			attributes JSONB
		);
	`
	
	if _, err := tc.db.ExecContext(ctx, createSecurityMetricsTable); err != nil {
		return fmt.Errorf("failed to create security_metrics table: %w", err)
	}
	
	// Create hypertable
	createHypertable := `
		SELECT create_hypertable('metrics.security_metrics', 'timestamp',
			chunk_time_interval => INTERVAL '%s',
			if_not_exists => TRUE
		);
	`
	
	if _, err := tc.db.ExecContext(ctx, fmt.Sprintf(createHypertable, tc.config.ChunkTimeInterval.String())); err != nil {
		return fmt.Errorf("failed to create hypertable: %w", err)
	}
	
	// Create performance metrics hypertable
	createPerformanceMetricsTable := `
		CREATE TABLE IF NOT EXISTS metrics.performance_metrics (
			timestamp TIMESTAMPTZ NOT NULL,
			metric_name TEXT NOT NULL,
			value DOUBLE PRECISION NOT NULL,
			tenant_id TEXT NOT NULL,
			component_id TEXT NOT NULL,
			tags JSONB
		);
	`
	
	if _, err := tc.db.ExecContext(ctx, createPerformanceMetricsTable); err != nil {
		return fmt.Errorf("failed to create performance_metrics table: %w", err)
	}
	
	if _, err := tc.db.ExecContext(ctx, fmt.Sprintf(`
		SELECT create_hypertable('metrics.performance_metrics', 'timestamp',
			chunk_time_interval => INTERVAL '%s',
			if_not_exists => TRUE
		);
	`, tc.config.ChunkTimeInterval.String())); err != nil {
		return fmt.Errorf("failed to create performance hypertable: %w", err)
	}
	
	// Set up compression policy
	if tc.compressionPolicy.Enabled {
		if err := tc.setupCompressionPolicies(ctx); err != nil {
			return fmt.Errorf("failed to setup compression policies: %w", err)
		}
	}
	
	// Set up retention policy
	if tc.retentionPolicy.Enabled {
		if err := tc.setupRetentionPolicies(ctx); err != nil {
			return fmt.Errorf("failed to setup retention policies: %w", err)
		}
	}
	
	// Create indices for common queries
	if err := tc.createIndices(ctx); err != nil {
		return fmt.Errorf("failed to create indices: %w", err)
	}
	
	// Set up row-level security if enabled
	if tc.config.EnableRowSecurity {
		if err := tc.setupRowLevelSecurity(ctx); err != nil {
			return fmt.Errorf("failed to setup row-level security: %w", err)
		}
	}
	
	return nil
}

// setupCompressionPolicies sets up compression policies
func (tc *TimescaleClient) setupCompressionPolicies(ctx context.Context) error {
	// Enable compression on security_metrics
	compressionQuery := `
		ALTER TABLE metrics.security_metrics SET (
			timescaledb.compress,
			timescaledb.compress_segmentby = 'tenant_id, component_id, event_type',
			timescaledb.compress_orderby = 'timestamp DESC'
		);
	`
	
	if _, err := tc.db.ExecContext(ctx, compressionQuery); err != nil {
		tc.logger.Warn("Failed to set compression on security_metrics", zap.Error(err))
	}
	
	// Add compression policy
	addCompressionPolicy := `
		SELECT add_compression_policy('metrics.security_metrics', INTERVAL '%s');
	`
	
	if _, err := tc.db.ExecContext(ctx, fmt.Sprintf(addCompressionPolicy, tc.compressionPolicy.CompressionAfter.String())); err != nil {
		tc.logger.Warn("Failed to add compression policy", zap.Error(err))
	}
	
	// Enable compression on performance_metrics
	compressionQuery = `
		ALTER TABLE metrics.performance_metrics SET (
			timescaledb.compress,
			timescaledb.compress_segmentby = 'tenant_id, component_id',
			timescaledb.compress_orderby = 'timestamp DESC'
		);
	`
	
	if _, err := tc.db.ExecContext(ctx, compressionQuery); err != nil {
		tc.logger.Warn("Failed to set compression on performance_metrics", zap.Error(err))
	}
	
	if _, err := tc.db.ExecContext(ctx, fmt.Sprintf(`
		SELECT add_compression_policy('metrics.performance_metrics', INTERVAL '%s');
	`, tc.compressionPolicy.CompressionAfter.String())); err != nil {
		tc.logger.Warn("Failed to add compression policy for performance_metrics", zap.Error(err))
	}
	
	return nil
}

// setupRetentionPolicies sets up data retention policies
func (tc *TimescaleClient) setupRetentionPolicies(ctx context.Context) error {
	// Add retention policy for security_metrics
	addRetentionPolicy := `
		SELECT add_retention_policy('metrics.security_metrics', INTERVAL '%s');
	`
	
	if _, err := tc.db.ExecContext(ctx, fmt.Sprintf(addRetentionPolicy, tc.retentionPolicy.RetentionPeriod.String())); err != nil {
		tc.logger.Warn("Failed to add retention policy for security_metrics", zap.Error(err))
	}
	
	// Add retention policy for performance_metrics
	if _, err := tc.db.ExecContext(ctx, fmt.Sprintf(`
		SELECT add_retention_policy('metrics.performance_metrics', INTERVAL '%s');
	`, tc.retentionPolicy.RetentionPeriod.String())); err != nil {
		tc.logger.Warn("Failed to add retention policy for performance_metrics", zap.Error(err))
	}
	
	return nil
}

// createIndices creates optimized indices for common query patterns
func (tc *TimescaleClient) createIndices(ctx context.Context) error {
	indices := []string{
		// Security metrics indices
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_tenant_time ON metrics.security_metrics (tenant_id, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_component ON metrics.security_metrics (component_id, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_event_type ON metrics.security_metrics (event_type, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_threat_level ON metrics.security_metrics (threat_level, timestamp DESC) WHERE threat_level IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_source_ip ON metrics.security_metrics (source_ip, timestamp DESC) WHERE source_ip IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_user_id ON metrics.security_metrics (user_id, timestamp DESC) WHERE user_id IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_risk_score ON metrics.security_metrics (risk_score DESC, timestamp DESC) WHERE risk_score IS NOT NULL",
		
		// Performance metrics indices
		"CREATE INDEX IF NOT EXISTS idx_performance_metrics_tenant_time ON metrics.performance_metrics (tenant_id, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_performance_metrics_component ON metrics.performance_metrics (component_id, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_performance_metrics_name ON metrics.performance_metrics (metric_name, timestamp DESC)",
		
		// GIN indices for JSONB columns
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_tags ON metrics.security_metrics USING GIN (tags)",
		"CREATE INDEX IF NOT EXISTS idx_security_metrics_attributes ON metrics.security_metrics USING GIN (attributes)",
		"CREATE INDEX IF NOT EXISTS idx_performance_metrics_tags ON metrics.performance_metrics USING GIN (tags)",
	}
	
	for _, indexSQL := range indices {
		if _, err := tc.db.ExecContext(ctx, indexSQL); err != nil {
			tc.logger.Warn("Failed to create index", zap.String("sql", indexSQL), zap.Error(err))
		}
	}
	
	return nil
}

// setupRowLevelSecurity sets up row-level security for multi-tenancy
func (tc *TimescaleClient) setupRowLevelSecurity(ctx context.Context) error {
	// Enable RLS on security_metrics
	if _, err := tc.db.ExecContext(ctx, "ALTER TABLE metrics.security_metrics ENABLE ROW LEVEL SECURITY"); err != nil {
		return fmt.Errorf("failed to enable RLS on security_metrics: %w", err)
	}
	
	// Create RLS policy
	rlsPolicy := `
		CREATE POLICY tenant_isolation_security ON metrics.security_metrics
		USING (tenant_id = current_setting('app.current_tenant'))
	`
	
	if _, err := tc.db.ExecContext(ctx, rlsPolicy); err != nil {
		tc.logger.Warn("Failed to create RLS policy for security_metrics", zap.Error(err))
	}
	
	// Enable RLS on performance_metrics
	if _, err := tc.db.ExecContext(ctx, "ALTER TABLE metrics.performance_metrics ENABLE ROW LEVEL SECURITY"); err != nil {
		return fmt.Errorf("failed to enable RLS on performance_metrics: %w", err)
	}
	
	rlsPolicy = `
		CREATE POLICY tenant_isolation_performance ON metrics.performance_metrics
		USING (tenant_id = current_setting('app.current_tenant'))
	`
	
	if _, err := tc.db.ExecContext(ctx, rlsPolicy); err != nil {
		tc.logger.Warn("Failed to create RLS policy for performance_metrics", zap.Error(err))
	}
	
	return nil
}

// WriteSecurityMetric writes a security metric to TimescaleDB
func (tc *TimescaleClient) WriteSecurityMetric(ctx context.Context, metric *SecurityMetric) error {
	tc.writeBuffer.mu.Lock()
	defer tc.writeBuffer.mu.Unlock()
	
	// Add to buffer
	tc.writeBuffer.buffer = append(tc.writeBuffer.buffer, metric.MetricPoint)
	
	// Check if we need to flush
	if len(tc.writeBuffer.buffer) >= tc.writeBuffer.maxSize ||
		time.Since(tc.writeBuffer.lastFlush) >= tc.writeBuffer.flushInterval {
		return tc.flushWriteBuffer()
	}
	
	return nil
}

// WritePerformanceMetric writes a performance metric to TimescaleDB
func (tc *TimescaleClient) WritePerformanceMetric(ctx context.Context, metric *MetricPoint) error {
	return tc.WriteSecurityMetric(ctx, &SecurityMetric{MetricPoint: *metric})
}

// flushWriteBuffer flushes the write buffer to the database
func (tc *TimescaleClient) flushWriteBuffer() error {
	if len(tc.writeBuffer.buffer) == 0 {
		return nil
	}
	
	start := time.Now()
	
	// Batch insert
	query := `
		INSERT INTO metrics.security_metrics (
			timestamp, metric_name, value, tenant_id, component_id, event_type,
			threat_level, attack_vector, source_ip, user_id, asset_id, risk_score,
			tags, attributes
		) VALUES %s
	`
	
	// Build values for batch insert
	valueStrings := make([]string, 0, len(tc.writeBuffer.buffer))
	valueArgs := make([]interface{}, 0, len(tc.writeBuffer.buffer)*14)
	
	for i, metric := range tc.writeBuffer.buffer {
		valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			i*14+1, i*14+2, i*14+3, i*14+4, i*14+5, i*14+6, i*14+7, i*14+8, i*14+9, i*14+10, i*14+11, i*14+12, i*14+13, i*14+14))
		
		valueArgs = append(valueArgs,
			metric.Timestamp,
			metric.MetricName,
			metric.Value,
			metric.TenantID,
			metric.ComponentID,
			metric.EventType,
			nil, // threat_level
			nil, // attack_vector
			nil, // source_ip
			nil, // user_id
			nil, // asset_id
			nil, // risk_score
			nil, // tags
			nil, // attributes
		)
	}
	
	finalQuery := fmt.Sprintf(query, strings.Join(valueStrings, ","))
	
	ctx, cancel := context.WithTimeout(context.Background(), tc.config.WriteTimeout)
	defer cancel()
	
	if _, err := tc.db.ExecContext(ctx, finalQuery, valueArgs...); err != nil {
		tc.stats.mu.Lock()
		tc.stats.ErrorCount++
		tc.stats.mu.Unlock()
		return fmt.Errorf("failed to flush write buffer: %w", err)
	}
	
	// Update statistics
	duration := time.Since(start)
	tc.stats.mu.Lock()
	tc.stats.WriteCount += int64(len(tc.writeBuffer.buffer))
	tc.stats.AverageWriteTime = (tc.stats.AverageWriteTime + duration) / 2
	tc.stats.mu.Unlock()
	
	// Clear buffer
	tc.writeBuffer.buffer = tc.writeBuffer.buffer[:0]
	tc.writeBuffer.lastFlush = time.Now()
	
	tc.logger.Debug("Flushed write buffer",
		zap.Int("metrics_count", len(valueStrings)),
		zap.Duration("duration", duration),
	)
	
	return nil
}

// runWriteBufferFlusher runs periodic write buffer flushing
func (tc *TimescaleClient) runWriteBufferFlusher() {
	ticker := time.NewTicker(tc.config.FlushInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-tc.ctx.Done():
			// Final flush on shutdown
			tc.writeBuffer.mu.Lock()
			tc.flushWriteBuffer()
			tc.writeBuffer.mu.Unlock()
			return
		case <-ticker.C:
			tc.writeBuffer.mu.Lock()
			if time.Since(tc.writeBuffer.lastFlush) >= tc.writeBuffer.flushInterval {
				tc.flushWriteBuffer()
			}
			tc.writeBuffer.mu.Unlock()
		}
	}
}

// runMaintenance runs periodic database maintenance
func (tc *TimescaleClient) runMaintenance() {
	for {
		select {
		case <-tc.ctx.Done():
			return
		case <-tc.maintenanceTicker.C:
			tc.performMaintenance()
		}
	}
}

// performMaintenance performs database maintenance tasks
func (tc *TimescaleClient) performMaintenance() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	
	// Health check
	if err := tc.db.PingContext(ctx); err != nil {
		tc.mu.Lock()
		tc.isHealthy = false
		tc.stats.ConnectionErrors++
		tc.mu.Unlock()
		tc.logger.Error("Database health check failed", zap.Error(err))
		return
	}
	
	tc.mu.Lock()
	tc.isHealthy = true
	tc.lastHealthCheck = time.Now()
	tc.mu.Unlock()
	
	// Update statistics
	if err := tc.updateStatistics(ctx); err != nil {
		tc.logger.Warn("Failed to update statistics", zap.Error(err))
	}
	
	// Vacuum if enabled
	if tc.config.VacuumEnabled {
		if err := tc.vacuum(ctx); err != nil {
			tc.logger.Warn("Failed to vacuum", zap.Error(err))
		}
	}
	
	// Reindex if enabled
	if tc.config.ReindexEnabled {
		if err := tc.reindex(ctx); err != nil {
			tc.logger.Warn("Failed to reindex", zap.Error(err))
		}
	}
	
	tc.logger.Debug("Database maintenance completed")
}

// updateStatistics updates table statistics
func (tc *TimescaleClient) updateStatistics(ctx context.Context) error {
	tables := []string{"metrics.security_metrics", "metrics.performance_metrics"}
	
	for _, table := range tables {
		if _, err := tc.db.ExecContext(ctx, fmt.Sprintf("ANALYZE %s", table)); err != nil {
			return fmt.Errorf("failed to analyze table %s: %w", table, err)
		}
	}
	
	return nil
}

// vacuum runs vacuum on tables
func (tc *TimescaleClient) vacuum(ctx context.Context) error {
	tables := []string{"metrics.security_metrics", "metrics.performance_metrics"}
	
	for _, table := range tables {
		if _, err := tc.db.ExecContext(ctx, fmt.Sprintf("VACUUM %s", table)); err != nil {
			return fmt.Errorf("failed to vacuum table %s: %w", table, err)
		}
	}
	
	return nil
}

// reindex rebuilds indices
func (tc *TimescaleClient) reindex(ctx context.Context) error {
	if _, err := tc.db.ExecContext(ctx, "REINDEX SCHEMA metrics"); err != nil {
		return fmt.Errorf("failed to reindex schema: %w", err)
	}
	
	return nil
}

// IsHealthy returns the health status of the client
func (tc *TimescaleClient) IsHealthy() bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.isHealthy
}

// GetStats returns client statistics
func (tc *TimescaleClient) GetStats() *ClientStats {
	tc.stats.mu.RLock()
	defer tc.stats.mu.RUnlock()
	
	stats := *tc.stats
	return &stats
}

// Close closes the TimescaleDB client
func (tc *TimescaleClient) Close() error {
	if tc.cancel != nil {
		tc.cancel()
	}
	
	if tc.maintenanceTicker != nil {
		tc.maintenanceTicker.Stop()
	}
	
	// Final flush
	tc.writeBuffer.mu.Lock()
	tc.flushWriteBuffer()
	tc.writeBuffer.mu.Unlock()
	
	if tc.db != nil {
		tc.db.Close()
	}
	
	tc.logger.Info("TimescaleDB client closed")
	return nil
}