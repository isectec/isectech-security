package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// RepositoryManager manages all database repositories for the auth service
type RepositoryManager struct {
	db            *sqlx.DB
	connectionMgr *ConnectionManager
	userRepo      *UserRepository
	mfaDeviceRepo *MFADeviceRepository
	auditRepo     *AuditRepository
}

// NewRepositoryManager creates a new repository manager
func NewRepositoryManager(config *DatabaseConfig) (*RepositoryManager, error) {
	// Create connection manager
	connectionMgr, err := NewConnectionManager(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	db := connectionMgr.GetDB()

	// Create individual repositories
	userRepo := NewUserRepository(db)
	mfaDeviceRepo := NewMFADeviceRepository(db)
	auditRepo := NewAuditRepository(db)

	return &RepositoryManager{
		db:            db,
		connectionMgr: connectionMgr,
		userRepo:      userRepo,
		mfaDeviceRepo: mfaDeviceRepo,
		auditRepo:     auditRepo,
	}, nil
}

// GetUserRepository returns the user repository
func (rm *RepositoryManager) GetUserRepository() *UserRepository {
	return rm.userRepo
}

// GetMFADeviceRepository returns the MFA device repository
func (rm *RepositoryManager) GetMFADeviceRepository() *MFADeviceRepository {
	return rm.mfaDeviceRepo
}

// GetAuditRepository returns the audit repository
func (rm *RepositoryManager) GetAuditRepository() *AuditRepository {
	return rm.auditRepo
}

// GetDB returns the database connection
func (rm *RepositoryManager) GetDB() *sqlx.DB {
	return rm.db
}

// GetConnectionManager returns the connection manager
func (rm *RepositoryManager) GetConnectionManager() *ConnectionManager {
	return rm.connectionMgr
}

// HealthCheck performs a health check on all repositories
func (rm *RepositoryManager) HealthCheck(ctx context.Context) error {
	return rm.connectionMgr.HealthCheck(ctx)
}

// Close closes all database connections
func (rm *RepositoryManager) Close() error {
	return rm.connectionMgr.Close()
}

// Transaction executes a function within a database transaction
func (rm *RepositoryManager) Transaction(ctx context.Context, fn func(*sqlx.Tx) error) error {
	return rm.connectionMgr.Transaction(ctx, fn)
}

// TransactionWithRetry executes a transaction with retry logic
func (rm *RepositoryManager) TransactionWithRetry(ctx context.Context, maxRetries int, fn func(*sqlx.Tx) error) error {
	return rm.connectionMgr.TransactionWithRetry(ctx, maxRetries, fn)
}

// RunMigrations runs database migrations
func (rm *RepositoryManager) RunMigrations(ctx context.Context, migrationPath string) error {
	// Read migration files and execute them
	// This is a simplified implementation - in production, use a proper migration library
	return fmt.Errorf("migration functionality not implemented - use external migration tool")
}

// DatabaseStats returns database connection statistics
type DatabaseStats struct {
	OpenConnections   int
	InUse             int
	Idle              int
	WaitCount         int64
	WaitDuration      string
	MaxIdleClosed     int64
	MaxLifetimeClosed int64
}

// GetDatabaseStats returns current database statistics
func (rm *RepositoryManager) GetDatabaseStats() DatabaseStats {
	stats := rm.connectionMgr.GetStats()
	return DatabaseStats{
		OpenConnections:   stats.OpenConnections,
		InUse:             stats.InUse,
		Idle:              stats.Idle,
		WaitCount:         stats.WaitCount,
		WaitDuration:      stats.WaitDuration.String(),
		MaxIdleClosed:     stats.MaxIdleClosed,
		MaxLifetimeClosed: stats.MaxLifetimeClosed,
	}
}

// CleanupExpiredData removes expired data from the database
func (rm *RepositoryManager) CleanupExpiredData(ctx context.Context) (map[string]int, error) {
	results := make(map[string]int)

	// Clean up expired MFA devices
	expiredDevices, err := rm.mfaDeviceRepo.CleanupExpired(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to cleanup expired MFA devices: %w", err)
	}
	results["expired_mfa_devices"] = expiredDevices

	// Use database function to clean up other expired data
	var totalCleaned int
	query := "SELECT cleanup_expired_data()"
	err = rm.db.GetContext(ctx, &totalCleaned, query)
	if err != nil {
		return nil, fmt.Errorf("failed to cleanup expired data: %w", err)
	}
	results["expired_sessions_tokens"] = totalCleaned

	return results, nil
}

// CleanupAuditLogs removes old audit logs based on retention policy
func (rm *RepositoryManager) CleanupAuditLogs(ctx context.Context, retentionDays int) (int, error) {
	return rm.auditRepo.CleanupOldAuditLogs(ctx, retentionDays)
}

// GetSystemHealth returns overall system health information
func (rm *RepositoryManager) GetSystemHealth(ctx context.Context) (map[string]interface{}, error) {
	health := make(map[string]interface{})

	// Database health
	dbErr := rm.HealthCheck(ctx)
	health["database_healthy"] = dbErr == nil
	if dbErr != nil {
		health["database_error"] = dbErr.Error()
	}

	// Database statistics
	stats := rm.GetDatabaseStats()
	health["database_stats"] = stats

	// Check for locked users that need attention
	// This is tenant-agnostic for system health, so we'll skip tenant-specific checks
	// In a real implementation, you might want to aggregate across tenants

	return health, nil
}

// ValidateSchema validates that the database schema is up to date
func (rm *RepositoryManager) ValidateSchema(ctx context.Context) error {
	// Check if required tables exist
	requiredTables := []string{
		"users", "mfa_devices", "roles", "permissions", "role_permissions",
		"user_roles", "sessions", "authentication_attempts", "mfa_audit_events",
		"security_events", "password_reset_tokens", "email_verification_tokens",
	}

	for _, table := range requiredTables {
		var exists bool
		query := `
			SELECT EXISTS (
				SELECT FROM information_schema.tables 
				WHERE table_schema = 'public' AND table_name = $1
			)`

		err := rm.db.GetContext(ctx, &exists, query, table)
		if err != nil {
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}

		if !exists {
			return fmt.Errorf("required table %s does not exist", table)
		}
	}

	// Check if required functions exist
	requiredFunctions := []string{
		"update_updated_at_column",
		"cleanup_expired_data",
	}

	for _, function := range requiredFunctions {
		var exists bool
		query := `
			SELECT EXISTS (
				SELECT FROM information_schema.routines 
				WHERE routine_schema = 'public' AND routine_name = $1
			)`

		err := rm.db.GetContext(ctx, &exists, query, function)
		if err != nil {
			return fmt.Errorf("failed to check function %s: %w", function, err)
		}

		if !exists {
			return fmt.Errorf("required function %s does not exist", function)
		}
	}

	return nil
}

// OptimizeDatabase performs database optimization tasks
func (rm *RepositoryManager) OptimizeDatabase(ctx context.Context) error {
	// Analyze tables for better query planning
	tables := []string{
		"users", "mfa_devices", "sessions", "authentication_attempts",
		"mfa_audit_events", "security_events",
	}

	for _, table := range tables {
		query := fmt.Sprintf("ANALYZE %s", table)
		_, err := rm.db.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to analyze table %s: %w", table, err)
		}
	}

	return nil
}

// GetQueryPerformanceStats returns query performance statistics
func (rm *RepositoryManager) GetQueryPerformanceStats(ctx context.Context) (map[string]interface{}, error) {
	// Check if pg_stat_statements extension is available
	var extensionExists bool
	extensionQuery := `
		SELECT EXISTS (
			SELECT FROM pg_extension WHERE extname = 'pg_stat_statements'
		)`

	err := rm.db.GetContext(ctx, &extensionExists, extensionQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to check pg_stat_statements extension: %w", err)
	}

	if !extensionExists {
		return map[string]interface{}{
			"pg_stat_statements_available": false,
			"message":                      "pg_stat_statements extension not available",
		}, nil
	}

	// Get top slow queries
	slowQueriesQuery := `
		SELECT 
			query,
			calls,
			total_time,
			mean_time,
			rows
		FROM pg_stat_statements
		WHERE query NOT LIKE '%pg_stat_statements%'
		ORDER BY mean_time DESC
		LIMIT 10`

	type SlowQuery struct {
		Query     string  `db:"query"`
		Calls     int64   `db:"calls"`
		TotalTime float64 `db:"total_time"`
		MeanTime  float64 `db:"mean_time"`
		Rows      int64   `db:"rows"`
	}

	var slowQueries []SlowQuery
	err = rm.db.SelectContext(ctx, &slowQueries, slowQueriesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get slow queries: %w", err)
	}

	return map[string]interface{}{
		"pg_stat_statements_available": true,
		"slow_queries":                 slowQueries,
	}, nil
}
