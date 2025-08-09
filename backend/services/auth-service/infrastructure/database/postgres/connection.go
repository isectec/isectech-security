package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// DatabaseConfig holds PostgreSQL database configuration
type DatabaseConfig struct {
	Host         string `yaml:"host" env:"DB_HOST" default:"localhost"`
	Port         int    `yaml:"port" env:"DB_PORT" default:"5432"`
	Database     string `yaml:"database" env:"DB_NAME" default:"isectech_auth"`
	Username     string `yaml:"username" env:"DB_USERNAME" default:"postgres"`
	Password     string `yaml:"password" env:"DB_PASSWORD" default:""`
	SSLMode      string `yaml:"sslmode" env:"DB_SSLMODE" default:"disable"`
	MaxOpenConns int    `yaml:"max_open_conns" env:"DB_MAX_OPEN_CONNS" default:"25"`
	MaxIdleConns int    `yaml:"max_idle_conns" env:"DB_MAX_IDLE_CONNS" default:"5"`
	MaxLifetime  string `yaml:"max_lifetime" env:"DB_MAX_LIFETIME" default:"5m"`
	Timezone     string `yaml:"timezone" env:"DB_TIMEZONE" default:"UTC"`
}

// ConnectionManager manages database connections for the auth service
type ConnectionManager struct {
	db     *sqlx.DB
	config *DatabaseConfig
}

// NewConnectionManager creates a new database connection manager
func NewConnectionManager(config *DatabaseConfig) (*ConnectionManager, error) {
	cm := &ConnectionManager{
		config: config,
	}

	err := cm.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return cm, nil
}

// Connect establishes a connection to PostgreSQL
func (cm *ConnectionManager) Connect() error {
	dsn := cm.buildDSN()

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Configure connection pool
	maxLifetime, err := time.ParseDuration(cm.config.MaxLifetime)
	if err != nil {
		maxLifetime = 5 * time.Minute
	}

	db.SetMaxOpenConns(cm.config.MaxOpenConns)
	db.SetMaxIdleConns(cm.config.MaxIdleConns)
	db.SetConnMaxLifetime(maxLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	cm.db = db
	return nil
}

// buildDSN constructs the PostgreSQL connection string
func (cm *ConnectionManager) buildDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s timezone=%s",
		cm.config.Host,
		cm.config.Port,
		cm.config.Username,
		cm.config.Password,
		cm.config.Database,
		cm.config.SSLMode,
		cm.config.Timezone,
	)
}

// GetDB returns the database connection
func (cm *ConnectionManager) GetDB() *sqlx.DB {
	return cm.db
}

// Close closes the database connection
func (cm *ConnectionManager) Close() error {
	if cm.db != nil {
		return cm.db.Close()
	}
	return nil
}

// HealthCheck performs a database health check
func (cm *ConnectionManager) HealthCheck(ctx context.Context) error {
	if cm.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Test with a simple query
	var result int
	err := cm.db.GetContext(ctx, &result, "SELECT 1")
	if err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	// Check connection stats
	stats := cm.db.Stats()
	if stats.OpenConnections == 0 && stats.MaxOpenConnections > 0 {
		return fmt.Errorf("no active database connections")
	}

	return nil
}

// GetStats returns database connection statistics
func (cm *ConnectionManager) GetStats() sql.DBStats {
	if cm.db == nil {
		return sql.DBStats{}
	}
	return cm.db.Stats()
}

// Transaction executes a function within a database transaction
func (cm *ConnectionManager) Transaction(ctx context.Context, fn func(*sqlx.Tx) error) error {
	tx, err := cm.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("transaction error: %v, rollback error: %v", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// TransactionWithRetry executes a transaction with retry logic
func (cm *ConnectionManager) TransactionWithRetry(ctx context.Context, maxRetries int, fn func(*sqlx.Tx) error) error {
	var err error
	for i := 0; i <= maxRetries; i++ {
		err = cm.Transaction(ctx, fn)
		if err == nil {
			return nil
		}

		// Check if error is retryable (e.g., serialization failure)
		if !isRetryableError(err) {
			return err
		}

		if i < maxRetries {
			// Exponential backoff
			backoff := time.Duration(1<<uint(i)) * 100 * time.Millisecond
			time.Sleep(backoff)
		}
	}

	return fmt.Errorf("transaction failed after %d retries: %w", maxRetries, err)
}

// isRetryableError checks if an error is retryable
func isRetryableError(err error) bool {
	// Check for PostgreSQL serialization failure
	if pqErr, ok := err.(*pq.Error); ok {
		// PostgreSQL error codes for retryable errors
		retryableCodes := []string{
			"40001", // serialization_failure
			"40P01", // deadlock_detected
			"53300", // too_many_connections
		}

		for _, code := range retryableCodes {
			if string(pqErr.Code) == code {
				return true
			}
		}
	}

	return false
}

// SQLError represents a PostgreSQL error with additional context
type SQLError struct {
	Query     string
	Args      []interface{}
	Err       error
	Operation string
}

func (e *SQLError) Error() string {
	return fmt.Sprintf("SQL error in %s: %v", e.Operation, e.Err)
}

func (e *SQLError) Unwrap() error {
	return e.Err
}

// WrapSQLError wraps a database error with additional context
func WrapSQLError(err error, operation, query string, args ...interface{}) error {
	if err == nil {
		return nil
	}

	return &SQLError{
		Query:     query,
		Args:      args,
		Err:       err,
		Operation: operation,
	}
}

// IsNoRowsError checks if the error is a "no rows" error
func IsNoRowsError(err error) bool {
	return err == sql.ErrNoRows
}

// IsUniqueConstraintError checks if the error is a unique constraint violation
func IsUniqueConstraintError(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return string(pqErr.Code) == "23505" // unique_violation
	}
	return false
}

// IsForeignKeyConstraintError checks if the error is a foreign key constraint violation
func IsForeignKeyConstraintError(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return string(pqErr.Code) == "23503" // foreign_key_violation
	}
	return false
}

// IsCheckConstraintError checks if the error is a check constraint violation
func IsCheckConstraintError(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return string(pqErr.Code) == "23514" // check_violation
	}
	return false
}

// QueryBuilder helps build dynamic SQL queries safely
type QueryBuilder struct {
	query    string
	args     []interface{}
	argIndex int
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		args:     make([]interface{}, 0),
		argIndex: 1,
	}
}

// Append adds SQL and arguments to the query
func (qb *QueryBuilder) Append(sql string, args ...interface{}) *QueryBuilder {
	qb.query += sql
	qb.args = append(qb.args, args...)
	return qb
}

// Where adds a WHERE clause with proper argument indexing
func (qb *QueryBuilder) Where(condition string, args ...interface{}) *QueryBuilder {
	if len(args) > 0 {
		qb.query += " WHERE " + condition
		qb.args = append(qb.args, args...)
	}
	return qb
}

// And adds an AND clause
func (qb *QueryBuilder) And(condition string, args ...interface{}) *QueryBuilder {
	if len(args) > 0 {
		qb.query += " AND " + condition
		qb.args = append(qb.args, args...)
	}
	return qb
}

// Or adds an OR clause
func (qb *QueryBuilder) Or(condition string, args ...interface{}) *QueryBuilder {
	if len(args) > 0 {
		qb.query += " OR " + condition
		qb.args = append(qb.args, args...)
	}
	return qb
}

// OrderBy adds an ORDER BY clause
func (qb *QueryBuilder) OrderBy(column string, direction string) *QueryBuilder {
	qb.query += fmt.Sprintf(" ORDER BY %s %s", column, direction)
	return qb
}

// Limit adds a LIMIT clause
func (qb *QueryBuilder) Limit(limit int) *QueryBuilder {
	qb.query += fmt.Sprintf(" LIMIT %d", limit)
	return qb
}

// Offset adds an OFFSET clause
func (qb *QueryBuilder) Offset(offset int) *QueryBuilder {
	qb.query += fmt.Sprintf(" OFFSET %d", offset)
	return qb
}

// Build returns the final query and arguments
func (qb *QueryBuilder) Build() (string, []interface{}) {
	return qb.query, qb.args
}

// String returns the query string for debugging
func (qb *QueryBuilder) String() string {
	return qb.query
}
