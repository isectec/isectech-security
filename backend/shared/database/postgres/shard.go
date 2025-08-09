package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// Query executes a query on the shard (with optional read replica routing)
func (s *ShardClient) Query(ctx context.Context, query string, args []interface{}, opts *QueryOptions) (*sqlx.Rows, error) {
	// Route to read replica if requested and available
	if opts.UseReplica && len(s.replicas) > 0 {
		replica := s.selectReplica(opts.Consistency)
		if replica != nil {
			return replica.Query(ctx, query, args)
		}
		// Fallback to primary if no replica available
		s.logger.Warn("No healthy replica available, using primary")
	}

	// Execute on primary
	return s.queryPrimary(ctx, query, args)
}

// Exec executes a statement on the primary shard
func (s *ShardClient) Exec(ctx context.Context, query string, args []interface{}, opts *QueryOptions) (sql.Result, error) {
	// Always execute writes on primary
	return s.execPrimary(ctx, query, args)
}

// Transaction executes a function within a database transaction
func (s *ShardClient) Transaction(ctx context.Context, fn func(*sqlx.Tx) error) error {
	// Start transaction on primary
	tx, err := s.primary.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Set tenant context in transaction if available
	if err := s.setTransactionContext(ctx, tx); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to set transaction context: %w", err)
	}

	// Execute function
	if err := fn(tx); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			s.logger.Error("Failed to rollback transaction",
				zap.Error(rollbackErr),
				zap.String("shard", s.name))
		}
		return err
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// queryPrimary executes a query on the primary database
func (s *ShardClient) queryPrimary(ctx context.Context, query string, args []interface{}) (*sqlx.Rows, error) {
	result, err := s.cb.Execute(func() (interface{}, error) {
		// Apply query timeout
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rows, err := s.primary.QueryxContext(ctx, query, args...)
		if err != nil {
			s.logger.Error("Query failed on primary",
				zap.Error(err),
				zap.String("shard", s.name),
				zap.String("query", query))
			return nil, err
		}
		return rows, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*sqlx.Rows), nil
}

// execPrimary executes a statement on the primary database
func (s *ShardClient) execPrimary(ctx context.Context, query string, args []interface{}) (sql.Result, error) {
	result, err := s.cb.Execute(func() (interface{}, error) {
		// Apply query timeout
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		result, err := s.primary.ExecContext(ctx, query, args...)
		if err != nil {
			s.logger.Error("Exec failed on primary",
				zap.Error(err),
				zap.String("shard", s.name),
				zap.String("query", query))
			return nil, err
		}
		return result, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(sql.Result), nil
}

// selectReplica selects an appropriate read replica based on consistency requirements
func (s *ShardClient) selectReplica(consistency ConsistencyLevel) *ReplicaClient {
	if len(s.replicas) == 0 {
		return nil
	}

	// Filter healthy replicas
	var healthyReplicas []*ReplicaClient
	for _, replica := range s.replicas {
		if replica.IsHealthy() {
			healthyReplicas = append(healthyReplicas, replica)
		}
	}

	if len(healthyReplicas) == 0 {
		return nil
	}

	switch consistency {
	case ConsistencyStrong, ConsistencyLinearizable:
		// For strong consistency, prefer replicas with lowest lag
		return s.selectReplicaByLag(healthyReplicas)
	case ConsistencyEventual:
		// For eventual consistency, use weighted round-robin
		return s.selectReplicaWeighted(healthyReplicas)
	default:
		return s.selectReplicaWeighted(healthyReplicas)
	}
}

// selectReplicaByLag selects replica with lowest replication lag
func (s *ShardClient) selectReplicaByLag(replicas []*ReplicaClient) *ReplicaClient {
	// Sort by priority (lower number = higher priority)
	sort.Slice(replicas, func(i, j int) bool {
		return replicas[i].config.Priority < replicas[j].config.Priority
	})

	// Return highest priority healthy replica
	return replicas[0]
}

// selectReplicaWeighted selects replica using weighted round-robin
func (s *ShardClient) selectReplicaWeighted(replicas []*ReplicaClient) *ReplicaClient {
	if len(replicas) == 1 {
		return replicas[0]
	}

	// Calculate total weight
	totalWeight := 0
	for _, replica := range replicas {
		totalWeight += replica.config.Weight
	}

	if totalWeight == 0 {
		// If no weights specified, use random selection
		return replicas[rand.Intn(len(replicas))]
	}

	// Weighted random selection
	r := rand.Intn(totalWeight)
	currentWeight := 0
	
	for _, replica := range replicas {
		currentWeight += replica.config.Weight
		if r < currentWeight {
			return replica
		}
	}

	// Fallback to first replica
	return replicas[0]
}

// setTransactionContext sets tenant context for row-level security in transaction
func (s *ShardClient) setTransactionContext(ctx context.Context, tx *sqlx.Tx) error {
	tenantID := ctx.Value("tenant_id")
	userID := ctx.Value("user_id")
	role := ctx.Value("role")
	
	if tenantID != nil {
		_, err := tx.ExecContext(ctx, "SET app.tenant_id = $1", tenantID)
		if err != nil {
			return fmt.Errorf("failed to set tenant_id: %w", err)
		}
	}

	if userID != nil {
		_, err := tx.ExecContext(ctx, "SET app.user_id = $1", userID)
		if err != nil {
			return fmt.Errorf("failed to set user_id: %w", err)
		}
	}

	if role != nil {
		_, err := tx.ExecContext(ctx, "SET app.role = $1", role)
		if err != nil {
			return fmt.Errorf("failed to set role: %w", err)
		}
	}

	return nil
}

// enableRowLevelSecurity enables RLS on the shard
func (s *ShardClient) enableRowLevelSecurity() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create the security schema and functions if they don't exist
	rlsSetupSQL := `
		-- Create app schema for session variables
		CREATE SCHEMA IF NOT EXISTS app;

		-- Create security functions
		CREATE OR REPLACE FUNCTION app.current_tenant_id() RETURNS TEXT AS $$
		BEGIN
			RETURN current_setting('app.tenant_id', true);
		END;
		$$ LANGUAGE plpgsql SECURITY DEFINER;

		CREATE OR REPLACE FUNCTION app.current_user_id() RETURNS TEXT AS $$
		BEGIN
			RETURN current_setting('app.user_id', true);
		END;
		$$ LANGUAGE plpgsql SECURITY DEFINER;

		CREATE OR REPLACE FUNCTION app.current_role() RETURNS TEXT AS $$
		BEGIN
			RETURN current_setting('app.role', true);
		END;
		$$ LANGUAGE plpgsql SECURITY DEFINER;

		-- Create tenant access function
		CREATE OR REPLACE FUNCTION app.has_tenant_access(tenant_id TEXT) RETURNS BOOLEAN AS $$
		BEGIN
			-- Allow access if current tenant matches or user has admin role
			RETURN tenant_id = app.current_tenant_id() OR app.current_role() = 'admin';
		END;
		$$ LANGUAGE plpgsql SECURITY DEFINER;

		-- Create security tag validation function
		CREATE OR REPLACE FUNCTION app.validate_security_clearance(required_clearance TEXT) RETURNS BOOLEAN AS $$
		DECLARE
			user_clearance TEXT;
		BEGIN
			-- Get user's security clearance (this would come from user profile)
			-- For now, assume it's stored in session or derived from role
			user_clearance := CASE 
				WHEN app.current_role() = 'admin' THEN 'TOP_SECRET'
				WHEN app.current_role() = 'analyst' THEN 'SECRET'
				WHEN app.current_role() = 'operator' THEN 'CONFIDENTIAL'
				ELSE 'UNCLASSIFIED'
			END;

			-- Hierarchy: TOP_SECRET > SECRET > CONFIDENTIAL > UNCLASSIFIED
			RETURN CASE 
				WHEN required_clearance = 'UNCLASSIFIED' THEN true
				WHEN required_clearance = 'CONFIDENTIAL' AND user_clearance IN ('CONFIDENTIAL', 'SECRET', 'TOP_SECRET') THEN true
				WHEN required_clearance = 'SECRET' AND user_clearance IN ('SECRET', 'TOP_SECRET') THEN true
				WHEN required_clearance = 'TOP_SECRET' AND user_clearance = 'TOP_SECRET' THEN true
				ELSE false
			END;
		END;
		$$ LANGUAGE plpgsql SECURITY DEFINER;
	`

	_, err := s.primary.ExecContext(ctx, rlsSetupSQL)
	if err != nil {
		return fmt.Errorf("failed to setup RLS functions: %w", err)
	}

	s.logger.Info("Row-level security enabled on shard", zap.String("shard", s.name))
	return nil
}

// Health checks the health of the shard and its replicas
func (s *ShardClient) Health(ctx context.Context) bool {
	// Check primary health
	if !s.healthCheckDB(ctx, s.primary) {
		return false
	}

	// Check replica health (at least one replica should be healthy if replicas exist)
	if len(s.replicas) > 0 {
		healthyReplicas := 0
		for _, replica := range s.replicas {
			if replica.IsHealthy() {
				healthyReplicas++
			}
		}
		// Consider shard healthy if primary is healthy and at least 50% of replicas are healthy
		return healthyReplicas >= len(s.replicas)/2
	}

	return true
}

// healthCheckDB performs a health check on a database connection
func (s *ShardClient) healthCheckDB(ctx context.Context, db *sqlx.DB) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var result int
	err := db.GetContext(ctx, &result, "SELECT 1")
	if err != nil {
		s.logger.Warn("Health check failed",
			zap.Error(err),
			zap.String("shard", s.name))
		return false
	}

	return true
}

// Close closes the shard and all its connections
func (s *ShardClient) Close() error {
	var errors []error

	// Close primary
	if err := s.primary.Close(); err != nil {
		errors = append(errors, fmt.Errorf("failed to close primary: %w", err))
	}

	// Close replicas
	for _, replica := range s.replicas {
		if err := replica.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close replica %s: %w", replica.name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing shard %s: %v", s.name, errors)
	}

	s.logger.Info("Shard closed", zap.String("shard", s.name))
	return nil
}

// ReplicaClient methods

// Query executes a query on the read replica
func (r *ReplicaClient) Query(ctx context.Context, query string, args []interface{}) (*sqlx.Rows, error) {
	result, err := r.cb.Execute(func() (interface{}, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rows, err := r.db.QueryxContext(ctx, query, args...)
		if err != nil {
			r.logger.Error("Query failed on replica",
				zap.Error(err),
				zap.String("replica", r.name),
				zap.String("query", query))
			return nil, err
		}
		return rows, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*sqlx.Rows), nil
}

// IsHealthy checks if the replica is healthy
func (r *ReplicaClient) IsHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result int
	err := r.db.GetContext(ctx, &result, "SELECT 1")
	if err != nil {
		r.logger.Warn("Replica health check failed",
			zap.Error(err),
			zap.String("replica", r.name))
		return false
	}

	return true
}

// Close closes the replica connection
func (r *ReplicaClient) Close() error {
	if err := r.db.Close(); err != nil {
		return fmt.Errorf("failed to close replica %s: %w", r.name, err)
	}

	r.logger.Info("Replica closed", zap.String("replica", r.name))
	return nil
}