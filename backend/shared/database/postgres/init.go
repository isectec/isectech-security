package postgres

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// DatabaseInitializer handles PostgreSQL database initialization for iSECTECH
type DatabaseInitializer struct {
	config        *Config
	client        *Client
	schemaManager *SchemaManager
	logger        *zap.Logger
}

// InitializationOptions provides options for database initialization
type InitializationOptions struct {
	CreateSchema     bool
	EnableRLS        bool
	CreateIndexes    bool
	SeedData         bool
	ForceRecreate    bool
	MigrationTimeout time.Duration
}

// DefaultInitializationOptions returns production-ready initialization options
func DefaultInitializationOptions() *InitializationOptions {
	return &InitializationOptions{
		CreateSchema:     true,
		EnableRLS:        true,
		CreateIndexes:    true,
		SeedData:         false, // Usually false in production
		ForceRecreate:    false,
		MigrationTimeout: 5 * time.Minute,
	}
}

// NewDatabaseInitializer creates a new database initializer
func NewDatabaseInitializer(logger *zap.Logger) (*DatabaseInitializer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load PostgreSQL config: %w", err)
	}

	return &DatabaseInitializer{
		config: config,
		logger: logger,
	}, nil
}

// Initialize initializes the PostgreSQL database with complete schema
func (di *DatabaseInitializer) Initialize(ctx context.Context, opts *InitializationOptions) error {
	if opts == nil {
		opts = DefaultInitializationOptions()
	}

	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, opts.MigrationTimeout)
	defer cancel()

	di.logger.Info("Starting PostgreSQL database initialization",
		zap.Bool("create_schema", opts.CreateSchema),
		zap.Bool("enable_rls", opts.EnableRLS),
		zap.Bool("create_indexes", opts.CreateIndexes),
		zap.Bool("seed_data", opts.SeedData))

	// Step 1: Initialize client
	if err := di.initializeClient(); err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}
	defer di.cleanup()

	// Step 2: Verify connectivity to all shards
	if err := di.verifyConnectivity(ctx); err != nil {
		return fmt.Errorf("failed to verify connectivity: %w", err)
	}

	// Step 3: Create schema if requested
	if opts.CreateSchema {
		if err := di.createSchema(ctx, opts.ForceRecreate); err != nil {
			return fmt.Errorf("failed to create schema: %w", err)
		}
	}

	// Step 4: Seed initial data if requested
	if opts.SeedData {
		if err := di.seedInitialData(ctx); err != nil {
			return fmt.Errorf("failed to seed initial data: %w", err)
		}
	}

	// Step 5: Validate installation
	if err := di.validateInstallation(ctx); err != nil {
		return fmt.Errorf("installation validation failed: %w", err)
	}

	di.logger.Info("PostgreSQL database initialization completed successfully")
	return nil
}

// initializeClient creates and configures the PostgreSQL client
func (di *DatabaseInitializer) initializeClient() error {
	client, err := NewClient(di.config, di.logger)
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL client: %w", err)
	}

	di.client = client
	di.schemaManager = NewSchemaManager(client, di.logger)
	
	return nil
}

// verifyConnectivity checks connectivity to all configured shards
func (di *DatabaseInitializer) verifyConnectivity(ctx context.Context) error {
	di.logger.Info("Verifying connectivity to all shards")

	health := di.client.Health(ctx)
	unhealthyShards := make([]string, 0)

	for shardName, healthy := range health {
		if !healthy {
			unhealthyShards = append(unhealthyShards, shardName)
		}
	}

	if len(unhealthyShards) > 0 {
		return fmt.Errorf("unhealthy shards detected: %v", unhealthyShards)
	}

	di.logger.Info("All shards are healthy",
		zap.Int("total_shards", len(health)))

	return nil
}

// createSchema creates the complete database schema
func (di *DatabaseInitializer) createSchema(ctx context.Context, forceRecreate bool) error {
	di.logger.Info("Creating database schema",
		zap.Bool("force_recreate", forceRecreate))

	if forceRecreate {
		di.logger.Warn("Force recreating schema - all existing data will be lost")
		if err := di.schemaManager.DropSchema(ctx); err != nil {
			return fmt.Errorf("failed to drop existing schema: %w", err)
		}
	}

	if err := di.schemaManager.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	di.logger.Info("Database schema created successfully")
	return nil
}

// seedInitialData seeds the database with initial data
func (di *DatabaseInitializer) seedInitialData(ctx context.Context) error {
	di.logger.Info("Seeding initial data")

	// Create default tenant for development/testing
	seedSQL := `
		-- Insert default tenant (only if not exists)
		INSERT INTO tenants (id, name, domain, plan, status, settings, security_config)
		SELECT 
			'00000000-0000-0000-0000-000000000001'::UUID,
			'iSECTECH Default',
			'default.isectech.local',
			'enterprise',
			'active',
			'{"theme": "dark", "timezone": "UTC"}'::JSONB,
			'{"require_mfa": true, "session_timeout": 3600, "password_policy": {"min_length": 12, "require_special": true}}'::JSONB
		WHERE NOT EXISTS (
			SELECT 1 FROM tenants WHERE domain = 'default.isectech.local'
		);

		-- Insert default admin user (only if not exists)
		INSERT INTO users (id, tenant_id, email, username, password_hash, first_name, last_name, role, security_clearance, permissions)
		SELECT 
			'00000000-0000-0000-0000-000000000001'::UUID,
			'00000000-0000-0000-0000-000000000001'::UUID,
			'admin@isectech.local',
			'admin',
			'$2a$12$rQj7.gZWZB1HxXZqk3N.eeF1Kf1Qq1YhN7QrX9bGqZjXwXqN.qZGa', -- bcrypt hash of 'admin123!@#'
			'System',
			'Administrator',
			'admin',
			'TOP_SECRET',
			'["*"]'::JSONB
		WHERE NOT EXISTS (
			SELECT 1 FROM users WHERE email = 'admin@isectech.local'
		);

		-- Insert sample compliance framework
		INSERT INTO compliance_frameworks (id, tenant_id, name, version, description, requirements)
		SELECT 
			'00000000-0000-0000-0000-000000000002'::UUID,
			'00000000-0000-0000-0000-000000000001'::UUID,
			'NIST Cybersecurity Framework',
			'1.1',
			'National Institute of Standards and Technology Cybersecurity Framework',
			'[
				{"id": "ID", "category": "Identify", "subcategories": ["ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM", "ID.SC"]},
				{"id": "PR", "category": "Protect", "subcategories": ["PR.AC", "PR.AT", "PR.DS", "PR.IP", "PR.MA", "PR.PT"]},
				{"id": "DE", "category": "Detect", "subcategories": ["DE.AE", "DE.CM", "DE.DP"]},
				{"id": "RS", "category": "Respond", "subcategories": ["RS.RP", "RS.CO", "RS.AN", "RS.MI", "RS.IM"]},
				{"id": "RC", "category": "Recover", "subcategories": ["RC.RP", "RC.IM", "RC.CO"]}
			]'::JSONB
		WHERE NOT EXISTS (
			SELECT 1 FROM compliance_frameworks WHERE name = 'NIST Cybersecurity Framework'
		);
	`

	// Execute seed data on all shards
	for shardName := range di.client.shards {
		shard := di.client.shards[shardName]
		_, err := shard.primary.ExecContext(ctx, seedSQL)
		if err != nil {
			return fmt.Errorf("failed to seed data on shard %s: %w", shardName, err)
		}
	}

	di.logger.Info("Initial data seeded successfully")
	return nil
}

// validateInstallation validates that the database installation is correct
func (di *DatabaseInitializer) validateInstallation(ctx context.Context) error {
	di.logger.Info("Validating database installation")

	// Test queries to validate schema
	validationQueries := []struct {
		name  string
		query string
	}{
		{"tenants_table", "SELECT COUNT(*) FROM tenants LIMIT 1"},
		{"users_table", "SELECT COUNT(*) FROM users LIMIT 1"},
		{"assets_table", "SELECT COUNT(*) FROM assets LIMIT 1"},
		{"threats_table", "SELECT COUNT(*) FROM threats LIMIT 1"},
		{"security_events_table", "SELECT COUNT(*) FROM security_events LIMIT 1"},
		{"alerts_table", "SELECT COUNT(*) FROM alerts LIMIT 1"},
		{"compliance_frameworks_table", "SELECT COUNT(*) FROM compliance_frameworks LIMIT 1"},
		{"compliance_assessments_table", "SELECT COUNT(*) FROM compliance_assessments LIMIT 1"},
		{"audit_logs_table", "SELECT COUNT(*) FROM audit_logs LIMIT 1"},
		{"rls_functions", "SELECT app.current_tenant_id()"},
	}

	// Test each query on all shards
	for shardName, shard := range di.client.shards {
		for _, validation := range validationQueries {
			var result interface{}
			err := shard.primary.GetContext(ctx, &result, validation.query)
			if err != nil {
				return fmt.Errorf("validation failed for %s on shard %s: %w", 
					validation.name, shardName, err)
			}
		}
	}

	// Test tenant context setting
	tenantCtx := &TenantContext{
		TenantID:     "00000000-0000-0000-0000-000000000001",
		UserID:       "00000000-0000-0000-0000-000000000001",
		Role:         "admin",
		Permissions:  []string{"*"},
		SecurityTags: map[string]string{"clearance": "TOP_SECRET"},
	}

	opts := &QueryOptions{
		Tenant:   tenantCtx,
		ShardKey: tenantCtx.TenantID,
	}

	rows, err := di.client.Query(ctx, "SELECT COUNT(*) FROM tenants", nil, opts)
	if err != nil {
		return fmt.Errorf("failed to test tenant context: %w", err)
	}
	defer rows.Close()

	di.logger.Info("Database installation validation completed successfully")
	return nil
}

// cleanup closes database connections
func (di *DatabaseInitializer) cleanup() {
	if di.client != nil {
		if err := di.client.Close(); err != nil {
			di.logger.Error("Failed to close database client during cleanup",
				zap.Error(err))
		}
	}
}

// GetClient returns the initialized database client
func (di *DatabaseInitializer) GetClient() *Client {
	return di.client
}

// GetSchemaManager returns the schema manager
func (di *DatabaseInitializer) GetSchemaManager() *SchemaManager {
	return di.schemaManager
}

// QuickStart performs a complete database setup for development
func QuickStart(ctx context.Context, logger *zap.Logger) (*Client, error) {
	initializer, err := NewDatabaseInitializer(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create initializer: %w", err)
	}

	opts := &InitializationOptions{
		CreateSchema:     true,
		EnableRLS:        true,
		CreateIndexes:    true,
		SeedData:         true, // Enable for development quickstart
		ForceRecreate:    false,
		MigrationTimeout: 5 * time.Minute,
	}

	if err := initializer.Initialize(ctx, opts); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Return the client for immediate use
	client := initializer.GetClient()
	
	// Don't cleanup since we're returning the client
	// The caller is responsible for closing it
	
	return client, nil
}