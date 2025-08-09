package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// DatabaseInitializer handles MongoDB database initialization for iSECTECH
type DatabaseInitializer struct {
	config *Config
	client *Client
	logger *zap.Logger
}

// InitializationOptions provides options for MongoDB initialization
type InitializationOptions struct {
	CreateCollections    bool
	CreateIndexes        bool
	EnableSharding       bool
	CreateTimeSeriesCollections bool
	SeedData             bool
	ForceRecreate        bool
	InitializationTimeout time.Duration
}

// DefaultInitializationOptions returns production-ready initialization options
func DefaultInitializationOptions() *InitializationOptions {
	return &InitializationOptions{
		CreateCollections:           true,
		CreateIndexes:               true,
		EnableSharding:              false, // Usually enabled in production clusters
		CreateTimeSeriesCollections: true,
		SeedData:                    false, // Usually false in production
		ForceRecreate:               false,
		InitializationTimeout:       10 * time.Minute,
	}
}

// NewDatabaseInitializer creates a new MongoDB database initializer
func NewDatabaseInitializer(logger *zap.Logger) (*DatabaseInitializer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load MongoDB config: %w", err)
	}

	return &DatabaseInitializer{
		config: config,
		logger: logger,
	}, nil
}

// Initialize initializes the MongoDB database with complete setup
func (di *DatabaseInitializer) Initialize(ctx context.Context, opts *InitializationOptions) error {
	if opts == nil {
		opts = DefaultInitializationOptions()
	}

	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, opts.InitializationTimeout)
	defer cancel()

	di.logger.Info("Starting MongoDB database initialization",
		zap.Bool("create_collections", opts.CreateCollections),
		zap.Bool("create_indexes", opts.CreateIndexes),
		zap.Bool("enable_sharding", opts.EnableSharding),
		zap.Bool("create_timeseries", opts.CreateTimeSeriesCollections),
		zap.Bool("seed_data", opts.SeedData))

	// Step 1: Initialize client
	if err := di.initializeClient(); err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}
	defer di.cleanup()

	// Step 2: Verify connectivity
	if err := di.verifyConnectivity(ctx); err != nil {
		return fmt.Errorf("failed to verify connectivity: %w", err)
	}

	// Step 3: Drop existing collections if force recreate is enabled
	if opts.ForceRecreate {
		if err := di.dropCollections(ctx); err != nil {
			return fmt.Errorf("failed to drop existing collections: %w", err)
		}
	}

	// Step 4: Create collections and indexes (handled by client initialization)
	// Collections are already created during client initialization

	// Step 5: Enable sharding if requested
	if opts.EnableSharding && di.config.Sharding.Enabled {
		if err := di.client.enableSharding(ctx); err != nil {
			return fmt.Errorf("failed to enable sharding: %w", err)
		}
	}

	// Step 6: Seed initial data if requested
	if opts.SeedData {
		if err := di.seedInitialData(ctx); err != nil {
			return fmt.Errorf("failed to seed initial data: %w", err)
		}
	}

	// Step 7: Validate installation
	if err := di.validateInstallation(ctx); err != nil {
		return fmt.Errorf("installation validation failed: %w", err)
	}

	di.logger.Info("MongoDB database initialization completed successfully")
	return nil
}

// initializeClient creates and configures the MongoDB client
func (di *DatabaseInitializer) initializeClient() error {
	client, err := NewClient(di.config, di.logger)
	if err != nil {
		return fmt.Errorf("failed to create MongoDB client: %w", err)
	}

	di.client = client
	return nil
}

// verifyConnectivity checks connectivity to MongoDB
func (di *DatabaseInitializer) verifyConnectivity(ctx context.Context) error {
	di.logger.Info("Verifying connectivity to MongoDB")

	if !di.client.Health(ctx) {
		return fmt.Errorf("MongoDB health check failed")
	}

	di.logger.Info("MongoDB connectivity verified successfully")
	return nil
}

// dropCollections drops all existing collections
func (di *DatabaseInitializer) dropCollections(ctx context.Context) error {
	di.logger.Warn("Force recreating collections - all existing data will be lost")

	collections, err := di.client.database.ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return fmt.Errorf("failed to list collections: %w", err)
	}

	for _, collectionName := range collections {
		if err := di.client.database.Collection(collectionName).Drop(ctx); err != nil {
			di.logger.Error("Failed to drop collection",
				zap.String("collection", collectionName),
				zap.Error(err))
		} else {
			di.logger.Info("Collection dropped",
				zap.String("collection", collectionName))
		}
	}

	return nil
}

// seedInitialData seeds the database with initial data
func (di *DatabaseInitializer) seedInitialData(ctx context.Context) error {
	di.logger.Info("Seeding initial data")

	// Create default tenant
	tenantCollection, err := di.client.GetCollection("tenants")
	if err != nil {
		return fmt.Errorf("failed to get tenants collection: %w", err)
	}

	defaultTenant := bson.M{
		"_id":                "default-tenant-001",
		"name":               "iSECTECH Default",
		"domain":             "default.isectech.local",
		"plan":               "enterprise",
		"status":             "active",
		"settings":           bson.M{"theme": "dark", "timezone": "UTC"},
		"security_config":    bson.M{"require_mfa": true, "session_timeout": 3600},
		"max_users":          1000,
		"max_assets":         10000,
		"created_at":         time.Now(),
		"updated_at":         time.Now(),
	}

	if err := tenantCollection.InsertOne(ctx, defaultTenant, nil); err != nil {
		di.logger.Warn("Failed to insert default tenant, may already exist", zap.Error(err))
	}

	// Create sample security event schema
	securityEventCollection, err := di.client.GetCollection("security_events")
	if err != nil {
		return fmt.Errorf("failed to get security_events collection: %w", err)
	}

	sampleEvent := &SecurityEvent{
		TenantID:    "default-tenant-001",
		Timestamp:   time.Now(),
		EventType:   "authentication",
		Severity:    "medium",
		Description: "Sample security event for schema validation",
		Source: EventSource{
			IP:       "192.168.1.100",
			Hostname: "web-server-01",
		},
		RawData: map[string]interface{}{
			"log_level": "INFO",
			"message":   "User login attempt",
		},
		NormalizedData: map[string]interface{}{
			"event_category": "authentication",
			"action":         "login",
			"outcome":        "success",
		},
		Indicators: []ThreatIndicator{
			{
				Type:       "ip",
				Value:      "192.168.1.100",
				Confidence: 0.8,
				Source:     "internal",
			},
		},
		RiskScore:      25,
		Classification: "INTERNAL",
		Tags:           []string{"authentication", "web-server"},
		ProcessingInfo: ProcessingInfo{
			IngestedAt:  time.Now(),
			ProcessedAt: time.Now(),
			Pipeline:    "sample",
			Version:     "1.0",
		},
		Metadata: EventMetadata{
			TenantID:    "default-tenant-001",
			EventType:   "authentication",
			Severity:    "medium",
			Source:      "web-server",
			Environment: "development",
		},
	}

	if err := di.client.InsertSecurityEvent(ctx, sampleEvent, nil); err != nil {
		di.logger.Warn("Failed to insert sample security event", zap.Error(err))
	}

	// Create sample performance metric
	performanceCollection, err := di.client.GetCollection("performance_metrics")
	if err != nil {
		return fmt.Errorf("failed to get performance_metrics collection: %w", err)
	}

	sampleMetric := &PerformanceMetric{
		Timestamp:   time.Now(),
		ServiceName: "api-gateway",
		Metrics: map[string]interface{}{
			"cpu_usage":    45.2,
			"memory_usage": 67.8,
			"request_rate": 150.0,
			"error_rate":   0.02,
		},
		Tags: map[string]string{
			"environment": "development",
			"version":     "1.0.0",
		},
		Metadata: PerformanceMetadata{
			Service:     "api-gateway",
			Instance:    "api-gateway-001",
			Version:     "1.0.0",
			Environment: "development",
		},
	}

	if err := performanceCollection.InsertOne(ctx, sampleMetric, nil); err != nil {
		di.logger.Warn("Failed to insert sample performance metric", zap.Error(err))
	}

	di.logger.Info("Initial data seeded successfully")
	return nil
}

// validateInstallation validates that the database installation is correct
func (di *DatabaseInitializer) validateInstallation(ctx context.Context) error {
	di.logger.Info("Validating MongoDB installation")

	// Test basic operations on each collection
	collections := []string{
		"tenants", "assets", "threats", "threat_intelligence",
		"alerts", "compliance_data", "user_sessions",
		"security_events", "performance_metrics", "audit_events",
	}

	for _, collectionName := range collections {
		collection, err := di.client.GetCollection(collectionName)
		if err != nil {
			return fmt.Errorf("collection %s not found: %w", collectionName, err)
		}

		// Test count operation
		count, err := collection.EstimatedDocumentCount(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to count documents in %s: %w", collectionName, err)
		}

		di.logger.Debug("Collection validation passed",
			zap.String("collection", collectionName),
			zap.Int64("document_count", count))
	}

	// Test time-series collections
	for collectionName := range di.config.TimeSeries.Collections {
		collection, err := di.client.GetCollection(collectionName)
		if err != nil {
			return fmt.Errorf("time-series collection %s not found: %w", collectionName, err)
		}

		// Test that it's properly configured as time-series
		if !collection.isTimeSeries {
			return fmt.Errorf("collection %s is not configured as time-series", collectionName)
		}
	}

	// Test index creation
	indexes, err := di.client.ListIndexes(ctx, "security_events")
	if err != nil {
		return fmt.Errorf("failed to list indexes: %w", err)
	}

	if len(indexes) < 2 { // At least _id and one custom index
		return fmt.Errorf("insufficient indexes found on security_events collection")
	}

	// Test sharding status if enabled
	if di.config.Sharding.Enabled {
		status, err := di.client.GetShardingStatus(ctx)
		if err != nil {
			di.logger.Warn("Failed to get sharding status", zap.Error(err))
		} else {
			di.logger.Info("Sharding status validated", zap.Any("status", status))
		}
	}

	di.logger.Info("MongoDB installation validation completed successfully")
	return nil
}

// cleanup closes database connections
func (di *DatabaseInitializer) cleanup() {
	if di.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := di.client.Close(ctx); err != nil {
			di.logger.Error("Failed to close MongoDB client during cleanup",
				zap.Error(err))
		}
	}
}

// GetClient returns the initialized database client
func (di *DatabaseInitializer) GetClient() *Client {
	return di.client
}

// QuickStart performs a complete database setup for development
func QuickStart(ctx context.Context, logger *zap.Logger) (*Client, error) {
	initializer, err := NewDatabaseInitializer(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create initializer: %w", err)
	}

	opts := &InitializationOptions{
		CreateCollections:           true,
		CreateIndexes:               true,
		EnableSharding:              false, // Usually disabled for development
		CreateTimeSeriesCollections: true,
		SeedData:                    true,  // Enable for development quickstart
		ForceRecreate:               false,
		InitializationTimeout:       10 * time.Minute,
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