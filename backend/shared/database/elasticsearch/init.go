package elasticsearch

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// DatabaseInitializer handles Elasticsearch database initialization for iSECTECH
type DatabaseInitializer struct {
	config          *Config
	client          *Client
	templateManager *TemplateManager
	ilmManager      *ILMManager
	ccrManager      *CCRManager
	logger          *zap.Logger
}

// InitializationOptions provides options for Elasticsearch initialization
type InitializationOptions struct {
	CreateTemplates       bool
	SetupILM              bool
	SetupCCR              bool
	CreateBootstrapIndices bool
	ValidateConfiguration bool
	TestConnections       bool
	InitializationTimeout time.Duration
}

// DefaultInitializationOptions returns production-ready initialization options
func DefaultInitializationOptions() *InitializationOptions {
	return &InitializationOptions{
		CreateTemplates:        true,
		SetupILM:               true,
		SetupCCR:               false, // Usually disabled by default
		CreateBootstrapIndices: true,
		ValidateConfiguration:  true,
		TestConnections:        true,
		InitializationTimeout:  10 * time.Minute,
	}
}

// NewDatabaseInitializer creates a new Elasticsearch database initializer
func NewDatabaseInitializer(logger *zap.Logger) (*DatabaseInitializer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Elasticsearch config: %w", err)
	}

	return &DatabaseInitializer{
		config: config,
		logger: logger,
	}, nil
}

// Initialize initializes the Elasticsearch database with complete setup
func (di *DatabaseInitializer) Initialize(ctx context.Context, opts *InitializationOptions) error {
	if opts == nil {
		opts = DefaultInitializationOptions()
	}

	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, opts.InitializationTimeout)
	defer cancel()

	di.logger.Info("Starting Elasticsearch database initialization",
		zap.Bool("create_templates", opts.CreateTemplates),
		zap.Bool("setup_ilm", opts.SetupILM),
		zap.Bool("setup_ccr", opts.SetupCCR),
		zap.Bool("create_bootstrap_indices", opts.CreateBootstrapIndices),
		zap.Bool("validate_configuration", opts.ValidateConfiguration))

	// Step 1: Initialize client
	if err := di.initializeClient(); err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}
	defer di.cleanup()

	// Step 2: Initialize managers
	if err := di.initializeManagers(); err != nil {
		return fmt.Errorf("failed to initialize managers: %w", err)
	}

	// Step 3: Test connections
	if opts.TestConnections {
		if err := di.testConnections(ctx); err != nil {
			return fmt.Errorf("connection test failed: %w", err)
		}
	}

	// Step 4: Create component templates
	if opts.CreateTemplates {
		if err := di.templateManager.CreateComponentTemplates(ctx); err != nil {
			return fmt.Errorf("failed to create component templates: %w", err)
		}
	}

	// Step 5: Create index templates
	if opts.CreateTemplates {
		if err := di.templateManager.CreateIndexTemplates(ctx); err != nil {
			return fmt.Errorf("failed to create index templates: %w", err)
		}
	}

	// Step 6: Setup ILM
	if opts.SetupILM && di.config.ILM.Enabled {
		if err := di.setupILM(ctx); err != nil {
			return fmt.Errorf("failed to setup ILM: %w", err)
		}
	}

	// Step 7: Setup CCR
	if opts.SetupCCR && di.config.CCR.Enabled {
		if err := di.setupCCR(ctx); err != nil {
			return fmt.Errorf("failed to setup CCR: %w", err)
		}
	}

	// Step 8: Create bootstrap indices
	if opts.CreateBootstrapIndices {
		if err := di.templateManager.CreateBootstrapIndices(ctx); err != nil {
			return fmt.Errorf("failed to create bootstrap indices: %w", err)
		}
	}

	// Step 9: Validate configuration
	if opts.ValidateConfiguration {
		if err := di.validateInstallation(ctx); err != nil {
			return fmt.Errorf("installation validation failed: %w", err)
		}
	}

	di.logger.Info("Elasticsearch database initialization completed successfully")
	return nil
}

// initializeClient creates and configures the Elasticsearch client
func (di *DatabaseInitializer) initializeClient() error {
	client, err := NewClient(di.config, di.logger)
	if err != nil {
		return fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}

	di.client = client
	return nil
}

// initializeManagers creates management components
func (di *DatabaseInitializer) initializeManagers() error {
	var err error

	// Initialize template manager
	di.templateManager, err = NewTemplateManager(di.client, di.config, di.logger)
	if err != nil {
		return fmt.Errorf("failed to create template manager: %w", err)
	}

	// Initialize ILM manager
	di.ilmManager, err = NewILMManager(di.client, di.config, di.logger)
	if err != nil {
		return fmt.Errorf("failed to create ILM manager: %w", err)
	}

	// Initialize CCR manager
	di.ccrManager, err = NewCCRManager(di.client, di.config, di.logger)
	if err != nil {
		return fmt.Errorf("failed to create CCR manager: %w", err)
	}

	return nil
}

// testConnections tests connectivity to Elasticsearch
func (di *DatabaseInitializer) testConnections(ctx context.Context) error {
	di.logger.Info("Testing Elasticsearch connections")

	// Test ping
	if err := di.client.Ping(ctx); err != nil {
		return fmt.Errorf("ping test failed: %w", err)
	}

	// Test cluster health
	health, err := di.client.GetClusterHealth(ctx)
	if err != nil {
		return fmt.Errorf("cluster health test failed: %w", err)
	}

	status, _ := health["status"].(string)
	di.logger.Info("Cluster health retrieved",
		zap.String("status", status),
		zap.Any("cluster_name", health["cluster_name"]))

	if status == "red" {
		return fmt.Errorf("cluster health is red")
	}

	// Test basic indexing
	testEvent := &SecurityEvent{
		Timestamp:              time.Now(),
		TenantID:               "test-tenant",
		EventType:              "test",
		Severity:               "low",
		Description:            "Test event for initialization",
		SecurityClassification: "UNCLASSIFIED",
		Source: map[string]interface{}{
			"ip":       "127.0.0.1",
			"hostname": "localhost",
		},
		Target: map[string]interface{}{
			"ip":       "127.0.0.1",
			"hostname": "localhost",
		},
		RiskScore: 1,
		Tags:      []string{"test", "initialization"},
	}

	// Index test document
	indexOpts := &IndexOptions{
		Index:      "test-security-events",
		DocumentID: "test-init-doc",
		Refresh:    "true",
		Timeout:    30 * time.Second,
	}

	if err := di.client.IndexSecurityEvent(ctx, testEvent, indexOpts); err != nil {
		return fmt.Errorf("test indexing failed: %w", err)
	}

	// Search for test document
	searchQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"tenant_id": "test-tenant",
			},
		},
	}

	searchOpts := &SearchOptions{
		Index: "test-security-events",
		Size:  1,
	}

	results, err := di.client.Search(ctx, searchQuery, searchOpts)
	if err != nil {
		return fmt.Errorf("test search failed: %w", err)
	}

	if results.TotalHits == 0 {
		return fmt.Errorf("test document not found")
	}

	// Clean up test document
	di.client.client.Delete("test-security-events", "test-init-doc")

	di.logger.Info("Elasticsearch connection tests passed")
	return nil
}

// setupILM configures Index Lifecycle Management
func (di *DatabaseInitializer) setupILM(ctx context.Context) error {
	di.logger.Info("Setting up Index Lifecycle Management")

	// Start ILM service
	if err := di.ilmManager.StartILM(ctx); err != nil {
		di.logger.Warn("Failed to start ILM service (may already be running)", zap.Error(err))
	}

	// Create ILM policies
	if err := di.ilmManager.CreatePolicies(ctx); err != nil {
		return fmt.Errorf("failed to create ILM policies: %w", err)
	}

	// Set poll interval
	if err := di.ilmManager.SetPollInterval(ctx, di.config.ILM.PollInterval); err != nil {
		di.logger.Warn("Failed to set ILM poll interval", zap.Error(err))
	}

	di.logger.Info("ILM setup completed")
	return nil
}

// setupCCR configures Cross-Cluster Replication
func (di *DatabaseInitializer) setupCCR(ctx context.Context) error {
	di.logger.Info("Setting up Cross-Cluster Replication")

	// Setup remote clusters
	if err := di.ccrManager.SetupRemoteClusters(ctx); err != nil {
		return fmt.Errorf("failed to setup remote clusters: %w", err)
	}

	// Setup follower indices
	if err := di.ccrManager.SetupFollowerIndices(ctx); err != nil {
		return fmt.Errorf("failed to setup follower indices: %w", err)
	}

	di.logger.Info("CCR setup completed")
	return nil
}

// validateInstallation validates that the Elasticsearch installation is correct
func (di *DatabaseInitializer) validateInstallation(ctx context.Context) error {
	di.logger.Info("Validating Elasticsearch installation")

	// Validate cluster health
	health, err := di.client.GetClusterHealth(ctx)
	if err != nil {
		return fmt.Errorf("cluster health validation failed: %w", err)
	}

	status, _ := health["status"].(string)
	if status == "red" {
		return fmt.Errorf("cluster health is red")
	}

	// Validate templates
	if err := di.templateManager.ValidateTemplates(ctx); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Validate ILM if enabled
	if di.config.ILM.Enabled {
		if err := di.ilmManager.ValidatePolicies(ctx); err != nil {
			return fmt.Errorf("ILM validation failed: %w", err)
		}
	}

	// Validate CCR if enabled
	if di.config.CCR.Enabled {
		if err := di.ccrManager.ValidateConfiguration(ctx); err != nil {
			return fmt.Errorf("CCR validation failed: %w", err)
		}
	}

	// Test document indexing and search
	if err := di.validateDocumentOperations(ctx); err != nil {
		return fmt.Errorf("document operations validation failed: %w", err)
	}

	// Get cluster statistics
	stats, err := di.client.GetClusterStats(ctx)
	if err != nil {
		di.logger.Warn("Failed to get cluster stats", zap.Error(err))
	} else {
		if clusterName, ok := stats["cluster_name"].(string); ok {
			di.logger.Info("Cluster stats retrieved", zap.String("cluster_name", clusterName))
		}
	}

	di.logger.Info("Elasticsearch installation validation completed successfully")
	return nil
}

// validateDocumentOperations validates that document operations work correctly
func (di *DatabaseInitializer) validateDocumentOperations(ctx context.Context) error {
	// Test security event indexing
	securityEvent := &SecurityEvent{
		Timestamp:              time.Now(),
		TenantID:               "validation-tenant",
		EventType:              "validation",
		Severity:               "info",
		Description:            "Validation test event",
		SecurityClassification: "UNCLASSIFIED",
		Source: map[string]interface{}{
			"ip":       "10.0.0.1",
			"hostname": "test-host",
		},
		RiskScore: 2,
		Tags:      []string{"validation", "test"},
	}

	indexOpts := &IndexOptions{
		Index:      "validation-security-events",
		DocumentID: "validation-test",
		Refresh:    "true",
	}

	if err := di.client.IndexSecurityEvent(ctx, securityEvent, indexOpts); err != nil {
		return fmt.Errorf("security event indexing validation failed: %w", err)
	}

	// Test threat intelligence indexing
	threatIntel := &ThreatIntelligence{
		Timestamp:              time.Now(),
		TenantID:               "validation-tenant",
		ThreatID:               "validation-threat",
		ThreatType:             "malware",
		Severity:               "medium",
		Confidence:             0.85,
		Source:                 "validation-source",
		Description:            "Validation threat intelligence",
		SecurityClassification: "UNCLASSIFIED",
		ExpiresAt:              time.Now().Add(24 * time.Hour),
	}

	if err := di.client.IndexThreatIntelligence(ctx, threatIntel, indexOpts); err != nil {
		return fmt.Errorf("threat intelligence indexing validation failed: %w", err)
	}

	// Test audit log indexing
	auditLog := &AuditLog{
		Timestamp:              time.Now(),
		TenantID:               "validation-tenant",
		UserID:                 "validation-user",
		Action:                 "validation",
		ResourceType:           "document",
		ResourceID:             "validation-resource",
		SourceIP:               "10.0.0.1",
		UserAgent:              "validation-agent",
		Status:                 "success",
		SecurityClassification: "UNCLASSIFIED",
		Details: map[string]interface{}{
			"validation": true,
		},
	}

	if err := di.client.IndexAuditLog(ctx, auditLog, indexOpts); err != nil {
		return fmt.Errorf("audit log indexing validation failed: %w", err)
	}

	// Test search functionality
	searchQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"tenant_id": "validation-tenant",
			},
		},
	}

	searchOpts := &SearchOptions{
		Index: "validation-*",
		Size:  10,
	}

	results, err := di.client.Search(ctx, searchQuery, searchOpts)
	if err != nil {
		return fmt.Errorf("search validation failed: %w", err)
	}

	if results.TotalHits < 3 {
		return fmt.Errorf("expected at least 3 validation documents, found %d", results.TotalHits)
	}

	// Clean up validation documents
	go func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Delete validation indices
		di.client.client.Indices.Delete([]string{"validation-*"})
	}()

	di.logger.Info("Document operations validation passed")
	return nil
}

// cleanup closes database connections
func (di *DatabaseInitializer) cleanup() {
	if di.client != nil {
		if err := di.client.Close(); err != nil {
			di.logger.Error("Failed to close Elasticsearch client during cleanup",
				zap.Error(err))
		}
	}
}

// GetClient returns the initialized database client
func (di *DatabaseInitializer) GetClient() *Client {
	return di.client
}

// GetTemplateManager returns the template manager
func (di *DatabaseInitializer) GetTemplateManager() *TemplateManager {
	return di.templateManager
}

// GetILMManager returns the ILM manager
func (di *DatabaseInitializer) GetILMManager() *ILMManager {
	return di.ilmManager
}

// GetCCRManager returns the CCR manager
func (di *DatabaseInitializer) GetCCRManager() *CCRManager {
	return di.ccrManager
}

// QuickStart performs a complete database setup for development
func QuickStart(ctx context.Context, logger *zap.Logger) (*Client, error) {
	initializer, err := NewDatabaseInitializer(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create initializer: %w", err)
	}

	opts := &InitializationOptions{
		CreateTemplates:        true,
		SetupILM:               true,
		SetupCCR:               false, // Usually disabled for development
		CreateBootstrapIndices: true,
		ValidateConfiguration:  true,
		TestConnections:        true,
		InitializationTimeout:  10 * time.Minute,
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

// Upgrade performs database schema and configuration upgrades
func (di *DatabaseInitializer) Upgrade(ctx context.Context) error {
	di.logger.Info("Starting Elasticsearch database upgrade")

	// Initialize client and managers if not already done
	if di.client == nil {
		if err := di.initializeClient(); err != nil {
			return fmt.Errorf("failed to initialize client for upgrade: %w", err)
		}
		defer di.cleanup()
	}

	if di.templateManager == nil {
		if err := di.initializeManagers(); err != nil {
			return fmt.Errorf("failed to initialize managers for upgrade: %w", err)
		}
	}

	// Upgrade templates
	if err := di.templateManager.UpgradeTemplates(ctx); err != nil {
		return fmt.Errorf("failed to upgrade templates: %w", err)
	}

	// Cleanup failed ILM policies
	if di.config.ILM.Enabled {
		if err := di.ilmManager.CleanupFailedPolicies(ctx); err != nil {
			di.logger.Warn("Failed to cleanup ILM policies", zap.Error(err))
		}
	}

	// Monitor CCR if enabled
	if di.config.CCR.Enabled {
		if err := di.ccrManager.MonitorReplication(ctx); err != nil {
			di.logger.Warn("Failed to monitor CCR", zap.Error(err))
		}
	}

	di.logger.Info("Elasticsearch database upgrade completed")
	return nil
}

// MonitorHealth monitors the health of the Elasticsearch cluster
func (di *DatabaseInitializer) MonitorHealth(ctx context.Context) error {
	if di.client == nil {
		return fmt.Errorf("client not initialized")
	}

	// Monitor cluster health
	health, err := di.client.GetClusterHealth(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster health: %w", err)
	}

	status, _ := health["status"].(string)
	di.logger.Info("Cluster health check",
		zap.String("status", status),
		zap.Any("active_shards", health["active_shards"]),
		zap.Any("relocating_shards", health["relocating_shards"]),
		zap.Any("initializing_shards", health["initializing_shards"]),
		zap.Any("unassigned_shards", health["unassigned_shards"]))

	// Monitor ILM if enabled
	if di.config.ILM.Enabled && di.ilmManager != nil {
		if err := di.ilmManager.MonitorPolicies(ctx); err != nil {
			di.logger.Error("ILM monitoring failed", zap.Error(err))
		}
	}

	// Monitor CCR if enabled
	if di.config.CCR.Enabled && di.ccrManager != nil {
		if err := di.ccrManager.MonitorReplication(ctx); err != nil {
			di.logger.Error("CCR monitoring failed", zap.Error(err))
		}
	}

	return nil
}