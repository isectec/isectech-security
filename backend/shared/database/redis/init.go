package redis

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// DatabaseInitializer handles Redis database initialization for iSECTECH
type DatabaseInitializer struct {
	config *Config
	client *Client
	logger *zap.Logger
}

// InitializationOptions provides options for Redis initialization
type InitializationOptions struct {
	InitializeStreams    bool
	CreateConsumerGroups bool
	ConfigureCache       bool
	EnableACL            bool
	TestConnections      bool
	InitializationTimeout time.Duration
}

// DefaultInitializationOptions returns production-ready initialization options
func DefaultInitializationOptions() *InitializationOptions {
	return &InitializationOptions{
		InitializeStreams:     true,
		CreateConsumerGroups:  true,
		ConfigureCache:        true,
		EnableACL:             true,
		TestConnections:       true,
		InitializationTimeout: 5 * time.Minute,
	}
}

// NewDatabaseInitializer creates a new Redis database initializer
func NewDatabaseInitializer(logger *zap.Logger) (*DatabaseInitializer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Redis config: %w", err)
	}

	return &DatabaseInitializer{
		config: config,
		logger: logger,
	}, nil
}

// Initialize initializes the Redis database with complete setup
func (di *DatabaseInitializer) Initialize(ctx context.Context, opts *InitializationOptions) error {
	if opts == nil {
		opts = DefaultInitializationOptions()
	}

	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, opts.InitializationTimeout)
	defer cancel()

	di.logger.Info("Starting Redis database initialization",
		zap.Bool("initialize_streams", opts.InitializeStreams),
		zap.Bool("create_consumer_groups", opts.CreateConsumerGroups),
		zap.Bool("configure_cache", opts.ConfigureCache),
		zap.Bool("enable_acl", opts.EnableACL))

	// Step 1: Initialize client
	if err := di.initializeClient(); err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}
	defer di.cleanup()

	// Step 2: Test connections
	if opts.TestConnections {
		if err := di.testConnections(ctx); err != nil {
			return fmt.Errorf("connection test failed: %w", err)
		}
	}

	// Step 3: Configure cache settings
	if opts.ConfigureCache {
		if err := di.configureCacheSettings(ctx); err != nil {
			return fmt.Errorf("failed to configure cache settings: %w", err)
		}
	}

	// Step 4: Initialize streams
	if opts.InitializeStreams {
		if err := di.initializeStreams(ctx); err != nil {
			return fmt.Errorf("failed to initialize streams: %w", err)
		}
	}

	// Step 5: Create consumer groups
	if opts.CreateConsumerGroups && di.config.Streams.Enabled {
		if err := di.createConsumerGroups(ctx); err != nil {
			return fmt.Errorf("failed to create consumer groups: %w", err)
		}
	}

	// Step 6: Configure ACL if enabled
	if opts.EnableACL && di.config.Security.ACLConfig.Enabled {
		if err := di.configureACL(ctx); err != nil {
			return fmt.Errorf("failed to configure ACL: %w", err)
		}
	}

	// Step 7: Validate installation
	if err := di.validateInstallation(ctx); err != nil {
		return fmt.Errorf("installation validation failed: %w", err)
	}

	di.logger.Info("Redis database initialization completed successfully")
	return nil
}

// initializeClient creates and configures the Redis client
func (di *DatabaseInitializer) initializeClient() error {
	client, err := NewClient(di.config, di.logger)
	if err != nil {
		return fmt.Errorf("failed to create Redis client: %w", err)
	}

	di.client = client
	return nil
}

// testConnections tests connectivity to Redis
func (di *DatabaseInitializer) testConnections(ctx context.Context) error {
	di.logger.Info("Testing Redis connections")

	// Test ping
	if err := di.client.Ping(ctx); err != nil {
		return fmt.Errorf("ping test failed: %w", err)
	}

	// Test basic operations
	testKey := "isectech:init:test"
	testValue := "initialization test"

	// Test SET
	if err := di.client.Set(ctx, testKey, testValue, nil); err != nil {
		return fmt.Errorf("set operation failed: %w", err)
	}

	// Test GET
	value, err := di.client.Get(ctx, testKey, nil)
	if err != nil {
		return fmt.Errorf("get operation failed: %w", err)
	}

	if value != testValue {
		return fmt.Errorf("value mismatch: expected %s, got %s", testValue, value)
	}

	// Test DEL
	if err := di.client.Del(ctx, testKey); err != nil {
		return fmt.Errorf("delete operation failed: %w", err)
	}

	// Test cluster/sentinel specific operations if applicable
	if di.config.IsClusterMode() {
		if err := di.testClusterOperations(ctx); err != nil {
			return fmt.Errorf("cluster operations test failed: %w", err)
		}
	}

	if di.config.IsSentinelMode() {
		if err := di.testSentinelOperations(ctx); err != nil {
			return fmt.Errorf("sentinel operations test failed: %w", err)
		}
	}

	di.logger.Info("Redis connection tests passed")
	return nil
}

// testClusterOperations tests Redis cluster specific operations
func (di *DatabaseInitializer) testClusterOperations(ctx context.Context) error {
	// Test cluster info
	info, err := di.client.client.ClusterInfo(ctx).Result()
	if err != nil {
		return fmt.Errorf("cluster info failed: %w", err)
	}

	di.logger.Info("Cluster info retrieved", zap.String("info", info))

	// Test cluster nodes
	nodes, err := di.client.client.ClusterNodes(ctx).Result()
	if err != nil {
		return fmt.Errorf("cluster nodes failed: %w", err)
	}

	di.logger.Info("Cluster nodes retrieved", zap.String("nodes", nodes))
	return nil
}

// testSentinelOperations tests Redis sentinel specific operations
func (di *DatabaseInitializer) testSentinelOperations(ctx context.Context) error {
	// Test that we can connect to master
	if err := di.client.Ping(ctx); err != nil {
		return fmt.Errorf("sentinel master ping failed: %w", err)
	}

	di.logger.Info("Sentinel master connection verified")
	return nil
}

// configureCacheSettings configures Redis cache settings
func (di *DatabaseInitializer) configureCacheSettings(ctx context.Context) error {
	di.logger.Info("Configuring Redis cache settings")

	// Set memory policy
	if di.config.Cache.MaxMemory != "" {
		err := di.client.client.ConfigSet(ctx, "maxmemory", di.config.Cache.MaxMemory).Err()
		if err != nil {
			di.logger.Warn("Failed to set maxmemory", zap.Error(err))
		} else {
			di.logger.Info("Max memory set", zap.String("max_memory", di.config.Cache.MaxMemory))
		}
	}

	// Set eviction policy
	err := di.client.client.ConfigSet(ctx, "maxmemory-policy", di.config.Cache.EvictionPolicy).Err()
	if err != nil {
		di.logger.Warn("Failed to set eviction policy", zap.Error(err))
	} else {
		di.logger.Info("Eviction policy set", zap.String("policy", di.config.Cache.EvictionPolicy))
	}

	// Configure other cache-related settings
	cacheSettings := map[string]string{
		"save":                    "", // Disable RDB persistence for cache-only usage
		"appendonly":              "no", // Disable AOF for cache-only usage
		"tcp-keepalive":           "300",
		"timeout":                 "0",
		"tcp-backlog":             "511",
		"databases":               "16",
		"stop-writes-on-bgsave-error": "no",
	}

	for key, value := range cacheSettings {
		err := di.client.client.ConfigSet(ctx, key, value).Err()
		if err != nil {
			di.logger.Warn("Failed to set config",
				zap.String("key", key),
				zap.String("value", value),
				zap.Error(err))
		}
	}

	di.logger.Info("Cache settings configured")
	return nil
}

// initializeStreams initializes Redis Streams
func (di *DatabaseInitializer) initializeStreams(ctx context.Context) error {
	if !di.config.Streams.Enabled {
		return nil
	}

	di.logger.Info("Initializing Redis Streams")

	// Initialize each configured stream
	for name, groupConfig := range di.config.Streams.ConsumerGroups {
		streamName := groupConfig.StreamName

		// Check if stream exists
		exists, err := di.client.Exists(ctx, streamName)
		if err != nil {
			return fmt.Errorf("failed to check stream existence: %w", err)
		}

		if exists == 0 {
			// Create stream with initial message
			err = di.client.client.XAdd(ctx, &redis.XAddArgs{
				Stream: streamName,
				ID:     "*",
				Values: map[string]interface{}{
					"init": "stream_initialized",
					"timestamp": time.Now().Format(time.RFC3339),
					"tenant_id": "system",
					"event_type": "stream_init",
				},
			}).Err()

			if err != nil {
				return fmt.Errorf("failed to create stream %s: %w", streamName, err)
			}

			di.logger.Info("Stream created", 
				zap.String("stream", streamName),
				zap.String("consumer_group", name))
		}

		// Trim the stream to remove init message if it was the only one
		streamInfo, err := di.client.client.XInfoStream(ctx, streamName).Result()
		if err == nil && streamInfo.Length == 1 {
			di.client.client.XTrim(ctx, streamName, 0)
		}
	}

	di.logger.Info("Redis Streams initialized")
	return nil
}

// createConsumerGroups creates Redis Stream consumer groups
func (di *DatabaseInitializer) createConsumerGroups(ctx context.Context) error {
	di.logger.Info("Creating Redis Stream consumer groups")

	for name, groupConfig := range di.config.Streams.ConsumerGroups {
		// Create consumer group
		err := di.client.client.XGroupCreate(ctx, groupConfig.StreamName, groupConfig.GroupName, "0").Err()
		if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
			return fmt.Errorf("failed to create consumer group %s: %w", groupConfig.GroupName, err)
		}

		di.logger.Info("Consumer group ready",
			zap.String("group", name),
			zap.String("stream", groupConfig.StreamName),
			zap.String("group_name", groupConfig.GroupName))
	}

	di.logger.Info("Consumer groups created")
	return nil
}

// configureACL configures Redis Access Control Lists
func (di *DatabaseInitializer) configureACL(ctx context.Context) error {
	di.logger.Info("Configuring Redis ACL")

	// Enable ACL logging
	err := di.client.client.ConfigSet(ctx, "acllog-max-len", "128").Err()
	if err != nil {
		di.logger.Warn("Failed to set ACL log max length", zap.Error(err))
	}

	// Create ACL users
	for username, userConfig := range di.config.Security.ACLConfig.Users {
		aclCommand := fmt.Sprintf("ACL SETUSER %s", username)
		
		// Add password
		if userConfig.Password != "" {
			aclCommand += fmt.Sprintf(" >%s", userConfig.Password)
		}

		// Add categories
		for _, category := range userConfig.Categories {
			aclCommand += fmt.Sprintf(" %s", category)
		}

		// Add commands
		for _, command := range userConfig.Commands {
			aclCommand += fmt.Sprintf(" %s", command)
		}

		// Add key patterns
		for _, keyPattern := range userConfig.Keys {
			aclCommand += fmt.Sprintf(" %s", keyPattern)
		}

		// Add channel patterns
		for _, channel := range userConfig.Channels {
			aclCommand += fmt.Sprintf(" %s", channel)
		}

		// Execute ACL command
		err := di.client.client.Do(ctx, "ACL", "SETUSER", username, aclCommand).Err()
		if err != nil {
			di.logger.Warn("Failed to set ACL for user",
				zap.String("username", username),
				zap.Error(err))
		} else {
			di.logger.Info("ACL user configured", zap.String("username", username))
		}
	}

	di.logger.Info("Redis ACL configured")
	return nil
}

// validateInstallation validates that the Redis installation is correct
func (di *DatabaseInitializer) validateInstallation(ctx context.Context) error {
	di.logger.Info("Validating Redis installation")

	// Test basic operations
	if err := di.client.Ping(ctx); err != nil {
		return fmt.Errorf("ping validation failed: %w", err)
	}

	// Test cache operations
	cache := di.client.GetCacheManager()
	if cache == nil {
		return fmt.Errorf("cache manager not initialized")
	}

	// Test session storage
	testSession := &SessionData{
		UserID:       "test-user",
		TenantID:     "test-tenant",
		Role:         "admin",
		LoginTime:    time.Now(),
		LastActivity: time.Now(),
		IPAddress:    "127.0.0.1",
		MFAVerified:  true,
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	err := cache.StoreSession(ctx, "test-session", testSession)
	if err != nil {
		return fmt.Errorf("session storage test failed: %w", err)
	}

	retrievedSession, err := cache.GetSession(ctx, "test-session", "test-tenant")
	if err != nil {
		return fmt.Errorf("session retrieval test failed: %w", err)
	}

	if retrievedSession.UserID != testSession.UserID {
		return fmt.Errorf("session data mismatch")
	}

	// Clean up test data
	cache.InvalidateSession(ctx, "test-session", "test-tenant")

	// Test streams if enabled
	if di.config.Streams.Enabled && di.client.GetStreamsManager() != nil {
		streams := di.client.GetStreamsManager()
		
		// Test publishing a message
		testEvent := &SecurityEvent{
			ID:          "test-event",
			TenantID:    "test-tenant",
			EventType:   "test",
			Severity:    "low",
			Description: "Test event for validation",
			Timestamp:   time.Now(),
		}

		err = di.client.PublishSecurityEvent(ctx, testEvent)
		if err != nil {
			return fmt.Errorf("stream publishing test failed: %w", err)
		}

		di.logger.Info("Stream publishing test passed")
	}

	// Get Redis info
	stats, err := di.client.GetStats(ctx)
	if err != nil {
		di.logger.Warn("Failed to get Redis stats", zap.Error(err))
	} else {
		di.logger.Info("Redis stats retrieved", zap.Any("stats_keys", getMapKeys(stats)))
	}

	di.logger.Info("Redis installation validation completed successfully")
	return nil
}

// cleanup closes database connections
func (di *DatabaseInitializer) cleanup() {
	if di.client != nil {
		if err := di.client.Close(); err != nil {
			di.logger.Error("Failed to close Redis client during cleanup",
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
		InitializeStreams:     true,
		CreateConsumerGroups:  true,
		ConfigureCache:        true,
		EnableACL:             false, // Usually disabled for development
		TestConnections:       true,
		InitializationTimeout: 5 * time.Minute,
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

// Helper function to get map keys for logging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}