package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// enableSharding enables sharding for the database and collections
func (c *Client) enableSharding(ctx context.Context) error {
	if !c.config.Sharding.Enabled {
		return nil
	}

	c.logger.Info("Enabling sharding for database", 
		zap.String("database", c.config.Database))

	// Enable sharding for the database
	err := c.runAdminCommand(ctx, bson.D{
		{Key: "enableSharding", Value: c.config.Database},
	})
	if err != nil {
		return fmt.Errorf("failed to enable sharding for database: %w", err)
	}

	// Shard collections that require sharding
	shardedCollections := map[string]string{
		"security_events":      "metadata.tenant_id",
		"performance_metrics":  "metadata.service",
		"audit_events":         "metadata.tenant_id",
		"assets":               "tenant_id",
		"threats":              "tenant_id",
		"alerts":               "tenant_id",
	}

	for collectionName, shardKey := range shardedCollections {
		if err := c.shardCollection(ctx, collectionName, shardKey); err != nil {
			c.logger.Warn("Failed to shard collection, continuing",
				zap.String("collection", collectionName),
				zap.Error(err))
		}
	}

	// Configure balancer settings
	if err := c.configureBalancer(ctx); err != nil {
		return fmt.Errorf("failed to configure balancer: %w", err)
	}

	c.logger.Info("Sharding enabled successfully")
	return nil
}

// shardCollection shards a specific collection
func (c *Client) shardCollection(ctx context.Context, collectionName, shardKey string) error {
	namespace := fmt.Sprintf("%s.%s", c.config.Database, collectionName)
	
	c.logger.Info("Sharding collection",
		zap.String("collection", collectionName),
		zap.String("shard_key", shardKey))

	// Create shard key index first
	collection := c.database.Collection(collectionName)
	indexModel := mongo.IndexModel{
		Keys: bson.D{{Key: shardKey, Value: 1}},
	}
	
	_, err := collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create shard key index: %w", err)
	}

	// Shard the collection
	shardCommand := bson.D{
		{Key: "shardCollection", Value: namespace},
		{Key: "key", Value: bson.D{{Key: shardKey, Value: 1}}},
	}

	// Add additional sharding options from config
	if c.config.Sharding.Chunks.Size > 0 {
		shardCommand = append(shardCommand, 
			bson.E{Key: "chunkSize", Value: c.config.Sharding.Chunks.Size})
	}

	err = c.runAdminCommand(ctx, shardCommand)
	if err != nil {
		return fmt.Errorf("failed to shard collection %s: %w", collectionName, err)
	}

	c.logger.Info("Collection sharded successfully",
		zap.String("collection", collectionName),
		zap.String("shard_key", shardKey))

	return nil
}

// configureBalancer configures the MongoDB balancer
func (c *Client) configureBalancer(ctx context.Context) error {
	balancerConfig := c.config.Sharding.Balancer

	// Enable or disable balancer
	var command bson.D
	if balancerConfig.Enabled {
		command = bson.D{{Key: "balancerStart", Value: 1}}
	} else {
		command = bson.D{{Key: "balancerStop", Value: 1}}
	}

	if err := c.runAdminCommand(ctx, command); err != nil {
		return fmt.Errorf("failed to configure balancer state: %w", err)
	}

	// Configure balancer window if specified
	if balancerConfig.ActiveWindow.Start != "" && balancerConfig.ActiveWindow.Stop != "" {
		windowCommand := bson.D{
			{Key: "updateOne", Value: "settings"},
			{Key: "updates", Value: bson.A{
				bson.D{
					{Key: "q", Value: bson.D{{Key: "_id", Value: "balancer"}}},
					{Key: "u", Value: bson.D{
						{Key: "$set", Value: bson.D{
							{Key: "activeWindow", Value: bson.D{
								{Key: "start", Value: balancerConfig.ActiveWindow.Start},
								{Key: "stop", Value: balancerConfig.ActiveWindow.Stop},
							}},
						}},
					}},
					{Key: "upsert", Value: true},
				},
			}},
		}

		if err := c.runConfigCommand(ctx, windowCommand); err != nil {
			return fmt.Errorf("failed to configure balancer window: %w", err)
		}
	}

	c.logger.Info("Balancer configured successfully",
		zap.Bool("enabled", balancerConfig.Enabled),
		zap.String("active_window_start", balancerConfig.ActiveWindow.Start),
		zap.String("active_window_stop", balancerConfig.ActiveWindow.Stop))

	return nil
}

// runAdminCommand runs a command against the admin database
func (c *Client) runAdminCommand(ctx context.Context, command bson.D) error {
	adminDB := c.client.Database("admin")
	
	var result bson.M
	err := adminDB.RunCommand(ctx, command).Decode(&result)
	if err != nil {
		c.logger.Error("Admin command failed",
			zap.Error(err),
			zap.Any("command", command))
		return err
	}

	// Check if the command succeeded
	if ok, exists := result["ok"]; exists {
		if okFloat, isFloat := ok.(float64); isFloat && okFloat != 1.0 {
			return fmt.Errorf("admin command failed: %v", result)
		}
	}

	return nil
}

// runConfigCommand runs a command against the config database
func (c *Client) runConfigCommand(ctx context.Context, command bson.D) error {
	configDB := c.client.Database("config")
	
	var result bson.M
	err := configDB.RunCommand(ctx, command).Decode(&result)
	if err != nil {
		c.logger.Error("Config command failed",
			zap.Error(err),
			zap.Any("command", command))
		return err
	}

	return nil
}

// GetShardingStatus returns the current sharding status
func (c *Client) GetShardingStatus(ctx context.Context) (bson.M, error) {
	var status bson.M
	
	err := c.runAdminCommand(ctx, bson.D{{Key: "sh.status", Value: 1}})
	if err != nil {
		return nil, fmt.Errorf("failed to get sharding status: %w", err)
	}

	return status, nil
}

// ListShards returns information about all shards
func (c *Client) ListShards(ctx context.Context) ([]bson.M, error) {
	var result struct {
		Shards []bson.M `bson:"shards"`
	}

	err := c.runAdminCommand(ctx, bson.D{{Key: "listShards", Value: 1}})
	if err != nil {
		return nil, fmt.Errorf("failed to list shards: %w", err)
	}

	return result.Shards, nil
}

// AddShard adds a new shard to the cluster
func (c *Client) AddShard(ctx context.Context, shardConnectionString string, name string) error {
	command := bson.D{
		{Key: "addShard", Value: shardConnectionString},
	}

	if name != "" {
		command = append(command, bson.E{Key: "name", Value: name})
	}

	err := c.runAdminCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to add shard: %w", err)
	}

	c.logger.Info("Shard added successfully",
		zap.String("connection_string", shardConnectionString),
		zap.String("name", name))

	return nil
}

// RemoveShard removes a shard from the cluster
func (c *Client) RemoveShard(ctx context.Context, shardName string) error {
	command := bson.D{
		{Key: "removeShard", Value: shardName},
	}

	err := c.runAdminCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to remove shard: %w", err)
	}

	c.logger.Info("Shard removal initiated",
		zap.String("shard_name", shardName))

	return nil
}

// MoveChunk moves a chunk from one shard to another
func (c *Client) MoveChunk(ctx context.Context, namespace string, find bson.M, toShard string) error {
	command := bson.D{
		{Key: "moveChunk", Value: namespace},
		{Key: "find", Value: find},
		{Key: "to", Value: toShard},
	}

	err := c.runAdminCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to move chunk: %w", err)
	}

	c.logger.Info("Chunk moved successfully",
		zap.String("namespace", namespace),
		zap.String("to_shard", toShard))

	return nil
}

// SplitChunk splits a chunk at the specified split point
func (c *Client) SplitChunk(ctx context.Context, namespace string, middle bson.M) error {
	command := bson.D{
		{Key: "split", Value: namespace},
		{Key: "middle", Value: middle},
	}

	err := c.runAdminCommand(ctx, command)
	if err != nil {
		return fmt.Errorf("failed to split chunk: %w", err)
	}

	c.logger.Info("Chunk split successfully",
		zap.String("namespace", namespace))

	return nil
}

// GetChunkInfo returns information about chunks for a collection
func (c *Client) GetChunkInfo(ctx context.Context, namespace string) ([]bson.M, error) {
	configDB := c.client.Database("config")
	chunksCollection := configDB.Collection("chunks")

	filter := bson.M{"ns": namespace}
	cursor, err := chunksCollection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query chunks: %w", err)
	}
	defer cursor.Close(ctx)

	var chunks []bson.M
	if err := cursor.All(ctx, &chunks); err != nil {
		return nil, fmt.Errorf("failed to decode chunks: %w", err)
	}

	return chunks, nil
}