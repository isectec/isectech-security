package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// createIndexes creates all necessary indexes for iSECTECH collections
func (c *Client) createIndexes(ctx context.Context) error {
	c.logger.Info("Creating indexes for MongoDB collections")

	// Indexes for standard collections
	standardIndexes := map[string][]IndexConfig{
		"tenants": {
			{
				Keys:    bson.D{{Key: "domain", Value: 1}},
				Options: IndexOptions{Name: "domain_unique_idx", Unique: true},
			},
			{
				Keys:    bson.D{{Key: "status", Value: 1}},
				Options: IndexOptions{Name: "status_idx"},
			},
		},
		"assets": {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "name", Value: 1}},
				Options: IndexOptions{Name: "tenant_name_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "type", Value: 1}},
				Options: IndexOptions{Name: "tenant_type_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "ip_addresses", Value: 1}},
				Options: IndexOptions{Name: "tenant_ip_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "criticality", Value: 1}},
				Options: IndexOptions{Name: "tenant_criticality_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "security_classification", Value: 1}},
				Options: IndexOptions{Name: "tenant_classification_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "last_seen_at", Value: -1}},
				Options: IndexOptions{Name: "tenant_last_seen_idx"},
			},
		},
		"threats": {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "type", Value: 1}},
				Options: IndexOptions{Name: "tenant_type_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "severity", Value: 1}},
				Options: IndexOptions{Name: "tenant_severity_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "mitre_attack_ids", Value: 1}},
				Options: IndexOptions{Name: "tenant_mitre_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "first_seen_at", Value: -1}},
				Options: IndexOptions{Name: "tenant_first_seen_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "tags", Value: 1}},
				Options: IndexOptions{Name: "tenant_tags_idx"},
			},
		},
		"threat_intelligence": {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "indicators.type", Value: 1}},
				Options: IndexOptions{Name: "tenant_indicator_type_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "indicators.value", Value: 1}},
				Options: IndexOptions{Name: "tenant_indicator_value_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "confidence", Value: -1}},
				Options: IndexOptions{Name: "tenant_confidence_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "source", Value: 1}},
				Options: IndexOptions{Name: "tenant_source_idx"},
			},
		},
		"alerts": {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "severity", Value: 1}},
				Options: IndexOptions{Name: "tenant_severity_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "status", Value: 1}},
				Options: IndexOptions{Name: "tenant_status_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "category", Value: 1}},
				Options: IndexOptions{Name: "tenant_category_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "created_at", Value: -1}},
				Options: IndexOptions{Name: "tenant_created_at_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "assigned_to", Value: 1}},
				Options: IndexOptions{Name: "tenant_assigned_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "risk_score", Value: -1}},
				Options: IndexOptions{Name: "tenant_risk_score_idx"},
			},
		},
		"compliance_data": {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "framework", Value: 1}},
				Options: IndexOptions{Name: "tenant_framework_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "requirement_id", Value: 1}},
				Options: IndexOptions{Name: "tenant_requirement_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "status", Value: 1}},
				Options: IndexOptions{Name: "tenant_status_idx"},
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "assessed_at", Value: -1}},
				Options: IndexOptions{Name: "tenant_assessed_at_idx"},
			},
		},
		"user_sessions": {
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "user_id", Value: 1}},
				Options: IndexOptions{Name: "tenant_user_idx"},
			},
			{
				Keys:    bson.D{{Key: "session_id", Value: 1}},
				Options: IndexOptions{Name: "session_id_unique_idx", Unique: true},
			},
			{
				Keys:    bson.D{{Key: "expires_at", Value: 1}},
				Options: IndexOptions{Name: "expires_at_ttl_idx", TTL: 0}, // TTL index
			},
			{
				Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "created_at", Value: -1}},
				Options: IndexOptions{Name: "tenant_created_at_idx"},
			},
		},
	}

	// Create indexes for standard collections
	for collectionName, indexes := range standardIndexes {
		collection, err := c.GetCollection(collectionName)
		if err != nil {
			c.logger.Warn("Collection not found, skipping indexes",
				zap.String("collection", collectionName),
				zap.Error(err))
			continue
		}

		for _, indexConfig := range indexes {
			if err := collection.createIndex(ctx, indexConfig); err != nil {
				c.logger.Error("Failed to create index",
					zap.String("collection", collectionName),
					zap.String("index", indexConfig.Options.Name),
					zap.Error(err))
				// Continue with other indexes even if one fails
			}
		}
	}

	// Create text indexes for search functionality
	if err := c.createTextIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create text indexes: %w", err)
	}

	// Create geospatial indexes if needed
	if err := c.createGeoIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create geo indexes: %w", err)
	}

	c.logger.Info("All indexes created successfully")
	return nil
}

// createTextIndexes creates text indexes for full-text search
func (c *Client) createTextIndexes(ctx context.Context) error {
	textIndexConfigs := map[string][]string{
		"assets": {"name", "description", "manufacturer", "model"},
		"threats": {"name", "description", "indicators.context"},
		"alerts": {"title", "description", "resolution_notes"},
		"compliance_data": {"requirement_title", "requirement_description", "findings"},
	}

	for collectionName, fields := range textIndexConfigs {
		collection, err := c.GetCollection(collectionName)
		if err != nil {
			continue // Skip if collection doesn't exist
		}

		indexOpts := options.Index().
			SetName(fmt.Sprintf("%s_text_search_idx", collectionName)).
			SetBackground(true)

		if err := collection.CreateTextIndex(ctx, fields, indexOpts); err != nil {
			c.logger.Error("Failed to create text index",
				zap.String("collection", collectionName),
				zap.Strings("fields", fields),
				zap.Error(err))
		} else {
			c.logger.Info("Text index created",
				zap.String("collection", collectionName),
				zap.Strings("fields", fields))
		}
	}

	return nil
}

// createGeoIndexes creates geospatial indexes
func (c *Client) createGeoIndexes(ctx context.Context) error {
	geoIndexConfigs := map[string]map[string]string{
		"assets": {
			"location.coordinates": "2dsphere", // For GeoJSON coordinates
		},
		"security_events": {
			"source.location": "2dsphere", // For source location
			"target.location": "2dsphere", // For target location
		},
	}

	for collectionName, geoFields := range geoIndexConfigs {
		collection, err := c.GetCollection(collectionName)
		if err != nil {
			continue // Skip if collection doesn't exist
		}

		for field, indexType := range geoFields {
			indexOpts := options.Index().
				SetName(fmt.Sprintf("%s_%s_geo_idx", collectionName, field)).
				SetBackground(true)

			if err := collection.CreateGeoIndex(ctx, field, indexType, indexOpts); err != nil {
				c.logger.Error("Failed to create geo index",
					zap.String("collection", collectionName),
					zap.String("field", field),
					zap.String("type", indexType),
					zap.Error(err))
			} else {
				c.logger.Info("Geo index created",
					zap.String("collection", collectionName),
					zap.String("field", field),
					zap.String("type", indexType))
			}
		}
	}

	return nil
}

// CreateCompoundIndex creates a compound index with multiple fields
func (c *Client) CreateCompoundIndex(ctx context.Context, collectionName string, fields bson.D, opts *options.IndexOptions) error {
	collection, err := c.GetCollection(collectionName)
	if err != nil {
		return fmt.Errorf("collection %s not found: %w", collectionName, err)
	}

	indexModel := mongo.IndexModel{
		Keys:    fields,
		Options: opts,
	}

	_, err = collection.collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create compound index: %w", err)
	}

	c.logger.Info("Compound index created",
		zap.String("collection", collectionName),
		zap.Any("fields", fields))

	return nil
}

// CreatePartialIndex creates a partial index with filter expression
func (c *Client) CreatePartialIndex(ctx context.Context, collectionName string, keys bson.D, filter bson.D, indexName string) error {
	collection, err := c.GetCollection(collectionName)
	if err != nil {
		return fmt.Errorf("collection %s not found: %w", collectionName, err)
	}

	indexOpts := options.Index().
		SetName(indexName).
		SetPartialFilterExpression(filter).
		SetBackground(true)

	indexModel := mongo.IndexModel{
		Keys:    keys,
		Options: indexOpts,
	}

	_, err = collection.collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create partial index: %w", err)
	}

	c.logger.Info("Partial index created",
		zap.String("collection", collectionName),
		zap.String("index_name", indexName),
		zap.Any("filter", filter))

	return nil
}

// CreateSparseIndex creates a sparse index that only includes documents with the indexed field
func (c *Client) CreateSparseIndex(ctx context.Context, collectionName string, field string, indexName string) error {
	collection, err := c.GetCollection(collectionName)
	if err != nil {
		return fmt.Errorf("collection %s not found: %w", collectionName, err)
	}

	indexOpts := options.Index().
		SetName(indexName).
		SetSparse(true).
		SetBackground(true)

	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: field, Value: 1}},
		Options: indexOpts,
	}

	_, err = collection.collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create sparse index: %w", err)
	}

	c.logger.Info("Sparse index created",
		zap.String("collection", collectionName),
		zap.String("field", field),
		zap.String("index_name", indexName))

	return nil
}

// DropIndex drops an index by name
func (c *Client) DropIndex(ctx context.Context, collectionName string, indexName string) error {
	collection, err := c.GetCollection(collectionName)
	if err != nil {
		return fmt.Errorf("collection %s not found: %w", collectionName, err)
	}

	_, err = collection.collection.Indexes().DropOne(ctx, indexName)
	if err != nil {
		return fmt.Errorf("failed to drop index %s: %w", indexName, err)
	}

	c.logger.Info("Index dropped",
		zap.String("collection", collectionName),
		zap.String("index_name", indexName))

	return nil
}

// ListIndexes returns all indexes for a collection
func (c *Client) ListIndexes(ctx context.Context, collectionName string) ([]bson.M, error) {
	collection, err := c.GetCollection(collectionName)
	if err != nil {
		return nil, fmt.Errorf("collection %s not found: %w", collectionName, err)
	}

	cursor, err := collection.collection.Indexes().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list indexes: %w", err)
	}
	defer cursor.Close(ctx)

	var indexes []bson.M
	if err := cursor.All(ctx, &indexes); err != nil {
		return nil, fmt.Errorf("failed to decode indexes: %w", err)
	}

	return indexes, nil
}

// GetIndexStats returns index usage statistics
func (c *Client) GetIndexStats(ctx context.Context, collectionName string) (bson.M, error) {
	collection, err := c.GetCollection(collectionName)
	if err != nil {
		return nil, fmt.Errorf("collection %s not found: %w", collectionName, err)
	}

	pipeline := mongo.Pipeline{
		{{Key: "$indexStats", Value: bson.D{}}},
	}

	cursor, err := collection.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to get index stats: %w", err)
	}
	defer cursor.Close(ctx)

	var stats []bson.M
	if err := cursor.All(ctx, &stats); err != nil {
		return nil, fmt.Errorf("failed to decode index stats: %w", err)
	}

	result := bson.M{
		"collection": collectionName,
		"indexes":    stats,
	}

	return result, nil
}