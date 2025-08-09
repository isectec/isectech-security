package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// InsertOne inserts a single document with circuit breaker protection
func (c *Collection) InsertOne(ctx context.Context, document interface{}, opts *QueryOptions) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		insertOpts := options.Insert()
		
		// Apply timeout
		if opts != nil && opts.Timeout > 0 {
			ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
		}

		// Apply write concern
		if opts != nil && opts.WriteConcern != nil {
			insertOpts.SetWriteConcern(opts.WriteConcern)
		}

		result, err := c.collection.InsertOne(ctx, document, insertOpts)
		if err != nil {
			c.logger.Error("Failed to insert document",
				zap.Error(err),
				zap.String("collection", c.name))
			return nil, err
		}

		c.logger.Debug("Document inserted successfully",
			zap.String("collection", c.name),
			zap.Any("inserted_id", result.InsertedID))

		return result, nil
	})

	return err
}

// InsertMany inserts multiple documents with circuit breaker protection
func (c *Collection) InsertMany(ctx context.Context, documents []interface{}, opts *QueryOptions) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		insertOpts := options.InsertMany()
		
		// Apply timeout
		if opts != nil && opts.Timeout > 0 {
			ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
		}

		// Apply write concern
		if opts != nil && opts.WriteConcern != nil {
			insertOpts.SetWriteConcern(opts.WriteConcern)
		}

		// For large batches, insert in chunks to avoid timeouts
		batchSize := 1000
		if len(documents) <= batchSize {
			result, err := c.collection.InsertMany(ctx, documents, insertOpts)
			if err != nil {
				return nil, err
			}
			return result, nil
		}

		// Process in batches
		var allInsertedIDs []interface{}
		for i := 0; i < len(documents); i += batchSize {
			end := i + batchSize
			if end > len(documents) {
				end = len(documents)
			}

			batch := documents[i:end]
			result, err := c.collection.InsertMany(ctx, batch, insertOpts)
			if err != nil {
				c.logger.Error("Failed to insert batch",
					zap.Error(err),
					zap.String("collection", c.name),
					zap.Int("batch_start", i),
					zap.Int("batch_size", len(batch)))
				return nil, err
			}

			allInsertedIDs = append(allInsertedIDs, result.InsertedIDs...)
		}

		c.logger.Info("Batch insert completed",
			zap.String("collection", c.name),
			zap.Int("total_documents", len(documents)),
			zap.Int("inserted_count", len(allInsertedIDs)))

		return &mongo.InsertManyResult{InsertedIDs: allInsertedIDs}, nil
	})

	return err
}

// Find performs a find operation with circuit breaker protection
func (c *Collection) Find(ctx context.Context, filter interface{}, opts *QueryOptions) (*mongo.Cursor, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		findOpts := options.Find()

		// Apply query options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.ReadPreference != nil {
				findOpts.SetReadPreference(opts.ReadPreference)
			}

			if opts.ReadConcern != nil {
				findOpts.SetReadConcern(opts.ReadConcern)
			}

			if opts.MaxTime > 0 {
				findOpts.SetMaxTime(opts.MaxTime)
			}

			if opts.AllowDiskUse {
				findOpts.SetAllowDiskUse(opts.AllowDiskUse)
			}

			if opts.Hint != nil {
				findOpts.SetHint(opts.Hint)
			}

			if opts.Sort != nil {
				findOpts.SetSort(opts.Sort)
			}

			if opts.Limit > 0 {
				findOpts.SetLimit(opts.Limit)
			}

			if opts.Skip > 0 {
				findOpts.SetSkip(opts.Skip)
			}
		}

		cursor, err := c.collection.Find(ctx, filter, findOpts)
		if err != nil {
			c.logger.Error("Failed to execute find query",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Any("filter", filter))
			return nil, err
		}

		return cursor, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*mongo.Cursor), nil
}

// FindOne performs a findOne operation with circuit breaker protection
func (c *Collection) FindOne(ctx context.Context, filter interface{}, opts *QueryOptions) *mongo.SingleResult {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		findOneOpts := options.FindOne()

		// Apply query options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.ReadPreference != nil {
				findOneOpts.SetReadPreference(opts.ReadPreference)
			}

			if opts.ReadConcern != nil {
				findOneOpts.SetReadConcern(opts.ReadConcern)
			}

			if opts.MaxTime > 0 {
				findOneOpts.SetMaxTime(opts.MaxTime)
			}

			if opts.AllowDiskUse {
				findOneOpts.SetAllowDiskUse(opts.AllowDiskUse)
			}

			if opts.Hint != nil {
				findOneOpts.SetHint(opts.Hint)
			}

			if opts.Sort != nil {
				findOneOpts.SetSort(opts.Sort)
			}

			if opts.Skip > 0 {
				findOneOpts.SetSkip(opts.Skip)
			}
		}

		result := c.collection.FindOne(ctx, filter, findOneOpts)
		return result, nil
	})

	if err != nil {
		// Return a result with the error
		return &mongo.SingleResult{}
	}

	return result.(*mongo.SingleResult)
}

// UpdateOne updates a single document with circuit breaker protection
func (c *Collection) UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts *QueryOptions) (*mongo.UpdateResult, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		updateOpts := options.Update()

		// Apply options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.WriteConcern != nil {
				updateOpts.SetWriteConcern(opts.WriteConcern)
			}

			if opts.Hint != nil {
				updateOpts.SetHint(opts.Hint)
			}
		}

		result, err := c.collection.UpdateOne(ctx, filter, update, updateOpts)
		if err != nil {
			c.logger.Error("Failed to update document",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Any("filter", filter))
			return nil, err
		}

		c.logger.Debug("Document updated successfully",
			zap.String("collection", c.name),
			zap.Int64("matched_count", result.MatchedCount),
			zap.Int64("modified_count", result.ModifiedCount))

		return result, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*mongo.UpdateResult), nil
}

// UpdateMany updates multiple documents with circuit breaker protection
func (c *Collection) UpdateMany(ctx context.Context, filter interface{}, update interface{}, opts *QueryOptions) (*mongo.UpdateResult, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		updateOpts := options.Update()

		// Apply options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.WriteConcern != nil {
				updateOpts.SetWriteConcern(opts.WriteConcern)
			}

			if opts.Hint != nil {
				updateOpts.SetHint(opts.Hint)
			}
		}

		result, err := c.collection.UpdateMany(ctx, filter, update, updateOpts)
		if err != nil {
			c.logger.Error("Failed to update documents",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Any("filter", filter))
			return nil, err
		}

		c.logger.Debug("Documents updated successfully",
			zap.String("collection", c.name),
			zap.Int64("matched_count", result.MatchedCount),
			zap.Int64("modified_count", result.ModifiedCount))

		return result, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*mongo.UpdateResult), nil
}

// DeleteOne deletes a single document with circuit breaker protection
func (c *Collection) DeleteOne(ctx context.Context, filter interface{}, opts *QueryOptions) (*mongo.DeleteResult, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		deleteOpts := options.Delete()

		// Apply options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.WriteConcern != nil {
				deleteOpts.SetWriteConcern(opts.WriteConcern)
			}

			if opts.Hint != nil {
				deleteOpts.SetHint(opts.Hint)
			}
		}

		result, err := c.collection.DeleteOne(ctx, filter, deleteOpts)
		if err != nil {
			c.logger.Error("Failed to delete document",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Any("filter", filter))
			return nil, err
		}

		c.logger.Debug("Document deleted successfully",
			zap.String("collection", c.name),
			zap.Int64("deleted_count", result.DeletedCount))

		return result, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*mongo.DeleteResult), nil
}

// DeleteMany deletes multiple documents with circuit breaker protection
func (c *Collection) DeleteMany(ctx context.Context, filter interface{}, opts *QueryOptions) (*mongo.DeleteResult, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		deleteOpts := options.Delete()

		// Apply options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.WriteConcern != nil {
				deleteOpts.SetWriteConcern(opts.WriteConcern)
			}

			if opts.Hint != nil {
				deleteOpts.SetHint(opts.Hint)
			}
		}

		result, err := c.collection.DeleteMany(ctx, filter, deleteOpts)
		if err != nil {
			c.logger.Error("Failed to delete documents",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Any("filter", filter))
			return nil, err
		}

		c.logger.Debug("Documents deleted successfully",
			zap.String("collection", c.name),
			zap.Int64("deleted_count", result.DeletedCount))

		return result, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*mongo.DeleteResult), nil
}

// Aggregate performs an aggregation operation with circuit breaker protection
func (c *Collection) Aggregate(ctx context.Context, pipeline interface{}, opts *QueryOptions) (*mongo.Cursor, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		aggregateOpts := options.Aggregate()

		// Apply options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.ReadPreference != nil {
				aggregateOpts.SetReadPreference(opts.ReadPreference)
			}

			if opts.ReadConcern != nil {
				aggregateOpts.SetReadConcern(opts.ReadConcern)
			}

			if opts.MaxTime > 0 {
				aggregateOpts.SetMaxTime(opts.MaxTime)
			}

			if opts.AllowDiskUse {
				aggregateOpts.SetAllowDiskUse(opts.AllowDiskUse)
			}

			if opts.Hint != nil {
				aggregateOpts.SetHint(opts.Hint)
			}
		}

		cursor, err := c.collection.Aggregate(ctx, pipeline, aggregateOpts)
		if err != nil {
			c.logger.Error("Failed to execute aggregation",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Any("pipeline", pipeline))
			return nil, err
		}

		return cursor, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*mongo.Cursor), nil
}

// CountDocuments counts documents matching the filter
func (c *Collection) CountDocuments(ctx context.Context, filter interface{}, opts *QueryOptions) (int64, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		countOpts := options.Count()

		// Apply options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.ReadPreference != nil {
				countOpts.SetReadPreference(opts.ReadPreference)
			}

			if opts.ReadConcern != nil {
				countOpts.SetReadConcern(opts.ReadConcern)
			}

			if opts.MaxTime > 0 {
				countOpts.SetMaxTime(opts.MaxTime)
			}

			if opts.Hint != nil {
				countOpts.SetHint(opts.Hint)
			}

			if opts.Limit > 0 {
				countOpts.SetLimit(opts.Limit)
			}

			if opts.Skip > 0 {
				countOpts.SetSkip(opts.Skip)
			}
		}

		count, err := c.collection.CountDocuments(ctx, filter, countOpts)
		if err != nil {
			c.logger.Error("Failed to count documents",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Any("filter", filter))
			return nil, err
		}

		return count, nil
	})

	if err != nil {
		return 0, err
	}

	return result.(int64), nil
}

// createIndex creates an index on the collection
func (c *Collection) createIndex(ctx context.Context, indexConfig IndexConfig) error {
	indexModel := mongo.IndexModel{
		Keys: indexConfig.Keys,
	}

	// Set index options
	indexOpts := options.Index()
	if indexConfig.Options.Name != "" {
		indexOpts.SetName(indexConfig.Options.Name)
	}
	if indexConfig.Options.Background {
		indexOpts.SetBackground(indexConfig.Options.Background)
	}
	if indexConfig.Options.Unique {
		indexOpts.SetUnique(indexConfig.Options.Unique)
	}
	if indexConfig.Options.Sparse {
		indexOpts.SetSparse(indexConfig.Options.Sparse)
	}
	if indexConfig.Options.TTL > 0 {
		indexOpts.SetExpireAfterSeconds(int32(indexConfig.Options.TTL.Seconds()))
	}

	indexModel.Options = indexOpts

	_, err := c.collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}

	c.logger.Info("Index created successfully",
		zap.String("collection", c.name),
		zap.String("index_name", indexConfig.Options.Name),
		zap.Any("keys", indexConfig.Keys))

	return nil
}

// CreateTextIndex creates a text index for full-text search
func (c *Collection) CreateTextIndex(ctx context.Context, fields []string, opts *options.IndexOptions) error {
	keys := bson.D{}
	for _, field := range fields {
		keys = append(keys, bson.E{Key: field, Value: "text"})
	}

	indexModel := mongo.IndexModel{
		Keys:    keys,
		Options: opts,
	}

	_, err := c.collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create text index: %w", err)
	}

	c.logger.Info("Text index created successfully",
		zap.String("collection", c.name),
		zap.Strings("fields", fields))

	return nil
}

// CreateGeoIndex creates a geospatial index
func (c *Collection) CreateGeoIndex(ctx context.Context, field string, indexType string, opts *options.IndexOptions) error {
	keys := bson.D{{Key: field, Value: indexType}} // "2d" or "2dsphere"

	indexModel := mongo.IndexModel{
		Keys:    keys,
		Options: opts,
	}

	_, err := c.collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create geo index: %w", err)
	}

	c.logger.Info("Geo index created successfully",
		zap.String("collection", c.name),
		zap.String("field", field),
		zap.String("type", indexType))

	return nil
}

// BulkWrite performs a bulk write operation
func (c *Collection) BulkWrite(ctx context.Context, models []mongo.WriteModel, opts *QueryOptions) (*mongo.BulkWriteResult, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		bulkOpts := options.BulkWrite()

		// Apply options
		if opts != nil {
			if opts.Timeout > 0 {
				ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			if opts.WriteConcern != nil {
				bulkOpts.SetWriteConcern(opts.WriteConcern)
			}
		}

		// Set ordered to false for better performance
		bulkOpts.SetOrdered(false)

		result, err := c.collection.BulkWrite(ctx, models, bulkOpts)
		if err != nil {
			c.logger.Error("Failed to execute bulk write",
				zap.Error(err),
				zap.String("collection", c.name),
				zap.Int("operations_count", len(models)))
			return nil, err
		}

		c.logger.Info("Bulk write completed successfully",
			zap.String("collection", c.name),
			zap.Int("operations_count", len(models)),
			zap.Int64("inserted_count", result.InsertedCount),
			zap.Int64("modified_count", result.ModifiedCount),
			zap.Int64("deleted_count", result.DeletedCount))

		return result, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*mongo.BulkWriteResult), nil
}

// GetStats returns collection statistics
func (c *Collection) GetStats(ctx context.Context) (bson.M, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		var stats bson.M
		
		err := c.collection.Database().RunCommand(ctx, bson.D{
			{Key: "collStats", Value: c.name},
		}).Decode(&stats)
		
		if err != nil {
			c.logger.Error("Failed to get collection stats",
				zap.Error(err),
				zap.String("collection", c.name))
			return nil, err
		}

		return stats, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(bson.M), nil
}

// EstimatedDocumentCount returns an estimated count of documents
func (c *Collection) EstimatedDocumentCount(ctx context.Context, opts *QueryOptions) (int64, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		estimateOpts := options.EstimatedDocumentCount()

		// Apply timeout
		if opts != nil && opts.Timeout > 0 {
			ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
		}

		count, err := c.collection.EstimatedDocumentCount(ctx, estimateOpts)
		if err != nil {
			c.logger.Error("Failed to estimate document count",
				zap.Error(err),
				zap.String("collection", c.name))
			return nil, err
		}

		return count, nil
	})

	if err != nil {
		return 0, err
	}

	return result.(int64), nil
}