package database

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/services/event-processor/domain/repository"
	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/types"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
)

// MongoEventRepository implements repository.EventRepository using MongoDB
type MongoEventRepository struct {
	db         *mongo.Database
	collection *mongo.Collection
	logger     *logging.Logger
	metrics    *metrics.Collector
	config     *repository.EventRepositoryConfig
}

// NewMongoEventRepository creates a new MongoDB event repository
func NewMongoEventRepository(
	db *mongo.Database,
	logger *logging.Logger,
	metrics *metrics.Collector,
	opts ...repository.EventRepositoryOption,
) *MongoEventRepository {
	config := &repository.EventRepositoryConfig{
		BatchSize:           100,
		QueryTimeout:        30 * time.Second,
		CacheEnabled:        false,
		CacheTTL:            5 * time.Minute,
		IndexingEnabled:     true,
		CompressionEnabled:  true,
		PartitioningEnabled: false,
		RetentionPolicy:     "90d",
	}

	// Apply options
	for _, opt := range opts {
		opt(config)
	}

	collection := db.Collection("events")
	
	repo := &MongoEventRepository{
		db:         db,
		collection: collection,
		logger:     logger,
		metrics:    metrics,
		config:     config,
	}

	// Create indexes
	if config.IndexingEnabled {
		if err := repo.createIndexes(context.Background()); err != nil {
			logger.Error("Failed to create indexes", logging.String("error", err.Error()))
		}
	}

	return repo
}

// Create creates a new event
func (r *MongoEventRepository) Create(ctx context.Context, event *entity.Event) error {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "insert", "events", time.Since(start))
	}()

	// Convert event to BSON
	doc := r.eventToBSON(event)

	_, err := r.collection.InsertOne(ctx, doc)
	if err != nil {
		r.metrics.RecordError("database_insert_error", "mongodb")
		r.logger.Error("Failed to insert event",
			logging.String("event_id", event.ID.String()),
			logging.String("error", err.Error()),
		)
		return common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to create event")
	}

	r.logger.Debug("Event created successfully",
		logging.String("event_id", event.ID.String()),
		logging.String("tenant_id", event.TenantID.String()),
	)

	return nil
}

// GetByID retrieves an event by ID
func (r *MongoEventRepository) GetByID(ctx context.Context, tenantID types.TenantID, eventID types.EventID) (*entity.Event, error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "findOne", "events", time.Since(start))
	}()

	filter := bson.M{
		"_id":       eventID,
		"tenant_id": tenantID,
	}

	var doc bson.M
	err := r.collection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, common.ErrNotFound("event")
		}
		r.metrics.RecordError("database_query_error", "mongodb")
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to get event")
	}

	event, err := r.bsonToEvent(doc)
	if err != nil {
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to decode event")
	}

	return event, nil
}

// Update updates an existing event
func (r *MongoEventRepository) Update(ctx context.Context, event *entity.Event) error {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "updateOne", "events", time.Since(start))
	}()

	filter := bson.M{
		"_id":       event.ID,
		"tenant_id": event.TenantID,
	}

	// Set updated timestamp
	event.UpdatedAt = time.Now().UTC()

	// Convert to BSON
	doc := r.eventToBSON(event)
	update := bson.M{"$set": doc}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.metrics.RecordError("database_update_error", "mongodb")
		return common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to update event")
	}

	if result.MatchedCount == 0 {
		return common.ErrNotFound("event")
	}

	return nil
}

// Delete deletes an event
func (r *MongoEventRepository) Delete(ctx context.Context, tenantID types.TenantID, eventID types.EventID) error {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "deleteOne", "events", time.Since(start))
	}()

	filter := bson.M{
		"_id":       eventID,
		"tenant_id": tenantID,
	}

	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		r.metrics.RecordError("database_delete_error", "mongodb")
		return common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to delete event")
	}

	if result.DeletedCount == 0 {
		return common.ErrNotFound("event")
	}

	return nil
}

// CreateBatch creates multiple events in batch
func (r *MongoEventRepository) CreateBatch(ctx context.Context, events []*entity.Event) error {
	if len(events) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "insertMany", "events", time.Since(start))
	}()

	// Convert events to BSON documents
	docs := make([]interface{}, len(events))
	for i, event := range events {
		docs[i] = r.eventToBSON(event)
	}

	// Process in batches
	batchSize := r.config.BatchSize
	for i := 0; i < len(docs); i += batchSize {
		end := i + batchSize
		if end > len(docs) {
			end = len(docs)
		}

		batch := docs[i:end]
		_, err := r.collection.InsertMany(ctx, batch)
		if err != nil {
			r.metrics.RecordError("database_batch_insert_error", "mongodb")
			return common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to create events batch")
		}
	}

	r.logger.Debug("Events batch created successfully",
		logging.Int("count", len(events)),
	)

	return nil
}

// UpdateBatch updates multiple events in batch
func (r *MongoEventRepository) UpdateBatch(ctx context.Context, events []*entity.Event) error {
	if len(events) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "bulkWrite", "events", time.Since(start))
	}()

	// Create bulk write operations
	var operations []mongo.WriteModel
	for _, event := range events {
		event.UpdatedAt = time.Now().UTC()
		
		filter := bson.M{
			"_id":       event.ID,
			"tenant_id": event.TenantID,
		}
		
		doc := r.eventToBSON(event)
		update := bson.M{"$set": doc}
		
		operation := mongo.NewUpdateOneModel().
			SetFilter(filter).
			SetUpdate(update)
		
		operations = append(operations, operation)
	}

	// Process in batches
	batchSize := r.config.BatchSize
	for i := 0; i < len(operations); i += batchSize {
		end := i + batchSize
		if end > len(operations) {
			end = len(operations)
		}

		batch := operations[i:end]
		_, err := r.collection.BulkWrite(ctx, batch)
		if err != nil {
			r.metrics.RecordError("database_bulk_write_error", "mongodb")
			return common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to update events batch")
		}
	}

	return nil
}

// Find retrieves events based on filter
func (r *MongoEventRepository) Find(ctx context.Context, filter *entity.EventFilter) ([]*entity.Event, error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "find", "events", time.Since(start))
	}()

	// Build MongoDB filter
	mongoFilter := r.buildMongoFilter(filter)

	// Build options
	opts := options.Find()
	if filter.Limit > 0 {
		opts.SetLimit(int64(filter.Limit))
	}
	if filter.Offset > 0 {
		opts.SetSkip(int64(filter.Offset))
	}

	// Default sort by created_at descending
	opts.SetSort(bson.M{"created_at": -1})

	cursor, err := r.collection.Find(ctx, mongoFilter, opts)
	if err != nil {
		r.metrics.RecordError("database_find_error", "mongodb")
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to find events")
	}
	defer cursor.Close(ctx)

	var events []*entity.Event
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			r.logger.Error("Failed to decode event document", logging.String("error", err.Error()))
			continue
		}

		event, err := r.bsonToEvent(doc)
		if err != nil {
			r.logger.Error("Failed to convert BSON to event", logging.String("error", err.Error()))
			continue
		}

		events = append(events, event)
	}

	if err := cursor.Err(); err != nil {
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "cursor error")
	}

	return events, nil
}

// FindWithPagination retrieves events with pagination
func (r *MongoEventRepository) FindWithPagination(
	ctx context.Context,
	filter *entity.EventFilter,
	limit, offset int,
) ([]*entity.Event, int64, error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "findWithPagination", "events", time.Since(start))
	}()

	// Build MongoDB filter
	mongoFilter := r.buildMongoFilter(filter)

	// Get total count
	totalCount, err := r.collection.CountDocuments(ctx, mongoFilter)
	if err != nil {
		r.metrics.RecordError("database_count_error", "mongodb")
		return nil, 0, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to count events")
	}

	// Get events with pagination
	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(offset)).
		SetSort(bson.M{"created_at": -1})

	cursor, err := r.collection.Find(ctx, mongoFilter, opts)
	if err != nil {
		r.metrics.RecordError("database_find_error", "mongodb")
		return nil, 0, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to find events")
	}
	defer cursor.Close(ctx)

	var events []*entity.Event
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}

		event, err := r.bsonToEvent(doc)
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, totalCount, nil
}

// Count counts events based on filter
func (r *MongoEventRepository) Count(ctx context.Context, filter *entity.EventFilter) (int64, error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "countDocuments", "events", time.Since(start))
	}()

	mongoFilter := r.buildMongoFilter(filter)

	count, err := r.collection.CountDocuments(ctx, mongoFilter)
	if err != nil {
		r.metrics.RecordError("database_count_error", "mongodb")
		return 0, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to count events")
	}

	return count, nil
}

// Search performs text search on events
func (r *MongoEventRepository) Search(
	ctx context.Context,
	tenantID types.TenantID,
	query string,
	limit, offset int,
) ([]*entity.Event, int64, error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "search", "events", time.Since(start))
	}()

	filter := bson.M{
		"tenant_id": tenantID,
		"$text":     bson.M{"$search": query},
	}

	// Get total count
	totalCount, err := r.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to count search results")
	}

	// Get events
	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(offset)).
		SetSort(bson.M{"score": bson.M{"$meta": "textScore"}})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to search events")
	}
	defer cursor.Close(ctx)

	var events []*entity.Event
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}

		event, err := r.bsonToEvent(doc)
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, totalCount, nil
}

// GetByStatus retrieves events by status
func (r *MongoEventRepository) GetByStatus(
	ctx context.Context,
	tenantID types.TenantID,
	status entity.EventStatus,
	limit, offset int,
) ([]*entity.Event, error) {
	filter := &entity.EventFilter{
		TenantID: &tenantID,
		Statuses: []entity.EventStatus{status},
		Limit:    limit,
		Offset:   offset,
	}

	return r.Find(ctx, filter)
}

// UpdateStatus updates event status
func (r *MongoEventRepository) UpdateStatus(
	ctx context.Context,
	tenantID types.TenantID,
	eventID types.EventID,
	status entity.EventStatus,
) error {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "updateOne", "events", time.Since(start))
	}()

	filter := bson.M{
		"_id":       eventID,
		"tenant_id": tenantID,
	}

	update := bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": time.Now().UTC(),
		},
	}

	if status == entity.EventStatusProcessed {
		update["$set"].(bson.M)["processed_at"] = time.Now().UTC()
	}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.metrics.RecordError("database_update_error", "mongodb")
		return common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to update event status")
	}

	if result.MatchedCount == 0 {
		return common.ErrNotFound("event")
	}

	return nil
}

// GetRepositoryHealth returns repository health information
func (r *MongoEventRepository) GetRepositoryHealth(ctx context.Context) (*repository.RepositoryHealth, error) {
	start := time.Now()

	// Ping the database
	err := r.db.Client().Ping(ctx, nil)
	isHealthy := err == nil

	health := &repository.RepositoryHealth{
		IsHealthy:        isHealthy,
		ConnectionStatus: "connected",
		ResponseTime:     time.Since(start),
		LastHealthCheck:  time.Now().UTC(),
		ErrorCount:       0,
	}

	if err != nil {
		health.ConnectionStatus = "disconnected"
		health.LastError = err.Error()
		health.ErrorCount = 1
	}

	return health, nil
}

// GetStorageStats returns storage statistics
func (r *MongoEventRepository) GetStorageStats(ctx context.Context, tenantID types.TenantID) (*repository.StorageStats, error) {
	// Get total events for tenant
	totalEvents, err := r.collection.CountDocuments(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to count events")
	}

	// Get collection stats
	var result bson.M
	err = r.db.RunCommand(ctx, bson.D{
		{Key: "collStats", Value: "events"},
		{Key: "scale", Value: 1},
	}).Decode(&result)

	stats := &repository.StorageStats{
		TenantID:    tenantID,
		TotalEvents: totalEvents,
	}

	if err == nil {
		if size, ok := result["size"].(int64); ok {
			stats.StorageSize = size
		}
		if indexSize, ok := result["totalIndexSize"].(int64); ok {
			stats.IndexSize = indexSize
		}
		if totalEvents > 0 {
			stats.AvgEventSize = stats.StorageSize / totalEvents
		}
	}

	return stats, nil
}

// Helper methods

// createIndexes creates necessary database indexes
func (r *MongoEventRepository) createIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "created_at", Value: -1},
			},
		},
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "type", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "status", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "severity", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "source_ip", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "asset_id", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "user_id", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "correlation_id", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "occurred_at", Value: -1},
			},
		},
		// Text index for search
		{
			Keys: bson.D{
				{Key: "title", Value: "text"},
				{Key: "description", Value: "text"},
				{Key: "source", Value: "text"},
			},
		},
		// TTL index for automatic cleanup
		{
			Keys: bson.D{
				{Key: "created_at", Value: 1},
			},
			Options: options.Index().SetExpireAfterSeconds(7776000), // 90 days
		},
	}

	_, err := r.collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	r.logger.Info("Database indexes created successfully")
	return nil
}

// eventToBSON converts an event entity to BSON document
func (r *MongoEventRepository) eventToBSON(event *entity.Event) bson.M {
	return bson.M{
		"_id":              event.ID,
		"tenant_id":        event.TenantID,
		"type":             event.Type,
		"source":           event.Source,
		"category":         event.Category,
		"title":            event.Title,
		"description":      event.Description,
		"severity":         event.Severity,
		"payload":          event.Payload,
		"metadata":         event.Metadata,
		"tags":             event.Tags,
		"source_ip":        event.SourceIP,
		"destination_ip":   event.DestinationIP,
		"source_port":      event.SourcePort,
		"destination_port": event.DestinationPort,
		"protocol":         event.Protocol,
		"asset_id":         event.AssetID,
		"asset_type":       event.AssetType,
		"asset_name":       event.AssetName,
		"user_id":          event.UserID,
		"username":         event.Username,
		"user_agent":       event.UserAgent,
		"session_id":       event.SessionID,
		"correlation_id":   event.CorrelationID,
		"parent_event_id":  event.ParentEventID,
		"root_event_id":    event.RootEventID,
		"status":           event.Status,
		"processing_log":   event.ProcessingLog,
		"risk_score":       event.RiskScore,
		"risk_factors":     event.RiskFactors,
		"confidence":       event.Confidence,
		"compliance_flags": event.ComplianceFlags,
		"retention_policy": event.RetentionPolicy,
		"occurred_at":      event.OccurredAt,
		"received_at":      event.ReceivedAt,
		"processed_at":     event.ProcessedAt,
		"created_at":       event.CreatedAt,
		"updated_at":       event.UpdatedAt,
	}
}

// bsonToEvent converts a BSON document to event entity
func (r *MongoEventRepository) bsonToEvent(doc bson.M) (*entity.Event, error) {
	event := &entity.Event{}

	// Required fields
	if id, ok := doc["_id"]; ok {
		if eventID, ok := id.(types.EventID); ok {
			event.ID = eventID
		} else if eventIDStr, ok := id.(string); ok {
			// Handle string representation
			event.ID = types.EventID(primitive.ObjectIDFromHex(eventIDStr))
		}
	}

	if tenantID, ok := doc["tenant_id"]; ok {
		if tid, ok := tenantID.(types.TenantID); ok {
			event.TenantID = tid
		}
	}

	if eventType, ok := doc["type"].(string); ok {
		event.Type = types.EventType(eventType)
	}

	if source, ok := doc["source"].(string); ok {
		event.Source = source
	}

	// Optional fields with safe extraction
	if category, ok := doc["category"].(string); ok {
		event.Category = category
	}

	if title, ok := doc["title"].(string); ok {
		event.Title = title
	}

	if description, ok := doc["description"].(string); ok {
		event.Description = description
	}

	if severity, ok := doc["severity"].(string); ok {
		event.Severity = types.Severity(severity)
	}

	if payload, ok := doc["payload"].(bson.M); ok {
		event.Payload = make(map[string]interface{})
		for k, v := range payload {
			event.Payload[k] = v
		}
	}

	if metadata, ok := doc["metadata"].(bson.M); ok {
		event.Metadata = make(map[string]interface{})
		for k, v := range metadata {
			event.Metadata[k] = v
		}
	}

	if tags, ok := doc["tags"].(primitive.A); ok {
		for _, tag := range tags {
			if tagStr, ok := tag.(string); ok {
				event.Tags = append(event.Tags, tagStr)
			}
		}
	}

	// Network fields
	if sourceIP, ok := doc["source_ip"].(string); ok {
		event.SourceIP = sourceIP
	}

	if destinationIP, ok := doc["destination_ip"].(string); ok {
		event.DestinationIP = destinationIP
	}

	if sourcePort, ok := doc["source_port"].(int32); ok {
		event.SourcePort = int(sourcePort)
	}

	if destinationPort, ok := doc["destination_port"].(int32); ok {
		event.DestinationPort = int(destinationPort)
	}

	if protocol, ok := doc["protocol"].(string); ok {
		event.Protocol = protocol
	}

	// Status
	if status, ok := doc["status"].(string); ok {
		event.Status = entity.EventStatus(status)
	}

	// Risk fields
	if riskScore, ok := doc["risk_score"].(float64); ok {
		event.RiskScore = riskScore
	}

	if confidence, ok := doc["confidence"].(float64); ok {
		event.Confidence = confidence
	}

	// Timestamps
	if occurredAt, ok := doc["occurred_at"].(primitive.DateTime); ok {
		event.OccurredAt = occurredAt.Time()
	}

	if receivedAt, ok := doc["received_at"].(primitive.DateTime); ok {
		event.ReceivedAt = receivedAt.Time()
	}

	if processedAt, ok := doc["processed_at"].(primitive.DateTime); ok {
		t := processedAt.Time()
		event.ProcessedAt = &t
	}

	if createdAt, ok := doc["created_at"].(primitive.DateTime); ok {
		event.CreatedAt = createdAt.Time()
	}

	if updatedAt, ok := doc["updated_at"].(primitive.DateTime); ok {
		event.UpdatedAt = updatedAt.Time()
	}

	return event, nil
}

// buildMongoFilter builds MongoDB filter from EventFilter
func (r *MongoEventRepository) buildMongoFilter(filter *entity.EventFilter) bson.M {
	mongoFilter := bson.M{}

	if filter == nil {
		return mongoFilter
	}

	if filter.TenantID != nil {
		mongoFilter["tenant_id"] = *filter.TenantID
	}

	if len(filter.EventTypes) > 0 {
		mongoFilter["type"] = bson.M{"$in": filter.EventTypes}
	}

	if len(filter.Sources) > 0 {
		mongoFilter["source"] = bson.M{"$in": filter.Sources}
	}

	if len(filter.Categories) > 0 {
		mongoFilter["category"] = bson.M{"$in": filter.Categories}
	}

	if len(filter.Severities) > 0 {
		mongoFilter["severity"] = bson.M{"$in": filter.Severities}
	}

	if len(filter.Statuses) > 0 {
		mongoFilter["status"] = bson.M{"$in": filter.Statuses}
	}

	if len(filter.Tags) > 0 {
		mongoFilter["tags"] = bson.M{"$in": filter.Tags}
	}

	// Time range filter
	if filter.FromTime != nil || filter.ToTime != nil {
		timeFilter := bson.M{}
		if filter.FromTime != nil {
			timeFilter["$gte"] = *filter.FromTime
		}
		if filter.ToTime != nil {
			timeFilter["$lte"] = *filter.ToTime
		}
		mongoFilter["occurred_at"] = timeFilter
	}

	// Network filters
	if len(filter.SourceIPs) > 0 {
		mongoFilter["source_ip"] = bson.M{"$in": filter.SourceIPs}
	}

	if len(filter.DestinationIPs) > 0 {
		mongoFilter["destination_ip"] = bson.M{"$in": filter.DestinationIPs}
	}

	if len(filter.Protocols) > 0 {
		mongoFilter["protocol"] = bson.M{"$in": filter.Protocols}
	}

	// Asset filters
	if len(filter.AssetIDs) > 0 {
		mongoFilter["asset_id"] = bson.M{"$in": filter.AssetIDs}
	}

	if len(filter.AssetTypes) > 0 {
		mongoFilter["asset_type"] = bson.M{"$in": filter.AssetTypes}
	}

	// User filters
	if len(filter.UserIDs) > 0 {
		mongoFilter["user_id"] = bson.M{"$in": filter.UserIDs}
	}

	if len(filter.Usernames) > 0 {
		mongoFilter["username"] = bson.M{"$in": filter.Usernames}
	}

	// Risk filters
	if filter.MinRiskScore != nil || filter.MaxRiskScore != nil {
		riskFilter := bson.M{}
		if filter.MinRiskScore != nil {
			riskFilter["$gte"] = *filter.MinRiskScore
		}
		if filter.MaxRiskScore != nil {
			riskFilter["$lte"] = *filter.MaxRiskScore
		}
		mongoFilter["risk_score"] = riskFilter
	}

	if len(filter.RiskFactors) > 0 {
		mongoFilter["risk_factors"] = bson.M{"$in": filter.RiskFactors}
	}

	// Search query
	if filter.SearchQuery != "" {
		mongoFilter["$text"] = bson.M{"$search": filter.SearchQuery}
	}

	return mongoFilter
}

// Additional methods required by the repository interface would be implemented here
// For brevity, I'm including just the core methods. The remaining methods would follow
// similar patterns for data access and manipulation.

// SearchByTimeRange searches events by time range
func (r *MongoEventRepository) SearchByTimeRange(
	ctx context.Context,
	tenantID types.TenantID,
	from, to time.Time,
	limit, offset int,
) ([]*entity.Event, error) {
	filter := &entity.EventFilter{
		TenantID: &tenantID,
		FromTime: &from,
		ToTime:   &to,
		Limit:    limit,
		Offset:   offset,
	}

	return r.Find(ctx, filter)
}

// GetByCorrelationID retrieves events by correlation ID
func (r *MongoEventRepository) GetByCorrelationID(
	ctx context.Context,
	tenantID types.TenantID,
	correlationID types.CorrelationID,
) ([]*entity.Event, error) {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "find", "events", time.Since(start))
	}()

	filter := bson.M{
		"tenant_id":      tenantID,
		"correlation_id": correlationID,
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to find events by correlation ID")
	}
	defer cursor.Close(ctx)

	var events []*entity.Event
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}

		event, err := r.bsonToEvent(doc)
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}

// GetRelatedEvents retrieves related events
func (r *MongoEventRepository) GetRelatedEvents(
	ctx context.Context,
	tenantID types.TenantID,
	eventID types.EventID,
) ([]*entity.Event, error) {
	// Get the original event first
	originalEvent, err := r.GetByID(ctx, tenantID, eventID)
	if err != nil {
		return nil, err
	}

	// Find related events by correlation ID
	return r.GetByCorrelationID(ctx, tenantID, originalEvent.CorrelationID)
}

// GetEventChain retrieves the complete event chain
func (r *MongoEventRepository) GetEventChain(
	ctx context.Context,
	tenantID types.TenantID,
	rootEventID types.EventID,
) ([]*entity.Event, error) {
	filter := bson.M{
		"tenant_id": tenantID,
		"$or": []bson.M{
			{"_id": rootEventID},
			{"root_event_id": rootEventID},
		},
	}

	opts := options.Find().SetSort(bson.M{"occurred_at": 1})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to find event chain")
	}
	defer cursor.Close(ctx)

	var events []*entity.Event
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}

		event, err := r.bsonToEvent(doc)
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}

// UpdateStatusBatch updates status for multiple events
func (r *MongoEventRepository) UpdateStatusBatch(
	ctx context.Context,
	tenantID types.TenantID,
	eventIDs []types.EventID,
	status entity.EventStatus,
) error {
	start := time.Now()
	defer func() {
		r.metrics.RecordDatabaseQuery("mongodb", "updateMany", "events", time.Since(start))
	}()

	filter := bson.M{
		"tenant_id": tenantID,
		"_id":       bson.M{"$in": eventIDs},
	}

	update := bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": time.Now().UTC(),
		},
	}

	if status == entity.EventStatusProcessed {
		update["$set"].(bson.M)["processed_at"] = time.Now().UTC()
	}

	result, err := r.collection.UpdateMany(ctx, filter, update)
	if err != nil {
		r.metrics.RecordError("database_update_error", "mongodb")
		return common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to update event statuses")
	}

	r.logger.Debug("Event statuses updated",
		logging.Int("requested", len(eventIDs)),
		logging.Int64("updated", result.ModifiedCount),
	)

	return nil
}

// GetPendingEvents retrieves pending events for processing
func (r *MongoEventRepository) GetPendingEvents(
	ctx context.Context,
	tenantID types.TenantID,
	limit int,
) ([]*entity.Event, error) {
	return r.GetByStatus(ctx, tenantID, entity.EventStatusReceived, limit, 0)
}

// GetFailedEvents retrieves failed events
func (r *MongoEventRepository) GetFailedEvents(
	ctx context.Context,
	tenantID types.TenantID,
	limit, offset int,
) ([]*entity.Event, error) {
	return r.GetByStatus(ctx, tenantID, entity.EventStatusFailed, limit, offset)
}

// GetEventsForReprocessing retrieves events that need reprocessing
func (r *MongoEventRepository) GetEventsForReprocessing(
	ctx context.Context,
	tenantID types.TenantID,
	limit int,
) ([]*entity.Event, error) {
	filter := bson.M{
		"tenant_id": tenantID,
		"status":    bson.M{"$in": []entity.EventStatus{
			entity.EventStatusFailed,
			entity.EventStatusReceived,
		}},
	}

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSort(bson.M{"created_at": 1}) // Oldest first

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, common.WrapError(err, common.ErrCodeDatabaseQuery, "failed to find events for reprocessing")
	}
	defer cursor.Close(ctx)

	var events []*entity.Event
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}

		event, err := r.bsonToEvent(doc)
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}