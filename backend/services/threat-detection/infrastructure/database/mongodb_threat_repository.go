package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"

	"threat-detection/domain/entity"
	"threat-detection/domain/repository"
)

// MongoDBThreatRepository implements ThreatRepository using MongoDB
type MongoDBThreatRepository struct {
	client               *mongo.Client
	database             *mongo.Database
	threatsCollection    *mongo.Collection
	timeSeriesCollection *mongo.Collection
	logger               *zap.Logger
}

// NewMongoDBThreatRepository creates a new MongoDB threat repository
func NewMongoDBThreatRepository(client *mongo.Client, dbName string, logger *zap.Logger) *MongoDBThreatRepository {
	database := client.Database(dbName)
	
	return &MongoDBThreatRepository{
		client:               client,
		database:             database,
		threatsCollection:    database.Collection("threats"),
		timeSeriesCollection: database.Collection("threat_timeseries"),
		logger:               logger,
	}
}

// Create creates a new threat
func (r *MongoDBThreatRepository) Create(ctx context.Context, threat *entity.Threat) error {
	r.logger.Debug("Creating threat", zap.String("threat_id", threat.ID.String()))

	// Set timestamps
	now := time.Now()
	threat.CreatedAt = now
	threat.UpdatedAt = now

	// Insert threat document
	_, err := r.threatsCollection.InsertOne(ctx, threat)
	if err != nil {
		r.logger.Error("Failed to create threat", zap.Error(err))
		return fmt.Errorf("failed to create threat: %w", err)
	}

	// Insert time-series data point
	timeSeriesPoint := &repository.TimeSeriesPoint{
		Timestamp:  now,
		TenantID:   threat.TenantID,
		MetricType: "threat_created",
		Value:      1.0,
		Tags: map[string]string{
			"threat_type": string(threat.Type),
			"severity":    string(threat.Severity),
			"status":      string(threat.Status),
		},
		Metadata: map[string]interface{}{
			"threat_id":   threat.ID.String(),
			"risk_score":  threat.RiskScore,
			"confidence":  string(threat.Confidence),
		},
	}

	if err := r.InsertTimeSeriesPoint(ctx, timeSeriesPoint); err != nil {
		r.logger.Warn("Failed to insert time-series point", zap.Error(err))
		// Don't fail the main operation for time-series errors
	}

	r.logger.Debug("Threat created successfully", zap.String("threat_id", threat.ID.String()))
	return nil
}

// GetByID retrieves a threat by ID
func (r *MongoDBThreatRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.Threat, error) {
	r.logger.Debug("Getting threat by ID", zap.String("threat_id", id.String()))

	var threat entity.Threat
	filter := bson.M{"_id": id}

	err := r.threatsCollection.FindOne(ctx, filter).Decode(&threat)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("threat not found: %s", id.String())
		}
		r.logger.Error("Failed to get threat by ID", zap.Error(err))
		return nil, fmt.Errorf("failed to get threat: %w", err)
	}

	return &threat, nil
}

// GetByTenantAndID retrieves a threat by tenant and ID
func (r *MongoDBThreatRepository) GetByTenantAndID(ctx context.Context, tenantID, id uuid.UUID) (*entity.Threat, error) {
	r.logger.Debug("Getting threat by tenant and ID",
		zap.String("tenant_id", tenantID.String()),
		zap.String("threat_id", id.String()))

	var threat entity.Threat
	filter := bson.M{
		"_id":       id,
		"tenant_id": tenantID,
	}

	err := r.threatsCollection.FindOne(ctx, filter).Decode(&threat)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("threat not found: %s", id.String())
		}
		r.logger.Error("Failed to get threat by tenant and ID", zap.Error(err))
		return nil, fmt.Errorf("failed to get threat: %w", err)
	}

	return &threat, nil
}

// Update updates an existing threat
func (r *MongoDBThreatRepository) Update(ctx context.Context, threat *entity.Threat) error {
	r.logger.Debug("Updating threat", zap.String("threat_id", threat.ID.String()))

	// Update timestamp and version
	threat.UpdatedAt = time.Now()
	threat.Version++

	filter := bson.M{"_id": threat.ID}
	update := bson.M{"$set": threat}

	result, err := r.threatsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.Error("Failed to update threat", zap.Error(err))
		return fmt.Errorf("failed to update threat: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("threat not found: %s", threat.ID.String())
	}

	// Insert time-series data point for update
	timeSeriesPoint := &repository.TimeSeriesPoint{
		Timestamp:  time.Now(),
		TenantID:   threat.TenantID,
		MetricType: "threat_updated",
		Value:      1.0,
		Tags: map[string]string{
			"threat_type": string(threat.Type),
			"severity":    string(threat.Severity),
			"status":      string(threat.Status),
		},
		Metadata: map[string]interface{}{
			"threat_id":  threat.ID.String(),
			"risk_score": threat.RiskScore,
			"version":    threat.Version,
		},
	}

	if err := r.InsertTimeSeriesPoint(ctx, timeSeriesPoint); err != nil {
		r.logger.Warn("Failed to insert time-series point for update", zap.Error(err))
	}

	r.logger.Debug("Threat updated successfully", zap.String("threat_id", threat.ID.String()))
	return nil
}

// Delete permanently deletes a threat
func (r *MongoDBThreatRepository) Delete(ctx context.Context, id uuid.UUID) error {
	r.logger.Debug("Deleting threat", zap.String("threat_id", id.String()))

	filter := bson.M{"_id": id}
	result, err := r.threatsCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.Error("Failed to delete threat", zap.Error(err))
		return fmt.Errorf("failed to delete threat: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("threat not found: %s", id.String())
	}

	r.logger.Debug("Threat deleted successfully", zap.String("threat_id", id.String()))
	return nil
}

// SoftDelete marks a threat as deleted
func (r *MongoDBThreatRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	r.logger.Debug("Soft deleting threat", zap.String("threat_id", id.String()))

	filter := bson.M{"_id": id}
	update := bson.M{
		"$set": bson.M{
			"status":     entity.ThreatStatusResolved,
			"updated_at": time.Now(),
		},
		"$inc": bson.M{"version": 1},
	}

	result, err := r.threatsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.Error("Failed to soft delete threat", zap.Error(err))
		return fmt.Errorf("failed to soft delete threat: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("threat not found: %s", id.String())
	}

	r.logger.Debug("Threat soft deleted successfully", zap.String("threat_id", id.String()))
	return nil
}

// List retrieves threats with filtering, sorting, and pagination
func (r *MongoDBThreatRepository) List(ctx context.Context, filter repository.ThreatFilter, sort []repository.ThreatSort, page repository.PageRequest) (*repository.ThreatListResult, error) {
	r.logger.Debug("Listing threats with filter")

	// Build MongoDB filter
	mongoFilter := r.buildFilter(filter)

	// Build sort options
	sortOptions := r.buildSort(sort)

	// Calculate skip and limit
	skip := int64((page.Page - 1) * page.PageSize)
	limit := int64(page.PageSize)

	// Create find options
	findOptions := options.Find().
		SetSort(sortOptions).
		SetSkip(skip).
		SetLimit(limit)

	// Execute query
	cursor, err := r.threatsCollection.Find(ctx, mongoFilter, findOptions)
	if err != nil {
		r.logger.Error("Failed to find threats", zap.Error(err))
		return nil, fmt.Errorf("failed to find threats: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	var threats []*entity.Threat
	if err := cursor.All(ctx, &threats); err != nil {
		r.logger.Error("Failed to decode threats", zap.Error(err))
		return nil, fmt.Errorf("failed to decode threats: %w", err)
	}

	// Get total count
	totalCount, err := r.threatsCollection.CountDocuments(ctx, mongoFilter)
	if err != nil {
		r.logger.Error("Failed to count threats", zap.Error(err))
		return nil, fmt.Errorf("failed to count threats: %w", err)
	}

	// Calculate pagination
	totalPages := int((totalCount + int64(page.PageSize) - 1) / int64(page.PageSize))
	pagination := repository.PageResponse{
		Page:       page.Page,
		PageSize:   page.PageSize,
		TotalPages: totalPages,
		TotalItems: totalCount,
		HasNext:    page.Page < totalPages,
		HasPrev:    page.Page > 1,
	}

	return &repository.ThreatListResult{
		Threats:    threats,
		Pagination: pagination,
	}, nil
}

// Search performs text search on threats
func (r *MongoDBThreatRepository) Search(ctx context.Context, tenantID uuid.UUID, query string, filter repository.ThreatFilter, page repository.PageRequest) (*repository.ThreatListResult, error) {
	r.logger.Debug("Searching threats", 
		zap.String("tenant_id", tenantID.String()),
		zap.String("query", query))

	// Build MongoDB filter with text search
	mongoFilter := r.buildFilter(filter)
	mongoFilter["tenant_id"] = tenantID

	// Add text search if query is provided
	if query != "" {
		mongoFilter["$text"] = bson.M{"$search": query}
	}

	// Calculate skip and limit
	skip := int64((page.Page - 1) * page.PageSize)
	limit := int64(page.PageSize)

	// Create find options with text score sorting if searching
	findOptions := options.Find().
		SetSkip(skip).
		SetLimit(limit)

	if query != "" {
		findOptions.SetSort(bson.M{"score": bson.M{"$meta": "textScore"}})
		findOptions.SetProjection(bson.M{"score": bson.M{"$meta": "textScore"}})
	}

	// Execute query
	cursor, err := r.threatsCollection.Find(ctx, mongoFilter, findOptions)
	if err != nil {
		r.logger.Error("Failed to search threats", zap.Error(err))
		return nil, fmt.Errorf("failed to search threats: %w", err)
	}
	defer cursor.Close(ctx)

	// Decode results
	var threats []*entity.Threat
	if err := cursor.All(ctx, &threats); err != nil {
		r.logger.Error("Failed to decode search results", zap.Error(err))
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}

	// Get total count
	totalCount, err := r.threatsCollection.CountDocuments(ctx, mongoFilter)
	if err != nil {
		r.logger.Error("Failed to count search results", zap.Error(err))
		return nil, fmt.Errorf("failed to count search results: %w", err)
	}

	// Calculate pagination
	totalPages := int((totalCount + int64(page.PageSize) - 1) / int64(page.PageSize))
	pagination := repository.PageResponse{
		Page:       page.Page,
		PageSize:   page.PageSize,
		TotalPages: totalPages,
		TotalItems: totalCount,
		HasNext:    page.Page < totalPages,
		HasPrev:    page.Page > 1,
	}

	return &repository.ThreatListResult{
		Threats:    threats,
		Pagination: pagination,
	}, nil
}

// GetByTenant retrieves threats for a specific tenant
func (r *MongoDBThreatRepository) GetByTenant(ctx context.Context, tenantID uuid.UUID, filter repository.ThreatFilter, page repository.PageRequest) (*repository.ThreatListResult, error) {
	// Set tenant ID in filter
	filter.TenantID = &tenantID
	return r.List(ctx, filter, nil, page)
}

// GetActiveThreatsByTenant retrieves active threats for a tenant
func (r *MongoDBThreatRepository) GetActiveThreatsByTenant(ctx context.Context, tenantID uuid.UUID) ([]*entity.Threat, error) {
	r.logger.Debug("Getting active threats for tenant", zap.String("tenant_id", tenantID.String()))

	filter := bson.M{
		"tenant_id": tenantID,
		"status": bson.M{
			"$in": []entity.ThreatStatus{
				entity.ThreatStatusActive,
				entity.ThreatStatusInvestigating,
			},
		},
	}

	cursor, err := r.threatsCollection.Find(ctx, filter)
	if err != nil {
		r.logger.Error("Failed to get active threats", zap.Error(err))
		return nil, fmt.Errorf("failed to get active threats: %w", err)
	}
	defer cursor.Close(ctx)

	var threats []*entity.Threat
	if err := cursor.All(ctx, &threats); err != nil {
		r.logger.Error("Failed to decode active threats", zap.Error(err))
		return nil, fmt.Errorf("failed to decode active threats: %w", err)
	}

	return threats, nil
}

// GetThreatsByTimeRange retrieves threats within a time range
func (r *MongoDBThreatRepository) GetThreatsByTimeRange(ctx context.Context, tenantID uuid.UUID, start, end time.Time) ([]*entity.Threat, error) {
	r.logger.Debug("Getting threats by time range",
		zap.String("tenant_id", tenantID.String()),
		zap.Time("start", start),
		zap.Time("end", end))

	filter := bson.M{
		"tenant_id": tenantID,
		"detected_at": bson.M{
			"$gte": start,
			"$lte": end,
		},
	}

	cursor, err := r.threatsCollection.Find(ctx, filter)
	if err != nil {
		r.logger.Error("Failed to get threats by time range", zap.Error(err))
		return nil, fmt.Errorf("failed to get threats by time range: %w", err)
	}
	defer cursor.Close(ctx)

	var threats []*entity.Threat
	if err := cursor.All(ctx, &threats); err != nil {
		r.logger.Error("Failed to decode threats by time range", zap.Error(err))
		return nil, fmt.Errorf("failed to decode threats by time range: %w", err)
	}

	return threats, nil
}

// GetRecentThreats retrieves threats from the recent past
func (r *MongoDBThreatRepository) GetRecentThreats(ctx context.Context, tenantID uuid.UUID, duration time.Duration) ([]*entity.Threat, error) {
	start := time.Now().Add(-duration)
	return r.GetThreatsByTimeRange(ctx, tenantID, start, time.Now())
}

// StreamThreats streams threats created since a specific time
func (r *MongoDBThreatRepository) StreamThreats(ctx context.Context, tenantID uuid.UUID, since time.Time) (<-chan *entity.Threat, error) {
	r.logger.Debug("Streaming threats", 
		zap.String("tenant_id", tenantID.String()),
		zap.Time("since", since))

	// Create change stream
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{
			{"fullDocument.tenant_id", tenantID},
			{"operationType", "insert"},
			{"fullDocument.detected_at", bson.M{"$gte": since}},
		}}},
	}

	stream, err := r.threatsCollection.Watch(ctx, pipeline)
	if err != nil {
		r.logger.Error("Failed to create change stream", zap.Error(err))
		return nil, fmt.Errorf("failed to create change stream: %w", err)
	}

	threatChan := make(chan *entity.Threat, 100)

	go func() {
		defer close(threatChan)
		defer stream.Close(ctx)

		for stream.Next(ctx) {
			var changeEvent bson.M
			if err := stream.Decode(&changeEvent); err != nil {
				r.logger.Error("Failed to decode change event", zap.Error(err))
				continue
			}

			// Extract full document
			if fullDocument, ok := changeEvent["fullDocument"].(bson.M); ok {
				var threat entity.Threat
				bytes, _ := bson.Marshal(fullDocument)
				if err := bson.Unmarshal(bytes, &threat); err == nil {
					threatChan <- &threat
				}
			}
		}
	}()

	return threatChan, nil
}

// GetThreatsByIOC retrieves threats matching specific IOCs
func (r *MongoDBThreatRepository) GetThreatsByIOC(ctx context.Context, tenantID uuid.UUID, iocType entity.IOCType, value string) ([]*entity.Threat, error) {
	r.logger.Debug("Getting threats by IOC",
		zap.String("tenant_id", tenantID.String()),
		zap.String("ioc_type", string(iocType)),
		zap.String("value", value))

	filter := bson.M{
		"tenant_id": tenantID,
		"iocs": bson.M{
			"$elemMatch": bson.M{
				"type":  iocType,
				"value": value,
			},
		},
	}

	cursor, err := r.threatsCollection.Find(ctx, filter)
	if err != nil {
		r.logger.Error("Failed to get threats by IOC", zap.Error(err))
		return nil, fmt.Errorf("failed to get threats by IOC: %w", err)
	}
	defer cursor.Close(ctx)

	var threats []*entity.Threat
	if err := cursor.All(ctx, &threats); err != nil {
		r.logger.Error("Failed to decode threats by IOC", zap.Error(err))
		return nil, fmt.Errorf("failed to decode threats by IOC: %w", err)
	}

	return threats, nil
}

// GetAggregation returns aggregated threat statistics
func (r *MongoDBThreatRepository) GetAggregation(ctx context.Context, tenantID uuid.UUID, filter repository.ThreatFilter) (*repository.ThreatAggregation, error) {
	r.logger.Debug("Getting threat aggregation", zap.String("tenant_id", tenantID.String()))

	// Build aggregation pipeline
	pipeline := []bson.M{
		{"$match": r.buildFilter(filter)},
		{"$group": bson.M{
			"_id": nil,
			"total_threats": bson.M{"$sum": 1},
			"avg_risk_score": bson.M{"$avg": "$risk_score"},
			"max_risk_score": bson.M{"$max": "$risk_score"},
			"min_risk_score": bson.M{"$min": "$risk_score"},
			"threats_by_type": bson.M{
				"$push": bson.M{
					"type": "$type",
					"count": 1,
				},
			},
			"threats_by_severity": bson.M{
				"$push": bson.M{
					"severity": "$severity",
					"count": 1,
				},
			},
			"threats_by_status": bson.M{
				"$push": bson.M{
					"status": "$status",
					"count": 1,
				},
			},
		}},
	}

	cursor, err := r.threatsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.Error("Failed to aggregate threats", zap.Error(err))
		return nil, fmt.Errorf("failed to aggregate threats: %w", err)
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		r.logger.Error("Failed to decode aggregation results", zap.Error(err))
		return nil, fmt.Errorf("failed to decode aggregation results: %w", err)
	}

	if len(results) == 0 {
		return &repository.ThreatAggregation{}, nil
	}

	result := results[0]
	
	aggregation := &repository.ThreatAggregation{
		TotalThreats:      getInt64(result, "total_threats"),
		AverageRiskScore:  getFloat64(result, "avg_risk_score"),
		MaxRiskScore:      getFloat64(result, "max_risk_score"),
		MinRiskScore:      getFloat64(result, "min_risk_score"),
		ThreatsByType:     make(map[entity.ThreatType]int64),
		ThreatsBySeverity: make(map[entity.ThreatSeverity]int64),
		ThreatsByStatus:   make(map[entity.ThreatStatus]int64),
	}

	// Process grouped data (simplified version)
	// In a full implementation, you'd properly aggregate the grouped data

	return aggregation, nil
}

// Time-series operations

// InsertTimeSeriesPoint inserts a time-series data point
func (r *MongoDBThreatRepository) InsertTimeSeriesPoint(ctx context.Context, point *repository.TimeSeriesPoint) error {
	_, err := r.timeSeriesCollection.InsertOne(ctx, point)
	if err != nil {
		r.logger.Error("Failed to insert time-series point", zap.Error(err))
		return fmt.Errorf("failed to insert time-series point: %w", err)
	}
	return nil
}

// GetTimeSeriesData retrieves time-series data
func (r *MongoDBThreatRepository) GetTimeSeriesData(ctx context.Context, tenantID uuid.UUID, metricType string, timeRange repository.TimeRange, granularity string) ([]*repository.TimeSeriesPoint, error) {
	r.logger.Debug("Getting time-series data",
		zap.String("tenant_id", tenantID.String()),
		zap.String("metric_type", metricType),
		zap.String("granularity", granularity))

	filter := bson.M{
		"tenant_id":   tenantID,
		"metric_type": metricType,
		"timestamp": bson.M{
			"$gte": timeRange.Start,
			"$lte": timeRange.End,
		},
	}

	cursor, err := r.timeSeriesCollection.Find(ctx, filter)
	if err != nil {
		r.logger.Error("Failed to get time-series data", zap.Error(err))
		return nil, fmt.Errorf("failed to get time-series data: %w", err)
	}
	defer cursor.Close(ctx)

	var points []*repository.TimeSeriesPoint
	if err := cursor.All(ctx, &points); err != nil {
		r.logger.Error("Failed to decode time-series data", zap.Error(err))
		return nil, fmt.Errorf("failed to decode time-series data: %w", err)
	}

	return points, nil
}

// Utility methods

// buildFilter builds MongoDB filter from ThreatFilter
func (r *MongoDBThreatRepository) buildFilter(filter repository.ThreatFilter) bson.M {
	mongoFilter := bson.M{}

	if filter.TenantID != nil {
		mongoFilter["tenant_id"] = *filter.TenantID
	}

	if len(filter.Types) > 0 {
		mongoFilter["type"] = bson.M{"$in": filter.Types}
	}

	if len(filter.Severities) > 0 {
		mongoFilter["severity"] = bson.M{"$in": filter.Severities}
	}

	if len(filter.Statuses) > 0 {
		mongoFilter["status"] = bson.M{"$in": filter.Statuses}
	}

	if filter.MinRiskScore != nil {
		if mongoFilter["risk_score"] == nil {
			mongoFilter["risk_score"] = bson.M{}
		}
		mongoFilter["risk_score"].(bson.M)["$gte"] = *filter.MinRiskScore
	}

	if filter.MaxRiskScore != nil {
		if mongoFilter["risk_score"] == nil {
			mongoFilter["risk_score"] = bson.M{}
		}
		mongoFilter["risk_score"].(bson.M)["$lte"] = *filter.MaxRiskScore
	}

	if filter.DetectedAfter != nil {
		if mongoFilter["detected_at"] == nil {
			mongoFilter["detected_at"] = bson.M{}
		}
		mongoFilter["detected_at"].(bson.M)["$gte"] = *filter.DetectedAfter
	}

	if filter.DetectedBefore != nil {
		if mongoFilter["detected_at"] == nil {
			mongoFilter["detected_at"] = bson.M{}
		}
		mongoFilter["detected_at"].(bson.M)["$lte"] = *filter.DetectedBefore
	}

	if len(filter.SourceIPs) > 0 {
		mongoFilter["source_info.source_ip"] = bson.M{"$in": filter.SourceIPs}
	}

	if len(filter.TargetIPs) > 0 {
		mongoFilter["target_info.target_ip"] = bson.M{"$in": filter.TargetIPs}
	}

	if len(filter.Tags) > 0 {
		mongoFilter["tags"] = bson.M{"$in": filter.Tags}
	}

	if filter.Search != nil && *filter.Search != "" {
		mongoFilter["$text"] = bson.M{"$search": *filter.Search}
	}

	return mongoFilter
}

// buildSort builds MongoDB sort options
func (r *MongoDBThreatRepository) buildSort(sort []repository.ThreatSort) bson.D {
	if len(sort) == 0 {
		return bson.D{{"detected_at", -1}} // Default sort by detection time descending
	}

	var sortDoc bson.D
	for _, s := range sort {
		direction := 1
		if s.Direction == "desc" {
			direction = -1
		}
		sortDoc = append(sortDoc, bson.E{Key: s.Field, Value: direction})
	}

	return sortDoc
}

// Helper functions for type conversion
func getInt64(doc bson.M, key string) int64 {
	if val, ok := doc[key]; ok {
		if intVal, ok := val.(int64); ok {
			return intVal
		}
		if intVal, ok := val.(int32); ok {
			return int64(intVal)
		}
	}
	return 0
}

func getFloat64(doc bson.M, key string) float64 {
	if val, ok := doc[key]; ok {
		if floatVal, ok := val.(float64); ok {
			return floatVal
		}
	}
	return 0.0
}

// Remaining repository methods would be implemented here...
// For brevity, showing the core CRUD and query operations

// CreateIndexes creates necessary indexes for the threat collection
func (r *MongoDBThreatRepository) CreateIndexes(ctx context.Context) error {
	r.logger.Info("Creating MongoDB indexes for threats collection")

	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{{"tenant_id", 1}, {"detected_at", -1}},
		},
		{
			Keys: bson.D{{"tenant_id", 1}, {"type", 1}},
		},
		{
			Keys: bson.D{{"tenant_id", 1}, {"severity", 1}},
		},
		{
			Keys: bson.D{{"tenant_id", 1}, {"status", 1}},
		},
		{
			Keys: bson.D{{"tenant_id", 1}, {"risk_score", -1}},
		},
		{
			Keys: bson.D{{"source_info.source_ip", 1}},
		},
		{
			Keys: bson.D{{"target_info.target_ip", 1}},
		},
		{
			Keys: bson.D{{"iocs.type", 1}, {"iocs.value", 1}},
		},
		{
			Keys: bson.D{{"mitre_attack.tactic_ids", 1}},
		},
		{
			Keys: bson.D{{"mitre_attack.technique_ids", 1}},
		},
		{
			Keys: bson.D{{"tags", 1}},
		},
		{
			Keys: bson.D{
				{"name", "text"},
				{"description", "text"},
			},
		},
	}

	// Create indexes for threats collection
	_, err := r.threatsCollection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		r.logger.Error("Failed to create threat indexes", zap.Error(err))
		return fmt.Errorf("failed to create threat indexes: %w", err)
	}

	// Create indexes for time-series collection
	timeSeriesIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{"tenant_id", 1}, {"timestamp", -1}},
		},
		{
			Keys: bson.D{{"tenant_id", 1}, {"metric_type", 1}, {"timestamp", -1}},
		},
		{
			Keys: bson.D{{"timestamp", -1}},
			Options: options.Index().SetExpireAfterSeconds(90 * 24 * 60 * 60), // 90 days TTL
		},
	}

	_, err = r.timeSeriesCollection.Indexes().CreateMany(ctx, timeSeriesIndexes)
	if err != nil {
		r.logger.Error("Failed to create time-series indexes", zap.Error(err))
		return fmt.Errorf("failed to create time-series indexes: %w", err)
	}

	r.logger.Info("MongoDB indexes created successfully")
	return nil
}

// HealthCheck checks the health of the MongoDB connection
func (r *MongoDBThreatRepository) HealthCheck(ctx context.Context) error {
	return r.client.Ping(ctx, nil)
}

// Implementation of remaining methods would continue here following the same patterns...