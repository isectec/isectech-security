package mongodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"go.uber.org/zap"
	"github.com/sony/gobreaker"

	"github.com/isectech/platform/shared/common"
)

// Client represents a MongoDB client for iSECTECH cybersecurity platform
type Client struct {
	config         *Config
	client         *mongo.Client
	database       *mongo.Database
	logger         *zap.Logger
	circuitBreaker *gobreaker.CircuitBreaker
	collections    map[string]*Collection
	closed         bool
}

// Collection represents a MongoDB collection with enhanced capabilities
type Collection struct {
	name           string
	collection     *mongo.Collection
	config         *Config
	isTimeSeries   bool
	tsConfig       TimeSeriesCollectionConfig
	logger         *zap.Logger
	circuitBreaker *gobreaker.CircuitBreaker
}

// TenantContext represents tenant information for multi-tenancy
type TenantContext struct {
	TenantID     string
	UserID       string
	Role         string
	Permissions  []string
	SecurityTags map[string]string
}

// QueryOptions represents options for MongoDB operations
type QueryOptions struct {
	Tenant          *TenantContext
	ReadPreference  *readpref.ReadPref
	ReadConcern     *readconcern.ReadConcern
	WriteConcern    *writeconcern.WriteConcern
	Timeout         time.Duration
	AllowDiskUse    bool
	MaxTime         time.Duration
	Hint            interface{}
	Sort            bson.D
	Limit           int64
	Skip            int64
}

// SecurityEvent represents a cybersecurity event document
type SecurityEvent struct {
	ID              string                 `bson:"_id,omitempty"`
	TenantID        string                 `bson:"tenant_id"`
	Timestamp       time.Time              `bson:"timestamp"`
	EventType       string                 `bson:"event_type"`
	Severity        string                 `bson:"severity"`
	Source          EventSource            `bson:"source"`
	Target          EventTarget            `bson:"target"`
	Description     string                 `bson:"description"`
	RawData         map[string]interface{} `bson:"raw_data"`
	NormalizedData  map[string]interface{} `bson:"normalized_data"`
	Indicators      []ThreatIndicator      `bson:"indicators"`
	MITREAttack     []string               `bson:"mitre_attack_techniques"`
	RiskScore       int                    `bson:"risk_score"`
	Classification  string                 `bson:"security_classification"`
	Tags            []string               `bson:"tags"`
	ProcessingInfo  ProcessingInfo         `bson:"processing_info"`
	Metadata        EventMetadata          `bson:"metadata"`
}

// EventSource represents the source of a security event
type EventSource struct {
	AssetID     string `bson:"asset_id,omitempty"`
	IP          string `bson:"ip,omitempty"`
	Hostname    string `bson:"hostname,omitempty"`
	Port        int    `bson:"port,omitempty"`
	ProcessName string `bson:"process_name,omitempty"`
	ProcessID   int    `bson:"process_id,omitempty"`
	UserID      string `bson:"user_id,omitempty"`
	UserName    string `bson:"username,omitempty"`
}

// EventTarget represents the target of a security event
type EventTarget struct {
	AssetID     string `bson:"asset_id,omitempty"`
	IP          string `bson:"ip,omitempty"`
	Hostname    string `bson:"hostname,omitempty"`
	Port        int    `bson:"port,omitempty"`
	Protocol    string `bson:"protocol,omitempty"`
	Service     string `bson:"service,omitempty"`
	Resource    string `bson:"resource,omitempty"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Type       string      `bson:"type"`
	Value      interface{} `bson:"value"`
	Confidence float64     `bson:"confidence"`
	Source     string      `bson:"source"`
	Context    string      `bson:"context,omitempty"`
}

// ProcessingInfo tracks event processing information
type ProcessingInfo struct {
	IngestedAt     time.Time `bson:"ingested_at"`
	ProcessedAt    time.Time `bson:"processed_at,omitempty"`
	EnrichedAt     time.Time `bson:"enriched_at,omitempty"`
	CorrelatedAt   time.Time `bson:"correlated_at,omitempty"`
	ProcessingTime int64     `bson:"processing_time_ms,omitempty"`
	Pipeline       string    `bson:"pipeline"`
	Version        string    `bson:"version"`
}

// EventMetadata contains metadata for time-series collections
type EventMetadata struct {
	TenantID     string `bson:"tenant_id"`
	EventType    string `bson:"event_type"`
	Severity     string `bson:"severity"`
	Source       string `bson:"source"`
	DataCenter   string `bson:"data_center,omitempty"`
	Environment  string `bson:"environment,omitempty"`
}

// PerformanceMetric represents system performance metrics
type PerformanceMetric struct {
	Timestamp   time.Time                  `bson:"timestamp"`
	ServiceName string                     `bson:"service_name"`
	Metrics     map[string]interface{}     `bson:"metrics"`
	Tags        map[string]string          `bson:"tags"`
	Metadata    PerformanceMetadata        `bson:"metadata"`
}

// PerformanceMetadata contains metadata for performance metrics
type PerformanceMetadata struct {
	Service     string `bson:"service"`
	Instance    string `bson:"instance"`
	Version     string `bson:"version"`
	Environment string `bson:"environment"`
}

// NewClient creates a new MongoDB client for iSECTECH
func NewClient(config *Config, logger *zap.Logger) (*Client, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Create MongoDB client options
	clientOpts := options.Client().ApplyURI(config.URI)
	
	// Configure connection pool
	clientOpts.SetMaxPoolSize(config.MaxPoolSize)
	clientOpts.SetMinPoolSize(config.MinPoolSize)
	clientOpts.SetMaxConnIdleTime(config.MaxConnIdleTime)
	
	// Configure timeouts
	clientOpts.SetConnectTimeout(config.ConnectTimeout)
	clientOpts.SetServerSelectionTimeout(config.ServerSelectionTimeout)
	clientOpts.SetSocketTimeout(config.SocketTimeout)
	
	// Configure replica set
	if config.ReplicaSet != "" {
		clientOpts.SetReplicaSet(config.ReplicaSet)
	}
	
	// Configure read preference
	readPref, err := parseReadPreference(config.ReadPreference)
	if err != nil {
		return nil, fmt.Errorf("invalid read preference: %w", err)
	}
	clientOpts.SetReadPreference(readPref)
	
	// Configure read concern
	readConcern, err := parseReadConcern(config.ReadConcern)
	if err != nil {
		return nil, fmt.Errorf("invalid read concern: %w", err)
	}
	clientOpts.SetReadConcern(readConcern)
	
	// Configure write concern
	writeConcern, err := parseWriteConcern(config.WriteConcern)
	if err != nil {
		return nil, fmt.Errorf("invalid write concern: %w", err)
	}
	clientOpts.SetWriteConcern(writeConcern)
	
	// Configure authentication
	if config.Security.Authentication.Username != "" {
		credential := options.Credential{
			AuthMechanism: config.Security.Authentication.Mechanism,
			AuthSource:    config.Security.Authentication.Source,
			Username:      config.Security.Authentication.Username,
			Password:      config.Security.Authentication.Password,
		}
		clientOpts.SetAuth(credential)
	}
	
	// Configure TLS
	if config.Security.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.Security.TLS.AllowInvalidCerts,
		}
		clientOpts.SetTLSConfig(tlsConfig)
	}

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectTimeout)
	defer cancel()

	mongoClient, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping to verify connection
	if err := mongoClient.Ping(ctx, readPref); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	// Get database
	database := mongoClient.Database(config.Database)

	client := &Client{
		config:      config,
		client:      mongoClient,
		database:    database,
		logger:      logger,
		collections: make(map[string]*Collection),
	}

	// Create circuit breaker
	client.circuitBreaker = gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "mongodb-client",
		MaxRequests: config.CircuitBreaker.MaxRequests,
		Interval:    config.CircuitBreaker.Interval,
		Timeout:     config.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= config.CircuitBreaker.FailureThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("Circuit breaker state changed",
				zap.String("name", name),
				zap.String("from", from.String()),
				zap.String("to", to.String()))
		},
	})

	// Initialize collections
	if err := client.initializeCollections(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize collections: %w", err)
	}

	logger.Info("MongoDB client initialized successfully",
		zap.String("database", config.Database),
		zap.String("replica_set", config.ReplicaSet),
		zap.Bool("sharding_enabled", config.Sharding.Enabled))

	return client, nil
}

// initializeCollections initializes all configured collections
func (c *Client) initializeCollections(ctx context.Context) error {
	// Create standard collections
	standardCollections := []string{
		"tenants",
		"assets",
		"threats",
		"threat_intelligence",
		"alerts",
		"compliance_data",
		"user_sessions",
	}

	for _, collName := range standardCollections {
		collection := &Collection{
			name:           collName,
			collection:     c.database.Collection(collName),
			config:         c.config,
			isTimeSeries:   false,
			logger:         c.logger.With(zap.String("collection", collName)),
			circuitBreaker: c.circuitBreaker,
		}
		c.collections[collName] = collection
	}

	// Create time-series collections
	for collName, tsConfig := range c.config.TimeSeries.Collections {
		if err := c.createTimeSeriesCollection(ctx, collName, tsConfig); err != nil {
			return fmt.Errorf("failed to create time-series collection %s: %w", collName, err)
		}
	}

	// Create indexes
	if err := c.createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	// Enable sharding if configured
	if c.config.Sharding.Enabled {
		if err := c.enableSharding(ctx); err != nil {
			return fmt.Errorf("failed to enable sharding: %w", err)
		}
	}

	return nil
}

// createTimeSeriesCollection creates a time-series collection
func (c *Client) createTimeSeriesCollection(ctx context.Context, name string, tsConfig TimeSeriesCollectionConfig) error {
	// Check if collection already exists
	collections, err := c.database.ListCollectionNames(ctx, bson.M{"name": name})
	if err != nil {
		return fmt.Errorf("failed to list collections: %w", err)
	}

	var exists bool
	for _, existing := range collections {
		if existing == name {
			exists = true
			break
		}
	}

	if !exists {
		// Create time-series collection options
		timeSeriesOpts := options.TimeSeries().
			SetTimeField(tsConfig.TimeField).
			SetGranularity(tsConfig.Granularity)

		if tsConfig.MetaField != "" {
			timeSeriesOpts.SetMetaField(tsConfig.MetaField)
		}

		// Create collection options
		createOpts := options.CreateCollection().
			SetTimeSeriesOptions(timeSeriesOpts)

		// Set expiration if configured
		if tsConfig.ExpireAfterSeconds > 0 {
			createOpts.SetExpireAfterSeconds(tsConfig.ExpireAfterSeconds)
		}

		// Create the collection
		if err := c.database.CreateCollection(ctx, name, createOpts); err != nil {
			return fmt.Errorf("failed to create time-series collection: %w", err)
		}

		c.logger.Info("Created time-series collection",
			zap.String("collection", name),
			zap.String("time_field", tsConfig.TimeField),
			zap.String("granularity", tsConfig.Granularity))
	}

	// Create collection wrapper
	collection := &Collection{
		name:           name,
		collection:     c.database.Collection(name),
		config:         c.config,
		isTimeSeries:   true,
		tsConfig:       tsConfig,
		logger:         c.logger.With(zap.String("collection", name)),
		circuitBreaker: c.circuitBreaker,
	}

	c.collections[name] = collection

	// Create indexes for time-series collection
	for _, indexConfig := range tsConfig.Indexes {
		if err := collection.createIndex(ctx, indexConfig); err != nil {
			return fmt.Errorf("failed to create index for collection %s: %w", name, err)
		}
	}

	return nil
}

// GetCollection returns a collection by name
func (c *Client) GetCollection(name string) (*Collection, error) {
	if c.closed {
		return nil, fmt.Errorf("client is closed")
	}

	collection, exists := c.collections[name]
	if !exists {
		return nil, fmt.Errorf("collection %s not found", name)
	}

	return collection, nil
}

// InsertSecurityEvent inserts a security event with tenant isolation
func (c *Client) InsertSecurityEvent(ctx context.Context, event *SecurityEvent, opts *QueryOptions) error {
	collection, err := c.GetCollection("security_events")
	if err != nil {
		return err
	}

	// Apply tenant context
	if opts != nil && opts.Tenant != nil {
		event.TenantID = opts.Tenant.TenantID
		event.Metadata.TenantID = opts.Tenant.TenantID
	}

	// Set processing information
	event.ProcessingInfo.IngestedAt = time.Now()
	event.ProcessingInfo.Pipeline = "ingestion"
	event.ProcessingInfo.Version = "1.0"

	return collection.InsertOne(ctx, event, opts)
}

// QuerySecurityEvents queries security events with tenant isolation
func (c *Client) QuerySecurityEvents(ctx context.Context, filter bson.M, opts *QueryOptions) (*mongo.Cursor, error) {
	collection, err := c.GetCollection("security_events")
	if err != nil {
		return nil, err
	}

	// Apply tenant filter
	if opts != nil && opts.Tenant != nil {
		filter["tenant_id"] = opts.Tenant.TenantID
		
		// Apply security classification filter based on user clearance
		if clearance, ok := opts.Tenant.SecurityTags["clearance"]; ok {
			filter["security_classification"] = bson.M{
				"$in": getAllowedClassifications(clearance),
			}
		}
	}

	return collection.Find(ctx, filter, opts)
}

// InsertPerformanceMetric inserts a performance metric
func (c *Client) InsertPerformanceMetric(ctx context.Context, metric *PerformanceMetric, opts *QueryOptions) error {
	collection, err := c.GetCollection("performance_metrics")
	if err != nil {
		return err
	}

	return collection.InsertOne(ctx, metric, opts)
}

// AggregateSecurityEvents performs aggregation on security events
func (c *Client) AggregateSecurityEvents(ctx context.Context, pipeline mongo.Pipeline, opts *QueryOptions) (*mongo.Cursor, error) {
	collection, err := c.GetCollection("security_events")
	if err != nil {
		return nil, err
	}

	// Add tenant isolation to pipeline
	if opts != nil && opts.Tenant != nil {
		matchStage := bson.D{
			{"$match", bson.M{"tenant_id": opts.Tenant.TenantID}},
		}
		pipeline = append(mongo.Pipeline{matchStage}, pipeline...)
	}

	return collection.Aggregate(ctx, pipeline, opts)
}

// Health checks the health of the MongoDB connection
func (c *Client) Health(ctx context.Context) bool {
	if c.closed {
		return false
	}

	err := c.client.Ping(ctx, nil)
	return err == nil
}

// Close closes the MongoDB connection
func (c *Client) Close(ctx context.Context) error {
	if c.closed {
		return nil
	}

	c.closed = true
	err := c.client.Disconnect(ctx)
	if err != nil {
		return fmt.Errorf("failed to disconnect MongoDB client: %w", err)
	}

	c.logger.Info("MongoDB client closed")
	return nil
}

// Helper functions

// parseReadPreference parses read preference string
func parseReadPreference(pref string) (*readpref.ReadPref, error) {
	switch pref {
	case "primary":
		return readpref.Primary(), nil
	case "primaryPreferred":
		return readpref.PrimaryPreferred(), nil
	case "secondary":
		return readpref.Secondary(), nil
	case "secondaryPreferred":
		return readpref.SecondaryPreferred(), nil
	case "nearest":
		return readpref.Nearest(), nil
	default:
		return readpref.PrimaryPreferred(), nil
	}
}

// parseReadConcern parses read concern string
func parseReadConcern(concern string) (*readconcern.ReadConcern, error) {
	switch concern {
	case "local":
		return readconcern.Local(), nil
	case "available":
		return readconcern.Available(), nil
	case "majority":
		return readconcern.Majority(), nil
	case "linearizable":
		return readconcern.Linearizable(), nil
	case "snapshot":
		return readconcern.Snapshot(), nil
	default:
		return readconcern.Majority(), nil
	}
}

// parseWriteConcern parses write concern configuration
func parseWriteConcern(config WriteConcernConfig) (*writeconcern.WriteConcern, error) {
	wc := writeconcern.New()
	
	if w, ok := config.W.(string); ok {
		wc = writeconcern.New(writeconcern.WTagSet(w))
	} else if w, ok := config.W.(int); ok {
		wc = writeconcern.New(writeconcern.W(w))
	}
	
	if config.WTimeout > 0 {
		wc = writeconcern.New(wc.GetW(), writeconcern.WTimeout(config.WTimeout))
	}
	
	if config.Journal {
		wc = writeconcern.New(wc.GetW(), writeconcern.J(config.Journal))
	}
	
	return wc, nil
}

// getAllowedClassifications returns allowed classifications based on clearance
func getAllowedClassifications(clearance string) []string {
	switch clearance {
	case "TOP_SECRET":
		return []string{"UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"}
	case "SECRET":
		return []string{"UNCLASSIFIED", "CONFIDENTIAL", "SECRET"}
	case "CONFIDENTIAL":
		return []string{"UNCLASSIFIED", "CONFIDENTIAL"}
	case "UNCLASSIFIED":
		return []string{"UNCLASSIFIED"}
	default:
		return []string{"UNCLASSIFIED"}
	}
}