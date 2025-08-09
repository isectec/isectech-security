package query

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DashboardQueryEngine handles real-time dashboard queries and caching
type DashboardQueryEngine struct {
	logger         *zap.Logger
	config         *DashboardConfig
	
	// Storage clients
	elasticClient  ElasticsearchQueryClient
	timescaleClient TimescaleQueryClient
	
	// Query cache
	queryCache     map[string]*CacheEntry
	cacheMutex     sync.RWMutex
	
	// Real-time subscriptions
	subscriptions  map[string]*RealtimeSubscription
	subsMutex      sync.RWMutex
	
	// Background processing
	ctx            context.Context
	cancel         context.CancelFunc
	refreshTicker  *time.Ticker
	
	// Statistics
	stats          *QueryEngineStats
	statsMutex     sync.RWMutex
}

// DashboardConfig defines dashboard query engine configuration
type DashboardConfig struct {
	// Cache settings
	CacheEnabled       bool          `json:"cache_enabled"`
	CacheTTL          time.Duration `json:"cache_ttl"`
	MaxCacheSize      int           `json:"max_cache_size"`
	
	// Real-time settings
	RealtimeEnabled   bool          `json:"realtime_enabled"`
	RefreshInterval   time.Duration `json:"refresh_interval"`
	MaxSubscriptions  int           `json:"max_subscriptions"`
	
	// Query settings
	DefaultTimeout    time.Duration `json:"default_timeout"`
	MaxQueryDuration  time.Duration `json:"max_query_duration"`
	QueryRateLimit    int           `json:"query_rate_limit"`
	
	// Performance settings
	MaxConcurrentQueries int         `json:"max_concurrent_queries"`
	QueryWorkers         int         `json:"query_workers"`
	MetricsEnabled       bool        `json:"metrics_enabled"`
}

// ElasticsearchQueryClient interface for Elasticsearch queries
type ElasticsearchQueryClient interface {
	Search(ctx context.Context, request *SearchRequest) (*SearchResponse, error)
	Aggregate(ctx context.Context, request *AggregationRequest) (*AggregationResponse, error)
	IsHealthy() bool
}

// TimescaleQueryClient interface for TimescaleDB queries
type TimescaleQueryClient interface {
	Query(ctx context.Context, query string, args ...interface{}) (*QueryResult, error)
	QueryMetrics(ctx context.Context, request *MetricsRequest) (*MetricsResponse, error)
	IsHealthy() bool
}

// CacheEntry represents a cached query result
type CacheEntry struct {
	Key        string      `json:"key"`
	Data       interface{} `json:"data"`
	Timestamp  time.Time   `json:"timestamp"`
	TTL        time.Duration `json:"ttl"`
	HitCount   int64       `json:"hit_count"`
	Size       int64       `json:"size"`
}

// RealtimeSubscription represents a real-time data subscription
type RealtimeSubscription struct {
	ID              string                 `json:"id"`
	DashboardID     string                 `json:"dashboard_id"`
	WidgetID        string                 `json:"widget_id"`
	Query           *DashboardQuery        `json:"query"`
	LastUpdate      time.Time              `json:"last_update"`
	UpdateChannel   chan *QueryResult      `json:"-"`
	ErrorChannel    chan error             `json:"-"`
	Context         context.Context        `json:"-"`
	Cancel          context.CancelFunc     `json:"-"`
	Filters         map[string]interface{} `json:"filters"`
	RefreshRate     time.Duration          `json:"refresh_rate"`
}

// DashboardQuery represents a dashboard query
type DashboardQuery struct {
	ID           string                 `json:"id"`
	DashboardID  string                 `json:"dashboard_id"`
	WidgetID     string                 `json:"widget_id"`
	Type         string                 `json:"type"` // timeseries, aggregate, search, metrics
	DataSource   string                 `json:"data_source"` // elasticsearch, timescale
	
	// Query parameters
	Query        string                 `json:"query"`
	Filters      map[string]interface{} `json:"filters"`
	TimeRange    *TimeRange             `json:"time_range"`
	Aggregations map[string]interface{} `json:"aggregations"`
	Grouping     []string               `json:"grouping"`
	Sorting      []SortField            `json:"sorting"`
	Limit        int                    `json:"limit"`
	
	// Cache settings
	CacheEnabled bool                   `json:"cache_enabled"`
	CacheTTL     time.Duration          `json:"cache_ttl"`
	
	// Real-time settings
	RealtimeEnabled bool               `json:"realtime_enabled"`
	RefreshRate     time.Duration      `json:"refresh_rate"`
	
	// Metadata
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// TimeRange defines time range for queries
type TimeRange struct {
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Relative  string    `json:"relative,omitempty"` // 1h, 1d, 7d, 30d
	Timezone  string    `json:"timezone"`
}

// SortField defines sorting parameters
type SortField struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // asc, desc
}

// QueryEngineStats tracks query engine statistics
type QueryEngineStats struct {
	TotalQueries      int64         `json:"total_queries"`
	CacheHits         int64         `json:"cache_hits"`
	CacheMisses       int64         `json:"cache_misses"`
	ActiveSubscriptions int64       `json:"active_subscriptions"`
	AverageQueryTime  time.Duration `json:"average_query_time"`
	ErrorCount        int64         `json:"error_count"`
	LastQueryTime     time.Time     `json:"last_query_time"`
}

// SearchRequest represents an Elasticsearch search request
type SearchRequest struct {
	Index    string                 `json:"index"`
	Query    map[string]interface{} `json:"query"`
	Size     int                    `json:"size"`
	From     int                    `json:"from"`
	Sort     []map[string]interface{} `json:"sort"`
	Aggs     map[string]interface{} `json:"aggs,omitempty"`
	Source   []string               `json:"_source,omitempty"`
}

// SearchResponse represents an Elasticsearch search response
type SearchResponse struct {
	Took         int                    `json:"took"`
	TimedOut     bool                   `json:"timed_out"`
	Hits         *SearchHits            `json:"hits"`
	Aggregations map[string]interface{} `json:"aggregations,omitempty"`
}

// SearchHits represents search results
type SearchHits struct {
	Total    *HitsTotal    `json:"total"`
	MaxScore float64       `json:"max_score"`
	Hits     []SearchHit   `json:"hits"`
}

// HitsTotal represents total hits
type HitsTotal struct {
	Value    int64  `json:"value"`
	Relation string `json:"relation"`
}

// SearchHit represents a single search result
type SearchHit struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Score  float64                `json:"_score"`
	Source map[string]interface{} `json:"_source"`
}

// AggregationRequest represents an aggregation request
type AggregationRequest struct {
	Index        string                 `json:"index"`
	Query        map[string]interface{} `json:"query"`
	Aggregations map[string]interface{} `json:"aggs"`
	Size         int                    `json:"size"`
}

// AggregationResponse represents an aggregation response
type AggregationResponse struct {
	Took         int                    `json:"took"`
	Aggregations map[string]interface{} `json:"aggregations"`
}

// MetricsRequest represents a metrics query request
type MetricsRequest struct {
	Table     string                 `json:"table"`
	Metrics   []string               `json:"metrics"`
	TimeRange *TimeRange             `json:"time_range"`
	Filters   map[string]interface{} `json:"filters"`
	GroupBy   []string               `json:"group_by"`
	Interval  string                 `json:"interval"`
}

// MetricsResponse represents a metrics query response
type MetricsResponse struct {
	Data      []map[string]interface{} `json:"data"`
	Metadata  *QueryMetadata           `json:"metadata"`
}

// QueryResult represents a generic query result
type QueryResult struct {
	Data      interface{}    `json:"data"`
	Metadata  *QueryMetadata `json:"metadata"`
	Error     string         `json:"error,omitempty"`
	Cached    bool           `json:"cached"`
	Duration  time.Duration  `json:"duration"`
}

// QueryMetadata contains query execution metadata
type QueryMetadata struct {
	QueryID       string        `json:"query_id"`
	ExecutionTime time.Duration `json:"execution_time"`
	RowCount      int64         `json:"row_count"`
	CacheHit      bool          `json:"cache_hit"`
	DataSource    string        `json:"data_source"`
	QueryType     string        `json:"query_type"`
	Timestamp     time.Time     `json:"timestamp"`
}

// NewDashboardQueryEngine creates a new dashboard query engine
func NewDashboardQueryEngine(logger *zap.Logger, config *DashboardConfig, elasticClient ElasticsearchQueryClient, timescaleClient TimescaleQueryClient) (*DashboardQueryEngine, error) {
	if config == nil {
		return nil, fmt.Errorf("dashboard configuration is required")
	}
	
	// Set defaults
	if err := setDashboardDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &DashboardQueryEngine{
		logger:          logger.With(zap.String("component", "dashboard-query-engine")),
		config:          config,
		elasticClient:   elasticClient,
		timescaleClient: timescaleClient,
		queryCache:      make(map[string]*CacheEntry),
		subscriptions:   make(map[string]*RealtimeSubscription),
		stats:           &QueryEngineStats{},
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// Start background processing
	if config.RealtimeEnabled {
		engine.refreshTicker = time.NewTicker(config.RefreshInterval)
		go engine.runRealtimeRefresh()
	}
	
	// Start cache cleanup
	if config.CacheEnabled {
		go engine.runCacheCleanup()
	}
	
	logger.Info("Dashboard query engine initialized",
		zap.Bool("cache_enabled", config.CacheEnabled),
		zap.Bool("realtime_enabled", config.RealtimeEnabled),
		zap.Duration("refresh_interval", config.RefreshInterval),
		zap.Int("max_subscriptions", config.MaxSubscriptions),
	)
	
	return engine, nil
}

// setDashboardDefaults sets configuration defaults
func setDashboardDefaults(config *DashboardConfig) error {
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.MaxCacheSize == 0 {
		config.MaxCacheSize = 1000
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 10 * time.Second
	}
	if config.MaxSubscriptions == 0 {
		config.MaxSubscriptions = 100
	}
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Second
	}
	if config.MaxQueryDuration == 0 {
		config.MaxQueryDuration = 2 * time.Minute
	}
	if config.QueryRateLimit == 0 {
		config.QueryRateLimit = 100 // queries per minute
	}
	if config.MaxConcurrentQueries == 0 {
		config.MaxConcurrentQueries = 10
	}
	if config.QueryWorkers == 0 {
		config.QueryWorkers = 5
	}
	
	return nil
}

// ExecuteQuery executes a dashboard query
func (dqe *DashboardQueryEngine) ExecuteQuery(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	start := time.Now()
	
	// Update statistics
	dqe.statsMutex.Lock()
	dqe.stats.TotalQueries++
	dqe.stats.LastQueryTime = time.Now()
	dqe.statsMutex.Unlock()
	
	// Check cache first
	if query.CacheEnabled && dqe.config.CacheEnabled {
		if cached := dqe.getCachedResult(query); cached != nil {
			dqe.statsMutex.Lock()
			dqe.stats.CacheHits++
			dqe.statsMutex.Unlock()
			
			cached.Cached = true
			cached.Duration = time.Since(start)
			return cached, nil
		}
		
		dqe.statsMutex.Lock()
		dqe.stats.CacheMisses++
		dqe.statsMutex.Unlock()
	}
	
	// Execute query based on data source
	var result *QueryResult
	var err error
	
	switch query.DataSource {
	case "elasticsearch":
		result, err = dqe.executeElasticsearchQuery(ctx, query)
	case "timescale":
		result, err = dqe.executeTimescaleQuery(ctx, query)
	default:
		err = fmt.Errorf("unsupported data source: %s", query.DataSource)
	}
	
	if err != nil {
		dqe.statsMutex.Lock()
		dqe.stats.ErrorCount++
		dqe.statsMutex.Unlock()
		
		return &QueryResult{
			Error:    err.Error(),
			Duration: time.Since(start),
			Metadata: &QueryMetadata{
				QueryID:       query.ID,
				ExecutionTime: time.Since(start),
				DataSource:    query.DataSource,
				QueryType:     query.Type,
				Timestamp:     time.Now(),
			},
		}, err
	}
	
	// Update execution time
	duration := time.Since(start)
	result.Duration = duration
	result.Metadata.ExecutionTime = duration
	
	// Update average query time
	dqe.statsMutex.Lock()
	dqe.stats.AverageQueryTime = (dqe.stats.AverageQueryTime + duration) / 2
	dqe.statsMutex.Unlock()
	
	// Cache result if caching is enabled
	if query.CacheEnabled && dqe.config.CacheEnabled && err == nil {
		dqe.cacheResult(query, result)
	}
	
	dqe.logger.Debug("Query executed",
		zap.String("query_id", query.ID),
		zap.String("data_source", query.DataSource),
		zap.Duration("duration", duration),
		zap.Bool("cached", result.Cached),
	)
	
	return result, nil
}

// executeElasticsearchQuery executes an Elasticsearch query
func (dqe *DashboardQueryEngine) executeElasticsearchQuery(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	if dqe.elasticClient == nil {
		return nil, fmt.Errorf("elasticsearch client not configured")
	}
	
	switch query.Type {
	case "search":
		return dqe.executeElasticsearchSearch(ctx, query)
	case "aggregate":
		return dqe.executeElasticsearchAggregation(ctx, query)
	case "timeseries":
		return dqe.executeElasticsearchTimeseries(ctx, query)
	default:
		return nil, fmt.Errorf("unsupported elasticsearch query type: %s", query.Type)
	}
}

// executeElasticsearchSearch executes an Elasticsearch search query
func (dqe *DashboardQueryEngine) executeElasticsearchSearch(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	// Build search request
	searchReq := &SearchRequest{
		Index: dqe.getIndexPattern(query),
		Size:  query.Limit,
		Query: dqe.buildElasticsearchQuery(query),
		Sort:  dqe.buildElasticsearchSort(query.Sorting),
	}
	
	// Execute search
	response, err := dqe.elasticClient.Search(ctx, searchReq)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch search failed: %w", err)
	}
	
	return &QueryResult{
		Data: response,
		Metadata: &QueryMetadata{
			QueryID:    query.ID,
			RowCount:   response.Hits.Total.Value,
			DataSource: "elasticsearch",
			QueryType:  "search",
			Timestamp:  time.Now(),
		},
	}, nil
}

// executeElasticsearchAggregation executes an Elasticsearch aggregation query
func (dqe *DashboardQueryEngine) executeElasticsearchAggregation(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	// Build aggregation request
	aggReq := &AggregationRequest{
		Index:        dqe.getIndexPattern(query),
		Query:        dqe.buildElasticsearchQuery(query),
		Aggregations: query.Aggregations,
		Size:         0, // No documents, only aggregations
	}
	
	// Execute aggregation
	response, err := dqe.elasticClient.Aggregate(ctx, aggReq)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch aggregation failed: %w", err)
	}
	
	return &QueryResult{
		Data: response,
		Metadata: &QueryMetadata{
			QueryID:    query.ID,
			DataSource: "elasticsearch",
			QueryType:  "aggregate",
			Timestamp:  time.Now(),
		},
	}, nil
}

// executeElasticsearchTimeseries executes an Elasticsearch timeseries query
func (dqe *DashboardQueryEngine) executeElasticsearchTimeseries(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	// Build timeseries aggregation
	timeseriesAgg := map[string]interface{}{
		"date_histogram": map[string]interface{}{
			"field":    "@timestamp",
			"interval": dqe.calculateTimeInterval(query.TimeRange),
			"format":   "yyyy-MM-dd HH:mm:ss",
		},
	}
	
	// Add sub-aggregations if specified
	if query.Aggregations != nil {
		timeseriesAgg["aggs"] = query.Aggregations
	}
	
	aggReq := &AggregationRequest{
		Index: dqe.getIndexPattern(query),
		Query: dqe.buildElasticsearchQuery(query),
		Aggregations: map[string]interface{}{
			"timeseries": timeseriesAgg,
		},
		Size: 0,
	}
	
	// Execute aggregation
	response, err := dqe.elasticClient.Aggregate(ctx, aggReq)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch timeseries failed: %w", err)
	}
	
	return &QueryResult{
		Data: response,
		Metadata: &QueryMetadata{
			QueryID:    query.ID,
			DataSource: "elasticsearch",
			QueryType:  "timeseries",
			Timestamp:  time.Now(),
		},
	}, nil
}

// executeTimescaleQuery executes a TimescaleDB query
func (dqe *DashboardQueryEngine) executeTimescaleQuery(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	if dqe.timescaleClient == nil {
		return nil, fmt.Errorf("timescale client not configured")
	}
	
	switch query.Type {
	case "metrics":
		return dqe.executeTimescaleMetrics(ctx, query)
	case "timeseries":
		return dqe.executeTimescaleTimeseries(ctx, query)
	default:
		return nil, fmt.Errorf("unsupported timescale query type: %s", query.Type)
	}
}

// executeTimescaleMetrics executes a TimescaleDB metrics query
func (dqe *DashboardQueryEngine) executeTimescaleMetrics(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	metricsReq := &MetricsRequest{
		Table:     dqe.getTimescaleTable(query),
		TimeRange: query.TimeRange,
		Filters:   query.Filters,
		GroupBy:   query.Grouping,
		Interval:  dqe.calculateTimeInterval(query.TimeRange),
	}
	
	// Parse metrics from query
	if metrics, ok := query.Aggregations["metrics"].([]interface{}); ok {
		for _, metric := range metrics {
			if metricStr, ok := metric.(string); ok {
				metricsReq.Metrics = append(metricsReq.Metrics, metricStr)
			}
		}
	}
	
	response, err := dqe.timescaleClient.QueryMetrics(ctx, metricsReq)
	if err != nil {
		return nil, fmt.Errorf("timescale metrics query failed: %w", err)
	}
	
	return &QueryResult{
		Data: response,
		Metadata: &QueryMetadata{
			QueryID:    query.ID,
			RowCount:   int64(len(response.Data)),
			DataSource: "timescale",
			QueryType:  "metrics",
			Timestamp:  time.Now(),
		},
	}, nil
}

// executeTimescaleTimeseries executes a TimescaleDB timeseries query
func (dqe *DashboardQueryEngine) executeTimescaleTimeseries(ctx context.Context, query *DashboardQuery) (*QueryResult, error) {
	// Build SQL query for timeseries
	sqlQuery := dqe.buildTimescaleTimeseriesQuery(query)
	
	result, err := dqe.timescaleClient.Query(ctx, sqlQuery)
	if err != nil {
		return nil, fmt.Errorf("timescale timeseries query failed: %w", err)
	}
	
	return &QueryResult{
		Data: result,
		Metadata: &QueryMetadata{
			QueryID:    query.ID,
			DataSource: "timescale",
			QueryType:  "timeseries",
			Timestamp:  time.Now(),
		},
	}, nil
}

// buildElasticsearchQuery builds an Elasticsearch query from dashboard query
func (dqe *DashboardQueryEngine) buildElasticsearchQuery(query *DashboardQuery) map[string]interface{} {
	esQuery := map[string]interface{}{
		"bool": map[string]interface{}{
			"must": []interface{}{},
		},
	}
	
	boolQuery := esQuery["bool"].(map[string]interface{})
	mustQueries := boolQuery["must"].([]interface{})
	
	// Add time range filter
	if query.TimeRange != nil {
		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"@timestamp": map[string]interface{}{
					"gte": query.TimeRange.From.Format(time.RFC3339),
					"lte": query.TimeRange.To.Format(time.RFC3339),
				},
			},
		}
		mustQueries = append(mustQueries, timeFilter)
	}
	
	// Add text query if provided
	if query.Query != "" {
		textQuery := map[string]interface{}{
			"query_string": map[string]interface{}{
				"query": query.Query,
			},
		}
		mustQueries = append(mustQueries, textQuery)
	}
	
	// Add filters
	for field, value := range query.Filters {
		filter := map[string]interface{}{
			"term": map[string]interface{}{
				field: value,
			},
		}
		mustQueries = append(mustQueries, filter)
	}
	
	boolQuery["must"] = mustQueries
	return esQuery
}

// buildElasticsearchSort builds Elasticsearch sort from sort fields
func (dqe *DashboardQueryEngine) buildElasticsearchSort(sortFields []SortField) []map[string]interface{} {
	if len(sortFields) == 0 {
		// Default sort by timestamp
		return []map[string]interface{}{
			{"@timestamp": map[string]interface{}{"order": "desc"}},
		}
	}
	
	sort := make([]map[string]interface{}, len(sortFields))
	for i, field := range sortFields {
		sort[i] = map[string]interface{}{
			field.Field: map[string]interface{}{
				"order": field.Direction,
			},
		}
	}
	
	return sort
}

// buildTimescaleTimeseriesQuery builds a TimescaleDB timeseries query
func (dqe *DashboardQueryEngine) buildTimescaleTimeseriesQuery(query *DashboardQuery) string {
	table := dqe.getTimescaleTable(query)
	interval := dqe.calculateTimeInterval(query.TimeRange)
	
	selectFields := []string{"time_bucket('" + interval + "', timestamp) as time_bucket"}
	
	// Add aggregation fields
	if metrics, ok := query.Aggregations["metrics"].([]interface{}); ok {
		for _, metric := range metrics {
			if metricStr, ok := metric.(string); ok {
				selectFields = append(selectFields, fmt.Sprintf("avg(%s) as avg_%s", metricStr, metricStr))
			}
		}
	}
	
	sqlQuery := fmt.Sprintf("SELECT %s FROM %s", strings.Join(selectFields, ", "), table)
	
	// Add WHERE clause
	whereClauses := []string{}
	
	if query.TimeRange != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("timestamp >= '%s' AND timestamp <= '%s'",
			query.TimeRange.From.Format(time.RFC3339),
			query.TimeRange.To.Format(time.RFC3339)))
	}
	
	// Add filter conditions
	for field, value := range query.Filters {
		whereClauses = append(whereClauses, fmt.Sprintf("%s = '%v'", field, value))
	}
	
	if len(whereClauses) > 0 {
		sqlQuery += " WHERE " + strings.Join(whereClauses, " AND ")
	}
	
	// Add GROUP BY
	groupByFields := []string{"time_bucket"}
	groupByFields = append(groupByFields, query.Grouping...)
	sqlQuery += " GROUP BY " + strings.Join(groupByFields, ", ")
	
	// Add ORDER BY
	sqlQuery += " ORDER BY time_bucket"
	
	return sqlQuery
}

// getCachedResult retrieves cached query result
func (dqe *DashboardQueryEngine) getCachedResult(query *DashboardQuery) *QueryResult {
	cacheKey := dqe.generateCacheKey(query)
	
	dqe.cacheMutex.RLock()
	entry, exists := dqe.queryCache[cacheKey]
	dqe.cacheMutex.RUnlock()
	
	if !exists {
		return nil
	}
	
	// Check if cache entry is still valid
	if time.Since(entry.Timestamp) > entry.TTL {
		dqe.cacheMutex.Lock()
		delete(dqe.queryCache, cacheKey)
		dqe.cacheMutex.Unlock()
		return nil
	}
	
	// Update hit count
	dqe.cacheMutex.Lock()
	entry.HitCount++
	dqe.cacheMutex.Unlock()
	
	if result, ok := entry.Data.(*QueryResult); ok {
		return result
	}
	
	return nil
}

// cacheResult caches a query result
func (dqe *DashboardQueryEngine) cacheResult(query *DashboardQuery, result *QueryResult) {
	cacheKey := dqe.generateCacheKey(query)
	ttl := query.CacheTTL
	if ttl == 0 {
		ttl = dqe.config.CacheTTL
	}
	
	// Calculate result size (approximate)
	data, _ := json.Marshal(result)
	size := int64(len(data))
	
	entry := &CacheEntry{
		Key:       cacheKey,
		Data:      result,
		Timestamp: time.Now(),
		TTL:       ttl,
		HitCount:  0,
		Size:      size,
	}
	
	dqe.cacheMutex.Lock()
	defer dqe.cacheMutex.Unlock()
	
	// Check if we need to evict entries
	if len(dqe.queryCache) >= dqe.config.MaxCacheSize {
		dqe.evictLRUEntry()
	}
	
	dqe.queryCache[cacheKey] = entry
}

// generateCacheKey generates a cache key for a query
func (dqe *DashboardQueryEngine) generateCacheKey(query *DashboardQuery) string {
	data, _ := json.Marshal(map[string]interface{}{
		"type":        query.Type,
		"data_source": query.DataSource,
		"query":       query.Query,
		"filters":     query.Filters,
		"time_range":  query.TimeRange,
		"aggregations": query.Aggregations,
		"grouping":    query.Grouping,
		"sorting":     query.Sorting,
		"limit":       query.Limit,
	})
	
	return fmt.Sprintf("query_%x", data)
}

// evictLRUEntry evicts the least recently used cache entry
func (dqe *DashboardQueryEngine) evictLRUEntry() {
	var oldestKey string
	var oldestTime time.Time
	
	for key, entry := range dqe.queryCache {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}
	
	if oldestKey != "" {
		delete(dqe.queryCache, oldestKey)
	}
}

// getIndexPattern returns the Elasticsearch index pattern for a query
func (dqe *DashboardQueryEngine) getIndexPattern(query *DashboardQuery) string {
	// Default to security events index pattern
	pattern := "security-events-*"
	
	// Override based on query filters or configuration
	if indexHint, exists := query.Filters["_index"]; exists {
		if indexStr, ok := indexHint.(string); ok {
			pattern = indexStr
		}
	}
	
	return pattern
}

// getTimescaleTable returns the TimescaleDB table for a query
func (dqe *DashboardQueryEngine) getTimescaleTable(query *DashboardQuery) string {
	// Default to metrics table
	table := "security_metrics"
	
	// Override based on query filters or configuration
	if tableHint, exists := query.Filters["_table"]; exists {
		if tableStr, ok := tableHint.(string); ok {
			table = tableStr
		}
	}
	
	return table
}

// calculateTimeInterval calculates appropriate time interval for timeseries queries
func (dqe *DashboardQueryEngine) calculateTimeInterval(timeRange *TimeRange) string {
	if timeRange == nil {
		return "1h"
	}
	
	duration := timeRange.To.Sub(timeRange.From)
	
	switch {
	case duration <= time.Hour:
		return "1m"
	case duration <= 24*time.Hour:
		return "5m"
	case duration <= 7*24*time.Hour:
		return "1h"
	case duration <= 30*24*time.Hour:
		return "6h"
	default:
		return "1d"
	}
}

// runRealtimeRefresh runs the real-time refresh process
func (dqe *DashboardQueryEngine) runRealtimeRefresh() {
	for {
		select {
		case <-dqe.ctx.Done():
			return
		case <-dqe.refreshTicker.C:
			dqe.refreshSubscriptions()
		}
	}
}

// refreshSubscriptions refreshes all active subscriptions
func (dqe *DashboardQueryEngine) refreshSubscriptions() {
	dqe.subsMutex.RLock()
	subscriptions := make([]*RealtimeSubscription, 0, len(dqe.subscriptions))
	for _, sub := range dqe.subscriptions {
		subscriptions = append(subscriptions, sub)
	}
	dqe.subsMutex.RUnlock()
	
	for _, sub := range subscriptions {
		if time.Since(sub.LastUpdate) >= sub.RefreshRate {
			go dqe.refreshSubscription(sub)
		}
	}
}

// refreshSubscription refreshes a single subscription
func (dqe *DashboardQueryEngine) refreshSubscription(sub *RealtimeSubscription) {
	ctx, cancel := context.WithTimeout(sub.Context, dqe.config.DefaultTimeout)
	defer cancel()
	
	result, err := dqe.ExecuteQuery(ctx, sub.Query)
	if err != nil {
		select {
		case sub.ErrorChannel <- err:
		case <-ctx.Done():
		}
		return
	}
	
	// Update last update time
	dqe.subsMutex.Lock()
	sub.LastUpdate = time.Now()
	dqe.subsMutex.Unlock()
	
	// Send result to channel
	select {
	case sub.UpdateChannel <- result:
	case <-ctx.Done():
	}
}

// runCacheCleanup runs the cache cleanup process
func (dqe *DashboardQueryEngine) runCacheCleanup() {
	ticker := time.NewTicker(dqe.config.CacheTTL / 2)
	defer ticker.Stop()
	
	for {
		select {
		case <-dqe.ctx.Done():
			return
		case <-ticker.C:
			dqe.cleanupExpiredCache()
		}
	}
}

// cleanupExpiredCache removes expired cache entries
func (dqe *DashboardQueryEngine) cleanupExpiredCache() {
	dqe.cacheMutex.Lock()
	defer dqe.cacheMutex.Unlock()
	
	now := time.Now()
	for key, entry := range dqe.queryCache {
		if now.Sub(entry.Timestamp) > entry.TTL {
			delete(dqe.queryCache, key)
		}
	}
}

// GetStats returns query engine statistics
func (dqe *DashboardQueryEngine) GetStats() *QueryEngineStats {
	dqe.statsMutex.RLock()
	defer dqe.statsMutex.RUnlock()
	
	stats := *dqe.stats
	
	// Add cache and subscription stats
	dqe.cacheMutex.RLock()
	stats.TotalQueries = int64(len(dqe.queryCache))
	dqe.cacheMutex.RUnlock()
	
	dqe.subsMutex.RLock()
	stats.ActiveSubscriptions = int64(len(dqe.subscriptions))
	dqe.subsMutex.RUnlock()
	
	return &stats
}

// IsHealthy returns the health status
func (dqe *DashboardQueryEngine) IsHealthy() bool {
	// Check if storage backends are healthy
	if dqe.elasticClient != nil && !dqe.elasticClient.IsHealthy() {
		return false
	}
	if dqe.timescaleClient != nil && !dqe.timescaleClient.IsHealthy() {
		return false
	}
	
	return true
}

// Close closes the dashboard query engine
func (dqe *DashboardQueryEngine) Close() error {
	if dqe.cancel != nil {
		dqe.cancel()
	}
	
	if dqe.refreshTicker != nil {
		dqe.refreshTicker.Stop()
	}
	
	// Close all subscriptions
	dqe.subsMutex.Lock()
	for _, sub := range dqe.subscriptions {
		if sub.Cancel != nil {
			sub.Cancel()
		}
		close(sub.UpdateChannel)
		close(sub.ErrorChannel)
	}
	dqe.subscriptions = make(map[string]*RealtimeSubscription)
	dqe.subsMutex.Unlock()
	
	dqe.logger.Info("Dashboard query engine closed")
	return nil
}