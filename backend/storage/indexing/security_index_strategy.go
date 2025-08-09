package indexing

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SecurityIndexStrategy manages indexing strategies for security event querying
type SecurityIndexStrategy struct {
	logger          *zap.Logger
	config          *IndexingConfig
	
	// Index management
	indexManager    *IndexManager
	queryOptimizer  *QueryOptimizer
	perfAnalyzer    *PerformanceAnalyzer
	
	// Background optimization
	ctx             context.Context
	cancel          context.CancelFunc
	optimizeTicker  *time.Ticker
	
	// Statistics
	stats           *IndexingStats
	statsMutex      sync.RWMutex
}

// IndexingConfig defines indexing configuration for security events
type IndexingConfig struct {
	// Index creation settings
	IndexPrefix             string        `json:"index_prefix"`
	DatePattern             string        `json:"date_pattern"`
	ShardCount              int           `json:"shard_count"`
	ReplicaCount            int           `json:"replica_count"`
	RefreshInterval         string        `json:"refresh_interval"`
	
	// Indexing strategy
	IndexingStrategy        string        `json:"indexing_strategy"` // time_based, threat_based, hybrid
	ThreatLevelSharding     bool          `json:"threat_level_sharding"`
	TenantSharding          bool          `json:"tenant_sharding"`
	EventTypeSharding       bool          `json:"event_type_sharding"`
	
	// Index optimization
	OptimizationEnabled     bool          `json:"optimization_enabled"`
	OptimizationInterval    time.Duration `json:"optimization_interval"`
	ForcemergeEnabled       bool          `json:"forcemerge_enabled"`
	ForcemergeSegments      int           `json:"forcemerge_segments"`
	
	// Query optimization
	CacheEnabled            bool          `json:"cache_enabled"`
	CacheSize               string        `json:"cache_size"`
	CacheTTL                time.Duration `json:"cache_ttl"`
	PreferenceRouting       bool          `json:"preference_routing"`
	
	// Performance settings
	BulkIndexingEnabled     bool          `json:"bulk_indexing_enabled"`
	BulkSize                int           `json:"bulk_size"`
	BulkTimeout             time.Duration `json:"bulk_timeout"`
	MaxConcurrentShards     int           `json:"max_concurrent_shards"`
	
	// Monitoring settings
	PerformanceMonitoring   bool          `json:"performance_monitoring"`
	SlowQueryThreshold      time.Duration `json:"slow_query_threshold"`
	IndexingRateLimit       int           `json:"indexing_rate_limit"`
}

// IndexManager manages index creation and maintenance
type IndexManager struct {
	logger          *zap.Logger
	config          *IndexingConfig
	templates       map[string]*IndexTemplate
	indices         map[string]*IndexInfo
	mutex           sync.RWMutex
}

// QueryOptimizer optimizes queries for better performance
type QueryOptimizer struct {
	logger          *zap.Logger
	config          *IndexingConfig
	queryCache      *QueryCache
	queryStats      map[string]*QueryStats
	mutex           sync.RWMutex
}

// PerformanceAnalyzer analyzes and reports on indexing performance
type PerformanceAnalyzer struct {
	logger          *zap.Logger
	metrics         *IndexingMetrics
	thresholds      *PerformanceThresholds
	alerts          chan *PerformanceAlert
}

// IndexTemplate defines an index template for security events
type IndexTemplate struct {
	Name            string                 `json:"name"`
	IndexPattern    string                 `json:"index_pattern"`
	Settings        map[string]interface{} `json:"settings"`
	Mappings        map[string]interface{} `json:"mappings"`
	Aliases         map[string]interface{} `json:"aliases"`
	Priority        int                    `json:"priority"`
	Version         int                    `json:"version"`
}

// IndexInfo contains information about an index
type IndexInfo struct {
	Name            string                 `json:"name"`
	CreatedAt       time.Time              `json:"created_at"`
	DocumentCount   int64                  `json:"document_count"`
	StorageSize     int64                  `json:"storage_size"`
	ShardInfo       []ShardInfo            `json:"shard_info"`
	Settings        map[string]interface{} `json:"settings"`
	Health          string                 `json:"health"`
	LastOptimized   time.Time              `json:"last_optimized"`
}

// ShardInfo contains shard-level information
type ShardInfo struct {
	ID              int       `json:"id"`
	Primary         bool      `json:"primary"`
	State           string    `json:"state"`
	DocumentCount   int64     `json:"document_count"`
	StorageSize     int64     `json:"storage_size"`
	Node            string    `json:"node"`
}

// QueryCache manages query result caching
type QueryCache struct {
	cache           map[string]*CachedQuery
	mutex           sync.RWMutex
	maxSize         int
	ttl             time.Duration
	hitCount        int64
	missCount       int64
}

// CachedQuery represents a cached query result
type CachedQuery struct {
	Query           string      `json:"query"`
	Result          interface{} `json:"result"`
	CachedAt        time.Time   `json:"cached_at"`
	ExpiresAt       time.Time   `json:"expires_at"`
	HitCount        int64       `json:"hit_count"`
	Size            int64       `json:"size"`
}

// QueryStats tracks query performance statistics
type QueryStats struct {
	Query           string        `json:"query"`
	ExecutionCount  int64         `json:"execution_count"`
	TotalTime       time.Duration `json:"total_time"`
	AverageTime     time.Duration `json:"average_time"`
	MinTime         time.Duration `json:"min_time"`
	MaxTime         time.Duration `json:"max_time"`
	ErrorCount      int64         `json:"error_count"`
	LastExecuted    time.Time     `json:"last_executed"`
}

// IndexingStats tracks indexing performance statistics
type IndexingStats struct {
	IndexedDocuments    int64         `json:"indexed_documents"`
	IndexingErrors      int64         `json:"indexing_errors"`
	AverageIndexTime    time.Duration `json:"average_index_time"`
	IndexingThroughput  float64       `json:"indexing_throughput"`
	QueryCount          int64         `json:"query_count"`
	AverageQueryTime    time.Duration `json:"average_query_time"`
	CacheHitRate        float64       `json:"cache_hit_rate"`
	LastOptimization    time.Time     `json:"last_optimization"`
}

// IndexingMetrics contains detailed indexing metrics
type IndexingMetrics struct {
	IndicesCount        int           `json:"indices_count"`
	TotalDocuments      int64         `json:"total_documents"`
	TotalStorageSize    int64         `json:"total_storage_size"`
	IndexingRate        float64       `json:"indexing_rate"`
	QueryRate           float64       `json:"query_rate"`
	AverageLatency      time.Duration `json:"average_latency"`
	P95Latency          time.Duration `json:"p95_latency"`
	P99Latency          time.Duration `json:"p99_latency"`
	ErrorRate           float64       `json:"error_rate"`
}

// PerformanceThresholds defines performance alert thresholds
type PerformanceThresholds struct {
	MaxIndexingLatency  time.Duration `json:"max_indexing_latency"`
	MaxQueryLatency     time.Duration `json:"max_query_latency"`
	MinCacheHitRate     float64       `json:"min_cache_hit_rate"`
	MaxErrorRate        float64       `json:"max_error_rate"`
	MaxStorageGrowth    float64       `json:"max_storage_growth"`
}

// PerformanceAlert represents a performance alert
type PerformanceAlert struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Threshold   float64   `json:"threshold"`
	ActualValue float64   `json:"actual_value"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewSecurityIndexStrategy creates a new security index strategy
func NewSecurityIndexStrategy(logger *zap.Logger, config *IndexingConfig) (*SecurityIndexStrategy, error) {
	if config == nil {
		return nil, fmt.Errorf("indexing configuration is required")
	}
	
	// Set defaults
	if err := setIndexingDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	strategy := &SecurityIndexStrategy{
		logger: logger.With(zap.String("component", "security-index-strategy")),
		config: config,
		stats:  &IndexingStats{},
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize components
	strategy.indexManager = NewIndexManager(logger, config)
	strategy.queryOptimizer = NewQueryOptimizer(logger, config)
	strategy.perfAnalyzer = NewPerformanceAnalyzer(logger)
	
	// Start background optimization if enabled
	if config.OptimizationEnabled {
		strategy.optimizeTicker = time.NewTicker(config.OptimizationInterval)
		go strategy.runOptimization()
	}
	
	logger.Info("Security index strategy initialized",
		zap.String("indexing_strategy", config.IndexingStrategy),
		zap.Bool("optimization_enabled", config.OptimizationEnabled),
		zap.Bool("cache_enabled", config.CacheEnabled),
	)
	
	return strategy, nil
}

// setIndexingDefaults sets configuration defaults
func setIndexingDefaults(config *IndexingConfig) error {
	if config.IndexPrefix == "" {
		config.IndexPrefix = "isectech-security-events"
	}
	if config.DatePattern == "" {
		config.DatePattern = "2006.01.02"
	}
	if config.ShardCount == 0 {
		config.ShardCount = 2
	}
	if config.ReplicaCount == 0 {
		config.ReplicaCount = 1
	}
	if config.RefreshInterval == "" {
		config.RefreshInterval = "5s"
	}
	if config.IndexingStrategy == "" {
		config.IndexingStrategy = "time_based"
	}
	if config.OptimizationInterval == 0 {
		config.OptimizationInterval = 1 * time.Hour
	}
	if config.ForcemergeSegments == 0 {
		config.ForcemergeSegments = 1
	}
	if config.CacheSize == "" {
		config.CacheSize = "100mb"
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.BulkSize == 0 {
		config.BulkSize = 1000
	}
	if config.BulkTimeout == 0 {
		config.BulkTimeout = 30 * time.Second
	}
	if config.MaxConcurrentShards == 0 {
		config.MaxConcurrentShards = 5
	}
	if config.SlowQueryThreshold == 0 {
		config.SlowQueryThreshold = 1 * time.Second
	}
	if config.IndexingRateLimit == 0 {
		config.IndexingRateLimit = 10000 // docs per second
	}
	
	return nil
}

// CreateSecurityEventTemplate creates optimized index template for security events
func (sis *SecurityIndexStrategy) CreateSecurityEventTemplate() (*IndexTemplate, error) {
	template := &IndexTemplate{
		Name:         fmt.Sprintf("%s-template", sis.config.IndexPrefix),
		IndexPattern: fmt.Sprintf("%s-*", sis.config.IndexPrefix),
		Priority:     200,
		Version:      1,
	}
	
	// Configure settings based on strategy
	template.Settings = sis.buildIndexSettings()
	
	// Configure mappings optimized for security queries
	template.Mappings = sis.buildSecurityMappings()
	
	// Configure aliases for efficient querying
	template.Aliases = sis.buildAliases()
	
	return template, nil
}

// buildIndexSettings builds optimized index settings
func (sis *SecurityIndexStrategy) buildIndexSettings() map[string]interface{} {
	settings := map[string]interface{}{
		"number_of_shards":   sis.config.ShardCount,
		"number_of_replicas": sis.config.ReplicaCount,
		"refresh_interval":   sis.config.RefreshInterval,
		"codec":              "best_compression",
		"max_result_window":  50000,
		
		// Routing settings for tenant isolation
		"routing": map[string]interface{}{
			"allocation": map[string]interface{}{
				"total_shards_per_node": 3,
			},
		},
		
		// Search settings
		"search": map[string]interface{}{
			"idle": map[string]interface{}{
				"after": "30s",
			},
		},
		
		// Merge policy for better performance
		"merge": map[string]interface{}{
			"policy": map[string]interface{}{
				"max_merged_segment": "2gb",
				"segments_per_tier":  10,
			},
		},
	}
	
	// Add caching if enabled
	if sis.config.CacheEnabled {
		settings["requests"] = map[string]interface{}{
			"cache": map[string]interface{}{
				"enable": true,
			},
		}
		settings["queries"] = map[string]interface{}{
			"cache": map[string]interface{}{
				"enabled": true,
			},
		}
	}
	
	// Add sorting for better compression and query performance
	settings["sort"] = map[string]interface{}{
		"field": []string{"@timestamp", "risk_score", "tenant_id"},
		"order": []string{"desc", "desc", "asc"},
	}
	
	return settings
}

// buildSecurityMappings builds security-optimized field mappings
func (sis *SecurityIndexStrategy) buildSecurityMappings() map[string]interface{} {
	return map[string]interface{}{
		"dynamic": "strict",
		"properties": map[string]interface{}{
			// Time-based fields (critical for time-series queries)
			"@timestamp": map[string]interface{}{
				"type":  "date",
				"index": true,
			},
			"event_timestamp": map[string]interface{}{
				"type":  "date",
				"index": true,
			},
			
			// Core identification fields
			"event_id": map[string]interface{}{
				"type":  "keyword",
				"index": true,
			},
			"tenant_id": map[string]interface{}{
				"type":  "keyword",
				"index": true,
			},
			"event_type": map[string]interface{}{
				"type":  "keyword",
				"index": true,
			},
			"severity": map[string]interface{}{
				"type":  "keyword",
				"index": true,
			},
			
			// Risk and threat fields (frequently queried)
			"risk_score": map[string]interface{}{
				"type":  "double",
				"index": true,
			},
			"threat_level": map[string]interface{}{
				"type":  "keyword",
				"index": true,
			},
			"confidence_score": map[string]interface{}{
				"type":  "float",
				"index": true,
			},
			
			// Source information (heavily indexed for investigations)
			"source": map[string]interface{}{
				"properties": map[string]interface{}{
					"ip": map[string]interface{}{
						"type":  "ip",
						"index": true,
					},
					"port": map[string]interface{}{
						"type":  "integer",
						"index": true,
					},
					"hostname": map[string]interface{}{
						"type":  "keyword",
						"index": true,
						"fields": map[string]interface{}{
							"wildcard": map[string]interface{}{
								"type": "wildcard",
							},
						},
					},
					"domain": map[string]interface{}{
						"type":  "keyword",
						"index": true,
						"fields": map[string]interface{}{
							"wildcard": map[string]interface{}{
								"type": "wildcard",
							},
						},
					},
					"asset_id": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
				},
			},
			
			// Destination information
			"destination": map[string]interface{}{
				"properties": map[string]interface{}{
					"ip": map[string]interface{}{
						"type":  "ip",
						"index": true,
					},
					"port": map[string]interface{}{
						"type":  "integer",
						"index": true,
					},
					"hostname": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"domain": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
				},
			},
			
			// User information (critical for insider threat detection)
			"user": map[string]interface{}{
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"name": map[string]interface{}{
						"type":  "keyword",
						"index": true,
						"fields": map[string]interface{}{
							"text": map[string]interface{}{
								"type":     "text",
								"analyzer": "standard",
							},
						},
					},
					"domain": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"groups": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"roles": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
				},
			},
			
			// Process information (malware detection)
			"process": map[string]interface{}{
				"properties": map[string]interface{}{
					"pid": map[string]interface{}{
						"type":  "integer",
						"index": true,
					},
					"name": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"executable": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"command_line": map[string]interface{}{
						"type":  "text",
						"index": true,
						"fields": map[string]interface{}{
							"keyword": map[string]interface{}{
								"type":         "keyword",
								"ignore_above": 512,
							},
						},
					},
					"hash": map[string]interface{}{
						"properties": map[string]interface{}{
							"md5": map[string]interface{}{
								"type":  "keyword",
								"index": true,
							},
							"sha1": map[string]interface{}{
								"type":  "keyword",
								"index": true,
							},
							"sha256": map[string]interface{}{
								"type":  "keyword",
								"index": true,
							},
						},
					},
				},
			},
			
			// File information
			"file": map[string]interface{}{
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":  "keyword",
						"index": true,
						"fields": map[string]interface{}{
							"wildcard": map[string]interface{}{
								"type": "wildcard",
							},
						},
					},
					"name": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"extension": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"hash": map[string]interface{}{
						"properties": map[string]interface{}{
							"md5": map[string]interface{}{
								"type":  "keyword",
								"index": true,
							},
							"sha1": map[string]interface{}{
								"type":  "keyword",
								"index": true,
							},
							"sha256": map[string]interface{}{
								"type":  "keyword",
								"index": true,
							},
						},
					},
				},
			},
			
			// Network information
			"network": map[string]interface{}{
				"properties": map[string]interface{}{
					"protocol": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"transport": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"bytes": map[string]interface{}{
						"type":  "long",
						"index": true,
					},
					"packets": map[string]interface{}{
						"type":  "long",
						"index": true,
					},
				},
			},
			
			// Threat intelligence (IOC matching)
			"threat_intel": map[string]interface{}{
				"properties": map[string]interface{}{
					"reputation": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"categories": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"iocs": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"sources": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
				},
			},
			
			// Detection results
			"detection": map[string]interface{}{
				"properties": map[string]interface{}{
					"rule_name": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"rule_id": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"technique": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"tactic": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"mitre_attack": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
				},
			},
			
			// Geolocation data
			"geo": map[string]interface{}{
				"properties": map[string]interface{}{
					"country": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"city": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
					"location": map[string]interface{}{
						"type": "geo_point",
					},
					"asn": map[string]interface{}{
						"type":  "keyword",
						"index": true,
					},
				},
			},
			
			// Tags and labels for categorization
			"tags": map[string]interface{}{
				"type":  "keyword",
				"index": true,
			},
			"labels": map[string]interface{}{
				"type": "object",
				"dynamic": true,
			},
			
			// Raw event data (not indexed for storage efficiency)
			"raw_event": map[string]interface{}{
				"type":  "text",
				"index": false,
			},
		},
	}
}

// buildAliases builds index aliases for efficient querying
func (sis *SecurityIndexStrategy) buildAliases() map[string]interface{} {
	aliases := make(map[string]interface{})
	
	// Main alias for all security events
	aliases[fmt.Sprintf("%s-all", sis.config.IndexPrefix)] = map[string]interface{}{}
	
	// Threat level aliases
	aliases[fmt.Sprintf("%s-critical", sis.config.IndexPrefix)] = map[string]interface{}{
		"filter": map[string]interface{}{
			"term": map[string]interface{}{
				"threat_level": "critical",
			},
		},
	}
	
	aliases[fmt.Sprintf("%s-high", sis.config.IndexPrefix)] = map[string]interface{}{
		"filter": map[string]interface{}{
			"term": map[string]interface{}{
				"threat_level": "high",
			},
		},
	}
	
	// Event type aliases
	aliases[fmt.Sprintf("%s-authentication", sis.config.IndexPrefix)] = map[string]interface{}{
		"filter": map[string]interface{}{
			"term": map[string]interface{}{
				"event_type": "authentication",
			},
		},
	}
	
	aliases[fmt.Sprintf("%s-network", sis.config.IndexPrefix)] = map[string]interface{}{
		"filter": map[string]interface{}{
			"term": map[string]interface{}{
				"event_type": "network",
			},
		},
	}
	
	aliases[fmt.Sprintf("%s-malware", sis.config.IndexPrefix)] = map[string]interface{}{
		"filter": map[string]interface{}{
			"term": map[string]interface{}{
				"event_type": "malware",
			},
		},
	}
	
	// Time-based aliases (current day, week, month)
	now := time.Now()
	
	aliases[fmt.Sprintf("%s-today", sis.config.IndexPrefix)] = map[string]interface{}{
		"filter": map[string]interface{}{
			"range": map[string]interface{}{
				"@timestamp": map[string]interface{}{
					"gte": now.Format("2006-01-02"),
				},
			},
		},
	}
	
	aliases[fmt.Sprintf("%s-this-week", sis.config.IndexPrefix)] = map[string]interface{}{
		"filter": map[string]interface{}{
			"range": map[string]interface{}{
				"@timestamp": map[string]interface{}{
					"gte": now.AddDate(0, 0, -7).Format("2006-01-02"),
				},
			},
		},
	}
	
	return aliases
}

// OptimizeQuery optimizes a query for better performance
func (sis *SecurityIndexStrategy) OptimizeQuery(originalQuery map[string]interface{}) map[string]interface{} {
	optimizedQuery := make(map[string]interface{})
	
	// Copy original query
	for k, v := range originalQuery {
		optimizedQuery[k] = v
	}
	
	// Add preference routing for better cache utilization
	if sis.config.PreferenceRouting {
		optimizedQuery["preference"] = "_local"
	}
	
	// Optimize sort fields
	if sort, exists := optimizedQuery["sort"]; exists {
		optimizedQuery["sort"] = sis.optimizeSortFields(sort)
	}
	
	// Add query caching hints
	if sis.config.CacheEnabled {
		optimizedQuery["request_cache"] = true
	}
	
	// Optimize aggregations
	if aggs, exists := optimizedQuery["aggs"]; exists {
		optimizedQuery["aggs"] = sis.optimizeAggregations(aggs)
	}
	
	// Add index hints based on query content
	indexHints := sis.analyzeQueryForIndexHints(optimizedQuery)
	if len(indexHints) > 0 {
		optimizedQuery["_index_hints"] = indexHints
	}
	
	return optimizedQuery
}

// optimizeSortFields optimizes sort fields for better performance
func (sis *SecurityIndexStrategy) optimizeSortFields(sort interface{}) interface{} {
	// Convert sort to slice if it's a map
	sortSlice, ok := sort.([]interface{})
	if !ok {
		return sort
	}
	
	optimizedSort := make([]interface{}, 0, len(sortSlice))
	
	for _, sortField := range sortSlice {
		if sortMap, ok := sortField.(map[string]interface{}); ok {
			optimizedSortField := make(map[string]interface{})
			for field, config := range sortMap {
				optimizedConfig := config
				
				// Add unmapped_type for better performance on sparse fields
				if configMap, ok := config.(map[string]interface{}); ok {
					if _, hasUnmapped := configMap["unmapped_type"]; !hasUnmapped {
						configMap["unmapped_type"] = "keyword"
						optimizedConfig = configMap
					}
				}
				
				optimizedSortField[field] = optimizedConfig
			}
			optimizedSort = append(optimizedSort, optimizedSortField)
		} else {
			optimizedSort = append(optimizedSort, sortField)
		}
	}
	
	return optimizedSort
}

// optimizeAggregations optimizes aggregations for better performance
func (sis *SecurityIndexStrategy) optimizeAggregations(aggs interface{}) interface{} {
	aggsMap, ok := aggs.(map[string]interface{})
	if !ok {
		return aggs
	}
	
	optimizedAggs := make(map[string]interface{})
	
	for aggName, aggConfig := range aggsMap {
		if aggConfigMap, ok := aggConfig.(map[string]interface{}); ok {
			optimizedConfig := make(map[string]interface{})
			
			for aggType, aggBody := range aggConfigMap {
				optimizedBody := aggBody
				
				// Add execution hints for terms aggregations
				if aggType == "terms" {
					if bodyMap, ok := aggBody.(map[string]interface{}); ok {
						if _, hasHint := bodyMap["execution_hint"]; !hasHint {
							bodyMap["execution_hint"] = "map"
							optimizedBody = bodyMap
						}
					}
				}
				
				optimizedConfig[aggType] = optimizedBody
			}
			
			optimizedAggs[aggName] = optimizedConfig
		} else {
			optimizedAggs[aggName] = aggConfig
		}
	}
	
	return optimizedAggs
}

// analyzeQueryForIndexHints analyzes query to suggest optimal indices
func (sis *SecurityIndexStrategy) analyzeQueryForIndexHints(query map[string]interface{}) []string {
	hints := make([]string, 0)
	
	// Check for time range in query
	if hasTimeRange(query) {
		hints = append(hints, "time_based_routing")
	}
	
	// Check for tenant filtering
	if hasTenantFilter(query) {
		hints = append(hints, "tenant_routing")
	}
	
	// Check for threat level filtering
	if hasThreatLevelFilter(query) {
		hints = append(hints, "threat_level_routing")
	}
	
	return hints
}

// hasTimeRange checks if query has time range filters
func hasTimeRange(query map[string]interface{}) bool {
	return containsTimeRangeRecursive(query)
}

// containsTimeRangeRecursive recursively searches for time range filters
func containsTimeRangeRecursive(obj interface{}) bool {
	switch v := obj.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if key == "@timestamp" || key == "event_timestamp" {
				if rangeMap, ok := value.(map[string]interface{}); ok {
					if _, hasGte := rangeMap["gte"]; hasGte {
						return true
					}
					if _, hasLte := rangeMap["lte"]; hasLte {
						return true
					}
				}
			}
			if containsTimeRangeRecursive(value) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if containsTimeRangeRecursive(item) {
				return true
			}
		}
	}
	return false
}

// hasTenantFilter checks if query has tenant filtering
func hasTenantFilter(query map[string]interface{}) bool {
	return containsFieldFilter(query, "tenant_id")
}

// hasThreatLevelFilter checks if query has threat level filtering
func hasThreatLevelFilter(query map[string]interface{}) bool {
	return containsFieldFilter(query, "threat_level")
}

// containsFieldFilter checks if query contains a specific field filter
func containsFieldFilter(obj interface{}, field string) bool {
	switch v := obj.(type) {
	case map[string]interface{}:
		if _, exists := v[field]; exists {
			return true
		}
		for _, value := range v {
			if containsFieldFilter(value, field) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if containsFieldFilter(item, field) {
				return true
			}
		}
	}
	return false
}

// runOptimization runs background optimization tasks
func (sis *SecurityIndexStrategy) runOptimization() {
	for {
		select {
		case <-sis.ctx.Done():
			return
		case <-sis.optimizeTicker.C:
			sis.performOptimization()
		}
	}
}

// performOptimization performs index optimization tasks
func (sis *SecurityIndexStrategy) performOptimization() {
	start := time.Now()
	
	sis.logger.Debug("Starting index optimization")
	
	// Update index statistics
	if err := sis.indexManager.UpdateIndexStats(); err != nil {
		sis.logger.Error("Failed to update index statistics", zap.Error(err))
	}
	
	// Optimize query cache
	if sis.config.CacheEnabled {
		sis.queryOptimizer.OptimizeCache()
	}
	
	// Perform forcemerge on old indices if enabled
	if sis.config.ForcemergeEnabled {
		if err := sis.indexManager.ForcemergeOldIndices(); err != nil {
			sis.logger.Error("Failed to forcemerge indices", zap.Error(err))
		}
	}
	
	// Update statistics
	duration := time.Since(start)
	sis.statsMutex.Lock()
	sis.stats.LastOptimization = time.Now()
	sis.statsMutex.Unlock()
	
	sis.logger.Debug("Index optimization completed", zap.Duration("duration", duration))
}

// GetStats returns indexing statistics
func (sis *SecurityIndexStrategy) GetStats() *IndexingStats {
	sis.statsMutex.RLock()
	defer sis.statsMutex.RUnlock()
	
	stats := *sis.stats
	return &stats
}

// IsHealthy returns the health status
func (sis *SecurityIndexStrategy) IsHealthy() bool {
	return sis.indexManager.IsHealthy() && 
		   sis.queryOptimizer.IsHealthy() && 
		   sis.perfAnalyzer.IsHealthy()
}

// Close closes the security index strategy
func (sis *SecurityIndexStrategy) Close() error {
	if sis.cancel != nil {
		sis.cancel()
	}
	
	if sis.optimizeTicker != nil {
		sis.optimizeTicker.Stop()
	}
	
	if sis.indexManager != nil {
		sis.indexManager.Close()
	}
	
	if sis.queryOptimizer != nil {
		sis.queryOptimizer.Close()
	}
	
	if sis.perfAnalyzer != nil {
		sis.perfAnalyzer.Close()
	}
	
	sis.logger.Info("Security index strategy closed")
	return nil
}

// Placeholder implementations for supporting components
func NewIndexManager(logger *zap.Logger, config *IndexingConfig) *IndexManager {
	return &IndexManager{
		logger:    logger.With(zap.String("component", "index-manager")),
		config:    config,
		templates: make(map[string]*IndexTemplate),
		indices:   make(map[string]*IndexInfo),
	}
}

func NewQueryOptimizer(logger *zap.Logger, config *IndexingConfig) *QueryOptimizer {
	return &QueryOptimizer{
		logger:     logger.With(zap.String("component", "query-optimizer")),
		config:     config,
		queryCache: &QueryCache{
			cache:   make(map[string]*CachedQuery),
			maxSize: 1000,
			ttl:     config.CacheTTL,
		},
		queryStats: make(map[string]*QueryStats),
	}
}

func NewPerformanceAnalyzer(logger *zap.Logger) *PerformanceAnalyzer {
	return &PerformanceAnalyzer{
		logger:  logger.With(zap.String("component", "performance-analyzer")),
		metrics: &IndexingMetrics{},
		thresholds: &PerformanceThresholds{
			MaxIndexingLatency: 5 * time.Second,
			MaxQueryLatency:    1 * time.Second,
			MinCacheHitRate:    0.8,
			MaxErrorRate:       0.05,
			MaxStorageGrowth:   0.2,
		},
		alerts: make(chan *PerformanceAlert, 100),
	}
}

// Placeholder methods for component interfaces
func (im *IndexManager) UpdateIndexStats() error { return nil }
func (im *IndexManager) ForcemergeOldIndices() error { return nil }
func (im *IndexManager) IsHealthy() bool { return true }
func (im *IndexManager) Close() error { return nil }

func (qo *QueryOptimizer) OptimizeCache() {}
func (qo *QueryOptimizer) IsHealthy() bool { return true }
func (qo *QueryOptimizer) Close() error { return nil }

func (pa *PerformanceAnalyzer) IsHealthy() bool { return true }
func (pa *PerformanceAnalyzer) Close() error { return nil }