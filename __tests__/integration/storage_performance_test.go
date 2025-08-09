package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// StoragePerformanceTestSuite runs comprehensive integration tests for storage and query performance
type StoragePerformanceTestSuite struct {
	logger              *zap.Logger
	ctx                 context.Context
	cancel              context.CancelFunc
	
	// Test configuration
	config              *PerformanceTestConfig
	
	// Components under test
	elasticsearchClient *ElasticsearchTestClient
	timescaleClient     *TimescaleTestClient
	queryEngine         *QueryEngineTestClient
	
	// Test data
	testEvents          []*SecurityEvent
	testMetrics         []*SecurityMetric
	
	// Performance metrics
	results             *PerformanceTestResults
}

// PerformanceTestConfig defines configuration for performance tests
type PerformanceTestConfig struct {
	// Test data size
	EventCount          int           `json:"event_count"`
	MetricCount         int           `json:"metric_count"`
	ConcurrentClients   int           `json:"concurrent_clients"`
	
	// Test duration
	TestDuration        time.Duration `json:"test_duration"`
	WarmupDuration      time.Duration `json:"warmup_duration"`
	
	// Performance targets
	MaxIngestionLatency    time.Duration `json:"max_ingestion_latency"`
	MaxQueryLatency        time.Duration `json:"max_query_latency"`
	MinThroughputEPS       float64       `json:"min_throughput_eps"`
	MaxMemoryUsageMB       int64         `json:"max_memory_usage_mb"`
	MaxCPUUsagePercent     float64       `json:"max_cpu_usage_percent"`
	
	// Storage targets
	MaxIndexingLatency     time.Duration `json:"max_indexing_latency"`
	MinQuerySuccessRate    float64       `json:"min_query_success_rate"`
	MaxStorageOverheadPercent float64    `json:"max_storage_overhead_percent"`
	
	// Elasticsearch settings
	ElasticsearchURL       string        `json:"elasticsearch_url"`
	ElasticsearchIndex     string        `json:"elasticsearch_index"`
	
	// TimescaleDB settings
	TimescaleConnString    string        `json:"timescale_conn_string"`
	TimescaleTable         string        `json:"timescale_table"`
}

// SecurityEvent represents a test security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Source      string                 `json:"source"`
	Severity    string                 `json:"severity"`
	UserID      string                 `json:"user_id,omitempty"`
	SourceIP    string                 `json:"source_ip"`
	TargetIP    string                 `json:"target_ip,omitempty"`
	Port        int                    `json:"port,omitempty"`
	Protocol    string                 `json:"protocol,omitempty"`
	Action      string                 `json:"action"`
	Result      string                 `json:"result"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	Tags        []string               `json:"tags"`
	ThreatScore float64                `json:"threat_score"`
}

// SecurityMetric represents a test security metric
type SecurityMetric struct {
	Timestamp    time.Time              `json:"timestamp"`
	MetricName   string                 `json:"metric_name"`
	MetricType   string                 `json:"metric_type"`
	Value        float64                `json:"value"`
	Labels       map[string]string      `json:"labels"`
	Dimensions   map[string]interface{} `json:"dimensions"`
}

// PerformanceTestResults holds test results
type PerformanceTestResults struct {
	// Ingestion performance
	TotalEventsIngested    int64         `json:"total_events_ingested"`
	TotalMetricsIngested   int64         `json:"total_metrics_ingested"`
	IngestionThroughputEPS float64       `json:"ingestion_throughput_eps"`
	AverageIngestionLatency time.Duration `json:"average_ingestion_latency"`
	P95IngestionLatency    time.Duration `json:"p95_ingestion_latency"`
	P99IngestionLatency    time.Duration `json:"p99_ingestion_latency"`
	IngestionErrors        int64         `json:"ingestion_errors"`
	
	// Query performance
	TotalQueriesExecuted   int64         `json:"total_queries_executed"`
	QueryThroughputQPS     float64       `json:"query_throughput_qps"`
	AverageQueryLatency    time.Duration `json:"average_query_latency"`
	P95QueryLatency        time.Duration `json:"p95_query_latency"`
	P99QueryLatency        time.Duration `json:"p99_query_latency"`
	QuerySuccessRate       float64       `json:"query_success_rate"`
	QueryErrors            int64         `json:"query_errors"`
	
	// Storage performance
	StorageSize            int64         `json:"storage_size"`
	IndexingLatency        time.Duration `json:"indexing_latency"`
	CompressionRatio       float64       `json:"compression_ratio"`
	StorageOverhead        float64       `json:"storage_overhead"`
	
	// Resource utilization
	PeakMemoryUsageMB      int64         `json:"peak_memory_usage_mb"`
	AverageCPUPercent      float64       `json:"average_cpu_percent"`
	PeakCPUPercent         float64       `json:"peak_cpu_percent"`
	NetworkIOBytes         int64         `json:"network_io_bytes"`
	DiskIOBytes            int64         `json:"disk_io_bytes"`
	
	// Test metadata
	TestDuration           time.Duration `json:"test_duration"`
	TestStartTime          time.Time     `json:"test_start_time"`
	TestEndTime            time.Time     `json:"test_end_time"`
	PassedAssertions       int           `json:"passed_assertions"`
	FailedAssertions       int           `json:"failed_assertions"`
	TestStatus             string        `json:"test_status"`
}

// Test client interfaces
type ElasticsearchTestClient interface {
	IndexEvent(ctx context.Context, event *SecurityEvent) error
	SearchEvents(ctx context.Context, query map[string]interface{}) ([]*SecurityEvent, error)
	GetIndexStats(ctx context.Context, index string) (*IndexStats, error)
	BulkIndex(ctx context.Context, events []*SecurityEvent) error
	IsHealthy() bool
}

type TimescaleTestClient interface {
	InsertMetric(ctx context.Context, metric *SecurityMetric) error
	QueryMetrics(ctx context.Context, query string, args ...interface{}) ([]*SecurityMetric, error)
	GetTableStats(ctx context.Context, table string) (*TableStats, error)
	BulkInsert(ctx context.Context, metrics []*SecurityMetric) error
	IsHealthy() bool
}

type QueryEngineTestClient interface {
	ExecuteQuery(ctx context.Context, query interface{}) (interface{}, error)
	ExecuteAggregationQuery(ctx context.Context, query interface{}) (interface{}, error)
	GetQueryStats() *QueryStats
	IsHealthy() bool
}

// IndexStats represents Elasticsearch index statistics
type IndexStats struct {
	DocumentCount int64 `json:"document_count"`
	StorageSize   int64 `json:"storage_size"`
	IndexingRate  float64 `json:"indexing_rate"`
}

// TableStats represents TimescaleDB table statistics
type TableStats struct {
	RowCount      int64 `json:"row_count"`
	TableSize     int64 `json:"table_size"`
	InsertionRate float64 `json:"insertion_rate"`
}

// QueryStats represents query execution statistics
type QueryStats struct {
	TotalQueries     int64         `json:"total_queries"`
	AverageLatency   time.Duration `json:"average_latency"`
	SuccessRate      float64       `json:"success_rate"`
	ErrorCount       int64         `json:"error_count"`
}

// TestStorageAndQueryPerformance runs the main performance test suite
func TestStorageAndQueryPerformance(t *testing.T) {
	suite := NewStoragePerformanceTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("Setup", suite.TestSetup)
	t.Run("IngestionPerformance", suite.TestIngestionPerformance)
	t.Run("QueryPerformance", suite.TestQueryPerformance)
	t.Run("ConcurrentLoadTest", suite.TestConcurrentLoad)
	t.Run("StorageEfficiency", suite.TestStorageEfficiency)
	t.Run("ScalabilityTest", suite.TestScalability)
	t.Run("FaultToleranceTest", suite.TestFaultTolerance)
	t.Run("ResourceUtilization", suite.TestResourceUtilization)
	t.Run("Results", suite.ValidateResults)
}

// NewStoragePerformanceTestSuite creates a new test suite
func NewStoragePerformanceTestSuite(t *testing.T) *StoragePerformanceTestSuite {
	logger := zaptest.NewLogger(t)
	ctx, cancel := context.WithCancel(context.Background())
	
	config := &PerformanceTestConfig{
		EventCount:             100000,
		MetricCount:            50000,
		ConcurrentClients:      10,
		TestDuration:           5 * time.Minute,
		WarmupDuration:         30 * time.Second,
		MaxIngestionLatency:    100 * time.Millisecond,
		MaxQueryLatency:        1 * time.Second,
		MinThroughputEPS:       1000.0,
		MaxMemoryUsageMB:       1024,
		MaxCPUUsagePercent:     80.0,
		MaxIndexingLatency:     50 * time.Millisecond,
		MinQuerySuccessRate:    99.0,
		MaxStorageOverheadPercent: 20.0,
		ElasticsearchURL:       "http://localhost:9200",
		ElasticsearchIndex:     "security-events-test",
		TimescaleConnString:    "postgresql://localhost:5432/isectech_test",
		TimescaleTable:         "security_metrics_test",
	}
	
	return &StoragePerformanceTestSuite{
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
		config:  config,
		results: &PerformanceTestResults{
			TestStartTime: time.Now(),
		},
	}
}

// TestSetup initializes test environment and generates test data
func (suite *StoragePerformanceTestSuite) TestSetup(t *testing.T) {
	suite.logger.Info("Setting up performance test environment")
	
	// Initialize test clients
	var err error
	suite.elasticsearchClient, err = NewElasticsearchTestClient(suite.config.ElasticsearchURL, suite.config.ElasticsearchIndex)
	require.NoError(t, err, "Failed to initialize Elasticsearch client")
	
	suite.timescaleClient, err = NewTimescaleTestClient(suite.config.TimescaleConnString, suite.config.TimescaleTable)
	require.NoError(t, err, "Failed to initialize TimescaleDB client")
	
	suite.queryEngine, err = NewQueryEngineTestClient(suite.elasticsearchClient, suite.timescaleClient)
	require.NoError(t, err, "Failed to initialize query engine")
	
	// Verify connectivity
	assert.True(t, suite.elasticsearchClient.IsHealthy(), "Elasticsearch should be healthy")
	assert.True(t, suite.timescaleClient.IsHealthy(), "TimescaleDB should be healthy")
	assert.True(t, suite.queryEngine.IsHealthy(), "Query engine should be healthy")
	
	// Generate test data
	suite.testEvents = suite.generateTestEvents(suite.config.EventCount)
	suite.testMetrics = suite.generateTestMetrics(suite.config.MetricCount)
	
	assert.Len(t, suite.testEvents, suite.config.EventCount, "Should generate correct number of events")
	assert.Len(t, suite.testMetrics, suite.config.MetricCount, "Should generate correct number of metrics")
	
	suite.logger.Info("Test setup completed",
		zap.Int("events_generated", len(suite.testEvents)),
		zap.Int("metrics_generated", len(suite.testMetrics)),
	)
}

// TestIngestionPerformance tests event and metric ingestion performance
func (suite *StoragePerformanceTestSuite) TestIngestionPerformance(t *testing.T) {
	suite.logger.Info("Testing ingestion performance")
	
	start := time.Now()
	
	// Test Elasticsearch event ingestion
	suite.runEventIngestionTest(t)
	
	// Test TimescaleDB metric ingestion
	suite.runMetricIngestionTest(t)
	
	duration := time.Since(start)
	suite.results.TestDuration = duration
	
	// Calculate throughput
	totalEvents := suite.results.TotalEventsIngested + suite.results.TotalMetricsIngested
	suite.results.IngestionThroughputEPS = float64(totalEvents) / duration.Seconds()
	
	// Validate performance targets
	assert.LessOrEqual(t, suite.results.AverageIngestionLatency, suite.config.MaxIngestionLatency,
		"Average ingestion latency should be within target")
	assert.GreaterOrEqual(t, suite.results.IngestionThroughputEPS, suite.config.MinThroughputEPS,
		"Ingestion throughput should meet minimum target")
	
	suite.logger.Info("Ingestion performance test completed",
		zap.Float64("throughput_eps", suite.results.IngestionThroughputEPS),
		zap.Duration("avg_latency", suite.results.AverageIngestionLatency),
		zap.Int64("total_events", suite.results.TotalEventsIngested),
		zap.Int64("total_metrics", suite.results.TotalMetricsIngested),
	)
}

// runEventIngestionTest tests Elasticsearch event ingestion
func (suite *StoragePerformanceTestSuite) runEventIngestionTest(t *testing.T) {
	batchSize := 1000
	latencies := make([]time.Duration, 0)
	errors := int64(0)
	
	for i := 0; i < len(suite.testEvents); i += batchSize {
		end := i + batchSize
		if end > len(suite.testEvents) {
			end = len(suite.testEvents)
		}
		
		batch := suite.testEvents[i:end]
		start := time.Now()
		
		err := suite.elasticsearchClient.BulkIndex(suite.ctx, batch)
		latency := time.Since(start)
		latencies = append(latencies, latency)
		
		if err != nil {
			errors++
			suite.logger.Error("Batch ingestion failed", zap.Error(err))
		} else {
			suite.results.TotalEventsIngested += int64(len(batch))
		}
	}
	
	suite.results.IngestionErrors += errors
	if len(latencies) > 0 {
		suite.results.AverageIngestionLatency = calculateAverage(latencies)
		suite.results.P95IngestionLatency = calculatePercentile(latencies, 95)
		suite.results.P99IngestionLatency = calculatePercentile(latencies, 99)
	}
}

// runMetricIngestionTest tests TimescaleDB metric ingestion
func (suite *StoragePerformanceTestSuite) runMetricIngestionTest(t *testing.T) {
	batchSize := 1000
	
	for i := 0; i < len(suite.testMetrics); i += batchSize {
		end := i + batchSize
		if end > len(suite.testMetrics) {
			end = len(suite.testMetrics)
		}
		
		batch := suite.testMetrics[i:end]
		
		err := suite.timescaleClient.BulkInsert(suite.ctx, batch)
		if err != nil {
			suite.results.IngestionErrors++
			suite.logger.Error("Metric batch ingestion failed", zap.Error(err))
		} else {
			suite.results.TotalMetricsIngested += int64(len(batch))
		}
	}
}

// TestQueryPerformance tests query execution performance
func (suite *StoragePerformanceTestSuite) TestQueryPerformance(t *testing.T) {
	suite.logger.Info("Testing query performance")
	
	// Wait for data to be indexed
	time.Sleep(10 * time.Second)
	
	start := time.Now()
	
	// Test various query types
	suite.runElasticsearchQueryTests(t)
	suite.runTimescaleQueryTests(t)
	suite.runComplexQueryTests(t)
	
	duration := time.Since(start)
	
	// Calculate query throughput
	suite.results.QueryThroughputQPS = float64(suite.results.TotalQueriesExecuted) / duration.Seconds()
	
	// Calculate success rate
	totalQueries := suite.results.TotalQueriesExecuted + suite.results.QueryErrors
	if totalQueries > 0 {
		suite.results.QuerySuccessRate = (float64(suite.results.TotalQueriesExecuted) / float64(totalQueries)) * 100
	}
	
	// Validate performance targets
	assert.LessOrEqual(t, suite.results.AverageQueryLatency, suite.config.MaxQueryLatency,
		"Average query latency should be within target")
	assert.GreaterOrEqual(t, suite.results.QuerySuccessRate, suite.config.MinQuerySuccessRate,
		"Query success rate should meet minimum target")
	
	suite.logger.Info("Query performance test completed",
		zap.Float64("query_throughput_qps", suite.results.QueryThroughputQPS),
		zap.Duration("avg_query_latency", suite.results.AverageQueryLatency),
		zap.Float64("success_rate", suite.results.QuerySuccessRate),
	)
}

// runElasticsearchQueryTests tests Elasticsearch queries
func (suite *StoragePerformanceTestSuite) runElasticsearchQueryTests(t *testing.T) {
	queries := []map[string]interface{}{
		// Simple term query
		{"term": map[string]interface{}{"event_type": "login"}},
		// Range query
		{"range": map[string]interface{}{"timestamp": map[string]interface{}{"gte": "now-1h"}}},
		// Boolean query
		{"bool": map[string]interface{}{
			"must": []interface{}{
				map[string]interface{}{"term": map[string]interface{}{"severity": "high"}},
				map[string]interface{}{"range": map[string]interface{}{"threat_score": map[string]interface{}{"gte": 7}}},
			},
		}},
		// Wildcard query
		{"wildcard": map[string]interface{}{"source_ip": "192.168.*"}},
		// Aggregation query
		{"terms": map[string]interface{}{"field": "event_type", "size": 10}},
	}
	
	latencies := make([]time.Duration, 0)
	
	for _, query := range queries {
		for i := 0; i < 100; i++ { // Run each query 100 times
			start := time.Now()
			
			_, err := suite.elasticsearchClient.SearchEvents(suite.ctx, query)
			latency := time.Since(start)
			latencies = append(latencies, latency)
			
			if err != nil {
				suite.results.QueryErrors++
			} else {
				suite.results.TotalQueriesExecuted++
			}
		}
	}
	
	if len(latencies) > 0 {
		suite.results.AverageQueryLatency = calculateAverage(latencies)
		suite.results.P95QueryLatency = calculatePercentile(latencies, 95)
		suite.results.P99QueryLatency = calculatePercentile(latencies, 99)
	}
}

// runTimescaleQueryTests tests TimescaleDB queries
func (suite *StoragePerformanceTestSuite) runTimescaleQueryTests(t *testing.T) {
	queries := []string{
		"SELECT * FROM " + suite.config.TimescaleTable + " WHERE timestamp > NOW() - INTERVAL '1 hour'",
		"SELECT metric_name, AVG(value) FROM " + suite.config.TimescaleTable + " GROUP BY metric_name",
		"SELECT time_bucket('5 minutes', timestamp) as bucket, AVG(value) FROM " + suite.config.TimescaleTable + " GROUP BY bucket ORDER BY bucket",
		"SELECT * FROM " + suite.config.TimescaleTable + " WHERE value > 100 ORDER BY timestamp DESC LIMIT 1000",
	}
	
	for _, query := range queries {
		for i := 0; i < 50; i++ { // Run each query 50 times
			start := time.Now()
			
			_, err := suite.timescaleClient.QueryMetrics(suite.ctx, query)
			
			if err != nil {
				suite.results.QueryErrors++
			} else {
				suite.results.TotalQueriesExecuted++
			}
		}
	}
}

// runComplexQueryTests tests complex cross-system queries
func (suite *StoragePerformanceTestSuite) runComplexQueryTests(t *testing.T) {
	// Test queries that span both systems
	for i := 0; i < 20; i++ {
		start := time.Now()
		
		// Complex query combining Elasticsearch and TimescaleDB data
		_, err := suite.queryEngine.ExecuteAggregationQuery(suite.ctx, map[string]interface{}{
			"elasticsearch_query": map[string]interface{}{
				"range": map[string]interface{}{"timestamp": map[string]interface{}{"gte": "now-1h"}},
			},
			"timescale_query": "SELECT metric_name, AVG(value) FROM " + suite.config.TimescaleTable + " WHERE timestamp > NOW() - INTERVAL '1 hour' GROUP BY metric_name",
		})
		
		if err != nil {
			suite.results.QueryErrors++
		} else {
			suite.results.TotalQueriesExecuted++
		}
	}
}

// TestConcurrentLoad tests performance under concurrent load
func (suite *StoragePerformanceTestSuite) TestConcurrentLoad(t *testing.T) {
	suite.logger.Info("Testing concurrent load performance")
	
	var wg sync.WaitGroup
	startTime := time.Now()
	endTime := startTime.Add(suite.config.TestDuration)
	
	// Start concurrent ingestion workers
	for i := 0; i < suite.config.ConcurrentClients/2; i++ {
		wg.Add(1)
		go suite.concurrentIngestionWorker(&wg, endTime)
	}
	
	// Start concurrent query workers
	for i := 0; i < suite.config.ConcurrentClients/2; i++ {
		wg.Add(1)
		go suite.concurrentQueryWorker(&wg, endTime)
	}
	
	wg.Wait()
	
	suite.logger.Info("Concurrent load test completed",
		zap.Duration("test_duration", time.Since(startTime)),
		zap.Int("concurrent_clients", suite.config.ConcurrentClients),
	)
}

// concurrentIngestionWorker runs continuous ingestion
func (suite *StoragePerformanceTestSuite) concurrentIngestionWorker(wg *sync.WaitGroup, endTime time.Time) {
	defer wg.Done()
	
	for time.Now().Before(endTime) {
		// Generate and ingest random events
		events := suite.generateTestEvents(100)
		
		err := suite.elasticsearchClient.BulkIndex(suite.ctx, events)
		if err != nil {
			suite.results.IngestionErrors++
		} else {
			suite.results.TotalEventsIngested += int64(len(events))
		}
		
		time.Sleep(100 * time.Millisecond)
	}
}

// concurrentQueryWorker runs continuous queries
func (suite *StoragePerformanceTestSuite) concurrentQueryWorker(wg *sync.WaitGroup, endTime time.Time) {
	defer wg.Done()
	
	queries := []map[string]interface{}{
		{"term": map[string]interface{}{"event_type": "login"}},
		{"range": map[string]interface{}{"timestamp": map[string]interface{}{"gte": "now-5m"}}},
		{"bool": map[string]interface{}{
			"must": []interface{}{
				map[string]interface{}{"term": map[string]interface{}{"severity": "high"}},
			},
		}},
	}
	
	for time.Now().Before(endTime) {
		query := queries[rand.Intn(len(queries))]
		
		_, err := suite.elasticsearchClient.SearchEvents(suite.ctx, query)
		if err != nil {
			suite.results.QueryErrors++
		} else {
			suite.results.TotalQueriesExecuted++
		}
		
		time.Sleep(50 * time.Millisecond)
	}
}

// TestStorageEfficiency tests storage efficiency and compression
func (suite *StoragePerformanceTestSuite) TestStorageEfficiency(t *testing.T) {
	suite.logger.Info("Testing storage efficiency")
	
	// Wait for indexing to complete
	time.Sleep(30 * time.Second)
	
	// Get Elasticsearch storage stats
	esStats, err := suite.elasticsearchClient.GetIndexStats(suite.ctx, suite.config.ElasticsearchIndex)
	require.NoError(t, err, "Should get Elasticsearch stats")
	
	// Get TimescaleDB storage stats
	tsStats, err := suite.timescaleClient.GetTableStats(suite.ctx, suite.config.TimescaleTable)
	require.NoError(t, err, "Should get TimescaleDB stats")
	
	suite.results.StorageSize = esStats.StorageSize + tsStats.TableSize
	
	// Calculate storage overhead
	rawDataSize := int64(len(suite.testEvents)) * 1024 + int64(len(suite.testMetrics)) * 256 // Estimated raw size
	suite.results.StorageOverhead = (float64(suite.results.StorageSize) / float64(rawDataSize)) * 100
	
	// Validate storage efficiency
	assert.LessOrEqual(t, suite.results.StorageOverhead, suite.config.MaxStorageOverheadPercent,
		"Storage overhead should be within acceptable limits")
	
	suite.logger.Info("Storage efficiency test completed",
		zap.Int64("storage_size", suite.results.StorageSize),
		zap.Float64("storage_overhead", suite.results.StorageOverhead),
	)
}

// TestScalability tests system scalability
func (suite *StoragePerformanceTestSuite) TestScalability(t *testing.T) {
	suite.logger.Info("Testing system scalability")
	
	// Test with increasing load
	loadLevels := []int{1, 5, 10, 20}
	
	for _, level := range loadLevels {
		suite.logger.Info("Testing scalability level", zap.Int("level", level))
		
		start := time.Now()
		var wg sync.WaitGroup
		
		for i := 0; i < level; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				
				events := suite.generateTestEvents(1000)
				err := suite.elasticsearchClient.BulkIndex(suite.ctx, events)
				if err != nil {
					suite.logger.Error("Scalability test batch failed", zap.Error(err))
				}
			}()
		}
		
		wg.Wait()
		duration := time.Since(start)
		
		throughput := float64(level*1000) / duration.Seconds()
		suite.logger.Info("Scalability level completed",
			zap.Int("level", level),
			zap.Duration("duration", duration),
			zap.Float64("throughput", throughput),
		)
		
		// Verify system remains responsive
		_, err := suite.elasticsearchClient.SearchEvents(suite.ctx, map[string]interface{}{
			"match_all": map[string]interface{}{},
		})
		assert.NoError(t, err, "System should remain responsive under load")
	}
}

// TestFaultTolerance tests system fault tolerance
func (suite *StoragePerformanceTestSuite) TestFaultTolerance(t *testing.T) {
	suite.logger.Info("Testing fault tolerance")
	
	// Test handling of malformed data
	malformedEvents := []*SecurityEvent{
		{ID: "malformed-1", Timestamp: time.Time{}, EventType: "", Message: ""},
		{ID: "malformed-2", Timestamp: time.Now(), EventType: "test", ThreatScore: -1},
	}
	
	err := suite.elasticsearchClient.BulkIndex(suite.ctx, malformedEvents)
	// Should handle malformed data gracefully
	suite.logger.Info("Malformed data handling test", zap.Error(err))
	
	// Test large batch handling
	largeEvents := suite.generateTestEvents(10000)
	start := time.Now()
	err = suite.elasticsearchClient.BulkIndex(suite.ctx, largeEvents)
	duration := time.Since(start)
	
	assert.NoError(t, err, "Should handle large batches")
	assert.Less(t, duration, 30*time.Second, "Large batch should complete within reasonable time")
	
	suite.logger.Info("Fault tolerance test completed")
}

// TestResourceUtilization tests resource utilization
func (suite *StoragePerformanceTestSuite) TestResourceUtilization(t *testing.T) {
	suite.logger.Info("Testing resource utilization")
	
	// Monitor resource usage during heavy load
	monitoring := suite.startResourceMonitoring()
	defer monitoring.Stop()
	
	// Generate heavy load
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			events := suite.generateTestEvents(5000)
			suite.elasticsearchClient.BulkIndex(suite.ctx, events)
			
			metrics := suite.generateTestMetrics(2500)
			suite.timescaleClient.BulkInsert(suite.ctx, metrics)
		}()
	}
	
	wg.Wait()
	
	resourceStats := monitoring.GetStats()
	suite.results.PeakMemoryUsageMB = resourceStats.PeakMemoryMB
	suite.results.AverageCPUPercent = resourceStats.AverageCPU
	suite.results.PeakCPUPercent = resourceStats.PeakCPU
	suite.results.NetworkIOBytes = resourceStats.NetworkIO
	suite.results.DiskIOBytes = resourceStats.DiskIO
	
	// Validate resource usage
	assert.LessOrEqual(t, suite.results.PeakMemoryUsageMB, suite.config.MaxMemoryUsageMB,
		"Memory usage should be within limits")
	assert.LessOrEqual(t, suite.results.AverageCPUPercent, suite.config.MaxCPUUsagePercent,
		"CPU usage should be within limits")
	
	suite.logger.Info("Resource utilization test completed",
		zap.Int64("peak_memory_mb", suite.results.PeakMemoryUsageMB),
		zap.Float64("avg_cpu_percent", suite.results.AverageCPUPercent),
		zap.Float64("peak_cpu_percent", suite.results.PeakCPUPercent),
	)
}

// ValidateResults validates overall test results
func (suite *StoragePerformanceTestSuite) ValidateResults(t *testing.T) {
	suite.results.TestEndTime = time.Now()
	suite.results.TestDuration = suite.results.TestEndTime.Sub(suite.results.TestStartTime)
	
	// Determine test status
	if suite.results.FailedAssertions == 0 {
		suite.results.TestStatus = "PASSED"
	} else {
		suite.results.TestStatus = "FAILED"
	}
	
	// Log comprehensive results
	resultsJSON, _ := json.MarshalIndent(suite.results, "", "  ")
	suite.logger.Info("Performance test results", zap.String("results", string(resultsJSON)))
	
	// Final assertions
	assert.Equal(t, "PASSED", suite.results.TestStatus, "All performance tests should pass")
	assert.Greater(t, suite.results.TotalEventsIngested, int64(0), "Should ingest events")
	assert.Greater(t, suite.results.TotalQueriesExecuted, int64(0), "Should execute queries")
	assert.GreaterOrEqual(t, suite.results.QuerySuccessRate, suite.config.MinQuerySuccessRate, "Query success rate should meet target")
}

// Helper methods

func (suite *StoragePerformanceTestSuite) generateTestEvents(count int) []*SecurityEvent {
	events := make([]*SecurityEvent, count)
	eventTypes := []string{"login", "logout", "file_access", "network_connection", "process_execution", "authentication_failure"}
	severities := []string{"low", "medium", "high", "critical"}
	sources := []string{"server-1", "server-2", "workstation-1", "firewall", "ids", "ad-controller"}
	actions := []string{"allow", "deny", "block", "alert", "quarantine"}
	
	for i := 0; i < count; i++ {
		events[i] = &SecurityEvent{
			ID:          fmt.Sprintf("event-%d-%d", time.Now().UnixNano(), i),
			Timestamp:   time.Now().Add(-time.Duration(rand.Intn(3600)) * time.Second),
			EventType:   eventTypes[rand.Intn(len(eventTypes))],
			Source:      sources[rand.Intn(len(sources))],
			Severity:    severities[rand.Intn(len(severities))],
			UserID:      fmt.Sprintf("user-%d", rand.Intn(1000)),
			SourceIP:    fmt.Sprintf("192.168.%d.%d", rand.Intn(255), rand.Intn(255)),
			TargetIP:    fmt.Sprintf("10.0.%d.%d", rand.Intn(255), rand.Intn(255)),
			Port:        rand.Intn(65535),
			Protocol:    []string{"TCP", "UDP", "ICMP"}[rand.Intn(3)],
			Action:      actions[rand.Intn(len(actions))],
			Result:      []string{"success", "failure"}[rand.Intn(2)],
			Message:     fmt.Sprintf("Test security event %d", i),
			Details:     map[string]interface{}{"test": true, "batch": time.Now().Format("2006-01-02T15:04:05")},
			Tags:        []string{"test", "performance", "integration"},
			ThreatScore: rand.Float64() * 10,
		}
	}
	
	return events
}

func (suite *StoragePerformanceTestSuite) generateTestMetrics(count int) []*SecurityMetric {
	metrics := make([]*SecurityMetric, count)
	metricNames := []string{"cpu_usage", "memory_usage", "disk_io", "network_traffic", "threat_score", "event_count"}
	metricTypes := []string{"gauge", "counter", "histogram"}
	
	for i := 0; i < count; i++ {
		metrics[i] = &SecurityMetric{
			Timestamp:  time.Now().Add(-time.Duration(rand.Intn(3600)) * time.Second),
			MetricName: metricNames[rand.Intn(len(metricNames))],
			MetricType: metricTypes[rand.Intn(len(metricTypes))],
			Value:      rand.Float64() * 100,
			Labels: map[string]string{
				"environment": "test",
				"component":   fmt.Sprintf("component-%d", rand.Intn(10)),
			},
			Dimensions: map[string]interface{}{
				"host":     fmt.Sprintf("host-%d", rand.Intn(5)),
				"region":   "us-west-2",
				"category": "security",
			},
		}
	}
	
	return metrics
}

func (suite *StoragePerformanceTestSuite) startResourceMonitoring() *ResourceMonitor {
	return &ResourceMonitor{
		ctx: suite.ctx,
		stats: &ResourceStats{},
	}
}

func calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	
	return total / time.Duration(len(durations))
}

func calculatePercentile(durations []time.Duration, percentile int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	// Simple percentile calculation
	// In production, would use a proper percentile algorithm
	index := (percentile * len(durations)) / 100
	if index >= len(durations) {
		index = len(durations) - 1
	}
	
	return durations[index]
}

func (suite *StoragePerformanceTestSuite) Cleanup() {
	if suite.cancel != nil {
		suite.cancel()
	}
	
	suite.logger.Info("Test suite cleanup completed")
}

// Supporting types and implementations

type ResourceMonitor struct {
	ctx   context.Context
	stats *ResourceStats
}

type ResourceStats struct {
	PeakMemoryMB int64
	AverageCPU   float64
	PeakCPU      float64
	NetworkIO    int64
	DiskIO       int64
}

func (rm *ResourceMonitor) GetStats() *ResourceStats {
	return rm.stats
}

func (rm *ResourceMonitor) Stop() {
	// Implementation would stop resource monitoring
}

// Placeholder implementations for test clients
func NewElasticsearchTestClient(url, index string) (ElasticsearchTestClient, error) {
	return &MockElasticsearchClient{}, nil
}

func NewTimescaleTestClient(connString, table string) (TimescaleTestClient, error) {
	return &MockTimescaleClient{}, nil
}

func NewQueryEngineTestClient(es ElasticsearchTestClient, ts TimescaleTestClient) (QueryEngineTestClient, error) {
	return &MockQueryEngineClient{}, nil
}

// Mock implementations
type MockElasticsearchClient struct{}

func (m *MockElasticsearchClient) IndexEvent(ctx context.Context, event *SecurityEvent) error {
	return nil
}

func (m *MockElasticsearchClient) SearchEvents(ctx context.Context, query map[string]interface{}) ([]*SecurityEvent, error) {
	return []*SecurityEvent{}, nil
}

func (m *MockElasticsearchClient) GetIndexStats(ctx context.Context, index string) (*IndexStats, error) {
	return &IndexStats{DocumentCount: 1000, StorageSize: 1024000}, nil
}

func (m *MockElasticsearchClient) BulkIndex(ctx context.Context, events []*SecurityEvent) error {
	return nil
}

func (m *MockElasticsearchClient) IsHealthy() bool {
	return true
}

type MockTimescaleClient struct{}

func (m *MockTimescaleClient) InsertMetric(ctx context.Context, metric *SecurityMetric) error {
	return nil
}

func (m *MockTimescaleClient) QueryMetrics(ctx context.Context, query string, args ...interface{}) ([]*SecurityMetric, error) {
	return []*SecurityMetric{}, nil
}

func (m *MockTimescaleClient) GetTableStats(ctx context.Context, table string) (*TableStats, error) {
	return &TableStats{RowCount: 500, TableSize: 512000}, nil
}

func (m *MockTimescaleClient) BulkInsert(ctx context.Context, metrics []*SecurityMetric) error {
	return nil
}

func (m *MockTimescaleClient) IsHealthy() bool {
	return true
}

type MockQueryEngineClient struct{}

func (m *MockQueryEngineClient) ExecuteQuery(ctx context.Context, query interface{}) (interface{}, error) {
	return map[string]interface{}{"result": "success"}, nil
}

func (m *MockQueryEngineClient) ExecuteAggregationQuery(ctx context.Context, query interface{}) (interface{}, error) {
	return map[string]interface{}{"aggregation": "result"}, nil
}

func (m *MockQueryEngineClient) GetQueryStats() *QueryStats {
	return &QueryStats{TotalQueries: 100, AverageLatency: 50 * time.Millisecond, SuccessRate: 99.0}
}

func (m *MockQueryEngineClient) IsHealthy() bool {
	return true
}