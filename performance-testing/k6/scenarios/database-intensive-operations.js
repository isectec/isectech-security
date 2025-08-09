// k6 Database-Intensive Operations Test
// Comprehensive load testing for database-heavy security operations

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { getTestConfig, getHttpParams, validateResponse, getThinkTime,
         securityEventProcessingRate, threatDetectionLatency, alertCorrelationTime,
         authenticationFailures, concurrentUsers } from '../config/config.js';

// Custom metrics for database operations
import { Counter, Gauge, Rate, Trend } from 'k6/metrics';
const databaseQueryLatency = new Trend('database_query_latency');
const dataIngestionRate = new Rate('data_ingestion_success');
const bulkOperationsLatency = new Trend('bulk_operations_latency');
const searchQueryPerformance = new Trend('search_query_performance');

// Test configuration
const testConfig = getTestConfig(__ENV.TEST_TYPE || 'baseline');
export const options = testConfig.options;

// Test data pools for realistic operations
const searchQueries = [
  { query: 'source_ip:192.168.1.* AND severity:HIGH', description: 'IP range + severity' },
  { query: 'event_type:login_failure AND timestamp:[now-1h TO now]', description: 'Failed logins last hour' },
  { query: 'threat_intel:true AND confidence:>0.8', description: 'High confidence threats' },
  { query: 'alert_status:ACTIVE AND assigned_to:null', description: 'Unassigned active alerts' },
  { query: 'malware_detected:true OR suspicious_activity:true', description: 'Security incidents' },
  { query: 'user_behavior:anomalous AND risk_score:>7', description: 'Anomalous user behavior' }
];

const bulkOperationSizes = [10, 25, 50, 100, 250];
const timeRanges = ['1h', '6h', '24h', '7d', '30d'];

export default function databaseIntensiveOperations() {
  const env = testConfig.environment;
  const analystToken = env.auth.analyst;
  
  if (!analystToken) {
    console.error('Analyst token not provided for environment:', env.name);
    authenticationFailures.add(1);
    return;
  }

  concurrentUsers.add(1);

  group('Large Dataset Queries', function() {
    // Historical data analysis - large time range
    const timeRange = timeRanges[Math.floor(Math.random() * timeRanges.length)];
    const historicalStart = Date.now();
    
    const historicalResponse = http.post(
      `${env.baseUrl}/api/events/search`,
      JSON.stringify({
        query: 'severity:(HIGH OR CRITICAL)',
        timeRange: `last_${timeRange}`,
        limit: 1000,
        sort: 'timestamp:desc',
        includeAggregations: true,
        aggregations: {
          by_severity: { field: 'severity' },
          by_source: { field: 'source_system' },
          timeline: { field: 'timestamp', interval: '1h' }
        }
      }),
      getHttpParams(analystToken)
    );
    
    if (validateResponse(historicalResponse, 'events/search/historical')) {
      const queryLatency = Date.now() - historicalStart;
      databaseQueryLatency.add(queryLatency);
      
      const results = JSON.parse(historicalResponse.body);
      check(results, {
        'Large query returns results': (r) => r.hits && r.hits.total > 0,
        'Aggregations computed': (r) => r.aggregations !== undefined,
        'Query performance acceptable': () => queryLatency < 10000, // < 10 seconds for large queries
        'Results properly paginated': (r) => r.hits.results.length <= 1000
      });
    }

    // Complex multi-field search with joins
    const complexSearchStart = Date.now();
    const complexSearchResponse = http.post(
      `${env.baseUrl}/api/analytics/complex-search`,
      JSON.stringify({
        conditions: [
          { field: 'event_type', operator: 'in', value: ['malware_detection', 'intrusion_attempt', 'data_exfiltration'] },
          { field: 'risk_score', operator: 'gte', value: 7 },
          { field: 'timestamp', operator: 'gte', value: Date.now() - 86400000 } // Last 24h
        ],
        joins: [
          { table: 'user_profiles', on: 'user_id' },
          { table: 'asset_inventory', on: 'asset_id' }
        ],
        aggregations: {
          risk_distribution: { field: 'risk_score', ranges: [0, 5, 7, 9, 10] },
          user_impact: { field: 'user_id', size: 50 },
          asset_impact: { field: 'asset_id', size: 50 }
        },
        limit: 500
      }),
      getHttpParams(analystToken)
    );
    
    if (validateResponse(complexSearchResponse, 'analytics/complex-search')) {
      const complexSearchLatency = Date.now() - complexSearchStart;
      searchQueryPerformance.add(complexSearchLatency);
      
      const complexResults = JSON.parse(complexSearchResponse.body);
      check(complexResults, {
        'Complex search executes': (r) => r.status !== 'error',
        'Joins processed correctly': (r) => r.joined_data !== undefined,
        'Complex query performance': () => complexSearchLatency < 15000 // < 15 seconds
      });
    }
  });

  sleep(getThinkTime('analysis'));

  group('Bulk Data Operations', function() {
    // Bulk alert processing
    const bulkSize = bulkOperationSizes[Math.floor(Math.random() * bulkOperationSizes.length)];
    const bulkStart = Date.now();
    
    // First, get alerts to operate on
    const alertsForBulkResponse = http.get(
      `${env.baseUrl}/api/alerts?status=ACTIVE&limit=${bulkSize}&fields=id,title,severity`,
      getHttpParams(analystToken)
    );
    
    let alertIds = [];
    if (validateResponse(alertsForBulkResponse, 'alerts/bulk-fetch')) {
      const alerts = JSON.parse(alertsForBulkResponse.body);
      alertIds = alerts.data?.map(alert => alert.id).slice(0, bulkSize) || [];
    }

    if (alertIds.length > 0) {
      // Bulk status update
      const bulkUpdateResponse = http.post(
        `${env.baseUrl}/api/alerts/bulk/update`,
        JSON.stringify({
          alertIds: alertIds,
          updates: {
            status: 'INVESTIGATING',
            assignee: 'load-test-analyst',
            priority: 'HIGH',
            notes: `Bulk operation test - ${bulkSize} alerts`
          }
        }),
        getHttpParams(analystToken)
      );
      
      if (validateResponse(bulkUpdateResponse, 'alerts/bulk-update')) {
        const bulkLatency = Date.now() - bulkStart;
        bulkOperationsLatency.add(bulkLatency);
        
        const updateResult = JSON.parse(bulkUpdateResponse.body);
        check(updateResult, {
          'Bulk update succeeds': (r) => r.success === true,
          'All alerts processed': (r) => r.processed_count === alertIds.length,
          'Bulk operation performance': () => bulkLatency < (bulkSize * 50), // < 50ms per item
          'No data corruption': (r) => r.errors === undefined || r.errors.length === 0
        });
      }

      // Bulk correlation analysis
      const correlationStart = Date.now();
      const bulkCorrelationResponse = http.post(
        `${env.baseUrl}/api/analytics/bulk-correlation`,
        JSON.stringify({
          alertIds: alertIds.slice(0, Math.min(20, alertIds.length)), // Limit correlation to 20 items
          correlationTypes: ['temporal', 'spatial', 'behavioral', 'threat_intel'],
          timeWindow: '4h',
          similarityThreshold: 0.7
        }),
        getHttpParams(analystToken)
      );
      
      if (validateResponse(bulkCorrelationResponse, 'analytics/bulk-correlation')) {
        const correlationLatency = Date.now() - correlationStart;
        alertCorrelationTime.add(correlationLatency);
        
        check(bulkCorrelationResponse, {
          'Bulk correlation completes': (r) => r.status === 200,
          'Correlation results available': (r) => JSON.parse(r.body).correlations !== undefined,
          'Correlation performance': () => correlationLatency < 30000 // < 30 seconds
        });
      }
    }
  });

  sleep(getThinkTime('analysis'));

  group('Data Ingestion Stress Testing', function() {
    // Simulate high-volume event ingestion
    const eventBatch = Array.from({ length: 50 }, (_, i) => ({
      timestamp: Date.now() - (i * 1000),
      event_type: ['login_attempt', 'file_access', 'network_connection', 'process_execution'][i % 4],
      severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)],
      source_ip: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
      user_id: `user_${Math.floor(Math.random() * 1000)}`,
      asset_id: `asset_${Math.floor(Math.random() * 500)}`,
      metadata: {
        process_id: Math.floor(Math.random() * 65536),
        command_line: `/usr/bin/test_process_${i}`,
        parent_process: 'system',
        file_hash: `sha256_${Math.random().toString(36).substring(7)}`
      }
    }));

    const ingestionStart = Date.now();
    const ingestionResponse = http.post(
      `${env.baseUrl}/api/events/batch-ingest`,
      JSON.stringify({
        events: eventBatch,
        source: 'load-test-agent',
        batch_id: `batch_${Date.now()}_${Math.random().toString(36).substring(7)}`
      }),
      getHttpParams(analystToken)
    );
    
    if (validateResponse(ingestionResponse, 'events/batch-ingest', 201)) {
      const ingestionLatency = Date.now() - ingestionStart;
      dataIngestionRate.add(1);
      
      const ingestionResult = JSON.parse(ingestionResponse.body);
      check(ingestionResult, {
        'Batch ingestion succeeds': (r) => r.ingested_count === eventBatch.length,
        'Ingestion performance': () => ingestionLatency < 5000, // < 5 seconds for 50 events
        'No duplicate detection errors': (r) => r.duplicate_count === 0,
        'Proper indexing': (r) => r.indexed === true
      });
    } else {
      dataIngestionRate.add(0);
    }

    // Real-time event processing verification
    sleep(2); // Allow processing time
    
    const processingVerificationResponse = http.get(
      `${env.baseUrl}/api/events/processing-status?batch_id=batch_${Date.now()}`,
      getHttpParams(analystToken)
    );
    
    validateResponse(processingVerificationResponse, 'events/processing-status');
  });

  sleep(getThinkTime('analysis'));

  group('Advanced Analytics Queries', function() {
    // Time-based trend analysis
    const trendAnalysisResponse = http.post(
      `${env.baseUrl}/api/analytics/trends`,
      JSON.stringify({
        metrics: ['alert_volume', 'threat_detections', 'user_risk_scores'],
        timeRange: 'last_7d',
        interval: '1h',
        aggregations: {
          alert_volume: { field: 'alert_count', function: 'sum' },
          threat_detections: { field: 'threat_count', function: 'sum' },
          user_risk_scores: { field: 'risk_score', function: 'avg' }
        },
        filters: {
          severity: ['MEDIUM', 'HIGH', 'CRITICAL'],
          confidence: { gte: 0.5 }
        }
      }),
      getHttpParams(analystToken)
    );
    
    validateResponse(trendAnalysisResponse, 'analytics/trends');

    // User behavior analytics
    const behaviorAnalysisResponse = http.post(
      `${env.baseUrl}/api/analytics/user-behavior`,
      JSON.stringify({
        analysis_type: 'anomaly_detection',
        users: 'all',
        timeRange: 'last_30d',
        features: ['login_patterns', 'file_access', 'network_activity', 'privilege_usage'],
        ml_model: 'isolation_forest',
        anomaly_threshold: 0.1
      }),
      getHttpParams(analystToken)
    );
    
    if (validateResponse(behaviorAnalysisResponse, 'analytics/user-behavior')) {
      const behaviorResults = JSON.parse(behaviorAnalysisResponse.body);
      check(behaviorResults, {
        'Behavior analysis completes': (r) => r.status === 'completed',
        'Anomalies detected': (r) => r.anomalies !== undefined,
        'Model performance metrics': (r) => r.model_metrics && r.model_metrics.precision > 0.7
      });
    }

    // Threat landscape analysis
    const threatLandscapeResponse = http.post(
      `${env.baseUrl}/api/analytics/threat-landscape`,
      JSON.stringify({
        scope: 'organization',
        timeframe: 'last_90d',
        include_metrics: [
          'attack_patterns', 'threat_actors', 'vulnerabilities', 
          'impact_assessment', 'trend_analysis'
        ],
        correlation_depth: 3,
        include_predictions: true
      }),
      getHttpParams(analystToken)
    );
    
    validateResponse(threatLandscapeResponse, 'analytics/threat-landscape');
  });

  sleep(getThinkTime('reporting'));

  group('Database Performance Monitoring', function() {
    // Query performance metrics
    const queryPerformanceResponse = http.get(
      `${env.baseUrl}/api/admin/database/performance?metrics=all&timeframe=1h`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(queryPerformanceResponse, 'admin/database/performance')) {
      const dbMetrics = JSON.parse(queryPerformanceResponse.body);
      check(dbMetrics, {
        'Database metrics available': (m) => m.query_stats && m.connection_stats,
        'Query performance healthy': (m) => m.query_stats.avg_duration < 1000,
        'Connection pool healthy': (m) => m.connection_stats.active_connections < m.connection_stats.max_connections * 0.8,
        'Index utilization good': (m) => m.index_stats && m.index_stats.hit_ratio > 0.95
      });
    }

    // Storage and indexing metrics
    const storageMetricsResponse = http.get(
      `${env.baseUrl}/api/admin/storage/metrics?include=elasticsearch,postgres,timescale`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(storageMetricsResponse, 'admin/storage/metrics')) {
      const storageMetrics = JSON.parse(storageMetricsResponse.body);
      check(storageMetrics, {
        'Storage metrics complete': (m) => m.elasticsearch && m.postgres && m.timescale,
        'Elasticsearch healthy': (m) => m.elasticsearch.cluster_health === 'green',
        'PostgreSQL responsive': (m) => m.postgres.response_time < 100,
        'TimescaleDB operational': (m) => m.timescale.compression_ratio > 0.5
      });
    }
  });

  concurrentUsers.add(-1);
}

// Setup function for database-intensive testing
export function setup() {
  const searchQuery = searchQueries[Math.floor(Math.random() * searchQueries.length)];
  console.log(`Starting Database-Intensive Operations test on ${testConfig.environment.name} environment`);
  console.log(`Base URL: ${testConfig.environment.baseUrl}`);
  console.log(`Test Type: ${__ENV.TEST_TYPE || 'baseline'}`);
  console.log(`Sample search query: ${searchQuery.description}`);
  
  return {
    environment: testConfig.environment,
    searchQuery: searchQuery,
    startTime: Date.now()
  };
}

// Teardown function
export function teardown(data) {
  const duration = Date.now() - data.startTime;
  console.log(`Database-Intensive Operations test completed in ${duration}ms`);
  
  console.log('Database Test Summary:');
  console.log(`- Environment: ${data.environment.name}`);
  console.log(`- Duration: ${Math.round(duration / 1000)}s`);
  console.log(`- Search pattern tested: ${data.searchQuery.description}`);
}