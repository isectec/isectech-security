// k6 Security Analyst Workflow Test
// Comprehensive load testing for security analyst daily operations

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { getTestConfig, getHttpParams, validateResponse, getThinkTime, 
         securityEventProcessingRate, threatDetectionLatency, alertCorrelationTime,
         authenticationFailures, concurrentUsers } from '../config/config.js';

// Test configuration
const testConfig = getTestConfig(__ENV.TEST_TYPE || 'baseline');
export const options = testConfig.options;

// Global variables for test data
let testData = {
  userId: null,
  alertIds: [],
  threatIds: [],
  eventIds: []
};

export default function securityAnalystWorkflow() {
  const env = testConfig.environment;
  const analystToken = env.auth.analyst;
  
  if (!analystToken) {
    console.error('Analyst token not provided for environment:', env.name);
    authenticationFailures.add(1);
    return;
  }

  concurrentUsers.add(1);

  group('Authentication & Profile Setup', function() {
    // Authenticate and get user profile
    const profileResponse = http.get(
      `${env.baseUrl}/api/auth/profile`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(profileResponse, 'auth/profile')) {
      const profile = JSON.parse(profileResponse.body);
      testData.userId = profile.user?.id;
      
      check(profile, {
        'Profile has required fields': (p) => p.user && p.user.id && p.user.role,
        'User has analyst permissions': (p) => p.user.role === 'analyst' || p.user.permissions?.includes('VIEW_ALERTS')
      });
    } else {
      authenticationFailures.add(1);
      return; // Exit if authentication fails
    }
  });

  sleep(getThinkTime('quickAction'));

  group('Dashboard Data Loading', function() {
    // Load main security dashboard
    const dashboardStart = Date.now();
    const dashboardResponse = http.get(
      `${env.baseUrl}/api/dashboard/summary`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(dashboardResponse, 'dashboard/summary')) {
      const dashboardLatency = Date.now() - dashboardStart;
      threatDetectionLatency.add(dashboardLatency);
      
      const dashboard = JSON.parse(dashboardResponse.body);
      check(dashboard, {
        'Dashboard has metrics': (d) => typeof d.alerts_count === 'number',
        'Dashboard has threat data': (d) => typeof d.threats_count === 'number',
        'Dashboard loads quickly': () => dashboardLatency < 1000
      });
    }

    // Load system health metrics
    const healthResponse = http.get(
      `${env.baseUrl}/api/health`,
      getHttpParams(analystToken)
    );
    
    validateResponse(healthResponse, 'health', 200);
  });

  sleep(getThinkTime('analysis'));

  group('Alert Management Operations', function() {
    // Fetch active alerts with filtering
    const alertsResponse = http.get(
      `${env.baseUrl}/api/alerts?status=ACTIVE&severity=HIGH,CRITICAL&limit=50&sort=created_desc`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(alertsResponse, 'alerts/list')) {
      const alerts = JSON.parse(alertsResponse.body);
      testData.alertIds = alerts.data?.slice(0, 5).map(alert => alert.id) || [];
      
      check(alerts, {
        'Alerts have proper structure': (a) => a.data && Array.isArray(a.data),
        'Alert metadata present': (a) => a.total !== undefined && a.page !== undefined,
        'Alerts have required fields': (a) => a.data.length === 0 || 
          (a.data[0].id && a.data[0].severity && a.data[0].status)
      });
      
      securityEventProcessingRate.add(1);
    }

    // Get detailed alert information for the first alert
    if (testData.alertIds.length > 0) {
      const alertDetailResponse = http.get(
        `${env.baseUrl}/api/alerts/${testData.alertIds[0]}`,
        getHttpParams(analystToken)
      );
      
      if (validateResponse(alertDetailResponse, 'alerts/detail')) {
        const alert = JSON.parse(alertDetailResponse.body);
        check(alert, {
          'Alert detail complete': (a) => a.id && a.events && a.timeline,
          'Alert has evidence': (a) => a.evidence && Array.isArray(a.evidence),
          'Alert has correlation data': (a) => a.correlations !== undefined
        });
      }
    }

    // Simulate alert correlation analysis
    if (testData.alertIds.length >= 2) {
      const correlationStart = Date.now();
      const correlationResponse = http.post(
        `${env.baseUrl}/api/alerts/correlate`,
        JSON.stringify({
          alertIds: testData.alertIds.slice(0, 3),
          timeWindow: '1h',
          correlationTypes: ['IP', 'USER', 'ASSET']
        }),
        getHttpParams(analystToken)
      );
      
      if (validateResponse(correlationResponse, 'alerts/correlate', 200)) {
        const correlationTime = Date.now() - correlationStart;
        alertCorrelationTime.add(correlationTime);
        
        check(correlationResponse, {
          'Correlation analysis completes': (r) => r.status === 200,
          'Correlation is fast': () => correlationTime < 2000
        });
      }
    }
  });

  sleep(getThinkTime('analysis'));

  group('Threat Intelligence Operations', function() {
    // Fetch current threat intelligence
    const threatsResponse = http.get(
      `${env.baseUrl}/api/threats?confidence=high&severity=critical&limit=20&timeframe=24h`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(threatsResponse, 'threats/list')) {
      const threats = JSON.parse(threatsResponse.body);
      testData.threatIds = threats.data?.slice(0, 3).map(threat => threat.id) || [];
      
      check(threats, {
        'Threats properly formatted': (t) => t.data && Array.isArray(t.data),
        'Threat intel has confidence scores': (t) => t.data.length === 0 || 
          typeof t.data[0].confidence === 'number',
        'Threats have IOCs': (t) => t.data.length === 0 || 
          (t.data[0].indicators && Array.isArray(t.data[0].indicators))
      });
    }

    // Get detailed threat analysis for high-confidence threats
    if (testData.threatIds.length > 0) {
      const threatDetailResponse = http.get(
        `${env.baseUrl}/api/threats/${testData.threatIds[0]}/analysis`,
        getHttpParams(analystToken)
      );
      
      validateResponse(threatDetailResponse, 'threats/analysis');
    }

    // Search for threat indicators in recent events
    const threatSearchResponse = http.post(
      `${env.baseUrl}/api/events/search`,
      JSON.stringify({
        query: 'threat_indicators:true',
        timeRange: 'last_6h',
        limit: 100,
        fields: ['timestamp', 'source_ip', 'threat_type', 'confidence']
      }),
      getHttpParams(analystToken)
    );
    
    validateResponse(threatSearchResponse, 'events/search');
  });

  sleep(getThinkTime('analysis'));

  group('Security Event Analysis', function() {
    // Real-time event stream simulation
    const eventsResponse = http.get(
      `${env.baseUrl}/api/events/stream?since=${Date.now() - 3600000}&limit=200`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(eventsResponse, 'events/stream')) {
      const events = JSON.parse(eventsResponse.body);
      testData.eventIds = events.data?.slice(0, 10).map(event => event.id) || [];
      
      check(events, {
        'Events stream active': (e) => e.data && Array.isArray(e.data),
        'Events have timestamps': (e) => e.data.length === 0 || e.data[0].timestamp,
        'Events properly categorized': (e) => e.data.length === 0 || e.data[0].category
      });
    }

    // Perform advanced search with complex query
    const advancedSearchResponse = http.post(
      `${env.baseUrl}/api/events/search/advanced`,
      JSON.stringify({
        conditions: [
          { field: 'severity', operator: 'in', value: ['HIGH', 'CRITICAL'] },
          { field: 'timestamp', operator: 'gte', value: Date.now() - 86400000 }
        ],
        aggregations: {
          by_source: { field: 'source_system' },
          by_severity: { field: 'severity' },
          timeline: { field: 'timestamp', interval: '1h' }
        },
        limit: 500
      }),
      getHttpParams(analystToken)
    );
    
    if (validateResponse(advancedSearchResponse, 'events/search/advanced')) {
      const searchResults = JSON.parse(advancedSearchResponse.body);
      check(searchResults, {
        'Advanced search returns results': (r) => r.hits && r.hits.total > 0,
        'Aggregations present': (r) => r.aggregations !== undefined,
        'Search performance acceptable': (r) => r.took < 5000 // < 5 seconds
      });
    }
  });

  sleep(getThinkTime('reporting'));

  group('Reporting and Export Operations', function() {
    // Generate security metrics report
    const metricsResponse = http.get(
      `${env.baseUrl}/api/reports/security-metrics?timeframe=24h&format=json`,
      getHttpParams(analystToken)
    );
    
    validateResponse(metricsResponse, 'reports/security-metrics');

    // Export alert data for analysis
    const exportResponse = http.post(
      `${env.baseUrl}/api/reports/export`,
      JSON.stringify({
        type: 'alerts',
        format: 'csv',
        filters: {
          status: ['ACTIVE', 'INVESTIGATING'],
          severity: ['HIGH', 'CRITICAL'],
          timeRange: 'last_24h'
        },
        fields: ['id', 'title', 'severity', 'status', 'created_at', 'source_system']
      }),
      getHttpParams(analystToken)
    );
    
    if (validateResponse(exportResponse, 'reports/export', 202)) {
      const exportJob = JSON.parse(exportResponse.body);
      check(exportJob, {
        'Export job created': (j) => j.jobId !== undefined,
        'Export status tracking': (j) => j.status && j.estimatedCompletion
      });
    }
  });

  sleep(getThinkTime('quickAction'));

  group('Performance Monitoring', function() {
    // Check system performance metrics
    const performanceResponse = http.get(
      `${env.baseUrl}/api/metrics/performance?component=all&timeframe=1h`,
      getHttpParams(analystToken)
    );
    
    if (validateResponse(performanceResponse, 'metrics/performance')) {
      const performance = JSON.parse(performanceResponse.body);
      check(performance, {
        'Performance metrics available': (p) => p.system && p.database && p.api,
        'Response times healthy': (p) => p.api?.avg_response_time < 500,
        'Error rates acceptable': (p) => p.api?.error_rate < 0.05
      });
    }

    // Quick alert count for situational awareness
    const alertCountResponse = http.get(
      `${env.baseUrl}/api/alerts/count?status=ACTIVE&groupBy=severity`,
      getHttpParams(analystToken)
    );
    
    validateResponse(alertCountResponse, 'alerts/count');
  });

  concurrentUsers.add(-1);
}

// Setup function to initialize test environment
export function setup() {
  console.log(`Starting Security Analyst Workflow test on ${testConfig.environment.name} environment`);
  console.log(`Base URL: ${testConfig.environment.baseUrl}`);
  console.log(`Test Type: ${__ENV.TEST_TYPE || 'baseline'}`);
  
  return {
    environment: testConfig.environment,
    startTime: Date.now()
  };
}

// Teardown function for cleanup
export function teardown(data) {
  const duration = Date.now() - data.startTime;
  console.log(`Security Analyst Workflow test completed in ${duration}ms`);
  
  // Log final metrics summary
  console.log('Test Summary:');
  console.log(`- Environment: ${data.environment.name}`);
  console.log(`- Duration: ${Math.round(duration / 1000)}s`);
}