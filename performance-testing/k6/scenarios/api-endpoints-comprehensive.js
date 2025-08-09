// k6 Comprehensive API Endpoints Test
// Complete coverage of all API endpoints with realistic payloads

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { getTestConfig, getHttpParams, validateResponse, getThinkTime,
         securityEventProcessingRate, threatDetectionLatency, alertCorrelationTime,
         authenticationFailures, concurrentUsers } from '../config/config.js';

// Custom metrics for API testing
import { Counter, Gauge, Rate, Trend } from 'k6/metrics';
const apiEndpointCoverage = new Counter('api_endpoint_coverage');
const apiResponseSize = new Trend('api_response_size');
const apiErrorsByEndpoint = new Counter('api_errors_by_endpoint');
const authenticationLatency = new Trend('authentication_latency');

// Test configuration
const testConfig = getTestConfig(__ENV.TEST_TYPE || 'baseline');
export const options = testConfig.options;

// Comprehensive endpoint definitions with expected behaviors
const apiEndpoints = {
  authentication: [
    { method: 'POST', path: '/api/auth/login', requiresAuth: false, critical: true },
    { method: 'POST', path: '/api/auth/logout', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/auth/profile', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/auth/refresh', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/auth/change-password', requiresAuth: true, critical: false }
  ],
  alerts: [
    { method: 'GET', path: '/api/alerts', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/alerts/{id}', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/alerts', requiresAuth: true, critical: true },
    { method: 'PATCH', path: '/api/alerts/{id}', requiresAuth: true, critical: true },
    { method: 'DELETE', path: '/api/alerts/{id}', requiresAuth: true, critical: false },
    { method: 'GET', path: '/api/alerts/count', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/alerts/bulk/acknowledge', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/alerts/bulk/update', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/alerts/correlate', requiresAuth: true, critical: true }
  ],
  threats: [
    { method: 'GET', path: '/api/threats', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/threats/{id}', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/threats/{id}/analysis', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/threats/search', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/threats/feed/update', requiresAuth: true, critical: false }
  ],
  events: [
    { method: 'GET', path: '/api/events/stream', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/events/search', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/events/search/advanced', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/events/batch-ingest', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/events/{id}', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/events/processing-status', requiresAuth: true, critical: false }
  ],
  dashboard: [
    { method: 'GET', path: '/api/dashboard/summary', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/dashboard/widgets', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/dashboard/widgets', requiresAuth: true, critical: false },
    { method: 'GET', path: '/api/dashboard/metrics', requiresAuth: true, critical: true }
  ],
  analytics: [
    { method: 'POST', path: '/api/analytics/complex-search', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/analytics/trends', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/analytics/user-behavior', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/analytics/threat-landscape', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/analytics/bulk-correlation', requiresAuth: true, critical: true }
  ],
  reports: [
    { method: 'GET', path: '/api/reports/security-metrics', requiresAuth: true, critical: true },
    { method: 'POST', path: '/api/reports/export', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/reports/{id}', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/reports/{id}/download', requiresAuth: true, critical: false }
  ],
  admin: [
    { method: 'GET', path: '/api/admin/users', requiresAuth: true, critical: false, role: 'admin' },
    { method: 'GET', path: '/api/admin/config', requiresAuth: true, critical: false, role: 'admin' },
    { method: 'GET', path: '/api/admin/audit-logs', requiresAuth: true, critical: false, role: 'admin' },
    { method: 'GET', path: '/api/admin/health/detailed', requiresAuth: true, critical: false, role: 'admin' },
    { method: 'GET', path: '/api/admin/database/performance', requiresAuth: true, critical: false, role: 'admin' },
    { method: 'GET', path: '/api/admin/storage/metrics', requiresAuth: true, critical: false, role: 'admin' }
  ],
  metrics: [
    { method: 'GET', path: '/api/metrics/performance', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/metrics/system', requiresAuth: true, critical: true },
    { method: 'GET', path: '/api/metrics/security', requiresAuth: true, critical: true }
  ],
  health: [
    { method: 'GET', path: '/api/health', requiresAuth: false, critical: true },
    { method: 'GET', path: '/api/health/ready', requiresAuth: false, critical: true },
    { method: 'GET', path: '/api/health/live', requiresAuth: false, critical: true }
  ]
};

// Test data generators
const testDataGenerators = {
  loginPayload: () => ({
    username: `testuser_${Math.floor(Math.random() * 1000)}`,
    password: 'TestPassword123!',
    rememberMe: Math.random() > 0.5
  }),
  
  alertPayload: () => ({
    title: `Test Alert ${Date.now()}`,
    description: 'Automated load test generated alert',
    severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)],
    category: ['malware', 'intrusion', 'policy_violation', 'anomaly'][Math.floor(Math.random() * 4)],
    source_system: 'load-test-generator',
    metadata: {
      confidence: Math.random(),
      impact_score: Math.floor(Math.random() * 10) + 1
    }
  }),
  
  searchPayload: () => ({
    query: [
      'severity:HIGH',
      'event_type:login_failure',
      'source_ip:192.168.1.*',
      'threat_intel:true',
      'user_behavior:anomalous'
    ][Math.floor(Math.random() * 5)],
    timeRange: ['1h', '6h', '24h', '7d'][Math.floor(Math.random() * 4)],
    limit: [25, 50, 100, 200][Math.floor(Math.random() * 4)]
  }),
  
  bulkOperationPayload: (alertIds) => ({
    alertIds: alertIds.slice(0, Math.min(10, alertIds.length)),
    updates: {
      status: 'INVESTIGATING',
      assignee: `analyst_${Math.floor(Math.random() * 5) + 1}`,
      notes: `Bulk update via load test ${Date.now()}`
    }
  }),
  
  exportPayload: () => ({
    type: ['alerts', 'events', 'threats'][Math.floor(Math.random() * 3)],
    format: ['json', 'csv', 'xlsx'][Math.floor(Math.random() * 3)],
    filters: {
      timeRange: 'last_24h',
      severity: ['HIGH', 'CRITICAL']
    }
  })
};

export default function comprehensiveApiTest() {
  const env = testConfig.environment;
  const tokens = {
    analyst: env.auth.analyst,
    admin: env.auth.admin,
    viewer: env.auth.viewer
  };
  
  if (!tokens.analyst) {
    console.error('Required tokens not provided for environment:', env.name);
    authenticationFailures.add(1);
    return;
  }

  concurrentUsers.add(1);
  let testDataCache = {
    alertIds: [],
    threatIds: [],
    userId: null
  };

  // Test each endpoint category
  Object.keys(apiEndpoints).forEach(category => {
    group(`${category.toUpperCase()} API Endpoints`, function() {
      apiEndpoints[category].forEach(endpoint => {
        // Skip admin endpoints if no admin token
        if (endpoint.role === 'admin' && !tokens.admin) {
          return;
        }

        // Determine which token to use
        const token = endpoint.role === 'admin' ? tokens.admin : tokens.analyst;
        const headers = endpoint.requiresAuth ? getHttpParams(token) : { headers: { 'Content-Type': 'application/json' } };
        
        // Track endpoint coverage
        apiEndpointCoverage.add(1, { endpoint: `${endpoint.method} ${endpoint.path}`, category });

        // Generate test URL and payload
        let testUrl = `${env.baseUrl}${endpoint.path}`;
        let payload = null;
        
        // Handle parameterized URLs
        if (endpoint.path.includes('{id}')) {
          let testId = 'test-id-123';
          if (endpoint.path.includes('/alerts/') && testDataCache.alertIds.length > 0) {
            testId = testDataCache.alertIds[0];
          } else if (endpoint.path.includes('/threats/') && testDataCache.threatIds.length > 0) {
            testId = testDataCache.threatIds[0];
          }
          testUrl = testUrl.replace('{id}', testId);
        }

        // Generate appropriate payload for POST/PATCH requests
        if (['POST', 'PATCH'].includes(endpoint.method)) {
          if (endpoint.path.includes('/auth/login')) {
            payload = JSON.stringify(testDataGenerators.loginPayload());
          } else if (endpoint.path.includes('/alerts') && !endpoint.path.includes('bulk')) {
            payload = JSON.stringify(testDataGenerators.alertPayload());
          } else if (endpoint.path.includes('/search')) {
            payload = JSON.stringify(testDataGenerators.searchPayload());
          } else if (endpoint.path.includes('/bulk')) {
            payload = JSON.stringify(testDataGenerators.bulkOperationPayload(testDataCache.alertIds));
          } else if (endpoint.path.includes('/export')) {
            payload = JSON.stringify(testDataGenerators.exportPayload());
          } else {
            payload = JSON.stringify({ test: true, timestamp: Date.now() });
          }
        }

        // Execute request
        let response;
        const requestStart = Date.now();
        
        switch (endpoint.method) {
          case 'GET':
            response = http.get(testUrl, headers);
            break;
          case 'POST':
            response = http.post(testUrl, payload, headers);
            break;
          case 'PATCH':
            response = http.patch(testUrl, payload, headers);
            break;
          case 'DELETE':
            response = http.del(testUrl, null, headers);
            break;
          default:
            console.error(`Unsupported method: ${endpoint.method}`);
            return;
        }

        const requestLatency = Date.now() - requestStart;

        // Validate response
        const endpointName = `${endpoint.method} ${endpoint.path}`;
        const expectedStatus = endpoint.method === 'POST' && endpoint.path.includes('/api/alerts') ? 201 : 200;
        
        const validationResult = check(response, {
          [`${endpointName}: response code valid`]: (r) => [200, 201, 202, 204].includes(r.status),
          [`${endpointName}: response time acceptable`]: () => requestLatency < (endpoint.critical ? 2000 : 5000),
          [`${endpointName}: has response body`]: (r) => endpoint.method !== 'DELETE' ? r.body.length > 0 : true,
          [`${endpointName}: content type valid`]: (r) => !r.headers['Content-Type'] || r.headers['Content-Type'].includes('application/json')
        });

        if (!validationResult) {
          apiErrorsByEndpoint.add(1, { endpoint: endpointName, status: response.status });
        }

        // Track response metrics
        if (response.body) {
          apiResponseSize.add(response.body.length, { endpoint: endpointName });
        }

        // Cache useful data for subsequent tests
        if (response.status === 200 && response.body) {
          try {
            const responseData = JSON.parse(response.body);
            
            if (endpoint.path.includes('/alerts') && responseData.data && Array.isArray(responseData.data)) {
              testDataCache.alertIds = responseData.data.map(item => item.id).slice(0, 10);
            }
            
            if (endpoint.path.includes('/threats') && responseData.data && Array.isArray(responseData.data)) {
              testDataCache.threatIds = responseData.data.map(item => item.id).slice(0, 10);
            }
            
            if (endpoint.path.includes('/profile') && responseData.user) {
              testDataCache.userId = responseData.user.id;
            }
          } catch (e) {
            // Ignore JSON parsing errors for non-JSON responses
          }
        }

        // Track authentication-specific metrics
        if (endpoint.path.includes('/auth/')) {
          authenticationLatency.add(requestLatency);
        }

        // Security event processing tracking
        if (endpoint.critical && response.status === 200) {
          securityEventProcessingRate.add(1);
        } else if (endpoint.critical) {
          securityEventProcessingRate.add(0);
        }

        // Small pause between endpoint tests
        sleep(0.1);
      });

      // Pause between endpoint categories
      sleep(getThinkTime('quickAction'));
    });
  });

  group('Edge Cases and Error Handling', function() {
    // Test with invalid authentication
    const invalidAuthResponse = http.get(
      `${env.baseUrl}/api/alerts`,
      { headers: { 'Authorization': 'Bearer invalid-token' } }
    );
    
    check(invalidAuthResponse, {
      'Invalid auth returns 401': (r) => r.status === 401,
      'Auth error has proper format': (r) => r.body.includes('error') || r.body.includes('unauthorized')
    });

    // Test with malformed payloads
    const malformedPayloadResponse = http.post(
      `${env.baseUrl}/api/events/search`,
      '{"invalid":"json",,}',
      getHttpParams(tokens.analyst)
    );
    
    check(malformedPayloadResponse, {
      'Malformed payload returns 400': (r) => r.status === 400,
      'Error response is structured': (r) => r.headers['Content-Type']?.includes('application/json')
    });

    // Test rate limiting (if implemented)
    const rapidRequests = Array.from({ length: 20 }, () => 
      http.get(`${env.baseUrl}/api/health`, { timeout: '5s' })
    );
    
    const rateLimitHit = rapidRequests.some(r => r.status === 429);
    check({ rateLimitResponses: rapidRequests }, {
      'Rate limiting properly implemented': () => rateLimitHit || rapidRequests.every(r => r.status === 200)
    });

    // Test non-existent endpoints
    const notFoundResponse = http.get(`${env.baseUrl}/api/nonexistent-endpoint`);
    check(notFoundResponse, {
      'Non-existent endpoint returns 404': (r) => r.status === 404
    });
  });

  concurrentUsers.add(-1);
}

// Setup function
export function setup() {
  const totalEndpoints = Object.values(apiEndpoints).reduce((sum, endpoints) => sum + endpoints.length, 0);
  const criticalEndpoints = Object.values(apiEndpoints)
    .flat()
    .filter(endpoint => endpoint.critical).length;
  
  console.log(`Starting Comprehensive API Test on ${testConfig.environment.name} environment`);
  console.log(`Base URL: ${testConfig.environment.baseUrl}`);
  console.log(`Total endpoints to test: ${totalEndpoints}`);
  console.log(`Critical endpoints: ${criticalEndpoints}`);
  console.log(`Test Type: ${__ENV.TEST_TYPE || 'baseline'}`);
  
  return {
    environment: testConfig.environment,
    totalEndpoints,
    criticalEndpoints,
    startTime: Date.now()
  };
}

// Teardown function
export function teardown(data) {
  const duration = Date.now() - data.startTime;
  console.log(`Comprehensive API Test completed in ${duration}ms`);
  
  console.log('API Test Summary:');
  console.log(`- Environment: ${data.environment.name}`);
  console.log(`- Duration: ${Math.round(duration / 1000)}s`);
  console.log(`- Total endpoints tested: ${data.totalEndpoints}`);
  console.log(`- Critical endpoints: ${data.criticalEndpoints}`);
}