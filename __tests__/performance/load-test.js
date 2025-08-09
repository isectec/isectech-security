/**
 * K6 Load Testing Configuration
 * iSECTECH Protect - Security Platform Load Testing
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics for security operations
const securityEventProcessingTime = new Trend('security_event_processing_time');
const alertGenerationRate = new Rate('alert_generation_rate');
const threatDetectionCounter = new Counter('threat_detection_count');
const authFailureRate = new Rate('auth_failure_rate');

// Test configuration for different scenarios
export const options = {
  scenarios: {
    // Standard user load - security analysts
    security_analysts: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 100 },  // Ramp up to 100 analysts
        { duration: '5m', target: 100 },  // Stay at 100 analysts
        { duration: '2m', target: 200 },  // Ramp up to 200 analysts
        { duration: '5m', target: 200 },  // Stay at 200 analysts
        { duration: '2m', target: 0 },    // Ramp down
      ],
      tags: { test_type: 'security_analysts' },
    },

    // Peak load simulation - incident response
    incident_response: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 50 },   // Quick ramp up during incident
        { duration: '10m', target: 500 }, // High load during active incident
        { duration: '1m', target: 0 },    // Incident resolved
      ],
      startTime: '30s',
      tags: { test_type: 'incident_response' },
    },

    // Stress testing - system limits
    stress_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 100,
      maxVUs: 1000,
      stages: [
        { duration: '2m', target: 100 },  // 100 requests per second
        { duration: '5m', target: 500 },  // 500 requests per second
        { duration: '2m', target: 1000 }, // 1000 requests per second
        { duration: '2m', target: 0 },    // Ramp down
      ],
      startTime: '5m',
      tags: { test_type: 'stress_test' },
    },

    // Spike testing - sudden traffic bursts
    spike_test: {
      executor: 'ramping-vus',
      startVUs: 100,
      stages: [
        { duration: '10s', target: 100 },
        { duration: '30s', target: 2000 }, // Sudden spike
        { duration: '10s', target: 100 },
        { duration: '30s', target: 2000 }, // Another spike
        { duration: '10s', target: 100 },
      ],
      startTime: '10m',
      tags: { test_type: 'spike_test' },
    },
  },

  // Performance thresholds
  thresholds: {
    // Response time requirements
    'http_req_duration': ['p(95)<500', 'p(99)<1000'],
    'http_req_duration{endpoint:dashboard}': ['p(95)<200'],
    'http_req_duration{endpoint:alerts}': ['p(95)<300'],
    'http_req_duration{endpoint:threats}': ['p(95)<400'],
    
    // Success rate requirements
    'http_req_failed': ['rate<0.01'], // Less than 1% failure rate
    'http_req_failed{critical:true}': ['rate<0.001'], // Less than 0.1% for critical endpoints
    
    // Security-specific thresholds
    'security_event_processing_time': ['p(95)<1000'],
    'alert_generation_rate': ['rate>0.8'], // 80% of security events should generate alerts
    'auth_failure_rate': ['rate<0.05'], // Less than 5% authentication failures
  },
};

// Test data and configuration
const BASE_URL = __ENV.API_BASE_URL || 'http://localhost:3000';
const API_BASE_URL = __ENV.API_URL || 'http://localhost:8080';

// Authentication tokens for different user types
const AUTH_TOKENS = {
  analyst: __ENV.ANALYST_TOKEN || 'test-analyst-token',
  admin: __ENV.ADMIN_TOKEN || 'test-admin-token',
  viewer: __ENV.VIEWER_TOKEN || 'test-viewer-token',
};

// Test user sessions
let userSession = null;

export function setup() {
  console.log('🚀 Starting iSECTECH Load Testing');
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`API URL: ${API_BASE_URL}`);
  
  // Warm up the system
  const warmupResponse = http.get(`${BASE_URL}/api/health`);
  check(warmupResponse, {
    'warmup successful': (r) => r.status === 200,
  });
  
  return { baseUrl: BASE_URL, apiUrl: API_BASE_URL };
}

export default function (data) {
  const testType = __ENV.K6_SCENARIO || 'security_analysts';
  
  switch (testType) {
    case 'security_analysts':
      securityAnalystWorkflow(data);
      break;
    case 'incident_response':
      incidentResponseWorkflow(data);
      break;
    case 'stress_test':
      stressTestWorkflow(data);
      break;
    case 'spike_test':
      spikeTestWorkflow(data);
      break;
    default:
      securityAnalystWorkflow(data);
  }
  
  sleep(1);
}

function securityAnalystWorkflow(data) {
  const token = AUTH_TOKENS.analyst;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  // 1. Load security dashboard
  const dashboardStart = Date.now();
  const dashboardResponse = http.get(`${data.baseUrl}/dashboard`, {
    headers,
    tags: { endpoint: 'dashboard', critical: 'true' },
  });
  
  check(dashboardResponse, {
    'dashboard loads successfully': (r) => r.status === 200,
    'dashboard loads within SLA': (r) => r.timings.duration < 2000,
  });

  // 2. Fetch security alerts
  const alertsResponse = http.get(`${data.apiUrl}/api/alerts`, {
    headers,
    tags: { endpoint: 'alerts', critical: 'true' },
  });
  
  check(alertsResponse, {
    'alerts fetch successfully': (r) => r.status === 200,
    'alerts response time acceptable': (r) => r.timings.duration < 300,
  });

  // 3. Process security events
  const eventProcessingStart = Date.now();
  const eventsResponse = http.get(`${data.apiUrl}/api/events?limit=50`, {
    headers,
    tags: { endpoint: 'events' },
  });
  
  const processingTime = Date.now() - eventProcessingStart;
  securityEventProcessingTime.add(processingTime);
  
  check(eventsResponse, {
    'events fetch successfully': (r) => r.status === 200,
  });

  // 4. Threat intelligence lookup
  const threatResponse = http.get(`${data.apiUrl}/api/threats?indicators=ip:192.168.1.100`, {
    headers,
    tags: { endpoint: 'threats' },
  });
  
  check(threatResponse, {
    'threat lookup successful': (r) => r.status === 200,
  });

  // 5. Generate security alert (20% of the time)
  if (Math.random() < 0.2) {
    const alertData = {
      type: 'SUSPICIOUS_ACTIVITY',
      severity: 'HIGH',
      source_ip: '192.168.1.100',
      description: 'Load test generated alert',
      timestamp: new Date().toISOString(),
    };

    const createAlertResponse = http.post(`${data.apiUrl}/api/alerts`, JSON.stringify(alertData), {
      headers,
      tags: { endpoint: 'create_alert', critical: 'true' },
    });
    
    const alertCreated = check(createAlertResponse, {
      'alert created successfully': (r) => r.status === 201,
    });
    
    alertGenerationRate.add(alertCreated);
    if (alertCreated) {
      threatDetectionCounter.add(1);
    }
  }
}

function incidentResponseWorkflow(data) {
  const token = AUTH_TOKENS.admin;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  // High-frequency operations during incident response
  
  // 1. Real-time alert monitoring
  const alertsResponse = http.get(`${data.apiUrl}/api/alerts?status=ACTIVE&severity=CRITICAL`, {
    headers,
    tags: { endpoint: 'critical_alerts', critical: 'true' },
  });
  
  check(alertsResponse, {
    'critical alerts retrieved': (r) => r.status === 200,
  });

  // 2. Incident creation and updates
  if (Math.random() < 0.1) { // 10% chance to create incident
    const incidentData = {
      title: 'Security Incident - Load Test',
      severity: 'CRITICAL',
      category: 'SECURITY_BREACH',
      description: 'Automated incident for load testing',
      alerts: ['alert-123', 'alert-456'],
    };

    const incidentResponse = http.post(`${data.apiUrl}/api/incidents`, JSON.stringify(incidentData), {
      headers,
      tags: { endpoint: 'create_incident', critical: 'true' },
    });
    
    check(incidentResponse, {
      'incident created': (r) => r.status === 201,
    });
  }

  // 3. Bulk alert operations
  const bulkUpdateData = {
    alertIds: ['alert-1', 'alert-2', 'alert-3'],
    action: 'ACKNOWLEDGE',
    assignee: 'analyst-123',
  };

  const bulkResponse = http.put(`${data.apiUrl}/api/alerts/bulk`, JSON.stringify(bulkUpdateData), {
    headers,
    tags: { endpoint: 'bulk_update' },
  });
  
  check(bulkResponse, {
    'bulk update successful': (r) => r.status === 200,
  });
}

function stressTestWorkflow(data) {
  // Simplified workflow for stress testing
  const token = AUTH_TOKENS.viewer;
  
  const response = http.get(`${data.apiUrl}/api/health`, {
    headers: { 'Authorization': `Bearer ${token}` },
    tags: { endpoint: 'health_check' },
  });
  
  check(response, {
    'system responsive under stress': (r) => r.status === 200,
  });
}

function spikeTestWorkflow(data) {
  // Mixed operations during spike
  const operations = [
    () => http.get(`${data.baseUrl}/dashboard`),
    () => http.get(`${data.apiUrl}/api/alerts`),
    () => http.get(`${data.apiUrl}/api/threats`),
    () => http.get(`${data.apiUrl}/api/events`),
  ];
  
  const randomOperation = operations[Math.floor(Math.random() * operations.length)];
  const response = randomOperation();
  
  check(response, {
    'spike operation successful': (r) => r.status === 200,
  });
}

export function teardown(data) {
  console.log('🏁 Load testing completed');
  console.log('Check the results for performance metrics and SLA compliance');
}