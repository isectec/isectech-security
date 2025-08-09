// k6 Configuration for iSECTECH Security Platform
// Production-grade load testing configuration with security focus

import { check, group, sleep } from 'k6';
import { Counter, Gauge, Rate, Trend } from 'k6/metrics';

// Custom metrics for security platform monitoring
export const securityEventProcessingRate = new Rate('security_event_processing_success');
export const threatDetectionLatency = new Trend('threat_detection_latency');
export const alertCorrelationTime = new Trend('alert_correlation_time');
export const authenticationFailures = new Counter('authentication_failures');
export const concurrentUsers = new Gauge('concurrent_users');

// Environment configuration
const config = {
  // Base URLs for different environments
  environments: {
    development: 'http://localhost:3000',
    staging: 'https://staging.isectech.com',
    production: 'https://api.isectech.com'
  },
  
  // Authentication tokens by environment and role
  auth: {
    development: {
      analyst: __ENV.DEV_ANALYST_TOKEN || 'dev-analyst-token',
      admin: __ENV.DEV_ADMIN_TOKEN || 'dev-admin-token',
      viewer: __ENV.DEV_VIEWER_TOKEN || 'dev-viewer-token'
    },
    staging: {
      analyst: __ENV.STAGING_ANALYST_TOKEN,
      admin: __ENV.STAGING_ADMIN_TOKEN,
      viewer: __ENV.STAGING_VIEWER_TOKEN
    },
    production: {
      analyst: __ENV.PROD_ANALYST_TOKEN,
      admin: __ENV.PROD_ADMIN_TOKEN,
      viewer: __ENV.PROD_VIEWER_TOKEN
    }
  },

  // Performance thresholds by test type
  thresholds: {
    baseline: {
      'http_req_duration': ['p(95)<500', 'p(99)<1000'],
      'http_req_failed': ['rate<0.01'],
      'security_event_processing_success': ['rate>0.99'],
      'threat_detection_latency': ['p(95)<300'],
      'alert_correlation_time': ['p(95)<200']
    },
    stress: {
      'http_req_duration': ['p(95)<1000', 'p(99)<2000'],
      'http_req_failed': ['rate<0.05'],
      'security_event_processing_success': ['rate>0.95'],
      'threat_detection_latency': ['p(95)<500'],
      'alert_correlation_time': ['p(95)<400']
    },
    spike: {
      'http_req_duration': ['p(95)<1500', 'p(99)<3000'],
      'http_req_failed': ['rate<0.10'],
      'security_event_processing_success': ['rate>0.90'],
      'threat_detection_latency': ['p(95)<800'],
      'alert_correlation_time': ['p(95)<600']
    }
  },

  // Load patterns for different test scenarios
  loadPatterns: {
    baseline: {
      executor: 'constant-vus',
      vus: 10,
      duration: '5m',
    },
    rampUp: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 20 },
        { duration: '5m', target: 20 },
        { duration: '2m', target: 40 },
        { duration: '5m', target: 40 },
        { duration: '2m', target: 0 }
      ],
    },
    stress: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 100 },
        { duration: '5m', target: 100 },
        { duration: '2m', target: 200 },
        { duration: '5m', target: 200 },
        { duration: '10m', target: 0 }
      ],
    },
    spike: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 100 },
        { duration: '1m', target: 100 },
        { duration: '10s', target: 1400 },
        { duration: '3m', target: 1400 },
        { duration: '10s', target: 100 },
        { duration: '3m', target: 100 },
        { duration: '10s', target: 0 }
      ],
    },
    endurance: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30m',
    }
  }
};

// Get current environment
export function getEnvironment() {
  const env = __ENV.ENVIRONMENT || 'development';
  return {
    name: env,
    baseUrl: config.environments[env],
    auth: config.auth[env]
  };
}

// Get test configuration based on test type
export function getTestConfig(testType = 'baseline') {
  const env = getEnvironment();
  const pattern = config.loadPatterns[testType] || config.loadPatterns.baseline;
  const thresholds = config.thresholds[testType] || config.thresholds.baseline;
  
  return {
    environment: env,
    options: {
      scenarios: {
        [testType]: pattern
      },
      thresholds: thresholds,
      summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
      summaryTimeUnit: 'ms',
    }
  };
}

// Common HTTP parameters for all requests
export function getHttpParams(token, additionalHeaders = {}) {
  return {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'k6-isectech-loadtest/1.0',
      'X-Test-Run': `${__ENV.TEST_RUN_ID || 'local'}`,
      'X-Test-Environment': __ENV.ENVIRONMENT || 'development',
      ...additionalHeaders
    },
    timeout: '30s',
    tags: {
      test_type: __ENV.TEST_TYPE || 'baseline',
      environment: __ENV.ENVIRONMENT || 'development'
    }
  };
}

// Utility function for common response validation
export function validateResponse(response, endpoint, expectedStatus = 200) {
  const checks = check(response, {
    [`${endpoint}: status is ${expectedStatus}`]: (r) => r.status === expectedStatus,
    [`${endpoint}: response time < 30s`]: (r) => r.timings.duration < 30000,
    [`${endpoint}: has valid JSON`]: (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch (e) {
        return false;
      }
    },
    [`${endpoint}: content-type is JSON`]: (r) => 
      r.headers['Content-Type'] && r.headers['Content-Type'].includes('application/json')
  });

  if (!checks) {
    console.error(`Validation failed for ${endpoint}: ${response.status} - ${response.body}`);
  }

  return checks;
}

// Think time calculator based on user behavior patterns
export function getThinkTime(operation = 'default') {
  const thinkTimes = {
    quickAction: () => Math.random() * 2 + 1,        // 1-3 seconds
    analysis: () => Math.random() * 5 + 3,           // 3-8 seconds
    reading: () => Math.random() * 10 + 5,           // 5-15 seconds
    reporting: () => Math.random() * 20 + 10,        // 10-30 seconds
    default: () => Math.random() * 3 + 1             // 1-4 seconds
  };
  
  return thinkTimes[operation] ? thinkTimes[operation]() : thinkTimes.default();
}

export default config;