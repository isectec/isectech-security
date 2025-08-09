/**
 * Environment Setup for iSECTECH Protect Tests
 * Configures environment variables for testing
 */

// Test environment configuration
process.env.NODE_ENV = 'test';
process.env.NEXT_PUBLIC_APP_ENV = 'test';

// API configuration
process.env.NEXT_PUBLIC_API_URL = 'http://localhost:3001';
process.env.NEXT_PUBLIC_WS_URL = 'ws://localhost:3001';

// Security configuration
process.env.NEXT_PUBLIC_ENABLE_SECURITY_HEADERS = 'true';
process.env.NEXT_PUBLIC_CSP_NONCE = 'test-nonce';

// Feature flags for testing
process.env.NEXT_PUBLIC_ENABLE_ANALYTICS = 'false';
process.env.NEXT_PUBLIC_ENABLE_ERROR_REPORTING = 'false';
process.env.NEXT_PUBLIC_ENABLE_PERFORMANCE_MONITORING = 'false';

// Mock service configuration
process.env.MOCK_API_RESPONSES = 'true';
process.env.MOCK_WEBSOCKET = 'true';
process.env.MOCK_NOTIFICATIONS = 'true';

// Accessibility testing
process.env.ENABLE_A11Y_TESTING = 'true';
process.env.A11Y_VIOLATION_THRESHOLD = 'warn';

// Performance testing
process.env.PERFORMANCE_BUDGET_ENABLED = 'true';
process.env.LIGHTHOUSE_CI_ENABLED = 'false';

// Security testing
process.env.SECURITY_HEADERS_CHECK = 'true';
process.env.XSS_PROTECTION_CHECK = 'true';
process.env.CSRF_PROTECTION_CHECK = 'true';

// Test data configuration
process.env.USE_MOCK_DATA = 'true';
process.env.GENERATE_MOCK_SECURITY_EVENTS = 'true';
process.env.MOCK_USER_PERMISSIONS = 'admin';

// Logging configuration for tests
process.env.LOG_LEVEL = 'error';
process.env.SUPPRESS_TEST_WARNINGS = 'true';

// Timezone for consistent test results
process.env.TZ = 'UTC';

console.log('🔧 Test environment configured for iSECTECH Protect');
