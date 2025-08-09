/**
 * Global Test Setup for iSECTECH Protect
 * Runs once before all tests
 */

import { GlobalConfig } from '@jest/types';

export default async function globalSetup(globalConfig: GlobalConfig): Promise<void> {
  console.log('🔧 Setting up global test environment for iSECTECH Protect...');

  // Set global test environment variables
  process.env.NODE_ENV = 'test';
  process.env.NEXT_PUBLIC_API_URL = 'http://localhost:3001';
  process.env.NEXT_PUBLIC_APP_ENV = 'test';

  // Mock external services
  process.env.MOCK_EXTERNAL_APIS = 'true';

  // Security test configuration
  process.env.SECURITY_TEST_MODE = 'true';
  process.env.ENABLE_A11Y_TESTING = 'true';

  // Performance test configuration
  process.env.PERFORMANCE_BUDGET_JS = '250';
  process.env.PERFORMANCE_BUDGET_CSS = '100';

  // Database setup for integration tests
  if (process.env.TEST_TYPE === 'integration') {
    console.log('🗄️  Setting up test database...');
    // Initialize test database here if needed
  }

  // Start mock services if needed
  if (process.env.START_MOCK_SERVICES === 'true') {
    console.log('🚀 Starting mock services...');
    // Start mock API server, WebSocket server, etc.
  }

  console.log('✅ Global test setup complete');
}
