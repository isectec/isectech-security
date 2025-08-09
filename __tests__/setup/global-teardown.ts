/**
 * Global Test Teardown for iSECTECH Protect
 * Runs once after all tests
 */

import { GlobalConfig } from '@jest/types';

export default async function globalTeardown(globalConfig: GlobalConfig): Promise<void> {
  console.log('🧹 Cleaning up global test environment...');

  // Clean up test database
  if (process.env.TEST_TYPE === 'integration') {
    console.log('🗄️  Cleaning up test database...');
    // Clean up test database here if needed
  }

  // Stop mock services
  if (process.env.START_MOCK_SERVICES === 'true') {
    console.log('🛑 Stopping mock services...');
    // Stop mock API server, WebSocket server, etc.
  }

  // Clean up temporary files
  console.log('📁 Cleaning up temporary test files...');

  // Reset environment variables
  delete process.env.SECURITY_TEST_MODE;
  delete process.env.ENABLE_A11Y_TESTING;
  delete process.env.MOCK_EXTERNAL_APIS;

  console.log('✅ Global test cleanup complete');
}
