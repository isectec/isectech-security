/**
 * Playwright Global Teardown for iSECTECH Protect
 * Cleans up test environment
 */

import { FullConfig } from '@playwright/test';
import path from 'path';

async function globalTeardown(config: FullConfig) {
  console.log('🧹 Cleaning up Playwright test environment...');

  try {
    // Clean up authentication files
    const fs = await import('fs/promises');
    const authDir = path.join(__dirname, '.auth');

    try {
      await fs.rm(authDir, { recursive: true, force: true });
      console.log('✅ Authentication files cleaned up');
    } catch (error) {
      console.warn('⚠️  Failed to clean up auth files:', error);
    }

    // Clean up temporary test files
    const testResultsDir = path.join(process.cwd(), 'test-results');
    try {
      // Only clean up if not in CI to preserve artifacts
      if (!process.env.CI) {
        const files = await fs.readdir(testResultsDir).catch(() => []);
        for (const file of files) {
          if (file.startsWith('temp-')) {
            await fs.rm(path.join(testResultsDir, file), { force: true });
          }
        }
      }
    } catch (error) {
      console.warn('⚠️  Failed to clean up temp files:', error);
    }
  } catch (error) {
    console.error('❌ Error during teardown:', error);
  }

  console.log('✅ Playwright global teardown complete');
}

export default globalTeardown;
