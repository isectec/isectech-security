/**
 * Playwright Configuration for iSECTECH Protect
 * Production-grade E2E testing setup for cybersecurity frontend
 */

import { defineConfig, devices } from '@playwright/test';
import path from 'path';

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
  testDir: './playwright',

  /* Run tests in files in parallel */
  fullyParallel: true,

  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,

  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,

  /* Optimized parallel execution for security testing */
  workers: process.env.CI ? 4 : 6,

  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [
    [
      'html',
      {
        outputFolder: 'playwright-report',
        open: process.env.CI ? 'never' : 'on-failure',
      },
    ],
    ['json', { outputFile: 'test-results/playwright-results.json' }],
    ['junit', { outputFile: 'test-results/playwright-junit.xml' }],
    process.env.CI ? ['github'] : ['line'],
  ],

  /* Shared settings for all the projects below. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000',

    /* Collect trace when retrying the failed test. */
    trace: 'on-first-retry',

    /* Capture screenshots on failure */
    screenshot: 'only-on-failure',

    /* Capture video on failure */
    video: 'retain-on-failure',

    /* Browser context options */
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,

    /* Security headers */
    extraHTTPHeaders: {
      'X-Security-Test': 'true',
      'User-Agent': 'iSECTECH-Playwright-Tests/1.0',
    },
  },

  /* Timeout configuration - enhanced for security operations */
  timeout: 60000,
  expect: {
    timeout: 15000,
  },

  /* Global setup and teardown */
  globalSetup: path.resolve(__dirname, 'playwright/global-setup.ts'),
  globalTeardown: path.resolve(__dirname, 'playwright/global-teardown.ts'),

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/,
    },

    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
    },

    {
      name: 'firefox',
      use: {
        ...devices['Desktop Firefox'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
    },

    {
      name: 'webkit',
      use: {
        ...devices['Desktop Safari'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
    },

    /* Security-focused mobile testing */
    {
      name: 'Mobile Chrome',
      use: {
        ...devices['Pixel 5'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
    },

    {
      name: 'Mobile Safari',
      use: {
        ...devices['iPhone 12'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
    },

    /* Security testing with different contexts */
    {
      name: 'security-analyst',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/analyst.json',
      },
      dependencies: ['setup'],
      testMatch: '**/*analyst*.spec.ts',
    },

    {
      name: 'admin-user',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/admin.json',
      },
      dependencies: ['setup'],
      testMatch: '**/*admin*.spec.ts',
    },

    /* Performance testing */
    {
      name: 'performance',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
      testMatch: '**/*performance*.spec.ts',
      metadata: {
        performance: true,
      },
    },

    /* Accessibility testing */
    {
      name: 'accessibility',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
      testMatch: '**/*accessibility*.spec.ts',
    },

    /* Visual regression testing */
    {
      name: 'visual',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
      testMatch: '**/*visual*.spec.ts',
    },

    /* Security penetration testing */
    {
      name: 'penetration-testing',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/admin.json',
        extraHTTPHeaders: {
          'X-Security-Test': 'penetration',
          'X-Test-Mode': 'security-validation',
          'User-Agent': 'iSECTECH-Security-Tests/1.0',
        },
      },
      dependencies: ['setup'],
      testMatch: '**/*penetration*.spec.ts',
      timeout: 120000, // Extended timeout for security tests
    },

    /* Compliance validation testing */
    {
      name: 'compliance',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/admin.json',
        extraHTTPHeaders: {
          'X-Compliance-Test': 'true',
          'X-Audit-Mode': 'validation',
        },
      },
      dependencies: ['setup'],
      testMatch: '**/*compliance*.spec.ts',
    },
  ],

  /* Output configuration */
  outputDir: 'test-results/',

  /* Web Server for development */
  webServer: process.env.CI
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://localhost:3000',
        reuseExistingServer: !process.env.CI,
        timeout: 120000,
      },
});
