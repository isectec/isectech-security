/**
 * Cross-Browser Testing Configuration for Security Dashboard
 * iSECTECH Protect - Multi-Browser Test Configuration
 */

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './__tests__/cross-browser',
  outputDir: './test-results/cross-browser',
  timeout: 60000,
  expect: {
    timeout: 10000,
  },
  fullyParallel: false, // Sequential for resource management
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: process.env.CI ? 2 : 1,
  reporter: [
    ['html', { outputFolder: './playwright-report/cross-browser' }],
    ['json', { outputFile: './test-results/cross-browser/results.json' }],
    ['junit', { outputFile: './test-results/cross-browser/junit.xml' }],
    ['list'],
  ],
  
  use: {
    baseURL: process.env.TEST_BASE_URL || 'http://localhost:3000',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    // Desktop Chrome - Primary security testing browser
    {
      name: 'Desktop Chrome',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
          extraHTTPHeaders: {
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
          },
        },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--enable-precise-memory-info',
            '--js-flags="--max-old-space-size=4096"',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--enable-logging',
            '--log-level=0',
          ],
        },
      },
      testMatch: ['**/*.spec.ts'],
    },

    // Desktop Firefox - Firefox-specific testing
    {
      name: 'Desktop Firefox',
      use: {
        ...devices['Desktop Firefox'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
        },
        launchOptions: {
          firefoxUserPrefs: {
            // Security preferences
            'security.tls.version.max': 4,
            'security.tls.version.min': 3,
            'dom.security.https_only_mode': false,
            'browser.cache.disk.enable': false,
            'browser.cache.memory.enable': false,
            
            // Performance preferences
            'dom.max_script_run_time': 0,
            'dom.max_chrome_script_run_time': 0,
            'browser.tabs.remote.autostart': false,
            'browser.sessionstore.resume_from_crash': false,
            
            // Privacy preferences for testing
            'privacy.trackingprotection.enabled': false,
            'dom.webnotifications.enabled': true,
            'dom.push.enabled': true,
          },
        },
      },
      testMatch: ['**/*.spec.ts'],
    },

    // Desktop Safari (WebKit) - Safari-specific testing
    {
      name: 'Desktop Safari',
      use: {
        ...devices['Desktop Safari'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
        },
      },
      testMatch: ['**/*.spec.ts'],
    },

    // Desktop Edge - Chromium-based Edge testing
    {
      name: 'Desktop Edge',
      use: {
        ...devices['Desktop Edge'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
        },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--enable-precise-memory-info',
            '--disable-background-timer-throttling',
          ],
        },
      },
      testMatch: ['**/*.spec.ts'],
    },

    // Mobile Chrome - Mobile security dashboard testing
    {
      name: 'Mobile Chrome',
      use: {
        ...devices['Pixel 5'],
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
        },
      },
      testMatch: ['**/mobile-*.spec.ts', '**/*mobile*.spec.ts'],
    },

    // Mobile Safari - iOS testing
    {
      name: 'Mobile Safari',
      use: {
        ...devices['iPhone 12'],
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
        },
      },
      testMatch: ['**/mobile-*.spec.ts', '**/*mobile*.spec.ts'],
    },

    // Tablet Chrome - Tablet-specific testing
    {
      name: 'Tablet Chrome',
      use: {
        ...devices['iPad Pro'],
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
        },
      },
      testMatch: ['**/tablet-*.spec.ts', '**/*tablet*.spec.ts'],
    },

    // High DPI Testing
    {
      name: 'High DPI Chrome',
      use: {
        ...devices['Desktop Chrome HiDPI'],
        viewport: { width: 1920, height: 1080 },
        deviceScaleFactor: 2,
        contextOptions: {
          permissions: ['clipboard-read', 'clipboard-write'],
        },
      },
      testMatch: ['**/high-dpi-*.spec.ts'],
    },

    // Security-focused browser configurations
    {
      name: 'Security Hardened Chrome',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1920, height: 1080 },
        contextOptions: {
          permissions: [], // No extra permissions
          strictSelectors: true,
          ignoreHTTPSErrors: false,
          extraHTTPHeaders: {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
          },
        },
        launchOptions: {
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-web-security',
            '--enable-strict-powerful-feature-restrictions',
            '--enable-strict-mixed-content-checking',
            '--disable-background-networking',
            '--disable-default-apps',
            '--disable-extensions',
          ],
        },
      },
      testMatch: ['**/security-*.spec.ts'],
    },

    // Legacy Browser Support Testing
    {
      name: 'Legacy Chrome',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1366, height: 768 },
        contextOptions: {
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
        },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--js-flags="--max-old-space-size=2048"', // Lower memory
          ],
        },
      },
      testMatch: ['**/legacy-*.spec.ts'],
    },
  ],

  // Global test configuration
  globalSetup: './test-setup/cross-browser-setup.ts',
  globalTeardown: './test-setup/cross-browser-teardown.ts',

  // Web server configuration for testing
  webServer: {
    command: 'npm run dev',
    port: 3000,
    reuseExistingServer: !process.env.CI,
    env: {
      NODE_ENV: 'test',
      NEXT_PUBLIC_ENV: 'test',
    },
  },
});