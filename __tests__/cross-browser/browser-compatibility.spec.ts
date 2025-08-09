/**
 * Cross-Browser Compatibility Testing for Security Dashboard
 * iSECTECH Protect - Multi-Browser Security Platform Validation
 */

import { test, expect, devices } from '@playwright/test';

const BROWSERS = ['chromium', 'firefox', 'webkit'] as const;
const SECURITY_DASHBOARD_ROUTES = [
  '/dashboard',
  '/alerts',
  '/threats',
  '/threats/map',
  '/incidents',
  '/reports',
  '/search',
  '/settings/security',
] as const;

interface BrowserCompatibilityResult {
  browser: string;
  route: string;
  renderTime: number;
  jsErrors: string[];
  cssIssues: string[];
  securityFeatures: {
    csp: boolean;
    https: boolean;
    secureHeaders: boolean;
  };
  passed: boolean;
}

class CrossBrowserTester {
  private results: BrowserCompatibilityResult[] = [];

  async testBrowserCompatibility(browserName: string, route: string, page: any): Promise<BrowserCompatibilityResult> {
    const result: BrowserCompatibilityResult = {
      browser: browserName,
      route,
      renderTime: 0,
      jsErrors: [],
      cssIssues: [],
      securityFeatures: {
        csp: false,
        https: false,
        secureHeaders: false,
      },
      passed: false,
    };

    // Capture JS errors
    page.on('pageerror', (error: Error) => {
      result.jsErrors.push(error.message);
    });

    // Capture console errors
    page.on('console', (msg: any) => {
      if (msg.type() === 'error') {
        result.jsErrors.push(msg.text());
      }
    });

    // Navigate and measure render time
    const startTime = performance.now();
    
    try {
      await page.goto(`http://localhost:3000${route}`, { 
        waitUntil: 'networkidle',
        timeout: 30000 
      });
      
      // Wait for security dashboard to be fully loaded
      await page.waitForSelector('[data-testid="page-loaded"]', { timeout: 10000 });
      
      result.renderTime = performance.now() - startTime;

      // Check security features
      result.securityFeatures.https = page.url().startsWith('https://');
      
      // Check CSP header
      const response = await page.goto(`http://localhost:3000${route}`);
      const headers = response?.headers();
      result.securityFeatures.csp = !!(headers && headers['content-security-policy']);
      result.securityFeatures.secureHeaders = !!(
        headers && 
        headers['x-frame-options'] && 
        headers['x-content-type-options']
      );

      // Check for CSS issues
      const cssErrors = await page.evaluate(() => {
        const errors = [];
        const computedStyles = window.getComputedStyle(document.body);
        
        // Check for common CSS issues
        if (computedStyles.display === 'none') {
          errors.push('Body element is hidden');
        }
        
        // Check for missing critical styles
        const criticalElements = document.querySelectorAll('[data-testid^="security-"]');
        criticalElements.forEach((element, index) => {
          const styles = window.getComputedStyle(element as Element);
          if (styles.visibility === 'hidden' || styles.opacity === '0') {
            errors.push(`Security element ${index} is not visible`);
          }
        });
        
        return errors;
      });
      
      result.cssIssues = cssErrors;
      result.passed = result.jsErrors.length === 0 && result.cssIssues.length === 0 && result.renderTime < 5000;

    } catch (error) {
      result.jsErrors.push(error instanceof Error ? error.message : String(error));
      result.passed = false;
    }

    this.results.push(result);
    return result;
  }

  getResults(): BrowserCompatibilityResult[] {
    return this.results;
  }

  generateCompatibilityReport(): string {
    const totalTests = this.results.length;
    const passedTests = this.results.filter(r => r.passed).length;
    const failedTests = totalTests - passedTests;

    let report = `\n🌐 Cross-Browser Compatibility Report\n`;
    report += `==========================================\n`;
    report += `Total Tests: ${totalTests}\n`;
    report += `Passed: ${passedTests} (${((passedTests/totalTests) * 100).toFixed(1)}%)\n`;
    report += `Failed: ${failedTests} (${((failedTests/totalTests) * 100).toFixed(1)}%)\n\n`;

    // Browser-specific results
    BROWSERS.forEach(browser => {
      const browserResults = this.results.filter(r => r.browser === browser);
      const browserPassed = browserResults.filter(r => r.passed).length;
      
      report += `📱 ${browser.toUpperCase()}:\n`;
      report += `  Passed: ${browserPassed}/${browserResults.length}\n`;
      report += `  Avg Render Time: ${(browserResults.reduce((sum, r) => sum + r.renderTime, 0) / browserResults.length).toFixed(0)}ms\n`;
      
      const browserFailures = browserResults.filter(r => !r.passed);
      if (browserFailures.length > 0) {
        report += `  ❌ Failed Routes:\n`;
        browserFailures.forEach(failure => {
          report += `    ${failure.route}: ${failure.jsErrors.length} JS errors, ${failure.cssIssues.length} CSS issues\n`;
        });
      }
      report += `\n`;
    });

    // Route-specific results
    const uniqueRoutes = [...new Set(this.results.map(r => r.route))];
    report += `📊 Route Performance:\n`;
    uniqueRoutes.forEach(route => {
      const routeResults = this.results.filter(r => r.route === route);
      const avgRenderTime = routeResults.reduce((sum, r) => sum + r.renderTime, 0) / routeResults.length;
      const routePassed = routeResults.filter(r => r.passed).length;
      
      report += `  ${route}: ${avgRenderTime.toFixed(0)}ms avg, ${routePassed}/${routeResults.length} browsers\n`;
    });

    return report;
  }
}

// Configure browsers with security-specific settings
const BROWSER_CONFIGS = {
  chromium: {
    launchOptions: {
      args: [
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor',
        '--enable-precise-memory-info',
        '--js-flags="--max-old-space-size=4096"',
      ],
    },
    contextOptions: {
      ignoreHTTPSErrors: false,
      extraHTTPHeaders: {
        'Accept-Language': 'en-US,en;q=0.9',
      },
    },
  },
  firefox: {
    launchOptions: {
      firefoxUserPrefs: {
        'security.tls.version.max': 4,
        'security.tls.version.min': 3,
        'dom.security.https_only_mode': false,
        'browser.cache.disk.enable': false,
        'browser.cache.memory.enable': false,
      },
    },
    contextOptions: {
      ignoreHTTPSErrors: false,
    },
  },
  webkit: {
    launchOptions: {},
    contextOptions: {
      ignoreHTTPSErrors: false,
    },
  },
};

test.describe('🌐 Cross-Browser Security Dashboard Compatibility', () => {
  let tester: CrossBrowserTester;

  test.beforeEach(() => {
    tester = new CrossBrowserTester();
  });

  // Test each browser individually
  BROWSERS.forEach(browserName => {
    test.describe(`${browserName.toUpperCase()} Browser Tests`, () => {
      
      SECURITY_DASHBOARD_ROUTES.forEach(route => {
        test(`should render ${route} correctly in ${browserName}`, async ({ playwright }) => {
          const browser = await playwright[browserName].launch(BROWSER_CONFIGS[browserName].launchOptions);
          const context = await browser.newContext(BROWSER_CONFIGS[browserName].contextOptions);
          const page = await context.newPage();

          // Login first
          await page.goto('http://localhost:3000/login');
          await page.fill('[data-testid="email-input"]', 'test@isectech.com');
          await page.fill('[data-testid="password-input"]', 'TestPassword123!');
          await page.click('[data-testid="login-button"]');
          await page.waitForURL('**/dashboard');

          const result = await tester.testBrowserCompatibility(browserName, route, page);

          // Assertions
          expect(result.passed).toBe(true);
          expect(result.renderTime).toBeLessThan(8000); // Max 8s render time
          expect(result.jsErrors.length).toBe(0);
          expect(result.cssIssues.length).toBe(0);

          // Security-specific checks
          if (route.includes('security') || route.includes('alerts')) {
            expect(result.securityFeatures.csp).toBe(true);
          }

          await browser.close();
        });
      });

      test(`should handle security features correctly in ${browserName}`, async ({ playwright }) => {
        const browser = await playwright[browserName].launch(BROWSER_CONFIGS[browserName].launchOptions);
        const context = await browser.newContext(BROWSER_CONFIGS[browserName].contextOptions);
        const page = await context.newPage();

        // Test security-specific functionality
        await page.goto('http://localhost:3000/login');
        await page.fill('[data-testid="email-input"]', 'test@isectech.com');
        await page.fill('[data-testid="password-input"]', 'TestPassword123!');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL('**/dashboard');

        // Test WebCrypto API support
        const cryptoSupport = await page.evaluate(() => {
          return typeof window.crypto !== 'undefined' && 
                 typeof window.crypto.subtle !== 'undefined';
        });
        expect(cryptoSupport).toBe(true);

        // Test WebSocket support for real-time alerts
        const websocketSupport = await page.evaluate(() => {
          return typeof WebSocket !== 'undefined';
        });
        expect(websocketSupport).toBe(true);

        // Test Local Storage for session management
        const localStorageSupport = await page.evaluate(() => {
          try {
            localStorage.setItem('test', 'test');
            localStorage.removeItem('test');
            return true;
          } catch {
            return false;
          }
        });
        expect(localStorageSupport).toBe(true);

        // Test IndexedDB for offline capabilities
        const indexedDBSupport = await page.evaluate(() => {
          return typeof indexedDB !== 'undefined';
        });
        expect(indexedDBSupport).toBe(true);

        await browser.close();
      });

      test(`should handle responsive design in ${browserName}`, async ({ playwright }) => {
        const browser = await playwright[browserName].launch(BROWSER_CONFIGS[browserName].launchOptions);
        const context = await browser.newContext(BROWSER_CONFIGS[browserName].contextOptions);
        const page = await context.newPage();

        // Test different viewport sizes
        const viewports = [
          { width: 1920, height: 1080, name: 'Desktop Large' },
          { width: 1366, height: 768, name: 'Desktop Standard' },
          { width: 1024, height: 768, name: 'Tablet Landscape' },
          { width: 768, height: 1024, name: 'Tablet Portrait' },
          { width: 375, height: 667, name: 'Mobile' },
        ];

        await page.goto('http://localhost:3000/login');
        await page.fill('[data-testid="email-input"]', 'test@isectech.com');
        await page.fill('[data-testid="password-input"]', 'TestPassword123!');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL('**/dashboard');

        for (const viewport of viewports) {
          await page.setViewportSize({ width: viewport.width, height: viewport.height });
          await page.reload();
          await page.waitForSelector('[data-testid="dashboard-loaded"]');

          // Check that critical security elements are visible
          const criticalElements = [
            '[data-testid="security-alerts-widget"]',
            '[data-testid="threat-map-widget"]',
            '[data-testid="system-health-widget"]',
            '[data-testid="navigation-menu"]',
          ];

          for (const selector of criticalElements) {
            const element = page.locator(selector);
            if (await element.count() > 0) {
              await expect(element).toBeVisible();
            }
          }

          // Check for horizontal scroll issues
          const hasHorizontalScroll = await page.evaluate(() => {
            return document.documentElement.scrollWidth > document.documentElement.clientWidth;
          });

          // Allow horizontal scroll only on mobile
          if (viewport.width >= 768) {
            expect(hasHorizontalScroll).toBe(false);
          }
        }

        await browser.close();
      });
    });
  });

  test('should maintain feature parity across all browsers', async ({ playwright }) => {
    const featureTests = [
      {
        name: 'Alert Creation',
        test: async (page: any) => {
          await page.goto('http://localhost:3000/alerts');
          await page.click('[data-testid="create-alert-button"]');
          await page.waitForSelector('[data-testid="alert-form"]');
          return true;
        },
      },
      {
        name: 'Threat Map Interaction',
        test: async (page: any) => {
          await page.goto('http://localhost:3000/threats/map');
          await page.waitForSelector('[data-testid="threat-map-loaded"]');
          await page.click('[data-testid="threat-indicator"]:first-child');
          return await page.locator('[data-testid="threat-details-modal"]').isVisible();
        },
      },
      {
        name: 'Search Functionality',
        test: async (page: any) => {
          await page.goto('http://localhost:3000/search');
          await page.fill('[data-testid="search-input"]', 'malware');
          await page.click('[data-testid="search-button"]');
          await page.waitForSelector('[data-testid="search-results"]');
          return true;
        },
      },
      {
        name: 'Report Generation',
        test: async (page: any) => {
          await page.goto('http://localhost:3000/reports');
          await page.click('[data-testid="generate-report-button"]');
          await page.waitForSelector('[data-testid="report-options"]');
          return true;
        },
      },
    ];

    const results: { [key: string]: { [key: string]: boolean } } = {};

    for (const browserName of BROWSERS) {
      results[browserName] = {};
      
      const browser = await playwright[browserName].launch(BROWSER_CONFIGS[browserName].launchOptions);
      const context = await browser.newContext(BROWSER_CONFIGS[browserName].contextOptions);
      const page = await context.newPage();

      // Login
      await page.goto('http://localhost:3000/login');
      await page.fill('[data-testid="email-input"]', 'test@isectech.com');
      await page.fill('[data-testid="password-input"]', 'TestPassword123!');
      await page.click('[data-testid="login-button"]');
      await page.waitForURL('**/dashboard');

      for (const featureTest of featureTests) {
        try {
          const result = await featureTest.test(page);
          results[browserName][featureTest.name] = result;
        } catch (error) {
          results[browserName][featureTest.name] = false;
          console.error(`Feature '${featureTest.name}' failed in ${browserName}:`, error);
        }
      }

      await browser.close();
    }

    // Verify feature parity
    const features = featureTests.map(t => t.name);
    features.forEach(feature => {
      const browserResults = BROWSERS.map(browser => results[browser][feature]);
      const allBrowsersPass = browserResults.every(result => result === true);
      
      expect(allBrowsersPass).toBe(true);
      
      if (!allBrowsersPass) {
        console.error(`Feature parity issue with '${feature}':`);
        BROWSERS.forEach(browser => {
          console.error(`  ${browser}: ${results[browser][feature]}`);
        });
      }
    });

    console.log('\n🌐 Feature Parity Report:');
    features.forEach(feature => {
      const support = BROWSERS.map(browser => results[browser][feature] ? '✅' : '❌').join(' ');
      console.log(`${feature}: ${support} (${BROWSERS.join(' ')})`);
    });
  });

  test('should handle performance consistently across browsers', async ({ playwright }) => {
    const performanceResults: { [key: string]: number } = {};

    for (const browserName of BROWSERS) {
      const browser = await playwright[browserName].launch(BROWSER_CONFIGS[browserName].launchOptions);
      const context = await browser.newContext(BROWSER_CONFIGS[browserName].contextOptions);
      const page = await context.newPage();

      // Login
      await page.goto('http://localhost:3000/login');
      await page.fill('[data-testid="email-input"]', 'test@isectech.com');
      await page.fill('[data-testid="password-input"]', 'TestPassword123!');
      await page.click('[data-testid="login-button"]');
      await page.waitForURL('**/dashboard');

      // Measure dashboard load performance
      const startTime = performance.now();
      await page.reload();
      await page.waitForSelector('[data-testid="dashboard-loaded"]');
      const loadTime = performance.now() - startTime;

      performanceResults[browserName] = loadTime;

      // Performance should be reasonable
      expect(loadTime).toBeLessThan(10000); // 10s max in any browser

      await browser.close();
    }

    // Check performance consistency (no browser should be more than 3x slower)
    const times = Object.values(performanceResults);
    const minTime = Math.min(...times);
    const maxTime = Math.max(...times);
    const performanceRatio = maxTime / minTime;

    expect(performanceRatio).toBeLessThan(3);

    console.log('\n⚡ Performance Comparison:');
    Object.entries(performanceResults).forEach(([browser, time]) => {
      console.log(`${browser}: ${time.toFixed(0)}ms`);
    });
    console.log(`Performance ratio: ${performanceRatio.toFixed(2)}x`);
  });

  test.afterEach(() => {
    if (tester.getResults().length > 0) {
      console.log(tester.generateCompatibilityReport());
    }
  });
});