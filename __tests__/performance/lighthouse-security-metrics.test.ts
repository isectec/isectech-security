/**
 * Lighthouse Performance Testing with Custom Security Metrics
 * iSECTECH Protect - Comprehensive Performance Validation
 */

import lighthouse from 'lighthouse';
import { chromium, Browser, Page } from 'playwright';
import { performance } from 'perf_hooks';

interface SecurityPerformanceMetrics {
  threatMapLoadTime: number;
  alertPanelLoadTime: number;
  dashboardInteractiveTime: number;
  securityEventProcessingTime: number;
  alertCorrelationTime: number;
  realTimeUpdateLatency: number;
  authenticationTime: number;
  roleBasedAccessTime: number;
  dataEncryptionTime: number;
  searchResponseTime: number;
}

interface LighthouseSecurityResults {
  performance: number;
  accessibility: number;
  bestPractices: number;
  seo: number;
  customSecurityMetrics: SecurityPerformanceMetrics;
  securitySpecificAudits: {
    httpsUsage: boolean;
    mixedContentIssues: number;
    vulnerableLibraries: string[];
    cspImplementation: boolean;
    sensitiveDataExposure: boolean;
  };
}

class SecurityPerformanceTester {
  private browser!: Browser;
  private page!: Page;
  
  async setup() {
    this.browser = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--allow-running-insecure-content',
      ],
    });
    
    this.page = await this.browser.newPage();
    
    // Set security headers for testing
    await this.page.setExtraHTTPHeaders({
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
    });
  }

  async cleanup() {
    await this.browser?.close();
  }

  async runLighthouseAnalysis(url: string): Promise<any> {
    const options = {
      logLevel: 'info' as const,
      output: 'json' as const,
      onlyCategories: ['performance', 'accessibility', 'best-practices', 'seo'],
      port: 9222,
      chromeFlags: [
        '--headless',
        '--no-sandbox',
        '--disable-gpu',
        '--disable-dev-shm-usage',
      ],
      
      // Custom security-focused audits
      extends: 'lighthouse:default',
      settings: {
        additionalTraceCategories: 'devtools.timeline,disabled-by-default-devtools.timeline',
        auditMode: false,
        gatherMode: false,
        disableStorageReset: false,
        throttlingMethod: 'devtools',
        throttling: {
          rttMs: 40,
          throughputKbps: 10240,
          cpuSlowdownMultiplier: 1,
          requestLatencyMs: 0,
          downloadThroughputKbps: 0,
          uploadThroughputKbps: 0,
        },
        screenEmulation: {
          mobile: false,
          width: 1920,
          height: 1080,
          deviceScaleFactor: 1,
          disabled: false,
        },
        formFactor: 'desktop' as const,
      },
    };

    return await lighthouse(url, options);
  }

  async measureSecurityMetrics(baseUrl: string): Promise<SecurityPerformanceMetrics> {
    const metrics: SecurityPerformanceMetrics = {
      threatMapLoadTime: 0,
      alertPanelLoadTime: 0,
      dashboardInteractiveTime: 0,
      securityEventProcessingTime: 0,
      alertCorrelationTime: 0,
      realTimeUpdateLatency: 0,
      authenticationTime: 0,
      roleBasedAccessTime: 0,
      dataEncryptionTime: 0,
      searchResponseTime: 0,
    };

    // Authentication Performance
    await this.page.goto(`${baseUrl}/login`);
    const authStart = performance.now();
    
    await this.page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await this.page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await this.page.click('[data-testid="login-button"]');
    
    await this.page.waitForURL('**/dashboard');
    metrics.authenticationTime = performance.now() - authStart;

    // Dashboard Interactive Time
    const dashboardStart = performance.now();
    await this.page.waitForSelector('[data-testid="dashboard-loaded"]');
    metrics.dashboardInteractiveTime = performance.now() - dashboardStart;

    // Threat Map Load Time
    const threatMapStart = performance.now();
    await this.page.goto(`${baseUrl}/threats/map`);
    await this.page.waitForSelector('[data-testid="threat-map-rendered"]');
    metrics.threatMapLoadTime = performance.now() - threatMapStart;

    // Alert Panel Load Time
    const alertStart = performance.now();
    await this.page.goto(`${baseUrl}/alerts`);
    await this.page.waitForSelector('[data-testid="alerts-table-loaded"]');
    metrics.alertPanelLoadTime = performance.now() - alertStart;

    // Security Event Processing Time
    const eventStart = performance.now();
    await this.page.click('[data-testid="create-alert-button"]');
    await this.page.waitForSelector('[data-testid="alert-form"]');
    
    await this.page.fill('[data-testid="alert-title"]', 'Performance Test Alert');
    await this.page.selectOption('[data-testid="alert-severity"]', 'HIGH');
    await this.page.click('[data-testid="submit-alert"]');
    
    await this.page.waitForSelector('[data-testid="alert-created-success"]');
    metrics.securityEventProcessingTime = performance.now() - eventStart;

    // Real-Time Update Latency
    const realtimeStart = performance.now();
    await this.page.goto(`${baseUrl}/dashboard`);
    
    // Simulate real-time update
    await this.page.evaluate(() => {
      // Trigger WebSocket message simulation
      window.dispatchEvent(new CustomEvent('security-update', {
        detail: { type: 'new-alert', severity: 'CRITICAL' }
      }));
    });
    
    await this.page.waitForSelector('[data-testid="realtime-update-received"]');
    metrics.realTimeUpdateLatency = performance.now() - realtimeStart;

    // Search Response Time
    const searchStart = performance.now();
    await this.page.goto(`${baseUrl}/search`);
    await this.page.fill('[data-testid="search-input"]', 'malware');
    await this.page.click('[data-testid="search-button"]');
    
    await this.page.waitForSelector('[data-testid="search-results-loaded"]');
    metrics.searchResponseTime = performance.now() - searchStart;

    // Role-Based Access Time
    const rbacStart = performance.now();
    await this.page.goto(`${baseUrl}/admin/settings`);
    await this.page.waitForSelector('[data-testid="admin-panel-loaded"]');
    metrics.roleBasedAccessTime = performance.now() - rbacStart;

    // Data Encryption Time (simulate)
    const encryptStart = performance.now();
    await this.page.evaluate(() => {
      // Simulate client-side encryption
      const data = 'sensitive-security-data';
      const encrypted = btoa(data); // Simple base64 for testing
      return encrypted;
    });
    metrics.dataEncryptionTime = performance.now() - encryptStart;

    // Alert Correlation Time
    const correlationStart = performance.now();
    await this.page.goto(`${baseUrl}/alerts/correlate`);
    await this.page.click('[data-testid="start-correlation"]');
    await this.page.waitForSelector('[data-testid="correlation-complete"]');
    metrics.alertCorrelationTime = performance.now() - correlationStart;

    return metrics;
  }

  async auditSecuritySpecificMetrics(url: string) {
    await this.page.goto(url);
    
    const securityAudits = {
      httpsUsage: false,
      mixedContentIssues: 0,
      vulnerableLibraries: [] as string[],
      cspImplementation: false,
      sensitiveDataExposure: false,
    };

    // Check HTTPS Usage
    securityAudits.httpsUsage = url.startsWith('https://');

    // Check Content Security Policy
    const cspHeader = await this.page.evaluate(() => {
      const metaTags = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
      return metaTags.length > 0;
    });
    securityAudits.cspImplementation = cspHeader;

    // Check for mixed content issues
    const mixedContent = await this.page.evaluate(() => {
      const resources = performance.getEntriesByType('resource');
      return resources.filter((resource: any) => 
        resource.name.startsWith('http://') && window.location.protocol === 'https:'
      ).length;
    });
    securityAudits.mixedContentIssues = mixedContent;

    // Check for vulnerable libraries (simulate)
    const libraries = await this.page.evaluate(() => {
      return Object.keys((window as any).__webpack_require__?.cache || {});
    });
    
    const vulnerablePatterns = ['jquery-1.', 'lodash-3.', 'moment-2.29.1'];
    securityAudits.vulnerableLibraries = libraries.filter(lib => 
      vulnerablePatterns.some(pattern => lib.includes(pattern))
    );

    // Check for potential sensitive data exposure
    const sensitiveDataCheck = await this.page.evaluate(() => {
      const text = document.body.innerText;
      const sensitivePatterns = [
        /api[_-]?key/i,
        /secret/i,
        /password/i,
        /token.*[a-f0-9]{32,}/i
      ];
      return sensitivePatterns.some(pattern => pattern.test(text));
    });
    securityAudits.sensitiveDataExposure = sensitiveDataCheck;

    return securityAudits;
  }
}

describe('🚀 Lighthouse Performance & Security Metrics', () => {
  let tester: SecurityPerformanceTester;
  const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000';
  
  beforeAll(async () => {
    tester = new SecurityPerformanceTester();
    await tester.setup();
  });

  afterAll(async () => {
    await tester.cleanup();
  });

  describe('Core Performance Metrics', () => {
    it('should meet performance benchmarks for security dashboard', async () => {
      const results = await tester.runLighthouseAnalysis(`${baseUrl}/dashboard`);
      const scores = results.report.categories;

      // Performance thresholds for security applications
      expect(scores.performance.score).toBeGreaterThanOrEqual(0.85); // 85+ performance score
      expect(scores.accessibility.score).toBeGreaterThanOrEqual(0.95); // 95+ accessibility (security critical)
      expect(scores['best-practices'].score).toBeGreaterThanOrEqual(0.90); // 90+ best practices
      
      // Core Web Vitals for security dashboard
      const audits = results.report.audits;
      expect(audits['first-contentful-paint'].numericValue).toBeLessThan(2000); // < 2s
      expect(audits['largest-contentful-paint'].numericValue).toBeLessThan(3000); // < 3s
      expect(audits['cumulative-layout-shift'].numericValue).toBeLessThan(0.1); // < 0.1
      
      if (audits['first-input-delay']) {
        expect(audits['first-input-delay'].numericValue).toBeLessThan(100); // < 100ms
      }
    }, 60000);

    it('should maintain performance under security load', async () => {
      const results = await tester.runLighthouseAnalysis(`${baseUrl}/alerts`);
      const audits = results.report.audits;

      // Security-specific performance requirements
      expect(audits['speed-index'].numericValue).toBeLessThan(4000); // < 4s for alert loading
      expect(audits['interactive'].numericValue).toBeLessThan(5000); // < 5s for interactivity
      expect(audits['total-blocking-time'].numericValue).toBeLessThan(300); // < 300ms blocking time
    }, 60000);

    it('should optimize threat intelligence page performance', async () => {
      const results = await tester.runLighthouseAnalysis(`${baseUrl}/threats`);
      const scores = results.report.categories;
      const audits = results.report.audits;

      expect(scores.performance.score).toBeGreaterThanOrEqual(0.80); // Slightly lower for data-heavy page
      expect(audits['server-response-time'].numericValue).toBeLessThan(600); // < 600ms server response
      expect(audits['render-blocking-resources'].details?.items.length || 0).toBeLessThan(5);
    }, 60000);
  });

  describe('Custom Security Performance Metrics', () => {
    let securityMetrics: SecurityPerformanceMetrics;

    beforeAll(async () => {
      securityMetrics = await tester.measureSecurityMetrics(baseUrl);
    });

    it('should authenticate within acceptable time limits', () => {
      expect(securityMetrics.authenticationTime).toBeLessThan(3000); // < 3s for login
      expect(securityMetrics.roleBasedAccessTime).toBeLessThan(1000); // < 1s for RBAC
    });

    it('should load security dashboards rapidly', () => {
      expect(securityMetrics.dashboardInteractiveTime).toBeLessThan(2500); // < 2.5s dashboard
      expect(securityMetrics.threatMapLoadTime).toBeLessThan(4000); // < 4s threat map
      expect(securityMetrics.alertPanelLoadTime).toBeLessThan(2000); // < 2s alerts
    });

    it('should process security events efficiently', () => {
      expect(securityMetrics.securityEventProcessingTime).toBeLessThan(1500); // < 1.5s event processing
      expect(securityMetrics.alertCorrelationTime).toBeLessThan(5000); // < 5s correlation
      expect(securityMetrics.searchResponseTime).toBeLessThan(800); // < 800ms search
    });

    it('should maintain real-time performance', () => {
      expect(securityMetrics.realTimeUpdateLatency).toBeLessThan(500); // < 500ms real-time updates
      expect(securityMetrics.dataEncryptionTime).toBeLessThan(50); // < 50ms encryption
    });
  });

  describe('Security-Specific Audits', () => {
    it('should pass security implementation audits', async () => {
      const securityAudits = await tester.auditSecuritySpecificMetrics(`${baseUrl}/dashboard`);

      expect(securityAudits.httpsUsage).toBe(true);
      expect(securityAudits.cspImplementation).toBe(true);
      expect(securityAudits.mixedContentIssues).toBe(0);
      expect(securityAudits.vulnerableLibraries).toEqual([]);
      expect(securityAudits.sensitiveDataExposure).toBe(false);
    });

    it('should validate secure headers implementation', async () => {
      const results = await tester.runLighthouseAnalysis(`${baseUrl}/login`);
      const audits = results.report.audits;

      // Security headers audit
      expect(audits['is-on-https'].score).toBe(1);
      if (audits['redirects-http']) {
        expect(audits['redirects-http'].score).toBe(1);
      }
    });
  });

  describe('Performance Under Load Simulation', () => {
    it('should maintain performance with high alert volume', async () => {
      // Simulate high alert volume
      const loadStart = performance.now();
      
      await tester.page.goto(`${baseUrl}/alerts`);
      
      // Simulate receiving 100 rapid alerts
      for (let i = 0; i < 100; i++) {
        await tester.page.evaluate((index) => {
          window.dispatchEvent(new CustomEvent('new-alert', {
            detail: {
              id: `load-test-${index}`,
              severity: 'HIGH',
              title: `Load Test Alert ${index}`
            }
          }));
        }, i);
      }
      
      await tester.page.waitForFunction(() => {
        return document.querySelectorAll('[data-testid="alert-row"]').length >= 100;
      });
      
      const loadTime = performance.now() - loadStart;
      expect(loadTime).toBeLessThan(10000); // < 10s for 100 alerts
    }, 30000);

    it('should handle concurrent user scenarios', async () => {
      const concurrentActions = [
        () => tester.page.goto(`${baseUrl}/dashboard`),
        () => tester.page.goto(`${baseUrl}/alerts`),
        () => tester.page.goto(`${baseUrl}/threats`),
        () => tester.page.goto(`${baseUrl}/incidents`),
      ];

      const startTime = performance.now();
      
      // Execute concurrent navigation
      await Promise.all(concurrentActions.map(action => action()));
      
      const totalTime = performance.now() - startTime;
      expect(totalTime).toBeLessThan(8000); // < 8s for concurrent load
    }, 20000);
  });

  describe('Resource Optimization Validation', () => {
    it('should optimize JavaScript bundle sizes', async () => {
      const results = await tester.runLighthouseAnalysis(`${baseUrl}/dashboard`);
      const audits = results.report.audits;

      expect(audits['unused-javascript'].score).toBeGreaterThanOrEqual(0.8);
      expect(audits['unminified-javascript'].score).toBe(1);
      
      // Bundle size limits for security app
      const bundleSize = audits['total-byte-weight'].numericValue;
      expect(bundleSize).toBeLessThan(2000000); // < 2MB total
    });

    it('should optimize image and asset delivery', async () => {
      const results = await tester.runLighthouseAnalysis(`${baseUrl}/threats/map`);
      const audits = results.report.audits;

      expect(audits['uses-optimized-images'].score).toBeGreaterThanOrEqual(0.9);
      expect(audits['uses-webp-images'].score).toBeGreaterThanOrEqual(0.8);
      expect(audits['offscreen-images'].score).toBeGreaterThanOrEqual(0.9);
    });

    it('should implement efficient caching strategies', async () => {
      const results = await tester.runLighthouseAnalysis(`${baseUrl}/dashboard`);
      const audits = results.report.audits;

      expect(audits['uses-long-cache-ttl'].score).toBeGreaterThanOrEqual(0.8);
      expect(audits['efficient-animated-content'].score).toBe(1);
    });
  });

  describe('Mobile Performance Validation', () => {
    it('should maintain performance on mobile devices', async () => {
      // Configure mobile emulation
      await tester.page.emulate({
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
        viewport: { width: 375, height: 667 },
        deviceScaleFactor: 2,
        isMobile: true,
        hasTouch: true,
      });

      const results = await tester.runLighthouseAnalysis(`${baseUrl}/dashboard`);
      const scores = results.report.categories;

      expect(scores.performance.score).toBeGreaterThanOrEqual(0.75); // Mobile threshold
      expect(scores.accessibility.score).toBeGreaterThanOrEqual(0.95); // High accessibility on mobile
    }, 60000);
  });
});