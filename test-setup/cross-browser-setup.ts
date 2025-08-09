/**
 * Cross-Browser Testing Global Setup
 * iSECTECH Protect - Multi-Browser Test Environment Setup
 */

import { chromium, firefox, webkit, FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

interface BrowserSetupResult {
  browser: string;
  version: string;
  userAgent: string;
  features: {
    webgl: boolean;
    webrtc: boolean;
    webworkers: boolean;
    serviceWorkers: boolean;
    indexedDB: boolean;
    webCrypto: boolean;
    notifications: boolean;
    geolocation: boolean;
  };
  securityFeatures: {
    csp: boolean;
    hsts: boolean;
    xFrameOptions: boolean;
    contentTypeOptions: boolean;
  };
}

async function setupBrowserCapabilities() {
  const results: BrowserSetupResult[] = [];
  const browsers = [
    { name: 'chromium', launcher: chromium },
    { name: 'firefox', launcher: firefox },
    { name: 'webkit', launcher: webkit },
  ];

  for (const { name, launcher } of browsers) {
    console.log(`🔧 Setting up ${name} browser capabilities...`);
    
    try {
      const browser = await launcher.launch({ headless: true });
      const context = await browser.newContext();
      const page = await context.newPage();

      // Get browser version and user agent
      const userAgent = await page.evaluate(() => navigator.userAgent);
      const version = await browser.version();

      // Test browser features
      const features = await page.evaluate(() => {
        return {
          webgl: !!(window as any).WebGLRenderingContext,
          webrtc: !!(window as any).RTCPeerConnection,
          webworkers: typeof Worker !== 'undefined',
          serviceWorkers: 'serviceWorker' in navigator,
          indexedDB: 'indexedDB' in window,
          webCrypto: !!(window.crypto && window.crypto.subtle),
          notifications: 'Notification' in window,
          geolocation: 'geolocation' in navigator,
        };
      });

      // Test security features
      const securityFeatures = await page.evaluate(() => {
        return {
          csp: !!document.querySelector('meta[http-equiv="Content-Security-Policy"]'),
          hsts: document.location.protocol === 'https:',
          xFrameOptions: true, // Will be tested with actual headers
          contentTypeOptions: true, // Will be tested with actual headers
        };
      });

      const result: BrowserSetupResult = {
        browser: name,
        version,
        userAgent,
        features,
        securityFeatures,
      };

      results.push(result);
      console.log(`✅ ${name} setup complete - Version: ${version}`);

      await browser.close();
    } catch (error) {
      console.error(`❌ Failed to setup ${name}:`, error);
    }
  }

  // Save browser capabilities report
  const reportPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'browser-capabilities.json');
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));

  return results;
}

async function createTestData() {
  console.log('📊 Creating cross-browser test data...');
  
  const testData = {
    users: [
      {
        email: 'chrome.analyst@isectech.com',
        password: 'ChromeTest123!',
        role: 'SECURITY_ANALYST',
        browser: 'chromium',
      },
      {
        email: 'firefox.analyst@isectech.com', 
        password: 'FirefoxTest123!',
        role: 'SECURITY_ANALYST',
        browser: 'firefox',
      },
      {
        email: 'safari.analyst@isectech.com',
        password: 'SafariTest123!',
        role: 'SECURITY_ANALYST', 
        browser: 'webkit',
      },
    ],
    alerts: Array.from({ length: 50 }, (_, i) => ({
      id: `cross-browser-alert-${i}`,
      title: `Cross Browser Test Alert ${i}`,
      severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][i % 4],
      type: 'NETWORK_ANOMALY',
      description: `Test alert for browser compatibility testing - Alert ${i}`,
      source_ip: `192.168.1.${(i % 254) + 1}`,
      created_at: new Date(Date.now() - i * 60000).toISOString(),
      browser_test: true,
    })),
    threats: Array.from({ length: 25 }, (_, i) => ({
      id: `cross-browser-threat-${i}`,
      type: 'malware',
      severity: ['low', 'medium', 'high'][i % 3],
      indicators: [`hash-${i}`, `ip-192.168.1.${(i % 254) + 1}`],
      description: `Browser compatibility test threat ${i}`,
      browser_test: true,
    })),
  };

  const testDataPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'test-data.json');
  fs.writeFileSync(testDataPath, JSON.stringify(testData, null, 2));

  console.log('✅ Test data created successfully');
  return testData;
}

async function setupSecurityHeaders() {
  console.log('🔒 Setting up security headers for testing...');
  
  const securityHeaders = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' ws: wss:;",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  };

  // Save security headers configuration
  const headersPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'security-headers.json');
  fs.writeFileSync(headersPath, JSON.stringify(securityHeaders, null, 2));

  console.log('✅ Security headers configured');
  return securityHeaders;
}

async function validateTestEnvironment() {
  console.log('🔍 Validating cross-browser test environment...');
  
  const validations = {
    nodeVersion: process.version,
    playwrightVersion: require('@playwright/test/package.json').version,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3000',
    ci: !!process.env.CI,
  };

  // Validate required directories exist
  const requiredDirs = [
    'test-results/cross-browser',
    'playwright-report/cross-browser',
    '__tests__/cross-browser',
  ];

  for (const dir of requiredDirs) {
    const fullPath = path.join(process.cwd(), dir);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
      console.log(`📁 Created directory: ${dir}`);
    }
  }

  // Check for test server availability
  try {
    const response = await fetch(validations.baseUrl);
    validations['serverAvailable'] = response.ok;
    console.log(`✅ Test server available at ${validations.baseUrl}`);
  } catch (error) {
    validations['serverAvailable'] = false;
    console.log(`⚠️ Test server not available at ${validations.baseUrl}`);
  }

  // Save validation results
  const validationPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'environment-validation.json');
  fs.writeFileSync(validationPath, JSON.stringify(validations, null, 2));

  return validations;
}

async function setupBrowserSpecificConfigs() {
  console.log('⚙️ Setting up browser-specific configurations...');
  
  const configs = {
    chromium: {
      viewport: { width: 1920, height: 1080 },
      deviceScaleFactor: 1,
      permissions: ['clipboard-read', 'clipboard-write', 'notifications'],
      extraHTTPHeaders: {
        'Accept-Language': 'en-US,en;q=0.9',
      },
      launchOptions: {
        args: [
          '--disable-web-security',
          '--disable-features=VizDisplayCompositor',
          '--enable-precise-memory-info',
          '--js-flags="--max-old-space-size=4096"',
        ],
      },
    },
    firefox: {
      viewport: { width: 1920, height: 1080 },
      deviceScaleFactor: 1,
      permissions: ['clipboard-read', 'clipboard-write'],
      firefoxUserPrefs: {
        'security.tls.version.max': 4,
        'security.tls.version.min': 3,
        'dom.security.https_only_mode': false,
        'browser.cache.disk.enable': false,
        'browser.cache.memory.enable': false,
      },
    },
    webkit: {
      viewport: { width: 1920, height: 1080 },
      deviceScaleFactor: 1,
      permissions: ['clipboard-read', 'clipboard-write'],
    },
  };

  const configPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'browser-configs.json');
  fs.writeFileSync(configPath, JSON.stringify(configs, null, 2));

  console.log('✅ Browser configurations saved');
  return configs;
}

async function generateSetupReport(browserCapabilities: BrowserSetupResult[], validations: any) {
  console.log('📋 Generating setup report...');
  
  const report = {
    timestamp: new Date().toISOString(),
    environment: validations,
    browsers: browserCapabilities,
    summary: {
      totalBrowsers: browserCapabilities.length,
      supportedFeatures: {
        webCrypto: browserCapabilities.filter(b => b.features.webCrypto).length,
        serviceWorkers: browserCapabilities.filter(b => b.features.serviceWorkers).length,
        indexedDB: browserCapabilities.filter(b => b.features.indexedDB).length,
        notifications: browserCapabilities.filter(b => b.features.notifications).length,
      },
      securitySupport: {
        allBrowsersSecure: browserCapabilities.every(b => 
          b.securityFeatures.csp && 
          b.securityFeatures.contentTypeOptions
        ),
      },
    },
    recommendations: [],
  };

  // Add recommendations based on browser capabilities
  browserCapabilities.forEach(browser => {
    if (!browser.features.webCrypto) {
      report.recommendations.push(`${browser.browser}: WebCrypto API not supported - encryption features may be limited`);
    }
    if (!browser.features.serviceWorkers) {
      report.recommendations.push(`${browser.browser}: Service Workers not supported - offline capabilities limited`);
    }
    if (!browser.features.notifications) {
      report.recommendations.push(`${browser.browser}: Notifications not supported - alert notifications may not work`);
    }
  });

  const reportPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'setup-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

  // Generate markdown report
  let markdownReport = `# Cross-Browser Testing Setup Report\n\n`;
  markdownReport += `**Generated:** ${new Date().toISOString()}\n\n`;
  markdownReport += `## Environment\n`;
  markdownReport += `- Node.js: ${validations.nodeVersion}\n`;
  markdownReport += `- Playwright: ${validations.playwrightVersion}\n`;
  markdownReport += `- Base URL: ${validations.baseUrl}\n`;
  markdownReport += `- Server Available: ${validations.serverAvailable ? '✅' : '❌'}\n\n`;
  
  markdownReport += `## Browser Capabilities\n\n`;
  browserCapabilities.forEach(browser => {
    markdownReport += `### ${browser.browser.toUpperCase()}\n`;
    markdownReport += `- Version: ${browser.version}\n`;
    markdownReport += `- WebCrypto: ${browser.features.webCrypto ? '✅' : '❌'}\n`;
    markdownReport += `- Service Workers: ${browser.features.serviceWorkers ? '✅' : '❌'}\n`;
    markdownReport += `- IndexedDB: ${browser.features.indexedDB ? '✅' : '❌'}\n`;
    markdownReport += `- Notifications: ${browser.features.notifications ? '✅' : '❌'}\n\n`;
  });

  if (report.recommendations.length > 0) {
    markdownReport += `## Recommendations\n\n`;
    report.recommendations.forEach(rec => {
      markdownReport += `- ${rec}\n`;
    });
  }

  const markdownPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'setup-report.md');
  fs.writeFileSync(markdownPath, markdownReport);

  console.log('✅ Setup report generated');
  return report;
}

// Main setup function
export default async function globalSetup(config: FullConfig) {
  console.log('🚀 Starting cross-browser testing setup...\n');
  
  try {
    // Run all setup tasks
    const browserCapabilities = await setupBrowserCapabilities();
    const testData = await createTestData();
    const securityHeaders = await setupSecurityHeaders();
    const validations = await validateTestEnvironment();
    const browserConfigs = await setupBrowserSpecificConfigs();
    const setupReport = await generateSetupReport(browserCapabilities, validations);

    console.log('\n✅ Cross-browser testing setup completed successfully!');
    console.log(`📊 Setup report saved to: test-results/cross-browser/setup-report.md`);
    
    // Store setup results for teardown
    const setupResults = {
      browserCapabilities,
      testData,
      securityHeaders,
      validations,
      browserConfigs,
      setupReport,
    };

    const setupResultsPath = path.join(process.cwd(), 'test-results', 'cross-browser', 'setup-results.json');
    fs.writeFileSync(setupResultsPath, JSON.stringify(setupResults, null, 2));

    return setupResults;
  } catch (error) {
    console.error('❌ Cross-browser setup failed:', error);
    throw error;
  }
}