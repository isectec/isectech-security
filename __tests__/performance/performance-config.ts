/**
 * Performance Testing Configuration
 * iSECTECH Protect - Performance Test Settings & Utilities
 */

export const PERFORMANCE_THRESHOLDS = {
  // Core Web Vitals (Security Platform)
  firstContentfulPaint: 2000, // 2s
  largestContentfulPaint: 3000, // 3s
  firstInputDelay: 100, // 100ms
  cumulativeLayoutShift: 0.1, // 0.1
  timeToInteractive: 5000, // 5s

  // Security-Specific Metrics
  authentication: {
    loginTime: 3000, // 3s max login time
    mfaVerification: 2000, // 2s max MFA
    tokenRefresh: 500, // 500ms token refresh
    rbacCheck: 1000, // 1s RBAC validation
  },

  dashboard: {
    initialLoad: 2500, // 2.5s dashboard load
    realTimeUpdate: 500, // 500ms real-time updates
    widgetRender: 1000, // 1s per widget
    dataRefresh: 2000, // 2s data refresh
  },

  alerts: {
    listLoad: 2000, // 2s alert list
    createAlert: 1500, // 1.5s alert creation
    bulkOperations: 5000, // 5s bulk operations
    alertCorrelation: 5000, // 5s correlation
  },

  threats: {
    mapLoad: 4000, // 4s threat map
    intelligenceQuery: 3000, // 3s threat intel
    patternAnalysis: 10000, // 10s pattern analysis
    huntingQuery: 15000, // 15s hunting queries
  },

  search: {
    basicSearch: 800, // 800ms basic search
    advancedSearch: 2000, // 2s advanced search
    globalSearch: 1500, // 1.5s global search
    resultPagination: 300, // 300ms pagination
  },

  reports: {
    generateReport: 30000, // 30s report generation
    renderChart: 2000, // 2s chart rendering
    exportPdf: 10000, // 10s PDF export
    exportExcel: 5000, // 5s Excel export
  },

  // Performance Budgets
  budgets: {
    totalBundleSize: 2000000, // 2MB total bundle
    initialJs: 500000, // 500KB initial JS
    initialCss: 100000, // 100KB initial CSS
    images: 1000000, // 1MB images
    fonts: 100000, // 100KB fonts
  },

  // Load Testing Limits
  loadTesting: {
    concurrentUsers: 100, // 100 concurrent users
    alertsPerSecond: 1000, // 1000 alerts/second
    searchQPS: 50, // 50 queries per second
    maxResponseTime: 5000, // 5s max response
    errorRateThreshold: 0.01, // 1% error rate
  },

  // Mobile Performance (Reduced Thresholds)
  mobile: {
    firstContentfulPaint: 3000, // 3s
    largestContentfulPaint: 4000, // 4s
    timeToInteractive: 8000, // 8s
    dashboardLoad: 4000, // 4s
  },
};

export const LIGHTHOUSE_CONFIG = {
  extends: 'lighthouse:default',
  settings: {
    onlyCategories: ['performance', 'accessibility', 'best-practices'],
    skipAudits: ['uses-http2'], // Skip HTTP/2 for local testing
    throttling: {
      rttMs: 40,
      throughputKbps: 10240,
      cpuSlowdownMultiplier: 1,
    },
    screenEmulation: {
      mobile: false,
      width: 1920,
      height: 1080,
      deviceScaleFactor: 1,
    },
    formFactor: 'desktop',
    additionalTraceCategories: 'devtools.timeline,disabled-by-default-devtools.timeline',
  },
  audits: [
    'first-contentful-paint',
    'largest-contentful-paint',
    'first-meaningful-paint',
    'speed-index',
    'interactive',
    'first-cpu-idle',
    'max-potential-fid',
    'cumulative-layout-shift',
    'server-response-time',
    'render-blocking-resources',
    'unused-javascript',
    'unused-css-rules',
    'uses-optimized-images',
    'uses-webp-images',
    'uses-text-compression',
    'uses-rel-preconnect',
    'preload-lcp-image',
    'total-byte-weight',
    'dom-size',
    'critical-request-chains',
    'user-timings',
    'bootup-time',
    'mainthread-work-breakdown',
    'third-party-summary',
  ],
};

export const SECURITY_PERFORMANCE_MONITORS = {
  encryption: {
    name: 'Client-Side Encryption',
    threshold: 50, // 50ms
    category: 'security',
  },
  
  authentication: {
    name: 'Authentication Flow',
    threshold: 3000, // 3s
    category: 'security',
  },

  authorization: {
    name: 'Authorization Check',
    threshold: 1000, // 1s
    category: 'security',
  },

  alertProcessing: {
    name: 'Security Alert Processing',
    threshold: 1500, // 1.5s
    category: 'security',
  },

  threatIntelLookup: {
    name: 'Threat Intelligence Lookup',
    threshold: 2000, // 2s
    category: 'security',
  },

  eventCorrelation: {
    name: 'Event Correlation',
    threshold: 5000, // 5s
    category: 'security',
  },

  incidentResponse: {
    name: 'Incident Response Actions',
    threshold: 2000, // 2s
    category: 'security',
  },

  complianceReporting: {
    name: 'Compliance Report Generation',
    threshold: 30000, // 30s
    category: 'compliance',
  },
};

export interface PerformanceMetric {
  name: string;
  value: number;
  threshold: number;
  category: string;
  timestamp: number;
  passed: boolean;
}

export class PerformanceMonitor {
  private metrics: PerformanceMetric[] = [];
  private startTimes: Map<string, number> = new Map();

  startTimer(name: string): void {
    this.startTimes.set(name, performance.now());
  }

  endTimer(name: string, category: string = 'general'): PerformanceMetric {
    const startTime = this.startTimes.get(name);
    if (!startTime) {
      throw new Error(`Timer '${name}' was not started`);
    }

    const value = performance.now() - startTime;
    const threshold = this.getThreshold(name, category);
    
    const metric: PerformanceMetric = {
      name,
      value,
      threshold,
      category,
      timestamp: Date.now(),
      passed: value <= threshold,
    };

    this.metrics.push(metric);
    this.startTimes.delete(name);

    return metric;
  }

  private getThreshold(name: string, category: string): number {
    // Dynamic threshold lookup based on name and category
    const thresholdMap: { [key: string]: number } = {
      'login': PERFORMANCE_THRESHOLDS.authentication.loginTime,
      'dashboard': PERFORMANCE_THRESHOLDS.dashboard.initialLoad,
      'alerts': PERFORMANCE_THRESHOLDS.alerts.listLoad,
      'search': PERFORMANCE_THRESHOLDS.search.basicSearch,
      'encryption': SECURITY_PERFORMANCE_MONITORS.encryption.threshold,
      'correlation': SECURITY_PERFORMANCE_MONITORS.eventCorrelation.threshold,
    };

    return thresholdMap[name.toLowerCase()] || 5000; // Default 5s
  }

  getMetrics(): PerformanceMetric[] {
    return [...this.metrics];
  }

  getFailedMetrics(): PerformanceMetric[] {
    return this.metrics.filter(metric => !metric.passed);
  }

  generateReport(): string {
    const total = this.metrics.length;
    const passed = this.metrics.filter(m => m.passed).length;
    const failed = total - passed;

    let report = `\n📊 Performance Test Report\n`;
    report += `===========================\n`;
    report += `Total Tests: ${total}\n`;
    report += `Passed: ${passed} (${((passed/total) * 100).toFixed(1)}%)\n`;
    report += `Failed: ${failed} (${((failed/total) * 100).toFixed(1)}%)\n\n`;

    if (failed > 0) {
      report += `❌ Failed Tests:\n`;
      this.getFailedMetrics().forEach(metric => {
        report += `  ${metric.name}: ${metric.value.toFixed(2)}ms (threshold: ${metric.threshold}ms)\n`;
      });
      report += `\n`;
    }

    report += `📈 Performance Summary:\n`;
    const categories = [...new Set(this.metrics.map(m => m.category))];
    
    categories.forEach(category => {
      const categoryMetrics = this.metrics.filter(m => m.category === category);
      const avgTime = categoryMetrics.reduce((sum, m) => sum + m.value, 0) / categoryMetrics.length;
      const categoryPassed = categoryMetrics.filter(m => m.passed).length;
      
      report += `  ${category}: ${avgTime.toFixed(2)}ms avg, ${categoryPassed}/${categoryMetrics.length} passed\n`;
    });

    return report;
  }

  clear(): void {
    this.metrics = [];
    this.startTimes.clear();
  }
}

export const createSecurityPerformanceTest = (
  testName: string,
  testFn: (monitor: PerformanceMonitor) => Promise<void>
) => {
  return async () => {
    const monitor = new PerformanceMonitor();
    
    try {
      await testFn(monitor);
      
      const failedMetrics = monitor.getFailedMetrics();
      if (failedMetrics.length > 0) {
        console.error(monitor.generateReport());
        throw new Error(`Performance test failed: ${failedMetrics.length} metrics exceeded thresholds`);
      }
      
      console.log(monitor.generateReport());
    } catch (error) {
      console.error(monitor.generateReport());
      throw error;
    }
  };
};

export const BROWSER_PERFORMANCE_CONFIG = {
  chrome: {
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-web-security',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      '--disable-features=TranslateUI',
      '--disable-component-extensions-with-background-pages',
      '--enable-precise-memory-info',
    ],
  },
  firefox: {
    prefs: {
      'dom.disable_beforeunload': true,
      'browser.tabs.remote.autostart': false,
      'browser.sessionstore.resume_from_crash': false,
    },
  },
};

export const MEMORY_THRESHOLDS = {
  heapUsed: 100 * 1024 * 1024, // 100MB
  heapTotal: 200 * 1024 * 1024, // 200MB
  external: 50 * 1024 * 1024, // 50MB
  arrayBuffers: 10 * 1024 * 1024, // 10MB
};

export const CPU_THRESHOLDS = {
  mainThreadBlocking: 300, // 300ms max blocking time
  totalCpuTime: 10000, // 10s max total CPU time
  scriptEvaluation: 2000, // 2s max script evaluation
};

export const NETWORK_THRESHOLDS = {
  maxRequestSize: 1024 * 1024, // 1MB max request
  maxResponseTime: 5000, // 5s max response time
  maxConcurrentRequests: 6, // 6 concurrent requests
  cacheHitRatio: 0.8, // 80% cache hit ratio
};