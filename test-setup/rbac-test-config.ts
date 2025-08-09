/**
 * RBAC Testing Configuration and Setup
 * Centralizes test configuration, environment setup, and test execution utilities
 */

export const RBAC_TEST_CONFIG = {
  // Database configuration for testing
  database: {
    host: process.env.TEST_DB_HOST || 'localhost',
    port: parseInt(process.env.TEST_DB_PORT || '5432'),
    adminUser: process.env.TEST_DB_ADMIN_USER || 'postgres',
    adminPassword: process.env.TEST_DB_ADMIN_PASSWORD || 'test',
    testUser: process.env.TEST_DB_USER || 'test_user',
    testPassword: process.env.TEST_DB_PASSWORD || 'test',
    testDbPrefix: 'rbac_test_',
    maxConnections: 20,
    connectionTimeout: 2000,
    idleTimeout: 30000
  },

  // Performance test thresholds (in milliseconds)
  performance: {
    simpleQuery: 5,
    complexQuery: 20,
    hierarchyResolution: 10,
    rlsFilteredQuery: 20,
    bulkOperations: 50,
    concurrentOperations: 100,
    contextSwitching: 10,
    
    // SLA definitions
    p95Latency: 50,   // 95th percentile should be under 50ms
    p99Latency: 100,  // 99th percentile should be under 100ms
    throughputMin: 1000, // Minimum 1000 operations per second
    
    // Scalability targets
    linearScalingFactor: 2, // 2x data should not cause >2x performance degradation
    maxSlowdownRatio: 5     // Max 5x slower than baseline for any operation
  },

  // Security test parameters
  security: {
    maxCrossTenantAttempts: 100,    // Test various attack vectors
    maxPrivilegeEscalationTests: 50, // Different privilege escalation attempts
    concurrentSessionTests: 100,     // Concurrent session isolation tests
    sqlInjectionPayloads: [
      "'; DROP TABLE roles; --",
      "' OR '1'='1",
      "'; SET app.current_tenant_id = 'other-tenant'; SELECT * FROM roles WHERE '1'='1",
      "/**/UNION/**/SELECT/**/password/**/FROM/**/users",
      "' AND (SELECT COUNT(*) FROM roles) > 0 --",
      "'; EXEC xp_cmdshell('dir'); --",
      "' WAITFOR DELAY '00:00:05' --"
    ]
  },

  // Test data generation parameters
  testData: {
    smallTenantUsers: 10,
    mediumTenantUsers: 100,
    largeTenantUsers: 1000,
    maxRoleHierarchyDepth: 8,
    permissionsPerRole: 5,
    rolesPerUser: 3,
    
    // Scalability test sizes
    scalabilityTests: [
      { name: 'baseline', tenants: 1, usersPerTenant: 10 },
      { name: 'small', tenants: 10, usersPerTenant: 50 },
      { name: 'medium', tenants: 50, usersPerTenant: 100 },
      { name: 'large', tenants: 100, usersPerTenant: 500 }
    ]
  },

  // Test execution configuration
  execution: {
    timeouts: {
      unitTest: 5000,      // 5 seconds
      integrationTest: 30000, // 30 seconds
      performanceTest: 60000, // 60 seconds
      securityTest: 45000,    // 45 seconds
      setupTeardown: 120000   // 2 minutes
    },
    
    retry: {
      maxAttempts: 3,
      backoffMs: 1000
    },
    
    parallel: {
      maxWorkers: 4,
      isolateEnvironments: true
    },
    
    coverage: {
      minThreshold: 90,     // 90% minimum code coverage
      includeIntegration: true,
      excludePatterns: [
        'node_modules/**',
        '**/*.test.ts',
        '**/*.spec.ts',
        'test-setup/**'
      ]
    }
  },

  // CI/CD integration settings
  ci: {
    environments: ['development', 'testing', 'staging', 'production'],
    requiredChecks: [
      'unit-tests',
      'integration-tests', 
      'security-tests',
      'performance-tests',
      'code-coverage'
    ],
    
    notifications: {
      slack: {
        channel: '#security-alerts',
        onFailure: true,
        onSuccess: false
      },
      email: {
        recipients: ['security-team@company.com'],
        onCriticalFailure: true
      }
    },
    
    artifacts: {
      testReports: 'test-results/',
      performanceReports: 'performance-results/',
      securityReports: 'security-results/',
      coverageReports: 'coverage-results/',
      retentionDays: 30
    }
  }
};

// Test environment utilities
export class RBACTestEnvironment {
  private static instance: RBACTestEnvironment;
  private dbSetup: any;
  private isInitialized = false;

  static getInstance(): RBACTestEnvironment {
    if (!RBACTestEnvironment.instance) {
      RBACTestEnvironment.instance = new RBACTestEnvironment();
    }
    return RBACTestEnvironment.instance;
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    console.log('🚀 Initializing RBAC test environment...');
    
    // Check required environment variables
    this.validateEnvironment();
    
    // Import and setup database
    const { DatabaseTestSetup } = await import('./database-test-setup');
    this.dbSetup = new DatabaseTestSetup();
    await this.dbSetup.initialize();
    
    this.isInitialized = true;
    console.log('✅ RBAC test environment initialized');
  }

  private validateEnvironment(): void {
    const requiredEnvVars = [
      'TEST_DB_HOST',
      'TEST_DB_PORT', 
      'TEST_DB_USER',
      'TEST_DB_PASSWORD'
    ];

    const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);
    
    if (missing.length > 0) {
      console.warn(`⚠️  Missing environment variables: ${missing.join(', ')}`);
      console.warn('Using default values for testing');
    }
  }

  async cleanup(): Promise<void> {
    if (this.dbSetup) {
      await this.dbSetup.destroy();
    }
    this.isInitialized = false;
    console.log('🧹 RBAC test environment cleaned up');
  }

  getDatabaseSetup(): any {
    return this.dbSetup;
  }

  isReady(): boolean {
    return this.isInitialized;
  }
}

// Test result aggregation and reporting
export class RBACTestReporter {
  private results: Map<string, any> = new Map();
  private startTime: number = Date.now();

  recordTestSuite(suiteName: string, results: any): void {
    this.results.set(suiteName, {
      ...results,
      timestamp: Date.now(),
      duration: Date.now() - this.startTime
    });
  }

  recordPerformanceMetric(metricName: string, value: number, threshold: number): void {
    const existing = this.results.get('performance') || { metrics: {} };
    existing.metrics[metricName] = {
      value,
      threshold,
      pass: value <= threshold,
      timestamp: Date.now()
    };
    this.results.set('performance', existing);
  }

  recordSecurityTest(testName: string, passed: boolean, details?: any): void {
    const existing = this.results.get('security') || { tests: {} };
    existing.tests[testName] = {
      passed,
      details,
      timestamp: Date.now()
    };
    this.results.set('security', existing);
  }

  generateSummaryReport(): any {
    const totalDuration = Date.now() - this.startTime;
    const suiteResults = Array.from(this.results.entries());
    
    return {
      summary: {
        totalDuration,
        totalSuites: suiteResults.length,
        overallStatus: this.calculateOverallStatus()
      },
      suites: Object.fromEntries(suiteResults),
      performance: this.generatePerformanceReport(),
      security: this.generateSecurityReport(),
      recommendations: this.generateRecommendations()
    };
  }

  private calculateOverallStatus(): 'PASS' | 'FAIL' | 'WARNING' {
    const performanceResults = this.results.get('performance');
    const securityResults = this.results.get('security');
    
    // Critical: All security tests must pass
    if (securityResults) {
      const securityTests = Object.values(securityResults.tests || {});
      if (securityTests.some((test: any) => !test.passed)) {
        return 'FAIL';
      }
    }
    
    // Important: Performance thresholds
    if (performanceResults) {
      const metrics = Object.values(performanceResults.metrics || {});
      const criticalFailures = metrics.filter((metric: any) => 
        !metric.pass && metric.value > metric.threshold * 2
      );
      
      if (criticalFailures.length > 0) {
        return 'FAIL';
      }
      
      const minorFailures = metrics.filter((metric: any) => !metric.pass);
      if (minorFailures.length > 0) {
        return 'WARNING';
      }
    }
    
    return 'PASS';
  }

  private generatePerformanceReport(): any {
    const performanceResults = this.results.get('performance');
    if (!performanceResults) return null;
    
    const metrics = performanceResults.metrics || {};
    const passed = Object.values(metrics).filter((m: any) => m.pass).length;
    const failed = Object.values(metrics).filter((m: any) => !m.pass).length;
    
    return {
      totalMetrics: passed + failed,
      passed,
      failed,
      passRate: (passed / (passed + failed)) * 100,
      slowestMetrics: Object.entries(metrics)
        .filter(([_, metric]: [string, any]) => !metric.pass)
        .sort(([_, a]: [string, any], [__, b]: [string, any]) => 
          (b.value / b.threshold) - (a.value / a.threshold)
        )
        .slice(0, 5)
    };
  }

  private generateSecurityReport(): any {
    const securityResults = this.results.get('security');
    if (!securityResults) return null;
    
    const tests = securityResults.tests || {};
    const passed = Object.values(tests).filter((t: any) => t.passed).length;
    const failed = Object.values(tests).filter((t: any) => !t.passed).length;
    
    return {
      totalTests: passed + failed,
      passed,
      failed,
      passRate: (passed / (passed + failed)) * 100,
      criticalFailures: Object.entries(tests)
        .filter(([_, test]: [string, any]) => !test.passed)
        .map(([name, test]: [string, any]) => ({ name, ...test }))
    };
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    const overallStatus = this.calculateOverallStatus();
    
    if (overallStatus === 'FAIL') {
      recommendations.push('🚨 CRITICAL: Fix all failing security tests before deployment');
      recommendations.push('🚨 CRITICAL: Address performance issues exceeding 2x threshold');
    }
    
    if (overallStatus === 'WARNING') {
      recommendations.push('⚠️  Review performance metrics that exceed thresholds');
      recommendations.push('⚠️  Consider optimization for better SLA compliance');
    }
    
    const performanceResults = this.results.get('performance');
    if (performanceResults) {
      const slowMetrics = Object.entries(performanceResults.metrics || {})
        .filter(([_, metric]: [string, any]) => !metric.pass)
        .length;
      
      if (slowMetrics > 0) {
        recommendations.push(`🔧 Optimize ${slowMetrics} performance metrics that exceed targets`);
        recommendations.push('🔧 Review database indexes and query plans');
        recommendations.push('🔧 Consider implementing caching strategies');
      }
    }
    
    if (recommendations.length === 0) {
      recommendations.push('✅ All tests passed - system is performing within targets');
      recommendations.push('✅ Continue monitoring performance trends');
    }
    
    return recommendations;
  }

  exportReport(format: 'json' | 'html' | 'console' = 'console'): string {
    const report = this.generateSummaryReport();
    
    switch (format) {
      case 'json':
        return JSON.stringify(report, null, 2);
        
      case 'html':
        return this.generateHTMLReport(report);
        
      case 'console':
      default:
        return this.generateConsoleReport(report);
    }
  }

  private generateConsoleReport(report: any): string {
    const lines = [];
    
    lines.push('');
    lines.push('🔒 RBAC TESTING COMPREHENSIVE REPORT');
    lines.push('=' .repeat(50));
    lines.push('');
    
    // Overall status
    const statusEmoji = report.summary.overallStatus === 'PASS' ? '✅' : 
                       report.summary.overallStatus === 'WARNING' ? '⚠️' : '❌';
    lines.push(`Overall Status: ${statusEmoji} ${report.summary.overallStatus}`);
    lines.push(`Total Duration: ${(report.summary.totalDuration / 1000).toFixed(2)}s`);
    lines.push(`Test Suites: ${report.summary.totalSuites}`);
    lines.push('');
    
    // Performance summary
    if (report.performance) {
      lines.push('📊 PERFORMANCE SUMMARY');
      lines.push('-'.repeat(30));
      lines.push(`Pass Rate: ${report.performance.passRate.toFixed(1)}%`);
      lines.push(`Passed: ${report.performance.passed}/${report.performance.totalMetrics}`);
      
      if (report.performance.slowestMetrics.length > 0) {
        lines.push('Slowest Metrics:');
        report.performance.slowestMetrics.forEach(([name, metric]: [string, any]) => {
          const ratio = (metric.value / metric.threshold).toFixed(1);
          lines.push(`  • ${name}: ${metric.value.toFixed(2)}ms (${ratio}x threshold)`);
        });
      }
      lines.push('');
    }
    
    // Security summary
    if (report.security) {
      lines.push('🛡️  SECURITY SUMMARY');
      lines.push('-'.repeat(30));
      lines.push(`Pass Rate: ${report.security.passRate.toFixed(1)}%`);
      lines.push(`Passed: ${report.security.passed}/${report.security.totalTests}`);
      
      if (report.security.criticalFailures.length > 0) {
        lines.push('Critical Failures:');
        report.security.criticalFailures.forEach((failure: any) => {
          lines.push(`  • ${failure.name}: ${failure.details || 'Security test failed'}`);
        });
      }
      lines.push('');
    }
    
    // Recommendations
    if (report.recommendations.length > 0) {
      lines.push('💡 RECOMMENDATIONS');
      lines.push('-'.repeat(30));
      report.recommendations.forEach((rec: string) => {
        lines.push(rec);
      });
      lines.push('');
    }
    
    return lines.join('\n');
  }

  private generateHTMLReport(report: any): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <title>RBAC Testing Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .header { text-align: center; margin-bottom: 30px; }
    .status-pass { color: #28a745; }
    .status-warning { color: #ffc107; }
    .status-fail { color: #dc3545; }
    .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
    .metric { margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 3px; }
    .recommendations { background: #e7f3ff; border-left: 4px solid #2196F3; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔒 RBAC Testing Comprehensive Report</h1>
      <p class="status-${report.summary.overallStatus.toLowerCase()}">
        Status: ${report.summary.overallStatus}
      </p>
      <p>Duration: ${(report.summary.totalDuration / 1000).toFixed(2)}s | Suites: ${report.summary.totalSuites}</p>
    </div>
    
    ${report.performance ? `
    <div class="section">
      <h2>📊 Performance Summary</h2>
      <p>Pass Rate: ${report.performance.passRate.toFixed(1)}% (${report.performance.passed}/${report.performance.totalMetrics})</p>
      ${report.performance.slowestMetrics.length > 0 ? `
      <h3>Slowest Metrics</h3>
      ${report.performance.slowestMetrics.map(([name, metric]: [string, any]) => `
        <div class="metric">
          <strong>${name}</strong>: ${metric.value.toFixed(2)}ms 
          (${(metric.value / metric.threshold).toFixed(1)}x threshold)
        </div>
      `).join('')}
      ` : ''}
    </div>
    ` : ''}
    
    ${report.security ? `
    <div class="section">
      <h2>🛡️ Security Summary</h2>
      <p>Pass Rate: ${report.security.passRate.toFixed(1)}% (${report.security.passed}/${report.security.totalTests})</p>
      ${report.security.criticalFailures.length > 0 ? `
      <h3>Critical Failures</h3>
      ${report.security.criticalFailures.map((failure: any) => `
        <div class="metric status-fail">
          <strong>${failure.name}</strong>: ${failure.details || 'Security test failed'}
        </div>
      `).join('')}
      ` : ''}
    </div>
    ` : ''}
    
    <div class="section recommendations">
      <h2>💡 Recommendations</h2>
      ${report.recommendations.map((rec: string) => `<p>${rec}</p>`).join('')}
    </div>
  </div>
</body>
</html>
    `.trim();
  }
}

// Export test utilities
export * from './database-test-setup';
export { RBACTestEnvironment, RBACTestReporter };