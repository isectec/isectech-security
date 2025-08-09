#!/usr/bin/env ts-node

/**
 * RBAC Comprehensive Test Execution Script
 * Orchestrates the complete RBAC testing suite with reporting and CI/CD integration
 */

import { execSync, spawn } from 'child_process';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { RBACTestEnvironment, RBACTestReporter, RBAC_TEST_CONFIG } from '../test-setup/rbac-test-config';

class RBACTestOrchestrator {
  private testEnv: RBACTestEnvironment;
  private reporter: RBACTestReporter;
  private projectRoot: string;
  private outputDir: string;

  constructor() {
    this.testEnv = RBACTestEnvironment.getInstance();
    this.reporter = new RBACTestReporter();
    this.projectRoot = process.cwd();
    this.outputDir = join(this.projectRoot, 'test-results', 'rbac-comprehensive');
    
    // Ensure output directory exists
    if (!existsSync(this.outputDir)) {
      mkdirSync(this.outputDir, { recursive: true });
    }
  }

  async runComprehensiveTests(): Promise<void> {
    console.log('🚀 Starting RBAC Comprehensive Test Suite...');
    console.log(`Output directory: ${this.outputDir}`);
    
    const startTime = Date.now();
    let overallSuccess = true;

    try {
      // Initialize test environment
      await this.testEnv.initialize();
      
      // Execute test suites in sequence
      const testSuites = [
        {
          name: 'Unit Tests',
          command: 'npm run test:unit:rbac',
          description: 'Basic RBAC function unit tests',
          critical: false
        },
        {
          name: 'RLS Integration Tests',
          command: 'npm run test:integration:rls',
          description: 'Row-Level Security policy integration tests',
          critical: true
        },
        {
          name: 'Tenant Isolation Tests',
          command: 'npm run test:security:isolation',
          description: 'Cross-tenant access prevention tests',
          critical: true
        },
        {
          name: 'Hierarchy Tests',
          command: 'npm run test:integration:hierarchy',
          description: 'Role hierarchy and permission inheritance tests',
          critical: true
        },
        {
          name: 'Concurrent Session Tests',
          command: 'npm run test:integration:concurrent',
          description: 'Concurrent access and session management tests',
          critical: true
        },
        {
          name: 'Performance Benchmarks',
          command: 'npm run test:performance:rbac',
          description: 'Performance benchmarks and SLA validation',
          critical: false
        },
        {
          name: 'Security Boundary Tests',
          command: 'npm run test:security:boundaries',
          description: 'Security boundary and edge case testing',
          critical: true
        },
        {
          name: 'API Integration Tests',
          command: 'npm run test:integration:api',
          description: 'API authorization layer integration tests',
          critical: true
        }
      ];

      for (const suite of testSuites) {
        console.log(`\n🧪 Running ${suite.name}...`);
        console.log(`   ${suite.description}`);
        
        const suiteResult = await this.runTestSuite(suite);
        this.reporter.recordTestSuite(suite.name, suiteResult);
        
        if (!suiteResult.success) {
          overallSuccess = false;
          if (suite.critical) {
            console.error(`❌ CRITICAL FAILURE in ${suite.name}`);
            break; // Stop on critical failures
          } else {
            console.warn(`⚠️  Non-critical failure in ${suite.name}`);
          }
        } else {
          console.log(`✅ ${suite.name} completed successfully`);
        }
      }

      // Generate comprehensive report
      await this.generateReports();
      
      const totalDuration = Date.now() - startTime;
      console.log(`\n🏁 Test suite completed in ${(totalDuration / 1000).toFixed(2)}s`);
      
      if (overallSuccess) {
        console.log('✅ All tests passed - RBAC system is secure and performant');
        process.exit(0);
      } else {
        console.error('❌ Some tests failed - Review results before deployment');
        process.exit(1);
      }

    } catch (error) {
      console.error('💥 Test execution failed:', error);
      await this.generateErrorReport(error);
      process.exit(1);
    } finally {
      await this.testEnv.cleanup();
    }
  }

  private async runTestSuite(suite: any): Promise<any> {
    const startTime = Date.now();
    
    try {
      // Check if command exists as npm script
      const packageJsonPath = join(this.projectRoot, 'package.json');
      let command = suite.command;
      
      if (!existsSync(packageJsonPath)) {
        // Fallback to direct vitest execution
        command = this.buildDirectTestCommand(suite.name);
      }

      const result = await this.executeCommand(command, {
        timeout: RBAC_TEST_CONFIG.execution.timeouts.integrationTest
      });

      const duration = Date.now() - startTime;
      
      return {
        success: result.exitCode === 0,
        duration,
        output: result.output,
        errors: result.errors,
        testCount: this.extractTestCount(result.output),
        passCount: this.extractPassCount(result.output),
        failCount: this.extractFailCount(result.output)
      };

    } catch (error) {
      return {
        success: false,
        duration: Date.now() - startTime,
        error: error.message,
        testCount: 0,
        passCount: 0,
        failCount: 1
      };
    }
  }

  private buildDirectTestCommand(suiteName: string): string {
    const testPatterns = {
      'Unit Tests': '__tests__/unit/**/*.test.ts',
      'RLS Integration Tests': '__tests__/integration/rbac-rls-comprehensive.test.ts',
      'Tenant Isolation Tests': '__tests__/security/tenant-isolation-verification.test.ts',
      'Hierarchy Tests': '__tests__/integration/hierarchical-permission-inheritance.test.ts',
      'Concurrent Session Tests': '__tests__/integration/concurrent-session-management.test.ts',
      'Performance Benchmarks': '__tests__/performance/rbac-performance-benchmarks.test.ts',
      'Security Boundary Tests': '__tests__/security/**/*.test.ts',
      'API Integration Tests': '__tests__/integration/api-**/*.test.ts'
    };

    const pattern = testPatterns[suiteName] || '**/*.test.ts';
    return `npx vitest run ${pattern} --reporter=verbose --reporter=json --outputFile=${this.outputDir}/${suiteName.toLowerCase().replace(/\s+/g, '-')}-results.json`;
  }

  private async executeCommand(command: string, options: any = {}): Promise<any> {
    return new Promise((resolve) => {
      const [cmd, ...args] = command.split(' ');
      const child = spawn(cmd, args, {
        stdio: 'pipe',
        shell: true,
        timeout: options.timeout || 30000
      });

      let output = '';
      let errors = '';

      child.stdout.on('data', (data) => {
        output += data.toString();
        process.stdout.write(data);
      });

      child.stderr.on('data', (data) => {
        errors += data.toString();
        process.stderr.write(data);
      });

      child.on('close', (exitCode) => {
        resolve({
          exitCode: exitCode || 0,
          output,
          errors
        });
      });

      child.on('error', (error) => {
        resolve({
          exitCode: 1,
          output,
          errors: errors + error.message
        });
      });
    });
  }

  private extractTestCount(output: string): number {
    const match = output.match(/(\d+) tests?/i);
    return match ? parseInt(match[1]) : 0;
  }

  private extractPassCount(output: string): number {
    const match = output.match(/(\d+) passed/i);
    return match ? parseInt(match[1]) : 0;
  }

  private extractFailCount(output: string): number {
    const match = output.match(/(\d+) failed/i);
    return match ? parseInt(match[1]) : 0;
  }

  private async generateReports(): Promise<void> {
    console.log('\n📊 Generating comprehensive reports...');

    const report = this.reporter.generateSummaryReport();

    // Console report
    const consoleReport = this.reporter.exportReport('console');
    console.log(consoleReport);

    // JSON report for CI/CD
    const jsonReport = this.reporter.exportReport('json');
    writeFileSync(join(this.outputDir, 'rbac-test-report.json'), jsonReport);

    // HTML report for human review
    const htmlReport = this.reporter.exportReport('html');
    writeFileSync(join(this.outputDir, 'rbac-test-report.html'), htmlReport);

    // Performance metrics CSV
    await this.generatePerformanceCSV(report);

    // Security summary
    await this.generateSecuritySummary(report);

    console.log(`✅ Reports generated in: ${this.outputDir}`);
  }

  private async generatePerformanceCSV(report: any): Promise<void> {
    if (!report.performance || !report.performance.metrics) {
      return;
    }

    const csvLines = ['Metric,Value,Threshold,Pass,Timestamp'];
    
    Object.entries(report.performance.metrics).forEach(([name, metric]: [string, any]) => {
      csvLines.push(
        `${name},${metric.value},${metric.threshold},${metric.pass},${new Date(metric.timestamp).toISOString()}`
      );
    });

    writeFileSync(join(this.outputDir, 'performance-metrics.csv'), csvLines.join('\n'));
  }

  private async generateSecuritySummary(report: any): Promise<void> {
    if (!report.security) {
      return;
    }

    const summary = {
      timestamp: new Date().toISOString(),
      passRate: report.security.passRate,
      totalTests: report.security.totalTests,
      criticalFailures: report.security.criticalFailures,
      recommendations: report.recommendations.filter((r: string) => r.includes('CRITICAL')),
      overallStatus: report.summary.overallStatus
    };

    writeFileSync(
      join(this.outputDir, 'security-summary.json'), 
      JSON.stringify(summary, null, 2)
    );
  }

  private async generateErrorReport(error: any): Promise<void> {
    const errorReport = {
      timestamp: new Date().toISOString(),
      error: error.message,
      stack: error.stack,
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        env: process.env.NODE_ENV
      },
      recommendations: [
        '🔧 Check database connectivity and credentials',
        '🔧 Verify test environment setup',
        '🔧 Review test configuration files',
        '🔧 Check for conflicting processes using test databases'
      ]
    };

    writeFileSync(
      join(this.outputDir, 'error-report.json'),
      JSON.stringify(errorReport, null, 2)
    );

    console.error('\n💥 Error report generated in:', join(this.outputDir, 'error-report.json'));
  }
}

// CLI interface
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
🔒 RBAC Comprehensive Test Suite

Usage:
  npm run test:rbac:comprehensive         # Run all RBAC tests
  npm run test:rbac:comprehensive -- --performance-only   # Performance tests only
  npm run test:rbac:comprehensive -- --security-only      # Security tests only
  npm run test:rbac:comprehensive -- --fast               # Skip performance tests

Options:
  --help, -h          Show this help message
  --performance-only  Run only performance benchmarks
  --security-only     Run only security tests
  --fast             Skip time-consuming performance tests
  --verbose          Show detailed output
  --output DIR       Set custom output directory

Environment Variables:
  TEST_DB_HOST        Database host (default: localhost)
  TEST_DB_PORT        Database port (default: 5432)
  TEST_DB_USER        Database user (default: test_user)
  TEST_DB_PASSWORD    Database password (default: test)
  RBAC_TEST_PARALLEL  Number of parallel workers (default: 4)
    `);
    return;
  }

  // Handle test filtering flags
  if (args.includes('--performance-only')) {
    process.env.RBAC_TEST_FILTER = 'performance';
  } else if (args.includes('--security-only')) {
    process.env.RBAC_TEST_FILTER = 'security';
  } else if (args.includes('--fast')) {
    process.env.RBAC_TEST_FAST = 'true';
  }

  if (args.includes('--verbose')) {
    process.env.RBAC_TEST_VERBOSE = 'true';
  }

  const orchestrator = new RBACTestOrchestrator();
  await orchestrator.runComprehensiveTests();
}

// Execute if run directly
if (require.main === module) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { RBACTestOrchestrator };