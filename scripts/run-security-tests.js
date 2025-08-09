#!/usr/bin/env node

/**
 * Security Test Runner Script
 * Orchestrates comprehensive security testing for CI/CD pipelines
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class SecurityTestRunner {
  constructor() {
    this.configPath = path.join(__dirname, '../__tests__/security/security-test-config.json');
    this.config = this.loadConfiguration();
    this.environment = process.env.TEST_ENVIRONMENT || 'ci';
    this.verbose = process.argv.includes('--verbose') || process.env.VERBOSE === 'true';
    this.dryRun = process.argv.includes('--dry-run');
    this.testResults = [];
  }

  loadConfiguration() {
    try {
      const configContent = fs.readFileSync(this.configPath, 'utf8');
      return JSON.parse(configContent);
    } catch (error) {
      console.error('❌ Failed to load security test configuration:', error.message);
      process.exit(1);
    }
  }

  getEnvironmentConfig() {
    return this.config.environments[this.environment] || this.config.environments.ci;
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = level === 'error' ? '❌' : level === 'warn' ? '⚠️' : level === 'success' ? '✅' : 'ℹ️';
    
    if (level === 'verbose' && !this.verbose) return;
    
    console.log(`[${timestamp}] ${prefix} ${message}`);
  }

  async runTest(testCategory, envConfig) {
    const testInfo = this.config.testCategories[testCategory];
    if (!testInfo) {
      this.log(`Unknown test category: ${testCategory}`, 'error');
      return { success: false, category: testCategory, error: 'Unknown category' };
    }

    this.log(`Running ${testInfo.name} tests...`);
    
    if (this.dryRun) {
      this.log(`[DRY RUN] Would run: ${testInfo.testFile} with pattern: ${testInfo.testPattern}`, 'verbose');
      return { success: true, category: testCategory, dryRun: true };
    }

    const testCommand = [
      'npm', 'test', '--',
      `__tests__/security/${testInfo.testFile}`,
      '--maxWorkers=' + envConfig.maxWorkers,
      '--timeout=' + envConfig.timeout,
      `--testNamePattern="${testInfo.testPattern}"`,
      '--reporter=json',
      '--outputFile=test-results/security-' + testCategory + '-results.json'
    ];

    try {
      const startTime = Date.now();
      
      this.log(`Executing: ${testCommand.join(' ')}`, 'verbose');
      
      const result = execSync(testCommand.join(' '), {
        cwd: path.join(__dirname, '..'),
        encoding: 'utf8',
        timeout: envConfig.timeout,
        env: {
          ...process.env,
          TARGET_URL: envConfig.baseURL,
          TEST_ENVIRONMENT: this.environment,
          BUILD_ID: process.env.BUILD_ID || Date.now().toString(),
          CI: process.env.CI || 'true'
        }
      });

      const executionTime = Date.now() - startTime;
      this.log(`✅ ${testInfo.name} completed in ${executionTime}ms`);
      
      return {
        success: true,
        category: testCategory,
        executionTime,
        output: result
      };

    } catch (error) {
      this.log(`❌ ${testInfo.name} failed: ${error.message}`, 'error');
      
      // Check if it's a critical test that should block deployment
      const isCritical = testInfo.severity === 'CRITICAL' || testInfo.requiredForCI;
      
      return {
        success: false,
        category: testCategory,
        error: error.message,
        critical: isCritical,
        output: error.stdout || error.output || ''
      };
    }
  }

  async runAllTests() {
    const envConfig = this.getEnvironmentConfig();
    const testsToRun = envConfig.enabledTests.filter(test => 
      this.config.testCategories[test]
    );

    this.log(`🔒 Starting security test suite for ${this.environment} environment`);
    this.log(`📊 Base URL: ${envConfig.baseURL}`);
    this.log(`🧪 Tests to run: ${testsToRun.join(', ')}`);
    this.log(`⚡ Max workers: ${envConfig.maxWorkers}`);
    this.log(`⏱️ Timeout: ${envConfig.timeout}ms`);

    if (this.dryRun) {
      this.log('🏃 Running in DRY RUN mode - no tests will be executed', 'warn');
    }

    // Ensure test results directory exists
    const resultsDir = path.join(__dirname, '..', 'test-results');
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const results = [];
    let criticalFailures = 0;
    let totalFailures = 0;

    // Run tests sequentially to avoid resource conflicts
    for (const testCategory of testsToRun) {
      const result = await this.runTest(testCategory, envConfig);
      results.push(result);

      if (!result.success) {
        totalFailures++;
        if (result.critical) {
          criticalFailures++;
        }
      }
    }

    // Generate summary report
    const summary = this.generateSummaryReport(results, envConfig);
    
    this.log(`\n📊 Security Test Summary:`);
    this.log(`   Total tests: ${results.length}`);
    this.log(`   Passed: ${results.filter(r => r.success).length}`);
    this.log(`   Failed: ${totalFailures}`);
    this.log(`   Critical failures: ${criticalFailures}`);
    
    // Check thresholds and determine if deployment should be blocked
    const shouldBlockDeployment = this.evaluateDeploymentBlocking(summary, envConfig);
    
    if (shouldBlockDeployment) {
      this.log(`🚨 DEPLOYMENT BLOCKED due to critical security issues`, 'error');
      
      // Save blocking reasons
      summary.deploymentBlocked = true;
      summary.blockingReasons = this.getBlockingReasons(summary, envConfig);
      
    } else {
      this.log(`✅ Security tests passed - deployment may proceed`, 'success');
      summary.deploymentBlocked = false;
    }

    // Save comprehensive summary
    const summaryPath = path.join(resultsDir, 'security-test-summary.json');
    fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
    this.log(`📄 Summary report saved: ${summaryPath}`);

    // Generate notifications if enabled
    if (envConfig.reportingEnabled) {
      await this.sendNotifications(summary);
    }

    // Exit with appropriate code
    if (shouldBlockDeployment) {
      process.exit(1);
    } else if (totalFailures > 0) {
      process.exit(2); // Non-critical failures
    } else {
      process.exit(0); // All tests passed
    }
  }

  generateSummaryReport(results, envConfig) {
    const timestamp = new Date().toISOString();
    const passed = results.filter(r => r.success).length;
    const failed = results.length - passed;
    const criticalFailed = results.filter(r => !r.success && r.critical).length;

    return {
      timestamp,
      environment: this.environment,
      buildId: process.env.BUILD_ID || 'local',
      commitHash: this.getCommitHash(),
      branch: this.getBranch(),
      summary: {
        totalTests: results.length,
        passed,
        failed,
        criticalFailed,
        successRate: (passed / results.length) * 100
      },
      results: results.map(r => ({
        category: r.category,
        name: this.config.testCategories[r.category]?.name || r.category,
        success: r.success,
        critical: r.critical || false,
        executionTime: r.executionTime || 0,
        error: r.error || null,
        dryRun: r.dryRun || false
      })),
      thresholds: this.config.securityThresholds,
      compliance: this.evaluateCompliance(results),
      recommendations: this.generateRecommendations(results),
      configuration: {
        environment: this.environment,
        baseURL: envConfig.baseURL,
        enabledTests: envConfig.enabledTests,
        thresholds: envConfig
      }
    };
  }

  evaluateCompliance(results) {
    const compliance = {};
    
    Object.entries(this.config.complianceFrameworks).forEach(([framework, config]) => {
      if (!config.enabled) return;
      
      const criticalFailures = results.filter(r => !r.success && r.critical).length;
      const totalFailures = results.filter(r => !r.success).length;
      
      // Calculate compliance score based on test results
      let score = 100;
      score -= (criticalFailures * 25); // Critical failures heavily impact compliance
      score -= (totalFailures * 10);    // Any failure impacts compliance
      score = Math.max(0, score);
      
      const status = score >= config.minimumScore ? 'PASS' : 
                    score >= (config.minimumScore * 0.8) ? 'WARNING' : 'FAIL';
      
      compliance[framework] = {
        score,
        status,
        minimumRequired: config.minimumScore,
        controlsEvaluated: config.requiredControls || []
      };
    });
    
    return compliance;
  }

  generateRecommendations(results) {
    const recommendations = [];
    
    const criticalFailures = results.filter(r => !r.success && r.critical);
    const nonCriticalFailures = results.filter(r => !r.success && !r.critical);
    
    if (criticalFailures.length > 0) {
      recommendations.push('🔥 IMMEDIATE ACTION REQUIRED: Fix critical security test failures before deployment');
      criticalFailures.forEach(failure => {
        recommendations.push(`   - Fix ${this.config.testCategories[failure.category]?.name || failure.category}`);
      });
    }
    
    if (nonCriticalFailures.length > 0) {
      recommendations.push('⚠️ Address non-critical security test failures in next sprint');
      nonCriticalFailures.forEach(failure => {
        recommendations.push(`   - Review ${this.config.testCategories[failure.category]?.name || failure.category}`);
      });
    }
    
    if (results.every(r => r.success)) {
      recommendations.push('✅ All security tests passing - maintain current security posture');
      recommendations.push('📈 Consider adding additional security test coverage');
    }
    
    recommendations.push('🔄 Update security test baselines with current results');
    recommendations.push('📊 Review security metrics trends and patterns');
    
    return recommendations;
  }

  evaluateDeploymentBlocking(summary, envConfig) {
    // Block deployment if there are critical failures
    if (summary.summary.criticalFailed > 0) {
      return true;
    }
    
    // Block deployment based on environment-specific thresholds
    const thresholds = this.config.securityThresholds;
    const env = this.environment;
    
    if (thresholds.criticalVulnerabilities[env] !== undefined && 
        summary.summary.criticalFailed > thresholds.criticalVulnerabilities[env]) {
      return true;
    }
    
    // Check overall success rate
    const successRateThreshold = thresholds.authorizationSuccessRate[env] || 80;
    if (summary.summary.successRate < successRateThreshold) {
      return true;
    }
    
    // Environment-specific blocking rules
    if (env === 'production' && summary.summary.failed > 0) {
      return true; // Production has zero tolerance for failures
    }
    
    return false;
  }

  getBlockingReasons(summary, envConfig) {
    const reasons = [];
    
    if (summary.summary.criticalFailed > 0) {
      reasons.push(`${summary.summary.criticalFailed} critical security test failures`);
    }
    
    const successRateThreshold = this.config.securityThresholds.authorizationSuccessRate[this.environment] || 80;
    if (summary.summary.successRate < successRateThreshold) {
      reasons.push(`Success rate ${summary.summary.successRate.toFixed(1)}% below threshold ${successRateThreshold}%`);
    }
    
    if (this.environment === 'production' && summary.summary.failed > 0) {
      reasons.push('Production environment requires 100% test success rate');
    }
    
    return reasons;
  }

  async sendNotifications(summary) {
    const notificationConfig = this.config.notifications;
    
    if (notificationConfig.slack?.enabled && process.env.SLACK_WEBHOOK_URL) {
      await this.sendSlackNotification(summary, notificationConfig.slack);
    }
    
    if (notificationConfig.email?.enabled && process.env.EMAIL_API_KEY) {
      await this.sendEmailNotification(summary, notificationConfig.email);
    }
  }

  async sendSlackNotification(summary, slackConfig) {
    try {
      const webhookUrl = process.env.SLACK_WEBHOOK_URL;
      if (!webhookUrl) return;

      const isSuccess = summary.summary.failed === 0;
      const isCritical = summary.summary.criticalFailed > 0;
      
      const icon = isCritical ? '🔥' : !isSuccess ? '⚠️' : '✅';
      const color = isCritical ? '#ff0000' : !isSuccess ? '#ffaa00' : '#00ff00';
      const channel = isCritical ? slackConfig.criticalChannel : slackConfig.alertsChannel;
      
      const message = {
        text: `${icon} Security Test Results - ${this.environment.toUpperCase()}`,
        attachments: [{
          color,
          fields: [
            {
              title: 'Environment',
              value: this.environment.toUpperCase(),
              short: true
            },
            {
              title: 'Success Rate',
              value: `${summary.summary.successRate.toFixed(1)}%`,
              short: true
            },
            {
              title: 'Tests Passed',
              value: `${summary.summary.passed}/${summary.summary.totalTests}`,
              short: true
            },
            {
              title: 'Critical Failures',
              value: summary.summary.criticalFailed.toString(),
              short: true
            }
          ],
          footer: 'iSECTECH Security Testing',
          ts: Math.floor(Date.now() / 1000)
        }]
      };

      if (channel) {
        message.channel = channel;
      }

      // In a real implementation, this would use proper HTTP client
      this.log(`📱 Slack notification prepared for ${channel || 'default channel'}`, 'verbose');
      
    } catch (error) {
      this.log(`Failed to send Slack notification: ${error.message}`, 'error');
    }
  }

  getCommitHash() {
    try {
      return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
    } catch (error) {
      return 'unknown';
    }
  }

  getBranch() {
    try {
      return execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim();
    } catch (error) {
      return 'unknown';
    }
  }

  printUsage() {
    console.log(`
Usage: node scripts/run-security-tests.js [options]

Options:
  --environment <env>    Set test environment (ci|staging|production)
  --verbose             Enable verbose logging
  --dry-run            Show what would be executed without running tests
  --help               Show this help message

Environment Variables:
  TEST_ENVIRONMENT      Test environment (default: ci)
  TARGET_URL           Override base URL for tests
  BUILD_ID             Build identifier for reporting
  SLACK_WEBHOOK_URL    Slack webhook for notifications
  VERBOSE              Enable verbose logging (true/false)

Examples:
  node scripts/run-security-tests.js --environment staging
  node scripts/run-security-tests.js --dry-run --verbose
  TEST_ENVIRONMENT=production node scripts/run-security-tests.js
    `);
  }
}

// Main execution
async function main() {
  if (process.argv.includes('--help')) {
    new SecurityTestRunner().printUsage();
    process.exit(0);
  }

  const envArg = process.argv.find(arg => arg.startsWith('--environment='));
  if (envArg) {
    process.env.TEST_ENVIRONMENT = envArg.split('=')[1];
  }

  const runner = new SecurityTestRunner();
  
  try {
    await runner.runAllTests();
  } catch (error) {
    console.error('❌ Security test runner failed:', error.message);
    process.exit(3);
  }
}

if (require.main === module) {
  main();
}

module.exports = SecurityTestRunner;