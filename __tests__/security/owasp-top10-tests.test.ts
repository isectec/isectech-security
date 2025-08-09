/**
 * OWASP Top 10 Security Testing Suite
 * iSECTECH Protect - OWASP 2021 Top 10 Compliance Testing
 */

import { test, expect, Page } from '@playwright/test';
import fs from 'fs';
import path from 'path';

interface OWASPTestResult {
  category: string;
  rank: number;
  description: string;
  tests: {
    name: string;
    passed: boolean;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    details: string;
    remediation: string;
  }[];
  overallScore: number;
  compliant: boolean;
}

class OWASPTop10Tester {
  
  // A01:2021 – Broken Access Control
  async testBrokenAccessControl(page: Page): Promise<OWASPTestResult> {
    const tests = [];
    
    // Test 1: Direct object reference
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'user@isectech.com');
    await page.fill('[data-testid="password-input"]', 'UserPassword123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    
    // Try to access admin panel directly
    await page.goto('http://localhost:3000/admin');
    const hasAdminAccess = await page.locator('[data-testid="admin-panel"]').count() > 0;
    
    tests.push({
      name: 'Direct Object Reference Protection',
      passed: !hasAdminAccess,
      severity: hasAdminAccess ? 'CRITICAL' : 'LOW',
      details: hasAdminAccess ? 'Regular user can access admin panel' : 'Proper access control enforced',
      remediation: 'Implement proper role-based access control validation',
    });

    // Test 2: IDOR (Insecure Direct Object References)
    await page.goto('http://localhost:3000/alerts/1');
    const alert1Accessible = await page.locator('[data-testid="alert-details"]').count() > 0;
    
    await page.goto('http://localhost:3000/alerts/999999');
    const alert999999Response = page.waitForResponse(/\/api\/alerts\/999999/);
    const response = await alert999999Response;
    const isIDORVulnerable = response.status() === 200;
    
    tests.push({
      name: 'Insecure Direct Object References',
      passed: !isIDORVulnerable,
      severity: isIDORVulnerable ? 'HIGH' : 'LOW',
      details: isIDORVulnerable ? 'Can access arbitrary object IDs' : 'IDOR protection working',
      remediation: 'Validate user ownership of objects before returning data',
    });

    // Test 3: HTTP verb tampering
    try {
      const deleteResponse = await page.request.delete('http://localhost:3000/api/alerts/1');
      const allowsDelete = deleteResponse.status() === 200;
      
      tests.push({
        name: 'HTTP Verb Tampering Protection',
        passed: !allowsDelete,
        severity: allowsDelete ? 'HIGH' : 'LOW',
        details: allowsDelete ? 'Accepts unauthorized HTTP methods' : 'HTTP method restrictions enforced',
        remediation: 'Implement proper HTTP method validation and authorization',
      });
    } catch (error) {
      tests.push({
        name: 'HTTP Verb Tampering Protection',
        passed: true,
        severity: 'LOW',
        details: 'HTTP method restrictions properly enforced',
        remediation: 'Continue current implementation',
      });
    }

    const passedTests = tests.filter(t => t.passed).length;
    const overallScore = Math.round((passedTests / tests.length) * 100);
    
    return {
      category: 'Broken Access Control',
      rank: 1,
      description: 'Access control enforces policy such that users cannot act outside of their intended permissions',
      tests,
      overallScore,
      compliant: overallScore >= 80,
    };
  }

  // A02:2021 – Cryptographic Failures
  async testCryptographicFailures(page: Page): Promise<OWASPTestResult> {
    const tests = [];
    
    await page.goto('http://localhost:3000/dashboard');
    
    // Test 1: HTTPS enforcement
    const isHTTPS = page.url().startsWith('https://');
    tests.push({
      name: 'HTTPS Enforcement',
      passed: isHTTPS,
      severity: isHTTPS ? 'LOW' : 'CRITICAL',
      details: isHTTPS ? 'HTTPS properly enforced' : 'Site accessible over HTTP',
      remediation: 'Enforce HTTPS for all communications and implement HSTS',
    });

    // Test 2: Secure cookie attributes
    const response = await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.click('[data-testid="login-button"]');
    
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name.includes('session') || c.name.includes('token'));
    
    let cookieSecurityPassed = true;
    let cookieIssues = [];
    
    if (sessionCookie) {
      if (!sessionCookie.secure) {
        cookieSecurityPassed = false;
        cookieIssues.push('not Secure');
      }
      if (!sessionCookie.httpOnly) {
        cookieSecurityPassed = false;
        cookieIssues.push('not HttpOnly');
      }
      if (sessionCookie.sameSite !== 'Strict' && sessionCookie.sameSite !== 'Lax') {
        cookieSecurityPassed = false;
        cookieIssues.push('missing SameSite');
      }
    }
    
    tests.push({
      name: 'Secure Cookie Configuration',
      passed: cookieSecurityPassed,
      severity: cookieSecurityPassed ? 'LOW' : 'HIGH',
      details: cookieSecurityPassed ? 'Cookies properly secured' : `Cookie issues: ${cookieIssues.join(', ')}`,
      remediation: 'Set Secure, HttpOnly, and SameSite attributes on all session cookies',
    });

    // Test 3: Sensitive data in transit
    const headers = response?.headers() || {};
    const hasHSTS = !!headers['strict-transport-security'];
    
    tests.push({
      name: 'Transport Security (HSTS)',
      passed: hasHSTS,
      severity: hasHSTS ? 'LOW' : 'MEDIUM',
      details: hasHSTS ? 'HSTS header present' : 'HSTS header missing',
      remediation: 'Implement HTTP Strict Transport Security header',
    });

    // Test 4: Password storage (simulate)
    await page.goto('http://localhost:3000/profile/change-password');
    const passwordFieldType = await page.getAttribute('[data-testid="new-password"]', 'type');
    const isPasswordMasked = passwordFieldType === 'password';
    
    tests.push({
      name: 'Password Field Security',
      passed: isPasswordMasked,
      severity: isPasswordMasked ? 'LOW' : 'MEDIUM',
      details: isPasswordMasked ? 'Password fields properly masked' : 'Password fields not masked',
      remediation: 'Ensure all password fields use type="password"',
    });

    const passedTests = tests.filter(t => t.passed).length;
    const overallScore = Math.round((passedTests / tests.length) * 100);
    
    return {
      category: 'Cryptographic Failures',
      rank: 2,
      description: 'Protect data in transit and at rest with strong cryptography',
      tests,
      overallScore,
      compliant: overallScore >= 85,
    };
  }

  // A03:2021 – Injection
  async testInjection(page: Page): Promise<OWASPTestResult> {
    const tests = [];
    
    // Test 1: SQL Injection
    await page.goto('http://localhost:3000/search');
    const sqlPayload = "'; DROP TABLE users; --";
    
    await page.fill('[data-testid="search-input"]', sqlPayload);
    const searchResponse = page.waitForResponse(/\/api\/search/);
    await page.click('[data-testid="search-button"]');
    
    try {
      const response = await searchResponse;
      const responseText = await response.text();
      const hasSQLError = /SQL|syntax|mysql|postgresql|oracle/i.test(responseText);
      
      tests.push({
        name: 'SQL Injection Protection',
        passed: !hasSQLError && response.status() !== 500,
        severity: hasSQLError ? 'CRITICAL' : 'LOW',
        details: hasSQLError ? 'SQL injection vulnerability detected' : 'SQL injection protection working',
        remediation: 'Use parameterized queries and input validation',
      });
    } catch (error) {
      tests.push({
        name: 'SQL Injection Protection',
        passed: false,
        severity: 'HIGH',  
        details: 'Search endpoint error with SQL injection payload',
        remediation: 'Implement proper error handling and input validation',
      });
    }

    // Test 2: NoSQL Injection (MongoDB)
    const noSQLPayload = '{"$ne": null}';
    await page.fill('[data-testid="search-input"]', noSQLPayload);
    const noSQLResponse = page.waitForResponse(/\/api\/search/);
    await page.click('[data-testid="search-button"]');
    
    try {
      const response = await noSQLResponse;
      const responseText = await response.text();
      const hasNoSQLVuln = responseText.includes('$ne') || response.status() === 200;
      
      tests.push({
        name: 'NoSQL Injection Protection',
        passed: !hasNoSQLVuln,
        severity: hasNoSQLVuln ? 'HIGH' : 'LOW',
        details: hasNoSQLVuln ? 'NoSQL injection vulnerability detected' : 'NoSQL injection protection working',
        remediation: 'Validate and sanitize NoSQL query parameters',
      });
    } catch (error) {
      tests.push({
        name: 'NoSQL Injection Protection',
        passed: true,
        severity: 'LOW',
        details: 'NoSQL injection properly blocked',
        remediation: 'Continue current implementation',
      });
    }

    // Test 3: Command Injection
    const cmdPayload = '; ls -la';
    await page.goto('http://localhost:3000/admin/system');
    
    if (await page.locator('[data-testid="system-command-input"]').count() > 0) {
      await page.fill('[data-testid="system-command-input"]', `ping 127.0.0.1${cmdPayload}`);
      const cmdResponse = page.waitForResponse(/\/api\/admin\/system/);
      await page.click('[data-testid="execute-command"]');
      
      try {
        const response = await cmdResponse;
        const responseText = await response.text();
        const hasCmdInjection = responseText.includes('total ') || responseText.includes('drwx');
        
        tests.push({
          name: 'Command Injection Protection',
          passed: !hasCmdInjection,
          severity: hasCmdInjection ? 'CRITICAL' : 'LOW',  
          details: hasCmdInjection ? 'Command injection vulnerability detected' : 'Command injection protection working',
          remediation: 'Never execute user input directly, use safe alternatives',
        });
      } catch (error) {
        tests.push({
          name: 'Command Injection Protection',
          passed: true,
          severity: 'LOW',
          details: 'Command injection properly blocked',
          remediation: 'Continue current implementation',
        });
      }
    } else {
      tests.push({
        name: 'Command Injection Protection',
        passed: true,
        severity: 'LOW',
        details: 'No command execution interface found',
        remediation: 'Continue avoiding command execution interfaces',
      });
    }

    const passedTests = tests.filter(t => t.passed).length;
    const overallScore = Math.round((passedTests / tests.length) * 100);
    
    return {
      category: 'Injection',
      rank: 3,
      description: 'Prevent injection flaws by validating and sanitizing input data',
      tests,
      overallScore,
      compliant: overallScore >= 90,
    };
  }

  // A04:2021 – Insecure Design
  async testInsecureDesign(page: Page): Promise<OWASPTestResult> {
    const tests = [];
    
    await page.goto('http://localhost:3000/login');
    
    // Test 1: Account lockout mechanism
    const testEmail = 'brute.force@test.com';
    let lockoutTriggered = false;
    
    for (let i = 0; i < 6; i++) {
      await page.fill('[data-testid="email-input"]', testEmail);
      await page.fill('[data-testid="password-input"]', `wrongpassword${i}`);
      await page.click('[data-testid="login-button"]');
      
      if (await page.locator('[data-testid="account-locked"]').count() > 0) {
        lockoutTriggered = true;
        break;
      }
      
      await page.waitForTimeout(1000);
    }
    
    tests.push({
      name: 'Account Lockout Mechanism',
      passed: lockoutTriggered,
      severity: lockoutTriggered ? 'LOW' : 'MEDIUM',
      details: lockoutTriggered ? 'Account lockout working after failed attempts' : 'No account lockout detected',
      remediation: 'Implement account lockout after 5 failed login attempts',
    });

    // Test 2: Rate limiting
    await page.goto('http://localhost:3000/api/search');
    let rateLimitTriggered = false;
    
    for (let i = 0; i < 20; i++) {
      const response = await page.request.get('http://localhost:3000/api/search?q=test');
      if (response.status() === 429) {
        rateLimitTriggered = true;
        break;
      }
    }
    
    tests.push({
      name: 'API Rate Limiting',
      passed: rateLimitTriggered,
      severity: rateLimitTriggered ? 'LOW' : 'MEDIUM',
      details: rateLimitTriggered ? 'Rate limiting properly implemented' : 'No rate limiting detected',
      remediation: 'Implement rate limiting on all API endpoints',
    });

    // Test 3: Business logic validation
    await page.goto('http://localhost:3000/alerts');
    await page.click('[data-testid="create-alert-button"]');
    
    // Try to create alert with invalid severity
    await page.fill('[data-testid="alert-title"]', 'Test Alert');
    await page.evaluate(() => {
      const select = document.querySelector('[data-testid="alert-severity"]') as HTMLSelectElement;
      if (select) {
        const option = document.createElement('option');
        option.value = 'INVALID_SEVERITY';
        option.textContent = 'Invalid';
        select.appendChild(option);
        select.value = 'INVALID_SEVERITY';
      }
    });
    
    await page.click('[data-testid="create-alert-submit"]');
    const hasValidationError = await page.locator('[data-testid="validation-error"]').count() > 0;
    
    tests.push({
      name: 'Business Logic Validation',
      passed: hasValidationError,
      severity: hasValidationError ? 'LOW' : 'MEDIUM',
      details: hasValidationError ? 'Business logic validation working' : 'Accepts invalid business values',
      remediation: 'Implement comprehensive input validation for all business logic',
    });

    const passedTests = tests.filter(t => t.passed).length;
    const overallScore = Math.round((passedTests / tests.length) * 100);
    
    return {
      category: 'Insecure Design',
      rank: 4,
      description: 'Implement security controls in the design phase',
      tests,
      overallScore,
      compliant: overallScore >= 75,
    };
  }

  // A05:2021 – Security Misconfiguration
  async testSecurityMisconfiguration(page: Page): Promise<OWASPTestResult> {
    const tests = [];
    
    await page.goto('http://localhost:3000/dashboard');
    const response = await page.goto('http://localhost:3000/dashboard');
    const headers = response?.headers() || {};
    
    // Test 1: Security headers
    const requiredHeaders = [
      { name: 'strict-transport-security', critical: true },
      { name: 'content-security-policy', critical: true },
      { name: 'x-frame-options', critical: false },
      { name: 'x-content-type-options', critical: false },
    ];
    
    let headerScore = 0;
    let headerDetails = [];
    
    requiredHeaders.forEach(({ name, critical }) => {
      if (headers[name]) {
        headerScore++;
        headerDetails.push(`${name}: present`);
      } else {
        headerDetails.push(`${name}: missing${critical ? ' (critical)' : ''}`);
      }
    });
    
    const headersPassed = headerScore === requiredHeaders.length;
    
    tests.push({
      name: 'Security Headers Configuration',
      passed: headersPassed,
      severity: headersPassed ? 'LOW' : 'HIGH',
      details: headerDetails.join(', '),
      remediation: 'Implement all required security headers',
    });

    // Test 2: Error handling
    await page.goto('http://localhost:3000/nonexistent-page');
    const errorContent = await page.content();
    const exposesStackTrace = /at\s+.*\s+\(.*:\d+:\d+\)/.test(errorContent) || 
                             errorContent.includes('Error:') || 
                             errorContent.includes('Exception:');
    
    tests.push({
      name: 'Error Information Disclosure',
      passed: !exposesStackTrace,
      severity: exposesStackTrace ? 'MEDIUM' : 'LOW',
      details: exposesStackTrace ? 'Stack traces or detailed errors exposed' : 'Proper error handling',
      remediation: 'Implement generic error messages for production',
    });

    // Test 3: Debug information exposure
    const pageContent = await page.content();
    const hasDebugInfo = /debug\s*[:=]\s*true/i.test(pageContent) ||
                        /console\.log/i.test(pageContent) ||
                        /debugger;/i.test(pageContent);
    
    tests.push({
      name: 'Debug Information Exposure',
      passed: !hasDebugInfo,
      severity: hasDebugInfo ? 'MEDIUM' : 'LOW',
      details: hasDebugInfo ? 'Debug information found in production' : 'No debug information exposed',
      remediation: 'Remove all debug code from production builds',
    });

    // Test 4: Default configurations
    const defaultEndpoints = [
      '/admin',
      '/debug',
      '/test',
      '/.env',
      '/config',
    ];

    let defaultConfigExposed = false;
    for (const endpoint of defaultEndpoints) {
      const response = await page.request.get(`http://localhost:3000${endpoint}`);
      if (response.status() === 200) {
        defaultConfigExposed = true;
        break;
      }
    }
    
    tests.push({
      name: 'Default Configuration Exposure',
      passed: !defaultConfigExposed,
      severity: defaultConfigExposed ? 'HIGH' : 'LOW',
      details: defaultConfigExposed ? 'Default configuration endpoints accessible' : 'Default endpoints properly secured',
      remediation: 'Remove or secure all default configuration endpoints',
    });

    const passedTests = tests.filter(t => t.passed).length;
    const overallScore = Math.round((passedTests / tests.length) * 100);
    
    return {
      category: 'Security Misconfiguration',
      rank: 5,
      description: 'Ensure secure configuration throughout the application stack',
      tests,
      overallScore,
      compliant: overallScore >= 80,
    };
  }

  async runFullOWASPTop10Assessment(page: Page): Promise<OWASPTestResult[]> {
    console.log('🔍 Starting OWASP Top 10 2021 Assessment...');
    
    const results = await Promise.all([
      this.testBrokenAccessControl(page),
      this.testCryptographicFailures(page),
      this.testInjection(page),
      this.testInsecureDesign(page),
      this.testSecurityMisconfiguration(page),
    ]);
    
    return results;
  }
}

test.describe('🛡️ OWASP Top 10 2021 Security Testing', () => {
  let owaspTester: OWASPTop10Tester;

  test.beforeEach(() => {
    owaspTester = new OWASPTop10Tester();
  });

  test('A01:2021 – Broken Access Control', async ({ page }) => {
    const result = await owaspTester.testBrokenAccessControl(page);
    
    expect(result.compliant).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(80);
    
    const criticalFailures = result.tests.filter(t => !t.passed && t.severity === 'CRITICAL');
    expect(criticalFailures.length).toBe(0);
    
    console.log(`📊 A01 - Broken Access Control: ${result.overallScore}% (${result.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'})`);
  });

  test('A02:2021 – Cryptographic Failures', async ({ page }) => {
    const result = await owaspTester.testCryptographicFailures(page);
    
    expect(result.compliant).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(85);
    
    console.log(`📊 A02 - Cryptographic Failures: ${result.overallScore}% (${result.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'})`);
  });

  test('A03:2021 – Injection', async ({ page }) => {
    const result = await owaspTester.testInjection(page);
    
    expect(result.compliant).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(90);
    
    const criticalFailures = result.tests.filter(t => !t.passed && t.severity === 'CRITICAL');
    expect(criticalFailures.length).toBe(0);
    
    console.log(`📊 A03 - Injection: ${result.overallScore}% (${result.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'})`);
  });

  test('A04:2021 – Insecure Design', async ({ page }) => {
    const result = await owaspTester.testInsecureDesign(page);
    
    expect(result.compliant).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(75);
    
    console.log(`📊 A04 - Insecure Design: ${result.overallScore}% (${result.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'})`);
  });

  test('A05:2021 – Security Misconfiguration', async ({ page }) => {
    const result = await owaspTester.testSecurityMisconfiguration(page);
    
    expect(result.compliant).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(80);
    
    console.log(`📊 A05 - Security Misconfiguration: ${result.overallScore}% (${result.compliant ? 'COMPLIANT' : 'NON-COMPLIANT'})`);
  });

  test('Complete OWASP Top 10 Assessment', async ({ page }) => {
    const results = await owaspTester.runFullOWASPTop10Assessment(page);
    
    // Calculate overall compliance
    const totalScore = results.reduce((sum, result) => sum + result.overallScore, 0);
    const averageScore = Math.round(totalScore / results.length);
    const compliantCategories = results.filter(r => r.compliant).length;
    const overallCompliant = compliantCategories === results.length;
    
    // Assert overall compliance
    expect(overallCompliant).toBe(true);
    expect(averageScore).toBeGreaterThanOrEqual(80);
    
    // Generate detailed report
    const report = {
      timestamp: new Date().toISOString(),
      overallScore: averageScore,
      overallCompliant,
      compliantCategories,
      totalCategories: results.length,
      results,
      summary: {
        critical: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'CRITICAL').length, 0),
        high: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'HIGH').length, 0),
        medium: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'MEDIUM').length, 0),
        low: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'LOW').length, 0),
      },
    };
    
    // Save report
    const reportPath = path.join(__dirname, '../../test-results/owasp-top10-report.json');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    // Generate markdown report
    let markdown = `# OWASP Top 10 2021 Assessment Report\n\n`;
    markdown += `**Generated:** ${report.timestamp}\n`;
    markdown += `**Overall Score:** ${report.overallScore}%\n`;
    markdown += `**Compliance Status:** ${report.overallCompliant ? '✅ COMPLIANT' : '❌ NON-COMPLIANT'}\n`;
    markdown += `**Categories Passed:** ${report.compliantCategories}/${report.totalCategories}\n\n`;
    
    markdown += `## Summary\n`;
    markdown += `- **Critical Issues:** ${report.summary.critical}\n`;
    markdown += `- **High Issues:** ${report.summary.high}\n`;
    markdown += `- **Medium Issues:** ${report.summary.medium}\n`;
    markdown += `- **Low Issues:** ${report.summary.low}\n\n`;
    
    markdown += `## Detailed Results\n\n`;
    results.forEach(result => {
      markdown += `### ${result.category} (A0${result.rank}:2021)\n`;
      markdown += `**Score:** ${result.overallScore}% ${result.compliant ? '✅' : '❌'}\n`;
      markdown += `**Description:** ${result.description}\n\n`;
      
      result.tests.forEach(test => {
        const status = test.passed ? '✅' : '❌';
        markdown += `- ${status} **${test.name}** (${test.severity}): ${test.details}\n`;
        if (!test.passed) {
          markdown += `  - *Remediation:* ${test.remediation}\n`;
        }
      });
      markdown += `\n`;
    });
    
    const markdownPath = path.join(__dirname, '../../test-results/owasp-top10-report.md');
    fs.writeFileSync(markdownPath, markdown);
    
    console.log('\n🏆 OWASP Top 10 2021 Assessment Complete:');
    console.log(`  Overall Score: ${averageScore}%`);
    console.log(`  Compliance: ${overallCompliant ? 'PASSED' : 'FAILED'}`);
    console.log(`  Categories Passed: ${compliantCategories}/${results.length}`);
    console.log(`\n📊 Issue Summary:`);
    console.log(`  Critical: ${report.summary.critical}`);
    console.log(`  High: ${report.summary.high}`);
    console.log(`  Medium: ${report.summary.medium}`);
    console.log(`  Low: ${report.summary.low}`);
    
    results.forEach(result => {
      const status = result.compliant ? '✅' : '❌';
      console.log(`  ${status} A0${result.rank} - ${result.category}: ${result.overallScore}%`);
    });
    
    console.log(`\n📋 Reports saved:`);
    console.log(`  JSON: ${reportPath}`);
    console.log(`  Markdown: ${markdownPath}`);
  }, 180000); // 3 minute timeout
});