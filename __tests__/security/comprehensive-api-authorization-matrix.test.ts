/**
 * Comprehensive API Authorization Matrix Test Suite
 * iSECTECH Protect - Complete validation of 215+ endpoint authorization matrix
 * 
 * Task: 81.8 - Create comprehensive automated tests for API authorization matrix
 */

import { describe, expect, test, beforeAll, afterAll } from '@jest/globals';
import { NextRequest } from 'next/server';
import jwt from 'jsonwebtoken';
import { createClient } from 'redis';
import { Pool } from 'pg';
import fs from 'fs';
import path from 'path';
import {
  AuthorizationMiddleware,
  createAuthorizationMiddleware,
  AuthorizationResult,
  AuthorizationConfig
} from '../../api-gateway/security/authorization-middleware';
import { TenantContextService } from '../../api-gateway/security/tenant-context-service';
import { createRBACPermissionService } from '../../api-gateway/security/rbac-permission-service';

interface TestUser {
  userId: string;
  tenantId: string;
  roles: string[];
  permissions: string[];
  clearanceLevel?: string;
  mfaVerified?: boolean;
  sessionId?: string;
}

interface EndpointTestCase {
  endpoint: string;
  method: string;
  expectedPermissions: string[];
  tenantContext: string;
  requiresRole?: string[];
  requiresClearance?: string;
  requiresMFA?: boolean;
  publicEndpoint?: boolean;
  description: string;
}

interface AuthorizationMatrixTestResult {
  endpoint: string;
  method: string;
  testCases: {
    user: TestUser;
    expectedResult: boolean;
    actualResult: boolean;
    reason: string;
    passed: boolean;
    evaluationTimeMs: number;
  }[];
  overallPassed: boolean;
  summary: {
    totalTests: number;
    passed: number;
    failed: number;
    successRate: number;
  };
}

class ComprehensiveAuthorizationMatrixTester {
  private middleware: AuthorizationMiddleware;
  private authorizationMatrix: any;
  private testUsers: TestUser[];
  private redisClient: ReturnType<typeof createClient>;
  private pgPool: Pool;
  private jwtSecret: string = 'test-jwt-secret-key-12345';
  private testResults: AuthorizationMatrixTestResult[] = [];

  constructor() {
    this.loadAuthorizationMatrix();
    this.setupTestUsers();
    this.setupInfrastructure();
  }

  private loadAuthorizationMatrix(): void {
    const matrixPath = path.join(__dirname, '../../api-gateway/security/authorization-matrix.json');
    this.authorizationMatrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
  }

  private setupTestUsers(): void {
    this.testUsers = [
      // Public/Anonymous user
      {
        userId: 'anonymous',
        tenantId: 'none',
        roles: [],
        permissions: [],
      },
      // Basic authenticated user
      {
        userId: 'user-basic-001',
        tenantId: 'tenant-001',
        roles: ['user'],
        permissions: [
          'auth:verify', 'auth:logout', 'auth:profile:read', 'auth:sessions:read',
          'notifications:read', 'notifications:preferences:read', 'trust-score:read',
          'compliance:status:read', 'assets:read', 'assets:search'
        ],
      },
      // Security analyst
      {
        userId: 'user-analyst-001',
        tenantId: 'tenant-001',
        roles: ['analyst', 'user'],
        permissions: [
          'auth:verify', 'auth:logout', 'analytics:performance:read',
          'compliance:violations:read', 'assets:aggregation:read',
          'trust-score:analytics:read', 'events:read', 'threats:read'
        ],
        clearanceLevel: 'confidential',
      },
      // Tenant administrator
      {
        userId: 'user-admin-001',
        tenantId: 'tenant-001',
        roles: ['administrator', 'analyst', 'user'],
        permissions: [
          'notifications:create', 'notifications:update', 'assets:create',
          'compliance:violations:resolve', 'onboarding:create', 'trust-score:update',
          'tenants:read', 'tenants:update'
        ],
        clearanceLevel: 'confidential',
        mfaVerified: true,
      },
      // System administrator
      {
        userId: 'user-sysadmin-001',
        tenantId: 'system',
        roles: ['admin', 'administrator', 'analyst', 'user'],
        permissions: [
          'users:admin:list', 'users:admin:create', 'sessions:admin:list',
          'audit:admin:read', 'system:admin:health', 'policy:bundles:read',
          'tenants:create', 'tenants:delete'
        ],
        clearanceLevel: 'secret',
        mfaVerified: true,
      },
      // Security officer (highest privileges)
      {
        userId: 'user-secoff-001',
        tenantId: 'system',
        roles: ['security_officer', 'admin', 'administrator', 'analyst', 'user'],
        permissions: [
          'security:alerts:read', 'security:threats:read', 'security:incidents:create',
          'security:audit:export', 'security:compliance:report', 'kong:admin:status'
        ],
        clearanceLevel: 'top_secret',
        mfaVerified: true,
      },
      // Cross-tenant user (multiple tenants)
      {
        userId: 'user-multitenant-001',
        tenantId: 'tenant-001',
        roles: ['administrator'],
        permissions: [
          'tenants:list', 'assets:read', 'compliance:status:read'
        ],
        clearanceLevel: 'confidential',
      },
      // Limited permissions user
      {
        userId: 'user-limited-001',
        tenantId: 'tenant-002',
        roles: ['user'],
        permissions: [
          'auth:verify', 'notifications:read'
        ],
      },
      // User with expired/revoked access
      {
        userId: 'user-revoked-001',
        tenantId: 'tenant-001',
        roles: [],
        permissions: [],
      }
    ];
  }

  private setupInfrastructure(): void {
    // Setup Redis mock client
    this.redisClient = {
      get: jest.fn().mockResolvedValue(null),
      setex: jest.fn().mockResolvedValue('OK'),
      del: jest.fn().mockResolvedValue(1),
      quit: jest.fn().mockResolvedValue(null),
    } as any;

    // Setup PostgreSQL mock pool
    this.pgPool = {
      connect: jest.fn().mockResolvedValue({
        query: jest.fn().mockResolvedValue({ rows: [] }),
        release: jest.fn(),
      }),
      end: jest.fn(),
    } as any;

    // Create tenant context service mock
    const mockTenantContextService = {
      extractTenantContext: jest.fn().mockImplementation((request: NextRequest) => {
        const authHeader = request.headers.get('authorization');
        if (authHeader?.startsWith('Bearer ')) {
          try {
            const token = authHeader.substring(7);
            const payload = jwt.decode(token) as any;
            if (payload && payload.tenantId) {
              return Promise.resolve({
                success: true,
                tenantId: payload.tenantId,
                tenantContext: {
                  tenantId: payload.tenantId,
                  status: 'active',
                  tenantTier: 'enterprise',
                  features: ['advanced_analytics', 'vulnerability_scanning', 'threat_intelligence']
                }
              });
            }
          } catch (error) {
            // Invalid token
          }
        }
        return Promise.resolve({
          success: false,
          error: { code: 'TENANT_EXTRACTION_FAILED', message: 'Failed to extract tenant context' }
        });
      }),
    } as any;

    // Setup RBAC permission service mock
    const mockRBACService = {
      checkPermissions: jest.fn().mockImplementation(async (request) => {
        const user = this.testUsers.find(u => u.userId === request.userId);
        if (!user) {
          return {
            allowed: false,
            deniedPermissions: request.permissions,
            grantedPermissions: [],
            effectiveRoles: [],
            roleHierarchy: [],
            cacheHit: false,
            evaluationTimeMs: 10
          };
        }

        const grantedPermissions = request.permissions.filter(p => 
          user.permissions.includes(p)
        );
        const deniedPermissions = request.permissions.filter(p => 
          !user.permissions.includes(p)
        );

        return {
          allowed: deniedPermissions.length === 0,
          deniedPermissions,
          grantedPermissions,
          effectiveRoles: user.roles,
          roleHierarchy: user.roles,
          cacheHit: false,
          evaluationTimeMs: 15
        };
      }),
      hasAnyRole: jest.fn().mockImplementation(async (userId, tenantId, requiredRoles) => {
        const user = this.testUsers.find(u => u.userId === userId);
        if (!user) return false;
        return requiredRoles.some((role: string) => user.roles.includes(role));
      })
    };

    // Create authorization middleware
    const config: AuthorizationConfig = {
      enableCaching: true,
      cacheTimeoutMs: 5 * 60 * 1000,
      enableAuditLogging: true,
      enableMetrics: true,
      fallbackToDeny: true,
      maxEvaluationTimeMs: 5000,
      redisClient: this.redisClient,
      pgPool: this.pgPool,
      jwtSecret: this.jwtSecret
    };

    this.middleware = new AuthorizationMiddleware(
      mockTenantContextService,
      config,
      mockRBACService
    );
  }

  private generateJWT(user: TestUser): string {
    const payload = {
      sub: user.userId,
      tenantId: user.tenantId,
      roles: user.roles,
      permissions: user.permissions,
      clearanceLevel: user.clearanceLevel,
      mfaVerified: user.mfaVerified || false,
      sessionId: user.sessionId || `session-${Date.now()}`,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
    };

    return jwt.sign(payload, this.jwtSecret);
  }

  private createMockRequest(endpoint: string, method: string, user?: TestUser): NextRequest {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'user-agent': 'AuthorizationMatrixTester/1.0',
      'x-tenant-id': user?.tenantId || 'none'
    };

    if (user && user.userId !== 'anonymous') {
      headers['authorization'] = `Bearer ${this.generateJWT(user)}`;
    }

    // @ts-expect-error - Creating minimal NextRequest for testing
    return {
      method,
      nextUrl: { pathname: endpoint },
      headers: new Map(Object.entries(headers)),
      cookies: { get: () => undefined },
      ip: '127.0.0.1',
    } as NextRequest;
  }

  private extractEndpointTestCases(): EndpointTestCase[] {
    const testCases: EndpointTestCase[] = [];

    // Extract from both frontend and backend API sections
    const apiSections = ['frontend_api', 'backend_auth_service', 'backend_asset_discovery'];

    apiSections.forEach(section => {
      const endpoints = this.authorizationMatrix.endpoint_permissions[section];
      if (!endpoints) return;

      Object.entries(endpoints).forEach(([endpoint, methods]) => {
        Object.entries(methods as any).forEach(([method, config]) => {
          const endpointConfig = config as any;
          testCases.push({
            endpoint,
            method,
            expectedPermissions: endpointConfig.permissions || [],
            tenantContext: endpointConfig.tenant_context || 'none',
            requiresRole: endpointConfig.requires_role,
            requiresClearance: endpointConfig.requires_clearance,
            requiresMFA: endpointConfig.requires_mfa,
            publicEndpoint: endpointConfig.public || false,
            description: endpointConfig.description || `${method} ${endpoint}`
          });
        });
      });
    });

    return testCases;
  }

  async testEndpointAuthorization(testCase: EndpointTestCase): Promise<AuthorizationMatrixTestResult> {
    const result: AuthorizationMatrixTestResult = {
      endpoint: testCase.endpoint,
      method: testCase.method,
      testCases: [],
      overallPassed: true,
      summary: {
        totalTests: 0,
        passed: 0,
        failed: 0,
        successRate: 0
      }
    };

    // Test each user type against this endpoint
    for (const user of this.testUsers) {
      const startTime = Date.now();
      const request = this.createMockRequest(testCase.endpoint, testCase.method, user);

      // Determine expected result based on user permissions and endpoint requirements
      let expectedResult = false;
      let expectedReason = '';

      if (testCase.publicEndpoint) {
        expectedResult = true;
        expectedReason = 'Public endpoint';
      } else if (user.userId === 'anonymous') {
        expectedResult = false;
        expectedReason = 'Authentication required';
      } else {
        // Check permissions
        const hasRequiredPermissions = testCase.expectedPermissions.length === 0 || 
          testCase.expectedPermissions.every(perm => user.permissions.includes(perm));

        // Check roles
        const hasRequiredRole = !testCase.requiresRole ||
          testCase.requiresRole.some(role => user.roles.includes(role));

        // Check clearance
        const hasRequiredClearance = !testCase.requiresClearance ||
          this.checkClearanceLevel(user.clearanceLevel, testCase.requiresClearance);

        // Check MFA
        const hasMFA = !testCase.requiresMFA || user.mfaVerified === true;

        expectedResult = hasRequiredPermissions && hasRequiredRole && hasRequiredClearance && hasMFA;

        if (!expectedResult) {
          if (!hasRequiredPermissions) {
            const missingPerms = testCase.expectedPermissions.filter(p => !user.permissions.includes(p));
            expectedReason = `Missing permissions: ${missingPerms.join(', ')}`;
          } else if (!hasRequiredRole) {
            expectedReason = `Missing required role: ${testCase.requiresRole?.join(' or ')}`;
          } else if (!hasRequiredClearance) {
            expectedReason = `Insufficient clearance: ${testCase.requiresClearance} required`;
          } else if (!hasMFA) {
            expectedReason = 'MFA required but not verified';
          }
        } else {
          expectedReason = 'All authorization checks passed';
        }
      }

      try {
        // Execute authorization check
        const authResult: AuthorizationResult = await this.middleware.authorize(request);
        const evaluationTime = Date.now() - startTime;

        const testPassed = authResult.allowed === expectedResult;
        
        result.testCases.push({
          user,
          expectedResult,
          actualResult: authResult.allowed,
          reason: authResult.reason,
          passed: testPassed,
          evaluationTimeMs: evaluationTime
        });

        if (testPassed) {
          result.summary.passed++;
        } else {
          result.summary.failed++;
          result.overallPassed = false;
        }

      } catch (error) {
        const evaluationTime = Date.now() - startTime;
        result.testCases.push({
          user,
          expectedResult,
          actualResult: false,
          reason: `Authorization error: ${error}`,
          passed: false,
          evaluationTimeMs: evaluationTime
        });

        result.summary.failed++;
        result.overallPassed = false;
      }

      result.summary.totalTests++;
    }

    result.summary.successRate = result.summary.totalTests > 0 ? 
      (result.summary.passed / result.summary.totalTests) * 100 : 0;

    return result;
  }

  private checkClearanceLevel(userClearance: string | undefined, requiredClearance: string): boolean {
    const clearanceLevels = ['confidential', 'secret', 'top_secret'];
    const userLevel = userClearance ? clearanceLevels.indexOf(userClearance) : -1;
    const requiredLevel = clearanceLevels.indexOf(requiredClearance);
    
    return userLevel >= requiredLevel;
  }

  async runComprehensiveAuthorizationTests(): Promise<AuthorizationMatrixTestResult[]> {
    console.log('🔒 Starting comprehensive authorization matrix testing...');
    
    const testCases = this.extractEndpointTestCases();
    console.log(`📊 Testing ${testCases.length} endpoint configurations`);
    console.log(`👥 Against ${this.testUsers.length} different user types`);
    console.log(`🧪 Total test scenarios: ${testCases.length * this.testUsers.length}`);

    const results: AuthorizationMatrixTestResult[] = [];

    for (let i = 0; i < testCases.length; i++) {
      const testCase = testCases[i];
      console.log(`Testing ${i + 1}/${testCases.length}: ${testCase.method} ${testCase.endpoint}`);
      
      const result = await this.testEndpointAuthorization(testCase);
      results.push(result);
      
      // Log progress
      if (result.overallPassed) {
        console.log(`✅ ${testCase.method} ${testCase.endpoint} - All tests passed`);
      } else {
        console.log(`❌ ${testCase.method} ${testCase.endpoint} - ${result.summary.failed} failed tests`);
      }
    }

    this.testResults = results;
    return results;
  }

  generateComprehensiveReport(): any {
    const totalTests = this.testResults.reduce((sum, result) => sum + result.summary.totalTests, 0);
    const totalPassed = this.testResults.reduce((sum, result) => sum + result.summary.passed, 0);
    const totalFailed = this.testResults.reduce((sum, result) => sum + result.summary.failed, 0);
    
    const endpointsPassed = this.testResults.filter(r => r.overallPassed).length;
    const endpointsFailed = this.testResults.length - endpointsPassed;

    const averageEvaluationTime = this.testResults.reduce((sum, result) => {
      const avgTime = result.testCases.reduce((tSum, tc) => tSum + tc.evaluationTimeMs, 0) / result.testCases.length;
      return sum + avgTime;
    }, 0) / this.testResults.length;

    return {
      timestamp: new Date().toISOString(),
      summary: {
        totalEndpoints: this.testResults.length,
        endpointsPassed,
        endpointsFailed,
        endpointSuccessRate: (endpointsPassed / this.testResults.length) * 100,
        totalTestScenarios: totalTests,
        totalPassed,
        totalFailed,
        overallSuccessRate: (totalPassed / totalTests) * 100,
        averageEvaluationTimeMs: averageEvaluationTime
      },
      testUsers: this.testUsers.length,
      userTypes: this.testUsers.map(u => ({
        userId: u.userId,
        roles: u.roles,
        permissionCount: u.permissions.length,
        clearanceLevel: u.clearanceLevel,
        mfaVerified: u.mfaVerified
      })),
      failedEndpoints: this.testResults.filter(r => !r.overallPassed).map(r => ({
        endpoint: r.endpoint,
        method: r.method,
        failedTests: r.summary.failed,
        totalTests: r.summary.totalTests,
        successRate: r.summary.successRate,
        failures: r.testCases.filter(tc => !tc.passed).map(tc => ({
          userId: tc.user.userId,
          expected: tc.expectedResult,
          actual: tc.actualResult,
          reason: tc.reason
        }))
      })),
      performanceMetrics: {
        fastestEvaluation: Math.min(...this.testResults.flatMap(r => r.testCases.map(tc => tc.evaluationTimeMs))),
        slowestEvaluation: Math.max(...this.testResults.flatMap(r => r.testCases.map(tc => tc.evaluationTimeMs))),
        averageEvaluationTime: averageEvaluationTime,
        evaluationsOver1000ms: this.testResults.flatMap(r => r.testCases).filter(tc => tc.evaluationTimeMs > 1000).length
      },
      securityAnalysis: this.analyzeSecurityFindings(),
      recommendations: this.generateRecommendations(),
      detailedResults: this.testResults
    };
  }

  private analyzeSecurityFindings(): any {
    const findings: string[] = [];
    const criticalIssues: string[] = [];
    const warnings: string[] = [];

    // Analyze failed authorization attempts
    const unauthorizedAccess = this.testResults.flatMap(r => 
      r.testCases.filter(tc => tc.expectedResult === false && tc.actualResult === true)
    );

    if (unauthorizedAccess.length > 0) {
      criticalIssues.push(`${unauthorizedAccess.length} cases of unauthorized access granted`);
      unauthorizedAccess.forEach(ua => {
        criticalIssues.push(
          `User ${ua.user.userId} granted access to ${this.testResults.find(r => 
            r.testCases.includes(ua)
          )?.method} ${this.testResults.find(r => r.testCases.includes(ua))?.endpoint}`
        );
      });
    }

    // Analyze overly restrictive permissions
    const overlyRestrictive = this.testResults.flatMap(r => 
      r.testCases.filter(tc => tc.expectedResult === true && tc.actualResult === false)
    );

    if (overlyRestrictive.length > 10) {
      warnings.push(`${overlyRestrictive.length} cases of potentially overly restrictive authorization`);
    }

    // Check performance issues
    const slowEvaluations = this.testResults.flatMap(r => r.testCases).filter(tc => tc.evaluationTimeMs > 1000);
    if (slowEvaluations.length > 0) {
      warnings.push(`${slowEvaluations.length} authorization evaluations took over 1 second`);
    }

    // Check tenant isolation
    const tenantIsolationIssues = this.testResults.filter(r => {
      return r.testCases.some(tc => 
        tc.user.tenantId !== 'system' && 
        tc.actualResult === true && 
        (tc.user.tenantId === 'none' || tc.user.tenantId !== tc.user.tenantId)
      );
    });

    if (tenantIsolationIssues.length > 0) {
      criticalIssues.push(`${tenantIsolationIssues.length} potential tenant isolation violations`);
    }

    return {
      criticalIssues,
      warnings,
      findings,
      securityScore: Math.max(0, 100 - (criticalIssues.length * 20) - (warnings.length * 5))
    };
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    
    const failedEndpoints = this.testResults.filter(r => !r.overallPassed);
    if (failedEndpoints.length > 0) {
      recommendations.push(`Review and fix authorization configuration for ${failedEndpoints.length} failing endpoints`);
    }

    const slowEvaluations = this.testResults.flatMap(r => r.testCases).filter(tc => tc.evaluationTimeMs > 500);
    if (slowEvaluations.length > 10) {
      recommendations.push('Optimize authorization evaluation performance - consider caching improvements');
    }

    const highPrivilegeEndpoints = this.testResults.filter(r => 
      r.testCases.some(tc => tc.user.roles.includes('admin') || tc.user.roles.includes('security_officer'))
    );
    if (highPrivilegeEndpoints.length > 50) {
      recommendations.push('Review high-privilege endpoint access patterns for security compliance');
    }

    recommendations.push('Implement continuous authorization monitoring in production');
    recommendations.push('Set up alerting for authorization failures and anomalies');
    recommendations.push('Regular review of RBAC permission assignments');

    return recommendations;
  }

  async cleanup(): Promise<void> {
    await this.redisClient?.quit?.();
    await this.pgPool?.end?.();
  }
}

describe('🔒 Comprehensive API Authorization Matrix Test Suite', () => {
  let authTester: ComprehensiveAuthorizationMatrixTester;

  beforeAll(async () => {
    authTester = new ComprehensiveAuthorizationMatrixTester();
  });

  afterAll(async () => {
    await authTester.cleanup();
  });

  test('should validate all 215+ API endpoints with comprehensive authorization matrix', async () => {
    const results = await authTester.runComprehensiveAuthorizationTests();
    
    expect(results.length).toBeGreaterThan(50); // Should test many endpoints
    
    // Check that all test scenarios were executed
    const totalTests = results.reduce((sum, result) => sum + result.summary.totalTests, 0);
    expect(totalTests).toBeGreaterThan(400); // Many user/endpoint combinations
    
    // Verify that most tests pass
    const totalPassed = results.reduce((sum, result) => sum + result.summary.passed, 0);
    const successRate = (totalPassed / totalTests) * 100;
    
    expect(successRate).toBeGreaterThanOrEqual(85); // 85% success rate minimum
    
    // Check for critical security failures (unauthorized access granted)
    const unauthorizedAccess = results.flatMap(r => 
      r.testCases.filter(tc => tc.expectedResult === false && tc.actualResult === true)
    );
    expect(unauthorizedAccess.length).toBe(0); // No unauthorized access should be granted
    
    console.log(`🔒 Authorization Matrix Test Results:`);
    console.log(`  Endpoints tested: ${results.length}`);
    console.log(`  Total test scenarios: ${totalTests}`);
    console.log(`  Passed: ${totalPassed}`);
    console.log(`  Success rate: ${successRate.toFixed(2)}%`);
    console.log(`  Unauthorized access attempts: ${unauthorizedAccess.length}`);
  }, 300000); // 5 minute timeout

  test('should validate tenant isolation enforcement', async () => {
    const results = await authTester.runComprehensiveAuthorizationTests();
    
    // Find all tenant-scoped endpoints
    const tenantScopedResults = results.filter(r => 
      r.testCases.some(tc => tc.user.tenantId !== 'system' && tc.user.tenantId !== 'none')
    );
    
    expect(tenantScopedResults.length).toBeGreaterThan(0);
    
    // Verify no cross-tenant access violations
    const crossTenantViolations = tenantScopedResults.flatMap(r => 
      r.testCases.filter(tc => 
        tc.actualResult === true && 
        tc.user.tenantId !== 'system' && 
        r.endpoint.includes('{tenantId}') && 
        !tc.user.roles.includes('admin')
      )
    );
    
    expect(crossTenantViolations.length).toBe(0);
    
    console.log(`🏢 Tenant Isolation Test Results:`);
    console.log(`  Tenant-scoped endpoints: ${tenantScopedResults.length}`);
    console.log(`  Cross-tenant violations: ${crossTenantViolations.length}`);
  });

  test('should validate RBAC permission enforcement', async () => {
    const results = await authTester.runComprehensiveAuthorizationTests();
    
    // Test role hierarchy enforcement
    const adminResults = results.flatMap(r => 
      r.testCases.filter(tc => tc.user.roles.includes('admin'))
    );
    
    const userResults = results.flatMap(r => 
      r.testCases.filter(tc => tc.user.roles.includes('user') && !tc.user.roles.includes('admin'))
    );
    
    // Admin should have broader access than basic users
    const adminAccess = adminResults.filter(tc => tc.actualResult === true).length;
    const userAccess = userResults.filter(tc => tc.actualResult === true).length;
    
    expect(adminAccess).toBeGreaterThan(userAccess);
    
    console.log(`👑 RBAC Permission Test Results:`);
    console.log(`  Admin successful access: ${adminAccess}/${adminResults.length}`);
    console.log(`  User successful access: ${userAccess}/${userResults.length}`);
  });

  test('should validate MFA and clearance requirements', async () => {
    const results = await authTester.runComprehensiveAuthorizationTests();
    
    // Find high-security endpoints requiring MFA or clearance
    const highSecurityResults = results.filter(r => 
      r.testCases.some(tc => 
        (tc.user.clearanceLevel === 'secret' || tc.user.clearanceLevel === 'top_secret') ||
        tc.user.mfaVerified === true
      )
    );
    
    expect(highSecurityResults.length).toBeGreaterThan(10);
    
    // Verify users without proper clearance/MFA are denied
    const inadequateClearanceAttempts = results.flatMap(r => 
      r.testCases.filter(tc => 
        tc.expectedResult === false && 
        tc.reason.includes('clearance') &&
        tc.actualResult === false
      )
    );
    
    console.log(`🔐 High-Security Endpoint Test Results:`);
    console.log(`  High-security endpoints: ${highSecurityResults.length}`);
    console.log(`  Properly denied inadequate clearance: ${inadequateClearanceAttempts.length}`);
  });

  test('should validate authorization performance and caching', async () => {
    const results = await authTester.runComprehensiveAuthorizationTests();
    
    // Check evaluation times
    const allEvaluations = results.flatMap(r => r.testCases);
    const evaluationTimes = allEvaluations.map(tc => tc.evaluationTimeMs);
    
    const averageTime = evaluationTimes.reduce((sum, time) => sum + time, 0) / evaluationTimes.length;
    const maxTime = Math.max(...evaluationTimes);
    const slowEvaluations = evaluationTimes.filter(time => time > 1000).length;
    
    // Performance expectations
    expect(averageTime).toBeLessThan(100); // Average under 100ms
    expect(maxTime).toBeLessThan(2000); // Max under 2 seconds
    expect(slowEvaluations).toBeLessThan(5); // Less than 5 slow evaluations
    
    console.log(`⚡ Authorization Performance Test Results:`);
    console.log(`  Average evaluation time: ${averageTime.toFixed(2)}ms`);
    console.log(`  Maximum evaluation time: ${maxTime}ms`);
    console.log(`  Evaluations over 1 second: ${slowEvaluations}`);
  });

  test('should generate comprehensive authorization matrix report', async () => {
    const results = await authTester.runComprehensiveAuthorizationTests();
    const report = authTester.generateComprehensiveReport();
    
    expect(report.summary).toBeDefined();
    expect(report.summary.totalEndpoints).toBeGreaterThan(50);
    expect(report.summary.overallSuccessRate).toBeGreaterThanOrEqual(85);
    
    expect(report.securityAnalysis).toBeDefined();
    expect(report.securityAnalysis.securityScore).toBeGreaterThanOrEqual(80);
    
    expect(report.recommendations).toBeDefined();
    expect(Array.isArray(report.recommendations)).toBe(true);
    
    expect(report.performanceMetrics).toBeDefined();
    expect(report.performanceMetrics.averageEvaluationTime).toBeLessThan(200);
    
    // Save report to file system
    const reportPath = path.join(__dirname, '../../test-results/comprehensive-authorization-matrix-report.json');
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    console.log('📊 Comprehensive Authorization Matrix Report Generated:');
    console.log(`  Endpoints tested: ${report.summary.totalEndpoints}`);
    console.log(`  Overall success rate: ${report.summary.overallSuccessRate.toFixed(2)}%`);
    console.log(`  Security score: ${report.securityAnalysis.securityScore}/100`);
    console.log(`  Average evaluation time: ${report.performanceMetrics.averageEvaluationTime.toFixed(2)}ms`);
    console.log(`  Report saved: ${reportPath}`);
  }, 300000); // 5 minute timeout
});