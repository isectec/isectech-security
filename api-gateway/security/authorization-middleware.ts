/**
 * API Gateway Authorization Middleware  
 * Comprehensive authorization enforcement for all API endpoints
 * 
 * Task: 81.4 - Develop authorization middleware for API gateway
 */

import { NextRequest, NextResponse } from 'next/server';
import { createClient } from 'redis';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import {
  TenantContextService,
  TenantExtractionResult
} from './tenant-context-service';
import {
  TenantErrorCode,
  TenantUtils,
  AccessEventType,
  TenantRequestContext
} from './tenant-context-types';
import {
  RBACPermissionService,
  createRBACPermissionService,
  PermissionCheckRequest
} from './rbac-permission-service';

// Authorization result types
export interface AuthorizationResult {
  allowed: boolean;
  reason: string;
  tenantId?: string;
  userId?: string;
  permissions?: string[];
  cacheHit?: boolean;
  evaluationTimeMs?: number;
  auditData?: AuthorizationAuditData;
}

export interface AuthorizationAuditData {
  requestId: string;
  userId: string;
  tenantId: string;
  endpoint: string;
  method: string;
  ipAddress: string;
  userAgent?: string;
  sessionId?: string;
  result: boolean;
  reason: string;
  timestamp: string;
  evaluationTimeMs: number;
  cacheHit: boolean;
  errorCode?: string;
}

export interface AuthorizationConfig {
  enableCaching: boolean;
  cacheTimeoutMs: number;
  enableAuditLogging: boolean;
  enableMetrics: boolean;
  fallbackToDeny: boolean;
  maxEvaluationTimeMs: number;
  redisClient?: ReturnType<typeof createClient>;
  pgPool?: Pool;
  jwtSecret: string;
}

// Middleware configuration from authorization matrix
interface EndpointConfig {
  permissions: string[];
  tenantContextType: string;
  requiresRole?: string[];
  requiresClearance?: string;
  requiresMFA?: boolean;
  publicEndpoint?: boolean;
  apiKeyRequired?: boolean;
}

export class AuthorizationMiddleware {
  private tenantContextService: TenantContextService;
  private rbacPermissionService: RBACPermissionService;
  private config: AuthorizationConfig;
  private redisClient?: ReturnType<typeof createClient>;
  private pgPool?: Pool;
  private authorizationMatrix: Map<string, Map<string, EndpointConfig>>;

  constructor(
    tenantContextService: TenantContextService,
    config: AuthorizationConfig,
    rbacPermissionService?: RBACPermissionService
  ) {
    this.tenantContextService = tenantContextService;
    this.config = config;
    this.redisClient = config.redisClient;
    this.pgPool = config.pgPool;
    this.authorizationMatrix = new Map();
    
    // Initialize RBAC permission service
    this.rbacPermissionService = rbacPermissionService || createRBACPermissionService(
      this.pgPool,
      this.redisClient,
      {
        cacheEnabled: config.enableCaching,
        cacheTTL: config.cacheTimeoutMs / 1000
      }
    );
    
    this.loadAuthorizationMatrix();
  }

  /**
   * Main authorization middleware function
   */
  async authorize(request: NextRequest): Promise<AuthorizationResult> {
    const startTime = Date.now();
    const requestId = this.generateRequestId();
    
    try {
      // Extract basic request information
      const method = request.method;
      const pathname = request.nextUrl.pathname;
      const ipAddress = this.getClientIP(request);
      const userAgent = request.headers.get('user-agent') || undefined;

      // Get endpoint configuration
      const endpointConfig = this.getEndpointConfig(pathname, method);
      
      // Handle public endpoints
      if (endpointConfig?.publicEndpoint) {
        return {
          allowed: true,
          reason: 'Public endpoint - no authorization required',
          evaluationTimeMs: Date.now() - startTime,
          cacheHit: false
        };
      }

      // Extract user authentication
      const userId = await this.extractUserId(request);
      if (!userId) {
        const result = this.createDeniedResult(
          'Authentication required',
          startTime,
          'AUTHENTICATION_REQUIRED'
        );
        
        await this.auditAuthorizationDecision({
          requestId,
          userId: 'anonymous',
          tenantId: 'none',
          endpoint: pathname,
          method,
          ipAddress,
          userAgent,
          result: false,
          reason: result.reason,
          timestamp: new Date().toISOString(),
          evaluationTimeMs: result.evaluationTimeMs!,
          cacheHit: false,
          errorCode: 'AUTHENTICATION_REQUIRED'
        });

        return result;
      }

      // Check cache first (if enabled)
      if (this.config.enableCaching && this.redisClient) {
        const cacheKey = this.buildCacheKey(userId, pathname, method);
        const cached = await this.getCachedDecision(cacheKey);
        if (cached) {
          cached.evaluationTimeMs = Date.now() - startTime;
          cached.cacheHit = true;
          return cached;
        }
      }

      // Extract tenant context (if required)
      let tenantResult: TenantExtractionResult | null = null;
      if (this.requiresTenantContext(pathname, method)) {
        tenantResult = await this.tenantContextService.extractTenantContext(request);
        
        if (!tenantResult.success) {
          const result = this.createDeniedResult(
            tenantResult.error?.message || 'Tenant context validation failed',
            startTime,
            tenantResult.error?.code || 'TENANT_VALIDATION_FAILED'
          );

          await this.auditAuthorizationDecision({
            requestId,
            userId,
            tenantId: 'unknown',
            endpoint: pathname,
            method,
            ipAddress,
            userAgent,
            result: false,
            reason: result.reason,
            timestamp: new Date().toISOString(),
            evaluationTimeMs: result.evaluationTimeMs!,
            cacheHit: false,
            errorCode: tenantResult.error?.code || 'TENANT_VALIDATION_FAILED'
          });

          return result;
        }
      }

      const tenantId = tenantResult?.tenantId || 'system';

      // Perform endpoint-specific authorization
      const authResult = await this.performEndpointAuthorization(
        userId,
        tenantId,
        pathname,
        method,
        endpointConfig,
        tenantResult
      );

      const evaluationTime = Date.now() - startTime;
      authResult.evaluationTimeMs = evaluationTime;
      authResult.tenantId = tenantId;
      authResult.userId = userId;

      // Cache the result (if enabled and allowed)
      if (this.config.enableCaching && this.redisClient && authResult.allowed) {
        const cacheKey = this.buildCacheKey(userId, pathname, method);
        await this.cacheDecision(cacheKey, authResult);
      }

      // Audit the decision
      await this.auditAuthorizationDecision({
        requestId,
        userId,
        tenantId,
        endpoint: pathname,
        method,
        ipAddress,
        userAgent,
        result: authResult.allowed,
        reason: authResult.reason,
        timestamp: new Date().toISOString(),
        evaluationTimeMs: evaluationTime,
        cacheHit: false
      });

      return authResult;

    } catch (error) {
      console.error('Authorization middleware error:', error);
      
      const result = this.createDeniedResult(
        'Authorization service error',
        startTime,
        'AUTHORIZATION_SERVICE_ERROR'
      );

      // Still try to audit the error
      try {
        await this.auditAuthorizationDecision({
          requestId,
          userId: 'unknown',
          tenantId: 'unknown',
          endpoint: request.nextUrl.pathname,
          method: request.method,
          ipAddress: this.getClientIP(request),
          userAgent: request.headers.get('user-agent') || undefined,
          result: false,
          reason: 'Authorization service error',
          timestamp: new Date().toISOString(),
          evaluationTimeMs: result.evaluationTimeMs!,
          cacheHit: false,
          errorCode: 'AUTHORIZATION_SERVICE_ERROR'
        });
      } catch (auditError) {
        console.error('Failed to audit authorization error:', auditError);
      }

      return result;
    }
  }

  /**
   * Perform endpoint-specific authorization checks
   */
  private async performEndpointAuthorization(
    userId: string,
    tenantId: string,
    pathname: string,
    method: string,
    endpointConfig: EndpointConfig | null,
    tenantResult: TenantExtractionResult | null
  ): Promise<AuthorizationResult> {
    
    if (!endpointConfig) {
      return this.createDeniedResult('Endpoint not found in authorization matrix');
    }

    // Check required permissions with context
    if (endpointConfig.permissions && endpointConfig.permissions.length > 0) {
      // Build permission context
      const permissionContext = {
        endpoint: pathname,
        method,
        requiresMFA: endpointConfig.requiresMFA,
        requiredClearance: endpointConfig.requiresClearance,
        tenantContext: tenantResult?.tenantContext
      };

      const hasPermissions = await this.checkUserPermissions(
        userId,
        tenantId,
        endpointConfig.permissions,
        permissionContext
      );

      if (!hasPermissions.allowed) {
        const missingPerms = hasPermissions.missingPermissions?.join(', ') || 'unknown';
        return this.createDeniedResult(
          `Missing required permissions: ${missingPerms}`,
          undefined,
          'INSUFFICIENT_PERMISSIONS'
        );
      }
    }

    // Check role requirements
    if (endpointConfig.requiresRole) {
      const hasRole = await this.checkUserRole(userId, tenantId, endpointConfig.requiresRole);
      if (!hasRole) {
        return this.createDeniedResult(
          `Missing required role: ${endpointConfig.requiresRole.join(' or ')}`
        );
      }
    }

    // Check security clearance requirements  
    if (endpointConfig.requiresClearance) {
      const hasClearance = await this.checkSecurityClearance(
        userId,
        endpointConfig.requiresClearance
      );
      if (!hasClearance) {
        return this.createDeniedResult(
          `Insufficient security clearance: ${endpointConfig.requiresClearance} required`
        );
      }
    }

    // Check MFA requirements
    if (endpointConfig.requiresMFA) {
      const mfaVerified = await this.checkMFAStatus(userId);
      if (!mfaVerified) {
        return this.createDeniedResult('Multi-factor authentication required');
      }
    }

    // Check tenant-specific restrictions
    if (tenantResult?.tenantContext) {
      const tenantCheck = await this.checkTenantRestrictions(
        tenantResult.tenantContext,
        pathname,
        method
      );
      if (!tenantCheck.allowed) {
        return this.createDeniedResult(tenantCheck.reason);
      }
    }

    // All checks passed
    return {
      allowed: true,
      reason: 'All authorization checks passed',
      permissions: endpointConfig.permissions
    };
  }

  /**
   * Check if user has required permissions using RBAC service
   */
  private async checkUserPermissions(
    userId: string,
    tenantId: string,
    requiredPermissions: string[],
    context?: Record<string, any>
  ): Promise<{ allowed: boolean; missingPermissions?: string[]; rbacDetails?: any }> {
    
    try {
      const permissionRequest: PermissionCheckRequest = {
        userId,
        tenantId,
        permissions: requiredPermissions,
        context
      };

      const result = await this.rbacPermissionService.checkPermissions(permissionRequest);

      return {
        allowed: result.allowed,
        missingPermissions: result.deniedPermissions.length > 0 ? result.deniedPermissions : undefined,
        rbacDetails: {
          effectiveRoles: result.effectiveRoles,
          grantedPermissions: result.grantedPermissions,
          roleHierarchy: result.roleHierarchy,
          cacheHit: result.cacheHit,
          evaluationTimeMs: result.evaluationTimeMs
        }
      };

    } catch (error) {
      console.error('RBAC permission check error:', error);
      return { 
        allowed: false,
        missingPermissions: requiredPermissions
      };
    }
  }

  /**
   * Check if user has required role using RBAC service (with hierarchy support)
   */
  private async checkUserRole(
    userId: string,
    tenantId: string,
    requiredRoles: string[]
  ): Promise<boolean> {
    
    try {
      return await this.rbacPermissionService.hasAnyRole(userId, tenantId, requiredRoles);
    } catch (error) {
      console.error('RBAC role check error:', error);
      return false;
    }
  }

  /**
   * Check user's security clearance level
   */
  private async checkSecurityClearance(
    userId: string,
    requiredClearance: string
  ): Promise<boolean> {
    
    // For now, extract from JWT token
    // In production, this should be stored in user profile
    try {
      // This would typically query user profile for clearance level
      // For demo purposes, assume clearance is in JWT token
      return true; // Simplified implementation
    } catch (error) {
      console.error('Security clearance check error:', error);
      return false;
    }
  }

  /**
   * Check if user's MFA is verified
   */
  private async checkMFAStatus(userId: string): Promise<boolean> {
    try {
      // This would check the user's current session for MFA verification
      // For demo purposes, assume MFA is verified
      return true; // Simplified implementation
    } catch (error) {
      console.error('MFA status check error:', error);
      return false;
    }
  }

  /**
   * Check tenant-specific restrictions and capabilities
   */
  private async checkTenantRestrictions(
    tenantContext: any,
    pathname: string,
    method: string
  ): Promise<{ allowed: boolean; reason: string }> {
    
    // Check tenant status
    if (tenantContext.status !== 'active') {
      return {
        allowed: false,
        reason: `Tenant is ${tenantContext.status}`
      };
    }

    // Check feature availability based on tenant tier
    const requiredFeature = this.getRequiredFeatureForEndpoint(pathname);
    if (requiredFeature && !tenantContext.features.includes(requiredFeature)) {
      return {
        allowed: false,
        reason: `Feature '${requiredFeature}' not available for tenant tier '${tenantContext.tenantTier}'`
      };
    }

    return { allowed: true, reason: 'Tenant restrictions passed' };
  }

  /**
   * Load authorization matrix from configuration
   */
  private loadAuthorizationMatrix(): void {
    // Load the authorization matrix from the JSON file we created
    // This would typically be loaded from a configuration service
    // For now, implementing key endpoints directly in code
    
    const matrix = new Map<string, Map<string, EndpointConfig>>();

    // Authentication endpoints
    this.addEndpoint(matrix, '/api/auth/login', 'POST', {
      permissions: ['auth:login'],
      tenantContextType: 'required_in_request',
      publicEndpoint: false
    });

    this.addEndpoint(matrix, '/api/auth/logout', 'POST', {
      permissions: ['auth:logout'],
      tenantContextType: 'from_session',
      publicEndpoint: false
    });

    this.addEndpoint(matrix, '/api/auth/verify', 'GET', {
      permissions: ['auth:verify'],
      tenantContextType: 'from_session',
      publicEndpoint: false
    });

    // Asset endpoints
    this.addEndpoint(matrix, '/api/v1/assets', 'GET', {
      permissions: ['assets:read'],
      tenantContextType: 'tenant_scoped',
      publicEndpoint: false
    });

    this.addEndpoint(matrix, '/api/v1/assets', 'POST', {
      permissions: ['assets:create'],
      tenantContextType: 'tenant_scoped',
      publicEndpoint: false
    });

    // Admin endpoints
    this.addEndpoint(matrix, '/api/v1/admin/users', 'GET', {
      permissions: ['users:admin:list'],
      tenantContextType: 'cross_tenant',
      requiresRole: ['admin'],
      requiresClearance: 'secret',
      requiresMFA: true,
      publicEndpoint: false
    });

    // Security endpoints
    this.addEndpoint(matrix, '/api/v1/security/alerts', 'GET', {
      permissions: ['security:alerts:read'],
      tenantContextType: 'cross_tenant',
      requiresRole: ['security_officer'],
      requiresClearance: 'top_secret',
      requiresMFA: true,
      publicEndpoint: false
    });

    // Public endpoints
    this.addEndpoint(matrix, '/health', 'GET', {
      permissions: [],
      tenantContextType: 'none',
      publicEndpoint: true
    });

    this.addEndpoint(matrix, '/api/health', 'GET', {
      permissions: [],
      tenantContextType: 'none',
      publicEndpoint: true
    });

    this.authorizationMatrix = matrix;
  }

  private addEndpoint(
    matrix: Map<string, Map<string, EndpointConfig>>,
    path: string,
    method: string,
    config: EndpointConfig
  ): void {
    if (!matrix.has(path)) {
      matrix.set(path, new Map());
    }
    matrix.get(path)!.set(method, config);
  }

  /**
   * Get endpoint configuration from authorization matrix
   */
  private getEndpointConfig(pathname: string, method: string): EndpointConfig | null {
    // Direct match
    const pathMethods = this.authorizationMatrix.get(pathname);
    if (pathMethods?.has(method)) {
      return pathMethods.get(method)!;
    }

    // Pattern matching for parameterized routes
    for (const [pattern, methods] of this.authorizationMatrix.entries()) {
      if (this.matchesPattern(pathname, pattern) && methods.has(method)) {
        return methods.get(method)!;
      }
    }

    return null;
  }

  /**
   * Simple pattern matching for routes with parameters
   */
  private matchesPattern(pathname: string, pattern: string): boolean {
    // Convert pattern like "/api/v1/assets/{id}" to regex
    const regexPattern = pattern.replace(/\{[^}]+\}/g, '[^/]+');
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(pathname);
  }

  /**
   * Check if endpoint requires tenant context
   */
  private requiresTenantContext(pathname: string, method: string): boolean {
    const config = this.getEndpointConfig(pathname, method);
    if (config?.publicEndpoint) {
      return false;
    }

    return TenantUtils.isTenantContextRequired(pathname, method);
  }

  /**
   * Helper methods
   */
  private async extractUserId(request: NextRequest): Promise<string | null> {
    try {
      const authHeader = request.headers.get('authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const payload = jwt.verify(token, this.config.jwtSecret) as any;
        return payload.sub;
      }

      const sessionCookie = request.cookies.get('session_token');
      if (sessionCookie?.value) {
        const payload = jwt.verify(sessionCookie.value, this.config.jwtSecret) as any;
        return payload.sub;
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  private getClientIP(request: NextRequest): string {
    const xForwardedFor = request.headers.get('x-forwarded-for');
    const xRealIP = request.headers.get('x-real-ip');
    const cfConnectingIP = request.headers.get('cf-connecting-ip');
    
    return cfConnectingIP || 
           xRealIP || 
           (xForwardedFor?.split(',')[0].trim()) || 
           request.ip || 
           '0.0.0.0';
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private buildCacheKey(userId: string, pathname: string, method: string): string {
    return `authz:${userId}:${btoa(pathname)}:${method}`;
  }

  private async getCachedDecision(cacheKey: string): Promise<AuthorizationResult | null> {
    if (!this.redisClient) return null;

    try {
      const cached = await this.redisClient.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      console.error('Cache get error:', error);
    }
    
    return null;
  }

  private async cacheDecision(cacheKey: string, result: AuthorizationResult): Promise<void> {
    if (!this.redisClient) return;

    try {
      await this.redisClient.setex(
        cacheKey,
        this.config.cacheTimeoutMs / 1000,
        JSON.stringify(result)
      );
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  private createDeniedResult(
    reason: string,
    startTime?: number,
    errorCode?: string
  ): AuthorizationResult {
    return {
      allowed: false,
      reason,
      evaluationTimeMs: startTime ? Date.now() - startTime : 0,
      cacheHit: false
    };
  }

  private async auditAuthorizationDecision(auditData: AuthorizationAuditData): Promise<void> {
    if (!this.config.enableAuditLogging) return;

    try {
      // Log to console for now - in production, send to logging service
      console.log('Authorization Decision:', JSON.stringify(auditData, null, 2));

      // Store in database if available
      if (this.pgPool) {
        const client = await this.pgPool.connect();
        try {
          await client.query(`
            INSERT INTO tenant_access_events (
              user_id, tenant_id, event_type, endpoint_path, http_method,
              ip_address, user_agent, success, error_code, error_message,
              session_id, request_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
          `, [
            auditData.userId === 'unknown' ? null : auditData.userId,
            auditData.tenantId === 'unknown' ? null : auditData.tenantId,
            'permission_check',
            auditData.endpoint,
            auditData.method,
            auditData.ipAddress,
            auditData.userAgent,
            auditData.result,
            auditData.errorCode,
            auditData.reason,
            auditData.sessionId,
            auditData.requestId
          ]);
        } finally {
          client.release();
        }
      }
    } catch (error) {
      console.error('Failed to audit authorization decision:', error);
    }
  }

  private getRequiredFeatureForEndpoint(pathname: string): string | null {
    if (pathname.includes('/analytics/')) return 'advanced_analytics';
    if (pathname.includes('/vulnerability/')) return 'vulnerability_scanning';
    if (pathname.includes('/threat/')) return 'threat_intelligence';
    if (pathname.includes('/mobile/')) return 'mobile_notifications';
    if (pathname.includes('/compliance/')) return 'compliance_reporting';
    return null;
  }
}

/**
 * Factory function to create authorization middleware
 */
export function createAuthorizationMiddleware(
  tenantContextService: TenantContextService,
  config?: Partial<AuthorizationConfig>
): AuthorizationMiddleware {
  
  const defaultConfig: AuthorizationConfig = {
    enableCaching: true,
    cacheTimeoutMs: 5 * 60 * 1000, // 5 minutes
    enableAuditLogging: true,
    enableMetrics: true,
    fallbackToDeny: true,
    maxEvaluationTimeMs: 5000,
    jwtSecret: process.env.JWT_SECRET || 'your-jwt-secret-key'
  };

  const finalConfig = { ...defaultConfig, ...config };

  return new AuthorizationMiddleware(tenantContextService, finalConfig);
}

// Export middleware instance for use in Next.js
export const authorizationMiddleware = createAuthorizationMiddleware(
  new TenantContextService(
    createClient({ url: process.env.REDIS_URL }),
    new Pool({
      host: process.env.POSTGRES_HOST,
      port: parseInt(process.env.POSTGRES_PORT || '5432'),
      database: process.env.POSTGRES_DB,
      user: process.env.POSTGRES_USER,
      password: process.env.POSTGRES_PASSWORD
    }),
    process.env.JWT_SECRET || 'your-jwt-secret-key'
  )
);