/**
 * Tenant Context Service
 * Handles tenant context extraction, validation, and isolation for the API Gateway
 * 
 * Task: 81.3 - Implement tenant context extraction and validation logic
 */

import { NextRequest } from 'next/server';
import jwt from 'jsonwebtoken';
import { createClient } from 'redis';
import { Pool } from 'pg';

// Types and interfaces
export interface TenantContext {
  tenantId: string;
  tenantName: string;
  tenantType: 'enterprise' | 'standard' | 'trial';
  tenantTier: 'basic' | 'premium' | 'enterprise';
  status: 'active' | 'suspended' | 'trial_expired';
  maxUsers?: number;
  features: string[];
  dataResidency?: string;
  complianceFrameworks: string[];
}

export interface UserTenantAssociation {
  userId: string;
  tenantId: string;
  role: string;
  permissions: string[];
  status: 'active' | 'inactive' | 'suspended';
  joinedAt: Date;
  lastAccessAt?: Date;
}

export interface TenantExtractionResult {
  success: boolean;
  tenantId?: string;
  tenantContext?: TenantContext;
  userAssociation?: UserTenantAssociation;
  error?: {
    code: string;
    message: string;
  };
}

export interface JWTPayload {
  sub: string; // user ID
  tenant_id?: string;
  tenant_ids?: string[]; // for multi-tenant users
  roles?: string[];
  permissions?: string[];
  security_clearance?: string;
  iat: number;
  exp: number;
  iss: string;
}

// Configuration
const TENANT_CACHE_TTL = 5 * 60; // 5 minutes
const USER_TENANT_CACHE_TTL = 10 * 60; // 10 minutes

export class TenantContextService {
  private redisClient: ReturnType<typeof createClient>;
  private pgPool: Pool;
  private jwtSecret: string;

  constructor(
    redisClient: ReturnType<typeof createClient>,
    pgPool: Pool,
    jwtSecret: string
  ) {
    this.redisClient = redisClient;
    this.pgPool = pgPool;
    this.jwtSecret = jwtSecret;
  }

  /**
   * Extract tenant context from request
   * Supports multiple extraction methods in priority order
   */
  async extractTenantContext(request: NextRequest): Promise<TenantExtractionResult> {
    try {
      // 1. Try to extract from X-Tenant-ID header (highest priority)
      const headerTenantId = request.headers.get('x-tenant-id');
      if (headerTenantId) {
        return await this.validateTenantFromHeader(request, headerTenantId);
      }

      // 2. Try to extract from JWT token tenant claim
      const authHeader = request.headers.get('authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        return await this.validateTenantFromJWT(request, token);
      }

      // 3. Try to extract from session cookie
      const sessionCookie = request.cookies.get('session_token');
      if (sessionCookie?.value) {
        return await this.validateTenantFromSession(request, sessionCookie.value);
      }

      // 4. Try to extract from URL path parameter (for tenant-specific routes)
      const pathTenantId = this.extractTenantFromPath(request.nextUrl.pathname);
      if (pathTenantId) {
        return await this.validateTenantFromPath(request, pathTenantId);
      }

      // 5. Try to extract from query parameter (lowest priority)
      const queryTenantId = request.nextUrl.searchParams.get('tenant_id');
      if (queryTenantId) {
        return await this.validateTenantFromQuery(request, queryTenantId);
      }

      // No tenant context found
      return {
        success: false,
        error: {
          code: 'TENANT_CONTEXT_MISSING',
          message: 'No tenant context found in request'
        }
      };

    } catch (error) {
      console.error('Tenant context extraction error:', error);
      return {
        success: false,
        error: {
          code: 'TENANT_EXTRACTION_ERROR',
          message: 'Failed to extract tenant context'
        }
      };
    }
  }

  /**
   * Validate tenant from X-Tenant-ID header
   */
  private async validateTenantFromHeader(
    request: NextRequest, 
    tenantId: string
  ): Promise<TenantExtractionResult> {
    // Validate UUID format
    if (!this.isValidUUID(tenantId)) {
      return {
        success: false,
        error: {
          code: 'INVALID_TENANT_ID_FORMAT',
          message: 'Tenant ID must be a valid UUID'
        }
      };
    }

    // Get user from token/session for association validation
    const userId = await this.extractUserFromRequest(request);
    if (!userId) {
      return {
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'User authentication required for tenant access'
        }
      };
    }

    // Validate tenant and user association
    return await this.validateTenantAccess(userId, tenantId);
  }

  /**
   * Validate tenant from JWT token
   */
  private async validateTenantFromJWT(
    request: NextRequest, 
    token: string
  ): Promise<TenantExtractionResult> {
    try {
      const payload = jwt.verify(token, this.jwtSecret) as JWTPayload;
      
      // Single tenant in token
      if (payload.tenant_id) {
        return await this.validateTenantAccess(payload.sub, payload.tenant_id);
      }

      // Multiple tenants - need to determine which one to use
      if (payload.tenant_ids && payload.tenant_ids.length > 0) {
        // Use first tenant by default (could be enhanced with tenant selection logic)
        return await this.validateTenantAccess(payload.sub, payload.tenant_ids[0]);
      }

      return {
        success: false,
        error: {
          code: 'NO_TENANT_IN_JWT',
          message: 'No tenant information found in JWT token'
        }
      };

    } catch (error) {
      return {
        success: false,
        error: {
          code: 'INVALID_JWT_TOKEN',
          message: 'Invalid or expired JWT token'
        }
      };
    }
  }

  /**
   * Validate tenant from session cookie
   */
  private async validateTenantFromSession(
    request: NextRequest,
    sessionToken: string
  ): Promise<TenantExtractionResult> {
    try {
      // For simplicity, assume session token is a JWT
      // In production, this might be a session ID that maps to stored session data
      return await this.validateTenantFromJWT(request, sessionToken);
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'INVALID_SESSION',
          message: 'Invalid or expired session'
        }
      };
    }
  }

  /**
   * Extract tenant ID from URL path (e.g., /api/tenants/{tenantId}/assets)
   */
  private extractTenantFromPath(pathname: string): string | null {
    const tenantPathRegex = /\/(?:api\/)?tenants\/([0-9a-f-]{36})(?:\/|$)/i;
    const match = pathname.match(tenantPathRegex);
    return match ? match[1] : null;
  }

  /**
   * Validate tenant from path parameter
   */
  private async validateTenantFromPath(
    request: NextRequest,
    tenantId: string
  ): Promise<TenantExtractionResult> {
    const userId = await this.extractUserFromRequest(request);
    if (!userId) {
      return {
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'User authentication required for tenant access'
        }
      };
    }

    return await this.validateTenantAccess(userId, tenantId);
  }

  /**
   * Validate tenant from query parameter
   */
  private async validateTenantFromQuery(
    request: NextRequest,
    tenantId: string
  ): Promise<TenantExtractionResult> {
    if (!this.isValidUUID(tenantId)) {
      return {
        success: false,
        error: {
          code: 'INVALID_TENANT_ID_FORMAT',
          message: 'Tenant ID must be a valid UUID'
        }
      };
    }

    const userId = await this.extractUserFromRequest(request);
    if (!userId) {
      return {
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'User authentication required for tenant access'
        }
      };
    }

    return await this.validateTenantAccess(userId, tenantId);
  }

  /**
   * Core tenant access validation logic
   */
  private async validateTenantAccess(
    userId: string, 
    tenantId: string
  ): Promise<TenantExtractionResult> {
    try {
      // Check cache first
      const cacheKey = `tenant_access:${userId}:${tenantId}`;
      const cached = await this.redisClient.get(cacheKey);
      
      if (cached) {
        const parsedData = JSON.parse(cached);
        if (parsedData.success) {
          return parsedData;
        }
      }

      // Query database for tenant and user association
      const client = await this.pgPool.connect();
      
      try {
        // Begin transaction for consistent reads
        await client.query('BEGIN');
        
        // Get tenant information
        const tenantQuery = `
          SELECT 
            t.id, t.name, 
            tm.tenant_type, tm.tenant_tier, tm.status,
            tm.max_users, tm.features, tm.data_residency,
            tm.compliance_frameworks
          FROM tenants t
          LEFT JOIN tenant_metadata tm ON t.id = tm.tenant_id
          WHERE t.id = $1 AND (tm.status IS NULL OR tm.status = 'active')
        `;
        
        const tenantResult = await client.query(tenantQuery, [tenantId]);
        
        if (tenantResult.rows.length === 0) {
          await client.query('ROLLBACK');
          
          const result = {
            success: false,
            error: {
              code: 'TENANT_NOT_FOUND',
              message: 'Tenant not found or inactive'
            }
          };
          
          // Cache negative result for shorter time
          await this.redisClient.setex(cacheKey, 60, JSON.stringify(result));
          return result;
        }

        // Get user-tenant association
        const associationQuery = `
          SELECT 
            ur.user_id, ur.tenant_id, ur.created_at as joined_at,
            r.name as role,
            array_agg(DISTINCT p.resource_namespace || ':' || p.resource || ':' || p.action) as permissions,
            ua.status, ua.last_access_at
          FROM user_roles ur
          JOIN roles r ON ur.role_id = r.id
          JOIN role_permissions rp ON r.id = rp.role_id
          JOIN permissions p ON rp.permission_id = p.id
          LEFT JOIN user_access_log ua ON ur.user_id = ua.user_id AND ur.tenant_id = ua.tenant_id
          WHERE ur.user_id = $1 AND ur.tenant_id = $2
          GROUP BY ur.user_id, ur.tenant_id, ur.created_at, r.name, ua.status, ua.last_access_at
        `;
        
        const associationResult = await client.query(associationQuery, [userId, tenantId]);
        
        if (associationResult.rows.length === 0) {
          await client.query('ROLLBACK');
          
          const result = {
            success: false,
            error: {
              code: 'TENANT_ACCESS_DENIED',
              message: 'User not authorized to access this tenant'
            }
          };
          
          await this.redisClient.setex(cacheKey, 60, JSON.stringify(result));
          return result;
        }

        await client.query('COMMIT');

        // Build successful response
        const tenantData = tenantResult.rows[0];
        const associationData = associationResult.rows[0];

        const tenantContext: TenantContext = {
          tenantId: tenantData.id,
          tenantName: tenantData.name,
          tenantType: tenantData.tenant_type || 'standard',
          tenantTier: tenantData.tenant_tier || 'basic',
          status: tenantData.status || 'active',
          maxUsers: tenantData.max_users,
          features: tenantData.features || [],
          dataResidency: tenantData.data_residency,
          complianceFrameworks: tenantData.compliance_frameworks || []
        };

        const userAssociation: UserTenantAssociation = {
          userId: associationData.user_id,
          tenantId: associationData.tenant_id,
          role: associationData.role,
          permissions: associationData.permissions || [],
          status: associationData.status || 'active',
          joinedAt: associationData.joined_at,
          lastAccessAt: associationData.last_access_at
        };

        const result: TenantExtractionResult = {
          success: true,
          tenantId,
          tenantContext,
          userAssociation
        };

        // Cache successful result
        await this.redisClient.setex(cacheKey, USER_TENANT_CACHE_TTL, JSON.stringify(result));
        
        // Update last access time asynchronously
        this.updateLastAccess(userId, tenantId).catch(err => 
          console.error('Failed to update last access:', err)
        );

        return result;

      } finally {
        client.release();
      }

    } catch (error) {
      console.error('Tenant access validation error:', error);
      return {
        success: false,
        error: {
          code: 'TENANT_VALIDATION_ERROR',
          message: 'Internal error validating tenant access'
        }
      };
    }
  }

  /**
   * Extract user ID from request (JWT token or session)
   */
  private async extractUserFromRequest(request: NextRequest): Promise<string | null> {
    try {
      // Try Authorization header first
      const authHeader = request.headers.get('authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const payload = jwt.verify(token, this.jwtSecret) as JWTPayload;
        return payload.sub;
      }

      // Try session cookie
      const sessionCookie = request.cookies.get('session_token');
      if (sessionCookie?.value) {
        const payload = jwt.verify(sessionCookie.value, this.jwtSecret) as JWTPayload;
        return payload.sub;
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Validate UUID format
   */
  private isValidUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }

  /**
   * Update user's last access time for tenant
   */
  private async updateLastAccess(userId: string, tenantId: string): Promise<void> {
    try {
      const client = await this.pgPool.connect();
      try {
        await client.query(`
          INSERT INTO user_access_log (user_id, tenant_id, last_access_at)
          VALUES ($1, $2, NOW())
          ON CONFLICT (user_id, tenant_id) 
          DO UPDATE SET last_access_at = NOW()
        `, [userId, tenantId]);
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Failed to update last access:', error);
    }
  }

  /**
   * Check if tenant context is required for endpoint
   */
  static isTenantContextRequired(pathname: string, method: string): boolean {
    // Public endpoints that don't require tenant context
    const publicEndpoints = [
      '/health',
      '/api/health',
      '/metrics',
      '/api/auth/login',
      '/api/auth/logout',
      '/api/auth/password/reset',
      '/api/policy/evaluate'
    ];

    // Check if endpoint is public
    for (const endpoint of publicEndpoints) {
      if (pathname.startsWith(endpoint)) {
        return false;
      }
    }

    // OPTIONS requests are typically public for CORS
    if (method === 'OPTIONS') {
      return false;
    }

    // All other endpoints require tenant context
    return true;
  }

  /**
   * Get tenant context type for endpoint
   */
  static getTenantContextType(pathname: string): string {
    if (pathname.includes('/admin/')) {
      return 'cross_tenant';
    }
    if (pathname.includes('/security/')) {
      return 'cross_tenant';
    }
    if (pathname.match(/\/tenants\/[0-9a-f-]{36}/)) {
      return 'specific_tenant';
    }
    if (pathname.startsWith('/api/system/') || pathname.startsWith('/api/policy/admin/')) {
      return 'system_wide';
    }
    
    return 'tenant_scoped';
  }
}

// Factory function to create tenant context service
export function createTenantContextService(): TenantContextService {
  const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    password: process.env.REDIS_PASSWORD
  });

  const pgPool = new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432'),
    database: process.env.POSTGRES_DB || 'isectech',
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  const jwtSecret = process.env.JWT_SECRET || 'your-jwt-secret-key';

  return new TenantContextService(redisClient, pgPool, jwtSecret);
}

// Export for use in middleware
export const tenantContextService = createTenantContextService();