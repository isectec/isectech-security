/**
 * Tenant Context Middleware for iSECTECH Multi-Tenant Platform
 * Provides tenant isolation and context switching with <500ms performance
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import { UUID } from 'crypto';

export interface TenantContext {
  tenantId: string;
  tenantName: string;
  tenantType: 'enterprise' | 'government' | 'defense' | 'critical_infra' | 'financial' | 'healthcare' | 'msp' | 'startup';
  tenantTier: 'essential' | 'advanced' | 'enterprise' | 'government';
  securityClearance: 'unclassified' | 'cui' | 'confidential' | 'secret' | 'top_secret';
  permissions: string[];
  resourceQuotas: {
    maxUsers: number;
    maxDevices: number;
    maxAlerts: number;
    storageQuotaGB: number;
    apiCallsPerMinute: number;
  };
  complianceFrameworks: string[];
  ipAddress: string;
  userAgent: string;
  sessionId: string;
  requestId: string;
  timestamp: Date;
}

export interface TenantMiddlewareOptions {
  enforceIpWhitelist?: boolean;
  requireSecurityClearance?: boolean;
  enableRateLimiting?: boolean;
  logAllAccess?: boolean;
  enableCrossTenantAccess?: boolean;
  validationMode: 'strict' | 'permissive';
}

const DEFAULT_OPTIONS: TenantMiddlewareOptions = {
  enforceIpWhitelist: true,
  requireSecurityClearance: true,
  enableRateLimiting: true,
  logAllAccess: true,
  enableCrossTenantAccess: false,
  validationMode: 'strict',
};

/**
 * Extracts tenant context from request headers and validates access
 */
export async function extractTenantContext(
  request: NextRequest,
  options: Partial<TenantMiddlewareOptions> = {}
): Promise<TenantContext | null> {
  const config = { ...DEFAULT_OPTIONS, ...options };
  
  try {
    // Extract tenant ID from header, subdomain, or path
    const tenantId = getTenantIdFromRequest(request);
    if (!tenantId) {
      console.warn('No tenant ID found in request');
      return null;
    }

    // Get client IP and user agent
    const ipAddress = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || '';
    
    // Generate request tracking IDs
    const requestId = crypto.randomUUID();
    const sessionId = request.headers.get('x-session-id') || crypto.randomUUID();

    // Fetch tenant context from cache or API
    const tenantData = await fetchTenantContext(tenantId, {
      ipAddress,
      userAgent,
      requestId,
    });

    if (!tenantData) {
      console.error(`Tenant not found: ${tenantId}`);
      return null;
    }

    // Validate IP whitelist if enabled
    if (config.enforceIpWhitelist && !isIPAllowed(ipAddress, tenantData.allowedIpRanges)) {
      console.warn(`IP ${ipAddress} not allowed for tenant ${tenantId}`);
      return null;
    }

    // Build tenant context
    const context: TenantContext = {
      tenantId: tenantData.id,
      tenantName: tenantData.name,
      tenantType: tenantData.type,
      tenantTier: tenantData.tier,
      securityClearance: tenantData.maxSecurityClearance,
      permissions: tenantData.permissions || [],
      resourceQuotas: tenantData.resourceQuotas,
      complianceFrameworks: tenantData.complianceFrameworks || [],
      ipAddress,
      userAgent,
      sessionId,
      requestId,
      timestamp: new Date(),
    };

    // Log access if enabled
    if (config.logAllAccess) {
      await logTenantAccess(context, request);
    }

    return context;
  } catch (error) {
    console.error('Failed to extract tenant context:', error);
    return null;
  }
}

/**
 * Creates tenant isolation middleware for Next.js API routes
 */
export function createTenantMiddleware(options: Partial<TenantMiddlewareOptions> = {}) {
  return async (request: NextRequest) => {
    const startTime = performance.now();
    
    try {
      // Extract tenant context
      const tenantContext = await extractTenantContext(request, options);
      
      if (!tenantContext) {
        return NextResponse.json(
          { error: 'Invalid or missing tenant context' },
          { status: 401 }
        );
      }

      // Apply rate limiting if enabled
      if (options.enableRateLimiting) {
        const rateLimitResult = await checkRateLimit(tenantContext);
        if (!rateLimitResult.allowed) {
          return NextResponse.json(
            { 
              error: 'Rate limit exceeded',
              retryAfter: rateLimitResult.retryAfter 
            },
            { 
              status: 429,
              headers: {
                'Retry-After': rateLimitResult.retryAfter.toString(),
                'X-RateLimit-Limit': rateLimitResult.limit.toString(),
                'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
              }
            }
          );
        }
      }

      // Create response with tenant context headers
      const response = NextResponse.next();
      
      // Add tenant context to headers for downstream middleware
      response.headers.set('X-Tenant-ID', tenantContext.tenantId);
      response.headers.set('X-Tenant-Name', tenantContext.tenantName);
      response.headers.set('X-Tenant-Type', tenantContext.tenantType);
      response.headers.set('X-Tenant-Tier', tenantContext.tenantTier);
      response.headers.set('X-Security-Clearance', tenantContext.securityClearance);
      response.headers.set('X-Request-ID', tenantContext.requestId);
      response.headers.set('X-Session-ID', tenantContext.sessionId);
      
      // Add performance timing
      const processingTime = performance.now() - startTime;
      response.headers.set('X-Tenant-Processing-Time', processingTime.toString());
      
      // Store context for API routes (using AsyncLocalStorage in production)
      (global as any).__tenantContext = tenantContext;
      
      return response;
    } catch (error) {
      console.error('Tenant middleware error:', error);
      return NextResponse.json(
        { error: 'Internal server error' },
        { status: 500 }
      );
    }
  };
}

/**
 * Hook to get current tenant context in API routes
 */
export function getCurrentTenantContext(): TenantContext | null {
  // In production, this would use AsyncLocalStorage
  return (global as any).__tenantContext || null;
}

/**
 * Validates tenant access permissions for specific operations
 */
export async function validateTenantOperation(
  context: TenantContext,
  operation: string,
  resource?: string
): Promise<boolean> {
  try {
    // Check basic permissions
    const hasPermission = context.permissions.includes(`${operation}:${resource}`) ||
                         context.permissions.includes(`${operation}:*`) ||
                         context.permissions.includes('*:*');

    if (!hasPermission) {
      await logSecurityViolation(context, 'permission_denied', {
        operation,
        resource,
        requiredPermission: `${operation}:${resource}`
      });
      return false;
    }

    // Additional security clearance validation
    if (resource && requiresSecurityClearance(resource)) {
      const requiredClearance = getRequiredSecurityClearance(resource);
      if (!hasRequiredClearance(context.securityClearance, requiredClearance)) {
        await logSecurityViolation(context, 'clearance_insufficient', {
          operation,
          resource,
          userClearance: context.securityClearance,
          requiredClearance
        });
        return false;
      }
    }

    return true;
  } catch (error) {
    console.error('Failed to validate tenant operation:', error);
    return false;
  }
}

/**
 * Creates tenant-isolated database query context
 */
export function createTenantDatabaseContext(context: TenantContext) {
  return {
    tenantId: context.tenantId,
    securityClearance: context.securityClearance,
    rowLevelSecurity: true,
    auditEnabled: true,
    filters: {
      tenant_id: context.tenantId,
      max_security_clearance: context.securityClearance
    }
  };
}

// Helper functions

function getTenantIdFromRequest(request: NextRequest): string | null {
  // Check X-Tenant-ID header first
  const headerTenantId = request.headers.get('X-Tenant-ID');
  if (headerTenantId) return headerTenantId;

  // Check subdomain (e.g., acme.app.isectech.org)
  const host = request.headers.get('host');
  if (host) {
    const subdomain = host.split('.')[0];
    if (subdomain && subdomain !== 'app' && subdomain !== 'www') {
      return subdomain;
    }
  }

  // Check path parameter (e.g., /api/tenants/123/...)
  const pathMatch = request.nextUrl.pathname.match(/\/api\/tenants\/([^\/]+)/);
  if (pathMatch) return pathMatch[1];

  return null;
}

function getClientIP(request: NextRequest): string {
  const xForwardedFor = request.headers.get('x-forwarded-for');
  const xRealIP = request.headers.get('x-real-ip');
  const cfConnectingIP = request.headers.get('cf-connecting-ip');
  
  return cfConnectingIP || 
         xRealIP || 
         (xForwardedFor?.split(',')[0].trim()) || 
         request.ip || 
         '0.0.0.0';
}

async function fetchTenantContext(tenantId: string, metadata: any) {
  // In production, this would fetch from Redis cache first, then database
  // For now, return mock data structure
  return {
    id: tenantId,
    name: `Tenant ${tenantId}`,
    type: 'enterprise' as const,
    tier: 'enterprise' as const,
    maxSecurityClearance: 'confidential' as const,
    permissions: ['read:*', 'write:alerts', 'manage:users'],
    resourceQuotas: {
      maxUsers: 1000,
      maxDevices: 10000,
      maxAlerts: 100000,
      storageQuotaGB: 1000,
      apiCallsPerMinute: 10000,
    },
    complianceFrameworks: ['soc2', 'iso27001'],
    allowedIpRanges: ['0.0.0.0/0'], // Allow all for now
  };
}

function isIPAllowed(ipAddress: string, allowedRanges: string[]): boolean {
  // Simplified IP range checking - in production use proper CIDR validation
  if (allowedRanges.includes('0.0.0.0/0')) return true;
  return allowedRanges.some(range => ipAddress.startsWith(range.split('/')[0]));
}

async function checkRateLimit(context: TenantContext): Promise<{
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfter: number;
}> {
  // In production, this would use Redis for distributed rate limiting
  return {
    allowed: true,
    limit: context.resourceQuotas.apiCallsPerMinute,
    remaining: context.resourceQuotas.apiCallsPerMinute - 1,
    retryAfter: 60
  };
}

async function logTenantAccess(context: TenantContext, request: NextRequest) {
  // In production, this would write to audit log system
  console.log(`Tenant access: ${context.tenantId} from ${context.ipAddress} to ${request.nextUrl.pathname}`);
}

async function logSecurityViolation(context: TenantContext, violation: string, details: any) {
  // In production, this would trigger security alerts
  console.warn(`Security violation: ${violation} for tenant ${context.tenantId}`, details);
}

function requiresSecurityClearance(resource: string): boolean {
  const secureResources = ['classified-alerts', 'threat-intelligence', 'security-reports'];
  return secureResources.some(secure => resource.includes(secure));
}

function getRequiredSecurityClearance(resource: string): string {
  if (resource.includes('top-secret')) return 'top_secret';
  if (resource.includes('secret')) return 'secret';
  if (resource.includes('confidential')) return 'confidential';
  return 'unclassified';
}

function hasRequiredClearance(userClearance: string, requiredClearance: string): boolean {
  const clearanceLevels = ['unclassified', 'cui', 'confidential', 'secret', 'top_secret'];
  const userLevel = clearanceLevels.indexOf(userClearance);
  const requiredLevel = clearanceLevels.indexOf(requiredClearance);
  return userLevel >= requiredLevel;
}