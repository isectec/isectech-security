/**
 * Authentication Middleware for iSECTECH Enterprise Security Platform
 * Handles JWT validation, session management, and user authorization
 */

import { NextRequest, NextResponse } from 'next/server';
// JWT utilities - using crypto instead of jose for production deployment
import { createHash, createHmac } from 'crypto';

// Types
interface User {
  id: string;
  email: string;
  tenantId: string;
  role: string;
  permissions: string[];
  lastLogin?: string;
  sessionId?: string;
}

interface AuthContext {
  user: User;
  token: string;
  isValid: boolean;
  expiresAt: number;
}

interface AuthMiddlewareOptions {
  required?: boolean;
  roles?: string[];
  permissions?: string[];
  tenantRequired?: boolean;
  skipPaths?: string[];
}

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_ISSUER = process.env.JWT_ISSUER || 'isectech-platform';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'isectech-api';
const JWT_EXPIRES_IN_MS = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

/**
 * Generate JWT token for user (simplified implementation)
 */
export async function generateToken(user: User): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.floor(JWT_EXPIRES_IN_MS / 1000);
  
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  const payload = {
    userId: user.id,
    email: user.email,
    tenantId: user.tenantId,
    role: user.role,
    permissions: user.permissions,
    sessionId: user.sessionId || crypto.randomUUID(),
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    iat: now,
    exp: exp
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  
  const signature = createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Verify and decode JWT token (simplified implementation)
 */
export async function verifyToken(token: string): Promise<AuthContext | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [encodedHeader, encodedPayload, signature] = parts;
    
    // Verify signature
    const expectedSignature = createHmac('sha256', JWT_SECRET)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    
    if (signature !== expectedSignature) {
      return null;
    }

    // Decode payload
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null;
    }
    
    // Check issuer and audience
    if (payload.iss !== JWT_ISSUER || payload.aud !== JWT_AUDIENCE) {
      return null;
    }

    const user: User = {
      id: payload.userId as string,
      email: payload.email as string,
      tenantId: payload.tenantId as string,
      role: payload.role as string,
      permissions: payload.permissions as string[],
      sessionId: payload.sessionId as string,
    };

    return {
      user,
      token,
      isValid: true,
      expiresAt: payload.exp * 1000, // Convert to milliseconds
    };
  } catch (error) {
    console.error('JWT verification failed:', error);
    return null;
  }
}

/**
 * Extract token from request headers
 */
export function extractToken(req: NextRequest): string | null {
  // Check Authorization header
  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Check cookies
  const cookieToken = req.cookies.get('auth-token')?.value;
  if (cookieToken) {
    return cookieToken;
  }

  return null;
}

/**
 * Check if user has required role
 */
export function hasRole(user: User, requiredRoles: string[]): boolean {
  return requiredRoles.includes(user.role) || user.role === 'super_admin';
}

/**
 * Check if user has required permissions
 */
export function hasPermission(user: User, requiredPermissions: string[]): boolean {
  // Super admin has all permissions
  if (user.role === 'super_admin') {
    return true;
  }

  return requiredPermissions.every(permission => 
    user.permissions.includes(permission)
  );
}

/**
 * Check if user belongs to required tenant
 */
export function hasTenantAccess(user: User, requiredTenantId?: string): boolean {
  if (!requiredTenantId) {
    return true; // No tenant requirement
  }
  
  // Super admin can access all tenants
  if (user.role === 'super_admin') {
    return true;
  }

  return user.tenantId === requiredTenantId;
}

/**
 * Main authentication middleware
 */
export function authMiddleware(options: AuthMiddlewareOptions = {}) {
  return async (req: NextRequest): Promise<NextResponse | null> => {
    const {
      required = true,
      roles = [],
      permissions = [],
      tenantRequired = false,
      skipPaths = []
    } = options;

    const pathname = req.nextUrl.pathname;

    // Skip authentication for specified paths
    if (skipPaths.some(path => pathname.startsWith(path))) {
      return null; // Continue without authentication
    }

    const token = extractToken(req);

    if (!token) {
      if (required) {
        return NextResponse.json(
          {
            success: false,
            error: 'Authentication required',
            message: 'No authentication token provided'
          },
          { status: 401 }
        );
      }
      return null; // Continue without authentication
    }

    const authContext = await verifyToken(token);

    if (!authContext || !authContext.isValid) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid token',
          message: 'Authentication token is invalid or expired'
        },
        { status: 401 }
      );
    }

    const { user } = authContext;

    // Check role requirements
    if (roles.length > 0 && !hasRole(user, roles)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Insufficient privileges',
          message: `Required role: ${roles.join(' or ')}`
        },
        { status: 403 }
      );
    }

    // Check permission requirements
    if (permissions.length > 0 && !hasPermission(user, permissions)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Insufficient permissions',
          message: `Required permissions: ${permissions.join(', ')}`
        },
        { status: 403 }
      );
    }

    // Check tenant requirements
    if (tenantRequired && !user.tenantId) {
      return NextResponse.json(
        {
          success: false,
          error: 'Tenant required',
          message: 'User must be associated with a tenant'
        },
        { status: 403 }
      );
    }

    // Add user context to request headers for downstream use
    const response = NextResponse.next();
    response.headers.set('x-user-id', user.id);
    response.headers.set('x-user-email', user.email);
    response.headers.set('x-user-role', user.role);
    response.headers.set('x-tenant-id', user.tenantId);
    response.headers.set('x-user-permissions', JSON.stringify(user.permissions));

    return null; // Continue with authenticated request
  };
}

/**
 * Predefined middleware configurations
 */
export const requireAuth = authMiddleware({ required: true });
export const requireAdmin = authMiddleware({ required: true, roles: ['admin', 'super_admin'] });
export const requireSuperAdmin = authMiddleware({ required: true, roles: ['super_admin'] });
export const requireTenant = authMiddleware({ required: true, tenantRequired: true });

/**
 * Middleware for compliance-related endpoints
 */
export const requireComplianceAccess = authMiddleware({
  required: true,
  permissions: ['compliance:read', 'compliance:write'],
  tenantRequired: true
});

/**
 * Middleware for executive dashboard access
 */
export const requireExecutiveAccess = authMiddleware({
  required: true,
  roles: ['executive', 'admin', 'super_admin'],
  tenantRequired: true
});

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
export const optionalAuth = authMiddleware({ required: false });

/**
 * Get user context from request (after authentication middleware)
 */
export function getUserFromRequest(req: NextRequest): User | null {
  try {
    const userId = req.headers.get('x-user-id');
    const email = req.headers.get('x-user-email');
    const role = req.headers.get('x-user-role');
    const tenantId = req.headers.get('x-tenant-id');
    const permissionsHeader = req.headers.get('x-user-permissions');

    if (!userId || !email || !role) {
      return null;
    }

    const permissions = permissionsHeader ? JSON.parse(permissionsHeader) : [];

    return {
      id: userId,
      email,
      role,
      tenantId: tenantId || '',
      permissions
    };
  } catch (error) {
    console.error('Error extracting user from request:', error);
    return null;
  }
}

/**
 * Refresh token if close to expiry
 */
export async function refreshTokenIfNeeded(authContext: AuthContext): Promise<string | null> {
  const now = Date.now();
  const timeUntilExpiry = authContext.expiresAt - now;
  const refreshThreshold = 15 * 60 * 1000; // 15 minutes

  if (timeUntilExpiry < refreshThreshold) {
    return await generateToken(authContext.user);
  }

  return null;
}

export default authMiddleware;