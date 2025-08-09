/**
 * Session Verification API
 * Validates session tokens and returns user/tenant context
 */

import { NextRequest, NextResponse } from 'next/server';
import { tenantAuthService } from '@/lib/auth/tenant-auth';

/**
 * GET /api/auth/verify - Verify session and return user context
 */
export async function GET(request: NextRequest) {
  try {
    // Get session token from cookie or header
    const sessionToken = getSessionToken(request);
    
    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'No session token provided' },
        { status: 401 }
      );
    }

    // Validate session
    const user = await tenantAuthService.validateSession(sessionToken);
    
    if (!user) {
      return NextResponse.json(
        { success: false, error: 'Invalid or expired session' },
        { status: 401 }
      );
    }

    // Return user and tenant context
    const response = NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenantId: user.tenantId,
        securityClearance: user.securityClearance,
        permissions: user.permissions,
        status: user.status,
        lastLoginAt: user.lastLoginAt,
        mfaEnabled: user.mfaEnabled,
      },
      session: {
        sessionId: user.sessionId,
        // In production, calculate actual expiry time
        expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000),
      }
    });

    // Set current tenant context headers
    response.headers.set('X-Tenant-ID', user.tenantId);
    response.headers.set('X-User-Role', user.role);
    response.headers.set('X-Security-Clearance', user.securityClearance);

    return response;

  } catch (error) {
    console.error('Session verification error:', error);
    return NextResponse.json(
      { success: false, error: 'Session verification service error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/auth/verify - Verify session with additional authorization checks
 */
export async function POST(request: NextRequest) {
  try {
    const sessionToken = getSessionToken(request);
    
    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'No session token provided' },
        { status: 401 }
      );
    }

    const user = await tenantAuthService.validateSession(sessionToken);
    
    if (!user) {
      return NextResponse.json(
        { success: false, error: 'Invalid or expired session' },
        { status: 401 }
      );
    }

    // Parse authorization request
    const body = await request.json();
    const { action, resource, context } = body;

    if (action) {
      // Perform authorization check
      const authResult = await tenantAuthService.authorize(user, action, resource, context);
      
      return NextResponse.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          tenantId: user.tenantId,
          securityClearance: user.securityClearance,
          permissions: user.permissions,
        },
        authorization: {
          allowed: authResult.allowed,
          reason: authResult.reason,
          requiredPermissions: authResult.requiredPermissions,
        }
      });
    }

    // No authorization check requested, just return user info
    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        tenantId: user.tenantId,
        securityClearance: user.securityClearance,
        permissions: user.permissions,
      }
    });

  } catch (error) {
    console.error('Session verification with authorization error:', error);
    return NextResponse.json(
      { success: false, error: 'Session verification service error' },
      { status: 500 }
    );
  }
}

/**
 * OPTIONS /api/auth/verify - Handle CORS preflight
 */
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || 'https://app.isectech.org',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cookie',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    },
  });
}

// Helper functions

function getSessionToken(request: NextRequest): string | null {
  // Try to get from Authorization header first
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Try to get from cookie
  const sessionCookie = request.cookies.get('session_token');
  if (sessionCookie?.value) {
    return sessionCookie.value;
  }

  return null;
}