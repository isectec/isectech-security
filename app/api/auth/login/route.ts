/**
 * Tenant-Aware Authentication API
 * Handles login with tenant context and security validation
 */

import { NextRequest, NextResponse } from 'next/server';
import { tenantAuthService } from '@/lib/auth/tenant-auth';
import { z } from 'zod';

const LoginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  tenantId: z.string().uuid('Invalid tenant ID format'),
  mfaToken: z.string().length(6, 'MFA token must be 6 digits').optional(),
  rememberMe: z.boolean().default(false),
});

/**
 * POST /api/auth/login - Authenticate user with tenant context
 */
export async function POST(request: NextRequest) {
  try {
    // Parse and validate request body
    const body = await request.json();
    const loginData = LoginSchema.parse(body);

    // Extract client metadata
    const ipAddress = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || '';

    // Authenticate user
    const authResult = await tenantAuthService.authenticate(
      loginData.email,
      loginData.password,
      loginData.tenantId,
      {
        ipAddress,
        userAgent,
        mfaToken: loginData.mfaToken,
        requireMfa: false, // Will be determined by user/tenant settings
      }
    );

    if (!authResult.success) {
      // Return appropriate error response
      const statusCode = getErrorStatusCode(authResult.error?.code);
      return NextResponse.json(
        {
          success: false,
          error: authResult.error?.message,
          code: authResult.error?.code,
          requiresMfa: authResult.error?.code === 'MFA_REQUIRED',
        },
        { status: statusCode }
      );
    }

    // Set secure session cookies
    const response = NextResponse.json({
      success: true,
      user: {
        id: authResult.user!.id,
        email: authResult.user!.email,
        role: authResult.user!.role,
        tenantId: authResult.user!.tenantId,
        securityClearance: authResult.user!.securityClearance,
        permissions: authResult.user!.permissions,
        mfaEnabled: authResult.user!.mfaEnabled,
      },
      tenant: {
        id: authResult.tenantContext!.tenantId,
        name: authResult.tenantContext!.tenantName,
        type: authResult.tenantContext!.tenantType,
        tier: authResult.tenantContext!.tenantTier,
      },
      expiresAt: authResult.expiresAt,
    });

    // Set session cookies with appropriate security flags
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict' as const,
      maxAge: loginData.rememberMe ? 30 * 24 * 60 * 60 : 8 * 60 * 60, // 30 days or 8 hours
      path: '/',
    };

    response.cookies.set('session_token', authResult.sessionToken!, cookieOptions);
    response.cookies.set('refresh_token', authResult.refreshToken!, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60, // 30 days for refresh token
    });

    // Set tenant context headers
    response.headers.set('X-Tenant-ID', authResult.tenantContext!.tenantId);
    response.headers.set('X-Tenant-Name', authResult.tenantContext!.tenantName);
    response.headers.set('X-User-Role', authResult.user!.role);
    response.headers.set('X-Security-Clearance', authResult.user!.securityClearance);

    return response;

  } catch (error) {
    console.error('Login API error:', error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid login data',
          details: error.errors,
        },
        { status: 400 }
      );
    }

    return NextResponse.json(
      {
        success: false,
        error: 'Authentication service error',
      },
      { status: 500 }
    );
  }
}

/**
 * OPTIONS /api/auth/login - Handle CORS preflight
 */
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || 'https://app.isectech.org',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Tenant-ID',
      'Access-Control-Max-Age': '86400',
    },
  });
}

// Helper functions

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

function getErrorStatusCode(errorCode?: string): number {
  switch (errorCode) {
    case 'INVALID_CREDENTIALS':
    case 'INVALID_MFA':
      return 401;
    case 'USER_INACTIVE':
    case 'IP_NOT_ALLOWED':
    case 'TIME_RESTRICTED':
      return 403;
    case 'INVALID_TENANT':
      return 404;
    case 'RATE_LIMITED':
      return 429;
    case 'MFA_REQUIRED':
      return 200; // Special case - not an error, just requires additional step
    default:
      return 500;
  }
}