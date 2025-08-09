/**
 * Tenant-Aware Logout API
 * Handles secure session cleanup and audit logging
 */

import { NextRequest, NextResponse } from 'next/server';
import { tenantAuthService } from '@/lib/auth/tenant-auth';

/**
 * POST /api/auth/logout - Logout user and cleanup session
 */
export async function POST(request: NextRequest) {
  try {
    // Get session token from cookie or header
    const sessionToken = getSessionToken(request);
    
    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'No active session found' },
        { status: 400 }
      );
    }

    // Logout user (this handles audit logging and session cleanup)
    await tenantAuthService.logout(sessionToken);

    // Create response with cleared cookies
    const response = NextResponse.json({
      success: true,
      message: 'Logged out successfully',
    });

    // Clear session cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict' as const,
      path: '/',
      maxAge: 0, // Expire immediately
    };

    response.cookies.set('session_token', '', cookieOptions);
    response.cookies.set('refresh_token', '', cookieOptions);

    // Clear tenant context headers
    response.headers.set('X-Tenant-ID', '');
    response.headers.set('X-Tenant-Name', '');
    response.headers.set('X-User-Role', '');
    response.headers.set('X-Security-Clearance', '');

    return response;

  } catch (error) {
    console.error('Logout API error:', error);
    return NextResponse.json(
      { success: false, error: 'Logout service error' },
      { status: 500 }
    );
  }
}

/**
 * OPTIONS /api/auth/logout - Handle CORS preflight
 */
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || 'https://app.isectech.org',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
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