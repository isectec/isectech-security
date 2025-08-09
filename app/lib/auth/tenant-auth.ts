/**
 * Tenant-Aware Authentication and Authorization System
 * Integrates with PostgreSQL RLS and tenant context middleware
 */

import { NextRequest } from 'next/server';
import { getCurrentTenantContext, validateTenantOperation, TenantContext } from '@/lib/middleware/tenant-context';
import { UUID } from 'crypto';

export interface TenantUser {
  id: string;
  tenantId: string;
  email: string;
  role: 'super_admin' | 'tenant_admin' | 'security_analyst' | 'operator' | 'viewer' | 'msp_admin';
  securityClearance: 'unclassified' | 'cui' | 'confidential' | 'secret' | 'top_secret';
  permissions: string[];
  status: 'active' | 'inactive' | 'suspended' | 'pending';
  lastLoginAt?: Date;
  mfaEnabled: boolean;
  sessionId?: string;
  ipWhitelist?: string[];
  timeBasedAccess?: {
    allowedHours: [number, number]; // [start, end] in 24h format
    timezone: string;
    allowedDays: number[]; // 0-6 (Sunday-Saturday)
  };
}

export interface AuthenticationResult {
  success: boolean;
  user?: TenantUser;
  tenantContext?: TenantContext;
  sessionToken?: string;
  refreshToken?: string;
  expiresAt?: Date;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
}

export interface AuthorizationResult {
  allowed: boolean;
  reason?: string;
  requiredPermissions?: string[];
  userPermissions?: string[];
  securityViolation?: boolean;
}

/**
 * Tenant-aware authentication service
 */
export class TenantAuthService {
  private readonly sessionStore: Map<string, TenantUser> = new Map();
  private readonly rateLimitStore: Map<string, { count: number; resetTime: number }> = new Map();

  /**
   * Authenticate user within tenant context
   */
  async authenticate(
    email: string,
    password: string,
    tenantId: string,
    options: {
      ipAddress?: string;
      userAgent?: string;
      mfaToken?: string;
      requireMfa?: boolean;
    } = {}
  ): Promise<AuthenticationResult> {
    try {
      // Rate limiting check
      if (!this.checkRateLimit(email, options.ipAddress)) {
        return {
          success: false,
          error: {
            code: 'RATE_LIMITED',
            message: 'Too many authentication attempts. Please try again later.',
          }
        };
      }

      // Validate tenant exists and is active
      const tenantValid = await this.validateTenant(tenantId);
      if (!tenantValid) {
        return {
          success: false,
          error: {
            code: 'INVALID_TENANT',
            message: 'Tenant not found or inactive',
          }
        };
      }

      // Authenticate user credentials
      const user = await this.validateUserCredentials(email, password, tenantId);
      if (!user) {
        this.recordFailedAttempt(email, options.ipAddress);
        return {
          success: false,
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password',
          }
        };
      }

      // Validate user status
      if (user.status !== 'active') {
        return {
          success: false,
          error: {
            code: 'USER_INACTIVE',
            message: `User account is ${user.status}`,
          }
        };
      }

      // IP whitelist validation
      if (user.ipWhitelist && options.ipAddress) {
        if (!this.validateIPAccess(options.ipAddress, user.ipWhitelist)) {
          await this.logSecurityViolation(user, 'ip_whitelist_violation', {
            ipAddress: options.ipAddress,
            allowedIPs: user.ipWhitelist
          });
          return {
            success: false,
            error: {
              code: 'IP_NOT_ALLOWED',
              message: 'Access denied from this IP address',
            }
          };
        }
      }

      // Time-based access validation
      if (user.timeBasedAccess && !this.validateTimeBasedAccess(user.timeBasedAccess)) {
        return {
          success: false,
          error: {
            code: 'TIME_RESTRICTED',
            message: 'Access not allowed at this time',
          }
        };
      }

      // MFA validation
      if (user.mfaEnabled || options.requireMfa) {
        if (!options.mfaToken) {
          return {
            success: false,
            error: {
              code: 'MFA_REQUIRED',
              message: 'Multi-factor authentication required',
            }
          };
        }

        const mfaValid = await this.validateMfaToken(user.id, options.mfaToken);
        if (!mfaValid) {
          await this.logSecurityViolation(user, 'mfa_failure', {
            ipAddress: options.ipAddress,
            userAgent: options.userAgent
          });
          return {
            success: false,
            error: {
              code: 'INVALID_MFA',
              message: 'Invalid MFA token',
            }
          };
        }
      }

      // Generate session tokens
      const sessionToken = await this.generateSessionToken(user);
      const refreshToken = await this.generateRefreshToken(user);
      const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours

      // Update user session info
      user.sessionId = sessionToken;
      user.lastLoginAt = new Date();
      this.sessionStore.set(sessionToken, user);

      // Create tenant context
      const tenantContext = await this.createTenantContext(user, {
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
        sessionId: sessionToken,
      });

      // Log successful authentication
      await this.logAuthenticationEvent(user, 'login_success', {
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
        mfaUsed: !!options.mfaToken
      });

      return {
        success: true,
        user,
        tenantContext,
        sessionToken,
        refreshToken,
        expiresAt,
      };

    } catch (error) {
      console.error('Authentication error:', error);
      return {
        success: false,
        error: {
          code: 'AUTHENTICATION_ERROR',
          message: 'Authentication service error',
          details: error.message
        }
      };
    }
  }

  /**
   * Authorize user action within tenant context
   */
  async authorize(
    user: TenantUser,
    action: string,
    resource?: string,
    context?: {
      resourceTenantId?: string;
      securityClassification?: string;
      additionalChecks?: Record<string, any>;
    }
  ): Promise<AuthorizationResult> {
    try {
      // Basic permission check
      const requiredPermission = resource ? `${action}:${resource}` : action;
      const hasBasicPermission = this.checkPermission(user.permissions, requiredPermission);

      if (!hasBasicPermission) {
        await this.logSecurityViolation(user, 'permission_denied', {
          action,
          resource,
          requiredPermission,
          userPermissions: user.permissions
        });

        return {
          allowed: false,
          reason: 'Insufficient permissions',
          requiredPermissions: [requiredPermission],
          userPermissions: user.permissions,
          securityViolation: true,
        };
      }

      // Cross-tenant access check
      if (context?.resourceTenantId && context.resourceTenantId !== user.tenantId) {
        const crossTenantAllowed = await this.validateCrossTenantAccess(user, context.resourceTenantId);
        if (!crossTenantAllowed) {
          await this.logSecurityViolation(user, 'cross_tenant_access_denied', {
            action,
            resource,
            userTenantId: user.tenantId,
            resourceTenantId: context.resourceTenantId
          });

          return {
            allowed: false,
            reason: 'Cross-tenant access denied',
            securityViolation: true,
          };
        }
      }

      // Security clearance check
      if (context?.securityClassification) {
        const clearanceValid = this.validateSecurityClearance(
          user.securityClearance,
          context.securityClassification
        );

        if (!clearanceValid) {
          await this.logSecurityViolation(user, 'clearance_insufficient', {
            action,
            resource,
            userClearance: user.securityClearance,
            requiredClearance: context.securityClassification
          });

          return {
            allowed: false,
            reason: 'Insufficient security clearance',
            securityViolation: true,
          };
        }
      }

      // Additional context-specific checks
      if (context?.additionalChecks) {
        for (const [checkName, checkValue] of Object.entries(context.additionalChecks)) {
          const checkResult = await this.performAdditionalCheck(user, checkName, checkValue);
          if (!checkResult) {
            return {
              allowed: false,
              reason: `Failed additional check: ${checkName}`,
            };
          }
        }
      }

      // Log successful authorization
      await this.logAuthorizationEvent(user, 'authorization_granted', {
        action,
        resource,
        securityClassification: context?.securityClassification
      });

      return {
        allowed: true,
      };

    } catch (error) {
      console.error('Authorization error:', error);
      return {
        allowed: false,
        reason: 'Authorization service error',
      };
    }
  }

  /**
   * Validate session token and return user context
   */
  async validateSession(sessionToken: string): Promise<TenantUser | null> {
    const user = this.sessionStore.get(sessionToken);
    if (!user) {
      return null;
    }

    // Check if session is still valid (not expired, user still active, etc.)
    if (user.status !== 'active') {
      this.sessionStore.delete(sessionToken);
      return null;
    }

    return user;
  }

  /**
   * Logout user and cleanup session
   */
  async logout(sessionToken: string): Promise<void> {
    const user = this.sessionStore.get(sessionToken);
    if (user) {
      await this.logAuthenticationEvent(user, 'logout', {});
      this.sessionStore.delete(sessionToken);
      
      // Clear tenant context in database
      // In production: await db.query('DELETE FROM session_context WHERE session_id = $1', [sessionToken]);
    }
  }

  // Private helper methods

  private checkRateLimit(email: string, ipAddress?: string): boolean {
    const key = `${email}:${ipAddress || 'unknown'}`;
    const now = Date.now();
    const limit = this.rateLimitStore.get(key);

    if (!limit || now > limit.resetTime) {
      this.rateLimitStore.set(key, { count: 1, resetTime: now + 15 * 60 * 1000 }); // 15 min window
      return true;
    }

    if (limit.count >= 5) { // Max 5 attempts per window
      return false;
    }

    limit.count++;
    return true;
  }

  private recordFailedAttempt(email: string, ipAddress?: string): void {
    // In production, this would log to security monitoring system
    console.warn(`Failed login attempt for ${email} from ${ipAddress}`);
  }

  private async validateTenant(tenantId: string): Promise<boolean> {
    // In production, query database to validate tenant
    return tenantId && tenantId.length > 0;
  }

  private async validateUserCredentials(email: string, password: string, tenantId: string): Promise<TenantUser | null> {
    // In production, this would hash password and query database
    // Mock implementation for development
    const mockUsers: Record<string, TenantUser> = {
      'admin@acme.com': {
        id: '111e4567-e89b-12d3-a456-426614174000',
        tenantId: '123e4567-e89b-12d3-a456-426614174000',
        email: 'admin@acme.com',
        role: 'tenant_admin',
        securityClearance: 'confidential',
        permissions: ['*:*'],
        status: 'active',
        mfaEnabled: true,
      },
      'admin@defense.gov': {
        id: '222e5678-e89b-12d3-a456-426614174001',
        tenantId: '234e5678-e89b-12d3-a456-426614174001',
        email: 'admin@defense.gov',
        role: 'tenant_admin',
        securityClearance: 'secret',
        permissions: ['*:*'],
        status: 'active',
        mfaEnabled: true,
      }
    };

    const user = mockUsers[email];
    if (user && user.tenantId === tenantId) {
      return { ...user };
    }

    return null;
  }

  private validateIPAccess(ipAddress: string, allowedIPs: string[]): boolean {
    // Simplified IP validation - in production use proper CIDR matching
    return allowedIPs.some(allowed => 
      allowed === '0.0.0.0/0' || ipAddress.startsWith(allowed.split('/')[0])
    );
  }

  private validateTimeBasedAccess(timeAccess: NonNullable<TenantUser['timeBasedAccess']>): boolean {
    const now = new Date();
    const currentHour = now.getHours();
    const currentDay = now.getDay();

    // Check allowed hours
    const [startHour, endHour] = timeAccess.allowedHours;
    if (currentHour < startHour || currentHour > endHour) {
      return false;
    }

    // Check allowed days
    if (!timeAccess.allowedDays.includes(currentDay)) {
      return false;
    }

    return true;
  }

  private async validateMfaToken(userId: string, token: string): Promise<boolean> {
    // In production, this would validate TOTP/SMS/push notification
    // Mock implementation accepts any 6-digit code
    return /^\d{6}$/.test(token);
  }

  private async generateSessionToken(user: TenantUser): Promise<string> {
    // In production, use cryptographically secure token generation
    return `session_${crypto.randomUUID()}`;
  }

  private async generateRefreshToken(user: TenantUser): Promise<string> {
    // In production, use cryptographically secure token generation
    return `refresh_${crypto.randomUUID()}`;
  }

  private async createTenantContext(user: TenantUser, metadata: any): Promise<TenantContext> {
    // This would integrate with the tenant context middleware
    return {
      tenantId: user.tenantId,
      tenantName: `tenant-${user.tenantId}`,
      tenantType: 'enterprise', // Would be fetched from database
      tenantTier: 'enterprise',
      securityClearance: user.securityClearance,
      permissions: user.permissions,
      resourceQuotas: {
        maxUsers: 1000,
        maxDevices: 10000,
        maxAlerts: 100000,
        storageQuotaGB: 1000,
        apiCallsPerMinute: 10000,
      },
      complianceFrameworks: ['soc2', 'iso27001'],
      ipAddress: metadata.ipAddress || '0.0.0.0',
      userAgent: metadata.userAgent || '',
      sessionId: metadata.sessionId,
      requestId: crypto.randomUUID(),
      timestamp: new Date(),
    };
  }

  private checkPermission(userPermissions: string[], requiredPermission: string): boolean {
    // Check for exact match
    if (userPermissions.includes(requiredPermission)) {
      return true;
    }

    // Check for wildcard permissions
    if (userPermissions.includes('*:*')) {
      return true;
    }

    // Check for resource wildcard (e.g., 'read:*' matches 'read:alerts')
    const [action, resource] = requiredPermission.split(':');
    if (userPermissions.includes(`${action}:*`)) {
      return true;
    }

    return false;
  }

  private async validateCrossTenantAccess(user: TenantUser, targetTenantId: string): Promise<boolean> {
    // Check if user has cross-tenant permissions (e.g., MSP admin)
    if (user.role === 'msp_admin' || user.permissions.includes('manage:tenants')) {
      // In production, verify the relationship between tenants
      return true;
    }

    return false;
  }

  private validateSecurityClearance(userClearance: string, requiredClearance: string): boolean {
    const clearanceLevels = ['unclassified', 'cui', 'confidential', 'secret', 'top_secret'];
    const userLevel = clearanceLevels.indexOf(userClearance);
    const requiredLevel = clearanceLevels.indexOf(requiredClearance);
    return userLevel >= requiredLevel;
  }

  private async performAdditionalCheck(user: TenantUser, checkName: string, checkValue: any): Promise<boolean> {
    // Implement custom authorization checks
    switch (checkName) {
      case 'compliance_framework':
        // Check if user's tenant supports required compliance framework
        return true; // Mock implementation
      case 'data_classification':
        // Check data classification access
        return this.validateSecurityClearance(user.securityClearance, checkValue);
      default:
        return true;
    }
  }

  private async logAuthenticationEvent(user: TenantUser, event: string, details: any): Promise<void> {
    // In production, write to audit log system
    console.log(`Auth event: ${event} for user ${user.email} in tenant ${user.tenantId}`, details);
  }

  private async logAuthorizationEvent(user: TenantUser, event: string, details: any): Promise<void> {
    // In production, write to audit log system
    console.log(`Authz event: ${event} for user ${user.email}`, details);
  }

  private async logSecurityViolation(user: TenantUser, violation: string, details: any): Promise<void> {
    // In production, trigger security alerts
    console.warn(`Security violation: ${violation} by user ${user.email}`, details);
  }
}

// Export singleton instance
export const tenantAuthService = new TenantAuthService();

// Middleware integration function
export async function withTenantAuth(request: NextRequest, handler: Function) {
  const sessionToken = request.headers.get('Authorization')?.replace('Bearer ', '');
  
  if (!sessionToken) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const user = await tenantAuthService.validateSession(sessionToken);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Invalid or expired session' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Add user to request context
  (request as any).user = user;
  return handler(request);
}