/**
 * Emergency Multi-Tenant Security Validation Middleware
 * CRITICAL SECURITY PATCH - Phase 1 Emergency Remediation
 * 
 * This module implements immediate security fixes for the confirmed
 * multi-tenant boundary bypass vulnerability (CVSS 9.8) identified
 * during penetration testing.
 * 
 * BUSINESS IMPACT: Prevents $15M-$45M potential breach cost
 * DEPLOYMENT: Emergency deployment within 8 hours
 */

import { NextRequest, NextResponse } from 'next/server';
import { createHash, createHmac } from 'crypto';
import { z } from 'zod';

/**
 * Security violation logging for immediate threat detection
 */
interface SecurityViolation {
  violationType: 'CROSS_TENANT_ACCESS_ATTEMPT' | 'TENANT_MANIPULATION' | 'UNAUTHORIZED_ACCESS' | 'SUSPICIOUS_PATTERN';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  userTenant: string;
  resourceTenant?: string;
  endpoint: string;
  ipAddress: string;
  userAgent: string;
  timestamp: string;
  evidence: Record<string, any>;
  businessImpact: string;
  actionRequired: string;
}

/**
 * Tenant validation result with security context
 */
interface TenantValidationResult {
  valid: boolean;
  userTenantId: string;
  resourceTenantId?: string;
  securityContext: {
    isCrossTenantAccess: boolean;
    isAuthorized: boolean;
    securityViolation?: SecurityViolation;
    requiredAction?: 'BLOCK' | 'AUDIT' | 'ESCALATE' | 'MONITOR';
  };
}

/**
 * EMERGENCY: Multi-Tenant Boundary Security Enforcement
 * 
 * This class implements immediate security controls to prevent the confirmed
 * cross-tenant data access vulnerability that allows attackers to access
 * 508,000+ customer records across all 127 tenants.
 */
export class EmergencyTenantValidationMiddleware {
  private readonly HMAC_SECRET: string;
  private readonly SECURITY_ALERT_WEBHOOK: string;
  private readonly violationStore = new Map<string, SecurityViolation[]>();
  private readonly suspiciousPatterns = new Set<string>();

  constructor() {
    // In production, these would come from secure environment variables
    this.HMAC_SECRET = process.env.TENANT_SECURITY_HMAC_SECRET || 'emergency-security-key';
    this.SECURITY_ALERT_WEBHOOK = process.env.SECURITY_ALERT_WEBHOOK || '';
    
    // Initialize suspicious pattern detection
    this.initializeThreatPatterns();
  }

  /**
   * CRITICAL: Primary tenant boundary validation
   * This is the main security checkpoint that MUST validate every request
   */
  async validateTenantAccess(request: NextRequest): Promise<TenantValidationResult> {
    const startTime = Date.now();
    
    try {
      // Extract security context from request
      const userTenant = this.extractUserTenant(request.headers.get('authorization'));
      const resourceTenant = this.extractResourceTenant(request.nextUrl.pathname, await this.safeParseRequestBody(request));
      const ipAddress = this.getClientIP(request);
      const userAgent = request.headers.get('user-agent') || '';
      const endpoint = request.nextUrl.pathname;

      // CRITICAL: Validate tenant identifiers
      if (!userTenant || !this.isValidTenantId(userTenant)) {
        await this.logSecurityViolation({
          violationType: 'TENANT_MANIPULATION',
          severity: 'CRITICAL',
          userTenant: userTenant || 'INVALID',
          endpoint,
          ipAddress,
          userAgent,
          timestamp: new Date().toISOString(),
          evidence: { 
            invalidTenantId: userTenant,
            authorizationHeader: this.maskSensitiveData(request.headers.get('authorization'))
          },
          businessImpact: 'Potential tenant boundary manipulation attempt',
          actionRequired: 'BLOCK_IMMEDIATELY'
        });

        return {
          valid: false,
          userTenantId: userTenant || 'INVALID',
          securityContext: {
            isCrossTenantAccess: false,
            isAuthorized: false,
            requiredAction: 'BLOCK'
          }
        };
      }

      // CRITICAL: Cross-tenant access detection
      if (resourceTenant && resourceTenant !== userTenant) {
        return await this.handleCrossTenantAccess(userTenant, resourceTenant, request, {
          endpoint,
          ipAddress,
          userAgent,
          timestamp: new Date().toISOString()
        });
      }

      // CRITICAL: Check for wildcard tenant exploitation
      if (this.isWildcardTenantAttempt(userTenant, request)) {
        await this.logSecurityViolation({
          violationType: 'TENANT_MANIPULATION',
          severity: 'CRITICAL',
          userTenant,
          endpoint,
          ipAddress,
          userAgent,
          timestamp: new Date().toISOString(),
          evidence: { 
            wildcardAttempt: true,
            suspiciousHeaders: this.extractSuspiciousHeaders(request)
          },
          businessImpact: 'Wildcard tenant bypass attempt - could access all tenant data',
          actionRequired: 'BLOCK_AND_ESCALATE'
        });

        return {
          valid: false,
          userTenantId: userTenant,
          securityContext: {
            isCrossTenantAccess: false,
            isAuthorized: false,
            requiredAction: 'BLOCK'
          }
        };
      }

      // CRITICAL: Pattern-based attack detection
      if (await this.detectSuspiciousPatterns(userTenant, request, { ipAddress, userAgent, endpoint })) {
        return {
          valid: false,
          userTenantId: userTenant,
          securityContext: {
            isCrossTenantAccess: false,
            isAuthorized: false,
            requiredAction: 'BLOCK'
          }
        };
      }

      // Log successful validation for audit trail
      await this.logSecurityEvent('TENANT_ACCESS_VALIDATED', {
        userTenant,
        resourceTenant,
        endpoint,
        ipAddress,
        processingTimeMs: Date.now() - startTime
      });

      return {
        valid: true,
        userTenantId: userTenant,
        resourceTenantId: resourceTenant,
        securityContext: {
          isCrossTenantAccess: false,
          isAuthorized: true,
          requiredAction: 'MONITOR'
        }
      };

    } catch (error) {
      console.error('Emergency tenant validation error:', error);
      
      // FAIL SECURE: Block access on any validation error
      await this.logSecurityViolation({
        violationType: 'UNAUTHORIZED_ACCESS',
        severity: 'HIGH',
        userTenant: 'UNKNOWN',
        endpoint: request.nextUrl.pathname,
        ipAddress: this.getClientIP(request),
        userAgent: request.headers.get('user-agent') || '',
        timestamp: new Date().toISOString(),
        evidence: { 
          error: error.message,
          stackTrace: error.stack
        },
        businessImpact: 'Tenant validation system failure - potential security bypass',
        actionRequired: 'ESCALATE_TO_SOC'
      });

      return {
        valid: false,
        userTenantId: 'ERROR',
        securityContext: {
          isCrossTenantAccess: false,
          isAuthorized: false,
          requiredAction: 'BLOCK'
        }
      };
    }
  }

  /**
   * CRITICAL: Cross-tenant access validation
   * Implements strict controls to prevent the confirmed vulnerability
   */
  private async handleCrossTenantAccess(
    userTenant: string, 
    resourceTenant: string, 
    request: NextRequest,
    context: { endpoint: string; ipAddress: string; userAgent: string; timestamp: string }
  ): Promise<TenantValidationResult> {
    
    // IMMEDIATE BLOCK: No cross-tenant access allowed in emergency mode
    // This is the critical fix for the CVSS 9.8 vulnerability
    await this.logSecurityViolation({
      violationType: 'CROSS_TENANT_ACCESS_ATTEMPT',
      severity: 'CRITICAL',
      userTenant,
      resourceTenant,
      endpoint: context.endpoint,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: context.timestamp,
      evidence: { 
        userTenantId: userTenant,
        resourceTenantId: resourceTenant,
        requestPath: context.endpoint,
        requestMethod: request.method,
        requestHeaders: this.sanitizeHeaders(request),
        sessionData: this.extractSessionData(request)
      },
      businessImpact: 'CRITICAL: Cross-tenant boundary violation - potential data breach of 500K+ records',
      actionRequired: 'IMMEDIATE_BLOCK_AND_SOC_ALERT'
    });

    // Trigger immediate security response
    await this.triggerSecurityIncident('CROSS_TENANT_BREACH_ATTEMPT', {
      severity: 'CRITICAL',
      userTenant,
      resourceTenant,
      ipAddress: context.ipAddress,
      timestamp: context.timestamp,
      potentialImpact: 'Multi-tenant data breach',
      immediateAction: 'ACCESS_BLOCKED'
    });

    return {
      valid: false,
      userTenantId: userTenant,
      resourceTenantId: resourceTenant,
      securityContext: {
        isCrossTenantAccess: true,
        isAuthorized: false,
        requiredAction: 'BLOCK'
      }
    };
  }

  /**
   * Extract user tenant ID from JWT token with strict validation
   */
  private extractUserTenant(authorizationHeader: string | null): string | null {
    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
      return null;
    }

    try {
      const token = authorizationHeader.substring(7);
      
      // Basic JWT structure validation
      const tokenParts = token.split('.');
      if (tokenParts.length !== 3) {
        return null;
      }

      // Decode payload (we're not verifying signature here - that's handled separately)
      const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64url').toString());
      
      // Extract tenant ID with strict validation
      const tenantId = payload.tenant_id || payload.tenantId || payload.tid;
      
      // CRITICAL: Prevent wildcard tenant exploitation
      if (!tenantId || tenantId === '*' || tenantId.includes('*') || tenantId.includes('%')) {
        return null;
      }

      return tenantId;
    } catch (error) {
      console.error('Failed to extract user tenant from JWT:', error);
      return null;
    }
  }

  /**
   * Extract resource tenant ID from request path and body
   */
  private extractResourceTenant(pathname: string, requestBody: any): string | null {
    // Extract from URL path patterns
    const pathPatterns = [
      /\/api\/tenants\/([^\/]+)/,
      /\/api\/tenant\/([^\/]+)/,
      /\/tenants\/([^\/]+)/,
      /\/t\/([^\/]+)/,
    ];

    for (const pattern of pathPatterns) {
      const match = pathname.match(pattern);
      if (match && match[1] !== 'current' && this.isValidTenantId(match[1])) {
        return match[1];
      }
    }

    // Extract from request body
    if (requestBody && typeof requestBody === 'object') {
      const tenantFields = ['tenant_id', 'tenantId', 'tenant', 'tid'];
      for (const field of tenantFields) {
        if (requestBody[field] && this.isValidTenantId(requestBody[field])) {
          return requestBody[field];
        }
      }
    }

    return null;
  }

  /**
   * Validate tenant ID format to prevent injection attacks
   */
  private isValidTenantId(tenantId: string): boolean {
    if (!tenantId || typeof tenantId !== 'string') {
      return false;
    }

    // Strict UUID v4 validation
    const uuidV4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    
    // Allow UUID format or alphanumeric with hyphens (legacy format)
    const legacyFormatRegex = /^[a-z0-9][a-z0-9\-]{2,63}$/i;
    
    return uuidV4Regex.test(tenantId) || legacyFormatRegex.test(tenantId);
  }

  /**
   * Detect wildcard tenant exploitation attempts
   */
  private isWildcardTenantAttempt(tenantId: string, request: NextRequest): boolean {
    // Check for obvious wildcard patterns
    const wildcardPatterns = ['*', '%', 'all', 'ANY', 'wildcard', '.*', '%25', '%2A'];
    
    if (wildcardPatterns.some(pattern => tenantId.includes(pattern))) {
      return true;
    }

    // Check for SQL injection patterns in tenant context
    const sqlPatterns = ['OR ', 'UNION ', 'SELECT ', 'DROP ', 'UPDATE ', 'DELETE ', '--', '/*'];
    const tenantContext = JSON.stringify({
      tenantId,
      path: request.nextUrl.pathname,
      headers: Object.fromEntries(request.headers.entries())
    }).toUpperCase();

    return sqlPatterns.some(pattern => tenantContext.includes(pattern));
  }

  /**
   * Detect suspicious attack patterns
   */
  private async detectSuspiciousPatterns(
    tenantId: string, 
    request: NextRequest, 
    context: { ipAddress: string; userAgent: string; endpoint: string }
  ): Promise<boolean> {
    const signature = this.generateRequestSignature(tenantId, context);
    
    // Check if this pattern has been flagged as suspicious
    if (this.suspiciousPatterns.has(signature)) {
      await this.logSecurityViolation({
        violationType: 'SUSPICIOUS_PATTERN',
        severity: 'HIGH',
        userTenant: tenantId,
        endpoint: context.endpoint,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date().toISOString(),
        evidence: { 
          patternSignature: signature,
          previousDetections: true
        },
        businessImpact: 'Repeated suspicious access pattern detected',
        actionRequired: 'BLOCK_AND_MONITOR'
      });
      return true;
    }

    // Check for rapid tenant switching (potential enumeration attack)
    const recentViolations = this.violationStore.get(context.ipAddress) || [];
    const recentCrossTenantAttempts = recentViolations.filter(
      v => v.violationType === 'CROSS_TENANT_ACCESS_ATTEMPT' && 
           Date.now() - new Date(v.timestamp).getTime() < 300000 // 5 minutes
    );

    if (recentCrossTenantAttempts.length >= 3) {
      this.suspiciousPatterns.add(signature);
      await this.logSecurityViolation({
        violationType: 'SUSPICIOUS_PATTERN',
        severity: 'CRITICAL',
        userTenant: tenantId,
        endpoint: context.endpoint,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date().toISOString(),
        evidence: { 
          rapidTenantSwitching: true,
          attemptCount: recentCrossTenantAttempts.length,
          timeWindow: '5 minutes'
        },
        businessImpact: 'Potential tenant enumeration attack - rapid cross-tenant access attempts',
        actionRequired: 'IMMEDIATE_BLOCK_IP'
      });
      return true;
    }

    return false;
  }

  /**
   * Generate request signature for pattern detection
   */
  private generateRequestSignature(tenantId: string, context: { ipAddress: string; userAgent: string; endpoint: string }): string {
    const data = `${tenantId}:${context.ipAddress}:${context.userAgent}:${context.endpoint}`;
    return createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  /**
   * Initialize threat detection patterns
   */
  private initializeThreatPatterns(): void {
    // Load known attack patterns from security intelligence feeds
    // In production, this would come from threat intelligence database
    const knownAttackPatterns = [
      'cross-tenant-enum',
      'wildcard-exploit',
      'jwt-manipulation',
      'tenant-injection'
    ];

    knownAttackPatterns.forEach(pattern => {
      this.suspiciousPatterns.add(pattern);
    });
  }

  /**
   * CRITICAL: Log security violations for immediate response
   */
  private async logSecurityViolation(violation: SecurityViolation): Promise<void> {
    // Store violation for pattern analysis
    const ipViolations = this.violationStore.get(violation.ipAddress) || [];
    ipViolations.push(violation);
    this.violationStore.set(violation.ipAddress, ipViolations);

    // Log to console for immediate visibility
    console.error('🚨 CRITICAL SECURITY VIOLATION:', {
      type: violation.violationType,
      severity: violation.severity,
      tenant: violation.userTenant,
      impact: violation.businessImpact,
      action: violation.actionRequired,
      timestamp: violation.timestamp,
      evidence: violation.evidence
    });

    // In production, this would:
    // 1. Send to SIEM system immediately
    // 2. Trigger PagerDuty/Slack alerts
    // 3. Update security dashboard
    // 4. Store in immutable audit log
    
    // Trigger immediate security response for critical violations
    if (violation.severity === 'CRITICAL') {
      await this.triggerSecurityIncident(violation.violationType, {
        severity: violation.severity,
        userTenant: violation.userTenant,
        resourceTenant: violation.resourceTenant,
        ipAddress: violation.ipAddress,
        evidence: violation.evidence,
        businessImpact: violation.businessImpact,
        actionRequired: violation.actionRequired
      });
    }
  }

  /**
   * Log security events for audit trail
   */
  private async logSecurityEvent(eventType: string, details: Record<string, any>): Promise<void> {
    // In production, write to audit log system
    console.log(`Security event: ${eventType}`, {
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  /**
   * Trigger security incident response
   */
  private async triggerSecurityIncident(incidentType: string, details: Record<string, any>): Promise<void> {
    console.error('🚨🚨🚨 SECURITY INCIDENT TRIGGERED:', {
      incident: incidentType,
      timestamp: new Date().toISOString(),
      ...details
    });

    // In production, this would:
    // 1. Create incident in security platform
    // 2. Send to SOC team immediately
    // 3. Execute automated containment
    // 4. Update threat intelligence feeds
  }

  /**
   * Utility functions
   */
  private getClientIP(request: NextRequest): string {
    return request.headers.get('cf-connecting-ip') ||
           request.headers.get('x-real-ip') ||
           request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
           request.ip ||
           '0.0.0.0';
  }

  private async safeParseRequestBody(request: NextRequest): Promise<any> {
    try {
      if (request.headers.get('content-type')?.includes('application/json')) {
        return await request.clone().json();
      }
    } catch (error) {
      // Ignore parsing errors
    }
    return null;
  }

  private maskSensitiveData(data: string | null): string {
    if (!data) return 'null';
    return data.length > 10 ? data.substring(0, 10) + '***[REDACTED]' : '***[REDACTED]';
  }

  private extractSuspiciousHeaders(request: NextRequest): Record<string, string> {
    const suspiciousHeaders: Record<string, string> = {};
    const headerNames = ['x-tenant-id', 'x-forwarded-tenant', 'x-override-tenant', 'x-tenant-bypass'];
    
    headerNames.forEach(name => {
      const value = request.headers.get(name);
      if (value) {
        suspiciousHeaders[name] = this.maskSensitiveData(value);
      }
    });
    
    return suspiciousHeaders;
  }

  private sanitizeHeaders(request: NextRequest): Record<string, string> {
    const headers: Record<string, string> = {};
    const allowedHeaders = ['user-agent', 'content-type', 'accept', 'x-forwarded-for', 'x-real-ip'];
    
    allowedHeaders.forEach(name => {
      const value = request.headers.get(name);
      if (value) {
        headers[name] = name.includes('agent') ? this.maskSensitiveData(value) : value;
      }
    });
    
    return headers;
  }

  private extractSessionData(request: NextRequest): Record<string, any> {
    return {
      sessionId: this.maskSensitiveData(request.headers.get('x-session-id')),
      requestId: this.maskSensitiveData(request.headers.get('x-request-id')),
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Export singleton instance for use across the application
 */
export const emergencyTenantValidator = new EmergencyTenantValidationMiddleware();

/**
 * Next.js middleware integration function
 */
export async function withEmergencyTenantValidation(
  request: NextRequest,
  handler: (request: NextRequest) => Promise<NextResponse>
): Promise<NextResponse> {
  const validationResult = await emergencyTenantValidator.validateTenantAccess(request);
  
  if (!validationResult.valid || validationResult.securityContext.requiredAction === 'BLOCK') {
    return NextResponse.json(
      {
        error: 'Access denied',
        code: 'TENANT_ACCESS_VIOLATION',
        message: 'Cross-tenant access detected and blocked',
        timestamp: new Date().toISOString(),
        requestId: crypto.randomUUID()
      },
      { 
        status: 403,
        headers: {
          'X-Security-Violation': 'TENANT_BOUNDARY_VIOLATION',
          'X-Block-Reason': validationResult.securityContext.requiredAction || 'SECURITY_POLICY'
        }
      }
    );
  }

  // Add security headers to response
  const response = await handler(request);
  response.headers.set('X-Tenant-Validation', 'EMERGENCY_SECURITY_MODE');
  response.headers.set('X-Tenant-ID', validationResult.userTenantId);
  response.headers.set('X-Security-Level', 'CRITICAL_PROTECTION');
  
  return response;
}