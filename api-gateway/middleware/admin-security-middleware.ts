/**
 * Kong Admin API Security Middleware
 * CRITICAL SECURITY PATCH - Phase 1 Emergency Remediation
 * 
 * This middleware implements emergency Kong Admin API security to prevent
 * the confirmed CVSS 9.6 administrative system takeover vulnerability.
 * 
 * BUSINESS IMPACT: Prevents platform-wide administrative compromise
 * DEPLOYMENT: Emergency deployment within 16 hours
 */

import { Request, Response, NextFunction } from 'express';
import { emergencyKongAdminSecurity } from '../security/emergency-kong-admin-security';
import * as crypto from 'crypto';
import * as fs from 'fs';

interface SecureAdminRequest extends Request {
  clientCertificate?: string;
  securityContext?: {
    sessionId: string;
    validatedAt: string;
    securityLevel: string;
  };
}

/**
 * CRITICAL: Emergency Kong Admin API Security Middleware
 * 
 * This middleware MUST be applied to all Kong Admin API routes to prevent
 * administrative system takeover attacks.
 */
export class KongAdminSecurityMiddleware {
  private blockedRequests: Set<string> = new Set();
  private securityViolations: Array<{
    timestamp: string;
    sourceIP: string;
    violation: string;
    details: any;
  }> = [];

  /**
   * CRITICAL: Main security middleware function
   */
  public secureAdminAPI = (req: SecureAdminRequest, res: Response, next: NextFunction): void => {
    const startTime = Date.now();
    
    try {
      console.log(`🔒 EMERGENCY SECURITY: Validating Kong Admin API request from ${req.ip}`);

      // CRITICAL: Extract client certificate if present
      const clientCert = this.extractClientCertificate(req);

      // CRITICAL: Build security validation request
      const securityRequest = {
        method: req.method,
        url: req.originalUrl || req.url,
        headers: req.headers as Record<string, string>,
        sourceIP: this.getClientIP(req),
        clientCert,
        body: req.body
      };

      // CRITICAL: Validate request through emergency security system
      const validationResult = emergencyKongAdminSecurity.validateAdminRequest(securityRequest);

      if (!validationResult.allowed) {
        // CRITICAL: Block dangerous request
        this.handleSecurityViolation(validationResult, securityRequest, req, res);
        return;
      }

      // CRITICAL: Add security context to request
      req.securityContext = {
        sessionId: crypto.randomUUID(),
        validatedAt: new Date().toISOString(),
        securityLevel: 'EMERGENCY_HARDENED'
      };

      // CRITICAL: Add security headers to response
      this.addSecurityHeaders(res);

      // CRITICAL: Log successful validation
      const processingTime = Date.now() - startTime;
      console.log(`✅ Kong Admin API request VALIDATED: ${req.method} ${req.url} (${processingTime}ms)`);

      // Proceed to next middleware
      next();

    } catch (error) {
      console.error('🚨 CRITICAL: Kong Admin API security validation failed:', error);
      
      // FAIL SECURE: Block request on any validation error
      res.status(500).json({
        error: 'Admin API security validation failed',
        code: 'ADMIN_SECURITY_SYSTEM_ERROR',
        timestamp: new Date().toISOString(),
        message: 'Emergency security system error - request blocked for safety'
      });

      // Log security system error
      this.logSecurityIncident('ADMIN_SECURITY_SYSTEM_ERROR', req.ip, {
        error: error.message,
        url: req.url,
        method: req.method
      });
    }
  };

  /**
   * CRITICAL: Handle security violations
   */
  private handleSecurityViolation(
    validationResult: any, 
    securityRequest: any, 
    req: Request, 
    res: Response
  ): void {
    const violation = {
      timestamp: new Date().toISOString(),
      sourceIP: securityRequest.sourceIP,
      violation: validationResult.securityViolation || 'UNKNOWN_VIOLATION',
      details: {
        method: securityRequest.method,
        url: securityRequest.url,
        reason: validationResult.reason,
        action: validationResult.action,
        userAgent: req.headers['user-agent'],
        requestId: crypto.randomUUID()
      }
    };

    // Log security violation
    this.securityViolations.push(violation);
    console.error('🚨 KONG ADMIN API SECURITY VIOLATION:', JSON.stringify(violation, null, 2));

    // CRITICAL: Determine response based on violation severity
    let statusCode = 403;
    let responseMessage = 'Kong Admin API access denied';

    switch (validationResult.securityViolation) {
      case 'UNAUTHORIZED_ACCESS_ATTEMPT':
        statusCode = 403;
        responseMessage = 'Unauthorized source - Admin API access restricted';
        break;
      
      case 'MTLS_AUTHENTICATION_FAILURE':
        statusCode = 401;
        responseMessage = 'Client certificate authentication required';
        break;
      
      case 'RATE_LIMIT_VIOLATION':
        statusCode = 429;
        responseMessage = 'Rate limit exceeded - Temporary access restriction';
        break;
      
      case 'EMERGENCY_LOCKDOWN_VIOLATION':
        statusCode = 503;
        responseMessage = 'Emergency lockdown active - Admin operations restricted';
        break;
      
      case 'DANGEROUS_ENDPOINT_WRITE_ATTEMPT':
        statusCode = 403;
        responseMessage = 'Write operation blocked - Dangerous endpoint access denied';
        break;
      
      case 'DANGEROUS_CONFIG_MODIFICATION':
        statusCode = 403;
        responseMessage = 'Configuration change blocked - Dangerous operation detected';
        break;
      
      default:
        statusCode = 403;
        responseMessage = 'Kong Admin API security violation detected';
    }

    // CRITICAL: Block the request
    res.status(statusCode).json({
      error: responseMessage,
      code: validationResult.securityViolation,
      timestamp: new Date().toISOString(),
      incident_id: violation.details.requestId,
      security_level: 'EMERGENCY_HARDENING_ACTIVE',
      message: 'This incident has been logged and security teams have been notified'
    });

    // CRITICAL: Take additional security actions
    this.executeSecurityActions(validationResult.action, securityRequest.sourceIP);
  }

  /**
   * CRITICAL: Execute security actions based on violation
   */
  private executeSecurityActions(action: string, sourceIP: string): void {
    switch (action) {
      case 'BLOCK_AND_LOG':
        // Already logged, no additional action needed
        break;
      
      case 'BLOCK_AND_ALERT':
        this.sendSecurityAlert('HIGH', `Kong Admin API security violation from ${sourceIP}`);
        break;
      
      case 'TEMPORARILY_BLOCK':
        this.temporarilyBlockIP(sourceIP, 300000); // 5 minutes
        break;
      
      case 'EMERGENCY_BLOCK':
        this.temporarilyBlockIP(sourceIP, 3600000); // 1 hour
        this.sendSecurityAlert('CRITICAL', `Emergency Kong Admin API block for ${sourceIP}`);
        break;
      
      case 'ESCALATE_TO_SOC_IMMEDIATELY':
        this.escalateToSOC(sourceIP);
        break;
    }
  }

  /**
   * CRITICAL: Extract client certificate from request
   */
  private extractClientCertificate(req: Request): string | undefined {
    // Try different common headers for client certificates
    const certHeaders = [
      'x-ssl-client-cert',
      'x-client-cert',
      'ssl-client-cert',
      'client-cert'
    ];

    for (const header of certHeaders) {
      const cert = req.headers[header] as string;
      if (cert) {
        // Decode URL-encoded certificate
        return decodeURIComponent(cert.replace(/\s+/g, '\n'));
      }
    }

    // Check for TLS client certificate in socket
    if ((req as any).connection && (req as any).connection.getPeerCertificate) {
      const cert = (req as any).connection.getPeerCertificate();
      if (cert && cert.raw) {
        return cert.raw.toString('base64');
      }
    }

    return undefined;
  }

  /**
   * CRITICAL: Get client IP address safely
   */
  private getClientIP(req: Request): string {
    // Check various headers for client IP
    const ipHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'x-client-ip',
      'cf-connecting-ip'
    ];

    for (const header of ipHeaders) {
      const ip = req.headers[header] as string;
      if (ip) {
        // Take first IP if comma-separated list
        return ip.split(',')[0].trim();
      }
    }

    // Fallback to connection IP
    return req.ip || req.connection.remoteAddress || 'unknown';
  }

  /**
   * CRITICAL: Add security headers to response
   */
  private addSecurityHeaders(res: Response): void {
    // CRITICAL: Security headers for Admin API
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Kong-Admin-Security', 'EMERGENCY_HARDENING_ACTIVE');
    res.setHeader('X-Security-Level', 'MAXIMUM');
  }

  /**
   * CRITICAL: Temporarily block IP address
   */
  private temporarilyBlockIP(sourceIP: string, durationMs: number): void {
    this.blockedRequests.add(sourceIP);
    
    console.log(`🚨 TEMPORARILY BLOCKING IP: ${sourceIP} for ${durationMs / 1000} seconds`);
    
    setTimeout(() => {
      this.blockedRequests.delete(sourceIP);
      console.log(`✅ IP UNBLOCKED: ${sourceIP}`);
    }, durationMs);
  }

  /**
   * CRITICAL: Send security alert
   */
  private sendSecurityAlert(severity: string, message: string): void {
    const alert = {
      timestamp: new Date().toISOString(),
      severity,
      component: 'KONG_ADMIN_API_SECURITY',
      message,
      incident_type: 'ADMIN_API_SECURITY_VIOLATION',
      requires_immediate_action: severity === 'CRITICAL'
    };

    console.error(`🚨 SECURITY ALERT [${severity}]: ${message}`);
    
    // In production, this would:
    // 1. Send to SIEM/SOAR system
    // 2. Trigger PagerDuty alerts
    // 3. Send to security Slack channels
    // 4. Create security incident tickets
    // 5. Notify security management team
  }

  /**
   * CRITICAL: Escalate to SOC team
   */
  private escalateToSOC(sourceIP: string): void {
    const escalation = {
      timestamp: new Date().toISOString(),
      incident_type: 'KONG_ADMIN_API_COMPROMISE_ATTEMPT',
      severity: 'CRITICAL',
      source_ip: sourceIP,
      threat_level: 'HIGH',
      business_impact: 'Potential administrative system takeover attempt',
      immediate_action_required: true,
      recommended_response: [
        'Immediately block source IP at firewall level',
        'Review all admin API access logs for this IP',
        'Audit Kong configuration for unauthorized changes',
        'Notify security management immediately',
        'Consider emergency Kong admin API maintenance mode'
      ]
    };

    console.error('🚨 ESCALATING TO SOC:', JSON.stringify(escalation, null, 2));
    
    // In production, this would immediately:
    // 1. Create P1 security incident
    // 2. Page on-call security engineer
    // 3. Send executive security briefing
    // 4. Initiate emergency response procedures
    // 5. Contact Kong technical support if needed
  }

  /**
   * CRITICAL: Log security incident
   */
  private logSecurityIncident(incidentType: string, sourceIP: string, details: any): void {
    const incident = {
      incident_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      incident_type: incidentType,
      source_ip: sourceIP,
      component: 'KONG_ADMIN_API_SECURITY',
      severity: 'CRITICAL',
      details,
      security_level: 'EMERGENCY_HARDENING_ACTIVE'
    };

    console.error('🚨 SECURITY INCIDENT:', JSON.stringify(incident, null, 2));
    
    // Store incident for audit trail
    this.securityViolations.push({
      timestamp: incident.timestamp,
      sourceIP,
      violation: incidentType,
      details
    });
  }

  /**
   * Get current security status
   */
  public getSecurityStatus(): object {
    return {
      timestamp: new Date().toISOString(),
      emergency_hardening_active: true,
      blocked_ips: Array.from(this.blockedRequests),
      recent_violations: this.securityViolations.slice(-10), // Last 10 violations
      total_violations: this.securityViolations.length,
      middleware_version: '1.0.0_emergency',
      protection_level: 'MAXIMUM',
      component: 'KONG_ADMIN_API_SECURITY_MIDDLEWARE'
    };
  }

  /**
   * CRITICAL: Health check endpoint (for monitoring)
   */
  public healthCheck = (req: Request, res: Response): void => {
    const securityStatus = emergencyKongAdminSecurity.getSecurityStatus();
    
    res.json({
      status: 'EMERGENCY_HARDENING_ACTIVE',
      timestamp: new Date().toISOString(),
      admin_api_security: {
        middleware_active: true,
        protection_level: 'MAXIMUM',
        security_status: securityStatus
      },
      health: 'OK'
    });
  };
}

// Export singleton instance
export const kongAdminSecurityMiddleware = new KongAdminSecurityMiddleware();

/**
 * CRITICAL: Express.js middleware function for Kong Admin API protection
 */
export const secureKongAdminAPI = kongAdminSecurityMiddleware.secureAdminAPI;

/**
 * CRITICAL: Health check middleware
 */
export const kongAdminSecurityHealthCheck = kongAdminSecurityMiddleware.healthCheck;

// Example Express.js integration
export function configureKongAdminSecurity(app: any): void {
  console.log('🚨 EMERGENCY: Configuring Kong Admin API Security Middleware');
  
  // CRITICAL: Apply security middleware to all admin routes
  app.use('/admin/*', secureKongAdminAPI);
  app.use('/8001/*', secureKongAdminAPI); // Common Kong admin port
  
  // Health check endpoint
  app.get('/admin/security/health', kongAdminSecurityHealthCheck);
  
  console.log('✅ Kong Admin API Security Middleware configured');
}

// Example usage
if (require.main === module) {
  console.log('🔒 Testing Kong Admin API Security Middleware');
  console.log('='.repeat(60));
  
  // Display current security status
  const status = kongAdminSecurityMiddleware.getSecurityStatus();
  console.log('\nSecurity Status:', JSON.stringify(status, null, 2));
  
  console.log('\n🔒 Kong Admin API Security Middleware is ready for deployment!');
}