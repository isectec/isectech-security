/**
 * Example Integration: Custom Business Rule Validators with Next.js Middleware
 * Demonstrates how to integrate the validation system into a Next.js application
 * 
 * Task: 83.5 - Integration example for business rule validators
 */

import { NextRequest, NextResponse } from 'next/server';
import { 
  createValidationPipeline,
  requiresValidation,
  validateSecurityConfiguration,
  type EnhancedValidationConfig,
  type BusinessRuleConfig
} from './index';

/**
 * Example 1: Basic Integration
 * Simple setup with default configuration
 */
export function createBasicValidationMiddleware() {
  // Create validation pipeline with default settings
  const validationPipeline = createValidationPipeline();

  return async function middleware(request: NextRequest) {
    const pathname = request.nextUrl.pathname;
    const method = request.method;

    // Skip validation for static assets and health checks
    if (!requiresValidation(pathname, method)) {
      return NextResponse.next();
    }

    // Perform validation
    const validationResult = await validationPipeline.validateRequest(request);
    
    if (validationResult) {
      // Validation failed - return error response
      return validationResult;
    }

    // Validation passed - continue to next middleware/handler
    return NextResponse.next();
  };
}

/**
 * Example 2: Custom Configuration
 * Advanced setup with custom business rules and validation settings
 */
export function createAdvancedValidationMiddleware() {
  // Custom business rule configuration
  const businessRuleConfig: Partial<BusinessRuleConfig> = {
    transactionLimits: {
      enabled: true,
      tiers: {
        // Custom tier limits for this environment
        startup: {
          dailyLimit: 50,
          hourlyLimit: 10,
          transactionValueLimit: 500,
          aggregateMonthlyLimit: 10000
        },
        growth: {
          dailyLimit: 200,
          hourlyLimit: 50,
          transactionValueLimit: 5000,
          aggregateMonthlyLimit: 100000
        },
        enterprise: {
          dailyLimit: 1000,
          hourlyLimit: 200,
          transactionValueLimit: 50000,
          aggregateMonthlyLimit: 1000000,
          requiresApprovalThreshold: 10000
        }
      }
    },
    
    timeBasedAccess: {
      enabled: true,
      rules: [
        // High-value transactions restricted to business hours
        {
          endpoint: '/api/v1/payments/process',
          method: 'POST',
          allowedDays: [1, 2, 3, 4, 5], // Monday-Friday
          allowedHours: { start: 8, end: 18 }, // 8 AM - 6 PM
          timezone: 'America/New_York',
          emergencyOverride: true
        },
        // System maintenance only allowed during off-hours
        {
          endpoint: '/api/v1/admin/maintenance',
          method: 'POST',
          allowedDays: [0, 6], // Weekends only
          allowedHours: { start: 20, end: 6 }, // 8 PM - 6 AM
          timezone: 'UTC',
          emergencyOverride: false
        }
      ]
    },

    security: {
      sensitiveEndpoints: [
        '/api/v1/admin/',
        '/api/v1/financial/',
        '/api/v1/security/',
        '/api/v1/audit/'
      ],
      threatDetection: {
        enabled: true,
        suspiciousPatterns: [
          {
            pattern: 'rapid_failed_validations',
            severity: 'high',
            action: 'block'
          },
          {
            pattern: 'unusual_access_pattern',
            severity: 'medium',
            action: 'warn'
          }
        ]
      }
    }
  };

  // Enhanced validation configuration
  const validationConfig: Partial<EnhancedValidationConfig> = {
    enableSchemaValidation: true,
    enableBusinessRuleValidation: true,
    failFast: false, // Run both validations even if one fails
    logViolations: true,
    returnDetailedErrors: process.env.NODE_ENV === 'development',
    maxValidationTimeMs: 5000 // 5 second timeout
  };

  // Create validation pipeline with custom configuration
  const validationPipeline = createValidationPipeline({
    businessRuleConfig,
    validationConfig
  });

  return async function middleware(request: NextRequest) {
    const pathname = request.nextUrl.pathname;
    const method = request.method;

    // Skip validation for exempt endpoints
    if (!requiresValidation(pathname, method)) {
      return NextResponse.next();
    }

    // Add custom headers for request tracing
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    try {
      // Perform validation with timeout
      const validationPromise = validationPipeline.validateRequest(request);
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Validation timeout')), 10000)
      );

      const validationResult = await Promise.race([validationPromise, timeoutPromise]);
      
      if (validationResult) {
        // Add request tracing to error response
        const response = NextResponse.json(
          {
            ...await validationResult.json(),
            request_id: requestId,
            timestamp: new Date().toISOString()
          },
          { status: validationResult.status }
        );

        // Add CORS headers if needed
        response.headers.set('Access-Control-Allow-Origin', '*');
        response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        
        return response;
      }

      // Validation passed - add success headers and continue
      const response = NextResponse.next();
      response.headers.set('X-Validation-Status', 'passed');
      response.headers.set('X-Request-ID', requestId);
      
      return response;

    } catch (error) {
      console.error('Validation middleware error:', error);
      
      // Return generic error response
      return NextResponse.json({
        success: false,
        error: 'validation_system_error',
        message: 'Validation system temporarily unavailable',
        request_id: requestId,
        timestamp: new Date().toISOString()
      }, { status: 503 });
    }
  };
}

/**
 * Example 3: Environment-Specific Configuration
 * Different validation rules for different environments
 */
export function createEnvironmentAwareMiddleware() {
  const environment = process.env.NODE_ENV || 'development';
  
  let businessRuleConfig: Partial<BusinessRuleConfig> = {};
  let validationConfig: Partial<EnhancedValidationConfig> = {};

  switch (environment) {
    case 'development':
      // Relaxed rules for development
      businessRuleConfig = {
        transactionLimits: {
          enabled: false // Disable for easier testing
        },
        timeBasedAccess: {
          enabled: false // Allow access anytime in dev
        },
        performance: {
          maxValidationTimeMs: 30000, // Longer timeout for debugging
          enableCaching: false // Disable caching for fresh results
        }
      };
      
      validationConfig = {
        enableSchemaValidation: true,
        enableBusinessRuleValidation: true,
        returnDetailedErrors: true,
        logViolations: true
      };
      break;

    case 'staging':
      // Production-like rules but with logging
      businessRuleConfig = {
        transactionLimits: {
          enabled: true,
          tiers: {
            // Lower limits for staging
            basic: {
              dailyLimit: 10,
              hourlyLimit: 5,
              transactionValueLimit: 100,
              aggregateMonthlyLimit: 1000
            }
          }
        },
        performance: {
          maxValidationTimeMs: 10000,
          enableCaching: true
        }
      };
      
      validationConfig = {
        enableSchemaValidation: true,
        enableBusinessRuleValidation: true,
        returnDetailedErrors: true,
        logViolations: true
      };
      break;

    case 'production':
      // Full production rules
      businessRuleConfig = {
        transactionLimits: { enabled: true },
        timeBasedAccess: { enabled: true },
        resourceConsistency: { enabled: true },
        workflowStates: { enabled: true },
        tenantDataIsolation: { enabled: true, strictMode: true },
        performance: {
          maxValidationTimeMs: 5000,
          enableCaching: true,
          enableMetrics: true
        },
        security: {
          threatDetection: { enabled: true },
          rateLimitingIntegration: { enabled: true }
        }
      };
      
      validationConfig = {
        enableSchemaValidation: true,
        enableBusinessRuleValidation: true,
        returnDetailedErrors: false, // Hide details in production
        logViolations: true,
        failFast: false
      };
      break;
  }

  const validationPipeline = createValidationPipeline({
    businessRuleConfig,
    validationConfig
  });

  return validationPipeline.createMiddlewareFunction();
}

/**
 * Example 4: Conditional Validation
 * Apply different validation rules based on request characteristics
 */
export function createConditionalValidationMiddleware() {
  const validationPipeline = createValidationPipeline();

  return async function middleware(request: NextRequest) {
    const pathname = request.nextUrl.pathname;
    const method = request.method;
    const userAgent = request.headers.get('user-agent') || '';

    // Skip validation for health checks
    if (pathname === '/health' || pathname === '/api/health') {
      return NextResponse.next();
    }

    // Skip validation for trusted internal services
    const internalApiKey = request.headers.get('x-internal-api-key');
    if (internalApiKey === process.env.INTERNAL_API_KEY) {
      const response = NextResponse.next();
      response.headers.set('X-Validation-Status', 'bypassed-internal');
      return response;
    }

    // Enhanced validation for mobile clients
    const isMobileClient = userAgent.includes('Mobile') || 
                          request.headers.get('x-client-type') === 'mobile';
    
    if (isMobileClient) {
      // Apply stricter validation for mobile clients
      // (mobile clients might have different security requirements)
      
      // Check for required mobile security headers
      const mobileDeviceId = request.headers.get('x-device-id');
      const mobileAppVersion = request.headers.get('x-app-version');
      
      if (!mobileDeviceId || !mobileAppVersion) {
        return NextResponse.json({
          success: false,
          error: 'mobile_security_headers_required',
          message: 'Mobile clients must provide device ID and app version',
          required_headers: ['x-device-id', 'x-app-version']
        }, { status: 400 });
      }
    }

    // Apply standard validation
    const validationResult = await validationPipeline.validateRequest(request);
    
    if (validationResult) {
      return validationResult;
    }

    // Add client-specific headers to successful responses
    const response = NextResponse.next();
    response.headers.set('X-Validation-Status', 'passed');
    response.headers.set('X-Client-Type', isMobileClient ? 'mobile' : 'web');
    
    return response;
  };
}

/**
 * Example 5: Health Check Integration
 * Middleware that includes validation health status
 */
export function createHealthAwareMiddleware() {
  const validationPipeline = createValidationPipeline();
  let lastHealthCheck: Date | null = null;
  let isHealthy = true;
  let healthCheckErrors: string[] = [];

  // Periodic health check (every 5 minutes)
  setInterval(async () => {
    try {
      const configValidation = validateSecurityConfiguration();
      lastHealthCheck = new Date();
      isHealthy = configValidation.isValid;
      healthCheckErrors = configValidation.errors;
      
      if (!isHealthy) {
        console.warn('Validation system health check failed:', configValidation.errors);
      }
    } catch (error) {
      isHealthy = false;
      healthCheckErrors = [`Health check failed: ${error}`];
      console.error('Validation health check error:', error);
    }
  }, 5 * 60 * 1000); // 5 minutes

  return async function middleware(request: NextRequest) {
    const pathname = request.nextUrl.pathname;

    // Special health endpoint that includes validation status
    if (pathname === '/api/health/validation') {
      return NextResponse.json({
        status: isHealthy ? 'healthy' : 'unhealthy',
        last_check: lastHealthCheck?.toISOString(),
        errors: healthCheckErrors,
        validation_pipeline: {
          schema_validation: 'enabled',
          business_rule_validation: 'enabled',
          performance_monitoring: 'enabled'
        }
      });
    }

    // Skip validation if system is unhealthy (fail open)
    if (!isHealthy && process.env.VALIDATION_FAIL_OPEN === 'true') {
      const response = NextResponse.next();
      response.headers.set('X-Validation-Status', 'bypassed-unhealthy');
      response.headers.set('X-Validation-Health', 'degraded');
      return response;
    }

    // Normal validation flow
    if (!requiresValidation(pathname, request.method)) {
      return NextResponse.next();
    }

    const validationResult = await validationPipeline.validateRequest(request);
    
    if (validationResult) {
      return validationResult;
    }

    const response = NextResponse.next();
    response.headers.set('X-Validation-Status', 'passed');
    response.headers.set('X-Validation-Health', isHealthy ? 'healthy' : 'degraded');
    
    return response;
  };
}

/**
 * Example Usage in Next.js middleware.ts file:
 */
/*
import { createAdvancedValidationMiddleware } from './api-gateway/security/middleware-integration-example';

// Create the validation middleware
const validationMiddleware = createAdvancedValidationMiddleware();

export async function middleware(request: NextRequest) {
  // Apply validation middleware
  return await validationMiddleware(request);
}

// Configure which routes the middleware runs on
export const config = {
  matcher: [
    '/api/:path*',        // All API routes
    '/((?!_next/static|_next/image|favicon.ico).*)', // All non-static routes
  ]
};
*/

export {
  createBasicValidationMiddleware,
  createAdvancedValidationMiddleware,
  createEnvironmentAwareMiddleware,
  createConditionalValidationMiddleware,
  createHealthAwareMiddleware
};