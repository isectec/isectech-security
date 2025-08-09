/**
 * Enhanced Validation Middleware
 * Integrates OpenAPI schema validation with custom business rule validation
 * 
 * Task: 83.5 - Integration layer for custom business rule validators
 */

import { NextRequest, NextResponse } from 'next/server';
import { validateIncomingRequest } from './request-validation-middleware';
import { 
  BusinessRuleValidator,
  BusinessRuleValidationRequest,
  BusinessRuleValidationResult,
  ValidationViolation,
  ValidationWarning
} from './business-rule-validators';
import { TenantContextService } from './tenant-context-service';

export interface EnhancedValidationConfig {
  enableSchemaValidation: boolean;
  enableBusinessRuleValidation: boolean;
  failFast: boolean;
  logViolations: boolean;
  returnDetailedErrors: boolean;
  maxValidationTimeMs: number;
}

export interface EnhancedValidationResult {
  success: boolean;
  schemaValidation: {
    passed: boolean;
    errors: any[];
    timeMs: number;
  };
  businessRuleValidation: {
    passed: boolean;
    violations: ValidationViolation[];
    warnings: ValidationWarning[];
    timeMs: number;
  };
  totalTimeMs: number;
}

export interface ValidationErrorResponse {
  success: false;
  error: string;
  error_code: string;
  details: {
    schema_errors?: any[];
    business_rule_violations?: Array<{
      rule_id: string;
      severity: string;
      message: string;
      field?: string;
      remediation?: string;
    }>;
    warnings?: Array<{
      rule_id: string;
      message: string;
      suggestion?: string;
    }>;
  };
  validation_metadata: {
    schema_validation_time_ms: number;
    business_rule_validation_time_ms: number;
    total_validation_time_ms: number;
  };
  request_id: string;
  timestamp: string;
}

export class EnhancedValidationMiddleware {
  private businessRuleValidator: BusinessRuleValidator;
  private tenantContextService: TenantContextService;
  private config: EnhancedValidationConfig;

  constructor(
    businessRuleValidator: BusinessRuleValidator,
    tenantContextService: TenantContextService,
    config: Partial<EnhancedValidationConfig> = {}
  ) {
    this.businessRuleValidator = businessRuleValidator;
    this.tenantContextService = tenantContextService;
    
    // Default configuration
    this.config = {
      enableSchemaValidation: true,
      enableBusinessRuleValidation: true,
      failFast: false,
      logViolations: true,
      returnDetailedErrors: true,
      maxValidationTimeMs: 10000, // 10 seconds max
      ...config
    };
  }

  /**
   * Main validation middleware entry point
   */
  async validateRequest(request: NextRequest): Promise<NextResponse | null> {
    const startTime = Date.now();
    const requestId = this.generateRequestId();
    
    try {
      // Apply timeout to prevent hanging validation
      const validationResult = await Promise.race([
        this.performValidation(request, requestId),
        this.createTimeoutPromise()
      ]);

      const totalTime = Date.now() - startTime;

      // Log validation results if configured
      if (this.config.logViolations) {
        this.logValidationResults(validationResult, requestId, totalTime);
      }

      // Return error response if validation failed
      if (!validationResult.success) {
        return this.createValidationErrorResponse(validationResult, requestId, totalTime);
      }

      // Validation passed - allow request to proceed
      return null;

    } catch (error) {
      console.error('Enhanced validation middleware error:', error);
      
      return NextResponse.json({
        success: false,
        error: 'validation_system_error',
        message: 'Validation system encountered an error',
        request_id: requestId,
        timestamp: new Date().toISOString()
      }, { status: 500 });
    }
  }

  /**
   * Perform both schema and business rule validation
   */
  private async performValidation(
    request: NextRequest,
    requestId: string
  ): Promise<EnhancedValidationResult> {
    const result: EnhancedValidationResult = {
      success: true,
      schemaValidation: {
        passed: true,
        errors: [],
        timeMs: 0
      },
      businessRuleValidation: {
        passed: true,
        violations: [],
        warnings: [],
        timeMs: 0
      },
      totalTimeMs: 0
    };

    // 1. Schema Validation (if enabled)
    if (this.config.enableSchemaValidation) {
      const schemaStartTime = Date.now();
      
      try {
        const schemaValidationResponse = await validateIncomingRequest(request);
        result.schemaValidation.timeMs = Date.now() - schemaStartTime;
        
        if (schemaValidationResponse) {
          // Schema validation failed
          result.schemaValidation.passed = false;
          result.success = false;
          
          // Extract error details from the response
          const responseData = await schemaValidationResponse.clone().json();
          result.schemaValidation.errors = responseData.details || [responseData];
          
          // If fail-fast is enabled, return early
          if (this.config.failFast) {
            return result;
          }
        }
      } catch (error) {
        result.schemaValidation.passed = false;
        result.schemaValidation.errors = [{
          message: 'Schema validation system error',
          error: error instanceof Error ? error.message : 'Unknown error'
        }];
        result.success = false;
        
        if (this.config.failFast) {
          return result;
        }
      }
    }

    // 2. Business Rule Validation (if enabled)
    if (this.config.enableBusinessRuleValidation) {
      const businessRuleStartTime = Date.now();
      
      try {
        const businessRuleRequest = await this.buildBusinessRuleValidationRequest(request);
        const businessRuleResult = await this.businessRuleValidator.validateBusinessRules(
          businessRuleRequest
        );
        
        result.businessRuleValidation.timeMs = Date.now() - businessRuleStartTime;
        result.businessRuleValidation.violations = businessRuleResult.violations;
        result.businessRuleValidation.warnings = businessRuleResult.warnings;
        result.businessRuleValidation.passed = businessRuleResult.isValid;
        
        if (!businessRuleResult.isValid) {
          result.success = false;
        }
        
      } catch (error) {
        result.businessRuleValidation.passed = false;
        result.businessRuleValidation.violations = [{
          ruleId: 'business_rule_validation_system_error',
          severity: 'critical' as const,
          message: 'Business rule validation system error',
          remediation: 'Contact system administrator'
        }];
        result.success = false;
      }
    }

    return result;
  }

  /**
   * Build business rule validation request from Next.js request
   */
  private async buildBusinessRuleValidationRequest(
    request: NextRequest
  ): Promise<BusinessRuleValidationRequest> {
    const url = request.nextUrl;
    const pathname = url.pathname;
    const method = request.method;
    
    // Extract user ID from token (simplified - should use proper auth extraction)
    const userId = await this.extractUserIdFromRequest(request);
    
    // Extract tenant context
    const tenantResult = await this.tenantContextService.extractTenantContext(request);
    const tenantId = tenantResult.success ? tenantResult.tenantId! : 'unknown';
    
    // Parse request body
    let requestBody: any = null;
    try {
      if (['POST', 'PUT', 'PATCH'].includes(method)) {
        const clonedRequest = request.clone();
        const text = await clonedRequest.text();
        if (text) {
          requestBody = JSON.parse(text);
        }
      }
    } catch (error) {
      // Body parsing failed - will be caught by schema validation
    }
    
    // Extract query and path parameters
    const queryParams: Record<string, string> = {};
    url.searchParams.forEach((value, key) => {
      queryParams[key] = value;
    });
    
    const pathParams = this.extractPathParameters(pathname);
    
    // Extract headers (only safe ones)
    const headers: Record<string, string> = {};
    const safeHeaders = ['content-type', 'user-agent', 'x-tenant-id', 'x-client-version'];
    safeHeaders.forEach(headerName => {
      const value = request.headers.get(headerName);
      if (value) {
        headers[headerName] = value;
      }
    });

    return {
      userId: userId || 'anonymous',
      tenantId,
      endpoint: pathname,
      method,
      requestBody,
      queryParams,
      pathParams,
      headers,
      tenantContext: tenantResult.tenantContext,
      timestamp: new Date()
    };
  }

  /**
   * Extract user ID from request (JWT token)
   */
  private async extractUserIdFromRequest(request: NextRequest): Promise<string | null> {
    try {
      const authHeader = request.headers.get('authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        // In a real implementation, decode JWT token to get user ID
        // For now, return a placeholder
        return 'user_from_jwt';
      }
      
      const sessionCookie = request.cookies.get('session_token');
      if (sessionCookie?.value) {
        // In a real implementation, decode session token
        return 'user_from_session';
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Extract path parameters from URL
   */
  private extractPathParameters(pathname: string): Record<string, string> {
    const pathParams: Record<string, string> = {};
    
    // Extract common ID patterns
    const idMatch = pathname.match(/\/([a-f0-9-]{36})(?:\/|$)/); // UUID
    if (idMatch) {
      pathParams.id = idMatch[1];
    }
    
    const userIdMatch = pathname.match(/\/users\/([^/]+)/);
    if (userIdMatch) {
      pathParams.userId = userIdMatch[1];
    }
    
    const tenantIdMatch = pathname.match(/\/tenants\/([^/]+)/);
    if (tenantIdMatch) {
      pathParams.tenantId = tenantIdMatch[1];
    }
    
    return pathParams;
  }

  /**
   * Create timeout promise for validation
   */
  private createTimeoutPromise(): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Validation timeout after ${this.config.maxValidationTimeMs}ms`));
      }, this.config.maxValidationTimeMs);
    });
  }

  /**
   * Create detailed validation error response
   */
  private createValidationErrorResponse(
    validationResult: EnhancedValidationResult,
    requestId: string,
    totalTimeMs: number
  ): NextResponse {
    const response: ValidationErrorResponse = {
      success: false,
      error: 'validation_failed',
      error_code: this.getErrorCode(validationResult),
      details: {},
      validation_metadata: {
        schema_validation_time_ms: validationResult.schemaValidation.timeMs,
        business_rule_validation_time_ms: validationResult.businessRuleValidation.timeMs,
        total_validation_time_ms: totalTimeMs
      },
      request_id: requestId,
      timestamp: new Date().toISOString()
    };

    // Add schema validation errors
    if (!validationResult.schemaValidation.passed && validationResult.schemaValidation.errors.length > 0) {
      response.details.schema_errors = validationResult.schemaValidation.errors;
    }

    // Add business rule violations
    if (validationResult.businessRuleValidation.violations.length > 0) {
      response.details.business_rule_violations = validationResult.businessRuleValidation.violations.map(v => ({
        rule_id: v.ruleId,
        severity: v.severity,
        message: v.message,
        field: v.field,
        remediation: v.remediation
      }));
    }

    // Add warnings (if configured to return detailed errors)
    if (this.config.returnDetailedErrors && validationResult.businessRuleValidation.warnings.length > 0) {
      response.details.warnings = validationResult.businessRuleValidation.warnings.map(w => ({
        rule_id: w.ruleId,
        message: w.message,
        suggestion: w.suggestion
      }));
    }

    // Determine appropriate HTTP status code
    const statusCode = this.getHttpStatusCode(validationResult);

    return NextResponse.json(response, { status: statusCode });
  }

  /**
   * Get appropriate error code based on validation results
   */
  private getErrorCode(validationResult: EnhancedValidationResult): string {
    if (!validationResult.schemaValidation.passed && !validationResult.businessRuleValidation.passed) {
      return 'SCHEMA_AND_BUSINESS_RULE_VALIDATION_FAILED';
    } else if (!validationResult.schemaValidation.passed) {
      return 'SCHEMA_VALIDATION_FAILED';
    } else if (!validationResult.businessRuleValidation.passed) {
      return 'BUSINESS_RULE_VALIDATION_FAILED';
    }
    return 'VALIDATION_FAILED';
  }

  /**
   * Get appropriate HTTP status code based on validation results
   */
  private getHttpStatusCode(validationResult: EnhancedValidationResult): number {
    // Check for critical business rule violations
    const hasCriticalViolation = validationResult.businessRuleValidation.violations.some(
      v => v.severity === 'critical'
    );
    
    if (hasCriticalViolation) {
      return 403; // Forbidden - business rule violation
    }
    
    // Schema validation failure or other business rule violations
    if (!validationResult.schemaValidation.passed || !validationResult.businessRuleValidation.passed) {
      return 400; // Bad Request
    }
    
    return 400; // Default to Bad Request
  }

  /**
   * Log validation results for monitoring and debugging
   */
  private logValidationResults(
    validationResult: EnhancedValidationResult,
    requestId: string,
    totalTimeMs: number
  ): void {
    const logData = {
      request_id: requestId,
      timestamp: new Date().toISOString(),
      success: validationResult.success,
      schema_validation: {
        passed: validationResult.schemaValidation.passed,
        errors_count: validationResult.schemaValidation.errors.length,
        time_ms: validationResult.schemaValidation.timeMs
      },
      business_rule_validation: {
        passed: validationResult.businessRuleValidation.passed,
        violations_count: validationResult.businessRuleValidation.violations.length,
        warnings_count: validationResult.businessRuleValidation.warnings.length,
        critical_violations: validationResult.businessRuleValidation.violations.filter(v => v.severity === 'critical').length,
        time_ms: validationResult.businessRuleValidation.timeMs
      },
      total_time_ms: totalTimeMs
    };

    console.log('Enhanced Validation Result:', JSON.stringify(logData, null, 2));

    // Log violations separately for alerting
    if (validationResult.businessRuleValidation.violations.length > 0) {
      validationResult.businessRuleValidation.violations.forEach(violation => {
        console.warn(`Business Rule Violation [${requestId}]:`, {
          rule_id: violation.ruleId,
          severity: violation.severity,
          message: violation.message,
          field: violation.field,
          remediation: violation.remediation
        });
      });
    }
  }

  /**
   * Generate unique request ID for tracking
   */
  private generateRequestId(): string {
    return `val_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Check if validation is required for this endpoint
   */
  static shouldValidateEndpoint(pathname: string, method: string): boolean {
    // Skip validation for health checks and public endpoints
    const skipPatterns = [
      '/health',
      '/metrics',
      '/favicon.ico',
      '/_next/',
      '/static/'
    ];

    for (const pattern of skipPatterns) {
      if (pathname.startsWith(pattern)) {
        return false;
      }
    }

    // Skip validation for OPTIONS requests (CORS preflight)
    if (method === 'OPTIONS') {
      return false;
    }

    return true;
  }

  /**
   * Create middleware function for use in Next.js
   */
  createMiddlewareFunction() {
    return async (request: NextRequest): Promise<NextResponse | null> => {
      const pathname = request.nextUrl.pathname;
      const method = request.method;

      // Check if validation is required
      if (!EnhancedValidationMiddleware.shouldValidateEndpoint(pathname, method)) {
        return null; // Allow request to proceed without validation
      }

      // Perform validation
      return await this.validateRequest(request);
    };
  }
}

// Factory function to create enhanced validation middleware
export function createEnhancedValidationMiddleware(
  businessRuleValidator: BusinessRuleValidator,
  tenantContextService: TenantContextService,
  config?: Partial<EnhancedValidationConfig>
): EnhancedValidationMiddleware {
  return new EnhancedValidationMiddleware(
    businessRuleValidator,
    tenantContextService,
    config
  );
}

// Export types for external use
export type {
  EnhancedValidationConfig,
  EnhancedValidationResult,
  ValidationErrorResponse
};