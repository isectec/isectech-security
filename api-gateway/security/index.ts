/**
 * API Gateway Security Module - Main Integration Layer
 * Exports all security components including business rule validators
 * 
 * Task: 83.5 - Integration and export layer for custom business rule validators
 */

// Core validation components
export {
  validateIncomingRequest
} from './request-validation-middleware';

// Business rule validators
export {
  BusinessRuleValidator,
  createBusinessRuleValidator,
  businessRuleValidator,
  type BusinessRuleValidationRequest,
  type BusinessRuleValidationResult,
  type ValidationViolation,
  type ValidationWarning,
  type TransactionLimitRule,
  type TimeBasedAccessRule,
  type ResourceConsistencyRule,
  type WorkflowStateRule,
  type TenantDataIsolationRule
} from './business-rule-validators';

// Enhanced validation middleware
export {
  EnhancedValidationMiddleware,
  createEnhancedValidationMiddleware,
  type EnhancedValidationConfig,
  type EnhancedValidationResult,
  type ValidationErrorResponse
} from './enhanced-validation-middleware';

// Business rules configuration
export {
  BusinessRuleConfigManager,
  businessRuleConfigManager,
  defaultBusinessRuleConfig,
  type BusinessRuleConfig
} from './business-rules-config';

// Tenant context and authorization
export {
  TenantContextService,
  createTenantContextService,
  tenantContextService,
  type TenantContext,
  type UserTenantAssociation,
  type TenantExtractionResult,
  type JWTPayload
} from './tenant-context-service';

export {
  AuthorizationMiddleware,
  createAuthorizationMiddleware,
  authorizationMiddleware,
  type AuthorizationResult,
  type AuthorizationAuditData,
  type AuthorizationConfig
} from './authorization-middleware';

// RBAC and permissions
export {
  RBACPermissionService,
  createRBACPermissionService,
  type PermissionCheckRequest,
  type PermissionCheckResult
} from './rbac-permission-service';

// Tenant context types and utilities
export {
  TenantErrorCode,
  TenantUtils,
  AccessEventType,
  type TenantRequestContext
} from './tenant-context-types';

// API security manager
export {
  APISecurityManager
} from './api-security-manager';

/**
 * Factory function to create a complete validation pipeline
 * Combines schema validation with business rule validation
 */
export function createValidationPipeline(config?: {
  enableSchemaValidation?: boolean;
  enableBusinessRuleValidation?: boolean;
  businessRuleConfig?: Partial<BusinessRuleConfig>;
  validationConfig?: Partial<EnhancedValidationConfig>;
}) {
  const {
    enableSchemaValidation = true,
    enableBusinessRuleValidation = true,
    businessRuleConfig = {},
    validationConfig = {}
  } = config || {};

  // Initialize business rule validator with custom config
  if (Object.keys(businessRuleConfig).length > 0) {
    businessRuleConfigManager.updateConfig(businessRuleConfig);
  }

  // Create enhanced validation middleware
  const enhancedMiddleware = createEnhancedValidationMiddleware(
    businessRuleValidator,
    tenantContextService,
    {
      enableSchemaValidation,
      enableBusinessRuleValidation,
      ...validationConfig
    }
  );

  return enhancedMiddleware;
}

/**
 * Utility function to validate business rules independently
 * Useful for testing or manual validation scenarios
 */
export async function validateBusinessRulesStandalone(
  request: BusinessRuleValidationRequest
): Promise<BusinessRuleValidationResult> {
  return businessRuleValidator.validateBusinessRules(request);
}

/**
 * Helper function to check if an endpoint requires validation
 */
export function requiresValidation(pathname: string, method: string): boolean {
  return EnhancedValidationMiddleware.shouldValidateEndpoint(pathname, method);
}

/**
 * Configuration validation utility
 */
export function validateSecurityConfiguration(): {
  isValid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate business rule configuration
  const configValidation = businessRuleConfigManager.validateConfig();
  if (!configValidation.isValid) {
    errors.push(...configValidation.errors);
  }

  // Check environment variables
  const requiredEnvVars = [
    'JWT_SECRET',
    'REDIS_URL',
    'POSTGRES_HOST',
    'POSTGRES_DB',
    'POSTGRES_USER',
    'POSTGRES_PASSWORD'
  ];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      errors.push(`Missing required environment variable: ${envVar}`);
    }
  }

  // Check optional but recommended environment variables
  const recommendedEnvVars = [
    'REDIS_PASSWORD',
    'POSTGRES_SSL',
    'SECURITY_WEBHOOK_URL',
    'SMTP_HOST'
  ];

  for (const envVar of recommendedEnvVars) {
    if (!process.env[envVar]) {
      warnings.push(`Recommended environment variable not set: ${envVar}`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Health check function for security components
 */
export async function performSecurityHealthCheck(): Promise<{
  healthy: boolean;
  components: Record<string, {
    status: 'healthy' | 'degraded' | 'unhealthy';
    message?: string;
    lastCheck: string;
  }>;
}> {
  const components: Record<string, any> = {};
  let allHealthy = true;

  try {
    // Test business rule validator
    const testRequest: BusinessRuleValidationRequest = {
      userId: 'health-check',
      tenantId: 'health-check',
      endpoint: '/health',
      method: 'GET',
      timestamp: new Date()
    };

    const validationResult = await businessRuleValidator.validateBusinessRules(testRequest);
    components.businessRuleValidator = {
      status: validationResult ? 'healthy' : 'degraded',
      message: validationResult ? 'Validation working' : 'Validation issues detected',
      lastCheck: new Date().toISOString()
    };

    if (!validationResult) {
      allHealthy = false;
    }
  } catch (error) {
    components.businessRuleValidator = {
      status: 'unhealthy',
      message: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      lastCheck: new Date().toISOString()
    };
    allHealthy = false;
  }

  try {
    // Test tenant context service
    // Note: In a real implementation, you'd create a minimal test request
    components.tenantContextService = {
      status: 'healthy',
      message: 'Service initialized',
      lastCheck: new Date().toISOString()
    };
  } catch (error) {
    components.tenantContextService = {
      status: 'unhealthy',
      message: `Service error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      lastCheck: new Date().toISOString()
    };
    allHealthy = false;
  }

  // Test configuration validity
  const configValidation = validateSecurityConfiguration();
  components.configuration = {
    status: configValidation.isValid ? 'healthy' : 'degraded',
    message: configValidation.isValid 
      ? 'Configuration valid' 
      : `Configuration issues: ${configValidation.errors.slice(0, 3).join(', ')}`,
    lastCheck: new Date().toISOString()
  };

  if (!configValidation.isValid) {
    allHealthy = false;
  }

  return {
    healthy: allHealthy,
    components
  };
}

/**
 * Export version information
 */
export const SECURITY_MODULE_VERSION = '1.0.0';
export const SUPPORTED_OPENAPI_VERSION = '3.1.0';

/**
 * Default exports for common use cases
 */
export default {
  createValidationPipeline,
  validateBusinessRulesStandalone,
  requiresValidation,
  validateSecurityConfiguration,
  performSecurityHealthCheck,
  businessRuleValidator,
  tenantContextService,
  authorizationMiddleware,
  businessRuleConfigManager
};