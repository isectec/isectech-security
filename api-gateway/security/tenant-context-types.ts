/**
 * Tenant Context Types and Utilities
 * Shared types and constants for tenant context validation
 * 
 * Task: 81.3 - Implement tenant context extraction and validation logic
 */

// Core tenant context types
export enum TenantType {
  ENTERPRISE = 'enterprise',
  STANDARD = 'standard',  
  TRIAL = 'trial'
}

export enum TenantTier {
  BASIC = 'basic',
  PREMIUM = 'premium',
  ENTERPRISE = 'enterprise'
}

export enum TenantStatus {
  ACTIVE = 'active',
  SUSPENDED = 'suspended',
  TRIAL_EXPIRED = 'trial_expired'
}

export enum UserTenantStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended'
}

export enum TenantContextType {
  NONE = 'none',
  TENANT_SCOPED = 'tenant_scoped',
  TENANT_SPECIFIC = 'tenant_specific',
  SPECIFIC_TENANT = 'specific_tenant',
  MULTI_TENANT = 'multi_tenant',
  CROSS_TENANT = 'cross_tenant',
  SYSTEM_WIDE = 'system_wide',
  REQUIRED_IN_REQUEST = 'required_in_request',
  FROM_SESSION = 'from_session',
  SESSION_CONTEXT = 'session_context',
  SYSTEM_ADMIN = 'system_admin'
}

// Tenant access error codes
export enum TenantErrorCode {
  TENANT_CONTEXT_MISSING = 'TENANT_CONTEXT_MISSING',
  TENANT_EXTRACTION_ERROR = 'TENANT_EXTRACTION_ERROR',
  INVALID_TENANT_ID_FORMAT = 'INVALID_TENANT_ID_FORMAT',
  AUTHENTICATION_REQUIRED = 'AUTHENTICATION_REQUIRED',
  NO_TENANT_IN_JWT = 'NO_TENANT_IN_JWT',
  INVALID_JWT_TOKEN = 'INVALID_JWT_TOKEN',
  INVALID_SESSION = 'INVALID_SESSION',
  TENANT_NOT_FOUND = 'TENANT_NOT_FOUND',
  TENANT_ACCESS_DENIED = 'TENANT_ACCESS_DENIED',
  TENANT_VALIDATION_ERROR = 'TENANT_VALIDATION_ERROR',
  TENANT_SUSPENDED = 'TENANT_SUSPENDED',
  USER_ACCESS_SUSPENDED = 'USER_ACCESS_SUSPENDED'
}

// Feature flags for tenant capabilities
export enum TenantFeature {
  ADVANCED_ANALYTICS = 'advanced_analytics',
  CUSTOM_POLICIES = 'custom_policies',
  MULTI_REGION = 'multi_region',
  SOC_AUTOMATION = 'soc_automation',
  THREAT_INTELLIGENCE = 'threat_intelligence',
  VULNERABILITY_SCANNING = 'vulnerability_scanning',
  COMPLIANCE_REPORTING = 'compliance_reporting',
  API_RATE_LIMITING = 'api_rate_limiting',
  MOBILE_NOTIFICATIONS = 'mobile_notifications',
  WHITE_LABELING = 'white_labeling',
  SSO_INTEGRATION = 'sso_integration',
  CUSTOM_ROLES = 'custom_roles',
  ADVANCED_AUDIT = 'advanced_audit',
  REAL_TIME_MONITORING = 'real_time_monitoring',
  INCIDENT_RESPONSE = 'incident_response'
}

// Compliance framework types
export enum ComplianceFramework {
  SOC2 = 'SOC2',
  GDPR = 'GDPR', 
  HIPAA = 'HIPAA',
  PCI_DSS = 'PCI_DSS',
  ISO_27001 = 'ISO_27001',
  NIST = 'NIST',
  FedRAMP = 'FedRAMP',
  FISMA = 'FISMA'
}

// Data residency regions
export enum DataResidency {
  US_EAST_1 = 'us-east-1',
  US_WEST_2 = 'us-west-2',
  EU_WEST_1 = 'eu-west-1',
  EU_CENTRAL_1 = 'eu-central-1',
  AP_SOUTHEAST_1 = 'ap-southeast-1',
  AP_NORTHEAST_1 = 'ap-northeast-1',
  CA_CENTRAL_1 = 'ca-central-1'
}

// Access event types for logging
export enum AccessEventType {
  LOGIN = 'login',
  ACCESS = 'access',
  LOGOUT = 'logout',
  DENIED = 'denied',
  SUSPENDED = 'suspended',
  TOKEN_REFRESH = 'token_refresh',
  MFA_VERIFY = 'mfa_verify',
  PERMISSION_CHECK = 'permission_check'
}

// Tenant context validation result
export interface TenantValidationResult {
  isValid: boolean;
  tenantId?: string;
  tenantContext?: TenantContextInfo;
  userPermissions?: string[];
  errorCode?: TenantErrorCode;
  errorMessage?: string;
  cacheHit?: boolean;
}

// Extended tenant context information
export interface TenantContextInfo {
  tenantId: string;
  tenantName: string;
  tenantType: TenantType;
  tenantTier: TenantTier;
  status: TenantStatus;
  maxUsers?: number;
  features: TenantFeature[];
  dataResidency?: DataResidency;
  complianceFrameworks: ComplianceFramework[];
  customConfig?: Record<string, any>;
}

// User-tenant relationship info
export interface UserTenantInfo {
  userId: string;
  tenantId: string;
  role: string;
  permissions: string[];
  status: UserTenantStatus;
  joinedAt: Date;
  lastAccessAt?: Date;
  accessCount?: number;
  lastIpAddress?: string;
  lastUserAgent?: string;
}

// Request context for tenant operations
export interface TenantRequestContext {
  userId: string;
  tenantId: string;
  sessionId?: string;
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
  endpoint: string;
  method: string;
  timestamp: Date;
}

// Configuration for tenant context service
export interface TenantContextConfig {
  cacheEnabled: boolean;
  cacheTtl: number;
  userTenantCacheTtl: number;
  enableAccessLogging: boolean;
  enableDetailedAuditLog: boolean;
  maxTenantAssociations: number;
  jwtSecret: string;
  redisUrl?: string;
  postgresConfig: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    maxConnections: number;
  };
}

// Tenant context extraction options
export interface TenantExtractionOptions {
  allowQueryParameter: boolean;
  allowPathParameter: boolean;
  requireAuthentication: boolean;
  validatePermissions: boolean;
  logAccess: boolean;
}

// Helper utility functions
export class TenantUtils {
  /**
   * Check if tenant has specific feature enabled
   */
  static hasFeature(tenant: TenantContextInfo, feature: TenantFeature): boolean {
    return tenant.features.includes(feature);
  }

  /**
   * Check if tenant meets compliance framework requirements
   */
  static isCompliantWith(tenant: TenantContextInfo, framework: ComplianceFramework): boolean {
    return tenant.complianceFrameworks.includes(framework);
  }

  /**
   * Get tenant capability level based on tier
   */
  static getTenantCapabilities(tier: TenantTier): TenantFeature[] {
    switch (tier) {
      case TenantTier.BASIC:
        return [
          TenantFeature.API_RATE_LIMITING,
          TenantFeature.MOBILE_NOTIFICATIONS
        ];
      case TenantTier.PREMIUM:
        return [
          TenantFeature.API_RATE_LIMITING,
          TenantFeature.MOBILE_NOTIFICATIONS,
          TenantFeature.ADVANCED_ANALYTICS,
          TenantFeature.COMPLIANCE_REPORTING,
          TenantFeature.SSO_INTEGRATION,
          TenantFeature.VULNERABILITY_SCANNING
        ];
      case TenantTier.ENTERPRISE:
        return Object.values(TenantFeature);
      default:
        return [];
    }
  }

  /**
   * Validate tenant ID format
   */
  static isValidTenantId(tenantId: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(tenantId);
  }

  /**
   * Extract tenant ID from URL path
   */
  static extractTenantFromPath(pathname: string): string | null {
    // Match patterns like /api/tenants/{uuid}/... or /tenants/{uuid}/...
    const patterns = [
      /\/(?:api\/)?tenants\/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:\/|$)/i,
      /\/t\/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:\/|$)/i
    ];

    for (const pattern of patterns) {
      const match = pathname.match(pattern);
      if (match) {
        return match[1];
      }
    }

    return null;
  }

  /**
   * Get tenant context type for endpoint
   */
  static getTenantContextType(pathname: string, method: string): TenantContextType {
    // System-wide endpoints
    if (pathname.startsWith('/api/system/') || 
        pathname.startsWith('/api/policy/admin/') ||
        pathname.startsWith('/kong-admin/')) {
      return TenantContextType.SYSTEM_WIDE;
    }

    // Cross-tenant endpoints (admin/security)
    if (pathname.includes('/admin/') || pathname.includes('/security/')) {
      return TenantContextType.CROSS_TENANT;
    }

    // Specific tenant endpoints with tenant ID in path
    if (this.extractTenantFromPath(pathname)) {
      return TenantContextType.SPECIFIC_TENANT;
    }

    // Multi-tenant endpoints (user can access multiple tenants)
    if (pathname.startsWith('/api/tenants') && method === 'GET') {
      return TenantContextType.MULTI_TENANT;
    }

    // Public endpoints
    if (this.isPublicEndpoint(pathname, method)) {
      return TenantContextType.NONE;
    }

    // Default to tenant-scoped
    return TenantContextType.TENANT_SCOPED;
  }

  /**
   * Check if endpoint is public (no tenant context required)
   */
  static isPublicEndpoint(pathname: string, method: string): boolean {
    const publicEndpoints = [
      '/health',
      '/api/health',
      '/metrics',
      '/api/auth/login',
      '/api/auth/logout',
      '/api/auth/password/reset',
      '/api/auth/password/reset/complete',
      '/api/auth/password/validate'
    ];

    // Check exact matches
    for (const endpoint of publicEndpoints) {
      if (pathname === endpoint || pathname.startsWith(endpoint + '/')) {
        return true;
      }
    }

    // OPTIONS requests are typically public for CORS
    if (method === 'OPTIONS') {
      return true;
    }

    // Policy evaluation can be public with API key
    if (pathname === '/api/policy/evaluate' && method === 'POST') {
      return true;
    }

    return false;
  }

  /**
   * Create cache key for tenant context
   */
  static createCacheKey(userId: string, tenantId: string, prefix = 'tenant_access'): string {
    return `${prefix}:${userId}:${tenantId}`;
  }

  /**
   * Create audit event payload
   */
  static createAuditEvent(
    context: TenantRequestContext,
    eventType: AccessEventType,
    success: boolean,
    errorCode?: TenantErrorCode,
    errorMessage?: string
  ): Record<string, any> {
    return {
      userId: context.userId,
      tenantId: context.tenantId,
      eventType,
      endpoint: context.endpoint,
      method: context.method,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      success,
      errorCode,
      errorMessage,
      sessionId: context.sessionId,
      requestId: context.requestId,
      timestamp: context.timestamp.toISOString()
    };
  }

  /**
   * Validate tenant tier permissions for operation
   */
  static canPerformOperation(
    tenantTier: TenantTier,
    requiredFeature: TenantFeature
  ): boolean {
    const availableFeatures = this.getTenantCapabilities(tenantTier);
    return availableFeatures.includes(requiredFeature);
  }

  /**
   * Get default tenant configuration by tier
   */
  static getDefaultTenantConfig(tier: TenantTier): Partial<TenantContextInfo> {
    const baseConfig = {
      tenantType: TenantType.STANDARD,
      status: TenantStatus.ACTIVE,
      complianceFrameworks: [] as ComplianceFramework[]
    };

    switch (tier) {
      case TenantTier.BASIC:
        return {
          ...baseConfig,
          tenantTier: tier,
          maxUsers: 10,
          features: this.getTenantCapabilities(tier)
        };
      case TenantTier.PREMIUM:
        return {
          ...baseConfig,
          tenantTier: tier,
          maxUsers: 100,
          features: this.getTenantCapabilities(tier),
          complianceFrameworks: [ComplianceFramework.SOC2]
        };
      case TenantTier.ENTERPRISE:
        return {
          ...baseConfig,
          tenantType: TenantType.ENTERPRISE,
          tenantTier: tier,
          maxUsers: undefined, // unlimited
          features: this.getTenantCapabilities(tier),
          complianceFrameworks: [
            ComplianceFramework.SOC2,
            ComplianceFramework.GDPR,
            ComplianceFramework.HIPAA,
            ComplianceFramework.ISO_27001
          ]
        };
      default:
        return baseConfig;
    }
  }
}

// Default configuration
export const DEFAULT_TENANT_CONFIG: TenantContextConfig = {
  cacheEnabled: true,
  cacheTtl: 5 * 60, // 5 minutes
  userTenantCacheTtl: 10 * 60, // 10 minutes
  enableAccessLogging: true,
  enableDetailedAuditLog: true,
  maxTenantAssociations: 10,
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL,
  postgresConfig: {
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432'),
    database: process.env.POSTGRES_DB || 'isectech',
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    maxConnections: 20
  }
};