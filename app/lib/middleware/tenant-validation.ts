/**
 * Tenant Validation Middleware for iSECTECH Enterprise Security Platform
 * Ensures proper tenant isolation and validates tenant access rights
 */

import { NextRequest, NextResponse } from 'next/server';

// Types
interface Tenant {
  id: string;
  name: string;
  domain: string;
  status: 'active' | 'suspended' | 'inactive';
  plan: 'starter' | 'professional' | 'enterprise' | 'custom';
  features: string[];
  limits: {
    maxUsers: number;
    maxAssessments: number;
    dataRetentionDays: number;
    apiRequestsPerDay: number;
  };
  createdAt: string;
  lastActiveAt: string;
  complianceFrameworks: string[];
}

interface TenantValidationOptions {
  required?: boolean;
  allowedStatuses?: string[];
  requiredFeatures?: string[];
  requiredPlans?: string[];
  validateLimits?: boolean;
  skipValidation?: (req: NextRequest) => boolean;
}

interface TenantContext {
  tenant: Tenant;
  isValid: boolean;
  hasRequiredFeatures: boolean;
  withinLimits: boolean;
}

// Mock tenant data - in production, this would come from a database
const MOCK_TENANTS: Record<string, Tenant> = {
  'tenant-001': {
    id: 'tenant-001',
    name: 'Acme Corporation',
    domain: 'acme.com',
    status: 'active',
    plan: 'enterprise',
    features: [
      'compliance-assessments',
      'executive-dashboard',
      'audit-logging',
      'api-access',
      'white-labeling',
      'advanced-analytics',
      'multi-framework-support',
      'custom-integrations'
    ],
    limits: {
      maxUsers: 1000,
      maxAssessments: 500,
      dataRetentionDays: 2555, // 7 years
      apiRequestsPerDay: 100000
    },
    createdAt: '2024-01-01T00:00:00Z',
    lastActiveAt: new Date().toISOString(),
    complianceFrameworks: ['GDPR', 'HIPAA', 'SOC2', 'ISO27001', 'PCI_DSS']
  },
  'tenant-002': {
    id: 'tenant-002',
    name: 'TechStart Inc.',
    domain: 'techstart.io',
    status: 'active',
    plan: 'professional',
    features: [
      'compliance-assessments',
      'executive-dashboard',
      'audit-logging',
      'api-access',
      'advanced-analytics'
    ],
    limits: {
      maxUsers: 100,
      maxAssessments: 50,
      dataRetentionDays: 1095, // 3 years
      apiRequestsPerDay: 10000
    },
    createdAt: '2024-06-15T00:00:00Z',
    lastActiveAt: new Date().toISOString(),
    complianceFrameworks: ['GDPR', 'SOC2']
  },
  'tenant-003': {
    id: 'tenant-003',
    name: 'Small Business LLC',
    domain: 'smallbiz.com',
    status: 'active',
    plan: 'starter',
    features: [
      'compliance-assessments',
      'executive-dashboard',
      'audit-logging'
    ],
    limits: {
      maxUsers: 25,
      maxAssessments: 10,
      dataRetentionDays: 365, // 1 year
      apiRequestsPerDay: 1000
    },
    createdAt: '2024-11-01T00:00:00Z',
    lastActiveAt: new Date().toISOString(),
    complianceFrameworks: ['GDPR']
  }
};

/**
 * Extract tenant ID from request
 */
export function extractTenantId(req: NextRequest): string | null {
  // Check headers first (most common for API requests)
  const headerTenantId = req.headers.get('x-tenant-id');
  if (headerTenantId) {
    return headerTenantId;
  }

  // Check subdomain
  const host = req.headers.get('host');
  if (host) {
    const subdomain = host.split('.')[0];
    // Map subdomain to tenant if it follows a pattern
    if (subdomain && subdomain !== 'www' && subdomain !== 'api') {
      // In production, you'd lookup the tenant by subdomain
      return `tenant-${subdomain}`;
    }
  }

  // Check URL path parameter
  const url = new URL(req.url);
  const pathSegments = url.pathname.split('/');
  const tenantSegmentIndex = pathSegments.findIndex(segment => segment === 'tenant');
  if (tenantSegmentIndex !== -1 && pathSegments[tenantSegmentIndex + 1]) {
    return pathSegments[tenantSegmentIndex + 1];
  }

  // Check query parameter
  const queryTenantId = url.searchParams.get('tenantId') || url.searchParams.get('tenant_id');
  if (queryTenantId) {
    return queryTenantId;
  }

  return null;
}

/**
 * Get tenant by ID
 */
export async function getTenant(tenantId: string): Promise<Tenant | null> {
  // In production, this would query your database
  return MOCK_TENANTS[tenantId] || null;
}

/**
 * Validate tenant status
 */
export function isTenantValid(tenant: Tenant, allowedStatuses: string[] = ['active']): boolean {
  return allowedStatuses.includes(tenant.status);
}

/**
 * Check if tenant has required features
 */
export function tenantHasFeatures(tenant: Tenant, requiredFeatures: string[]): boolean {
  return requiredFeatures.every(feature => tenant.features.includes(feature));
}

/**
 * Check if tenant plan meets requirements
 */
export function tenantHasPlan(tenant: Tenant, requiredPlans: string[]): boolean {
  return requiredPlans.includes(tenant.plan);
}

/**
 * Validate tenant limits (simplified - in production you'd check actual usage)
 */
export function validateTenantLimits(tenant: Tenant): boolean {
  // In production, you would:
  // 1. Query current usage from database
  // 2. Compare against tenant.limits
  // 3. Return true/false based on whether limits are exceeded
  
  // For now, return true (assuming within limits)
  return true;
}

/**
 * Get tenant features available for a specific endpoint
 */
export function getRequiredFeaturesForEndpoint(pathname: string): string[] {
  if (pathname.startsWith('/api/compliance')) {
    return ['compliance-assessments'];
  }
  if (pathname.startsWith('/api/executive')) {
    return ['executive-dashboard'];
  }
  if (pathname.startsWith('/api/audit')) {
    return ['audit-logging'];
  }
  if (pathname.startsWith('/api/analytics')) {
    return ['advanced-analytics'];
  }
  if (pathname.startsWith('/api/integrations')) {
    return ['custom-integrations'];
  }
  return []; // No specific features required
}

/**
 * Main tenant validation middleware
 */
export function tenantValidationMiddleware(options: TenantValidationOptions = {}) {
  return async (req: NextRequest): Promise<NextResponse | null> => {
    const {
      required = true,
      allowedStatuses = ['active'],
      requiredFeatures = [],
      requiredPlans = [],
      validateLimits = true,
      skipValidation
    } = options;

    // Skip validation if custom skip condition is met
    if (skipValidation && skipValidation(req)) {
      return null;
    }

    const tenantId = extractTenantId(req);

    if (!tenantId) {
      if (required) {
        return NextResponse.json(
          {
            success: false,
            error: 'Tenant required',
            message: 'No tenant ID provided. Please specify tenant via header, subdomain, or query parameter.'
          },
          { status: 400 }
        );
      }
      return null; // Continue without tenant validation
    }

    const tenant = await getTenant(tenantId);

    if (!tenant) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid tenant',
          message: `Tenant '${tenantId}' not found`
        },
        { status: 404 }
      );
    }

    // Validate tenant status
    if (!isTenantValid(tenant, allowedStatuses)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Tenant unavailable',
          message: `Tenant is ${tenant.status}. Only ${allowedStatuses.join(', ')} tenants allowed.`
        },
        { status: 403 }
      );
    }

    // Auto-detect required features based on endpoint if not specified
    const endpointFeatures = getRequiredFeaturesForEndpoint(req.nextUrl.pathname);
    const allRequiredFeatures = [...requiredFeatures, ...endpointFeatures];

    // Validate tenant features
    if (allRequiredFeatures.length > 0 && !tenantHasFeatures(tenant, allRequiredFeatures)) {
      const missingFeatures = allRequiredFeatures.filter(feature => !tenant.features.includes(feature));
      return NextResponse.json(
        {
          success: false,
          error: 'Feature not available',
          message: `Tenant plan '${tenant.plan}' does not include: ${missingFeatures.join(', ')}`,
          requiredFeatures: missingFeatures,
          availableFeatures: tenant.features,
          upgradeRequired: true
        },
        { status: 403 }
      );
    }

    // Validate tenant plan
    if (requiredPlans.length > 0 && !tenantHasPlan(tenant, requiredPlans)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Plan upgrade required',
          message: `Current plan '${tenant.plan}' not sufficient. Required: ${requiredPlans.join(' or ')}`,
          currentPlan: tenant.plan,
          requiredPlans,
          upgradeRequired: true
        },
        { status: 403 }
      );
    }

    // Validate tenant limits
    if (validateLimits && !validateTenantLimits(tenant)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Limit exceeded',
          message: 'Tenant has exceeded usage limits',
          limits: tenant.limits,
          upgradeRequired: true
        },
        { status: 429 }
      );
    }

    // Add tenant context to request headers
    const response = NextResponse.next();
    response.headers.set('x-tenant-id', tenant.id);
    response.headers.set('x-tenant-name', tenant.name);
    response.headers.set('x-tenant-plan', tenant.plan);
    response.headers.set('x-tenant-features', JSON.stringify(tenant.features));
    response.headers.set('x-tenant-status', tenant.status);

    return null; // Continue with validated tenant
  };
}

/**
 * Predefined middleware configurations
 */
export const requireTenant = tenantValidationMiddleware({ required: true });
export const requireActiveTenant = tenantValidationMiddleware({ 
  required: true, 
  allowedStatuses: ['active'] 
});
export const requireEnterpriseTenant = tenantValidationMiddleware({
  required: true,
  requiredPlans: ['enterprise', 'custom']
});
export const requireComplianceTenant = tenantValidationMiddleware({
  required: true,
  requiredFeatures: ['compliance-assessments']
});

/**
 * Get tenant context from request (after validation middleware)
 */
export function getTenantFromRequest(req: NextRequest): Partial<Tenant> | null {
  try {
    const tenantId = req.headers.get('x-tenant-id');
    const tenantName = req.headers.get('x-tenant-name');
    const tenantPlan = req.headers.get('x-tenant-plan');
    const tenantStatus = req.headers.get('x-tenant-status');
    const featuresHeader = req.headers.get('x-tenant-features');

    if (!tenantId) {
      return null;
    }

    const features = featuresHeader ? JSON.parse(featuresHeader) : [];

    return {
      id: tenantId,
      name: tenantName || '',
      plan: tenantPlan as Tenant['plan'],
      status: tenantStatus as Tenant['status'],
      features
    };
  } catch (error) {
    console.error('Error extracting tenant from request:', error);
    return null;
  }
}

/**
 * Check if tenant has specific feature
 */
export function tenantHasFeature(req: NextRequest, feature: string): boolean {
  const tenant = getTenantFromRequest(req);
  return tenant?.features?.includes(feature) || false;
}

/**
 * Utility to create tenant-scoped middleware
 */
export function createTenantScopedMiddleware<T>(
  handler: (req: NextRequest, tenantContext: TenantContext) => Promise<T>
) {
  return async (req: NextRequest): Promise<T | NextResponse> => {
    const tenantId = extractTenantId(req);
    
    if (!tenantId) {
      return NextResponse.json(
        { success: false, error: 'Tenant ID required' },
        { status: 400 }
      );
    }

    const tenant = await getTenant(tenantId);
    
    if (!tenant) {
      return NextResponse.json(
        { success: false, error: 'Tenant not found' },
        { status: 404 }
      );
    }

    const tenantContext: TenantContext = {
      tenant,
      isValid: isTenantValid(tenant),
      hasRequiredFeatures: true, // Would be determined based on endpoint
      withinLimits: validateTenantLimits(tenant)
    };

    return handler(req, tenantContext);
  };
}

export default tenantValidationMiddleware;