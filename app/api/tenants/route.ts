/**
 * Tenant Management API Routes
 * Multi-tenant aware API endpoints with PostgreSQL RLS integration
 */

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentTenantContext, validateTenantOperation } from '@/lib/middleware/tenant-context';
import { z } from 'zod';

// Validation schemas
const CreateTenantSchema = z.object({
  name: z.string().min(1).max(100),
  displayName: z.string().min(1).max(200),
  description: z.string().optional(),
  type: z.enum(['enterprise', 'government', 'defense', 'critical_infra', 'financial', 'healthcare', 'msp', 'startup']),
  tier: z.enum(['essential', 'advanced', 'enterprise', 'government']),
  domain: z.string().min(1).max(255),
  industry: z.string().optional(),
  country: z.string().length(2),
  complianceFrameworks: z.array(z.string()).optional(),
  maxSecurityClearance: z.enum(['unclassified', 'cui', 'confidential', 'secret', 'top_secret']).default('unclassified'),
  billingEmail: z.string().email(),
  contractStartDate: z.string().datetime(),
  contractEndDate: z.string().datetime().optional(),
});

const UpdateTenantSchema = CreateTenantSchema.partial();

const GetTenantsSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  search: z.string().optional(),
  status: z.string().optional(),
  type: z.string().optional(),
  includeStats: z.coerce.boolean().default(false),
  includeHealth: z.coerce.boolean().default(false),
});

/**
 * GET /api/tenants - List tenants with tenant isolation
 */
export async function GET(request: NextRequest) {
  try {
    // Get tenant context from middleware
    const tenantContext = getCurrentTenantContext();
    if (!tenantContext) {
      return NextResponse.json({ error: 'Tenant context required' }, { status: 401 });
    }

    // Validate permissions
    const canListTenants = await validateTenantOperation(tenantContext, 'list', 'tenants');
    if (!canListTenants) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Parse and validate query parameters
    const url = new URL(request.url);
    const queryParams = Object.fromEntries(url.searchParams.entries());
    const params = GetTenantsSchema.parse(queryParams);

    // Build tenant-aware database query
    const dbContext = createTenantDatabaseContext(tenantContext);
    const tenants = await fetchTenantsWithIsolation(params, dbContext);

    // Apply additional filtering based on user role and permissions
    const filteredTenants = filterTenantsByPermissions(tenants, tenantContext);

    return NextResponse.json({
      data: filteredTenants,
      pagination: {
        page: params.page,
        limit: params.limit,
        total: filteredTenants.length,
        hasMore: filteredTenants.length === params.limit,
      },
      metadata: {
        tenantId: tenantContext.tenantId,
        requestId: tenantContext.requestId,
        timestamp: new Date().toISOString(),
      }
    });

  } catch (error) {
    console.error('GET /api/tenants error:', error);
    
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: error.errors },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/tenants - Create new tenant
 */
export async function POST(request: NextRequest) {
  try {
    // Get tenant context from middleware
    const tenantContext = getCurrentTenantContext();
    if (!tenantContext) {
      return NextResponse.json({ error: 'Tenant context required' }, { status: 401 });
    }

    // Validate permissions (only super admins can create tenants)
    const canCreateTenants = await validateTenantOperation(tenantContext, 'create', 'tenants');
    if (!canCreateTenants) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Parse and validate request body
    const body = await request.json();
    const tenantData = CreateTenantSchema.parse(body);

    // Create tenant with PostgreSQL RLS
    const newTenant = await createTenantWithIsolation(tenantData, tenantContext);

    // Initialize tenant isolation (database schema, network policies, etc.)
    await initializeTenantIsolation(newTenant.id);

    // Log tenant creation
    await logTenantEvent(tenantContext, {
      eventType: 'tenant_created',
      resourceId: newTenant.id,
      details: { tenantName: newTenant.name, createdBy: tenantContext.tenantId }
    });

    return NextResponse.json({
      data: newTenant,
      metadata: {
        tenantId: tenantContext.tenantId,
        requestId: tenantContext.requestId,
        timestamp: new Date().toISOString(),
      }
    }, { status: 201 });

  } catch (error) {
    console.error('POST /api/tenants error:', error);
    
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid tenant data', details: error.errors },
        { status: 400 }
      );
    }

    if (error.code === 'TENANT_EXISTS') {
      return NextResponse.json(
        { error: 'Tenant with this domain already exists' },
        { status: 409 }
      );
    }

    return NextResponse.json(
      { error: 'Failed to create tenant' },
      { status: 500 }
    );
  }
}

// Helper functions

function createTenantDatabaseContext(tenantContext: any) {
  return {
    tenantId: tenantContext.tenantId,
    securityClearance: tenantContext.securityClearance,
    userId: tenantContext.userId,
    sessionId: tenantContext.sessionId,
    enableRLS: true,
    auditEnabled: true,
  };
}

async function fetchTenantsWithIsolation(params: any, dbContext: any) {
  // In production, this would execute tenant-aware PostgreSQL queries
  // with Row Level Security automatically filtering results
  
  // Mock implementation
  const mockTenants = [
    {
      id: '123e4567-e89b-12d3-a456-426614174000',
      name: 'acme-corp',
      displayName: 'ACME Corporation',
      type: 'enterprise',
      tier: 'enterprise',
      status: 'active',
      domain: 'acme.com',
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
    }
  ];

  // Apply tenant isolation filter
  return mockTenants.filter(tenant => 
    tenant.id === dbContext.tenantId || 
    hasAccessToTenant(tenant.id, dbContext)
  );
}

function filterTenantsByPermissions(tenants: any[], tenantContext: any) {
  // Apply additional permission-based filtering
  return tenants.filter(tenant => {
    // Super admins see all tenants
    if (tenantContext.permissions.includes('*:*')) {
      return true;
    }
    
    // Users see only their own tenant or explicitly granted tenants
    return tenant.id === tenantContext.tenantId ||
           tenantContext.permissions.includes(`tenant:${tenant.id}:read`);
  });
}

async function createTenantWithIsolation(tenantData: any, tenantContext: any) {
  // In production, this would:
  // 1. Execute INSERT with tenant context
  // 2. Create tenant-specific database schema
  // 3. Initialize Row Level Security policies
  // 4. Set up tenant-specific encryption keys
  
  const newTenant = {
    id: crypto.randomUUID(),
    ...tenantData,
    status: 'provisioning',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: tenantContext.tenantId,
  };

  return newTenant;
}

async function initializeTenantIsolation(tenantId: string) {
  // In production, this would call the Go backend tenant isolation service
  console.log(`Initializing tenant isolation for ${tenantId}`);
  
  // Mock implementation
  return {
    schemaCreated: true,
    rlsEnabled: true,
    networkPoliciesApplied: true,
    encryptionKeysGenerated: true,
  };
}

function hasAccessToTenant(tenantId: string, dbContext: any): boolean {
  // Implement hierarchical tenant access logic
  // For MSP scenarios where parent tenants can access child tenants
  return false;
}

async function logTenantEvent(tenantContext: any, event: any) {
  // In production, this would write to the audit log system
  console.log(`Tenant event: ${event.eventType} for tenant ${tenantContext.tenantId}`, event);
}