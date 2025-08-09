/**
 * RBAC Permission Service
 * Integrates permission checking with hierarchical RBAC system
 * 
 * Task: 81.5 - Integrate permission checking with RBAC system
 */

import { Pool, PoolClient } from 'pg';
import { createClient } from 'redis';

// Permission check types
export interface PermissionCheckRequest {
  userId: string;
  tenantId: string;
  permissions: string[];
  context?: Record<string, any>;
}

export interface PermissionCheckResult {
  allowed: boolean;
  grantedPermissions: string[];
  deniedPermissions: string[];
  effectiveRoles: string[];
  roleHierarchy: RoleHierarchyNode[];
  cacheHit: boolean;
  evaluationTimeMs: number;
}

export interface RoleHierarchyNode {
  roleId: string;
  roleName: string;
  permissions: string[];
  parentRoles: string[];
  childRoles: string[];
  isDirectlyAssigned: boolean;
}

export interface UserRolePermissions {
  userId: string;
  tenantId: string;
  directRoles: string[];
  inheritedRoles: string[];
  allPermissions: Set<string>;
  roleHierarchy: Map<string, RoleHierarchyNode>;
}

export interface PermissionConstraint {
  key: string;
  operator: 'equals' | 'in' | 'not_in' | 'greater_than' | 'less_than' | 'regex';
  value: any;
}

export interface PermissionContext {
  resourceId?: string;
  resourceType?: string;
  action?: string;
  ipAddress?: string;
  timeOfDay?: string;
  dayOfWeek?: string;
  environment?: string;
  [key: string]: any;
}

export class RBACPermissionService {
  private pgPool: Pool;
  private redisClient?: ReturnType<typeof createClient>;
  private cacheEnabled: boolean;
  private cacheTTL: number;

  constructor(
    pgPool: Pool,
    redisClient?: ReturnType<typeof createClient>,
    options: {
      cacheEnabled?: boolean;
      cacheTTL?: number;
    } = {}
  ) {
    this.pgPool = pgPool;
    this.redisClient = redisClient;
    this.cacheEnabled = options.cacheEnabled ?? true;
    this.cacheTTL = options.cacheTTL ?? 300; // 5 minutes
  }

  /**
   * Main permission checking method with hierarchy support
   */
  async checkPermissions(request: PermissionCheckRequest): Promise<PermissionCheckResult> {
    const startTime = Date.now();

    try {
      // Check cache first
      const cacheKey = this.buildPermissionCacheKey(
        request.userId, 
        request.tenantId, 
        request.permissions
      );

      if (this.cacheEnabled && this.redisClient) {
        const cached = await this.getCachedPermissions(cacheKey);
        if (cached) {
          cached.evaluationTimeMs = Date.now() - startTime;
          cached.cacheHit = true;
          return cached;
        }
      }

      // Load user's complete role and permission structure
      const userPermissions = await this.loadUserRolePermissions(
        request.userId, 
        request.tenantId
      );

      // Evaluate permissions against role hierarchy
      const evaluationResult = this.evaluatePermissions(
        request.permissions,
        userPermissions,
        request.context
      );

      const result: PermissionCheckResult = {
        allowed: evaluationResult.allowed,
        grantedPermissions: evaluationResult.grantedPermissions,
        deniedPermissions: evaluationResult.deniedPermissions,
        effectiveRoles: Array.from(userPermissions.roleHierarchy.keys()),
        roleHierarchy: Array.from(userPermissions.roleHierarchy.values()),
        cacheHit: false,
        evaluationTimeMs: Date.now() - startTime
      };

      // Cache the result
      if (this.cacheEnabled && this.redisClient && result.allowed) {
        await this.cachePermissions(cacheKey, result);
      }

      return result;

    } catch (error) {
      console.error('RBAC permission check error:', error);
      
      return {
        allowed: false,
        grantedPermissions: [],
        deniedPermissions: request.permissions,
        effectiveRoles: [],
        roleHierarchy: [],
        cacheHit: false,
        evaluationTimeMs: Date.now() - startTime
      };
    }
  }

  /**
   * Load user's complete role and permission structure with hierarchy
   */
  private async loadUserRolePermissions(
    userId: string, 
    tenantId: string
  ): Promise<UserRolePermissions> {
    
    const client = await this.pgPool.connect();
    
    try {
      // Set tenant context for RLS
      if (tenantId !== 'system') {
        await client.query('SET app.current_tenant_id = $1', [tenantId]);
      }

      // Get user's direct role assignments
      const directRolesResult = await client.query(`
        SELECT 
          ur.role_id,
          r.name as role_name
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = $1 AND ur.tenant_id = $2
      `, [userId, tenantId]);

      const directRoles = directRolesResult.rows.map(row => row.role_name);
      const directRoleIds = directRolesResult.rows.map(row => row.role_id);

      // Get complete role hierarchy for user's roles
      const hierarchyResult = await client.query(`
        WITH RECURSIVE role_tree AS (
          -- Start with user's direct roles
          SELECT 
            r.id as role_id,
            r.name as role_name,
            ur.role_id as assigned_role_id,
            0 as level,
            ARRAY[r.name] as path,
            true as is_direct
          FROM user_roles ur
          JOIN roles r ON ur.role_id = r.id
          WHERE ur.user_id = $1 AND ur.tenant_id = $2
          
          UNION ALL
          
          -- Recursively get parent roles
          SELECT 
            pr.id as role_id,
            pr.name as role_name,
            rt.assigned_role_id,
            rt.level + 1 as level,
            rt.path || pr.name,
            false as is_direct
          FROM role_tree rt
          JOIN role_hierarchy rh ON rt.role_id = rh.child_role_id
          JOIN roles pr ON rh.parent_role_id = pr.id
          WHERE rh.tenant_id = $2
            AND NOT pr.name = ANY(rt.path) -- Prevent cycles
            AND rt.level < 10 -- Prevent infinite recursion
        )
        SELECT DISTINCT
          rt.role_id,
          rt.role_name,
          rt.is_direct,
          rt.level,
          array_agg(DISTINCT p.resource_namespace || ':' || p.resource || ':' || p.action) 
            FILTER (WHERE p.id IS NOT NULL) as permissions,
          array_agg(DISTINCT parent_r.name) 
            FILTER (WHERE parent_r.name IS NOT NULL) as parent_roles,
          array_agg(DISTINCT child_r.name) 
            FILTER (WHERE child_r.name IS NOT NULL) as child_roles
        FROM role_tree rt
        LEFT JOIN role_permissions rp ON rt.role_id = rp.role_id AND rp.tenant_id = $2
        LEFT JOIN permissions p ON rp.permission_id = p.id
        LEFT JOIN role_hierarchy rh_parent ON rt.role_id = rh_parent.child_role_id AND rh_parent.tenant_id = $2
        LEFT JOIN roles parent_r ON rh_parent.parent_role_id = parent_r.id
        LEFT JOIN role_hierarchy rh_child ON rt.role_id = rh_child.parent_role_id AND rh_child.tenant_id = $2
        LEFT JOIN roles child_r ON rh_child.child_role_id = child_r.id
        GROUP BY rt.role_id, rt.role_name, rt.is_direct, rt.level
        ORDER BY rt.level, rt.role_name
      `, [userId, tenantId]);

      // Build role hierarchy map
      const roleHierarchy = new Map<string, RoleHierarchyNode>();
      const allPermissions = new Set<string>();
      const inheritedRoles: string[] = [];

      for (const row of hierarchyResult.rows) {
        const permissions = row.permissions || [];
        const parentRoles = row.parent_roles || [];
        const childRoles = row.child_roles || [];

        // Add permissions to global set
        permissions.forEach((perm: string) => allPermissions.add(perm));

        // Track inherited roles
        if (!row.is_direct) {
          inheritedRoles.push(row.role_name);
        }

        // Build hierarchy node
        roleHierarchy.set(row.role_name, {
          roleId: row.role_id,
          roleName: row.role_name,
          permissions,
          parentRoles,
          childRoles,
          isDirectlyAssigned: row.is_direct
        });
      }

      return {
        userId,
        tenantId,
        directRoles,
        inheritedRoles,
        allPermissions,
        roleHierarchy
      };

    } finally {
      client.release();
    }
  }

  /**
   * Evaluate permissions against user's role hierarchy
   */
  private evaluatePermissions(
    requiredPermissions: string[],
    userPermissions: UserRolePermissions,
    context?: Record<string, any>
  ): {
    allowed: boolean;
    grantedPermissions: string[];
    deniedPermissions: string[];
  } {
    
    const grantedPermissions: string[] = [];
    const deniedPermissions: string[] = [];

    for (const permission of requiredPermissions) {
      if (this.hasPermission(permission, userPermissions, context)) {
        grantedPermissions.push(permission);
      } else {
        deniedPermissions.push(permission);
      }
    }

    return {
      allowed: deniedPermissions.length === 0,
      grantedPermissions,
      deniedPermissions
    };
  }

  /**
   * Check if user has a specific permission considering role hierarchy
   */
  private hasPermission(
    permission: string,
    userPermissions: UserRolePermissions,
    context?: Record<string, any>
  ): boolean {
    
    // Direct permission check
    if (userPermissions.allPermissions.has(permission)) {
      return this.checkPermissionConstraints(permission, context);
    }

    // Wildcard permission check (e.g., assets:* matches assets:read)
    const [namespace, resource, action] = permission.split(':');
    const wildcardPatterns = [
      `${namespace}:*:*`,
      `${namespace}:${resource}:*`,
      `*:*:*`
    ];

    for (const pattern of wildcardPatterns) {
      if (userPermissions.allPermissions.has(pattern)) {
        return this.checkPermissionConstraints(pattern, context);
      }
    }

    // Check role-specific permissions with inheritance
    return this.checkRoleBasedPermission(permission, userPermissions, context);
  }

  /**
   * Check permission constraints (ABAC-style attributes)
   */
  private checkPermissionConstraints(
    permission: string,
    context?: Record<string, any>
  ): boolean {
    
    if (!context) {
      return true; // No constraints to check
    }

    // This would implement ABAC-style constraint checking
    // For now, simplified implementation
    
    // Example: Time-based access restrictions
    if (context.timeRestricted && context.currentTime) {
      const currentHour = new Date(context.currentTime).getHours();
      if (currentHour < 8 || currentHour > 18) {
        return false; // Outside business hours
      }
    }

    // Example: IP-based restrictions
    if (context.ipRestricted && context.ipAddress) {
      const allowedNetworks = context.allowedNetworks || [];
      if (allowedNetworks.length > 0) {
        // Simplified IP check - in production use proper CIDR matching
        const userIP = context.ipAddress;
        const allowed = allowedNetworks.some((network: string) => 
          userIP.startsWith(network)
        );
        if (!allowed) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Check role-based permission with hierarchy consideration
   */
  private checkRoleBasedPermission(
    permission: string,
    userPermissions: UserRolePermissions,
    context?: Record<string, any>
  ): boolean {
    
    // Check each role in hierarchy
    for (const [roleName, roleNode] of userPermissions.roleHierarchy) {
      if (roleNode.permissions.includes(permission)) {
        // Check role-specific constraints
        if (this.checkRoleConstraints(roleName, context)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check role-specific constraints
   */
  private checkRoleConstraints(
    roleName: string,
    context?: Record<string, any>
  ): boolean {
    
    if (!context) {
      return true;
    }

    // Role-specific constraint examples
    switch (roleName) {
      case 'admin':
        // Admins might require MFA for sensitive operations
        if (context.requiresMFA && !context.mfaVerified) {
          return false;
        }
        break;
        
      case 'security_officer':
        // Security officers might be restricted by clearance level
        if (context.requiredClearance && 
            context.userClearance < context.requiredClearance) {
          return false;
        }
        break;
        
      case 'analyst':
        // Analysts might have time-based restrictions
        if (context.businessHoursOnly) {
          const hour = new Date().getHours();
          if (hour < 8 || hour > 18) {
            return false;
          }
        }
        break;
    }

    return true;
  }

  /**
   * Get user's effective roles with hierarchy
   */
  async getUserRoles(userId: string, tenantId: string): Promise<{
    directRoles: string[];
    inheritedRoles: string[];
    allRoles: string[];
    roleHierarchy: RoleHierarchyNode[];
  }> {
    
    const userPermissions = await this.loadUserRolePermissions(userId, tenantId);
    
    return {
      directRoles: userPermissions.directRoles,
      inheritedRoles: userPermissions.inheritedRoles,
      allRoles: [...userPermissions.directRoles, ...userPermissions.inheritedRoles],
      roleHierarchy: Array.from(userPermissions.roleHierarchy.values())
    };
  }

  /**
   * Get all permissions for a user (direct and inherited)
   */
  async getUserPermissions(userId: string, tenantId: string): Promise<{
    allPermissions: string[];
    permissionsByRole: Record<string, string[]>;
    roleHierarchy: RoleHierarchyNode[];
  }> {
    
    const userPermissions = await this.loadUserRolePermissions(userId, tenantId);
    
    const permissionsByRole: Record<string, string[]> = {};
    for (const [roleName, roleNode] of userPermissions.roleHierarchy) {
      permissionsByRole[roleName] = roleNode.permissions;
    }
    
    return {
      allPermissions: Array.from(userPermissions.allPermissions),
      permissionsByRole,
      roleHierarchy: Array.from(userPermissions.roleHierarchy.values())
    };
  }

  /**
   * Check if user has any of the specified roles (with hierarchy)
   */
  async hasAnyRole(
    userId: string, 
    tenantId: string, 
    roles: string[]
  ): Promise<boolean> {
    
    const userRoles = await this.getUserRoles(userId, tenantId);
    return roles.some(role => userRoles.allRoles.includes(role));
  }

  /**
   * Check if user has all specified roles (with hierarchy)
   */
  async hasAllRoles(
    userId: string, 
    tenantId: string, 
    roles: string[]
  ): Promise<boolean> {
    
    const userRoles = await this.getUserRoles(userId, tenantId);
    return roles.every(role => userRoles.allRoles.includes(role));
  }

  /**
   * Invalidate cached permissions for user
   */
  async invalidateUserPermissions(userId: string, tenantId: string): Promise<void> {
    if (!this.redisClient) return;

    try {
      // Get all cache keys for this user
      const pattern = `rbac:perm:${userId}:${tenantId}:*`;
      const keys = await this.redisClient.keys(pattern);
      
      if (keys.length > 0) {
        await this.redisClient.del(...keys);
      }
    } catch (error) {
      console.error('Failed to invalidate user permissions cache:', error);
    }
  }

  /**
   * Invalidate all permissions cache for tenant
   */
  async invalidateTenantPermissions(tenantId: string): Promise<void> {
    if (!this.redisClient) return;

    try {
      const pattern = `rbac:perm:*:${tenantId}:*`;
      const keys = await this.redisClient.keys(pattern);
      
      if (keys.length > 0) {
        await this.redisClient.del(...keys);
      }
    } catch (error) {
      console.error('Failed to invalidate tenant permissions cache:', error);
    }
  }

  /**
   * Helper methods for caching
   */
  private buildPermissionCacheKey(
    userId: string, 
    tenantId: string, 
    permissions: string[]
  ): string {
    const permissionHash = Buffer.from(permissions.sort().join(',')).toString('base64');
    return `rbac:perm:${userId}:${tenantId}:${permissionHash}`;
  }

  private async getCachedPermissions(cacheKey: string): Promise<PermissionCheckResult | null> {
    if (!this.redisClient) return null;

    try {
      const cached = await this.redisClient.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error) {
      console.error('Failed to get cached permissions:', error);
    }
    
    return null;
  }

  private async cachePermissions(
    cacheKey: string, 
    result: PermissionCheckResult
  ): Promise<void> {
    if (!this.redisClient) return;

    try {
      await this.redisClient.setex(
        cacheKey,
        this.cacheTTL,
        JSON.stringify(result)
      );
    } catch (error) {
      console.error('Failed to cache permissions:', error);
    }
  }
}

/**
 * Factory function to create RBAC permission service
 */
export function createRBACPermissionService(
  pgPool?: Pool,
  redisClient?: ReturnType<typeof createClient>,
  options?: {
    cacheEnabled?: boolean;
    cacheTTL?: number;
  }
): RBACPermissionService {
  
  const pool = pgPool || new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432'),
    database: process.env.POSTGRES_DB || 'isectech',
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  const redis = redisClient || createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    password: process.env.REDIS_PASSWORD
  });

  return new RBACPermissionService(pool, redis, options);
}

// Export service instance
export const rbacPermissionService = createRBACPermissionService();