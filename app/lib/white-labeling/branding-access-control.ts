/**
 * Branding Access Control Manager for iSECTECH Protect White-Labeling
 * Production-grade role-based access control and audit logging system
 */

import crypto from 'crypto';
import type {
  BrandingPermission,
  BrandingRole,
  BrandingAuditLog,
  BrandingAuditAction,
  WhiteLabelConfiguration,
} from '@/types/white-labeling';
import type { UserRole } from '@/types/security';

export interface AccessControlContext {
  userId: string;
  userEmail: string;
  userRole: UserRole;
  tenantId: string;
  ipAddress: string;
  userAgent: string;
  sessionId?: string;
}

export interface PermissionCheck {
  permission: BrandingPermission;
  resource?: string;
  resourceId?: string;
  context?: Record<string, any>;
}

export interface AccessControlResult {
  granted: boolean;
  reason?: string;
  requiredPermissions?: BrandingPermission[];
  missingPermissions?: BrandingPermission[];
}

export interface AuditLogFilter {
  userId?: string;
  resourceType?: string;
  resourceId?: string;
  action?: BrandingAuditAction;
  success?: boolean;
  startDate?: Date;
  endDate?: Date;
  tenantId?: string;
  limit?: number;
  offset?: number;
}

export interface RiskAssessment {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  score: number;
  factors: string[];
  recommendations: string[];
}

export class BrandingAccessControl {
  private static instance: BrandingAccessControl;
  private permissionCache = new Map<string, { permissions: BrandingPermission[]; timestamp: number }>();
  private roleCache = new Map<string, { role: BrandingRole; timestamp: number }>();
  private readonly CACHE_TTL = 300000; // 5 minutes
  
  private constructor() {}

  public static getInstance(): BrandingAccessControl {
    if (!BrandingAccessControl.instance) {
      BrandingAccessControl.instance = new BrandingAccessControl();
    }
    return BrandingAccessControl.instance;
  }

  /**
   * Check if user has required permission
   */
  public async checkPermission(
    context: AccessControlContext,
    check: PermissionCheck
  ): Promise<AccessControlResult> {
    try {
      // Get user permissions
      const userPermissions = await this.getUserPermissions(context.userId, context.tenantId);
      
      // Check for wildcard permission
      if (userPermissions.includes('brand:*' as BrandingPermission)) {
        await this.logAccess(context, {
          action: 'permission:check',
          resource: check.resource || 'permission',
          resourceId: check.permission,
          success: true,
          details: { granted: true, reason: 'wildcard permission' },
        });
        
        return { granted: true, reason: 'User has wildcard branding permissions' };
      }

      // Check specific permission
      const hasPermission = userPermissions.includes(check.permission);
      
      // Additional context-based checks
      const contextualCheck = await this.performContextualChecks(context, check, userPermissions);
      
      const granted = hasPermission && contextualCheck.granted;
      
      await this.logAccess(context, {
        action: 'permission:check',
        resource: check.resource || 'permission',
        resourceId: check.permission,
        success: granted,
        details: { 
          granted,
          permission: check.permission,
          reason: granted ? 'permission granted' : contextualCheck.reason || 'permission denied',
        },
      });

      return {
        granted,
        reason: granted ? 'Permission granted' : contextualCheck.reason || 'Insufficient permissions',
        requiredPermissions: [check.permission],
        missingPermissions: granted ? [] : [check.permission],
      };

    } catch (error) {
      await this.logAccess(context, {
        action: 'permission:check',
        resource: check.resource || 'permission',
        resourceId: check.permission,
        success: false,
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
      });

      return {
        granted: false,
        reason: 'Error checking permissions',
        requiredPermissions: [check.permission],
        missingPermissions: [check.permission],
      };
    }
  }

  /**
   * Check multiple permissions (requires all)
   */
  public async checkPermissions(
    context: AccessControlContext,
    permissions: BrandingPermission[],
    resource?: string,
    resourceId?: string
  ): Promise<AccessControlResult> {
    const results: AccessControlResult[] = [];
    
    for (const permission of permissions) {
      const result = await this.checkPermission(context, {
        permission,
        resource,
        resourceId,
      });
      results.push(result);
    }

    const granted = results.every(r => r.granted);
    const missingPermissions = results
      .filter(r => !r.granted)
      .flatMap(r => r.missingPermissions || []);

    return {
      granted,
      reason: granted ? 'All permissions granted' : 'Some permissions missing',
      requiredPermissions: permissions,
      missingPermissions,
    };
  }

  /**
   * Check if user can perform action on configuration
   */
  public async canAccessConfiguration(
    context: AccessControlContext,
    configurationId: string,
    action: 'read' | 'write' | 'delete' | 'approve' | 'deploy'
  ): Promise<AccessControlResult> {
    const permissionMap: Record<typeof action, BrandingPermission> = {
      read: 'brand:read',
      write: 'brand:write',
      delete: 'brand:delete',
      approve: 'brand:approve',
      deploy: 'brand:deploy',
    };

    return this.checkPermission(context, {
      permission: permissionMap[action],
      resource: 'configuration',
      resourceId: configurationId,
    });
  }

  /**
   * Create new branding role
   */
  public async createBrandingRole(
    context: AccessControlContext,
    roleData: {
      name: string;
      description: string;
      permissions: BrandingPermission[];
      isDefault?: boolean;
    }
  ): Promise<BrandingRole> {
    // Check permissions
    const permissionCheck = await this.checkPermission(context, {
      permission: 'brand:admin',
      resource: 'role',
    });

    if (!permissionCheck.granted) {
      throw new Error('Insufficient permissions to create branding role');
    }

    // Validate role data
    if (!roleData.name || !roleData.description || !roleData.permissions.length) {
      throw new Error('Role name, description, and permissions are required');
    }

    // Create role
    const role: BrandingRole = {
      id: this.generateId(),
      name: roleData.name,
      description: roleData.description,
      permissions: roleData.permissions,
      isDefault: roleData.isDefault || false,
      tenantId: context.tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: context.userId,
      updatedBy: context.userId,
    };

    // Save role
    await this.saveRole(role);

    // Log activity
    await this.logAccess(context, {
      action: 'role:create',
      resource: 'role',
      resourceId: role.id,
      success: true,
      details: {
        roleName: role.name,
        permissions: role.permissions,
      },
    });

    // Clear cache
    this.clearRoleCache(context.tenantId);

    return role;
  }

  /**
   * Update branding role
   */
  public async updateBrandingRole(
    context: AccessControlContext,
    roleId: string,
    updates: Partial<BrandingRole>
  ): Promise<BrandingRole> {
    // Check permissions
    const permissionCheck = await this.checkPermission(context, {
      permission: 'brand:admin',
      resource: 'role',
      resourceId: roleId,
    });

    if (!permissionCheck.granted) {
      throw new Error('Insufficient permissions to update branding role');
    }

    // Get existing role
    const existingRole = await this.getRole(roleId, context.tenantId);
    if (!existingRole) {
      throw new Error('Role not found');
    }

    // Apply updates
    const updatedRole: BrandingRole = {
      ...existingRole,
      ...updates,
      updatedAt: new Date(),
      updatedBy: context.userId,
    };

    // Save updated role
    await this.saveRole(updatedRole);

    // Log activity
    await this.logAccess(context, {
      action: 'role:update',
      resource: 'role',
      resourceId: roleId,
      success: true,
      details: {
        updates,
        previousPermissions: existingRole.permissions,
        newPermissions: updatedRole.permissions,
      },
    });

    // Clear cache
    this.clearRoleCache(context.tenantId);

    return updatedRole;
  }

  /**
   * Assign role to user
   */
  public async assignRole(
    context: AccessControlContext,
    targetUserId: string,
    roleId: string
  ): Promise<void> {
    // Check permissions
    const permissionCheck = await this.checkPermission(context, {
      permission: 'brand:admin',
      resource: 'user_role',
    });

    if (!permissionCheck.granted) {
      throw new Error('Insufficient permissions to assign role');
    }

    // Get role to validate it exists
    const role = await this.getRole(roleId, context.tenantId);
    if (!role) {
      throw new Error('Role not found');
    }

    // Assign role
    await this.assignUserRole(targetUserId, roleId, context.tenantId);

    // Log activity
    await this.logAccess(context, {
      action: 'role:assign',
      resource: 'user_role',
      resourceId: `${targetUserId}:${roleId}`,
      success: true,
      details: {
        targetUserId,
        roleId,
        roleName: role.name,
      },
    });

    // Clear user permission cache
    this.clearUserPermissionCache(targetUserId, context.tenantId);
  }

  /**
   * Remove role from user
   */
  public async removeRole(
    context: AccessControlContext,
    targetUserId: string,
    roleId: string
  ): Promise<void> {
    // Check permissions
    const permissionCheck = await this.checkPermission(context, {
      permission: 'brand:admin',
      resource: 'user_role',
    });

    if (!permissionCheck.granted) {
      throw new Error('Insufficient permissions to remove role');
    }

    // Remove role assignment
    await this.removeUserRole(targetUserId, roleId, context.tenantId);

    // Log activity
    await this.logAccess(context, {
      action: 'role:remove',
      resource: 'user_role',
      resourceId: `${targetUserId}:${roleId}`,
      success: true,
      details: {
        targetUserId,
        roleId,
      },
    });

    // Clear user permission cache
    this.clearUserPermissionCache(targetUserId, context.tenantId);
  }

  /**
   * Get audit logs
   */
  public async getAuditLogs(
    context: AccessControlContext,
    filter: AuditLogFilter = {}
  ): Promise<{ logs: BrandingAuditLog[]; total: number }> {
    // Check permissions
    const permissionCheck = await this.checkPermission(context, {
      permission: 'brand:audit',
      resource: 'audit_log',
    });

    if (!permissionCheck.granted) {
      throw new Error('Insufficient permissions to view audit logs');
    }

    // Apply tenant filter
    const tenantFilter = { ...filter, tenantId: context.tenantId };

    // Fetch logs
    const result = await this.fetchAuditLogs(tenantFilter);

    // Log access to audit logs
    await this.logAccess(context, {
      action: 'audit:view',
      resource: 'audit_log',
      resourceId: 'query',
      success: true,
      details: {
        filter: tenantFilter,
        resultCount: result.logs.length,
      },
    });

    return result;
  }

  /**
   * Assess security risk of branding changes
   */
  public async assessRisk(
    context: AccessControlContext,
    configuration: WhiteLabelConfiguration,
    changes?: Partial<WhiteLabelConfiguration>
  ): Promise<RiskAssessment> {
    const factors: string[] = [];
    let score = 0;

    // Check for domain changes
    if (changes?.domain || configuration.domain) {
      factors.push('Custom domain configuration');
      score += 20;
    }

    // Check for asset uploads
    if (changes?.theme?.assets || configuration.theme?.assets) {
      const assetCount = Object.values(configuration.theme?.assets || {}).filter(Boolean).length;
      if (assetCount > 0) {
        factors.push(`${assetCount} brand assets`);
        score += assetCount * 5;
      }
    }

    // Check for content customizations
    if (changes?.content || configuration.content?.length) {
      factors.push('Content customizations');
      score += 10;
    }

    // Check for email template changes
    if (changes?.emailTemplates || configuration.emailTemplates?.length) {
      factors.push('Email template customizations');
      score += 15;
    }

    // Check user permissions and role
    const userPermissions = await this.getUserPermissions(context.userId, context.tenantId);
    if (!userPermissions.includes('brand:admin')) {
      factors.push('Non-admin user making changes');
      score += 10;
    }

    // Check for off-hours activity
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) {
      factors.push('Off-hours activity');
      score += 15;
    }

    // Determine risk level
    let riskLevel: RiskAssessment['riskLevel'];
    if (score >= 60) {
      riskLevel = 'CRITICAL';
    } else if (score >= 40) {
      riskLevel = 'HIGH';
    } else if (score >= 20) {
      riskLevel = 'MEDIUM';
    } else {
      riskLevel = 'LOW';
    }

    // Generate recommendations
    const recommendations: string[] = [];
    if (score >= 40) {
      recommendations.push('Consider requiring additional approval');
      recommendations.push('Enable enhanced monitoring');
    }
    if (configuration.domain) {
      recommendations.push('Verify domain ownership');
      recommendations.push('Monitor DNS changes');
    }
    if (userPermissions.includes('brand:admin')) {
      recommendations.push('Review admin access logs');
    }

    return {
      riskLevel,
      score,
      factors,
      recommendations,
    };
  }

  /**
   * Create access control middleware for API endpoints
   */
  public createMiddleware(requiredPermissions: BrandingPermission[]) {
    return async (req: any, res: any, next: any) => {
      try {
        const context: AccessControlContext = {
          userId: req.user?.id || 'anonymous',
          userEmail: req.user?.email || '',
          userRole: req.user?.role || 'READ_ONLY',
          tenantId: req.user?.tenantId || '',
          ipAddress: req.ip || req.connection?.remoteAddress || '',
          userAgent: req.get('User-Agent') || '',
          sessionId: req.sessionID,
        };

        const result = await this.checkPermissions(context, requiredPermissions);
        
        if (!result.granted) {
          return res.status(403).json({
            error: 'Access denied',
            message: result.reason,
            requiredPermissions,
            missingPermissions: result.missingPermissions,
          });
        }

        // Add context to request for use in handlers
        req.brandingContext = context;
        next();
        
      } catch (error) {
        return res.status(500).json({
          error: 'Access control error',
          message: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    };
  }

  // Private helper methods

  private async performContextualChecks(
    context: AccessControlContext,
    check: PermissionCheck,
    userPermissions: BrandingPermission[]
  ): Promise<AccessControlResult> {
    // Check for tenant isolation
    if (check.resourceId && check.resource === 'configuration') {
      const config = await this.getConfigurationMeta(check.resourceId);
      if (config && config.tenantId !== context.tenantId) {
        return {
          granted: false,
          reason: 'Cross-tenant access denied',
        };
      }
    }

    // Check for time-based restrictions
    const hour = new Date().getHours();
    if (check.permission === 'brand:deploy' && (hour < 6 || hour > 22)) {
      // Allow with elevated permissions during off-hours
      if (!userPermissions.includes('brand:admin')) {
        return {
          granted: false,
          reason: 'Deployment restricted during off-hours without admin privileges',
        };
      }
    }

    return { granted: true };
  }

  private async getUserPermissions(userId: string, tenantId: string): Promise<BrandingPermission[]> {
    const cacheKey = `${userId}:${tenantId}`;
    
    // Check cache
    const cached = this.permissionCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.permissions;
    }

    // Fetch from database
    const permissions = await this.fetchUserPermissions(userId, tenantId);
    
    // Cache result
    this.permissionCache.set(cacheKey, {
      permissions,
      timestamp: Date.now(),
    });

    return permissions;
  }

  private async logAccess(
    context: AccessControlContext,
    logData: {
      action: BrandingAuditAction | string;
      resource: string;
      resourceId: string;
      success: boolean;
      details?: Record<string, any>;
      error?: string;
    }
  ): Promise<void> {
    const auditLog: BrandingAuditLog = {
      id: this.generateId(),
      action: logData.action as BrandingAuditAction,
      resourceType: logData.resource,
      resourceId: logData.resourceId,
      userId: context.userId,
      userEmail: context.userEmail,
      details: logData.details || {},
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      success: logData.success,
      error: logData.error,
      tenantId: context.tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: context.userId,
      updatedBy: context.userId,
    };

    await this.saveAuditLog(auditLog);
  }

  private clearUserPermissionCache(userId: string, tenantId: string): void {
    this.permissionCache.delete(`${userId}:${tenantId}`);
  }

  private clearRoleCache(tenantId: string): void {
    for (const key of this.roleCache.keys()) {
      if (key.endsWith(`:${tenantId}`)) {
        this.roleCache.delete(key);
      }
    }
  }

  private generateId(): string {
    return `access_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  // Mock database operations - would be replaced with actual database calls

  private async fetchUserPermissions(userId: string, tenantId: string): Promise<BrandingPermission[]> {
    // Mock implementation - would fetch from database
    const defaultPermissions: BrandingPermission[] = ['brand:read'];
    
    // Super admins get all permissions
    if (userId === 'super-admin') {
      return [
        'brand:read',
        'brand:write',
        'brand:delete',
        'brand:approve',
        'brand:deploy',
        'brand:audit',
        'brand:admin',
      ];
    }

    return defaultPermissions;
  }

  private async getRole(roleId: string, tenantId: string): Promise<BrandingRole | null> {
    // Mock implementation
    return null;
  }

  private async saveRole(role: BrandingRole): Promise<void> {
    // Mock implementation
    console.log('Saving branding role:', role);
  }

  private async assignUserRole(userId: string, roleId: string, tenantId: string): Promise<void> {
    // Mock implementation
    console.log(`Assigning role ${roleId} to user ${userId} in tenant ${tenantId}`);
  }

  private async removeUserRole(userId: string, roleId: string, tenantId: string): Promise<void> {
    // Mock implementation
    console.log(`Removing role ${roleId} from user ${userId} in tenant ${tenantId}`);
  }

  private async fetchAuditLogs(filter: AuditLogFilter): Promise<{ logs: BrandingAuditLog[]; total: number }> {
    // Mock implementation
    return { logs: [], total: 0 };
  }

  private async saveAuditLog(log: BrandingAuditLog): Promise<void> {
    // Mock implementation - would save to database
    console.log('Audit Log:', {
      action: log.action,
      resource: `${log.resourceType}:${log.resourceId}`,
      user: log.userEmail,
      success: log.success,
      timestamp: log.createdAt.toISOString(),
    });
  }

  private async getConfigurationMeta(configId: string): Promise<{ tenantId: string } | null> {
    // Mock implementation
    return null;
  }
}

// Export singleton instance
export const brandingAccessControl = BrandingAccessControl.getInstance();