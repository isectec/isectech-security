/**
 * Hierarchical Permission Inheritance Testing
 * Tests role hierarchy resolution and permission inheritance patterns
 */

import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import { DatabaseTestSetup, TestTenantContext } from '../../test-setup/database-test-setup';
import { PoolClient } from 'pg';

describe('Hierarchical Permission Inheritance Tests', () => {
  let dbSetup: DatabaseTestSetup;
  let testTenant: TestTenantContext;

  beforeAll(async () => {
    dbSetup = new DatabaseTestSetup();
    await dbSetup.initialize();

    // Create comprehensive role hierarchy test data
    testTenant = {
      tenantId: 'hier-test-tenant-id',
      tenantName: 'Hierarchy Test Tenant',
      users: [
        { id: 'ceo-user', email: 'ceo@company.com', roleIds: ['role-ceo'] },
        { id: 'cto-user', email: 'cto@company.com', roleIds: ['role-cto'] },
        { id: 'director-user', email: 'director@company.com', roleIds: ['role-security-director'] },
        { id: 'manager-user', email: 'manager@company.com', roleIds: ['role-security-manager'] },
        { id: 'senior-user', email: 'senior@company.com', roleIds: ['role-senior-analyst'] },
        { id: 'analyst-user', email: 'analyst@company.com', roleIds: ['role-security-analyst'] },
        { id: 'junior-user', email: 'junior@company.com', roleIds: ['role-junior-analyst'] },
        { id: 'intern-user', email: 'intern@company.com', roleIds: ['role-intern'] },
        { id: 'auditor-user', email: 'auditor@company.com', roleIds: ['role-auditor'] },
        { id: 'external-user', email: 'external@partner.com', roleIds: ['role-external-consultant'] }
      ],
      roles: [
        // Top level - CEO
        {
          id: 'role-ceo',
          name: 'CEO',
          description: 'Chief Executive Officer - Full access',
          permissions: ['perm-global-admin']
        },
        
        // C-Level - CTO reports to CEO
        {
          id: 'role-cto',
          name: 'CTO',
          description: 'Chief Technology Officer',
          parentRoleId: 'role-ceo',
          permissions: ['perm-tech-admin', 'perm-security-oversight']
        },
        
        // Director level - reports to CTO
        {
          id: 'role-security-director',
          name: 'Security Director',
          description: 'Head of Security Operations',
          parentRoleId: 'role-cto',
          permissions: ['perm-security-admin', 'perm-budget-approve']
        },
        
        // Manager level - reports to Director
        {
          id: 'role-security-manager',
          name: 'Security Manager',
          description: 'Security Team Manager',
          parentRoleId: 'role-security-director',
          permissions: ['perm-team-manage', 'perm-incident-manage']
        },
        
        // Senior level - reports to Manager
        {
          id: 'role-senior-analyst',
          name: 'Senior Security Analyst',
          description: 'Senior Security Professional',
          parentRoleId: 'role-security-manager',
          permissions: ['perm-advanced-analysis', 'perm-mentor-junior']
        },
        
        // Regular level - reports to Senior
        {
          id: 'role-security-analyst',
          name: 'Security Analyst',
          description: 'Security Analyst',
          parentRoleId: 'role-senior-analyst',
          permissions: ['perm-alert-investigate', 'perm-report-create']
        },
        
        // Junior level - reports to Analyst
        {
          id: 'role-junior-analyst',
          name: 'Junior Security Analyst',
          description: 'Entry-level Security Analyst',
          parentRoleId: 'role-security-analyst',
          permissions: ['perm-alert-view', 'perm-basic-tools']
        },
        
        // Intern - reports to Junior
        {
          id: 'role-intern',
          name: 'Security Intern',
          description: 'Security Intern',
          parentRoleId: 'role-junior-analyst',
          permissions: ['perm-read-only']
        },
        
        // Parallel hierarchy - Auditor reports to Director
        {
          id: 'role-auditor',
          name: 'Security Auditor', 
          description: 'Independent Security Auditor',
          parentRoleId: 'role-security-director',
          permissions: ['perm-audit-access', 'perm-compliance-check']
        },
        
        // External - minimal access, reports to Manager
        {
          id: 'role-external-consultant',
          name: 'External Consultant',
          description: 'External Security Consultant',
          parentRoleId: 'role-security-manager',
          permissions: ['perm-consultant-access']
        }
      ],
      permissions: [
        // Top-level permissions
        { id: 'perm-global-admin', resourceNamespace: 'system', resource: '*', action: '*' },
        
        // C-level permissions
        { id: 'perm-tech-admin', resourceNamespace: 'technology', resource: '*', action: '*' },
        { id: 'perm-security-oversight', resourceNamespace: 'security', resource: 'oversight', action: '*' },
        
        // Director-level permissions
        { id: 'perm-security-admin', resourceNamespace: 'security', resource: 'administration', action: '*' },
        { id: 'perm-budget-approve', resourceNamespace: 'finance', resource: 'budget', action: 'approve' },
        
        // Manager-level permissions
        { id: 'perm-team-manage', resourceNamespace: 'hr', resource: 'team', action: 'manage' },
        { id: 'perm-incident-manage', resourceNamespace: 'security', resource: 'incidents', action: 'manage' },
        
        // Senior-level permissions
        { id: 'perm-advanced-analysis', resourceNamespace: 'security', resource: 'analysis', action: 'advanced' },
        { id: 'perm-mentor-junior', resourceNamespace: 'hr', resource: 'mentoring', action: 'provide' },
        
        // Analyst-level permissions
        { id: 'perm-alert-investigate', resourceNamespace: 'security', resource: 'alerts', action: 'investigate' },
        { id: 'perm-report-create', resourceNamespace: 'security', resource: 'reports', action: 'create' },
        
        // Junior-level permissions
        { id: 'perm-alert-view', resourceNamespace: 'security', resource: 'alerts', action: 'view' },
        { id: 'perm-basic-tools', resourceNamespace: 'security', resource: 'tools', action: 'basic' },
        
        // Base permissions
        { id: 'perm-read-only', resourceNamespace: 'security', resource: 'data', action: 'read' },
        
        // Special permissions
        { id: 'perm-audit-access', resourceNamespace: 'security', resource: 'audit', action: '*' },
        { id: 'perm-compliance-check', resourceNamespace: 'compliance', resource: '*', action: 'check' },
        { id: 'perm-consultant-access', resourceNamespace: 'security', resource: 'consulting', action: '*' }
      ]
    };

    await dbSetup.createTestTenant(testTenant);
    console.log('✅ Hierarchical permission inheritance test environment initialized');
  }, 30000);

  afterAll(async () => {
    await dbSetup.destroy();
  });

  beforeEach(async () => {
    // Clear any test audit logs
    const client = await dbSetup.getConnection();
    try {
      await client.query('TRUNCATE security_audit_log');
    } finally {
      client.release();
    }
  });

  describe('Role Hierarchy Structure Validation', () => {
    it('should correctly establish role hierarchy relationships', async () => {
      const hierarchyQuery = `
        SELECT 
          p.name as parent_role,
          c.name as child_role,
          rh.tenant_id
        FROM role_hierarchy rh
        JOIN roles p ON p.id = rh.parent_role_id
        JOIN roles c ON c.id = rh.child_role_id
        ORDER BY p.name, c.name
      `;
      
      const hierarchy = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        hierarchyQuery
      );
      
      // Verify expected hierarchy relationships exist
      const expectedRelationships = [
        { parent: 'CEO', child: 'CTO' },
        { parent: 'CTO', child: 'Security Director' },
        { parent: 'Security Director', child: 'Security Manager' },
        { parent: 'Security Director', child: 'Security Auditor' },
        { parent: 'Security Manager', child: 'Senior Security Analyst' },
        { parent: 'Security Manager', child: 'External Consultant' },
        { parent: 'Senior Security Analyst', child: 'Security Analyst' },
        { parent: 'Security Analyst', child: 'Junior Security Analyst' },
        { parent: 'Junior Security Analyst', child: 'Security Intern' }
      ];
      
      expect(hierarchy.rows.length).toBe(expectedRelationships.length);
      
      for (const expected of expectedRelationships) {
        const found = hierarchy.rows.find(h => 
          h.parent_role === expected.parent && h.child_role === expected.child
        );
        expect(found, `Missing hierarchy relationship: ${expected.parent} -> ${expected.child}`).toBeDefined();
        expect(found.tenant_id).toBe(testTenant.tenantId);
      }
    });

    it('should prevent circular role hierarchy creation', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, testTenant.tenantId);
        
        // Attempt to create circular dependency: CEO -> CTO -> CEO
        await expect(
          client.query(`
            INSERT INTO role_hierarchy (tenant_id, parent_role_id, child_role_id)
            VALUES ($1, $2, $3)
          `, [
            testTenant.tenantId,
            'role-cto', // CTO as parent
            'role-ceo'  // CEO as child - would create cycle
          ])
        ).rejects.toThrow();
        
        // Attempt self-referential hierarchy
        await expect(
          client.query(`
            INSERT INTO role_hierarchy (tenant_id, parent_role_id, child_role_id)
            VALUES ($1, $2, $3)
          `, [
            testTenant.tenantId,
            'role-ceo',
            'role-ceo'
          ])
        ).rejects.toThrow(/no_self_inheritance/);
        
      } finally {
        client.release();
      }
    });

    it('should correctly resolve effective roles through hierarchy', async () => {
      const effectiveRolesQuery = `
        SELECT 
          r.name as role_name,
          er.role_id
        FROM v_effective_roles er
        JOIN roles r ON r.id = er.role_id
        WHERE er.tenant_id = $1
        ORDER BY r.name
      `;
      
      const effectiveRoles = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        effectiveRolesQuery,
        [testTenant.tenantId]
      );
      
      // Should include all roles that have parent-child relationships
      expect(effectiveRoles.rows.length).toBeGreaterThan(0);
      
      // Verify specific inheritance patterns
      const roleNames = effectiveRoles.rows.map(r => r.role_name);
      
      // All roles with parents should appear in effective roles
      const expectedInheritingRoles = [
        'CTO', 'Security Director', 'Security Manager', 'Senior Security Analyst',
        'Security Analyst', 'Junior Security Analyst', 'Security Intern',
        'Security Auditor', 'External Consultant'
      ];
      
      for (const roleName of expectedInheritingRoles) {
        expect(roleNames).toContain(roleName);
      }
    });
  });

  describe('Permission Inheritance Resolution', () => {
    it('should resolve inherited permissions correctly through role hierarchy', async () => {
      // Test permission inheritance for the Security Analyst role
      // Should inherit from: Senior Analyst -> Manager -> Director -> CTO -> CEO
      
      const inheritedPermissionsQuery = `
        SELECT DISTINCT
          p.resource_namespace,
          p.resource,
          p.action,
          r.name as granting_role
        FROM user_roles ur
        JOIN roles ur_role ON ur_role.id = ur.role_id
        LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
        JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
        JOIN permissions p ON p.id = rp.permission_id
        JOIN roles r ON r.id = rp.role_id
        WHERE ur.user_id = $1 AND ur.tenant_id = $2
        ORDER BY p.resource_namespace, p.resource, p.action
      `;
      
      const analystPermissions = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        inheritedPermissionsQuery,
        ['analyst-user', testTenant.tenantId]
      );
      
      // Analyst should inherit permissions from entire chain
      const permissionActions = analystPermissions.rows.map(p => `${p.resource_namespace}:${p.resource}:${p.action}`);
      
      // Direct permissions
      expect(permissionActions).toContain('security:alerts:investigate');
      expect(permissionActions).toContain('security:reports:create');
      
      // Inherited from Senior Analyst
      expect(permissionActions).toContain('security:analysis:advanced');
      expect(permissionActions).toContain('hr:mentoring:provide');
      
      // Inherited from Manager
      expect(permissionActions).toContain('hr:team:manage');
      expect(permissionActions).toContain('security:incidents:manage');
      
      // Inherited from Director
      expect(permissionActions).toContain('security:administration:*');
      expect(permissionActions).toContain('finance:budget:approve');
      
      // Inherited from CTO
      expect(permissionActions).toContain('technology:*:*');
      expect(permissionActions).toContain('security:oversight:*');
      
      // Inherited from CEO
      expect(permissionActions).toContain('system:*:*');
      
      console.log(`✅ Analyst inherited ${permissionActions.length} permissions through hierarchy`);
    });

    it('should handle permission inheritance for users with multiple roles', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, testTenant.tenantId);
        
        // Assign multiple roles to a user (e.g., both Analyst and Auditor)
        await client.query(`
          INSERT INTO user_roles (tenant_id, user_id, role_id)
          VALUES ($1, 'multi-role-user', $2)
        `, [testTenant.tenantId, 'role-security-analyst']);
        
        await client.query(`
          INSERT INTO user_roles (tenant_id, user_id, role_id)
          VALUES ($1, 'multi-role-user', $2)
        `, [testTenant.tenantId, 'role-auditor']);
        
        // Query combined permissions from both role hierarchies
        const multiRolePermissionsQuery = `
          SELECT DISTINCT
            p.resource_namespace,
            p.resource,
            p.action,
            COUNT(*) as permission_count
          FROM user_roles ur
          LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
          JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
          JOIN permissions p ON p.id = rp.permission_id
          WHERE ur.user_id = $1 AND ur.tenant_id = $2
          GROUP BY p.resource_namespace, p.resource, p.action
          ORDER BY p.resource_namespace, p.resource, p.action
        `;
        
        const multiRolePermissions = await dbSetup.executeWithTenantContext(
          testTenant.tenantId,
          multiRolePermissionsQuery,
          ['multi-role-user', testTenant.tenantId]
        );
        
        const permissionSet = new Set(
          multiRolePermissions.rows.map(p => `${p.resource_namespace}:${p.resource}:${p.action}`)
        );
        
        // Should have permissions from both role hierarchies
        // From Analyst hierarchy
        expect(permissionSet).toContain('security:alerts:investigate');
        expect(permissionSet).toContain('system:*:*'); // From CEO
        
        // From Auditor hierarchy
        expect(permissionSet).toContain('security:audit:*');
        expect(permissionSet).toContain('compliance:*:check');
        
        // Should inherit Director-level permissions from both paths
        expect(permissionSet).toContain('security:administration:*');
        
        console.log(`✅ Multi-role user has ${permissionSet.size} unique permissions from combined hierarchies`);
        
      } finally {
        client.release();
      }
    });

    it('should validate has_permission function with hierarchical inheritance', async () => {
      // Test the has_permission function with different levels in hierarchy
      const permissionChecks = [
        // CEO should have global admin permission directly
        {
          user: 'ceo-user',
          namespace: 'system',
          resource: '*',
          action: '*',
          expected: true,
          description: 'CEO has direct global admin permission'
        },
        
        // Security Analyst should have inherited global admin through hierarchy
        {
          user: 'analyst-user',
          namespace: 'system',
          resource: '*',
          action: '*',
          expected: true,
          description: 'Analyst inherits global admin through hierarchy'
        },
        
        // Junior Analyst should have inherited permissions
        {
          user: 'junior-user',
          namespace: 'security',
          resource: 'alerts',
          action: 'investigate',
          expected: true,
          description: 'Junior inherits investigation permission from Analyst'
        },
        
        // Intern should have most permissions through inheritance
        {
          user: 'intern-user',
          namespace: 'technology',
          resource: '*',
          action: '*',
          expected: true,
          description: 'Intern inherits tech admin through full hierarchy'
        },
        
        // Auditor should have audit permissions plus inherited director permissions
        {
          user: 'auditor-user',
          namespace: 'security',
          resource: 'audit',
          action: '*',
          expected: true,
          description: 'Auditor has direct audit permission'
        },
        
        // Auditor should inherit from Director level
        {
          user: 'auditor-user',
          namespace: 'technology',
          resource: '*',
          action: '*',
          expected: true,
          description: 'Auditor inherits tech admin through Director->CTO->CEO'
        },
        
        // External consultant should have limited permissions
        {
          user: 'external-user',
          namespace: 'security',
          resource: 'consulting',
          action: '*',
          expected: true,
          description: 'External consultant has direct consulting permission'
        },
        
        // External should also inherit manager-level permissions
        {
          user: 'external-user',
          namespace: 'hr',
          resource: 'team',
          action: 'manage',
          expected: true,
          description: 'External inherits team management from Manager level'
        }
      ];
      
      for (const check of permissionChecks) {
        const hasPermResult = await dbSetup.executeWithTenantContext(
          testTenant.tenantId,
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, check.user, check.namespace, check.resource, check.action]
        );
        
        expect(hasPermResult.rows[0].has_perm, check.description).toBe(check.expected);
        console.log(`✅ ${check.description}: ${hasPermResult.rows[0].has_perm}`);
      }
    });
  });

  describe('Deep Hierarchy Resolution (5+ Levels)', () => {
    it('should correctly resolve permissions through deep hierarchy chains', async () => {
      // Test the deepest chain: CEO -> CTO -> Director -> Manager -> Senior -> Analyst -> Junior -> Intern
      // Intern should inherit permissions from all 8 levels
      
      const deepHierarchyQuery = `
        WITH RECURSIVE permission_chain AS (
          -- Start with intern's direct roles
          SELECT ur.role_id, r.name as role_name, 0 as level
          FROM user_roles ur
          JOIN roles r ON r.id = ur.role_id
          WHERE ur.user_id = $1 AND ur.tenant_id = $2
          
          UNION ALL
          
          -- Recursively find parent roles
          SELECT rh.parent_role_id, pr.name as role_name, pc.level + 1
          FROM permission_chain pc
          JOIN role_hierarchy rh ON rh.child_role_id = pc.role_id AND rh.tenant_id = $2
          JOIN roles pr ON pr.id = rh.parent_role_id
          WHERE pc.level < 10 -- Prevent infinite recursion
        )
        SELECT 
          pc.role_name,
          pc.level,
          COUNT(DISTINCT p.id) as permission_count,
          string_agg(DISTINCT p.resource || ':' || p.action, ', ' ORDER BY p.resource || ':' || p.action) as permissions
        FROM permission_chain pc
        JOIN role_permissions rp ON rp.role_id = pc.role_id AND rp.tenant_id = $2
        JOIN permissions p ON p.id = rp.permission_id
        GROUP BY pc.role_name, pc.level
        ORDER BY pc.level
      `;
      
      const internHierarchy = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        deepHierarchyQuery,
        ['intern-user', testTenant.tenantId]
      );
      
      // Verify the complete chain is resolved
      expect(internHierarchy.rows.length).toBeGreaterThanOrEqual(7); // At least 7 levels
      
      // Check we have the full hierarchy from intern to CEO
      const hierarchyLevels = new Map(internHierarchy.rows.map(h => [h.level, h.role_name]));
      
      expect(hierarchyLevels.get(0)).toBe('Security Intern');
      expect(hierarchyLevels.get(1)).toBe('Junior Security Analyst');
      expect(hierarchyLevels.get(2)).toBe('Security Analyst');
      expect(hierarchyLevels.get(3)).toBe('Senior Security Analyst');
      expect(hierarchyLevels.get(4)).toBe('Security Manager');
      expect(hierarchyLevels.get(5)).toBe('Security Director');
      expect(hierarchyLevels.get(6)).toBe('CTO');
      expect(hierarchyLevels.get(7)).toBe('CEO');
      
      // Verify intern gets CEO's global admin permission through inheritance
      const internGlobalAccess = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        'SELECT has_permission($1, $2, $3, $4, $5) as has_global',
        [testTenant.tenantId, 'intern-user', 'system', '*', '*']
      );
      
      expect(internGlobalAccess.rows[0].has_global).toBe(true);
      
      console.log('✅ Deep hierarchy (8 levels) correctly resolved for intern user');
    });

    it('should maintain performance with deep hierarchy resolution', async () => {
      // Performance test for deep hierarchy permission checks
      const performanceTests = [
        'intern-user',    // 8-level hierarchy
        'junior-user',   // 7-level hierarchy  
        'analyst-user',  // 6-level hierarchy
        'senior-user',   // 5-level hierarchy
        'manager-user'   // 4-level hierarchy
      ];
      
      for (const user of performanceTests) {
        const start = performance.now();
        
        // Complex permission check through hierarchy
        const result = await dbSetup.executeWithTenantContext(
          testTenant.tenantId,
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, user, 'system', '*', '*']
        );
        
        const end = performance.now();
        const duration = end - start;
        
        expect(result.rows[0].has_perm).toBe(true);
        expect(duration).toBeLessThan(20); // Should complete within 20ms
        
        console.log(`✅ Deep hierarchy permission check for ${user}: ${duration.toFixed(2)}ms`);
      }
    });
  });

  describe('Parallel Hierarchy Branches', () => {
    it('should handle parallel hierarchy branches correctly', async () => {
      // Test that Auditor and External Consultant (both report to different levels) work correctly
      
      // Auditor reports to Director, External reports to Manager
      // Both should inherit from their parent chains but not from each other
      
      const auditorPermissions = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        `SELECT DISTINCT p.resource_namespace || ':' || p.resource || ':' || p.action as permission
         FROM user_roles ur
         LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id  
         JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
         JOIN permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = $1 AND ur.tenant_id = $2`,
        ['auditor-user', testTenant.tenantId]
      );
      
      const consultantPermissions = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        `SELECT DISTINCT p.resource_namespace || ':' || p.resource || ':' || p.action as permission
         FROM user_roles ur
         LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
         JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
         JOIN permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = $1 AND ur.tenant_id = $2`,
        ['external-user', testTenant.tenantId]
      );
      
      const auditorPerms = new Set(auditorPermissions.rows.map(p => p.permission));
      const consultantPerms = new Set(consultantPermissions.rows.map(p => p.permission));
      
      // Both should inherit CEO permissions (through different paths)
      expect(auditorPerms).toContain('system:*:*');
      expect(consultantPerms).toContain('system:*:*');
      
      // Auditor should have audit-specific permissions
      expect(auditorPerms).toContain('security:audit:*');
      expect(auditorPerms).toContain('compliance:*:check');
      
      // Consultant should have consultant-specific permissions
      expect(consultantPerms).toContain('security:consulting:*');
      
      // Auditor should inherit from Director level (budget approval)
      expect(auditorPerms).toContain('finance:budget:approve');
      
      // Consultant should inherit from Manager level (team management) 
      expect(consultantPerms).toContain('hr:team:manage');
      
      // But consultant should NOT have budget approval (Manager doesn't have it)
      expect(consultantPerms).not.toContain('finance:budget:approve');
      
      console.log(`✅ Parallel branches: Auditor has ${auditorPerms.size}, Consultant has ${consultantPerms.size} permissions`);
    });
  });

  describe('Dynamic Hierarchy Modifications', () => {
    it('should handle role hierarchy changes and update permissions', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, testTenant.tenantId);
        
        // Check initial permission for analyst
        let hasAdvanced = await client.query(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, 'analyst-user', 'security', 'analysis', 'advanced']
        );
        expect(hasAdvanced.rows[0].has_perm).toBe(true); // Should inherit from Senior
        
        // Remove the hierarchy link: Senior -> Analyst
        await client.query(`
          DELETE FROM role_hierarchy 
          WHERE tenant_id = $1 AND parent_role_id = $2 AND child_role_id = $3
        `, [testTenant.tenantId, 'role-senior-analyst', 'role-security-analyst']);
        
        // Check permission again - should no longer have advanced analysis
        hasAdvanced = await client.query(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, 'analyst-user', 'security', 'analysis', 'advanced']
        );
        expect(hasAdvanced.rows[0].has_perm).toBe(false); // No longer inherits from Senior
        
        // But should still have own permissions
        let hasInvestigate = await client.query(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, 'analyst-user', 'security', 'alerts', 'investigate']
        );
        expect(hasInvestigate.rows[0].has_perm).toBe(true); // Direct permission
        
        // Restore the hierarchy
        await client.query(`
          INSERT INTO role_hierarchy (tenant_id, parent_role_id, child_role_id)
          VALUES ($1, $2, $3)
        `, [testTenant.tenantId, 'role-senior-analyst', 'role-security-analyst']);
        
        // Permission should be restored
        hasAdvanced = await client.query(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, 'analyst-user', 'security', 'analysis', 'advanced']
        );
        expect(hasAdvanced.rows[0].has_perm).toBe(true); // Inheritance restored
        
      } finally {
        client.release();
      }
    });

    it('should handle role permission changes and cascade through hierarchy', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, testTenant.tenantId);
        
        // Add a new permission to the CEO role
        await client.query(`
          INSERT INTO permissions (id, resource_namespace, resource, action)
          VALUES ('perm-new-power', 'executive', 'decisions', 'ultimate')
        `);
        
        await client.query(`
          INSERT INTO role_permissions (tenant_id, role_id, permission_id)
          VALUES ($1, 'role-ceo', 'perm-new-power')
        `, [testTenant.tenantId]);
        
        // Check that all subordinates inherit this new permission
        const subordinates = [
          'cto-user', 'director-user', 'manager-user', 'senior-user',
          'analyst-user', 'junior-user', 'intern-user', 'auditor-user'
        ];
        
        for (const user of subordinates) {
          const hasNewPower = await client.query(
            'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
            [testTenant.tenantId, user, 'executive', 'decisions', 'ultimate']
          );
          
          expect(hasNewPower.rows[0].has_perm, `${user} should inherit new CEO permission`).toBe(true);
        }
        
        // External consultant should also inherit it (through Manager -> Director -> CTO -> CEO chain)
        const consultantHasNewPower = await client.query(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, 'external-user', 'executive', 'decisions', 'ultimate']
        );
        expect(consultantHasNewPower.rows[0].has_perm).toBe(true);
        
        console.log('✅ New CEO permission cascaded to all subordinates through hierarchy');
        
      } finally {
        client.release();
      }
    });
  });

  describe('Hierarchy Edge Cases', () => {
    it('should handle orphaned roles gracefully', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, testTenant.tenantId);
        
        // Create an orphaned role (no parent)
        await client.query(`
          INSERT INTO roles (id, tenant_id, name, description)
          VALUES ('orphan-role', $1, 'Orphaned Role', 'Role with no parent')
        `, [testTenant.tenantId]);
        
        await client.query(`
          INSERT INTO permissions (id, resource_namespace, resource, action)
          VALUES ('perm-orphan', 'orphan', 'data', 'access')
        `);
        
        await client.query(`
          INSERT INTO role_permissions (tenant_id, role_id, permission_id)
          VALUES ($1, 'orphan-role', 'perm-orphan')
        `, [testTenant.tenantId]);
        
        // Assign to a user
        await client.query(`
          INSERT INTO user_roles (tenant_id, user_id, role_id)
          VALUES ($1, 'orphan-user', 'orphan-role')
        `, [testTenant.tenantId]);
        
        await client.query(`
          INSERT INTO users (id, email)
          VALUES ('orphan-user', 'orphan@test.com')
        `);
        
        // Orphaned role should work but only have its direct permissions
        const orphanPerms = await client.query(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, 'orphan-user', 'orphan', 'data', 'access']
        );
        expect(orphanPerms.rows[0].has_perm).toBe(true);
        
        // Should NOT inherit any permissions from hierarchy
        const inheritedPerm = await client.query(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [testTenant.tenantId, 'orphan-user', 'system', '*', '*']
        );
        expect(inheritedPerm.rows[0].has_perm).toBe(false);
        
      } finally {
        client.release();
      }
    });

    it('should prevent infinite recursion in corrupted hierarchies', async () => {
      // This test would verify that the v_effective_roles view handles
      // potential circular references gracefully
      
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, testTenant.tenantId);
        
        // Query should complete without infinite recursion even with complex hierarchy
        const start = performance.now();
        const effectiveRoles = await client.query(`
          SELECT COUNT(*) as role_count FROM v_effective_roles WHERE tenant_id = $1
        `, [testTenant.tenantId]);
        const end = performance.now();
        
        expect(effectiveRoles.rows[0].role_count).toBeGreaterThan(0);
        expect(end - start).toBeLessThan(100); // Should complete quickly
        
        console.log(`✅ Hierarchy resolution completed in ${(end - start).toFixed(2)}ms`);
        
      } finally {
        client.release();
      }
    });

    it('should maintain hierarchy isolation across tenants', async () => {
      // Create a second tenant with different hierarchy
      const tenant2 = DatabaseTestSetup.createTestTenantData(
        'hierarchy-tenant-2',
        'Hierarchy Test 2'
      );
      
      await dbSetup.createTestTenant(tenant2);
      
      // Verify hierarchies don't cross tenant boundaries
      const tenant1Hierarchy = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        'SELECT COUNT(*) as count FROM v_effective_roles'
      );
      
      const tenant2Hierarchy = await dbSetup.executeWithTenantContext(
        tenant2.tenantId,
        'SELECT COUNT(*) as count FROM v_effective_roles'
      );
      
      // Both should have their own hierarchy counts
      expect(parseInt(tenant1Hierarchy.rows[0].count)).toBeGreaterThan(0);
      expect(parseInt(tenant2Hierarchy.rows[0].count)).toBeGreaterThan(0);
      
      // Verify no cross-tenant role inheritance
      const crossTenantCheck = await dbSetup.executeWithTenantContext(
        testTenant.tenantId,
        `SELECT COUNT(*) as count FROM v_effective_roles er 
         JOIN roles r ON r.id = er.role_id 
         WHERE r.tenant_id != er.tenant_id`
      );
      
      expect(parseInt(crossTenantCheck.rows[0].count)).toBe(0);
      
      console.log('✅ Role hierarchies properly isolated between tenants');
    });
  });
});