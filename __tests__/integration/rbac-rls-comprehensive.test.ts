/**
 * Comprehensive RBAC Row-Level Security (RLS) Integration Tests
 * Tests real database policies and tenant isolation with actual PostgreSQL
 */

import { describe, expect, it, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { DatabaseTestSetup, TEST_TENANTS, TestTenantContext } from '../../test-setup/database-test-setup';
import { PoolClient } from 'pg';

describe('RBAC RLS Comprehensive Integration Tests', () => {
  let dbSetup: DatabaseTestSetup;
  let enterpriseTenant: TestTenantContext;
  let governmentTenant: TestTenantContext;
  let mspTenant: TestTenantContext;

  beforeAll(async () => {
    // Setup test database with real PostgreSQL
    dbSetup = new DatabaseTestSetup();
    await dbSetup.initialize();

    // Create test tenant data
    enterpriseTenant = DatabaseTestSetup.createTestTenantData(
      TEST_TENANTS.ENTERPRISE.id,
      TEST_TENANTS.ENTERPRISE.name
    );
    
    governmentTenant = DatabaseTestSetup.createTestTenantData(
      TEST_TENANTS.GOVERNMENT.id,
      TEST_TENANTS.GOVERNMENT.name
    );
    
    mspTenant = DatabaseTestSetup.createTestTenantData(
      TEST_TENANTS.MSP.id,
      TEST_TENANTS.MSP.name
    );

    // Insert test data
    await dbSetup.createTestTenant(enterpriseTenant);
    await dbSetup.createTestTenant(governmentTenant);
    await dbSetup.createTestTenant(mspTenant);

    console.log('✅ RBAC RLS test environment initialized');
  }, 30000);

  afterAll(async () => {
    await dbSetup.destroy();
    console.log('✅ RBAC RLS test environment cleaned up');
  });

  beforeEach(async () => {
    // Clear any previous audit logs for clean test runs
    await dbSetup.cleanup();
    await dbSetup.createTestTenant(enterpriseTenant);
    await dbSetup.createTestTenant(governmentTenant);
    await dbSetup.createTestTenant(mspTenant);
  });

  describe('RLS Policy Activation Verification', () => {
    it('should verify RLS is enabled on all tenant-scoped tables', async () => {
      const rlsStatus = await dbSetup.verifyRLSEnabled();
      
      // Critical RBAC tables must have RLS enabled
      const criticalTables = ['roles', 'role_hierarchy', 'role_permissions', 'user_roles'];
      
      for (const table of criticalTables) {
        const tableStatus = rlsStatus.find(t => t.table === table);
        expect(tableStatus, `Table ${table} not found in RLS status`).toBeDefined();
        expect(tableStatus!.rlsEnabled, `RLS not enabled on ${table}`).toBe(true);
        expect(tableStatus!.policyCount, `No RLS policies on ${table}`).toBeGreaterThan(0);
      }
    });

    it('should enforce tenant context requirement', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Attempt to query without tenant context should fail
        await expect(
          client.query('SELECT * FROM roles')
        ).rejects.toThrow(/Tenant context not set/);
        
        // Set tenant context and verify access works
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        const result = await client.query('SELECT * FROM roles WHERE tenant_id = $1', [enterpriseTenant.tenantId]);
        expect(result.rows.length).toBeGreaterThan(0);
        
      } finally {
        client.release();
      }
    });
  });

  describe('Cross-Tenant Access Prevention', () => {
    it('should completely block cross-tenant data access in roles table', async () => {
      // Set context for Enterprise tenant
      const enterpriseResult = await dbSetup.executeWithTenantContext(
        enterpriseTenant.tenantId,
        'SELECT * FROM roles'
      );
      
      // Should see Enterprise roles
      expect(enterpriseResult.rows.length).toBe(3); // admin, analyst, viewer
      expect(enterpriseResult.rows.every(role => role.tenant_id === enterpriseTenant.tenantId)).toBe(true);
      
      // Set context for Government tenant
      const governmentResult = await dbSetup.executeWithTenantContext(
        governmentTenant.tenantId,
        'SELECT * FROM roles'
      );
      
      // Should see Government roles only
      expect(governmentResult.rows.length).toBe(3);
      expect(governmentResult.rows.every(role => role.tenant_id === governmentTenant.tenantId)).toBe(true);
      
      // Verify no cross-tenant data appears
      const enterpriseRoleIds = new Set(enterpriseResult.rows.map(r => r.id));
      const governmentRoleIds = new Set(governmentResult.rows.map(r => r.id));
      
      expect(enterpriseRoleIds.size).toBe(3);
      expect(governmentRoleIds.size).toBe(3);
      
      // No overlap between tenant role IDs
      const intersection = new Set([...enterpriseRoleIds].filter(x => governmentRoleIds.has(x)));
      expect(intersection.size).toBe(0);
    });

    it('should prevent INSERT operations with wrong tenant_id', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        
        // Attempt to insert role for different tenant should fail
        await expect(
          client.query(`
            INSERT INTO roles (id, tenant_id, name, description) 
            VALUES ($1, $2, $3, $4)
          `, [
            'malicious-role-id',
            governmentTenant.tenantId, // Wrong tenant!
            'Malicious Role',
            'Should not be allowed'
          ])
        ).rejects.toThrow();
        
        // Verify malicious role was not created
        await dbSetup.setTenantContext(client, governmentTenant.tenantId);
        const result = await client.query('SELECT * FROM roles WHERE id = $1', ['malicious-role-id']);
        expect(result.rows.length).toBe(0);
        
      } finally {
        client.release();
      }
    });

    it('should prevent UPDATE operations across tenant boundaries', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Get a role from Enterprise tenant
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        const enterpriseRole = await client.query('SELECT * FROM roles LIMIT 1');
        const roleId = enterpriseRole.rows[0].id;
        
        // Switch to Government tenant context
        await dbSetup.setTenantContext(client, governmentTenant.tenantId);
        
        // Attempt to update Enterprise role from Government context
        const updateResult = await client.query(`
          UPDATE roles SET name = 'Hacked Role' WHERE id = $1
        `, [roleId]);
        
        // Update should affect 0 rows (blocked by RLS)
        expect(updateResult.rowCount).toBe(0);
        
        // Verify role wasn't modified
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        const verifyResult = await client.query('SELECT name FROM roles WHERE id = $1', [roleId]);
        expect(verifyResult.rows[0].name).not.toBe('Hacked Role');
        
      } finally {
        client.release();
      }
    });

    it('should prevent DELETE operations across tenant boundaries', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Get count of Enterprise roles
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        const beforeCount = await client.query('SELECT COUNT(*) FROM roles');
        const initialCount = parseInt(beforeCount.rows[0].count);
        
        // Switch to Government tenant and try to delete Enterprise roles
        await dbSetup.setTenantContext(client, governmentTenant.tenantId);
        const deleteResult = await client.query('DELETE FROM roles');
        
        // Should delete only Government roles, not Enterprise
        expect(deleteResult.rowCount).toBe(3); // Government tenant roles only
        
        // Verify Enterprise roles still exist
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        const afterCount = await client.query('SELECT COUNT(*) FROM roles');
        expect(parseInt(afterCount.rows[0].count)).toBe(initialCount);
        
      } finally {
        client.release();
      }
    });
  });

  describe('Role Hierarchy RLS Enforcement', () => {
    it('should enforce tenant isolation in role_hierarchy table', async () => {
      // Enterprise tenant should only see their role hierarchy
      const enterpriseHierarchy = await dbSetup.executeWithTenantContext(
        enterpriseTenant.tenantId,
        'SELECT * FROM role_hierarchy'
      );
      
      expect(enterpriseHierarchy.rows.length).toBeGreaterThan(0);
      expect(enterpriseHierarchy.rows.every(h => h.tenant_id === enterpriseTenant.tenantId)).toBe(true);
      
      // Government tenant should only see their role hierarchy
      const governmentHierarchy = await dbSetup.executeWithTenantContext(
        governmentTenant.tenantId,
        'SELECT * FROM role_hierarchy'
      );
      
      expect(governmentHierarchy.rows.length).toBeGreaterThan(0);
      expect(governmentHierarchy.rows.every(h => h.tenant_id === governmentTenant.tenantId)).toBe(true);
      
      // No cross-tenant hierarchy relationships
      const enterpriseRelations = new Set(enterpriseHierarchy.rows.map(h => `${h.parent_role_id}-${h.child_role_id}`));
      const governmentRelations = new Set(governmentHierarchy.rows.map(h => `${h.parent_role_id}-${h.child_role_id}`));
      
      const intersection = new Set([...enterpriseRelations].filter(x => governmentRelations.has(x)));
      expect(intersection.size).toBe(0);
    });

    it('should prevent cross-tenant role hierarchy creation', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        
        // Get Enterprise parent role
        const enterpriseParent = await client.query('SELECT id FROM roles WHERE name = $1', ['Admin']);
        const parentRoleId = enterpriseParent.rows[0].id;
        
        // Switch to Government context
        await dbSetup.setTenantContext(client, governmentTenant.tenantId);
        
        // Get Government child role
        const governmentChild = await client.query('SELECT id FROM roles WHERE name = $1', ['Viewer']);
        const childRoleId = governmentChild.rows[0].id;
        
        // Attempt to create cross-tenant hierarchy should fail
        await expect(
          client.query(`
            INSERT INTO role_hierarchy (tenant_id, parent_role_id, child_role_id)
            VALUES ($1, $2, $3)
          `, [governmentTenant.tenantId, parentRoleId, childRoleId])
        ).rejects.toThrow();
        
      } finally {
        client.release();
      }
    });
  });

  describe('Permission Assignment RLS Enforcement', () => {
    it('should enforce tenant isolation in role_permissions table', async () => {
      // Each tenant should only see their role-permission mappings
      const enterprisePerms = await dbSetup.executeWithTenantContext(
        enterpriseTenant.tenantId,
        'SELECT * FROM role_permissions'
      );
      
      const governmentPerms = await dbSetup.executeWithTenantContext(
        governmentTenant.tenantId,
        'SELECT * FROM role_permissions'
      );
      
      expect(enterprisePerms.rows.every(p => p.tenant_id === enterpriseTenant.tenantId)).toBe(true);
      expect(governmentPerms.rows.every(p => p.tenant_id === governmentTenant.tenantId)).toBe(true);
      
      // Verify no cross-tenant permission assignments visible
      const enterpriseRolePerms = new Set(enterprisePerms.rows.map(p => `${p.role_id}-${p.permission_id}`));
      const governmentRolePerms = new Set(governmentPerms.rows.map(p => `${p.role_id}-${p.permission_id}`));
      
      const intersection = new Set([...enterpriseRolePerms].filter(x => governmentRolePerms.has(x)));
      expect(intersection.size).toBe(0);
    });

    it('should prevent unauthorized permission grants across tenants', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        
        // Get Enterprise role and shared permission
        const enterpriseRole = await client.query('SELECT id FROM roles WHERE name = $1', ['Admin']);
        const sharedPerm = await client.query('SELECT id FROM permissions LIMIT 1');
        
        // Switch to Government context and attempt unauthorized grant
        await dbSetup.setTenantContext(client, governmentTenant.tenantId);
        
        await expect(
          client.query(`
            INSERT INTO role_permissions (tenant_id, role_id, permission_id)
            VALUES ($1, $2, $3)
          `, [governmentTenant.tenantId, enterpriseRole.rows[0].id, sharedPerm.rows[0].id])
        ).rejects.toThrow();
        
      } finally {
        client.release();
      }
    });
  });

  describe('User Role Assignment RLS Enforcement', () => {
    it('should enforce tenant isolation in user_roles table', async () => {
      const enterpriseUserRoles = await dbSetup.executeWithTenantContext(
        enterpriseTenant.tenantId,
        'SELECT * FROM user_roles'
      );
      
      const governmentUserRoles = await dbSetup.executeWithTenantContext(
        governmentTenant.tenantId,
        'SELECT * FROM user_roles'
      );
      
      expect(enterpriseUserRoles.rows.every(ur => ur.tenant_id === enterpriseTenant.tenantId)).toBe(true);
      expect(governmentUserRoles.rows.every(ur => ur.tenant_id === governmentTenant.tenantId)).toBe(true);
      
      // Verify user-role assignments don't cross tenant boundaries
      const enterpriseAssignments = new Set(enterpriseUserRoles.rows.map(ur => `${ur.user_id}-${ur.role_id}`));
      const governmentAssignments = new Set(governmentUserRoles.rows.map(ur => `${ur.user_id}-${ur.role_id}`));
      
      const intersection = new Set([...enterpriseAssignments].filter(x => governmentAssignments.has(x)));
      expect(intersection.size).toBe(0);
    });

    it('should prevent cross-tenant user role assignments', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Get Enterprise user and Government role
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        const enterpriseUser = await client.query('SELECT id FROM users LIMIT 1');
        
        await dbSetup.setTenantContext(client, governmentTenant.tenantId);
        const governmentRole = await client.query('SELECT id FROM roles WHERE name = $1', ['Admin']);
        
        // Attempt cross-tenant assignment should fail
        await expect(
          client.query(`
            INSERT INTO user_roles (tenant_id, user_id, role_id)
            VALUES ($1, $2, $3)
          `, [governmentTenant.tenantId, enterpriseUser.rows[0].id, governmentRole.rows[0].id])
        ).rejects.toThrow();
        
      } finally {
        client.release();
      }
    });
  });

  describe('Complex Multi-Table Query RLS Enforcement', () => {
    it('should enforce RLS on JOIN operations across RBAC tables', async () => {
      // Complex query joining multiple RBAC tables
      const query = `
        SELECT 
          u.email,
          r.name as role_name,
          p.resource,
          p.action
        FROM user_roles ur
        JOIN users u ON u.id = ur.user_id
        JOIN roles r ON r.id = ur.role_id
        JOIN role_permissions rp ON rp.role_id = r.id
        JOIN permissions p ON p.id = rp.permission_id
        ORDER BY u.email, r.name, p.resource, p.action
      `;
      
      // Execute for Enterprise tenant
      const enterpriseResult = await dbSetup.executeWithTenantContext(
        enterpriseTenant.tenantId,
        query
      );
      
      // Execute for Government tenant
      const governmentResult = await dbSetup.executeWithTenantContext(
        governmentTenant.tenantId,
        query
      );
      
      // Verify results are tenant-isolated
      expect(enterpriseResult.rows.length).toBeGreaterThan(0);
      expect(governmentResult.rows.length).toBeGreaterThan(0);
      
      // Check that emails belong to correct tenant domain
      const enterpriseEmails = enterpriseResult.rows.map(r => r.email);
      const governmentEmails = governmentResult.rows.map(r => r.email);
      
      expect(enterpriseEmails.every(email => email.includes('enterprise'))).toBe(true);
      expect(governmentEmails.every(email => email.includes('gov'))).toBe(true);
      
      // No email overlap between tenants
      const emailIntersection = new Set([...enterpriseEmails].filter(x => governmentEmails.includes(x)));
      expect(emailIntersection.size).toBe(0);
    });

    it('should maintain RLS with hierarchical role resolution', async () => {
      // Query using the hierarchical role view
      const hierarchyQuery = `
        SELECT 
          r.name as role_name,
          er.role_id as effective_role_id,
          COUNT(rp.permission_id) as permission_count
        FROM v_effective_roles er
        JOIN roles r ON r.id = er.role_id
        LEFT JOIN role_permissions rp ON rp.role_id = er.role_id
        GROUP BY r.name, er.role_id
        ORDER BY r.name
      `;
      
      const enterpriseHierarchy = await dbSetup.executeWithTenantContext(
        enterpriseTenant.tenantId,
        hierarchyQuery
      );
      
      const governmentHierarchy = await dbSetup.executeWithTenantContext(
        governmentTenant.tenantId,
        hierarchyQuery
      );
      
      // Verify tenant isolation in hierarchical views
      expect(enterpriseHierarchy.rows.length).toBeGreaterThan(0);
      expect(governmentHierarchy.rows.length).toBeGreaterThan(0);
      
      // Role names should be tenant-specific (no cross-contamination)
      const enterpriseRoleNames = new Set(enterpriseHierarchy.rows.map(r => r.role_name));
      const governmentRoleNames = new Set(governmentHierarchy.rows.map(r => r.role_name));
      
      // While role names might be same (Admin, Viewer), the role IDs should be different
      const enterpriseRoleIds = new Set(enterpriseHierarchy.rows.map(r => r.effective_role_id));
      const governmentRoleIds = new Set(governmentHierarchy.rows.map(r => r.effective_role_id));
      
      const roleIdIntersection = new Set([...enterpriseRoleIds].filter(x => governmentRoleIds.has(x)));
      expect(roleIdIntersection.size).toBe(0);
    });
  });

  describe('Audit Logging for RLS Violations', () => {
    it('should log RLS violation attempts', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Clear existing audit logs
        await client.query('TRUNCATE security_audit_log');
        
        // Attempt operation that should trigger audit logging
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        
        // Manually trigger audit logging
        await client.query(`
          SELECT audit_rls_violation($1, $2, $3, $4, $5)
        `, [
          'roles',
          'SELECT',
          enterpriseTenant.tenantId,
          governmentTenant.tenantId,
          JSON.stringify({ test: 'cross_tenant_attempt' })
        ]);
        
        // Verify audit log entry was created
        const auditLogs = await dbSetup.getSecurityAuditLogs('RLS_VIOLATION');
        expect(auditLogs.length).toBe(1);
        
        const logEntry = auditLogs[0];
        expect(logEntry.event_type).toBe('RLS_VIOLATION');
        expect(logEntry.severity).toBe('CRITICAL');
        expect(logEntry.table_name).toBe('roles');
        expect(logEntry.operation_type).toBe('SELECT');
        expect(logEntry.user_tenant_id).toBe(enterpriseTenant.tenantId);
        expect(logEntry.resource_tenant_id).toBe(governmentTenant.tenantId);
        
      } finally {
        client.release();
      }
    });

    it('should maintain audit trail integrity', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Clear and create multiple audit entries
        await client.query('TRUNCATE security_audit_log');
        
        const violations = [
          ['roles', 'SELECT', enterpriseTenant.tenantId, governmentTenant.tenantId],
          ['user_roles', 'INSERT', governmentTenant.tenantId, enterpriseTenant.tenantId],
          ['role_permissions', 'UPDATE', mspTenant.tenantId, enterpriseTenant.tenantId]
        ];
        
        for (const [table, operation, userTenant, resourceTenant] of violations) {
          await client.query(`
            SELECT audit_rls_violation($1, $2, $3, $4, $5)
          `, [table, operation, userTenant, resourceTenant, JSON.stringify({ sequential_test: true })]);
        }
        
        // Verify all entries were logged
        const auditLogs = await dbSetup.getSecurityAuditLogs('RLS_VIOLATION');
        expect(auditLogs.length).toBe(3);
        
        // Verify chronological ordering
        const timestamps = auditLogs.map(log => new Date(log.timestamp).getTime());
        const sortedTimestamps = [...timestamps].sort();
        expect(timestamps).toEqual(sortedTimestamps.reverse()); // DESC order
        
        // Verify unique violations
        const violationSignatures = auditLogs.map(log => 
          `${log.table_name}-${log.operation_type}-${log.user_tenant_id}-${log.resource_tenant_id}`
        );
        const uniqueSignatures = new Set(violationSignatures);
        expect(uniqueSignatures.size).toBe(3);
        
      } finally {
        client.release();
      }
    });
  });

  describe('Performance Under RLS Constraints', () => {
    it('should maintain acceptable query performance with RLS enabled', async () => {
      // Test performance of common RBAC queries
      const queries = [
        {
          name: 'Simple role lookup',
          query: 'SELECT * FROM roles WHERE name = $1',
          params: ['Admin']
        },
        {
          name: 'User permissions resolution', 
          query: `
            SELECT DISTINCT p.resource, p.action
            FROM user_roles ur
            JOIN role_permissions rp ON rp.role_id = ur.role_id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = $1
          `,
          params: [enterpriseTenant.users[0].id]
        },
        {
          name: 'Hierarchical role query',
          query: 'SELECT * FROM v_effective_roles WHERE tenant_id = $1',
          params: [enterpriseTenant.tenantId]
        }
      ];
      
      for (const testQuery of queries) {
        const client = await dbSetup.getConnection();
        
        try {
          await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
          
          const performance = await dbSetup.measureQueryPerformance(
            testQuery.query, 
            testQuery.params, 
            10
          );
          
          // Performance targets: average < 50ms, max < 100ms
          expect(performance.averageTime, `${testQuery.name} average time too high`).toBeLessThan(50);
          expect(performance.maxTime, `${testQuery.name} max time too high`).toBeLessThan(100);
          
          console.log(`✅ ${testQuery.name}: avg ${performance.averageTime.toFixed(2)}ms, max ${performance.maxTime.toFixed(2)}ms`);
          
        } finally {
          client.release();
        }
      }
    });

    it('should handle concurrent tenant operations efficiently', async () => {
      const concurrentOperations = Array.from({ length: 10 }, async (_, index) => {
        const tenantId = index % 2 === 0 ? enterpriseTenant.tenantId : governmentTenant.tenantId;
        
        return dbSetup.executeWithTenantContext(
          tenantId,
          'SELECT COUNT(*) as role_count FROM roles'
        );
      });
      
      const start = performance.now();
      const results = await Promise.all(concurrentOperations);
      const end = performance.now();
      
      // All operations should complete successfully
      expect(results.length).toBe(10);
      results.forEach(result => {
        expect(result.rows[0].role_count).toBe('3'); // Each tenant has 3 roles
      });
      
      // Total time should be reasonable for concurrent operations
      const totalTime = end - start;
      expect(totalTime).toBeLessThan(1000); // < 1 second for 10 concurrent operations
      
      console.log(`✅ Concurrent operations completed in ${totalTime.toFixed(2)}ms`);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle malformed tenant context gracefully', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Test invalid UUID formats
        const invalidContexts = [
          'invalid-uuid',
          '123',
          'null',
          '',
          'SELECT * FROM roles'  // SQL injection attempt
        ];
        
        for (const invalidContext of invalidContexts) {
          await expect(
            client.query(`SET app.current_tenant_id = '${invalidContext}'`)
          ).rejects.toThrow();
        }
        
      } finally {
        client.release();
      }
    });

    it('should enforce RLS even for empty result sets', async () => {
      // Query that would normally return results but should be filtered by RLS
      const result = await dbSetup.executeWithTenantContext(
        enterpriseTenant.tenantId,
        'SELECT * FROM roles WHERE tenant_id = $1',
        [governmentTenant.tenantId] // Wrong tenant ID in WHERE clause
      );
      
      // Should return 0 results due to RLS filtering
      expect(result.rows.length).toBe(0);
    });

    it('should handle transaction rollbacks with RLS context', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, enterpriseTenant.tenantId);
        
        await client.query('BEGIN');
        
        // Insert valid data
        await client.query(`
          INSERT INTO roles (id, tenant_id, name, description)
          VALUES ($1, $2, $3, $4)
        `, ['test-role-id', enterpriseTenant.tenantId, 'Test Role', 'Test Description']);
        
        // Verify data exists in transaction
        let result = await client.query('SELECT * FROM roles WHERE id = $1', ['test-role-id']);
        expect(result.rows.length).toBe(1);
        
        // Rollback transaction
        await client.query('ROLLBACK');
        
        // Verify data was rolled back
        result = await client.query('SELECT * FROM roles WHERE id = $1', ['test-role-id']);
        expect(result.rows.length).toBe(0);
        
      } finally {
        client.release();
      }
    });
  });
});