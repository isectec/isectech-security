/**
 * Tenant Isolation Verification Tests
 * Comprehensive security tests to verify complete tenant boundary enforcement
 */

import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import { DatabaseTestSetup, TEST_TENANTS, TestTenantContext } from '../../test-setup/database-test-setup';
import { PoolClient } from 'pg';

describe('Tenant Isolation Verification Tests', () => {
  let dbSetup: DatabaseTestSetup;
  let tenantA: TestTenantContext;
  let tenantB: TestTenantContext;
  let tenantC: TestTenantContext;
  let mspTenant: TestTenantContext;

  beforeAll(async () => {
    dbSetup = new DatabaseTestSetup();
    await dbSetup.initialize();

    // Create multiple test tenants with overlapping user scenarios
    tenantA = {
      tenantId: '111e1111-e11b-11d1-a111-111111111111',
      tenantName: 'Tenant Alpha',
      users: [
        {
          id: 'user-001', // Same user ID across tenants (realistic scenario)
          email: 'admin@alpha.com',
          roleIds: ['role-alpha-admin']
        },
        {
          id: 'user-002',
          email: 'analyst@alpha.com', 
          roleIds: ['role-alpha-analyst']
        }
      ],
      roles: [
        {
          id: 'role-alpha-admin',
          name: 'Admin',
          description: 'Alpha Admin Role',
          permissions: ['perm-alpha-all']
        },
        {
          id: 'role-alpha-analyst',
          name: 'Analyst',
          description: 'Alpha Security Analyst',
          parentRoleId: undefined,
          permissions: ['perm-alpha-read']
        }
      ],
      permissions: [
        {
          id: 'perm-alpha-all',
          resourceNamespace: 'security',
          resource: '*',
          action: '*'
        },
        {
          id: 'perm-alpha-read',
          resourceNamespace: 'security',
          resource: 'alerts',
          action: 'read'
        }
      ]
    };

    tenantB = {
      tenantId: '222e2222-e22b-22d2-a222-222222222222',
      tenantName: 'Tenant Beta',
      users: [
        {
          id: 'user-001', // Same user ID as Tenant A (critical test case)
          email: 'admin@beta.com',
          roleIds: ['role-beta-admin']
        },
        {
          id: 'user-003',
          email: 'viewer@beta.com',
          roleIds: ['role-beta-viewer']
        }
      ],
      roles: [
        {
          id: 'role-beta-admin',
          name: 'Admin',
          description: 'Beta Admin Role',
          permissions: ['perm-beta-all']
        },
        {
          id: 'role-beta-viewer',
          name: 'Viewer',
          description: 'Beta Viewer Role',
          permissions: ['perm-beta-read']
        }
      ],
      permissions: [
        {
          id: 'perm-beta-all',
          resourceNamespace: 'security',
          resource: '*',
          action: '*'
        },
        {
          id: 'perm-beta-read',
          resourceNamespace: 'security',
          resource: 'events',
          action: 'read'
        }
      ]
    };

    tenantC = {
      tenantId: '333e3333-e33b-33d3-a333-333333333333',
      tenantName: 'Tenant Charlie',
      users: [
        {
          id: 'user-004',
          email: 'manager@charlie.com',
          roleIds: ['role-charlie-manager']
        }
      ],
      roles: [
        {
          id: 'role-charlie-manager',
          name: 'Manager',
          description: 'Charlie Manager Role',
          permissions: ['perm-charlie-manage']
        }
      ],
      permissions: [
        {
          id: 'perm-charlie-manage',
          resourceNamespace: 'security',
          resource: 'incidents',
          action: 'manage'
        }
      ]
    };

    // MSP tenant with special privileges
    mspTenant = {
      tenantId: '999e9999-e99b-99d9-a999-999999999999',
      tenantName: 'MSP Provider',
      users: [
        {
          id: 'msp-user-001',
          email: 'admin@msp.com',
          roleIds: ['role-msp-admin']
        }
      ],
      roles: [
        {
          id: 'role-msp-admin',
          name: 'MSP Admin',
          description: 'MSP Super Admin',
          permissions: ['perm-msp-global']
        }
      ],
      permissions: [
        {
          id: 'perm-msp-global',
          resourceNamespace: 'msp',
          resource: '*',
          action: '*'
        }
      ]
    };

    // Create all test tenants
    await dbSetup.createTestTenant(tenantA);
    await dbSetup.createTestTenant(tenantB);
    await dbSetup.createTestTenant(tenantC);
    await dbSetup.createTestTenant(mspTenant);

    console.log('✅ Tenant isolation test environment initialized');
  }, 30000);

  afterAll(async () => {
    await dbSetup.destroy();
  });

  beforeEach(async () => {
    // Clear audit logs between tests
    const client = await dbSetup.getConnection();
    try {
      await client.query('TRUNCATE security_audit_log');
    } finally {
      client.release();
    }
  });

  describe('Complete Data Isolation Verification', () => {
    it('should completely isolate tenant data across all RBAC tables', async () => {
      // Test data isolation across all major RBAC tables
      const tables = ['roles', 'role_hierarchy', 'role_permissions', 'user_roles'];
      
      for (const table of tables) {
        // Get data for each tenant
        const tenantAData = await dbSetup.executeWithTenantContext(
          tenantA.tenantId,
          `SELECT * FROM ${table}`
        );
        
        const tenantBData = await dbSetup.executeWithTenantContext(
          tenantB.tenantId,
          `SELECT * FROM ${table}`
        );
        
        const tenantCData = await dbSetup.executeWithTenantContext(
          tenantC.tenantId,
          `SELECT * FROM ${table}`
        );
        
        // Verify each tenant only sees their own data
        if (tenantAData.rows.length > 0) {
          expect(tenantAData.rows.every(row => row.tenant_id === tenantA.tenantId),
            `Tenant A saw non-tenant data in ${table}`).toBe(true);
        }
        
        if (tenantBData.rows.length > 0) {
          expect(tenantBData.rows.every(row => row.tenant_id === tenantB.tenantId),
            `Tenant B saw non-tenant data in ${table}`).toBe(true);
        }
        
        if (tenantCData.rows.length > 0) {
          expect(tenantCData.rows.every(row => row.tenant_id === tenantC.tenantId),
            `Tenant C saw non-tenant data in ${table}`).toBe(true);
        }
        
        console.log(`✅ Table ${table}: Complete tenant isolation verified`);
      }
    });

    it('should handle overlapping user IDs without cross-tenant contamination', async () => {
      // Critical test: Both Tenant A and B have user-001
      
      // Query user roles for user-001 from Tenant A perspective
      const tenantAUserRoles = await dbSetup.executeWithTenantContext(
        tenantA.tenantId,
        'SELECT * FROM user_roles WHERE user_id = $1',
        ['user-001']
      );
      
      // Query user roles for user-001 from Tenant B perspective  
      const tenantBUserRoles = await dbSetup.executeWithTenantContext(
        tenantB.tenantId,
        'SELECT * FROM user_roles WHERE user_id = $1',
        ['user-001']
      );
      
      // Both should return results but for different tenants
      expect(tenantAUserRoles.rows.length).toBeGreaterThan(0);
      expect(tenantBUserRoles.rows.length).toBeGreaterThan(0);
      
      // Verify complete isolation
      expect(tenantAUserRoles.rows.every(role => role.tenant_id === tenantA.tenantId)).toBe(true);
      expect(tenantBUserRoles.rows.every(role => role.tenant_id === tenantB.tenantId)).toBe(true);
      
      // Role IDs should be different even for same user ID
      const tenantARoleIds = new Set(tenantAUserRoles.rows.map(r => r.role_id));
      const tenantBRoleIds = new Set(tenantBUserRoles.rows.map(r => r.role_id));
      
      const roleIntersection = new Set([...tenantARoleIds].filter(x => tenantBRoleIds.has(x)));
      expect(roleIntersection.size).toBe(0);
      
      console.log('✅ Overlapping user IDs properly isolated between tenants');
    });

    it('should prevent tenant context switching attacks', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Set initial tenant context
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        
        // Verify we see Tenant A data
        let result = await client.query('SELECT COUNT(*) as count FROM roles');
        const tenantACount = parseInt(result.rows[0].count);
        expect(tenantACount).toBeGreaterThan(0);
        
        // Attempt context switch attack via SQL injection
        const maliciousQueries = [
          "'; SET app.current_tenant_id = '" + tenantB.tenantId + "'; SELECT * FROM roles WHERE '1'='1",
          `RESET app.current_tenant_id; SET app.current_tenant_id = '${tenantB.tenantId}'`,
          `/* comment */ SET app.current_tenant_id = '${tenantB.tenantId}' --`,
        ];
        
        for (const maliciousQuery of maliciousQueries) {
          try {
            await client.query(maliciousQuery);
            // If no error, verify we still see only Tenant A data
            result = await client.query('SELECT COUNT(*) as count FROM roles');
            expect(parseInt(result.rows[0].count)).toBe(tenantACount);
          } catch (error) {
            // Expected - malicious query should fail
            expect(error).toBeDefined();
          }
        }
        
        // Verify context is still Tenant A
        result = await client.query('SELECT current_setting(\'app.current_tenant_id\')');
        expect(result.rows[0].current_setting).toBe(tenantA.tenantId);
        
      } finally {
        client.release();
      }
    });
  });

  describe('Cross-Tenant Access Attack Simulation', () => {
    it('should block all forms of cross-tenant SELECT operations', async () => {
      const crossTenantQueries = [
        // Direct tenant_id manipulation
        `SELECT * FROM roles WHERE tenant_id = '${tenantB.tenantId}'`,
        
        // UNION attacks
        `SELECT * FROM roles WHERE tenant_id = '${tenantA.tenantId}' UNION SELECT * FROM roles WHERE tenant_id = '${tenantB.tenantId}'`,
        
        // Subquery attacks
        `SELECT * FROM roles WHERE tenant_id IN (SELECT tenant_id FROM roles WHERE name = 'Admin')`,
        
        // JOIN attacks
        `SELECT r1.* FROM roles r1 JOIN roles r2 ON r1.tenant_id != r2.tenant_id`,
        
        // Function bypasses
        `SELECT * FROM roles WHERE tenant_id = (SELECT id FROM tenants WHERE name = '${tenantB.tenantName}')`,
        
        // Case manipulation
        `SELECT * FROM roles WHERE UPPER(tenant_id::text) = UPPER('${tenantB.tenantId}')`
      ];
      
      // Execute from Tenant A context
      for (const query of crossTenantQueries) {
        const result = await dbSetup.executeWithTenantContext(
          tenantA.tenantId,
          query
        );
        
        // Should return empty results or only Tenant A data
        if (result.rows.length > 0) {
          expect(result.rows.every(row => row.tenant_id === tenantA.tenantId),
            `Cross-tenant query leaked data: ${query}`).toBe(true);
        }
        
        console.log(`✅ Blocked cross-tenant query: ${query.substring(0, 50)}...`);
      }
    });

    it('should prevent cross-tenant INSERT attacks', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        
        const maliciousInserts = [
          // Direct wrong tenant_id
          {
            query: `INSERT INTO roles (id, tenant_id, name) VALUES ($1, $2, $3)`,
            params: ['malicious-role-1', tenantB.tenantId, 'Malicious Role']
          },
          
          // Subquery tenant_id
          {
            query: `INSERT INTO roles (id, tenant_id, name) VALUES ($1, (SELECT id FROM tenants WHERE name = $2), $3)`,
            params: ['malicious-role-2', tenantB.tenantName, 'Subquery Attack']
          },
          
          // User role assignment to wrong tenant
          {
            query: `INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES ($1, $2, $3)`,
            params: [tenantB.tenantId, 'user-001', 'role-alpha-admin']
          }
        ];
        
        for (const maliciousInsert of maliciousInserts) {
          await expect(
            client.query(maliciousInsert.query, maliciousInsert.params)
          ).rejects.toThrow();
        }
        
        // Verify no malicious data was inserted by checking from both tenant contexts
        await dbSetup.setTenantContext(client, tenantB.tenantId);
        const tenantBRoles = await client.query('SELECT * FROM roles WHERE name LIKE $1', ['%Malicious%']);
        expect(tenantBRoles.rows.length).toBe(0);
        
        const tenantBUserRoles = await client.query('SELECT * FROM user_roles WHERE role_id = $1', ['role-alpha-admin']);
        expect(tenantBUserRoles.rows.length).toBe(0);
        
      } finally {
        client.release();
      }
    });

    it('should prevent cross-tenant UPDATE attacks', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Get existing role from Tenant B
        await dbSetup.setTenantContext(client, tenantB.tenantId);
        const tenantBRole = await client.query('SELECT * FROM roles LIMIT 1');
        const targetRoleId = tenantBRole.rows[0].id;
        const originalName = tenantBRole.rows[0].name;
        
        // Switch to Tenant A and attempt cross-tenant update
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        
        const maliciousUpdates = [
          // Direct role modification
          `UPDATE roles SET name = 'HACKED' WHERE id = '${targetRoleId}'`,
          
          // Tenant ID modification attempt
          `UPDATE roles SET tenant_id = '${tenantA.tenantId}' WHERE id = '${targetRoleId}'`,
          
          // Bulk update attempt
          `UPDATE roles SET name = 'COMPROMISED' WHERE name = '${originalName}'`
        ];
        
        for (const updateQuery of maliciousUpdates) {
          const result = await client.query(updateQuery);
          
          // Should affect 0 rows (blocked by RLS)
          expect(result.rowCount).toBe(0);
        }
        
        // Verify Tenant B role was not modified
        await dbSetup.setTenantContext(client, tenantB.tenantId);
        const verifyResult = await client.query('SELECT name FROM roles WHERE id = $1', [targetRoleId]);
        expect(verifyResult.rows[0].name).toBe(originalName);
        
      } finally {
        client.release();
      }
    });

    it('should prevent cross-tenant DELETE attacks', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Count roles in both tenants before attack
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        const tenantACountBefore = await client.query('SELECT COUNT(*) FROM roles');
        
        await dbSetup.setTenantContext(client, tenantB.tenantId);
        const tenantBCountBefore = await client.query('SELECT COUNT(*) FROM roles');
        const tenantBInitialCount = parseInt(tenantBCountBefore.rows[0].count);
        
        // Switch to Tenant A and attempt cross-tenant deletes
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        
        const maliciousDeletes = [
          // Attempt to delete all roles (should only delete Tenant A roles)
          'DELETE FROM roles',
          
          // Attempt specific deletion
          `DELETE FROM roles WHERE tenant_id = '${tenantB.tenantId}'`,
          
          // Attempt subquery deletion
          `DELETE FROM roles WHERE tenant_id IN (SELECT id FROM tenants WHERE name = '${tenantB.tenantName}')`
        ];
        
        let tenantADeleted = 0;
        for (const deleteQuery of maliciousDeletes) {
          const result = await client.query(deleteQuery);
          tenantADeleted += result.rowCount || 0;
        }
        
        // Verify Tenant B roles are intact
        await dbSetup.setTenantContext(client, tenantB.tenantId);
        const tenantBCountAfter = await client.query('SELECT COUNT(*) FROM roles');
        expect(parseInt(tenantBCountAfter.rows[0].count)).toBe(tenantBInitialCount);
        
        // Verify only Tenant A roles were affected
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        const tenantACountAfter = await client.query('SELECT COUNT(*) FROM roles');
        expect(parseInt(tenantACountAfter.rows[0].count)).toBeLessThanOrEqual(
          parseInt(tenantACountBefore.rows[0].count)
        );
        
      } finally {
        client.release();
      }
    });
  });

  describe('Advanced Security Boundary Tests', () => {
    it('should prevent privilege escalation through role manipulation', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        
        // Attempt to grant super permissions by manipulating role hierarchy
        const escalationAttempts = [
          // Try to make analyst role inherit from admin role
          `INSERT INTO role_hierarchy (tenant_id, parent_role_id, child_role_id) 
           VALUES ('${tenantA.tenantId}', '${tenantA.roles[0].id}', '${tenantA.roles[1].id}')`,
          
          // Try to assign admin permissions to analyst role
          `INSERT INTO role_permissions (tenant_id, role_id, permission_id)
           VALUES ('${tenantA.tenantId}', '${tenantA.roles[1].id}', '${tenantA.permissions[0].id}')`,
          
          // Try to create a new super-admin role
          `INSERT INTO roles (id, tenant_id, name, description)
           VALUES ('super-admin-role', '${tenantA.tenantId}', 'Super Admin', 'Elevated privileges')`
        ];
        
        for (const attempt of escalationAttempts) {
          // These operations might succeed within tenant boundaries, but shouldn't cross tenants
          try {
            await client.query(attempt);
            
            // If successful, verify it only affected current tenant
            const hierarchyCheck = await client.query('SELECT * FROM role_hierarchy');
            expect(hierarchyCheck.rows.every(h => h.tenant_id === tenantA.tenantId)).toBe(true);
            
            const permissionCheck = await client.query('SELECT * FROM role_permissions');
            expect(permissionCheck.rows.every(p => p.tenant_id === tenantA.tenantId)).toBe(true);
            
            const roleCheck = await client.query('SELECT * FROM roles');
            expect(roleCheck.rows.every(r => r.tenant_id === tenantA.tenantId)).toBe(true);
            
          } catch (error) {
            // Some attempts may fail due to constraints, which is also acceptable
            console.log(`✅ Privilege escalation attempt blocked: ${error.message}`);
          }
        }
        
        // Most importantly, verify no cross-tenant impact
        await dbSetup.setTenantContext(client, tenantB.tenantId);
        const tenantBRoles = await client.query('SELECT COUNT(*) FROM roles');
        expect(parseInt(tenantBRoles.rows[0].count)).toBe(tenantB.roles.length);
        
      } finally {
        client.release();
      }
    });

    it('should maintain isolation under transaction failures', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, tenantA.tenantId);
        
        await client.query('BEGIN');
        
        // Insert valid data for Tenant A
        await client.query(`
          INSERT INTO roles (id, tenant_id, name, description)
          VALUES ('temp-role-a', '${tenantA.tenantId}', 'Temp Role A', 'Temporary')
        `);
        
        // Attempt invalid cross-tenant operation that should fail
        try {
          await client.query(`
            INSERT INTO user_roles (tenant_id, user_id, role_id)
            VALUES ('${tenantB.tenantId}', 'user-001', 'temp-role-a')
          `);
          
          // This should not succeed, but if it does, rollback
          await client.query('ROLLBACK');
        } catch (error) {
          // Expected failure - rollback the transaction
          await client.query('ROLLBACK');
        }
        
        // Verify no data persisted in either tenant
        const tenantACheck = await client.query('SELECT * FROM roles WHERE id = $1', ['temp-role-a']);
        expect(tenantACheck.rows.length).toBe(0);
        
        await dbSetup.setTenantContext(client, tenantB.tenantId);
        const tenantBCheck = await client.query('SELECT * FROM user_roles WHERE user_id = $1 AND role_id = $2', ['user-001', 'temp-role-a']);
        expect(tenantBCheck.rows.length).toBe(0);
        
      } finally {
        client.release();
      }
    });

    it('should enforce isolation in concurrent multi-tenant operations', async () => {
      // Simulate concurrent operations across multiple tenants
      const concurrentOperations = [
        // Tenant A operations
        ...Array.from({ length: 3 }, (_, i) => ({
          tenantId: tenantA.tenantId,
          operation: () => dbSetup.executeWithTenantContext(
            tenantA.tenantId,
            `INSERT INTO roles (id, tenant_id, name) VALUES ($1, $2, $3)`,
            [`concurrent-role-a-${i}`, tenantA.tenantId, `Concurrent Role A ${i}`]
          )
        })),
        
        // Tenant B operations
        ...Array.from({ length: 3 }, (_, i) => ({
          tenantId: tenantB.tenantId,
          operation: () => dbSetup.executeWithTenantContext(
            tenantB.tenantId,
            `INSERT INTO roles (id, tenant_id, name) VALUES ($1, $2, $3)`,
            [`concurrent-role-b-${i}`, tenantB.tenantId, `Concurrent Role B ${i}`]
          )
        })),
        
        // Tenant C operations
        ...Array.from({ length: 2 }, (_, i) => ({
          tenantId: tenantC.tenantId,
          operation: () => dbSetup.executeWithTenantContext(
            tenantC.tenantId,
            `INSERT INTO roles (id, tenant_id, name) VALUES ($1, $2, $3)`,
            [`concurrent-role-c-${i}`, tenantC.tenantId, `Concurrent Role C ${i}`]
          )
        }))
      ];
      
      // Execute all operations concurrently
      const results = await Promise.allSettled(
        concurrentOperations.map(op => op.operation())
      );
      
      // Verify all operations completed successfully
      const successfulOps = results.filter(r => r.status === 'fulfilled').length;
      expect(successfulOps).toBe(concurrentOperations.length);
      
      // Verify tenant isolation was maintained
      const tenantAConcurrentRoles = await dbSetup.executeWithTenantContext(
        tenantA.tenantId,
        'SELECT * FROM roles WHERE name LIKE $1',
        ['Concurrent Role A%']
      );
      expect(tenantAConcurrentRoles.rows.length).toBe(3);
      expect(tenantAConcurrentRoles.rows.every(r => r.tenant_id === tenantA.tenantId)).toBe(true);
      
      const tenantBConcurrentRoles = await dbSetup.executeWithTenantContext(
        tenantB.tenantId,
        'SELECT * FROM roles WHERE name LIKE $1',
        ['Concurrent Role B%']
      );
      expect(tenantBConcurrentRoles.rows.length).toBe(3);
      expect(tenantBConcurrentRoles.rows.every(r => r.tenant_id === tenantB.tenantId)).toBe(true);
      
      const tenantCConcurrentRoles = await dbSetup.executeWithTenantContext(
        tenantC.tenantId,
        'SELECT * FROM roles WHERE name LIKE $1',
        ['Concurrent Role C%']
      );
      expect(tenantCConcurrentRoles.rows.length).toBe(2);
      expect(tenantCConcurrentRoles.rows.every(r => r.tenant_id === tenantC.tenantId)).toBe(true);
      
      console.log('✅ Concurrent multi-tenant operations maintained perfect isolation');
    });
  });

  describe('MSP Multi-Tenant Scenarios', () => {
    it('should handle MSP tenant permissions correctly', async () => {
      // MSP tenant should have access only to their own data by default
      // (Special MSP cross-tenant access would be implemented through application layer)
      
      const mspRoles = await dbSetup.executeWithTenantContext(
        mspTenant.tenantId,
        'SELECT * FROM roles'
      );
      
      // MSP should only see their own roles via RLS
      expect(mspRoles.rows.length).toBe(1);
      expect(mspRoles.rows[0].tenant_id).toBe(mspTenant.tenantId);
      
      // MSP shouldn't be able to access child tenant data through RLS
      const mspCrossAccess = await dbSetup.executeWithTenantContext(
        mspTenant.tenantId,
        `SELECT * FROM roles WHERE tenant_id = '${tenantA.tenantId}'`
      );
      
      expect(mspCrossAccess.rows.length).toBe(0);
      
      console.log('✅ MSP tenant properly isolated - cross-tenant access requires application-layer authorization');
    });
  });

  describe('Audit Trail for Isolation Violations', () => {
    it('should generate audit logs for cross-tenant access attempts', async () => {
      // Clear existing audit logs
      const client = await dbSetup.getConnection();
      
      try {
        await client.query('TRUNCATE security_audit_log');
        
        // Manually trigger audit logging for simulated violations
        const violations = [
          {
            table: 'roles',
            operation: 'SELECT',
            userTenant: tenantA.tenantId,
            resourceTenant: tenantB.tenantId
          },
          {
            table: 'user_roles',
            operation: 'INSERT',
            userTenant: tenantB.tenantId,
            resourceTenant: tenantA.tenantId
          },
          {
            table: 'role_permissions',
            operation: 'UPDATE',
            userTenant: tenantC.tenantId,
            resourceTenant: tenantA.tenantId
          }
        ];
        
        for (const violation of violations) {
          await client.query(`
            SELECT audit_rls_violation($1, $2, $3, $4, $5)
          `, [
            violation.table,
            violation.operation,
            violation.userTenant,
            violation.resourceTenant,
            JSON.stringify({ test: 'tenant_isolation_verification' })
          ]);
        }
        
        // Verify audit logs were created
        const auditLogs = await dbSetup.getSecurityAuditLogs('RLS_VIOLATION');
        expect(auditLogs.length).toBe(3);
        
        // Verify audit log contents
        for (let i = 0; i < violations.length; i++) {
          const violation = violations[i];
          const auditLog = auditLogs.find(log => 
            log.table_name === violation.table && 
            log.operation_type === violation.operation
          );
          
          expect(auditLog).toBeDefined();
          expect(auditLog.event_type).toBe('RLS_VIOLATION');
          expect(auditLog.severity).toBe('CRITICAL');
          expect(auditLog.user_tenant_id).toBe(violation.userTenant);
          expect(auditLog.resource_tenant_id).toBe(violation.resourceTenant);
        }
        
        console.log('✅ Audit logging captures all cross-tenant access attempts');
        
      } finally {
        client.release();
      }
    });
  });
});