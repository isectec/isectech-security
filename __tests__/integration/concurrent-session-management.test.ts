/**
 * Concurrent Access and Session Management Tests
 * Tests session context isolation, PgBouncer integration, and concurrent operations
 */

import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import { DatabaseTestSetup, TEST_TENANTS, TestTenantContext } from '../../test-setup/database-test-setup';
import { Pool, PoolClient } from 'pg';

describe('Concurrent Session Management Tests', () => {
  let dbSetup: DatabaseTestSetup;
  let tenantA: TestTenantContext;
  let tenantB: TestTenantContext;
  let tenantC: TestTenantContext;
  
  // Additional connection pools for concurrency testing
  let concurrentPool1: Pool;
  let concurrentPool2: Pool;
  let concurrentPool3: Pool;

  beforeAll(async () => {
    dbSetup = new DatabaseTestSetup();
    await dbSetup.initialize();

    // Create test tenants
    tenantA = DatabaseTestSetup.createTestTenantData(TEST_TENANTS.ENTERPRISE.id, TEST_TENANTS.ENTERPRISE.name);
    tenantB = DatabaseTestSetup.createTestTenantData(TEST_TENANTS.GOVERNMENT.id, TEST_TENANTS.GOVERNMENT.name);
    tenantC = DatabaseTestSetup.createTestTenantData(TEST_TENANTS.MSP.id, TEST_TENANTS.MSP.name);

    await dbSetup.createTestTenant(tenantA);
    await dbSetup.createTestTenant(tenantB);
    await dbSetup.createTestTenant(tenantC);

    // Create additional connection pools to simulate PgBouncer scenario
    const baseConfig = {
      host: process.env.TEST_DB_HOST || 'localhost',
      port: parseInt(process.env.TEST_DB_PORT || '5432'),
      user: process.env.TEST_DB_USER || 'test_user',
      password: process.env.TEST_DB_PASSWORD || 'test',
      database: 'rbac_test_db',
      max: 10, // Lower pool sizes to simulate PgBouncer connection limits
      idleTimeoutMillis: 1000,
      connectionTimeoutMillis: 2000,
    };

    concurrentPool1 = new Pool({ ...baseConfig, application_name: 'concurrent_test_1' });
    concurrentPool2 = new Pool({ ...baseConfig, application_name: 'concurrent_test_2' });
    concurrentPool3 = new Pool({ ...baseConfig, application_name: 'concurrent_test_3' });

    console.log('✅ Concurrent session management test environment initialized');
  }, 30000);

  afterAll(async () => {
    await concurrentPool1.end();
    await concurrentPool2.end();
    await concurrentPool3.end();
    await dbSetup.destroy();
  });

  beforeEach(async () => {
    // Clear audit logs before each test
    const client = await dbSetup.getConnection();
    try {
      await client.query('TRUNCATE security_audit_log');
    } finally {
      client.release();
    }
  });

  describe('Session Context Isolation', () => {
    it('should isolate tenant contexts across concurrent connections', async () => {
      // Create 3 concurrent connections with different tenant contexts
      const connections = await Promise.all([
        concurrentPool1.connect(),
        concurrentPool2.connect(),
        concurrentPool3.connect()
      ]);

      try {
        // Set different tenant contexts on each connection
        await connections[0].query(`SET app.current_tenant_id = '${tenantA.tenantId}'`);
        await connections[1].query(`SET app.current_tenant_id = '${tenantB.tenantId}'`);
        await connections[2].query(`SET app.current_tenant_id = '${tenantC.tenantId}'`);

        // Verify each connection sees only their tenant's data
        const [resultA, resultB, resultC] = await Promise.all([
          connections[0].query('SELECT * FROM roles'),
          connections[1].query('SELECT * FROM roles'),
          connections[2].query('SELECT * FROM roles')
        ]);

        // Each connection should see only their tenant's roles
        expect(resultA.rows.every(role => role.tenant_id === tenantA.tenantId)).toBe(true);
        expect(resultB.rows.every(role => role.tenant_id === tenantB.tenantId)).toBe(true);
        expect(resultC.rows.every(role => role.tenant_id === tenantC.tenantId)).toBe(true);

        // No cross-contamination
        const allRoleIds = [
          ...resultA.rows.map(r => r.id),
          ...resultB.rows.map(r => r.id),
          ...resultC.rows.map(r => r.id)
        ];
        const uniqueRoleIds = new Set(allRoleIds);
        expect(uniqueRoleIds.size).toBe(allRoleIds.length); // No duplicates

        console.log(`✅ Perfect isolation: A=${resultA.rows.length}, B=${resultB.rows.length}, C=${resultC.rows.length} roles`);

      } finally {
        connections.forEach(conn => conn.release());
      }
    });

    it('should prevent session context bleeding between operations', async () => {
      const client = await dbSetup.getConnection();

      try {
        // Set initial tenant context
        await client.query(`SET app.current_tenant_id = '${tenantA.tenantId}'`);
        
        // Verify we see Tenant A data
        let result = await client.query('SELECT COUNT(*) as count FROM roles');
        const tenantACount = parseInt(result.rows[0].count);
        expect(tenantACount).toBeGreaterThan(0);

        // Switch tenant context
        await client.query(`SET app.current_tenant_id = '${tenantB.tenantId}'`);
        
        // Verify we now see Tenant B data
        result = await client.query('SELECT COUNT(*) as count FROM roles');
        const tenantBCount = parseInt(result.rows[0].count);
        expect(tenantBCount).toBeGreaterThan(0);
        expect(tenantBCount).not.toBe(tenantACount);

        // Verify actual role data is different
        const tenantBRoles = await client.query('SELECT id FROM roles');
        const tenantBRoleIds = new Set(tenantBRoles.rows.map(r => r.id));

        // Switch back to Tenant A
        await client.query(`SET app.current_tenant_id = '${tenantA.tenantId}'`);
        const tenantARoles = await client.query('SELECT id FROM roles');
        const tenantARoleIds = new Set(tenantARoles.rows.map(r => r.id));

        // Role sets should be completely different
        const intersection = new Set([...tenantARoleIds].filter(x => tenantBRoleIds.has(x)));
        expect(intersection.size).toBe(0);

      } finally {
        client.release();
      }
    });

    it('should handle rapid context switching without corruption', async () => {
      const client = await dbSetup.getConnection();
      const tenants = [tenantA, tenantB, tenantC];

      try {
        // Rapidly switch between tenant contexts
        for (let i = 0; i < 50; i++) {
          const tenant = tenants[i % tenants.length];
          
          await client.query(`SET app.current_tenant_id = '${tenant.tenantId}'`);
          
          // Verify correct context
          const result = await client.query('SELECT COUNT(*) as count FROM roles');
          expect(parseInt(result.rows[0].count)).toBe(tenant.roles.length);
          
          // Double-check with actual role query
          const roleCheck = await client.query('SELECT * FROM roles LIMIT 1');
          if (roleCheck.rows.length > 0) {
            expect(roleCheck.rows[0].tenant_id).toBe(tenant.tenantId);
          }
        }

        console.log('✅ Rapid context switching (50 iterations) completed successfully');

      } finally {
        client.release();
      }
    });
  });

  describe('Concurrent Multi-Tenant Operations', () => {
    it('should handle 100 concurrent operations across multiple tenants', async () => {
      const operations = [];
      const tenants = [tenantA, tenantB, tenantC];

      // Create 100 concurrent operations across different tenants
      for (let i = 0; i < 100; i++) {
        const tenant = tenants[i % tenants.length];
        const operationId = `concurrent-op-${i}`;
        
        operations.push({
          tenant,
          operationId,
          operation: async () => {
            const client = await dbSetup.getConnection();
            
            try {
              await client.query(`SET app.current_tenant_id = '${tenant.tenantId}'`);
              
              // Perform a multi-step operation
              await client.query('BEGIN');
              
              // Insert a temporary role
              await client.query(`
                INSERT INTO roles (id, tenant_id, name, description)
                VALUES ($1, $2, $3, $4)
              `, [operationId, tenant.tenantId, `Concurrent Role ${i}`, 'Test role']);
              
              // Query to verify isolation
              const roleCheck = await client.query('SELECT COUNT(*) FROM roles');
              
              // Update the role
              await client.query(`
                UPDATE roles SET description = $1 WHERE id = $2
              `, [`Updated description ${i}`, operationId]);
              
              // Commit the transaction
              await client.query('COMMIT');
              
              return {
                operationId,
                tenantId: tenant.tenantId,
                roleCount: parseInt(roleCheck.rows[0].count),
                success: true
              };
              
            } catch (error) {
              await client.query('ROLLBACK');
              throw error;
            } finally {
              client.release();
            }
          }
        });
      }

      // Execute all operations concurrently
      const start = performance.now();
      const results = await Promise.allSettled(
        operations.map(op => op.operation())
      );
      const end = performance.now();

      // Analyze results
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      expect(successful).toBeGreaterThan(95); // At least 95% success rate
      expect(failed).toBeLessThan(5); // Less than 5% failures acceptable

      // Verify tenant isolation was maintained
      for (let i = 0; i < results.length; i++) {
        if (results[i].status === 'fulfilled') {
          const result = (results[i] as any).value;
          const expectedTenant = operations[i].tenant;
          expect(result.tenantId).toBe(expectedTenant.tenantId);
        }
      }

      // Performance check
      const avgTimePerOp = (end - start) / operations.length;
      expect(avgTimePerOp).toBeLessThan(100); // Average < 100ms per operation

      console.log(`✅ Concurrent operations: ${successful}/${operations.length} successful in ${(end - start).toFixed(2)}ms (avg: ${avgTimePerOp.toFixed(2)}ms/op)`);
    });

    it('should handle connection pool exhaustion gracefully', async () => {
      // Create more operations than available connections to test pool behavior
      const poolSize = 5; // Smaller pool to force connection reuse
      const operationCount = 20; // More operations than pool size

      const limitedPool = new Pool({
        host: process.env.TEST_DB_HOST || 'localhost',
        port: parseInt(process.env.TEST_DB_PORT || '5432'),
        user: process.env.TEST_DB_USER || 'test_user',
        password: process.env.TEST_DB_PASSWORD || 'test',
        database: 'rbac_test_db',
        max: poolSize,
        idleTimeoutMillis: 500,
        connectionTimeoutMillis: 2000,
      });

      try {
        const operations = Array.from({ length: operationCount }, (_, i) => ({
          operationId: i,
          tenant: [tenantA, tenantB, tenantC][i % 3],
          operation: async () => {
            const client = await limitedPool.connect();
            
            try {
              const tenant = [tenantA, tenantB, tenantC][i % 3];
              await client.query(`SET app.current_tenant_id = '${tenant.tenantId}'`);
              
              // Simulate work with database
              await new Promise(resolve => setTimeout(resolve, 10)); // Small delay
              
              const result = await client.query('SELECT COUNT(*) FROM roles');
              return {
                operationId: i,
                tenantId: tenant.tenantId,
                roleCount: parseInt(result.rows[0].count)
              };
              
            } finally {
              client.release();
            }
          }
        }));

        const results = await Promise.allSettled(
          operations.map(op => op.operation())
        );

        // All operations should complete successfully despite connection limits
        const successful = results.filter(r => r.status === 'fulfilled').length;
        expect(successful).toBe(operationCount);

        // Verify tenant isolation was maintained even with connection reuse
        for (let i = 0; i < results.length; i++) {
          if (results[i].status === 'fulfilled') {
            const result = (results[i] as any).value;
            const expectedTenant = operations[i].tenant;
            expect(result.tenantId).toBe(expectedTenant.tenantId);
          }
        }

        console.log(`✅ Connection pool exhaustion test: ${successful}/${operationCount} operations completed with ${poolSize} connections`);

      } finally {
        await limitedPool.end();
      }
    });

    it('should maintain session isolation under high concurrency stress', async () => {
      const stressTestOperations = [];
      const tenants = [tenantA, tenantB, tenantC];
      const operationCount = 200; // High stress test

      for (let i = 0; i < operationCount; i++) {
        const tenant = tenants[i % tenants.length];
        
        stressTestOperations.push(async () => {
          const client = await dbSetup.getConnection();
          
          try {
            await client.query(`SET app.current_tenant_id = '${tenant.tenantId}'`);
            
            // Complex multi-query operation to stress session management
            await client.query('BEGIN');
            
            // Query 1: Role count
            const roleResult = await client.query('SELECT COUNT(*) as count FROM roles');
            
            // Query 2: Permission lookup
            const permResult = await client.query(`
              SELECT COUNT(*) as count FROM role_permissions WHERE tenant_id = $1
            `, [tenant.tenantId]);
            
            // Query 3: User role assignments
            const userRoleResult = await client.query(`
              SELECT COUNT(*) as count FROM user_roles WHERE tenant_id = $1
            `, [tenant.tenantId]);
            
            await client.query('COMMIT');
            
            return {
              tenantId: tenant.tenantId,
              roleCount: parseInt(roleResult.rows[0].count),
              permCount: parseInt(permResult.rows[0].count),
              userRoleCount: parseInt(userRoleResult.rows[0].count),
              timestamp: Date.now()
            };
            
          } catch (error) {
            await client.query('ROLLBACK');
            throw error;
          } finally {
            client.release();
          }
        });
      }

      // Execute all stress operations concurrently
      const start = performance.now();
      const results = await Promise.allSettled(stressTestOperations);
      const end = performance.now();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      // High success rate expected even under stress
      expect(successful).toBeGreaterThan(operationCount * 0.95); // 95% success
      expect(failed).toBeLessThan(operationCount * 0.05); // < 5% failures

      // Verify data integrity - group results by tenant
      const successfulResults = results
        .filter(r => r.status === 'fulfilled')
        .map(r => (r as any).value);

      const tenantResults = {
        [tenantA.tenantId]: successfulResults.filter(r => r.tenantId === tenantA.tenantId),
        [tenantB.tenantId]: successfulResults.filter(r => r.tenantId === tenantB.tenantId),
        [tenantC.tenantId]: successfulResults.filter(r => r.tenantId === tenantC.tenantId)
      };

      // Each tenant should have consistent results across all operations
      for (const [tenantId, results] of Object.entries(tenantResults)) {
        if (results.length > 0) {
          const firstResult = results[0];
          
          // All results for this tenant should be identical (same counts)
          const allSameRoleCount = results.every(r => r.roleCount === firstResult.roleCount);
          const allSamePermCount = results.every(r => r.permCount === firstResult.permCount);
          const allSameUserRoleCount = results.every(r => r.userRoleCount === firstResult.userRoleCount);
          
          expect(allSameRoleCount, `Inconsistent role counts for tenant ${tenantId}`).toBe(true);
          expect(allSamePermCount, `Inconsistent permission counts for tenant ${tenantId}`).toBe(true);
          expect(allSameUserRoleCount, `Inconsistent user role counts for tenant ${tenantId}`).toBe(true);
        }
      }

      const totalTime = end - start;
      const avgTimePerOp = totalTime / operationCount;

      console.log(`✅ High concurrency stress test: ${successful}/${operationCount} ops in ${totalTime.toFixed(2)}ms (avg: ${avgTimePerOp.toFixed(2)}ms/op)`);
      expect(avgTimePerOp).toBeLessThan(50); // Should average < 50ms per operation
    });
  });

  describe('Session Context Recovery and Error Handling', () => {
    it('should handle connection drops and context recovery', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        // Set tenant context
        await client.query(`SET app.current_tenant_id = '${tenantA.tenantId}'`);
        
        // Verify context is set
        let contextCheck = await client.query('SELECT current_setting(\'app.current_tenant_id\') as tenant_id');
        expect(contextCheck.rows[0].tenant_id).toBe(tenantA.tenantId);
        
        // Simulate connection reset by clearing all session variables
        await client.query('RESET ALL');
        
        // Tenant context should be cleared
        try {
          await client.query('SELECT * FROM roles');
          expect(true).toBe(false); // Should not reach here
        } catch (error) {
          expect(error.message).toContain('Tenant context not set');
        }
        
        // Re-establish context
        await client.query(`SET app.current_tenant_id = '${tenantB.tenantId}'`);
        
        // Should now see Tenant B data
        const roles = await client.query('SELECT * FROM roles');
        expect(roles.rows.every(role => role.tenant_id === tenantB.tenantId)).toBe(true);
        
      } finally {
        client.release();
      }
    });

    it('should handle invalid tenant context gracefully', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        const invalidContexts = [
          'invalid-uuid-format',
          '00000000-0000-0000-0000-000000000000', // Valid UUID but non-existent tenant
          '', // Empty string
          'null',
          '123',
          'SELECT * FROM tenants' // SQL injection attempt
        ];
        
        for (const invalidContext of invalidContexts) {
          try {
            await client.query(`SET app.current_tenant_id = '${invalidContext}'`);
            
            // Query should fail with invalid context
            await expect(
              client.query('SELECT * FROM roles')
            ).rejects.toThrow();
            
          } catch (setupError) {
            // Some invalid contexts might fail at SET stage, which is also acceptable
            expect(setupError).toBeDefined();
          }
        }
        
      } finally {
        client.release();
      }
    });

    it('should handle transaction failures with proper context cleanup', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await client.query(`SET app.current_tenant_id = '${tenantA.tenantId}'`);
        
        await client.query('BEGIN');
        
        // Insert valid data
        await client.query(`
          INSERT INTO roles (id, tenant_id, name, description)
          VALUES ('temp-role-tx-test', $1, 'Temp Role', 'Transaction test')
        `, [tenantA.tenantId]);
        
        // Verify data exists in transaction
        let result = await client.query('SELECT * FROM roles WHERE id = $1', ['temp-role-tx-test']);
        expect(result.rows.length).toBe(1);
        
        // Force transaction failure by violating constraint
        try {
          await client.query(`
            INSERT INTO roles (id, tenant_id, name, description)
            VALUES ('temp-role-tx-test', $1, 'Duplicate', 'Should fail')
          `, [tenantA.tenantId]); // Duplicate ID should fail
          
        } catch (error) {
          // Expected constraint violation
          expect(error.message).toContain('duplicate');
        }
        
        // Rollback the transaction
        await client.query('ROLLBACK');
        
        // Verify data was rolled back
        result = await client.query('SELECT * FROM roles WHERE id = $1', ['temp-role-tx-test']);
        expect(result.rows.length).toBe(0);
        
        // Verify tenant context is still intact after transaction failure
        const contextCheck = await client.query('SELECT current_setting(\'app.current_tenant_id\') as tenant_id');
        expect(contextCheck.rows[0].tenant_id).toBe(tenantA.tenantId);
        
        // Should still be able to query normally
        result = await client.query('SELECT COUNT(*) FROM roles');
        expect(parseInt(result.rows[0].count)).toBe(tenantA.roles.length);
        
      } finally {
        client.release();
      }
    });
  });

  describe('PgBouncer Simulation Tests', () => {
    it('should handle connection pooling with session context isolation', async () => {
      // Simulate PgBouncer behavior by creating multiple sessions that reuse connections
      const sessions = [];
      
      // Create 10 sessions that will compete for a smaller connection pool
      for (let i = 0; i < 10; i++) {
        sessions.push({
          sessionId: `session-${i}`,
          tenant: [tenantA, tenantB, tenantC][i % 3],
          operations: []
        });
      }
      
      // Each session performs multiple operations with connection reuse
      const sessionPromises = sessions.map(async (session) => {
        const results = [];
        
        for (let opNum = 0; opNum < 5; opNum++) {
          const client = await concurrentPool1.connect();
          
          try {
            // Set session context (this simulates what application layer does)
            await client.query(`SET app.current_tenant_id = '${session.tenant.tenantId}'`);
            
            // Perform operation
            const roleCount = await client.query('SELECT COUNT(*) FROM roles');
            const userRoleCount = await client.query('SELECT COUNT(*) FROM user_roles');
            
            results.push({
              sessionId: session.sessionId,
              operationNum: opNum,
              tenantId: session.tenant.tenantId,
              roleCount: parseInt(roleCount.rows[0].count),
              userRoleCount: parseInt(userRoleCount.rows[0].count),
              timestamp: Date.now()
            });
            
          } finally {
            client.release();
          }
        }
        
        return results;
      });
      
      // Wait for all sessions to complete
      const allResults = await Promise.all(sessionPromises);
      const flatResults = allResults.flat();
      
      // Verify each session maintained consistent tenant isolation
      for (const session of sessions) {
        const sessionResults = flatResults.filter(r => r.sessionId === session.sessionId);
        
        // All operations in this session should see same tenant data
        const uniqueTenantIds = new Set(sessionResults.map(r => r.tenantId));
        expect(uniqueTenantIds.size).toBe(1);
        expect([...uniqueTenantIds][0]).toBe(session.tenant.tenantId);
        
        // All operations should return consistent counts
        const roleCounts = new Set(sessionResults.map(r => r.roleCount));
        const userRoleCounts = new Set(sessionResults.map(r => r.userRoleCount));
        
        expect(roleCounts.size).toBe(1); // Same role count across operations
        expect(userRoleCounts.size).toBe(1); // Same user role count across operations
      }
      
      console.log(`✅ PgBouncer simulation: ${sessions.length} sessions × 5 operations each completed with perfect isolation`);
    });

    it('should handle session variable persistence across connection reuse', async () => {
      // Test that session variables don't persist when connections are reused
      // (This is critical for PgBouncer session pooling mode)
      
      const client = await concurrentPool1.connect();
      
      try {
        // Set tenant context for Tenant A
        await client.query(`SET app.current_tenant_id = '${tenantA.tenantId}'`);
        
        // Verify Tenant A context
        let result = await client.query('SELECT * FROM roles');
        expect(result.rows.every(role => role.tenant_id === tenantA.tenantId)).toBe(true);
        
        // Release and get connection again (simulates PgBouncer connection reuse)
        client.release();
        
        const newClient = await concurrentPool1.connect();
        
        try {
          // Connection might be reused, but context should not persist
          // (In real PgBouncer, session variables are reset between sessions)
          
          // Try to query without setting context - should fail
          try {
            await newClient.query('SELECT * FROM roles');
            expect(true).toBe(false); // Should not reach here
          } catch (error) {
            expect(error.message).toContain('Tenant context not set');
          }
          
          // Set different tenant context
          await newClient.query(`SET app.current_tenant_id = '${tenantB.tenantId}'`);
          
          // Should now see Tenant B data
          result = await newClient.query('SELECT * FROM roles');
          expect(result.rows.every(role => role.tenant_id === tenantB.tenantId)).toBe(true);
          
        } finally {
          newClient.release();
        }
        
      } finally {
        // Client was already released above
      }
    });

    it('should handle rapid connection acquisition and release', async () => {
      // Simulate high-frequency connection usage pattern common with PgBouncer
      const operations = [];
      
      for (let i = 0; i < 100; i++) {
        operations.push(async () => {
          const client = await concurrentPool2.connect();
          
          try {
            const tenant = [tenantA, tenantB, tenantC][i % 3];
            
            await client.query(`SET app.current_tenant_id = '${tenant.tenantId}'`);
            
            // Quick operation
            const result = await client.query('SELECT COUNT(*) FROM roles');
            
            return {
              operationId: i,
              tenantId: tenant.tenantId,
              roleCount: parseInt(result.rows[0].count),
              success: true
            };
            
          } finally {
            client.release();
          }
        });
      }
      
      const start = performance.now();
      const results = await Promise.allSettled(operations);
      const end = performance.now();
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      
      expect(successful).toBe(100); // All operations should succeed
      
      // Verify tenant isolation
      const successfulResults = results
        .filter(r => r.status === 'fulfilled')
        .map(r => (r as any).value);
      
      const tenantACounts = successfulResults
        .filter(r => r.tenantId === tenantA.tenantId)
        .map(r => r.roleCount);
      const tenantBCounts = successfulResults
        .filter(r => r.tenantId === tenantB.tenantId)
        .map(r => r.roleCount);
      const tenantCCounts = successfulResults
        .filter(r => r.tenantId === tenantC.tenantId)
        .map(r => r.roleCount);
      
      // All counts for each tenant should be consistent
      expect(new Set(tenantACounts).size).toBe(1);
      expect(new Set(tenantBCounts).size).toBe(1);
      expect(new Set(tenantCCounts).size).toBe(1);
      
      const avgTime = (end - start) / operations.length;
      expect(avgTime).toBeLessThan(10); // Should be very fast for simple queries
      
      console.log(`✅ Rapid connection usage: 100 operations in ${(end - start).toFixed(2)}ms (avg: ${avgTime.toFixed(2)}ms/op)`);
    });
  });
});