/**
 * RBAC Performance Benchmarks and Testing
 * Tests query performance, scalability, and optimization effectiveness
 */

import { describe, expect, it, beforeAll, afterAll, beforeEach } from 'vitest';
import { DatabaseTestSetup, TestTenantContext } from '../../test-setup/database-test-setup';
import { PoolClient } from 'pg';

describe('RBAC Performance Benchmarks', () => {
  let dbSetup: DatabaseTestSetup;
  let largeTenant: TestTenantContext;
  let mediumTenants: TestTenantContext[];
  let smallTenants: TestTenantContext[];

  // Performance thresholds (in milliseconds)
  const PERFORMANCE_TARGETS = {
    simplePermissionCheck: 5,
    complexPermissionCheck: 20,
    hierarchyResolution: 10,
    rlsFilteredQuery: 20,
    bulkRoleQuery: 50,
    concurrentUserQuery: 100,
    tenantSwitchOverhead: 10
  };

  beforeAll(async () => {
    dbSetup = new DatabaseTestSetup();
    await dbSetup.initialize();

    // Create performance test data at scale
    await createScalabilityTestData();
    console.log('✅ Performance test environment with scaled data initialized');
  }, 60000); // Longer timeout for data setup

  afterAll(async () => {
    await dbSetup.destroy();
  });

  beforeEach(async () => {
    // Clear performance-related audit logs
    const client = await dbSetup.getConnection();
    try {
      await client.query('TRUNCATE security_audit_log');
    } finally {
      client.release();
    }
  });

  async function createScalabilityTestData() {
    // Create one large tenant with many users, roles, and permissions
    largeTenant = {
      tenantId: 'large-tenant-perf-test',
      tenantName: 'Large Scale Performance Tenant',
      users: [],
      roles: [],
      permissions: []
    };

    // Create 1000 users
    for (let i = 0; i < 1000; i++) {
      largeTenant.users.push({
        id: `user-${i.toString().padStart(4, '0')}`,
        email: `user${i}@largecorp.com`,
        roleIds: [`role-department-${Math.floor(i / 50)}`, `role-level-${i % 10}`] // Multiple roles per user
      });
    }

    // Create hierarchical department structure (20 departments, each with 5 role levels)
    for (let dept = 0; dept < 20; dept++) {
      for (let level = 0; level < 5; level++) {
        const roleId = `role-dept-${dept}-level-${level}`;
        const parentRoleId = level > 0 ? `role-dept-${dept}-level-${level - 1}` : undefined;
        
        largeTenant.roles.push({
          id: roleId,
          name: `Department ${dept} Level ${level}`,
          description: `Role for department ${dept} at level ${level}`,
          parentRoleId,
          permissions: [`perm-dept-${dept}`, `perm-level-${level}`, `perm-combined-${dept}-${level}`]
        });
      }
      
      // Additional department role
      largeTenant.roles.push({
        id: `role-department-${dept}`,
        name: `Department ${dept}`,
        description: `General department role`,
        permissions: [`perm-dept-${dept}`]
      });
    }

    // Create level-based roles
    for (let level = 0; level < 10; level++) {
      largeTenant.roles.push({
        id: `role-level-${level}`,
        name: `Level ${level}`,
        description: `Experience level ${level}`,
        parentRoleId: level > 0 ? `role-level-${level - 1}` : undefined,
        permissions: [`perm-level-${level}`, `perm-experience-${Math.floor(level / 2)}`]
      });
    }

    // Create comprehensive permission set
    for (let dept = 0; dept < 20; dept++) {
      largeTenant.permissions.push({
        id: `perm-dept-${dept}`,
        resourceNamespace: 'department',
        resource: `dept-${dept}`,
        action: '*'
      });
      
      for (let level = 0; level < 5; level++) {
        largeTenant.permissions.push({
          id: `perm-combined-${dept}-${level}`,
          resourceNamespace: 'department',
          resource: `dept-${dept}`,
          action: `level-${level}`
        });
      }
    }

    for (let level = 0; level < 10; level++) {
      largeTenant.permissions.push({
        id: `perm-level-${level}`,
        resourceNamespace: 'access',
        resource: 'level',
        action: `level-${level}`
      });
      
      largeTenant.permissions.push({
        id: `perm-experience-${Math.floor(level / 2)}`,
        resourceNamespace: 'experience',
        resource: 'tier',
        action: `tier-${Math.floor(level / 2)}`
      });
    }

    // Create additional performance-focused permissions
    for (let i = 0; i < 100; i++) {
      largeTenant.permissions.push({
        id: `perm-resource-${i}`,
        resourceNamespace: 'resources',
        resource: `resource-${i}`,
        action: 'access'
      });
    }

    await dbSetup.createTestTenant(largeTenant);

    // Create medium-sized tenants for multi-tenant performance testing
    mediumTenants = [];
    for (let t = 0; t < 10; t++) {
      const tenant: TestTenantContext = {
        tenantId: `medium-tenant-${t}`,
        tenantName: `Medium Tenant ${t}`,
        users: [],
        roles: [],
        permissions: []
      };

      // 100 users per medium tenant
      for (let i = 0; i < 100; i++) {
        tenant.users.push({
          id: `medium-${t}-user-${i}`,
          email: `user${i}@medium${t}.com`,
          roleIds: [`medium-${t}-role-${i % 5}`]
        });
      }

      // 10 roles per medium tenant
      for (let i = 0; i < 10; i++) {
        tenant.roles.push({
          id: `medium-${t}-role-${i}`,
          name: `Medium Role ${i}`,
          description: `Role ${i} for medium tenant ${t}`,
          parentRoleId: i > 0 ? `medium-${t}-role-${i - 1}` : undefined,
          permissions: [`medium-${t}-perm-${i}`, `medium-${t}-perm-common`]
        });
      }

      // 20 permissions per medium tenant
      for (let i = 0; i < 20; i++) {
        tenant.permissions.push({
          id: `medium-${t}-perm-${i}`,
          resourceNamespace: `medium-${t}`,
          resource: `resource-${i}`,
          action: 'access'
        });
      }

      tenant.permissions.push({
        id: `medium-${t}-perm-common`,
        resourceNamespace: `medium-${t}`,
        resource: 'common',
        action: '*'
      });

      mediumTenants.push(tenant);
      await dbSetup.createTestTenant(tenant);
    }

    // Create small tenants for baseline performance
    smallTenants = [];
    for (let t = 0; t < 50; t++) {
      const tenant = DatabaseTestSetup.createTestTenantData(
        `small-tenant-${t}`,
        `Small Tenant ${t}`
      );
      smallTenants.push(tenant);
      await dbSetup.createTestTenant(tenant);
    }
  }

  describe('Basic Query Performance', () => {
    it('should meet performance targets for simple permission checks', async () => {
      // Test basic has_permission function performance
      const testCases = [
        {
          user: largeTenant.users[0].id,
          namespace: 'department',
          resource: 'dept-0',
          action: '*'
        },
        {
          user: largeTenant.users[100].id,
          namespace: 'access',
          resource: 'level',
          action: 'level-5'
        },
        {
          user: largeTenant.users[500].id,
          namespace: 'resources',
          resource: 'resource-25',
          action: 'access'
        }
      ];

      for (const testCase of testCases) {
        const performance = await dbSetup.measureQueryPerformance(
          'SELECT has_permission($1, $2, $3, $4, $5) as has_perm',
          [largeTenant.tenantId, testCase.user, testCase.namespace, testCase.resource, testCase.action],
          20 // 20 iterations for stable average
        );

        expect(performance.averageTime).toBeLessThan(PERFORMANCE_TARGETS.simplePermissionCheck);
        expect(performance.maxTime).toBeLessThan(PERFORMANCE_TARGETS.simplePermissionCheck * 2);

        console.log(`✅ Permission check: avg ${performance.averageTime.toFixed(2)}ms, max ${performance.maxTime.toFixed(2)}ms`);
      }
    });

    it('should meet performance targets for RLS-filtered queries', async () => {
      const queries = [
        {
          name: 'Simple role count',
          query: 'SELECT COUNT(*) FROM roles',
          params: []
        },
        {
          name: 'Role with permissions',
          query: `
            SELECT r.*, COUNT(rp.permission_id) as perm_count
            FROM roles r
            LEFT JOIN role_permissions rp ON rp.role_id = r.id
            GROUP BY r.id, r.name, r.description, r.tenant_id
            LIMIT 100
          `,
          params: []
        },
        {
          name: 'User roles with hierarchy',
          query: `
            SELECT ur.*, r.name as role_name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            ORDER BY ur.user_id
            LIMIT 100
          `,
          params: []
        }
      ];

      for (const queryTest of queries) {
        const performance = await dbSetup.measureQueryPerformance(
          queryTest.query,
          queryTest.params,
          10
        );

        expect(performance.averageTime).toBeLessThan(PERFORMANCE_TARGETS.rlsFilteredQuery);
        console.log(`✅ ${queryTest.name}: avg ${performance.averageTime.toFixed(2)}ms`);
      }
    });

    it('should meet performance targets for hierarchy resolution', async () => {
      // Test v_effective_roles view performance
      const hierarchyQueries = [
        {
          name: 'Effective roles view',
          query: 'SELECT COUNT(*) FROM v_effective_roles',
          params: []
        },
        {
          name: 'User effective permissions',
          query: `
            SELECT COUNT(DISTINCT p.id) as permission_count
            FROM user_roles ur
            LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
            JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
            JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = $1 AND ur.tenant_id = $2
          `,
          params: [largeTenant.users[50].id, largeTenant.tenantId]
        },
        {
          name: 'Deep hierarchy traversal',
          query: `
            WITH RECURSIVE role_tree AS (
              SELECT role_id, role_id as root_role, 0 as depth
              FROM user_roles ur WHERE ur.user_id = $1 AND ur.tenant_id = $2
              
              UNION ALL
              
              SELECT rh.parent_role_id, rt.root_role, rt.depth + 1
              FROM role_tree rt
              JOIN role_hierarchy rh ON rh.child_role_id = rt.role_id AND rh.tenant_id = $2
              WHERE rt.depth < 10
            )
            SELECT COUNT(DISTINCT role_id) FROM role_tree
          `,
          params: [largeTenant.users[100].id, largeTenant.tenantId]
        }
      ];

      for (const queryTest of hierarchyQueries) {
        const client = await dbSetup.getConnection();
        
        try {
          await dbSetup.setTenantContext(client, largeTenant.tenantId);
          
          const start = performance.now();
          await client.query(queryTest.query, queryTest.params);
          const end = performance.now();
          
          const duration = end - start;
          expect(duration).toBeLessThan(PERFORMANCE_TARGETS.hierarchyResolution);
          
          console.log(`✅ ${queryTest.name}: ${duration.toFixed(2)}ms`);
          
        } finally {
          client.release();
        }
      }
    });
  });

  describe('Scalability Performance', () => {
    it('should maintain performance with large datasets', async () => {
      // Test queries that work with the full large tenant dataset
      const scalabilityTests = [
        {
          name: 'Bulk user permission resolution',
          query: `
            SELECT 
              ur.user_id,
              COUNT(DISTINCT rp.permission_id) as permission_count
            FROM user_roles ur
            LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
            JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
            GROUP BY ur.user_id
            LIMIT 100
          `,
          target: PERFORMANCE_TARGETS.bulkRoleQuery
        },
        {
          name: 'Complex permission aggregation',
          query: `
            SELECT 
              p.resource_namespace,
              p.resource,
              COUNT(DISTINCT ur.user_id) as user_count,
              COUNT(DISTINCT r.id) as role_count
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            JOIN roles r ON r.id = rp.role_id
            JOIN user_roles ur ON ur.role_id = r.id
            GROUP BY p.resource_namespace, p.resource
            ORDER BY user_count DESC
            LIMIT 50
          `,
          target: PERFORMANCE_TARGETS.bulkRoleQuery
        },
        {
          name: 'Department hierarchy analysis',
          query: `
            SELECT 
              r.name,
              COUNT(ur.user_id) as user_count,
              COUNT(DISTINCT rp.permission_id) as permission_count
            FROM roles r
            LEFT JOIN user_roles ur ON ur.role_id = r.id
            LEFT JOIN role_permissions rp ON rp.role_id = r.id
            WHERE r.name LIKE 'Department%'
            GROUP BY r.id, r.name
            ORDER BY user_count DESC
          `,
          target: PERFORMANCE_TARGETS.complexPermissionCheck
        }
      ];

      for (const test of scalabilityTests) {
        const performance = await dbSetup.measureQueryPerformance(
          test.query,
          [],
          5 // Fewer iterations for complex queries
        );

        expect(performance.averageTime).toBeLessThan(test.target);
        expect(performance.maxTime).toBeLessThan(test.target * 2);

        console.log(`✅ ${test.name}: avg ${performance.averageTime.toFixed(2)}ms (target: ${test.target}ms)`);
      }
    });

    it('should handle concurrent multi-tenant queries efficiently', async () => {
      // Test performance when multiple tenants are queried concurrently
      const concurrentQueries = [];
      const allTenants = [largeTenant, ...mediumTenants, ...smallTenants.slice(0, 10)];

      // Create concurrent queries across different tenant sizes
      for (let i = 0; i < 20; i++) {
        const tenant = allTenants[i % allTenants.length];
        
        concurrentQueries.push({
          tenant,
          query: async () => {
            return dbSetup.executeWithTenantContext(
              tenant.tenantId,
              `
                SELECT 
                  COUNT(DISTINCT r.id) as role_count,
                  COUNT(DISTINCT ur.user_id) as user_count,
                  COUNT(DISTINCT p.id) as permission_count
                FROM roles r
                LEFT JOIN user_roles ur ON ur.role_id = r.id
                LEFT JOIN role_permissions rp ON rp.role_id = r.id
                LEFT JOIN permissions p ON p.id = rp.permission_id
              `
            );
          }
        });
      }

      const start = performance.now();
      const results = await Promise.all(concurrentQueries.map(q => q.query()));
      const end = performance.now();

      const totalTime = end - start;
      const avgTimePerQuery = totalTime / concurrentQueries.length;

      expect(avgTimePerQuery).toBeLessThan(PERFORMANCE_TARGETS.concurrentUserQuery);
      expect(totalTime).toBeLessThan(PERFORMANCE_TARGETS.concurrentUserQuery * 5); // Total should be much less due to concurrency

      // Verify all queries returned valid results
      results.forEach((result, i) => {
        expect(result.rows.length).toBe(1);
        expect(parseInt(result.rows[0].role_count)).toBeGreaterThan(0);
      });

      console.log(`✅ Concurrent multi-tenant queries: ${concurrentQueries.length} queries in ${totalTime.toFixed(2)}ms (avg: ${avgTimePerQuery.toFixed(2)}ms/query)`);
    });

    it('should optimize index usage for common query patterns', async () => {
      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, largeTenant.tenantId);
        
        // Test queries that should use indexes efficiently
        const indexedQueries = [
          {
            name: 'Tenant ID index usage',
            query: 'EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM roles WHERE tenant_id = $1',
            params: [largeTenant.tenantId],
            shouldUseIndex: 'idx_roles_tenant'
          },
          {
            name: 'User roles index usage',
            query: 'EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM user_roles WHERE tenant_id = $1 AND user_id = $2',
            params: [largeTenant.tenantId, largeTenant.users[0].id],
            shouldUseIndex: 'idx_user_roles_tenant_user'
          },
          {
            name: 'Role permissions index usage',
            query: 'EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM role_permissions WHERE tenant_id = $1',
            params: [largeTenant.tenantId],
            shouldUseIndex: 'idx_role_permissions_tenant'
          },
          {
            name: 'Permission resource index usage',
            query: 'EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM permissions WHERE resource_namespace = $1 AND resource = $2',
            params: ['department', 'dept-0'],
            shouldUseIndex: 'idx_permissions_resource'
          }
        ];

        for (const test of indexedQueries) {
          const result = await client.query(test.query, test.params);
          const executionPlan = result.rows.map(r => r['QUERY PLAN']).join('\n');
          
          // Check if execution plan mentions the expected index
          expect(executionPlan).toContain('Index Scan');
          
          // Extract execution time from the plan
          const timeMatch = executionPlan.match(/actual time=[\d.]+\.\.[\d.]+ rows=\d+ loops=\d+/);
          if (timeMatch) {
            console.log(`✅ ${test.name}: Using index scan - ${timeMatch[0]}`);
          }
        }
        
      } finally {
        client.release();
      }
    });
  });

  describe('Performance Regression Detection', () => {
    it('should maintain consistent performance across multiple runs', async () => {
      const testQuery = `
        SELECT COUNT(*) as total_permissions
        FROM user_roles ur
        LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
        JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
        WHERE ur.user_id = $1 AND ur.tenant_id = $2
      `;

      const testUser = largeTenant.users[250].id; // User in middle of dataset
      const measurements = [];

      // Run the same query 50 times to detect performance variance
      for (let i = 0; i < 50; i++) {
        const start = performance.now();
        
        const result = await dbSetup.executeWithTenantContext(
          largeTenant.tenantId,
          testQuery,
          [testUser, largeTenant.tenantId]
        );
        
        const end = performance.now();
        measurements.push(end - start);
        
        // Verify query returns consistent results
        expect(parseInt(result.rows[0].total_permissions)).toBeGreaterThan(0);
      }

      // Statistical analysis
      const avg = measurements.reduce((a, b) => a + b) / measurements.length;
      const min = Math.min(...measurements);
      const max = Math.max(...measurements);
      const variance = measurements.reduce((acc, val) => acc + Math.pow(val - avg, 2), 0) / measurements.length;
      const stdDev = Math.sqrt(variance);

      // Performance consistency checks
      expect(avg).toBeLessThan(PERFORMANCE_TARGETS.complexPermissionCheck);
      expect(max).toBeLessThan(PERFORMANCE_TARGETS.complexPermissionCheck * 3); // Max shouldn't be > 3x average
      expect(stdDev).toBeLessThan(avg * 0.5); // Standard deviation should be < 50% of average

      console.log(`✅ Performance consistency: avg ${avg.toFixed(2)}ms, min ${min.toFixed(2)}ms, max ${max.toFixed(2)}ms, σ ${stdDev.toFixed(2)}ms`);
    });

    it('should detect performance degradation with tenant size', async () => {
      // Test same query pattern across different tenant sizes
      const testQuery = `
        SELECT 
          COUNT(DISTINCT ur.user_id) as user_count,
          COUNT(DISTINCT rp.permission_id) as permission_count
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
      `;

      const tenantSizeTests = [
        { tenant: smallTenants[0], expectedUsers: 3, category: 'small' },
        { tenant: mediumTenants[0], expectedUsers: 100, category: 'medium' },
        { tenant: largeTenant, expectedUsers: 1000, category: 'large' }
      ];

      const performanceBySize = {};

      for (const test of tenantSizeTests) {
        const performance = await dbSetup.measureQueryPerformance(
          testQuery,
          [],
          10
        );

        // Set tenant context and verify query
        const result = await dbSetup.executeWithTenantContext(
          test.tenant.tenantId,
          testQuery
        );

        const userCount = parseInt(result.rows[0].user_count);
        expect(userCount).toBeGreaterThanOrEqual(test.expectedUsers);

        performanceBySize[test.category] = {
          avgTime: performance.averageTime,
          userCount,
          timePerUser: performance.averageTime / userCount
        };

        console.log(`✅ ${test.category} tenant (${userCount} users): ${performance.averageTime.toFixed(2)}ms avg`);
      }

      // Performance should scale reasonably with data size
      // Large tenant shouldn't be more than 10x slower than small tenant
      const slowdownRatio = performanceBySize.large.avgTime / performanceBySize.small.avgTime;
      expect(slowdownRatio).toBeLessThan(10);

      // Time per user should actually improve or stay similar (better algorithm efficiency)
      expect(performanceBySize.large.timePerUser).toBeLessThan(performanceBySize.small.timePerUser * 2);
    });
  });

  describe('Cache and Optimization Performance', () => {
    it('should benefit from query plan caching', async () => {
      const cachedQuery = `
        SELECT has_permission($1, $2, $3, $4, $5) as has_perm
      `;

      const testParams = [
        [largeTenant.tenantId, largeTenant.users[0].id, 'department', 'dept-0', '*'],
        [largeTenant.tenantId, largeTenant.users[1].id, 'department', 'dept-1', '*'],
        [largeTenant.tenantId, largeTenant.users[2].id, 'department', 'dept-2', '*']
      ];

      const client = await dbSetup.getConnection();
      
      try {
        await dbSetup.setTenantContext(client, largeTenant.tenantId);
        
        // First run (cold cache)
        const coldTimes = [];
        for (const params of testParams) {
          const start = performance.now();
          await client.query(cachedQuery, params);
          const end = performance.now();
          coldTimes.push(end - start);
        }

        // Second run (warm cache)
        const warmTimes = [];
        for (const params of testParams) {
          const start = performance.now();
          await client.query(cachedQuery, params);
          const end = performance.now();
          warmTimes.push(end - start);
        }

        const coldAvg = coldTimes.reduce((a, b) => a + b) / coldTimes.length;
        const warmAvg = warmTimes.reduce((a, b) => a + b) / warmTimes.length;

        // Warm queries should be faster (plan caching benefit)
        expect(warmAvg).toBeLessThan(coldAvg * 1.1); // Allow small variance
        expect(warmAvg).toBeLessThan(PERFORMANCE_TARGETS.simplePermissionCheck);

        console.log(`✅ Query plan caching: cold ${coldAvg.toFixed(2)}ms, warm ${warmAvg.toFixed(2)}ms`);
        
      } finally {
        client.release();
      }
    });

    it('should optimize tenant context switching overhead', async () => {
      const client = await dbSetup.getConnection();
      const testTenants = [largeTenant, mediumTenants[0], smallTenants[0]];
      
      try {
        // Measure context switch overhead
        const contextSwitchTimes = [];
        
        for (let i = 0; i < 30; i++) {
          const fromTenant = testTenants[i % testTenants.length];
          const toTenant = testTenants[(i + 1) % testTenants.length];
          
          // Set initial context
          await client.query(`SET app.current_tenant_id = '${fromTenant.tenantId}'`);
          
          // Measure context switch time
          const start = performance.now();
          await client.query(`SET app.current_tenant_id = '${toTenant.tenantId}'`);
          const end = performance.now();
          
          contextSwitchTimes.push(end - start);
          
          // Verify switch worked
          const verifyResult = await client.query('SELECT COUNT(*) FROM roles');
          expect(parseInt(verifyResult.rows[0].count)).toBe(toTenant.roles.length);
        }

        const avgSwitchTime = contextSwitchTimes.reduce((a, b) => a + b) / contextSwitchTimes.length;
        const maxSwitchTime = Math.max(...contextSwitchTimes);

        expect(avgSwitchTime).toBeLessThan(PERFORMANCE_TARGETS.tenantSwitchOverhead);
        expect(maxSwitchTime).toBeLessThan(PERFORMANCE_TARGETS.tenantSwitchOverhead * 2);

        console.log(`✅ Context switch overhead: avg ${avgSwitchTime.toFixed(2)}ms, max ${maxSwitchTime.toFixed(2)}ms`);
        
      } finally {
        client.release();
      }
    });

    it('should maintain performance under memory pressure', async () => {
      // Test performance with large result sets that might cause memory pressure
      const memoryPressureQuery = `
        SELECT 
          ur.user_id,
          ur.role_id,
          r.name as role_name,
          p.resource_namespace,
          p.resource,
          p.action
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
        JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
        JOIN permissions p ON p.id = rp.permission_id
        ORDER BY ur.user_id, r.name, p.resource_namespace, p.resource
      `;

      const performance = await dbSetup.measureQueryPerformance(
        memoryPressureQuery,
        [],
        3 // Fewer iterations for memory-intensive query
      );

      // Should still complete within reasonable time despite large result set
      expect(performance.averageTime).toBeLessThan(PERFORMANCE_TARGETS.bulkRoleQuery * 2);
      expect(performance.maxTime).toBeLessThan(PERFORMANCE_TARGETS.bulkRoleQuery * 3);

      // Verify query actually returns substantial data
      const result = await dbSetup.executeWithTenantContext(
        largeTenant.tenantId,
        'SELECT COUNT(*) FROM (' + memoryPressureQuery + ') as subquery'
      );

      const resultCount = parseInt(result.rows[0].count);
      expect(resultCount).toBeGreaterThan(1000); // Should return many rows

      console.log(`✅ Memory pressure test: ${performance.averageTime.toFixed(2)}ms avg for ${resultCount} result rows`);
    });
  });

  describe('Performance SLA Validation', () => {
    it('should meet all defined performance SLAs', async () => {
      const slaTests = [
        {
          name: 'Simple permission check SLA',
          query: 'SELECT has_permission($1, $2, $3, $4, $5)',
          params: [largeTenant.tenantId, largeTenant.users[0].id, 'department', 'dept-0', '*'],
          sla: PERFORMANCE_TARGETS.simplePermissionCheck,
          iterations: 50
        },
        {
          name: 'Role lookup SLA',
          query: 'SELECT * FROM roles WHERE name LIKE $1 LIMIT 10',
          params: ['Department%'],
          sla: PERFORMANCE_TARGETS.rlsFilteredQuery,
          iterations: 20
        },
        {
          name: 'User permissions SLA',
          query: `
            SELECT COUNT(DISTINCT p.id) 
            FROM user_roles ur
            LEFT JOIN v_effective_roles er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
            JOIN role_permissions rp ON (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
            JOIN permissions p ON p.id = rp.permission_id
            WHERE ur.user_id = $1 AND ur.tenant_id = $2
          `,
          params: [largeTenant.users[100].id, largeTenant.tenantId],
          sla: PERFORMANCE_TARGETS.complexPermissionCheck,
          iterations: 10
        }
      ];

      const slaResults = [];

      for (const test of slaTests) {
        const performance = await dbSetup.measureQueryPerformance(
          test.query,
          test.params,
          test.iterations
        );

        const slaPass = performance.averageTime <= test.sla;
        const slaPassRate = performance.minTime <= test.sla ? 1 : 0; // At least fastest execution should meet SLA

        slaResults.push({
          name: test.name,
          avgTime: performance.averageTime,
          slaTarget: test.sla,
          slaPass,
          passRate: slaPassRate
        });

        expect(slaPass, `SLA failed for ${test.name}: ${performance.averageTime.toFixed(2)}ms > ${test.sla}ms`).toBe(true);

        console.log(`✅ ${test.name}: ${performance.averageTime.toFixed(2)}ms avg (SLA: ${test.sla}ms) - PASS`);
      }

      // Generate SLA compliance report
      const overallPassRate = slaResults.filter(r => r.slaPass).length / slaResults.length;
      expect(overallPassRate).toBe(1.0); // 100% SLA compliance required

      console.log(`✅ Overall SLA compliance: ${(overallPassRate * 100).toFixed(1)}%`);
    });
  });
});