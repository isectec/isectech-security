/**
 * Database Test Setup Infrastructure
 * Provides real PostgreSQL connections for RBAC testing
 */

import { Pool, PoolClient, PoolConfig } from 'pg';
import { readFileSync } from 'fs';
import { join } from 'path';

export interface TestTenantContext {
  tenantId: string;
  tenantName: string;
  users: TestUser[];
  roles: TestRole[];
  permissions: TestPermission[];
}

export interface TestUser {
  id: string;
  email: string;
  roleIds: string[];
}

export interface TestRole {
  id: string;
  name: string;
  description: string;
  parentRoleId?: string;
  permissions: string[];
}

export interface TestPermission {
  id: string;
  resourceNamespace: string;
  resource: string;
  action: string;
}

export class DatabaseTestSetup {
  private testPool: Pool;
  private adminPool: Pool;
  private testDbName: string;
  
  constructor(testDbName: string = 'rbac_test_db') {
    this.testDbName = testDbName;
    
    // Admin connection for database setup
    this.adminPool = new Pool({
      host: process.env.TEST_DB_HOST || 'localhost',
      port: parseInt(process.env.TEST_DB_PORT || '5432'),
      user: process.env.TEST_DB_ADMIN_USER || 'postgres',
      password: process.env.TEST_DB_ADMIN_PASSWORD || 'test',
      database: 'postgres', // Connect to default database for setup
      max: 5,
      idleTimeoutMillis: 30000,
    });

    // Test database connection
    this.testPool = new Pool({
      host: process.env.TEST_DB_HOST || 'localhost',
      port: parseInt(process.env.TEST_DB_PORT || '5432'),
      user: process.env.TEST_DB_USER || 'test_user',
      password: process.env.TEST_DB_PASSWORD || 'test',
      database: this.testDbName,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });
  }

  /**
   * Initialize test database with RBAC schema
   */
  async initialize(): Promise<void> {
    try {
      // Create test database if it doesn't exist
      await this.createTestDatabase();
      
      // Apply RBAC schema
      await this.applyRBACSchema();
      
      // Apply emergency RLS policies
      await this.applyRLSPolicies();
      
      // Create test roles and users
      await this.createTestUsers();
      
      console.log('✅ Database test setup completed successfully');
    } catch (error) {
      console.error('❌ Database test setup failed:', error);
      throw error;
    }
  }

  /**
   * Create isolated test database
   */
  private async createTestDatabase(): Promise<void> {
    const client = await this.adminPool.connect();
    
    try {
      // Drop existing test database
      await client.query(`DROP DATABASE IF EXISTS "${this.testDbName}"`);
      
      // Create fresh test database
      await client.query(`CREATE DATABASE "${this.testDbName}" OWNER postgres`);
      
      // Create application role
      await client.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'application_role') THEN
            CREATE ROLE application_role;
          END IF;
        END
        $$;
      `);
      
      // Grant permissions to test user
      await client.query(`
        GRANT CONNECT ON DATABASE "${this.testDbName}" TO application_role;
        GRANT USAGE, CREATE ON SCHEMA public TO application_role;
      `);
      
    } finally {
      client.release();
    }
  }

  /**
   * Apply RBAC schema from backend/security/rbac_schema.sql
   */
  private async applyRBACSchema(): Promise<void> {
    const client = await this.testPool.connect();
    
    try {
      const schemaPath = join(__dirname, '../backend/security/rbac_schema.sql');
      const schema = readFileSync(schemaPath, 'utf8');
      
      await client.query(schema);
      
      // Grant necessary permissions to application role
      await client.query(`
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO application_role;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO application_role;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO application_role;
      `);
      
    } finally {
      client.release();
    }
  }

  /**
   * Apply RLS policies from emergency-rls-policies.sql
   */
  private async applyRLSPolicies(): Promise<void> {
    const client = await this.testPool.connect();
    
    try {
      // Create audit log table for RLS testing
      await client.query(`
        CREATE TABLE IF NOT EXISTS security_audit_log (
          id BIGSERIAL PRIMARY KEY,
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          table_name TEXT NOT NULL,
          operation_type TEXT NOT NULL,
          user_tenant_id TEXT,
          resource_tenant_id TEXT,
          violation_context JSONB DEFAULT '{}',
          timestamp TIMESTAMPTZ DEFAULT NOW(),
          session_id TEXT,
          application_user TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_security_audit_log_event_type ON security_audit_log(event_type);
        CREATE INDEX IF NOT EXISTS idx_security_audit_log_timestamp ON security_audit_log(timestamp);
      `);

      // Apply key RLS functions from emergency policies
      const rlsFunctions = `
        -- Create tenant context validation function
        CREATE OR REPLACE FUNCTION get_current_tenant_id() 
        RETURNS uuid 
        LANGUAGE plpgsql 
        SECURITY DEFINER
        STABLE
        AS $$
        DECLARE
            tenant_id uuid;
        BEGIN
            BEGIN
                tenant_id := current_setting('app.current_tenant_id')::uuid;
                
                IF tenant_id IS NULL THEN
                    RAISE EXCEPTION 'Tenant context not set - access denied';
                END IF;
                
                RETURN tenant_id;
            EXCEPTION
                WHEN others THEN
                    RAISE EXCEPTION 'Tenant validation failed - access denied: %', SQLERRM;
            END;
        END;
        $$;

        -- Create audit logging function
        CREATE OR REPLACE FUNCTION audit_rls_violation(
            table_name text,
            operation text,
            user_tenant_id text,
            resource_tenant_id text,
            additional_context jsonb DEFAULT '{}'::jsonb
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        AS $$
        BEGIN
            INSERT INTO security_audit_log (
                event_type,
                severity,
                table_name,
                operation_type,
                user_tenant_id,
                resource_tenant_id,
                violation_context,
                timestamp
            ) VALUES (
                'RLS_VIOLATION',
                'CRITICAL',
                table_name,
                operation,
                user_tenant_id,
                resource_tenant_id,
                additional_context,
                NOW()
            );
        END;
        $$;
      `;
      
      await client.query(rlsFunctions);
      
    } finally {
      client.release();
    }
  }

  /**
   * Create test users and database roles
   */
  private async createTestUsers(): Promise<void> {
    const client = await this.adminPool.connect();
    
    try {
      // Create test database user if not exists
      await client.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'test_user') THEN
            CREATE ROLE test_user WITH LOGIN PASSWORD 'test';
          END IF;
        END
        $$;
      `);
      
      // Grant application role to test user
      await client.query('GRANT application_role TO test_user');
      
    } finally {
      client.release();
    }
  }

  /**
   * Set tenant context for current session
   */
  async setTenantContext(client: PoolClient, tenantId: string, userId?: string): Promise<void> {
    await client.query(`SET app.current_tenant_id = '${tenantId}'`);
    
    if (userId) {
      await client.query(`SET app.current_user_id = '${userId}'`);
    }
  }

  /**
   * Clear tenant context for current session
   */
  async clearTenantContext(client: PoolClient): Promise<void> {
    await client.query('RESET app.current_tenant_id');
    await client.query('RESET app.current_user_id');
  }

  /**
   * Create test tenant with users, roles, and permissions
   */
  async createTestTenant(tenantData: TestTenantContext): Promise<void> {
    const client = await this.testPool.connect();
    
    try {
      await client.query('BEGIN');
      
      // Set admin context for creation
      await this.setTenantContext(client, tenantData.tenantId);
      
      // Create tenant
      await client.query(`
        INSERT INTO tenants (id, name) 
        VALUES ($1, $2)
        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
      `, [tenantData.tenantId, tenantData.tenantName]);
      
      // Create users
      for (const user of tenantData.users) {
        await client.query(`
          INSERT INTO users (id, email) 
          VALUES ($1, $2)
          ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email
        `, [user.id, user.email]);
      }
      
      // Create permissions
      for (const permission of tenantData.permissions) {
        await client.query(`
          INSERT INTO permissions (id, resource_namespace, resource, action) 
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (resource_namespace, resource, action) DO NOTHING
        `, [permission.id, permission.resourceNamespace, permission.resource, permission.action]);
      }
      
      // Create roles
      for (const role of tenantData.roles) {
        await client.query(`
          INSERT INTO roles (id, tenant_id, name, description) 
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description
        `, [role.id, tenantData.tenantId, role.name, role.description]);
        
        // Assign permissions to role
        for (const permissionId of role.permissions) {
          await client.query(`
            INSERT INTO role_permissions (tenant_id, role_id, permission_id)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
          `, [tenantData.tenantId, role.id, permissionId]);
        }
      }
      
      // Set up role hierarchy
      for (const role of tenantData.roles) {
        if (role.parentRoleId) {
          await client.query(`
            INSERT INTO role_hierarchy (tenant_id, parent_role_id, child_role_id)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
          `, [tenantData.tenantId, role.parentRoleId, role.id]);
        }
      }
      
      // Assign roles to users
      for (const user of tenantData.users) {
        for (const roleId of user.roleIds) {
          await client.query(`
            INSERT INTO user_roles (tenant_id, user_id, role_id)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
          `, [tenantData.tenantId, user.id, roleId]);
        }
      }
      
      await client.query('COMMIT');
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get database connection for testing
   */
  async getConnection(): Promise<PoolClient> {
    return await this.testPool.connect();
  }

  /**
   * Execute query with tenant context
   */
  async executeWithTenantContext<T = any>(
    tenantId: string, 
    query: string, 
    params: any[] = [],
    userId?: string
  ): Promise<{ rows: T[]; rowCount: number }> {
    const client = await this.testPool.connect();
    
    try {
      await this.setTenantContext(client, tenantId, userId);
      const result = await client.query(query, params);
      return {
        rows: result.rows,
        rowCount: result.rowCount || 0
      };
    } finally {
      client.release();
    }
  }

  /**
   * Verify RLS is enabled on critical tables
   */
  async verifyRLSEnabled(): Promise<{ table: string; rlsEnabled: boolean; policyCount: number }[]> {
    const client = await this.testPool.connect();
    
    try {
      const result = await client.query(`
        SELECT 
          schemaname,
          tablename,
          rowsecurity as rls_enabled,
          (SELECT COUNT(*) FROM pg_policy WHERE polrelid = (schemaname||'.'||tablename)::regclass) as policy_count
        FROM pg_tables 
        WHERE schemaname = 'public'
        AND tablename IN ('roles', 'role_hierarchy', 'role_permissions', 'user_roles')
        ORDER BY tablename
      `);
      
      return result.rows.map(row => ({
        table: row.tablename,
        rlsEnabled: row.rls_enabled,
        policyCount: parseInt(row.policy_count)
      }));
    } finally {
      client.release();
    }
  }

  /**
   * Get security audit log entries
   */
  async getSecurityAuditLogs(eventType?: string): Promise<any[]> {
    const client = await this.testPool.connect();
    
    try {
      const query = eventType 
        ? 'SELECT * FROM security_audit_log WHERE event_type = $1 ORDER BY timestamp DESC LIMIT 100'
        : 'SELECT * FROM security_audit_log ORDER BY timestamp DESC LIMIT 100';
      
      const params = eventType ? [eventType] : [];
      const result = await client.query(query, params);
      
      return result.rows;
    } finally {
      client.release();
    }
  }

  /**
   * Clean up test data between tests
   */
  async cleanup(): Promise<void> {
    const client = await this.testPool.connect();
    
    try {
      await client.query('BEGIN');
      
      // Clear test data in reverse dependency order
      await client.query('TRUNCATE user_roles CASCADE');
      await client.query('TRUNCATE role_hierarchy CASCADE');
      await client.query('TRUNCATE role_permissions CASCADE');
      await client.query('TRUNCATE roles CASCADE');
      await client.query('TRUNCATE permissions CASCADE');
      await client.query('TRUNCATE users CASCADE');
      await client.query('TRUNCATE tenants CASCADE');
      await client.query('TRUNCATE security_audit_log CASCADE');
      
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Cleanup and close connections
   */
  async destroy(): Promise<void> {
    await this.testPool.end();
    
    // Drop test database
    const client = await this.adminPool.connect();
    try {
      await client.query(`DROP DATABASE IF EXISTS "${this.testDbName}"`);
    } finally {
      client.release();
      await this.adminPool.end();
    }
  }

  /**
   * Test data factory methods
   */
  static createTestTenantData(tenantId: string, tenantName: string): TestTenantContext {
    return {
      tenantId,
      tenantName,
      users: [
        {
          id: `${tenantId}-user-1`,
          email: `user1@${tenantName.toLowerCase()}.com`,
          roleIds: [`${tenantId}-role-admin`]
        },
        {
          id: `${tenantId}-user-2`,
          email: `user2@${tenantName.toLowerCase()}.com`,
          roleIds: [`${tenantId}-role-analyst`]
        },
        {
          id: `${tenantId}-user-3`,
          email: `user3@${tenantName.toLowerCase()}.com`,
          roleIds: [`${tenantId}-role-viewer`]
        }
      ],
      roles: [
        {
          id: `${tenantId}-role-admin`,
          name: 'Admin',
          description: 'Full administrative access',
          permissions: [`perm-admin-all`]
        },
        {
          id: `${tenantId}-role-analyst`,
          name: 'Security Analyst',
          description: 'Security analysis and monitoring',
          parentRoleId: `${tenantId}-role-viewer`,
          permissions: [`perm-alerts-write`, `perm-reports-read`]
        },
        {
          id: `${tenantId}-role-viewer`,
          name: 'Viewer',
          description: 'Read-only access to security data',
          permissions: [`perm-alerts-read`, `perm-events-read`]
        }
      ],
      permissions: [
        {
          id: 'perm-admin-all',
          resourceNamespace: 'security',
          resource: '*',
          action: '*'
        },
        {
          id: 'perm-alerts-read',
          resourceNamespace: 'security',
          resource: 'alerts',
          action: 'read'
        },
        {
          id: 'perm-alerts-write',
          resourceNamespace: 'security',
          resource: 'alerts',
          action: 'write'
        },
        {
          id: 'perm-events-read',
          resourceNamespace: 'security',
          resource: 'events',
          action: 'read'
        },
        {
          id: 'perm-reports-read',
          resourceNamespace: 'security',
          resource: 'reports',
          action: 'read'
        }
      ]
    };
  }

  /**
   * Performance monitoring utilities
   */
  async measureQueryPerformance(query: string, params: any[] = [], iterations: number = 10): Promise<{
    averageTime: number;
    minTime: number;
    maxTime: number;
    totalTime: number;
  }> {
    const client = await this.testPool.connect();
    const times: number[] = [];
    
    try {
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        await client.query(query, params);
        const end = performance.now();
        times.push(end - start);
      }
      
      const totalTime = times.reduce((sum, time) => sum + time, 0);
      return {
        averageTime: totalTime / iterations,
        minTime: Math.min(...times),
        maxTime: Math.max(...times),
        totalTime
      };
    } finally {
      client.release();
    }
  }
}

// Export test helper constants
export const TEST_TENANTS = {
  ENTERPRISE: {
    id: '123e4567-e89b-12d3-a456-426614174000',
    name: 'Enterprise Corp'
  },
  GOVERNMENT: {
    id: '234e5678-e89b-12d3-a456-426614174001', 
    name: 'Gov Agency'
  },
  MSP: {
    id: '345e6789-e89b-12d3-a456-426614174002',
    name: 'MSP Provider'
  }
};