/**
 * Alerts API Integration Tests
 * iSECTECH Protect - API & Database Integration Testing
 * Tests real API endpoints with test database
 */

import request from 'supertest';
import { app } from '../../../backend/cmd/api-gateway/main';
import { setupTestDatabase, cleanupTestDatabase } from '../../setup/database-setup';
import { createTestUser, getTestToken } from '../../setup/auth-setup';

describe('Alerts API Integration Tests', () => {
  let testDb: any;
  let authToken: string;
  let testUserId: string;
  let testTenantId: string;

  beforeAll(async () => {
    // Setup test database
    testDb = await setupTestDatabase();
    
    // Create test user with proper permissions
    const testUser = await createTestUser({
      email: 'test.analyst@isectech.com',
      role: 'SECURITY_ANALYST',
      permissions: ['read:alerts', 'write:alerts', 'acknowledge:alerts'],
      securityClearance: 'SECRET',
      tenantId: 'test-tenant-123',
    });
    
    testUserId = testUser.id;
    testTenantId = testUser.tenantId;
    authToken = await getTestToken(testUser);
  });

  afterAll(async () => {
    await cleanupTestDatabase(testDb);
  });

  beforeEach(async () => {
    // Clean alerts table before each test
    await testDb.query('DELETE FROM alerts WHERE tenant_id = $1', [testTenantId]);
  });

  describe('GET /api/alerts', () => {
    beforeEach(async () => {
      // Insert test alerts
      await testDb.query(`
        INSERT INTO alerts (id, title, severity, status, type, description, source_ip, tenant_id, created_at)
        VALUES 
        ($1, 'Test Alert 1', 'HIGH', 'ACTIVE', 'NETWORK_ANOMALY', 'Test description 1', '192.168.1.100', $2, NOW()),
        ($3, 'Test Alert 2', 'CRITICAL', 'ACKNOWLEDGED', 'MALWARE', 'Test description 2', '192.168.1.101', $2, NOW()),
        ($4, 'Test Alert 3', 'MEDIUM', 'RESOLVED', 'INTRUSION', 'Test description 3', '192.168.1.102', $2, NOW())
      `, ['alert-1', testTenantId, 'alert-2', 'alert-3']);
    });

    it('should retrieve all alerts for authenticated user', async () => {
      const response = await request(app)
        .get('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(3);
      expect(response.body.pagination.total).toBe(3);
      
      // Verify alert structure
      const alert = response.body.data[0];
      expect(alert).toHaveProperty('id');
      expect(alert).toHaveProperty('title');
      expect(alert).toHaveProperty('severity');
      expect(alert).toHaveProperty('status');
      expect(alert).toHaveProperty('type');
    });

    it('should filter alerts by severity', async () => {
      const response = await request(app)
        .get('/api/alerts?severity=CRITICAL')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].severity).toBe('CRITICAL');
    });

    it('should filter alerts by status', async () => {
      const response = await request(app)
        .get('/api/alerts?status=ACTIVE')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].status).toBe('ACTIVE');
    });

    it('should paginate alerts correctly', async () => {
      const response = await request(app)
        .get('/api/alerts?page=1&limit=2')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(2);
      expect(response.body.pagination.page).toBe(1);
      expect(response.body.pagination.limit).toBe(2);
      expect(response.body.pagination.total).toBe(3);
      expect(response.body.pagination.pages).toBe(2);
    });

    it('should sort alerts by timestamp', async () => {
      const response = await request(app)
        .get('/api/alerts?sort=created_at&order=desc')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const alerts = response.body.data;
      expect(new Date(alerts[0].created_at).getTime())
        .toBeGreaterThanOrEqual(new Date(alerts[1].created_at).getTime());
    });

    it('should enforce tenant isolation', async () => {
      // Create another tenant's alerts
      await testDb.query(`
        INSERT INTO alerts (id, title, severity, status, tenant_id, created_at)
        VALUES ($1, 'Other Tenant Alert', 'HIGH', 'ACTIVE', $2, NOW())
      `, ['other-alert', 'other-tenant']);

      const response = await request(app)
        .get('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Should only see own tenant's alerts
      expect(response.body.data).toHaveLength(3);
      expect(response.body.data.every(alert => alert.tenant_id === testTenantId)).toBe(true);
    });

    it('should return 401 without authentication', async () => {
      await request(app)
        .get('/api/alerts')
        .expect(401);
    });

    it('should return 403 without proper permissions', async () => {
      const limitedUser = await createTestUser({
        email: 'limited@isectech.com',
        role: 'VIEWER',
        permissions: ['read:dashboard'], // No alert permissions
        tenantId: testTenantId,
      });
      
      const limitedToken = await getTestToken(limitedUser);

      await request(app)
        .get('/api/alerts')
        .set('Authorization', `Bearer ${limitedToken}`)
        .expect(403);
    });
  });

  describe('POST /api/alerts', () => {
    it('should create new alert with valid data', async () => {
      const alertData = {
        title: 'New Security Alert',
        severity: 'HIGH',
        type: 'NETWORK_ANOMALY',
        description: 'Suspicious network activity detected',
        source_ip: '192.168.1.200',
        destination_ip: '10.0.0.1',
        metadata: {
          protocol: 'TCP',
          port: 443,
          bytes: 1024000,
        },
        tags: ['network', 'anomaly'],
      };

      const response = await request(app)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(alertData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.id).toBeDefined();
      expect(response.body.data.title).toBe(alertData.title);
      expect(response.body.data.tenant_id).toBe(testTenantId);
      expect(response.body.data.created_by).toBe(testUserId);

      // Verify alert was saved to database
      const savedAlert = await testDb.query(
        'SELECT * FROM alerts WHERE id = $1',
        [response.body.data.id]
      );
      expect(savedAlert.rows).toHaveLength(1);
    });

    it('should validate required fields', async () => {
      const invalidData = {
        severity: 'HIGH',
        // Missing title and type
      };

      const response = await request(app)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.errors).toContain('title is required');
      expect(response.body.errors).toContain('type is required');
    });

    it('should validate severity levels', async () => {
      const invalidData = {
        title: 'Test Alert',
        severity: 'INVALID_SEVERITY',
        type: 'NETWORK_ANOMALY',
      };

      await request(app)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);
    });

    it('should sanitize input data', async () => {
      const maliciousData = {
        title: '<script>alert("xss")</script>Malicious Alert',
        severity: 'HIGH',
        type: 'NETWORK_ANOMALY',
        description: 'DROP TABLE alerts; --',
        source_ip: '192.168.1.100',
      };

      const response = await request(app)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(maliciousData)
        .expect(201);

      // Should sanitize XSS
      expect(response.body.data.title).toBe('Malicious Alert');
      
      // Should not contain SQL injection
      expect(response.body.data.description).not.toContain('DROP TABLE');
    });

    it('should auto-assign tenant_id from authenticated user', async () => {
      const alertData = {
        title: 'Test Alert',
        severity: 'MEDIUM',
        type: 'NETWORK_ANOMALY',
      };

      const response = await request(app)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(alertData)
        .expect(201);

      expect(response.body.data.tenant_id).toBe(testTenantId);
    });
  });

  describe('PUT /api/alerts/:id', () => {
    let testAlertId: string;

    beforeEach(async () => {
      const result = await testDb.query(`
        INSERT INTO alerts (id, title, severity, status, tenant_id, created_by)
        VALUES ($1, 'Test Alert', 'MEDIUM', 'ACTIVE', $2, $3)
        RETURNING id
      `, ['test-alert-update', testTenantId, testUserId]);
      
      testAlertId = result.rows[0].id;
    });

    it('should update alert with valid data', async () => {
      const updateData = {
        title: 'Updated Alert Title',
        severity: 'HIGH',
        status: 'ACKNOWLEDGED',
        assignee: testUserId,
        notes: 'Alert acknowledged by analyst',
      };

      const response = await request(app)
        .put(`/api/alerts/${testAlertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.title).toBe(updateData.title);
      expect(response.body.data.severity).toBe(updateData.severity);
      expect(response.body.data.status).toBe(updateData.status);

      // Verify update in database
      const updatedAlert = await testDb.query(
        'SELECT * FROM alerts WHERE id = $1',
        [testAlertId]
      );
      expect(updatedAlert.rows[0].title).toBe(updateData.title);
    });

    it('should create audit log entry for updates', async () => {
      const updateData = {
        status: 'RESOLVED',
        notes: 'False positive - resolved',
      };

      await request(app)
        .put(`/api/alerts/${testAlertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      // Verify audit log entry
      const auditLog = await testDb.query(`
        SELECT * FROM audit_logs 
        WHERE resource_type = 'alert' 
        AND resource_id = $1 
        AND action = 'update'
      `, [testAlertId]);

      expect(auditLog.rows).toHaveLength(1);
      expect(auditLog.rows[0].user_id).toBe(testUserId);
    });

    it('should enforce tenant isolation for updates', async () => {
      // Try to update alert from different tenant
      const otherTenantAlert = await testDb.query(`
        INSERT INTO alerts (id, title, tenant_id, created_by)
        VALUES ($1, 'Other Tenant Alert', $2, $3)
        RETURNING id
      `, ['other-alert', 'other-tenant', 'other-user']);

      await request(app)
        .put(`/api/alerts/${otherTenantAlert.rows[0].id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ title: 'Hacked' })
        .expect(404); // Should not find alert from different tenant
    });

    it('should validate status transitions', async () => {
      // Try invalid status transition
      await request(app)
        .put(`/api/alerts/${testAlertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ status: 'INVALID_STATUS' })
        .expect(400);
    });
  });

  describe('DELETE /api/alerts/:id', () => {
    let testAlertId: string;

    beforeEach(async () => {
      const result = await testDb.query(`
        INSERT INTO alerts (id, title, severity, tenant_id, created_by)
        VALUES ($1, 'Test Alert Delete', 'LOW', $2, $3)
        RETURNING id
      `, ['test-alert-delete', testTenantId, testUserId]);
      
      testAlertId = result.rows[0].id;
    });

    it('should soft delete alert', async () => {
      const response = await request(app)
        .delete(`/api/alerts/${testAlertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify soft delete (should still exist but marked as deleted)
      const deletedAlert = await testDb.query(
        'SELECT * FROM alerts WHERE id = $1',
        [testAlertId]
      );
      expect(deletedAlert.rows[0].deleted_at).not.toBeNull();
    });

    it('should create audit log for deletion', async () => {
      await request(app)
        .delete(`/api/alerts/${testAlertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const auditLog = await testDb.query(`
        SELECT * FROM audit_logs 
        WHERE resource_type = 'alert' 
        AND resource_id = $1 
        AND action = 'delete'
      `, [testAlertId]);

      expect(auditLog.rows).toHaveLength(1);
    });

    it('should require admin permissions for deletion', async () => {
      const analystUser = await createTestUser({
        email: 'analyst.only@isectech.com',
        role: 'SECURITY_ANALYST',
        permissions: ['read:alerts', 'write:alerts'], // No delete permission
        tenantId: testTenantId,
      });
      
      const analystToken = await getTestToken(analystUser);

      await request(app)
        .delete(`/api/alerts/${testAlertId}`)
        .set('Authorization', `Bearer ${analystToken}`)
        .expect(403);
    });
  });

  describe('POST /api/alerts/bulk', () => {
    let testAlertIds: string[];

    beforeEach(async () => {
      const alerts = await testDb.query(`
        INSERT INTO alerts (id, title, severity, status, tenant_id, created_by)
        VALUES 
        ($1, 'Bulk Test 1', 'HIGH', 'ACTIVE', $4, $5),
        ($2, 'Bulk Test 2', 'MEDIUM', 'ACTIVE', $4, $5),
        ($3, 'Bulk Test 3', 'LOW', 'ACTIVE', $4, $5)
        RETURNING id
      `, ['bulk-1', 'bulk-2', 'bulk-3', testTenantId, testUserId]);
      
      testAlertIds = alerts.rows.map(row => row.id);
    });

    it('should acknowledge multiple alerts', async () => {
      const bulkData = {
        alert_ids: testAlertIds,
        action: 'acknowledge',
        assignee: testUserId,
        notes: 'Bulk acknowledgment',
      };

      const response = await request(app)
        .post('/api/alerts/bulk')
        .set('Authorization', `Bearer ${authToken}`)
        .send(bulkData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.updated_count).toBe(3);

      // Verify all alerts were updated
      const updatedAlerts = await testDb.query(`
        SELECT * FROM alerts 
        WHERE id = ANY($1) AND status = 'ACKNOWLEDGED'
      `, [testAlertIds]);

      expect(updatedAlerts.rows).toHaveLength(3);
    });

    it('should assign multiple alerts', async () => {
      const bulkData = {
        alert_ids: testAlertIds.slice(0, 2), // Only first 2 alerts
        action: 'assign',
        assignee: testUserId,
      };

      const response = await request(app)
        .post('/api/alerts/bulk')
        .set('Authorization', `Bearer ${authToken}`)
        .send(bulkData)
        .expect(200);

      expect(response.body.data.updated_count).toBe(2);

      // Verify assignments
      const assignedAlerts = await testDb.query(`
        SELECT * FROM alerts 
        WHERE id = ANY($1) AND assignee = $2
      `, [testAlertIds.slice(0, 2), testUserId]);

      expect(assignedAlerts.rows).toHaveLength(2);
    });

    it('should validate bulk operation limits', async () => {
      const tooManyIds = Array.from({ length: 101 }, (_, i) => `fake-id-${i}`);
      
      const bulkData = {
        alert_ids: tooManyIds,
        action: 'acknowledge',
      };

      const response = await request(app)
        .post('/api/alerts/bulk')
        .set('Authorization', `Bearer ${authToken}`)
        .send(bulkData)
        .expect(400);

      expect(response.body.error).toContain('Too many alerts');
    });

    it('should handle partial failures gracefully', async () => {
      const mixedIds = [...testAlertIds.slice(0, 2), 'non-existent-id'];
      
      const bulkData = {
        alert_ids: mixedIds,
        action: 'acknowledge',
      };

      const response = await request(app)
        .post('/api/alerts/bulk')
        .set('Authorization', `Bearer ${authToken}`)
        .send(bulkData)
        .expect(200);

      expect(response.body.data.updated_count).toBe(2);
      expect(response.body.data.failed_count).toBe(1);
      expect(response.body.data.errors).toHaveLength(1);
    });
  });

  describe('Database Transaction Integrity', () => {
    it('should rollback on database errors', async () => {
      // Mock database error during insert
      const originalQuery = testDb.query;
      testDb.query = jest.fn().mockRejectedValueOnce(new Error('Database error'));

      const alertData = {
        title: 'Transaction Test',
        severity: 'HIGH',
        type: 'NETWORK_ANOMALY',
      };

      await request(app)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(alertData)
        .expect(500);

      // Restore original query function
      testDb.query = originalQuery;

      // Verify no partial data was saved
      const alerts = await testDb.query(
        'SELECT * FROM alerts WHERE title = $1',
        ['Transaction Test']
      );
      expect(alerts.rows).toHaveLength(0);
    });

    it('should maintain referential integrity', async () => {
      // Create alert with non-existent assignee (should fail)
      const alertData = {
        title: 'Integrity Test',
        severity: 'HIGH',
        type: 'NETWORK_ANOMALY',
        assignee: 'non-existent-user-id',
      };

      await request(app)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(alertData)
        .expect(400);
    });
  });

  describe('Performance Tests', () => {
    beforeAll(async () => {
      // Insert 1000 test alerts for performance testing
      const insertPromises = [];
      for (let i = 0; i < 1000; i++) {
        insertPromises.push(
          testDb.query(`
            INSERT INTO alerts (id, title, severity, status, tenant_id, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
          `, [`perf-alert-${i}`, `Performance Alert ${i}`, 'MEDIUM', 'ACTIVE', testTenantId])
        );
      }
      await Promise.all(insertPromises);
    });

    it('should handle large result sets efficiently', async () => {
      const startTime = Date.now();
      
      const response = await request(app)
        .get('/api/alerts?limit=1000')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(response.body.data).toHaveLength(1000);
      expect(responseTime).toBeLessThan(2000); // Should respond within 2 seconds
    });

    it('should use database indexes effectively', async () => {
      // Query with indexed fields should be fast
      const startTime = Date.now();
      
      await request(app)
        .get('/api/alerts?severity=HIGH&status=ACTIVE&limit=100')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(responseTime).toBeLessThan(500); // Should be very fast with indexes
    });
  });
});