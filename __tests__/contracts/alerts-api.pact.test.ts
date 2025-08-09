/**
 * Alerts API Contract Tests (Consumer Side)
 * iSECTECH Protect - API Contract Validation
 */

import { Pact, Matchers } from '@pact-foundation/pact';
import { AlertsAPI } from '@/lib/api/services/alerts';
import path from 'path';

const { like, eachLike, iso8601DateTime, uuid } = Matchers;

const mockProvider = new Pact({
  consumer: 'isectech-frontend',
  provider: 'isectech-alerts-api',
  port: 1235,
  log: path.resolve(process.cwd(), 'logs', 'pact-alerts.log'),
  dir: path.resolve(process.cwd(), 'pacts'),
  logLevel: 'INFO',
  spec: 3,
});

describe('Alerts API Contract Tests', () => {
  beforeAll(() => mockProvider.setup());
  afterAll(() => mockProvider.finalize());
  afterEach(() => mockProvider.verify());

  describe('GET /api/alerts', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'alerts exist for tenant',
        uponReceiving: 'a request for alerts list',
        withRequest: {
          method: 'GET',
          path: '/api/alerts',
          headers: {
            'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
            'Accept': 'application/json',
          },
          query: {
            page: '1',
            limit: '50',
            severity: 'HIGH',
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: eachLike({
              id: uuid('alert-123'),
              title: like('Suspicious Network Activity'),
              severity: like('HIGH'),
              status: like('ACTIVE'),
              type: like('NETWORK_ANOMALY'),
              description: like('Unusual traffic patterns detected'),
              source_ip: like('192.168.1.100'),
              destination_ip: like('10.0.0.1'),
              tenant_id: uuid('tenant-abc'),
              created_by: uuid('user-123'),
              created_at: iso8601DateTime('2025-01-02T10:30:00Z'),
              updated_at: iso8601DateTime('2025-01-02T10:30:00Z'),
              assignee: null,
              tags: eachLike('network'),
              metadata: like({
                protocol: 'TCP',
                port: 443,
                bytes: 1024000,
              }),
            }),
            pagination: {
              page: like(1),
              limit: like(50),
              total: like(150),
              pages: like(3),
            },
          },
        },
      });
    });

    it('returns paginated alerts list', async () => {
      const alertsAPI = new AlertsAPI('http://localhost:1235');
      
      const response = await alertsAPI.getAlerts({
        page: 1,
        limit: 50,
        severity: 'HIGH',
      }, 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

      expect(response.success).toBe(true);
      expect(response.data).toHaveLength(1);
      expect(response.data[0]).toHaveProperty('id');
      expect(response.data[0]).toHaveProperty('title');
      expect(response.data[0]).toHaveProperty('severity');
      expect(response.data[0]).toHaveProperty('metadata');
      expect(response.pagination).toHaveProperty('total');
    });
  });

  describe('POST /api/alerts', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'user can create alerts',
        uponReceiving: 'a request to create new alert',
        withRequest: {
          method: 'POST',
          path: '/api/alerts',
          headers: {
            'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
            'Content-Type': 'application/json',
          },
          body: {
            title: like('New Security Alert'),
            severity: like('HIGH'),
            type: like('NETWORK_ANOMALY'),
            description: like('Suspicious activity detected'),
            source_ip: like('192.168.1.200'),
            destination_ip: like('10.0.0.1'),
            metadata: like({
              protocol: 'TCP',
              port: 443,
              bytes: 1024000,
            }),
            tags: eachLike('network'),
          },
        },
        willRespondWith: {
          status: 201,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: {
              id: uuid('alert-new-123'),
              title: like('New Security Alert'),
              severity: like('HIGH'),
              status: like('ACTIVE'),
              type: like('NETWORK_ANOMALY'),
              description: like('Suspicious activity detected'),
              source_ip: like('192.168.1.200'),
              destination_ip: like('10.0.0.1'),
              tenant_id: uuid('tenant-abc'),
              created_by: uuid('user-123'),
              created_at: iso8601DateTime('2025-01-02T12:00:00Z'),
              updated_at: iso8601DateTime('2025-01-02T12:00:00Z'),
              assignee: null,
              tags: eachLike('network'),
              metadata: like({
                protocol: 'TCP',
                port: 443,
                bytes: 1024000,
              }),
            },
          },
        },
      });
    });

    it('creates new alert with valid data', async () => {
      const alertsAPI = new AlertsAPI('http://localhost:1235');
      
      const alertData = {
        title: 'New Security Alert',
        severity: 'HIGH' as const,
        type: 'NETWORK_ANOMALY' as const,
        description: 'Suspicious activity detected',
        source_ip: '192.168.1.200',
        destination_ip: '10.0.0.1',
        metadata: {
          protocol: 'TCP',
          port: 443,
          bytes: 1024000,
        },
        tags: ['network'],
      };

      const response = await alertsAPI.createAlert(
        alertData,
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
      );

      expect(response.success).toBe(true);
      expect(response.data.id).toBeDefined();
      expect(response.data.title).toBe(alertData.title);
      expect(response.data.severity).toBe(alertData.severity);
      expect(response.data.status).toBe('ACTIVE');
    });
  });

  describe('PUT /api/alerts/:id', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'alert exists and user can update it',
        uponReceiving: 'a request to update alert',
        withRequest: {
          method: 'PUT',
          path: '/api/alerts/alert-123',
          headers: {
            'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
            'Content-Type': 'application/json',
          },
          body: {
            status: like('ACKNOWLEDGED'),
            assignee: uuid('user-123'),
            notes: like('Alert acknowledged by security analyst'),
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: {
              id: like('alert-123'),
              title: like('Suspicious Network Activity'),
              severity: like('HIGH'),
              status: like('ACKNOWLEDGED'),
              type: like('NETWORK_ANOMALY'),
              description: like('Unusual traffic patterns detected'),
              source_ip: like('192.168.1.100'),
              tenant_id: uuid('tenant-abc'),
              created_by: uuid('user-456'),
              created_at: iso8601DateTime('2025-01-02T10:30:00Z'),
              updated_at: iso8601DateTime('2025-01-02T12:15:00Z'),
              assignee: uuid('user-123'),
              notes: like('Alert acknowledged by security analyst'),
              tags: eachLike('network'),
              metadata: like({
                protocol: 'TCP',
                port: 443,
              }),
            },
          },
        },
      });
    });

    it('updates alert status and assignment', async () => {
      const alertsAPI = new AlertsAPI('http://localhost:1235');
      
      const updateData = {
        status: 'ACKNOWLEDGED' as const,
        assignee: 'user-123',
        notes: 'Alert acknowledged by security analyst',
      };

      const response = await alertsAPI.updateAlert(
        'alert-123',
        updateData,
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
      );

      expect(response.success).toBe(true);
      expect(response.data.status).toBe('ACKNOWLEDGED');
      expect(response.data.assignee).toBe('user-123');
      expect(response.data.notes).toBe('Alert acknowledged by security analyst');
    });
  });

  describe('POST /api/alerts/bulk', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'multiple alerts exist and user can perform bulk operations',
        uponReceiving: 'a request for bulk alert operations',
        withRequest: {
          method: 'POST',
          path: '/api/alerts/bulk',
          headers: {
            'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
            'Content-Type': 'application/json',
          },
          body: {
            alert_ids: eachLike('alert-123'),
            action: like('acknowledge'),
            assignee: uuid('user-123'),
            notes: like('Bulk acknowledgment by security team'),
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: {
              updated_count: like(3),
              failed_count: like(0),
              errors: [],
              updated_alerts: eachLike({
                id: uuid('alert-123'),
                status: like('ACKNOWLEDGED'),
                assignee: uuid('user-123'),
                updated_at: iso8601DateTime('2025-01-02T12:30:00Z'),
              }),
            },
          },
        },
      });
    });

    it('performs bulk operations on multiple alerts', async () => {
      const alertsAPI = new AlertsAPI('http://localhost:1235');
      
      const bulkData = {
        alert_ids: ['alert-123', 'alert-456', 'alert-789'],
        action: 'acknowledge' as const,
        assignee: 'user-123',
        notes: 'Bulk acknowledgment by security team',
      };

      const response = await alertsAPI.bulkUpdateAlerts(
        bulkData,
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
      );

      expect(response.success).toBe(true);
      expect(response.data.updated_count).toBe(3);
      expect(response.data.failed_count).toBe(0);
      expect(response.data.updated_alerts).toHaveLength(1);
    });
  });

  describe('GET /api/alerts/:id', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'alert exists with full details',
        uponReceiving: 'a request for specific alert details',
        withRequest: {
          method: 'GET',
          path: '/api/alerts/alert-123',
          headers: {
            'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
            'Accept': 'application/json',
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: {
              id: like('alert-123'),
              title: like('Advanced Persistent Threat Detected'),
              severity: like('CRITICAL'),
              status: like('ACTIVE'),
              type: like('MALWARE'),
              description: like('Sophisticated malware campaign detected'),
              source_ip: like('192.168.1.100'),
              destination_ip: like('10.0.0.1'),
              tenant_id: uuid('tenant-abc'),
              created_by: uuid('user-456'),
              created_at: iso8601DateTime('2025-01-02T10:30:00Z'),
              updated_at: iso8601DateTime('2025-01-02T10:30:00Z'),
              assignee: uuid('user-123'),
              tags: eachLike('apt'),
              metadata: like({
                malware_family: 'Lazarus',
                attack_vector: 'spear_phishing',
                confidence: 0.95,
                iocs: eachLike({
                  type: 'hash',
                  value: 'sha256:abc123...',
                }),
              }),
              timeline: eachLike({
                timestamp: iso8601DateTime('2025-01-02T10:30:00Z'),
                event: like('Initial detection'),
                details: like('Suspicious process execution detected'),
              }),
              related_alerts: eachLike({
                id: uuid('alert-456'),
                title: like('Related Network Activity'),
                severity: like('MEDIUM'),
              }),
            },
          },
        },
      });
    });

    it('returns detailed alert information with relationships', async () => {
      const alertsAPI = new AlertsAPI('http://localhost:1235');
      
      const response = await alertsAPI.getAlertById(
        'alert-123',
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
      );

      expect(response.success).toBe(true);
      expect(response.data.id).toBe('alert-123');
      expect(response.data.severity).toBe('CRITICAL');
      expect(response.data.metadata).toHaveProperty('malware_family');
      expect(response.data.timeline).toHaveLength(1);
      expect(response.data.related_alerts).toHaveLength(1);
    });
  });

  describe('Error Handling Contracts', () => {
    describe('404 Not Found', () => {
      beforeEach(() => {
        return mockProvider.addInteraction({
          state: 'alert does not exist',
          uponReceiving: 'a request for non-existent alert',
          withRequest: {
            method: 'GET',
            path: '/api/alerts/non-existent-alert',
            headers: {
              'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
              'Accept': 'application/json',
            },
          },
          willRespondWith: {
            status: 404,
            headers: {
              'Content-Type': 'application/json',
            },
            body: {
              success: false,
              error: like('ALERT_NOT_FOUND'),
              message: like('Alert not found or access denied'),
              timestamp: iso8601DateTime('2025-01-02T12:00:00Z'),
            },
          },
        });
      });

      it('handles non-existent alert gracefully', async () => {
        const alertsAPI = new AlertsAPI('http://localhost:1235');
        
        try {
          await alertsAPI.getAlertById(
            'non-existent-alert',
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
          );
          fail('Should have thrown an error');
        } catch (error: any) {
          expect(error.status).toBe(404);
          expect(error.data.error).toBe('ALERT_NOT_FOUND');
        }
      });
    });

    describe('400 Bad Request', () => {
      beforeEach(() => {
        return mockProvider.addInteraction({
          state: 'user provides invalid data',
          uponReceiving: 'a request with invalid alert data',
          withRequest: {
            method: 'POST',
            path: '/api/alerts',
            headers: {
              'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
              'Content-Type': 'application/json',
            },
            body: {
              title: '', // Invalid: empty title
              severity: 'INVALID_SEVERITY', // Invalid severity
              type: 'NETWORK_ANOMALY',
            },
          },
          willRespondWith: {
            status: 400,
            headers: {
              'Content-Type': 'application/json',
            },
            body: {
              success: false,
              error: like('VALIDATION_ERROR'),
              message: like('Invalid request data'),
              errors: eachLike({
                field: like('title'),
                message: like('Title cannot be empty'),
              }),
              timestamp: iso8601DateTime('2025-01-02T12:00:00Z'),
            },
          },
        });
      });

      it('handles validation errors properly', async () => {
        const alertsAPI = new AlertsAPI('http://localhost:1235');
        
        try {
          await alertsAPI.createAlert({
            title: '',
            severity: 'INVALID_SEVERITY' as any,
            type: 'NETWORK_ANOMALY',
          }, 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
          
          fail('Should have thrown an error');
        } catch (error: any) {
          expect(error.status).toBe(400);
          expect(error.data.error).toBe('VALIDATION_ERROR');
          expect(error.data.errors).toHaveLength(1);
        }
      });
    });

    describe('401 Unauthorized', () => {
      beforeEach(() => {
        return mockProvider.addInteraction({
          state: 'user is not authenticated',
          uponReceiving: 'a request without valid authentication',
          withRequest: {
            method: 'GET',
            path: '/api/alerts',
            headers: {
              'Accept': 'application/json',
            },
          },
          willRespondWith: {
            status: 401,
            headers: {
              'Content-Type': 'application/json',
            },
            body: {
              success: false,
              error: like('UNAUTHORIZED'),
              message: like('Authentication required'),
              timestamp: iso8601DateTime('2025-01-02T12:00:00Z'),
            },
          },
        });
      });

      it('handles missing authentication', async () => {
        const alertsAPI = new AlertsAPI('http://localhost:1235');
        
        try {
          await alertsAPI.getAlerts({}, null);
          fail('Should have thrown an error');
        } catch (error: any) {
          expect(error.status).toBe(401);
          expect(error.data.error).toBe('UNAUTHORIZED');
        }
      });
    });

    describe('403 Forbidden', () => {
      beforeEach(() => {
        return mockProvider.addInteraction({
          state: 'user lacks required permissions',
          uponReceiving: 'a request from user without permissions',
          withRequest: {
            method: 'DELETE',
            path: '/api/alerts/alert-123',
            headers: {
              'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
            },
          },
          willRespondWith: {
            status: 403,
            headers: {
              'Content-Type': 'application/json',
            },
            body: {
              success: false,
              error: like('INSUFFICIENT_PERMISSIONS'),
              message: like('You do not have permission to delete alerts'),
              required_permissions: eachLike('delete:alerts'),
              timestamp: iso8601DateTime('2025-01-02T12:00:00Z'),
            },
          },
        });
      });

      it('handles insufficient permissions', async () => {
        const alertsAPI = new AlertsAPI('http://localhost:1235');
        
        try {
          await alertsAPI.deleteAlert(
            'alert-123',
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
          );
          fail('Should have thrown an error');
        } catch (error: any) {
          expect(error.status).toBe(403);
          expect(error.data.error).toBe('INSUFFICIENT_PERMISSIONS');
          expect(error.data.required_permissions).toHaveLength(1);
        }
      });
    });

    describe('429 Rate Limited', () => {
      beforeEach(() => {
        return mockProvider.addInteraction({
          state: 'user has exceeded rate limits',
          uponReceiving: 'too many requests from user',
          withRequest: {
            method: 'POST',
            path: '/api/alerts',
            headers: {
              'Authorization': like('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'),
              'Content-Type': 'application/json',
            },
            body: like({
              title: 'Rate Limited Alert',
              severity: 'HIGH',
              type: 'NETWORK_ANOMALY',
            }),
          },
          willRespondWith: {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': '60',
            },
            body: {
              success: false,
              error: like('RATE_LIMITED'),
              message: like('Too many requests - please try again later'),
              retry_after: like(60),
              timestamp: iso8601DateTime('2025-01-02T12:00:00Z'),
            },
          },
        });
      });

      it('handles rate limiting with retry information', async () => {
        const alertsAPI = new AlertsAPI('http://localhost:1235');
        
        try {
          await alertsAPI.createAlert({
            title: 'Rate Limited Alert',
            severity: 'HIGH',
            type: 'NETWORK_ANOMALY',
          }, 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
          
          fail('Should have thrown an error');
        } catch (error: any) {
          expect(error.status).toBe(429);
          expect(error.data.error).toBe('RATE_LIMITED');
          expect(error.data.retry_after).toBe(60);
        }
      });
    });
  });
});