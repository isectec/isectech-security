/**
 * Pact Contract Tests for Authentication API
 * iSECTECH Protect - API Contract Validation
 */

import { Pact } from '@pact-foundation/pact';
import { AuthAPI } from '@/lib/api/services/auth';
import path from 'path';

const mockProvider = new Pact({
  consumer: 'isectech-frontend',
  provider: 'isectech-auth-api',
  port: 1234,
  log: path.resolve(process.cwd(), 'logs', 'pact.log'),
  dir: path.resolve(process.cwd(), 'pacts'),
  logLevel: 'INFO',
  spec: 3,
});

describe('Authentication API Contract', () => {
  beforeAll(() => mockProvider.setup());
  afterAll(() => mockProvider.finalize());
  afterEach(() => mockProvider.verify());

  describe('POST /auth/login', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'user exists with valid credentials',
        uponReceiving: 'a login request with valid credentials',
        withRequest: {
          method: 'POST',
          path: '/auth/login',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: {
            email: 'analyst@isectech.com',
            password: 'SecurePassword123!',
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            user: {
              id: 'user-123',
              email: 'analyst@isectech.com',
              role: 'SECURITY_ANALYST',
              tenantId: 'tenant-abc',
              securityClearance: 'SECRET',
              permissions: ['read:alerts', 'read:threats', 'write:incidents'],
            },
            tokens: {
              accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
              refreshToken: 'refresh_token_value',
              expiresIn: 3600,
            },
            session: {
              id: 'session-xyz',
              expiresAt: '2025-01-03T12:00:00Z',
            },
          },
        },
      });
    });

    it('returns valid authentication response', async () => {
      const authAPI = new AuthAPI('http://localhost:1234');
      
      const response = await authAPI.login({
        email: 'analyst@isectech.com',
        password: 'SecurePassword123!',
      });

      expect(response.success).toBe(true);
      expect(response.user.role).toBe('SECURITY_ANALYST');
      expect(response.tokens.accessToken).toBeDefined();
      expect(response.session.id).toBeDefined();
    });
  });

  describe('POST /auth/mfa/verify', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'user has valid MFA setup',
        uponReceiving: 'an MFA verification request',
        withRequest: {
          method: 'POST',
          path: '/auth/mfa/verify',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          },
          body: {
            code: '123456',
            method: 'TOTP',
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            mfaVerified: true,
            sessionUpgraded: true,
            privilegedOperationsEnabled: true,
          },
        },
      });
    });

    it('verifies MFA and upgrades session', async () => {
      const authAPI = new AuthAPI('http://localhost:1234');
      
      const response = await authAPI.verifyMFA({
        code: '123456',
        method: 'TOTP',
      }, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

      expect(response.success).toBe(true);
      expect(response.mfaVerified).toBe(true);
      expect(response.privilegedOperationsEnabled).toBe(true);
    });
  });

  describe('GET /auth/profile', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'user is authenticated',
        uponReceiving: 'a profile request',
        withRequest: {
          method: 'GET',
          path: '/auth/profile',
          headers: {
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            user: {
              id: 'user-123',
              email: 'analyst@isectech.com',
              name: 'Security Analyst',
              role: 'SECURITY_ANALYST',
              tenantId: 'tenant-abc',
              securityClearance: 'SECRET',
              permissions: ['read:alerts', 'read:threats', 'write:incidents'],
              mfaEnabled: true,
              lastLogin: '2025-01-02T10:30:00Z',
            },
            tenant: {
              id: 'tenant-abc',
              name: 'ACME Corporation',
              plan: 'ENTERPRISE',
            },
          },
        },
      });
    });

    it('returns user profile information', async () => {
      const authAPI = new AuthAPI('http://localhost:1234');
      
      const response = await authAPI.getProfile('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

      expect(response.user.id).toBe('user-123');
      expect(response.user.securityClearance).toBe('SECRET');
      expect(response.tenant.plan).toBe('ENTERPRISE');
    });
  });

  describe('POST /auth/logout', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'user has active session',
        uponReceiving: 'a logout request',
        withRequest: {
          method: 'POST',
          path: '/auth/logout',
          headers: {
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          },
          body: {
            sessionId: 'session-xyz',
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            message: 'Successfully logged out',
            sessionInvalidated: true,
          },
        },
      });
    });

    it('successfully logs out user', async () => {
      const authAPI = new AuthAPI('http://localhost:1234');
      
      const response = await authAPI.logout({
        sessionId: 'session-xyz',
      }, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

      expect(response.success).toBe(true);
      expect(response.sessionInvalidated).toBe(true);
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      return mockProvider.addInteraction({
        state: 'invalid credentials provided',
        uponReceiving: 'a login request with invalid credentials',
        withRequest: {
          method: 'POST',
          path: '/auth/login',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            email: 'invalid@example.com',
            password: 'wrongpassword',
          },
        },
        willRespondWith: {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: false,
            error: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password',
            timestamp: '2025-01-02T12:00:00Z',
          },
        },
      });
    });

    it('handles authentication errors correctly', async () => {
      const authAPI = new AuthAPI('http://localhost:1234');
      
      try {
        await authAPI.login({
          email: 'invalid@example.com',
          password: 'wrongpassword',
        });
        fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.status).toBe(401);
        expect(error.data.error).toBe('INVALID_CREDENTIALS');
      }
    });
  });
});