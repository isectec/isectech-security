/**
 * Authentication Store Unit Tests
 * iSECTECH Protect - Critical Security Component Testing
 * Coverage Target: 100% (Critical Security Component)
 */

import { renderHook, act } from '@testing-library/react';
import { useAuthStore } from '@/lib/store/auth';
import { AuthUser, LoginCredentials, MFAVerification } from '@/types/auth';

// Mock the API client
jest.mock('@/lib/api/client', () => ({
  apiClient: {
    post: jest.fn(),
    get: jest.fn(),
    delete: jest.fn(),
  },
}));

// Mock crypto utilities
jest.mock('@/lib/utils/crypto', () => ({
  encryptToken: jest.fn((token) => `encrypted_${token}`),
  decryptToken: jest.fn((encrypted) => encrypted.replace('encrypted_', '')),
  hashPassword: jest.fn((password) => `hashed_${password}`),
  verifyPassword: jest.fn((password, hash) => hash === `hashed_${password}`),
}));

describe('AuthStore - Critical Security Component', () => {
  let store: ReturnType<typeof useAuthStore>;

  beforeEach(() => {
    // Reset store state before each test
    const { result } = renderHook(() => useAuthStore());
    store = result.current;
    
    // Clear any existing state
    act(() => {
      store.clearAuth();
    });

    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('Authentication State Management', () => {
    it('should initialize with secure default state', () => {
      expect(store.user).toBeNull();
      expect(store.isAuthenticated).toBe(false);
      expect(store.isLoading).toBe(false);
      expect(store.error).toBeNull();
      expect(store.session).toBeNull();
      expect(store.mfaRequired).toBe(false);
    });

    it('should handle login successfully with valid credentials', async () => {
      const mockUser: AuthUser = {
        id: 'user-123',
        email: 'analyst@isectech.com',
        name: 'Security Analyst',
        role: 'SECURITY_ANALYST',
        tenantId: 'tenant-abc',
        securityClearance: 'SECRET',
        permissions: ['read:alerts', 'read:threats'],
        mfaEnabled: true,
        lastLogin: new Date().toISOString(),
      };

      const mockTokens = {
        accessToken: 'jwt-access-token',
        refreshToken: 'jwt-refresh-token',
        expiresIn: 3600,
      };

      const mockSession = {
        id: 'session-xyz',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      // Mock successful API response
      const mockApiResponse = {
        success: true,
        user: mockUser,
        tokens: mockTokens,
        session: mockSession,
      };

      require('@/lib/api/client').apiClient.post.mockResolvedValueOnce({
        data: mockApiResponse,
      });

      const credentials: LoginCredentials = {
        email: 'analyst@isectech.com',
        password: 'SecurePassword123!',
      };

      await act(async () => {
        await store.login(credentials);
      });

      expect(store.isAuthenticated).toBe(true);
      expect(store.user).toEqual(mockUser);
      expect(store.session?.id).toBe('session-xyz');
      expect(store.error).toBeNull();
      expect(store.isLoading).toBe(false);
    });

    it('should handle login failure with invalid credentials', async () => {
      const mockError = {
        status: 401,
        data: {
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      };

      require('@/lib/api/client').apiClient.post.mockRejectedValueOnce(mockError);

      const credentials: LoginCredentials = {
        email: 'invalid@example.com',
        password: 'wrongpassword',
      };

      await act(async () => {
        await store.login(credentials);
      });

      expect(store.isAuthenticated).toBe(false);
      expect(store.user).toBeNull();
      expect(store.error).toBe('Invalid email or password');
      expect(store.isLoading).toBe(false);
    });

    it('should require MFA for users with MFA enabled', async () => {
      const mockResponse = {
        success: false,
        mfaRequired: true,
        tempToken: 'temp-mfa-token',
        user: {
          id: 'user-123',
          email: 'analyst@isectech.com',
          mfaEnabled: true,
        },
      };

      require('@/lib/api/client').apiClient.post.mockResolvedValueOnce({
        data: mockResponse,
      });

      const credentials: LoginCredentials = {
        email: 'analyst@isectech.com',
        password: 'SecurePassword123!',
      };

      await act(async () => {
        await store.login(credentials);
      });

      expect(store.mfaRequired).toBe(true);
      expect(store.isAuthenticated).toBe(false);
      expect(store.tempToken).toBe('temp-mfa-token');
    });
  });

  describe('Multi-Factor Authentication', () => {
    beforeEach(() => {
      // Set up MFA required state
      act(() => {
        store.setMfaRequired(true, 'temp-mfa-token');
      });
    });

    it('should verify MFA successfully with valid TOTP code', async () => {
      const mockUser: AuthUser = {
        id: 'user-123',
        email: 'analyst@isectech.com',
        name: 'Security Analyst',
        role: 'SECURITY_ANALYST',
        tenantId: 'tenant-abc',
        securityClearance: 'SECRET',
        permissions: ['read:alerts', 'read:threats'],
        mfaEnabled: true,
        lastLogin: new Date().toISOString(),
      };

      const mockResponse = {
        success: true,
        user: mockUser,
        tokens: {
          accessToken: 'jwt-access-token',
          refreshToken: 'jwt-refresh-token',
          expiresIn: 3600,
        },
        session: {
          id: 'session-xyz',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      };

      require('@/lib/api/client').apiClient.post.mockResolvedValueOnce({
        data: mockResponse,
      });

      const mfaData: MFAVerification = {
        code: '123456',
        method: 'TOTP',
      };

      await act(async () => {
        await store.verifyMFA(mfaData);
      });

      expect(store.isAuthenticated).toBe(true);
      expect(store.mfaRequired).toBe(false);
      expect(store.user).toEqual(mockUser);
      expect(store.tempToken).toBeNull();
    });

    it('should handle MFA verification failure', async () => {
      const mockError = {
        status: 400,
        data: {
          error: 'INVALID_MFA_CODE',
          message: 'Invalid MFA code provided',
        },
      };

      require('@/lib/api/client').apiClient.post.mockRejectedValueOnce(mockError);

      const mfaData: MFAVerification = {
        code: '000000',
        method: 'TOTP',
      };

      await act(async () => {
        await store.verifyMFA(mfaData);
      });

      expect(store.isAuthenticated).toBe(false);
      expect(store.mfaRequired).toBe(true);
      expect(store.error).toBe('Invalid MFA code provided');
    });

    it('should prevent MFA bypass attempts', async () => {
      // Attempt to authenticate without proper MFA verification
      const bypassAttempt = {
        tempToken: null,
        mfaSkip: true,
      };

      // Should not allow authentication without proper MFA flow
      expect(store.isAuthenticated).toBe(false);
      expect(store.mfaRequired).toBe(true);

      // Ensure tempToken is required for MFA verification
      const mfaData: MFAVerification = {
        code: '123456',
        method: 'TOTP',
      };

      // Clear tempToken to simulate bypass attempt
      act(() => {
        store.tempToken = null;
      });

      await act(async () => {
        await store.verifyMFA(mfaData);
      });

      expect(store.error).toContain('Invalid MFA session');
    });
  });

  describe('Session Management', () => {
    beforeEach(async () => {
      // Set up authenticated state
      const mockUser: AuthUser = {
        id: 'user-123',
        email: 'analyst@isectech.com',
        name: 'Security Analyst',
        role: 'SECURITY_ANALYST',
        tenantId: 'tenant-abc',
        securityClearance: 'SECRET',
        permissions: ['read:alerts', 'read:threats'],
        mfaEnabled: true,
        lastLogin: new Date().toISOString(),
      };

      act(() => {
        store.setAuthenticatedUser(mockUser, {
          accessToken: 'jwt-access-token',
          refreshToken: 'jwt-refresh-token',
          expiresIn: 3600,
        }, {
          id: 'session-xyz',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        });
      });
    });

    it('should refresh token automatically when near expiration', async () => {
      const mockRefreshResponse = {
        accessToken: 'new-jwt-access-token',
        refreshToken: 'new-jwt-refresh-token',
        expiresIn: 3600,
      };

      require('@/lib/api/client').apiClient.post.mockResolvedValueOnce({
        data: mockRefreshResponse,
      });

      await act(async () => {
        await store.refreshToken();
      });

      expect(store.tokens?.accessToken).toBe('new-jwt-access-token');
      expect(store.isAuthenticated).toBe(true);
    });

    it('should handle token refresh failure and logout user', async () => {
      const mockError = {
        status: 401,
        data: {
          error: 'INVALID_REFRESH_TOKEN',
          message: 'Refresh token is invalid or expired',
        },
      };

      require('@/lib/api/client').apiClient.post.mockRejectedValueOnce(mockError);

      await act(async () => {
        await store.refreshToken();
      });

      expect(store.isAuthenticated).toBe(false);
      expect(store.user).toBeNull();
      expect(store.tokens).toBeNull();
    });

    it('should validate session expiration', () => {
      // Test with expired session
      const expiredSession = {
        id: 'session-expired',
        expiresAt: new Date(Date.now() - 1000).toISOString(), // 1 second ago
      };

      act(() => {
        store.session = expiredSession;
      });

      const isValid = store.isSessionValid();
      expect(isValid).toBe(false);
    });

    it('should logout user and clear all authentication data', async () => {
      require('@/lib/api/client').apiClient.post.mockResolvedValueOnce({
        data: { success: true },
      });

      await act(async () => {
        await store.logout();
      });

      expect(store.isAuthenticated).toBe(false);
      expect(store.user).toBeNull();
      expect(store.tokens).toBeNull();
      expect(store.session).toBeNull();
      expect(store.mfaRequired).toBe(false);
      expect(store.tempToken).toBeNull();
    });
  });

  describe('Permission Management', () => {
    beforeEach(() => {
      const mockUser: AuthUser = {
        id: 'user-123',
        email: 'analyst@isectech.com',
        name: 'Security Analyst',
        role: 'SECURITY_ANALYST',
        tenantId: 'tenant-abc',
        securityClearance: 'SECRET',
        permissions: ['read:alerts', 'read:threats', 'write:incidents'],
        mfaEnabled: true,
        lastLogin: new Date().toISOString(),
      };

      act(() => {
        store.setAuthenticatedUser(mockUser, {
          accessToken: 'jwt-access-token',
          refreshToken: 'jwt-refresh-token',
          expiresIn: 3600,
        }, {
          id: 'session-xyz',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        });
      });
    });

    it('should validate user permissions correctly', () => {
      expect(store.hasPermission('read:alerts')).toBe(true);
      expect(store.hasPermission('read:threats')).toBe(true);
      expect(store.hasPermission('write:incidents')).toBe(true);
      expect(store.hasPermission('admin:users')).toBe(false);
    });

    it('should validate multiple permissions', () => {
      expect(store.hasAllPermissions(['read:alerts', 'read:threats'])).toBe(true);
      expect(store.hasAllPermissions(['read:alerts', 'admin:users'])).toBe(false);
    });

    it('should validate any of multiple permissions', () => {
      expect(store.hasAnyPermission(['read:alerts', 'admin:users'])).toBe(true);
      expect(store.hasAnyPermission(['admin:users', 'admin:config'])).toBe(false);
    });

    it('should validate security clearance levels', () => {
      expect(store.hasSecurityClearance('CONFIDENTIAL')).toBe(true);
      expect(store.hasSecurityClearance('SECRET')).toBe(true);
      expect(store.hasSecurityClearance('TOP_SECRET')).toBe(false);
    });

    it('should validate role-based access', () => {
      expect(store.hasRole('SECURITY_ANALYST')).toBe(true);
      expect(store.hasRole('TENANT_ADMIN')).toBe(false);
      expect(store.hasRole('SUPER_ADMIN')).toBe(false);
    });
  });

  describe('Security Validations', () => {
    it('should validate password strength requirements', () => {
      const weakPasswords = [
        'password',
        '123456',
        'abc123',
        'password123',
        'Password',
        '12345678',
      ];

      const strongPasswords = [
        'SecurePassword123!',
        'MyStr0ng&P@ssw0rd',
        'C0mpl3x!P@ssw0rd#2024',
      ];

      weakPasswords.forEach(password => {
        expect(store.validatePasswordStrength(password)).toBe(false);
      });

      strongPasswords.forEach(password => {
        expect(store.validatePasswordStrength(password)).toBe(true);
      });
    });

    it('should prevent concurrent session hijacking', () => {
      const session1 = {
        id: 'session-1',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      const session2 = {
        id: 'session-2',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      // Set first session
      act(() => {
        store.session = session1;
      });

      expect(store.session?.id).toBe('session-1');

      // Attempt to set second session should invalidate first
      act(() => {
        store.session = session2;
      });

      expect(store.session?.id).toBe('session-2');
      // Should log security event for session change
      expect(console.warn).toHaveBeenCalledWith(
        'Session changed - potential security event',
        expect.any(Object)
      );
    });

    it('should handle rate limiting for failed login attempts', async () => {
      const credentials: LoginCredentials = {
        email: 'analyst@isectech.com',
        password: 'wrongpassword',
      };

      // Mock multiple failed attempts
      const rateLimitError = {
        status: 429,
        data: {
          error: 'RATE_LIMITED',
          message: 'Too many failed login attempts',
          retryAfter: 300,
        },
      };

      require('@/lib/api/client').apiClient.post.mockRejectedValueOnce(rateLimitError);

      await act(async () => {
        await store.login(credentials);
      });

      expect(store.error).toBe('Too many failed login attempts');
      expect(store.isRateLimited).toBe(true);
      expect(store.rateLimitRetryAfter).toBe(300);
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      const networkError = new Error('Network Error');
      networkError.name = 'NetworkError';

      require('@/lib/api/client').apiClient.post.mockRejectedValueOnce(networkError);

      const credentials: LoginCredentials = {
        email: 'analyst@isectech.com',
        password: 'SecurePassword123!',
      };

      await act(async () => {
        await store.login(credentials);
      });

      expect(store.error).toBe('Network error - please check your connection');
      expect(store.isAuthenticated).toBe(false);
    });

    it('should handle server errors gracefully', async () => {
      const serverError = {
        status: 500,
        data: {
          error: 'INTERNAL_SERVER_ERROR',
          message: 'Internal server error',
        },
      };

      require('@/lib/api/client').apiClient.post.mockRejectedValueOnce(serverError);

      const credentials: LoginCredentials = {
        email: 'analyst@isectech.com',
        password: 'SecurePassword123!',
      };

      await act(async () => {
        await store.login(credentials);
      });

      expect(store.error).toBe('Server error - please try again later');
      expect(store.isAuthenticated).toBe(false);
    });

    it('should clear errors on successful operations', async () => {
      // Set initial error state
      act(() => {
        store.error = 'Previous error';
      });

      const mockResponse = {
        success: true,
        user: {
          id: 'user-123',
          email: 'analyst@isectech.com',
          role: 'SECURITY_ANALYST',
        },
      };

      require('@/lib/api/client').apiClient.post.mockResolvedValueOnce({
        data: mockResponse,
      });

      const credentials: LoginCredentials = {
        email: 'analyst@isectech.com',
        password: 'SecurePassword123!',
      };

      await act(async () => {
        await store.login(credentials);
      });

      expect(store.error).toBeNull();
    });
  });

  describe('Data Persistence', () => {
    it('should persist authentication state to secure storage', () => {
      const mockUser: AuthUser = {
        id: 'user-123',
        email: 'analyst@isectech.com',
        name: 'Security Analyst',
        role: 'SECURITY_ANALYST',
        tenantId: 'tenant-abc',
        securityClearance: 'SECRET',
        permissions: ['read:alerts'],
        mfaEnabled: true,
        lastLogin: new Date().toISOString(),
      };

      act(() => {
        store.setAuthenticatedUser(mockUser, {
          accessToken: 'jwt-access-token',
          refreshToken: 'jwt-refresh-token',
          expiresIn: 3600,
        }, {
          id: 'session-xyz',
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        });
      });

      // Verify encrypted storage calls
      expect(localStorage.setItem).toHaveBeenCalledWith(
        'auth_user',
        expect.stringContaining('encrypted_')
      );
    });

    it('should restore authentication state from secure storage', () => {
      const mockEncryptedData = 'encrypted_{"user":{"id":"user-123"}}';
      localStorage.getItem = jest.fn().mockReturnValue(mockEncryptedData);

      act(() => {
        store.restoreFromStorage();
      });

      expect(store.user?.id).toBe('user-123');
    });

    it('should handle corrupted storage data gracefully', () => {
      localStorage.getItem = jest.fn().mockReturnValue('corrupted_data');

      act(() => {
        store.restoreFromStorage();
      });

      expect(store.user).toBeNull();
      expect(store.isAuthenticated).toBe(false);
    });
  });
});