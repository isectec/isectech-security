/**
 * Authentication API Services for iSECTECH Protect
 * Production-grade authentication service layer
 */

import type {
  LoginCredentials,
  MFACredentials,
  LoginResponse,
  TokenPair,
  User,
  Tenant,
  PasswordChangeRequest,
  PasswordResetRequest,
  PasswordResetConfirm,
  MFASetup,
  TrustedDevice,
  AuthenticationEvent,
  ApiResponse,
} from '@/types';
import { apiClient } from '../client';

export class AuthService {
  // Authentication
  async login(credentials: LoginCredentials): Promise<LoginResponse> {
    const response = await apiClient.post<LoginResponse>('/auth/login', credentials);
    return response.data!;
  }

  async loginWithMFA(credentials: MFACredentials): Promise<LoginResponse> {
    const response = await apiClient.post<LoginResponse>('/auth/mfa-verify', credentials);
    return response.data!;
  }

  async logout(): Promise<void> {
    await apiClient.post('/auth/logout');
  }

  async refreshTokens(refreshToken: string): Promise<TokenPair> {
    const response = await apiClient.post<TokenPair>('/auth/refresh', { refreshToken });
    return response.data!;
  }

  // User management
  async getCurrentUser(): Promise<User> {
    const response = await apiClient.get<User>('/auth/me');
    return response.data!;
  }

  async updateProfile(updates: Partial<User>): Promise<User> {
    const response = await apiClient.patch<User>('/auth/profile', updates);
    return response.data!;
  }

  // Password management
  async changePassword(request: PasswordChangeRequest): Promise<void> {
    await apiClient.post('/auth/change-password', request);
  }

  async requestPasswordReset(request: PasswordResetRequest): Promise<void> {
    await apiClient.post('/auth/password-reset', request);
  }

  async confirmPasswordReset(request: PasswordResetConfirm): Promise<void> {
    await apiClient.post('/auth/password-reset/confirm', request);
  }

  // Multi-Factor Authentication
  async setupMFA(type: 'TOTP' | 'SMS' | 'EMAIL'): Promise<MFASetup> {
    const response = await apiClient.post<MFASetup>('/auth/mfa/setup', { type });
    return response.data!;
  }

  async enableMFA(secret: string, code: string): Promise<string[]> {
    const response = await apiClient.post<string[]>('/auth/mfa/enable', { secret, code });
    return response.data!;
  }

  async disableMFA(code: string): Promise<void> {
    await apiClient.post('/auth/mfa/disable', { code });
  }

  async generateBackupCodes(): Promise<string[]> {
    const response = await apiClient.post<string[]>('/auth/mfa/backup-codes');
    return response.data!;
  }

  // Device management
  async getTrustedDevices(): Promise<TrustedDevice[]> {
    const response = await apiClient.get<TrustedDevice[]>('/auth/devices');
    return response.data!;
  }

  async trustDevice(deviceFingerprint: string, name: string): Promise<TrustedDevice> {
    const response = await apiClient.post<TrustedDevice>('/auth/devices/trust', {
      deviceFingerprint,
      name,
    });
    return response.data!;
  }

  async revokeTrustedDevice(deviceId: string): Promise<void> {
    await apiClient.delete(`/auth/devices/${deviceId}`);
  }

  // Session management
  async getActiveSessions(): Promise<any[]> {
    const response = await apiClient.get<any[]>('/auth/sessions');
    return response.data!;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await apiClient.delete(`/auth/sessions/${sessionId}`);
  }

  async revokeAllSessions(): Promise<void> {
    await apiClient.delete('/auth/sessions');
  }

  // Tenant management
  async switchTenant(tenantId: string): Promise<{ tenant: Tenant; permissions: string[] }> {
    const response = await apiClient.post<{ tenant: Tenant; permissions: string[] }>('/auth/switch-tenant', {
      tenantId,
    });
    return response.data!;
  }

  async getUserTenants(): Promise<Tenant[]> {
    const response = await apiClient.get<Tenant[]>('/auth/tenants');
    return response.data!;
  }

  // Audit and history
  async getAuthenticationHistory(params?: {
    limit?: number;
    offset?: number;
    fromDate?: Date;
    toDate?: Date;
  }): Promise<{ events: AuthenticationEvent[]; total: number }> {
    const response = await apiClient.get<{ events: AuthenticationEvent[]; total: number }>(
      '/auth/history',
      { params }
    );
    return response.data!;
  }

  // Security utilities
  async validatePassword(password: string): Promise<{
    isValid: boolean;
    errors: string[];
    strength: 'WEAK' | 'FAIR' | 'GOOD' | 'STRONG';
    score: number;
  }> {
    const response = await apiClient.post<{
      isValid: boolean;
      errors: string[];
      strength: 'WEAK' | 'FAIR' | 'GOOD' | 'STRONG';
      score: number;
    }>('/auth/validate-password', { password });
    return response.data!;
  }

  async checkSecurityQuestions(): Promise<boolean> {
    const response = await apiClient.get<{ hasQuestions: boolean }>('/auth/security-questions/check');
    return response.data!.hasQuestions;
  }

  // Health check
  async healthCheck(): Promise<boolean> {
    try {
      await apiClient.get('/auth/health');
      return true;
    } catch {
      return false;
    }
  }
}

export const authService = new AuthService();
export default authService;