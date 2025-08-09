/**
 * Tenant Management API Services for iSECTECH Protect MSSP Edition
 * Enterprise multi-tenant management with <500ms context switching
 */

import type { PaginatedData, SearchParams, Tenant, TenantLimits, TenantSettings, User } from '@/types';
import { apiClient } from '../client';

// Tenant-specific interfaces
export interface TenantStats {
  totalUsers: number;
  activeUsers: number;
  totalAssets: number;
  activeAlerts: number;
  complianceScore: number;
  riskScore: number;
  lastActivity: Date;
  dataUsage: {
    storage: number; // GB
    bandwidth: number; // GB/month
    apiCalls: number; // per month
  };
  features: {
    enabled: string[];
    available: string[];
    limits: Record<string, number>;
  };
}

export interface TenantHealth {
  overall: 'healthy' | 'warning' | 'critical';
  status: 'active' | 'suspended' | 'maintenance' | 'inactive';
  uptime: number; // percentage
  issues: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    category: 'performance' | 'security' | 'compliance' | 'technical';
    message: string;
    timestamp: Date;
    resolved: boolean;
  }>;
  performance: {
    responseTime: number; // ms
    errorRate: number; // percentage
    throughput: number; // requests/second
  };
  security: {
    lastSecurityScan: Date;
    vulnerabilities: number;
    complianceStatus: string;
    securityScore: number; // 0-100
  };
}

export interface TenantAnalytics {
  period: 'hour' | 'day' | 'week' | 'month';
  data: Array<{
    timestamp: Date;
    metrics: {
      activeUsers: number;
      alertVolume: number;
      responseTime: number;
      errorRate: number;
      resourceUsage: number;
    };
  }>;
  trends: {
    userGrowth: number; // percentage
    alertTrend: number; // percentage
    performanceTrend: number; // percentage
    securityTrend: number; // percentage
  };
}

export interface TenantOnboarding {
  id: string;
  tenantName: string;
  adminEmail: string;
  plan: Tenant['plan'];
  features: string[];
  customization: {
    logo?: File;
    primaryColor?: string;
    secondaryColor?: string;
    customDomain?: string;
  };
  configuration: {
    timezone: string;
    language: string;
    complianceFrameworks: string[];
    integrations: string[];
  };
  status: 'pending' | 'provisioning' | 'configuring' | 'completed' | 'failed';
  progress: number; // 0-100
  estimatedCompletion: Date;
  steps: Array<{
    name: string;
    status: 'pending' | 'in_progress' | 'completed' | 'failed';
    description: string;
    startedAt?: Date;
    completedAt?: Date;
    error?: string;
  }>;
}

export interface TenantTemplate {
  id: string;
  name: string;
  description: string;
  category: 'financial' | 'healthcare' | 'government' | 'retail' | 'manufacturing' | 'custom';
  features: string[];
  limits: TenantLimits;
  settings: TenantSettings;
  complianceFrameworks: string[];
  preConfiguredIntegrations: string[];
  estimatedSetupTime: number; // minutes
}

export interface TenantBilling {
  plan: Tenant['plan'];
  billing: {
    cycle: 'monthly' | 'annual';
    amount: number;
    currency: string;
    nextBillingDate: Date;
    paymentMethod: string;
    status: 'active' | 'past_due' | 'canceled' | 'trial';
  };
  usage: {
    users: { current: number; limit: number; overage: number };
    assets: { current: number; limit: number; overage: number };
    alerts: { current: number; limit: number; overage: number };
    storage: { current: number; limit: number; overage: number }; // GB
    apiCalls: { current: number; limit: number; overage: number };
  };
  costs: {
    base: number;
    overageCharges: number;
    addOns: number;
    total: number;
  };
  history: Array<{
    date: Date;
    amount: number;
    description: string;
    status: 'paid' | 'pending' | 'failed';
  }>;
}

export interface TenantSwitchContext {
  previousTenantId: string;
  newTenantId: string;
  switchStartTime: Date;
  dataPreloaded: boolean;
  cacheWarmed: boolean;
  permissionsVerified: boolean;
  contextIsolated: boolean;
}

export class TenantService {
  // Core tenant management
  async getTenants(params?: {
    search?: SearchParams;
    filters?: {
      status?: Tenant['status'][];
      plan?: Tenant['plan'][];
      features?: string[];
    };
    includeStats?: boolean;
    includeHealth?: boolean;
  }): Promise<PaginatedData<Tenant & { stats?: TenantStats; health?: TenantHealth }>> {
    const response = await apiClient.get<PaginatedData<Tenant & { stats?: TenantStats; health?: TenantHealth }>>(
      '/tenants',
      { params }
    );
    return response.data!;
  }

  async getTenant(
    id: string,
    options?: {
      includeStats?: boolean;
      includeHealth?: boolean;
      includeAnalytics?: boolean;
      includeBilling?: boolean;
    }
  ): Promise<
    Tenant & {
      stats?: TenantStats;
      health?: TenantHealth;
      analytics?: TenantAnalytics;
      billing?: TenantBilling;
    }
  > {
    const response = await apiClient.get<
      Tenant & {
        stats?: TenantStats;
        health?: TenantHealth;
        analytics?: TenantAnalytics;
        billing?: TenantBilling;
      }
    >(`/tenants/${id}`, { params: options });
    return response.data!;
  }

  async createTenant(tenant: Omit<Tenant, 'id' | 'createdAt' | 'updatedAt'>): Promise<Tenant> {
    const response = await apiClient.post<Tenant>('/tenants', tenant);
    return response.data!;
  }

  async updateTenant(id: string, updates: Partial<Tenant>): Promise<Tenant> {
    const response = await apiClient.patch<Tenant>(`/tenants/${id}`, updates);
    return response.data!;
  }

  async deleteTenant(
    id: string,
    options?: {
      transferDataTo?: string;
      preserveAuditLogs?: boolean;
    }
  ): Promise<void> {
    await apiClient.delete(`/tenants/${id}`, { data: options });
  }

  // Lightning-fast tenant switching (target: <500ms)
  async switchTenant(
    tenantId: string,
    options?: {
      preloadData?: string[]; // Data types to preload
      warmCache?: boolean;
      skipPermissionCheck?: boolean;
    }
  ): Promise<{
    tenant: Tenant;
    user: User;
    permissions: string[];
    context: TenantSwitchContext;
    switchTime: number; // milliseconds
  }> {
    const startTime = Date.now();

    const response = await apiClient.post<{
      tenant: Tenant;
      user: User;
      permissions: string[];
      context: TenantSwitchContext;
    }>('/auth/switch-tenant', { tenantId, ...options });

    const switchTime = Date.now() - startTime;

    return {
      ...response.data!,
      switchTime,
    };
  }

  async preloadTenantData(tenantId: string, dataTypes: string[] = ['alerts', 'assets', 'users']): Promise<void> {
    await apiClient.post('/tenants/preload', { tenantId, dataTypes });
  }

  async getCurrentTenantContext(): Promise<{
    tenant: Tenant;
    permissions: string[];
    dataAccess: string[];
    lastSwitched: Date;
    sessionExpiry: Date;
  }> {
    const response = await apiClient.get<{
      tenant: Tenant;
      permissions: string[];
      dataAccess: string[];
      lastSwitched: Date;
      sessionExpiry: Date;
    }>('/auth/tenant-context');
    return response.data!;
  }

  // Tenant statistics and health
  async getTenantStats(
    tenantId: string,
    timeRange?: {
      start: Date;
      end: Date;
    }
  ): Promise<TenantStats> {
    const response = await apiClient.get<TenantStats>(`/tenants/${tenantId}/stats`, { params: timeRange });
    return response.data!;
  }

  async getTenantHealth(tenantId: string): Promise<TenantHealth> {
    const response = await apiClient.get<TenantHealth>(`/tenants/${tenantId}/health`);
    return response.data!;
  }

  async getTenantAnalytics(
    tenantId: string,
    params: {
      period: TenantAnalytics['period'];
      metrics: string[];
      dateRange?: { start: Date; end: Date };
    }
  ): Promise<TenantAnalytics> {
    const response = await apiClient.get<TenantAnalytics>(`/tenants/${tenantId}/analytics`, { params });
    return response.data!;
  }

  // Tenant onboarding
  async getTenantTemplates(): Promise<TenantTemplate[]> {
    const response = await apiClient.get<TenantTemplate[]>('/tenants/templates');
    return response.data!;
  }

  async startTenantOnboarding(
    onboarding: Omit<TenantOnboarding, 'id' | 'status' | 'progress' | 'steps'>
  ): Promise<TenantOnboarding> {
    const response = await apiClient.post<TenantOnboarding>('/tenants/onboard', onboarding);
    return response.data!;
  }

  async getOnboardingStatus(onboardingId: string): Promise<TenantOnboarding> {
    const response = await apiClient.get<TenantOnboarding>(`/tenants/onboard/${onboardingId}`);
    return response.data!;
  }

  async cancelOnboarding(onboardingId: string): Promise<void> {
    await apiClient.delete(`/tenants/onboard/${onboardingId}`);
  }

  // Tenant billing and usage
  async getTenantBilling(tenantId: string): Promise<TenantBilling> {
    const response = await apiClient.get<TenantBilling>(`/tenants/${tenantId}/billing`);
    return response.data!;
  }

  async updateTenantPlan(
    tenantId: string,
    plan: Tenant['plan'],
    options?: {
      effectiveDate?: Date;
      prorateBilling?: boolean;
    }
  ): Promise<{ tenant: Tenant; billing: TenantBilling }> {
    const response = await apiClient.patch<{ tenant: Tenant; billing: TenantBilling }>(`/tenants/${tenantId}/plan`, {
      plan,
      ...options,
    });
    return response.data!;
  }

  async updateTenantLimits(tenantId: string, limits: Partial<TenantLimits>): Promise<Tenant> {
    const response = await apiClient.patch<Tenant>(`/tenants/${tenantId}/limits`, limits);
    return response.data!;
  }

  // Tenant configuration
  async updateTenantSettings(tenantId: string, settings: Partial<TenantSettings>): Promise<Tenant> {
    const response = await apiClient.patch<Tenant>(`/tenants/${tenantId}/settings`, settings);
    return response.data!;
  }

  async updateTenantBranding(
    tenantId: string,
    branding: {
      logo?: File;
      primaryColor?: string;
      secondaryColor?: string;
      customDomain?: string;
    }
  ): Promise<Tenant> {
    const formData = new FormData();
    if (branding.logo) formData.append('logo', branding.logo);
    if (branding.primaryColor) formData.append('primaryColor', branding.primaryColor);
    if (branding.secondaryColor) formData.append('secondaryColor', branding.secondaryColor);
    if (branding.customDomain) formData.append('customDomain', branding.customDomain);

    const response = await apiClient.patch<Tenant>(`/tenants/${tenantId}/branding`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data!;
  }

  // Tenant users and access
  async getTenantUsers(
    tenantId: string,
    params?: {
      search?: SearchParams;
      includeInactive?: boolean;
    }
  ): Promise<PaginatedData<User>> {
    const response = await apiClient.get<PaginatedData<User>>(`/tenants/${tenantId}/users`, { params });
    return response.data!;
  }

  async inviteTenantUser(
    tenantId: string,
    invitation: {
      email: string;
      role: User['role'];
      permissions?: string[];
      sendEmail?: boolean;
    }
  ): Promise<{ invitation: any; user?: User }> {
    const response = await apiClient.post<{ invitation: any; user?: User }>(
      `/tenants/${tenantId}/users/invite`,
      invitation
    );
    return response.data!;
  }

  async removeTenantUser(
    tenantId: string,
    userId: string,
    options?: {
      transferDataTo?: string;
      deactivateOnly?: boolean;
    }
  ): Promise<void> {
    await apiClient.delete(`/tenants/${tenantId}/users/${userId}`, { data: options });
  }

  // Tenant security and compliance
  async getTenantSecurityPolicies(tenantId: string): Promise<any[]> {
    const response = await apiClient.get<any[]>(`/tenants/${tenantId}/security/policies`);
    return response.data!;
  }

  async updateTenantSecurityPolicy(tenantId: string, policyId: string, policy: any): Promise<any> {
    const response = await apiClient.patch<any>(`/tenants/${tenantId}/security/policies/${policyId}`, policy);
    return response.data!;
  }

  async runTenantSecurityScan(tenantId: string): Promise<{
    scanId: string;
    status: 'queued' | 'running' | 'completed' | 'failed';
    estimatedCompletion: Date;
  }> {
    const response = await apiClient.post<{
      scanId: string;
      status: 'queued' | 'running' | 'completed' | 'failed';
      estimatedCompletion: Date;
    }>(`/tenants/${tenantId}/security/scan`);
    return response.data!;
  }

  // Tenant data and export
  async exportTenantData(
    tenantId: string,
    options: {
      dataTypes: string[];
      format: 'json' | 'csv' | 'xml';
      includeMetadata?: boolean;
      dateRange?: { start: Date; end: Date };
    }
  ): Promise<{ downloadUrl: string; expiresAt: Date; size: number }> {
    const response = await apiClient.post<{ downloadUrl: string; expiresAt: Date; size: number }>(
      `/tenants/${tenantId}/export`,
      options
    );
    return response.data!;
  }

  async cloneTenant(
    sourceTenantId: string,
    options: {
      name: string;
      includeData?: string[];
      includeUsers?: boolean;
      includeSettings?: boolean;
    }
  ): Promise<{ tenant: Tenant; cloneId: string; status: string }> {
    const response = await apiClient.post<{ tenant: Tenant; cloneId: string; status: string }>(
      `/tenants/${sourceTenantId}/clone`,
      options
    );
    return response.data!;
  }

  // System-wide tenant operations
  async getTenantOverview(): Promise<{
    totalTenants: number;
    activeTenants: number;
    totalUsers: number;
    totalAssets: number;
    totalAlerts: number;
    systemHealth: 'healthy' | 'warning' | 'critical';
    resourceUtilization: {
      cpu: number;
      memory: number;
      storage: number;
      bandwidth: number;
    };
    topTenants: Array<{
      tenant: Tenant;
      stats: TenantStats;
      health: TenantHealth['overall'];
    }>;
  }> {
    const response = await apiClient.get<{
      totalTenants: number;
      activeTenants: number;
      totalUsers: number;
      totalAssets: number;
      totalAlerts: number;
      systemHealth: 'healthy' | 'warning' | 'critical';
      resourceUtilization: {
        cpu: number;
        memory: number;
        storage: number;
        bandwidth: number;
      };
      topTenants: Array<{
        tenant: Tenant;
        stats: TenantStats;
        health: TenantHealth['overall'];
      }>;
    }>('/tenants/overview');
    return response.data!;
  }

  async healthCheck(): Promise<boolean> {
    try {
      await apiClient.get('/tenants/health');
      return true;
    } catch {
      return false;
    }
  }
}

export const tenantService = new TenantService();
export default tenantService;
