/**
 * Tenant Management Hooks for iSECTECH Protect MSSP Edition
 * High-performance React hooks for multi-tenant operations
 */

import { tenantService } from '@/lib/api/services/tenants';
import { useAppStore, useAuthStore } from '@/lib/store';
import type { SearchParams, Tenant } from '@/types';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useState } from 'react';

// Query keys for consistent caching
export const tenantQueryKeys = {
  all: ['tenants'] as const,
  lists: () => [...tenantQueryKeys.all, 'list'] as const,
  list: (filters: any) => [...tenantQueryKeys.lists(), filters] as const,
  details: () => [...tenantQueryKeys.all, 'detail'] as const,
  detail: (id: string) => [...tenantQueryKeys.details(), id] as const,
  stats: (id: string) => [...tenantQueryKeys.all, 'stats', id] as const,
  health: (id: string) => [...tenantQueryKeys.all, 'health', id] as const,
  analytics: (id: string, params: any) => [...tenantQueryKeys.all, 'analytics', id, params] as const,
  overview: () => [...tenantQueryKeys.all, 'overview'] as const,
  templates: () => [...tenantQueryKeys.all, 'templates'] as const,
  users: (tenantId: string) => [...tenantQueryKeys.all, 'users', tenantId] as const,
  billing: (tenantId: string) => [...tenantQueryKeys.all, 'billing', tenantId] as const,
};

// Main tenants list hook with real-time updates
export function useTenants(
  options: {
    search?: SearchParams;
    filters?: {
      status?: Tenant['status'][];
      plan?: Tenant['plan'][];
      features?: string[];
    };
    includeStats?: boolean;
    includeHealth?: boolean;
    enabled?: boolean;
  } = {}
) {
  const { search, filters = {}, includeStats, includeHealth, enabled = true } = options;
  const { showError } = useAppStore();

  const query = useQuery({
    queryKey: tenantQueryKeys.list({ search, filters, includeStats, includeHealth }),
    queryFn: () =>
      tenantService.getTenants({
        search,
        filters,
        includeStats,
        includeHealth,
      }),
    enabled,
    staleTime: 2 * 60 * 1000, // 2 minutes
    refetchInterval: 5 * 60 * 1000, // Refresh every 5 minutes
    onError: (error: any) => {
      showError('Failed to load tenants', error.message);
    },
  });

  return {
    ...query,
    tenants: query.data?.items || [],
    pagination: query.data?.meta,
  };
}

// Single tenant detail hook with comprehensive data
export function useTenant(
  id: string,
  options: {
    includeStats?: boolean;
    includeHealth?: boolean;
    includeAnalytics?: boolean;
    includeBilling?: boolean;
    enabled?: boolean;
  } = {}
) {
  const { includeStats, includeHealth, includeAnalytics, includeBilling, enabled = !!id } = options;
  const { showError } = useAppStore();

  return useQuery({
    queryKey: tenantQueryKeys.detail(id),
    queryFn: () =>
      tenantService.getTenant(id, {
        includeStats,
        includeHealth,
        includeAnalytics,
        includeBilling,
      }),
    enabled,
    staleTime: 60 * 1000, // 1 minute
    onError: (error: any) => {
      showError('Failed to load tenant details', error.message);
    },
  });
}

// Current tenant context hook
export function useCurrentTenant() {
  const auth = useAuthStore();
  const { showError } = useAppStore();

  return useQuery({
    queryKey: ['auth', 'tenant-context'],
    queryFn: () => tenantService.getCurrentTenantContext(),
    enabled: auth.isAuthenticated,
    staleTime: 30 * 1000, // 30 seconds
    refetchInterval: 60 * 1000, // Refresh every minute
    onError: (error: any) => {
      showError('Failed to load tenant context', error.message);
    },
  });
}

// Lightning-fast tenant switching hook
export function useTenantSwitching() {
  const queryClient = useQueryClient();
  const auth = useAuthStore();
  const { showSuccess, showError, setGlobalLoading, setTenantContext } = useAppStore();
  const [switchingTo, setSwitchingTo] = useState<string | null>(null);

  const switchTenant = useMutation({
    mutationFn: async ({ tenantId, preloadData }: { tenantId: string; preloadData?: string[] }) => {
      setSwitchingTo(tenantId);
      setGlobalLoading(true);

      const startTime = Date.now();

      // Preload data for faster switching
      if (preloadData?.length) {
        await tenantService.preloadTenantData(tenantId, preloadData);
      }

      const result = await tenantService.switchTenant(tenantId, {
        preloadData,
        warmCache: true,
      });

      const totalTime = Date.now() - startTime;

      return { ...result, totalTime };
    },
    onSuccess: (result) => {
      // Update auth store
      auth.setTenant(result.tenant);
      auth.setUser(result.user);

      // Update app store tenant context
      setTenantContext({
        id: result.tenant.id,
        name: result.tenant.name,
        switchingInProgress: false,
      });

      // Invalidate all queries to refresh data for new tenant
      queryClient.invalidateQueries();

      // Clear cache for previous tenant
      queryClient.removeQueries({ predicate: (query) => query.queryKey.includes('tenant-specific') });

      const message =
        result.switchTime < 500
          ? `Switched to ${result.tenant.displayName} in ${result.switchTime}ms`
          : `Switched to ${result.tenant.displayName}`;

      showSuccess('Tenant switched successfully', message);

      setSwitchingTo(null);
      setGlobalLoading(false);
    },
    onError: (error: any) => {
      showError('Failed to switch tenant', error.message);
      setSwitchingTo(null);
      setGlobalLoading(false);
      setTenantContext({ switchingInProgress: false });
    },
    onMutate: ({ tenantId }) => {
      setTenantContext({
        id: tenantId,
        switchingInProgress: true,
      });
    },
  });

  const quickSwitch = useCallback(
    async (tenantId: string) => {
      await switchTenant.mutateAsync({
        tenantId,
        preloadData: ['alerts', 'assets', 'users'],
      });
    },
    [switchTenant]
  );

  return {
    switchTenant: switchTenant.mutate,
    quickSwitch,
    isLoading: switchTenant.isLoading,
    switchingTo,
    error: switchTenant.error,
  };
}

// Tenant statistics hook with real-time updates
export function useTenantStats(
  tenantId: string,
  timeRange?: {
    start: Date;
    end: Date;
  }
) {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: tenantQueryKeys.stats(tenantId),
    queryFn: () => tenantService.getTenantStats(tenantId, timeRange),
    enabled: !!tenantId,
    staleTime: 30 * 1000, // 30 seconds
    refetchInterval: 60 * 1000, // Refresh every minute
    onError: (error: any) => {
      showError('Failed to load tenant statistics', error.message);
    },
  });
}

// Tenant health monitoring hook
export function useTenantHealth(tenantId: string) {
  const { showError, showWarning } = useAppStore();

  const query = useQuery({
    queryKey: tenantQueryKeys.health(tenantId),
    queryFn: () => tenantService.getTenantHealth(tenantId),
    enabled: !!tenantId,
    staleTime: 30 * 1000, // 30 seconds
    refetchInterval: 60 * 1000, // Refresh every minute
    onError: (error: any) => {
      showError('Failed to load tenant health', error.message);
    },
  });

  // Show warnings for critical health issues
  useEffect(() => {
    if (query.data?.overall === 'critical') {
      const criticalIssues = query.data.issues.filter((issue) => issue.severity === 'critical' && !issue.resolved);
      if (criticalIssues.length > 0) {
        showWarning(
          'Critical tenant issues detected',
          `${criticalIssues.length} critical issues require immediate attention`
        );
      }
    }
  }, [query.data, showWarning]);

  return query;
}

// Tenant analytics hook
export function useTenantAnalytics(
  tenantId: string,
  params: {
    period: 'hour' | 'day' | 'week' | 'month';
    metrics: string[];
    dateRange?: { start: Date; end: Date };
  }
) {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: tenantQueryKeys.analytics(tenantId, params),
    queryFn: () => tenantService.getTenantAnalytics(tenantId, params),
    enabled: !!tenantId && params.metrics.length > 0,
    staleTime: 5 * 60 * 1000, // 5 minutes
    onError: (error: any) => {
      showError('Failed to load tenant analytics', error.message);
    },
  });
}

// System overview hook for MSSP dashboard
export function useTenantOverview() {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: tenantQueryKeys.overview(),
    queryFn: () => tenantService.getTenantOverview(),
    staleTime: 60 * 1000, // 1 minute
    refetchInterval: 2 * 60 * 1000, // Refresh every 2 minutes
    onError: (error: any) => {
      showError('Failed to load system overview', error.message);
    },
  });
}

// Tenant templates hook
export function useTenantTemplates() {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: tenantQueryKeys.templates(),
    queryFn: () => tenantService.getTenantTemplates(),
    staleTime: 10 * 60 * 1000, // 10 minutes
    onError: (error: any) => {
      showError('Failed to load tenant templates', error.message);
    },
  });
}

// Tenant users hook
export function useTenantUsers(
  tenantId: string,
  params?: {
    search?: SearchParams;
    includeInactive?: boolean;
  }
) {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: tenantQueryKeys.users(tenantId),
    queryFn: () => tenantService.getTenantUsers(tenantId, params),
    enabled: !!tenantId,
    staleTime: 2 * 60 * 1000, // 2 minutes
    onError: (error: any) => {
      showError('Failed to load tenant users', error.message);
    },
  });
}

// Tenant billing hook
export function useTenantBilling(tenantId: string) {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: tenantQueryKeys.billing(tenantId),
    queryFn: () => tenantService.getTenantBilling(tenantId),
    enabled: !!tenantId,
    staleTime: 5 * 60 * 1000, // 5 minutes
    onError: (error: any) => {
      showError('Failed to load billing information', error.message);
    },
  });
}

// Tenant mutations hook for CRUD operations
export function useTenantMutations() {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useAppStore();

  const createTenant = useMutation({
    mutationFn: (tenant: Omit<Tenant, 'id' | 'createdAt' | 'updatedAt'>) => tenantService.createTenant(tenant),
    onSuccess: (newTenant) => {
      queryClient.invalidateQueries({ queryKey: tenantQueryKeys.lists() });
      showSuccess('Tenant created successfully', `${newTenant.displayName} is now active`);
    },
    onError: (error: any) => {
      showError('Failed to create tenant', error.message);
    },
  });

  const updateTenant = useMutation({
    mutationFn: ({ id, updates }: { id: string; updates: Partial<Tenant> }) => tenantService.updateTenant(id, updates),
    onSuccess: (updatedTenant) => {
      queryClient.invalidateQueries({ queryKey: tenantQueryKeys.lists() });
      queryClient.setQueryData(tenantQueryKeys.detail(updatedTenant.id), updatedTenant);
      showSuccess('Tenant updated successfully');
    },
    onError: (error: any) => {
      showError('Failed to update tenant', error.message);
    },
  });

  const updateTenantSettings = useMutation({
    mutationFn: ({ tenantId, settings }: { tenantId: string; settings: any }) =>
      tenantService.updateTenantSettings(tenantId, settings),
    onSuccess: (updatedTenant) => {
      queryClient.invalidateQueries({ queryKey: tenantQueryKeys.detail(updatedTenant.id) });
      showSuccess('Tenant settings updated successfully');
    },
    onError: (error: any) => {
      showError('Failed to update tenant settings', error.message);
    },
  });

  const updateTenantBranding = useMutation({
    mutationFn: ({ tenantId, branding }: { tenantId: string; branding: any }) =>
      tenantService.updateTenantBranding(tenantId, branding),
    onSuccess: (updatedTenant) => {
      queryClient.invalidateQueries({ queryKey: tenantQueryKeys.detail(updatedTenant.id) });
      showSuccess('Tenant branding updated successfully');
    },
    onError: (error: any) => {
      showError('Failed to update tenant branding', error.message);
    },
  });

  const deleteTenant = useMutation({
    mutationFn: ({ id, options }: { id: string; options?: any }) => tenantService.deleteTenant(id, options),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: tenantQueryKeys.lists() });
      showSuccess('Tenant deleted successfully');
    },
    onError: (error: any) => {
      showError('Failed to delete tenant', error.message);
    },
  });

  return {
    createTenant,
    updateTenant,
    updateTenantSettings,
    updateTenantBranding,
    deleteTenant,
  };
}

// Optimized tenant search and filtering
export function useTenantFiltering() {
  const [filters, setFilters] = useState<{
    status?: Tenant['status'][];
    plan?: Tenant['plan'][];
    features?: string[];
    healthStatus?: ('healthy' | 'warning' | 'critical')[];
  }>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<{
    field: string;
    direction: 'asc' | 'desc';
  }>({ field: 'displayName', direction: 'asc' });

  const updateFilter = useCallback((key: string, value: any) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value,
    }));
  }, []);

  const clearFilter = useCallback((key: string) => {
    setFilters((prev) => {
      const newFilters = { ...prev };
      delete newFilters[key as keyof typeof newFilters];
      return newFilters;
    });
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilters({});
    setSearchQuery('');
  }, []);

  const activeFilterCount = useMemo(() => {
    return Object.keys(filters).length + (searchQuery ? 1 : 0);
  }, [filters, searchQuery]);

  const searchParams: SearchParams | undefined = searchQuery
    ? {
        query: searchQuery,
        fields: ['name', 'displayName', 'domain'],
      }
    : undefined;

  return {
    filters,
    searchQuery,
    searchParams,
    sortBy,
    activeFilterCount,
    updateFilter,
    clearFilter,
    clearAllFilters,
    setSearchQuery,
    setSortBy,
  };
}

// Performance monitoring for tenant operations
export function useTenantPerformance() {
  const [metrics, setMetrics] = useState<{
    switchTime: number[];
    loadTime: number[];
    errorRate: number;
    activeConnections: number;
  }>({
    switchTime: [],
    loadTime: [],
    errorRate: 0,
    activeConnections: 0,
  });

  const recordSwitchTime = useCallback((time: number) => {
    setMetrics((prev) => ({
      ...prev,
      switchTime: [...prev.switchTime.slice(-9), time], // Keep last 10 measurements
    }));
  }, []);

  const recordLoadTime = useCallback((time: number) => {
    setMetrics((prev) => ({
      ...prev,
      loadTime: [...prev.loadTime.slice(-9), time], // Keep last 10 measurements
    }));
  }, []);

  const averageSwitchTime = useMemo(() => {
    if (metrics.switchTime.length === 0) return 0;
    return metrics.switchTime.reduce((sum, time) => sum + time, 0) / metrics.switchTime.length;
  }, [metrics.switchTime]);

  const averageLoadTime = useMemo(() => {
    if (metrics.loadTime.length === 0) return 0;
    return metrics.loadTime.reduce((sum, time) => sum + time, 0) / metrics.loadTime.length;
  }, [metrics.loadTime]);

  const performanceScore = useMemo(() => {
    if (averageSwitchTime === 0) return 100;

    // Score based on sub-500ms target
    const switchScore = Math.max(0, 100 - (averageSwitchTime / 500) * 100);
    const loadScore = Math.max(0, 100 - (averageLoadTime / 2000) * 100);
    const errorScore = Math.max(0, 100 - metrics.errorRate * 100);

    return (switchScore + loadScore + errorScore) / 3;
  }, [averageSwitchTime, averageLoadTime, metrics.errorRate]);

  return {
    metrics,
    averageSwitchTime,
    averageLoadTime,
    performanceScore,
    recordSwitchTime,
    recordLoadTime,
  };
}
