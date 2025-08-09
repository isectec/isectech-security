/**
 * Cache Synchronization Hook for iSECTECH Protect
 * Manages cross-component cache invalidation and state synchronization
 */

import { useAppStore, useAuthStore } from '@/lib/store';
import { useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect } from 'react';
import { alertQueryKeys } from './use-alerts';
import { dashboardQueryKeys } from './use-dashboard';
import { tenantQueryKeys } from './use-tenants';

// Event types for cache synchronization
export type CacheSyncEvent =
  | 'tenant-switch'
  | 'user-logout'
  | 'user-login'
  | 'alert-update'
  | 'tenant-update'
  | 'user-update'
  | 'permission-change'
  | 'global-refresh';

// Cache invalidation strategies
export interface CacheInvalidationStrategy {
  // Which query keys to invalidate
  queryKeys: string[][];
  // Whether to refetch immediately
  refetchImmediately?: boolean;
  // Whether to remove from cache entirely
  removeFromCache?: boolean;
  // Custom invalidation logic
  customLogic?: () => void;
}

// Cache synchronization configuration
const CACHE_SYNC_CONFIG: Record<CacheSyncEvent, CacheInvalidationStrategy> = {
  'tenant-switch': {
    queryKeys: [
      alertQueryKeys.all,
      tenantQueryKeys.users('{current}'), // Will be replaced with actual tenant ID
      dashboardQueryKeys.all,
    ],
    refetchImmediately: true,
    customLogic: () => {
      // Clear any tenant-specific local storage
      sessionStorage.removeItem('selected-alerts');
      sessionStorage.removeItem('dashboard-filters');
    },
  },
  'user-logout': {
    queryKeys: [alertQueryKeys.all, tenantQueryKeys.all, dashboardQueryKeys.all],
    removeFromCache: true,
    customLogic: () => {
      // Clear all local storage
      sessionStorage.clear();
      localStorage.removeItem('dashboard-config');
    },
  },
  'user-login': {
    queryKeys: [alertQueryKeys.all, tenantQueryKeys.all, dashboardQueryKeys.all],
    refetchImmediately: true,
  },
  'alert-update': {
    queryKeys: [
      alertQueryKeys.all,
      dashboardQueryKeys.metrics('24h'), // Update dashboard metrics
    ],
    refetchImmediately: true,
  },
  'tenant-update': {
    queryKeys: [
      tenantQueryKeys.all,
      dashboardQueryKeys.all, // Tenant changes might affect dashboard
    ],
    refetchImmediately: true,
  },
  'user-update': {
    queryKeys: [
      tenantQueryKeys.users('{current}'),
      alertQueryKeys.all, // User permissions might affect visible alerts
    ],
    refetchImmediately: true,
  },
  'permission-change': {
    queryKeys: [alertQueryKeys.all, tenantQueryKeys.all, dashboardQueryKeys.all],
    refetchImmediately: true,
    customLogic: () => {
      // Clear cached permission-based data
      sessionStorage.removeItem('filtered-alerts');
      sessionStorage.removeItem('accessible-tenants');
    },
  },
  'global-refresh': {
    queryKeys: [alertQueryKeys.all, tenantQueryKeys.all, dashboardQueryKeys.all],
    refetchImmediately: true,
  },
};

// Cache synchronization hook
export function useCacheSync() {
  const queryClient = useQueryClient();
  const { user, tenant } = useAuthStore();
  const { showInfo } = useAppStore();

  // Trigger cache synchronization for specific events
  const syncCache = useCallback(
    (
      event: CacheSyncEvent,
      options?: {
        tenantId?: string;
        silent?: boolean;
      }
    ) => {
      const config = CACHE_SYNC_CONFIG[event];
      const { tenantId, silent = false } = options || {};

      if (!silent && event !== 'global-refresh') {
        showInfo('Synchronizing Data', 'Updating cached information...');
      }

      // Process query keys (replace placeholders)
      const processedQueryKeys = config.queryKeys.map((queryKey) => {
        return queryKey.map((key) => {
          if (key === '{current}') {
            return tenantId || tenant?.id || 'unknown';
          }
          return key;
        });
      });

      // Execute invalidation strategy
      processedQueryKeys.forEach((queryKey) => {
        if (config.removeFromCache) {
          queryClient.removeQueries({ queryKey });
        } else {
          queryClient.invalidateQueries({
            queryKey,
            refetchType: config.refetchImmediately ? 'all' : 'none',
          });
        }
      });

      // Execute custom logic
      config.customLogic?.();

      console.log(`Cache sync executed for event: ${event}`, {
        queryKeys: processedQueryKeys,
        config,
      });
    },
    [queryClient, tenant?.id, showInfo]
  );

  // Automatic cache synchronization based on auth state changes
  useEffect(() => {
    const unsubscribeAuth = useAuthStore.subscribe(
      (state) => ({
        user: state.user,
        tenant: state.tenant,
        isAuthenticated: state.isAuthenticated,
      }),
      (current, previous) => {
        // Handle user login/logout
        if (current.isAuthenticated !== previous.isAuthenticated) {
          if (current.isAuthenticated) {
            syncCache('user-login', { silent: true });
          } else {
            syncCache('user-logout', { silent: true });
          }
        }

        // Handle tenant switching
        if (current.tenant?.id !== previous.tenant?.id && current.tenant) {
          syncCache('tenant-switch', {
            tenantId: current.tenant.id,
            silent: false,
          });
        }

        // Handle user changes (role, permissions)
        if (current.user?.id === previous.user?.id && current.user) {
          // Check if permissions or role changed
          const permissionsChanged =
            JSON.stringify(current.user.permissions) !== JSON.stringify(previous.user?.permissions);
          const roleChanged = current.user.role !== previous.user?.role;

          if (permissionsChanged || roleChanged) {
            syncCache('permission-change', { silent: true });
          }
        }
      }
    );

    return unsubscribeAuth;
  }, [syncCache]);

  // Manual refresh all data
  const refreshAllData = useCallback(() => {
    syncCache('global-refresh');
  }, [syncCache]);

  // Invalidate specific data types
  const invalidateAlerts = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: alertQueryKeys.all });
  }, [queryClient]);

  const invalidateTenants = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: tenantQueryKeys.all });
  }, [queryClient]);

  const invalidateDashboard = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: dashboardQueryKeys.all });
  }, [queryClient]);

  // Get cache status for debugging
  const getCacheStatus = useCallback(() => {
    const alertQueries = queryClient.getQueryCache().findAll({ queryKey: alertQueryKeys.all });
    const tenantQueries = queryClient.getQueryCache().findAll({ queryKey: tenantQueryKeys.all });
    const dashboardQueries = queryClient.getQueryCache().findAll({ queryKey: dashboardQueryKeys.all });

    return {
      alerts: {
        count: alertQueries.length,
        stale: alertQueries.filter((q) => q.isStale()).length,
        fresh: alertQueries.filter((q) => !q.isStale()).length,
      },
      tenants: {
        count: tenantQueries.length,
        stale: tenantQueries.filter((q) => q.isStale()).length,
        fresh: tenantQueries.filter((q) => !q.isStale()).length,
      },
      dashboard: {
        count: dashboardQueries.length,
        stale: dashboardQueries.filter((q) => q.isStale()).length,
        fresh: dashboardQueries.filter((q) => !q.isStale()).length,
      },
      total: alertQueries.length + tenantQueries.length + dashboardQueries.length,
    };
  }, [queryClient]);

  // Clear all cache
  const clearAllCache = useCallback(() => {
    queryClient.clear();
    sessionStorage.clear();
    localStorage.removeItem('dashboard-config');
    showInfo('Cache Cleared', 'All cached data has been cleared');
  }, [queryClient, showInfo]);

  return {
    // Main sync function
    syncCache,

    // Convenience methods
    refreshAllData,
    invalidateAlerts,
    invalidateTenants,
    invalidateDashboard,

    // Cache management
    getCacheStatus,
    clearAllCache,

    // Current user context for cache keys
    currentUserId: user?.id,
    currentTenantId: tenant?.id,
  };
}

// Hook for component-specific cache management
export function useComponentCacheSync(componentName: string) {
  const { syncCache, invalidateAlerts, invalidateTenants, invalidateDashboard } = useCacheSync();
  const { showInfo } = useAppStore();

  // Track component-specific cache operations
  const refreshComponent = useCallback(() => {
    const componentCacheMap: Record<string, () => void> = {
      alerts: invalidateAlerts,
      dashboard: invalidateDashboard,
      tenants: invalidateTenants,
      'multi-tenant': invalidateTenants,
    };

    const refreshFn = componentCacheMap[componentName];
    if (refreshFn) {
      refreshFn();
      showInfo(`${componentName} Data Refreshed`, 'Component data has been updated');
    } else {
      syncCache('global-refresh');
    }
  }, [componentName, invalidateAlerts, invalidateDashboard, invalidateTenants, syncCache, showInfo]);

  return {
    refreshComponent,
    syncCache,
  };
}

// Development helper hook for cache debugging
export function useCacheDebug() {
  const { getCacheStatus, clearAllCache } = useCacheSync();
  const queryClient = useQueryClient();

  const logCacheStatus = useCallback(() => {
    const status = getCacheStatus();
    console.group('🔍 Cache Status Debug');
    console.table(status);
    console.log('All Queries:', queryClient.getQueryCache().getAll());
    console.groupEnd();
  }, [getCacheStatus, queryClient]);

  // Auto-log cache status in development
  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      const interval = setInterval(logCacheStatus, 30000); // Log every 30 seconds
      return () => clearInterval(interval);
    }
  }, [logCacheStatus]);

  return {
    logCacheStatus,
    clearAllCache,
    getCacheStatus,
  };
}
