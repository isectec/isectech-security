/**
 * Store Index for iSECTECH Protect
 * Central export point for all Zustand stores
 */

export { useAppStore } from './app';
export { setApiClient, useAuthStore } from './auth';
export { dashboardHelpers, dashboardSelectors, useDashboardStore } from './dashboard';

// Re-export commonly used store actions
export const stores = {
  auth: () => import('./auth').then((m) => m.useAuthStore),
  app: () => import('./app').then((m) => m.useAppStore),
  dashboard: () => import('./dashboard').then((m) => m.useDashboardStore),
} as const;

// Combined store hook for common operations
export const useStores = () => {
  const auth = useAuthStore();
  const app = useAppStore();
  const dashboard = useDashboardStore();

  return {
    auth,
    app,
    dashboard,

    // Combined actions
    showError: (title: string, message?: string) => {
      return app.showError(title, message);
    },

    showSuccess: (title: string, message?: string) => {
      return app.showSuccess(title, message);
    },

    showWarning: (title: string, message?: string) => {
      return app.showWarning(title, message);
    },

    showInfo: (title: string, message?: string) => {
      return app.showInfo(title, message);
    },

    setLoading: (key: string, loading: boolean) => {
      app.setLoadingState(key, { isLoading: loading });
    },

    setError: (key: string, error: string | null) => {
      app.setLoadingState(key, { error, isLoading: false });
    },

    clearState: (key: string) => {
      app.clearLoadingState(key);
    },

    // Security helpers
    hasPermission: (permission: string, resource?: string) => {
      return auth.checkPermission(permission, resource);
    },

    hasClearance: (clearance: import('@/types').SecurityClearance) => {
      return auth.checkClearance(clearance);
    },

    hasRole: (role: import('@/types').UserRole | import('@/types').UserRole[]) => {
      return auth.checkRole(role);
    },

    isAuthenticated: () => {
      return auth.isAuthenticated && auth.validateSecurityContext();
    },

    getCurrentUser: () => {
      return auth.user;
    },

    getCurrentTenant: () => {
      return auth.tenant;
    },

    // UI helpers
    toggleSidebar: () => {
      app.toggleSidebar();
    },

    setCurrentPage: (page: string) => {
      app.setCurrentPage(page);
    },

    setBreadcrumbs: (breadcrumbs: import('@/types').Breadcrumb[]) => {
      app.setBreadcrumbs(breadcrumbs);
    },

    // Performance tracking
    trackPerformance: (metrics: Partial<ReturnType<typeof app.getState>['performanceMetrics']>) => {
      app.updatePerformanceMetrics(metrics);
    },

    // Error boundary helper
    handleError: (error: Error, context?: string) => {
      console.error(`Error in ${context || 'unknown context'}:`, error);
      app.showError('Application Error', error.message || 'An unexpected error occurred');
    },

    // Loading state helpers
    withLoading: async <T>(
      key: string,
      asyncOperation: () => Promise<T>,
      options?: { errorMessage?: string }
    ): Promise<T | null> => {
      try {
        app.setLoadingState(key, { isLoading: true, error: null });
        const result = await asyncOperation();
        app.setLoadingState(key, { isLoading: false, error: null });
        return result;
      } catch (error) {
        const errorMessage = options?.errorMessage || 'Operation failed';
        app.setLoadingState(key, {
          isLoading: false,
          error: error instanceof Error ? error.message : errorMessage,
        });
        app.showError('Operation Failed', errorMessage);
        return null;
      }
    },
  };
};

// Store selectors for optimized re-renders
export const authSelectors = {
  isAuthenticated: (state: ReturnType<typeof useAuthStore.getState>) => state.isAuthenticated,
  user: (state: ReturnType<typeof useAuthStore.getState>) => state.user,
  tenant: (state: ReturnType<typeof useAuthStore.getState>) => state.tenant,
  permissions: (state: ReturnType<typeof useAuthStore.getState>) => state.permissions,
  securityClearance: (state: ReturnType<typeof useAuthStore.getState>) => state.securityClearance,
  isLoading: (state: ReturnType<typeof useAuthStore.getState>) => state.isLoading,
  error: (state: ReturnType<typeof useAuthStore.getState>) => state.error,
};

export const appSelectors = {
  theme: (state: ReturnType<typeof useAppStore.getState>) => state.theme,
  sidebarOpen: (state: ReturnType<typeof useAppStore.getState>) => state.sidebarOpen,
  sidebarCollapsed: (state: ReturnType<typeof useAppStore.getState>) => state.sidebarCollapsed,
  notifications: (state: ReturnType<typeof useAppStore.getState>) => state.notifications,
  unreadCount: (state: ReturnType<typeof useAppStore.getState>) => state.unreadCount,
  globalLoading: (state: ReturnType<typeof useAppStore.getState>) => state.globalLoading,
  currentPage: (state: ReturnType<typeof useAppStore.getState>) => state.currentPage,
  breadcrumbs: (state: ReturnType<typeof useAppStore.getState>) => state.breadcrumbs,
  connectionStatus: (state: ReturnType<typeof useAppStore.getState>) => state.connectionStatus,
};

// Devtools integration
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  // Add stores to window for debugging
  (window as any).__ISECTECH_STORES__ = {
    auth: useAuthStore,
    app: useAppStore,
    dashboard: useDashboardStore,
  };
}
