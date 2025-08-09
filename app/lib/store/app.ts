/**
 * Application Store for iSECTECH Protect
 * Global UI state management for the cybersecurity dashboard
 */

import { create } from 'zustand';
import { createJSONStorage, persist, subscribeWithSelector } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import type { 
  ThemeMode,
  Notification,
  NotificationType,
  UserPreferences,
  LoadingState,
  DateRange,
  MenuItem,
  Breadcrumb
} from '@/types';
import { appConfig, dashboardConfig } from '@/config/app';

interface AppState {
  // Theme and UI
  theme: ThemeMode;
  sidebarOpen: boolean;
  sidebarCollapsed: boolean;
  fullscreen: boolean;
  
  // Loading states
  globalLoading: boolean;
  loadingStates: Record<string, LoadingState>;
  
  // Notifications
  notifications: Notification[];
  unreadCount: number;
  
  // Navigation
  currentPage: string;
  breadcrumbs: Breadcrumb[];
  menuItems: MenuItem[];
  
  // Dashboard state
  dashboardRefreshInterval: number;
  autoRefresh: boolean;
  dateRange: DateRange;
  
  // Preferences
  preferences: UserPreferences;
  
  // Error handling
  globalError: string | null;
  errorBoundaryInfo: any;
  
  // Feature flags (runtime)
  featureFlags: Record<string, boolean>;
  
  // Performance monitoring
  performanceMetrics: {
    loadTime: number;
    renderTime: number;
    apiResponseTime: number;
    lastUpdated: Date;
  };
  
  // Multi-tenant context
  tenantContext: {
    id: string | null;
    name: string | null;
    switchingInProgress: boolean;
  };
  
  // Search state
  globalSearchQuery: string;
  searchHistory: string[];
  
  // Connection status
  connectionStatus: {
    online: boolean;
    apiConnected: boolean;
    websocketConnected: boolean;
    lastCheck: Date;
  };
}

interface AppStore extends AppState {
  // Theme actions
  setTheme: (theme: ThemeMode) => void;
  toggleTheme: () => void;
  
  // Sidebar actions
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  toggleSidebarCollapse: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  
  // Fullscreen actions
  toggleFullscreen: () => void;
  setFullscreen: (fullscreen: boolean) => void;
  
  // Loading actions
  setGlobalLoading: (loading: boolean) => void;
  setLoadingState: (key: string, state: Partial<LoadingState>) => void;
  clearLoadingState: (key: string) => void;
  
  // Notification actions
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => string;
  removeNotification: (id: string) => void;
  markNotificationRead: (id: string) => void;
  markAllNotificationsRead: () => void;
  clearNotifications: () => void;
  showSuccess: (title: string, message?: string) => string;
  showError: (title: string, message?: string) => string;
  showWarning: (title: string, message?: string) => string;
  showInfo: (title: string, message?: string) => string;
  
  // Navigation actions
  setCurrentPage: (page: string) => void;
  setBreadcrumbs: (breadcrumbs: Breadcrumb[]) => void;
  addBreadcrumb: (breadcrumb: Breadcrumb) => void;
  setMenuItems: (items: MenuItem[]) => void;
  
  // Dashboard actions
  setDashboardRefreshInterval: (interval: number) => void;
  setAutoRefresh: (enabled: boolean) => void;
  setDateRange: (range: DateRange) => void;
  refreshDashboard: () => void;
  
  // Preferences actions
  updatePreferences: (preferences: Partial<UserPreferences>) => void;
  resetPreferences: () => void;
  
  // Error actions
  setGlobalError: (error: string | null) => void;
  setErrorBoundaryInfo: (info: any) => void;
  clearErrors: () => void;
  
  // Feature flags
  setFeatureFlag: (flag: string, enabled: boolean) => void;
  isFeatureEnabled: (flag: string) => boolean;
  
  // Performance
  updatePerformanceMetrics: (metrics: Partial<AppState['performanceMetrics']>) => void;
  
  // Tenant context
  setTenantContext: (context: Partial<AppState['tenantContext']>) => void;
  
  // Search
  setGlobalSearchQuery: (query: string) => void;
  addToSearchHistory: (query: string) => void;
  clearSearchHistory: () => void;
  
  // Connection status
  setConnectionStatus: (status: Partial<AppState['connectionStatus']>) => void;
  checkConnectivity: () => Promise<void>;
  
  // Utility actions
  reset: () => void;
  exportState: () => string;
  importState: (state: string) => boolean;
}

const defaultPreferences: UserPreferences = {
  theme: appConfig.defaultTheme,
  language: appConfig.defaultLanguage,
  timezone: appConfig.defaultTimezone,
  dateFormat: 'MM/dd/yyyy',
  timeFormat: '12h',
  currency: 'USD',
  notifications: {
    email: true,
    browser: true,
    mobile: true,
    types: ['security', 'alerts', 'system'],
  },
  privacy: {
    shareAnalytics: false,
    shareUsageData: false,
  },
};

const initialState: AppState = {
  // Theme and UI
  theme: appConfig.defaultTheme,
  sidebarOpen: true,
  sidebarCollapsed: false,
  fullscreen: false,
  
  // Loading states
  globalLoading: false,
  loadingStates: {},
  
  // Notifications
  notifications: [],
  unreadCount: 0,
  
  // Navigation
  currentPage: '/',
  breadcrumbs: [],
  menuItems: [],
  
  // Dashboard state
  dashboardRefreshInterval: dashboardConfig.refreshInterval,
  autoRefresh: true,
  dateRange: {
    start: new Date(Date.now() - dashboardConfig.defaultDateRange * 60 * 60 * 1000),
    end: new Date(),
  },
  
  // Preferences
  preferences: defaultPreferences,
  
  // Error handling
  globalError: null,
  errorBoundaryInfo: null,
  
  // Feature flags
  featureFlags: {},
  
  // Performance monitoring
  performanceMetrics: {
    loadTime: 0,
    renderTime: 0,
    apiResponseTime: 0,
    lastUpdated: new Date(),
  },
  
  // Multi-tenant context
  tenantContext: {
    id: null,
    name: null,
    switchingInProgress: false,
  },
  
  // Search state
  globalSearchQuery: '',
  searchHistory: [],
  
  // Connection status
  connectionStatus: {
    online: typeof navigator !== 'undefined' ? navigator.onLine : true,
    apiConnected: false,
    websocketConnected: false,
    lastCheck: new Date(),
  },
};

export const useAppStore = create<AppStore>()(
  subscribeWithSelector(
    persist(
      immer((set, get) => ({
        ...initialState,

        // Theme actions
        setTheme: (theme: ThemeMode) => {
          set((state) => {
            state.theme = theme;
            state.preferences.theme = theme;
          });
        },

        toggleTheme: () => {
          const { theme } = get();
          const newTheme = theme === 'light' ? 'dark' : 'light';
          get().setTheme(newTheme);
        },

        // Sidebar actions
        toggleSidebar: () => {
          set((state) => {
            state.sidebarOpen = !state.sidebarOpen;
          });
        },

        setSidebarOpen: (open: boolean) => {
          set((state) => {
            state.sidebarOpen = open;
          });
        },

        toggleSidebarCollapse: () => {
          set((state) => {
            state.sidebarCollapsed = !state.sidebarCollapsed;
          });
        },

        setSidebarCollapsed: (collapsed: boolean) => {
          set((state) => {
            state.sidebarCollapsed = collapsed;
          });
        },

        // Fullscreen actions
        toggleFullscreen: () => {
          set((state) => {
            state.fullscreen = !state.fullscreen;
          });
        },

        setFullscreen: (fullscreen: boolean) => {
          set((state) => {
            state.fullscreen = fullscreen;
          });
        },

        // Loading actions
        setGlobalLoading: (loading: boolean) => {
          set((state) => {
            state.globalLoading = loading;
          });
        },

        setLoadingState: (key: string, loadingState: Partial<LoadingState>) => {
          set((state) => {
            if (!state.loadingStates[key]) {
              state.loadingStates[key] = {
                isLoading: false,
                error: null,
                lastUpdated: null,
              };
            }
            Object.assign(state.loadingStates[key], loadingState);
          });
        },

        clearLoadingState: (key: string) => {
          set((state) => {
            delete state.loadingStates[key];
          });
        },

        // Notification actions
        addNotification: (notification): string => {
          const id = `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          
          set((state) => {
            state.notifications.unshift({
              ...notification,
              id,
              timestamp: new Date(),
              read: false,
            });
            
            // Keep only last 100 notifications
            if (state.notifications.length > 100) {
              state.notifications = state.notifications.slice(0, 100);
            }
            
            state.unreadCount = state.notifications.filter(n => !n.read).length;
          });

          return id;
        },

        removeNotification: (id: string) => {
          set((state) => {
            state.notifications = state.notifications.filter(n => n.id !== id);
            state.unreadCount = state.notifications.filter(n => !n.read).length;
          });
        },

        markNotificationRead: (id: string) => {
          set((state) => {
            const notification = state.notifications.find(n => n.id === id);
            if (notification && !notification.read) {
              notification.read = true;
              state.unreadCount = state.notifications.filter(n => !n.read).length;
            }
          });
        },

        markAllNotificationsRead: () => {
          set((state) => {
            state.notifications.forEach(n => { n.read = true; });
            state.unreadCount = 0;
          });
        },

        clearNotifications: () => {
          set((state) => {
            state.notifications = [];
            state.unreadCount = 0;
          });
        },

        showSuccess: (title: string, message?: string): string => {
          return get().addNotification({
            type: 'success',
            title,
            message,
            duration: 5000,
          });
        },

        showError: (title: string, message?: string): string => {
          return get().addNotification({
            type: 'error',
            title,
            message,
            duration: 0, // Persistent
          });
        },

        showWarning: (title: string, message?: string): string => {
          return get().addNotification({
            type: 'warning',
            title,
            message,
            duration: 8000,
          });
        },

        showInfo: (title: string, message?: string): string => {
          return get().addNotification({
            type: 'info',
            title,
            message,
            duration: 6000,
          });
        },

        // Navigation actions
        setCurrentPage: (page: string) => {
          set((state) => {
            state.currentPage = page;
          });
        },

        setBreadcrumbs: (breadcrumbs: Breadcrumb[]) => {
          set((state) => {
            state.breadcrumbs = breadcrumbs;
          });
        },

        addBreadcrumb: (breadcrumb: Breadcrumb) => {
          set((state) => {
            state.breadcrumbs.push(breadcrumb);
          });
        },

        setMenuItems: (items: MenuItem[]) => {
          set((state) => {
            state.menuItems = items;
          });
        },

        // Dashboard actions
        setDashboardRefreshInterval: (interval: number) => {
          set((state) => {
            state.dashboardRefreshInterval = interval;
          });
        },

        setAutoRefresh: (enabled: boolean) => {
          set((state) => {
            state.autoRefresh = enabled;
          });
        },

        setDateRange: (range: DateRange) => {
          set((state) => {
            state.dateRange = range;
          });
        },

        refreshDashboard: () => {
          // Trigger dashboard refresh event
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('dashboard-refresh'));
          }
        },

        // Preferences actions
        updatePreferences: (preferences: Partial<UserPreferences>) => {
          set((state) => {
            Object.assign(state.preferences, preferences);
            
            // Update related state
            if (preferences.theme) {
              state.theme = preferences.theme;
            }
          });
        },

        resetPreferences: () => {
          set((state) => {
            state.preferences = { ...defaultPreferences };
            state.theme = defaultPreferences.theme;
          });
        },

        // Error actions
        setGlobalError: (error: string | null) => {
          set((state) => {
            state.globalError = error;
          });
        },

        setErrorBoundaryInfo: (info: any) => {
          set((state) => {
            state.errorBoundaryInfo = info;
          });
        },

        clearErrors: () => {
          set((state) => {
            state.globalError = null;
            state.errorBoundaryInfo = null;
          });
        },

        // Feature flags
        setFeatureFlag: (flag: string, enabled: boolean) => {
          set((state) => {
            state.featureFlags[flag] = enabled;
          });
        },

        isFeatureEnabled: (flag: string): boolean => {
          const { featureFlags } = get();
          return featureFlags[flag] ?? false;
        },

        // Performance
        updatePerformanceMetrics: (metrics: Partial<AppState['performanceMetrics']>) => {
          set((state) => {
            Object.assign(state.performanceMetrics, metrics);
            state.performanceMetrics.lastUpdated = new Date();
          });
        },

        // Tenant context
        setTenantContext: (context: Partial<AppState['tenantContext']>) => {
          set((state) => {
            Object.assign(state.tenantContext, context);
          });
        },

        // Search
        setGlobalSearchQuery: (query: string) => {
          set((state) => {
            state.globalSearchQuery = query;
          });
        },

        addToSearchHistory: (query: string) => {
          if (!query.trim()) return;
          
          set((state) => {
            // Remove if exists and add to front
            state.searchHistory = [
              query,
              ...state.searchHistory.filter(q => q !== query),
            ].slice(0, 10); // Keep only last 10
          });
        },

        clearSearchHistory: () => {
          set((state) => {
            state.searchHistory = [];
          });
        },

        // Connection status
        setConnectionStatus: (status: Partial<AppState['connectionStatus']>) => {
          set((state) => {
            Object.assign(state.connectionStatus, status);
            state.connectionStatus.lastCheck = new Date();
          });
        },

        checkConnectivity: async (): Promise<void> => {
          try {
            // Check if we can reach our API
            const response = await fetch('/api/health', {
              method: 'HEAD',
              cache: 'no-cache',
            });
            
            get().setConnectionStatus({
              online: navigator.onLine,
              apiConnected: response.ok,
            });
          } catch (error) {
            get().setConnectionStatus({
              online: navigator.onLine,
              apiConnected: false,
            });
          }
        },

        // Utility actions
        reset: () => {
          set(() => ({ ...initialState }));
        },

        exportState: (): string => {
          const state = get();
          return JSON.stringify(state, null, 2);
        },

        importState: (stateJson: string): boolean => {
          try {
            const state = JSON.parse(stateJson);
            set(() => state);
            return true;
          } catch (error) {
            console.error('Failed to import state:', error);
            return false;
          }
        },
      })),
      {
        name: 'isectech-app-state',
        storage: createJSONStorage(() => localStorage),
        partialize: (state) => ({
          theme: state.theme,
          sidebarCollapsed: state.sidebarCollapsed,
          preferences: state.preferences,
          dashboardRefreshInterval: state.dashboardRefreshInterval,
          autoRefresh: state.autoRefresh,
          searchHistory: state.searchHistory,
          featureFlags: state.featureFlags,
        }),
        version: 1,
      }
    )
  )
);

// Browser event listeners
if (typeof window !== 'undefined') {
  // Online/offline status
  window.addEventListener('online', () => {
    useAppStore.getState().setConnectionStatus({ online: true });
    useAppStore.getState().checkConnectivity();
  });

  window.addEventListener('offline', () => {
    useAppStore.getState().setConnectionStatus({ 
      online: false,
      apiConnected: false,
      websocketConnected: false,
    });
  });

  // Fullscreen change
  document.addEventListener('fullscreenchange', () => {
    useAppStore.getState().setFullscreen(!!document.fullscreenElement);
  });

  // Performance observer
  if ('PerformanceObserver' in window) {
    const observer = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      entries.forEach((entry) => {
        if (entry.entryType === 'navigation') {
          const navEntry = entry as PerformanceNavigationTiming;
          useAppStore.getState().updatePerformanceMetrics({
            loadTime: navEntry.loadEventEnd - navEntry.navigationStart,
          });
        }
      });
    });
    observer.observe({ entryTypes: ['navigation'] });
  }
}

export default useAppStore;