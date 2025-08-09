/**
 * Dashboard Store for iSECTECH Protect
 * UI-specific state management for dashboard components
 */

import type { DashboardConfig, DashboardFilter, DashboardLayout, DashboardWidget, TimeRange } from '@/types';
import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';

interface DashboardState {
  // Dashboard configuration
  config: DashboardConfig;

  // UI state
  selectedTimeRange: TimeRange;
  activeFilters: DashboardFilter;
  selectedWidgets: DashboardWidget[];
  layout: DashboardLayout;

  // Dashboard-specific UI state
  widgetStates: Record<
    string,
    {
      isMinimized: boolean;
      isFullscreen: boolean;
      refreshInterval?: number;
      lastRefresh?: Date;
    }
  >;

  // Real-time updates
  realTimeEnabled: boolean;
  connectionStatus: 'connected' | 'disconnected' | 'connecting';
  lastDataUpdate: Date | null;

  // Performance metrics
  performanceMetrics: {
    renderTime: number;
    dataFetchTime: number;
    totalWidgets: number;
    activeQueries: number;
  };

  // Error handling
  errors: Record<
    string,
    {
      message: string;
      timestamp: Date;
      component: string;
    }
  >;

  // Loading states
  loadingStates: Record<string, boolean>;
}

interface DashboardActions {
  // Configuration management
  updateConfig: (config: Partial<DashboardConfig>) => void;
  resetConfig: () => void;

  // Time range and filters
  setTimeRange: (timeRange: TimeRange) => void;
  updateFilters: (filters: Partial<DashboardFilter>) => void;
  clearFilters: () => void;

  // Widget management
  addWidget: (widget: DashboardWidget) => void;
  removeWidget: (widgetId: string) => void;
  updateWidget: (widgetId: string, updates: Partial<DashboardWidget>) => void;
  reorderWidgets: (widgetIds: string[]) => void;

  // Widget state management
  toggleWidgetMinimize: (widgetId: string) => void;
  toggleWidgetFullscreen: (widgetId: string) => void;
  setWidgetRefreshInterval: (widgetId: string, interval: number) => void;
  refreshWidget: (widgetId: string) => void;
  refreshAllWidgets: () => void;

  // Layout management
  updateLayout: (layout: DashboardLayout) => void;
  resetLayout: () => void;

  // Real-time updates
  setRealTimeEnabled: (enabled: boolean) => void;
  updateConnectionStatus: (status: DashboardState['connectionStatus']) => void;
  markDataUpdated: () => void;

  // Performance tracking
  updatePerformanceMetrics: (metrics: Partial<DashboardState['performanceMetrics']>) => void;

  // Error handling
  setError: (component: string, error: string) => void;
  clearError: (component: string) => void;
  clearAllErrors: () => void;

  // Loading states
  setLoading: (component: string, loading: boolean) => void;
  clearLoading: (component: string) => void;
  clearAllLoading: () => void;

  // Bulk operations
  reset: () => void;
}

// Default configuration
const defaultConfig: DashboardConfig = {
  layout: 'grid',
  widgets: ['metrics', 'threatActivity', 'riskScore', 'assetHealth', 'compliance'],
  refreshInterval: 30,
  theme: 'dark',
  timeRange: '24h',
};

const defaultState: DashboardState = {
  config: defaultConfig,
  selectedTimeRange: '24h',
  activeFilters: {},
  selectedWidgets: [
    { id: 'metrics', type: 'metrics', position: { x: 0, y: 0 }, size: { width: 12, height: 4 } },
    { id: 'threatActivity', type: 'threatActivity', position: { x: 0, y: 4 }, size: { width: 6, height: 6 } },
    { id: 'riskScore', type: 'riskScore', position: { x: 6, y: 4 }, size: { width: 6, height: 6 } },
    { id: 'assetHealth', type: 'assetHealth', position: { x: 0, y: 10 }, size: { width: 6, height: 6 } },
    { id: 'compliance', type: 'compliance', position: { x: 6, y: 10 }, size: { width: 6, height: 6 } },
  ],
  layout: 'grid',
  widgetStates: {},
  realTimeEnabled: true,
  connectionStatus: 'disconnected',
  lastDataUpdate: null,
  performanceMetrics: {
    renderTime: 0,
    dataFetchTime: 0,
    totalWidgets: 0,
    activeQueries: 0,
  },
  errors: {},
  loadingStates: {},
};

export const useDashboardStore = create<DashboardState & DashboardActions>()(
  subscribeWithSelector((set, get) => ({
    ...defaultState,

    // Configuration management
    updateConfig: (config) => {
      set((state) => ({
        config: { ...state.config, ...config },
      }));
    },

    resetConfig: () => {
      set((state) => ({ ...state, config: defaultConfig }));
    },

    // Time range and filters
    setTimeRange: (timeRange) => {
      set((state) => ({ ...state, selectedTimeRange: timeRange }));
    },

    updateFilters: (filters) => {
      set((state) => ({
        activeFilters: { ...state.activeFilters, ...filters },
      }));
    },

    clearFilters: () => {
      set((state) => ({ ...state, activeFilters: {} }));
    },

    // Widget management
    addWidget: (widget) => {
      set((state) => ({
        selectedWidgets: [...state.selectedWidgets, widget],
        widgetStates: {
          ...state.widgetStates,
          [widget.id]: {
            isMinimized: false,
            isFullscreen: false,
          },
        },
      }));
    },

    removeWidget: (widgetId) => {
      set((state) => {
        const newWidgetStates = { ...state.widgetStates };
        delete newWidgetStates[widgetId];

        return {
          selectedWidgets: state.selectedWidgets.filter((w) => w.id !== widgetId),
          widgetStates: newWidgetStates,
        };
      });
    },

    updateWidget: (widgetId, updates) => {
      set((state) => ({
        selectedWidgets: state.selectedWidgets.map((widget) =>
          widget.id === widgetId ? { ...widget, ...updates } : widget
        ),
      }));
    },

    reorderWidgets: (widgetIds) => {
      set((state) => {
        const widgetMap = new Map(state.selectedWidgets.map((w) => [w.id, w]));
        const reorderedWidgets = widgetIds.map((id) => widgetMap.get(id)).filter(Boolean) as DashboardWidget[];
        return { selectedWidgets: reorderedWidgets };
      });
    },

    // Widget state management
    toggleWidgetMinimize: (widgetId) => {
      set((state) => ({
        widgetStates: {
          ...state.widgetStates,
          [widgetId]: {
            ...state.widgetStates[widgetId],
            isMinimized: !state.widgetStates[widgetId]?.isMinimized,
          },
        },
      }));
    },

    toggleWidgetFullscreen: (widgetId) => {
      set((state) => ({
        widgetStates: {
          ...state.widgetStates,
          [widgetId]: {
            ...state.widgetStates[widgetId],
            isFullscreen: !state.widgetStates[widgetId]?.isFullscreen,
          },
        },
      }));
    },

    setWidgetRefreshInterval: (widgetId, interval) => {
      set((state) => ({
        widgetStates: {
          ...state.widgetStates,
          [widgetId]: {
            ...state.widgetStates[widgetId],
            refreshInterval: interval,
          },
        },
      }));
    },

    refreshWidget: (widgetId) => {
      set((state) => ({
        widgetStates: {
          ...state.widgetStates,
          [widgetId]: {
            ...state.widgetStates[widgetId],
            lastRefresh: new Date(),
          },
        },
      }));
    },

    refreshAllWidgets: () => {
      const now = new Date();
      set((state) => {
        const updatedStates = { ...state.widgetStates };
        Object.keys(updatedStates).forEach((widgetId) => {
          updatedStates[widgetId] = {
            ...updatedStates[widgetId],
            lastRefresh: now,
          };
        });
        return { widgetStates: updatedStates };
      });
    },

    // Layout management
    updateLayout: (layout) => {
      set((state) => ({ ...state, layout }));
    },

    resetLayout: () => {
      set((state) => ({ ...state, layout: 'grid' }));
    },

    // Real-time updates
    setRealTimeEnabled: (enabled) => {
      set((state) => ({ ...state, realTimeEnabled: enabled }));
    },

    updateConnectionStatus: (status) => {
      set((state) => ({ ...state, connectionStatus: status }));
    },

    markDataUpdated: () => {
      set((state) => ({ ...state, lastDataUpdate: new Date() }));
    },

    // Performance tracking
    updatePerformanceMetrics: (metrics) => {
      set((state) => ({
        performanceMetrics: { ...state.performanceMetrics, ...metrics },
      }));
    },

    // Error handling
    setError: (component, error) => {
      set((state) => ({
        errors: {
          ...state.errors,
          [component]: {
            message: error,
            timestamp: new Date(),
            component,
          },
        },
      }));
    },

    clearError: (component) => {
      set((state) => {
        const newErrors = { ...state.errors };
        delete newErrors[component];
        return { errors: newErrors };
      });
    },

    clearAllErrors: () => {
      set((state) => ({ ...state, errors: {} }));
    },

    // Loading states
    setLoading: (component, loading) => {
      set((state) => ({
        loadingStates: {
          ...state.loadingStates,
          [component]: loading,
        },
      }));
    },

    clearLoading: (component) => {
      set((state) => {
        const newLoadingStates = { ...state.loadingStates };
        delete newLoadingStates[component];
        return { loadingStates: newLoadingStates };
      });
    },

    clearAllLoading: () => {
      set((state) => ({ ...state, loadingStates: {} }));
    },

    // Bulk operations
    reset: () => {
      set(defaultState);
    },
  }))
);

// Selectors for optimized re-renders
export const dashboardSelectors = {
  config: (state: DashboardState) => state.config,
  timeRange: (state: DashboardState) => state.selectedTimeRange,
  filters: (state: DashboardState) => state.activeFilters,
  widgets: (state: DashboardState) => state.selectedWidgets,
  layout: (state: DashboardState) => state.layout,
  isRealTimeEnabled: (state: DashboardState) => state.realTimeEnabled,
  connectionStatus: (state: DashboardState) => state.connectionStatus,
  errors: (state: DashboardState) => state.errors,
  loadingStates: (state: DashboardState) => state.loadingStates,
  performanceMetrics: (state: DashboardState) => state.performanceMetrics,

  // Computed selectors
  hasErrors: (state: DashboardState) => Object.keys(state.errors).length > 0,
  isLoading: (state: DashboardState) => Object.values(state.loadingStates).some(Boolean),
  getWidgetState: (widgetId: string) => (state: DashboardState) => state.widgetStates[widgetId],
  getErrorsForComponent: (component: string) => (state: DashboardState) =>
    Object.values(state.errors).filter((error) => error.component === component),
};

// Helper functions for dashboard management
export const dashboardHelpers = {
  // Create widget configuration
  createWidget: (type: string, id?: string): DashboardWidget => ({
    id: id || `${type}-${Date.now()}`,
    type: type as DashboardWidget['type'],
    position: { x: 0, y: 0 },
    size: { width: 6, height: 6 },
  }),

  // Calculate grid layout
  calculateOptimalLayout: (widgets: DashboardWidget[]): DashboardWidget[] => {
    // Simple auto-layout algorithm
    const columns = 12;
    let currentX = 0;
    let currentY = 0;
    let maxHeightInRow = 0;

    return widgets.map((widget) => {
      if (currentX + widget.size.width > columns) {
        currentX = 0;
        currentY += maxHeightInRow;
        maxHeightInRow = 0;
      }

      const positioned = {
        ...widget,
        position: { x: currentX, y: currentY },
      };

      currentX += widget.size.width;
      maxHeightInRow = Math.max(maxHeightInRow, widget.size.height);

      return positioned;
    });
  },

  // Validate dashboard configuration
  validateConfig: (config: Partial<DashboardConfig>): string[] => {
    const errors: string[] = [];

    if (config.refreshInterval && (config.refreshInterval < 5 || config.refreshInterval > 300)) {
      errors.push('Refresh interval must be between 5 and 300 seconds');
    }

    if (config.widgets && config.widgets.length === 0) {
      errors.push('Dashboard must have at least one widget');
    }

    return errors;
  },
};

// Development tools
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  (window as any).__DASHBOARD_STORE__ = useDashboardStore;
}
