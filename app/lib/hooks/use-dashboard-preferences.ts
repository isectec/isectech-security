'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { debounce } from 'lodash';

interface DashboardPreferences {
  layout: 'compact' | 'detailed' | 'executive';
  refreshInterval: number;
  theme: 'light' | 'dark' | 'auto';
  mobileOptimized: boolean;
  widgets: WidgetPreference[];
  notifications: NotificationPreferences;
  performance: PerformancePreferences;
  accessibility: AccessibilityPreferences;
  customization: CustomizationPreferences;
}

interface WidgetPreference {
  id: string;
  visible: boolean;
  position: { x: number; y: number; w: number; h: number };
  settings: WidgetSettings;
  customTitle?: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  collapsed?: boolean;
}

interface WidgetSettings {
  showTrends: boolean;
  showConfidenceScore: boolean;
  compactView: boolean;
  alertThreshold?: number;
  refreshRate?: number;
  dataPoints?: number;
  colorScheme: 'default' | 'executive' | 'high-contrast';
  chartType?: 'line' | 'bar' | 'area' | 'pie';
  timeRange?: '1h' | '24h' | '7d' | '30d' | '90d';
}

interface NotificationPreferences {
  enabled: boolean;
  criticalAlerts: boolean;
  executiveBriefings: boolean;
  complianceUpdates: boolean;
  threatAlerts: boolean;
  frequency: 'realtime' | 'hourly' | 'daily' | 'weekly';
  quietHours: {
    enabled: boolean;
    start: string;
    end: string;
  };
  channels: {
    email: boolean;
    sms: boolean;
    inApp: boolean;
    slack: boolean;
  };
}

interface PerformancePreferences {
  enableAnimations: boolean;
  dataCaching: boolean;
  backgroundRefresh: boolean;
  lowBandwidthMode: boolean;
  preloadWidgets: boolean;
  maxCacheSize: number;
  compressionEnabled: boolean;
  prefetchData: boolean;
}

interface AccessibilityPreferences {
  highContrast: boolean;
  largeText: boolean;
  reducedMotion: boolean;
  screenReaderOptimized: boolean;
  keyboardNavigation: boolean;
  focusIndicators: boolean;
  alternativeText: boolean;
}

interface CustomizationPreferences {
  savedViews: SavedView[];
  defaultView: string;
  quickFilters: QuickFilter[];
  exportFormats: string[];
  favoriteMetrics: string[];
  customColors: Record<string, string>;
  dashboardLayouts: DashboardLayout[];
}

interface SavedView {
  id: string;
  name: string;
  description?: string;
  isDefault: boolean;
  preferences: Partial<DashboardPreferences>;
  createdAt: Date;
  lastUsed: Date;
}

interface QuickFilter {
  id: string;
  name: string;
  filters: Record<string, any>;
  icon?: string;
  color?: string;
}

interface DashboardLayout {
  id: string;
  name: string;
  widgets: WidgetPreference[];
  gridSize: { cols: number; rows: number };
  breakpoints: Record<string, { cols: number; rows: number }>;
}

export interface UseDashboardPreferencesOptions {
  userId: string;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  tenantId: string;
  autoSave?: boolean;
  saveDelay?: number;
}

export interface UseDashboardPreferencesReturn {
  preferences: DashboardPreferences;
  updatePreferences: (updates: Partial<DashboardPreferences>) => Promise<void>;
  resetPreferences: () => Promise<void>;
  saveView: (view: Omit<SavedView, 'id' | 'createdAt' | 'lastUsed'>) => Promise<string>;
  loadView: (viewId: string) => Promise<void>;
  deleteView: (viewId: string) => Promise<void>;
  getSavedViews: () => SavedView[];
  exportPreferences: () => string;
  importPreferences: (data: string) => Promise<void>;
  isLoading: boolean;
  hasUnsavedChanges: boolean;
  lastSaved: Date | null;
  error: Error | null;
}

const DEFAULT_PREFERENCES: DashboardPreferences = {
  layout: 'executive',
  refreshInterval: 30000,
  theme: 'auto',
  mobileOptimized: true,
  widgets: [
    {
      id: 'security-posture',
      visible: true,
      position: { x: 0, y: 0, w: 3, h: 2 },
      settings: {
        showTrends: true,
        showConfidenceScore: true,
        compactView: false,
        colorScheme: 'executive',
        chartType: 'area',
        timeRange: '30d'
      },
      priority: 'critical'
    },
    {
      id: 'threat-landscape',
      visible: true,
      position: { x: 3, y: 0, w: 3, h: 2 },
      settings: {
        showTrends: true,
        showConfidenceScore: true,
        compactView: false,
        colorScheme: 'executive',
        chartType: 'bar',
        timeRange: '7d'
      },
      priority: 'high'
    },
    {
      id: 'compliance-status',
      visible: true,
      position: { x: 6, y: 0, w: 3, h: 2 },
      settings: {
        showTrends: false,
        showConfidenceScore: false,
        compactView: false,
        colorScheme: 'executive',
        chartType: 'pie'
      },
      priority: 'critical'
    },
    {
      id: 'roi-metrics',
      visible: true,
      position: { x: 9, y: 0, w: 3, h: 2 },
      settings: {
        showTrends: true,
        showConfidenceScore: false,
        compactView: false,
        colorScheme: 'executive',
        chartType: 'line',
        timeRange: '90d'
      },
      priority: 'high'
    }
  ],
  notifications: {
    enabled: true,
    criticalAlerts: true,
    executiveBriefings: true,
    complianceUpdates: true,
    threatAlerts: true,
    frequency: 'hourly',
    quietHours: {
      enabled: true,
      start: '22:00',
      end: '06:00'
    },
    channels: {
      email: true,
      sms: false,
      inApp: true,
      slack: false
    }
  },
  performance: {
    enableAnimations: true,
    dataCaching: true,
    backgroundRefresh: true,
    lowBandwidthMode: false,
    preloadWidgets: true,
    maxCacheSize: 100,
    compressionEnabled: true,
    prefetchData: true
  },
  accessibility: {
    highContrast: false,
    largeText: false,
    reducedMotion: false,
    screenReaderOptimized: false,
    keyboardNavigation: true,
    focusIndicators: true,
    alternativeText: true
  },
  customization: {
    savedViews: [],
    defaultView: 'executive-default',
    quickFilters: [
      {
        id: 'last-24h',
        name: 'Last 24 Hours',
        filters: { timeRange: '24h' }
      },
      {
        id: 'high-severity',
        name: 'High Severity Only',
        filters: { minSeverity: 'high' }
      },
      {
        id: 'compliance-issues',
        name: 'Compliance Issues',
        filters: { hasComplianceIssues: true }
      }
    ],
    exportFormats: ['pdf', 'excel'],
    favoriteMetrics: ['security-posture', 'threat-landscape', 'compliance-status'],
    customColors: {},
    dashboardLayouts: []
  }
};

// Role-based preference overrides
const ROLE_PREFERENCES: Record<string, Partial<DashboardPreferences>> = {
  board_member: {
    layout: 'compact',
    widgets: [
      {
        id: 'security-posture',
        visible: true,
        position: { x: 0, y: 0, w: 6, h: 3 },
        settings: {
          showTrends: false,
          showConfidenceScore: false,
          compactView: true,
          colorScheme: 'executive',
          chartType: 'pie'
        },
        priority: 'critical'
      },
      {
        id: 'compliance-status',
        visible: true,
        position: { x: 6, y: 0, w: 6, h: 3 },
        settings: {
          showTrends: false,
          showConfidenceScore: false,
          compactView: true,
          colorScheme: 'executive',
          chartType: 'bar'
        },
        priority: 'critical'
      }
    ],
    notifications: {
      ...DEFAULT_PREFERENCES.notifications,
      frequency: 'daily',
      threatAlerts: false,
      complianceUpdates: true
    }
  },
  executive_assistant: {
    layout: 'detailed',
    notifications: {
      ...DEFAULT_PREFERENCES.notifications,
      frequency: 'hourly',
      criticalAlerts: true,
      executiveBriefings: true
    },
    performance: {
      ...DEFAULT_PREFERENCES.performance,
      enableAnimations: false,
      lowBandwidthMode: true
    }
  }
};

export const useDashboardPreferences = (
  options: UseDashboardPreferencesOptions
): UseDashboardPreferencesReturn => {
  const {
    userId,
    userRole,
    tenantId,
    autoSave = true,
    saveDelay = 1000
  } = options;

  const [preferences, setPreferences] = useState<DashboardPreferences>(
    () => getRoleBasedDefaults(userRole)
  );
  const [isLoading, setIsLoading] = useState(true);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);
  const [error, setError] = useState<Error | null>(null);

  const saveTimeoutRef = useRef<NodeJS.Timeout>();
  const initialLoadRef = useRef(false);

  // Debounced save function
  const debouncedSave = useCallback(
    debounce(async (prefs: DashboardPreferences) => {
      try {
        await savePreferencesToStorage(userId, tenantId, prefs);
        setLastSaved(new Date());
        setHasUnsavedChanges(false);
        setError(null);
      } catch (err) {
        setError(err as Error);
      }
    }, saveDelay),
    [userId, tenantId, saveDelay]
  );

  // Load preferences on mount
  useEffect(() => {
    const loadPreferences = async () => {
      if (initialLoadRef.current) return;
      
      setIsLoading(true);
      try {
        const savedPrefs = await loadPreferencesFromStorage(userId, tenantId);
        if (savedPrefs) {
          const mergedPrefs = mergeWithDefaults(savedPrefs, userRole);
          setPreferences(mergedPrefs);
        }
        setError(null);
      } catch (err) {
        setError(err as Error);
        // Fall back to role-based defaults on error
        setPreferences(getRoleBasedDefaults(userRole));
      } finally {
        setIsLoading(false);
        initialLoadRef.current = true;
      }
    };

    loadPreferences();
  }, [userId, tenantId, userRole]);

  // Auto-save when preferences change
  useEffect(() => {
    if (!initialLoadRef.current || !autoSave) return;

    setHasUnsavedChanges(true);
    debouncedSave(preferences);
  }, [preferences, autoSave, debouncedSave]);

  const updatePreferences = useCallback(async (updates: Partial<DashboardPreferences>) => {
    setPreferences(prev => {
      const updated = deepMerge(prev, updates);
      return validatePreferences(updated, userRole);
    });
  }, [userRole]);

  const resetPreferences = useCallback(async () => {
    const defaultPrefs = getRoleBasedDefaults(userRole);
    setPreferences(defaultPrefs);
    
    try {
      await clearPreferencesFromStorage(userId, tenantId);
      setLastSaved(new Date());
      setHasUnsavedChanges(false);
      setError(null);
    } catch (err) {
      setError(err as Error);
    }
  }, [userId, tenantId, userRole]);

  const saveView = useCallback(async (view: Omit<SavedView, 'id' | 'createdAt' | 'lastUsed'>) => {
    const newView: SavedView = {
      ...view,
      id: generateId(),
      createdAt: new Date(),
      lastUsed: new Date()
    };

    await updatePreferences({
      customization: {
        ...preferences.customization,
        savedViews: [...preferences.customization.savedViews, newView]
      }
    });

    return newView.id;
  }, [preferences.customization, updatePreferences]);

  const loadView = useCallback(async (viewId: string) => {
    const view = preferences.customization.savedViews.find(v => v.id === viewId);
    if (!view) throw new Error('View not found');

    if (view.preferences) {
      await updatePreferences(view.preferences);
    }

    // Update last used timestamp
    const updatedViews = preferences.customization.savedViews.map(v =>
      v.id === viewId ? { ...v, lastUsed: new Date() } : v
    );

    await updatePreferences({
      customization: {
        ...preferences.customization,
        savedViews: updatedViews
      }
    });
  }, [preferences.customization, updatePreferences]);

  const deleteView = useCallback(async (viewId: string) => {
    const updatedViews = preferences.customization.savedViews.filter(v => v.id !== viewId);
    
    await updatePreferences({
      customization: {
        ...preferences.customization,
        savedViews: updatedViews,
        defaultView: preferences.customization.defaultView === viewId 
          ? 'executive-default' 
          : preferences.customization.defaultView
      }
    });
  }, [preferences.customization, updatePreferences]);

  const getSavedViews = useCallback(() => {
    return [...preferences.customization.savedViews].sort(
      (a, b) => b.lastUsed.getTime() - a.lastUsed.getTime()
    );
  }, [preferences.customization.savedViews]);

  const exportPreferences = useCallback(() => {
    const exportData = {
      version: '1.0',
      userId,
      userRole,
      tenantId,
      preferences,
      exportedAt: new Date().toISOString()
    };
    return JSON.stringify(exportData, null, 2);
  }, [userId, userRole, tenantId, preferences]);

  const importPreferences = useCallback(async (data: string) => {
    try {
      const importData = JSON.parse(data);
      
      // Validate import data
      if (!importData.preferences || !importData.version) {
        throw new Error('Invalid import data format');
      }

      const validated = validatePreferences(importData.preferences, userRole);
      await updatePreferences(validated);
    } catch (err) {
      throw new Error('Failed to import preferences: ' + (err as Error).message);
    }
  }, [userRole, updatePreferences]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
      debouncedSave.cancel();
    };
  }, [debouncedSave]);

  return {
    preferences,
    updatePreferences,
    resetPreferences,
    saveView,
    loadView,
    deleteView,
    getSavedViews,
    exportPreferences,
    importPreferences,
    isLoading,
    hasUnsavedChanges,
    lastSaved,
    error
  };
};

// Helper functions
function getRoleBasedDefaults(userRole: string): DashboardPreferences {
  const roleOverrides = ROLE_PREFERENCES[userRole] || {};
  return deepMerge(DEFAULT_PREFERENCES, roleOverrides);
}

function mergeWithDefaults(saved: Partial<DashboardPreferences>, userRole: string): DashboardPreferences {
  const defaults = getRoleBasedDefaults(userRole);
  return deepMerge(defaults, saved);
}

function validatePreferences(prefs: DashboardPreferences, userRole: string): DashboardPreferences {
  // Apply role-based restrictions
  const validated = { ...prefs };

  if (userRole === 'board_member') {
    // Board members have limited customization
    validated.layout = 'compact';
    validated.widgets = validated.widgets.map(widget => ({
      ...widget,
      settings: {
        ...widget.settings,
        showConfidenceScore: false,
        compactView: true
      }
    }));
  }

  if (userRole === 'executive_assistant') {
    // Executive assistants have limited notification permissions
    validated.notifications = {
      ...validated.notifications,
      criticalAlerts: true,
      threatAlerts: false
    };
  }

  return validated;
}

async function savePreferencesToStorage(userId: string, tenantId: string, preferences: DashboardPreferences): Promise<void> {
  const key = `dashboard_preferences_${tenantId}_${userId}`;
  const data = {
    preferences,
    version: '1.0',
    savedAt: new Date().toISOString()
  };
  
  try {
    // Use localStorage for now - in production this would be an API call
    localStorage.setItem(key, JSON.stringify(data));
  } catch (err) {
    throw new Error('Failed to save preferences: ' + (err as Error).message);
  }
}

async function loadPreferencesFromStorage(userId: string, tenantId: string): Promise<Partial<DashboardPreferences> | null> {
  const key = `dashboard_preferences_${tenantId}_${userId}`;
  
  try {
    const data = localStorage.getItem(key);
    if (!data) return null;
    
    const parsed = JSON.parse(data);
    return parsed.preferences;
  } catch (err) {
    console.warn('Failed to load preferences:', err);
    return null;
  }
}

async function clearPreferencesFromStorage(userId: string, tenantId: string): Promise<void> {
  const key = `dashboard_preferences_${tenantId}_${userId}`;
  localStorage.removeItem(key);
}

function deepMerge(target: any, source: any): any {
  if (!source) return target;
  
  const result = { ...target };
  
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  
  return result;
}

function generateId(): string {
  return `view_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

export default useDashboardPreferences;