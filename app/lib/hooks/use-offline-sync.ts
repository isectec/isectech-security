/**
 * Offline Sync Hook for iSECTECH Protect PWA
 * React hook for managing offline data synchronization
 */

'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { backgroundSync, type SyncResult } from '@/lib/mobile/background-sync';
import { offlineStorage } from '@/lib/mobile/offline-storage';
import { useOffline } from './use-offline';

interface OfflineSyncState {
  isSyncing: boolean;
  lastSyncTime: Date | null;
  pendingCount: number;
  syncResult: SyncResult | null;
  error: string | null;
  queueStatus: {
    userActions: number;
    analytics: number;
    totalPending: number;
    storageUsage: {
      notifications: number;
      preferences: number;
      queue: number;
      analytics: number;
      total: number;
    };
  } | null;
}

interface OfflineSyncHookReturn extends OfflineSyncState {
  sync: () => Promise<SyncResult>;
  clearError: () => void;
  refreshQueueStatus: () => Promise<void>;
  storeNotificationOffline: (notification: any) => Promise<void>;
  getOfflineNotifications: (options?: any) => Promise<any[]>;
  markNotificationReadOffline: (id: string) => Promise<void>;
  deleteNotificationOffline: (id: string) => Promise<void>;
  savePreferenceOffline: (key: string, value: any) => Promise<void>;
  getPreferenceOffline: (key: string) => Promise<any>;
  queueAction: (action: any) => Promise<void>;
  clearOfflineData: () => Promise<void>;
}

export function useOfflineSync(): OfflineSyncHookReturn {
  const [state, setState] = useState<OfflineSyncState>({
    isSyncing: false,
    lastSyncTime: null,
    pendingCount: 0,
    syncResult: null,
    error: null,
    queueStatus: null,
  });

  const { isOnline, retryWhenOnline } = useOffline();
  const syncCallbackRef = useRef<((result: SyncResult) => void) | null>(null);

  // Initialize sync callback
  useEffect(() => {
    const handleSyncComplete = (result: SyncResult) => {
      setState(prev => ({
        ...prev,
        isSyncing: false,
        lastSyncTime: new Date(),
        syncResult: result,
        error: result.success ? null : result.errors.join(', '),
      }));

      // Refresh queue status after sync
      refreshQueueStatus();
    };

    syncCallbackRef.current = handleSyncComplete;
    backgroundSync.onSyncComplete('sync-all', handleSyncComplete);

    return () => {
      if (syncCallbackRef.current) {
        backgroundSync.offSyncComplete('sync-all', syncCallbackRef.current);
      }
    };
  }, []);

  // Load initial queue status
  useEffect(() => {
    refreshQueueStatus();
  }, []);

  // Auto-sync when coming back online
  useEffect(() => {
    if (isOnline && state.pendingCount > 0) {
      console.log('[Offline Sync Hook] Device back online, auto-syncing...');
      sync();
    }
  }, [isOnline, state.pendingCount]);

  const refreshQueueStatus = useCallback(async () => {
    try {
      const status = await backgroundSync.getQueueStatus();
      
      if (status) {
        setState(prev => ({
          ...prev,
          pendingCount: status.totalPending,
          queueStatus: status,
          lastSyncTime: status.lastSync ? new Date(status.lastSync) : prev.lastSyncTime,
        }));
      }
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to refresh queue status:', error);
    }
  }, []);

  const sync = useCallback(async (): Promise<SyncResult> => {
    if (state.isSyncing) {
      console.log('[Offline Sync Hook] Sync already in progress');
      return { success: false, syncedCount: 0, failedCount: 0, errors: ['Sync in progress'] };
    }

    setState(prev => ({
      ...prev,
      isSyncing: true,
      error: null,
      syncResult: null,
    }));

    try {
      let result: SyncResult;

      if (isOnline) {
        result = await backgroundSync.forceSyncNow();
      } else {
        console.log('[Offline Sync Hook] Device offline, queuing for later sync');
        result = await retryWhenOnline(() => backgroundSync.forceSyncNow());
      }

      setState(prev => ({
        ...prev,
        isSyncing: false,
        lastSyncTime: new Date(),
        syncResult: result,
        error: result.success ? null : result.errors.join(', '),
      }));

      await refreshQueueStatus();
      return result;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown sync error';
      const errorResult: SyncResult = {
        success: false,
        syncedCount: 0,
        failedCount: 0,
        errors: [errorMessage],
      };

      setState(prev => ({
        ...prev,
        isSyncing: false,
        syncResult: errorResult,
        error: errorMessage,
      }));

      return errorResult;
    }
  }, [state.isSyncing, isOnline, retryWhenOnline, refreshQueueStatus]);

  const clearError = useCallback(() => {
    setState(prev => ({
      ...prev,
      error: null,
    }));
  }, []);

  // Offline notification methods
  const storeNotificationOffline = useCallback(async (notification: any) => {
    try {
      await offlineStorage.storeNotification({
        id: notification.id || `offline-${Date.now()}`,
        type: notification.type || 'info',
        title: notification.title,
        message: notification.message,
        timestamp: notification.timestamp ? new Date(notification.timestamp) : new Date(),
        read: notification.read || false,
        actions: notification.actions,
      });

      await refreshQueueStatus();
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to store notification offline:', error);
      throw error;
    }
  }, [refreshQueueStatus]);

  const getOfflineNotifications = useCallback(async (options: any = {}) => {
    try {
      return await offlineStorage.getNotifications(options);
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to get offline notifications:', error);
      throw error;
    }
  }, []);

  const markNotificationReadOffline = useCallback(async (id: string) => {
    try {
      await offlineStorage.markNotificationAsRead(id);
      await refreshQueueStatus();
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to mark notification read offline:', error);
      throw error;
    }
  }, [refreshQueueStatus]);

  const deleteNotificationOffline = useCallback(async (id: string) => {
    try {
      await offlineStorage.deleteNotification(id);
      await refreshQueueStatus();
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to delete notification offline:', error);
      throw error;
    }
  }, [refreshQueueStatus]);

  // User preferences methods
  const savePreferenceOffline = useCallback(async (key: string, value: any) => {
    try {
      await offlineStorage.savePreference(key, value);
      await refreshQueueStatus();
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to save preference offline:', error);
      throw error;
    }
  }, [refreshQueueStatus]);

  const getPreferenceOffline = useCallback(async (key: string) => {
    try {
      return await offlineStorage.getPreference(key);
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to get preference offline:', error);
      throw error;
    }
  }, []);

  // Queue action method
  const queueAction = useCallback(async (action: any) => {
    try {
      await offlineStorage.queueAction(action);
      await refreshQueueStatus();
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to queue action:', error);
      throw error;
    }
  }, [refreshQueueStatus]);

  // Clear offline data method
  const clearOfflineData = useCallback(async () => {
    try {
      await offlineStorage.clearAllData();
      await refreshQueueStatus();
    } catch (error) {
      console.error('[Offline Sync Hook] Failed to clear offline data:', error);
      throw error;
    }
  }, [refreshQueueStatus]);

  return {
    ...state,
    sync,
    clearError,
    refreshQueueStatus,
    storeNotificationOffline,
    getOfflineNotifications,
    markNotificationReadOffline,
    deleteNotificationOffline,
    savePreferenceOffline,
    getPreferenceOffline,
    queueAction,
    clearOfflineData,
  };
}

export default useOfflineSync;