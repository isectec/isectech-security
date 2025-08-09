/**
 * Background Sync Management for iSECTECH Protect PWA
 * Handles offline queue synchronization and background tasks
 */

import { offlineStorage } from './offline-storage';

interface SyncResult {
  success: boolean;
  syncedCount: number;
  failedCount: number;
  errors: string[];
}

interface SyncOptions {
  maxRetries?: number;
  retryDelay?: number;
  batchSize?: number;
  timeout?: number;
}

class BackgroundSyncManager {
  private syncInProgress = false;
  private syncCallbacks: Map<string, Array<(result: SyncResult) => void>> = new Map();
  private retryTimeouts: Map<string, NodeJS.Timeout> = new Map();

  constructor() {
    this.initializeEventListeners();
  }

  private initializeEventListeners() {
    // Listen for online/offline events
    window.addEventListener('online', () => {
      console.log('[Background Sync] Network restored, starting sync...');
      this.syncAll();
    });

    window.addEventListener('offline', () => {
      console.log('[Background Sync] Network lost, canceling pending syncs');
      this.cancelPendingSyncs();
    });

    // Listen for service worker messages
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.addEventListener('message', (event) => {
        const { type, payload } = event.data;
        
        if (type === 'SYNC_COMPLETED') {
          this.handleSyncCompleted(payload);
        } else if (type === 'SYNC_FAILED') {
          this.handleSyncFailed(payload);
        }
      });
    }

    // Register background sync if supported
    this.registerBackgroundSync();
  }

  private async registerBackgroundSync() {
    if (!('serviceWorker' in navigator) || !('sync' in window.ServiceWorkerRegistration.prototype)) {
      console.warn('[Background Sync] Background sync not supported');
      return;
    }

    try {
      const registration = await navigator.serviceWorker.ready;
      
      // Register different sync tags
      await registration.sync.register('notification-queue');
      await registration.sync.register('analytics-queue');
      await registration.sync.register('user-actions-queue');
      
      console.log('[Background Sync] Background sync registered successfully');
      
    } catch (error) {
      console.error('[Background Sync] Failed to register background sync:', error);
    }
  }

  // Main sync method - syncs all queues
  public async syncAll(options: SyncOptions = {}): Promise<SyncResult> {
    if (this.syncInProgress) {
      console.log('[Background Sync] Sync already in progress');
      return { success: false, syncedCount: 0, failedCount: 0, errors: ['Sync in progress'] };
    }

    if (!navigator.onLine) {
      console.log('[Background Sync] Device is offline, skipping sync');
      return { success: false, syncedCount: 0, failedCount: 0, errors: ['Device offline'] };
    }

    this.syncInProgress = true;
    const startTime = Date.now();
    
    try {
      console.log('[Background Sync] Starting complete sync...');
      
      // Sync all queues in parallel
      const [userActions, analytics, notifications] = await Promise.allSettled([
        this.syncUserActions(options),
        this.syncAnalytics(options),
        this.syncNotifications(options),
      ]);

      // Collect results
      const results = [userActions, analytics, notifications];
      const successResults = results.filter(r => r.status === 'fulfilled').map(r => r.value as SyncResult);
      const failureResults = results.filter(r => r.status === 'rejected').map(r => r.reason);

      const totalSynced = successResults.reduce((sum, r) => sum + r.syncedCount, 0);
      const totalFailed = successResults.reduce((sum, r) => sum + r.failedCount, 0);
      const allErrors = [
        ...successResults.flatMap(r => r.errors),
        ...failureResults.map(e => e.message || 'Unknown error'),
      ];

      const finalResult: SyncResult = {
        success: failureResults.length === 0 && totalFailed === 0,
        syncedCount: totalSynced,
        failedCount: totalFailed,
        errors: allErrors,
      };

      const duration = Date.now() - startTime;
      console.log(`[Background Sync] Complete sync finished in ${duration}ms:`, finalResult);

      // Notify callbacks
      this.notifyCallbacks('sync-all', finalResult);

      return finalResult;

    } catch (error) {
      const errorResult: SyncResult = {
        success: false,
        syncedCount: 0,
        failedCount: 0,
        errors: [error instanceof Error ? error.message : 'Unknown sync error'],
      };

      console.error('[Background Sync] Complete sync failed:', error);
      this.notifyCallbacks('sync-all', errorResult);

      return errorResult;

    } finally {
      this.syncInProgress = false;
    }
  }

  // Sync user actions queue
  public async syncUserActions(options: SyncOptions = {}): Promise<SyncResult> {
    const { maxRetries = 3, batchSize = 10, timeout = 30000 } = options;
    
    try {
      const queuedActions = await offlineStorage.getQueuedActions('user-action');
      
      if (queuedActions.length === 0) {
        return { success: true, syncedCount: 0, failedCount: 0, errors: [] };
      }

      console.log(`[Background Sync] Syncing ${queuedActions.length} user actions...`);

      let syncedCount = 0;
      let failedCount = 0;
      const errors: string[] = [];

      // Process in batches
      for (let i = 0; i < queuedActions.length; i += batchSize) {
        const batch = queuedActions.slice(i, i + batchSize);
        
        await Promise.all(
          batch.map(async (action) => {
            try {
              // Skip actions that have exceeded max retries
              if (action.retryCount >= maxRetries) {
                failedCount++;
                errors.push(`Action ${action.id} exceeded max retries`);
                await offlineStorage.removeQueuedAction(action.id);
                return;
              }

              const controller = new AbortController();
              const timeoutId = setTimeout(() => controller.abort(), timeout);

              const response = await fetch(action.endpoint, {
                method: action.method,
                headers: {
                  'Content-Type': 'application/json',
                  ...action.headers,
                },
                body: JSON.stringify(action.payload),
                signal: controller.signal,
              });

              clearTimeout(timeoutId);

              if (response.ok) {
                await offlineStorage.removeQueuedAction(action.id);
                syncedCount++;
                console.log(`[Background Sync] Synced user action: ${action.id}`);
              } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
              }

            } catch (error) {
              console.error(`[Background Sync] Failed to sync user action ${action.id}:`, error);
              
              // Increment retry count
              await offlineStorage.incrementRetryCount(action.id);
              
              if (action.retryCount + 1 >= maxRetries) {
                await offlineStorage.removeQueuedAction(action.id);
                failedCount++;
                errors.push(`Action ${action.id}: ${error instanceof Error ? error.message : 'Unknown error'}`);
              } else {
                // Schedule retry
                this.scheduleRetry(action.id, (action.retryCount + 1) * 5000); // Exponential backoff
              }
            }
          })
        );
      }

      return {
        success: failedCount === 0,
        syncedCount,
        failedCount,
        errors,
      };

    } catch (error) {
      console.error('[Background Sync] User actions sync failed:', error);
      return {
        success: false,
        syncedCount: 0,
        failedCount: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
      };
    }
  }

  // Sync analytics data
  public async syncAnalytics(options: SyncOptions = {}): Promise<SyncResult> {
    const { batchSize = 20, timeout = 15000 } = options;
    
    try {
      const unsyncedAnalytics = await offlineStorage.getUnsyncedAnalytics();
      
      if (unsyncedAnalytics.length === 0) {
        return { success: true, syncedCount: 0, failedCount: 0, errors: [] };
      }

      console.log(`[Background Sync] Syncing ${unsyncedAnalytics.length} analytics records...`);

      let syncedCount = 0;
      let failedCount = 0;
      const errors: string[] = [];

      // Process in batches
      for (let i = 0; i < unsyncedAnalytics.length; i += batchSize) {
        const batch = unsyncedAnalytics.slice(i, i + batchSize);
        
        // Send batch to analytics endpoint
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), timeout);

          const response = await fetch('/api/analytics/performance', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              batch: batch.map(item => item.payload),
              timestamp: Date.now(),
            }),
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          if (response.ok) {
            // Mark all in batch as synced
            await Promise.all(
              batch.map(item => offlineStorage.markAnalyticsAsSynced(item.id))
            );
            syncedCount += batch.length;
            console.log(`[Background Sync] Synced analytics batch of ${batch.length} records`);
          } else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }

        } catch (error) {
          console.error('[Background Sync] Failed to sync analytics batch:', error);
          failedCount += batch.length;
          errors.push(`Analytics batch: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

      return {
        success: failedCount === 0,
        syncedCount,
        failedCount,
        errors,
      };

    } catch (error) {
      console.error('[Background Sync] Analytics sync failed:', error);
      return {
        success: false,
        syncedCount: 0,
        failedCount: 0,
        errors: [error instanceof Error ? error.message : 'Unknown error'],
      };
    }
  }

  // Sync notifications (if needed)
  public async syncNotifications(options: SyncOptions = {}): Promise<SyncResult> {
    // This method can be used to sync notification read states or other notification-related data
    // For now, we'll just return success as notifications are primarily received, not sent
    return { success: true, syncedCount: 0, failedCount: 0, errors: [] };
  }

  // Schedule retry for failed sync
  private scheduleRetry(actionId: string, delay: number) {
    const existingTimeout = this.retryTimeouts.get(actionId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    const timeoutId = setTimeout(() => {
      this.retrySync(actionId);
      this.retryTimeouts.delete(actionId);
    }, delay);

    this.retryTimeouts.set(actionId, timeoutId);
    console.log(`[Background Sync] Scheduled retry for action ${actionId} in ${delay}ms`);
  }

  private async retrySync(actionId: string) {
    if (!navigator.onLine) {
      console.log(`[Background Sync] Device offline, postponing retry for ${actionId}`);
      return;
    }

    try {
      const actions = await offlineStorage.getQueuedActions('user-action');
      const action = actions.find(a => a.id === actionId);
      
      if (action) {
        console.log(`[Background Sync] Retrying sync for action: ${actionId}`);
        await this.syncUserActions({ batchSize: 1 });
      }

    } catch (error) {
      console.error(`[Background Sync] Retry failed for action ${actionId}:`, error);
    }
  }

  // Cancel pending sync operations
  private cancelPendingSyncs() {
    // Clear retry timeouts
    this.retryTimeouts.forEach((timeoutId) => {
      clearTimeout(timeoutId);
    });
    this.retryTimeouts.clear();

    console.log('[Background Sync] Canceled pending sync operations');
  }

  // Event handling for service worker messages
  private handleSyncCompleted(payload: any) {
    console.log('[Background Sync] Service worker sync completed:', payload);
    this.notifyCallbacks('service-worker-sync', {
      success: true,
      syncedCount: payload.syncedCount || 0,
      failedCount: 0,
      errors: [],
    });
  }

  private handleSyncFailed(payload: any) {
    console.error('[Background Sync] Service worker sync failed:', payload);
    this.notifyCallbacks('service-worker-sync', {
      success: false,
      syncedCount: 0,
      failedCount: payload.failedCount || 1,
      errors: [payload.error || 'Service worker sync failed'],
    });
  }

  // Callback management
  public onSyncComplete(tag: string, callback: (result: SyncResult) => void) {
    if (!this.syncCallbacks.has(tag)) {
      this.syncCallbacks.set(tag, []);
    }
    this.syncCallbacks.get(tag)!.push(callback);
  }

  public offSyncComplete(tag: string, callback: (result: SyncResult) => void) {
    const callbacks = this.syncCallbacks.get(tag);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  private notifyCallbacks(tag: string, result: SyncResult) {
    const callbacks = this.syncCallbacks.get(tag);
    if (callbacks) {
      callbacks.forEach(callback => {
        try {
          callback(result);
        } catch (error) {
          console.error('[Background Sync] Callback error:', error);
        }
      });
    }
  }

  // Public utility methods
  public async getQueueStatus() {
    try {
      const [userActions, analytics, storageUsage] = await Promise.all([
        offlineStorage.getQueuedActions('user-action'),
        offlineStorage.getUnsyncedAnalytics(),
        offlineStorage.getStorageUsage(),
      ]);

      return {
        userActions: userActions.length,
        analytics: analytics.length,
        totalPending: userActions.length + analytics.length,
        storageUsage,
        lastSync: localStorage.getItem('last-sync-timestamp'),
      };

    } catch (error) {
      console.error('[Background Sync] Failed to get queue status:', error);
      return null;
    }
  }

  public async forceSyncNow(): Promise<SyncResult> {
    if (this.syncInProgress) {
      console.log('[Background Sync] Force sync requested but sync already in progress');
      return { success: false, syncedCount: 0, failedCount: 0, errors: ['Sync in progress'] };
    }

    console.log('[Background Sync] Force sync requested by user');
    const result = await this.syncAll({ maxRetries: 1, batchSize: 5, timeout: 10000 });
    
    if (result.success) {
      localStorage.setItem('last-sync-timestamp', new Date().toISOString());
    }
    
    return result;
  }
}

// Singleton instance
export const backgroundSync = new BackgroundSyncManager();

// Export types for use in other modules
export type { SyncResult, SyncOptions };

export default backgroundSync;