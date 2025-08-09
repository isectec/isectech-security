/**
 * Offline Storage Management for iSECTECH Protect PWA
 * Handles IndexedDB operations and offline data synchronization
 */

interface OfflineNotification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  timestamp: Date;
  read: boolean;
  offline: boolean;
  actions?: Array<{
    action: string;
    label: string;
    primary?: boolean;
  }>;
}

interface QueuedAction {
  id: string;
  type: 'notification' | 'user-action' | 'analytics';
  endpoint: string;
  method: string;
  payload: any;
  headers?: Record<string, string>;
  timestamp: Date;
  retryCount: number;
  maxRetries: number;
}

interface UserPreference {
  key: string;
  value: any;
  timestamp: Date;
}

interface AnalyticsData {
  id: string;
  payload: any;
  timestamp: Date;
  synced: boolean;
}

const DB_NAME = 'isectech-protect-offline';
const DB_VERSION = 1;
const STORES = {
  NOTIFICATIONS: 'notifications',
  USER_PREFERENCES: 'user-preferences',
  OFFLINE_QUEUE: 'offline-queue',
  ANALYTICS: 'analytics',
} as const;

class OfflineStorageManager {
  private db: IDBDatabase | null = null;
  private initPromise: Promise<IDBDatabase> | null = null;

  constructor() {
    this.initPromise = this.initializeDB();
  }

  private async initializeDB(): Promise<IDBDatabase> {
    if (this.db) {
      return this.db;
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      
      request.onerror = () => {
        console.error('Failed to open IndexedDB:', request.error);
        reject(request.error);
      };
      
      request.onsuccess = () => {
        this.db = request.result;
        console.log('IndexedDB initialized successfully');
        resolve(this.db);
      };
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        // Create notifications store
        if (!db.objectStoreNames.contains(STORES.NOTIFICATIONS)) {
          const notificationStore = db.createObjectStore(STORES.NOTIFICATIONS, {
            keyPath: 'id',
          });
          notificationStore.createIndex('timestamp', 'timestamp');
          notificationStore.createIndex('type', 'type');
          notificationStore.createIndex('read', 'read');
        }
        
        // Create user preferences store
        if (!db.objectStoreNames.contains(STORES.USER_PREFERENCES)) {
          db.createObjectStore(STORES.USER_PREFERENCES, {
            keyPath: 'key',
          });
        }
        
        // Create offline queue store
        if (!db.objectStoreNames.contains(STORES.OFFLINE_QUEUE)) {
          const queueStore = db.createObjectStore(STORES.OFFLINE_QUEUE, {
            keyPath: 'id',
          });
          queueStore.createIndex('type', 'type');
          queueStore.createIndex('timestamp', 'timestamp');
          queueStore.createIndex('retryCount', 'retryCount');
        }
        
        // Create analytics store
        if (!db.objectStoreNames.contains(STORES.ANALYTICS)) {
          const analyticsStore = db.createObjectStore(STORES.ANALYTICS, {
            keyPath: 'id',
          });
          analyticsStore.createIndex('timestamp', 'timestamp');
          analyticsStore.createIndex('synced', 'synced');
        }
      };
    });
  }

  private async getDB(): Promise<IDBDatabase> {
    if (!this.initPromise) {
      this.initPromise = this.initializeDB();
    }
    return this.initPromise;
  }

  // Notification methods
  async storeNotification(notification: Omit<OfflineNotification, 'offline'>): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.NOTIFICATIONS], 'readwrite');
    const store = transaction.objectStore(STORES.NOTIFICATIONS);
    
    const offlineNotification: OfflineNotification = {
      ...notification,
      offline: true,
    };
    
    await new Promise<void>((resolve, reject) => {
      const request = store.put(offlineNotification);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    
    console.log('Notification stored offline:', notification.id);
  }

  async getNotifications(options: {
    limit?: number;
    filter?: 'unread' | 'read' | 'all';
    type?: OfflineNotification['type'];
  } = {}): Promise<OfflineNotification[]> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.NOTIFICATIONS], 'readonly');
    const store = transaction.objectStore(STORES.NOTIFICATIONS);
    const index = store.index('timestamp');
    
    return new Promise((resolve, reject) => {
      const notifications: OfflineNotification[] = [];
      const request = index.openCursor(null, 'prev'); // Newest first
      
      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        
        if (cursor && (!options.limit || notifications.length < options.limit)) {
          const notification = cursor.value as OfflineNotification;
          
          // Apply filters
          let include = true;
          
          if (options.filter === 'unread' && notification.read) {
            include = false;
          } else if (options.filter === 'read' && !notification.read) {
            include = false;
          }
          
          if (options.type && notification.type !== options.type) {
            include = false;
          }
          
          if (include) {
            notifications.push(notification);
          }
          
          cursor.continue();
        } else {
          resolve(notifications);
        }
      };
      
      request.onerror = () => reject(request.error);
    });
  }

  async markNotificationAsRead(notificationId: string): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.NOTIFICATIONS], 'readwrite');
    const store = transaction.objectStore(STORES.NOTIFICATIONS);
    
    const notification = await new Promise<OfflineNotification>((resolve, reject) => {
      const request = store.get(notificationId);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    
    if (notification) {
      notification.read = true;
      
      await new Promise<void>((resolve, reject) => {
        const request = store.put(notification);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      // Queue the action for sync when online
      await this.queueAction({
        type: 'user-action',
        endpoint: '/api/notifications/mark-read',
        method: 'POST',
        payload: { notificationId, read: true },
      });
    }
  }

  async deleteNotification(notificationId: string): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.NOTIFICATIONS], 'readwrite');
    const store = transaction.objectStore(STORES.NOTIFICATIONS);
    
    await new Promise<void>((resolve, reject) => {
      const request = store.delete(notificationId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    
    // Queue the action for sync when online
    await this.queueAction({
      type: 'user-action',
      endpoint: '/api/notifications/delete',
      method: 'DELETE',
      payload: { notificationId },
    });
    
    console.log('Notification deleted offline:', notificationId);
  }

  // User preferences methods
  async savePreference(key: string, value: any): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.USER_PREFERENCES], 'readwrite');
    const store = transaction.objectStore(STORES.USER_PREFERENCES);
    
    const preference: UserPreference = {
      key,
      value,
      timestamp: new Date(),
    };
    
    await new Promise<void>((resolve, reject) => {
      const request = store.put(preference);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    
    // Queue for sync
    await this.queueAction({
      type: 'user-action',
      endpoint: '/api/user/preferences',
      method: 'POST',
      payload: { key, value },
    });
  }

  async getPreference(key: string): Promise<any> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.USER_PREFERENCES], 'readonly');
    const store = transaction.objectStore(STORES.USER_PREFERENCES);
    
    return new Promise((resolve, reject) => {
      const request = store.get(key);
      request.onsuccess = () => {
        const result = request.result;
        resolve(result ? result.value : null);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async getAllPreferences(): Promise<Record<string, any>> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.USER_PREFERENCES], 'readonly');
    const store = transaction.objectStore(STORES.USER_PREFERENCES);
    
    return new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => {
        const preferences: Record<string, any> = {};
        request.result.forEach((pref: UserPreference) => {
          preferences[pref.key] = pref.value;
        });
        resolve(preferences);
      };
      request.onerror = () => reject(request.error);
    });
  }

  // Offline queue methods
  async queueAction(action: Omit<QueuedAction, 'id' | 'timestamp' | 'retryCount' | 'maxRetries'>): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    const queuedAction: QueuedAction = {
      ...action,
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      retryCount: 0,
      maxRetries: 3,
    };
    
    await new Promise<void>((resolve, reject) => {
      const request = store.add(queuedAction);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    
    // Register for background sync if available
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      try {
        const registration = await navigator.serviceWorker.ready;
        await registration.sync.register('user-actions-queue');
      } catch (error) {
        console.warn('Background sync registration failed:', error);
      }
    }
    
    console.log('Action queued for offline sync:', queuedAction.id);
  }

  async getQueuedActions(type?: QueuedAction['type']): Promise<QueuedAction[]> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readonly');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    if (type) {
      const index = store.index('type');
      return new Promise((resolve, reject) => {
        const request = index.getAll(type);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    } else {
      return new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    }
  }

  async removeQueuedAction(actionId: string): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    await new Promise<void>((resolve, reject) => {
      const request = store.delete(actionId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async incrementRetryCount(actionId: string): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    const action = await new Promise<QueuedAction>((resolve, reject) => {
      const request = store.get(actionId);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    
    if (action) {
      action.retryCount += 1;
      
      await new Promise<void>((resolve, reject) => {
        const request = store.put(action);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    }
  }

  // Analytics methods
  async storeAnalytics(data: any): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.ANALYTICS], 'readwrite');
    const store = transaction.objectStore(STORES.ANALYTICS);
    
    const analyticsData: AnalyticsData = {
      id: `analytics-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      payload: data,
      timestamp: new Date(),
      synced: false,
    };
    
    await new Promise<void>((resolve, reject) => {
      const request = store.add(analyticsData);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
    
    // Register for background sync if available
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      try {
        const registration = await navigator.serviceWorker.ready;
        await registration.sync.register('analytics-queue');
      } catch (error) {
        console.warn('Analytics sync registration failed:', error);
      }
    }
  }

  async getUnsyncedAnalytics(): Promise<AnalyticsData[]> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.ANALYTICS], 'readonly');
    const store = transaction.objectStore(STORES.ANALYTICS);
    const index = store.index('synced');
    
    return new Promise((resolve, reject) => {
      const request = index.getAll(false);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async markAnalyticsAsSynced(analyticsId: string): Promise<void> {
    const db = await this.getDB();
    const transaction = db.transaction([STORES.ANALYTICS], 'readwrite');
    const store = transaction.objectStore(STORES.ANALYTICS);
    
    const analyticsData = await new Promise<AnalyticsData>((resolve, reject) => {
      const request = store.get(analyticsId);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    
    if (analyticsData) {
      analyticsData.synced = true;
      
      await new Promise<void>((resolve, reject) => {
        const request = store.put(analyticsData);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    }
  }

  // Utility methods
  async clearAllData(): Promise<void> {
    const db = await this.getDB();
    const storeNames = Object.values(STORES);
    const transaction = db.transaction(storeNames, 'readwrite');
    
    const promises = storeNames.map(storeName => {
      return new Promise<void>((resolve, reject) => {
        const store = transaction.objectStore(storeName);
        const request = store.clear();
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    });
    
    await Promise.all(promises);
    console.log('All offline data cleared');
  }

  async getStorageUsage(): Promise<{
    notifications: number;
    preferences: number;
    queue: number;
    analytics: number;
    total: number;
  }> {
    const db = await this.getDB();
    const transaction = db.transaction(Object.values(STORES), 'readonly');
    
    const counts = await Promise.all(
      Object.values(STORES).map(async (storeName) => {
        const store = transaction.objectStore(storeName);
        return new Promise<number>((resolve, reject) => {
          const request = store.count();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
      })
    );
    
    return {
      notifications: counts[0],
      preferences: counts[1],
      queue: counts[2],
      analytics: counts[3],
      total: counts.reduce((sum, count) => sum + count, 0),
    };
  }

  // Cleanup old data
  async cleanupOldData(maxAge: number = 30 * 24 * 60 * 60 * 1000): Promise<void> {
    const cutoffDate = new Date(Date.now() - maxAge);
    const db = await this.getDB();
    
    // Clean up old notifications
    const notificationTransaction = db.transaction([STORES.NOTIFICATIONS], 'readwrite');
    const notificationStore = notificationTransaction.objectStore(STORES.NOTIFICATIONS);
    const notificationIndex = notificationStore.index('timestamp');
    
    await new Promise<void>((resolve, reject) => {
      const request = notificationIndex.openCursor(IDBKeyRange.upperBound(cutoffDate));
      
      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        } else {
          resolve();
        }
      };
      
      request.onerror = () => reject(request.error);
    });
    
    // Clean up old analytics data
    const analyticsTransaction = db.transaction([STORES.ANALYTICS], 'readwrite');
    const analyticsStore = analyticsTransaction.objectStore(STORES.ANALYTICS);
    const analyticsIndex = analyticsStore.index('timestamp');
    
    await new Promise<void>((resolve, reject) => {
      const request = analyticsIndex.openCursor(IDBKeyRange.upperBound(cutoffDate));
      
      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (cursor) {
          const data = cursor.value as AnalyticsData;
          if (data.synced) {
            cursor.delete();
          }
          cursor.continue();
        } else {
          resolve();
        }
      };
      
      request.onerror = () => reject(request.error);
    });
    
    console.log('Cleanup completed for data older than', cutoffDate);
  }
}

// Singleton instance
export const offlineStorage = new OfflineStorageManager();

export default offlineStorage;