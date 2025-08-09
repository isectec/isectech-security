/**
 * iSECTECH Protect PWA Service Worker
 * Provides offline functionality, background sync, and push notification handling
 */

const CACHE_VERSION = 'v1.2.0';
const APP_CACHE = `isectech-protect-app-${CACHE_VERSION}`;
const DATA_CACHE = `isectech-protect-data-${CACHE_VERSION}`;
const IMAGE_CACHE = `isectech-protect-images-${CACHE_VERSION}`;
const API_CACHE = `isectech-protect-api-${CACHE_VERSION}`;

// Critical resources to cache immediately
const CRITICAL_RESOURCES = [
  '/',
  '/mobile',
  '/mobile/notifications',
  '/manifest.json',
  '/offline.html',
];

// API endpoints that should be cached
const CACHEABLE_APIS = [
  '/api/health',
  '/api/notifications/test',
  '/api/analytics/performance',
];

// Background sync tags
const SYNC_TAGS = {
  NOTIFICATION_QUEUE: 'notification-queue',
  ANALYTICS_QUEUE: 'analytics-queue',
  USER_ACTIONS: 'user-actions-queue',
};

// IndexedDB configuration for offline storage
const DB_NAME = 'isectech-protect-offline';
const DB_VERSION = 1;
const STORES = {
  NOTIFICATIONS: 'notifications',
  USER_PREFERENCES: 'user-preferences',
  OFFLINE_QUEUE: 'offline-queue',
  ANALYTICS: 'analytics',
};

// Install event - cache critical resources
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Install event');
  
  event.waitUntil(
    (async () => {
      try {
        // Cache critical app resources
        const appCache = await caches.open(APP_CACHE);
        await appCache.addAll(CRITICAL_RESOURCES);
        
        // Initialize IndexedDB
        await initializeDB();
        
        console.log('[Service Worker] Critical resources cached successfully');
        
        // Skip waiting to activate immediately
        self.skipWaiting();
      } catch (error) {
        console.error('[Service Worker] Install failed:', error);
      }
    })()
  );
});

// Activate event - cleanup old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activate event');
  
  event.waitUntil(
    (async () => {
      try {
        // Clean up old caches
        const cacheNames = await caches.keys();
        const oldCaches = cacheNames.filter(name => 
          name.startsWith('isectech-protect-') && 
          !name.includes(CACHE_VERSION)
        );
        
        await Promise.all(
          oldCaches.map(cacheName => caches.delete(cacheName))
        );
        
        console.log(`[Service Worker] Cleaned up ${oldCaches.length} old caches`);
        
        // Take control of all clients immediately
        await self.clients.claim();
        
        // Notify clients about the update
        const clients = await self.clients.matchAll();
        clients.forEach(client => {
          client.postMessage({
            type: 'SERVICE_WORKER_ACTIVATED',
            version: CACHE_VERSION,
          });
        });
        
      } catch (error) {
        console.error('[Service Worker] Activation failed:', error);
      }
    })()
  );
});

// Fetch event - handle network requests with caching strategy
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests for caching
  if (request.method !== 'GET') {
    return;
  }
  
  // Skip chrome-extension and other non-http requests
  if (!url.protocol.startsWith('http')) {
    return;
  }
  
  event.respondWith(handleFetch(request));
});

// Handle fetch requests with appropriate caching strategy
async function handleFetch(request) {
  const url = new URL(request.url);
  
  try {
    // API requests - Network First with fallback
    if (url.pathname.startsWith('/api/')) {
      return await networkFirstStrategy(request, API_CACHE);
    }
    
    // Images - Cache First
    if (request.destination === 'image') {
      return await cacheFirstStrategy(request, IMAGE_CACHE);
    }
    
    // Static assets - Cache First
    if (url.pathname.includes('/_next/static/') || 
        url.pathname.includes('/static/') ||
        url.pathname.match(/\.(js|css|woff2?|png|jpg|jpeg|gif|webp|svg|ico)$/)) {
      return await cacheFirstStrategy(request, APP_CACHE);
    }
    
    // App shell - Network First with app cache fallback
    return await networkFirstStrategy(request, APP_CACHE, '/offline.html');
    
  } catch (error) {
    console.error('[Service Worker] Fetch error:', error);
    
    // Return offline page for navigation requests
    if (request.mode === 'navigate') {
      const cache = await caches.open(APP_CACHE);
      const offlinePage = await cache.match('/offline.html');
      return offlinePage || new Response('Offline', { status: 503 });
    }
    
    return new Response('Network error', { status: 503 });
  }
}

// Network First strategy - try network, fallback to cache
async function networkFirstStrategy(request, cacheName, fallbackUrl = null) {
  const cache = await caches.open(cacheName);
  
  try {
    // Try network first
    const networkResponse = await fetch(request);
    
    // Cache successful responses
    if (networkResponse.ok) {
      // Clone the response before caching
      const responseClone = networkResponse.clone();
      await cache.put(request, responseClone);
    }
    
    return networkResponse;
    
  } catch (networkError) {
    console.log('[Service Worker] Network failed, trying cache:', request.url);
    
    // Try cache
    const cachedResponse = await cache.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Try fallback URL if provided
    if (fallbackUrl) {
      const fallbackResponse = await cache.match(fallbackUrl);
      if (fallbackResponse) {
        return fallbackResponse;
      }
    }
    
    throw networkError;
  }
}

// Cache First strategy - try cache, fallback to network
async function cacheFirstStrategy(request, cacheName) {
  const cache = await caches.open(cacheName);
  
  // Try cache first
  const cachedResponse = await cache.match(request);
  if (cachedResponse) {
    return cachedResponse;
  }
  
  try {
    // Try network as fallback
    const networkResponse = await fetch(request);
    
    // Cache the response if successful
    if (networkResponse.ok) {
      const responseClone = networkResponse.clone();
      await cache.put(request, responseClone);
    }
    
    return networkResponse;
    
  } catch (networkError) {
    console.error('[Service Worker] Cache first strategy failed:', networkError);
    throw networkError;
  }
}

// Push notification event
self.addEventListener('push', (event) => {
  console.log('[Service Worker] Push notification received');
  
  event.waitUntil(
    (async () => {
      try {
        let notificationData = {};
        
        if (event.data) {
          try {
            notificationData = event.data.json();
          } catch (e) {
            notificationData = { title: event.data.text() };
          }
        }
        
        // Default notification options
        const options = {
          title: notificationData.title || 'iSECTECH Security Alert',
          body: notificationData.body || 'New security notification received',
          icon: '/icons/icon-192x192.png',
          badge: '/icons/icon-72x72.png',
          tag: notificationData.tag || 'general',
          data: notificationData.data || {},
          requireInteraction: notificationData.priority === 'high',
          silent: notificationData.silent || false,
          actions: notificationData.actions || [
            { action: 'view', title: 'View Details', icon: '/icons/view.png' },
            { action: 'dismiss', title: 'Dismiss', icon: '/icons/dismiss.png' }
          ],
        };
        
        // Store notification in IndexedDB for offline access
        await storeNotificationOffline(notificationData);
        
        // Show notification
        await self.registration.showNotification(options.title, options);
        
        // Send message to clients
        const clients = await self.clients.matchAll();
        clients.forEach(client => {
          client.postMessage({
            type: 'PUSH_NOTIFICATION',
            payload: notificationData,
          });
        });
        
      } catch (error) {
        console.error('[Service Worker] Push notification error:', error);
      }
    })()
  );
});

// Notification click event
self.addEventListener('notificationclick', (event) => {
  console.log('[Service Worker] Notification clicked:', event.notification);
  
  event.notification.close();
  
  event.waitUntil(
    (async () => {
      try {
        const clients = await self.clients.matchAll({ type: 'window' });
        const action = event.action;
        const data = event.notification.data;
        
        if (action === 'dismiss') {
          return; // Just close the notification
        }
        
        // Determine URL to open
        let urlToOpen = '/mobile/notifications';
        
        if (action === 'view' && data.url) {
          urlToOpen = data.url;
        } else if (data.type === 'security-alert') {
          urlToOpen = '/mobile/alerts';
        }
        
        // Try to focus existing window or open new one
        for (const client of clients) {
          if (client.url.includes(urlToOpen) && 'focus' in client) {
            await client.focus();
            return;
          }
        }
        
        // Open new window
        if (self.clients.openWindow) {
          await self.clients.openWindow(urlToOpen);
        }
        
      } catch (error) {
        console.error('[Service Worker] Notification click error:', error);
      }
    })()
  );
});

// Background sync event
self.addEventListener('sync', (event) => {
  console.log('[Service Worker] Background sync:', event.tag);
  
  if (event.tag === SYNC_TAGS.NOTIFICATION_QUEUE) {
    event.waitUntil(syncNotificationQueue());
  } else if (event.tag === SYNC_TAGS.ANALYTICS_QUEUE) {
    event.waitUntil(syncAnalyticsQueue());
  } else if (event.tag === SYNC_TAGS.USER_ACTIONS) {
    event.waitUntil(syncUserActionsQueue());
  }
});

// Sync notification queue when back online
async function syncNotificationQueue() {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    const queuedItems = await getAllFromStore(store);
    const notificationItems = queuedItems.filter(item => item.type === 'notification');
    
    for (const item of notificationItems) {
      try {
        // Attempt to sync with server
        const response = await fetch('/api/notifications/sync', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(item.data),
        });
        
        if (response.ok) {
          // Remove from queue on successful sync
          await store.delete(item.id);
          console.log('[Service Worker] Synced notification:', item.id);
        }
        
      } catch (error) {
        console.error('[Service Worker] Failed to sync notification:', item.id, error);
      }
    }
    
  } catch (error) {
    console.error('[Service Worker] Notification sync failed:', error);
  }
}

// Sync analytics queue
async function syncAnalyticsQueue() {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORES.ANALYTICS], 'readwrite');
    const store = transaction.objectStore(STORES.ANALYTICS);
    
    const analyticsData = await getAllFromStore(store);
    
    for (const data of analyticsData) {
      try {
        const response = await fetch('/api/analytics/performance', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data.payload),
        });
        
        if (response.ok) {
          await store.delete(data.id);
          console.log('[Service Worker] Synced analytics data:', data.id);
        }
        
      } catch (error) {
        console.error('[Service Worker] Failed to sync analytics:', data.id, error);
      }
    }
    
  } catch (error) {
    console.error('[Service Worker] Analytics sync failed:', error);
  }
}

// Sync user actions queue
async function syncUserActionsQueue() {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    const queuedItems = await getAllFromStore(store);
    const actionItems = queuedItems.filter(item => item.type === 'user-action');
    
    for (const item of actionItems) {
      try {
        const response = await fetch(item.data.endpoint, {
          method: item.data.method || 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...item.data.headers,
          },
          body: JSON.stringify(item.data.payload),
        });
        
        if (response.ok) {
          await store.delete(item.id);
          console.log('[Service Worker] Synced user action:', item.id);
        }
        
      } catch (error) {
        console.error('[Service Worker] Failed to sync user action:', item.id, error);
      }
    }
    
  } catch (error) {
    console.error('[Service Worker] User actions sync failed:', error);
  }
}

// Message event - handle messages from clients
self.addEventListener('message', (event) => {
  const { type, payload } = event.data;
  
  switch (type) {
    case 'SKIP_WAITING':
      self.skipWaiting();
      break;
      
    case 'GET_CACHE_STATUS':
      event.ports[0].postMessage({
        version: CACHE_VERSION,
        caches: [APP_CACHE, DATA_CACHE, IMAGE_CACHE, API_CACHE],
      });
      break;
      
    case 'CLEAR_CACHE':
      clearAllCaches().then(() => {
        event.ports[0].postMessage({ success: true });
      });
      break;
      
    case 'QUEUE_OFFLINE_ACTION':
      queueOfflineAction(payload).then(() => {
        event.ports[0].postMessage({ success: true });
      });
      break;
      
    default:
      console.log('[Service Worker] Unknown message type:', type);
  }
});

// IndexedDB helper functions
async function initializeDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      
      // Create stores
      if (!db.objectStoreNames.contains(STORES.NOTIFICATIONS)) {
        const notificationStore = db.createObjectStore(STORES.NOTIFICATIONS, {
          keyPath: 'id',
          autoIncrement: true,
        });
        notificationStore.createIndex('timestamp', 'timestamp');
        notificationStore.createIndex('type', 'type');
      }
      
      if (!db.objectStoreNames.contains(STORES.USER_PREFERENCES)) {
        db.createObjectStore(STORES.USER_PREFERENCES, { keyPath: 'key' });
      }
      
      if (!db.objectStoreNames.contains(STORES.OFFLINE_QUEUE)) {
        const queueStore = db.createObjectStore(STORES.OFFLINE_QUEUE, {
          keyPath: 'id',
          autoIncrement: true,
        });
        queueStore.createIndex('type', 'type');
        queueStore.createIndex('timestamp', 'timestamp');
      }
      
      if (!db.objectStoreNames.contains(STORES.ANALYTICS)) {
        const analyticsStore = db.createObjectStore(STORES.ANALYTICS, {
          keyPath: 'id',
          autoIncrement: true,
        });
        analyticsStore.createIndex('timestamp', 'timestamp');
      }
    };
  });
}

async function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

async function storeNotificationOffline(notificationData) {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORES.NOTIFICATIONS], 'readwrite');
    const store = transaction.objectStore(STORES.NOTIFICATIONS);
    
    const notification = {
      ...notificationData,
      timestamp: Date.now(),
      read: false,
      offline: true,
    };
    
    await store.add(notification);
    console.log('[Service Worker] Notification stored offline');
    
  } catch (error) {
    console.error('[Service Worker] Failed to store notification offline:', error);
  }
}

async function queueOfflineAction(actionData) {
  try {
    const db = await openDB();
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    const queueItem = {
      type: actionData.type,
      data: actionData,
      timestamp: Date.now(),
      retryCount: 0,
    };
    
    await store.add(queueItem);
    
    // Register for background sync
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      await self.registration.sync.register(SYNC_TAGS.USER_ACTIONS);
    }
    
  } catch (error) {
    console.error('[Service Worker] Failed to queue offline action:', error);
  }
}

async function getAllFromStore(store) {
  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

async function clearAllCaches() {
  try {
    const cacheNames = await caches.keys();
    const isecTechCaches = cacheNames.filter(name => 
      name.startsWith('isectech-protect-')
    );
    
    await Promise.all(
      isecTechCaches.map(cacheName => caches.delete(cacheName))
    );
    
    console.log(`[Service Worker] Cleared ${isecTechCaches.length} caches`);
    
  } catch (error) {
    console.error('[Service Worker] Failed to clear caches:', error);
  }
}

// Periodic background sync (if supported)
if ('periodicSync' in self.registration) {
  self.addEventListener('periodicsync', (event) => {
    if (event.tag === 'background-sync') {
      event.waitUntil(performBackgroundSync());
    }
  });
}

async function performBackgroundSync() {
  console.log('[Service Worker] Performing periodic background sync');
  
  try {
    // Sync all queues
    await Promise.all([
      syncNotificationQueue(),
      syncAnalyticsQueue(),
      syncUserActionsQueue(),
    ]);
    
    console.log('[Service Worker] Background sync completed');
    
  } catch (error) {
    console.error('[Service Worker] Background sync failed:', error);
  }
}

console.log('[Service Worker] Service worker script loaded');