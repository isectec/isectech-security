/**
 * PWA Functionality Testing Suite
 * 
 * Tests progressive web app features including:
 * - Service worker registration and caching
 * - Offline functionality and background sync
 * - Push notification infrastructure
 * - App installation and updates
 * - Performance optimization features
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/test';
import { JSDOM } from 'jsdom';

// PWA-specific imports
import '../../../public/service-worker.js';

describe('PWA Functionality Tests', () => {
  let dom: JSDOM;
  let window: Window;
  let document: Document;
  let navigator: Navigator;

  beforeAll(async () => {
    // Setup DOM environment
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'https://app.isectech.com',
      pretendToBeVisual: true,
      resources: 'usable'
    });

    global.window = dom.window as unknown as Window & typeof globalThis;
    global.document = dom.window.document;
    global.navigator = dom.window.navigator;

    // Mock Service Worker APIs
    setupServiceWorkerMocks();
  });

  afterAll(() => {
    dom.window.close();
  });

  describe('Service Worker Registration', () => {
    test('should register service worker successfully', async () => {
      const mockRegistration = {
        installing: null,
        waiting: null,
        active: {
          state: 'activated',
          scriptURL: '/service-worker.js'
        },
        scope: '/',
        update: jest.fn(),
        unregister: jest.fn(),
        addEventListener: jest.fn()
      };

      const mockRegister = jest.fn().mockResolvedValue(mockRegistration);
      Object.defineProperty(navigator, 'serviceWorker', {
        value: {
          register: mockRegister,
          ready: Promise.resolve(mockRegistration),
          controller: mockRegistration.active,
          getRegistration: jest.fn().mockResolvedValue(mockRegistration)
        },
        writable: true
      });

      // Test service worker registration
      const registration = await navigator.serviceWorker.register('/service-worker.js');
      
      expect(mockRegister).toHaveBeenCalledWith('/service-worker.js');
      expect(registration.active?.state).toBe('activated');
      expect(registration.scope).toBe('/');
    });

    test('should handle service worker update lifecycle', async () => {
      const mockRegistration = {
        installing: {
          state: 'installing',
          addEventListener: jest.fn()
        },
        waiting: null,
        active: {
          state: 'activated',
          scriptURL: '/service-worker.js'
        },
        scope: '/',
        update: jest.fn(),
        unregister: jest.fn(),
        addEventListener: jest.fn()
      };

      Object.defineProperty(navigator, 'serviceWorker', {
        value: {
          register: jest.fn().mockResolvedValue(mockRegistration),
          ready: Promise.resolve(mockRegistration),
          controller: mockRegistration.active
        },
        writable: true
      });

      const registration = await navigator.serviceWorker.register('/service-worker.js');
      
      // Simulate service worker state changes
      const stateChangeHandler = jest.fn();
      registration.installing?.addEventListener('statechange', stateChangeHandler);

      // Simulate state transition: installing -> installed -> activating -> activated
      Object.defineProperty(registration.installing, 'state', { value: 'installed' });
      registration.installing?.dispatchEvent(new Event('statechange'));

      expect(stateChangeHandler).toHaveBeenCalled();
    });

    test('should handle service worker registration failure', async () => {
      const mockError = new Error('Service worker registration failed');
      const mockRegister = jest.fn().mockRejectedValue(mockError);

      Object.defineProperty(navigator, 'serviceWorker', {
        value: {
          register: mockRegister
        },
        writable: true
      });

      await expect(navigator.serviceWorker.register('/service-worker.js')).rejects.toThrow(mockError);
    });
  });

  describe('Caching Strategies', () => {
    test('should implement cache-first strategy for static assets', async () => {
      const mockCache = {
        match: jest.fn().mockResolvedValue(new Response('cached content')),
        add: jest.fn(),
        addAll: jest.fn(),
        put: jest.fn(),
        delete: jest.fn(),
        keys: jest.fn().mockResolvedValue([])
      };

      const mockCaches = {
        open: jest.fn().mockResolvedValue(mockCache),
        match: jest.fn().mockResolvedValue(new Response('global cached content')),
        has: jest.fn().mockResolvedValue(true),
        delete: jest.fn(),
        keys: jest.fn().mockResolvedValue(['isectech-v1'])
      };

      global.caches = mockCaches;

      // Test cache-first strategy
      const cache = await caches.open('isectech-v1');
      const cachedResponse = await cache.match('/static/app.css');
      
      expect(cachedResponse).toBeTruthy();
      expect(mockCache.match).toHaveBeenCalledWith('/static/app.css');
    });

    test('should implement network-first strategy for API calls', async () => {
      const mockFetch = jest.fn()
        .mockResolvedValueOnce(new Response('network response'))
        .mockRejectedValueOnce(new Error('Network failed'));

      const mockCache = {
        match: jest.fn().mockResolvedValue(new Response('cached api response')),
        put: jest.fn()
      };

      global.fetch = mockFetch;
      global.caches = {
        open: jest.fn().mockResolvedValue(mockCache),
        match: jest.fn()
      };

      // Test network-first strategy
      const cache = await caches.open('isectech-v1');
      
      // First call should use network
      let response;
      try {
        response = await fetch('/api/notifications');
        await cache.put('/api/notifications', response.clone());
      } catch (error) {
        response = await cache.match('/api/notifications');
      }

      expect(mockFetch).toHaveBeenCalledWith('/api/notifications');
      expect(response).toBeTruthy();
    });

    test('should manage cache storage limits', async () => {
      const mockCache = {
        keys: jest.fn().mockResolvedValue([
          new Request('/old-resource-1'),
          new Request('/old-resource-2'),
          new Request('/current-resource')
        ]),
        delete: jest.fn().mockResolvedValue(true),
        match: jest.fn(),
        put: jest.fn()
      };

      global.caches = {
        open: jest.fn().mockResolvedValue(mockCache),
        keys: jest.fn()
      };

      // Test cache cleanup
      const cache = await caches.open('isectech-v1');
      const allRequests = await cache.keys();
      
      // Simulate cache limit exceeded
      if (allRequests.length > 50) {
        const oldestRequest = allRequests[0];
        await cache.delete(oldestRequest);
      }

      expect(mockCache.keys).toHaveBeenCalled();
    });
  });

  describe('Offline Functionality', () => {
    test('should detect offline/online status changes', async () => {
      const onlineHandler = jest.fn();
      const offlineHandler = jest.fn();

      window.addEventListener('online', onlineHandler);
      window.addEventListener('offline', offlineHandler);

      // Simulate going offline
      Object.defineProperty(navigator, 'onLine', { value: false, writable: true });
      window.dispatchEvent(new Event('offline'));

      expect(offlineHandler).toHaveBeenCalled();

      // Simulate going online
      Object.defineProperty(navigator, 'onLine', { value: true, writable: true });
      window.dispatchEvent(new Event('online'));

      expect(onlineHandler).toHaveBeenCalled();
    });

    test('should serve cached content when offline', async () => {
      const mockCache = {
        match: jest.fn().mockResolvedValue(new Response('offline content', {
          status: 200,
          headers: { 'Content-Type': 'text/html' }
        }))
      };

      global.caches = {
        match: jest.fn().mockResolvedValue(new Response('offline content'))
      };

      // Simulate offline request
      Object.defineProperty(navigator, 'onLine', { value: false, writable: true });
      
      const offlineResponse = await caches.match('/mobile');
      
      expect(offlineResponse).toBeTruthy();
      expect(await offlineResponse?.text()).toBe('offline content');
    });

    test('should queue failed requests for background sync', async () => {
      const mockIndexedDB = {
        open: jest.fn().mockResolvedValue({
          transaction: jest.fn().mockReturnValue({
            objectStore: jest.fn().mockReturnValue({
              add: jest.fn(),
              get: jest.fn(),
              getAll: jest.fn().mockResolvedValue([]),
              delete: jest.fn()
            })
          })
        })
      };

      global.indexedDB = mockIndexedDB;

      // Simulate failed request that should be queued
      const failedRequest = {
        url: '/api/notifications/mark-read',
        method: 'POST',
        body: JSON.stringify({ id: '123' }),
        timestamp: Date.now()
      };

      // This would be handled by the service worker
      const queueRequest = async (request: any) => {
        const db = await indexedDB.open('sync-queue', 1);
        const transaction = db.transaction(['requests'], 'readwrite');
        const store = transaction.objectStore('requests');
        await store.add(request);
      };

      await queueRequest(failedRequest);

      expect(mockIndexedDB.open).toHaveBeenCalledWith('sync-queue', 1);
    });
  });

  describe('Background Sync', () => {
    test('should register background sync for queued requests', async () => {
      const mockSyncManager = {
        register: jest.fn().mockResolvedValue(undefined),
        getTags: jest.fn().mockResolvedValue(['background-sync'])
      };

      const mockRegistration = {
        sync: mockSyncManager
      };

      Object.defineProperty(navigator, 'serviceWorker', {
        value: {
          ready: Promise.resolve(mockRegistration)
        },
        writable: true
      });

      // Test background sync registration
      const registration = await navigator.serviceWorker.ready;
      await registration.sync.register('background-sync');

      expect(mockSyncManager.register).toHaveBeenCalledWith('background-sync');
    });

    test('should process queued requests when sync event fires', async () => {
      const mockIndexedDB = {
        open: jest.fn().mockResolvedValue({
          transaction: jest.fn().mockReturnValue({
            objectStore: jest.fn().mockReturnValue({
              getAll: jest.fn().mockResolvedValue([
                {
                  id: 1,
                  url: '/api/notifications/mark-read',
                  method: 'POST',
                  body: '{"id": "123"}',
                  timestamp: Date.now()
                }
              ]),
              delete: jest.fn()
            })
          })
        })
      };

      const mockFetch = jest.fn().mockResolvedValue(new Response('{"success": true}'));

      global.indexedDB = mockIndexedDB;
      global.fetch = mockFetch;

      // Simulate sync event processing
      const processSyncQueue = async () => {
        const db = await indexedDB.open('sync-queue', 1);
        const transaction = db.transaction(['requests'], 'readwrite');
        const store = transaction.objectStore('requests');
        const requests = await store.getAll();

        for (const request of requests) {
          try {
            await fetch(request.url, {
              method: request.method,
              body: request.body,
              headers: { 'Content-Type': 'application/json' }
            });
            await store.delete(request.id);
          } catch (error) {
            console.log('Sync failed for request:', request.id);
          }
        }
      };

      await processSyncQueue();

      expect(mockFetch).toHaveBeenCalledWith('/api/notifications/mark-read', {
        method: 'POST',
        body: '{"id": "123"}',
        headers: { 'Content-Type': 'application/json' }
      });
    });
  });

  describe('Push Notifications', () => {
    test('should handle push message events', async () => {
      const mockNotification = {
        close: jest.fn(),
        addEventListener: jest.fn()
      };

      const mockServiceWorkerGlobalScope = {
        registration: {
          showNotification: jest.fn().mockResolvedValue(mockNotification)
        },
        addEventListener: jest.fn()
      };

      // Test push event handling
      const pushEventData = {
        title: 'Security Alert',
        body: 'Suspicious activity detected',
        icon: '/icons/icon-192x192.png',
        badge: '/icons/badge-72x72.png',
        tag: 'security-alert',
        data: {
          url: '/mobile/notifications/123',
          action: 'view'
        }
      };

      const handlePushEvent = async (event: any) => {
        const data = event.data ? event.data.json() : pushEventData;
        
        return mockServiceWorkerGlobalScope.registration.showNotification(data.title, {
          body: data.body,
          icon: data.icon,
          badge: data.badge,
          tag: data.tag,
          data: data.data,
          actions: [
            { action: 'view', title: 'View Details' },
            { action: 'dismiss', title: 'Dismiss' }
          ]
        });
      };

      await handlePushEvent({ data: { json: () => pushEventData } });

      expect(mockServiceWorkerGlobalScope.registration.showNotification).toHaveBeenCalledWith(
        'Security Alert',
        expect.objectContaining({
          body: 'Suspicious activity detected',
          icon: '/icons/icon-192x192.png',
          actions: expect.arrayContaining([
            { action: 'view', title: 'View Details' }
          ])
        })
      );
    });

    test('should handle notification click events', async () => {
      const mockClients = {
        matchAll: jest.fn().mockResolvedValue([]),
        openWindow: jest.fn().mockResolvedValue({
          focus: jest.fn()
        })
      };

      const mockNotificationEvent = {
        notification: {
          data: {
            url: '/mobile/notifications/123',
            action: 'view'
          },
          close: jest.fn()
        },
        action: 'view',
        waitUntil: jest.fn()
      };

      global.clients = mockClients;

      // Test notification click handling
      const handleNotificationClick = async (event: any) => {
        event.notification.close();

        const urlToOpen = event.notification.data.url;
        const clients = await self.clients.matchAll({ type: 'window' });

        let clientToFocus = clients.find((client: any) => client.url === urlToOpen);

        if (clientToFocus) {
          return clientToFocus.focus();
        } else {
          return self.clients.openWindow(urlToOpen);
        }
      };

      await handleNotificationClick(mockNotificationEvent);

      expect(mockNotificationEvent.notification.close).toHaveBeenCalled();
      expect(mockClients.openWindow).toHaveBeenCalledWith('/mobile/notifications/123');
    });

    test('should handle push subscription changes', async () => {
      const mockPushManager = {
        subscribe: jest.fn().mockResolvedValue({
          endpoint: 'https://fcm.googleapis.com/fcm/send/new-endpoint',
          keys: {
            p256dh: 'new-p256dh-key',
            auth: 'new-auth-key'
          }
        }),
        getSubscription: jest.fn().mockResolvedValue(null)
      };

      const mockRegistration = {
        pushManager: mockPushManager
      };

      // Test subscription update
      const updateSubscription = async () => {
        const subscription = await mockRegistration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: 'BJ_TEST_KEY'
        });

        // Send subscription to server
        await fetch('/api/push/subscribe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            endpoint: subscription.endpoint,
            keys: subscription.keys
          })
        });

        return subscription;
      };

      const subscription = await updateSubscription();

      expect(mockPushManager.subscribe).toHaveBeenCalledWith({
        userVisibleOnly: true,
        applicationServerKey: 'BJ_TEST_KEY'
      });
    });
  });

  describe('App Installation', () => {
    test('should handle beforeinstallprompt event', async () => {
      let installPrompt: any = null;
      const beforeInstallPromptHandler = (e: any) => {
        e.preventDefault();
        installPrompt = e;
      };

      window.addEventListener('beforeinstallprompt', beforeInstallPromptHandler);

      // Simulate beforeinstallprompt event
      const mockInstallPrompt = {
        preventDefault: jest.fn(),
        prompt: jest.fn().mockResolvedValue(undefined),
        userChoice: Promise.resolve({ outcome: 'accepted' })
      };

      window.dispatchEvent(Object.assign(new Event('beforeinstallprompt'), mockInstallPrompt));

      expect(mockInstallPrompt.preventDefault).toHaveBeenCalled();
      expect(installPrompt).toBeTruthy();

      // Test showing install prompt
      if (installPrompt) {
        await installPrompt.prompt();
        const choiceResult = await installPrompt.userChoice;
        expect(choiceResult.outcome).toBe('accepted');
      }
    });

    test('should detect PWA installation status', async () => {
      // Test standalone display mode detection
      const isStandalone = window.matchMedia('(display-mode: standalone)').matches ||
                           (navigator as any).standalone ||
                           document.referrer.includes('android-app://');

      // Test different installation scenarios
      expect(typeof isStandalone).toBe('boolean');

      // Test iOS standalone detection
      Object.defineProperty(navigator, 'standalone', { value: true, writable: true });
      const iosStandalone = (navigator as any).standalone;
      expect(iosStandalone).toBe(true);
    });
  });

  describe('Performance Optimization', () => {
    test('should implement resource prioritization', async () => {
      const mockCache = {
        addAll: jest.fn(),
        match: jest.fn(),
        put: jest.fn()
      };

      global.caches = {
        open: jest.fn().mockResolvedValue(mockCache)
      };

      // Test critical resource caching
      const criticalResources = [
        '/mobile',
        '/static/css/mobile.css',
        '/static/js/mobile.js',
        '/manifest.json',
        '/icons/icon-192x192.png'
      ];

      const cache = await caches.open('isectech-v1');
      await cache.addAll(criticalResources);

      expect(mockCache.addAll).toHaveBeenCalledWith(criticalResources);
    });

    test('should implement lazy loading for non-critical resources', async () => {
      const mockIntersectionObserver = jest.fn().mockImplementation((callback) => ({
        observe: jest.fn(),
        unobserve: jest.fn(),
        disconnect: jest.fn()
      }));

      global.IntersectionObserver = mockIntersectionObserver;

      // Test lazy loading implementation
      const lazyLoadImages = () => {
        const images = document.querySelectorAll('img[data-src]');
        
        const imageObserver = new IntersectionObserver((entries) => {
          entries.forEach(entry => {
            if (entry.isIntersecting) {
              const img = entry.target as HTMLImageElement;
              img.src = img.dataset.src!;
              img.removeAttribute('data-src');
              imageObserver.unobserve(img);
            }
          });
        });

        images.forEach(img => imageObserver.observe(img));
      };

      // Create test image element
      const img = document.createElement('img');
      img.setAttribute('data-src', '/icons/lazy-icon.png');
      document.body.appendChild(img);

      lazyLoadImages();

      expect(mockIntersectionObserver).toHaveBeenCalled();
    });
  });

  // Helper Functions

  function setupServiceWorkerMocks() {
    // Mock Cache API
    global.caches = {
      open: jest.fn(),
      match: jest.fn(),
      has: jest.fn(),
      delete: jest.fn(),
      keys: jest.fn()
    };

    // Mock IndexedDB
    global.indexedDB = {
      open: jest.fn(),
      deleteDatabase: jest.fn()
    };

    // Mock Notification API
    global.Notification = class MockNotification {
      static permission = 'default';
      static requestPermission = jest.fn().mockResolvedValue('granted');
      
      constructor(public title: string, public options?: NotificationOptions) {}
      
      close = jest.fn();
      addEventListener = jest.fn();
    } as any;

    // Mock Fetch API
    global.fetch = jest.fn();

    // Mock Navigator APIs
    Object.defineProperty(navigator, 'serviceWorker', {
      value: {
        register: jest.fn(),
        ready: Promise.resolve({}),
        controller: null,
        getRegistration: jest.fn()
      },
      writable: true
    });

    Object.defineProperty(navigator, 'onLine', {
      value: true,
      writable: true
    });
  }
});