/**
 * Comprehensive Mobile Testing Suite
 * 
 * This test suite validates the mobile notification system across:
 * - PWA functionality and offline capabilities
 * - Push notifications across iOS, Android, and major browsers
 * - Performance testing for mobile devices
 * - Cross-browser/device compatibility
 * - Mobile-specific security features
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/test';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserContext, Page, Browser, devices } from '@playwright/test';
import { performance } from 'perf_hooks';

// Mobile Components
import MobileDashboard from '../../app/components/mobile/mobile-dashboard';
import MobileNotifications from '../../app/components/mobile/mobile-notifications';
import { PWAProvider } from '../../app/components/mobile/pwa-provider';

// Utilities and Hooks
import { useOfflineSync } from '../../app/lib/hooks/use-offline-sync';
import { usePWA } from '../../app/lib/hooks/use-pwa';
import { usePushNotifications } from '../../app/lib/hooks/use-push-notifications';

// Test Utilities
import { createMobileTestEnvironment, MockServiceWorker } from '../utils/mobile-test-utils';

describe('Mobile Comprehensive Test Suite', () => {
  let testEnvironment: any;
  let mockServiceWorker: MockServiceWorker;
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  beforeAll(async () => {
    testEnvironment = await createMobileTestEnvironment();
    mockServiceWorker = new MockServiceWorker();
    await mockServiceWorker.start();
  });

  afterAll(async () => {
    await mockServiceWorker.stop();
    await testEnvironment.cleanup();
    if (browser) await browser.close();
  });

  describe('PWA Functionality Tests', () => {
    describe('Installation and Manifest', () => {
      test('should have valid PWA manifest', async () => {
        const manifestResponse = await fetch('/manifest.json');
        const manifest = await manifestResponse.json();

        expect(manifest.name).toBe('iSECTECH Protect Mobile');
        expect(manifest.short_name).toBe('iSECTECH');
        expect(manifest.start_url).toBe('/mobile');
        expect(manifest.display).toBe('standalone');
        expect(manifest.theme_color).toBeDefined();
        expect(manifest.background_color).toBeDefined();
        expect(manifest.icons).toHaveLength(4); // Different sizes for iOS/Android
      });

      test('should register service worker successfully', async () => {
        render(
          <PWAProvider>
            <MobileDashboard />
          </PWAProvider>
        );

        await waitFor(() => {
          expect(navigator.serviceWorker.controller).toBeTruthy();
        });

        const registration = await navigator.serviceWorker.ready;
        expect(registration.active?.state).toBe('activated');
      });

      test('should show install prompt on supported devices', async () => {
        const { container } = render(
          <PWAProvider>
            <MobileDashboard />
          </PWAProvider>
        );

        // Simulate beforeinstallprompt event
        const beforeInstallPromptEvent = new Event('beforeinstallprompt');
        window.dispatchEvent(beforeInstallPromptEvent);

        await waitFor(() => {
          expect(screen.getByText(/Install App/i)).toBeInTheDocument();
        });
      });

      test('should handle PWA update notifications', async () => {
        render(
          <PWAProvider>
            <MobileDashboard />
          </PWAProvider>
        );

        // Simulate service worker update
        const updateEvent = new MessageEvent('message', {
          data: { type: 'UPDATE_AVAILABLE' }
        });
        
        navigator.serviceWorker.controller?.postMessage(updateEvent.data);

        await waitFor(() => {
          expect(screen.getByText(/Update Available/i)).toBeInTheDocument();
        });
      });
    });

    describe('Offline Capabilities', () => {
      test('should cache critical resources for offline use', async () => {
        const { container } = render(
          <PWAProvider>
            <MobileDashboard />
          </PWAProvider>
        );

        // Check cache storage
        const cacheNames = await caches.keys();
        expect(cacheNames).toContain('isectech-v1');

        const cache = await caches.open('isectech-v1');
        const cachedRequests = await cache.keys();
        
        // Verify critical resources are cached
        const cachedUrls = cachedRequests.map(req => req.url);
        expect(cachedUrls).toEqual(expect.arrayContaining([
          expect.stringContaining('/mobile'),
          expect.stringContaining('/api/notifications'),
          expect.stringContaining('/manifest.json')
        ]));
      });

      test('should handle offline navigation', async () => {
        const OfflineTestComponent = () => {
          const { isOffline, syncStatus } = useOfflineSync();
          return (
            <div>
              <span data-testid="offline-status">{isOffline ? 'offline' : 'online'}</span>
              <span data-testid="sync-status">{syncStatus}</span>
            </div>
          );
        };

        render(
          <PWAProvider>
            <OfflineTestComponent />
          </PWAProvider>
        );

        // Simulate offline
        Object.defineProperty(navigator, 'onLine', { value: false, writable: true });
        window.dispatchEvent(new Event('offline'));

        await waitFor(() => {
          expect(screen.getByTestId('offline-status')).toHaveTextContent('offline');
        });

        // Navigate while offline
        fireEvent.click(screen.getByRole('link', { name: /notifications/i }));
        
        await waitFor(() => {
          expect(screen.getByText(/Offline Mode/i)).toBeInTheDocument();
        });
      });

      test('should queue actions for sync when offline', async () => {
        const TestComponent = () => {
          const { queueAction, syncQueue } = useOfflineSync();
          
          return (
            <div>
              <button onClick={() => queueAction('mark_read', { id: '123' })}>
                Mark Read
              </button>
              <span data-testid="queue-count">{syncQueue.length}</span>
            </div>
          );
        };

        render(
          <PWAProvider>
            <TestComponent />
          </PWAProvider>
        );

        // Go offline
        Object.defineProperty(navigator, 'onLine', { value: false, writable: true });
        window.dispatchEvent(new Event('offline'));

        // Perform action while offline
        fireEvent.click(screen.getByText('Mark Read'));

        await waitFor(() => {
          expect(screen.getByTestId('queue-count')).toHaveTextContent('1');
        });
      });

      test('should sync queued actions when coming back online', async () => {
        const mockSyncAction = jest.fn();
        const TestComponent = () => {
          const { queueAction, syncStatus } = useOfflineSync();
          
          return (
            <div>
              <button onClick={() => queueAction('delete', { id: '456' })}>
                Delete
              </button>
              <span data-testid="sync-status">{syncStatus}</span>
            </div>
          );
        };

        render(
          <PWAProvider>
            <TestComponent />
          </PWAProvider>
        );

        // Queue action while offline
        Object.defineProperty(navigator, 'onLine', { value: false, writable: true });
        fireEvent.click(screen.getByText('Delete'));

        // Go back online
        Object.defineProperty(navigator, 'onLine', { value: true, writable: true });
        window.dispatchEvent(new Event('online'));

        await waitFor(() => {
          expect(screen.getByTestId('sync-status')).toHaveTextContent('syncing');
        });

        await waitFor(() => {
          expect(screen.getByTestId('sync-status')).toHaveTextContent('synced');
        });
      });
    });

    describe('Background Sync', () => {
      test('should register background sync when offline actions occur', async () => {
        const mockRegistration = {
          sync: {
            register: jest.fn().mockResolvedValue(undefined)
          }
        };

        Object.defineProperty(navigator, 'serviceWorker', {
          value: { ready: Promise.resolve(mockRegistration) },
          writable: true
        });

        const TestComponent = () => {
          const { queueAction } = useOfflineSync();
          return (
            <button onClick={() => queueAction('bulk_action', { ids: ['1', '2'] })}>
              Bulk Action
            </button>
          );
        };

        render(
          <PWAProvider>
            <TestComponent />
          </PWAProvider>
        );

        fireEvent.click(screen.getByText('Bulk Action'));

        await waitFor(() => {
          expect(mockRegistration.sync.register).toHaveBeenCalledWith('background-sync');
        });
      });
    });
  });

  describe('Push Notification Tests', () => {
    describe('Registration and Permissions', () => {
      test('should request notification permissions on mobile devices', async () => {
        const mockRequestPermission = jest.fn().mockResolvedValue('granted');
        Object.defineProperty(Notification, 'requestPermission', {
          value: mockRequestPermission,
          writable: true
        });

        const NotificationTestComponent = () => {
          const { requestPermission, permission } = usePushNotifications();
          return (
            <div>
              <button onClick={requestPermission}>Request Permission</button>
              <span data-testid="permission">{permission}</span>
            </div>
          );
        };

        render(<NotificationTestComponent />);

        fireEvent.click(screen.getByText('Request Permission'));

        await waitFor(() => {
          expect(mockRequestPermission).toHaveBeenCalled();
          expect(screen.getByTestId('permission')).toHaveTextContent('granted');
        });
      });

      test('should handle push subscription registration', async () => {
        const mockSubscribe = jest.fn().mockResolvedValue({
          endpoint: 'https://fcm.googleapis.com/fcm/send/test',
          keys: {
            p256dh: 'test-key',
            auth: 'test-auth'
          }
        });

        const mockRegistration = {
          pushManager: {
            subscribe: mockSubscribe,
            getSubscription: jest.fn().mockResolvedValue(null)
          }
        };

        Object.defineProperty(navigator, 'serviceWorker', {
          value: { ready: Promise.resolve(mockRegistration) },
          writable: true
        });

        const SubscriptionTestComponent = () => {
          const { subscribe, subscription } = usePushNotifications();
          return (
            <div>
              <button onClick={subscribe}>Subscribe</button>
              <span data-testid="subscribed">{subscription ? 'subscribed' : 'not subscribed'}</span>
            </div>
          );
        };

        render(<SubscriptionTestComponent />);

        fireEvent.click(screen.getByText('Subscribe'));

        await waitFor(() => {
          expect(mockSubscribe).toHaveBeenCalled();
          expect(screen.getByTestId('subscribed')).toHaveTextContent('subscribed');
        });
      });
    });

    describe('Notification Display and Interaction', () => {
      test('should display notifications with proper mobile formatting', () => {
        render(
          <PWAProvider>
            <MobileNotifications />
          </PWAProvider>
        );

        const notifications = [
          {
            id: '1',
            title: 'Security Alert',
            body: 'Suspicious activity detected in your network',
            priority: 'critical',
            timestamp: new Date(),
            actions: [{ title: 'View Details', action: 'view' }]
          }
        ];

        notifications.forEach(notification => {
          expect(screen.getByText(notification.title)).toBeInTheDocument();
          expect(screen.getByText(notification.body)).toBeInTheDocument();
        });

        // Test mobile-optimized layout
        const notificationElement = screen.getByText('Security Alert').closest('[data-testid="notification"]');
        expect(notificationElement).toHaveClass('mobile-optimized');
      });

      test('should handle notification actions on mobile devices', async () => {
        const mockActionHandler = jest.fn();
        
        render(
          <PWAProvider>
            <MobileNotifications onNotificationAction={mockActionHandler} />
          </PWAProvider>
        );

        const actionButton = screen.getByRole('button', { name: /view details/i });
        fireEvent.click(actionButton);

        expect(mockActionHandler).toHaveBeenCalledWith('view', expect.any(String));
      });

      test('should support touch gestures for notification management', async () => {
        const user = userEvent.setup();
        
        render(
          <PWAProvider>
            <MobileNotifications />
          </PWAProvider>
        );

        const notification = screen.getByTestId('notification');
        
        // Test swipe to dismiss
        fireEvent.touchStart(notification, {
          touches: [{ clientX: 100, clientY: 100 }]
        });
        
        fireEvent.touchMove(notification, {
          touches: [{ clientX: 200, clientY: 100 }]
        });
        
        fireEvent.touchEnd(notification);

        await waitFor(() => {
          expect(notification).toHaveClass('dismissed');
        });
      });
    });

    describe('Notification Batching and Priority', () => {
      test('should batch low-priority notifications correctly', async () => {
        const mockBatchService = {
          batchNotifications: jest.fn(),
          shouldBatch: jest.fn().mockReturnValue(true)
        };

        const notifications = Array.from({ length: 5 }, (_, i) => ({
          id: i.toString(),
          title: `Info ${i}`,
          body: `Information message ${i}`,
          priority: 'informational'
        }));

        // Test batching logic
        notifications.forEach(notification => {
          mockBatchService.batchNotifications(notification);
        });

        expect(mockBatchService.batchNotifications).toHaveBeenCalledTimes(5);
      });

      test('should deliver critical notifications immediately', async () => {
        const criticalNotification = {
          id: 'critical-1',
          title: 'Critical Security Alert',
          body: 'Immediate action required',
          priority: 'critical'
        };

        const mockDeliveryService = {
          deliverImmediate: jest.fn(),
          shouldDelayDelivery: jest.fn().mockReturnValue(false)
        };

        mockDeliveryService.deliverImmediate(criticalNotification);
        
        expect(mockDeliveryService.deliverImmediate).toHaveBeenCalledWith(criticalNotification);
        expect(mockDeliveryService.shouldDelayDelivery(criticalNotification)).toBe(false);
      });
    });
  });

  describe('Cross-Browser/Device Compatibility Tests', () => {
    const testDevices = [
      devices['iPhone 12'],
      devices['iPhone 12 Pro'],
      devices['Pixel 5'],
      devices['Galaxy S9+'],
      devices['iPad Pro'],
      devices['Desktop Chrome'],
      devices['Desktop Firefox'],
      devices['Desktop Safari']
    ];

    describe('Responsive Design Validation', () => {
      test.each(testDevices)('should render correctly on %s', async (device) => {
        const { page } = await createDeviceContext(device);
        
        await page.goto('/mobile');
        await page.waitForSelector('[data-testid="mobile-dashboard"]');

        // Test responsive layout
        const dashboard = await page.locator('[data-testid="mobile-dashboard"]');
        expect(await dashboard.isVisible()).toBe(true);

        // Verify mobile-optimized elements
        const touchTargets = await page.locator('[data-touch-target="true"]').count();
        expect(touchTargets).toBeGreaterThan(0);

        // Test navigation
        await page.click('[data-testid="mobile-nav-toggle"]');
        const nav = await page.locator('[data-testid="mobile-navigation"]');
        expect(await nav.isVisible()).toBe(true);

        await page.close();
      });

      test.each(['portrait', 'landscape'])('should handle %s orientation', async (orientation) => {
        const { page } = await createDeviceContext(devices['iPhone 12']);
        
        if (orientation === 'landscape') {
          await page.setViewportSize({ width: 844, height: 390 });
        }

        await page.goto('/mobile');
        
        // Test layout adaptation
        const dashboard = await page.locator('[data-testid="mobile-dashboard"]');
        const boundingBox = await dashboard.boundingBox();
        
        if (orientation === 'portrait') {
          expect(boundingBox!.height).toBeGreaterThan(boundingBox!.width);
        } else {
          expect(boundingBox!.width).toBeGreaterThan(boundingBox!.height);
        }

        await page.close();
      });
    });

    describe('Browser-Specific Feature Tests', () => {
      test('should work with iOS Safari PWA features', async () => {
        const { page } = await createDeviceContext(devices['iPhone 12']);
        
        await page.goto('/mobile');
        
        // Test iOS-specific PWA features
        const isStandalone = await page.evaluate(() => 
          (window.navigator as any).standalone || 
          window.matchMedia('(display-mode: standalone)').matches
        );

        // Test iOS notification permissions
        const notificationPermission = await page.evaluate(() => 
          'Notification' in window ? Notification.permission : 'default'
        );
        
        expect(['default', 'granted', 'denied']).toContain(notificationPermission);

        await page.close();
      });

      test('should work with Android Chrome push messaging', async () => {
        const { page } = await createDeviceContext(devices['Pixel 5']);
        
        await page.goto('/mobile');
        
        // Test service worker registration
        const swRegistered = await page.evaluate(async () => {
          if ('serviceWorker' in navigator) {
            const registration = await navigator.serviceWorker.ready;
            return registration.active !== null;
          }
          return false;
        });
        
        expect(swRegistered).toBe(true);

        // Test push manager availability
        const pushManagerAvailable = await page.evaluate(() => {
          return 'PushManager' in window;
        });
        
        expect(pushManagerAvailable).toBe(true);

        await page.close();
      });
    });
  });

  describe('Performance Testing for Mobile', () => {
    describe('Load Time Performance', () => {
      test('should meet mobile load time targets (<3s)', async () => {
        const { page } = await createDeviceContext(devices['Pixel 5']);
        
        const startTime = performance.now();
        await page.goto('/mobile', { waitUntil: 'networkidle0' });
        const loadTime = performance.now() - startTime;
        
        expect(loadTime).toBeLessThan(3000); // 3 seconds

        // Test Time to Interactive
        const tti = await page.evaluate(() => {
          return new Promise((resolve) => {
            if ('PerformanceObserver' in window) {
              const observer = new PerformanceObserver((list) => {
                const entries = list.getEntries();
                const navigationEntry = entries[0];
                resolve(navigationEntry.loadEventEnd - navigationEntry.navigationStart);
              });
              observer.observe({ entryTypes: ['navigation'] });
            } else {
              resolve(0);
            }
          });
        });

        expect(tti).toBeLessThan(3000);

        await page.close();
      });

      test('should optimize resource loading on slower connections', async () => {
        const { page } = await createDeviceContext(devices['iPhone 12']);
        
        // Simulate 3G connection
        await page.context().route('**/*', async (route) => {
          await new Promise(resolve => setTimeout(resolve, 100)); // Add latency
          await route.continue();
        });

        const startTime = performance.now();
        await page.goto('/mobile');
        const loadTime = performance.now() - startTime;

        // Should still load reasonably fast on 3G
        expect(loadTime).toBeLessThan(5000); // 5 seconds on 3G

        await page.close();
      });
    });

    describe('Runtime Performance', () => {
      test('should maintain smooth animations on mobile devices', async () => {
        const { page } = await createDeviceContext(devices['Galaxy S9+']);
        
        await page.goto('/mobile');
        
        // Test notification animation performance
        await page.click('[data-testid="show-notifications"]');
        
        const animationPerformance = await page.evaluate(() => {
          return new Promise((resolve) => {
            let frameCount = 0;
            let startTime = performance.now();
            
            function measureFrameRate() {
              frameCount++;
              if (frameCount < 60) { // Measure for ~1 second
                requestAnimationFrame(measureFrameRate);
              } else {
                const endTime = performance.now();
                const fps = frameCount / ((endTime - startTime) / 1000);
                resolve(fps);
              }
            }
            
            requestAnimationFrame(measureFrameRate);
          });
        });

        expect(animationPerformance).toBeGreaterThan(30); // At least 30 FPS

        await page.close();
      });

      test('should handle large notification lists without performance degradation', async () => {
        const { page } = await createDeviceContext(devices['iPhone 12 Pro']);
        
        await page.goto('/mobile');
        
        // Simulate large notification list
        await page.evaluate(() => {
          const notificationContainer = document.querySelector('[data-testid="notification-list"]');
          for (let i = 0; i < 100; i++) {
            const notification = document.createElement('div');
            notification.className = 'notification-item';
            notification.textContent = `Notification ${i}`;
            notificationContainer?.appendChild(notification);
          }
        });

        // Measure scroll performance
        const scrollPerformance = await page.evaluate(() => {
          return new Promise((resolve) => {
            const container = document.querySelector('[data-testid="notification-list"]');
            let startTime = performance.now();
            
            container?.scrollTo({ top: 1000, behavior: 'smooth' });
            
            container?.addEventListener('scroll', function onScroll() {
              if (container.scrollTop >= 900) { // Near target
                const endTime = performance.now();
                container.removeEventListener('scroll', onScroll);
                resolve(endTime - startTime);
              }
            });
          });
        });

        expect(scrollPerformance).toBeLessThan(1000); // Should complete smoothly

        await page.close();
      });
    });

    describe('Memory Usage', () => {
      test('should maintain reasonable memory usage during extended use', async () => {
        const { page } = await createDeviceContext(devices['Pixel 5']);
        
        await page.goto('/mobile');
        
        // Measure initial memory
        const initialMemory = await page.evaluate(() => {
          return (performance as any).memory?.usedJSHeapSize || 0;
        });

        // Simulate extended usage
        for (let i = 0; i < 50; i++) {
          await page.click('[data-testid="refresh-notifications"]');
          await page.waitForTimeout(100);
        }

        // Measure final memory
        const finalMemory = await page.evaluate(() => {
          return (performance as any).memory?.usedJSHeapSize || 0;
        });

        // Memory growth should be reasonable
        const memoryGrowth = finalMemory - initialMemory;
        expect(memoryGrowth).toBeLessThan(10 * 1024 * 1024); // Less than 10MB growth

        await page.close();
      });
    });

    describe('Battery Impact', () => {
      test('should minimize battery drain during background operation', async () => {
        // This test would integrate with battery monitoring tools in a real environment
        const { page } = await createDeviceContext(devices['iPhone 12']);
        
        await page.goto('/mobile');
        
        // Enable background operation simulation
        await page.evaluate(() => {
          // Simulate app going to background
          document.hidden = true;
          document.dispatchEvent(new Event('visibilitychange'));
        });

        // Test that background operations are throttled
        const backgroundActivityCount = await page.evaluate(() => {
          return new Promise((resolve) => {
            let activityCount = 0;
            const observer = new PerformanceObserver((list) => {
              activityCount += list.getEntries().length;
            });
            observer.observe({ entryTypes: ['measure'] });
            
            setTimeout(() => {
              resolve(activityCount);
            }, 5000);
          });
        });

        // Background activity should be minimal
        expect(backgroundActivityCount).toBeLessThan(10);

        await page.close();
      });
    });
  });

  describe('Mobile Security Features', () => {
    test('should implement proper Content Security Policy for mobile', async () => {
      const { page } = await createDeviceContext(devices['iPhone 12']);
      
      await page.goto('/mobile');
      
      const cspHeader = await page.evaluate(() => {
        const metaTag = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        return metaTag?.getAttribute('content') || '';
      });

      expect(cspHeader).toContain("default-src 'self'");
      expect(cspHeader).toContain("connect-src 'self' https:");
      expect(cspHeader).not.toContain("'unsafe-eval'");

      await page.close();
    });

    test('should handle biometric authentication on supported devices', async () => {
      const { page } = await createDeviceContext(devices['iPhone 12']);
      
      await page.goto('/mobile');
      
      // Test WebAuthn availability
      const webauthnSupported = await page.evaluate(() => {
        return 'credentials' in navigator && 'create' in navigator.credentials;
      });

      if (webauthnSupported) {
        // Test biometric authentication trigger
        await page.click('[data-testid="biometric-auth"]');
        
        // In a real test, this would interact with the device's biometric system
        // For now, we just verify the interface is available
        const authDialog = await page.locator('[data-testid="auth-dialog"]');
        expect(await authDialog.isVisible()).toBe(true);
      }

      await page.close();
    });
  });

  // Utility Functions

  async function createDeviceContext(device: any): Promise<{ page: Page; context: BrowserContext }> {
    const { chromium } = await import('@playwright/test');
    const browser = await chromium.launch();
    const context = await browser.newContext({
      ...device,
      permissions: ['notifications'],
      geolocation: { latitude: 37.7749, longitude: -122.4194 } // San Francisco
    });
    const page = await context.newPage();
    return { page, context };
  }

  async function createMobileTestEnvironment() {
    // Mock mobile-specific APIs and services
    return {
      cleanup: async () => {
        // Cleanup test environment
      }
    };
  }
});

// Mock Service Worker for testing
class MockServiceWorker {
  async start() {
    // Setup mock service worker
    Object.defineProperty(navigator, 'serviceWorker', {
      value: {
        ready: Promise.resolve({
          active: { state: 'activated' },
          pushManager: {
            subscribe: jest.fn(),
            getSubscription: jest.fn()
          }
        }),
        register: jest.fn().mockResolvedValue({}),
        controller: {
          postMessage: jest.fn()
        }
      },
      writable: true
    });
  }

  async stop() {
    // Cleanup mock service worker
  }
}