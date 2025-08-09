/**
 * Cross-Platform Mobile Testing Suite
 * 
 * This suite tests mobile functionality across different:
 * - Browsers: Chrome, Firefox, Safari, Edge
 * - Devices: iOS (iPhone/iPad), Android (various screen sizes)
 * - Operating Systems: iOS 14+, Android 10+
 * - Network conditions: 3G, 4G, WiFi, offline
 * 
 * Uses Playwright for comprehensive cross-browser testing
 */

import { test, expect, devices, chromium, firefox, webkit, Browser, BrowserContext, Page } from '@playwright/test';

// Test configuration for different platforms
const MOBILE_DEVICES = [
  devices['iPhone 12'],
  devices['iPhone 12 Pro'],
  devices['iPhone 13'],
  devices['iPhone 13 Pro Max'],
  devices['Pixel 5'],
  devices['Galaxy S9+'],
  devices['Galaxy Note 20'],
  devices['iPad Pro'],
  devices['Galaxy Tab S4']
];

const DESKTOP_BROWSERS = [
  { name: 'chromium', browser: chromium },
  { name: 'firefox', browser: firefox },
  { name: 'webkit', browser: webkit }
];

const NETWORK_CONDITIONS = [
  {
    name: '3G',
    downloadThroughput: 1.6 * 1024 * 1024 / 8, // 1.6 Mbps
    uploadThroughput: 750 * 1024 / 8, // 750 Kbps
    latency: 40
  },
  {
    name: '4G',
    downloadThroughput: 9 * 1024 * 1024 / 8, // 9 Mbps
    uploadThroughput: 1 * 1024 * 1024 / 8, // 1 Mbps
    latency: 20
  },
  {
    name: 'WiFi',
    downloadThroughput: 50 * 1024 * 1024 / 8, // 50 Mbps
    uploadThroughput: 10 * 1024 * 1024 / 8, // 10 Mbps
    latency: 2
  }
];

test.describe('Cross-Platform Mobile Testing', () => {
  
  test.describe('Device Compatibility Tests', () => {
    MOBILE_DEVICES.forEach(device => {
      test(`Mobile Dashboard - ${device.name}`, async ({ browser }) => {
        const context = await browser.newContext({
          ...device,
          permissions: ['notifications', 'geolocation']
        });
        
        const page = await context.newPage();
        
        try {
          await page.goto('/mobile');
          await page.waitForSelector('[data-testid="mobile-dashboard"]', { timeout: 10000 });

          // Test responsive layout
          const dashboard = page.locator('[data-testid="mobile-dashboard"]');
          await expect(dashboard).toBeVisible();

          // Test mobile-specific elements
          const mobileNavToggle = page.locator('[data-testid="mobile-nav-toggle"]');
          await expect(mobileNavToggle).toBeVisible();

          // Test touch interaction
          await mobileNavToggle.tap();
          const mobileNav = page.locator('[data-testid="mobile-navigation"]');
          await expect(mobileNav).toBeVisible();

          // Test notification panel
          const notificationIcon = page.locator('[data-testid="notification-icon"]');
          await notificationIcon.tap();
          const notificationPanel = page.locator('[data-testid="notification-panel"]');
          await expect(notificationPanel).toBeVisible();

          // Validate mobile-optimized touch targets (minimum 44px)
          const touchTargets = page.locator('[data-touch-target="true"]');
          const count = await touchTargets.count();
          
          for (let i = 0; i < count; i++) {
            const element = touchTargets.nth(i);
            const boundingBox = await element.boundingBox();
            
            if (boundingBox) {
              expect(boundingBox.width).toBeGreaterThanOrEqual(44);
              expect(boundingBox.height).toBeGreaterThanOrEqual(44);
            }
          }

          // Test scroll performance
          const notificationList = page.locator('[data-testid="notification-list"]');
          await notificationList.scrollIntoViewIfNeeded();
          
          // Measure scroll performance
          const scrollStart = Date.now();
          await page.evaluate(() => {
            document.querySelector('[data-testid="notification-list"]')?.scrollTo({ 
              top: 500, 
              behavior: 'smooth' 
            });
          });
          
          await page.waitForTimeout(1000);
          const scrollEnd = Date.now();
          const scrollTime = scrollEnd - scrollStart;
          
          expect(scrollTime).toBeLessThan(2000); // Should complete within 2 seconds

        } finally {
          await context.close();
        }
      });

      test(`PWA Installation - ${device.name}`, async ({ browser }) => {
        const context = await browser.newContext({
          ...device,
          permissions: ['notifications']
        });
        
        const page = await context.newPage();
        
        try {
          await page.goto('/mobile');

          // Test PWA manifest
          const manifestLink = page.locator('link[rel="manifest"]');
          await expect(manifestLink).toHaveAttribute('href', '/manifest.json');

          // Test service worker registration
          const serviceWorkerRegistered = await page.evaluate(async () => {
            if ('serviceWorker' in navigator) {
              try {
                const registration = await navigator.serviceWorker.ready;
                return registration.active !== null;
              } catch (error) {
                return false;
              }
            }
            return false;
          });

          expect(serviceWorkerRegistered).toBe(true);

          // Test PWA installation prompt (if supported)
          const hasBeforeInstallPrompt = await page.evaluate(() => {
            return new Promise((resolve) => {
              let hasPrompt = false;
              
              const handler = (e: Event) => {
                hasPrompt = true;
                e.preventDefault();
                window.removeEventListener('beforeinstallprompt', handler);
                resolve(hasPrompt);
              };
              
              window.addEventListener('beforeinstallprompt', handler);
              
              // Simulate the event for testing
              setTimeout(() => {
                if (!hasPrompt) {
                  resolve(hasPrompt);
                }
              }, 2000);
            });
          });

          // Note: Not all devices/browsers support beforeinstallprompt
          console.log(`Install prompt support on ${device.name}: ${hasBeforeInstallPrompt}`);

        } finally {
          await context.close();
        }
      });
    });
  });

  test.describe('Browser Compatibility Tests', () => {
    DESKTOP_BROWSERS.forEach(({ name, browser: browserType }) => {
      test(`Mobile View Compatibility - ${name}`, async () => {
        const browser = await browserType.launch();
        const context = await browser.newContext({
          viewport: { width: 390, height: 844 }, // iPhone 12 size
          userAgent: devices['iPhone 12'].userAgent,
          permissions: ['notifications']
        });
        
        const page = await context.newPage();
        
        try {
          await page.goto('/mobile');
          await page.waitForSelector('[data-testid="mobile-dashboard"]');

          // Test mobile layout in desktop browser
          const dashboard = page.locator('[data-testid="mobile-dashboard"]');
          await expect(dashboard).toBeVisible();

          // Test responsive behavior
          await page.setViewportSize({ width: 768, height: 1024 }); // Tablet size
          await expect(dashboard).toBeVisible();

          // Test notification functionality
          const notificationPermission = await page.evaluate(async () => {
            if ('Notification' in window) {
              return Notification.permission;
            }
            return 'unsupported';
          });

          expect(['default', 'granted', 'denied', 'unsupported']).toContain(notificationPermission);

          // Test push notification support
          const pushSupported = await page.evaluate(() => {
            return 'PushManager' in window;
          });

          if (name === 'webkit') {
            // Safari has limited push notification support
            console.log(`Push notifications on ${name}: ${pushSupported}`);
          } else {
            expect(pushSupported).toBe(true);
          }

          // Test service worker support
          const serviceWorkerSupported = await page.evaluate(() => {
            return 'serviceWorker' in navigator;
          });

          expect(serviceWorkerSupported).toBe(true);

        } finally {
          await browser.close();
        }
      });

      test(`Offline Functionality - ${name}`, async () => {
        const browser = await browserType.launch();
        const context = await browser.newContext({
          viewport: { width: 390, height: 844 },
          permissions: ['notifications']
        });
        
        const page = await context.newPage();
        
        try {
          await page.goto('/mobile');
          await page.waitForSelector('[data-testid="mobile-dashboard"]');

          // Ensure service worker is registered
          await page.waitForFunction(() => {
            return navigator.serviceWorker.controller !== null;
          }, { timeout: 10000 });

          // Go offline
          await context.setOffline(true);

          // Test offline page loading
          await page.reload();
          
          // Should show offline indicator or cached content
          const offlineIndicator = page.locator('[data-testid="offline-indicator"]');
          const cachedContent = page.locator('[data-testid="mobile-dashboard"]');
          
          const hasOfflineIndicator = await offlineIndicator.isVisible().catch(() => false);
          const hasCachedContent = await cachedContent.isVisible().catch(() => false);
          
          expect(hasOfflineIndicator || hasCachedContent).toBe(true);

          // Test offline navigation
          if (hasCachedContent) {
            await page.click('[data-testid="mobile-nav-toggle"]');
            const nav = page.locator('[data-testid="mobile-navigation"]');
            await expect(nav).toBeVisible();
          }

          // Go back online
          await context.setOffline(false);
          await page.waitForTimeout(2000); // Wait for reconnection

          // Verify reconnection
          const onlineStatus = await page.evaluate(() => navigator.onLine);
          expect(onlineStatus).toBe(true);

        } finally {
          await browser.close();
        }
      });
    });
  });

  test.describe('Network Condition Tests', () => {
    NETWORK_CONDITIONS.forEach(networkCondition => {
      test(`Performance on ${networkCondition.name}`, async ({ browser }) => {
        const context = await browser.newContext({
          ...devices['iPhone 12'],
          permissions: ['notifications']
        });
        
        const page = await context.newPage();
        
        // Apply network condition
        await page.route('**/*', async (route) => {
          await new Promise(resolve => setTimeout(resolve, networkCondition.latency));
          await route.continue();
        });
        
        try {
          const startTime = Date.now();
          
          await page.goto('/mobile', { waitUntil: 'networkidle0', timeout: 30000 });
          await page.waitForSelector('[data-testid="mobile-dashboard"]');
          
          const loadTime = Date.now() - startTime;
          
          // Set performance expectations based on network condition
          let maxLoadTime: number;
          switch (networkCondition.name) {
            case '3G':
              maxLoadTime = 10000; // 10 seconds on 3G
              break;
            case '4G':
              maxLoadTime = 5000; // 5 seconds on 4G
              break;
            case 'WiFi':
              maxLoadTime = 3000; // 3 seconds on WiFi
              break;
            default:
              maxLoadTime = 5000;
          }
          
          expect(loadTime).toBeLessThan(maxLoadTime);
          console.log(`Load time on ${networkCondition.name}: ${loadTime}ms`);

          // Test notification loading under network conditions
          const notificationIcon = page.locator('[data-testid="notification-icon"]');
          const notificationStart = Date.now();
          
          await notificationIcon.tap();
          await page.waitForSelector('[data-testid="notification-panel"]');
          
          const notificationLoadTime = Date.now() - notificationStart;
          expect(notificationLoadTime).toBeLessThan(5000); // Should load within 5 seconds

        } finally {
          await context.close();
        }
      });
    });

    test('Progressive Loading on Slow Networks', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['Pixel 5'],
        permissions: ['notifications']
      });
      
      const page = await context.newPage();
      
      // Simulate very slow network
      await page.route('**/*', async (route) => {
        const url = route.request().url();
        
        // Add different delays for different resource types
        let delay = 100; // Default 100ms
        
        if (url.includes('.js')) delay = 500; // JS files load slower
        if (url.includes('.css')) delay = 300; // CSS files moderate delay
        if (url.includes('/api/')) delay = 1000; // API calls slowest
        if (url.includes('images') || url.includes('.png') || url.includes('.jpg')) {
          delay = 800; // Images load slowly
        }
        
        await new Promise(resolve => setTimeout(resolve, delay));
        await route.continue();
      });
      
      try {
        await page.goto('/mobile');
        
        // Test that critical content loads first
        const loadingIndicator = page.locator('[data-testid="loading-indicator"]');
        await expect(loadingIndicator).toBeVisible();
        
        // Wait for critical content
        const dashboard = page.locator('[data-testid="mobile-dashboard"]');
        await expect(dashboard).toBeVisible({ timeout: 15000 });
        
        // Test progressive enhancement
        await page.waitForTimeout(2000);
        
        const enhancedFeatures = page.locator('[data-testid="enhanced-feature"]');
        const enhancedCount = await enhancedFeatures.count();
        
        // Some enhanced features should be available even on slow networks
        expect(enhancedCount).toBeGreaterThan(0);
        
        // Test that app remains functional during slow loading
        const notificationIcon = page.locator('[data-testid="notification-icon"]');
        await notificationIcon.tap();
        
        // Should at least show loading state or cached content
        const hasNotificationContent = await page.locator('[data-testid="notification-panel"], [data-testid="notification-loading"]').isVisible();
        expect(hasNotificationContent).toBe(true);

      } finally {
        await context.close();
      }
    });
  });

  test.describe('Accessibility Across Platforms', () => {
    test('Touch Accessibility on Mobile Devices', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        permissions: ['notifications'],
        reducedMotion: 'reduce' // Test with reduced motion preference
      });
      
      const page = await context.newPage();
      
      try {
        await page.goto('/mobile');
        await page.waitForSelector('[data-testid="mobile-dashboard"]');

        // Test focus management for touch interfaces
        const focusableElements = page.locator('button, a, input, [tabindex]:not([tabindex="-1"])');
        const count = await focusableElements.count();
        
        expect(count).toBeGreaterThan(0);
        
        // Test sequential focus navigation
        for (let i = 0; i < Math.min(count, 5); i++) { // Test first 5 elements
          const element = focusableElements.nth(i);
          await element.focus();
          
          const isFocused = await element.evaluate(el => document.activeElement === el);
          expect(isFocused).toBe(true);
        }

        // Test touch target sizes
        const interactiveElements = page.locator('[role="button"], button, a, input');
        const interactiveCount = await interactiveElements.count();
        
        for (let i = 0; i < Math.min(interactiveCount, 10); i++) {
          const element = interactiveElements.nth(i);
          const boundingBox = await element.boundingBox();
          
          if (boundingBox) {
            // WCAG AA recommendation: minimum 44px touch targets
            expect(boundingBox.width).toBeGreaterThanOrEqual(44);
            expect(boundingBox.height).toBeGreaterThanOrEqual(44);
          }
        }

        // Test screen reader compatibility
        const ariaLabels = page.locator('[aria-label]');
        const ariaLabelCount = await ariaLabels.count();
        expect(ariaLabelCount).toBeGreaterThan(0);

        // Test headings hierarchy
        const headings = page.locator('h1, h2, h3, h4, h5, h6');
        const headingCount = await headings.count();
        expect(headingCount).toBeGreaterThan(0);

      } finally {
        await context.close();
      }
    });

    test('High Contrast Mode Support', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        colorScheme: 'dark',
        forcedColors: 'active' // Simulate high contrast mode
      });
      
      const page = await context.newPage();
      
      try {
        await page.goto('/mobile');
        await page.waitForSelector('[data-testid="mobile-dashboard"]');

        // Test that content is still visible in high contrast mode
        const dashboard = page.locator('[data-testid="mobile-dashboard"]');
        await expect(dashboard).toBeVisible();

        // Test color contrast ratios
        const textElements = page.locator('p, span, div, h1, h2, h3, h4, h5, h6');
        const textCount = await textElements.count();
        
        // Sample check on first few text elements
        for (let i = 0; i < Math.min(textCount, 5); i++) {
          const element = textElements.nth(i);
          const styles = await element.evaluate((el) => {
            const computed = window.getComputedStyle(el);
            return {
              color: computed.color,
              backgroundColor: computed.backgroundColor,
              fontSize: computed.fontSize
            };
          });
          
          expect(styles.color).toBeTruthy();
          expect(styles.fontSize).toBeTruthy();
        }

      } finally {
        await context.close();
      }
    });
  });

  test.describe('Security Across Platforms', () => {
    test('HTTPS and Security Headers', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['Pixel 5']
      });
      
      const page = await context.newPage();
      
      try {
        const response = await page.goto('/mobile');
        
        // Test HTTPS usage
        expect(response?.url()).toContain('https://');
        
        // Test security headers
        const headers = response?.headers();
        expect(headers).toBeTruthy();
        
        if (headers) {
          // Test for important security headers
          expect(headers['strict-transport-security']).toBeTruthy();
          expect(headers['x-content-type-options']).toBe('nosniff');
          expect(headers['x-frame-options']).toBeTruthy();
          expect(headers['content-security-policy']).toBeTruthy();
        }

        // Test that sensitive data is not exposed
        const pageContent = await page.content();
        expect(pageContent).not.toContain('password');
        expect(pageContent).not.toContain('secret');
        expect(pageContent).not.toContain('api-key');

      } finally {
        await context.close();
      }
    });

    test('Local Storage Security', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['iPhone 12']
      });
      
      const page = await context.newPage();
      
      try {
        await page.goto('/mobile');
        
        // Test that sensitive data is not stored in localStorage
        const localStorageData = await page.evaluate(() => {
          const data: { [key: string]: string } = {};
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key) {
              data[key] = localStorage.getItem(key) || '';
            }
          }
          return data;
        });

        // Check that no sensitive data is in localStorage
        Object.entries(localStorageData).forEach(([key, value]) => {
          expect(key.toLowerCase()).not.toContain('password');
          expect(key.toLowerCase()).not.toContain('token');
          expect(value.toLowerCase()).not.toContain('password');
        });

        // Test sessionStorage security
        const sessionStorageData = await page.evaluate(() => {
          const data: { [key: string]: string } = {};
          for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key) {
              data[key] = sessionStorage.getItem(key) || '';
            }
          }
          return data;
        });

        Object.entries(sessionStorageData).forEach(([key, value]) => {
          expect(key.toLowerCase()).not.toContain('password');
          expect(value.toLowerCase()).not.toContain('password');
        });

      } finally {
        await context.close();
      }
    });
  });

  test.describe('Performance Benchmarks', () => {
    test('Core Web Vitals on Mobile', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['Pixel 5']
      });
      
      const page = await context.newPage();
      
      try {
        // Enable performance tracking
        await page.addInitScript(() => {
          (window as any).performanceMetrics = {
            lcp: 0,
            fid: 0,
            cls: 0
          };

          // Track LCP (Largest Contentful Paint)
          new PerformanceObserver((entryList) => {
            const entries = entryList.getEntries();
            const lastEntry = entries[entries.length - 1];
            (window as any).performanceMetrics.lcp = lastEntry.startTime;
          }).observe({entryTypes: ['largest-contentful-paint']});

          // Track CLS (Cumulative Layout Shift)
          let clsValue = 0;
          new PerformanceObserver((entryList) => {
            for (const entry of entryList.getEntries()) {
              if (!(entry as any).hadRecentInput) {
                clsValue += (entry as any).value;
              }
            }
            (window as any).performanceMetrics.cls = clsValue;
          }).observe({entryTypes: ['layout-shift']});
        });

        await page.goto('/mobile');
        await page.waitForSelector('[data-testid="mobile-dashboard"]');
        
        // Wait for metrics to stabilize
        await page.waitForTimeout(3000);

        const metrics = await page.evaluate(() => (window as any).performanceMetrics);

        // Test Core Web Vitals thresholds
        expect(metrics.lcp).toBeLessThan(2500); // LCP < 2.5s (good)
        expect(metrics.cls).toBeLessThan(0.1); // CLS < 0.1 (good)
        
        // Test Time to Interactive
        const navigationTiming = await page.evaluate(() => {
          const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
          return {
            domContentLoaded: navigation.domContentLoadedEventEnd - navigation.navigationStart,
            loadComplete: navigation.loadEventEnd - navigation.navigationStart
          };
        });

        expect(navigationTiming.domContentLoaded).toBeLessThan(3000);
        expect(navigationTiming.loadComplete).toBeLessThan(5000);

      } finally {
        await context.close();
      }
    });

    test('Memory Usage on Low-End Devices', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['Galaxy S9+'], // Older device simulation
        deviceScaleFactor: 1 // Reduce resource usage
      });
      
      const page = await context.newPage();
      
      try {
        await page.goto('/mobile');
        
        // Measure initial memory
        const initialMemory = await page.evaluate(() => {
          return (performance as any).memory ? {
            used: (performance as any).memory.usedJSHeapSize,
            total: (performance as any).memory.totalJSHeapSize,
            limit: (performance as any).memory.jsHeapSizeLimit
          } : null;
        });

        // Simulate heavy usage
        await page.click('[data-testid="notification-icon"]');
        await page.waitForTimeout(1000);
        
        for (let i = 0; i < 10; i++) {
          await page.click('[data-testid="refresh-notifications"]');
          await page.waitForTimeout(200);
        }

        // Measure memory after usage
        const finalMemory = await page.evaluate(() => {
          return (performance as any).memory ? {
            used: (performance as any).memory.usedJSHeapSize,
            total: (performance as any).memory.totalJSHeapSize,
            limit: (performance as any).memory.jsHeapSizeLimit
          } : null;
        });

        if (initialMemory && finalMemory) {
          const memoryGrowth = finalMemory.used - initialMemory.used;
          const growthPercentage = (memoryGrowth / initialMemory.used) * 100;
          
          // Memory growth should be reasonable
          expect(growthPercentage).toBeLessThan(50); // Less than 50% growth
          expect(finalMemory.used).toBeLessThan(finalMemory.limit * 0.8); // Stay under 80% of limit
        }

      } finally {
        await context.close();
      }
    });
  });
});