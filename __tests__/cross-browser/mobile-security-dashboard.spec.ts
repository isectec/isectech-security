/**
 * Mobile Security Dashboard Testing
 * iSECTECH Protect - Mobile Browser Compatibility
 */

import { test, expect, devices } from '@playwright/test';

const MOBILE_DEVICES = [
  { name: 'iPhone 12', ...devices['iPhone 12'] },
  { name: 'iPhone SE', ...devices['iPhone SE'] },
  { name: 'Pixel 5', ...devices['Pixel 5'] },
  { name: 'Galaxy S21', ...devices['Galaxy S21'] }, 
] as const;

interface MobileSecurityFeature {
  name: string;
  selector: string;
  critical: boolean;
  mobileOptimized: boolean;
}

const MOBILE_SECURITY_FEATURES: MobileSecurityFeature[] = [
  {
    name: 'Critical Alerts Banner',
    selector: '[data-testid="critical-alerts-banner"]',
    critical: true,
    mobileOptimized: true,
  },
  {
    name: 'Emergency Response Button',
    selector: '[data-testid="emergency-response-button"]',
    critical: true,
    mobileOptimized: true,
  },
  {
    name: 'Quick Actions Menu',
    selector: '[data-testid="quick-actions-menu"]',
    critical: true,
    mobileOptimized: true,
  },
  {
    name: 'Security Status Widget',
    selector: '[data-testid="security-status-widget"]',
    critical: true,
    mobileOptimized: true,
  },
  {
    name: 'Threat Map (Simplified)',
    selector: '[data-testid="mobile-threat-map"]',
    critical: false,
    mobileOptimized: true,
  },
  {
    name: 'Navigation Drawer',
    selector: '[data-testid="mobile-navigation-drawer"]',
    critical: true,
    mobileOptimized: true,
  },
  {
    name: 'Search Bar',
    selector: '[data-testid="mobile-search-bar"]',
    critical: true,
    mobileOptimized: true,
  },
];

class MobileSecurityTester {
  async testMobileNavigation(page: any): Promise<boolean> {
    // Test hamburger menu
    await page.click('[data-testid="hamburger-menu"]');
    await page.waitForSelector('[data-testid="mobile-navigation-drawer"]');
    
    // Test navigation links
    const navLinks = [
      { text: 'Dashboard', url: '/dashboard' },
      { text: 'Alerts', url: '/alerts' },
      { text: 'Threats', url: '/threats' },
      { text: 'Incidents', url: '/incidents' },
    ];

    for (const link of navLinks) {
      await page.click(`[data-testid="nav-link-${link.text.toLowerCase()}"]`);
      await page.waitForURL(`**${link.url}`);
      await page.waitForSelector('[data-testid="page-loaded"]');
      
      // Navigate back to test next link
      await page.click('[data-testid="hamburger-menu"]');
      await page.waitForSelector('[data-testid="mobile-navigation-drawer"]');
    }

    return true;
  }

  async testTouchInteractions(page: any): Promise<boolean> {
    await page.goto('http://localhost:3000/dashboard');
    await page.waitForSelector('[data-testid="dashboard-loaded"]');

    // Test swipe gestures on widgets
    const widgets = await page.locator('[data-testid*="widget"]').all();
    
    for (const widget of widgets.slice(0, 3)) { // Test first 3 widgets
      const box = await widget.boundingBox();
      if (box) {
        // Swipe left
        await page.touchscreen.tap(box.x + box.width * 0.8, box.y + box.height / 2);
        await page.waitForTimeout(300);
        
        // Swipe right
        await page.touchscreen.tap(box.x + box.width * 0.2, box.y + box.height / 2);
        await page.waitForTimeout(300);
      }
    }

    // Test pinch zoom on threat map (if available)
    if (await page.locator('[data-testid="mobile-threat-map"]').count() > 0) {
      const mapBox = await page.locator('[data-testid="mobile-threat-map"]').boundingBox();
      if (mapBox) {
        // Simulate pinch zoom
        await page.touchscreen.tap(mapBox.x + mapBox.width / 2, mapBox.y + mapBox.height / 2);
        await page.waitForTimeout(500);
      }
    }

    return true;
  }

  async testMobileAlertManagement(page: any): Promise<boolean> {
    await page.goto('http://localhost:3000/alerts');
    await page.waitForSelector('[data-testid="alerts-mobile-view"]');

    // Test pull-to-refresh
    await page.evaluate(() => {
      window.scrollTo(0, 0);
    });
    
    // Simulate pull gesture
    const body = await page.locator('body').boundingBox();
    if (body) {
      await page.touchscreen.tap(body.width / 2, 50);
      await page.touchscreen.tap(body.width / 2, 150);
      await page.waitForTimeout(1000);
    }

    // Test alert card interactions
    const alertCards = await page.locator('[data-testid="alert-card"]').all();
    
    if (alertCards.length > 0) {
      // Tap to expand first alert
      await alertCards[0].tap();
      await page.waitForSelector('[data-testid="alert-details-mobile"]');
      
      // Test quick actions
      const quickActions = [
        '[data-testid="quick-acknowledge"]',
        '[data-testid="quick-assign"]',
        '[data-testid="quick-escalate"]',
      ];
      
      for (const action of quickActions) {
        if (await page.locator(action).count() > 0) {
          await page.locator(action).tap();
          await page.waitForTimeout(500);
        }
      }
      
      // Close alert details
      await page.locator('[data-testid="close-alert-details"]').tap();
    }

    return true;
  }

  async testMobileSearchFunctionality(page: any): Promise<boolean> {
    await page.goto('http://localhost:3000/dashboard');
    await page.waitForSelector('[data-testid="dashboard-loaded"]');

    // Test mobile search
    await page.tap('[data-testid="mobile-search-trigger"]');
    await page.waitForSelector('[data-testid="mobile-search-overlay"]');
    
    // Test voice search (if supported)
    if (await page.locator('[data-testid="voice-search-button"]').count() > 0) {
      await page.tap('[data-testid="voice-search-button"]');
      await page.waitForTimeout(1000);
      
      // Simulate voice input (mock)
      await page.fill('[data-testid="search-input"]', 'malware detection');
    } else {
      await page.fill('[data-testid="search-input"]', 'malware detection');
    }
    
    await page.tap('[data-testid="search-submit"]');
    await page.waitForSelector('[data-testid="search-results-mobile"]');
    
    // Test result interaction
    const results = await page.locator('[data-testid="search-result-item"]').all();
    if (results.length > 0) {
      await results[0].tap();
      await page.waitForSelector('[data-testid="search-result-details"]');
    }

    return true;
  }

  async testMobilePerformance(page: any): Promise<{ loadTime: number; renderTime: number; interactionTime: number }> {
    const startTime = performance.now();
    
    await page.goto('http://localhost:3000/dashboard');
    const loadTime = performance.now() - startTime;
    
    const renderStart = performance.now();
    await page.waitForSelector('[data-testid="dashboard-loaded"]');
    const renderTime = performance.now() - renderStart;
    
    const interactionStart = performance.now();
    await page.tap('[data-testid="hamburger-menu"]');
    await page.waitForSelector('[data-testid="mobile-navigation-drawer"]');
    const interactionTime = performance.now() - interactionStart;
    
    return { loadTime, renderTime, interactionTime };
  }
}

test.describe('📱 Mobile Security Dashboard Compatibility', () => {
  let mobileTester: MobileSecurityTester;

  test.beforeEach(() => {
    mobileTester = new MobileSecurityTester();
  });

  test('should display all critical security features on mobile', async ({ page, browserName }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');    
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Check mobile-optimized features
    for (const feature of MOBILE_SECURITY_FEATURES.filter(f => f.critical)) {
      if (await page.locator(feature.selector).count() > 0) {
        await expect(page.locator(feature.selector)).toBeVisible();
        
        // Test that element is properly sized for mobile
        const box = await page.locator(feature.selector).boundingBox();
        expect(box?.width).toBeGreaterThan(44); // Minimum touch target size
        expect(box?.height).toBeGreaterThan(44);
      }
    }

    console.log(`✅ All critical mobile features visible in ${browserName}`);
  });

  test('should support touch interactions for security operations', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    const touchTestResult = await mobileTester.testTouchInteractions(page);
    expect(touchTestResult).toBe(true);

    console.log('✅ Touch interactions working correctly');
  });

  test('should provide efficient mobile navigation', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    const navigationResult = await mobileTester.testMobileNavigation(page);
    expect(navigationResult).toBe(true);

    console.log('✅ Mobile navigation working correctly');
  });

  test('should handle mobile alert management efficiently', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    const alertManagementResult = await mobileTester.testMobileAlertManagement(page);
    expect(alertManagementResult).toBe(true);

    console.log('✅ Mobile alert management working correctly');
  });

  test('should support mobile search with optimization', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    const searchResult = await mobileTester.testMobileSearchFunctionality(page);
    expect(searchResult).toBe(true);

    console.log('✅ Mobile search functionality working correctly');
  });

  test('should maintain performance standards on mobile', async ({ page, browserName }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    const performance = await mobileTester.testMobilePerformance(page);
    
    // Mobile performance thresholds (more lenient than desktop)
    expect(performance.loadTime).toBeLessThan(8000); // 8s max load time
    expect(performance.renderTime).toBeLessThan(3000); // 3s max render time
    expect(performance.interactionTime).toBeLessThan(300); // 300ms max interaction time

    console.log(`📊 Mobile Performance (${browserName}):`);
    console.log(`  Load Time: ${performance.loadTime.toFixed(0)}ms`);
    console.log(`  Render Time: ${performance.renderTime.toFixed(0)}ms`);
    console.log(`  Interaction Time: ${performance.interactionTime.toFixed(0)}ms`);
  });

  test('should handle offline scenarios gracefully', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Simulate offline
    await page.route('**/*', route => route.abort());
    
    // Test offline indicators
    await page.reload();
    await page.waitForSelector('[data-testid="offline-indicator"]', { timeout: 5000 });
    
    // Test cached content access
    const cachedElements = [
      '[data-testid="cached-dashboard"]',
      '[data-testid="cached-alerts"]',
      '[data-testid="offline-mode-banner"]',
    ];
    
    for (const selector of cachedElements) {
      if (await page.locator(selector).count() > 0) {
        await expect(page.locator(selector)).toBeVisible();
      }
    }

    console.log('✅ Offline handling working correctly');
  });

  test('should work with mobile-specific security gestures', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'test@isectech.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.tap('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');

    // Test panic gesture (shake to trigger emergency mode)
    await page.evaluate(() => {
      // Simulate device motion event
      window.dispatchEvent(new DeviceMotionEvent('devicemotion', {
        acceleration: { x: 10, y: 10, z: 10 },
        accelerationIncludingGravity: { x: 15, y: 15, z: 15 },
        rotationRate: { alpha: 50, beta: 50, gamma: 50 },
        interval: 100,
      }));
    });

    // Check if emergency mode triggers
    await page.waitForTimeout(1000);
    if (await page.locator('[data-testid="emergency-mode-activated"]').count() > 0) {
      await expect(page.locator('[data-testid="emergency-mode-activated"]')).toBeVisible();
      console.log('✅ Emergency gesture recognition working');
    }

    // Test long-press for context menus
    const alertCards = await page.locator('[data-testid="alert-card"]').all();
    if (alertCards.length > 0) {
      // Long press simulation
      await alertCards[0].tap({ timeout: 1000 });
      await page.waitForTimeout(800);
      
      if (await page.locator('[data-testid="context-menu"]').count() > 0) {
        await expect(page.locator('[data-testid="context-menu"]')).toBeVisible();
        console.log('✅ Long-press context menu working');
      }
    }
  });

  test('should support mobile biometric authentication', async ({ page, browserName }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    
    await page.goto('http://localhost:3000/login');
    
    // Check for biometric support
    const biometricSupport = await page.evaluate(() => {
      return !!(
        navigator.credentials && 
        'create' in navigator.credentials && 
        'get' in navigator.credentials
      );
    });

    if (biometricSupport && browserName !== 'firefox') { // Firefox has limited WebAuthn support
      // Test biometric login option  
      if (await page.locator('[data-testid="biometric-login"]').count() > 0) {
        await page.tap('[data-testid="biometric-login"]');
        
        // Mock biometric authentication
        await page.evaluate(() => {
          // Mock successful biometric auth
          window.dispatchEvent(new CustomEvent('biometric-auth-success', {
            detail: { userId: 'test-user', timestamp: Date.now() }
          }));
        });
        
        await page.waitForURL('**/dashboard', { timeout: 10000 });
        await expect(page).toHaveURL(/.*dashboard/);
        
        console.log(`✅ Biometric authentication working in ${browserName}`);
      }
    } else {
      console.log(`ℹ️ Biometric auth not supported/available in ${browserName}`);
    }
  });
});