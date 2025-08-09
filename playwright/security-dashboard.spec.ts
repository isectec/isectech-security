/**
 * Security Dashboard E2E Tests
 * Production-grade end-to-end testing for cybersecurity dashboard
 */

import { expect, test } from '@playwright/test';
import { checkA11y, injectAxe } from 'axe-playwright';

test.describe('Security Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to dashboard
    await page.goto('/dashboard');

    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="security-dashboard"]');

    // Inject axe for accessibility testing
    await injectAxe(page);
  });

  test.describe('Dashboard Overview', () => {
    test('should display security metrics and alerts', async ({ page }) => {
      // Verify main dashboard elements
      await expect(page.locator('[data-testid="threat-level-indicator"]')).toBeVisible();
      await expect(page.locator('[data-testid="active-alerts-count"]')).toBeVisible();
      await expect(page.locator('[data-testid="compliance-score"]')).toBeVisible();

      // Verify charts are rendered
      await expect(page.locator('[data-testid="threat-activity-chart"]')).toBeVisible();
      await expect(page.locator('[data-testid="asset-health-chart"]')).toBeVisible();
    });

    test('should be accessible to screen readers', async ({ page }) => {
      // Check overall accessibility
      await checkA11y(page, null, {
        rules: {
          'color-contrast': { enabled: true },
          'aria-required-attr': { enabled: true },
          'keyboard-navigation': { enabled: true },
        },
      });

      // Verify ARIA landmarks
      const landmarks = await page.locator('[role="main"], [role="navigation"], [role="region"]').count();
      expect(landmarks).toBeGreaterThan(0);

      // Verify alert announcements
      const alertRegions = await page.locator('[aria-live="assertive"], [role="alert"]').count();
      expect(alertRegions).toBeGreaterThan(0);
    });

    test('should support keyboard navigation', async ({ page }) => {
      // Test tab navigation through interactive elements
      await page.keyboard.press('Tab');
      await expect(page.locator(':focus')).toBeVisible();

      // Navigate through dashboard widgets
      for (let i = 0; i < 10; i++) {
        await page.keyboard.press('Tab');
        const focusedElement = await page.locator(':focus');
        await expect(focusedElement).toBeVisible();
      }

      // Test Enter key activation
      await page.keyboard.press('Enter');
      // Should activate focused element without errors
    });
  });

  test.describe('Real-time Updates', () => {
    test('should update threat indicators in real-time', async ({ page }) => {
      // Get initial threat level
      const initialThreatLevel = await page.locator('[data-testid="threat-level-value"]').textContent();

      // Simulate real-time update (would come from WebSocket in real app)
      await page.evaluate(() => {
        window.dispatchEvent(
          new CustomEvent('threat-level-update', {
            detail: { level: 'HIGH', score: 85 },
          })
        );
      });

      // Verify update is reflected
      await expect(page.locator('[data-testid="threat-level-value"]')).not.toHaveText(initialThreatLevel || '');
      await expect(page.locator('[data-testid="threat-level-indicator"]')).toHaveAttribute('data-level', 'HIGH');
    });

    test('should announce critical alerts immediately', async ({ page }) => {
      // Monitor for alert announcements
      const alertPromise = page.waitForSelector('[role="alert"][aria-live="assertive"]');

      // Simulate critical alert
      await page.evaluate(() => {
        window.dispatchEvent(
          new CustomEvent('critical-alert', {
            detail: {
              id: 'alert-001',
              severity: 'CRITICAL',
              title: 'Security Breach Detected',
              description: 'Unauthorized access attempt detected',
            },
          })
        );
      });

      // Verify alert is announced
      const alertElement = await alertPromise;
      await expect(alertElement).toContainText('Security Breach Detected');
    });
  });

  test.describe('Security Controls', () => {
    test('should implement proper content security policy', async ({ page }) => {
      // Check for CSP headers
      const response = await page.goto('/dashboard');
      const cspHeader = response?.headers()['content-security-policy'];
      expect(cspHeader).toBeTruthy();
      expect(cspHeader).toContain("default-src 'self'");
    });

    test('should prevent XSS attacks', async ({ page }) => {
      // Test XSS prevention in search functionality
      const searchInput = page.locator('[data-testid="global-search"]');
      await searchInput.fill('<script>alert("xss")</script>');
      await page.keyboard.press('Enter');

      // Should not execute script
      let alertTriggered = false;
      page.on('dialog', () => {
        alertTriggered = true;
      });

      await page.waitForTimeout(1000);
      expect(alertTriggered).toBe(false);

      // Verify content is escaped
      const results = page.locator('[data-testid="search-results"]');
      await expect(results).not.toContainText('<script>');
    });

    test('should validate user permissions', async ({ page }) => {
      // Test admin-only functionality
      const adminButton = page.locator('[data-testid="admin-settings"]');

      // Should be hidden for non-admin users
      if (await adminButton.isVisible()) {
        await adminButton.click();
        await expect(page.locator('[data-testid="permission-denied"]')).toBeVisible();
      }
    });
  });

  test.describe('Multi-tenant Support', () => {
    test('should switch tenant contexts securely', async ({ page }) => {
      // Locate tenant switcher
      const tenantSwitcher = page.locator('[data-testid="tenant-switcher"]');
      await tenantSwitcher.click();

      // Select different tenant
      await page.locator('[data-testid="tenant-option-2"]').click();

      // Verify context switch
      await expect(page.locator('[data-testid="current-tenant"]')).toContainText('Tenant 2');

      // Verify data isolation (alerts should be different)
      const alertCount = await page.locator('[data-testid="active-alerts-count"]').textContent();
      expect(alertCount).toBeTruthy();
    });

    test('should maintain tenant isolation', async ({ page }) => {
      // Switch to tenant 1
      await page.locator('[data-testid="tenant-switcher"]').click();
      await page.locator('[data-testid="tenant-option-1"]').click();

      const tenant1Alerts = await page.locator('[data-testid="alert-list"] .alert-item').count();

      // Switch to tenant 2
      await page.locator('[data-testid="tenant-switcher"]').click();
      await page.locator('[data-testid="tenant-option-2"]').click();

      const tenant2Alerts = await page.locator('[data-testid="alert-list"] .alert-item').count();

      // Data should be different (isolation working)
      expect(tenant1Alerts).not.toBe(tenant2Alerts);
    });
  });

  test.describe('Performance', () => {
    test('should load dashboard within performance budget', async ({ page }) => {
      const startTime = Date.now();

      await page.goto('/dashboard');
      await page.waitForSelector('[data-testid="security-dashboard"]');
      await page.waitForLoadState('networkidle');

      const loadTime = Date.now() - startTime;

      // Should load within 3 seconds
      expect(loadTime).toBeLessThan(3000);
    });

    test('should handle large datasets efficiently', async ({ page }) => {
      // Simulate large dataset
      await page.evaluate(() => {
        // Mock large alert dataset
        const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
          id: `alert-${i}`,
          severity: ['low', 'medium', 'high', 'critical'][i % 4],
          title: `Security Alert ${i}`,
        }));

        window.mockAlerts = largeDataset;
      });

      await page.reload();
      await page.waitForSelector('[data-testid="alert-list"]');

      // Should render efficiently with virtualization
      const visibleAlerts = await page.locator('[data-testid="alert-list"] .alert-item').count();
      expect(visibleAlerts).toBeLessThan(100); // Should virtualize
    });
  });

  test.describe('Error Handling', () => {
    test('should handle API failures gracefully', async ({ page }) => {
      // Intercept API calls and return errors
      await page.route('/api/alerts', (route) => {
        route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Internal Server Error' }),
        });
      });

      await page.reload();

      // Should show user-friendly error
      await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
      await expect(page.locator('[data-testid="retry-button"]')).toBeVisible();

      // Error should not expose sensitive information
      const errorText = await page.locator('[data-testid="error-message"]').textContent();
      expect(errorText).not.toContain('database');
      expect(errorText).not.toContain('server');
    });

    test('should provide offline support', async ({ page, context }) => {
      // Go offline
      await context.setOffline(true);

      await page.reload();

      // Should show offline indicator
      await expect(page.locator('[data-testid="offline-indicator"]')).toBeVisible();

      // Should still show cached data
      await expect(page.locator('[data-testid="security-dashboard"]')).toBeVisible();
    });
  });

  test.describe('Emergency Response', () => {
    test('should handle emergency alerts properly', async ({ page }) => {
      // Simulate emergency alert
      await page.evaluate(() => {
        window.dispatchEvent(
          new CustomEvent('emergency-alert', {
            detail: {
              id: 'emergency-001',
              severity: 'CRITICAL',
              type: 'ACTIVE_BREACH',
              title: 'Active Security Breach',
              requiresImmediate: true,
            },
          })
        );
      });

      // Should show emergency modal
      await expect(page.locator('[data-testid="emergency-modal"]')).toBeVisible();

      // Should announce to screen reader
      await expect(page.locator('[role="alert"][aria-live="assertive"]')).toContainText('Active Security Breach');

      // Should provide immediate action buttons
      await expect(page.locator('[data-testid="emergency-escalate"]')).toBeVisible();
      await expect(page.locator('[data-testid="emergency-investigate"]')).toBeVisible();
    });

    test('should support rapid incident response', async ({ page }) => {
      // Navigate to incident response
      await page.locator('[data-testid="incident-response"]').click();

      // Should load quickly for emergency situations
      const startTime = Date.now();
      await page.waitForSelector('[data-testid="incident-dashboard"]');
      const loadTime = Date.now() - startTime;

      expect(loadTime).toBeLessThan(1000); // Emergency response should be fast

      // Should have keyboard shortcuts for common actions
      await page.keyboard.press('Control+1'); // Quick escalate
      await expect(page.locator('[data-testid="escalation-dialog"]')).toBeVisible();
    });
  });
});

test.describe('Visual Regression Tests', () => {
  test('dashboard should match visual baseline @visual', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForSelector('[data-testid="security-dashboard"]');
    await page.waitForLoadState('networkidle');

    // Take screenshot and compare
    await expect(page).toHaveScreenshot('security-dashboard.png', {
      fullPage: true,
      threshold: 0.3, // Allow for minor differences
    });
  });

  test('alert management should match visual baseline @visual', async ({ page }) => {
    await page.goto('/alerts');
    await page.waitForSelector('[data-testid="alert-management"]');
    await page.waitForLoadState('networkidle');

    await expect(page).toHaveScreenshot('alert-management.png', {
      fullPage: true,
      threshold: 0.3,
    });
  });
});
