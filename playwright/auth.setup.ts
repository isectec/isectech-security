/**
 * Authentication Setup for Playwright Tests
 * Prepares user sessions for testing
 */

import { expect, test as setup } from '@playwright/test';

setup('authenticate as analyst', async ({ page }) => {
  console.log('🔐 Setting up analyst authentication...');

  await page.goto('/');

  // Check if login is needed
  const isLoginPage = await page
    .locator('input[type="email"]')
    .isVisible()
    .catch(() => false);

  if (isLoginPage) {
    await page.locator('input[type="email"]').fill('analyst@isectech.com');
    await page.locator('input[type="password"]').fill('password123');
    await page.locator('[data-testid="login-button"]').click();

    // Wait for successful login
    await page.waitForURL('/dashboard');
  } else {
    // Mock authentication for development
    await page.addInitScript(() => {
      window.localStorage.setItem('auth_token', 'mock-analyst-token');
      window.localStorage.setItem('user_role', 'analyst');
      window.localStorage.setItem('user_email', 'analyst@isectech.com');
    });

    await page.reload();
  }

  // Verify authentication
  await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();

  // Save authenticated state
  await page.context().storageState({ path: 'playwright/.auth/analyst.json' });

  console.log('✅ Analyst authentication complete');
});

setup('authenticate as admin', async ({ page }) => {
  console.log('🔐 Setting up admin authentication...');

  await page.goto('/');

  const isLoginPage = await page
    .locator('input[type="email"]')
    .isVisible()
    .catch(() => false);

  if (isLoginPage) {
    await page.locator('input[type="email"]').fill('admin@isectech.com');
    await page.locator('input[type="password"]').fill('admin123');
    await page.locator('[data-testid="login-button"]').click();

    await page.waitForURL('/dashboard');
  } else {
    await page.addInitScript(() => {
      window.localStorage.setItem('auth_token', 'mock-admin-token');
      window.localStorage.setItem('user_role', 'admin');
      window.localStorage.setItem('user_email', 'admin@isectech.com');
    });

    await page.reload();
  }

  await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
  await page.context().storageState({ path: 'playwright/.auth/admin.json' });

  console.log('✅ Admin authentication complete');
});

setup('authenticate as user', async ({ page }) => {
  console.log('🔐 Setting up user authentication...');

  await page.goto('/');

  const isLoginPage = await page
    .locator('input[type="email"]')
    .isVisible()
    .catch(() => false);

  if (isLoginPage) {
    await page.locator('input[type="email"]').fill('user@isectech.com');
    await page.locator('input[type="password"]').fill('user123');
    await page.locator('[data-testid="login-button"]').click();

    await page.waitForURL('/dashboard');
  } else {
    await page.addInitScript(() => {
      window.localStorage.setItem('auth_token', 'mock-user-token');
      window.localStorage.setItem('user_role', 'user');
      window.localStorage.setItem('user_email', 'user@isectech.com');
    });

    await page.reload();
  }

  await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
  await page.context().storageState({ path: 'playwright/.auth/user.json' });

  console.log('✅ User authentication complete');
});
