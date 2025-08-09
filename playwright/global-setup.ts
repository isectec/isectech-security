/**
 * Playwright Global Setup for iSECTECH Protect
 * Sets up authentication and test environment
 */

import { chromium, FullConfig } from '@playwright/test';
import path from 'path';

async function globalSetup(config: FullConfig) {
  console.log('🔧 Setting up Playwright test environment...');

  // Create auth directory
  const authDir = path.join(__dirname, '.auth');
  const fs = await import('fs/promises');
  await fs.mkdir(authDir, { recursive: true });

  const browser = await chromium.launch();

  // Setup authentication for different user roles
  await setupAuthentication(browser, 'user', 'analyst@isectech.com', 'password123');
  await setupAuthentication(browser, 'analyst', 'analyst@isectech.com', 'password123');
  await setupAuthentication(browser, 'admin', 'admin@isectech.com', 'admin123');

  await browser.close();

  console.log('✅ Playwright global setup complete');
}

async function setupAuthentication(browser: any, role: string, email: string, password: string) {
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Navigate to login page
    await page.goto(process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000');

    // Check if already logged in
    const isLoggedIn = await page
      .locator('[data-testid="user-menu"]')
      .isVisible()
      .catch(() => false);

    if (!isLoggedIn) {
      // Look for login form or button
      const loginButton = page.locator('[data-testid="login-button"]').first();
      const emailInput = page.locator('input[type="email"]').first();
      const passwordInput = page.locator('input[type="password"]').first();

      if (await emailInput.isVisible().catch(() => false)) {
        // Fill login form
        await emailInput.fill(email);
        await passwordInput.fill(password);
        await loginButton.click();

        // Wait for successful login
        await page.waitForLoadState('networkidle');
        await page.waitForSelector('[data-testid="user-menu"]', { timeout: 10000 });
      } else {
        console.log(`Login form not found for ${role}, creating mock authentication`);

        // Set mock authentication state
        await page.addInitScript(() => {
          window.localStorage.setItem('auth_token', 'mock-jwt-token');
          window.localStorage.setItem('user_role', role);
          window.localStorage.setItem('user_email', email);
        });
      }
    }

    // Save authentication state
    await context.storageState({
      path: path.join(__dirname, '.auth', `${role}.json`),
    });

    console.log(`✅ Authentication setup complete for ${role}`);
  } catch (error) {
    console.warn(`⚠️  Authentication setup failed for ${role}:`, error);

    // Create minimal auth state for testing
    const authState = {
      cookies: [],
      origins: [
        {
          origin: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000',
          localStorage: [
            { name: 'auth_token', value: 'mock-jwt-token' },
            { name: 'user_role', value: role },
            { name: 'user_email', value: email },
          ],
        },
      ],
    };

    const fs = await import('fs/promises');
    await fs.writeFile(path.join(__dirname, '.auth', `${role}.json`), JSON.stringify(authState, null, 2));
  } finally {
    await context.close();
  }
}

export default globalSetup;
