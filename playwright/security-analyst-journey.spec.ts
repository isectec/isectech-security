/**
 * Security Analyst Complete User Journey E2E Tests
 * iSECTECH Protect - Production Security Workflows
 */

import { test, expect, Page } from '@playwright/test';
import { SecurityTestFixtures } from './fixtures/security-fixtures';

// Test data for security scenarios
const SECURITY_TEST_DATA = {
  analyst: {
    email: 'analyst@isectech.com',
    password: 'SecureAnalyst123!',
    mfaCode: '123456',
    role: 'SECURITY_ANALYST',
    clearance: 'SECRET',
  },
  threats: {
    suspiciousIp: '192.168.1.100',
    malwareHash: 'sha256:d4f4f4f4f4f4f4f4...',
    attackVector: 'spear_phishing',
  },
  alerts: {
    critical: {
      title: 'Advanced Persistent Threat Detected',
      severity: 'CRITICAL',
      type: 'MALWARE',
      sourceIp: '192.168.1.100',
    },
    high: {
      title: 'Suspicious Network Activity',
      severity: 'HIGH', 
      type: 'NETWORK_ANOMALY',
      sourceIp: '192.168.1.101',
    },
  },
};

test.describe('🛡️ Security Analyst Complete Workflow', () => {
  let securityFixtures: SecurityTestFixtures;

  test.beforeAll(async () => {
    securityFixtures = new SecurityTestFixtures();
    await securityFixtures.setupSecurityTestEnvironment();
  });

  test.afterAll(async () => {
    await securityFixtures.cleanupSecurityTestEnvironment();
  });

  test.describe('🔐 Authentication & Session Management', () => {
    test('should complete secure login with MFA', async ({ page }) => {
      await test.step('Navigate to login page', async () => {
        await page.goto('/login');
        await expect(page.getByRole('heading', { name: 'iSECTECH Protect' })).toBeVisible();
      });

      await test.step('Enter credentials', async () => {
        await page.getByLabel('Email').fill(SECURITY_TEST_DATA.analyst.email);
        await page.getByLabel('Password').fill(SECURITY_TEST_DATA.analyst.password);
        await page.getByRole('button', { name: 'Sign In' }).click();
      });

      await test.step('Complete MFA challenge', async () => {
        await expect(page.getByText('Multi-Factor Authentication')).toBeVisible();
        await page.getByLabel('Enter 6-digit code').fill(SECURITY_TEST_DATA.analyst.mfaCode);
        await page.getByRole('button', { name: 'Verify' }).click();
      });

      await test.step('Verify successful login', async () => {
        await expect(page).toHaveURL('/dashboard');
        await expect(page.getByRole('navigation')).toBeVisible();
        await expect(page.getByText(SECURITY_TEST_DATA.analyst.email)).toBeVisible();
      });

      await test.step('Verify security context', async () => {
        await page.getByRole('button', { name: 'User Menu' }).click();
        await expect(page.getByText(SECURITY_TEST_DATA.analyst.role)).toBeVisible();
        await expect(page.getByText(SECURITY_TEST_DATA.analyst.clearance)).toBeVisible();
      });
    });

    test('should maintain session across browser refresh', async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
      
      await test.step('Navigate to alerts page', async () => {
        await page.goto('/alerts');
        await expect(page.getByRole('heading', { name: 'Security Alerts' })).toBeVisible();
      });

      await test.step('Refresh browser and verify session', async () => {
        await page.reload();
        await expect(page.getByRole('heading', { name: 'Security Alerts' })).toBeVisible();
        await expect(page.getByText(SECURITY_TEST_DATA.analyst.email)).toBeVisible();
      });
    });

    test('should logout securely and clear session', async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
      
      await test.step('Perform secure logout', async () => {
        await page.getByRole('button', { name: 'User Menu' }).click();
        await page.getByRole('menuitem', { name: 'Logout' }).click();
      });

      await test.step('Verify logout and session cleanup', async () => {
        await expect(page).toHaveURL('/login');
        
        // Try to access protected page directly
        await page.goto('/dashboard');
        await expect(page).toHaveURL('/login');
      });
    });
  });

  test.describe('📊 Security Dashboard Operations', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
    });

    test('should display comprehensive security overview', async ({ page }) => {
      await test.step('Navigate to dashboard', async () => {
        await page.goto('/dashboard');
        await expect(page.getByRole('heading', { name: 'Security Dashboard' })).toBeVisible();
      });

      await test.step('Verify key metrics are displayed', async () => {
        const metricsCards = page.locator('[data-testid="metric-card"]');
        await expect(metricsCards).toHaveCount(6);
        
        await expect(page.getByText('Active Alerts')).toBeVisible();
        await expect(page.getByText('Critical Threats')).toBeVisible();
        await expect(page.getByText('System Health')).toBeVisible();
        await expect(page.getByText('Events/Hour')).toBeVisible();
      });

      await test.step('Verify threat map is interactive', async () => {
        const threatMap = page.locator('[data-testid="threat-map"]');
        await expect(threatMap).toBeVisible();
        
        // Click on threat indicator
        await threatMap.locator('.threat-indicator').first().click();
        await expect(page.getByRole('dialog', { name: 'Threat Details' })).toBeVisible();
      });

      await test.step('Verify real-time updates', async () => {
        const alertCount = await page.getByTestId('active-alerts-count').textContent();
        
        // Simulate new alert arrival
        await securityFixtures.injectSecurityEvent({
          type: 'alert_created',
          data: SECURITY_TEST_DATA.alerts.critical,
        });

        // Wait for real-time update
        await page.waitForTimeout(2000);
        const newAlertCount = await page.getByTestId('active-alerts-count').textContent();
        expect(newAlertCount).not.toBe(alertCount);
      });
    });

    test('should handle high-frequency updates without performance issues', async ({ page }) => {
      await page.goto('/dashboard');
      
      await test.step('Monitor performance during updates', async () => {
        const startTime = Date.now();
        
        // Inject multiple rapid updates
        for (let i = 0; i < 50; i++) {
          await securityFixtures.injectSecurityEvent({
            type: 'threat_intel_update',
            data: { id: `threat-${i}`, severity: 'MEDIUM' },
          });
        }
        
        // Verify dashboard remains responsive
        await page.getByRole('button', { name: 'Refresh' }).click();
        const endTime = Date.now();
        
        expect(endTime - startTime).toBeLessThan(5000); // Under 5 seconds
      });
    });
  });

  test.describe('🚨 Alert Management Workflow', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
      await securityFixtures.seedTestAlerts([
        SECURITY_TEST_DATA.alerts.critical,
        SECURITY_TEST_DATA.alerts.high,
      ]);
    });

    test('should complete full alert investigation workflow', async ({ page }) => {
      await test.step('Navigate to alerts and filter criticals', async () => {
        await page.goto('/alerts');
        await expect(page.getByRole('heading', { name: 'Security Alerts' })).toBeVisible();
        
        await page.getByRole('combobox', { name: 'Severity Filter' }).selectOption('CRITICAL');
        await expect(page.getByText(SECURITY_TEST_DATA.alerts.critical.title)).toBeVisible();
      });

      await test.step('Open alert details for investigation', async () => {
        await page.getByText(SECURITY_TEST_DATA.alerts.critical.title).click();
        await expect(page.getByRole('dialog', { name: 'Alert Details' })).toBeVisible();
        
        // Verify all investigation data is present
        await expect(page.getByText('Timeline')).toBeVisible();
        await expect(page.getByText('Related Events')).toBeVisible();
        await expect(page.getByText('Threat Intelligence')).toBeVisible();
        await expect(page.getByText('Asset Context')).toBeVisible();
      });

      await test.step('Enrich with threat intelligence', async () => {
        await page.getByRole('button', { name: 'Enrich with TI' }).click();
        
        // Verify threat intelligence enrichment
        await expect(page.getByText('IOC Analysis')).toBeVisible();
        await expect(page.getByText('Attribution')).toBeVisible();
        await expect(page.getByText('Risk Score:')).toBeVisible();
      });

      await test.step('Add investigation notes', async () => {
        const investigationNotes = `Initial analysis shows signs of APT activity. 
        Malware hash matches known Lazarus group TTPs. 
        Recommend immediate containment and forensic imaging.`;
        
        await page.getByRole('textbox', { name: 'Investigation Notes' }).fill(investigationNotes);
        await page.getByRole('button', { name: 'Save Notes' }).click();
        
        await expect(page.getByText('Notes saved successfully')).toBeVisible();
      });

      await test.step('Escalate to incident', async () => {
        await page.getByRole('button', { name: 'Escalate to Incident' }).click();
        
        const incidentForm = page.getByRole('dialog', { name: 'Create Incident' });
        await expect(incidentForm).toBeVisible();
        
        await incidentForm.getByLabel('Incident Title').fill('APT Detection - Immediate Response Required');
        await incidentForm.getByLabel('Severity').selectOption('CRITICAL');
        await incidentForm.getByLabel('Category').selectOption('MALWARE');
        await incidentForm.getByRole('button', { name: 'Create Incident' }).click();
        
        await expect(page.getByText('Incident created successfully')).toBeVisible();
      });
    });

    test('should perform bulk alert operations efficiently', async ({ page }) => {
      await page.goto('/alerts');
      
      await test.step('Select multiple alerts', async () => {
        const alertCheckboxes = page.getByRole('checkbox', { name: /Select alert/ });
        
        // Select first 3 alerts
        for (let i = 0; i < 3; i++) {
          await alertCheckboxes.nth(i).check();
        }
        
        await expect(page.getByText('3 alerts selected')).toBeVisible();
      });

      await test.step('Perform bulk acknowledgment', async () => {
        await page.getByRole('button', { name: 'Bulk Actions' }).click();
        await page.getByRole('menuitem', { name: 'Acknowledge Selected' }).click();
        
        const bulkDialog = page.getByRole('dialog', { name: 'Bulk Acknowledge' });
        await bulkDialog.getByLabel('Notes').fill('Bulk acknowledgment after initial triage');
        await bulkDialog.getByRole('button', { name: 'Acknowledge' }).click();
        
        await expect(page.getByText('3 alerts acknowledged')).toBeVisible();
      });

      await test.step('Verify bulk operation results', async () => {
        // All selected alerts should now show as acknowledged
        const acknowledgedAlerts = page.locator('[data-alert-status="ACKNOWLEDGED"]');
        await expect(acknowledgedAlerts).toHaveCount(3);
      });
    });
  });

  test.describe('🔍 Threat Hunting & Analysis', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
    });

    test('should conduct advanced threat hunting session', async ({ page }) => {
      await test.step('Navigate to threat hunting interface', async () => {
        await page.goto('/threats/hunt');
        await expect(page.getByRole('heading', { name: 'Threat Hunting' })).toBeVisible();
      });

      await test.step('Build complex hunting query', async () => {
        const queryBuilder = page.locator('[data-testid="query-builder"]');
        
        // Add multiple hunting conditions
        await queryBuilder.getByRole('button', { name: 'Add Condition' }).click();
        await page.getByLabel('Field').selectOption('source_ip');
        await page.getByLabel('Operator').selectOption('equals');
        await page.getByLabel('Value').fill(SECURITY_TEST_DATA.threats.suspiciousIp);
        
        await queryBuilder.getByRole('button', { name: 'Add Condition' }).click();
        await page.getByLabel('Field').nth(1).selectOption('event_type');
        await page.getByLabel('Operator').nth(1).selectOption('contains');  
        await page.getByLabel('Value').nth(1).fill('malware');
        
        await page.getByRole('button', { name: 'Execute Hunt' }).click();
      });

      await test.step('Analyze hunting results', async () => {
        await expect(page.getByRole('table', { name: 'Hunt Results' })).toBeVisible();
        
        const resultCount = await page.getByTestId('result-count').textContent();
        expect(parseInt(resultCount || '0')).toBeGreaterThan(0);
        
        // Examine detailed results
        await page.getByRole('row').first().click();
        await expect(page.getByRole('dialog', { name: 'Event Details' })).toBeVisible();
      });

      await test.step('Save hunting query for reuse', async () => {
        await page.getByRole('button', { name: 'Save Query' }).click();
        
        const saveDialog = page.getByRole('dialog', { name: 'Save Hunt Query' });
        await saveDialog.getByLabel('Query Name').fill('APT Malware Hunt');
        await saveDialog.getByLabel('Description').fill('Hunt for APT-related malware activity');
        await saveDialog.getByRole('button', { name: 'Save' }).click();
        
        await expect(page.getByText('Query saved successfully')).toBeVisible();
      });
    });

    test('should correlate events across multiple data sources', async ({ page }) => {
      await page.goto('/threats/correlate');
      
      await test.step('Set up correlation analysis', async () => {
        await page.getByLabel('Time Range').selectOption('last_24h');
        await page.getByLabel('Correlation Type').selectOption('ip_based');
        await page.getByLabel('Minimum Events').fill('5');
        
        await page.getByRole('button', { name: 'Start Correlation' }).click();
      });

      await test.step('Review correlation results', async () => {
        await expect(page.getByRole('progressbar')).toBeVisible();
        await expect(page.getByRole('progressbar')).not.toBeVisible({ timeout: 30000 });
        
        const correlationResults = page.locator('[data-testid="correlation-result"]');
        await expect(correlationResults.first()).toBeVisible();
        
        // Click on a correlation cluster
        await correlationResults.first().click();
        await expect(page.getByText('Correlation Details')).toBeVisible();
      });
    });
  });

  test.describe('📈 Security Analytics & Reporting', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
    });

    test('should generate comprehensive security report', async ({ page }) => {
      await test.step('Navigate to reporting interface', async () => {
        await page.goto('/reports');
        await expect(page.getByRole('heading', { name: 'Security Reports' })).toBeVisible();
      });

      await test.step('Configure report parameters', async () => {
        await page.getByLabel('Report Type').selectOption('security_summary');
        await page.getByLabel('Time Period').selectOption('last_week');
        await page.getByLabel('Include Charts').check();
        await page.getByLabel('Include Recommendations').check();
        
        await page.getByRole('button', { name: 'Generate Report' }).click();
      });

      await test.step('Verify report generation and content', async () => {
        await expect(page.getByText('Report generated successfully')).toBeVisible();
        
        // Verify report sections
        await expect(page.getByText('Executive Summary')).toBeVisible();
        await expect(page.getByText('Threat Landscape')).toBeVisible();
        await expect(page.getByText('Security Metrics')).toBeVisible();
        await expect(page.getByText('Recommendations')).toBeVisible();
        
        // Verify charts are rendered
        const charts = page.locator('[data-testid="security-chart"]');
        await expect(charts.first()).toBeVisible();
      });

      await test.step('Export report in multiple formats', async () => {
        await page.getByRole('button', { name: 'Export' }).click();
        
        // Test PDF export
        const [pdfDownload] = await Promise.all([
          page.waitForEvent('download'),
          page.getByRole('menuitem', { name: 'Export as PDF' }).click(),
        ]);
        expect(pdfDownload.suggestedFilename()).toContain('.pdf');
        
        // Test Excel export
        const [excelDownload] = await Promise.all([
          page.waitForEvent('download'),
          page.getByRole('menuitem', { name: 'Export as Excel' }).click(),
        ]);
        expect(excelDownload.suggestedFilename()).toContain('.xlsx');
      });
    });
  });

  test.describe('🛠️ Incident Response Workflow', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
    });

    test('should manage complete incident lifecycle', async ({ page }) => {
      await test.step('Create new security incident', async () => {
        await page.goto('/incidents');
        await page.getByRole('button', { name: 'Create Incident' }).click();
        
        const incidentForm = page.getByRole('dialog', { name: 'New Incident' });
        await incidentForm.getByLabel('Title').fill('Data Exfiltration Attempt');
        await incidentForm.getByLabel('Severity').selectOption('HIGH');
        await incidentForm.getByLabel('Category').selectOption('DATA_BREACH');
        await incidentForm.getByLabel('Description').fill('Suspicious data transfer detected from critical server');
        
        await incidentForm.getByRole('button', { name: 'Create' }).click();
        await expect(page.getByText('Incident created successfully')).toBeVisible();
      });

      await test.step('Assign incident to response team', async () => {
        await page.getByRole('button', { name: 'Assign Team' }).click();
        
        const assignDialog = page.getByRole('dialog', { name: 'Assign Response Team' });
        await assignDialog.getByLabel('Primary Responder').selectOption('analyst@isectech.com');
        await assignDialog.getByLabel('Response Team').selectOption('incident_response');
        await assignDialog.getByRole('button', { name: 'Assign' }).click();
      });

      await test.step('Execute response playbook', async () => {
        await page.getByRole('button', { name: 'Run Playbook' }).click();
        
        const playbookDialog = page.getByRole('dialog', { name: 'Select Playbook' });
        await playbookDialog.getByText('Data Breach Response').click();
        await playbookDialog.getByRole('button', { name: 'Execute' }).click();
        
        // Verify playbook steps are displayed
        await expect(page.getByText('Containment')).toBeVisible();
        await expect(page.getByText('Investigation')).toBeVisible();
        await expect(page.getByText('Eradication')).toBeVisible();
        await expect(page.getByText('Recovery')).toBeVisible();
      });

      await test.step('Update incident status and add timeline entries', async () => {
        await page.getByRole('button', { name: 'Update Status' }).click();
        await page.getByLabel('Status').selectOption('IN_PROGRESS');
        await page.getByLabel('Update Notes').fill('Initial containment measures implemented');
        await page.getByRole('button', { name: 'Update' }).click();
        
        // Verify timeline update
        await expect(page.getByText('Status changed to IN_PROGRESS')).toBeVisible();
      });

      await test.step('Close incident with lessons learned', async () => {
        await page.getByRole('button', { name: 'Close Incident' }).click();
        
        const closeDialog = page.getByRole('dialog', { name: 'Close Incident' });
        await closeDialog.getByLabel('Resolution').selectOption('RESOLVED');
        await closeDialog.getByLabel('Resolution Summary').fill('False positive - legitimate data backup operation');
        await closeDialog.getByLabel('Lessons Learned').fill('Improve monitoring rules to reduce false positives');
        await closeDialog.getByRole('button', { name: 'Close' }).click();
        
        await expect(page.getByText('Incident closed successfully')).toBeVisible();
      });
    });
  });

  test.describe('🔒 Security Configuration & Settings', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
    });

    test('should manage security policies and rules', async ({ page }) => {
      await test.step('Navigate to security settings', async () => {
        await page.goto('/settings/security');
        await expect(page.getByRole('heading', { name: 'Security Configuration' })).toBeVisible();
      });

      await test.step('Update detection rules', async () => {
        await page.getByRole('tab', { name: 'Detection Rules' }).click();
        
        await page.getByRole('button', { name: 'Add Rule' }).click();
        const ruleDialog = page.getByRole('dialog', { name: 'Create Detection Rule' });
        
        await ruleDialog.getByLabel('Rule Name').fill('Suspicious Login Activity');
        await ruleDialog.getByLabel('Severity').selectOption('MEDIUM');
        await ruleDialog.getByLabel('Condition').fill('failed_logins > 5 AND time_window < 300');
        await ruleDialog.getByRole('button', { name: 'Create' }).click();
        
        await expect(page.getByText('Detection rule created')).toBeVisible();
      });

      await test.step('Configure alert thresholds', async () => {
        await page.getByRole('tab', { name: 'Alert Thresholds' }).click();
        
        await page.getByLabel('Critical Alert Threshold').fill('10');
        await page.getByLabel('High Alert Threshold').fill('25');
        await page.getByLabel('Alert Retention Days').fill('90');
        
        await page.getByRole('button', { name: 'Save Settings' }).click();
        await expect(page.getByText('Settings saved successfully')).toBeVisible();
      });
    });
  });

  test.describe('⚡ Performance & Accessibility', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
    });

    test('should maintain performance with large datasets', async ({ page }) => {
      await test.step('Load large alert dataset', async () => {
        await securityFixtures.seedLargeDataset('alerts', 1000);
        
        const startTime = Date.now();
        await page.goto('/alerts');
        
        await expect(page.getByRole('table')).toBeVisible();
        const loadTime = Date.now() - startTime;
        
        expect(loadTime).toBeLessThan(5000); // Should load within 5 seconds
      });

      await test.step('Test virtual scrolling performance', async () => {
        const alertTable = page.getByRole('table');
        
        // Scroll through large dataset
        for (let i = 0; i < 10; i++) {
          await alertTable.press('PageDown');
          await page.waitForTimeout(100);
        }
        
        // Should remain responsive
        await expect(page.getByRole('row')).toHaveCountGreaterThan(10);
      });
    });

    test('should be fully accessible with screen readers', async ({ page }) => {
      await test.step('Verify keyboard navigation', async () => {
        await page.goto('/dashboard');
        
        // Tab through main navigation
        await page.keyboard.press('Tab');
        await expect(page.getByRole('link', { name: 'Dashboard' })).toBeFocused();
        
        await page.keyboard.press('Tab');
        await expect(page.getByRole('link', { name: 'Alerts' })).toBeFocused();
      });

      await test.step('Verify ARIA labels and roles', async () => {
        await page.goto('/alerts');
        
        const alertTable = page.getByRole('table', { name: 'Security Alerts' });
        await expect(alertTable).toBeVisible();
        
        const statusFilter = page.getByRole('combobox', { name: 'Filter alerts by status' });
        await expect(statusFilter).toBeVisible();
      });

      await test.step('Verify high contrast mode', async () => {
        // Enable high contrast mode
        await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
        await page.goto('/dashboard');
        
        // Verify high contrast elements are applied
        const criticalAlerts = page.locator('[data-severity="CRITICAL"]');
        await expect(criticalAlerts.first()).toHaveCSS('background-color', /rgb\(139, 0, 0\)/); // Dark red
      });
    });
  });

  test.describe('🔧 Error Handling & Recovery', () => {
    test.beforeEach(async ({ page }) => {
      await securityFixtures.loginAsSecurityAnalyst(page);
    });

    test('should handle network errors gracefully', async ({ page }) => {
      await test.step('Simulate network failure during alert loading', async () => {
        await page.route('**/api/alerts', route => route.abort('failed'));
        
        await page.goto('/alerts');
        
        // Should show error state with retry option
        await expect(page.getByText('Failed to load alerts')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible();
      });

      await test.step('Test automatic retry and recovery', async () => {
        // Remove network failure simulation
        await page.unroute('**/api/alerts');
        
        await page.getByRole('button', { name: 'Retry' }).click();
        
        // Should successfully load alerts
        await expect(page.getByRole('table')).toBeVisible();
      });
    });

    test('should maintain data integrity during connection issues', async ({ page }) => {
      await page.goto('/alerts');
      
      await test.step('Start creating alert with network interruption', async () => {
        await page.getByRole('button', { name: 'Create Alert' }).click();
        
        const alertForm = page.getByRole('dialog', { name: 'New Alert' });
        await alertForm.getByLabel('Title').fill('Network Test Alert');
        await alertForm.getByLabel('Severity').selectOption('HIGH');
        
        // Simulate network failure during form submission
        await page.route('**/api/alerts', route => route.abort('failed'));
        await alertForm.getByRole('button', { name: 'Create' }).click();
        
        await expect(page.getByText('Network error')).toBeVisible();
      });

      await test.step('Recover and complete operation', async () => {
        // Restore network
        await page.unroute('**/api/alerts');
        
        // Form should retain data
        const alertForm = page.getByRole('dialog', { name: 'New Alert' });
        await expect(alertForm.getByLabel('Title')).toHaveValue('Network Test Alert');
        
        await alertForm.getByRole('button', { name: 'Create' }).click();
        await expect(page.getByText('Alert created successfully')).toBeVisible();
      });
    });
  });
});