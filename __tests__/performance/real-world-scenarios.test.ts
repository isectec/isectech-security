/**
 * Real-World Security Scenarios Performance Testing
 * iSECTECH Protect - Production-Like Performance Validation
 */

import { test, expect, Page } from '@playwright/test';
import { PerformanceMonitor, PERFORMANCE_THRESHOLDS, createSecurityPerformanceTest } from './performance-config';

interface SecurityScenario {
  name: string;
  description: string;
  expectedDuration: number;
  criticalPath: boolean;
}

const SECURITY_SCENARIOS: SecurityScenario[] = [
  {
    name: 'incident_response_workflow',
    description: 'Complete incident response from alert to resolution',
    expectedDuration: 30000, // 30 seconds
    criticalPath: true,
  },
  {
    name: 'threat_hunting_session',
    description: 'Advanced threat hunting with correlation',
    expectedDuration: 45000, // 45 seconds
    criticalPath: true,
  },
  {
    name: 'compliance_audit_report',
    description: 'Generate comprehensive compliance report',
    expectedDuration: 60000, // 60 seconds
    criticalPath: false,
  },
  {
    name: 'security_analyst_daily_workflow',
    description: 'Typical security analyst daily operations',
    expectedDuration: 20000, // 20 seconds
    criticalPath: true,
  },
];

class SecurityScenarioTester {
  private monitor: PerformanceMonitor;
  
  constructor() {
    this.monitor = new PerformanceMonitor();
  }

  async executeIncidentResponseWorkflow(page: Page, baseUrl: string): Promise<void> {
    this.monitor.startTimer('incident_response_workflow');

    // Step 1: Detect critical alert
    this.monitor.startTimer('alert_detection');
    await page.goto(`${baseUrl}/alerts`);
    await page.waitForSelector('[data-testid="alerts-table-loaded"]');
    
    // Filter for critical alerts
    await page.selectOption('[data-testid="severity-filter"]', 'CRITICAL');
    await page.waitForSelector('[data-testid="critical-alerts-filtered"]');
    this.monitor.endTimer('alert_detection', 'security');

    // Step 2: Alert investigation
    this.monitor.startTimer('alert_investigation');
    await page.click('[data-testid="alert-row"]:first-child');
    await page.waitForSelector('[data-testid="alert-details-modal"]');
    
    // Review alert timeline
    await page.click('[data-testid="timeline-tab"]');
    await page.waitForSelector('[data-testid="timeline-loaded"]');
    
    // Check related events
    await page.click('[data-testid="related-events-tab"]');
    await page.waitForSelector('[data-testid="related-events-loaded"]');
    this.monitor.endTimer('alert_investigation', 'security');

    // Step 3: Threat intelligence enrichment
    this.monitor.startTimer('threat_intel_enrichment');
    await page.click('[data-testid="enrich-with-ti-button"]');
    await page.waitForSelector('[data-testid="threat-intel-loaded"]');
    this.monitor.endTimer('threat_intel_enrichment', 'security');

    // Step 4: Escalate to incident
    this.monitor.startTimer('incident_escalation');
    await page.click('[data-testid="escalate-to-incident-button"]');
    await page.waitForSelector('[data-testid="incident-form"]');
    
    await page.fill('[data-testid="incident-title"]', 'Critical Security Incident - APT Detection');
    await page.selectOption('[data-testid="incident-severity"]', 'CRITICAL');
    await page.selectOption('[data-testid="incident-category"]', 'MALWARE');
    await page.click('[data-testid="create-incident-button"]');
    
    await page.waitForSelector('[data-testid="incident-created-success"]');
    this.monitor.endTimer('incident_escalation', 'security');

    // Step 5: Incident response actions
    this.monitor.startTimer('response_actions');
    await page.goto(`${baseUrl}/incidents`);
    await page.waitForSelector('[data-testid="incidents-table-loaded"]');
    
    // Open newly created incident
    await page.click('[data-testid="incident-row"]:first-child');
    await page.waitForSelector('[data-testid="incident-details"]');
    
    // Execute response playbook
    await page.click('[data-testid="run-playbook-button"]');
    await page.waitForSelector('[data-testid="playbook-dialog"]');
    await page.click('[data-testid="malware-response-playbook"]');
    await page.click('[data-testid="execute-playbook-button"]');
    
    await page.waitForSelector('[data-testid="playbook-executing"]');
    await page.waitForSelector('[data-testid="playbook-complete"]', { timeout: 15000 });
    this.monitor.endTimer('response_actions', 'security');

    // Step 6: Update incident status
    this.monitor.startTimer('incident_update');
    await page.click('[data-testid="update-status-button"]');
    await page.selectOption('[data-testid="incident-status"]', 'IN_PROGRESS');
    await page.fill('[data-testid="status-notes"]', 'Initial containment measures implemented');
    await page.click('[data-testid="update-incident-button"]');
    
    await page.waitForSelector('[data-testid="incident-updated-success"]');
    this.monitor.endTimer('incident_update', 'security');

    this.monitor.endTimer('incident_response_workflow', 'security');
  }

  async executeThreatHuntingSession(page: Page, baseUrl: string): Promise<void> {
    this.monitor.startTimer('threat_hunting_session');

    // Step 1: Navigate to threat hunting
    this.monitor.startTimer('hunting_interface_load');
    await page.goto(`${baseUrl}/threats/hunt`);
    await page.waitForSelector('[data-testid="hunting-interface-loaded"]');
    this.monitor.endTimer('hunting_interface_load', 'security');

    // Step 2: Build complex hunting query
    this.monitor.startTimer('query_building');
    await page.click('[data-testid="add-condition-button"]');
    await page.selectOption('[data-testid="condition-field"]', 'source_ip');
    await page.selectOption('[data-testid="condition-operator"]', 'in_subnet');
    await page.fill('[data-testid="condition-value"]', '192.168.1.0/24');

    await page.click('[data-testid="add-condition-button"]');
    await page.selectOption('[data-testid="condition-field"]:nth-child(2)', 'event_type');
    await page.selectOption('[data-testid="condition-operator"]:nth-child(2)', 'contains');
    await page.fill('[data-testid="condition-value"]:nth-child(2)', 'malware');

    await page.click('[data-testid="add-condition-button"]');
    await page.selectOption('[data-testid="condition-field"]:nth-child(3)', 'timestamp');
    await page.selectOption('[data-testid="condition-operator"]:nth-child(3)', 'last_hours');
    await page.fill('[data-testid="condition-value"]:nth-child(3)', '24');
    this.monitor.endTimer('query_building', 'security');

    // Step 3: Execute hunting query
    this.monitor.startTimer('hunting_execution');
    await page.click('[data-testid="execute-hunt-button"]');
    await page.waitForSelector('[data-testid="hunting-progress"]');
    await page.waitForSelector('[data-testid="hunting-results-loaded"]', { timeout: 20000 });
    this.monitor.endTimer('hunting_execution', 'security');

    // Step 4: Analyze results
    this.monitor.startTimer('result_analysis');
    await page.click('[data-testid="analyze-results-button"]');
    await page.waitForSelector('[data-testid="analysis-complete"]');
    
    // View correlation analysis
    await page.click('[data-testid="correlation-tab"]');
    await page.waitForSelector('[data-testid="correlation-chart-loaded"]');
    
    // View timeline analysis
    await page.click('[data-testid="timeline-tab"]');
    await page.waitForSelector('[data-testid="timeline-chart-loaded"]');
    this.monitor.endTimer('result_analysis', 'security');

    // Step 5: Create hunting report
    this.monitor.startTimer('hunting_report');
    await page.click('[data-testid="create-report-button"]');
    await page.waitForSelector('[data-testid="report-form"]');
    
    await page.fill('[data-testid="report-title"]', 'APT Hunting Results - Q1 2025');
    await page.fill('[data-testid="report-description"]', 'Comprehensive hunting for APT indicators');
    await page.click('[data-testid="include-iocs-checkbox"]');
    await page.click('[data-testid="include-timeline-checkbox"]');
    
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-generated-success"]');
    this.monitor.endTimer('hunting_report', 'security');

    this.monitor.endTimer('threat_hunting_session', 'security');
  }

  async executeComplianceAuditReport(page: Page, baseUrl: string): Promise<void> {
    this.monitor.startTimer('compliance_audit_report');

    // Step 1: Navigate to compliance reporting
    this.monitor.startTimer('compliance_interface_load');
    await page.goto(`${baseUrl}/compliance/reports`);
    await page.waitForSelector('[data-testid="compliance-interface-loaded"]');
    this.monitor.endTimer('compliance_interface_load', 'compliance');

    // Step 2: Configure audit parameters
    this.monitor.startTimer('audit_configuration');
    await page.click('[data-testid="new-audit-button"]');
    await page.waitForSelector('[data-testid="audit-config-form"]');
    
    await page.selectOption('[data-testid="compliance-framework"]', 'SOC2_TYPE2');
    await page.selectOption('[data-testid="audit-period"]', 'last_quarter');
    await page.check('[data-testid="include-controls-checkbox"]');
    await page.check('[data-testid="include-evidence-checkbox"]');
    await page.check('[data-testid="include-gaps-checkbox"]');
    this.monitor.endTimer('audit_configuration', 'compliance');

    // Step 3: Execute compliance scan
    this.monitor.startTimer('compliance_scan');
    await page.click('[data-testid="start-audit-button"]');
    await page.waitForSelector('[data-testid="audit-progress"]');
    await page.waitForSelector('[data-testid="audit-complete"]', { timeout: 30000 });
    this.monitor.endTimer('compliance_scan', 'compliance');

    // Step 4: Review audit results
    this.monitor.startTimer('results_review');
    await page.click('[data-testid="view-results-button"]');
    await page.waitForSelector('[data-testid="audit-results-loaded"]');
    
    // Review control results
    await page.click('[data-testid="controls-tab"]');
    await page.waitForSelector('[data-testid="controls-results-loaded"]');
    
    // Review gaps and findings
    await page.click('[data-testid="findings-tab"]');
    await page.waitForSelector('[data-testid="findings-loaded"]');
    this.monitor.endTimer('results_review', 'compliance');

    // Step 5: Generate comprehensive report
    this.monitor.startTimer('report_generation');
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="report-options-dialog"]');
    
    await page.check('[data-testid="executive-summary-checkbox"]');
    await page.check('[data-testid="detailed-findings-checkbox"]');
    await page.check('[data-testid="remediation-plan-checkbox"]');
    await page.selectOption('[data-testid="report-format"]', 'pdf');
    
    await page.click('[data-testid="create-report-button"]');
    await page.waitForSelector('[data-testid="report-generation-progress"]');
    await page.waitForSelector('[data-testid="report-ready"]', { timeout: 25000 });
    this.monitor.endTimer('report_generation', 'compliance');

    this.monitor.endTimer('compliance_audit_report', 'compliance');
  }

  async executeSecurityAnalystDailyWorkflow(page: Page, baseUrl: string): Promise<void> {
    this.monitor.startTimer('security_analyst_daily_workflow');

    // Step 1: Morning dashboard review
    this.monitor.startTimer('dashboard_review');
    await page.goto(`${baseUrl}/dashboard`);
    await page.waitForSelector('[data-testid="dashboard-loaded"]');
    
    // Review overnight metrics
    await page.click('[data-testid="metrics-card-alerts"]');
    await page.waitForSelector('[data-testid="alerts-summary-loaded"]');
    
    await page.click('[data-testid="metrics-card-threats"]');
    await page.waitForSelector('[data-testid="threats-summary-loaded"]');
    this.monitor.endTimer('dashboard_review', 'security');

    // Step 2: Alert triage
    this.monitor.startTimer('alert_triage');
    await page.goto(`${baseUrl}/alerts`);
    await page.waitForSelector('[data-testid="alerts-table-loaded"]');
    
    // Filter new alerts from last 24h
    await page.selectOption('[data-testid="time-filter"]', 'last_24h');
    await page.selectOption('[data-testid="status-filter"]', 'NEW');
    await page.waitForSelector('[data-testid="filtered-alerts-loaded"]');
    
    // Quick triage - acknowledge low priority alerts
    await page.click('[data-testid="bulk-select-all"]');
    await page.click('[data-testid="bulk-actions-button"]');
    await page.click('[data-testid="bulk-acknowledge-button"]');
    await page.fill('[data-testid="bulk-notes"]', 'Daily triage - low priority alerts acknowledged');
    await page.click('[data-testid="confirm-bulk-action"]');
    await page.waitForSelector('[data-testid="bulk-action-complete"]');
    this.monitor.endTimer('alert_triage', 'security');

    // Step 3: Investigation work
    this.monitor.startTimer('investigation_work');
    await page.selectOption('[data-testid="severity-filter"]', 'HIGH');
    await page.click('[data-testid="alert-row"]:first-child');
    await page.waitForSelector('[data-testid="alert-details-modal"]');
    
    // Add investigation notes
    await page.fill('[data-testid="investigation-notes"]', 
      'Initial analysis indicates potential lateral movement. Escalating for deeper investigation.');
    await page.click('[data-testid="save-notes-button"]');
    
    // Assign to team member
    await page.selectOption('[data-testid="assignee-select"]', 'senior-analyst');
    await page.click('[data-testid="assign-button"]');
    this.monitor.endTimer('investigation_work', 'security');

    // Step 4: Threat intelligence check
    this.monitor.startTimer('threat_intel_check');
    await page.goto(`${baseUrl}/threats/intelligence`);
    await page.waitForSelector('[data-testid="threat-intel-loaded"]');
    
    // Check latest IOCs
    await page.click('[data-testid="iocs-tab"]');
    await page.waitForSelector('[data-testid="iocs-loaded"]');
    
    // Search for specific indicators
    await page.fill('[data-testid="ioc-search"]', '192.168.1.100');
    await page.click('[data-testid="search-iocs-button"]');
    await page.waitForSelector('[data-testid="ioc-search-results"]');
    this.monitor.endTimer('threat_intel_check', 'security');

    // Step 5: Daily report update
    this.monitor.startTimer('daily_report_update');
    await page.goto(`${baseUrl}/reports/daily`);
    await page.waitForSelector('[data-testid="daily-report-loaded"]');
    
    // Update analyst notes
    await page.fill('[data-testid="daily-notes"]', 
      'Processed 15 new alerts, 3 high priority investigations ongoing. ' +
      'Threat landscape showing increased phishing activity.');
    await page.click('[data-testid="save-daily-report"]');
    await page.waitForSelector('[data-testid="report-saved-success"]');
    this.monitor.endTimer('daily_report_update', 'security');

    this.monitor.endTimer('security_analyst_daily_workflow', 'security');
  }

  getMetrics(): any {
    return this.monitor.getMetrics();
  }

  generateReport(): string {
    return this.monitor.generateReport();
  }
}

test.describe('🛡️ Real-World Security Scenarios', () => {
  let scenarioTester: SecurityScenarioTester;
  const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000';

  test.beforeEach(async () => {
    scenarioTester = new SecurityScenarioTester();
  });

  test('should handle complete incident response workflow efficiently', 
    createSecurityPerformanceTest('incident_response', async (monitor) => {
      const { page } = await test.step('Setup', async () => {
        const { browser } = require('@playwright/test');
        const context = await browser.newContext();
        const page = await context.newPage();
        
        // Login as security analyst
        await page.goto(`${baseUrl}/login`);
        await page.fill('[data-testid="email-input"]', 'analyst@isectech.com');
        await page.fill('[data-testid="password-input"]', 'TestPassword123!');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL('**/dashboard');
        
        return { page };
      });

      await scenarioTester.executeIncidentResponseWorkflow(page, baseUrl);
      
      const metrics = scenarioTester.getMetrics();
      const totalTime = metrics.find(m => m.name === 'incident_response_workflow')?.value || 0;
      
      expect(totalTime).toBeLessThan(SECURITY_SCENARIOS[0].expectedDuration);
      console.log(scenarioTester.generateReport());
    })
  );

  test('should support advanced threat hunting session', 
    createSecurityPerformanceTest('threat_hunting', async (monitor) => {
      const { page } = await test.step('Setup', async () => {
        const { browser } = require('@playwright/test');
        const context = await browser.newContext();
        const page = await context.newPage();
        
        await page.goto(`${baseUrl}/login`);
        await page.fill('[data-testid="email-input"]', 'hunter@isectech.com');
        await page.fill('[data-testid="password-input"]', 'TestPassword123!');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL('**/dashboard');
        
        return { page };
      });

      await scenarioTester.executeThreatHuntingSession(page, baseUrl);
      
      const metrics = scenarioTester.getMetrics();
      const totalTime = metrics.find(m => m.name === 'threat_hunting_session')?.value || 0;
      
      expect(totalTime).toBeLessThan(SECURITY_SCENARIOS[1].expectedDuration);
      console.log(scenarioTester.generateReport());
    })
  );

  test('should generate compliance audit reports within SLA', 
    createSecurityPerformanceTest('compliance_audit', async (monitor) => {
      const { page } = await test.step('Setup', async () => {
        const { browser } = require('@playwright/test');
        const context = await browser.newContext();
        const page = await context.newPage();
        
        await page.goto(`${baseUrl}/login`);
        await page.fill('[data-testid="email-input"]', 'compliance@isectech.com');
        await page.fill('[data-testid="password-input"]', 'TestPassword123!');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL('**/dashboard');
        
        return { page };
      });

      await scenarioTester.executeComplianceAuditReport(page, baseUrl);
      
      const metrics = scenarioTester.getMetrics();
      const totalTime = metrics.find(m => m.name === 'compliance_audit_report')?.value || 0;
      
      expect(totalTime).toBeLessThan(SECURITY_SCENARIOS[2].expectedDuration);
      console.log(scenarioTester.generateReport());
    })
  );

  test('should support typical security analyst daily workflow', 
    createSecurityPerformanceTest('daily_workflow', async (monitor) => {
      const { page } = await test.step('Setup', async () => {
        const { browser } = require('@playwright/test');
        const context = await browser.newContext();
        const page = await context.newPage();
        
        await page.goto(`${baseUrl}/login`);
        await page.fill('[data-testid="email-input"]', 'analyst@isectech.com');
        await page.fill('[data-testid="password-input"]', 'TestPassword123!');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL('**/dashboard');
        
        return { page };
      });

      await scenarioTester.executeSecurityAnalystDailyWorkflow(page, baseUrl);
      
      const metrics = scenarioTester.getMetrics();
      const totalTime = metrics.find(m => m.name === 'security_analyst_daily_workflow')?.value || 0;
      
      expect(totalTime).toBeLessThan(SECURITY_SCENARIOS[3].expectedDuration);
      console.log(scenarioTester.generateReport());
    })
  );

  test('should maintain performance consistency across scenarios', async () => {
    const results = [];
    
    // Run each scenario multiple times to test consistency
    for (const scenario of SECURITY_SCENARIOS.filter(s => s.criticalPath)) {
      const scenarioResults = [];
      
      for (let run = 0; run < 3; run++) {
        const tester = new SecurityScenarioTester();
        const { browser } = require('@playwright/test');
        const context = await browser.newContext();
        const page = await context.newPage();
        
        // Login
        await page.goto(`${baseUrl}/login`);
        await page.fill('[data-testid="email-input"]', 'analyst@isectech.com');
        await page.fill('[data-testid="password-input"]', 'TestPassword123!');
        await page.click('[data-testid="login-button"]');
        await page.waitForURL('**/dashboard');
        
        // Execute scenario
        const startTime = performance.now();
        
        switch (scenario.name) {
          case 'incident_response_workflow':
            await tester.executeIncidentResponseWorkflow(page, baseUrl);
            break;
          case 'security_analyst_daily_workflow':
            await tester.executeSecurityAnalystDailyWorkflow(page, baseUrl);
            break;
        }
        
        const endTime = performance.now();
        const duration = endTime - startTime;
        
        scenarioResults.push(duration);
        await context.close();
      }
      
      const avgDuration = scenarioResults.reduce((sum, d) => sum + d, 0) / scenarioResults.length;
      const maxDuration = Math.max(...scenarioResults);
      const minDuration = Math.min(...scenarioResults);
      const variance = scenarioResults.reduce((sum, d) => sum + Math.pow(d - avgDuration, 2), 0) / scenarioResults.length;
      
      results.push({
        scenario: scenario.name,
        avgDuration,
        maxDuration,
        minDuration,
        variance,
        consistency: (1 - (Math.sqrt(variance) / avgDuration)) * 100, // Consistency percentage
      });
      
      // Performance consistency requirements
      expect(avgDuration).toBeLessThan(scenario.expectedDuration);
      expect(variance).toBeLessThan(Math.pow(scenario.expectedDuration * 0.2, 2)); // < 20% variance
    }
    
    console.log('\n📊 Performance Consistency Report:');
    results.forEach(result => {
      console.log(`${result.scenario}:`);
      console.log(`  Avg: ${result.avgDuration.toFixed(0)}ms`);
      console.log(`  Range: ${result.minDuration.toFixed(0)}-${result.maxDuration.toFixed(0)}ms`);
      console.log(`  Consistency: ${result.consistency.toFixed(1)}%`);
    });
  }, 180000); // 3 minutes timeout
});