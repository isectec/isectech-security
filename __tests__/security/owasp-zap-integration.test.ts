/**
 * OWASP ZAP Security Scanner Integration
 * iSECTECH Protect - Automated Security Scanning with ZAP
 */

import { test, expect, Page } from '@playwright/test';
import { spawn, exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';

const execAsync = promisify(exec);

interface ZAPScanResult {
  timestamp: string;
  scanDuration: number;
  baseUrl: string;
  scanType: 'baseline' | 'full' | 'api';
  alerts: ZAPAlert[];
  summary: {
    total: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  compliance: {
    owaspTop10: { passed: number; failed: number };
    securityHeaders: { passed: number; failed: number };
  };
}

interface ZAPAlert {
  pluginid: string;
  alertRef: string;
  alert: string;
  name: string;
  riskcode: string;
  confidence: string;
  riskdesc: string;
  desc: string;
  instances: ZAPInstance[];
  count: string;
  solution: string;
  otherinfo: string;
  reference: string;
  cweid: string;
  wascid: string;
  sourceid: string;
}

interface ZAPInstance {
  uri: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
  otherinfo: string;
}

class OWASPZAPScanner {
  private zapPort: number = 8080;
  private zapApiKey: string = 'zaproxy-api-key';
  private zapProcess: any = null;
  private baseUrl: string;
  private resultsDir: string;

  constructor(baseUrl: string = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
    this.resultsDir = path.join(__dirname, '../../test-results/zap-scans');
    fs.mkdirSync(this.resultsDir, { recursive: true });
  }

  async startZAP(): Promise<void> {
    console.log('🚀 Starting OWASP ZAP...');
    
    return new Promise((resolve, reject) => {
      // Start ZAP in daemon mode
      this.zapProcess = spawn('zap.sh', [
        '-daemon',
        '-port', this.zapPort.toString(),
        '-config', `api.key=${this.zapApiKey}`,
        '-config', 'api.addrs.addr.name=.*',
        '-config', 'api.addrs.addr.regex=true',
        '-config', 'spider.maxDuration=5',
        '-config', 'ascan.maxRuleDurationInMins=5',
      ], {
        stdio: 'pipe',
        detached: false,
      });

      this.zapProcess.stdout?.on('data', (data: Buffer) => {
        const output = data.toString();
        if (output.includes('ZAP is now listening')) {
          console.log('✅ OWASP ZAP started successfully');
          resolve();
        }
      });

      this.zapProcess.stderr?.on('data', (data: Buffer) => {
        console.log('ZAP stderr:', data.toString());
      });

      this.zapProcess.on('error', (error: Error) => {
        console.error('Failed to start ZAP:', error);
        reject(error);
      });

      // Timeout if ZAP doesn't start within 60 seconds
      setTimeout(() => {
        if (this.zapProcess && !this.zapProcess.killed) {
          reject(new Error('ZAP startup timeout'));
        }
      }, 60000);
    });
  }

  async stopZAP(): Promise<void> {
    if (this.zapProcess) {
      console.log('🛑 Stopping OWASP ZAP...');
      
      try {
        // Graceful shutdown via API
        await this.callZAPAPI('core/action/shutdown/');
        await new Promise(resolve => setTimeout(resolve, 5000));
      } catch (error) {
        console.warn('Graceful ZAP shutdown failed, forcing termination');
      }

      if (!this.zapProcess.killed) {
        this.zapProcess.kill('SIGTERM');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        if (!this.zapProcess.killed) {
          this.zapProcess.kill('SIGKILL');
        }
      }
      
      this.zapProcess = null;
      console.log('✅ OWASP ZAP stopped');
    }
  }

  private async callZAPAPI(endpoint: string, params: Record<string, string> = {}): Promise<any> {
    const url = new URL(`http://localhost:${this.zapPort}/JSON/${endpoint}`);
    url.searchParams.append('apikey', this.zapApiKey);
    
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.append(key, value);
    });

    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(`ZAP API call failed: ${response.status} ${response.statusText}`);
    }
    
    return response.json();
  }

  async performBaselineScan(targetUrl: string): Promise<ZAPScanResult> {
    console.log(`🔍 Starting ZAP baseline scan of ${targetUrl}...`);
    const startTime = Date.now();

    try {
      // Wait for ZAP to be ready
      await this.waitForZAP();

      // Set up context and authentication if needed
      await this.setupScanContext(targetUrl);

      // Spider the application
      console.log('🕷️ Spidering application...');
      const spiderResult = await this.callZAPAPI('spider/action/scan/', { 
        url: targetUrl,
        maxChildren: '10',
        recurse: 'true',
      });
      
      const spiderId = spiderResult.scan;
      await this.waitForSpiderComplete(spiderId);

      // Passive scan (automatic during spidering)
      console.log('🔍 Running passive scan...');
      await this.waitForPassiveScanComplete();

      // Active scan
      console.log('⚡ Running active scan...');
      const ascanResult = await this.callZAPAPI('ascan/action/scan/', {
        url: targetUrl,
        recurse: 'true',
        inScopeOnly: 'false',
      });
      
      const ascanId = ascanResult.scan;
      await this.waitForActiveScanComplete(ascanId);

      // Get results
      const alertsResult = await this.callZAPAPI('core/view/alerts/', { baseurl: targetUrl });
      const alerts = alertsResult.alerts || [];

      const scanDuration = Date.now() - startTime;
      
      const result: ZAPScanResult = {
        timestamp: new Date().toISOString(),
        scanDuration,
        baseUrl: targetUrl,
        scanType: 'baseline',
        alerts,
        summary: this.calculateSummary(alerts),
        compliance: this.calculateCompliance(alerts),
      };

      console.log(`✅ Baseline scan completed in ${scanDuration}ms`);
      console.log(`📊 Found ${result.summary.total} alerts (${result.summary.high} high risk)`);

      return result;
    } catch (error) {
      console.error('Baseline scan failed:', error);
      throw error;
    }
  }

  async performFullScan(targetUrl: string): Promise<ZAPScanResult> {
    console.log(`🔍 Starting ZAP full scan of ${targetUrl}...`);
    const startTime = Date.now();

    try {
      await this.waitForZAP();
      await this.setupScanContext(targetUrl);

      // Extended spidering
      console.log('🕷️ Extended spidering...');
      const spiderResult = await this.callZAPAPI('spider/action/scan/', { 
        url: targetUrl,
        maxChildren: '50',
        recurse: 'true',
      });
      
      await this.waitForSpiderComplete(spiderResult.scan);

      // AJAX spider for modern web apps
      console.log('🕸️ AJAX spidering...');
      const ajaxSpiderResult = await this.callZAPAPI('ajaxSpider/action/scan/', {
        url: targetUrl,
        inScope: 'true',
      });
      
      await this.waitForAjaxSpiderComplete();

      // Passive scan
      await this.waitForPassiveScanComplete();

      // Full active scan with all policies
      console.log('⚡ Full active scan...');
      const ascanResult = await this.callZAPAPI('ascan/action/scan/', {
        url: targetUrl,
        recurse: 'true',
        inScopeOnly: 'false',
        scanPolicyName: 'Default Policy',
      });
      
      await this.waitForActiveScanComplete(ascanResult.scan);

      const alertsResult = await this.callZAPAPI('core/view/alerts/', { baseurl: targetUrl });
      const alerts = alertsResult.alerts || [];

      const scanDuration = Date.now() - startTime;
      
      const result: ZAPScanResult = {
        timestamp: new Date().toISOString(),
        scanDuration,
        baseUrl: targetUrl,
        scanType: 'full',
        alerts,
        summary: this.calculateSummary(alerts),
        compliance: this.calculateCompliance(alerts),
      };

      console.log(`✅ Full scan completed in ${scanDuration}ms`);
      console.log(`📊 Found ${result.summary.total} alerts (${result.summary.high} high risk)`);

      return result;
    } catch (error) {
      console.error('Full scan failed:', error);
      throw error;
    }
  }

  async performAPIScan(targetUrl: string, apiDefinition?: string): Promise<ZAPScanResult> {
    console.log(`🔍 Starting ZAP API scan of ${targetUrl}...`);
    const startTime = Date.now();

    try {
      await this.waitForZAP();
      await this.setupScanContext(targetUrl);

      // Import API definition if provided
      if (apiDefinition) {
        console.log('📋 Importing API definition...');
        await this.callZAPAPI('openapi/action/importUrl/', {
          url: apiDefinition,
        });
      }

      // Spider API endpoints
      console.log('🕷️ Discovering API endpoints...');
      const spiderResult = await this.callZAPAPI('spider/action/scan/', { 
        url: targetUrl,
        maxChildren: '20',
        recurse: 'true',
      });
      
      await this.waitForSpiderComplete(spiderResult.scan);

      // API-focused active scan
      console.log('⚡ API security scan...');
      const ascanResult = await this.callZAPAPI('ascan/action/scan/', {
        url: targetUrl,
        recurse: 'true',
        inScopeOnly: 'false',
        scanPolicyName: 'API-focused',
      });
      
      await this.waitForActiveScanComplete(ascanResult.scan);

      const alertsResult = await this.callZAPAPI('core/view/alerts/', { baseurl: targetUrl });
      const alerts = alertsResult.alerts || [];

      const scanDuration = Date.now() - startTime;
      
      const result: ZAPScanResult = {
        timestamp: new Date().toISOString(),
        scanDuration,
        baseUrl: targetUrl,
        scanType: 'api',
        alerts,
        summary: this.calculateSummary(alerts),
        compliance: this.calculateCompliance(alerts),
      };

      console.log(`✅ API scan completed in ${scanDuration}ms`);
      console.log(`📊 Found ${result.summary.total} alerts (${result.summary.high} high risk)`);

      return result;
    } catch (error) {
      console.error('API scan failed:', error);
      throw error;
    }
  }

  private async waitForZAP(timeout: number = 30000): Promise<void> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      try {
        await this.callZAPAPI('core/view/version/');
        return;
      } catch (error) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    throw new Error('ZAP not ready within timeout');
  }

  private async setupScanContext(targetUrl: string): Promise<void> {
    console.log('⚙️ Setting up scan context...');
    
    // Create new context
    await this.callZAPAPI('context/action/newContext/', { 
      contextName: 'isectech-scan' 
    });
    
    // Include target URL in context
    await this.callZAPAPI('context/action/includeInContext/', {
      contextName: 'isectech-scan',
      regex: `${targetUrl}.*`,
    });

    // Set up session management
    await this.callZAPAPI('sessionManagement/action/setSessionManagementMethod/', {
      contextId: '0',
      methodName: 'cookieBasedSessionManagement',
    });
  }

  private async waitForSpiderComplete(spiderId: string): Promise<void> {
    let progress = 0;
    while (progress < 100) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      const status = await this.callZAPAPI('spider/view/status/', { scanId: spiderId });
      progress = parseInt(status.status);
      console.log(`🕷️ Spider progress: ${progress}%`);
    }
  }

  private async waitForAjaxSpiderComplete(): Promise<void> {
    let status = 'running';
    while (status === 'running') {
      await new Promise(resolve => setTimeout(resolve, 2000));
      const result = await this.callZAPAPI('ajaxSpider/view/status/');
      status = result.status;
      console.log(`🕸️ AJAX Spider status: ${status}`);
    }
  }

  private async waitForPassiveScanComplete(): Promise<void> {
    let recordsToScan = 1;
    while (recordsToScan > 0) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      const status = await this.callZAPAPI('pscan/view/recordsToScan/');
      recordsToScan = parseInt(status.recordsToScan);
      if (recordsToScan > 0) {
        console.log(`🔍 Passive scan records remaining: ${recordsToScan}`);
      }
    }
  }

  private async waitForActiveScanComplete(scanId: string): Promise<void> {
    let progress = 0;
    while (progress < 100) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      const status = await this.callZAPAPI('ascan/view/status/', { scanId });
      progress = parseInt(status.status);
      console.log(`⚡ Active scan progress: ${progress}%`);
    }
  }

  private calculateSummary(alerts: ZAPAlert[]) {
    return {
      total: alerts.length,
      high: alerts.filter(a => a.riskdesc.startsWith('High')).length,
      medium: alerts.filter(a => a.riskdesc.startsWith('Medium')).length,
      low: alerts.filter(a => a.riskdesc.startsWith('Low')).length,
      informational: alerts.filter(a => a.riskdesc.startsWith('Informational')).length,
    };
  }

  private calculateCompliance(alerts: ZAPAlert[]) {
    // Map ZAP alerts to OWASP Top 10 categories
    const owaspTop10Issues = alerts.filter(alert => {
      const alertName = alert.alert.toLowerCase();
      return (
        alertName.includes('injection') ||
        alertName.includes('authentication') ||
        alertName.includes('xss') ||
        alertName.includes('access control') ||
        alertName.includes('security misconfiguration') ||
        alertName.includes('cryptographic')
      );
    });

    // Security headers compliance
    const securityHeaderIssues = alerts.filter(alert => {
      const alertName = alert.alert.toLowerCase();
      return (
        alertName.includes('header') ||
        alertName.includes('hsts') ||
        alertName.includes('csp') ||
        alertName.includes('x-frame-options')
      );
    });

    return {
      owaspTop10: {
        passed: Math.max(0, 10 - owaspTop10Issues.length),
        failed: owaspTop10Issues.length,
      },
      securityHeaders: {
        passed: Math.max(0, 5 - securityHeaderIssues.length),
        failed: securityHeaderIssues.length,
      },
    };
  }

  async generateReport(scanResult: ZAPScanResult): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Save JSON report
    const jsonReportPath = path.join(this.resultsDir, `zap-${scanResult.scanType}-${timestamp}.json`);
    fs.writeFileSync(jsonReportPath, JSON.stringify(scanResult, null, 2));

    // Generate HTML report
    const htmlReportPath = path.join(this.resultsDir, `zap-${scanResult.scanType}-${timestamp}.html`);
    await this.generateHTMLReport(scanResult, htmlReportPath);

    // Generate Markdown report
    const markdownReportPath = path.join(this.resultsDir, `zap-${scanResult.scanType}-${timestamp}.md`);
    await this.generateMarkdownReport(scanResult, markdownReportPath);

    console.log(`📋 ZAP reports generated:`);
    console.log(`  JSON: ${jsonReportPath}`);
    console.log(`  HTML: ${htmlReportPath}`);
    console.log(`  Markdown: ${markdownReportPath}`);
  }

  private async generateHTMLReport(scanResult: ZAPScanResult, outputPath: string): Promise<void> {
    try {
      const htmlResult = await this.callZAPAPI('core/other/htmlreport/', { 
        baseurl: scanResult.baseUrl 
      });
      
      fs.writeFileSync(outputPath, htmlResult);
    } catch (error) {
      console.warn('Failed to generate HTML report via ZAP API, creating custom report');
      
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>OWASP ZAP Security Scan Report</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .alert { margin: 20px 0; padding: 15px; border-left: 4px solid; }
            .high { border-color: #dc3545; background-color: #f8d7da; }
            .medium { border-color: #fd7e14; background-color: #fff3cd; }
            .low { border-color: #28a745; background-color: #d4edda; }
            .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; }
          </style>
        </head>
        <body>
          <h1>OWASP ZAP Security Scan Report</h1>
          <div class="summary">
            <h2>Summary</h2>
            <p><strong>Scan Type:</strong> ${scanResult.scanType}</p>
            <p><strong>Target:</strong> ${scanResult.baseUrl}</p>
            <p><strong>Timestamp:</strong> ${scanResult.timestamp}</p>
            <p><strong>Duration:</strong> ${Math.round(scanResult.scanDuration / 1000)}s</p>
            <p><strong>Total Alerts:</strong> ${scanResult.summary.total}</p>
            <ul>
              <li>High Risk: ${scanResult.summary.high}</li>
              <li>Medium Risk: ${scanResult.summary.medium}</li>
              <li>Low Risk: ${scanResult.summary.low}</li>
              <li>Informational: ${scanResult.summary.informational}</li>
            </ul>
          </div>
          
          <h2>Alerts</h2>
          ${scanResult.alerts.map(alert => `
            <div class="alert ${alert.riskdesc.split(' ')[0].toLowerCase()}">
              <h3>${alert.alert}</h3>
              <p><strong>Risk:</strong> ${alert.riskdesc}</p>
              <p><strong>Confidence:</strong> ${alert.confidence}</p>
              <p><strong>Description:</strong> ${alert.desc}</p>
              <p><strong>Solution:</strong> ${alert.solution}</p>
              ${alert.instances.length > 0 ? `
                <h4>Instances (${alert.instances.length})</h4>
                <ul>
                  ${alert.instances.slice(0, 5).map(instance => `
                    <li>${instance.method} ${instance.uri}</li>
                  `).join('')}
                </ul>
              ` : ''}
            </div>
          `).join('')}
        </body>
        </html>
      `;
      
      fs.writeFileSync(outputPath, html);
    }
  }

  private async generateMarkdownReport(scanResult: ZAPScanResult, outputPath: string): Promise<void> {
    let markdown = `# OWASP ZAP Security Scan Report\n\n`;
    markdown += `**Scan Type:** ${scanResult.scanType}\n`;
    markdown += `**Target:** ${scanResult.baseUrl}\n`;
    markdown += `**Timestamp:** ${scanResult.timestamp}\n`;
    markdown += `**Duration:** ${Math.round(scanResult.scanDuration / 1000)}s\n\n`;
    
    markdown += `## Summary\n\n`;
    markdown += `- **Total Alerts:** ${scanResult.summary.total}\n`;
    markdown += `- **High Risk:** ${scanResult.summary.high}\n`;
    markdown += `- **Medium Risk:** ${scanResult.summary.medium}\n`;
    markdown += `- **Low Risk:** ${scanResult.summary.low}\n`;
    markdown += `- **Informational:** ${scanResult.summary.informational}\n\n`;
    
    markdown += `## Compliance\n\n`;
    markdown += `- **OWASP Top 10:** ${scanResult.compliance.owaspTop10.passed}/10 passed\n`;
    markdown += `- **Security Headers:** ${scanResult.compliance.securityHeaders.passed}/5 passed\n\n`;
    
    if (scanResult.alerts.length > 0) {
      markdown += `## Alerts\n\n`;
      
      scanResult.alerts.forEach((alert, index) => {
        markdown += `### ${index + 1}. ${alert.alert}\n\n`;
        markdown += `- **Risk:** ${alert.riskdesc}\n`;
        markdown += `- **Confidence:** ${alert.confidence}\n`;
        markdown += `- **CWE ID:** ${alert.cweid || 'N/A'}\n`;
        markdown += `- **WASC ID:** ${alert.wascid || 'N/A'}\n\n`;
        markdown += `**Description:** ${alert.desc}\n\n`;
        markdown += `**Solution:** ${alert.solution}\n\n`;
        
        if (alert.instances.length > 0) {
          markdown += `**Instances (${alert.instances.length}):**\n`;
          alert.instances.slice(0, 5).forEach(instance => {
            markdown += `- ${instance.method} ${instance.uri}\n`;
          });
          markdown += `\n`;
        }
        
        markdown += `---\n\n`;
      });
    }
    
    fs.writeFileSync(outputPath, markdown);
  }
}

test.describe('🛡️ OWASP ZAP Security Scanning', () => {
  let zapScanner: OWASPZAPScanner;
  const targetUrl = process.env.TEST_BASE_URL || 'http://localhost:3000';

  test.beforeAll(async () => {
    zapScanner = new OWASPZAPScanner(targetUrl);
    
    try {
      await zapScanner.startZAP();
    } catch (error) {
      console.error('Failed to start ZAP:', error);
      test.skip(true, 'OWASP ZAP not available - skipping security scans');
    }
  }, 120000); // 2 minute timeout for ZAP startup

  test.afterAll(async () => {
    if (zapScanner) {
      await zapScanner.stopZAP();
    }
  }, 30000);

  test('should perform baseline security scan', async () => {
    const scanResult = await zapScanner.performBaselineScan(targetUrl);
    
    // Assert security baseline
    expect(scanResult.summary.high).toBeLessThanOrEqual(2); // Allow max 2 high-risk issues
    expect(scanResult.summary.total).toBeLessThan(50); // Reasonable total alert count
    
    // Generate reports
    await zapScanner.generateReport(scanResult);
    
    console.log(`🔍 Baseline Scan Results:`);
    console.log(`  Duration: ${Math.round(scanResult.scanDuration / 1000)}s`);
    console.log(`  Total Alerts: ${scanResult.summary.total}`);
    console.log(`  High Risk: ${scanResult.summary.high}`);
    console.log(`  Medium Risk: ${scanResult.summary.medium}`);
    console.log(`  OWASP Top 10 Compliance: ${scanResult.compliance.owaspTop10.passed}/10`);
    
    // Fail test if critical security issues found
    if (scanResult.summary.high > 5) {
      throw new Error(`Too many high-risk security issues found: ${scanResult.summary.high}`);
    }
  }, 600000); // 10 minute timeout

  test('should perform API security scan', async () => {
    const apiUrl = `${targetUrl}/api`;
    const scanResult = await zapScanner.performAPIScan(apiUrl);
    
    // API security requirements are stricter
    expect(scanResult.summary.high).toBeLessThanOrEqual(1);
    
    await zapScanner.generateReport(scanResult);
    
    console.log(`🔍 API Scan Results:`);
    console.log(`  Duration: ${Math.round(scanResult.scanDuration / 1000)}s`);
    console.log(`  Total Alerts: ${scanResult.summary.total}`);
    console.log(`  High Risk: ${scanResult.summary.high}`);
    console.log(`  Security Headers Compliance: ${scanResult.compliance.securityHeaders.passed}/5`);
    
    if (scanResult.summary.high > 2) {
      throw new Error(`Critical API security issues found: ${scanResult.summary.high}`);
    }
  }, 600000); // 10 minute timeout

  test('should perform comprehensive security scan', async () => {
    const scanResult = await zapScanner.performFullScan(targetUrl);
    
    // Full scan comprehensive security assessment
    expect(scanResult.summary.high).toBeLessThanOrEqual(3);
    expect(scanResult.compliance.owaspTop10.passed).toBeGreaterThanOrEqual(8);
    
    await zapScanner.generateReport(scanResult);
    
    console.log(`🔍 Full Scan Results:`);
    console.log(`  Duration: ${Math.round(scanResult.scanDuration / 1000)}s`);
    console.log(`  Total Alerts: ${scanResult.summary.total}`);
    console.log(`  Risk Distribution:`);
    console.log(`    High: ${scanResult.summary.high}`);
    console.log(`    Medium: ${scanResult.summary.medium}`);  
    console.log(`    Low: ${scanResult.summary.low}`);
    console.log(`    Info: ${scanResult.summary.informational}`);
    console.log(`  Compliance Scores:`);
    console.log(`    OWASP Top 10: ${scanResult.compliance.owaspTop10.passed}/10`);
    console.log(`    Security Headers: ${scanResult.compliance.securityHeaders.passed}/5`);
    
    // Report high-risk findings
    const highRiskAlerts = scanResult.alerts.filter(a => a.riskdesc.startsWith('High'));
    if (highRiskAlerts.length > 0) {
      console.log(`\n🚨 High Risk Findings:`);
      highRiskAlerts.forEach((alert, index) => {
        console.log(`  ${index + 1}. ${alert.alert}`);
        console.log(`     Risk: ${alert.riskdesc}`);
        console.log(`     Instances: ${alert.instances.length}`);
      });
    }
    
    if (scanResult.summary.high > 5) {
      throw new Error(`Unacceptable number of high-risk security issues: ${scanResult.summary.high}`);
    }
  }, 900000); // 15 minute timeout for full scan
});