// iSECTECH SLA Reporting System
// Automated SLA report generation with multiple output formats

import { SLAMonitor, SLAReport, SLATarget, SLAReportTarget } from './sla-monitor';
import * as fs from 'fs/promises';
import * as path from 'path';
import { createObjectCsvWriter } from 'csv-writer';
import PDFDocument from 'pdfkit';
import * as nodemailer from 'nodemailer';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ReportConfig {
  outputDir: string;
  templateDir?: string;
  branding: {
    companyName: string;
    logo?: string;
    colors: {
      primary: string;
      secondary: string;
      success: string;
      warning: string;
      danger: string;
    };
  };
  email?: {
    transporter: nodemailer.Transporter;
    from: string;
    template?: string;
  };
}

export interface ReportTemplate {
  name: string;
  description: string;
  sections: ReportSection[];
}

export interface ReportSection {
  title: string;
  type: 'summary' | 'table' | 'chart' | 'text' | 'metrics';
  content?: string;
  data?: any;
  config?: any;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLA REPORTER CLASS
// ═══════════════════════════════════════════════════════════════════════════════

export class SLAReporter {
  private slaMonitor: SLAMonitor;
  private config: ReportConfig;

  constructor(slaMonitor: SLAMonitor, config: ReportConfig) {
    this.slaMonitor = slaMonitor;
    this.config = config;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // REPORT GENERATION
  // ═════════════════════════════════════════════════════════════════════════════

  async generateReport(
    period: 'hourly' | 'daily' | 'weekly' | 'monthly',
    format: 'json' | 'csv' | 'html' | 'pdf',
    startTime?: Date,
    endTime?: Date
  ): Promise<string> {
    // Generate the base report data
    const report = await this.slaMonitor.generateReport(period, startTime, endTime);
    
    // Generate the report in the requested format
    let filePath: string;
    
    switch (format) {
      case 'json':
        filePath = await this.generateJSONReport(report, period);
        break;
      case 'csv':
        filePath = await this.generateCSVReport(report, period);
        break;
      case 'html':
        filePath = await this.generateHTMLReport(report, period);
        break;
      case 'pdf':
        filePath = await this.generatePDFReport(report, period);
        break;
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
    
    return filePath;
  }

  async generateAllFormats(
    period: 'hourly' | 'daily' | 'weekly' | 'monthly',
    startTime?: Date,
    endTime?: Date
  ): Promise<{ [format: string]: string }> {
    const formats: ('json' | 'csv' | 'html' | 'pdf')[] = ['json', 'csv', 'html', 'pdf'];
    const results: { [format: string]: string } = {};
    
    for (const format of formats) {
      try {
        results[format] = await this.generateReport(period, format, startTime, endTime);
      } catch (error) {
        console.error(`Failed to generate ${format} report:`, error);
      }
    }
    
    return results;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // JSON REPORT
  // ═════════════════════════════════════════════════════════════════════════════

  private async generateJSONReport(report: SLAReport, period: string): Promise<string> {
    const timestamp = this.formatTimestamp(report.generatedAt);
    const filename = `sla-report-${period}-${timestamp}.json`;
    const filePath = path.join(this.config.outputDir, filename);
    
    await fs.writeFile(filePath, JSON.stringify(report, null, 2));
    return filePath;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // CSV REPORT
  // ═════════════════════════════════════════════════════════════════════════════

  private async generateCSVReport(report: SLAReport, period: string): Promise<string> {
    const timestamp = this.formatTimestamp(report.generatedAt);
    const filename = `sla-report-${period}-${timestamp}.csv`;
    const filePath = path.join(this.config.outputDir, filename);
    
    // Prepare CSV data
    const csvData = report.targets.map(target => ({
      service: target.target.service,
      targetName: target.target.name,
      slaTarget: `${target.target.target}%`,
      actualValue: `${target.actualValue.toFixed(2)}%`,
      slaAchieved: target.slaAchieved ? 'Yes' : 'No',
      uptimePercentage: `${target.uptimePercentage.toFixed(2)}%`,
      downtimeMinutes: target.downtimeMinutes,
      violationCount: target.violationCount,
      mttr: `${target.mttr.toFixed(1)} min`,
      mtbf: `${target.mtbf.toFixed(1)} min`,
      severity: target.target.severity,
      environment: target.target.environment,
    }));
    
    // Create CSV writer
    const csvWriter = createObjectCsvWriter({
      path: filePath,
      header: [
        { id: 'service', title: 'Service' },
        { id: 'targetName', title: 'SLA Target' },
        { id: 'slaTarget', title: 'Target %' },
        { id: 'actualValue', title: 'Actual %' },
        { id: 'slaAchieved', title: 'SLA Met' },
        { id: 'uptimePercentage', title: 'Uptime %' },
        { id: 'downtimeMinutes', title: 'Downtime (min)' },
        { id: 'violationCount', title: 'Violations' },
        { id: 'mttr', title: 'MTTR' },
        { id: 'mtbf', title: 'MTBF' },
        { id: 'severity', title: 'Severity' },
        { id: 'environment', title: 'Environment' },
      ],
    });
    
    await csvWriter.writeRecords(csvData);
    return filePath;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // HTML REPORT
  // ═════════════════════════════════════════════════════════════════════════════

  private async generateHTMLReport(report: SLAReport, period: string): Promise<string> {
    const timestamp = this.formatTimestamp(report.generatedAt);
    const filename = `sla-report-${period}-${timestamp}.html`;
    const filePath = path.join(this.config.outputDir, filename);
    
    const html = this.buildHTMLReport(report, period);
    await fs.writeFile(filePath, html);
    return filePath;
  }

  private buildHTMLReport(report: SLAReport, period: string): string {
    const { branding } = this.config;
    const periodText = this.formatPeriodText(period, report.startTime, report.endTime);
    
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${branding.companyName} SLA Report - ${periodText}</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f8f9fa;
            }
            .header {
                background: linear-gradient(135deg, ${branding.colors.primary}, ${branding.colors.secondary});
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 2.5em;
                font-weight: 300;
            }
            .header p {
                margin: 10px 0 0 0;
                font-size: 1.2em;
                opacity: 0.9;
            }
            .summary-cards {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .summary-card {
                background: white;
                padding: 25px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
            }
            .summary-card h3 {
                margin: 0 0 10px 0;
                color: #666;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .summary-card .value {
                font-size: 2.5em;
                font-weight: bold;
                margin: 0;
            }
            .success { color: ${branding.colors.success}; }
            .warning { color: ${branding.colors.warning}; }
            .danger { color: ${branding.colors.danger}; }
            .section {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }
            .section h2 {
                margin: 0 0 20px 0;
                color: ${branding.colors.primary};
                border-bottom: 2px solid ${branding.colors.primary};
                padding-bottom: 10px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            th, td {
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #f8f9fa;
                font-weight: 600;
                color: #555;
            }
            tr:hover {
                background-color: #f8f9fa;
            }
            .status-badge {
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: bold;
                color: white;
            }
            .status-met { background-color: ${branding.colors.success}; }
            .status-violated { background-color: ${branding.colors.danger}; }
            .incident {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 5px;
                padding: 15px;
                margin: 10px 0;
            }
            .incident-critical { border-color: ${branding.colors.danger}; background: #f8d7da; }
            .incident-high { border-color: ${branding.colors.warning}; background: #fff3cd; }
            .footer {
                text-align: center;
                padding: 20px;
                color: #666;
                font-size: 0.9em;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>${branding.companyName}</h1>
            <p>Service Level Agreement Report - ${periodText}</p>
            <p>Generated on ${report.generatedAt.toLocaleString()}</p>
        </div>

        <div class="summary-cards">
            <div class="summary-card">
                <h3>Overall SLA</h3>
                <p class="value ${this.getSLAClass(report.summary.overallSLAPercentage)}">
                    ${report.summary.overallSLAPercentage.toFixed(1)}%
                </p>
            </div>
            <div class="summary-card">
                <h3>Targets Met</h3>
                <p class="value success">${report.summary.targetsAchieved}/${report.summary.totalTargets}</p>
            </div>
            <div class="summary-card">
                <h3>Total Downtime</h3>
                <p class="value ${report.summary.totalDowntime > 60 ? 'danger' : 'success'}">
                    ${this.formatDowntime(report.summary.totalDowntime)}
                </p>
            </div>
            <div class="summary-card">
                <h3>Incidents</h3>
                <p class="value ${report.incidents.length > 0 ? 'warning' : 'success'}">
                    ${report.incidents.length}
                </p>
            </div>
        </div>

        <div class="section">
            <h2>SLA Targets Performance</h2>
            <table>
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>SLA Target</th>
                        <th>Target %</th>
                        <th>Actual %</th>
                        <th>Status</th>
                        <th>Uptime %</th>
                        <th>Downtime</th>
                        <th>Violations</th>
                        <th>MTTR</th>
                    </tr>
                </thead>
                <tbody>
                    ${report.targets.map(target => `
                        <tr>
                            <td><strong>${target.target.service}</strong></td>
                            <td>${target.target.name}</td>
                            <td>${target.target.target}%</td>
                            <td>${target.actualValue.toFixed(2)}%</td>
                            <td>
                                <span class="status-badge ${target.slaAchieved ? 'status-met' : 'status-violated'}">
                                    ${target.slaAchieved ? 'Met' : 'Violated'}
                                </span>
                            </td>
                            <td>${target.uptimePercentage.toFixed(2)}%</td>
                            <td>${this.formatDowntime(target.downtimeMinutes)}</td>
                            <td>${target.violationCount}</td>
                            <td>${target.mttr.toFixed(1)}m</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        ${report.incidents.length > 0 ? `
        <div class="section">
            <h2>Incidents (${report.incidents.length})</h2>
            ${report.incidents.map(incident => `
                <div class="incident incident-${incident.severity}">
                    <h4>${incident.title || incident.impact}</h4>
                    <p><strong>Service:</strong> ${incident.service}</p>
                    <p><strong>Duration:</strong> ${incident.duration ? this.formatDowntime(incident.duration) : 'Ongoing'}</p>
                    <p><strong>Severity:</strong> ${incident.severity}</p>
                    <p><strong>Status:</strong> ${incident.status}</p>
                    ${incident.resolution ? `<p><strong>Resolution:</strong> ${incident.resolution}</p>` : ''}
                </div>
            `).join('')}
        </div>
        ` : ''}

        <div class="footer">
            <p>This report was automatically generated by the ${branding.companyName} SLA monitoring system.</p>
            <p>For questions or concerns, please contact the operations team.</p>
        </div>
    </body>
    </html>
    `;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // PDF REPORT
  // ═════════════════════════════════════════════════════════════════════════════

  private async generatePDFReport(report: SLAReport, period: string): Promise<string> {
    const timestamp = this.formatTimestamp(report.generatedAt);
    const filename = `sla-report-${period}-${timestamp}.pdf`;
    const filePath = path.join(this.config.outputDir, filename);
    
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50 });
        doc.pipe(require('fs').createWriteStream(filePath));
        
        this.buildPDFReport(doc, report, period);
        
        doc.end();
        
        doc.on('end', () => resolve(filePath));
        doc.on('error', reject);
      } catch (error) {
        reject(error);
      }
    });
  }

  private buildPDFReport(doc: PDFDocument, report: SLAReport, period: string): void {
    const { branding } = this.config;
    const periodText = this.formatPeriodText(period, report.startTime, report.endTime);
    
    // Header
    doc.fontSize(20).text(branding.companyName, { align: 'center' });
    doc.fontSize(16).text(`Service Level Agreement Report`, { align: 'center' });
    doc.fontSize(12).text(periodText, { align: 'center' });
    doc.text(`Generated: ${report.generatedAt.toLocaleString()}`, { align: 'center' });
    
    doc.moveDown(2);
    
    // Summary Section
    doc.fontSize(14).text('Executive Summary', { underline: true });
    doc.moveDown();
    
    doc.fontSize(10)
       .text(`Overall SLA Performance: ${report.summary.overallSLAPercentage.toFixed(1)}%`)
       .text(`Targets Achieved: ${report.summary.targetsAchieved} of ${report.summary.totalTargets}`)
       .text(`Total Downtime: ${this.formatDowntime(report.summary.totalDowntime)}`)
       .text(`Incidents: ${report.incidents.length}`);
    
    doc.moveDown(2);
    
    // SLA Targets Table
    doc.fontSize(14).text('SLA Performance Details', { underline: true });
    doc.moveDown();
    
    // Table headers
    const startY = doc.y;
    const tableTop = startY;
    const rowHeight = 20;
    
    doc.fontSize(8);
    doc.text('Service', 50, tableTop, { width: 80 });
    doc.text('Target', 130, tableTop, { width: 60 });
    doc.text('Actual', 190, tableTop, { width: 60 });
    doc.text('Status', 250, tableTop, { width: 50 });
    doc.text('Uptime', 300, tableTop, { width: 60 });
    doc.text('Downtime', 360, tableTop, { width: 60 });
    doc.text('Violations', 420, tableTop, { width: 60 });
    doc.text('MTTR', 480, tableTop, { width: 60 });
    
    // Table data
    let currentY = tableTop + rowHeight;
    
    for (const target of report.targets) {
      if (currentY > 700) {
        doc.addPage();
        currentY = 50;
      }
      
      doc.text(target.target.service, 50, currentY, { width: 80 });
      doc.text(`${target.target.target}%`, 130, currentY, { width: 60 });
      doc.text(`${target.actualValue.toFixed(1)}%`, 190, currentY, { width: 60 });
      doc.text(target.slaAchieved ? 'Met' : 'Violated', 250, currentY, { width: 50 });
      doc.text(`${target.uptimePercentage.toFixed(1)}%`, 300, currentY, { width: 60 });
      doc.text(this.formatDowntime(target.downtimeMinutes), 360, currentY, { width: 60 });
      doc.text(target.violationCount.toString(), 420, currentY, { width: 60 });
      doc.text(`${target.mttr.toFixed(1)}m`, 480, currentY, { width: 60 });
      
      currentY += rowHeight;
    }
    
    // Incidents section if any
    if (report.incidents.length > 0) {
      doc.addPage();
      doc.fontSize(14).text('Incidents', { underline: true });
      doc.moveDown();
      
      for (const incident of report.incidents) {
        doc.fontSize(10)
           .text(`Service: ${incident.service}`)
           .text(`Duration: ${incident.duration ? this.formatDowntime(incident.duration) : 'Ongoing'}`)
           .text(`Severity: ${incident.severity}`)
           .text(`Status: ${incident.status}`);
        
        if (incident.resolution) {
          doc.text(`Resolution: ${incident.resolution}`);
        }
        
        doc.moveDown();
      }
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // EMAIL DISTRIBUTION
  // ═════════════════════════════════════════════════════════════════════════════

  async emailReport(
    reportPaths: { [format: string]: string },
    recipients: string[],
    period: string,
    subject?: string
  ): Promise<void> {
    if (!this.config.email) {
      throw new Error('Email configuration not provided');
    }
    
    const { transporter, from } = this.config.email;
    const reportSubject = subject || `iSECTECH SLA Report - ${period.charAt(0).toUpperCase() + period.slice(1)}`;
    
    // Prepare attachments
    const attachments = Object.entries(reportPaths).map(([format, filePath]) => ({
      filename: path.basename(filePath),
      path: filePath,
    }));
    
    // Email content
    const emailBody = this.buildEmailBody(period);
    
    // Send email
    await transporter.sendMail({
      from,
      to: recipients.join(', '),
      subject: reportSubject,
      html: emailBody,
      attachments,
    });
  }

  private buildEmailBody(period: string): string {
    const { branding } = this.config;
    
    return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: ${branding.colors.primary}; color: white; padding: 20px; text-align: center;">
        <h1>${branding.companyName}</h1>
        <h2>SLA Report - ${period.charAt(0).toUpperCase() + period.slice(1)}</h2>
      </div>
      
      <div style="padding: 20px;">
        <p>Dear Team,</p>
        
        <p>Please find attached the latest SLA performance report for the ${period} period. 
        The report includes detailed metrics on service availability, performance, and incident summaries.</p>
        
        <p>The report is available in multiple formats:</p>
        <ul>
          <li><strong>HTML:</strong> Interactive web-based report</li>
          <li><strong>PDF:</strong> Printable executive summary</li>
          <li><strong>CSV:</strong> Raw data for analysis</li>
          <li><strong>JSON:</strong> Machine-readable format</li>
        </ul>
        
        <p>Please review the report and contact the operations team if you have any questions 
        or concerns about the SLA performance.</p>
        
        <p>Best regards,<br>
        ${branding.companyName} Operations Team</p>
      </div>
      
      <div style="background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #666;">
        This report was automatically generated by the ${branding.companyName} SLA monitoring system.
      </div>
    </div>
    `;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private formatTimestamp(date: Date): string {
    return date.toISOString().slice(0, 19).replace(/:/g, '-');
  }

  private formatPeriodText(period: string, startTime: Date, endTime: Date): string {
    const start = startTime.toLocaleDateString();
    const end = endTime.toLocaleDateString();
    return `${period.charAt(0).toUpperCase() + period.slice(1)} Report (${start} - ${end})`;
  }

  private formatDowntime(minutes: number): string {
    if (minutes < 60) {
      return `${minutes.toFixed(0)}m`;
    }
    
    const hours = Math.floor(minutes / 60);
    const mins = Math.floor(minutes % 60);
    
    if (hours < 24) {
      return `${hours}h ${mins}m`;
    }
    
    const days = Math.floor(hours / 24);
    const remainingHours = hours % 24;
    return `${days}d ${remainingHours}h ${mins}m`;
  }

  private getSLAClass(percentage: number): string {
    if (percentage >= 99.5) return 'success';
    if (percentage >= 99.0) return 'warning';
    return 'danger';
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function createSLAReporter(slaMonitor: SLAMonitor, config: ReportConfig): SLAReporter {
  return new SLAReporter(slaMonitor, config);
}

// Export default configuration
export const defaultReportConfig: Partial<ReportConfig> = {
  branding: {
    companyName: 'iSECTECH',
    colors: {
      primary: '#2563eb',
      secondary: '#1e40af',
      success: '#16a34a',
      warning: '#d97706',
      danger: '#dc2626',
    },
  },
};