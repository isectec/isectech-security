import jsPDF from 'jspdf';
import 'jspdf-autotable';
import * as XLSX from 'xlsx';

// Types for export data
interface ExecutiveMetrics {
  securityScore: number;
  riskExposure: number;
  complianceScore: number;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  incidentCount: number;
  mttr: number;
  mttd: number;
  securityROI: number;
  budgetUtilization: number;
  teamEfficiency: number;
  timestamp: Date;
  confidence: number;
}

interface RiskTrend {
  timestamp: Date;
  securityScore: number;
  riskExposure: number;
  incidentCount: number;
  threatLevel: number;
  complianceScore: number;
}

interface ComplianceFramework {
  name: string;
  score: number;
  status: 'compliant' | 'partial' | 'non_compliant';
  lastAudit: Date;
  nextAudit: Date;
  criticalFindings: number;
}

interface SecurityAlert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  timestamp: Date;
  category: string;
  status: 'open' | 'investigating' | 'resolved';
  assignee?: string;
}

interface SecurityPostureScore {
  overall: number;
  categories: {
    identity: number;
    network: number;
    data: number;
    application: number;
    infrastructure: number;
    compliance: number;
  };
  trends: {
    category: string;
    current: number;
    previous: number;
    change: number;
    trend: 'up' | 'down' | 'stable';
  }[];
  timestamp: Date;
  confidence: number;
}

interface ExportData {
  executiveMetrics?: ExecutiveMetrics | null;
  riskTrends?: RiskTrend[] | null;
  complianceFrameworks?: ComplianceFramework[] | null;
  securityAlerts?: SecurityAlert[] | null;
  securityPostureScore?: SecurityPostureScore | null;
  generatedAt: Date;
  timeRange: string;
  userRole: string;
  tenantId: string;
  organizationName?: string;
}

interface ExportOptions {
  includeTrends: boolean;
  includeCompliance: boolean;
  includeAlerts: boolean;
  includePostureScoring: boolean;
  logoUrl?: string;
  customBranding?: {
    primaryColor: string;
    secondaryColor: string;
    companyName: string;
  };
}

export class ExecutiveReportExportService {
  private static instance: ExecutiveReportExportService;

  static getInstance(): ExecutiveReportExportService {
    if (!ExecutiveReportExportService.instance) {
      ExecutiveReportExportService.instance = new ExecutiveReportExportService();
    }
    return ExecutiveReportExportService.instance;
  }

  /**
   * Export executive report as PDF
   */
  async exportToPDF(data: ExportData, options: ExportOptions): Promise<void> {
    try {
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      let currentY = 20;

      // Colors
      const primaryColor = options.customBranding?.primaryColor || '#1976d2';
      const secondaryColor = options.customBranding?.secondaryColor || '#757575';

      // Header
      pdf.setFillColor(primaryColor);
      pdf.rect(0, 0, pageWidth, 25, 'F');
      
      pdf.setTextColor(255, 255, 255);
      pdf.setFontSize(20);
      pdf.text('Executive Security Report', 20, 15);
      
      pdf.setFontSize(12);
      pdf.text(`Generated: ${data.generatedAt.toLocaleString()}`, pageWidth - 80, 15);
      
      currentY = 35;

      // Executive Summary
      pdf.setTextColor(0, 0, 0);
      pdf.setFontSize(16);
      pdf.text('Executive Summary', 20, currentY);
      currentY += 10;

      if (data.executiveMetrics) {
        const metrics = data.executiveMetrics;
        
        // Key metrics table
        const summaryData = [
          ['Security Score', `${Math.round(metrics.securityScore)}%`, this.getScoreStatus(metrics.securityScore)],
          ['Risk Exposure', `${Math.round(metrics.riskExposure)}%`, this.getRiskStatus(metrics.riskExposure)],
          ['Compliance Score', `${Math.round(metrics.complianceScore)}%`, this.getScoreStatus(metrics.complianceScore)],
          ['Threat Level', metrics.threatLevel.toUpperCase(), this.getThreatStatus(metrics.threatLevel)],
          ['Active Incidents', metrics.incidentCount.toString(), metrics.incidentCount > 5 ? 'High' : 'Normal'],
          ['MTTR', `${Math.round(metrics.mttr)} min`, this.getTimeStatus(metrics.mttr)],
          ['Security ROI', `${Math.round(metrics.securityROI)}%`, metrics.securityROI > 100 ? 'Positive' : 'Negative'],
          ['Budget Utilization', `${Math.round(metrics.budgetUtilization)}%`, this.getBudgetStatus(metrics.budgetUtilization)]
        ];

        (pdf as any).autoTable({
          startY: currentY,
          head: [['Metric', 'Value', 'Status']],
          body: summaryData,
          theme: 'grid',
          headStyles: { fillColor: primaryColor },
          margin: { left: 20, right: 20 }
        });

        currentY = (pdf as any).lastAutoTable.finalY + 20;
      }

      // Security Posture Breakdown
      if (data.securityPostureScore && options.includePostureScoring) {
        if (currentY > pageHeight - 60) {
          pdf.addPage();
          currentY = 20;
        }

        pdf.setFontSize(16);
        pdf.text('Security Posture Breakdown', 20, currentY);
        currentY += 10;

        const postureData = Object.entries(data.securityPostureScore.categories).map(([category, score]) => {
          const trend = data.securityPostureScore!.trends.find(t => t.category === category);
          return [
            category.charAt(0).toUpperCase() + category.slice(1),
            `${Math.round(score)}%`,
            trend ? `${trend.change > 0 ? '+' : ''}${trend.change.toFixed(1)}%` : 'N/A',
            this.getScoreStatus(score)
          ];
        });

        (pdf as any).autoTable({
          startY: currentY,
          head: [['Category', 'Score', 'Trend', 'Status']],
          body: postureData,
          theme: 'grid',
          headStyles: { fillColor: primaryColor },
          margin: { left: 20, right: 20 }
        });

        currentY = (pdf as any).lastAutoTable.finalY + 20;
      }

      // Compliance Status
      if (data.complianceFrameworks && options.includeCompliance) {
        if (currentY > pageHeight - 60) {
          pdf.addPage();
          currentY = 20;
        }

        pdf.setFontSize(16);
        pdf.text('Compliance Status', 20, currentY);
        currentY += 10;

        const complianceData = data.complianceFrameworks.map(framework => [
          framework.name,
          `${Math.round(framework.score)}%`,
          framework.status.replace('_', ' ').toUpperCase(),
          framework.lastAudit.toLocaleDateString(),
          framework.criticalFindings.toString()
        ]);

        (pdf as any).autoTable({
          startY: currentY,
          head: [['Framework', 'Score', 'Status', 'Last Audit', 'Critical Findings']],
          body: complianceData,
          theme: 'grid',
          headStyles: { fillColor: primaryColor },
          margin: { left: 20, right: 20 }
        });

        currentY = (pdf as any).lastAutoTable.finalY + 20;
      }

      // Security Alerts
      if (data.securityAlerts && options.includeAlerts) {
        if (currentY > pageHeight - 60) {
          pdf.addPage();
          currentY = 20;
        }

        pdf.setFontSize(16);
        pdf.text('Recent Security Alerts', 20, currentY);
        currentY += 10;

        const criticalAlerts = data.securityAlerts
          .filter(alert => alert.severity === 'critical' || alert.severity === 'high')
          .slice(0, 10)
          .map(alert => [
            alert.severity.toUpperCase(),
            alert.title,
            alert.category,
            alert.status.toUpperCase(),
            alert.timestamp.toLocaleDateString()
          ]);

        if (criticalAlerts.length > 0) {
          (pdf as any).autoTable({
            startY: currentY,
            head: [['Severity', 'Title', 'Category', 'Status', 'Date']],
            body: criticalAlerts,
            theme: 'grid',
            headStyles: { fillColor: primaryColor },
            margin: { left: 20, right: 20 }
          });
        } else {
          pdf.text('No critical or high severity alerts found.', 20, currentY);
        }
      }

      // Footer
      const totalPages = pdf.getNumberOfPages();
      for (let i = 1; i <= totalPages; i++) {
        pdf.setPage(i);
        pdf.setFontSize(10);
        pdf.setTextColor(128, 128, 128);
        pdf.text(
          `Page ${i} of ${totalPages} - Confidential Security Report`,
          pageWidth / 2,
          pageHeight - 10,
          { align: 'center' }
        );
      }

      // Save the PDF
      const fileName = `executive-security-report-${new Date().toISOString().split('T')[0]}.pdf`;
      pdf.save(fileName);

    } catch (error) {
      throw new Error(`PDF export failed: ${error}`);
    }
  }

  /**
   * Export executive report as Excel
   */
  async exportToExcel(data: ExportData, options: ExportOptions): Promise<void> {
    try {
      const workbook = XLSX.utils.book_new();

      // Executive Summary sheet
      if (data.executiveMetrics) {
        const summaryData = [
          ['Executive Security Report'],
          [`Generated: ${data.generatedAt.toLocaleString()}`],
          [`Time Range: ${data.timeRange}`],
          [`User Role: ${data.userRole}`],
          [''],
          ['Key Metrics', 'Value', 'Status'],
          ['Security Score', `${Math.round(data.executiveMetrics.securityScore)}%`, this.getScoreStatus(data.executiveMetrics.securityScore)],
          ['Risk Exposure', `${Math.round(data.executiveMetrics.riskExposure)}%`, this.getRiskStatus(data.executiveMetrics.riskExposure)],
          ['Compliance Score', `${Math.round(data.executiveMetrics.complianceScore)}%`, this.getScoreStatus(data.executiveMetrics.complianceScore)],
          ['Threat Level', data.executiveMetrics.threatLevel.toUpperCase(), this.getThreatStatus(data.executiveMetrics.threatLevel)],
          ['Active Incidents', data.executiveMetrics.incidentCount, data.executiveMetrics.incidentCount > 5 ? 'High' : 'Normal'],
          ['MTTR (minutes)', Math.round(data.executiveMetrics.mttr), this.getTimeStatus(data.executiveMetrics.mttr)],
          ['MTTD (minutes)', Math.round(data.executiveMetrics.mttd), this.getTimeStatus(data.executiveMetrics.mttd)],
          ['Security ROI', `${Math.round(data.executiveMetrics.securityROI)}%`, data.executiveMetrics.securityROI > 100 ? 'Positive' : 'Negative'],
          ['Budget Utilization', `${Math.round(data.executiveMetrics.budgetUtilization)}%`, this.getBudgetStatus(data.executiveMetrics.budgetUtilization)]
        ];

        const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
        XLSX.utils.book_append_sheet(workbook, summarySheet, 'Executive Summary');
      }

      // Security Posture sheet
      if (data.securityPostureScore && options.includePostureScoring) {
        const postureData = [
          ['Security Posture Breakdown'],
          ['Category', 'Current Score', 'Previous Score', 'Change %', 'Trend', 'Status'],
          ...Object.entries(data.securityPostureScore.categories).map(([category, score]) => {
            const trend = data.securityPostureScore!.trends.find(t => t.category === category);
            return [
              category.charAt(0).toUpperCase() + category.slice(1),
              Math.round(score),
              trend ? Math.round(trend.previous) : 'N/A',
              trend ? `${trend.change.toFixed(1)}%` : 'N/A',
              trend ? trend.trend.toUpperCase() : 'N/A',
              this.getScoreStatus(score)
            ];
          })
        ];

        const postureSheet = XLSX.utils.aoa_to_sheet(postureData);
        XLSX.utils.book_append_sheet(workbook, postureSheet, 'Security Posture');
      }

      // Risk Trends sheet
      if (data.riskTrends && options.includeTrends) {
        const trendsData = [
          ['Risk Trends Over Time'],
          ['Date', 'Security Score', 'Risk Exposure', 'Incident Count', 'Threat Level', 'Compliance Score'],
          ...data.riskTrends.map(trend => [
            trend.timestamp.toLocaleDateString(),
            Math.round(trend.securityScore),
            Math.round(trend.riskExposure),
            trend.incidentCount,
            trend.threatLevel,
            Math.round(trend.complianceScore)
          ])
        ];

        const trendsSheet = XLSX.utils.aoa_to_sheet(trendsData);
        XLSX.utils.book_append_sheet(workbook, trendsSheet, 'Risk Trends');
      }

      // Compliance sheet
      if (data.complianceFrameworks && options.includeCompliance) {
        const complianceData = [
          ['Compliance Framework Status'],
          ['Framework', 'Score', 'Status', 'Last Audit', 'Next Audit', 'Critical Findings'],
          ...data.complianceFrameworks.map(framework => [
            framework.name,
            Math.round(framework.score),
            framework.status.replace('_', ' ').toUpperCase(),
            framework.lastAudit.toLocaleDateString(),
            framework.nextAudit.toLocaleDateString(),
            framework.criticalFindings
          ])
        ];

        const complianceSheet = XLSX.utils.aoa_to_sheet(complianceData);
        XLSX.utils.book_append_sheet(workbook, complianceSheet, 'Compliance');
      }

      // Security Alerts sheet
      if (data.securityAlerts && options.includeAlerts) {
        const alertsData = [
          ['Security Alerts'],
          ['Severity', 'Title', 'Description', 'Category', 'Status', 'Assignee', 'Timestamp'],
          ...data.securityAlerts.map(alert => [
            alert.severity.toUpperCase(),
            alert.title,
            alert.description,
            alert.category,
            alert.status.toUpperCase(),
            alert.assignee || 'Unassigned',
            alert.timestamp.toLocaleString()
          ])
        ];

        const alertsSheet = XLSX.utils.aoa_to_sheet(alertsData);
        XLSX.utils.book_append_sheet(workbook, alertsSheet, 'Security Alerts');
      }

      // Save the Excel file
      const fileName = `executive-security-report-${new Date().toISOString().split('T')[0]}.xlsx`;
      XLSX.writeFile(workbook, fileName);

    } catch (error) {
      throw new Error(`Excel export failed: ${error}`);
    }
  }

  /**
   * Export executive report as CSV
   */
  async exportToCSV(data: ExportData, options: ExportOptions): Promise<void> {
    try {
      let csvContent = '';

      // Executive Summary CSV
      if (data.executiveMetrics) {
        csvContent += 'Executive Security Report Summary\n';
        csvContent += `Generated,${data.generatedAt.toLocaleString()}\n`;
        csvContent += `Time Range,${data.timeRange}\n`;
        csvContent += `User Role,${data.userRole}\n\n`;

        csvContent += 'Metric,Value,Status\n';
        csvContent += `Security Score,${Math.round(data.executiveMetrics.securityScore)}%,${this.getScoreStatus(data.executiveMetrics.securityScore)}\n`;
        csvContent += `Risk Exposure,${Math.round(data.executiveMetrics.riskExposure)}%,${this.getRiskStatus(data.executiveMetrics.riskExposure)}\n`;
        csvContent += `Compliance Score,${Math.round(data.executiveMetrics.complianceScore)}%,${this.getScoreStatus(data.executiveMetrics.complianceScore)}\n`;
        csvContent += `Threat Level,${data.executiveMetrics.threatLevel.toUpperCase()},${this.getThreatStatus(data.executiveMetrics.threatLevel)}\n`;
        csvContent += `Active Incidents,${data.executiveMetrics.incidentCount},${data.executiveMetrics.incidentCount > 5 ? 'High' : 'Normal'}\n`;
        csvContent += `MTTR (minutes),${Math.round(data.executiveMetrics.mttr)},${this.getTimeStatus(data.executiveMetrics.mttr)}\n`;
        csvContent += `MTTD (minutes),${Math.round(data.executiveMetrics.mttd)},${this.getTimeStatus(data.executiveMetrics.mttd)}\n`;
        csvContent += `Security ROI,${Math.round(data.executiveMetrics.securityROI)}%,${data.executiveMetrics.securityROI > 100 ? 'Positive' : 'Negative'}\n`;
        csvContent += `Budget Utilization,${Math.round(data.executiveMetrics.budgetUtilization)}%,${this.getBudgetStatus(data.executiveMetrics.budgetUtilization)}\n\n`;
      }

      // Security Posture CSV
      if (data.securityPostureScore && options.includePostureScoring) {
        csvContent += 'Security Posture Breakdown\n';
        csvContent += 'Category,Current Score,Previous Score,Change %,Trend,Status\n';
        
        Object.entries(data.securityPostureScore.categories).forEach(([category, score]) => {
          const trend = data.securityPostureScore!.trends.find(t => t.category === category);
          csvContent += `${category.charAt(0).toUpperCase() + category.slice(1)},${Math.round(score)},${trend ? Math.round(trend.previous) : 'N/A'},${trend ? trend.change.toFixed(1) + '%' : 'N/A'},${trend ? trend.trend.toUpperCase() : 'N/A'},${this.getScoreStatus(score)}\n`;
        });
        csvContent += '\n';
      }

      // Compliance CSV
      if (data.complianceFrameworks && options.includeCompliance) {
        csvContent += 'Compliance Framework Status\n';
        csvContent += 'Framework,Score,Status,Last Audit,Next Audit,Critical Findings\n';
        
        data.complianceFrameworks.forEach(framework => {
          csvContent += `${framework.name},${Math.round(framework.score)},${framework.status.replace('_', ' ').toUpperCase()},${framework.lastAudit.toLocaleDateString()},${framework.nextAudit.toLocaleDateString()},${framework.criticalFindings}\n`;
        });
        csvContent += '\n';
      }

      // Download CSV
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `executive-security-report-${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

    } catch (error) {
      throw new Error(`CSV export failed: ${error}`);
    }
  }

  // Helper methods for status determination
  private getScoreStatus(score: number): string {
    if (score >= 90) return 'Excellent';
    if (score >= 80) return 'Good';
    if (score >= 70) return 'Fair';
    if (score >= 60) return 'Poor';
    return 'Critical';
  }

  private getRiskStatus(risk: number): string {
    if (risk <= 20) return 'Low';
    if (risk <= 40) return 'Medium';
    if (risk <= 60) return 'High';
    return 'Critical';
  }

  private getThreatStatus(level: string): string {
    switch (level) {
      case 'low': return 'Low Risk';
      case 'medium': return 'Medium Risk';
      case 'high': return 'High Risk';
      case 'critical': return 'Critical Risk';
      default: return 'Unknown';
    }
  }

  private getTimeStatus(minutes: number): string {
    if (minutes <= 60) return 'Excellent';
    if (minutes <= 120) return 'Good';
    if (minutes <= 240) return 'Fair';
    return 'Poor';
  }

  private getBudgetStatus(utilization: number): string {
    if (utilization <= 75) return 'Under Budget';
    if (utilization <= 90) return 'On Track';
    if (utilization <= 95) return 'Near Limit';
    return 'Over Budget';
  }
}

// Export service instance
export const exportService = ExecutiveReportExportService.getInstance();