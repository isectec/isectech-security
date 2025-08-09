'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Box, Alert, Typography, CircularProgress } from '@mui/material';
import { useReportGeneration } from '../../../lib/hooks/use-report-generation';
import {
  ExecutiveReportGeneratorProps,
  ExecutiveReport,
  ExecutiveReportSection,
  ReportVisualization
} from './types';

export const ExecutiveReportGenerator: React.FC<ExecutiveReportGeneratorProps> = ({
  config,
  onReportGenerated,
  template = 'executive-brief',
  schedule = 'weekly',
  autoGenerate = true
}) => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastGenerated, setLastGenerated] = useState<Date | null>(null);

  const {
    generateReport,
    getReportTemplate,
    validateReportData,
    exportReport
  } = useReportGeneration({
    userId: config.userId,
    tenantId: config.tenantId,
    userRole: config.userRole
  });

  useEffect(() => {
    if (autoGenerate) {
      const interval = getScheduleInterval(schedule);
      const timer = setInterval(generateScheduledReport, interval);
      
      // Generate initial report if none exists
      if (!lastGenerated) {
        generateScheduledReport();
      }

      return () => clearInterval(timer);
    }
  }, [autoGenerate, schedule, lastGenerated]);

  const getScheduleInterval = (schedule: string): number => {
    switch (schedule) {
      case 'daily': return 24 * 60 * 60 * 1000; // 24 hours
      case 'weekly': return 7 * 24 * 60 * 60 * 1000; // 7 days
      case 'monthly': return 30 * 24 * 60 * 60 * 1000; // 30 days
      default: return 7 * 24 * 60 * 60 * 1000;
    }
  };

  const generateScheduledReport = useCallback(async () => {
    if (isGenerating) return;

    try {
      setIsGenerating(true);
      setError(null);

      const report = await generateExecutiveReport();
      
      setLastGenerated(new Date());
      onReportGenerated(report);

    } catch (error) {
      console.error('Scheduled report generation failed:', error);
      setError('Failed to generate scheduled report');
    } finally {
      setIsGenerating(false);
    }
  }, [isGenerating, generateExecutiveReport, onReportGenerated]);

  const generateExecutiveReport = async (): Promise<ExecutiveReport> => {
    const now = new Date();
    const period = getReportPeriod(schedule);

    // Gather report data
    const reportData = await gatherReportData(period);

    // Generate report sections
    const sections = await generateReportSections(reportData);

    // Generate executive summary
    const executiveSummary = generateExecutiveSummary(reportData, config.userRole);

    // Create the report
    const report: ExecutiveReport = {
      id: `exec-report-${now.getTime()}`,
      type: 'security-summary',
      title: `Executive Security Report - ${period.label}`,
      subtitle: `Comprehensive security analysis for ${config.userRole.toUpperCase()}`,
      period,
      sections,
      executiveSummary,
      keyMetrics: generateKeyMetrics(reportData),
      insights: generateInsights(reportData),
      recommendations: generateRecommendations(reportData),
      appendices: generateAppendices(reportData),
      metadata: {
        generatedAt: now,
        generatedBy: 'AI Executive Agent',
        version: '1.0',
        confidentialityLevel: 'confidential',
        distributionList: [config.userId],
        expirationDate: new Date(now.getTime() + (30 * 24 * 60 * 60 * 1000)) // 30 days
      },
      format: {
        template: template as any,
        styling: getExecutiveStyling(),
        exportFormats: ['pdf', 'powerpoint', 'html']
      }
    };

    return report;
  };

  const getReportPeriod = (schedule: string) => {
    const now = new Date();
    const start = new Date();
    
    switch (schedule) {
      case 'daily':
        start.setDate(now.getDate() - 1);
        return { start, end: now, label: 'Last 24 Hours' };
      case 'weekly':
        start.setDate(now.getDate() - 7);
        return { start, end: now, label: 'Past Week' };
      case 'monthly':
        start.setMonth(now.getMonth() - 1);
        return { start, end: now, label: 'Past Month' };
      default:
        start.setDate(now.getDate() - 7);
        return { start, end: now, label: 'Past Week' };
    }
  };

  const gatherReportData = async (period: any) => {
    // Simulate gathering comprehensive security data
    return {
      securityPosture: {
        score: 87,
        trend: 'improving',
        change: 5.2
      },
      threatLandscape: {
        totalThreats: 342,
        criticalThreats: 8,
        resolvedThreats: 298,
        averageResponseTime: 186 // minutes
      },
      compliance: {
        overallScore: 92,
        frameworks: {
          'GDPR': 96,
          'SOX': 89,
          'HIPAA': 91,
          'PCI-DSS': 94
        }
      },
      incidents: {
        total: 15,
        resolved: 13,
        pending: 2,
        averageResolutionTime: 4.2 // hours
      },
      investments: {
        totalSpent: 2500000,
        roi: 145,
        costSavings: 890000
      }
    };
  };

  const generateReportSections = async (data: any): Promise<ExecutiveReportSection[]> => {
    return [
      {
        id: 'executive-overview',
        title: 'Executive Overview',
        content: generateOverviewContent(data),
        visualizations: await generateOverviewVisualizations(data),
        order: 1,
        importance: 'critical'
      },
      {
        id: 'security-posture',
        title: 'Security Posture Analysis',
        content: generateSecurityPostureContent(data),
        visualizations: await generateSecurityVisualizations(data),
        order: 2,
        importance: 'high'
      },
      {
        id: 'threat-intelligence',
        title: 'Threat Intelligence Summary',
        content: generateThreatContent(data),
        visualizations: await generateThreatVisualizations(data),
        order: 3,
        importance: 'high'
      },
      {
        id: 'compliance-status',
        title: 'Compliance & Risk Assessment',
        content: generateComplianceContent(data),
        visualizations: await generateComplianceVisualizations(data),
        order: 4,
        importance: 'high'
      },
      {
        id: 'investment-analysis',
        title: 'Security Investment & ROI',
        content: generateInvestmentContent(data),
        visualizations: await generateInvestmentVisualizations(data),
        order: 5,
        importance: 'medium'
      }
    ];
  };

  const generateExecutiveSummary = (data: any, userRole: string): string => {
    const summary = `
**Executive Summary**

Our security posture remains strong with a score of ${data.securityPosture.score}%, representing a ${data.securityPosture.change}% improvement over the previous period. 

**Key Highlights:**
• Successfully detected and mitigated ${data.threatLandscape.resolvedThreats} of ${data.threatLandscape.totalThreats} threats
• Maintained ${data.compliance.overallScore}% compliance across all regulatory frameworks
• Achieved ${data.investments.roi}% return on security investments
• Reduced incident response time to ${data.incidents.averageResolutionTime} hours

**Strategic Priorities:**
${userRole === 'ceo' ? 
  '• Focus on security ROI optimization and business risk reduction\n• Ensure alignment with business growth objectives\n• Maintain competitive security advantage' :
  '• Enhance threat detection capabilities and response times\n• Address compliance gaps in identified frameworks\n• Optimize security operations efficiency'
}

**Executive Action Required:**
• Review and approve recommended security investments totaling $${(data.investments.totalSpent / 1000000).toFixed(1)}M
• Address ${data.incidents.pending} pending high-priority incidents
• Consider expanding security team to support growth initiatives
    `.trim();

    return summary;
  };

  const generateKeyMetrics = (data: any) => {
    return [
      {
        id: 'security-posture',
        name: 'Security Posture Score',
        value: data.securityPosture.score,
        unit: '%',
        format: 'percentage' as const,
        trend: { direction: 'up' as const, change: data.securityPosture.change, period: 'month' },
        target: 90,
        status: data.securityPosture.score >= 85 ? 'good' as const : 'warning' as const,
        description: 'Overall security health measurement'
      },
      {
        id: 'threat-resolution',
        name: 'Threat Resolution Rate',
        value: Math.round((data.threatLandscape.resolvedThreats / data.threatLandscape.totalThreats) * 100),
        unit: '%',
        format: 'percentage' as const,
        trend: { direction: 'up' as const, change: 8.3, period: 'month' },
        target: 95,
        status: 'good' as const,
        description: 'Percentage of threats successfully resolved'
      },
      {
        id: 'response-time',
        name: 'Average Response Time',
        value: data.incidents.averageResolutionTime,
        unit: 'hours',
        format: 'time' as const,
        trend: { direction: 'down' as const, change: -12.5, period: 'month' },
        target: 4,
        status: data.incidents.averageResolutionTime <= 4 ? 'good' as const : 'warning' as const,
        description: 'Average time to resolve security incidents'
      },
      {
        id: 'security-roi',
        name: 'Security ROI',
        value: data.investments.roi,
        unit: '%',
        format: 'percentage' as const,
        trend: { direction: 'up' as const, change: 23.1, period: 'quarter' },
        status: 'good' as const,
        description: 'Return on security investments'
      }
    ];
  };

  const generateInsights = (data: any) => {
    return [
      {
        id: 'insight-1',
        type: 'security-posture' as const,
        title: 'Security Posture Improvement',
        description: `Security posture has improved by ${data.securityPosture.change}% due to enhanced endpoint protection and network security measures.`,
        severity: 'medium' as const,
        confidence: 0.92,
        impact: {
          business: 'medium' as const,
          financial: 450000,
          operational: 'moderate' as const
        },
        recommendations: [],
        supportingData: data.securityPosture,
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        actionable: true,
        tags: ['security', 'improvement', 'posture']
      }
    ];
  };

  const generateRecommendations = (data: any) => {
    return [
      {
        id: 'rec-1',
        title: 'Enhance Threat Detection Capabilities',
        description: 'Implement advanced AI-powered threat detection to reduce false positives and improve response times.',
        priority: 'high' as const,
        estimatedEffort: 'moderate' as const,
        timeframe: 'short-term' as const,
        expectedOutcome: 'Reduce false positives by 40% and improve detection accuracy by 25%',
        resourcesRequired: ['Security team', 'AI platform', 'Integration services'],
        riskReduction: 35,
        costBenefit: {
          cost: 150000,
          benefit: 600000,
          roi: 300
        }
      }
    ];
  };

  const generateAppendices = (data: any) => {
    return [
      {
        id: 'appendix-data',
        title: 'Detailed Security Metrics',
        type: 'data-tables' as const,
        content: data,
        order: 1
      },
      {
        id: 'appendix-methodology',
        title: 'Analysis Methodology',
        type: 'methodology' as const,
        content: 'Security metrics calculated using industry-standard frameworks and AI-powered analysis.',
        order: 2
      }
    ];
  };

  // Content generation helpers
  const generateOverviewContent = (data: any): string => {
    return `This executive security report provides a comprehensive analysis of our organization's security posture, threat landscape, and compliance status. The analysis covers ${data.threatLandscape.totalThreats} detected threats, ${data.incidents.total} security incidents, and compliance across multiple regulatory frameworks.`;
  };

  const generateSecurityPostureContent = (data: any): string => {
    return `Our security posture score of ${data.securityPosture.score}% represents a ${data.securityPosture.change}% improvement, indicating strengthened security controls and effective risk management practices.`;
  };

  const generateThreatContent = (data: any): string => {
    return `Threat analysis reveals ${data.threatLandscape.totalThreats} total threats detected, with ${data.threatLandscape.criticalThreats} classified as critical. Our threat resolution rate of ${Math.round((data.threatLandscape.resolvedThreats / data.threatLandscape.totalThreats) * 100)}% demonstrates effective threat management capabilities.`;
  };

  const generateComplianceContent = (data: any): string => {
    return `Compliance assessment shows ${data.compliance.overallScore}% overall compliance across all frameworks, with strong performance in GDPR (${data.compliance.frameworks.GDPR}%) and PCI-DSS (${data.compliance.frameworks['PCI-DSS']}%).`;
  };

  const generateInvestmentContent = (data: any): string => {
    return `Security investments totaling $${(data.investments.totalSpent / 1000000).toFixed(1)}M have generated a ${data.investments.roi}% return, with cost savings of $${(data.investments.costSavings / 1000000).toFixed(1)}M through improved efficiency and incident prevention.`;
  };

  // Visualization generation (simplified)
  const generateOverviewVisualizations = async (data: any): Promise<ReportVisualization[]> => {
    return [
      {
        id: 'overview-dashboard',
        type: 'gauge',
        title: 'Security Health Dashboard',
        data: { score: data.securityPosture.score },
        config: { min: 0, max: 100, target: 90 },
        executiveFriendly: true,
        interactionEnabled: false
      }
    ];
  };

  const generateSecurityVisualizations = async (data: any): Promise<ReportVisualization[]> => {
    return [
      {
        id: 'security-trend',
        type: 'trend',
        title: 'Security Posture Trend',
        data: { trend: data.securityPosture.trend },
        config: { timeframe: 'monthly' },
        executiveFriendly: true,
        interactionEnabled: false
      }
    ];
  };

  const generateThreatVisualizations = async (data: any): Promise<ReportVisualization[]> => {
    return [
      {
        id: 'threat-summary',
        type: 'chart',
        title: 'Threat Detection Summary',
        data: data.threatLandscape,
        config: { chartType: 'donut' },
        executiveFriendly: true,
        interactionEnabled: false
      }
    ];
  };

  const generateComplianceVisualizations = async (data: any): Promise<ReportVisualization[]> => {
    return [
      {
        id: 'compliance-scores',
        type: 'heatmap',
        title: 'Compliance Framework Scores',
        data: data.compliance.frameworks,
        config: { colorScale: 'compliance' },
        executiveFriendly: true,
        interactionEnabled: false
      }
    ];
  };

  const generateInvestmentVisualizations = async (data: any): Promise<ReportVisualization[]> => {
    return [
      {
        id: 'roi-analysis',
        type: 'comparison',
        title: 'Security Investment ROI',
        data: data.investments,
        config: { showBenchmark: true },
        executiveFriendly: true,
        interactionEnabled: false
      }
    ];
  };

  const getExecutiveStyling = () => {
    return {
      theme: 'executive' as const,
      colors: {
        primary: '#1976d2',
        secondary: '#dc004e',
        accent: '#00acc1',
        warning: '#f57c00',
        error: '#d32f2f',
        success: '#388e3c'
      },
      fonts: {
        heading: 'Roboto, Arial, sans-serif',
        body: 'Roboto, Arial, sans-serif',
        monospace: 'Roboto Mono, monospace'
      },
      layout: {
        pageSize: 'A4' as const,
        orientation: 'portrait' as const,
        margins: { top: 20, right: 20, bottom: 20, left: 20 }
      },
      branding: {
        logo: '/logo.png',
        companyName: 'iSECTECH',
        brandColors: ['#1976d2', '#dc004e']
      }
    };
  };

  return (
    <Box sx={{ display: 'none' }}>
      {/* Hidden component - processing happens in background */}
      {isGenerating && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <CircularProgress size={16} />
          <Typography variant="caption">
            Generating executive report...
          </Typography>
        </Box>
      )}
      {error && (
        <Alert severity="error" sx={{ mt: 1 }}>
          {error}
        </Alert>
      )}
    </Box>
  );
};