import { useState, useEffect, useCallback, useRef } from 'react';
import { useWebSocket } from './use-websocket';

// Types for executive reporting
interface ExecutiveMetrics {
  securityScore: number;
  riskExposure: number;
  complianceScore: number;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  incidentCount: number;
  mttr: number; // minutes
  mttd: number; // minutes
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

interface ExportOptions {
  includeTrends: boolean;
  includeCompliance: boolean;
  includeAlerts: boolean;
  timeRange: string;
  userRole: string;
}

interface UseExecutiveReportingOptions {
  userId: string;
  tenantId: string;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  timeRange: '24h' | '7d' | '30d' | '90d' | '1y';
  realTimeUpdates: boolean;
  includeCompliance: boolean;
  includeAlerts: boolean;
  refreshInterval?: number;
}

interface UseExecutiveReportingReturn {
  executiveMetrics: ExecutiveMetrics | null;
  riskTrends: RiskTrend[] | null;
  complianceFrameworks: ComplianceFramework[] | null;
  securityAlerts: SecurityAlert[] | null;
  isLoading: boolean;
  error: Error | null;
  refreshData: () => Promise<void>;
  exportReport: (format: 'pdf' | 'excel' | 'csv', options: ExportOptions) => Promise<void>;
  scheduleReport: (frequency: 'daily' | 'weekly' | 'monthly', recipients: string[]) => Promise<void>;
  getMetricDetails: (metric: string) => any;
  lastUpdated: Date | null;
}

export const useExecutiveReporting = (options: UseExecutiveReportingOptions): UseExecutiveReportingReturn => {
  const {
    userId,
    tenantId,
    userRole,
    timeRange,
    realTimeUpdates,
    includeCompliance,
    includeAlerts,
    refreshInterval = 30000
  } = options;

  // State management
  const [executiveMetrics, setExecutiveMetrics] = useState<ExecutiveMetrics | null>(null);
  const [riskTrends, setRiskTrends] = useState<RiskTrend[] | null>(null);
  const [complianceFrameworks, setComplianceFrameworks] = useState<ComplianceFramework[] | null>(null);
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refreshTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // WebSocket for real-time updates
  const { isConnected, sendMessage, lastMessage } = useWebSocket({
    url: `/api/websocket/executive-reporting?tenant=${tenantId}&role=${userRole}`,
    enabled: realTimeUpdates,
    reconnectAttempts: 5,
    reconnectInterval: 3000
  });

  // Generate mock executive data for demonstration
  const generateMockExecutiveData = useCallback((): {
    metrics: ExecutiveMetrics;
    trends: RiskTrend[];
    compliance: ComplianceFramework[];
    alerts: SecurityAlert[];
  } => {
    const now = new Date();

    // Generate realistic executive metrics
    const baseSecurityScore = 78 + Math.random() * 15;
    const baseRiskExposure = 25 + Math.random() * 30;
    
    const metrics: ExecutiveMetrics = {
      securityScore: baseSecurityScore,
      riskExposure: baseRiskExposure,
      complianceScore: 85 + Math.random() * 12,
      threatLevel: baseRiskExposure > 50 ? 'high' : baseRiskExposure > 35 ? 'medium' : 'low',
      incidentCount: Math.floor(Math.random() * 8),
      mttr: 120 + Math.random() * 180, // 2-5 hours
      mttd: 45 + Math.random() * 75,   // 45-120 minutes
      securityROI: 150 + Math.random() * 100,
      budgetUtilization: 65 + Math.random() * 25,
      teamEfficiency: 80 + Math.random() * 15,
      timestamp: now,
      confidence: 0.85 + Math.random() * 0.1
    };

    // Generate historical trends based on time range
    const timeRanges = {
      '24h': { count: 24, interval: 1, unit: 'hours' },
      '7d': { count: 168, interval: 1, unit: 'hours' },
      '30d': { count: 30, interval: 24, unit: 'hours' },
      '90d': { count: 90, interval: 24, unit: 'hours' },
      '1y': { count: 12, interval: 24 * 30, unit: 'hours' }
    };

    const { count, interval } = timeRanges[timeRange];
    const trends: RiskTrend[] = [];

    for (let i = count; i >= 0; i--) {
      const timestamp = new Date(now.getTime() - i * interval * 60 * 60 * 1000);
      const variation = Math.sin((i / count) * Math.PI * 2) * 8 + (Math.random() - 0.5) * 5;
      const incidentSpike = Math.random() < 0.1 ? Math.floor(Math.random() * 3) : 0;
      
      trends.push({
        timestamp,
        securityScore: Math.max(60, Math.min(95, baseSecurityScore + variation)),
        riskExposure: Math.max(10, Math.min(80, baseRiskExposure + variation * -1)),
        incidentCount: Math.floor(Math.random() * 5) + incidentSpike,
        threatLevel: Math.max(1, Math.min(4, Math.floor(baseRiskExposure / 25) + Math.floor(Math.random() * 2))),
        complianceScore: Math.max(75, Math.min(100, metrics.complianceScore + variation * 0.5))
      });
    }

    // Generate compliance frameworks
    const complianceFrameworkNames = ['SOC 2 Type II', 'ISO 27001', 'GDPR', 'HIPAA', 'PCI DSS', 'NIST CSF'];
    const compliance: ComplianceFramework[] = complianceFrameworkNames.map(name => {
      const score = 75 + Math.random() * 20;
      return {
        name,
        score,
        status: score >= 90 ? 'compliant' : score >= 75 ? 'partial' : 'non_compliant',
        lastAudit: new Date(now.getTime() - Math.random() * 90 * 24 * 60 * 60 * 1000),
        nextAudit: new Date(now.getTime() + Math.random() * 180 * 24 * 60 * 60 * 1000),
        criticalFindings: score < 75 ? Math.floor(Math.random() * 5) + 1 : 0
      };
    });

    // Generate security alerts
    const alertTemplates = [
      {
        severity: 'critical' as const,
        title: 'Potential Data Breach Detected',
        description: 'Unusual data access patterns detected in customer database',
        category: 'data_protection',
        status: 'open' as const
      },
      {
        severity: 'high' as const,
        title: 'Multiple Failed Login Attempts',
        description: 'Brute force attack detected on admin accounts',
        category: 'authentication',
        status: 'investigating' as const
      },
      {
        severity: 'high' as const,
        title: 'Suspicious Network Activity',
        description: 'Potential lateral movement detected in network',
        category: 'network_security',
        status: 'open' as const
      },
      {
        severity: 'medium' as const,
        title: 'Outdated Security Patches',
        description: 'Critical security patches pending on 15 systems',
        category: 'vulnerability_management',
        status: 'open' as const
      },
      {
        severity: 'medium' as const,
        title: 'Compliance Policy Violation',
        description: 'Data retention policy violated in archive system',
        category: 'compliance',
        status: 'investigating' as const
      },
      {
        severity: 'low' as const,
        title: 'Certificate Expiration Warning',
        description: 'SSL certificates expiring within 30 days',
        category: 'certificates',
        status: 'resolved' as const
      }
    ];

    const alerts: SecurityAlert[] = alertTemplates
      .filter(() => Math.random() > 0.3) // Randomly include alerts
      .map((template, index) => ({
        ...template,
        id: `alert-${Date.now()}-${index}`,
        timestamp: new Date(now.getTime() - Math.random() * 7 * 24 * 60 * 60 * 1000),
        assignee: ['John Doe', 'Jane Smith', 'Security Team'][Math.floor(Math.random() * 3)]
      }));

    return { metrics, trends, compliance, alerts };
  }, [timeRange, userRole]);

  // Fetch executive reporting data
  const fetchExecutiveData = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);

      // In a real implementation, these would be actual API calls
      // For now, we'll generate mock data
      const { metrics, trends, compliance, alerts } = generateMockExecutiveData();

      setExecutiveMetrics(metrics);
      setRiskTrends(trends);
      
      if (includeCompliance) {
        setComplianceFrameworks(compliance);
      }

      if (includeAlerts) {
        setSecurityAlerts(alerts);
      }

      setLastUpdated(new Date());
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [generateMockExecutiveData, includeCompliance, includeAlerts]);

  // Handle real-time updates
  useEffect(() => {
    if (realTimeUpdates && lastMessage) {
      try {
        const data = JSON.parse(lastMessage.data);
        
        if (data.type === 'executive-metrics-update') {
          setExecutiveMetrics(prev => ({
            ...prev,
            ...data.payload,
            timestamp: new Date(data.payload.timestamp)
          }));
          setLastUpdated(new Date());
        } else if (data.type === 'security-alert') {
          setSecurityAlerts(prev => [
            { ...data.payload, timestamp: new Date(data.payload.timestamp) },
            ...(prev || []).slice(0, 49) // Keep latest 50 alerts
          ]);
        }
      } catch (err) {
        console.error('Error processing WebSocket message:', err);
      }
    }
  }, [lastMessage, realTimeUpdates]);

  // Auto-refresh data
  useEffect(() => {
    if (realTimeUpdates && refreshInterval > 0) {
      refreshTimeoutRef.current = setTimeout(() => {
        fetchExecutiveData();
      }, refreshInterval);

      return () => {
        if (refreshTimeoutRef.current) {
          clearTimeout(refreshTimeoutRef.current);
        }
      };
    }
  }, [fetchExecutiveData, realTimeUpdates, refreshInterval]);

  // Initial data fetch
  useEffect(() => {
    fetchExecutiveData();
  }, [fetchExecutiveData]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
    };
  }, []);

  // Export report function
  const exportReport = useCallback(async (format: 'pdf' | 'excel' | 'csv', options: ExportOptions) => {
    try {
      const reportData = {
        executiveMetrics,
        riskTrends: options.includeTrends ? riskTrends : null,
        complianceFrameworks: options.includeCompliance ? complianceFrameworks : null,
        securityAlerts: options.includeAlerts ? securityAlerts : null,
        generatedAt: new Date(),
        timeRange: options.timeRange,
        userRole: options.userRole
      };

      // In a real implementation, this would call an API endpoint
      console.log(`Exporting ${format} report with data:`, reportData);
      
      // Simulate export delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Create and download file (mock implementation)
      const dataStr = JSON.stringify(reportData, null, 2);
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
      
      const exportFileDefaultName = `executive-security-report-${new Date().toISOString().split('T')[0]}.${format === 'excel' ? 'xlsx' : format}`;
      
      const linkElement = document.createElement('a');
      linkElement.setAttribute('href', dataUri);
      linkElement.setAttribute('download', exportFileDefaultName);
      linkElement.click();
      
    } catch (err) {
      throw new Error(`Failed to export report: ${err}`);
    }
  }, [executiveMetrics, riskTrends, complianceFrameworks, securityAlerts]);

  // Schedule report function
  const scheduleReport = useCallback(async (
    frequency: 'daily' | 'weekly' | 'monthly', 
    recipients: string[]
  ) => {
    try {
      // In a real implementation, this would call an API endpoint
      console.log(`Scheduling ${frequency} report for recipients:`, recipients);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
      
    } catch (err) {
      throw new Error(`Failed to schedule report: ${err}`);
    }
  }, []);

  // Get metric details function
  const getMetricDetails = useCallback((metric: string) => {
    if (!executiveMetrics || !riskTrends) return null;

    switch (metric) {
      case 'security':
        return {
          current: executiveMetrics.securityScore,
          historical: riskTrends.map(t => ({ timestamp: t.timestamp, value: t.securityScore })),
          target: 85,
          description: 'Overall security posture health score'
        };
      case 'risk':
        return {
          current: executiveMetrics.riskExposure,
          historical: riskTrends.map(t => ({ timestamp: t.timestamp, value: t.riskExposure })),
          target: 25,
          description: 'Current organizational risk exposure level'
        };
      case 'compliance':
        return {
          current: executiveMetrics.complianceScore,
          historical: riskTrends.map(t => ({ timestamp: t.timestamp, value: t.complianceScore })),
          target: 95,
          description: 'Regulatory compliance adherence score'
        };
      case 'incidents':
        return {
          current: executiveMetrics.incidentCount,
          historical: riskTrends.map(t => ({ timestamp: t.timestamp, value: t.incidentCount })),
          description: 'Number of active security incidents'
        };
      case 'mttd':
        return {
          current: executiveMetrics.mttd,
          target: 120,
          description: 'Mean time to detect security incidents (minutes)'
        };
      case 'mttr':
        return {
          current: executiveMetrics.mttr,
          target: 240,
          description: 'Mean time to respond to security incidents (minutes)'
        };
      case 'roi':
        return {
          current: executiveMetrics.securityROI,
          target: 150,
          description: 'Return on security investment percentage'
        };
      case 'budget':
        return {
          current: executiveMetrics.budgetUtilization,
          target: 85,
          description: 'Security budget utilization percentage'
        };
      default:
        return null;
    }
  }, [executiveMetrics, riskTrends]);

  const refreshData = useCallback(async () => {
    await fetchExecutiveData();
  }, [fetchExecutiveData]);

  return {
    executiveMetrics,
    riskTrends,
    complianceFrameworks,
    securityAlerts,
    isLoading,
    error,
    refreshData,
    exportReport,
    scheduleReport,
    getMetricDetails,
    lastUpdated
  };
};