/**
 * Executive Compliance Hook
 * Custom hook for managing compliance data and operations for executive dashboard
 */

import { useState, useEffect, useCallback } from 'react';
import { ComplianceFramework, ComplianceStatus, ViolationType } from '../../types/compliance';

interface ComplianceViolation {
  id: string;
  framework: ComplianceFramework;
  violationType: ViolationType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  detectedAt: string;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  affectedSystems: string[];
  dataExposureRisk: string;
  businessImpact?: string;
  remediationSteps: string[];
  assignedTo?: string;
  dueDate?: string;
}

interface ComplianceAssessment {
  id: string;
  framework: ComplianceFramework;
  timestamp: string;
  score: number;
  status: 'passed' | 'failed' | 'partial';
  assessorId: string;
  controlsAssessed: number;
  compliantControls: number;
  findings: Array<{
    severity: 'high' | 'medium' | 'low';
    description: string;
    recommendation: string;
  }>;
  nextAssessmentDue?: string;
}

interface AuditTrailEntry {
  id: string;
  timestamp: string;
  userId: string;
  action: string;
  resource: string;
  outcome: 'success' | 'failure' | 'partial';
  riskLevel?: 'Low' | 'Medium' | 'High' | 'Critical';
  sensitiveDataAccessed: boolean;
  dataClassification?: string;
  ipAddress?: string;
  userAgent?: string;
}

interface ComplianceReport {
  id: string;
  type: 'executive' | 'detailed' | 'audit';
  framework?: ComplianceFramework;
  generatedAt: string;
  periodStart: string;
  periodEnd: string;
  overallScore: number;
  summary: {
    totalViolations: number;
    resolvedViolations: number;
    criticalIssues: number;
    compliancePercentage: number;
  };
  downloadUrl: string;
}

interface FrameworkComplianceStatus {
  compliancePercentage: number;
  totalControls: number;
  compliantControls: number;
  lastAssessment?: string;
  nextAssessmentDue?: string;
  criticalViolations: number;
  highViolations: number;
  trend: 'improving' | 'stable' | 'declining';
}

interface UseExecutiveComplianceReturn {
  complianceStatus: Record<ComplianceFramework, FrameworkComplianceStatus> | null;
  violations: ComplianceViolation[] | null;
  auditTrail: AuditTrailEntry[] | null;
  assessments: ComplianceAssessment[] | null;
  reports: ComplianceReport[] | null;
  loading: boolean;
  error: string | null;
  refreshCompliance: () => Promise<void>;
  generateComplianceReport: (type: 'executive' | 'detailed' | 'audit', framework?: ComplianceFramework) => Promise<ComplianceReport>;
  resolveViolation: (violationId: string) => Promise<void>;
  scheduleAssessment: (framework: ComplianceFramework, date: string) => Promise<void>;
  exportAuditTrail: (startDate: string, endDate: string) => Promise<string>;
}

export const useExecutiveCompliance = (): UseExecutiveComplianceReturn => {
  const [complianceStatus, setComplianceStatus] = useState<Record<ComplianceFramework, FrameworkComplianceStatus> | null>(null);
  const [violations, setViolations] = useState<ComplianceViolation[] | null>(null);
  const [auditTrail, setAuditTrail] = useState<AuditTrailEntry[] | null>(null);
  const [assessments, setAssessments] = useState<ComplianceAssessment[] | null>(null);
  const [reports, setReports] = useState<ComplianceReport[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchComplianceData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch compliance status for all frameworks
      const statusResponse = await fetch('/api/compliance/status', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!statusResponse.ok) {
        throw new Error('Failed to fetch compliance status');
      }

      const statusData = await statusResponse.json();
      setComplianceStatus(statusData.frameworkStatus);

      // Fetch violations
      const violationsResponse = await fetch('/api/compliance/violations', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!violationsResponse.ok) {
        throw new Error('Failed to fetch violations');
      }

      const violationsData = await violationsResponse.json();
      setViolations(violationsData.violations);

      // Fetch recent audit trail
      const auditResponse = await fetch('/api/compliance/audit-trail?limit=50', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!auditResponse.ok) {
        throw new Error('Failed to fetch audit trail');
      }

      const auditData = await auditResponse.json();
      setAuditTrail(auditData.entries);

      // Fetch recent assessments
      const assessmentsResponse = await fetch('/api/compliance/assessments?limit=10', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!assessmentsResponse.ok) {
        throw new Error('Failed to fetch assessments');
      }

      const assessmentsData = await assessmentsResponse.json();
      setAssessments(assessmentsData.assessments);

      // Fetch available reports
      const reportsResponse = await fetch('/api/compliance/reports', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!reportsResponse.ok) {
        throw new Error('Failed to fetch reports');
      }

      const reportsData = await reportsResponse.json();
      setReports(reportsData.reports);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshCompliance = useCallback(async () => {
    await fetchComplianceData();
  }, [fetchComplianceData]);

  const generateComplianceReport = useCallback(async (
    type: 'executive' | 'detailed' | 'audit',
    framework?: ComplianceFramework
  ): Promise<ComplianceReport> => {
    try {
      const response = await fetch('/api/compliance/generate-report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type,
          framework,
          periodStart: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // Last 30 days
          periodEnd: new Date().toISOString(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to generate compliance report');
      }

      const reportData = await response.json();
      
      // Update reports list
      if (reports) {
        setReports([reportData.report, ...reports]);
      }

      return reportData.report;
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : 'Failed to generate report');
    }
  }, [reports]);

  const resolveViolation = useCallback(async (violationId: string): Promise<void> => {
    try {
      const response = await fetch(`/api/compliance/violations/${violationId}/resolve`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status: 'resolved',
          resolvedAt: new Date().toISOString(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to resolve violation');
      }

      // Update local state
      if (violations) {
        setViolations(violations.map(v => 
          v.id === violationId 
            ? { ...v, status: 'resolved' as const }
            : v
        ));
      }
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : 'Failed to resolve violation');
    }
  }, [violations]);

  const scheduleAssessment = useCallback(async (
    framework: ComplianceFramework,
    date: string
  ): Promise<void> => {
    try {
      const response = await fetch('/api/compliance/assessments/schedule', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          framework,
          scheduledDate: date,
          type: 'comprehensive',
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to schedule assessment');
      }

      // Refresh data to show the scheduled assessment
      await fetchComplianceData();
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : 'Failed to schedule assessment');
    }
  }, [fetchComplianceData]);

  const exportAuditTrail = useCallback(async (
    startDate: string,
    endDate: string
  ): Promise<string> => {
    try {
      const response = await fetch('/api/compliance/audit-trail/export', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          startDate,
          endDate,
          format: 'csv',
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to export audit trail');
      }

      const data = await response.json();
      return data.downloadUrl;
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : 'Failed to export audit trail');
    }
  }, []);

  // Initial data load
  useEffect(() => {
    fetchComplianceData();
  }, [fetchComplianceData]);

  // Auto-refresh every 5 minutes
  useEffect(() => {
    const interval = setInterval(() => {
      if (!loading) {
        fetchComplianceData();
      }
    }, 5 * 60 * 1000); // 5 minutes

    return () => clearInterval(interval);
  }, [loading, fetchComplianceData]);

  return {
    complianceStatus,
    violations,
    auditTrail,
    assessments,
    reports,
    loading,
    error,
    refreshCompliance,
    generateComplianceReport,
    resolveViolation,
    scheduleAssessment,
    exportAuditTrail,
  };
};