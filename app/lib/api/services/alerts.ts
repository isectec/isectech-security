/**
 * Alert Management API Services for iSECTECH Protect
 * AI-powered alert correlation, priority scoring, and investigation
 */

import type {
  Alert,
  AlertPriority,
  AlertStatus,
  PaginatedData,
  SearchParams,
  ThreatCategory,
  ThreatSeverity,
} from '@/types';
import { apiClient } from '../client';

// Alert-specific interfaces
export interface AlertFilters {
  status?: AlertStatus[];
  priority?: AlertPriority[];
  severity?: ThreatSeverity[];
  category?: ThreatCategory[];
  assignedTo?: string[];
  tags?: string[];
  dateRange?: {
    start: Date;
    end: Date;
  };
  riskScoreRange?: {
    min: number;
    max: number;
  };
  confidenceScoreRange?: {
    min: number;
    max: number;
  };
  hasInvestigationNotes?: boolean;
  slaBreached?: boolean;
}

export interface AlertCorrelation {
  id: string;
  type: 'DUPLICATE' | 'RELATED' | 'CHAIN' | 'CAMPAIGN';
  confidence: number;
  reason: string;
  relatedAlerts: Alert[];
  suggestedAction: 'MERGE' | 'LINK' | 'ESCALATE' | 'SUPPRESS';
  aiInsights: string[];
}

export interface AlertEnrichment {
  businessImpact: {
    score: number; // 0-100
    factors: string[];
    affectedSystems: string[];
    potentialLoss: number;
  };
  contextualData: {
    userBehavior: {
      isAnomalous: boolean;
      baselineDeviation: number;
      riskFactors: string[];
    };
    assetCriticality: {
      level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      businessFunction: string;
      dataClassification: string;
    };
    threatLandscape: {
      similarIncidents: number;
      trendingTTPs: string[];
      industryContext: string[];
    };
    networkContext: {
      communicationPatterns: string[];
      accessPatterns: string[];
      geographicIndicators: string[];
    };
  };
  recommendations: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
    preventive: string[];
  };
}

export interface AlertInvestigation {
  id: string;
  alertId: string;
  investigator: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'BLOCKED' | 'COMPLETED';
  timeline: Array<{
    timestamp: Date;
    action: string;
    description: string;
    evidence?: string[];
    findings?: string;
  }>;
  evidenceCollected: string[];
  conclusionsReached: string[];
  nextSteps: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface AlertTriage {
  id: string;
  alertId: string;
  triageScore: number; // AI-calculated priority score
  triageReasons: string[];
  suggestedPriority: AlertPriority;
  suggestedAssignee: string;
  estimatedResolutionTime: number; // hours
  requiredSkills: string[];
  escalationThreshold: number; // hours
  automatedActions: Array<{
    action: string;
    trigger: string;
    executed: boolean;
    result?: string;
  }>;
}

export interface AlertMetrics {
  totalAlerts: number;
  alertsByStatus: Record<AlertStatus, number>;
  alertsByPriority: Record<AlertPriority, number>;
  alertsBySeverity: Record<ThreatSeverity, number>;
  meanTimeToDetection: number; // minutes
  meanTimeToResponse: number; // minutes
  meanTimeToResolution: number; // hours
  falsePositiveRate: number; // percentage
  alertFatigueScore: number; // 0-100
  topCategories: Array<{ category: ThreatCategory; count: number }>;
  correlationStats: {
    duplicatesReduced: number;
    correlatedCampaigns: number;
    noiseReduction: number; // percentage
  };
}

export interface AlertWorkflow {
  id: string;
  name: string;
  description: string;
  trigger: {
    conditions: Array<{
      field: string;
      operator: string;
      value: unknown;
    }>;
    schedule?: string; // cron expression
  };
  actions: Array<{
    type: 'ASSIGN' | 'ESCALATE' | 'SUPPRESS' | 'ENRICH' | 'NOTIFY' | 'INVESTIGATE';
    parameters: Record<string, unknown>;
    conditions?: Array<{
      field: string;
      operator: string;
      value: unknown;
    }>;
  }>;
  enabled: boolean;
  executionCount: number;
  lastExecuted?: Date;
}

export class AlertService {
  // Alert CRUD operations
  async getAlerts(params?: {
    filters?: AlertFilters;
    search?: SearchParams;
    includeCorrelations?: boolean;
    includeEnrichment?: boolean;
  }): Promise<PaginatedData<Alert & { correlations?: AlertCorrelation[]; enrichment?: AlertEnrichment }>> {
    const response = await apiClient.get<
      PaginatedData<Alert & { correlations?: AlertCorrelation[]; enrichment?: AlertEnrichment }>
    >('/alerts', { params });
    return response.data!;
  }

  async getAlert(
    id: string,
    options?: {
      includeCorrelations?: boolean;
      includeEnrichment?: boolean;
      includeInvestigation?: boolean;
    }
  ): Promise<
    Alert & {
      correlations?: AlertCorrelation[];
      enrichment?: AlertEnrichment;
      investigation?: AlertInvestigation;
    }
  > {
    const response = await apiClient.get<
      Alert & {
        correlations?: AlertCorrelation[];
        enrichment?: AlertEnrichment;
        investigation?: AlertInvestigation;
      }
    >(`/alerts/${id}`, { params: options });
    return response.data!;
  }

  async createAlert(alert: Omit<Alert, 'id' | 'createdAt' | 'updatedAt'>): Promise<Alert> {
    const response = await apiClient.post<Alert>('/alerts', alert);
    return response.data!;
  }

  async updateAlert(id: string, updates: Partial<Alert>): Promise<Alert> {
    const response = await apiClient.patch<Alert>(`/alerts/${id}`, updates);
    return response.data!;
  }

  async deleteAlert(id: string): Promise<void> {
    await apiClient.delete(`/alerts/${id}`);
  }

  // Alert status management
  async updateAlertStatus(id: string, status: AlertStatus, comment?: string): Promise<Alert> {
    const response = await apiClient.patch<Alert>(`/alerts/${id}/status`, { status, comment });
    return response.data!;
  }

  async assignAlert(id: string, assigneeId: string, comment?: string): Promise<Alert> {
    const response = await apiClient.patch<Alert>(`/alerts/${id}/assign`, { assigneeId, comment });
    return response.data!;
  }

  async escalateAlert(id: string, escalationLevel: number, reason: string): Promise<Alert> {
    const response = await apiClient.post<Alert>(`/alerts/${id}/escalate`, { escalationLevel, reason });
    return response.data!;
  }

  // AI-powered correlation and analysis
  async correlateAlerts(alertIds: string[]): Promise<AlertCorrelation[]> {
    const response = await apiClient.post<AlertCorrelation[]>('/alerts/correlate', { alertIds });
    return response.data!;
  }

  async enrichAlert(id: string, forceRefresh = false): Promise<AlertEnrichment> {
    const response = await apiClient.post<AlertEnrichment>(`/alerts/${id}/enrich`, { forceRefresh });
    return response.data!;
  }

  async triageAlert(id: string): Promise<AlertTriage> {
    const response = await apiClient.post<AlertTriage>(`/alerts/${id}/triage`);
    return response.data!;
  }

  async getAlertSimilarity(
    id: string,
    limit = 10
  ): Promise<Array<{ alert: Alert; similarity: number; reasons: string[] }>> {
    const response = await apiClient.get<Array<{ alert: Alert; similarity: number; reasons: string[] }>>(
      `/alerts/${id}/similar`,
      { params: { limit } }
    );
    return response.data!;
  }

  // Investigation management
  async startInvestigation(alertId: string, initialNotes?: string): Promise<AlertInvestigation> {
    const response = await apiClient.post<AlertInvestigation>(`/alerts/${alertId}/investigate`, { initialNotes });
    return response.data!;
  }

  async updateInvestigation(
    investigationId: string,
    updates: Partial<AlertInvestigation>
  ): Promise<AlertInvestigation> {
    const response = await apiClient.patch<AlertInvestigation>(`/investigations/${investigationId}`, updates);
    return response.data!;
  }

  async addInvestigationNote(
    investigationId: string,
    note: {
      action: string;
      description: string;
      evidence?: string[];
      findings?: string;
    }
  ): Promise<AlertInvestigation> {
    const response = await apiClient.post<AlertInvestigation>(`/investigations/${investigationId}/notes`, note);
    return response.data!;
  }

  // Bulk operations
  async bulkUpdateAlerts(alertIds: string[], updates: Partial<Alert>): Promise<{ updated: number; failed: string[] }> {
    const response = await apiClient.patch<{ updated: number; failed: string[] }>('/alerts/bulk', {
      alertIds,
      updates,
    });
    return response.data!;
  }

  async mergeAlerts(primaryAlertId: string, duplicateAlertIds: string[], reason: string): Promise<Alert> {
    const response = await apiClient.post<Alert>(`/alerts/${primaryAlertId}/merge`, { duplicateAlertIds, reason });
    return response.data!;
  }

  async suppressAlerts(alertIds: string[], duration: number, reason: string): Promise<{ suppressed: number }> {
    const response = await apiClient.post<{ suppressed: number }>('/alerts/suppress', { alertIds, duration, reason });
    return response.data!;
  }

  // Analytics and metrics
  async getAlertMetrics(params?: {
    dateRange?: { start: Date; end: Date };
    groupBy?: 'hour' | 'day' | 'week' | 'month';
    filters?: AlertFilters;
  }): Promise<AlertMetrics> {
    const response = await apiClient.get<AlertMetrics>('/alerts/metrics', { params });
    return response.data!;
  }

  async getAlertTrends(params?: {
    dateRange?: { start: Date; end: Date };
    metric: 'volume' | 'severity' | 'category' | 'response_time';
    granularity: 'hour' | 'day' | 'week';
  }): Promise<Array<{ timestamp: Date; value: number; metadata?: Record<string, unknown> }>> {
    const response = await apiClient.get<Array<{ timestamp: Date; value: number; metadata?: Record<string, unknown> }>>(
      '/alerts/trends',
      { params }
    );
    return response.data!;
  }

  async getFatigueAnalysis(): Promise<{
    fatigueScore: number;
    noisyRules: Array<{ rule: string; volume: number; falsePositiveRate: number }>;
    recommendedActions: string[];
    suppressionOpportunities: Array<{ pattern: string; impact: number }>;
  }> {
    const response = await apiClient.get<{
      fatigueScore: number;
      noisyRules: Array<{ rule: string; volume: number; falsePositiveRate: number }>;
      recommendedActions: string[];
      suppressionOpportunities: Array<{ pattern: string; impact: number }>;
    }>('/alerts/fatigue-analysis');
    return response.data!;
  }

  // Workflow automation
  async getWorkflows(): Promise<AlertWorkflow[]> {
    const response = await apiClient.get<AlertWorkflow[]>('/alerts/workflows');
    return response.data!;
  }

  async createWorkflow(
    workflow: Omit<AlertWorkflow, 'id' | 'executionCount' | 'lastExecuted'>
  ): Promise<AlertWorkflow> {
    const response = await apiClient.post<AlertWorkflow>('/alerts/workflows', workflow);
    return response.data!;
  }

  async updateWorkflow(id: string, updates: Partial<AlertWorkflow>): Promise<AlertWorkflow> {
    const response = await apiClient.patch<AlertWorkflow>(`/alerts/workflows/${id}`, updates);
    return response.data!;
  }

  async executeWorkflow(
    id: string,
    alertIds?: string[]
  ): Promise<{ executed: number; results: Array<{ alertId: string; success: boolean; message?: string }> }> {
    const response = await apiClient.post<{
      executed: number;
      results: Array<{ alertId: string; success: boolean; message?: string }>;
    }>(`/alerts/workflows/${id}/execute`, { alertIds });
    return response.data!;
  }

  // Real-time subscriptions
  async subscribeToAlerts(filters?: AlertFilters, callback?: (alert: Alert) => void): Promise<() => void> {
    // WebSocket subscription implementation would go here
    // For now, return a mock unsubscribe function
    return () => {};
  }

  // Export and reporting
  async exportAlerts(params: {
    filters?: AlertFilters;
    format: 'csv' | 'excel' | 'pdf' | 'json';
    includeDetails?: boolean;
  }): Promise<{ downloadUrl: string; expiresAt: Date }> {
    const response = await apiClient.post<{ downloadUrl: string; expiresAt: Date }>('/alerts/export', params);
    return response.data!;
  }

  // Health and diagnostics
  async getAlertSystemHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    metrics: {
      processingLatency: number;
      queueDepth: number;
      errorRate: number;
      throughput: number;
    };
    issues: string[];
  }> {
    const response = await apiClient.get<{
      status: 'healthy' | 'degraded' | 'unhealthy';
      metrics: {
        processingLatency: number;
        queueDepth: number;
        errorRate: number;
        throughput: number;
      };
      issues: string[];
    }>('/alerts/health');
    return response.data!;
  }
}

export const alertService = new AlertService();
export default alertService;
