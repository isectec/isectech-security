/**
 * Dashboard Data Hooks for iSECTECH Protect
 * Production-grade React hooks for security dashboard data management
 */

import { useAppStore, useAuthStore } from '@/lib/store';
import type {
  AssetHealthData,
  ComplianceData,
  DashboardConfig,
  DashboardFilter,
  DashboardMetrics,
  RiskScoreData,
  SecurityEvent,
  ThreatActivityData,
  TimeRange,
} from '@/types';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback } from 'react';

// Dashboard API service (would typically be in services directory)
const dashboardService = {
  async getMetrics(timeRange: TimeRange = '24h'): Promise<DashboardMetrics> {
    // Mock implementation - replace with actual API call
    return {
      totalAlerts: 1247,
      criticalAlerts: 23,
      activeIncidents: 7,
      riskScore: 7.2,
      complianceScore: 94.3,
      assetsMonitored: 8954,
      threatsBlocked: 156,
      uptimePercentage: 99.97,
      timeRange,
      updatedAt: new Date(),
    };
  },

  async getThreatActivity(filter: DashboardFilter): Promise<ThreatActivityData> {
    // Mock implementation
    return {
      heatMapData: [
        { region: 'North America', threatLevel: 'high', incidents: 45, coordinates: [39.8283, -98.5795] },
        { region: 'Europe', threatLevel: 'medium', incidents: 23, coordinates: [54.526, 15.2551] },
        { region: 'Asia Pacific', threatLevel: 'low', incidents: 12, coordinates: [34.0479, 100.6197] },
      ],
      timeSeriesData: Array.from({ length: 24 }, (_, i) => ({
        timestamp: new Date(Date.now() - (23 - i) * 60 * 60 * 1000),
        threats: Math.floor(Math.random() * 50) + 10,
        blocked: Math.floor(Math.random() * 30) + 5,
      })),
      topThreatTypes: [
        { type: 'Malware', count: 67, trend: 'up' },
        { type: 'Phishing', count: 34, trend: 'down' },
        { type: 'DDoS', count: 23, trend: 'stable' },
        { type: 'SQL Injection', count: 12, trend: 'up' },
      ],
      filter,
    };
  },

  async getRiskScoreData(timeRange: TimeRange): Promise<RiskScoreData> {
    return {
      currentScore: 7.2,
      trend: 'increasing',
      historicalData: Array.from({ length: 30 }, (_, i) => ({
        date: new Date(Date.now() - (29 - i) * 24 * 60 * 60 * 1000),
        score: 6 + Math.random() * 3,
        factors: [
          { name: 'Network Security', score: 8.1, weight: 0.3 },
          { name: 'Endpoint Security', score: 7.5, weight: 0.25 },
          { name: 'Identity & Access', score: 6.8, weight: 0.2 },
          { name: 'Data Protection', score: 7.9, weight: 0.15 },
          { name: 'Compliance', score: 8.5, weight: 0.1 },
        ],
      })),
      predictiveAnalysis: {
        nextWeekPrediction: 7.8,
        confidence: 0.85,
        factors: ['Increased malware activity', 'Pending security updates'],
      },
      timeRange,
    };
  },

  async getAssetHealth(): Promise<AssetHealthData> {
    return {
      totalAssets: 8954,
      healthyAssets: 8234,
      warningAssets: 567,
      criticalAssets: 153,
      assetsByType: [
        { type: 'Servers', total: 2341, healthy: 2198, warning: 112, critical: 31 },
        { type: 'Workstations', total: 4567, healthy: 4456, warning: 89, critical: 22 },
        { type: 'Network Devices', total: 789, healthy: 723, warning: 56, critical: 10 },
        { type: 'IoT Devices', total: 1257, healthy: 857, warning: 310, critical: 90 },
      ],
      vulnerabilities: {
        critical: 23,
        high: 156,
        medium: 467,
        low: 1234,
      },
      patchStatus: {
        upToDate: 7123,
        pending: 1567,
        overdue: 264,
      },
    };
  },

  async getComplianceData(): Promise<ComplianceData> {
    return {
      overallScore: 94.3,
      frameworks: [
        { name: 'SOC 2', score: 96.5, status: 'compliant', lastAudit: new Date('2024-06-15') },
        { name: 'ISO 27001', score: 93.2, status: 'compliant', lastAudit: new Date('2024-05-20') },
        { name: 'GDPR', score: 98.1, status: 'compliant', lastAudit: new Date('2024-07-01') },
        { name: 'HIPAA', score: 91.8, status: 'minor_issues', lastAudit: new Date('2024-06-30') },
        { name: 'PCI DSS', score: 89.4, status: 'minor_issues', lastAudit: new Date('2024-07-10') },
      ],
      recentChanges: [
        { framework: 'GDPR', change: 'New data processing agreement updated', impact: 'positive', date: new Date() },
        { framework: 'SOC 2', change: 'Access control review completed', impact: 'positive', date: new Date() },
      ],
      upcomingAudits: [
        { framework: 'ISO 27001', scheduledDate: new Date('2024-11-15'), type: 'annual' },
        { framework: 'PCI DSS', scheduledDate: new Date('2024-09-30'), type: 'quarterly' },
      ],
    };
  },

  async getSecurityEvents(limit: number = 10): Promise<SecurityEvent[]> {
    return Array.from({ length: limit }, (_, i) => ({
      id: `event-${i + 1}`,
      type: ['alert', 'incident', 'threat', 'compliance'][Math.floor(Math.random() * 4)] as SecurityEvent['type'],
      title: [
        'Malware detected on endpoint',
        'Unusual login activity detected',
        'Failed compliance check',
        'Network intrusion attempt blocked',
        'Phishing email campaign detected',
      ][Math.floor(Math.random() * 5)],
      severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)] as SecurityEvent['severity'],
      timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000),
      source: ['Network Scanner', 'Email Security', 'Endpoint Protection', 'SIEM'][Math.floor(Math.random() * 4)],
      status: ['open', 'investigating', 'resolved'][Math.floor(Math.random() * 3)] as SecurityEvent['status'],
      assignedTo: Math.random() > 0.5 ? 'analyst@isectech.com' : undefined,
    }));
  },

  async updateDashboardConfig(config: DashboardConfig): Promise<DashboardConfig> {
    // Mock implementation - would save to backend
    return config;
  },
};

// Query keys for consistent caching
export const dashboardQueryKeys = {
  all: ['dashboard'] as const,
  metrics: (timeRange: TimeRange) => [...dashboardQueryKeys.all, 'metrics', timeRange] as const,
  threatActivity: (filter: DashboardFilter) => [...dashboardQueryKeys.all, 'threatActivity', filter] as const,
  riskScore: (timeRange: TimeRange) => [...dashboardQueryKeys.all, 'riskScore', timeRange] as const,
  assetHealth: () => [...dashboardQueryKeys.all, 'assetHealth'] as const,
  compliance: () => [...dashboardQueryKeys.all, 'compliance'] as const,
  events: (limit: number) => [...dashboardQueryKeys.all, 'events', limit] as const,
  config: () => [...dashboardQueryKeys.all, 'config'] as const,
};

// Main dashboard metrics hook
export function useDashboardMetrics(timeRange: TimeRange = '24h') {
  const { showError } = useAppStore();
  const { user } = useAuthStore();

  return useQuery({
    queryKey: dashboardQueryKeys.metrics(timeRange),
    queryFn: () => dashboardService.getMetrics(timeRange),
    enabled: !!user,
    staleTime: 5 * 60 * 1000, // 5 minutes
    refetchInterval: 30 * 1000, // 30 seconds for real-time updates
    onError: (error) => {
      console.error('Failed to fetch dashboard metrics:', error);
      showError('Data Loading Error', 'Failed to load dashboard metrics');
    },
  });
}

// Threat activity data hook
export function useThreatActivity(filter: DashboardFilter = {}) {
  const { showError } = useAppStore();
  const { user } = useAuthStore();

  return useQuery({
    queryKey: dashboardQueryKeys.threatActivity(filter),
    queryFn: () => dashboardService.getThreatActivity(filter),
    enabled: !!user,
    staleTime: 2 * 60 * 1000, // 2 minutes
    refetchInterval: 60 * 1000, // 1 minute
    onError: (error) => {
      console.error('Failed to fetch threat activity:', error);
      showError('Data Loading Error', 'Failed to load threat activity data');
    },
  });
}

// Risk score data hook
export function useRiskScoreData(timeRange: TimeRange = '30d') {
  const { showError } = useAppStore();
  const { user } = useAuthStore();

  return useQuery({
    queryKey: dashboardQueryKeys.riskScore(timeRange),
    queryFn: () => dashboardService.getRiskScoreData(timeRange),
    enabled: !!user,
    staleTime: 10 * 60 * 1000, // 10 minutes
    refetchInterval: 5 * 60 * 1000, // 5 minutes
    onError: (error) => {
      console.error('Failed to fetch risk score data:', error);
      showError('Data Loading Error', 'Failed to load risk score data');
    },
  });
}

// Asset health data hook
export function useAssetHealth() {
  const { showError } = useAppStore();
  const { user } = useAuthStore();

  return useQuery({
    queryKey: dashboardQueryKeys.assetHealth(),
    queryFn: () => dashboardService.getAssetHealth(),
    enabled: !!user,
    staleTime: 5 * 60 * 1000, // 5 minutes
    refetchInterval: 2 * 60 * 1000, // 2 minutes
    onError: (error) => {
      console.error('Failed to fetch asset health:', error);
      showError('Data Loading Error', 'Failed to load asset health data');
    },
  });
}

// Compliance data hook
export function useComplianceData() {
  const { showError } = useAppStore();
  const { user } = useAuthStore();

  return useQuery({
    queryKey: dashboardQueryKeys.compliance(),
    queryFn: () => dashboardService.getComplianceData(),
    enabled: !!user,
    staleTime: 15 * 60 * 1000, // 15 minutes
    refetchInterval: 10 * 60 * 1000, // 10 minutes
    onError: (error) => {
      console.error('Failed to fetch compliance data:', error);
      showError('Data Loading Error', 'Failed to load compliance data');
    },
  });
}

// Security events hook
export function useSecurityEvents(limit: number = 10) {
  const { showError } = useAppStore();
  const { user } = useAuthStore();

  return useQuery({
    queryKey: dashboardQueryKeys.events(limit),
    queryFn: () => dashboardService.getSecurityEvents(limit),
    enabled: !!user,
    staleTime: 1 * 60 * 1000, // 1 minute
    refetchInterval: 30 * 1000, // 30 seconds
    onError: (error) => {
      console.error('Failed to fetch security events:', error);
      showError('Data Loading Error', 'Failed to load security events');
    },
  });
}

// Dashboard config management
export function useDashboardConfig() {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useAppStore();
  const { user } = useAuthStore();

  const query = useQuery({
    queryKey: dashboardQueryKeys.config(),
    queryFn: async (): Promise<DashboardConfig> => {
      // Mock implementation - would fetch from backend
      return {
        layout: 'default',
        widgets: ['metrics', 'threatActivity', 'riskScore', 'assetHealth', 'compliance'],
        refreshInterval: 30,
        theme: 'dark',
        timeRange: '24h',
      };
    },
    enabled: !!user,
    staleTime: 30 * 60 * 1000, // 30 minutes
  });

  const updateConfig = useMutation({
    mutationFn: dashboardService.updateDashboardConfig,
    onSuccess: (updatedConfig) => {
      queryClient.setQueryData(dashboardQueryKeys.config(), updatedConfig);
      showSuccess('Configuration Updated', 'Dashboard settings have been saved');
    },
    onError: (error) => {
      console.error('Failed to update dashboard config:', error);
      showError('Update Failed', 'Failed to save dashboard configuration');
    },
  });

  return {
    config: query.data,
    isLoading: query.isLoading,
    error: query.error,
    updateConfig: updateConfig.mutate,
    isUpdating: updateConfig.isPending,
  };
}

// Combined dashboard data hook for convenience
export function useDashboardData(timeRange: TimeRange = '24h') {
  const metrics = useDashboardMetrics(timeRange);
  const threatActivity = useThreatActivity({});
  const riskScore = useRiskScoreData(timeRange);
  const assetHealth = useAssetHealth();
  const compliance = useComplianceData();
  const events = useSecurityEvents(10);

  const isLoading =
    metrics.isLoading ||
    threatActivity.isLoading ||
    riskScore.isLoading ||
    assetHealth.isLoading ||
    compliance.isLoading ||
    events.isLoading;

  const hasError =
    metrics.error || threatActivity.error || riskScore.error || assetHealth.error || compliance.error || events.error;

  return {
    metrics: metrics.data,
    threatActivity: threatActivity.data,
    riskScore: riskScore.data,
    assetHealth: assetHealth.data,
    compliance: compliance.data,
    events: events.data,
    isLoading,
    hasError,
    refetchAll: useCallback(() => {
      metrics.refetch();
      threatActivity.refetch();
      riskScore.refetch();
      assetHealth.refetch();
      compliance.refetch();
      events.refetch();
    }, [metrics, threatActivity, riskScore, assetHealth, compliance, events]),
  };
}

// Dashboard refresh hook for manual refresh capability
export function useDashboardRefresh() {
  const queryClient = useQueryClient();

  return useCallback(
    (timeRange?: TimeRange) => {
      // Invalidate all dashboard queries to force refetch
      queryClient.invalidateQueries({ queryKey: dashboardQueryKeys.all });

      // Optionally invalidate related queries
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
    },
    [queryClient]
  );
}
