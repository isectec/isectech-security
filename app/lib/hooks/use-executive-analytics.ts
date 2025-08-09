'use client';

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useAuthStore } from '../store';

export interface ExecutiveAnalyticsData {
  executiveMetrics: ExecutiveMetrics | null;
  threatLandscape: ThreatLandscapeData | null;
  complianceStatus: ComplianceStatusData | null;
  roiMetrics: ROIMetricsData | null;
  predictiveAnalytics: PredictiveAnalyticsData | null;
  isLoading: boolean;
  error: string | null;
  dataFreshness: number | null;
  lastRefresh: Date | null;
  refreshData: () => Promise<void>;
  retryCount: number;
}

export interface ExecutiveMetrics {
  securityPostureScore: number;
  riskExposureIndex: number;
  threatLandscapeSeverity: 'low' | 'medium' | 'high' | 'critical';
  complianceScores: Record<string, number>;
  securityInvestmentROI: number;
  mttd: number; // milliseconds
  mttr: number; // milliseconds
  businessDisruptionEvents: number;
  customerTrustIndex: number;
  revenueAtRisk: number;
  securityTeamProductivity: number;
  automationRatio: number;
  falsePositiveRate: number;
  vulnerabilityRemediationSLA: number;
  trainingCompletionRate: number;
  lastUpdated: Date;
  dataFreshness: Record<string, number>;
  confidenceScores: Record<string, number>;
  calculationDuration: number;
}

export interface ThreatLandscapeData {
  globalThreatLevel: 'low' | 'medium' | 'high' | 'critical';
  industryThreatLevel: 'low' | 'medium' | 'high' | 'critical';
  activeThreatCount: number;
  emergingThreats: EmergingThreat[];
  threatActorActivity: ThreatActorActivity[];
  geopoliticalFactors: GeopoliticalFactor[];
  threatTrends: ThreatTrendData[];
  lastIntelligenceSync: Date;
}

export interface EmergingThreat {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  firstSeen: Date;
  affectedAssets: number;
  indicators: string[];
  mitigationStatus: 'open' | 'in-progress' | 'mitigated';
}

export interface ThreatActorActivity {
  actorName: string;
  activityLevel: 'low' | 'medium' | 'high';
  targetSectors: string[];
  recentCampaigns: string[];
  lastActivity: Date;
  threatScore: number;
}

export interface GeopoliticalFactor {
  factor: string;
  impact: 'low' | 'medium' | 'high';
  probability: number;
  timeline: Date;
  description: string;
}

export interface ThreatTrendData {
  date: Date;
  threatCount: number;
  severityDistribution: Record<string, number>;
  category: string;
}

export interface ComplianceStatusData {
  overallScore: number;
  frameworkScores: Record<string, ComplianceFrameworkScore>;
  auditReadiness: number;
  controlsStatus: ControlsStatusSummary;
  upcomingDeadlines: ComplianceDeadline[];
  recentChanges: ComplianceChange[];
  riskAreas: ComplianceRiskArea[];
  lastAssessment: Date;
}

export interface ComplianceFrameworkScore {
  framework: string;
  score: number;
  maxScore: number;
  controlsPassed: number;
  controlsFailed: number;
  controlsPending: number;
  trend: 'improving' | 'declining' | 'stable';
  lastAssessment: Date;
}

export interface ControlsStatusSummary {
  totalControls: number;
  activeControls: number;
  inactiveControls: number;
  pendingControls: number;
  criticalControlsAtRisk: number;
}

export interface ComplianceDeadline {
  framework: string;
  deadline: Date;
  readiness: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  requiresAction: boolean;
}

export interface ComplianceChange {
  framework: string;
  changeType: 'new_requirement' | 'updated_requirement' | 'deprecated';
  description: string;
  effectiveDate: Date;
  impact: 'low' | 'medium' | 'high';
}

export interface ComplianceRiskArea {
  area: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  affectedFrameworks: string[];
  recommendedActions: string[];
  deadline: Date;
}

export interface ROIMetricsData {
  securityInvestmentROI: number;
  totalSecuritySpend: number;
  costAvoidance: number;
  incidentCostSavings: number;
  productivityGains: number;
  complianceCostSavings: number;
  roiByCategory: Record<string, number>;
  investmentBreakdown: Record<string, number>;
  projectedROI: ProjectedROIData;
  benchmarkComparison: ROIBenchmarkData;
  lastCalculation: Date;
}

export interface ProjectedROIData {
  sixMonthROI: number;
  oneYearROI: number;
  threeYearROI: number;
  breakevenPeriod: number; // days
  confidenceLevel: number;
  assumptions: string[];
}

export interface ROIBenchmarkData {
  industryAverage: number;
  peerComparison: 'above' | 'below' | 'average';
  percentileRanking: number;
  bestPracticeGap: number;
}

export interface PredictiveAnalyticsData {
  threatProbabilityIndex: PredictiveThreatIndex;
  vulnerabilityRiskScore: PredictiveVulnerabilityScore;
  budgetImpactForecast: BudgetForecastData;
  complianceDeadlineRisk: ComplianceDeadlineRiskData;
  incidentLikelihood: IncidentLikelihoodData;
  recommendedActions: RecommendedAction[];
  modelPerformance: ModelPerformanceData;
  lastUpdate: Date;
}

export interface PredictiveThreatIndex {
  thirtyDayProbability: number;
  ninetyDayProbability: number;
  confidenceScore: number;
  primaryRiskFactors: string[];
  mitigationRecommendations: string[];
}

export interface PredictiveVulnerabilityScore {
  currentScore: number;
  projectedScore: number;
  peakRiskTiming: Date;
  confidenceInterval: [number, number];
  keyRiskFactors: string[];
  remediationImpact: number;
}

export interface BudgetForecastData {
  projectedCosts: Record<string, number>;
  roiForecast: number;
  riskAdjustedBudget: number;
  forecastHorizon: number; // days
  costDrivers: CostDriver[];
}

export interface CostDriver {
  category: string;
  currentCost: number;
  projectedCost: number;
  impact: 'low' | 'medium' | 'high';
  confidence: number;
}

export interface ComplianceDeadlineRiskData {
  upcomingDeadlines: ComplianceDeadlineRisk[];
  overallRiskLevel: 'low' | 'medium' | 'high' | 'critical';
  recommendedActions: string[];
  timeToNextCriticalDeadline: number; // days
}

export interface ComplianceDeadlineRisk {
  framework: string;
  deadline: Date;
  readiness: number;
  riskScore: number;
  criticalPath: string[];
}

export interface IncidentLikelihoodData {
  overallScore: number;
  categoryScores: Record<string, number>;
  trendDirection: 'increasing' | 'decreasing' | 'stable';
  primaryTriggers: string[];
  preventiveMeasures: string[];
}

export interface RecommendedAction {
  id: string;
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  category: 'security' | 'compliance' | 'operations' | 'budget';
  estimatedImpact: number;
  timeframe: string;
  effort: 'low' | 'medium' | 'high';
  confidence: number;
}

export interface ModelPerformanceData {
  accuracy: number;
  precision: number;
  recall: number;
  lastTraining: Date;
  dataQuality: number;
  modelVersion: string;
}

interface UseExecutiveAnalyticsOptions {
  userId: string;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  tenantId: string;
  refreshInterval?: number;
  autoRefresh?: boolean;
  retryLimit?: number;
  cacheTTL?: number;
}

const EXECUTIVE_API_BASE = '/api/executive-analytics';
const DEFAULT_REFRESH_INTERVAL = 30000; // 30 seconds
const DEFAULT_RETRY_LIMIT = 3;
const DEFAULT_CACHE_TTL = 60000; // 1 minute

export function useExecutiveAnalytics(options: UseExecutiveAnalyticsOptions): ExecutiveAnalyticsData {
  const {
    userId,
    userRole,
    tenantId,
    refreshInterval = DEFAULT_REFRESH_INTERVAL,
    autoRefresh = true,
    retryLimit = DEFAULT_RETRY_LIMIT,
    cacheTTL = DEFAULT_CACHE_TTL
  } = options;

  const auth = useAuthStore();
  
  // State management
  const [executiveMetrics, setExecutiveMetrics] = useState<ExecutiveMetrics | null>(null);
  const [threatLandscape, setThreatLandscape] = useState<ThreatLandscapeData | null>(null);
  const [complianceStatus, setComplianceStatus] = useState<ComplianceStatusData | null>(null);
  const [roiMetrics, setROIMetrics] = useState<ROIMetricsData | null>(null);
  const [predictiveAnalytics, setPredictiveAnalytics] = useState<PredictiveAnalyticsData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dataFreshness, setDataFreshness] = useState<number | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [retryCount, setRetryCount] = useState(0);

  // Refs for cleanup and caching
  const refreshTimeoutRef = useRef<NodeJS.Timeout>();
  const cacheRef = useRef<Map<string, { data: any; timestamp: number }>>(new Map());
  const abortControllerRef = useRef<AbortController>();

  // Cache management
  const getCacheKey = useCallback((endpoint: string) => {
    return `${endpoint}-${userId}-${tenantId}-${userRole}`;
  }, [userId, tenantId, userRole]);

  const getCachedData = useCallback((key: string) => {
    const cached = cacheRef.current.get(key);
    if (cached && Date.now() - cached.timestamp < cacheTTL) {
      return cached.data;
    }
    return null;
  }, [cacheTTL]);

  const setCachedData = useCallback((key: string, data: any) => {
    cacheRef.current.set(key, { data, timestamp: Date.now() });
  }, []);

  // API request helper with retry logic and executive SLA requirements
  const fetchWithRetry = useCallback(async (
    endpoint: string,
    retries = retryLimit
  ): Promise<any> => {
    const cacheKey = getCacheKey(endpoint);
    const cachedData = getCachedData(cacheKey);
    
    if (cachedData) {
      return cachedData;
    }

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        // Cancel previous request
        if (abortControllerRef.current) {
          abortControllerRef.current.abort();
        }
        
        abortControllerRef.current = new AbortController();
        
        const response = await fetch(`${EXECUTIVE_API_BASE}${endpoint}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${auth.token}`,
            'Content-Type': 'application/json',
            'X-User-Role': userRole,
            'X-Tenant-ID': tenantId,
            'X-Executive-Priority': 'true' // Executive SLA flag
          },
          signal: abortControllerRef.current.signal,
          // Executive requirement: 5-second timeout
          cache: 'no-cache'
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        setCachedData(cacheKey, data);
        
        // Reset retry count on success
        setRetryCount(0);
        
        return data;
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          throw err;
        }
        
        if (attempt === retries) {
          setRetryCount(attempt + 1);
          throw new Error(`Failed to fetch ${endpoint} after ${retries + 1} attempts: ${err}`);
        }
        
        // Exponential backoff for executive analytics (max 5 seconds)
        const delay = Math.min(Math.pow(2, attempt) * 1000, 5000);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }, [retryLimit, auth.token, userRole, tenantId, getCacheKey, getCachedData, setCachedData]);

  // Fetch executive KPI snapshot
  const fetchExecutiveMetrics = useCallback(async (): Promise<ExecutiveMetrics> => {
    const data = await fetchWithRetry('/kpi-snapshot');
    return {
      ...data,
      lastUpdated: new Date(data.timestamp),
      calculationDuration: data.calculation_duration || 0,
      dataFreshness: data.data_freshness || {},
      confidenceScores: data.confidence_scores || {}
    };
  }, [fetchWithRetry]);

  // Fetch threat landscape data
  const fetchThreatLandscape = useCallback(async (): Promise<ThreatLandscapeData> => {
    const data = await fetchWithRetry('/threat-landscape');
    return {
      ...data,
      emergingThreats: data.emerging_threats?.map((threat: any) => ({
        ...threat,
        firstSeen: new Date(threat.first_seen)
      })) || [],
      threatActorActivity: data.threat_actor_activity?.map((activity: any) => ({
        ...activity,
        lastActivity: new Date(activity.last_activity)
      })) || [],
      geopoliticalFactors: data.geopolitical_factors?.map((factor: any) => ({
        ...factor,
        timeline: new Date(factor.timeline)
      })) || [],
      threatTrends: data.threat_trends?.map((trend: any) => ({
        ...trend,
        date: new Date(trend.date)
      })) || [],
      lastIntelligenceSync: new Date(data.last_intelligence_sync)
    };
  }, [fetchWithRetry]);

  // Fetch compliance status
  const fetchComplianceStatus = useCallback(async (): Promise<ComplianceStatusData> => {
    const data = await fetchWithRetry('/compliance-status');
    return {
      ...data,
      upcomingDeadlines: data.upcoming_deadlines?.map((deadline: any) => ({
        ...deadline,
        deadline: new Date(deadline.deadline)
      })) || [],
      recentChanges: data.recent_changes?.map((change: any) => ({
        ...change,
        effectiveDate: new Date(change.effective_date)
      })) || [],
      riskAreas: data.risk_areas?.map((area: any) => ({
        ...area,
        deadline: new Date(area.deadline)
      })) || [],
      lastAssessment: new Date(data.last_assessment)
    };
  }, [fetchWithRetry]);

  // Fetch ROI metrics
  const fetchROIMetrics = useCallback(async (): Promise<ROIMetricsData> => {
    const data = await fetchWithRetry('/roi-metrics');
    return {
      ...data,
      lastCalculation: new Date(data.last_calculation),
      projectedROI: {
        ...data.projected_roi,
        assumptions: data.projected_roi?.assumptions || []
      }
    };
  }, [fetchWithRetry]);

  // Fetch predictive analytics
  const fetchPredictiveAnalytics = useCallback(async (): Promise<PredictiveAnalyticsData> => {
    const data = await fetchWithRetry('/predictive-analytics');
    return {
      ...data,
      vulnerabilityRiskScore: {
        ...data.vulnerability_risk_score,
        peakRiskTiming: new Date(data.vulnerability_risk_score.peak_risk_timing)
      },
      budgetImpactForecast: {
        ...data.budget_impact_forecast,
        costDrivers: data.budget_impact_forecast.cost_drivers || []
      },
      complianceDeadlineRisk: {
        ...data.compliance_deadline_risk,
        upcomingDeadlines: data.compliance_deadline_risk.upcoming_deadlines?.map((deadline: any) => ({
          ...deadline,
          deadline: new Date(deadline.deadline)
        })) || []
      },
      recommendedActions: data.recommended_actions || [],
      modelPerformance: {
        ...data.model_performance,
        lastTraining: new Date(data.model_performance.last_training)
      },
      lastUpdate: new Date(data.last_update)
    };
  }, [fetchWithRetry]);

  // Main data refresh function
  const refreshData = useCallback(async () => {
    try {
      setError(null);
      setIsLoading(true);
      
      const startTime = Date.now();

      // Parallel fetch for optimal executive performance
      const [
        metricsData,
        threatData,
        complianceData,
        roiData,
        predictiveData
      ] = await Promise.allSettled([
        fetchExecutiveMetrics(),
        fetchThreatLandscape(),
        fetchComplianceStatus(),
        fetchROIMetrics(),
        fetchPredictiveAnalytics()
      ]);

      // Process results with error handling
      if (metricsData.status === 'fulfilled') {
        setExecutiveMetrics(metricsData.value);
      } else {
        console.error('Failed to fetch executive metrics:', metricsData.reason);
      }

      if (threatData.status === 'fulfilled') {
        setThreatLandscape(threatData.value);
      } else {
        console.error('Failed to fetch threat landscape:', threatData.reason);
      }

      if (complianceData.status === 'fulfilled') {
        setComplianceStatus(complianceData.value);
      } else {
        console.error('Failed to fetch compliance status:', complianceData.reason);
      }

      if (roiData.status === 'fulfilled') {
        setROIMetrics(roiData.value);
      } else {
        console.error('Failed to fetch ROI metrics:', roiData.reason);
      }

      if (predictiveData.status === 'fulfilled') {
        setPredictiveAnalytics(predictiveData.value);
      } else {
        console.error('Failed to fetch predictive analytics:', predictiveData.reason);
      }

      const loadTime = Date.now() - startTime;
      setDataFreshness(loadTime);
      setLastRefresh(new Date());

      // Check executive SLA compliance (5-second load time)
      if (loadTime > 5000) {
        console.warn(`Executive dashboard SLA breach: ${loadTime}ms load time`);
      }

      // If all requests failed, set error
      const failedCount = [metricsData, threatData, complianceData, roiData, predictiveData]
        .filter(result => result.status === 'rejected').length;
      
      if (failedCount === 5) {
        setError('Unable to load executive dashboard data. Please try again.');
      } else if (failedCount > 0) {
        setError(`Some dashboard components are unavailable (${failedCount}/5 failed)`);
      }

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Executive analytics refresh failed:', err);
    } finally {
      setIsLoading(false);
    }
  }, [
    fetchExecutiveMetrics,
    fetchThreatLandscape,
    fetchComplianceStatus,
    fetchROIMetrics,
    fetchPredictiveAnalytics
  ]);

  // Auto-refresh setup with cleanup
  useEffect(() => {
    if (!autoRefresh) return;

    const setupAutoRefresh = () => {
      refreshTimeoutRef.current = setTimeout(() => {
        refreshData().then(() => {
          setupAutoRefresh(); // Schedule next refresh
        });
      }, refreshInterval);
    };

    setupAutoRefresh();

    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
    };
  }, [autoRefresh, refreshInterval, refreshData]);

  // Initial data load
  useEffect(() => {
    refreshData();
    
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [refreshData]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      cacheRef.current.clear();
    };
  }, []);

  return useMemo(() => ({
    executiveMetrics,
    threatLandscape,
    complianceStatus,
    roiMetrics,
    predictiveAnalytics,
    isLoading,
    error,
    dataFreshness,
    lastRefresh,
    refreshData,
    retryCount
  }), [
    executiveMetrics,
    threatLandscape,
    complianceStatus,
    roiMetrics,
    predictiveAnalytics,
    isLoading,
    error,
    dataFreshness,
    lastRefresh,
    refreshData,
    retryCount
  ]);
}

export default useExecutiveAnalytics;