/**
 * Executive Analytics Dashboard Agent Types
 * Type definitions for intelligent agent components
 */

import { ReactNode } from 'react';

export interface ExecutiveAgentConfig {
  userId: string;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  tenantId: string;
  preferences: {
    insightGenerationFrequency: number;
    anomalyDetectionSensitivity: 'low' | 'medium' | 'high';
    predictiveAnalyticsHorizon: number; // days
    reportGenerationSchedule: 'daily' | 'weekly' | 'monthly';
    nlqEnabled: boolean;
    autoRefreshInterval: number;
  };
  capabilities: {
    aiInsights: boolean;
    anomalyDetection: boolean;
    predictiveAnalytics: boolean;
    naturalLanguageQuery: boolean;
    automatedReporting: boolean;
    realTimeAnalytics: boolean;
  };
}

export interface ExecutiveInsight {
  id: string;
  type: 'security-posture' | 'threat-landscape' | 'compliance-gap' | 'investment-optimization' | 'risk-mitigation';
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0-1
  impact: {
    business: 'low' | 'medium' | 'high';
    financial: number; // estimated dollar impact
    operational: 'minimal' | 'moderate' | 'significant';
  };
  recommendations: ExecutiveRecommendation[];
  supportingData: any;
  generatedAt: Date;
  expiresAt: Date;
  actionable: boolean;
  tags: string[];
}

export interface ExecutiveRecommendation {
  id: string;
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'urgent';
  estimatedEffort: 'minimal' | 'moderate' | 'significant' | 'major';
  timeframe: 'immediate' | 'short-term' | 'medium-term' | 'long-term';
  expectedOutcome: string;
  resourcesRequired: string[];
  riskReduction: number; // percentage
  costBenefit: {
    cost: number;
    benefit: number;
    roi: number;
  };
}

export interface ExecutiveAnomaly {
  id: string;
  type: 'security-deviation' | 'performance-drop' | 'compliance-drift' | 'cost-spike' | 'user-behavior';
  title: string;
  description: string;
  severity: 'info' | 'warning' | 'critical';
  confidence: number; // 0-1
  detectedAt: Date;
  affectedSystems: string[];
  metrics: {
    baseline: number;
    current: number;
    deviation: number; // percentage
    threshold: number;
  };
  potentialCauses: string[];
  suggestedActions: string[];
  businessImpact: {
    immediate: string;
    longTerm: string;
    financialRisk: number;
  };
  visualizations: AnomalyVisualization[];
}

export interface AnomalyVisualization {
  type: 'timeline' | 'heatmap' | 'scatter' | 'distribution';
  data: any;
  config: any;
  title: string;
  description: string;
}

export interface ExecutiveQuery {
  id: string;
  query: string;
  intent: {
    type: 'data-request' | 'trend-analysis' | 'comparison' | 'prediction' | 'recommendation';
    entities: string[];
    timeframe: {
      start?: Date;
      end?: Date;
      period?: 'hour' | 'day' | 'week' | 'month' | 'quarter' | 'year';
    };
    filters: Record<string, any>;
  };
  response: {
    type: 'visualization' | 'insight' | 'recommendation' | 'data-table' | 'narrative';
    content: any;
    confidence: number;
    sources: string[];
    generatedAt: Date;
  };
  conversationContext: NLQContext[];
  userId: string;
  sessionId: string;
}

export interface NLQContext {
  query: string;
  response: string;
  timestamp: Date;
  entities: string[];
  intent: string;
}

export interface ExecutiveReport {
  id: string;
  type: 'security-summary' | 'compliance-status' | 'threat-assessment' | 'investment-analysis' | 'performance-review';
  title: string;
  subtitle?: string;
  period: {
    start: Date;
    end: Date;
    label: string;
  };
  sections: ExecutiveReportSection[];
  executiveSummary: string;
  keyMetrics: ExecutiveMetric[];
  insights: ExecutiveInsight[];
  recommendations: ExecutiveRecommendation[];
  appendices: ExecutiveAppendix[];
  metadata: {
    generatedAt: Date;
    generatedBy: string;
    version: string;
    confidentialityLevel: 'public' | 'internal' | 'confidential' | 'restricted';
    distributionList: string[];
    expirationDate?: Date;
  };
  format: {
    template: 'executive-brief' | 'detailed-analysis' | 'board-presentation' | 'regulatory-filing';
    styling: ReportStyling;
    exportFormats: ('pdf' | 'powerpoint' | 'word' | 'html' | 'json')[];
  };
}

export interface ExecutiveReportSection {
  id: string;
  title: string;
  content: string;
  visualizations: ReportVisualization[];
  order: number;
  importance: 'critical' | 'high' | 'medium' | 'low';
}

export interface ReportVisualization {
  id: string;
  type: 'chart' | 'table' | 'heatmap' | 'gauge' | 'trend' | 'comparison';
  title: string;
  data: any;
  config: any;
  executiveFriendly: boolean;
  interactionEnabled: boolean;
}

export interface ReportStyling {
  theme: 'executive' | 'board' | 'technical' | 'regulatory';
  colors: {
    primary: string;
    secondary: string;
    accent: string;
    warning: string;
    error: string;
    success: string;
  };
  fonts: {
    heading: string;
    body: string;
    monospace: string;
  };
  layout: {
    pageSize: 'A4' | 'Letter' | 'A3';
    orientation: 'portrait' | 'landscape';
    margins: { top: number; right: number; bottom: number; left: number; };
  };
  branding: {
    logo: string;
    watermark?: string;
    companyName: string;
    brandColors: string[];
  };
}

export interface ExecutiveAppendix {
  id: string;
  title: string;
  type: 'data-tables' | 'technical-details' | 'methodology' | 'glossary' | 'references';
  content: any;
  order: number;
}

export interface ExecutiveMetric {
  id: string;
  name: string;
  value: number | string;
  unit?: string;
  format: 'number' | 'percentage' | 'currency' | 'time' | 'text';
  trend: {
    direction: 'up' | 'down' | 'stable';
    change: number;
    period: string;
  };
  target?: number;
  status: 'good' | 'warning' | 'critical';
  description: string;
}

export interface ExecutivePrediction {
  id: string;
  type: 'security-trend' | 'threat-forecast' | 'compliance-projection' | 'cost-prediction' | 'risk-assessment';
  title: string;
  description: string;
  timeHorizon: {
    period: 'days' | 'weeks' | 'months' | 'quarters';
    value: number;
  };
  confidence: number; // 0-1
  methodology: string;
  predictions: PredictionPoint[];
  scenarios: PredictionScenario[];
  recommendations: ExecutiveRecommendation[];
  businessImplications: {
    risks: string[];
    opportunities: string[];
    requiredActions: string[];
    investmentNeeds: number;
  };
  visualizations: PredictionVisualization[];
  lastUpdated: Date;
  dataQuality: {
    completeness: number;
    accuracy: number;
    freshness: number;
  };
}

export interface PredictionPoint {
  timestamp: Date;
  value: number;
  confidence: number;
  range: {
    lower: number;
    upper: number;
  };
  contributors: string[];
}

export interface PredictionScenario {
  id: string;
  name: string;
  description: string;
  probability: number;
  timeline: string;
  impact: {
    financial: number;
    operational: 'low' | 'medium' | 'high';
    reputational: 'low' | 'medium' | 'high';
  };
  mitigationStrategies: string[];
}

export interface PredictionVisualization {
  type: 'forecast-chart' | 'scenario-matrix' | 'confidence-bands' | 'impact-analysis';
  data: any;
  config: any;
  interactionEnabled: boolean;
  executiveFocus: boolean;
}

// Agent Event Types
export interface AgentEvent {
  type: 'insight-generated' | 'anomaly-detected' | 'prediction-updated' | 'report-generated' | 'query-processed';
  timestamp: Date;
  data: any;
  userId: string;
  tenantId: string;
}

// Agent Performance Metrics
export interface AgentMetrics {
  insightAccuracy: number;
  anomalyDetectionRate: number;
  falsePositiveRate: number;
  responseTime: number;
  userSatisfaction: number;
  adoptionRate: number;
  systemLoad: {
    cpu: number;
    memory: number;
    network: number;
  };
  dataProcessingStats: {
    recordsProcessed: number;
    errorRate: number;
    latency: number;
  };
}

// React Component Props
export interface ExecutiveAgentProps {
  config: ExecutiveAgentConfig;
  onInsightGenerated?: (insight: ExecutiveInsight) => void;
  onAnomalyDetected?: (anomaly: ExecutiveAnomaly) => void;
  onPredictionUpdated?: (prediction: ExecutivePrediction) => void;
  onReportGenerated?: (report: ExecutiveReport) => void;
  onQueryProcessed?: (query: ExecutiveQuery) => void;
  className?: string;
  children?: ReactNode;
}

export interface ExecutiveInsightsEngineProps {
  config: ExecutiveAgentConfig;
  onInsightGenerated: (insight: ExecutiveInsight) => void;
  dataStream?: any;
  enabled?: boolean;
}

export interface ExecutiveAnomalyDetectorProps {
  config: ExecutiveAgentConfig;
  onAnomalyDetected: (anomaly: ExecutiveAnomaly) => void;
  metrics: any[];
  sensitivity: 'low' | 'medium' | 'high';
  enabled?: boolean;
}

export interface ExecutiveNLQInterfaceProps {
  config: ExecutiveAgentConfig;
  onQueryProcessed: (query: ExecutiveQuery) => void;
  placeholder?: string;
  suggestions?: string[];
  contextAware?: boolean;
  voiceEnabled?: boolean;
}

export interface ExecutiveReportGeneratorProps {
  config: ExecutiveAgentConfig;
  onReportGenerated: (report: ExecutiveReport) => void;
  template?: string;
  schedule?: string;
  autoGenerate?: boolean;
}

export interface ExecutivePredictiveEngineProps {
  config: ExecutiveAgentConfig;
  onPredictionUpdated: (prediction: ExecutivePrediction) => void;
  horizon: number;
  models: string[];
  enabled?: boolean;
}