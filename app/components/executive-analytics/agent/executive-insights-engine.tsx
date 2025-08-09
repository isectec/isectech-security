'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Box, Typography, CircularProgress, Alert } from '@mui/material';
import { useWebSocket } from '../../../lib/hooks/use-websocket';
import { useAIInsights } from '../../../lib/hooks/use-ai-insights';
import {
  ExecutiveInsightsEngineProps,
  ExecutiveInsight,
  ExecutiveRecommendation
} from './types';

export const ExecutiveInsightsEngine: React.FC<ExecutiveInsightsEngineProps> = ({
  config,
  onInsightGenerated,
  dataStream,
  enabled = true
}) => {
  const [isProcessing, setIsProcessing] = useState(false);
  const [lastProcessedAt, setLastProcessedAt] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const processingInterval = useRef<NodeJS.Timeout | null>(null);
  const insightQueue = useRef<any[]>([]);

  // AI Insights hook for ML-powered analysis
  const {
    generateInsight,
    analyzePatterns,
    predictTrends,
    calculateConfidence,
    isLoading: aiLoading
  } = useAIInsights({
    userId: config.userId,
    tenantId: config.tenantId,
    userRole: config.userRole
  });

  // Data stream WebSocket for real-time insights
  const { isConnected, sendMessage } = useWebSocket(
    `/api/insights/stream?userId=${config.userId}&tenantId=${config.tenantId}`,
    {
      onMessage: handleDataStreamMessage,
      onError: (error) => setError('Data stream connection failed'),
      reconnectAttempts: 3,
      reconnectInterval: 5000
    }
  );

  useEffect(() => {
    if (enabled) {
      startInsightGeneration();
    } else {
      stopInsightGeneration();
    }

    return () => {
      stopInsightGeneration();
    };
  }, [enabled, config.preferences.insightGenerationFrequency]);

  const startInsightGeneration = () => {
    if (processingInterval.current) {
      clearInterval(processingInterval.current);
    }

    processingInterval.current = setInterval(
      processInsightGeneration,
      config.preferences.insightGenerationFrequency
    );

    // Generate initial insights
    processInsightGeneration();
  };

  const stopInsightGeneration = () => {
    if (processingInterval.current) {
      clearInterval(processingInterval.current);
      processingInterval.current = null;
    }
  };

  const handleDataStreamMessage = useCallback((message: any) => {
    try {
      const data = JSON.parse(message.data);
      insightQueue.current.push(data);
      
      // Process if queue is getting full
      if (insightQueue.current.length >= 10) {
        processInsightGeneration();
      }
    } catch (error) {
      console.error('Failed to parse data stream message:', error);
    }
  }, []);

  const processInsightGeneration = async () => {
    if (isProcessing || !enabled) return;

    try {
      setIsProcessing(true);
      setError(null);

      // Get current data from queue
      const currentData = [...insightQueue.current];
      insightQueue.current = [];

      // Generate insights based on user role and preferences
      const insights = await generateExecutiveInsights(currentData);
      
      // Process each insight
      for (const insight of insights) {
        if (await validateInsight(insight)) {
          onInsightGenerated(insight);
        }
      }

      setLastProcessedAt(new Date());
    } catch (error) {
      console.error('Insight generation failed:', error);
      setError('Failed to generate insights');
    } finally {
      setIsProcessing(false);
    }
  };

  const generateExecutiveInsights = async (data: any[]): Promise<ExecutiveInsight[]> => {
    const insights: ExecutiveInsight[] = [];

    try {
      // Security Posture Insights
      const securityInsights = await generateSecurityPostureInsights(data);
      insights.push(...securityInsights);

      // Threat Landscape Insights
      const threatInsights = await generateThreatLandscapeInsights(data);
      insights.push(...threatInsights);

      // Compliance Gap Analysis
      const complianceInsights = await generateComplianceInsights(data);
      insights.push(...complianceInsights);

      // Investment Optimization Insights
      const investmentInsights = await generateInvestmentInsights(data);
      insights.push(...investmentInsights);

      // Risk Mitigation Recommendations
      const riskInsights = await generateRiskMitigationInsights(data);
      insights.push(...riskInsights);

    } catch (error) {
      console.error('Failed to generate executive insights:', error);
    }

    return insights;
  };

  const generateSecurityPostureInsights = async (data: any[]): Promise<ExecutiveInsight[]> => {
    const insights: ExecutiveInsight[] = [];

    // Analyze security posture trends
    const postureData = data.filter(d => d.type === 'security-posture');
    if (postureData.length === 0) return insights;

    const patterns = await analyzePatterns(postureData);
    const trends = await predictTrends(postureData, 7); // 7-day forecast

    // Generate insight based on analysis
    if (patterns.deterioration && patterns.confidence > 0.7) {
      insights.push({
        id: `security-posture-${Date.now()}`,
        type: 'security-posture',
        title: 'Security Posture Deterioration Detected',
        description: `Security posture has declined by ${Math.round(patterns.change * 100)}% over the past ${patterns.period}. Key areas of concern include ${patterns.affectedAreas.join(', ')}.`,
        severity: patterns.change > 0.2 ? 'high' : 'medium',
        confidence: patterns.confidence,
        impact: {
          business: patterns.change > 0.3 ? 'high' : 'medium',
          financial: estimateFinancialImpact(patterns.change, 'security-posture'),
          operational: patterns.change > 0.2 ? 'significant' : 'moderate'
        },
        recommendations: await generateSecurityRecommendations(patterns),
        supportingData: { patterns, trends, rawData: postureData },
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        actionable: true,
        tags: ['security', 'posture', 'decline', 'urgent']
      });
    }

    return insights;
  };

  const generateThreatLandscapeInsights = async (data: any[]): Promise<ExecutiveInsight[]> => {
    const insights: ExecutiveInsight[] = [];

    const threatData = data.filter(d => d.type === 'threat-detection');
    if (threatData.length === 0) return insights;

    const threatAnalysis = await analyzePatterns(threatData);
    
    if (threatAnalysis.emergingPatterns && threatAnalysis.confidence > 0.8) {
      insights.push({
        id: `threat-landscape-${Date.now()}`,
        type: 'threat-landscape',
        title: 'Emerging Threat Pattern Identified',
        description: `New threat pattern detected with ${Math.round(threatAnalysis.confidence * 100)}% confidence. ${threatAnalysis.description}`,
        severity: threatAnalysis.severity || 'medium',
        confidence: threatAnalysis.confidence,
        impact: {
          business: 'high',
          financial: estimateFinancialImpact(threatAnalysis.impactScore, 'threat-landscape'),
          operational: 'significant'
        },
        recommendations: await generateThreatRecommendations(threatAnalysis),
        supportingData: { analysis: threatAnalysis, rawData: threatData },
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 12 * 60 * 60 * 1000), // 12 hours
        actionable: true,
        tags: ['threat', 'emerging', 'pattern', 'security']
      });
    }

    return insights;
  };

  const generateComplianceInsights = async (data: any[]): Promise<ExecutiveInsight[]> => {
    const insights: ExecutiveInsight[] = [];

    const complianceData = data.filter(d => d.type === 'compliance-status');
    if (complianceData.length === 0) return insights;

    const complianceAnalysis = await analyzePatterns(complianceData);
    
    if (complianceAnalysis.gaps && complianceAnalysis.gaps.length > 0) {
      insights.push({
        id: `compliance-gap-${Date.now()}`,
        type: 'compliance-gap',
        title: 'Compliance Gaps Require Executive Attention',
        description: `${complianceAnalysis.gaps.length} compliance gaps identified across ${complianceAnalysis.frameworks.join(', ')} frameworks. Immediate attention required to avoid regulatory penalties.`,
        severity: complianceAnalysis.criticalGaps > 0 ? 'critical' : 'high',
        confidence: 0.95, // High confidence for compliance data
        impact: {
          business: 'high',
          financial: estimateCompliancePenalties(complianceAnalysis.gaps),
          operational: 'significant'
        },
        recommendations: await generateComplianceRecommendations(complianceAnalysis),
        supportingData: { analysis: complianceAnalysis, gaps: complianceAnalysis.gaps },
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        actionable: true,
        tags: ['compliance', 'gaps', 'regulatory', 'urgent']
      });
    }

    return insights;
  };

  const generateInvestmentInsights = async (data: any[]): Promise<ExecutiveInsight[]> => {
    const insights: ExecutiveInsight[] = [];

    const investmentData = data.filter(d => d.type === 'security-investment');
    if (investmentData.length === 0) return insights;

    const roiAnalysis = await analyzePatterns(investmentData);
    
    if (roiAnalysis.optimizationOpportunities && roiAnalysis.optimizationOpportunities.length > 0) {
      insights.push({
        id: `investment-optimization-${Date.now()}`,
        type: 'investment-optimization',
        title: 'Security Investment Optimization Opportunities',
        description: `Analysis identifies ${roiAnalysis.optimizationOpportunities.length} opportunities to optimize security investments, potentially saving ${formatCurrency(roiAnalysis.potentialSavings)} annually.`,
        severity: 'medium',
        confidence: roiAnalysis.confidence,
        impact: {
          business: 'medium',
          financial: roiAnalysis.potentialSavings,
          operational: 'minimal'
        },
        recommendations: await generateInvestmentRecommendations(roiAnalysis),
        supportingData: { analysis: roiAnalysis, opportunities: roiAnalysis.optimizationOpportunities },
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        actionable: true,
        tags: ['investment', 'optimization', 'roi', 'savings']
      });
    }

    return insights;
  };

  const generateRiskMitigationInsights = async (data: any[]): Promise<ExecutiveInsight[]> => {
    const insights: ExecutiveInsight[] = [];

    const riskData = data.filter(d => d.type === 'risk-assessment');
    if (riskData.length === 0) return insights;

    const riskAnalysis = await analyzePatterns(riskData);
    
    if (riskAnalysis.highRiskAreas && riskAnalysis.highRiskAreas.length > 0) {
      insights.push({
        id: `risk-mitigation-${Date.now()}`,
        type: 'risk-mitigation',
        title: 'High-Risk Areas Require Executive Action',
        description: `${riskAnalysis.highRiskAreas.length} high-risk areas identified requiring executive-level mitigation strategies. Combined risk exposure: ${formatCurrency(riskAnalysis.totalExposure)}.`,
        severity: riskAnalysis.criticalRisks > 0 ? 'critical' : 'high',
        confidence: riskAnalysis.confidence,
        impact: {
          business: 'high',
          financial: riskAnalysis.totalExposure,
          operational: 'significant'
        },
        recommendations: await generateRiskRecommendations(riskAnalysis),
        supportingData: { analysis: riskAnalysis, risks: riskAnalysis.highRiskAreas },
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        actionable: true,
        tags: ['risk', 'mitigation', 'high-priority', 'executive']
      });
    }

    return insights;
  };

  const validateInsight = async (insight: ExecutiveInsight): Promise<boolean> => {
    // Validate insight quality and relevance
    if (insight.confidence < 0.6) return false;
    if (!insight.actionable && insight.severity !== 'critical') return false;
    if (insight.recommendations.length === 0) return false;
    
    return true;
  };

  // Helper functions for generating recommendations
  const generateSecurityRecommendations = async (patterns: any): Promise<ExecutiveRecommendation[]> => {
    const recommendations: ExecutiveRecommendation[] = [];

    if (patterns.affectedAreas.includes('endpoint-security')) {
      recommendations.push({
        id: `endpoint-rec-${Date.now()}`,
        title: 'Enhance Endpoint Security Controls',
        description: 'Deploy advanced endpoint detection and response (EDR) solution across all endpoints to improve security posture.',
        priority: 'high',
        estimatedEffort: 'moderate',
        timeframe: 'short-term',
        expectedOutcome: 'Reduce endpoint-related incidents by 70%',
        resourcesRequired: ['Security team', 'IT infrastructure', 'EDR platform'],
        riskReduction: 45,
        costBenefit: {
          cost: 150000,
          benefit: 500000,
          roi: 233
        }
      });
    }

    return recommendations;
  };

  const generateThreatRecommendations = async (analysis: any): Promise<ExecutiveRecommendation[]> => {
    // Implementation for threat-specific recommendations
    return [];
  };

  const generateComplianceRecommendations = async (analysis: any): Promise<ExecutiveRecommendation[]> => {
    // Implementation for compliance-specific recommendations
    return [];
  };

  const generateInvestmentRecommendations = async (analysis: any): Promise<ExecutiveRecommendation[]> => {
    // Implementation for investment-specific recommendations
    return [];
  };

  const generateRiskRecommendations = async (analysis: any): Promise<ExecutiveRecommendation[]> => {
    // Implementation for risk-specific recommendations
    return [];
  };

  // Helper functions
  const estimateFinancialImpact = (changeScore: number, type: string): number => {
    const baseCosts = {
      'security-posture': 1000000,
      'threat-landscape': 2000000,
      'compliance-gap': 500000
    };
    
    return Math.round((baseCosts[type] || 100000) * changeScore);
  };

  const estimateCompliancePenalties = (gaps: any[]): number => {
    return gaps.reduce((total, gap) => total + (gap.potentialPenalty || 50000), 0);
  };

  const formatCurrency = (amount: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(amount);
  };

  return (
    <Box sx={{ display: 'none' }}>
      {/* Hidden component - processing happens in background */}
      {isProcessing && <CircularProgress size={20} />}
      {error && (
        <Alert severity="error" sx={{ mt: 1 }}>
          {error}
        </Alert>
      )}
    </Box>
  );
};