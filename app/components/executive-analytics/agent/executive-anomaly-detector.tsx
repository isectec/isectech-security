'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Box, Typography, Alert } from '@mui/material';
import { useAnomalyDetection } from '../../../lib/hooks/use-anomaly-detection';
import {
  ExecutiveAnomalyDetectorProps,
  ExecutiveAnomaly,
  AnomalyVisualization
} from './types';

export const ExecutiveAnomalyDetector: React.FC<ExecutiveAnomalyDetectorProps> = ({
  config,
  onAnomalyDetected,
  metrics,
  sensitivity,
  enabled = true
}) => {
  const [isProcessing, setIsProcessing] = useState(false);
  const [baselines, setBaselines] = useState<Record<string, any>>({});
  const [error, setError] = useState<string | null>(null);
  
  const detectionInterval = useRef<NodeJS.Timeout | null>(null);
  const metricsBuffer = useRef<any[]>([]);

  // Anomaly detection algorithms
  const {
    detectStatisticalAnomalies,
    detectBehavioralAnomalies,
    detectSeasonalAnomalies,
    detectTrendAnomalies,
    updateBaselines,
    calculateDeviationScore
  } = useAnomalyDetection({
    userId: config.userId,
    tenantId: config.tenantId,
    sensitivity
  });

  useEffect(() => {
    if (enabled) {
      startAnomalyDetection();
    } else {
      stopAnomalyDetection();
    }

    return () => {
      stopAnomalyDetection();
    };
  }, [enabled, sensitivity, metrics]);

  useEffect(() => {
    if (metrics && metrics.length > 0) {
      metricsBuffer.current = [...metrics];
      if (enabled) {
        processAnomalyDetection();
      }
    }
  }, [metrics, enabled]);

  const startAnomalyDetection = () => {
    if (detectionInterval.current) {
      clearInterval(detectionInterval.current);
    }

    // Process anomaly detection every 30 seconds for executive responsiveness
    detectionInterval.current = setInterval(
      processAnomalyDetection,
      30000
    );

    // Initial baseline establishment
    establishBaselines();
  };

  const stopAnomalyDetection = () => {
    if (detectionInterval.current) {
      clearInterval(detectionInterval.current);
      detectionInterval.current = null;
    }
  };

  const establishBaselines = async () => {
    try {
      const currentMetrics = metricsBuffer.current;
      if (currentMetrics.length < 10) return; // Need minimum data

      const newBaselines = await updateBaselines(currentMetrics);
      setBaselines(newBaselines);
    } catch (error) {
      console.error('Failed to establish baselines:', error);
    }
  };

  const processAnomalyDetection = async () => {
    if (isProcessing || !enabled || metricsBuffer.current.length === 0) return;

    try {
      setIsProcessing(true);
      setError(null);

      const currentMetrics = metricsBuffer.current;
      const detectedAnomalies: ExecutiveAnomaly[] = [];

      // Security Posture Anomalies
      const securityAnomalies = await detectSecurityAnomalies(currentMetrics);
      detectedAnomalies.push(...securityAnomalies);

      // Performance Anomalies
      const performanceAnomalies = await detectPerformanceAnomalies(currentMetrics);
      detectedAnomalies.push(...performanceAnomalies);

      // Compliance Anomalies
      const complianceAnomalies = await detectComplianceAnomalies(currentMetrics);
      detectedAnomalies.push(...complianceAnomalies);

      // Cost Anomalies
      const costAnomalies = await detectCostAnomalies(currentMetrics);
      detectedAnomalies.push(...costAnomalies);

      // User Behavior Anomalies
      const behaviorAnomalies = await detectUserBehaviorAnomalies(currentMetrics);
      detectedAnomalies.push(...behaviorAnomalies);

      // Process and notify about significant anomalies
      for (const anomaly of detectedAnomalies) {
        if (await validateAnomaly(anomaly)) {
          onAnomalyDetected(anomaly);
        }
      }

    } catch (error) {
      console.error('Anomaly detection failed:', error);
      setError('Failed to process anomaly detection');
    } finally {
      setIsProcessing(false);
    }
  };

  const detectSecurityAnomalies = async (metrics: any[]): Promise<ExecutiveAnomaly[]> => {
    const anomalies: ExecutiveAnomaly[] = [];

    const securityMetrics = metrics.filter(m => m.category === 'security');
    if (securityMetrics.length === 0) return anomalies;

    // Security Posture Score Anomaly
    const postureMetrics = securityMetrics.filter(m => m.type === 'security-posture');
    if (postureMetrics.length > 0) {
      const latestPosture = postureMetrics[postureMetrics.length - 1];
      const baseline = baselines['security-posture'] || { mean: 85, stddev: 5 };
      
      const deviationScore = calculateDeviationScore(latestPosture.value, baseline);
      
      if (deviationScore > getSensitivityThreshold(sensitivity)) {
        const deviation = ((latestPosture.value - baseline.mean) / baseline.mean) * 100;
        
        anomalies.push({
          id: `security-posture-anomaly-${Date.now()}`,
          type: 'security-deviation',
          title: 'Security Posture Deviation Detected',
          description: `Security posture score has deviated by ${Math.abs(deviation).toFixed(1)}% from baseline (${baseline.mean}%). Current score: ${latestPosture.value}%.`,
          severity: Math.abs(deviation) > 20 ? 'critical' : Math.abs(deviation) > 10 ? 'warning' : 'info',
          confidence: Math.min(deviationScore / 3, 1), // Normalize to 0-1
          detectedAt: new Date(),
          affectedSystems: ['Security Dashboard', 'Threat Detection', 'Vulnerability Management'],
          metrics: {
            baseline: baseline.mean,
            current: latestPosture.value,
            deviation: deviation,
            threshold: getSensitivityThreshold(sensitivity)
          },
          potentialCauses: generatePotentialCauses('security-posture', deviation),
          suggestedActions: generateSuggestedActions('security-posture', deviation),
          businessImpact: {
            immediate: deviation < 0 ? 'Increased security risk exposure' : 'Potential over-investment in security',
            longTerm: 'Sustained security posture issues could lead to breaches or compliance failures',
            financialRisk: estimateFinancialRisk('security-posture', Math.abs(deviation))
          },
          visualizations: await generateAnomalyVisualizations('security-posture', postureMetrics, baseline)
        });
      }
    }

    // Threat Detection Rate Anomaly
    const threatMetrics = securityMetrics.filter(m => m.type === 'threat-detection-rate');
    if (threatMetrics.length > 0) {
      const recentThreats = threatMetrics.slice(-10); // Last 10 data points
      const statisticalAnomalies = await detectStatisticalAnomalies(recentThreats);
      
      for (const statAnomaly of statisticalAnomalies) {
        anomalies.push({
          id: `threat-detection-anomaly-${Date.now()}-${statAnomaly.id}`,
          type: 'security-deviation',
          title: 'Threat Detection Rate Anomaly',
          description: `Unusual threat detection pattern identified. ${statAnomaly.description}`,
          severity: statAnomaly.severity,
          confidence: statAnomaly.confidence,
          detectedAt: new Date(),
          affectedSystems: ['Threat Detection Engine', 'SIEM', 'SOC Operations'],
          metrics: statAnomaly.metrics,
          potentialCauses: [
            'New threat campaign targeting organization',
            'Changes in threat detection rules',
            'Network configuration changes',
            'False positive increase'
          ],
          suggestedActions: [
            'Review threat detection rules and thresholds',
            'Investigate recent security incidents',
            'Validate threat intelligence feeds',
            'Check for false positive patterns'
          ],
          businessImpact: {
            immediate: 'Potential gaps in threat detection capability',
            longTerm: 'Increased risk of undetected security incidents',
            financialRisk: 1500000 // Average cost of undetected breach
          },
          visualizations: await generateThreatAnomalyVisualizations(threatMetrics, statAnomaly)
        });
      }
    }

    return anomalies;
  };

  const detectPerformanceAnomalies = async (metrics: any[]): Promise<ExecutiveAnomaly[]> => {
    const anomalies: ExecutiveAnomaly[] = [];

    const performanceMetrics = metrics.filter(m => m.category === 'performance');
    
    // Response Time Anomalies
    const responseTimeMetrics = performanceMetrics.filter(m => m.type === 'response-time');
    if (responseTimeMetrics.length > 0) {
      const trendAnomalies = await detectTrendAnomalies(responseTimeMetrics);
      
      for (const trendAnomaly of trendAnomalies) {
        if (trendAnomaly.significance > 0.8) { // High significance threshold
          anomalies.push({
            id: `performance-trend-anomaly-${Date.now()}`,
            type: 'performance-drop',
            title: 'System Performance Degradation',
            description: `System response times showing ${trendAnomaly.direction} trend with ${(trendAnomaly.significance * 100).toFixed(1)}% confidence.`,
            severity: trendAnomaly.impact > 0.5 ? 'warning' : 'info',
            confidence: trendAnomaly.significance,
            detectedAt: new Date(),
            affectedSystems: ['Dashboard', 'API Gateway', 'Database'],
            metrics: {
              baseline: trendAnomaly.baseline,
              current: trendAnomaly.current,
              deviation: trendAnomaly.change,
              threshold: getSensitivityThreshold(sensitivity)
            },
            potentialCauses: [
              'Increased system load',
              'Database performance degradation',
              'Network latency issues',
              'Resource constraints'
            ],
            suggestedActions: [
              'Review system resource utilization',
              'Analyze database query performance',
              'Check network connectivity and bandwidth',
              'Consider scaling infrastructure'
            ],
            businessImpact: {
              immediate: 'Reduced user experience and productivity',
              longTerm: 'Potential customer dissatisfaction and churn',
              financialRisk: estimatePerformanceImpact(trendAnomaly.impact)
            },
            visualizations: await generatePerformanceVisualizations(responseTimeMetrics, trendAnomaly)
          });
        }
      }
    }

    return anomalies;
  };

  const detectComplianceAnomalies = async (metrics: any[]): Promise<ExecutiveAnomaly[]> => {
    const anomalies: ExecutiveAnomaly[] = [];

    const complianceMetrics = metrics.filter(m => m.category === 'compliance');
    
    // Compliance Score Drift
    const complianceScores = complianceMetrics.filter(m => m.type === 'compliance-score');
    if (complianceScores.length > 0) {
      const behavioralAnomalies = await detectBehavioralAnomalies(complianceScores);
      
      for (const behaviorAnomaly of behavioralAnomalies) {
        if (behaviorAnomaly.severity === 'high' || behaviorAnomaly.severity === 'critical') {
          anomalies.push({
            id: `compliance-drift-anomaly-${Date.now()}`,
            type: 'compliance-drift',
            title: 'Compliance Score Drift Detected',
            description: `Compliance score showing unusual deviation from established patterns. ${behaviorAnomaly.description}`,
            severity: behaviorAnomaly.severity,
            confidence: behaviorAnomaly.confidence,
            detectedAt: new Date(),
            affectedSystems: ['Compliance Management', 'Audit Systems', 'Risk Assessment'],
            metrics: behaviorAnomaly.metrics,
            potentialCauses: [
              'Policy changes not properly implemented',
              'System configuration drift',
              'Training gaps in compliance procedures',
              'Regulatory requirement changes'
            ],
            suggestedActions: [
              'Review recent policy changes',
              'Audit system configurations',
              'Assess compliance training effectiveness',
              'Update compliance monitoring rules'
            ],
            businessImpact: {
              immediate: 'Increased regulatory risk',
              longTerm: 'Potential compliance violations and penalties',
              financialRisk: estimateComplianceRisk(behaviorAnomaly.impact)
            },
            visualizations: await generateComplianceVisualizations(complianceScores, behaviorAnomaly)
          });
        }
      }
    }

    return anomalies;
  };

  const detectCostAnomalies = async (metrics: any[]): Promise<ExecutiveAnomaly[]> => {
    const anomalies: ExecutiveAnomaly[] = [];

    const costMetrics = metrics.filter(m => m.category === 'cost');
    
    // Security Investment Spikes
    const securityCosts = costMetrics.filter(m => m.type === 'security-investment');
    if (securityCosts.length > 0) {
      const seasonalAnomalies = await detectSeasonalAnomalies(securityCosts);
      
      for (const seasonalAnomaly of seasonalAnomalies) {
        if (seasonalAnomaly.unexpected) {
          anomalies.push({
            id: `cost-spike-anomaly-${Date.now()}`,
            type: 'cost-spike',
            title: 'Unexpected Security Cost Spike',
            description: `Security costs showing unexpected increase of ${(seasonalAnomaly.deviation * 100).toFixed(1)}% compared to seasonal baseline.`,
            severity: seasonalAnomaly.deviation > 0.3 ? 'warning' : 'info',
            confidence: seasonalAnomaly.confidence,
            detectedAt: new Date(),
            affectedSystems: ['Budget Management', 'Financial Reporting', 'Procurement'],
            metrics: seasonalAnomaly.metrics,
            potentialCauses: [
              'Emergency security investments',
              'License cost increases',
              'Incident response costs',
              'Consulting and professional services'
            ],
            suggestedActions: [
              'Review recent security expenditures',
              'Analyze budget vs actual spending',
              'Identify cost optimization opportunities',
              'Update budget forecasts'
            ],
            businessImpact: {
              immediate: 'Budget variance and financial reporting impact',
              longTerm: 'Potential budget constraints for future investments',
              financialRisk: seasonalAnomaly.amount || 0
            },
            visualizations: await generateCostVisualizations(securityCosts, seasonalAnomaly)
          });
        }
      }
    }

    return anomalies;
  };

  const detectUserBehaviorAnomalies = async (metrics: any[]): Promise<ExecutiveAnomaly[]> => {
    const anomalies: ExecutiveAnomaly[] = [];

    const behaviorMetrics = metrics.filter(m => m.category === 'user-behavior');
    
    // Executive Dashboard Usage Patterns
    const usageMetrics = behaviorMetrics.filter(m => m.type === 'dashboard-usage');
    if (usageMetrics.length > 0) {
      const behaviorAnomalies = await detectBehavioralAnomalies(usageMetrics);
      
      for (const behaviorAnomaly of behaviorAnomalies) {
        if (behaviorAnomaly.significant) {
          anomalies.push({
            id: `user-behavior-anomaly-${Date.now()}`,
            type: 'user-behavior',
            title: 'Executive Dashboard Usage Pattern Change',
            description: `Unusual change in executive dashboard usage patterns detected. ${behaviorAnomaly.description}`,
            severity: 'info',
            confidence: behaviorAnomaly.confidence,
            detectedAt: new Date(),
            affectedSystems: ['Executive Dashboard', 'Analytics', 'User Experience'],
            metrics: behaviorAnomaly.metrics,
            potentialCauses: [
              'Changes in business priorities',
              'New executive team members',
              'Dashboard feature updates',
              'External business events'
            ],
            suggestedActions: [
              'Survey executive users for feedback',
              'Review recent dashboard changes',
              'Analyze feature adoption patterns',
              'Consider UX improvements'
            ],
            businessImpact: {
              immediate: 'Potential impact on executive decision-making',
              longTerm: 'May indicate need for dashboard optimization',
              financialRisk: 0 // Generally low financial risk
            },
            visualizations: await generateBehaviorVisualizations(usageMetrics, behaviorAnomaly)
          });
        }
      }
    }

    return anomalies;
  };

  const validateAnomaly = async (anomaly: ExecutiveAnomaly): Promise<boolean> => {
    // Validate anomaly significance and executive relevance
    if (anomaly.confidence < 0.7) return false;
    if (anomaly.severity === 'info' && anomaly.businessImpact.financialRisk < 10000) return false;
    
    return true;
  };

  // Helper functions
  const getSensitivityThreshold = (sensitivity: string): number => {
    switch (sensitivity) {
      case 'high': return 1.5; // Detect smaller deviations
      case 'medium': return 2.0;
      case 'low': return 3.0; // Only detect large deviations
      default: return 2.0;
    }
  };

  const generatePotentialCauses = (type: string, deviation: number): string[] => {
    const commonCauses = {
      'security-posture': [
        'New vulnerabilities discovered',
        'Security control failures',
        'Policy compliance issues',
        'Infrastructure changes'
      ]
    };
    
    return commonCauses[type] || ['Unknown cause requiring investigation'];
  };

  const generateSuggestedActions = (type: string, deviation: number): string[] => {
    const commonActions = {
      'security-posture': [
        'Review security control effectiveness',
        'Conduct vulnerability assessment',
        'Update security policies',
        'Implement additional controls'
      ]
    };
    
    return commonActions[type] || ['Investigate anomaly cause'];
  };

  const estimateFinancialRisk = (type: string, deviation: number): number => {
    const riskMultipliers = {
      'security-posture': 100000, // $100k per percentage point
      'threat-detection': 50000,
      'compliance': 200000
    };
    
    return Math.round((riskMultipliers[type] || 10000) * deviation);
  };

  const estimatePerformanceImpact = (impact: number): number => {
    // Estimate revenue impact from performance degradation
    return Math.round(impact * 500000); // $500k potential impact
  };

  const estimateComplianceRisk = (impact: number): number => {
    // Estimate compliance penalty risk
    return Math.round(impact * 1000000); // $1M potential penalty
  };

  const generateAnomalyVisualizations = async (type: string, data: any[], baseline: any): Promise<AnomalyVisualization[]> => {
    return [
      {
        type: 'timeline',
        data: data.map(d => ({ x: d.timestamp, y: d.value })),
        config: {
          baseline: baseline.mean,
          thresholds: {
            upper: baseline.mean + (baseline.stddev * 2),
            lower: baseline.mean - (baseline.stddev * 2)
          }
        },
        title: `${type} Timeline with Anomaly Detection`,
        description: 'Historical data showing deviation from baseline'
      }
    ];
  };

  const generateThreatAnomalyVisualizations = async (data: any[], anomaly: any): Promise<AnomalyVisualization[]> => {
    return [
      {
        type: 'heatmap',
        data: anomaly.heatmapData,
        config: { colorScale: 'threat-severity' },
        title: 'Threat Detection Heatmap',
        description: 'Threat detection patterns over time'
      }
    ];
  };

  const generatePerformanceVisualizations = async (data: any[], trend: any): Promise<AnomalyVisualization[]> => {
    return [
      {
        type: 'scatter',
        data: trend.scatterData,
        config: { trendLine: true },
        title: 'Performance Trend Analysis',
        description: 'Performance metrics with trend analysis'
      }
    ];
  };

  const generateComplianceVisualizations = async (data: any[], behavior: any): Promise<AnomalyVisualization[]> => {
    return [
      {
        type: 'distribution',
        data: behavior.distributionData,
        config: { showOutliers: true },
        title: 'Compliance Score Distribution',
        description: 'Distribution showing behavioral anomalies'
      }
    ];
  };

  const generateCostVisualizations = async (data: any[], seasonal: any): Promise<AnomalyVisualization[]> => {
    return [
      {
        type: 'timeline',
        data: seasonal.timelineData,
        config: { seasonalBaseline: true },
        title: 'Cost Anomaly Timeline',
        description: 'Cost patterns with seasonal baseline'
      }
    ];
  };

  const generateBehaviorVisualizations = async (data: any[], behavior: any): Promise<AnomalyVisualization[]> => {
    return [
      {
        type: 'heatmap',
        data: behavior.usageHeatmap,
        config: { timeGranularity: 'hour' },
        title: 'Usage Pattern Heatmap',
        description: 'User behavior patterns over time'
      }
    ];
  };

  return (
    <Box sx={{ display: 'none' }}>
      {/* Hidden component - processing happens in background */}
      {error && (
        <Alert severity="error" sx={{ mt: 1 }}>
          {error}
        </Alert>
      )}
    </Box>
  );
};