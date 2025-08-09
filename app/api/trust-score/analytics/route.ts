/**
 * Trust Score Analytics API
 * Comprehensive analytics and reporting for trust scoring system
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { rateLimit } from '@/lib/middleware/rate-limiting';
import { authenticate, authorize } from '@/lib/middleware/auth';
import { validateTenant } from '@/lib/middleware/tenant-validation';
import { auditLog } from '@/lib/middleware/audit-logging';
import { sanitizeInput } from '@/lib/utils/input-sanitization';
import { metrics } from '@/lib/monitoring/metrics';
import { logger } from '@/lib/utils/logger';

// Validation schemas
const analyticsQuerySchema = z.object({
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  granularity: z.enum(['hour', 'day', 'week', 'month']).default('day'),
  metrics: z.array(z.enum([
    'average_score', 'score_distribution', 'risk_distribution', 
    'factor_impact', 'threshold_crossings', 'calculation_volume'
  ])).optional(),
  groupBy: z.array(z.enum([
    'user_segment', 'device_type', 'location', 'time_period', 'risk_level'
  ])).optional(),
  filters: z.object({
    userSegments: z.array(z.string()).optional(),
    deviceTypes: z.array(z.string()).optional(),
    locations: z.array(z.string()).optional(),
    riskLevels: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
    scoreRanges: z.array(z.object({
      min: z.number().min(0).max(100),
      max: z.number().min(0).max(100),
    })).optional(),
  }).optional(),
  includeComparisons: z.boolean().default(false),
  includePredictions: z.boolean().default(false),
  includeRecommendations: z.boolean().default(true),
});

const reportQuerySchema = z.object({
  reportType: z.enum(['executive', 'operational', 'security', 'compliance']),
  format: z.enum(['json', 'csv', 'pdf']).default('json'),
  includeCharts: z.boolean().default(true),
  includeDetails: z.boolean().default(true),
  timeframe: z.enum(['24h', '7d', '30d', '90d', '1y']).default('30d'),
  recipients: z.array(z.string()).optional(),
});

interface TrustScoreAnalyticsService {
  getOverviewAnalytics(tenantId: string, params: any): Promise<any>;
  getDetailedAnalytics(tenantId: string, params: any): Promise<any>;
  getFactorAnalysis(tenantId: string, params: any): Promise<any>;
  getRiskTrendAnalysis(tenantId: string, params: any): Promise<any>;
  getUserSegmentAnalysis(tenantId: string, params: any): Promise<any>;
  getAnomalyDetection(tenantId: string, params: any): Promise<any>;
  generateReport(tenantId: string, params: any): Promise<any>;
  getPerformanceMetrics(tenantId: string, params: any): Promise<any>;
  getPredictiveAnalysis(tenantId: string, params: any): Promise<any>;
}

// Mock trust score analytics service
class MockTrustScoreAnalyticsService implements TrustScoreAnalyticsService {
  
  private generateTimeSeries(startDate: string, endDate: string, granularity: string): any[] {
    const start = new Date(startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000));
    const end = new Date(endDate || new Date());
    const data = [];
    
    let current = new Date(start);
    const increment = granularity === 'hour' ? 3600000 : 
                     granularity === 'day' ? 86400000 :
                     granularity === 'week' ? 604800000 : 2592000000;

    while (current <= end) {
      data.push({
        timestamp: current.toISOString(),
        averageScore: Math.random() * 30 + 60, // 60-90 range
        calculationCount: Math.floor(Math.random() * 1000) + 100,
        riskDistribution: {
          low: Math.floor(Math.random() * 60) + 30,
          medium: Math.floor(Math.random() * 30) + 10,
          high: Math.floor(Math.random() * 15) + 5,
          critical: Math.floor(Math.random() * 5) + 1,
        },
        factorImpact: {
          behavioral: Math.random() * 0.1 + 0.3,
          device: Math.random() * 0.1 + 0.2,
          network: Math.random() * 0.1 + 0.15,
          location: Math.random() * 0.1 + 0.1,
          threat: Math.random() * 0.1 + 0.05,
        },
      });
      current = new Date(current.getTime() + increment);
    }
    
    return data;
  }

  async getOverviewAnalytics(tenantId: string, params: any) {
    const timeSeries = this.generateTimeSeries(params.startDate, params.endDate, params.granularity);
    
    const overview = {
      totalCalculations: 125000,
      averageScore: 74.2,
      scoreImprovement: 8.5, // percentage
      riskReduction: 12.3, // percentage
      highRiskUsers: 234,
      anomaliesDetected: 18,
      systemUptime: 99.97,
    };

    const riskDistribution = {
      low: { count: 89500, percentage: 71.6 },
      medium: { count: 28750, percentage: 23.0 },
      high: { count: 5625, percentage: 4.5 },
      critical: { count: 1125, percentage: 0.9 },
    };

    const scoreDistribution = [
      { range: '0-20', count: 1250, percentage: 1.0 },
      { range: '21-40', count: 3750, percentage: 3.0 },
      { range: '41-60', count: 18750, percentage: 15.0 },
      { range: '61-80', count: 62500, percentage: 50.0 },
      { range: '81-100', count: 38750, percentage: 31.0 },
    ];

    return {
      overview,
      riskDistribution,
      scoreDistribution,
      timeSeries,
      period: {
        startDate: params.startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        endDate: params.endDate || new Date().toISOString(),
        granularity: params.granularity,
      },
    };
  }

  async getDetailedAnalytics(tenantId: string, params: any) {
    const baseAnalytics = await this.getOverviewAnalytics(tenantId, params);

    const factorBreakdown = {
      behavioral: {
        averageScore: 78.5,
        impact: 35.2,
        trends: {
          loginFrequency: { score: 82.1, trend: 'stable' },
          sessionPatterns: { score: 76.8, trend: 'improving' },
          suspiciousActivity: { score: 75.2, trend: 'improving' },
        },
        topIssues: [
          { issue: 'Irregular login times', affectedUsers: 1250, impact: 'medium' },
          { issue: 'Multiple failed attempts', affectedUsers: 890, impact: 'high' },
          { issue: 'Unusual session duration', affectedUsers: 560, impact: 'low' },
        ],
      },
      device: {
        averageScore: 71.3,
        impact: 28.7,
        trends: {
          deviceFingerprinting: { score: 85.2, trend: 'stable' },
          deviceReputation: { score: 68.9, trend: 'declining' },
          securityPosture: { score: 59.8, trend: 'declining' },
        },
        topIssues: [
          { issue: 'Jailbroken/Rooted devices', affectedUsers: 2100, impact: 'high' },
          { issue: 'Unknown device types', affectedUsers: 1800, impact: 'medium' },
          { issue: 'Outdated security patches', affectedUsers: 3200, impact: 'medium' },
        ],
      },
      network: {
        averageScore: 73.8,
        impact: 22.1,
        trends: {
          ipReputation: { score: 76.5, trend: 'stable' },
          vpnDetection: { score: 68.2, trend: 'stable' },
          geoConsistency: { score: 77.1, trend: 'improving' },
        },
        topIssues: [
          { issue: 'VPN usage detected', affectedUsers: 5600, impact: 'medium' },
          { issue: 'Suspicious IP ranges', affectedUsers: 890, impact: 'high' },
          { issue: 'Proxy connections', affectedUsers: 1200, impact: 'medium' },
        ],
      },
    };

    const userSegmentAnalysis = {
      powerUsers: {
        count: 12500,
        averageScore: 85.2,
        riskLevel: 'low',
        scoreImprovement: 5.8,
      },
      regularUsers: {
        count: 87500,
        averageScore: 72.1,
        riskLevel: 'medium',
        scoreImprovement: 8.9,
      },
      newUsers: {
        count: 18750,
        averageScore: 65.3,
        riskLevel: 'medium',
        scoreImprovement: 15.2,
      },
      inactiveUsers: {
        count: 6250,
        averageScore: 58.7,
        riskLevel: 'high',
        scoreImprovement: -2.1,
      },
    };

    return {
      ...baseAnalytics,
      factorBreakdown,
      userSegmentAnalysis,
      calculations: {
        totalToday: 15600,
        averageLatency: 145, // milliseconds
        cacheHitRate: 78.5, // percentage
        errorRate: 0.2, // percentage
      },
    };
  }

  async getFactorAnalysis(tenantId: string, params: any) {
    return {
      factorWeights: {
        current: {
          behavioral: 0.35,
          device: 0.25,
          network: 0.20,
          location: 0.15,
          threat: 0.05,
        },
        recommended: {
          behavioral: 0.40,
          device: 0.25,
          network: 0.18,
          location: 0.12,
          threat: 0.05,
        },
        changes: {
          behavioral: +0.05,
          device: 0.00,
          network: -0.02,
          location: -0.03,
          threat: 0.00,
        },
      },
      factorCorrelations: {
        'behavioral-device': 0.65,
        'behavioral-network': 0.42,
        'device-network': 0.38,
        'location-network': 0.71,
        'threat-network': 0.33,
      },
      factorEffectiveness: {
        behavioral: {
          effectiveness: 0.82,
          falsePositives: 0.08,
          falseNegatives: 0.12,
          description: 'High effectiveness in detecting user behavior anomalies',
        },
        device: {
          effectiveness: 0.75,
          falsePositives: 0.15,
          falseNegatives: 0.18,
          description: 'Good at identifying compromised devices',
        },
        network: {
          effectiveness: 0.68,
          falsePositives: 0.22,
          falseNegatives: 0.25,
          description: 'Moderate effectiveness with some geographic bias',
        },
      },
      recommendations: [
        {
          type: 'weight_adjustment',
          factor: 'behavioral',
          recommendation: 'Increase weight from 35% to 40%',
          reasoning: 'Behavioral factors show highest correlation with actual risk',
          impact: 'Expected 12% improvement in accuracy',
        },
        {
          type: 'new_factor',
          factor: 'temporal',
          recommendation: 'Add time-based pattern analysis',
          reasoning: 'Time-based patterns could improve detection of automated attacks',
          impact: 'Potential 8% reduction in false positives',
        },
      ],
    };
  }

  async getRiskTrendAnalysis(tenantId: string, params: any) {
    const timeSeries = this.generateTimeSeries(params.startDate, params.endDate, params.granularity);

    return {
      trends: {
        overallRisk: {
          direction: 'decreasing',
          rate: -2.3, // percentage per period
          confidence: 0.87,
        },
        riskBySegment: {
          newUsers: { direction: 'increasing', rate: 3.1 },
          powerUsers: { direction: 'stable', rate: -0.2 },
          inactiveUsers: { direction: 'decreasing', rate: -5.8 },
        },
        riskByFactor: {
          behavioral: { direction: 'improving', rate: -1.8 },
          device: { direction: 'stable', rate: 0.3 },
          network: { direction: 'degrading', rate: 2.1 },
        },
      },
      forecasting: {
        nextPeriod: {
          expectedAverageScore: 76.8,
          expectedRiskDistribution: {
            low: 74.2,
            medium: 21.8,
            high: 3.5,
            critical: 0.5,
          },
          confidence: 0.82,
        },
        alerts: [
          {
            type: 'trend_reversal',
            description: 'Network risk factor showing upward trend',
            severity: 'medium',
            recommendation: 'Monitor VPN and proxy usage patterns',
          },
        ],
      },
      seasonalPatterns: {
        weeklyPattern: {
          monday: 1.05,
          tuesday: 0.98,
          wednesday: 0.95,
          thursday: 1.02,
          friday: 1.15,
          saturday: 0.85,
          sunday: 0.78,
        },
        hourlyPattern: {
          businessHours: 1.12,
          offHours: 0.85,
          peakHour: { hour: 14, multiplier: 1.35 },
          lowHour: { hour: 3, multiplier: 0.45 },
        },
      },
      timeSeries,
    };
  }

  async getUserSegmentAnalysis(tenantId: string, params: any) {
    return {
      segments: {
        byScore: {
          'high-trust': {
            scoreRange: '80-100',
            userCount: 38750,
            percentage: 31.0,
            characteristics: ['Consistent behavior', 'Known devices', 'Trusted locations'],
            trends: { scoreChange: 2.1, riskChange: -15.2 },
          },
          'medium-trust': {
            scoreRange: '60-79',
            userCount: 62500,
            percentage: 50.0,
            characteristics: ['Generally consistent', 'Some device changes', 'Occasional VPN usage'],
            trends: { scoreChange: 1.5, riskChange: -8.7 },
          },
          'low-trust': {
            scoreRange: '40-59',
            userCount: 18750,
            percentage: 15.0,
            characteristics: ['Irregular patterns', 'Multiple devices', 'Frequent location changes'],
            trends: { scoreChange: -0.8, riskChange: 5.2 },
          },
          'high-risk': {
            scoreRange: '0-39',
            userCount: 5000,
            percentage: 4.0,
            characteristics: ['Suspicious activity', 'Compromised devices', 'Threat indicators'],
            trends: { scoreChange: -2.3, riskChange: 12.8 },
          },
        },
        byBehavior: {
          consistent: {
            userCount: 95000,
            averageScore: 78.2,
            description: 'Users with predictable, consistent behavior patterns',
          },
          evolving: {
            userCount: 22500,
            averageScore: 68.5,
            description: 'Users showing gradual changes in behavior',
          },
          erratic: {
            userCount: 7500,
            averageScore: 52.1,
            description: 'Users with unpredictable or suspicious patterns',
          },
        },
      },
      riskMigration: {
        improved: {
          count: 15600,
          description: 'Users who moved to lower risk categories',
          factors: ['Consistent login patterns', 'Device security improvements'],
        },
        degraded: {
          count: 4200,
          description: 'Users who moved to higher risk categories', 
          factors: ['New suspicious activities', 'Compromised devices'],
        },
        stable: {
          count: 105200,
          description: 'Users maintaining their risk level',
        },
      },
      actionItems: [
        {
          priority: 'high',
          segment: 'high-risk',
          action: 'Implement mandatory MFA for 5000 high-risk users',
          expectedImpact: 'Reduce fraud risk by 65%',
        },
        {
          priority: 'medium',
          segment: 'low-trust',
          action: 'Deploy device verification for irregular device usage',
          expectedImpact: 'Improve trust scores by 12-15 points',
        },
      ],
    };
  }

  async getAnomalyDetection(tenantId: string, params: any) {
    return {
      currentAnomalies: [
        {
          id: 'anomaly-001',
          type: 'score_drop',
          severity: 'medium',
          description: 'Sudden drop in average trust scores',
          detectedAt: new Date(Date.now() - 3600000).toISOString(),
          affectedUsers: 1250,
          scoreImpact: -12.5,
          possibleCauses: ['Network infrastructure changes', 'New device types'],
          status: 'investigating',
        },
        {
          id: 'anomaly-002',
          type: 'factor_imbalance',
          severity: 'low',
          description: 'Unusual network factor contribution',
          detectedAt: new Date(Date.now() - 7200000).toISOString(),
          affectedUsers: 3400,
          scoreImpact: -3.2,
          possibleCauses: ['VPN usage increase', 'New ISP routing'],
          status: 'resolved',
        },
      ],
      anomalyPatterns: {
        temporal: {
          description: 'Time-based anomalies',
          patterns: [
            { time: '02:00-04:00', anomalyRate: 2.3, description: 'High suspicious activity during night hours' },
            { time: '12:00-14:00', anomalyRate: 1.1, description: 'Slight increase during lunch hours' },
          ],
        },
        geographical: {
          description: 'Location-based anomalies',
          patterns: [
            { location: 'Asia-Pacific', anomalyRate: 1.8, description: 'Higher VPN usage rates' },
            { location: 'Europe', anomalyRate: 0.9, description: 'Below average anomaly rates' },
          ],
        },
      },
      detection: {
        algorithms: [
          {
            name: 'Statistical Outlier Detection',
            enabled: true,
            sensitivity: 0.05,
            falsePositiveRate: 0.08,
            detectionRate: 0.74,
          },
          {
            name: 'Machine Learning Clustering',
            enabled: true,
            sensitivity: 0.03,
            falsePositiveRate: 0.12,
            detectionRate: 0.82,
          },
        ],
        performance: {
          totalAnomaliesDetected: 245,
          confirmedAnomalies: 189,
          falsePositives: 56,
          accuracy: 0.77,
        },
      },
    };
  }

  async generateReport(tenantId: string, params: any) {
    const { reportType, format, timeframe } = params;

    const reportData = {
      metadata: {
        reportType,
        format,
        timeframe,
        generatedAt: new Date().toISOString(),
        tenantId,
        dataPoints: 125000,
      },
      executive: {
        summary: 'Trust scoring system performance remains strong with 74.2 average score and 8.5% improvement over last period.',
        keyMetrics: {
          systemHealth: 'Good',
          riskReduction: '12.3%',
          anomaliesDetected: 18,
          actionItemsCompleted: 12,
        },
        recommendations: [
          'Increase focus on device security factor weighting',
          'Implement additional behavioral analysis patterns',
          'Review network factor effectiveness',
        ],
      },
      operational: {
        systemPerformance: {
          calculationsPerSecond: 850,
          averageLatency: '145ms',
          uptime: '99.97%',
          errorRate: '0.2%',
        },
        capacityPlanning: {
          currentCapacity: '85%',
          projectedGrowth: '25%',
          recommendedScaling: 'Add 2 processing nodes by Q2',
        },
      },
      security: {
        threatLandscape: {
          totalThreats: 1250,
          blockedThreats: 1189,
          successRate: '95.1%',
        },
        riskMitigation: {
          highRiskUsers: 234,
          mitigationActions: 187,
          pendingActions: 47,
        },
      },
    };

    return {
      report: reportData,
      downloadUrl: `/api/trust-score/reports/${reportType}-${Date.now()}.${format}`,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
    };
  }

  async getPerformanceMetrics(tenantId: string, params: any) {
    return {
      calculation: {
        throughput: {
          current: 850, // calculations per second
          peak: 1200,
          average: 650,
          target: 1000,
        },
        latency: {
          p50: 120, // milliseconds
          p95: 280,
          p99: 450,
          target: 200,
        },
        accuracy: {
          overall: 0.847,
          byFactor: {
            behavioral: 0.892,
            device: 0.834,
            network: 0.756,
            location: 0.823,
            threat: 0.911,
          },
        },
      },
      caching: {
        hitRate: 78.5, // percentage
        missRate: 21.5,
        evictionRate: 2.3,
        cacheSize: '2.1GB',
        entries: 125000,
      },
      resources: {
        cpu: {
          usage: 68.5, // percentage
          cores: 16,
          peak: 89.2,
        },
        memory: {
          usage: 72.1, // percentage
          total: '32GB',
          peak: 85.7,
        },
        storage: {
          usage: 45.8, // percentage
          total: '1TB',
          growth: '2.1GB/day',
        },
      },
      availability: {
        uptime: 99.97, // percentage
        incidents: 2,
        meanTimeToRecovery: 180, // seconds
        lastIncident: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      },
    };
  }

  async getPredictiveAnalysis(tenantId: string, params: any) {
    return {
      scorePredictions: {
        nextWeek: {
          averageScore: 75.8,
          confidence: 0.78,
          factors: {
            behavioral: { predicted: 79.2, trend: 'stable' },
            device: { predicted: 72.1, trend: 'declining' },
            network: { predicted: 74.5, trend: 'improving' },
          },
        },
        nextMonth: {
          averageScore: 77.2,
          confidence: 0.65,
          riskDistribution: {
            low: 73.5,
            medium: 22.1,
            high: 3.8,
            critical: 0.6,
          },
        },
      },
      riskForecasting: {
        emergingRisks: [
          {
            risk: 'AI-generated behavioral mimicry',
            probability: 0.15,
            timeframe: '6 months',
            impact: 'medium',
            mitigation: 'Enhanced behavioral pattern analysis',
          },
          {
            risk: 'New device exploitation techniques',
            probability: 0.32,
            timeframe: '3 months',
            impact: 'high',
            mitigation: 'Device fingerprinting improvements',
          },
        ],
        modelDrift: {
          detected: true,
          severity: 'low',
          affectedFactors: ['network'],
          recommendedAction: 'Retrain network analysis model',
          timeline: '2 weeks',
        },
      },
      recommendations: [
        {
          type: 'proactive',
          priority: 'high',
          action: 'Implement behavioral sequence analysis',
          rationale: 'Predicted increase in sophisticated attacks',
          timeline: '4 weeks',
          resources: 'Medium',
        },
        {
          type: 'optimization',
          priority: 'medium',
          action: 'Optimize device factor calculations',
          rationale: 'Performance degradation predicted',
          timeline: '2 weeks',
          resources: 'Low',
        },
      ],
    };
  }
}

const analyticsService = new MockTrustScoreAnalyticsService();

// GET /api/trust-score/analytics - Get trust score analytics
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 200, // Analytics operations are more intensive
      keyGenerator: (req) => `trust-analytics:${req.headers.get('x-forwarded-for') || 'unknown'}`,
    });

    if (!rateLimitResult.success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', retryAfter: rateLimitResult.retryAfter },
        { status: 429, headers: { 'Retry-After': rateLimitResult.retryAfter?.toString() || '60' } }
      );
    }

    // Authentication & Authorization
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const hasPermission = await authorize(user, 'trust-score:analytics:read');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse query parameters
    const { searchParams } = new URL(request.url);
    const queryParams = Object.fromEntries(searchParams);
    
    const validationResult = analyticsQuerySchema.safeParse(queryParams);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Get analytics type from query
    const analyticsType = searchParams.get('type') || 'overview';
    
    let analyticsData;
    
    switch (analyticsType) {
      case 'overview':
        analyticsData = await analyticsService.getOverviewAnalytics(tenantValidation.tenantId, validationResult.data);
        break;
      case 'detailed':
        analyticsData = await analyticsService.getDetailedAnalytics(tenantValidation.tenantId, validationResult.data);
        break;
      case 'factors':
        analyticsData = await analyticsService.getFactorAnalysis(tenantValidation.tenantId, validationResult.data);
        break;
      case 'trends':
        analyticsData = await analyticsService.getRiskTrendAnalysis(tenantValidation.tenantId, validationResult.data);
        break;
      case 'segments':
        analyticsData = await analyticsService.getUserSegmentAnalysis(tenantValidation.tenantId, validationResult.data);
        break;
      case 'anomalies':
        analyticsData = await analyticsService.getAnomalyDetection(tenantValidation.tenantId, validationResult.data);
        break;
      case 'performance':
        analyticsData = await analyticsService.getPerformanceMetrics(tenantValidation.tenantId, validationResult.data);
        break;
      case 'predictions':
        analyticsData = await analyticsService.getPredictiveAnalysis(tenantValidation.tenantId, validationResult.data);
        break;
      default:
        return NextResponse.json(
          { error: 'Invalid analytics type. Valid types: overview, detailed, factors, trends, segments, anomalies, performance, predictions' },
          { status: 400 }
        );
    }

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'trust_score.analytics.view',
      resource: 'trust_score_analytics',
      metadata: { 
        analyticsType,
        query: validationResult.data,
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('trust_score.analytics.get.success', {
      tenantId: tenantValidation.tenantId,
      analyticsType,
    });

    metrics.histogram('trust_score.analytics.get.duration', Date.now() - startTime, {
      tenantId: tenantValidation.tenantId,
      analyticsType,
    });

    return NextResponse.json({
      success: true,
      data: analyticsData,
      type: analyticsType,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
        dataFreshness: 'real-time',
      },
    });

  } catch (error: any) {
    logger.error('Trust Score Analytics API GET error:', error);
    
    metrics.increment('trust_score.analytics.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to get trust score analytics',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// POST /api/trust-score/analytics - Generate custom reports
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Authentication & Authorization
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const hasPermission = await authorize(user, 'trust-score:analytics:generate_reports');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse and validate request body
    const body = await request.json();
    const sanitizedBody = sanitizeInput(body);
    
    const validationResult = reportQuerySchema.safeParse(sanitizedBody);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid report request', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Generate report
    const report = await analyticsService.generateReport(tenantValidation.tenantId, validationResult.data);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'trust_score.analytics.generate_report',
      resource: 'trust_score_analytics',
      metadata: { 
        reportType: validationResult.data.reportType,
        format: validationResult.data.format,
        timeframe: validationResult.data.timeframe,
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('trust_score.analytics.report.success', {
      tenantId: tenantValidation.tenantId,
      reportType: validationResult.data.reportType,
    });

    return NextResponse.json({
      success: true,
      data: report,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    }, { status: 201 });

  } catch (error: any) {
    logger.error('Trust Score Analytics Report API error:', error);
    
    metrics.increment('trust_score.analytics.report.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to generate report',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}