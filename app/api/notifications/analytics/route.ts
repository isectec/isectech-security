/**
 * Notification Analytics API
 * Provides comprehensive analytics and insights for notification performance
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
    'sent', 'delivered', 'read', 'clicked', 'failed',
    'delivery_rate', 'read_rate', 'click_rate', 'bounce_rate'
  ])).optional(),
  groupBy: z.array(z.enum([
    'type', 'priority', 'channel', 'template', 'device_type', 'user_segment'
  ])).optional(),
  filters: z.object({
    type: z.array(z.enum(['security', 'alert', 'info', 'warning', 'error'])).optional(),
    priority: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
    channel: z.array(z.enum(['push', 'email', 'sms', 'webhook'])).optional(),
    templateId: z.array(z.string()).optional(),
    deviceType: z.array(z.enum(['mobile', 'desktop', 'tablet'])).optional(),
    userSegment: z.array(z.string()).optional(),
  }).optional(),
  includeComparisons: z.boolean().default(false),
  includePredictions: z.boolean().default(false),
});

const performanceQuerySchema = z.object({
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  includeLatency: z.boolean().default(true),
  includeThroughput: z.boolean().default(true),
  includeErrors: z.boolean().default(true),
  includeChannelBreakdown: z.boolean().default(true),
});

interface AnalyticsService {
  getOverviewMetrics(tenantId: string, params: any): Promise<any>;
  getDetailedAnalytics(tenantId: string, params: any): Promise<any>;
  getPerformanceMetrics(tenantId: string, params: any): Promise<any>;
  getUserEngagementAnalytics(tenantId: string, params: any): Promise<any>;
  getChannelEfficiencyAnalytics(tenantId: string, params: any): Promise<any>;
  getTrendAnalysis(tenantId: string, params: any): Promise<any>;
  generateInsights(tenantId: string, params: any): Promise<any>;
}

// Mock analytics service
class MockAnalyticsService implements AnalyticsService {
  private generateMockTimeSeries(startDate: string, endDate: string, granularity: string): any[] {
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
        sent: Math.floor(Math.random() * 1000) + 100,
        delivered: Math.floor(Math.random() * 900) + 90,
        read: Math.floor(Math.random() * 600) + 50,
        clicked: Math.floor(Math.random() * 200) + 10,
        failed: Math.floor(Math.random() * 50),
      });
      current = new Date(current.getTime() + increment);
    }
    
    return data;
  }

  async getOverviewMetrics(tenantId: string, params: any) {
    const timeSeries = this.generateMockTimeSeries(params.startDate, params.endDate, params.granularity);
    
    const totals = timeSeries.reduce((acc, point) => ({
      sent: acc.sent + point.sent,
      delivered: acc.delivered + point.delivered,
      read: acc.read + point.read,
      clicked: acc.clicked + point.clicked,
      failed: acc.failed + point.failed,
    }), { sent: 0, delivered: 0, read: 0, clicked: 0, failed: 0 });

    const deliveryRate = totals.sent > 0 ? (totals.delivered / totals.sent) * 100 : 0;
    const readRate = totals.delivered > 0 ? (totals.read / totals.delivered) * 100 : 0;
    const clickRate = totals.read > 0 ? (totals.clicked / totals.read) * 100 : 0;

    return {
      overview: {
        ...totals,
        deliveryRate: Math.round(deliveryRate * 100) / 100,
        readRate: Math.round(readRate * 100) / 100,
        clickRate: Math.round(clickRate * 100) / 100,
      },
      timeSeries,
      period: {
        startDate: params.startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        endDate: params.endDate || new Date().toISOString(),
        granularity: params.granularity,
      },
    };
  }

  async getDetailedAnalytics(tenantId: string, params: any) {
    const baseMetrics = await this.getOverviewMetrics(tenantId, params);
    
    const byType = {
      security: { sent: 450, delivered: 440, read: 380, clicked: 120 },
      alert: { sent: 320, delivered: 310, read: 250, clicked: 80 },
      info: { sent: 280, delivered: 270, read: 180, clicked: 45 },
      warning: { sent: 200, delivered: 190, read: 140, clicked: 35 },
      error: { sent: 150, delivered: 145, read: 130, clicked: 40 },
    };

    const byPriority = {
      critical: { sent: 200, delivered: 195, read: 180, clicked: 90 },
      high: { sent: 350, delivered: 340, read: 290, clicked: 110 },
      medium: { sent: 500, delivered: 480, read: 350, clicked: 85 },
      low: { sent: 350, delivered: 340, read: 260, clicked: 35 },
    };

    const byChannel = {
      push: { sent: 800, delivered: 750, read: 600, clicked: 200 },
      email: { sent: 400, delivered: 380, read: 280, clicked: 90 },
      sms: { sent: 150, delivered: 145, read: 120, clicked: 30 },
      webhook: { sent: 50, delivered: 48, read: 45, clicked: 0 },
    };

    return {
      ...baseMetrics,
      breakdowns: {
        byType,
        byPriority,
        byChannel,
      },
      topPerformingTemplates: [
        { id: '1', name: 'Security Alert', sent: 450, deliveryRate: 97.8, readRate: 86.4 },
        { id: '2', name: 'System Update', sent: 320, deliveryRate: 96.9, readRate: 80.6 },
        { id: '3', name: 'Maintenance Notice', sent: 280, deliveryRate: 96.4, readRate: 66.7 },
      ],
      deviceBreakdown: {
        mobile: { sent: 720, delivered: 690, read: 580, clicked: 220 },
        desktop: { sent: 480, delivered: 460, read: 340, clicked: 80 },
        tablet: { sent: 200, delivered: 195, read: 160, clicked: 20 },
      },
    };
  }

  async getPerformanceMetrics(tenantId: string, params: any) {
    return {
      latency: {
        average: 145, // milliseconds
        p95: 280,
        p99: 450,
        breakdown: {
          push: { average: 120, p95: 250, p99: 400 },
          email: { average: 180, p95: 320, p99: 500 },
          sms: { average: 240, p95: 450, p99: 680 },
          webhook: { average: 95, p95: 180, p99: 280 },
        },
      },
      throughput: {
        current: 1250, // notifications per second
        peak: 2100,
        average: 850,
        timeline: this.generateMockTimeSeries(params.startDate, params.endDate, 'hour')
          .map(point => ({
            timestamp: point.timestamp,
            throughput: Math.floor(Math.random() * 1000) + 500,
          })),
      },
      errors: {
        rate: 2.3, // percentage
        count: 45,
        breakdown: {
          timeout: 18,
          connection_failed: 12,
          invalid_token: 8,
          rate_limited: 5,
          other: 2,
        },
      },
      availability: {
        uptime: 99.95, // percentage
        incidents: [
          {
            timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            duration: 180, // seconds
            cause: 'Database connection timeout',
            impact: 'Low',
          },
        ],
      },
    };
  }

  async getUserEngagementAnalytics(tenantId: string, params: any) {
    return {
      activeUsers: {
        total: 12450,
        daily: 3200,
        weekly: 8900,
        monthly: 12450,
      },
      engagementRates: {
        overall: 68.5,
        byUserSegment: {
          'power_users': 85.2,
          'regular_users': 72.1,
          'new_users': 45.8,
          'inactive_users': 25.3,
        },
        byDeviceType: {
          mobile: 75.2,
          desktop: 65.8,
          tablet: 58.1,
        },
      },
      behaviorPatterns: {
        preferredChannels: {
          push: 65.2,
          email: 28.7,
          sms: 5.1,
          webhook: 1.0,
        },
        optimalSendTimes: {
          weekdays: {
            peak: '14:00',
            good: ['09:00', '11:00', '16:00'],
            poor: ['01:00', '05:00', '23:00'],
          },
          weekends: {
            peak: '10:00',
            good: ['11:00', '15:00', '19:00'],
            poor: ['03:00', '07:00', '22:00'],
          },
        },
        retentionAnalysis: {
          day1: 92.5,
          day7: 76.8,
          day30: 54.2,
          day90: 38.7,
        },
      },
    };
  }

  async getChannelEfficiencyAnalytics(tenantId: string, params: any) {
    return {
      channelComparison: {
        push: {
          deliveryRate: 93.8,
          readRate: 76.5,
          clickRate: 25.2,
          cost: 0.0012, // per notification
          latency: 120,
          reliability: 99.2,
        },
        email: {
          deliveryRate: 95.0,
          readRate: 73.7,
          clickRate: 22.8,
          cost: 0.0025,
          latency: 180,
          reliability: 98.8,
        },
        sms: {
          deliveryRate: 96.7,
          readRate: 80.0,
          clickRate: 20.0,
          cost: 0.0450,
          latency: 240,
          reliability: 99.5,
        },
        webhook: {
          deliveryRate: 96.0,
          readRate: 93.8,
          clickRate: 0,
          cost: 0.0001,
          latency: 95,
          reliability: 99.8,
        },
      },
      recommendations: [
        {
          type: 'optimization',
          channel: 'push',
          message: 'Push notifications show highest engagement - consider increasing usage for time-sensitive alerts',
          priority: 'medium',
          impact: 'Potential 15% increase in engagement',
        },
        {
          type: 'cost_optimization',
          channel: 'sms',
          message: 'SMS has highest cost - consider using for critical notifications only',
          priority: 'high',
          impact: 'Potential 30% cost reduction',
        },
      ],
    };
  }

  async getTrendAnalysis(tenantId: string, params: any) {
    return {
      trends: {
        volumeGrowth: {
          monthOverMonth: 12.5, // percentage
          yearOverYear: 145.2,
          forecast: {
            nextMonth: 15800,
            nextQuarter: 52000,
            nextYear: 195000,
          },
        },
        engagementTrends: {
          direction: 'increasing',
          rate: 3.2, // percentage per month
          factors: [
            'Improved personalization',
            'Better send time optimization',
            'Reduced notification fatigue',
          ],
        },
        seasonalPatterns: {
          weekday: {
            monday: 1.2,
            tuesday: 1.0,
            wednesday: 0.9,
            thursday: 1.1,
            friday: 1.3,
            saturday: 0.7,
            sunday: 0.6,
          },
          hourly: {
            peak: { hour: 14, multiplier: 2.1 },
            trough: { hour: 3, multiplier: 0.1 },
          },
        },
      },
      anomalies: [
        {
          timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
          type: 'delivery_rate_drop',
          severity: 'medium',
          description: 'Delivery rate dropped by 15% due to upstream service issues',
          duration: 45, // minutes
          resolution: 'Auto-resolved when upstream service recovered',
        },
      ],
    };
  }

  async generateInsights(tenantId: string, params: any) {
    return {
      insights: [
        {
          type: 'performance',
          title: 'Peak Engagement Window Identified',
          description: 'Notifications sent between 2-4 PM show 40% higher engagement rates',
          recommendation: 'Schedule non-urgent notifications during peak hours',
          confidence: 0.92,
          impact: 'high',
        },
        {
          type: 'user_behavior',
          title: 'Mobile Users Show Higher Engagement',
          description: 'Mobile users are 25% more likely to interact with notifications',
          recommendation: 'Optimize notification content for mobile viewing',
          confidence: 0.88,
          impact: 'medium',
        },
        {
          type: 'content_optimization',
          title: 'Shorter Messages Perform Better',
          description: 'Notifications under 50 characters have 30% higher read rates',
          recommendation: 'Use concise, action-oriented language',
          confidence: 0.85,
          impact: 'medium',
        },
      ],
      actionItems: [
        {
          priority: 'high',
          action: 'Implement intelligent send time optimization',
          estimatedImpact: '25% increase in engagement',
          effort: 'medium',
          timeline: '2-3 weeks',
        },
        {
          priority: 'medium',
          action: 'Create mobile-optimized notification templates',
          estimatedImpact: '15% increase in mobile engagement',
          effort: 'low',
          timeline: '1 week',
        },
      ],
    };
  }
}

const analyticsService = new MockAnalyticsService();

// GET /api/notifications/analytics - Get comprehensive analytics
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 100,
      keyGenerator: (req) => `analytics:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:analytics:read');
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

    const query = validationResult.data;

    // Get analytics type from query
    const analyticsType = searchParams.get('type') || 'overview';
    
    let analyticsData;
    
    switch (analyticsType) {
      case 'overview':
        analyticsData = await analyticsService.getOverviewMetrics(tenantValidation.tenantId, query);
        break;
      case 'detailed':
        analyticsData = await analyticsService.getDetailedAnalytics(tenantValidation.tenantId, query);
        break;
      case 'performance':
        analyticsData = await analyticsService.getPerformanceMetrics(tenantValidation.tenantId, query);
        break;
      case 'engagement':
        analyticsData = await analyticsService.getUserEngagementAnalytics(tenantValidation.tenantId, query);
        break;
      case 'channels':
        analyticsData = await analyticsService.getChannelEfficiencyAnalytics(tenantValidation.tenantId, query);
        break;
      case 'trends':
        analyticsData = await analyticsService.getTrendAnalysis(tenantValidation.tenantId, query);
        break;
      case 'insights':
        analyticsData = await analyticsService.generateInsights(tenantValidation.tenantId, query);
        break;
      default:
        return NextResponse.json(
          { error: 'Invalid analytics type. Valid types: overview, detailed, performance, engagement, channels, trends, insights' },
          { status: 400 }
        );
    }

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'analytics.view',
      resource: 'notification_analytics',
      metadata: { 
        analyticsType,
        query: validationResult.data,
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('analytics.api.get.success', {
      tenantId: tenantValidation.tenantId,
      analyticsType,
    });

    metrics.histogram('analytics.api.get.duration', Date.now() - startTime, {
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
        dataFreshness: 'real-time', // In production, indicate data freshness
      },
    });

  } catch (error: any) {
    logger.error('Analytics API GET error:', error);
    
    metrics.increment('analytics.api.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to get analytics',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}