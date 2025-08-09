/**
 * Onboarding Analytics API Routes
 * Production-grade analytics for customer onboarding workflows
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import type { OnboardingAnalytics, CustomerType, ServiceTier } from '@/types/onboarding';

// Mock analytics data - replace with actual database queries
const generateMockAnalytics = (timeRange: { startDate: Date; endDate: Date }): OnboardingAnalytics => {
  const daysDiff = Math.ceil((timeRange.endDate.getTime() - timeRange.startDate.getTime()) / (1000 * 60 * 60 * 24));
  const totalFlows = Math.floor(daysDiff * 2.5); // ~2.5 onboardings per day
  const completedFlows = Math.floor(totalFlows * 0.75); // 75% completion rate
  const failedFlows = Math.floor(totalFlows * 0.15); // 15% failure rate
  const inProgressFlows = totalFlows - completedFlows - failedFlows;

  return {
    timeRange,
    totalFlows,
    completedFlows,
    inProgressFlows,
    failedFlows,
    averageCompletionTime: 145, // 2.4 hours
    completionRate: Math.round((completedFlows / totalFlows) * 100),
    stepAnalytics: [
      {
        stepType: 'account-provisioning',
        completionRate: 98.5,
        averageTime: 12.3,
        failureRate: 1.5,
        commonErrors: ['Domain validation failed', 'SSO configuration timeout'],
        automationRate: 95.0,
      },
      {
        stepType: 'identity-setup',
        completionRate: 94.2,
        averageTime: 18.7,
        failureRate: 5.8,
        commonErrors: ['LDAP connection failed', 'Invalid certificate'],
        automationRate: 88.5,
      },
      {
        stepType: 'service-configuration',
        completionRate: 89.1,
        averageTime: 25.4,
        failureRate: 10.9,
        commonErrors: ['Network connectivity issues', 'Configuration validation failed'],
        automationRate: 82.3,
      },
      {
        stepType: 'compliance-validation',
        completionRate: 91.7,
        averageTime: 31.2,
        failureRate: 8.3,
        commonErrors: ['Policy conflicts', 'Compliance framework mismatch'],
        automationRate: 76.8,
      },
      {
        stepType: 'training-assignment',
        completionRate: 96.8,
        averageTime: 3.1,
        failureRate: 3.2,
        commonErrors: ['Course not available', 'User email invalid'],
        automationRate: 99.2,
      },
      {
        stepType: 'welcome-communication',
        completionRate: 99.1,
        averageTime: 1.8,
        failureRate: 0.9,
        commonErrors: ['Email delivery failed'],
        automationRate: 100.0,
      },
      {
        stepType: 'guided-tour',
        completionRate: 87.4,
        averageTime: 35.6,
        failureRate: 12.6,
        commonErrors: ['Scheduling conflicts', 'Customer unavailable'],
        automationRate: 45.2,
      },
    ],
    commonBlockers: [
      {
        blockerType: 'Domain validation timeout',
        frequency: 12,
        averageResolutionTime: 45,
        impactScore: 8.5,
        mostAffectedSteps: ['account-provisioning'],
      },
      {
        blockerType: 'SSO configuration issues',
        frequency: 18,
        averageResolutionTime: 67,
        impactScore: 7.8,
        mostAffectedSteps: ['identity-setup'],
      },
      {
        blockerType: 'Network connectivity problems',
        frequency: 9,
        averageResolutionTime: 89,
        impactScore: 9.1,
        mostAffectedSteps: ['service-configuration', 'compliance-validation'],
      },
      {
        blockerType: 'Customer approval delays',
        frequency: 25,
        averageResolutionTime: 180,
        impactScore: 6.2,
        mostAffectedSteps: ['compliance-validation', 'guided-tour'],
      },
    ],
    byCustomerType: {
      enterprise: {
        total: Math.floor(totalFlows * 0.4),
        completed: Math.floor(completedFlows * 0.45),
        averageTime: 165,
        completionRate: 82,
      },
      'mid-market': {
        total: Math.floor(totalFlows * 0.35),
        completed: Math.floor(completedFlows * 0.32),
        averageTime: 135,
        completionRate: 78,
      },
      'small-business': {
        total: Math.floor(totalFlows * 0.2),
        completed: Math.floor(completedFlows * 0.18),
        averageTime: 95,
        completionRate: 85,
      },
      individual: {
        total: Math.floor(totalFlows * 0.05),
        completed: Math.floor(completedFlows * 0.05),
        averageTime: 65,
        completionRate: 92,
      },
    },
    byServiceTier: {
      basic: {
        total: Math.floor(totalFlows * 0.25),
        completed: Math.floor(completedFlows * 0.22),
        averageTime: 85,
        completionRate: 88,
      },
      professional: {
        total: Math.floor(totalFlows * 0.35),
        completed: Math.floor(completedFlows * 0.33),
        averageTime: 125,
        completionRate: 82,
      },
      enterprise: {
        total: Math.floor(totalFlows * 0.3),
        completed: Math.floor(completedFlows * 0.32),
        averageTime: 175,
        completionRate: 76,
      },
      'enterprise-plus': {
        total: Math.floor(totalFlows * 0.1),
        completed: Math.floor(completedFlows * 0.13),
        averageTime: 245,
        completionRate: 71,
      },
    },
    trends: {
      period: 'daily',
      data: Array.from({ length: Math.min(daysDiff, 30) }, (_, i) => {
        const date = new Date(timeRange.startDate);
        date.setDate(date.getDate() + i);
        
        const dailyStarted = Math.floor(Math.random() * 5) + 1;
        const dailyCompleted = Math.floor(dailyStarted * (0.6 + Math.random() * 0.3));
        const dailyFailed = Math.floor((dailyStarted - dailyCompleted) * (0.5 + Math.random() * 0.4));
        
        return {
          date,
          started: dailyStarted,
          completed: dailyCompleted,
          failed: dailyFailed,
          averageTime: 120 + Math.floor(Math.random() * 60),
        };
      }),
    },
    dropoffAnalysis: [
      {
        stepId: 'service-configuration',
        stepName: 'Service Configuration',
        dropoffCount: Math.floor(totalFlows * 0.08),
        dropoffRate: 8.0,
        topReasons: [
          'Complex network requirements',
          'Integration compatibility issues',
          'Resource allocation constraints',
        ],
      },
      {
        stepId: 'compliance-validation',
        stepName: 'Compliance Setup',
        dropoffCount: Math.floor(totalFlows * 0.06),
        dropoffRate: 6.0,
        topReasons: [
          'Regulatory approval pending',
          'Policy review required',
          'Additional documentation needed',
        ],
      },
      {
        stepId: 'guided-tour',
        stepName: 'Platform Tour',
        dropoffCount: Math.floor(totalFlows * 0.04),
        dropoffRate: 4.0,
        topReasons: [
          'Scheduling conflicts',
          'Customer requested postponement',
          'Technical difficulties',
        ],
      },
    ],
    customerFeedback: {
      averageRating: 4.3,
      totalResponses: Math.floor(completedFlows * 0.65), // 65% response rate
      feedback: [
        {
          rating: 5,
          comment: 'Smooth and efficient onboarding process. Very impressed with the automation.',
          timestamp: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
        },
        {
          rating: 4,
          comment: 'Good overall experience, though some steps took longer than expected.',
          timestamp: new Date(Date.now() - Math.random() * 14 * 24 * 60 * 60 * 1000),
        },
        {
          rating: 3,
          comment: 'Process was okay but needed more guidance on compliance requirements.',
          timestamp: new Date(Date.now() - Math.random() * 21 * 24 * 60 * 60 * 1000),
        },
        {
          rating: 5,
          comment: 'Excellent support throughout. The training assignments were very helpful.',
          timestamp: new Date(Date.now() - Math.random() * 28 * 24 * 60 * 60 * 1000),
        },
        {
          rating: 4,
          comment: 'Professional process with good communication at each step.',
          timestamp: new Date(Date.now() - Math.random() * 35 * 24 * 60 * 60 * 1000),
        },
      ],
    },
    automationEffectiveness: {
      automatedSteps: Math.floor(totalFlows * 5.2), // Average 5.2 automated steps per flow
      manualSteps: Math.floor(totalFlows * 1.8), // Average 1.8 manual steps per flow
      automationSuccessRate: 87.3,
      timeSavedMinutes: Math.floor(totalFlows * 75), // ~75 minutes saved per flow
      errorReductionRate: 68.5, // 68.5% reduction in human errors
    },
  };
};

async function validateTenantContext(request: NextRequest): Promise<string> {
  const headersList = headers();
  const tenantId = headersList.get('x-tenant-id');
  
  if (!tenantId) {
    throw new Error('Missing tenant context');
  }
  
  return tenantId;
}

// GET /api/onboarding/analytics - Get onboarding analytics
export async function GET(request: NextRequest) {
  try {
    const tenantId = await validateTenantContext(request);
    const { searchParams } = new URL(request.url);
    
    // Parse query parameters
    const startDate = searchParams.get('startDate') 
      ? new Date(searchParams.get('startDate')!)
      : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // Default: 30 days ago
      
    const endDate = searchParams.get('endDate')
      ? new Date(searchParams.get('endDate')!)
      : new Date(); // Default: now
      
    const includeDetails = searchParams.get('includeDetails') === 'true';
    const customerType = searchParams.get('customerType') as CustomerType;
    const serviceTier = searchParams.get('serviceTier') as ServiceTier;
    
    // Validate date range
    if (startDate >= endDate) {
      return NextResponse.json(
        { error: 'Invalid date range: startDate must be before endDate' },
        { status: 400 }
      );
    }
    
    const maxDays = 365; // Maximum 1 year of data
    const daysDiff = Math.ceil((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));
    if (daysDiff > maxDays) {
      return NextResponse.json(
        { error: `Date range too large. Maximum ${maxDays} days allowed.` },
        { status: 400 }
      );
    }
    
    // Generate analytics data
    let analytics = generateMockAnalytics({ startDate, endDate });
    
    // Apply filters
    if (customerType) {
      // Filter analytics by customer type
      const typeData = analytics.byCustomerType[customerType];
      if (typeData) {
        const ratio = typeData.total / analytics.totalFlows;
        analytics.totalFlows = typeData.total;
        analytics.completedFlows = typeData.completed;
        analytics.failedFlows = Math.floor(typeData.total * 0.15);
        analytics.inProgressFlows = typeData.total - typeData.completed - analytics.failedFlows;
        analytics.averageCompletionTime = typeData.averageTime;
        analytics.completionRate = typeData.completionRate;
        
        // Adjust other metrics proportionally
        analytics.commonBlockers = analytics.commonBlockers.map(blocker => ({
          ...blocker,
          frequency: Math.floor(blocker.frequency * ratio),
        }));
        
        analytics.dropoffAnalysis = analytics.dropoffAnalysis.map(dropoff => ({
          ...dropoff,
          dropoffCount: Math.floor(dropoff.dropoffCount * ratio),
        }));
      }
    }
    
    if (serviceTier) {
      // Similar filtering logic for service tier
      const tierData = analytics.byServiceTier[serviceTier];
      if (tierData) {
        const ratio = tierData.total / analytics.totalFlows;
        analytics.totalFlows = tierData.total;
        analytics.completedFlows = tierData.completed;
        analytics.averageCompletionTime = tierData.averageTime;
        analytics.completionRate = tierData.completionRate;
        
        // Adjust other metrics
        analytics.automationEffectiveness.automatedSteps = Math.floor(
          analytics.automationEffectiveness.automatedSteps * ratio
        );
        analytics.automationEffectiveness.manualSteps = Math.floor(
          analytics.automationEffectiveness.manualSteps * ratio
        );
        analytics.automationEffectiveness.timeSavedMinutes = Math.floor(
          analytics.automationEffectiveness.timeSavedMinutes * ratio
        );
      }
    }
    
    // Remove sensitive details if not requested
    if (!includeDetails) {
      analytics.customerFeedback.feedback = analytics.customerFeedback.feedback.slice(0, 3);
      analytics.trends.data = analytics.trends.data.slice(-7); // Last 7 days only
    }
    
    return NextResponse.json({
      analytics,
      metadata: {
        tenantId,
        generatedAt: new Date(),
        timeRange: { startDate, endDate },
        filters: {
          customerType: customerType || null,
          serviceTier: serviceTier || null,
        },
        dataPoints: analytics.totalFlows,
      },
    });
    
  } catch (error) {
    console.error('Error generating onboarding analytics:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// POST /api/onboarding/analytics - Update analytics data (for real-time updates)
export async function POST(request: NextRequest) {
  try {
    const tenantId = await validateTenantContext(request);
    const body = await request.json();
    
    // In production, this would update metrics in real-time
    // For now, just acknowledge the update
    
    const { eventType, data } = body;
    
    if (!eventType) {
      return NextResponse.json(
        { error: 'Event type is required' },
        { status: 400 }
      );
    }
    
    // Process different event types
    const supportedEvents = [
      'onboarding.instance.started',
      'onboarding.instance.completed',
      'onboarding.instance.failed',
      'onboarding.step.completed',
      'onboarding.step.failed',
      'onboarding.feedback.received',
    ];
    
    if (!supportedEvents.includes(eventType)) {
      return NextResponse.json(
        { error: 'Unsupported event type' },
        { status: 400 }
      );
    }
    
    // Log the event (in production, update actual metrics)
    console.log(`Analytics event received: ${eventType}`, { tenantId, data });
    
    return NextResponse.json({
      success: true,
      eventType,
      processedAt: new Date(),
      tenantId,
    });
    
  } catch (error) {
    console.error('Error processing analytics event:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}