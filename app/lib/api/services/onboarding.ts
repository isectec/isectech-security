/**
 * Customer Onboarding API Service
 * Production-grade service for automated customer onboarding workflows
 */

import type {
  OnboardingInstance,
  OnboardingFlow,
  OnboardingAnalytics,
  OnboardingProgress,
  CustomerProfile,
  ServiceConfiguration,
  OnboardingStepInstance,
  OnboardingSearchParams,
  OnboardingDashboardData,
  OnboardingApiResponse,
} from '@/types/onboarding';
import { apiClient } from '../client';

export interface CreateOnboardingFlowRequest {
  customerProfile: CustomerProfile;
  serviceConfiguration?: ServiceConfiguration;
  templateId?: string;
  automationEnabled?: boolean;
  assignedCSM?: string;
}

export interface CreateOnboardingFlowResponse {
  flowId: string;
  status: OnboardingInstance['status'];
  nextStep?: OnboardingStepInstance;
  estimatedCompletionTime?: Date;
  createdAt: Date;
}

export interface UpdateOnboardingStepRequest {
  stepId: string;
  status?: OnboardingStepInstance['status'];
  outputs?: Record<string, any>;
  configuration?: Record<string, any>;
  errorMessage?: string;
}

export interface UpdateOnboardingStepResponse {
  stepId: string;
  status: OnboardingStepInstance['status'];
  nextStep?: OnboardingStepInstance;
  flowComplete: boolean;
}

export interface OnboardingFlowResponse {
  flow: OnboardingInstance;
  progress: OnboardingProgress;
  nextActions: string[];
  recommendations: string[];
}

export class OnboardingService {
  
  // Onboarding flow management
  async createOnboardingFlow(request: CreateOnboardingFlowRequest): Promise<CreateOnboardingFlowResponse> {
    const response = await apiClient.post<CreateOnboardingFlowResponse>('/onboarding', request);
    return response.data!;
  }

  async getOnboardingFlow(flowId: string): Promise<OnboardingFlowResponse> {
    const response = await apiClient.get<OnboardingFlowResponse>(`/onboarding/${flowId}`);
    return response.data!;
  }

  async listOnboardingFlows(params?: OnboardingSearchParams): Promise<{
    data: OnboardingInstance[];
    pagination: {
      total: number;
      offset: number;
      limit: number;
      hasMore: boolean;
    };
  }> {
    const response = await apiClient.get<{
      data: OnboardingInstance[];
      pagination: {
        total: number;
        offset: number;
        limit: number;
        hasMore: boolean;
      };
    }>('/onboarding', { params });
    return response.data!;
  }

  async updateOnboardingFlow(
    flowId: string,
    updates: {
      action: 'update_step' | 'retry_step' | 'pause' | 'resume' | 'cancel';
      stepId?: string;
      status?: OnboardingStepInstance['status'];
      outputs?: Record<string, any>;
      configuration?: Record<string, any>;
      errorMessage?: string;
    }
  ): Promise<UpdateOnboardingStepResponse> {
    const response = await apiClient.patch<UpdateOnboardingStepResponse>(`/onboarding/${flowId}`, updates);
    return response.data!;
  }

  async cancelOnboardingFlow(flowId: string): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.delete<{ success: boolean; message: string }>(`/onboarding/${flowId}`);
    return response.data!;
  }

  // Step management
  async updateOnboardingStep(
    flowId: string, 
    request: UpdateOnboardingStepRequest
  ): Promise<UpdateOnboardingStepResponse> {
    return this.updateOnboardingFlow(flowId, {
      action: 'update_step',
      ...request,
    });
  }

  async retryOnboardingStep(flowId: string, stepId: string): Promise<UpdateOnboardingStepResponse> {
    return this.updateOnboardingFlow(flowId, {
      action: 'retry_step',
      stepId,
    });
  }

  async pauseOnboardingFlow(flowId: string): Promise<UpdateOnboardingStepResponse> {
    return this.updateOnboardingFlow(flowId, {
      action: 'pause',
    });
  }

  async resumeOnboardingFlow(flowId: string): Promise<UpdateOnboardingStepResponse> {
    return this.updateOnboardingFlow(flowId, {
      action: 'resume',
    });
  }

  // Analytics and reporting
  async getOnboardingAnalytics(params?: {
    startDate?: Date;
    endDate?: Date;
    customerType?: string;
    serviceTier?: string;
    includeDetails?: boolean;
  }): Promise<{
    analytics: OnboardingAnalytics;
    metadata: {
      tenantId: string;
      generatedAt: Date;
      timeRange: { startDate: Date; endDate: Date };
      filters: {
        customerType: string | null;
        serviceTier: string | null;
      };
      dataPoints: number;
    };
  }> {
    const response = await apiClient.get<{
      analytics: OnboardingAnalytics;
      metadata: {
        tenantId: string;
        generatedAt: Date;
        timeRange: { startDate: Date; endDate: Date };
        filters: {
          customerType: string | null;
          serviceTier: string | null;
        };
        dataPoints: number;
      };
    }>('/onboarding/analytics', { params });
    return response.data!;
  }

  async trackOnboardingEvent(eventType: string, data: Record<string, any>): Promise<{
    success: boolean;
    eventType: string;
    processedAt: Date;
    tenantId: string;
  }> {
    const response = await apiClient.post<{
      success: boolean;
      eventType: string;
      processedAt: Date;
      tenantId: string;
    }>('/onboarding/analytics', { eventType, data });
    return response.data!;
  }

  // Dashboard data aggregation
  async getOnboardingDashboardData(params?: {
    limit?: number;
    includePending?: boolean;
    includeAnalytics?: boolean;
  }): Promise<OnboardingDashboardData> {
    const limit = params?.limit || 10;
    
    // Fetch multiple data sources in parallel
    const [flows, analytics] = await Promise.all([
      this.listOnboardingFlows({
        sort: { field: 'createdAt', direction: 'desc' },
        pagination: { page: 1, limit: limit * 2 },
      }),
      params?.includeAnalytics ? this.getOnboardingAnalytics({
        startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
        endDate: new Date(),
        includeDetails: false,
      }) : null,
    ]);

    // Separate flows by status
    const activeFlows = flows.data
      .filter(flow => ['in-progress', 'pending-approval'].includes(flow.status))
      .slice(0, limit);

    const recentCompletions = flows.data
      .filter(flow => flow.status === 'completed')
      .slice(0, limit);

    // Generate alerts from failed flows and blockers
    const alerts = flows.data
      .filter(flow => flow.errors.length > 0 || flow.status === 'failed')
      .map(flow => ({
        id: `alert_${flow.id}`,
        type: 'validation_error' as const,
        severity: flow.status === 'failed' ? 'critical' as const : 'medium' as const,
        title: `Onboarding Issue: ${flow.customData?.customerProfile?.companyName || 'Unknown Company'}`,
        description: flow.errors[0]?.message || 'Onboarding workflow encountered issues',
        affectedSteps: flow.stepInstances
          .filter(step => step.status === 'failed')
          .map(step => step.stepId),
        createdAt: flow.errors[0]?.createdAt || flow.updatedAt,
        resolvedAt: flow.errors[0]?.resolvedAt,
        assignedTo: flow.metadata?.customerSuccessManager,
        resolutionNotes: flow.errors[0]?.resolution,
      }))
      .slice(0, limit);

    // Generate upcoming milestones
    const upcomingMilestones = activeFlows
      .filter(flow => flow.estimatedCompletionTime && flow.estimatedCompletionTime > new Date())
      .map(flow => ({
        id: `milestone_${flow.id}`,
        name: 'Onboarding Completion',
        description: `${flow.customData?.customerProfile?.companyName || 'Customer'} onboarding completion`,
        targetDate: flow.estimatedCompletionTime,
        status: 'pending' as const,
        requiredSteps: flow.stepInstances
          .filter(step => step.status === 'pending')
          .map(step => step.stepId),
        completedSteps: flow.stepInstances
          .filter(step => step.status === 'completed')
          .map(step => step.stepId),
      }))
      .sort((a, b) => (a.targetDate?.getTime() || 0) - (b.targetDate?.getTime() || 0))
      .slice(0, limit);

    return {
      activeFlows,
      recentCompletions,
      analytics: analytics?.analytics,
      alerts,
      upcomingMilestones,
    };
  }

  // Template management
  async getOnboardingTemplates(params?: {
    customerType?: string;
    serviceTier?: string;
    active?: boolean;
  }): Promise<any[]> {
    // Mock templates - in production, this would fetch from API
    return [
      {
        id: 'default-enterprise-workflow',
        name: 'Enterprise Customer Onboarding',
        description: 'Comprehensive onboarding for enterprise customers with full compliance and custom integrations',
        customerType: 'enterprise',
        serviceTier: 'enterprise',
        estimatedDuration: 180, // 3 hours
        stepCount: 7,
        automationLevel: 85,
        isActive: true,
        usage: {
          timesUsed: 45,
          successRate: 89,
          averageCompletionTime: 167,
        },
      },
      {
        id: 'mid-market-workflow',
        name: 'Mid-Market Customer Onboarding',
        description: 'Streamlined onboarding for mid-market customers with essential features and basic compliance',
        customerType: 'mid-market',
        serviceTier: 'professional',
        estimatedDuration: 120, // 2 hours
        stepCount: 5,
        automationLevel: 92,
        isActive: true,
        usage: {
          timesUsed: 78,
          successRate: 93,
          averageCompletionTime: 115,
        },
      },
      {
        id: 'small-business-workflow',
        name: 'Small Business Quick Start',
        description: 'Fast-track onboarding for small businesses with automated setup and minimal manual intervention',
        customerType: 'small-business',
        serviceTier: 'basic',
        estimatedDuration: 60, // 1 hour
        stepCount: 4,
        automationLevel: 96,
        isActive: true,
        usage: {
          timesUsed: 156,
          successRate: 96,
          averageCompletionTime: 58,
        },
      },
    ].filter(template => {
      if (params?.customerType && template.customerType !== params.customerType) return false;
      if (params?.serviceTier && template.serviceTier !== params.serviceTier) return false;
      if (params?.active !== undefined && template.isActive !== params.active) return false;
      return true;
    });
  }

  // Utility methods
  async validateCustomerProfile(profile: Partial<CustomerProfile>): Promise<{
    isValid: boolean;
    errors: { field: string; message: string }[];
    warnings: { field: string; message: string }[];
  }> {
    // Mock validation - in production, this would use validation service
    const errors: { field: string; message: string }[] = [];
    const warnings: { field: string; message: string }[] = [];

    if (!profile.companyName?.trim()) {
      errors.push({ field: 'companyName', message: 'Company name is required' });
    }

    if (!profile.primaryContact?.email || !/\S+@\S+\.\S+/.test(profile.primaryContact.email)) {
      errors.push({ field: 'primaryContact.email', message: 'Valid email address is required' });
    }

    if (!profile.industry?.trim()) {
      warnings.push({ field: 'industry', message: 'Industry information helps optimize the onboarding process' });
    }

    if (!profile.securityRequirements?.complianceFrameworks?.length) {
      warnings.push({ field: 'securityRequirements.complianceFrameworks', message: 'Compliance frameworks should be specified for enterprise customers' });
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
    };
  }

  async estimateOnboardingDuration(
    customerType: string,
    serviceTier: string,
    selectedServices: string[]
  ): Promise<{
    estimatedMinutes: number;
    estimatedHours: number;
    breakdown: { step: string; duration: number; automated: boolean }[];
    automationLevel: number;
  }> {
    // Mock estimation logic - in production, use ML model or rules engine
    const baseTimeByTier: Record<string, number> = {
      basic: 60,
      professional: 120,
      enterprise: 180,
      'enterprise-plus': 240,
    };

    const serviceTimeMultiplier: Record<string, number> = {
      'threat-detection': 1.2,
      'vulnerability-scanning': 1.1,
      'compliance-monitoring': 1.5,
      'incident-response': 1.3,
      'forensics': 1.4,
      'user-behavior-analytics': 1.2,
      'network-monitoring': 1.1,
    };

    let baseTime = baseTimeByTier[serviceTier] || 120;
    let multiplier = 1.0;

    selectedServices.forEach(service => {
      multiplier *= (serviceTimeMultiplier[service] || 1.0);
    });

    const estimatedMinutes = Math.round(baseTime * multiplier);
    const automationLevel = customerType === 'enterprise' ? 75 : 
                           customerType === 'mid-market' ? 85 : 
                           customerType === 'small-business' ? 95 : 90;

    const breakdown = [
      { step: 'Account Provisioning', duration: Math.round(estimatedMinutes * 0.1), automated: true },
      { step: 'Identity Setup', duration: Math.round(estimatedMinutes * 0.15), automated: true },
      { step: 'Service Configuration', duration: Math.round(estimatedMinutes * 0.35), automated: customerType !== 'enterprise' },
      { step: 'Compliance Setup', duration: Math.round(estimatedMinutes * 0.25), automated: false },
      { step: 'Training Assignment', duration: Math.round(estimatedMinutes * 0.05), automated: true },
      { step: 'Welcome Communications', duration: Math.round(estimatedMinutes * 0.05), automated: true },
      { step: 'Guided Tour', duration: Math.round(estimatedMinutes * 0.05), automated: false },
    ];

    return {
      estimatedMinutes,
      estimatedHours: Math.round(estimatedMinutes / 60 * 10) / 10,
      breakdown,
      automationLevel,
    };
  }

  // Real-time updates
  subscribeToOnboardingUpdates(
    flowId: string,
    onUpdate: (update: { 
      type: 'step_completed' | 'step_failed' | 'flow_completed' | 'error_occurred';
      data: any;
    }) => void
  ): () => void {
    // Mock WebSocket subscription - in production, use actual WebSocket
    const interval = setInterval(async () => {
      try {
        const flow = await this.getOnboardingFlow(flowId);
        // Simulate random updates for demo
        if (Math.random() < 0.1) { // 10% chance of update
          onUpdate({
            type: 'step_completed',
            data: { flow },
          });
        }
      } catch (error) {
        console.error('Error fetching onboarding updates:', error);
      }
    }, 5000); // Check every 5 seconds

    return () => clearInterval(interval);
  }
}

export const onboardingService = new OnboardingService();
export default onboardingService;