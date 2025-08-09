/**
 * Customer Success Portal API Service for Onboarding Integration
 * Production-grade service for integrating onboarding workflows with customer success resources
 */

import type {
  KnowledgeArticle,
  TrainingCourse,
  TrainingEnrollment,
  SupportTicket,
  CustomerHealthScore,
  OnboardingInstance,
  CustomerProfile,
} from '@/types';
import { apiClient } from '../client';

export interface OnboardingResourcesRequest {
  customerType: string;
  serviceTier: string;
  industry?: string;
  complianceFrameworks?: string[];
  selectedServices?: string[];
  onboardingStage?: 'account-setup' | 'configuration' | 'training' | 'validation' | 'completion';
}

export interface OnboardingResourcesResponse {
  knowledgeArticles: KnowledgeArticle[];
  recommendedTraining: TrainingCourse[];
  quickStartGuides: {
    id: string;
    title: string;
    description: string;
    estimatedDuration: number; // minutes
    steps: {
      id: string;
      title: string;
      description: string;
      order: number;
      isCompleted: boolean;
      requiredRole?: string;
    }[];
  }[];
  supportContacts: {
    type: 'customer-success-manager' | 'technical-account-manager' | 'support-engineer';
    name: string;
    email: string;
    phone?: string;
    timezone: string;
    availability: string;
    avatar?: string;
  }[];
  videoLibrary: {
    id: string;
    title: string;
    description: string;
    duration: number; // seconds
    thumbnailUrl: string;
    videoUrl: string;
    transcriptUrl?: string;
    category: 'platform-overview' | 'feature-deep-dive' | 'best-practices' | 'troubleshooting';
    difficulty: 'beginner' | 'intermediate' | 'advanced';
  }[];
}

export interface OnboardingProgressTrackingRequest {
  onboardingInstanceId: string;
  completedActivities: {
    type: 'article-viewed' | 'video-watched' | 'training-completed' | 'guide-finished';
    resourceId: string;
    completedAt: Date;
    timeSpent?: number; // seconds
    rating?: number; // 1-5
    feedback?: string;
  }[];
}

export interface CustomerSuccessIntegrationData {
  onboardingInstance: OnboardingInstance;
  customerHealthScore: CustomerHealthScore;
  engagementMetrics: {
    knowledgeBaseUsage: {
      articlesViewed: number;
      totalTimeSpent: number; // minutes
      searchQueries: number;
      helpfulnessRating: number;
    };
    trainingProgress: {
      coursesEnrolled: number;
      coursesCompleted: number;
      totalTrainingHours: number;
      avgAssessmentScore: number;
    };
    supportInteraction: {
      ticketsCreated: number;
      avgResolutionTime: number; // hours
      satisfactionRating: number;
      escalationCount: number;
    };
  };
  nextActions: {
    type: 'schedule-training' | 'assign-csm-call' | 'provide-resources' | 'escalate-support';
    priority: 'low' | 'medium' | 'high' | 'urgent';
    title: string;
    description: string;
    dueDate: Date;
    assignedTo?: string;
  }[];
}

export class CustomerSuccessService {
  
  // Resource delivery and recommendations
  async getOnboardingResources(request: OnboardingResourcesRequest): Promise<OnboardingResourcesResponse> {
    const response = await apiClient.post<OnboardingResourcesResponse>('/customer-success/onboarding-resources', request);
    return response.data!;
  }

  async getPersonalizedTrainingPath(customerProfile: CustomerProfile, onboardingStage: string): Promise<{
    trainingPath: {
      id: string;
      title: string;
      description: string;
      courses: TrainingCourse[];
      estimatedDuration: number; // hours
      priority: 'required' | 'recommended' | 'optional';
    }[];
    completionTracking: {
      totalCourses: number;
      completedCourses: number;
      inProgressCourses: number;
      estimatedTimeToComplete: number; // hours
    };
  }> {
    const response = await apiClient.post<{
      trainingPath: {
        id: string;
        title: string;
        description: string;
        courses: TrainingCourse[];
        estimatedDuration: number;
        priority: 'required' | 'recommended' | 'optional';
      }[];
      completionTracking: {
        totalCourses: number;
        completedCourses: number;
        inProgressCourses: number;
        estimatedTimeToComplete: number;
      };
    }>('/customer-success/training-path', {
      customerProfile,
      onboardingStage,
    });
    return response.data!;
  }

  async assignAutomaticTraining(onboardingInstanceId: string, trainingCourseIds: string[]): Promise<{
    enrollments: TrainingEnrollment[];
    dueDate: Date;
    assignedCSM: string;
    notificationsSent: boolean;
  }> {
    const response = await apiClient.post<{
      enrollments: TrainingEnrollment[];
      dueDate: Date;
      assignedCSM: string;
      notificationsSent: boolean;
    }>('/customer-success/assign-training', {
      onboardingInstanceId,
      trainingCourseIds,
    });
    return response.data!;
  }

  // Progress tracking and analytics
  async trackOnboardingProgress(request: OnboardingProgressTrackingRequest): Promise<{
    success: boolean;
    updatedHealthScore: number;
    engagementLevel: 'low' | 'medium' | 'high';
    recommendations: string[];
  }> {
    const response = await apiClient.post<{
      success: boolean;
      updatedHealthScore: number;
      engagementLevel: 'low' | 'medium' | 'high';
      recommendations: string[];
    }>('/customer-success/track-progress', request);
    return response.data!;
  }

  async getCustomerSuccessIntegration(onboardingInstanceId: string): Promise<CustomerSuccessIntegrationData> {
    const response = await apiClient.get<CustomerSuccessIntegrationData>(`/customer-success/integration/${onboardingInstanceId}`);
    return response.data!;
  }

  async updateCustomerHealthScore(customerId: string, onboardingData: {
    completionRate: number;
    timeToValue: number; // days
    engagementScore: number;
    trainingProgress: number;
    supportSatisfaction: number;
  }): Promise<CustomerHealthScore> {
    const response = await apiClient.patch<CustomerHealthScore>(`/customer-success/health-score/${customerId}`, {
      onboardingMetrics: onboardingData,
    });
    return response.data!;
  }

  // Knowledge base integration
  async getContextualHelp(context: {
    currentStep: string;
    customerType: string;
    serviceTier: string;
    userRole?: string;
    previousErrors?: string[];
  }): Promise<{
    articles: KnowledgeArticle[];
    videos: any[];
    faqs: {
      question: string;
      answer: string;
      helpfulCount: number;
    }[];
    relatedTickets: {
      id: string;
      subject: string;
      status: string;
      resolution: string;
      createdAt: Date;
    }[];
  }> {
    const response = await apiClient.post<{
      articles: KnowledgeArticle[];
      videos: any[];
      faqs: {
        question: string;
        answer: string;
        helpfulCount: number;
      }[];
      relatedTickets: {
        id: string;
        subject: string;
        status: string;
        resolution: string;
        createdAt: Date;
      }[];
    }>('/customer-success/contextual-help', context);
    return response.data!;
  }

  async createOnboardingSupportTicket(data: {
    onboardingInstanceId: string;
    subject: string;
    description: string;
    priority: 'low' | 'normal' | 'high' | 'urgent';
    category: 'onboarding-issue' | 'technical-question' | 'training-request' | 'escalation';
    attachments?: File[];
  }): Promise<SupportTicket> {
    const formData = new FormData();
    formData.append('onboardingInstanceId', data.onboardingInstanceId);
    formData.append('subject', data.subject);
    formData.append('description', data.description);
    formData.append('priority', data.priority);
    formData.append('category', data.category);
    
    if (data.attachments) {
      data.attachments.forEach((file, index) => {
        formData.append(`attachments[${index}]`, file);
      });
    }

    const response = await apiClient.post<SupportTicket>('/customer-success/support-ticket', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data!;
  }

  // CSM assignment and communication
  async assignCustomerSuccessManager(onboardingInstanceId: string, csmId?: string): Promise<{
    assignedCSM: {
      id: string;
      name: string;
      email: string;
      phone: string;
      timezone: string;
      specializations: string[];
      avatar?: string;
    };
    introductionScheduled: boolean;
    kickoffMeetingDate: Date;
    communicationPreferences: {
      email: boolean;
      phone: boolean;
      slack: boolean;
      teams: boolean;
    };
  }> {
    const response = await apiClient.post<{
      assignedCSM: {
        id: string;
        name: string;
        email: string;
        phone: string;
        timezone: string;
        specializations: string[];
        avatar?: string;
      };
      introductionScheduled: boolean;
      kickoffMeetingDate: Date;
      communicationPreferences: {
        email: boolean;
        phone: boolean;
        slack: boolean;
        teams: boolean;
      };
    }>('/customer-success/assign-csm', {
      onboardingInstanceId,
      csmId,
    });
    return response.data!;
  }

  async scheduleOnboardingCall(data: {
    onboardingInstanceId: string;
    callType: 'kickoff' | 'training' | 'configuration' | 'go-live' | 'follow-up';
    attendees: string[];
    scheduledAt: Date;
    duration: number; // minutes
    agenda: string[];
    meetingLink?: string;
  }): Promise<{
    meetingId: string;
    invitationsSent: boolean;
    calendarEvents: boolean;
    meetingDetails: {
      link: string;
      dialIn: string;
      passcode: string;
    };
  }> {
    const response = await apiClient.post<{
      meetingId: string;
      invitationsSent: boolean;
      calendarEvents: boolean;
      meetingDetails: {
        link: string;
        dialIn: string;
        passcode: string;
      };
    }>('/customer-success/schedule-call', data);
    return response.data!;
  }

  // White-labeling support for customer success resources
  async getWhiteLabeledResources(tenantId: string, brandingConfig: {
    primaryColor: string;
    logoUrl: string;
    companyName: string;
    customDomain?: string;
  }): Promise<{
    brandedKnowledgeBase: {
      baseUrl: string;
      customCss: string;
      logoPlacement: string;
    };
    brandedTrainingPortal: {
      baseUrl: string;
      customTheme: any;
      certificateTemplates: string[];
    };
    brandedSupportPortal: {
      baseUrl: string;
      customBranding: any;
      ticketTemplates: string[];
    };
  }> {
    const response = await apiClient.post<{
      brandedKnowledgeBase: {
        baseUrl: string;
        customCss: string;
        logoPlacement: string;
      };
      brandedTrainingPortal: {
        baseUrl: string;
        customTheme: any;
        certificateTemplates: string[];
      };
      brandedSupportPortal: {
        baseUrl: string;
        customBranding: any;
        ticketTemplates: string[];
      };
    }>('/customer-success/white-label-resources', {
      tenantId,
      brandingConfig,
    });
    return response.data!;
  }

  // Real-time engagement tracking
  subscribeToCustomerSuccessUpdates(
    onboardingInstanceId: string,
    onUpdate: (update: {
      type: 'training_progress' | 'knowledge_base_activity' | 'support_ticket_update' | 'health_score_change' | 'csm_note_added';
      data: any;
      timestamp: Date;
    }) => void
  ): () => void {
    // Mock WebSocket subscription - in production, use actual WebSocket
    const interval = setInterval(async () => {
      try {
        const integration = await this.getCustomerSuccessIntegration(onboardingInstanceId);
        
        // Simulate random updates for demo
        if (Math.random() < 0.15) { // 15% chance of update
          const updateTypes = ['training_progress', 'knowledge_base_activity', 'support_ticket_update', 'health_score_change', 'csm_note_added'] as const;
          const randomType = updateTypes[Math.floor(Math.random() * updateTypes.length)];
          
          onUpdate({
            type: randomType,
            data: { integration },
            timestamp: new Date(),
          });
        }
      } catch (error) {
        console.error('Error fetching customer success updates:', error);
      }
    }, 8000); // Check every 8 seconds

    return () => clearInterval(interval);
  }

  // Analytics for customer success teams
  async getOnboardingSuccessMetrics(params?: {
    startDate?: Date;
    endDate?: Date;
    customerType?: string;
    serviceTier?: string;
    csmId?: string;
  }): Promise<{
    overview: {
      totalOnboardings: number;
      avgTimeToValue: number; // days
      avgHealthScore: number;
      csmSatisfactionRating: number;
    };
    trainingMetrics: {
      avgCoursesCompleted: number;
      avgCompletionTime: number; // days
      certificationRate: number;
      topPerformingCourses: {
        courseId: string;
        title: string;
        completionRate: number;
        avgRating: number;
      }[];
    };
    supportMetrics: {
      ticketsPerOnboarding: number;
      avgResolutionTime: number; // hours
      firstCallResolutionRate: number;
      escalationRate: number;
      satisfactionScore: number;
    };
    engagementMetrics: {
      knowledgeBaseUsage: number; // sessions per customer
      videoWatchTime: number; // minutes per customer
      communityParticipation: number;
      featureAdoptionRate: number;
    };
    csmPerformance: {
      csmId: string;
      name: string;
      onboardingsHandled: number;
      avgTimeToValue: number;
      customerHealthScore: number;
      satisfactionRating: number;
    }[];
  }> {
    const response = await apiClient.get<{
      overview: {
        totalOnboardings: number;
        avgTimeToValue: number;
        avgHealthScore: number;
        csmSatisfactionRating: number;
      };
      trainingMetrics: {
        avgCoursesCompleted: number;
        avgCompletionTime: number;
        certificationRate: number;
        topPerformingCourses: {
          courseId: string;
          title: string;
          completionRate: number;
          avgRating: number;
        }[];
      };
      supportMetrics: {
        ticketsPerOnboarding: number;
        avgResolutionTime: number;
        firstCallResolutionRate: number;
        escalationRate: number;
        satisfactionScore: number;
      };
      engagementMetrics: {
        knowledgeBaseUsage: number;
        videoWatchTime: number;
        communityParticipation: number;
        featureAdoptionRate: number;
      };
      csmPerformance: {
        csmId: string;
        name: string;
        onboardingsHandled: number;
        avgTimeToValue: number;
        customerHealthScore: number;
        satisfactionRating: number;
      }[];
    }>('/customer-success/onboarding-metrics', { params });
    return response.data!;
  }
}

export const customerSuccessService = new CustomerSuccessService();
export default customerSuccessService;