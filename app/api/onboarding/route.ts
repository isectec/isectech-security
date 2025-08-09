/**
 * Customer Onboarding Workflow API Routes
 * Production-grade automated onboarding for iSECTECH Protect
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import { z } from 'zod';
import type { 
  OnboardingFlow, 
  OnboardingInstance,
  CustomerProfile,
  ServiceConfiguration,
  OnboardingStepInstance 
} from '@/types/onboarding';

// Validation schemas
const CreateOnboardingSchema = z.object({
  customerProfile: z.object({
    companyName: z.string().min(1),
    industry: z.string().min(1),
    companySize: z.enum(['1-10', '11-50', '51-200', '201-1000', '1001-5000', '5000+']),
    customerType: z.enum(['enterprise', 'mid-market', 'small-business', 'individual']),
    serviceTier: z.enum(['basic', 'professional', 'enterprise', 'enterprise-plus']),
    primaryContact: z.object({
      firstName: z.string().min(1),
      lastName: z.string().min(1),
      email: z.string().email(),
      phone: z.string().optional(),
      title: z.string().min(1),
      department: z.string().min(1),
      timezone: z.string().min(1),
      locale: z.string().min(1),
      preferredLanguage: z.string().min(1),
    }),
    technicalContact: z.object({
      firstName: z.string().min(1),
      lastName: z.string().min(1),
      email: z.string().email(),
      phone: z.string().optional(),
      title: z.string().min(1),
      department: z.string().min(1),
    }).optional(),
    billingContact: z.object({
      firstName: z.string().min(1),
      lastName: z.string().min(1),
      email: z.string().email(),
      phone: z.string().optional(),
    }).optional(),
    companyInfo: z.object({
      website: z.string().url().optional(),
      address: z.object({
        street: z.string().min(1),
        city: z.string().min(1),
        state: z.string().min(1),
        zipCode: z.string().min(1),
        country: z.string().min(1),
      }),
      taxId: z.string().optional(),
      businessType: z.string().min(1),
    }),
    securityRequirements: z.object({
      complianceFrameworks: z.array(z.string()),
      dataResidency: z.array(z.string()),
      securityClearance: z.string().optional(),
      industryRegulations: z.array(z.string()),
    }),
    selectedServices: z.object({
      coreServices: z.array(z.string()),
      addOnServices: z.array(z.string()),
      integrations: z.array(z.string()),
    }),
    customization: z.object({
      whiteLabelRequired: z.boolean(),
      customDomain: z.string().optional(),
      brandingRequirements: z.string().optional(),
    }),
  }),
  templateId: z.string().optional(),
  automationEnabled: z.boolean().default(true),
  assignedCSM: z.string().optional(),
});

// Mock data for development - replace with actual database calls
const mockOnboardingInstances = new Map<string, OnboardingInstance>();
const mockWorkflowTemplates = new Map<string, any>();

// Initialize default workflow template
const DEFAULT_WORKFLOW_ID = 'default-enterprise-workflow';
mockWorkflowTemplates.set(DEFAULT_WORKFLOW_ID, {
  id: DEFAULT_WORKFLOW_ID,
  name: 'Enterprise Customer Onboarding',
  steps: [
    {
      id: 'tenant-provisioning',
      type: 'account-provisioning',
      name: 'Account Provisioning',
      description: 'Create tenant account and initial configuration',
      order: 1,
      isRequired: true,
      estimatedDuration: 15,
      configuration: {},
      dependencies: [],
    },
    {
      id: 'identity-setup',
      type: 'identity-setup', 
      name: 'Identity Configuration',
      description: 'Setup SSO and user identity management',
      order: 2,
      isRequired: true,
      estimatedDuration: 10,
      configuration: {},
      dependencies: ['tenant-provisioning'],
    },
    {
      id: 'service-config',
      type: 'service-configuration',
      name: 'Service Configuration',
      description: 'Configure selected security services',
      order: 3,
      isRequired: true,
      estimatedDuration: 20,
      configuration: {},
      dependencies: ['identity-setup'],
    },
    {
      id: 'compliance-validation',
      type: 'compliance-validation',
      name: 'Compliance Setup',
      description: 'Configure compliance frameworks and policies',
      order: 4,
      isRequired: true,
      estimatedDuration: 25,
      configuration: {},
      dependencies: ['service-config'],
    },
    {
      id: 'training-assignment',
      type: 'training-assignment',
      name: 'Training Assignment',
      description: 'Assign training courses to users',
      order: 5,
      isRequired: false,
      estimatedDuration: 5,
      configuration: {},
      dependencies: ['compliance-validation'],
    },
    {
      id: 'welcome-communication',
      type: 'welcome-communication',
      name: 'Welcome Communications',
      description: 'Send welcome emails and onboarding materials',
      order: 6,
      isRequired: true,
      estimatedDuration: 2,
      configuration: {},
      dependencies: ['training-assignment'],
    },
    {
      id: 'guided-tour',
      type: 'guided-tour',
      name: 'Platform Tour',
      description: 'Schedule guided platform walkthrough',
      order: 7,
      isRequired: false,
      estimatedDuration: 30,
      configuration: {},
      dependencies: ['welcome-communication'],
    },
  ],
});

// Helper functions
async function validateTenantContext(request: NextRequest): Promise<string> {
  const headersList = headers();
  const tenantId = headersList.get('x-tenant-id');
  
  if (!tenantId) {
    throw new Error('Missing tenant context');
  }
  
  // In production, validate tenant exists and user has permission
  return tenantId;
}

function generateOnboardingId(): string {
  return `onb_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
}

function createOnboardingInstance(
  customerProfile: CustomerProfile,
  workflowId: string,
  tenantId: string,
  userId: string = 'system'
): OnboardingInstance {
  const workflow = mockWorkflowTemplates.get(workflowId || DEFAULT_WORKFLOW_ID);
  if (!workflow) {
    throw new Error('Workflow template not found');
  }

  const instanceId = generateOnboardingId();
  const now = new Date();
  
  const stepInstances: OnboardingStepInstance[] = workflow.steps.map((step: any) => ({
    id: `${instanceId}_${step.id}`,
    onboardingInstanceId: instanceId,
    stepId: step.id,
    status: step.order === 1 ? 'pending' : 'pending',
    attempts: 0,
    logs: [],
    createdAt: now,
    updatedAt: now,
    tenantId,
  }));

  const totalEstimatedDuration = workflow.steps.reduce((sum: number, step: any) => sum + step.estimatedDuration, 0);

  const instance: OnboardingInstance = {
    id: instanceId,
    workflowId: workflowId || DEFAULT_WORKFLOW_ID,
    customerProfileId: `profile_${instanceId}`,
    status: 'in-progress',
    currentStep: stepInstances[0]?.stepId,
    startedAt: now,
    estimatedCompletionTime: new Date(now.getTime() + totalEstimatedDuration * 60000),
    stepInstances,
    metadata: {
      initiatedBy: userId,
      initiationType: 'automatic',
      priority: 'normal',
    },
    progress: {
      completedSteps: 0,
      totalSteps: workflow.steps.length,
      percentComplete: 0,
    },
    notifications: [],
    errors: [],
    customData: {
      customerProfile,
    },
    createdAt: now,
    updatedAt: now,
    tenantId,
  };

  return instance;
}

async function processOnboardingStep(instanceId: string, stepId: string): Promise<{
  success: boolean;
  error?: string;
  data?: any;
}> {
  // Mock step processing - in production, implement actual provisioning logic
  const instance = mockOnboardingInstances.get(instanceId);
  if (!instance) {
    return { success: false, error: 'Instance not found' };
  }

  const step = instance.stepInstances.find(s => s.stepId === stepId);
  if (!step) {
    return { success: false, error: 'Step not found' };
  }

  try {
    // Simulate step processing based on type
    switch (step.stepId) {
      case 'tenant-provisioning':
        // In production, call actual tenant provisioning service
        await simulateAsyncOperation(2000);
        return {
          success: true,
          data: {
            tenantId: `tenant_${Date.now()}`,
            adminUserId: `user_${Date.now()}`,
            setupTasks: ['domain_verification', 'ssl_certificate_setup'],
          },
        };
      
      case 'identity-setup':
        // In production, configure SSO and identity providers
        await simulateAsyncOperation(1500);
        return {
          success: true,
          data: {
            ssoConfigured: true,
            identityProviders: ['internal', 'google', 'azure'],
          },
        };
      
      case 'service-config':
        // In production, configure security services based on customer profile
        await simulateAsyncOperation(3000);
        return {
          success: true,
          data: {
            servicesConfigured: ['threat_detection', 'vulnerability_scanning', 'compliance_monitoring'],
            integrations: ['siem', 'soar'],
          },
        };
      
      case 'compliance-validation':
        // In production, set up compliance frameworks
        await simulateAsyncOperation(2500);
        return {
          success: true,
          data: {
            frameworks: ['soc2', 'iso27001'],
            policiesCreated: 15,
            auditTrailEnabled: true,
          },
        };
      
      case 'training-assignment':
        // In production, assign training courses
        await simulateAsyncOperation(500);
        return {
          success: true,
          data: {
            coursesAssigned: ['fundamentals', 'compliance-training'],
            enrollmentCount: 5,
          },
        };
      
      case 'welcome-communication':
        // In production, send welcome emails and notifications
        await simulateAsyncOperation(1000);
        return {
          success: true,
          data: {
            emailsSent: 3,
            notificationsCreated: 2,
          },
        };
      
      case 'guided-tour':
        // In production, schedule tour session
        await simulateAsyncOperation(500);
        return {
          success: true,
          data: {
            tourScheduled: true,
            scheduledFor: new Date(Date.now() + 24 * 60 * 60 * 1000), // Tomorrow
          },
        };
      
      default:
        return { success: false, error: 'Unknown step type' };
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Processing failed',
    };
  }
}

async function simulateAsyncOperation(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// GET /api/onboarding - List onboarding instances
export async function GET(request: NextRequest) {
  try {
    const tenantId = await validateTenantContext(request);
    const { searchParams } = new URL(request.url);
    
    const status = searchParams.get('status');
    const customerType = searchParams.get('customerType');
    const limit = parseInt(searchParams.get('limit') || '10');
    const offset = parseInt(searchParams.get('offset') || '0');

    // Filter instances by tenant and query parameters
    const instances = Array.from(mockOnboardingInstances.values())
      .filter(instance => {
        if (instance.tenantId !== tenantId) return false;
        if (status && instance.status !== status) return false;
        if (customerType) {
          const profile = instance.customData?.customerProfile as CustomerProfile;
          if (profile?.customerType !== customerType) return false;
        }
        return true;
      })
      .slice(offset, offset + limit);

    return NextResponse.json({
      data: instances,
      pagination: {
        total: instances.length,
        offset,
        limit,
        hasMore: instances.length === limit,
      },
    });
  } catch (error) {
    console.error('Error listing onboarding instances:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// POST /api/onboarding - Create new onboarding instance
export async function POST(request: NextRequest) {
  try {
    const tenantId = await validateTenantContext(request);
    const body = await request.json();
    
    // Validate request body
    const validatedData = CreateOnboardingSchema.parse(body);
    
    // Create onboarding instance
    const instance = createOnboardingInstance(
      validatedData.customerProfile,
      validatedData.templateId || DEFAULT_WORKFLOW_ID,
      tenantId
    );
    
    // Store instance
    mockOnboardingInstances.set(instance.id, instance);
    
    // Start first step processing asynchronously
    const firstStep = instance.stepInstances[0];
    if (firstStep && validatedData.automationEnabled) {
      // Process first step in background
      processOnboardingStep(instance.id, firstStep.stepId).then(result => {
        const updatedInstance = mockOnboardingInstances.get(instance.id);
        if (updatedInstance) {
          const step = updatedInstance.stepInstances.find(s => s.stepId === firstStep.stepId);
          if (step) {
            step.status = result.success ? 'completed' : 'failed';
            step.result = result;
            step.completedAt = new Date();
            
            if (result.success) {
              // Move to next step
              const nextStep = updatedInstance.stepInstances.find(s => s.status === 'pending');
              if (nextStep) {
                updatedInstance.currentStep = nextStep.stepId;
                nextStep.status = 'in-progress';
                nextStep.startedAt = new Date();
              } else {
                // All steps completed
                updatedInstance.status = 'completed';
                updatedInstance.completedAt = new Date();
              }
              
              // Update progress
              const completedCount = updatedInstance.stepInstances.filter(s => s.status === 'completed').length;
              updatedInstance.progress.completedSteps = completedCount;
              updatedInstance.progress.percentComplete = Math.round((completedCount / updatedInstance.progress.totalSteps) * 100);
            } else {
              updatedInstance.status = 'failed';
              updatedInstance.errors.push({
                id: `err_${Date.now()}`,
                onboardingInstanceId: instance.id,
                stepInstanceId: step.id,
                errorType: 'configuration',
                errorCode: 'STEP_PROCESSING_FAILED',
                message: result.error || 'Step processing failed',
                details: { stepId: firstStep.stepId },
                context: {},
                severity: 'high',
                resolved: false,
                createdAt: new Date(),
                updatedAt: new Date(),
                tenantId,
              });
            }
            
            updatedInstance.updatedAt = new Date();
            mockOnboardingInstances.set(instance.id, updatedInstance);
          }
        }
      }).catch(error => {
        console.error('Error processing onboarding step:', error);
      });
    }
    
    return NextResponse.json({
      flowId: instance.id,
      status: instance.status,
      nextStep: firstStep,
      estimatedCompletionTime: instance.estimatedCompletionTime,
      createdAt: instance.createdAt,
    }, { status: 201 });
    
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { 
          error: 'Validation error',
          details: error.errors 
        },
        { status: 400 }
      );
    }
    
    console.error('Error creating onboarding instance:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}