/**
 * Individual Onboarding Instance API Routes
 * Production-grade onboarding instance management
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import { z } from 'zod';
import type { OnboardingInstance, OnboardingStepInstance } from '@/types/onboarding';

// Validation schemas
const UpdateStepSchema = z.object({
  stepId: z.string().min(1),
  status: z.enum(['pending', 'in-progress', 'completed', 'failed', 'skipped', 'blocked']).optional(),
  outputs: z.record(z.any()).optional(),
  configuration: z.record(z.any()).optional(),
  errorMessage: z.string().optional(),
});

// Mock storage - replace with actual database
const mockOnboardingInstances = new Map<string, OnboardingInstance>();

// Helper functions
async function validateTenantContext(request: NextRequest): Promise<string> {
  const headersList = headers();
  const tenantId = headersList.get('x-tenant-id');
  
  if (!tenantId) {
    throw new Error('Missing tenant context');
  }
  
  return tenantId;
}

async function processOnboardingStep(instanceId: string, stepId: string): Promise<{
  success: boolean;
  error?: string;
  data?: any;
}> {
  // Mock step processing - in production, implement actual logic
  const instance = mockOnboardingInstances.get(instanceId);
  if (!instance) {
    return { success: false, error: 'Instance not found' };
  }

  const step = instance.stepInstances.find(s => s.stepId === stepId);
  if (!step) {
    return { success: false, error: 'Step not found' };
  }

  try {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
    
    // Simulate success/failure (90% success rate)
    if (Math.random() < 0.9) {
      return {
        success: true,
        data: {
          processedAt: new Date(),
          stepId,
          result: `Successfully processed ${stepId}`,
        },
      };
    } else {
      return {
        success: false,
        error: `Processing failed for step ${stepId}`,
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Processing failed',
    };
  }
}

// GET /api/onboarding/[id] - Get onboarding instance details
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = await validateTenantContext(request);
    const { id } = params;
    
    const instance = mockOnboardingInstances.get(id);
    if (!instance || instance.tenantId !== tenantId) {
      return NextResponse.json(
        { error: 'Onboarding instance not found' },
        { status: 404 }
      );
    }

    // Calculate progress and next actions
    const completedSteps = instance.stepInstances.filter(s => s.status === 'completed');
    const failedSteps = instance.stepInstances.filter(s => s.status === 'failed');
    const inProgressSteps = instance.stepInstances.filter(s => s.status === 'in-progress');
    const pendingSteps = instance.stepInstances.filter(s => s.status === 'pending');
    
    const nextActions: string[] = [];
    if (failedSteps.length > 0) {
      nextActions.push('Resolve failed steps before continuing');
    }
    if (inProgressSteps.length > 0) {
      nextActions.push('Wait for current step to complete');
    }
    if (pendingSteps.length > 0 && inProgressSteps.length === 0 && failedSteps.length === 0) {
      nextActions.push('Process next pending step');
    }
    
    const recommendations: string[] = [];
    if (completedSteps.length === 0) {
      recommendations.push('Review customer profile for accuracy');
    }
    if (failedSteps.length > 0) {
      recommendations.push('Check error logs and retry failed steps');
    }
    if (instance.progress.percentComplete > 50) {
      recommendations.push('Prepare for customer handoff process');
    }

    // Calculate detailed progress
    const progress = {
      flowId: instance.id,
      customerId: instance.customerProfileId,
      overallProgress: instance.progress.percentComplete,
      stepProgress: instance.stepInstances.map(step => ({
        stepId: step.stepId,
        stepType: step.stepId as any, // Type assertion for mock data
        status: step.status,
        progress: step.status === 'completed' ? 100 : 
                 step.status === 'in-progress' ? 50 : 0,
        timeSpent: step.duration || 0,
        attempts: step.attempts,
        lastAttemptAt: step.lastAttemptAt,
        errors: step.logs.filter(log => log.level === 'error').map(log => ({
          errorCode: 'STEP_ERROR',
          errorMessage: log.message,
          occurredAt: log.timestamp,
          resolved: false,
        })),
      })),
      timeSpent: Math.round((new Date().getTime() - instance.startedAt!.getTime()) / 60000),
      estimatedTimeRemaining: instance.estimatedCompletionTime ? 
        Math.max(0, Math.round((instance.estimatedCompletionTime.getTime() - new Date().getTime()) / 60000)) : 0,
      blockers: instance.errors.filter(error => !error.resolved).map(error => ({
        id: error.id,
        type: error.errorType as any,
        severity: error.severity as any,
        title: error.errorCode,
        description: error.message,
        affectedSteps: [error.stepInstanceId].filter(Boolean),
        createdAt: error.createdAt,
        resolvedAt: error.resolvedAt,
        assignedTo: error.resolvedBy,
        resolutionNotes: error.resolution,
      })),
      milestones: [],
      lastUpdated: instance.updatedAt,
    };

    return NextResponse.json({
      flow: instance,
      progress,
      nextActions,
      recommendations,
    });
  } catch (error) {
    console.error('Error fetching onboarding instance:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// PATCH /api/onboarding/[id] - Update onboarding instance
export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = await validateTenantContext(request);
    const { id } = params;
    const body = await request.json();
    
    const instance = mockOnboardingInstances.get(id);
    if (!instance || instance.tenantId !== tenantId) {
      return NextResponse.json(
        { error: 'Onboarding instance not found' },
        { status: 404 }
      );
    }

    // Handle different update types
    if (body.action === 'update_step') {
      const validatedData = UpdateStepSchema.parse(body);
      const step = instance.stepInstances.find(s => s.stepId === validatedData.stepId);
      
      if (!step) {
        return NextResponse.json(
          { error: 'Step not found' },
          { status: 404 }
        );
      }

      // Update step
      if (validatedData.status) {
        step.status = validatedData.status;
        
        if (validatedData.status === 'completed') {
          step.completedAt = new Date();
          step.duration = step.startedAt ? 
            Math.round((new Date().getTime() - step.startedAt.getTime()) / 60000) : 0;
        } else if (validatedData.status === 'in-progress') {
          step.startedAt = new Date();
        } else if (validatedData.status === 'failed' && validatedData.errorMessage) {
          // Log error
          step.logs.push({
            timestamp: new Date(),
            level: 'error',
            message: validatedData.errorMessage,
            data: validatedData.outputs,
          });
          
          // Add to instance errors
          instance.errors.push({
            id: `err_${Date.now()}`,
            onboardingInstanceId: instance.id,
            stepInstanceId: step.id,
            errorType: 'configuration',
            errorCode: 'STEP_FAILED',
            message: validatedData.errorMessage,
            details: validatedData.outputs || {},
            context: {},
            severity: 'medium',
            resolved: false,
            createdAt: new Date(),
            updatedAt: new Date(),
            tenantId,
          });
        }
      }

      if (validatedData.outputs) {
        if (!step.result) step.result = { success: true, data: {} };
        step.result.data = { ...step.result.data, ...validatedData.outputs };
      }

      if (validatedData.configuration) {
        // Store configuration updates
        step.logs.push({
          timestamp: new Date(),
          level: 'info',
          message: 'Configuration updated',
          data: validatedData.configuration,
        });
      }

      step.attempts += 1;
      step.lastAttemptAt = new Date();
      step.updatedAt = new Date();

      // Update instance progress
      const completedCount = instance.stepInstances.filter(s => s.status === 'completed').length;
      const failedCount = instance.stepInstances.filter(s => s.status === 'failed').length;
      
      instance.progress.completedSteps = completedCount;
      instance.progress.percentComplete = Math.round((completedCount / instance.progress.totalSteps) * 100);
      
      // Update instance status
      if (completedCount === instance.progress.totalSteps) {
        instance.status = 'completed';
        instance.completedAt = new Date();
      } else if (failedCount > 0) {
        instance.status = 'failed';
      } else {
        instance.status = 'in-progress';
      }
      
      // Move to next step if current completed
      if (validatedData.status === 'completed') {
        const nextStep = instance.stepInstances.find(s => 
          s.status === 'pending' && 
          !s.dependencies?.some(dep => 
            !instance.stepInstances.find(depStep => 
              depStep.stepId === dep && depStep.status === 'completed'
            )
          )
        );
        
        if (nextStep) {
          instance.currentStep = nextStep.stepId;
          nextStep.status = 'pending'; // Will be picked up by automation
        }
      }

    } else if (body.action === 'retry_step') {
      const stepId = body.stepId;
      const step = instance.stepInstances.find(s => s.stepId === stepId);
      
      if (!step) {
        return NextResponse.json(
          { error: 'Step not found' },
          { status: 404 }
        );
      }
      
      if (step.status !== 'failed') {
        return NextResponse.json(
          { error: 'Can only retry failed steps' },
          { status: 400 }
        );
      }
      
      // Reset step for retry
      step.status = 'in-progress';
      step.startedAt = new Date();
      step.attempts += 1;
      step.lastAttemptAt = new Date();
      
      // Process step asynchronously
      processOnboardingStep(instance.id, stepId).then(result => {
        const currentInstance = mockOnboardingInstances.get(instance.id);
        if (currentInstance) {
          const currentStep = currentInstance.stepInstances.find(s => s.stepId === stepId);
          if (currentStep) {
            currentStep.status = result.success ? 'completed' : 'failed';
            currentStep.result = result;
            if (result.success) {
              currentStep.completedAt = new Date();
              currentStep.duration = currentStep.startedAt ? 
                Math.round((new Date().getTime() - currentStep.startedAt.getTime()) / 60000) : 0;
            }
            currentStep.updatedAt = new Date();
            mockOnboardingInstances.set(instance.id, currentInstance);
          }
        }
      }).catch(error => {
        console.error('Error retrying step:', error);
      });
      
    } else if (body.action === 'pause') {
      instance.status = 'pending-approval';
      
    } else if (body.action === 'resume') {
      if (instance.status === 'pending-approval') {
        instance.status = 'in-progress';
      }
      
    } else if (body.action === 'cancel') {
      instance.status = 'cancelled';
      instance.completedAt = new Date();
    }

    instance.updatedAt = new Date();
    mockOnboardingInstances.set(id, instance);

    // Determine next step and flow completion
    const nextStep = instance.stepInstances.find(s => s.status === 'in-progress') ||
                    instance.stepInstances.find(s => s.status === 'pending');
    const flowComplete = instance.status === 'completed' || instance.status === 'cancelled';

    return NextResponse.json({
      stepId: body.stepId,
      status: body.status || instance.status,
      nextStep,
      flowComplete,
    });

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
    
    console.error('Error updating onboarding instance:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// DELETE /api/onboarding/[id] - Cancel/delete onboarding instance
export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = await validateTenantContext(request);
    const { id } = params;
    
    const instance = mockOnboardingInstances.get(id);
    if (!instance || instance.tenantId !== tenantId) {
      return NextResponse.json(
        { error: 'Onboarding instance not found' },
        { status: 404 }
      );
    }

    // Check if instance can be cancelled
    if (instance.status === 'completed') {
      return NextResponse.json(
        { error: 'Cannot cancel completed onboarding' },
        { status: 400 }
      );
    }

    // Cancel the instance
    instance.status = 'cancelled';
    instance.completedAt = new Date();
    instance.updatedAt = new Date();
    
    // Stop all in-progress steps
    instance.stepInstances.forEach(step => {
      if (step.status === 'in-progress') {
        step.status = 'cancelled';
        step.completedAt = new Date();
        step.updatedAt = new Date();
        
        step.logs.push({
          timestamp: new Date(),
          level: 'info',
          message: 'Step cancelled due to onboarding cancellation',
        });
      }
    });

    mockOnboardingInstances.set(id, instance);

    return NextResponse.json({ 
      success: true,
      message: 'Onboarding instance cancelled successfully' 
    });

  } catch (error) {
    console.error('Error cancelling onboarding instance:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}