/**
 * iSECTECH Remediation Tracking System
 * Comprehensive remediation tracking, SLA monitoring, and progress management
 * Integrates with gap analysis engine and external project management systems
 */

import { z } from 'zod';
import { promises as fs } from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { GapAnalysisResult, RemediationTicket, gapAnalysisEngine } from './gap-analysis-engine';
import { ComplianceFramework } from '../requirements/multi-framework-analysis';

// ═══════════════════════════════════════════════════════════════════════════════
// REMEDIATION TRACKING SCHEMAS AND TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export const RemediationProgressSchema = z.object({
  ticketId: z.string(),
  gapId: z.string(),
  currentStatus: z.enum(['OPEN', 'IN_PROGRESS', 'BLOCKED', 'RESOLVED', 'CLOSED', 'CANCELLED']),
  progressPercentage: z.number().min(0).max(100),
  completedSteps: z.number(),
  totalSteps: z.number(),
  timeSpent: z.number(), // hours
  estimatedTimeRemaining: z.number(), // hours
  lastActivity: z.date(),
  blockers: z.array(z.object({
    id: z.string(),
    title: z.string(),
    description: z.string(),
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    blockedSince: z.date(),
    assignee: z.string().optional(),
    resolution: z.string().optional(),
    resolvedAt: z.date().optional()
  })),
  milestones: z.array(z.object({
    id: z.string(),
    title: z.string(),
    description: z.string(),
    targetDate: z.date(),
    actualDate: z.date().optional(),
    status: z.enum(['PENDING', 'IN_PROGRESS', 'COMPLETED', 'OVERDUE']),
    dependencies: z.array(z.string()),
    deliverables: z.array(z.string())
  })),
  riskFactors: z.array(z.object({
    factor: z.string(),
    likelihood: z.number().min(1).max(5),
    impact: z.number().min(1).max(5),
    mitigation: z.string(),
    owner: z.string()
  })),
  qualityGates: z.array(z.object({
    gate: z.string(),
    criteria: z.array(z.string()),
    status: z.enum(['PENDING', 'PASSED', 'FAILED', 'WAIVED']),
    reviewer: z.string().optional(),
    reviewDate: z.date().optional(),
    comments: z.string().optional()
  })),
  metadata: z.object({
    lastUpdated: z.date(),
    updatedBy: z.string(),
    autoCalculated: z.boolean(),
    nextReview: z.date(),
    escalationLevel: z.number().optional()
  })
});

export type RemediationProgress = z.infer<typeof RemediationProgressSchema>;

export const SLATrackingSchema = z.object({
  ticketId: z.string(),
  slaType: z.enum(['RESPONSE', 'RESOLUTION', 'ESCALATION', 'REVIEW']),
  target: z.object({
    value: z.number(),
    unit: z.enum(['MINUTES', 'HOURS', 'DAYS']),
    businessHoursOnly: z.boolean()
  }),
  actual: z.object({
    startTime: z.date(),
    endTime: z.date().optional(),
    duration: z.number().optional(), // in target units
    businessHoursUsed: z.number().optional()
  }),
  status: z.enum(['ON_TRACK', 'AT_RISK', 'BREACHED', 'PAUSED', 'COMPLETED']),
  breach: z.object({
    isBreached: z.boolean(),
    breachTime: z.date().optional(),
    breachDuration: z.number().optional(),
    breachReason: z.string().optional(),
    autoEscalated: z.boolean()
  }),
  pauseHistory: z.array(z.object({
    pausedAt: z.date(),
    resumedAt: z.date().optional(),
    reason: z.string(),
    approvedBy: z.string(),
    duration: z.number() // in minutes
  })),
  notifications: z.array(z.object({
    type: z.enum(['WARNING', 'BREACH', 'ESCALATION']),
    sentAt: z.date(),
    recipients: z.array(z.string()),
    channel: z.string(),
    acknowledged: z.boolean()
  })),
  metadata: z.object({
    calculatedAt: z.date(),
    nextCalculation: z.date(),
    frameworkRequirement: z.string().optional(),
    complianceImpact: z.string().optional()
  })
});

export type SLATracking = z.infer<typeof SLATrackingSchema>;

export const WorkflowStageSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  order: z.number(),
  isRequired: z.boolean(),
  autoTransition: z.boolean(),
  transitionConditions: z.array(z.string()),
  approvers: z.array(z.string()),
  estimatedDuration: z.number(), // hours
  qualityGates: z.array(z.string()),
  documentation: z.array(z.object({
    type: z.string(),
    template: z.string(),
    required: z.boolean()
  })),
  notifications: z.object({
    onEntry: z.array(z.string()),
    onExit: z.array(z.string()),
    onDelay: z.array(z.string())
  })
});

export type WorkflowStage = z.infer<typeof WorkflowStageSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// REMEDIATION TRACKING SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

export class RemediationTrackingSystem {
  private progress: Map<string, RemediationProgress> = new Map();
  private slaTracking: Map<string, SLATracking[]> = new Map();
  private workflows: Map<string, WorkflowStage[]> = new Map();
  private config: RemediationTrackingConfig;

  constructor(config: RemediationTrackingConfig) {
    this.config = config;
    this.initializeWorkflows();
    this.startAutomatedProcesses();
  }

  /**
   * Initialize standard remediation workflows
   */
  private initializeWorkflows(): void {
    // Critical gap remediation workflow
    const criticalWorkflow: WorkflowStage[] = [
      {
        id: 'immediate-response',
        name: 'Immediate Response',
        description: 'Initial assessment and immediate containment measures',
        order: 1,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['assessment_complete', 'containment_implemented'],
        approvers: ['security-lead'],
        estimatedDuration: 2,
        qualityGates: ['impact_assessed', 'stakeholders_notified'],
        documentation: [
          { type: 'incident_report', template: 'critical-gap-assessment', required: true },
          { type: 'stakeholder_notification', template: 'critical-gap-notification', required: true }
        ],
        notifications: {
          onEntry: ['security-team', 'compliance-team', 'ciso'],
          onExit: ['security-lead'],
          onDelay: ['ciso', 'security-manager']
        }
      },
      {
        id: 'detailed-analysis',
        name: 'Detailed Analysis',
        description: 'Comprehensive gap analysis and remediation planning',
        order: 2,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['root_cause_identified', 'remediation_plan_approved'],
        approvers: ['security-manager', 'compliance-officer'],
        estimatedDuration: 8,
        qualityGates: ['root_cause_analysis', 'impact_quantification', 'remediation_options'],
        documentation: [
          { type: 'gap_analysis_report', template: 'detailed-gap-analysis', required: true },
          { type: 'remediation_plan', template: 'remediation-strategy', required: true }
        ],
        notifications: {
          onEntry: ['assigned-analyst'],
          onExit: ['security-manager', 'compliance-officer'],
          onDelay: ['security-lead', 'ciso']
        }
      },
      {
        id: 'implementation',
        name: 'Implementation',
        description: 'Execute remediation plan with continuous monitoring',
        order: 3,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['implementation_complete', 'testing_passed'],
        approvers: ['implementation-lead'],
        estimatedDuration: 40,
        qualityGates: ['code_review', 'security_testing', 'performance_testing'],
        documentation: [
          { type: 'implementation_log', template: 'implementation-progress', required: true },
          { type: 'test_results', template: 'testing-report', required: true }
        ],
        notifications: {
          onEntry: ['implementation-team'],
          onExit: ['security-team', 'compliance-team'],
          onDelay: ['implementation-lead', 'security-manager']
        }
      },
      {
        id: 'validation',
        name: 'Validation & Testing',
        description: 'Comprehensive validation of remediation effectiveness',
        order: 4,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['validation_complete', 'compliance_verified'],
        approvers: ['qa-lead', 'security-architect'],
        estimatedDuration: 16,
        qualityGates: ['functional_testing', 'security_validation', 'compliance_check'],
        documentation: [
          { type: 'validation_report', template: 'validation-results', required: true },
          { type: 'compliance_attestation', template: 'compliance-sign-off', required: true }
        ],
        notifications: {
          onEntry: ['qa-team', 'security-team'],
          onExit: ['compliance-team', 'security-manager'],
          onDelay: ['qa-lead', 'security-architect']
        }
      },
      {
        id: 'deployment',
        name: 'Production Deployment',
        description: 'Deploy remediation to production with monitoring',
        order: 5,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['deployment_complete', 'monitoring_active'],
        approvers: ['ops-lead', 'security-manager'],
        estimatedDuration: 8,
        qualityGates: ['deployment_checklist', 'rollback_plan', 'monitoring_configured'],
        documentation: [
          { type: 'deployment_plan', template: 'production-deployment', required: true },
          { type: 'monitoring_setup', template: 'monitoring-configuration', required: true }
        ],
        notifications: {
          onEntry: ['ops-team', 'security-team'],
          onExit: ['all-stakeholders'],
          onDelay: ['ops-lead', 'ciso']
        }
      },
      {
        id: 'verification',
        name: 'Post-Implementation Verification',
        description: 'Verify remediation effectiveness in production',
        order: 6,
        isRequired: true,
        autoTransition: true,
        transitionConditions: ['verification_period_complete', 'no_issues_detected'],
        approvers: ['compliance-officer'],
        estimatedDuration: 24,
        qualityGates: ['effectiveness_verified', 'compliance_maintained', 'no_regressions'],
        documentation: [
          { type: 'verification_report', template: 'post-implementation-verification', required: true }
        ],
        notifications: {
          onEntry: ['compliance-team'],
          onExit: ['all-stakeholders'],
          onDelay: ['compliance-officer', 'security-manager']
        }
      }
    ];

    this.workflows.set('CRITICAL', criticalWorkflow);

    // Add other workflow types (HIGH, MEDIUM, LOW) with appropriate stages
    this.workflows.set('HIGH', this.createHighPriorityWorkflow());
    this.workflows.set('MEDIUM', this.createMediumPriorityWorkflow());
    this.workflows.set('LOW', this.createLowPriorityWorkflow());
  }

  /**
   * Track progress for a remediation ticket
   */
  async trackProgress(ticketId: string): Promise<RemediationProgress> {
    let progress = this.progress.get(ticketId);
    
    if (!progress) {
      progress = await this.initializeProgress(ticketId);
    } else {
      progress = await this.updateProgress(progress);
    }

    this.progress.set(ticketId, progress);
    return progress;
  }

  /**
   * Initialize progress tracking for a new ticket
   */
  private async initializeProgress(ticketId: string): Promise<RemediationProgress> {
    // Get ticket details from gap analysis engine
    const tickets = Array.from(gapAnalysisEngine['tickets'].values());
    const ticket = tickets.find(t => t.id === ticketId);
    
    if (!ticket) {
      throw new Error(`Ticket ${ticketId} not found`);
    }

    const workflow = this.workflows.get(ticket.severity) || this.workflows.get('MEDIUM')!;

    const progress: RemediationProgress = {
      ticketId,
      gapId: ticket.gapId,
      currentStatus: ticket.status,
      progressPercentage: 0,
      completedSteps: 0,
      totalSteps: ticket.remediationSteps.length,
      timeSpent: 0,
      estimatedTimeRemaining: ticket.estimatedEffort,
      lastActivity: new Date(),
      blockers: [],
      milestones: this.generateMilestones(ticket, workflow),
      riskFactors: this.identifyRiskFactors(ticket),
      qualityGates: this.createQualityGates(workflow),
      metadata: {
        lastUpdated: new Date(),
        updatedBy: 'remediation-tracking-system',
        autoCalculated: true,
        nextReview: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      }
    };

    // Initialize SLA tracking
    await this.initializeSLATracking(ticketId, ticket);

    return progress;
  }

  /**
   * Update existing progress tracking
   */
  private async updateProgress(progress: RemediationProgress): Promise<RemediationProgress> {
    const tickets = Array.from(gapAnalysisEngine['tickets'].values());
    const ticket = tickets.find(t => t.id === progress.ticketId);
    
    if (!ticket) {
      return progress;
    }

    // Update completion metrics
    const completedSteps = ticket.remediationSteps.filter(step => step.status === 'COMPLETED').length;
    const progressPercentage = (completedSteps / ticket.remediationSteps.length) * 100;
    const timeSpent = ticket.remediationSteps.reduce((total, step) => 
      total + (step.actualHours || 0), 0
    );

    // Update milestone status
    const updatedMilestones = progress.milestones.map(milestone => {
      const isOverdue = new Date() > milestone.targetDate && milestone.status !== 'COMPLETED';
      return {
        ...milestone,
        status: isOverdue ? 'OVERDUE' as const : milestone.status
      };
    });

    // Check for new blockers
    const activeBlockers = await this.identifyActiveBlockers(ticket);

    // Calculate estimated time remaining
    const remainingSteps = ticket.remediationSteps.filter(step => step.status !== 'COMPLETED');
    const estimatedTimeRemaining = remainingSteps.reduce((total, step) => 
      total + step.estimatedHours, 0
    );

    return {
      ...progress,
      currentStatus: ticket.status,
      progressPercentage,
      completedSteps,
      timeSpent,
      estimatedTimeRemaining,
      lastActivity: new Date(),
      blockers: activeBlockers,
      milestones: updatedMilestones,
      metadata: {
        ...progress.metadata,
        lastUpdated: new Date(),
        autoCalculated: true,
        nextReview: new Date(Date.now() + 24 * 60 * 60 * 1000)
      }
    };
  }

  /**
   * Initialize SLA tracking for a ticket
   */
  private async initializeSLATracking(ticketId: string, ticket: RemediationTicket): Promise<void> {
    const slaConfigs = this.getSLAConfigurations(ticket);
    const slaTrackings: SLATracking[] = [];

    for (const config of slaConfigs) {
      const slaTracking: SLATracking = {
        ticketId,
        slaType: config.type,
        target: config.target,
        actual: {
          startTime: ticket.metadata.createdAt,
          duration: 0
        },
        status: 'ON_TRACK',
        breach: {
          isBreached: false,
          autoEscalated: false
        },
        pauseHistory: [],
        notifications: [],
        metadata: {
          calculatedAt: new Date(),
          nextCalculation: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
          frameworkRequirement: config.frameworkRequirement,
          complianceImpact: config.complianceImpact
        }
      };

      slaTrackings.push(slaTracking);
    }

    this.slaTracking.set(ticketId, slaTrackings);
  }

  /**
   * Update SLA status for all active tickets
   */
  async updateSLAStatus(): Promise<void> {
    console.log('Updating SLA status for all active tickets...');
    
    for (const [ticketId, slaTrackings] of this.slaTracking.entries()) {
      for (const slaTracking of slaTrackings) {
        await this.updateSingleSLAStatus(slaTracking);
      }
    }
  }

  /**
   * Update SLA status for a single tracking entry
   */
  private async updateSingleSLAStatus(slaTracking: SLATracking): Promise<void> {
    const now = new Date();
    const elapsedTime = this.calculateElapsedTime(slaTracking.actual.startTime, now, slaTracking.target.businessHoursOnly);
    
    // Calculate pause time
    const totalPauseTime = slaTracking.pauseHistory.reduce((total, pause) => {
      const endTime = pause.resumedAt || now;
      return total + (endTime.getTime() - pause.pausedAt.getTime()) / (1000 * 60); // minutes
    }, 0);

    // Adjust elapsed time for pauses
    const adjustedElapsedTime = elapsedTime - this.convertToTargetUnits(totalPauseTime / 60, slaTracking.target.unit); // convert pause minutes to target units

    slaTracking.actual.duration = adjustedElapsedTime;

    // Determine status
    const targetValue = slaTracking.target.value;
    const warningThreshold = targetValue * 0.8; // 80% of target
    const breachThreshold = targetValue;

    if (adjustedElapsedTime >= breachThreshold && !slaTracking.breach.isBreached) {
      slaTracking.status = 'BREACHED';
      slaTracking.breach.isBreached = true;
      slaTracking.breach.breachTime = now;
      slaTracking.breach.breachDuration = adjustedElapsedTime - breachThreshold;
      
      await this.handleSLABreach(slaTracking);
    } else if (adjustedElapsedTime >= warningThreshold && slaTracking.status === 'ON_TRACK') {
      slaTracking.status = 'AT_RISK';
      await this.sendSLAWarning(slaTracking);
    }

    slaTracking.metadata.calculatedAt = now;
    slaTracking.metadata.nextCalculation = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour
  }

  /**
   * Handle SLA breach
   */
  private async handleSLABreach(slaTracking: SLATracking): Promise<void> {
    console.log(`SLA breached for ticket ${slaTracking.ticketId}, type: ${slaTracking.slaType}`);

    // Send breach notification
    const notification = {
      type: 'BREACH' as const,
      sentAt: new Date(),
      recipients: this.config.notifications.breachRecipients,
      channel: 'email+slack',
      acknowledged: false
    };

    slaTracking.notifications.push(notification);

    // Auto-escalate if configured
    if (this.config.escalation.autoEscalateOnBreach) {
      await this.autoEscalateTicket(slaTracking.ticketId, 'SLA_BREACH');
      slaTracking.breach.autoEscalated = true;
    }

    // Update progress metadata
    const progress = this.progress.get(slaTracking.ticketId);
    if (progress) {
      progress.metadata.escalationLevel = (progress.metadata.escalationLevel || 0) + 1;
    }
  }

  /**
   * Send SLA warning notification
   */
  private async sendSLAWarning(slaTracking: SLATracking): Promise<void> {
    console.log(`SLA warning for ticket ${slaTracking.ticketId}, type: ${slaTracking.slaType}`);

    const notification = {
      type: 'WARNING' as const,
      sentAt: new Date(),
      recipients: this.config.notifications.warningRecipients,
      channel: 'email',
      acknowledged: false
    };

    slaTracking.notifications.push(notification);
  }

  /**
   * Auto-escalate a ticket
   */
  private async autoEscalateTicket(ticketId: string, reason: string): Promise<void> {
    console.log(`Auto-escalating ticket ${ticketId}, reason: ${reason}`);

    const progress = this.progress.get(ticketId);
    if (!progress) return;

    const escalationLevel = (progress.metadata.escalationLevel || 0) + 1;
    const escalationPath = this.config.escalation.escalationLevels[escalationLevel - 1];

    if (escalationPath) {
      // Notify escalation recipients
      console.log(`Escalating to level ${escalationLevel}: ${escalationPath.role}`);
      
      progress.metadata.escalationLevel = escalationLevel;
      progress.metadata.lastUpdated = new Date();
    }
  }

  /**
   * Generate comprehensive tracking report
   */
  async generateTrackingReport(): Promise<RemediationTrackingReport> {
    const allProgress = Array.from(this.progress.values());
    const allSLAs = Array.from(this.slaTracking.values()).flat();

    const report: RemediationTrackingReport = {
      id: uuidv4(),
      generatedAt: new Date(),
      summary: {
        totalTickets: allProgress.length,
        activeTickets: allProgress.filter(p => !['CLOSED', 'CANCELLED'].includes(p.currentStatus)).length,
        completedTickets: allProgress.filter(p => p.currentStatus === 'CLOSED').length,
        blockedTickets: allProgress.filter(p => p.currentStatus === 'BLOCKED').length,
        overdueMilestones: allProgress.reduce((count, p) => 
          count + p.milestones.filter(m => m.status === 'OVERDUE').length, 0
        ),
        averageCompletion: allProgress.reduce((sum, p) => sum + p.progressPercentage, 0) / allProgress.length || 0,
        totalTimeSpent: allProgress.reduce((sum, p) => sum + p.timeSpent, 0),
        estimatedTimeRemaining: allProgress.reduce((sum, p) => sum + p.estimatedTimeRemaining, 0)
      },
      slaMetrics: {
        totalSLAs: allSLAs.length,
        onTrackSLAs: allSLAs.filter(s => s.status === 'ON_TRACK').length,
        atRiskSLAs: allSLAs.filter(s => s.status === 'AT_RISK').length,
        breachedSLAs: allSLAs.filter(s => s.status === 'BREACHED').length,
        averageResponseTime: this.calculateAverageResponseTime(allSLAs),
        breachRate: allSLAs.filter(s => s.breach.isBreached).length / allSLAs.length * 100
      },
      progressByPriority: this.categorizeProgressByPriority(allProgress),
      blockerAnalysis: this.analyzeBlockers(allProgress),
      riskFactors: this.analyzeRiskFactors(allProgress),
      qualityGateStatus: this.analyzeQualityGates(allProgress),
      workflowEfficiency: this.analyzeWorkflowEfficiency(allProgress),
      recommendations: this.generateTrackingRecommendations(allProgress, allSLAs)
    };

    return report;
  }

  // Helper methods for workflow generation
  private createHighPriorityWorkflow(): WorkflowStage[] {
    return [
      {
        id: 'assessment',
        name: 'Assessment',
        description: 'Rapid assessment and planning',
        order: 1,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['assessment_complete'],
        approvers: ['security-lead'],
        estimatedDuration: 4,
        qualityGates: ['impact_assessed'],
        documentation: [{ type: 'assessment_report', template: 'high-priority-assessment', required: true }],
        notifications: { onEntry: ['security-team'], onExit: ['security-lead'], onDelay: ['security-manager'] }
      },
      {
        id: 'implementation',
        name: 'Implementation',
        description: 'Execute remediation with priority',
        order: 2,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['implementation_complete', 'testing_passed'],
        approvers: ['implementation-lead'],
        estimatedDuration: 24,
        qualityGates: ['security_testing'],
        documentation: [{ type: 'implementation_log', template: 'implementation-progress', required: true }],
        notifications: { onEntry: ['implementation-team'], onExit: ['security-team'], onDelay: ['implementation-lead'] }
      },
      {
        id: 'verification',
        name: 'Verification',
        description: 'Verify remediation effectiveness',
        order: 3,
        isRequired: true,
        autoTransition: true,
        transitionConditions: ['verification_complete'],
        approvers: ['security-architect'],
        estimatedDuration: 8,
        qualityGates: ['effectiveness_verified'],
        documentation: [{ type: 'verification_report', template: 'verification-results', required: true }],
        notifications: { onEntry: ['qa-team'], onExit: ['all-stakeholders'], onDelay: ['security-architect'] }
      }
    ];
  }

  private createMediumPriorityWorkflow(): WorkflowStage[] {
    return [
      {
        id: 'planning',
        name: 'Planning',
        description: 'Detailed planning and resource allocation',
        order: 1,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['plan_approved'],
        approvers: ['project-manager'],
        estimatedDuration: 8,
        qualityGates: ['plan_reviewed'],
        documentation: [{ type: 'remediation_plan', template: 'medium-priority-plan', required: true }],
        notifications: { onEntry: ['assigned-team'], onExit: ['project-manager'], onDelay: ['team-lead'] }
      },
      {
        id: 'implementation',
        name: 'Implementation',
        description: 'Standard implementation process',
        order: 2,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['implementation_complete'],
        approvers: ['implementation-lead'],
        estimatedDuration: 40,
        qualityGates: ['testing_complete'],
        documentation: [{ type: 'implementation_log', template: 'implementation-progress', required: true }],
        notifications: { onEntry: ['implementation-team'], onExit: ['project-manager'], onDelay: ['implementation-lead'] }
      },
      {
        id: 'review',
        name: 'Review',
        description: 'Standard review and approval process',
        order: 3,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['review_complete'],
        approvers: ['security-team'],
        estimatedDuration: 16,
        qualityGates: ['security_approved'],
        documentation: [{ type: 'review_report', template: 'review-results', required: true }],
        notifications: { onEntry: ['security-team'], onExit: ['all-stakeholders'], onDelay: ['security-lead'] }
      }
    ];
  }

  private createLowPriorityWorkflow(): WorkflowStage[] {
    return [
      {
        id: 'batch-planning',
        name: 'Batch Planning',
        description: 'Plan with other low priority items',
        order: 1,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['batch_planned'],
        approvers: ['team-lead'],
        estimatedDuration: 16,
        qualityGates: ['batch_approved'],
        documentation: [{ type: 'batch_plan', template: 'low-priority-batch', required: true }],
        notifications: { onEntry: ['assigned-team'], onExit: ['team-lead'], onDelay: ['project-manager'] }
      },
      {
        id: 'implementation',
        name: 'Implementation',
        description: 'Standard implementation in batch',
        order: 2,
        isRequired: true,
        autoTransition: false,
        transitionConditions: ['implementation_complete'],
        approvers: ['implementation-lead'],
        estimatedDuration: 80,
        qualityGates: ['basic_testing'],
        documentation: [{ type: 'implementation_log', template: 'batch-implementation', required: true }],
        notifications: { onEntry: ['implementation-team'], onExit: ['team-lead'], onDelay: ['implementation-lead'] }
      }
    ];
  }

  // Helper methods for progress tracking
  private generateMilestones(ticket: RemediationTicket, workflow: WorkflowStage[]): any[] {
    return workflow.map(stage => ({
      id: uuidv4(),
      title: stage.name,
      description: stage.description,
      targetDate: new Date(Date.now() + stage.estimatedDuration * 60 * 60 * 1000),
      status: 'PENDING' as const,
      dependencies: [],
      deliverables: stage.documentation.map(doc => doc.type)
    }));
  }

  private identifyRiskFactors(ticket: RemediationTicket): any[] {
    const riskFactors = [];

    if (ticket.estimatedEffort > 120) { // > 120 hours
      riskFactors.push({
        factor: 'Large implementation scope',
        likelihood: 4,
        impact: 3,
        mitigation: 'Break down into smaller phases',
        owner: 'project-manager'
      });
    }

    if (ticket.dependencies?.length > 0) {
      riskFactors.push({
        factor: 'External dependencies',
        likelihood: 3,
        impact: 4,
        mitigation: 'Proactive dependency management',
        owner: 'implementation-lead'
      });
    }

    return riskFactors;
  }

  private createQualityGates(workflow: WorkflowStage[]): any[] {
    const allGates = workflow.flatMap(stage => stage.qualityGates);
    return [...new Set(allGates)].map(gate => ({
      gate,
      criteria: this.getQualityGateCriteria(gate),
      status: 'PENDING' as const
    }));
  }

  private getQualityGateCriteria(gate: string): string[] {
    const criteria: Record<string, string[]> = {
      'impact_assessed': ['Business impact quantified', 'Technical impact analyzed', 'Compliance impact documented'],
      'security_testing': ['Vulnerability scan passed', 'Penetration test completed', 'Security review approved'],
      'effectiveness_verified': ['Control testing passed', 'Compliance verified', 'No regressions detected']
    };

    return criteria[gate] || ['Standard criteria applied'];
  }

  private async identifyActiveBlockers(ticket: RemediationTicket): Promise<any[]> {
    const blockers = [];

    // Check for overdue dependencies
    for (const stepId of ticket.dependencies) {
      const isBlocked = await this.checkDependencyStatus(stepId);
      if (isBlocked) {
        blockers.push({
          id: uuidv4(),
          title: `Dependency blocker: ${stepId}`,
          description: `Waiting for dependency ${stepId} to be resolved`,
          severity: 'MEDIUM' as const,
          blockedSince: new Date(),
          assignee: 'dependency-owner'
        });
      }
    }

    return blockers;
  }

  private async checkDependencyStatus(dependencyId: string): Promise<boolean> {
    // Simulate dependency check - in real implementation, this would check actual dependencies
    return Math.random() > 0.8; // 20% chance of being blocked
  }

  private getSLAConfigurations(ticket: RemediationTicket): any[] {
    const configs = [];

    // Response SLA
    configs.push({
      type: 'RESPONSE',
      target: {
        value: ticket.priority === 'P0' ? 1 : ticket.priority === 'P1' ? 4 : ticket.priority === 'P2' ? 24 : 72,
        unit: 'HOURS',
        businessHoursOnly: false
      },
      frameworkRequirement: `${ticket.framework} response time requirement`,
      complianceImpact: 'Response time impacts compliance posture'
    });

    // Resolution SLA
    configs.push({
      type: 'RESOLUTION',
      target: {
        value: ticket.priority === 'P0' ? 1 : ticket.priority === 'P1' ? 3 : ticket.priority === 'P2' ? 14 : 30,
        unit: 'DAYS',
        businessHoursOnly: true
      },
      frameworkRequirement: `${ticket.framework} resolution time requirement`,
      complianceImpact: 'Resolution time affects audit readiness'
    });

    return configs;
  }

  private calculateElapsedTime(startTime: Date, endTime: Date, businessHoursOnly: boolean): number {
    if (!businessHoursOnly) {
      return (endTime.getTime() - startTime.getTime()) / (1000 * 60 * 60); // hours
    }

    // Calculate business hours only (9 AM - 5 PM, Monday - Friday)
    let elapsed = 0;
    const current = new Date(startTime);
    
    while (current < endTime) {
      const dayOfWeek = current.getDay();
      const hour = current.getHours();
      
      if (dayOfWeek >= 1 && dayOfWeek <= 5 && hour >= 9 && hour < 17) {
        elapsed += 1;
      }
      
      current.setHours(current.getHours() + 1);
    }

    return elapsed;
  }

  private convertToTargetUnits(hours: number, unit: string): number {
    switch (unit) {
      case 'MINUTES': return hours * 60;
      case 'HOURS': return hours;
      case 'DAYS': return hours / 24;
      default: return hours;
    }
  }

  private calculateAverageResponseTime(slaTrackings: SLATracking[]): number {
    const responseSLAs = slaTrackings.filter(s => s.slaType === 'RESPONSE' && s.actual.duration);
    if (responseSLAs.length === 0) return 0;
    
    const totalTime = responseSLAs.reduce((sum, s) => sum + (s.actual.duration || 0), 0);
    return totalTime / responseSLAs.length;
  }

  private categorizeProgressByPriority(allProgress: RemediationProgress[]): any {
    const categories = { P0: [], P1: [], P2: [], P3: [] };
    
    // This would need access to ticket priority - simplified for now
    return {
      P0: { count: 0, avgCompletion: 0 },
      P1: { count: 0, avgCompletion: 0 },
      P2: { count: 0, avgCompletion: 0 },
      P3: { count: 0, avgCompletion: 0 }
    };
  }

  private analyzeBlockers(allProgress: RemediationProgress[]): any {
    const allBlockers = allProgress.flatMap(p => p.blockers);
    return {
      totalBlockers: allBlockers.length,
      blockerTypes: this.groupBy(allBlockers, 'title'),
      averageBlockerDuration: this.calculateAverageBlockerDuration(allBlockers),
      mostCommonBlockers: this.getMostCommonBlockers(allBlockers)
    };
  }

  private analyzeRiskFactors(allProgress: RemediationProgress[]): any {
    const allRisks = allProgress.flatMap(p => p.riskFactors);
    return {
      totalRiskFactors: allRisks.length,
      highRiskTickets: allProgress.filter(p => 
        p.riskFactors.some(r => r.likelihood * r.impact >= 15)
      ).length,
      commonRiskFactors: this.getMostCommonRiskFactors(allRisks)
    };
  }

  private analyzeQualityGates(allProgress: RemediationProgress[]): any {
    const allGates = allProgress.flatMap(p => p.qualityGates);
    return {
      totalGates: allGates.length,
      passedGates: allGates.filter(g => g.status === 'PASSED').length,
      failedGates: allGates.filter(g => g.status === 'FAILED').length,
      pendingGates: allGates.filter(g => g.status === 'PENDING').length
    };
  }

  private analyzeWorkflowEfficiency(allProgress: RemediationProgress[]): any {
    return {
      averageTimePerStage: 24, // hours - would calculate from actual data
      bottleneckStages: ['implementation', 'review'],
      workflowOptimizationOpportunities: [
        'Automate quality gate checking',
        'Parallel processing for independent tasks',
        'Template-based documentation generation'
      ]
    };
  }

  private generateTrackingRecommendations(allProgress: RemediationProgress[], allSLAs: SLATracking[]): string[] {
    const recommendations = [];

    const blockedTickets = allProgress.filter(p => p.currentStatus === 'BLOCKED').length;
    if (blockedTickets > allProgress.length * 0.2) {
      recommendations.push('High number of blocked tickets - review blocker resolution process');
    }

    const breachedSLAs = allSLAs.filter(s => s.breach.isBreached).length;
    if (breachedSLAs > allSLAs.length * 0.1) {
      recommendations.push('SLA breach rate exceeds threshold - review resource allocation');
    }

    const overdueItems = allProgress.reduce((count, p) => 
      count + p.milestones.filter(m => m.status === 'OVERDUE').length, 0
    );
    if (overdueItems > 0) {
      recommendations.push('Multiple overdue milestones - consider timeline adjustment');
    }

    return recommendations;
  }

  // Utility methods
  private groupBy<T>(array: T[], key: string): Record<string, T[]> {
    return array.reduce((groups, item) => {
      const value = (item as any)[key];
      groups[value] = groups[value] || [];
      groups[value].push(item);
      return groups;
    }, {} as Record<string, T[]>);
  }

  private calculateAverageBlockerDuration(blockers: any[]): number {
    if (blockers.length === 0) return 0;
    
    const now = new Date();
    const totalDuration = blockers.reduce((sum, blocker) => {
      const resolvedAt = blocker.resolvedAt || now;
      return sum + (resolvedAt.getTime() - blocker.blockedSince.getTime()) / (1000 * 60 * 60 * 24); // days
    }, 0);
    
    return totalDuration / blockers.length;
  }

  private getMostCommonBlockers(blockers: any[]): any[] {
    const grouped = this.groupBy(blockers, 'title');
    return Object.entries(grouped)
      .map(([title, items]) => ({ title, count: items.length }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  private getMostCommonRiskFactors(risks: any[]): any[] {
    const grouped = this.groupBy(risks, 'factor');
    return Object.entries(grouped)
      .map(([factor, items]) => ({ factor, count: items.length }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  /**
   * Start automated background processes
   */
  private startAutomatedProcesses(): void {
    // Update SLA status every hour
    setInterval(() => {
      this.updateSLAStatus().catch(console.error);
    }, 60 * 60 * 1000); // 1 hour

    // Update progress every 30 minutes
    setInterval(() => {
      this.updateAllProgress().catch(console.error);
    }, 30 * 60 * 1000); // 30 minutes

    console.log('Remediation tracking automated processes started');
  }

  private async updateAllProgress(): Promise<void> {
    for (const ticketId of this.progress.keys()) {
      try {
        await this.trackProgress(ticketId);
      } catch (error) {
        console.error(`Failed to update progress for ticket ${ticketId}:`, error);
      }
    }
  }

  /**
   * Save tracking data to files
   */
  async saveTrackingData(outputDir: string = './remediation-tracking-output'): Promise<void> {
    await fs.mkdir(outputDir, { recursive: true });

    // Save progress data
    const progressData = Array.from(this.progress.values());
    await fs.writeFile(
      path.join(outputDir, 'remediation-progress.json'),
      JSON.stringify(progressData, null, 2)
    );

    // Save SLA tracking data
    const slaData = Array.from(this.slaTracking.entries()).map(([ticketId, trackings]) => ({
      ticketId,
      trackings
    }));
    await fs.writeFile(
      path.join(outputDir, 'sla-tracking.json'),
      JSON.stringify(slaData, null, 2)
    );

    // Save workflows
    const workflowData = Array.from(this.workflows.entries()).map(([priority, stages]) => ({
      priority,
      stages
    }));
    await fs.writeFile(
      path.join(outputDir, 'workflows.json'),
      JSON.stringify(workflowData, null, 2)
    );

    console.log(`Remediation tracking data saved to: ${outputDir}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface RemediationTrackingConfig {
  notifications: {
    warningRecipients: string[];
    breachRecipients: string[];
    escalationRecipients: string[];
  };
  escalation: {
    autoEscalateOnBreach: boolean;
    escalationLevels: Array<{
      level: number;
      role: string;
      hoursOverdue: number;
    }>;
  };
  sla: {
    businessHours: {
      start: number; // hour of day
      end: number;   // hour of day
      timezone: string;
    };
    holidays: Date[];
  };
  integrations: {
    projectManagement?: {
      enabled: boolean;
      system: 'jira' | 'asana' | 'azure-devops';
      apiEndpoint?: string;
      authToken?: string;
    };
    notifications?: {
      email: boolean;
      slack: boolean;
      teams: boolean;
    };
  };
}

export interface RemediationTrackingReport {
  id: string;
  generatedAt: Date;
  summary: {
    totalTickets: number;
    activeTickets: number;
    completedTickets: number;
    blockedTickets: number;
    overdueMilestones: number;
    averageCompletion: number;
    totalTimeSpent: number;
    estimatedTimeRemaining: number;
  };
  slaMetrics: {
    totalSLAs: number;
    onTrackSLAs: number;
    atRiskSLAs: number;
    breachedSLAs: number;
    averageResponseTime: number;
    breachRate: number;
  };
  progressByPriority: any;
  blockerAnalysis: any;
  riskFactors: any;
  qualityGateStatus: any;
  workflowEfficiency: any;
  recommendations: string[];
}

// Default configuration for iSECTECH
export const defaultRemediationTrackingConfig: RemediationTrackingConfig = {
  notifications: {
    warningRecipients: ['security-team@isectech.com', 'compliance-team@isectech.com'],
    breachRecipients: ['ciso@isectech.com', 'security-manager@isectech.com'],
    escalationRecipients: ['executives@isectech.com']
  },
  escalation: {
    autoEscalateOnBreach: true,
    escalationLevels: [
      { level: 1, role: 'team-lead', hoursOverdue: 24 },
      { level: 2, role: 'security-manager', hoursOverdue: 72 },
      { level: 3, role: 'ciso', hoursOverdue: 168 }
    ]
  },
  sla: {
    businessHours: {
      start: 9,
      end: 17,
      timezone: 'America/New_York'
    },
    holidays: []
  },
  integrations: {
    projectManagement: {
      enabled: false,
      system: 'jira'
    },
    notifications: {
      email: true,
      slack: true,
      teams: false
    }
  }
};

// Export the tracking system instance
export const remediationTrackingSystem = new RemediationTrackingSystem(defaultRemediationTrackingConfig);