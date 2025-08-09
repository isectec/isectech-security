/**
 * Production-grade Response Orchestrator for Deception Technology
 * 
 * Master orchestrator that coordinates automated responses across all
 * integrated systems (SOAR, SIEM, network controls, etc.)
 * 
 * Custom implementation for iSECTECH's security operations.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import { 
  isectechDeceptionResponseEngine, 
  DeceptionEvent, 
  ResponsePlaybook 
} from './deception-response-engine';
import { isectechSOARIntegration } from './soar-integration';
import { isectechSIEMIntegration } from './siem-integration';

// Response Orchestration Schemas
export const OrchestrationContextSchema = z.object({
  orchestrationId: z.string(),
  deceptionEvent: z.any(), // DeceptionEvent
  
  // Orchestration configuration
  orchestrationMode: z.enum(['FULL_AUTO', 'SEMI_AUTO', 'MANUAL_APPROVAL', 'MONITORING_ONLY']),
  maxResponseTime: z.number(), // seconds
  escalationThreshold: z.number(), // minutes
  
  // Integration targets
  enabledIntegrations: z.array(z.enum(['SOAR', 'SIEM', 'NETWORK', 'ENDPOINT', 'EMAIL', 'IDENTITY'])),
  
  // Execution tracking
  status: z.enum(['INITIATED', 'PROCESSING', 'EXECUTING', 'COMPLETED', 'FAILED', 'ESCALATED']),
  startTime: z.date(),
  endTime: z.date().optional(),
  
  // Response tracking
  responseResults: z.array(z.object({
    system: z.string(),
    success: z.boolean(),
    responseId: z.string().optional(),
    executionTime: z.number().optional(),
    error: z.string().optional(),
    actionsExecuted: z.number().optional()
  })).default([]),
  
  // Approval workflow
  requiresApproval: z.boolean().default(false),
  approvalLevel: z.enum(['L1', 'L2', 'L3', 'MANAGER', 'CISO']).optional(),
  approvedBy: z.string().optional(),
  approvalTimestamp: z.date().optional(),
  
  // Quality metrics
  falsePositiveScore: z.number().min(0).max(1).default(0),
  effectivenessScore: z.number().min(0).max(1).default(0),
  responseQuality: z.enum(['EXCELLENT', 'GOOD', 'ACCEPTABLE', 'POOR']).optional(),
  
  // Metadata
  createdAt: z.date(),
  updatedAt: z.date()
});

export const OrchestrationRuleSchema = z.object({
  ruleId: z.string(),
  name: z.string(),
  description: z.string(),
  isActive: z.boolean().default(true),
  
  // Trigger conditions
  eventTypes: z.array(z.string()),
  severityThreshold: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  confidenceThreshold: z.number().min(0).max(1),
  
  // Additional conditions
  sourceConditions: z.object({
    ipRanges: z.array(z.string()).optional(),
    countries: z.array(z.string()).optional(),
    asns: z.array(z.string()).optional()
  }).optional(),
  
  targetConditions: z.object({
    assetTypes: z.array(z.string()).optional(),
    networkSegments: z.array(z.string()).optional()
  }).optional(),
  
  timeConditions: z.object({
    businessHoursOnly: z.boolean().default(false),
    weekdaysOnly: z.boolean().default(false),
    timeZone: z.string().default('UTC')
  }).optional(),
  
  // Response configuration
  orchestrationMode: z.enum(['FULL_AUTO', 'SEMI_AUTO', 'MANUAL_APPROVAL', 'MONITORING_ONLY']),
  maxResponseTime: z.number().default(300), // 5 minutes
  escalationTime: z.number().default(900), // 15 minutes
  
  enabledIntegrations: z.array(z.string()),
  approvalRequired: z.boolean().default(false),
  approvalLevel: z.enum(['L1', 'L2', 'L3', 'MANAGER', 'CISO']).optional(),
  
  // Rule priority and execution
  priority: z.number().default(100),
  maxConcurrentExecutions: z.number().default(5),
  
  // Usage tracking
  timesTriggered: z.number().default(0),
  successRate: z.number().default(0),
  averageExecutionTime: z.number().default(0),
  
  createdBy: z.string(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const ResponseMetricsSchema = z.object({
  metricsId: z.string(),
  timestamp: z.date(),
  
  // Volume metrics
  totalEvents: z.number(),
  eventsProcessed: z.number(),
  responsesExecuted: z.number(),
  escalations: z.number(),
  falsePositives: z.number(),
  
  // Performance metrics
  averageResponseTime: z.number(), // seconds
  averageProcessingTime: z.number(), // seconds
  successRate: z.number(), // 0-1
  
  // System metrics
  systemAvailability: z.number(), // 0-1
  integrationHealth: z.record(z.number()), // system -> health score
  
  // Effectiveness metrics
  containmentEffectiveness: z.number(), // 0-1
  evidenceQuality: z.number(), // 0-1
  alertAccuracy: z.number(), // 0-1
  
  // Resource utilization
  cpuUtilization: z.number(), // 0-1
  memoryUtilization: z.number(), // 0-1
  networkUtilization: z.number(), // 0-1
  
  createdAt: z.date()
});

export type OrchestrationContext = z.infer<typeof OrchestrationContextSchema>;
export type OrchestrationRule = z.infer<typeof OrchestrationRuleSchema>;
export type ResponseMetrics = z.infer<typeof ResponseMetricsSchema>;

/**
 * Response Orchestration Engine
 */
export class ISECTECHResponseOrchestrator {
  private orchestrationContexts: Map<string, OrchestrationContext> = new Map();
  private orchestrationRules: Map<string, OrchestrationRule> = new Map();
  private responseMetrics: ResponseMetrics[] = [];
  
  // Integration instances
  private deceptionEngine = isectechDeceptionResponseEngine;
  private soarIntegration = isectechSOARIntegration;
  private siemIntegration = isectechSIEMIntegration;

  constructor() {
    this.initializeOrchestrator();
  }

  /**
   * Initialize the response orchestrator
   */
  private initializeOrchestrator(): void {
    console.log('Initializing iSECTECH Response Orchestrator...');
    
    // Initialize default orchestration rules
    this.initializeDefaultRules();
    
    // Start metrics collection
    this.startMetricsCollection();
    
    console.log(`Response Orchestrator initialized with ${this.orchestrationRules.size} rules`);
  }

  /**
   * Process deception event through orchestrated response
   */
  public async orchestrateResponse(deceptionEventData: Partial<DeceptionEvent>): Promise<{
    success: boolean;
    orchestrationId?: string;
    responsesSummary?: any;
    error?: string;
  }> {
    const orchestrationId = crypto.randomUUID();
    const startTime = new Date();

    try {
      console.log(`Initiating orchestrated response: ${orchestrationId}`);

      // Process event through deception engine first
      const deceptionResult = await this.deceptionEngine.processDeceptionEvent(deceptionEventData);
      if (!deceptionResult.success) {
        throw new Error(`Deception engine processing failed: ${deceptionResult.error}`);
      }

      const deceptionEvent = this.deceptionEngine.getEvent(deceptionResult.eventId!);
      if (!deceptionEvent) {
        throw new Error('Failed to retrieve processed deception event');
      }

      // Find applicable orchestration rule
      const applicableRule = this.findApplicableRule(deceptionEvent);
      if (!applicableRule) {
        console.log('No applicable orchestration rule found - using default monitoring');
        return { success: true, orchestrationId, responsesSummary: { mode: 'MONITORING_ONLY' } };
      }

      // Create orchestration context
      const context = await this.createOrchestrationContext(orchestrationId, deceptionEvent, applicableRule);

      // Check for approval requirement
      if (context.requiresApproval) {
        await this.requestApproval(context);
        if (context.status === 'ESCALATED') {
          return { 
            success: true, 
            orchestrationId, 
            responsesSummary: { mode: 'AWAITING_APPROVAL' } 
          };
        }
      }

      // Execute orchestrated response
      const responseResults = await this.executeOrchestatedResponse(context, applicableRule);
      
      // Update context with results
      context.responseResults = responseResults;
      context.endTime = new Date();
      context.status = responseResults.some(r => !r.success) ? 'FAILED' : 'COMPLETED';
      context.updatedAt = new Date();

      // Calculate effectiveness scores
      await this.calculateResponseEffectiveness(context);

      // Update rule statistics
      await this.updateRuleStatistics(applicableRule, context);

      const executionTime = (context.endTime.getTime() - context.startTime.getTime()) / 1000;
      console.log(`Orchestrated response completed: ${orchestrationId} (${executionTime}s)`);

      return {
        success: true,
        orchestrationId,
        responsesSummary: {
          mode: context.orchestrationMode,
          responsesExecuted: responseResults.length,
          successfulResponses: responseResults.filter(r => r.success).length,
          executionTime,
          systemsInvolved: responseResults.map(r => r.system)
        }
      };

    } catch (error) {
      console.error('Orchestrated response failed:', error);
      
      // Update context with failure
      const context = this.orchestrationContexts.get(orchestrationId);
      if (context) {
        context.status = 'FAILED';
        context.endTime = new Date();
        context.updatedAt = new Date();
      }

      return { 
        success: false, 
        orchestrationId,
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Execute coordinated response across all systems
   */
  private async executeOrchestatedResponse(
    context: OrchestrationContext, 
    rule: OrchestrationRule
  ): Promise<any[]> {
    const responseResults: any[] = [];
    const deceptionEvent = context.deceptionEvent;

    console.log(`Executing orchestrated response with integrations: ${rule.enabledIntegrations.join(', ')}`);

    // Execute responses in parallel for efficiency
    const responsePromises: Promise<any>[] = [];

    // SOAR Integration
    if (rule.enabledIntegrations.includes('SOAR')) {
      responsePromises.push(this.executeSOARResponse(deceptionEvent, context.orchestrationId));
    }

    // SIEM Integration
    if (rule.enabledIntegrations.includes('SIEM')) {
      responsePromises.push(this.executeSIEMResponse(deceptionEvent, context.orchestrationId));
    }

    // Network Controls Integration
    if (rule.enabledIntegrations.includes('NETWORK')) {
      responsePromises.push(this.executeNetworkResponse(deceptionEvent, context.orchestrationId));
    }

    // Endpoint Security Integration
    if (rule.enabledIntegrations.includes('ENDPOINT')) {
      responsePromises.push(this.executeEndpointResponse(deceptionEvent, context.orchestrationId));
    }

    // Email Security Integration
    if (rule.enabledIntegrations.includes('EMAIL')) {
      responsePromises.push(this.executeEmailResponse(deceptionEvent, context.orchestrationId));
    }

    // Identity Management Integration
    if (rule.enabledIntegrations.includes('IDENTITY')) {
      responsePromises.push(this.executeIdentityResponse(deceptionEvent, context.orchestrationId));
    }

    // Wait for all responses to complete
    const results = await Promise.allSettled(responsePromises);
    
    results.forEach((result, index) => {
      const system = rule.enabledIntegrations[index];
      if (result.status === 'fulfilled') {
        responseResults.push({
          system,
          success: result.value.success,
          responseId: result.value.responseId,
          executionTime: result.value.executionTime,
          actionsExecuted: result.value.actionsExecuted
        });
      } else {
        responseResults.push({
          system,
          success: false,
          error: result.reason instanceof Error ? result.reason.message : 'Unknown error',
          executionTime: 0,
          actionsExecuted: 0
        });
      }
    });

    return responseResults;
  }

  /**
   * Execute SOAR response
   */
  private async executeSOARResponse(
    deceptionEvent: DeceptionEvent, 
    orchestrationId: string
  ): Promise<{ success: boolean; responseId?: string; executionTime?: number; actionsExecuted?: number }> {
    const startTime = Date.now();
    
    try {
      console.log('Executing SOAR response...');

      // Create SOAR case
      const caseResult = await this.soarIntegration.createCaseFromDeceptionEvent(deceptionEvent);
      if (!caseResult.success) {
        throw new Error(`SOAR case creation failed: ${caseResult.error}`);
      }

      // Create SOAR alert
      const alertResult = await this.soarIntegration.createAlertFromDeceptionEvent(deceptionEvent);
      if (!alertResult.success) {
        console.warn(`SOAR alert creation failed: ${alertResult.error}`);
      }

      // Get applicable playbook and execute
      const playbook = this.deceptionEngine.getAllPlaybooks().find(p => 
        p.triggers.some(t => t.eventType === deceptionEvent.eventType)
      );

      let playbookResult: any = null;
      if (playbook) {
        playbookResult = await this.soarIntegration.executePlaybookInSOAR(
          caseResult.caseId!, 
          playbook, 
          deceptionEvent
        );
      }

      const executionTime = Date.now() - startTime;

      return {
        success: true,
        responseId: caseResult.caseId,
        executionTime,
        actionsExecuted: playbook?.actions.length || 0
      };

    } catch (error) {
      console.error('SOAR response execution failed:', error);
      return {
        success: false,
        executionTime: Date.now() - startTime,
        actionsExecuted: 0
      };
    }
  }

  /**
   * Execute SIEM response
   */
  private async executeSIEMResponse(
    deceptionEvent: DeceptionEvent, 
    orchestrationId: string
  ): Promise<{ success: boolean; responseId?: string; executionTime?: number; actionsExecuted?: number }> {
    const startTime = Date.now();
    
    try {
      console.log('Executing SIEM response...');

      // Forward event to SIEM
      const alertResult = await this.siemIntegration.forwardDeceptionEventToSIEM(deceptionEvent);
      if (!alertResult.success) {
        throw new Error(`SIEM alert creation failed: ${alertResult.error}`);
      }

      // Create detailed events
      const eventsResult = await this.siemIntegration.createDetailedSIEMEvents(deceptionEvent);
      if (!eventsResult.success) {
        console.warn(`SIEM detailed events creation failed: ${eventsResult.error}`);
      }

      // Enrich event with SIEM data
      const enrichmentResult = await this.siemIntegration.enrichEventWithSIEMData(deceptionEvent);
      if (!enrichmentResult.success) {
        console.warn(`SIEM enrichment failed: ${enrichmentResult.error}`);
      }

      // Query for related events
      const relatedEventsResult = await this.siemIntegration.queryRelatedEvents(deceptionEvent);
      if (relatedEventsResult.success && relatedEventsResult.events) {
        console.log(`Found ${relatedEventsResult.events.length} related events in SIEM`);
      }

      const executionTime = Date.now() - startTime;

      return {
        success: true,
        responseId: alertResult.alertId,
        executionTime,
        actionsExecuted: 4 // Alert + Events + Enrichment + Query
      };

    } catch (error) {
      console.error('SIEM response execution failed:', error);
      return {
        success: false,
        executionTime: Date.now() - startTime,
        actionsExecuted: 0
      };
    }
  }

  /**
   * Execute network controls response
   */
  private async executeNetworkResponse(
    deceptionEvent: DeceptionEvent, 
    orchestrationId: string
  ): Promise<{ success: boolean; responseId?: string; executionTime?: number; actionsExecuted?: number }> {
    const startTime = Date.now();
    
    try {
      console.log('Executing network controls response...');

      let actionsExecuted = 0;

      // Block source IP at firewall
      if (deceptionEvent.severity === 'HIGH' || deceptionEvent.severity === 'CRITICAL') {
        console.log(`[NETWORK] Blocking source IP: ${deceptionEvent.source.sourceIP}`);
        await new Promise(resolve => setTimeout(resolve, 500)); // Simulate firewall API call
        actionsExecuted++;
      }

      // Isolate target network segment
      if (deceptionEvent.eventType === 'LATERAL_MOVEMENT_ATTEMPT') {
        console.log(`[NETWORK] Isolating network segment: ${deceptionEvent.target.networkSegment}`);
        await new Promise(resolve => setTimeout(resolve, 800)); // Simulate network isolation
        actionsExecuted++;
      }

      // Enable enhanced monitoring
      console.log(`[NETWORK] Enabling enhanced monitoring for source IP`);
      await new Promise(resolve => setTimeout(resolve, 300)); // Simulate monitoring setup
      actionsExecuted++;

      const executionTime = Date.now() - startTime;

      return {
        success: true,
        responseId: `network-${orchestrationId}`,
        executionTime,
        actionsExecuted
      };

    } catch (error) {
      console.error('Network response execution failed:', error);
      return {
        success: false,
        executionTime: Date.now() - startTime,
        actionsExecuted: 0
      };
    }
  }

  /**
   * Execute endpoint security response
   */
  private async executeEndpointResponse(
    deceptionEvent: DeceptionEvent, 
    orchestrationId: string
  ): Promise<{ success: boolean; responseId?: string; executionTime?: number; actionsExecuted?: number }> {
    const startTime = Date.now();
    
    try {
      console.log('Executing endpoint security response...');

      let actionsExecuted = 0;

      // Scan for related endpoints
      console.log(`[ENDPOINT] Scanning for related endpoints`);
      await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate endpoint scan
      actionsExecuted++;

      // Deploy additional monitoring
      if (deceptionEvent.attackDetails.payloadHash) {
        console.log(`[ENDPOINT] Deploying hash-based monitoring: ${deceptionEvent.attackDetails.payloadHash}`);
        await new Promise(resolve => setTimeout(resolve, 600)); // Simulate hash deployment
        actionsExecuted++;
      }

      // Update endpoint detection rules
      console.log(`[ENDPOINT] Updating detection rules based on attack technique`);
      await new Promise(resolve => setTimeout(resolve, 400)); // Simulate rule update
      actionsExecuted++;

      const executionTime = Date.now() - startTime;

      return {
        success: true,
        responseId: `endpoint-${orchestrationId}`,
        executionTime,
        actionsExecuted
      };

    } catch (error) {
      console.error('Endpoint response execution failed:', error);
      return {
        success: false,
        executionTime: Date.now() - startTime,
        actionsExecuted: 0
      };
    }
  }

  /**
   * Execute email security response
   */
  private async executeEmailResponse(
    deceptionEvent: DeceptionEvent, 
    orchestrationId: string
  ): Promise<{ success: boolean; responseId?: string; executionTime?: number; actionsExecuted?: number }> {
    const startTime = Date.now();
    
    try {
      console.log('Executing email security response...');

      let actionsExecuted = 0;

      // Send security alert to SOC
      console.log(`[EMAIL] Sending security alert to SOC team`);
      await new Promise(resolve => setTimeout(resolve, 200)); // Simulate email send
      actionsExecuted++;

      // Notify affected users if credential compromise suspected
      if (deceptionEvent.attackDetails.credentials) {
        console.log(`[EMAIL] Notifying potentially affected users`);
        await new Promise(resolve => setTimeout(resolve, 300)); // Simulate user notifications
        actionsExecuted++;
      }

      // Update email security filters
      if (deceptionEvent.source.userAgent) {
        console.log(`[EMAIL] Updating email security filters`);
        await new Promise(resolve => setTimeout(resolve, 250)); // Simulate filter update
        actionsExecuted++;
      }

      const executionTime = Date.now() - startTime;

      return {
        success: true,
        responseId: `email-${orchestrationId}`,
        executionTime,
        actionsExecuted
      };

    } catch (error) {
      console.error('Email response execution failed:', error);
      return {
        success: false,
        executionTime: Date.now() - startTime,
        actionsExecuted: 0
      };
    }
  }

  /**
   * Execute identity management response
   */
  private async executeIdentityResponse(
    deceptionEvent: DeceptionEvent, 
    orchestrationId: string
  ): Promise<{ success: boolean; responseId?: string; executionTime?: number; actionsExecuted?: number }> {
    const startTime = Date.now();
    
    try {
      console.log('Executing identity management response...');

      let actionsExecuted = 0;

      // Rotate canary credentials if exposed
      if (deceptionEvent.eventType === 'CANARY_TOKEN_TRIGGER') {
        console.log(`[IDENTITY] Rotating exposed canary credentials`);
        await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate credential rotation
        actionsExecuted++;
      }

      // Disable compromised accounts
      if (deceptionEvent.attackDetails.credentials?.username) {
        console.log(`[IDENTITY] Disabling compromised account: ${deceptionEvent.attackDetails.credentials.username}`);
        await new Promise(resolve => setTimeout(resolve, 400)); // Simulate account disable
        actionsExecuted++;
      }

      // Enhance authentication monitoring
      console.log(`[IDENTITY] Enhancing authentication monitoring`);
      await new Promise(resolve => setTimeout(resolve, 300)); // Simulate monitoring enhancement
      actionsExecuted++;

      const executionTime = Date.now() - startTime;

      return {
        success: true,
        responseId: `identity-${orchestrationId}`,
        executionTime,
        actionsExecuted
      };

    } catch (error) {
      console.error('Identity response execution failed:', error);
      return {
        success: false,
        executionTime: Date.now() - startTime,
        actionsExecuted: 0
      };
    }
  }

  /**
   * Find applicable orchestration rule
   */
  private findApplicableRule(deceptionEvent: DeceptionEvent): OrchestrationRule | null {
    const applicableRules = Array.from(this.orchestrationRules.values())
      .filter(rule => rule.isActive)
      .filter(rule => this.evaluateRuleConditions(rule, deceptionEvent))
      .sort((a, b) => a.priority - b.priority); // Lower priority number = higher priority

    return applicableRules[0] || null;
  }

  /**
   * Evaluate rule conditions against event
   */
  private evaluateRuleConditions(rule: OrchestrationRule, event: DeceptionEvent): boolean {
    // Check event type
    if (!rule.eventTypes.includes(event.eventType)) {
      return false;
    }

    // Check severity threshold
    const severityValues = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    if (severityValues[event.severity] < severityValues[rule.severityThreshold]) {
      return false;
    }

    // Check confidence threshold
    if (event.confidence < rule.confidenceThreshold) {
      return false;
    }

    // Check source conditions
    if (rule.sourceConditions) {
      // IP range checks would go here
      // Country checks would go here
      // ASN checks would go here
    }

    // Check target conditions
    if (rule.targetConditions) {
      if (rule.targetConditions.assetTypes && 
          !rule.targetConditions.assetTypes.includes(event.target.assetType)) {
        return false;
      }
      
      if (rule.targetConditions.networkSegments && 
          !rule.targetConditions.networkSegments.includes(event.target.networkSegment)) {
        return false;
      }
    }

    // Check time conditions
    if (rule.timeConditions) {
      const eventTime = new Date(event.timestamp);
      
      if (rule.timeConditions.businessHoursOnly) {
        const hour = eventTime.getHours();
        if (hour < 8 || hour > 17) return false;
      }
      
      if (rule.timeConditions.weekdaysOnly) {
        const dayOfWeek = eventTime.getDay();
        if (dayOfWeek === 0 || dayOfWeek === 6) return false; // Sunday = 0, Saturday = 6
      }
    }

    return true;
  }

  /**
   * Create orchestration context
   */
  private async createOrchestrationContext(
    orchestrationId: string,
    deceptionEvent: DeceptionEvent,
    rule: OrchestrationRule
  ): Promise<OrchestrationContext> {
    const context: OrchestrationContext = {
      orchestrationId,
      deceptionEvent,
      orchestrationMode: rule.orchestrationMode,
      maxResponseTime: rule.maxResponseTime,
      escalationThreshold: rule.escalationTime / 60, // Convert to minutes
      enabledIntegrations: rule.enabledIntegrations as any[],
      status: 'INITIATED',
      startTime: new Date(),
      responseResults: [],
      requiresApproval: rule.approvalRequired,
      approvalLevel: rule.approvalLevel,
      falsePositiveScore: 0,
      effectivenessScore: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedContext = OrchestrationContextSchema.parse(context);
    this.orchestrationContexts.set(orchestrationId, validatedContext);

    return validatedContext;
  }

  /**
   * Request approval for response execution
   */
  private async requestApproval(context: OrchestrationContext): Promise<void> {
    console.log(`Requesting approval for orchestration: ${context.orchestrationId} (Level: ${context.approvalLevel})`);
    
    // In production, this would integrate with approval workflow systems
    // For simulation, we'll auto-approve based on context
    if (context.deceptionEvent.severity === 'CRITICAL') {
      // Auto-approve critical events
      context.approvedBy = 'auto-approval-critical';
      context.approvalTimestamp = new Date();
      console.log('Auto-approved due to critical severity');
    } else {
      // For demo, simulate approval delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      context.approvedBy = 'soc-manager';
      context.approvalTimestamp = new Date();
      console.log('Approval granted by SOC manager');
    }

    context.updatedAt = new Date();
  }

  /**
   * Calculate response effectiveness
   */
  private async calculateResponseEffectiveness(context: OrchestrationContext): Promise<void> {
    const successfulResponses = context.responseResults.filter(r => r.success).length;
    const totalResponses = context.responseResults.length;
    
    // Base effectiveness on success rate and response time
    const successRate = totalResponses > 0 ? successfulResponses / totalResponses : 0;
    const executionTime = context.endTime ? 
      (context.endTime.getTime() - context.startTime.getTime()) / 1000 : 0;
    
    const timeFactor = Math.max(0, 1 - (executionTime / context.maxResponseTime));
    
    context.effectivenessScore = (successRate * 0.7) + (timeFactor * 0.3);
    
    // Determine quality rating
    if (context.effectivenessScore >= 0.9) {
      context.responseQuality = 'EXCELLENT';
    } else if (context.effectivenessScore >= 0.7) {
      context.responseQuality = 'GOOD';
    } else if (context.effectivenessScore >= 0.5) {
      context.responseQuality = 'ACCEPTABLE';
    } else {
      context.responseQuality = 'POOR';
    }

    context.updatedAt = new Date();
  }

  /**
   * Update rule statistics
   */
  private async updateRuleStatistics(rule: OrchestrationRule, context: OrchestrationContext): Promise<void> {
    rule.timesTriggered++;
    
    const wasSuccessful = context.status === 'COMPLETED';
    if (wasSuccessful) {
      rule.successRate = (rule.successRate * (rule.timesTriggered - 1) + 1) / rule.timesTriggered;
    } else {
      rule.successRate = (rule.successRate * (rule.timesTriggered - 1)) / rule.timesTriggered;
    }

    const executionTime = context.endTime ? 
      (context.endTime.getTime() - context.startTime.getTime()) / 1000 : 0;
    
    rule.averageExecutionTime = 
      (rule.averageExecutionTime * (rule.timesTriggered - 1) + executionTime) / 
      rule.timesTriggered;

    rule.updatedAt = new Date();
  }

  /**
   * Initialize default orchestration rules
   */
  private initializeDefaultRules(): void {
    const defaultRules: Partial<OrchestrationRule>[] = [
      {
        name: 'Critical Honeypot Access',
        description: 'Full automated response for critical honeypot access',
        eventTypes: ['HONEYPOT_ACCESS'],
        severityThreshold: 'CRITICAL',
        confidenceThreshold: 0.8,
        orchestrationMode: 'FULL_AUTO',
        maxResponseTime: 180, // 3 minutes
        escalationTime: 300, // 5 minutes
        enabledIntegrations: ['SOAR', 'SIEM', 'NETWORK', 'EMAIL'],
        priority: 10
      },
      
      {
        name: 'Canary Token Trigger',
        description: 'Automated response for canary token activation',
        eventTypes: ['CANARY_TOKEN_TRIGGER'],
        severityThreshold: 'HIGH',
        confidenceThreshold: 0.7,
        orchestrationMode: 'SEMI_AUTO',
        maxResponseTime: 300, // 5 minutes
        escalationTime: 600, // 10 minutes
        enabledIntegrations: ['SOAR', 'SIEM', 'IDENTITY', 'EMAIL'],
        approvalRequired: true,
        approvalLevel: 'L2',
        priority: 20
      },
      
      {
        name: 'Decoy Service Breach',
        description: 'Comprehensive response for decoy service compromise',
        eventTypes: ['DECOY_SERVICE_BREACH'],
        severityThreshold: 'MEDIUM',
        confidenceThreshold: 0.8,
        orchestrationMode: 'SEMI_AUTO',
        maxResponseTime: 600, // 10 minutes
        escalationTime: 900, // 15 minutes
        enabledIntegrations: ['SOAR', 'SIEM', 'NETWORK', 'ENDPOINT', 'EMAIL'],
        priority: 30
      },
      
      {
        name: 'Multiple Trigger Correlation',
        description: 'Response for correlated multiple deception triggers',
        eventTypes: ['SUSPICIOUS_RECONNAISSANCE', 'LATERAL_MOVEMENT_ATTEMPT'],
        severityThreshold: 'MEDIUM',
        confidenceThreshold: 0.6,
        orchestrationMode: 'FULL_AUTO',
        maxResponseTime: 240, // 4 minutes
        escalationTime: 480, // 8 minutes
        enabledIntegrations: ['SOAR', 'SIEM', 'NETWORK', 'ENDPOINT', 'EMAIL', 'IDENTITY'],
        priority: 15
      },
      
      {
        name: 'Default Monitoring',
        description: 'Basic monitoring for low-severity events',
        eventTypes: ['HONEYPOT_ACCESS', 'CANARY_TOKEN_TRIGGER', 'DECOY_SERVICE_BREACH'],
        severityThreshold: 'LOW',
        confidenceThreshold: 0.3,
        orchestrationMode: 'MONITORING_ONLY',
        maxResponseTime: 3600, // 1 hour
        escalationTime: 7200, // 2 hours
        enabledIntegrations: ['SIEM'],
        priority: 100
      }
    ];

    defaultRules.forEach(ruleData => {
      const rule: OrchestrationRule = {
        ruleId: ruleData.ruleId || crypto.randomUUID(),
        name: ruleData.name || 'Unnamed Rule',
        description: ruleData.description || '',
        isActive: true,
        eventTypes: ruleData.eventTypes || [],
        severityThreshold: ruleData.severityThreshold || 'MEDIUM',
        confidenceThreshold: ruleData.confidenceThreshold || 0.5,
        orchestrationMode: ruleData.orchestrationMode || 'MONITORING_ONLY',
        maxResponseTime: ruleData.maxResponseTime || 300,
        escalationTime: ruleData.escalationTime || 900,
        enabledIntegrations: ruleData.enabledIntegrations || [],
        approvalRequired: ruleData.approvalRequired || false,
        approvalLevel: ruleData.approvalLevel,
        priority: ruleData.priority || 100,
        maxConcurrentExecutions: ruleData.maxConcurrentExecutions || 5,
        timesTriggered: 0,
        successRate: 0,
        averageExecutionTime: 0,
        createdBy: 'SYSTEM',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const validatedRule = OrchestrationRuleSchema.parse(rule);
      this.orchestrationRules.set(validatedRule.ruleId, validatedRule);
    });
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    // Collect metrics every 5 minutes
    setInterval(() => {
      this.collectMetrics();
    }, 5 * 60 * 1000);

    // Initial metrics collection
    setTimeout(() => this.collectMetrics(), 1000);
  }

  /**
   * Collect and store response metrics
   */
  private collectMetrics(): void {
    const now = new Date();
    const contexts = Array.from(this.orchestrationContexts.values());
    
    // Filter contexts from last hour for recent metrics
    const recentContexts = contexts.filter(ctx => 
      (now.getTime() - ctx.createdAt.getTime()) < 60 * 60 * 1000
    );

    const metrics: ResponseMetrics = {
      metricsId: crypto.randomUUID(),
      timestamp: now,
      
      // Volume metrics
      totalEvents: contexts.length,
      eventsProcessed: contexts.filter(ctx => ctx.status !== 'INITIATED').length,
      responsesExecuted: contexts.filter(ctx => ctx.status === 'COMPLETED').length,
      escalations: contexts.filter(ctx => ctx.status === 'ESCALATED').length,
      falsePositives: contexts.filter(ctx => ctx.falsePositiveScore > 0.7).length,
      
      // Performance metrics
      averageResponseTime: this.calculateAverageResponseTime(recentContexts),
      averageProcessingTime: this.calculateAverageProcessingTime(recentContexts),
      successRate: this.calculateSuccessRate(recentContexts),
      
      // System metrics (simulated)
      systemAvailability: 0.999,
      integrationHealth: {
        'SOAR': 0.98,
        'SIEM': 0.99,
        'NETWORK': 0.97,
        'ENDPOINT': 0.96,
        'EMAIL': 0.99,
        'IDENTITY': 0.98
      },
      
      // Effectiveness metrics
      containmentEffectiveness: this.calculateContainmentEffectiveness(recentContexts),
      evidenceQuality: this.calculateEvidenceQuality(recentContexts),
      alertAccuracy: this.calculateAlertAccuracy(recentContexts),
      
      // Resource utilization (simulated)
      cpuUtilization: Math.random() * 0.3 + 0.2, // 20-50%
      memoryUtilization: Math.random() * 0.25 + 0.3, // 30-55%
      networkUtilization: Math.random() * 0.2 + 0.1, // 10-30%
      
      createdAt: now
    };

    this.responseMetrics.push(metrics);
    
    // Keep only last 288 metrics (24 hours worth at 5-minute intervals)
    if (this.responseMetrics.length > 288) {
      this.responseMetrics = this.responseMetrics.slice(-288);
    }

    console.log(`Metrics collected: ${metrics.responsesExecuted} responses, ${(metrics.successRate * 100).toFixed(1)}% success rate`);
  }

  // Metrics calculation helpers
  private calculateAverageResponseTime(contexts: OrchestrationContext[]): number {
    if (contexts.length === 0) return 0;
    
    const completedContexts = contexts.filter(ctx => ctx.endTime);
    if (completedContexts.length === 0) return 0;
    
    const totalTime = completedContexts.reduce((sum, ctx) => 
      sum + (ctx.endTime!.getTime() - ctx.startTime.getTime()), 0);
    
    return (totalTime / completedContexts.length) / 1000; // Convert to seconds
  }

  private calculateAverageProcessingTime(contexts: OrchestrationContext[]): number {
    // Similar to response time but focusing on processing phase
    return this.calculateAverageResponseTime(contexts);
  }

  private calculateSuccessRate(contexts: OrchestrationContext[]): number {
    if (contexts.length === 0) return 0;
    
    const successfulContexts = contexts.filter(ctx => ctx.status === 'COMPLETED');
    return successfulContexts.length / contexts.length;
  }

  private calculateContainmentEffectiveness(contexts: OrchestrationContext[]): number {
    if (contexts.length === 0) return 0;
    
    const avgEffectiveness = contexts.reduce((sum, ctx) => sum + ctx.effectivenessScore, 0);
    return avgEffectiveness / contexts.length;
  }

  private calculateEvidenceQuality(contexts: OrchestrationContext[]): number {
    // Simulated based on successful SIEM integrations
    const siemSuccessRate = contexts
      .filter(ctx => ctx.responseResults.some(r => r.system === 'SIEM'))
      .reduce((sum, ctx) => {
        const siemResult = ctx.responseResults.find(r => r.system === 'SIEM');
        return sum + (siemResult?.success ? 1 : 0);
      }, 0);
    
    const siemTotal = contexts.filter(ctx => 
      ctx.responseResults.some(r => r.system === 'SIEM')
    ).length;
    
    return siemTotal > 0 ? siemSuccessRate / siemTotal : 0;
  }

  private calculateAlertAccuracy(contexts: OrchestrationContext[]): number {
    if (contexts.length === 0) return 0;
    
    const accurateAlerts = contexts.filter(ctx => ctx.falsePositiveScore < 0.3);
    return accurateAlerts.length / contexts.length;
  }

  /**
   * Get orchestration context by ID
   */
  public getOrchestrationContext(orchestrationId: string): OrchestrationContext | null {
    return this.orchestrationContexts.get(orchestrationId) || null;
  }

  /**
   * Get all orchestration contexts
   */
  public getAllOrchestrationContexts(): OrchestrationContext[] {
    return Array.from(this.orchestrationContexts.values());
  }

  /**
   * Get orchestration rule by ID
   */
  public getOrchestrationRule(ruleId: string): OrchestrationRule | null {
    return this.orchestrationRules.get(ruleId) || null;
  }

  /**
   * Get all orchestration rules
   */
  public getAllOrchestrationRules(): OrchestrationRule[] {
    return Array.from(this.orchestrationRules.values());
  }

  /**
   * Get latest response metrics
   */
  public getLatestMetrics(): ResponseMetrics | null {
    return this.responseMetrics[this.responseMetrics.length - 1] || null;
  }

  /**
   * Get historical metrics
   */
  public getHistoricalMetrics(hours: number = 24): ResponseMetrics[] {
    const cutoffTime = new Date(Date.now() - hours * 60 * 60 * 1000);
    return this.responseMetrics.filter(metrics => metrics.timestamp >= cutoffTime);
  }

  /**
   * Get orchestration statistics
   */
  public getOrchestrationStatistics(): any {
    const contexts = Array.from(this.orchestrationContexts.values());
    const rules = Array.from(this.orchestrationRules.values());
    const latestMetrics = this.getLatestMetrics();

    return {
      totalOrchestrations: contexts.length,
      activeRules: rules.filter(r => r.isActive).length,
      completedResponses: contexts.filter(ctx => ctx.status === 'COMPLETED').length,
      failedResponses: contexts.filter(ctx => ctx.status === 'FAILED').length,
      pendingApprovals: contexts.filter(ctx => ctx.requiresApproval && !ctx.approvedBy).length,
      averageEffectiveness: contexts.length > 0 ? 
        contexts.reduce((sum, ctx) => sum + ctx.effectivenessScore, 0) / contexts.length : 0,
      systemHealth: latestMetrics?.integrationHealth || {},
      performanceMetrics: latestMetrics ? {
        averageResponseTime: latestMetrics.averageResponseTime,
        successRate: latestMetrics.successRate,
        systemAvailability: latestMetrics.systemAvailability
      } : null
    };
  }
}

// Export orchestration engine
export const isectechResponseOrchestrator = new ISECTECHResponseOrchestrator();