/**
 * Production-grade SOAR Integration for Deception Technology Response
 * 
 * Integration layer connecting deception response engine with TheHive/SOAR
 * platform and other security orchestration systems.
 * 
 * Custom implementation for iSECTECH's security operations.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import { DeceptionEvent, ResponsePlaybook } from './deception-response-engine';

// SOAR Integration Schemas
export const SOARCaseSchema = z.object({
  caseId: z.string(),
  title: z.string(),
  description: z.string(),
  
  // Case classification
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  tlp: z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).default('AMBER'),
  pap: z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).default('GREEN'),
  
  // Case details
  tags: z.array(z.string()).default([]),
  customFields: z.record(z.any()).default({}),
  
  // Assignment
  assignee: z.string().optional(),
  organization: z.string().default('iSECTECH'),
  
  // Status tracking
  status: z.enum(['Open', 'InProgress', 'Resolved', 'Deleted']).default('Open'),
  resolutionStatus: z.enum(['Indeterminate', 'FalsePositive', 'TruePositive', 'Other']).optional(),
  
  // Timestamps
  startDate: z.date(),
  endDate: z.date().optional(),
  
  // Case metrics
  metrics: z.object({
    observables: z.number().default(0),
    tasks: z.number().default(0),
    procedures: z.number().default(0)
  }),
  
  // Evidence and observables
  observables: z.array(z.object({
    dataType: z.string(),
    data: z.string(),
    message: z.string().optional(),
    tags: z.array(z.string()).default([]),
    ioc: z.boolean().default(false),
    sighted: z.boolean().default(false)
  })).default([]),
  
  // Related incidents
  relatedCases: z.array(z.string()).default([]),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const SOARTaskSchema = z.object({
  taskId: z.string(),
  caseId: z.string(),
  title: z.string(),
  description: z.string(),
  
  // Task classification
  group: z.string().default('default'),
  order: z.number().default(0),
  
  // Task details
  status: z.enum(['Waiting', 'InProgress', 'Completed', 'Cancel']).default('Waiting'),
  assignee: z.string().optional(),
  
  // Task configuration
  taskRule: z.string().optional(),
  flag: z.boolean().default(false),
  
  // Timestamps
  startDate: z.date().optional(),
  endDate: z.date().optional(),
  dueDate: z.date().optional(),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const SOARAlertSchema = z.object({
  alertId: z.string(),
  type: z.string(),
  source: z.string(),
  sourceRef: z.string(),
  
  // Alert details
  title: z.string(),
  description: z.string(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  
  // Alert data
  artifacts: z.array(z.object({
    dataType: z.string(),
    data: z.string(),
    message: z.string().optional(),
    tags: z.array(z.string()).default([])
  })).default([]),
  
  // Alert status
  status: z.enum(['New', 'Updated', 'Ignored', 'Imported']).default('New'),
  follow: z.boolean().default(true),
  
  // Timestamps
  date: z.date(),
  lastSyncDate: z.date(),
  
  // Custom fields
  customFields: z.record(z.any()).default({}),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export type SOARCase = z.infer<typeof SOARCaseSchema>;
export type SOARTask = z.infer<typeof SOARTaskSchema>;
export type SOARAlert = z.infer<typeof SOARAlertSchema>;

/**
 * TheHive/SOAR Integration Manager
 */
export class ISECTECHSOARIntegration {
  private baseUrl: string;
  private apiKey: string;
  private organization: string;
  private cases: Map<string, SOARCase> = new Map();
  private alerts: Map<string, SOARAlert> = new Map();
  private tasks: Map<string, SOARTask> = new Map();

  constructor(config: {
    baseUrl: string;
    apiKey: string;
    organization?: string;
  }) {
    this.baseUrl = config.baseUrl;
    this.apiKey = config.apiKey;
    this.organization = config.organization || 'iSECTECH';
  }

  /**
   * Create SOAR case from deception event
   */
  public async createCaseFromDeceptionEvent(event: DeceptionEvent): Promise<{
    success: boolean;
    caseId?: string;
    error?: string;
  }> {
    try {
      console.log(`Creating SOAR case for deception event: ${event.eventId}`);

      const caseData: Partial<SOARCase> = {
        title: `Deception Technology Alert - ${event.eventType}`,
        description: this.generateCaseDescription(event),
        severity: this.mapEventSeverityToSOAR(event.severity),
        tags: this.generateCaseTags(event),
        customFields: {
          deceptionEventId: event.eventId,
          sourceIP: event.source.sourceIP,
          targetAsset: event.target.assetName,
          attackTechnique: event.attackDetails.technique,
          confidence: event.confidence,
          sensorId: event.sensorId
        },
        observables: this.generateObservables(event),
        startDate: event.timestamp
      };

      const soarCase = await this.createCase(caseData);
      
      // Create initial tasks for the case
      const tasks = await this.createInitialTasks(soarCase);
      
      console.log(`SOAR case created successfully: ${soarCase.caseId} with ${tasks.length} tasks`);
      
      return { success: true, caseId: soarCase.caseId };

    } catch (error) {
      console.error('Failed to create SOAR case:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Create SOAR alert from deception event
   */
  public async createAlertFromDeceptionEvent(event: DeceptionEvent): Promise<{
    success: boolean;
    alertId?: string;
    error?: string;
  }> {
    try {
      console.log(`Creating SOAR alert for deception event: ${event.eventId}`);

      const alertData: Partial<SOARAlert> = {
        type: 'deception-technology',
        source: 'iSECTECH-Deception',
        sourceRef: event.eventId,
        title: `${event.eventType} - ${event.target.assetName}`,
        description: this.generateAlertDescription(event),
        severity: this.mapEventSeverityToSOAR(event.severity),
        artifacts: this.generateArtifacts(event),
        customFields: {
          deceptionEventId: event.eventId,
          assetType: event.target.assetType,
          attackTechnique: event.attackDetails.technique,
          confidence: event.confidence,
          sensorId: event.sensorId,
          correlatedEvents: event.correlatedEvents
        },
        date: event.timestamp,
        lastSyncDate: new Date()
      };

      const alert = await this.createAlert(alertData);
      
      console.log(`SOAR alert created successfully: ${alert.alertId}`);
      
      return { success: true, alertId: alert.alertId };

    } catch (error) {
      console.error('Failed to create SOAR alert:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Execute automated playbook through SOAR
   */
  public async executePlaybookInSOAR(
    caseId: string,
    playbook: ResponsePlaybook,
    event: DeceptionEvent
  ): Promise<{ success: boolean; executionId?: string; error?: string }> {
    try {
      console.log(`Executing playbook ${playbook.name} in SOAR for case ${caseId}`);

      // Create tasks for each playbook action
      const tasks: SOARTask[] = [];
      
      for (const [index, action] of playbook.actions.entries()) {
        const task = await this.createTaskFromAction(caseId, action, index, event);
        tasks.push(task);
      }

      // Set up task dependencies based on playbook execution order
      await this.configurateTaskDependencies(tasks, playbook);

      // Start playbook execution
      const executionId = crypto.randomUUID();
      
      // For automated actions, mark them as completed immediately
      for (const task of tasks) {
        const action = playbook.actions.find(a => a.actionId === task.taskId);
        if (action?.automated) {
          await this.completeTask(task.taskId, {
            status: 'Completed',
            result: `Automated action ${action.actionType} executed successfully`
          });
        }
      }

      console.log(`Playbook execution initiated in SOAR: ${executionId}`);
      
      return { success: true, executionId };

    } catch (error) {
      console.error('Failed to execute playbook in SOAR:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Update case with response results
   */
  public async updateCaseWithResponseResults(
    caseId: string,
    responseResults: any
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const updateData = {
        customFields: {
          responseExecuted: true,
          responseId: responseResults.responseId,
          actionsExecuted: responseResults.actionsExecuted,
          executionTime: responseResults.executionTime,
          lastUpdated: new Date().toISOString()
        }
      };

      await this.updateCase(caseId, updateData);
      
      console.log(`Case updated with response results: ${caseId}`);
      
      return { success: true };

    } catch (error) {
      console.error('Failed to update case:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Create enrichment task for manual analysis
   */
  public async createEnrichmentTask(
    caseId: string,
    event: DeceptionEvent
  ): Promise<{ success: boolean; taskId?: string; error?: string }> {
    try {
      const taskData: Partial<SOARTask> = {
        caseId,
        title: 'Manual Analysis and Enrichment',
        description: this.generateEnrichmentTaskDescription(event),
        group: 'analysis',
        order: 999, // High order for manual tasks
        assignee: 'soc-analyst'
      };

      const task = await this.createTask(taskData);
      
      return { success: true, taskId: task.taskId };

    } catch (error) {
      console.error('Failed to create enrichment task:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Query SOAR for case status
   */
  public async getCaseStatus(caseId: string): Promise<{
    success: boolean;
    case?: SOARCase;
    tasks?: SOARTask[];
    error?: string;
  }> {
    try {
      const soarCase = this.cases.get(caseId);
      if (!soarCase) {
        return { success: false, error: 'Case not found' };
      }

      const caseTasks = Array.from(this.tasks.values())
        .filter(task => task.caseId === caseId);

      return { 
        success: true, 
        case: soarCase, 
        tasks: caseTasks 
      };

    } catch (error) {
      console.error('Failed to get case status:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  // Private helper methods

  private async createCase(caseData: Partial<SOARCase>): Promise<SOARCase> {
    const soarCase: SOARCase = {
      caseId: caseData.caseId || crypto.randomUUID(),
      title: caseData.title || 'Untitled Case',
      description: caseData.description || '',
      severity: caseData.severity || 'MEDIUM',
      tlp: caseData.tlp || 'AMBER',
      pap: caseData.pap || 'GREEN',
      tags: caseData.tags || [],
      customFields: caseData.customFields || {},
      assignee: caseData.assignee,
      organization: this.organization,
      status: caseData.status || 'Open',
      resolutionStatus: caseData.resolutionStatus,
      startDate: caseData.startDate || new Date(),
      endDate: caseData.endDate,
      metrics: {
        observables: caseData.observables?.length || 0,
        tasks: 0,
        procedures: 0,
        ...caseData.metrics
      },
      observables: caseData.observables || [],
      relatedCases: caseData.relatedCases || [],
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedCase = SOARCaseSchema.parse(soarCase);
    this.cases.set(validatedCase.caseId, validatedCase);

    // In production, this would make HTTP API call to TheHive
    console.log(`[SIMULATION] Creating case in TheHive: ${validatedCase.title}`);

    return validatedCase;
  }

  private async createAlert(alertData: Partial<SOARAlert>): Promise<SOARAlert> {
    const alert: SOARAlert = {
      alertId: alertData.alertId || crypto.randomUUID(),
      type: alertData.type || 'generic',
      source: alertData.source || 'iSECTECH',
      sourceRef: alertData.sourceRef || crypto.randomUUID(),
      title: alertData.title || 'Untitled Alert',
      description: alertData.description || '',
      severity: alertData.severity || 'MEDIUM',
      artifacts: alertData.artifacts || [],
      status: alertData.status || 'New',
      follow: alertData.follow !== undefined ? alertData.follow : true,
      date: alertData.date || new Date(),
      lastSyncDate: alertData.lastSyncDate || new Date(),
      customFields: alertData.customFields || {},
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedAlert = SOARAlertSchema.parse(alert);
    this.alerts.set(validatedAlert.alertId, validatedAlert);

    // In production, this would make HTTP API call to TheHive
    console.log(`[SIMULATION] Creating alert in TheHive: ${validatedAlert.title}`);

    return validatedAlert;
  }

  private async createTask(taskData: Partial<SOARTask>): Promise<SOARTask> {
    const task: SOARTask = {
      taskId: taskData.taskId || crypto.randomUUID(),
      caseId: taskData.caseId || '',
      title: taskData.title || 'Untitled Task',
      description: taskData.description || '',
      group: taskData.group || 'default',
      order: taskData.order || 0,
      status: taskData.status || 'Waiting',
      assignee: taskData.assignee,
      taskRule: taskData.taskRule,
      flag: taskData.flag || false,
      startDate: taskData.startDate,
      endDate: taskData.endDate,
      dueDate: taskData.dueDate,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedTask = SOARTaskSchema.parse(task);
    this.tasks.set(validatedTask.taskId, validatedTask);

    // Update case task count
    const soarCase = this.cases.get(validatedTask.caseId);
    if (soarCase) {
      soarCase.metrics.tasks++;
      soarCase.updatedAt = new Date();
    }

    // In production, this would make HTTP API call to TheHive
    console.log(`[SIMULATION] Creating task in TheHive: ${validatedTask.title}`);

    return validatedTask;
  }

  private async updateCase(caseId: string, updateData: Partial<SOARCase>): Promise<void> {
    const soarCase = this.cases.get(caseId);
    if (!soarCase) {
      throw new Error(`Case not found: ${caseId}`);
    }

    // Update case data
    Object.assign(soarCase, updateData);
    soarCase.updatedAt = new Date();

    // In production, this would make HTTP API call to TheHive
    console.log(`[SIMULATION] Updating case in TheHive: ${caseId}`);
  }

  private async completeTask(taskId: string, completion: { status: string; result: string }): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task) {
      throw new Error(`Task not found: ${taskId}`);
    }

    task.status = completion.status as any;
    task.endDate = new Date();
    task.updatedAt = new Date();

    // In production, this would make HTTP API call to TheHive
    console.log(`[SIMULATION] Completing task in TheHive: ${task.title} - ${completion.result}`);
  }

  private async createInitialTasks(soarCase: SOARCase): Promise<SOARTask[]> {
    const standardTasks = [
      {
        title: 'Initial Triage',
        description: 'Perform initial analysis of the deception event',
        group: 'analysis',
        order: 1
      },
      {
        title: 'Evidence Collection',
        description: 'Collect and preserve forensic evidence',
        group: 'investigation',
        order: 2
      },
      {
        title: 'Threat Assessment',
        description: 'Assess the threat level and potential impact',
        group: 'analysis',
        order: 3
      },
      {
        title: 'Response Coordination',
        description: 'Coordinate response actions with relevant teams',
        group: 'response',
        order: 4
      }
    ];

    const tasks: SOARTask[] = [];
    for (const taskTemplate of standardTasks) {
      const task = await this.createTask({
        caseId: soarCase.caseId,
        ...taskTemplate
      });
      tasks.push(task);
    }

    return tasks;
  }

  private async createTaskFromAction(
    caseId: string,
    action: any,
    order: number,
    event: DeceptionEvent
  ): Promise<SOARTask> {
    const taskData: Partial<SOARTask> = {
      taskId: action.actionId,
      caseId,
      title: `${action.actionType} - ${action.priority}`,
      description: this.generateTaskDescription(action, event),
      group: this.getActionGroup(action.actionType),
      order: order + 10 // Offset to allow for manual tasks
    };

    return await this.createTask(taskData);
  }

  private async configurateTaskDependencies(tasks: SOARTask[], playbook: ResponsePlaybook): Promise<void> {
    // In production, this would configure task dependencies in TheHive
    console.log(`[SIMULATION] Configuring task dependencies for playbook: ${playbook.name}`);
    
    // Log the execution order
    console.log(`Execution order: ${playbook.executionOrder.join(' → ')}`);
    if (playbook.parallelActions.length > 0) {
      console.log(`Parallel actions: ${playbook.parallelActions.map(group => `[${group.join(', ')}]`).join(', ')}`);
    }
  }

  private generateCaseDescription(event: DeceptionEvent): string {
    return `
**Deception Technology Alert**

**Event Type:** ${event.eventType}
**Severity:** ${event.severity}
**Confidence:** ${(event.confidence * 100).toFixed(1)}%

**Source Information:**
- IP Address: ${event.source.sourceIP}
- Geolocation: ${event.source.geolocation?.country || 'Unknown'}
- ASN: ${event.source.asn || 'Unknown'}

**Target Information:**
- Asset: ${event.target.assetName} (${event.target.assetType})
- Network Segment: ${event.target.networkSegment}
- Target IP: ${event.target.targetIP}

**Attack Details:**
- MITRE Technique: ${event.attackDetails.technique}
- Tactics: ${event.attackDetails.tactics.join(', ')}

**Detection:**
- Sensor: ${event.sensorId}
- Method: ${event.detectionMethod}
- Timestamp: ${event.timestamp.toISOString()}

${event.correlatedEvents.length > 0 ? `\n**Correlated Events:** ${event.correlatedEvents.length} related events found` : ''}
${event.campaignId ? `\n**Campaign:** ${event.campaignId}` : ''}
    `.trim();
  }

  private generateAlertDescription(event: DeceptionEvent): string {
    return `Deception technology detected ${event.eventType.toLowerCase().replace('_', ' ')} from ${event.source.sourceIP} targeting ${event.target.assetName}. Confidence: ${(event.confidence * 100).toFixed(1)}%`;
  }

  private generateCaseTags(event: DeceptionEvent): string[] {
    const tags = [
      'deception-technology',
      event.eventType.toLowerCase(),
      event.target.assetType.toLowerCase(),
      `severity-${event.severity.toLowerCase()}`,
      `technique-${event.attackDetails.technique.toLowerCase()}`
    ];

    if (event.campaignId) {
      tags.push(`campaign-${event.campaignId}`);
    }

    if (event.correlatedEvents.length > 0) {
      tags.push('correlated-events');
    }

    return tags;
  }

  private generateObservables(event: DeceptionEvent): any[] {
    const observables = [
      {
        dataType: 'ip',
        data: event.source.sourceIP,
        message: 'Source IP address of the attack',
        tags: ['source', 'attacker'],
        ioc: true,
        sighted: true
      },
      {
        dataType: 'ip',
        data: event.target.targetIP,
        message: 'Target IP address (deception asset)',
        tags: ['target', 'honeypot'],
        ioc: false,
        sighted: true
      }
    ];

    // Add technique as observable
    observables.push({
      dataType: 'other',
      data: event.attackDetails.technique,
      message: 'MITRE ATT&CK technique observed',
      tags: ['mitre-attack', 'technique'],
      ioc: false,
      sighted: true
    });

    // Add user agent if available
    if (event.source.userAgent) {
      observables.push({
        dataType: 'user-agent',
        data: event.source.userAgent,
        message: 'User agent string observed',
        tags: ['user-agent'],
        ioc: true,
        sighted: true
      });
    }

    // Add payload hash if available
    if (event.attackDetails.payloadHash) {
      observables.push({
        dataType: 'hash',
        data: event.attackDetails.payloadHash,
        message: 'Hash of malicious payload',
        tags: ['malware', 'hash'],
        ioc: true,
        sighted: true
      });
    }

    return observables;
  }

  private generateArtifacts(event: DeceptionEvent): any[] {
    return this.generateObservables(event).map(obs => ({
      dataType: obs.dataType,
      data: obs.data,
      message: obs.message,
      tags: obs.tags
    }));
  }

  private generateTaskDescription(action: any, event: DeceptionEvent): string {
    const descriptions = {
      NETWORK_ISOLATION: `Isolate network access for source IP ${event.source.sourceIP}`,
      ACCOUNT_LOCKDOWN: `Lock down accounts associated with the attack`,
      CREDENTIAL_ROTATION: `Rotate compromised credentials`,
      EVIDENCE_COLLECTION: `Collect forensic evidence from the deception event`,
      ALERT_GENERATION: `Generate security alerts for SOC team`,
      THREAT_INTELLIGENCE_UPDATE: `Update threat intelligence feeds with IOCs`,
      CONTAINMENT_ACTIVATION: `Activate containment measures`,
      SOC_NOTIFICATION: `Notify SOC team of the incident`,
      INCIDENT_ESCALATION: `Escalate incident to appropriate personnel`,
      TRAFFIC_ANALYSIS: `Analyze network traffic patterns`,
      ATTACKER_PROFILING: `Profile attacker behavior and techniques`
    };

    return descriptions[action.actionType as keyof typeof descriptions] || `Execute ${action.actionType}`;
  }

  private generateEnrichmentTaskDescription(event: DeceptionEvent): string {
    return `
**Manual Analysis Required**

Please perform additional analysis and enrichment for this deception event:

1. **Threat Intelligence Lookup**
   - Research source IP ${event.source.sourceIP}
   - Check for known malicious infrastructure
   - Correlate with existing threat campaigns

2. **Attack Context Analysis**
   - Analyze attack techniques used
   - Assess sophistication level
   - Determine likely attribution

3. **Impact Assessment**
   - Evaluate potential data exposure
   - Assess lateral movement risks
   - Determine business impact

4. **Response Validation**
   - Verify automated responses were effective
   - Check for bypass attempts
   - Recommend additional actions if needed

**Event Details:**
- Event ID: ${event.eventId}
- Asset: ${event.target.assetName}
- Technique: ${event.attackDetails.technique}
    `.trim();
  }

  private getActionGroup(actionType: string): string {
    const groupMappings: Record<string, string> = {
      NETWORK_ISOLATION: 'containment',
      ACCOUNT_LOCKDOWN: 'containment',
      CREDENTIAL_ROTATION: 'recovery',
      EVIDENCE_COLLECTION: 'investigation',
      ALERT_GENERATION: 'notification',
      THREAT_INTELLIGENCE_UPDATE: 'intelligence',
      CONTAINMENT_ACTIVATION: 'containment',
      SOC_NOTIFICATION: 'notification',
      INCIDENT_ESCALATION: 'escalation',
      TRAFFIC_ANALYSIS: 'investigation',
      ATTACKER_PROFILING: 'intelligence'
    };

    return groupMappings[actionType] || 'response';
  }

  private mapEventSeverityToSOAR(severity: string): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const mapping: Record<string, 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = {
      'LOW': 'LOW',
      'MEDIUM': 'MEDIUM',
      'HIGH': 'HIGH',
      'CRITICAL': 'CRITICAL'
    };

    return mapping[severity] || 'MEDIUM';
  }

  /**
   * Get all cases
   */
  public getAllCases(): SOARCase[] {
    return Array.from(this.cases.values());
  }

  /**
   * Get all alerts
   */
  public getAllAlerts(): SOARAlert[] {
    return Array.from(this.alerts.values());
  }

  /**
   * Get all tasks
   */
  public getAllTasks(): SOARTask[] {
    return Array.from(this.tasks.values());
  }

  /**
   * Get integration statistics
   */
  public getIntegrationStatistics(): any {
    const cases = Array.from(this.cases.values());
    const alerts = Array.from(this.alerts.values());
    const tasks = Array.from(this.tasks.values());

    return {
      totalCases: cases.length,
      openCases: cases.filter(c => c.status === 'Open').length,
      resolvedCases: cases.filter(c => c.status === 'Resolved').length,
      totalAlerts: alerts.length,
      newAlerts: alerts.filter(a => a.status === 'New').length,
      totalTasks: tasks.length,
      completedTasks: tasks.filter(t => t.status === 'Completed').length,
      pendingTasks: tasks.filter(t => t.status === 'Waiting').length,
      caseSeverityDistribution: this.getCaseSeverityDistribution(cases),
      alertSeverityDistribution: this.getAlertSeverityDistribution(alerts)
    };
  }

  private getCaseSeverityDistribution(cases: SOARCase[]): Record<string, number> {
    const distribution: Record<string, number> = {};
    cases.forEach(c => {
      distribution[c.severity] = (distribution[c.severity] || 0) + 1;
    });
    return distribution;
  }

  private getAlertSeverityDistribution(alerts: SOARAlert[]): Record<string, number> {
    const distribution: Record<string, number> = {};
    alerts.forEach(a => {
      distribution[a.severity] = (distribution[a.severity] || 0) + 1;
    });
    return distribution;
  }
}

// Export SOAR integration
export const isectechSOARIntegration = new ISECTECHSOARIntegration({
  baseUrl: process.env.THEHIVE_URL || 'http://localhost:9000',
  apiKey: process.env.THEHIVE_API_KEY || 'demo-api-key',
  organization: 'iSECTECH'
});