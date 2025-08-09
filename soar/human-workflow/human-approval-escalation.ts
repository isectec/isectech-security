/**
 * iSECTECH SOAR Human Approval and Escalation System
 * 
 * Comprehensive human-in-the-loop workflow management for SOAR operations,
 * ensuring proper governance, compliance, and human oversight while maintaining
 * operational efficiency and automated response capabilities.
 * 
 * Features:
 * - Configurable approval workflows with multi-level decision points
 * - Intelligent escalation management with time-based and rule-based triggers
 * - Multi-channel notification system (email, Slack, Teams, SMS, push)
 * - Role-based approval authority and delegation management
 * - Comprehensive audit trails and compliance tracking
 * - Emergency override and break-glass procedures
 * - Real-time dashboard integration and status monitoring
 * - Timeout handling with configurable fallback actions
 */

import { z } from 'zod';
import { EventEmitter } from 'events';

// Core Human Workflow Schemas
const ApprovalStatusSchema = z.enum(['pending', 'approved', 'rejected', 'timeout', 'escalated', 'delegated', 'cancelled']);
const EscalationTriggerSchema = z.enum(['timeout', 'manual', 'auto_rule', 'severity_increase', 'business_impact', 'compliance']);
const NotificationChannelSchema = z.enum(['email', 'slack', 'teams', 'sms', 'push', 'webhook', 'pager']);
const ApprovalTypeSchema = z.enum(['sequential', 'parallel', 'unanimous', 'majority', 'single_required', 'escalation_only']);
const UserRoleSchema = z.enum(['analyst', 'senior_analyst', 'team_lead', 'manager', 'director', 'ciso', 'admin', 'emergency_responder']);

const ISECTECHApprovalRequestSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  
  // Request details
  requestType: z.enum(['case_action', 'playbook_execution', 'integration_action', 'policy_change', 'emergency_response', 'data_access', 'system_modification']),
  requestedBy: z.string(),
  priority: z.enum(['low', 'medium', 'high', 'critical', 'emergency']),
  urgency: z.enum(['low', 'medium', 'high', 'critical']),
  
  // Approval configuration
  approvalType: ApprovalTypeSchema,
  requiredApprovers: z.array(z.string()),
  optionalApprovers: z.array(z.string()).optional(),
  minimumApprovals: z.number().min(1).default(1),
  
  // Context and justification
  businessJustification: z.string(),
  riskAssessment: z.object({
    level: z.enum(['low', 'medium', 'high', 'critical']),
    factors: z.array(z.string()),
    mitigations: z.array(z.string()).optional()
  }),
  
  // Operational details
  operation: z.string(),
  parameters: z.record(z.any()).optional(),
  affectedSystems: z.array(z.string()).optional(),
  expectedImpact: z.string().optional(),
  
  // Status tracking
  status: ApprovalStatusSchema,
  createdAt: z.date(),
  updatedAt: z.date(),
  dueDate: z.date().optional(),
  completedAt: z.date().optional(),
  
  // Approval tracking
  approvals: z.array(z.object({
    approverId: z.string(),
    decision: z.enum(['approve', 'reject', 'request_info', 'delegate']),
    timestamp: z.date(),
    comments: z.string().optional(),
    conditions: z.array(z.string()).optional(),
    delegatedTo: z.string().optional()
  })).default([]),
  
  // Escalation tracking
  escalations: z.array(z.object({
    level: z.number(),
    trigger: EscalationTriggerSchema,
    escalatedAt: z.date(),
    escalatedBy: z.string(),
    escalatedTo: z.array(z.string()),
    reason: z.string(),
    resolved: z.boolean().default(false),
    resolvedAt: z.date().optional()
  })).default([]),
  
  // Notification tracking
  notifications: z.array(z.object({
    id: z.string(),
    channel: NotificationChannelSchema,
    recipient: z.string(),
    sentAt: z.date(),
    acknowledged: z.boolean().default(false),
    acknowledgedAt: z.date().optional()
  })).default([]),
  
  // Compliance and audit
  complianceRequirements: z.array(z.string()).optional(),
  auditTrail: z.array(z.object({
    timestamp: z.date(),
    userId: z.string(),
    action: z.string(),
    details: z.string(),
    ipAddress: z.string().optional()
  })).default([]),
  
  // Timeout handling
  timeoutAction: z.enum(['auto_approve', 'auto_reject', 'escalate', 'extend', 'manual']).default('escalate'),
  timeoutExtensions: z.number().default(0),
  maxTimeoutExtensions: z.number().default(2),
  
  // Emergency override
  emergencyOverride: z.object({
    enabled: z.boolean().default(false),
    overriddenBy: z.string().optional(),
    overriddenAt: z.date().optional(),
    reason: z.string().optional(),
    approvalRequired: z.boolean().default(true)
  }).optional(),
  
  // Metadata
  tags: z.array(z.string()).default([]),
  customFields: z.record(z.any()).optional()
});

const ISECTECHEscalationRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  
  // Rule conditions
  conditions: z.object({
    requestTypes: z.array(z.string()).optional(),
    priorities: z.array(z.string()).optional(),
    urgencyLevels: z.array(z.string()).optional(),
    riskLevels: z.array(z.string()).optional(),
    businessUnits: z.array(z.string()).optional(),
    timeConditions: z.object({
      businessHours: z.boolean().default(true),
      weekends: z.boolean().default(false),
      holidays: z.boolean().default(false)
    }).optional()
  }),
  
  // Escalation configuration
  escalationLevels: z.array(z.object({
    level: z.number(),
    timeoutMinutes: z.number(),
    approvers: z.array(z.string()),
    notificationChannels: z.array(NotificationChannelSchema),
    requiresJustification: z.boolean().default(false),
    autoEscalateOnTimeout: z.boolean().default(true)
  })),
  
  // Emergency escalation
  emergencyEscalation: z.object({
    enabled: z.boolean().default(true),
    triggers: z.array(z.string()),
    recipients: z.array(z.string()),
    immediateNotification: z.boolean().default(true)
  }).optional(),
  
  // Settings
  isActive: z.boolean().default(true),
  priority: z.number().default(10),
  
  createdBy: z.string(),
  createdAt: z.date(),
  updatedAt: z.date()
});

const ISECTECHApprovalPolicySchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  
  // Policy scope
  applicableOperations: z.array(z.string()),
  applicableRoles: z.array(UserRoleSchema).optional(),
  applicableBusinessUnits: z.array(z.string()).optional(),
  
  // Approval requirements
  defaultApprovalType: ApprovalTypeSchema,
  approvalMatrix: z.array(z.object({
    condition: z.string(), // JavaScript expression
    requiredRoles: z.array(UserRoleSchema),
    minimumApprovals: z.number(),
    timeoutMinutes: z.number()
  })),
  
  // Risk-based requirements
  riskBasedApproval: z.object({
    lowRisk: z.object({
      required: z.boolean().default(false),
      roles: z.array(UserRoleSchema).optional()
    }),
    mediumRisk: z.object({
      required: z.boolean().default(true),
      roles: z.array(UserRoleSchema)
    }),
    highRisk: z.object({
      required: z.boolean().default(true),
      roles: z.array(UserRoleSchema),
      multipleApprovals: z.boolean().default(true)
    }),
    criticalRisk: z.object({
      required: z.boolean().default(true),
      roles: z.array(UserRoleSchema),
      unanimousApproval: z.boolean().default(true),
      emergencyProcedures: z.boolean().default(true)
    })
  }),
  
  // Compliance settings
  complianceFrameworks: z.array(z.string()).optional(),
  auditRequirements: z.object({
    retentionDays: z.number().default(2555), // 7 years
    immutableLogs: z.boolean().default(true),
    digitalSignatures: z.boolean().default(false)
  }),
  
  // Delegation rules
  delegationRules: z.object({
    enabled: z.boolean().default(true),
    maxDelegationLevels: z.number().default(2),
    allowedDelegationRoles: z.array(UserRoleSchema).optional(),
    requiresDelegationApproval: z.boolean().default(false)
  }),
  
  isActive: z.boolean().default(true),
  effectiveDate: z.date(),
  expirationDate: z.date().optional(),
  
  createdBy: z.string(),
  createdAt: z.date(),
  updatedAt: z.date()
});

const ISECTECHUserProfileSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string(),
  role: UserRoleSchema,
  department: z.string(),
  businessUnit: z.string().optional(),
  
  // Contact preferences
  notificationPreferences: z.object({
    email: z.boolean().default(true),
    slack: z.boolean().default(false),
    teams: z.boolean().default(false),
    sms: z.boolean().default(false),
    push: z.boolean().default(true)
  }),
  
  // Contact information
  contacts: z.object({
    email: z.string().email(),
    phone: z.string().optional(),
    slackUserId: z.string().optional(),
    teamsUserId: z.string().optional()
  }),
  
  // Approval authority
  approvalAuthority: z.object({
    maxRiskLevel: z.enum(['low', 'medium', 'high', 'critical']),
    maxFinancialImpact: z.number().optional(),
    approvedOperations: z.array(z.string()),
    restrictedOperations: z.array(z.string()).optional()
  }),
  
  // Availability and scheduling
  workingHours: z.object({
    timezone: z.string(),
    businessHours: z.object({
      start: z.string(), // HH:MM format
      end: z.string()
    }),
    workingDays: z.array(z.number()) // 0-6, Sunday = 0
  }),
  
  // Delegation settings
  delegates: z.array(z.object({
    userId: z.string(),
    startDate: z.date(),
    endDate: z.date().optional(),
    operations: z.array(z.string()).optional(), // empty = all operations
    isActive: z.boolean().default(true)
  })).default([]),
  
  // Status
  isActive: z.boolean().default(true),
  lastLogin: z.date().optional(),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

type ISECTECHApprovalRequest = z.infer<typeof ISECTECHApprovalRequestSchema>;
type ISECTECHEscalationRule = z.infer<typeof ISECTECHEscalationRuleSchema>;
type ISECTECHApprovalPolicy = z.infer<typeof ISECTECHApprovalPolicySchema>;
type ISECTECHUserProfile = z.infer<typeof ISECTECHUserProfileSchema>;

interface HumanWorkflowConfig {
  defaultTimeoutMinutes: number;
  maxEscalationLevels: number;
  enableEmergencyOverride: boolean;
  auditRetentionDays: number;
  notificationRetryAttempts: number;
  notificationRetryDelay: number;
  enableRealTimeUpdates: boolean;
  complianceMode: boolean;
  emergencyContactTimeout: number;
}

interface NotificationTemplate {
  id: string;
  name: string;
  type: string;
  subject: string;
  body: string;
  channels: z.infer<typeof NotificationChannelSchema>[];
  variables: Record<string, string>;
}

export class ISECTECHHumanApprovalEscalationEngine extends EventEmitter {
  private approvalRequests = new Map<string, ISECTECHApprovalRequest>();
  private escalationRules = new Map<string, ISECTECHEscalationRule>();
  private approvalPolicies = new Map<string, ISECTECHApprovalPolicy>();
  private userProfiles = new Map<string, ISECTECHUserProfile>();
  private config: HumanWorkflowConfig;
  
  // Notification system
  private notificationTemplates = new Map<string, NotificationTemplate>();
  private notificationQueue: any[] = [];
  private notificationTimer: NodeJS.Timeout | null = null;
  
  // Timeout management
  private timeoutHandlers = new Map<string, NodeJS.Timeout>();
  
  // Real-time monitoring
  private pendingApprovals = new Set<string>();
  private activeEscalations = new Map<string, any>();
  
  // Emergency management
  private emergencyContacts = new Map<string, any>();
  private breakGlassAccess = new Map<string, any>();
  
  // Metrics tracking
  private metrics = {
    totalRequests: 0,
    approvedRequests: 0,
    rejectedRequests: 0,
    timedOutRequests: 0,
    escalatedRequests: 0,
    averageApprovalTime: 0,
    emergencyOverrides: 0,
    complianceViolations: 0,
    startTime: new Date()
  };

  constructor(config: HumanWorkflowConfig) {
    super();
    this.config = config;
    this.initializeDefaultTemplates();
    this.initializeDefaultPolicies();
    this.initializeDefaultUsers();
    this.startNotificationProcessor();
    this.startTimeoutMonitoring();
  }

  // Approval Request Management
  async createApprovalRequest(requestData: Partial<ISECTECHApprovalRequest>): Promise<string> {
    try {
      const requestId = `APPROVAL-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      // Determine approval requirements based on policy
      const policy = await this.getApplicablePolicy(requestData);
      const approvalConfig = await this.calculateApprovalRequirements(requestData, policy);
      
      const request: ISECTECHApprovalRequest = {
        id: requestId,
        title: requestData.title || 'Approval Request',
        description: requestData.description || 'No description provided',
        
        requestType: requestData.requestType || 'case_action',
        requestedBy: requestData.requestedBy || 'system',
        priority: requestData.priority || 'medium',
        urgency: requestData.urgency || 'medium',
        
        approvalType: approvalConfig.type,
        requiredApprovers: approvalConfig.requiredApprovers,
        optionalApprovers: approvalConfig.optionalApprovers,
        minimumApprovals: approvalConfig.minimumApprovals,
        
        businessJustification: requestData.businessJustification || '',
        riskAssessment: requestData.riskAssessment || {
          level: 'medium',
          factors: [],
          mitigations: []
        },
        
        operation: requestData.operation || 'unknown',
        parameters: requestData.parameters,
        affectedSystems: requestData.affectedSystems,
        expectedImpact: requestData.expectedImpact,
        
        status: 'pending',
        createdAt: new Date(),
        updatedAt: new Date(),
        dueDate: this.calculateDueDate(requestData.priority, requestData.urgency),
        
        approvals: [],
        escalations: [],
        notifications: [],
        
        complianceRequirements: await this.getComplianceRequirements(requestData),
        auditTrail: [{
          timestamp: new Date(),
          userId: requestData.requestedBy || 'system',
          action: 'request_created',
          details: `Approval request created: ${requestData.title}`,
          ipAddress: '127.0.0.1'
        }],
        
        timeoutAction: requestData.timeoutAction || 'escalate',
        timeoutExtensions: 0,
        maxTimeoutExtensions: 2,
        
        tags: requestData.tags || [],
        customFields: requestData.customFields
      };

      this.approvalRequests.set(requestId, request);
      this.pendingApprovals.add(requestId);
      this.metrics.totalRequests++;

      // Set up timeout handler
      this.setupTimeoutHandler(request);

      // Send initial notifications
      await this.sendApprovalNotifications(request);

      // Check for immediate escalation triggers
      await this.checkEscalationTriggers(request);

      this.emit('approvalRequestCreated', request);
      return requestId;

    } catch (error) {
      console.error('Error creating approval request:', error);
      throw error;
    }
  }

  async processApprovalDecision(requestId: string, approverId: string, decision: {
    action: 'approve' | 'reject' | 'request_info' | 'delegate';
    comments?: string;
    conditions?: string[];
    delegatedTo?: string;
  }): Promise<void> {
    try {
      const request = this.approvalRequests.get(requestId);
      if (!request) {
        throw new Error(`Approval request ${requestId} not found`);
      }

      if (request.status !== 'pending') {
        throw new Error(`Cannot process decision for request ${requestId} with status ${request.status}`);
      }

      // Validate approver authority
      await this.validateApproverAuthority(approverId, request);

      // Record the approval decision
      const approval = {
        approverId,
        decision: decision.action,
        timestamp: new Date(),
        comments: decision.comments,
        conditions: decision.conditions,
        delegatedTo: decision.delegatedTo
      };

      request.approvals.push(approval);
      request.updatedAt = new Date();

      // Add audit trail entry
      request.auditTrail.push({
        timestamp: new Date(),
        userId: approverId,
        action: `decision_${decision.action}`,
        details: `Decision: ${decision.action}${decision.comments ? ` - ${decision.comments}` : ''}`,
        ipAddress: '127.0.0.1'
      });

      // Handle delegation
      if (decision.action === 'delegate' && decision.delegatedTo) {
        await this.processDelegation(request, approverId, decision.delegatedTo);
        this.emit('approvalDelegated', { request, approverId, delegatedTo: decision.delegatedTo });
        return;
      }

      // Check if approval process is complete
      const completionResult = await this.checkApprovalCompletion(request);
      
      if (completionResult.isComplete) {
        await this.completeApprovalProcess(request, completionResult.finalDecision);
      } else {
        // Send notifications about the decision
        await this.sendDecisionNotifications(request, approval);
      }

      this.emit('approvalDecisionProcessed', { request, approval });

    } catch (error) {
      console.error('Error processing approval decision:', error);
      throw error;
    }
  }

  async escalateRequest(requestId: string, trigger: z.infer<typeof EscalationTriggerSchema>, escalatedBy: string, reason: string): Promise<void> {
    try {
      const request = this.approvalRequests.get(requestId);
      if (!request) {
        throw new Error(`Approval request ${requestId} not found`);
      }

      const escalationRule = await this.getApplicableEscalationRule(request);
      if (!escalationRule) {
        throw new Error(`No escalation rule found for request ${requestId}`);
      }

      const currentLevel = request.escalations.length;
      const nextLevel = escalationRule.escalationLevels.find(level => level.level === currentLevel + 1);
      
      if (!nextLevel) {
        throw new Error(`No escalation level ${currentLevel + 1} defined for request ${requestId}`);
      }

      // Create escalation record
      const escalation = {
        level: nextLevel.level,
        trigger,
        escalatedAt: new Date(),
        escalatedBy,
        escalatedTo: nextLevel.approvers,
        reason,
        resolved: false
      };

      request.escalations.push(escalation);
      request.status = 'escalated';
      request.updatedAt = new Date();

      // Update required approvers to next level
      request.requiredApprovers = nextLevel.approvers;
      
      // Add audit trail entry
      request.auditTrail.push({
        timestamp: new Date(),
        userId: escalatedBy,
        action: 'escalated',
        details: `Escalated to level ${nextLevel.level}: ${reason}`,
        ipAddress: '127.0.0.1'
      });

      // Track active escalation
      this.activeEscalations.set(requestId, escalation);
      this.metrics.escalatedRequests++;

      // Set new timeout for escalated level
      this.setupTimeoutHandler(request, nextLevel.timeoutMinutes);

      // Send escalation notifications
      await this.sendEscalationNotifications(request, escalation);

      this.emit('requestEscalated', { request, escalation });

    } catch (error) {
      console.error('Error escalating request:', error);
      throw error;
    }
  }

  async processEmergencyOverride(requestId: string, overriddenBy: string, reason: string): Promise<void> {
    try {
      if (!this.config.enableEmergencyOverride) {
        throw new Error('Emergency override is disabled');
      }

      const request = this.approvalRequests.get(requestId);
      if (!request) {
        throw new Error(`Approval request ${requestId} not found`);
      }

      // Validate emergency override authority
      await this.validateEmergencyOverrideAuthority(overriddenBy, request);

      // Record emergency override
      request.emergencyOverride = {
        enabled: true,
        overriddenBy,
        overriddenAt: new Date(),
        reason,
        approvalRequired: true
      };

      request.status = 'approved';
      request.completedAt = new Date();
      request.updatedAt = new Date();

      // Add audit trail entry
      request.auditTrail.push({
        timestamp: new Date(),
        userId: overriddenBy,
        action: 'emergency_override',
        details: `Emergency override applied: ${reason}`,
        ipAddress: '127.0.0.1'
      });

      // Clean up timeout handler
      this.clearTimeoutHandler(requestId);
      this.pendingApprovals.delete(requestId);
      this.metrics.emergencyOverrides++;

      // Send emergency override notifications
      await this.sendEmergencyOverrideNotifications(request);

      // Schedule post-override approval if required
      if (request.emergencyOverride.approvalRequired) {
        await this.schedulePostOverrideApproval(request);
      }

      this.emit('emergencyOverrideProcessed', { request, overriddenBy, reason });

    } catch (error) {
      console.error('Error processing emergency override:', error);
      throw error;
    }
  }

  // User and Role Management
  async createUserProfile(userData: Partial<ISECTECHUserProfile>): Promise<string> {
    try {
      const userId = userData.id || `USER-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const user: ISECTECHUserProfile = {
        id: userId,
        email: userData.email || '',
        name: userData.name || '',
        role: userData.role || 'analyst',
        department: userData.department || '',
        businessUnit: userData.businessUnit,
        
        notificationPreferences: userData.notificationPreferences || {
          email: true,
          slack: false,
          teams: false,
          sms: false,
          push: true
        },
        
        contacts: userData.contacts || {
          email: userData.email || '',
          phone: userData.contacts?.phone,
          slackUserId: userData.contacts?.slackUserId,
          teamsUserId: userData.contacts?.teamsUserId
        },
        
        approvalAuthority: userData.approvalAuthority || {
          maxRiskLevel: 'medium',
          approvedOperations: [],
          restrictedOperations: []
        },
        
        workingHours: userData.workingHours || {
          timezone: 'UTC',
          businessHours: { start: '09:00', end: '17:00' },
          workingDays: [1, 2, 3, 4, 5] // Monday to Friday
        },
        
        delegates: userData.delegates || [],
        
        isActive: userData.isActive !== false,
        
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.userProfiles.set(userId, user);
      this.emit('userProfileCreated', user);
      
      return userId;

    } catch (error) {
      console.error('Error creating user profile:', error);
      throw error;
    }
  }

  // Policy Management
  async createApprovalPolicy(policyData: Partial<ISECTECHApprovalPolicy>): Promise<string> {
    try {
      const policyId = `POLICY-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const policy: ISECTECHApprovalPolicy = {
        id: policyId,
        name: policyData.name || 'Unnamed Policy',
        description: policyData.description || '',
        
        applicableOperations: policyData.applicableOperations || [],
        applicableRoles: policyData.applicableRoles,
        applicableBusinessUnits: policyData.applicableBusinessUnits,
        
        defaultApprovalType: policyData.defaultApprovalType || 'single_required',
        approvalMatrix: policyData.approvalMatrix || [],
        
        riskBasedApproval: policyData.riskBasedApproval || {
          lowRisk: { required: false },
          mediumRisk: { required: true, roles: ['team_lead'] },
          highRisk: { required: true, roles: ['manager'], multipleApprovals: true },
          criticalRisk: { required: true, roles: ['director', 'ciso'], unanimousApproval: true, emergencyProcedures: true }
        },
        
        complianceFrameworks: policyData.complianceFrameworks,
        auditRequirements: policyData.auditRequirements || {
          retentionDays: 2555,
          immutableLogs: true,
          digitalSignatures: false
        },
        
        delegationRules: policyData.delegationRules || {
          enabled: true,
          maxDelegationLevels: 2,
          requiresDelegationApproval: false
        },
        
        isActive: policyData.isActive !== false,
        effectiveDate: policyData.effectiveDate || new Date(),
        expirationDate: policyData.expirationDate,
        
        createdBy: policyData.createdBy || 'system',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.approvalPolicies.set(policyId, policy);
      this.emit('approvalPolicyCreated', policy);
      
      return policyId;

    } catch (error) {
      console.error('Error creating approval policy:', error);
      throw error;
    }
  }

  // Escalation Rule Management
  async createEscalationRule(ruleData: Partial<ISECTECHEscalationRule>): Promise<string> {
    try {
      const ruleId = `ESCALATION-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const rule: ISECTECHEscalationRule = {
        id: ruleId,
        name: ruleData.name || 'Unnamed Escalation Rule',
        description: ruleData.description || '',
        
        conditions: ruleData.conditions || {},
        escalationLevels: ruleData.escalationLevels || [],
        emergencyEscalation: ruleData.emergencyEscalation,
        
        isActive: ruleData.isActive !== false,
        priority: ruleData.priority || 10,
        
        createdBy: ruleData.createdBy || 'system',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.escalationRules.set(ruleId, rule);
      this.emit('escalationRuleCreated', rule);
      
      return ruleId;

    } catch (error) {
      console.error('Error creating escalation rule:', error);
      throw error;
    }
  }

  // Query and Reporting Methods
  async getPendingApprovals(userId?: string, filters?: any): Promise<ISECTECHApprovalRequest[]> {
    const pending = Array.from(this.approvalRequests.values())
      .filter(request => request.status === 'pending' || request.status === 'escalated');

    if (userId) {
      return pending.filter(request => 
        request.requiredApprovers.includes(userId) || 
        request.optionalApprovers?.includes(userId)
      );
    }

    return pending;
  }

  async getApprovalHistory(requestId?: string, userId?: string, timeRange?: { start: Date; end: Date }): Promise<ISECTECHApprovalRequest[]> {
    let requests = Array.from(this.approvalRequests.values());

    if (requestId) {
      const request = this.approvalRequests.get(requestId);
      return request ? [request] : [];
    }

    if (userId) {
      requests = requests.filter(request => 
        request.requestedBy === userId ||
        request.approvals.some(approval => approval.approverId === userId)
      );
    }

    if (timeRange) {
      requests = requests.filter(request =>
        request.createdAt >= timeRange.start && request.createdAt <= timeRange.end
      );
    }

    return requests.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getEscalationReport(): Promise<any> {
    const activeEscalations = Array.from(this.activeEscalations.values());
    const allEscalations = Array.from(this.approvalRequests.values())
      .flatMap(request => request.escalations);

    return {
      active: activeEscalations.length,
      total: allEscalations.length,
      byTrigger: this.groupEscalationsByTrigger(allEscalations),
      byLevel: this.groupEscalationsByLevel(allEscalations),
      averageResolutionTime: this.calculateAverageEscalationTime(allEscalations),
      trends: this.calculateEscalationTrends(allEscalations)
    };
  }

  // Private Helper Methods
  private async getApplicablePolicy(requestData: Partial<ISECTECHApprovalRequest>): Promise<ISECTECHApprovalPolicy | null> {
    for (const policy of this.approvalPolicies.values()) {
      if (policy.isActive && this.isPolicyApplicable(policy, requestData)) {
        return policy;
      }
    }
    return null;
  }

  private isPolicyApplicable(policy: ISECTECHApprovalPolicy, requestData: Partial<ISECTECHApprovalRequest>): boolean {
    if (requestData.operation && !policy.applicableOperations.includes(requestData.operation)) {
      return false;
    }
    // Additional policy matching logic would go here
    return true;
  }

  private async calculateApprovalRequirements(requestData: Partial<ISECTECHApprovalRequest>, policy: ISECTECHApprovalPolicy | null): Promise<any> {
    if (!policy) {
      return {
        type: 'single_required' as const,
        requiredApprovers: ['admin'],
        optionalApprovers: [],
        minimumApprovals: 1
      };
    }

    const riskLevel = requestData.riskAssessment?.level || 'medium';
    const riskConfig = policy.riskBasedApproval[`${riskLevel}Risk` as keyof typeof policy.riskBasedApproval];

    return {
      type: policy.defaultApprovalType,
      requiredApprovers: await this.getUsersByRoles(riskConfig.roles || ['team_lead']),
      optionalApprovers: [],
      minimumApprovals: riskConfig.multipleApprovals ? 2 : 1
    };
  }

  private async getUsersByRoles(roles: z.infer<typeof UserRoleSchema>[]): Promise<string[]> {
    const users: string[] = [];
    for (const user of this.userProfiles.values()) {
      if (roles.includes(user.role) && user.isActive) {
        users.push(user.id);
      }
    }
    return users;
  }

  private calculateDueDate(priority?: string, urgency?: string): Date {
    let hours = this.config.defaultTimeoutMinutes / 60;
    
    if (priority === 'critical' || urgency === 'critical') hours = 1;
    else if (priority === 'high' || urgency === 'high') hours = 4;
    else if (priority === 'medium' || urgency === 'medium') hours = 24;
    else hours = 72;

    return new Date(Date.now() + (hours * 60 * 60 * 1000));
  }

  private async getComplianceRequirements(requestData: Partial<ISECTECHApprovalRequest>): Promise<string[]> {
    const requirements: string[] = [];
    
    if (requestData.requestType === 'data_access') {
      requirements.push('GDPR', 'SOX');
    }
    if (requestData.priority === 'critical') {
      requirements.push('SOC2', 'ISO27001');
    }
    
    return requirements;
  }

  private setupTimeoutHandler(request: ISECTECHApprovalRequest, customTimeoutMinutes?: number): void {
    const timeoutMinutes = customTimeoutMinutes || this.config.defaultTimeoutMinutes;
    const timeoutMs = timeoutMinutes * 60 * 1000;

    // Clear existing timeout
    this.clearTimeoutHandler(request.id);

    const timeoutHandler = setTimeout(async () => {
      await this.handleApprovalTimeout(request.id);
    }, timeoutMs);

    this.timeoutHandlers.set(request.id, timeoutHandler);
  }

  private clearTimeoutHandler(requestId: string): void {
    const handler = this.timeoutHandlers.get(requestId);
    if (handler) {
      clearTimeout(handler);
      this.timeoutHandlers.delete(requestId);
    }
  }

  private async handleApprovalTimeout(requestId: string): Promise<void> {
    try {
      const request = this.approvalRequests.get(requestId);
      if (!request || request.status !== 'pending') {
        return;
      }

      switch (request.timeoutAction) {
        case 'auto_approve':
          await this.completeApprovalProcess(request, 'approved');
          break;
        case 'auto_reject':
          await this.completeApprovalProcess(request, 'rejected');
          break;
        case 'escalate':
          await this.escalateRequest(requestId, 'timeout', 'system', 'Approval timeout reached');
          break;
        case 'extend':
          if (request.timeoutExtensions < request.maxTimeoutExtensions) {
            request.timeoutExtensions++;
            this.setupTimeoutHandler(request);
            await this.sendTimeoutExtensionNotifications(request);
          } else {
            await this.escalateRequest(requestId, 'timeout', 'system', 'Maximum timeout extensions reached');
          }
          break;
      }

      this.metrics.timedOutRequests++;

    } catch (error) {
      console.error('Error handling approval timeout:', error);
    }
  }

  private async validateApproverAuthority(approverId: string, request: ISECTECHApprovalRequest): Promise<void> {
    const user = this.userProfiles.get(approverId);
    if (!user || !user.isActive) {
      throw new Error(`User ${approverId} not found or inactive`);
    }

    if (!request.requiredApprovers.includes(approverId) && 
        !request.optionalApprovers?.includes(approverId)) {
      throw new Error(`User ${approverId} is not authorized to approve this request`);
    }

    // Check risk level authority
    const requestRiskLevel = request.riskAssessment.level;
    const userMaxRiskLevel = user.approvalAuthority.maxRiskLevel;
    
    const riskLevels = ['low', 'medium', 'high', 'critical'];
    const userRiskIndex = riskLevels.indexOf(userMaxRiskLevel);
    const requestRiskIndex = riskLevels.indexOf(requestRiskLevel);
    
    if (requestRiskIndex > userRiskIndex) {
      throw new Error(`User ${approverId} does not have authority for ${requestRiskLevel} risk level requests`);
    }
  }

  private async processDelegation(request: ISECTECHApprovalRequest, delegatedBy: string, delegatedTo: string): Promise<void> {
    // Remove original approver and add delegate
    const approverIndex = request.requiredApprovers.indexOf(delegatedBy);
    if (approverIndex !== -1) {
      request.requiredApprovers[approverIndex] = delegatedTo;
    }

    request.auditTrail.push({
      timestamp: new Date(),
      userId: delegatedBy,
      action: 'delegated',
      details: `Approval delegated to ${delegatedTo}`,
      ipAddress: '127.0.0.1'
    });

    // Send delegation notification
    await this.sendDelegationNotifications(request, delegatedBy, delegatedTo);
  }

  private async checkApprovalCompletion(request: ISECTECHApprovalRequest): Promise<{ isComplete: boolean; finalDecision: 'approved' | 'rejected' }> {
    const approvals = request.approvals;
    const approveCount = approvals.filter(a => a.decision === 'approve').length;
    const rejectCount = approvals.filter(a => a.decision === 'reject').length;

    switch (request.approvalType) {
      case 'single_required':
        if (approveCount >= 1) return { isComplete: true, finalDecision: 'approved' };
        if (rejectCount >= 1) return { isComplete: true, finalDecision: 'rejected' };
        break;
      
      case 'unanimous':
        if (approveCount === request.requiredApprovers.length) return { isComplete: true, finalDecision: 'approved' };
        if (rejectCount >= 1) return { isComplete: true, finalDecision: 'rejected' };
        break;
      
      case 'majority':
        const required = Math.ceil(request.requiredApprovers.length / 2);
        if (approveCount >= required) return { isComplete: true, finalDecision: 'approved' };
        if (rejectCount >= required) return { isComplete: true, finalDecision: 'rejected' };
        break;
      
      default:
        if (approveCount >= request.minimumApprovals) return { isComplete: true, finalDecision: 'approved' };
        if (rejectCount >= 1) return { isComplete: true, finalDecision: 'rejected' };
    }

    return { isComplete: false, finalDecision: 'approved' };
  }

  private async completeApprovalProcess(request: ISECTECHApprovalRequest, decision: 'approved' | 'rejected'): Promise<void> {
    request.status = decision;
    request.completedAt = new Date();
    request.updatedAt = new Date();

    // Clean up
    this.clearTimeoutHandler(request.id);
    this.pendingApprovals.delete(request.id);
    this.activeEscalations.delete(request.id);

    // Update metrics
    if (decision === 'approved') {
      this.metrics.approvedRequests++;
    } else {
      this.metrics.rejectedRequests++;
    }

    const duration = request.completedAt.getTime() - request.createdAt.getTime();
    this.updateAverageApprovalTime(duration);

    // Add final audit entry
    request.auditTrail.push({
      timestamp: new Date(),
      userId: 'system',
      action: 'completed',
      details: `Approval process completed with decision: ${decision}`,
      ipAddress: '127.0.0.1'
    });

    // Send completion notifications
    await this.sendCompletionNotifications(request, decision);

    this.emit('approvalProcessCompleted', { request, decision });
  }

  // Notification System
  private initializeDefaultTemplates(): void {
    const templates: NotificationTemplate[] = [
      {
        id: 'approval_request',
        name: 'Approval Request Notification',
        type: 'approval',
        subject: 'Approval Required: {title}',
        body: 'An approval request requires your attention.\n\nTitle: {title}\nRequested by: {requestedBy}\nPriority: {priority}\nDue: {dueDate}\n\nPlease review and approve or reject this request.',
        channels: ['email', 'slack'],
        variables: { title: '', requestedBy: '', priority: '', dueDate: '' }
      },
      {
        id: 'escalation_notification',
        name: 'Escalation Notification',
        type: 'escalation',
        subject: 'ESCALATED: {title}',
        body: 'An approval request has been escalated to you.\n\nTitle: {title}\nEscalation Level: {level}\nReason: {reason}\n\nImmediate attention required.',
        channels: ['email', 'slack', 'push'],
        variables: { title: '', level: '', reason: '' }
      },
      {
        id: 'emergency_override',
        name: 'Emergency Override Notification',
        type: 'emergency',
        subject: 'EMERGENCY OVERRIDE: {title}',
        body: 'An emergency override has been applied.\n\nTitle: {title}\nOverridden by: {overriddenBy}\nReason: {reason}\n\nPost-override approval may be required.',
        channels: ['email', 'slack', 'sms', 'push'],
        variables: { title: '', overriddenBy: '', reason: '' }
      }
    ];

    templates.forEach(template => {
      this.notificationTemplates.set(template.id, template);
    });
  }

  private async sendApprovalNotifications(request: ISECTECHApprovalRequest): Promise<void> {
    const template = this.notificationTemplates.get('approval_request');
    if (!template) return;

    for (const approverId of request.requiredApprovers) {
      await this.sendNotification(approverId, template, {
        title: request.title,
        requestedBy: request.requestedBy,
        priority: request.priority,
        dueDate: request.dueDate?.toISOString() || 'Not specified'
      });
    }
  }

  private async sendEscalationNotifications(request: ISECTECHApprovalRequest, escalation: any): Promise<void> {
    const template = this.notificationTemplates.get('escalation_notification');
    if (!template) return;

    for (const approverId of escalation.escalatedTo) {
      await this.sendNotification(approverId, template, {
        title: request.title,
        level: escalation.level.toString(),
        reason: escalation.reason
      });
    }
  }

  private async sendEmergencyOverrideNotifications(request: ISECTECHApprovalRequest): Promise<void> {
    const template = this.notificationTemplates.get('emergency_override');
    if (!template) return;

    // Notify all stakeholders about emergency override
    const stakeholders = [
      ...request.requiredApprovers,
      request.requestedBy,
      ...this.getEmergencyContacts()
    ];

    for (const stakeholderId of [...new Set(stakeholders)]) {
      await this.sendNotification(stakeholderId, template, {
        title: request.title,
        overriddenBy: request.emergencyOverride?.overriddenBy || 'Unknown',
        reason: request.emergencyOverride?.reason || 'No reason provided'
      });
    }
  }

  private async sendNotification(userId: string, template: NotificationTemplate, variables: Record<string, string>): Promise<void> {
    const user = this.userProfiles.get(userId);
    if (!user || !user.isActive) return;

    // Replace variables in template
    let subject = template.subject;
    let body = template.body;

    Object.entries(variables).forEach(([key, value]) => {
      const placeholder = `{${key}}`;
      subject = subject.replace(new RegExp(placeholder, 'g'), value);
      body = body.replace(new RegExp(placeholder, 'g'), value);
    });

    // Queue notification for each enabled channel
    for (const channel of template.channels) {
      if (user.notificationPreferences[channel]) {
        this.notificationQueue.push({
          id: `NOTIF-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          userId,
          channel,
          subject,
          body,
          timestamp: new Date(),
          attempts: 0
        });
      }
    }
  }

  private startNotificationProcessor(): void {
    this.notificationTimer = setInterval(async () => {
      await this.processNotificationQueue();
    }, 5000); // Process every 5 seconds
  }

  private async processNotificationQueue(): Promise<void> {
    const batch = this.notificationQueue.splice(0, 10); // Process 10 at a time
    
    for (const notification of batch) {
      try {
        await this.deliverNotification(notification);
      } catch (error) {
        notification.attempts++;
        if (notification.attempts < this.config.notificationRetryAttempts) {
          // Re-queue for retry
          setTimeout(() => {
            this.notificationQueue.push(notification);
          }, this.config.notificationRetryDelay);
        }
      }
    }
  }

  private async deliverNotification(notification: any): Promise<void> {
    // In a real implementation, this would integrate with actual notification services
    console.log(`[NOTIFICATION] ${notification.channel.toUpperCase()} to ${notification.userId}: ${notification.subject}`);
    
    // Simulate delivery
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  // Utility Methods
  private updateAverageApprovalTime(duration: number): void {
    const currentAvg = this.metrics.averageApprovalTime;
    const totalRequests = this.metrics.approvedRequests + this.metrics.rejectedRequests;
    
    this.metrics.averageApprovalTime = (currentAvg * (totalRequests - 1) + duration) / totalRequests;
  }

  private getEmergencyContacts(): string[] {
    return Array.from(this.emergencyContacts.keys());
  }

  private groupEscalationsByTrigger(escalations: any[]): Record<string, number> {
    const groups: Record<string, number> = {};
    escalations.forEach(esc => {
      groups[esc.trigger] = (groups[esc.trigger] || 0) + 1;
    });
    return groups;
  }

  private groupEscalationsByLevel(escalations: any[]): Record<string, number> {
    const groups: Record<string, number> = {};
    escalations.forEach(esc => {
      groups[esc.level] = (groups[esc.level] || 0) + 1;
    });
    return groups;
  }

  private calculateAverageEscalationTime(escalations: any[]): number {
    if (escalations.length === 0) return 0;
    
    const resolved = escalations.filter(esc => esc.resolved && esc.resolvedAt);
    if (resolved.length === 0) return 0;
    
    const totalTime = resolved.reduce((sum, esc) => {
      return sum + (esc.resolvedAt.getTime() - esc.escalatedAt.getTime());
    }, 0);
    
    return totalTime / resolved.length;
  }

  private calculateEscalationTrends(escalations: any[]): any {
    // Simple trend calculation - would be more sophisticated in production
    const now = new Date();
    const last30Days = escalations.filter(esc => 
      (now.getTime() - esc.escalatedAt.getTime()) <= (30 * 24 * 60 * 60 * 1000)
    );
    
    return {
      last30Days: last30Days.length,
      trend: last30Days.length > escalations.length * 0.5 ? 'increasing' : 'stable'
    };
  }

  // Initialization methods (simplified)
  private initializeDefaultPolicies(): void {
    // Default policies would be created here
  }

  private initializeDefaultUsers(): void {
    // Default users would be created here
  }

  private startTimeoutMonitoring(): void {
    setInterval(() => {
      // Monitor and handle timeouts
    }, 60000); // Check every minute
  }

  // Additional helper methods would be implemented here...
  private async getApplicableEscalationRule(request: ISECTECHApprovalRequest): Promise<ISECTECHEscalationRule | null> {
    // Implementation would find the most applicable escalation rule
    return Array.from(this.escalationRules.values())[0] || null;
  }

  private async checkEscalationTriggers(request: ISECTECHApprovalRequest): Promise<void> {
    // Implementation would check various escalation triggers
  }

  private async validateEmergencyOverrideAuthority(userId: string, request: ISECTECHApprovalRequest): Promise<void> {
    // Implementation would validate emergency override permissions
  }

  private async schedulePostOverrideApproval(request: ISECTECHApprovalRequest): Promise<void> {
    // Implementation would schedule post-override approval process
  }

  private async sendDecisionNotifications(request: ISECTECHApprovalRequest, approval: any): Promise<void> {
    // Implementation would send notifications about approval decisions
  }

  private async sendDelegationNotifications(request: ISECTECHApprovalRequest, delegatedBy: string, delegatedTo: string): Promise<void> {
    // Implementation would send delegation notifications
  }

  private async sendCompletionNotifications(request: ISECTECHApprovalRequest, decision: string): Promise<void> {
    // Implementation would send completion notifications
  }

  private async sendTimeoutExtensionNotifications(request: ISECTECHApprovalRequest): Promise<void> {
    // Implementation would send timeout extension notifications
  }

  // Public API methods
  getSystemStatus(): any {
    return {
      pendingApprovals: this.pendingApprovals.size,
      activeEscalations: this.activeEscalations.size,
      totalUsers: this.userProfiles.size,
      activePolicies: Array.from(this.approvalPolicies.values()).filter(p => p.isActive).length,
      metrics: this.metrics,
      queuedNotifications: this.notificationQueue.length
    };
  }

  getMetrics(): any {
    return {
      ...this.metrics,
      approvalRate: this.metrics.approvedRequests / Math.max(this.metrics.totalRequests, 1),
      escalationRate: this.metrics.escalatedRequests / Math.max(this.metrics.totalRequests, 1),
      timeoutRate: this.metrics.timedOutRequests / Math.max(this.metrics.totalRequests, 1)
    };
  }

  // Cleanup
  shutdown(): void {
    if (this.notificationTimer) {
      clearInterval(this.notificationTimer);
    }
    
    for (const timeout of this.timeoutHandlers.values()) {
      clearTimeout(timeout);
    }
    
    this.emit('shutdown');
  }
}