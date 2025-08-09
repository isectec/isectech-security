/**
 * iSECTECH SOAR Automated Case Management System
 * 
 * Comprehensive case management for security incidents with automated workflows,
 * evidence preservation, collaboration tools, and investigation tracking.
 * 
 * Features:
 * - Automated case creation from security events
 * - Evidence collection and chain of custody
 * - Investigation timeline and milestone tracking
 * - Multi-analyst collaboration with real-time updates
 * - Knowledge base integration and case similarity detection
 * - SLA monitoring and automated escalation
 * - Advanced analytics and reporting
 */

import { z } from 'zod';
import { EventEmitter } from 'events';

// Core Schemas
const CasePrioritySchema = z.enum(['critical', 'high', 'medium', 'low']);
const CaseStatusSchema = z.enum(['new', 'assigned', 'investigating', 'awaiting_approval', 'resolved', 'closed', 'escalated']);
const CaseCategorySchema = z.enum(['malware', 'phishing', 'data_breach', 'unauthorized_access', 'ddos', 'insider_threat', 'compliance_violation', 'other']);
const EvidenceTypeSchema = z.enum(['log_file', 'network_capture', 'memory_dump', 'disk_image', 'email', 'document', 'screenshot', 'artifact']);

const ISECTECHCaseSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  category: CaseCategorySchema,
  priority: CasePrioritySchema,
  status: CaseStatusSchema,
  severity: z.number().min(1).max(10),
  
  // Assignment and ownership
  assignedAnalyst: z.string().optional(),
  assignedTeam: z.string().optional(),
  caseOwner: z.string(),
  
  // Timestamps
  createdAt: z.date(),
  updatedAt: z.date(),
  dueDate: z.date().optional(),
  resolvedAt: z.date().optional(),
  closedAt: z.date().optional(),
  
  // Source information
  sourceType: z.enum(['alert', 'manual', 'automated', 'external_report']),
  sourceId: z.string().optional(),
  affectedAssets: z.array(z.string()),
  
  // Investigation tracking
  investigationPhase: z.enum(['initial_triage', 'containment', 'investigation', 'eradication', 'recovery', 'lessons_learned']),
  milestones: z.array(z.object({
    id: z.string(),
    name: z.string(),
    description: z.string(),
    targetDate: z.date(),
    completedAt: z.date().optional(),
    completedBy: z.string().optional()
  })),
  
  // Evidence and artifacts
  evidenceIds: z.array(z.string()),
  artifactCount: z.number().default(0),
  
  // Collaboration
  collaborators: z.array(z.string()),
  notes: z.array(z.object({
    id: z.string(),
    authorId: z.string(),
    content: z.string(),
    timestamp: z.date(),
    isPrivate: z.boolean().default(false)
  })),
  
  // Escalation and SLA
  slaTarget: z.number(), // hours
  escalationLevel: z.number().default(0),
  escalationHistory: z.array(z.object({
    level: z.number(),
    escalatedAt: z.date(),
    escalatedBy: z.string(),
    reason: z.string()
  })),
  
  // Metrics and analytics
  timeToAssignment: z.number().optional(), // minutes
  timeToContainment: z.number().optional(), // minutes
  timeToResolution: z.number().optional(), // minutes
  
  // Related cases and knowledge
  relatedCases: z.array(z.string()),
  similarCases: z.array(z.object({
    caseId: z.string(),
    similarity: z.number(),
    matchingCriteria: z.array(z.string())
  })),
  
  // Tags and metadata
  tags: z.array(z.string()),
  customFields: z.record(z.any()).optional(),
  
  // Audit trail
  auditLog: z.array(z.object({
    timestamp: z.date(),
    userId: z.string(),
    action: z.string(),
    details: z.string(),
    ipAddress: z.string().optional()
  }))
});

const ISECTECHEvidenceSchema = z.object({
  id: z.string(),
  caseId: z.string(),
  type: EvidenceTypeSchema,
  name: z.string(),
  description: z.string(),
  
  // File information
  fileName: z.string().optional(),
  filePath: z.string().optional(),
  fileSize: z.number().optional(),
  mimeType: z.string().optional(),
  checksumMD5: z.string().optional(),
  checksumSHA256: z.string().optional(),
  
  // Chain of custody
  collectedBy: z.string(),
  collectedAt: z.date(),
  source: z.string(),
  custodyChain: z.array(z.object({
    handedOverBy: z.string(),
    handedOverTo: z.string(),
    timestamp: z.date(),
    reason: z.string(),
    digitalSignature: z.string()
  })),
  
  // Analysis results
  analysisResults: z.array(z.object({
    tool: z.string(),
    timestamp: z.date(),
    result: z.any(),
    confidence: z.number().min(0).max(1)
  })),
  
  // Metadata
  tags: z.array(z.string()),
  isEncrypted: z.boolean().default(false),
  retentionPeriod: z.number(), // days
  
  // Access control
  accessLevel: z.enum(['public', 'team', 'restricted', 'classified']),
  authorizedUsers: z.array(z.string()),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

const CaseTemplateSchema = z.object({
  id: z.string(),
  name: z.string(),
  category: CaseCategorySchema,
  description: z.string(),
  defaultPriority: CasePrioritySchema,
  defaultSLA: z.number(),
  
  // Template fields
  requiredFields: z.array(z.string()),
  recommendedFields: z.array(z.string()),
  defaultMilestones: z.array(z.object({
    name: z.string(),
    description: z.string(),
    targetDaysFromCreation: z.number()
  })),
  
  // Automation rules
  autoAssignmentRules: z.array(z.object({
    condition: z.string(),
    assignTo: z.string(),
    priority: z.number()
  })),
  
  // Playbook integration
  recommendedPlaybooks: z.array(z.string()),
  
  isActive: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date()
});

const CaseMetricsSchema = z.object({
  caseId: z.string(),
  
  // Time metrics
  creationTime: z.date(),
  firstResponseTime: z.date().optional(),
  assignmentTime: z.date().optional(),
  containmentTime: z.date().optional(),
  resolutionTime: z.date().optional(),
  closureTime: z.date().optional(),
  
  // Performance metrics
  slaCompliance: z.boolean(),
  escalationCount: z.number().default(0),
  reopenCount: z.number().default(0),
  
  // Resource metrics
  analystHours: z.number().default(0),
  toolsUsed: z.array(z.string()),
  evidenceCount: z.number().default(0),
  
  // Quality metrics
  customerSatisfaction: z.number().min(1).max(5).optional(),
  resolutionAccuracy: z.number().min(0).max(1).optional(),
  
  // Cost metrics
  estimatedCost: z.number().optional(),
  businessImpact: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  
  calculatedAt: z.date(),
  lastUpdated: z.date()
});

type ISECTECHCase = z.infer<typeof ISECTECHCaseSchema>;
type ISECTECHEvidence = z.infer<typeof ISECTECHEvidenceSchema>;
type CaseTemplate = z.infer<typeof CaseTemplateSchema>;
type CaseMetrics = z.infer<typeof CaseMetricsSchema>;

interface CaseAutomationConfig {
  enableAutoAssignment: boolean;
  enableAutoEscalation: boolean;
  enableSimilarCaseDetection: boolean;
  enableKnowledgeBaseSuggestions: boolean;
  enableRealTimeNotifications: boolean;
  slaWarningThresholds: {
    yellow: number; // percentage of SLA
    red: number;    // percentage of SLA
  };
  maxEscalationLevels: number;
  evidenceRetentionDays: number;
}

export class ISECTECHAutomatedCaseManager extends EventEmitter {
  private cases = new Map<string, ISECTECHCase>();
  private evidence = new Map<string, ISECTECHEvidence>();
  private templates = new Map<string, CaseTemplate>();
  private metrics = new Map<string, CaseMetrics>();
  private config: CaseAutomationConfig;
  private knowledgeBase = new Map<string, any>();
  private escalationRules = new Map<string, any[]>();
  
  // Circuit breakers and rate limiting
  private circuitBreaker = {
    isOpen: false,
    failureCount: 0,
    lastFailureTime: 0,
    resetTimeout: 60000
  };
  
  private rateLimiter = new Map<string, number[]>();
  private readonly rateLimitWindow = 60000; // 1 minute
  private readonly rateLimitMax = 100; // requests per minute

  constructor(config: CaseAutomationConfig) {
    super();
    this.config = config;
    this.initializeTemplates();
    this.setupEventHandlers();
    this.setupSLAMonitoring();
  }

  private initializeTemplates(): void {
    const defaultTemplates: CaseTemplate[] = [
      {
        id: 'malware-incident',
        name: 'Malware Incident Response',
        category: 'malware',
        description: 'Template for handling malware infections and containment',
        defaultPriority: 'high',
        defaultSLA: 4, // 4 hours
        requiredFields: ['affectedAssets', 'malwareType', 'detectionMethod'],
        recommendedFields: ['networkSegments', 'userAccounts', 'systemBackups'],
        defaultMilestones: [
          { name: 'Initial Containment', description: 'Isolate affected systems', targetDaysFromCreation: 0.17 }, // 4 hours
          { name: 'Malware Analysis', description: 'Analyze malware samples', targetDaysFromCreation: 1 },
          { name: 'System Remediation', description: 'Clean and restore systems', targetDaysFromCreation: 2 },
          { name: 'Post-Incident Review', description: 'Document lessons learned', targetDaysFromCreation: 7 }
        ],
        autoAssignmentRules: [
          { condition: 'severity >= 8', assignTo: 'senior-malware-analyst', priority: 1 },
          { condition: 'category == "ransomware"', assignTo: 'incident-commander', priority: 0 }
        ],
        recommendedPlaybooks: ['malware-containment', 'forensic-analysis'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      },
      {
        id: 'phishing-incident',
        name: 'Phishing Email Response',
        category: 'phishing',
        description: 'Template for phishing email investigations',
        defaultPriority: 'medium',
        defaultSLA: 8, // 8 hours
        requiredFields: ['emailSender', 'recipientCount', 'emailContent'],
        recommendedFields: ['clickThroughRate', 'compromisedCredentials'],
        defaultMilestones: [
          { name: 'Email Analysis', description: 'Analyze phishing email', targetDaysFromCreation: 0.25 }, // 6 hours
          { name: 'User Notification', description: 'Notify affected users', targetDaysFromCreation: 0.5 }, // 12 hours
          { name: 'Credential Reset', description: 'Reset compromised credentials', targetDaysFromCreation: 1 },
          { name: 'Security Awareness', description: 'Update security training', targetDaysFromCreation: 5 }
        ],
        autoAssignmentRules: [
          { condition: 'recipientCount > 100', assignTo: 'senior-email-analyst', priority: 1 },
          { condition: 'category == "spear_phishing"', assignTo: 'threat-intelligence-analyst', priority: 0 }
        ],
        recommendedPlaybooks: ['phishing-response', 'credential-management'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      },
      {
        id: 'data-breach-incident',
        name: 'Data Breach Investigation',
        category: 'data_breach',
        description: 'Template for data breach incidents and compliance',
        defaultPriority: 'critical',
        defaultSLA: 2, // 2 hours
        requiredFields: ['dataTypes', 'recordCount', 'exposureMethod'],
        recommendedFields: ['regulatoryRequirements', 'customerNotification'],
        defaultMilestones: [
          { name: 'Immediate Containment', description: 'Stop data exposure', targetDaysFromCreation: 0.08 }, // 2 hours
          { name: 'Impact Assessment', description: 'Assess breach scope', targetDaysFromCreation: 0.25 }, // 6 hours
          { name: 'Regulatory Notification', description: 'Notify authorities', targetDaysFromCreation: 3 }, // 72 hours
          { name: 'Customer Communication', description: 'Notify affected customers', targetDaysFromCreation: 7 }
        ],
        autoAssignmentRules: [
          { condition: 'recordCount > 10000', assignTo: 'incident-commander', priority: 0 },
          { condition: 'dataTypes includes "pii"', assignTo: 'privacy-officer', priority: 1 }
        ],
        recommendedPlaybooks: ['data-breach-response', 'regulatory-compliance'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    ];

    defaultTemplates.forEach(template => {
      this.templates.set(template.id, template);
    });
  }

  private setupEventHandlers(): void {
    this.on('caseCreated', this.handleCaseCreated.bind(this));
    this.on('caseAssigned', this.handleCaseAssigned.bind(this));
    this.on('caseEscalated', this.handleCaseEscalated.bind(this));
    this.on('milestoneCompleted', this.handleMilestoneCompleted.bind(this));
    this.on('evidenceAdded', this.handleEvidenceAdded.bind(this));
    this.on('slaWarning', this.handleSLAWarning.bind(this));
  }

  private setupSLAMonitoring(): void {
    setInterval(() => {
      this.monitorSLAs();
    }, 60000); // Check every minute
  }

  async createCase(caseData: Partial<ISECTECHCase>, templateId?: string): Promise<ISECTECHCase> {
    try {
      if (!this.checkRateLimit('createCase')) {
        throw new Error('Rate limit exceeded for case creation');
      }

      const template = templateId ? this.templates.get(templateId) : null;
      const caseId = `CASE-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const newCase: ISECTECHCase = {
        id: caseId,
        title: caseData.title || 'Untitled Security Incident',
        description: caseData.description || 'No description provided',
        category: caseData.category || template?.category || 'other',
        priority: caseData.priority || template?.defaultPriority || 'medium',
        status: 'new',
        severity: caseData.severity || 5,
        
        assignedAnalyst: caseData.assignedAnalyst,
        assignedTeam: caseData.assignedTeam,
        caseOwner: caseData.caseOwner || 'system',
        
        createdAt: new Date(),
        updatedAt: new Date(),
        dueDate: template ? new Date(Date.now() + (template.defaultSLA * 60 * 60 * 1000)) : undefined,
        
        sourceType: caseData.sourceType || 'manual',
        sourceId: caseData.sourceId,
        affectedAssets: caseData.affectedAssets || [],
        
        investigationPhase: 'initial_triage',
        milestones: template?.defaultMilestones.map(m => ({
          id: `milestone-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          name: m.name,
          description: m.description,
          targetDate: new Date(Date.now() + (m.targetDaysFromCreation * 24 * 60 * 60 * 1000))
        })) || [],
        
        evidenceIds: [],
        artifactCount: 0,
        
        collaborators: [],
        notes: [],
        
        slaTarget: template?.defaultSLA || 24,
        escalationLevel: 0,
        escalationHistory: [],
        
        relatedCases: [],
        similarCases: [],
        
        tags: caseData.tags || [],
        customFields: caseData.customFields,
        
        auditLog: [{
          timestamp: new Date(),
          userId: 'system',
          action: 'case_created',
          details: `Case created using template: ${templateId || 'none'}`,
          ipAddress: '127.0.0.1'
        }]
      };

      this.cases.set(caseId, newCase);
      
      // Initialize metrics tracking
      const metrics: CaseMetrics = {
        caseId,
        creationTime: new Date(),
        slaCompliance: true,
        escalationCount: 0,
        reopenCount: 0,
        analystHours: 0,
        toolsUsed: [],
        evidenceCount: 0,
        calculatedAt: new Date(),
        lastUpdated: new Date()
      };
      this.metrics.set(caseId, metrics);

      // Auto-assignment logic
      if (this.config.enableAutoAssignment && template) {
        await this.processAutoAssignment(newCase, template);
      }

      // Similar case detection
      if (this.config.enableSimilarCaseDetection) {
        await this.detectSimilarCases(newCase);
      }

      this.emit('caseCreated', newCase);
      return newCase;

    } catch (error) {
      this.handleError('createCase', error as Error);
      throw error;
    }
  }

  async addEvidence(caseId: string, evidenceData: Partial<ISECTECHEvidence>): Promise<ISECTECHEvidence> {
    try {
      const case_ = this.cases.get(caseId);
      if (!case_) {
        throw new Error(`Case ${caseId} not found`);
      }

      const evidenceId = `EVIDENCE-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const evidence: ISECTECHEvidence = {
        id: evidenceId,
        caseId,
        type: evidenceData.type || 'artifact',
        name: evidenceData.name || 'Unnamed Evidence',
        description: evidenceData.description || 'No description provided',
        
        fileName: evidenceData.fileName,
        filePath: evidenceData.filePath,
        fileSize: evidenceData.fileSize,
        mimeType: evidenceData.mimeType,
        checksumMD5: evidenceData.checksumMD5,
        checksumSHA256: evidenceData.checksumSHA256,
        
        collectedBy: evidenceData.collectedBy || 'system',
        collectedAt: evidenceData.collectedAt || new Date(),
        source: evidenceData.source || 'manual_upload',
        custodyChain: [{
          handedOverBy: 'system',
          handedOverTo: evidenceData.collectedBy || 'system',
          timestamp: new Date(),
          reason: 'Initial evidence collection',
          digitalSignature: this.generateDigitalSignature(evidenceId)
        }],
        
        analysisResults: [],
        
        tags: evidenceData.tags || [],
        isEncrypted: evidenceData.isEncrypted || false,
        retentionPeriod: evidenceData.retentionPeriod || this.config.evidenceRetentionDays,
        
        accessLevel: evidenceData.accessLevel || 'team',
        authorizedUsers: evidenceData.authorizedUsers || [],
        
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.evidence.set(evidenceId, evidence);
      
      // Update case
      case_.evidenceIds.push(evidenceId);
      case_.artifactCount++;
      case_.updatedAt = new Date();
      case_.auditLog.push({
        timestamp: new Date(),
        userId: evidenceData.collectedBy || 'system',
        action: 'evidence_added',
        details: `Evidence added: ${evidence.name} (${evidence.type})`,
        ipAddress: '127.0.0.1'
      });

      // Update metrics
      const metrics = this.metrics.get(caseId);
      if (metrics) {
        metrics.evidenceCount++;
        metrics.lastUpdated = new Date();
      }

      this.emit('evidenceAdded', { case: case_, evidence });
      return evidence;

    } catch (error) {
      this.handleError('addEvidence', error as Error);
      throw error;
    }
  }

  async assignCase(caseId: string, analystId: string, teamId?: string): Promise<void> {
    try {
      const case_ = this.cases.get(caseId);
      if (!case_) {
        throw new Error(`Case ${caseId} not found`);
      }

      const previousAnalyst = case_.assignedAnalyst;
      case_.assignedAnalyst = analystId;
      case_.assignedTeam = teamId;
      case_.status = 'assigned';
      case_.updatedAt = new Date();
      
      case_.auditLog.push({
        timestamp: new Date(),
        userId: analystId,
        action: 'case_assigned',
        details: `Case assigned from ${previousAnalyst || 'unassigned'} to ${analystId}`,
        ipAddress: '127.0.0.1'
      });

      // Update metrics
      const metrics = this.metrics.get(caseId);
      if (metrics && !metrics.assignmentTime) {
        metrics.assignmentTime = new Date();
        metrics.timeToAssignment = Math.round((metrics.assignmentTime.getTime() - metrics.creationTime.getTime()) / 60000);
        metrics.lastUpdated = new Date();
      }

      this.emit('caseAssigned', { case: case_, analystId, teamId });

    } catch (error) {
      this.handleError('assignCase', error as Error);
      throw error;
    }
  }

  async updateCaseStatus(caseId: string, newStatus: z.infer<typeof CaseStatusSchema>, userId: string): Promise<void> {
    try {
      const case_ = this.cases.get(caseId);
      if (!case_) {
        throw new Error(`Case ${caseId} not found`);
      }

      const previousStatus = case_.status;
      case_.status = newStatus;
      case_.updatedAt = new Date();

      if (newStatus === 'resolved') {
        case_.resolvedAt = new Date();
      } else if (newStatus === 'closed') {
        case_.closedAt = new Date();
      }

      case_.auditLog.push({
        timestamp: new Date(),
        userId,
        action: 'status_changed',
        details: `Status changed from ${previousStatus} to ${newStatus}`,
        ipAddress: '127.0.0.1'
      });

      // Update metrics
      const metrics = this.metrics.get(caseId);
      if (metrics) {
        if (newStatus === 'resolved' && !metrics.resolutionTime) {
          metrics.resolutionTime = new Date();
          metrics.timeToResolution = Math.round((metrics.resolutionTime.getTime() - metrics.creationTime.getTime()) / 60000);
        } else if (newStatus === 'closed' && !metrics.closureTime) {
          metrics.closureTime = new Date();
        }
        metrics.lastUpdated = new Date();
      }

      this.emit('caseStatusChanged', { case: case_, previousStatus, newStatus, userId });

    } catch (error) {
      this.handleError('updateCaseStatus', error as Error);
      throw error;
    }
  }

  async escalateCase(caseId: string, reason: string, escalatedBy: string): Promise<void> {
    try {
      const case_ = this.cases.get(caseId);
      if (!case_) {
        throw new Error(`Case ${caseId} not found`);
      }

      if (case_.escalationLevel >= this.config.maxEscalationLevels) {
        throw new Error(`Case ${caseId} has reached maximum escalation level`);
      }

      case_.escalationLevel++;
      case_.priority = this.getEscalatedPriority(case_.priority);
      case_.status = 'escalated';
      case_.updatedAt = new Date();

      case_.escalationHistory.push({
        level: case_.escalationLevel,
        escalatedAt: new Date(),
        escalatedBy,
        reason
      });

      case_.auditLog.push({
        timestamp: new Date(),
        userId: escalatedBy,
        action: 'case_escalated',
        details: `Case escalated to level ${case_.escalationLevel}: ${reason}`,
        ipAddress: '127.0.0.1'
      });

      // Update metrics
      const metrics = this.metrics.get(caseId);
      if (metrics) {
        metrics.escalationCount++;
        metrics.lastUpdated = new Date();
      }

      this.emit('caseEscalated', { case: case_, reason, escalatedBy });

    } catch (error) {
      this.handleError('escalateCase', error as Error);
      throw error;
    }
  }

  async addNote(caseId: string, content: string, authorId: string, isPrivate = false): Promise<void> {
    try {
      const case_ = this.cases.get(caseId);
      if (!case_) {
        throw new Error(`Case ${caseId} not found`);
      }

      const noteId = `NOTE-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      case_.notes.push({
        id: noteId,
        authorId,
        content,
        timestamp: new Date(),
        isPrivate
      });

      case_.updatedAt = new Date();
      
      case_.auditLog.push({
        timestamp: new Date(),
        userId: authorId,
        action: 'note_added',
        details: `Note added (${isPrivate ? 'private' : 'public'})`,
        ipAddress: '127.0.0.1'
      });

      this.emit('noteAdded', { case: case_, noteId, authorId, content, isPrivate });

    } catch (error) {
      this.handleError('addNote', error as Error);
      throw error;
    }
  }

  async completeMilestone(caseId: string, milestoneId: string, completedBy: string): Promise<void> {
    try {
      const case_ = this.cases.get(caseId);
      if (!case_) {
        throw new Error(`Case ${caseId} not found`);
      }

      const milestone = case_.milestones.find(m => m.id === milestoneId);
      if (!milestone) {
        throw new Error(`Milestone ${milestoneId} not found`);
      }

      if (milestone.completedAt) {
        throw new Error(`Milestone ${milestoneId} is already completed`);
      }

      milestone.completedAt = new Date();
      milestone.completedBy = completedBy;
      case_.updatedAt = new Date();

      case_.auditLog.push({
        timestamp: new Date(),
        userId: completedBy,
        action: 'milestone_completed',
        details: `Milestone completed: ${milestone.name}`,
        ipAddress: '127.0.0.1'
      });

      this.emit('milestoneCompleted', { case: case_, milestone, completedBy });

    } catch (error) {
      this.handleError('completeMilestone', error as Error);
      throw error;
    }
  }

  async searchCases(criteria: {
    status?: z.infer<typeof CaseStatusSchema>[];
    priority?: z.infer<typeof CasePrioritySchema>[];
    category?: z.infer<typeof CaseCategorySchema>[];
    assignedAnalyst?: string;
    assignedTeam?: string;
    dateRange?: { start: Date; end: Date };
    tags?: string[];
    searchText?: string;
  }): Promise<ISECTECHCase[]> {
    try {
      const results: ISECTECHCase[] = [];
      
      for (const case_ of this.cases.values()) {
        let matches = true;

        if (criteria.status && !criteria.status.includes(case_.status)) matches = false;
        if (criteria.priority && !criteria.priority.includes(case_.priority)) matches = false;
        if (criteria.category && !criteria.category.includes(case_.category)) matches = false;
        if (criteria.assignedAnalyst && case_.assignedAnalyst !== criteria.assignedAnalyst) matches = false;
        if (criteria.assignedTeam && case_.assignedTeam !== criteria.assignedTeam) matches = false;
        
        if (criteria.dateRange) {
          if (case_.createdAt < criteria.dateRange.start || case_.createdAt > criteria.dateRange.end) {
            matches = false;
          }
        }

        if (criteria.tags && !criteria.tags.every(tag => case_.tags.includes(tag))) matches = false;

        if (criteria.searchText) {
          const searchLower = criteria.searchText.toLowerCase();
          if (!case_.title.toLowerCase().includes(searchLower) && 
              !case_.description.toLowerCase().includes(searchLower)) {
            matches = false;
          }
        }

        if (matches) {
          results.push(case_);
        }
      }

      return results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    } catch (error) {
      this.handleError('searchCases', error as Error);
      throw error;
    }
  }

  async generateCaseReport(caseId: string): Promise<any> {
    try {
      const case_ = this.cases.get(caseId);
      if (!case_) {
        throw new Error(`Case ${caseId} not found`);
      }

      const metrics = this.metrics.get(caseId);
      const caseEvidence = Array.from(this.evidence.values()).filter(e => e.caseId === caseId);

      return {
        case: case_,
        metrics,
        evidence: caseEvidence,
        timeline: this.generateCaseTimeline(case_),
        collaborationSummary: this.generateCollaborationSummary(case_),
        recommendations: await this.generateRecommendations(case_),
        generatedAt: new Date()
      };

    } catch (error) {
      this.handleError('generateCaseReport', error as Error);
      throw error;
    }
  }

  private async processAutoAssignment(case_: ISECTECHCase, template: CaseTemplate): Promise<void> {
    for (const rule of template.autoAssignmentRules) {
      if (this.evaluateAssignmentCondition(case_, rule.condition)) {
        await this.assignCase(case_.id, rule.assignTo);
        break;
      }
    }
  }

  private async detectSimilarCases(case_: ISECTECHCase): Promise<void> {
    const similarCases: Array<{ caseId: string; similarity: number; matchingCriteria: string[] }> = [];

    for (const existingCase of this.cases.values()) {
      if (existingCase.id === case_.id) continue;

      const similarity = this.calculateCaseSimilarity(case_, existingCase);
      if (similarity > 0.7) {
        similarCases.push({
          caseId: existingCase.id,
          similarity,
          matchingCriteria: this.getMatchingCriteria(case_, existingCase)
        });
      }
    }

    case_.similarCases = similarCases.sort((a, b) => b.similarity - a.similarity).slice(0, 5);
  }

  private calculateCaseSimilarity(case1: ISECTECHCase, case2: ISECTECHCase): number {
    let score = 0;
    let maxScore = 0;

    // Category match (30%)
    maxScore += 0.3;
    if (case1.category === case2.category) score += 0.3;

    // Priority match (20%)
    maxScore += 0.2;
    if (case1.priority === case2.priority) score += 0.2;

    // Affected assets overlap (25%)
    maxScore += 0.25;
    const assetOverlap = case1.affectedAssets.filter(asset => case2.affectedAssets.includes(asset)).length;
    if (case1.affectedAssets.length > 0 && case2.affectedAssets.length > 0) {
      score += 0.25 * (assetOverlap / Math.max(case1.affectedAssets.length, case2.affectedAssets.length));
    }

    // Tag overlap (25%)
    maxScore += 0.25;
    const tagOverlap = case1.tags.filter(tag => case2.tags.includes(tag)).length;
    if (case1.tags.length > 0 && case2.tags.length > 0) {
      score += 0.25 * (tagOverlap / Math.max(case1.tags.length, case2.tags.length));
    }

    return score / maxScore;
  }

  private getMatchingCriteria(case1: ISECTECHCase, case2: ISECTECHCase): string[] {
    const criteria: string[] = [];
    
    if (case1.category === case2.category) criteria.push('category');
    if (case1.priority === case2.priority) criteria.push('priority');
    if (case1.affectedAssets.some(asset => case2.affectedAssets.includes(asset))) criteria.push('affected_assets');
    if (case1.tags.some(tag => case2.tags.includes(tag))) criteria.push('tags');
    
    return criteria;
  }

  private evaluateAssignmentCondition(case_: ISECTECHCase, condition: string): boolean {
    try {
      // Simple condition evaluation (in production, use a proper expression evaluator)
      return eval(condition.replace(/(\w+)/g, (match) => {
        const value = (case_ as any)[match];
        return typeof value === 'string' ? `"${value}"` : value;
      }));
    } catch {
      return false;
    }
  }

  private getEscalatedPriority(currentPriority: z.infer<typeof CasePrioritySchema>): z.infer<typeof CasePrioritySchema> {
    const priorityOrder: z.infer<typeof CasePrioritySchema>[] = ['low', 'medium', 'high', 'critical'];
    const currentIndex = priorityOrder.indexOf(currentPriority);
    return currentIndex < priorityOrder.length - 1 ? priorityOrder[currentIndex + 1] : currentPriority;
  }

  private monitorSLAs(): void {
    const now = new Date();
    
    for (const case_ of this.cases.values()) {
      if (case_.status === 'closed' || case_.status === 'resolved') continue;
      if (!case_.dueDate) continue;

      const timeRemaining = case_.dueDate.getTime() - now.getTime();
      const totalTime = case_.dueDate.getTime() - case_.createdAt.getTime();
      const percentRemaining = timeRemaining / totalTime;

      if (percentRemaining <= this.config.slaWarningThresholds.red / 100) {
        this.emit('slaWarning', { case: case_, level: 'red', timeRemaining });
      } else if (percentRemaining <= this.config.slaWarningThresholds.yellow / 100) {
        this.emit('slaWarning', { case: case_, level: 'yellow', timeRemaining });
      }

      // Auto-escalation for critical SLA breaches
      if (this.config.enableAutoEscalation && timeRemaining <= 0 && case_.escalationLevel === 0) {
        this.escalateCase(case_.id, 'SLA breach - automatic escalation', 'system');
      }
    }
  }

  private generateCaseTimeline(case_: ISECTECHCase): any[] {
    const timeline = case_.auditLog.map(log => ({
      timestamp: log.timestamp,
      type: 'audit',
      description: log.details,
      userId: log.userId
    }));

    case_.notes.forEach(note => {
      timeline.push({
        timestamp: note.timestamp,
        type: 'note',
        description: `Note added: ${note.content.substring(0, 100)}...`,
        userId: note.authorId
      });
    });

    case_.milestones.forEach(milestone => {
      if (milestone.completedAt) {
        timeline.push({
          timestamp: milestone.completedAt,
          type: 'milestone',
          description: `Milestone completed: ${milestone.name}`,
          userId: milestone.completedBy
        });
      }
    });

    return timeline.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  private generateCollaborationSummary(case_: ISECTECHCase): any {
    return {
      totalCollaborators: case_.collaborators.length,
      totalNotes: case_.notes.length,
      publicNotes: case_.notes.filter(n => !n.isPrivate).length,
      privateNotes: case_.notes.filter(n => n.isPrivate).length,
      lastActivity: case_.updatedAt,
      mostActiveCollaborator: this.getMostActiveCollaborator(case_)
    };
  }

  private getMostActiveCollaborator(case_: ISECTECHCase): string | null {
    const activity = new Map<string, number>();
    
    case_.auditLog.forEach(log => {
      activity.set(log.userId, (activity.get(log.userId) || 0) + 1);
    });
    
    case_.notes.forEach(note => {
      activity.set(note.authorId, (activity.get(note.authorId) || 0) + 1);
    });

    let maxActivity = 0;
    let mostActive: string | null = null;
    
    for (const [userId, count] of activity.entries()) {
      if (count > maxActivity) {
        maxActivity = count;
        mostActive = userId;
      }
    }

    return mostActive;
  }

  private async generateRecommendations(case_: ISECTECHCase): Promise<string[]> {
    const recommendations: string[] = [];

    // Based on similar cases
    if (case_.similarCases.length > 0) {
      recommendations.push('Review similar cases for proven resolution strategies');
    }

    // Based on case age
    const caseAge = Date.now() - case_.createdAt.getTime();
    if (caseAge > 48 * 60 * 60 * 1000 && case_.status !== 'resolved') { // 48 hours
      recommendations.push('Consider escalation due to case age');
    }

    // Based on evidence count
    if (case_.evidenceIds.length === 0) {
      recommendations.push('Collect additional evidence to support investigation');
    }

    // Based on milestone progress
    const overdueMilestones = case_.milestones.filter(m => 
      !m.completedAt && m.targetDate < new Date()
    );
    if (overdueMilestones.length > 0) {
      recommendations.push(`${overdueMilestones.length} milestone(s) are overdue`);
    }

    return recommendations;
  }

  private generateDigitalSignature(evidenceId: string): string {
    // In production, use proper cryptographic signing
    return `SIG-${evidenceId}-${Date.now()}`;
  }

  private checkRateLimit(operation: string): boolean {
    const now = Date.now();
    const requests = this.rateLimiter.get(operation) || [];
    
    // Remove old requests outside the window
    const validRequests = requests.filter(time => now - time < this.rateLimitWindow);
    
    if (validRequests.length >= this.rateLimitMax) {
      return false;
    }
    
    validRequests.push(now);
    this.rateLimiter.set(operation, validRequests);
    return true;
  }

  private handleError(operation: string, error: Error): void {
    console.error(`[ISECTECHAutomatedCaseManager] Error in ${operation}:`, error);
    
    this.circuitBreaker.failureCount++;
    this.circuitBreaker.lastFailureTime = Date.now();
    
    if (this.circuitBreaker.failureCount >= 5) {
      this.circuitBreaker.isOpen = true;
      setTimeout(() => {
        this.circuitBreaker.isOpen = false;
        this.circuitBreaker.failureCount = 0;
      }, this.circuitBreaker.resetTimeout);
    }
    
    this.emit('error', { operation, error });
  }

  private handleCaseCreated(case_: ISECTECHCase): void {
    console.log(`[ISECTECHAutomatedCaseManager] Case created: ${case_.id} - ${case_.title}`);
  }

  private handleCaseAssigned(data: { case: ISECTECHCase; analystId: string; teamId?: string }): void {
    console.log(`[ISECTECHAutomatedCaseManager] Case ${data.case.id} assigned to ${data.analystId}`);
  }

  private handleCaseEscalated(data: { case: ISECTECHCase; reason: string; escalatedBy: string }): void {
    console.log(`[ISECTECHAutomatedCaseManager] Case ${data.case.id} escalated: ${data.reason}`);
  }

  private handleMilestoneCompleted(data: { case: ISECTECHCase; milestone: any; completedBy: string }): void {
    console.log(`[ISECTECHAutomatedCaseManager] Milestone completed in case ${data.case.id}: ${data.milestone.name}`);
  }

  private handleEvidenceAdded(data: { case: ISECTECHCase; evidence: ISECTECHEvidence }): void {
    console.log(`[ISECTECHAutomatedCaseManager] Evidence added to case ${data.case.id}: ${data.evidence.name}`);
  }

  private handleSLAWarning(data: { case: ISECTECHCase; level: string; timeRemaining: number }): void {
    console.log(`[ISECTECHAutomatedCaseManager] SLA warning for case ${data.case.id}: ${data.level} level, ${data.timeRemaining}ms remaining`);
  }

  // Public getters for external access
  getCase(caseId: string): ISECTECHCase | undefined {
    return this.cases.get(caseId);
  }

  getAllCases(): ISECTECHCase[] {
    return Array.from(this.cases.values());
  }

  getEvidence(evidenceId: string): ISECTECHEvidence | undefined {
    return this.evidence.get(evidenceId);
  }

  getCaseEvidence(caseId: string): ISECTECHEvidence[] {
    return Array.from(this.evidence.values()).filter(e => e.caseId === caseId);
  }

  getMetrics(caseId: string): CaseMetrics | undefined {
    return this.metrics.get(caseId);
  }

  getTemplates(): CaseTemplate[] {
    return Array.from(this.templates.values());
  }

  getSystemHealth(): any {
    return {
      totalCases: this.cases.size,
      totalEvidence: this.evidence.size,
      circuitBreakerStatus: this.circuitBreaker.isOpen ? 'open' : 'closed',
      rateLimitStatus: Object.fromEntries(this.rateLimiter.entries())
    };
  }
}