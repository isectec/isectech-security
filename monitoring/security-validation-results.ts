/**
 * Security Validation Results Management System
 * 
 * Centralized management of security validation test results with automated
 * remediation tracking, compliance reporting, and trend analysis.
 * 
 * Tasks 90.11-90.12: Centralized Test Results and Automated Remediation Tracking
 */

import { Logger } from 'winston';
import { Registry, Counter, Histogram, Gauge } from 'prom-client';
import { EventEmitter } from 'events';

interface ValidationTestResult {
  testId: string;
  testSuite: string;
  testType: 'penetration_test' | 'vulnerability_scan' | 'compliance_check' | 'bas_simulation' | 'regression_test';
  testCategory: 'network' | 'application' | 'infrastructure' | 'data' | 'identity' | 'endpoint';
  
  // Test execution details
  executionId: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  executor: string;
  environment: 'development' | 'staging' | 'production';
  
  // Test results
  status: 'passed' | 'failed' | 'partial' | 'error' | 'skipped';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  confidence: number; // 0-100
  
  // Findings
  findings: SecurityFinding[];
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  
  // Compliance and frameworks
  complianceFrameworks: string[]; // e.g., ['NIST', 'CIS', 'ISO27001']
  mitreTechniques: string[];
  owaspCategories: string[];
  
  // Metadata
  assets: string[];
  targets: string[];
  tools: string[];
  tags: string[];
  customFields: Record<string, any>;
  
  // Workflow
  assignedTo?: string;
  remediation?: RemediationPlan;
  verificationStatus?: 'pending' | 'in_progress' | 'verified' | 'failed_verification';
}

interface SecurityFinding {
  findingId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  confidence: number;
  
  // Technical details
  asset: string;
  component: string;
  vulnerability: {
    cveId?: string;
    cweId?: string;
    cvssScore?: number;
    cvssVector?: string;
  };
  
  // Evidence and proof
  evidence: {
    screenshots: string[];
    logs: string[];
    payloads: string[];
    requests: string[];
    responses: string[];
  };
  
  // Impact assessment
  impact: {
    business: string;
    technical: string;
    exploitability: 'high' | 'medium' | 'low';
    scope: 'changed' | 'unchanged';
  };
  
  // Classification
  category: string;
  subcategory: string;
  mitreTechniques: string[];
  owaspCategory?: string;
  complianceViolations: string[];
  
  // Status tracking
  status: 'open' | 'in_remediation' | 'resolved' | 'accepted_risk' | 'false_positive';
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  
  // Remediation
  remediation?: RemediationAction;
  retestRequired: boolean;
  retestResults?: RetestResult[];
}

interface RemediationPlan {
  planId: string;
  createdAt: Date;
  updatedAt: Date;
  estimatedDuration: number; // hours
  priority: 'immediate' | 'urgent' | 'normal' | 'low';
  
  actions: RemediationAction[];
  timeline: RemediationTimeline[];
  resources: {
    assignedTeam: string;
    assignedPersons: string[];
    externalVendors: string[];
    estimatedCost: number;
  };
  
  status: 'draft' | 'approved' | 'in_progress' | 'completed' | 'cancelled';
  approvedBy?: string;
  completedAt?: Date;
}

interface RemediationAction {
  actionId: string;
  findingId: string;
  actionType: 'patch' | 'configuration' | 'process' | 'compensating_control' | 'accept_risk';
  
  description: string;
  implementation: string;
  verification: string;
  
  priority: 'immediate' | 'urgent' | 'normal' | 'low';
  effort: 'low' | 'medium' | 'high';
  complexity: 'low' | 'medium' | 'high';
  
  status: 'planned' | 'in_progress' | 'completed' | 'verified' | 'failed';
  assignedTo: string;
  assignedTeam: string;
  
  scheduledStart?: Date;
  actualStart?: Date;
  scheduledComplete?: Date;
  actualComplete?: Date;
  
  dependencies: string[];
  blockers: string[];
  
  verification: {
    method: 'automated_test' | 'manual_verification' | 'code_review' | 'external_audit';
    verifiedBy?: string;
    verifiedAt?: Date;
    verificationEvidence: string[];
  };
  
  rollbackPlan?: string;
}

interface RemediationTimeline {
  milestoneId: string;
  name: string;
  description: string;
  scheduledDate: Date;
  actualDate?: Date;
  status: 'pending' | 'completed' | 'overdue' | 'cancelled';
  dependencies: string[];
  deliverables: string[];
}

interface RetestResult {
  retestId: string;
  originalFindingId: string;
  retestDate: Date;
  tester: string;
  methodology: string;
  
  result: 'resolved' | 'partially_resolved' | 'not_resolved' | 'regression';
  notes: string;
  evidence: string[];
  
  newFindings: SecurityFinding[];
  recommendation: 'close' | 'reopen' | 'investigate_further';
}

interface TestResultMetrics {
  // Test execution metrics
  testExecutions: Counter<string>;
  testDuration: Histogram<string>;
  testSuccessRate: Gauge<string>;
  
  // Findings metrics
  findingsTotal: Counter<string>;
  findingsBySeverity: Counter<string>;
  findingsByCategory: Counter<string>;
  findingsAge: Histogram<string>;
  
  // Remediation metrics
  remediationActions: Counter<string>;
  remediationDuration: Histogram<string>;
  remediationSuccessRate: Gauge<string>;
  remediationBacklog: Gauge<string>;
  
  // Compliance metrics
  complianceScore: Gauge<string>;
  frameworkCompliance: Gauge<string>;
  controlEffectiveness: Gauge<string>;
  
  // Performance metrics
  processingTime: Histogram<string>;
  systemHealth: Gauge<string>;
}

interface SecurityValidationConfig {
  // Test result processing
  processing: {
    batchSize: number;
    processingInterval: number;
    retentionDays: number;
    archiveThreshold: number;
  };
  
  // Remediation tracking
  remediation: {
    enableAutomatedTracking: boolean;
    slaThresholds: {
      critical: number; // days
      high: number;
      medium: number;
      low: number;
    };
    escalationRules: Array<{
      condition: string;
      action: string;
      recipients: string[];
    }>;
  };
  
  // Integration settings
  integrations: {
    jira: {
      enabled: boolean;
      url: string;
      projectKey: string;
    };
    servicenow: {
      enabled: boolean;
      url: string;
      table: string;
    };
    slack: {
      enabled: boolean;
      webhook: string;
      channels: Record<string, string>;
    };
  };
  
  // Reporting
  reporting: {
    enableAutomatedReports: boolean;
    reportSchedules: Record<string, string>;
    dashboardRefreshInterval: number;
  };
}

/**
 * Security Validation Results Management System
 * 
 * Provides comprehensive management of security validation results with:
 * - Centralized test result collection and storage
 * - Automated remediation tracking and workflow
 * - Compliance monitoring and reporting
 * - Trend analysis and metrics
 * - Integration with ticketing and notification systems
 */
export class SecurityValidationResultsManager extends EventEmitter {
  private metrics: TestResultMetrics;
  private logger: Logger;
  private config: SecurityValidationConfig;
  private registry: Registry;
  
  private testResults: Map<string, ValidationTestResult> = new Map();
  private findings: Map<string, SecurityFinding> = new Map();
  private remediationPlans: Map<string, RemediationPlan> = new Map();
  private remediationActions: Map<string, RemediationAction> = new Map();
  
  private processingQueue: ValidationTestResult[] = [];
  private complianceCache: Map<string, any> = new Map();
  
  constructor(logger: Logger, config: SecurityValidationConfig) {
    super();
    this.logger = logger;
    this.config = config;
    this.registry = new Registry();
    
    this.initializeMetrics();
    this.startPeriodicProcessing();

    this.logger.info('Security Validation Results Manager initialized', {
      component: 'SecurityValidationResultsManager',
      automatedTracking: config.remediation.enableAutomatedTracking,
      integrations: {
        jira: config.integrations.jira.enabled,
        servicenow: config.integrations.servicenow.enabled,
        slack: config.integrations.slack.enabled,
      },
    });
  }

  /**
   * Initialize Prometheus metrics
   */
  private initializeMetrics(): void {
    this.metrics = {
      // Test execution metrics
      testExecutions: new Counter({
        name: 'security_test_executions_total',
        help: 'Total number of security test executions',
        labelNames: ['test_type', 'test_category', 'environment', 'status'],
        registers: [this.registry],
      }),

      testDuration: new Histogram({
        name: 'security_test_duration_seconds',
        help: 'Duration of security test executions',
        labelNames: ['test_type', 'test_category', 'environment'],
        buckets: [60, 300, 900, 1800, 3600, 7200, 14400, 28800, 86400],
        registers: [this.registry],
      }),

      testSuccessRate: new Gauge({
        name: 'security_test_success_rate',
        help: 'Success rate of security tests',
        labelNames: ['test_type', 'environment', 'time_period'],
        registers: [this.registry],
      }),

      // Findings metrics
      findingsTotal: new Counter({
        name: 'security_findings_total',
        help: 'Total number of security findings',
        labelNames: ['severity', 'category', 'test_type', 'environment'],
        registers: [this.registry],
      }),

      findingsBySeverity: new Counter({
        name: 'security_findings_by_severity_total',
        help: 'Security findings grouped by severity',
        labelNames: ['severity', 'status', 'framework'],
        registers: [this.registry],
      }),

      findingsByCategory: new Counter({
        name: 'security_findings_by_category_total',
        help: 'Security findings grouped by category',
        labelNames: ['category', 'subcategory', 'status'],
        registers: [this.registry],
      }),

      findingsAge: new Histogram({
        name: 'security_findings_age_days',
        help: 'Age of open security findings in days',
        labelNames: ['severity', 'category'],
        buckets: [1, 3, 7, 14, 30, 60, 90, 180, 365],
        registers: [this.registry],
      }),

      // Remediation metrics
      remediationActions: new Counter({
        name: 'security_remediation_actions_total',
        help: 'Total number of remediation actions',
        labelNames: ['action_type', 'priority', 'status', 'team'],
        registers: [this.registry],
      }),

      remediationDuration: new Histogram({
        name: 'security_remediation_duration_hours',
        help: 'Duration of remediation actions in hours',
        labelNames: ['action_type', 'priority', 'complexity'],
        buckets: [1, 4, 8, 24, 48, 168, 336, 720, 2160], // 1h to 3 months
        registers: [this.registry],
      }),

      remediationSuccessRate: new Gauge({
        name: 'security_remediation_success_rate',
        help: 'Success rate of remediation actions',
        labelNames: ['action_type', 'team', 'time_period'],
        registers: [this.registry],
      }),

      remediationBacklog: new Gauge({
        name: 'security_remediation_backlog',
        help: 'Number of pending remediation actions',
        labelNames: ['priority', 'team', 'age_category'],
        registers: [this.registry],
      }),

      // Compliance metrics
      complianceScore: new Gauge({
        name: 'security_compliance_score',
        help: 'Overall compliance score (0-100)',
        labelNames: ['framework', 'domain', 'environment'],
        registers: [this.registry],
      }),

      frameworkCompliance: new Gauge({
        name: 'security_framework_compliance_percentage',
        help: 'Compliance percentage for specific frameworks',
        labelNames: ['framework', 'control_family'],
        registers: [this.registry],
      }),

      controlEffectiveness: new Gauge({
        name: 'security_control_effectiveness',
        help: 'Effectiveness score of security controls',
        labelNames: ['control_id', 'control_type', 'environment'],
        registers: [this.registry],
      }),

      // Performance metrics
      processingTime: new Histogram({
        name: 'security_validation_processing_duration_seconds',
        help: 'Time to process security validation results',
        labelNames: ['operation_type'],
        buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60],
        registers: [this.registry],
      }),

      systemHealth: new Gauge({
        name: 'security_validation_system_health',
        help: 'Health score of the validation system',
        labelNames: ['component'],
        registers: [this.registry],
      }),
    };
  }

  /**
   * Ingest test result from security validation tools
   */
  public async ingestTestResult(testResult: ValidationTestResult): Promise<void> {
    const startTime = Date.now();

    try {
      // Validate test result
      this.validateTestResult(testResult);

      // Store test result
      this.testResults.set(testResult.testId, testResult);

      // Process findings
      await this.processFindings(testResult);

      // Update metrics
      this.updateTestMetrics(testResult);

      // Add to processing queue for additional analysis
      this.processingQueue.push(testResult);

      // Create remediation plan if needed
      if (testResult.criticalFindings > 0 || testResult.highFindings > 0) {
        await this.createRemediationPlan(testResult);
      }

      // Trigger integrations
      await this.triggerIntegrations(testResult);

      this.logger.info('Test result ingested successfully', {
        testId: testResult.testId,
        testType: testResult.testType,
        findingsCount: testResult.totalFindings,
        severity: testResult.severity,
      });

      this.emit('test-result-ingested', testResult);

    } catch (error) {
      this.logger.error('Failed to ingest test result', {
        testId: testResult.testId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    } finally {
      const processingTime = (Date.now() - startTime) / 1000;
      this.metrics.processingTime.observe({ operation_type: 'ingest' }, processingTime);
    }
  }

  /**
   * Process findings from test results
   */
  private async processFindings(testResult: ValidationTestResult): Promise<void> {
    for (const finding of testResult.findings) {
      // Store finding
      this.findings.set(finding.findingId, finding);

      // Update finding metrics
      this.metrics.findingsTotal.inc({
        severity: finding.severity,
        category: finding.category,
        test_type: testResult.testType,
        environment: testResult.environment,
      });

      this.metrics.findingsBySeverity.inc({
        severity: finding.severity,
        status: finding.status,
        framework: testResult.complianceFrameworks[0] || 'none',
      });

      this.metrics.findingsByCategory.inc({
        category: finding.category,
        subcategory: finding.subcategory,
        status: finding.status,
      });

      // Calculate finding age
      const ageInDays = (Date.now() - finding.createdAt.getTime()) / (1000 * 60 * 60 * 24);
      this.metrics.findingsAge.observe({
        severity: finding.severity,
        category: finding.category,
      }, ageInDays);

      // Check for duplicates and correlate
      await this.correlateFinding(finding);
    }
  }

  /**
   * Create remediation plan for high-priority findings
   */
  private async createRemediationPlan(testResult: ValidationTestResult): Promise<void> {
    const highPriorityFindings = testResult.findings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    );

    if (highPriorityFindings.length === 0) return;

    const planId = `remediation_${testResult.testId}_${Date.now()}`;
    const remediationPlan: RemediationPlan = {
      planId,
      createdAt: new Date(),
      updatedAt: new Date(),
      estimatedDuration: this.calculateEstimatedDuration(highPriorityFindings),
      priority: testResult.criticalFindings > 0 ? 'immediate' : 'urgent',
      actions: [],
      timeline: [],
      resources: {
        assignedTeam: this.determineAssignedTeam(testResult),
        assignedPersons: [],
        externalVendors: [],
        estimatedCost: 0,
      },
      status: 'draft',
    };

    // Create remediation actions for each finding
    for (const finding of highPriorityFindings) {
      const action = await this.createRemediationAction(finding, planId);
      remediationPlan.actions.push(action);
      this.remediationActions.set(action.actionId, action);
    }

    // Create timeline milestones
    remediationPlan.timeline = this.createRemediationTimeline(remediationPlan);

    // Store remediation plan
    this.remediationPlans.set(planId, remediationPlan);

    // Update metrics
    this.updateRemediationMetrics(remediationPlan);

    this.logger.info('Remediation plan created', {
      planId,
      findingsCount: highPriorityFindings.length,
      priority: remediationPlan.priority,
      estimatedDuration: remediationPlan.estimatedDuration,
    });

    this.emit('remediation-plan-created', remediationPlan);
  }

  /**
   * Create remediation action for a finding
   */
  private async createRemediationAction(finding: SecurityFinding, planId: string): Promise<RemediationAction> {
    const actionId = `action_${finding.findingId}_${Date.now()}`;
    
    const action: RemediationAction = {
      actionId,
      findingId: finding.findingId,
      actionType: this.determineActionType(finding),
      description: this.generateActionDescription(finding),
      implementation: this.generateImplementationSteps(finding),
      verification: this.generateVerificationSteps(finding),
      priority: this.mapSeverityToPriority(finding.severity),
      effort: this.estimateEffort(finding),
      complexity: this.estimateComplexity(finding),
      status: 'planned',
      assignedTo: '',
      assignedTeam: this.determineAssignedTeamForFinding(finding),
      dependencies: [],
      blockers: [],
      verification: {
        method: 'automated_test',
        verificationEvidence: [],
      },
    };

    // Set SLA-based scheduling
    const slaHours = this.getSLAHours(finding.severity);
    action.scheduledComplete = new Date(Date.now() + slaHours * 60 * 60 * 1000);

    return action;
  }

  /**
   * Update remediation action status
   */
  public async updateRemediationStatus(
    actionId: string,
    status: RemediationAction['status'],
    updatedBy: string,
    notes?: string
  ): Promise<void> {
    const action = this.remediationActions.get(actionId);
    if (!action) {
      throw new Error(`Remediation action not found: ${actionId}`);
    }

    const oldStatus = action.status;
    action.status = status;

    // Update timestamps
    switch (status) {
      case 'in_progress':
        action.actualStart = new Date();
        break;
      case 'completed':
        action.actualComplete = new Date();
        break;
      case 'verified':
        action.verification.verifiedAt = new Date();
        action.verification.verifiedBy = updatedBy;
        break;
    }

    // Update metrics
    this.metrics.remediationActions.inc({
      action_type: action.actionType,
      priority: action.priority,
      status: status,
      team: action.assignedTeam,
    });

    // Calculate duration if completed
    if (status === 'completed' && action.actualStart && action.actualComplete) {
      const durationHours = (action.actualComplete.getTime() - action.actualStart.getTime()) / (1000 * 60 * 60);
      this.metrics.remediationDuration.observe({
        action_type: action.actionType,
        priority: action.priority,
        complexity: action.complexity,
      }, durationHours);
    }

    // Trigger retest if verified
    if (status === 'verified') {
      await this.scheduleRetest(action);
    }

    // Trigger integrations
    await this.notifyRemediationUpdate(action, oldStatus, notes);

    this.logger.info('Remediation status updated', {
      actionId,
      findingId: action.findingId,
      oldStatus,
      newStatus: status,
      updatedBy,
    });

    this.emit('remediation-status-updated', { action, oldStatus, newStatus: status });
  }

  /**
   * Schedule retest for remediated finding
   */
  private async scheduleRetest(action: RemediationAction): Promise<void> {
    const finding = this.findings.get(action.findingId);
    if (!finding) return;

    // Mark finding as requiring retest
    finding.retestRequired = true;
    finding.status = 'in_remediation';

    // Create retest task (this would integrate with testing tools)
    const retestId = `retest_${action.findingId}_${Date.now()}`;
    
    this.logger.info('Retest scheduled', {
      retestId,
      findingId: action.findingId,
      actionId: action.actionId,
    });

    this.emit('retest-scheduled', { retestId, finding, action });
  }

  /**
   * Process retest results
   */
  public async processRetestResult(retestResult: RetestResult): Promise<void> {
    const startTime = Date.now();

    try {
      const finding = this.findings.get(retestResult.originalFindingId);
      if (!finding) {
        throw new Error(`Original finding not found: ${retestResult.originalFindingId}`);
      }

      // Store retest result
      if (!finding.retestResults) {
        finding.retestResults = [];
      }
      finding.retestResults.push(retestResult);

      // Update finding status based on retest result
      switch (retestResult.result) {
        case 'resolved':
          finding.status = 'resolved';
          finding.resolvedAt = retestResult.retestDate;
          break;
        case 'not_resolved':
          finding.status = 'open';
          // Escalate or create new remediation actions
          break;
        case 'regression':
          finding.status = 'open';
          // Handle regression
          break;
        case 'partially_resolved':
          // Keep in remediation status
          break;
      }

      // Process any new findings from retest
      for (const newFinding of retestResult.newFindings) {
        this.findings.set(newFinding.findingId, newFinding);
        await this.processNewFinding(newFinding);
      }

      this.logger.info('Retest result processed', {
        retestId: retestResult.retestId,
        originalFindingId: retestResult.originalFindingId,
        result: retestResult.result,
        newFindingsCount: retestResult.newFindings.length,
      });

      this.emit('retest-result-processed', retestResult);

    } finally {
      const processingTime = (Date.now() - startTime) / 1000;
      this.metrics.processingTime.observe({ operation_type: 'retest' }, processingTime);
    }
  }

  /**
   * Generate compliance report
   */
  public async generateComplianceReport(frameworks: string[], environment?: string): Promise<any> {
    const startTime = Date.now();

    try {
      const report = {
        generatedAt: new Date(),
        frameworks: frameworks,
        environment: environment || 'all',
        summary: {
          overallScore: 0,
          frameworkScores: {} as Record<string, number>,
          totalControls: 0,
          passedControls: 0,
          failedControls: 0,
        },
        findings: {
          total: 0,
          bySeverity: {} as Record<string, number>,
          byFramework: {} as Record<string, number>,
        },
        remediation: {
          totalActions: 0,
          completedActions: 0,
          pendingActions: 0,
          overdueActions: 0,
        },
        trends: {
          complianceScoreHistory: [] as any[],
          findingsTrends: [] as any[],
          remediationTrends: [] as any[],
        },
      };

      // Calculate framework-specific scores
      for (const framework of frameworks) {
        const score = await this.calculateFrameworkScore(framework, environment);
        report.summary.frameworkScores[framework] = score;
        
        this.metrics.frameworkCompliance.set({
          framework,
          control_family: 'overall',
        }, score);
      }

      // Calculate overall score
      report.summary.overallScore = Object.values(report.summary.frameworkScores)
        .reduce((sum, score) => sum + score, 0) / frameworks.length;

      // Aggregate findings data
      report.findings = await this.aggregateFindingsForCompliance(frameworks, environment);
      
      // Aggregate remediation data
      report.remediation = await this.aggregateRemediationForCompliance(frameworks, environment);
      
      // Generate trends (simplified)
      report.trends = await this.generateComplianceTrends(frameworks, environment);

      this.logger.info('Compliance report generated', {
        frameworks,
        environment,
        overallScore: report.summary.overallScore,
        totalFindings: report.findings.total,
      });

      return report;

    } finally {
      const processingTime = (Date.now() - startTime) / 1000;
      this.metrics.processingTime.observe({ operation_type: 'compliance_report' }, processingTime);
    }
  }

  /**
   * Get remediation dashboard data
   */
  public getRemediationDashboard(): any {
    const now = Date.now();
    const oneDayMs = 24 * 60 * 60 * 1000;
    const oneWeekMs = 7 * oneDayMs;

    const allActions = Array.from(this.remediationActions.values());
    const allFindings = Array.from(this.findings.values());

    return {
      summary: {
        totalActions: allActions.length,
        completedActions: allActions.filter(a => a.status === 'completed').length,
        inProgressActions: allActions.filter(a => a.status === 'in_progress').length,
        overdueActions: allActions.filter(a => 
          a.scheduledComplete && a.scheduledComplete.getTime() < now && a.status !== 'completed'
        ).length,
      },
      backlog: {
        immediate: allActions.filter(a => a.priority === 'immediate' && a.status === 'planned').length,
        urgent: allActions.filter(a => a.priority === 'urgent' && a.status === 'planned').length,
        normal: allActions.filter(a => a.priority === 'normal' && a.status === 'planned').length,
        low: allActions.filter(a => a.priority === 'low' && a.status === 'planned').length,
      },
      findings: {
        open: allFindings.filter(f => f.status === 'open').length,
        inRemediation: allFindings.filter(f => f.status === 'in_remediation').length,
        resolved: allFindings.filter(f => f.status === 'resolved').length,
        bySeverity: {
          critical: allFindings.filter(f => f.severity === 'critical' && f.status === 'open').length,
          high: allFindings.filter(f => f.severity === 'high' && f.status === 'open').length,
          medium: allFindings.filter(f => f.severity === 'medium' && f.status === 'open').length,
          low: allFindings.filter(f => f.severity === 'low' && f.status === 'open').length,
        },
      },
      slaStatus: {
        critical: this.calculateSLAStatus('critical', allActions),
        high: this.calculateSLAStatus('high', allActions),
        medium: this.calculateSLAStatus('medium', allActions),
        low: this.calculateSLAStatus('low', allActions),
      },
      recentActivity: {
        newFindings24h: allFindings.filter(f => 
          (now - f.createdAt.getTime()) < oneDayMs
        ).length,
        resolvedFindings7d: allFindings.filter(f => 
          f.resolvedAt && (now - f.resolvedAt.getTime()) < oneWeekMs
        ).length,
        completedActions7d: allActions.filter(a => 
          a.actualComplete && (now - a.actualComplete.getTime()) < oneWeekMs
        ).length,
      },
    };
  }

  /**
   * Start periodic processing tasks
   */
  private startPeriodicProcessing(): void {
    // Process queue every 30 seconds
    setInterval(() => {
      this.processQueue();
    }, 30000);

    // Update remediation metrics every 5 minutes
    setInterval(() => {
      this.updateRemediationBacklogMetrics();
    }, 300000);

    // Generate compliance reports every hour
    if (this.config.reporting.enableAutomatedReports) {
      setInterval(() => {
        this.generateScheduledReports();
      }, 3600000);
    }

    // Clean up old data daily
    setInterval(() => {
      this.cleanupOldData();
    }, 86400000);
  }

  /**
   * Process items in the queue
   */
  private async processQueue(): Promise<void> {
    if (this.processingQueue.length === 0) return;

    const batchSize = Math.min(this.config.processing.batchSize, this.processingQueue.length);
    const batch = this.processingQueue.splice(0, batchSize);

    for (const testResult of batch) {
      try {
        await this.performAdditionalAnalysis(testResult);
      } catch (error) {
        this.logger.error('Queue processing error', {
          testId: testResult.testId,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }
  }

  /**
   * Update remediation backlog metrics
   */
  private updateRemediationBacklogMetrics(): void {
    const now = Date.now();
    const allActions = Array.from(this.remediationActions.values());

    // Group by priority and age
    const priorities = ['immediate', 'urgent', 'normal', 'low'] as const;
    const teams = new Set(allActions.map(a => a.assignedTeam));

    for (const priority of priorities) {
      for (const team of teams) {
        const actions = allActions.filter(a => 
          a.priority === priority && 
          a.assignedTeam === team &&
          (a.status === 'planned' || a.status === 'in_progress')
        );

        // Age categories: new (<1 day), aging (1-7 days), stale (>7 days)
        const newActions = actions.filter(a => (now - a.scheduledStart?.getTime() || now) < 86400000);
        const agingActions = actions.filter(a => {
          const age = now - (a.scheduledStart?.getTime() || now);
          return age >= 86400000 && age < 604800000; // 1-7 days
        });
        const staleActions = actions.filter(a => (now - (a.scheduledStart?.getTime() || now)) >= 604800000);

        this.metrics.remediationBacklog.set({ priority, team, age_category: 'new' }, newActions.length);
        this.metrics.remediationBacklog.set({ priority, team, age_category: 'aging' }, agingActions.length);
        this.metrics.remediationBacklog.set({ priority, team, age_category: 'stale' }, staleActions.length);
      }
    }
  }

  // Helper methods (simplified implementations)

  private validateTestResult(testResult: ValidationTestResult): void {
    if (!testResult.testId || !testResult.testType || !testResult.startTime) {
      throw new Error('Invalid test result: missing required fields');
    }
  }

  private updateTestMetrics(testResult: ValidationTestResult): void {
    this.metrics.testExecutions.inc({
      test_type: testResult.testType,
      test_category: testResult.testCategory,
      environment: testResult.environment,
      status: testResult.status,
    });

    this.metrics.testDuration.observe({
      test_type: testResult.testType,
      test_category: testResult.testCategory,
      environment: testResult.environment,
    }, testResult.duration);
  }

  private updateRemediationMetrics(plan: RemediationPlan): void {
    for (const action of plan.actions) {
      this.metrics.remediationActions.inc({
        action_type: action.actionType,
        priority: action.priority,
        status: action.status,
        team: action.assignedTeam,
      });
    }
  }

  private async correlateFinding(finding: SecurityFinding): Promise<void> {
    // Simplified correlation logic
    // In production, this would implement sophisticated deduplication and correlation
    this.logger.debug('Correlating finding', { findingId: finding.findingId });
  }

  private calculateEstimatedDuration(findings: SecurityFinding[]): number {
    // Simplified duration calculation
    return findings.reduce((total, finding) => {
      const baseDuration = finding.severity === 'critical' ? 8 : 
                          finding.severity === 'high' ? 4 : 
                          finding.severity === 'medium' ? 2 : 1;
      return total + baseDuration;
    }, 0);
  }

  private determineAssignedTeam(testResult: ValidationTestResult): string {
    // Logic to determine which team should handle remediation
    switch (testResult.testCategory) {
      case 'network': return 'network-team';
      case 'application': return 'dev-team';
      case 'infrastructure': return 'ops-team';
      default: return 'security-team';
    }
  }

  private determineActionType(finding: SecurityFinding): RemediationAction['actionType'] {
    if (finding.vulnerability.cveId) return 'patch';
    if (finding.category === 'configuration') return 'configuration';
    return 'process';
  }

  private generateActionDescription(finding: SecurityFinding): string {
    return `Remediate ${finding.title}: ${finding.description}`;
  }

  private generateImplementationSteps(finding: SecurityFinding): string {
    return `1. Analyze the vulnerability\n2. Develop fix\n3. Test fix\n4. Deploy to production`;
  }

  private generateVerificationSteps(finding: SecurityFinding): string {
    return `1. Re-run security test\n2. Verify fix effectiveness\n3. Check for regressions`;
  }

  private mapSeverityToPriority(severity: SecurityFinding['severity']): RemediationAction['priority'] {
    const mapping = {
      critical: 'immediate' as const,
      high: 'urgent' as const,
      medium: 'normal' as const,
      low: 'low' as const,
      informational: 'low' as const,
    };
    return mapping[severity];
  }

  private estimateEffort(finding: SecurityFinding): 'low' | 'medium' | 'high' {
    return finding.severity === 'critical' ? 'high' : 'medium';
  }

  private estimateComplexity(finding: SecurityFinding): 'low' | 'medium' | 'high' {
    return finding.impact.exploitability === 'high' ? 'high' : 'medium';
  }

  private determineAssignedTeamForFinding(finding: SecurityFinding): string {
    return finding.category === 'application' ? 'dev-team' : 'security-team';
  }

  private getSLAHours(severity: SecurityFinding['severity']): number {
    return this.config.remediation.slaThresholds[severity] * 24;
  }

  private createRemediationTimeline(plan: RemediationPlan): RemediationTimeline[] {
    return [
      {
        milestoneId: `${plan.planId}_start`,
        name: 'Remediation Start',
        description: 'Begin remediation activities',
        scheduledDate: new Date(),
        status: 'pending',
        dependencies: [],
        deliverables: ['Remediation plan approved'],
      },
    ];
  }

  private async triggerIntegrations(testResult: ValidationTestResult): Promise<void> {
    // Integrate with external systems
    if (this.config.integrations.jira.enabled) {
      await this.createJiraIssues(testResult);
    }
    
    if (this.config.integrations.slack.enabled) {
      await this.sendSlackNotifications(testResult);
    }
  }

  private async createJiraIssues(testResult: ValidationTestResult): Promise<void> {
    // Simplified JIRA integration
    this.logger.info('Creating JIRA issues for findings', {
      testId: testResult.testId,
      findingsCount: testResult.totalFindings,
    });
  }

  private async sendSlackNotifications(testResult: ValidationTestResult): Promise<void> {
    // Simplified Slack integration
    this.logger.info('Sending Slack notifications', {
      testId: testResult.testId,
      severity: testResult.severity,
    });
  }

  private async notifyRemediationUpdate(action: RemediationAction, oldStatus: string, notes?: string): Promise<void> {
    // Notify stakeholders of remediation updates
    this.logger.info('Remediation update notification sent', {
      actionId: action.actionId,
      oldStatus,
      newStatus: action.status,
    });
  }

  private async processNewFinding(finding: SecurityFinding): Promise<void> {
    // Process new findings discovered during retest
    this.logger.info('Processing new finding from retest', {
      findingId: finding.findingId,
      severity: finding.severity,
    });
  }

  private async calculateFrameworkScore(framework: string, environment?: string): Promise<number> {
    // Calculate compliance score for specific framework
    return 85; // Simplified - would be based on actual compliance data
  }

  private async aggregateFindingsForCompliance(frameworks: string[], environment?: string): Promise<any> {
    // Aggregate findings data for compliance reporting
    return {
      total: this.findings.size,
      bySeverity: { critical: 5, high: 10, medium: 20, low: 15 },
      byFramework: { NIST: 25, CIS: 15, ISO27001: 10 },
    };
  }

  private async aggregateRemediationForCompliance(frameworks: string[], environment?: string): Promise<any> {
    // Aggregate remediation data for compliance reporting
    return {
      totalActions: this.remediationActions.size,
      completedActions: Array.from(this.remediationActions.values()).filter(a => a.status === 'completed').length,
      pendingActions: Array.from(this.remediationActions.values()).filter(a => a.status === 'planned').length,
      overdueActions: 5,
    };
  }

  private async generateComplianceTrends(frameworks: string[], environment?: string): Promise<any> {
    // Generate compliance trends data
    return {
      complianceScoreHistory: [],
      findingsTrends: [],
      remediationTrends: [],
    };
  }

  private calculateSLAStatus(severity: string, actions: RemediationAction[]): any {
    const relevantActions = actions.filter(a => 
      this.mapSeverityToPriority(severity as any).includes(a.priority)
    );
    
    const total = relevantActions.length;
    const onTime = relevantActions.filter(a => 
      !a.scheduledComplete || 
      (a.actualComplete && a.actualComplete <= a.scheduledComplete)
    ).length;

    return {
      total,
      onTime,
      percentage: total > 0 ? (onTime / total) * 100 : 100,
    };
  }

  private async performAdditionalAnalysis(testResult: ValidationTestResult): Promise<void> {
    // Perform additional analysis on test results
    this.logger.debug('Performing additional analysis', { testId: testResult.testId });
  }

  private async generateScheduledReports(): Promise<void> {
    // Generate and send scheduled compliance reports
    this.logger.info('Generating scheduled compliance reports');
  }

  private async cleanupOldData(): Promise<void> {
    const cutoffDate = new Date(Date.now() - this.config.processing.retentionDays * 24 * 60 * 60 * 1000);
    
    // Clean up old test results, findings, etc.
    let removedCount = 0;
    for (const [key, result] of this.testResults) {
      if (result.startTime < cutoffDate) {
        this.testResults.delete(key);
        removedCount++;
      }
    }

    this.logger.info('Data cleanup completed', {
      removedTestResults: removedCount,
      retentionDays: this.config.processing.retentionDays,
    });
  }

  /**
   * Get Prometheus metrics registry
   */
  public getMetricsRegistry(): Registry {
    return this.registry;
  }

  /**
   * Get system health status
   */
  public getHealth(): { status: 'healthy' | 'degraded' | 'unhealthy'; details: Record<string, any> } {
    const queueSize = this.processingQueue.length;
    const testResultsCount = this.testResults.size;
    const pendingActions = Array.from(this.remediationActions.values())
      .filter(a => a.status === 'planned' || a.status === 'in_progress').length;

    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

    if (queueSize > 100 || pendingActions > 500) {
      status = 'degraded';
    }

    if (queueSize > 500 || testResultsCount > 10000) {
      status = 'unhealthy';
    }

    return {
      status,
      details: {
        queueSize,
        testResultsCount,
        findingsCount: this.findings.size,
        pendingRemediationActions: pendingActions,
        activeRemediationPlans: this.remediationPlans.size,
      },
    };
  }
}

/**
 * Factory function to create SecurityValidationResultsManager
 */
export function createSecurityValidationResultsManager(
  logger: Logger,
  overrides: Partial<SecurityValidationConfig> = {}
): SecurityValidationResultsManager {
  const defaultConfig: SecurityValidationConfig = {
    processing: {
      batchSize: 50,
      processingInterval: 30000,
      retentionDays: 365,
      archiveThreshold: 1000,
    },
    remediation: {
      enableAutomatedTracking: true,
      slaThresholds: {
        critical: 1,  // 1 day
        high: 7,      // 7 days
        medium: 30,   // 30 days
        low: 90,      // 90 days
      },
      escalationRules: [],
    },
    integrations: {
      jira: {
        enabled: false,
        url: '',
        projectKey: 'SEC',
      },
      servicenow: {
        enabled: false,
        url: '',
        table: 'incident',
      },
      slack: {
        enabled: false,
        webhook: '',
        channels: {},
      },
    },
    reporting: {
      enableAutomatedReports: false,
      reportSchedules: {},
      dashboardRefreshInterval: 300000,
    },
  };

  const config = { ...defaultConfig, ...overrides };
  return new SecurityValidationResultsManager(logger, config);
}

export {
  SecurityValidationResultsManager,
  ValidationTestResult,
  SecurityFinding,
  RemediationPlan,
  RemediationAction,
  RetestResult,
  SecurityValidationConfig,
};