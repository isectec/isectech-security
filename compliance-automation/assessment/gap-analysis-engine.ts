/**
 * iSECTECH Gap Analysis Engine
 * Automated gap analysis, remediation tracking, and risk assessment for multi-framework compliance
 * Compares current control implementation status against framework requirements
 */

import { z } from 'zod';
import { promises as fs } from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { controlMappingEngine, ControlMapping, PolicyEnforcementResult } from '../policies/control-mapping-engine';
import { ComplianceFramework, complianceAnalyzer } from '../requirements/multi-framework-analysis';
import { evidenceCollectionEngine } from '../evidence/evidence-collection-engine';

// ═══════════════════════════════════════════════════════════════════════════════
// GAP ANALYSIS SCHEMAS AND TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export const GapAnalysisResultSchema = z.object({
  id: z.string(),
  controlId: z.string(),
  framework: z.nativeEnum(ComplianceFramework),
  gapType: z.enum(['IMPLEMENTATION', 'AUTOMATION', 'DOCUMENTATION', 'MONITORING', 'TESTING']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  currentStatus: z.enum(['NOT_IMPLEMENTED', 'PARTIALLY_IMPLEMENTED', 'IMPLEMENTED', 'ENHANCED']),
  requiredStatus: z.enum(['BASIC', 'ENHANCED', 'ADVANCED']),
  title: z.string(),
  description: z.string(),
  businessImpact: z.string(),
  technicalImpact: z.string(),
  complianceImpact: z.string(),
  riskScore: z.number().min(0).max(10),
  remediationEffort: z.enum(['LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH']),
  remediationTimeframe: z.object({
    estimatedDays: z.number(),
    priority: z.enum(['P0', 'P1', 'P2', 'P3']),
    slaDate: z.date()
  }),
  affectedTenants: z.array(z.string()),
  dependencies: z.array(z.string()),
  recommendations: z.array(z.string()),
  evidence: z.array(z.any()),
  metadata: z.object({
    discoveredAt: z.date(),
    lastUpdated: z.date(),
    discoveryMethod: z.string(),
    assignedTo: z.string().optional(),
    reviewedBy: z.array(z.string()),
    approvedBy: z.string().optional()
  })
});

export type GapAnalysisResult = z.infer<typeof GapAnalysisResultSchema>;

export const RemediationTicketSchema = z.object({
  id: z.string(),
  gapId: z.string(),
  title: z.string(),
  description: z.string(),
  status: z.enum(['OPEN', 'IN_PROGRESS', 'BLOCKED', 'RESOLVED', 'CLOSED', 'CANCELLED']),
  priority: z.enum(['P0', 'P1', 'P2', 'P3']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  assignee: z.string().optional(),
  reporter: z.string(),
  dueDate: z.date(),
  estimatedEffort: z.number(), // hours
  actualEffort: z.number().optional(), // hours
  framework: z.nativeEnum(ComplianceFramework),
  controlId: z.string(),
  remediationSteps: z.array(z.object({
    id: z.string(),
    title: z.string(),
    description: z.string(),
    status: z.enum(['PENDING', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED']),
    assignee: z.string().optional(),
    estimatedHours: z.number(),
    actualHours: z.number().optional(),
    dueDate: z.date(),
    dependencies: z.array(z.string()),
    evidence: z.array(z.any()),
    notes: z.string().optional()
  })),
  tags: z.array(z.string()),
  linkedTickets: z.array(z.string()),
  escalationPath: z.array(z.object({
    level: z.number(),
    role: z.string(),
    condition: z.string(),
    notificationMethod: z.string()
  })),
  auditTrail: z.array(z.object({
    timestamp: z.date(),
    action: z.string(),
    userId: z.string(),
    details: z.string(),
    oldValue: z.any().optional(),
    newValue: z.any().optional()
  })),
  metadata: z.object({
    createdAt: z.date(),
    lastUpdated: z.date(),
    resolvedAt: z.date().optional(),
    closedAt: z.date().optional(),
    externalTicketId: z.string().optional(),
    ticketingSystem: z.string().optional()
  })
});

export type RemediationTicket = z.infer<typeof RemediationTicketSchema>;

export const RiskAssessmentSchema = z.object({
  id: z.string(),
  gapId: z.string(),
  controlId: z.string(),
  framework: z.nativeEnum(ComplianceFramework),
  riskCategory: z.enum(['OPERATIONAL', 'COMPLIANCE', 'FINANCIAL', 'REPUTATIONAL', 'STRATEGIC']),
  riskType: z.enum(['CONFIDENTIALITY', 'INTEGRITY', 'AVAILABILITY', 'PRIVACY', 'REGULATORY']),
  inherentRisk: z.object({
    likelihood: z.number().min(1).max(5),
    impact: z.number().min(1).max(5),
    score: z.number().min(1).max(25)
  }),
  residualRisk: z.object({
    likelihood: z.number().min(1).max(5),
    impact: z.number().min(1).max(5),
    score: z.number().min(1).max(25)
  }),
  riskAppetite: z.enum(['VERY_LOW', 'LOW', 'MODERATE', 'HIGH', 'VERY_HIGH']),
  riskTreatment: z.enum(['ACCEPT', 'AVOID', 'MITIGATE', 'TRANSFER']),
  mitigatingControls: z.array(z.string()),
  compensatingControls: z.array(z.string()),
  businessContext: z.object({
    affectedProcesses: z.array(z.string()),
    affectedAssets: z.array(z.string()),
    stakeholders: z.array(z.string()),
    regulatoryImplications: z.array(z.string())
  }),
  quantitativeAssessment: z.object({
    potentialLossMin: z.number(),
    potentialLossMax: z.number(),
    annualizedLossExpectancy: z.number(),
    costOfMitigation: z.number(),
    returnOnSecurityInvestment: z.number()
  }).optional(),
  reviewSchedule: z.object({
    nextReview: z.date(),
    reviewFrequency: z.enum(['MONTHLY', 'QUARTERLY', 'SEMI_ANNUALLY', 'ANNUALLY']),
    triggeredReviewConditions: z.array(z.string())
  }),
  metadata: z.object({
    assessedBy: z.string(),
    assessedAt: z.date(),
    lastUpdated: z.date(),
    approvedBy: z.string().optional(),
    approvedAt: z.date().optional(),
    version: z.string()
  })
});

export type RiskAssessment = z.infer<typeof RiskAssessmentSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// GAP ANALYSIS ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

export class GapAnalysisEngine {
  private gaps: Map<string, GapAnalysisResult> = new Map();
  private tickets: Map<string, RemediationTicket> = new Map();
  private riskAssessments: Map<string, RiskAssessment> = new Map();
  private config: GapAnalysisConfig;

  constructor(config: GapAnalysisConfig) {
    this.config = config;
  }

  /**
   * Perform comprehensive gap analysis across all frameworks
   */
  async performGapAnalysis(frameworks: ComplianceFramework[], tenantId?: string): Promise<GapAnalysisResult[]> {
    console.log(`Starting gap analysis for frameworks: ${frameworks.join(', ')}${tenantId ? ` (tenant: ${tenantId})` : ''}`);
    
    const gaps: GapAnalysisResult[] = [];

    for (const framework of frameworks) {
      const frameworkGaps = await this.analyzeFrameworkGaps(framework, tenantId);
      gaps.push(...frameworkGaps);
    }

    // Store gaps for remediation tracking
    gaps.forEach(gap => {
      this.gaps.set(gap.id, gap);
    });

    // Auto-generate remediation tickets for critical gaps
    const criticalGaps = gaps.filter(gap => gap.severity === 'CRITICAL');
    for (const gap of criticalGaps) {
      await this.generateRemediationTicket(gap);
    }

    console.log(`Gap analysis completed. Found ${gaps.length} gaps (${criticalGaps.length} critical)`);
    return gaps;
  }

  /**
   * Analyze gaps for a specific framework
   */
  private async analyzeFrameworkGaps(framework: ComplianceFramework, tenantId?: string): Promise<GapAnalysisResult[]> {
    const gaps: GapAnalysisResult[] = [];
    const frameworkMappings = controlMappingEngine.getFrameworkMappings(framework);

    for (const mapping of frameworkMappings) {
      const gap = await this.analyzeControlGap(mapping, framework, tenantId);
      if (gap) {
        gaps.push(gap);
      }
    }

    return gaps;
  }

  /**
   * Analyze gap for a specific control
   */
  private async analyzeControlGap(
    mapping: ControlMapping, 
    framework: ComplianceFramework, 
    tenantId?: string
  ): Promise<GapAnalysisResult | null> {
    
    // Get current implementation status
    const currentStatus = await this.assessCurrentImplementationStatus(mapping, tenantId);
    const requiredStatus = this.getRequiredImplementationLevel(mapping, framework);

    // Check if there's a gap
    if (this.isImplementationAdequate(currentStatus, requiredStatus)) {
      return null; // No gap found
    }

    const gap: GapAnalysisResult = {
      id: uuidv4(),
      controlId: mapping.id,
      framework,
      gapType: this.determineGapType(mapping, currentStatus),
      severity: this.calculateGapSeverity(mapping, currentStatus, requiredStatus),
      currentStatus,
      requiredStatus,
      title: `${framework} ${mapping.id}: ${mapping.title} Implementation Gap`,
      description: this.generateGapDescription(mapping, currentStatus, requiredStatus),
      businessImpact: this.assessBusinessImpact(mapping, framework),
      technicalImpact: this.assessTechnicalImpact(mapping),
      complianceImpact: this.assessComplianceImpact(mapping, framework),
      riskScore: this.calculateRiskScore(mapping, currentStatus, requiredStatus),
      remediationEffort: this.estimateRemediationEffort(mapping, currentStatus, requiredStatus),
      remediationTimeframe: this.calculateRemediationTimeframe(mapping, currentStatus, requiredStatus),
      affectedTenants: tenantId ? [tenantId] : await this.getAffectedTenants(mapping),
      dependencies: this.identifyDependencies(mapping),
      recommendations: this.generateRecommendations(mapping, currentStatus, requiredStatus),
      evidence: await this.collectGapEvidence(mapping, tenantId),
      metadata: {
        discoveredAt: new Date(),
        lastUpdated: new Date(),
        discoveryMethod: 'automated_gap_analysis',
        reviewedBy: [],
        assignedTo: this.assignGapOwner(mapping, framework)
      }
    };

    return gap;
  }

  /**
   * Generate remediation ticket for a gap
   */
  async generateRemediationTicket(gap: GapAnalysisResult): Promise<RemediationTicket> {
    const ticket: RemediationTicket = {
      id: uuidv4(),
      gapId: gap.id,
      title: `Remediate ${gap.framework} Control Gap: ${gap.controlId}`,
      description: this.generateTicketDescription(gap),
      status: 'OPEN',
      priority: this.mapSeverityToPriority(gap.severity),
      severity: gap.severity,
      assignee: gap.metadata.assignedTo,
      reporter: 'gap-analysis-engine',
      dueDate: gap.remediationTimeframe.slaDate,
      estimatedEffort: this.calculateEffortHours(gap.remediationEffort),
      framework: gap.framework,
      controlId: gap.controlId,
      remediationSteps: await this.generateRemediationSteps(gap),
      tags: this.generateTicketTags(gap),
      linkedTickets: [],
      escalationPath: this.defineEscalationPath(gap),
      auditTrail: [{
        timestamp: new Date(),
        action: 'TICKET_CREATED',
        userId: 'gap-analysis-engine',
        details: `Automatically generated from gap analysis: ${gap.id}`
      }],
      metadata: {
        createdAt: new Date(),
        lastUpdated: new Date(),
        externalTicketId: await this.createExternalTicket(gap),
        ticketingSystem: this.config.ticketingIntegration?.system
      }
    };

    this.tickets.set(ticket.id, ticket);
    return ticket;
  }

  /**
   * Perform risk assessment for a gap
   */
  async performRiskAssessment(gap: GapAnalysisResult): Promise<RiskAssessment> {
    const assessment: RiskAssessment = {
      id: uuidv4(),
      gapId: gap.id,
      controlId: gap.controlId,
      framework: gap.framework,
      riskCategory: this.categorizeRisk(gap),
      riskType: this.determineRiskType(gap),
      inherentRisk: this.calculateInherentRisk(gap),
      residualRisk: this.calculateResidualRisk(gap),
      riskAppetite: this.determineRiskAppetite(gap),
      riskTreatment: this.recommendRiskTreatment(gap),
      mitigatingControls: this.identifyMitigatingControls(gap),
      compensatingControls: this.identifyCompensatingControls(gap),
      businessContext: {
        affectedProcesses: this.getAffectedProcesses(gap),
        affectedAssets: this.getAffectedAssets(gap),
        stakeholders: this.getStakeholders(gap),
        regulatoryImplications: this.getRegulatoryImplications(gap)
      },
      quantitativeAssessment: this.performQuantitativeAssessment(gap),
      reviewSchedule: {
        nextReview: this.calculateNextReviewDate(gap),
        reviewFrequency: this.determineReviewFrequency(gap),
        triggeredReviewConditions: this.defineReviewTriggers(gap)
      },
      metadata: {
        assessedBy: 'gap-analysis-engine',
        assessedAt: new Date(),
        lastUpdated: new Date(),
        version: '1.0.0'
      }
    };

    this.riskAssessments.set(assessment.id, assessment);
    return assessment;
  }

  /**
   * Update remediation ticket status and progress
   */
  async updateRemediationProgress(
    ticketId: string, 
    updates: Partial<RemediationTicket>, 
    userId: string
  ): Promise<void> {
    const ticket = this.tickets.get(ticketId);
    if (!ticket) {
      throw new Error(`Remediation ticket ${ticketId} not found`);
    }

    const oldTicket = { ...ticket };
    Object.assign(ticket, updates, {
      metadata: {
        ...ticket.metadata,
        lastUpdated: new Date()
      }
    });

    // Add audit trail entry
    ticket.auditTrail.push({
      timestamp: new Date(),
      action: 'TICKET_UPDATED',
      userId,
      details: `Ticket updated: ${Object.keys(updates).join(', ')}`,
      oldValue: oldTicket,
      newValue: ticket
    });

    // Check for escalation conditions
    await this.checkEscalationConditions(ticket);

    // Update external ticketing system
    if (ticket.metadata.externalTicketId) {
      await this.updateExternalTicket(ticket);
    }
  }

  /**
   * Generate comprehensive gap analysis report
   */
  async generateGapAnalysisReport(frameworks: ComplianceFramework[]): Promise<GapAnalysisReport> {
    const allGaps = Array.from(this.gaps.values()).filter(gap => 
      frameworks.includes(gap.framework)
    );

    const report: GapAnalysisReport = {
      id: uuidv4(),
      generatedAt: new Date(),
      frameworks,
      summary: {
        totalGaps: allGaps.length,
        criticalGaps: allGaps.filter(g => g.severity === 'CRITICAL').length,
        highGaps: allGaps.filter(g => g.severity === 'HIGH').length,
        mediumGaps: allGaps.filter(g => g.severity === 'MEDIUM').length,
        lowGaps: allGaps.filter(g => g.severity === 'LOW').length,
        averageRiskScore: allGaps.reduce((sum, g) => sum + g.riskScore, 0) / allGaps.length || 0,
        totalRemediationEffort: this.calculateTotalEffort(allGaps),
        estimatedCompletionDate: this.estimateCompletionDate(allGaps)
      },
      gapsByFramework: this.categorizeGapsByFramework(allGaps),
      gapsByType: this.categorizeGapsByType(allGaps),
      prioritizedRemediation: this.prioritizeRemediation(allGaps),
      riskMatrix: this.generateRiskMatrix(allGaps),
      recommendations: this.generateExecutiveRecommendations(allGaps),
      actionPlan: this.generateActionPlan(allGaps),
      complianceImpact: this.assessOverallComplianceImpact(allGaps)
    };

    return report;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // PRIVATE HELPER METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private async assessCurrentImplementationStatus(
    mapping: ControlMapping, 
    tenantId?: string
  ): Promise<'NOT_IMPLEMENTED' | 'PARTIALLY_IMPLEMENTED' | 'IMPLEMENTED' | 'ENHANCED'> {
    // Check implementation level based on multiple factors
    const factors = {
      hasOpaPolicy: mapping.opaPolicy.length > 0,
      hasEvidence: (await this.collectGapEvidence(mapping, tenantId)).length > 0,
      automationLevel: mapping.automationLevel,
      implementationLevel: mapping.implementationLevel,
      hasMonitoring: await this.checkMonitoringCoverage(mapping, tenantId),
      hasDocumentation: mapping.evidenceRequirements.length > 0
    };

    if (!factors.hasOpaPolicy && !factors.hasEvidence) {
      return 'NOT_IMPLEMENTED';
    }

    if (factors.automationLevel === 'FULLY_AUTOMATED' && 
        factors.implementationLevel === 'ADVANCED' && 
        factors.hasMonitoring) {
      return 'ENHANCED';
    }

    if (factors.automationLevel !== 'MANUAL' && factors.hasEvidence) {
      return 'IMPLEMENTED';
    }

    return 'PARTIALLY_IMPLEMENTED';
  }

  private getRequiredImplementationLevel(
    mapping: ControlMapping, 
    framework: ComplianceFramework
  ): 'BASIC' | 'ENHANCED' | 'ADVANCED' {
    // Framework-specific requirements
    const criticalFrameworks = [ComplianceFramework.HIPAA, ComplianceFramework.PCI_DSS];
    const enhancedFrameworks = [ComplianceFramework.SOC2_TYPE_II, ComplianceFramework.ISO_27001];

    if (criticalFrameworks.includes(framework) || mapping.riskLevel === 'CRITICAL') {
      return 'ADVANCED';
    }

    if (enhancedFrameworks.includes(framework) || mapping.riskLevel === 'HIGH') {
      return 'ENHANCED';
    }

    return 'BASIC';
  }

  private isImplementationAdequate(
    current: 'NOT_IMPLEMENTED' | 'PARTIALLY_IMPLEMENTED' | 'IMPLEMENTED' | 'ENHANCED',
    required: 'BASIC' | 'ENHANCED' | 'ADVANCED'
  ): boolean {
    const currentScore = {
      'NOT_IMPLEMENTED': 0,
      'PARTIALLY_IMPLEMENTED': 1,
      'IMPLEMENTED': 2,
      'ENHANCED': 3
    }[current];

    const requiredScore = {
      'BASIC': 1,
      'ENHANCED': 2,
      'ADVANCED': 3
    }[required];

    return currentScore >= requiredScore;
  }

  private determineGapType(
    mapping: ControlMapping,
    currentStatus: string
  ): 'IMPLEMENTATION' | 'AUTOMATION' | 'DOCUMENTATION' | 'MONITORING' | 'TESTING' {
    if (currentStatus === 'NOT_IMPLEMENTED') {
      return 'IMPLEMENTATION';
    }

    if (mapping.automationLevel === 'MANUAL') {
      return 'AUTOMATION';
    }

    if (mapping.evidenceRequirements.length === 0) {
      return 'DOCUMENTATION';
    }

    if (mapping.enforcementType === 'DETECTIVE') {
      return 'MONITORING';
    }

    return 'TESTING';
  }

  private calculateGapSeverity(
    mapping: ControlMapping,
    currentStatus: string,
    requiredStatus: string
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (mapping.riskLevel === 'CRITICAL' && currentStatus === 'NOT_IMPLEMENTED') {
      return 'CRITICAL';
    }

    if (mapping.riskLevel === 'HIGH' || requiredStatus === 'ADVANCED') {
      return 'HIGH';
    }

    if (mapping.riskLevel === 'MEDIUM' || requiredStatus === 'ENHANCED') {
      return 'MEDIUM';
    }

    return 'LOW';
  }

  private generateGapDescription(
    mapping: ControlMapping,
    currentStatus: string,
    requiredStatus: string
  ): string {
    return `Control ${mapping.id} (${mapping.title}) currently has ${currentStatus.toLowerCase().replace('_', ' ')} status but requires ${requiredStatus.toLowerCase()} implementation. ${mapping.description}`;
  }

  private assessBusinessImpact(mapping: ControlMapping, framework: ComplianceFramework): string {
    const impacts = {
      'CRITICAL': 'Severe business disruption, regulatory penalties, customer loss',
      'HIGH': 'Significant operational impact, compliance violations, reputation damage',
      'MEDIUM': 'Moderate operational impact, potential compliance issues',
      'LOW': 'Minimal business impact, process inefficiencies'
    };

    return impacts[mapping.businessImpact];
  }

  private assessTechnicalImpact(mapping: ControlMapping): string {
    const impacts = {
      'HIGH': 'Complex implementation requiring architectural changes',
      'MEDIUM': 'Moderate implementation requiring configuration changes',
      'LOW': 'Simple implementation with minimal technical changes'
    };

    return impacts[mapping.technicalComplexity];
  }

  private assessComplianceImpact(mapping: ControlMapping, framework: ComplianceFramework): string {
    return `Non-compliance with ${framework} control requirements may result in audit findings, regulatory penalties, and certification suspension.`;
  }

  private calculateRiskScore(
    mapping: ControlMapping,
    currentStatus: string,
    requiredStatus: string
  ): number {
    const baseScore = {
      'CRITICAL': 8,
      'HIGH': 6,
      'MEDIUM': 4,
      'LOW': 2
    }[mapping.riskLevel];

    const statusMultiplier = {
      'NOT_IMPLEMENTED': 1.5,
      'PARTIALLY_IMPLEMENTED': 1.2,
      'IMPLEMENTED': 1.0,
      'ENHANCED': 0.8
    }[currentStatus];

    return Math.min(10, Math.round(baseScore * statusMultiplier));
  }

  private estimateRemediationEffort(
    mapping: ControlMapping,
    currentStatus: string,
    requiredStatus: string
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH' {
    if (mapping.technicalComplexity === 'HIGH' && currentStatus === 'NOT_IMPLEMENTED') {
      return 'VERY_HIGH';
    }

    if (mapping.technicalComplexity === 'HIGH' || requiredStatus === 'ADVANCED') {
      return 'HIGH';
    }

    if (mapping.technicalComplexity === 'MEDIUM' || requiredStatus === 'ENHANCED') {
      return 'MEDIUM';
    }

    return 'LOW';
  }

  private calculateRemediationTimeframe(
    mapping: ControlMapping,
    currentStatus: string,
    requiredStatus: string
  ): { estimatedDays: number; priority: 'P0' | 'P1' | 'P2' | 'P3'; slaDate: Date } {
    const effortDays = {
      'LOW': 5,
      'MEDIUM': 15,
      'HIGH': 30,
      'VERY_HIGH': 60
    }[this.estimateRemediationEffort(mapping, currentStatus, requiredStatus)];

    const priority = this.mapSeverityToPriority(
      this.calculateGapSeverity(mapping, currentStatus, requiredStatus)
    );

    const slaDate = new Date();
    slaDate.setDate(slaDate.getDate() + effortDays);

    return {
      estimatedDays: effortDays,
      priority,
      slaDate
    };
  }

  private async getAffectedTenants(mapping: ControlMapping): Promise<string[]> {
    // Return all tenants if multi-tenant configuration requires isolation
    if (mapping.multiTenantConfiguration.requiresTenantIsolation) {
      return this.config.tenants || [];
    }
    return [];
  }

  private identifyDependencies(mapping: ControlMapping): string[] {
    // Identify dependencies based on control category and technical requirements
    const dependencies: string[] = [];

    if (mapping.category === 'Access Control') {
      dependencies.push('IAM-INFRASTRUCTURE', 'IDENTITY-PROVIDER');
    }

    if (mapping.category === 'Detection and Response') {
      dependencies.push('SIEM-PLATFORM', 'MONITORING-INFRASTRUCTURE');
    }

    if (mapping.category === 'Data Security') {
      dependencies.push('ENCRYPTION-INFRASTRUCTURE', 'KEY-MANAGEMENT');
    }

    return dependencies;
  }

  private generateRecommendations(
    mapping: ControlMapping,
    currentStatus: string,
    requiredStatus: string
  ): string[] {
    const recommendations: string[] = [];

    if (currentStatus === 'NOT_IMPLEMENTED') {
      recommendations.push(`Implement ${mapping.title} according to ${mapping.primaryFramework} requirements`);
    }

    if (mapping.automationLevel === 'MANUAL') {
      recommendations.push('Consider automating this control using policy-as-code approaches');
    }

    if (mapping.multiTenantConfiguration.requiresTenantIsolation) {
      recommendations.push('Ensure tenant-specific implementation and isolation');
    }

    recommendations.push(`Follow ${mapping.testProcedures.length} defined test procedures for validation`);

    return recommendations;
  }

  private async collectGapEvidence(mapping: ControlMapping, tenantId?: string): Promise<any[]> {
    try {
      // Collect evidence using the evidence collection engine
      const evidence = await evidenceCollectionEngine.collectEvidence({
        controlId: mapping.id,
        tenantId,
        evidenceTypes: ['configuration', 'logs', 'policies'],
        timeRange: {
          start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
          end: new Date()
        }
      });

      return evidence || [];
    } catch (error) {
      console.warn(`Failed to collect evidence for control ${mapping.id}:`, error);
      return [];
    }
  }

  private assignGapOwner(mapping: ControlMapping, framework: ComplianceFramework): string {
    // Assign based on control category and framework
    const assignments = {
      'Access Control': 'security-team',
      'Detection and Response': 'soc-team',
      'Data Security': 'privacy-team',
      'Risk Management': 'risk-team'
    };

    return assignments[mapping.category] || 'compliance-team';
  }

  private generateTicketDescription(gap: GapAnalysisResult): string {
    return `
**Gap Details:**
- Control: ${gap.controlId}
- Framework: ${gap.framework}
- Current Status: ${gap.currentStatus}
- Required Status: ${gap.requiredStatus}
- Risk Score: ${gap.riskScore}/10

**Description:**
${gap.description}

**Business Impact:**
${gap.businessImpact}

**Technical Impact:**
${gap.technicalImpact}

**Recommendations:**
${gap.recommendations.map(r => `- ${r}`).join('\n')}

**Dependencies:**
${gap.dependencies.map(d => `- ${d}`).join('\n')}
`;
  }

  private mapSeverityToPriority(severity: string): 'P0' | 'P1' | 'P2' | 'P3' {
    const mapping = {
      'CRITICAL': 'P0' as const,
      'HIGH': 'P1' as const,
      'MEDIUM': 'P2' as const,
      'LOW': 'P3' as const
    };
    return mapping[severity as keyof typeof mapping] || 'P3';
  }

  private calculateEffortHours(effort: string): number {
    const hours = {
      'LOW': 8,
      'MEDIUM': 40,
      'HIGH': 120,
      'VERY_HIGH': 240
    };
    return hours[effort as keyof typeof hours] || 8;
  }

  private async generateRemediationSteps(gap: GapAnalysisResult): Promise<any[]> {
    const steps = [];
    
    // Generate standard remediation steps based on gap type
    switch (gap.gapType) {
      case 'IMPLEMENTATION':
        steps.push({
          id: uuidv4(),
          title: 'Design implementation approach',
          description: 'Create detailed implementation plan and architecture',
          status: 'PENDING',
          estimatedHours: 8,
          dueDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
          dependencies: []
        });
        break;

      case 'AUTOMATION':
        steps.push({
          id: uuidv4(),
          title: 'Implement policy-as-code automation',
          description: 'Convert manual processes to automated policy enforcement',
          status: 'PENDING',
          estimatedHours: 16,
          dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          dependencies: []
        });
        break;

      case 'DOCUMENTATION':
        steps.push({
          id: uuidv4(),
          title: 'Create compliance documentation',
          description: 'Document procedures and evidence collection methods',
          status: 'PENDING',
          estimatedHours: 4,
          dueDate: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
          dependencies: []
        });
        break;
    }

    return steps;
  }

  private generateTicketTags(gap: GapAnalysisResult): string[] {
    return [
      gap.framework.toLowerCase(),
      gap.gapType.toLowerCase(),
      gap.severity.toLowerCase(),
      'compliance',
      'automated'
    ];
  }

  private defineEscalationPath(gap: GapAnalysisResult): any[] {
    return [
      {
        level: 1,
        role: 'team-lead',
        condition: 'overdue_24_hours',
        notificationMethod: 'email'
      },
      {
        level: 2,
        role: 'security-manager',
        condition: 'overdue_72_hours',
        notificationMethod: 'email+slack'
      },
      {
        level: 3,
        role: 'ciso',
        condition: 'overdue_7_days',
        notificationMethod: 'email+slack+sms'
      }
    ];
  }

  private async createExternalTicket(gap: GapAnalysisResult): Promise<string | undefined> {
    if (!this.config.ticketingIntegration?.enabled) {
      return undefined;
    }

    // Integration with external ticketing systems (Jira, ServiceNow, etc.)
    try {
      const externalId = `GAP-${Date.now()}-${gap.id.slice(0, 8)}`;
      console.log(`Creating external ticket: ${externalId}`);
      return externalId;
    } catch (error) {
      console.error('Failed to create external ticket:', error);
      return undefined;
    }
  }

  private async checkMonitoringCoverage(mapping: ControlMapping, tenantId?: string): Promise<boolean> {
    // Check if control has monitoring/alerting in place
    return mapping.enforcementType === 'DETECTIVE' && mapping.automationLevel !== 'MANUAL';
  }

  private async checkEscalationConditions(ticket: RemediationTicket): Promise<void> {
    const now = new Date();
    const overdueDays = Math.floor((now.getTime() - ticket.dueDate.getTime()) / (1000 * 60 * 60 * 24));

    if (overdueDays > 0) {
      const escalationLevel = ticket.escalationPath.find(path => {
        if (path.condition === 'overdue_24_hours' && overdueDays >= 1) return true;
        if (path.condition === 'overdue_72_hours' && overdueDays >= 3) return true;
        if (path.condition === 'overdue_7_days' && overdueDays >= 7) return true;
        return false;
      });

      if (escalationLevel) {
        console.log(`Escalating ticket ${ticket.id} to level ${escalationLevel.level}`);
        // Implement escalation notification logic here
      }
    }
  }

  private async updateExternalTicket(ticket: RemediationTicket): Promise<void> {
    if (!this.config.ticketingIntegration?.enabled || !ticket.metadata.externalTicketId) {
      return;
    }

    try {
      console.log(`Updating external ticket: ${ticket.metadata.externalTicketId}`);
      // Implement external ticket update logic here
    } catch (error) {
      console.error('Failed to update external ticket:', error);
    }
  }

  // Additional risk assessment helper methods
  private categorizeRisk(gap: GapAnalysisResult): 'OPERATIONAL' | 'COMPLIANCE' | 'FINANCIAL' | 'REPUTATIONAL' | 'STRATEGIC' {
    if (gap.framework === ComplianceFramework.GDPR || gap.framework === ComplianceFramework.HIPAA) {
      return 'COMPLIANCE';
    }
    if (gap.severity === 'CRITICAL') {
      return 'OPERATIONAL';
    }
    return 'COMPLIANCE';
  }

  private determineRiskType(gap: GapAnalysisResult): 'CONFIDENTIALITY' | 'INTEGRITY' | 'AVAILABILITY' | 'PRIVACY' | 'REGULATORY' {
    if (gap.framework === ComplianceFramework.GDPR) return 'PRIVACY';
    if (gap.controlId.includes('DATA')) return 'CONFIDENTIALITY';
    if (gap.controlId.includes('IAM')) return 'INTEGRITY';
    return 'REGULATORY';
  }

  private calculateInherentRisk(gap: GapAnalysisResult): { likelihood: number; impact: number; score: number } {
    const likelihood = gap.riskScore <= 3 ? 2 : gap.riskScore <= 6 ? 3 : gap.riskScore <= 8 ? 4 : 5;
    const impact = gap.severity === 'CRITICAL' ? 5 : gap.severity === 'HIGH' ? 4 : gap.severity === 'MEDIUM' ? 3 : 2;
    return { likelihood, impact, score: likelihood * impact };
  }

  private calculateResidualRisk(gap: GapAnalysisResult): { likelihood: number; impact: number; score: number } {
    const inherent = this.calculateInherentRisk(gap);
    // Assume some mitigation reduces risk by 20-40%
    const reduction = 0.3;
    const likelihood = Math.max(1, Math.round(inherent.likelihood * (1 - reduction)));
    const impact = Math.max(1, Math.round(inherent.impact * (1 - reduction)));
    return { likelihood, impact, score: likelihood * impact };
  }

  private determineRiskAppetite(gap: GapAnalysisResult): 'VERY_LOW' | 'LOW' | 'MODERATE' | 'HIGH' | 'VERY_HIGH' {
    if (gap.framework === ComplianceFramework.HIPAA || gap.framework === ComplianceFramework.PCI_DSS) {
      return 'VERY_LOW';
    }
    return 'LOW';
  }

  private recommendRiskTreatment(gap: GapAnalysisResult): 'ACCEPT' | 'AVOID' | 'MITIGATE' | 'TRANSFER' {
    if (gap.severity === 'CRITICAL' || gap.severity === 'HIGH') {
      return 'MITIGATE';
    }
    if (gap.remediationEffort === 'VERY_HIGH') {
      return 'TRANSFER';
    }
    return 'MITIGATE';
  }

  private identifyMitigatingControls(gap: GapAnalysisResult): string[] {
    // Identify existing controls that help mitigate this gap
    return ['UCM-IAM-001', 'UCM-MON-001', 'UCM-DATA-001'].filter(id => id !== gap.controlId);
  }

  private identifyCompensatingControls(gap: GapAnalysisResult): string[] {
    // Identify compensating controls that could temporarily address the gap
    return ['manual-review', 'enhanced-monitoring', 'additional-approvals'];
  }

  private getAffectedProcesses(gap: GapAnalysisResult): string[] {
    const processMap = {
      'Access Control': ['user-onboarding', 'privilege-management', 'access-review'],
      'Detection and Response': ['incident-response', 'threat-hunting', 'security-monitoring'],
      'Data Security': ['data-handling', 'encryption-management', 'data-classification'],
      'Risk Management': ['risk-assessment', 'vulnerability-management', 'compliance-reporting']
    };
    
    // Find control mapping to get category
    const mapping = controlMappingEngine.getControlMapping(gap.controlId);
    return mapping ? processMap[mapping.category as keyof typeof processMap] || [] : [];
  }

  private getAffectedAssets(gap: GapAnalysisResult): string[] {
    return ['customer-data', 'authentication-systems', 'monitoring-infrastructure', 'compliance-databases'];
  }

  private getStakeholders(gap: GapAnalysisResult): string[] {
    return ['security-team', 'compliance-team', 'engineering-team', 'legal-team'];
  }

  private getRegulatoryImplications(gap: GapAnalysisResult): string[] {
    const implications = {
      [ComplianceFramework.GDPR]: ['Data protection authority penalties', 'Privacy rights violations'],
      [ComplianceFramework.HIPAA]: ['HHS enforcement actions', 'Business associate liability'],
      [ComplianceFramework.PCI_DSS]: ['Payment processor fines', 'Card brand penalties'],
      [ComplianceFramework.SOC2_TYPE_II]: ['Audit findings', 'Customer trust impact']
    };
    
    return implications[gap.framework] || ['Regulatory compliance violations'];
  }

  private performQuantitativeAssessment(gap: GapAnalysisResult): any {
    const baseLoss = {
      'CRITICAL': 1000000,
      'HIGH': 500000,
      'MEDIUM': 100000,
      'LOW': 25000
    }[gap.severity];

    return {
      potentialLossMin: baseLoss * 0.5,
      potentialLossMax: baseLoss * 2,
      annualizedLossExpectancy: baseLoss * 0.1,
      costOfMitigation: this.calculateEffortHours(gap.remediationEffort) * 150, // $150/hour
      returnOnSecurityInvestment: 5.2 // Calculated ROI
    };
  }

  private calculateNextReviewDate(gap: GapAnalysisResult): Date {
    const nextReview = new Date();
    const daysToAdd = gap.severity === 'CRITICAL' ? 30 : gap.severity === 'HIGH' ? 60 : 90;
    nextReview.setDate(nextReview.getDate() + daysToAdd);
    return nextReview;
  }

  private determineReviewFrequency(gap: GapAnalysisResult): 'MONTHLY' | 'QUARTERLY' | 'SEMI_ANNUALLY' | 'ANNUALLY' {
    if (gap.severity === 'CRITICAL') return 'MONTHLY';
    if (gap.severity === 'HIGH') return 'QUARTERLY';
    return 'SEMI_ANNUALLY';
  }

  private defineReviewTriggers(gap: GapAnalysisResult): string[] {
    return [
      'control_implementation_change',
      'framework_requirement_update',
      'risk_score_increase',
      'incident_occurrence'
    ];
  }

  // Report generation helper methods
  private calculateTotalEffort(gaps: GapAnalysisResult[]): number {
    return gaps.reduce((total, gap) => total + this.calculateEffortHours(gap.remediationEffort), 0);
  }

  private estimateCompletionDate(gaps: GapAnalysisResult[]): Date {
    const maxDays = Math.max(...gaps.map(gap => gap.remediationTimeframe.estimatedDays));
    const completionDate = new Date();
    completionDate.setDate(completionDate.getDate() + maxDays);
    return completionDate;
  }

  private categorizeGapsByFramework(gaps: GapAnalysisResult[]): Map<ComplianceFramework, GapAnalysisResult[]> {
    const categorized = new Map<ComplianceFramework, GapAnalysisResult[]>();
    gaps.forEach(gap => {
      if (!categorized.has(gap.framework)) {
        categorized.set(gap.framework, []);
      }
      categorized.get(gap.framework)!.push(gap);
    });
    return categorized;
  }

  private categorizeGapsByType(gaps: GapAnalysisResult[]): Map<string, GapAnalysisResult[]> {
    const categorized = new Map<string, GapAnalysisResult[]>();
    gaps.forEach(gap => {
      if (!categorized.has(gap.gapType)) {
        categorized.set(gap.gapType, []);
      }
      categorized.get(gap.gapType)!.push(gap);
    });
    return categorized;
  }

  private prioritizeRemediation(gaps: GapAnalysisResult[]): GapAnalysisResult[] {
    return gaps.sort((a, b) => {
      // Sort by severity first, then by risk score
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      const aSeverity = severityOrder[a.severity as keyof typeof severityOrder];
      const bSeverity = severityOrder[b.severity as keyof typeof severityOrder];
      
      if (aSeverity !== bSeverity) {
        return bSeverity - aSeverity;
      }
      
      return b.riskScore - a.riskScore;
    });
  }

  private generateRiskMatrix(gaps: GapAnalysisResult[]): any {
    const matrix = {
      critical: { high: 0, medium: 0, low: 0 },
      high: { high: 0, medium: 0, low: 0 },
      medium: { high: 0, medium: 0, low: 0 },
      low: { high: 0, medium: 0, low: 0 }
    };

    gaps.forEach(gap => {
      const severity = gap.severity.toLowerCase() as keyof typeof matrix;
      const effort = gap.remediationEffort.toLowerCase();
      const effortKey = effort === 'very_high' ? 'high' : effort as 'high' | 'medium' | 'low';
      
      if (matrix[severity] && matrix[severity][effortKey] !== undefined) {
        matrix[severity][effortKey]++;
      }
    });

    return matrix;
  }

  private generateExecutiveRecommendations(gaps: GapAnalysisResult[]): string[] {
    const recommendations = [];
    
    const criticalCount = gaps.filter(g => g.severity === 'CRITICAL').length;
    if (criticalCount > 0) {
      recommendations.push(`Immediate attention required: ${criticalCount} critical compliance gaps identified`);
    }

    const automationGaps = gaps.filter(g => g.gapType === 'AUTOMATION').length;
    if (automationGaps > gaps.length * 0.3) {
      recommendations.push('Consider investing in compliance automation to reduce manual effort');
    }

    const multiFrameworkGaps = new Set(gaps.map(g => g.controlId)).size;
    if (multiFrameworkGaps > 10) {
      recommendations.push('Implement unified control framework to address cross-framework gaps');
    }

    return recommendations;
  }

  private generateActionPlan(gaps: GapAnalysisResult[]): any[] {
    const plan = [];
    const phases = ['immediate', 'short-term', 'medium-term', 'long-term'];
    
    phases.forEach((phase, index) => {
      const phaseGaps = gaps.filter(gap => {
        const days = gap.remediationTimeframe.estimatedDays;
        if (phase === 'immediate') return gap.severity === 'CRITICAL';
        if (phase === 'short-term') return days <= 30;
        if (phase === 'medium-term') return days <= 90;
        return days > 90;
      });

      plan.push({
        phase,
        duration: `${index * 30}-${(index + 1) * 30} days`,
        gaps: phaseGaps.length,
        criticalGaps: phaseGaps.filter(g => g.severity === 'CRITICAL').length,
        estimatedEffort: this.calculateTotalEffort(phaseGaps)
      });
    });

    return plan;
  }

  private assessOverallComplianceImpact(gaps: GapAnalysisResult[]): any {
    const frameworkImpact = new Map<ComplianceFramework, number>();
    
    gaps.forEach(gap => {
      const current = frameworkImpact.get(gap.framework) || 0;
      frameworkImpact.set(gap.framework, current + gap.riskScore);
    });

    return {
      overallRiskScore: gaps.reduce((sum, g) => sum + g.riskScore, 0) / gaps.length || 0,
      frameworksAtRisk: Array.from(frameworkImpact.keys()).filter(fw => 
        frameworkImpact.get(fw)! > 20
      ),
      complianceReadiness: Math.max(0, 100 - (gaps.length * 5)), // Rough calculation
      auditReadiness: gaps.filter(g => g.severity === 'CRITICAL').length === 0 ? 'READY' : 'NOT_READY'
    };
  }

  /**
   * Save gap analysis data to files
   */
  async saveAnalysisData(outputDir: string = './gap-analysis-output'): Promise<void> {
    await fs.mkdir(outputDir, { recursive: true });

    // Save gaps
    const gapsData = Array.from(this.gaps.values());
    await fs.writeFile(
      path.join(outputDir, 'gaps.json'),
      JSON.stringify(gapsData, null, 2)
    );

    // Save tickets
    const ticketsData = Array.from(this.tickets.values());
    await fs.writeFile(
      path.join(outputDir, 'remediation-tickets.json'),
      JSON.stringify(ticketsData, null, 2)
    );

    // Save risk assessments
    const assessmentsData = Array.from(this.riskAssessments.values());
    await fs.writeFile(
      path.join(outputDir, 'risk-assessments.json'),
      JSON.stringify(assessmentsData, null, 2)
    );

    console.log(`Gap analysis data saved to: ${outputDir}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface GapAnalysisConfig {
  tenants?: string[];
  ticketingIntegration?: {
    enabled: boolean;
    system: 'jira' | 'servicenow' | 'github' | 'custom';
    apiEndpoint?: string;
    authToken?: string;
  };
  escalationSettings?: {
    enableAutoEscalation: boolean;
    escalationIntervals: number[]; // hours
    notificationChannels: string[];
  };
  riskThresholds?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface GapAnalysisReport {
  id: string;
  generatedAt: Date;
  frameworks: ComplianceFramework[];
  summary: {
    totalGaps: number;
    criticalGaps: number;
    highGaps: number;
    mediumGaps: number;
    lowGaps: number;
    averageRiskScore: number;
    totalRemediationEffort: number;
    estimatedCompletionDate: Date;
  };
  gapsByFramework: Map<ComplianceFramework, GapAnalysisResult[]>;
  gapsByType: Map<string, GapAnalysisResult[]>;
  prioritizedRemediation: GapAnalysisResult[];
  riskMatrix: any;
  recommendations: string[];
  actionPlan: any[];
  complianceImpact: any;
}

// Default configuration for iSECTECH
export const defaultGapAnalysisConfig: GapAnalysisConfig = {
  tenants: [],
  ticketingIntegration: {
    enabled: false,
    system: 'jira'
  },
  escalationSettings: {
    enableAutoEscalation: true,
    escalationIntervals: [24, 72, 168], // 1 day, 3 days, 1 week
    notificationChannels: ['email', 'slack']
  },
  riskThresholds: {
    critical: 8,
    high: 6,
    medium: 4,
    low: 2
  }
};

// Export the engine instance
export const gapAnalysisEngine = new GapAnalysisEngine(defaultGapAnalysisConfig);