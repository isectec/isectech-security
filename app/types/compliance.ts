/**
 * Compliance Types and Interfaces
 * TypeScript definitions for compliance management system
 */

export enum ComplianceFramework {
  GDPR = 'gdpr',
  HIPAA = 'hipaa',
  PCI_DSS = 'pci_dss',
  SOC2 = 'soc2',
  ISO27001 = 'iso27001',
  NIST = 'nist',
  CCPA = 'ccpa',
  PIPEDA = 'pipeda'
}

export enum ComplianceStatus {
  COMPLIANT = 'compliant',
  NON_COMPLIANT = 'non_compliant',
  PARTIAL = 'partial',
  UNDER_REVIEW = 'under_review',
  NOT_APPLICABLE = 'not_applicable'
}

export enum ViolationType {
  DATA_BREACH = 'data_breach',
  ACCESS_VIOLATION = 'access_violation',
  RETENTION_VIOLATION = 'retention_violation',
  ENCRYPTION_FAILURE = 'encryption_failure',
  AUDIT_FAILURE = 'audit_failure',
  CONSENT_VIOLATION = 'consent_violation',
  PRIVACY_VIOLATION = 'privacy_violation',
  SECURITY_CONTROL_FAILURE = 'security_control_failure',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  DATA_PROCESSING_VIOLATION = 'data_processing_violation'
}

export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
  PHI = 'phi', // Protected Health Information
  PII = 'pii', // Personally Identifiable Information
  CHD = 'chd', // Cardholder Data
  SENSITIVE = 'sensitive'
}

export enum AuditEventType {
  USER_AUTHENTICATION = 'user_authentication',
  DATA_ACCESS = 'data_access',
  DATA_MODIFICATION = 'data_modification',
  SYSTEM_ACCESS = 'system_access',
  CONFIGURATION_CHANGE = 'configuration_change',
  SECURITY_EVENT = 'security_event',
  COMPLIANCE_EVENT = 'compliance_event',
  MODEL_TRAINING = 'model_training',
  MODEL_INFERENCE = 'model_inference',
  API_REQUEST = 'api_request'
}

export interface ComplianceControl {
  id: string;
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  category: string;
  status: ComplianceStatus;
  implementationDate?: string;
  lastAssessed?: string;
  nextAssessmentDue?: string;
  responsible: string;
  evidence: string[];
  automated: boolean;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface ComplianceAssessmentResult {
  id: string;
  controlId: string;
  assessmentDate: string;
  assessor: string;
  status: ComplianceStatus;
  score: number;
  findings: AssessmentFinding[];
  recommendations: string[];
  evidenceReviewed: string[];
  nextAssessmentDue: string;
}

export interface AssessmentFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  recommendation: string;
  status: 'open' | 'in_progress' | 'resolved' | 'accepted_risk';
  dueDate?: string;
  assignedTo?: string;
}

export interface ComplianceViolation {
  id: string;
  framework: ComplianceFramework;
  violationType: ViolationType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  detectedAt: string;
  resolvedAt?: string;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  affectedSystems: string[];
  affectedData: DataClassification[];
  dataSubjectsAffected?: number;
  businessImpact: string;
  riskScore: number;
  remediationPlan: string[];
  assignedTo?: string;
  dueDate?: string;
  regulatoryReportingRequired: boolean;
  externalNotificationRequired: boolean;
  evidence: Evidence[];
  timeline: ViolationTimelineEvent[];
}

export interface Evidence {
  id: string;
  type: 'document' | 'screenshot' | 'log' | 'report' | 'certificate';
  title: string;
  description: string;
  filePath: string;
  uploadedBy: string;
  uploadedAt: string;
  tags: string[];
  sensitive: boolean;
}

export interface ViolationTimelineEvent {
  id: string;
  timestamp: string;
  event: string;
  description: string;
  performer: string;
  automated: boolean;
}

export interface DataInventoryItem {
  id: string;
  name: string;
  description: string;
  classification: DataClassification;
  location: string;
  owner: string;
  custodian: string;
  retentionPeriod: number; // days
  processingPurpose: string[];
  legalBasis: string[];
  dataSubjects: string[];
  thirdPartySharing: boolean;
  encryptionStatus: 'encrypted' | 'not_encrypted' | 'partial';
  accessControls: string[];
  backupLocation?: string;
  lastAccessed?: string;
  complianceFrameworks: ComplianceFramework[];
}

export interface AuditTrailEntry {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  userId?: string;
  sessionId?: string;
  sourceIP?: string;
  userAgent?: string;
  action: string;
  resource: string;
  resourceType: string;
  outcome: 'success' | 'failure' | 'partial';
  details: Record<string, any>;
  sensitiveDataAccessed: boolean;
  dataClassification?: DataClassification;
  complianceFrameworks: ComplianceFramework[];
  digitalSignature?: string;
  integrityVerified: boolean;
}

export interface ComplianceReport {
  id: string;
  type: 'executive' | 'detailed' | 'audit' | 'incident' | 'assessment';
  framework?: ComplianceFramework;
  title: string;
  description: string;
  generatedAt: string;
  generatedBy: string;
  periodStart: string;
  periodEnd: string;
  status: 'draft' | 'final' | 'published';
  confidentiality: 'public' | 'internal' | 'confidential' | 'restricted';
  
  executiveSummary: {
    overallComplianceScore: number;
    totalViolations: number;
    resolvedViolations: number;
    criticalIssues: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    keyFindings: string[];
    recommendations: string[];
  };
  
  metrics: ComplianceMetrics;
  violations: ComplianceViolation[];
  assessments: ComplianceAssessmentResult[];
  auditSummary: AuditSummary;
  riskAssessment: RiskAssessment;
  actionItems: ActionItem[];
  
  downloadUrl?: string;
  distributionList: string[];
  approvers: ReportApprover[];
  tags: string[];
}

export interface ComplianceMetrics {
  frameworkScores: Record<ComplianceFramework, number>;
  controlsAssessed: number;
  controlsCompliant: number;
  controlsNonCompliant: number;
  violationsByCategory: Record<ViolationType, number>;
  violationsBySeverity: Record<string, number>;
  meanTimeToResolution: number; // hours
  auditTrailCompleteness: number; // percentage
  dataProtectionScore: number;
  incidentResponseTime: number; // hours
  complianceTrend: 'improving' | 'stable' | 'declining';
}

export interface AuditSummary {
  totalEvents: number;
  eventsByType: Record<AuditEventType, number>;
  sensitiveDataAccessEvents: number;
  failedAccessAttempts: number;
  integrityViolations: number;
  suspiciousActivities: number;
  complianceRelatedEvents: number;
  auditCoverage: number; // percentage
}

export interface RiskAssessment {
  overallRiskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskFactors: RiskFactor[];
  mitigationStrategies: string[];
  residualRisk: number;
  riskTrend: 'decreasing' | 'stable' | 'increasing';
  nextReviewDate: string;
}

export interface RiskFactor {
  id: string;
  category: string;
  description: string;
  impact: number; // 1-10
  likelihood: number; // 1-10
  riskScore: number; // impact * likelihood
  mitigated: boolean;
  mitigationPlan?: string;
}

export interface ActionItem {
  id: string;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'in_progress' | 'completed' | 'cancelled';
  assignedTo: string;
  dueDate: string;
  estimatedEffort: number; // hours
  relatedViolations: string[];
  relatedControls: string[];
  dependencies: string[];
  progress: number; // 0-100
  lastUpdated: string;
}

export interface ReportApprover {
  userId: string;
  name: string;
  role: string;
  status: 'pending' | 'approved' | 'rejected';
  approvedAt?: string;
  comments?: string;
}

export interface ComplianceConfiguration {
  id: string;
  organizationId: string;
  enabledFrameworks: ComplianceFramework[];
  dataRetentionPolicies: Record<DataClassification, number>;
  notificationSettings: NotificationSettings;
  automationSettings: AutomationSettings;
  reportingSettings: ReportingSettings;
  integrationSettings: IntegrationSettings;
  lastUpdated: string;
  updatedBy: string;
}

export interface NotificationSettings {
  emailNotifications: boolean;
  slackNotifications: boolean;
  webhookNotifications: boolean;
  criticalViolationAlerts: boolean;
  assessmentReminders: boolean;
  reportGeneration: boolean;
  escalationPolicies: EscalationPolicy[];
}

export interface EscalationPolicy {
  id: string;
  name: string;
  triggers: string[];
  escalationLevels: EscalationLevel[];
  active: boolean;
}

export interface EscalationLevel {
  level: number;
  delayMinutes: number;
  recipients: string[];
  actions: string[];
}

export interface AutomationSettings {
  autoAssessments: boolean;
  autoRemediation: boolean;
  autoReporting: boolean;
  autoEscalation: boolean;
  mlAnomalyDetection: boolean;
  scheduledScans: boolean;
}

export interface ReportingSettings {
  defaultFormat: 'pdf' | 'html' | 'csv' | 'json';
  includeExecutiveSummary: boolean;
  includeDetailedFindings: boolean;
  includeRecommendations: boolean;
  customBranding: boolean;
  distributionLists: Record<string, string[]>;
  scheduledReports: ScheduledReport[];
}

export interface ScheduledReport {
  id: string;
  name: string;
  type: 'executive' | 'detailed' | 'audit';
  frameworks: ComplianceFramework[];
  frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly';
  recipients: string[];
  active: boolean;
  lastGenerated?: string;
  nextDue: string;
}

export interface IntegrationSettings {
  siemIntegration: boolean;
  ticketingSystem: boolean;
  identityProvider: boolean;
  cloudProviders: string[];
  apiKeys: Record<string, string>;
  webhookEndpoints: string[];
}

// API Response Types
export interface ComplianceStatusResponse {
  success: boolean;
  data: {
    frameworkStatus: Record<ComplianceFramework, {
      complianceScore: number;
      totalControls: number;
      compliantControls: number;
      lastAssessed: string;
      nextAssessmentDue: string;
    }>;
    overallScore: number;
    riskLevel: string;
    lastUpdated: string;
  };
  timestamp: string;
}

export interface ViolationsResponse {
  success: boolean;
  data: {
    violations: ComplianceViolation[];
    total: number;
    openCount: number;
    criticalCount: number;
    filters: Record<string, string[]>;
  };
  pagination: {
    page: number;
    limit: number;
    totalPages: number;
  };
}

export interface AuditTrailResponse {
  success: boolean;
  data: {
    entries: AuditTrailEntry[];
    total: number;
    integrityStatus: 'verified' | 'compromised' | 'unknown';
    filters: Record<string, string[]>;
  };
  pagination: {
    page: number;
    limit: number;
    totalPages: number;
  };
}

// Utility Types
export type ComplianceFrameworkConfig = {
  [K in ComplianceFramework]: {
    name: string;
    description: string;
    requiredControls: string[];
    optionalControls: string[];
    assessmentFrequency: number; // days
    reportingRequirements: string[];
    dataTypes: DataClassification[];
  };
};