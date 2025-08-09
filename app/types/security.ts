/**
 * Security Domain Types for iSECTECH Protect
 * Production-grade TypeScript definitions for cybersecurity entities
 */

// Security Clearance Levels
export type SecurityClearance = 'TOP_SECRET' | 'SECRET' | 'CONFIDENTIAL' | 'UNCLASSIFIED';

// Data Classification Levels
export type DataClassification = 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET';

// MITRE ATT&CK Framework
export interface MITREAttackTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  mitigations: string[];
  dataSourcesRequired: string[];
}

// Asset Types and Status
export type AssetType =
  | 'SERVER'
  | 'WORKSTATION'
  | 'MOBILE_DEVICE'
  | 'NETWORK_DEVICE'
  | 'IOT_DEVICE'
  | 'CLOUD_RESOURCE'
  | 'APPLICATION'
  | 'DATABASE';

export type AssetStatus = 'ACTIVE' | 'INACTIVE' | 'QUARANTINED' | 'DECOMMISSIONED';

export interface Asset {
  id: string;
  tenantId: string;
  name: string;
  type: AssetType;
  status: AssetStatus;
  ipAddress?: string;
  macAddress?: string;
  hostname?: string;
  operatingSystem?: string;
  version?: string;
  location?: string;
  owner?: string;
  criticality: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  securityClearance: SecurityClearance;
  dataClassification: DataClassification;
  lastSeen: Date;
  vulnerabilities: VulnerabilityCount;
  complianceStatus: ComplianceStatus;
  tags: string[];
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

// Threat Intelligence
export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatStatus = 'ACTIVE' | 'MITIGATED' | 'RESOLVED' | 'FALSE_POSITIVE';
export type ThreatCategory =
  | 'MALWARE'
  | 'PHISHING'
  | 'RANSOMWARE'
  | 'APT'
  | 'INSIDER_THREAT'
  | 'DATA_BREACH'
  | 'DDOS'
  | 'VULNERABILITY_EXPLOIT';

export interface Threat {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  status: ThreatStatus;
  confidenceScore: number; // 0-100
  riskScore: number; // 0-100
  mitreAttackTechniques: MITREAttackTechnique[];
  indicators: ThreatIndicator[];
  affectedAssets: string[]; // Asset IDs
  recommendations: string[];
  timeline: ThreatTimelineEvent[];
  sources: string[];
  tags: string[];
  assignedTo?: string;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
}

export interface ThreatIndicator {
  type: 'IP' | 'DOMAIN' | 'URL' | 'FILE_HASH' | 'EMAIL' | 'REGISTRY_KEY';
  value: string;
  confidence: number;
  firstSeen: Date;
  lastSeen: Date;
  sources: string[];
}

export interface ThreatTimelineEvent {
  id: string;
  timestamp: Date;
  event: string;
  description: string;
  severity: ThreatSeverity;
  actor: string;
  metadata: Record<string, unknown>;
}

// Security Events
export type EventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type EventCategory =
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'NETWORK'
  | 'FILE_ACTIVITY'
  | 'PROCESS_ACTIVITY'
  | 'SYSTEM_ACTIVITY'
  | 'APPLICATION_ACTIVITY'
  | 'DATA_ACCESS';

export interface SecurityEvent {
  id: string;
  tenantId: string;
  timestamp: Date;
  category: EventCategory;
  severity: EventSeverity;
  title: string;
  description: string;
  sourceAsset: string;
  destinationAsset?: string;
  user?: string;
  sourceIp?: string;
  destinationIp?: string;
  protocol?: string;
  port?: number;
  eventData: Record<string, unknown>;
  normalized: boolean;
  enriched: boolean;
  correlated: boolean;
  tags: string[];
  riskScore: number;
  mitreAttackTechniques: string[];
  relatedAlerts: string[];
  createdAt: Date;
}

// Alerts
export type AlertStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED' | 'FALSE_POSITIVE';
export type AlertPriority = 'P1' | 'P2' | 'P3' | 'P4' | 'P5';

export interface Alert {
  id: string;
  tenantId: string;
  title: string;
  description: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  priority: AlertPriority;
  status: AlertStatus;
  riskScore: number;
  confidenceScore: number;
  sourceEvents: SecurityEvent[];
  affectedAssets: Asset[];
  assignedTo?: string;
  assignedAt?: Date;
  assignedBy?: string;
  investigationNotes: InvestigationNote[];
  recommendations: AlertRecommendation[];
  mitreAttackTechniques: MITREAttackTechnique[];
  timeline: AlertTimelineEvent[];
  tags: string[];
  sla: AlertSLA;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  resolvedBy?: string;
  resolution?: string;
}

export interface InvestigationNote {
  id: string;
  author: string;
  content: string;
  timestamp: Date;
  classification: DataClassification;
}

export interface AlertRecommendation {
  id: string;
  type: 'IMMEDIATE' | 'SHORT_TERM' | 'LONG_TERM';
  priority: number;
  action: string;
  description: string;
  estimatedEffort: string;
  riskReduction: number;
}

export interface AlertTimelineEvent {
  id: string;
  timestamp: Date;
  event: string;
  actor: string;
  details: string;
  metadata: Record<string, unknown>;
}

export interface AlertSLA {
  responseTime: number; // minutes
  resolutionTime: number; // hours
  escalationTime: number; // hours
  breached: boolean;
  timeRemaining?: number; // minutes
}

// Compliance
export type ComplianceFramework =
  | 'NIST_CSF'
  | 'ISO_27001'
  | 'SOC2'
  | 'PCI_DSS'
  | 'HIPAA'
  | 'GDPR'
  | 'SOX'
  | 'FedRAMP'
  | 'CIS_CONTROLS';

export type ComplianceStatus = 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIALLY_COMPLIANT' | 'NOT_ASSESSED';

export interface ComplianceControl {
  id: string;
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  category: string;
  subcategory?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: ComplianceStatus;
  implementationStatus: 'NOT_IMPLEMENTED' | 'PARTIALLY_IMPLEMENTED' | 'IMPLEMENTED';
  assessmentDate: Date;
  nextAssessmentDate: Date;
  evidence: string[];
  gaps: string[];
  remediation: string[];
  owner: string;
  tags: string[];
}

export interface ComplianceAssessment {
  id: string;
  tenantId: string;
  framework: ComplianceFramework;
  name: string;
  description: string;
  scope: string[];
  controls: ComplianceControl[];
  overallScore: number; // 0-100
  status: 'IN_PROGRESS' | 'COMPLETED' | 'APPROVED' | 'REJECTED';
  assessor: string;
  startDate: Date;
  endDate?: Date;
  approvedAt?: Date;
  approvedBy?: string;
  reportUrl?: string;
  findings: ComplianceFinding[];
  recommendations: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface ComplianceFinding {
  id: string;
  controlId: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  evidence: string[];
  recommendation: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED';
  assignedTo?: string;
  dueDate?: Date;
  resolvedAt?: Date;
}

// Vulnerabilities
export interface VulnerabilityCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface Vulnerability {
  id: string;
  cveId?: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvssScore?: number;
  cvssVector?: string;
  affectedAssets: string[];
  patchAvailable: boolean;
  patchComplexity: 'LOW' | 'MEDIUM' | 'HIGH';
  exploitAvailable: boolean;
  exploitComplexity: 'LOW' | 'MEDIUM' | 'HIGH';
  firstDetected: Date;
  lastSeen: Date;
  status: 'OPEN' | 'PATCHED' | 'MITIGATED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE';
  assignedTo?: string;
  dueDate?: Date;
  tags: string[];
  references: string[];
}

// Multi-Tenancy
export interface Tenant {
  id: string;
  name: string;
  displayName: string;
  domain?: string;
  logo?: string;
  primaryColor?: string;
  secondaryColor?: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'INACTIVE';
  plan: 'STARTER' | 'PROFESSIONAL' | 'ENTERPRISE' | 'CUSTOM';
  features: string[];
  limits: TenantLimits;
  settings: TenantSettings;
  createdAt: Date;
  updatedAt: Date;
}

export interface TenantLimits {
  maxUsers: number;
  maxAssets: number;
  maxAlerts: number;
  dataRetentionDays: number;
  apiCallsPerMonth: number;
}

export interface TenantSettings {
  timezone: string;
  dateFormat: string;
  alertThresholds: {
    high: number;
    medium: number;
    low: number;
  };
  notificationSettings: {
    email: boolean;
    sms: boolean;
    webhook: boolean;
  };
  complianceFrameworks: ComplianceFramework[];
  customFields: CustomField[];
}

export interface CustomField {
  id: string;
  name: string;
  type: 'text' | 'number' | 'boolean' | 'date' | 'select';
  required: boolean;
  options?: string[];
  validation?: string;
}

// User Management
export interface User {
  id: string;
  tenantId: string;
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  securityClearance: SecurityClearance;
  department?: string;
  title?: string;
  phone?: string;
  avatar?: string;
  status: 'ACTIVE' | 'INACTIVE' | 'LOCKED' | 'PENDING_VERIFICATION';
  lastLogin?: Date;
  loginCount: number;
  failedLoginAttempts: number;
  mfaEnabled: boolean;
  preferences: UserPreferences;
  permissions: string[];
  createdAt: Date;
  updatedAt: Date;
  passwordChangedAt: Date;
}

export type UserRole =
  | 'SUPER_ADMIN'
  | 'TENANT_ADMIN'
  | 'SECURITY_ANALYST'
  | 'SOC_ANALYST'
  | 'INCIDENT_RESPONDER'
  | 'COMPLIANCE_OFFICER'
  | 'READ_ONLY'
  | 'CUSTOM';

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  language: string;
  timezone: string;
  dashboardLayout: Record<string, unknown>;
  notificationPreferences: {
    email: boolean;
    browser: boolean;
    mobile: boolean;
    frequency: 'IMMEDIATE' | 'HOURLY' | 'DAILY' | 'WEEKLY';
  };
}

// API Response Types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
  errors?: string[];
  metadata?: {
    total?: number;
    page?: number;
    limit?: number;
    totalPages?: number;
  };
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

// Search and Filtering
export interface SearchParams {
  query?: string;
  filters?: Record<string, unknown>;
  sort?: {
    field: string;
    direction: 'asc' | 'desc';
  };
  page?: number;
  limit?: number;
}

export interface FilterOption {
  label: string;
  value: string;
  count?: number;
}

// Dashboard Analytics
export interface DashboardMetrics {
  totalAssets: number;
  activeThreats: number;
  openAlerts: number;
  complianceScore: number;
  riskScore: number;
  lastUpdated: Date;
}

export interface ThreatActivityData {
  timestamp: Date;
  count: number;
  severity: ThreatSeverity;
  location?: {
    latitude: number;
    longitude: number;
    country: string;
    city: string;
  };
}

export interface RiskTrendData {
  timestamp: Date;
  riskScore: number;
  factors: {
    vulnerabilities: number;
    threats: number;
    compliance: number;
    userBehavior: number;
  };
}
