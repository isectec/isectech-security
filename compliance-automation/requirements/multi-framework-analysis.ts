/**
 * iSECTECH Multi-Framework Compliance Requirements Analysis
 * Comprehensive analysis and mapping of compliance requirements across multiple regulatory frameworks
 * 
 * Supported Frameworks:
 * - SOC 2 Type II
 * - ISO 27001:2022
 * - GDPR (General Data Protection Regulation)
 * - HIPAA (Health Insurance Portability and Accountability Act)
 * - PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
 * - CMMC 2.0 (Cybersecurity Maturity Model Certification)
 * - FERPA (Family Educational Rights and Privacy Act)
 * - Custom iSECTECH Security Framework
 */

import { z } from 'zod';

// ═══════════════════════════════════════════════════════════════════════════════
// CORE TYPES AND SCHEMAS
// ═══════════════════════════════════════════════════════════════════════════════

export enum ComplianceFramework {
  SOC2_TYPE_II = 'SOC2_TYPE_II',
  ISO_27001 = 'ISO_27001',
  GDPR = 'GDPR',
  HIPAA = 'HIPAA',
  PCI_DSS = 'PCI_DSS',
  CMMC = 'CMMC',
  FERPA = 'FERPA',
  ISECTECH_CUSTOM = 'ISECTECH_CUSTOM'
}

export enum ControlType {
  ADMINISTRATIVE = 'ADMINISTRATIVE',
  TECHNICAL = 'TECHNICAL',
  PHYSICAL = 'PHYSICAL',
  OPERATIONAL = 'OPERATIONAL',
  PRIVACY = 'PRIVACY',
  SECURITY = 'SECURITY'
}

export enum ImplementationStatus {
  NOT_IMPLEMENTED = 'NOT_IMPLEMENTED',
  PARTIALLY_IMPLEMENTED = 'PARTIALLY_IMPLEMENTED',
  IMPLEMENTED = 'IMPLEMENTED',
  CONTINUOUSLY_MONITORED = 'CONTINUOUSLY_MONITORED',
  AUTOMATED = 'AUTOMATED'
}

export enum EvidenceType {
  DOCUMENT = 'DOCUMENT',
  CONFIGURATION = 'CONFIGURATION',
  LOG = 'LOG',
  SCREENSHOT = 'SCREENSHOT',
  AUTOMATED_SCAN = 'AUTOMATED_SCAN',
  MANUAL_REVIEW = 'MANUAL_REVIEW',
  INTERVIEW = 'INTERVIEW',
  OBSERVATION = 'OBSERVATION'
}

export const ComplianceControlSchema = z.object({
  id: z.string(),
  framework: z.nativeEnum(ComplianceFramework),
  category: z.string(),
  title: z.string(),
  description: z.string(),
  controlType: z.nativeEnum(ControlType),
  implementationStatus: z.nativeEnum(ImplementationStatus),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  implementationGuidance: z.string(),
  evidenceRequirements: z.array(z.nativeEnum(EvidenceType)),
  automationPossible: z.boolean(),
  frequency: z.enum(['CONTINUOUS', 'DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUALLY']),
  ownerTeam: z.string(),
  dependencies: z.array(z.string()),
  applicableServices: z.array(z.string()),
  exceptions: z.array(z.string()).optional(),
  lastAssessed: z.date().optional(),
  nextAssessment: z.date().optional(),
  
  // Cross-framework mapping
  mappedControls: z.record(z.nativeEnum(ComplianceFramework), z.array(z.string())),
  
  // iSECTECH-specific fields
  cybersecurityRelevance: z.enum(['DIRECT', 'INDIRECT', 'SUPPORTING']),
  customerDataImpact: z.boolean(),
  multiTenantConsiderations: z.string().optional(),
});

export type ComplianceControl = z.infer<typeof ComplianceControlSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// FRAMEWORK-SPECIFIC CONTROL DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * SOC 2 Type II Trust Service Criteria Controls
 * Based on AICPA TSC 2017 with 2023 updates
 */
export const SOC2_CONTROLS: ComplianceControl[] = [
  {
    id: 'SOC2-CC1.1',
    framework: ComplianceFramework.SOC2_TYPE_II,
    category: 'Common Criteria',
    title: 'Control Environment - Integrity and Ethical Values',
    description: 'The entity demonstrates a commitment to integrity and ethical values',
    controlType: ControlType.ADMINISTRATIVE,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Establish and maintain code of conduct, ethics training, and whistleblower policies',
    evidenceRequirements: [EvidenceType.DOCUMENT, EvidenceType.MANUAL_REVIEW],
    automationPossible: false,
    frequency: 'ANNUALLY',
    ownerTeam: 'Legal & Compliance',
    dependencies: [],
    applicableServices: ['All Services'],
    mappedControls: {
      [ComplianceFramework.ISO_27001]: ['A.5.1.1', 'A.7.2.1'],
      [ComplianceFramework.CMMC]: ['AC.L1-3.1.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['GOV-001']
    },
    cybersecurityRelevance: 'SUPPORTING',
    customerDataImpact: false
  },
  {
    id: 'SOC2-CC2.1',
    framework: ComplianceFramework.SOC2_TYPE_II,
    category: 'Common Criteria',
    title: 'Communication and Information - Internal Communication',
    description: 'The entity obtains or generates and uses relevant, quality information to support the functioning of internal control',
    controlType: ControlType.ADMINISTRATIVE,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'MEDIUM',
    implementationGuidance: 'Implement internal communication channels, document management, and information sharing protocols',
    evidenceRequirements: [EvidenceType.DOCUMENT, EvidenceType.CONFIGURATION],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'IT Operations',
    dependencies: ['SOC2-CC1.1'],
    applicableServices: ['Communication Systems', 'Document Management'],
    mappedControls: {
      [ComplianceFramework.ISO_27001]: ['A.5.1.2', 'A.7.2.2'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['COM-001']
    },
    cybersecurityRelevance: 'SUPPORTING',
    customerDataImpact: false
  },
  {
    id: 'SOC2-CC6.1',
    framework: ComplianceFramework.SOC2_TYPE_II,
    category: 'Common Criteria',
    title: 'Logical and Physical Access Controls - Access Management',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.CONTINUOUSLY_MONITORED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement identity and access management (IAM), multi-factor authentication, role-based access control',
    evidenceRequirements: [EvidenceType.CONFIGURATION, EvidenceType.LOG, EvidenceType.AUTOMATED_SCAN],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Security',
    dependencies: ['SOC2-CC2.1'],
    applicableServices: ['IAM Service', 'All Applications'],
    mappedControls: {
      [ComplianceFramework.ISO_27001]: ['A.9.1.1', 'A.9.2.1', 'A.9.4.2'],
      [ComplianceFramework.HIPAA]: ['164.312(a)(1)', '164.312(d)'],
      [ComplianceFramework.PCI_DSS]: ['7.1', '8.1', '8.2'],
      [ComplianceFramework.CMMC]: ['AC.L2-3.1.1', 'IA.L2-3.5.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['IAM-001', 'IAM-002']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Tenant isolation, segregation of duties across tenants'
  },
  {
    id: 'SOC2-CC7.1',
    framework: ComplianceFramework.SOC2_TYPE_II,
    category: 'Common Criteria',
    title: 'System Operations - Detection of Changes',
    description: 'The entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.AUTOMATED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Implement configuration management, vulnerability scanning, and change detection systems',
    evidenceRequirements: [EvidenceType.AUTOMATED_SCAN, EvidenceType.LOG, EvidenceType.CONFIGURATION],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Platform Engineering',
    dependencies: ['SOC2-CC6.1'],
    applicableServices: ['Vulnerability Management', 'Configuration Management', 'All Infrastructure'],
    mappedControls: {
      [ComplianceFramework.ISO_27001]: ['A.12.6.1', 'A.14.2.4'],
      [ComplianceFramework.PCI_DSS]: ['11.2', '6.1'],
      [ComplianceFramework.CMMC]: ['CM.L2-3.4.1', 'SI.L1-3.14.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['VULN-001', 'CHANGE-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true
  }
];

/**
 * ISO 27001:2022 Annex A Controls
 * Comprehensive information security management system controls
 */
export const ISO27001_CONTROLS: ComplianceControl[] = [
  {
    id: 'ISO27001-A.5.1',
    framework: ComplianceFramework.ISO_27001,
    category: 'Organizational Controls',
    title: 'Policies for Information Security',
    description: 'Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties',
    controlType: ControlType.ADMINISTRATIVE,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Develop comprehensive information security policies covering all aspects of cybersecurity operations',
    evidenceRequirements: [EvidenceType.DOCUMENT, EvidenceType.MANUAL_REVIEW],
    automationPossible: false,
    frequency: 'ANNUALLY',
    ownerTeam: 'Security',
    dependencies: [],
    applicableServices: ['All Services'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC1.1'],
      [ComplianceFramework.CMMC]: ['MP.L1-3.8.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['POL-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: false
  },
  {
    id: 'ISO27001-A.8.2',
    framework: ComplianceFramework.ISO_27001,
    category: 'Technology Controls',
    title: 'Privileged Access Rights',
    description: 'The allocation and use of privileged access rights shall be restricted and managed',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.CONTINUOUSLY_MONITORED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement privileged access management (PAM) with just-in-time access, session recording, and approval workflows',
    evidenceRequirements: [EvidenceType.CONFIGURATION, EvidenceType.LOG, EvidenceType.AUTOMATED_SCAN],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Security',
    dependencies: ['ISO27001-A.5.1'],
    applicableServices: ['PAM Service', 'All Critical Systems'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC6.1'],
      [ComplianceFramework.HIPAA]: ['164.312(a)(2)(i)'],
      [ComplianceFramework.PCI_DSS]: ['7.2', '8.2'],
      [ComplianceFramework.CMMC]: ['AC.L2-3.1.2'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['PAM-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Tenant-specific privilege boundaries, cross-tenant access prevention'
  },
  {
    id: 'ISO27001-A.8.16',
    framework: ComplianceFramework.ISO_27001,
    category: 'Technology Controls',
    title: 'Monitoring Activities',
    description: 'Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.AUTOMATED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Deploy SIEM, behavioral analytics, and automated incident detection systems',
    evidenceRequirements: [EvidenceType.LOG, EvidenceType.AUTOMATED_SCAN, EvidenceType.CONFIGURATION],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'SOC Team',
    dependencies: ['ISO27001-A.8.2'],
    applicableServices: ['SIEM', 'Monitoring Systems', 'All Infrastructure'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1'],
      [ComplianceFramework.HIPAA]: ['164.312(b)'],
      [ComplianceFramework.PCI_DSS]: ['10.1', '11.4'],
      [ComplianceFramework.CMMC]: ['AU.L2-3.3.1', 'SI.L1-3.14.2'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['MON-001', 'SIEM-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true
  }
];

/**
 * GDPR Articles and Requirements
 * European Union General Data Protection Regulation
 */
export const GDPR_CONTROLS: ComplianceControl[] = [
  {
    id: 'GDPR-ART25',
    framework: ComplianceFramework.GDPR,
    category: 'Data Protection by Design and by Default',
    title: 'Article 25 - Data Protection by Design and by Default',
    description: 'Taking into account the state of the art, the cost of implementation and the nature, scope, context and purposes of processing as well as the risks of varying likelihood and severity for rights and freedoms of natural persons posed by the processing, the controller shall, both at the time of the determination of the means for processing and at the time of the processing itself, implement appropriate technical and organisational measures',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement privacy-by-design principles: data minimization, encryption, pseudonymization, access controls',
    evidenceRequirements: [EvidenceType.DOCUMENT, EvidenceType.CONFIGURATION, EvidenceType.AUTOMATED_SCAN],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Privacy Office',
    dependencies: [],
    applicableServices: ['All Data Processing Services'],
    mappedControls: {
      [ComplianceFramework.ISO_27001]: ['A.8.2', 'A.8.24'],
      [ComplianceFramework.HIPAA]: ['164.312(a)(1)'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['PRIV-001', 'PRIV-002']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Data isolation between tenants, tenant-specific privacy controls'
  },
  {
    id: 'GDPR-ART32',
    framework: ComplianceFramework.GDPR,
    category: 'Security of Processing',
    title: 'Article 32 - Security of Processing',
    description: 'Taking into account the state of the art, the costs of implementation and the nature, scope, context and purposes of processing as well as the risk of varying likelihood and severity for the rights and freedoms of natural persons, the controller and the processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.CONTINUOUSLY_MONITORED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement encryption, access controls, incident response, regular security testing, and data breach procedures',
    evidenceRequirements: [EvidenceType.CONFIGURATION, EvidenceType.AUTOMATED_SCAN, EvidenceType.LOG, EvidenceType.DOCUMENT],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Security',
    dependencies: ['GDPR-ART25'],
    applicableServices: ['All Data Processing Services', 'Encryption Services', 'Incident Response'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC6.1', 'CC7.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.24', 'A.8.16'],
      [ComplianceFramework.HIPAA]: ['164.312(a)(1)', '164.312(e)(1)'],
      [ComplianceFramework.PCI_DSS]: ['3.4', '4.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['ENC-001', 'INC-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Tenant-specific encryption keys, isolated incident response procedures'
  },
  {
    id: 'GDPR-ART33',
    framework: ComplianceFramework.GDPR,
    category: 'Personal Data Breach Notification',
    title: 'Article 33 - Notification of Personal Data Breach to Supervisory Authority',
    description: 'In the case of a personal data breach, the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the personal data breach to the supervisory authority',
    controlType: ControlType.OPERATIONAL,
    implementationStatus: ImplementationStatus.AUTOMATED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement automated breach detection, classification, and notification systems with regulatory timeline compliance',
    evidenceRequirements: [EvidenceType.DOCUMENT, EvidenceType.LOG, EvidenceType.AUTOMATED_SCAN],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Privacy Office',
    dependencies: ['GDPR-ART32'],
    applicableServices: ['Incident Response', 'Data Loss Prevention', 'Monitoring Systems'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1'],
      [ComplianceFramework.ISO_27001]: ['A.5.26'],
      [ComplianceFramework.HIPAA]: ['164.408'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['BREACH-001', 'NOTIFY-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Tenant-specific breach notification requirements and timelines'
  }
];

/**
 * HIPAA Security Rule Controls
 * Health Insurance Portability and Accountability Act
 */
export const HIPAA_CONTROLS: ComplianceControl[] = [
  {
    id: 'HIPAA-164.312(a)(1)',
    framework: ComplianceFramework.HIPAA,
    category: 'Administrative Safeguards',
    title: 'Access Control - Unique User Identification',
    description: 'Assign a unique name and/or number for identifying and tracking user identity',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Implement unique user identification across all systems handling PHI',
    evidenceRequirements: [EvidenceType.CONFIGURATION, EvidenceType.LOG],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Security',
    dependencies: [],
    applicableServices: ['IAM Service', 'All PHI Systems'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC6.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.2'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['IAM-003']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Healthcare tenant isolation, PHI access controls'
  },
  {
    id: 'HIPAA-164.312(e)(1)',
    framework: ComplianceFramework.HIPAA,
    category: 'Technical Safeguards',
    title: 'Transmission Security',
    description: 'Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement end-to-end encryption for all PHI transmissions using TLS 1.3 or higher',
    evidenceRequirements: [EvidenceType.CONFIGURATION, EvidenceType.AUTOMATED_SCAN],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Security',
    dependencies: ['HIPAA-164.312(a)(1)'],
    applicableServices: ['Encryption Services', 'API Gateway', 'All PHI Systems'],
    mappedControls: {
      [ComplianceFramework.GDPR]: ['GDPR-ART32'],
      [ComplianceFramework.ISO_27001]: ['A.8.24'],
      [ComplianceFramework.PCI_DSS]: ['4.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['ENC-002', 'TRANS-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Tenant-specific encryption keys for PHI, isolated transmission channels'
  }
];

/**
 * PCI-DSS v4.0 Requirements
 * Payment Card Industry Data Security Standard
 */
export const PCI_DSS_CONTROLS: ComplianceControl[] = [
  {
    id: 'PCI-DSS-3.4',
    framework: ComplianceFramework.PCI_DSS,
    category: 'Protect Stored Cardholder Data',
    title: 'Requirement 3.4 - Primary Account Number Rendering',
    description: 'PAN is masked when displayed (the first six and last four digits are the maximum number of digits to be displayed), such that only personnel with a legitimate business need can see more than the first six/last four digits of the PAN',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement PAN masking in all user interfaces and reports, with role-based unmasking capabilities',
    evidenceRequirements: [EvidenceType.CONFIGURATION, EvidenceType.SCREENSHOT, EvidenceType.MANUAL_REVIEW],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Payment Security',
    dependencies: [],
    applicableServices: ['Payment Processing', 'Customer Portal', 'Admin Interfaces'],
    mappedControls: {
      [ComplianceFramework.ISO_27001]: ['A.8.2'],
      [ComplianceFramework.GDPR]: ['GDPR-ART25'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['PAY-001', 'MASK-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Payment processor tenant isolation, PCI scope boundaries'
  },
  {
    id: 'PCI-DSS-11.2',
    framework: ComplianceFramework.PCI_DSS,
    category: 'Regularly Test Security Systems',
    title: 'Requirement 11.2 - Vulnerability Scanning',
    description: 'Run internal and external network vulnerability scans at least quarterly and after any significant change in the network',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.AUTOMATED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Implement automated quarterly vulnerability scanning with ASV-approved tools for external scans',
    evidenceRequirements: [EvidenceType.AUTOMATED_SCAN, EvidenceType.DOCUMENT],
    automationPossible: true,
    frequency: 'QUARTERLY',
    ownerTeam: 'Security',
    dependencies: ['PCI-DSS-3.4'],
    applicableServices: ['Vulnerability Management', 'All PCI Systems'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1'],
      [ComplianceFramework.ISO_27001]: ['A.12.6.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['VULN-002']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true
  }
];

/**
 * CMMC 2.0 Assessment Objectives
 * Cybersecurity Maturity Model Certification
 */
export const CMMC_CONTROLS: ComplianceControl[] = [
  {
    id: 'CMMC-AC.L2-3.1.1',
    framework: ComplianceFramework.CMMC,
    category: 'Access Control',
    title: 'AC.L2-3.1.1 - Account Management',
    description: 'Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems)',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.CONTINUOUSLY_MONITORED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Implement comprehensive account lifecycle management with automated provisioning/deprovisioning',
    evidenceRequirements: [EvidenceType.CONFIGURATION, EvidenceType.LOG, EvidenceType.AUTOMATED_SCAN],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Security',
    dependencies: [],
    applicableServices: ['IAM Service', 'All Systems with CUI'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC6.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.2'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['IAM-004']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Defense contractor tenant isolation, CUI access controls'
  },
  {
    id: 'CMMC-AU.L2-3.3.1',
    framework: ComplianceFramework.CMMC,
    category: 'Audit and Accountability',
    title: 'AU.L2-3.3.1 - Audit Events',
    description: 'Create and retain information system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized information system activity',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.AUTOMATED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Implement comprehensive audit logging with centralized log management and retention',
    evidenceRequirements: [EvidenceType.LOG, EvidenceType.CONFIGURATION, EvidenceType.AUTOMATED_SCAN],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'SOC Team',
    dependencies: ['CMMC-AC.L2-3.1.1'],
    applicableServices: ['SIEM', 'Log Management', 'All Systems with CUI'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.16'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['LOG-001', 'AUDIT-001']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true
  }
];

/**
 * FERPA Requirements
 * Family Educational Rights and Privacy Act
 */
export const FERPA_CONTROLS: ComplianceControl[] = [
  {
    id: 'FERPA-99.31',
    framework: ComplianceFramework.FERPA,
    category: 'Educational Records Protection',
    title: '34 CFR 99.31 - Conditions for Disclosure',
    description: 'Educational agencies and institutions must obtain written consent before disclosing personally identifiable information from students educational records',
    controlType: ControlType.ADMINISTRATIVE,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Implement consent management system for educational record access and disclosure',
    evidenceRequirements: [EvidenceType.DOCUMENT, EvidenceType.CONFIGURATION, EvidenceType.LOG],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Privacy Office',
    dependencies: [],
    applicableServices: ['Consent Management', 'Educational Data Systems'],
    mappedControls: {
      [ComplianceFramework.GDPR]: ['GDPR-ART25'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['EDU-001', 'CONSENT-001']
    },
    cybersecurityRelevance: 'INDIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Educational institution tenant isolation, student data segregation'
  }
];

/**
 * iSECTECH Custom Security Framework
 * Tailored security controls for cybersecurity platform operations
 */
export const ISECTECH_CUSTOM_CONTROLS: ComplianceControl[] = [
  {
    id: 'ISECTECH-CSOC-001',
    framework: ComplianceFramework.ISECTECH_CUSTOM,
    category: 'Cybersecurity Operations Center',
    title: 'CSOC-001 - Real-time Threat Detection',
    description: 'Implement continuous real-time threat detection with automated response capabilities for all customer environments',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.AUTOMATED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Deploy AI-powered threat detection with sub-second response times and automated containment',
    evidenceRequirements: [EvidenceType.AUTOMATED_SCAN, EvidenceType.LOG, EvidenceType.CONFIGURATION],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'SOC Team',
    dependencies: [],
    applicableServices: ['Threat Detection Engine', 'AI/ML Services', 'SIEM'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.16'],
      [ComplianceFramework.CMMC]: ['AU.L2-3.3.1']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Tenant-specific threat signatures, isolated threat intelligence'
  },
  {
    id: 'ISECTECH-MSSP-001',
    framework: ComplianceFramework.ISECTECH_CUSTOM,
    category: 'Managed Security Service Provider',
    title: 'MSSP-001 - Multi-Tenant Security Isolation',
    description: 'Ensure complete security isolation between MSSP clients with no cross-tenant data leakage or access',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.CONTINUOUSLY_MONITORED,
    riskLevel: 'CRITICAL',
    implementationGuidance: 'Implement network-level, application-level, and data-level isolation with continuous verification',
    evidenceRequirements: [EvidenceType.AUTOMATED_SCAN, EvidenceType.CONFIGURATION, EvidenceType.MANUAL_REVIEW],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'Platform Engineering',
    dependencies: ['ISECTECH-CSOC-001'],
    applicableServices: ['Multi-Tenant Platform', 'Network Isolation', 'Data Isolation'],
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC6.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.2'],
      [ComplianceFramework.GDPR]: ['GDPR-ART25']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Core multi-tenancy requirement with zero cross-tenant access'
  },
  {
    id: 'ISECTECH-AI-001',
    framework: ComplianceFramework.ISECTECH_CUSTOM,
    category: 'AI/ML Security',
    title: 'AI-001 - ML Model Security and Integrity',
    description: 'Protect machine learning models from adversarial attacks, ensure model integrity, and validate training data security',
    controlType: ControlType.TECHNICAL,
    implementationStatus: ImplementationStatus.IMPLEMENTED,
    riskLevel: 'HIGH',
    implementationGuidance: 'Implement model versioning, adversarial testing, data poisoning detection, and model explainability',
    evidenceRequirements: [EvidenceType.AUTOMATED_SCAN, EvidenceType.MANUAL_REVIEW, EvidenceType.DOCUMENT],
    automationPossible: true,
    frequency: 'CONTINUOUS',
    ownerTeam: 'AI/ML Team',
    dependencies: ['ISECTECH-MSSP-001'],
    applicableServices: ['AI/ML Services', 'Behavioral Analytics', 'Threat Intelligence'],
    mappedControls: {
      [ComplianceFramework.ISO_27001]: ['A.14.2.4'],
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1']
    },
    cybersecurityRelevance: 'DIRECT',
    customerDataImpact: true,
    multiTenantConsiderations: 'Tenant-specific ML models, isolated training environments'
  }
];

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLIANCE REQUIREMENTS ANALYSIS ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

export class ComplianceRequirementsAnalyzer {
  private allControls: ComplianceControl[];
  private controlMappings: Map<string, ComplianceControl[]>;

  constructor() {
    this.allControls = [
      ...SOC2_CONTROLS,
      ...ISO27001_CONTROLS,
      ...GDPR_CONTROLS,
      ...HIPAA_CONTROLS,
      ...PCI_DSS_CONTROLS,
      ...CMMC_CONTROLS,
      ...FERPA_CONTROLS,
      ...ISECTECH_CUSTOM_CONTROLS
    ];
    
    this.controlMappings = this.buildControlMappings();
  }

  /**
   * Analyze compliance requirements for iSECTECH platform
   */
  public analyzeComplianceRequirements(): ComplianceAnalysisResult {
    const frameworkStats = this.calculateFrameworkStatistics();
    const overlappingControls = this.identifyOverlappingControls();
    const implementationGaps = this.identifyImplementationGaps();
    const automationOpportunities = this.identifyAutomationOpportunities();
    const riskAssessment = this.performRiskAssessment();
    const multiTenantConsiderations = this.analyzeMultiTenantRequirements();

    return {
      summary: {
        totalControls: this.allControls.length,
        totalFrameworks: Object.keys(ComplianceFramework).length,
        criticalControls: this.allControls.filter(c => c.riskLevel === 'CRITICAL').length,
        automatedControls: this.allControls.filter(c => c.implementationStatus === ImplementationStatus.AUTOMATED).length,
        cybersecurityRelevantControls: this.allControls.filter(c => c.cybersecurityRelevance === 'DIRECT').length
      },
      frameworkStats,
      overlappingControls,
      implementationGaps,
      automationOpportunities,
      riskAssessment,
      multiTenantConsiderations,
      recommendations: this.generateRecommendations()
    };
  }

  /**
   * Get controls by framework
   */
  public getControlsByFramework(framework: ComplianceFramework): ComplianceControl[] {
    return this.allControls.filter(control => control.framework === framework);
  }

  /**
   * Get controls by implementation status
   */
  public getControlsByStatus(status: ImplementationStatus): ComplianceControl[] {
    return this.allControls.filter(control => control.implementationStatus === status);
  }

  /**
   * Get high-risk controls requiring immediate attention
   */
  public getCriticalControls(): ComplianceControl[] {
    return this.allControls.filter(control => 
      control.riskLevel === 'CRITICAL' && 
      control.implementationStatus !== ImplementationStatus.AUTOMATED &&
      control.implementationStatus !== ImplementationStatus.CONTINUOUSLY_MONITORED
    );
  }

  /**
   * Find controls that can be automated for efficiency
   */
  public getAutomationCandidates(): ComplianceControl[] {
    return this.allControls.filter(control => 
      control.automationPossible && 
      control.implementationStatus !== ImplementationStatus.AUTOMATED
    );
  }

  /**
   * Generate unified control mapping across frameworks
   */
  public generateUnifiedControlMapping(): Map<string, ComplianceControl[]> {
    const unifiedMap = new Map<string, ComplianceControl[]>();
    
    // Group controls by similar control objectives
    const controlGroups = new Map<string, ComplianceControl[]>();
    
    this.allControls.forEach(control => {
      const category = this.normalizeControlCategory(control.category);
      if (!controlGroups.has(category)) {
        controlGroups.set(category, []);
      }
      controlGroups.get(category)!.push(control);
    });

    return controlGroups;
  }

  private buildControlMappings(): Map<string, ComplianceControl[]> {
    const mappings = new Map<string, ComplianceControl[]>();
    
    this.allControls.forEach(control => {
      Object.entries(control.mappedControls).forEach(([framework, controlIds]) => {
        controlIds.forEach(controlId => {
          const key = `${framework}:${controlId}`;
          if (!mappings.has(key)) {
            mappings.set(key, []);
          }
          mappings.get(key)!.push(control);
        });
      });
    });

    return mappings;
  }

  private calculateFrameworkStatistics(): FrameworkStatistics[] {
    return Object.values(ComplianceFramework).map(framework => {
      const controls = this.getControlsByFramework(framework);
      return {
        framework,
        totalControls: controls.length,
        implementedControls: controls.filter(c => 
          c.implementationStatus === ImplementationStatus.IMPLEMENTED ||
          c.implementationStatus === ImplementationStatus.CONTINUOUSLY_MONITORED ||
          c.implementationStatus === ImplementationStatus.AUTOMATED
        ).length,
        criticalControls: controls.filter(c => c.riskLevel === 'CRITICAL').length,
        automatedControls: controls.filter(c => c.implementationStatus === ImplementationStatus.AUTOMATED).length,
        gapCount: controls.filter(c => 
          c.implementationStatus === ImplementationStatus.NOT_IMPLEMENTED ||
          c.implementationStatus === ImplementationStatus.PARTIALLY_IMPLEMENTED
        ).length
      };
    });
  }

  private identifyOverlappingControls(): OverlappingControl[] {
    const overlaps: OverlappingControl[] = [];
    const processedGroups = new Set<string>();

    this.allControls.forEach(control => {
      const relatedControls: ComplianceControl[] = [];
      
      Object.entries(control.mappedControls).forEach(([framework, controlIds]) => {
        controlIds.forEach(controlId => {
          const mappedControls = this.controlMappings.get(`${framework}:${controlId}`) || [];
          relatedControls.push(...mappedControls.filter(c => c.id !== control.id));
        });
      });

      if (relatedControls.length > 0) {
        const groupKey = [control.id, ...relatedControls.map(c => c.id)].sort().join(',');
        if (!processedGroups.has(groupKey)) {
          processedGroups.add(groupKey);
          overlaps.push({
            primaryControl: control,
            relatedControls: relatedControls,
            overlapType: this.determineOverlapType(control, relatedControls),
            consolidationOpportunity: this.assessConsolidationOpportunity(control, relatedControls)
          });
        }
      }
    });

    return overlaps;
  }

  private identifyImplementationGaps(): ImplementationGap[] {
    return this.allControls
      .filter(control => 
        control.implementationStatus === ImplementationStatus.NOT_IMPLEMENTED ||
        control.implementationStatus === ImplementationStatus.PARTIALLY_IMPLEMENTED
      )
      .map(control => ({
        control,
        gapType: control.implementationStatus === ImplementationStatus.NOT_IMPLEMENTED ? 'NOT_IMPLEMENTED' : 'PARTIAL',
        priority: this.calculateGapPriority(control),
        estimatedEffort: this.estimateImplementationEffort(control),
        dependencies: control.dependencies,
        blockers: this.identifyImplementationBlockers(control)
      }));
  }

  private identifyAutomationOpportunities(): AutomationOpportunity[] {
    return this.allControls
      .filter(control => 
        control.automationPossible && 
        control.implementationStatus !== ImplementationStatus.AUTOMATED
      )
      .map(control => ({
        control,
        automationType: this.determineAutomationType(control),
        priority: this.calculateAutomationPriority(control),
        estimatedROI: this.calculateAutomationROI(control),
        technicalRequirements: this.identifyTechnicalRequirements(control)
      }));
  }

  private performRiskAssessment(): RiskAssessment {
    const criticalRisks = this.allControls.filter(c => 
      c.riskLevel === 'CRITICAL' && 
      (c.implementationStatus === ImplementationStatus.NOT_IMPLEMENTED ||
       c.implementationStatus === ImplementationStatus.PARTIALLY_IMPLEMENTED)
    );

    return {
      overallRiskLevel: criticalRisks.length > 0 ? 'HIGH' : 'MEDIUM',
      criticalGaps: criticalRisks.length,
      customerDataImpactControls: this.allControls.filter(c => c.customerDataImpact).length,
      complianceRisk: this.calculateComplianceRisk(),
      mitigation: this.generateRiskMitigation(criticalRisks)
    };
  }

  private analyzeMultiTenantRequirements(): MultiTenantRequirement[] {
    return this.allControls
      .filter(control => control.multiTenantConsiderations)
      .map(control => ({
        control,
        tenantIsolationLevel: this.determineTenantIsolationLevel(control),
        dataSegregationRequired: control.customerDataImpact,
        tenantSpecificConfiguration: this.requiresTenantSpecificConfig(control),
        crossTenantRisk: this.assessCrossTenantRisk(control)
      }));
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    
    // Critical gap recommendations
    const criticalGaps = this.getCriticalControls();
    if (criticalGaps.length > 0) {
      recommendations.push(`Immediate action required: Implement ${criticalGaps.length} critical controls`);
    }

    // Automation recommendations
    const automationCandidates = this.getAutomationCandidates();
    if (automationCandidates.length > 0) {
      recommendations.push(`Consider automating ${automationCandidates.length} controls for improved efficiency`);
    }

    // Multi-tenant recommendations
    const multiTenantControls = this.allControls.filter(c => c.multiTenantConsiderations);
    if (multiTenantControls.length > 0) {
      recommendations.push(`Review multi-tenant isolation requirements for ${multiTenantControls.length} controls`);
    }

    return recommendations;
  }

  // Helper methods for analysis
  private normalizeControlCategory(category: string): string {
    return category.toLowerCase().replace(/[^a-z0-9]/g, '-');
  }

  private determineOverlapType(primary: ComplianceControl, related: ComplianceControl[]): string {
    if (related.some(c => c.controlType === primary.controlType)) {
      return 'DIRECT_OVERLAP';
    }
    return 'COMPLEMENTARY';
  }

  private assessConsolidationOpportunity(primary: ComplianceControl, related: ComplianceControl[]): boolean {
    return related.some(c => 
      c.controlType === primary.controlType && 
      c.automationPossible && 
      primary.automationPossible
    );
  }

  private calculateGapPriority(control: ComplianceControl): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (control.riskLevel === 'CRITICAL' && control.customerDataImpact) {
      return 'HIGH';
    }
    if (control.riskLevel === 'HIGH' || control.customerDataImpact) {
      return 'MEDIUM';
    }
    return 'LOW';
  }

  private estimateImplementationEffort(control: ComplianceControl): 'LOW' | 'MEDIUM' | 'HIGH' {
    if (control.automationPossible && control.controlType === ControlType.TECHNICAL) {
      return 'MEDIUM';
    }
    if (control.controlType === ControlType.ADMINISTRATIVE) {
      return 'LOW';
    }
    return 'HIGH';
  }

  private identifyImplementationBlockers(control: ComplianceControl): string[] {
    const blockers: string[] = [];
    if (control.dependencies.length > 0) {
      blockers.push('Pending dependencies');
    }
    if (control.multiTenantConsiderations) {
      blockers.push('Multi-tenant architecture requirements');
    }
    return blockers;
  }

  private determineAutomationType(control: ComplianceControl): string {
    if (control.evidenceRequirements.includes(EvidenceType.AUTOMATED_SCAN)) {
      return 'AUTOMATED_SCANNING';
    }
    if (control.evidenceRequirements.includes(EvidenceType.LOG)) {
      return 'LOG_ANALYSIS';
    }
    return 'CONFIGURATION_MONITORING';
  }

  private calculateAutomationPriority(control: ComplianceControl): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (control.frequency === 'CONTINUOUS' && control.riskLevel === 'CRITICAL') {
      return 'HIGH';
    }
    if (control.frequency === 'CONTINUOUS' || control.riskLevel === 'HIGH') {
      return 'MEDIUM';
    }
    return 'LOW';
  }

  private calculateAutomationROI(control: ComplianceControl): number {
    // Simplified ROI calculation based on frequency and manual effort
    const frequencyMultiplier = control.frequency === 'CONTINUOUS' ? 10 : 1;
    const riskMultiplier = control.riskLevel === 'CRITICAL' ? 5 : 1;
    return frequencyMultiplier * riskMultiplier;
  }

  private identifyTechnicalRequirements(control: ComplianceControl): string[] {
    const requirements: string[] = [];
    
    if (control.evidenceRequirements.includes(EvidenceType.AUTOMATED_SCAN)) {
      requirements.push('Vulnerability scanning integration');
    }
    if (control.evidenceRequirements.includes(EvidenceType.LOG)) {
      requirements.push('SIEM/log management integration');
    }
    if (control.evidenceRequirements.includes(EvidenceType.CONFIGURATION)) {
      requirements.push('Configuration management system');
    }
    
    return requirements;
  }

  private calculateComplianceRisk(): 'HIGH' | 'MEDIUM' | 'LOW' {
    const totalControls = this.allControls.length;
    const unimplementedCritical = this.allControls.filter(c => 
      c.riskLevel === 'CRITICAL' && 
      c.implementationStatus === ImplementationStatus.NOT_IMPLEMENTED
    ).length;
    
    const riskPercentage = (unimplementedCritical / totalControls) * 100;
    
    if (riskPercentage > 10) return 'HIGH';
    if (riskPercentage > 5) return 'MEDIUM';
    return 'LOW';
  }

  private generateRiskMitigation(criticalControls: ComplianceControl[]): string[] {
    return criticalControls.map(control => 
      `Implement ${control.id}: ${control.implementationGuidance}`
    );
  }

  private determineTenantIsolationLevel(control: ComplianceControl): 'NETWORK' | 'APPLICATION' | 'DATA' | 'FULL' {
    if (control.customerDataImpact && control.riskLevel === 'CRITICAL') {
      return 'FULL';
    }
    if (control.customerDataImpact) {
      return 'DATA';
    }
    if (control.controlType === ControlType.TECHNICAL) {
      return 'APPLICATION';
    }
    return 'NETWORK';
  }

  private requiresTenantSpecificConfig(control: ComplianceControl): boolean {
    return control.multiTenantConsiderations !== undefined && 
           control.customerDataImpact;
  }

  private assessCrossTenantRisk(control: ComplianceControl): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (control.customerDataImpact && control.riskLevel === 'CRITICAL') {
      return 'HIGH';
    }
    if (control.customerDataImpact || control.riskLevel === 'HIGH') {
      return 'MEDIUM';
    }
    return 'LOW';
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS RESULT TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ComplianceAnalysisResult {
  summary: {
    totalControls: number;
    totalFrameworks: number;
    criticalControls: number;
    automatedControls: number;
    cybersecurityRelevantControls: number;
  };
  frameworkStats: FrameworkStatistics[];
  overlappingControls: OverlappingControl[];
  implementationGaps: ImplementationGap[];
  automationOpportunities: AutomationOpportunity[];
  riskAssessment: RiskAssessment;
  multiTenantConsiderations: MultiTenantRequirement[];
  recommendations: string[];
}

export interface FrameworkStatistics {
  framework: ComplianceFramework;
  totalControls: number;
  implementedControls: number;
  criticalControls: number;
  automatedControls: number;
  gapCount: number;
}

export interface OverlappingControl {
  primaryControl: ComplianceControl;
  relatedControls: ComplianceControl[];
  overlapType: string;
  consolidationOpportunity: boolean;
}

export interface ImplementationGap {
  control: ComplianceControl;
  gapType: 'NOT_IMPLEMENTED' | 'PARTIAL';
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  estimatedEffort: 'LOW' | 'MEDIUM' | 'HIGH';
  dependencies: string[];
  blockers: string[];
}

export interface AutomationOpportunity {
  control: ComplianceControl;
  automationType: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  estimatedROI: number;
  technicalRequirements: string[];
}

export interface RiskAssessment {
  overallRiskLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  criticalGaps: number;
  customerDataImpactControls: number;
  complianceRisk: 'HIGH' | 'MEDIUM' | 'LOW';
  mitigation: string[];
}

export interface MultiTenantRequirement {
  control: ComplianceControl;
  tenantIsolationLevel: 'NETWORK' | 'APPLICATION' | 'DATA' | 'FULL';
  dataSegregationRequired: boolean;
  tenantSpecificConfiguration: boolean;
  crossTenantRisk: 'HIGH' | 'MEDIUM' | 'LOW';
}

// Export the analyzer instance
export const complianceAnalyzer = new ComplianceRequirementsAnalyzer();