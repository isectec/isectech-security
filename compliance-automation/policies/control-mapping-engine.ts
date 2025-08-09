/**
 * iSECTECH Control Mapping Engine
 * Unified control mapping layer that aligns controls across all supported compliance frameworks
 * Implements policy-as-code using OPA and OSCAL for automated enforcement and documentation
 */

import { z } from 'zod';
import { ComplianceFramework, ComplianceControl, complianceAnalyzer } from '../requirements/multi-framework-analysis';

// ═══════════════════════════════════════════════════════════════════════════════
// CONTROL MAPPING SCHEMAS AND TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export const ControlMappingSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  category: z.string(),
  mappedControls: z.record(z.nativeEnum(ComplianceFramework), z.array(z.string())),
  primaryFramework: z.nativeEnum(ComplianceFramework),
  controlObjective: z.string(),
  implementationLevel: z.enum(['BASIC', 'ENHANCED', 'ADVANCED']),
  automationLevel: z.enum(['MANUAL', 'SEMI_AUTOMATED', 'FULLY_AUTOMATED']),
  enforcementType: z.enum(['PREVENTIVE', 'DETECTIVE', 'CORRECTIVE']),
  opaPolicy: z.string(),
  oscalDefinition: z.object({
    controlId: z.string(),
    class: z.string(),
    title: z.string(),
    properties: z.record(z.string(), z.any()),
    parts: z.array(z.any()),
    controls: z.array(z.any()).optional()
  }),
  evidenceRequirements: z.array(z.string()),
  testProcedures: z.array(z.string()),
  riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  businessImpact: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  technicalComplexity: z.enum(['LOW', 'MEDIUM', 'HIGH']),
  multiTenantConfiguration: z.object({
    requiresTenantIsolation: z.boolean(),
    tenantSpecificPolicies: z.boolean(),
    crossTenantRisk: z.enum(['LOW', 'MEDIUM', 'HIGH']),
    isolationLevel: z.enum(['NETWORK', 'APPLICATION', 'DATA', 'FULL'])
  }),
  metadata: z.object({
    createdBy: z.string(),
    createdAt: z.date(),
    lastModified: z.date(),
    version: z.string(),
    approvedBy: z.array(z.string()),
    reviewDate: z.date(),
    nextReview: z.date()
  })
});

export type ControlMapping = z.infer<typeof ControlMappingSchema>;

export const PolicyEnforcementResultSchema = z.object({
  policyId: z.string(),
  controlId: z.string(),
  timestamp: z.date(),
  result: z.enum(['PASS', 'FAIL', 'WARNING', 'ERROR']),
  details: z.string(),
  evidence: z.array(z.object({
    type: z.string(),
    source: z.string(),
    data: z.any(),
    hash: z.string(),
    signature: z.string().optional()
  })),
  remediation: z.array(z.string()).optional(),
  riskScore: z.number().min(0).max(10),
  tenantId: z.string().optional(),
  affectedResources: z.array(z.string()),
  complianceFrameworks: z.array(z.nativeEnum(ComplianceFramework))
});

export type PolicyEnforcementResult = z.infer<typeof PolicyEnforcementResultSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// UNIFIED CONTROL MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

export const UNIFIED_CONTROL_MATRIX: ControlMapping[] = [
  {
    id: 'UCM-IAM-001',
    title: 'Identity and Access Management',
    description: 'Comprehensive identity and access management controls across all systems and frameworks',
    category: 'Access Control',
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC6.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.2'],
      [ComplianceFramework.HIPAA]: ['164.312(a)(1)'],
      [ComplianceFramework.PCI_DSS]: ['7.1', '8.1', '8.2'],
      [ComplianceFramework.CMMC]: ['AC.L2-3.1.1', 'IA.L2-3.5.1'],
      [ComplianceFramework.GDPR]: ['GDPR-ART25'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['IAM-001', 'IAM-002', 'IAM-003', 'IAM-004']
    },
    primaryFramework: ComplianceFramework.ISECTECH_CUSTOM,
    controlObjective: 'Ensure only authorized users have access to systems and data based on least privilege principles',
    implementationLevel: 'ADVANCED',
    automationLevel: 'FULLY_AUTOMATED',
    enforcementType: 'PREVENTIVE',
    opaPolicy: `
package isectech.iam

import rego.v1

# Allow access if user is authenticated and authorized
default allow = false

allow if {
    input.user.authenticated == true
    input.user.permissions[input.resource.type]
    not denied_by_tenant_isolation
    not denied_by_time_restrictions
    audit_access_attempt
}

# Deny access if user is from different tenant
denied_by_tenant_isolation if {
    input.user.tenant_id != input.resource.tenant_id
    input.resource.tenant_id != "shared"
}

# Deny access outside business hours for sensitive resources
denied_by_time_restrictions if {
    input.resource.sensitivity == "high"
    not business_hours
}

business_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 17
}

# Audit all access attempts
audit_access_attempt if {
    print("ACCESS_ATTEMPT:", {
        "user": input.user.id,
        "resource": input.resource.id,
        "tenant": input.user.tenant_id,
        "timestamp": time.now_ns(),
        "allowed": allow
    })
}
`,
    oscalDefinition: {
      controlId: 'UCM-IAM-001',
      class: 'SP800-53',
      title: 'Identity and Access Management',
      properties: {
        label: 'UCM-IAM-001',
        sort_id: 'iam-001',
        status: 'implemented'
      },
      parts: [
        {
          id: 'iam-001_smt',
          name: 'statement',
          narrative: 'The organization implements comprehensive identity and access management controls to ensure only authorized users can access systems and data.'
        },
        {
          id: 'iam-001_gdn',
          name: 'guidance',
          narrative: 'Implement multi-factor authentication, role-based access control, privileged access management, and continuous access monitoring.'
        }
      ]
    },
    evidenceRequirements: [
      'IAM system configuration exports',
      'User access logs and audit trails',
      'Role and permission matrices',
      'Multi-factor authentication reports',
      'Privileged access session recordings'
    ],
    testProcedures: [
      'Verify multi-factor authentication is enabled for all users',
      'Test role-based access control implementation',
      'Validate privileged access approval workflows',
      'Confirm access logging and monitoring',
      'Test tenant isolation boundaries'
    ],
    riskLevel: 'CRITICAL',
    businessImpact: 'CRITICAL',
    technicalComplexity: 'HIGH',
    multiTenantConfiguration: {
      requiresTenantIsolation: true,
      tenantSpecificPolicies: true,
      crossTenantRisk: 'HIGH',
      isolationLevel: 'FULL'
    },
    metadata: {
      createdBy: 'Security Team',
      createdAt: new Date('2024-01-15T00:00:00Z'),
      lastModified: new Date('2024-08-02T00:00:00Z'),
      version: '1.2.0',
      approvedBy: ['CISO', 'CTO', 'Compliance Officer'],
      reviewDate: new Date('2024-08-01T00:00:00Z'),
      nextReview: new Date('2024-11-01T00:00:00Z')
    }
  },
  {
    id: 'UCM-MON-001',
    title: 'Security Monitoring and Incident Detection',
    description: 'Continuous security monitoring, anomaly detection, and incident response controls',
    category: 'Detection and Response',
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.16'],
      [ComplianceFramework.HIPAA]: ['164.312(b)'],
      [ComplianceFramework.PCI_DSS]: ['10.1', '11.4'],
      [ComplianceFramework.CMMC]: ['AU.L2-3.3.1', 'SI.L1-3.14.2'],
      [ComplianceFramework.GDPR]: ['GDPR-ART32'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['MON-001', 'SIEM-001', 'CSOC-001']
    },
    primaryFramework: ComplianceFramework.ISECTECH_CUSTOM,
    controlObjective: 'Detect, alert, and respond to security incidents in real-time across all systems and tenants',
    implementationLevel: 'ADVANCED',
    automationLevel: 'FULLY_AUTOMATED',
    enforcementType: 'DETECTIVE',
    opaPolicy: `
package isectech.monitoring

import rego.v1

# Security event classification and response
default alert_level = "info"

alert_level := "critical" if {
    input.event.type == "authentication_failure"
    input.event.failed_attempts >= 5
    input.event.time_window <= 300  # 5 minutes
}

alert_level := "critical" if {
    input.event.type == "privilege_escalation"
    not authorized_escalation
}

alert_level := "high" if {
    input.event.type == "suspicious_network_activity"
    input.event.data_volume > 100000000  # 100MB
}

alert_level := "medium" if {
    input.event.type == "configuration_change"
    not input.event.approved_change
}

# Automated response actions
response_actions contains "block_user" if {
    alert_level == "critical"
    input.event.type == "authentication_failure"
}

response_actions contains "isolate_network" if {
    alert_level == "critical"
    input.event.type == "malware_detected"
}

response_actions contains "create_incident" if {
    alert_level in ["critical", "high"]
}

# Tenant-specific monitoring rules
tenant_monitoring_required if {
    input.tenant.compliance_frameworks[_] in [
        "HIPAA", "PCI_DSS", "CMMC"
    ]
}

authorized_escalation if {
    input.event.approver_id
    input.event.approval_timestamp
    input.event.approval_timestamp > (time.now_ns() - 3600000000000)  # 1 hour
}
`,
    oscalDefinition: {
      controlId: 'UCM-MON-001',
      class: 'SP800-53',
      title: 'Security Monitoring and Incident Detection',
      properties: {
        label: 'UCM-MON-001',
        sort_id: 'mon-001',
        status: 'implemented'
      },
      parts: [
        {
          id: 'mon-001_smt',
          name: 'statement',
          narrative: 'The organization implements continuous security monitoring and automated incident detection across all systems and data.'
        },
        {
          id: 'mon-001_gdn',
          name: 'guidance',
          narrative: 'Deploy SIEM, behavioral analytics, threat intelligence integration, and automated incident response capabilities.'
        }
      ]
    },
    evidenceRequirements: [
      'SIEM configuration and rule sets',
      'Security event logs and alerts',
      'Incident response logs and timelines',
      'Threat detection analytics reports',
      'Automated response execution logs'
    ],
    testProcedures: [
      'Verify real-time event detection and alerting',
      'Test automated incident response workflows',
      'Validate threat intelligence integration',
      'Confirm security analytics accuracy',
      'Test multi-tenant monitoring isolation'
    ],
    riskLevel: 'HIGH',
    businessImpact: 'HIGH',
    technicalComplexity: 'HIGH',
    multiTenantConfiguration: {
      requiresTenantIsolation: true,
      tenantSpecificPolicies: true,
      crossTenantRisk: 'MEDIUM',
      isolationLevel: 'APPLICATION'
    },
    metadata: {
      createdBy: 'SOC Team',
      createdAt: new Date('2024-01-15T00:00:00Z'),
      lastModified: new Date('2024-08-02T00:00:00Z'),
      version: '1.1.0',
      approvedBy: ['CISO', 'SOC Manager'],
      reviewDate: new Date('2024-08-01T00:00:00Z'),
      nextReview: new Date('2024-10-01T00:00:00Z')
    }
  },
  {
    id: 'UCM-DATA-001',
    title: 'Data Protection and Encryption',
    description: 'Comprehensive data protection controls including encryption, masking, and access controls',
    category: 'Data Security',
    mappedControls: {
      [ComplianceFramework.GDPR]: ['GDPR-ART25', 'GDPR-ART32'],
      [ComplianceFramework.HIPAA]: ['164.312(e)(1)'],
      [ComplianceFramework.PCI_DSS]: ['3.4', '4.1'],
      [ComplianceFramework.ISO_27001]: ['A.8.24'],
      [ComplianceFramework.CMMC]: ['SC.L2-3.13.8'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['ENC-001', 'ENC-002', 'PRIV-001', 'PRIV-002']
    },
    primaryFramework: ComplianceFramework.GDPR,
    controlObjective: 'Protect sensitive data through encryption, access controls, and privacy-preserving techniques',
    implementationLevel: 'ADVANCED',
    automationLevel: 'FULLY_AUTOMATED',
    enforcementType: 'PREVENTIVE',
    opaPolicy: `
package isectech.data_protection

import rego.v1

# Data classification and protection requirements
default encryption_required = false
default masking_required = false

encryption_required if {
    input.data.classification in ["confidential", "restricted", "pii", "phi", "pci"]
}

encryption_required if {
    input.data.tenant_classification in ["healthcare", "financial", "government"]
}

masking_required if {
    input.data.type in ["ssn", "ccn", "account_number"]
    input.user.role != "data_admin"
}

# Tenant-specific data protection
tenant_encryption_key if {
    input.tenant.id
    input.data.tenant_specific == true
}

# Cross-border data transfer restrictions
transfer_allowed if {
    input.transfer.source_country == input.transfer.destination_country
}

transfer_allowed if {
    input.transfer.destination_country in adequacy_countries
    input.data.classification != "restricted"
}

transfer_allowed if {
    input.transfer.legal_basis in ["consent", "contract", "vital_interests"]
    input.transfer.safeguards == "standard_contractual_clauses"
}

adequacy_countries := [
    "US", "CA", "UK", "EU", "JP", "AU", "NZ"
]

# Data retention and deletion
retention_period_days := 2555 if {  # 7 years
    input.data.type in ["audit_log", "financial_record"]
}

retention_period_days := 365 if {  # 1 year
    input.data.type in ["session_log", "api_log"]
}

retention_period_days := 90 if {  # 90 days
    input.data.type in ["debug_log", "performance_metric"]
}

deletion_required if {
    data_age_days > retention_period_days
}

data_age_days := (time.now_ns() - input.data.created_timestamp) / 86400000000000
`,
    oscalDefinition: {
      controlId: 'UCM-DATA-001',
      class: 'SP800-53',
      title: 'Data Protection and Encryption',
      properties: {
        label: 'UCM-DATA-001',
        sort_id: 'data-001',
        status: 'implemented'
      },
      parts: [
        {
          id: 'data-001_smt',
          name: 'statement',
          narrative: 'The organization implements comprehensive data protection controls including encryption, access restrictions, and privacy-preserving techniques.'
        },
        {
          id: 'data-001_gdn',
          name: 'guidance',
          narrative: 'Implement encryption at rest and in transit, data classification, access controls, data masking, and privacy-by-design principles.'
        }
      ]
    },
    evidenceRequirements: [
      'Encryption configuration and key management',
      'Data classification policies and procedures',
      'Access control matrices for sensitive data',
      'Data masking and anonymization reports',
      'Cross-border transfer documentation'
    ],
    testProcedures: [
      'Verify encryption implementation for data at rest and in transit',
      'Test data classification and labeling accuracy',
      'Validate data masking and anonymization effectiveness',
      'Confirm tenant-specific data isolation',
      'Test data retention and deletion procedures'
    ],
    riskLevel: 'CRITICAL',
    businessImpact: 'CRITICAL',
    technicalComplexity: 'HIGH',
    multiTenantConfiguration: {
      requiresTenantIsolation: true,
      tenantSpecificPolicies: true,
      crossTenantRisk: 'HIGH',
      isolationLevel: 'DATA'
    },
    metadata: {
      createdBy: 'Privacy Office',
      createdAt: new Date('2024-01-15T00:00:00Z'),
      lastModified: new Date('2024-08-02T00:00:00Z'),
      version: '1.3.0',
      approvedBy: ['DPO', 'CISO', 'Legal'],
      reviewDate: new Date('2024-08-01T00:00:00Z'),
      nextReview: new Date('2024-11-01T00:00:00Z')
    }
  },
  {
    id: 'UCM-VULN-001',
    title: 'Vulnerability Management and Security Testing',
    description: 'Continuous vulnerability assessment, patch management, and security testing controls',
    category: 'Risk Management',
    mappedControls: {
      [ComplianceFramework.SOC2_TYPE_II]: ['CC7.1'],
      [ComplianceFramework.ISO_27001]: ['A.12.6.1', 'A.14.2.4'],
      [ComplianceFramework.PCI_DSS]: ['11.2', '6.1'],
      [ComplianceFramework.CMMC]: ['CM.L2-3.4.1', 'SI.L1-3.14.1'],
      [ComplianceFramework.ISECTECH_CUSTOM]: ['VULN-001', 'VULN-002']
    },
    primaryFramework: ComplianceFramework.ISO_27001,
    controlObjective: 'Identify, assess, and remediate security vulnerabilities in a timely manner',
    implementationLevel: 'ENHANCED',
    automationLevel: 'FULLY_AUTOMATED',
    enforcementType: 'DETECTIVE',
    opaPolicy: `
package isectech.vulnerability_management

import rego.v1

# Vulnerability severity and remediation timeframes
default remediation_sla_hours = 720  # 30 days

remediation_sla_hours := 24 if {  # 1 day
    input.vulnerability.severity == "critical"
    input.vulnerability.exploitable == true
}

remediation_sla_hours := 72 if {  # 3 days
    input.vulnerability.severity == "high"
    input.vulnerability.public_exploit == true
}

remediation_sla_hours := 168 if {  # 7 days
    input.vulnerability.severity == "high"
}

remediation_sla_hours := 336 if {  # 14 days
    input.vulnerability.severity == "medium"
    input.asset.criticality == "high"
}

# SLA breach detection
sla_breached if {
    vulnerability_age_hours > remediation_sla_hours
}

vulnerability_age_hours := (time.now_ns() - input.vulnerability.discovered_timestamp) / 3600000000000

# Automated patching approval
auto_patch_approved if {
    input.vulnerability.severity in ["low", "medium"]
    input.patch.testing_completed == true
    input.asset.environment != "production"
}

auto_patch_approved if {
    input.vulnerability.severity == "critical"
    input.vulnerability.active_exploitation == true
    input.patch.emergency_approved == true
}

# Compliance framework specific requirements
pci_quarterly_scan_required if {
    input.asset.pci_scope == true
    days_since_last_scan > 90
}

cmmc_continuous_monitoring_required if {
    input.asset.cui_handling == true
}

days_since_last_scan := (time.now_ns() - input.asset.last_scan_timestamp) / 86400000000000

# Risk scoring and prioritization
risk_score := severity_score + exploitability_score + asset_criticality_score

severity_score := 10 if input.vulnerability.severity == "critical"
severity_score := 7 if input.vulnerability.severity == "high"
severity_score := 4 if input.vulnerability.severity == "medium"
severity_score := 1 if input.vulnerability.severity == "low"

exploitability_score := 5 if input.vulnerability.exploitable == true
exploitability_score := 3 if input.vulnerability.public_exploit == true
exploitability_score := 0

asset_criticality_score := 5 if input.asset.criticality == "critical"
asset_criticality_score := 3 if input.asset.criticality == "high"
asset_criticality_score := 1 if input.asset.criticality == "medium"
asset_criticality_score := 0
`,
    oscalDefinition: {
      controlId: 'UCM-VULN-001',
      class: 'SP800-53',
      title: 'Vulnerability Management and Security Testing',
      properties: {
        label: 'UCM-VULN-001',
        sort_id: 'vuln-001',
        status: 'implemented'
      },
      parts: [
        {
          id: 'vuln-001_smt',
          name: 'statement',
          narrative: 'The organization implements continuous vulnerability management including scanning, assessment, and remediation processes.'
        },
        {
          id: 'vuln-001_gdn',
          name: 'guidance',
          narrative: 'Deploy automated vulnerability scanners, implement risk-based remediation prioritization, and maintain current patch management procedures.'
        }
      ]
    },
    evidenceRequirements: [
      'Vulnerability scan reports and schedules',
      'Patch management policies and procedures',
      'Risk assessment and prioritization matrices',
      'Remediation tracking and SLA reports',
      'Security testing results and documentation'
    ],
    testProcedures: [
      'Verify automated vulnerability scanning coverage',
      'Test remediation SLA compliance and tracking',
      'Validate risk-based prioritization accuracy',
      'Confirm patch management process effectiveness',
      'Test integration with asset management systems'
    ],
    riskLevel: 'HIGH',
    businessImpact: 'HIGH',
    technicalComplexity: 'MEDIUM',
    multiTenantConfiguration: {
      requiresTenantIsolation: false,
      tenantSpecificPolicies: true,
      crossTenantRisk: 'LOW',
      isolationLevel: 'APPLICATION'
    },
    metadata: {
      createdBy: 'Vulnerability Management Team',
      createdAt: new Date('2024-01-15T00:00:00Z'),
      lastModified: new Date('2024-08-02T00:00:00Z'),
      version: '1.0.0',
      approvedBy: ['Security Manager', 'Infrastructure Lead'],
      reviewDate: new Date('2024-08-01T00:00:00Z'),
      nextReview: new Date('2024-11-01T00:00:00Z')
    }
  }
];

// ═══════════════════════════════════════════════════════════════════════════════
// CONTROL MAPPING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

export class ControlMappingEngine {
  private controlMappings: Map<string, ControlMapping>;
  private frameworkMappings: Map<ComplianceFramework, ControlMapping[]>;
  private categoryMappings: Map<string, ControlMapping[]>;

  constructor() {
    this.controlMappings = new Map();
    this.frameworkMappings = new Map();
    this.categoryMappings = new Map();
    
    this.initializeMappings();
  }

  /**
   * Initialize all control mappings and indexes
   */
  private initializeMappings(): void {
    // Load unified control matrix
    UNIFIED_CONTROL_MATRIX.forEach(mapping => {
      this.controlMappings.set(mapping.id, mapping);
      
      // Index by framework
      Object.keys(mapping.mappedControls).forEach(framework => {
        const fw = framework as ComplianceFramework;
        if (!this.frameworkMappings.has(fw)) {
          this.frameworkMappings.set(fw, []);
        }
        this.frameworkMappings.get(fw)!.push(mapping);
      });
      
      // Index by category
      if (!this.categoryMappings.has(mapping.category)) {
        this.categoryMappings.set(mapping.category, []);
      }
      this.categoryMappings.get(mapping.category)!.push(mapping);
    });
  }

  /**
   * Get unified control mapping by ID
   */
  public getControlMapping(id: string): ControlMapping | undefined {
    return this.controlMappings.get(id);
  }

  /**
   * Get all control mappings for a specific framework
   */
  public getFrameworkMappings(framework: ComplianceFramework): ControlMapping[] {
    return this.frameworkMappings.get(framework) || [];
  }

  /**
   * Get all control mappings by category
   */
  public getCategoryMappings(category: string): ControlMapping[] {
    return this.categoryMappings.get(category) || [];
  }

  /**
   * Find controls that map across multiple frameworks
   */
  public getCrossFrameworkMappings(): Map<string, ComplianceFramework[]> {
    const crossMappings = new Map<string, ComplianceFramework[]>();
    
    this.controlMappings.forEach(mapping => {
      const frameworks = Object.keys(mapping.mappedControls) as ComplianceFramework[];
      if (frameworks.length > 1) {
        crossMappings.set(mapping.id, frameworks);
      }
    });
    
    return crossMappings;
  }

  /**
   * Generate OSCAL catalog for all unified controls
   */
  public generateOSCALCatalog(): any {
    const catalog = {
      catalog: {
        uuid: 'f8f9e56e-8f5a-4f6b-9c7d-1a2b3c4d5e6f',
        metadata: {
          title: 'iSECTECH Unified Compliance Control Catalog',
          'last-modified': new Date().toISOString(),
          version: '1.0.0',
          'oscal-version': '1.0.6',
          parties: [
            {
              uuid: 'isectech-org',
              type: 'organization',
              name: 'iSECTECH',
              'email-addresses': ['compliance@isectech.com']
            }
          ],
          responsible_parties: [
            {
              'role-id': 'maintainer',
              'party-uuids': ['isectech-org']
            }
          ]
        },
        groups: [
          {
            id: 'access-control',
            title: 'Access Control',
            controls: this.getCategoryMappings('Access Control').map(m => m.id)
          },
          {
            id: 'detection-response',
            title: 'Detection and Response',
            controls: this.getCategoryMappings('Detection and Response').map(m => m.id)
          },
          {
            id: 'data-security',
            title: 'Data Security',
            controls: this.getCategoryMappings('Data Security').map(m => m.id)
          },
          {
            id: 'risk-management',
            title: 'Risk Management',
            controls: this.getCategoryMappings('Risk Management').map(m => m.id)
          }
        ],
        controls: Array.from(this.controlMappings.values()).map(mapping => ({
          ...mapping.oscalDefinition,
          properties: {
            ...mapping.oscalDefinition.properties,
            frameworks: Object.keys(mapping.mappedControls).join(', '),
            automation_level: mapping.automationLevel,
            enforcement_type: mapping.enforcementType,
            risk_level: mapping.riskLevel,
            multi_tenant: mapping.multiTenantConfiguration.requiresTenantIsolation.toString()
          }
        }))
      }
    };
    
    return catalog;
  }

  /**
   * Validate control mapping consistency
   */
  public validateMappings(): ValidationResult[] {
    const results: ValidationResult[] = [];
    
    this.controlMappings.forEach(mapping => {
      // Validate OPA policy syntax
      try {
        this.validateOPAPolicy(mapping.opaPolicy);
      } catch (error) {
        results.push({
          controlId: mapping.id,
          type: 'ERROR',
          message: `Invalid OPA policy: ${error instanceof Error ? error.message : 'Unknown error'}`,
          framework: mapping.primaryFramework
        });
      }
      
      // Validate OSCAL definition
      if (!mapping.oscalDefinition.controlId || !mapping.oscalDefinition.title) {
        results.push({
          controlId: mapping.id,
          type: 'ERROR',
          message: 'Invalid OSCAL definition: missing required fields',
          framework: mapping.primaryFramework
        });
      }
      
      // Validate framework mappings
      Object.entries(mapping.mappedControls).forEach(([framework, controlIds]) => {
        if (controlIds.length === 0) {
          results.push({
            controlId: mapping.id,
            type: 'WARNING',
            message: `No mapped controls for framework: ${framework}`,
            framework: framework as ComplianceFramework
          });
        }
      });
      
      // Validate multi-tenant configuration
      if (mapping.multiTenantConfiguration.requiresTenantIsolation && 
          mapping.multiTenantConfiguration.crossTenantRisk === 'LOW') {
        results.push({
          controlId: mapping.id,
          type: 'WARNING',
          message: 'Inconsistent multi-tenant configuration: requires isolation but low cross-tenant risk',
          framework: mapping.primaryFramework
        });
      }
    });
    
    return results;
  }

  /**
   * Generate implementation report for specific frameworks
   */
  public generateImplementationReport(frameworks: ComplianceFramework[]): ImplementationReport {
    const report: ImplementationReport = {
      frameworks,
      totalControls: 0,
      implementedControls: 0,
      automatedControls: 0,
      coverageByFramework: new Map(),
      gapAnalysis: [],
      recommendations: []
    };
    
    frameworks.forEach(framework => {
      const mappings = this.getFrameworkMappings(framework);
      const implemented = mappings.filter(m => 
        m.implementationLevel !== 'BASIC' || m.automationLevel !== 'MANUAL'
      );
      const automated = mappings.filter(m => m.automationLevel === 'FULLY_AUTOMATED');
      
      report.totalControls += mappings.length;
      report.implementedControls += implemented.length;
      report.automatedControls += automated.length;
      
      report.coverageByFramework.set(framework, {
        total: mappings.length,
        implemented: implemented.length,
        automated: automated.length,
        coverage: implemented.length / mappings.length * 100
      });
      
      // Identify gaps
      mappings.filter(m => m.implementationLevel === 'BASIC').forEach(mapping => {
        report.gapAnalysis.push({
          controlId: mapping.id,
          framework,
          gapType: 'IMPLEMENTATION',
          severity: mapping.riskLevel,
          description: `Control ${mapping.id} requires enhanced implementation`
        });
      });
    });
    
    // Generate recommendations
    if (report.automatedControls / report.totalControls < 0.8) {
      report.recommendations.push('Consider increasing automation coverage for better efficiency');
    }
    
    if (report.implementedControls / report.totalControls < 0.9) {
      report.recommendations.push('Address implementation gaps to improve compliance posture');
    }
    
    return report;
  }

  /**
   * Basic OPA policy syntax validation
   */
  private validateOPAPolicy(policy: string): void {
    // Basic syntax checks
    if (!policy.includes('package ')) {
      throw new Error('Policy must declare a package');
    }
    
    if (!policy.includes('import rego.v1')) {
      throw new Error('Policy should import rego.v1 for best practices');
    }
    
    // Check for common syntax errors
    const lines = policy.split('\n');
    lines.forEach((line, index) => {
      if (line.trim().startsWith('#')) return; // Skip comments
      
      if (line.includes('if {') && !line.includes('if {')) {
        throw new Error(`Syntax error at line ${index + 1}: malformed if statement`);
      }
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ValidationResult {
  controlId: string;
  type: 'ERROR' | 'WARNING' | 'INFO';
  message: string;
  framework: ComplianceFramework;
}

export interface ImplementationReport {
  frameworks: ComplianceFramework[];
  totalControls: number;
  implementedControls: number;
  automatedControls: number;
  coverageByFramework: Map<ComplianceFramework, {
    total: number;
    implemented: number;
    automated: number;
    coverage: number;
  }>;
  gapAnalysis: {
    controlId: string;
    framework: ComplianceFramework;
    gapType: 'IMPLEMENTATION' | 'AUTOMATION' | 'DOCUMENTATION';
    severity: string;
    description: string;
  }[];
  recommendations: string[];
}

// Export the engine instance
export const controlMappingEngine = new ControlMappingEngine();