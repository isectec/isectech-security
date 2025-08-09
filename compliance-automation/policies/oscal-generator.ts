/**
 * iSECTECH OSCAL Documentation Generator
 * Open Security Controls Assessment Language (OSCAL) compliance documentation
 * Generates standardized compliance artifacts for audit and certification
 */

import { promises as fs } from 'fs';
import * as path from 'path';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { ControlMapping, controlMappingEngine } from './control-mapping-engine';
import { ComplianceFramework } from '../requirements/multi-framework-analysis';

// ═══════════════════════════════════════════════════════════════════════════════
// OSCAL SCHEMAS AND TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export const OSCALMetadataSchema = z.object({
  title: z.string(),
  'last-modified': z.string(),
  version: z.string(),
  'oscal-version': z.string(),
  parties: z.array(z.object({
    uuid: z.string(),
    type: z.string(),
    name: z.string(),
    'email-addresses': z.array(z.string()).optional(),
    'telephone-numbers': z.array(z.string()).optional(),
    addresses: z.array(z.any()).optional()
  })),
  'responsible-parties': z.array(z.object({
    'role-id': z.string(),
    'party-uuids': z.array(z.string())
  })).optional(),
  remarks: z.string().optional()
});

export const OSCALControlSchema = z.object({
  id: z.string(),
  class: z.string(),
  title: z.string(),
  params: z.array(z.any()).optional(),
  props: z.array(z.object({
    name: z.string(),
    value: z.string(),
    class: z.string().optional()
  })).optional(),
  links: z.array(z.object({
    href: z.string(),
    rel: z.string(),
    text: z.string().optional()
  })).optional(),
  parts: z.array(z.object({
    id: z.string(),
    name: z.string(),
    title: z.string().optional(),
    prose: z.string().optional(),
    parts: z.array(z.any()).optional()
  })),
  controls: z.array(z.any()).optional()
});

export type OSCALMetadata = z.infer<typeof OSCALMetadataSchema>;
export type OSCALControl = z.infer<typeof OSCALControlSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// OSCAL DOCUMENT GENERATORS
// ═══════════════════════════════════════════════════════════════════════════════

export class OSCALGenerator {
  private organizationInfo: {
    uuid: string;
    name: string;
    email: string;
    website: string;
    address: any;
  };

  constructor() {
    this.organizationInfo = {
      uuid: 'isectech-org-uuid',
      name: 'iSECTECH',
      email: 'compliance@isectech.com',
      website: 'https://isectech.com',
      address: {
        'addr-lines': ['123 Security Boulevard'],
        city: 'Cyber City',
        state: 'CA',
        'postal-code': '90210',
        country: 'US'
      }
    };
  }

  /**
   * Generate complete OSCAL Catalog for iSECTECH unified controls
   */
  async generateCatalog(): Promise<any> {
    const catalog = {
      catalog: {
        uuid: uuidv4(),
        metadata: this.generateMetadata('iSECTECH Unified Compliance Control Catalog'),
        groups: this.generateControlGroups(),
        controls: this.generateCatalogControls()
      }
    };

    return catalog;
  }

  /**
   * Generate OSCAL System Security Plan (SSP)
   */
  async generateSSP(systemInfo: SystemInfo): Promise<any> {
    const ssp = {
      'system-security-plan': {
        uuid: uuidv4(),
        metadata: this.generateMetadata(`${systemInfo.name} System Security Plan`),
        'import-profile': {
          href: './profiles/isectech-baseline-profile.json'
        },
        'system-characteristics': this.generateSystemCharacteristics(systemInfo),
        'system-implementation': this.generateSystemImplementation(systemInfo),
        'control-implementation': this.generateControlImplementation(),
        'back-matter': this.generateBackMatter()
      }
    };

    return ssp;
  }

  /**
   * Generate OSCAL Profile for specific compliance framework
   */
  async generateProfile(framework: ComplianceFramework): Promise<any> {
    const profile = {
      profile: {
        uuid: uuidv4(),
        metadata: this.generateMetadata(`iSECTECH ${framework} Compliance Profile`),
        imports: [
          {
            href: './catalogs/isectech-unified-catalog.json',
            'include-controls': this.getFrameworkControlIds(framework)
          }
        ],
        merge: {
          'combine': {
            method: 'merge'
          }
        },
        modify: {
          'set-parameters': this.getFrameworkParameters(framework),
          alters: this.getFrameworkAlterations(framework)
        }
      }
    };

    return profile;
  }

  /**
   * Generate OSCAL Assessment Plan (AP)
   */
  async generateAssessmentPlan(frameworkList: ComplianceFramework[]): Promise<any> {
    const ap = {
      'assessment-plan': {
        uuid: uuidv4(),
        metadata: this.generateMetadata('iSECTECH Multi-Framework Assessment Plan'),
        'import-ssp': {
          href: './ssp/isectech-system-security-plan.json'
        },
        'local-definitions': this.generateLocalDefinitions(),
        terms: this.generateTermsAndConditions(),
        'reviewed-controls': this.generateReviewedControls(frameworkList),
        'assessment-subjects': this.generateAssessmentSubjects(),
        'assessment-assets': this.generateAssessmentAssets(),
        tasks: this.generateAssessmentTasks(frameworkList)
      }
    };

    return ap;
  }

  /**
   * Generate OSCAL Assessment Results (AR)
   */
  async generateAssessmentResults(assessmentData: AssessmentData): Promise<any> {
    const ar = {
      'assessment-results': {
        uuid: uuidv4(),
        metadata: this.generateMetadata('iSECTECH Compliance Assessment Results'),
        'import-ap': {
          href: './assessment-plans/isectech-assessment-plan.json'
        },
        'local-definitions': this.generateLocalDefinitions(),
        results: this.generateResults(assessmentData),
        'back-matter': this.generateBackMatter()
      }
    };

    return ar;
  }

  /**
   * Generate OSCAL Plan of Action and Milestones (POA&M)
   */
  async generatePOAM(findings: Finding[]): Promise<any> {
    const poam = {
      'plan-of-action-and-milestones': {
        uuid: uuidv4(),
        metadata: this.generateMetadata('iSECTECH Plan of Action and Milestones'),
        'import-ssp': {
          href: './ssp/isectech-system-security-plan.json'
        },
        'system-id': {
          'identifier-type': 'https://ietf.org/rfc/rfc4122',
          id: 'isectech-cybersecurity-platform'
        },
        'local-definitions': this.generateLocalDefinitions(),
        'poam-items': this.generatePOAMItems(findings)
      }
    };

    return poam;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // PRIVATE HELPER METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private generateMetadata(title: string): OSCALMetadata {
    return {
      title,
      'last-modified': new Date().toISOString(),
      version: '1.0.0',
      'oscal-version': '1.0.6',
      parties: [
        {
          uuid: this.organizationInfo.uuid,
          type: 'organization',
          name: this.organizationInfo.name,
          'email-addresses': [this.organizationInfo.email],
          'telephone-numbers': ['+1-555-ISECTECH'],
          addresses: [this.organizationInfo.address]
        },
        {
          uuid: 'ciso-uuid',
          type: 'person',
          name: 'Chief Information Security Officer',
          'email-addresses': ['ciso@isectech.com']
        },
        {
          uuid: 'compliance-officer-uuid',
          type: 'person',
          name: 'Compliance Officer',
          'email-addresses': ['compliance@isectech.com']
        }
      ],
      'responsible-parties': [
        {
          'role-id': 'system-owner',
          'party-uuids': ['ciso-uuid']
        },
        {
          'role-id': 'compliance-manager',
          'party-uuids': ['compliance-officer-uuid']
        }
      ],
      remarks: 'Generated by iSECTECH Compliance Automation Framework'
    };
  }

  private generateControlGroups(): any[] {
    const categories = ['Access Control', 'Detection and Response', 'Data Security', 'Risk Management'];
    
    return categories.map(category => ({
      id: category.toLowerCase().replace(/\s+/g, '-'),
      title: category,
      controls: controlMappingEngine.getCategoryMappings(category).map(m => m.id)
    }));
  }

  private generateCatalogControls(): OSCALControl[] {
    const controls: OSCALControl[] = [];
    
    // Get all unified control mappings
    const unifiedControls = Array.from(controlMappingEngine['controlMappings'].values());
    
    unifiedControls.forEach(mapping => {
      const control: OSCALControl = {
        id: mapping.id,
        class: 'iSECTECH',
        title: mapping.title,
        props: [
          { name: 'label', value: mapping.id },
          { name: 'sort-id', value: mapping.id.toLowerCase() },
          { name: 'implementation-level', value: mapping.implementationLevel },
          { name: 'automation-level', value: mapping.automationLevel },
          { name: 'enforcement-type', value: mapping.enforcementType },
          { name: 'risk-level', value: mapping.riskLevel },
          { name: 'multi-tenant', value: mapping.multiTenantConfiguration.requiresTenantIsolation.toString() }
        ],
        links: [
          {
            href: `#control-implementation-${mapping.id}`,
            rel: 'implementation',
            text: 'Implementation Details'
          }
        ],
        parts: [
          {
            id: `${mapping.id}_smt`,
            name: 'statement',
            prose: mapping.description
          },
          {
            id: `${mapping.id}_gdn`,
            name: 'guidance',
            prose: this.generateImplementationGuidance(mapping)
          },
          {
            id: `${mapping.id}_obj`,
            name: 'objective',
            prose: mapping.controlObjective
          },
          {
            id: `${mapping.id}_asm`,
            name: 'assessment',
            parts: [
              {
                id: `${mapping.id}_asm_obj`,
                name: 'assessment-objective',
                prose: `Verify that ${mapping.controlObjective.toLowerCase()}`
              },
              {
                id: `${mapping.id}_asm_mth`,
                name: 'assessment-method',
                prose: this.generateAssessmentMethods(mapping)
              }
            ]
          }
        ]
      };
      
      controls.push(control);
    });
    
    return controls;
  }

  private generateSystemCharacteristics(systemInfo: SystemInfo): any {
    return {
      'system-ids': [
        {
          'identifier-type': 'https://ietf.org/rfc/rfc4122',
          id: systemInfo.id
        }
      ],
      'system-name': systemInfo.name,
      'system-name-short': systemInfo.shortName,
      description: systemInfo.description,
      'security-sensitivity-level': systemInfo.sensitivityLevel,
      'system-information': {
        'information-types': systemInfo.informationTypes.map(type => ({
          uuid: uuidv4(),
          title: type.title,
          description: type.description,
          'categorizations': type.categorizations,
          'confidentiality-impact': { base: type.confidentialityImpact },
          'integrity-impact': { base: type.integrityImpact },
          'availability-impact': { base: type.availabilityImpact }
        }))
      },
      'security-impact-level': {
        'security-objective-confidentiality': systemInfo.securityObjectives.confidentiality,
        'security-objective-integrity': systemInfo.securityObjectives.integrity,
        'security-objective-availability': systemInfo.securityObjectives.availability
      },
      status: { state: systemInfo.status },
      'authorization-boundary': {
        description: systemInfo.authorizationBoundary.description,
        diagrams: systemInfo.authorizationBoundary.diagrams?.map(diagram => ({
          uuid: uuidv4(),
          description: diagram.description,
          links: [{ href: diagram.href, rel: 'diagram' }]
        }))
      },
      'network-architecture': {
        description: 'Multi-tenant cloud-native cybersecurity platform',
        diagrams: [
          {
            uuid: uuidv4(),
            description: 'Network Architecture Diagram',
            links: [{ href: './diagrams/network-architecture.png', rel: 'diagram' }]
          }
        ]
      },
      'data-flow': {
        description: 'Data flow for cybersecurity event processing and analysis',
        diagrams: [
          {
            uuid: uuidv4(),
            description: 'Data Flow Diagram',
            links: [{ href: './diagrams/data-flow.png', rel: 'diagram' }]
          }
        ]
      }
    };
  }

  private generateSystemImplementation(systemInfo: SystemInfo): any {
    return {
      users: systemInfo.users.map(user => ({
        uuid: uuidv4(),
        title: user.title,
        description: user.description,
        'role-ids': user.roleIds,
        'authorized-privileges': user.authorizedPrivileges.map(priv => ({
          title: priv.title,
          description: priv.description,
          'functions-performed': priv.functionsPerformed
        }))
      })),
      components: systemInfo.components.map(component => ({
        uuid: uuidv4(),
        type: component.type,
        title: component.title,
        description: component.description,
        status: { state: component.status },
        'responsible-roles': component.responsibleRoles.map(role => ({
          'role-id': role.roleId,
          'party-uuids': role.partyUuids
        })),
        protocols: component.protocols?.map(protocol => ({
          uuid: uuidv4(),
          name: protocol.name,
          title: protocol.title,
          'port-ranges': protocol.portRanges
        }))
      }))
    };
  }

  private generateControlImplementation(): any {
    const implementedControls: any[] = [];
    
    // Get all unified control mappings
    const unifiedControls = Array.from(controlMappingEngine['controlMappings'].values());
    
    unifiedControls.forEach(mapping => {
      implementedControls.push({
        'control-id': mapping.id,
        'set-parameters': this.generateControlParameters(mapping),
        'implementation-status': { state: this.mapImplementationStatus(mapping.implementationLevel) },
        statements: [
          {
            'statement-id': `${mapping.id}_smt`,
            uuid: uuidv4(),
            description: mapping.description,
            'responsible-roles': [
              { 'role-id': 'system-administrator' },
              { 'role-id': 'security-analyst' }
            ],
            'by-components': this.generateByComponents(mapping)
          }
        ]
      });
    });
    
    return {
      description: 'iSECTECH cybersecurity platform control implementation',
      'implemented-requirements': implementedControls
    };
  }

  private generateLocalDefinitions(): any {
    return {
      'objectives-and-methods': [
        {
          uuid: uuidv4(),
          description: 'Automated compliance validation using policy-as-code',
          'assessment-method': 'AUTOMATED',
          'assessment-type': 'TEST'
        },
        {
          uuid: uuidv4(),
          description: 'Manual review of documentation and procedures',
          'assessment-method': 'EXAMINE',
          'assessment-type': 'INTERVIEW'
        }
      ],
      activities: [
        {
          uuid: uuidv4(),
          title: 'Continuous Compliance Monitoring',
          description: 'Real-time monitoring and validation of compliance controls',
          'step': [
            { uuid: uuidv4(), title: 'Deploy OPA policies', description: 'Deploy and configure policy enforcement' },
            { uuid: uuidv4(), title: 'Monitor violations', description: 'Monitor and alert on policy violations' },
            { uuid: uuidv4(), title: 'Generate reports', description: 'Generate compliance reports and evidence' }
          ]
        }
      ]
    };
  }

  private generateTermsAndConditions(): any {
    return {
      parts: [
        {
          id: 'assessment-assumptions',
          name: 'assumptions',
          prose: 'This assessment assumes that all system components are properly configured and operational during the assessment period.'
        },
        {
          id: 'assessment-methodology',
          name: 'methodology',
          prose: 'Assessment methodology combines automated policy enforcement validation with manual documentation review and stakeholder interviews.'
        }
      ]
    };
  }

  private generateReviewedControls(frameworks: ComplianceFramework[]): any {
    const reviewedControls: any[] = [];
    
    frameworks.forEach(framework => {
      const mappings = controlMappingEngine.getFrameworkMappings(framework);
      mappings.forEach(mapping => {
        reviewedControls.push({
          'control-id': mapping.id,
          'control-objective': mapping.controlObjective,
          'assessment-methods': this.getAssessmentMethodsForControl(mapping),
          'assessment-objects': this.getAssessmentObjectsForControl(mapping)
        });
      });
    });
    
    return {
      description: 'Controls selected for assessment based on applicable compliance frameworks',
      'control-selections': [
        {
          'include-controls': reviewedControls.map(rc => ({ 'control-id': rc['control-id'] }))
        }
      ]
    };
  }

  private generateAssessmentSubjects(): any[] {
    return [
      {
        uuid: uuidv4(),
        type: 'inventory-item',
        title: 'iSECTECH Cybersecurity Platform',
        description: 'Multi-tenant cloud-native cybersecurity platform',
        'include-subjects': [
          { 'subject-uuid': 'platform-components' },
          { 'subject-uuid': 'data-stores' },
          { 'subject-uuid': 'network-infrastructure' }
        ]
      }
    ];
  }

  private generateAssessmentAssets(): any[] {
    return [
      {
        uuid: 'assessment-team',
        title: 'Assessment Team',
        description: 'Internal security and compliance assessment team',
        'assessment-subjects': [
          { 'subject-uuid': 'ciso-uuid' },
          { 'subject-uuid': 'compliance-officer-uuid' }
        ]
      },
      {
        uuid: 'assessment-tools',
        title: 'Assessment Tools',
        description: 'Automated and manual assessment tools',
        'assessment-subjects': [
          { 'subject-uuid': 'opa-policy-engine' },
          { 'subject-uuid': 'vulnerability-scanner' },
          { 'subject-uuid': 'siem-platform' }
        ]
      }
    ];
  }

  private generateAssessmentTasks(frameworks: ComplianceFramework[]): any[] {
    const tasks: any[] = [];
    
    frameworks.forEach(framework => {
      tasks.push({
        uuid: uuidv4(),
        type: 'action',
        title: `${framework} Compliance Assessment`,
        description: `Comprehensive assessment of ${framework} compliance requirements`,
        'associated-activities': [
          {
            'activity-uuid': 'continuous-monitoring',
            subjects: [
              { 'subject-uuid': 'platform-components', type: 'inventory-item' }
            ]
          }
        ],
        'responsible-roles': [
          { 'role-id': 'assessor' },
          { 'role-id': 'system-owner' }
        ],
        timing: {
          'within-date-range': {
            start: new Date().toISOString(),
            end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
          }
        }
      });
    });
    
    return tasks;
  }

  private generateResults(assessmentData: AssessmentData): any[] {
    return assessmentData.results.map(result => ({
      uuid: uuidv4(),
      title: result.title,
      description: result.description,
      start: result.start,
      end: result.end,
      'reviewed-controls': {
        'control-selections': [
          {
            'include-controls': result.controlsAssessed.map(controlId => ({ 'control-id': controlId }))
          }
        ]
      },
      attestations: result.attestations.map(attestation => ({
        uuid: uuidv4(),
        'responsible-parties': [{ 'role-id': attestation.roleId, 'party-uuids': [attestation.partyUuid] }],
        parts: [
          {
            id: 'attestation-statement',
            name: 'attestation',
            prose: attestation.statement
          }
        ]
      })),
      'assessment-log': {
        entries: result.logEntries.map(entry => ({
          uuid: uuidv4(),
          title: entry.title,
          description: entry.description,
          start: entry.timestamp,
          'logged-by': [{ 'party-uuid': entry.loggedBy }],
          'related-tasks': entry.relatedTasks?.map(taskId => ({ 'task-uuid': taskId }))
        }))
      },
      observations: result.observations.map(obs => ({
        uuid: uuidv4(),
        title: obs.title,
        description: obs.description,
        'collected': obs.collected,
        'assessment-method': obs.method,
        types: [obs.type],
        origins: obs.origins.map(origin => ({
          uuid: uuidv4(),
          actors: [{ 'party-uuid': origin.actorUuid, type: origin.actorType }]
        })),
        subjects: obs.subjects.map(subject => ({ 'subject-uuid': subject })),
        'relevant-evidence': obs.evidence.map(evidence => ({
          href: evidence.href,
          description: evidence.description
        }))
      })),
      findings: result.findings.map(finding => ({
        uuid: uuidv4(),
        title: finding.title,
        description: finding.description,
        'implementation-statement-uuid': finding.implementationStatementUuid,
        'related-observations': finding.relatedObservations.map(obsId => ({ 'observation-uuid': obsId })),
        'target': {
          type: finding.target.type,
          'target-id': finding.target.targetId,
          title: finding.target.title,
          description: finding.target.description
        },
        'risk': {
          status: finding.risk.status,
          'risk-log': {
            entries: finding.risk.logEntries.map(entry => ({
              uuid: uuidv4(),
              title: entry.title,
              description: entry.description,
              start: entry.timestamp,
              'logged-by': [{ 'party-uuid': entry.loggedBy }]
            }))
          }
        }
      }))
    }));
  }

  private generatePOAMItems(findings: Finding[]): any[] {
    return findings.map(finding => ({
      uuid: uuidv4(),
      title: finding.title,
      description: finding.description,
      'related-findings': finding.relatedFindings?.map(findingId => ({ 'finding-uuid': findingId })),
      'related-observations': finding.relatedObservations?.map(obsId => ({ 'observation-uuid': obsId })),
      'associated-risk': {
        title: finding.risk.title,
        description: finding.risk.description,
        statement: finding.risk.statement,
        status: finding.risk.status,
        'risk-log': {
          entries: finding.risk.logEntries.map(entry => ({
            uuid: uuidv4(),
            title: entry.title,
            description: entry.description,
            start: entry.timestamp,
            'logged-by': [{ 'party-uuid': entry.loggedBy }]
          }))
        }
      },
      'remediation-tracking': {
        'tracking-entries': finding.remediationTracking.map(tracking => ({
          uuid: uuidv4(),
          type: tracking.type,
          title: tracking.title,
          description: tracking.description,
          'date-time-stamp': tracking.timestamp,
          'responsible-roles': [{ 'role-id': tracking.responsibleRole }]
        }))
      }
    }));
  }

  private generateBackMatter(): any {
    return {
      resources: [
        {
          uuid: uuidv4(),
          title: 'iSECTECH Compliance Framework Documentation',
          'document-ids': [
            { identifier: 'ISECTECH-CF-001', scheme: 'internal' }
          ],
          'citation': {
            text: 'iSECTECH Multi-Framework Compliance Implementation Guide'
          },
          rlinks: [
            { href: './docs/compliance-implementation-guide.pdf' }
          ]
        },
        {
          uuid: uuidv4(),
          title: 'OPA Policy Repository',
          'document-ids': [
            { identifier: 'ISECTECH-OPA-001', scheme: 'internal' }
          ],
          'citation': {
            text: 'Open Policy Agent Compliance Policies'
          },
          rlinks: [
            { href: './policies/opa-policies.json' }
          ]
        }
      ]
    };
  }

  // Additional helper methods...
  private generateImplementationGuidance(mapping: ControlMapping): string {
    return `Implementation guidance for ${mapping.title}: ${mapping.controlObjective}. 
    Technical complexity: ${mapping.technicalComplexity}. 
    Automation level: ${mapping.automationLevel}. 
    Multi-tenant considerations: ${mapping.multiTenantConfiguration.requiresTenantIsolation ? 'Requires tenant isolation' : 'No special tenant requirements'}.`;
  }

  private generateAssessmentMethods(mapping: ControlMapping): string {
    const methods = [];
    if (mapping.automationLevel === 'FULLY_AUTOMATED') {
      methods.push('Automated policy validation');
    }
    if (mapping.evidenceRequirements.length > 0) {
      methods.push('Evidence review and validation');
    }
    methods.push('Configuration assessment');
    return methods.join(', ');
  }

  private generateControlParameters(mapping: ControlMapping): any[] {
    return [
      {
        'param-id': `${mapping.id}_param_1`,
        'param-value': mapping.implementationLevel
      }
    ];
  }

  private mapImplementationStatus(level: string): string {
    switch (level) {
      case 'ADVANCED': return 'implemented';
      case 'ENHANCED': return 'partially-implemented';
      case 'BASIC': return 'planned';
      default: return 'not-applicable';
    }
  }

  private generateByComponents(mapping: ControlMapping): any[] {
    return [
      {
        'component-uuid': 'opa-policy-engine',
        uuid: uuidv4(),
        description: 'Automated policy enforcement using Open Policy Agent',
        'implementation-status': { state: 'implemented' }
      }
    ];
  }

  private getFrameworkControlIds(framework: ComplianceFramework): any {
    const mappings = controlMappingEngine.getFrameworkMappings(framework);
    return {
      'with-ids': mappings.map(m => m.id)
    };
  }

  private getFrameworkParameters(framework: ComplianceFramework): any[] {
    // Framework-specific parameter overrides
    return [];
  }

  private getFrameworkAlterations(framework: ComplianceFramework): any[] {
    // Framework-specific control alterations
    return [];
  }

  private getAssessmentMethodsForControl(mapping: ControlMapping): string[] {
    const methods = ['TEST'];
    if (mapping.evidenceRequirements.some(req => req.includes('document'))) {
      methods.push('EXAMINE');
    }
    if (mapping.evidenceRequirements.some(req => req.includes('interview'))) {
      methods.push('INTERVIEW');
    }
    return methods;
  }

  private getAssessmentObjectsForControl(mapping: ControlMapping): string[] {
    return mapping.applicableServices;
  }

  /**
   * Save OSCAL document to file
   */
  async saveOSCALDocument(document: any, filename: string, outputDir: string = './oscal-output'): Promise<void> {
    await fs.mkdir(outputDir, { recursive: true });
    const filepath = path.join(outputDir, filename);
    await fs.writeFile(filepath, JSON.stringify(document, null, 2));
    console.log(`OSCAL document saved to: ${filepath}`);
  }

  /**
   * Generate complete OSCAL documentation suite
   */
  async generateCompleteSuite(outputDir: string = './oscal-output'): Promise<void> {
    console.log('Generating complete OSCAL documentation suite...');
    
    // Generate catalog
    const catalog = await this.generateCatalog();
    await this.saveOSCALDocument(catalog, 'isectech-unified-catalog.json', outputDir);
    
    // Generate profiles for each framework
    const frameworks = Object.values(ComplianceFramework);
    for (const framework of frameworks) {
      const profile = await this.generateProfile(framework);
      await this.saveOSCALDocument(profile, `${framework.toLowerCase()}-profile.json`, outputDir);
    }
    
    // Generate SSP
    const systemInfo: SystemInfo = this.getDefaultSystemInfo();
    const ssp = await this.generateSSP(systemInfo);
    await this.saveOSCALDocument(ssp, 'isectech-system-security-plan.json', outputDir);
    
    // Generate Assessment Plan
    const assessmentPlan = await this.generateAssessmentPlan(frameworks);
    await this.saveOSCALDocument(assessmentPlan, 'isectech-assessment-plan.json', outputDir);
    
    console.log('OSCAL documentation suite generated successfully');
  }

  private getDefaultSystemInfo(): SystemInfo {
    return {
      id: 'isectech-cybersecurity-platform',
      name: 'iSECTECH Cybersecurity Platform',
      shortName: 'iSECTECH',
      description: 'Multi-tenant cloud-native cybersecurity platform providing comprehensive security monitoring, threat detection, and compliance automation',
      sensitivityLevel: 'high',
      status: 'operational',
      informationTypes: [
        {
          title: 'Security Event Data',
          description: 'Real-time security events and alerts',
          categorizations: ['security'],
          confidentialityImpact: 'moderate',
          integrityImpact: 'high',
          availabilityImpact: 'high'
        }
      ],
      securityObjectives: {
        confidentiality: 'moderate',
        integrity: 'high',
        availability: 'high'
      },
      authorizationBoundary: {
        description: 'iSECTECH platform boundary includes all components within the Kubernetes cluster and associated cloud services'
      },
      users: [],
      components: []
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface SystemInfo {
  id: string;
  name: string;
  shortName: string;
  description: string;
  sensitivityLevel: string;
  status: string;
  informationTypes: Array<{
    title: string;
    description: string;
    categorizations: string[];
    confidentialityImpact: string;
    integrityImpact: string;
    availabilityImpact: string;
  }>;
  securityObjectives: {
    confidentiality: string;
    integrity: string;
    availability: string;
  };
  authorizationBoundary: {
    description: string;
    diagrams?: Array<{
      description: string;
      href: string;
    }>;
  };
  users: Array<{
    title: string;
    description: string;
    roleIds: string[];
    authorizedPrivileges: Array<{
      title: string;
      description: string;
      functionsPerformed: string[];
    }>;
  }>;
  components: Array<{
    type: string;
    title: string;
    description: string;
    status: string;
    responsibleRoles: Array<{
      roleId: string;
      partyUuids: string[];
    }>;
    protocols?: Array<{
      name: string;
      title: string;
      portRanges: Array<{
        start: number;
        end: number;
        transport: string;
      }>;
    }>;
  }>;
}

export interface AssessmentData {
  results: Array<{
    title: string;
    description: string;
    start: string;
    end: string;
    controlsAssessed: string[];
    attestations: Array<{
      roleId: string;
      partyUuid: string;
      statement: string;
    }>;
    logEntries: Array<{
      title: string;
      description: string;
      timestamp: string;
      loggedBy: string;
      relatedTasks?: string[];
    }>;
    observations: Array<{
      title: string;
      description: string;
      collected: string;
      method: string;
      type: string;
      origins: Array<{
        actorUuid: string;
        actorType: string;
      }>;
      subjects: string[];
      evidence: Array<{
        href: string;
        description: string;
      }>;
    }>;
    findings: Array<{
      title: string;
      description: string;
      implementationStatementUuid: string;
      relatedObservations: string[];
      target: {
        type: string;
        targetId: string;
        title: string;
        description: string;
      };
      risk: {
        status: string;
        logEntries: Array<{
          title: string;
          description: string;
          timestamp: string;
          loggedBy: string;
        }>;
      };
    }>;
  }>;
}

export interface Finding {
  title: string;
  description: string;
  relatedFindings?: string[];
  relatedObservations?: string[];
  risk: {
    title: string;
    description: string;
    statement: string;
    status: string;
    logEntries: Array<{
      title: string;
      description: string;
      timestamp: string;
      loggedBy: string;
    }>;
  };
  remediationTracking: Array<{
    type: string;
    title: string;
    description: string;
    timestamp: string;
    responsibleRole: string;
  }>;
}

// Export the generator
export const oscalGenerator = new OSCALGenerator();