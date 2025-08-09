/**
 * iSECTECH Evidence Collection Engine
 * Automated evidence collection and continuous monitoring for compliance controls
 * Ensures digital signatures for evidence integrity and real-time alerting for deviations
 */

import { promises as fs } from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import { z } from 'zod';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { ComplianceFramework } from '../requirements/multi-framework-analysis';
import { ControlMapping, controlMappingEngine } from '../policies/control-mapping-engine';

// ═══════════════════════════════════════════════════════════════════════════════
// EVIDENCE COLLECTION SCHEMAS AND TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export const EvidenceRecordSchema = z.object({
  id: z.string(),
  controlId: z.string(),
  complianceFrameworks: z.array(z.nativeEnum(ComplianceFramework)),
  tenantId: z.string().optional(),
  evidenceType: z.enum([
    'CONFIGURATION',
    'LOG_ENTRY',
    'SCAN_RESULT',
    'SCREENSHOT',
    'DOCUMENT',
    'AUTOMATED_CHECK',
    'MANUAL_REVIEW',
    'INTERVIEW_RECORD',
    'SYSTEM_STATE',
    'NETWORK_CAPTURE',
    'DATABASE_QUERY',
    'API_RESPONSE'
  ]),
  source: z.object({
    system: z.string(),
    component: z.string(),
    location: z.string(),
    agent: z.string(),
    version: z.string()
  }),
  collectionTimestamp: z.date(),
  data: z.any(),
  metadata: z.object({
    size: z.number(),
    format: z.string(),
    encoding: z.string().optional(),
    checksum: z.string(),
    digitalSignature: z.object({
      algorithm: z.string(),
      signature: z.string(),
      publicKey: z.string(),
      certificateChain: z.array(z.string()).optional()
    }),
    classification: z.enum(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']),
    retentionPeriod: z.number(), // days
    tags: z.array(z.string())
  }),
  auditTrail: z.array(z.object({
    action: z.string(),
    timestamp: z.date(),
    actor: z.string(),
    details: z.any()
  })),
  validationStatus: z.enum(['PENDING', 'VALID', 'INVALID', 'EXPIRED']),
  complianceContext: z.object({
    requirement: z.string(),
    assessmentMethod: z.string(),
    expectedResult: z.string(),
    actualResult: z.string(),
    assessment: z.enum(['PASS', 'FAIL', 'WARNING', 'NOT_APPLICABLE']),
    assessor: z.string().optional(),
    reviewDate: z.date().optional()
  })
});

export type EvidenceRecord = z.infer<typeof EvidenceRecordSchema>;

export const MonitoringAgentConfigSchema = z.object({
  agentId: z.string(),
  name: z.string(),
  type: z.enum([
    'CLOUD_RESOURCE_MONITOR',
    'ENDPOINT_AGENT',
    'NETWORK_MONITOR',
    'APPLICATION_MONITOR',
    'DATABASE_MONITOR',
    'KUBERNETES_MONITOR',
    'SECURITY_SCANNER',
    'LOG_COLLECTOR'
  ]),
  targetSystems: z.array(z.string()),
  collectionSchedule: z.object({
    frequency: z.enum(['CONTINUOUS', 'REAL_TIME', 'HOURLY', 'DAILY', 'WEEKLY']),
    cronExpression: z.string().optional(),
    triggerEvents: z.array(z.string()).optional()
  }),
  evidenceTypes: z.array(z.string()),
  credentials: z.object({
    type: z.enum(['AWS_ROLE', 'SERVICE_ACCOUNT', 'API_KEY', 'CERTIFICATE']),
    configuration: z.any()
  }),
  outputConfiguration: z.object({
    storage: z.object({
      primary: z.string(),
      backup: z.string().optional(),
      encryption: z.boolean(),
      compression: z.boolean()
    }),
    notification: z.object({
      onSuccess: z.boolean(),
      onFailure: z.boolean(),
      onAnomalies: z.boolean(),
      channels: z.array(z.string())
    })
  }),
  monitoringConfiguration: z.object({
    healthCheck: z.object({
      enabled: z.boolean(),
      interval: z.number(), // seconds
      timeout: z.number(), // seconds
      retries: z.number()
    }),
    metrics: z.object({
      enabled: z.boolean(),
      namespace: z.string(),
      customMetrics: z.array(z.string())
    }),
    alerting: z.object({
      enabled: z.boolean(),
      thresholds: z.record(z.string(), z.number()),
      escalation: z.array(z.string())
    })
  })
});

export type MonitoringAgentConfig = z.infer<typeof MonitoringAgentConfigSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// PREDEFINED MONITORING AGENTS FOR ISECTECH
// ═══════════════════════════════════════════════════════════════════════════════

export const ISECTECH_MONITORING_AGENTS: MonitoringAgentConfig[] = [
  {
    agentId: 'aws-resource-monitor',
    name: 'AWS Cloud Resource Monitor',
    type: 'CLOUD_RESOURCE_MONITOR',
    targetSystems: ['aws-iam', 'aws-s3', 'aws-ec2', 'aws-rds', 'aws-eks'],
    collectionSchedule: {
      frequency: 'HOURLY',
      cronExpression: '0 * * * *',
      triggerEvents: ['configuration_change', 'policy_update', 'access_event']
    },
    evidenceTypes: ['CONFIGURATION', 'LOG_ENTRY', 'AUTOMATED_CHECK'],
    credentials: {
      type: 'AWS_ROLE',
      configuration: {
        roleArn: 'arn:aws:iam::ACCOUNT:role/isectech-compliance-monitor',
        externalId: 'isectech-compliance-external-id'
      }
    },
    outputConfiguration: {
      storage: {
        primary: 's3://isectech-compliance-evidence/aws-resources/',
        backup: 's3://isectech-compliance-evidence-backup/aws-resources/',
        encryption: true,
        compression: true
      },
      notification: {
        onSuccess: false,
        onFailure: true,
        onAnomalies: true,
        channels: ['sns://compliance-alerts', 'slack://compliance-channel']
      }
    },
    monitoringConfiguration: {
      healthCheck: {
        enabled: true,
        interval: 300, // 5 minutes
        timeout: 30,
        retries: 3
      },
      metrics: {
        enabled: true,
        namespace: 'iSECTECH/Compliance/AWS',
        customMetrics: ['evidence_collected', 'compliance_violations', 'configuration_drift']
      },
      alerting: {
        enabled: true,
        thresholds: {
          'evidence_collection_failure_rate': 0.05, // 5%
          'compliance_violations_per_hour': 10,
          'configuration_drift_percentage': 0.02 // 2%
        },
        escalation: ['compliance-team', 'security-team', 'platform-team']
      }
    }
  },
  {
    agentId: 'kubernetes-monitor',
    name: 'Kubernetes Cluster Monitor',
    type: 'KUBERNETES_MONITOR',
    targetSystems: ['isectech-prod-cluster', 'isectech-staging-cluster'],
    collectionSchedule: {
      frequency: 'CONTINUOUS',
      triggerEvents: ['pod_creation', 'service_update', 'rbac_change', 'secret_access']
    },
    evidenceTypes: ['CONFIGURATION', 'LOG_ENTRY', 'SYSTEM_STATE'],
    credentials: {
      type: 'SERVICE_ACCOUNT',
      configuration: {
        namespace: 'isectech-compliance',
        serviceAccount: 'compliance-monitor',
        clusterRole: 'compliance-cluster-reader'
      }
    },
    outputConfiguration: {
      storage: {
        primary: 's3://isectech-compliance-evidence/kubernetes/',
        encryption: true,
        compression: true
      },
      notification: {
        onSuccess: false,
        onFailure: true,
        onAnomalies: true,
        channels: ['sns://compliance-alerts']
      }
    },
    monitoringConfiguration: {
      healthCheck: {
        enabled: true,
        interval: 60, // 1 minute
        timeout: 10,
        retries: 3
      },
      metrics: {
        enabled: true,
        namespace: 'iSECTECH/Compliance/Kubernetes',
        customMetrics: ['rbac_violations', 'security_policy_violations', 'resource_compliance']
      },
      alerting: {
        enabled: true,
        thresholds: {
          'rbac_violations_per_hour': 5,
          'security_policy_violations_per_hour': 3,
          'non_compliant_resources_percentage': 0.01 // 1%
        },
        escalation: ['sre-team', 'security-team']
      }
    }
  },
  {
    agentId: 'application-security-monitor',
    name: 'Application Security Monitor',
    type: 'APPLICATION_MONITOR',
    targetSystems: ['isectech-api', 'isectech-frontend', 'isectech-auth-service'],
    collectionSchedule: {
      frequency: 'REAL_TIME',
      triggerEvents: ['authentication_event', 'authorization_failure', 'data_access', 'api_call']
    },
    evidenceTypes: ['LOG_ENTRY', 'API_RESPONSE', 'AUTOMATED_CHECK'],
    credentials: {
      type: 'API_KEY',
      configuration: {
        endpoint: 'https://api.isectech.com/compliance',
        apiKey: '${ISECTECH_COMPLIANCE_API_KEY}',
        headers: {
          'X-Tenant-ID': 'compliance-monitoring',
          'X-Agent-ID': 'application-security-monitor'
        }
      }
    },
    outputConfiguration: {
      storage: {
        primary: 's3://isectech-compliance-evidence/applications/',
        encryption: true,
        compression: true
      },
      notification: {
        onSuccess: false,
        onFailure: true,
        onAnomalies: true,
        channels: ['sns://security-alerts', 'slack://security-channel']
      }
    },
    monitoringConfiguration: {
      healthCheck: {
        enabled: true,
        interval: 30, // 30 seconds
        timeout: 5,
        retries: 3
      },
      metrics: {
        enabled: true,
        namespace: 'iSECTECH/Compliance/Applications',
        customMetrics: ['authentication_failures', 'authorization_violations', 'data_access_anomalies']
      },
      alerting: {
        enabled: true,
        thresholds: {
          'authentication_failure_rate': 0.10, // 10%
          'authorization_violations_per_minute': 5,
          'suspicious_data_access_events': 3
        },
        escalation: ['security-team', 'soc-team']
      }
    }
  },
  {
    agentId: 'database-compliance-monitor',
    name: 'Database Compliance Monitor',
    type: 'DATABASE_MONITOR',
    targetSystems: ['postgres-primary', 'postgres-replica', 'elasticsearch-cluster', 'redis-cluster'],
    collectionSchedule: {
      frequency: 'CONTINUOUS',
      triggerEvents: ['data_modification', 'schema_change', 'user_access', 'privilege_change']
    },
    evidenceTypes: ['CONFIGURATION', 'LOG_ENTRY', 'DATABASE_QUERY', 'AUTOMATED_CHECK'],
    credentials: {
      type: 'SERVICE_ACCOUNT',
      configuration: {
        connectionStrings: {
          postgres: '${POSTGRES_COMPLIANCE_CONNECTION_STRING}',
          elasticsearch: '${ELASTICSEARCH_COMPLIANCE_CONNECTION_STRING}',
          redis: '${REDIS_COMPLIANCE_CONNECTION_STRING}'
        },
        ssl: true,
        readOnly: true
      }
    },
    outputConfiguration: {
      storage: {
        primary: 's3://isectech-compliance-evidence/databases/',
        encryption: true,
        compression: true
      },
      notification: {
        onSuccess: false,
        onFailure: true,
        onAnomalies: true,
        channels: ['sns://data-alerts']
      }
    },
    monitoringConfiguration: {
      healthCheck: {
        enabled: true,
        interval: 120, // 2 minutes
        timeout: 10,
        retries: 3
      },
      metrics: {
        enabled: true,
        namespace: 'iSECTECH/Compliance/Databases',
        customMetrics: ['data_access_violations', 'schema_compliance', 'encryption_status']
      },
      alerting: {
        enabled: true,
        thresholds: {
          'unencrypted_data_percentage': 0.001, // 0.1%
          'unauthorized_access_attempts': 1,
          'schema_compliance_violations': 0
        },
        escalation: ['data-team', 'security-team']
      }
    }
  }
];

// ═══════════════════════════════════════════════════════════════════════════════
// EVIDENCE COLLECTION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

export class EvidenceCollectionEngine {
  private agents: Map<string, MonitoringAgent> = new Map();
  private evidenceStore: EvidenceStore;
  private digitalSigner: DigitalSigner;
  private continuousMonitor: ContinuousMonitor;
  private alertManager: AlertManager;

  constructor(config: EvidenceCollectionConfig) {
    this.evidenceStore = new EvidenceStore(config.storage);
    this.digitalSigner = new DigitalSigner(config.signing);
    this.continuousMonitor = new ContinuousMonitor(config.monitoring);
    this.alertManager = new AlertManager(config.alerting);
    
    this.initializeAgents();
  }

  /**
   * Initialize all monitoring agents
   */
  private async initializeAgents(): Promise<void> {
    console.log('Initializing evidence collection agents...');
    
    for (const agentConfig of ISECTECH_MONITORING_AGENTS) {
      try {
        const agent = this.createAgent(agentConfig);
        this.agents.set(agentConfig.agentId, agent);
        await agent.initialize();
        console.log(`Initialized agent: ${agentConfig.name}`);
      } catch (error) {
        console.error(`Failed to initialize agent ${agentConfig.agentId}:`, error);
      }
    }
    
    console.log(`Initialized ${this.agents.size} evidence collection agents`);
  }

  /**
   * Start all monitoring agents
   */
  async startMonitoring(): Promise<void> {
    console.log('Starting continuous compliance monitoring...');
    
    for (const [agentId, agent] of this.agents) {
      try {
        await agent.start();
        console.log(`Started monitoring agent: ${agentId}`);
      } catch (error) {
        console.error(`Failed to start agent ${agentId}:`, error);
        await this.alertManager.sendAlert({
          severity: 'HIGH',
          message: `Failed to start monitoring agent: ${agentId}`,
          details: error instanceof Error ? error.message : 'Unknown error',
          source: 'evidence-collection-engine'
        });
      }
    }
    
    // Start continuous monitoring
    await this.continuousMonitor.start(this.agents);
    
    console.log('Continuous compliance monitoring started');
  }

  /**
   * Stop all monitoring agents
   */
  async stopMonitoring(): Promise<void> {
    console.log('Stopping compliance monitoring...');
    
    await this.continuousMonitor.stop();
    
    for (const [agentId, agent] of this.agents) {
      try {
        await agent.stop();
        console.log(`Stopped monitoring agent: ${agentId}`);
      } catch (error) {
        console.error(`Failed to stop agent ${agentId}:`, error);
      }
    }
    
    console.log('Compliance monitoring stopped');
  }

  /**
   * Collect evidence manually for specific control
   */
  async collectEvidenceForControl(
    controlId: string, 
    tenantId?: string
  ): Promise<EvidenceRecord[]> {
    const controlMapping = controlMappingEngine.getControlMapping(controlId);
    if (!controlMapping) {
      throw new Error(`Control mapping not found: ${controlId}`);
    }

    console.log(`Collecting evidence for control: ${controlId}`);
    const evidenceRecords: EvidenceRecord[] = [];

    // Determine which agents can collect evidence for this control
    const relevantAgents = this.getRelevantAgentsForControl(controlMapping);
    
    for (const agent of relevantAgents) {
      try {
        const evidence = await agent.collectEvidence(controlMapping, tenantId);
        evidenceRecords.push(...evidence);
      } catch (error) {
        console.error(`Failed to collect evidence from agent ${agent.config.agentId}:`, error);
      }
    }

    // Sign and store evidence
    for (const evidence of evidenceRecords) {
      await this.processEvidence(evidence);
    }

    console.log(`Collected ${evidenceRecords.length} evidence records for control ${controlId}`);
    return evidenceRecords;
  }

  /**
   * Generate compliance evidence package for audit
   */
  async generateEvidencePackage(
    frameworks: ComplianceFramework[],
    timeRange: { start: Date; end: Date },
    tenantId?: string
  ): Promise<EvidencePackage> {
    console.log(`Generating evidence package for frameworks: ${frameworks.join(', ')}`);
    
    const evidencePackage: EvidencePackage = {
      id: `evidence-package-${Date.now()}`,
      frameworks,
      timeRange,
      tenantId,
      generatedAt: new Date(),
      evidence: new Map(),
      summary: {
        totalEvidence: 0,
        evidenceByType: new Map(),
        evidenceByControl: new Map(),
        complianceStatus: new Map()
      },
      digitalSignature: null
    };

    // Collect evidence for each framework
    for (const framework of frameworks) {
      const controls = controlMappingEngine.getFrameworkMappings(framework);
      
      for (const control of controls) {
        const evidence = await this.evidenceStore.getEvidenceForControl(
          control.id,
          timeRange,
          tenantId
        );
        
        evidencePackage.evidence.set(control.id, evidence);
        evidencePackage.summary.totalEvidence += evidence.length;
        evidencePackage.summary.evidenceByControl.set(control.id, evidence.length);
        
        // Update evidence type counts
        evidence.forEach(ev => {
          const count = evidencePackage.summary.evidenceByType.get(ev.evidenceType) || 0;
          evidencePackage.summary.evidenceByType.set(ev.evidenceType, count + 1);
        });
        
        // Assess compliance status for control
        const complianceStatus = this.assessControlCompliance(control, evidence);
        evidencePackage.summary.complianceStatus.set(control.id, complianceStatus);
      }
    }

    // Sign the evidence package
    evidencePackage.digitalSignature = await this.digitalSigner.signData(evidencePackage);

    // Store the evidence package
    await this.evidenceStore.storeEvidencePackage(evidencePackage);

    console.log(`Generated evidence package with ${evidencePackage.summary.totalEvidence} evidence records`);
    return evidencePackage;
  }

  /**
   * Get compliance monitoring status
   */
  getMonitoringStatus(): MonitoringStatus {
    const agentStatuses = new Map<string, AgentStatus>();
    
    this.agents.forEach((agent, agentId) => {
      agentStatuses.set(agentId, agent.getStatus());
    });

    return {
      overallStatus: this.calculateOverallStatus(agentStatuses),
      agentStatuses,
      lastUpdate: new Date(),
      totalAgents: this.agents.size,
      activeAgents: Array.from(agentStatuses.values()).filter(s => s.status === 'RUNNING').length,
      totalEvidenceCollected: this.continuousMonitor.getMetrics().totalEvidenceCollected,
      evidenceCollectionRate: this.continuousMonitor.getMetrics().evidenceCollectionRate,
      complianceViolations: this.continuousMonitor.getMetrics().complianceViolations,
      alertsSent: this.alertManager.getMetrics().alertsSent
    };
  }

  // Private helper methods
  private createAgent(config: MonitoringAgentConfig): MonitoringAgent {
    switch (config.type) {
      case 'CLOUD_RESOURCE_MONITOR':
        return new CloudResourceMonitoringAgent(config, this.evidenceStore, this.digitalSigner);
      case 'KUBERNETES_MONITOR':
        return new KubernetesMonitoringAgent(config, this.evidenceStore, this.digitalSigner);
      case 'APPLICATION_MONITOR':
        return new ApplicationMonitoringAgent(config, this.evidenceStore, this.digitalSigner);
      case 'DATABASE_MONITOR':
        return new DatabaseMonitoringAgent(config, this.evidenceStore, this.digitalSigner);
      default:
        throw new Error(`Unsupported agent type: ${config.type}`);
    }
  }

  private getRelevantAgentsForControl(controlMapping: ControlMapping): MonitoringAgent[] {
    const relevantAgents: MonitoringAgent[] = [];
    
    // Determine agent relevance based on control characteristics
    if (controlMapping.category === 'Access Control') {
      relevantAgents.push(
        ...Array.from(this.agents.values()).filter(agent => 
          agent.config.type === 'APPLICATION_MONITOR' || 
          agent.config.type === 'CLOUD_RESOURCE_MONITOR'
        )
      );
    }
    
    if (controlMapping.category === 'Data Security') {
      relevantAgents.push(
        ...Array.from(this.agents.values()).filter(agent => 
          agent.config.type === 'DATABASE_MONITOR' ||
          agent.config.type === 'APPLICATION_MONITOR'
        )
      );
    }
    
    if (controlMapping.category === 'Detection and Response') {
      relevantAgents.push(
        ...Array.from(this.agents.values()).filter(agent => 
          agent.config.type === 'APPLICATION_MONITOR' ||
          agent.config.type === 'KUBERNETES_MONITOR'
        )
      );
    }
    
    return relevantAgents;
  }

  private async processEvidence(evidence: EvidenceRecord): Promise<void> {
    // Sign the evidence
    evidence.metadata.digitalSignature = await this.digitalSigner.signData(evidence.data);
    
    // Validate evidence
    evidence.validationStatus = await this.validateEvidence(evidence);
    
    // Store evidence
    await this.evidenceStore.storeEvidence(evidence);
    
    // Check for compliance violations
    if (evidence.complianceContext.assessment === 'FAIL') {
      await this.handleComplianceViolation(evidence);
    }
  }

  private async validateEvidence(evidence: EvidenceRecord): Promise<'VALID' | 'INVALID'> {
    try {
      // Verify digital signature
      const isSignatureValid = await this.digitalSigner.verifySignature(
        evidence.data,
        evidence.metadata.digitalSignature
      );
      
      if (!isSignatureValid) {
        return 'INVALID';
      }
      
      // Verify checksum
      const calculatedChecksum = crypto
        .createHash('sha256')
        .update(JSON.stringify(evidence.data))
        .digest('hex');
      
      if (calculatedChecksum !== evidence.metadata.checksum) {
        return 'INVALID';
      }
      
      return 'VALID';
    } catch (error) {
      console.error('Evidence validation failed:', error);
      return 'INVALID';
    }
  }

  private async handleComplianceViolation(evidence: EvidenceRecord): Promise<void> {
    await this.alertManager.sendAlert({
      severity: 'HIGH',
      message: `Compliance violation detected for control ${evidence.controlId}`,
      details: JSON.stringify(evidence.complianceContext),
      source: 'evidence-collection-engine',
      tenantId: evidence.tenantId,
      frameworks: evidence.complianceFrameworks
    });
  }

  private assessControlCompliance(
    control: ControlMapping, 
    evidence: EvidenceRecord[]
  ): 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL' | 'NO_EVIDENCE' {
    if (evidence.length === 0) {
      return 'NO_EVIDENCE';
    }
    
    const totalEvidence = evidence.length;
    const passedEvidence = evidence.filter(e => e.complianceContext.assessment === 'PASS').length;
    const failedEvidence = evidence.filter(e => e.complianceContext.assessment === 'FAIL').length;
    
    if (failedEvidence > 0) {
      return 'NON_COMPLIANT';
    }
    
    if (passedEvidence === totalEvidence) {
      return 'COMPLIANT';
    }
    
    return 'PARTIAL';
  }

  private calculateOverallStatus(agentStatuses: Map<string, AgentStatus>): 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY' {
    const statuses = Array.from(agentStatuses.values());
    const healthyCount = statuses.filter(s => s.status === 'RUNNING').length;
    const totalCount = statuses.length;
    
    const healthPercentage = healthyCount / totalCount;
    
    if (healthPercentage >= 0.9) return 'HEALTHY';
    if (healthPercentage >= 0.7) return 'DEGRADED';
    return 'UNHEALTHY';
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ABSTRACT MONITORING AGENT
// ═══════════════════════════════════════════════════════════════════════════════

export abstract class MonitoringAgent {
  protected evidenceStore: EvidenceStore;
  protected digitalSigner: DigitalSigner;
  protected status: AgentStatus;

  constructor(
    public config: MonitoringAgentConfig,
    evidenceStore: EvidenceStore,
    digitalSigner: DigitalSigner
  ) {
    this.evidenceStore = evidenceStore;
    this.digitalSigner = digitalSigner;
    this.status = {
      status: 'STOPPED',
      lastUpdate: new Date(),
      errorCount: 0,
      evidenceCollected: 0,
      lastEvidenceCollection: null
    };
  }

  abstract initialize(): Promise<void>;
  abstract start(): Promise<void>;
  abstract stop(): Promise<void>;
  abstract collectEvidence(control: ControlMapping, tenantId?: string): Promise<EvidenceRecord[]>;

  getStatus(): AgentStatus {
    return { ...this.status };
  }

  protected updateStatus(status: Partial<AgentStatus>): void {
    this.status = { ...this.status, ...status, lastUpdate: new Date() };
  }

  protected async createEvidenceRecord(
    controlId: string,
    evidenceType: EvidenceRecord['evidenceType'],
    data: any,
    complianceContext: EvidenceRecord['complianceContext'],
    tenantId?: string
  ): Promise<EvidenceRecord> {
    const id = `${this.config.agentId}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const dataString = JSON.stringify(data);
    const checksum = crypto.createHash('sha256').update(dataString).digest('hex');

    return {
      id,
      controlId,
      complianceFrameworks: this.getFrameworksForControl(controlId),
      tenantId,
      evidenceType,
      source: {
        system: this.config.targetSystems[0] || 'unknown',
        component: this.config.agentId,
        location: process.env.HOSTNAME || 'unknown',
        agent: this.config.name,
        version: '1.0.0'
      },
      collectionTimestamp: new Date(),
      data,
      metadata: {
        size: Buffer.byteLength(dataString, 'utf8'),
        format: 'application/json',
        encoding: 'utf8',
        checksum,
        digitalSignature: await this.digitalSigner.signData(data),
        classification: this.determineClassification(data),
        retentionPeriod: this.determineRetentionPeriod(controlId),
        tags: this.generateTags(controlId, evidenceType)
      },
      auditTrail: [{
        action: 'created',
        timestamp: new Date(),
        actor: this.config.agentId,
        details: { automated: true }
      }],
      validationStatus: 'PENDING',
      complianceContext
    };
  }

  private getFrameworksForControl(controlId: string): ComplianceFramework[] {
    const control = controlMappingEngine.getControlMapping(controlId);
    return control ? Object.keys(control.mappedControls) as ComplianceFramework[] : [];
  }

  private determineClassification(data: any): 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' {
    // Simple classification logic - can be enhanced
    if (data.sensitive === true || data.pii === true) return 'CONFIDENTIAL';
    if (data.internal === true) return 'INTERNAL';
    return 'PUBLIC';
  }

  private determineRetentionPeriod(controlId: string): number {
    // Default retention periods based on control type
    if (controlId.includes('AUDIT') || controlId.includes('LOG')) return 2555; // 7 years
    if (controlId.includes('CONFIG')) return 1095; // 3 years
    return 365; // 1 year default
  }

  private generateTags(controlId: string, evidenceType: string): string[] {
    return [
      `control:${controlId}`,
      `type:${evidenceType.toLowerCase()}`,
      `agent:${this.config.agentId}`,
      `automated:true`
    ];
  }
}

// Specific agent implementations would be defined here...
// For brevity, showing simplified class definitions

export class CloudResourceMonitoringAgent extends MonitoringAgent {
  async initialize(): Promise<void> {
    this.updateStatus({ status: 'INITIALIZING' });
    // Initialize AWS SDK clients, verify credentials, etc.
    this.updateStatus({ status: 'INITIALIZED' });
  }

  async start(): Promise<void> {
    this.updateStatus({ status: 'RUNNING' });
    // Start continuous monitoring
  }

  async stop(): Promise<void> {
    this.updateStatus({ status: 'STOPPED' });
    // Stop monitoring
  }

  async collectEvidence(control: ControlMapping, tenantId?: string): Promise<EvidenceRecord[]> {
    // Collect AWS resource configurations, IAM policies, etc.
    return [];
  }
}

export class KubernetesMonitoringAgent extends MonitoringAgent {
  async initialize(): Promise<void> {
    this.updateStatus({ status: 'INITIALIZING' });
    // Initialize Kubernetes client
    this.updateStatus({ status: 'INITIALIZED' });
  }

  async start(): Promise<void> {
    this.updateStatus({ status: 'RUNNING' });
    // Start watching Kubernetes resources
  }

  async stop(): Promise<void> {
    this.updateStatus({ status: 'STOPPED' });
  }

  async collectEvidence(control: ControlMapping, tenantId?: string): Promise<EvidenceRecord[]> {
    // Collect K8s RBAC, security policies, resource configurations
    return [];
  }
}

export class ApplicationMonitoringAgent extends MonitoringAgent {
  async initialize(): Promise<void> {
    this.updateStatus({ status: 'INITIALIZING' });
    // Initialize application monitoring connections
    this.updateStatus({ status: 'INITIALIZED' });
  }

  async start(): Promise<void> {
    this.updateStatus({ status: 'RUNNING' });
    // Start monitoring application events
  }

  async stop(): Promise<void> {
    this.updateStatus({ status: 'STOPPED' });
  }

  async collectEvidence(control: ControlMapping, tenantId?: string): Promise<EvidenceRecord[]> {
    // Collect application logs, API calls, authentication events
    return [];
  }
}

export class DatabaseMonitoringAgent extends MonitoringAgent {
  async initialize(): Promise<void> {
    this.updateStatus({ status: 'INITIALIZING' });
    // Initialize database connections
    this.updateStatus({ status: 'INITIALIZED' });
  }

  async start(): Promise<void> {
    this.updateStatus({ status: 'RUNNING' });
    // Start monitoring database activity
  }

  async stop(): Promise<void> {
    this.updateStatus({ status: 'STOPPED' });
  }

  async collectEvidence(control: ControlMapping, tenantId?: string): Promise<EvidenceRecord[]> {
    // Collect database configurations, access logs, encryption status
    return [];
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPPORTING CLASSES AND TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export class EvidenceStore {
  constructor(private config: any) {}

  async storeEvidence(evidence: EvidenceRecord): Promise<void> {
    // Implementation for storing evidence
  }

  async getEvidenceForControl(
    controlId: string,
    timeRange: { start: Date; end: Date },
    tenantId?: string
  ): Promise<EvidenceRecord[]> {
    // Implementation for retrieving evidence
    return [];
  }

  async storeEvidencePackage(evidencePackage: EvidencePackage): Promise<void> {
    // Implementation for storing evidence packages
  }
}

export class DigitalSigner {
  constructor(private config: any) {}

  async signData(data: any): Promise<any> {
    // Implementation for digital signatures
    return {
      algorithm: 'RSA-SHA256',
      signature: 'signature-placeholder',
      publicKey: 'public-key-placeholder'
    };
  }

  async verifySignature(data: any, signature: any): Promise<boolean> {
    // Implementation for signature verification
    return true;
  }
}

export class ContinuousMonitor {
  constructor(private config: any) {}

  async start(agents: Map<string, MonitoringAgent>): Promise<void> {
    // Implementation for continuous monitoring
  }

  async stop(): Promise<void> {
    // Implementation for stopping monitoring
  }

  getMetrics(): any {
    return {
      totalEvidenceCollected: 0,
      evidenceCollectionRate: 0,
      complianceViolations: 0
    };
  }
}

export class AlertManager {
  constructor(private config: any) {}

  async sendAlert(alert: {
    severity: string;
    message: string;
    details: string;
    source: string;
    tenantId?: string;
    frameworks?: ComplianceFramework[];
  }): Promise<void> {
    // Implementation for sending alerts
  }

  getMetrics(): any {
    return {
      alertsSent: 0
    };
  }
}

// Additional types
export interface EvidenceCollectionConfig {
  storage: any;
  signing: any;
  monitoring: any;
  alerting: any;
}

export interface EvidencePackage {
  id: string;
  frameworks: ComplianceFramework[];
  timeRange: { start: Date; end: Date };
  tenantId?: string;
  generatedAt: Date;
  evidence: Map<string, EvidenceRecord[]>;
  summary: {
    totalEvidence: number;
    evidenceByType: Map<string, number>;
    evidenceByControl: Map<string, number>;
    complianceStatus: Map<string, string>;
  };
  digitalSignature: any;
}

export interface AgentStatus {
  status: 'STOPPED' | 'INITIALIZING' | 'INITIALIZED' | 'RUNNING' | 'ERROR';
  lastUpdate: Date;
  errorCount: number;
  evidenceCollected: number;
  lastEvidenceCollection: Date | null;
}

export interface MonitoringStatus {
  overallStatus: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
  agentStatuses: Map<string, AgentStatus>;
  lastUpdate: Date;
  totalAgents: number;
  activeAgents: number;
  totalEvidenceCollected: number;
  evidenceCollectionRate: number;
  complianceViolations: number;
  alertsSent: number;
}

// Export default configuration
export const defaultEvidenceCollectionConfig: EvidenceCollectionConfig = {
  storage: {
    primary: 's3://isectech-compliance-evidence/',
    backup: 's3://isectech-compliance-evidence-backup/',
    encryption: true,
    retention: {
      default: 365, // days
      audit: 2555,  // 7 years
      compliance: 1095 // 3 years
    }
  },
  signing: {
    algorithm: 'RSA-SHA256',
    keySize: 2048,
    certificateAuthority: 'iSECTECH Internal CA'
  },
  monitoring: {
    healthCheckInterval: 300, // 5 minutes
    metricsNamespace: 'iSECTECH/Compliance',
    alertThresholds: {
      evidenceCollectionFailureRate: 0.05, // 5%
      agentDowntime: 600 // 10 minutes
    }
  },
  alerting: {
    channels: ['sns://compliance-alerts', 'slack://compliance-channel'],
    escalation: {
      level1: 'compliance-team',
      level2: 'security-team',
      level3: 'executives'
    }
  }
};