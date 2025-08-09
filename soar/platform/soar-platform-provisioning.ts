/**
 * Production-grade SOAR Platform Selection and Provisioning System
 * 
 * Comprehensive platform evaluation, selection criteria, and automated provisioning
 * system specifically designed for iSECTECH's enterprise SOAR implementation.
 * 
 * Custom implementation supporting multiple SOAR platforms and deployment strategies.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// SOAR Platform Evaluation Schemas
export const PlatformCapabilitySchema = z.object({
  capabilityId: z.string(),
  name: z.string(),
  description: z.string(),
  category: z.enum([
    'WORKFLOW_ENGINE',
    'VISUAL_DESIGNER', 
    'INTEGRATION_FRAMEWORK',
    'CASE_MANAGEMENT',
    'REPORTING_ANALYTICS',
    'USER_INTERFACE',
    'API_CAPABILITIES',
    'SECURITY_FEATURES',
    'SCALABILITY',
    'DEPLOYMENT_OPTIONS'
  ]),
  
  // Evaluation criteria
  importance: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  weight: z.number().min(1).max(10),
  
  // Assessment metrics
  assessment: z.object({
    functionality: z.number().min(1).max(5),
    usability: z.number().min(1).max(5),
    performance: z.number().min(1).max(5),
    reliability: z.number().min(1).max(5),
    scalability: z.number().min(1).max(5),
    security: z.number().min(1).max(5),
    integration: z.number().min(1).max(5),
    documentation: z.number().min(1).max(5)
  }),
  
  // Platform support
  supportedBy: z.array(z.string()),
  
  // Implementation details
  implementationComplexity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH']),
  technicalRequirements: z.array(z.string()),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const SOARPlatformSchema = z.object({
  platformId: z.string(),
  name: z.string(),
  vendor: z.string(),
  version: z.string(),
  
  // Platform classification
  type: z.enum(['COMMERCIAL', 'OPEN_SOURCE', 'CLOUD_NATIVE', 'HYBRID']),
  deploymentModel: z.enum(['ON_PREMISE', 'CLOUD', 'HYBRID', 'SAAS']),
  
  // Core platform details
  description: z.string(),
  architecture: z.enum(['MONOLITHIC', 'MICROSERVICES', 'SERVERLESS', 'HYBRID']),
  
  // Capabilities assessment
  capabilities: z.array(z.string()), // capability IDs
  overallScore: z.number().min(0).max(100),
  
  // Technical specifications
  techSpecs: z.object({
    supportedOS: z.array(z.string()),
    minCPUCores: z.number(),
    minRAM: z.number(), // GB
    minStorage: z.number(), // GB
    supportedDatabases: z.array(z.string()),
    programmingLanguages: z.array(z.string()),
    apiTypes: z.array(z.string()),
    authenticationMethods: z.array(z.string())
  }),
  
  // Integration capabilities
  integrations: z.object({
    preBuiltConnectors: z.number(),
    customConnectorSDK: z.boolean(),
    webhookSupport: z.boolean(),
    restApiSupport: z.boolean(),
    soapApiSupport: z.boolean(),
    messagingSupport: z.array(z.string()),
    databaseConnectors: z.array(z.string())
  }),
  
  // Workflow engine features
  workflowEngine: z.object({
    visualDesigner: z.boolean(),
    codeBasedWorkflows: z.boolean(),
    conditionalLogic: z.boolean(),
    loopsAndIterations: z.boolean(),
    parallelExecution: z.boolean(),
    errorHandling: z.boolean(),
    retryMechanisms: z.boolean(),
    humanApproval: z.boolean(),
    scheduling: z.boolean(),
    versioning: z.boolean()
  }),
  
  // Security features
  security: z.object({
    rbacSupport: z.boolean(),
    mfaIntegration: z.boolean(),
    encryptionAtRest: z.boolean(),
    encryptionInTransit: z.boolean(),
    auditLogging: z.boolean(),
    secretsManagement: z.boolean(),
    networkSegmentation: z.boolean(),
    complianceCertifications: z.array(z.string())
  }),
  
  // Scalability and performance
  scalability: z.object({
    horizontalScaling: z.boolean(),
    verticalScaling: z.boolean(),
    loadBalancing: z.boolean(),
    clustering: z.boolean(),
    maxConcurrentWorkflows: z.number().optional(),
    maxWorkflowSteps: z.number().optional(),
    performanceBenchmarks: z.record(z.number()).optional()
  }),
  
  // Licensing and cost
  licensing: z.object({
    model: z.enum(['PERPETUAL', 'SUBSCRIPTION', 'USAGE_BASED', 'FREEMIUM', 'OPEN_SOURCE']),
    costStructure: z.string(),
    annualCostEstimate: z.number().optional(),
    maintenanceCostPercentage: z.number().optional(),
    supportTiers: z.array(z.string())
  }),
  
  // Vendor information
  vendor: z.object({
    marketPosition: z.enum(['LEADER', 'CHALLENGER', 'VISIONARY', 'NICHE']),
    customerBase: z.number().optional(),
    yearsFounded: z.number().optional(),
    financialStability: z.enum(['EXCELLENT', 'GOOD', 'FAIR', 'POOR']),
    supportQuality: z.number().min(1).max(5),
    roadmapAlignment: z.number().min(1).max(5)
  }),
  
  // Evaluation results
  evaluation: z.object({
    evaluatedBy: z.string(),
    evaluationDate: z.date(),
    strengths: z.array(z.string()),
    weaknesses: z.array(z.string()),
    recommendation: z.enum(['HIGHLY_RECOMMENDED', 'RECOMMENDED', 'CONDITIONAL', 'NOT_RECOMMENDED']),
    riskLevel: z.enum(['LOW', 'MEDIUM', 'HIGH']),
    implementationTimeframe: z.string()
  }),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const ProvisioningConfigSchema = z.object({
  configId: z.string(),
  platformId: z.string(),
  deploymentName: z.string(),
  environment: z.enum(['DEVELOPMENT', 'STAGING', 'PRODUCTION']),
  
  // Infrastructure configuration
  infrastructure: z.object({
    provider: z.enum(['AWS', 'AZURE', 'GCP', 'ON_PREMISE', 'HYBRID']),
    region: z.string(),
    availabilityZones: z.array(z.string()),
    
    // Compute resources
    compute: z.object({
      instanceType: z.string(),
      minInstances: z.number(),
      maxInstances: z.number(),
      autoScaling: z.boolean(),
      cpuTarget: z.number().optional(),
      memoryTarget: z.number().optional()
    }),
    
    // Storage configuration
    storage: z.object({
      type: z.enum(['SSD', 'HDD', 'NVME', 'NETWORK_ATTACHED']),
      size: z.number(), // GB
      iops: z.number().optional(),
      throughput: z.number().optional(),
      backupEnabled: z.boolean(),
      encryptionEnabled: z.boolean()
    }),
    
    // Networking
    networking: z.object({
      vpcId: z.string().optional(),
      subnetIds: z.array(z.string()),
      securityGroupIds: z.array(z.string()),
      loadBalancer: z.boolean(),
      publicAccess: z.boolean(),
      privateEndpoints: z.array(z.string())
    })
  }),
  
  // Database configuration
  database: z.object({
    type: z.enum(['POSTGRESQL', 'MYSQL', 'MONGODB', 'ELASTICSEARCH', 'REDIS']),
    version: z.string(),
    multiAZ: z.boolean(),
    backupRetention: z.number(), // days
    encryptionAtRest: z.boolean(),
    performanceInsights: z.boolean(),
    connectionPooling: z.boolean()
  }),
  
  // Security configuration
  security: z.object({
    sslCertificate: z.string().optional(),
    wafEnabled: z.boolean(),
    ddosProtection: z.boolean(),
    ipWhitelist: z.array(z.string()),
    secretsManagerIntegration: z.boolean(),
    vaultIntegration: z.boolean(),
    ssoConfiguration: z.object({
      enabled: z.boolean(),
      provider: z.string().optional(),
      metadata: z.record(z.string()).optional()
    })
  }),
  
  // Monitoring and logging
  monitoring: z.object({
    metricsEnabled: z.boolean(),
    loggingEnabled: z.boolean(),
    tracingEnabled: z.boolean(),
    alertingEnabled: z.boolean(),
    dashboardsEnabled: z.boolean(),
    retentionPeriod: z.number(), // days
    logLevel: z.enum(['ERROR', 'WARN', 'INFO', 'DEBUG'])
  }),
  
  // Integration settings
  integrations: z.array(z.object({
    name: z.string(),
    type: z.string(),
    endpoint: z.string(),
    authentication: z.record(z.any()),
    enabled: z.boolean()
  })),
  
  // Configuration parameters
  parameters: z.record(z.any()),
  
  // Deployment status
  status: z.enum(['PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'UPDATING']),
  deploymentStartTime: z.date().optional(),
  deploymentEndTime: z.date().optional(),
  lastHealthCheck: z.date().optional(),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export type PlatformCapability = z.infer<typeof PlatformCapabilitySchema>;
export type SOARPlatform = z.infer<typeof SOARPlatformSchema>;
export type ProvisioningConfig = z.infer<typeof ProvisioningConfigSchema>;

/**
 * SOAR Platform Selection and Provisioning Manager
 */
export class ISECTECHSOARPlatformManager {
  private capabilities: Map<string, PlatformCapability> = new Map();
  private platforms: Map<string, SOARPlatform> = new Map();
  private provisioningConfigs: Map<string, ProvisioningConfig> = new Map();
  private evaluationMatrix: Map<string, Map<string, number>> = new Map();

  constructor() {
    this.initializePlatformEvaluation();
  }

  /**
   * Initialize platform evaluation framework
   */
  private initializePlatformEvaluation(): void {
    console.log('Initializing iSECTECH SOAR Platform Evaluation Framework...');
    
    // Initialize evaluation capabilities
    this.initializeEvaluationCapabilities();
    
    // Initialize platform candidates
    this.initializePlatformCandidates();
    
    // Conduct platform evaluation
    this.conductPlatformEvaluation();
    
    console.log('Platform evaluation framework initialized');
  }

  /**
   * Initialize evaluation capabilities and criteria
   */
  private initializeEvaluationCapabilities(): void {
    const capabilities: Partial<PlatformCapability>[] = [
      // Workflow Engine Capabilities
      {
        name: 'Visual Workflow Designer',
        description: 'Drag-and-drop visual interface for creating workflows',
        category: 'VISUAL_DESIGNER',
        importance: 'CRITICAL',
        weight: 9,
        assessment: {
          functionality: 5,
          usability: 5,
          performance: 4,
          reliability: 4,
          scalability: 4,
          security: 4,
          integration: 4,
          documentation: 4
        },
        implementationComplexity: 'MEDIUM',
        technicalRequirements: ['Web browser support', 'Real-time collaboration', 'Version control']
      },
      
      {
        name: 'Conditional Logic and Decision Points',
        description: 'Support for if-then-else logic and complex decision trees',
        category: 'WORKFLOW_ENGINE',
        importance: 'CRITICAL',
        weight: 9,
        assessment: {
          functionality: 5,
          usability: 4,
          performance: 5,
          reliability: 5,
          scalability: 5,
          security: 4,
          integration: 4,
          documentation: 4
        },
        implementationComplexity: 'HIGH',
        technicalRequirements: ['Expression evaluation', 'Rule engine', 'Complex branching']
      },
      
      {
        name: 'Parallel Execution Support',
        description: 'Ability to execute multiple workflow paths simultaneously',
        category: 'WORKFLOW_ENGINE',
        importance: 'HIGH',
        weight: 8,
        assessment: {
          functionality: 4,
          usability: 4,
          performance: 5,
          reliability: 4,
          scalability: 5,
          security: 4,
          integration: 4,
          documentation: 4
        },
        implementationComplexity: 'HIGH',
        technicalRequirements: ['Thread management', 'Resource coordination', 'Error isolation']
      },
      
      {
        name: 'Error Handling and Retry Logic',
        description: 'Comprehensive error handling with retry mechanisms',
        category: 'WORKFLOW_ENGINE',
        importance: 'CRITICAL',
        weight: 9,
        assessment: {
          functionality: 5,
          usability: 4,
          performance: 4,
          reliability: 5,
          scalability: 4,
          security: 4,
          integration: 5,
          documentation: 4
        },
        implementationComplexity: 'MEDIUM',
        technicalRequirements: ['Exception handling', 'Retry policies', 'Circuit breakers']
      },
      
      // Integration Framework
      {
        name: 'Pre-built Integrations',
        description: 'Extensive library of pre-built security tool integrations',
        category: 'INTEGRATION_FRAMEWORK',
        importance: 'CRITICAL',
        weight: 10,
        assessment: {
          functionality: 5,
          usability: 5,
          performance: 4,
          reliability: 4,
          scalability: 4,
          security: 5,
          integration: 5,
          documentation: 4
        },
        implementationComplexity: 'LOW',
        technicalRequirements: ['API connectors', 'Authentication support', 'Data transformation']
      },
      
      {
        name: 'Custom Integration SDK',
        description: 'Software development kit for creating custom integrations',
        category: 'INTEGRATION_FRAMEWORK',
        importance: 'HIGH',
        weight: 8,
        assessment: {
          functionality: 4,
          usability: 3,
          performance: 4,
          reliability: 4,
          scalability: 4,
          security: 4,
          integration: 5,
          documentation: 3
        },
        implementationComplexity: 'HIGH',
        technicalRequirements: ['SDK documentation', 'Testing framework', 'Deployment pipeline']
      },
      
      // Case Management
      {
        name: 'Automated Case Creation',
        description: 'Automatic case creation from security alerts and events',
        category: 'CASE_MANAGEMENT',
        importance: 'HIGH',
        weight: 8,
        assessment: {
          functionality: 4,
          usability: 4,
          performance: 4,
          reliability: 4,
          scalability: 4,
          security: 4,
          integration: 5,
          documentation: 4
        },
        implementationComplexity: 'MEDIUM',
        technicalRequirements: ['Alert processing', 'Case templates', 'Escalation rules']
      },
      
      {
        name: 'Evidence Collection and Preservation',
        description: 'Automated collection and forensic preservation of evidence',
        category: 'CASE_MANAGEMENT',
        importance: 'HIGH',
        weight: 8,
        assessment: {
          functionality: 4,
          usability: 4,
          performance: 4,
          reliability: 5,
          scalability: 4,
          security: 5,
          integration: 4,
          documentation: 4
        },
        implementationComplexity: 'HIGH',
        technicalRequirements: ['Chain of custody', 'Digital signatures', 'Immutable storage']
      },
      
      // Security Features
      {
        name: 'Role-Based Access Control',
        description: 'Granular RBAC with workflow-level permissions',
        category: 'SECURITY_FEATURES',
        importance: 'CRITICAL',
        weight: 9,
        assessment: {
          functionality: 5,
          usability: 4,
          performance: 4,
          reliability: 5,
          scalability: 4,
          security: 5,
          integration: 4,
          documentation: 4
        },
        implementationComplexity: 'MEDIUM',
        technicalRequirements: ['User management', 'Permission matrix', 'API security']
      },
      
      {
        name: 'Audit Logging and Compliance',
        description: 'Comprehensive audit trails for compliance requirements',
        category: 'SECURITY_FEATURES',
        importance: 'CRITICAL',
        weight: 9,
        assessment: {
          functionality: 5,
          usability: 4,
          performance: 4,
          reliability: 5,
          scalability: 4,
          security: 5,
          integration: 4,
          documentation: 5
        },
        implementationComplexity: 'MEDIUM',
        technicalRequirements: ['Immutable logs', 'Compliance reports', 'Retention policies']
      },
      
      // Scalability
      {
        name: 'Horizontal Scaling',
        description: 'Ability to scale out across multiple nodes',
        category: 'SCALABILITY',
        importance: 'HIGH',
        weight: 8,
        assessment: {
          functionality: 4,
          usability: 3,
          performance: 5,
          reliability: 4,
          scalability: 5,
          security: 4,
          integration: 4,
          documentation: 3
        },
        implementationComplexity: 'HIGH',
        technicalRequirements: ['Load balancing', 'State management', 'Cluster coordination']
      },
      
      // Reporting and Analytics
      {
        name: 'Real-time Dashboards',
        description: 'Real-time monitoring and analytics dashboards',
        category: 'REPORTING_ANALYTICS',
        importance: 'HIGH',
        weight: 7,
        assessment: {
          functionality: 4,
          usability: 5,
          performance: 4,
          reliability: 4,
          scalability: 4,
          security: 4,
          integration: 4,
          documentation: 4
        },
        implementationComplexity: 'MEDIUM',
        technicalRequirements: ['Real-time data', 'Visualization library', 'Custom widgets']
      }
    ];

    capabilities.forEach(capability => {
      this.addCapability(capability);
    });

    console.log(`Initialized ${capabilities.length} evaluation capabilities`);
  }

  /**
   * Initialize platform candidates for evaluation
   */
  private initializePlatformCandidates(): void {
    const platforms: Partial<SOARPlatform>[] = [
      // Temporal.io + Node-RED Hybrid Solution
      {
        name: 'iSECTECH Custom SOAR (Temporal + Node-RED)',
        vendor: 'Custom Implementation',
        version: '1.0.0',
        type: 'HYBRID',
        deploymentModel: 'HYBRID',
        description: 'Custom SOAR solution combining Temporal workflow engine with Node-RED visual designer',
        architecture: 'MICROSERVICES',
        
        techSpecs: {
          supportedOS: ['Linux', 'Windows', 'macOS'],
          minCPUCores: 4,
          minRAM: 16,
          minStorage: 100,
          supportedDatabases: ['PostgreSQL', 'MongoDB', 'Redis'],
          programmingLanguages: ['TypeScript', 'JavaScript', 'Python', 'Go'],
          apiTypes: ['REST', 'GraphQL', 'gRPC'],
          authenticationMethods: ['OAuth2', 'SAML', 'LDAP', 'JWT']
        },
        
        integrations: {
          preBuiltConnectors: 50,
          customConnectorSDK: true,
          webhookSupport: true,
          restApiSupport: true,
          soapApiSupport: true,
          messagingSupport: ['Kafka', 'RabbitMQ', 'Redis'],
          databaseConnectors: ['PostgreSQL', 'MongoDB', 'Elasticsearch']
        },
        
        workflowEngine: {
          visualDesigner: true,
          codeBasedWorkflows: true,
          conditionalLogic: true,
          loopsAndIterations: true,
          parallelExecution: true,
          errorHandling: true,
          retryMechanisms: true,
          humanApproval: true,
          scheduling: true,
          versioning: true
        },
        
        security: {
          rbacSupport: true,
          mfaIntegration: true,
          encryptionAtRest: true,
          encryptionInTransit: true,
          auditLogging: true,
          secretsManagement: true,
          networkSegmentation: true,
          complianceCertifications: ['SOC2', 'ISO27001']
        },
        
        scalability: {
          horizontalScaling: true,
          verticalScaling: true,
          loadBalancing: true,
          clustering: true,
          maxConcurrentWorkflows: 10000,
          maxWorkflowSteps: 1000
        },
        
        licensing: {
          model: 'OPEN_SOURCE',
          costStructure: 'Infrastructure + Development costs only',
          annualCostEstimate: 200000,
          maintenanceCostPercentage: 15,
          supportTiers: ['Community', 'Enterprise']
        },
        
        vendor: {
          marketPosition: 'NICHE',
          financialStability: 'EXCELLENT',
          supportQuality: 4,
          roadmapAlignment: 5
        }
      },
      
      // Phantom (Splunk SOAR)
      {
        name: 'Splunk SOAR (Phantom)',
        vendor: 'Splunk',
        version: '5.3.0',
        type: 'COMMERCIAL',
        deploymentModel: 'HYBRID',
        description: 'Enterprise SOAR platform with extensive security tool integrations',
        architecture: 'MONOLITHIC',
        
        techSpecs: {
          supportedOS: ['CentOS', 'Red Hat', 'Ubuntu'],
          minCPUCores: 8,
          minRAM: 32,
          minStorage: 500,
          supportedDatabases: ['PostgreSQL'],
          programmingLanguages: ['Python', 'JavaScript'],
          apiTypes: ['REST'],
          authenticationMethods: ['LDAP', 'SAML', 'Local']
        },
        
        integrations: {
          preBuiltConnectors: 300,
          customConnectorSDK: true,
          webhookSupport: true,
          restApiSupport: true,
          soapApiSupport: false,
          messagingSupport: ['Email', 'Slack', 'Teams'],
          databaseConnectors: ['PostgreSQL', 'Splunk']
        },
        
        workflowEngine: {
          visualDesigner: true,
          codeBasedWorkflows: true,
          conditionalLogic: true,
          loopsAndIterations: true,
          parallelExecution: true,
          errorHandling: true,
          retryMechanisms: true,
          humanApproval: true,
          scheduling: true,
          versioning: true
        },
        
        security: {
          rbacSupport: true,
          mfaIntegration: true,
          encryptionAtRest: true,
          encryptionInTransit: true,
          auditLogging: true,
          secretsManagement: true,
          networkSegmentation: true,
          complianceCertifications: ['SOC2', 'FedRAMP', 'Common Criteria']
        },
        
        scalability: {
          horizontalScaling: true,
          verticalScaling: true,
          loadBalancing: true,
          clustering: true,
          maxConcurrentWorkflows: 5000,
          maxWorkflowSteps: 500
        },
        
        licensing: {
          model: 'SUBSCRIPTION',
          costStructure: 'Per analyst seat + infrastructure',
          annualCostEstimate: 500000,
          maintenanceCostPercentage: 20,
          supportTiers: ['Standard', 'Premium', 'Elite']
        },
        
        vendor: {
          marketPosition: 'LEADER',
          customerBase: 1000,
          yearsFounded: 2014,
          financialStability: 'EXCELLENT',
          supportQuality: 4,
          roadmapAlignment: 4
        }
      },
      
      // Microsoft Sentinel with Logic Apps
      {
        name: 'Microsoft Sentinel + Logic Apps',
        vendor: 'Microsoft',
        version: '2023.1',
        type: 'CLOUD_NATIVE',
        deploymentModel: 'CLOUD',
        description: 'Cloud-native SIEM/SOAR with integrated automation capabilities',
        architecture: 'SERVERLESS',
        
        techSpecs: {
          supportedOS: ['Cloud-based'],
          minCPUCores: 0, // Serverless
          minRAM: 0, // Serverless
          minStorage: 0, // Managed
          supportedDatabases: ['Azure Data Explorer'],
          programmingLanguages: ['C#', 'PowerShell', 'KQL'],
          apiTypes: ['REST', 'GraphQL'],
          authenticationMethods: ['Azure AD', 'OAuth2', 'SAML']
        },
        
        integrations: {
          preBuiltConnectors: 200,
          customConnectorSDK: true,
          webhookSupport: true,
          restApiSupport: true,
          soapApiSupport: true,
          messagingSupport: ['Service Bus', 'Event Hub', 'Teams'],
          databaseConnectors: ['SQL Database', 'Cosmos DB', 'Synapse']
        },
        
        workflowEngine: {
          visualDesigner: true,
          codeBasedWorkflows: true,
          conditionalLogic: true,
          loopsAndIterations: true,
          parallelExecution: true,
          errorHandling: true,
          retryMechanisms: true,
          humanApproval: true,
          scheduling: true,
          versioning: true
        },
        
        security: {
          rbacSupport: true,
          mfaIntegration: true,
          encryptionAtRest: true,
          encryptionInTransit: true,
          auditLogging: true,
          secretsManagement: true,
          networkSegmentation: true,
          complianceCertifications: ['SOC2', 'ISO27001', 'FedRAMP']
        },
        
        scalability: {
          horizontalScaling: true,
          verticalScaling: true,
          loadBalancing: true,
          clustering: true,
          maxConcurrentWorkflows: 50000,
          maxWorkflowSteps: 2000
        },
        
        licensing: {
          model: 'USAGE_BASED',
          costStructure: 'Per GB ingested + compute time',
          annualCostEstimate: 600000,
          maintenanceCostPercentage: 0,
          supportTiers: ['Basic', 'Standard', 'Professional Direct']
        },
        
        vendor: {
          marketPosition: 'LEADER',
          customerBase: 10000,
          yearsFounded: 1975,
          financialStability: 'EXCELLENT',
          supportQuality: 4,
          roadmapAlignment: 5
        }
      },
      
      // XSOAR (Cortex XSOAR)
      {
        name: 'Cortex XSOAR',
        vendor: 'Palo Alto Networks',
        version: '6.8',
        type: 'COMMERCIAL',
        deploymentModel: 'HYBRID',
        description: 'Enterprise SOAR platform with AI-powered incident response',
        architecture: 'MICROSERVICES',
        
        techSpecs: {
          supportedOS: ['CentOS', 'Red Hat', 'Ubuntu'],
          minCPUCores: 8,
          minRAM: 32,
          minStorage: 500,
          supportedDatabases: ['Elasticsearch', 'MongoDB'],
          programmingLanguages: ['Python', 'JavaScript', 'PowerShell'],
          apiTypes: ['REST'],
          authenticationMethods: ['LDAP', 'SAML', 'OAuth2']
        },
        
        integrations: {
          preBuiltConnectors: 450,
          customConnectorSDK: true,
          webhookSupport: true,
          restApiSupport: true,
          soapApiSupport: true,
          messagingSupport: ['Slack', 'Teams', 'Email'],
          databaseConnectors: ['Elasticsearch', 'SQL databases']
        },
        
        workflowEngine: {
          visualDesigner: true,
          codeBasedWorkflows: true,
          conditionalLogic: true,
          loopsAndIterations: true,
          parallelExecution: true,
          errorHandling: true,
          retryMechanisms: true,
          humanApproval: true,
          scheduling: true,
          versioning: true
        },
        
        security: {
          rbacSupport: true,
          mfaIntegration: true,
          encryptionAtRest: true,
          encryptionInTransit: true,
          auditLogging: true,
          secretsManagement: true,
          networkSegmentation: true,
          complianceCertifications: ['SOC2', 'ISO27001', 'Common Criteria']
        },
        
        scalability: {
          horizontalScaling: true,
          verticalScaling: true,
          loadBalancing: true,
          clustering: true,
          maxConcurrentWorkflows: 8000,
          maxWorkflowSteps: 1000
        },
        
        licensing: {
          model: 'SUBSCRIPTION',
          costStructure: 'Per analyst seat + premium features',
          annualCostEstimate: 700000,
          maintenanceCostPercentage: 20,
          supportTiers: ['Standard', 'Premium', 'Ultimate']
        },
        
        vendor: {
          marketPosition: 'LEADER',
          customerBase: 800,
          yearsFounded: 2005,
          financialStability: 'EXCELLENT',
          supportQuality: 4,
          roadmapAlignment: 4
        }
      }
    ];

    platforms.forEach(platform => {
      this.addPlatform(platform);
    });

    console.log(`Initialized ${platforms.length} platform candidates`);
  }

  /**
   * Conduct comprehensive platform evaluation
   */
  private conductPlatformEvaluation(): void {
    const platforms = Array.from(this.platforms.values());
    const capabilities = Array.from(this.capabilities.values());

    platforms.forEach(platform => {
      this.evaluatePlatformAgainstCapabilities(platform, capabilities);
    });

    // Generate evaluation matrix
    this.generateEvaluationMatrix();
    
    console.log('Platform evaluation completed');
  }

  /**
   * Evaluate platform against all capabilities
   */
  private evaluatePlatformAgainstCapabilities(platform: SOARPlatform, capabilities: PlatformCapability[]): void {
    let totalScore = 0;
    let maxPossibleScore = 0;

    capabilities.forEach(capability => {
      const capabilityScore = this.calculateCapabilityScore(platform, capability);
      const weightedScore = capabilityScore * capability.weight;
      
      totalScore += weightedScore;
      maxPossibleScore += (5 * capability.weight); // Max score is 5
      
      // Store individual capability scores
      if (!this.evaluationMatrix.has(platform.platformId)) {
        this.evaluationMatrix.set(platform.platformId, new Map());
      }
      this.evaluationMatrix.get(platform.platformId)!.set(capability.capabilityId, capabilityScore);
    });

    // Update platform overall score
    platform.overallScore = (totalScore / maxPossibleScore) * 100;
    
    // Update evaluation recommendations
    this.updatePlatformEvaluation(platform);
  }

  /**
   * Calculate capability score for platform
   */
  private calculateCapabilityScore(platform: SOARPlatform, capability: PlatformCapability): number {
    let score = 0;
    
    // Score based on platform features matching capability requirements
    switch (capability.category) {
      case 'WORKFLOW_ENGINE':
        score = this.evaluateWorkflowEngine(platform, capability);
        break;
      case 'VISUAL_DESIGNER':
        score = platform.workflowEngine.visualDesigner ? 5 : 1;
        break;
      case 'INTEGRATION_FRAMEWORK':
        score = this.evaluateIntegrationFramework(platform, capability);
        break;
      case 'SECURITY_FEATURES':
        score = this.evaluateSecurityFeatures(platform, capability);
        break;
      case 'SCALABILITY':
        score = this.evaluateScalability(platform, capability);
        break;
      default:
        score = 3; // Default score
    }
    
    return Math.min(Math.max(score, 1), 5); // Ensure score is between 1-5
  }

  /**
   * Evaluate workflow engine capabilities
   */
  private evaluateWorkflowEngine(platform: SOARPlatform, capability: PlatformCapability): number {
    const engine = platform.workflowEngine;
    let score = 0;
    
    if (capability.name.includes('Conditional Logic')) {
      score = engine.conditionalLogic ? 5 : 2;
    } else if (capability.name.includes('Parallel Execution')) {
      score = engine.parallelExecution ? 5 : 2;
    } else if (capability.name.includes('Error Handling')) {
      score = (engine.errorHandling && engine.retryMechanisms) ? 5 : 3;
    } else {
      // General workflow engine score
      const features = [
        engine.visualDesigner,
        engine.codeBasedWorkflows,
        engine.conditionalLogic,
        engine.parallelExecution,
        engine.errorHandling,
        engine.humanApproval,
        engine.versioning
      ];
      const supportedFeatures = features.filter(f => f).length;
      score = Math.round((supportedFeatures / features.length) * 5);
    }
    
    return score;
  }

  /**
   * Evaluate integration framework capabilities
   */
  private evaluateIntegrationFramework(platform: SOARPlatform, capability: PlatformCapability): number {
    const integrations = platform.integrations;
    
    if (capability.name.includes('Pre-built Integrations')) {
      if (integrations.preBuiltConnectors >= 300) return 5;
      if (integrations.preBuiltConnectors >= 200) return 4;
      if (integrations.preBuiltConnectors >= 100) return 3;
      if (integrations.preBuiltConnectors >= 50) return 2;
      return 1;
    } else if (capability.name.includes('Custom Integration SDK')) {
      return integrations.customConnectorSDK ? 5 : 1;
    }
    
    // General integration score
    const features = [
      integrations.customConnectorSDK,
      integrations.webhookSupport,
      integrations.restApiSupport,
      integrations.preBuiltConnectors > 100
    ];
    const supportedFeatures = features.filter(f => f).length;
    return Math.round((supportedFeatures / features.length) * 5);
  }

  /**
   * Evaluate security features
   */
  private evaluateSecurityFeatures(platform: SOARPlatform, capability: PlatformCapability): number {
    const security = platform.security;
    
    if (capability.name.includes('Role-Based Access Control')) {
      return security.rbacSupport ? 5 : 1;
    } else if (capability.name.includes('Audit Logging')) {
      return security.auditLogging ? 5 : 1;
    }
    
    // General security score
    const features = [
      security.rbacSupport,
      security.mfaIntegration,
      security.encryptionAtRest,
      security.encryptionInTransit,
      security.auditLogging,
      security.secretsManagement
    ];
    const supportedFeatures = features.filter(f => f).length;
    return Math.round((supportedFeatures / features.length) * 5);
  }

  /**
   * Evaluate scalability features
   */
  private evaluateScalability(platform: SOARPlatform, capability: PlatformCapability): number {
    const scalability = platform.scalability;
    
    if (capability.name.includes('Horizontal Scaling')) {
      return scalability.horizontalScaling ? 5 : 2;
    }
    
    // General scalability score
    const features = [
      scalability.horizontalScaling,
      scalability.verticalScaling,
      scalability.loadBalancing,
      scalability.clustering
    ];
    const supportedFeatures = features.filter(f => f).length;
    return Math.round((supportedFeatures / features.length) * 5);
  }

  /**
   * Update platform evaluation and recommendations
   */
  private updatePlatformEvaluation(platform: SOARPlatform): void {
    const score = platform.overallScore;
    let recommendation: string;
    let riskLevel: string;
    
    if (score >= 85) {
      recommendation = 'HIGHLY_RECOMMENDED';
      riskLevel = 'LOW';
    } else if (score >= 70) {
      recommendation = 'RECOMMENDED';
      riskLevel = 'LOW';
    } else if (score >= 55) {
      recommendation = 'CONDITIONAL';
      riskLevel = 'MEDIUM';
    } else {
      recommendation = 'NOT_RECOMMENDED';
      riskLevel = 'HIGH';
    }
    
    platform.evaluation = {
      evaluatedBy: 'SOAR Platform Team',
      evaluationDate: new Date(),
      strengths: this.identifyPlatformStrengths(platform),
      weaknesses: this.identifyPlatformWeaknesses(platform),
      recommendation: recommendation as any,
      riskLevel: riskLevel as any,
      implementationTimeframe: this.estimateImplementationTimeframe(platform)
    };
  }

  /**
   * Generate evaluation matrix
   */
  private generateEvaluationMatrix(): void {
    const platforms = Array.from(this.platforms.values());
    const capabilities = Array.from(this.capabilities.values());
    
    console.log('\n=== SOAR Platform Evaluation Matrix ===');
    console.log('Platform\t\t\tOverall Score\tRecommendation');
    console.log('=' .repeat(60));
    
    platforms
      .sort((a, b) => b.overallScore - a.overallScore)
      .forEach(platform => {
        console.log(`${platform.name.padEnd(25)}\t${platform.overallScore.toFixed(1)}\t\t${platform.evaluation.recommendation}`);
      });
    
    console.log('=' .repeat(60));
  }

  /**
   * Create provisioning configuration for selected platform
   */
  public createProvisioningConfig(
    platformId: string,
    environment: 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION',
    customConfig?: Partial<ProvisioningConfig>
  ): ProvisioningConfig {
    const platform = this.platforms.get(platformId);
    if (!platform) {
      throw new Error(`Platform not found: ${platformId}`);
    }

    const config: ProvisioningConfig = {
      configId: crypto.randomUUID(),
      platformId,
      deploymentName: `isectech-soar-${environment.toLowerCase()}`,
      environment,
      
      infrastructure: {
        provider: 'AWS',
        region: 'us-east-1',
        availabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
        
        compute: {
          instanceType: environment === 'PRODUCTION' ? 'c5.4xlarge' : 'c5.2xlarge',
          minInstances: environment === 'PRODUCTION' ? 3 : 2,
          maxInstances: environment === 'PRODUCTION' ? 10 : 5,
          autoScaling: true,
          cpuTarget: 70,
          memoryTarget: 80
        },
        
        storage: {
          type: 'SSD',
          size: environment === 'PRODUCTION' ? 1000 : 500,
          iops: 3000,
          throughput: 250,
          backupEnabled: true,
          encryptionEnabled: true
        },
        
        networking: {
          subnetIds: ['subnet-12345', 'subnet-67890'],
          securityGroupIds: ['sg-soar-app', 'sg-soar-db'],
          loadBalancer: true,
          publicAccess: false,
          privateEndpoints: ['s3', 'secretsmanager']
        }
      },
      
      database: {
        type: 'POSTGRESQL',
        version: '14.9',
        multiAZ: environment === 'PRODUCTION',
        backupRetention: environment === 'PRODUCTION' ? 30 : 7,
        encryptionAtRest: true,
        performanceInsights: true,
        connectionPooling: true
      },
      
      security: {
        wafEnabled: environment === 'PRODUCTION',
        ddosProtection: environment === 'PRODUCTION',
        ipWhitelist: ['10.0.0.0/8'],
        secretsManagerIntegration: true,
        vaultIntegration: false,
        ssoConfiguration: {
          enabled: true,
          provider: 'Azure AD'
        }
      },
      
      monitoring: {
        metricsEnabled: true,
        loggingEnabled: true,
        tracingEnabled: environment !== 'DEVELOPMENT',
        alertingEnabled: true,
        dashboardsEnabled: true,
        retentionPeriod: environment === 'PRODUCTION' ? 90 : 30,
        logLevel: environment === 'DEVELOPMENT' ? 'DEBUG' : 'INFO'
      },
      
      integrations: [],
      parameters: {},
      status: 'PENDING',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...customConfig
    };

    const validatedConfig = ProvisioningConfigSchema.parse(config);
    this.provisioningConfigs.set(validatedConfig.configId, validatedConfig);
    
    return validatedConfig;
  }

  /**
   * Deploy platform configuration
   */
  public async deployPlatform(configId: string): Promise<{ success: boolean; deploymentId?: string; error?: string }> {
    try {
      const config = this.provisioningConfigs.get(configId);
      if (!config) {
        return { success: false, error: 'Configuration not found' };
      }

      // Update status
      config.status = 'IN_PROGRESS';
      config.deploymentStartTime = new Date();
      
      // Simulate deployment process
      console.log(`Starting deployment: ${config.deploymentName}`);
      
      // Deploy infrastructure
      await this.deployInfrastructure(config);
      
      // Deploy database
      await this.deployDatabase(config);
      
      // Deploy application
      await this.deployApplication(config);
      
      // Configure security
      await this.configureSecurity(config);
      
      // Setup monitoring
      await this.setupMonitoring(config);
      
      // Final configuration
      await this.finalizeDeployment(config);
      
      // Update status
      config.status = 'COMPLETED';
      config.deploymentEndTime = new Date();
      config.lastHealthCheck = new Date();
      
      console.log(`Deployment completed: ${config.deploymentName}`);
      return { success: true, deploymentId: config.configId };
      
    } catch (error) {
      console.error('Deployment failed:', error);
      return { success: false, error: 'Deployment failed' };
    }
  }

  /**
   * Generate platform selection report
   */
  public generatePlatformSelectionReport(): any {
    const platforms = Array.from(this.platforms.values())
      .sort((a, b) => b.overallScore - a.overallScore);
    
    const topPlatform = platforms[0];
    
    return {
      executiveSummary: {
        evaluatedPlatforms: platforms.length,
        recommendedPlatform: topPlatform.name,
        overallScore: topPlatform.overallScore,
        estimatedCost: topPlatform.licensing.annualCostEstimate,
        implementationTimeframe: topPlatform.evaluation.implementationTimeframe
      },
      platformRankings: platforms.map(p => ({
        name: p.name,
        vendor: p.vendor,
        score: p.overallScore,
        recommendation: p.evaluation.recommendation,
        riskLevel: p.evaluation.riskLevel
      })),
      detailedAnalysis: platforms.map(p => ({
        platform: p.name,
        strengths: p.evaluation.strengths,
        weaknesses: p.evaluation.weaknesses,
        technicalFit: this.calculateTechnicalFit(p),
        costAnalysis: this.analyzeCost(p),
        riskAssessment: this.assessRisk(p)
      })),
      recommendation: this.generateFinalRecommendation(topPlatform),
      nextSteps: this.generateNextSteps(topPlatform)
    };
  }

  // Private helper methods
  private identifyPlatformStrengths(platform: SOARPlatform): string[] {
    const strengths = [];
    
    if (platform.integrations.preBuiltConnectors >= 200) {
      strengths.push('Extensive pre-built integrations');
    }
    if (platform.workflowEngine.visualDesigner && platform.workflowEngine.codeBasedWorkflows) {
      strengths.push('Flexible workflow design options');
    }
    if (platform.scalability.horizontalScaling) {
      strengths.push('Excellent scalability');
    }
    if (platform.security.complianceCertifications.length >= 2) {
      strengths.push('Strong compliance posture');
    }
    if (platform.vendor.marketPosition === 'LEADER') {
      strengths.push('Market-leading vendor');
    }
    
    return strengths;
  }

  private identifyPlatformWeaknesses(platform: SOARPlatform): string[] {
    const weaknesses = [];
    
    if (platform.licensing.annualCostEstimate && platform.licensing.annualCostEstimate > 500000) {
      weaknesses.push('High licensing costs');
    }
    if (!platform.workflowEngine.visualDesigner) {
      weaknesses.push('Limited visual workflow design');
    }
    if (!platform.scalability.horizontalScaling) {
      weaknesses.push('Limited scalability options');
    }
    if (platform.techSpecs.minRAM > 32) {
      weaknesses.push('High resource requirements');
    }
    if (platform.vendor.supportQuality < 4) {
      weaknesses.push('Below-average support quality');
    }
    
    return weaknesses;
  }

  private estimateImplementationTimeframe(platform: SOARPlatform): string {
    let weeks = 12; // Base implementation time
    
    // Adjust based on platform complexity
    if (platform.type === 'CLOUD_NATIVE') weeks -= 2;
    if (platform.architecture === 'MICROSERVICES') weeks += 2;
    if (platform.integrations.preBuiltConnectors < 100) weeks += 4;
    if (!platform.workflowEngine.visualDesigner) weeks += 3;
    
    return `${weeks}-${weeks + 4} weeks`;
  }

  private calculateTechnicalFit(platform: SOARPlatform): number {
    // Technical fit score based on requirements alignment
    let score = 0;
    
    // Integration requirements
    if (platform.integrations.preBuiltConnectors >= 200) score += 20;
    if (platform.integrations.customConnectorSDK) score += 15;
    
    // Workflow requirements
    if (platform.workflowEngine.visualDesigner) score += 15;
    if (platform.workflowEngine.parallelExecution) score += 10;
    
    // Security requirements
    if (platform.security.rbacSupport) score += 10;
    if (platform.security.auditLogging) score += 10;
    
    // Scalability requirements
    if (platform.scalability.horizontalScaling) score += 10;
    if (platform.scalability.clustering) score += 10;
    
    return Math.min(score, 100);
  }

  private analyzeCost(platform: SOARPlatform): any {
    const annual = platform.licensing.annualCostEstimate || 0;
    const maintenance = (annual * (platform.licensing.maintenanceCostPercentage || 0)) / 100;
    
    return {
      initialCost: annual,
      annualMaintenance: maintenance,
      fiveYearTCO: (annual * 5) + (maintenance * 4),
      costPerAnalyst: annual / 25 // Assuming 25 analysts
    };
  }

  private assessRisk(platform: SOARPlatform): any {
    const risks = [];
    
    if (platform.vendor.financialStability !== 'EXCELLENT') {
      risks.push('Vendor financial stability concerns');
    }
    if (platform.licensing.annualCostEstimate && platform.licensing.annualCostEstimate > 600000) {
      risks.push('High cost investment risk');
    }
    if (platform.type === 'HYBRID' && platform.name.includes('Custom')) {
      risks.push('Custom implementation complexity');
    }
    
    return {
      identifiedRisks: risks,
      overallRiskLevel: platform.evaluation.riskLevel,
      mitigationStrategies: this.generateRiskMitigationStrategies(risks)
    };
  }

  private generateRiskMitigationStrategies(risks: string[]): string[] {
    return [
      'Establish vendor relationship and support agreements',
      'Plan phased implementation to reduce complexity',
      'Develop comprehensive testing strategy',
      'Create backup and recovery procedures',
      'Implement thorough change management process'
    ];
  }

  private generateFinalRecommendation(platform: SOARPlatform): string {
    return `Based on comprehensive evaluation, ${platform.name} is recommended for iSECTECH SOAR implementation due to its ${platform.evaluation.strengths.join(', ').toLowerCase()}. The platform scores ${platform.overallScore.toFixed(1)}/100 and aligns well with our technical and business requirements.`;
  }

  private generateNextSteps(platform: SOARPlatform): string[] {
    return [
      'Conduct proof of concept with selected platform',
      'Negotiate licensing terms and support agreements',
      'Develop detailed implementation plan',
      'Prepare infrastructure and provisioning requirements',
      'Establish project team and governance structure'
    ];
  }

  // Deployment helper methods
  private async deployInfrastructure(config: ProvisioningConfig): Promise<void> {
    console.log('Deploying infrastructure...');
    // Simulate infrastructure deployment
    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  private async deployDatabase(config: ProvisioningConfig): Promise<void> {
    console.log('Deploying database...');
    // Simulate database deployment
    await new Promise(resolve => setTimeout(resolve, 1500));
  }

  private async deployApplication(config: ProvisioningConfig): Promise<void> {
    console.log('Deploying application...');
    // Simulate application deployment
    await new Promise(resolve => setTimeout(resolve, 3000));
  }

  private async configureSecurity(config: ProvisioningConfig): Promise<void> {
    console.log('Configuring security...');
    // Simulate security configuration
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  private async setupMonitoring(config: ProvisioningConfig): Promise<void> {
    console.log('Setting up monitoring...');
    // Simulate monitoring setup
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  private async finalizeDeployment(config: ProvisioningConfig): Promise<void> {
    console.log('Finalizing deployment...');
    // Simulate final configuration
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  /**
   * Add capability to evaluation framework
   */
  public addCapability(capabilityData: Partial<PlatformCapability>): PlatformCapability {
    const capability: PlatformCapability = {
      capabilityId: capabilityData.capabilityId || crypto.randomUUID(),
      name: capabilityData.name || '',
      description: capabilityData.description || '',
      category: capabilityData.category || 'WORKFLOW_ENGINE',
      importance: capabilityData.importance || 'MEDIUM',
      weight: capabilityData.weight || 5,
      assessment: {
        functionality: 3,
        usability: 3,
        performance: 3,
        reliability: 3,
        scalability: 3,
        security: 3,
        integration: 3,
        documentation: 3,
        ...capabilityData.assessment
      },
      supportedBy: capabilityData.supportedBy || [],
      implementationComplexity: capabilityData.implementationComplexity || 'MEDIUM',
      technicalRequirements: capabilityData.technicalRequirements || [],
      createdAt: new Date(),
      updatedAt: new Date(),
      ...capabilityData
    };

    const validatedCapability = PlatformCapabilitySchema.parse(capability);
    this.capabilities.set(validatedCapability.capabilityId, validatedCapability);
    
    return validatedCapability;
  }

  /**
   * Add platform to evaluation
   */
  public addPlatform(platformData: Partial<SOARPlatform>): SOARPlatform {
    const platform: SOARPlatform = {
      platformId: platformData.platformId || crypto.randomUUID(),
      name: platformData.name || '',
      vendor: platformData.vendor || '',
      version: platformData.version || '1.0.0',
      type: platformData.type || 'COMMERCIAL',
      deploymentModel: platformData.deploymentModel || 'ON_PREMISE',
      description: platformData.description || '',
      architecture: platformData.architecture || 'MONOLITHIC',
      capabilities: platformData.capabilities || [],
      overallScore: platformData.overallScore || 0,
      techSpecs: {
        supportedOS: ['Linux'],
        minCPUCores: 4,
        minRAM: 8,
        minStorage: 100,
        supportedDatabases: ['PostgreSQL'],
        programmingLanguages: ['JavaScript'],
        apiTypes: ['REST'],
        authenticationMethods: ['Local'],
        ...platformData.techSpecs
      },
      integrations: {
        preBuiltConnectors: 50,
        customConnectorSDK: true,
        webhookSupport: true,
        restApiSupport: true,
        soapApiSupport: false,
        messagingSupport: [],
        databaseConnectors: [],
        ...platformData.integrations
      },
      workflowEngine: {
        visualDesigner: true,
        codeBasedWorkflows: true,
        conditionalLogic: true,
        loopsAndIterations: true,
        parallelExecution: true,
        errorHandling: true,
        retryMechanisms: true,
        humanApproval: true,
        scheduling: true,
        versioning: true,
        ...platformData.workflowEngine
      },
      security: {
        rbacSupport: true,
        mfaIntegration: true,
        encryptionAtRest: true,
        encryptionInTransit: true,
        auditLogging: true,
        secretsManagement: true,
        networkSegmentation: true,
        complianceCertifications: [],
        ...platformData.security
      },
      scalability: {
        horizontalScaling: true,
        verticalScaling: true,
        loadBalancing: true,
        clustering: true,
        ...platformData.scalability
      },
      licensing: {
        model: 'SUBSCRIPTION',
        costStructure: 'Per user',
        supportTiers: ['Standard'],
        ...platformData.licensing
      },
      vendor: {
        marketPosition: 'NICHE',
        financialStability: 'GOOD',
        supportQuality: 3,
        roadmapAlignment: 3,
        ...platformData.vendor
      },
      evaluation: {
        evaluatedBy: 'SOAR Team',
        evaluationDate: new Date(),
        strengths: [],
        weaknesses: [],
        recommendation: 'CONDITIONAL',
        riskLevel: 'MEDIUM',
        implementationTimeframe: '12-16 weeks',
        ...platformData.evaluation
      },
      createdAt: new Date(),
      updatedAt: new Date(),
      ...platformData
    };

    const validatedPlatform = SOARPlatformSchema.parse(platform);
    this.platforms.set(validatedPlatform.platformId, validatedPlatform);
    
    return validatedPlatform;
  }

  /**
   * Public getters for testing and external access
   */
  public getCapability(capabilityId: string): PlatformCapability | null {
    return this.capabilities.get(capabilityId) || null;
  }

  public getAllCapabilities(): PlatformCapability[] {
    return Array.from(this.capabilities.values());
  }

  public getPlatform(platformId: string): SOARPlatform | null {
    return this.platforms.get(platformId) || null;
  }

  public getAllPlatforms(): SOARPlatform[] {
    return Array.from(this.platforms.values());
  }

  public getProvisioningConfig(configId: string): ProvisioningConfig | null {
    return this.provisioningConfigs.get(configId) || null;
  }

  public getAllProvisioningConfigs(): ProvisioningConfig[] {
    return Array.from(this.provisioningConfigs.values());
  }

  public getEvaluationMatrix(): Map<string, Map<string, number>> {
    return this.evaluationMatrix;
  }
}

// Export production-ready platform management system
export const isectechSOARPlatformManager = new ISECTECHSOARPlatformManager();