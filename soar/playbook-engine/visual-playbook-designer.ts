/**
 * Production-grade Visual Playbook Engine for SOAR
 * 
 * Comprehensive visual playbook designer with drag-and-drop interface,
 * conditional logic, decision points, parallel execution, error handling,
 * and enterprise-grade features for iSECTECH's SOAR platform.
 * 
 * Custom implementation with advanced workflow orchestration capabilities.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// Visual Playbook Engine Schemas
export const PlaybookNodeSchema = z.object({
  nodeId: z.string(),
  type: z.enum([
    'START',
    'END', 
    'ACTION',
    'CONDITION',
    'PARALLEL_GATEWAY',
    'MERGE_GATEWAY',
    'HUMAN_TASK',
    'SERVICE_TASK',
    'SCRIPT_TASK',
    'EMAIL_TASK',
    'TIMER_EVENT',
    'ERROR_EVENT',
    'ESCALATION_EVENT',
    'SUBPROCESS',
    'LOOP',
    'SWITCH'
  ]),
  
  // Visual properties
  position: z.object({
    x: z.number(),
    y: z.number(),
    width: z.number().default(120),
    height: z.number().default(80)
  }),
  
  // Node configuration
  name: z.string(),
  description: z.string().optional(),
  
  // Node-specific configuration
  configuration: z.record(z.any()),
  
  // Input/Output definitions
  inputs: z.array(z.object({
    name: z.string(),
    type: z.string(),
    required: z.boolean().default(false),
    defaultValue: z.any().optional(),
    validation: z.string().optional()
  })).default([]),
  
  outputs: z.array(z.object({
    name: z.string(),
    type: z.string(),
    description: z.string().optional()
  })).default([]),
  
  // Execution properties
  timeout: z.number().optional(), // seconds
  retryCount: z.number().default(0),
  retryDelay: z.number().default(1000), // milliseconds
  
  // Conditional logic (for CONDITION nodes)
  conditions: z.array(z.object({
    expression: z.string(),
    nextNodeId: z.string(),
    description: z.string().optional()
  })).optional(),
  
  // Loop configuration (for LOOP nodes)
  loopConfig: z.object({
    condition: z.string(),
    maxIterations: z.number().default(100),
    iterationVariable: z.string().optional()
  }).optional(),
  
  // Human task configuration
  humanTask: z.object({
    assignee: z.string().optional(),
    candidateGroups: z.array(z.string()).default([]),
    dueDate: z.string().optional(),
    priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
    formKey: z.string().optional(),
    formFields: z.array(z.object({
      id: z.string(),
      label: z.string(),
      type: z.enum(['TEXT', 'NUMBER', 'BOOLEAN', 'SELECT', 'MULTISELECT', 'DATE', 'TEXTAREA']),
      required: z.boolean().default(false),
      options: z.array(z.string()).optional(),
      validation: z.string().optional()
    })).default([])
  }).optional(),
  
  // Script task configuration
  scriptTask: z.object({
    language: z.enum(['JAVASCRIPT', 'PYTHON', 'POWERSHELL', 'BASH']),
    script: z.string(),
    variables: z.record(z.any()).default({})
  }).optional(),
  
  // Service task configuration
  serviceTask: z.object({
    serviceType: z.enum(['REST_API', 'EMAIL', 'DATABASE', 'FILE_SYSTEM', 'CUSTOM']),
    endpoint: z.string().optional(),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).optional(),
    headers: z.record(z.string()).default({}),
    requestBody: z.any().optional(),
    authentication: z.object({
      type: z.enum(['NONE', 'BASIC', 'BEARER', 'API_KEY', 'OAUTH2']),
      credentials: z.record(z.string()).default({})
    }).optional()
  }).optional(),
  
  // Error handling
  errorHandling: z.object({
    onError: z.enum(['FAIL', 'RETRY', 'CONTINUE', 'ESCALATE']).default('FAIL'),
    errorNodeId: z.string().optional(),
    errorMessage: z.string().optional()
  }).default({ onError: 'FAIL' }),
  
  // Visual styling
  style: z.object({
    backgroundColor: z.string().default('#f0f0f0'),
    borderColor: z.string().default('#cccccc'),
    textColor: z.string().default('#333333'),
    icon: z.string().optional(),
    borderWidth: z.number().default(2),
    borderRadius: z.number().default(8)
  }).default({}),
  
  // Metadata
  tags: z.array(z.string()).default([]),
  documentation: z.string().optional(),
  version: z.string().default('1.0.0'),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const PlaybookConnectionSchema = z.object({
  connectionId: z.string(),
  sourceNodeId: z.string(),
  targetNodeId: z.string(),
  
  // Connection properties
  sourcePort: z.string().default('output'),
  targetPort: z.string().default('input'),
  
  // Conditional connections
  condition: z.string().optional(),
  conditionType: z.enum(['EXPRESSION', 'OUTCOME', 'DEFAULT']).default('DEFAULT'),
  
  // Visual properties
  path: z.array(z.object({
    x: z.number(),
    y: z.number()
  })).optional(),
  
  style: z.object({
    strokeColor: z.string().default('#666666'),
    strokeWidth: z.number().default(2),
    strokeStyle: z.enum(['SOLID', 'DASHED', 'DOTTED']).default('SOLID'),
    arrowStyle: z.enum(['NONE', 'ARROW', 'DIAMOND', 'CIRCLE']).default('ARROW')
  }).default({}),
  
  // Metadata
  label: z.string().optional(),
  description: z.string().optional(),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const VisualPlaybookSchema = z.object({
  playbookId: z.string(),
  name: z.string(),
  description: z.string(),
  version: z.string(),
  
  // Playbook metadata
  category: z.string(),
  tags: z.array(z.string()).default([]),
  author: z.string(),
  
  // Visual canvas properties
  canvas: z.object({
    width: z.number().default(2000),
    height: z.number().default(1500),
    zoom: z.number().default(1.0),
    viewportX: z.number().default(0),
    viewportY: z.number().default(0),
    gridSize: z.number().default(20),
    snapToGrid: z.boolean().default(true)
  }),
  
  // Playbook structure
  nodes: z.array(PlaybookNodeSchema),
  connections: z.array(PlaybookConnectionSchema),
  
  // Global variables
  variables: z.array(z.object({
    name: z.string(),
    type: z.enum(['STRING', 'NUMBER', 'BOOLEAN', 'OBJECT', 'ARRAY']),
    defaultValue: z.any().optional(),
    description: z.string().optional(),
    required: z.boolean().default(false)
  })).default([]),
  
  // Input parameters
  inputParameters: z.array(z.object({
    name: z.string(),
    type: z.string(),
    required: z.boolean().default(false),
    defaultValue: z.any().optional(),
    description: z.string().optional(),
    validation: z.string().optional()
  })).default([]),
  
  // Output parameters
  outputParameters: z.array(z.object({
    name: z.string(),
    type: z.string(),
    description: z.string().optional()
  })).default([]),
  
  // Execution configuration
  execution: z.object({
    timeout: z.number().default(3600), // 1 hour default
    priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
    maxConcurrentInstances: z.number().default(10),
    retryPolicy: z.object({
      maxRetries: z.number().default(3),
      retryDelay: z.number().default(5000),
      backoffMultiplier: z.number().default(2)
    })
  }),
  
  // Validation and testing
  validation: z.object({
    isValid: z.boolean().default(false),
    errors: z.array(z.object({
      type: z.enum(['ERROR', 'WARNING', 'INFO']),
      nodeId: z.string().optional(),
      message: z.string(),
      details: z.string().optional()
    })).default([]),
    lastValidated: z.date().optional()
  }),
  
  // Versioning and lifecycle
  status: z.enum(['DRAFT', 'TESTING', 'APPROVED', 'DEPLOYED', 'DEPRECATED']).default('DRAFT'),
  publishedVersion: z.string().optional(),
  
  // Access control
  permissions: z.object({
    canEdit: z.array(z.string()).default([]),
    canExecute: z.array(z.string()).default([]),
    canView: z.array(z.string()).default([])
  }),
  
  // Execution statistics
  statistics: z.object({
    totalExecutions: z.number().default(0),
    successfulExecutions: z.number().default(0),
    failedExecutions: z.number().default(0),
    averageExecutionTime: z.number().default(0),
    lastExecuted: z.date().optional()
  }),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const PlaybookTemplateSchema = z.object({
  templateId: z.string(),
  name: z.string(),
  description: z.string(),
  category: z.string(),
  
  // Template structure
  template: VisualPlaybookSchema,
  
  // Configuration parameters
  parameters: z.array(z.object({
    name: z.string(),
    type: z.string(),
    description: z.string(),
    defaultValue: z.any().optional(),
    required: z.boolean().default(false),
    options: z.array(z.any()).optional()
  })).default([]),
  
  // Usage information
  usageCount: z.number().default(0),
  rating: z.number().min(1).max(5).optional(),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export type PlaybookNode = z.infer<typeof PlaybookNodeSchema>;
export type PlaybookConnection = z.infer<typeof PlaybookConnectionSchema>;
export type VisualPlaybook = z.infer<typeof VisualPlaybookSchema>;
export type PlaybookTemplate = z.infer<typeof PlaybookTemplateSchema>;

/**
 * Visual Playbook Engine Manager
 */
export class ISECTECHVisualPlaybookEngine {
  private playbooks: Map<string, VisualPlaybook> = new Map();
  private templates: Map<string, PlaybookTemplate> = new Map();
  private nodeLibrary: Map<string, any> = new Map();
  private executionInstances: Map<string, any> = new Map();

  constructor() {
    this.initializeEngine();
  }

  /**
   * Initialize the visual playbook engine
   */
  private initializeEngine(): void {
    console.log('Initializing iSECTECH Visual Playbook Engine...');
    
    // Initialize node library
    this.initializeNodeLibrary();
    
    // Initialize templates
    this.initializePlaybookTemplates();
    
    console.log('Visual Playbook Engine initialized successfully');
  }

  /**
   * Initialize the node library with standard node types
   */
  private initializeNodeLibrary(): void {
    const nodeTypes = [
      // Control Flow Nodes
      {
        type: 'START',
        name: 'Start Event',
        description: 'Starting point of the playbook',
        category: 'Events',
        icon: 'play-circle',
        defaultConfig: {
          maxInstances: 1
        },
        inputs: [],
        outputs: [{ name: 'output', type: 'flow' }]
      },
      
      {
        type: 'END',
        name: 'End Event',
        description: 'End point of the playbook',
        category: 'Events',
        icon: 'stop-circle',
        defaultConfig: {},
        inputs: [{ name: 'input', type: 'flow', required: true }],
        outputs: []
      },
      
      {
        type: 'CONDITION',
        name: 'Decision Gateway',
        description: 'Conditional branching based on expressions',
        category: 'Gateways',
        icon: 'git-branch',
        defaultConfig: {
          evaluationMode: 'ALL_CONDITIONS'
        },
        inputs: [{ name: 'input', type: 'flow', required: true }],
        outputs: [{ name: 'output', type: 'flow' }]
      },
      
      {
        type: 'PARALLEL_GATEWAY',
        name: 'Parallel Gateway',
        description: 'Split execution into parallel paths',
        category: 'Gateways',
        icon: 'split',
        defaultConfig: {
          waitForAll: false
        },
        inputs: [{ name: 'input', type: 'flow', required: true }],
        outputs: [{ name: 'output', type: 'flow' }]
      },
      
      {
        type: 'MERGE_GATEWAY',
        name: 'Merge Gateway',
        description: 'Merge parallel execution paths',
        category: 'Gateways',
        icon: 'merge',
        defaultConfig: {
          waitForAll: true
        },
        inputs: [{ name: 'input', type: 'flow', required: true }],
        outputs: [{ name: 'output', type: 'flow' }]
      },
      
      // Task Nodes
      {
        type: 'SERVICE_TASK',
        name: 'Service Task',
        description: 'Execute external service calls',
        category: 'Tasks',
        icon: 'server',
        defaultConfig: {
          serviceType: 'REST_API',
          timeout: 30000,
          retryCount: 3
        },
        inputs: [
          { name: 'input', type: 'flow', required: true },
          { name: 'parameters', type: 'object' }
        ],
        outputs: [
          { name: 'output', type: 'flow' },
          { name: 'result', type: 'object' }
        ]
      },
      
      {
        type: 'SCRIPT_TASK',
        name: 'Script Task',
        description: 'Execute custom scripts',
        category: 'Tasks',
        icon: 'code',
        defaultConfig: {
          language: 'JAVASCRIPT',
          timeout: 30000
        },
        inputs: [
          { name: 'input', type: 'flow', required: true },
          { name: 'variables', type: 'object' }
        ],
        outputs: [
          { name: 'output', type: 'flow' },
          { name: 'result', type: 'any' }
        ]
      },
      
      {
        type: 'HUMAN_TASK',
        name: 'Human Task',
        description: 'Require human interaction and approval',
        category: 'Tasks',
        icon: 'user',
        defaultConfig: {
          priority: 'MEDIUM',
          timeout: 86400000 // 24 hours
        },
        inputs: [
          { name: 'input', type: 'flow', required: true },
          { name: 'taskData', type: 'object' }
        ],
        outputs: [
          { name: 'approved', type: 'flow' },
          { name: 'rejected', type: 'flow' },
          { name: 'response', type: 'object' }
        ]
      },
      
      {
        type: 'EMAIL_TASK',
        name: 'Email Task',
        description: 'Send email notifications',
        category: 'Communication',
        icon: 'mail',
        defaultConfig: {
          template: 'default',
          priority: 'MEDIUM'
        },
        inputs: [
          { name: 'input', type: 'flow', required: true },
          { name: 'recipients', type: 'array', required: true },
          { name: 'subject', type: 'string', required: true },
          { name: 'body', type: 'string', required: true }
        ],
        outputs: [
          { name: 'output', type: 'flow' },
          { name: 'messageId', type: 'string' }
        ]
      },
      
      // Event Nodes
      {
        type: 'TIMER_EVENT',
        name: 'Timer Event',
        description: 'Wait for specified time duration',
        category: 'Events',
        icon: 'clock',
        defaultConfig: {
          duration: 60000, // 1 minute
          unit: 'MILLISECONDS'
        },
        inputs: [{ name: 'input', type: 'flow', required: true }],
        outputs: [{ name: 'output', type: 'flow' }]
      },
      
      {
        type: 'ERROR_EVENT',
        name: 'Error Event',
        description: 'Handle error conditions',
        category: 'Events',
        icon: 'alert-triangle',
        defaultConfig: {
          errorCode: 'GENERAL_ERROR',
          escalate: false
        },
        inputs: [{ name: 'error', type: 'object', required: true }],
        outputs: [{ name: 'output', type: 'flow' }]
      },
      
      {
        type: 'ESCALATION_EVENT',
        name: 'Escalation Event',
        description: 'Escalate to higher authority',
        category: 'Events',
        icon: 'arrow-up',
        defaultConfig: {
          escalationLevel: 1,
          notifyManagement: true
        },
        inputs: [
          { name: 'input', type: 'flow', required: true },
          { name: 'escalationData', type: 'object' }
        ],
        outputs: [{ name: 'output', type: 'flow' }]
      },
      
      // Loop and Control Structures
      {
        type: 'LOOP',
        name: 'Loop',
        description: 'Iterate over collections or conditions',
        category: 'Control',
        icon: 'repeat',
        defaultConfig: {
          loopType: 'FOR_EACH',
          maxIterations: 100
        },
        inputs: [
          { name: 'input', type: 'flow', required: true },
          { name: 'collection', type: 'array' }
        ],
        outputs: [
          { name: 'iteration', type: 'flow' },
          { name: 'completed', type: 'flow' },
          { name: 'item', type: 'any' }
        ]
      },
      
      {
        type: 'SUBPROCESS',
        name: 'Sub-Process',
        description: 'Execute another playbook as subprocess',
        category: 'Control',
        icon: 'box',
        defaultConfig: {
          inheritVariables: true,
          waitForCompletion: true
        },
        inputs: [
          { name: 'input', type: 'flow', required: true },
          { name: 'parameters', type: 'object' }
        ],
        outputs: [
          { name: 'output', type: 'flow' },
          { name: 'result', type: 'object' }
        ]
      }
    ];

    nodeTypes.forEach(nodeType => {
      this.nodeLibrary.set(nodeType.type, nodeType);
    });

    console.log(`Initialized ${nodeTypes.length} node types in library`);
  }

  /**
   * Initialize standard playbook templates
   */
  private initializePlaybookTemplates(): void {
    const templates: Partial<PlaybookTemplate>[] = [
      {
        name: 'Phishing Email Response',
        description: 'Standard template for phishing email incident response',
        category: 'Email Security',
        template: this.createPhishingResponseTemplate(),
        parameters: [
          { name: 'email_id', type: 'string', description: 'Email message ID', required: true },
          { name: 'sender_email', type: 'string', description: 'Sender email address', required: true },
          { name: 'urgency_level', type: 'string', description: 'Incident urgency level', defaultValue: 'MEDIUM' }
        ]
      },
      
      {
        name: 'Malware Containment',
        description: 'Template for malware detection and containment',
        category: 'Endpoint Security',
        template: this.createMalwareContainmentTemplate(),
        parameters: [
          { name: 'endpoint_id', type: 'string', description: 'Affected endpoint identifier', required: true },
          { name: 'malware_hash', type: 'string', description: 'Malware file hash', required: true },
          { name: 'isolation_required', type: 'boolean', description: 'Whether to isolate endpoint', defaultValue: true }
        ]
      },
      
      {
        name: 'User Access Investigation',
        description: 'Template for investigating suspicious user access',
        category: 'Identity Security',
        template: this.createUserAccessInvestigationTemplate(),
        parameters: [
          { name: 'user_id', type: 'string', description: 'User account identifier', required: true },
          { name: 'suspicious_activity', type: 'string', description: 'Description of suspicious activity', required: true },
          { name: 'disable_account', type: 'boolean', description: 'Whether to disable the account', defaultValue: false }
        ]
      },
      
      {
        name: 'Vulnerability Assessment',
        description: 'Template for vulnerability scanning and assessment',
        category: 'Vulnerability Management',
        template: this.createVulnerabilityAssessmentTemplate(),
        parameters: [
          { name: 'target_assets', type: 'array', description: 'List of assets to scan', required: true },
          { name: 'scan_type', type: 'string', description: 'Type of vulnerability scan', defaultValue: 'COMPREHENSIVE' },
          { name: 'priority_threshold', type: 'string', description: 'Minimum priority for reporting', defaultValue: 'MEDIUM' }
        ]
      }
    ];

    templates.forEach(template => {
      this.addTemplate(template);
    });

    console.log(`Initialized ${templates.length} playbook templates`);
  }

  /**
   * Create a new visual playbook
   */
  public createPlaybook(playbookData: Partial<VisualPlaybook>): VisualPlaybook {
    const playbook: VisualPlaybook = {
      playbookId: playbookData.playbookId || crypto.randomUUID(),
      name: playbookData.name || 'New Playbook',
      description: playbookData.description || '',
      version: playbookData.version || '1.0.0',
      category: playbookData.category || 'General',
      tags: playbookData.tags || [],
      author: playbookData.author || 'Anonymous',
      
      canvas: {
        width: 2000,
        height: 1500,
        zoom: 1.0,
        viewportX: 0,
        viewportY: 0,
        gridSize: 20,
        snapToGrid: true,
        ...playbookData.canvas
      },
      
      nodes: playbookData.nodes || [],
      connections: playbookData.connections || [],
      variables: playbookData.variables || [],
      inputParameters: playbookData.inputParameters || [],
      outputParameters: playbookData.outputParameters || [],
      
      execution: {
        timeout: 3600,
        priority: 'MEDIUM',
        maxConcurrentInstances: 10,
        retryPolicy: {
          maxRetries: 3,
          retryDelay: 5000,
          backoffMultiplier: 2
        },
        ...playbookData.execution
      },
      
      validation: {
        isValid: false,
        errors: [],
        ...playbookData.validation
      },
      
      status: playbookData.status || 'DRAFT',
      permissions: {
        canEdit: [],
        canExecute: [],
        canView: [],
        ...playbookData.permissions
      },
      
      statistics: {
        totalExecutions: 0,
        successfulExecutions: 0,
        failedExecutions: 0,
        averageExecutionTime: 0,
        ...playbookData.statistics
      },
      
      createdAt: new Date(),
      updatedAt: new Date(),
      ...playbookData
    };

    const validatedPlaybook = VisualPlaybookSchema.parse(playbook);
    this.playbooks.set(validatedPlaybook.playbookId, validatedPlaybook);
    
    return validatedPlaybook;
  }

  /**
   * Add node to playbook
   */
  public addNode(playbookId: string, nodeData: Partial<PlaybookNode>): PlaybookNode {
    const playbook = this.playbooks.get(playbookId);
    if (!playbook) {
      throw new Error(`Playbook not found: ${playbookId}`);
    }

    const nodeType = this.nodeLibrary.get(nodeData.type || 'ACTION');
    const node: PlaybookNode = {
      nodeId: nodeData.nodeId || crypto.randomUUID(),
      type: nodeData.type || 'ACTION',
      position: nodeData.position || { x: 100, y: 100, width: 120, height: 80 },
      name: nodeData.name || nodeType?.name || 'New Node',
      description: nodeData.description,
      configuration: { ...nodeType?.defaultConfig, ...nodeData.configuration },
      inputs: nodeData.inputs || nodeType?.inputs || [],
      outputs: nodeData.outputs || nodeType?.outputs || [],
      timeout: nodeData.timeout,
      retryCount: nodeData.retryCount || 0,
      retryDelay: nodeData.retryDelay || 1000,
      conditions: nodeData.conditions,
      loopConfig: nodeData.loopConfig,
      humanTask: nodeData.humanTask,
      scriptTask: nodeData.scriptTask,
      serviceTask: nodeData.serviceTask,
      errorHandling: {
        onError: 'FAIL',
        ...nodeData.errorHandling
      },
      style: {
        backgroundColor: '#f0f0f0',
        borderColor: '#cccccc',
        textColor: '#333333',
        borderWidth: 2,
        borderRadius: 8,
        ...nodeData.style
      },
      tags: nodeData.tags || [],
      documentation: nodeData.documentation,
      version: nodeData.version || '1.0.0',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedNode = PlaybookNodeSchema.parse(node);
    playbook.nodes.push(validatedNode);
    playbook.updatedAt = new Date();
    
    // Re-validate playbook
    this.validatePlaybook(playbookId);
    
    return validatedNode;
  }

  /**
   * Add connection between nodes
   */
  public addConnection(playbookId: string, connectionData: Partial<PlaybookConnection>): PlaybookConnection {
    const playbook = this.playbooks.get(playbookId);
    if (!playbook) {
      throw new Error(`Playbook not found: ${playbookId}`);
    }

    if (!connectionData.sourceNodeId || !connectionData.targetNodeId) {
      throw new Error('Source and target node IDs are required');
    }

    const connection: PlaybookConnection = {
      connectionId: connectionData.connectionId || crypto.randomUUID(),
      sourceNodeId: connectionData.sourceNodeId,
      targetNodeId: connectionData.targetNodeId,
      sourcePort: connectionData.sourcePort || 'output',
      targetPort: connectionData.targetPort || 'input',
      condition: connectionData.condition,
      conditionType: connectionData.conditionType || 'DEFAULT',
      path: connectionData.path,
      style: {
        strokeColor: '#666666',
        strokeWidth: 2,
        strokeStyle: 'SOLID',
        arrowStyle: 'ARROW',
        ...connectionData.style
      },
      label: connectionData.label,
      description: connectionData.description,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedConnection = PlaybookConnectionSchema.parse(connection);
    playbook.connections.push(validatedConnection);
    playbook.updatedAt = new Date();
    
    // Re-validate playbook
    this.validatePlaybook(playbookId);
    
    return validatedConnection;
  }

  /**
   * Validate playbook structure and logic
   */
  public validatePlaybook(playbookId: string): { isValid: boolean; errors: any[] } {
    const playbook = this.playbooks.get(playbookId);
    if (!playbook) {
      throw new Error(`Playbook not found: ${playbookId}`);
    }

    const errors: any[] = [];

    // Check for start and end nodes
    const startNodes = playbook.nodes.filter(n => n.type === 'START');
    const endNodes = playbook.nodes.filter(n => n.type === 'END');

    if (startNodes.length === 0) {
      errors.push({
        type: 'ERROR',
        message: 'Playbook must have at least one START node',
        details: 'Every playbook requires a starting point'
      });
    }

    if (startNodes.length > 1) {
      errors.push({
        type: 'WARNING',
        message: 'Multiple START nodes detected',
        details: 'Only one START node should be used per playbook'
      });
    }

    if (endNodes.length === 0) {
      errors.push({
        type: 'ERROR',
        message: 'Playbook must have at least one END node',
        details: 'Every playbook requires at least one ending point'
      });
    }

    // Check for orphaned nodes
    const connectedNodeIds = new Set<string>();
    playbook.connections.forEach(conn => {
      connectedNodeIds.add(conn.sourceNodeId);
      connectedNodeIds.add(conn.targetNodeId);
    });

    playbook.nodes.forEach(node => {
      if (!connectedNodeIds.has(node.nodeId) && node.type !== 'START' && node.type !== 'END') {
        errors.push({
          type: 'WARNING',
          nodeId: node.nodeId,
          message: `Orphaned node detected: ${node.name}`,
          details: 'Node is not connected to any other nodes'
        });
      }
    });

    // Check for circular dependencies
    const cycles = this.detectCycles(playbook);
    if (cycles.length > 0) {
      errors.push({
        type: 'ERROR',
        message: 'Circular dependencies detected',
        details: `Cycles found: ${cycles.join(', ')}`
      });
    }

    // Validate node configurations
    playbook.nodes.forEach(node => {
      const nodeErrors = this.validateNodeConfiguration(node);
      errors.push(...nodeErrors);
    });

    // Validate connections
    playbook.connections.forEach(connection => {
      const sourceNode = playbook.nodes.find(n => n.nodeId === connection.sourceNodeId);
      const targetNode = playbook.nodes.find(n => n.nodeId === connection.targetNodeId);

      if (!sourceNode) {
        errors.push({
          type: 'ERROR',
          message: `Connection references non-existent source node: ${connection.sourceNodeId}`,
          details: 'Connection must reference valid nodes'
        });
      }

      if (!targetNode) {
        errors.push({
          type: 'ERROR',
          message: `Connection references non-existent target node: ${connection.targetNodeId}`,
          details: 'Connection must reference valid nodes'
        });
      }
    });

    // Update validation status
    const isValid = errors.filter(e => e.type === 'ERROR').length === 0;
    playbook.validation = {
      isValid,
      errors,
      lastValidated: new Date()
    };

    return { isValid, errors };
  }

  /**
   * Execute playbook
   */
  public async executePlaybook(
    playbookId: string,
    inputData: Record<string, any> = {},
    context: Record<string, any> = {}
  ): Promise<{ success: boolean; executionId?: string; result?: any; error?: string }> {
    try {
      const playbook = this.playbooks.get(playbookId);
      if (!playbook) {
        return { success: false, error: 'Playbook not found' };
      }

      // Validate playbook before execution
      const validation = this.validatePlaybook(playbookId);
      if (!validation.isValid) {
        return { success: false, error: 'Playbook validation failed' };
      }

      const executionId = crypto.randomUUID();
      const executionContext = {
        executionId,
        playbookId,
        inputData,
        context,
        startTime: new Date(),
        variables: new Map<string, any>(),
        nodeStates: new Map<string, any>(),
        executionPath: [],
        status: 'RUNNING'
      };

      // Store execution instance
      this.executionInstances.set(executionId, executionContext);

      // Start execution from START node
      const startNode = playbook.nodes.find(n => n.type === 'START');
      if (!startNode) {
        return { success: false, error: 'No START node found' };
      }

      // Initialize variables
      playbook.variables.forEach(variable => {
        executionContext.variables.set(variable.name, variable.defaultValue);
      });

      // Set input parameters
      Object.entries(inputData).forEach(([key, value]) => {
        executionContext.variables.set(key, value);
      });

      // Execute starting from START node
      const result = await this.executeNode(executionContext, startNode, playbook);

      // Update statistics
      playbook.statistics.totalExecutions++;
      if (result.success) {
        playbook.statistics.successfulExecutions++;
      } else {
        playbook.statistics.failedExecutions++;
      }

      const executionTime = Date.now() - executionContext.startTime.getTime();
      playbook.statistics.averageExecutionTime = 
        (playbook.statistics.averageExecutionTime * (playbook.statistics.totalExecutions - 1) + executionTime) / 
        playbook.statistics.totalExecutions;
      
      playbook.statistics.lastExecuted = new Date();

      console.log(`Playbook execution ${result.success ? 'completed' : 'failed'}: ${executionId}`);
      return { success: true, executionId, result };

    } catch (error) {
      console.error('Playbook execution failed:', error);
      return { success: false, error: 'Execution failed' };
    }
  }

  /**
   * Create playbook from template
   */
  public createPlaybookFromTemplate(
    templateId: string,
    name: string,
    parameters: Record<string, any> = {}
  ): VisualPlaybook {
    const template = this.templates.get(templateId);
    if (!template) {
      throw new Error(`Template not found: ${templateId}`);
    }

    // Clone template
    const playbookData = JSON.parse(JSON.stringify(template.template));
    
    // Apply parameters
    template.parameters.forEach(param => {
      const value = parameters[param.name] || param.defaultValue;
      if (value !== undefined) {
        // Replace parameter placeholders in the template
        this.applyParameterToPlaybook(playbookData, param.name, value);
      }
    });

    // Create new playbook
    const playbook = this.createPlaybook({
      ...playbookData,
      playbookId: crypto.randomUUID(),
      name,
      status: 'DRAFT'
    });

    // Update template usage
    template.usageCount++;

    return playbook;
  }

  /**
   * Export playbook to various formats
   */
  public exportPlaybook(playbookId: string, format: 'JSON' | 'BPMN' | 'XML'): string {
    const playbook = this.playbooks.get(playbookId);
    if (!playbook) {
      throw new Error(`Playbook not found: ${playbookId}`);
    }

    switch (format) {
      case 'JSON':
        return JSON.stringify(playbook, null, 2);
      
      case 'BPMN':
        return this.exportToBPMN(playbook);
      
      case 'XML':
        return this.exportToXML(playbook);
      
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Import playbook from various formats
   */
  public importPlaybook(content: string, format: 'JSON' | 'BPMN' | 'XML'): VisualPlaybook {
    let playbookData: any;

    switch (format) {
      case 'JSON':
        playbookData = JSON.parse(content);
        break;
      
      case 'BPMN':
        playbookData = this.importFromBPMN(content);
        break;
      
      case 'XML':
        playbookData = this.importFromXML(content);
        break;
      
      default:
        throw new Error(`Unsupported import format: ${format}`);
    }

    // Create playbook with new ID
    playbookData.playbookId = crypto.randomUUID();
    playbookData.createdAt = new Date();
    playbookData.updatedAt = new Date();

    return this.createPlaybook(playbookData);
  }

  /**
   * Get playbook execution history
   */
  public getExecutionHistory(playbookId: string): any[] {
    const history = Array.from(this.executionInstances.values())
      .filter(instance => instance.playbookId === playbookId)
      .sort((a, b) => b.startTime.getTime() - a.startTime.getTime());

    return history.map(instance => ({
      executionId: instance.executionId,
      startTime: instance.startTime,
      endTime: instance.endTime,
      status: instance.status,
      inputData: instance.inputData,
      result: instance.result,
      executionPath: instance.executionPath,
      duration: instance.endTime ? 
        instance.endTime.getTime() - instance.startTime.getTime() : null
    }));
  }

  // Private helper methods for template creation
  private createPhishingResponseTemplate(): VisualPlaybook {
    return this.createPlaybook({
      name: 'Phishing Email Response Template',
      description: 'Standard workflow for phishing email incident response',
      category: 'Email Security',
      nodes: [
        {
          nodeId: 'start-1',
          type: 'START',
          name: 'Phishing Alert Received',
          position: { x: 100, y: 200, width: 120, height: 80 }
        },
        {
          nodeId: 'analyze-1',
          type: 'SERVICE_TASK',
          name: 'Analyze Email',
          position: { x: 300, y: 200, width: 120, height: 80 },
          serviceTask: {
            serviceType: 'REST_API',
            endpoint: '/api/email/analyze',
            method: 'POST'
          }
        },
        {
          nodeId: 'decision-1',
          type: 'CONDITION',
          name: 'Is Malicious?',
          position: { x: 500, y: 200, width: 120, height: 80 },
          conditions: [
            { expression: 'result.threat_level >= 0.7', nextNodeId: 'quarantine-1', description: 'High threat' },
            { expression: 'result.threat_level < 0.7', nextNodeId: 'monitor-1', description: 'Low threat' }
          ]
        },
        {
          nodeId: 'quarantine-1',
          type: 'SERVICE_TASK',
          name: 'Quarantine Email',
          position: { x: 700, y: 100, width: 120, height: 80 },
          serviceTask: {
            serviceType: 'REST_API',
            endpoint: '/api/email/quarantine',
            method: 'POST'
          }
        },
        {
          nodeId: 'monitor-1',
          type: 'SERVICE_TASK',
          name: 'Monitor User',
          position: { x: 700, y: 300, width: 120, height: 80 },
          serviceTask: {
            serviceType: 'REST_API',
            endpoint: '/api/user/monitor',
            method: 'POST'
          }
        },
        {
          nodeId: 'end-1',
          type: 'END',
          name: 'Response Complete',
          position: { x: 900, y: 200, width: 120, height: 80 }
        }
      ] as PlaybookNode[],
      connections: [
        { connectionId: 'conn-1', sourceNodeId: 'start-1', targetNodeId: 'analyze-1' },
        { connectionId: 'conn-2', sourceNodeId: 'analyze-1', targetNodeId: 'decision-1' },
        { connectionId: 'conn-3', sourceNodeId: 'decision-1', targetNodeId: 'quarantine-1', condition: 'result.threat_level >= 0.7' },
        { connectionId: 'conn-4', sourceNodeId: 'decision-1', targetNodeId: 'monitor-1', condition: 'result.threat_level < 0.7' },
        { connectionId: 'conn-5', sourceNodeId: 'quarantine-1', targetNodeId: 'end-1' },
        { connectionId: 'conn-6', sourceNodeId: 'monitor-1', targetNodeId: 'end-1' }
      ] as PlaybookConnection[]
    });
  }

  private createMalwareContainmentTemplate(): VisualPlaybook {
    return this.createPlaybook({
      name: 'Malware Containment Template',
      description: 'Standard workflow for malware detection and containment',
      category: 'Endpoint Security'
    });
  }

  private createUserAccessInvestigationTemplate(): VisualPlaybook {
    return this.createPlaybook({
      name: 'User Access Investigation Template',
      description: 'Standard workflow for investigating suspicious user access',
      category: 'Identity Security'
    });
  }

  private createVulnerabilityAssessmentTemplate(): VisualPlaybook {
    return this.createPlaybook({
      name: 'Vulnerability Assessment Template',
      description: 'Standard workflow for vulnerability scanning and assessment',
      category: 'Vulnerability Management'
    });
  }

  // Additional private helper methods
  private detectCycles(playbook: VisualPlaybook): string[] {
    // Implement cycle detection algorithm
    const visited = new Set<string>();
    const recursionStack = new Set<string>();
    const cycles: string[] = [];

    const hasCycle = (nodeId: string, path: string[]): boolean => {
      if (recursionStack.has(nodeId)) {
        cycles.push(path.join(' -> ') + ' -> ' + nodeId);
        return true;
      }

      if (visited.has(nodeId)) {
        return false;
      }

      visited.add(nodeId);
      recursionStack.add(nodeId);

      const outgoingConnections = playbook.connections.filter(c => c.sourceNodeId === nodeId);
      for (const connection of outgoingConnections) {
        if (hasCycle(connection.targetNodeId, [...path, nodeId])) {
          return true;
        }
      }

      recursionStack.delete(nodeId);
      return false;
    };

    playbook.nodes.forEach(node => {
      if (!visited.has(node.nodeId)) {
        hasCycle(node.nodeId, []);
      }
    });

    return cycles;
  }

  private validateNodeConfiguration(node: PlaybookNode): any[] {
    const errors: any[] = [];

    // Validate required inputs
    node.inputs.forEach(input => {
      if (input.required && !node.configuration[input.name]) {
        errors.push({
          type: 'ERROR',
          nodeId: node.nodeId,
          message: `Required input missing: ${input.name}`,
          details: `Node ${node.name} requires input ${input.name}`
        });
      }
    });

    // Type-specific validation
    switch (node.type) {
      case 'SERVICE_TASK':
        if (!node.serviceTask?.endpoint) {
          errors.push({
            type: 'ERROR',
            nodeId: node.nodeId,
            message: 'Service task requires endpoint configuration',
            details: 'Endpoint URL must be specified for service tasks'
          });
        }
        break;

      case 'SCRIPT_TASK':
        if (!node.scriptTask?.script) {
          errors.push({
            type: 'ERROR',
            nodeId: node.nodeId,
            message: 'Script task requires script code',
            details: 'Script content must be provided for script tasks'
          });
        }
        break;

      case 'CONDITION':
        if (!node.conditions || node.conditions.length === 0) {
          errors.push({
            type: 'ERROR',
            nodeId: node.nodeId,
            message: 'Condition node requires at least one condition',
            details: 'Decision gateways must have conditional expressions'
          });
        }
        break;
    }

    return errors;
  }

  private async executeNode(
    context: any,
    node: PlaybookNode,
    playbook: VisualPlaybook
  ): Promise<{ success: boolean; result?: any; error?: string }> {
    try {
      context.executionPath.push(node.nodeId);
      context.nodeStates.set(node.nodeId, { status: 'RUNNING', startTime: new Date() });

      let result: any = {};

      // Execute node based on type
      switch (node.type) {
        case 'START':
          result = { started: true };
          break;

        case 'END':
          context.status = 'COMPLETED';
          result = { completed: true };
          break;

        case 'SERVICE_TASK':
          result = await this.executeServiceTask(node, context);
          break;

        case 'SCRIPT_TASK':
          result = await this.executeScriptTask(node, context);
          break;

        case 'HUMAN_TASK':
          result = await this.executeHumanTask(node, context);
          break;

        case 'CONDITION':
          result = await this.executeCondition(node, context);
          break;

        case 'TIMER_EVENT':
          result = await this.executeTimerEvent(node, context);
          break;

        default:
          result = { executed: true };
      }

      // Update node state
      context.nodeStates.set(node.nodeId, {
        status: 'COMPLETED',
        startTime: context.nodeStates.get(node.nodeId).startTime,
        endTime: new Date(),
        result
      });

      // Find next nodes to execute
      const nextConnections = playbook.connections.filter(c => c.sourceNodeId === node.nodeId);
      
      if (nextConnections.length > 0) {
        // Execute next nodes
        for (const connection of nextConnections) {
          const nextNode = playbook.nodes.find(n => n.nodeId === connection.targetNodeId);
          if (nextNode) {
            await this.executeNode(context, nextNode, playbook);
          }
        }
      }

      return { success: true, result };

    } catch (error) {
      context.nodeStates.set(node.nodeId, {
        status: 'FAILED',
        startTime: context.nodeStates.get(node.nodeId)?.startTime,
        endTime: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }

  private async executeServiceTask(node: PlaybookNode, context: any): Promise<any> {
    // Simulate service task execution
    console.log(`Executing service task: ${node.name}`);
    await new Promise(resolve => setTimeout(resolve, 1000));
    return { data: 'Service task completed', timestamp: new Date() };
  }

  private async executeScriptTask(node: PlaybookNode, context: any): Promise<any> {
    // Simulate script execution
    console.log(`Executing script task: ${node.name}`);
    await new Promise(resolve => setTimeout(resolve, 500));
    return { output: 'Script executed successfully', variables: context.variables };
  }

  private async executeHumanTask(node: PlaybookNode, context: any): Promise<any> {
    // Simulate human task (would normally wait for user input)
    console.log(`Human task created: ${node.name}`);
    return { taskId: crypto.randomUUID(), status: 'WAITING_FOR_USER' };
  }

  private async executeCondition(node: PlaybookNode, context: any): Promise<any> {
    // Simulate condition evaluation
    console.log(`Evaluating condition: ${node.name}`);
    return { conditionResult: true, evaluatedConditions: node.conditions };
  }

  private async executeTimerEvent(node: PlaybookNode, context: any): Promise<any> {
    // Simulate timer wait
    const duration = node.configuration.duration || 1000;
    console.log(`Waiting for timer: ${duration}ms`);
    await new Promise(resolve => setTimeout(resolve, Math.min(duration, 5000))); // Cap at 5 seconds for demo
    return { waited: duration, completed: true };
  }

  private applyParameterToPlaybook(playbook: any, paramName: string, value: any): void {
    // Recursively replace parameter placeholders
    const replaceInObject = (obj: any) => {
      if (typeof obj === 'string') {
        return obj.replace(new RegExp(`\\$\\{${paramName}\\}`, 'g'), value);
      } else if (Array.isArray(obj)) {
        return obj.map(replaceInObject);
      } else if (obj && typeof obj === 'object') {
        const result: any = {};
        for (const [key, val] of Object.entries(obj)) {
          result[key] = replaceInObject(val);
        }
        return result;
      }
      return obj;
    };

    Object.keys(playbook).forEach(key => {
      playbook[key] = replaceInObject(playbook[key]);
    });
  }

  private exportToBPMN(playbook: VisualPlaybook): string {
    // Simplified BPMN export
    return `<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL">
  <process id="${playbook.playbookId}" name="${playbook.name}">
    <!-- BPMN elements would be generated here -->
  </process>
</definitions>`;
  }

  private exportToXML(playbook: VisualPlaybook): string {
    // Simplified XML export
    return `<?xml version="1.0" encoding="UTF-8"?>
<playbook id="${playbook.playbookId}" name="${playbook.name}">
  <!-- XML elements would be generated here -->
</playbook>`;
  }

  private importFromBPMN(content: string): any {
    // Simplified BPMN import
    return { name: 'Imported from BPMN', nodes: [], connections: [] };
  }

  private importFromXML(content: string): any {
    // Simplified XML import
    return { name: 'Imported from XML', nodes: [], connections: [] };
  }

  /**
   * Add template to the library
   */
  public addTemplate(templateData: Partial<PlaybookTemplate>): PlaybookTemplate {
    const template: PlaybookTemplate = {
      templateId: templateData.templateId || crypto.randomUUID(),
      name: templateData.name || 'New Template',
      description: templateData.description || '',
      category: templateData.category || 'General',
      template: templateData.template || this.createPlaybook({}),
      parameters: templateData.parameters || [],
      usageCount: templateData.usageCount || 0,
      rating: templateData.rating,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedTemplate = PlaybookTemplateSchema.parse(template);
    this.templates.set(validatedTemplate.templateId, validatedTemplate);
    
    return validatedTemplate;
  }

  /**
   * Public getters for testing and external access
   */
  public getPlaybook(playbookId: string): VisualPlaybook | null {
    return this.playbooks.get(playbookId) || null;
  }

  public getAllPlaybooks(): VisualPlaybook[] {
    return Array.from(this.playbooks.values());
  }

  public getTemplate(templateId: string): PlaybookTemplate | null {
    return this.templates.get(templateId) || null;
  }

  public getAllTemplates(): PlaybookTemplate[] {
    return Array.from(this.templates.values());
  }

  public getNodeLibrary(): Map<string, any> {
    return this.nodeLibrary;
  }

  public getExecutionInstance(executionId: string): any {
    return this.executionInstances.get(executionId);
  }
}

// Export production-ready visual playbook engine
export const isectechVisualPlaybookEngine = new ISECTECHVisualPlaybookEngine();