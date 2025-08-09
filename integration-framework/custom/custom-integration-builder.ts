/**
 * Production-grade Custom Integration Builder for iSECTECH
 * 
 * Provides comprehensive tooling for users to create, configure, and manage
 * custom integrations with third-party tools not covered by pre-built connectors.
 * Includes APIs, SDKs, visual configuration interfaces, and security validation.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import { isectechIntegrationFramework, IntegrationConfig } from '../core/integration-architecture';

// Custom Integration Schemas
export const CustomIntegrationSchema = z.object({
  customIntegrationId: z.string(),
  name: z.string(),
  description: z.string(),
  tenantId: z.string(),
  createdBy: z.string(),
  
  // Integration configuration
  configuration: z.object({
    // Basic connection settings
    connectionType: z.enum(['API_CLIENT', 'WEBHOOK', 'BIDIRECTIONAL', 'FILE_BASED', 'DATABASE']),
    baseUrl: z.string().url().optional(),
    endpoints: z.record(z.string()).optional(),
    
    // Authentication configuration
    authentication: z.object({
      type: z.enum(['API_KEY', 'OAUTH2', 'JWT', 'BASIC_AUTH', 'MTLS', 'CUSTOM']),
      customAuthLogic: z.string().optional(), // JavaScript code for custom auth
      config: z.record(z.any()),
      testEndpoint: z.string().url().optional()
    }),
    
    // Data mapping configuration
    dataMapping: z.object({
      inputSchema: z.any(), // JSON Schema for input data
      outputSchema: z.any(), // JSON Schema for output data
      transformationRules: z.array(z.object({
        sourceField: z.string(),
        targetField: z.string(),
        transformation: z.string(), // JavaScript transformation function
        required: z.boolean().default(false),
        defaultValue: z.any().optional()
      })),
      customTransformations: z.string().optional() // JavaScript code for complex transformations
    }),
    
    // Validation rules
    validation: z.object({
      inputValidation: z.string().optional(), // JavaScript validation code
      outputValidation: z.string().optional(),
      requiredFields: z.array(z.string()).default([]),
      customRules: z.array(z.object({
        name: z.string(),
        rule: z.string(), // JavaScript validation rule
        errorMessage: z.string()
      })).default([])
    }),
    
    // Error handling configuration
    errorHandling: z.object({
      retryPolicy: z.object({
        maxRetries: z.number().default(3),
        retryDelay: z.number().default(1000),
        backoffStrategy: z.enum(['LINEAR', 'EXPONENTIAL', 'FIXED']).default('EXPONENTIAL')
      }),
      errorTransformation: z.string().optional(), // JavaScript error handling code
      fallbackAction: z.enum(['IGNORE', 'LOG', 'ALERT', 'CUSTOM']).default('LOG'),
      customErrorHandler: z.string().optional()
    }),
    
    // Scheduling and triggers
    scheduling: z.object({
      enabled: z.boolean().default(false),
      type: z.enum(['INTERVAL', 'CRON', 'WEBHOOK', 'EVENT_DRIVEN']).default('INTERVAL'),
      schedule: z.string().optional(), // Cron expression or interval
      timezone: z.string().default('UTC'),
      maxConcurrentExecutions: z.number().default(1)
    })
  }),
  
  // Testing configuration
  testing: z.object({
    testCases: z.array(z.object({
      testId: z.string(),
      name: z.string(),
      description: z.string(),
      inputData: z.any(),
      expectedOutput: z.any(),
      enabled: z.boolean().default(true)
    })).default([]),
    mockData: z.object({
      enabled: z.boolean().default(false),
      mockResponses: z.record(z.any()).optional()
    })
  }),
  
  // Security settings
  security: z.object({
    allowedIPs: z.array(z.string()).optional(),
    encryptData: z.boolean().default(true),
    sanitizeInput: z.boolean().default(true),
    validateCertificates: z.boolean().default(true),
    auditLogging: z.boolean().default(true),
    accessControl: z.object({
      requiredRoles: z.array(z.string()).default([]),
      requiredPermissions: z.array(z.string()).default([])
    })
  }),
  
  // Monitoring and alerting
  monitoring: z.object({
    healthCheck: z.object({
      enabled: z.boolean().default(true),
      endpoint: z.string().optional(),
      interval: z.number().default(300000), // 5 minutes
      timeout: z.number().default(30000)
    }),
    metrics: z.object({
      enabled: z.boolean().default(true),
      customMetrics: z.array(z.object({
        name: z.string(),
        type: z.enum(['COUNTER', 'GAUGE', 'HISTOGRAM']),
        description: z.string(),
        extractionLogic: z.string() // JavaScript code to extract metric value
      })).default([])
    }),
    alerting: z.object({
      enabled: z.boolean().default(true),
      thresholds: z.object({
        errorRate: z.number().default(0.1),
        responseTime: z.number().default(10000),
        failureCount: z.number().default(5)
      }),
      notificationChannels: z.array(z.string()).default(['EMAIL'])
    })
  }),
  
  // Deployment configuration
  deployment: z.object({
    environment: z.enum(['DEVELOPMENT', 'STAGING', 'PRODUCTION']).default('DEVELOPMENT'),
    resourceLimits: z.object({
      maxMemory: z.number().default(512), // MB
      maxCpu: z.number().default(1000), // millicores
      maxExecutionTime: z.number().default(300000) // milliseconds
    }),
    scaling: z.object({
      enabled: z.boolean().default(false),
      minInstances: z.number().default(1),
      maxInstances: z.number().default(5),
      targetCpuUtilization: z.number().default(70)
    })
  }),
  
  // Version control
  version: z.string().default('1.0.0'),
  changelog: z.array(z.object({
    version: z.string(),
    date: z.date(),
    changes: z.array(z.string()),
    author: z.string()
  })).default([]),
  
  // Status and lifecycle
  status: z.enum(['DRAFT', 'TESTING', 'ACTIVE', 'DEPRECATED', 'DISABLED']).default('DRAFT'),
  lastTested: z.date().optional(),
  lastDeployed: z.date().optional(),
  
  // Metadata
  tags: z.array(z.string()).default([]),
  documentation: z.string().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const IntegrationTemplateSchema = z.object({
  templateId: z.string(),
  name: z.string(),
  description: z.string(),
  category: z.string(),
  
  // Template configuration
  template: z.object({
    baseConfiguration: z.any(), // Base CustomIntegrationSchema configuration
    requiredFields: z.array(z.string()),
    optionalFields: z.array(z.string()),
    defaultValues: z.record(z.any()),
    
    // Template-specific settings
    variables: z.array(z.object({
      name: z.string(),
      type: z.enum(['STRING', 'NUMBER', 'BOOLEAN', 'OBJECT', 'ARRAY']),
      description: z.string(),
      required: z.boolean().default(false),
      defaultValue: z.any().optional(),
      validation: z.string().optional() // JavaScript validation code
    }))
  }),
  
  // Documentation and examples
  documentation: z.object({
    overview: z.string(),
    setupInstructions: z.string(),
    examples: z.array(z.object({
      name: z.string(),
      description: z.string(),
      configuration: z.any(),
      expectedBehavior: z.string()
    }))
  }),
  
  // Template metadata
  author: z.string(),
  version: z.string(),
  tags: z.array(z.string()).default([]),
  isPublic: z.boolean().default(false),
  downloadCount: z.number().default(0),
  rating: z.number().default(0),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const IntegrationExecutionResultSchema = z.object({
  executionId: z.string(),
  customIntegrationId: z.string(),
  tenantId: z.string(),
  
  // Execution details
  startTime: z.date(),
  endTime: z.date().optional(),
  duration: z.number().optional(), // milliseconds
  status: z.enum(['RUNNING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED']),
  
  // Input/Output data
  inputData: z.any(),
  outputData: z.any().optional(),
  transformedData: z.any().optional(),
  
  // Execution metrics
  metrics: z.object({
    recordsProcessed: z.number().default(0),
    recordsSuccessful: z.number().default(0),
    recordsFailed: z.number().default(0),
    bytesProcessed: z.number().default(0),
    apiCallsMade: z.number().default(0)
  }),
  
  // Error information
  errors: z.array(z.object({
    timestamp: z.date(),
    level: z.enum(['WARNING', 'ERROR', 'CRITICAL']),
    message: z.string(),
    details: z.any().optional(),
    stackTrace: z.string().optional()
  })).default([]),
  
  // Debug information
  debugInfo: z.object({
    enabled: z.boolean().default(false),
    logs: z.array(z.object({
      timestamp: z.date(),
      level: z.enum(['DEBUG', 'INFO', 'WARN', 'ERROR']),
      message: z.string(),
      context: z.any().optional()
    })).default([]),
    performance: z.object({
      authTime: z.number().optional(),
      transformationTime: z.number().optional(),
      validationTime: z.number().optional(),
      networkTime: z.number().optional()
    }).optional()
  })
});

export type CustomIntegration = z.infer<typeof CustomIntegrationSchema>;
export type IntegrationTemplate = z.infer<typeof IntegrationTemplateSchema>;
export type IntegrationExecutionResult = z.infer<typeof IntegrationExecutionResultSchema>;

/**
 * Custom Integration Builder
 */
export class ISECTECHCustomIntegrationBuilder {
  private customIntegrations: Map<string, CustomIntegration> = new Map();
  private templates: Map<string, IntegrationTemplate> = new Map();
  private executionResults: Map<string, IntegrationExecutionResult> = new Map();
  private executionQueue: Array<{ integrationId: string; inputData: any; tenantId: string }> = [];

  constructor() {
    this.initializeTemplates();
    this.startExecutionEngine();
    this.startMaintenanceTasks();
  }

  /**
   * Initialize common integration templates
   */
  private initializeTemplates(): void {
    const templates: Partial<IntegrationTemplate>[] = [
      {
        templateId: 'rest-api-template',
        name: 'REST API Integration Template',
        description: 'Template for integrating with REST APIs',
        category: 'API',
        template: {
          baseConfiguration: {
            connectionType: 'API_CLIENT',
            authentication: {
              type: 'API_KEY',
              config: {
                apiKey: '${API_KEY}',
                headerName: 'Authorization'
              }
            },
            dataMapping: {
              transformationRules: [],
              customTransformations: ''
            }
          },
          requiredFields: ['baseUrl', 'authentication.config.apiKey'],
          optionalFields: ['endpoints', 'dataMapping.transformationRules'],
          defaultValues: {
            'configuration.errorHandling.retryPolicy.maxRetries': 3,
            'configuration.scheduling.type': 'INTERVAL'
          },
          variables: [
            {
              name: 'baseUrl',
              type: 'STRING',
              description: 'Base URL of the API endpoint',
              required: true
            },
            {
              name: 'apiKey',
              type: 'STRING',
              description: 'API key for authentication',
              required: true
            },
            {
              name: 'pollInterval',
              type: 'NUMBER',
              description: 'Polling interval in milliseconds',
              required: false,
              defaultValue: 300000
            }
          ]
        },
        documentation: {
          overview: 'This template provides a foundation for integrating with REST APIs. It includes authentication, data transformation, and error handling capabilities.',
          setupInstructions: '1. Configure the base URL\n2. Set up authentication credentials\n3. Define data mapping rules\n4. Test the integration',
          examples: [
            {
              name: 'Simple API Integration',
              description: 'Basic REST API integration with API key authentication',
              configuration: {
                baseUrl: 'https://api.example.com',
                authentication: {
                  type: 'API_KEY',
                  config: {
                    apiKey: 'your-api-key-here'
                  }
                }
              },
              expectedBehavior: 'Retrieves data from the API and processes it according to configured rules'
            }
          ]
        },
        author: 'iSECTECH Team',
        version: '1.0.0',
        tags: ['api', 'rest', 'template'],
        isPublic: true
      },
      {
        templateId: 'webhook-receiver-template',
        name: 'Webhook Receiver Template',
        description: 'Template for receiving webhook notifications',
        category: 'WEBHOOK',
        template: {
          baseConfiguration: {
            connectionType: 'WEBHOOK',
            authentication: {
              type: 'CUSTOM',
              config: {
                signatureHeader: 'X-Signature',
                secret: '${WEBHOOK_SECRET}'
              }
            },
            dataMapping: {
              transformationRules: [],
              customTransformations: 'function transform(data) { return data; }'
            }
          },
          requiredFields: ['authentication.config.secret'],
          optionalFields: ['dataMapping.transformationRules'],
          variables: [
            {
              name: 'webhookSecret',
              type: 'STRING',
              description: 'Secret key for webhook signature validation',
              required: true
            },
            {
              name: 'signatureHeader',
              type: 'STRING',
              description: 'Header name containing the webhook signature',
              required: false,
              defaultValue: 'X-Signature'
            }
          ]
        }
      },
      {
        templateId: 'database-integration-template',
        name: 'Database Integration Template',
        description: 'Template for database-based integrations',
        category: 'DATABASE',
        template: {
          baseConfiguration: {
            connectionType: 'DATABASE',
            authentication: {
              type: 'BASIC_AUTH',
              config: {
                host: '${DB_HOST}',
                port: '${DB_PORT}',
                database: '${DB_NAME}',
                username: '${DB_USERNAME}',
                password: '${DB_PASSWORD}'
              }
            },
            scheduling: {
              enabled: true,
              type: 'INTERVAL',
              schedule: '300000' // 5 minutes
            }
          },
          requiredFields: [
            'authentication.config.host',
            'authentication.config.database',
            'authentication.config.username',
            'authentication.config.password'
          ],
          variables: [
            {
              name: 'dbHost',
              type: 'STRING',
              description: 'Database host address',
              required: true
            },
            {
              name: 'dbPort',
              type: 'NUMBER',
              description: 'Database port number',
              required: false,
              defaultValue: 5432
            },
            {
              name: 'dbName',
              type: 'STRING',
              description: 'Database name',
              required: true
            }
          ]
        }
      }
    ];

    templates.forEach(template => {
      const fullTemplate = this.createFullTemplate(template);
      this.templates.set(fullTemplate.templateId, fullTemplate);
    });

    console.log(`Initialized ${templates.length} integration templates`);
  }

  /**
   * Create a custom integration from template
   */
  public async createFromTemplate(
    templateId: string,
    name: string,
    tenantId: string,
    createdBy: string,
    variables: Record<string, any>
  ): Promise<{ success: boolean; integration?: CustomIntegration; error?: string }> {
    try {
      const template = this.templates.get(templateId);
      if (!template) {
        return { success: false, error: 'Template not found' };
      }

      // Validate required variables
      const missingVariables = template.template.variables
        .filter(variable => variable.required && !variables[variable.name])
        .map(variable => variable.name);

      if (missingVariables.length > 0) {
        return { 
          success: false, 
          error: `Missing required variables: ${missingVariables.join(', ')}` 
        };
      }

      // Create integration configuration
      const customIntegrationId = crypto.randomUUID();
      const baseConfig = template.template.baseConfiguration;
      
      // Substitute variables in configuration
      const configuration = this.substituteVariables(baseConfig, variables);

      const customIntegration: CustomIntegration = {
        customIntegrationId,
        name,
        description: `Custom integration created from ${template.name}`,
        tenantId,
        createdBy,
        configuration,
        testing: {
          testCases: [],
          mockData: { enabled: false }
        },
        security: {
          encryptData: true,
          sanitizeInput: true,
          validateCertificates: true,
          auditLogging: true,
          accessControl: {
            requiredRoles: [],
            requiredPermissions: []
          }
        },
        monitoring: {
          healthCheck: { enabled: true, interval: 300000, timeout: 30000 },
          metrics: { enabled: true, customMetrics: [] },
          alerting: {
            enabled: true,
            thresholds: {
              errorRate: 0.1,
              responseTime: 10000,
              failureCount: 5
            },
            notificationChannels: ['EMAIL']
          }
        },
        deployment: {
          environment: 'DEVELOPMENT',
          resourceLimits: {
            maxMemory: 512,
            maxCpu: 1000,
            maxExecutionTime: 300000
          },
          scaling: {
            enabled: false,
            minInstances: 1,
            maxInstances: 5,
            targetCpuUtilization: 70
          }
        },
        version: '1.0.0',
        changelog: [{
          version: '1.0.0',
          date: new Date(),
          changes: [`Created from template: ${template.name}`],
          author: createdBy
        }],
        status: 'DRAFT',
        tags: [...template.tags, 'custom'],
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const validatedIntegration = CustomIntegrationSchema.parse(customIntegration);
      this.customIntegrations.set(customIntegrationId, validatedIntegration);

      console.log(`Created custom integration: ${name} from template ${template.name}`);
      return { success: true, integration: validatedIntegration };

    } catch (error) {
      console.error('Failed to create integration from template:', error);
      return { success: false, error: 'Failed to create integration' };
    }
  }

  /**
   * Create a custom integration from scratch
   */
  public async createCustomIntegration(
    integrationData: Partial<CustomIntegration>
  ): Promise<{ success: boolean; integration?: CustomIntegration; error?: string }> {
    try {
      const customIntegrationId = crypto.randomUUID();
      
      const customIntegration: CustomIntegration = {
        customIntegrationId,
        name: integrationData.name || 'Untitled Integration',
        description: integrationData.description || '',
        tenantId: integrationData.tenantId || 'default',
        createdBy: integrationData.createdBy || 'unknown',
        
        configuration: {
          connectionType: 'API_CLIENT',
          authentication: {
            type: 'API_KEY',
            config: {},
            testEndpoint: undefined
          },
          dataMapping: {
            inputSchema: {},
            outputSchema: {},
            transformationRules: [],
            customTransformations: undefined
          },
          validation: {
            requiredFields: [],
            customRules: []
          },
          errorHandling: {
            retryPolicy: {
              maxRetries: 3,
              retryDelay: 1000,
              backoffStrategy: 'EXPONENTIAL'
            },
            fallbackAction: 'LOG'
          },
          scheduling: {
            enabled: false,
            type: 'INTERVAL',
            timezone: 'UTC',
            maxConcurrentExecutions: 1
          },
          ...integrationData.configuration
        },
        
        testing: {
          testCases: [],
          mockData: { enabled: false },
          ...integrationData.testing
        },
        
        security: {
          encryptData: true,
          sanitizeInput: true,
          validateCertificates: true,
          auditLogging: true,
          accessControl: {
            requiredRoles: [],
            requiredPermissions: []
          },
          ...integrationData.security
        },
        
        monitoring: {
          healthCheck: { enabled: true, interval: 300000, timeout: 30000 },
          metrics: { enabled: true, customMetrics: [] },
          alerting: {
            enabled: true,
            thresholds: {
              errorRate: 0.1,
              responseTime: 10000,
              failureCount: 5
            },
            notificationChannels: ['EMAIL']
          },
          ...integrationData.monitoring
        },
        
        deployment: {
          environment: 'DEVELOPMENT',
          resourceLimits: {
            maxMemory: 512,
            maxCpu: 1000,
            maxExecutionTime: 300000
          },
          scaling: {
            enabled: false,
            minInstances: 1,
            maxInstances: 5,
            targetCpuUtilization: 70
          },
          ...integrationData.deployment
        },
        
        version: integrationData.version || '1.0.0',
        changelog: integrationData.changelog || [{
          version: '1.0.0',
          date: new Date(),
          changes: ['Initial version'],
          author: integrationData.createdBy || 'unknown'
        }],
        status: integrationData.status || 'DRAFT',
        tags: integrationData.tags || ['custom'],
        documentation: integrationData.documentation,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const validatedIntegration = CustomIntegrationSchema.parse(customIntegration);
      this.customIntegrations.set(customIntegrationId, validatedIntegration);

      console.log(`Created custom integration: ${validatedIntegration.name}`);
      return { success: true, integration: validatedIntegration };

    } catch (error) {
      console.error('Failed to create custom integration:', error);
      return { success: false, error: 'Failed to create integration' };
    }
  }

  /**
   * Test custom integration
   */
  public async testIntegration(
    integrationId: string,
    testData?: any
  ): Promise<{ success: boolean; result?: IntegrationExecutionResult; error?: string }> {
    try {
      const integration = this.customIntegrations.get(integrationId);
      if (!integration) {
        return { success: false, error: 'Integration not found' };
      }

      const executionId = crypto.randomUUID();
      const startTime = new Date();

      const executionResult: IntegrationExecutionResult = {
        executionId,
        customIntegrationId: integrationId,
        tenantId: integration.tenantId,
        startTime,
        status: 'RUNNING',
        inputData: testData || {},
        metrics: {
          recordsProcessed: 0,
          recordsSuccessful: 0,
          recordsFailed: 0,
          bytesProcessed: 0,
          apiCallsMade: 0
        },
        errors: [],
        debugInfo: {
          enabled: true,
          logs: [],
          performance: {}
        }
      };

      this.executionResults.set(executionId, executionResult);

      // Simulate integration execution
      try {
        // Validate input data
        if (integration.configuration.validation.inputValidation) {
          const isValid = await this.executeValidation(
            integration.configuration.validation.inputValidation,
            testData
          );
          if (!isValid) {
            throw new Error('Input validation failed');
          }
        }

        // Execute data transformation
        let transformedData = testData;
        if (integration.configuration.dataMapping.customTransformations) {
          transformedData = await this.executeTransformation(
            integration.configuration.dataMapping.customTransformations,
            testData
          );
        }

        // Apply transformation rules
        if (integration.configuration.dataMapping.transformationRules.length > 0) {
          transformedData = this.applyTransformationRules(
            transformedData,
            integration.configuration.dataMapping.transformationRules
          );
        }

        // Validate output data
        if (integration.configuration.validation.outputValidation) {
          const isValid = await this.executeValidation(
            integration.configuration.validation.outputValidation,
            transformedData
          );
          if (!isValid) {
            throw new Error('Output validation failed');
          }
        }

        // Update execution result
        executionResult.endTime = new Date();
        executionResult.duration = executionResult.endTime.getTime() - startTime.getTime();
        executionResult.status = 'SUCCESS';
        executionResult.outputData = transformedData;
        executionResult.transformedData = transformedData;
        executionResult.metrics.recordsProcessed = 1;
        executionResult.metrics.recordsSuccessful = 1;

        // Update integration last tested
        integration.lastTested = new Date();
        integration.updatedAt = new Date();

        console.log(`Integration test completed successfully: ${integration.name}`);
        return { success: true, result: executionResult };

      } catch (error) {
        // Handle execution error
        executionResult.endTime = new Date();
        executionResult.duration = executionResult.endTime.getTime() - startTime.getTime();
        executionResult.status = 'FAILED';
        executionResult.errors.push({
          timestamp: new Date(),
          level: 'ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
          details: error,
          stackTrace: error instanceof Error ? error.stack : undefined
        });
        executionResult.metrics.recordsFailed = 1;

        console.error(`Integration test failed: ${integration.name}`, error);
        return { success: false, result: executionResult, error: 'Test execution failed' };
      }

    } catch (error) {
      console.error('Failed to test integration:', error);
      return { success: false, error: 'Failed to test integration' };
    }
  }

  /**
   * Deploy custom integration
   */
  public async deployIntegration(
    integrationId: string,
    environment: 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION'
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const integration = this.customIntegrations.get(integrationId);
      if (!integration) {
        return { success: false, error: 'Integration not found' };
      }

      if (integration.status !== 'TESTING' && environment === 'PRODUCTION') {
        return { success: false, error: 'Integration must be tested before production deployment' };
      }

      // Update deployment configuration
      integration.deployment.environment = environment;
      integration.status = 'ACTIVE';
      integration.lastDeployed = new Date();
      integration.updatedAt = new Date();

      // Register with integration framework
      const integrationConfig: IntegrationConfig = this.convertToIntegrationConfig(integration);
      isectechIntegrationFramework.registerIntegration(integrationConfig);

      console.log(`Deployed integration: ${integration.name} to ${environment}`);
      return { success: true };

    } catch (error) {
      console.error('Failed to deploy integration:', error);
      return { success: false, error: 'Failed to deploy integration' };
    }
  }

  /**
   * Get custom integration
   */
  public getCustomIntegration(integrationId: string): CustomIntegration | null {
    return this.customIntegrations.get(integrationId) || null;
  }

  /**
   * List custom integrations for tenant
   */
  public listCustomIntegrations(tenantId: string): CustomIntegration[] {
    return Array.from(this.customIntegrations.values())
      .filter(integration => integration.tenantId === tenantId);
  }

  /**
   * Get available templates
   */
  public getTemplates(): IntegrationTemplate[] {
    return Array.from(this.templates.values());
  }

  /**
   * Get template by ID
   */
  public getTemplate(templateId: string): IntegrationTemplate | null {
    return this.templates.get(templateId) || null;
  }

  /**
   * Update custom integration
   */
  public updateCustomIntegration(
    integrationId: string,
    updates: Partial<CustomIntegration>
  ): boolean {
    const integration = this.customIntegrations.get(integrationId);
    if (!integration) return false;

    // Update integration
    Object.assign(integration, updates);
    integration.updatedAt = new Date();

    // Update version if configuration changed
    if (updates.configuration) {
      const [major, minor, patch] = integration.version.split('.').map(Number);
      integration.version = `${major}.${minor}.${patch + 1}`;
      
      integration.changelog.push({
        version: integration.version,
        date: new Date(),
        changes: ['Configuration updated'],
        author: integration.createdBy
      });
    }

    this.customIntegrations.set(integrationId, integration);
    return true;
  }

  /**
   * Delete custom integration
   */
  public deleteCustomIntegration(integrationId: string): boolean {
    const integration = this.customIntegrations.get(integrationId);
    if (!integration) return false;

    // Remove from integration framework if deployed
    if (integration.status === 'ACTIVE') {
      // Would remove from integration framework
    }

    this.customIntegrations.delete(integrationId);
    console.log(`Deleted custom integration: ${integration.name}`);
    return true;
  }

  // Private helper methods
  private createFullTemplate(partial: Partial<IntegrationTemplate>): IntegrationTemplate {
    return IntegrationTemplateSchema.parse({
      templateId: partial.templateId || crypto.randomUUID(),
      name: partial.name || 'Untitled Template',
      description: partial.description || '',
      category: partial.category || 'OTHER',
      template: {
        baseConfiguration: {},
        requiredFields: [],
        optionalFields: [],
        defaultValues: {},
        variables: [],
        ...partial.template
      },
      documentation: {
        overview: '',
        setupInstructions: '',
        examples: [],
        ...partial.documentation
      },
      author: partial.author || 'Unknown',
      version: partial.version || '1.0.0',
      tags: partial.tags || [],
      isPublic: partial.isPublic || false,
      downloadCount: 0,
      rating: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    });
  }

  private substituteVariables(config: any, variables: Record<string, any>): any {
    const configStr = JSON.stringify(config);
    let substitutedStr = configStr;

    // Replace variable placeholders
    Object.entries(variables).forEach(([key, value]) => {
      const placeholder = `\${${key}}`;
      substitutedStr = substitutedStr.replace(new RegExp(placeholder, 'g'), String(value));
    });

    return JSON.parse(substitutedStr);
  }

  private async executeValidation(validationCode: string, data: any): Promise<boolean> {
    try {
      // In a real implementation, this would execute the validation code in a secure sandbox
      const validationFunction = new Function('data', validationCode);
      return validationFunction(data);
    } catch (error) {
      console.error('Validation execution failed:', error);
      return false;
    }
  }

  private async executeTransformation(transformationCode: string, data: any): Promise<any> {
    try {
      // In a real implementation, this would execute the transformation code in a secure sandbox
      const transformationFunction = new Function('data', `return (${transformationCode})(data);`);
      return transformationFunction(data);
    } catch (error) {
      console.error('Transformation execution failed:', error);
      throw error;
    }
  }

  private applyTransformationRules(data: any, rules: any[]): any {
    const result = { ...data };

    rules.forEach(rule => {
      try {
        const sourceValue = this.getNestedValue(data, rule.sourceField);
        
        if (sourceValue !== undefined || rule.required) {
          const transformedValue = rule.transformation 
            ? this.executeSimpleTransformation(rule.transformation, sourceValue)
            : sourceValue;
          
          this.setNestedValue(result, rule.targetField, transformedValue ?? rule.defaultValue);
        }
      } catch (error) {
        console.error(`Transformation rule failed for field ${rule.sourceField}:`, error);
      }
    });

    return result;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  private setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    const lastKey = keys.pop()!;
    const target = keys.reduce((current, key) => {
      if (!current[key]) current[key] = {};
      return current[key];
    }, obj);
    target[lastKey] = value;
  }

  private executeSimpleTransformation(transformation: string, value: any): any {
    try {
      // Simple transformation functions
      const transformations: Record<string, (val: any) => any> = {
        'toUpperCase': (val) => String(val).toUpperCase(),
        'toLowerCase': (val) => String(val).toLowerCase(),
        'toString': (val) => String(val),
        'toNumber': (val) => Number(val),
        'toDate': (val) => new Date(val),
        'trim': (val) => String(val).trim()
      };

      return transformations[transformation] ? transformations[transformation](value) : value;
    } catch (error) {
      console.error('Simple transformation failed:', error);
      return value;
    }
  }

  private convertToIntegrationConfig(customIntegration: CustomIntegration): IntegrationConfig {
    // Convert custom integration to standard integration config
    return {
      integrationId: customIntegration.customIntegrationId,
      name: customIntegration.name,
      description: customIntegration.description,
      category: 'CUSTOM',
      vendor: 'Custom',
      version: customIntegration.version,
      
      connection: {
        type: customIntegration.configuration.connectionType === 'API_CLIENT' ? 'API_CLIENT' : 
              customIntegration.configuration.connectionType === 'WEBHOOK' ? 'WEBHOOK' : 'BIDIRECTIONAL',
        baseUrl: customIntegration.configuration.baseUrl,
        endpoints: customIntegration.configuration.endpoints,
        timeout: 30000,
        retryAttempts: customIntegration.configuration.errorHandling.retryPolicy.maxRetries,
        retryDelay: customIntegration.configuration.errorHandling.retryPolicy.retryDelay
      },
      
      authentication: customIntegration.configuration.authentication,
      
      dataTransformation: {
        inbound: {
          normalizer: 'custom_normalizer',
          validator: 'custom_validator',
          enrichment: []
        },
        outbound: {
          formatter: 'custom_formatter',
          compression: false
        }
      },
      
      rateLimiting: {
        requestsPerSecond: 10,
        requestsPerMinute: 600,
        requestsPerHour: 36000,
        burstLimit: 50,
        backoffStrategy: 'EXPONENTIAL'
      },
      
      resilience: {
        circuitBreaker: {
          enabled: true,
          failureThreshold: 5,
          timeout: 60000,
          resetTimeout: 30000
        },
        healthCheck: {
          enabled: customIntegration.monitoring.healthCheck.enabled,
          interval: customIntegration.monitoring.healthCheck.interval,
          endpoint: customIntegration.monitoring.healthCheck.endpoint,
          method: 'GET'
        }
      },
      
      security: customIntegration.security,
      
      tenantConfig: {
        multiTenant: true,
        tenantIsolation: true,
        perTenantConfig: true,
        sharedCredentials: false
      },
      
      monitoring: {
        metricsEnabled: customIntegration.monitoring.metrics.enabled,
        tracingEnabled: true,
        alerting: {
          onFailure: customIntegration.monitoring.alerting.enabled,
          onHighLatency: customIntegration.monitoring.alerting.enabled,
          onRateLimit: customIntegration.monitoring.alerting.enabled,
          thresholds: {
            errorRate: customIntegration.monitoring.alerting.thresholds.errorRate,
            latency: customIntegration.monitoring.alerting.thresholds.responseTime,
            availability: 0.995
          }
        }
      },
      
      isActive: customIntegration.status === 'ACTIVE',
      isProduction: customIntegration.deployment.environment === 'PRODUCTION',
      createdAt: customIntegration.createdAt,
      updatedAt: customIntegration.updatedAt,
      tags: customIntegration.tags
    };
  }

  private startExecutionEngine(): void {
    // Process execution queue every 5 seconds
    setInterval(() => {
      if (this.executionQueue.length > 0) {
        const execution = this.executionQueue.shift();
        if (execution) {
          this.testIntegration(execution.integrationId, execution.inputData);
        }
      }
    }, 5000);
  }

  private startMaintenanceTasks(): void {
    // Clean up old execution results every hour
    setInterval(() => {
      const cutoffTime = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago

      for (const [executionId, result] of this.executionResults.entries()) {
        if (result.startTime < cutoffTime) {
          this.executionResults.delete(executionId);
        }
      }

      console.log('Custom integration maintenance completed');
    }, 60 * 60 * 1000); // Every hour
  }
}

// Export production-ready custom integration builder
export const isectechCustomIntegrationBuilder = new ISECTECHCustomIntegrationBuilder();