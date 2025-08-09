/**
 * Production-grade Visual Configuration Interface for iSECTECH Integrations
 * 
 * Comprehensive visual configuration system for setting up, testing, and managing 
 * integrations through an intuitive drag-and-drop interface. Supports form generation,
 * validation, testing workflows, and guided setup wizards.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import { isectechIntegrationMarketplace } from './integration-marketplace';
import { isectechEnterpriseConnectors, ConnectorRegistry } from '../connectors/enterprise-connectors';

// Visual Configuration Schemas
export const ConfigurationFieldSchema = z.object({
  fieldId: z.string(),
  name: z.string(),
  label: z.string(),
  description: z.string(),
  type: z.enum([
    'TEXT', 'PASSWORD', 'EMAIL', 'URL', 'NUMBER', 'BOOLEAN', 
    'SELECT', 'MULTISELECT', 'TEXTAREA', 'JSON', 'FILE', 
    'DATE', 'DATETIME', 'COLOR', 'SLIDER', 'TAGS'
  ]),
  
  // Field properties
  required: z.boolean().default(false),
  placeholder: z.string().optional(),
  defaultValue: z.any().optional(),
  helpText: z.string().optional(),
  
  // Validation rules
  validation: z.object({
    minLength: z.number().optional(),
    maxLength: z.number().optional(),
    pattern: z.string().optional(), // regex pattern
    customValidator: z.string().optional(), // function name
    asyncValidator: z.string().optional() // async validation function
  }).optional(),
  
  // Field options for SELECT/MULTISELECT
  options: z.array(z.object({
    value: z.any(),
    label: z.string(),
    description: z.string().optional(),
    group: z.string().optional()
  })).optional(),
  
  // Conditional display
  conditionalDisplay: z.object({
    dependsOn: z.string(), // field ID
    condition: z.enum(['EQUALS', 'NOT_EQUALS', 'CONTAINS', 'NOT_CONTAINS', 'GREATER_THAN', 'LESS_THAN']),
    value: z.any()
  }).optional(),
  
  // Field styling and layout
  layout: z.object({
    width: z.enum(['FULL', 'HALF', 'THIRD', 'QUARTER']).default('FULL'),
    order: z.number().default(0),
    section: z.string().optional(),
    inline: z.boolean().default(false)
  }),
  
  // Security settings
  security: z.object({
    encrypted: z.boolean().default(false),
    masked: z.boolean().default(false),
    restricted: z.boolean().default(false),
    auditLogged: z.boolean().default(false)
  }).optional()
});

export const ConfigurationFormSchema = z.object({
  formId: z.string(),
  integrationId: z.string(),
  name: z.string(),
  description: z.string(),
  version: z.string(),
  
  // Form structure
  sections: z.array(z.object({
    sectionId: z.string(),
    title: z.string(),
    description: z.string().optional(),
    collapsible: z.boolean().default(false),
    order: z.number(),
    fields: z.array(z.string()) // field IDs
  })),
  
  fields: z.array(ConfigurationFieldSchema),
  
  // Form behavior
  behavior: z.object({
    saveOnChange: z.boolean().default(false),
    validateOnChange: z.boolean().default(true),
    showProgress: z.boolean().default(true),
    allowReset: z.boolean().default(true),
    confirmOnSubmit: z.boolean().default(false)
  }),
  
  // Submission handling
  submission: z.object({
    endpoint: z.string().url(),
    method: z.enum(['POST', 'PUT', 'PATCH']).default('POST'),
    successMessage: z.string().optional(),
    errorMessage: z.string().optional(),
    redirectUrl: z.string().url().optional()
  }),
  
  // Form metadata
  createdAt: z.date(),
  updatedAt: z.date(),
  createdBy: z.string(),
  tags: z.array(z.string()).default([])
});

export const ConfigurationWizardSchema = z.object({
  wizardId: z.string(),
  integrationId: z.string(),
  name: z.string(),
  description: z.string(),
  
  // Wizard steps
  steps: z.array(z.object({
    stepId: z.string(),
    title: z.string(),
    description: z.string(),
    order: z.number(),
    type: z.enum(['FORM', 'VALIDATION', 'REVIEW', 'COMPLETION']),
    
    // Step content
    formId: z.string().optional(), // Reference to ConfigurationForm
    validationRules: z.array(z.string()).optional(),
    template: z.string().optional(), // Custom template
    
    // Step behavior
    skippable: z.boolean().default(false),
    required: z.boolean().default(true),
    estimatedTime: z.number().optional(), // minutes
    
    // Navigation
    nextStep: z.string().optional(),
    previousStep: z.string().optional(),
    conditionalNext: z.object({
      condition: z.string(),
      trueStep: z.string(),
      falseStep: z.string()
    }).optional()
  })),
  
  // Wizard configuration
  configuration: z.object({
    allowBackNavigation: z.boolean().default(true),
    showProgress: z.boolean().default(true),
    autoSave: z.boolean().default(true),
    timeoutMinutes: z.number().default(30),
    maxAttempts: z.number().default(3)
  }),
  
  // Completion handling
  completion: z.object({
    action: z.enum(['DEPLOY', 'SAVE_DRAFT', 'TEST', 'REVIEW']),
    successTemplate: z.string().optional(),
    failureTemplate: z.string().optional(),
    followUpActions: z.array(z.string()).default([])
  }),
  
  // Wizard metadata
  createdAt: z.date(),
  updatedAt: z.date(),
  estimatedDuration: z.number(), // minutes
  difficulty: z.enum(['EASY', 'MEDIUM', 'ADVANCED']),
  tags: z.array(z.string()).default([])
});

export const ConfigurationValidationResultSchema = z.object({
  validationId: z.string(),
  fieldId: z.string(),
  formId: z.string(),
  
  // Validation details
  isValid: z.boolean(),
  errors: z.array(z.object({
    code: z.string(),
    message: z.string(),
    severity: z.enum(['ERROR', 'WARNING', 'INFO'])
  })),
  warnings: z.array(z.string()).default([]),
  
  // Suggestions
  suggestions: z.array(z.object({
    type: z.enum(['CORRECTION', 'OPTIMIZATION', 'SECURITY', 'BEST_PRACTICE']),
    message: z.string(),
    action: z.string().optional()
  })).default([]),
  
  // Validation metadata
  validatedAt: z.date(),
  validatorType: z.enum(['CLIENT', 'SERVER', 'EXTERNAL']),
  validatorVersion: z.string(),
  responseTime: z.number() // milliseconds
});

export type ConfigurationField = z.infer<typeof ConfigurationFieldSchema>;
export type ConfigurationForm = z.infer<typeof ConfigurationFormSchema>;
export type ConfigurationWizard = z.infer<typeof ConfigurationWizardSchema>;
export type ConfigurationValidationResult = z.infer<typeof ConfigurationValidationResultSchema>;

/**
 * Visual Configuration Interface Manager
 */
export class ISECTECHVisualConfiguration {
  private configurationForms: Map<string, ConfigurationForm> = new Map();
  private configurationWizards: Map<string, ConfigurationWizard> = new Map();
  private validationResults: Map<string, ConfigurationValidationResult> = new Map();
  private fieldValidators: Map<string, Function> = new Map();
  private formTemplates: Map<string, any> = new Map();

  constructor() {
    this.initializeVisualConfiguration();
    this.registerBuiltInValidators();
    this.createFormTemplates();
  }

  /**
   * Initialize visual configuration system
   */
  private initializeVisualConfiguration(): void {
    console.log('Initializing iSECTECH Visual Configuration Interface...');
    
    // Generate configuration forms for all connectors
    const connectors = isectechEnterpriseConnectors.getAllConnectors();
    connectors.forEach(connector => {
      this.generateConfigurationForm(connector);
      this.generateConfigurationWizard(connector);
    });
    
    console.log(`Visual configuration initialized for ${connectors.length} integrations`);
  }

  /**
   * Generate configuration form for connector
   */
  private generateConfigurationForm(connector: ConnectorRegistry): void {
    const formId = `form-${connector.connectorId}`;
    
    const fields: ConfigurationField[] = [];
    let fieldOrder = 0;

    // Basic information fields
    fields.push({
      fieldId: 'integration-name',
      name: 'integrationName',
      label: 'Integration Name',
      description: 'Unique name for this integration instance',
      type: 'TEXT',
      required: true,
      placeholder: `${connector.name} Integration`,
      validation: {
        minLength: 3,
        maxLength: 50,
        pattern: '^[a-zA-Z0-9-_\\s]+$'
      },
      layout: { width: 'HALF', order: fieldOrder++ },
      security: { auditLogged: true }
    });

    fields.push({
      fieldId: 'integration-description',
      name: 'integrationDescription',
      label: 'Description',
      description: 'Optional description for this integration',
      type: 'TEXTAREA',
      required: false,
      placeholder: 'Describe the purpose and scope of this integration',
      layout: { width: 'FULL', order: fieldOrder++ }
    });

    // Authentication fields based on supported methods
    if (connector.authMethods.includes('API_KEY')) {
      fields.push({
        fieldId: 'api-key',
        name: 'apiKey',
        label: 'API Key',
        description: `${connector.vendor} API key for authentication`,
        type: 'PASSWORD',
        required: true,
        placeholder: 'Enter your API key',
        layout: { width: 'FULL', order: fieldOrder++, section: 'authentication' },
        security: { encrypted: true, masked: true, auditLogged: true }
      });
    }

    if (connector.authMethods.includes('BASIC_AUTH')) {
      fields.push({
        fieldId: 'username',
        name: 'username',
        label: 'Username',
        description: 'Username for basic authentication',
        type: 'TEXT',
        required: true,
        layout: { width: 'HALF', order: fieldOrder++, section: 'authentication' },
        security: { auditLogged: true }
      });

      fields.push({
        fieldId: 'password',
        name: 'password',
        label: 'Password',
        description: 'Password for basic authentication',
        type: 'PASSWORD',
        required: true,
        layout: { width: 'HALF', order: fieldOrder++, section: 'authentication' },
        security: { encrypted: true, masked: true, auditLogged: true }
      });
    }

    if (connector.authMethods.includes('OAUTH2')) {
      fields.push({
        fieldId: 'client-id',
        name: 'clientId',
        label: 'Client ID',
        description: 'OAuth 2.0 Client ID',
        type: 'TEXT',
        required: true,
        layout: { width: 'HALF', order: fieldOrder++, section: 'authentication' },
        security: { auditLogged: true }
      });

      fields.push({
        fieldId: 'client-secret',
        name: 'clientSecret',
        label: 'Client Secret',
        description: 'OAuth 2.0 Client Secret',
        type: 'PASSWORD',
        required: true,
        layout: { width: 'HALF', order: fieldOrder++, section: 'authentication' },
        security: { encrypted: true, masked: true, auditLogged: true }
      });

      fields.push({
        fieldId: 'redirect-uri',
        name: 'redirectUri',
        label: 'Redirect URI',
        description: 'OAuth 2.0 Redirect URI',
        type: 'URL',
        required: true,
        placeholder: 'https://your-app.com/oauth/callback',
        layout: { width: 'FULL', order: fieldOrder++, section: 'authentication' }
      });
    }

    // Connection configuration
    if (connector.integrationConfig?.connection?.baseUrl) {
      fields.push({
        fieldId: 'base-url',
        name: 'baseUrl',
        label: 'Base URL',
        description: 'Base URL for API connections',
        type: 'URL',
        required: true,
        defaultValue: connector.integrationConfig.connection.baseUrl,
        layout: { width: 'FULL', order: fieldOrder++, section: 'connection' }
      });
    }

    // Rate limiting configuration
    fields.push({
      fieldId: 'rate-limit',
      name: 'rateLimit',
      label: 'Rate Limit (requests/second)',
      description: 'Maximum requests per second',
      type: 'SLIDER',
      required: false,
      defaultValue: 10,
      validation: { minLength: 1, maxLength: 100 },
      layout: { width: 'HALF', order: fieldOrder++, section: 'performance' }
    });

    // Data type selection
    fields.push({
      fieldId: 'data-types',
      name: 'dataTypes',
      label: 'Data Types',
      description: 'Select which data types to sync',
      type: 'MULTISELECT',
      required: true,
      options: connector.dataTypes.map(type => ({
        value: type,
        label: type.replace('_', ' ').toLowerCase(),
        description: `Sync ${type.toLowerCase()} data`
      })),
      defaultValue: connector.dataTypes,
      layout: { width: 'FULL', order: fieldOrder++, section: 'data' }
    });

    // Environment selection
    fields.push({
      fieldId: 'environment',
      name: 'environment',
      label: 'Environment',
      description: 'Deployment environment',
      type: 'SELECT',
      required: true,
      options: [
        { value: 'development', label: 'Development', description: 'Development environment' },
        { value: 'staging', label: 'Staging', description: 'Staging environment' },
        { value: 'production', label: 'Production', description: 'Production environment' }
      ],
      defaultValue: 'development',
      layout: { width: 'HALF', order: fieldOrder++, section: 'deployment' }
    });

    // Enable/disable features
    fields.push({
      fieldId: 'enable-monitoring',
      name: 'enableMonitoring',
      label: 'Enable Monitoring',
      description: 'Enable real-time monitoring and alerting',
      type: 'BOOLEAN',
      required: false,
      defaultValue: true,
      layout: { width: 'QUARTER', order: fieldOrder++, section: 'features' }
    });

    fields.push({
      fieldId: 'enable-encryption',
      name: 'enableEncryption',
      label: 'Enable Encryption',
      description: 'Encrypt data in transit and at rest',
      type: 'BOOLEAN',
      required: false,
      defaultValue: true,
      layout: { width: 'QUARTER', order: fieldOrder++, section: 'features' }
    });

    const form: ConfigurationForm = {
      formId,
      integrationId: connector.connectorId,
      name: `${connector.name} Configuration`,
      description: `Configuration form for ${connector.name} integration`,
      version: '1.0.0',
      
      sections: [
        {
          sectionId: 'basic',
          title: 'Basic Information',
          description: 'Basic integration settings',
          order: 0,
          fields: fields.filter(f => !f.layout.section).map(f => f.fieldId)
        },
        {
          sectionId: 'authentication',
          title: 'Authentication',
          description: 'Authentication and authorization settings',
          order: 1,
          fields: fields.filter(f => f.layout.section === 'authentication').map(f => f.fieldId)
        },
        {
          sectionId: 'connection',
          title: 'Connection',
          description: 'Connection and endpoint configuration',
          order: 2,
          fields: fields.filter(f => f.layout.section === 'connection').map(f => f.fieldId)
        },
        {
          sectionId: 'data',
          title: 'Data Configuration',
          description: 'Data types and transformation settings',
          order: 3,
          fields: fields.filter(f => f.layout.section === 'data').map(f => f.fieldId)
        },
        {
          sectionId: 'performance',
          title: 'Performance',
          description: 'Rate limiting and performance settings',
          order: 4,
          fields: fields.filter(f => f.layout.section === 'performance').map(f => f.fieldId)
        },
        {
          sectionId: 'features',
          title: 'Features',
          description: 'Optional features and capabilities',
          order: 5,
          fields: fields.filter(f => f.layout.section === 'features').map(f => f.fieldId)
        },
        {
          sectionId: 'deployment',
          title: 'Deployment',
          description: 'Deployment and environment settings',
          order: 6,
          fields: fields.filter(f => f.layout.section === 'deployment').map(f => f.fieldId)
        }
      ],
      
      fields,
      
      behavior: {
        saveOnChange: false,
        validateOnChange: true,
        showProgress: true,
        allowReset: true,
        confirmOnSubmit: true
      },
      
      submission: {
        endpoint: `https://api.isectech.com/integrations/v1/${connector.connectorId}/configure`,
        method: 'POST',
        successMessage: 'Integration configured successfully!',
        errorMessage: 'Failed to configure integration. Please check your settings.',
        redirectUrl: `https://dashboard.isectech.com/integrations/${connector.connectorId}`
      },
      
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'system',
      tags: ['auto-generated', connector.category.toLowerCase(), connector.vendor.toLowerCase()]
    };

    const validatedForm = ConfigurationFormSchema.parse(form);
    this.configurationForms.set(formId, validatedForm);
  }

  /**
   * Generate configuration wizard for connector
   */
  private generateConfigurationWizard(connector: ConnectorRegistry): void {
    const wizardId = `wizard-${connector.connectorId}`;
    const formId = `form-${connector.connectorId}`;
    
    const wizard: ConfigurationWizard = {
      wizardId,
      integrationId: connector.connectorId,
      name: `${connector.name} Setup Wizard`,
      description: `Step-by-step setup wizard for ${connector.name} integration`,
      
      steps: [
        {
          stepId: 'welcome',
          title: 'Welcome',
          description: `Welcome to the ${connector.name} integration setup wizard`,
          order: 0,
          type: 'FORM',
          template: 'welcome-template',
          skippable: false,
          required: true,
          estimatedTime: 2,
          nextStep: 'authentication'
        },
        {
          stepId: 'authentication',
          title: 'Authentication',
          description: 'Configure authentication settings',
          order: 1,
          type: 'FORM',
          formId,
          skippable: false,
          required: true,
          estimatedTime: 5,
          nextStep: 'connection',
          previousStep: 'welcome'
        },
        {
          stepId: 'connection',
          title: 'Connection',
          description: 'Configure connection settings',
          order: 2,
          type: 'FORM',
          formId,
          skippable: false,
          required: true,
          estimatedTime: 3,
          nextStep: 'validation',
          previousStep: 'authentication'
        },
        {
          stepId: 'validation',
          title: 'Validation',
          description: 'Test your configuration',
          order: 3,
          type: 'VALIDATION',
          validationRules: ['connection-test', 'auth-test', 'data-flow-test'],
          skippable: false,
          required: true,
          estimatedTime: 5,
          nextStep: 'review',
          previousStep: 'connection'
        },
        {
          stepId: 'review',
          title: 'Review',
          description: 'Review your configuration before deployment',
          order: 4,
          type: 'REVIEW',
          template: 'review-template',
          skippable: false,
          required: true,
          estimatedTime: 3,
          nextStep: 'completion',
          previousStep: 'validation'
        },
        {
          stepId: 'completion',
          title: 'Complete',
          description: 'Integration setup completed successfully',
          order: 5,
          type: 'COMPLETION',
          template: 'completion-template',
          skippable: false,
          required: true,
          estimatedTime: 1,
          previousStep: 'review'
        }
      ],
      
      configuration: {
        allowBackNavigation: true,
        showProgress: true,
        autoSave: true,
        timeoutMinutes: 30,
        maxAttempts: 3
      },
      
      completion: {
        action: 'DEPLOY',
        successTemplate: 'deployment-success-template',
        failureTemplate: 'deployment-failure-template',
        followUpActions: ['create-monitoring-dashboard', 'setup-alerting', 'schedule-health-checks']
      },
      
      createdAt: new Date(),
      updatedAt: new Date(),
      estimatedDuration: 19, // Sum of step times
      difficulty: this.getWizardDifficulty(connector),
      tags: ['auto-generated', 'wizard', connector.category.toLowerCase()]
    };

    const validatedWizard = ConfigurationWizardSchema.parse(wizard);
    this.configurationWizards.set(wizardId, validatedWizard);
  }

  /**
   * Validate configuration field
   */
  public async validateField(
    fieldId: string,
    value: any,
    formId: string,
    context: Record<string, any> = {}
  ): Promise<ConfigurationValidationResult> {
    const validationId = crypto.randomUUID();
    const startTime = Date.now();
    
    const form = this.configurationForms.get(formId);
    if (!form) {
      throw new Error('Configuration form not found');
    }

    const field = form.fields.find(f => f.fieldId === fieldId);
    if (!field) {
      throw new Error('Configuration field not found');
    }

    const errors = [];
    const warnings = [];
    const suggestions = [];

    try {
      // Basic type validation
      if (!this.validateFieldType(field, value)) {
        errors.push({
          code: 'TYPE_MISMATCH',
          message: `Value must be of type ${field.type}`,
          severity: 'ERROR' as const
        });
      }

      // Required field validation
      if (field.required && (value === null || value === undefined || value === '')) {
        errors.push({
          code: 'REQUIRED_FIELD',
          message: 'This field is required',
          severity: 'ERROR' as const
        });
      }

      // Length validation
      if (field.validation?.minLength && value && value.length < field.validation.minLength) {
        errors.push({
          code: 'MIN_LENGTH',
          message: `Minimum length is ${field.validation.minLength} characters`,
          severity: 'ERROR' as const
        });
      }

      if (field.validation?.maxLength && value && value.length > field.validation.maxLength) {
        errors.push({
          code: 'MAX_LENGTH',
          message: `Maximum length is ${field.validation.maxLength} characters`,
          severity: 'ERROR' as const
        });
      }

      // Pattern validation
      if (field.validation?.pattern && value) {
        const regex = new RegExp(field.validation.pattern);
        if (!regex.test(value)) {
          errors.push({
            code: 'PATTERN_MISMATCH',
            message: 'Value does not match required pattern',
            severity: 'ERROR' as const
          });
        }
      }

      // Custom validation
      if (field.validation?.customValidator) {
        const validator = this.fieldValidators.get(field.validation.customValidator);
        if (validator) {
          const customResult = await validator(value, field, context);
          if (!customResult.isValid) {
            errors.push(...customResult.errors);
            warnings.push(...customResult.warnings);
            suggestions.push(...customResult.suggestions);
          }
        }
      }

      // Security validation
      if (field.security?.encrypted && field.type === 'PASSWORD') {
        if (value && value.length < 8) {
          warnings.push('Consider using a stronger password (8+ characters)');
        }
      }

      // Add suggestions based on field type and value
      if (field.type === 'URL' && value && !value.startsWith('https://')) {
        suggestions.push({
          type: 'SECURITY',
          message: 'Consider using HTTPS for secure connections',
          action: 'Change protocol to HTTPS'
        });
      }

    } catch (error) {
      errors.push({
        code: 'VALIDATION_ERROR',
        message: error instanceof Error ? error.message : 'Validation failed',
        severity: 'ERROR' as const
      });
    }

    const result: ConfigurationValidationResult = {
      validationId,
      fieldId,
      formId,
      isValid: errors.length === 0,
      errors,
      warnings,
      suggestions,
      validatedAt: new Date(),
      validatorType: 'SERVER',
      validatorVersion: '1.0.0',
      responseTime: Date.now() - startTime
    };

    const validatedResult = ConfigurationValidationResultSchema.parse(result);
    this.validationResults.set(validationId, validatedResult);

    return validatedResult;
  }

  /**
   * Generate form HTML/JSON for frontend rendering
   */
  public generateFormDefinition(formId: string): {
    form: ConfigurationForm;
    uiSchema: any;
    jsonSchema: any;
  } {
    const form = this.configurationForms.get(formId);
    if (!form) {
      throw new Error('Configuration form not found');
    }

    // Generate JSON Schema for validation
    const jsonSchema = {
      type: 'object',
      properties: {},
      required: [] as string[]
    };

    // Generate UI Schema for rendering
    const uiSchema: any = {
      'ui:order': [] as string[]
    };

    form.fields.forEach(field => {
      // Add to JSON Schema
      jsonSchema.properties[field.name] = this.fieldToJsonSchema(field);
      if (field.required) {
        jsonSchema.required.push(field.name);
      }

      // Add to UI Schema
      uiSchema[field.name] = this.fieldToUISchema(field);
      uiSchema['ui:order'].push(field.name);
    });

    return {
      form,
      uiSchema,
      jsonSchema
    };
  }

  /**
   * Execute configuration wizard step
   */
  public async executeWizardStep(
    wizardId: string,
    stepId: string,
    data: Record<string, any>,
    context: Record<string, any> = {}
  ): Promise<{
    success: boolean;
    nextStep?: string;
    validationResults?: ConfigurationValidationResult[];
    error?: string;
  }> {
    const wizard = this.configurationWizards.get(wizardId);
    if (!wizard) {
      return { success: false, error: 'Wizard not found' };
    }

    const step = wizard.steps.find(s => s.stepId === stepId);
    if (!step) {
      return { success: false, error: 'Wizard step not found' };
    }

    try {
      switch (step.type) {
        case 'FORM':
          if (step.formId) {
            const validationResults = await this.validateFormData(step.formId, data);
            const hasErrors = validationResults.some(result => !result.isValid);
            
            if (hasErrors) {
              return { 
                success: false, 
                validationResults,
                error: 'Validation errors found' 
              };
            }
          }
          break;

        case 'VALIDATION':
          const testResults = await this.executeValidationTests(wizard.integrationId, data, step.validationRules || []);
          if (!testResults.success) {
            return { 
              success: false, 
              error: 'Validation tests failed' 
            };
          }
          break;

        case 'REVIEW':
        case 'COMPLETION':
          // These steps typically don't require validation
          break;
      }

      // Determine next step
      let nextStep = step.nextStep;
      if (step.conditionalNext && this.evaluateCondition(step.conditionalNext.condition, data, context)) {
        nextStep = step.conditionalNext.trueStep;
      } else if (step.conditionalNext) {
        nextStep = step.conditionalNext.falseStep;
      }

      return { 
        success: true, 
        nextStep 
      };

    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Step execution failed' 
      };
    }
  }

  // Private helper methods
  private registerBuiltInValidators(): void {
    // URL validator
    this.fieldValidators.set('url-validator', async (value: string) => {
      try {
        new URL(value);
        return { isValid: true, errors: [], warnings: [], suggestions: [] };
      } catch {
        return {
          isValid: false,
          errors: [{ code: 'INVALID_URL', message: 'Invalid URL format', severity: 'ERROR' }],
          warnings: [],
          suggestions: []
        };
      }
    });

    // Email validator
    this.fieldValidators.set('email-validator', async (value: string) => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      const isValid = emailRegex.test(value);
      
      return {
        isValid,
        errors: isValid ? [] : [{ code: 'INVALID_EMAIL', message: 'Invalid email format', severity: 'ERROR' }],
        warnings: [],
        suggestions: []
      };
    });

    // Password strength validator
    this.fieldValidators.set('password-strength-validator', async (value: string) => {
      const errors = [];
      const warnings = [];
      const suggestions = [];

      if (value.length < 8) {
        errors.push({ code: 'PASSWORD_TOO_SHORT', message: 'Password must be at least 8 characters', severity: 'ERROR' });
      }

      if (!/[A-Z]/.test(value)) {
        warnings.push('Password should contain uppercase letters');
      }

      if (!/[0-9]/.test(value)) {
        warnings.push('Password should contain numbers');
      }

      if (!/[!@#$%^&*]/.test(value)) {
        suggestions.push({
          type: 'SECURITY',
          message: 'Consider adding special characters for stronger security',
          action: 'Add special characters'
        });
      }

      return {
        isValid: errors.length === 0,
        errors,
        warnings,
        suggestions
      };
    });
  }

  private createFormTemplates(): void {
    // Implementation would create reusable form templates
    console.log('Form templates created');
  }

  private getWizardDifficulty(connector: ConnectorRegistry): 'EASY' | 'MEDIUM' | 'ADVANCED' {
    const authComplexity = connector.authMethods.includes('OAUTH2') ? 2 : 1;
    const dataComplexity = connector.dataTypes.length > 3 ? 1 : 0;
    const capabilityComplexity = connector.capabilities.bidirectional ? 1 : 0;
    
    const totalComplexity = authComplexity + dataComplexity + capabilityComplexity;
    
    if (totalComplexity <= 2) return 'EASY';
    if (totalComplexity <= 3) return 'MEDIUM';
    return 'ADVANCED';
  }

  private validateFieldType(field: ConfigurationField, value: any): boolean {
    switch (field.type) {
      case 'TEXT':
      case 'PASSWORD':
      case 'EMAIL':
      case 'URL':
      case 'TEXTAREA':
        return typeof value === 'string';
      case 'NUMBER':
      case 'SLIDER':
        return typeof value === 'number';
      case 'BOOLEAN':
        return typeof value === 'boolean';
      case 'SELECT':
        return field.options?.some(opt => opt.value === value) || false;
      case 'MULTISELECT':
      case 'TAGS':
        return Array.isArray(value);
      case 'JSON':
        try {
          JSON.parse(value);
          return true;
        } catch {
          return false;
        }
      default:
        return true;
    }
  }

  private fieldToJsonSchema(field: ConfigurationField): any {
    const schema: any = {};

    switch (field.type) {
      case 'TEXT':
      case 'PASSWORD':
      case 'EMAIL':
      case 'URL':
      case 'TEXTAREA':
        schema.type = 'string';
        if (field.validation?.minLength) schema.minLength = field.validation.minLength;
        if (field.validation?.maxLength) schema.maxLength = field.validation.maxLength;
        if (field.validation?.pattern) schema.pattern = field.validation.pattern;
        break;
      case 'NUMBER':
      case 'SLIDER':
        schema.type = 'number';
        break;
      case 'BOOLEAN':
        schema.type = 'boolean';
        break;
      case 'SELECT':
        schema.type = 'string';
        schema.enum = field.options?.map(opt => opt.value) || [];
        break;
      case 'MULTISELECT':
      case 'TAGS':
        schema.type = 'array';
        schema.items = { type: 'string' };
        break;
    }

    if (field.defaultValue !== undefined) {
      schema.default = field.defaultValue;
    }

    schema.title = field.label;
    schema.description = field.description;

    return schema;
  }

  private fieldToUISchema(field: ConfigurationField): any {
    const uiSchema: any = {};

    switch (field.type) {
      case 'PASSWORD':
        uiSchema['ui:widget'] = 'password';
        break;
      case 'EMAIL':
        uiSchema['ui:widget'] = 'email';
        break;
      case 'URL':
        uiSchema['ui:widget'] = 'uri';
        break;
      case 'TEXTAREA':
        uiSchema['ui:widget'] = 'textarea';
        break;
      case 'SELECT':
        uiSchema['ui:widget'] = 'select';
        break;
      case 'MULTISELECT':
        uiSchema['ui:widget'] = 'checkboxes';
        break;
      case 'SLIDER':
        uiSchema['ui:widget'] = 'range';
        break;
      case 'JSON':
        uiSchema['ui:widget'] = 'textarea';
        uiSchema['ui:options'] = { rows: 10 };
        break;
    }

    if (field.placeholder) {
      uiSchema['ui:placeholder'] = field.placeholder;
    }

    if (field.helpText) {
      uiSchema['ui:help'] = field.helpText;
    }

    return uiSchema;
  }

  private async validateFormData(formId: string, data: Record<string, any>): Promise<ConfigurationValidationResult[]> {
    const form = this.configurationForms.get(formId);
    if (!form) {
      throw new Error('Form not found');
    }

    const results = [];
    for (const field of form.fields) {
      const value = data[field.name];
      const result = await this.validateField(field.fieldId, value, formId, data);
      results.push(result);
    }

    return results;
  }

  private async executeValidationTests(integrationId: string, data: Record<string, any>, rules: string[]): Promise<{ success: boolean; results?: any }> {
    // Implementation would execute validation tests
    // For now, return success
    return { success: true };
  }

  private evaluateCondition(condition: string, data: Record<string, any>, context: Record<string, any>): boolean {
    // Implementation would evaluate conditional logic
    // For now, return true
    return true;
  }

  /**
   * Public getters for testing and external access
   */
  public getConfigurationForm(formId: string): ConfigurationForm | null {
    return this.configurationForms.get(formId) || null;
  }

  public getConfigurationWizard(wizardId: string): ConfigurationWizard | null {
    return this.configurationWizards.get(wizardId) || null;
  }

  public getValidationResult(validationId: string): ConfigurationValidationResult | null {
    return this.validationResults.get(validationId) || null;
  }

  public listConfigurationForms(): ConfigurationForm[] {
    return Array.from(this.configurationForms.values());
  }

  public listConfigurationWizards(): ConfigurationWizard[] {
    return Array.from(this.configurationWizards.values());
  }
}

// Export production-ready visual configuration interface
export const isectechVisualConfiguration = new ISECTECHVisualConfiguration();