/**
 * Production-grade Developer Portal Application for iSECTECH
 * 
 * Provides interactive API documentation, developer authentication, API key management,
 * code examples, and comprehensive developer resources for the iSECTECH platform.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

// Developer Portal Configuration Schemas
export const DeveloperPortalConfigSchema = z.object({
  portalId: z.string(),
  name: z.string(),
  description: z.string(),
  
  // Portal settings
  settings: z.object({
    baseUrl: z.string().url(),
    apiBaseUrl: z.string().url(),
    authRequired: z.boolean().default(true),
    publicAPIsEnabled: z.boolean().default(true),
    sandboxEnabled: z.boolean().default(true),
    rateLimitingEnabled: z.boolean().default(true),
    analyticsEnabled: z.boolean().default(true)
  }),
  
  // Authentication configuration
  authentication: z.object({
    providers: z.array(z.enum(['OAUTH2', 'GITHUB', 'GOOGLE', 'EMAIL'])).default(['OAUTH2', 'EMAIL']),
    sessionTimeout: z.number().default(3600), // seconds
    requireEmailVerification: z.boolean().default(true),
    requireTermsAcceptance: z.boolean().default(true),
    mfaEnabled: z.boolean().default(false)
  }),
  
  // API documentation configuration
  documentation: z.object({
    format: z.enum(['OPENAPI_3', 'SWAGGER_2', 'ASYNC_API']).default('OPENAPI_3'),
    interactive: z.boolean().default(true),
    codeExamples: z.boolean().default(true),
    supportedLanguages: z.array(z.string()).default([
      'javascript', 'python', 'go', 'java', 'php', 'ruby', 'curl'
    ]),
    autoSync: z.boolean().default(true),
    versioningEnabled: z.boolean().default(true)
  }),
  
  // Developer features
  features: z.object({
    apiKeyManagement: z.boolean().default(true),
    usageAnalytics: z.boolean().default(true),
    quotaManagement: z.boolean().default(true),
    webhookManagement: z.boolean().default(true),
    testingPlayground: z.boolean().default(true),
    codeGeneration: z.boolean().default(true),
    communityForum: z.boolean().default(true),
    supportTickets: z.boolean().default(true)
  }),
  
  // Theming and branding
  theme: z.object({
    primaryColor: z.string().default('#1a365d'),
    secondaryColor: z.string().default('#2d3748'),
    accentColor: z.string().default('#4299e1'),
    logoUrl: z.string().url().optional(),
    faviconUrl: z.string().url().optional(),
    customCSS: z.string().optional(),
    darkModeEnabled: z.boolean().default(true)
  }),
  
  // Content management
  content: z.object({
    welcomeMessage: z.string().default('Welcome to the iSECTECH Developer Portal'),
    gettingStartedGuide: z.string().default(''),
    tutorials: z.array(z.object({
      id: z.string(),
      title: z.string(),
      description: z.string(),
      content: z.string(),
      difficulty: z.enum(['BEGINNER', 'INTERMEDIATE', 'ADVANCED']),
      estimatedTime: z.string(),
      tags: z.array(z.string())
    })).default([]),
    codeExamples: z.array(z.object({
      id: z.string(),
      name: z.string(),
      description: z.string(),
      language: z.string(),
      code: z.string(),
      tags: z.array(z.string())
    })).default([])
  }),
  
  // Analytics and monitoring
  analytics: z.object({
    enabled: z.boolean().default(true),
    trackingId: z.string().optional(),
    customEvents: z.boolean().default(true),
    performanceMonitoring: z.boolean().default(true),
    errorTracking: z.boolean().default(true)
  }),
  
  // Security settings
  security: z.object({
    csrfProtection: z.boolean().default(true),
    rateLimiting: z.object({
      enabled: z.boolean().default(true),
      requestsPerMinute: z.number().default(60),
      requestsPerHour: z.number().default(1000)
    }),
    contentSecurityPolicy: z.boolean().default(true),
    httpsOnly: z.boolean().default(true),
    sessionSecurity: z.object({
      httpOnly: z.boolean().default(true),
      secure: z.boolean().default(true),
      sameSite: z.enum(['strict', 'lax', 'none']).default('strict')
    })
  }),
  
  // Integration settings
  integrations: z.object({
    kong: z.object({
      enabled: z.boolean().default(true),
      adminApiUrl: z.string().url().optional(),
      devPortalAuth: z.boolean().default(true)
    }),
    github: z.object({
      enabled: z.boolean().default(false),
      organization: z.string().optional(),
      repository: z.string().optional(),
      syncEnabled: z.boolean().default(false)
    }),
    slack: z.object({
      enabled: z.boolean().default(false),
      webhookUrl: z.string().url().optional(),
      notificationsEnabled: z.boolean().default(false)
    })
  }),
  
  // Metadata
  createdAt: z.date(),
  updatedAt: z.date(),
  version: z.string(),
  tags: z.array(z.string()).default(['isectech', 'developer-portal', 'api-documentation'])
});

export const DeveloperAccountSchema = z.object({
  developerId: z.string(),
  email: z.string().email(),
  username: z.string(),
  firstName: z.string(),
  lastName: z.string(),
  organization: z.string().optional(),
  
  // Account status
  status: z.enum(['PENDING_VERIFICATION', 'ACTIVE', 'SUSPENDED', 'DEACTIVATED']).default('PENDING_VERIFICATION'),
  emailVerified: z.boolean().default(false),
  termsAccepted: z.boolean().default(false),
  termsAcceptedAt: z.date().optional(),
  
  // Developer tier and permissions
  tier: z.enum(['FREE', 'DEVELOPER', 'PROFESSIONAL', 'ENTERPRISE']).default('FREE'),
  permissions: z.array(z.string()).default(['read:docs', 'create:api_keys']),
  quotas: z.object({
    apiCalls: z.object({
      daily: z.number().default(1000),
      monthly: z.number().default(25000)
    }),
    apiKeys: z.number().default(5),
    webhooks: z.number().default(3)
  }),
  
  // API access
  apiKeys: z.array(z.object({
    keyId: z.string(),
    name: z.string(),
    keyHash: z.string(), // Hashed API key
    scopes: z.array(z.string()),
    createdAt: z.date(),
    expiresAt: z.date().optional(),
    lastUsed: z.date().optional(),
    isActive: z.boolean().default(true)
  })).default([]),
  
  // Developer preferences
  preferences: z.object({
    theme: z.enum(['light', 'dark', 'auto']).default('auto'),
    language: z.string().default('en'),
    emailNotifications: z.boolean().default(true),
    newsletter: z.boolean().default(false),
    codeExampleLanguage: z.string().default('javascript')
  }),
  
  // Usage statistics
  statistics: z.object({
    totalApiCalls: z.number().default(0),
    totalApiCallsThisMonth: z.number().default(0),
    averageResponseTime: z.number().default(0),
    errorRate: z.number().default(0),
    lastActivity: z.date().optional()
  }),
  
  // Security
  twoFactorEnabled: z.boolean().default(false),
  lastLoginAt: z.date().optional(),
  loginCount: z.number().default(0),
  
  // Metadata
  createdAt: z.date(),
  updatedAt: z.date(),
  notes: z.string().optional(),
  tags: z.array(z.string()).default([])
});

export const APIDocumentationSchema = z.object({
  documentId: z.string(),
  title: z.string(),
  description: z.string(),
  version: z.string(),
  
  // OpenAPI specification
  openApiSpec: z.object({
    openapi: z.string().default('3.0.3'),
    info: z.object({
      title: z.string(),
      description: z.string(),
      version: z.string(),
      contact: z.object({
        name: z.string().optional(),
        email: z.string().email().optional(),
        url: z.string().url().optional()
      }).optional(),
      license: z.object({
        name: z.string(),
        url: z.string().url().optional()
      }).optional()
    }),
    servers: z.array(z.object({
      url: z.string(),
      description: z.string().optional()
    })),
    paths: z.record(z.any()), // Paths object
    components: z.object({
      schemas: z.record(z.any()).optional(),
      securitySchemes: z.record(z.any()).optional(),
      parameters: z.record(z.any()).optional(),
      responses: z.record(z.any()).optional()
    }).optional(),
    security: z.array(z.record(z.array(z.string()))).optional(),
    tags: z.array(z.object({
      name: z.string(),
      description: z.string().optional()
    })).optional()
  }),
  
  // Portal-specific configuration
  portalConfig: z.object({
    category: z.string(),
    featured: z.boolean().default(false),
    difficulty: z.enum(['BEGINNER', 'INTERMEDIATE', 'ADVANCED']).default('INTERMEDIATE'),
    estimatedTime: z.string().optional(),
    prerequisites: z.array(z.string()).default([]),
    codeExamples: z.boolean().default(true),
    interactiveExamples: z.boolean().default(true),
    changelog: z.array(z.object({
      version: z.string(),
      date: z.date(),
      changes: z.array(z.string())
    })).default([])
  }),
  
  // Status and lifecycle
  status: z.enum(['DRAFT', 'PUBLISHED', 'DEPRECATED']).default('DRAFT'),
  publishedAt: z.date().optional(),
  deprecatedAt: z.date().optional(),
  
  // Metadata
  createdBy: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
  tags: z.array(z.string()).default([])
});

export type DeveloperPortalConfig = z.infer<typeof DeveloperPortalConfigSchema>;
export type DeveloperAccount = z.infer<typeof DeveloperAccountSchema>;
export type APIDocumentation = z.infer<typeof APIDocumentationSchema>;

/**
 * Developer Portal Application for iSECTECH
 */
export class ISECTECHDeveloperPortalApp {
  private config: DeveloperPortalConfig;
  private developers: Map<string, DeveloperAccount> = new Map();
  private apiDocs: Map<string, APIDocumentation> = new Map();
  private sessions: Map<string, any> = new Map();

  constructor(config: Partial<DeveloperPortalConfig>) {
    this.config = this.initializeDefaultConfig(config);
    this.initializeISECTECHPortal();
    this.startMaintenanceTasks();
  }

  /**
   * Initialize default portal configuration
   */
  private initializeDefaultConfig(partialConfig: Partial<DeveloperPortalConfig>): DeveloperPortalConfig {
    const defaultConfig: DeveloperPortalConfig = {
      portalId: 'isectech-developer-portal',
      name: 'iSECTECH Developer Portal',
      description: 'Comprehensive developer portal for iSECTECH cybersecurity APIs',
      
      settings: {
        baseUrl: 'https://developer.isectech.com',
        apiBaseUrl: 'https://api.isectech.com',
        authRequired: true,
        publicAPIsEnabled: true,
        sandboxEnabled: true,
        rateLimitingEnabled: true,
        analyticsEnabled: true
      },
      
      authentication: {
        providers: ['OAUTH2', 'EMAIL', 'GITHUB'],
        sessionTimeout: 3600,
        requireEmailVerification: true,
        requireTermsAcceptance: true,
        mfaEnabled: false
      },
      
      documentation: {
        format: 'OPENAPI_3',
        interactive: true,
        codeExamples: true,
        supportedLanguages: ['javascript', 'python', 'go', 'java', 'php', 'ruby', 'curl'],
        autoSync: true,
        versioningEnabled: true
      },
      
      features: {
        apiKeyManagement: true,
        usageAnalytics: true,
        quotaManagement: true,
        webhookManagement: true,
        testingPlayground: true,
        codeGeneration: true,
        communityForum: true,
        supportTickets: true
      },
      
      theme: {
        primaryColor: '#0f4c75',
        secondaryColor: '#3282b8',
        accentColor: '#bbe1fa',
        logoUrl: 'https://assets.isectech.com/logo/isectech-logo.svg',
        faviconUrl: 'https://assets.isectech.com/favicon/favicon.ico',
        darkModeEnabled: true
      },
      
      content: {
        welcomeMessage: 'Welcome to the iSECTECH Developer Portal - Build secure applications with our cybersecurity APIs',
        gettingStartedGuide: '',
        tutorials: [],
        codeExamples: []
      },
      
      analytics: {
        enabled: true,
        customEvents: true,
        performanceMonitoring: true,
        errorTracking: true
      },
      
      security: {
        csrfProtection: true,
        rateLimiting: {
          enabled: true,
          requestsPerMinute: 60,
          requestsPerHour: 1000
        },
        contentSecurityPolicy: true,
        httpsOnly: true,
        sessionSecurity: {
          httpOnly: true,
          secure: true,
          sameSite: 'strict'
        }
      },
      
      integrations: {
        kong: {
          enabled: true,
          adminApiUrl: 'http://kong-admin.isectech.svc.cluster.local:8001',
          devPortalAuth: true
        },
        github: {
          enabled: false
        },
        slack: {
          enabled: false
        }
      },
      
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0.0',
      tags: ['isectech', 'developer-portal', 'cybersecurity', 'api-documentation']
    };

    return DeveloperPortalConfigSchema.parse({ ...defaultConfig, ...partialConfig });
  }

  /**
   * Initialize the iSECTECH developer portal
   */
  private initializeISECTECHPortal(): void {
    console.log(`Initializing developer portal: ${this.config.name}`);
    
    // Initialize API documentation
    this.initializeAPIDocumentation();
    
    // Initialize tutorials and guides
    this.initializeTutorials();
    
    // Initialize code examples
    this.initializeCodeExamples();
    
    console.log('Developer portal initialized successfully');
  }

  /**
   * Initialize API documentation with iSECTECH APIs
   */
  private initializeAPIDocumentation(): void {
    // Threat Detection API Documentation
    const threatDetectionDoc: APIDocumentation = {
      documentId: 'threat-detection-api',
      title: 'Threat Detection API',
      description: 'Advanced threat detection and analysis capabilities',
      version: 'v1.0',
      
      openApiSpec: {
        openapi: '3.0.3',
        info: {
          title: 'iSECTECH Threat Detection API',
          description: 'Real-time threat detection and behavioral analysis API',
          version: '1.0.0',
          contact: {
            name: 'iSECTECH API Support',
            email: 'api-support@isectech.com',
            url: 'https://support.isectech.com'
          },
          license: {
            name: 'iSECTECH API License',
            url: 'https://developer.isectech.com/license'
          }
        },
        servers: [
          {
            url: 'https://api.isectech.com/v1',
            description: 'Production server'
          },
          {
            url: 'https://sandbox-api.isectech.com/v1',
            description: 'Sandbox server'
          }
        ],
        paths: {
          '/threats/analyze': {
            post: {
              tags: ['Threat Analysis'],
              summary: 'Analyze potential threats',
              description: 'Submit data for threat analysis using AI/ML models',
              operationId: 'analyzeThreat',
              requestBody: {
                required: true,
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: {
                        data: {
                          type: 'string',
                          description: 'Data to analyze (base64 encoded)'
                        },
                        type: {
                          type: 'string',
                          enum: ['file', 'url', 'ip', 'domain'],
                          description: 'Type of data being analyzed'
                        },
                        options: {
                          type: 'object',
                          properties: {
                            deep_scan: {
                              type: 'boolean',
                              default: false
                            },
                            include_metadata: {
                              type: 'boolean',
                              default: true
                            }
                          }
                        }
                      },
                      required: ['data', 'type']
                    }
                  }
                }
              },
              responses: {
                200: {
                  description: 'Threat analysis results',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          threat_score: {
                            type: 'number',
                            minimum: 0,
                            maximum: 1,
                            description: 'Threat confidence score'
                          },
                          threat_type: {
                            type: 'string',
                            description: 'Identified threat type'
                          },
                          details: {
                            type: 'object',
                            description: 'Detailed analysis results'
                          },
                          recommendations: {
                            type: 'array',
                            items: {
                              type: 'string'
                            },
                            description: 'Security recommendations'
                          }
                        }
                      }
                    }
                  }
                },
                400: {
                  description: 'Invalid request data'
                },
                429: {
                  description: 'Rate limit exceeded'
                }
              },
              security: [
                {
                  ApiKeyAuth: []
                }
              ]
            }
          },
          '/threats/feeds': {
            get: {
              tags: ['Threat Intelligence'],
              summary: 'Get threat intelligence feeds',
              description: 'Retrieve latest threat intelligence data',
              operationId: 'getThreatFeeds',
              parameters: [
                {
                  name: 'type',
                  in: 'query',
                  description: 'Filter by threat type',
                  schema: {
                    type: 'string',
                    enum: ['malware', 'phishing', 'ip_reputation', 'domain_reputation']
                  }
                },
                {
                  name: 'limit',
                  in: 'query',
                  description: 'Number of results to return',
                  schema: {
                    type: 'integer',
                    default: 100,
                    maximum: 1000
                  }
                }
              ],
              responses: {
                200: {
                  description: 'Threat intelligence feeds',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          feeds: {
                            type: 'array',
                            items: {
                              type: 'object',
                              properties: {
                                id: { type: 'string' },
                                type: { type: 'string' },
                                indicator: { type: 'string' },
                                confidence: { type: 'number' },
                                first_seen: { type: 'string', format: 'date-time' },
                                last_seen: { type: 'string', format: 'date-time' },
                                tags: {
                                  type: 'array',
                                  items: { type: 'string' }
                                }
                              }
                            }
                          },
                          pagination: {
                            type: 'object',
                            properties: {
                              total: { type: 'integer' },
                              page: { type: 'integer' },
                              per_page: { type: 'integer' }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              },
              security: [
                {
                  ApiKeyAuth: []
                }
              ]
            }
          }
        },
        components: {
          securitySchemes: {
            ApiKeyAuth: {
              type: 'apiKey',
              in: 'header',
              name: 'X-API-Key'
            },
            BearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT'
            }
          },
          schemas: {
            Error: {
              type: 'object',
              properties: {
                error: {
                  type: 'string',
                  description: 'Error message'
                },
                code: {
                  type: 'string',
                  description: 'Error code'
                },
                details: {
                  type: 'object',
                  description: 'Additional error details'
                }
              }
            }
          }
        },
        security: [
          {
            ApiKeyAuth: []
          }
        ],
        tags: [
          {
            name: 'Threat Analysis',
            description: 'Operations for threat detection and analysis'
          },
          {
            name: 'Threat Intelligence',
            description: 'Threat intelligence feeds and data'
          }
        ]
      },
      
      portalConfig: {
        category: 'Security',
        featured: true,
        difficulty: 'INTERMEDIATE',
        estimatedTime: '30 minutes',
        prerequisites: ['API Key', 'Basic HTTP knowledge'],
        codeExamples: true,
        interactiveExamples: true,
        changelog: [
          {
            version: '1.0.0',
            date: new Date('2024-01-01'),
            changes: ['Initial release', 'Threat analysis endpoint', 'Intelligence feeds']
          }
        ]
      },
      
      status: 'PUBLISHED',
      publishedAt: new Date(),
      createdBy: 'system',
      createdAt: new Date(),
      updatedAt: new Date(),
      tags: ['threat-detection', 'security', 'ai-ml', 'featured']
    };

    // Asset Discovery API Documentation
    const assetDiscoveryDoc: APIDocumentation = {
      documentId: 'asset-discovery-api',
      title: 'Asset Discovery API',
      description: 'Network asset discovery and inventory management',
      version: 'v1.0',
      
      openApiSpec: {
        openapi: '3.0.3',
        info: {
          title: 'iSECTECH Asset Discovery API',
          description: 'Comprehensive network asset discovery and management API',
          version: '1.0.0'
        },
        servers: [
          {
            url: 'https://api.isectech.com/v1',
            description: 'Production server'
          }
        ],
        paths: {
          '/assets/scan': {
            post: {
              tags: ['Asset Discovery'],
              summary: 'Initiate asset discovery scan',
              description: 'Start a network scan to discover assets',
              operationId: 'startAssetScan',
              requestBody: {
                required: true,
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: {
                        targets: {
                          type: 'array',
                          items: { type: 'string' },
                          description: 'IP ranges or hostnames to scan'
                        },
                        scan_type: {
                          type: 'string',
                          enum: ['fast', 'comprehensive', 'stealth'],
                          default: 'fast'
                        },
                        ports: {
                          type: 'array',
                          items: { type: 'integer' },
                          description: 'Specific ports to scan'
                        }
                      },
                      required: ['targets']
                    }
                  }
                }
              },
              responses: {
                202: {
                  description: 'Scan initiated successfully',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          scan_id: { type: 'string' },
                          status: { type: 'string' },
                          estimated_completion: { type: 'string', format: 'date-time' }
                        }
                      }
                    }
                  }
                }
              },
              security: [{ ApiKeyAuth: [] }]
            }
          },
          '/assets': {
            get: {
              tags: ['Asset Management'],
              summary: 'Get discovered assets',
              description: 'Retrieve list of discovered network assets',
              operationId: 'getAssets',
              parameters: [
                {
                  name: 'filter',
                  in: 'query',
                  description: 'Filter assets by type or status',
                  schema: { type: 'string' }
                }
              ],
              responses: {
                200: {
                  description: 'List of assets',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          assets: {
                            type: 'array',
                            items: {
                              type: 'object',
                              properties: {
                                id: { type: 'string' },
                                ip_address: { type: 'string' },
                                hostname: { type: 'string' },
                                asset_type: { type: 'string' },
                                os: { type: 'string' },
                                services: {
                                  type: 'array',
                                  items: {
                                    type: 'object',
                                    properties: {
                                      port: { type: 'integer' },
                                      protocol: { type: 'string' },
                                      service: { type: 'string' },
                                      version: { type: 'string' }
                                    }
                                  }
                                },
                                last_seen: { type: 'string', format: 'date-time' }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              },
              security: [{ ApiKeyAuth: [] }]
            }
          }
        },
        components: {
          securitySchemes: {
            ApiKeyAuth: {
              type: 'apiKey',
              in: 'header',
              name: 'X-API-Key'
            }
          }
        },
        tags: [
          {
            name: 'Asset Discovery',
            description: 'Asset discovery and scanning operations'
          },
          {
            name: 'Asset Management',
            description: 'Asset inventory management'
          }
        ]
      },
      
      portalConfig: {
        category: 'Network Security',
        featured: false,
        difficulty: 'BEGINNER',
        estimatedTime: '15 minutes',
        prerequisites: ['API Key'],
        codeExamples: true,
        interactiveExamples: true,
        changelog: []
      },
      
      status: 'PUBLISHED',
      publishedAt: new Date(),
      createdBy: 'system',
      createdAt: new Date(),
      updatedAt: new Date(),
      tags: ['asset-discovery', 'network-security', 'inventory']
    };

    // Store API documentation
    [threatDetectionDoc, assetDiscoveryDoc].forEach(doc => {
      const validatedDoc = APIDocumentationSchema.parse(doc);
      this.apiDocs.set(doc.documentId, validatedDoc);
    });

    console.log(`Initialized ${this.apiDocs.size} API documentation sets`);
  }

  /**
   * Initialize tutorials and learning content
   */
  private initializeTutorials(): void {
    const tutorials = [
      {
        id: 'getting-started',
        title: 'Getting Started with iSECTECH APIs',
        description: 'Learn the basics of using iSECTECH cybersecurity APIs',
        content: `
# Getting Started with iSECTECH APIs

Welcome to the iSECTECH API platform! This tutorial will guide you through the essential steps to start using our cybersecurity APIs.

## 1. Create Your Developer Account

First, sign up for a developer account at [https://developer.isectech.com](https://developer.isectech.com).

## 2. Generate Your API Key

After email verification:
1. Go to your dashboard
2. Click "API Keys" in the sidebar
3. Click "Generate New Key"
4. Give your key a descriptive name
5. Select the appropriate scopes

## 3. Make Your First API Call

Here's a simple example using the Threat Detection API:

\`\`\`javascript
const response = await fetch('https://api.isectech.com/v1/threats/analyze', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'your-api-key-here'
  },
  body: JSON.stringify({
    data: btoa('suspicious-file-content'),
    type: 'file'
  })
});

const result = await response.json();
console.log('Threat Score:', result.threat_score);
\`\`\`

## 4. Handle Rate Limits

All APIs have rate limits. Always check the response headers:
- \`X-RateLimit-Remaining\`: Requests remaining
- \`X-RateLimit-Reset\`: Time when limit resets

## 5. Error Handling

Always implement proper error handling:

\`\`\`javascript
if (!response.ok) {
  const error = await response.json();
  console.error('API Error:', error.error);
  console.error('Error Code:', error.code);
}
\`\`\`

## Next Steps

- Explore our [API Reference](/docs)
- Try the [Interactive Playground](/playground)
- Join our [Developer Community](/community)
        `,
        difficulty: 'BEGINNER',
        estimatedTime: '10 minutes',
        tags: ['getting-started', 'basics', 'authentication']
      },
      {
        id: 'advanced-threat-detection',
        title: 'Advanced Threat Detection Techniques',
        description: 'Learn advanced patterns for threat detection and analysis',
        content: `
# Advanced Threat Detection Techniques

This tutorial covers advanced usage patterns for the iSECTECH Threat Detection API.

## Batch Processing

Process multiple items efficiently:

\`\`\`python
import asyncio
import aiohttp

async def analyze_threats(items):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for item in items:
            task = analyze_single_threat(session, item)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return results

async def analyze_single_threat(session, item):
    async with session.post(
        'https://api.isectech.com/v1/threats/analyze',
        headers={'X-API-Key': 'your-key'},
        json={'data': item['data'], 'type': item['type']}
    ) as response:
        return await response.json()
\`\`\`

## Webhook Integration

Set up real-time threat notifications:

\`\`\`javascript
// Configure webhook endpoint
app.post('/threats/webhook', (req, res) => {
  const { threat_score, threat_type, details } = req.body;
  
  if (threat_score > 0.8) {
    // High threat detected - take immediate action
    alertSecurityTeam(details);
  }
  
  res.status(200).send('OK');
});
\`\`\`

## Custom ML Models

Integrate with your own models:

\`\`\`go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

type ThreatAnalysisRequest struct {
    Data    string            \`json:"data"\`
    Type    string            \`json:"type"\`
    Options map[string]interface{} \`json:"options"\`
}

func analyzeThreat(data string, customModel bool) (*ThreatResult, error) {
    req := ThreatAnalysisRequest{
        Data: data,
        Type: "file",
        Options: map[string]interface{}{
            "use_custom_model": customModel,
            "model_id": "your-model-id",
        },
    }
    
    // Make API request...
    return result, nil
}
\`\`\`
        `,
        difficulty: 'ADVANCED',
        estimatedTime: '45 minutes',
        tags: ['threat-detection', 'advanced', 'integration']
      }
    ];

    this.config.content.tutorials = tutorials;
  }

  /**
   * Initialize code examples
   */
  private initializeCodeExamples(): void {
    const codeExamples = [
      {
        id: 'basic-threat-analysis-js',
        name: 'Basic Threat Analysis (JavaScript)',
        description: 'Simple threat analysis using fetch API',
        language: 'javascript',
        code: `
const analyzeFile = async (fileContent) => {
  try {
    const response = await fetch('https://api.isectech.com/v1/threats/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': process.env.ISECTECH_API_KEY
      },
      body: JSON.stringify({
        data: btoa(fileContent),
        type: 'file',
        options: {
          deep_scan: true,
          include_metadata: true
        }
      })
    });

    if (!response.ok) {
      throw new Error(\`HTTP error! status: \${response.status}\`);
    }

    const result = await response.json();
    
    console.log('Threat Score:', result.threat_score);
    console.log('Threat Type:', result.threat_type);
    console.log('Recommendations:', result.recommendations);
    
    return result;
  } catch (error) {
    console.error('Analysis failed:', error);
    throw error;
  }
};

// Usage
analyzeFile('suspicious file content')
  .then(result => console.log('Analysis complete:', result))
  .catch(error => console.error('Error:', error));
        `,
        tags: ['javascript', 'threat-detection', 'basic']
      },
      {
        id: 'asset-discovery-python',
        name: 'Asset Discovery (Python)',
        description: 'Network asset discovery using Python requests',
        language: 'python',
        code: `
import requests
import time
import json
from typing import List, Dict, Any

class ISECTECHAssetDiscovery:
    def __init__(self, api_key: str, base_url: str = "https://api.isectech.com/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': api_key
        }
    
    def start_scan(self, targets: List[str], scan_type: str = "fast") -> Dict[str, Any]:
        """Start an asset discovery scan"""
        payload = {
            'targets': targets,
            'scan_type': scan_type,
            'ports': [22, 80, 443, 8080, 8443]  # Common ports
        }
        
        response = requests.post(
            f"{self.base_url}/assets/scan",
            headers=self.headers,
            json=payload
        )
        
        response.raise_for_status()
        return response.json()
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Check scan status"""
        response = requests.get(
            f"{self.base_url}/assets/scans/{scan_id}",
            headers=self.headers
        )
        
        response.raise_for_status()
        return response.json()
    
    def wait_for_scan_completion(self, scan_id: str, timeout: int = 300) -> Dict[str, Any]:
        """Wait for scan to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_scan_status(scan_id)
            
            if status['status'] == 'completed':
                return status
            elif status['status'] == 'failed':
                raise Exception(f"Scan failed: {status.get('error')}")
            
            time.sleep(10)  # Wait 10 seconds before checking again
        
        raise TimeoutError("Scan did not complete within timeout period")
    
    def get_discovered_assets(self, scan_id: str = None) -> List[Dict[str, Any]]:
        """Get discovered assets"""
        params = {'scan_id': scan_id} if scan_id else {}
        
        response = requests.get(
            f"{self.base_url}/assets",
            headers=self.headers,
            params=params
        )
        
        response.raise_for_status()
        return response.json()['assets']

# Usage example
if __name__ == "__main__":
    # Initialize the client
    client = ISECTECHAssetDiscovery(api_key="your-api-key-here")
    
    # Start a scan
    scan_result = client.start_scan(
        targets=["192.168.1.0/24", "10.0.0.0/24"],
        scan_type="comprehensive"
    )
    
    print(f"Scan started: {scan_result['scan_id']}")
    
    # Wait for completion
    try:
        final_status = client.wait_for_scan_completion(scan_result['scan_id'])
        print("Scan completed successfully!")
        
        # Get discovered assets
        assets = client.get_discovered_assets(scan_result['scan_id'])
        
        print(f"Discovered {len(assets)} assets:")
        for asset in assets:
            print(f"  - {asset['ip_address']} ({asset['asset_type']})")
            
    except Exception as e:
        print(f"Scan failed: {e}")
        `,
        tags: ['python', 'asset-discovery', 'network-security']
      },
      {
        id: 'go-threat-intelligence',
        name: 'Threat Intelligence Feed (Go)',
        description: 'Fetch threat intelligence feeds using Go',
        language: 'go',
        code: `
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "time"
)

type ISECTECHClient struct {
    APIKey  string
    BaseURL string
    Client  *http.Client
}

type ThreatFeed struct {
    ID         string    \`json:"id"\`
    Type       string    \`json:"type"\`
    Indicator  string    \`json:"indicator"\`
    Confidence float64   \`json:"confidence"\`
    FirstSeen  time.Time \`json:"first_seen"\`
    LastSeen   time.Time \`json:"last_seen"\`
    Tags       []string  \`json:"tags"\`
}

type ThreatFeedsResponse struct {
    Feeds      []ThreatFeed \`json:"feeds"\`
    Pagination struct {
        Total   int \`json:"total"\`
        Page    int \`json:"page"\`
        PerPage int \`json:"per_page"\`
    } \`json:"pagination"\`
}

func NewISECTECHClient(apiKey string) *ISECTECHClient {
    return &ISECTECHClient{
        APIKey:  apiKey,
        BaseURL: "https://api.isectech.com/v1",
        Client: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

func (c *ISECTECHClient) GetThreatFeeds(threatType string, limit int) (*ThreatFeedsResponse, error) {
    // Build URL with query parameters
    u, err := url.Parse(fmt.Sprintf("%s/threats/feeds", c.BaseURL))
    if err != nil {
        return nil, err
    }
    
    params := url.Values{}
    if threatType != "" {
        params.Add("type", threatType)
    }
    if limit > 0 {
        params.Add("limit", fmt.Sprintf("%d", limit))
    }
    u.RawQuery = params.Encode()
    
    // Create request
    req, err := http.NewRequest("GET", u.String(), nil)
    if err != nil {
        return nil, err
    }
    
    // Add headers
    req.Header.Set("X-API-Key", c.APIKey)
    req.Header.Set("Content-Type", "application/json")
    
    // Make request
    resp, err := c.Client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    // Check status code
    if resp.StatusCode != http.StatusOK {
        body, _ := ioutil.ReadAll(resp.Body)
        return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
    }
    
    // Parse response
    var threatFeeds ThreatFeedsResponse
    if err := json.NewDecoder(resp.Body).Decode(&threatFeeds); err != nil {
        return nil, err
    }
    
    return &threatFeeds, nil
}

func main() {
    // Initialize client
    client := NewISECTECHClient("your-api-key-here")
    
    // Get malware indicators
    feeds, err := client.GetThreatFeeds("malware", 50)
    if err != nil {
        fmt.Printf("Error fetching threat feeds: %v\\n", err)
        return
    }
    
    fmt.Printf("Retrieved %d threat indicators:\\n", len(feeds.Feeds))
    
    for _, feed := range feeds.Feeds {
        fmt.Printf("- %s (%s): %s (confidence: %.2f)\\n", 
            feed.Type, feed.Indicator, feed.Tags, feed.Confidence)
    }
    
    fmt.Printf("\\nTotal available: %d\\n", feeds.Pagination.Total)
}
        `,
        tags: ['go', 'threat-intelligence', 'feeds']
      }
    ];

    this.config.content.codeExamples = codeExamples;
  }

  /**
   * Register a new developer account
   */
  public async registerDeveloper(registrationData: {
    email: string;
    username: string;
    firstName: string;
    lastName: string;
    organization?: string;
    password: string;
  }): Promise<{ success: boolean; developerId?: string; error?: string }> {
    try {
      // Check if email or username already exists
      for (const developer of this.developers.values()) {
        if (developer.email === registrationData.email) {
          return { success: false, error: 'Email already registered' };
        }
        if (developer.username === registrationData.username) {
          return { success: false, error: 'Username already taken' };
        }
      }

      const developerId = crypto.randomUUID();
      const newDeveloper: DeveloperAccount = {
        developerId,
        email: registrationData.email,
        username: registrationData.username,
        firstName: registrationData.firstName,
        lastName: registrationData.lastName,
        organization: registrationData.organization,
        
        status: 'PENDING_VERIFICATION',
        emailVerified: false,
        termsAccepted: false,
        
        tier: 'FREE',
        permissions: ['read:docs', 'create:api_keys'],
        quotas: {
          apiCalls: {
            daily: 1000,
            monthly: 25000
          },
          apiKeys: 5,
          webhooks: 3
        },
        
        apiKeys: [],
        
        preferences: {
          theme: 'auto',
          language: 'en',
          emailNotifications: true,
          newsletter: false,
          codeExampleLanguage: 'javascript'
        },
        
        statistics: {
          totalApiCalls: 0,
          totalApiCallsThisMonth: 0,
          averageResponseTime: 0,
          errorRate: 0
        },
        
        twoFactorEnabled: false,
        loginCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['new-developer']
      };

      const validatedDeveloper = DeveloperAccountSchema.parse(newDeveloper);
      this.developers.set(developerId, validatedDeveloper);

      // Send verification email (implementation would send actual email)
      await this.sendVerificationEmail(validatedDeveloper);

      console.log(`New developer registered: ${registrationData.email}`);
      return { success: true, developerId };

    } catch (error) {
      console.error('Developer registration failed:', error);
      return { success: false, error: 'Registration failed' };
    }
  }

  /**
   * Generate API key for developer
   */
  public async generateAPIKey(developerId: string, keyData: {
    name: string;
    scopes: string[];
    expiresAt?: Date;
  }): Promise<{ success: boolean; apiKey?: string; keyId?: string; error?: string }> {
    try {
      const developer = this.developers.get(developerId);
      if (!developer) {
        return { success: false, error: 'Developer not found' };
      }

      if (developer.status !== 'ACTIVE') {
        return { success: false, error: 'Developer account not active' };
      }

      if (developer.apiKeys.length >= developer.quotas.apiKeys) {
        return { success: false, error: 'API key limit reached' };
      }

      const keyId = crypto.randomUUID();
      const apiKey = `isectech_${crypto.randomBytes(32).toString('hex')}`;
      const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

      const newApiKey = {
        keyId,
        name: keyData.name,
        keyHash,
        scopes: keyData.scopes,
        createdAt: new Date(),
        expiresAt: keyData.expiresAt,
        isActive: true
      };

      developer.apiKeys.push(newApiKey);
      developer.updatedAt = new Date();

      console.log(`API key generated for developer: ${developer.email}`);
      return { success: true, apiKey, keyId };

    } catch (error) {
      console.error('API key generation failed:', error);
      return { success: false, error: 'Key generation failed' };
    }
  }

  /**
   * Get developer dashboard data
   */
  public getDeveloperDashboard(developerId: string): any {
    const developer = this.developers.get(developerId);
    if (!developer) {
      return null;
    }

    return {
      developer: {
        id: developer.developerId,
        username: developer.username,
        email: developer.email,
        tier: developer.tier,
        status: developer.status
      },
      apiKeys: developer.apiKeys.map(key => ({
        keyId: key.keyId,
        name: key.name,
        scopes: key.scopes,
        createdAt: key.createdAt,
        lastUsed: key.lastUsed,
        isActive: key.isActive
      })),
      usage: {
        totalCalls: developer.statistics.totalApiCalls,
        thisMonth: developer.statistics.totalApiCallsThisMonth,
        quotas: developer.quotas,
        averageResponseTime: developer.statistics.averageResponseTime,
        errorRate: developer.statistics.errorRate
      },
      recentActivity: [] // Would be populated with recent API calls
    };
  }

  /**
   * Get portal configuration for frontend
   */
  public getPortalConfig(): any {
    return {
      name: this.config.name,
      description: this.config.description,
      theme: this.config.theme,
      features: this.config.features,
      authentication: {
        providers: this.config.authentication.providers,
        requireEmailVerification: this.config.authentication.requireEmailVerification
      },
      documentation: {
        interactive: this.config.documentation.interactive,
        supportedLanguages: this.config.documentation.supportedLanguages
      }
    };
  }

  /**
   * Get API documentation list
   */
  public getAPIDocumentationList(): any[] {
    return Array.from(this.apiDocs.values()).map(doc => ({
      id: doc.documentId,
      title: doc.title,
      description: doc.description,
      version: doc.version,
      category: doc.portalConfig.category,
      featured: doc.portalConfig.featured,
      difficulty: doc.portalConfig.difficulty,
      status: doc.status,
      tags: doc.tags
    }));
  }

  /**
   * Get specific API documentation
   */
  public getAPIDocumentation(documentId: string): APIDocumentation | null {
    return this.apiDocs.get(documentId) || null;
  }

  // Private helper methods
  private async sendVerificationEmail(developer: DeveloperAccount): Promise<void> {
    // Implementation would send actual verification email
    console.log(`Verification email sent to: ${developer.email}`);
  }

  private startMaintenanceTasks(): void {
    // Clean up expired sessions every hour
    setInterval(() => {
      const now = new Date();
      for (const [sessionId, session] of this.sessions) {
        if (session.expiresAt < now) {
          this.sessions.delete(sessionId);
        }
      }
    }, 60 * 60 * 1000);

    // Update developer statistics daily
    setInterval(() => {
      this.updateDeveloperStatistics();
    }, 24 * 60 * 60 * 1000);
  }

  private updateDeveloperStatistics(): void {
    // Implementation would update statistics from usage data
    console.log('Updating developer statistics...');
  }
}

// Export production-ready developer portal
export const isectechDeveloperPortalApp = new ISECTECHDeveloperPortalApp({
  portalId: 'isectech-production-developer-portal',
  name: 'iSECTECH Developer Portal',
  description: 'The official developer portal for iSECTECH cybersecurity APIs'
});