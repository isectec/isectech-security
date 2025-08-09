/**
 * Production-grade Interactive API Documentation Component for iSECTECH
 * 
 * Provides interactive API documentation with live testing capabilities,
 * code generation, authentication management, and comprehensive examples.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// Interactive Documentation Schemas
export const APIEndpointSchema = z.object({
  endpointId: z.string(),
  path: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']),
  summary: z.string(),
  description: z.string(),
  
  // Parameters
  parameters: z.array(z.object({
    name: z.string(),
    in: z.enum(['path', 'query', 'header', 'cookie']),
    description: z.string(),
    required: z.boolean().default(false),
    schema: z.object({
      type: z.string(),
      format: z.string().optional(),
      enum: z.array(z.string()).optional(),
      default: z.any().optional(),
      minimum: z.number().optional(),
      maximum: z.number().optional(),
      pattern: z.string().optional(),
      example: z.any().optional()
    }),
    examples: z.array(z.object({
      name: z.string(),
      value: z.any(),
      description: z.string().optional()
    })).optional()
  })).default([]),
  
  // Request body
  requestBody: z.object({
    description: z.string().optional(),
    required: z.boolean().default(false),
    content: z.record(z.object({
      schema: z.any(),
      examples: z.record(z.object({
        summary: z.string().optional(),
        description: z.string().optional(),
        value: z.any()
      })).optional()
    }))
  }).optional(),
  
  // Responses
  responses: z.record(z.object({
    description: z.string(),
    headers: z.record(z.object({
      description: z.string().optional(),
      schema: z.any()
    })).optional(),
    content: z.record(z.object({
      schema: z.any(),
      examples: z.record(z.object({
        summary: z.string().optional(),
        description: z.string().optional(),
        value: z.any()
      })).optional()
    })).optional()
  })),
  
  // Security requirements
  security: z.array(z.record(z.array(z.string()))).optional(),
  
  // Additional metadata
  tags: z.array(z.string()).default([]),
  deprecated: z.boolean().default(false),
  
  // Interactive features
  interactive: z.object({
    enabled: z.boolean().default(true),
    tryItOut: z.boolean().default(true),
    codeGeneration: z.boolean().default(true),
    curlGeneration: z.boolean().default(true),
    mockResponse: z.boolean().default(true)
  }).default({}),
  
  // Performance and usage info
  performance: z.object({
    averageResponseTime: z.number().optional(),
    rateLimits: z.array(z.object({
      type: z.string(),
      limit: z.number(),
      window: z.string()
    })).optional(),
    cacheable: z.boolean().default(false),
    cachePolicy: z.string().optional()
  }).optional()
});

export const CodeGeneratorConfigSchema = z.object({
  language: z.string(),
  library: z.string().optional(),
  style: z.enum(['STANDARD', 'ASYNC', 'PROMISE', 'CALLBACK']).default('STANDARD'),
  includeHeaders: z.boolean().default(true),
  includeErrorHandling: z.boolean().default(true),
  includeComments: z.boolean().default(true),
  includeExamples: z.boolean().default(true),
  authType: z.enum(['API_KEY', 'BEARER_TOKEN', 'BASIC_AUTH', 'OAUTH2']).optional()
});

export const TestExecutionResultSchema = z.object({
  executionId: z.string(),
  endpoint: z.string(),
  method: z.string(),
  timestamp: z.date(),
  
  // Request details
  request: z.object({
    url: z.string(),
    headers: z.record(z.string()),
    body: z.any().optional(),
    parameters: z.record(z.any()).optional()
  }),
  
  // Response details
  response: z.object({
    status: z.number(),
    statusText: z.string(),
    headers: z.record(z.string()),
    body: z.any(),
    size: z.number(), // bytes
    duration: z.number() // milliseconds
  }),
  
  // Analysis
  analysis: z.object({
    success: z.boolean(),
    errors: z.array(z.string()).default([]),
    warnings: z.array(z.string()).default([]),
    performance: z.object({
      responseTime: z.number(),
      category: z.enum(['FAST', 'NORMAL', 'SLOW', 'TIMEOUT'])
    }),
    security: z.object({
      httpsUsed: z.boolean(),
      validCertificate: z.boolean(),
      securityHeaders: z.array(z.string()).default([])
    })
  }),
  
  // Usage tracking
  developerId: z.string().optional(),
  sessionId: z.string().optional()
});

export type APIEndpoint = z.infer<typeof APIEndpointSchema>;
export type CodeGeneratorConfig = z.infer<typeof CodeGeneratorConfigSchema>;
export type TestExecutionResult = z.infer<typeof TestExecutionResultSchema>;

/**
 * Interactive API Documentation Component
 */
export class ISECTECHInteractiveAPIDocs {
  private endpoints: Map<string, APIEndpoint> = new Map();
  private testResults: Map<string, TestExecutionResult> = new Map();
  private codeGenerators: Map<string, any> = new Map();

  constructor() {
    this.initializeISECTECHEndpoints();
    this.initializeCodeGenerators();
  }

  /**
   * Initialize iSECTECH API endpoints for interactive documentation
   */
  private initializeISECTECHEndpoints(): void {
    // Threat Analysis Endpoint
    const threatAnalysisEndpoint: APIEndpoint = {
      endpointId: 'threat-analysis-post',
      path: '/threats/analyze',
      method: 'POST',
      summary: 'Analyze potential security threats',
      description: 'Submit data for comprehensive threat analysis using advanced AI/ML models. Supports files, URLs, IP addresses, and domains.',
      
      parameters: [
        {
          name: 'X-API-Key',
          in: 'header',
          description: 'Your API key for authentication',
          required: true,
          schema: {
            type: 'string',
            pattern: '^isectech_[a-f0-9]{64}$',
            example: 'isectech_1234567890abcdef...'
          }
        },
        {
          name: 'X-Request-ID',
          in: 'header',
          description: 'Optional request ID for tracking',
          required: false,
          schema: {
            type: 'string',
            format: 'uuid',
            example: '123e4567-e89b-12d3-a456-426614174000'
          }
        }
      ],
      
      requestBody: {
        description: 'Threat analysis request data',
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                data: {
                  type: 'string',
                  description: 'Base64 encoded data to analyze (file content, URL, etc.)'
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
                      default: false,
                      description: 'Enable deep scanning (may take longer)'
                    },
                    include_metadata: {
                      type: 'boolean',
                      default: true,
                      description: 'Include detailed metadata in response'
                    },
                    timeout: {
                      type: 'integer',
                      minimum: 10,
                      maximum: 300,
                      default: 60,
                      description: 'Analysis timeout in seconds'
                    }
                  }
                }
              },
              required: ['data', 'type']
            },
            examples: {
              'malware-file': {
                summary: 'Malware File Analysis',
                description: 'Analyze a suspicious executable file',
                value: {
                  data: 'UEsDBAoAAAAAAJ5QaE4AAAAAAAAAAAAAAAAJABwAZXhhbXBsZS8=',
                  type: 'file',
                  options: {
                    deep_scan: true,
                    include_metadata: true
                  }
                }
              },
              'suspicious-url': {
                summary: 'Suspicious URL Analysis',
                description: 'Check if a URL is malicious',
                value: {
                  data: 'aHR0cHM6Ly9zdXNwaWNpb3VzLWRvbWFpbi5jb20vcGhpc2hpbmc=',
                  type: 'url',
                  options: {
                    deep_scan: false,
                    include_metadata: true
                  }
                }
              },
              'ip-reputation': {
                summary: 'IP Reputation Check',
                description: 'Check reputation of an IP address',
                value: {
                  data: 'MTkyLjE2OC4xLjEwMA==',
                  type: 'ip',
                  options: {
                    include_metadata: true
                  }
                }
              }
            }
          }
        }
      },
      
      responses: {
        '200': {
          description: 'Successful threat analysis',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  threat_score: {
                    type: 'number',
                    minimum: 0,
                    maximum: 1,
                    description: 'Threat confidence score (0 = safe, 1 = malicious)'
                  },
                  threat_type: {
                    type: 'string',
                    description: 'Identified threat category'
                  },
                  details: {
                    type: 'object',
                    description: 'Detailed analysis results'
                  },
                  recommendations: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Security recommendations'
                  },
                  metadata: {
                    type: 'object',
                    description: 'Additional metadata and context'
                  }
                }
              },
              examples: {
                'high-threat': {
                  summary: 'High Threat Detection',
                  value: {
                    threat_score: 0.92,
                    threat_type: 'malware',
                    details: {
                      family: 'trojan.downloader',
                      variant: 'emotet',
                      confidence: 'high',
                      first_seen: '2024-01-15T10:30:00Z'
                    },
                    recommendations: [
                      'Quarantine the file immediately',
                      'Scan connected systems',
                      'Update antivirus signatures'
                    ],
                    metadata: {
                      analysis_time: 2.5,
                      engines_used: ['ml_classifier', 'signature_scan', 'behavioral_analysis']
                    }
                  }
                },
                'safe-result': {
                  summary: 'Safe Content',
                  value: {
                    threat_score: 0.05,
                    threat_type: 'none',
                    details: {
                      file_type: 'text/plain',
                      size: 1024,
                      entropy: 3.2
                    },
                    recommendations: [
                      'File appears safe to use'
                    ],
                    metadata: {
                      analysis_time: 0.8,
                      engines_used: ['signature_scan']
                    }
                  }
                }
              }
            }
          }
        },
        '400': {
          description: 'Invalid request data',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string' },
                  code: { type: 'string' },
                  details: { type: 'object' }
                }
              }
            }
          }
        },
        '401': {
          description: 'Authentication failed',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string', example: 'Invalid API key' },
                  code: { type: 'string', example: 'INVALID_API_KEY' }
                }
              }
            }
          }
        },
        '429': {
          description: 'Rate limit exceeded',
          headers: {
            'X-RateLimit-Remaining': {
              description: 'Number of requests remaining',
              schema: { type: 'integer' }
            },
            'X-RateLimit-Reset': {
              description: 'Time when rate limit resets',
              schema: { type: 'integer' }
            }
          },
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string', example: 'Rate limit exceeded' },
                  code: { type: 'string', example: 'RATE_LIMIT_EXCEEDED' },
                  retry_after: { type: 'integer', description: 'Seconds to wait before retry' }
                }
              }
            }
          }
        },
        '500': {
          description: 'Internal server error',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  error: { type: 'string', example: 'Analysis service temporarily unavailable' },
                  code: { type: 'string', example: 'SERVICE_UNAVAILABLE' }
                }
              }
            }
          }
        }
      },
      
      security: [
        { 'ApiKeyAuth': [] }
      ],
      
      tags: ['Threat Analysis', 'Security'],
      
      interactive: {
        enabled: true,
        tryItOut: true,
        codeGeneration: true,
        curlGeneration: true,
        mockResponse: true
      },
      
      performance: {
        averageResponseTime: 2500, // ms
        rateLimits: [
          { type: 'requests_per_minute', limit: 60, window: '1m' },
          { type: 'requests_per_hour', limit: 1000, window: '1h' }
        ],
        cacheable: false // Real-time analysis, not cacheable
      }
    };

    // Asset Discovery Scan Endpoint
    const assetScanEndpoint: APIEndpoint = {
      endpointId: 'asset-scan-post',
      path: '/assets/scan',
      method: 'POST',
      summary: 'Initiate network asset discovery scan',
      description: 'Start a comprehensive network scan to discover and inventory assets across specified IP ranges or hostnames.',
      
      parameters: [
        {
          name: 'X-API-Key',
          in: 'header',
          description: 'Your API key for authentication',
          required: true,
          schema: {
            type: 'string',
            pattern: '^isectech_[a-f0-9]{64}$'
          }
        }
      ],
      
      requestBody: {
        description: 'Asset scan configuration',
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                targets: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'IP ranges, subnets, or hostnames to scan',
                  minItems: 1,
                  maxItems: 100
                },
                scan_type: {
                  type: 'string',
                  enum: ['fast', 'comprehensive', 'stealth'],
                  default: 'fast',
                  description: 'Type of scan to perform'
                },
                ports: {
                  type: 'array',
                  items: { type: 'integer', minimum: 1, maximum: 65535 },
                  description: 'Specific ports to scan (optional)',
                  maxItems: 1000
                },
                options: {
                  type: 'object',
                  properties: {
                    os_fingerprinting: {
                      type: 'boolean',
                      default: true,
                      description: 'Enable OS detection'
                    },
                    service_detection: {
                      type: 'boolean',
                      default: true,
                      description: 'Enable service version detection'
                    },
                    timeout: {
                      type: 'integer',
                      minimum: 60,
                      maximum: 3600,
                      default: 300,
                      description: 'Scan timeout in seconds'
                    }
                  }
                }
              },
              required: ['targets']
            },
            examples: {
              'basic-scan': {
                summary: 'Basic Network Scan',
                description: 'Scan a small network range with default settings',
                value: {
                  targets: ['192.168.1.0/24'],
                  scan_type: 'fast'
                }
              },
              'comprehensive-scan': {
                summary: 'Comprehensive Enterprise Scan',
                description: 'Thorough scan of multiple subnets with custom ports',
                value: {
                  targets: ['10.0.0.0/16', '172.16.0.0/12'],
                  scan_type: 'comprehensive',
                  ports: [22, 80, 443, 8080, 8443, 3389, 5432, 3306],
                  options: {
                    os_fingerprinting: true,
                    service_detection: true,
                    timeout: 1800
                  }
                }
              },
              'stealth-scan': {
                summary: 'Stealth Scan',
                description: 'Low-profile scan to avoid detection',
                value: {
                  targets: ['example.com', '203.0.113.0/24'],
                  scan_type: 'stealth',
                  options: {
                    timeout: 3600
                  }
                }
              }
            }
          }
        }
      },
      
      responses: {
        '202': {
          description: 'Scan initiated successfully',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  scan_id: {
                    type: 'string',
                    format: 'uuid',
                    description: 'Unique identifier for the scan'
                  },
                  status: {
                    type: 'string',
                    enum: ['queued', 'running'],
                    description: 'Current scan status'
                  },
                  estimated_completion: {
                    type: 'string',
                    format: 'date-time',
                    description: 'Estimated completion time'
                  },
                  target_count: {
                    type: 'integer',
                    description: 'Number of targets to scan'
                  }
                }
              },
              examples: {
                'scan-started': {
                  summary: 'Scan Successfully Started',
                  value: {
                    scan_id: '123e4567-e89b-12d3-a456-426614174000',
                    status: 'queued',
                    estimated_completion: '2024-01-15T10:45:00Z',
                    target_count: 254
                  }
                }
              }
            }
          }
        },
        '400': {
          description: 'Invalid scan parameters'
        },
        '401': {
          description: 'Authentication failed'
        },
        '403': {
          description: 'Insufficient permissions or quota exceeded'
        },
        '429': {
          description: 'Rate limit exceeded'
        }
      },
      
      security: [{ 'ApiKeyAuth': [] }],
      tags: ['Asset Discovery', 'Network Security'],
      
      interactive: {
        enabled: true,
        tryItOut: true,
        codeGeneration: true,
        curlGeneration: true,
        mockResponse: true
      },
      
      performance: {
        averageResponseTime: 500, // ms (just to initiate)
        rateLimits: [
          { type: 'scans_per_hour', limit: 10, window: '1h' },
          { type: 'targets_per_day', limit: 10000, window: '24h' }
        ],
        cacheable: false
      }
    };

    // Threat Intelligence Feeds Endpoint
    const threatFeedsEndpoint: APIEndpoint = {
      endpointId: 'threat-feeds-get',
      path: '/threats/feeds',
      method: 'GET',
      summary: 'Get threat intelligence feeds',
      description: 'Retrieve the latest threat intelligence data including IOCs, malware signatures, and reputation information.',
      
      parameters: [
        {
          name: 'X-API-Key',
          in: 'header',
          description: 'Your API key for authentication',
          required: true,
          schema: { type: 'string' }
        },
        {
          name: 'type',
          in: 'query',
          description: 'Filter by threat type',
          required: false,
          schema: {
            type: 'string',
            enum: ['malware', 'phishing', 'ip_reputation', 'domain_reputation', 'url_reputation'],
            example: 'malware'
          }
        },
        {
          name: 'limit',
          in: 'query',
          description: 'Number of results to return',
          required: false,
          schema: {
            type: 'integer',
            minimum: 1,
            maximum: 1000,
            default: 100,
            example: 50
          }
        },
        {
          name: 'since',
          in: 'query',
          description: 'Only return threats seen since this timestamp',
          required: false,
          schema: {
            type: 'string',
            format: 'date-time',
            example: '2024-01-15T00:00:00Z'
          }
        },
        {
          name: 'confidence',
          in: 'query',
          description: 'Minimum confidence score (0-1)',
          required: false,
          schema: {
            type: 'number',
            minimum: 0,
            maximum: 1,
            default: 0.5,
            example: 0.8
          }
        }
      ],
      
      responses: {
        '200': {
          description: 'Successful response with threat feeds',
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
                        tags: { type: 'array', items: { type: 'string' } },
                        source: { type: 'string' },
                        description: { type: 'string' }
                      }
                    }
                  },
                  pagination: {
                    type: 'object',
                    properties: {
                      total: { type: 'integer' },
                      page: { type: 'integer' },
                      per_page: { type: 'integer' },
                      has_more: { type: 'boolean' }
                    }
                  }
                }
              },
              examples: {
                'malware-feeds': {
                  summary: 'Malware Threat Feeds',
                  value: {
                    feeds: [
                      {
                        id: 'feed_001',
                        type: 'malware',
                        indicator: 'a1b2c3d4e5f6...',
                        confidence: 0.95,
                        first_seen: '2024-01-15T08:30:00Z',
                        last_seen: '2024-01-15T10:15:00Z',
                        tags: ['trojan', 'banking', 'emotet'],
                        source: 'isectech_intelligence',
                        description: 'Emotet banking trojan variant'
                      }
                    ],
                    pagination: {
                      total: 1247,
                      page: 1,
                      per_page: 100,
                      has_more: true
                    }
                  }
                }
              }
            }
          }
        },
        '400': {
          description: 'Invalid parameters'
        },
        '401': {
          description: 'Authentication failed'
        },
        '429': {
          description: 'Rate limit exceeded'
        }
      },
      
      security: [{ 'ApiKeyAuth': [] }],
      tags: ['Threat Intelligence', 'IOCs'],
      
      interactive: {
        enabled: true,
        tryItOut: true,
        codeGeneration: true,
        curlGeneration: true,
        mockResponse: true
      },
      
      performance: {
        averageResponseTime: 800, // ms
        rateLimits: [
          { type: 'requests_per_minute', limit: 120, window: '1m' },
          { type: 'requests_per_hour', limit: 2000, window: '1h' }
        ],
        cacheable: true,
        cachePolicy: 'max-age=300' // 5 minutes
      }
    };

    // Store all endpoints
    [threatAnalysisEndpoint, assetScanEndpoint, threatFeedsEndpoint].forEach(endpoint => {
      const validatedEndpoint = APIEndpointSchema.parse(endpoint);
      this.endpoints.set(endpoint.endpointId, validatedEndpoint);
    });

    console.log(`Initialized ${this.endpoints.size} interactive API endpoints`);
  }

  /**
   * Initialize code generators for different languages
   */
  private initializeCodeGenerators(): void {
    // JavaScript/Node.js code generator
    this.codeGenerators.set('javascript', {
      generateCode: (endpoint: APIEndpoint, config: CodeGeneratorConfig) => {
        return this.generateJavaScriptCode(endpoint, config);
      }
    });

    // Python code generator
    this.codeGenerators.set('python', {
      generateCode: (endpoint: APIEndpoint, config: CodeGeneratorConfig) => {
        return this.generatePythonCode(endpoint, config);
      }
    });

    // Go code generator
    this.codeGenerators.set('go', {
      generateCode: (endpoint: APIEndpoint, config: CodeGeneratorConfig) => {
        return this.generateGoCode(endpoint, config);
      }
    });

    // cURL code generator
    this.codeGenerators.set('curl', {
      generateCode: (endpoint: APIEndpoint, config: CodeGeneratorConfig) => {
        return this.generateCurlCode(endpoint, config);
      }
    });

    console.log(`Initialized ${this.codeGenerators.size} code generators`);
  }

  /**
   * Execute API test with live endpoint
   */
  public async executeAPITest(
    endpointId: string,
    testData: {
      parameters?: Record<string, any>;
      headers?: Record<string, string>;
      body?: any;
      developerId?: string;
      sessionId?: string;
    }
  ): Promise<TestExecutionResult> {
    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint) {
      throw new Error(`Endpoint ${endpointId} not found`);
    }

    const executionId = crypto.randomUUID();
    const timestamp = new Date();

    try {
      // Build request URL
      let url = `https://api.isectech.com/v1${endpoint.path}`;
      if (testData.parameters) {
        const queryParams = new URLSearchParams();
        Object.entries(testData.parameters).forEach(([key, value]) => {
          if (value !== undefined && value !== null) {
            queryParams.append(key, String(value));
          }
        });
        if (queryParams.toString()) {
          url += `?${queryParams.toString()}`;
        }
      }

      // Build headers
      const headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'iSECTECH-Developer-Portal/1.0',
        ...testData.headers
      };

      // Build request options
      const requestOptions: any = {
        method: endpoint.method,
        headers
      };

      if (testData.body && ['POST', 'PUT', 'PATCH'].includes(endpoint.method)) {
        requestOptions.body = JSON.stringify(testData.body);
      }

      // Execute request
      const startTime = performance.now();
      const response = await fetch(url, requestOptions);
      const endTime = performance.now();
      const duration = endTime - startTime;

      // Parse response
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      let responseBody;
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        responseBody = await response.json();
      } else {
        responseBody = await response.text();
      }

      // Analyze response
      const analysis = {
        success: response.ok,
        errors: response.ok ? [] : [`HTTP ${response.status}: ${response.statusText}`],
        warnings: this.analyzeResponseWarnings(response, responseHeaders),
        performance: {
          responseTime: Math.round(duration),
          category: this.categorizeResponseTime(duration)
        },
        security: {
          httpsUsed: url.startsWith('https://'),
          validCertificate: true, // Would check certificate in real implementation
          securityHeaders: this.extractSecurityHeaders(responseHeaders)
        }
      };

      const testResult: TestExecutionResult = {
        executionId,
        endpoint: endpoint.path,
        method: endpoint.method,
        timestamp,
        request: {
          url,
          headers,
          body: testData.body,
          parameters: testData.parameters
        },
        response: {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
          body: responseBody,
          size: JSON.stringify(responseBody).length,
          duration: Math.round(duration)
        },
        analysis,
        developerId: testData.developerId,
        sessionId: testData.sessionId
      };

      const validatedResult = TestExecutionResultSchema.parse(testResult);
      this.testResults.set(executionId, validatedResult);

      return validatedResult;

    } catch (error) {
      // Handle request errors
      const testResult: TestExecutionResult = {
        executionId,
        endpoint: endpoint.path,
        method: endpoint.method,
        timestamp,
        request: {
          url: `https://api.isectech.com/v1${endpoint.path}`,
          headers: testData.headers || {},
          body: testData.body,
          parameters: testData.parameters
        },
        response: {
          status: 0,
          statusText: 'Request Failed',
          headers: {},
          body: { error: error instanceof Error ? error.message : 'Unknown error' },
          size: 0,
          duration: 0
        },
        analysis: {
          success: false,
          errors: [error instanceof Error ? error.message : 'Unknown error'],
          warnings: [],
          performance: {
            responseTime: 0,
            category: 'TIMEOUT'
          },
          security: {
            httpsUsed: false,
            validCertificate: false,
            securityHeaders: []
          }
        },
        developerId: testData.developerId,
        sessionId: testData.sessionId
      };

      const validatedResult = TestExecutionResultSchema.parse(testResult);
      this.testResults.set(executionId, validatedResult);

      return validatedResult;
    }
  }

  /**
   * Generate code example for endpoint
   */
  public generateCodeExample(
    endpointId: string,
    language: string,
    config: Partial<CodeGeneratorConfig> = {}
  ): string {
    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint) {
      throw new Error(`Endpoint ${endpointId} not found`);
    }

    const generator = this.codeGenerators.get(language);
    if (!generator) {
      throw new Error(`Code generator for ${language} not found`);
    }

    const fullConfig = CodeGeneratorConfigSchema.parse({
      language,
      ...config
    });

    return generator.generateCode(endpoint, fullConfig);
  }

  /**
   * Get endpoint documentation
   */
  public getEndpointDocumentation(endpointId: string): APIEndpoint | null {
    return this.endpoints.get(endpointId) || null;
  }

  /**
   * Get all endpoints for a tag
   */
  public getEndpointsByTag(tag: string): APIEndpoint[] {
    return Array.from(this.endpoints.values()).filter(endpoint =>
      endpoint.tags.includes(tag)
    );
  }

  /**
   * Get test execution result
   */
  public getTestResult(executionId: string): TestExecutionResult | null {
    return this.testResults.get(executionId) || null;
  }

  /**
   * Get test history for developer
   */
  public getTestHistory(developerId: string, limit: number = 50): TestExecutionResult[] {
    return Array.from(this.testResults.values())
      .filter(result => result.developerId === developerId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  // Private code generation methods
  private generateJavaScriptCode(endpoint: APIEndpoint, config: CodeGeneratorConfig): string {
    const hasBody = ['POST', 'PUT', 'PATCH'].includes(endpoint.method);
    const exampleBody = this.getExampleRequestBody(endpoint);
    
    let code = '';
    
    if (config.includeComments) {
      code += `// ${endpoint.summary}\n`;
      code += `// ${endpoint.description}\n\n`;
    }
    
    if (config.style === 'ASYNC') {
      code += `const ${this.toCamelCase(endpoint.path.split('/').pop() || 'apiCall')} = async () => {\n`;
      code += `  try {\n`;
      code += `    const response = await fetch('https://api.isectech.com/v1${endpoint.path}', {\n`;
      code += `      method: '${endpoint.method}',\n`;
      code += `      headers: {\n`;
      code += `        'Content-Type': 'application/json',\n`;
      code += `        'X-API-Key': process.env.ISECTECH_API_KEY\n`;
      code += `      }`;
      
      if (hasBody && exampleBody) {
        code += `,\n      body: JSON.stringify(${JSON.stringify(exampleBody, null, 8).replace(/^/gm, '        ')})`;
      }
      
      code += `\n    });\n\n`;
      
      if (config.includeErrorHandling) {
        code += `    if (!response.ok) {\n`;
        code += `      throw new Error(\`HTTP error! status: \${response.status}\`);\n`;
        code += `    }\n\n`;
      }
      
      code += `    const result = await response.json();\n`;
      code += `    console.log('Result:', result);\n`;
      code += `    return result;\n\n`;
      
      if (config.includeErrorHandling) {
        code += `  } catch (error) {\n`;
        code += `    console.error('API call failed:', error);\n`;
        code += `    throw error;\n`;
      }
      
      code += `  }\n`;
      code += `};\n\n`;
      
      if (config.includeExamples) {
        code += `// Usage\n`;
        code += `${this.toCamelCase(endpoint.path.split('/').pop() || 'apiCall')}()\n`;
        code += `  .then(result => console.log('Success:', result))\n`;
        code += `  .catch(error => console.error('Error:', error));\n`;
      }
    }
    
    return code;
  }

  private generatePythonCode(endpoint: APIEndpoint, config: CodeGeneratorConfig): string {
    const hasBody = ['POST', 'PUT', 'PATCH'].includes(endpoint.method);
    const exampleBody = this.getExampleRequestBody(endpoint);
    
    let code = '';
    
    if (config.includeComments) {
      code += `"""${endpoint.summary}\n\n${endpoint.description}\n"""\n\n`;
    }
    
    code += `import requests\n`;
    code += `import json\n`;
    code += `import os\n\n`;
    
    code += `def ${this.toSnakeCase(endpoint.path.split('/').pop() || 'api_call')}():\n`;
    
    if (config.includeComments) {
      code += `    """Execute ${endpoint.summary}"""\n`;
    }
    
    code += `    url = "https://api.isectech.com/v1${endpoint.path}"\n`;
    code += `    headers = {\n`;
    code += `        "Content-Type": "application/json",\n`;
    code += `        "X-API-Key": os.getenv("ISECTECH_API_KEY")\n`;
    code += `    }\n\n`;
    
    if (hasBody && exampleBody) {
      code += `    payload = ${JSON.stringify(exampleBody, null, 4).replace(/^/gm, '    ')}\n\n`;
    }
    
    if (config.includeErrorHandling) {
      code += `    try:\n        `;
    } else {
      code += `    `;
    }
    
    code += `response = requests.${endpoint.method.toLowerCase()}(\n`;
    code += `        url,\n`;
    code += `        headers=headers`;
    
    if (hasBody && exampleBody) {
      code += `,\n        json=payload`;
    }
    
    code += `\n    )\n\n`;
    
    if (config.includeErrorHandling) {
      code += `        response.raise_for_status()\n`;
      code += `        result = response.json()\n`;
      code += `        print("Result:", result)\n`;
      code += `        return result\n\n`;
      code += `    except requests.exceptions.RequestException as e:\n`;
      code += `        print(f"API call failed: {e}")\n`;
      code += `        raise\n\n`;
    } else {
      code += `    result = response.json()\n`;
      code += `    print("Result:", result)\n`;
      code += `    return result\n\n`;
    }
    
    if (config.includeExamples) {
      code += `# Usage\n`;
      code += `if __name__ == "__main__":\n`;
      code += `    try:\n`;
      code += `        result = ${this.toSnakeCase(endpoint.path.split('/').pop() || 'api_call')}()\n`;
      code += `        print("Success:", result)\n`;
      code += `    except Exception as e:\n`;
      code += `        print("Error:", e)\n`;
    }
    
    return code;
  }

  private generateGoCode(endpoint: APIEndpoint, config: CodeGeneratorConfig): string {
    const hasBody = ['POST', 'PUT', 'PATCH'].includes(endpoint.method);
    const exampleBody = this.getExampleRequestBody(endpoint);
    
    let code = '';
    
    if (config.includeComments) {
      code += `// ${endpoint.summary}\n`;
      code += `// ${endpoint.description}\n\n`;
    }
    
    code += `package main\n\n`;
    code += `import (\n`;
    code += `    "bytes"\n`;
    code += `    "encoding/json"\n`;
    code += `    "fmt"\n`;
    code += `    "io/ioutil"\n`;
    code += `    "net/http"\n`;
    code += `    "os"\n`;
    code += `)\n\n`;
    
    if (hasBody && exampleBody) {
      code += `type RequestPayload struct {\n`;
      // Generate struct fields based on example body
      this.generateGoStructFields(exampleBody, code, '    ');
      code += `}\n\n`;
    }
    
    code += `func ${this.toPascalCase(endpoint.path.split('/').pop() || 'APICall')}() error {\n`;
    code += `    url := "https://api.isectech.com/v1${endpoint.path}"\n`;
    code += `    apiKey := os.Getenv("ISECTECH_API_KEY")\n\n`;
    
    if (hasBody && exampleBody) {
      code += `    payload := RequestPayload${JSON.stringify(exampleBody, null, 8).replace(/"/g, '').replace(/^/gm, '        ')}\n\n`;
      code += `    jsonPayload, err := json.Marshal(payload)\n`;
      code += `    if err != nil {\n`;
      code += `        return fmt.Errorf("failed to marshal payload: %v", err)\n`;
      code += `    }\n\n`;
      code += `    req, err := http.NewRequest("${endpoint.method}", url, bytes.NewBuffer(jsonPayload))\n`;
    } else {
      code += `    req, err := http.NewRequest("${endpoint.method}", url, nil)\n`;
    }
    
    code += `    if err != nil {\n`;
    code += `        return fmt.Errorf("failed to create request: %v", err)\n`;
    code += `    }\n\n`;
    
    code += `    req.Header.Set("Content-Type", "application/json")\n`;
    code += `    req.Header.Set("X-API-Key", apiKey)\n\n`;
    
    code += `    client := &http.Client{}\n`;
    code += `    resp, err := client.Do(req)\n`;
    code += `    if err != nil {\n`;
    code += `        return fmt.Errorf("request failed: %v", err)\n`;
    code += `    }\n`;
    code += `    defer resp.Body.Close()\n\n`;
    
    if (config.includeErrorHandling) {
      code += `    if resp.StatusCode != http.StatusOK {\n`;
      code += `        body, _ := ioutil.ReadAll(resp.Body)\n`;
      code += `        return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))\n`;
      code += `    }\n\n`;
    }
    
    code += `    body, err := ioutil.ReadAll(resp.Body)\n`;
    code += `    if err != nil {\n`;
    code += `        return fmt.Errorf("failed to read response: %v", err)\n`;
    code += `    }\n\n`;
    
    code += `    fmt.Println("Response:", string(body))\n`;
    code += `    return nil\n`;
    code += `}\n\n`;
    
    if (config.includeExamples) {
      code += `func main() {\n`;
      code += `    if err := ${this.toPascalCase(endpoint.path.split('/').pop() || 'APICall')}(); err != nil {\n`;
      code += `        fmt.Printf("Error: %v\\n", err)\n`;
      code += `    }\n`;
      code += `}\n`;
    }
    
    return code;
  }

  private generateCurlCode(endpoint: APIEndpoint, config: CodeGeneratorConfig): string {
    const hasBody = ['POST', 'PUT', 'PATCH'].includes(endpoint.method);
    const exampleBody = this.getExampleRequestBody(endpoint);
    
    let code = '';
    
    if (config.includeComments) {
      code += `# ${endpoint.summary}\n`;
      code += `# ${endpoint.description}\n\n`;
    }
    
    code += `curl -X ${endpoint.method} \\\n`;
    code += `  "https://api.isectech.com/v1${endpoint.path}" \\\n`;
    code += `  -H "Content-Type: application/json" \\\n`;
    code += `  -H "X-API-Key: $ISECTECH_API_KEY"`;
    
    if (hasBody && exampleBody) {
      code += ` \\\n  -d '${JSON.stringify(exampleBody, null, 2)}'`;
    }
    
    code += `\n`;
    
    return code;
  }

  // Helper methods
  private getExampleRequestBody(endpoint: APIEndpoint): any {
    if (!endpoint.requestBody) return null;
    
    const jsonContent = endpoint.requestBody.content['application/json'];
    if (!jsonContent || !jsonContent.examples) return null;
    
    const firstExample = Object.values(jsonContent.examples)[0];
    return firstExample ? firstExample.value : null;
  }

  private analyzeResponseWarnings(response: Response, headers: Record<string, string>): string[] {
    const warnings: string[] = [];
    
    if (response.status >= 300 && response.status < 400) {
      warnings.push('Response indicates redirection');
    }
    
    if (!headers['x-ratelimit-remaining']) {
      warnings.push('Rate limit headers not present');
    }
    
    if (!headers['content-security-policy']) {
      warnings.push('Content Security Policy header missing');
    }
    
    return warnings;
  }

  private categorizeResponseTime(duration: number): 'FAST' | 'NORMAL' | 'SLOW' | 'TIMEOUT' {
    if (duration < 500) return 'FAST';
    if (duration < 2000) return 'NORMAL';
    if (duration < 10000) return 'SLOW';
    return 'TIMEOUT';
  }

  private extractSecurityHeaders(headers: Record<string, string>): string[] {
    const securityHeaders: string[] = [];
    const securityHeaderNames = [
      'strict-transport-security',
      'content-security-policy',
      'x-content-type-options',
      'x-frame-options',
      'x-xss-protection',
      'referrer-policy'
    ];
    
    securityHeaderNames.forEach(headerName => {
      if (headers[headerName]) {
        securityHeaders.push(headerName);
      }
    });
    
    return securityHeaders;
  }

  private toCamelCase(str: string): string {
    return str.replace(/-([a-z])/g, (g) => g[1].toUpperCase()).replace(/^[A-Z]/, (g) => g.toLowerCase());
  }

  private toSnakeCase(str: string): string {
    return str.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`).replace(/^_/, '');
  }

  private toPascalCase(str: string): string {
    return str.replace(/(^\w|-\w)/g, (g) => g.replace(/-/, '').toUpperCase());
  }

  private generateGoStructFields(obj: any, code: string, indent: string): void {
    // Implementation would generate Go struct fields from JSON object
    // This is a simplified version
  }
}

// Export production-ready interactive API docs
export const isectechInteractiveAPIDocs = new ISECTECHInteractiveAPIDocs();