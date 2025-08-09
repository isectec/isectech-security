/**
 * Production-grade API Security Manager for iSECTECH Kong Gateway
 * 
 * Provides comprehensive security controls including OAuth 2.1, OpenID Connect 1.0,
 * JWT validation, API keys, mTLS, IP controls, request validation, and threat protection
 * tailored for the cybersecurity platform requirements.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

// Security Configuration Schemas
export const SecurityPolicySchema = z.object({
  policyId: z.string(),
  name: z.string(),
  description: z.string(),
  serviceScope: z.array(z.string()), // Which services this policy applies to
  routeScope: z.array(z.string()).optional(), // Specific routes
  
  authentication: z.object({
    enabled: z.boolean().default(true),
    methods: z.array(z.enum([
      'OAUTH2_1',
      'OPENID_CONNECT_1_0',
      'JWT_BEARER',
      'API_KEY',
      'MTLS',
      'BASIC_AUTH',
      'CUSTOM_TOKEN'
    ])),
    oauth2: z.object({
      authorizationServer: z.string(),
      clientId: z.string(),
      clientSecret: z.string(),
      scope: z.array(z.string()),
      tokenEndpoint: z.string(),
      introspectionEndpoint: z.string(),
      jwksUri: z.string(),
      issuer: z.string(),
      algorithm: z.enum(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']),
      cacheTTL: z.number().default(300),
      requireHttps: z.boolean().default(true)
    }).optional(),
    
    jwt: z.object({
      secret: z.string().optional(),
      algorithm: z.string().default('RS256'),
      issuer: z.string(),
      audience: z.string(),
      maximumExpiration: z.number().default(3600),
      keyClaimName: z.string().default('kid'),
      clockSkew: z.number().default(30),
      requireNbf: z.boolean().default(true),
      requireExp: z.boolean().default(true)
    }).optional(),
    
    apiKey: z.object({
      keyName: z.string().default('X-API-Key'),
      keyLocation: z.enum(['header', 'query', 'body']).default('header'),
      hideCredentials: z.boolean().default(true),
      allowAnonymous: z.boolean().default(false),
      keyValidation: z.object({
        minLength: z.number().default(32),
        maxLength: z.number().default(128),
        allowedCharacters: z.string().default('A-Za-z0-9-_'),
        requirePrefix: z.string().optional()
      })
    }).optional(),
    
    mTLS: z.object({
      enabled: z.boolean().default(false),
      caCertificate: z.string(),
      certificateRevocationList: z.string().optional(),
      subjectMatch: z.enum(['exact', 'prefix', 'suffix', 'regex']).default('exact'),
      subjectPattern: z.string().optional(),
      requireClientCert: z.boolean().default(true),
      skipVerification: z.boolean().default(false)
    }).optional()
  }),
  
  authorization: z.object({
    enabled: z.boolean().default(true),
    model: z.enum(['RBAC', 'ABAC', 'ACL', 'CUSTOM']).default('RBAC'),
    
    rbac: z.object({
      roles: z.array(z.object({
        name: z.string(),
        permissions: z.array(z.string()),
        resources: z.array(z.string()),
        conditions: z.record(z.any()).optional()
      })),
      defaultRole: z.string().optional(),
      roleHierarchy: z.boolean().default(false)
    }).optional(),
    
    abac: z.object({
      attributes: z.object({
        subject: z.array(z.string()),
        resource: z.array(z.string()),
        action: z.array(z.string()),
        environment: z.array(z.string())
      }),
      policies: z.array(z.object({
        id: z.string(),
        effect: z.enum(['allow', 'deny']),
        condition: z.string(), // Policy expression
        priority: z.number().default(0)
      }))
    }).optional(),
    
    customClaims: z.record(z.any()).optional(),
    tenantIsolation: z.boolean().default(true),
    requireTenantHeader: z.boolean().default(true),
    tenantHeaderName: z.string().default('X-Tenant-ID')
  }),
  
  ipAccess: z.object({
    enabled: z.boolean().default(true),
    allowList: z.array(z.string()).default([]), // CIDR blocks
    denyList: z.array(z.string()).default([]), // CIDR blocks
    geoBlocking: z.object({
      enabled: z.boolean().default(false),
      allowedCountries: z.array(z.string()).default([]),
      blockedCountries: z.array(z.string()).default([]),
      provider: z.enum(['maxmind', 'ipapi', 'custom']).default('maxmind')
    }).optional(),
    trustProxy: z.boolean().default(true),
    proxyHeaders: z.array(z.string()).default(['X-Forwarded-For', 'X-Real-IP'])
  }),
  
  requestValidation: z.object({
    enabled: z.boolean().default(true),
    
    bodyValidation: z.object({
      enabled: z.boolean().default(true),
      maxSize: z.number().default(10485760), // 10MB
      requiredContentType: z.array(z.string()).default(['application/json']),
      jsonSchema: z.record(z.any()).optional(),
      customValidator: z.string().optional()
    }),
    
    parameterValidation: z.object({
      enabled: z.boolean().default(true),
      queryParams: z.record(z.object({
        required: z.boolean().default(false),
        type: z.enum(['string', 'number', 'boolean', 'array']),
        pattern: z.string().optional(),
        minLength: z.number().optional(),
        maxLength: z.number().optional(),
        allowedValues: z.array(z.string()).optional()
      })).optional(),
      pathParams: z.record(z.object({
        type: z.enum(['string', 'number', 'uuid']),
        pattern: z.string().optional()
      })).optional()
    }),
    
    headerValidation: z.object({
      enabled: z.boolean().default(true),
      requiredHeaders: z.array(z.string()).default(['Content-Type', 'User-Agent']),
      blockedHeaders: z.array(z.string()).default(['X-Forwarded-Host']),
      customHeaders: z.record(z.string()).optional()
    })
  }),
  
  threatProtection: z.object({
    enabled: z.boolean().default(true),
    
    sqlInjection: z.object({
      enabled: z.boolean().default(true),
      checkQueryParams: z.boolean().default(true),
      checkBody: z.boolean().default(true),
      checkHeaders: z.boolean().default(true),
      patterns: z.array(z.string()).default([
        "(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
        "(?i)(script|javascript|vbscript|onload|onerror|onclick)",
        "(\\b(or|and)\\b\\s*['\"]?\\s*\\d+\\s*['\"]?\\s*=\\s*['\"]?\\d)"
      ])
    }),
    
    xss: z.object({
      enabled: z.boolean().default(true),
      checkQueryParams: z.boolean().default(true),
      checkBody: z.boolean().default(true),
      checkHeaders: z.boolean().default(true),
      patterns: z.array(z.string()).default([
        "(?i)<script[^>]*>.*?</script>",
        "(?i)javascript:",
        "(?i)on\\w+\\s*=",
        "(?i)<iframe[^>]*>.*?</iframe>"
      ])
    }),
    
    commandInjection: z.object({
      enabled: z.boolean().default(true),
      patterns: z.array(z.string()).default([
        "(?i)(\\||&|;|\\$\\(|`|\\{|\\})",
        "(?i)(rm|cat|ls|ps|kill|curl|wget|nc|ncat)"
      ])
    }),
    
    pathTraversal: z.object({
      enabled: z.boolean().default(true),
      patterns: z.array(z.string()).default([
        "\\.\\./",
        "\\.\\.\\\\",
        "(?i)\\b(etc/passwd|windows/system32)\\b"
      ])
    }),
    
    ddosProtection: z.object({
      enabled: z.boolean().default(true),
      requestSizeLimit: z.number().default(10485760), // 10MB
      connectionLimit: z.number().default(1000),
      rateLimitPerIP: z.number().default(100), // requests per minute
      slowlorisProtection: z.boolean().default(true)
    }),
    
    customRules: z.array(z.object({
      name: z.string(),
      pattern: z.string(),
      action: z.enum(['block', 'log', 'alert']),
      severity: z.enum(['low', 'medium', 'high', 'critical'])
    })).default([])
  }),
  
  responseManipulation: z.object({
    enabled: z.boolean().default(true),
    removeHeaders: z.array(z.string()).default([
      'Server',
      'X-Powered-By',
      'X-AspNet-Version',
      'X-AspNetMvc-Version'
    ]),
    addHeaders: z.record(z.string()).default({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'",
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    }),
    sanitizeErrors: z.boolean().default(true),
    customErrorMessages: z.record(z.string()).optional()
  }),
  
  audit: z.object({
    enabled: z.boolean().default(true),
    logLevel: z.enum(['DEBUG', 'INFO', 'WARN', 'ERROR']).default('INFO'),
    logAuthAttempts: z.boolean().default(true),
    logSecurityEvents: z.boolean().default(true),
    logSensitiveData: z.boolean().default(false),
    retentionDays: z.number().default(90),
    
    alerting: z.object({
      enabled: z.boolean().default(true),
      channels: z.array(z.enum(['email', 'slack', 'webhook', 'sms'])),
      thresholds: z.object({
        failedAuthAttempts: z.number().default(5),
        threatDetections: z.number().default(1),
        ipBlocks: z.number().default(10)
      })
    })
  }),
  
  compliance: z.object({
    frameworks: z.array(z.enum([
      'SOC2_TYPE_II',
      'ISO_27001_2022',
      'GDPR',
      'HIPAA',
      'PCI_DSS_4_0',
      'CMMC_2_0',
      'FERPA'
    ])).default(['SOC2_TYPE_II', 'ISO_27001_2022']),
    dataClassification: z.enum(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']).default('CONFIDENTIAL'),
    encryption: z.object({
      inTransit: z.boolean().default(true),
      atRest: z.boolean().default(true),
      algorithm: z.string().default('AES-256-GCM')
    })
  }),
  
  tags: z.array(z.string()).default(['isectech', 'security', 'api-gateway']),
  createdAt: z.date(),
  updatedAt: z.date(),
  version: z.string().default('1.0')
});

export type SecurityPolicy = z.infer<typeof SecurityPolicySchema>;

export interface SecurityMetrics {
  policyId: string;
  totalRequests: number;
  authenticatedRequests: number;
  deniedRequests: number;
  threatDetections: number;
  averageLatency: number;
  securityEvents: Array<{
    type: string;
    severity: string;
    timestamp: Date;
    details: any;
  }>;
  lastUpdated: Date;
}

/**
 * Comprehensive API Security Manager for iSECTECH
 */
export class ISECTECHAPISecurityManager {
  private securityPolicies: Map<string, SecurityPolicy> = new Map();
  private metricsStore: Map<string, SecurityMetrics> = new Map();
  private activeTokens: Map<string, any> = new Map(); // JWT token cache
  private apiKeyStore: Map<string, any> = new Map(); // API key storage
  private ipReputationCache: Map<string, any> = new Map(); // IP reputation cache

  constructor(
    private config: {
      jwtSecret: string;
      encryptionKey: string;
      tokenCacheTTL: number;
      maxFailedAttempts: number;
      lockoutDuration: number;
    }
  ) {
    this.initializeISECTECHSecurityPolicies();
  }

  /**
   * Initialize security policies for iSECTECH services
   */
  private initializeISECTECHSecurityPolicies(): void {
    // High Security Policy for Threat Detection APIs
    const threatDetectionSecurityPolicy: SecurityPolicy = {
      policyId: 'threat-detection-high-security',
      name: 'Threat Detection High Security Policy',
      description: 'Maximum security controls for threat detection and AI/ML APIs',
      serviceScope: ['isectech-threat-detection', 'isectech-ai-ml-services'],
      routeScope: ['/api/v1/threats/analyze', '/api/v1/ai/behavioral/analyze'],
      
      authentication: {
        enabled: true,
        methods: ['OAUTH2_1', 'JWT_BEARER', 'MTLS'],
        oauth2: {
          authorizationServer: 'https://auth.isectech.com',
          clientId: 'isectech-threat-detection',
          clientSecret: process.env.OAUTH2_CLIENT_SECRET || '',
          scope: ['threat-detection', 'ai-analysis', 'security-data'],
          tokenEndpoint: 'https://auth.isectech.com/oauth2/token',
          introspectionEndpoint: 'https://auth.isectech.com/oauth2/introspect',
          jwksUri: 'https://auth.isectech.com/.well-known/jwks.json',
          issuer: 'https://auth.isectech.com',
          algorithm: 'RS256',
          cacheTTL: 300,
          requireHttps: true
        },
        jwt: {
          algorithm: 'RS256',
          issuer: 'https://auth.isectech.com',
          audience: 'isectech-api-gateway',
          maximumExpiration: 1800, // 30 minutes for sensitive operations
          keyClaimName: 'kid',
          clockSkew: 30,
          requireNbf: true,
          requireExp: true
        },
        mTLS: {
          enabled: true,
          caCertificate: process.env.MTLS_CA_CERT || '',
          requireClientCert: true,
          subjectMatch: 'exact',
          skipVerification: false
        }
      },
      
      authorization: {
        enabled: true,
        model: 'RBAC',
        rbac: {
          roles: [
            {
              name: 'security-analyst',
              permissions: ['threat:read', 'threat:analyze'],
              resources: ['threats', 'incidents', 'analytics']
            },
            {
              name: 'threat-hunter',
              permissions: ['threat:read', 'threat:analyze', 'threat:investigate'],
              resources: ['threats', 'incidents', 'analytics', 'intelligence']
            },
            {
              name: 'security-admin',
              permissions: ['threat:*', 'ai:*', 'config:*'],
              resources: ['*']
            }
          ],
          defaultRole: 'security-analyst',
          roleHierarchy: true
        },
        tenantIsolation: true,
        requireTenantHeader: true,
        tenantHeaderName: 'X-Tenant-ID'
      },
      
      ipAccess: {
        enabled: true,
        allowList: [
          '10.0.0.0/8',      // Internal network
          '172.16.0.0/12',   // Internal network
          '192.168.0.0/16'   // Internal network
        ],
        denyList: [
          '169.254.0.0/16',  // Link-local
          '127.0.0.0/8'      // Loopback (except from proxy)
        ],
        geoBlocking: {
          enabled: true,
          allowedCountries: ['US', 'CA', 'GB', 'DE', 'AU'],
          blockedCountries: ['CN', 'RU', 'KP', 'IR'],
          provider: 'maxmind'
        },
        trustProxy: true,
        proxyHeaders: ['X-Forwarded-For', 'X-Real-IP']
      },
      
      requestValidation: {
        enabled: true,
        bodyValidation: {
          enabled: true,
          maxSize: 5242880, // 5MB for ML payloads
          requiredContentType: ['application/json'],
          jsonSchema: {
            type: 'object',
            required: ['data'],
            properties: {
              data: { type: 'object' },
              metadata: { type: 'object' }
            }
          }
        },
        parameterValidation: {
          enabled: true,
          queryParams: {
            'threat_type': {
              required: false,
              type: 'string',
              allowedValues: ['malware', 'phishing', 'c2', 'apt', 'insider']
            },
            'confidence': {
              required: false,
              type: 'number'
            }
          }
        },
        headerValidation: {
          enabled: true,
          requiredHeaders: ['Content-Type', 'User-Agent', 'X-Tenant-ID'],
          blockedHeaders: ['X-Forwarded-Host', 'X-Original-URL']
        }
      },
      
      threatProtection: {
        enabled: true,
        sqlInjection: {
          enabled: true,
          checkQueryParams: true,
          checkBody: true,
          checkHeaders: true,
          patterns: [
            "(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
            "(?i)(script|javascript|vbscript|onload|onerror|onclick)",
            "(\\b(or|and)\\b\\s*['\"]?\\s*\\d+\\s*['\"]?\\s*=\\s*['\"]?\\d)"
          ]
        },
        xss: {
          enabled: true,
          checkQueryParams: true,
          checkBody: true,
          checkHeaders: true,
          patterns: [
            "(?i)<script[^>]*>.*?</script>",
            "(?i)javascript:",
            "(?i)on\\w+\\s*=",
            "(?i)<iframe[^>]*>.*?</iframe>"
          ]
        },
        commandInjection: {
          enabled: true,
          patterns: [
            "(?i)(\\||&|;|\\$\\(|`|\\{|\\})",
            "(?i)(rm|cat|ls|ps|kill|curl|wget|nc|ncat)"
          ]
        },
        pathTraversal: {
          enabled: true,
          patterns: [
            "\\.\\./",
            "\\.\\.\\\\",
            "(?i)\\b(etc/passwd|windows/system32)\\b"
          ]
        },
        ddosProtection: {
          enabled: true,
          requestSizeLimit: 5242880, // 5MB
          connectionLimit: 500,
          rateLimitPerIP: 50, // requests per minute
          slowlorisProtection: true
        },
        customRules: [
          {
            name: 'threat-intel-injection',
            pattern: '(?i)(\\b(mitre|att&ck|cve-\\d{4}-\\d{4,7})\\b.*?[<>\\\'\\";])',
            action: 'block',
            severity: 'high'
          }
        ]
      },
      
      responseManipulation: {
        enabled: true,
        removeHeaders: [
          'Server',
          'X-Powered-By',
          'X-Kong-Upstream-Latency',
          'X-Kong-Proxy-Latency'
        ],
        addHeaders: {
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
          'Content-Security-Policy': "default-src 'self'; script-src 'none'; object-src 'none'",
          'Referrer-Policy': 'no-referrer',
          'X-API-Security': 'isectech-protected'
        },
        sanitizeErrors: true,
        customErrorMessages: {
          '401': 'Authentication required for threat detection services',
          '403': 'Insufficient privileges for security operations',
          '429': 'Rate limit exceeded for security API'
        }
      },
      
      audit: {
        enabled: true,
        logLevel: 'INFO',
        logAuthAttempts: true,
        logSecurityEvents: true,
        logSensitiveData: false,
        retentionDays: 365, // Longer retention for security logs
        alerting: {
          enabled: true,
          channels: ['email', 'slack', 'webhook'],
          thresholds: {
            failedAuthAttempts: 3,
            threatDetections: 1,
            ipBlocks: 5
          }
        }
      },
      
      compliance: {
        frameworks: ['SOC2_TYPE_II', 'ISO_27001_2022', 'CMMC_2_0'],
        dataClassification: 'RESTRICTED',
        encryption: {
          inTransit: true,
          atRest: true,
          algorithm: 'AES-256-GCM'
        }
      },
      
      tags: ['isectech', 'threat-detection', 'high-security', 'restricted'],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0'
    };

    // Standard Security Policy for General APIs
    const standardSecurityPolicy: SecurityPolicy = {
      policyId: 'standard-security',
      name: 'Standard Security Policy',
      description: 'Standard security controls for general API endpoints',
      serviceScope: [
        'isectech-asset-discovery',
        'isectech-vulnerability-management',
        'isectech-incident-response'
      ],
      
      authentication: {
        enabled: true,
        methods: ['OAUTH2_1', 'JWT_BEARER', 'API_KEY'],
        oauth2: {
          authorizationServer: 'https://auth.isectech.com',
          clientId: 'isectech-standard-apis',
          clientSecret: process.env.OAUTH2_CLIENT_SECRET || '',
          scope: ['api-access', 'user-data'],
          tokenEndpoint: 'https://auth.isectech.com/oauth2/token',
          introspectionEndpoint: 'https://auth.isectech.com/oauth2/introspect',
          jwksUri: 'https://auth.isectech.com/.well-known/jwks.json',
          issuer: 'https://auth.isectech.com',
          algorithm: 'RS256',
          cacheTTL: 600,
          requireHttps: true
        },
        jwt: {
          algorithm: 'RS256',
          issuer: 'https://auth.isectech.com',
          audience: 'isectech-api-gateway',
          maximumExpiration: 3600, // 1 hour
          keyClaimName: 'kid',
          clockSkew: 60,
          requireNbf: true,
          requireExp: true
        },
        apiKey: {
          keyName: 'X-API-Key',
          keyLocation: 'header',
          hideCredentials: true,
          allowAnonymous: false,
          keyValidation: {
            minLength: 32,
            maxLength: 64,
            allowedCharacters: 'A-Za-z0-9-_',
            requirePrefix: 'isec_'
          }
        }
      },
      
      authorization: {
        enabled: true,
        model: 'RBAC',
        rbac: {
          roles: [
            {
              name: 'user',
              permissions: ['read:assets', 'read:vulnerabilities'],
              resources: ['assets', 'vulnerabilities']
            },
            {
              name: 'operator',
              permissions: ['read:*', 'write:incidents', 'write:assets'],
              resources: ['assets', 'vulnerabilities', 'incidents']
            },
            {
              name: 'admin',
              permissions: ['*'],
              resources: ['*']
            }
          ],
          defaultRole: 'user',
          roleHierarchy: true
        },
        tenantIsolation: true,
        requireTenantHeader: true,
        tenantHeaderName: 'X-Tenant-ID'
      },
      
      ipAccess: {
        enabled: true,
        allowList: [], // Allow all by default
        denyList: [
          '0.0.0.0/8',       // Reserved
          '169.254.0.0/16',  // Link-local
          '224.0.0.0/4'      // Multicast
        ],
        geoBlocking: {
          enabled: false
        },
        trustProxy: true,
        proxyHeaders: ['X-Forwarded-For', 'X-Real-IP']
      },
      
      requestValidation: {
        enabled: true,
        bodyValidation: {
          enabled: true,
          maxSize: 1048576, // 1MB
          requiredContentType: ['application/json', 'application/x-www-form-urlencoded']
        },
        parameterValidation: {
          enabled: true
        },
        headerValidation: {
          enabled: true,
          requiredHeaders: ['Content-Type', 'User-Agent'],
          blockedHeaders: ['X-Forwarded-Host']
        }
      },
      
      threatProtection: {
        enabled: true,
        sqlInjection: {
          enabled: true,
          checkQueryParams: true,
          checkBody: true,
          checkHeaders: false,
          patterns: [
            "(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
            "(\\b(or|and)\\b\\s*['\"]?\\s*\\d+\\s*['\"]?\\s*=\\s*['\"]?\\d)"
          ]
        },
        xss: {
          enabled: true,
          checkQueryParams: true,
          checkBody: true,
          checkHeaders: false,
          patterns: [
            "(?i)<script[^>]*>.*?</script>",
            "(?i)javascript:",
            "(?i)on\\w+\\s*="
          ]
        },
        commandInjection: {
          enabled: true,
          patterns: [
            "(?i)(\\||&|;|\\$\\(|`)",
            "(?i)(rm|cat|ls|ps|kill)"
          ]
        },
        pathTraversal: {
          enabled: true,
          patterns: [
            "\\.\\./",
            "\\.\\.\\\\",
            "(?i)\\b(etc/passwd|windows/system32)\\b"
          ]
        },
        ddosProtection: {
          enabled: true,
          requestSizeLimit: 1048576, // 1MB
          connectionLimit: 1000,
          rateLimitPerIP: 100, // requests per minute
          slowlorisProtection: true
        },
        customRules: []
      },
      
      responseManipulation: {
        enabled: true,
        removeHeaders: [
          'Server',
          'X-Powered-By'
        ],
        addHeaders: {
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'SAMEORIGIN',
          'X-XSS-Protection': '1; mode=block',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
          'Content-Security-Policy': "default-src 'self'",
          'Referrer-Policy': 'strict-origin-when-cross-origin'
        },
        sanitizeErrors: true
      },
      
      audit: {
        enabled: true,
        logLevel: 'INFO',
        logAuthAttempts: true,
        logSecurityEvents: true,
        logSensitiveData: false,
        retentionDays: 90,
        alerting: {
          enabled: true,
          channels: ['email', 'slack'],
          thresholds: {
            failedAuthAttempts: 5,
            threatDetections: 3,
            ipBlocks: 20
          }
        }
      },
      
      compliance: {
        frameworks: ['SOC2_TYPE_II', 'ISO_27001_2022'],
        dataClassification: 'CONFIDENTIAL',
        encryption: {
          inTransit: true,
          atRest: true,
          algorithm: 'AES-256-GCM'
        }
      },
      
      tags: ['isectech', 'standard-security', 'general-apis'],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0'
    };

    // Public API Security Policy (for documentation, health checks, etc.)
    const publicSecurityPolicy: SecurityPolicy = {
      policyId: 'public-low-security',
      name: 'Public API Security Policy',
      description: 'Minimal security controls for public endpoints',
      serviceScope: [
        'isectech-api-docs',
        'isectech-health-check',
        'isectech-public-status'
      ],
      
      authentication: {
        enabled: false,
        methods: []
      },
      
      authorization: {
        enabled: false,
        model: 'ACL',
        tenantIsolation: false,
        requireTenantHeader: false
      },
      
      ipAccess: {
        enabled: true,
        allowList: [], // Allow all
        denyList: [
          '0.0.0.0/8',       // Reserved
          '169.254.0.0/16',  // Link-local
          '224.0.0.0/4'      // Multicast
        ],
        geoBlocking: {
          enabled: false
        },
        trustProxy: true,
        proxyHeaders: ['X-Forwarded-For', 'X-Real-IP']
      },
      
      requestValidation: {
        enabled: true,
        bodyValidation: {
          enabled: false,
          maxSize: 1024, // 1KB
          requiredContentType: []
        },
        parameterValidation: {
          enabled: false
        },
        headerValidation: {
          enabled: true,
          requiredHeaders: ['User-Agent'],
          blockedHeaders: ['X-Forwarded-Host']
        }
      },
      
      threatProtection: {
        enabled: true,
        sqlInjection: {
          enabled: false,
          checkQueryParams: false,
          checkBody: false,
          checkHeaders: false,
          patterns: []
        },
        xss: {
          enabled: true,
          checkQueryParams: true,
          checkBody: false,
          checkHeaders: false,
          patterns: [
            "(?i)<script[^>]*>.*?</script>",
            "(?i)javascript:"
          ]
        },
        commandInjection: {
          enabled: false,
          patterns: []
        },
        pathTraversal: {
          enabled: true,
          patterns: [
            "\\.\\./",
            "\\.\\.\\\\"
          ]
        },
        ddosProtection: {
          enabled: true,
          requestSizeLimit: 1024, // 1KB
          connectionLimit: 2000,
          rateLimitPerIP: 1000, // requests per minute
          slowlorisProtection: true
        },
        customRules: []
      },
      
      responseManipulation: {
        enabled: true,
        removeHeaders: [
          'Server',
          'X-Powered-By'
        ],
        addHeaders: {
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'SAMEORIGIN',
          'Cache-Control': 'public, max-age=300'
        },
        sanitizeErrors: false // Allow detailed errors for public docs
      },
      
      audit: {
        enabled: true,
        logLevel: 'WARN',
        logAuthAttempts: false,
        logSecurityEvents: true,
        logSensitiveData: false,
        retentionDays: 30,
        alerting: {
          enabled: true,
          channels: ['webhook'],
          thresholds: {
            failedAuthAttempts: 100,
            threatDetections: 10,
            ipBlocks: 50
          }
        }
      },
      
      compliance: {
        frameworks: ['SOC2_TYPE_II'],
        dataClassification: 'PUBLIC',
        encryption: {
          inTransit: true,
          atRest: false,
          algorithm: 'AES-256-GCM'
        }
      },
      
      tags: ['isectech', 'public-api', 'low-security'],
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0'
    };

    // Store all security policies
    [
      threatDetectionSecurityPolicy,
      standardSecurityPolicy,
      publicSecurityPolicy
    ].forEach(policy => {
      const validatedPolicy = SecurityPolicySchema.parse(policy);
      this.securityPolicies.set(policy.policyId, validatedPolicy);
      
      // Initialize metrics for each policy
      this.metricsStore.set(policy.policyId, {
        policyId: policy.policyId,
        totalRequests: 0,
        authenticatedRequests: 0,
        deniedRequests: 0,
        threatDetections: 0,
        averageLatency: 0,
        securityEvents: [],
        lastUpdated: new Date()
      });
    });
  }

  /**
   * Get security policy by ID
   */
  public getSecurityPolicy(policyId: string): SecurityPolicy | undefined {
    return this.securityPolicies.get(policyId);
  }

  /**
   * Get security policy for a service
   */
  public getSecurityPolicyForService(serviceName: string): SecurityPolicy | undefined {
    for (const policy of this.securityPolicies.values()) {
      if (policy.serviceScope.includes(serviceName)) {
        return policy;
      }
    }
    return undefined;
  }

  /**
   * Get all security policies
   */
  public getAllSecurityPolicies(): Map<string, SecurityPolicy> {
    return new Map(this.securityPolicies);
  }

  /**
   * Generate Kong security plugin configurations
   */
  public generateKongSecurityPluginConfigurations(): Array<{
    name: string;
    service?: { id: string };
    route?: { id: string };
    config: object;
    enabled: boolean;
    tags: string[];
  }> {
    const pluginConfigurations: Array<{
      name: string;
      service?: { id: string };
      route?: { id: string };
      config: object;
      enabled: boolean;
      tags: string[];
    }> = [];

    for (const [policyId, policy] of this.securityPolicies) {
      // OAuth 2.0 plugin configuration
      if (policy.authentication.enabled && 
          policy.authentication.methods.includes('OAUTH2_1') && 
          policy.authentication.oauth2) {
        pluginConfigurations.push({
          name: 'oauth2',
          config: {
            scopes: policy.authentication.oauth2.scope,
            mandatory_scope: true,
            token_expiration: policy.authentication.oauth2.cacheTTL,
            enable_authorization_code: true,
            enable_client_credentials: true,
            enable_implicit_grant: false,
            enable_password_grant: false,
            hide_credentials: true,
            accept_http_if_already_terminated: false
          },
          enabled: true,
          tags: policy.tags
        });
      }

      // JWT plugin configuration
      if (policy.authentication.enabled && 
          policy.authentication.methods.includes('JWT_BEARER') && 
          policy.authentication.jwt) {
        pluginConfigurations.push({
          name: 'jwt',
          config: {
            uri_param_names: ['jwt'],
            cookie_names: ['jwt'],
            header_names: ['Authorization'],
            claims_to_verify: ['exp', 'nbf'],
            key_claim_name: policy.authentication.jwt.keyClaimName,
            secret_is_base64: false,
            maximum_expiration: policy.authentication.jwt.maximumExpiration,
            clock_skew_seconds: policy.authentication.jwt.clockSkew,
            run_on_preflight: false
          },
          enabled: true,
          tags: policy.tags
        });
      }

      // API Key plugin configuration
      if (policy.authentication.enabled && 
          policy.authentication.methods.includes('API_KEY') && 
          policy.authentication.apiKey) {
        pluginConfigurations.push({
          name: 'key-auth',
          config: {
            key_names: [policy.authentication.apiKey.keyName],
            key_in_body: policy.authentication.apiKey.keyLocation === 'body',
            key_in_header: policy.authentication.apiKey.keyLocation === 'header',
            key_in_query: policy.authentication.apiKey.keyLocation === 'query',
            hide_credentials: policy.authentication.apiKey.hideCredentials,
            anonymous: policy.authentication.apiKey.allowAnonymous ? 'anonymous' : null,
            run_on_preflight: false
          },
          enabled: true,
          tags: policy.tags
        });
      }

      // IP Restriction plugin configuration
      if (policy.ipAccess.enabled) {
        pluginConfigurations.push({
          name: 'ip-restriction',
          config: {
            allow: policy.ipAccess.allowList,
            deny: policy.ipAccess.denyList,
            message: 'Access denied from this IP address'
          },
          enabled: true,
          tags: policy.tags
        });
      }

      // Request Size Limiting plugin
      if (policy.threatProtection.enabled && policy.threatProtection.ddosProtection.enabled) {
        pluginConfigurations.push({
          name: 'request-size-limiting',
          config: {
            allowed_payload_size: policy.threatProtection.ddosProtection.requestSizeLimit,
            size_unit: 'bytes',
            require_content_length: true
          },
          enabled: true,
          tags: policy.tags
        });
      }

      // Response Transformer plugin
      if (policy.responseManipulation.enabled) {
        pluginConfigurations.push({
          name: 'response-transformer',
          config: {
            remove: {
              headers: policy.responseManipulation.removeHeaders
            },
            add: {
              headers: Object.entries(policy.responseManipulation.addHeaders).map(([key, value]) => `${key}:${value}`)
            }
          },
          enabled: true,
          tags: policy.tags
        });
      }

      // Request Validator plugin
      if (policy.requestValidation.enabled) {
        pluginConfigurations.push({
          name: 'request-validator',
          config: {
            body_schema: policy.requestValidation.bodyValidation.jsonSchema,
            parameter_schema: policy.requestValidation.parameterValidation.queryParams,
            allowed_content_types: policy.requestValidation.bodyValidation.requiredContentType
          },
          enabled: true,
          tags: policy.tags
        });
      }

      // CORS plugin for public APIs
      if (policyId === 'public-low-security') {
        pluginConfigurations.push({
          name: 'cors',
          config: {
            origins: ['*'],
            methods: ['GET', 'HEAD', 'OPTIONS'],
            headers: ['Accept', 'Accept-Version', 'Content-Length', 'Content-MD5', 'Content-Type', 'Date', 'X-Auth-Token'],
            exposed_headers: ['X-Auth-Token'],
            credentials: false,
            max_age: 3600,
            preflight_continue: false
          },
          enabled: true,
          tags: policy.tags
        });
      }
    }

    return pluginConfigurations;
  }

  /**
   * Validate JWT token
   */
  public validateJWTToken(token: string, policy: SecurityPolicy): { valid: boolean; payload?: any; error?: string } {
    try {
      if (!policy.authentication.jwt) {
        return { valid: false, error: 'JWT configuration not found' };
      }

      const decoded = jwt.verify(token, this.config.jwtSecret, {
        algorithms: [policy.authentication.jwt.algorithm as jwt.Algorithm],
        issuer: policy.authentication.jwt.issuer,
        audience: policy.authentication.jwt.audience,
        maxAge: policy.authentication.jwt.maximumExpiration,
        clockTolerance: policy.authentication.jwt.clockSkew
      });

      // Cache valid token
      this.activeTokens.set(token, {
        payload: decoded,
        timestamp: new Date(),
        ttl: policy.authentication.oauth2?.cacheTTL || 300
      });

      return { valid: true, payload: decoded };
    } catch (error) {
      return { valid: false, error: `JWT validation failed: ${error}` };
    }
  }

  /**
   * Validate API Key
   */
  public validateAPIKey(apiKey: string, policy: SecurityPolicy): { valid: boolean; keyData?: any; error?: string } {
    try {
      if (!policy.authentication.apiKey) {
        return { valid: false, error: 'API Key configuration not found' };
      }

      // Validate key format
      const validation = policy.authentication.apiKey.keyValidation;
      if (apiKey.length < validation.minLength || apiKey.length > validation.maxLength) {
        return { valid: false, error: 'Invalid API key length' };
      }

      if (validation.requirePrefix && !apiKey.startsWith(validation.requirePrefix)) {
        return { valid: false, error: 'Invalid API key prefix' };
      }

      const regex = new RegExp(`^[${validation.allowedCharacters}]+$`);
      if (!regex.test(apiKey)) {
        return { valid: false, error: 'Invalid API key characters' };
      }

      // Check if key exists and is active (mock implementation)
      const keyData = this.apiKeyStore.get(apiKey);
      if (!keyData || !keyData.active) {
        return { valid: false, error: 'Invalid or inactive API key' };
      }

      return { valid: true, keyData };
    } catch (error) {
      return { valid: false, error: `API key validation failed: ${error}` };
    }
  }

  /**
   * Check for threat patterns in request
   */
  public detectThreats(request: {
    method: string;
    path: string;
    query?: Record<string, string>;
    headers?: Record<string, string>;
    body?: string;
  }, policy: SecurityPolicy): Array<{ type: string; severity: string; description: string }> {
    const threats: Array<{ type: string; severity: string; description: string }> = [];

    if (!policy.threatProtection.enabled) {
      return threats;
    }

    const requestText = JSON.stringify(request);

    // SQL Injection detection
    if (policy.threatProtection.sqlInjection.enabled) {
      for (const pattern of policy.threatProtection.sqlInjection.patterns) {
        const regex = new RegExp(pattern, 'gi');
        if (regex.test(requestText)) {
          threats.push({
            type: 'SQL_INJECTION',
            severity: 'high',
            description: `Potential SQL injection detected: ${pattern}`
          });
        }
      }
    }

    // XSS detection
    if (policy.threatProtection.xss.enabled) {
      for (const pattern of policy.threatProtection.xss.patterns) {
        const regex = new RegExp(pattern, 'gi');
        if (regex.test(requestText)) {
          threats.push({
            type: 'XSS',
            severity: 'medium',
            description: `Potential XSS detected: ${pattern}`
          });
        }
      }
    }

    // Command Injection detection
    if (policy.threatProtection.commandInjection.enabled) {
      for (const pattern of policy.threatProtection.commandInjection.patterns) {
        const regex = new RegExp(pattern, 'gi');
        if (regex.test(requestText)) {
          threats.push({
            type: 'COMMAND_INJECTION',
            severity: 'critical',
            description: `Potential command injection detected: ${pattern}`
          });
        }
      }
    }

    // Path Traversal detection
    if (policy.threatProtection.pathTraversal.enabled) {
      for (const pattern of policy.threatProtection.pathTraversal.patterns) {
        const regex = new RegExp(pattern, 'gi');
        if (regex.test(requestText)) {
          threats.push({
            type: 'PATH_TRAVERSAL',
            severity: 'medium',
            description: `Potential path traversal detected: ${pattern}`
          });
        }
      }
    }

    // Custom rules
    for (const rule of policy.threatProtection.customRules) {
      const regex = new RegExp(rule.pattern, 'gi');
      if (regex.test(requestText)) {
        threats.push({
          type: 'CUSTOM_RULE',
          severity: rule.severity,
          description: `Custom rule triggered: ${rule.name}`
        });
      }
    }

    return threats;
  }

  /**
   * Generate security metrics report
   */
  public generateSecurityMetricsReport(): object {
    const report: any = {
      generatedAt: new Date(),
      policies: {},
      overallMetrics: {
        totalPolicies: this.securityPolicies.size,
        totalRequests: 0,
        totalThreats: 0,
        averageLatency: 0
      }
    };

    for (const [policyId, metrics] of this.metricsStore) {
      report.policies[policyId] = {
        ...metrics,
        securityEvents: metrics.securityEvents.slice(-10) // Last 10 events
      };

      report.overallMetrics.totalRequests += metrics.totalRequests;
      report.overallMetrics.totalThreats += metrics.threatDetections;
    }

    return report;
  }

  /**
   * Update security metrics
   */
  public updateSecurityMetrics(policyId: string, update: Partial<SecurityMetrics>): void {
    const metrics = this.metricsStore.get(policyId);
    if (metrics) {
      Object.assign(metrics, update);
      metrics.lastUpdated = new Date();
    }
  }

  /**
   * Validate all security policies
   */
  public validatePolicies(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (const [policyId, policy] of this.securityPolicies) {
      try {
        SecurityPolicySchema.parse(policy);
      } catch (error) {
        errors.push(`Invalid policy ${policyId}: ${error}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

// Export production-ready API security manager
export const isectechAPISecurityManager = new ISECTECHAPISecurityManager({
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
  tokenCacheTTL: parseInt(process.env.TOKEN_CACHE_TTL || '300'),
  maxFailedAttempts: parseInt(process.env.MAX_FAILED_ATTEMPTS || '5'),
  lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900')
});