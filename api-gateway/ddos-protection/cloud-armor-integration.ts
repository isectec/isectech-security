/**
 * Google Cloud Armor Integration for iSECTECH DDoS Protection
 * 
 * Integrates with Google Cloud Armor to provide L3/L4 volumetric DDoS protection,
 * automatic rule management, and coordinated defense with application-layer protection.
 * 
 * Features:
 * - Automatic security policy management
 * - Dynamic rule creation and updates
 * - Rate limiting rule synchronization
 * - Geographic restrictions
 * - Bot management integration
 * - Real-time threat response
 * - Adaptive protection based on attack patterns
 */

import { z } from 'zod';
import { GoogleAuth } from 'google-auth-library';
import { google } from 'googleapis';

// Cloud Armor Configuration Schema
export const CloudArmorConfigSchema = z.object({
  projectId: z.string(),
  region: z.string().default('global'),
  policyName: z.string(),
  
  // Authentication
  credentials: z.object({
    keyFile: z.string().optional(),
    clientEmail: z.string().optional(),
    privateKey: z.string().optional()
  }).optional(),
  
  // Security policy configuration
  policy: z.object({
    description: z.string().default('iSECTECH DDoS Protection Security Policy'),
    type: z.enum(['CLOUD_ARMOR', 'CLOUD_ARMOR_EDGE']).default('CLOUD_ARMOR'),
    
    // Adaptive protection
    adaptiveProtection: z.object({
      enabled: z.boolean().default(true),
      layer7DdosDefense: z.boolean().default(true),
      autoDeployConfidenceThreshold: z.number().min(0).max(1).default(0.6)
    }),
    
    // Default rule action
    defaultRule: z.object({
      action: z.enum(['allow', 'deny', 'rate_based_ban', 'redirect', 'throttle']).default('allow'),
      priority: z.number().default(2147483647),
      description: z.string().default('Default allow rule')
    })
  }),
  
  // Rate limiting rules
  rateLimitingRules: z.array(z.object({
    name: z.string(),
    description: z.string(),
    priority: z.number().min(0).max(2147483646),
    action: z.enum(['allow', 'deny', 'rate_based_ban', 'redirect', 'throttle']),
    
    // Match conditions
    match: z.object({
      // Source IP matching
      srcIpRanges: z.array(z.string()).optional(),
      
      // Geographic matching
      regionCode: z.array(z.string()).optional(),
      
      // Request attributes
      headers: z.array(z.object({
        name: z.string(),
        value: z.string(),
        matchType: z.enum(['EXACT', 'PREFIX', 'SUFFIX', 'REGEX', 'CONTAINS'])
      })).optional(),
      
      // Path matching
      path: z.object({
        value: z.string(),
        matchType: z.enum(['EXACT', 'PREFIX', 'SUFFIX', 'REGEX', 'CONTAINS'])
      }).optional(),
      
      // Method matching
      methods: z.array(z.string()).optional()
    }),
    
    // Rate limiting options
    rateLimitOptions: z.object({
      rateLimitThreshold: z.object({
        count: z.number().min(1),
        intervalSec: z.number().min(1)
      }),
      
      banThreshold: z.object({
        count: z.number().min(1),
        intervalSec: z.number().min(1)
      }),
      
      banDurationSec: z.number().min(1).max(86400),
      
      // Enforcement on key
      enforceOnKey: z.enum([
        'IP', 'ALL', 'HTTP_HEADER', 'XFF_IP', 'HTTP_COOKIE', 'HTTP_PATH', 'SNI'
      ]).default('IP'),
      
      enforceOnKeyName: z.string().optional(),
      
      // Action when threshold exceeded
      exceedAction: z.enum(['deny', 'redirect', 'log']).default('deny')
    }).optional(),
    
    // Redirect options
    redirectOptions: z.object({
      type: z.enum(['EXTERNAL_302', 'GOOGLE_RECAPTCHA']),
      target: z.string().optional()
    }).optional()
  })).default([]),
  
  // Geographic restrictions
  geographicRules: z.array(z.object({
    name: z.string(),
    description: z.string(),
    priority: z.number(),
    action: z.enum(['allow', 'deny']),
    countryCodes: z.array(z.string()),
    regionCodes: z.array(z.string()).optional()
  })).default([]),
  
  // Bot management
  botManagement: z.object({
    enabled: z.boolean().default(true),
    
    // reCAPTCHA integration
    recaptcha: z.object({
      enabled: z.boolean().default(true),
      siteKey: z.string(),
      secretKey: z.string(),
      score: z.number().min(0).max(1).default(0.5)
    }).optional(),
    
    // Challenge rules
    challengeRules: z.array(z.object({
      name: z.string(),
      priority: z.number(),
      description: z.string(),
      match: z.any(), // Same structure as rate limiting match
      challengeType: z.enum(['RECAPTCHA', 'JS_CHALLENGE']).default('JS_CHALLENGE')
    })).default([])
  }),
  
  // Monitoring and logging
  logging: z.object({
    enabled: z.boolean().default(true),
    sampleRate: z.number().min(0).max(1).default(1.0),
    
    // Log configuration
    logConfig: z.object({
      enable: z.boolean().default(true),
      logLevel: z.enum(['NORMAL', 'VERBOSE']).default('NORMAL')
    })
  }),
  
  // Advanced settings
  advanced: z.object({
    // JSON parsing
    jsonParsing: z.enum(['DISABLED', 'STANDARD', 'STANDARD_WITH_GRAPHQL']).default('STANDARD'),
    
    // Load balancing integration
    loadBalancerName: z.string().optional(),
    
    // Edge security policy
    edgeSecurityPolicy: z.boolean().default(false),
    
    // Custom rules
    customRules: z.array(z.object({
      name: z.string(),
      description: z.string(),
      priority: z.number(),
      action: z.string(),
      expression: z.string() // CEL expression
    })).default([])
  })
});

export type CloudArmorConfig = z.infer<typeof CloudArmorConfigSchema>;

/**
 * Security Rule Templates for common attack patterns
 */
export const SECURITY_RULE_TEMPLATES = {
  // SQL Injection Protection
  SQL_INJECTION: {
    name: 'block-sql-injection',
    description: 'Block SQL injection attempts',
    priority: 1000,
    action: 'deny' as const,
    match: {
      headers: [{
        name: 'User-Agent',
        value: '.*(union|select|script|javascript|vbscript|onload|onerror).*',
        matchType: 'REGEX' as const
      }]
    }
  },
  
  // XSS Protection
  XSS_PROTECTION: {
    name: 'block-xss-attempts',
    description: 'Block cross-site scripting attempts',
    priority: 1001,
    action: 'deny' as const,
    match: {
      path: {
        value: '.*(script|javascript|vbscript|onload|onerror).*',
        matchType: 'REGEX' as const
      }
    }
  },
  
  // High-frequency requests from single IP
  RATE_LIMIT_HIGH_FREQUENCY: {
    name: 'rate-limit-high-frequency',
    description: 'Rate limit high-frequency requests',
    priority: 2000,
    action: 'rate_based_ban' as const,
    match: {},
    rateLimitOptions: {
      rateLimitThreshold: { count: 100, intervalSec: 60 },
      banThreshold: { count: 200, intervalSec: 60 },
      banDurationSec: 600,
      enforceOnKey: 'IP' as const,
      exceedAction: 'deny' as const
    }
  },
  
  // Suspicious user agents
  SUSPICIOUS_USER_AGENTS: {
    name: 'block-suspicious-user-agents',
    description: 'Block requests from suspicious user agents',
    priority: 1500,
    action: 'deny' as const,
    match: {
      headers: [{
        name: 'User-Agent',
        value: '.*(bot|crawler|spider|scraper|scanner|curl|wget|python-requests|java|go-http).*',
        matchType: 'REGEX' as const
      }]
    }
  },
  
  // Block known malicious IPs from threat intelligence
  THREAT_INTEL_IPS: {
    name: 'block-threat-intel-ips',
    description: 'Block IPs from threat intelligence feeds',
    priority: 500,
    action: 'deny' as const,
    match: {
      srcIpRanges: [] // Will be populated dynamically
    }
  }
};

/**
 * Google Cloud Armor Security Policy Manager
 */
export class CloudArmorSecurityManager {
  private compute: any;
  private config: CloudArmorConfig;
  private policyFingerprint: string | null = null;
  private lastRuleUpdate: Date = new Date();

  constructor(config: CloudArmorConfig) {
    this.config = CloudArmorConfigSchema.parse(config);
    this.initializeGoogleCloudClient();
  }

  private async initializeGoogleCloudClient(): Promise<void> {
    const auth = new GoogleAuth({
      keyFile: this.config.credentials?.keyFile,
      credentials: this.config.credentials ? {
        client_email: this.config.credentials.clientEmail,
        private_key: this.config.credentials.privateKey
      } : undefined,
      scopes: ['https://www.googleapis.com/auth/cloud-platform']
    });

    this.compute = google.compute({ version: 'v1', auth });
  }

  /**
   * Create or update the security policy
   */
  public async createOrUpdateSecurityPolicy(): Promise<void> {
    try {
      // Check if policy exists
      const existingPolicy = await this.getSecurityPolicy();
      
      if (existingPolicy) {
        console.log(`Updating existing security policy: ${this.config.policyName}`);
        await this.updateSecurityPolicy(existingPolicy);
      } else {
        console.log(`Creating new security policy: ${this.config.policyName}`);
        await this.createSecurityPolicy();
      }
      
      // Add default rules
      await this.addDefaultRules();
      
      console.log(`Security policy ${this.config.policyName} is ready`);
    } catch (error) {
      console.error('Failed to create/update security policy:', error);
      throw error;
    }
  }

  /**
   * Get existing security policy
   */
  private async getSecurityPolicy(): Promise<any> {
    try {
      const response = await this.compute.securityPolicies.get({
        project: this.config.projectId,
        securityPolicy: this.config.policyName
      });
      
      this.policyFingerprint = response.data.fingerprint;
      return response.data;
    } catch (error: any) {
      if (error.code === 404) {
        return null; // Policy doesn't exist
      }
      throw error;
    }
  }

  /**
   * Create new security policy
   */
  private async createSecurityPolicy(): Promise<void> {
    const policyResource = {
      name: this.config.policyName,
      description: this.config.policy.description,
      type: this.config.policy.type,
      
      // Adaptive protection configuration
      adaptiveProtectionConfig: this.config.policy.adaptiveProtection.enabled ? {
        layer7DdosDefenseConfig: {
          enable: this.config.policy.adaptiveProtection.layer7DdosDefense,
          ruleVisibility: 'STANDARD'
        },
        autoDeployConfig: {
          loadThreshold: this.config.policy.adaptiveProtection.autoDeployConfidenceThreshold,
          confidenceThreshold: this.config.policy.adaptiveProtection.autoDeployConfidenceThreshold,
          impactedBaselineThreshold: this.config.policy.adaptiveProtection.autoDeployConfidenceThreshold,
          expirationSec: 3600 // 1 hour
        }
      } : undefined,
      
      // Default rule
      rules: [{
        priority: this.config.policy.defaultRule.priority,
        action: this.config.policy.defaultRule.action,
        description: this.config.policy.defaultRule.description,
        match: {
          versionedExpr: 'SRC_IPS_V1',
          config: {
            srcIpRanges: ['*']
          }
        }
      }]
    };

    const response = await this.compute.securityPolicies.insert({
      project: this.config.projectId,
      requestBody: policyResource
    });

    // Wait for operation to complete
    await this.waitForOperation(response.data.name, 'global');
    
    // Get the created policy to update fingerprint
    const createdPolicy = await this.getSecurityPolicy();
    this.policyFingerprint = createdPolicy.fingerprint;
  }

  /**
   * Update existing security policy
   */
  private async updateSecurityPolicy(existingPolicy: any): Promise<void> {
    // Update policy configuration if needed
    const updates = {
      fingerprint: this.policyFingerprint,
      description: this.config.policy.description,
      
      // Update adaptive protection if changed
      adaptiveProtectionConfig: this.config.policy.adaptiveProtection.enabled ? {
        layer7DdosDefenseConfig: {
          enable: this.config.policy.adaptiveProtection.layer7DdosDefense,
          ruleVisibility: 'STANDARD'
        }
      } : undefined
    };

    const response = await this.compute.securityPolicies.patch({
      project: this.config.projectId,
      securityPolicy: this.config.policyName,
      requestBody: updates
    });

    await this.waitForOperation(response.data.name, 'global');
  }

  /**
   * Add default security rules
   */
  private async addDefaultRules(): Promise<void> {
    const rulesToAdd = [];
    
    // Add template-based rules
    rulesToAdd.push(SECURITY_RULE_TEMPLATES.SQL_INJECTION);
    rulesToAdd.push(SECURITY_RULE_TEMPLATES.XSS_PROTECTION);
    rulesToAdd.push(SECURITY_RULE_TEMPLATES.RATE_LIMIT_HIGH_FREQUENCY);
    rulesToAdd.push(SECURITY_RULE_TEMPLATES.SUSPICIOUS_USER_AGENTS);
    
    // Add configured rate limiting rules
    rulesToAdd.push(...this.config.rateLimitingRules);
    
    // Add geographic restriction rules
    rulesToAdd.push(...this.config.geographicRules);

    // Add each rule
    for (const rule of rulesToAdd) {
      try {
        await this.addSecurityRule(rule);
        console.log(`Added security rule: ${rule.name}`);
      } catch (error) {
        console.error(`Failed to add rule ${rule.name}:`, error);
      }
    }
  }

  /**
   * Add a security rule to the policy
   */
  public async addSecurityRule(rule: any): Promise<void> {
    // Check if rule already exists
    const existingRule = await this.getSecurityRule(rule.priority);
    if (existingRule) {
      console.log(`Rule with priority ${rule.priority} already exists, updating...`);
      await this.updateSecurityRule(rule);
      return;
    }

    const ruleResource = this.buildRuleResource(rule);
    
    const response = await this.compute.securityPolicies.addRule({
      project: this.config.projectId,
      securityPolicy: this.config.policyName,
      requestBody: ruleResource
    });

    await this.waitForOperation(response.data.name, 'global');
  }

  /**
   * Update an existing security rule
   */
  public async updateSecurityRule(rule: any): Promise<void> {
    const ruleResource = this.buildRuleResource(rule);
    
    const response = await this.compute.securityPolicies.patchRule({
      project: this.config.projectId,
      securityPolicy: this.config.policyName,
      priority: rule.priority,
      requestBody: ruleResource
    });

    await this.waitForOperation(response.data.name, 'global');
  }

  /**
   * Remove a security rule
   */
  public async removeSecurityRule(priority: number): Promise<void> {
    try {
      const response = await this.compute.securityPolicies.removeRule({
        project: this.config.projectId,
        securityPolicy: this.config.policyName,
        priority: priority
      });

      await this.waitForOperation(response.data.name, 'global');
      console.log(`Removed security rule with priority ${priority}`);
    } catch (error: any) {
      if (error.code !== 404) {
        throw error;
      }
    }
  }

  /**
   * Get a specific security rule
   */
  private async getSecurityRule(priority: number): Promise<any> {
    try {
      const response = await this.compute.securityPolicies.getRule({
        project: this.config.projectId,
        securityPolicy: this.config.policyName,
        priority: priority
      });
      return response.data;
    } catch (error: any) {
      if (error.code === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Build rule resource for Cloud Armor API
   */
  private buildRuleResource(rule: any): any {
    const resource: any = {
      priority: rule.priority,
      action: rule.action,
      description: rule.description || rule.name,
      match: {}
    };

    // Build match conditions
    if (rule.match) {
      if (rule.match.srcIpRanges) {
        resource.match = {
          versionedExpr: 'SRC_IPS_V1',
          config: {
            srcIpRanges: rule.match.srcIpRanges
          }
        };
      }
      
      if (rule.match.regionCode) {
        resource.match = {
          expr: {
            expression: `origin.region_code in ['${rule.match.regionCode.join("', '")}']`
          }
        };
      }
      
      if (rule.match.headers || rule.match.path || rule.match.methods) {
        // Build complex match expression using CEL
        const expressions = [];
        
        if (rule.match.headers) {
          for (const header of rule.match.headers) {
            const expr = this.buildHeaderExpression(header);
            if (expr) expressions.push(expr);
          }
        }
        
        if (rule.match.path) {
          const expr = this.buildPathExpression(rule.match.path);
          if (expr) expressions.push(expr);
        }
        
        if (rule.match.methods) {
          expressions.push(`request.method in ['${rule.match.methods.join("', '")}']`);
        }
        
        if (expressions.length > 0) {
          resource.match = {
            expr: {
              expression: expressions.join(' && ')
            }
          };
        }
      }
    }

    // Add rate limiting options
    if (rule.rateLimitOptions && rule.action === 'rate_based_ban') {
      resource.rateLimitOptions = {
        rateLimitThreshold: rule.rateLimitOptions.rateLimitThreshold,
        banThreshold: rule.rateLimitOptions.banThreshold,
        banDurationSec: rule.rateLimitOptions.banDurationSec,
        enforceOnKey: rule.rateLimitOptions.enforceOnKey,
        enforceOnKeyName: rule.rateLimitOptions.enforceOnKeyName,
        exceedAction: rule.rateLimitOptions.exceedAction
      };
    }

    // Add redirect options
    if (rule.redirectOptions && (rule.action === 'redirect' || rule.action === 'throttle')) {
      resource.redirectOptions = rule.redirectOptions;
    }

    return resource;
  }

  /**
   * Build CEL expression for header matching
   */
  private buildHeaderExpression(header: any): string {
    const headerRef = `request.headers['${header.name.toLowerCase()}']`;
    
    switch (header.matchType) {
      case 'EXACT':
        return `${headerRef} == '${header.value}'`;
      case 'PREFIX':
        return `${headerRef}.startsWith('${header.value}')`;
      case 'SUFFIX':
        return `${headerRef}.endsWith('${header.value}')`;
      case 'CONTAINS':
        return `${headerRef}.contains('${header.value}')`;
      case 'REGEX':
        return `${headerRef}.matches('${header.value}')`;
      default:
        return `${headerRef} == '${header.value}'`;
    }
  }

  /**
   * Build CEL expression for path matching
   */
  private buildPathExpression(path: any): string {
    const pathRef = 'request.path';
    
    switch (path.matchType) {
      case 'EXACT':
        return `${pathRef} == '${path.value}'`;
      case 'PREFIX':
        return `${pathRef}.startsWith('${path.value}')`;
      case 'SUFFIX':
        return `${pathRef}.endsWith('${path.value}')`;
      case 'CONTAINS':
        return `${pathRef}.contains('${path.value}')`;
      case 'REGEX':
        return `${pathRef}.matches('${path.value}')`;
      default:
        return `${pathRef} == '${path.value}'`;
    }
  }

  /**
   * Block IP addresses dynamically
   */
  public async blockIPs(ipAddresses: string[], reason: string, duration: number = 3600): Promise<void> {
    const ruleName = `block-ips-${Date.now()}`;
    const priority = Math.floor(Math.random() * 1000) + 100; // Random priority between 100-1099
    
    const rule = {
      name: ruleName,
      description: `Auto-generated rule: ${reason}`,
      priority: priority,
      action: 'deny' as const,
      match: {
        srcIpRanges: ipAddresses
      }
    };

    await this.addSecurityRule(rule);
    
    // Schedule rule removal after duration
    setTimeout(async () => {
      try {
        await this.removeSecurityRule(priority);
        console.log(`Removed temporary IP block rule: ${ruleName}`);
      } catch (error) {
        console.error(`Failed to remove temporary rule ${ruleName}:`, error);
      }
    }, duration * 1000);

    console.log(`Blocked ${ipAddresses.length} IPs for ${duration} seconds: ${reason}`);
  }

  /**
   * Update rate limiting rules based on attack patterns
   */
  public async updateRateLimitingRules(attackType: string, severity: string): Promise<void> {
    const timestamp = Date.now();
    const rules = [];

    // Create adaptive rules based on attack type
    switch (attackType) {
      case 'HTTP_FLOOD':
        rules.push({
          name: `http-flood-protection-${timestamp}`,
          description: `Adaptive rate limiting for HTTP flood attack (${severity})`,
          priority: 1900,
          action: 'rate_based_ban' as const,
          match: {},
          rateLimitOptions: {
            rateLimitThreshold: { count: severity === 'CRITICAL' ? 20 : 50, intervalSec: 60 },
            banThreshold: { count: severity === 'CRITICAL' ? 40 : 100, intervalSec: 60 },
            banDurationSec: severity === 'CRITICAL' ? 3600 : 1800,
            enforceOnKey: 'IP' as const,
            exceedAction: 'deny' as const
          }
        });
        break;
        
      case 'SLOWLORIS':
        rules.push({
          name: `slowloris-protection-${timestamp}`,
          description: `Connection-based protection for Slowloris attack (${severity})`,
          priority: 1901,
          action: 'rate_based_ban' as const,
          match: {},
          rateLimitOptions: {
            rateLimitThreshold: { count: 10, intervalSec: 60 },
            banThreshold: { count: 20, intervalSec: 60 },
            banDurationSec: 7200, // 2 hours
            enforceOnKey: 'IP' as const,
            exceedAction: 'deny' as const
          }
        });
        break;
        
      case 'BOTNET':
        rules.push({
          name: `botnet-protection-${timestamp}`,
          description: `Distributed botnet protection (${severity})`,
          priority: 1902,
          action: 'rate_based_ban' as const,
          match: {},
          rateLimitOptions: {
            rateLimitThreshold: { count: severity === 'CRITICAL' ? 5 : 15, intervalSec: 60 },
            banThreshold: { count: severity === 'CRITICAL' ? 10 : 30, intervalSec: 60 },
            banDurationSec: severity === 'CRITICAL' ? 7200 : 3600,
            enforceOnKey: 'IP' as const,
            exceedAction: 'deny' as const
          }
        });
        break;
    }

    // Add the rules
    for (const rule of rules) {
      await this.addSecurityRule(rule);
    }

    // Schedule cleanup after 2 hours
    setTimeout(async () => {
      for (const rule of rules) {
        try {
          await this.removeSecurityRule(rule.priority);
        } catch (error) {
          console.error(`Failed to remove adaptive rule ${rule.name}:`, error);
        }
      }
    }, 2 * 3600 * 1000);
  }

  /**
   * Get security policy statistics
   */
  public async getSecurityPolicyStats(): Promise<any> {
    try {
      const policy = await this.getSecurityPolicy();
      if (!policy) {
        throw new Error('Security policy not found');
      }

      const rules = policy.rules || [];
      const ruleStats = {
        total: rules.length,
        allow: rules.filter((r: any) => r.action === 'allow').length,
        deny: rules.filter((r: any) => r.action === 'deny').length,
        rateBased: rules.filter((r: any) => r.action === 'rate_based_ban').length,
        redirect: rules.filter((r: any) => r.action === 'redirect').length,
        throttle: rules.filter((r: any) => r.action === 'throttle').length
      };

      return {
        policyName: this.config.policyName,
        policyType: policy.type,
        fingerprint: policy.fingerprint,
        adaptiveProtection: policy.adaptiveProtectionConfig?.layer7DdosDefenseConfig?.enable || false,
        lastModified: policy.creationTimestamp,
        rules: ruleStats,
        status: 'ACTIVE'
      };
    } catch (error) {
      console.error('Failed to get security policy stats:', error);
      throw error;
    }
  }

  /**
   * Wait for operation to complete
   */
  private async waitForOperation(operationName: string, zone: string = 'global'): Promise<void> {
    let attempts = 0;
    const maxAttempts = 60; // 5 minutes max wait

    while (attempts < maxAttempts) {
      try {
        const response = zone === 'global' 
          ? await this.compute.globalOperations.get({
              project: this.config.projectId,
              operation: operationName
            })
          : await this.compute.zoneOperations.get({
              project: this.config.projectId,
              zone: zone,
              operation: operationName
            });

        if (response.data.status === 'DONE') {
          if (response.data.error) {
            throw new Error(`Operation failed: ${JSON.stringify(response.data.error)}`);
          }
          return;
        }
        
        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
        attempts++;
      } catch (error) {
        console.error(`Operation check failed (attempt ${attempts}):`, error);
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
    
    throw new Error(`Operation ${operationName} timed out`);
  }

  /**
   * Test security policy configuration
   */
  public async testSecurityPolicy(): Promise<any> {
    try {
      const policy = await this.getSecurityPolicy();
      const stats = await this.getSecurityPolicyStats();
      
      return {
        success: true,
        policy: policy ? 'EXISTS' : 'NOT_FOUND',
        rules: stats.rules.total,
        adaptiveProtection: stats.adaptiveProtection,
        lastTest: new Date(),
        status: 'HEALTHY'
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        lastTest: new Date(),
        status: 'ERROR'
      };
    }
  }
}

// Export configured Cloud Armor integration for iSECTECH
export const isectechCloudArmor = new CloudArmorSecurityManager({
  projectId: process.env.GCP_PROJECT_ID || 'isectech-production',
  region: 'global',
  policyName: 'isectech-ddos-protection-policy',
  
  credentials: {
    keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    clientEmail: process.env.GCP_SERVICE_ACCOUNT_EMAIL,
    privateKey: process.env.GCP_PRIVATE_KEY?.replace(/\\n/g, '\n')
  },
  
  policy: {
    description: 'iSECTECH DDoS Protection and Security Policy - Automated by Intelligent DDoS Protection System',
    type: 'CLOUD_ARMOR',
    adaptiveProtection: {
      enabled: true,
      layer7DdosDefense: true,
      autoDeployConfidenceThreshold: 0.7
    },
    defaultRule: {
      action: 'allow',
      priority: 2147483647,
      description: 'Default allow rule for legitimate traffic'
    }
  },
  
  rateLimitingRules: [
    {
      name: 'global-rate-limit',
      description: 'Global rate limiting for all traffic',
      priority: 2000,
      action: 'rate_based_ban',
      match: {},
      rateLimitOptions: {
        rateLimitThreshold: { count: 1000, intervalSec: 60 },
        banThreshold: { count: 2000, intervalSec: 60 },
        banDurationSec: 3600,
        enforceOnKey: 'IP',
        exceedAction: 'deny'
      }
    },
    {
      name: 'api-specific-rate-limit',
      description: 'Stricter rate limiting for API endpoints',
      priority: 1999,
      action: 'rate_based_ban',
      match: {
        path: {
          value: '/api/.*',
          matchType: 'REGEX'
        }
      },
      rateLimitOptions: {
        rateLimitThreshold: { count: 200, intervalSec: 60 },
        banThreshold: { count: 400, intervalSec: 60 },
        banDurationSec: 1800,
        enforceOnKey: 'IP',
        exceedAction: 'deny'
      }
    }
  ],
  
  geographicRules: [
    // Example: Block traffic from specific countries if needed
    // {
    //   name: 'block-high-risk-countries',
    //   description: 'Block traffic from high-risk countries',
    //   priority: 500,
    //   action: 'deny',
    //   countryCodes: ['CN', 'RU', 'KP']
    // }
  ],
  
  botManagement: {
    enabled: true,
    recaptcha: {
      enabled: Boolean(process.env.RECAPTCHA_SITE_KEY),
      siteKey: process.env.RECAPTCHA_SITE_KEY || '',
      secretKey: process.env.RECAPTCHA_SECRET_KEY || '',
      score: 0.5
    }
  },
  
  logging: {
    enabled: true,
    sampleRate: 1.0,
    logConfig: {
      enable: true,
      logLevel: 'NORMAL'
    }
  },
  
  advanced: {
    jsonParsing: 'STANDARD',
    loadBalancerName: process.env.GCP_LOAD_BALANCER_NAME,
    edgeSecurityPolicy: false,
    customRules: []
  }
});