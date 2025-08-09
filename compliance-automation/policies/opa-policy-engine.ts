/**
 * iSECTECH OPA Policy Engine
 * Open Policy Agent integration for automated policy enforcement and compliance validation
 * Implements policy-as-code for unified compliance control enforcement
 */

import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';
import { z } from 'zod';
import { ControlMapping, PolicyEnforcementResult, controlMappingEngine } from './control-mapping-engine';
import { ComplianceFramework } from '../requirements/multi-framework-analysis';

// ═══════════════════════════════════════════════════════════════════════════════
// OPA POLICY ENGINE SCHEMAS AND TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export const OPAPolicySchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  package: z.string(),
  version: z.string(),
  controlMappings: z.array(z.string()),
  policy: z.string(),
  testCases: z.array(z.object({
    name: z.string(),
    input: z.any(),
    expected: z.any()
  })),
  metadata: z.object({
    author: z.string(),
    created: z.date(),
    lastModified: z.date(),
    reviewedBy: z.array(z.string()),
    approvedBy: z.string(),
    tags: z.array(z.string())
  })
});

export type OPAPolicy = z.infer<typeof OPAPolicySchema>;

export const PolicyEvaluationRequestSchema = z.object({
  policyId: z.string(),
  input: z.any(),
  tenantId: z.string().optional(),
  context: z.object({
    timestamp: z.date(),
    requestId: z.string(),
    source: z.string(),
    compliance_frameworks: z.array(z.nativeEnum(ComplianceFramework)).optional()
  })
});

export type PolicyEvaluationRequest = z.infer<typeof PolicyEvaluationRequestSchema>;

export interface OPAEngineConfig {
  opaEndpoint: string;
  authToken?: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  batchSize: number;
  caching: {
    enabled: boolean;
    ttlSeconds: number;
    maxEntries: number;
  };
  monitoring: {
    metricsEnabled: boolean;
    loggingLevel: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
    auditTrail: boolean;
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREDEFINED OPA POLICIES FOR ISECTECH COMPLIANCE
// ═══════════════════════════════════════════════════════════════════════════════

export const ISECTECH_OPA_POLICIES: OPAPolicy[] = [
  {
    id: 'opa-iam-policy',
    name: 'Identity and Access Management Policy',
    description: 'Comprehensive IAM policy enforcement for multi-tenant cybersecurity platform',
    package: 'isectech.iam',
    version: '1.2.0',
    controlMappings: ['UCM-IAM-001'],
    policy: `
package isectech.iam

import rego.v1

# Default deny all access
default allow = false
default reasons = []

# Main allow rule with comprehensive checks
allow if {
    is_authenticated
    is_authorized
    not is_blocked
    not violates_tenant_isolation
    not violates_time_restrictions
    not violates_geographic_restrictions
    audit_access_attempt
}

# Authentication checks
is_authenticated if {
    input.user.authenticated == true
    input.user.session_valid == true
    input.user.mfa_verified == true
}

# Authorization checks
is_authorized if {
    required_permission := sprintf("%s:%s", [input.resource.type, input.action])
    required_permission in input.user.permissions
}

is_authorized if {
    input.user.role in input.resource.allowed_roles
    not input.user.role in input.resource.denied_roles
}

# Blocking conditions
is_blocked if {
    input.user.account_locked == true
    reasons := array.concat(reasons, ["Account locked"])
}

is_blocked if {
    input.user.password_expired == true
    input.action != "change_password"
    reasons := array.concat(reasons, ["Password expired"])
}

is_blocked if {
    suspicious_activity_detected
    reasons := array.concat(reasons, ["Suspicious activity detected"])
}

# Tenant isolation enforcement
violates_tenant_isolation if {
    input.user.tenant_id != input.resource.tenant_id
    input.resource.tenant_id != "shared"
    input.user.role != "super_admin"
}

violates_tenant_isolation if {
    input.action == "admin"
    input.user.tenant_id != input.resource.tenant_id
    not input.user.cross_tenant_admin == true
}

# Time-based restrictions
violates_time_restrictions if {
    input.resource.business_hours_only == true
    not is_business_hours
    input.user.role != "on_call"
}

is_business_hours if {
    now := time.now_ns()
    hour := time.clock(now)[0]
    weekday := time.weekday(now)
    hour >= 9
    hour <= 17
    weekday >= 1  # Monday
    weekday <= 5  # Friday
}

# Geographic restrictions
violates_geographic_restrictions if {
    input.resource.geographic_restrictions[_] == input.user.location.country
    input.user.vpn_verified != true
}

# Suspicious activity detection
suspicious_activity_detected if {
    input.user.failed_login_attempts >= 5
    input.user.last_failed_login > (time.now_ns() - 300000000000)  # 5 minutes
}

suspicious_activity_detected if {
    input.user.location.country != input.user.usual_country
    input.user.location_verification != true
}

suspicious_activity_detected if {
    input.action in ["delete", "export", "admin"]
    input.user.velocity > 100  # actions per minute
}

# Privileged access controls
privileged_access_required if {
    input.resource.sensitivity == "high"
    input.action in ["admin", "delete", "export"]
}

privileged_access_approved if {
    privileged_access_required
    input.user.privileged_session == true
    input.user.approval_timestamp > (time.now_ns() - 14400000000000)  # 4 hours
}

# Multi-factor authentication requirements
mfa_required if {
    input.resource.sensitivity in ["high", "critical"]
}

mfa_required if {
    input.action in ["admin", "privileged", "sensitive_data_access"]
}

mfa_required if {
    input.user.role in ["admin", "super_admin", "security_analyst"]
}

# Audit logging
audit_access_attempt if {
    print(sprintf("ACCESS_ATTEMPT: user=%s resource=%s action=%s tenant=%s allowed=%v", [
        input.user.id,
        input.resource.id,
        input.action,
        input.user.tenant_id,
        allow
    ]))
}

# Risk scoring
risk_score := user_risk + resource_risk + action_risk + context_risk

user_risk := 3 if input.user.risk_level == "high"
user_risk := 1 if input.user.risk_level == "medium"
user_risk := 0

resource_risk := 5 if input.resource.sensitivity == "critical"
resource_risk := 3 if input.resource.sensitivity == "high"
resource_risk := 1 if input.resource.sensitivity == "medium"
resource_risk := 0

action_risk := 4 if input.action in ["delete", "export", "admin"]
action_risk := 2 if input.action in ["modify", "create"]
action_risk := 0

context_risk := 2 if input.user.location.suspicious == true
context_risk := 1 if not is_business_hours
context_risk := 0
`,
    testCases: [
      {
        name: 'Allow authenticated user with valid permissions',
        input: {
          user: {
            id: 'user123',
            authenticated: true,
            session_valid: true,
            mfa_verified: true,
            tenant_id: 'tenant-a',
            permissions: ['resource:read', 'resource:write'],
            role: 'analyst',
            risk_level: 'low'
          },
          resource: {
            id: 'resource-456',
            type: 'resource',
            tenant_id: 'tenant-a',
            sensitivity: 'medium'
          },
          action: 'read'
        },
        expected: { allow: true }
      },
      {
        name: 'Deny cross-tenant access',
        input: {
          user: {
            id: 'user123',
            authenticated: true,
            session_valid: true,
            mfa_verified: true,
            tenant_id: 'tenant-a',
            permissions: ['resource:read'],
            role: 'analyst'
          },
          resource: {
            id: 'resource-456',
            type: 'resource',
            tenant_id: 'tenant-b',
            sensitivity: 'medium'
          },
          action: 'read'
        },
        expected: { allow: false }
      }
    ],
    metadata: {
      author: 'Security Team',
      created: new Date('2024-01-15T00:00:00Z'),
      lastModified: new Date('2024-08-02T00:00:00Z'),
      reviewedBy: ['CISO', 'Security Architect'],
      approvedBy: 'CISO',
      tags: ['iam', 'access-control', 'multi-tenant']
    }
  },
  {
    id: 'opa-data-protection-policy',
    name: 'Data Protection and Privacy Policy',
    description: 'GDPR, HIPAA, and multi-framework data protection enforcement',
    package: 'isectech.data_protection',
    version: '1.3.0',
    controlMappings: ['UCM-DATA-001'],
    policy: `
package isectech.data_protection

import rego.v1

# Data access control decisions
default allow_access = false
default encryption_required = false
default masking_required = false
default audit_required = false

# Allow data access with proper controls
allow_access if {
    user_authorized
    data_protection_applied
    legal_basis_valid
    audit_trail_enabled
}

# User authorization for data access
user_authorized if {
    input.user.data_access_certified == true
    required_role in input.user.roles
    not input.user.access_suspended
}

required_role := "data_analyst" if input.data.type == "analytics"
required_role := "healthcare_admin" if input.data.classification == "phi"
required_role := "financial_admin" if input.data.classification == "pci"
required_role := "privacy_officer" if input.action == "export"

# Data protection requirements
data_protection_applied if {
    encryption_applied
    masking_applied_if_required
    access_logging_enabled
}

encryption_applied if {
    input.data.encrypted == true
    input.data.encryption_standard in ["AES-256", "ChaCha20-Poly1305"]
}

masking_applied_if_required if {
    not masking_required
}

masking_applied_if_required if {
    masking_required
    input.data.masked == true
}

access_logging_enabled if {
    input.context.audit_enabled == true
}

# Determine when encryption is required
encryption_required if {
    input.data.classification in ["phi", "pci", "confidential", "restricted"]
}

encryption_required if {
    input.data.contains_pii == true
}

encryption_required if {
    input.tenant.compliance_frameworks[_] in ["HIPAA", "PCI_DSS", "GDPR"]
}

# Determine when masking is required
masking_required if {
    input.data.type in ["ssn", "credit_card", "account_number", "phone", "email"]
    input.user.role != "privacy_officer"
    input.action == "view"
}

masking_required if {
    input.data.classification == "phi"
    input.user.role not in ["physician", "nurse", "healthcare_admin"]
}

# Legal basis validation for GDPR
legal_basis_valid if {
    not gdpr_applies
}

legal_basis_valid if {
    gdpr_applies
    input.legal_basis.type in valid_legal_bases
    input.legal_basis.documented == true
}

gdpr_applies if {
    input.data.subject_location in eu_countries
}

gdpr_applies if {
    input.tenant.location in eu_countries
}

valid_legal_bases := [
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests"
]

eu_countries := [
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE"
]

# Data retention and deletion
retention_expired if {
    data_age_days > max_retention_days
}

data_age_days := (time.now_ns() - input.data.created_timestamp) / 86400000000000

max_retention_days := 2555 if input.data.type in ["audit_log", "compliance_record"]  # 7 years
max_retention_days := 1095 if input.data.type == "financial_record"  # 3 years
max_retention_days := 365 if input.data.type in ["session_log", "api_log"]  # 1 year
max_retention_days := 90 if input.data.type in ["cache", "temporary"]  # 90 days

deletion_required if {
    retention_expired
    not input.data.legal_hold == true
}

# Cross-border transfer restrictions
transfer_allowed if {
    input.transfer.source_country == input.transfer.destination_country
}

transfer_allowed if {
    input.transfer.destination_country in adequacy_countries
    input.data.classification != "restricted"
}

transfer_allowed if {
    input.transfer.safeguards in ["standard_contractual_clauses", "binding_corporate_rules"]
    input.transfer.data_subject_consent == true
}

adequacy_countries := ["US", "CA", "UK", "JP", "AU", "NZ", "IL", "AR", "UY"]

# Audit requirements
audit_required if {
    input.data.classification in ["phi", "pci", "confidential"]
}

audit_required if {
    input.action in ["export", "delete", "modify"]
}

audit_required if {
    input.user.role in ["admin", "privileged_user"]
}

audit_trail_enabled if {
    audit_required
    input.context.audit_enabled == true
}

audit_trail_enabled if {
    not audit_required
}

# Risk assessment
data_risk_score := classification_risk + sensitivity_risk + access_risk + location_risk

classification_risk := 10 if input.data.classification == "restricted"
classification_risk := 8 if input.data.classification == "confidential"
classification_risk := 6 if input.data.classification in ["phi", "pci"]
classification_risk := 3 if input.data.classification == "internal"
classification_risk := 1 if input.data.classification == "public"

sensitivity_risk := 5 if input.data.contains_pii == true
sensitivity_risk := 3 if input.data.contains_sensitive == true
sensitivity_risk := 0

access_risk := 4 if input.action in ["export", "delete"]
access_risk := 2 if input.action in ["modify", "create"]
access_risk := 1 if input.action == "view"
access_risk := 0

location_risk := 3 if input.user.location.country not in adequacy_countries
location_risk := 1 if input.user.location.vpn_required == true
location_risk := 0
`,
    testCases: [
      {
        name: 'Allow access to encrypted PHI data with proper authorization',
        input: {
          user: {
            data_access_certified: true,
            roles: ['healthcare_admin'],
            access_suspended: false
          },
          data: {
            classification: 'phi',
            encrypted: true,
            encryption_standard: 'AES-256',
            type: 'medical_record'
          },
          action: 'view',
          legal_basis: {
            type: 'vital_interests',
            documented: true
          },
          context: {
            audit_enabled: true
          }
        },
        expected: { allow_access: true, encryption_required: true }
      }
    ],
    metadata: {
      author: 'Privacy Office',
      created: new Date('2024-01-15T00:00:00Z'),
      lastModified: new Date('2024-08-02T00:00:00Z'),
      reviewedBy: ['DPO', 'Legal Counsel'],
      approvedBy: 'DPO',
      tags: ['data-protection', 'gdpr', 'hipaa', 'privacy']
    }
  }
];

// ═══════════════════════════════════════════════════════════════════════════════
// OPA POLICY ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

export class OPAPolicyEngine {
  private config: OPAEngineConfig;
  private policies: Map<string, OPAPolicy> = new Map();
  private policyCache: Map<string, any> = new Map();
  private metrics: {
    evaluations: number;
    failures: number;
    cacheHits: number;
    averageLatency: number;
  } = {
    evaluations: 0,
    failures: 0,
    cacheHits: 0,
    averageLatency: 0
  };

  constructor(config: OPAEngineConfig) {
    this.config = config;
    this.loadPredefinedPolicies();
  }

  /**
   * Load predefined iSECTECH policies
   */
  private loadPredefinedPolicies(): void {
    ISECTECH_OPA_POLICIES.forEach(policy => {
      this.policies.set(policy.id, policy);
    });
  }

  /**
   * Deploy policy to OPA server
   */
  async deployPolicy(policy: OPAPolicy): Promise<void> {
    try {
      const response = await axios.put(
        `${this.config.opaEndpoint}/v1/policies/${policy.id}`,
        policy.policy,
        {
          headers: {
            'Content-Type': 'text/plain',
            ...(this.config.authToken && { 'Authorization': `Bearer ${this.config.authToken}` })
          },
          timeout: this.config.timeout
        }
      );

      if (response.status === 200) {
        this.policies.set(policy.id, policy);
        console.log(`Policy ${policy.id} deployed successfully`);
      }
    } catch (error) {
      console.error(`Failed to deploy policy ${policy.id}:`, error);
      throw error;
    }
  }

  /**
   * Deploy all iSECTECH policies
   */
  async deployAllPolicies(): Promise<void> {
    console.log('Deploying all iSECTECH compliance policies...');
    
    for (const policy of ISECTECH_OPA_POLICIES) {
      await this.deployPolicy(policy);
    }
    
    console.log(`Deployed ${ISECTECH_OPA_POLICIES.length} policies successfully`);
  }

  /**
   * Evaluate policy with input data
   */
  async evaluatePolicy(request: PolicyEvaluationRequest): Promise<PolicyEnforcementResult> {
    const startTime = Date.now();
    this.metrics.evaluations++;

    try {
      // Check cache first
      const cacheKey = this.generateCacheKey(request);
      if (this.config.caching.enabled && this.policyCache.has(cacheKey)) {
        this.metrics.cacheHits++;
        return this.policyCache.get(cacheKey);
      }

      // Get policy
      const policy = this.policies.get(request.policyId);
      if (!policy) {
        throw new Error(`Policy ${request.policyId} not found`);
      }

      // Evaluate policy
      const response = await axios.post(
        `${this.config.opaEndpoint}/v1/data/${policy.package.replace(/\./g, '/')}`,
        { input: request.input },
        {
          headers: {
            'Content-Type': 'application/json',
            ...(this.config.authToken && { 'Authorization': `Bearer ${this.config.authToken}` })
          },
          timeout: this.config.timeout
        }
      );

      // Process result
      const result: PolicyEnforcementResult = {
        policyId: request.policyId,
        controlId: policy.controlMappings[0] || 'unknown',
        timestamp: new Date(),
        result: this.determineResult(response.data.result),
        details: this.formatDetails(response.data.result),
        evidence: this.generateEvidence(request, response.data.result),
        riskScore: this.calculateRiskScore(response.data.result),
        tenantId: request.tenantId,
        affectedResources: this.extractAffectedResources(request.input),
        complianceFrameworks: this.getFrameworksForPolicy(policy)
      };

      // Add remediation if needed
      if (result.result === 'FAIL') {
        result.remediation = this.generateRemediation(policy, response.data.result);
      }

      // Cache result
      if (this.config.caching.enabled) {
        this.policyCache.set(cacheKey, result);
        
        // Cleanup cache if too large
        if (this.policyCache.size > this.config.caching.maxEntries) {
          const firstKey = this.policyCache.keys().next().value;
          this.policyCache.delete(firstKey);
        }
      }

      // Update metrics
      const latency = Date.now() - startTime;
      this.metrics.averageLatency = (this.metrics.averageLatency + latency) / 2;

      return result;

    } catch (error) {
      this.metrics.failures++;
      console.error(`Policy evaluation failed for ${request.policyId}:`, error);
      
      return {
        policyId: request.policyId,
        controlId: 'unknown',
        timestamp: new Date(),
        result: 'ERROR',
        details: `Policy evaluation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        evidence: [],
        riskScore: 10,
        tenantId: request.tenantId,
        affectedResources: [],
        complianceFrameworks: []
      };
    }
  }

  /**
   * Batch evaluate multiple policies
   */
  async batchEvaluate(requests: PolicyEvaluationRequest[]): Promise<PolicyEnforcementResult[]> {
    const results: PolicyEnforcementResult[] = [];
    
    // Process in batches
    for (let i = 0; i < requests.length; i += this.config.batchSize) {
      const batch = requests.slice(i, i + this.config.batchSize);
      const batchPromises = batch.map(request => this.evaluatePolicy(request));
      const batchResults = await Promise.allSettled(batchPromises);
      
      batchResults.forEach(result => {
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          results.push({
            policyId: 'unknown',
            controlId: 'unknown',
            timestamp: new Date(),
            result: 'ERROR',
            details: `Batch evaluation failed: ${result.reason}`,
            evidence: [],
            riskScore: 10,
            affectedResources: [],
            complianceFrameworks: []
          });
        }
      });
    }
    
    return results;
  }

  /**
   * Test policy with test cases
   */
  async testPolicy(policyId: string): Promise<PolicyTestResult[]> {
    const policy = this.policies.get(policyId);
    if (!policy) {
      throw new Error(`Policy ${policyId} not found`);
    }

    const results: PolicyTestResult[] = [];
    
    for (const testCase of policy.testCases) {
      try {
        const request: PolicyEvaluationRequest = {
          policyId,
          input: testCase.input,
          context: {
            timestamp: new Date(),
            requestId: `test-${Date.now()}`,
            source: 'policy-test'
          }
        };
        
        const result = await this.evaluatePolicy(request);
        const passed = this.compareResults(result, testCase.expected);
        
        results.push({
          testName: testCase.name,
          passed,
          expected: testCase.expected,
          actual: result,
          error: passed ? undefined : 'Result mismatch'
        });
        
      } catch (error) {
        results.push({
          testName: testCase.name,
          passed: false,
          expected: testCase.expected,
          actual: null,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
    
    return results;
  }

  /**
   * Get policy metrics and health status
   */
  getMetrics(): PolicyEngineMetrics {
    const successRate = this.metrics.evaluations > 0 
      ? ((this.metrics.evaluations - this.metrics.failures) / this.metrics.evaluations) * 100 
      : 100;
    
    const cacheHitRate = this.metrics.evaluations > 0
      ? (this.metrics.cacheHits / this.metrics.evaluations) * 100
      : 0;

    return {
      totalEvaluations: this.metrics.evaluations,
      failures: this.metrics.failures,
      successRate,
      cacheHits: this.metrics.cacheHits,
      cacheHitRate,
      averageLatency: this.metrics.averageLatency,
      policiesLoaded: this.policies.size,
      cacheSize: this.policyCache.size,
      healthStatus: successRate > 95 ? 'HEALTHY' : successRate > 85 ? 'DEGRADED' : 'UNHEALTHY'
    };
  }

  // Helper methods
  private generateCacheKey(request: PolicyEvaluationRequest): string {
    return `${request.policyId}:${JSON.stringify(request.input)}`;
  }

  private determineResult(opaResult: any): 'PASS' | 'FAIL' | 'WARNING' | 'ERROR' {
    if (opaResult.allow === true) return 'PASS';
    if (opaResult.allow === false) return 'FAIL';
    if (opaResult.warn === true) return 'WARNING';
    return 'ERROR';
  }

  private formatDetails(opaResult: any): string {
    return JSON.stringify(opaResult, null, 2);
  }

  private generateEvidence(request: PolicyEvaluationRequest, opaResult: any): any[] {
    return [
      {
        type: 'policy_evaluation',
        source: 'opa',
        data: {
          input: request.input,
          result: opaResult
        },
        hash: this.hashObject({ input: request.input, result: opaResult })
      }
    ];
  }

  private calculateRiskScore(opaResult: any): number {
    if (opaResult.risk_score) return Math.min(10, Math.max(0, opaResult.risk_score));
    if (opaResult.allow === false) return 8;
    if (opaResult.warn === true) return 5;
    return 1;
  }

  private extractAffectedResources(input: any): string[] {
    const resources: string[] = [];
    if (input.resource?.id) resources.push(input.resource.id);
    if (input.resources) resources.push(...input.resources.map((r: any) => r.id));
    return resources;
  }

  private getFrameworksForPolicy(policy: OPAPolicy): ComplianceFramework[] {
    const frameworks: ComplianceFramework[] = [];
    
    policy.controlMappings.forEach(controlId => {
      const mapping = controlMappingEngine.getControlMapping(controlId);
      if (mapping) {
        frameworks.push(...Object.keys(mapping.mappedControls) as ComplianceFramework[]);
      }
    });
    
    return [...new Set(frameworks)];
  }

  private generateRemediation(policy: OPAPolicy, opaResult: any): string[] {
    const remediation: string[] = [];
    
    if (policy.id === 'opa-iam-policy') {
      if (opaResult.reasons?.includes('Account locked')) {
        remediation.push('Contact administrator to unlock account');
      }
      if (opaResult.reasons?.includes('Password expired')) {
        remediation.push('Reset password through self-service portal');
      }
      if (opaResult.reasons?.includes('Suspicious activity detected')) {
        remediation.push('Verify identity and location, contact security team');
      }
    }
    
    return remediation;
  }

  private compareResults(actual: PolicyEnforcementResult, expected: any): boolean {
    // Simple comparison - can be enhanced
    return actual.result === (expected.allow ? 'PASS' : 'FAIL');
  }

  private hashObject(obj: any): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(JSON.stringify(obj)).digest('hex');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface PolicyTestResult {
  testName: string;
  passed: boolean;
  expected: any;
  actual: PolicyEnforcementResult | null;
  error?: string;
}

export interface PolicyEngineMetrics {
  totalEvaluations: number;
  failures: number;
  successRate: number;
  cacheHits: number;
  cacheHitRate: number;
  averageLatency: number;
  policiesLoaded: number;
  cacheSize: number;
  healthStatus: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
}

// Default configuration for iSECTECH
export const defaultOPAConfig: OPAEngineConfig = {
  opaEndpoint: 'http://opa.isectech.local:8181',
  timeout: 5000,
  retryAttempts: 3,
  retryDelay: 1000,
  batchSize: 10,
  caching: {
    enabled: true,
    ttlSeconds: 300, // 5 minutes
    maxEntries: 1000
  },
  monitoring: {
    metricsEnabled: true,
    loggingLevel: 'INFO',
    auditTrail: true
  }
};