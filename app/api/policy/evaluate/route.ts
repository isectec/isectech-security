import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { requirePolicyApiKey } from '../_shared/auth';
import { buildDecisionCacheKey, getAuthzCache, getTtlSeconds, shouldBypassCache } from '../_shared/cache';
import { recordCacheHit, recordCacheMiss, recordDecisionError, recordDecisionMetrics } from '../_shared/metrics';
import { computeTrustScore } from '../_shared/trust_score';

/**
 * Policy Evaluation API Endpoints
 * Provides RESTful interfaces for external systems to submit access requests
 * and receive policy decisions from OPA
 */

// Request validation schemas
const AccessRequestSchema = z.object({
  user: z.object({
    id: z.string(),
    tenant_id: z.string(),
    roles: z.array(z.string()),
    authenticated: z.boolean(),
    status: z.enum(['active', 'blocked', 'suspended', 'disabled']).optional(),
    session: z
      .object({
        id: z.string(),
        start_time: z.string(),
        last_activity: z.string(),
      })
      .optional(),
    mfa: z
      .object({
        verified: z.boolean(),
        timestamp: z.string(),
      })
      .optional(),
    profile: z
      .object({
        timezone: z.string().optional(),
      })
      .optional(),
  }),
  resource: z.string(),
  action: z.string(),
  tenant_id: z.string(),
  context: z.object({
    ip_address: z.string(),
    user_agent: z.string().optional(),
    timestamp: z.number(),
    session_id: z.string(),
    region: z.string().optional(),
    access_type: z.enum(['normal', 'emergency', 'scheduled_maintenance']).optional(),
    justification: z.string().optional(),
    audit_reference: z.string().optional(),
    multi_tenant_justification: z.string().optional(),
    audit_trail: z.string().optional(),
    emergency_reference: z.string().optional(),
    emergency_start_time: z.string().optional(),
    maintenance_ticket: z.string().optional(),
    high_risk_authorized: z.boolean().optional(),
    requested_amount: z.number().optional(),
  }),
  device: z
    .object({
      id: z.string().optional(),
      registered: z.boolean().optional(),
      status: z.enum(['trusted', 'compromised', 'suspicious', 'quarantined']).optional(),
    })
    .optional(),
  affected_tenants: z.array(z.string()).optional(),
  resource_type: z.string().optional(),
});

const BatchAccessRequestSchema = z.object({
  requests: z.array(AccessRequestSchema),
});

// OPA client configuration
const OPA_URL = process.env.OPA_URL || 'http://opa-service:8181';
const OPA_TIMEOUT = parseInt(process.env.OPA_TIMEOUT || '5000');

interface PolicyDecision {
  allow: boolean;
  reasons?: string[];
  trust_score?: number;
  risk_level?: string;
  context?: any;
  audit_info?: any;
}

interface OPAResponse {
  result: PolicyDecision;
}

class PolicyEvaluationService {
  private baseUrl: string;
  private timeout: number;
  private bundleVersion: string;

  constructor(baseUrl: string = OPA_URL, timeout: number = OPA_TIMEOUT) {
    this.baseUrl = baseUrl;
    this.timeout = timeout;
    this.bundleVersion = process.env.OPA_BUNDLE_VERSION || '1.0.0';
  }

  /**
   * Evaluate a single access request against OPA policies
   */
  async evaluateAccess(request: z.infer<typeof AccessRequestSchema>): Promise<PolicyDecision> {
    try {
      const startTime = Date.now();
      const cache = getAuthzCache();
      const bypass = shouldBypassCache({
        access_type: request.context.access_type,
        high_risk_authorized: request.context.high_risk_authorized,
      });
      const cacheKey = buildDecisionCacheKey({
        bundleVersion: this.bundleVersion,
        tenantId: request.tenant_id,
        userId: request.user.id,
        resource: request.resource,
        action: request.action,
        context: {
          ip_address: request.context.ip_address,
          region: request.context.region,
          access_type: request.context.access_type,
          device_status: request.device?.status,
          high_risk_authorized: request.context.high_risk_authorized,
        },
      });

      if (!bypass && cache.available()) {
        const cached = await cache.get<PolicyDecision>(cacheKey);
        if (cached) {
          const duration = Date.now() - startTime;
          cached.context = {
            ...(cached.context || {}),
            cache_hit: true,
            evaluation_time_ms: duration,
            policy_version: this.bundleVersion,
          };
          await this.auditPolicyDecision(cached);
          recordCacheHit(request.tenant_id, request.resource, request.action);
          recordDecisionMetrics({
            tenant: request.tenant_id,
            resource: request.resource,
            action: request.action,
            allow: !!cached.allow,
            latencyMs: duration,
            cacheHit: true,
          });
          return cached;
        }
        recordCacheMiss(request.tenant_id, request.resource, request.action);
      }

      // Call OPA decision endpoint
      const response = await fetch(`${this.baseUrl}/v1/data/authz/allow`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input: request }),
        signal: AbortSignal.timeout(this.timeout),
      });

      if (!response.ok) {
        throw new Error(`OPA request failed with status ${response.status}: ${response.statusText}`);
      }

      const opaResult: OPAResponse = await response.json();
      const duration = Date.now() - startTime;

      // Get additional context from OPA and compute trust score
      const contextResponse = await this.getDecisionContext(request);
      const trust = await computeTrustScore(request);

      const decision: PolicyDecision = {
        allow: opaResult.result || false,
        reasons: await this.getDecisionReasons(request, opaResult.result),
        trust_score: trust && typeof trust.trust_score === 'number' ? trust.trust_score : contextResponse?.trust_score,
        risk_level: trust && trust.risk_level ? trust.risk_level : contextResponse?.risk_level,
        context: {
          evaluation_time_ms: duration,
          policy_version: this.bundleVersion,
          opa_response: opaResult,
          trust_bucket: trust?.bucket,
          cache_hit: false,
        },
        audit_info: {
          request_id: request.context.session_id,
          user_id: request.user.id,
          tenant_id: request.tenant_id,
          resource: request.resource,
          action: request.action,
          timestamp: new Date().toISOString(),
          ip_address: request.context.ip_address,
          decision: opaResult.result || false,
        },
      };

      // Write to cache when allowed
      try {
        if (!bypass && getAuthzCache().available()) {
          await cache.set(cacheKey, decision, getTtlSeconds(decision.allow));
        }
      } catch (e) {
        // degrade gracefully
        console.warn('Authz cache set failed:', e);
      }

      // Log the decision for audit trail
      await this.auditPolicyDecision(decision);
      recordDecisionMetrics({
        tenant: request.tenant_id,
        resource: request.resource,
        action: request.action,
        allow: !!decision.allow,
        latencyMs: duration,
        cacheHit: false,
      });

      return decision;
    } catch (error) {
      console.error('Policy evaluation error:', error);

      // Return secure default (deny) on error
      const decision: PolicyDecision = {
        allow: false,
        reasons: ['Policy evaluation service error'],
        context: {
          error: error instanceof Error ? error.message : 'Unknown error',
          fallback_applied: true,
        },
        audit_info: {
          request_id: request.context.session_id,
          user_id: request.user.id,
          tenant_id: request.tenant_id,
          resource: request.resource,
          action: request.action,
          timestamp: new Date().toISOString(),
          ip_address: request.context.ip_address,
          decision: false,
          error: true,
        },
      };

      await this.auditPolicyDecision(decision);
      recordDecisionError(request.tenant_id, request.resource, request.action);
      return decision;
    }
  }

  /**
   * Batch evaluate multiple access requests
   */
  async evaluateBatchAccess(requests: z.infer<typeof AccessRequestSchema>[]): Promise<Map<string, PolicyDecision>> {
    const results = new Map<string, PolicyDecision>();

    // Process requests in parallel with concurrency limit
    const BATCH_SIZE = 10;
    const batches = [];

    for (let i = 0; i < requests.length; i += BATCH_SIZE) {
      batches.push(requests.slice(i, i + BATCH_SIZE));
    }

    for (const batch of batches) {
      const batchPromises = batch.map(async (request) => {
        const decision = await this.evaluateAccess(request);
        return { requestId: request.context.session_id, decision };
      });

      const batchResults = await Promise.allSettled(batchPromises);

      batchResults.forEach((result) => {
        if (result.status === 'fulfilled') {
          results.set(result.value.requestId, result.value.decision);
        } else {
          // Create a default deny decision for failed evaluations
          console.error('Batch evaluation failed:', result.reason);
        }
      });
    }

    return results;
  }

  /**
   * Get additional decision context from OPA
   */
  private async getDecisionContext(request: z.infer<typeof AccessRequestSchema>): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/data/authz/audit_context`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input: request }),
        signal: AbortSignal.timeout(this.timeout),
      });

      if (response.ok) {
        const result = await response.json();
        return result.result;
      }
    } catch (error) {
      console.warn('Could not get decision context:', error);
    }
    return null;
  }

  /**
   * Get human-readable reasons for policy decision
   */
  private async getDecisionReasons(request: z.infer<typeof AccessRequestSchema>, allowed: boolean): Promise<string[]> {
    const reasons: string[] = [];

    if (!allowed) {
      // Check common denial reasons
      if (!request.user.authenticated) {
        reasons.push('User not authenticated');
      }
      if (request.user.status && !['active'].includes(request.user.status)) {
        reasons.push(`User status: ${request.user.status}`);
      }
      if (!request.user.roles || request.user.roles.length === 0) {
        reasons.push('No roles assigned to user');
      }
    } else {
      reasons.push('All policy checks passed');
    }

    return reasons;
  }

  /**
   * Audit policy decision
   */
  private async auditPolicyDecision(decision: PolicyDecision): Promise<void> {
    try {
      // This would typically send to a logging service like Elasticsearch
      console.log(
        'Policy Decision Audit:',
        JSON.stringify({
          timestamp: new Date().toISOString(),
          type: 'policy_decision',
          ...decision.audit_info,
        })
      );

      // TODO: Integrate with actual audit logging service
    } catch (error) {
      console.error('Failed to audit policy decision:', error);
    }
  }

  /**
   * Health check for policy evaluation service
   */
  async healthCheck(): Promise<{ status: string; details: any }> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(3000),
      });

      const isHealthy = response.ok;
      const details = {
        opa_available: isHealthy,
        opa_url: this.baseUrl,
        response_status: response.status,
        timestamp: new Date().toISOString(),
      };

      return {
        status: isHealthy ? 'healthy' : 'unhealthy',
        details,
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        details: {
          opa_available: false,
          opa_url: this.baseUrl,
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString(),
        },
      };
    }
  }
}

const policyService = new PolicyEvaluationService();

/**
 * POST /api/policy/evaluate
 * Evaluate a single access request
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    requirePolicyApiKey(request.headers);
    const body = await request.json();
    const validatedRequest = AccessRequestSchema.parse(body);

    const decision = await policyService.evaluateAccess(validatedRequest);

    // Basic response validation
    const ok = typeof decision.allow === 'boolean' && decision.context && typeof decision.context === 'object';
    if (!ok) {
      return NextResponse.json(
        {
          success: false,
          error: 'response_validation_failed',
          details: 'Decision object missing required fields',
        },
        { status: 500 }
      );
    }

    return NextResponse.json(
      {
        success: true,
        decision: decision.allow,
        data: decision,
      },
      {
        status: decision.allow ? 200 : 403,
        headers: {
          'X-Policy-Version': policyService['bundleVersion'] || '1.0.0',
          'X-Evaluation-Time': decision.context?.evaluation_time_ms?.toString() || '0',
        },
      }
    );
  } catch (error) {
    console.error('Policy evaluation endpoint error:', error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid request format',
          details: error.errors,
        },
        { status: 400 }
      );
    }

    return NextResponse.json(
      {
        success: false,
        error: 'Policy evaluation failed',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

/**
 * GET /api/policy/evaluate/health
 * Health check endpoint
 */
export async function GET(): Promise<NextResponse> {
  try {
    const health = await policyService.healthCheck();

    return NextResponse.json(
      {
        success: true,
        data: health,
      },
      {
        status: health.status === 'healthy' ? 200 : 503,
      }
    );
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error: 'Health check failed',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
