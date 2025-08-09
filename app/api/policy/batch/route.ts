import { NextRequest, NextResponse } from 'next/server';
import { requirePolicyApiKey } from '../_shared/auth';
import { buildDecisionCacheKey, getAuthzCache, getTtlSeconds, shouldBypassCache } from '../_shared/cache';
import { recordCacheHit, recordCacheMiss, recordDecisionMetrics } from '../_shared/metrics';

/**
 * Batch Policy Evaluation API Endpoint
 * Handles multiple access request evaluations in a single call
 */

// Types and runtime validation
interface AccessRequest {
  user: { id: string; tenant_id: string; roles?: string[]; authenticated: boolean; status?: string };
  resource: string;
  action: string;
  tenant_id: string;
  context: {
    ip_address: string;
    session_id: string;
    region?: string;
    access_type?: string;
    high_risk_authorized?: boolean;
  } & Record<string, unknown>;
  device?: { status?: string } & Record<string, unknown>;
}

interface BatchAccessRequest {
  requests: AccessRequest[];
  options?: { fail_fast?: boolean; timeout_ms?: number; parallel_limit?: number };
}

function isValidAccessRequest(obj: any): obj is AccessRequest {
  return (
    !!obj &&
    typeof obj === 'object' &&
    obj.user &&
    typeof obj.user.id === 'string' &&
    typeof obj.tenant_id === 'string' &&
    typeof obj.resource === 'string' &&
    typeof obj.action === 'string' &&
    obj.context &&
    typeof obj.context.session_id === 'string' &&
    typeof obj.context.ip_address === 'string'
  );
}

const OPA_URL = process.env.OPA_URL || 'http://opa-service:8181';
const OPA_TIMEOUT = parseInt(process.env.OPA_TIMEOUT || '5000');

interface BatchPolicyDecision {
  request_id: string;
  allow: boolean;
  reasons?: string[];
  trust_score?: number;
  risk_level?: string;
  context?: any;
  audit_info?: any;
  error?: string;
}

interface BatchEvaluationResult {
  total_requests: number;
  successful_evaluations: number;
  failed_evaluations: number;
  decisions: BatchPolicyDecision[];
  execution_time_ms: number;
  errors?: string[];
}

class BatchPolicyEvaluationService {
  private baseUrl: string;
  private bundleVersion: string;

  constructor(baseUrl: string = OPA_URL, _timeout: number = OPA_TIMEOUT) {
    this.baseUrl = baseUrl;
    this.bundleVersion = process.env.OPA_BUNDLE_VERSION || '1.0.0';
  }

  /**
   * Evaluate multiple access requests in batch
   */
  async evaluateBatch(
    requests: AccessRequest[],
    options: {
      fail_fast?: boolean;
      timeout_ms?: number;
      parallel_limit?: number;
    } = {}
  ): Promise<BatchEvaluationResult> {
    const startTime = Date.now();
    const decisions: BatchPolicyDecision[] = [];
    const errors: string[] = [];

    const fail_fast = options.fail_fast ?? false;
    const timeout_ms = options.timeout_ms ?? 30000;
    const parallel_limit = options.parallel_limit ?? 10;

    try {
      // Process requests in parallel batches
      const batches = this.createBatches(requests, parallel_limit);
      let successfulEvaluations = 0;
      let failedEvaluations = 0;

      for (const batch of batches) {
        const batchPromises = batch.map(async (request, index) => {
          const requestId = request.context.session_id || `batch_${index}`;

          try {
            // Call OPA with individual request
            const decision = await this.evaluateSingleRequest(request, timeout_ms);
            successfulEvaluations++;
            return {
              request_id: requestId,
              ...decision,
            };
          } catch (error) {
            failedEvaluations++;
            const errorMsg = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Request ${requestId}: ${errorMsg}`);

            if (fail_fast) {
              throw error;
            }

            // Return deny decision for failed requests
            return {
              request_id: requestId,
              allow: false,
              reasons: ['Policy evaluation failed'],
              error: errorMsg,
              audit_info: {
                request_id: requestId,
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
          }
        });

        const batchResults = await Promise.allSettled(batchPromises);

        batchResults.forEach((result) => {
          if (result.status === 'fulfilled') {
            decisions.push(result.value);
          } else if (fail_fast) {
            throw new Error(`Batch evaluation failed: ${result.reason}`);
          }
        });
      }

      const result: BatchEvaluationResult = {
        total_requests: requests.length,
        successful_evaluations: successfulEvaluations,
        failed_evaluations: failedEvaluations,
        decisions,
        execution_time_ms: Date.now() - startTime,
      };
      if (errors.length > 0) {
        (result as any).errors = errors;
      }

      // Audit batch evaluation
      await this.auditBatchEvaluation(result);

      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown batch evaluation error';
      console.error('Batch policy evaluation error:', error);

      // Return complete failure result
      return {
        total_requests: requests.length,
        successful_evaluations: 0,
        failed_evaluations: requests.length,
        decisions: requests.map((request, index) => ({
          request_id: request.context.session_id || `batch_${index}`,
          allow: false,
          reasons: ['Batch evaluation service error'],
          error: errorMsg,
        })),
        execution_time_ms: Date.now() - startTime,
        errors: [errorMsg],
      };
    }
  }

  /**
   * Evaluate a single request within the batch context
   */
  private async evaluateSingleRequest(
    request: AccessRequest,
    timeoutMs: number
  ): Promise<Omit<BatchPolicyDecision, 'request_id'>> {
    const cache = getAuthzCache();
    // Cast to required shape without undefined to satisfy exactOptionalPropertyTypes
    const scParams: { access_type?: string; high_risk_authorized?: boolean; no_cache?: boolean } = {};
    if (typeof request.context.access_type === 'string') scParams.access_type = request.context.access_type;
    if (typeof request.context.high_risk_authorized === 'boolean')
      scParams.high_risk_authorized = request.context.high_risk_authorized;
    const bypass = shouldBypassCache(scParams);
    const cacheKey = buildDecisionCacheKey({
      bundleVersion: this.bundleVersion,
      tenantId: request.tenant_id,
      userId: request.user.id,
      resource: request.resource,
      action: request.action,
      context: {
        ip_address: request.context.ip_address,
        region: (request.context.region as string | undefined) ?? '',
        access_type: (request.context.access_type as string | undefined) ?? '',
        device_status: (request.device?.status as string | undefined) ?? '',
        high_risk_authorized: (request.context.high_risk_authorized as boolean | undefined) ?? false,
      },
    });

    if (!bypass && cache.available()) {
      const cached = await cache.get<Omit<BatchPolicyDecision, 'request_id'>>(cacheKey);
      if (cached) {
        recordCacheHit(request.tenant_id, request.resource, request.action);
        return {
          ...cached,
          context: {
            ...(cached.context || {}),
            policy_version: this.bundleVersion,
            cache_hit: true,
          },
        };
      }
      recordCacheMiss(request.tenant_id, request.resource, request.action);
    }
    // Prepare OPA request
    const opaRequest = {
      input: request,
    };

    // Call OPA decision endpoint
    const response = await fetch(`${this.baseUrl}/v1/data/authz/allow`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(opaRequest),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`OPA request failed with status ${response.status}: ${response.statusText}`);
    }

    const opaResult = await response.json();
    const allow = opaResult.result || false;

    // Get additional context
    const contextResponse = await this.getDecisionContext(request).catch(() => null);

    const decision: Omit<BatchPolicyDecision, 'request_id'> = {
      allow,
      reasons: await this.getDecisionReasons(request, allow),
      trust_score: contextResponse?.trust_score,
      risk_level: contextResponse?.risk_level,
      context: {
        policy_version: this.bundleVersion,
        opa_response: opaResult,
      },
      audit_info: {
        request_id: request.context.session_id,
        user_id: request.user.id,
        tenant_id: request.tenant_id,
        resource: request.resource,
        action: request.action,
        timestamp: new Date().toISOString(),
        ip_address: request.context.ip_address,
        decision: allow,
      },
    };

    try {
      if (!bypass && cache.available()) {
        await cache.set(cacheKey, decision, getTtlSeconds(allow));
      }
    } catch (e) {
      console.warn('Authz cache set failed (batch):', e);
    }

    // Record metrics with unknown latency at this layer; use 0 and rely on single evaluate path or outer timers
    recordDecisionMetrics({
      tenant: request.tenant_id,
      resource: request.resource,
      action: request.action,
      allow,
      latencyMs: 0,
      cacheHit: false,
    });

    return decision;
  }

  /**
   * Create batches of requests for parallel processing
   */
  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  /**
   * Get additional decision context from OPA
   */
  private async getDecisionContext(request: AccessRequest): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/v1/data/authz/audit_context`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input: request }),
        signal: AbortSignal.timeout(2000), // Shorter timeout for context
      });

      if (response.ok) {
        const result = await response.json();
        return result.result;
      }
    } catch (error) {
      // Context is optional, don't fail the entire request
    }
    return null;
  }

  /**
   * Get human-readable reasons for policy decision
   */
  private async getDecisionReasons(request: AccessRequest, allowed: boolean): Promise<string[]> {
    const reasons: string[] = [];

    if (!allowed) {
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
   * Audit batch evaluation
   */
  private async auditBatchEvaluation(result: BatchEvaluationResult): Promise<void> {
    try {
      console.log(
        'Batch Policy Evaluation Audit:',
        JSON.stringify({
          timestamp: new Date().toISOString(),
          type: 'batch_policy_evaluation',
          total_requests: result.total_requests,
          successful_evaluations: result.successful_evaluations,
          failed_evaluations: result.failed_evaluations,
          execution_time_ms: result.execution_time_ms,
          success_rate: result.successful_evaluations / result.total_requests,
          has_errors: !!result.errors?.length,
        })
      );
    } catch (error) {
      console.error('Failed to audit batch policy evaluation:', error);
    }
  }
}

const batchPolicyService = new BatchPolicyEvaluationService();

/**
 * POST /api/policy/batch
 * Evaluate multiple access requests
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    requirePolicyApiKey(request.headers);
    const body = (await request.json()) as BatchAccessRequest;
    if (!body || !Array.isArray(body.requests) || body.requests.some((r) => !isValidAccessRequest(r))) {
      return NextResponse.json({ success: false, error: 'Invalid request format' }, { status: 400 });
    }
    const validatedRequest: BatchAccessRequest = {
      requests: body.requests,
      options: {
        fail_fast: body.options?.fail_fast ?? false,
        timeout_ms: body.options?.timeout_ms ?? 30000,
        parallel_limit: body.options?.parallel_limit ?? 10,
      },
    };

    const result = await batchPolicyService.evaluateBatch(validatedRequest.requests, validatedRequest.options);

    // Response validation
    const valid =
      typeof result.total_requests === 'number' &&
      Array.isArray(result.decisions) &&
      result.decisions.every((d) => typeof d.request_id === 'string' && typeof d.allow === 'boolean');
    if (!valid) {
      return NextResponse.json(
        { success: false, error: 'response_validation_failed', details: 'Invalid batch result format' },
        { status: 500 }
      );
    }

    return NextResponse.json(
      {
        success: true,
        data: result,
      },
      {
        status: 200,
        headers: {
          'X-Policy-Version': '1.0.0',
          'X-Batch-Size': result.total_requests.toString(),
          'X-Success-Rate': (result.successful_evaluations / result.total_requests).toString(),
          'X-Execution-Time': result.execution_time_ms.toString(),
        },
      }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error('Batch policy evaluation endpoint error:', message);

    return NextResponse.json(
      { success: false, error: 'Batch policy evaluation failed', details: message },
      { status: 500 }
    );
  }
}
