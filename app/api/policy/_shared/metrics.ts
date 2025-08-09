import client from 'prom-client';

// Initialize default registry and metrics once per process
const register = new client.Registry();
client.collectDefaultMetrics({ register, prefix: 'isectech_' });

export const decisionsTotal = new client.Counter({
  name: 'isectech_pdp_decisions_total',
  help: 'Total number of PDP decisions',
  labelNames: ['tenant', 'resource', 'action', 'allow'] as const,
});

export const decisionErrorsTotal = new client.Counter({
  name: 'isectech_pdp_errors_total',
  help: 'Total number of PDP errors',
  labelNames: ['tenant', 'resource', 'action'] as const,
});

export const decisionLatencyMs = new client.Histogram({
  name: 'isectech_pdp_decision_latency_ms',
  help: 'Latency of PDP decisions in milliseconds',
  labelNames: ['tenant', 'resource', 'action', 'cache_hit'] as const,
  buckets: [5, 10, 20, 50, 100, 200, 500, 1000],
});

export const cacheHits = new client.Counter({
  name: 'isectech_pdp_cache_hits_total',
  help: 'Total cache hits in PDP',
  labelNames: ['tenant', 'resource', 'action'] as const,
});

export const cacheMisses = new client.Counter({
  name: 'isectech_pdp_cache_misses_total',
  help: 'Total cache misses in PDP',
  labelNames: ['tenant', 'resource', 'action'] as const,
});

// Register metrics
register.registerMetric(decisionsTotal);
register.registerMetric(decisionErrorsTotal);
register.registerMetric(decisionLatencyMs);
register.registerMetric(cacheHits);
register.registerMetric(cacheMisses);

export function recordDecisionMetrics(params: {
  tenant: string;
  resource: string;
  action: string;
  allow: boolean;
  latencyMs: number;
  cacheHit: boolean;
}) {
  const { tenant, resource, action, allow, latencyMs, cacheHit } = params;
  decisionsTotal.inc({ tenant, resource, action, allow: allow ? 'true' : 'false' });
  decisionLatencyMs.observe({ tenant, resource, action, cache_hit: cacheHit ? 'true' : 'false' }, latencyMs);
}

export function recordCacheHit(tenant: string, resource: string, action: string) {
  cacheHits.inc({ tenant, resource, action });
}

export function recordCacheMiss(tenant: string, resource: string, action: string) {
  cacheMisses.inc({ tenant, resource, action });
}

export function recordDecisionError(tenant: string, resource: string, action: string) {
  decisionErrorsTotal.inc({ tenant, resource, action });
}

export { register };
