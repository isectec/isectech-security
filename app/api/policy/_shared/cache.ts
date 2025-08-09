import crypto from 'crypto';

// Lightweight cache interface to allow pluggable backends (Redis preferred, in-memory fallback)
export interface AuthzCache {
  get<T = unknown>(key: string): Promise<T | null>;
  set<T = unknown>(key: string, value: T, ttlSeconds: number): Promise<void>;
  available(): boolean;
}

class InMemoryLRUCache implements AuthzCache {
  private store: Map<string, { value: unknown; expiresAt: number }> = new Map();
  private maxEntries: number;

  constructor(maxEntries = 5000) {
    this.maxEntries = maxEntries;
  }

  async get<T>(key: string): Promise<T | null> {
    const now = Date.now();
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= now) {
      this.store.delete(key);
      return null;
    }
    // touch LRU
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value as T;
  }

  async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.store.set(key, { value, expiresAt });
    if (this.store.size > this.maxEntries) {
      // delete oldest (first inserted) entry
      const oldestKey = this.store.keys().next().value as string | undefined;
      if (oldestKey) this.store.delete(oldestKey);
    }
  }

  available(): boolean {
    return true;
  }
}

class RedisAuthzCache implements AuthzCache {
  private client: any; // ioredis type
  private isReady = false;

  constructor(client: any) {
    this.client = client;
    this.isReady = !!client;
  }

  async get<T>(key: string): Promise<T | null> {
    if (!this.isReady) return null;
    const raw = await this.client.get(key);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    if (!this.isReady) return;
    const payload = JSON.stringify(value);
    await this.client.set(key, payload, 'EX', ttlSeconds);
  }

  available(): boolean {
    return this.isReady;
  }
}

let cacheInstance: AuthzCache | null = null;

export function getAuthzCache(): AuthzCache {
  if (cacheInstance) return cacheInstance;

  const redisUrl = process.env.REDIS_URL || process.env.ISECTECH_REDIS_URL;
  if (redisUrl) {
    // Dynamically import ioredis to avoid hard dependency when not installed
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const IORedis = require('ioredis');
      const tls = (process.env.REDIS_TLS || 'true').toLowerCase() === 'true';
      const client = new IORedis.default(redisUrl, tls ? { tls: { rejectUnauthorized: true } } : {});
      cacheInstance = new RedisAuthzCache(client);
      return cacheInstance;
    } catch (e) {
      // Fallback to in-memory if ioredis is not available at runtime
      cacheInstance = new InMemoryLRUCache();
      return cacheInstance;
    }
  }

  cacheInstance = new InMemoryLRUCache();
  return cacheInstance;
}

export function buildDecisionCacheKey(params: {
  bundleVersion: string;
  tenantId: string;
  userId: string;
  resource: string;
  action: string;
  context: {
    ip_address?: string;
    region?: string;
    access_type?: string;
    device_status?: string;
    high_risk_authorized?: boolean;
  };
}): string {
  const { bundleVersion, tenantId, userId, resource, action, context } = params;
  const ctx = JSON.stringify({
    ip: context.ip_address || '',
    region: context.region || '',
    access: context.access_type || '',
    device: context.device_status || '',
    hra: !!context.high_risk_authorized,
  });
  const ctxHash = crypto.createHash('sha256').update(ctx).digest('hex');
  return `authz:${bundleVersion}:${tenantId}:${userId}:${resource}:${action}:${ctxHash}`;
}

export function getTtlSeconds(allow: boolean): number {
  const allowTtl = parseInt(process.env.AUTHZ_CACHE_TTL_SECONDS || '60', 10);
  const denyTtl = parseInt(process.env.AUTHZ_DENY_TTL_SECONDS || '15', 10);
  return allow ? allowTtl : denyTtl;
}

export function shouldBypassCache(input: {
  access_type?: string;
  high_risk_authorized?: boolean;
  no_cache?: boolean;
}): boolean {
  if (input.no_cache) return true;
  if (input.high_risk_authorized) return true;
  if (input.access_type && ['emergency'].includes(input.access_type)) return true;
  return false;
}
