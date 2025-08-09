import { describe, expect, it } from '@jest/globals';
import type { NextRequest } from 'next/server';
import {
  AuthorizationMiddleware,
  createAuthorizationMiddleware,
} from '../../api-gateway/security/authorization-middleware';

function mockRequest(path: string, method: string, headers: Record<string, string> = {}): NextRequest {
  const url = `https://example.org${path}`;
  // @ts-expect-error - constructing minimal NextRequest-like object for unit testing
  return {
    method,
    nextUrl: { pathname: path },
    headers: new Map(Object.entries(headers)),
    cookies: { get: () => undefined },
    ip: '127.0.0.1',
  } as unknown as NextRequest;
}

describe('Authorization Matrix', () => {
  const middleware: AuthorizationMiddleware = createAuthorizationMiddleware(
    // @ts-expect-error minimal TenantContextService created inside factory
    undefined,
    {
      enableCaching: false,
      enableAuditLogging: false,
      enableMetrics: false,
      cacheTimeoutMs: 1000,
      fallbackToDeny: true,
      maxEvaluationTimeMs: 1000,
      jwtSecret: 'test',
    }
  );

  it('denies unknown endpoints', async () => {
    const req = mockRequest('/api/unknown', 'GET');
    const res = await middleware['performEndpointAuthorization']('u', 't', '/api/unknown', 'GET', null, null);
    expect(res.allowed).toBe(false);
  });

  it('requires permissions for secured endpoints', async () => {
    const req = mockRequest('/api/v1/assets', 'GET', { Authorization: 'Bearer fake' });
    const cfg = (middleware as any)['getEndpointConfig']('/api/v1/assets', 'GET');
    expect(cfg?.permissions).toBeDefined();
  });
});
