import { describe, expect, it } from '@jest/globals';
import { NextRequest } from 'next/server';
import { validateIncomingRequest } from '../../api-gateway/security/request-validation-middleware';

function buildReq(path: string, method: string, body: any, headers: Record<string, string> = {}) {
  const url = `https://example.org${path}`;
  const encoded = JSON.stringify(body);
  // Minimal shim to satisfy validateIncomingRequest usage
  const req: any = {
    method,
    nextUrl: { pathname: path },
    headers: new Map(Object.entries({ 'content-type': 'application/json', ...headers })),
    clone() {
      return { json: async () => body };
    },
  };
  return req as unknown as NextRequest;
}

describe('Request validation middleware', () => {
  it('rejects invalid payload for /api/policy/evaluate', async () => {
    const req = buildReq('/api/policy/evaluate', 'POST', { invalid: true });
    const res = await validateIncomingRequest(req);
    expect(res).not.toBeNull();
  });

  it('accepts valid payload for /api/policy/batch', async () => {
    const req = buildReq('/api/policy/batch', 'POST', {
      requests: [
        {
          user: { id: 'u1', tenant_id: 't1', authenticated: true },
          resource: 'r',
          action: 'read',
          tenant_id: 't1',
          context: { ip_address: '1.1.1.1', session_id: 's1' },
        },
      ],
    });
    const res = await validateIncomingRequest(req);
    expect(res).toBeNull();
  });
});
