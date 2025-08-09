export function requirePolicyApiKey(headers: Headers): void {
  const configured = process.env.POLICY_API_KEY;
  if (!configured) return; // no key configured, allow
  const provided = headers.get('x-api-key') || headers.get('authorization')?.replace(/^Bearer\s+/i, '') || '';
  if (provided !== configured) {
    const err = new Error('Unauthorized');
    // @ts-expect-error custom code
    err.statusCode = 401;
    throw err;
  }
}

