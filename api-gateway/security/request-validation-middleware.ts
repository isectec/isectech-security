import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

interface RouteKey {
  pathPattern: RegExp;
  method: HttpMethod;
}

interface RouteValidator {
  requestSchema?: z.ZodTypeAny;
}

// Schemas for high-value security endpoints (extend as needed)
const AccessRequestSchema = z.object({
  user: z.object({
    id: z.string(),
    tenant_id: z.string(),
    roles: z.array(z.string()).optional(),
    authenticated: z.boolean(),
    status: z.string().optional(),
  }),
  resource: z.string(),
  action: z.string(),
  tenant_id: z.string(),
  context: z
    .object({
      ip_address: z.string(),
      session_id: z.string(),
      region: z.string().optional(),
      access_type: z.string().optional(),
      high_risk_authorized: z.boolean().optional(),
    })
    .passthrough(),
  device: z.object({ status: z.string().optional() }).partial().optional(),
});

const BatchAccessRequestSchema = z.object({
  requests: z.array(AccessRequestSchema),
  options: z
    .object({
      fail_fast: z.boolean().optional(),
      timeout_ms: z.number().optional(),
      parallel_limit: z.number().optional(),
    })
    .optional(),
});

// Register validations per route
const registry: Array<{ key: RouteKey; validator: RouteValidator }> = [
  {
    key: { pathPattern: /^\/api\/policy\/evaluate$/, method: 'POST' },
    validator: { requestSchema: AccessRequestSchema },
  },
  {
    key: { pathPattern: /^\/api\/policy\/batch$/, method: 'POST' },
    validator: { requestSchema: BatchAccessRequestSchema },
  },
];

function findValidator(pathname: string, method: string): RouteValidator | null {
  for (const { key, validator } of registry) {
    if (key.method === (method as HttpMethod) && key.pathPattern.test(pathname)) {
      return validator;
    }
  }
  return null;
}

export async function validateIncomingRequest(request: NextRequest): Promise<NextResponse | null> {
  try {
    const { pathname } = request.nextUrl;
    const validator = findValidator(pathname, request.method);
    if (!validator || !validator.requestSchema) return null;

    // Enforce content type for JSON bodies
    const contentType = request.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return NextResponse.json(
        {
          success: false,
          error: 'invalid_content_type',
          message: 'Content-Type must be application/json',
        },
        { status: 415 }
      );
    }

    const body = await request
      .clone()
      .json()
      .catch(() => undefined);
    if (typeof body === 'undefined') {
      return NextResponse.json(
        {
          success: false,
          error: 'invalid_json',
          message: 'Request body must be valid JSON',
        },
        { status: 400 }
      );
    }

    const parseResult = validator.requestSchema.safeParse(body);
    if (!parseResult.success) {
      return NextResponse.json(
        {
          success: false,
          error: 'request_validation_failed',
          details: parseResult.error.issues.map((i) => ({ path: i.path, code: i.code, message: i.message })),
        },
        { status: 400 }
      );
    }

    return null;
  } catch (err) {
    return NextResponse.json(
      {
        success: false,
        error: 'request_validation_error',
        message: 'Validation middleware failure',
      },
      { status: 500 }
    );
  }
}
