import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';

/**
 * API Routes for Onboarding Communications
 * Handles welcome emails, onboarding notifications, and checklist automation
 */

// GET /api/onboarding/communications - List communications
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = headers().get('x-tenant-id') || 'default';
    
    // Extract query parameters
    const customerProfileId = searchParams.get('customer_profile_id');
    const onboardingInstanceId = searchParams.get('onboarding_instance_id');
    const type = searchParams.get('type');
    const status = searchParams.get('status');
    const customerTier = searchParams.get('customer_tier');
    const language = searchParams.get('language');
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '20');
    const sortBy = searchParams.get('sort_by') || 'created_at';
    const sortDirection = searchParams.get('sort_direction') || 'desc';
    
    // Date range filters
    const startDate = searchParams.get('start_date');
    const endDate = searchParams.get('end_date');
    
    // Build filter object
    const filter = {
      customer_profile_id: customerProfileId,
      onboarding_instance_id: onboardingInstanceId,
      type: type as any,
      status: status as any,
      customer_tier: customerTier,
      language,
      date_range: startDate && endDate ? {
        start: new Date(startDate),
        end: new Date(endDate),
      } : undefined,
      page,
      limit,
      sort_by: sortBy,
      sort_direction: sortDirection,
    };

    // Call communication service (would be replaced with actual service call)
    const response = await fetch(`${process.env.BACKEND_URL}/api/v1/communications`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
        'Authorization': request.headers.get('authorization') || '',
      },
      body: JSON.stringify(filter),
    });

    if (!response.ok) {
      throw new Error(`Backend service error: ${response.status}`);
    }

    const communications = await response.json();

    return NextResponse.json({
      success: true,
      data: communications,
    });

  } catch (error) {
    console.error('Error fetching communications:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch communications',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// POST /api/onboarding/communications - Send communication
export async function POST(request: NextRequest) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const body = await request.json();
    
    // Validate request body
    if (!body.type || !body.customer_profile_id || !body.recipient_email) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required fields: type, customer_profile_id, recipient_email',
        },
        { status: 400 }
      );
    }

    // Route to appropriate communication handler based on type
    let serviceEndpoint = '';
    let payload = { ...body, tenant_id: tenantId };

    switch (body.type) {
      case 'welcome':
        serviceEndpoint = '/api/v1/communications/welcome';
        break;
      case 'onboarding-step':
        serviceEndpoint = '/api/v1/communications/onboarding-step';
        break;
      case 'reminder':
        serviceEndpoint = '/api/v1/communications/reminder';
        break;
      case 'checklist-item':
        serviceEndpoint = '/api/v1/communications/checklist-reminder';
        break;
      case 'completion':
        serviceEndpoint = '/api/v1/communications/completion';
        break;
      default:
        return NextResponse.json(
          {
            success: false,
            error: `Unsupported communication type: ${body.type}`,
          },
          { status: 400 }
        );
    }

    // Call backend service
    const response = await fetch(`${process.env.BACKEND_URL}${serviceEndpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
        'Authorization': request.headers.get('authorization') || '',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Backend service error: ${response.status}`);
    }

    const result = await response.json();

    return NextResponse.json({
      success: true,
      data: result,
    });

  } catch (error) {
    console.error('Error sending communication:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to send communication',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// POST /api/onboarding/communications/bulk - Send bulk communications
export async function PUT(request: NextRequest) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const body = await request.json();
    
    // Validate bulk request
    if (!body.type || !body.recipients || !Array.isArray(body.recipients)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required fields: type, recipients (array)',
        },
        { status: 400 }
      );
    }

    // Validate recipients
    for (const recipient of body.recipients) {
      if (!recipient.customer_profile_id || !recipient.recipient_email) {
        return NextResponse.json(
          {
            success: false,
            error: 'Each recipient must have customer_profile_id and recipient_email',
          },
          { status: 400 }
        );
      }
    }

    const payload = {
      ...body,
      tenant_id: tenantId,
      batch_size: body.batch_size || 100,
      delay_between_batches: body.delay_between_batches || 1000, // 1 second
    };

    // Call bulk communication service
    const response = await fetch(`${process.env.BACKEND_URL}/api/v1/communications/bulk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
        'Authorization': request.headers.get('authorization') || '',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Backend service error: ${response.status}`);
    }

    const result = await response.json();

    return NextResponse.json({
      success: true,
      data: result,
    });

  } catch (error) {
    console.error('Error sending bulk communications:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to send bulk communications',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}