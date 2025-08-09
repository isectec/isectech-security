import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';

/**
 * API Routes for Onboarding Checklists
 * Handles dynamic checklist creation, progress tracking, and reminder scheduling
 */

// GET /api/onboarding/checklists - List checklists
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const tenantId = headers().get('x-tenant-id') || 'default';
    
    // Extract query parameters
    const customerProfileId = searchParams.get('customer_profile_id');
    const onboardingInstanceId = searchParams.get('onboarding_instance_id');
    const status = searchParams.get('status');
    const customerTier = searchParams.get('customer_tier');
    const serviceTier = searchParams.get('service_tier');
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
      status,
      customer_tier: customerTier,
      service_tier: serviceTier,
      date_range: startDate && endDate ? {
        start: new Date(startDate),
        end: new Date(endDate),
      } : undefined,
      page,
      limit,
      sort_by: sortBy,
      sort_direction: sortDirection,
    };

    // Call checklist service
    const response = await fetch(`${process.env.BACKEND_URL}/api/v1/checklists`, {
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

    const checklists = await response.json();

    return NextResponse.json({
      success: true,
      data: checklists,
    });

  } catch (error) {
    console.error('Error fetching checklists:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch checklists',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// POST /api/onboarding/checklists - Create checklist
export async function POST(request: NextRequest) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const body = await request.json();
    
    // Validate request body
    if (!body.customer_profile_id || !body.onboarding_instance_id) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required fields: customer_profile_id, onboarding_instance_id',
        },
        { status: 400 }
      );
    }

    const payload = {
      customer_profile_id: body.customer_profile_id,
      onboarding_instance_id: body.onboarding_instance_id,
      tenant_id: tenantId,
      title: body.title,
      description: body.description,
      customer_tier: body.customer_tier || 'basic',
      service_tier: body.service_tier || 'basic',
      items: body.items || [],
      due_at: body.due_at ? new Date(body.due_at) : null,
      selected_services: body.selected_services || [],
      compliance_frameworks: body.compliance_frameworks || [],
      language: body.language || 'en',
      timezone: body.timezone || 'UTC',
    };

    // Determine if this is a template-based creation or custom creation
    const endpoint = body.use_template !== false ? 
      '/api/v1/checklists/from-template' : 
      '/api/v1/checklists';

    const response = await fetch(`${process.env.BACKEND_URL}${endpoint}`, {
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
    console.error('Error creating checklist:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to create checklist',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}