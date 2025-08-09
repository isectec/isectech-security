import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';

/**
 * API Routes for Checklist Item Management
 * Handles checklist item operations, completion, and verification
 */

// GET /api/onboarding/checklists/[id]/items - Get checklist items
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const { id: checklistId } = params;
    const { searchParams } = new URL(request.url);
    
    // Extract query parameters
    const status = searchParams.get('status'); // completed, pending, blocked
    const category = searchParams.get('category');
    const includeCompleted = searchParams.get('include_completed') === 'true';
    
    const queryParams = new URLSearchParams();
    if (status) queryParams.append('status', status);
    if (category) queryParams.append('category', category);
    if (includeCompleted) queryParams.append('include_completed', 'true');
    
    const url = `${process.env.BACKEND_URL}/api/v1/checklists/${checklistId}/items${
      queryParams.toString() ? '?' + queryParams.toString() : ''
    }`;

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
        'Authorization': request.headers.get('authorization') || '',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return NextResponse.json(
          {
            success: false,
            error: 'Checklist not found',
          },
          { status: 404 }
        );
      }
      throw new Error(`Backend service error: ${response.status}`);
    }

    const items = await response.json();

    return NextResponse.json({
      success: true,
      data: items,
    });

  } catch (error) {
    console.error('Error fetching checklist items:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch checklist items',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// POST /api/onboarding/checklists/[id]/items - Add item to checklist
export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const { id: checklistId } = params;
    const body = await request.json();
    
    // Validate request body
    if (!body.title || !body.description) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required fields: title, description',
        },
        { status: 400 }
      );
    }

    const payload = {
      title: body.title,
      description: body.description,
      instructions: body.instructions || '',
      category: body.category || 'general',
      is_required: body.is_required !== false,
      estimated_duration: body.estimated_duration || 15,
      depends_on: body.depends_on || [],
      action_url: body.action_url,
      action_text: body.action_text,
      requires_verification: body.requires_verification || false,
      reminder_schedule: body.reminder_schedule || [],
      created_by: body.created_by || 'system',
    };

    const response = await fetch(`${process.env.BACKEND_URL}/api/v1/checklists/${checklistId}/items`, {
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
    console.error('Error creating checklist item:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to create checklist item',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}