import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';

/**
 * API Routes for Individual Checklist Management
 * Handles checklist retrieval, updates, progress tracking, and item management
 */

// GET /api/onboarding/checklists/[id] - Get specific checklist
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const { id } = params;
    
    // Call backend service to get checklist
    const response = await fetch(`${process.env.BACKEND_URL}/api/v1/checklists/${id}`, {
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

    const checklist = await response.json();

    return NextResponse.json({
      success: true,
      data: checklist,
    });

  } catch (error) {
    console.error('Error fetching checklist:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch checklist',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// PUT /api/onboarding/checklists/[id] - Update checklist
export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const { id } = params;
    const body = await request.json();
    
    const payload = {
      title: body.title,
      description: body.description,
      due_at: body.due_at ? new Date(body.due_at) : undefined,
      updated_by: body.updated_by || 'system',
    };

    const response = await fetch(`${process.env.BACKEND_URL}/api/v1/checklists/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId,
        'Authorization': request.headers.get('authorization') || '',
      },
      body: JSON.stringify(payload),
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

    const result = await response.json();

    return NextResponse.json({
      success: true,
      data: result,
    });

  } catch (error) {
    console.error('Error updating checklist:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to update checklist',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// DELETE /api/onboarding/checklists/[id] - Delete checklist
export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const { id } = params;
    
    const response = await fetch(`${process.env.BACKEND_URL}/api/v1/checklists/${id}`, {
      method: 'DELETE',
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

    return NextResponse.json({
      success: true,
      message: 'Checklist deleted successfully',
    });

  } catch (error) {
    console.error('Error deleting checklist:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to delete checklist',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}