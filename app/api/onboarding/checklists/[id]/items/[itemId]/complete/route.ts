import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';

/**
 * API Route for Completing Checklist Items
 * Handles item completion, verification, and progress updates
 */

// POST /api/onboarding/checklists/[id]/items/[itemId]/complete - Complete checklist item
export async function POST(
  request: NextRequest,
  { params }: { params: { id: string; itemId: string } }
) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const { id: checklistId, itemId } = params;
    const body = await request.json();
    
    // Validate request
    if (!body.completed_by) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required field: completed_by',
        },
        { status: 400 }
      );
    }

    const payload = {
      completed_by: body.completed_by,
      completion_notes: body.completion_notes || null,
      verification_required: body.verification_required || false,
    };

    const response = await fetch(
      `${process.env.BACKEND_URL}/api/v1/checklists/${checklistId}/items/${itemId}/complete`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': tenantId,
          'Authorization': request.headers.get('authorization') || '',
        },
        body: JSON.stringify(payload),
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        return NextResponse.json(
          {
            success: false,
            error: 'Checklist item not found',
          },
          { status: 404 }
        );
      }
      
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Backend service error: ${response.status}`);
    }

    const result = await response.json();

    // Trigger progress update
    try {
      await fetch(`${process.env.BACKEND_URL}/api/v1/checklists/${checklistId}/progress`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': tenantId,
          'Authorization': request.headers.get('authorization') || '',
        },
      });
    } catch (progressError) {
      console.error('Error updating checklist progress:', progressError);
      // Don't fail the request if progress update fails
    }

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Checklist item completed successfully',
    });

  } catch (error) {
    console.error('Error completing checklist item:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to complete checklist item',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// DELETE /api/onboarding/checklists/[id]/items/[itemId]/complete - Uncomplete checklist item
export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string; itemId: string } }
) {
  try {
    const tenantId = headers().get('x-tenant-id') || 'default';
    const { id: checklistId, itemId } = params;
    const body = await request.json();
    
    const payload = {
      uncompleted_by: body.uncompleted_by || 'system',
      reason: body.reason || 'Marked as incomplete',
    };

    const response = await fetch(
      `${process.env.BACKEND_URL}/api/v1/checklists/${checklistId}/items/${itemId}/uncomplete`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': tenantId,
          'Authorization': request.headers.get('authorization') || '',
        },
        body: JSON.stringify(payload),
      }
    );

    if (!response.ok) {
      if (response.status === 404) {
        return NextResponse.json(
          {
            success: false,
            error: 'Checklist item not found',
          },
          { status: 404 }
        );
      }
      
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Backend service error: ${response.status}`);
    }

    const result = await response.json();

    // Trigger progress update
    try {
      await fetch(`${process.env.BACKEND_URL}/api/v1/checklists/${checklistId}/progress`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': tenantId,
          'Authorization': request.headers.get('authorization') || '',
        },
      });
    } catch (progressError) {
      console.error('Error updating checklist progress:', progressError);
      // Don't fail the request if progress update fails
    }

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Checklist item marked as incomplete',
    });

  } catch (error) {
    console.error('Error uncompleting checklist item:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to uncomplete checklist item',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}