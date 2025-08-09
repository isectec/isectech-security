/**
 * Resolve Compliance Violation API Route
 * Handles resolution of individual compliance violations
 */

import { NextRequest, NextResponse } from 'next/server';

export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const violationId = params.id;
    const body = await request.json();
    const { status, resolvedAt, resolutionNotes, verifiedBy } = body;

    // Validate the violation ID format
    if (!violationId.match(/^VIO_\d+$/)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid violation ID format',
          message: 'Violation ID must follow format VIO_XXX'
        },
        { status: 400 }
      );
    }

    // Validate resolution data
    if (!status || !['resolved', 'false_positive', 'accepted_risk'].includes(status)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid resolution status',
          message: 'Status must be one of: resolved, false_positive, accepted_risk'
        },
        { status: 400 }
      );
    }

    // In production, this would update the violation in the database
    const resolutionData = {
      violationId,
      previousStatus: 'open', // This would come from the database
      newStatus: status,
      resolvedAt: resolvedAt || new Date().toISOString(),
      resolutionNotes: resolutionNotes || '',
      verifiedBy: verifiedBy || 'system',
      resolutionId: `RES_${Date.now()}`,
      auditTrail: {
        action: 'violation_resolved',
        performedBy: verifiedBy || 'system',
        timestamp: new Date().toISOString(),
        details: {
          violationId,
          oldStatus: 'open',
          newStatus: status,
          notes: resolutionNotes
        }
      }
    };

    // Log the resolution for audit purposes
    console.log('Violation resolved:', resolutionData);

    const response = {
      success: true,
      message: `Violation ${violationId} has been marked as ${status}`,
      data: {
        violationId,
        status,
        resolvedAt: resolutionData.resolvedAt,
        resolutionId: resolutionData.resolutionId,
        verifiedBy: resolutionData.verifiedBy
      },
      timestamp: new Date().toISOString()
    };

    return NextResponse.json(response);

  } catch (error) {
    console.error('Error resolving violation:', error);
    
    return NextResponse.json(
      {
        success: false,
        error: 'Internal server error',
        message: 'Failed to resolve violation',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}