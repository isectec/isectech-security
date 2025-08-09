/**
 * Push Notification Unsubscription API Route
 * Handles device unregistration for push notifications
 */

import { NextRequest, NextResponse } from 'next/server';

interface UnsubscriptionPayload {
  subscription: {
    endpoint: string;
    keys: {
      p256dh: string;
      auth: string;
    };
  };
  userId?: string;
}

export async function POST(request: NextRequest) {
  try {
    const body: UnsubscriptionPayload = await request.json();
    
    // Validate required fields
    if (!body.subscription || !body.subscription.endpoint) {
      return NextResponse.json(
        { error: 'Invalid subscription data' },
        { status: 400 }
      );
    }

    // In a real implementation, you would:
    // 1. Find the subscription in your database by endpoint
    // 2. Mark it as inactive or delete it
    // 3. Clean up any associated data
    // 4. Log the unsubscription for analytics
    
    console.log('Push notification subscription removed:', {
      endpoint: body.subscription.endpoint.substring(0, 50) + '...',
      userId: body.userId,
    });

    // Mock database removal
    const unsubscriptionRecord = {
      endpoint: body.subscription.endpoint,
      userId: body.userId || 'anonymous',
      removedAt: new Date().toISOString(),
      reason: 'user_requested',
    };

    // Here you would typically update your database:
    // await db.pushSubscriptions.update(
    //   { endpoint: body.subscription.endpoint },
    //   { isActive: false, removedAt: new Date() }
    // );

    return NextResponse.json({
      success: true,
      message: 'Push notification subscription removed successfully',
    });

  } catch (error) {
    console.error('Error removing push subscription:', error);
    
    return NextResponse.json(
      { 
        error: 'Failed to remove push subscription',
        details: process.env.NODE_ENV === 'development' ? error : undefined 
      },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  // Alternative endpoint for deletion via DELETE method
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get('userId');
  const endpoint = searchParams.get('endpoint');

  if (!userId && !endpoint) {
    return NextResponse.json(
      { error: 'Either userId or endpoint is required' },
      { status: 400 }
    );
  }

  try {
    // Mock deletion logic
    let deletedCount = 0;
    
    if (userId) {
      // Delete all subscriptions for user
      console.log(`Removing all push subscriptions for user: ${userId}`);
      deletedCount = 1; // Mock count
    } else if (endpoint) {
      // Delete specific subscription by endpoint
      console.log(`Removing push subscription for endpoint: ${endpoint.substring(0, 50)}...`);
      deletedCount = 1; // Mock count
    }

    return NextResponse.json({
      success: true,
      deletedCount,
      message: `${deletedCount} subscription(s) removed successfully`,
    });

  } catch (error) {
    console.error('Error deleting subscriptions:', error);
    
    return NextResponse.json(
      { error: 'Failed to delete subscriptions' },
      { status: 500 }
    );
  }
}