/**
 * Push Notification Subscription API Route
 * Handles device registration for push notifications
 */

import { NextRequest, NextResponse } from 'next/server';

interface SubscriptionPayload {
  subscription: {
    endpoint: string;
    keys: {
      p256dh: string;
      auth: string;
    };
  };
  userId?: string;
  deviceInfo?: {
    userAgent: string;
    platform: string;
    timestamp: string;
  };
}

export async function POST(request: NextRequest) {
  try {
    const body: SubscriptionPayload = await request.json();
    
    // Validate required fields
    if (!body.subscription || !body.subscription.endpoint) {
      return NextResponse.json(
        { error: 'Invalid subscription data' },
        { status: 400 }
      );
    }

    // In a real implementation, you would:
    // 1. Validate the subscription with the push service
    // 2. Store the subscription in your database
    // 3. Associate it with the user account
    // 4. Set up any necessary webhook handlers
    
    console.log('Push notification subscription registered:', {
      endpoint: body.subscription.endpoint.substring(0, 50) + '...',
      userId: body.userId,
      userAgent: body.deviceInfo?.userAgent?.substring(0, 50) + '...',
    });

    // Mock database save
    const subscriptionRecord = {
      id: Date.now().toString(),
      userId: body.userId || 'anonymous',
      endpoint: body.subscription.endpoint,
      keys: body.subscription.keys,
      deviceInfo: body.deviceInfo,
      createdAt: new Date().toISOString(),
      isActive: true,
    };

    // Here you would typically save to your database:
    // await db.pushSubscriptions.create(subscriptionRecord);

    return NextResponse.json({
      success: true,
      subscriptionId: subscriptionRecord.id,
      message: 'Push notification subscription registered successfully',
    });

  } catch (error) {
    console.error('Error registering push subscription:', error);
    
    return NextResponse.json(
      { 
        error: 'Failed to register push subscription',
        details: process.env.NODE_ENV === 'development' ? error : undefined 
      },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  // Get subscription status for a user
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get('userId');

  if (!userId) {
    return NextResponse.json(
      { error: 'User ID is required' },
      { status: 400 }
    );
  }

  try {
    // Mock response - in real implementation, query your database
    const subscriptions = [
      {
        id: '1',
        userId,
        endpoint: 'https://fcm.googleapis.com/fcm/send/...',
        isActive: true,
        createdAt: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
        lastUsed: new Date().toISOString(),
      }
    ];

    return NextResponse.json({
      subscriptions,
      totalActive: subscriptions.filter(s => s.isActive).length,
    });

  } catch (error) {
    console.error('Error fetching subscriptions:', error);
    
    return NextResponse.json(
      { error: 'Failed to fetch subscriptions' },
      { status: 500 }
    );
  }
}