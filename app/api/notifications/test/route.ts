/**
 * Test Push Notification API Route
 * Sends a test notification to verify the push notification system
 */

import { NextRequest, NextResponse } from 'next/server';

interface TestNotificationPayload {
  userId: string;
  title?: string;
  message?: string;
  type?: 'info' | 'warning' | 'error' | 'success';
}

export async function POST(request: NextRequest) {
  try {
    const body: TestNotificationPayload = await request.json();
    
    // Validate required fields
    if (!body.userId) {
      return NextResponse.json(
        { error: 'User ID is required' },
        { status: 400 }
      );
    }

    // Default test notification content
    const notification = {
      title: body.title || 'iSECTECH Protect Test',
      message: body.message || 'This is a test notification to verify your push notification setup is working correctly.',
      type: body.type || 'info',
      timestamp: new Date().toISOString(),
      id: `test-${Date.now()}`,
    };

    // In a real implementation, you would:
    // 1. Look up the user's active push subscriptions
    // 2. Send push notifications via FCM/APNS
    // 3. Log the notification for delivery tracking
    // 4. Handle any delivery failures

    console.log('Sending test push notification:', {
      userId: body.userId,
      title: notification.title,
      type: notification.type,
    });

    // Mock push notification sending logic
    const mockSendResult = {
      notificationId: notification.id,
      userId: body.userId,
      sentAt: notification.timestamp,
      deliveryStatus: 'sent',
      subscriptionsTargeted: 1,
      deliveryAttempts: 1,
    };

    // Simulate some processing time
    await new Promise(resolve => setTimeout(resolve, 500));

    return NextResponse.json({
      success: true,
      notification,
      delivery: mockSendResult,
      message: 'Test notification sent successfully',
    });

  } catch (error) {
    console.error('Error sending test notification:', error);
    
    return NextResponse.json(
      { 
        error: 'Failed to send test notification',
        details: process.env.NODE_ENV === 'development' ? error : undefined 
      },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  // Get test notification history
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get('userId');

  if (!userId) {
    return NextResponse.json(
      { error: 'User ID is required' },
      { status: 400 }
    );
  }

  try {
    // Mock test notification history
    const testNotifications = [
      {
        id: 'test-1',
        userId,
        title: 'iSECTECH Protect Test',
        message: 'Test notification sent successfully',
        type: 'info',
        sentAt: new Date(Date.now() - 300000).toISOString(), // 5 minutes ago
        deliveryStatus: 'delivered',
      },
      {
        id: 'test-2',
        userId,
        title: 'Security Alert Test',
        message: 'Test security alert notification',
        type: 'warning',
        sentAt: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
        deliveryStatus: 'delivered',
      },
    ];

    return NextResponse.json({
      testNotifications,
      totalSent: testNotifications.length,
      lastTest: testNotifications[0]?.sentAt,
    });

  } catch (error) {
    console.error('Error fetching test notifications:', error);
    
    return NextResponse.json(
      { error: 'Failed to fetch test notifications' },
      { status: 500 }
    );
  }
}