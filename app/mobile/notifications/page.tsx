/**
 * Mobile Notifications Page for iSECTECH Protect PWA
 * Real-time notification management optimized for mobile devices
 */

import React from 'react';
import { Metadata, Viewport } from 'next';
import { MobileLayout } from '@/components/mobile/mobile-layout';
import { MobileNotifications } from '@/components/mobile/mobile-notifications';

export const metadata: Metadata = {
  title: 'Notifications - iSECTECH Protect Mobile',
  description: 'Real-time security notifications and alerts management for mobile devices',
  keywords: ['security notifications', 'mobile alerts', 'real-time updates', 'PWA'],
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'default',
    title: 'Notifications',
  },
  icons: {
    apple: '/icons/icon-192x192.png',
  },
  themeColor: '#3a9fc5',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  themeColor: '#3a9fc5',
  viewportFit: 'cover',
};

export default function MobileNotificationsPage() {
  const handleRefresh = async () => {
    // Implement notification refresh logic here
    console.log('Refreshing notifications...');
    
    // In a real app, this would:
    // 1. Fetch latest notifications from API
    // 2. Update unread counts
    // 3. Sync with push notification service
    // 4. Update local cache/IndexedDB
  };

  return (
    <MobileLayout 
      title="Notifications"
      showRefresh={true}
      onRefresh={handleRefresh}
    >
      <MobileNotifications />
    </MobileLayout>
  );
}