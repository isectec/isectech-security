/**
 * Mobile Dashboard Page for iSECTECH Protect PWA
 * Entry point for mobile-optimized security dashboard
 */

import React from 'react';
import { Metadata, Viewport } from 'next';
import { MobileLayout } from '@/components/mobile/mobile-layout';
import { MobileDashboard } from '@/components/mobile/mobile-dashboard';

export const metadata: Metadata = {
  title: 'Security Dashboard - iSECTECH Protect Mobile',
  description: 'Real-time security monitoring and threat detection dashboard optimized for mobile devices',
  keywords: ['security dashboard', 'mobile security', 'threat monitoring', 'PWA'],
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'default',
    title: 'iSECTECH Protect',
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

export default function MobilePage() {
  const handleRefresh = async () => {
    // Implement refresh logic here
    console.log('Refreshing dashboard...');
    
    // In a real app, this would:
    // 1. Fetch latest security metrics
    // 2. Update notification counts
    // 3. Refresh real-time data
  };

  return (
    <MobileLayout 
      title="Security Dashboard"
      showRefresh={true}
      onRefresh={handleRefresh}
    >
      <MobileDashboard />
    </MobileLayout>
  );
}