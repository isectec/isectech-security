/**
 * Providers Index for iSECTECH Protect
 * Combined providers for the application
 */

'use client';

import React from 'react';
import { ISECTechThemeProvider } from './theme-provider';
import { QueryProvider } from './query-provider';
import { PWAProvider } from '@/components/mobile/pwa-provider';

interface ProvidersProps {
  children: React.ReactNode;
}

export function Providers({ children }: ProvidersProps) {
  return (
    <ISECTechThemeProvider>
      <QueryProvider>
        <PWAProvider>
          {children}
        </PWAProvider>
      </QueryProvider>
    </ISECTechThemeProvider>
  );
}

export default Providers;