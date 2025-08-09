/**
 * Store Initializer for iSECTECH Protect
 * Initializes and connects stores with API client and global state
 */

'use client';

import { config } from '@/config/app';
import { apiClient } from '@/lib/api/client';
import { useCacheSync } from '@/lib/hooks/use-cache-sync';
import { setApiClient, useAppStore, useAuthStore } from '@/lib/store';
import { useEffect } from 'react';

export function StoreInitializer() {
  // Initialize cache synchronization
  const { syncCache } = useCacheSync();

  useEffect(() => {
    // Initialize API client with store references
    setApiClient(apiClient);

    // Make stores available globally for API client
    if (typeof window !== 'undefined') {
      (window as any).__AUTH_STORE__ = useAuthStore.getState();
      (window as any).__APP_STORE__ = useAppStore.getState();
      (window as any).__API_CLIENT__ = apiClient;
    }

    // Start session timer if authenticated
    const { isAuthenticated, startSessionTimer } = useAuthStore.getState();
    if (isAuthenticated) {
      startSessionTimer();
    }

    // Check initial connection status
    const { checkConnectivity } = useAppStore.getState();
    checkConnectivity();

    // Set up periodic connection checks
    const connectionCheckInterval = setInterval(() => {
      checkConnectivity();
    }, 30000); // Check every 30 seconds

    // Set up feature flags from environment
    const { setFeatureFlag } = useAppStore.getState();
    Object.entries(config.features).forEach(([flag, enabled]) => {
      setFeatureFlag(flag, enabled);
    });

    // Set up performance monitoring
    if (config.performance.enablePerfMonitoring && typeof window !== 'undefined') {
      // Monitor navigation timing
      const observer = new PerformanceObserver((list) => {
        const { updatePerformanceMetrics } = useAppStore.getState();

        list.getEntries().forEach((entry) => {
          if (entry.entryType === 'navigation') {
            const navEntry = entry as PerformanceNavigationTiming;
            updatePerformanceMetrics({
              loadTime: navEntry.loadEventEnd - navEntry.navigationStart,
            });
          }
        });
      });

      observer.observe({ entryTypes: ['navigation'] });

      // Clean up observer
      return () => {
        observer.disconnect();
        clearInterval(connectionCheckInterval);
      };
    }

    return () => {
      clearInterval(connectionCheckInterval);
    };
  }, []);

  // Subscribe to auth state changes to update API client
  useEffect(() => {
    const unsubscribe = useAuthStore.subscribe(
      (state) => state.tokens,
      (tokens) => {
        // Update global store reference when tokens change
        if (typeof window !== 'undefined') {
          (window as any).__AUTH_STORE__ = useAuthStore.getState();
        }
      }
    );

    return unsubscribe;
  }, []);

  // Subscribe to connection status changes
  useEffect(() => {
    const unsubscribe = useAppStore.subscribe(
      (state) => state.connectionStatus,
      (connectionStatus) => {
        // Show notification when connection status changes
        const { showWarning, showSuccess } = useAppStore.getState();

        if (!connectionStatus.online) {
          showWarning('Connection Lost', 'You are currently offline. Some features may not be available.');
        } else if (!connectionStatus.apiConnected) {
          showWarning('API Disconnected', 'Unable to connect to the server. Retrying...');
        } else if (connectionStatus.online && connectionStatus.apiConnected) {
          // Only show success if we were previously disconnected
          const prevState = useAppStore.getState().connectionStatus;
          if (!prevState.online || !prevState.apiConnected) {
            showSuccess('Connection Restored', 'Successfully reconnected to the server.');
          }
        }
      }
    );

    return unsubscribe;
  }, []);

  return null; // This component doesn't render anything
}

export default StoreInitializer;
