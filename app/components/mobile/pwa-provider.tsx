/**
 * PWA Provider for iSECTECH Protect
 * Manages PWA lifecycle, push notifications, and offline functionality
 */

'use client';

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { 
  Snackbar, 
  Alert, 
  Button, 
  Box,
  Typography,
  IconButton,
  Slide,
} from '@mui/material';
import {
  Close as CloseIcon,
  GetApp as InstallIcon,
  Refresh as UpdateIcon,
  WifiOff as OfflineIcon,
  Notifications as NotificationsIcon,
} from '@mui/icons-material';

import { usePWA } from '@/lib/hooks/use-pwa';
import { usePushNotifications } from '@/lib/hooks/use-push-notifications';
import { useOffline } from '@/lib/hooks/use-offline';
import { performanceMonitor, performanceReporting, batteryOptimization } from '@/lib/mobile/performance';

interface PWAContextValue {
  isOnline: boolean;
  canInstall: boolean;
  isInstalled: boolean;
  hasUpdate: boolean;
  install: () => Promise<boolean>;
  applyUpdate: () => Promise<void>;
  requestNotifications: () => Promise<boolean>;
  isNotificationsEnabled: boolean;
}

const PWAContext = createContext<PWAContextValue | null>(null);

export function usePWAContext() {
  const context = useContext(PWAContext);
  if (!context) {
    throw new Error('usePWAContext must be used within PWAProvider');
  }
  return context;
}

interface PWAProviderProps {
  children: ReactNode;
}

export function PWAProvider({ children }: PWAProviderProps) {
  const [showInstallPrompt, setShowInstallPrompt] = useState(false);
  const [showUpdatePrompt, setShowUpdatePrompt] = useState(false);
  const [showOfflineAlert, setShowOfflineAlert] = useState(false);
  const [showNotificationPrompt, setShowNotificationPrompt] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [batteryOptimized, setBatteryOptimized] = useState(false);

  // PWA hooks
  const pwa = usePWA({
    onInstallPrompt: () => {
      setShowInstallPrompt(true);
    },
    onInstalled: () => {
      setShowInstallPrompt(false);
      // Report successful installation
      performanceReporting.reportMetrics('/api/analytics/pwa-install');
    },
    onUpdateAvailable: () => {
      setShowUpdatePrompt(true);
    },
    autoUpdate: false, // We'll handle updates manually
  });

  const pushNotifications = usePushNotifications({
    enabled: true,
    vapidKey: process.env.NEXT_PUBLIC_VAPID_KEY,
    onNotificationReceived: (notification) => {
      console.log('Push notification received:', notification);
    },
    onError: (error) => {
      console.error('Push notification error:', error);
    },
  });

  const offline = useOffline({
    onOnline: () => {
      setShowOfflineAlert(false);
      console.log('App is back online');
    },
    onOffline: () => {
      setShowOfflineAlert(true);
      console.log('App is offline');
    },
    checkInterval: 30000, // Check every 30 seconds
    pingUrl: '/api/health',
  });

  // Initialize PWA features
  useEffect(() => {
    const initializePWA = async () => {
      // Request persistent storage
      await pwa.requestPersistentStorage();

      // Check if user should be prompted for notifications
      if (pwa.isInstalled && pushNotifications.permission === 'default') {
        setTimeout(() => {
          setShowNotificationPrompt(true);
        }, 5000); // Wait 5 seconds after install
      }

      // Apply battery optimizations if needed
      const batteryOptimizations = await batteryOptimization.applyBatterySavingMode();
      setBatteryOptimized(batteryOptimizations.reducedAnimations);

      // Report initial performance metrics
      setTimeout(() => {
        performanceReporting.reportMetrics('/api/analytics/pwa-load');
      }, 2000);
    };

    initializePWA();
  }, [pwa.isInstalled, pushNotifications.permission]);

  // Handle install
  const handleInstall = async () => {
    const success = await pwa.install();
    if (success) {
      setShowInstallPrompt(false);
    }
  };

  // Handle update
  const handleUpdate = async () => {
    setIsUpdating(true);
    try {
      await pwa.applyUpdate();
    } catch (error) {
      console.error('Failed to apply update:', error);
      setIsUpdating(false);
    }
  };

  // Handle notification permission
  const handleNotificationRequest = async () => {
    const success = await pushNotifications.subscribe();
    setShowNotificationPrompt(false);
    
    if (success) {
      console.log('Notifications enabled successfully');
    }
  };

  const contextValue: PWAContextValue = {
    isOnline: offline.isOnline,
    canInstall: pwa.canInstall,
    isInstalled: pwa.isInstalled,
    hasUpdate: pwa.hasUpdate,
    install: pwa.install,
    applyUpdate: pwa.applyUpdate,
    requestNotifications: pushNotifications.subscribe,
    isNotificationsEnabled: pushNotifications.isSubscribed,
  };

  return (
    <PWAContext.Provider value={contextValue}>
      {children}

      {/* Install App Prompt */}
      <Snackbar
        open={showInstallPrompt && !pwa.isInstalled}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        TransitionComponent={Slide}
        TransitionProps={{ direction: 'up' }}
      >
        <Alert
          severity="info"
          variant="filled"
          sx={{ width: '100%' }}
          icon={<InstallIcon />}
          action={
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                color="inherit"
                size="small"
                onClick={handleInstall}
                sx={{ fontWeight: 600 }}
              >
                Install
              </Button>
              <IconButton
                size="small"
                color="inherit"
                onClick={() => setShowInstallPrompt(false)}
              >
                <CloseIcon fontSize="small" />
              </IconButton>
            </Box>
          }
        >
          <Typography variant="body2" sx={{ fontWeight: 500 }}>
            Install iSECTECH Protect for better performance and offline access
          </Typography>
        </Alert>
      </Snackbar>

      {/* App Update Available */}
      <Snackbar
        open={showUpdatePrompt}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        TransitionComponent={Slide}
        TransitionProps={{ direction: 'down' }}
      >
        <Alert
          severity="warning"
          variant="filled"
          sx={{ width: '100%' }}
          icon={<UpdateIcon />}
          action={
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                color="inherit"
                size="small"
                onClick={handleUpdate}
                disabled={isUpdating}
                sx={{ fontWeight: 600 }}
              >
                {isUpdating ? 'Updating...' : 'Update'}
              </Button>
              <IconButton
                size="small"
                color="inherit"
                onClick={() => setShowUpdatePrompt(false)}
                disabled={isUpdating}
              >
                <CloseIcon fontSize="small" />
              </IconButton>
            </Box>
          }
        >
          <Typography variant="body2" sx={{ fontWeight: 500 }}>
            A new version is available with security improvements
          </Typography>
        </Alert>
      </Snackbar>

      {/* Offline Alert */}
      <Snackbar
        open={showOfflineAlert}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Alert
          severity="warning"
          variant="filled"
          icon={<OfflineIcon />}
          onClose={() => setShowOfflineAlert(false)}
        >
          <Typography variant="body2">
            You're offline. Some features may be limited.
          </Typography>
        </Alert>
      </Snackbar>

      {/* Notification Permission Prompt */}
      <Snackbar
        open={showNotificationPrompt}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        TransitionComponent={Slide}
        TransitionProps={{ direction: 'up' }}
      >
        <Alert
          severity="info"
          variant="filled"
          sx={{ width: '100%' }}
          icon={<NotificationsIcon />}
          action={
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                color="inherit"
                size="small"
                onClick={handleNotificationRequest}
                sx={{ fontWeight: 600 }}
              >
                Allow
              </Button>
              <Button
                color="inherit"
                size="small"
                onClick={() => setShowNotificationPrompt(false)}
              >
                Skip
              </Button>
            </Box>
          }
        >
          <Typography variant="body2" sx={{ fontWeight: 500 }}>
            Enable notifications to stay informed of critical security alerts
          </Typography>
        </Alert>
      </Snackbar>
    </PWAContext.Provider>
  );
}

export default PWAProvider;