/**
 * PWA Management Hook for iSECTECH Protect
 * Handles installation, updates, and PWA lifecycle events
 */

'use client';

import { useState, useEffect, useCallback } from 'react';

interface PWAOptions {
  onInstallPrompt?: (event: BeforeInstallPromptEvent) => void;
  onInstalled?: () => void;
  onUpdateAvailable?: () => void;
  onUpdateReady?: () => void;
  autoUpdate?: boolean;
}

interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{
    outcome: 'accepted' | 'dismissed';
    platform: string;
  }>;
  prompt(): Promise<void>;
}

interface PWAInstallationState {
  canInstall: boolean;
  isInstalled: boolean;
  isStandalone: boolean;
  installPromptEvent: BeforeInstallPromptEvent | null;
  hasUpdate: boolean;
  isUpdating: boolean;
}

export function usePWA(options: PWAOptions = {}) {
  const [state, setState] = useState<PWAInstallationState>({
    canInstall: false,
    isInstalled: false,
    isStandalone: false,
    installPromptEvent: null,
    hasUpdate: false,
    isUpdating: false,
  });

  // Detect PWA installation state
  useEffect(() => {
    const isStandalone = () => {
      return (
        window.matchMedia('(display-mode: standalone)').matches ||
        (window.navigator as any).standalone === true ||
        document.referrer.includes('android-app://')
      );
    };

    const isInstalled = () => {
      return isStandalone() || (window as any).matchMedia?.('(display-mode: standalone)').matches;
    };

    setState(prev => ({
      ...prev,
      isStandalone: isStandalone(),
      isInstalled: isInstalled(),
    }));

    // Listen for display mode changes
    const mediaQuery = window.matchMedia('(display-mode: standalone)');
    const handleDisplayModeChange = (e: MediaQueryListEvent) => {
      setState(prev => ({
        ...prev,
        isStandalone: e.matches,
        isInstalled: e.matches,
      }));
    };

    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handleDisplayModeChange);
    } else {
      // Fallback for older browsers
      mediaQuery.addListener(handleDisplayModeChange);
    }

    return () => {
      if (mediaQuery.removeEventListener) {
        mediaQuery.removeEventListener('change', handleDisplayModeChange);
      } else {
        mediaQuery.removeListener(handleDisplayModeChange);
      }
    };
  }, []);

  // Handle install prompt
  useEffect(() => {
    const handleBeforeInstallPrompt = (e: BeforeInstallPromptEvent) => {
      e.preventDefault();
      setState(prev => ({
        ...prev,
        canInstall: true,
        installPromptEvent: e,
      }));
      options.onInstallPrompt?.(e);
    };

    const handleAppInstalled = () => {
      setState(prev => ({
        ...prev,
        canInstall: false,
        isInstalled: true,
        installPromptEvent: null,
      }));
      options.onInstalled?.();
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, [options]);

  // Handle service worker updates
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;

    const handleServiceWorkerUpdate = () => {
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        window.location.reload();
      });

      navigator.serviceWorker.addEventListener('message', (event) => {
        const { type, payload } = event.data;

        switch (type) {
          case 'UPDATE_AVAILABLE':
            setState(prev => ({ ...prev, hasUpdate: true }));
            options.onUpdateAvailable?.();
            break;
          
          case 'UPDATE_READY':
            options.onUpdateReady?.();
            if (options.autoUpdate) {
              applyUpdate();
            }
            break;
        }
      });
    };

    navigator.serviceWorker.ready.then(handleServiceWorkerUpdate);
  }, [options]);

  const install = useCallback(async (): Promise<boolean> => {
    if (!state.installPromptEvent) {
      return false;
    }

    try {
      await state.installPromptEvent.prompt();
      const { outcome } = await state.installPromptEvent.userChoice;
      
      setState(prev => ({
        ...prev,
        canInstall: false,
        installPromptEvent: null,
      }));

      return outcome === 'accepted';
    } catch (error) {
      console.error('Failed to install PWA:', error);
      return false;
    }
  }, [state.installPromptEvent]);

  const applyUpdate = useCallback(async () => {
    if (!('serviceWorker' in navigator)) return;

    setState(prev => ({ ...prev, isUpdating: true }));

    try {
      const registration = await navigator.serviceWorker.ready;
      const waitingWorker = registration.waiting;

      if (waitingWorker) {
        // Tell the waiting worker to skip waiting
        waitingWorker.postMessage({ type: 'SKIP_WAITING' });
      }
    } catch (error) {
      console.error('Failed to apply update:', error);
      setState(prev => ({ ...prev, isUpdating: false }));
    }
  }, []);

  const checkForUpdates = useCallback(async () => {
    if (!('serviceWorker' in navigator)) return false;

    try {
      const registration = await navigator.serviceWorker.ready;
      await registration.update();
      return true;
    } catch (error) {
      console.error('Failed to check for updates:', error);
      return false;
    }
  }, []);

  const getInstallationGuide = useCallback(() => {
    const userAgent = navigator.userAgent.toLowerCase();
    
    if (userAgent.includes('chrome') && !userAgent.includes('edg')) {
      return {
        browser: 'Chrome',
        steps: [
          'Tap the menu (⋮) in the top right corner',
          'Select "Add to Home screen" or "Install app"',
          'Tap "Add" to confirm installation',
        ],
      };
    } else if (userAgent.includes('safari') && !userAgent.includes('chrome')) {
      return {
        browser: 'Safari',
        steps: [
          'Tap the share button (📤) at the bottom',
          'Scroll down and tap "Add to Home Screen"',
          'Tap "Add" to confirm installation',
        ],
      };
    } else if (userAgent.includes('firefox')) {
      return {
        browser: 'Firefox',
        steps: [
          'Tap the menu (☰) in the top right corner',
          'Select "Install" or "Add to Home screen"',
          'Tap "Add" to confirm installation',
        ],
      };
    } else if (userAgent.includes('edg')) {
      return {
        browser: 'Edge',
        steps: [
          'Tap the menu (⋯) in the bottom bar',
          'Select "Add to phone" or "Install app"',
          'Tap "Add" to confirm installation',
        ],
      };
    }

    return {
      browser: 'Unknown',
      steps: [
        'Look for "Add to Home Screen" or "Install" option in your browser menu',
        'Follow the prompts to install the app',
      ],
    };
  }, []);

  const shareApp = useCallback(async (customText?: string) => {
    const shareData = {
      title: 'iSECTECH Protect',
      text: customText || 'Check out iSECTECH Protect - Enterprise Cybersecurity Command Center',
      url: window.location.origin,
    };

    if ('share' in navigator) {
      try {
        await (navigator as any).share(shareData);
        return true;
      } catch (error) {
        console.log('Native share failed, falling back to clipboard');
      }
    }

    // Fallback to clipboard
    try {
      await navigator.clipboard.writeText(
        `${shareData.text}\n${shareData.url}`
      );
      return true;
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      return false;
    }
  }, []);

  const requestPersistentStorage = useCallback(async () => {
    if ('storage' in navigator && 'persist' in navigator.storage) {
      try {
        const granted = await navigator.storage.persist();
        return granted;
      } catch (error) {
        console.error('Failed to request persistent storage:', error);
        return false;
      }
    }
    return false;
  }, []);

  const getStorageUsage = useCallback(async () => {
    if ('storage' in navigator && 'estimate' in navigator.storage) {
      try {
        const estimate = await navigator.storage.estimate();
        return {
          quota: estimate.quota || 0,
          usage: estimate.usage || 0,
          percentage: estimate.quota ? ((estimate.usage || 0) / estimate.quota) * 100 : 0,
        };
      } catch (error) {
        console.error('Failed to get storage usage:', error);
        return null;
      }
    }
    return null;
  }, []);

  return {
    ...state,
    install,
    applyUpdate,
    checkForUpdates,
    getInstallationGuide,
    shareApp,
    requestPersistentStorage,
    getStorageUsage,
  };
}