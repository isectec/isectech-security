/**
 * Push Notifications Hook for iSECTECH Protect PWA
 * Handles push notification registration and real-time updates
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAppStore } from '@/lib/store';

interface PushNotificationOptions {
  enabled: boolean;
  vapidKey?: string;
  onNotificationReceived?: (notification: any) => void;
  onError?: (error: Error) => void;
}

interface PushSubscription {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

export function usePushNotifications(options: PushNotificationOptions = { enabled: true }) {
  const [isSupported, setIsSupported] = useState(false);
  const [permission, setPermission] = useState<NotificationPermission>('default');
  const [subscription, setSubscription] = useState<PushSubscription | null>(null);
  const [isSubscribed, setIsSubscribed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const app = useAppStore();

  // Check for push notification support
  useEffect(() => {
    const checkSupport = () => {
      const supported = 
        'serviceWorker' in navigator &&
        'PushManager' in window &&
        'Notification' in window;
      
      setIsSupported(supported);
      
      if (supported) {
        setPermission(Notification.permission);
      }
    };

    checkSupport();
  }, []);

  // Register service worker and set up push notifications
  useEffect(() => {
    if (!isSupported || !options.enabled) return;

    const initializePush = async () => {
      try {
        // Register service worker
        const registration = await navigator.serviceWorker.register('/service-worker.js');
        console.log('Service Worker registered:', registration);

        // Check for existing subscription
        const existingSubscription = await registration.pushManager.getSubscription();
        if (existingSubscription) {
          setSubscription(existingSubscription as any);
          setIsSubscribed(true);
        }

        // Listen for push messages
        navigator.serviceWorker.addEventListener('message', handleServiceWorkerMessage);
        
      } catch (err) {
        const error = err as Error;
        console.error('Failed to initialize push notifications:', error);
        setError(error.message);
        options.onError?.(error);
      }
    };

    initializePush();

    return () => {
      navigator.serviceWorker.removeEventListener('message', handleServiceWorkerMessage);
    };
  }, [isSupported, options.enabled]);

  const handleServiceWorkerMessage = useCallback((event: MessageEvent) => {
    if (event.data.type === 'PUSH_NOTIFICATION') {
      const notification = event.data.payload;
      
      // Add to notification store
      app.addNotification({
        id: notification.id || Date.now().toString(),
        type: notification.type || 'info',
        title: notification.title,
        message: notification.body,
        timestamp: new Date(),
        read: false,
        actions: notification.actions,
      });

      options.onNotificationReceived?.(notification);
    }
  }, [app, options.onNotificationReceived]);

  const requestPermission = useCallback(async (): Promise<boolean> => {
    if (!isSupported) {
      setError('Push notifications not supported');
      return false;
    }

    setIsLoading(true);
    setError(null);

    try {
      const result = await Notification.requestPermission();
      setPermission(result);
      
      if (result === 'granted') {
        return true;
      } else {
        setError('Permission denied by user');
        return false;
      }
    } catch (err) {
      const error = err as Error;
      setError(error.message);
      return false;
    } finally {
      setIsLoading(false);
    }
  }, [isSupported]);

  const subscribe = useCallback(async (): Promise<boolean> => {
    if (!isSupported) {
      setError('Push notifications not supported');
      return false;
    }

    if (permission !== 'granted') {
      const permitted = await requestPermission();
      if (!permitted) return false;
    }

    setIsLoading(true);
    setError(null);

    try {
      const registration = await navigator.serviceWorker.ready;
      
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: options.vapidKey || process.env.NEXT_PUBLIC_VAPID_KEY,
      });

      setSubscription(subscription as any);
      setIsSubscribed(true);

      // Send subscription to server
      await sendSubscriptionToServer(subscription);
      
      return true;
    } catch (err) {
      const error = err as Error;
      console.error('Failed to subscribe to push notifications:', error);
      setError(error.message);
      return false;
    } finally {
      setIsLoading(false);
    }
  }, [isSupported, permission, requestPermission, options.vapidKey]);

  const unsubscribe = useCallback(async (): Promise<boolean> => {
    if (!subscription) return true;

    setIsLoading(true);
    setError(null);

    try {
      const registration = await navigator.serviceWorker.ready;
      const pushSubscription = await registration.pushManager.getSubscription();
      
      if (pushSubscription) {
        await pushSubscription.unsubscribe();
        
        // Remove from server
        await removeSubscriptionFromServer(pushSubscription);
      }

      setSubscription(null);
      setIsSubscribed(false);
      return true;
    } catch (err) {
      const error = err as Error;
      console.error('Failed to unsubscribe from push notifications:', error);
      setError(error.message);
      return false;
    } finally {
      setIsLoading(false);
    }
  }, [subscription]);

  const sendSubscriptionToServer = async (subscription: any) => {
    try {
      const response = await fetch('/api/notifications/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          subscription: subscription.toJSON(),
          userId: app.user?.id,
          deviceInfo: {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            timestamp: new Date().toISOString(),
          },
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to register subscription with server');
      }
    } catch (error) {
      console.error('Error sending subscription to server:', error);
      throw error;
    }
  };

  const removeSubscriptionFromServer = async (subscription: any) => {
    try {
      const response = await fetch('/api/notifications/unsubscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          subscription: subscription.toJSON(),
          userId: app.user?.id,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to remove subscription from server');
      }
    } catch (error) {
      console.error('Error removing subscription from server:', error);
      // Don't throw here as the local unsubscribe was successful
    }
  };

  const sendTestNotification = useCallback(async () => {
    if (!isSubscribed) {
      setError('Not subscribed to push notifications');
      return false;
    }

    try {
      const response = await fetch('/api/notifications/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: app.user?.id,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to send test notification');
      }

      return true;
    } catch (err) {
      const error = err as Error;
      setError(error.message);
      return false;
    }
  }, [isSubscribed, app.user?.id]);

  return {
    isSupported,
    permission,
    subscription,
    isSubscribed,
    isLoading,
    error,
    requestPermission,
    subscribe,
    unsubscribe,
    sendTestNotification,
  };
}