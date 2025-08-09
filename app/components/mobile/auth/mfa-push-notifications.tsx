'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Shield, 
  Bell, 
  AlertTriangle, 
  Check, 
  X,
  Clock,
  Smartphone,
  Key,
  RefreshCw,
  QrCode
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';

/**
 * Multi-Factor Authentication with Push Notifications
 * Production-grade MFA implementation with WebPush API integration
 * Supports TOTP, push notifications, and backup codes
 */

export interface MFAConfig {
  serviceWorkerPath?: string;
  vapidPublicKey: string;
  totpSecret?: string;
  backupCodes?: string[];
  pushEndpoint: string;
  totpEndpoint: string;
  verificationEndpoint: string;
  registrationEndpoint: string;
}

export interface PushSubscription {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

export interface MFAChallenge {
  challengeId: string;
  challengeType: 'push' | 'totp' | 'backup';
  expiresAt: number;
  metadata?: {
    deviceInfo?: string;
    location?: string;
    ipAddress?: string;
    userAgent?: string;
  };
}

export interface MFAVerificationResult {
  success: boolean;
  challengeId: string;
  verificationMethod: string;
  timestamp: number;
  error?: string;
  requiresAdditionalAuth?: boolean;
  nextChallenge?: MFAChallenge;
}

interface MFAPushNotificationsProps {
  config: MFAConfig;
  userId: string;
  sessionToken: string;
  onVerificationSuccess: (result: MFAVerificationResult) => void;
  onVerificationFailure: (error: string) => void;
  onRegistrationComplete?: () => void;
  autoRegisterPush?: boolean;
  enableTOTP?: boolean;
  enableBackupCodes?: boolean;
}

// Security constants for MFA
const MFA_CONFIG = {
  PUSH_TIMEOUT: 60000, // 1 minute
  TOTP_WINDOW: 30000, // 30 seconds
  CHALLENGE_VALIDITY: 300000, // 5 minutes
  MAX_ATTEMPTS: 3,
  BACKUP_CODE_LENGTH: 8,
  POLLING_INTERVAL: 2000,
} as const;

export function MFAPushNotifications({
  config,
  userId,
  sessionToken,
  onVerificationSuccess,
  onVerificationFailure,
  onRegistrationComplete,
  autoRegisterPush = true,
  enableTOTP = true,
  enableBackupCodes = true
}: MFAPushNotificationsProps) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationMethod, setVerificationMethod] = useState<'push' | 'totp' | 'backup'>('push');
  const [currentChallenge, setCurrentChallenge] = useState<MFAChallenge | null>(null);
  const [pushSubscription, setPushSubscription] = useState<PushSubscription | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [backupCode, setBackupCode] = useState('');
  const [lastError, setLastError] = useState<string | null>(null);
  const [timeRemaining, setTimeRemaining] = useState(0);
  const [attemptCount, setAttemptCount] = useState(0);
  const [pushPermissionStatus, setPushPermissionStatus] = useState<NotificationPermission>('default');
  
  const pollingIntervalRef = useRef<NodeJS.Timeout>();
  const countdownIntervalRef = useRef<NodeJS.Timeout>();

  /**
   * Check push notification support and permissions
   */
  const checkPushSupport = useCallback(async (): Promise<boolean> => {
    if (!('serviceWorker' in navigator)) {
      setLastError('Service Worker not supported');
      return false;
    }

    if (!('PushManager' in window)) {
      setLastError('Push API not supported');
      return false;
    }

    if (!('Notification' in window)) {
      setLastError('Notifications not supported');
      return false;
    }

    const permission = await Notification.requestPermission();
    setPushPermissionStatus(permission);
    
    if (permission !== 'granted') {
      setLastError('Notification permission denied');
      return false;
    }

    return true;
  }, []);

  /**
   * Register service worker for push notifications
   */
  const registerServiceWorker = useCallback(async (): Promise<ServiceWorkerRegistration> => {
    const swPath = config.serviceWorkerPath || '/sw.js';
    
    try {
      const registration = await navigator.serviceWorker.register(swPath);
      await navigator.serviceWorker.ready;
      return registration;
    } catch (error) {
      throw new Error(`Service Worker registration failed: ${error}`);
    }
  }, [config.serviceWorkerPath]);

  /**
   * Subscribe to push notifications
   */
  const subscribeToPush = useCallback(async (): Promise<PushSubscription> => {
    const isSupported = await checkPushSupport();
    if (!isSupported) {
      throw new Error('Push notifications not supported or permitted');
    }

    const registration = await registerServiceWorker();
    
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(config.vapidPublicKey)
    });

    const subscriptionData: PushSubscription = {
      endpoint: subscription.endpoint,
      keys: {
        p256dh: arrayBufferToBase64(subscription.getKey('p256dh')!),
        auth: arrayBufferToBase64(subscription.getKey('auth')!)
      }
    };

    return subscriptionData;
  }, [checkPushSupport, registerServiceWorker, config.vapidPublicKey]);

  /**
   * Register push subscription with backend
   */
  const registerPushSubscription = useCallback(async () => {
    setIsRegistering(true);
    setLastError(null);

    try {
      const subscription = await subscribeToPush();
      
      const response = await fetch(config.registrationEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`
        },
        body: JSON.stringify({
          userId,
          subscription,
          deviceInfo: {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            timestamp: Date.now()
          }
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || 'Push registration failed');
      }

      setPushSubscription(subscription);
      onRegistrationComplete?.();
      
    } catch (error: any) {
      setLastError(error.message || 'Failed to register for push notifications');
    } finally {
      setIsRegistering(false);
    }
  }, [subscribeToPush, config.registrationEndpoint, sessionToken, userId, onRegistrationComplete]);

  /**
   * Initiate MFA challenge
   */
  const initiateMFAChallenge = useCallback(async (method: 'push' | 'totp' | 'backup') => {
    setIsVerifying(true);
    setLastError(null);
    setVerificationMethod(method);

    try {
      const response = await fetch(config.verificationEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`
        },
        body: JSON.stringify({
          userId,
          challengeType: method,
          metadata: {
            userAgent: navigator.userAgent,
            timestamp: Date.now()
          }
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || 'Failed to initiate MFA challenge');
      }

      const challenge: MFAChallenge = await response.json();
      setCurrentChallenge(challenge);
      
      const timeLeft = challenge.expiresAt - Date.now();
      setTimeRemaining(timeLeft);

      // Start countdown timer
      countdownIntervalRef.current = setInterval(() => {
        setTimeRemaining(prev => {
          if (prev <= 1000) {
            setLastError('Challenge expired');
            setCurrentChallenge(null);
            setIsVerifying(false);
            return 0;
          }
          return prev - 1000;
        });
      }, 1000);

      // For push notifications, start polling for verification
      if (method === 'push' && pushSubscription) {
        startVerificationPolling(challenge.challengeId);
      }

    } catch (error: any) {
      setLastError(error.message || 'Failed to initiate MFA challenge');
      setIsVerifying(false);
    }
  }, [config.verificationEndpoint, sessionToken, userId, pushSubscription]);

  /**
   * Poll for push notification verification
   */
  const startVerificationPolling = useCallback((challengeId: string) => {
    pollingIntervalRef.current = setInterval(async () => {
      try {
        const response = await fetch(`${config.verificationEndpoint}/${challengeId}/status`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${sessionToken}`
          }
        });

        if (response.ok) {
          const result = await response.json();
          if (result.verified) {
            clearPollingAndCountdown();
            setIsVerifying(false);
            onVerificationSuccess({
              success: true,
              challengeId,
              verificationMethod: 'push',
              timestamp: Date.now()
            });
          }
        }
      } catch (error) {
        console.error('Polling error:', error);
      }
    }, MFA_CONFIG.POLLING_INTERVAL);
  }, [config.verificationEndpoint, sessionToken, onVerificationSuccess]);

  /**
   * Verify TOTP code
   */
  const verifyTOTPCode = useCallback(async () => {
    if (!totpCode || totpCode.length !== 6) {
      setLastError('Please enter a valid 6-digit code');
      return;
    }

    if (!currentChallenge) {
      setLastError('No active challenge');
      return;
    }

    try {
      const response = await fetch(config.totpEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`
        },
        body: JSON.stringify({
          challengeId: currentChallenge.challengeId,
          code: totpCode,
          userId
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        setAttemptCount(prev => prev + 1);
        
        if (attemptCount + 1 >= MFA_CONFIG.MAX_ATTEMPTS) {
          throw new Error('Maximum attempts exceeded');
        }
        
        throw new Error(errorData.message || 'Invalid TOTP code');
      }

      const result = await response.json();
      clearPollingAndCountdown();
      setIsVerifying(false);
      setTotpCode('');
      
      onVerificationSuccess({
        success: true,
        challengeId: currentChallenge.challengeId,
        verificationMethod: 'totp',
        timestamp: Date.now()
      });

    } catch (error: any) {
      setLastError(error.message || 'TOTP verification failed');
      
      if (attemptCount + 1 >= MFA_CONFIG.MAX_ATTEMPTS) {
        setIsVerifying(false);
        onVerificationFailure('Maximum attempts exceeded');
      }
    }
  }, [totpCode, currentChallenge, config.totpEndpoint, sessionToken, userId, attemptCount, onVerificationSuccess, onVerificationFailure]);

  /**
   * Verify backup code
   */
  const verifyBackupCode = useCallback(async () => {
    if (!backupCode || backupCode.length !== MFA_CONFIG.BACKUP_CODE_LENGTH) {
      setLastError(`Please enter a valid ${MFA_CONFIG.BACKUP_CODE_LENGTH}-character backup code`);
      return;
    }

    if (!currentChallenge) {
      setLastError('No active challenge');
      return;
    }

    try {
      const response = await fetch(`${config.verificationEndpoint}/backup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`
        },
        body: JSON.stringify({
          challengeId: currentChallenge.challengeId,
          backupCode: backupCode.toUpperCase(),
          userId
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        setAttemptCount(prev => prev + 1);
        
        if (attemptCount + 1 >= MFA_CONFIG.MAX_ATTEMPTS) {
          throw new Error('Maximum attempts exceeded');
        }
        
        throw new Error(errorData.message || 'Invalid backup code');
      }

      const result = await response.json();
      clearPollingAndCountdown();
      setIsVerifying(false);
      setBackupCode('');
      
      onVerificationSuccess({
        success: true,
        challengeId: currentChallenge.challengeId,
        verificationMethod: 'backup',
        timestamp: Date.now()
      });

    } catch (error: any) {
      setLastError(error.message || 'Backup code verification failed');
      
      if (attemptCount + 1 >= MFA_CONFIG.MAX_ATTEMPTS) {
        setIsVerifying(false);
        onVerificationFailure('Maximum attempts exceeded');
      }
    }
  }, [backupCode, currentChallenge, config.verificationEndpoint, sessionToken, userId, attemptCount, onVerificationSuccess, onVerificationFailure]);

  /**
   * Clear polling and countdown timers
   */
  const clearPollingAndCountdown = useCallback(() => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = undefined;
    }
    if (countdownIntervalRef.current) {
      clearInterval(countdownIntervalRef.current);
      countdownIntervalRef.current = undefined;
    }
  }, []);

  /**
   * Cancel current verification
   */
  const cancelVerification = useCallback(() => {
    clearPollingAndCountdown();
    setCurrentChallenge(null);
    setIsVerifying(false);
    setTotpCode('');
    setBackupCode('');
    setAttemptCount(0);
    setLastError(null);
  }, [clearPollingAndCountdown]);

  // Auto-register push notifications on mount
  useEffect(() => {
    if (autoRegisterPush && !pushSubscription && pushPermissionStatus !== 'denied') {
      registerPushSubscription();
    }
  }, [autoRegisterPush, pushSubscription, pushPermissionStatus, registerPushSubscription]);

  // Cleanup effect
  useEffect(() => {
    return () => {
      clearPollingAndCountdown();
    };
  }, [clearPollingAndCountdown]);

  // Helper functions
  function urlBase64ToUint8Array(base64String: string): Uint8Array {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
  }

  function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary);
  }

  const formatTime = (ms: number): string => {
    const seconds = Math.ceil(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-blue-600" />
          Multi-Factor Authentication
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Push Registration Status */}
        {!pushSubscription && !isRegistering && (
          <Alert>
            <Bell className="h-4 w-4" />
            <AlertDescription>
              Push notifications not registered. 
              <Button
                variant="link"
                className="p-0 h-auto font-normal"
                onClick={registerPushSubscription}
                disabled={pushPermissionStatus === 'denied'}
              >
                Register now
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {/* Registration Progress */}
        {isRegistering && (
          <div className="flex items-center gap-2">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
            <span className="text-sm">Registering for push notifications...</span>
          </div>
        )}

        {/* Error Display */}
        {lastError && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{lastError}</AlertDescription>
          </Alert>
        )}

        {/* Challenge Timer */}
        {currentChallenge && timeRemaining > 0 && (
          <div className="text-center">
            <div className="text-2xl font-mono">{formatTime(timeRemaining)}</div>
            <div className="text-sm text-gray-500">Time remaining</div>
            <Progress 
              value={(timeRemaining / MFA_CONFIG.CHALLENGE_VALIDITY) * 100} 
              className="mt-2" 
            />
          </div>
        )}

        {/* Active Challenge - Push */}
        {currentChallenge && verificationMethod === 'push' && (
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <div className="p-4 bg-blue-100 rounded-full">
                <Bell className="h-8 w-8 text-blue-600 animate-pulse" />
              </div>
            </div>
            <div>
              <h3 className="font-medium">Push Notification Sent</h3>
              <p className="text-sm text-gray-600">
                Check your device and approve the authentication request
              </p>
            </div>
            
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => initiateMFAChallenge('push')}
              >
                <RefreshCw className="h-4 w-4" />
                Resend
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={cancelVerification}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}

        {/* Active Challenge - TOTP */}
        {currentChallenge && verificationMethod === 'totp' && (
          <div className="space-y-3">
            <div className="text-center">
              <div className="p-4 bg-green-100 rounded-full w-fit mx-auto">
                <Key className="h-8 w-8 text-green-600" />
              </div>
              <h3 className="font-medium mt-2">Enter TOTP Code</h3>
              <p className="text-sm text-gray-600">
                Enter the 6-digit code from your authenticator app
              </p>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="totp">TOTP Code</Label>
              <Input
                id="totp"
                type="text"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                className="text-center text-lg tracking-wider font-mono"
              />
            </div>

            <div className="flex gap-2">
              <Button
                onClick={verifyTOTPCode}
                disabled={totpCode.length !== 6}
                className="flex-1"
              >
                <Check className="h-4 w-4 mr-2" />
                Verify
              </Button>
              <Button
                variant="outline"
                onClick={cancelVerification}
              >
                <X className="h-4 w-4" />
                Cancel
              </Button>
            </div>
          </div>
        )}

        {/* Active Challenge - Backup Code */}
        {currentChallenge && verificationMethod === 'backup' && (
          <div className="space-y-3">
            <div className="text-center">
              <div className="p-4 bg-orange-100 rounded-full w-fit mx-auto">
                <QrCode className="h-8 w-8 text-orange-600" />
              </div>
              <h3 className="font-medium mt-2">Enter Backup Code</h3>
              <p className="text-sm text-gray-600">
                Enter one of your backup codes
              </p>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="backup">Backup Code</Label>
              <Input
                id="backup"
                type="text"
                maxLength={MFA_CONFIG.BACKUP_CODE_LENGTH}
                value={backupCode}
                onChange={(e) => setBackupCode(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, ''))}
                placeholder="ABC123XY"
                className="text-center text-lg tracking-wider font-mono"
              />
            </div>

            <div className="flex gap-2">
              <Button
                onClick={verifyBackupCode}
                disabled={backupCode.length !== MFA_CONFIG.BACKUP_CODE_LENGTH}
                className="flex-1"
              >
                <Check className="h-4 w-4 mr-2" />
                Verify
              </Button>
              <Button
                variant="outline"
                onClick={cancelVerification}
              >
                <X className="h-4 w-4" />
                Cancel
              </Button>
            </div>
          </div>
        )}

        {/* Method Selection */}
        {!currentChallenge && !isVerifying && pushSubscription && (
          <div className="space-y-3">
            <div className="text-sm font-medium">Choose authentication method:</div>
            
            <Button
              onClick={() => initiateMFAChallenge('push')}
              className="w-full justify-start"
              variant="outline"
            >
              <Bell className="h-4 w-4 mr-2" />
              Push Notification
              <Badge className="ml-auto">Recommended</Badge>
            </Button>

            {enableTOTP && (
              <Button
                onClick={() => initiateMFAChallenge('totp')}
                className="w-full justify-start"
                variant="outline"
              >
                <Key className="h-4 w-4 mr-2" />
                Authenticator App (TOTP)
              </Button>
            )}

            {enableBackupCodes && (
              <Button
                onClick={() => initiateMFAChallenge('backup')}
                className="w-full justify-start"
                variant="outline"
              >
                <QrCode className="h-4 w-4 mr-2" />
                Backup Code
              </Button>
            )}
          </div>
        )}

        {/* Attempt Counter */}
        {attemptCount > 0 && (
          <div className="text-sm text-gray-600 text-center">
            Attempts: {attemptCount} / {MFA_CONFIG.MAX_ATTEMPTS}
          </div>
        )}

        {/* Security Information */}
        <div className="text-xs text-gray-500 space-y-1">
          <p>• Push notifications are sent to registered devices only</p>
          <p>• TOTP codes are time-based and expire every 30 seconds</p>
          <p>• Backup codes can only be used once</p>
          <p>• All verification attempts are logged for security</p>
        </div>
      </CardContent>
    </Card>
  );
}

export default MFAPushNotifications;