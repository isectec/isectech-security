'use client';

import { useState, useEffect, useCallback } from 'react';
import { Shield, Fingerprint, Eye, AlertTriangle, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';

/**
 * Biometric Authentication Component
 * Production-grade implementation with WebAuthn API support
 * Implements FIDO2/WebAuthn standards for secure biometric authentication
 */

export interface BiometricCapabilities {
  fingerprint: boolean;
  faceId: boolean;
  voiceRecognition: boolean;
  platformAuthenticator: boolean;
}

export interface BiometricAuthResult {
  success: boolean;
  credentialId?: string;
  authenticatorData?: ArrayBuffer;
  signature?: ArrayBuffer;
  userHandle?: ArrayBuffer;
  errorCode?: string;
  errorMessage?: string;
}

interface BiometricAuthProps {
  onAuthSuccess: (result: BiometricAuthResult) => void;
  onAuthFailure: (error: BiometricAuthResult) => void;
  userId: string;
  challengeToken: string;
  allowedAuthenticators?: AuthenticatorSelectionCriteria;
  timeout?: number;
  maxAttempts?: number;
  onCapabilitiesDetected?: (capabilities: BiometricCapabilities) => void;
}

// Security constants for biometric authentication
const BIOMETRIC_CONFIG = {
  TIMEOUT_MS: 60000,
  MAX_ATTEMPTS: 3,
  CHALLENGE_LENGTH: 32,
  CREDENTIAL_ID_LENGTH: 64,
  RATE_LIMIT_WINDOW: 900000, // 15 minutes
} as const;

export function BiometricAuth({
  onAuthSuccess,
  onAuthFailure,
  userId,
  challengeToken,
  allowedAuthenticators = {
    authenticatorAttachment: 'platform',
    requireResidentKey: true,
    residentKey: 'required',
    userVerification: 'required'
  },
  timeout = BIOMETRIC_CONFIG.TIMEOUT_MS,
  maxAttempts = BIOMETRIC_CONFIG.MAX_ATTEMPTS,
  onCapabilitiesDetected
}: BiometricAuthProps) {
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [capabilities, setCapabilities] = useState<BiometricCapabilities>({
    fingerprint: false,
    faceId: false,
    voiceRecognition: false,
    platformAuthenticator: false
  });
  const [attemptCount, setAttemptCount] = useState(0);
  const [lastError, setLastError] = useState<string | null>(null);
  const [isSupported, setIsSupported] = useState(false);

  /**
   * Detect biometric capabilities on component mount
   * Uses WebAuthn API to detect available authenticators
   */
  useEffect(() => {
    const detectCapabilities = async () => {
      try {
        // Check for WebAuthn API support
        if (!window.PublicKeyCredential) {
          setLastError('Biometric authentication not supported on this device');
          return;
        }

        const isAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        const conditionalMediationSupported = await PublicKeyCredential.isConditionalMediationAvailable?.();

        const detectedCapabilities: BiometricCapabilities = {
          platformAuthenticator: isAvailable,
          fingerprint: isAvailable && 'ontouchstart' in window,
          faceId: isAvailable && navigator.mediaDevices?.getUserMedia !== undefined,
          voiceRecognition: 'webkitSpeechRecognition' in window || 'SpeechRecognition' in window
        };

        setCapabilities(detectedCapabilities);
        setIsSupported(isAvailable);
        onCapabilitiesDetected?.(detectedCapabilities);
      } catch (error) {
        console.error('Failed to detect biometric capabilities:', error);
        setLastError('Failed to detect biometric capabilities');
      }
    };

    detectCapabilities();
  }, [onCapabilitiesDetected]);

  /**
   * Generate secure challenge for authentication
   */
  const generateChallenge = useCallback((): Uint8Array => {
    const challenge = new Uint8Array(BIOMETRIC_CONFIG.CHALLENGE_LENGTH);
    crypto.getRandomValues(challenge);
    return challenge;
  }, []);

  /**
   * Convert string to ArrayBuffer for WebAuthn API
   */
  const stringToArrayBuffer = useCallback((str: string): ArrayBuffer => {
    return new TextEncoder().encode(str);
  }, []);

  /**
   * Convert ArrayBuffer to base64url for transmission
   */
  const arrayBufferToBase64Url = useCallback((buffer: ArrayBuffer): string => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }, []);

  /**
   * Perform biometric authentication using WebAuthn
   */
  const performBiometricAuth = useCallback(async (): Promise<BiometricAuthResult> => {
    if (!isSupported) {
      throw new Error('Biometric authentication not supported');
    }

    if (attemptCount >= maxAttempts) {
      throw new Error('Maximum authentication attempts exceeded');
    }

    setAttemptCount(prev => prev + 1);
    setIsAuthenticating(true);
    setLastError(null);

    try {
      const challenge = generateChallenge();
      
      // Create authentication options
      const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge,
        timeout,
        rpId: window.location.hostname,
        userVerification: 'required',
        allowCredentials: [{
          type: 'public-key',
          id: stringToArrayBuffer(userId),
          transports: ['internal']
        }]
      };

      // Request authentication
      const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
        mediation: 'required'
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Authentication cancelled or failed');
      }

      const response = credential.response as AuthenticatorAssertionResponse;
      
      // Prepare authentication result
      const authResult: BiometricAuthResult = {
        success: true,
        credentialId: arrayBufferToBase64Url(credential.rawId),
        authenticatorData: response.authenticatorData,
        signature: response.signature,
        userHandle: response.userHandle || undefined
      };

      return authResult;

    } catch (error: any) {
      const errorResult: BiometricAuthResult = {
        success: false,
        errorCode: error.name || 'UNKNOWN_ERROR',
        errorMessage: error.message || 'Biometric authentication failed'
      };

      throw errorResult;
    } finally {
      setIsAuthenticating(false);
    }
  }, [
    isSupported,
    attemptCount,
    maxAttempts,
    timeout,
    userId,
    generateChallenge,
    stringToArrayBuffer,
    arrayBufferToBase64Url
  ]);

  /**
   * Handle authentication button click
   */
  const handleAuthenticate = useCallback(async () => {
    try {
      const result = await performBiometricAuth();
      setAttemptCount(0);
      onAuthSuccess(result);
    } catch (error) {
      setLastError(error.errorMessage || 'Authentication failed');
      onAuthFailure(error as BiometricAuthResult);
    }
  }, [performBiometricAuth, onAuthSuccess, onAuthFailure]);

  /**
   * Reset authentication state
   */
  const resetAuthentication = useCallback(() => {
    setAttemptCount(0);
    setLastError(null);
  }, []);

  if (!isSupported) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            Biometric Authentication Unavailable
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              Biometric authentication is not supported on this device. Please use alternative authentication methods.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-blue-600" />
          Biometric Authentication
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Biometric Capabilities Display */}
        <div className="space-y-2">
          <p className="text-sm text-gray-600">Available authentication methods:</p>
          <div className="flex flex-wrap gap-2">
            {capabilities.fingerprint && (
              <Badge variant="secondary" className="flex items-center gap-1">
                <Fingerprint className="h-3 w-3" />
                Fingerprint
              </Badge>
            )}
            {capabilities.faceId && (
              <Badge variant="secondary" className="flex items-center gap-1">
                <Eye className="h-3 w-3" />
                Face ID
              </Badge>
            )}
            {capabilities.platformAuthenticator && (
              <Badge variant="secondary" className="flex items-center gap-1">
                <Check className="h-3 w-3" />
                Platform Auth
              </Badge>
            )}
          </div>
        </div>

        {/* Error Display */}
        {lastError && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{lastError}</AlertDescription>
          </Alert>
        )}

        {/* Attempt Counter */}
        {attemptCount > 0 && (
          <div className="text-sm text-gray-600">
            Attempts: {attemptCount} / {maxAttempts}
          </div>
        )}

        {/* Authentication Button */}
        <div className="space-y-2">
          <Button
            onClick={handleAuthenticate}
            disabled={isAuthenticating || attemptCount >= maxAttempts}
            className="w-full"
          >
            {isAuthenticating ? (
              <div className="flex items-center gap-2">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Authenticating...
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Fingerprint className="h-4 w-4" />
                Authenticate with Biometrics
              </div>
            )}
          </Button>
          
          {attemptCount > 0 && (
            <Button
              variant="outline"
              onClick={resetAuthentication}
              className="w-full"
              size="sm"
            >
              Reset Authentication
            </Button>
          )}
        </div>

        {/* Security Notice */}
        <div className="text-xs text-gray-500 space-y-1">
          <p>• Your biometric data is processed locally on your device</p>
          <p>• Authentication uses FIDO2/WebAuthn security standards</p>
          <p>• No biometric data is transmitted to our servers</p>
        </div>
      </CardContent>
    </Card>
  );
}

export default BiometricAuth;