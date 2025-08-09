/**
 * Mobile Authentication Components Export Index
 * Production-grade security components for mobile PWA authentication
 */

// Biometric Authentication
export { BiometricAuth } from './biometric-auth';
export type { 
  BiometricCapabilities, 
  BiometricAuthResult 
} from './biometric-auth';

// OAuth 2.0/OIDC Mobile Authentication
export { OAuthMobileAuth } from './oauth-mobile-auth';
export type { 
  OAuthConfig, 
  TokenSet, 
  UserInfo, 
  OAuthAuthResult 
} from './oauth-mobile-auth';

// Device Trust Verification
export { DeviceTrustVerification } from './device-trust-verification';
export type { 
  DeviceFingerprint, 
  GeolocationData, 
  NetworkInfo, 
  DeviceTrustScore, 
  DeviceTrustResult 
} from './device-trust-verification';

// Multi-Factor Authentication with Push Notifications
export { MFAPushNotifications } from './mfa-push-notifications';
export type { 
  MFAConfig, 
  PushSubscription, 
  MFAChallenge, 
  MFAVerificationResult 
} from './mfa-push-notifications';

// Secure Token Storage
export { SecureTokenStorage } from './secure-token-storage';
export type { 
  SecureToken, 
  StorageConfig, 
  StorageStats, 
  TokenOperationResult 
} from './secure-token-storage';

// Session Management
export { SessionManagement, useSession } from './session-management';
export type { 
  SessionConfig, 
  SessionState, 
  ActivityEvent, 
  SessionEvent 
} from './session-management';