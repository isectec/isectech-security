/**
 * Authentication & Authorization Types for iSECTECH Protect
 * Production-grade security authentication definitions
 */

import type { SecurityClearance, Tenant, User, UserRole } from './security';

// JWT Token Structure
export interface JWTPayload {
  sub: string; // User ID
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  tenantId: string;
  role: UserRole;
  securityClearance: SecurityClearance;
  permissions: string[];
  sessionId: string;
  mfaVerified: boolean;
  ipAddress?: string;
  userAgent?: string;
}

// Authentication State
export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  tenant: Tenant | null;
  tokens: TokenPair | null;
  session: SessionInfo | null;
  permissions: string[];
  securityClearance: SecurityClearance;
  lastActivity: Date | null;
  error: string | null;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  tokenType: 'Bearer';
}

export interface SessionInfo {
  id: string;
  userId: string;
  tenantId: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActivity: Date;
  expiresAt: Date;
  mfaVerified: boolean;
  deviceFingerprint?: string;
  location?: {
    country: string;
    region: string;
    city: string;
    coordinates?: {
      latitude: number;
      longitude: number;
    };
  };
}

// Login & Authentication
export interface LoginCredentials {
  email: string;
  password: string;
  tenantId?: string;
  rememberMe?: boolean;
  deviceFingerprint?: string;
}

export interface MFACredentials {
  sessionToken: string;
  code: string;
  type: 'TOTP' | 'SMS' | 'EMAIL' | 'BACKUP_CODE';
}

export interface LoginResponse {
  success: boolean;
  requiresMFA: boolean;
  sessionToken?: string; // For MFA flow
  tokens?: TokenPair;
  user?: User;
  tenant?: Tenant;
  permissions?: string[];
  message?: string;
  nextStep?: 'MFA_REQUIRED' | 'PASSWORD_CHANGE_REQUIRED' | 'TERMS_ACCEPTANCE_REQUIRED';
}

export interface MFASetup {
  secret: string;
  qrCode: string;
  backupCodes: string[];
  type: 'TOTP' | 'SMS' | 'EMAIL';
}

// Password Management
export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  maxConsecutiveChars: number;
  historyCount: number; // Number of previous passwords to check
  maxAge: number; // Days before password expires
  lockoutAttempts: number;
  lockoutDuration: number; // Minutes
}

export interface PasswordValidation {
  isValid: boolean;
  errors: string[];
  strength: 'WEAK' | 'FAIR' | 'GOOD' | 'STRONG';
  score: number; // 0-100
}

export interface PasswordChangeRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface PasswordResetRequest {
  email: string;
  tenantId?: string;
}

export interface PasswordResetConfirm {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

// Permissions & Authorization
export interface Permission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: string;
  conditions?: PermissionCondition[];
  requiredClearance?: SecurityClearance;
  createdAt: Date;
  updatedAt: Date;
}

export interface PermissionCondition {
  field: string;
  operator: 'eq' | 'ne' | 'in' | 'nin' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'startsWith' | 'endsWith';
  value: unknown;
  type: 'string' | 'number' | 'boolean' | 'date' | 'array';
}

export interface Role {
  id: string;
  name: UserRole;
  displayName: string;
  description: string;
  permissions: string[];
  isSystemRole: boolean;
  isCustomRole: boolean;
  requiredClearance?: SecurityClearance;
  createdAt: Date;
  updatedAt: Date;
}

// Security Context
export interface SecurityContext {
  userId: string;
  tenantId: string;
  role: UserRole;
  securityClearance: SecurityClearance;
  permissions: string[];
  sessionId: string;
  ipAddress?: string;
  userAgent?: string;
  timestamp: Date;
}

// API Authentication
export interface ApiKeyCredentials {
  apiKey: string;
  apiSecret: string;
  tenantId?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  tenantId: string;
  userId: string;
  keyHash: string; // SHA-256 hash of the key
  permissions: string[];
  scopes: string[];
  ipWhitelist?: string[];
  rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
    requestsPerDay: number;
  };
  status: 'ACTIVE' | 'INACTIVE' | 'REVOKED';
  lastUsed?: Date;
  usageCount: number;
  expiresAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// SSO & Federation
export interface SSOConfig {
  tenantId: string;
  provider: 'SAML' | 'OIDC' | 'LDAP' | 'ACTIVE_DIRECTORY';
  enabled: boolean;
  configuration: Record<string, unknown>;
  attributeMapping: {
    email: string;
    firstName: string;
    lastName: string;
    role?: string;
    department?: string;
    securityClearance?: string;
  };
  autoProvisioning: boolean;
  defaultRole: UserRole;
  defaultClearance: SecurityClearance;
  createdAt: Date;
  updatedAt: Date;
}

export interface SSOLoginRequest {
  provider: string;
  tenantId: string;
  returnUrl?: string;
}

// Audit & Security Events
export interface AuthenticationEvent {
  id: string;
  type:
    | 'LOGIN'
    | 'LOGOUT'
    | 'LOGIN_FAILED'
    | 'MFA_VERIFY'
    | 'MFA_FAILED'
    | 'PASSWORD_CHANGE'
    | 'PASSWORD_RESET'
    | 'ACCOUNT_LOCKED'
    | 'ACCOUNT_UNLOCKED';
  userId?: string;
  email?: string;
  tenantId?: string;
  ipAddress: string;
  userAgent: string;
  sessionId?: string;
  success: boolean;
  failureReason?: string;
  metadata: Record<string, unknown>;
  timestamp: Date;
  location?: {
    country: string;
    region: string;
    city: string;
    coordinates?: {
      latitude: number;
      longitude: number;
    };
  };
  riskScore: number; // 0-100
  riskFactors: string[];
}

// Device Management
export interface DeviceInfo {
  fingerprint: string;
  type: 'DESKTOP' | 'MOBILE' | 'TABLET' | 'UNKNOWN';
  os: string;
  browser: string;
  version: string;
  isTrusted: boolean;
  lastSeen: Date;
  ipAddresses: string[];
  locations: Array<{
    country: string;
    region: string;
    city: string;
    timestamp: Date;
  }>;
}

export interface TrustedDevice {
  id: string;
  userId: string;
  deviceFingerprint: string;
  name: string;
  deviceInfo: DeviceInfo;
  status: 'ACTIVE' | 'REVOKED';
  trustedAt: Date;
  trustedBy: string;
  lastUsed: Date;
  expiresAt?: Date;
}

// Risk Assessment
export interface AuthenticationRisk {
  score: number; // 0-100
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: RiskFactor[];
  recommendations: string[];
  requiresAdditionalVerification: boolean;
  blockedReason?: string;
}

export interface RiskFactor {
  type: 'LOCATION' | 'DEVICE' | 'TIME' | 'BEHAVIOR' | 'IP_REPUTATION' | 'VELOCITY';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  weight: number;
  value: unknown;
}

// Security Policies
export interface SecurityPolicy {
  id: string;
  tenantId: string;
  type: 'PASSWORD' | 'MFA' | 'SESSION' | 'IP_WHITELIST' | 'DEVICE_TRUST' | 'RISK_BASED_AUTH';
  name: string;
  description: string;
  configuration: Record<string, unknown>;
  enabled: boolean;
  enforced: boolean;
  exceptions: string[]; // User IDs or roles
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  updatedBy: string;
}

// Session Management
export interface SessionPolicy {
  maxConcurrentSessions: number;
  sessionTimeout: number; // Minutes
  idleTimeout: number; // Minutes
  requireMFAForSensitive: boolean;
  requireReAuthForAdmin: boolean;
  allowedIpRanges?: string[];
  allowedCountries?: string[];
  deviceTrustRequired: boolean;
}

// Error Types
export interface AuthError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  retryable: boolean;
  nextAction?: 'RETRY' | 'MFA_REQUIRED' | 'CONTACT_ADMIN' | 'ACCOUNT_LOCKED';
}

// Hooks and Context Types
export interface AuthContextType {
  state: AuthState;
  login: (credentials: LoginCredentials) => Promise<LoginResponse>;
  loginWithMFA: (credentials: MFACredentials) => Promise<LoginResponse>;
  logout: () => Promise<void>;
  refreshTokens: () => Promise<boolean>;
  checkPermission: (permission: string, resource?: string) => boolean;
  checkClearance: (requiredClearance: SecurityClearance) => boolean;
  updateProfile: (updates: Partial<User>) => Promise<void>;
  changePassword: (request: PasswordChangeRequest) => Promise<void>;
  setupMFA: (type: 'TOTP' | 'SMS' | 'EMAIL') => Promise<MFASetup>;
  verifyMFA: (code: string, type: 'TOTP' | 'SMS' | 'EMAIL') => Promise<boolean>;
  disableMFA: () => Promise<void>;
  getTrustedDevices: () => Promise<TrustedDevice[]>;
  revokeTrustedDevice: (deviceId: string) => Promise<void>;
  getAuthenticationHistory: () => Promise<AuthenticationEvent[]>;
}
