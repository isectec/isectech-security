/**
 * Developer Authentication and Authorization System
 * Production-grade authentication for iSECTECH Developer Portal
 */

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export interface DeveloperAccount {
  id: string;
  email: string;
  organizationName: string;
  organizationId: string;
  developerLevel: 'INDIVIDUAL' | 'ORGANIZATION' | 'ENTERPRISE';
  verificationStatus: 'PENDING' | 'VERIFIED' | 'SUSPENDED' | 'REVOKED';
  createdAt: Date;
  lastLoginAt?: Date;
  apiKeyCount: number;
  appCount: number;
  totalDownloads: number;
  rating: number;
  isActive: boolean;
  subscriptionTier: 'FREE' | 'PROFESSIONAL' | 'ENTERPRISE';
  complianceCertifications: string[];
  securityClearanceLevel: 'PUBLIC' | 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET';
}

export interface DeveloperApiKey {
  id: string;
  developerId: string;
  name: string;
  keyHash: string;
  permissions: DeveloperPermission[];
  rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
    requestsPerDay: number;
  };
  ipWhitelist: string[];
  expiresAt?: Date;
  lastUsedAt?: Date;
  isActive: boolean;
  createdAt: Date;
  environment: 'SANDBOX' | 'PRODUCTION';
}

export interface DeveloperPermission {
  scope: string;
  actions: ('read' | 'write' | 'delete' | 'admin')[];
  resources: string[];
  conditions?: {
    timeWindow?: string;
    ipRestrictions?: string[];
    dataClassification?: string[];
  };
}

export interface DeveloperSession {
  sessionId: string;
  developerId: string;
  deviceFingerprint: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  expiresAt: Date;
  isActive: boolean;
  permissions: DeveloperPermission[];
}

export class DeveloperAuthService {
  private static instance: DeveloperAuthService;
  private jwtSecret: string;
  private sessions = new Map<string, DeveloperSession>();
  private failedAttempts = new Map<string, { count: number; lastAttempt: Date }>();
  private readonly SALT_ROUNDS = 12;
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes

  private constructor() {
    this.jwtSecret = process.env.DEVELOPER_JWT_SECRET || crypto.randomBytes(64).toString('hex');
  }

  public static getInstance(): DeveloperAuthService {
    if (!DeveloperAuthService.instance) {
      DeveloperAuthService.instance = new DeveloperAuthService();
    }
    return DeveloperAuthService.instance;
  }

  /**
   * Register new developer account with security verification
   */
  public async registerDeveloper(
    email: string,
    password: string,
    organizationName: string,
    developerLevel: DeveloperAccount['developerLevel'],
    securityClearanceLevel: DeveloperAccount['securityClearanceLevel']
  ): Promise<{ account: DeveloperAccount; verificationToken: string }> {
    // Validate email format and domain security
    if (!this.isValidSecureEmail(email)) {
      throw new Error('Invalid email or unsecured email domain');
    }

    // Validate password strength for security platform access
    if (!this.isStrongPassword(password)) {
      throw new Error('Password must meet security requirements: 12+ chars, uppercase, lowercase, numbers, special chars');
    }

    // Check for existing account
    const existingAccount = await this.getDeveloperByEmail(email);
    if (existingAccount) {
      throw new Error('Developer account already exists');
    }

    const hashedPassword = await bcrypt.hash(password, this.SALT_ROUNDS);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    const account: DeveloperAccount = {
      id: `dev_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`,
      email,
      organizationName,
      organizationId: `org_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`,
      developerLevel,
      verificationStatus: 'PENDING',
      createdAt: new Date(),
      apiKeyCount: 0,
      appCount: 0,
      totalDownloads: 0,
      rating: 0,
      isActive: true,
      subscriptionTier: 'FREE',
      complianceCertifications: [],
      securityClearanceLevel,
    };

    // Store account (mock - would be database in production)
    await this.storeDeveloperAccount(account, hashedPassword, verificationToken);

    // Send security verification email
    await this.sendSecurityVerificationEmail(email, verificationToken);

    // Log registration for security audit
    await this.auditLog('DEVELOPER_REGISTRATION', {
      developerId: account.id,
      email,
      organizationName,
      developerLevel,
      securityClearanceLevel,
    });

    return { account, verificationToken };
  }

  /**
   * Authenticate developer with enhanced security checks
   */
  public async authenticateDeveloper(
    email: string,
    password: string,
    deviceFingerprint: string,
    ipAddress: string,
    userAgent: string
  ): Promise<{ token: string; session: DeveloperSession; account: DeveloperAccount }> {
    // Check for brute force attempts
    if (this.isAccountLocked(email)) {
      throw new Error('Account temporarily locked due to failed login attempts');
    }

    const account = await this.getDeveloperByEmail(email);
    if (!account || !account.isActive) {
      this.recordFailedAttempt(email);
      throw new Error('Invalid credentials');
    }

    if (account.verificationStatus !== 'VERIFIED') {
      throw new Error('Account not verified. Please complete email verification.');
    }

    const storedPassword = await this.getStoredPassword(account.id);
    const isValidPassword = await bcrypt.compare(password, storedPassword);

    if (!isValidPassword) {
      this.recordFailedAttempt(email);
      await this.auditLog('FAILED_LOGIN', {
        developerId: account.id,
        email,
        ipAddress,
        userAgent,
      });
      throw new Error('Invalid credentials');
    }

    // Reset failed attempts on successful login
    this.failedAttempts.delete(email);

    // Perform security risk assessment
    const riskScore = await this.assessLoginRisk(account, ipAddress, userAgent, deviceFingerprint);
    if (riskScore > 7) {
      await this.triggerAdditionalVerification(account, riskScore);
      throw new Error('Additional verification required for security');
    }

    // Create session
    const session = await this.createDeveloperSession(account, deviceFingerprint, ipAddress, userAgent);

    // Generate JWT token
    const token = this.generateJWT(account, session);

    // Update last login
    account.lastLoginAt = new Date();
    await this.updateDeveloperAccount(account);

    // Log successful login
    await this.auditLog('SUCCESSFUL_LOGIN', {
      developerId: account.id,
      sessionId: session.sessionId,
      ipAddress,
      riskScore,
    });

    return { token, session, account };
  }

  /**
   * Generate API key for developer with security controls
   */
  public async generateApiKey(
    developerId: string,
    keyName: string,
    permissions: DeveloperPermission[],
    environment: 'SANDBOX' | 'PRODUCTION',
    rateLimit?: DeveloperApiKey['rateLimit'],
    expirationDays?: number
  ): Promise<{ apiKey: DeveloperApiKey; plainKey: string }> {
    const account = await this.getDeveloperById(developerId);
    if (!account || account.verificationStatus !== 'VERIFIED') {
      throw new Error('Developer account not found or not verified');
    }

    // Validate permissions against account level
    if (!this.validatePermissions(account, permissions)) {
      throw new Error('Requested permissions exceed account authorization level');
    }

    // Generate secure API key
    const plainKey = `isec_${environment.toLowerCase()}_${crypto.randomBytes(32).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(plainKey).digest('hex');

    const defaultRateLimit = this.getDefaultRateLimit(account.subscriptionTier, environment);

    const apiKey: DeveloperApiKey = {
      id: `key_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`,
      developerId,
      name: keyName,
      keyHash,
      permissions,
      rateLimit: rateLimit || defaultRateLimit,
      ipWhitelist: [],
      expiresAt: expirationDays ? new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000) : undefined,
      isActive: true,
      createdAt: new Date(),
      environment,
    };

    await this.storeApiKey(apiKey);

    // Update account API key count
    account.apiKeyCount++;
    await this.updateDeveloperAccount(account);

    // Log API key generation
    await this.auditLog('API_KEY_GENERATED', {
      developerId,
      keyId: apiKey.id,
      keyName,
      environment,
      permissions: permissions.map(p => p.scope),
    });

    return { apiKey, plainKey };
  }

  /**
   * Validate API key and return associated permissions
   */
  public async validateApiKey(
    apiKeyPlain: string,
    ipAddress: string,
    requestedPermission: { scope: string; action: string; resource: string }
  ): Promise<{ valid: boolean; developerId?: string; permissions?: DeveloperPermission[] }> {
    const keyHash = crypto.createHash('sha256').update(apiKeyPlain).digest('hex');
    const apiKey = await this.getApiKeyByHash(keyHash);

    if (!apiKey || !apiKey.isActive) {
      await this.auditLog('INVALID_API_KEY_ATTEMPT', { keyHash, ipAddress });
      return { valid: false };
    }

    if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
      await this.auditLog('EXPIRED_API_KEY_ATTEMPT', { keyId: apiKey.id, ipAddress });
      return { valid: false };
    }

    // Check IP whitelist
    if (apiKey.ipWhitelist.length > 0 && !apiKey.ipWhitelist.includes(ipAddress)) {
      await this.auditLog('IP_NOT_WHITELISTED', { keyId: apiKey.id, ipAddress });
      return { valid: false };
    }

    // Check rate limits
    const rateLimitPassed = await this.checkRateLimit(apiKey, ipAddress);
    if (!rateLimitPassed) {
      await this.auditLog('RATE_LIMIT_EXCEEDED', { keyId: apiKey.id, ipAddress });
      return { valid: false };
    }

    // Validate specific permission
    const hasPermission = this.checkPermission(apiKey.permissions, requestedPermission);
    if (!hasPermission) {
      await this.auditLog('INSUFFICIENT_PERMISSIONS', {
        keyId: apiKey.id,
        requestedPermission,
        availablePermissions: apiKey.permissions,
      });
      return { valid: false };
    }

    // Update last used timestamp
    apiKey.lastUsedAt = new Date();
    await this.updateApiKey(apiKey);

    return {
      valid: true,
      developerId: apiKey.developerId,
      permissions: apiKey.permissions,
    };
  }

  // Private helper methods

  private isValidSecureEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return false;

    // Additional security checks for email domain
    const domain = email.split('@')[1].toLowerCase();
    const suspiciousDomains = ['tempmail.org', '10minutemail.com', 'guerrillamail.com'];
    return !suspiciousDomains.includes(domain);
  }

  private isStrongPassword(password: string): boolean {
    return (
      password.length >= 12 &&
      /[a-z]/.test(password) &&
      /[A-Z]/.test(password) &&
      /[0-9]/.test(password) &&
      /[^a-zA-Z0-9]/.test(password)
    );
  }

  private isAccountLocked(email: string): boolean {
    const attempts = this.failedAttempts.get(email);
    if (!attempts) return false;

    return (
      attempts.count >= this.MAX_LOGIN_ATTEMPTS &&
      Date.now() - attempts.lastAttempt.getTime() < this.LOCKOUT_DURATION
    );
  }

  private recordFailedAttempt(email: string): void {
    const current = this.failedAttempts.get(email) || { count: 0, lastAttempt: new Date() };
    current.count++;
    current.lastAttempt = new Date();
    this.failedAttempts.set(email, current);
  }

  private async assessLoginRisk(
    account: DeveloperAccount,
    ipAddress: string,
    userAgent: string,
    deviceFingerprint: string
  ): Promise<number> {
    let riskScore = 0;

    // Check for unusual location
    const previousLocations = await this.getPreviousLoginLocations(account.id);
    const currentLocation = await this.getLocationFromIP(ipAddress);
    if (!previousLocations.includes(currentLocation.country)) {
      riskScore += 3;
    }

    // Check for new device
    const knownDevices = await this.getKnownDevices(account.id);
    if (!knownDevices.includes(deviceFingerprint)) {
      riskScore += 2;
    }

    // Check login time patterns
    const hour = new Date().getHours();
    const usualHours = await this.getUsualLoginHours(account.id);
    if (hour < usualHours.min || hour > usualHours.max) {
      riskScore += 1;
    }

    return riskScore;
  }

  private generateJWT(account: DeveloperAccount, session: DeveloperSession): string {
    const payload = {
      sub: account.id,
      email: account.email,
      org: account.organizationId,
      level: account.developerLevel,
      clearance: account.securityClearanceLevel,
      session: session.sessionId,
      permissions: session.permissions,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(session.expiresAt.getTime() / 1000),
    };

    return jwt.sign(payload, this.jwtSecret, { algorithm: 'HS256' });
  }

  private async createDeveloperSession(
    account: DeveloperAccount,
    deviceFingerprint: string,
    ipAddress: string,
    userAgent: string
  ): Promise<DeveloperSession> {
    const session: DeveloperSession = {
      sessionId: `sess_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`,
      developerId: account.id,
      deviceFingerprint,
      ipAddress,
      userAgent,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours
      isActive: true,
      permissions: await this.getDeveloperPermissions(account),
    };

    this.sessions.set(session.sessionId, session);
    return session;
  }

  private getDefaultRateLimit(
    tier: DeveloperAccount['subscriptionTier'],
    environment: 'SANDBOX' | 'PRODUCTION'
  ): DeveloperApiKey['rateLimit'] {
    const limits = {
      FREE: { SANDBOX: { requestsPerMinute: 100, requestsPerHour: 1000, requestsPerDay: 10000 },
              PRODUCTION: { requestsPerMinute: 10, requestsPerHour: 100, requestsPerDay: 1000 } },
      PROFESSIONAL: { SANDBOX: { requestsPerMinute: 500, requestsPerHour: 10000, requestsPerDay: 100000 },
                     PRODUCTION: { requestsPerMinute: 100, requestsPerHour: 5000, requestsPerDay: 50000 } },
      ENTERPRISE: { SANDBOX: { requestsPerMinute: 2000, requestsPerHour: 50000, requestsPerDay: 1000000 },
                   PRODUCTION: { requestsPerMinute: 1000, requestsPerHour: 25000, requestsPerDay: 500000 } },
    };

    return limits[tier][environment];
  }

  // Mock database methods (would be replaced with actual database calls in production)
  private async getDeveloperByEmail(email: string): Promise<DeveloperAccount | null> {
    // Mock implementation
    return null;
  }

  private async getDeveloperById(id: string): Promise<DeveloperAccount | null> {
    // Mock implementation
    return null;
  }

  private async storeDeveloperAccount(
    account: DeveloperAccount,
    hashedPassword: string,
    verificationToken: string
  ): Promise<void> {
    console.log('Storing developer account:', account.id);
  }

  private async getStoredPassword(developerId: string): Promise<string> {
    // Mock implementation
    return '';
  }

  private async storeApiKey(apiKey: DeveloperApiKey): Promise<void> {
    console.log('Storing API key:', apiKey.id);
  }

  private async auditLog(action: string, details: any): Promise<void> {
    console.log(`Audit: ${action}`, details);
  }

  private async sendSecurityVerificationEmail(email: string, token: string): Promise<void> {
    console.log(`Sending verification email to ${email} with token ${token}`);
  }

  private async updateDeveloperAccount(account: DeveloperAccount): Promise<void> {
    console.log('Updating developer account:', account.id);
  }

  private async getApiKeyByHash(keyHash: string): Promise<DeveloperApiKey | null> {
    return null;
  }

  private async checkRateLimit(apiKey: DeveloperApiKey, ipAddress: string): Promise<boolean> {
    return true;
  }

  private checkPermission(
    permissions: DeveloperPermission[],
    requested: { scope: string; action: string; resource: string }
  ): boolean {
    return permissions.some(
      p =>
        p.scope === requested.scope &&
        p.actions.includes(requested.action as any) &&
        p.resources.includes(requested.resource)
    );
  }

  private async updateApiKey(apiKey: DeveloperApiKey): Promise<void> {
    console.log('Updating API key:', apiKey.id);
  }

  // Additional mock methods for risk assessment
  private async getPreviousLoginLocations(developerId: string): Promise<string[]> {
    return ['US', 'CA'];
  }

  private async getLocationFromIP(ipAddress: string): Promise<{ country: string; city: string }> {
    return { country: 'US', city: 'San Francisco' };
  }

  private async getKnownDevices(developerId: string): Promise<string[]> {
    return [];
  }

  private async getUsualLoginHours(developerId: string): Promise<{ min: number; max: number }> {
    return { min: 8, max: 18 };
  }

  private async getDeveloperPermissions(account: DeveloperAccount): Promise<DeveloperPermission[]> {
    // Return permissions based on account level and clearance
    const basePermissions: DeveloperPermission[] = [
      {
        scope: 'marketplace',
        actions: ['read'],
        resources: ['apps', 'documentation'],
      },
    ];

    if (account.securityClearanceLevel !== 'PUBLIC') {
      basePermissions.push({
        scope: 'security-apis',
        actions: ['read'],
        resources: ['threat-intel', 'vulnerability-data'],
        conditions: {
          dataClassification: [account.securityClearanceLevel],
        },
      });
    }

    return basePermissions;
  }

  private validatePermissions(account: DeveloperAccount, permissions: DeveloperPermission[]): boolean {
    // Validate that requested permissions don't exceed account capabilities
    return permissions.every(perm => {
      if (perm.conditions?.dataClassification) {
        return perm.conditions.dataClassification.every(
          classification => this.hasAccessToClassification(account, classification)
        );
      }
      return true;
    });
  }

  private hasAccessToClassification(account: DeveloperAccount, classification: string): boolean {
    const clearanceLevels = ['PUBLIC', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET'];
    const accountLevel = clearanceLevels.indexOf(account.securityClearanceLevel);
    const requiredLevel = clearanceLevels.indexOf(classification);
    return accountLevel >= requiredLevel;
  }

  private async triggerAdditionalVerification(account: DeveloperAccount, riskScore: number): Promise<void> {
    // Trigger additional security verification (2FA, email verification, etc.)
    console.log(`Additional verification required for ${account.id}, risk score: ${riskScore}`);
  }
}

// Export singleton instance
export const developerAuthService = DeveloperAuthService.getInstance();