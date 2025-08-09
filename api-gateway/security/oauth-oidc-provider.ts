/**
 * Production-grade OAuth 2.1 and OpenID Connect 1.0 Provider for iSECTECH
 * 
 * Provides comprehensive OAuth 2.1 and OIDC 1.0 authentication and authorization
 * services with PKCE, security best practices, and multi-tenant support.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { URL } from 'url';

// OAuth 2.1 and OIDC Configuration Schemas
export const OAuthClientSchema = z.object({
  clientId: z.string(),
  clientSecret: z.string().optional(), // Optional for public clients
  clientType: z.enum(['CONFIDENTIAL', 'PUBLIC']),
  clientName: z.string(),
  redirectUris: z.array(z.string().url()),
  allowedScopes: z.array(z.string()),
  allowedGrantTypes: z.array(z.enum([
    'authorization_code',
    'client_credentials',
    'refresh_token'
  ])),
  requirePkce: z.boolean().default(true),
  tokenEndpointAuthMethod: z.enum([
    'client_secret_basic',
    'client_secret_post',
    'client_secret_jwt',
    'private_key_jwt',
    'none'
  ]).default('client_secret_basic'),
  
  // OIDC specific
  responseTypes: z.array(z.enum(['code', 'id_token', 'token'])).default(['code']),
  subjectType: z.enum(['public', 'pairwise']).default('public'),
  idTokenSignedResponseAlg: z.string().default('RS256'),
  
  // iSECTECH specific
  tenantId: z.string(),
  securityClearance: z.enum(['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET']).default('CONFIDENTIAL'),
  allowedServices: z.array(z.string()),
  
  // Metadata
  createdAt: z.date(),
  updatedAt: z.date(),
  isActive: z.boolean().default(true),
  tags: z.array(z.string()).default(['isectech', 'oauth2', 'oidc'])
});

export const AuthorizationCodeSchema = z.object({
  code: z.string(),
  clientId: z.string(),
  userId: z.string(),
  tenantId: z.string(),
  redirectUri: z.string().url(),
  scopes: z.array(z.string()),
  codeChallenge: z.string().optional(),
  codeChallengeMethod: z.enum(['S256', 'plain']).optional(),
  nonce: z.string().optional(),
  state: z.string().optional(),
  expiresAt: z.date(),
  createdAt: z.date(),
  isUsed: z.boolean().default(false)
});

export const AccessTokenSchema = z.object({
  tokenId: z.string(),
  accessToken: z.string(),
  tokenType: z.string().default('Bearer'),
  clientId: z.string(),
  userId: z.string(),
  tenantId: z.string(),
  scopes: z.array(z.string()),
  expiresAt: z.date(),
  createdAt: z.date(),
  refreshToken: z.string().optional(),
  refreshTokenExpiresAt: z.date().optional(),
  isRevoked: z.boolean().default(false)
});

export const OIDCUserInfoSchema = z.object({
  sub: z.string(), // Subject identifier
  name: z.string().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  middle_name: z.string().optional(),
  nickname: z.string().optional(),
  preferred_username: z.string().optional(),
  profile: z.string().url().optional(),
  picture: z.string().url().optional(),
  website: z.string().url().optional(),
  email: z.string().email().optional(),
  email_verified: z.boolean().optional(),
  gender: z.string().optional(),
  birthdate: z.string().optional(),
  zoneinfo: z.string().optional(),
  locale: z.string().optional(),
  phone_number: z.string().optional(),
  phone_number_verified: z.boolean().optional(),
  address: z.object({
    formatted: z.string().optional(),
    street_address: z.string().optional(),
    locality: z.string().optional(),
    region: z.string().optional(),
    postal_code: z.string().optional(),
    country: z.string().optional()
  }).optional(),
  updated_at: z.number().optional(),
  
  // iSECTECH custom claims
  tenant_id: z.string(),
  security_clearance: z.string(),
  roles: z.array(z.string()),
  permissions: z.array(z.string()),
  services: z.array(z.string()),
  groups: z.array(z.string()).optional()
});

export type OAuthClient = z.infer<typeof OAuthClientSchema>;
export type AuthorizationCode = z.infer<typeof AuthorizationCodeSchema>;
export type AccessToken = z.infer<typeof AccessTokenSchema>;
export type OIDCUserInfo = z.infer<typeof OIDCUserInfoSchema>;

/**
 * OAuth 2.1 and OIDC 1.0 Provider for iSECTECH
 */
export class ISECTECHOAuthOIDCProvider {
  private clients: Map<string, OAuthClient> = new Map();
  private authorizationCodes: Map<string, AuthorizationCode> = new Map();
  private accessTokens: Map<string, AccessToken> = new Map();
  private refreshTokens: Map<string, AccessToken> = new Map();
  private userInfo: Map<string, OIDCUserInfo> = new Map();

  constructor(
    private config: {
      issuer: string;
      privateKey: string;
      publicKey: string;
      keyId: string;
      authorizationCodeTTL: number; // seconds
      accessTokenTTL: number; // seconds
      refreshTokenTTL: number; // seconds
      idTokenTTL: number; // seconds
      supportedScopes: string[];
      supportedClaims: string[];
    }
  ) {
    this.initializeISECTECHClients();
  }

  /**
   * Initialize OAuth clients for iSECTECH services
   */
  private initializeISECTECHClients(): void {
    // Threat Detection Service Client
    const threatDetectionClient: OAuthClient = {
      clientId: 'isectech-threat-detection-client',
      clientSecret: this.generateClientSecret(),
      clientType: 'CONFIDENTIAL',
      clientName: 'iSECTECH Threat Detection Service',
      redirectUris: [
        'https://threat-detection.isectech.com/oauth/callback',
        'https://threat-detection.isectech.com/auth/callback'
      ],
      allowedScopes: [
        'openid',
        'profile',
        'email',
        'threat-detection',
        'ai-analysis',
        'security-data',
        'tenant-data'
      ],
      allowedGrantTypes: ['authorization_code', 'client_credentials', 'refresh_token'],
      requirePkce: true,
      tokenEndpointAuthMethod: 'client_secret_basic',
      responseTypes: ['code'],
      subjectType: 'public',
      idTokenSignedResponseAlg: 'RS256',
      tenantId: 'system',
      securityClearance: 'SECRET',
      allowedServices: ['threat-detection', 'ai-ml-services', 'event-processing'],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      tags: ['isectech', 'threat-detection', 'confidential']
    };

    // Asset Discovery Service Client
    const assetDiscoveryClient: OAuthClient = {
      clientId: 'isectech-asset-discovery-client',
      clientSecret: this.generateClientSecret(),
      clientType: 'CONFIDENTIAL',
      clientName: 'iSECTECH Asset Discovery Service',
      redirectUris: [
        'https://assets.isectech.com/oauth/callback',
        'https://assets.isectech.com/auth/callback'
      ],
      allowedScopes: [
        'openid',
        'profile',
        'email',
        'asset-discovery',
        'asset-management',
        'network-scanning',
        'tenant-data'
      ],
      allowedGrantTypes: ['authorization_code', 'client_credentials', 'refresh_token'],
      requirePkce: true,
      tokenEndpointAuthMethod: 'client_secret_basic',
      responseTypes: ['code'],
      subjectType: 'public',
      idTokenSignedResponseAlg: 'RS256',
      tenantId: 'system',
      securityClearance: 'CONFIDENTIAL',
      allowedServices: ['asset-discovery', 'vulnerability-management'],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      tags: ['isectech', 'asset-discovery', 'confidential']
    };

    // Compliance Service Client
    const complianceClient: OAuthClient = {
      clientId: 'isectech-compliance-client',
      clientSecret: this.generateClientSecret(),
      clientType: 'CONFIDENTIAL',
      clientName: 'iSECTECH Compliance Automation Service',
      redirectUris: [
        'https://compliance.isectech.com/oauth/callback',
        'https://compliance.isectech.com/auth/callback'
      ],
      allowedScopes: [
        'openid',
        'profile',
        'email',
        'compliance-automation',
        'audit-data',
        'reporting',
        'tenant-data'
      ],
      allowedGrantTypes: ['authorization_code', 'client_credentials', 'refresh_token'],
      requirePkce: true,
      tokenEndpointAuthMethod: 'client_secret_basic',
      responseTypes: ['code'],
      subjectType: 'public',
      idTokenSignedResponseAlg: 'RS256',
      tenantId: 'system',
      securityClearance: 'CONFIDENTIAL',
      allowedServices: ['compliance-automation'],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      tags: ['isectech', 'compliance', 'confidential']
    };

    // Developer Portal Client (Public)
    const developerPortalClient: OAuthClient = {
      clientId: 'isectech-developer-portal-client',
      clientType: 'PUBLIC',
      clientName: 'iSECTECH Developer Portal',
      redirectUris: [
        'https://developer.isectech.com/oauth/callback',
        'https://developer.isectech.com/auth/callback',
        'http://localhost:3000/oauth/callback' // Development
      ],
      allowedScopes: [
        'openid',
        'profile',
        'email',
        'api-access',
        'documentation'
      ],
      allowedGrantTypes: ['authorization_code', 'refresh_token'],
      requirePkce: true,
      tokenEndpointAuthMethod: 'none',
      responseTypes: ['code'],
      subjectType: 'public',
      idTokenSignedResponseAlg: 'RS256',
      tenantId: 'public',
      securityClearance: 'UNCLASSIFIED',
      allowedServices: ['developer-portal', 'api-docs'],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      tags: ['isectech', 'developer-portal', 'public']
    };

    // Store all clients
    [
      threatDetectionClient,
      assetDiscoveryClient,
      complianceClient,
      developerPortalClient
    ].forEach(client => {
      const validatedClient = OAuthClientSchema.parse(client);
      this.clients.set(client.clientId, validatedClient);
    });
  }

  /**
   * Handle OAuth 2.1 Authorization Request
   */
  public handleAuthorizationRequest(params: {
    response_type: string;
    client_id: string;
    redirect_uri: string;
    scope?: string;
    state?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    nonce?: string;
  }): { success: boolean; authorizationUrl?: string; error?: string } {
    try {
      const client = this.clients.get(params.client_id);
      if (!client || !client.isActive) {
        return { success: false, error: 'invalid_client' };
      }

      // Validate response_type
      if (!client.responseTypes.includes(params.response_type as any)) {
        return { success: false, error: 'unsupported_response_type' };
      }

      // Validate redirect_uri
      if (!client.redirectUris.includes(params.redirect_uri)) {
        return { success: false, error: 'invalid_redirect_uri' };
      }

      // Validate PKCE for public clients
      if (client.clientType === 'PUBLIC' && client.requirePkce) {
        if (!params.code_challenge || !params.code_challenge_method) {
          return { success: false, error: 'invalid_request' };
        }
        if (params.code_challenge_method !== 'S256') {
          return { success: false, error: 'invalid_request' };
        }
      }

      // Validate scopes
      const requestedScopes = params.scope ? params.scope.split(' ') : ['openid'];
      const invalidScopes = requestedScopes.filter(scope => !client.allowedScopes.includes(scope));
      if (invalidScopes.length > 0) {
        return { success: false, error: 'invalid_scope' };
      }

      // Generate authorization URL for user consent
      const authUrl = new URL(`${this.config.issuer}/oauth/authorize`);
      authUrl.searchParams.set('response_type', params.response_type);
      authUrl.searchParams.set('client_id', params.client_id);
      authUrl.searchParams.set('redirect_uri', params.redirect_uri);
      authUrl.searchParams.set('scope', requestedScopes.join(' '));
      if (params.state) authUrl.searchParams.set('state', params.state);
      if (params.code_challenge) authUrl.searchParams.set('code_challenge', params.code_challenge);
      if (params.code_challenge_method) authUrl.searchParams.set('code_challenge_method', params.code_challenge_method);
      if (params.nonce) authUrl.searchParams.set('nonce', params.nonce);

      return { success: true, authorizationUrl: authUrl.toString() };
    } catch (error) {
      return { success: false, error: 'server_error' };
    }
  }

  /**
   * Generate Authorization Code after user consent
   */
  public generateAuthorizationCode(params: {
    client_id: string;
    user_id: string;
    tenant_id: string;
    redirect_uri: string;
    scopes: string[];
    code_challenge?: string;
    code_challenge_method?: string;
    nonce?: string;
    state?: string;
  }): { success: boolean; code?: string; error?: string } {
    try {
      const client = this.clients.get(params.client_id);
      if (!client || !client.isActive) {
        return { success: false, error: 'invalid_client' };
      }

      const code = this.generateSecureCode();
      const authorizationCode: AuthorizationCode = {
        code,
        clientId: params.client_id,
        userId: params.user_id,
        tenantId: params.tenant_id,
        redirectUri: params.redirect_uri,
        scopes: params.scopes,
        codeChallenge: params.code_challenge,
        codeChallengeMethod: params.code_challenge_method as 'S256' | 'plain',
        nonce: params.nonce,
        state: params.state,
        expiresAt: new Date(Date.now() + this.config.authorizationCodeTTL * 1000),
        createdAt: new Date(),
        isUsed: false
      };

      const validatedCode = AuthorizationCodeSchema.parse(authorizationCode);
      this.authorizationCodes.set(code, validatedCode);

      // Clean up expired codes
      this.cleanupExpiredCodes();

      return { success: true, code };
    } catch (error) {
      return { success: false, error: 'server_error' };
    }
  }

  /**
   * Exchange Authorization Code for Access Token
   */
  public exchangeAuthorizationCode(params: {
    grant_type: string;
    code: string;
    redirect_uri: string;
    client_id: string;
    client_secret?: string;
    code_verifier?: string;
  }): { success: boolean; tokenResponse?: any; error?: string } {
    try {
      if (params.grant_type !== 'authorization_code') {
        return { success: false, error: 'unsupported_grant_type' };
      }

      const client = this.clients.get(params.client_id);
      if (!client || !client.isActive) {
        return { success: false, error: 'invalid_client' };
      }

      // Validate client authentication
      if (client.clientType === 'CONFIDENTIAL') {
        if (!params.client_secret || params.client_secret !== client.clientSecret) {
          return { success: false, error: 'invalid_client' };
        }
      }

      const authCode = this.authorizationCodes.get(params.code);
      if (!authCode || authCode.isUsed || authCode.expiresAt < new Date()) {
        return { success: false, error: 'invalid_grant' };
      }

      // Validate redirect_uri
      if (authCode.redirectUri !== params.redirect_uri) {
        return { success: false, error: 'invalid_grant' };
      }

      // Validate PKCE
      if (authCode.codeChallenge && authCode.codeChallengeMethod) {
        if (!params.code_verifier) {
          return { success: false, error: 'invalid_request' };
        }

        const expectedChallenge = authCode.codeChallengeMethod === 'S256'
          ? crypto.createHash('sha256').update(params.code_verifier).digest('base64url')
          : params.code_verifier;

        if (expectedChallenge !== authCode.codeChallenge) {
          return { success: false, error: 'invalid_grant' };
        }
      }

      // Mark code as used
      authCode.isUsed = true;

      // Generate access token
      const tokenId = crypto.randomUUID();
      const accessToken = this.generateAccessToken({
        tokenId,
        clientId: authCode.clientId,
        userId: authCode.userId,
        tenantId: authCode.tenantId,
        scopes: authCode.scopes
      });

      const refreshToken = this.generateRefreshToken();

      const accessTokenRecord: AccessToken = {
        tokenId,
        accessToken,
        tokenType: 'Bearer',
        clientId: authCode.clientId,
        userId: authCode.userId,
        tenantId: authCode.tenantId,
        scopes: authCode.scopes,
        expiresAt: new Date(Date.now() + this.config.accessTokenTTL * 1000),
        createdAt: new Date(),
        refreshToken,
        refreshTokenExpiresAt: new Date(Date.now() + this.config.refreshTokenTTL * 1000),
        isRevoked: false
      };

      const validatedToken = AccessTokenSchema.parse(accessTokenRecord);
      this.accessTokens.set(accessToken, validatedToken);
      this.refreshTokens.set(refreshToken, validatedToken);

      // Generate ID token if openid scope is present
      let idToken;
      if (authCode.scopes.includes('openid')) {
        idToken = this.generateIDToken({
          clientId: authCode.clientId,
          userId: authCode.userId,
          tenantId: authCode.tenantId,
          scopes: authCode.scopes,
          nonce: authCode.nonce,
          accessToken
        });
      }

      const tokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: this.config.accessTokenTTL,
        refresh_token: refreshToken,
        scope: authCode.scopes.join(' '),
        ...(idToken && { id_token: idToken })
      };

      return { success: true, tokenResponse };
    } catch (error) {
      return { success: false, error: 'server_error' };
    }
  }

  /**
   * Handle Client Credentials Grant
   */
  public handleClientCredentialsGrant(params: {
    grant_type: string;
    client_id: string;
    client_secret: string;
    scope?: string;
  }): { success: boolean; tokenResponse?: any; error?: string } {
    try {
      if (params.grant_type !== 'client_credentials') {
        return { success: false, error: 'unsupported_grant_type' };
      }

      const client = this.clients.get(params.client_id);
      if (!client || !client.isActive || client.clientType !== 'CONFIDENTIAL') {
        return { success: false, error: 'invalid_client' };
      }

      if (params.client_secret !== client.clientSecret) {
        return { success: false, error: 'invalid_client' };
      }

      if (!client.allowedGrantTypes.includes('client_credentials')) {
        return { success: false, error: 'unauthorized_client' };
      }

      // Validate scopes
      const requestedScopes = params.scope ? params.scope.split(' ') : [];
      const invalidScopes = requestedScopes.filter(scope => !client.allowedScopes.includes(scope));
      if (invalidScopes.length > 0) {
        return { success: false, error: 'invalid_scope' };
      }

      // Generate access token
      const tokenId = crypto.randomUUID();
      const accessToken = this.generateAccessToken({
        tokenId,
        clientId: client.clientId,
        userId: client.clientId, // Use client_id as user_id for client credentials
        tenantId: client.tenantId,
        scopes: requestedScopes
      });

      const accessTokenRecord: AccessToken = {
        tokenId,
        accessToken,
        tokenType: 'Bearer',
        clientId: client.clientId,
        userId: client.clientId,
        tenantId: client.tenantId,
        scopes: requestedScopes,
        expiresAt: new Date(Date.now() + this.config.accessTokenTTL * 1000),
        createdAt: new Date(),
        isRevoked: false
      };

      const validatedToken = AccessTokenSchema.parse(accessTokenRecord);
      this.accessTokens.set(accessToken, validatedToken);

      const tokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: this.config.accessTokenTTL,
        scope: requestedScopes.join(' ')
      };

      return { success: true, tokenResponse };
    } catch (error) {
      return { success: false, error: 'server_error' };
    }
  }

  /**
   * Refresh Access Token
   */
  public refreshAccessToken(params: {
    grant_type: string;
    refresh_token: string;
    client_id: string;
    client_secret?: string;
    scope?: string;
  }): { success: boolean; tokenResponse?: any; error?: string } {
    try {
      if (params.grant_type !== 'refresh_token') {
        return { success: false, error: 'unsupported_grant_type' };
      }

      const client = this.clients.get(params.client_id);
      if (!client || !client.isActive) {
        return { success: false, error: 'invalid_client' };
      }

      if (client.clientType === 'CONFIDENTIAL' && params.client_secret !== client.clientSecret) {
        return { success: false, error: 'invalid_client' };
      }

      const tokenRecord = this.refreshTokens.get(params.refresh_token);
      if (!tokenRecord || tokenRecord.isRevoked || !tokenRecord.refreshTokenExpiresAt || 
          tokenRecord.refreshTokenExpiresAt < new Date()) {
        return { success: false, error: 'invalid_grant' };
      }

      // Validate scopes (can only request subset of original scopes)
      let scopes = tokenRecord.scopes;
      if (params.scope) {
        const requestedScopes = params.scope.split(' ');
        const invalidScopes = requestedScopes.filter(scope => !tokenRecord.scopes.includes(scope));
        if (invalidScopes.length > 0) {
          return { success: false, error: 'invalid_scope' };
        }
        scopes = requestedScopes;
      }

      // Revoke old tokens
      tokenRecord.isRevoked = true;

      // Generate new access token
      const tokenId = crypto.randomUUID();
      const accessToken = this.generateAccessToken({
        tokenId,
        clientId: tokenRecord.clientId,
        userId: tokenRecord.userId,
        tenantId: tokenRecord.tenantId,
        scopes
      });

      const refreshToken = this.generateRefreshToken();

      const newTokenRecord: AccessToken = {
        tokenId,
        accessToken,
        tokenType: 'Bearer',
        clientId: tokenRecord.clientId,
        userId: tokenRecord.userId,
        tenantId: tokenRecord.tenantId,
        scopes,
        expiresAt: new Date(Date.now() + this.config.accessTokenTTL * 1000),
        createdAt: new Date(),
        refreshToken,
        refreshTokenExpiresAt: new Date(Date.now() + this.config.refreshTokenTTL * 1000),
        isRevoked: false
      };

      const validatedToken = AccessTokenSchema.parse(newTokenRecord);
      this.accessTokens.set(accessToken, validatedToken);
      this.refreshTokens.set(refreshToken, validatedToken);

      const tokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: this.config.accessTokenTTL,
        refresh_token: refreshToken,
        scope: scopes.join(' ')
      };

      return { success: true, tokenResponse };
    } catch (error) {
      return { success: false, error: 'server_error' };
    }
  }

  /**
   * Get OIDC UserInfo
   */
  public getUserInfo(accessToken: string): { success: boolean; userInfo?: OIDCUserInfo; error?: string } {
    try {
      const tokenRecord = this.accessTokens.get(accessToken);
      if (!tokenRecord || tokenRecord.isRevoked || tokenRecord.expiresAt < new Date()) {
        return { success: false, error: 'invalid_token' };
      }

      if (!tokenRecord.scopes.includes('openid')) {
        return { success: false, error: 'insufficient_scope' };
      }

      const userInfo = this.userInfo.get(tokenRecord.userId);
      if (!userInfo) {
        return { success: false, error: 'user_not_found' };
      }

      // Filter user info based on scopes
      const filteredUserInfo = this.filterUserInfoByScopes(userInfo, tokenRecord.scopes);

      return { success: true, userInfo: filteredUserInfo };
    } catch (error) {
      return { success: false, error: 'server_error' };
    }
  }

  /**
   * Introspect Token (RFC 7662)
   */
  public introspectToken(token: string, clientId?: string): { 
    success: boolean; 
    tokenInfo?: any; 
    error?: string 
  } {
    try {
      const tokenRecord = this.accessTokens.get(token);
      if (!tokenRecord) {
        return { success: true, tokenInfo: { active: false } };
      }

      if (tokenRecord.isRevoked || tokenRecord.expiresAt < new Date()) {
        return { success: true, tokenInfo: { active: false } };
      }

      // Validate client authorization to introspect
      if (clientId && tokenRecord.clientId !== clientId) {
        const client = this.clients.get(clientId);
        if (!client || client.clientType !== 'CONFIDENTIAL') {
          return { success: false, error: 'unauthorized_client' };
        }
      }

      const tokenInfo = {
        active: true,
        scope: tokenRecord.scopes.join(' '),
        client_id: tokenRecord.clientId,
        username: tokenRecord.userId,
        token_type: tokenRecord.tokenType,
        exp: Math.floor(tokenRecord.expiresAt.getTime() / 1000),
        iat: Math.floor(tokenRecord.createdAt.getTime() / 1000),
        sub: tokenRecord.userId,
        aud: tokenRecord.clientId,
        iss: this.config.issuer,
        jti: tokenRecord.tokenId,
        tenant_id: tokenRecord.tenantId
      };

      return { success: true, tokenInfo };
    } catch (error) {
      return { success: false, error: 'server_error' };
    }
  }

  /**
   * Generate JWKS (JSON Web Key Set)
   */
  public generateJWKS(): any {
    return {
      keys: [
        {
          kty: 'RSA',
          use: 'sig',
          kid: this.config.keyId,
          alg: 'RS256',
          n: this.extractPublicKeyModulus(),
          e: 'AQAB'
        }
      ]
    };
  }

  /**
   * Get OpenID Connect Discovery Document
   */
  public getDiscoveryDocument(): any {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${this.config.issuer}/oauth/authorize`,
      token_endpoint: `${this.config.issuer}/oauth/token`,
      userinfo_endpoint: `${this.config.issuer}/oauth/userinfo`,
      jwks_uri: `${this.config.issuer}/.well-known/jwks.json`,
      introspection_endpoint: `${this.config.issuer}/oauth/introspect`,
      revocation_endpoint: `${this.config.issuer}/oauth/revoke`,
      
      response_types_supported: ['code', 'id_token', 'code id_token'],
      subject_types_supported: ['public', 'pairwise'],
      id_token_signing_alg_values_supported: ['RS256', 'RS384', 'RS512'],
      scopes_supported: this.config.supportedScopes,
      claims_supported: this.config.supportedClaims,
      grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt',
        'none'
      ],
      code_challenge_methods_supported: ['S256'],
      
      // iSECTECH specific
      tenant_isolation_supported: true,
      security_clearance_levels: ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
      supported_services: [
        'threat-detection',
        'asset-discovery',
        'compliance-automation',
        'ai-ml-services',
        'developer-portal'
      ]
    };
  }

  // Private helper methods
  private generateClientSecret(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  private generateSecureCode(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  private generateAccessToken(payload: {
    tokenId: string;
    clientId: string;
    userId: string;
    tenantId: string;
    scopes: string[];
  }): string {
    const now = Math.floor(Date.now() / 1000);
    const tokenPayload = {
      iss: this.config.issuer,
      aud: payload.clientId,
      sub: payload.userId,
      client_id: payload.clientId,
      tenant_id: payload.tenantId,
      scope: payload.scopes.join(' '),
      jti: payload.tokenId,
      iat: now,
      exp: now + this.config.accessTokenTTL
    };

    return jwt.sign(tokenPayload, this.config.privateKey, {
      algorithm: 'RS256',
      keyid: this.config.keyId
    });
  }

  private generateRefreshToken(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  private generateIDToken(params: {
    clientId: string;
    userId: string;
    tenantId: string;
    scopes: string[];
    nonce?: string;
    accessToken: string;
  }): string {
    const now = Math.floor(Date.now() / 1000);
    const userInfo = this.userInfo.get(params.userId);
    
    const idTokenPayload = {
      iss: this.config.issuer,
      aud: params.clientId,
      sub: params.userId,
      tenant_id: params.tenantId,
      iat: now,
      exp: now + this.config.idTokenTTL,
      at_hash: this.generateATHash(params.accessToken),
      ...(params.nonce && { nonce: params.nonce }),
      ...(userInfo && this.filterUserInfoByScopes(userInfo, params.scopes))
    };

    return jwt.sign(idTokenPayload, this.config.privateKey, {
      algorithm: 'RS256',
      keyid: this.config.keyId
    });
  }

  private generateATHash(accessToken: string): string {
    const hash = crypto.createHash('sha256').update(accessToken).digest();
    return hash.slice(0, hash.length / 2).toString('base64url');
  }

  private filterUserInfoByScopes(userInfo: OIDCUserInfo, scopes: string[]): Partial<OIDCUserInfo> {
    const filtered: Partial<OIDCUserInfo> = { sub: userInfo.sub };
    
    if (scopes.includes('profile')) {
      Object.assign(filtered, {
        name: userInfo.name,
        given_name: userInfo.given_name,
        family_name: userInfo.family_name,
        preferred_username: userInfo.preferred_username,
        picture: userInfo.picture
      });
    }
    
    if (scopes.includes('email')) {
      Object.assign(filtered, {
        email: userInfo.email,
        email_verified: userInfo.email_verified
      });
    }

    // iSECTECH custom claims
    Object.assign(filtered, {
      tenant_id: userInfo.tenant_id,
      security_clearance: userInfo.security_clearance,
      roles: userInfo.roles,
      permissions: userInfo.permissions,
      services: userInfo.services
    });

    return filtered;
  }

  private extractPublicKeyModulus(): string {
    // Extract modulus from public key for JWKS
    return crypto.createPublicKey(this.config.publicKey)
      .export({ format: 'jwk' }).n as string;
  }

  private cleanupExpiredCodes(): void {
    const now = new Date();
    for (const [code, authCode] of this.authorizationCodes) {
      if (authCode.expiresAt < now) {
        this.authorizationCodes.delete(code);
      }
    }
  }
}

// Export production-ready OAuth/OIDC provider
export const isectechOAuthOIDCProvider = new ISECTECHOAuthOIDCProvider({
  issuer: process.env.OAUTH_ISSUER || 'https://auth.isectech.com',
  privateKey: process.env.OAUTH_PRIVATE_KEY || '',
  publicKey: process.env.OAUTH_PUBLIC_KEY || '',
  keyId: process.env.OAUTH_KEY_ID || 'isectech-auth-key-1',
  authorizationCodeTTL: parseInt(process.env.OAUTH_AUTH_CODE_TTL || '600'), // 10 minutes
  accessTokenTTL: parseInt(process.env.OAUTH_ACCESS_TOKEN_TTL || '3600'), // 1 hour
  refreshTokenTTL: parseInt(process.env.OAUTH_REFRESH_TOKEN_TTL || '2592000'), // 30 days
  idTokenTTL: parseInt(process.env.OAUTH_ID_TOKEN_TTL || '3600'), // 1 hour
  supportedScopes: [
    'openid', 'profile', 'email', 'offline_access',
    'threat-detection', 'asset-discovery', 'compliance-automation',
    'ai-analysis', 'security-data', 'tenant-data', 'api-access'
  ],
  supportedClaims: [
    'sub', 'name', 'given_name', 'family_name', 'preferred_username',
    'email', 'email_verified', 'tenant_id', 'security_clearance',
    'roles', 'permissions', 'services', 'groups'
  ]
});