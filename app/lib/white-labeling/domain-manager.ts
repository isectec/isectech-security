/**
 * Domain Manager for iSECTECH Protect White-Labeling
 * Production-grade domain configuration with DNS validation and SSL management
 */

import crypto from 'crypto';
import type { 
  DomainConfiguration,
  DomainType,
  DomainStatus
} from '@/types/white-labeling';

export interface DomainValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  dnsRecords: {
    type: string;
    name: string;
    value: string;
    found: boolean;
    actualValue?: string;
  }[];
}

export interface SSLCertificateInfo {
  status: 'pending' | 'active' | 'expired' | 'failed';
  issuer: string;
  subject: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
  serialNumber: string;
}

export class DomainManager {
  private static instance: DomainManager;
  private domainCache = new Map<string, DomainConfiguration>();
  private validationCache = new Map<string, { result: DomainValidationResult; timestamp: number }>();
  private readonly CACHE_TTL = 300000; // 5 minutes
  
  private constructor() {}

  public static getInstance(): DomainManager {
    if (!DomainManager.instance) {
      DomainManager.instance = new DomainManager();
    }
    return DomainManager.instance;
  }

  /**
   * Configure a new domain for a tenant
   */
  public async configureDomain(
    tenantId: string,
    domainConfig: {
      type: DomainType;
      domain: string;
      subdomain?: string;
      autoRedirect?: boolean;
    },
    userId: string
  ): Promise<DomainConfiguration> {
    // Validate domain format and availability
    const validation = await this.validateDomainFormat(domainConfig.domain);
    if (!validation.isValid) {
      throw new Error(`Domain validation failed: ${validation.errors.join(', ')}`);
    }

    // Check if domain is already in use
    const existingDomain = await this.getDomainByName(domainConfig.domain);
    if (existingDomain && existingDomain.tenantId !== tenantId) {
      throw new Error('Domain is already in use by another tenant');
    }

    // Generate DNS records required for domain verification
    const requiredDnsRecords = this.generateRequiredDnsRecords(domainConfig);

    const configuration: DomainConfiguration = {
      id: this.generateId(),
      type: domainConfig.type,
      domain: domainConfig.domain,
      subdomain: domainConfig.subdomain,
      status: 'pending',
      sslCertificate: {
        status: 'pending',
        autoRenew: true,
      },
      dnsRecords: requiredDnsRecords,
      redirects: domainConfig.autoRedirect ? [
        {
          from: `www.${domainConfig.domain}`,
          to: domainConfig.domain,
          permanent: true,
        }
      ] : [],
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    // Save domain configuration
    await this.saveDomainConfiguration(configuration);

    // Clear cache
    this.domainCache.delete(domainConfig.domain);

    return configuration;
  }

  /**
   * Validate DNS records for domain verification
   */
  public async validateDnsRecords(
    domain: string,
    tenantId: string
  ): Promise<DomainValidationResult> {
    const cacheKey = `${domain}:${tenantId}`;
    
    // Check cache first
    const cached = this.validationCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.result;
    }

    const domainConfig = await this.getDomainConfiguration(domain, tenantId);
    if (!domainConfig) {
      throw new Error('Domain configuration not found');
    }

    const errors: string[] = [];
    const warnings: string[] = [];
    const dnsRecords: DomainValidationResult['dnsRecords'] = [];

    // Validate each required DNS record
    for (const record of domainConfig.dnsRecords) {
      try {
        const actualRecords = await this.queryDnsRecord(record.name, record.type);
        const found = actualRecords.includes(record.value);

        dnsRecords.push({
          type: record.type,
          name: record.name,
          value: record.value,
          found,
          actualValue: actualRecords[0] || undefined,
        });

        if (!found) {
          errors.push(`DNS ${record.type} record for ${record.name} not found or incorrect`);
        }
      } catch (error) {
        errors.push(`Failed to query DNS record ${record.type} for ${record.name}: ${error}`);
        dnsRecords.push({
          type: record.type,
          name: record.name,
          value: record.value,
          found: false,
        });
      }
    }

    const result: DomainValidationResult = {
      isValid: errors.length === 0,
      errors,
      warnings,
      dnsRecords,
    };

    // Cache the result
    this.validationCache.set(cacheKey, {
      result,
      timestamp: Date.now(),
    });

    return result;
  }

  /**
   * Request SSL certificate for domain
   */
  public async requestSslCertificate(
    domain: string,
    tenantId: string
  ): Promise<SSLCertificateInfo> {
    const domainConfig = await this.getDomainConfiguration(domain, tenantId);
    if (!domainConfig) {
      throw new Error('Domain configuration not found');
    }

    // Validate DNS records first
    const dnsValidation = await this.validateDnsRecords(domain, tenantId);
    if (!dnsValidation.isValid) {
      throw new Error('DNS validation failed. Cannot request SSL certificate until DNS records are properly configured.');
    }

    // Mock SSL certificate request - would integrate with Let's Encrypt, DigiCert, etc.
    const certificateInfo = await this.createSslCertificate(domain);

    // Update domain configuration with SSL certificate info
    domainConfig.sslCertificate = {
      status: 'active',
      issuer: certificateInfo.issuer,
      expiresAt: certificateInfo.validTo,
      autoRenew: true,
    };
    
    domainConfig.status = 'active';
    domainConfig.updatedAt = new Date();

    await this.saveDomainConfiguration(domainConfig);

    return certificateInfo;
  }

  /**
   * Renew SSL certificate
   */
  public async renewSslCertificate(
    domain: string,
    tenantId: string
  ): Promise<SSLCertificateInfo> {
    const domainConfig = await this.getDomainConfiguration(domain, tenantId);
    if (!domainConfig) {
      throw new Error('Domain configuration not found');
    }

    if (domainConfig.sslCertificate.status !== 'active') {
      throw new Error('Cannot renew certificate that is not currently active');
    }

    // Check if certificate needs renewal (30 days before expiration)
    if (domainConfig.sslCertificate.expiresAt) {
      const daysUntilExpiry = Math.ceil(
        (domainConfig.sslCertificate.expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
      );
      
      if (daysUntilExpiry > 30) {
        throw new Error('Certificate does not need renewal yet (renews 30 days before expiration)');
      }
    }

    // Request new certificate
    const newCertificate = await this.createSslCertificate(domain);

    // Update configuration
    domainConfig.sslCertificate = {
      status: 'active',
      issuer: newCertificate.issuer,
      expiresAt: newCertificate.validTo,
      autoRenew: true,
    };
    
    domainConfig.updatedAt = new Date();
    
    await this.saveDomainConfiguration(domainConfig);

    return newCertificate;
  }

  /**
   * Add domain redirect
   */
  public async addDomainRedirect(
    domain: string,
    tenantId: string,
    redirect: {
      from: string;
      to: string;
      permanent: boolean;
    },
    userId: string
  ): Promise<DomainConfiguration> {
    const domainConfig = await this.getDomainConfiguration(domain, tenantId);
    if (!domainConfig) {
      throw new Error('Domain configuration not found');
    }

    // Validate redirect URLs
    if (!this.isValidUrl(redirect.from) || !this.isValidUrl(redirect.to)) {
      throw new Error('Invalid redirect URLs provided');
    }

    // Check if redirect already exists
    const existingRedirect = domainConfig.redirects.find(r => r.from === redirect.from);
    if (existingRedirect) {
      existingRedirect.to = redirect.to;
      existingRedirect.permanent = redirect.permanent;
    } else {
      domainConfig.redirects.push(redirect);
    }

    domainConfig.updatedAt = new Date();
    domainConfig.updatedBy = userId;

    await this.saveDomainConfiguration(domainConfig);

    return domainConfig;
  }

  /**
   * Remove domain redirect
   */
  public async removeDomainRedirect(
    domain: string,
    tenantId: string,
    fromUrl: string,
    userId: string
  ): Promise<DomainConfiguration> {
    const domainConfig = await this.getDomainConfiguration(domain, tenantId);
    if (!domainConfig) {
      throw new Error('Domain configuration not found');
    }

    domainConfig.redirects = domainConfig.redirects.filter(r => r.from !== fromUrl);
    domainConfig.updatedAt = new Date();
    domainConfig.updatedBy = userId;

    await this.saveDomainConfiguration(domainConfig);

    return domainConfig;
  }

  /**
   * Get domain configuration
   */
  public async getDomainConfiguration(
    domain: string,
    tenantId: string
  ): Promise<DomainConfiguration | null> {
    const cacheKey = `${domain}:${tenantId}`;
    
    if (this.domainCache.has(cacheKey)) {
      return this.domainCache.get(cacheKey)!;
    }

    const config = await this.fetchDomainFromDatabase(domain, tenantId);
    
    if (config) {
      this.domainCache.set(cacheKey, config);
    }

    return config;
  }

  /**
   * List domains for tenant
   */
  public async getDomainsForTenant(tenantId: string): Promise<DomainConfiguration[]> {
    return this.fetchDomainsForTenant(tenantId);
  }

  /**
   * Delete domain configuration
   */
  public async deleteDomainConfiguration(
    domain: string,
    tenantId: string,
    userId: string
  ): Promise<void> {
    const domainConfig = await this.getDomainConfiguration(domain, tenantId);
    if (!domainConfig) {
      throw new Error('Domain configuration not found');
    }

    // Revoke SSL certificate if active
    if (domainConfig.sslCertificate.status === 'active') {
      await this.revokeSslCertificate(domain);
    }

    // Delete from database
    await this.deleteDomainFromDatabase(domain, tenantId);

    // Clear cache
    this.domainCache.delete(`${domain}:${tenantId}`);
    this.validationCache.delete(`${domain}:${tenantId}`);
  }

  /**
   * Check certificate expiration and renew if needed
   */
  public async checkAndRenewCertificates(): Promise<{
    renewed: string[];
    failed: { domain: string; error: string }[];
  }> {
    const renewed: string[] = [];
    const failed: { domain: string; error: string }[] = [];

    // Get all active domains with auto-renew enabled
    const domains = await this.getDomainsWithAutoRenew();

    for (const domain of domains) {
      try {
        if (this.needsCertificateRenewal(domain)) {
          await this.renewSslCertificate(domain.domain, domain.tenantId);
          renewed.push(domain.domain);
        }
      } catch (error) {
        failed.push({
          domain: domain.domain,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    return { renewed, failed };
  }

  // Private helper methods

  private generateRequiredDnsRecords(config: {
    type: DomainType;
    domain: string;
    subdomain?: string;
  }) {
    const records = [];
    const verificationToken = this.generateVerificationToken();

    if (config.type === 'custom-domain') {
      // A record pointing to our load balancer
      records.push({
        type: 'A' as const,
        name: config.domain,
        value: process.env.LOADBALANCER_IP || '203.0.113.1',
        verified: false,
      });

      // CNAME for www subdomain
      records.push({
        type: 'CNAME' as const,
        name: `www.${config.domain}`,
        value: config.domain,
        verified: false,
      });
    } else {
      // Subdomain CNAME
      const subdomainName = config.subdomain || 'app';
      records.push({
        type: 'CNAME' as const,
        name: `${subdomainName}.${config.domain}`,
        value: process.env.PLATFORM_DOMAIN || 'platform.isectech.com',
        verified: false,
      });
    }

    // TXT record for domain verification
    records.push({
      type: 'TXT' as const,
      name: `_isectech-verify.${config.domain}`,
      value: verificationToken,
      verified: false,
    });

    return records;
  }

  private async validateDomainFormat(domain: string): Promise<{ isValid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Basic domain format validation
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
    if (!domainRegex.test(domain)) {
      errors.push('Invalid domain format');
    }

    // Check domain length
    if (domain.length > 253) {
      errors.push('Domain name too long (max 253 characters)');
    }

    // Check for reserved domains
    const reservedDomains = ['localhost', 'example.com', 'test.com', 'invalid'];
    if (reservedDomains.includes(domain.toLowerCase())) {
      errors.push('Domain name is reserved and cannot be used');
    }

    return { isValid: errors.length === 0, errors };
  }

  private async queryDnsRecord(name: string, type: string): Promise<string[]> {
    try {
      // Use API endpoint for DNS queries to avoid client-side Node.js imports
      const response = await fetch('/api/dns-query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, type }),
      });

      if (!response.ok) {
        throw new Error(`DNS query failed: ${response.statusText}`);
      }

      const data = await response.json();
      return data.records || [];
    } catch (error) {
      console.warn(`DNS query failed for ${name} (${type}):`, error);
      return [];
    }
  }

  private async createSslCertificate(domain: string): Promise<SSLCertificateInfo> {
    // Mock SSL certificate creation - would integrate with Let's Encrypt, DigiCert, etc.
    const now = new Date();
    const validTo = new Date(now.getTime() + (90 * 24 * 60 * 60 * 1000)); // 90 days

    return {
      status: 'active',
      issuer: 'Let\'s Encrypt Authority X3',
      subject: `CN=${domain}`,
      validFrom: now,
      validTo,
      fingerprint: crypto.createHash('sha256').update(domain + now.toISOString()).digest('hex'),
      serialNumber: Math.random().toString(16).slice(2, 18),
    };
  }

  private async revokeSslCertificate(domain: string): Promise<void> {
    // Mock certificate revocation - would integrate with certificate authority
    console.log(`Revoking SSL certificate for domain: ${domain}`);
  }

  private needsCertificateRenewal(domain: DomainConfiguration): boolean {
    if (!domain.sslCertificate.expiresAt || !domain.sslCertificate.autoRenew) {
      return false;
    }

    const daysUntilExpiry = Math.ceil(
      (domain.sslCertificate.expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
    );

    return daysUntilExpiry <= 30;
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  private generateId(): string {
    return `domain_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateVerificationToken(): string {
    return `isectech-verify=${crypto.randomBytes(32).toString('hex')}`;
  }

  // Mock database operations - would be replaced with actual database calls

  private async getDomainByName(domain: string): Promise<DomainConfiguration | null> {
    // Mock implementation
    return null;
  }

  private async saveDomainConfiguration(config: DomainConfiguration): Promise<void> {
    // Mock implementation
    console.log('Saving domain configuration:', config);
  }

  private async fetchDomainFromDatabase(domain: string, tenantId: string): Promise<DomainConfiguration | null> {
    // Mock implementation
    return null;
  }

  private async fetchDomainsForTenant(tenantId: string): Promise<DomainConfiguration[]> {
    // Mock implementation
    return [];
  }

  private async deleteDomainFromDatabase(domain: string, tenantId: string): Promise<void> {
    // Mock implementation
    console.log(`Deleting domain ${domain} for tenant ${tenantId}`);
  }

  private async getDomainsWithAutoRenew(): Promise<DomainConfiguration[]> {
    // Mock implementation
    return [];
  }
}

// Export singleton instance
export const domainManager = DomainManager.getInstance();