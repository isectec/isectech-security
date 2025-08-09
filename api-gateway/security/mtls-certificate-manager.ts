/**
 * Production-grade mTLS Certificate Manager for iSECTECH
 * 
 * Provides comprehensive mutual TLS certificate management including
 * certificate generation, validation, rotation, and revocation for
 * secure service-to-service communication.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import * as forge from 'node-forge';
import * as fs from 'fs';
import * as path from 'path';

// Certificate Configuration Schemas
export const CertificateSchema = z.object({
  certificateId: z.string(),
  commonName: z.string(),
  subjectAlternativeNames: z.array(z.string()).default([]),
  organizationUnit: z.string().default('iSECTECH'),
  organization: z.string().default('iSECTECH Cybersecurity Platform'),
  country: z.string().default('US'),
  state: z.string().default('California'),
  locality: z.string().default('San Francisco'),
  
  certificateType: z.enum(['ROOT_CA', 'INTERMEDIATE_CA', 'SERVER', 'CLIENT', 'SERVICE']),
  keyUsage: z.array(z.enum([
    'digitalSignature',
    'keyEncipherment',
    'keyAgreement',
    'keyCertSign',
    'cRLSign',
    'dataEncipherment',
    'nonRepudiation'
  ])),
  extendedKeyUsage: z.array(z.enum([
    'serverAuth',
    'clientAuth',
    'codeSigning',
    'emailProtection',
    'timeStamping',
    'ocspSigning'
  ])).optional(),
  
  // Certificate content
  certificate: z.string(), // PEM format
  privateKey: z.string(), // PEM format
  publicKey: z.string(), // PEM format
  certificateChain: z.array(z.string()).default([]), // Full chain in PEM format
  
  // Validity
  notBefore: z.date(),
  notAfter: z.date(),
  serialNumber: z.string(),
  fingerprint: z.string(),
  
  // Status
  status: z.enum(['ACTIVE', 'REVOKED', 'EXPIRED', 'PENDING']).default('ACTIVE'),
  revocationReason: z.enum([
    'unspecified',
    'keyCompromise',
    'caCompromise',
    'affiliationChanged',
    'superseded',
    'cessationOfOperation',
    'certificateHold',
    'removeFromCRL'
  ]).optional(),
  revokedAt: z.date().optional(),
  
  // iSECTECH specific
  tenantId: z.string(),
  serviceId: z.string(),
  securityClearance: z.enum(['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET']).default('CONFIDENTIAL'),
  allowedServices: z.array(z.string()),
  
  // Metadata
  createdAt: z.date(),
  updatedAt: z.date(),
  autoRenewal: z.boolean().default(true),
  renewalThresholdDays: z.number().default(30),
  tags: z.array(z.string()).default(['isectech', 'mtls', 'certificate'])
});

export const CertificateAuthoritySchema = z.object({
  caId: z.string(),
  name: z.string(),
  type: z.enum(['ROOT_CA', 'INTERMEDIATE_CA']),
  certificate: z.string(), // PEM format
  privateKey: z.string(), // PEM format (encrypted)
  publicKey: z.string(), // PEM format
  
  // CA specific
  parentCaId: z.string().optional(), // For intermediate CAs
  crlDistributionPoints: z.array(z.string()).default([]),
  ocspUrl: z.string().optional(),
  
  // Validity
  notBefore: z.date(),
  notAfter: z.date(),
  serialNumber: z.string(),
  nextCrlUpdate: z.date(),
  
  // Configuration
  keySize: z.number().default(4096),
  hashAlgorithm: z.string().default('sha256'),
  maxPathLength: z.number().optional(),
  
  // Status
  isActive: z.boolean().default(true),
  issuedCertificates: z.number().default(0),
  revokedCertificates: z.number().default(0),
  
  // Security
  privateKeyEncrypted: z.boolean().default(true),
  hsmBacked: z.boolean().default(false),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const CertificateRevocationListSchema = z.object({
  crlId: z.string(),
  caId: z.string(),
  version: z.number(),
  thisUpdate: z.date(),
  nextUpdate: z.date(),
  
  revokedCertificates: z.array(z.object({
    serialNumber: z.string(),
    revocationDate: z.date(),
    reason: z.string()
  })),
  
  crlData: z.string(), // DER format base64 encoded
  signature: z.string(),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export type Certificate = z.infer<typeof CertificateSchema>;
export type CertificateAuthority = z.infer<typeof CertificateAuthoritySchema>;
export type CertificateRevocationList = z.infer<typeof CertificateRevocationListSchema>;

export interface CertificateValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  expiryDays: number;
  trustChainValid: boolean;
  revocationStatus: 'GOOD' | 'REVOKED' | 'UNKNOWN';
}

/**
 * mTLS Certificate Manager for iSECTECH
 */
export class ISECTECHmTLSCertificateManager {
  private certificates: Map<string, Certificate> = new Map();
  private certificateAuthorities: Map<string, CertificateAuthority> = new Map();
  private crlStore: Map<string, CertificateRevocationList> = new Map();
  private serialNumbers: Set<string> = new Set();

  constructor(
    private config: {
      certificateStorePath: string;
      caStorePath: string;
      crlStorePath: string;
      defaultValidityDays: number;
      autoRenewalEnabled: boolean;
      hsmEnabled: boolean;
      encryptionPassword: string;
    }
  ) {
    this.initializeRootCA();
    this.initializeServiceCertificates();
  }

  /**
   * Initialize Root Certificate Authority
   */
  private initializeRootCA(): void {
    const rootCA = this.generateRootCA({
      commonName: 'iSECTECH Root Certificate Authority',
      organization: 'iSECTECH Cybersecurity Platform',
      validityYears: 20
    });

    this.certificateAuthorities.set(rootCA.caId, rootCA);
    console.log(`Initialized Root CA: ${rootCA.caId}`);
  }

  /**
   * Initialize service certificates for iSECTECH services
   */
  private initializeServiceCertificates(): void {
    const serviceConfigs = [
      {
        serviceId: 'kong-gateway',
        commonName: 'kong-gateway.isectech.internal',
        sans: ['kong-gateway', 'api-gateway.isectech.com', 'gateway.isectech.internal'],
        tenantId: 'system',
        securityClearance: 'SECRET' as const,
        allowedServices: ['*']
      },
      {
        serviceId: 'threat-detection',
        commonName: 'threat-detection.isectech.internal',
        sans: ['threat-detection', 'threats.isectech.com'],
        tenantId: 'system',
        securityClearance: 'SECRET' as const,
        allowedServices: ['ai-ml-services', 'event-processing', 'kong-gateway']
      },
      {
        serviceId: 'asset-discovery',
        commonName: 'asset-discovery.isectech.internal',
        sans: ['asset-discovery', 'assets.isectech.com'],
        tenantId: 'system',
        securityClearance: 'CONFIDENTIAL' as const,
        allowedServices: ['vulnerability-management', 'kong-gateway']
      },
      {
        serviceId: 'compliance-automation',
        commonName: 'compliance.isectech.internal',
        sans: ['compliance-automation', 'compliance.isectech.com'],
        tenantId: 'system',
        securityClearance: 'CONFIDENTIAL' as const,
        allowedServices: ['kong-gateway']
      },
      {
        serviceId: 'ai-ml-services',
        commonName: 'ai-ml.isectech.internal',
        sans: ['ai-ml-services', 'ai.isectech.com'],
        tenantId: 'system',
        securityClearance: 'SECRET' as const,
        allowedServices: ['threat-detection', 'behavioral-analysis', 'kong-gateway']
      }
    ];

    serviceConfigs.forEach(config => {
      const certificate = this.generateServiceCertificate(config);
      this.certificates.set(certificate.certificateId, certificate);
      console.log(`Generated service certificate for: ${config.serviceId}`);
    });
  }

  /**
   * Generate Root Certificate Authority
   */
  private generateRootCA(params: {
    commonName: string;
    organization: string;
    validityYears: number;
  }): CertificateAuthority {
    const caId = `root-ca-${Date.now()}`;
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Create certificate using forge
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);
    cert.serialNumber = this.generateSerialNumber();
    
    const now = new Date();
    const notAfter = new Date(now.getTime() + params.validityYears * 365 * 24 * 60 * 60 * 1000);
    cert.validity.notBefore = now;
    cert.validity.notAfter = notAfter;

    // Set subject and issuer (same for root CA)
    const attrs = [
      { name: 'commonName', value: params.commonName },
      { name: 'organizationName', value: params.organization },
      { name: 'organizationalUnitName', value: 'Certificate Authority' },
      { name: 'countryName', value: 'US' },
      { name: 'stateOrProvinceName', value: 'California' },
      { name: 'localityName', value: 'San Francisco' }
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // Set extensions for CA
    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: true,
        critical: true
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        cRLSign: true,
        critical: true
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ]);

    // Sign certificate
    const privateKey = forge.pki.privateKeyFromPem(keyPair.privateKey);
    cert.sign(privateKey, forge.md.sha256.create());

    const certificatePem = forge.pki.certificateToPem(cert);
    const encryptedPrivateKey = this.encryptPrivateKey(keyPair.privateKey);

    const rootCA: CertificateAuthority = {
      caId,
      name: params.commonName,
      type: 'ROOT_CA',
      certificate: certificatePem,
      privateKey: encryptedPrivateKey,
      publicKey: keyPair.publicKey,
      crlDistributionPoints: [`https://pki.isectech.com/crl/${caId}.crl`],
      ocspUrl: `https://ocsp.isectech.com`,
      notBefore: now,
      notAfter,
      serialNumber: cert.serialNumber,
      nextCrlUpdate: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000), // 7 days
      keySize: 4096,
      hashAlgorithm: 'sha256',
      isActive: true,
      issuedCertificates: 0,
      revokedCertificates: 0,
      privateKeyEncrypted: true,
      hsmBacked: this.config.hsmEnabled,
      createdAt: now,
      updatedAt: now
    };

    return CertificateAuthoritySchema.parse(rootCA);
  }

  /**
   * Generate service certificate
   */
  private generateServiceCertificate(params: {
    serviceId: string;
    commonName: string;
    sans: string[];
    tenantId: string;
    securityClearance: 'UNCLASSIFIED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET';
    allowedServices: string[];
  }): Certificate {
    const certificateId = `${params.serviceId}-${Date.now()}`;
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Get Root CA for signing
    const rootCA = Array.from(this.certificateAuthorities.values())
      .find(ca => ca.type === 'ROOT_CA');
    if (!rootCA) {
      throw new Error('Root CA not found');
    }

    // Create certificate
    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);
    cert.serialNumber = this.generateSerialNumber();

    const now = new Date();
    const notAfter = new Date(now.getTime() + this.config.defaultValidityDays * 24 * 60 * 60 * 1000);
    cert.validity.notBefore = now;
    cert.validity.notAfter = notAfter;

    // Set subject
    const subjectAttrs = [
      { name: 'commonName', value: params.commonName },
      { name: 'organizationName', value: 'iSECTECH Cybersecurity Platform' },
      { name: 'organizationalUnitName', value: 'iSECTECH Services' },
      { name: 'countryName', value: 'US' },
      { name: 'stateOrProvinceName', value: 'California' },
      { name: 'localityName', value: 'San Francisco' }
    ];
    cert.setSubject(subjectAttrs);

    // Set issuer (Root CA)
    const rootCert = forge.pki.certificateFromPem(rootCA.certificate);
    cert.setIssuer(rootCert.subject.attributes);

    // Set extensions
    const extensions = [
      {
        name: 'basicConstraints',
        cA: false,
        critical: true
      },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyEncipherment: true,
        critical: true
      },
      {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
        critical: true
      },
      {
        name: 'subjectKeyIdentifier'
      },
      {
        name: 'authorityKeyIdentifier',
        keyIdentifier: true
      }
    ];

    // Add Subject Alternative Names
    if (params.sans.length > 0) {
      extensions.push({
        name: 'subjectAltName',
        altNames: params.sans.map(san => ({
          type: san.includes('.') ? 2 : 2, // DNS name
          value: san
        }))
      } as any);
    }

    // Add CRL Distribution Points
    extensions.push({
      name: 'cRLDistributionPoints',
      distributionPoints: [{
        fullName: [{
          type: 6, // URI
          value: `https://pki.isectech.com/crl/${rootCA.caId}.crl`
        }]
      }]
    } as any);

    cert.setExtensions(extensions);

    // Sign certificate with Root CA
    const caPrivateKey = forge.pki.privateKeyFromPem(
      this.decryptPrivateKey(rootCA.privateKey)
    );
    cert.sign(caPrivateKey, forge.md.sha256.create());

    const certificatePem = forge.pki.certificateToPem(cert);
    const fingerprint = forge.md.sha256.create();
    fingerprint.update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());

    const certificate: Certificate = {
      certificateId,
      commonName: params.commonName,
      subjectAlternativeNames: params.sans,
      organizationUnit: 'iSECTECH Services',
      organization: 'iSECTECH Cybersecurity Platform',
      country: 'US',
      state: 'California',
      locality: 'San Francisco',
      certificateType: 'SERVICE',
      keyUsage: ['digitalSignature', 'keyEncipherment'],
      extendedKeyUsage: ['serverAuth', 'clientAuth'],
      certificate: certificatePem,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      certificateChain: [certificatePem, rootCA.certificate],
      notBefore: now,
      notAfter,
      serialNumber: cert.serialNumber,
      fingerprint: fingerprint.digest().toHex(),
      status: 'ACTIVE',
      tenantId: params.tenantId,
      serviceId: params.serviceId,
      securityClearance: params.securityClearance,
      allowedServices: params.allowedServices,
      createdAt: now,
      updatedAt: now,
      autoRenewal: true,
      renewalThresholdDays: 30,
      tags: ['isectech', 'mtls', 'service', params.serviceId]
    };

    return CertificateSchema.parse(certificate);
  }

  /**
   * Validate certificate
   */
  public validateCertificate(certificateId: string): CertificateValidationResult {
    const certificate = this.certificates.get(certificateId);
    if (!certificate) {
      return {
        isValid: false,
        errors: ['Certificate not found'],
        warnings: [],
        expiryDays: 0,
        trustChainValid: false,
        revocationStatus: 'UNKNOWN'
      };
    }

    const errors: string[] = [];
    const warnings: string[] = [];

    // Check expiry
    const now = new Date();
    const expiryDays = Math.floor((certificate.notAfter.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
    
    if (certificate.notAfter < now) {
      errors.push('Certificate has expired');
    } else if (expiryDays <= certificate.renewalThresholdDays) {
      warnings.push(`Certificate expires in ${expiryDays} days`);
    }

    // Check status
    if (certificate.status === 'REVOKED') {
      errors.push('Certificate has been revoked');
    } else if (certificate.status === 'EXPIRED') {
      errors.push('Certificate has expired');
    }

    // Validate certificate chain
    const trustChainValid = this.validateCertificateChain(certificate);
    if (!trustChainValid) {
      errors.push('Certificate chain validation failed');
    }

    // Check revocation status
    const revocationStatus = this.checkRevocationStatus(certificate);

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      expiryDays,
      trustChainValid,
      revocationStatus
    };
  }

  /**
   * Validate certificate chain
   */
  private validateCertificateChain(certificate: Certificate): boolean {
    try {
      const cert = forge.pki.certificateFromPem(certificate.certificate);
      const caStore = forge.pki.createCaStore();

      // Add all CA certificates to store
      for (const ca of this.certificateAuthorities.values()) {
        const caCert = forge.pki.certificateFromPem(ca.certificate);
        caStore.addCertificate(caCert);
      }

      // Verify certificate chain
      const verified = forge.pki.verifyCertificateChain(caStore, [cert]);
      return verified;
    } catch (error) {
      console.error('Certificate chain validation error:', error);
      return false;
    }
  }

  /**
   * Check certificate revocation status
   */
  private checkRevocationStatus(certificate: Certificate): 'GOOD' | 'REVOKED' | 'UNKNOWN' {
    if (certificate.status === 'REVOKED') {
      return 'REVOKED';
    }

    // Check against CRL
    for (const crl of this.crlStore.values()) {
      const revokedCert = crl.revokedCertificates.find(
        rc => rc.serialNumber === certificate.serialNumber
      );
      if (revokedCert) {
        return 'REVOKED';
      }
    }

    return 'GOOD';
  }

  /**
   * Revoke certificate
   */
  public revokeCertificate(
    certificateId: string,
    reason: 'unspecified' | 'keyCompromise' | 'caCompromise' | 'affiliationChanged' | 
           'superseded' | 'cessationOfOperation' | 'certificateHold' | 'removeFromCRL'
  ): boolean {
    const certificate = this.certificates.get(certificateId);
    if (!certificate) {
      return false;
    }

    certificate.status = 'REVOKED';
    certificate.revocationReason = reason;
    certificate.revokedAt = new Date();
    certificate.updatedAt = new Date();

    // Update CRL
    this.updateCRL(certificate);

    console.log(`Certificate ${certificateId} revoked with reason: ${reason}`);
    return true;
  }

  /**
   * Renew certificate
   */
  public renewCertificate(certificateId: string): Certificate | null {
    const oldCertificate = this.certificates.get(certificateId);
    if (!oldCertificate) {
      return null;
    }

    // Generate new certificate with same parameters
    const newCertificate = this.generateServiceCertificate({
      serviceId: oldCertificate.serviceId,
      commonName: oldCertificate.commonName,
      sans: oldCertificate.subjectAlternativeNames,
      tenantId: oldCertificate.tenantId,
      securityClearance: oldCertificate.securityClearance,
      allowedServices: oldCertificate.allowedServices
    });

    // Revoke old certificate
    this.revokeCertificate(certificateId, 'superseded');

    // Store new certificate
    this.certificates.set(newCertificate.certificateId, newCertificate);

    console.log(`Certificate ${certificateId} renewed. New certificate: ${newCertificate.certificateId}`);
    return newCertificate;
  }

  /**
   * Auto-renew certificates
   */
  public autoRenewCertificates(): string[] {
    const renewedCertificates: string[] = [];
    const now = new Date();

    for (const [certificateId, certificate] of this.certificates) {
      if (!certificate.autoRenewal || certificate.status !== 'ACTIVE') {
        continue;
      }

      const daysUntilExpiry = Math.floor(
        (certificate.notAfter.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
      );

      if (daysUntilExpiry <= certificate.renewalThresholdDays) {
        const newCertificate = this.renewCertificate(certificateId);
        if (newCertificate) {
          renewedCertificates.push(newCertificate.certificateId);
        }
      }
    }

    return renewedCertificates;
  }

  /**
   * Update Certificate Revocation List
   */
  private updateCRL(revokedCertificate: Certificate): void {
    const rootCA = Array.from(this.certificateAuthorities.values())
      .find(ca => ca.type === 'ROOT_CA');
    if (!rootCA) {
      return;
    }

    let crl = this.crlStore.get(rootCA.caId);
    if (!crl) {
      crl = {
        crlId: `crl-${rootCA.caId}`,
        caId: rootCA.caId,
        version: 1,
        thisUpdate: new Date(),
        nextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        revokedCertificates: [],
        crlData: '',
        signature: '',
        createdAt: new Date(),
        updatedAt: new Date()
      };
    }

    // Add revoked certificate
    crl.revokedCertificates.push({
      serialNumber: revokedCertificate.serialNumber,
      revocationDate: revokedCertificate.revokedAt!,
      reason: revokedCertificate.revocationReason!
    });

    crl.version += 1;
    crl.thisUpdate = new Date();
    crl.updatedAt = new Date();

    // Generate CRL data using forge
    const crlObj = forge.pki.createCertificateRevocationList();
    crlObj.version = crl.version - 1; // CRL version is 0-based
    crlObj.thisUpdate = crl.thisUpdate;
    crlObj.nextUpdate = crl.nextUpdate;

    // Add revoked certificates
    crl.revokedCertificates.forEach(rc => {
      crlObj.addRevokedCertificate({
        serialNumber: rc.serialNumber,
        revocationDate: rc.revocationDate
      });
    });

    // Sign CRL
    const caPrivateKey = forge.pki.privateKeyFromPem(
      this.decryptPrivateKey(rootCA.privateKey)
    );
    const caCert = forge.pki.certificateFromPem(rootCA.certificate);
    crlObj.sign(caPrivateKey, forge.md.sha256.create());
    crlObj.issuer = caCert.subject;

    crl.crlData = forge.util.encode64(forge.asn1.toDer(forge.pki.certificateRevocationListToAsn1(crlObj)).getBytes());
    crl.signature = 'sha256WithRSAEncryption';

    this.crlStore.set(rootCA.caId, crl);
  }

  /**
   * Get certificate for service
   */
  public getCertificateForService(serviceId: string): Certificate | null {
    for (const certificate of this.certificates.values()) {
      if (certificate.serviceId === serviceId && certificate.status === 'ACTIVE') {
        return certificate;
      }
    }
    return null;
  }

  /**
   * Get Kong mTLS plugin configuration
   */
  public generateKongmTLSPluginConfiguration(): Array<{
    name: string;
    config: object;
    enabled: boolean;
    tags: string[];
  }> {
    const configurations = [];

    // Get Root CA certificate
    const rootCA = Array.from(this.certificateAuthorities.values())
      .find(ca => ca.type === 'ROOT_CA');
    
    if (rootCA) {
      configurations.push({
        name: 'mtls-auth',
        config: {
          ca_certificates: [rootCA.certificate],
          skip_consumer_lookup: false,
          anonymous: null,
          consumer_by: ['username', 'custom_id'],
          cache_ttl: 3600,
          revocation_check_mode: 'IGNORE_CA_ERROR',
          http_timeout: 30000,
          cert_cache_ttl: 60000
        },
        enabled: true,
        tags: ['isectech', 'mtls', 'authentication']
      });
    }

    return configurations;
  }

  /**
   * Generate SSL configuration for Kong
   */
  public generateKongSSLConfiguration(): object {
    const certificates = [];
    
    for (const certificate of this.certificates.values()) {
      if (certificate.status === 'ACTIVE' && certificate.certificateType === 'SERVICE') {
        certificates.push({
          cert: certificate.certificate,
          key: certificate.privateKey,
          snis: [certificate.commonName, ...certificate.subjectAlternativeNames]
        });
      }
    }

    return {
      ssl_cert_by_lua_block: `
        local ssl = require "resty.openssl.ssl"
        local x509 = require "resty.openssl.x509"
        local pkey = require "resty.openssl.pkey"
        
        -- mTLS certificate selection logic
        local sni = ssl.get_server_name()
        if sni then
          -- Select appropriate certificate based on SNI
          local cert_data = get_certificate_for_sni(sni)
          if cert_data then
            ssl.set_cert(cert_data.cert)
            ssl.set_priv_key(cert_data.key)
          end
        end
      `,
      ssl_certificate_by_lua_block: `
        local ssl = require "resty.openssl.ssl"
        -- Custom certificate selection logic for iSECTECH services
      `
    };
  }

  // Private utility methods
  private generateSerialNumber(): string {
    let serial;
    do {
      serial = crypto.randomBytes(16).toString('hex');
    } while (this.serialNumbers.has(serial));
    
    this.serialNumbers.add(serial);
    return serial;
  }

  private encryptPrivateKey(privateKey: string): string {
    const cipher = crypto.createCipher('aes-256-cbc', this.config.encryptionPassword);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private decryptPrivateKey(encryptedPrivateKey: string): string {
    const decipher = crypto.createDecipher('aes-256-cbc', this.config.encryptionPassword);
    let decrypted = decipher.update(encryptedPrivateKey, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  /**
   * Export certificates for external use
   */
  public exportCertificate(certificateId: string, format: 'PEM' | 'DER' | 'P12'): string | Buffer | null {
    const certificate = this.certificates.get(certificateId);
    if (!certificate) {
      return null;
    }

    switch (format) {
      case 'PEM':
        return certificate.certificate;
      case 'DER':
        const cert = forge.pki.certificateFromPem(certificate.certificate);
        return Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), 'binary');
      case 'P12':
        // Create PKCS#12 bundle
        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
          forge.pki.privateKeyFromPem(certificate.privateKey),
          [forge.pki.certificateFromPem(certificate.certificate)],
          this.config.encryptionPassword
        );
        return Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), 'binary');
      default:
        return null;
    }
  }

  /**
   * Get certificate statistics
   */
  public getCertificateStatistics(): object {
    const stats = {
      totalCertificates: this.certificates.size,
      activeCertificates: 0,
      revokedCertificates: 0,
      expiredCertificates: 0,
      expiringIn30Days: 0,
      certificatesByType: {} as Record<string, number>,
      certificatesByService: {} as Record<string, number>
    };

    const now = new Date();
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    for (const certificate of this.certificates.values()) {
      // Status counts
      if (certificate.status === 'ACTIVE') {
        stats.activeCertificates++;
        if (certificate.notAfter < thirtyDaysFromNow) {
          stats.expiringIn30Days++;
        }
      } else if (certificate.status === 'REVOKED') {
        stats.revokedCertificates++;
      } else if (certificate.status === 'EXPIRED') {
        stats.expiredCertificates++;
      }

      // Type counts
      stats.certificatesByType[certificate.certificateType] = 
        (stats.certificatesByType[certificate.certificateType] || 0) + 1;

      // Service counts
      stats.certificatesByService[certificate.serviceId] = 
        (stats.certificatesByService[certificate.serviceId] || 0) + 1;
    }

    return stats;
  }
}

// Export production-ready mTLS certificate manager
export const isectechMTLSCertificateManager = new ISECTECHmTLSCertificateManager({
  certificateStorePath: process.env.CERT_STORE_PATH || '/secure/certificates',
  caStorePath: process.env.CA_STORE_PATH || '/secure/ca',
  crlStorePath: process.env.CRL_STORE_PATH || '/secure/crl',
  defaultValidityDays: parseInt(process.env.CERT_VALIDITY_DAYS || '365'),
  autoRenewalEnabled: process.env.CERT_AUTO_RENEWAL !== 'false',
  hsmEnabled: process.env.HSM_ENABLED === 'true',
  encryptionPassword: process.env.CERT_ENCRYPTION_PASSWORD || crypto.randomBytes(32).toString('hex')
});