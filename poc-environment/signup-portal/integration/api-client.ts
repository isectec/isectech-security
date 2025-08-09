// iSECTECH POC Signup Portal - API Client Integration
// Production-Grade TypeScript API Client for Frontend-Backend Communication
// Version: 1.0
// Author: Claude Code Implementation

import axios, { AxiosInstance, AxiosResponse, AxiosError } from 'axios';
import { v4 as uuidv4 } from 'uuid';

// ===== Types and Interfaces =====

export interface POCSignupRequest {
  // Company Information
  company_name: string;
  industry_vertical: string;
  company_size: 'startup' | 'small' | 'medium' | 'large' | 'enterprise';
  employee_count?: number;
  annual_revenue?: number;
  headquarters_country: string;
  website_url?: string;
  
  // Contact Information
  contact_name: string;
  contact_email: string;
  contact_phone?: string;
  job_title?: string;
  department?: string;
  
  // POC Configuration
  poc_tier: 'standard' | 'enterprise' | 'premium';
  poc_duration_days: number;
  security_clearance: 'unclassified' | 'confidential' | 'secret' | 'top_secret';
  data_residency_region: string;
  compliance_frameworks: string[];
  
  // Security Assessment
  current_security_tools?: Record<string, any>;
  security_maturity_level?: number;
  primary_security_challenges?: string[];
  evaluation_objectives?: string[];
  success_criteria?: Record<string, any>;
  
  // Business Context
  decision_makers?: Array<{
    name: string;
    title: string;
    email: string;
    role: string;
    influence_level: 'low' | 'medium' | 'high';
  }>;
  budget_range?: string;
  timeline_to_decision?: string;
  competitive_alternatives?: string[];
  
  // Technical Requirements
  integration_requirements?: Record<string, any>;
  compliance_requirements?: Record<string, any>;
  scalability_requirements?: Record<string, any>;
  
  // Tracking
  source_campaign?: string;
  
  // Legal Agreements
  terms_accepted: boolean;
  privacy_policy_accepted: boolean;
  nda_accepted: boolean;
  marketing_opt_in?: boolean;
}

export interface POCSignupResponse {
  success: boolean;
  message: string;
  tenant_id?: string;
  tenant_slug?: string;
  provisioning_id?: string;
  estimated_ready_at?: string;
  access_instructions?: string;
  support_contact?: string;
}

export interface APIError {
  error: string;
  message: string;
  details?: Record<string, any>;
  request_id: string;
  timestamp: string;
}

export interface HealthStatus {
  status: 'healthy' | 'unhealthy';
  database: 'connected' | 'disconnected';
  version: string;
  timestamp: string;
}

// ===== Configuration =====

export interface APIClientConfig {
  baseURL: string;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
  enableRequestLogging?: boolean;
  enableResponseLogging?: boolean;
  customHeaders?: Record<string, string>;
}

const DEFAULT_CONFIG: Required<APIClientConfig> = {
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL || 'https://api.app.isectech.org/api/v1',
  timeout: 30000, // 30 seconds
  retryAttempts: 3,
  retryDelay: 1000, // 1 second
  enableRequestLogging: process.env.NODE_ENV === 'development',
  enableResponseLogging: process.env.NODE_ENV === 'development',
  customHeaders: {},
};

// ===== API Client Class =====

export class POCSignupAPIClient {
  private client: AxiosInstance;
  private config: Required<APIClientConfig>;

  constructor(config: Partial<APIClientConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.client = this.createAxiosInstance();
  }

  private createAxiosInstance(): AxiosInstance {
    const client = axios.create({
      baseURL: this.config.baseURL,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...this.config.customHeaders,
      },
    });

    // Request interceptor
    client.interceptors.request.use(
      (config) => {
        // Add unique request ID for tracing
        const requestId = uuidv4();
        config.headers['X-Request-ID'] = requestId;
        
        // Add timestamp
        config.metadata = {
          ...config.metadata,
          requestId,
          startTime: Date.now(),
        };

        if (this.config.enableRequestLogging) {
          console.log(`[API Request] ${config.method?.toUpperCase()} ${config.url}`, {
            requestId,
            headers: config.headers,
            data: config.data,
          });
        }

        return config;
      },
      (error) => {
        console.error('[API Request Error]', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    client.interceptors.response.use(
      (response) => {
        const duration = Date.now() - (response.config.metadata?.startTime || 0);
        
        if (this.config.enableResponseLogging) {
          console.log(`[API Response] ${response.status} ${response.config.url} (${duration}ms)`, {
            requestId: response.config.metadata?.requestId,
            status: response.status,
            data: response.data,
            duration,
          });
        }

        return response;
      },
      async (error: AxiosError) => {
        const duration = Date.now() - (error.config?.metadata?.startTime || 0);
        
        console.error(`[API Error] ${error.response?.status || 'Network'} ${error.config?.url} (${duration}ms)`, {
          requestId: error.config?.metadata?.requestId,
          status: error.response?.status,
          data: error.response?.data,
          message: error.message,
          duration,
        });

        // Handle retry logic for specific errors
        if (this.shouldRetry(error) && !error.config?._retryCount) {
          return this.retryRequest(error);
        }

        return Promise.reject(this.transformError(error));
      }
    );

    return client;
  }

  private shouldRetry(error: AxiosError): boolean {
    // Retry on network errors or 5xx server errors
    return (
      !error.response ||
      (error.response.status >= 500 && error.response.status <= 599) ||
      error.code === 'ECONNABORTED' ||
      error.code === 'ENOTFOUND' ||
      error.code === 'ECONNRESET'
    );
  }

  private async retryRequest(error: AxiosError): Promise<AxiosResponse> {
    const config = error.config!;
    config._retryCount = (config._retryCount || 0) + 1;

    if (config._retryCount > this.config.retryAttempts) {
      return Promise.reject(error);
    }

    console.log(`[API Retry] Attempt ${config._retryCount}/${this.config.retryAttempts} for ${config.url}`);

    // Exponential backoff
    const delay = this.config.retryDelay * Math.pow(2, config._retryCount - 1);
    await new Promise(resolve => setTimeout(resolve, delay));

    return this.client.request(config);
  }

  private transformError(error: AxiosError): APIError {
    if (error.response?.data && typeof error.response.data === 'object') {
      // Server returned structured error
      return error.response.data as APIError;
    }

    // Generic error transformation
    return {
      error: error.code || 'network_error',
      message: error.message || 'An unexpected error occurred',
      request_id: error.config?.headers?.['X-Request-ID'] || 'unknown',
      timestamp: new Date().toISOString(),
    };
  }

  // ===== API Methods =====

  /**
   * Check the health status of the API service
   */
  async checkHealth(): Promise<HealthStatus> {
    const response = await this.client.get<HealthStatus>('/health');
    return response.data;
  }

  /**
   * Submit a POC signup request
   */
  async submitPOCSignup(request: POCSignupRequest): Promise<POCSignupResponse> {
    // Validate required fields before sending
    this.validatePOCSignupRequest(request);

    const response = await this.client.post<POCSignupResponse>('/poc/signup', request);
    return response.data;
  }

  /**
   * Get POC status by tenant ID (placeholder for future implementation)
   */
  async getPOCStatus(tenantId: string): Promise<any> {
    const response = await this.client.get(`/poc/status/${tenantId}`);
    return response.data;
  }

  /**
   * Request POC extension (placeholder for future implementation)
   */
  async requestPOCExtension(tenantId: string, extensionDays: number): Promise<any> {
    const response = await this.client.post(`/poc/extend/${tenantId}`, {
      extension_days: extensionDays,
    });
    return response.data;
  }

  /**
   * Terminate POC environment (placeholder for future implementation)
   */
  async terminatePOC(tenantId: string): Promise<any> {
    const response = await this.client.delete(`/poc/${tenantId}`);
    return response.data;
  }

  // ===== Validation Methods =====

  private validatePOCSignupRequest(request: POCSignupRequest): void {
    const errors: string[] = [];

    // Required string fields
    const requiredStringFields: (keyof POCSignupRequest)[] = [
      'company_name',
      'industry_vertical',
      'company_size',
      'headquarters_country',
      'contact_name',
      'contact_email',
      'poc_tier',
      'security_clearance',
      'data_residency_region',
    ];

    requiredStringFields.forEach(field => {
      const value = request[field];
      if (!value || (typeof value === 'string' && value.trim().length === 0)) {
        errors.push(`${field} is required`);
      }
    });

    // Required number fields
    if (!request.poc_duration_days || request.poc_duration_days < 7 || request.poc_duration_days > 180) {
      errors.push('poc_duration_days must be between 7 and 180');
    }

    // Required array fields
    if (!request.compliance_frameworks || request.compliance_frameworks.length === 0) {
      errors.push('compliance_frameworks is required and must contain at least one framework');
    }

    // Required boolean fields
    if (request.terms_accepted !== true) {
      errors.push('terms_accepted must be true');
    }
    if (request.privacy_policy_accepted !== true) {
      errors.push('privacy_policy_accepted must be true');
    }
    if (request.nda_accepted !== true) {
      errors.push('nda_accepted must be true');
    }

    // Email validation
    const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
    if (request.contact_email && !emailRegex.test(request.contact_email)) {
      errors.push('contact_email must be a valid email address');
    }

    // URL validation
    if (request.website_url) {
      try {
        new URL(request.website_url);
      } catch {
        errors.push('website_url must be a valid URL');
      }
    }

    // Enum validations
    const validCompanySizes = ['startup', 'small', 'medium', 'large', 'enterprise'];
    if (request.company_size && !validCompanySizes.includes(request.company_size)) {
      errors.push(`company_size must be one of: ${validCompanySizes.join(', ')}`);
    }

    const validPOCTiers = ['standard', 'enterprise', 'premium'];
    if (request.poc_tier && !validPOCTiers.includes(request.poc_tier)) {
      errors.push(`poc_tier must be one of: ${validPOCTiers.join(', ')}`);
    }

    const validSecurityClearances = ['unclassified', 'confidential', 'secret', 'top_secret'];
    if (request.security_clearance && !validSecurityClearances.includes(request.security_clearance)) {
      errors.push(`security_clearance must be one of: ${validSecurityClearances.join(', ')}`);
    }

    // Optional field validations
    if (request.security_maturity_level !== undefined) {
      if (request.security_maturity_level < 1 || request.security_maturity_level > 5) {
        errors.push('security_maturity_level must be between 1 and 5');
      }
    }

    if (errors.length > 0) {
      throw new Error(`Validation failed: ${errors.join(', ')}`);
    }
  }

  // ===== Utility Methods =====

  /**
   * Update API configuration
   */
  updateConfig(newConfig: Partial<APIClientConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.client = this.createAxiosInstance();
  }

  /**
   * Get current configuration
   */
  getConfig(): Required<APIClientConfig> {
    return { ...this.config };
  }

  /**
   * Clear any cached data or reset client state
   */
  reset(): void {
    this.client = this.createAxiosInstance();
  }
}

// ===== Factory Functions =====

/**
 * Create a new POC Signup API client instance
 */
export function createPOCSignupClient(config?: Partial<APIClientConfig>): POCSignupAPIClient {
  return new POCSignupAPIClient(config);
}

/**
 * Create a preconfigured client for development environment
 */
export function createDevelopmentClient(): POCSignupAPIClient {
  return new POCSignupAPIClient({
    baseURL: 'http://localhost:8080/api/v1',
    enableRequestLogging: true,
    enableResponseLogging: true,
    timeout: 10000,
  });
}

/**
 * Create a preconfigured client for production environment
 */
export function createProductionClient(): POCSignupAPIClient {
  return new POCSignupAPIClient({
    baseURL: 'https://api.app.isectech.org/api/v1',
    enableRequestLogging: false,
    enableResponseLogging: false,
    timeout: 30000,
    retryAttempts: 3,
  });
}

// ===== Default Export =====

export default POCSignupAPIClient;

// ===== Constants and Helpers =====

export const INDUSTRY_VERTICALS = [
  'financial_services',
  'healthcare',
  'government',
  'education',
  'retail',
  'manufacturing',
  'technology',
  'energy',
  'telecommunications',
  'media_entertainment',
  'transportation',
  'real_estate',
  'other',
] as const;

export const COMPANY_SIZES = [
  'startup',
  'small',
  'medium',
  'large',
  'enterprise',
] as const;

export const POC_TIERS = [
  'standard',
  'enterprise',
  'premium',
] as const;

export const SECURITY_CLEARANCES = [
  'unclassified',
  'confidential',
  'secret',
  'top_secret',
] as const;

export const COMPLIANCE_FRAMEWORKS = [
  'soc2',
  'iso27001',
  'hipaa',
  'gdpr',
  'fedramp',
  'fisma',
  'pci_dss',
  'ccpa',
  'nist',
  'cis',
] as const;

export const DATA_RESIDENCY_REGIONS = [
  'us',
  'eu',
  'uk',
  'ca',
  'au',
  'jp',
  'in',
  'sg',
  'global',
] as const;