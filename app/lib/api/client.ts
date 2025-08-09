/**
 * API Client for iSECTECH Protect
 * Production-grade HTTP client with security, retries, and interceptors
 */

import axios, { 
  AxiosInstance, 
  AxiosRequestConfig, 
  AxiosResponse, 
  AxiosError,
  InternalAxiosRequestConfig 
} from 'axios';
import type { 
  ApiResponse, 
  ApiError, 
  SecurityContext,
  User,
  Tenant,
  TokenPair 
} from '@/types';
import { config } from '@/config/app';

// Request queue for token refresh
interface QueuedRequest {
  resolve: (value: any) => void;
  reject: (error: any) => void;
  config: AxiosRequestConfig;
}

class ApiClient {
  private instance: AxiosInstance;
  private isRefreshing = false;
  private failedQueue: QueuedRequest[] = [];
  private requestId = 0;
  private retryCount = new Map<string, number>();

  constructor() {
    this.instance = axios.create({
      baseURL: config.api.baseUrl,
      timeout: config.api.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Client-Version': config.app.version,
        'X-Client-Type': 'web',
      },
      withCredentials: true,
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.instance.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        // Add request ID for tracking
        const requestId = `req_${++this.requestId}_${Date.now()}`;
        config.headers['X-Request-ID'] = requestId;

        // Add timestamp for performance tracking
        config.metadata = { 
          ...config.metadata,
          requestId,
          startTime: Date.now() 
        };

        // Add security headers from auth store
        const securityHeaders = this.getSecurityHeaders();
        Object.assign(config.headers, securityHeaders);

        // Add tenant context if available
        const tenantId = this.getCurrentTenantId();
        if (tenantId) {
          config.headers['X-Tenant-ID'] = tenantId;
        }

        // Add device fingerprint
        const fingerprint = this.getDeviceFingerprint();
        if (fingerprint) {
          config.headers['X-Device-Fingerprint'] = fingerprint;
        }

        // Log request in development
        if (config.isDevelopment) {
          console.debug(`[API Request] ${config.method?.toUpperCase()} ${config.url}`, {
            requestId,
            headers: config.headers,
            data: config.data,
          });
        }

        return config;
      },
      (error: AxiosError) => {
        console.error('[API Request Error]', error);
        return Promise.reject(this.transformError(error));
      }
    );

    // Response interceptor
    this.instance.interceptors.response.use(
      (response: AxiosResponse) => {
        // Calculate response time
        const startTime = response.config.metadata?.startTime;
        const responseTime = startTime ? Date.now() - startTime : 0;

        // Update performance metrics
        this.updatePerformanceMetrics(responseTime);

        // Log response in development
        if (config.isDevelopment) {
          const requestId = response.config.metadata?.requestId;
          console.debug(`[API Response] ${response.status} ${response.config.url}`, {
            requestId,
            responseTime: `${responseTime}ms`,
            data: response.data,
          });
        }

        // Transform response to standard format
        return this.transformResponse(response);
      },
      async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

        // Handle 401 Unauthorized - token refresh
        if (error.response?.status === 401 && !originalRequest._retry) {
          if (this.isRefreshing) {
            // Queue the request while refreshing
            return new Promise((resolve, reject) => {
              this.failedQueue.push({ resolve, reject, config: originalRequest });
            });
          }

          originalRequest._retry = true;
          this.isRefreshing = true;

          try {
            const success = await this.refreshTokens();
            
            if (success) {
              // Process queued requests
              this.processQueue(null);
              
              // Retry original request with new token
              const securityHeaders = this.getSecurityHeaders();
              Object.assign(originalRequest.headers, securityHeaders);
              
              return this.instance.request(originalRequest);
            } else {
              // Refresh failed - redirect to login
              this.processQueue(new Error('Token refresh failed'));
              this.handleAuthFailure();
              return Promise.reject(this.transformError(error));
            }
          } catch (refreshError) {
            this.processQueue(refreshError);
            this.handleAuthFailure();
            return Promise.reject(this.transformError(error));
          } finally {
            this.isRefreshing = false;
          }
        }

        // Handle rate limiting
        if (error.response?.status === 429) {
          const retryAfter = error.response.headers['retry-after'];
          const delay = retryAfter ? parseInt(retryAfter) * 1000 : 1000;
          
          return this.retryRequest(originalRequest, delay);
        }

        // Handle server errors with retry
        if (error.response?.status && error.response.status >= 500) {
          const requestId = originalRequest.metadata?.requestId || 'unknown';
          const currentRetryCount = this.retryCount.get(requestId) || 0;
          
          if (currentRetryCount < config.api.retries) {
            this.retryCount.set(requestId, currentRetryCount + 1);
            const delay = Math.pow(2, currentRetryCount) * config.api.retryDelay;
            
            return this.retryRequest(originalRequest, delay);
          }
        }

        // Log error
        console.error('[API Response Error]', {
          url: error.config?.url,
          method: error.config?.method,
          status: error.response?.status,
          message: error.message,
          data: error.response?.data,
        });

        return Promise.reject(this.transformError(error));
      }
    );
  }

  private async retryRequest(config: AxiosRequestConfig, delay: number): Promise<AxiosResponse> {
    await new Promise(resolve => setTimeout(resolve, delay));
    return this.instance.request(config);
  }

  private processQueue(error: any): void {
    this.failedQueue.forEach(({ resolve, reject, config }) => {
      if (error) {
        reject(error);
      } else {
        resolve(this.instance.request(config));
      }
    });

    this.failedQueue = [];
  }

  private transformResponse(response: AxiosResponse): AxiosResponse {
    // Ensure consistent API response format
    if (response.data && typeof response.data === 'object') {
      if (!('success' in response.data)) {
        response.data = {
          success: true,
          data: response.data,
          metadata: {
            requestId: response.config.metadata?.requestId,
            timestamp: new Date(),
            duration: response.config.metadata?.startTime 
              ? Date.now() - response.config.metadata.startTime 
              : 0,
            version: config.app.version,
          },
        };
      }
    }

    return response;
  }

  private transformError(error: AxiosError): ApiError {
    const requestId = error.config?.metadata?.requestId || 'unknown';
    
    if (error.response) {
      // Server responded with error status
      const data = error.response.data as any;
      
      return {
        code: data?.code || `HTTP_${error.response.status}`,
        message: data?.message || error.message || 'Request failed',
        details: {
          status: error.response.status,
          statusText: error.response.statusText,
          url: error.config?.url,
          method: error.config?.method,
          requestId,
          ...data?.details,
        },
        field: data?.field,
        timestamp: new Date(),
        traceId: requestId,
      };
    } else if (error.request) {
      // Request was made but no response received
      return {
        code: 'NETWORK_ERROR',
        message: 'Network error - please check your connection',
        details: {
          url: error.config?.url,
          method: error.config?.method,
          requestId,
        },
        timestamp: new Date(),
        traceId: requestId,
      };
    } else {
      // Something else happened
      return {
        code: 'CLIENT_ERROR',
        message: error.message || 'An unexpected error occurred',
        details: {
          requestId,
        },
        timestamp: new Date(),
        traceId: requestId,
      };
    }
  }

  private getSecurityHeaders(): Record<string, string> {
    // This will be injected by the auth store
    if (typeof window !== 'undefined' && (window as any).__AUTH_STORE__) {
      return (window as any).__AUTH_STORE__.getSecurityHeaders();
    }
    return {};
  }

  private getCurrentTenantId(): string | null {
    // This will be injected by the auth store
    if (typeof window !== 'undefined' && (window as any).__AUTH_STORE__) {
      const tenant = (window as any).__AUTH_STORE__.tenant;
      return tenant?.id || null;
    }
    return null;
  }

  private getDeviceFingerprint(): string | null {
    if (typeof window !== 'undefined') {
      // Generate or retrieve device fingerprint
      let fingerprint = localStorage.getItem('device_fingerprint');
      
      if (!fingerprint) {
        fingerprint = this.generateDeviceFingerprint();
        localStorage.setItem('device_fingerprint', fingerprint);
      }
      
      return fingerprint;
    }
    return null;
  }

  private generateDeviceFingerprint(): string {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx?.fillText('iSECTECH Protect', 10, 10);
    
    const fingerprint = btoa(JSON.stringify({
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
      },
      canvas: canvas.toDataURL(),
      timestamp: Date.now(),
    }));

    return fingerprint.slice(0, 32); // Truncate for security
  }

  private async refreshTokens(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && (window as any).__AUTH_STORE__) {
        return await (window as any).__AUTH_STORE__.refreshTokens();
      }
      return false;
    } catch (error) {
      console.error('Token refresh failed:', error);
      return false;
    }
  }

  private handleAuthFailure(): void {
    if (typeof window !== 'undefined') {
      // Clear auth state and redirect to login
      if ((window as any).__AUTH_STORE__) {
        (window as any).__AUTH_STORE__.clearAuth();
      }
      
      // Redirect to login page
      window.location.href = '/login';
    }
  }

  private updatePerformanceMetrics(responseTime: number): void {
    if (typeof window !== 'undefined' && (window as any).__APP_STORE__) {
      (window as any).__APP_STORE__.updatePerformanceMetrics({
        apiResponseTime: responseTime,
      });
    }
  }

  // Public methods
  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.instance.get(url, config);
    return response.data;
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.instance.post(url, data, config);
    return response.data;
  }

  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.instance.put(url, data, config);
    return response.data;
  }

  async patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.instance.patch(url, data, config);
    return response.data;
  }

  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    const response = await this.instance.delete(url, config);
    return response.data;
  }

  // File upload with progress
  async uploadFile<T = any>(
    url: string,
    file: File,
    onProgress?: (progress: number) => void,
    config?: AxiosRequestConfig
  ): Promise<ApiResponse<T>> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await this.instance.post(url, formData, {
      ...config,
      headers: {
        'Content-Type': 'multipart/form-data',
        ...config?.headers,
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const percentComplete = (progressEvent.loaded / progressEvent.total) * 100;
          onProgress(percentComplete);
        }
      },
    });

    return response.data;
  }

  // Download file
  async downloadFile(url: string, filename?: string, config?: AxiosRequestConfig): Promise<void> {
    const response = await this.instance.get(url, {
      ...config,
      responseType: 'blob',
    });

    const blob = new Blob([response.data]);
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename || 'download';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  }

  // Health check
  async healthCheck(): Promise<boolean> {
    try {
      await this.get('/health');
      return true;
    } catch (error) {
      return false;
    }
  }

  // Get instance for advanced usage
  getInstance(): AxiosInstance {
    return this.instance;
  }

  // Update base URL
  setBaseURL(baseURL: string): void {
    this.instance.defaults.baseURL = baseURL;
  }

  // Update timeout
  setTimeout(timeout: number): void {
    this.instance.defaults.timeout = timeout;
  }

  // Cancel all pending requests
  cancelAllRequests(): void {
    // Implementation would require tracking active requests
    console.warn('Cancel all requests not implemented');
  }
}

// Create singleton instance
export const apiClient = new ApiClient();

// Export for dependency injection
export default apiClient;

// Make available globally for stores
if (typeof window !== 'undefined') {
  (window as any).__API_CLIENT__ = apiClient;
}