/**
 * Application Configuration for iSECTECH Protect
 * Production-grade configuration management
 */

import type { Environment } from '@/types';

// Environment Configuration
export const env: Environment = (process.env.NODE_ENV as Environment) || 'development';

export const isDevelopment = env === 'development';
export const isProduction = env === 'production';
export const isStaging = env === 'staging';
export const isTest = env === 'test';

// API Configuration
export const apiConfig = {
  baseUrl: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080',
  timeout: parseInt(process.env.NEXT_PUBLIC_API_TIMEOUT || '30000'),
  retries: parseInt(process.env.NEXT_PUBLIC_API_RETRIES || '3'),
  retryDelay: parseInt(process.env.NEXT_PUBLIC_API_RETRY_DELAY || '1000'),
  endpoints: {
    auth: '/api/v1/auth',
    users: '/api/v1/users',
    tenants: '/api/v1/tenants',
    assets: '/api/v1/assets',
    threats: '/api/v1/threats',
    alerts: '/api/v1/alerts',
    events: '/api/v1/events',
    compliance: '/api/v1/compliance',
    reports: '/api/v1/reports',
    analytics: '/api/v1/analytics',
    websocket: '/ws',
  },
} as const;

// WebSocket Configuration
export const websocketConfig = {
  url: process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8080/ws',
  reconnectAttempts: parseInt(process.env.NEXT_PUBLIC_WS_RECONNECT_ATTEMPTS || '5'),
  reconnectInterval: parseInt(process.env.NEXT_PUBLIC_WS_RECONNECT_INTERVAL || '5000'),
  heartbeatInterval: parseInt(process.env.NEXT_PUBLIC_WS_HEARTBEAT_INTERVAL || '30000'),
  maxMessageSize: parseInt(process.env.NEXT_PUBLIC_WS_MAX_MESSAGE_SIZE || '1048576'), // 1MB
} as const;

// Authentication Configuration
export const authConfig = {
  tokenKey: 'isectech_auth_token',
  refreshTokenKey: 'isectech_refresh_token',
  sessionKey: 'isectech_session',
  tokenExpiry: parseInt(process.env.NEXT_PUBLIC_TOKEN_EXPIRY || '3600'), // 1 hour
  refreshTokenExpiry: parseInt(process.env.NEXT_PUBLIC_REFRESH_TOKEN_EXPIRY || '604800'), // 7 days
  sessionTimeout: parseInt(process.env.NEXT_PUBLIC_SESSION_TIMEOUT || '1800'), // 30 minutes
  maxLoginAttempts: parseInt(process.env.NEXT_PUBLIC_MAX_LOGIN_ATTEMPTS || '5'),
  lockoutDuration: parseInt(process.env.NEXT_PUBLIC_LOCKOUT_DURATION || '900'), // 15 minutes
  mfaCodeLength: parseInt(process.env.NEXT_PUBLIC_MFA_CODE_LENGTH || '6'),
  mfaCodeExpiry: parseInt(process.env.NEXT_PUBLIC_MFA_CODE_EXPIRY || '300'), // 5 minutes
  rememberMeDuration: parseInt(process.env.NEXT_PUBLIC_REMEMBER_ME_DURATION || '2592000'), // 30 days
} as const;

// Security Configuration
export const securityConfig = {
  encryption: {
    algorithm: 'AES-256-GCM',
    keyLength: 32,
    ivLength: 16,
    tagLength: 16,
  },
  password: {
    minLength: parseInt(process.env.NEXT_PUBLIC_PASSWORD_MIN_LENGTH || '12'),
    maxLength: parseInt(process.env.NEXT_PUBLIC_PASSWORD_MAX_LENGTH || '128'),
    requireUppercase: process.env.NEXT_PUBLIC_PASSWORD_REQUIRE_UPPERCASE !== 'false',
    requireLowercase: process.env.NEXT_PUBLIC_PASSWORD_REQUIRE_LOWERCASE !== 'false',
    requireNumbers: process.env.NEXT_PUBLIC_PASSWORD_REQUIRE_NUMBERS !== 'false',
    requireSpecialChars: process.env.NEXT_PUBLIC_PASSWORD_REQUIRE_SPECIAL !== 'false',
    maxConsecutive: parseInt(process.env.NEXT_PUBLIC_PASSWORD_MAX_CONSECUTIVE || '3'),
    historyCount: parseInt(process.env.NEXT_PUBLIC_PASSWORD_HISTORY_COUNT || '12'),
    maxAge: parseInt(process.env.NEXT_PUBLIC_PASSWORD_MAX_AGE || '90'), // days
  },
  session: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax' as const,
    maxAge: authConfig.sessionTimeout * 1000,
  },
  csp: {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
    'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com'],
    'img-src': ["'self'", 'data:', 'https:'],
    'connect-src': ["'self'", apiConfig.baseUrl],
    'frame-ancestors': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
  },
} as const;

// Application Configuration
export const appConfig = {
  name: 'iSECTECH Protect',
  version: process.env.NEXT_PUBLIC_APP_VERSION || '1.0.0',
  description: 'Enterprise Cybersecurity Command Center',
  author: 'iSECTECH',
  supportEmail: process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'support@isectech.org',
  documentationUrl: process.env.NEXT_PUBLIC_DOCS_URL || 'https://docs.isectech.org',
  statusPageUrl: process.env.NEXT_PUBLIC_STATUS_URL || 'https://status.isectech.org',
  defaultTimezone: process.env.NEXT_PUBLIC_DEFAULT_TIMEZONE || 'UTC',
  defaultLanguage: process.env.NEXT_PUBLIC_DEFAULT_LANGUAGE || 'en',
  defaultTheme: (process.env.NEXT_PUBLIC_DEFAULT_THEME as 'light' | 'dark' | 'auto') || 'auto',
  maxFileUploadSize: parseInt(process.env.NEXT_PUBLIC_MAX_FILE_SIZE || '52428800'), // 50MB
  allowedFileTypes: (process.env.NEXT_PUBLIC_ALLOWED_FILE_TYPES || 'pdf,doc,docx,xls,xlsx,csv,txt,png,jpg,jpeg').split(','),
} as const;

// Dashboard Configuration
export const dashboardConfig = {
  refreshInterval: parseInt(process.env.NEXT_PUBLIC_DASHBOARD_REFRESH || '30000'), // 30 seconds
  alertRefreshInterval: parseInt(process.env.NEXT_PUBLIC_ALERT_REFRESH || '5000'), // 5 seconds
  maxAlertItems: parseInt(process.env.NEXT_PUBLIC_MAX_ALERT_ITEMS || '100'),
  maxEventItems: parseInt(process.env.NEXT_PUBLIC_MAX_EVENT_ITEMS || '1000'),
  defaultDateRange: parseInt(process.env.NEXT_PUBLIC_DEFAULT_DATE_RANGE || '24'), // hours
  chartAnimationDuration: parseInt(process.env.NEXT_PUBLIC_CHART_ANIMATION || '300'),
  tablePageSize: parseInt(process.env.NEXT_PUBLIC_TABLE_PAGE_SIZE || '25'),
  virtualScrollThreshold: parseInt(process.env.NEXT_PUBLIC_VIRTUAL_SCROLL || '100'),
} as const;

// Feature Flags
export const featureFlags = {
  enableAnalytics: process.env.NEXT_PUBLIC_ENABLE_ANALYTICS === 'true',
  enableTelemetry: process.env.NEXT_PUBLIC_ENABLE_TELEMETRY === 'true',
  enableDebugMode: process.env.NEXT_PUBLIC_ENABLE_DEBUG === 'true' || isDevelopment,
  enableDevTools: process.env.NEXT_PUBLIC_ENABLE_DEVTOOLS === 'true' || isDevelopment,
  enableMockData: process.env.NEXT_PUBLIC_ENABLE_MOCK_DATA === 'true' || isDevelopment,
  enableExperimentalFeatures: process.env.NEXT_PUBLIC_ENABLE_EXPERIMENTAL === 'true',
  enableOfflineMode: process.env.NEXT_PUBLIC_ENABLE_OFFLINE === 'true',
  enableServiceWorker: process.env.NEXT_PUBLIC_ENABLE_SW === 'true' && isProduction,
  enableMfa: process.env.NEXT_PUBLIC_ENABLE_MFA !== 'false',
  enableSso: process.env.NEXT_PUBLIC_ENABLE_SSO === 'true',
  enableWhiteLabeling: process.env.NEXT_PUBLIC_ENABLE_WHITE_LABEL === 'true',
  enableAdvancedAnalytics: process.env.NEXT_PUBLIC_ENABLE_ADVANCED_ANALYTICS === 'true',
  enableThreatIntelligence: process.env.NEXT_PUBLIC_ENABLE_THREAT_INTEL === 'true',
  enableComplianceAutomation: process.env.NEXT_PUBLIC_ENABLE_COMPLIANCE_AUTO === 'true',
  enableRealtimeNotifications: process.env.NEXT_PUBLIC_ENABLE_REALTIME_NOTIFICATIONS !== 'false',
} as const;

// Performance Configuration
export const performanceConfig = {
  enablePerfMonitoring: process.env.NEXT_PUBLIC_ENABLE_PERF_MONITORING === 'true',
  enableErrorBoundary: process.env.NEXT_PUBLIC_ENABLE_ERROR_BOUNDARY !== 'false',
  enableVirtualization: process.env.NEXT_PUBLIC_ENABLE_VIRTUALIZATION !== 'false',
  enableLazyLoading: process.env.NEXT_PUBLIC_ENABLE_LAZY_LOADING !== 'false',
  enableCodeSplitting: process.env.NEXT_PUBLIC_ENABLE_CODE_SPLITTING !== 'false',
  enableImageOptimization: process.env.NEXT_PUBLIC_ENABLE_IMAGE_OPT !== 'false',
  bundleAnalysis: process.env.ANALYZE === 'true',
  chunkSize: {
    maxInitial: parseInt(process.env.NEXT_PUBLIC_MAX_INITIAL_CHUNK || '512000'), // 500KB
    maxAsync: parseInt(process.env.NEXT_PUBLIC_MAX_ASYNC_CHUNK || '1048576'), // 1MB
  },
} as const;

// Monitoring and Logging
export const monitoringConfig = {
  enableLogging: process.env.NEXT_PUBLIC_ENABLE_LOGGING !== 'false',
  logLevel: (process.env.NEXT_PUBLIC_LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error') || (isDevelopment ? 'debug' : 'warn'),
  enableConsoleLogging: process.env.NEXT_PUBLIC_ENABLE_CONSOLE_LOG !== 'false' || isDevelopment,
  enableRemoteLogging: process.env.NEXT_PUBLIC_ENABLE_REMOTE_LOG === 'true',
  sentryDsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  enableSentry: !!process.env.NEXT_PUBLIC_SENTRY_DSN,
  enableMetrics: process.env.NEXT_PUBLIC_ENABLE_METRICS === 'true',
  metricsEndpoint: process.env.NEXT_PUBLIC_METRICS_ENDPOINT,
} as const;

// Accessibility Configuration
export const a11yConfig = {
  enableScreenReaderSupport: process.env.NEXT_PUBLIC_ENABLE_SCREEN_READER !== 'false',
  enableKeyboardNavigation: process.env.NEXT_PUBLIC_ENABLE_KEYBOARD_NAV !== 'false',
  enableHighContrast: process.env.NEXT_PUBLIC_ENABLE_HIGH_CONTRAST === 'true',
  enableReducedMotion: process.env.NEXT_PUBLIC_ENABLE_REDUCED_MOTION === 'true',
  focusRingStyle: process.env.NEXT_PUBLIC_FOCUS_RING_STYLE || 'outline',
  announcePageChanges: process.env.NEXT_PUBLIC_ANNOUNCE_PAGE_CHANGES !== 'false',
} as const;

// Cache Configuration
export const cacheConfig = {
  enableServiceWorkerCache: process.env.NEXT_PUBLIC_ENABLE_SW_CACHE === 'true' && isProduction,
  enableQueryCache: process.env.NEXT_PUBLIC_ENABLE_QUERY_CACHE !== 'false',
  queryCacheTime: parseInt(process.env.NEXT_PUBLIC_QUERY_CACHE_TIME || '300000'), // 5 minutes
  staleTime: parseInt(process.env.NEXT_PUBLIC_STALE_TIME || '60000'), // 1 minute
  maxCacheSize: parseInt(process.env.NEXT_PUBLIC_MAX_CACHE_SIZE || '52428800'), // 50MB
  staticAssetCacheDuration: parseInt(process.env.NEXT_PUBLIC_STATIC_CACHE_DURATION || '86400'), // 24 hours
} as const;

// Validation
function validateConfig() {
  const errors: string[] = [];

  if (!apiConfig.baseUrl) {
    errors.push('NEXT_PUBLIC_API_URL is required');
  }

  if (authConfig.tokenExpiry < 300) {
    errors.push('Token expiry must be at least 5 minutes');
  }

  if (securityConfig.password.minLength < 8) {
    errors.push('Password minimum length must be at least 8 characters');
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
  }
}

// Validate configuration on import
if (typeof window === 'undefined') {
  validateConfig();
}

// Export configuration object
export const config = {
  env,
  isDevelopment,
  isProduction,
  isStaging,
  isTest,
  api: apiConfig,
  websocket: websocketConfig,
  auth: authConfig,
  security: securityConfig,
  app: appConfig,
  dashboard: dashboardConfig,
  features: featureFlags,
  performance: performanceConfig,
  monitoring: monitoringConfig,
  a11y: a11yConfig,
  cache: cacheConfig,
} as const;

export default config;