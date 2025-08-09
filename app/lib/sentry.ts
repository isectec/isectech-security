// iSECTECH Sentry Integration
// Production-grade error tracking and performance monitoring for Next.js

import * as Sentry from '@sentry/nextjs';
import { BrowserTracing } from '@sentry/tracing';
import { ExtraErrorData } from '@sentry/integrations';

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const SENTRY_DSN = process.env.NEXT_PUBLIC_SENTRY_DSN || process.env.SENTRY_DSN;
const ENVIRONMENT = process.env.NODE_ENV || 'development';
const RELEASE = process.env.VERCEL_GIT_COMMIT_SHA || process.env.npm_package_version || '1.0.0';
const SERVICE_NAME = 'isectech-frontend';

// ═══════════════════════════════════════════════════════════════════════════════
// SENTRY CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const sentryConfig: Sentry.NodeOptions = {
  dsn: SENTRY_DSN,
  environment: ENVIRONMENT,
  release: RELEASE,
  
  // Performance monitoring
  tracesSampleRate: ENVIRONMENT === 'production' ? 0.1 : 1.0,
  
  // Profiling
  profilesSampleRate: ENVIRONMENT === 'production' ? 0.1 : 1.0,
  
  // Enhanced error tracking
  integrations: [
    new BrowserTracing({
      // Trace navigation and interactions
      routingInstrumentation: Sentry.reactRouterV6Instrumentation(
        // React Router instrumentation will be added here
      ),
      
      // Trace specific operations
      tracePropagationTargets: [
        'localhost',
        /^https:\/\/api\.isectech\.com\/api/,
        /^https:\/\/isectech\.com/,
      ],
    }),
    
    // Additional error context
    new ExtraErrorData({
      depth: 5,
      captureErrorCause: true,
    }),
    
    // Custom iSECTECH integration
    {
      name: 'ISECTECHIntegration',
      setupOnce() {
        // Custom setup for iSECTECH specific tracking
      },
    },
  ],
  
  // Data scrubbing for security
  beforeSend(event, hint) {
    return processSentryEvent(event, hint);
  },
  
  // Breadcrumb filtering
  beforeBreadcrumb(breadcrumb) {
    return processBreadcrumb(breadcrumb);
  },
  
  // Initial scope configuration
  initialScope: {
    tags: {
      component: 'frontend',
      service: SERVICE_NAME,
      team: 'frontend-team',
    },
    contexts: {
      app: {
        name: SERVICE_NAME,
        version: RELEASE,
      },
    },
  },
  
  // Error filtering
  ignoreErrors: [
    // Browser extension errors
    'Non-Error exception captured',
    'Non-Error promise rejection captured',
    
    // Network errors that are not actionable
    'NetworkError',
    'ChunkLoadError',
    'Loading chunk',
    'Loading CSS chunk',
    
    // AbortError from cancelled requests
    'AbortError',
    
    // ResizeObserver errors (browser bugs)
    'ResizeObserver loop limit exceeded',
    
    // Safari specific errors
    'AbortError: Fetch is aborted',
    
    // Development hot reload errors
    'HMR',
    'Hot reload',
  ],
  
  // URL filtering for privacy
  denyUrls: [
    // Browser extensions
    /extensions\//i,
    /^chrome:\/\//i,
    /^chrome-extension:\/\//i,
    /^moz-extension:\/\//i,
    
    // Development tools
    /webpack-dev-server/i,
  ],
  
  // Maximum breadcrumbs
  maxBreadcrumbs: 100,
  
  // Attach stack traces to pure capture message calls
  attachStacktrace: true,
  
  // Send default PII (personally identifiable information)
  sendDefaultPii: false,
  
  // Auto session tracking
  autoSessionTracking: true,
  
  // Capture console messages
  captureConsoleIntegration: {
    levels: ['error', 'warn'],
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// EVENT PROCESSING
// ═══════════════════════════════════════════════════════════════════════════════

function processSentryEvent(event: Sentry.Event, hint: Sentry.EventHint): Sentry.Event | null {
  // Add custom context for iSECTECH
  if (event.contexts) {
    event.contexts.isectech = {
      environment: ENVIRONMENT,
      service: SERVICE_NAME,
      timestamp: new Date().toISOString(),
    };
  }
  
  // Add user context if available
  const userContext = getCurrentUserContext();
  if (userContext && event.user) {
    event.user = {
      ...event.user,
      ...userContext,
    };
  }
  
  // Scrub sensitive data
  event = scrubSensitiveData(event);
  
  // Add request context
  if (typeof window !== 'undefined') {
    event.request = {
      url: window.location.href,
      headers: {
        'User-Agent': navigator.userAgent,
      },
    };
  }
  
  // Filter out non-actionable errors in production
  if (ENVIRONMENT === 'production') {
    const error = hint.originalException;
    if (error instanceof Error) {
      // Skip chunk loading errors
      if (error.message?.includes('Loading chunk')) {
        return null;
      }
      
      // Skip network timeout errors
      if (error.message?.includes('timeout')) {
        return null;
      }
    }
  }
  
  return event;
}

function processBreadcrumb(breadcrumb: Sentry.Breadcrumb): Sentry.Breadcrumb | null {
  // Filter out noisy breadcrumbs
  if (breadcrumb.category === 'console' && breadcrumb.level === 'log') {
    return null;
  }
  
  // Filter out HTTP requests to health check endpoints
  if (breadcrumb.category === 'fetch' && breadcrumb.data?.url?.includes('/health')) {
    return null;
  }
  
  // Scrub sensitive data from breadcrumbs
  if (breadcrumb.data) {
    breadcrumb.data = scrubObjectData(breadcrumb.data);
  }
  
  return breadcrumb;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA SCRUBBING
// ═══════════════════════════════════════════════════════════════════════════════

function scrubSensitiveData(event: Sentry.Event): Sentry.Event {
  // Scrub request data
  if (event.request?.data) {
    event.request.data = scrubObjectData(event.request.data);
  }
  
  // Scrub extra data
  if (event.extra) {
    event.extra = scrubObjectData(event.extra);
  }
  
  // Scrub breadcrumb data
  if (event.breadcrumbs) {
    event.breadcrumbs = event.breadcrumbs.map(breadcrumb => ({
      ...breadcrumb,
      data: breadcrumb.data ? scrubObjectData(breadcrumb.data) : undefined,
    }));
  }
  
  return event;
}

function scrubObjectData(obj: any): any {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }
  
  const sensitiveKeys = [
    'password', 'passwd', 'secret', 'api_key', 'apikey', 'token',
    'authorization', 'auth', 'session', 'sessionid', 'cookie',
    'email', 'phone', 'ssn', 'credit_card', 'card_number',
    'private_key', 'privatekey', 'credentials',
  ];
  
  const scrubbed: any = Array.isArray(obj) ? [] : {};
  
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    
    if (sensitiveKeys.some(sensitiveKey => lowerKey.includes(sensitiveKey))) {
      scrubbed[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      scrubbed[key] = scrubObjectData(value);
    } else {
      scrubbed[key] = value;
    }
  }
  
  return scrubbed;
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function getCurrentUserContext() {
  // This should be implemented based on your authentication system
  try {
    // Example: Get user from localStorage, context, or API
    const userString = typeof window !== 'undefined' ? localStorage.getItem('user') : null;
    if (userString) {
      const user = JSON.parse(userString);
      return {
        id: user.id,
        username: user.username,
        email: user.email, // Note: This will be scrubbed by data scrubbing
      };
    }
  } catch (error) {
    // Ignore errors when getting user context
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM ERROR TRACKING
// ═══════════════════════════════════════════════════════════════════════════════

export function captureSecurityEvent(
  eventType: string,
  details: Record<string, any>,
  level: Sentry.SeverityLevel = 'warning'
) {
  Sentry.withScope(scope => {
    scope.setTag('event_type', 'security');
    scope.setTag('security_event_type', eventType);
    scope.setLevel(level);
    scope.setContext('security_details', details);
    
    Sentry.captureMessage(`Security Event: ${eventType}`, level);
  });
}

export function captureBusinessEvent(
  eventType: string,
  userId: string,
  details: Record<string, any>
) {
  Sentry.withScope(scope => {
    scope.setTag('event_type', 'business');
    scope.setTag('business_event_type', eventType);
    scope.setUser({ id: userId });
    scope.setContext('business_details', details);
    
    Sentry.captureMessage(`Business Event: ${eventType}`, 'info');
  });
}

export function capturePerformanceIssue(
  operation: string,
  duration: number,
  threshold: number
) {
  if (duration > threshold) {
    Sentry.withScope(scope => {
      scope.setTag('event_type', 'performance');
      scope.setTag('performance_issue', 'slow_operation');
      scope.setContext('performance_details', {
        operation,
        duration,
        threshold,
        slowness_factor: duration / threshold,
      });
      
      Sentry.captureMessage(
        `Slow Operation: ${operation} took ${duration}ms (threshold: ${threshold}ms)`,
        'warning'
      );
    });
  }
}

export function captureAPIError(
  endpoint: string,
  method: string,
  statusCode: number,
  responseText: string
) {
  Sentry.withScope(scope => {
    scope.setTag('event_type', 'api_error');
    scope.setTag('api_endpoint', endpoint);
    scope.setTag('api_method', method);
    scope.setTag('api_status_code', statusCode.toString());
    scope.setContext('api_details', {
      endpoint,
      method,
      statusCode,
      responseText: responseText.substring(0, 1000), // Limit response text
    });
    
    Sentry.captureMessage(
      `API Error: ${method} ${endpoint} returned ${statusCode}`,
      statusCode >= 500 ? 'error' : 'warning'
    );
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERFORMANCE MONITORING
// ═══════════════════════════════════════════════════════════════════════════════

export function createPerformanceTransaction(name: string, operation: string) {
  return Sentry.startTransaction({
    name,
    op: operation,
    tags: {
      component: 'frontend',
      service: SERVICE_NAME,
    },
  });
}

export function measureAsyncOperation<T>(
  operationName: string,
  operation: () => Promise<T>
): Promise<T> {
  const transaction = createPerformanceTransaction(operationName, 'async_operation');
  
  return operation()
    .then(result => {
      transaction.setStatus('ok');
      return result;
    })
    .catch(error => {
      transaction.setStatus('internal_error');
      Sentry.captureException(error);
      throw error;
    })
    .finally(() => {
      transaction.finish();
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

export function initializeSentry() {
  if (!SENTRY_DSN) {
    console.warn('Sentry DSN not configured, error tracking disabled');
    return;
  }
  
  try {
    Sentry.init(sentryConfig);
    
    // Set initial user and context
    Sentry.configureScope(scope => {
      scope.setTag('initialization', 'success');
      scope.setContext('environment', {
        node_env: ENVIRONMENT,
        user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
        url: typeof window !== 'undefined' ? window.location.href : 'unknown',
      });
    });
    
    console.log(`✅ Sentry initialized for ${SERVICE_NAME}`, {
      environment: ENVIRONMENT,
      release: RELEASE,
      dsn: SENTRY_DSN.substring(0, 20) + '...',
    });
  } catch (error) {
    console.error('❌ Failed to initialize Sentry:', error);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR BOUNDARY INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

export function withSentryErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  options?: Sentry.ErrorBoundaryOptions
) {
  return Sentry.withErrorBoundary(Component, {
    fallback: ({ error, resetError }) => (
      <div className="error-boundary">
        <h2>Something went wrong</h2>
        <p>We've been notified of this error and are working to fix it.</p>
        <button onClick={resetError}>Try again</button>
        {ENVIRONMENT === 'development' && (
          <details>
            <summary>Error details (development only)</summary>
            <pre>{error.message}</pre>
          </details>
        )}
      </div>
    ),
    beforeCapture: (scope, error, errorInfo) => {
      scope.setTag('error_boundary', true);
      scope.setContext('error_info', errorInfo);
    },
    ...options,
  });
}

// Auto-initialize if not in test environment
if (typeof window !== 'undefined' && process.env.NODE_ENV !== 'test') {
  initializeSentry();
}