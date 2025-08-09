/**
 * iSECTECH Frontend - Health Check API Endpoint
 * Comprehensive health monitoring for Cloud Run and Kubernetes
 * Author: Claude Code - iSECTECH Infrastructure Team
 * Version: 2.0.0
 */

import { NextRequest, NextResponse } from 'next/server';

interface HealthCheck {
  timestamp: string;
  service: string;
  version: string;
  environment: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  checks: {
    [key: string]: {
      status: 'ok' | 'warning' | 'error';
      message?: string;
      duration?: number;
      lastCheck?: string;
    };
  };
  build?: {
    date?: string;
    version?: string;
    commit?: string;
  };
  system?: {
    memory?: {
      used: number;
      total: number;
      percentage: number;
    };
    cpu?: {
      usage: number;
    };
    disk?: {
      usage: number;
    };
  };
}

// Cache health check results for 30 seconds
let cachedHealthCheck: HealthCheck | null = null;
let lastHealthCheckTime = 0;
const HEALTH_CHECK_CACHE_TTL = 30 * 1000; // 30 seconds

// Service start time for uptime calculation
const SERVICE_START_TIME = Date.now();

/**
 * Performs comprehensive health checks
 */
async function performHealthChecks(): Promise<HealthCheck> {
  const startTime = Date.now();
  const checks: HealthCheck['checks'] = {};
  let overallStatus: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

  // 1. Basic service health
  checks.service = {
    status: 'ok',
    message: 'Service is running',
    duration: 0,
    lastCheck: new Date().toISOString(),
  };

  // 2. Environment configuration check
  try {
    const requiredEnvVars = [
      'NODE_ENV',
      'NEXT_PUBLIC_API_URL',
    ];

    const missingVars = requiredEnvVars.filter(
      (varName) => !process.env[varName]
    );

    if (missingVars.length > 0) {
      checks.environment = {
        status: 'warning',
        message: `Missing environment variables: ${missingVars.join(', ')}`,
        lastCheck: new Date().toISOString(),
      };
      if (overallStatus === 'healthy') overallStatus = 'degraded';
    } else {
      checks.environment = {
        status: 'ok',
        message: 'All required environment variables are set',
        lastCheck: new Date().toISOString(),
      };
    }
  } catch (error) {
    checks.environment = {
      status: 'error',
      message: `Environment check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      lastCheck: new Date().toISOString(),
    };
    overallStatus = 'unhealthy';
  }

  // 3. Memory usage check
  try {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memUsage = process.memoryUsage();
      const totalMemory = memUsage.heapTotal + memUsage.external;
      const usedMemory = memUsage.heapUsed;
      const memoryPercentage = (usedMemory / totalMemory) * 100;

      if (memoryPercentage > 90) {
        checks.memory = {
          status: 'error',
          message: `High memory usage: ${memoryPercentage.toFixed(1)}%`,
          lastCheck: new Date().toISOString(),
        };
        overallStatus = 'unhealthy';
      } else if (memoryPercentage > 75) {
        checks.memory = {
          status: 'warning',
          message: `Elevated memory usage: ${memoryPercentage.toFixed(1)}%`,
          lastCheck: new Date().toISOString(),
        };
        if (overallStatus === 'healthy') overallStatus = 'degraded';
      } else {
        checks.memory = {
          status: 'ok',
          message: `Memory usage: ${memoryPercentage.toFixed(1)}%`,
          lastCheck: new Date().toISOString(),
        };
      }
    } else {
      checks.memory = {
        status: 'warning',
        message: 'Memory usage information not available',
        lastCheck: new Date().toISOString(),
      };
    }
  } catch (error) {
    checks.memory = {
      status: 'error',
      message: `Memory check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      lastCheck: new Date().toISOString(),
    };
    if (overallStatus !== 'unhealthy') overallStatus = 'degraded';
  }

  // 4. API connectivity check (if enabled)
  if (process.env.HEALTH_CHECK_API_ENABLED === 'true') {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      if (apiUrl) {
        const apiCheckStart = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

        try {
          const response = await fetch(`${apiUrl}/health`, {
            method: 'GET',
            headers: {
              'User-Agent': 'iSECTECH-Frontend-HealthCheck/2.0.0',
              'Accept': 'application/json',
            },
            signal: controller.signal,
          });

          clearTimeout(timeoutId);
          const apiCheckDuration = Date.now() - apiCheckStart;

          if (response.ok) {
            checks.api = {
              status: 'ok',
              message: `API is reachable (${response.status})`,
              duration: apiCheckDuration,
              lastCheck: new Date().toISOString(),
            };
          } else {
            checks.api = {
              status: 'warning',
              message: `API returned ${response.status}`,
              duration: apiCheckDuration,
              lastCheck: new Date().toISOString(),
            };
            if (overallStatus === 'healthy') overallStatus = 'degraded';
          }
        } catch (fetchError) {
          clearTimeout(timeoutId);
          checks.api = {
            status: 'error',
            message: fetchError instanceof Error ? fetchError.message : 'API check failed',
            duration: Date.now() - apiCheckStart,
            lastCheck: new Date().toISOString(),
          };
          if (overallStatus !== 'unhealthy') overallStatus = 'degraded';
        }
      } else {
        checks.api = {
          status: 'warning',
          message: 'API URL not configured',
          lastCheck: new Date().toISOString(),
        };
      }
    } catch (error) {
      checks.api = {
        status: 'error',
        message: `API connectivity check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        lastCheck: new Date().toISOString(),
      };
      if (overallStatus !== 'unhealthy') overallStatus = 'degraded';
    }
  }

  // 5. Security configuration check
  try {
    const securityChecks = [];
    
    if (process.env.NODE_ENV === 'production') {
      if (process.env.NEXTAUTH_SECRET) {
        securityChecks.push('✓ NextAuth secret configured');
      } else {
        securityChecks.push('✗ NextAuth secret missing');
        overallStatus = 'unhealthy';
      }

      if (process.env.SECURITY_HEADERS_ENABLED === 'true') {
        securityChecks.push('✓ Security headers enabled');
      } else {
        securityChecks.push('⚠ Security headers disabled');
        if (overallStatus === 'healthy') overallStatus = 'degraded';
      }

      if (process.env.CSP_ENABLED === 'true') {
        securityChecks.push('✓ Content Security Policy enabled');
      } else {
        securityChecks.push('⚠ CSP disabled');
      }
    }

    checks.security = {
      status: overallStatus === 'unhealthy' ? 'error' : 
             overallStatus === 'degraded' ? 'warning' : 'ok',
      message: securityChecks.join(', '),
      lastCheck: new Date().toISOString(),
    };
  } catch (error) {
    checks.security = {
      status: 'error',
      message: `Security check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      lastCheck: new Date().toISOString(),
    };
    overallStatus = 'unhealthy';
  }

  const totalDuration = Date.now() - startTime;

  // Build system information
  let systemInfo: HealthCheck['system'] | undefined;
  try {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memUsage = process.memoryUsage();
      systemInfo = {
        memory: {
          used: memUsage.heapUsed,
          total: memUsage.heapTotal,
          percentage: (memUsage.heapUsed / memUsage.heapTotal) * 100,
        },
        cpu: {
          usage: process.cpuUsage ? 
            (process.cpuUsage().user + process.cpuUsage().system) / 1000000 : 0,
        },
      };
    }
  } catch (error) {
    // System info is optional, don't fail health check
  }

  return {
    timestamp: new Date().toISOString(),
    service: 'isectech-frontend',
    version: process.env.NEXT_PUBLIC_BUILD_VERSION || '2.0.0',
    environment: process.env.NODE_ENV || 'development',
    status: overallStatus,
    uptime: Date.now() - SERVICE_START_TIME,
    checks,
    build: {
      date: process.env.NEXT_PUBLIC_BUILD_DATE,
      version: process.env.NEXT_PUBLIC_BUILD_VERSION || '2.0.0',
      commit: process.env.NEXT_PUBLIC_BUILD_COMMIT,
    },
    system: systemInfo,
  };
}

/**
 * GET /api/health - Comprehensive health check endpoint
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const now = Date.now();
    const userAgent = request.headers.get('user-agent') || '';
    
    // Use cached result if available and fresh
    if (cachedHealthCheck && (now - lastHealthCheckTime) < HEALTH_CHECK_CACHE_TTL) {
      const status = cachedHealthCheck.status === 'healthy' ? 200 :
                    cachedHealthCheck.status === 'degraded' ? 200 : 503;
      
      return NextResponse.json(cachedHealthCheck, { 
        status,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0',
          'Content-Type': 'application/json',
        },
      });
    }

    // Perform fresh health check
    const healthCheck = await performHealthChecks();
    
    // Cache the result
    cachedHealthCheck = healthCheck;
    lastHealthCheckTime = now;

    // Determine HTTP status code based on health status
    const status = healthCheck.status === 'healthy' ? 200 :
                  healthCheck.status === 'degraded' ? 200 : 503;

    // Add performance timing
    healthCheck.checks.overall = {
      status: healthCheck.status === 'healthy' ? 'ok' : 
              healthCheck.status === 'degraded' ? 'warning' : 'error',
      message: `Health check completed in ${Date.now() - now}ms`,
      duration: Date.now() - now,
      lastCheck: new Date().toISOString(),
    };

    // Log health check for monitoring (in production)
    if (process.env.NODE_ENV === 'production' && healthCheck.status !== 'healthy') {
      console.warn('Health check warning/error:', {
        status: healthCheck.status,
        checks: Object.entries(healthCheck.checks)
          .filter(([_, check]) => check.status !== 'ok')
          .reduce((acc, [key, check]) => ({ ...acc, [key]: check }), {}),
        timestamp: healthCheck.timestamp,
        service: healthCheck.service,
        userAgent: userAgent.substring(0, 100), // Truncate for security
      });
    }

    return NextResponse.json(healthCheck, { 
      status,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Content-Type': 'application/json',
        'X-Health-Check-Duration': `${Date.now() - now}ms`,
        'X-Service-Version': healthCheck.version,
      },
    });

  } catch (error) {
    // Fallback error response
    const errorResponse: HealthCheck = {
      timestamp: new Date().toISOString(),
      service: 'isectech-frontend',
      version: process.env.NEXT_PUBLIC_BUILD_VERSION || '2.0.0',
      environment: process.env.NODE_ENV || 'development',
      status: 'unhealthy',
      uptime: Date.now() - SERVICE_START_TIME,
      checks: {
        error: {
          status: 'error',
          message: error instanceof Error ? error.message : 'Unknown health check error',
          lastCheck: new Date().toISOString(),
        },
      },
      build: {
        date: process.env.NEXT_PUBLIC_BUILD_DATE,
        version: process.env.NEXT_PUBLIC_BUILD_VERSION || '2.0.0',
        commit: process.env.NEXT_PUBLIC_BUILD_COMMIT,
      },
    };

    // Log the error
    console.error('Health check failed:', error);

    return NextResponse.json(errorResponse, { 
      status: 503,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Content-Type': 'application/json',
      },
    });
  }
}

/**
 * HEAD /api/health - Lightweight health check for load balancers
 */
export async function HEAD(): Promise<NextResponse> {
  try {
    // Simple check without detailed analysis for load balancers
    const isHealthy = true; // Basic service availability
    
    return new NextResponse(null, {
      status: isHealthy ? 200 : 503,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Service-Name': 'isectech-frontend',
        'X-Service-Version': process.env.NEXT_PUBLIC_BUILD_VERSION || '2.0.0',
        'X-Health-Status': isHealthy ? 'healthy' : 'unhealthy',
      },
    });
  } catch (error) {
    return new NextResponse(null, {
      status: 503,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Health-Status': 'error',
      },
    });
  }
}