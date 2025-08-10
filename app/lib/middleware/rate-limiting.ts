/**
 * Rate Limiting Middleware for iSECTECH Enterprise Security Platform
 * Provides configurable rate limiting for API endpoints
 */

import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';

interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per window
  keyGenerator?: (req: NextRequest) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  onLimitReached?: (req: NextRequest) => void;
}

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

// In-memory store for rate limiting (in production, use Redis or similar)
const rateLimitStore: RateLimitStore = {};

// Default rate limit configurations for different endpoint types
export const RATE_LIMIT_CONFIGS = {
  api: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
  },
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5, // Strict limit for auth endpoints
  },
  compliance: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 30,
  },
  executive: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 50,
  }
} as const;

/**
 * Default key generator - uses IP address and user agent
 */
const defaultKeyGenerator = (req: NextRequest): string => {
  const forwarded = req.headers.get('x-forwarded-for');
  const ip = forwarded ? forwarded.split(',')[0] : 
    req.headers.get('x-real-ip') || 
    'unknown';
  const userAgent = req.headers.get('user-agent') || 'unknown';
  return `${ip}:${userAgent.slice(0, 50)}`;
};

/**
 * Clean up expired entries from the rate limit store
 */
const cleanupStore = () => {
  const now = Date.now();
  Object.keys(rateLimitStore).forEach(key => {
    if (rateLimitStore[key].resetTime < now) {
      delete rateLimitStore[key];
    }
  });
};

/**
 * Rate limiting middleware function
 */
export function rateLimit(config: RateLimitConfig) {
  return async (req: NextRequest): Promise<NextResponse | null> => {
    const {
      windowMs,
      maxRequests,
      keyGenerator = defaultKeyGenerator,
      skipSuccessfulRequests = false,
      skipFailedRequests = false,
      onLimitReached
    } = config;

    // Clean up expired entries periodically
    if (Math.random() < 0.01) { // 1% chance on each request
      cleanupStore();
    }

    const key = keyGenerator(req);
    const now = Date.now();
    const resetTime = now + windowMs;

    // Get current rate limit data
    let rateLimitData = rateLimitStore[key];

    if (!rateLimitData || rateLimitData.resetTime < now) {
      // Create new or reset expired entry
      rateLimitData = {
        count: 0,
        resetTime
      };
      rateLimitStore[key] = rateLimitData;
    }

    // Check if limit exceeded
    if (rateLimitData.count >= maxRequests) {
      if (onLimitReached) {
        onLimitReached(req);
      }

      const resetTimeSeconds = Math.ceil((rateLimitData.resetTime - now) / 1000);
      
      return NextResponse.json(
        {
          success: false,
          error: 'Rate limit exceeded',
          message: `Too many requests. Try again in ${resetTimeSeconds} seconds.`,
          retryAfter: resetTimeSeconds
        },
        { 
          status: 429,
          headers: {
            'X-RateLimit-Limit': maxRequests.toString(),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': rateLimitData.resetTime.toString(),
            'Retry-After': resetTimeSeconds.toString()
          }
        }
      );
    }

    // Increment counter
    rateLimitData.count++;

    // Add rate limit headers to response (will be handled by calling function)
    return null; // Allow request to continue
  };
}

/**
 * Rate limiting middleware for API routes
 */
export const apiRateLimit = rateLimit(RATE_LIMIT_CONFIGS.api);

/**
 * Rate limiting middleware for authentication routes
 */
export const authRateLimit = rateLimit(RATE_LIMIT_CONFIGS.auth);

/**
 * Rate limiting middleware for compliance routes
 */
export const complianceRateLimit = rateLimit(RATE_LIMIT_CONFIGS.compliance);

/**
 * Rate limiting middleware for executive routes
 */
export const executiveRateLimit = rateLimit(RATE_LIMIT_CONFIGS.executive);

/**
 * Custom rate limiter for tenant-specific limits
 */
export const tenantRateLimit = (tenantId: string, customConfig?: Partial<RateLimitConfig>) => {
  const config: RateLimitConfig = {
    ...RATE_LIMIT_CONFIGS.api,
    ...customConfig,
    keyGenerator: (req: NextRequest) => {
      const baseKey = defaultKeyGenerator(req);
      return `tenant:${tenantId}:${baseKey}`;
    }
  };
  
  return rateLimit(config);
};

/**
 * Helper to get rate limit status for a key
 */
export const getRateLimitStatus = (key: string) => {
  const rateLimitData = rateLimitStore[key];
  if (!rateLimitData) {
    return {
      count: 0,
      remaining: Infinity,
      resetTime: null
    };
  }

  return {
    count: rateLimitData.count,
    remaining: Math.max(0, RATE_LIMIT_CONFIGS.api.maxRequests - rateLimitData.count),
    resetTime: rateLimitData.resetTime
  };
};

export default rateLimit;