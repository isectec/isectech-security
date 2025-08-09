import Redis from 'ioredis';
import axios from 'axios';
import { createHash } from 'crypto';

/**
 * Trust Score Integration Service
 * Provides secure integration between OPA and the trust scoring system
 */

interface TrustScoreRequest {
  userId: string;
  deviceId?: string;
  context: AccessContext;
}

interface AccessContext {
  ipAddress: string;
  userAgent: string;
  location?: GeoLocation;
  timestamp: number;
  sessionId: string;
  riskFactors?: string[];
}

interface GeoLocation {
  country: string;
  region: string;
  city: string;
  latitude?: number;
  longitude?: number;
}

interface TrustScoreResponse {
  trustScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: TrustFactor[];
  expiresAt: number;
  calculatedAt: number;
}

interface TrustFactor {
  type: string;
  impact: number;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

interface CachedTrustScore {
  score: number;
  riskLevel: string;
  factors: TrustFactor[];
  expiresAt: number;
  cacheKey: string;
}

export class TrustScoreIntegrationService {
  private redis: Redis;
  private trustScoreApiUrl: string;
  private apiToken: string;
  private cachePrefix = 'trust_score:';
  private defaultCacheTtl = 300; // 5 minutes
  private maxRetries = 3;
  private timeout = 5000; // 5 seconds

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true
    });

    this.trustScoreApiUrl = process.env.TRUST_SCORE_API_URL || 'http://trust-score-service:8080';
    this.apiToken = process.env.TRUST_SCORE_API_TOKEN || '';

    if (!this.apiToken) {
      throw new Error('TRUST_SCORE_API_TOKEN environment variable is required');
    }
  }

  /**
   * Get trust score with caching and fallback mechanisms
   */
  async getTrustScore(request: TrustScoreRequest): Promise<TrustScoreResponse> {
    const cacheKey = this.generateCacheKey(request);
    
    try {
      // Try to get from cache first
      const cached = await this.getCachedScore(cacheKey);
      if (cached && cached.expiresAt > Date.now()) {
        return {
          trustScore: cached.score,
          riskLevel: cached.riskLevel as any,
          factors: cached.factors,
          expiresAt: cached.expiresAt,
          calculatedAt: Date.now()
        };
      }

      // Fetch from trust score service
      const freshScore = await this.fetchTrustScore(request);
      
      // Cache the result
      await this.cacheScore(cacheKey, freshScore);
      
      return freshScore;
    } catch (error) {
      console.error('Error getting trust score:', error);
      
      // Try to return stale cache if available
      const staleScore = await this.getCachedScore(cacheKey);
      if (staleScore) {
        console.warn('Using stale trust score due to service error');
        return {
          trustScore: staleScore.score,
          riskLevel: staleScore.riskLevel as any,
          factors: staleScore.factors,
          expiresAt: Date.now() + 60000, // Extend by 1 minute
          calculatedAt: Date.now()
        };
      }

      // Fallback to default safe score
      return this.getDefaultTrustScore(request);
    }
  }

  /**
   * Batch get trust scores for multiple requests
   */
  async getBatchTrustScores(requests: TrustScoreRequest[]): Promise<Map<string, TrustScoreResponse>> {
    const results = new Map<string, TrustScoreResponse>();
    const uncachedRequests: TrustScoreRequest[] = [];
    const cacheKeys: string[] = [];

    // Check cache for all requests
    for (const request of requests) {
      const cacheKey = this.generateCacheKey(request);
      cacheKeys.push(cacheKey);
      
      const cached = await this.getCachedScore(cacheKey);
      if (cached && cached.expiresAt > Date.now()) {
        results.set(request.userId, {
          trustScore: cached.score,
          riskLevel: cached.riskLevel as any,
          factors: cached.factors,
          expiresAt: cached.expiresAt,
          calculatedAt: Date.now()
        });
      } else {
        uncachedRequests.push(request);
      }
    }

    // Batch fetch uncached scores
    if (uncachedRequests.length > 0) {
      try {
        const batchResponse = await this.fetchBatchTrustScores(uncachedRequests);
        
        for (const [userId, score] of batchResponse.entries()) {
          results.set(userId, score);
          
          // Cache the result
          const request = uncachedRequests.find(r => r.userId === userId);
          if (request) {
            const cacheKey = this.generateCacheKey(request);
            await this.cacheScore(cacheKey, score);
          }
        }
      } catch (error) {
        console.error('Error in batch trust score fetch:', error);
        
        // Fallback to default scores for uncached requests
        for (const request of uncachedRequests) {
          if (!results.has(request.userId)) {
            results.set(request.userId, this.getDefaultTrustScore(request));
          }
        }
      }
    }

    return results;
  }

  /**
   * Invalidate trust score cache for a user
   */
  async invalidateTrustScore(userId: string): Promise<void> {
    try {
      const pattern = `${this.cachePrefix}${userId}:*`;
      const keys = await this.redis.keys(pattern);
      
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    } catch (error) {
      console.error('Error invalidating trust score cache:', error);
    }
  }

  /**
   * Get trust score statistics
   */
  async getTrustScoreStats(): Promise<any> {
    try {
      const response = await axios.get(`${this.trustScoreApiUrl}/api/trust-score/stats`, {
        headers: {
          'Authorization': `Bearer ${this.apiToken}`,
          'Content-Type': 'application/json'
        },
        timeout: this.timeout
      });

      return response.data;
    } catch (error) {
      console.error('Error getting trust score stats:', error);
      throw error;
    }
  }

  /**
   * Generate cache key for trust score request
   */
  private generateCacheKey(request: TrustScoreRequest): string {
    const keyData = {
      userId: request.userId,
      deviceId: request.deviceId || 'unknown',
      ipAddress: request.context.ipAddress,
      timestamp: Math.floor(request.context.timestamp / 300000) // 5-minute buckets
    };
    
    const hash = createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex')
      .substring(0, 16);
    
    return `${this.cachePrefix}${request.userId}:${hash}`;
  }

  /**
   * Get cached trust score
   */
  private async getCachedScore(cacheKey: string): Promise<CachedTrustScore | null> {
    try {
      const cached = await this.redis.get(cacheKey);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      console.error('Error getting cached trust score:', error);
      return null;
    }
  }

  /**
   * Cache trust score
   */
  private async cacheScore(cacheKey: string, score: TrustScoreResponse): Promise<void> {
    try {
      const cached: CachedTrustScore = {
        score: score.trustScore,
        riskLevel: score.riskLevel,
        factors: score.factors,
        expiresAt: score.expiresAt,
        cacheKey
      };

      const ttl = Math.max(1, Math.floor((score.expiresAt - Date.now()) / 1000));
      await this.redis.setex(cacheKey, ttl, JSON.stringify(cached));
    } catch (error) {
      console.error('Error caching trust score:', error);
    }
  }

  /**
   * Fetch trust score from service
   */
  private async fetchTrustScore(request: TrustScoreRequest): Promise<TrustScoreResponse> {
    const response = await axios.post(
      `${this.trustScoreApiUrl}/api/trust-score/calculate`,
      {
        user_id: request.userId,
        device_id: request.deviceId,
        context: {
          ip_address: request.context.ipAddress,
          user_agent: request.context.userAgent,
          location: request.context.location,
          session_id: request.context.sessionId,
          risk_factors: request.context.riskFactors || [],
          timestamp: request.context.timestamp
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${this.apiToken}`,
          'Content-Type': 'application/json'
        },
        timeout: this.timeout,
        maxRedirects: 0
      }
    );

    if (response.status !== 200) {
      throw new Error(`Trust score service returned ${response.status}: ${response.statusText}`);
    }

    return {
      trustScore: response.data.trust_score,
      riskLevel: response.data.risk_level,
      factors: response.data.factors || [],
      expiresAt: Date.now() + (this.defaultCacheTtl * 1000),
      calculatedAt: Date.now()
    };
  }

  /**
   * Batch fetch trust scores
   */
  private async fetchBatchTrustScores(requests: TrustScoreRequest[]): Promise<Map<string, TrustScoreResponse>> {
    const batchRequest = {
      requests: requests.map(req => ({
        user_id: req.userId,
        device_id: req.deviceId,
        context: {
          ip_address: req.context.ipAddress,
          user_agent: req.context.userAgent,
          location: req.context.location,
          session_id: req.context.sessionId,
          risk_factors: req.context.riskFactors || [],
          timestamp: req.context.timestamp
        }
      }))
    };

    const response = await axios.post(
      `${this.trustScoreApiUrl}/api/trust-score/batch`,
      batchRequest,
      {
        headers: {
          'Authorization': `Bearer ${this.apiToken}`,
          'Content-Type': 'application/json'
        },
        timeout: this.timeout * 2, // Double timeout for batch requests
        maxRedirects: 0
      }
    );

    if (response.status !== 200) {
      throw new Error(`Trust score batch service returned ${response.status}: ${response.statusText}`);
    }

    const results = new Map<string, TrustScoreResponse>();
    
    for (const result of response.data.results) {
      results.set(result.user_id, {
        trustScore: result.trust_score,
        riskLevel: result.risk_level,
        factors: result.factors || [],
        expiresAt: Date.now() + (this.defaultCacheTtl * 1000),
        calculatedAt: Date.now()
      });
    }

    return results;
  }

  /**
   * Get default trust score when service is unavailable
   */
  private getDefaultTrustScore(request: TrustScoreRequest): TrustScoreResponse {
    // Conservative default - medium trust score
    return {
      trustScore: 50,
      riskLevel: 'MEDIUM',
      factors: [{
        type: 'service_unavailable',
        impact: -20,
        description: 'Trust score service unavailable, using default safe score',
        severity: 'MEDIUM'
      }],
      expiresAt: Date.now() + 60000, // 1 minute expiry for defaults
      calculatedAt: Date.now()
    };
  }

  /**
   * Health check for the service
   */
  async healthCheck(): Promise<{ status: string; details: any }> {
    const checks = {
      redis: false,
      trustScoreApi: false,
      overall: false
    };

    // Check Redis connection
    try {
      await this.redis.ping();
      checks.redis = true;
    } catch (error) {
      console.error('Redis health check failed:', error);
    }

    // Check Trust Score API
    try {
      const response = await axios.get(`${this.trustScoreApiUrl}/health`, {
        headers: {
          'Authorization': `Bearer ${this.apiToken}`
        },
        timeout: 3000
      });
      checks.trustScoreApi = response.status === 200;
    } catch (error) {
      console.error('Trust Score API health check failed:', error);
    }

    checks.overall = checks.redis && checks.trustScoreApi;

    return {
      status: checks.overall ? 'healthy' : 'unhealthy',
      details: checks
    };
  }

  /**
   * Cleanup resources
   */
  async close(): Promise<void> {
    try {
      await this.redis.quit();
    } catch (error) {
      console.error('Error closing Redis connection:', error);
    }
  }
}

export const trustScoreService = new TrustScoreIntegrationService();