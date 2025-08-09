/**
 * Trust Score API Routes
 * Production-grade REST API for trust scoring system
 * Supports real-time scoring, bulk operations, and analytics
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { rateLimit } from '@/lib/middleware/rate-limiting';
import { authenticate, authorize } from '@/lib/middleware/auth';
import { validateTenant } from '@/lib/middleware/tenant-validation';
import { auditLog } from '@/lib/middleware/audit-logging';
import { sanitizeInput } from '@/lib/utils/input-sanitization';
import { metrics } from '@/lib/monitoring/metrics';
import { logger } from '@/lib/utils/logger';

// Validation schemas
const trustScoreQuerySchema = z.object({
  userId: z.string().optional(),
  deviceId: z.string().optional(),
  sessionId: z.string().optional(),
  minScore: z.coerce.number().min(0).max(100).optional(),
  maxScore: z.coerce.number().min(0).max(100).optional(),
  includeFactors: z.boolean().default(false),
  includeHistory: z.boolean().default(false),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(1000).default(100),
  offset: z.coerce.number().min(0).default(0),
  sortBy: z.enum(['score', 'timestamp', 'risk_level']).default('timestamp'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

const trustScoreCalculateSchema = z.object({
  userId: z.string(),
  deviceId: z.string().optional(),
  sessionId: z.string().optional(),
  context: z.object({
    location: z.object({
      country: z.string().optional(),
      region: z.string().optional(),
      city: z.string().optional(),
      latitude: z.number().optional(),
      longitude: z.number().optional(),
      accuracy: z.number().optional(),
      vpnDetected: z.boolean().optional(),
      torDetected: z.boolean().optional(),
    }).optional(),
    device: z.object({
      fingerprint: z.string().optional(),
      platform: z.string().optional(),
      browser: z.string().optional(),
      version: z.string().optional(),
      screenResolution: z.string().optional(),
      timezone: z.string().optional(),
      language: z.string().optional(),
      plugins: z.array(z.string()).optional(),
      jailbroken: z.boolean().optional(),
      rooted: z.boolean().optional(),
    }).optional(),
    network: z.object({
      ipAddress: z.string().ip().optional(),
      isp: z.string().optional(),
      asn: z.string().optional(),
      connectionType: z.enum(['broadband', 'mobile', 'satellite', 'unknown']).optional(),
      vpnProvider: z.string().optional(),
      proxyType: z.string().optional(),
    }).optional(),
    behavior: z.object({
      loginFrequency: z.number().optional(),
      averageSessionDuration: z.number().optional(),
      lastActivity: z.string().datetime().optional(),
      failedLoginAttempts: z.number().optional(),
      suspiciousPatterns: z.array(z.string()).optional(),
      riskEvents: z.array(z.object({
        type: z.string(),
        severity: z.enum(['low', 'medium', 'high', 'critical']),
        timestamp: z.string().datetime(),
        details: z.record(z.any()).optional(),
      })).optional(),
    }).optional(),
    threat: z.object({
      knownThreatIps: z.array(z.string()).optional(),
      malwareScanResults: z.object({
        clean: z.boolean(),
        threats: z.array(z.string()).optional(),
        lastScan: z.string().datetime().optional(),
      }).optional(),
      reputationScores: z.record(z.number()).optional(),
    }).optional(),
  }),
  forceRecalculation: z.boolean().default(false),
  includeRecommendations: z.boolean().default(true),
});

const bulkCalculateSchema = z.object({
  requests: z.array(trustScoreCalculateSchema).min(1).max(100),
  parallel: z.boolean().default(true),
  includeFailures: z.boolean().default(true),
});

interface TrustScoringService {
  calculateTrustScore(params: any): Promise<any>;
  getTrustScores(query: any): Promise<any>;
  getTrustScore(id: string): Promise<any>;
  bulkCalculate(requests: any[]): Promise<any>;
  getTrustScoreHistory(userId: string, params: any): Promise<any>;
  getTrustScoreAnalytics(params: any): Promise<any>;
  updateTrustScore(id: string, updates: any): Promise<any>;
  getFactorWeights(tenantId: string): Promise<any>;
  updateFactorWeights(tenantId: string, weights: any): Promise<any>;
}

// Mock trust scoring service
class MockTrustScoringService implements TrustScoringService {
  private trustScores: Map<string, any> = new Map();
  private factorWeights: Map<string, any> = new Map();
  private nextId = 1;

  constructor() {
    this.seedData();
  }

  private seedData() {
    // Seed default factor weights
    this.factorWeights.set('default', {
      behavioral: 0.35,
      device: 0.25,
      network: 0.20,
      location: 0.15,
      threat: 0.05,
    });

    // Seed some sample trust scores
    const sampleScores = [
      {
        id: '1',
        userId: 'user1',
        deviceId: 'device1',
        sessionId: 'session1',
        score: 85.5,
        riskLevel: 'low',
        factors: {
          behavioral: { score: 90, weight: 0.35, details: { loginFrequency: 'normal', sessionPattern: 'consistent' } },
          device: { score: 88, weight: 0.25, details: { known: true, fingerprint: 'consistent' } },
          network: { score: 82, weight: 0.20, details: { knownIp: true, vpn: false } },
          location: { score: 80, weight: 0.15, details: { consistent: true, country: 'trusted' } },
          threat: { score: 95, weight: 0.05, details: { noThreats: true, reputation: 'good' } },
        },
        timestamp: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour
        calculatedAt: new Date().toISOString(),
      },
    ];

    sampleScores.forEach(score => {
      this.trustScores.set(score.id, score);
      this.nextId = Math.max(this.nextId, parseInt(score.id) + 1);
    });
  }

  async calculateTrustScore(params: any) {
    const { userId, deviceId, sessionId, context, forceRecalculation, includeRecommendations } = params;
    
    // Simulate trust score calculation
    const factors = {
      behavioral: this.calculateBehavioralScore(context.behavior || {}),
      device: this.calculateDeviceScore(context.device || {}),
      network: this.calculateNetworkScore(context.network || {}),
      location: this.calculateLocationScore(context.location || {}),
      threat: this.calculateThreatScore(context.threat || {}),
    };

    const weights = await this.getFactorWeights('default');
    
    const score = Math.round(
      factors.behavioral.score * weights.behavioral +
      factors.device.score * weights.device +
      factors.network.score * weights.network +
      factors.location.score * weights.location +
      factors.threat.score * weights.threat
    );

    const riskLevel = score >= 80 ? 'low' : 
                     score >= 60 ? 'medium' : 
                     score >= 40 ? 'high' : 'critical';

    const trustScore = {
      id: (this.nextId++).toString(),
      userId,
      deviceId,
      sessionId,
      score,
      riskLevel,
      factors: {
        behavioral: { score: factors.behavioral.score, weight: weights.behavioral, details: factors.behavioral.details },
        device: { score: factors.device.score, weight: weights.device, details: factors.device.details },
        network: { score: factors.network.score, weight: weights.network, details: factors.network.details },
        location: { score: factors.location.score, weight: weights.location, details: factors.location.details },
        threat: { score: factors.threat.score, weight: weights.threat, details: factors.threat.details },
      },
      context,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1 hour
      calculatedAt: new Date().toISOString(),
    };

    if (includeRecommendations) {
      trustScore.recommendations = this.generateRecommendations(trustScore);
    }

    this.trustScores.set(trustScore.id, trustScore);
    return trustScore;
  }

  private calculateBehavioralScore(behavior: any) {
    let score = 70; // Base score
    const details: any = {};

    if (behavior.loginFrequency) {
      if (behavior.loginFrequency > 10) {
        score -= 10;
        details.loginFrequency = 'high';
      } else if (behavior.loginFrequency < 1) {
        score -= 5;
        details.loginFrequency = 'low';
      } else {
        score += 10;
        details.loginFrequency = 'normal';
      }
    }

    if (behavior.failedLoginAttempts) {
      score -= Math.min(behavior.failedLoginAttempts * 5, 30);
      details.failedLogins = behavior.failedLoginAttempts;
    }

    if (behavior.suspiciousPatterns?.length) {
      score -= behavior.suspiciousPatterns.length * 10;
      details.suspiciousPatterns = behavior.suspiciousPatterns.length;
    }

    return { score: Math.max(0, Math.min(100, score)), details };
  }

  private calculateDeviceScore(device: any) {
    let score = 80; // Base score for known device
    const details: any = {};

    if (device.jailbroken || device.rooted) {
      score -= 25;
      details.compromised = true;
    }

    if (device.fingerprint) {
      score += 10;
      details.fingerprint = 'consistent';
    }

    return { score: Math.max(0, Math.min(100, score)), details };
  }

  private calculateNetworkScore(network: any) {
    let score = 75; // Base score
    const details: any = {};

    if (network.vpnProvider) {
      score -= 15;
      details.vpn = true;
    }

    if (network.proxyType) {
      score -= 10;
      details.proxy = true;
    }

    return { score: Math.max(0, Math.min(100, score)), details };
  }

  private calculateLocationScore(location: any) {
    let score = 70; // Base score
    const details: any = {};

    if (location.vpnDetected) {
      score -= 20;
      details.vpn = true;
    }

    if (location.torDetected) {
      score -= 30;
      details.tor = true;
    }

    if (location.country) {
      // Simulate trusted countries
      const trustedCountries = ['US', 'CA', 'GB', 'DE', 'AU'];
      if (trustedCountries.includes(location.country)) {
        score += 10;
        details.country = 'trusted';
      }
    }

    return { score: Math.max(0, Math.min(100, score)), details };
  }

  private calculateThreatScore(threat: any) {
    let score = 95; // Base score (assume clean)
    const details: any = {};

    if (threat.knownThreatIps?.length) {
      score -= threat.knownThreatIps.length * 20;
      details.threatIps = threat.knownThreatIps.length;
    }

    if (threat.malwareScanResults && !threat.malwareScanResults.clean) {
      score -= 40;
      details.malware = true;
    }

    return { score: Math.max(0, Math.min(100, score)), details };
  }

  private generateRecommendations(trustScore: any) {
    const recommendations = [];

    if (trustScore.score < 60) {
      recommendations.push({
        type: 'security',
        priority: 'high',
        action: 'require_additional_authentication',
        reason: 'Low trust score requires enhanced verification',
      });
    }

    if (trustScore.factors.behavioral.score < 50) {
      recommendations.push({
        type: 'behavioral',
        priority: 'medium',
        action: 'monitor_user_activity',
        reason: 'Unusual behavioral patterns detected',
      });
    }

    if (trustScore.factors.device.score < 70) {
      recommendations.push({
        type: 'device',
        priority: 'medium',
        action: 'verify_device',
        reason: 'Device security concerns identified',
      });
    }

    return recommendations;
  }

  async getTrustScores(query: any) {
    const { limit, offset, sortBy, sortOrder, userId, deviceId, minScore, maxScore, includeFactors, includeHistory } = query;
    
    let filtered = Array.from(this.trustScores.values()).filter(score => {
      if (userId && score.userId !== userId) return false;
      if (deviceId && score.deviceId !== deviceId) return false;
      if (minScore && score.score < minScore) return false;
      if (maxScore && score.score > maxScore) return false;
      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      let aVal, bVal;
      switch (sortBy) {
        case 'score':
          aVal = a.score;
          bVal = b.score;
          break;
        case 'timestamp':
          aVal = new Date(a.timestamp).getTime();
          bVal = new Date(b.timestamp).getTime();
          break;
        case 'risk_level':
          const riskOrder = { low: 1, medium: 2, high: 3, critical: 4 };
          aVal = riskOrder[a.riskLevel];
          bVal = riskOrder[b.riskLevel];
          break;
        default:
          aVal = 0;
          bVal = 0;
      }
      
      return sortOrder === 'asc' ? (aVal - bVal) : (bVal - aVal);
    });

    const total = filtered.length;
    let paginated = filtered.slice(offset, offset + limit);

    // Remove factors if not requested
    if (!includeFactors) {
      paginated = paginated.map(score => {
        const { factors, ...rest } = score;
        return rest;
      });
    }

    return {
      trustScores: paginated,
      total,
      limit,
      offset,
      hasMore: offset + limit < total,
    };
  }

  async getTrustScore(id: string) {
    const score = this.trustScores.get(id);
    if (!score) {
      throw new Error('Trust score not found');
    }
    return score;
  }

  async bulkCalculate(requests: any[]) {
    const results = [];
    
    for (const request of requests) {
      try {
        const score = await this.calculateTrustScore(request);
        results.push({ success: true, data: score, requestId: request.requestId });
      } catch (error: any) {
        results.push({ 
          success: false, 
          error: error.message, 
          requestId: request.requestId 
        });
      }
    }

    return {
      results,
      summary: {
        total: results.length,
        successful: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length,
      },
    };
  }

  async getTrustScoreHistory(userId: string, params: any) {
    const userScores = Array.from(this.trustScores.values())
      .filter(score => score.userId === userId)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    const { limit = 50, offset = 0 } = params;
    const paginated = userScores.slice(offset, offset + limit);

    return {
      history: paginated,
      total: userScores.length,
      limit,
      offset,
      hasMore: offset + limit < userScores.length,
      trends: {
        averageScore: userScores.length > 0 ? userScores.reduce((sum, s) => sum + s.score, 0) / userScores.length : 0,
        scoreImprovement: userScores.length > 1 ? userScores[0].score - userScores[userScores.length - 1].score : 0,
        riskLevelDistribution: {
          low: userScores.filter(s => s.riskLevel === 'low').length,
          medium: userScores.filter(s => s.riskLevel === 'medium').length,
          high: userScores.filter(s => s.riskLevel === 'high').length,
          critical: userScores.filter(s => s.riskLevel === 'critical').length,
        },
      },
    };
  }

  async getTrustScoreAnalytics(params: any) {
    const scores = Array.from(this.trustScores.values());
    
    return {
      overview: {
        totalScores: scores.length,
        averageScore: scores.length > 0 ? scores.reduce((sum, s) => sum + s.score, 0) / scores.length : 0,
        riskDistribution: {
          low: scores.filter(s => s.riskLevel === 'low').length,
          medium: scores.filter(s => s.riskLevel === 'medium').length,
          high: scores.filter(s => s.riskLevel === 'high').length,
          critical: scores.filter(s => s.riskLevel === 'critical').length,
        },
      },
      trends: {
        scoreImprovement: 12.5, // Percentage
        riskReduction: 8.3, // Percentage
      },
      topFactors: [
        { factor: 'behavioral', impact: 35.2, trend: 'improving' },
        { factor: 'device', impact: 28.1, trend: 'stable' },
        { factor: 'network', impact: 22.5, trend: 'degrading' },
      ],
    };
  }

  async updateTrustScore(id: string, updates: any) {
    const score = this.trustScores.get(id);
    if (!score) {
      throw new Error('Trust score not found');
    }

    const updated = {
      ...score,
      ...updates,
      id, // Preserve ID
      updatedAt: new Date().toISOString(),
    };

    this.trustScores.set(id, updated);
    return updated;
  }

  async getFactorWeights(tenantId: string) {
    return this.factorWeights.get(tenantId) || this.factorWeights.get('default');
  }

  async updateFactorWeights(tenantId: string, weights: any) {
    this.factorWeights.set(tenantId, weights);
    return weights;
  }
}

const trustScoringService = new MockTrustScoringService();

// GET /api/trust-score - Get trust scores with filtering
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting - High limits for trust scoring operations
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000, // 1 minute
      max: 5000, // 5000 requests per minute for high-frequency operations
      keyGenerator: (req) => `trust-score:${req.headers.get('x-forwarded-for') || 'unknown'}`,
    });

    if (!rateLimitResult.success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', retryAfter: rateLimitResult.retryAfter },
        { status: 429, headers: { 'Retry-After': rateLimitResult.retryAfter?.toString() || '60' } }
      );
    }

    // Authentication & Authorization
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const hasPermission = await authorize(user, 'trust-score:read');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse query parameters
    const { searchParams } = new URL(request.url);
    const queryParams = Object.fromEntries(searchParams);
    
    const validationResult = trustScoreQuerySchema.safeParse(queryParams);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Handle special endpoints
    const endpoint = searchParams.get('endpoint');
    
    if (endpoint === 'analytics') {
      const analytics = await trustScoringService.getTrustScoreAnalytics(validationResult.data);
      
      return NextResponse.json({
        success: true,
        data: analytics,
        metadata: {
          requestId: request.headers.get('x-request-id'),
          timestamp: new Date().toISOString(),
          processingTime: Date.now() - startTime,
        },
      });
    }

    if (endpoint === 'weights') {
      const weights = await trustScoringService.getFactorWeights(tenantValidation.tenantId);
      
      return NextResponse.json({
        success: true,
        data: weights,
        metadata: {
          requestId: request.headers.get('x-request-id'),
          timestamp: new Date().toISOString(),
          processingTime: Date.now() - startTime,
        },
      });
    }

    // Get trust scores
    const result = await trustScoringService.getTrustScores(validationResult.data);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'trust_scores.list',
      resource: 'trust_scores',
      metadata: { query: validationResult.data },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('trust_score.api.get.success', {
      tenantId: tenantValidation.tenantId,
      userId: user.id,
    });

    metrics.histogram('trust_score.api.get.duration', Date.now() - startTime, {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: result,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
        cacheHit: false, // In production, indicate cache status
      },
    });

  } catch (error: any) {
    logger.error('Trust Score API GET error:', error);
    
    metrics.increment('trust_score.api.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to get trust scores',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// POST /api/trust-score - Calculate new trust score or bulk calculate
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting - Lower limits for calculation operations
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 1000, // 1000 calculations per minute
      keyGenerator: (req) => `trust-score:calc:${req.headers.get('x-forwarded-for') || 'unknown'}`,
    });

    if (!rateLimitResult.success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', retryAfter: rateLimitResult.retryAfter },
        { status: 429, headers: { 'Retry-After': rateLimitResult.retryAfter?.toString() || '60' } }
      );
    }

    // Authentication & Authorization
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const hasPermission = await authorize(user, 'trust-score:calculate');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse and validate request body
    const body = await request.json();
    const sanitizedBody = sanitizeInput(body);

    // Handle bulk calculation
    if (Array.isArray(sanitizedBody.requests)) {
      const bulkValidation = bulkCalculateSchema.safeParse(sanitizedBody);
      if (!bulkValidation.success) {
        return NextResponse.json(
          { error: 'Invalid bulk request data', details: bulkValidation.error.issues },
          { status: 400 }
        );
      }

      // Process bulk calculation
      const result = await trustScoringService.bulkCalculate(bulkValidation.data.requests);

      // Audit logging
      await auditLog({
        userId: user.id,
        tenantId: tenantValidation.tenantId,
        action: 'trust_scores.bulk_calculate',
        resource: 'trust_scores',
        metadata: { 
          requestCount: bulkValidation.data.requests.length,
          successful: result.summary.successful,
          failed: result.summary.failed,
        },
        timestamp: new Date(),
      });

      // Metrics
      metrics.increment('trust_score.api.bulk_calculate.success', {
        tenantId: tenantValidation.tenantId,
      });

      metrics.histogram('trust_score.api.bulk_calculate.duration', Date.now() - startTime, {
        tenantId: tenantValidation.tenantId,
      });

      return NextResponse.json({
        success: true,
        data: result,
        metadata: {
          requestId: request.headers.get('x-request-id'),
          timestamp: new Date().toISOString(),
          processingTime: Date.now() - startTime,
        },
      });
    }

    // Single calculation
    const validationResult = trustScoreCalculateSchema.safeParse(sanitizedBody);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid calculation request', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Calculate trust score
    const trustScore = await trustScoringService.calculateTrustScore({
      ...validationResult.data,
      tenantId: tenantValidation.tenantId,
      calculatedBy: user.id,
    });

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'trust_scores.calculate',
      resource: 'trust_scores',
      resourceId: trustScore.id,
      metadata: { 
        userId: trustScore.userId,
        score: trustScore.score,
        riskLevel: trustScore.riskLevel,
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('trust_score.api.calculate.success', {
      tenantId: tenantValidation.tenantId,
      riskLevel: trustScore.riskLevel,
    });

    metrics.histogram('trust_score.api.calculate.duration', Date.now() - startTime, {
      tenantId: tenantValidation.tenantId,
    });

    metrics.histogram('trust_score.score', trustScore.score, {
      tenantId: tenantValidation.tenantId,
      riskLevel: trustScore.riskLevel,
    });

    return NextResponse.json({
      success: true,
      data: trustScore,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
        cached: false, // In production, indicate if result was cached
      },
    }, { status: 201 });

  } catch (error: any) {
    logger.error('Trust Score API POST error:', error);
    
    metrics.increment('trust_score.api.calculate.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to calculate trust score',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}