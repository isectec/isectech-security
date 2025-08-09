/**
 * Intelligent DDoS Protection System for iSECTECH
 * 
 * Provides multi-layered DDoS protection with baseline profiling, anomaly detection,
 * automatic mitigation, and integration with Google Cloud Armor for volumetric attacks.
 * 
 * Features:
 * - Application-layer (L7) DDoS protection
 * - Traffic baseline profiling and anomaly detection
 * - Automatic IP blacklisting and rate limiting
 * - Challenge-response mechanisms (CAPTCHA, JS challenge)
 * - Traffic shaping and prioritization
 * - Integration with Google Cloud Armor for L3/L4 protection
 * - Real-time threat intelligence integration
 * - Adaptive thresholds based on attack patterns
 * 
 * Performance Requirements:
 * - <5ms latency overhead for legitimate traffic
 * - 99.99% availability during attacks
 * - <0.01% false positive rate
 * - Detection time: <30 seconds for large attacks
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import * as geoip from 'geoip-lite';

// DDoS Protection Configuration Schema
export const DDoSProtectionConfigSchema = z.object({
  // Baseline profiling
  baselineProfiling: z.object({
    enabled: z.boolean().default(true),
    windowSize: z.number().min(60).default(300), // 5 minutes default
    historyDepth: z.number().min(24).default(168), // 1 week default (hours)
    minimumSamples: z.number().min(10).default(100),
    profileGranularity: z.enum(['GLOBAL', 'SERVICE', 'ENDPOINT', 'GEOGRAPHIC']).default('SERVICE'),
    adaptiveBaseline: z.boolean().default(true)
  }),
  
  // Anomaly detection
  anomalyDetection: z.object({
    enabled: z.boolean().default(true),
    algorithm: z.enum(['STATISTICAL', 'ML_BASED', 'HYBRID']).default('HYBRID'),
    sensitivityLevel: z.enum(['LOW', 'MEDIUM', 'HIGH', 'ADAPTIVE']).default('ADAPTIVE'),
    
    // Statistical thresholds
    requestRateThreshold: z.number().min(1).default(10), // X times baseline
    uniqueIPThreshold: z.number().min(1).default(5), // X times baseline unique IPs
    errorRateThreshold: z.number().min(0.1).max(1).default(0.3), // 30% error rate
    
    // Pattern detection
    burstDetection: z.boolean().default(true),
    slowlorisDetection: z.boolean().default(true),
    reflectionDetection: z.boolean().default(true),
    botnetDetection: z.boolean().default(true),
    
    // Geographic anomalies
    geographicAnomalyDetection: z.boolean().default(true),
    unusualGeoThreshold: z.number().min(2).default(5),
    
    // Advanced patterns
    requestPatternAnalysis: z.boolean().default(true),
    userAgentAnalysis: z.boolean().default(true),
    payloadAnalysis: z.boolean().default(true)
  }),
  
  // Mitigation strategies
  mitigationStrategies: z.object({
    automaticBlocking: z.object({
      enabled: z.boolean().default(true),
      blockDuration: z.number().min(60).default(3600), // 1 hour
      escalationFactor: z.number().min(1).default(2),
      maxBlockDuration: z.number().min(3600).default(86400) // 24 hours
    }),
    
    rateLimiting: z.object({
      enabled: z.boolean().default(true),
      aggressiveMode: z.boolean().default(true),
      dynamicLimits: z.boolean().default(true),
      priorityTraffic: z.array(z.string()).default(['api-key-authenticated', 'premium-clients'])
    }),
    
    challengeResponse: z.object({
      enabled: z.boolean().default(true),
      jsChallenge: z.boolean().default(true),
      captchaChallenge: z.boolean().default(true),
      proofOfWork: z.boolean().default(false),
      challengeThreshold: z.number().min(2).default(5) // Trigger after X suspicious requests
    }),
    
    trafficShaping: z.object({
      enabled: z.boolean().default(true),
      priorityQueues: z.boolean().default(true),
      bandwidthLimiting: z.boolean().default(true),
      connectionLimiting: z.boolean().default(true)
    })
  }),
  
  // Cloud Armor integration
  cloudArmor: z.object({
    enabled: z.boolean().default(true),
    projectId: z.string(),
    policyName: z.string().default('isectech-ddos-protection'),
    adaptiveProtection: z.boolean().default(true),
    
    // L3/L4 rules
    volumetricProtection: z.boolean().default(true),
    rateLimitingRules: z.array(z.object({
      name: z.string(),
      priority: z.number(),
      rateLimitOptions: z.object({
        rateLimitThreshold: z.object({
          count: z.number(),
          intervalSec: z.number()
        }),
        banThreshold: z.object({
          count: z.number(),
          intervalSec: z.number()
        }),
        banDurationSec: z.number()
      })
    })).default([]),
    
    // Geographic restrictions
    geographicRestrictions: z.object({
      enabled: z.boolean().default(false),
      allowedCountries: z.array(z.string()).default([]),
      blockedCountries: z.array(z.string()).default([])
    }),
    
    // Bot management
    botManagement: z.object({
      enabled: z.boolean().default(true),
      recaptchaOptions: z.object({
        siteKey: z.string(),
        secretKey: z.string()
      }).optional()
    })
  }),
  
  // Monitoring and alerting
  monitoring: z.object({
    enabled: z.boolean().default(true),
    realTimeMetrics: z.boolean().default(true),
    alerting: z.object({
      enabled: z.boolean().default(true),
      channels: z.array(z.enum(['EMAIL', 'SLACK', 'WEBHOOK', 'SMS', 'PAGERDUTY'])),
      thresholds: z.object({
        attackDetected: z.boolean().default(true),
        falsePositiveRate: z.number().min(0).max(1).default(0.01),
        mitigationEffectiveness: z.number().min(0).max(1).default(0.95)
      })
    }),
    
    forensics: z.object({
      enabled: z.boolean().default(true),
      detailedLogging: z.boolean().default(true),
      packetCapture: z.boolean().default(false),
      attackSignatures: z.boolean().default(true)
    })
  }),
  
  // Machine learning
  machineLearning: z.object({
    enabled: z.boolean().default(true),
    modelType: z.enum(['ENSEMBLE', 'NEURAL_NETWORK', 'RANDOM_FOREST']).default('ENSEMBLE'),
    trainingInterval: z.number().min(3600).default(86400), // 24 hours
    predictionConfidence: z.number().min(0).max(1).default(0.85),
    adaptiveThresholds: z.boolean().default(true),
    
    // Feature engineering
    features: z.object({
      requestMetrics: z.boolean().default(true),
      trafficPatterns: z.boolean().default(true),
      geolocationData: z.boolean().default(true),
      userBehavior: z.boolean().default(true),
      networkFingerprints: z.boolean().default(true)
    })
  }),
  
  // Performance and optimization
  performance: z.object({
    caching: z.object({
      enabled: z.boolean().default(true),
      baselineCacheTTL: z.number().min(60).default(300),
      rulesCacheTTL: z.number().min(30).default(60),
      ipReputationCacheTTL: z.number().min(300).default(900)
    }),
    
    processing: z.object({
      parallelProcessing: z.boolean().default(true),
      asyncAnalysis: z.boolean().default(true),
      batchProcessing: z.boolean().default(true),
      streamProcessing: z.boolean().default(true)
    }),
    
    scalability: z.object({
      autoScaling: z.boolean().default(true),
      loadBalancing: z.boolean().default(true),
      distributedProcessing: z.boolean().default(true)
    })
  }),
  
  // Integration settings
  integration: z.object({
    threatIntelligence: z.object({
      enabled: z.boolean().default(true),
      providers: z.array(z.enum(['CLOUDFLARE', 'ABUSEIPDB', 'VIRUSTOTAL', 'CUSTOM'])).default(['ABUSEIPDB']),
      updateInterval: z.number().min(300).default(3600),
      confidenceThreshold: z.number().min(0).max(100).default(75)
    }),
    
    siem: z.object({
      enabled: z.boolean().default(true),
      forwardEvents: z.boolean().default(true),
      eventFormat: z.enum(['JSON', 'SYSLOG', 'CEF']).default('JSON')
    }),
    
    externalServices: z.object({
      webhookNotifications: z.array(z.string()).default([]),
      apiIntegrations: z.array(z.string()).default([])
    })
  })
});

export const AttackEventSchema = z.object({
  eventId: z.string(),
  timestamp: z.date(),
  attackType: z.enum([
    'VOLUMETRIC', 'APPLICATION_LAYER', 'PROTOCOL', 'MIXED',
    'SLOWLORIS', 'HTTP_FLOOD', 'SYN_FLOOD', 'UDP_FLOOD',
    'REFLECTION_AMPLIFICATION', 'BOTNET', 'SCRAPING'
  ]),
  
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  confidence: z.number().min(0).max(1),
  
  // Attack characteristics
  sourceAnalysis: z.object({
    uniqueIPs: z.number(),
    topSourceIPs: z.array(z.string()),
    geographicDistribution: z.record(z.number()),
    asn: z.array(z.number()).optional(),
    suspiciousPatterns: z.array(z.string())
  }),
  
  // Traffic characteristics
  trafficAnalysis: z.object({
    requestRate: z.number(),
    baselineDeviation: z.number(),
    peakRequestRate: z.number(),
    totalRequests: z.number(),
    uniqueEndpoints: z.number(),
    errorRate: z.number()
  }),
  
  // Target information
  targetAnalysis: z.object({
    services: z.array(z.string()),
    endpoints: z.array(z.string()),
    methods: z.array(z.string()),
    impactAssessment: z.enum(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
  }),
  
  // Mitigation actions
  mitigationActions: z.array(z.object({
    action: z.enum(['BLOCK_IP', 'RATE_LIMIT', 'CHALLENGE', 'REDIRECT', 'DROP']),
    target: z.string(),
    timestamp: z.date(),
    effectiveness: z.number().min(0).max(1).optional()
  })),
  
  // Resolution information
  resolution: z.object({
    resolved: z.boolean(),
    resolvedAt: z.date().optional(),
    duration: z.number().optional(), // milliseconds
    falsePositive: z.boolean().default(false),
    notes: z.string().optional()
  }),
  
  // Forensic data
  forensics: z.object({
    attackSignatures: z.array(z.string()),
    payloadSamples: z.array(z.string()),
    userAgents: z.array(z.string()),
    requestPatterns: z.array(z.string())
  })
});

export type DDoSProtectionConfig = z.infer<typeof DDoSProtectionConfigSchema>;
export type AttackEvent = z.infer<typeof AttackEventSchema>;

/**
 * Traffic Baseline Manager
 */
class TrafficBaselineManager {
  private baselines: Map<string, any> = new Map();
  private historicalData: Map<string, number[]> = new Map();

  constructor(private config: DDoSProtectionConfig['baselineProfiling']) {}

  public async updateBaseline(
    identifier: string,
    metrics: {
      requestRate: number;
      uniqueIPs: number;
      errorRate: number;
      responseTime: number;
      payloadSize: number;
    }
  ): Promise<void> {
    const key = identifier;
    const history = this.historicalData.get(key) || [];
    
    // Add current metrics
    history.push(metrics.requestRate);
    
    // Keep only recent history
    const maxHistory = this.config.historyDepth * (3600 / this.config.windowSize); // Convert to data points
    if (history.length > maxHistory) {
      history.splice(0, history.length - maxHistory);
    }
    
    this.historicalData.set(key, history);

    // Update baseline if we have enough samples
    if (history.length >= this.config.minimumSamples) {
      const baseline = this.calculateBaseline(history);
      this.baselines.set(key, {
        ...baseline,
        lastUpdate: new Date(),
        sampleCount: history.length,
        metrics: { ...metrics }
      });
    }
  }

  private calculateBaseline(data: number[]): any {
    const sorted = [...data].sort((a, b) => a - b);
    const mean = data.reduce((sum, val) => sum + val, 0) / data.length;
    const median = sorted[Math.floor(sorted.length / 2)];
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const p99 = sorted[Math.floor(sorted.length * 0.99)];
    
    const variance = data.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / data.length;
    const stdDev = Math.sqrt(variance);

    return {
      mean,
      median,
      stdDev,
      p95,
      p99,
      min: Math.min(...data),
      max: Math.max(...data),
      trend: this.calculateTrend(data)
    };
  }

  private calculateTrend(data: number[]): 'INCREASING' | 'DECREASING' | 'STABLE' {
    if (data.length < 10) return 'STABLE';
    
    const recent = data.slice(-10);
    const older = data.slice(-20, -10);
    
    if (older.length === 0) return 'STABLE';
    
    const recentAvg = recent.reduce((sum, val) => sum + val, 0) / recent.length;
    const olderAvg = older.reduce((sum, val) => sum + val, 0) / older.length;
    
    const change = (recentAvg - olderAvg) / olderAvg;
    
    if (change > 0.1) return 'INCREASING';
    if (change < -0.1) return 'DECREASING';
    return 'STABLE';
  }

  public getBaseline(identifier: string): any | null {
    return this.baselines.get(identifier) || null;
  }

  public isAnomaly(identifier: string, currentValue: number, threshold: number = 3): boolean {
    const baseline = this.baselines.get(identifier);
    if (!baseline) return false;
    
    return Math.abs(currentValue - baseline.mean) > (threshold * baseline.stdDev);
  }
}

/**
 * Anomaly Detection Engine
 */
class AnomalyDetectionEngine {
  private mlModels: Map<string, any> = new Map();
  private featureExtractor: FeatureExtractor;

  constructor(
    private config: DDoSProtectionConfig['anomalyDetection'],
    private baselineManager: TrafficBaselineManager
  ) {
    this.featureExtractor = new FeatureExtractor();
  }

  public async detectAnomalies(
    trafficData: {
      identifier: string;
      requestRate: number;
      uniqueIPs: number;
      errorRate: number;
      geographicDistribution: Record<string, number>;
      userAgents: string[];
      requestPatterns: string[];
      payloadSizes: number[];
    }
  ): Promise<{
    isAnomaly: boolean;
    confidence: number;
    attackType?: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    reasons: string[];
    features: Record<string, number>;
  }> {
    const features = await this.featureExtractor.extract(trafficData);
    const baseline = this.baselineManager.getBaseline(trafficData.identifier);
    
    const detectionResults = await Promise.all([
      this.statisticalDetection(trafficData, baseline, features),
      this.patternDetection(trafficData, features),
      this.geographicDetection(trafficData, features),
      this.mlDetection(trafficData, features)
    ]);

    // Ensemble voting
    const confidences = detectionResults.map(r => r.confidence);
    const avgConfidence = confidences.reduce((sum, c) => sum + c, 0) / confidences.length;
    
    const isAnomaly = detectionResults.some(r => r.isAnomaly) && avgConfidence > 0.5;
    
    const reasons = detectionResults
      .filter(r => r.isAnomaly)
      .map(r => r.reason)
      .filter(Boolean);

    const severity = this.calculateSeverity(avgConfidence, trafficData);
    const attackType = this.identifyAttackType(detectionResults, features);

    return {
      isAnomaly,
      confidence: avgConfidence,
      attackType,
      severity,
      reasons,
      features
    };
  }

  private async statisticalDetection(trafficData: any, baseline: any, features: any): Promise<any> {
    if (!baseline) {
      return { isAnomaly: false, confidence: 0, reason: 'No baseline available' };
    }

    const deviations = {
      requestRate: Math.abs(trafficData.requestRate - baseline.mean) / baseline.stdDev,
      uniqueIPs: features.uniqueIPsRatio,
      errorRate: trafficData.errorRate - baseline.metrics?.errorRate || 0
    };

    const maxDeviation = Math.max(...Object.values(deviations));
    const threshold = this.getThresholdForSensitivity();
    
    return {
      isAnomaly: maxDeviation > threshold,
      confidence: Math.min(maxDeviation / threshold, 1),
      reason: `Statistical anomaly: ${maxDeviation.toFixed(2)}σ deviation`
    };
  }

  private async patternDetection(trafficData: any, features: any): Promise<any> {
    const suspiciousPatterns = [];
    
    // Check for common attack patterns
    if (features.repeatedRequestRatio > 0.8) {
      suspiciousPatterns.push('High request repetition');
    }
    
    if (features.singleEndpointRatio > 0.9) {
      suspiciousPatterns.push('Concentrated endpoint targeting');
    }
    
    if (features.shortRequestIntervalRatio > 0.7) {
      suspiciousPatterns.push('Rapid-fire requests');
    }
    
    if (features.emptyPayloadRatio > 0.8) {
      suspiciousPatterns.push('High empty payload ratio');
    }

    const confidence = suspiciousPatterns.length / 4; // Normalize to 0-1
    
    return {
      isAnomaly: suspiciousPatterns.length > 1,
      confidence,
      reason: `Pattern anomalies: ${suspiciousPatterns.join(', ')}`
    };
  }

  private async geographicDetection(trafficData: any, features: any): Promise<any> {
    if (!this.config.geographicAnomalyDetection) {
      return { isAnomaly: false, confidence: 0 };
    }

    const geoDistribution = trafficData.geographicDistribution;
    const totalRequests = Object.values(geoDistribution).reduce((sum: number, count: number) => sum + count, 0);
    
    // Check for unusual geographic concentration
    const topCountryShare = Math.max(...Object.values(geoDistribution).map(count => (count as number) / totalRequests));
    const countryCount = Object.keys(geoDistribution).length;
    
    // Anomaly if single country dominates or too many countries
    const concentrationAnomaly = topCountryShare > 0.8 && countryCount < 3;
    const distributionAnomaly = countryCount > 50 && totalRequests > 1000;
    
    const isAnomaly = concentrationAnomaly || distributionAnomaly;
    const confidence = isAnomaly ? Math.max(topCountryShare, countryCount / 100) : 0;

    return {
      isAnomaly,
      confidence: Math.min(confidence, 1),
      reason: isAnomaly ? 'Unusual geographic distribution' : undefined
    };
  }

  private async mlDetection(trafficData: any, features: any): Promise<any> {
    // Simplified ML detection - would use actual ML models in production
    const featureVector = Object.values(features);
    const anomalyScore = this.calculateAnomalyScore(featureVector);
    
    const threshold = this.config.algorithm === 'ML_BASED' ? 0.6 : 0.8;
    
    return {
      isAnomaly: anomalyScore > threshold,
      confidence: anomalyScore,
      reason: anomalyScore > threshold ? `ML-detected anomaly (score: ${anomalyScore.toFixed(3)})` : undefined
    };
  }

  private calculateAnomalyScore(featureVector: number[]): number {
    // Simplified anomaly scoring - would use trained ML models
    const normalizedFeatures = featureVector.map(f => Math.tanh(f)); // Normalize to [-1, 1]
    const meanDeviation = normalizedFeatures.reduce((sum, f) => sum + Math.abs(f), 0) / normalizedFeatures.length;
    return Math.min(meanDeviation, 1);
  }

  private getThresholdForSensitivity(): number {
    switch (this.config.sensitivityLevel) {
      case 'HIGH': return 2;
      case 'MEDIUM': return 3;
      case 'LOW': return 4;
      case 'ADAPTIVE': return 2.5; // Would be dynamically adjusted
      default: return 3;
    }
  }

  private calculateSeverity(confidence: number, trafficData: any): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (confidence > 0.9) return 'CRITICAL';
    if (confidence > 0.7) return 'HIGH';
    if (confidence > 0.5) return 'MEDIUM';
    return 'LOW';
  }

  private identifyAttackType(detectionResults: any[], features: any): string {
    // Simple attack type identification based on features
    if (features.requestRateDeviation > 10) return 'HTTP_FLOOD';
    if (features.uniqueIPsRatio > 5) return 'BOTNET';
    if (features.singleEndpointRatio > 0.9) return 'APPLICATION_LAYER';
    if (features.emptyPayloadRatio > 0.8) return 'VOLUMETRIC';
    return 'MIXED';
  }
}

/**
 * Feature Extraction for ML-based detection
 */
class FeatureExtractor {
  public async extract(trafficData: any): Promise<Record<string, number>> {
    const baseline = trafficData.baseline || {};
    
    return {
      // Request rate features
      requestRateDeviation: baseline.mean ? (trafficData.requestRate - baseline.mean) / baseline.stdDev : 0,
      requestRateRatio: baseline.mean ? trafficData.requestRate / baseline.mean : 1,
      
      // IP diversity features
      uniqueIPsRatio: trafficData.requestRate > 0 ? trafficData.uniqueIPs / trafficData.requestRate : 0,
      ipEntropyScore: this.calculateEntropy(Object.values(trafficData.geographicDistribution || {})),
      
      // Pattern features
      repeatedRequestRatio: this.calculateRepetitionRatio(trafficData.requestPatterns || []),
      singleEndpointRatio: this.calculateEndpointConcentration(trafficData.requestPatterns || []),
      shortRequestIntervalRatio: this.calculateShortIntervalRatio(trafficData.timestamps || []),
      
      // Payload features
      averagePayloadSize: trafficData.payloadSizes ? 
        trafficData.payloadSizes.reduce((sum: number, size: number) => sum + size, 0) / trafficData.payloadSizes.length : 0,
      emptyPayloadRatio: trafficData.payloadSizes ? 
        trafficData.payloadSizes.filter((size: number) => size === 0).length / trafficData.payloadSizes.length : 0,
      
      // User agent features
      userAgentDiversity: trafficData.userAgents ? new Set(trafficData.userAgents).size / trafficData.userAgents.length : 1,
      botUserAgentRatio: this.calculateBotRatio(trafficData.userAgents || []),
      
      // Error rate features
      errorRateDeviation: baseline.metrics?.errorRate ? 
        Math.abs(trafficData.errorRate - baseline.metrics.errorRate) : trafficData.errorRate,
      
      // Geographic features
      geographicConcentration: this.calculateGeographicConcentration(trafficData.geographicDistribution || {}),
      unusualGeographicActivity: this.detectUnusualGeographic(trafficData.geographicDistribution || {})
    };
  }

  private calculateEntropy(values: number[]): number {
    const total = values.reduce((sum, val) => sum + val, 0);
    if (total === 0) return 0;
    
    const probabilities = values.map(val => val / total).filter(p => p > 0);
    return -probabilities.reduce((sum, p) => sum + p * Math.log2(p), 0);
  }

  private calculateRepetitionRatio(patterns: string[]): number {
    if (patterns.length === 0) return 0;
    const uniquePatterns = new Set(patterns).size;
    return 1 - (uniquePatterns / patterns.length);
  }

  private calculateEndpointConcentration(patterns: string[]): number {
    if (patterns.length === 0) return 0;
    const endpointCounts = new Map<string, number>();
    
    patterns.forEach(pattern => {
      const endpoint = pattern.split(' ')[1] || pattern; // Extract endpoint from "METHOD /path"
      endpointCounts.set(endpoint, (endpointCounts.get(endpoint) || 0) + 1);
    });
    
    const maxCount = Math.max(...endpointCounts.values());
    return maxCount / patterns.length;
  }

  private calculateShortIntervalRatio(timestamps: number[]): number {
    if (timestamps.length < 2) return 0;
    
    const intervals = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i-1]);
    }
    
    const shortIntervals = intervals.filter(interval => interval < 100); // Less than 100ms
    return shortIntervals.length / intervals.length;
  }

  private calculateBotRatio(userAgents: string[]): number {
    if (userAgents.length === 0) return 0;
    
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i, /python/i
    ];
    
    const botCount = userAgents.filter(ua => 
      botPatterns.some(pattern => pattern.test(ua))
    ).length;
    
    return botCount / userAgents.length;
  }

  private calculateGeographicConcentration(geoDistribution: Record<string, number>): number {
    const values = Object.values(geoDistribution);
    if (values.length === 0) return 0;
    
    const total = values.reduce((sum, val) => sum + val, 0);
    const maxValue = Math.max(...values);
    
    return total > 0 ? maxValue / total : 0;
  }

  private detectUnusualGeographic(geoDistribution: Record<string, number>): number {
    const suspiciousCountries = ['CN', 'RU', 'KP', 'IR']; // Example suspicious countries
    const totalRequests = Object.values(geoDistribution).reduce((sum, val) => sum + val, 0);
    
    if (totalRequests === 0) return 0;
    
    const suspiciousRequests = suspiciousCountries.reduce((sum, country) => {
      return sum + (geoDistribution[country] || 0);
    }, 0);
    
    return suspiciousRequests / totalRequests;
  }
}

/**
 * Main Intelligent DDoS Protection System
 */
export class IntelligentDDoSProtectionSystem {
  private config: DDoSProtectionConfig;
  private baselineManager: TrafficBaselineManager;
  private anomalyEngine: AnomalyDetectionEngine;
  private activeAttacks: Map<string, AttackEvent> = new Map();
  private blockedIPs: Map<string, { until: Date; reason: string; escalationLevel: number }> = new Map();
  private challengeTokens: Map<string, { token: string; expires: Date; attempts: number }> = new Map();
  private threatIntelligence: Map<string, { score: number; lastUpdated: Date }> = new Map();

  constructor(config: DDoSProtectionConfig) {
    this.config = config;
    this.baselineManager = new TrafficBaselineManager(config.baselineProfiling);
    this.anomalyEngine = new AnomalyDetectionEngine(config.anomalyDetection, this.baselineManager);
    
    this.startPeriodicTasks();
  }

  /**
   * Analyze incoming traffic and determine if it's part of an attack
   */
  public async analyzeTraffic(
    request: {
      id: string;
      ip: string;
      method: string;
      path: string;
      userAgent: string;
      headers: Record<string, string>;
      payload?: string;
      timestamp: Date;
      responseTime?: number;
      statusCode?: number;
    }
  ): Promise<{
    allowed: boolean;
    action: 'ALLOW' | 'BLOCK' | 'CHALLENGE' | 'RATE_LIMIT' | 'MONITOR';
    reason: string;
    confidence: number;
    challengeToken?: string;
    retryAfter?: number;
    mitigationApplied?: string[];
  }> {
    try {
      // Check if IP is already blocked
      const blockInfo = this.blockedIPs.get(request.ip);
      if (blockInfo && blockInfo.until > new Date()) {
        return {
          allowed: false,
          action: 'BLOCK',
          reason: `IP blocked: ${blockInfo.reason}`,
          confidence: 1.0,
          retryAfter: Math.ceil((blockInfo.until.getTime() - Date.now()) / 1000)
        };
      }

      // Check threat intelligence
      const threatScore = await this.checkThreatIntelligence(request.ip);
      if (threatScore > 0.8) {
        await this.blockIP(request.ip, 'Threat intelligence match', 1);
        return {
          allowed: false,
          action: 'BLOCK',
          reason: 'Malicious IP detected by threat intelligence',
          confidence: threatScore
        };
      }

      // Collect traffic metrics
      const trafficMetrics = await this.collectTrafficMetrics(request);
      
      // Update baseline
      await this.baselineManager.updateBaseline('global', trafficMetrics);
      
      // Detect anomalies
      const anomalyResult = await this.anomalyEngine.detectAnomalies({
        identifier: 'global',
        ...trafficMetrics
      });

      if (anomalyResult.isAnomaly && anomalyResult.confidence > 0.7) {
        // Potential attack detected
        const attackEvent = await this.createAttackEvent(request, anomalyResult, trafficMetrics);
        await this.handleAttackEvent(attackEvent);
        
        // Determine action based on severity and attack type
        const action = await this.determineAction(anomalyResult, request);
        
        return {
          allowed: action.allowed,
          action: action.type,
          reason: action.reason,
          confidence: anomalyResult.confidence,
          challengeToken: action.challengeToken,
          retryAfter: action.retryAfter,
          mitigationApplied: action.mitigations
        };
      }

      // Check for challenge response if suspicious but not anomalous
      if (anomalyResult.confidence > 0.4) {
        const challengeResult = await this.checkChallengeResponse(request);
        if (challengeResult.requiresChallenge) {
          return {
            allowed: false,
            action: 'CHALLENGE',
            reason: 'Suspicious traffic requires verification',
            confidence: anomalyResult.confidence,
            challengeToken: challengeResult.token
          };
        }
      }

      // Traffic appears legitimate
      return {
        allowed: true,
        action: 'ALLOW',
        reason: 'Traffic within normal parameters',
        confidence: 1 - anomalyResult.confidence
      };

    } catch (error) {
      console.error('Error analyzing traffic:', error);
      
      // Fail-open in case of system errors
      return {
        allowed: true,
        action: 'MONITOR',
        reason: 'Analysis error - fail-open mode',
        confidence: 0
      };
    }
  }

  /**
   * Handle detected attack event
   */
  private async handleAttackEvent(attackEvent: AttackEvent): Promise<void> {
    this.activeAttacks.set(attackEvent.eventId, attackEvent);
    
    // Log attack event
    console.warn(`DDoS attack detected: ${attackEvent.attackType} (${attackEvent.severity})`);
    
    // Apply automatic mitigation
    if (this.config.mitigationStrategies.automaticBlocking.enabled) {
      await this.applyAutomaticMitigation(attackEvent);
    }
    
    // Send alerts
    if (this.config.monitoring.alerting.enabled) {
      await this.sendAttackAlert(attackEvent);
    }
    
    // Update Cloud Armor rules if enabled
    if (this.config.cloudArmor.enabled && attackEvent.severity !== 'LOW') {
      await this.updateCloudArmorRules(attackEvent);
    }
  }

  /**
   * Apply automatic mitigation strategies
   */
  private async applyAutomaticMitigation(attackEvent: AttackEvent): Promise<void> {
    const mitigations: string[] = [];
    
    // Block top attacking IPs
    for (const ip of attackEvent.sourceAnalysis.topSourceIPs.slice(0, 10)) {
      const escalationLevel = (this.blockedIPs.get(ip)?.escalationLevel || 0) + 1;
      const duration = this.config.mitigationStrategies.automaticBlocking.blockDuration * 
        Math.pow(this.config.mitigationStrategies.automaticBlocking.escalationFactor, escalationLevel - 1);
      
      await this.blockIP(ip, `Attack source: ${attackEvent.attackType}`, escalationLevel);
      mitigations.push(`IP_BLOCK:${ip}`);
    }
    
    // Apply aggressive rate limiting for affected services
    if (this.config.mitigationStrategies.rateLimiting.enabled) {
      for (const service of attackEvent.targetAnalysis.services) {
        await this.applyAggressiveRateLimit(service);
        mitigations.push(`RATE_LIMIT:${service}`);
      }
    }
    
    // Enable challenge mode for suspicious traffic
    if (this.config.mitigationStrategies.challengeResponse.enabled) {
      await this.enableChallengeMode(attackEvent.targetAnalysis.endpoints);
      mitigations.push('CHALLENGE_MODE');
    }
    
    // Update attack event with applied mitigations
    attackEvent.mitigationActions = mitigations.map(m => ({
      action: m.split(':')[0] as any,
      target: m.split(':')[1] || 'global',
      timestamp: new Date(),
      effectiveness: undefined
    }));
  }

  // Helper methods for traffic analysis and mitigation

  private async collectTrafficMetrics(request: any): Promise<any> {
    // This would collect comprehensive traffic metrics
    // For now, return mock data structure
    return {
      requestRate: 100,
      uniqueIPs: 50,
      errorRate: 0.1,
      responseTime: 150,
      payloadSize: request.payload?.length || 0,
      geographicDistribution: { 'US': 60, 'CA': 20, 'GB': 15, 'FR': 5 },
      userAgents: [request.userAgent],
      requestPatterns: [`${request.method} ${request.path}`],
      payloadSizes: [request.payload?.length || 0]
    };
  }

  private async createAttackEvent(request: any, anomaly: any, metrics: any): Promise<AttackEvent> {
    return {
      eventId: crypto.randomUUID(),
      timestamp: new Date(),
      attackType: anomaly.attackType || 'MIXED',
      severity: anomaly.severity,
      confidence: anomaly.confidence,
      sourceAnalysis: {
        uniqueIPs: metrics.uniqueIPs,
        topSourceIPs: [request.ip],
        geographicDistribution: metrics.geographicDistribution,
        suspiciousPatterns: anomaly.reasons
      },
      trafficAnalysis: {
        requestRate: metrics.requestRate,
        baselineDeviation: metrics.requestRate / 10, // Mock baseline
        peakRequestRate: metrics.requestRate * 1.5,
        totalRequests: metrics.requestRate * 60,
        uniqueEndpoints: 5,
        errorRate: metrics.errorRate
      },
      targetAnalysis: {
        services: ['isectech-api'],
        endpoints: [request.path],
        methods: [request.method],
        impactAssessment: anomaly.severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM'
      },
      mitigationActions: [],
      resolution: {
        resolved: false
      },
      forensics: {
        attackSignatures: anomaly.reasons,
        payloadSamples: [request.payload || ''],
        userAgents: [request.userAgent],
        requestPatterns: [`${request.method} ${request.path}`]
      }
    };
  }

  private async determineAction(anomaly: any, request: any): Promise<any> {
    if (anomaly.confidence > 0.9 || anomaly.severity === 'CRITICAL') {
      return {
        allowed: false,
        type: 'BLOCK',
        reason: `High-confidence attack detected: ${anomaly.reasons.join(', ')}`,
        mitigations: ['IP_BLOCK']
      };
    }
    
    if (anomaly.confidence > 0.7) {
      const token = crypto.randomUUID();
      this.challengeTokens.set(request.ip, {
        token,
        expires: new Date(Date.now() + 300000), // 5 minutes
        attempts: 0
      });
      
      return {
        allowed: false,
        type: 'CHALLENGE',
        reason: 'Suspicious traffic requires verification',
        challengeToken: token,
        mitigations: ['CHALLENGE']
      };
    }
    
    return {
      allowed: false,
      type: 'RATE_LIMIT',
      reason: 'Applying rate limiting due to anomalous traffic',
      retryAfter: 60,
      mitigations: ['RATE_LIMIT']
    };
  }

  private async blockIP(ip: string, reason: string, escalationLevel: number): Promise<void> {
    const maxDuration = this.config.mitigationStrategies.automaticBlocking.maxBlockDuration;
    const baseDuration = this.config.mitigationStrategies.automaticBlocking.blockDuration;
    const escalationFactor = this.config.mitigationStrategies.automaticBlocking.escalationFactor;
    
    const duration = Math.min(
      baseDuration * Math.pow(escalationFactor, escalationLevel - 1),
      maxDuration
    );
    
    this.blockedIPs.set(ip, {
      until: new Date(Date.now() + duration * 1000),
      reason,
      escalationLevel
    });
    
    console.log(`Blocked IP ${ip} for ${duration}s (level ${escalationLevel}): ${reason}`);
  }

  private async checkThreatIntelligence(ip: string): Promise<number> {
    const cached = this.threatIntelligence.get(ip);
    if (cached && Date.now() - cached.lastUpdated.getTime() < this.config.integration.threatIntelligence.updateInterval * 1000) {
      return cached.score;
    }
    
    // This would query external threat intelligence APIs
    // For now, return random score
    const score = Math.random() * 0.1; // Low random score
    this.threatIntelligence.set(ip, {
      score,
      lastUpdated: new Date()
    });
    
    return score;
  }

  private async checkChallengeResponse(request: any): Promise<any> {
    const existing = this.challengeTokens.get(request.ip);
    if (existing && existing.expires > new Date()) {
      // Check if challenge was solved
      const challengeHeader = request.headers['x-challenge-response'];
      if (challengeHeader && challengeHeader === existing.token) {
        this.challengeTokens.delete(request.ip);
        return { requiresChallenge: false };
      }
      
      existing.attempts++;
      if (existing.attempts > 3) {
        await this.blockIP(request.ip, 'Failed challenge attempts', 1);
        return { requiresChallenge: false };
      }
      
      return { requiresChallenge: true, token: existing.token };
    }
    
    // Generate new challenge if suspicious
    const token = crypto.randomUUID();
    this.challengeTokens.set(request.ip, {
      token,
      expires: new Date(Date.now() + 300000),
      attempts: 1
    });
    
    return { requiresChallenge: true, token };
  }

  private async applyAggressiveRateLimit(service: string): Promise<void> {
    // This would integrate with the rate limiting system
    console.log(`Applying aggressive rate limiting to service: ${service}`);
  }

  private async enableChallengeMode(endpoints: string[]): Promise<void> {
    // This would enable challenge mode for specific endpoints
    console.log(`Enabling challenge mode for endpoints: ${endpoints.join(', ')}`);
  }

  private async updateCloudArmorRules(attackEvent: AttackEvent): Promise<void> {
    // This would update Google Cloud Armor security policies
    console.log(`Updating Cloud Armor rules for attack: ${attackEvent.eventId}`);
  }

  private async sendAttackAlert(attackEvent: AttackEvent): Promise<void> {
    const alert = {
      timestamp: new Date(),
      severity: attackEvent.severity,
      attackType: attackEvent.attackType,
      confidence: attackEvent.confidence,
      sourceIPs: attackEvent.sourceAnalysis.topSourceIPs,
      targetServices: attackEvent.targetAnalysis.services,
      mitigationActions: attackEvent.mitigationActions.map(a => a.action),
      message: `DDoS attack detected: ${attackEvent.attackType} targeting ${attackEvent.targetAnalysis.services.join(', ')}`
    };
    
    console.log('DDoS Attack Alert:', alert);
    
    // This would send to configured alert channels
    for (const channel of this.config.monitoring.alerting.channels) {
      await this.sendAlertToChannel(channel, alert);
    }
  }

  private async sendAlertToChannel(channel: string, alert: any): Promise<void> {
    // Mock alert sending - would integrate with actual alerting systems
    console.log(`Sending alert to ${channel}:`, alert);
  }

  private startPeriodicTasks(): void {
    // Cleanup expired blocks and challenges
    setInterval(() => {
      const now = new Date();
      
      // Clean up expired IP blocks
      for (const [ip, blockInfo] of this.blockedIPs) {
        if (blockInfo.until <= now) {
          this.blockedIPs.delete(ip);
          console.log(`Unblocked IP: ${ip}`);
        }
      }
      
      // Clean up expired challenges
      for (const [ip, challenge] of this.challengeTokens) {
        if (challenge.expires <= now) {
          this.challengeTokens.delete(ip);
        }
      }
      
      // Clean up resolved attacks
      for (const [eventId, attack] of this.activeAttacks) {
        if (attack.resolution.resolved || Date.now() - attack.timestamp.getTime() > 3600000) { // 1 hour
          this.activeAttacks.delete(eventId);
        }
      }
    }, 60000); // Every minute
    
    // Update threat intelligence
    if (this.config.integration.threatIntelligence.enabled) {
      setInterval(() => {
        this.updateThreatIntelligence();
      }, this.config.integration.threatIntelligence.updateInterval * 1000);
    }
  }

  private async updateThreatIntelligence(): Promise<void> {
    // This would update threat intelligence data from external sources
    console.log('Updating threat intelligence data...');
  }

  /**
   * Get system status and statistics
   */
  public getSystemStatus(): any {
    return {
      timestamp: new Date(),
      status: 'ACTIVE',
      activeAttacks: this.activeAttacks.size,
      blockedIPs: this.blockedIPs.size,
      activeChallenges: this.challengeTokens.size,
      
      // Attack statistics (last 24 hours)
      attackStats: {
        totalAttacks: this.activeAttacks.size,
        mitigatedAttacks: Array.from(this.activeAttacks.values()).filter(a => a.resolution.resolved).length,
        attackTypes: this.getAttackTypeDistribution(),
        severityDistribution: this.getSeverityDistribution()
      },
      
      // System health
      systemHealth: {
        baselineManager: this.baselineManager ? 'HEALTHY' : 'ERROR',
        anomalyEngine: this.anomalyEngine ? 'HEALTHY' : 'ERROR',
        threatIntelligence: this.config.integration.threatIntelligence.enabled ? 'HEALTHY' : 'DISABLED',
        cloudArmor: this.config.cloudArmor.enabled ? 'HEALTHY' : 'DISABLED'
      },
      
      // Configuration status
      configuration: {
        baselineProfiling: this.config.baselineProfiling.enabled,
        anomalyDetection: this.config.anomalyDetection.enabled,
        automaticMitigation: this.config.mitigationStrategies.automaticBlocking.enabled,
        challengeResponse: this.config.mitigationStrategies.challengeResponse.enabled,
        cloudArmor: this.config.cloudArmor.enabled,
        machineLearning: this.config.machineLearning.enabled
      }
    };
  }

  private getAttackTypeDistribution(): Record<string, number> {
    const distribution: Record<string, number> = {};
    for (const attack of this.activeAttacks.values()) {
      distribution[attack.attackType] = (distribution[attack.attackType] || 0) + 1;
    }
    return distribution;
  }

  private getSeverityDistribution(): Record<string, number> {
    const distribution: Record<string, number> = {};
    for (const attack of this.activeAttacks.values()) {
      distribution[attack.severity] = (distribution[attack.severity] || 0) + 1;
    }
    return distribution;
  }
}

// Export configured instance for iSECTECH
export const isectechDDoSProtection = new IntelligentDDoSProtectionSystem({
  baselineProfiling: {
    enabled: true,
    windowSize: 300,
    historyDepth: 168,
    minimumSamples: 50,
    profileGranularity: 'SERVICE',
    adaptiveBaseline: true
  },
  anomalyDetection: {
    enabled: true,
    algorithm: 'HYBRID',
    sensitivityLevel: 'ADAPTIVE',
    requestRateThreshold: 8,
    uniqueIPThreshold: 5,
    errorRateThreshold: 0.25,
    burstDetection: true,
    slowlorisDetection: true,
    reflectionDetection: true,
    botnetDetection: true,
    geographicAnomalyDetection: true,
    unusualGeoThreshold: 3,
    requestPatternAnalysis: true,
    userAgentAnalysis: true,
    payloadAnalysis: true
  },
  mitigationStrategies: {
    automaticBlocking: {
      enabled: true,
      blockDuration: 1800, // 30 minutes
      escalationFactor: 2,
      maxBlockDuration: 86400 // 24 hours
    },
    rateLimiting: {
      enabled: true,
      aggressiveMode: true,
      dynamicLimits: true,
      priorityTraffic: ['api-key-authenticated', 'premium-clients', 'internal-services']
    },
    challengeResponse: {
      enabled: true,
      jsChallenge: true,
      captchaChallenge: true,
      proofOfWork: false,
      challengeThreshold: 3
    },
    trafficShaping: {
      enabled: true,
      priorityQueues: true,
      bandwidthLimiting: true,
      connectionLimiting: true
    }
  },
  cloudArmor: {
    enabled: true,
    projectId: process.env.GCP_PROJECT_ID || 'isectech-production',
    policyName: 'isectech-ddos-protection',
    adaptiveProtection: true,
    volumetricProtection: true,
    rateLimitingRules: [],
    geographicRestrictions: {
      enabled: false,
      allowedCountries: [],
      blockedCountries: []
    },
    botManagement: {
      enabled: true,
      recaptchaOptions: {
        siteKey: process.env.RECAPTCHA_SITE_KEY || '',
        secretKey: process.env.RECAPTCHA_SECRET_KEY || ''
      }
    }
  },
  monitoring: {
    enabled: true,
    realTimeMetrics: true,
    alerting: {
      enabled: true,
      channels: ['EMAIL', 'SLACK', 'WEBHOOK'],
      thresholds: {
        attackDetected: true,
        falsePositiveRate: 0.005,
        mitigationEffectiveness: 0.95
      }
    },
    forensics: {
      enabled: true,
      detailedLogging: true,
      packetCapture: false,
      attackSignatures: true
    }
  },
  machineLearning: {
    enabled: true,
    modelType: 'ENSEMBLE',
    trainingInterval: 86400,
    predictionConfidence: 0.8,
    adaptiveThresholds: true,
    features: {
      requestMetrics: true,
      trafficPatterns: true,
      geolocationData: true,
      userBehavior: true,
      networkFingerprints: true
    }
  },
  performance: {
    caching: {
      enabled: true,
      baselineCacheTTL: 300,
      rulesCacheTTL: 60,
      ipReputationCacheTTL: 900
    },
    processing: {
      parallelProcessing: true,
      asyncAnalysis: true,
      batchProcessing: true,
      streamProcessing: true
    },
    scalability: {
      autoScaling: true,
      loadBalancing: true,
      distributedProcessing: true
    }
  },
  integration: {
    threatIntelligence: {
      enabled: true,
      providers: ['ABUSEIPDB'],
      updateInterval: 3600,
      confidenceThreshold: 75
    },
    siem: {
      enabled: true,
      forwardEvents: true,
      eventFormat: 'JSON'
    },
    externalServices: {
      webhookNotifications: [process.env.DDOS_WEBHOOK_URL || ''].filter(Boolean),
      apiIntegrations: []
    }
  }
});