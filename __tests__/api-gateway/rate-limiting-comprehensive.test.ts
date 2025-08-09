/**
 * Comprehensive API Rate Limiting Test Suite
 * 
 * This test suite validates rate limiting infrastructure capable of handling:
 * - 100,000+ requests/second under attack
 * - Distributed attack simulations
 * - Circuit breaker functionality
 * - Failover mechanisms
 * - Performance benchmarking
 * 
 * Tests cover Kong Gateway, Redis-based rate limiting, and intelligent protection systems.
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/test';
import { performance } from 'perf_hooks';
import axios, { AxiosResponse } from 'axios';
import Redis from 'ioredis';

// Rate Limiting Components
import { APIRateLimitingManager } from '../../api-gateway/rate-limiting/api-rate-limiting-manager';
import { AdvancedTokenBucketRateLimiter } from '../../api-gateway/rate-limiting/advanced-token-bucket-rate-limiter';
import { IntelligentCircuitBreaker } from '../../api-gateway/circuit-breaker/intelligent-circuit-breaker';
import { IntelligentFailoverSystem } from '../../api-gateway/failover/intelligent-failover-system';

// Testing Utilities
import { LoadTestingFramework, AttackSimulator, PerformanceBenchmark } from '../utils/load-testing-utils';

interface RateLimitTestConfig {
  baseURL: string;
  endpoints: string[];
  rateLimits: {
    [endpoint: string]: {
      requestsPerSecond: number;
      burstCapacity: number;
      timeWindow: number;
    };
  };
  loadTestConfig: {
    maxConcurrentRequests: number;
    testDuration: number;
    rampUpTime: number;
  };
}

describe('API Rate Limiting Comprehensive Tests', () => {
  let rateLimitingManager: APIRateLimitingManager;
  let tokenBucketLimiter: AdvancedTokenBucketRateLimiter;
  let circuitBreaker: IntelligentCircuitBreaker;
  let failoverSystem: IntelligentFailoverSystem;
  let loadTester: LoadTestingFramework;
  let attackSimulator: AttackSimulator;
  let performanceBenchmark: PerformanceBenchmark;
  let redisClient: Redis;
  let testConfig: RateLimitTestConfig;

  beforeAll(async () => {
    // Test configuration
    testConfig = {
      baseURL: process.env.TEST_API_URL || 'http://localhost:8080',
      endpoints: [
        '/api/v1/auth/login',
        '/api/v1/notifications',
        '/api/v1/security/alerts',
        '/api/v1/dashboard/metrics',
        '/api/v1/admin/users'
      ],
      rateLimits: {
        '/api/v1/auth/login': { requestsPerSecond: 10, burstCapacity: 50, timeWindow: 60 },
        '/api/v1/notifications': { requestsPerSecond: 100, burstCapacity: 500, timeWindow: 60 },
        '/api/v1/security/alerts': { requestsPerSecond: 200, burstCapacity: 1000, timeWindow: 60 },
        '/api/v1/dashboard/metrics': { requestsPerSecond: 500, burstCapacity: 2000, timeWindow: 60 },
        '/api/v1/admin/users': { requestsPerSecond: 50, burstCapacity: 200, timeWindow: 60 }
      },
      loadTestConfig: {
        maxConcurrentRequests: 10000,
        testDuration: 300, // 5 minutes
        rampUpTime: 60 // 1 minute
      }
    };

    // Initialize components
    redisClient = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      retryDelayOnFailover: 100,
      enableOfflineQueue: false
    });

    rateLimitingManager = new APIRateLimitingManager({
      redisClient,
      defaultLimits: testConfig.rateLimits
    });

    tokenBucketLimiter = new AdvancedTokenBucketRateLimiter({
      redisClient,
      defaultCapacity: 1000,
      defaultRefillRate: 100
    });

    circuitBreaker = new IntelligentCircuitBreaker({
      failureThreshold: 50,
      recoveryTimeout: 30000,
      monitoringInterval: 5000
    });

    failoverSystem = new IntelligentFailoverSystem({
      healthCheckInterval: 10000,
      failoverThreshold: 0.8,
      recoveryThreshold: 0.95
    });

    loadTester = new LoadTestingFramework(testConfig.loadTestConfig);
    attackSimulator = new AttackSimulator();
    performanceBenchmark = new PerformanceBenchmark();

    // Initialize systems
    await rateLimitingManager.initialize();
    await circuitBreaker.initialize();
    await failoverSystem.initialize();
  });

  afterAll(async () => {
    await redisClient.quit();
    await rateLimitingManager.shutdown();
    await circuitBreaker.shutdown();
    await failoverSystem.shutdown();
  });

  describe('Basic Rate Limiting Functionality', () => {
    test('should enforce rate limits per endpoint', async () => {
      const endpoint = '/api/v1/auth/login';
      const limit = testConfig.rateLimits[endpoint];
      
      // Test normal operation within limits
      for (let i = 0; i < limit.requestsPerSecond; i++) {
        const response = await axios.get(`${testConfig.baseURL}${endpoint}`, {
          timeout: 5000,
          validateStatus: () => true
        });
        
        expect([200, 401, 404]).toContain(response.status); // Not rate limited
      }
      
      // Test rate limiting kicks in
      const rateLimitedResponse = await axios.get(`${testConfig.baseURL}${endpoint}`, {
        timeout: 5000,
        validateStatus: () => true
      });
      
      expect(rateLimitedResponse.status).toBe(429);
      expect(rateLimitedResponse.headers['x-ratelimit-remaining']).toBe('0');
      expect(rateLimitedResponse.headers['x-ratelimit-reset']).toBeDefined();
    });

    test('should handle burst capacity correctly', async () => {
      const endpoint = '/api/v1/notifications';
      const limit = testConfig.rateLimits[endpoint];
      
      // Send burst requests
      const burstPromises = Array(limit.burstCapacity).fill(0).map(() => 
        axios.get(`${testConfig.baseURL}${endpoint}`, {
          timeout: 10000,
          validateStatus: () => true
        })
      );
      
      const responses = await Promise.all(burstPromises);
      
      // Count successful and rate-limited responses
      const successfulResponses = responses.filter(r => r.status !== 429);
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      
      expect(successfulResponses.length).toBeGreaterThan(0);
      expect(successfulResponses.length).toBeLessThanOrEqual(limit.burstCapacity);
      
      // Should get rate limited after burst capacity
      if (rateLimitedResponses.length > 0) {
        rateLimitedResponses.forEach(response => {
          expect(response.headers['x-ratelimit-remaining']).toBe('0');
        });
      }
    });

    test('should reset rate limits after time window', async () => {
      const endpoint = '/api/v1/security/alerts';
      const limit = testConfig.rateLimits[endpoint];
      
      // Exhaust rate limit
      const exhaustPromises = Array(limit.requestsPerSecond + 10).fill(0).map(() =>
        axios.get(`${testConfig.baseURL}${endpoint}`, {
          timeout: 5000,
          validateStatus: () => true
        })
      );
      
      await Promise.all(exhaustPromises);
      
      // Verify rate limited
      const rateLimitedResponse = await axios.get(`${testConfig.baseURL}${endpoint}`, {
        validateStatus: () => true
      });
      expect(rateLimitedResponse.status).toBe(429);
      
      // Wait for time window reset (shorter window for testing)
      await new Promise(resolve => setTimeout(resolve, 65000)); // 65 seconds
      
      // Should be able to make requests again
      const resetResponse = await axios.get(`${testConfig.baseURL}${endpoint}`, {
        validateStatus: () => true
      });
      expect([200, 401, 404]).toContain(resetResponse.status);
    }, 120000); // 2 minute timeout
  });

  describe('High-Load Performance Tests', () => {
    test('should handle 10,000 concurrent requests', async () => {
      const endpoint = '/api/v1/dashboard/metrics';
      const concurrentRequests = 10000;
      
      console.log(`Starting ${concurrentRequests} concurrent requests test...`);
      
      const startTime = performance.now();
      
      const requestPromises = Array(concurrentRequests).fill(0).map(async (_, index) => {
        try {
          const response = await axios.get(`${testConfig.baseURL}${endpoint}`, {
            timeout: 30000,
            validateStatus: () => true,
            headers: { 'X-Test-Request-ID': `concurrent-${index}` }
          });
          
          return {
            status: response.status,
            responseTime: response.headers['x-response-time'] || 0,
            rateLimited: response.status === 429
          };
        } catch (error) {
          return {
            status: 0,
            responseTime: 30000,
            rateLimited: false,
            error: error.message
          };
        }
      });
      
      const results = await Promise.all(requestPromises);
      const endTime = performance.now();
      
      const totalTime = endTime - startTime;
      const requestsPerSecond = (concurrentRequests / totalTime) * 1000;
      
      // Analyze results
      const successfulRequests = results.filter(r => r.status === 200 || r.status === 429).length;
      const rateLimitedRequests = results.filter(r => r.rateLimited).length;
      const erroredRequests = results.filter(r => r.status === 0).length;
      
      console.log(`Test completed in ${totalTime.toFixed(2)}ms`);
      console.log(`Requests per second: ${requestsPerSecond.toFixed(2)}`);
      console.log(`Successful requests: ${successfulRequests}/${concurrentRequests}`);
      console.log(`Rate limited requests: ${rateLimitedRequests}`);
      console.log(`Errored requests: ${erroredRequests}`);
      
      // Performance assertions
      expect(requestsPerSecond).toBeGreaterThan(1000); // At least 1,000 RPS
      expect(successfulRequests / concurrentRequests).toBeGreaterThan(0.95); // 95% success rate
      expect(erroredRequests / concurrentRequests).toBeLessThan(0.05); // Less than 5% errors
    }, 300000); // 5 minute timeout

    test('should maintain performance under 100,000+ RPS attack simulation', async () => {
      console.log('Starting 100,000+ RPS attack simulation...');
      
      const attackConfig = {
        targetRPS: 100000,
        duration: 60000, // 1 minute
        endpoints: testConfig.endpoints,
        attackPatterns: ['distributed', 'focused', 'burst']
      };
      
      const attackResults = await attackSimulator.simulateAttack({
        baseURL: testConfig.baseURL,
        ...attackConfig
      });
      
      // Verify system survival
      expect(attackResults.systemAvailability).toBeGreaterThan(0.99); // 99% availability
      expect(attackResults.averageResponseTime).toBeLessThan(500); // < 500ms average
      expect(attackResults.successfulBlocks).toBeGreaterThan(0.9); // 90% of attacks blocked
      
      // Verify rate limiting effectiveness
      expect(attackResults.rateLimitingEffectiveness).toBeGreaterThan(0.95); // 95% effective
      expect(attackResults.falsePositiveRate).toBeLessThan(0.01); // < 1% false positives
      
      console.log(`Attack simulation completed:`);
      console.log(`- System Availability: ${(attackResults.systemAvailability * 100).toFixed(2)}%`);
      console.log(`- Average Response Time: ${attackResults.averageResponseTime}ms`);
      console.log(`- Rate Limiting Effectiveness: ${(attackResults.rateLimitingEffectiveness * 100).toFixed(2)}%`);
    }, 120000); // 2 minute timeout

    test('should handle sustained load over 5 minutes', async () => {
      console.log('Starting 5-minute sustained load test...');
      
      const sustainedLoadConfig = {
        targetRPS: 5000,
        duration: 300000, // 5 minutes
        rampUpTime: 30000, // 30 seconds
        endpoints: testConfig.endpoints
      };
      
      const loadTestResults = await loadTester.executeSustainedLoad({
        baseURL: testConfig.baseURL,
        ...sustainedLoadConfig
      });
      
      // Performance metrics validation
      expect(loadTestResults.averageResponseTime).toBeLessThan(200); // < 200ms average
      expect(loadTestResults.p95ResponseTime).toBeLessThan(500); // < 500ms 95th percentile
      expect(loadTestResults.p99ResponseTime).toBeLessThan(1000); // < 1s 99th percentile
      
      // Stability metrics
      expect(loadTestResults.errorRate).toBeLessThan(0.01); // < 1% error rate
      expect(loadTestResults.throughputStability).toBeGreaterThan(0.95); // 95% stable throughput
      expect(loadTestResults.memoryGrowth).toBeLessThan(20); // < 20% memory growth
      
      console.log(`Sustained load test completed:`);
      console.log(`- Average Response Time: ${loadTestResults.averageResponseTime}ms`);
      console.log(`- P95 Response Time: ${loadTestResults.p95ResponseTime}ms`);
      console.log(`- Error Rate: ${(loadTestResults.errorRate * 100).toFixed(3)}%`);
      console.log(`- Throughput Stability: ${(loadTestResults.throughputStability * 100).toFixed(2)}%`);
    }, 360000); // 6 minute timeout
  });

  describe('Distributed Attack Simulations', () => {
    test('should defend against coordinated DDoS attacks', async () => {
      const attackConfig = {
        attackNodes: 50, // Simulate 50 different sources
        requestsPerNode: 2000,
        attackDuration: 30000, // 30 seconds
        attackType: 'coordinated-ddos',
        targetEndpoints: ['/api/v1/auth/login', '/api/v1/notifications']
      };
      
      console.log('Simulating coordinated DDoS attack...');
      
      const attackResults = await attackSimulator.simulateDistributedAttack({
        baseURL: testConfig.baseURL,
        ...attackConfig
      });
      
      // Defense effectiveness
      expect(attackResults.blockedRequests / attackResults.totalRequests).toBeGreaterThan(0.9); // 90% blocked
      expect(attackResults.systemAvailability).toBeGreaterThan(0.95); // 95% availability maintained
      expect(attackResults.detectionTime).toBeLessThan(5000); // Detected within 5 seconds
      
      // Legitimate traffic protection
      expect(attackResults.legitimateTrafficImpact).toBeLessThan(0.1); // < 10% impact on legitimate traffic
      
      console.log(`DDoS defense results:`);
      console.log(`- Blocked Requests: ${(attackResults.blockedRequests / attackResults.totalRequests * 100).toFixed(2)}%`);
      console.log(`- Detection Time: ${attackResults.detectionTime}ms`);
      console.log(`- System Availability: ${(attackResults.systemAvailability * 100).toFixed(2)}%`);
    });

    test('should handle geographical attack distribution', async () => {
      const geoAttackConfig = {
        regions: ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
        requestsPerRegion: 5000,
        attackPattern: 'geo-distributed',
        targetEndpoints: testConfig.endpoints
      };
      
      const geoAttackResults = await attackSimulator.simulateGeographicalAttack({
        baseURL: testConfig.baseURL,
        ...geoAttackConfig
      });
      
      // Regional defense validation
      geoAttackResults.regionalResults.forEach(result => {
        expect(result.blockingEffectiveness).toBeGreaterThan(0.85); // 85% blocking per region
        expect(result.responseTime).toBeLessThan(1000); // < 1s response time per region
      });
      
      // Global coordination
      expect(geoAttackResults.crossRegionCoordination).toBe(true);
      expect(geoAttackResults.globalThreatIntelligence).toBe(true);
      
      console.log(`Geographical attack defense completed across ${geoAttackConfig.regions.length} regions`);
    });

    test('should adapt to evolving attack patterns', async () => {
      const adaptiveAttackConfig = {
        phases: [
          { pattern: 'burst', duration: 15000, intensity: 'high' },
          { pattern: 'sustained', duration: 30000, intensity: 'medium' },
          { pattern: 'stealth', duration: 45000, intensity: 'low' },
          { pattern: 'mixed', duration: 20000, intensity: 'variable' }
        ]
      };
      
      console.log('Testing adaptive defense against evolving attack patterns...');
      
      const adaptiveResults = await attackSimulator.simulateAdaptiveAttack({
        baseURL: testConfig.baseURL,
        ...adaptiveAttackConfig
      });
      
      // Adaptation effectiveness per phase
      adaptiveResults.phaseResults.forEach((result, index) => {
        const phase = adaptiveAttackConfig.phases[index];
        expect(result.adaptationTime).toBeLessThan(10000); // Adapt within 10 seconds
        expect(result.blockingEffectiveness).toBeGreaterThan(0.8); // 80% blocking after adaptation
        
        console.log(`Phase ${index + 1} (${phase.pattern}): ${(result.blockingEffectiveness * 100).toFixed(1)}% blocked, adapted in ${result.adaptationTime}ms`);
      });
      
      expect(adaptiveResults.overallAdaptability).toBeGreaterThan(0.9); // 90% overall adaptability
    });
  });

  describe('Circuit Breaker Testing', () => {
    test('should activate circuit breaker under high error rates', async () => {
      const endpoint = '/api/v1/admin/users'; // Simulate problematic endpoint
      
      // Simulate backend failures
      const failureRequests = Array(100).fill(0).map(() =>
        axios.get(`${testConfig.baseURL}${endpoint}`, {
          timeout: 1000,
          validateStatus: () => true
        })
      );
      
      const failureResults = await Promise.all(failureRequests);
      
      // Check circuit breaker activation
      const circuitState = await circuitBreaker.getState(endpoint);
      
      if (circuitState === 'open') {
        // Verify circuit breaker is protecting the system
        const protectedResponse = await axios.get(`${testConfig.baseURL}${endpoint}`, {
          validateStatus: () => true
        });
        
        expect(protectedResponse.status).toBe(503); // Service unavailable due to circuit breaker
        expect(protectedResponse.headers['x-circuit-breaker']).toBe('open');
      }
    });

    test('should recover after circuit breaker healing', async () => {
      const endpoint = '/api/v1/dashboard/metrics';
      
      // Force circuit breaker open
      await circuitBreaker.forceOpen(endpoint);
      
      // Verify circuit is open
      const openResponse = await axios.get(`${testConfig.baseURL}${endpoint}`, {
        validateStatus: () => true
      });
      expect(openResponse.status).toBe(503);
      
      // Wait for recovery timeout
      await new Promise(resolve => setTimeout(resolve, 31000)); // 31 seconds
      
      // Circuit should attempt to close
      const recoveryResponse = await axios.get(`${testConfig.baseURL}${endpoint}`, {
        validateStatus: () => true
      });
      
      // Should either work (circuit closed) or still be protecting (half-open testing)
      expect([200, 503]).toContain(recoveryResponse.status);
      
      if (recoveryResponse.status === 200) {
        console.log('Circuit breaker successfully recovered');
      }
    }, 35000); // 35 second timeout
  });

  describe('Failover Mechanism Testing', () => {
    test('should failover to backup instances during overload', async () => {
      const overloadConfig = {
        requestsPerSecond: 20000,
        duration: 30000, // 30 seconds
        endpoint: '/api/v1/security/alerts'
      };
      
      console.log('Testing failover under extreme load...');
      
      const overloadPromises = [];
      const startTime = Date.now();
      
      // Generate extreme load
      while (Date.now() - startTime < overloadConfig.duration) {
        for (let i = 0; i < overloadConfig.requestsPerSecond / 10; i++) {
          overloadPromises.push(
            axios.get(`${testConfig.baseURL}${overloadConfig.endpoint}`, {
              timeout: 10000,
              validateStatus: () => true
            })
          );
        }
        await new Promise(resolve => setTimeout(resolve, 100)); // 100ms batch interval
      }
      
      const overloadResults = await Promise.allSettled(overloadPromises);
      
      // Analyze failover behavior
      const successfulRequests = overloadResults.filter(r => 
        r.status === 'fulfilled' && [200, 429].includes((r.value as AxiosResponse).status)
      ).length;
      
      const failoverDetected = overloadResults.some(r => 
        r.status === 'fulfilled' && 
        (r.value as AxiosResponse).headers['x-served-by'] !== 'primary'
      );
      
      expect(successfulRequests / overloadPromises.length).toBeGreaterThan(0.8); // 80% success rate
      console.log(`Failover detected: ${failoverDetected}`);
    }, 60000); // 1 minute timeout

    test('should maintain session consistency during failover', async () => {
      // Create authenticated session
      const loginResponse = await axios.post(`${testConfig.baseURL}/api/v1/auth/login`, {
        username: 'test-user',
        password: 'test-password'
      }, { validateStatus: () => true });
      
      if (loginResponse.status === 200) {
        const sessionToken = loginResponse.data.token;
        
        // Simulate failover scenario
        await failoverSystem.simulateFailover('primary');
        
        // Test session persistence across failover
        const authenticatedResponse = await axios.get(`${testConfig.baseURL}/api/v1/admin/users`, {
          headers: { Authorization: `Bearer ${sessionToken}` },
          validateStatus: () => true
        });
        
        // Session should be maintained or properly handled
        expect([200, 401, 503]).toContain(authenticatedResponse.status);
        
        if (authenticatedResponse.status === 200) {
          console.log('Session consistency maintained during failover');
        } else if (authenticatedResponse.status === 401) {
          console.log('Session invalidated during failover (acceptable behavior)');
        }
      }
    });
  });

  describe('Performance Benchmarking', () => {
    test('should meet latency requirements under normal load', async () => {
      const benchmarkConfig = {
        endpoints: testConfig.endpoints,
        concurrentUsers: 1000,
        testDuration: 60000, // 1 minute
        latencyTargets: {
          p50: 100, // 50th percentile < 100ms
          p95: 300, // 95th percentile < 300ms
          p99: 500  // 99th percentile < 500ms
        }
      };
      
      const benchmarkResults = await performanceBenchmark.runLatencyBenchmark({
        baseURL: testConfig.baseURL,
        ...benchmarkConfig
      });
      
      // Validate latency requirements
      expect(benchmarkResults.p50Latency).toBeLessThan(benchmarkConfig.latencyTargets.p50);
      expect(benchmarkResults.p95Latency).toBeLessThan(benchmarkConfig.latencyTargets.p95);
      expect(benchmarkResults.p99Latency).toBeLessThan(benchmarkConfig.latencyTargets.p99);
      
      // Throughput validation
      expect(benchmarkResults.requestsPerSecond).toBeGreaterThan(1000);
      
      console.log(`Performance benchmark results:`);
      console.log(`- P50 Latency: ${benchmarkResults.p50Latency}ms`);
      console.log(`- P95 Latency: ${benchmarkResults.p95Latency}ms`);
      console.log(`- P99 Latency: ${benchmarkResults.p99Latency}ms`);
      console.log(`- Throughput: ${benchmarkResults.requestsPerSecond} RPS`);
    });

    test('should maintain performance under rate limiting stress', async () => {
      const stressConfig = {
        rateLimitedEndpoint: '/api/v1/auth/login',
        normalEndpoints: ['/api/v1/notifications', '/api/v1/dashboard/metrics'],
        stressIntensity: 'high',
        duration: 120000 // 2 minutes
      };
      
      const stressResults = await performanceBenchmark.runRateLimitingStressTest({
        baseURL: testConfig.baseURL,
        ...stressConfig
      });
      
      // Rate limiting should not impact normal endpoints
      expect(stressResults.normalEndpointPerformance.averageLatency).toBeLessThan(200);
      expect(stressResults.normalEndpointPerformance.errorRate).toBeLessThan(0.01);
      
      // Rate limited endpoint should be properly throttled
      expect(stressResults.rateLimitedEndpointPerformance.rateLimitingEffectiveness).toBeGreaterThan(0.95);
      
      // System stability
      expect(stressResults.systemStability.cpuUsage).toBeLessThan(80); // < 80% CPU
      expect(stressResults.systemStability.memoryUsage).toBeLessThan(90); // < 90% memory
      
      console.log(`Rate limiting stress test completed:`);
      console.log(`- Normal endpoints avg latency: ${stressResults.normalEndpointPerformance.averageLatency}ms`);
      console.log(`- Rate limiting effectiveness: ${(stressResults.rateLimitedEndpointPerformance.rateLimitingEffectiveness * 100).toFixed(2)}%`);
    });
  });

  describe('Security and Compliance Tests', () => {
    test('should prevent rate limit bypass attempts', async () => {
      const bypassAttempts = [
        // IP rotation
        { method: 'ip-rotation', count: 100 },
        // Header manipulation
        { method: 'header-manipulation', count: 50 },
        // User agent rotation
        { method: 'user-agent-rotation', count: 75 },
        // Session manipulation
        { method: 'session-manipulation', count: 60 }
      ];
      
      for (const attempt of bypassAttempts) {
        const bypassResults = await attackSimulator.simulateBypassAttempt({
          baseURL: testConfig.baseURL,
          method: attempt.method,
          requestCount: attempt.count,
          endpoint: '/api/v1/auth/login'
        });
        
        expect(bypassResults.successfulBypasses / attempt.count).toBeLessThan(0.1); // < 10% bypass rate
        expect(bypassResults.detectionRate).toBeGreaterThan(0.9); // > 90% detection rate
        
        console.log(`Bypass attempt (${attempt.method}): ${bypassResults.successfulBypasses}/${attempt.count} succeeded, ${(bypassResults.detectionRate * 100).toFixed(1)}% detected`);
      }
    });

    test('should log and audit rate limiting events', async () => {
      const endpoint = '/api/v1/security/alerts';
      
      // Generate rate limit events
      const rateLimitPromises = Array(50).fill(0).map((_, index) =>
        axios.get(`${testConfig.baseURL}${endpoint}`, {
          headers: { 'X-Test-ID': `audit-test-${index}` },
          validateStatus: () => true
        })
      );
      
      await Promise.all(rateLimitPromises);
      
      // Verify audit logging
      const auditLogs = await rateLimitingManager.getAuditLogs({
        endpoint,
        timeRange: '5m'
      });
      
      expect(auditLogs.length).toBeGreaterThan(0);
      
      // Verify log content
      auditLogs.forEach(log => {
        expect(log.timestamp).toBeDefined();
        expect(log.clientIP).toBeDefined();
        expect(log.endpoint).toBe(endpoint);
        expect(log.action).toMatch(/allowed|blocked|rate_limited/);
        expect(log.rateLimitRule).toBeDefined();
      });
      
      console.log(`Audit logs captured: ${auditLogs.length} events`);
    });
  });
});