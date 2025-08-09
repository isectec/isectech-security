/**
 * Security Processing Performance Microbenchmarks
 * iSECTECH Protect - Critical Performance Testing
 * Measures performance of security-critical processing paths
 */

import { performance } from 'perf_hooks';

// Mock security processing modules
const mockSecurityModules = {
  cryptoUtils: {
    hashPassword: (password: string) => {
      const start = performance.now();
      // Simulate bcrypt-like operation
      let hash = '';
      for (let i = 0; i < 10000; i++) {
        hash += Math.random().toString(36);
      }
      return { hash, duration: performance.now() - start };
    },
    
    encryptToken: (token: string) => {
      const start = performance.now();
      // Simulate AES encryption
      const encrypted = Buffer.from(token).toString('base64');
      return { encrypted, duration: performance.now() - start };
    },
    
    verifyJWT: (token: string) => {
      const start = performance.now();
      // Simulate JWT verification
      const parts = token.split('.');
      const decoded = parts.length === 3;
      return { decoded, duration: performance.now() - start };
    },
  },

  threatAnalysis: {
    analyzeNetworkPattern: (events: any[]) => {
      const start = performance.now();
      
      // Simulate complex pattern analysis
      const patterns = [];
      for (const event of events) {
        const pattern = {
          sourceIp: event.source_ip,
          confidence: Math.random(),
          riskScore: Math.random() * 100,
        };
        patterns.push(pattern);
      }
      
      return { patterns, duration: performance.now() - start };
    },
    
    correlateAlerts: (alerts: any[]) => {
      const start = performance.now();
      
      // Simulate alert correlation algorithm
      const correlations = [];
      for (let i = 0; i < alerts.length; i++) {
        for (let j = i + 1; j < alerts.length; j++) {
          const similarity = Math.random();
          if (similarity > 0.7) {
            correlations.push({ alert1: i, alert2: j, similarity });
          }
        }
      }
      
      return { correlations, duration: performance.now() - start };
    },
    
    calculateRiskScore: (indicators: any[]) => {
      const start = performance.now();
      
      // Simulate risk calculation
      let totalRisk = 0;
      for (const indicator of indicators) {
        totalRisk += indicator.severity * indicator.confidence * Math.random();
      }
      
      return { riskScore: totalRisk, duration: performance.now() - start };
    },
  },

  eventProcessing: {
    normalizeEvent: (rawEvent: any) => {
      const start = performance.now();
      
      // Simulate event normalization
      const normalized = {
        ...rawEvent,
        timestamp: new Date(rawEvent.timestamp).toISOString(),
        severity: rawEvent.severity?.toUpperCase() || 'MEDIUM',
        source_ip: rawEvent.source_ip?.trim(),
        normalized_at: new Date().toISOString(),
      };
      
      return { normalized, duration: performance.now() - start };
    },
    
    enrichEvent: (event: any) => {
      const start = performance.now();
      
      // Simulate threat intelligence enrichment
      const enriched = {
        ...event,
        geolocation: { country: 'US', city: 'New York' },
        threat_intel: { reputation: 'clean', sources: ['feed1', 'feed2'] },
        asset_context: { criticality: 'high', owner: 'IT Dept' },
      };
      
      return { enriched, duration: performance.now() - start };
    },
    
    validateEvent: (event: any) => {
      const start = performance.now();
      
      // Simulate comprehensive event validation
      const validations = [
        'timestamp_format',
        'ip_address_format',
        'severity_level',
        'required_fields',
        'data_types',
      ];
      
      const results = validations.map(check => ({
        check,
        passed: Math.random() > 0.1, // 90% pass rate
      }));
      
      return { results, duration: performance.now() - start };
    },
  },
};

// Benchmark utility functions
function runBenchmark(name: string, fn: () => any, iterations: number = 1000): BenchmarkResult {
  const durations: number[] = [];
  let minDuration = Infinity;
  let maxDuration = 0;
  
  // Warm up
  for (let i = 0; i < 10; i++) {
    fn();
  }
  
  // Actual benchmark
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
    const duration = performance.now() - start;
    
    durations.push(duration);
    minDuration = Math.min(minDuration, duration);
    maxDuration = Math.max(maxDuration, duration);
  }
  
  const avgDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
  const sortedDurations = durations.sort((a, b) => a - b);
  const p50 = sortedDurations[Math.floor(iterations * 0.5)];
  const p95 = sortedDurations[Math.floor(iterations * 0.95)];
  const p99 = sortedDurations[Math.floor(iterations * 0.99)];
  
  return {
    name,
    iterations,
    avgDuration,
    minDuration,
    maxDuration,
    p50,
    p95,
    p99,
    opsPerSecond: 1000 / avgDuration,
  };
}

interface BenchmarkResult {
  name: string;
  iterations: number;
  avgDuration: number;
  minDuration: number;
  maxDuration: number;
  p50: number;
  p95: number;
  p99: number;
  opsPerSecond: number;
}

function assertPerformance(result: BenchmarkResult, thresholds: {
  avgDuration?: number;
  p95?: number;
  p99?: number;
  opsPerSecond?: number;
}) {
  if (thresholds.avgDuration && result.avgDuration > thresholds.avgDuration) {
    throw new Error(`${result.name}: Average duration ${result.avgDuration}ms exceeds threshold ${thresholds.avgDuration}ms`);
  }
  
  if (thresholds.p95 && result.p95 > thresholds.p95) {
    throw new Error(`${result.name}: P95 duration ${result.p95}ms exceeds threshold ${thresholds.p95}ms`);
  }
  
  if (thresholds.p99 && result.p99 > thresholds.p99) {
    throw new Error(`${result.name}: P99 duration ${result.p99}ms exceeds threshold ${thresholds.p99}ms`);
  }
  
  if (thresholds.opsPerSecond && result.opsPerSecond < thresholds.opsPerSecond) {
    throw new Error(`${result.name}: Operations per second ${result.opsPerSecond} below threshold ${thresholds.opsPerSecond}`);
  }
}

describe('Security Processing Performance Benchmarks', () => {
  let benchmarkResults: BenchmarkResult[] = [];

  afterAll(() => {
    // Print comprehensive benchmark report
    console.log('\n🚀 Security Processing Performance Report');
    console.log('=========================================');
    
    benchmarkResults.forEach(result => {
      console.log(`\n📊 ${result.name}`);
      console.log(`   Operations: ${result.iterations.toLocaleString()}`);
      console.log(`   Avg Duration: ${result.avgDuration.toFixed(3)}ms`);
      console.log(`   Min Duration: ${result.minDuration.toFixed(3)}ms`);
      console.log(`   Max Duration: ${result.maxDuration.toFixed(3)}ms`);
      console.log(`   P50: ${result.p50.toFixed(3)}ms`);
      console.log(`   P95: ${result.p95.toFixed(3)}ms`);
      console.log(`   P99: ${result.p99.toFixed(3)}ms`);
      console.log(`   Ops/sec: ${result.opsPerSecond.toLocaleString()}`);
    });
  });

  describe('🔐 Cryptographic Operations', () => {
    it('should hash passwords within performance threshold', () => {
      const result = runBenchmark(
        'Password Hashing',
        () => mockSecurityModules.cryptoUtils.hashPassword('TestPassword123!'),
        100 // Fewer iterations for expensive operations
      );
      
      benchmarkResults.push(result);
      
      // Password hashing should be secure but not too slow for UX
      assertPerformance(result, {
        avgDuration: 50, // 50ms average
        p95: 100, // 100ms P95
        opsPerSecond: 10, // At least 10 ops/sec
      });
    });

    it('should encrypt tokens rapidly', () => {
      const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      
      const result = runBenchmark(
        'Token Encryption',
        () => mockSecurityModules.cryptoUtils.encryptToken(testToken),
        5000
      );
      
      benchmarkResults.push(result);
      
      // Token encryption should be very fast
      assertPerformance(result, {
        avgDuration: 1, // 1ms average
        p95: 5, // 5ms P95
        opsPerSecond: 500, // At least 500 ops/sec
      });
    });

    it('should verify JWT tokens quickly', () => {
      const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      
      const result = runBenchmark(
        'JWT Verification',
        () => mockSecurityModules.cryptoUtils.verifyJWT(testToken),
        10000
      );
      
      benchmarkResults.push(result);
      
      // JWT verification is critical path - must be very fast
      assertPerformance(result, {
        avgDuration: 0.5, // 0.5ms average
        p95: 2, // 2ms P95
        opsPerSecond: 1000, // At least 1000 ops/sec
      });
    });
  });

  describe('🔍 Threat Analysis', () => {
    it('should analyze network patterns efficiently', () => {
      const testEvents = Array.from({ length: 100 }, (_, i) => ({
        id: `event-${i}`,
        source_ip: `192.168.1.${i % 255}`,
        destination_ip: '10.0.0.1',
        protocol: 'TCP',
        port: 443,
        bytes: Math.floor(Math.random() * 10000),
        timestamp: new Date().toISOString(),
      }));
      
      const result = runBenchmark(
        'Network Pattern Analysis (100 events)',
        () => mockSecurityModules.threatAnalysis.analyzeNetworkPattern(testEvents),
        1000
      );
      
      benchmarkResults.push(result);
      
      // Pattern analysis for 100 events should complete quickly
      assertPerformance(result, {
        avgDuration: 10, // 10ms average
        p95: 25, // 25ms P95
        opsPerSecond: 50, // At least 50 ops/sec
      });
    });

    it('should correlate alerts within SLA', () => {
      const testAlerts = Array.from({ length: 50 }, (_, i) => ({
        id: `alert-${i}`,
        title: `Test Alert ${i}`,
        severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][i % 4],
        source_ip: `192.168.1.${i % 10}`,
        timestamp: new Date(Date.now() - i * 60000).toISOString(),
      }));
      
      const result = runBenchmark(
        'Alert Correlation (50 alerts)',
        () => mockSecurityModules.threatAnalysis.correlateAlerts(testAlerts),
        500
      );
      
      benchmarkResults.push(result);
      
      // Alert correlation is O(n²) but should still be fast for reasonable sizes
      assertPerformance(result, {
        avgDuration: 20, // 20ms average
        p95: 50, // 50ms P95
        opsPerSecond: 25, // At least 25 ops/sec
      });
    });

    it('should calculate risk scores rapidly', () => {
      const testIndicators = Array.from({ length: 20 }, (_, i) => ({
        type: 'ip',
        value: `192.168.1.${i}`,
        severity: Math.random() * 10,
        confidence: Math.random(),
        source: 'threat_feed',
      }));
      
      const result = runBenchmark(
        'Risk Score Calculation (20 indicators)',
        () => mockSecurityModules.threatAnalysis.calculateRiskScore(testIndicators),
        2000
      );
      
      benchmarkResults.push(result);
      
      // Risk calculation should be very fast
      assertPerformance(result, {
        avgDuration: 5, // 5ms average
        p95: 15, // 15ms P95
        opsPerSecond: 100, // At least 100 ops/sec
      });
    });
  });

  describe('⚡ Event Processing Pipeline', () => {
    it('should normalize events at high throughput', () => {
      const testEvent = {
        timestamp: '2025-01-02T10:30:00.000Z',
        severity: 'high',
        source_ip: '  192.168.1.100  ',
        destination_ip: '10.0.0.1',
        event_type: 'network_anomaly',
        raw_data: 'TCP connection from suspicious IP',
      };
      
      const result = runBenchmark(
        'Event Normalization',
        () => mockSecurityModules.eventProcessing.normalizeEvent(testEvent),
        10000
      );
      
      benchmarkResults.push(result);
      
      // Event normalization is in the hot path - must be very fast
      assertPerformance(result, {
        avgDuration: 1, // 1ms average
        p95: 3, // 3ms P95
        opsPerSecond: 500, // At least 500 ops/sec
      });
    });

    it('should enrich events efficiently', () => {
      const testEvent = {
        id: 'event-123',
        source_ip: '192.168.1.100',
        destination_ip: '10.0.0.1',
        event_type: 'network_anomaly',
        timestamp: '2025-01-02T10:30:00.000Z',
      };
      
      const result = runBenchmark(
        'Event Enrichment',
        () => mockSecurityModules.eventProcessing.enrichEvent(testEvent),
        5000
      );
      
      benchmarkResults.push(result);
      
      // Event enrichment includes external lookups but should be cached
      assertPerformance(result, {
        avgDuration: 5, // 5ms average
        p95: 15, // 15ms P95
        opsPerSecond: 100, // At least 100 ops/sec
      });
    });

    it('should validate events quickly', () => {
      const testEvent = {
        id: 'event-456',
        timestamp: '2025-01-02T10:30:00.000Z',
        severity: 'HIGH',
        source_ip: '192.168.1.100',
        destination_ip: '10.0.0.1',
        event_type: 'malware_detection',
        description: 'Malicious file detected',
      };
      
      const result = runBenchmark(
        'Event Validation',
        () => mockSecurityModules.eventProcessing.validateEvent(testEvent),
        5000
      );
      
      benchmarkResults.push(result);
      
      // Event validation should be fast to not bottleneck ingestion
      assertPerformance(result, {
        avgDuration: 2, // 2ms average
        p95: 8, // 8ms P95
        opsPerSecond: 200, // At least 200 ops/sec
      });
    });
  });

  describe('🔄 End-to-End Processing Scenarios', () => {
    it('should process complete security event pipeline', () => {
      const rawEvent = {
        timestamp: '2025-01-02T10:30:00.000Z',
        severity: 'high',
        source_ip: '  192.168.1.100  ',
        destination_ip: '10.0.0.1',
        event_type: 'network_anomaly',
        raw_data: 'Suspicious network activity detected',
      };
      
      const result = runBenchmark(
        'Complete Event Processing Pipeline',
        () => {
          // Simulate complete pipeline
          const normalized = mockSecurityModules.eventProcessing.normalizeEvent(rawEvent);
          const enriched = mockSecurityModules.eventProcessing.enrichEvent(normalized.normalized);
          const validated = mockSecurityModules.eventProcessing.validateEvent(enriched.enriched);
          const riskScore = mockSecurityModules.threatAnalysis.calculateRiskScore([{
            type: 'ip',
            value: enriched.enriched.source_ip,
            severity: 8,
            confidence: 0.9,
            source: 'internal',
          }]);
          
          return { normalized, enriched, validated, riskScore };
        },
        1000
      );
      
      benchmarkResults.push(result);
      
      // Complete pipeline should stay under reasonable latency
      assertPerformance(result, {
        avgDuration: 15, // 15ms average for complete pipeline
        p95: 40, // 40ms P95
        opsPerSecond: 50, // At least 50 complete pipelines/sec
      });
    });

    it('should handle high-volume alert processing', () => {
      const alerts = Array.from({ length: 10 }, (_, i) => ({
        id: `alert-${i}`,
        severity: ['HIGH', 'CRITICAL'][i % 2],
        source_ip: `192.168.1.${i % 5}`,
        timestamp: new Date(Date.now() - i * 1000).toISOString(),
      }));
      
      const result = runBenchmark(
        'High-Volume Alert Processing (10 alerts)',
        () => {
          const patterns = mockSecurityModules.threatAnalysis.analyzeNetworkPattern(alerts);
          const correlations = mockSecurityModules.threatAnalysis.correlateAlerts(alerts);
          const riskScores = alerts.map(alert => 
            mockSecurityModules.threatAnalysis.calculateRiskScore([{
              type: 'alert',
              value: alert.id,
              severity: alert.severity === 'CRITICAL' ? 10 : 7,
              confidence: 0.8,
              source: 'detection_engine',
            }])
          );
          
          return { patterns, correlations, riskScores };
        },
        500
      );
      
      benchmarkResults.push(result);
      
      // High-volume processing should maintain performance
      assertPerformance(result, {
        avgDuration: 50, // 50ms average for 10 alerts
        p95: 100, // 100ms P95
        opsPerSecond: 15, // At least 15 batches/sec
      });
    });
  });

  describe('📈 Scalability Tests', () => {
    it('should scale linearly with event count', () => {
      const eventCounts = [10, 50, 100, 500];
      const results: Array<{ count: number; avgDuration: number; opsPerSecond: number }> = [];
      
      eventCounts.forEach(count => {
        const events = Array.from({ length: count }, (_, i) => ({
          id: `event-${i}`,
          source_ip: `192.168.1.${i % 255}`,
          timestamp: new Date().toISOString(),
        }));
        
        const result = runBenchmark(
          `Network Analysis (${count} events)`,
          () => mockSecurityModules.threatAnalysis.analyzeNetworkPattern(events),
          100 // Fewer iterations for scalability test
        );
        
        results.push({
          count,
          avgDuration: result.avgDuration,
          opsPerSecond: result.opsPerSecond,
        });
      });
      
      // Check that performance scales reasonably (not exponentially)
      const firstResult = results[0];
      const lastResult = results[results.length - 1];
      
      const countRatio = lastResult.count / firstResult.count;
      const durationRatio = lastResult.avgDuration / firstResult.avgDuration;
      
      // Duration should not increase more than 3x the count increase
      expect(durationRatio).toBeLessThan(countRatio * 3);
      
      console.log('\n📈 Scalability Analysis:');
      results.forEach(r => {
        console.log(`   ${r.count} events: ${r.avgDuration.toFixed(2)}ms avg, ${r.opsPerSecond.toFixed(0)} ops/sec`);
      });
    });

    it('should maintain performance under concurrent load', async () => {
      const concurrentOperations = 10;
      const testEvent = {
        id: 'concurrent-test',
        source_ip: '192.168.1.100',
        timestamp: '2025-01-02T10:30:00.000Z',
      };
      
      const startTime = performance.now();
      
      // Run concurrent operations
      const promises = Array.from({ length: concurrentOperations }, () =>
        new Promise(resolve => {
          const opStart = performance.now();
          const result = mockSecurityModules.eventProcessing.normalizeEvent(testEvent);
          const opEnd = performance.now();
          resolve(opEnd - opStart);
        })
      );
      
      const durations = await Promise.all(promises) as number[];
      const totalTime = performance.now() - startTime;
      
      const avgDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const maxDuration = Math.max(...durations);
      
      console.log(`\n🔄 Concurrency Test Results:`);
      console.log(`   Concurrent operations: ${concurrentOperations}`);
      console.log(`   Total time: ${totalTime.toFixed(2)}ms`);
      console.log(`   Average op duration: ${avgDuration.toFixed(2)}ms`);
      console.log(`   Max op duration: ${maxDuration.toFixed(2)}ms`);
      
      // Under concurrent load, operations should not degrade significantly
      expect(avgDuration).toBeLessThan(10); // 10ms max under concurrency
      expect(maxDuration).toBeLessThan(25); // 25ms max for any single operation
    });
  });

  describe('🔒 Memory and Resource Usage', () => {
    it('should not leak memory during processing', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Process many events
      for (let i = 0; i < 1000; i++) {
        const event = {
          id: `memory-test-${i}`,
          source_ip: `192.168.1.${i % 255}`,
          data: 'x'.repeat(1000), // 1KB of data per event
        };
        
        mockSecurityModules.eventProcessing.normalizeEvent(event);
        
        // Force garbage collection periodically
        if (i % 100 === 0 && global.gc) {
          global.gc();
        }
      }
      
      // Force final garbage collection
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      const memoryIncreaseMB = memoryIncrease / 1024 / 1024;
      
      console.log(`\n💾 Memory Usage Analysis:`);
      console.log(`   Initial memory: ${(initialMemory / 1024 / 1024).toFixed(2)} MB`);
      console.log(`   Final memory: ${(finalMemory / 1024 / 1024).toFixed(2)} MB`);
      console.log(`   Memory increase: ${memoryIncreaseMB.toFixed(2)} MB`);
      
      // Memory increase should be reasonable (less than 50MB for 1000 events)
      expect(memoryIncreaseMB).toBeLessThan(50);
    });
  });
});