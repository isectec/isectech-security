/**
 * Security Platform Stress Testing
 * iSECTECH Protect - High-Load Performance Validation
 */

import { test, expect, Browser, Page } from '@playwright/test';
import { performance } from 'perf_hooks';

interface StressTestMetrics {
  maxConcurrentUsers: number;
  avgResponseTime: number;
  errorRate: number;
  memoryUsage: number;
  cpuUsage: number;
  throughputPerSecond: number;
}

class SecurityStressTester {
  private browsers: Browser[] = [];
  private pages: Page[] = [];

  async createMultipleUsers(count: number) {
    const { chromium } = require('@playwright/test');
    
    for (let i = 0; i < count; i++) {
      const browser = await chromium.launch({ headless: true });
      const page = await browser.newPage();
      
      this.browsers.push(browser);
      this.pages.push(page);
    }
  }

  async cleanup() {
    await Promise.all(this.browsers.map(browser => browser.close()));
    this.browsers = [];
    this.pages = [];
  }

  async simulateSecurityWorkload(page: Page, baseUrl: string): Promise<number[]> {
    const times: number[] = [];
    
    // Login
    const loginStart = performance.now();
    await page.goto(`${baseUrl}/login`);
    await page.fill('[data-testid="email-input"]', `user-${Math.random()}@isectech.com`);
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/dashboard');
    times.push(performance.now() - loginStart);

    // Dashboard load
    const dashStart = performance.now();
    await page.reload();
    await page.waitForSelector('[data-testid="dashboard-loaded"]');
    times.push(performance.now() - dashStart);

    // Alerts operations
    const alertsStart = performance.now();
    await page.goto(`${baseUrl}/alerts`);
    await page.waitForSelector('[data-testid="alerts-table-loaded"]');
    
    // Create alert
    await page.click('[data-testid="create-alert-button"]');
    await page.fill('[data-testid="alert-title"]', `Stress Test Alert ${Date.now()}`);
    await page.selectOption('[data-testid="alert-severity"]', 'HIGH');
    await page.click('[data-testid="submit-alert"]');
    await page.waitForSelector('[data-testid="alert-created-success"]');
    times.push(performance.now() - alertsStart);

    // Search operation
    const searchStart = performance.now();
    await page.goto(`${baseUrl}/search`);
    await page.fill('[data-testid="search-input"]', 'malware');
    await page.click('[data-testid="search-button"]');
    await page.waitForSelector('[data-testid="search-results-loaded"]');
    times.push(performance.now() - searchStart);

    return times;
  }

  async measureSystemResources(): Promise<{ memory: number; cpu: number }> {
    const memUsage = process.memoryUsage();
    return {
      memory: memUsage.heapUsed / 1024 / 1024, // MB
      cpu: process.cpuUsage().user / 1000, // ms
    };
  }
}

test.describe('🔥 Security Platform Stress Tests', () => {
  let stressTester: SecurityStressTester;
  const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000';

  test.beforeEach(async () => {
    stressTester = new SecurityStressTester();
  });

  test.afterEach(async () => {
    await stressTester.cleanup();
  });

  test('should handle 10 concurrent security analysts', async () => {
    const concurrentUsers = 10;
    await stressTester.createMultipleUsers(concurrentUsers);

    const startTime = performance.now();
    const startResources = await stressTester.measureSystemResources();

    // Execute concurrent workloads
    const workloadPromises = stressTester.pages.map(page => 
      stressTester.simulateSecurityWorkload(page, baseUrl)
    );

    const results = await Promise.all(workloadPromises);
    const endTime = performance.now();
    const endResources = await stressTester.measureSystemResources();

    // Calculate metrics
    const totalTime = endTime - startTime;
    const allResponseTimes = results.flat();
    const avgResponseTime = allResponseTimes.reduce((sum, time) => sum + time, 0) / allResponseTimes.length;
    const maxResponseTime = Math.max(...allResponseTimes);

    // Performance assertions
    expect(totalTime).toBeLessThan(60000); // Complete within 60 seconds
    expect(avgResponseTime).toBeLessThan(3000); // Average response < 3s
    expect(maxResponseTime).toBeLessThan(10000); // Max response < 10s

    // Resource usage assertions
    const memoryIncrease = endResources.memory - startResources.memory;
    expect(memoryIncrease).toBeLessThan(500); // < 500MB memory increase

    console.log(`Stress Test Results (${concurrentUsers} users):`);
    console.log(`Total Time: ${totalTime.toFixed(2)}ms`);
    console.log(`Avg Response: ${avgResponseTime.toFixed(2)}ms`);
    console.log(`Max Response: ${maxResponseTime.toFixed(2)}ms`);
    console.log(`Memory Usage: ${memoryIncrease.toFixed(2)}MB`);
  }, 120000);

  test('should maintain performance under alert flood scenario', async ({ page }) => {
    await page.goto(`${baseUrl}/dashboard`);
    
    const alertFloodStart = performance.now();
    let processedAlerts = 0;
    const targetAlerts = 1000;

    // Monitor performance during alert flood
    const performanceLog: number[] = [];
    
    for (let i = 0; i < targetAlerts; i++) {
      const batchStart = performance.now();
      
      // Simulate receiving batch of alerts
      await page.evaluate((alertIndex) => {
        for (let j = 0; j < 10; j++) {
          window.dispatchEvent(new CustomEvent('new-alert', {
            detail: {
              id: `flood-${alertIndex}-${j}`,
              severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][j % 4],
              title: `Flood Alert ${alertIndex}-${j}`,
              timestamp: new Date().toISOString(),
            }
          }));
        }
      }, i);

      // Wait for processing
      await page.waitForTimeout(10);
      
      const batchTime = performance.now() - batchStart;
      performanceLog.push(batchTime);
      processedAlerts += 10;

      // Check every 100 alerts for degradation
      if (i % 100 === 0 && i > 0) {
        const recentAvg = performanceLog.slice(-100).reduce((sum, time) => sum + time, 0) / 100;
        expect(recentAvg).toBeLessThan(50); // Processing should stay under 50ms per batch
      }
    }

    const totalFloodTime = performance.now() - alertFloodStart;
    const throughput = processedAlerts / (totalFloodTime / 1000); // alerts per second

    expect(totalFloodTime).toBeLessThan(120000); // Complete within 2 minutes
    expect(throughput).toBeGreaterThan(100); // > 100 alerts/second
    expect(processedAlerts).toBe(targetAlerts);

    console.log(`Alert Flood Results:`);
    console.log(`Processed: ${processedAlerts} alerts`);
    console.log(`Time: ${totalFloodTime.toFixed(2)}ms`);
    console.log(`Throughput: ${throughput.toFixed(2)} alerts/sec`);
  }, 150000);

  test('should handle sustained high-frequency real-time updates', async ({ page }) => {
    await page.goto(`${baseUrl}/dashboard`);
    
    const updateDuration = 60000; // 1 minute
    const updateInterval = 100; // Every 100ms
    const expectedUpdates = updateDuration / updateInterval;
    
    let receivedUpdates = 0;
    const latencies: number[] = [];

    // Setup update listener
    await page.evaluate(() => {
      (window as any).updateReceived = (latency: number) => {
        (window as any).receivedCount = ((window as any).receivedCount || 0) + 1;
        (window as any).latencies = ((window as any).latencies || []).concat(latency);
      };
    });

    const startTime = performance.now();
    
    // Send rapid updates
    const updateInterval_id = setInterval(async () => {
      const updateStart = performance.now();
      
      await page.evaluate((updateTime) => {
        const latency = performance.now() - updateTime;
        window.dispatchEvent(new CustomEvent('realtime-update', {
          detail: {
            type: 'threat-intel',
            data: { timestamp: updateTime, severity: 'MEDIUM' }
          }
        }));
        (window as any).updateReceived(latency);
      }, performance.now());

      if (performance.now() - startTime >= updateDuration) {
        clearInterval(updateInterval_id);
      }
    }, updateInterval);

    // Wait for test completion
    await page.waitForTimeout(updateDuration + 1000);

    // Get results
    const results = await page.evaluate(() => ({
      receivedCount: (window as any).receivedCount || 0,
      latencies: (window as any).latencies || []
    }));

    receivedUpdates = results.receivedCount;
    const avgLatency = results.latencies.length > 0 ? 
      results.latencies.reduce((sum: number, lat: number) => sum + lat, 0) / results.latencies.length : 0;
    const maxLatency = results.latencies.length > 0 ? Math.max(...results.latencies) : 0;

    // Performance assertions
    expect(receivedUpdates).toBeGreaterThan(expectedUpdates * 0.95); // > 95% delivery rate
    expect(avgLatency).toBeLessThan(50); // < 50ms average latency
    expect(maxLatency).toBeLessThan(200); // < 200ms max latency

    console.log(`Real-time Update Results:`);
    console.log(`Expected: ${expectedUpdates} updates`);
    console.log(`Received: ${receivedUpdates} updates`);
    console.log(`Delivery Rate: ${(receivedUpdates / expectedUpdates * 100).toFixed(1)}%`);
    console.log(`Avg Latency: ${avgLatency.toFixed(2)}ms`);
    console.log(`Max Latency: ${maxLatency.toFixed(2)}ms`);
  }, 80000);

  test('should maintain responsiveness during data-heavy operations', async ({ page }) => {
    await page.goto(`${baseUrl}/reports`);

    // Test large dataset handling
    const dataSetSizes = [1000, 5000, 10000, 50000];
    const results: Array<{ size: number; loadTime: number; renderTime: number }> = [];

    for (const size of dataSetSizes) {
      const loadStart = performance.now();

      // Simulate loading large datasets
      await page.evaluate((dataSize) => {
        const largeDataset = Array.from({ length: dataSize }, (_, i) => ({
          id: `data-${i}`,
          timestamp: new Date(Date.now() - i * 1000).toISOString(),
          severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][i % 4],
          type: 'NETWORK_ANOMALY',
          source_ip: `192.168.1.${i % 255}`,
        }));

        // Trigger dataset processing
        window.dispatchEvent(new CustomEvent('load-dataset', {
          detail: { data: largeDataset }
        }));
      }, size);

      // Wait for data processing
      await page.waitForSelector(`[data-testid="dataset-size-${size}"]`);
      const loadTime = performance.now() - loadStart;

      // Test rendering performance
      const renderStart = performance.now();
      await page.click('[data-testid="render-chart"]');
      await page.waitForSelector('[data-testid="chart-rendered"]');
      const renderTime = performance.now() - renderStart;

      results.push({ size, loadTime, renderTime });

      // Performance requirements scale with data size
      const expectedLoadTime = size * 0.1; // 0.1ms per record
      const expectedRenderTime = size * 0.05; // 0.05ms per record

      expect(loadTime).toBeLessThan(Math.max(expectedLoadTime, 1000)); // Min 1s max
      expect(renderTime).toBeLessThan(Math.max(expectedRenderTime, 2000)); // Min 2s max

      // Clear for next test
      await page.evaluate(() => {
        window.dispatchEvent(new CustomEvent('clear-dataset'));
      });
    }

    console.log('Data Processing Performance:');
    results.forEach(result => {
      console.log(`${result.size} records: Load ${result.loadTime.toFixed(0)}ms, Render ${result.renderTime.toFixed(0)}ms`);
    });
  }, 120000);

  test('should handle memory pressure gracefully', async ({ page }) => {
    await page.goto(`${baseUrl}/dashboard`);

    // Monitor memory usage during intensive operations
    const memorySnapshots: number[] = [];
    
    for (let i = 0; i < 100; i++) {
      // Create memory-intensive operations
      await page.evaluate((iteration) => {
        // Simulate creating large objects (security event processing)
        const largeObject = {
          events: Array.from({ length: 1000 }, (_, j) => ({
            id: `event-${iteration}-${j}`,
            data: 'x'.repeat(1000), // 1KB per event
            timestamp: Date.now(),
            metadata: {
              processed: true,
              analyzed: true,
              correlated: false,
            }
          }))
        };

        // Process and then clean up
        (window as any).tempStorage = (window as any).tempStorage || [];
        (window as any).tempStorage.push(largeObject);

        // Periodic cleanup
        if (iteration % 10 === 0) {
          (window as any).tempStorage = [];
        }
      }, i);

      // Take memory snapshot
      const memUsage = await page.evaluate(() => {
        return (performance as any).memory ? 
          (performance as any).memory.usedJSHeapSize / 1024 / 1024 : 0;
      });
      
      if (memUsage > 0) {
        memorySnapshots.push(memUsage);
      }

      // Verify memory doesn't grow uncontrollably
      if (memorySnapshots.length > 10) {
        const recent = memorySnapshots.slice(-10);
        const growth = recent[recent.length - 1] - recent[0];
        expect(growth).toBeLessThan(100); // < 100MB growth per 10 iterations
      }
    }

    // Force garbage collection
    await page.evaluate(() => {
      (window as any).tempStorage = null;
      if ((window as any).gc) {
        (window as any).gc();
      }
    });

    const finalMemory = await page.evaluate(() => {
      return (performance as any).memory ? 
        (performance as any).memory.usedJSHeapSize / 1024 / 1024 : 0;
    });

    if (memorySnapshots.length > 0 && finalMemory > 0) {
      const maxMemory = Math.max(...memorySnapshots);
      const memoryGrowth = finalMemory - memorySnapshots[0];
      
      expect(maxMemory).toBeLessThan(500); // < 500MB peak memory
      expect(memoryGrowth).toBeLessThan(200); // < 200MB total growth

      console.log(`Memory Usage Analysis:`);
      console.log(`Initial: ${memorySnapshots[0]?.toFixed(2)}MB`);
      console.log(`Peak: ${maxMemory.toFixed(2)}MB`);
      console.log(`Final: ${finalMemory.toFixed(2)}MB`);
      console.log(`Growth: ${memoryGrowth.toFixed(2)}MB`);
    }
  }, 90000);
});