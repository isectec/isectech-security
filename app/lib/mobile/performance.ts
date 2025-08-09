/**
 * Mobile Performance Optimization Utilities for iSECTECH Protect PWA
 * Provides performance monitoring and optimization features
 */

interface PerformanceMetrics {
  loadTime: number;
  firstContentfulPaint: number;
  largestContentfulPaint: number;
  firstInputDelay: number;
  cumulativeLayoutShift: number;
  timeToInteractive: number;
  memoryUsage?: {
    used: number;
    total: number;
    limit: number;
  };
  networkInfo?: {
    effectiveType: string;
    downlink: number;
    rtt: number;
    saveData: boolean;
  };
}

interface PerformanceObservation {
  timestamp: number;
  metrics: PerformanceMetrics;
  userAgent: string;
  screen: {
    width: number;
    height: number;
    devicePixelRatio: number;
  };
  battery?: {
    level: number;
    charging: boolean;
  };
}

class MobilePerformanceMonitor {
  private metrics: Partial<PerformanceMetrics> = {};
  private observers: PerformanceObserver[] = [];
  private isInitialized = false;

  constructor() {
    this.initializeObservers();
  }

  private initializeObservers() {
    if (this.isInitialized || typeof window === 'undefined') return;

    try {
      // Core Web Vitals Observer
      const vitalsObserver = new PerformanceObserver((list) => {
        list.getEntries().forEach((entry) => {
          switch (entry.entryType) {
            case 'paint':
              if (entry.name === 'first-contentful-paint') {
                this.metrics.firstContentfulPaint = entry.startTime;
              }
              break;

            case 'largest-contentful-paint':
              this.metrics.largestContentfulPaint = entry.startTime;
              break;

            case 'first-input':
              this.metrics.firstInputDelay = (entry as any).processingStart - entry.startTime;
              break;

            case 'layout-shift':
              if (!(entry as any).hadRecentInput) {
                this.metrics.cumulativeLayoutShift = (this.metrics.cumulativeLayoutShift || 0) + (entry as any).value;
              }
              break;
          }
        });
      });

      vitalsObserver.observe({ entryTypes: ['paint', 'largest-contentful-paint', 'first-input', 'layout-shift'] });
      this.observers.push(vitalsObserver);

      // Navigation timing
      this.metrics.loadTime = performance.timing?.loadEventEnd - performance.timing?.navigationStart || 0;
    } catch (error) {
      console.warn('Performance observers not supported:', error);
    }

    this.isInitialized = true;
  }

  public getMetrics(): PerformanceMetrics {
    const memory = (performance as any).memory;
    const connection = (navigator as any).connection || (navigator as any).mozConnection;

    return {
      loadTime: this.metrics.loadTime || 0,
      firstContentfulPaint: this.metrics.firstContentfulPaint || 0,
      largestContentfulPaint: this.metrics.largestContentfulPaint || 0,
      firstInputDelay: this.metrics.firstInputDelay || 0,
      cumulativeLayoutShift: this.metrics.cumulativeLayoutShift || 0,
      timeToInteractive: this.calculateTTI(),
      memoryUsage: memory
        ? {
            used: memory.usedJSHeapSize,
            total: memory.totalJSHeapSize,
            limit: memory.jsHeapSizeLimit,
          }
        : undefined,
      networkInfo: connection
        ? {
            effectiveType: connection.effectiveType,
            downlink: connection.downlink,
            rtt: connection.rtt,
            saveData: connection.saveData,
          }
        : undefined,
    };
  }

  private calculateTTI(): number {
    // Simplified TTI calculation
    const entries = performance.getEntriesByType('navigation');
    if (entries.length > 0) {
      const navEntry = entries[0] as PerformanceNavigationTiming;
      return navEntry.domInteractive - navEntry.navigationStart;
    }
    return 0;
  }

  public async getBatteryInfo() {
    try {
      const battery = await (navigator as any).getBattery?.();
      return battery
        ? {
            level: battery.level,
            charging: battery.charging,
            chargingTime: battery.chargingTime,
            dischargingTime: battery.dischargingTime,
          }
        : null;
    } catch {
      return null;
    }
  }

  public createPerformanceObservation(): PerformanceObservation {
    return {
      timestamp: Date.now(),
      metrics: this.getMetrics(),
      userAgent: navigator.userAgent,
      screen: {
        width: screen.width,
        height: screen.height,
        devicePixelRatio: window.devicePixelRatio,
      },
    };
  }

  public dispose() {
    this.observers.forEach((observer) => observer.disconnect());
    this.observers = [];
    this.isInitialized = false;
  }
}

// Image optimization utilities
export const imageOptimization = {
  // Determine optimal image format based on browser support
  getOptimalFormat(): 'avif' | 'webp' | 'jpg' {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;

    // Test AVIF support
    if (canvas.toDataURL('image/avif').indexOf('data:image/avif') === 0) {
      return 'avif';
    }

    // Test WebP support
    if (canvas.toDataURL('image/webp').indexOf('data:image/webp') === 0) {
      return 'webp';
    }

    return 'jpg';
  },

  // Generate responsive image sizes
  generateSizes(maxWidth: number): number[] {
    const breakpoints = [320, 480, 640, 768, 1024, 1280, 1600];
    return breakpoints.filter((bp) => bp <= maxWidth);
  },

  // Lazy load images with intersection observer
  lazyLoad(selector: string = 'img[data-src]') {
    if (!('IntersectionObserver' in window)) return;

    const images = document.querySelectorAll(selector);
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const img = entry.target as HTMLImageElement;
            const src = img.dataset.src;

            if (src) {
              img.src = src;
              img.removeAttribute('data-src');
              observer.unobserve(img);
            }
          }
        });
      },
      {
        rootMargin: '50px',
      }
    );

    images.forEach((img) => observer.observe(img));
    return observer;
  },
};

// Bundle optimization utilities
export const bundleOptimization = {
  // Preload critical resources
  preloadCriticalResources() {
    const criticalResources = ['/fonts/inter.woff2', '/icons/icon-192x192.png'];

    criticalResources.forEach((resource) => {
      const link = document.createElement('link');
      link.rel = 'preload';
      link.href = resource;

      if (resource.includes('.woff2')) {
        link.as = 'font';
        link.type = 'font/woff2';
        link.crossOrigin = 'anonymous';
      } else if (resource.includes('.png') || resource.includes('.jpg')) {
        link.as = 'image';
      }

      document.head.appendChild(link);
    });
  },

  // Lazy load non-critical JavaScript modules
  async loadModule(modulePath: string) {
    try {
      if (!modulePath || typeof modulePath !== 'string') return null;
      // Use eval-based dynamic import to avoid bundler static resolution errors (Turbopack)
      const dynamicImport = new Function('p', 'return import(p)') as (p: string) => Promise<any>;
      const module = await dynamicImport(modulePath);
      return module;
    } catch (error) {
      console.error(`Failed to load module: ${modulePath}`, error);
      return null;
    }
  },
};

// Memory management utilities
export const memoryOptimization = {
  // Monitor memory usage
  getMemoryUsage() {
    const memory = (performance as any).memory;
    if (!memory) return null;

    return {
      used: memory.usedJSHeapSize,
      total: memory.totalJSHeapSize,
      limit: memory.jsHeapSizeLimit,
      percentage: (memory.usedJSHeapSize / memory.jsHeapSizeLimit) * 100,
    };
  },

  // Force garbage collection (if available)
  forceGC() {
    if ((window as any).gc) {
      (window as any).gc();
    }
  },

  // Clear caches when memory is low
  async clearCachesIfNeeded(threshold = 80) {
    const usage = this.getMemoryUsage();
    if (usage && usage.percentage > threshold) {
      try {
        const cacheNames = await caches.keys();
        const oldCaches = cacheNames.filter((name) => !name.includes('v1') && !name.includes('critical'));

        await Promise.all(oldCaches.map((name) => caches.delete(name)));
        console.log(`Cleared ${oldCaches.length} old caches due to high memory usage`);
      } catch (error) {
        console.error('Failed to clear caches:', error);
      }
    }
  },
};

// Battery optimization utilities
export const batteryOptimization = {
  async getBatteryLevel(): Promise<number> {
    try {
      const battery = await (navigator as any).getBattery?.();
      return battery?.level || 1;
    } catch {
      return 1; // Assume full battery if unavailable
    }
  },

  async isCharging(): Promise<boolean> {
    try {
      const battery = await (navigator as any).getBattery?.();
      return battery?.charging || true;
    } catch {
      return true; // Assume charging if unavailable
    }
  },

  // Reduce functionality when battery is low
  async shouldReducePerformance(): Promise<boolean> {
    const batteryLevel = await this.getBatteryLevel();
    const isCharging = await this.isCharging();

    return batteryLevel < 0.2 && !isCharging;
  },

  // Apply battery-saving optimizations
  async applyBatterySavingMode() {
    if (await this.shouldReducePerformance()) {
      // Reduce animation frequency
      document.documentElement.style.setProperty('--animation-duration', '0.1s');

      // Disable non-critical background tasks
      return {
        reducedAnimations: true,
        backgroundSyncDisabled: true,
        refreshIntervalIncreased: true,
      };
    }

    return {
      reducedAnimations: false,
      backgroundSyncDisabled: false,
      refreshIntervalIncreased: false,
    };
  },
};

// Main performance monitor instance
export const performanceMonitor = new MobilePerformanceMonitor();

// Performance reporting utility
export const performanceReporting = {
  // Report metrics to analytics service
  async reportMetrics(endpoint = '/api/analytics/performance') {
    const observation = performanceMonitor.createPerformanceObservation();
    const batteryInfo = await performanceMonitor.getBatteryInfo();

    if (batteryInfo) {
      observation.battery = batteryInfo;
    }

    try {
      await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(observation),
      });
    } catch (error) {
      console.error('Failed to report performance metrics:', error);
    }
  },

  // Check if performance meets targets
  validatePerformanceTargets(metrics?: PerformanceMetrics): boolean {
    const targets = {
      loadTime: 3000, // 3 seconds
      firstContentfulPaint: 1800, // 1.8 seconds
      largestContentfulPaint: 2500, // 2.5 seconds
      firstInputDelay: 100, // 100ms
      cumulativeLayoutShift: 0.1,
    };

    const currentMetrics = metrics || performanceMonitor.getMetrics();

    return (
      currentMetrics.loadTime <= targets.loadTime &&
      currentMetrics.firstContentfulPaint <= targets.firstContentfulPaint &&
      currentMetrics.largestContentfulPaint <= targets.largestContentfulPaint &&
      currentMetrics.firstInputDelay <= targets.firstInputDelay &&
      currentMetrics.cumulativeLayoutShift <= targets.cumulativeLayoutShift
    );
  },
};

export default {
  performanceMonitor,
  imageOptimization,
  bundleOptimization,
  memoryOptimization,
  batteryOptimization,
  performanceReporting,
};
