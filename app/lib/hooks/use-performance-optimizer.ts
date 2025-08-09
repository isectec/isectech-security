/**
 * Performance Optimization Hook for Executive Analytics Dashboard
 * 
 * Provides comprehensive performance optimization including:
 * - Data virtualization for large datasets
 * - Intelligent caching strategies  
 * - Real-time update optimization
 * - Resource monitoring and alerting
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { debounce, throttle } from 'lodash';

interface PerformanceMetrics {
  renderTime: number;
  memoryUsage: number;
  cpuUsage: number;
  networkLatency: number;
  cacheHitRate: number;
  dataSize: number;
  lastUpdate: Date;
}

interface VirtualizationConfig {
  itemHeight: number;
  containerHeight: number;
  overscan: number;
  threshold: number;
}

interface CacheConfig {
  ttl: number;
  maxSize: number;
  strategy: 'lru' | 'lfu' | 'fifo';
  preloadKeys: string[];
}

interface OptimizationSettings {
  virtualization: VirtualizationConfig;
  caching: CacheConfig;
  realTimeUpdates: {
    enabled: boolean;
    interval: number;
    batchSize: number;
  };
  performanceMonitoring: {
    enabled: boolean;
    sampleRate: number;
    alertThresholds: {
      renderTime: number;
      memoryUsage: number;
      networkLatency: number;
    };
  };
}

const DEFAULT_OPTIMIZATION_SETTINGS: OptimizationSettings = {
  virtualization: {
    itemHeight: 48,
    containerHeight: 400,
    overscan: 5,
    threshold: 100
  },
  caching: {
    ttl: 300000, // 5 minutes
    maxSize: 100,
    strategy: 'lru',
    preloadKeys: []
  },
  realTimeUpdates: {
    enabled: true,
    interval: 5000, // 5 seconds
    batchSize: 50
  },
  performanceMonitoring: {
    enabled: true,
    sampleRate: 0.1,
    alertThresholds: {
      renderTime: 16, // 16ms for 60fps
      memoryUsage: 50, // 50MB
      networkLatency: 200 // 200ms
    }
  }
};

class PerformanceCache {
  private cache = new Map<string, { data: any; timestamp: number; hitCount: number }>();
  private config: CacheConfig;

  constructor(config: CacheConfig) {
    this.config = config;
  }

  get(key: string): any | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    // Check TTL
    if (Date.now() - entry.timestamp > this.config.ttl) {
      this.cache.delete(key);
      return undefined;
    }

    // Update hit count for LFU
    entry.hitCount++;
    return entry.data;
  }

  set(key: string, data: any): void {
    // Check cache size limit
    if (this.cache.size >= this.config.maxSize) {
      this.evict();
    }

    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      hitCount: 1
    });
  }

  private evict(): void {
    if (this.cache.size === 0) return;

    let keyToEvict: string;
    
    switch (this.config.strategy) {
      case 'lru':
        // Evict least recently used (oldest timestamp)
        keyToEvict = Array.from(this.cache.entries())
          .sort((a, b) => a[1].timestamp - b[1].timestamp)[0][0];
        break;
      
      case 'lfu':
        // Evict least frequently used (lowest hit count)
        keyToEvict = Array.from(this.cache.entries())
          .sort((a, b) => a[1].hitCount - b[1].hitCount)[0][0];
        break;
      
      case 'fifo':
      default:
        // Evict first in (oldest entry)
        keyToEvict = this.cache.keys().next().value;
        break;
    }

    this.cache.delete(keyToEvict);
  }

  clear(): void {
    this.cache.clear();
  }

  getStats(): { size: number; hitRate: number } {
    const entries = Array.from(this.cache.values());
    const totalHits = entries.reduce((sum, entry) => sum + entry.hitCount, 0);
    const totalRequests = entries.length;
    
    return {
      size: this.cache.size,
      hitRate: totalRequests > 0 ? totalHits / totalRequests : 0
    };
  }
}

class VirtualListManager {
  private config: VirtualizationConfig;
  
  constructor(config: VirtualizationConfig) {
    this.config = config;
  }

  calculateVisibleRange(scrollTop: number, totalItems: number): [number, number] {
    const startIndex = Math.floor(scrollTop / this.config.itemHeight);
    const endIndex = Math.min(
      startIndex + Math.ceil(this.config.containerHeight / this.config.itemHeight) + this.config.overscan,
      totalItems
    );
    
    return [Math.max(0, startIndex - this.config.overscan), endIndex];
  }

  shouldVirtualize(itemCount: number): boolean {
    return itemCount > this.config.threshold;
  }
}

class PerformanceMonitor {
  private metrics: PerformanceMetrics[] = [];
  private observers: ((metrics: PerformanceMetrics) => void)[] = [];

  startMonitoring(): void {
    // Use Performance Observer if available
    if ('PerformanceObserver' in window) {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          this.recordMetric(entry);
        }
      });
      
      observer.observe({ entryTypes: ['measure', 'navigation', 'resource'] });
    }

    // Fallback to manual monitoring
    this.startManualMonitoring();
  }

  private startManualMonitoring(): void {
    const monitor = () => {
      const metrics: PerformanceMetrics = {
        renderTime: performance.now(),
        memoryUsage: this.getMemoryUsage(),
        cpuUsage: 0, // Not directly available in browser
        networkLatency: this.getNetworkLatency(),
        cacheHitRate: 0,
        dataSize: 0,
        lastUpdate: new Date()
      };

      this.metrics.push(metrics);
      this.notifyObservers(metrics);

      // Keep only last 100 metrics
      if (this.metrics.length > 100) {
        this.metrics.shift();
      }
    };

    setInterval(monitor, 1000);
  }

  private getMemoryUsage(): number {
    if ('memory' in performance) {
      return (performance as any).memory.usedJSHeapSize / 1024 / 1024; // MB
    }
    return 0;
  }

  private getNetworkLatency(): number {
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    if (navigation) {
      return navigation.responseStart - navigation.requestStart;
    }
    return 0;
  }

  private recordMetric(entry: PerformanceEntry): void {
    // Process performance entries
    console.log('Performance entry:', entry);
  }

  subscribe(callback: (metrics: PerformanceMetrics) => void): () => void {
    this.observers.push(callback);
    return () => {
      const index = this.observers.indexOf(callback);
      if (index > -1) {
        this.observers.splice(index, 1);
      }
    };
  }

  private notifyObservers(metrics: PerformanceMetrics): void {
    this.observers.forEach(callback => callback(metrics));
  }

  getLatestMetrics(): PerformanceMetrics | undefined {
    return this.metrics[this.metrics.length - 1];
  }

  getAverageMetrics(): Partial<PerformanceMetrics> {
    if (this.metrics.length === 0) return {};

    const sums = this.metrics.reduce((acc, metric) => ({
      renderTime: acc.renderTime + metric.renderTime,
      memoryUsage: acc.memoryUsage + metric.memoryUsage,
      networkLatency: acc.networkLatency + metric.networkLatency
    }), { renderTime: 0, memoryUsage: 0, networkLatency: 0 });

    const count = this.metrics.length;
    return {
      renderTime: sums.renderTime / count,
      memoryUsage: sums.memoryUsage / count,
      networkLatency: sums.networkLatency / count
    };
  }
}

export function usePerformanceOptimizer(
  settings: Partial<OptimizationSettings> = {}
) {
  const finalSettings = useMemo(() => ({
    ...DEFAULT_OPTIMIZATION_SETTINGS,
    ...settings
  }), [settings]);

  const [performanceMetrics, setPerformanceMetrics] = useState<PerformanceMetrics>();
  const [isOptimized, setIsOptimized] = useState(false);
  
  // Initialize managers
  const cache = useMemo(() => new PerformanceCache(finalSettings.caching), [finalSettings.caching]);
  const virtualListManager = useMemo(() => new VirtualListManager(finalSettings.virtualization), [finalSettings.virtualization]);
  const performanceMonitor = useMemo(() => new PerformanceMonitor(), []);

  const queryClient = useQueryClient();
  const renderStartTime = useRef<number>();

  // Performance monitoring
  useEffect(() => {
    if (!finalSettings.performanceMonitoring.enabled) return;

    const unsubscribe = performanceMonitor.subscribe((metrics) => {
      setPerformanceMetrics(metrics);
      
      // Check thresholds and trigger alerts
      const thresholds = finalSettings.performanceMonitoring.alertThresholds;
      if (metrics.renderTime > thresholds.renderTime) {
        console.warn(`Render time exceeded threshold: ${metrics.renderTime}ms`);
      }
      if (metrics.memoryUsage > thresholds.memoryUsage) {
        console.warn(`Memory usage exceeded threshold: ${metrics.memoryUsage}MB`);
      }
      if (metrics.networkLatency > thresholds.networkLatency) {
        console.warn(`Network latency exceeded threshold: ${metrics.networkLatency}ms`);
      }
    });

    performanceMonitor.startMonitoring();
    return unsubscribe;
  }, [finalSettings.performanceMonitoring]);

  // Optimized data fetching with caching
  const fetchData = useCallback(async (key: string, fetcher: () => Promise<any>) => {
    // Check cache first
    const cached = cache.get(key);
    if (cached) {
      return cached;
    }

    // Fetch data
    const data = await fetcher();
    
    // Cache the result
    cache.set(key, data);
    
    return data;
  }, [cache]);

  // Debounced search function
  const debouncedSearch = useMemo(
    () => debounce((query: string, callback: (results: any[]) => void) => {
      // Implement search logic
      callback([]);
    }, 300),
    []
  );

  // Throttled scroll handler for virtualization
  const throttledScrollHandler = useMemo(
    () => throttle((scrollTop: number, totalItems: number) => {
      if (!virtualListManager.shouldVirtualize(totalItems)) return;
      
      const visibleRange = virtualListManager.calculateVisibleRange(scrollTop, totalItems);
      return visibleRange;
    }, 16), // 60fps
    [virtualListManager]
  );

  // Real-time data updates with batching
  const useRealTimeData = useCallback((keys: string[]) => {
    return useQuery({
      queryKey: ['realtime-data', keys],
      queryFn: async () => {
        const batchSize = finalSettings.realTimeUpdates.batchSize;
        const batches = [];
        
        for (let i = 0; i < keys.length; i += batchSize) {
          batches.push(keys.slice(i, i + batchSize));
        }
        
        const results = await Promise.all(
          batches.map(batch => 
            fetch(`/api/batch-data?keys=${batch.join(',')}`)
              .then(res => res.json())
          )
        );
        
        return results.flat();
      },
      refetchInterval: finalSettings.realTimeUpdates.enabled 
        ? finalSettings.realTimeUpdates.interval 
        : false,
      staleTime: finalSettings.caching.ttl,
      enabled: finalSettings.realTimeUpdates.enabled
    });
  }, [finalSettings]);

  // Render performance tracking
  const trackRenderStart = useCallback(() => {
    renderStartTime.current = performance.now();
  }, []);

  const trackRenderEnd = useCallback(() => {
    if (renderStartTime.current) {
      const renderTime = performance.now() - renderStartTime.current;
      console.log(`Render time: ${renderTime.toFixed(2)}ms`);
    }
  }, []);

  // Memory optimization utilities
  const clearCache = useCallback(() => {
    cache.clear();
    queryClient.clear();
  }, [cache, queryClient]);

  const preloadData = useCallback(async (keys: string[]) => {
    for (const key of keys) {
      if (!cache.get(key)) {
        try {
          const data = await fetch(`/api/data/${key}`).then(res => res.json());
          cache.set(key, data);
        } catch (error) {
          console.warn(`Failed to preload data for key: ${key}`, error);
        }
      }
    }
  }, [cache]);

  // Virtual list utilities
  const getVirtualizedList = useCallback((
    items: any[],
    scrollTop: number,
    renderItem: (item: any, index: number) => React.ReactNode
  ) => {
    if (!virtualListManager.shouldVirtualize(items.length)) {
      return items.map(renderItem);
    }

    const [startIndex, endIndex] = virtualListManager.calculateVisibleRange(scrollTop, items.length);
    const visibleItems = items.slice(startIndex, endIndex);
    
    return {
      visibleItems: visibleItems.map((item, index) => renderItem(item, startIndex + index)),
      totalHeight: items.length * finalSettings.virtualization.itemHeight,
      offsetY: startIndex * finalSettings.virtualization.itemHeight
    };
  }, [virtualListManager, finalSettings.virtualization.itemHeight]);

  // Performance optimization status
  useEffect(() => {
    const metrics = performanceMonitor.getAverageMetrics();
    const thresholds = finalSettings.performanceMonitoring.alertThresholds;
    
    const isWithinThresholds = 
      (metrics.renderTime || 0) < thresholds.renderTime &&
      (metrics.memoryUsage || 0) < thresholds.memoryUsage &&
      (metrics.networkLatency || 0) < thresholds.networkLatency;
    
    setIsOptimized(isWithinThresholds);
  }, [performanceMetrics, finalSettings]);

  return {
    // Performance metrics
    performanceMetrics,
    isOptimized,
    
    // Data management
    fetchData,
    useRealTimeData,
    clearCache,
    preloadData,
    
    // UI optimization
    debouncedSearch,
    throttledScrollHandler,
    getVirtualizedList,
    
    // Performance tracking
    trackRenderStart,
    trackRenderEnd,
    
    // Cache utilities
    cacheStats: cache.getStats(),
    
    // Settings
    settings: finalSettings
  };
}