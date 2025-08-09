/**
 * Offline Detection Hook for iSECTECH Protect PWA
 * Monitors network connectivity and provides offline capabilities
 */

'use client';

import { useState, useEffect, useCallback } from 'react';

interface OfflineOptions {
  onOnline?: () => void;
  onOffline?: () => void;
  checkInterval?: number;
  pingUrl?: string;
}

interface NetworkInfo {
  isOnline: boolean;
  connectionType?: string;
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  saveData?: boolean;
}

export function useOffline(options: OfflineOptions = {}) {
  const [isOnline, setIsOnline] = useState<boolean>(true);
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo>({ isOnline: true });
  const [lastOnline, setLastOnline] = useState<Date>(new Date());
  const [offlineDuration, setOfflineDuration] = useState<number>(0);

  // Get connection information
  const getConnectionInfo = useCallback((): NetworkInfo => {
    const connection = (navigator as any).connection || 
                     (navigator as any).mozConnection || 
                     (navigator as any).webkitConnection;

    return {
      isOnline: navigator.onLine,
      connectionType: connection?.type,
      effectiveType: connection?.effectiveType,
      downlink: connection?.downlink,
      rtt: connection?.rtt,
      saveData: connection?.saveData,
    };
  }, []);

  // Handle online/offline events
  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      setLastOnline(new Date());
      setOfflineDuration(0);
      setNetworkInfo(getConnectionInfo());
      options.onOnline?.();
    };

    const handleOffline = () => {
      setIsOnline(false);
      setNetworkInfo(prev => ({ ...getConnectionInfo(), isOnline: false }));
      options.onOffline?.();
    };

    const handleConnectionChange = () => {
      setNetworkInfo(getConnectionInfo());
    };

    // Initial state
    setIsOnline(navigator.onLine);
    setNetworkInfo(getConnectionInfo());

    // Add event listeners
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    const connection = (navigator as any).connection || 
                     (navigator as any).mozConnection || 
                     (navigator as any).webkitConnection;
    
    if (connection) {
      connection.addEventListener('change', handleConnectionChange);
    }

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      
      if (connection) {
        connection.removeEventListener('change', handleConnectionChange);
      }
    };
  }, [getConnectionInfo, options]);

  // Track offline duration
  useEffect(() => {
    if (!isOnline) {
      const interval = setInterval(() => {
        setOfflineDuration(prev => prev + 1);
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [isOnline]);

  // Periodic connectivity check (optional)
  useEffect(() => {
    if (!options.checkInterval) return;

    const interval = setInterval(async () => {
      try {
        const response = await fetch(options.pingUrl || '/api/health', {
          method: 'HEAD',
          cache: 'no-cache',
          signal: AbortSignal.timeout(5000),
        });
        
        const actuallyOnline = response.ok;
        
        if (actuallyOnline !== isOnline) {
          setIsOnline(actuallyOnline);
          setNetworkInfo(prev => ({ ...prev, isOnline: actuallyOnline }));
          
          if (actuallyOnline) {
            setLastOnline(new Date());
            setOfflineDuration(0);
            options.onOnline?.();
          } else {
            options.onOffline?.();
          }
        }
      } catch {
        // Network check failed, assume offline
        if (isOnline) {
          setIsOnline(false);
          setNetworkInfo(prev => ({ ...prev, isOnline: false }));
          options.onOffline?.();
        }
      }
    }, options.checkInterval);

    return () => clearInterval(interval);
  }, [options.checkInterval, options.pingUrl, isOnline, options]);

  const getConnectionQuality = useCallback((): 'excellent' | 'good' | 'poor' | 'offline' => {
    if (!isOnline) return 'offline';
    
    const { effectiveType, rtt, downlink } = networkInfo;
    
    if (effectiveType === '4g' && (rtt || 0) < 100 && (downlink || 0) > 10) {
      return 'excellent';
    } else if (effectiveType === '3g' || ((rtt || 0) < 300 && (downlink || 0) > 1)) {
      return 'good';
    } else {
      return 'poor';
    }
  }, [isOnline, networkInfo]);

  const retryWhenOnline = useCallback((callback: () => Promise<any>, maxRetries = 3) => {
    return new Promise((resolve, reject) => {
      let retryCount = 0;
      
      const attempt = async () => {
        try {
          if (!isOnline) {
            // Wait for online state
            const waitForOnline = () => {
              return new Promise<void>((resolveOnline) => {
                if (isOnline) {
                  resolveOnline();
                  return;
                }
                
                const handleOnline = () => {
                  window.removeEventListener('online', handleOnline);
                  resolveOnline();
                };
                
                window.addEventListener('online', handleOnline);
              });
            };
            
            await waitForOnline();
          }
          
          const result = await callback();
          resolve(result);
        } catch (error) {
          retryCount++;
          
          if (retryCount < maxRetries) {
            // Exponential backoff
            setTimeout(() => attempt(), Math.pow(2, retryCount) * 1000);
          } else {
            reject(error);
          }
        }
      };
      
      attempt();
    });
  }, [isOnline]);

  const cacheData = useCallback(async (key: string, data: any) => {
    if ('caches' in window) {
      try {
        const cache = await caches.open('offline-data');
        const response = new Response(JSON.stringify(data), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'max-age=86400', // 24 hours
          },
        });
        await cache.put(key, response);
      } catch (error) {
        console.error('Failed to cache data:', error);
      }
    }
  }, []);

  const getCachedData = useCallback(async (key: string) => {
    if ('caches' in window) {
      try {
        const cache = await caches.open('offline-data');
        const response = await cache.match(key);
        
        if (response) {
          return await response.json();
        }
      } catch (error) {
        console.error('Failed to get cached data:', error);
      }
    }
    return null;
  }, []);

  const clearCache = useCallback(async () => {
    if ('caches' in window) {
      try {
        const cache = await caches.open('offline-data');
        const keys = await cache.keys();
        await Promise.all(keys.map(key => cache.delete(key)));
      } catch (error) {
        console.error('Failed to clear cache:', error);
      }
    }
  }, []);

  return {
    isOnline,
    networkInfo,
    lastOnline,
    offlineDuration,
    connectionQuality: getConnectionQuality(),
    retryWhenOnline,
    cacheData,
    getCachedData,
    clearCache,
  };
}