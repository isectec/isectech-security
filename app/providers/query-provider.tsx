/**
 * React Query Provider for iSECTECH Protect
 * Production-grade data fetching and caching configuration
 */

'use client';

import React, { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { useAppStore } from '@/lib/store';
import { config } from '@/config/app';
import type { ApiError } from '@/types';

// Query client configuration
function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Stale time: how long data is considered fresh
        staleTime: config.cache.staleTime,
        // Cache time: how long data stays in cache when not being observed
        gcTime: config.cache.queryCacheTime,
        // Retry logic
        retry: (failureCount, error: any) => {
          // Don't retry on authentication errors
          if (error?.response?.status === 401) {
            return false;
          }
          // Don't retry on client errors (4xx)
          if (error?.response?.status >= 400 && error?.response?.status < 500) {
            return false;
          }
          // Retry up to 3 times for server errors
          return failureCount < 3;
        },
        retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
        // Network mode
        networkMode: 'online',
        // Refetch settings
        refetchOnMount: true,
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
        // Error handling
        useErrorBoundary: false,
        // Suspense
        suspense: false,
      },
      mutations: {
        // Retry logic for mutations
        retry: (failureCount, error: any) => {
          // Don't retry on authentication or client errors
          if (error?.response?.status && error.response.status < 500) {
            return false;
          }
          // Retry up to 2 times for server errors
          return failureCount < 2;
        },
        retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000),
        // Network mode
        networkMode: 'online',
        // Error handling
        useErrorBoundary: false,
      },
    },
    // Query cache configuration
    queryCache: {
      onError: (error: any, query) => {
        console.error('Query error:', {
          queryKey: query.queryKey,
          error: error.message,
          status: error?.response?.status,
        });

        // Show error notification for background queries
        if (query.state.data !== undefined) {
          const { showError } = useAppStore.getState();
          const apiError = error as ApiError;
          
          showError(
            'Data fetch failed',
            apiError.message || 'Failed to fetch latest data. Using cached version.'
          );
        }
      },
      onSuccess: (data: any, query) => {
        // Update performance metrics
        const { updatePerformanceMetrics } = useAppStore.getState();
        updatePerformanceMetrics({
          lastUpdated: new Date(),
        });

        if (config.isDevelopment) {
          console.debug('Query success:', {
            queryKey: query.queryKey,
            dataSize: JSON.stringify(data).length,
          });
        }
      },
    },
    // Mutation cache configuration
    mutationCache: {
      onError: (error: any, variables, context, mutation) => {
        console.error('Mutation error:', {
          mutationKey: mutation.options.mutationKey,
          error: error.message,
          status: error?.response?.status,
        });

        // Show error notification for mutations
        const { showError } = useAppStore.getState();
        const apiError = error as ApiError;
        
        showError(
          'Operation failed',
          apiError.message || 'The operation could not be completed. Please try again.'
        );
      },
      onSuccess: (data: any, variables, context, mutation) => {
        if (config.isDevelopment) {
          console.debug('Mutation success:', {
            mutationKey: mutation.options.mutationKey,
            variables,
          });
        }

        // Show success notification for certain mutations
        const mutationKey = mutation.options.mutationKey?.[0] as string;
        if (mutationKey && ['create', 'update', 'delete'].some(op => mutationKey.includes(op))) {
          const { showSuccess } = useAppStore.getState();
          showSuccess('Operation completed successfully');
        }
      },
    },
    // Logger configuration
    logger: config.isDevelopment ? {
      log: console.log,
      warn: console.warn,
      error: console.error,
    } : {
      log: () => {},
      warn: () => {},
      error: console.error,
    },
  });
}

interface QueryProviderProps {
  children: React.ReactNode;
}

export function QueryProvider({ children }: QueryProviderProps) {
  // Create a stable query client instance
  const [queryClient] = useState(() => createQueryClient());

  // Subscribe to connection status changes
  React.useEffect(() => {
    const { connectionStatus } = useAppStore.getState();
    
    // Pause/resume queries based on connection status
    if (connectionStatus.online && connectionStatus.apiConnected) {
      queryClient.resumePausedMutations();
    } else {
      queryClient.cancelQueries();
    }
  }, [queryClient]);

  // Handle focus and online events
  React.useEffect(() => {
    const handleFocus = () => {
      queryClient.resumePausedMutations();
    };

    const handleOnline = () => {
      queryClient.resumePausedMutations();
    };

    const handleOffline = () => {
      queryClient.cancelQueries();
    };

    window.addEventListener('focus', handleFocus);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [queryClient]);

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      {config.features.enableDevTools && (
        <ReactQueryDevtools
          initialIsOpen={false}
          position="bottom-right"
          toggleButtonProps={{
            style: {
              marginLeft: '5px',
              transform: undefined,
              width: '30px',
              height: '30px',
            },
          }}
        />
      )}
    </QueryClientProvider>
  );
}

// Custom hooks for common query patterns
export function useInvalidateQueries() {
  const queryClient = new QueryClient();
  
  return {
    invalidateAll: () => queryClient.invalidateQueries(),
    invalidateByKey: (queryKey: string[]) => queryClient.invalidateQueries({ queryKey }),
    invalidateByPattern: (pattern: string) => 
      queryClient.invalidateQueries({ predicate: (query) => 
        query.queryKey.some(key => String(key).includes(pattern))
      }),
  };
}

export function usePrefetchQuery() {
  const queryClient = new QueryClient();
  
  return {
    prefetch: (queryKey: string[], queryFn: () => Promise<any>) =>
      queryClient.prefetchQuery({ queryKey, queryFn }),
    prefetchInfinite: (queryKey: string[], queryFn: ({ pageParam }: { pageParam: any }) => Promise<any>) =>
      queryClient.prefetchInfiniteQuery({ queryKey, queryFn }),
  };
}

export function useQueryCache() {
  const queryClient = new QueryClient();
  
  return {
    getQueryData: <T = any>(queryKey: string[]): T | undefined =>
      queryClient.getQueryData(queryKey),
    setQueryData: <T = any>(queryKey: string[], data: T) =>
      queryClient.setQueryData(queryKey, data),
    removeQueries: (queryKey: string[]) =>
      queryClient.removeQueries({ queryKey }),
    clear: () => queryClient.clear(),
    getQueriesData: (filters?: any) => queryClient.getQueriesData(filters),
  };
}

export default QueryProvider;