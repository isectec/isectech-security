/**
 * Alert Management Hooks for iSECTECH Protect
 * Production-grade React hooks for AI-powered alert management
 */

import { alertService, type AlertFilters } from '@/lib/api/services/alerts';
import { useAppStore } from '@/lib/store';
import type { Alert, AlertStatus, SearchParams } from '@/types';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useMemo, useState } from 'react';

// Query keys for consistent caching
export const alertQueryKeys = {
  all: ['alerts'] as const,
  lists: () => [...alertQueryKeys.all, 'list'] as const,
  list: (filters: AlertFilters) => [...alertQueryKeys.lists(), filters] as const,
  details: () => [...alertQueryKeys.all, 'detail'] as const,
  detail: (id: string) => [...alertQueryKeys.details(), id] as const,
  metrics: () => [...alertQueryKeys.all, 'metrics'] as const,
  correlations: (id: string) => [...alertQueryKeys.all, 'correlations', id] as const,
  enrichment: (id: string) => [...alertQueryKeys.all, 'enrichment', id] as const,
  investigation: (id: string) => [...alertQueryKeys.all, 'investigation', id] as const,
  workflows: () => [...alertQueryKeys.all, 'workflows'] as const,
  fatigue: () => [...alertQueryKeys.all, 'fatigue'] as const,
  trends: (params: any) => [...alertQueryKeys.all, 'trends', params] as const,
};

// Main alerts list hook with advanced filtering and real-time updates
export function useAlerts(
  options: {
    filters?: AlertFilters;
    search?: SearchParams;
    includeCorrelations?: boolean;
    includeEnrichment?: boolean;
    realTime?: boolean;
    enabled?: boolean;
  } = {}
) {
  const { filters = {}, search, includeCorrelations, includeEnrichment, realTime = true, enabled = true } = options;

  const queryClient = useQueryClient();
  const { showError } = useAppStore();

  const query = useQuery({
    queryKey: alertQueryKeys.list({ ...filters, search, includeCorrelations, includeEnrichment } as AlertFilters),
    queryFn: () =>
      alertService.getAlerts({
        filters,
        search,
        includeCorrelations,
        includeEnrichment,
      }),
    enabled,
    staleTime: realTime ? 30 * 1000 : 5 * 60 * 1000, // 30s for real-time, 5min otherwise
    refetchInterval: realTime ? 30 * 1000 : false,
    onError: (error: any) => {
      showError('Failed to load alerts', error.message);
    },
  });

  const refreshAlerts = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
  }, [queryClient]);

  return {
    ...query,
    alerts: query.data?.items || [],
    pagination: query.data?.meta,
    refreshAlerts,
  };
}

// Infinite scroll alerts hook for large datasets
export function useInfiniteAlerts(
  options: {
    filters?: AlertFilters;
    search?: SearchParams;
    pageSize?: number;
  } = {}
) {
  const { filters = {}, search, pageSize = 25 } = options;
  const { showError } = useAppStore();

  return useInfiniteQuery({
    queryKey: [...alertQueryKeys.list(filters), 'infinite'],
    queryFn: ({ pageParam = 1 }) =>
      alertService.getAlerts({
        filters,
        search: { ...search, page: pageParam, limit: pageSize },
      }),
    getNextPageParam: (lastPage) => {
      const { page, totalPages } = lastPage.meta;
      return page < totalPages ? page + 1 : undefined;
    },
    onError: (error: any) => {
      showError('Failed to load alerts', error.message);
    },
  });
}

// Single alert detail hook with enrichment options
export function useAlert(
  id: string,
  options: {
    includeCorrelations?: boolean;
    includeEnrichment?: boolean;
    includeInvestigation?: boolean;
    enabled?: boolean;
  } = {}
) {
  const { includeCorrelations, includeEnrichment, includeInvestigation, enabled = !!id } = options;
  const { showError } = useAppStore();

  return useQuery({
    queryKey: alertQueryKeys.detail(id),
    queryFn: () =>
      alertService.getAlert(id, {
        includeCorrelations,
        includeEnrichment,
        includeInvestigation,
      }),
    enabled,
    staleTime: 2 * 60 * 1000, // 2 minutes
    onError: (error: any) => {
      showError('Failed to load alert details', error.message);
    },
  });
}

// Alert metrics and analytics hook
export function useAlertMetrics(params?: {
  dateRange?: { start: Date; end: Date };
  groupBy?: 'hour' | 'day' | 'week' | 'month';
  filters?: AlertFilters;
}) {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: alertQueryKeys.metrics(),
    queryFn: () => alertService.getAlertMetrics(params),
    staleTime: 5 * 60 * 1000, // 5 minutes
    refetchInterval: 5 * 60 * 1000, // Refresh every 5 minutes
    onError: (error: any) => {
      showError('Failed to load alert metrics', error.message);
    },
  });
}

// Alert fatigue analysis hook
export function useAlertFatigue() {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: alertQueryKeys.fatigue(),
    queryFn: () => alertService.getFatigueAnalysis(),
    staleTime: 15 * 60 * 1000, // 15 minutes
    refetchInterval: 15 * 60 * 1000,
    onError: (error: any) => {
      showError('Failed to load fatigue analysis', error.message);
    },
  });
}

// Alert workflows hook
export function useAlertWorkflows() {
  const { showError } = useAppStore();

  return useQuery({
    queryKey: alertQueryKeys.workflows(),
    queryFn: () => alertService.getWorkflows(),
    staleTime: 10 * 60 * 1000, // 10 minutes
    onError: (error: any) => {
      showError('Failed to load workflows', error.message);
    },
  });
}

// Alert mutations hook for create/update/delete operations
export function useAlertMutations() {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useAppStore();

  const updateStatus = useMutation({
    mutationFn: ({ id, status, comment }: { id: string; status: AlertStatus; comment?: string }) =>
      alertService.updateAlertStatus(id, status, comment),
    onSuccess: (updatedAlert) => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
      queryClient.setQueryData(alertQueryKeys.detail(updatedAlert.id), updatedAlert);
      showSuccess('Alert status updated successfully');
    },
    onError: (error: any) => {
      showError('Failed to update alert status', error.message);
    },
  });

  const assignAlert = useMutation({
    mutationFn: ({ id, assigneeId, comment }: { id: string; assigneeId: string; comment?: string }) =>
      alertService.assignAlert(id, assigneeId, comment),
    onSuccess: (updatedAlert) => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
      queryClient.setQueryData(alertQueryKeys.detail(updatedAlert.id), updatedAlert);
      showSuccess('Alert assigned successfully');
    },
    onError: (error: any) => {
      showError('Failed to assign alert', error.message);
    },
  });

  const escalateAlert = useMutation({
    mutationFn: ({ id, level, reason }: { id: string; level: number; reason: string }) =>
      alertService.escalateAlert(id, level, reason),
    onSuccess: (updatedAlert) => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
      queryClient.setQueryData(alertQueryKeys.detail(updatedAlert.id), updatedAlert);
      showSuccess('Alert escalated successfully');
    },
    onError: (error: any) => {
      showError('Failed to escalate alert', error.message);
    },
  });

  const enrichAlert = useMutation({
    mutationFn: ({ id, forceRefresh }: { id: string; forceRefresh?: boolean }) =>
      alertService.enrichAlert(id, forceRefresh),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.detail(id) });
      showSuccess('Alert enriched successfully');
    },
    onError: (error: any) => {
      showError('Failed to enrich alert', error.message);
    },
  });

  const triageAlert = useMutation({
    mutationFn: (id: string) => alertService.triageAlert(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.detail(id) });
      showSuccess('Alert triaged successfully');
    },
    onError: (error: any) => {
      showError('Failed to triage alert', error.message);
    },
  });

  const bulkUpdate = useMutation({
    mutationFn: ({ alertIds, updates }: { alertIds: string[]; updates: Partial<Alert> }) =>
      alertService.bulkUpdateAlerts(alertIds, updates),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
      showSuccess(`Updated ${result.updated} alerts successfully`);
      if (result.failed.length > 0) {
        showError(`Failed to update ${result.failed.length} alerts`);
      }
    },
    onError: (error: any) => {
      showError('Failed to update alerts', error.message);
    },
  });

  const mergeAlerts = useMutation({
    mutationFn: ({ primaryId, duplicateIds, reason }: { primaryId: string; duplicateIds: string[]; reason: string }) =>
      alertService.mergeAlerts(primaryId, duplicateIds, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
      showSuccess('Alerts merged successfully');
    },
    onError: (error: any) => {
      showError('Failed to merge alerts', error.message);
    },
  });

  const suppressAlerts = useMutation({
    mutationFn: ({ alertIds, duration, reason }: { alertIds: string[]; duration: number; reason: string }) =>
      alertService.suppressAlerts(alertIds, duration, reason),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
      showSuccess(`Suppressed ${result.suppressed} alerts`);
    },
    onError: (error: any) => {
      showError('Failed to suppress alerts', error.message);
    },
  });

  return {
    updateStatus,
    assignAlert,
    escalateAlert,
    enrichAlert,
    triageAlert,
    bulkUpdate,
    mergeAlerts,
    suppressAlerts,
  };
}

// Advanced alert filtering hook with debounced search
export function useAlertFilters() {
  const [filters, setFilters] = useState<AlertFilters>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');

  // Debounce search query
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(searchQuery);
    }, 300);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  const updateFilter = useCallback((key: keyof AlertFilters, value: any) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value,
    }));
  }, []);

  const clearFilter = useCallback((key: keyof AlertFilters) => {
    setFilters((prev) => {
      const newFilters = { ...prev };
      delete newFilters[key];
      return newFilters;
    });
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilters({});
    setSearchQuery('');
  }, []);

  const activeFilterCount = useMemo(() => {
    return Object.keys(filters).length;
  }, [filters]);

  const searchParams: SearchParams | undefined = debouncedQuery
    ? {
        query: debouncedQuery,
        fields: ['title', 'description'],
      }
    : undefined;

  return {
    filters,
    searchQuery,
    searchParams,
    activeFilterCount,
    updateFilter,
    clearFilter,
    clearAllFilters,
    setSearchQuery,
  };
}

// Alert selection hook for bulk operations
export function useAlertSelection() {
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set());

  const selectAlert = useCallback((alertId: string) => {
    setSelectedAlerts((prev) => new Set([...prev, alertId]));
  }, []);

  const deselectAlert = useCallback((alertId: string) => {
    setSelectedAlerts((prev) => {
      const newSet = new Set(prev);
      newSet.delete(alertId);
      return newSet;
    });
  }, []);

  const toggleAlert = useCallback((alertId: string) => {
    setSelectedAlerts((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(alertId)) {
        newSet.delete(alertId);
      } else {
        newSet.add(alertId);
      }
      return newSet;
    });
  }, []);

  const selectAll = useCallback((alertIds: string[]) => {
    setSelectedAlerts(new Set(alertIds));
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedAlerts(new Set());
  }, []);

  const isSelected = useCallback(
    (alertId: string) => {
      return selectedAlerts.has(alertId);
    },
    [selectedAlerts]
  );

  return {
    selectedAlerts: Array.from(selectedAlerts),
    selectedCount: selectedAlerts.size,
    selectAlert,
    deselectAlert,
    toggleAlert,
    selectAll,
    clearSelection,
    isSelected,
  };
}

// Real-time alert updates hook
export function useRealTimeAlerts(filters?: AlertFilters) {
  const queryClient = useQueryClient();
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');

  useEffect(() => {
    let unsubscribe: (() => void) | undefined;

    const connect = async () => {
      setConnectionStatus('connecting');
      try {
        unsubscribe = await alertService.subscribeToAlerts(filters, (alert) => {
          // Update queries with new alert data
          queryClient.invalidateQueries({ queryKey: alertQueryKeys.lists() });
          queryClient.setQueryData(alertQueryKeys.detail(alert.id), alert);
        });
        setConnectionStatus('connected');
      } catch (error) {
        console.error('Failed to connect to real-time alerts:', error);
        setConnectionStatus('disconnected');
      }
    };

    connect();

    return () => {
      if (unsubscribe) {
        unsubscribe();
      }
    };
  }, [filters, queryClient]);

  return {
    connectionStatus,
    isConnected: connectionStatus === 'connected',
  };
}

// Alert export hook
export function useAlertExport() {
  const { showSuccess, showError } = useAppStore();

  return useMutation({
    mutationFn: (params: {
      filters?: AlertFilters;
      format: 'csv' | 'excel' | 'pdf' | 'json';
      includeDetails?: boolean;
    }) => alertService.exportAlerts(params),
    onSuccess: (result) => {
      showSuccess('Export initiated successfully');
      // Trigger download
      window.open(result.downloadUrl, '_blank');
    },
    onError: (error: any) => {
      showError('Failed to export alerts', error.message);
    },
  });
}
