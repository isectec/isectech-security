'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Box, Alert, Typography, CircularProgress, LinearProgress } from '@mui/material';
import { useWebSocket } from '../../../lib/hooks/use-websocket';
import { useSyncManager } from '../../../lib/hooks/use-sync-manager';
import {
  NotificationSyncManagerProps,
  SyncStatus,
  SyncConflict
} from './types';

export const NotificationSyncManager: React.FC<NotificationSyncManagerProps> = ({
  config,
  onSyncStatusChange,
  onConflictDetected,
  autoResolveConflicts = true,
  syncInterval = 30000
}) => {
  const [syncInProgress, setSyncInProgress] = useState(false);
  const [lastSyncAt, setLastSyncAt] = useState<Date | null>(null);
  const [pendingConflicts, setPendingConflicts] = useState<SyncConflict[]>([]);
  const [error, setError] = useState<string | null>(null);

  const {
    syncNotifications,
    resolveConflict,
    detectConflicts,
    mergeSyncData,
    validateSyncState
  } = useSyncManager({
    userId: config.userId,
    tenantId: config.tenantId,
    deviceId: config.deviceInfo.platform
  });

  // WebSocket for real-time sync coordination
  const { isConnected, sendMessage } = useWebSocket(
    `/api/sync/notifications/ws?userId=${config.userId}&tenantId=${config.tenantId}`,
    {
      onMessage: handleSyncMessage,
      onError: handleSyncError,
      reconnectAttempts: 3
    }
  );

  // Initialize sync manager
  useEffect(() => {
    initializeSync();
    
    if (config.sync.enableCrossPlatform) {
      startPeriodicSync();
    }

    return () => {
      stopPeriodicSync();
    };
  }, [config.sync.enableCrossPlatform, syncInterval]);

  const initializeSync = async () => {
    try {
      // Perform initial sync
      await performSync();
    } catch (error) {
      console.error('Initial sync failed:', error);
      setError('Failed to initialize sync');
    }
  };

  const startPeriodicSync = () => {
    const interval = setInterval(performSync, syncInterval);
    return () => clearInterval(interval);
  };

  const stopPeriodicSync = () => {
    // Cleanup handled by useEffect return
  };

  const performSync = async () => {
    if (syncInProgress) return;

    try {
      setSyncInProgress(true);
      setError(null);

      // Detect local changes
      const localChanges = await detectLocalChanges();
      
      // Fetch remote changes
      const remoteChanges = await fetchRemoteChanges();
      
      // Detect conflicts
      const conflicts = await detectConflicts(localChanges, remoteChanges);
      
      if (conflicts.length > 0) {
        setPendingConflicts(conflicts);
        
        // Auto-resolve conflicts if enabled
        if (autoResolveConflicts) {
          await resolveConflictsAutomatically(conflicts);
        } else {
          // Notify about conflicts
          conflicts.forEach(conflict => onConflictDetected?.(conflict));
        }
      }

      // Perform sync
      const syncResult = await syncNotifications(localChanges, remoteChanges);
      
      // Update sync status
      const status: SyncStatus = {
        deviceId: config.deviceInfo.platform,
        lastSyncAt: new Date(),
        status: 'synced',
        pendingCount: 0,
        errorCount: 0,
        dataSize: syncResult.dataSize || 0,
        latency: syncResult.duration || 0,
        version: '1.0',
        conflicts: pendingConflicts
      };

      setLastSyncAt(status.lastSyncAt);
      onSyncStatusChange(status);

    } catch (error) {
      console.error('Sync failed:', error);
      setError(`Sync failed: ${error.message}`);
      
      const status: SyncStatus = {
        deviceId: config.deviceInfo.platform,
        lastSyncAt: lastSyncAt || new Date(),
        status: 'failed',
        pendingCount: 1,
        errorCount: 1,
        dataSize: 0,
        latency: 0,
        version: '1.0',
        conflicts: pendingConflicts
      };

      onSyncStatusChange(status);
    } finally {
      setSyncInProgress(false);
    }
  };

  const detectLocalChanges = async () => {
    // Simulate detecting local changes
    return {
      notifications: [],
      preferences: {},
      readStates: {},
      deletedItems: []
    };
  };

  const fetchRemoteChanges = async () => {
    // Simulate fetching remote changes
    return {
      notifications: [],
      preferences: {},
      readStates: {},
      deletedItems: []
    };
  };

  const resolveConflictsAutomatically = async (conflicts: SyncConflict[]) => {
    for (const conflict of conflicts) {
      try {
        let resolution = 'server-wins'; // Default resolution strategy

        // Apply conflict resolution rules
        switch (conflict.type) {
          case 'notification':
            // For notifications, prefer server data (authoritative source)
            resolution = 'server-wins';
            break;
          case 'preferences':
            // For preferences, prefer local data (user choice)
            resolution = 'local-wins';
            break;
          case 'state':
            // For read/unread states, merge intelligently
            resolution = 'merged';
            break;
        }

        const resolvedData = await resolveConflict(conflict, resolution);
        
        // Update conflict status
        const updatedConflict = {
          ...conflict,
          resolution: resolution as any,
          resolvedData,
          resolvedAt: new Date()
        };

        setPendingConflicts(prev => 
          prev.map(c => c.id === conflict.id ? updatedConflict : c)
        );

      } catch (error) {
        console.error(`Failed to resolve conflict ${conflict.id}:`, error);
      }
    }
  };

  const handleSyncMessage = useCallback((message: any) => {
    try {
      const data = JSON.parse(message.data);
      
      switch (data.type) {
        case 'sync-request':
          // Another device requested sync
          performSync();
          break;
        case 'conflict-detected':
          // Server detected a conflict
          const conflict: SyncConflict = data.conflict;
          setPendingConflicts(prev => [...prev, conflict]);
          onConflictDetected?.(conflict);
          break;
        case 'sync-completed':
          // Sync completed on another device
          setLastSyncAt(new Date(data.timestamp));
          break;
      }
    } catch (error) {
      console.error('Failed to handle sync message:', error);
    }
  }, [onConflictDetected]);

  const handleSyncError = useCallback((error: Event) => {
    console.error('Sync WebSocket error:', error);
    setError('Real-time sync connection failed');
  }, []);

  return (
    <Box sx={{ display: 'none' }}>
      {/* Hidden component - sync happens in background */}
      {syncInProgress && (
        <Box sx={{ mb: 1 }}>
          <Typography variant="caption">Syncing notifications...</Typography>
          <LinearProgress />
        </Box>
      )}
      
      {error && (
        <Alert severity="error" sx={{ mb: 1 }}>
          {error}
        </Alert>
      )}
      
      {pendingConflicts.length > 0 && !autoResolveConflicts && (
        <Alert severity="warning" sx={{ mb: 1 }}>
          {pendingConflicts.length} sync conflict{pendingConflicts.length > 1 ? 's' : ''} require attention
        </Alert>
      )}
    </Box>
  );
};