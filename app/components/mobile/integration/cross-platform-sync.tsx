'use client';

import React, { useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardHeader,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Button,
  LinearProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Grid,
  Avatar,
  useTheme
} from '@mui/material';
import {
  PhoneAndroid as PhoneAndroidIcon,
  PhoneIphone as PhoneIphoneIcon,
  Computer as ComputerIcon,
  Laptop as LaptopIcon,
  Sync as SyncIcon,
  CloudSync as CloudSyncIcon,
  Check as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Refresh as RefreshIcon,
  Settings as SettingsIcon
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { CrossPlatformSyncProps, DeviceInfo, SyncResult } from './types';

export const CrossPlatformNotificationSync: React.FC<CrossPlatformSyncProps> = ({
  config,
  devices,
  onSyncInitiated,
  onSyncCompleted,
  onSyncFailed
}) => {
  const theme = useTheme();
  
  const [syncInProgress, setSyncInProgress] = useState(false);
  const [syncProgress, setSyncProgress] = useState(0);
  const [syncResults, setSyncResults] = useState<SyncResult[]>([]);
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set());
  const [showSyncDialog, setShowSyncDialog] = useState(false);
  const [lastSyncAt, setLastSyncAt] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  const getDeviceIcon = (platform: string) => {
    switch (platform) {
      case 'ios': return <PhoneIphoneIcon />;
      case 'android': return <PhoneAndroidIcon />;
      case 'web': return <ComputerIcon />;
      case 'desktop': return <LaptopIcon />;
      default: return <ComputerIcon />;
    }
  };

  const getDeviceColor = (syncStatus: string) => {
    switch (syncStatus) {
      case 'active': return 'success';
      case 'inactive': return 'warning';
      case 'offline': return 'error';
      default: return 'default';
    }
  };

  const handleDeviceToggle = (deviceId: string) => {
    setSelectedDevices(prev => {
      const newSet = new Set(prev);
      if (newSet.has(deviceId)) {
        newSet.delete(deviceId);
      } else {
        newSet.add(deviceId);
      }
      return newSet;
    });
  };

  const handleSelectAll = () => {
    const activeDevices = devices.filter(d => d.syncStatus === 'active').map(d => d.id);
    setSelectedDevices(new Set(activeDevices));
  };

  const handleDeselectAll = () => {
    setSelectedDevices(new Set());
  };

  const initiateSync = async () => {
    if (selectedDevices.size === 0) {
      setError('Please select at least one device to sync');
      return;
    }

    try {
      setSyncInProgress(true);
      setSyncProgress(0);
      setError(null);
      setSyncResults([]);
      
      onSyncInitiated?.();

      const deviceList = devices.filter(d => selectedDevices.has(d.id));
      const totalSteps = deviceList.length * 3; // 3 steps per device
      let completedSteps = 0;

      const results: SyncResult[] = [];

      for (const device of deviceList) {
        try {
          // Step 1: Prepare sync
          await simulateAsyncOperation(500);
          completedSteps++;
          setSyncProgress((completedSteps / totalSteps) * 100);

          // Step 2: Transfer data
          await simulateAsyncOperation(1000);
          completedSteps++;
          setSyncProgress((completedSteps / totalSteps) * 100);

          // Step 3: Verify sync
          await simulateAsyncOperation(300);
          completedSteps++;
          setSyncProgress((completedSteps / totalSteps) * 100);

          // Record successful result
          const result: SyncResult = {
            deviceId: device.id,
            status: 'success',
            itemsSynced: Math.floor(Math.random() * 100) + 10,
            errors: [],
            conflictsResolved: Math.floor(Math.random() * 3),
            duration: 1800 + Math.random() * 500
          };

          results.push(result);

        } catch (deviceError) {
          // Record failed result
          const result: SyncResult = {
            deviceId: device.id,
            status: 'failed',
            itemsSynced: 0,
            errors: [deviceError.message || 'Sync failed'],
            conflictsResolved: 0,
            duration: 0
          };

          results.push(result);
        }
      }

      setSyncResults(results);
      setLastSyncAt(new Date());

      // Check if all syncs were successful
      const hasFailures = results.some(r => r.status === 'failed');
      if (hasFailures) {
        onSyncFailed?.('Some devices failed to sync');
      } else {
        onSyncCompleted?.(results);
      }

    } catch (error) {
      console.error('Sync operation failed:', error);
      setError(`Sync failed: ${error.message}`);
      onSyncFailed?.(error.message);
    } finally {
      setSyncInProgress(false);
      setSyncProgress(0);
    }
  };

  const simulateAsyncOperation = (delay: number): Promise<void> => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        // Simulate 5% chance of failure
        if (Math.random() < 0.05) {
          reject(new Error('Random sync failure'));
        } else {
          resolve();
        }
      }, delay);
    });
  };

  const getSyncResultSummary = () => {
    if (syncResults.length === 0) return null;

    const successful = syncResults.filter(r => r.status === 'success').length;
    const failed = syncResults.filter(r => r.status === 'failed').length;
    const totalItems = syncResults.reduce((sum, r) => sum + r.itemsSynced, 0);
    const totalConflicts = syncResults.reduce((sum, r) => sum + r.conflictsResolved, 0);

    return { successful, failed, totalItems, totalConflicts };
  };

  const summary = getSyncResultSummary();

  return (
    <Box sx={{ p: 2 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h6" fontWeight={600}>
          Cross-Platform Sync
        </Typography>
        
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            size="small"
            onClick={() => setShowSyncDialog(true)}
            disabled={syncInProgress}
          >
            <SettingsIcon sx={{ mr: 1 }} />
            Sync Settings
          </Button>
          
          <Button
            variant="contained"
            onClick={initiateSync}
            disabled={syncInProgress || selectedDevices.size === 0}
            startIcon={syncInProgress ? <CircularProgress size={20} /> : <SyncIcon />}
          >
            {syncInProgress ? 'Syncing...' : 'Start Sync'}
          </Button>
        </Box>
      </Box>

      {/* Sync Progress */}
      {syncInProgress && (
        <Card sx={{ mb: 2, bgcolor: 'primary.light' }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <CloudSyncIcon sx={{ mr: 1, color: 'white' }} />
              <Typography variant="h6" color="white">
                Synchronizing notifications...
              </Typography>
            </Box>
            <LinearProgress 
              variant="determinate" 
              value={syncProgress} 
              sx={{ 
                height: 8, 
                borderRadius: 4,
                bgcolor: 'rgba(255,255,255,0.3)',
                '& .MuiLinearProgress-bar': {
                  bgcolor: 'white'
                }
              }} 
            />
            <Typography variant="body2" color="rgba(255,255,255,0.8)" sx={{ mt: 1 }}>
              {syncProgress.toFixed(0)}% complete
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Sync Results Summary */}
      {summary && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="body2" gutterBottom>
            <strong>Sync Complete:</strong> {summary.successful} successful, {summary.failed} failed
          </Typography>
          <Typography variant="body2">
            Synced {summary.totalItems} items, resolved {summary.totalConflicts} conflicts
          </Typography>
        </Alert>
      )}

      {/* Device Selection */}
      <Card sx={{ mb: 2 }}>
        <CardHeader
          title="Connected Devices"
          subheader={`${devices.length} devices • Last sync: ${lastSyncAt ? formatDistanceToNow(lastSyncAt, { addSuffix: true }) : 'Never'}`}
          action={
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button size="small" onClick={handleSelectAll}>
                Select All
              </Button>
              <Button size="small" onClick={handleDeselectAll}>
                Deselect All
              </Button>
            </Box>
          }
        />
        
        <CardContent sx={{ pt: 0 }}>
          <List>
            {devices.map((device, index) => {
              const isSelected = selectedDevices.has(device.id);
              const syncResult = syncResults.find(r => r.deviceId === device.id);
              
              return (
                <ListItem
                  key={device.id}
                  button
                  onClick={() => handleDeviceToggle(device.id)}
                  sx={{
                    borderRadius: 2,
                    mb: 1,
                    bgcolor: isSelected ? 'action.selected' : 'transparent',
                    '&:hover': {
                      bgcolor: 'action.hover'
                    }
                  }}
                >
                  <ListItemIcon>
                    <Avatar sx={{ bgcolor: theme.palette[getDeviceColor(device.syncStatus)].main }}>
                      {getDeviceIcon(device.platform)}
                    </Avatar>
                  </ListItemIcon>
                  
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="subtitle1">
                          {device.name}
                        </Typography>
                        <Chip
                          label={device.syncStatus}
                          size="small"
                          color={getDeviceColor(device.syncStatus)}
                          variant="outlined"
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" color="text.secondary">
                          {device.platform} {device.version} • Last seen: {formatDistanceToNow(device.lastSeen, { addSuffix: true })}
                        </Typography>
                        {syncResult && (
                          <Typography variant="caption" color={syncResult.status === 'success' ? 'success.main' : 'error.main'}>
                            {syncResult.status === 'success' 
                              ? `✓ ${syncResult.itemsSynced} items synced` 
                              : `✗ ${syncResult.errors.join(', ')}`}
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                  
                  <ListItemSecondaryAction>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {syncResult && (
                        <IconButton size="small">
                          {syncResult.status === 'success' ? (
                            <CheckIcon color="success" />
                          ) : (
                            <ErrorIcon color="error" />
                          )}
                        </IconButton>
                      )}
                      
                      <Chip
                        label={device.capabilities.length}
                        size="small"
                        variant="outlined"
                      />
                    </Box>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
        </CardContent>
      </Card>

      {/* Sync Statistics */}
      {syncResults.length > 0 && (
        <Card>
          <CardHeader title="Sync Results" />
          <CardContent>
            <Grid container spacing={2}>
              {syncResults.map((result) => {
                const device = devices.find(d => d.id === result.deviceId);
                return (
                  <Grid item xs={12} sm={6} md={4} key={result.deviceId}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          {getDeviceIcon(device?.platform || 'web')}
                          <Typography variant="subtitle2" sx={{ ml: 1 }}>
                            {device?.name || 'Unknown Device'}
                          </Typography>
                        </Box>
                        
                        <Typography variant="body2" gutterBottom>
                          Status: <Chip 
                            label={result.status} 
                            size="small" 
                            color={result.status === 'success' ? 'success' : 'error'}
                          />
                        </Typography>
                        
                        {result.status === 'success' ? (
                          <>
                            <Typography variant="body2">
                              Items synced: {result.itemsSynced}
                            </Typography>
                            <Typography variant="body2">
                              Conflicts resolved: {result.conflictsResolved}
                            </Typography>
                            <Typography variant="body2">
                              Duration: {(result.duration / 1000).toFixed(1)}s
                            </Typography>
                          </>
                        ) : (
                          <Typography variant="body2" color="error">
                            {result.errors.join(', ')}
                          </Typography>
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                );
              })}
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Sync Settings Dialog */}
      <Dialog
        open={showSyncDialog}
        onClose={() => setShowSyncDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Sync Settings</DialogTitle>
        <DialogContent>
          <Typography variant="body2" paragraph>
            Configure how notifications are synchronized across your devices.
          </Typography>
          
          {/* Sync settings would go here */}
          <Alert severity="info">
            Advanced sync settings will be available in a future update.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowSyncDialog(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};