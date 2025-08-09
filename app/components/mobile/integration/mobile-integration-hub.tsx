'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box,
  Card,
  CardHeader,
  CardContent,
  Typography,
  Chip,
  Alert,
  CircularProgress,
  IconButton,
  Badge,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  useTheme,
  useMediaQuery,
  LinearProgress
} from '@mui/material';
import {
  PhoneAndroid as PhoneAndroidIcon,
  Sync as SyncIcon,
  Notifications as NotificationsIcon,
  Analytics as AnalyticsIcon,
  Settings as SettingsIcon,
  CloudSync as CloudSyncIcon,
  SignalWifi4Bar as SignalWifi4BarIcon,
  SignalWifiOff as SignalWifiOffIcon,
  Battery80 as Battery80Icon,
  Speed as SpeedIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useWebSocket } from '../../../lib/hooks/use-websocket';
import { usePerformanceMonitor } from '../../../lib/hooks/use-performance-monitor';
import { UnifiedNotificationCenter } from './unified-notification-center';
import { NotificationSyncManager } from './notification-sync-manager';
import { MobileAnalyticsDashboard } from './mobile-analytics-dashboard';
import { NotificationPreferencesManager } from './notification-preferences-manager';
import { CrossPlatformNotificationSync } from './cross-platform-sync';
import {
  MobileIntegrationHubProps,
  IntegrationEvent,
  SyncStatus,
  NotificationAnalytics,
  PreferenceSettings,
  DeviceInfo
} from './types';

export const MobileIntegrationHub: React.FC<MobileIntegrationHubProps> = ({
  config,
  onIntegrationEvent,
  onSyncStatusChange,
  onAnalyticsUpdate,
  className,
  children
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  // State management
  const [integrationStatus, setIntegrationStatus] = useState<'initializing' | 'connected' | 'degraded' | 'offline'>('initializing');
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null);
  const [analytics, setAnalytics] = useState<NotificationAnalytics>({
    sent: 0,
    delivered: 0,
    read: 0,
    clicked: 0,
    dismissed: 0,
    failed: 0,
    deliveryRate: 0,
    readRate: 0,
    clickRate: 0,
    engagementScore: 0,
    averageDeliveryTime: 0,
    averageReadTime: 0,
    topCategories: [],
    deviceBreakdown: {},
    timeDistribution: [],
    preferenceUpdates: 0
  });
  const [connectedDevices, setConnectedDevices] = useState<DeviceInfo[]>([]);
  const [preferences, setPreferences] = useState<PreferenceSettings | null>(null);
  const [activeDialogs, setActiveDialogs] = useState<{
    notifications: boolean;
    analytics: boolean;
    preferences: boolean;
    sync: boolean;
  }>({ notifications: false, analytics: false, preferences: false, sync: false });
  const [errors, setErrors] = useState<string[]>([]);
  const [metrics, setMetrics] = useState({
    notifications: { pending: 0, processed: 0, failed: 0 },
    sync: { inProgress: false, lastSync: null, conflicts: 0 },
    performance: { latency: 0, throughput: 0, errorRate: 0 }
  });

  // Performance monitoring
  const { performanceData, trackEvent } = usePerformanceMonitor();

  // WebSocket connection for real-time integration
  const { isConnected, sendMessage, lastMessage } = useWebSocket(
    `/api/mobile-integration/ws?userId=${config.userId}&tenantId=${config.tenantId}`,
    {
      onMessage: handleIntegrationMessage,
      onError: handleIntegrationError,
      onConnect: handleIntegrationConnect,
      reconnectAttempts: 5,
      reconnectInterval: 3000
    }
  );

  // Integration initialization
  useEffect(() => {
    initializeIntegration();
    return () => {
      // Cleanup integration resources
      setIntegrationStatus('offline');
    };
  }, [config]);

  // Handle WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      handleIntegrationMessage(lastMessage);
    }
  }, [lastMessage]);

  const initializeIntegration = async () => {
    try {
      setIntegrationStatus('initializing');
      setErrors([]);
      trackEvent('mobile_integration_init_start');

      // Initialize components in parallel
      await Promise.all([
        initializeNotificationSystem(),
        initializeSyncManager(),
        initializeAnalytics(),
        loadUserPreferences(),
        discoverDevices()
      ]);

      setIntegrationStatus('connected');
      trackEvent('mobile_integration_init_complete');

      // Send initial integration event
      const initEvent: IntegrationEvent = {
        id: `init-${Date.now()}`,
        type: 'sync-completed',
        userId: config.userId,
        tenantId: config.tenantId,
        data: { status: 'initialized', capabilities: config.deviceInfo.capabilities },
        metadata: {
          source: 'mobile-integration-hub',
          timestamp: new Date()
        }
      };
      
      handleIntegrationEvent(initEvent);

    } catch (error) {
      console.error('Mobile integration initialization failed:', error);
      setIntegrationStatus('offline');
      addError(`Integration initialization failed: ${error.message}`);
      trackEvent('mobile_integration_init_error', { error: error.message });
    }
  };

  const initializeNotificationSystem = async () => {
    // Initialize push notification services
    console.log('Initializing notification system for platform:', config.deviceInfo.platform);
    
    // Register service worker for web push
    if (config.deviceInfo.platform === 'web' && 'serviceWorker' in navigator) {
      try {
        const registration = await navigator.serviceWorker.register('/sw.js');
        console.log('Service worker registered:', registration);
      } catch (error) {
        console.error('Service worker registration failed:', error);
      }
    }

    // Initialize push token management
    await updatePushToken();
  };

  const initializeSyncManager = async () => {
    console.log('Initializing sync manager with config:', config.sync);
    
    // Set initial sync status
    setSyncStatus({
      deviceId: config.deviceInfo.platform,
      lastSyncAt: new Date(),
      status: 'synced',
      pendingCount: 0,
      errorCount: 0,
      dataSize: 0,
      latency: 0,
      version: '1.0',
      conflicts: []
    });
  };

  const initializeAnalytics = async () => {
    // Load analytics data
    const analyticsData = await fetchAnalytics();
    setAnalytics(analyticsData);
  };

  const loadUserPreferences = async () => {
    try {
      const userPrefs = await fetchUserPreferences();
      setPreferences(userPrefs);
    } catch (error) {
      console.error('Failed to load user preferences:', error);
    }
  };

  const discoverDevices = async () => {
    try {
      const devices = await fetchConnectedDevices();
      setConnectedDevices(devices);
    } catch (error) {
      console.error('Failed to discover devices:', error);
    }
  };

  const updatePushToken = async () => {
    if (config.deviceInfo.pushToken) {
      // Register/update push token with backend
      sendMessage({
        type: 'register-token',
        payload: {
          token: config.deviceInfo.pushToken,
          platform: config.deviceInfo.platform,
          userId: config.userId,
          tenantId: config.tenantId
        }
      });
    }
  };

  const fetchAnalytics = async (): Promise<NotificationAnalytics> => {
    // Simulate fetching analytics data
    return {
      sent: 1247,
      delivered: 1198,
      read: 892,
      clicked: 234,
      dismissed: 156,
      failed: 49,
      deliveryRate: 96.1,
      readRate: 74.5,
      clickRate: 26.2,
      engagementScore: 82.3,
      averageDeliveryTime: 2.3, // seconds
      averageReadTime: 45.2, // seconds
      topCategories: [
        { category: 'Security Alerts', count: 456 },
        { category: 'System Status', count: 234 },
        { category: 'Compliance Updates', count: 189 }
      ],
      deviceBreakdown: {
        ios: 45,
        android: 38,
        web: 17
      },
      timeDistribution: Array.from({ length: 24 }, (_, i) => ({
        hour: i,
        count: Math.floor(Math.random() * 100) + 10
      })),
      preferenceUpdates: 23
    };
  };

  const fetchUserPreferences = async (): Promise<PreferenceSettings> => {
    // Simulate fetching user preferences
    return {
      userId: config.userId,
      tenantId: config.tenantId,
      channels: {},
      global: {
        enabled: true,
        quietHours: {
          enabled: true,
          start: '22:00',
          end: '08:00',
          timezone: 'UTC',
          daysOfWeek: [0, 1, 2, 3, 4, 5, 6],
          emergencyOverride: true
        },
        groupSimilar: true,
        maxDailyNotifications: 50,
        priorityFilter: 'all'
      },
      device: {
        sound: true,
        vibration: true,
        badge: true,
        lockScreenVisibility: 'private'
      },
      delivery: {
        instantPush: true,
        batchEmail: false,
        emergencySMS: true,
        inAppPersistence: 24
      },
      privacy: {
        shareAnalytics: true,
        personalizedContent: true,
        locationBased: false,
        crossDeviceSync: true
      },
      updatedAt: new Date(),
      version: 1
    };
  };

  const fetchConnectedDevices = async (): Promise<DeviceInfo[]> => {
    // Simulate fetching connected devices
    return [
      {
        id: 'device-1',
        name: 'iPhone 15 Pro',
        platform: 'ios',
        version: '17.2',
        lastSeen: new Date(Date.now() - 5 * 60 * 1000), // 5 minutes ago
        pushToken: 'apns-token-123',
        capabilities: ['push', 'background-sync', 'biometric-auth'],
        preferences: {},
        syncStatus: 'active'
      },
      {
        id: 'device-2',
        name: 'Chrome Browser',
        platform: 'web',
        version: '120.0',
        lastSeen: new Date(),
        pushToken: 'web-push-token-456',
        capabilities: ['web-push', 'service-worker', 'offline'],
        preferences: {},
        syncStatus: 'active'
      }
    ];
  };

  const handleIntegrationMessage = useCallback((message: any) => {
    try {
      const data = typeof message.data === 'string' ? JSON.parse(message.data) : message.data;
      
      switch (data.type) {
        case 'notification':
          handleNotificationMessage(data);
          break;
        case 'sync':
          handleSyncMessage(data);
          break;
        case 'analytics':
          handleAnalyticsMessage(data);
          break;
        case 'preferences':
          handlePreferencesMessage(data);
          break;
        case 'status':
          handleStatusMessage(data);
          break;
        default:
          console.warn('Unknown message type:', data.type);
      }
    } catch (error) {
      console.error('Failed to process integration message:', error);
    }
  }, []);

  const handleIntegrationError = useCallback((error: Event) => {
    console.error('Integration WebSocket error:', error);
    setIntegrationStatus('degraded');
    addError('Connection error - some features may be limited');
  }, []);

  const handleIntegrationConnect = useCallback(() => {
    console.log('Integration WebSocket connected');
    setIntegrationStatus('connected');
    clearErrors();
  }, []);

  const handleNotificationMessage = (data: any) => {
    setMetrics(prev => ({
      ...prev,
      notifications: {
        ...prev.notifications,
        processed: prev.notifications.processed + 1
      }
    }));

    const event: IntegrationEvent = {
      id: `notification-${Date.now()}`,
      type: 'notification-sent',
      userId: config.userId,
      tenantId: config.tenantId,
      messageId: data.messageId,
      data,
      metadata: {
        source: 'notification-service',
        timestamp: new Date()
      }
    };

    handleIntegrationEvent(event);
  };

  const handleSyncMessage = (data: any) => {
    const newSyncStatus: SyncStatus = {
      deviceId: data.deviceId || config.deviceInfo.platform,
      lastSyncAt: new Date(),
      status: data.status,
      pendingCount: data.pendingCount || 0,
      errorCount: data.errorCount || 0,
      dataSize: data.dataSize || 0,
      latency: data.latency || 0,
      version: data.version || '1.0',
      conflicts: data.conflicts || []
    };

    setSyncStatus(newSyncStatus);
    onSyncStatusChange?.(newSyncStatus);
  };

  const handleAnalyticsMessage = (data: any) => {
    setAnalytics(prev => ({ ...prev, ...data }));
    onAnalyticsUpdate?.(data);
  };

  const handlePreferencesMessage = (data: any) => {
    setPreferences(prev => ({ ...prev, ...data }));
  };

  const handleStatusMessage = (data: any) => {
    if (data.devices) {
      setConnectedDevices(data.devices);
    }
    
    if (data.status) {
      setIntegrationStatus(data.status);
    }
  };

  const handleIntegrationEvent = (event: IntegrationEvent) => {
    onIntegrationEvent?.(event);
  };

  const addError = (error: string) => {
    setErrors(prev => [error, ...prev.slice(0, 4)]); // Keep last 5 errors
  };

  const clearErrors = () => {
    setErrors([]);
  };

  const handleDialogToggle = (dialog: keyof typeof activeDialogs) => {
    setActiveDialogs(prev => ({ ...prev, [dialog]: !prev[dialog] }));
  };

  const getStatusColor = () => {
    switch (integrationStatus) {
      case 'connected': return 'success';
      case 'degraded': return 'warning';
      case 'offline': return 'error';
      default: return 'info';
    }
  };

  const getStatusIcon = () => {
    switch (integrationStatus) {
      case 'connected': return <CheckCircleIcon />;
      case 'degraded': return <WarningIcon />;
      case 'offline': return <ErrorIcon />;
      default: return <CircularProgress size={20} />;
    }
  };

  return (
    <Box className={className} sx={{ position: 'relative' }}>
      {/* Integration Status Card */}
      <Card
        sx={{
          position: 'fixed',
          bottom: isMobile ? 16 : 120,
          left: 16,
          zIndex: 1300,
          minWidth: 320,
          maxWidth: isMobile ? 'calc(100vw - 32px)' : 400,
          boxShadow: theme.shadows[8],
          bgcolor: 'background.paper',
          border: `2px solid ${theme.palette[getStatusColor()].main}`
        }}
      >
        <CardHeader
          avatar={
            <Badge badgeContent={errors.length} color="error">
              {getStatusIcon()}
            </Badge>
          }
          title={
            <Typography variant="subtitle2" fontWeight={600}>
              Mobile Integration Hub
            </Typography>
          }
          subheader={
            <Chip
              label={integrationStatus.toUpperCase()}
              size="small"
              color={getStatusColor()}
              variant="filled"
            />
          }
          action={
            <IconButton
              size="small"
              onClick={() => initializeIntegration()}
              disabled={integrationStatus === 'initializing'}
            >
              <RefreshIcon />
            </IconButton>
          }
          sx={{ pb: 1 }}
        />
        
        <CardContent sx={{ pt: 0 }}>
          {/* Connection Status */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            {isConnected ? (
              <SignalWifi4BarIcon color="success" />
            ) : (
              <SignalWifiOffIcon color="error" />
            )}
            <Typography variant="caption">
              {isConnected ? 'Real-time connected' : 'Offline mode'}
            </Typography>
            <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <SpeedIcon fontSize="small" color="action" />
              <Typography variant="caption">
                {metrics.performance.latency}ms
              </Typography>
            </Box>
          </Box>

          {/* Metrics Overview */}
          <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
            <Chip
              icon={<NotificationsIcon />}
              label={`${metrics.notifications.processed} sent`}
              size="small"
              variant="outlined"
              onClick={() => handleDialogToggle('notifications')}
            />
            <Chip
              icon={<SyncIcon />}
              label={`${connectedDevices.length} devices`}
              size="small"
              variant="outlined"
              onClick={() => handleDialogToggle('sync')}
            />
            <Chip
              icon={<AnalyticsIcon />}
              label={`${analytics.deliveryRate.toFixed(1)}% delivered`}
              size="small"
              variant="outlined"
              onClick={() => handleDialogToggle('analytics')}
            />
          </Box>

          {/* Error Display */}
          {errors.length > 0 && (
            <Alert severity="warning" sx={{ mb: 2 }} onClose={clearErrors}>
              <Typography variant="body2">
                {errors[0]}
              </Typography>
              {errors.length > 1 && (
                <Typography variant="caption">
                  +{errors.length - 1} more errors
                </Typography>
              )}
            </Alert>
          )}

          {/* Quick Actions */}
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Button
              size="small"
              variant="outlined"
              startIcon={<NotificationsIcon />}
              onClick={() => handleDialogToggle('notifications')}
            >
              Notifications
            </Button>
            <Button
              size="small"
              variant="outlined"
              startIcon={<AnalyticsIcon />}
              onClick={() => handleDialogToggle('analytics')}
            >
              Analytics
            </Button>
            <Button
              size="small"
              variant="outlined"
              startIcon={<SettingsIcon />}
              onClick={() => handleDialogToggle('preferences')}
            >
              Settings
            </Button>
          </Box>

          {/* Sync Progress */}
          {syncStatus?.status === 'pending' && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="caption" gutterBottom>
                Syncing across devices...
              </Typography>
              <LinearProgress />
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Unified Notification Center Dialog */}
      <Dialog
        open={activeDialogs.notifications}
        onClose={() => handleDialogToggle('notifications')}
        maxWidth="md"
        fullWidth
        fullScreen={isMobile}
      >
        <DialogTitle>Unified Notification Center</DialogTitle>
        <DialogContent>
          <UnifiedNotificationCenter
            config={config}
            onNotificationInteraction={(messageId, action) => {
              console.log('Notification interaction:', messageId, action);
            }}
            onPreferencesChange={(prefs) => {
              setPreferences(prefs);
            }}
            maxDisplayItems={50}
            autoRefresh={true}
            showAnalytics={true}
          />
        </DialogContent>
      </Dialog>

      {/* Mobile Analytics Dashboard Dialog */}
      <Dialog
        open={activeDialogs.analytics}
        onClose={() => handleDialogToggle('analytics')}
        maxWidth="lg"
        fullWidth
        fullScreen={isMobile}
      >
        <DialogTitle>Mobile Analytics Dashboard</DialogTitle>
        <DialogContent>
          <MobileAnalyticsDashboard
            config={config}
            analytics={analytics}
            timeRange="week"
            onTimeRangeChange={(range) => {
              console.log('Time range changed:', range);
            }}
            showRealTime={true}
          />
        </DialogContent>
      </Dialog>

      {/* Notification Preferences Dialog */}
      <Dialog
        open={activeDialogs.preferences}
        onClose={() => handleDialogToggle('preferences')}
        maxWidth="sm"
        fullWidth
        fullScreen={isMobile}
      >
        <DialogTitle>Notification Preferences</DialogTitle>
        <DialogContent>
          {preferences && (
            <NotificationPreferencesManager
              config={config}
              preferences={preferences}
              onPreferencesChange={(prefs) => {
                setPreferences(prefs);
              }}
              channels={[]} // Will be populated from API
              showAdvanced={true}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Cross-Platform Sync Dialog */}
      <Dialog
        open={activeDialogs.sync}
        onClose={() => handleDialogToggle('sync')}
        maxWidth="md"
        fullWidth
        fullScreen={isMobile}
      >
        <DialogTitle>Cross-Platform Sync</DialogTitle>
        <DialogContent>
          <CrossPlatformNotificationSync
            config={config}
            devices={connectedDevices}
            onSyncInitiated={() => {
              console.log('Sync initiated');
            }}
            onSyncCompleted={(results) => {
              console.log('Sync completed:', results);
            }}
            onSyncFailed={(error) => {
              console.error('Sync failed:', error);
              addError(`Sync failed: ${error}`);
            }}
          />
        </DialogContent>
      </Dialog>

      {/* Background Components */}
      <Box sx={{ display: 'none' }}>
        <NotificationSyncManager
          config={config}
          onSyncStatusChange={(status) => {
            setSyncStatus(status);
            onSyncStatusChange?.(status);
          }}
          onConflictDetected={(conflict) => {
            console.log('Sync conflict detected:', conflict);
          }}
          autoResolveConflicts={true}
          syncInterval={config.sync.syncInterval}
        />
      </Box>

      {children}
    </Box>
  );
};