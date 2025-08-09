/**
 * Mobile System Integration Types
 * Type definitions for mobile notification integration
 */

import { ReactNode } from 'react';

export interface MobileIntegrationConfig {
  userId: string;
  tenantId: string;
  deviceInfo: {
    platform: 'ios' | 'android' | 'web';
    version: string;
    capabilities: string[];
    pushToken?: string;
  };
  preferences: {
    enablePushNotifications: boolean;
    enableWebPushNotifications: boolean;
    enableEmailNotifications: boolean;
    enableSMSNotifications: boolean;
    quietHours: {
      enabled: boolean;
      start: string; // HH:mm format
      end: string;
    };
    notificationGrouping: boolean;
    soundEnabled: boolean;
    vibrationEnabled: boolean;
    priority: 'all' | 'high-only' | 'critical-only';
  };
  sync: {
    enableCrossPlatform: boolean;
    syncInterval: number;
    offlineQueueSize: number;
    retryAttempts: number;
  };
  analytics: {
    trackDelivery: boolean;
    trackEngagement: boolean;
    trackPreferences: boolean;
    retentionPeriod: number; // days
  };
}

export interface NotificationChannel {
  id: string;
  name: string;
  type: 'security-alert' | 'compliance-update' | 'system-status' | 'user-action' | 'executive-summary';
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  delivery: {
    push: boolean;
    email: boolean;
    sms: boolean;
    inApp: boolean;
  };
  formatting: {
    template: string;
    variables: string[];
    maxLength: number;
    truncation: 'word' | 'character';
  };
  scheduling: {
    immediate: boolean;
    batchWindow: number; // minutes
    respectQuietHours: boolean;
  };
  targeting: {
    roles: string[];
    tenants: string[];
    devices: string[];
  };
}

export interface NotificationMessage {
  id: string;
  channelId: string;
  title: string;
  body: string;
  data: Record<string, any>;
  priority: 'low' | 'medium' | 'high' | 'critical';
  targetUsers: string[];
  targetTenants: string[];
  delivery: {
    push?: PushDelivery;
    email?: EmailDelivery;
    sms?: SMSDelivery;
    inApp?: InAppDelivery;
  };
  scheduling: {
    sendAt?: Date;
    expiresAt?: Date;
    batchId?: string;
  };
  metadata: {
    source: string;
    category: string;
    tags: string[];
    correlationId?: string;
  };
  createdAt: Date;
  updatedAt: Date;
}

export interface PushDelivery {
  fcmToken?: string;
  apnsToken?: string;
  webPushEndpoint?: string;
  sound?: string;
  badge?: number;
  clickAction?: string;
  icon?: string;
  image?: string;
  actions?: PushAction[];
}

export interface PushAction {
  action: string;
  title: string;
  icon?: string;
}

export interface EmailDelivery {
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  htmlBody?: string;
  textBody?: string;
  attachments?: EmailAttachment[];
}

export interface EmailAttachment {
  filename: string;
  content: string;
  contentType: string;
}

export interface SMSDelivery {
  to: string[];
  message: string;
  sender?: string;
}

export interface InAppDelivery {
  userId: string;
  persistent: boolean;
  actionRequired: boolean;
  actions?: InAppAction[];
}

export interface InAppAction {
  action: string;
  label: string;
  url?: string;
  callback?: string;
}

export interface DeliveryReceipt {
  messageId: string;
  channel: 'push' | 'email' | 'sms' | 'in-app';
  status: 'sent' | 'delivered' | 'read' | 'failed' | 'expired';
  deliveredAt?: Date;
  readAt?: Date;
  failureReason?: string;
  deviceInfo?: {
    platform: string;
    version: string;
    location?: string;
  };
  userInteraction?: {
    clicked: boolean;
    dismissed: boolean;
    actionTaken?: string;
  };
}

export interface SyncStatus {
  deviceId: string;
  lastSyncAt: Date;
  status: 'synced' | 'pending' | 'failed' | 'offline';
  pendingCount: number;
  errorCount: number;
  dataSize: number; // bytes
  latency: number; // milliseconds
  version: string;
  conflicts: SyncConflict[];
}

export interface SyncConflict {
  id: string;
  type: 'notification' | 'preferences' | 'state';
  itemId: string;
  localData: any;
  serverData: any;
  resolvedData?: any;
  resolution: 'local-wins' | 'server-wins' | 'merged' | 'manual' | 'pending';
  conflictedAt: Date;
  resolvedAt?: Date;
}

export interface AnalyticsMetric {
  id: string;
  name: string;
  value: number;
  unit: string;
  timestamp: Date;
  dimensions: {
    userId?: string;
    tenantId?: string;
    deviceType?: string;
    channel?: string;
    messageType?: string;
  };
  metadata: Record<string, any>;
}

export interface NotificationAnalytics {
  sent: number;
  delivered: number;
  read: number;
  clicked: number;
  dismissed: number;
  failed: number;
  deliveryRate: number;
  readRate: number;
  clickRate: number;
  engagementScore: number;
  averageDeliveryTime: number;
  averageReadTime: number;
  topCategories: Array<{ category: string; count: number; }>;
  deviceBreakdown: Record<string, number>;
  timeDistribution: Array<{ hour: number; count: number; }>;
  preferenceUpdates: number;
}

export interface PreferenceSettings {
  userId: string;
  tenantId: string;
  channels: Record<string, ChannelPreference>;
  global: {
    enabled: boolean;
    quietHours: QuietHours;
    groupSimilar: boolean;
    maxDailyNotifications: number;
    priorityFilter: 'all' | 'high' | 'critical';
  };
  device: {
    sound: boolean;
    vibration: boolean;
    badge: boolean;
    lockScreenVisibility: 'public' | 'private' | 'secret';
  };
  delivery: {
    instantPush: boolean;
    batchEmail: boolean;
    emergencySMS: boolean;
    inAppPersistence: number; // hours
  };
  privacy: {
    shareAnalytics: boolean;
    personalizedContent: boolean;
    locationBased: boolean;
    crossDeviceSync: boolean;
  };
  updatedAt: Date;
  version: number;
}

export interface ChannelPreference {
  enabled: boolean;
  priority: 'low' | 'medium' | 'high' | 'critical';
  delivery: {
    push: boolean;
    email: boolean;
    sms: boolean;
    inApp: boolean;
  };
  batching: {
    enabled: boolean;
    windowMinutes: number;
    maxBatchSize: number;
  };
  customization: {
    sound?: string;
    color?: string;
    icon?: string;
  };
}

export interface QuietHours {
  enabled: boolean;
  start: string; // HH:mm
  end: string; // HH:mm
  timezone: string;
  daysOfWeek: number[]; // 0-6, Sunday = 0
  emergencyOverride: boolean;
}

export interface IntegrationEvent {
  id: string;
  type: 'notification-sent' | 'delivery-confirmed' | 'user-interaction' | 'sync-completed' | 'preference-updated' | 'analytics-updated';
  userId: string;
  tenantId: string;
  deviceId?: string;
  messageId?: string;
  data: any;
  metadata: {
    source: string;
    correlationId?: string;
    sessionId?: string;
    timestamp: Date;
  };
}

export interface WebSocketMessage {
  type: 'notification' | 'sync' | 'analytics' | 'preferences' | 'status';
  payload: any;
  timestamp: Date;
  id: string;
}

export interface OfflineQueue {
  id: string;
  items: OfflineQueueItem[];
  maxSize: number;
  currentSize: number;
  lastProcessedAt?: Date;
  processingErrors: number;
}

export interface OfflineQueueItem {
  id: string;
  type: 'send-notification' | 'update-preferences' | 'mark-read' | 'sync-state';
  data: any;
  timestamp: Date;
  attempts: number;
  maxAttempts: number;
  priority: number;
  dependencies?: string[];
}

// React Component Props
export interface MobileIntegrationHubProps {
  config: MobileIntegrationConfig;
  onIntegrationEvent?: (event: IntegrationEvent) => void;
  onSyncStatusChange?: (status: SyncStatus) => void;
  onAnalyticsUpdate?: (analytics: NotificationAnalytics) => void;
  className?: string;
  children?: ReactNode;
}

export interface UnifiedNotificationCenterProps {
  config: MobileIntegrationConfig;
  onNotificationInteraction?: (messageId: string, action: string) => void;
  onPreferencesChange?: (preferences: PreferenceSettings) => void;
  maxDisplayItems?: number;
  autoRefresh?: boolean;
  showAnalytics?: boolean;
}

export interface NotificationSyncManagerProps {
  config: MobileIntegrationConfig;
  onSyncStatusChange: (status: SyncStatus) => void;
  onConflictDetected?: (conflict: SyncConflict) => void;
  autoResolveConflicts?: boolean;
  syncInterval?: number;
}

export interface MobileAnalyticsDashboardProps {
  config: MobileIntegrationConfig;
  analytics: NotificationAnalytics;
  timeRange: 'hour' | 'day' | 'week' | 'month';
  onTimeRangeChange?: (range: string) => void;
  showRealTime?: boolean;
}

export interface NotificationPreferencesManagerProps {
  config: MobileIntegrationConfig;
  preferences: PreferenceSettings;
  onPreferencesChange: (preferences: PreferenceSettings) => void;
  channels: NotificationChannel[];
  showAdvanced?: boolean;
}

export interface CrossPlatformSyncProps {
  config: MobileIntegrationConfig;
  devices: DeviceInfo[];
  onSyncInitiated?: () => void;
  onSyncCompleted?: (results: SyncResult[]) => void;
  onSyncFailed?: (error: string) => void;
}

export interface DeviceInfo {
  id: string;
  name: string;
  platform: 'ios' | 'android' | 'web' | 'desktop';
  version: string;
  lastSeen: Date;
  pushToken?: string;
  capabilities: string[];
  preferences: Partial<PreferenceSettings>;
  syncStatus: 'active' | 'inactive' | 'offline';
}

export interface SyncResult {
  deviceId: string;
  status: 'success' | 'partial' | 'failed';
  itemsSynced: number;
  errors: string[];
  conflictsResolved: number;
  duration: number; // milliseconds
}

// Service Worker Types
export interface ServiceWorkerNotification {
  title: string;
  body: string;
  icon?: string;
  badge?: string;
  image?: string;
  tag?: string;
  data?: any;
  requireInteraction?: boolean;
  silent?: boolean;
  timestamp?: number;
  actions?: ServiceWorkerAction[];
}

export interface ServiceWorkerAction {
  action: string;
  title: string;
  icon?: string;
}

export interface BackgroundSyncTask {
  id: string;
  type: string;
  data: any;
  timestamp: Date;
  retryCount: number;
  maxRetries: number;
}