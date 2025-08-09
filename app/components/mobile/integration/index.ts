/**
 * Mobile System Integration Components
 * Centralized exports for mobile notification integration
 */

export { MobileIntegrationHub } from './mobile-integration-hub';
export { UnifiedNotificationCenter } from './unified-notification-center';
export { NotificationSyncManager } from './notification-sync-manager';
export { MobileAnalyticsDashboard } from './mobile-analytics-dashboard';
export { NotificationPreferencesManager } from './notification-preferences-manager';
export { CrossPlatformNotificationSync } from './cross-platform-sync';

export type {
  MobileIntegrationConfig,
  NotificationChannel,
  SyncStatus,
  AnalyticsMetric,
  PreferenceSettings,
  IntegrationEvent
} from './types';