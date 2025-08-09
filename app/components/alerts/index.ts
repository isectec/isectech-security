/**
 * Alert Components Index for iSECTECH Protect
 * Exports for intelligent alert management components
 */

export { AlertBulkActions } from './alert-bulk-actions';
export { AlertCorrelationView } from './alert-correlation-view';
export { AlertFilters } from './alert-filters';
export { AlertList } from './alert-list';
export { AlertManagementPage } from './alert-management-page';

// Re-export types for convenience
export type { AlertFilters as AlertFiltersType } from '@/lib/api/services/alerts';

export default AlertManagementPage;
