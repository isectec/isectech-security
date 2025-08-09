/**
 * Common Types and Interfaces for iSECTECH Protect
 * Shared TypeScript definitions across the application
 */

// Base Entity Interface
export interface BaseEntity {
  id: string;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  updatedBy?: string;
}

// API Common Types
export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  field?: string;
  timestamp: Date;
  traceId: string;
}

export interface ApiSuccess<T = unknown> {
  success: true;
  data: T;
  message?: string;
  metadata?: ApiMetadata;
}

export interface ApiFailure {
  success: false;
  error: ApiError;
  errors?: ApiError[];
}

export type ApiResponse<T = unknown> = ApiSuccess<T> | ApiFailure;

export interface ApiMetadata {
  requestId: string;
  timestamp: Date;
  duration: number;
  version: string;
  rateLimit?: {
    limit: number;
    remaining: number;
    reset: Date;
  };
  pagination?: PaginationMeta;
}

// Pagination
export interface PaginationParams {
  page: number;
  limit: number;
  offset?: number;
}

export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
  offset: number;
}

export interface PaginatedData<T> {
  items: T[];
  meta: PaginationMeta;
}

// Sorting
export interface SortParams {
  field: string;
  direction: 'asc' | 'desc';
}

// Filtering
export interface FilterParams {
  field: string;
  operator: FilterOperator;
  value: unknown;
  type?: 'string' | 'number' | 'boolean' | 'date' | 'array';
}

export type FilterOperator = 
  | 'eq'        // equals
  | 'ne'        // not equals
  | 'gt'        // greater than
  | 'gte'       // greater than or equal
  | 'lt'        // less than
  | 'lte'       // less than or equal
  | 'in'        // in array
  | 'nin'       // not in array
  | 'contains'  // string contains
  | 'startsWith' // string starts with
  | 'endsWith'  // string ends with
  | 'regex'     // regex match
  | 'exists'    // field exists
  | 'null'      // field is null
  | 'empty';    // field is empty

// Search
export interface SearchParams {
  query?: string;
  fields?: string[];
  fuzzy?: boolean;
  highlight?: boolean;
  filters?: FilterParams[];
  sort?: SortParams[];
  pagination?: PaginationParams;
}

export interface SearchResult<T> {
  items: Array<T & { score?: number; highlights?: Record<string, string[]> }>;
  total: number;
  aggregations?: Record<string, unknown>;
  took: number;
  timedOut: boolean;
}

// Validation
export interface ValidationError {
  field: string;
  message: string;
  code: string;
  value?: unknown;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
}

// File Upload
export interface FileUpload {
  id: string;
  filename: string;
  originalName: string;
  mimeType: string;
  size: number;
  url: string;
  thumbnailUrl?: string;
  metadata?: Record<string, unknown>;
  uploadedAt: Date;
  uploadedBy: string;
}

export interface FileUploadProgress {
  id: string;
  filename: string;
  progress: number; // 0-100
  status: 'uploading' | 'processing' | 'completed' | 'failed';
  error?: string;
}

// Notification
export type NotificationType = 'info' | 'success' | 'warning' | 'error';
export type NotificationPosition = 'top-left' | 'top-center' | 'top-right' | 'bottom-left' | 'bottom-center' | 'bottom-right';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message?: string;
  duration?: number; // ms, 0 = persistent
  position?: NotificationPosition;
  actions?: NotificationAction[];
  data?: Record<string, unknown>;
  timestamp: Date;
  read: boolean;
}

export interface NotificationAction {
  label: string;
  action: string;
  primary?: boolean;
  destructive?: boolean;
}

// Theme and UI
export type ThemeMode = 'light' | 'dark' | 'auto';

export interface Theme {
  mode: ThemeMode;
  primaryColor: string;
  secondaryColor: string;
  backgroundColor: string;
  surfaceColor: string;
  textColor: string;
  borderColor: string;
  shadowColor: string;
  spacing: {
    xs: string;
    sm: string;
    md: string;
    lg: string;
    xl: string;
  };
  typography: {
    fontFamily: string;
    fontSize: Record<string, string>;
    fontWeight: Record<string, number>;
    lineHeight: Record<string, number>;
  };
  borderRadius: {
    sm: string;
    md: string;
    lg: string;
    xl: string;
  };
  animation: {
    duration: {
      fast: string;
      normal: string;
      slow: string;
    };
    easing: {
      ease: string;
      easeIn: string;
      easeOut: string;
      easeInOut: string;
    };
  };
}

// Charts and Visualization
export interface ChartDataPoint {
  x: number | string | Date;
  y: number;
  label?: string;
  color?: string;
  metadata?: Record<string, unknown>;
}

export interface ChartSeries {
  name: string;
  data: ChartDataPoint[];
  color?: string;
  type?: 'line' | 'bar' | 'area' | 'scatter' | 'pie';
}

export interface ChartConfig {
  type: 'line' | 'bar' | 'area' | 'scatter' | 'pie' | 'donut' | 'heatmap';
  width?: number;
  height?: number;
  responsive?: boolean;
  title?: string;
  subtitle?: string;
  xAxis?: {
    title?: string;
    type?: 'category' | 'datetime' | 'numeric';
    format?: string;
  };
  yAxis?: {
    title?: string;
    format?: string;
    min?: number;
    max?: number;
  };
  legend?: {
    show?: boolean;
    position?: 'top' | 'bottom' | 'left' | 'right';
  };
  tooltip?: {
    enabled?: boolean;
    format?: string;
  };
  colors?: string[];
  animation?: boolean;
}

// Data Export
export type ExportFormat = 'csv' | 'excel' | 'pdf' | 'json';

export interface ExportParams {
  format: ExportFormat;
  filename?: string;
  fields?: string[];
  filters?: FilterParams[];
  sort?: SortParams[];
}

export interface ExportJob {
  id: string;
  format: ExportFormat;
  filename: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  progress: number; // 0-100
  downloadUrl?: string;
  error?: string;
  createdAt: Date;
  completedAt?: Date;
  expiresAt?: Date;
}

// Audit Trail
export interface AuditEvent {
  id: string;
  tenantId: string;
  userId: string;
  action: string;
  resource: string;
  resourceId?: string;
  details: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
  success: boolean;
  error?: string;
}

// System Health
export interface HealthCheck {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  duration: number;
  checks: Record<string, HealthCheckResult>;
}

export interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  message?: string;
  duration: number;
  metadata?: Record<string, unknown>;
}

// Cache
export interface CacheEntry<T> {
  key: string;
  value: T;
  ttl: number;
  createdAt: Date;
  accessCount: number;
  lastAccessed: Date;
}

export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
  memory: number;
  hitRate: number;
}

// Feature Flags
export interface FeatureFlag {
  key: string;
  name: string;
  description: string;
  enabled: boolean;
  rolloutPercentage: number;
  conditions?: FeatureFlagCondition[];
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface FeatureFlagCondition {
  type: 'user' | 'tenant' | 'role' | 'custom';
  operator: 'eq' | 'ne' | 'in' | 'nin';
  value: unknown;
}

// WebSocket Events
export interface WebSocketMessage<T = unknown> {
  type: string;
  payload: T;
  timestamp: Date;
  id: string;
  correlationId?: string;
}

export interface WebSocketEvent {
  event: string;
  data: unknown;
  namespace?: string;
  room?: string;
}

// Preferences
export interface UserPreferences {
  theme: ThemeMode;
  language: string;
  timezone: string;
  dateFormat: string;
  timeFormat: '12h' | '24h';
  currency: string;
  dashboardLayout?: Record<string, unknown>;
  notifications: {
    email: boolean;
    browser: boolean;
    mobile: boolean;
    types: string[];
  };
  privacy: {
    shareAnalytics: boolean;
    shareUsageData: boolean;
  };
}

// Menu and Navigation
export interface MenuItem {
  id: string;
  label: string;
  icon?: string;
  url?: string;
  children?: MenuItem[];
  permissions?: string[];
  badge?: {
    text: string;
    color: string;
  };
  external?: boolean;
  divider?: boolean;
  disabled?: boolean;
}

export interface Breadcrumb {
  label: string;
  url?: string;
  icon?: string;
}

// Loading States
export interface LoadingState {
  isLoading: boolean;
  error: string | null;
  lastUpdated: Date | null;
}

export interface AsyncState<T> extends LoadingState {
  data: T | null;
}

// Generic Form Types
export interface FormField<T = string> {
  name: string;
  label: string;
  type: 'text' | 'email' | 'password' | 'number' | 'date' | 'select' | 'multiselect' | 'textarea' | 'checkbox' | 'radio' | 'file';
  value: T;
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  readonly?: boolean;
  options?: Array<{ label: string; value: T }>;
  validation?: {
    pattern?: string;
    min?: number;
    max?: number;
    minLength?: number;
    maxLength?: number;
    custom?: (value: T) => string | null;
  };
  help?: string;
  error?: string;
}

export interface FormState {
  isValid: boolean;
  isDirty: boolean;
  isSubmitting: boolean;
  errors: Record<string, string>;
  touched: Record<string, boolean>;
}

// Utility Types
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequiredBy<T, K extends keyof T> = T & Required<Pick<T, K>>;
export type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
export type DeepRequired<T> = {
  [P in keyof T]-?: T[P] extends object ? DeepRequired<T[P]> : T[P];
};

// Environment
export type Environment = 'development' | 'staging' | 'production' | 'test';

// Keyboard Shortcuts
export interface KeyboardShortcut {
  key: string;
  ctrlKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
  metaKey?: boolean;
  action: string;
  description: string;
  global?: boolean;
}

// Date Range
export interface DateRange {
  start: Date;
  end: Date;
}

export interface DateRangePreset {
  label: string;
  value: string;
  range: DateRange | (() => DateRange);
}