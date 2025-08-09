/**
 * White-Labeling Types for iSECTECH Protect
 * Production-grade TypeScript definitions for white-labeling and branding system
 */

import { BaseEntity } from './common';

// Asset Management Types
export type AssetType = 'logo-primary' | 'logo-secondary' | 'favicon' | 'email-header' | 'report-header' | 'mobile-icon' | 'background' | 'watermark';

export type AssetFormat = 'svg' | 'png' | 'jpg' | 'ico' | 'webp';

export interface BrandAsset extends BaseEntity {
  name: string;
  type: AssetType;
  format: AssetFormat;
  url: string;
  thumbnailUrl?: string;
  fileSize: number;
  dimensions: {
    width: number;
    height: number;
  };
  metadata: {
    alt?: string;
    title?: string;
    description?: string;
  };
  version: string;
  isActive: boolean;
  tenantId: string;
}

export interface AssetUploadRequest {
  name: string;
  type: AssetType;
  file: File;
  metadata?: {
    alt?: string;
    title?: string;
    description?: string;
  };
}

// Color Scheme Types
export interface ColorPalette {
  primary: string;
  primaryDark: string;
  primaryLight: string;
  secondary: string;
  secondaryDark: string;
  secondaryLight: string;
  accent: string;
  accentDark: string;
  accentLight: string;
  success: string;
  warning: string;
  error: string;
  info: string;
  background: string;
  surface: string;
  text: {
    primary: string;
    secondary: string;
    disabled: string;
  };
  border: string;
  divider: string;
}

export interface ColorScheme extends BaseEntity {
  name: string;
  description: string;
  light: ColorPalette;
  dark: ColorPalette;
  isDefault: boolean;
  tenantId: string;
}

// Typography Types
export type FontWeight = 100 | 200 | 300 | 400 | 500 | 600 | 700 | 800 | 900;

export interface FontFamily {
  name: string;
  fallback: string[];
  webFont?: {
    provider: 'google' | 'adobe' | 'custom';
    url: string;
    weights: FontWeight[];
  };
}

export interface TypographyScale {
  h1: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  h2: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  h3: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  h4: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  h5: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  h6: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  body1: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  body2: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  caption: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
  };
  button: {
    fontSize: string;
    fontWeight: FontWeight;
    lineHeight: number;
    letterSpacing?: string;
    textTransform?: 'uppercase' | 'lowercase' | 'capitalize' | 'none';
  };
}

export interface TypographyTheme extends BaseEntity {
  name: string;
  description: string;
  fontFamily: FontFamily;
  scale: TypographyScale;
  isDefault: boolean;
  tenantId: string;
}

// Theme Configuration Types
export interface ThemeConfiguration extends BaseEntity {
  name: string;
  description: string;
  colorScheme: ColorScheme;
  typography: TypographyTheme;
  assets: Record<AssetType, BrandAsset | null>;
  customCss?: string;
  isActive: boolean;
  version: string;
  tenantId: string;
}

// Content Customization Types
export type ContentType = 'welcome-message' | 'help-text' | 'error-message' | 'success-message' | 'terminology' | 'legal-document';

export interface ContentTemplate extends BaseEntity {
  type: ContentType;
  key: string;
  defaultContent: string;
  customContent?: string;
  variables: string[];
  isHtml: boolean;
  tenantId: string;
}

export interface TerminologyMapping extends BaseEntity {
  originalTerm: string;
  customTerm: string;
  context: string[];
  caseSensitive: boolean;
  tenantId: string;
}

// Domain Configuration Types
export type DomainType = 'subdomain' | 'custom-domain';

export type DomainStatus = 'pending' | 'verifying' | 'active' | 'failed' | 'suspended';

export interface DomainConfiguration extends BaseEntity {
  type: DomainType;
  domain: string;
  subdomain?: string;
  status: DomainStatus;
  sslCertificate: {
    status: 'pending' | 'active' | 'expired' | 'failed';
    issuer?: string;
    expiresAt?: Date;
    autoRenew: boolean;
  };
  dnsRecords: {
    type: 'A' | 'CNAME' | 'TXT';
    name: string;
    value: string;
    verified: boolean;
  }[];
  redirects: {
    from: string;
    to: string;
    permanent: boolean;
  }[];
  tenantId: string;
}

// Email Template Types
export type EmailType = 'welcome' | 'password-reset' | 'alert-notification' | 'report-delivery' | 'system-notification' | 'invitation' | 'reminder';

export interface EmailTemplate extends BaseEntity {
  type: EmailType;
  name: string;
  subject: string;
  htmlContent: string;
  textContent: string;
  variables: string[];
  previewData?: Record<string, string>;
  isDefault: boolean;
  tenantId: string;
}

// White-Label Configuration (Main Entity)
export type ConfigurationStatus = 'draft' | 'review' | 'approved' | 'active' | 'archived';

export interface WhiteLabelConfiguration extends BaseEntity {
  name: string;
  description: string;
  status: ConfigurationStatus;
  theme: ThemeConfiguration;
  content: ContentTemplate[];
  terminology: TerminologyMapping[];
  domain?: DomainConfiguration;
  emailTemplates: EmailTemplate[];
  legalDocuments: {
    privacyPolicy?: string;
    termsOfService?: string;
    cookiePolicy?: string;
    dataProcessingAgreement?: string;
    complianceStatement?: string;
  };
  approvalWorkflow?: {
    requiredApprovers: string[];
    currentApprovers: string[];
    comments: {
      userId: string;
      comment: string;
      timestamp: Date;
    }[];
  };
  version: string;
  isActive: boolean;
  tenantId: string;
}

// Configuration Management Types
export interface ConfigurationPreview {
  configurationId: string;
  previewUrl: string;
  screenshots: {
    desktop: string;
    tablet: string;
    mobile: string;
  };
  generatedAt: Date;
  expiresAt: Date;
}

export interface ConfigurationDeployment extends BaseEntity {
  configurationId: string;
  fromVersion: string;
  toVersion: string;
  deployedBy: string;
  deploymentStatus: 'pending' | 'in-progress' | 'completed' | 'failed' | 'rolled-back';
  rollbackVersion?: string;
  deploymentLog: {
    timestamp: Date;
    level: 'info' | 'warn' | 'error';
    message: string;
  }[];
  tenantId: string;
}

// Access Control Types
export type BrandingPermission = 
  | 'brand:read'
  | 'brand:write'
  | 'brand:delete'
  | 'brand:approve'
  | 'brand:deploy'
  | 'brand:audit'
  | 'assets:upload'
  | 'assets:delete'
  | 'theme:edit'
  | 'content:edit'
  | 'domain:configure'
  | 'email:template:edit';

export interface BrandingRole extends BaseEntity {
  name: string;
  description: string;
  permissions: BrandingPermission[];
  isDefault: boolean;
  tenantId: string;
}

// Audit and Logging Types
export type BrandingAuditAction = 
  | 'configuration:create'
  | 'configuration:update'
  | 'configuration:delete'
  | 'configuration:approve'
  | 'configuration:deploy'
  | 'asset:upload'
  | 'asset:delete'
  | 'theme:update'
  | 'content:update'
  | 'domain:configure'
  | 'email:template:update';

export interface BrandingAuditLog extends BaseEntity {
  action: BrandingAuditAction;
  resourceType: string;
  resourceId: string;
  userId: string;
  userEmail: string;
  details: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  error?: string;
  tenantId: string;
}

// Validation and Testing Types
export interface ValidationRule {
  id: string;
  name: string;
  description: string;
  type: 'required' | 'format' | 'size' | 'accessibility' | 'security';
  validator: (value: unknown) => { isValid: boolean; message?: string };
}

export interface ValidationResult {
  isValid: boolean;
  errors: {
    field: string;
    rule: string;
    message: string;
  }[];
  warnings: {
    field: string;
    rule: string;
    message: string;
  }[];
}

export interface AccessibilityTest {
  element: string;
  test: 'contrast' | 'font-size' | 'focus-visible' | 'aria-labels';
  result: 'pass' | 'fail' | 'warning';
  score?: number;
  recommendation?: string;
}

export interface PerformanceMetrics {
  loadTime: number;
  renderTime: number;
  assetSize: number;
  cacheHitRate: number;
  cdnDeliveryTime: number;
}

// API Response Types
export interface BrandingApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  validation?: ValidationResult;
  metadata?: {
    version: string;
    timestamp: Date;
    requestId: string;
  };
}

// Search and Filter Types
export interface BrandingSearchParams {
  query?: string;
  type?: string[];
  status?: ConfigurationStatus[];
  tenantId?: string;
  createdBy?: string;
  dateRange?: {
    start: Date;
    end: Date;
  };
  sort?: {
    field: string;
    direction: 'asc' | 'desc';
  };
  pagination?: {
    page: number;
    limit: number;
  };
}

// Utility Types
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type BrandingConfigUpdate = DeepPartial<WhiteLabelConfiguration>;

export type ThemeVariables = Record<string, string | number>;

// Constants
export const SUPPORTED_ASSET_FORMATS: Record<AssetType, AssetFormat[]> = {
  'logo-primary': ['svg', 'png'],
  'logo-secondary': ['svg', 'png'],
  'favicon': ['ico', 'png'],
  'email-header': ['png', 'jpg'],
  'report-header': ['png', 'jpg', 'svg'],
  'mobile-icon': ['png'],
  'background': ['jpg', 'png', 'webp'],
  'watermark': ['png', 'svg'],
};

export const MAX_ASSET_SIZES: Record<AssetType, number> = {
  'logo-primary': 2 * 1024 * 1024, // 2MB
  'logo-secondary': 2 * 1024 * 1024, // 2MB
  'favicon': 512 * 1024, // 512KB
  'email-header': 1024 * 1024, // 1MB
  'report-header': 2 * 1024 * 1024, // 2MB
  'mobile-icon': 512 * 1024, // 512KB
  'background': 5 * 1024 * 1024, // 5MB
  'watermark': 1024 * 1024, // 1MB
};

export const DEFAULT_COLOR_PALETTE: ColorPalette = {
  primary: '#1976d2',
  primaryDark: '#115293',
  primaryLight: '#4791db',
  secondary: '#dc004e',
  secondaryDark: '#9a0036',
  secondaryLight: '#e33371',
  accent: '#ff9800',
  accentDark: '#b26a00',
  accentLight: '#ffb74d',
  success: '#4caf50',
  warning: '#ff9800',
  error: '#f44336',
  info: '#2196f3',
  background: '#ffffff',
  surface: '#f5f5f5',
  text: {
    primary: '#212121',
    secondary: '#757575',
    disabled: '#bdbdbd',
  },
  border: '#e0e0e0',
  divider: '#e0e0e0',
};

export const DEFAULT_TYPOGRAPHY_SCALE: TypographyScale = {
  h1: { fontSize: '2.5rem', fontWeight: 700, lineHeight: 1.2 },
  h2: { fontSize: '2rem', fontWeight: 600, lineHeight: 1.3 },
  h3: { fontSize: '1.75rem', fontWeight: 600, lineHeight: 1.4 },
  h4: { fontSize: '1.5rem', fontWeight: 500, lineHeight: 1.4 },
  h5: { fontSize: '1.25rem', fontWeight: 500, lineHeight: 1.5 },
  h6: { fontSize: '1rem', fontWeight: 500, lineHeight: 1.5 },
  body1: { fontSize: '1rem', fontWeight: 400, lineHeight: 1.6 },
  body2: { fontSize: '0.875rem', fontWeight: 400, lineHeight: 1.6 },
  caption: { fontSize: '0.75rem', fontWeight: 400, lineHeight: 1.4 },
  button: { fontSize: '0.875rem', fontWeight: 500, lineHeight: 1.4, textTransform: 'uppercase' },
};