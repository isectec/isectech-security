/**
 * Customer Onboarding Workflow Types for iSECTECH Protect
 * Production-grade TypeScript definitions for automated customer onboarding
 */

import { BaseEntity } from './common';
import { WhiteLabelConfiguration } from './white-labeling';
import { TrainingCourse } from './customer-success';

// Core Onboarding Types
export type OnboardingStatus = 'not-started' | 'in-progress' | 'pending-approval' | 'completed' | 'failed' | 'cancelled';

export type OnboardingStepStatus = 'pending' | 'in-progress' | 'completed' | 'failed' | 'skipped' | 'blocked';

export type CustomerType = 'enterprise' | 'mid-market' | 'small-business' | 'individual';

export type ServiceTier = 'basic' | 'professional' | 'enterprise' | 'enterprise-plus';

// Customer Profile and Configuration
export interface CustomerProfile extends BaseEntity {
  companyName: string;
  industry: string;
  companySize: '1-10' | '11-50' | '51-200' | '201-1000' | '1001-5000' | '5000+';
  customerType: CustomerType;
  serviceTier: ServiceTier;
  primaryContact: {
    firstName: string;
    lastName: string;
    email: string;
    phone?: string;
    title: string;
    department: string;
    timezone: string;
    locale: string;
    preferredLanguage: string;
  };
  technicalContact?: {
    firstName: string;
    lastName: string;
    email: string;
    phone?: string;
    title: string;
    department: string;
  };
  billingContact?: {
    firstName: string;
    lastName: string;
    email: string;
    phone?: string;
  };
  companyInfo: {
    website?: string;
    address: {
      street: string;
      city: string;
      state: string;
      zipCode: string;
      country: string;
    };
    taxId?: string;
    businessType: string;
  };
  securityRequirements: {
    complianceFrameworks: string[];
    dataResidency: string[];
    securityClearance?: string;
    industryRegulations: string[];
  };
  selectedServices: {
    coreServices: string[];
    addOnServices: string[];
    integrations: string[];
  };
  customization: {
    whiteLabelRequired: boolean;
    customDomain?: string;
    brandingRequirements?: string;
  };
  tenantId: string;
}

// Onboarding Workflow Configuration
export interface OnboardingWorkflow extends BaseEntity {
  name: string;
  description: string;
  customerType: CustomerType;
  serviceTier: ServiceTier;
  version: string;
  isActive: boolean;
  steps: OnboardingStep[];
  estimatedDuration: number; // hours
  prerequisites: string[];
  successCriteria: string[];
  rollbackStrategy?: string;
  tenantId: string;
}

export interface OnboardingStep extends BaseEntity {
  workflowId: string;
  name: string;
  description: string;
  type: OnboardingStepType;
  order: number;
  isRequired: boolean;
  dependencies: string[];
  condition?: string; // JavaScript expression for conditional logic
  configuration: Record<string, unknown>;
  estimatedDuration: number; // minutes
  retryPolicy: {
    maxRetries: number;
    retryDelay: number; // milliseconds
    backoffMultiplier: number;
  };
  timeoutPolicy: {
    timeout: number; // milliseconds
    onTimeout: 'fail' | 'skip' | 'retry';
  };
  notifications: {
    onStart?: NotificationConfig[];
    onComplete?: NotificationConfig[];
    onError?: NotificationConfig[];
  };
}

export type OnboardingStepType = 
  | 'account-provisioning'
  | 'identity-setup'
  | 'service-configuration'
  | 'permissions-setup'
  | 'compliance-validation'
  | 'white-label-setup'
  | 'training-assignment'
  | 'welcome-communication'
  | 'guided-tour'
  | 'integration-setup'
  | 'validation-check'
  | 'manual-approval'
  | 'custom-script';

// Onboarding Instance and Tracking
export interface OnboardingInstance extends BaseEntity {
  workflowId: string;
  customerProfileId: string;
  status: OnboardingStatus;
  currentStep?: string;
  startedAt?: Date;
  completedAt?: Date;
  estimatedCompletionTime?: Date;
  actualDuration?: number; // minutes
  stepInstances: OnboardingStepInstance[];
  metadata: {
    initiatedBy: string;
    initiationType: 'automatic' | 'manual' | 'scheduled';
    priority: 'low' | 'normal' | 'high' | 'urgent';
    customerSuccessManager?: string;
    technicalAccountManager?: string;
  };
  progress: {
    completedSteps: number;
    totalSteps: number;
    percentComplete: number;
  };
  notifications: OnboardingNotification[];
  errors: OnboardingError[];
  customData: Record<string, unknown>;
  tenantId: string;
}

export interface OnboardingStepInstance extends BaseEntity {
  onboardingInstanceId: string;
  stepId: string;
  status: OnboardingStepStatus;
  startedAt?: Date;
  completedAt?: Date;
  duration?: number; // minutes
  attempts: number;
  lastAttemptAt?: Date;
  nextRetryAt?: Date;
  result?: {
    success: boolean;
    data?: Record<string, unknown>;
    error?: string;
  };
  logs: {
    timestamp: Date;
    level: 'info' | 'warn' | 'error' | 'debug';
    message: string;
    data?: Record<string, unknown>;
  }[];
  approvals?: {
    approverId: string;
    approverName: string;
    approverEmail: string;
    status: 'pending' | 'approved' | 'rejected';
    comment?: string;
    timestamp: Date;
  }[];
}

// Dynamic Forms and Data Collection
export type FormFieldType = 
  | 'text'
  | 'email'
  | 'phone'
  | 'number'
  | 'date'
  | 'select'
  | 'multiselect'
  | 'checkbox'
  | 'radio'
  | 'textarea'
  | 'file'
  | 'json';

export interface FormField {
  id: string;
  name: string;
  type: FormFieldType;
  label: string;
  placeholder?: string;
  description?: string;
  required: boolean;
  validation: ValidationRule[];
  conditionalLogic?: {
    showIf: string; // JavaScript expression
    requiredIf?: string; // JavaScript expression
  };
  options?: {
    value: string;
    label: string;
    disabled?: boolean;
  }[];
  defaultValue?: unknown;
  metadata: {
    category: string;
    sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
    retention: number; // days
  };
}

export interface ValidationRule {
  type: 'required' | 'min' | 'max' | 'pattern' | 'custom';
  value?: unknown;
  message: string;
  validator?: string; // JavaScript function
}

export interface DynamicForm extends BaseEntity {
  name: string;
  description: string;
  version: string;
  customerType?: CustomerType[];
  serviceTier?: ServiceTier[];
  fields: FormField[];
  layout: {
    sections: {
      id: string;
      title: string;
      description?: string;
      fields: string[];
      collapsible: boolean;
      defaultExpanded: boolean;
    }[];
    submitButton: {
      text: string;
      position: 'left' | 'center' | 'right';
    };
  };
  styling: {
    theme: 'default' | 'minimal' | 'modern';
    primaryColor?: string;
    customCss?: string;
  };
  behavior: {
    allowSave: boolean;
    autoSave: boolean;
    showProgress: boolean;
    allowBack: boolean;
  };
  tenantId: string;
}

export interface FormSubmission extends BaseEntity {
  formId: string;
  onboardingInstanceId: string;
  submittedBy: string;
  data: Record<string, unknown>;
  validation: {
    isValid: boolean;
    errors: {
      field: string;
      message: string;
    }[];
  };
  metadata: {
    userAgent: string;
    ipAddress: string;
    submissionTime: number; // milliseconds
    deviceType: 'desktop' | 'tablet' | 'mobile';
  };
  processing: {
    status: 'pending' | 'processing' | 'completed' | 'failed';
    result?: Record<string, unknown>;
    error?: string;
  };
  tenantId: string;
}

// Communication and Notifications
export type NotificationType = 'email' | 'sms' | 'push' | 'in-app' | 'webhook';

export interface NotificationConfig {
  type: NotificationType;
  templateId: string;
  recipients: {
    type: 'user' | 'role' | 'email';
    value: string;
  }[];
  delay?: number; // minutes
  condition?: string; // JavaScript expression
  variables: Record<string, string>;
}

export interface OnboardingNotification extends BaseEntity {
  onboardingInstanceId: string;
  type: NotificationType;
  templateId: string;
  recipient: string;
  subject?: string;
  content: string;
  status: 'pending' | 'sent' | 'delivered' | 'failed' | 'bounced';
  scheduledAt: Date;
  sentAt?: Date;
  deliveredAt?: Date;
  attempts: number;
  lastAttemptAt?: Date;
  error?: string;
  metadata: {
    messageId?: string;
    provider: string;
    cost?: number;
  };
  tenantId: string;
}

// Error Handling and Logging
export interface OnboardingError extends BaseEntity {
  onboardingInstanceId: string;
  stepInstanceId?: string;
  errorType: 'validation' | 'configuration' | 'external-service' | 'timeout' | 'permission' | 'unknown';
  errorCode: string;
  message: string;
  details: Record<string, unknown>;
  stackTrace?: string;
  context: {
    userId?: string;
    sessionId?: string;
    requestId?: string;
    userAgent?: string;
    ipAddress?: string;
  };
  severity: 'low' | 'medium' | 'high' | 'critical';
  resolved: boolean;
  resolvedAt?: Date;
  resolvedBy?: string;
  resolution?: string;
  tenantId: string;
}

// Analytics and Reporting
export interface OnboardingAnalytics {
  overview: {
    totalOnboardings: number;
    completedOnboardings: number;
    failedOnboardings: number;
    averageCompletionTime: number; // hours
    completionRate: number; // percentage
  };
  byCustomerType: Record<CustomerType, {
    total: number;
    completed: number;
    averageTime: number;
    completionRate: number;
  }>;
  byServiceTier: Record<ServiceTier, {
    total: number;
    completed: number;
    averageTime: number;
    completionRate: number;
  }>;
  stepAnalytics: {
    stepId: string;
    stepName: string;
    completionRate: number;
    averageTime: number;
    errorRate: number;
    commonErrors: string[];
  }[];
  trends: {
    period: 'daily' | 'weekly' | 'monthly';
    data: {
      date: Date;
      started: number;
      completed: number;
      failed: number;
      averageTime: number;
    }[];
  };
  dropoffAnalysis: {
    stepId: string;
    stepName: string;
    dropoffCount: number;
    dropoffRate: number;
    topReasons: string[];
  }[];
  customerFeedback: {
    averageRating: number;
    totalResponses: number;
    feedback: {
      rating: number;
      comment: string;
      timestamp: Date;
    }[];
  };
}

// Integration Types
export interface ExternalIntegration {
  id: string;
  name: string;
  type: 'crm' | 'support' | 'analytics' | 'billing' | 'identity' | 'custom';
  endpoint: string;
  authentication: {
    type: 'api-key' | 'oauth' | 'basic' | 'bearer';
    config: Record<string, unknown>;
  };
  mapping: {
    fields: Record<string, string>;
    transformation?: string; // JavaScript function
  };
  webhooks?: {
    events: string[];
    url: string;
    secret: string;
  };
  retryPolicy: {
    maxRetries: number;
    backoffStrategy: 'linear' | 'exponential' | 'fixed';
    baseDelay: number;
  };
  timeout: number; // milliseconds
  isActive: boolean;
}

// Wizard and Guided Tour Types
export interface GuidedTour extends BaseEntity {
  name: string;
  description: string;
  customerType?: CustomerType[];
  serviceTier?: ServiceTier[];
  steps: TourStep[];
  triggers: {
    onOnboarding: boolean;
    onFirstLogin: boolean;
    onFeatureAccess: boolean;
    manual: boolean;
  };
  settings: {
    allowSkip: boolean;
    allowRestart: boolean;
    showProgress: boolean;
    darkOverlay: boolean;
    highlightStyle: 'box' | 'circle' | 'none';
  };
  analytics: {
    completionRate: number;
    averageDuration: number;
    dropoffSteps: string[];
  };
  tenantId: string;
}

export interface TourStep {
  id: string;
  title: string;
  description: string;
  target: {
    selector: string;
    position: 'top' | 'bottom' | 'left' | 'right' | 'center';
    offset: { x: number; y: number };
  };
  content: {
    text: string;
    media?: {
      type: 'image' | 'video' | 'gif';
      url: string;
      alt: string;
    };
    cta?: {
      text: string;
      action: 'next' | 'skip' | 'finish' | 'external-link';
      url?: string;
    };
  };
  interaction: {
    type: 'click' | 'hover' | 'focus' | 'scroll' | 'wait';
    required: boolean;
    timeout?: number;
  };
  conditions?: {
    showIf: string; // JavaScript expression
    skipIf: string; // JavaScript expression
  };
}

export interface WizardStep {
  id: string;
  title: string;
  description: string;
  component: string;
  validation: ValidationRule[];
  canSkip: boolean;
  canGoBack: boolean;
  estimatedTime: number; // minutes
  helpContent?: {
    title: string;
    content: string;
    links: {
      text: string;
      url: string;
    }[];
  };
}

export interface SetupWizard extends BaseEntity {
  name: string;
  description: string;
  customerType?: CustomerType[];
  serviceTier?: ServiceTier[];
  steps: WizardStep[];
  settings: {
    showProgress: boolean;
    allowBack: boolean;
    autoSave: boolean;
    showHelp: boolean;
    theme: 'default' | 'minimal' | 'modern';
  };
  completion: {
    redirectUrl?: string;
    showSummary: boolean;
    generateReport: boolean;
  };
  tenantId: string;
}

// State Management Types
export interface OnboardingState {
  currentInstance?: OnboardingInstance;
  activeSteps: OnboardingStepInstance[];
  completedSteps: OnboardingStepInstance[];
  pendingApprovals: OnboardingStepInstance[];
  errors: OnboardingError[];
  notifications: OnboardingNotification[];
  analytics: OnboardingAnalytics;
  isLoading: boolean;
  lastUpdated: Date;
}

// API Response Types
export interface OnboardingApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  metadata?: {
    requestId: string;
    timestamp: Date;
    version: string;
  };
}

// Search and Filter Types
export interface OnboardingSearchParams {
  status?: OnboardingStatus[];
  customerType?: CustomerType[];
  serviceTier?: ServiceTier[];
  dateRange?: {
    start: Date;
    end: Date;
  };
  assignee?: string;
  priority?: string[];
  sort?: {
    field: string;
    direction: 'asc' | 'desc';
  };
  pagination?: {
    page: number;
    limit: number;
  };
}

// Configuration Management Types
export interface OnboardingConfiguration extends BaseEntity {
  name: string;
  description: string;
  version: string;
  workflows: OnboardingWorkflow[];
  forms: DynamicForm[];
  tours: GuidedTour[];
  wizards: SetupWizard[];
  integrations: ExternalIntegration[];
  globalSettings: {
    defaultTimeout: number;
    maxRetries: number;
    notificationSettings: {
      enableEmail: boolean;
      enableSms: boolean;
      enablePush: boolean;
      enableInApp: boolean;
    };
    analytics: {
      trackingEnabled: boolean;
      retentionPeriod: number; // days
      exportEnabled: boolean;
    };
    security: {
      encryptPii: boolean;
      auditAll: boolean;
      dataResidency: string[];
    };
  };
  isActive: boolean;
  tenantId: string;
}

// Utility Types
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type OnboardingConfigUpdate = DeepPartial<OnboardingConfiguration>;

export type CustomerProfileUpdate = DeepPartial<CustomerProfile>;

export type OnboardingInstanceUpdate = DeepPartial<OnboardingInstance>;

// Constants and Defaults
export const DEFAULT_RETRY_POLICY = {
  maxRetries: 3,
  retryDelay: 30000, // 30 seconds
  backoffMultiplier: 2,
};

export const DEFAULT_TIMEOUT_POLICY = {
  timeout: 300000, // 5 minutes
  onTimeout: 'retry' as const,
};

export const ONBOARDING_EVENTS = {
  INSTANCE_STARTED: 'onboarding.instance.started',
  INSTANCE_COMPLETED: 'onboarding.instance.completed',
  INSTANCE_FAILED: 'onboarding.instance.failed',
  STEP_STARTED: 'onboarding.step.started',
  STEP_COMPLETED: 'onboarding.step.completed',
  STEP_FAILED: 'onboarding.step.failed',
  APPROVAL_REQUESTED: 'onboarding.approval.requested',
  APPROVAL_GRANTED: 'onboarding.approval.granted',
  APPROVAL_DENIED: 'onboarding.approval.denied',
  ERROR_OCCURRED: 'onboarding.error.occurred',
  NOTIFICATION_SENT: 'onboarding.notification.sent',
} as const;

export type OnboardingEvent = typeof ONBOARDING_EVENTS[keyof typeof ONBOARDING_EVENTS];