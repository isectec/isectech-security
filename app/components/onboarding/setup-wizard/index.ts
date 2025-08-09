/**
 * Setup Wizard Components Exports
 * Production-grade guided setup wizard for iSECTECH Protect onboarding
 */

export { SetupWizard, type SetupWizardProps } from './setup-wizard';
export { OrganizationProfileStep } from './steps/organization-profile-step';
export { IdentitySetupStep } from './steps/identity-setup-step';
export { IntegrationsStep } from './steps/integrations-step';
export { DataIngestionStep } from './steps/data-ingestion-step';
export { ReviewStep } from './steps/review-step';

// Re-export all step components for easy import
export * from './steps/organization-profile-step';
export * from './steps/identity-setup-step';
export * from './steps/integrations-step';
export * from './steps/data-ingestion-step';
export * from './steps/review-step';

// Type definitions for wizard data
export interface WizardData {
  organizationProfile: {
    organizationName: string;
    description: string;
    industry: string;
    organizationSize: string;
    headquarters: {
      country: string;
      region: string;
      timezone: string;
    };
    securityRequirements: {
      complianceFrameworks: string[];
      dataResidency: string[];
      securityClearance: string;
      industryRegulations: string[];
      encryptionRequirements: string[];
    };
    businessCriticality: {
      level: string;
      description: string;
      rtoRequirements: number;
      rpoRequirements: number;
    };
    customSettings: {
      customBranding: boolean;
      whiteLabeling: boolean;
      customDomain: string;
      apiAccess: boolean;
      advancedAnalytics: boolean;
    };
  };
  identitySetup: {
    authenticationMethods: {
      primary: 'local' | 'saml' | 'oidc' | 'ldap';
      enableMFA: boolean;
      mfaMethods: string[];
      sessionTimeout: number;
      passwordPolicy: {
        minLength: number;
        requireUppercase: boolean;
        requireLowercase: boolean;
        requireNumbers: boolean;
        requireSpecialChars: boolean;
        passwordHistory: number;
        maxAge: number;
      };
    };
    ssoConfiguration: {
      provider: string;
      entityId: string;
      ssoUrl: string;
      logoutUrl: string;
      certificate: string;
      nameIdFormat: string;
      attributeMapping: {
        email: string;
        firstName: string;
        lastName: string;
        groups: string;
      };
    };
    userRoles: Array<{
      id: string;
      name: string;
      description: string;
      permissions: string[];
      isDefault: boolean;
    }>;
    initialUsers: Array<{
      id: string;
      email: string;
      firstName: string;
      lastName: string;
      role: string;
      department: string;
      isAdmin: boolean;
    }>;
    accessPolicies: {
      ipWhitelisting: {
        enabled: boolean;
        allowedRanges: string[];
      };
      timeBasedAccess: {
        enabled: boolean;
        allowedHours: {
          start: string;
          end: string;
          timezone: string;
        };
        allowedDays: string[];
      };
      deviceTrust: {
        enabled: boolean;
        requireManagedDevices: boolean;
        allowBYOD: boolean;
      };
    };
  };
  integrations: {
    selectedIntegrations: string[];
    configurations: Record<string, Record<string, string>>;
    testResults: Record<string, 'success' | 'error'>;
  };
  dataIngestion: {
    dataSourceTypes: string[];
    expectedVolume: number;
    retentionPeriod: number;
    compressionEnabled: boolean;
    encryptionAtRest: boolean;
    processingRules: any[];
    alertingThreshold: number;
  };
  review: {
    configurationApproved: boolean;
    deploymentStarted: boolean;
    deploymentProgress: number;
    currentDeploymentStep: number;
    deploymentComplete: boolean;
    errors: string[];
  };
}

export interface WizardStepProps {
  data: any;
  onUpdate: (data: any) => void;
  onValidate: (isValid: boolean, errors?: string[]) => void;
  onNext: () => void;
  onBack: () => void;
  customerProfile: any;
  wizardContext: {
    currentStep: number;
    totalSteps: number;
    isLastStep: boolean;
    canGoBack: boolean;
    canGoNext: boolean;
  };
}

export default SetupWizard;