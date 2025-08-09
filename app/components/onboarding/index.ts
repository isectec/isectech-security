/**
 * Onboarding Components Exports
 * Production-grade automated customer onboarding components for iSECTECH Protect
 */

// Main onboarding dashboard
export { OnboardingDashboard } from './onboarding-dashboard';

// Customer success portal integration
export { CustomerSuccessPortal } from './customer-success-portal';

// Setup wizard components
export { SetupWizard } from './setup-wizard';
export type { WizardData, WizardStepProps } from './setup-wizard';

// Re-export all setup wizard components
export * from './setup-wizard';

// Type definitions
export interface OnboardingComponentProps {
  onboardingInstance: any;
  customerProfile: any;
  className?: string;
}

// Common props for onboarding components
export interface OnboardingContextProps {
  onComplete?: (data: any) => void;
  onCancel?: () => void;
  onError?: (error: string) => void;
  onProgress?: (progress: number) => void;
}

export default {
  OnboardingDashboard,
  CustomerSuccessPortal,
  SetupWizard,
};