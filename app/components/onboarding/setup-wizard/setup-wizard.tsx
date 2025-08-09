/**
 * Guided Setup Wizard Component
 * Production-grade interactive setup wizard with contextual help and progress tracking
 */

'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Box,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Button,
  Paper,
  Typography,
  Card,
  CardContent,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Chip,
  LinearProgress,
  Alert,
  Tooltip,
  Fab,
  Zoom,
  Collapse,
  Stack,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  NavigateNext as NextIcon,
  NavigateBefore as BackIcon,
  Help as HelpIcon,
  CheckCircle as CompletedIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  PlayArrow as StartIcon,
  Pause as PauseIcon,
  Refresh as RetryIcon,
  Save as SaveIcon,
  Close as CloseIcon,
  Lightbulb as TipIcon,
  Assignment as TaskIcon,
} from '@mui/icons-material';
import { format } from 'date-fns';
import type { 
  OnboardingInstance,
  CustomerProfile,
  OnboardingStepInstance,
  WizardStep,
  SetupWizard,
} from '@/types';
import { onboardingService } from '@/lib/api/services/onboarding';
import { useStores } from '@/lib/store';

// Import wizard step components
import { OrganizationProfileStep } from './steps/organization-profile-step';
import { IdentitySetupStep } from './steps/identity-setup-step';
import { IntegrationsStep } from './steps/integrations-step';
import { DataIngestionStep } from './steps/data-ingestion-step';
import { ReviewStep } from './steps/review-step';

interface SetupWizardProps {
  onboardingInstance: OnboardingInstance;
  customerProfile: CustomerProfile;
  onComplete?: (data: any) => void;
  onCancel?: () => void;
  className?: string;
}

interface WizardData {
  organizationProfile: any;
  identitySetup: any;
  integrations: any;
  dataIngestion: any;
  review: any;
}

interface StepComponentProps {
  data: any;
  onUpdate: (data: any) => void;
  onValidate: (isValid: boolean, errors?: string[]) => void;
  onNext: () => void;
  onBack: () => void;
  customerProfile: CustomerProfile;
  wizardContext: {
    currentStep: number;
    totalSteps: number;
    isLastStep: boolean;
    canGoBack: boolean;
    canGoNext: boolean;
  };
}

const wizardSteps: WizardStep[] = [
  {
    id: 'organization-profile',
    title: 'Organization Profile',
    description: 'Configure your organization settings and security requirements',
    component: 'OrganizationProfileStep',
    validation: [],
    canSkip: false,
    canGoBack: false,
    estimatedTime: 5,
    helpContent: {
      title: 'Organization Profile Setup',
      content: 'This step configures your organization\'s basic settings, security requirements, and compliance frameworks. All fields are required for proper system initialization.',
      links: [
        { text: 'Security Framework Guide', url: '/docs/security-frameworks' },
        { text: 'Compliance Requirements', url: '/docs/compliance' },
      ],
    },
  },
  {
    id: 'identity-setup',
    title: 'Identity & Access Management',
    description: 'Set up user authentication, roles, and permissions',
    component: 'IdentitySetupStep',
    validation: [],
    canSkip: false,
    canGoBack: true,
    estimatedTime: 8,
    helpContent: {
      title: 'Identity Management Configuration',
      content: 'Configure authentication methods, user roles, and access permissions. This step is critical for security and user management.',
      links: [
        { text: 'SSO Configuration Guide', url: '/docs/sso-setup' },
        { text: 'Role-Based Access Control', url: '/docs/rbac' },
        { text: 'Multi-Factor Authentication', url: '/docs/mfa' },
      ],
    },
  },
  {
    id: 'integrations',
    title: 'System Integrations',
    description: 'Connect with your existing security tools and systems',
    component: 'IntegrationsStep',
    validation: [],
    canSkip: true,
    canGoBack: true,
    estimatedTime: 12,
    helpContent: {
      title: 'Integration Setup',
      content: 'Connect iSECTECH Protect with your existing security infrastructure including SIEM, firewalls, and monitoring tools.',
      links: [
        { text: 'Supported Integrations', url: '/docs/integrations' },
        { text: 'API Configuration', url: '/docs/api-setup' },
        { text: 'Troubleshooting Connections', url: '/docs/integration-troubleshooting' },
      ],
    },
  },
  {
    id: 'data-ingestion',
    title: 'Data Sources & Ingestion',
    description: 'Configure data sources and ingestion pipelines',
    component: 'DataIngestionStep',
    validation: [],
    canSkip: false,
    canGoBack: true,
    estimatedTime: 10,
    helpContent: {
      title: 'Data Ingestion Configuration',
      content: 'Set up data sources, configure ingestion pipelines, and establish data processing rules for optimal security monitoring.',
      links: [
        { text: 'Data Source Configuration', url: '/docs/data-sources' },
        { text: 'Log Format Requirements', url: '/docs/log-formats' },
        { text: 'Performance Optimization', url: '/docs/ingestion-optimization' },
      ],
    },
  },
  {
    id: 'review',
    title: 'Review & Deploy',
    description: 'Review configuration and deploy your security platform',
    component: 'ReviewStep',
    validation: [],
    canSkip: false,
    canGoBack: true,
    estimatedTime: 5,
    helpContent: {
      title: 'Final Review & Deployment',
      content: 'Review all configurations, test connections, and deploy your iSECTECH Protect instance to production.',
      links: [
        { text: 'Pre-deployment Checklist', url: '/docs/deployment-checklist' },
        { text: 'Post-deployment Testing', url: '/docs/testing-guide' },
        { text: 'Go-Live Support', url: '/docs/go-live-support' },
      ],
    },
  },
];

const stepComponents: Record<string, React.ComponentType<StepComponentProps>> = {
  'OrganizationProfileStep': OrganizationProfileStep,
  'IdentitySetupStep': IdentitySetupStep,
  'IntegrationsStep': IntegrationsStep,
  'DataIngestionStep': DataIngestionStep,
  'ReviewStep': ReviewStep,
};

export function SetupWizard({
  onboardingInstance,
  customerProfile,
  onComplete,
  onCancel,
  className,
}: SetupWizardProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { app } = useStores();

  // State
  const [currentStep, setCurrentStep] = useState(0);
  const [wizardData, setWizardData] = useState<WizardData>({
    organizationProfile: {},
    identitySetup: {},
    integrations: {},
    dataIngestion: {},
    review: {},
  });
  const [stepValidation, setStepValidation] = useState<Record<number, { isValid: boolean; errors: string[] }>>({});
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [showTips, setShowTips] = useState(true);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());
  const [estimatedTimeRemaining, setEstimatedTimeRemaining] = useState(0);
  const [startTime] = useState(new Date());

  // Load existing wizard data if available
  useEffect(() => {
    const loadWizardData = async () => {
      try {
        setLoading(true);
        // Check if there's existing wizard data in onboarding instance
        if (onboardingInstance.customData?.wizardData) {
          setWizardData(onboardingInstance.customData.wizardData);
          setCompletedSteps(new Set(onboardingInstance.customData.completedSteps || []));
          setCurrentStep(onboardingInstance.customData.currentWizardStep || 0);
        }
      } catch (error) {
        console.error('Error loading wizard data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadWizardData();
  }, [onboardingInstance.id]);

  // Calculate estimated time remaining
  useEffect(() => {
    const remainingSteps = wizardSteps.slice(currentStep + 1);
    const timeRemaining = remainingSteps.reduce((total, step) => total + step.estimatedTime, 0);
    setEstimatedTimeRemaining(timeRemaining);
  }, [currentStep]);

  // Auto-save wizard progress
  const saveProgress = useCallback(async () => {
    if (saving) return;
    
    try {
      setSaving(true);
      await onboardingService.updateOnboardingStep(onboardingInstance.id, {
        stepId: 'setup-wizard',
        outputs: {
          wizardData,
          currentWizardStep: currentStep,
          completedSteps: Array.from(completedSteps),
          lastSavedAt: new Date(),
        },
      });
    } catch (error) {
      console.error('Error saving wizard progress:', error);
    } finally {
      setSaving(false);
    }
  }, [onboardingInstance.id, wizardData, currentStep, completedSteps, saving]);

  // Auto-save every 30 seconds
  useEffect(() => {
    const interval = setInterval(saveProgress, 30000);
    return () => clearInterval(interval);
  }, [saveProgress]);

  // Handlers
  const handleStepDataUpdate = useCallback((stepIndex: number, data: any) => {
    setWizardData(prev => ({
      ...prev,
      [wizardSteps[stepIndex].id.replace('-', '')]: data,
    }));
    
    // Auto-save after data updates
    setTimeout(saveProgress, 1000);
  }, [saveProgress]);

  const handleStepValidation = useCallback((stepIndex: number, isValid: boolean, errors: string[] = []) => {
    setStepValidation(prev => ({
      ...prev,
      [stepIndex]: { isValid, errors },
    }));
  }, []);

  const handleNext = useCallback(async () => {
    if (loading) return;

    const currentStepData = wizardSteps[currentStep];
    const validation = stepValidation[currentStep];

    if (!validation?.isValid && !currentStepData.canSkip) {
      app.showError('Please complete all required fields before continuing');
      return;
    }

    // Mark step as completed
    setCompletedSteps(prev => new Set([...prev, currentStep]));

    // Track step completion analytics
    try {
      await onboardingService.trackOnboardingEvent('onboarding.step_completed', {
        onboardingInstanceId: onboardingInstance.id,
        stepId: currentStepData.id,
        stepIndex: currentStep,
        timeSpent: (Date.now() - startTime.getTime()) / 1000,
        validationPassed: validation?.isValid || false,
        skipped: !validation?.isValid && currentStepData.canSkip,
      });
    } catch (error) {
      console.error('Error tracking step completion:', error);
    }

    if (currentStep < wizardSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      // Wizard complete
      await handleComplete();
    }
  }, [currentStep, stepValidation, loading, onboardingInstance.id, startTime, app]);

  const handleBack = useCallback(() => {
    if (currentStep > 0 && wizardSteps[currentStep].canGoBack) {
      setCurrentStep(currentStep - 1);
    }
  }, [currentStep]);

  const handleStepClick = useCallback((stepIndex: number) => {
    // Allow navigation to completed steps or next step
    if (completedSteps.has(stepIndex) || stepIndex === currentStep + 1) {
      setCurrentStep(stepIndex);
    }
  }, [completedSteps, currentStep]);

  const handleComplete = useCallback(async () => {
    try {
      setLoading(true);
      
      // Final validation
      const allStepsValid = wizardSteps.every((step, index) => 
        stepValidation[index]?.isValid || step.canSkip
      );

      if (!allStepsValid) {
        app.showError('Please complete all required steps before finishing');
        return;
      }

      // Save final wizard data
      await saveProgress();

      // Track wizard completion
      await onboardingService.trackOnboardingEvent('onboarding.wizard_completed', {
        onboardingInstanceId: onboardingInstance.id,
        totalTimeSpent: (Date.now() - startTime.getTime()) / 1000,
        completedSteps: Array.from(completedSteps),
        skippedSteps: wizardSteps
          .map((step, index) => ({ step, index }))
          .filter(({ index }) => !completedSteps.has(index) && wizardSteps[index].canSkip)
          .map(({ step }) => step.id),
        wizardData,
      });

      // Complete the setup wizard step in onboarding
      await onboardingService.updateOnboardingStep(onboardingInstance.id, {
        stepId: 'guided-tour',
        status: 'completed',
        outputs: {
          wizardCompleted: true,
          finalData: wizardData,
          completionTime: new Date(),
        },
      });

      app.showSuccess('Setup wizard completed successfully!');
      onComplete?.(wizardData);
    } catch (error) {
      console.error('Error completing wizard:', error);
      app.showError('Failed to complete setup wizard');
    } finally {
      setLoading(false);
    }
  }, [
    stepValidation,
    wizardSteps,
    saveProgress,
    onboardingInstance.id,
    startTime,
    completedSteps,
    wizardData,
    app,
    onComplete,
  ]);

  const handleCancel = useCallback(() => {
    if (Object.keys(wizardData).some(key => Object.keys(wizardData[key as keyof WizardData]).length > 0)) {
      if (window.confirm('Are you sure you want to cancel? Your progress will be saved.')) {
        saveProgress().finally(() => onCancel?.());
      }
    } else {
      onCancel?.();
    }
  }, [wizardData, saveProgress, onCancel]);

  // Current step component and context
  const currentStepData = wizardSteps[currentStep];
  const CurrentStepComponent = stepComponents[currentStepData.component];
  
  const wizardContext = useMemo(() => ({
    currentStep,
    totalSteps: wizardSteps.length,
    isLastStep: currentStep === wizardSteps.length - 1,
    canGoBack: currentStep > 0 && currentStepData.canGoBack,
    canGoNext: stepValidation[currentStep]?.isValid || currentStepData.canSkip,
  }), [currentStep, currentStepData, stepValidation]);

  const progressPercentage = ((currentStep + 1) / wizardSteps.length) * 100;

  if (loading && !wizardData) {
    return (
      <Box className={className} sx={{ p: 3, textAlign: 'center' }}>
        <LinearProgress sx={{ mb: 2 }} />
        <Typography variant="body1">Loading setup wizard...</Typography>
      </Box>
    );
  }

  return (
    <Box className={className} sx={{ p: { xs: 2, md: 3 } }}>
      {/* Header */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 600, mb: 1 }}>
                iSECTECH Protect Setup Wizard
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Step {currentStep + 1} of {wizardSteps.length}: {currentStepData.title}
              </Typography>
            </Box>
            
            <Stack direction="row" spacing={2} alignItems="center">
              {estimatedTimeRemaining > 0 && (
                <Chip
                  icon={<TaskIcon />}
                  label={`~${estimatedTimeRemaining} min remaining`}
                  variant="outlined"
                  size="small"
                />
              )}
              {saving && (
                <Chip
                  icon={<SaveIcon />}
                  label="Saving..."
                  color="info"
                  variant="outlined"
                  size="small"
                />
              )}
              <Tooltip title="Get help">
                <IconButton onClick={() => setHelpOpen(true)}>
                  <HelpIcon />
                </IconButton>
              </Tooltip>
            </Stack>
          </Box>

          <LinearProgress
            variant="determinate"
            value={progressPercentage}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: theme.palette.grey[200],
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
              },
            }}
          />
        </CardContent>
      </Card>

      {/* Tips Banner */}
      <Collapse in={showTips}>
        <Alert
          severity="info"
          sx={{ mb: 3 }}
          action={
            <IconButton size="small" onClick={() => setShowTips(false)}>
              <CloseIcon />
            </IconButton>
          }
        >
          <Typography variant="subtitle2">
            💡 Tip: You can save your progress at any time and return later
          </Typography>
          <Typography variant="body2">
            All data is automatically saved every 30 seconds. Use the help button for step-specific guidance.
          </Typography>
        </Alert>
      </Collapse>

      <Box sx={{ display: 'flex', gap: 3 }}>
        {/* Stepper (Desktop) */}
        {!isMobile && (
          <Paper sx={{ width: 300, p: 2, height: 'fit-content' }}>
            <Stepper activeStep={currentStep} orientation="vertical">
              {wizardSteps.map((step, index) => {
                const isCompleted = completedSteps.has(index);
                const isActive = index === currentStep;
                const hasError = stepValidation[index]?.errors.length > 0;
                
                return (
                  <Step 
                    key={step.id}
                    completed={isCompleted}
                    sx={{ cursor: 'pointer' }}
                    onClick={() => handleStepClick(index)}
                  >
                    <StepLabel
                      error={hasError}
                      StepIconProps={{
                        sx: {
                          color: isCompleted ? 'success.main' :
                                 hasError ? 'error.main' :
                                 isActive ? 'primary.main' : 'grey.400',
                        },
                      }}
                    >
                      <Box>
                        <Typography 
                          variant="body2" 
                          fontWeight={isActive ? 600 : 400}
                        >
                          {step.title}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          ~{step.estimatedTime} minutes
                        </Typography>
                      </Box>
                    </StepLabel>
                    <StepContent>
                      <Typography variant="body2" color="text.secondary">
                        {step.description}
                      </Typography>
                    </StepContent>
                  </Step>
                );
              })}
            </Stepper>
          </Paper>
        )}

        {/* Main Content */}
        <Box sx={{ flexGrow: 1 }}>
          <Card>
            <CardContent sx={{ p: 4 }}>
              {/* Mobile Stepper */}
              {isMobile && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="h6" sx={{ mb: 2 }}>
                    {currentStepData.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {currentStepData.description}
                  </Typography>
                </Box>
              )}

              {/* Current Step Component */}
              {CurrentStepComponent && (
                <CurrentStepComponent
                  data={wizardData[currentStepData.id.replace('-', '') as keyof WizardData]}
                  onUpdate={(data) => handleStepDataUpdate(currentStep, data)}
                  onValidate={(isValid, errors) => handleStepValidation(currentStep, isValid, errors)}
                  onNext={handleNext}
                  onBack={handleBack}
                  customerProfile={customerProfile}
                  wizardContext={wizardContext}
                />
              )}

              {/* Validation Errors */}
              {stepValidation[currentStep]?.errors.length > 0 && (
                <Alert severity="error" sx={{ mt: 3 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>
                    Please fix the following issues:
                  </Typography>
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {stepValidation[currentStep].errors.map((error, index) => (
                      <li key={index}>
                        <Typography variant="body2">{error}</Typography>
                      </li>
                    ))}
                  </ul>
                </Alert>
              )}

              {/* Navigation Buttons */}
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
                <Button
                  startIcon={<BackIcon />}
                  onClick={handleBack}
                  disabled={!wizardContext.canGoBack || loading}
                >
                  Back
                </Button>

                <Stack direction="row" spacing={2}>
                  {currentStepData.canSkip && !stepValidation[currentStep]?.isValid && (
                    <Button
                      variant="outlined"
                      onClick={handleNext}
                      disabled={loading}
                    >
                      Skip Step
                    </Button>
                  )}
                  
                  <Button
                    variant="contained"
                    endIcon={wizardContext.isLastStep ? <CompletedIcon /> : <NextIcon />}
                    onClick={handleNext}
                    disabled={(!wizardContext.canGoNext && !currentStepData.canSkip) || loading}
                  >
                    {wizardContext.isLastStep ? 'Complete Setup' : 'Next'}
                  </Button>
                </Stack>
              </Box>
            </CardContent>
          </Card>
        </Box>
      </Box>

      {/* Floating Help Button */}
      <Zoom in={true}>
        <Fab
          color="primary"
          sx={{
            position: 'fixed',
            bottom: 24,
            right: 24,
            zIndex: 1000,
          }}
          onClick={() => setHelpOpen(true)}
        >
          <HelpIcon />
        </Fab>
      </Zoom>

      {/* Help Dialog */}
      <Dialog open={helpOpen} onClose={() => setHelpOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <TipIcon />
            <Typography variant="h6">
              {currentStepData.helpContent?.title || `Help: ${currentStepData.title}`}
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" sx={{ mb: 3 }}>
            {currentStepData.helpContent?.content || currentStepData.description}
          </Typography>
          
          {currentStepData.helpContent?.links && (
            <Box>
              <Typography variant="subtitle2" sx={{ mb: 2 }}>
                Helpful Resources:
              </Typography>
              <Stack spacing={1}>
                {currentStepData.helpContent.links.map((link, index) => (
                  <Button
                    key={index}
                    variant="outlined"
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{ justifyContent: 'flex-start' }}
                  >
                    {link.text}
                  </Button>
                ))}
              </Stack>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHelpOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default SetupWizard;