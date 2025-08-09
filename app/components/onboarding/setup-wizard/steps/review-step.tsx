/**
 * Review & Deploy Step
 * Final review of all configuration settings and deployment
 */

'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Alert,
  Stack,
  Chip,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from '@mui/material';
import {
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Refresh as DeployIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Storage as DataIcon,
  Hub as IntegrationIcon,
  Business as OrgIcon,
} from '@mui/icons-material';
import type { CustomerProfile } from '@/types';

interface ReviewStepProps {
  data: any;
  onUpdate: (data: any) => void;
  onValidate: (isValid: boolean, errors?: string[]) => void;
  onNext: () => void;
  onBack: () => void;
  customerProfile: CustomerProfile;
  wizardContext: any;
}

const deploymentSteps = [
  { id: 'infrastructure', label: 'Infrastructure Setup', duration: 30 },
  { id: 'database', label: 'Database Configuration', duration: 45 },
  { id: 'security', label: 'Security Policies', duration: 20 },
  { id: 'integrations', label: 'External Integrations', duration: 60 },
  { id: 'data-sources', label: 'Data Source Configuration', duration: 40 },
  { id: 'monitoring', label: 'Monitoring & Alerting', duration: 25 },
  { id: 'testing', label: 'System Testing', duration: 30 },
];

export function ReviewStep({
  data,
  onUpdate,
  onValidate,
  customerProfile,
  wizardContext,
}: ReviewStepProps) {
  const [reviewData, setReviewData] = useState({
    configurationApproved: false,
    deploymentStarted: false,
    deploymentProgress: 0,
    currentDeploymentStep: -1,
    deploymentComplete: false,
    errors: [],
  });

  const [errors, setErrors] = useState<string[]>([]);

  // Get all wizard data from parent context (this would come from the main wizard component)
  const allWizardData = {
    organizationProfile: data.organizationProfile || {},
    identitySetup: data.identitySetup || {},
    integrations: data.integrations || {},
    dataIngestion: data.dataIngestion || {},
  };

  useEffect(() => {
    onUpdate(reviewData);
  }, [reviewData, onUpdate]);

  const validateData = useCallback(() => {
    const newErrors: string[] = [];
    
    if (!reviewData.configurationApproved) {
      newErrors.push('Please review and approve the configuration before proceeding');
    }

    setErrors(newErrors);
    onValidate(newErrors.length === 0, newErrors);
  }, [reviewData, onValidate]);

  useEffect(() => {
    validateData();
  }, [validateData]);

  const handleApproveConfiguration = () => {
    setReviewData(prev => ({
      ...prev,
      configurationApproved: true,
    }));
  };

  const handleStartDeployment = async () => {
    setReviewData(prev => ({
      ...prev,
      deploymentStarted: true,
      deploymentProgress: 0,
      currentDeploymentStep: 0,
    }));

    // Simulate deployment process
    for (let i = 0; i < deploymentSteps.length; i++) {
      const step = deploymentSteps[i];
      
      // Update current step
      setReviewData(prev => ({
        ...prev,
        currentDeploymentStep: i,
      }));

      // Simulate deployment time
      const stepTime = step.duration * 100; // Convert to milliseconds (scaled down for demo)
      await new Promise(resolve => setTimeout(resolve, stepTime));

      // Update progress
      const progress = ((i + 1) / deploymentSteps.length) * 100;
      setReviewData(prev => ({
        ...prev,
        deploymentProgress: progress,
      }));
    }

    // Deployment complete
    setReviewData(prev => ({
      ...prev,
      deploymentComplete: true,
      currentDeploymentStep: deploymentSteps.length,
    }));
  };

  const renderConfigurationSummary = () => {
    const { organizationProfile, identitySetup, integrations, dataIngestion } = allWizardData;

    return (
      <Stack spacing={2}>
        {/* Organization Profile Summary */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <OrgIcon />
              <Typography variant="h6">Organization Profile</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2"><strong>Organization:</strong> {organizationProfile.organizationName}</Typography>
                <Typography variant="body2"><strong>Industry:</strong> {organizationProfile.industry}</Typography>
                <Typography variant="body2"><strong>Size:</strong> {organizationProfile.organizationSize}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="body2"><strong>Compliance Frameworks:</strong></Typography>
                <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                  {organizationProfile.securityRequirements?.complianceFrameworks?.map((framework: string) => (
                    <Chip key={framework} label={framework} size="small" />
                  ))}
                </Stack>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Identity Setup Summary */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon />
              <Typography variant="h6">Identity & Access Management</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2"><strong>Primary Auth:</strong> {identitySetup.authenticationMethods?.primary}</Typography>
                <Typography variant="body2"><strong>MFA Enabled:</strong> {identitySetup.authenticationMethods?.enableMFA ? 'Yes' : 'No'}</Typography>
                <Typography variant="body2"><strong>Initial Users:</strong> {identitySetup.initialUsers?.length || 0}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="body2"><strong>User Roles:</strong> {identitySetup.userRoles?.length || 0}</Typography>
                <Typography variant="body2"><strong>IP Whitelisting:</strong> {identitySetup.accessPolicies?.ipWhitelisting?.enabled ? 'Enabled' : 'Disabled'}</Typography>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Integrations Summary */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <IntegrationIcon />
              <Typography variant="h6">System Integrations</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2">
              <strong>Selected Integrations:</strong> {integrations.selectedIntegrations?.length || 0}
            </Typography>
            <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
              {integrations.selectedIntegrations?.map((integration: string) => (
                <Chip key={integration} label={integration} size="small" color="primary" />
              ))}
            </Stack>
          </AccordionDetails>
        </Accordion>

        {/* Data Ingestion Summary */}
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <DataIcon />
              <Typography variant="h6">Data Sources & Ingestion</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2"><strong>Expected Volume:</strong> {dataIngestion.expectedVolume?.toLocaleString()} events/sec</Typography>
                <Typography variant="body2"><strong>Retention Period:</strong> {dataIngestion.retentionPeriod} days</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="body2"><strong>Compression:</strong> {dataIngestion.compressionEnabled ? 'Enabled' : 'Disabled'}</Typography>
                <Typography variant="body2"><strong>Encryption at Rest:</strong> {dataIngestion.encryptionAtRest ? 'Enabled' : 'Disabled'}</Typography>
              </Grid>
            </Grid>
          </AccordionDetails>
        </Accordion>
      </Stack>
    );
  };

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 1 }}>
        <CheckIcon color="primary" />
        Review & Deploy Configuration
      </Typography>

      {!reviewData.deploymentStarted ? (
        <Grid container spacing={3}>
          {/* Configuration Review */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Configuration Summary
                </Typography>
                {renderConfigurationSummary()}
                
                <Box sx={{ mt: 3, textAlign: 'center' }}>
                  {!reviewData.configurationApproved ? (
                    <Button
                      variant="contained"
                      size="large"
                      onClick={handleApproveConfiguration}
                    >
                      Approve Configuration
                    </Button>
                  ) : (
                    <Stack spacing={2} alignItems="center">
                      <Alert severity="success">
                        Configuration approved and ready for deployment
                      </Alert>
                      <Button
                        variant="contained"
                        size="large"
                        startIcon={<DeployIcon />}
                        onClick={handleStartDeployment}
                      >
                        Start Deployment
                      </Button>
                    </Stack>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Pre-deployment Checklist */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Pre-deployment Checklist
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <CheckIcon color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Organization profile configured" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckIcon color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Identity and access management set up" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckIcon color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Integration endpoints configured" />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckIcon color="success" />
                    </ListItemIcon>
                    <ListItemText primary="Data ingestion pipeline defined" />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      ) : (
        /* Deployment Progress */
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Deployment Progress
                </Typography>
                
                <LinearProgress
                  variant="determinate"
                  value={reviewData.deploymentProgress}
                  sx={{ height: 10, borderRadius: 5, mb: 3 }}
                />
                
                <Typography variant="body1" sx={{ textAlign: 'center', mb: 3 }}>
                  {reviewData.deploymentProgress.toFixed(0)}% Complete
                </Typography>

                <Stepper activeStep={reviewData.currentDeploymentStep} orientation="vertical">
                  {deploymentSteps.map((step, index) => (
                    <Step key={step.id}>
                      <StepLabel>
                        <Typography variant="body2">{step.label}</Typography>
                      </StepLabel>
                      <StepContent>
                        <Typography variant="caption" color="text.secondary">
                          Estimated time: {step.duration} seconds
                        </Typography>
                      </StepContent>
                    </Step>
                  ))}
                </Stepper>

                {reviewData.deploymentComplete && (
                  <Alert severity="success" sx={{ mt: 3 }}>
                    <Typography variant="h6">Deployment Complete!</Typography>
                    <Typography variant="body2">
                      Your iSECTECH Protect instance has been successfully deployed and is ready for use.
                    </Typography>
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}
    </Box>
  );
}

export default ReviewStep;