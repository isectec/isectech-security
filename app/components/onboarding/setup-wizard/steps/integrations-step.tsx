/**
 * Integrations Setup Step
 * Configures connections with existing security tools and systems
 */

'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Checkbox,
  Card,
  CardContent,
  Typography,
  Alert,
  Stack,
  Chip,
  Switch,
  Button,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  Hub as IntegrationIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  CheckCircle as ConnectedIcon,
  Error as ErrorIcon,
  Settings as ConfigIcon,
} from '@mui/icons-material';
import type { CustomerProfile } from '@/types';

interface IntegrationsStepProps {
  data: any;
  onUpdate: (data: any) => void;
  onValidate: (isValid: boolean, errors?: string[]) => void;
  onNext: () => void;
  onBack: () => void;
  customerProfile: CustomerProfile;
  wizardContext: any;
}

const availableIntegrations = [
  {
    id: 'splunk',
    name: 'Splunk',
    category: 'SIEM',
    description: 'Connect to Splunk for log ingestion and correlation',
    required: false,
    fields: ['host', 'port', 'username', 'password', 'index'],
  },
  {
    id: 'sentinel',
    name: 'Microsoft Sentinel',
    category: 'SIEM',
    description: 'Azure Sentinel integration for cloud SIEM',
    required: false,
    fields: ['workspaceId', 'tenantId', 'clientId', 'clientSecret'],
  },
  {
    id: 'aws-cloudtrail',
    name: 'AWS CloudTrail',
    category: 'Cloud',
    description: 'Ingest AWS audit logs and API calls',
    required: false,
    fields: ['accessKey', 'secretKey', 'region', 'bucketName'],
  },
  {
    id: 'office365',
    name: 'Microsoft 365',
    category: 'Productivity',
    description: 'Monitor Office 365 security events',
    required: false,
    fields: ['tenantId', 'clientId', 'clientSecret'],
  },
  {
    id: 'crowdstrike',
    name: 'CrowdStrike',
    category: 'EDR',
    description: 'Endpoint detection and response integration',
    required: false,
    fields: ['clientId', 'clientSecret', 'baseUrl'],
  },
];

export function IntegrationsStep({
  data,
  onUpdate,
  onValidate,
  customerProfile,
}: IntegrationsStepProps) {
  const [integrationsData, setIntegrationsData] = useState({
    selectedIntegrations: data.selectedIntegrations || [],
    configurations: data.configurations || {},
    testResults: data.testResults || {},
  });

  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    onUpdate(integrationsData);
  }, [integrationsData, onUpdate]);

  const validateData = useCallback(() => {
    const newErrors: string[] = [];
    // Integrations are optional, so no validation errors
    setErrors(newErrors);
    onValidate(newErrors.length === 0, newErrors);
  }, [onValidate]);

  useEffect(() => {
    validateData();
  }, [validateData]);

  const handleIntegrationToggle = (integrationId: string) => {
    const isSelected = integrationsData.selectedIntegrations.includes(integrationId);
    const newSelected = isSelected
      ? integrationsData.selectedIntegrations.filter(id => id !== integrationId)
      : [...integrationsData.selectedIntegrations, integrationId];

    setIntegrationsData(prev => ({
      ...prev,
      selectedIntegrations: newSelected,
    }));
  };

  const handleConfigurationChange = (integrationId: string, field: string, value: string) => {
    setIntegrationsData(prev => ({
      ...prev,
      configurations: {
        ...prev.configurations,
        [integrationId]: {
          ...prev.configurations[integrationId],
          [field]: value,
        },
      },
    }));
  };

  const handleTestConnection = (integrationId: string) => {
    // Simulate connection test
    setTimeout(() => {
      setIntegrationsData(prev => ({
        ...prev,
        testResults: {
          ...prev.testResults,
          [integrationId]: Math.random() > 0.3 ? 'success' : 'error',
        },
      }));
    }, 1000);
  };

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 1 }}>
        <IntegrationIcon color="primary" />
        System Integrations Setup
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          <strong>Optional Step:</strong> Connect your existing security tools to centralize monitoring and correlation. 
          You can skip this step and configure integrations later.
        </Typography>
      </Alert>

      <Grid container spacing={3}>
        {availableIntegrations.map((integration) => {
          const isSelected = integrationsData.selectedIntegrations.includes(integration.id);
          const config = integrationsData.configurations[integration.id] || {};
          const testResult = integrationsData.testResults[integration.id];

          return (
            <Grid item xs={12} key={integration.id}>
              <Card variant="outlined">
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <Switch
                        checked={isSelected}
                        onChange={() => handleIntegrationToggle(integration.id)}
                      />
                      <Box>
                        <Typography variant="h6">{integration.name}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          {integration.description}
                        </Typography>
                        <Chip label={integration.category} size="small" sx={{ mt: 0.5 }} />
                      </Box>
                    </Box>
                    {testResult && (
                      <Chip
                        icon={testResult === 'success' ? <ConnectedIcon /> : <ErrorIcon />}
                        label={testResult === 'success' ? 'Connected' : 'Failed'}
                        color={testResult === 'success' ? 'success' : 'error'}
                        variant="outlined"
                      />
                    )}
                  </Box>

                  {isSelected && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="body2">Configuration Settings</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Grid container spacing={2}>
                          {integration.fields.map((field) => (
                            <Grid item xs={12} md={6} key={field}>
                              <TextField
                                fullWidth
                                label={field.charAt(0).toUpperCase() + field.slice(1)}
                                value={config[field] || ''}
                                onChange={(e) => handleConfigurationChange(integration.id, field, e.target.value)}
                                type={field.includes('password') || field.includes('secret') ? 'password' : 'text'}
                              />
                            </Grid>
                          ))}
                          <Grid item xs={12}>
                            <Button
                              variant="outlined"
                              onClick={() => handleTestConnection(integration.id)}
                              disabled={!integration.fields.every(field => config[field])}
                            >
                              Test Connection
                            </Button>
                          </Grid>
                        </Grid>
                      </AccordionDetails>
                    </Accordion>
                  )}
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>
    </Box>
  );
}

export default IntegrationsStep;