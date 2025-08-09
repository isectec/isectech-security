/**
 * Data Ingestion Setup Step
 * Configures data sources and ingestion pipelines
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
  Slider,
} from '@mui/material';
import {
  Storage as DataIcon,
  Speed as PerformanceIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import type { CustomerProfile } from '@/types';

interface DataIngestionStepProps {
  data: any;
  onUpdate: (data: any) => void;
  onValidate: (isValid: boolean, errors?: string[]) => void;
  onNext: () => void;
  onBack: () => void;
  customerProfile: CustomerProfile;
  wizardContext: any;
}

const dataSourceTypes = [
  { value: 'syslog', label: 'Syslog', description: 'Traditional syslog messages' },
  { value: 'json', label: 'JSON', description: 'Structured JSON logs' },
  { value: 'cef', label: 'CEF', description: 'Common Event Format' },
  { value: 'windows', label: 'Windows Events', description: 'Windows Event Log' },
  { value: 'api', label: 'REST API', description: 'RESTful API endpoints' },
];

export function DataIngestionStep({
  data,
  onUpdate,
  onValidate,
  customerProfile,
}: DataIngestionStepProps) {
  const [dataIngestionData, setDataIngestionData] = useState({
    dataSourceTypes: data.dataSourceTypes || ['syslog', 'json'],
    expectedVolume: data.expectedVolume || 1000, // events per second
    retentionPeriod: data.retentionPeriod || 90, // days
    compressionEnabled: data.compressionEnabled ?? true,
    encryptionAtRest: data.encryptionAtRest ?? true,
    processingRules: data.processingRules || [],
    alertingThreshold: data.alertingThreshold || 80, // percentage
  });

  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    onUpdate(dataIngestionData);
  }, [dataIngestionData, onUpdate]);

  const validateData = useCallback(() => {
    const newErrors: string[] = [];

    if (dataIngestionData.dataSourceTypes.length === 0) {
      newErrors.push('At least one data source type must be selected');
    }

    if (dataIngestionData.expectedVolume <= 0) {
      newErrors.push('Expected volume must be greater than 0');
    }

    if (dataIngestionData.retentionPeriod <= 0) {
      newErrors.push('Retention period must be greater than 0');
    }

    setErrors(newErrors);
    onValidate(newErrors.length === 0, newErrors);
  }, [dataIngestionData, onValidate]);

  useEffect(() => {
    validateData();
  }, [validateData]);

  const handleChange = (field: string, value: any) => {
    setDataIngestionData(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 1 }}>
        <DataIcon color="primary" />
        Data Sources & Ingestion Configuration
      </Typography>

      <Grid container spacing={3}>
        {/* Data Source Types */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
                Data Source Types
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Select the types of data sources you'll be ingesting:
              </Typography>
              
              <Grid container spacing={2}>
                {dataSourceTypes.map((type) => (
                  <Grid item xs={12} md={6} key={type.value}>
                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={dataIngestionData.dataSourceTypes.includes(type.value)}
                          onChange={(e) => {
                            const current = dataIngestionData.dataSourceTypes;
                            if (e.target.checked) {
                              handleChange('dataSourceTypes', [...current, type.value]);
                            } else {
                              handleChange('dataSourceTypes', current.filter(t => t !== type.value));
                            }
                          }}
                        />
                      }
                      label={
                        <Box>
                          <Typography variant="body2">{type.label}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {type.description}
                          </Typography>
                        </Box>
                      }
                    />
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Performance Configuration */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <PerformanceIcon />
                Performance & Capacity
              </Typography>
              
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography gutterBottom>Expected Volume (events/second)</Typography>
                  <Slider
                    value={dataIngestionData.expectedVolume}
                    onChange={(_, value) => handleChange('expectedVolume', value)}
                    min={1}
                    max={10000}
                    step={100}
                    marks={[
                      { value: 1, label: '1' },
                      { value: 1000, label: '1K' },
                      { value: 5000, label: '5K' },
                      { value: 10000, label: '10K' },
                    ]}
                    valueLabelDisplay="on"
                  />
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Typography gutterBottom>Data Retention (days)</Typography>
                  <Slider
                    value={dataIngestionData.retentionPeriod}
                    onChange={(_, value) => handleChange('retentionPeriod', value)}
                    min={1}
                    max={365}
                    step={1}
                    marks={[
                      { value: 30, label: '30d' },
                      { value: 90, label: '90d' },
                      { value: 180, label: '180d' },
                      { value: 365, label: '1y' },
                    ]}
                    valueLabelDisplay="on"
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <Typography gutterBottom>Alerting Threshold (%)</Typography>
                  <Slider
                    value={dataIngestionData.alertingThreshold}
                    onChange={(_, value) => handleChange('alertingThreshold', value)}
                    min={1}
                    max={100}
                    step={5}
                    marks={[
                      { value: 50, label: '50%' },
                      { value: 80, label: '80%' },
                      { value: 95, label: '95%' },
                    ]}
                    valueLabelDisplay="on"
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Security Configuration */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon />
                Security & Storage
              </Typography>
              
              <Stack spacing={2}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={dataIngestionData.compressionEnabled}
                      onChange={(e) => handleChange('compressionEnabled', e.target.checked)}
                    />
                  }
                  label="Enable data compression (recommended for large volumes)"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={dataIngestionData.encryptionAtRest}
                      onChange={(e) => handleChange('encryptionAtRest', e.target.checked)}
                    />
                  }
                  label="Enable encryption at rest (AES-256)"
                />
              </Stack>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Alert severity="info" sx={{ mt: 3 }}>
        <Typography variant="body2">
          <strong>Note:</strong> These settings will be used to optimize your data ingestion pipeline. 
          You can adjust performance settings later based on actual usage patterns.
        </Typography>
      </Alert>
    </Box>
  );
}

export default DataIngestionStep;