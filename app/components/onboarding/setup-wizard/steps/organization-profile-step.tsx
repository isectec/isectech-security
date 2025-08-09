/**
 * Organization Profile Setup Step
 * Configures organization settings and security requirements
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
  FormGroup,
  FormLabel,
  Card,
  CardContent,
  Typography,
  Alert,
  Stack,
  Chip,
  Autocomplete,
  Switch,
} from '@mui/material';
import {
  Business as BusinessIcon,
  Security as SecurityIcon,
  Gavel as ComplianceIcon,
  Language as RegionIcon,
} from '@mui/icons-material';
import type { CustomerProfile } from '@/types';

interface OrganizationProfileStepProps {
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

interface OrganizationData {
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
    rtoRequirements: number; // Recovery Time Objective in hours
    rpoRequirements: number; // Recovery Point Objective in hours
  };
  customSettings: {
    customBranding: boolean;
    whiteLabeling: boolean;
    customDomain: string;
    apiAccess: boolean;
    advancedAnalytics: boolean;
  };
}

const industries = [
  'Financial Services',
  'Healthcare',
  'Government',
  'Technology',
  'Manufacturing',
  'Retail',
  'Energy & Utilities',
  'Education',
  'Transportation',
  'Telecommunications',
  'Media & Entertainment',
  'Real Estate',
  'Legal Services',
  'Consulting',
  'Other',
];

const organizationSizes = [
  '1-10 employees',
  '11-50 employees',
  '51-200 employees',
  '201-1000 employees',
  '1001-5000 employees',
  '5000+ employees',
];

const complianceFrameworks = [
  'SOC 2 Type II',
  'ISO 27001',
  'NIST Cybersecurity Framework',
  'PCI DSS',
  'HIPAA',
  'GDPR',
  'CCPA',
  'FedRAMP',
  'SOX',
  'FISMA',
  'CIS Controls',
  'COBIT',
];

const securityClearanceLevels = [
  'None Required',
  'Public Trust',
  'Confidential',
  'Secret',
  'Top Secret',
  'TS/SCI',
];

const dataResidencyOptions = [
  'United States',
  'European Union',
  'United Kingdom',
  'Canada',
  'Australia',
  'Japan',
  'Singapore',
  'Other/Specify',
];

const encryptionRequirements = [
  'AES-256 at rest',
  'AES-256 in transit',
  'FIPS 140-2 Level 3',
  'Hardware Security Modules (HSM)',
  'Quantum-resistant encryption',
  'End-to-end encryption',
];

const businessCriticalityLevels = [
  { value: 'low', label: 'Low', description: 'Non-critical systems, can tolerate extended downtime' },
  { value: 'medium', label: 'Medium', description: 'Important systems, minimal business impact during downtime' },
  { value: 'high', label: 'High', description: 'Business-critical systems, significant impact during downtime' },
  { value: 'critical', label: 'Critical', description: 'Mission-critical systems, zero tolerance for downtime' },
];

const timezones = [
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Asia/Tokyo',
  'Asia/Singapore',
  'Australia/Sydney',
];

export function OrganizationProfileStep({
  data,
  onUpdate,
  onValidate,
  customerProfile,
}: OrganizationProfileStepProps) {
  const [organizationData, setOrganizationData] = useState<OrganizationData>({
    organizationName: data.organizationName || customerProfile.companyName || '',
    description: data.description || '',
    industry: data.industry || customerProfile.industry || '',
    organizationSize: data.organizationSize || customerProfile.companySize || '',
    headquarters: {
      country: data.headquarters?.country || customerProfile.companyInfo?.address?.country || '',
      region: data.headquarters?.region || customerProfile.companyInfo?.address?.state || '',
      timezone: data.headquarters?.timezone || customerProfile.primaryContact?.timezone || '',
    },
    securityRequirements: {
      complianceFrameworks: data.securityRequirements?.complianceFrameworks || 
                           customerProfile.securityRequirements?.complianceFrameworks || [],
      dataResidency: data.securityRequirements?.dataResidency || 
                     customerProfile.securityRequirements?.dataResidency || [],
      securityClearance: data.securityRequirements?.securityClearance || 
                        customerProfile.securityRequirements?.securityClearance || 'None Required',
      industryRegulations: data.securityRequirements?.industryRegulations || 
                          customerProfile.securityRequirements?.industryRegulations || [],
      encryptionRequirements: data.securityRequirements?.encryptionRequirements || [],
    },
    businessCriticality: {
      level: data.businessCriticality?.level || 'medium',
      description: data.businessCriticality?.description || '',
      rtoRequirements: data.businessCriticality?.rtoRequirements || 4,
      rpoRequirements: data.businessCriticality?.rpoRequirements || 1,
    },
    customSettings: {
      customBranding: data.customSettings?.customBranding || customerProfile.customization?.whiteLabelRequired || false,
      whiteLabeling: data.customSettings?.whiteLabeling || customerProfile.customization?.whiteLabelRequired || false,
      customDomain: data.customSettings?.customDomain || customerProfile.customization?.customDomain || '',
      apiAccess: data.customSettings?.apiAccess || customerProfile.serviceTier === 'enterprise' || customerProfile.serviceTier === 'enterprise-plus',
      advancedAnalytics: data.customSettings?.advancedAnalytics || customerProfile.serviceTier === 'enterprise-plus',
    },
  });

  const [errors, setErrors] = useState<string[]>([]);

  // Update parent component when data changes
  useEffect(() => {
    onUpdate(organizationData);
  }, [organizationData, onUpdate]);

  // Validation
  const validateData = useCallback(() => {
    const newErrors: string[] = [];

    if (!organizationData.organizationName.trim()) {
      newErrors.push('Organization name is required');
    }

    if (!organizationData.industry) {
      newErrors.push('Industry selection is required');
    }

    if (!organizationData.organizationSize) {
      newErrors.push('Organization size is required');
    }

    if (!organizationData.headquarters.country) {
      newErrors.push('Headquarters country is required');
    }

    if (!organizationData.headquarters.timezone) {
      newErrors.push('Timezone is required');
    }

    if (organizationData.securityRequirements.complianceFrameworks.length === 0) {
      newErrors.push('At least one compliance framework must be selected');
    }

    if (organizationData.securityRequirements.dataResidency.length === 0) {
      newErrors.push('Data residency requirements must be specified');
    }

    if (!organizationData.businessCriticality.description.trim()) {
      newErrors.push('Business criticality description is required');
    }

    setErrors(newErrors);
    onValidate(newErrors.length === 0, newErrors);
  }, [organizationData, onValidate]);

  useEffect(() => {
    validateData();
  }, [validateData]);

  const handleChange = (field: string, value: any) => {
    setOrganizationData(prev => {
      const keys = field.split('.');
      const newData = { ...prev };
      let current: any = newData;
      
      for (let i = 0; i < keys.length - 1; i++) {
        current[keys[i]] = { ...current[keys[i]] };
        current = current[keys[i]];
      }
      
      current[keys[keys.length - 1]] = value;
      return newData;
    });
  };

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 1 }}>
        <BusinessIcon color="primary" />
        Organization Profile Setup
      </Typography>

      <Grid container spacing={3}>
        {/* Basic Organization Info */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
                Basic Information
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Organization Name"
                    value={organizationData.organizationName}
                    onChange={(e) => handleChange('organizationName', e.target.value)}
                    required
                    error={errors.some(e => e.includes('Organization name'))}
                  />
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth required error={errors.some(e => e.includes('Industry'))}>
                    <InputLabel>Industry</InputLabel>
                    <Select
                      value={organizationData.industry}
                      label="Industry"
                      onChange={(e) => handleChange('industry', e.target.value)}
                    >
                      {industries.map((industry) => (
                        <MenuItem key={industry} value={industry}>
                          {industry}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>

                <Grid item xs={12} md={6}>
                  <FormControl fullWidth required error={errors.some(e => e.includes('Organization size'))}>
                    <InputLabel>Organization Size</InputLabel>
                    <Select
                      value={organizationData.organizationSize}
                      label="Organization Size"
                      onChange={(e) => handleChange('organizationSize', e.target.value)}
                    >
                      {organizationSizes.map((size) => (
                        <MenuItem key={size} value={size}>
                          {size}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    multiline
                    rows={3}
                    label="Organization Description"
                    value={organizationData.description}
                    onChange={(e) => handleChange('description', e.target.value)}
                    placeholder="Brief description of your organization and primary business activities..."
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Headquarters & Location */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <RegionIcon />
                Headquarters & Location
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <TextField
                    fullWidth
                    label="Country"
                    value={organizationData.headquarters.country}
                    onChange={(e) => handleChange('headquarters.country', e.target.value)}
                    required
                    error={errors.some(e => e.includes('country'))}
                  />
                </Grid>

                <Grid item xs={12} md={4}>
                  <TextField
                    fullWidth
                    label="State/Region"
                    value={organizationData.headquarters.region}
                    onChange={(e) => handleChange('headquarters.region', e.target.value)}
                  />
                </Grid>

                <Grid item xs={12} md={4}>
                  <FormControl fullWidth required error={errors.some(e => e.includes('Timezone'))}>
                    <InputLabel>Timezone</InputLabel>
                    <Select
                      value={organizationData.headquarters.timezone}
                      label="Timezone"
                      onChange={(e) => handleChange('headquarters.timezone', e.target.value)}
                    >
                      {timezones.map((tz) => (
                        <MenuItem key={tz} value={tz}>
                          {tz.replace('_', ' ')}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Security Requirements */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon />
                Security Requirements
              </Typography>
              
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <FormLabel component="legend" required>Compliance Frameworks *</FormLabel>
                  <Autocomplete
                    multiple
                    options={complianceFrameworks}
                    value={organizationData.securityRequirements.complianceFrameworks}
                    onChange={(_, value) => handleChange('securityRequirements.complianceFrameworks', value)}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        placeholder="Select compliance frameworks"
                        error={errors.some(e => e.includes('compliance framework'))}
                      />
                    )}
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <FormLabel component="legend" required>Data Residency Requirements *</FormLabel>
                  <Autocomplete
                    multiple
                    options={dataResidencyOptions}
                    value={organizationData.securityRequirements.dataResidency}
                    onChange={(_, value) => handleChange('securityRequirements.dataResidency', value)}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        placeholder="Select data residency requirements"
                        error={errors.some(e => e.includes('Data residency'))}
                      />
                    )}
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <FormControl fullWidth>
                    <InputLabel>Security Clearance Level</InputLabel>
                    <Select
                      value={organizationData.securityRequirements.securityClearance}
                      label="Security Clearance Level"
                      onChange={(e) => handleChange('securityRequirements.securityClearance', e.target.value)}
                    >
                      {securityClearanceLevels.map((level) => (
                        <MenuItem key={level} value={level}>
                          {level}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>

                <Grid item xs={12}>
                  <FormLabel component="legend">Encryption Requirements</FormLabel>
                  <Autocomplete
                    multiple
                    options={encryptionRequirements}
                    value={organizationData.securityRequirements.encryptionRequirements}
                    onChange={(_, value) => handleChange('securityRequirements.encryptionRequirements', value)}
                    renderTags={(value, getTagProps) =>
                      value.map((option, index) => (
                        <Chip
                          variant="outlined"
                          label={option}
                          {...getTagProps({ index })}
                          key={option}
                        />
                      ))
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        placeholder="Select encryption requirements"
                      />
                    )}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Business Criticality */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <ComplianceIcon />
                Business Criticality
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth>
                    <InputLabel>Business Criticality Level</InputLabel>
                    <Select
                      value={organizationData.businessCriticality.level}
                      label="Business Criticality Level"
                      onChange={(e) => handleChange('businessCriticality.level', e.target.value)}
                    >
                      {businessCriticalityLevels.map((level) => (
                        <MenuItem key={level.value} value={level.value}>
                          <Stack>
                            <Typography variant="body2">{level.label}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {level.description}
                            </Typography>
                          </Stack>
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>

                <Grid item xs={12} md={3}>
                  <TextField
                    fullWidth
                    label="RTO Requirements (hours)"
                    type="number"
                    value={organizationData.businessCriticality.rtoRequirements}
                    onChange={(e) => handleChange('businessCriticality.rtoRequirements', parseInt(e.target.value))}
                    inputProps={{ min: 0, max: 72 }}
                  />
                </Grid>

                <Grid item xs={12} md={3}>
                  <TextField
                    fullWidth
                    label="RPO Requirements (hours)"
                    type="number"
                    value={organizationData.businessCriticality.rpoRequirements}
                    onChange={(e) => handleChange('businessCriticality.rpoRequirements', parseInt(e.target.value))}
                    inputProps={{ min: 0, max: 24 }}
                  />
                </Grid>

                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    multiline
                    rows={3}
                    label="Business Impact Description"
                    value={organizationData.businessCriticality.description}
                    onChange={(e) => handleChange('businessCriticality.description', e.target.value)}
                    placeholder="Describe the business impact if security systems are unavailable..."
                    required
                    error={errors.some(e => e.includes('criticality description'))}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Custom Settings */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
                Platform Customization
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <FormGroup>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={organizationData.customSettings.customBranding}
                          onChange={(e) => handleChange('customSettings.customBranding', e.target.checked)}
                        />
                      }
                      label="Custom Branding"
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={organizationData.customSettings.whiteLabeling}
                          onChange={(e) => handleChange('customSettings.whiteLabeling', e.target.checked)}
                        />
                      }
                      label="White Labeling"
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={organizationData.customSettings.apiAccess}
                          onChange={(e) => handleChange('customSettings.apiAccess', e.target.checked)}
                        />
                      }
                      label="API Access"
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={organizationData.customSettings.advancedAnalytics}
                          onChange={(e) => handleChange('customSettings.advancedAnalytics', e.target.checked)}
                        />
                      }
                      label="Advanced Analytics"
                    />
                  </FormGroup>
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Custom Domain (Optional)"
                    value={organizationData.customSettings.customDomain}
                    onChange={(e) => handleChange('customSettings.customDomain', e.target.value)}
                    placeholder="security.yourcompany.com"
                    disabled={!organizationData.customSettings.whiteLabeling}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Information Alert */}
      <Alert severity="info" sx={{ mt: 3 }}>
        <Typography variant="body2">
          <strong>Note:</strong> This information will be used to configure your iSECTECH Protect instance. 
          You can modify most settings later in the administration panel.
        </Typography>
      </Alert>
    </Box>
  );
}

export default OrganizationProfileStep;