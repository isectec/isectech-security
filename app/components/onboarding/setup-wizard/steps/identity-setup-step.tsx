/**
 * Identity Setup Step
 * Configures authentication methods, user roles, and permissions
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
  RadioGroup,
  Radio,
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
  Security as SecurityIcon,
  Person as PersonIcon,
  Group as GroupIcon,
  VpnKey as KeyIcon,
  ExpandMore as ExpandMoreIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
} from '@mui/icons-material';
import type { CustomerProfile } from '@/types';

interface IdentitySetupStepProps {
  data: any;
  onUpdate: (data: any) => void;
  onValidate: (isValid: boolean, errors?: string[]) => void;
  onNext: () => void;
  onBack: () => void;
  customerProfile: CustomerProfile;
  wizardContext: any;
}

interface IdentityData {
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
}

const authenticationMethods = [
  { value: 'local', label: 'Local Authentication', description: 'Username/password stored locally' },
  { value: 'saml', label: 'SAML 2.0', description: 'Single Sign-On via SAML' },
  { value: 'oidc', label: 'OpenID Connect', description: 'OAuth 2.0 / OpenID Connect' },
  { value: 'ldap', label: 'LDAP/Active Directory', description: 'Directory-based authentication' },
];

const mfaMethods = [
  'SMS',
  'Email',
  'TOTP (Google Authenticator)',
  'FIDO2/WebAuthn',
  'Hardware Tokens',
  'Push Notifications',
];

const defaultPermissions = [
  'dashboard.view',
  'alerts.view',
  'alerts.manage',
  'reports.view',
  'reports.create',
  'users.view',
  'users.manage',
  'system.configure',
  'system.admin',
  'api.access',
  'compliance.view',
  'compliance.manage',
  'forensics.access',
  'threat-hunting.access',
];

const ssoProviders = [
  'Azure AD',
  'Okta',
  'Google Workspace',
  'AWS SSO',
  'OneLogin',
  'Ping Identity',
  'Auth0',
  'Generic SAML',
  'Generic OIDC',
];

const daysOfWeek = [
  'Monday',
  'Tuesday',
  'Wednesday',
  'Thursday',
  'Friday',
  'Saturday',
  'Sunday',
];

export function IdentitySetupStep({
  data,
  onUpdate,
  onValidate,
  customerProfile,
}: IdentitySetupStepProps) {
  const [identityData, setIdentityData] = useState<IdentityData>({
    authenticationMethods: {
      primary: data.authenticationMethods?.primary || 'local',
      enableMFA: data.authenticationMethods?.enableMFA ?? true,
      mfaMethods: data.authenticationMethods?.mfaMethods || ['TOTP (Google Authenticator)'],
      sessionTimeout: data.authenticationMethods?.sessionTimeout || 8,
      passwordPolicy: {
        minLength: data.authenticationMethods?.passwordPolicy?.minLength || 12,
        requireUppercase: data.authenticationMethods?.passwordPolicy?.requireUppercase ?? true,
        requireLowercase: data.authenticationMethods?.passwordPolicy?.requireLowercase ?? true,
        requireNumbers: data.authenticationMethods?.passwordPolicy?.requireNumbers ?? true,
        requireSpecialChars: data.authenticationMethods?.passwordPolicy?.requireSpecialChars ?? true,
        passwordHistory: data.authenticationMethods?.passwordPolicy?.passwordHistory || 5,
        maxAge: data.authenticationMethods?.passwordPolicy?.maxAge || 90,
      },
    },
    ssoConfiguration: {
      provider: data.ssoConfiguration?.provider || '',
      entityId: data.ssoConfiguration?.entityId || '',
      ssoUrl: data.ssoConfiguration?.ssoUrl || '',
      logoutUrl: data.ssoConfiguration?.logoutUrl || '',
      certificate: data.ssoConfiguration?.certificate || '',
      nameIdFormat: data.ssoConfiguration?.nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      attributeMapping: {
        email: data.ssoConfiguration?.attributeMapping?.email || 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        firstName: data.ssoConfiguration?.attributeMapping?.firstName || 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        lastName: data.ssoConfiguration?.attributeMapping?.lastName || 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
        groups: data.ssoConfiguration?.attributeMapping?.groups || 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
      },
    },
    userRoles: data.userRoles || [
      {
        id: 'admin',
        name: 'Administrator',
        description: 'Full system access and configuration rights',
        permissions: defaultPermissions,
        isDefault: false,
      },
      {
        id: 'analyst',
        name: 'Security Analyst',
        description: 'View and manage security alerts and incidents',
        permissions: ['dashboard.view', 'alerts.view', 'alerts.manage', 'reports.view', 'threat-hunting.access'],
        isDefault: true,
      },
      {
        id: 'viewer',
        name: 'Read-Only Viewer',
        description: 'View-only access to dashboards and reports',
        permissions: ['dashboard.view', 'alerts.view', 'reports.view'],
        isDefault: false,
      },
    ],
    initialUsers: data.initialUsers || [
      {
        id: 'initial-admin',
        email: customerProfile.primaryContact?.email || '',
        firstName: customerProfile.primaryContact?.firstName || '',
        lastName: customerProfile.primaryContact?.lastName || '',
        role: 'admin',
        department: customerProfile.primaryContact?.department || '',
        isAdmin: true,
      },
    ],
    accessPolicies: {
      ipWhitelisting: {
        enabled: data.accessPolicies?.ipWhitelisting?.enabled ?? false,
        allowedRanges: data.accessPolicies?.ipWhitelisting?.allowedRanges || [],
      },
      timeBasedAccess: {
        enabled: data.accessPolicies?.timeBasedAccess?.enabled ?? false,
        allowedHours: {
          start: data.accessPolicies?.timeBasedAccess?.allowedHours?.start || '08:00',
          end: data.accessPolicies?.timeBasedAccess?.allowedHours?.end || '18:00',
          timezone: data.accessPolicies?.timeBasedAccess?.allowedHours?.timezone || customerProfile.primaryContact?.timezone || 'UTC',
        },
        allowedDays: data.accessPolicies?.timeBasedAccess?.allowedDays || ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
      },
      deviceTrust: {
        enabled: data.accessPolicies?.deviceTrust?.enabled ?? false,
        requireManagedDevices: data.accessPolicies?.deviceTrust?.requireManagedDevices ?? false,
        allowBYOD: data.accessPolicies?.deviceTrust?.allowBYOD ?? true,
      },
    },
  });

  const [errors, setErrors] = useState<string[]>([]);
  const [showPasswordPolicyAdvanced, setShowPasswordPolicyAdvanced] = useState(false);
  const [newIpRange, setNewIpRange] = useState('');
  const [newUser, setNewUser] = useState({
    email: '',
    firstName: '',
    lastName: '',
    role: 'analyst',
    department: '',
    isAdmin: false,
  });

  // Update parent component when data changes
  useEffect(() => {
    onUpdate(identityData);
  }, [identityData, onUpdate]);

  // Validation
  const validateData = useCallback(() => {
    const newErrors: string[] = [];

    // Authentication method validation
    if (identityData.authenticationMethods.primary === 'saml' || identityData.authenticationMethods.primary === 'oidc') {
      if (!identityData.ssoConfiguration.provider) {
        newErrors.push('SSO provider is required for SAML/OIDC authentication');
      }
      if (!identityData.ssoConfiguration.entityId) {
        newErrors.push('Entity ID is required for SSO configuration');
      }
      if (!identityData.ssoConfiguration.ssoUrl) {
        newErrors.push('SSO URL is required for SSO configuration');
      }
    }

    // User validation
    if (identityData.initialUsers.length === 0) {
      newErrors.push('At least one initial user must be configured');
    } else {
      const hasAdmin = identityData.initialUsers.some(user => user.isAdmin);
      if (!hasAdmin) {
        newErrors.push('At least one administrator user must be configured');
      }

      // Validate each user
      identityData.initialUsers.forEach((user, index) => {
        if (!user.email || !/\S+@\S+\.\S+/.test(user.email)) {
          newErrors.push(`User ${index + 1}: Valid email address is required`);
        }
        if (!user.firstName.trim()) {
          newErrors.push(`User ${index + 1}: First name is required`);
        }
        if (!user.lastName.trim()) {
          newErrors.push(`User ${index + 1}: Last name is required`);
        }
      });
    }

    // Role validation
    if (identityData.userRoles.length === 0) {
      newErrors.push('At least one user role must be defined');
    }

    // IP whitelist validation
    if (identityData.accessPolicies.ipWhitelisting.enabled) {
      if (identityData.accessPolicies.ipWhitelisting.allowedRanges.length === 0) {
        newErrors.push('At least one IP range must be specified when IP whitelisting is enabled');
      }
    }

    setErrors(newErrors);
    onValidate(newErrors.length === 0, newErrors);
  }, [identityData, onValidate]);

  useEffect(() => {
    validateData();
  }, [validateData]);

  const handleChange = (field: string, value: any) => {
    setIdentityData(prev => {
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

  const handleAddIpRange = () => {
    if (newIpRange.trim()) {
      const updatedRanges = [...identityData.accessPolicies.ipWhitelisting.allowedRanges, newIpRange.trim()];
      handleChange('accessPolicies.ipWhitelisting.allowedRanges', updatedRanges);
      setNewIpRange('');
    }
  };

  const handleRemoveIpRange = (index: number) => {
    const updatedRanges = identityData.accessPolicies.ipWhitelisting.allowedRanges.filter((_, i) => i !== index);
    handleChange('accessPolicies.ipWhitelisting.allowedRanges', updatedRanges);
  };

  const handleAddUser = () => {
    if (newUser.email && newUser.firstName && newUser.lastName) {
      const updatedUsers = [...identityData.initialUsers, {
        ...newUser,
        id: `user-${Date.now()}`,
      }];
      handleChange('initialUsers', updatedUsers);
      setNewUser({
        email: '',
        firstName: '',
        lastName: '',
        role: 'analyst',
        department: '',
        isAdmin: false,
      });
    }
  };

  const handleRemoveUser = (index: number) => {
    const updatedUsers = identityData.initialUsers.filter((_, i) => i !== index);
    handleChange('initialUsers', updatedUsers);
  };

  const isSSOEnabled = identityData.authenticationMethods.primary === 'saml' || identityData.authenticationMethods.primary === 'oidc';

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 1 }}>
        <SecurityIcon color="primary" />
        Identity & Access Management Setup
      </Typography>

      <Grid container spacing={3}>
        {/* Authentication Methods */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <KeyIcon />
                Authentication Methods
              </Typography>

              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <FormControl component="fieldset">
                    <RadioGroup
                      value={identityData.authenticationMethods.primary}
                      onChange={(e) => handleChange('authenticationMethods.primary', e.target.value)}
                    >
                      {authenticationMethods.map((method) => (
                        <FormControlLabel
                          key={method.value}
                          value={method.value}
                          control={<Radio />}
                          label={
                            <Box>
                              <Typography variant="body2">{method.label}</Typography>
                              <Typography variant="caption" color="text.secondary">
                                {method.description}
                              </Typography>
                            </Box>
                          }
                        />
                      ))}
                    </RadioGroup>
                  </FormControl>
                </Grid>

                <Grid item xs={12} md={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={identityData.authenticationMethods.enableMFA}
                        onChange={(e) => handleChange('authenticationMethods.enableMFA', e.target.checked)}
                      />
                    }
                    label="Enable Multi-Factor Authentication (MFA)"
                  />
                </Grid>

                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    type="number"
                    label="Session Timeout (hours)"
                    value={identityData.authenticationMethods.sessionTimeout}
                    onChange={(e) => handleChange('authenticationMethods.sessionTimeout', parseInt(e.target.value))}
                    inputProps={{ min: 1, max: 24 }}
                  />
                </Grid>

                {identityData.authenticationMethods.enableMFA && (
                  <Grid item xs={12}>
                    <Typography variant="body2" sx={{ mb: 1 }}>MFA Methods:</Typography>
                    <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
                      {mfaMethods.map((method) => (
                        <FormControlLabel
                          key={method}
                          control={
                            <Checkbox
                              checked={identityData.authenticationMethods.mfaMethods.includes(method)}
                              onChange={(e) => {
                                const currentMethods = identityData.authenticationMethods.mfaMethods;
                                if (e.target.checked) {
                                  handleChange('authenticationMethods.mfaMethods', [...currentMethods, method]);
                                } else {
                                  handleChange('authenticationMethods.mfaMethods', currentMethods.filter(m => m !== method));
                                }
                              }}
                            />
                          }
                          label={method}
                        />
                      ))}
                    </Stack>
                  </Grid>
                )}
              </Grid>

              {/* Password Policy */}
              <Accordion expanded={showPasswordPolicyAdvanced} onChange={() => setShowPasswordPolicyAdvanced(!showPasswordPolicyAdvanced)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2">Password Policy Configuration</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <TextField
                        fullWidth
                        type="number"
                        label="Minimum Length"
                        value={identityData.authenticationMethods.passwordPolicy.minLength}
                        onChange={(e) => handleChange('authenticationMethods.passwordPolicy.minLength', parseInt(e.target.value))}
                        inputProps={{ min: 8, max: 128 }}
                      />
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <TextField
                        fullWidth
                        type="number"
                        label="Password History"
                        value={identityData.authenticationMethods.passwordPolicy.passwordHistory}
                        onChange={(e) => handleChange('authenticationMethods.passwordPolicy.passwordHistory', parseInt(e.target.value))}
                        inputProps={{ min: 0, max: 24 }}
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <Stack direction="row" spacing={2} sx={{ flexWrap: 'wrap' }}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={identityData.authenticationMethods.passwordPolicy.requireUppercase}
                              onChange={(e) => handleChange('authenticationMethods.passwordPolicy.requireUppercase', e.target.checked)}
                            />
                          }
                          label="Require Uppercase"
                        />
                        <FormControlLabel
                          control={
                            <Switch
                              checked={identityData.authenticationMethods.passwordPolicy.requireLowercase}
                              onChange={(e) => handleChange('authenticationMethods.passwordPolicy.requireLowercase', e.target.checked)}
                            />
                          }
                          label="Require Lowercase"
                        />
                        <FormControlLabel
                          control={
                            <Switch
                              checked={identityData.authenticationMethods.passwordPolicy.requireNumbers}
                              onChange={(e) => handleChange('authenticationMethods.passwordPolicy.requireNumbers', e.target.checked)}
                            />
                          }
                          label="Require Numbers"
                        />
                        <FormControlLabel
                          control={
                            <Switch
                              checked={identityData.authenticationMethods.passwordPolicy.requireSpecialChars}
                              onChange={(e) => handleChange('authenticationMethods.passwordPolicy.requireSpecialChars', e.target.checked)}
                            />
                          }
                          label="Require Special Characters"
                        />
                      </Stack>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </CardContent>
          </Card>
        </Grid>

        {/* SSO Configuration */}
        {isSSOEnabled && (
          <Grid item xs={12}>
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
                  SSO Configuration
                </Typography>

                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth error={errors.some(e => e.includes('SSO provider'))}>
                      <InputLabel>SSO Provider</InputLabel>
                      <Select
                        value={identityData.ssoConfiguration.provider}
                        label="SSO Provider"
                        onChange={(e) => handleChange('ssoConfiguration.provider', e.target.value)}
                      >
                        {ssoProviders.map((provider) => (
                          <MenuItem key={provider} value={provider}>
                            {provider}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Entity ID"
                      value={identityData.ssoConfiguration.entityId}
                      onChange={(e) => handleChange('ssoConfiguration.entityId', e.target.value)}
                      required
                      error={errors.some(e => e.includes('Entity ID'))}
                    />
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="SSO URL"
                      value={identityData.ssoConfiguration.ssoUrl}
                      onChange={(e) => handleChange('ssoConfiguration.ssoUrl', e.target.value)}
                      required
                      error={errors.some(e => e.includes('SSO URL'))}
                    />
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Logout URL"
                      value={identityData.ssoConfiguration.logoutUrl}
                      onChange={(e) => handleChange('ssoConfiguration.logoutUrl', e.target.value)}
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      multiline
                      rows={4}
                      label="X.509 Certificate"
                      value={identityData.ssoConfiguration.certificate}
                      onChange={(e) => handleChange('ssoConfiguration.certificate', e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    />
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Initial Users */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <PersonIcon />
                Initial Users
              </Typography>

              <List>
                {identityData.initialUsers.map((user, index) => (
                  <ListItem key={user.id}>
                    <ListItemText
                      primary={`${user.firstName} ${user.lastName}`}
                      secondary={
                        <Stack spacing={0.5}>
                          <Typography variant="body2">{user.email}</Typography>
                          <Stack direction="row" spacing={1}>
                            <Chip label={user.role} size="small" />
                            {user.isAdmin && <Chip label="Administrator" color="primary" size="small" />}
                            {user.department && <Chip label={user.department} variant="outlined" size="small" />}
                          </Stack>
                        </Stack>
                      }
                    />
                    <ListItemSecondaryAction>
                      <IconButton onClick={() => handleRemoveUser(index)}>
                        <DeleteIcon />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>

              <Divider sx={{ my: 2 }} />

              <Typography variant="body2" sx={{ mb: 2 }}>Add New User:</Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={3}>
                  <TextField
                    fullWidth
                    label="Email"
                    value={newUser.email}
                    onChange={(e) => setNewUser(prev => ({ ...prev, email: e.target.value }))}
                  />
                </Grid>
                <Grid item xs={12} md={3}>
                  <TextField
                    fullWidth
                    label="First Name"
                    value={newUser.firstName}
                    onChange={(e) => setNewUser(prev => ({ ...prev, firstName: e.target.value }))}
                  />
                </Grid>
                <Grid item xs={12} md={3}>
                  <TextField
                    fullWidth
                    label="Last Name"
                    value={newUser.lastName}
                    onChange={(e) => setNewUser(prev => ({ ...prev, lastName: e.target.value }))}
                  />
                </Grid>
                <Grid item xs={12} md={3}>
                  <FormControl fullWidth>
                    <InputLabel>Role</InputLabel>
                    <Select
                      value={newUser.role}
                      label="Role"
                      onChange={(e) => setNewUser(prev => ({ ...prev, role: e.target.value }))}
                    >
                      {identityData.userRoles.map((role) => (
                        <MenuItem key={role.id} value={role.id}>
                          {role.name}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12}>
                  <Stack direction="row" spacing={2} alignItems="center">
                    <TextField
                      label="Department"
                      value={newUser.department}
                      onChange={(e) => setNewUser(prev => ({ ...prev, department: e.target.value }))}
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={newUser.isAdmin}
                          onChange={(e) => setNewUser(prev => ({ ...prev, isAdmin: e.target.checked }))}
                        />
                      }
                      label="Administrator"
                    />
                    <Button
                      variant="contained"
                      startIcon={<AddIcon />}
                      onClick={handleAddUser}
                      disabled={!newUser.email || !newUser.firstName || !newUser.lastName}
                    >
                      Add User
                    </Button>
                  </Stack>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Access Policies */}
        <Grid item xs={12}>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <GroupIcon />
                Access Policies
              </Typography>

              <Grid container spacing={3}>
                {/* IP Whitelisting */}
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={identityData.accessPolicies.ipWhitelisting.enabled}
                        onChange={(e) => handleChange('accessPolicies.ipWhitelisting.enabled', e.target.checked)}
                      />
                    }
                    label="Enable IP Whitelisting"
                  />
                  
                  {identityData.accessPolicies.ipWhitelisting.enabled && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="body2" sx={{ mb: 1 }}>Allowed IP Ranges:</Typography>
                      <Stack spacing={1}>
                        {identityData.accessPolicies.ipWhitelisting.allowedRanges.map((range, index) => (
                          <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Chip label={range} />
                            <IconButton size="small" onClick={() => handleRemoveIpRange(index)}>
                              <DeleteIcon />
                            </IconButton>
                          </Box>
                        ))}
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <TextField
                            label="New IP Range"
                            value={newIpRange}
                            onChange={(e) => setNewIpRange(e.target.value)}
                            placeholder="192.168.1.0/24"
                            size="small"
                          />
                          <Button
                            variant="outlined"
                            startIcon={<AddIcon />}
                            onClick={handleAddIpRange}
                            disabled={!newIpRange.trim()}
                          >
                            Add
                          </Button>
                        </Box>
                      </Stack>
                    </Box>
                  )}
                </Grid>

                {/* Time-based Access */}
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={identityData.accessPolicies.timeBasedAccess.enabled}
                        onChange={(e) => handleChange('accessPolicies.timeBasedAccess.enabled', e.target.checked)}
                      />
                    }
                    label="Enable Time-based Access Controls"
                  />
                  
                  {identityData.accessPolicies.timeBasedAccess.enabled && (
                    <Grid container spacing={2} sx={{ mt: 1 }}>
                      <Grid item xs={12} md={4}>
                        <TextField
                          fullWidth
                          type="time"
                          label="Start Time"
                          value={identityData.accessPolicies.timeBasedAccess.allowedHours.start}
                          onChange={(e) => handleChange('accessPolicies.timeBasedAccess.allowedHours.start', e.target.value)}
                          InputLabelProps={{ shrink: true }}
                        />
                      </Grid>
                      <Grid item xs={12} md={4}>
                        <TextField
                          fullWidth
                          type="time"
                          label="End Time"
                          value={identityData.accessPolicies.timeBasedAccess.allowedHours.end}
                          onChange={(e) => handleChange('accessPolicies.timeBasedAccess.allowedHours.end', e.target.value)}
                          InputLabelProps={{ shrink: true }}
                        />
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="body2" sx={{ mb: 1 }}>Allowed Days:</Typography>
                        <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
                          {daysOfWeek.map((day) => (
                            <FormControlLabel
                              key={day}
                              control={
                                <Checkbox
                                  checked={identityData.accessPolicies.timeBasedAccess.allowedDays.includes(day)}
                                  onChange={(e) => {
                                    const currentDays = identityData.accessPolicies.timeBasedAccess.allowedDays;
                                    if (e.target.checked) {
                                      handleChange('accessPolicies.timeBasedAccess.allowedDays', [...currentDays, day]);
                                    } else {
                                      handleChange('accessPolicies.timeBasedAccess.allowedDays', currentDays.filter(d => d !== day));
                                    }
                                  }}
                                />
                              }
                              label={day}
                            />
                          ))}
                        </Stack>
                      </Grid>
                    </Grid>
                  )}
                </Grid>

                {/* Device Trust */}
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={identityData.accessPolicies.deviceTrust.enabled}
                        onChange={(e) => handleChange('accessPolicies.deviceTrust.enabled', e.target.checked)}
                      />
                    }
                    label="Enable Device Trust Policies"
                  />
                  
                  {identityData.accessPolicies.deviceTrust.enabled && (
                    <Box sx={{ mt: 2, ml: 4 }}>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={identityData.accessPolicies.deviceTrust.requireManagedDevices}
                            onChange={(e) => handleChange('accessPolicies.deviceTrust.requireManagedDevices', e.target.checked)}
                          />
                        }
                        label="Require Managed Devices"
                      />
                      <FormControlLabel
                        control={
                          <Switch
                            checked={identityData.accessPolicies.deviceTrust.allowBYOD}
                            onChange={(e) => handleChange('accessPolicies.deviceTrust.allowBYOD', e.target.checked)}
                          />
                        }
                        label="Allow BYOD (Bring Your Own Device)"
                      />
                    </Box>
                  )}
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Information Alert */}
      <Alert severity="info" sx={{ mt: 3 }}>
        <Typography variant="body2">
          <strong>Security Note:</strong> These identity and access settings establish the foundation of your security posture. 
          We recommend enabling MFA and implementing strict access policies for enterprise environments.
        </Typography>
      </Alert>
    </Box>
  );
}

export default IdentitySetupStep;