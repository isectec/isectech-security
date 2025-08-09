/**
 * White Label Customization Component for iSECTECH Protect
 * Production-grade tenant branding and customization interface
 */

'use client';

import { useAuthStore, useStores } from '@/lib/store';
import type { Tenant } from '@/types';
import {
  Brush as BrushIcon,
  Business as BusinessIcon,
  Delete as DeleteIcon,
  Palette as PaletteIcon,
  Preview as PreviewIcon,
  Restore as ResetIcon,
  Save as SaveIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Upload as UploadIcon,
} from '@mui/icons-material';
import {
  Alert,
  alpha,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  FormControlLabel,
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import React, { useCallback, useState } from 'react';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index, ...other }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`customization-tabpanel-${index}`}
      aria-labelledby={`customization-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 0 }}>{children}</Box>}
    </div>
  );
}

interface WhiteLabelCustomizationProps {
  /**
   * Current tenant being customized
   */
  tenant: Tenant;

  /**
   * Callback when customization is saved
   */
  onSave?: (customization: Partial<Tenant>) => Promise<void>;

  /**
   * Whether user can modify settings
   */
  readonly?: boolean;

  /**
   * Preview mode
   */
  previewMode?: boolean;
}

export function WhiteLabelCustomization({
  tenant,
  onSave,
  readonly = false,
  previewMode = false,
}: WhiteLabelCustomizationProps) {
  const theme = useTheme();
  const { user } = useAuthStore();
  const { showSuccess, showError, showWarning } = useStores();

  const [currentTab, setCurrentTab] = useState(0);
  const [customization, setCustomization] = useState<Partial<Tenant>>({
    displayName: tenant.displayName,
    logo: tenant.logo,
    primaryColor: tenant.primaryColor || theme.palette.primary.main,
    secondaryColor: tenant.secondaryColor || theme.palette.secondary.main,
    settings: tenant.settings || {},
  });
  const [isLoading, setIsLoading] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [logoFile, setLogoFile] = useState<File | null>(null);

  // Color presets for quick selection
  const colorPresets = [
    { name: 'Default Blue', primary: '#1976d2', secondary: '#dc004e' },
    { name: 'Corporate Green', primary: '#2e7d32', secondary: '#ed6c02' },
    { name: 'Security Red', primary: '#d32f2f', secondary: '#1976d2' },
    { name: 'Professional Purple', primary: '#7b1fa2', secondary: '#f57c00' },
    { name: 'Tech Orange', primary: '#f57c00', secondary: '#1976d2' },
    { name: 'Minimal Gray', primary: '#424242', secondary: '#1976d2' },
  ];

  // Handle color change
  const handleColorChange = useCallback((type: 'primary' | 'secondary', color: string) => {
    setCustomization((prev) => ({
      ...prev,
      [`${type}Color`]: color,
    }));
  }, []);

  // Handle logo upload
  const handleLogoUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (file) {
        // Validate file
        if (!file.type.startsWith('image/')) {
          showError('Invalid File', 'Please select an image file.');
          return;
        }

        if (file.size > 2 * 1024 * 1024) {
          // 2MB limit
          showError('File Too Large', 'Logo file must be less than 2MB.');
          return;
        }

        setLogoFile(file);

        // Create preview URL
        const reader = new FileReader();
        reader.onload = (e) => {
          setCustomization((prev) => ({
            ...prev,
            logo: e.target?.result as string,
          }));
        };
        reader.readAsDataURL(file);
      }
    },
    [showError]
  );

  // Apply color preset
  const applyColorPreset = useCallback(
    (preset: (typeof colorPresets)[0]) => {
      setCustomization((prev) => ({
        ...prev,
        primaryColor: preset.primary,
        secondaryColor: preset.secondary,
      }));
      showSuccess('Preset Applied', `Applied ${preset.name} color scheme.`);
    },
    [showSuccess]
  );

  // Reset to defaults
  const resetToDefaults = useCallback(() => {
    setCustomization({
      displayName: tenant.displayName,
      logo: tenant.logo,
      primaryColor: theme.palette.primary.main,
      secondaryColor: theme.palette.secondary.main,
      settings: tenant.settings || {},
    });
    setLogoFile(null);
    showSuccess('Reset Complete', 'Customization reset to defaults.');
  }, [tenant, theme, showSuccess]);

  // Save customization
  const saveCustomization = useCallback(async () => {
    if (!onSave) return;

    setIsLoading(true);
    try {
      await onSave(customization);
      showSuccess('Customization Saved', 'Tenant branding has been updated successfully.');
    } catch (error) {
      console.error('Failed to save customization:', error);
      showError('Save Failed', 'Unable to save customization changes.');
    } finally {
      setIsLoading(false);
    }
  }, [customization, onSave, showSuccess, showError]);

  // Check if user has permission to modify
  const canModify =
    user?.role === 'SUPER_ADMIN' ||
    (user?.role === 'TENANT_ADMIN' && user?.tenantId === tenant.id) ||
    user?.permissions.includes('tenant:customize');

  return (
    <Box>
      <Card elevation={2}>
        <CardHeader
          title={
            <Stack direction="row" alignItems="center" spacing={1}>
              <BrushIcon />
              <Typography variant="h6">White Label Customization</Typography>
              {readonly && <Chip label="Read Only" size="small" variant="outlined" />}
            </Stack>
          }
          subheader={`Customize branding for ${tenant.displayName}`}
          action={
            <Stack direction="row" spacing={1}>
              <Tooltip title="Preview Changes">
                <IconButton onClick={() => setShowPreview(true)}>
                  <PreviewIcon />
                </IconButton>
              </Tooltip>
              {!readonly && canModify && (
                <>
                  <Tooltip title="Reset to Defaults">
                    <IconButton onClick={resetToDefaults}>
                      <ResetIcon />
                    </IconButton>
                  </Tooltip>
                  <Button
                    variant="contained"
                    startIcon={<SaveIcon />}
                    onClick={saveCustomization}
                    disabled={isLoading}
                    size="small"
                  >
                    Save Changes
                  </Button>
                </>
              )}
            </Stack>
          }
        />

        <CardContent>
          <Tabs value={currentTab} onChange={(_, newValue) => setCurrentTab(newValue)}>
            <Tab label="Branding" icon={<BusinessIcon />} />
            <Tab label="Colors" icon={<PaletteIcon />} />
            <Tab label="Layout" icon={<SettingsIcon />} />
            <Tab label="Security" icon={<SecurityIcon />} />
          </Tabs>

          {/* Branding Tab */}
          <TabPanel value={currentTab} index={0}>
            <Stack spacing={3} sx={{ mt: 2 }}>
              {/* Display Name */}
              <TextField
                label="Display Name"
                value={customization.displayName || ''}
                onChange={(e) => setCustomization((prev) => ({ ...prev, displayName: e.target.value }))}
                fullWidth
                disabled={readonly || !canModify}
                helperText="The name displayed in the interface"
              />

              {/* Logo Upload */}
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Logo
                </Typography>
                <Grid container spacing={2} alignItems="center">
                  <Grid item>
                    <Avatar
                      src={customization.logo || undefined}
                      sx={{
                        width: 64,
                        height: 64,
                        bgcolor: customization.primaryColor,
                        fontSize: '1.5rem',
                      }}
                    >
                      {customization.displayName?.charAt(0) || '?'}
                    </Avatar>
                  </Grid>
                  <Grid item xs>
                    <Stack spacing={1}>
                      <input
                        accept="image/*"
                        style={{ display: 'none' }}
                        id="logo-upload"
                        type="file"
                        onChange={handleLogoUpload}
                        disabled={readonly || !canModify}
                      />
                      <Stack direction="row" spacing={1}>
                        <label htmlFor="logo-upload">
                          <Button
                            variant="outlined"
                            component="span"
                            startIcon={<UploadIcon />}
                            disabled={readonly || !canModify}
                            size="small"
                          >
                            Upload Logo
                          </Button>
                        </label>
                        {customization.logo && (
                          <Button
                            variant="outlined"
                            color="error"
                            startIcon={<DeleteIcon />}
                            onClick={() => setCustomization((prev) => ({ ...prev, logo: undefined }))}
                            disabled={readonly || !canModify}
                            size="small"
                          >
                            Remove
                          </Button>
                        )}
                      </Stack>
                      <Typography variant="caption" color="text.secondary">
                        Recommended: 256x256 pixels, PNG or JPG, max 2MB
                      </Typography>
                    </Stack>
                  </Grid>
                </Grid>
              </Box>
            </Stack>
          </TabPanel>

          {/* Colors Tab */}
          <TabPanel value={currentTab} index={1}>
            <Stack spacing={3} sx={{ mt: 2 }}>
              {/* Color Presets */}
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Quick Presets
                </Typography>
                <Grid container spacing={1}>
                  {colorPresets.map((preset) => (
                    <Grid item key={preset.name}>
                      <Tooltip title={preset.name}>
                        <Paper
                          sx={{
                            p: 1,
                            cursor: readonly || !canModify ? 'default' : 'pointer',
                            opacity: readonly || !canModify ? 0.5 : 1,
                            '&:hover':
                              readonly || !canModify
                                ? {}
                                : {
                                    boxShadow: theme.shadows[4],
                                  },
                          }}
                          onClick={() => !readonly && canModify && applyColorPreset(preset)}
                        >
                          <Stack direction="row" spacing={0.5}>
                            <Box
                              sx={{
                                width: 20,
                                height: 20,
                                bgcolor: preset.primary,
                                borderRadius: 0.5,
                              }}
                            />
                            <Box
                              sx={{
                                width: 20,
                                height: 20,
                                bgcolor: preset.secondary,
                                borderRadius: 0.5,
                              }}
                            />
                          </Stack>
                        </Paper>
                      </Tooltip>
                    </Grid>
                  ))}
                </Grid>
              </Box>

              {/* Custom Colors */}
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Primary Color
                  </Typography>
                  <Stack spacing={2}>
                    <TextField
                      type="color"
                      value={customization.primaryColor || theme.palette.primary.main}
                      onChange={(e) => handleColorChange('primary', e.target.value)}
                      disabled={readonly || !canModify}
                      sx={{ width: 60 }}
                    />
                    <TextField
                      label="Hex Value"
                      value={customization.primaryColor || theme.palette.primary.main}
                      onChange={(e) => handleColorChange('primary', e.target.value)}
                      disabled={readonly || !canModify}
                      placeholder="#1976d2"
                    />
                    {/* Color Preview */}
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: customization.primaryColor,
                        color: theme.palette.getContrastText(customization.primaryColor || theme.palette.primary.main),
                        textAlign: 'center',
                      }}
                    >
                      <Typography variant="body2">Primary Color Preview</Typography>
                    </Paper>
                  </Stack>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Secondary Color
                  </Typography>
                  <Stack spacing={2}>
                    <TextField
                      type="color"
                      value={customization.secondaryColor || theme.palette.secondary.main}
                      onChange={(e) => handleColorChange('secondary', e.target.value)}
                      disabled={readonly || !canModify}
                      sx={{ width: 60 }}
                    />
                    <TextField
                      label="Hex Value"
                      value={customization.secondaryColor || theme.palette.secondary.main}
                      onChange={(e) => handleColorChange('secondary', e.target.value)}
                      disabled={readonly || !canModify}
                      placeholder="#dc004e"
                    />
                    {/* Color Preview */}
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: customization.secondaryColor,
                        color: theme.palette.getContrastText(
                          customization.secondaryColor || theme.palette.secondary.main
                        ),
                        textAlign: 'center',
                      }}
                    >
                      <Typography variant="body2">Secondary Color Preview</Typography>
                    </Paper>
                  </Stack>
                </Grid>
              </Grid>
            </Stack>
          </TabPanel>

          {/* Layout Tab */}
          <TabPanel value={currentTab} index={2}>
            <Stack spacing={3} sx={{ mt: 2 }}>
              <Alert severity="info" variant="outlined">
                Layout customization features will be available in the next release.
              </Alert>

              {/* Placeholder for future layout options */}
              <Box sx={{ opacity: 0.5 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Sidebar Configuration
                </Typography>
                <FormControlLabel control={<Switch disabled />} label="Show company logo in sidebar" />
                <FormControlLabel control={<Switch disabled />} label="Collapsible sidebar by default" />

                <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                  Dashboard Layout
                </Typography>
                <FormControl disabled fullWidth size="small">
                  <InputLabel>Default Dashboard View</InputLabel>
                  <Select label="Default Dashboard View" value="">
                    <MenuItem value="overview">Security Overview</MenuItem>
                    <MenuItem value="alerts">Alert Management</MenuItem>
                    <MenuItem value="threats">Threat Intelligence</MenuItem>
                  </Select>
                </FormControl>
              </Box>
            </Stack>
          </TabPanel>

          {/* Security Tab */}
          <TabPanel value={currentTab} index={3}>
            <Stack spacing={3} sx={{ mt: 2 }}>
              <Alert severity="warning" variant="outlined">
                Security customization requires Super Admin privileges.
              </Alert>

              {/* Placeholder for security customization */}
              <Box sx={{ opacity: user?.role === 'SUPER_ADMIN' ? 1 : 0.5 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Branding Security
                </Typography>
                <FormControlLabel
                  control={<Switch disabled={user?.role !== 'SUPER_ADMIN'} />}
                  label="Hide iSECTECH branding"
                />
                <FormControlLabel
                  control={<Switch disabled={user?.role !== 'SUPER_ADMIN'} />}
                  label="Custom login page"
                />
                <FormControlLabel
                  control={<Switch disabled={user?.role !== 'SUPER_ADMIN'} />}
                  label="Custom domain support"
                />

                <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                  Content Filtering
                </Typography>
                <FormControlLabel
                  control={<Switch disabled={user?.role !== 'SUPER_ADMIN'} />}
                  label="Hide help documentation"
                />
                <FormControlLabel
                  control={<Switch disabled={user?.role !== 'SUPER_ADMIN'} />}
                  label="Custom support links"
                />
              </Box>
            </Stack>
          </TabPanel>
        </CardContent>
      </Card>

      {/* Preview Dialog */}
      <Dialog open={showPreview} onClose={() => setShowPreview(false)} maxWidth="md" fullWidth>
        <DialogTitle>Customization Preview</DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            <Alert severity="info" variant="outlined">
              This is a preview of how your customization will appear.
            </Alert>

            {/* Mock interface preview */}
            <Paper
              sx={{
                p: 2,
                bgcolor: alpha(customization.primaryColor || theme.palette.primary.main, 0.05),
                border: `1px solid ${alpha(customization.primaryColor || theme.palette.primary.main, 0.2)}`,
              }}
            >
              <Stack direction="row" alignItems="center" spacing={2}>
                <Avatar
                  src={customization.logo || undefined}
                  sx={{
                    bgcolor: customization.primaryColor,
                    color: theme.palette.getContrastText(customization.primaryColor || theme.palette.primary.main),
                  }}
                >
                  {customization.displayName?.charAt(0) || '?'}
                </Avatar>
                <Box>
                  <Typography variant="h6" sx={{ color: customization.primaryColor }}>
                    {customization.displayName} Security Command Center
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Powered by iSECTECH Protect
                  </Typography>
                </Box>
              </Stack>

              <Divider sx={{ my: 2 }} />

              <Stack direction="row" spacing={1}>
                <Button variant="contained" size="small" sx={{ bgcolor: customization.primaryColor }}>
                  Primary Action
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  sx={{
                    borderColor: customization.secondaryColor,
                    color: customization.secondaryColor,
                  }}
                >
                  Secondary Action
                </Button>
              </Stack>
            </Paper>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowPreview(false)}>Close Preview</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default WhiteLabelCustomization;
