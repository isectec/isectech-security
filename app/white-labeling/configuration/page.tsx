'use client';

/**
 * White-Label Configuration Management Page
 * Comprehensive administrative interface for managing all white-labeling configurations
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  LinearProgress,
  Tooltip,
  Menu,
  MenuItem as MenuItemComponent,
  ListItemIcon,
  ListItemText,
  Switch,
  FormControlLabel,
  Fab,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as PreviewIcon,
  CloudUpload as DeployIcon,
  History as HistoryIcon,
  GetApp as ExportIcon,
  Publish as ImportIcon,
  Settings as SettingsIcon,
  Palette as ThemeIcon,
  Image as AssetIcon,
  Article as ContentIcon,
  Domain as DomainIcon,
  Email as EmailIcon,
  Security as SecurityIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  MoreVert as MoreIcon,
  ExpandMore as ExpandMoreIcon,
  Launch as LaunchIcon,
  Backup as BackupIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';

import { configurationManager } from '@/lib/white-labeling/configuration-manager';
import { themeManager } from '@/lib/white-labeling/theme-manager';
import { assetManager } from '@/lib/white-labeling/asset-manager';
import { contentManager } from '@/lib/white-labeling/content-manager';
import { domainManager } from '@/lib/white-labeling/domain-manager';
import { emailTemplateManager } from '@/lib/white-labeling/email-template-manager';
import type {
  WhiteLabelConfiguration,
  ConfigurationStatus,
  ThemeConfiguration,
  BrandAsset,
  AssetType,
  EmailTemplate,
  DomainConfiguration,
} from '@/types/white-labeling';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div role="tabpanel" hidden={value !== index}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const configurationSteps = [
  { label: 'Basic Information', icon: <SettingsIcon /> },
  { label: 'Theme & Colors', icon: <ThemeIcon /> },
  { label: 'Brand Assets', icon: <AssetIcon /> },
  { label: 'Content Customization', icon: <ContentIcon /> },
  { label: 'Domain & Email', icon: <DomainIcon /> },
  { label: 'Review & Deploy', icon: <CheckIcon /> },
];

export default function ConfigurationManagementPage() {
  const [configurations, setConfigurations] = useState<WhiteLabelConfiguration[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Dialog states
  const [createDialog, setCreateDialog] = useState(false);
  const [editDialog, setEditDialog] = useState(false);
  const [previewDialog, setPreviewDialog] = useState(false);
  const [deployDialog, setDeployDialog] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState(false);
  
  // Configuration management state
  const [selectedConfig, setSelectedConfig] = useState<WhiteLabelConfiguration | null>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [configForm, setConfigForm] = useState({
    name: '',
    description: '',
    status: 'draft' as ConfigurationStatus,
  });
  
  // Theme configuration state
  const [themeConfig, setThemeConfig] = useState<Partial<ThemeConfiguration>>({});
  const [selectedAssets, setSelectedAssets] = useState<Record<AssetType, BrandAsset | null>>({
    'logo-primary': null,
    'logo-secondary': null,
    'favicon': null,
    'email-header': null,
    'report-header': null,
    'mobile-icon': null,
    'background': null,
    'watermark': null,
  });
  
  // Content and domain state
  const [emailTemplates, setEmailTemplates] = useState<EmailTemplate[]>([]);
  const [domainConfig, setDomainConfig] = useState<DomainConfiguration | null>(null);
  
  // UI state
  const [tabValue, setTabValue] = useState(0);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [deployProgress, setDeployProgress] = useState(0);
  const [validationResults, setValidationResults] = useState<any>(null);

  const tenantId = 'demo-tenant'; // Would get from auth context
  const userId = 'demo-user'; // Would get from auth context

  useEffect(() => {
    loadConfigurations();
  }, []);

  const loadConfigurations = async () => {
    try {
      setLoading(true);
      const result = await configurationManager.getConfigurationsForTenant(tenantId);
      setConfigurations(result.configurations);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load configurations');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateConfiguration = async () => {
    try {
      const config = await configurationManager.createConfiguration(
        tenantId,
        {
          name: configForm.name,
          description: configForm.description,
          theme: themeConfig as ThemeConfiguration,
          assets: selectedAssets,
          emailTemplates,
          domain: domainConfig || undefined,
        },
        userId
      );
      
      setConfigurations([...configurations, config]);
      setCreateDialog(false);
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create configuration');
    }
  };

  const handleUpdateConfiguration = async () => {
    if (!selectedConfig) return;
    
    try {
      const updated = await configurationManager.updateConfiguration(
        selectedConfig.id,
        tenantId,
        {
          name: configForm.name,
          description: configForm.description,
          theme: themeConfig as ThemeConfiguration,
          emailTemplates,
          domain: domainConfig || undefined,
        },
        userId
      );
      
      setConfigurations(configs => 
        configs.map(c => c.id === updated.id ? updated : c)
      );
      setEditDialog(false);
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update configuration');
    }
  };

  const handleValidateConfiguration = async (config: WhiteLabelConfiguration) => {
    try {
      const validation = await configurationManager.validateConfiguration(config);
      setValidationResults(validation);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to validate configuration');
    }
  };

  const handlePreviewConfiguration = async (config: WhiteLabelConfiguration) => {
    try {
      const preview = await configurationManager.generatePreview(
        config.id,
        tenantId,
        { includeScreenshots: true }
      );
      
      // Open preview in new window
      window.open(preview.previewUrl, '_blank');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate preview');
    }
  };

  const handleDeployConfiguration = async (config: WhiteLabelConfiguration) => {
    try {
      setDeployProgress(0);
      setDeployDialog(true);
      
      // Simulate deployment progress
      const progressInterval = setInterval(() => {
        setDeployProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      const deployment = await configurationManager.deployConfiguration(
        config.id,
        tenantId,
        userId,
        { immediateDeployment: true }
      );
      
      clearInterval(progressInterval);
      setDeployProgress(100);
      
      // Update configuration status
      setConfigurations(configs =>
        configs.map(c => c.id === config.id ? { ...c, isActive: true, status: 'active' as ConfigurationStatus } : c)
      );
      
      setTimeout(() => {
        setDeployDialog(false);
        setDeployProgress(0);
      }, 1000);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to deploy configuration');
      setDeployDialog(false);
      setDeployProgress(0);
    }
  };

  const handleDeleteConfiguration = async (config: WhiteLabelConfiguration) => {
    try {
      await configurationManager.deleteConfiguration(config.id, tenantId, userId);
      setConfigurations(configs => configs.filter(c => c.id !== config.id));
      setDeleteDialog(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete configuration');
    }
  };

  const handleExportConfiguration = async (config: WhiteLabelConfiguration) => {
    try {
      const exportData = await configurationManager.exportConfiguration(config.id, tenantId);
      
      // Create download
      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${config.name.replace(/\s+/g, '_')}_config.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export configuration');
    }
  };

  const resetForm = () => {
    setConfigForm({ name: '', description: '', status: 'draft' });
    setThemeConfig({});
    setSelectedAssets({
      'logo-primary': null,
      'logo-secondary': null,
      'favicon': null,
      'email-header': null,
      'report-header': null,
      'mobile-icon': null,
      'background': null,
      'watermark': null,
    });
    setEmailTemplates([]);
    setDomainConfig(null);
    setActiveStep(0);
    setSelectedConfig(null);
    setValidationResults(null);
  };

  const getStatusColor = (status: ConfigurationStatus) => {
    switch (status) {
      case 'active': return 'success';
      case 'approved': return 'info';
      case 'review': return 'warning';
      case 'draft': return 'default';
      case 'archived': return 'secondary';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: ConfigurationStatus, isActive: boolean) => {
    if (isActive) return <CheckIcon color="success" />;
    switch (status) {
      case 'approved': return <CheckIcon color="info" />;
      case 'review': return <WarningIcon color="warning" />;
      case 'draft': return <EditIcon color="action" />;
      default: return <ErrorIcon color="disabled" />;
    }
  };

  const renderConfigurationCard = (config: WhiteLabelConfiguration) => (
    <Grid item xs={12} md={6} lg={4} key={config.id}>
      <Card 
        sx={{ 
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          border: config.isActive ? 2 : 1,
          borderColor: config.isActive ? 'success.main' : 'divider',
        }}
      >
        <CardContent sx={{ flexGrow: 1 }}>
          <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
            <Box>
              <Typography variant="h6" component="h2" gutterBottom>
                {config.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {config.description}
              </Typography>
            </Box>
            <Box display="flex" alignItems="center" gap={1}>
              {getStatusIcon(config.status, config.isActive)}
              <IconButton
                size="small"
                onClick={(e) => {
                  setSelectedConfig(config);
                  setAnchorEl(e.currentTarget);
                }}
              >
                <MoreIcon />
              </IconButton>
            </Box>
          </Box>
          
          <Box display="flex" gap={1} mb={2}>
            <Chip 
              label={config.status} 
              color={getStatusColor(config.status) as any}
              size="small"
            />
            {config.isActive && (
              <Chip label="Active" color="success" size="small" />
            )}
          </Box>
          
          <Typography variant="caption" color="text.secondary" display="block">
            Version: {config.version}
          </Typography>
          <Typography variant="caption" color="text.secondary" display="block">
            Updated: {config.updatedAt.toLocaleDateString()}
          </Typography>
          <Typography variant="caption" color="text.secondary" display="block">
            By: {config.updatedBy}
          </Typography>
        </CardContent>
        
        <CardActions sx={{ justifyContent: 'space-between', p: 2 }}>
          <Box display="flex" gap={1}>
            <Tooltip title="Preview">
              <IconButton
                size="small"
                color="primary"
                onClick={() => handlePreviewConfiguration(config)}
              >
                <PreviewIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Edit">
              <IconButton
                size="small"
                onClick={() => {
                  setSelectedConfig(config);
                  setConfigForm({
                    name: config.name,
                    description: config.description,
                    status: config.status,
                  });
                  setThemeConfig(config.theme);
                  setEmailTemplates(config.emailTemplates);
                  setDomainConfig(config.domain || null);
                  setEditDialog(true);
                }}
              >
                <EditIcon />
              </IconButton>
            </Tooltip>
          </Box>
          
          {config.status === 'approved' && !config.isActive && (
            <Button
              variant="contained"
              size="small"
              startIcon={<DeployIcon />}
              onClick={() => handleDeployConfiguration(config)}
            >
              Deploy
            </Button>
          )}
        </CardActions>
      </Card>
    </Grid>
  );

  const renderConfigurationWizard = () => (
    <Box>
      <Stepper activeStep={activeStep} orientation="vertical">
        {configurationSteps.map((step, index) => (
          <Step key={step.label}>
            <StepLabel icon={step.icon}>
              {step.label}
            </StepLabel>
            <StepContent>
              {index === 0 && (
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Configuration Name"
                      value={configForm.name}
                      onChange={(e) => setConfigForm({ ...configForm, name: e.target.value })}
                      placeholder="My Custom Brand"
                      required
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      multiline
                      rows={3}
                      label="Description"
                      value={configForm.description}
                      onChange={(e) => setConfigForm({ ...configForm, description: e.target.value })}
                      placeholder="Describe this white-label configuration..."
                    />
                  </Grid>
                </Grid>
              )}
              
              {index === 1 && (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Theme Configuration
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Configure colors, typography, and visual styling for your white-label theme.
                  </Alert>
                  {/* Theme configuration components would go here */}
                  <Button variant="outlined" startIcon={<ThemeIcon />}>
                    Open Theme Editor
                  </Button>
                </Box>
              )}
              
              {index === 2 && (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Brand Assets
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Upload and manage brand assets like logos, icons, and images.
                  </Alert>
                  <Grid container spacing={2}>
                    {(['logo-primary', 'logo-secondary', 'favicon'] as AssetType[]).map(assetType => (
                      <Grid item xs={12} md={4} key={assetType}>
                        <Card variant="outlined">
                          <CardContent>
                            <Typography variant="subtitle1" gutterBottom>
                              {assetType.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </Typography>
                            {selectedAssets[assetType] ? (
                              <Box>
                                <img 
                                  src={selectedAssets[assetType]?.url} 
                                  alt={assetType}
                                  style={{ maxWidth: '100%', maxHeight: 100 }}
                                />
                                <Typography variant="caption" display="block">
                                  {selectedAssets[assetType]?.name}
                                </Typography>
                              </Box>
                            ) : (
                              <Box 
                                sx={{ 
                                  height: 100, 
                                  display: 'flex', 
                                  alignItems: 'center', 
                                  justifyContent: 'center',
                                  border: '2px dashed #ccc',
                                  borderRadius: 1,
                                }}
                              >
                                <Typography variant="caption" color="text.secondary">
                                  No asset uploaded
                                </Typography>
                              </Box>
                            )}
                            <Button
                              fullWidth
                              variant="outlined"
                              size="small"
                              sx={{ mt: 1 }}
                              startIcon={<CloudUpload />}
                            >
                              Upload
                            </Button>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              )}
              
              {index === 3 && (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Content Customization
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Customize text content, terminology, and legal documents.
                  </Alert>
                  <Button variant="outlined" startIcon={<ContentIcon />}>
                    Open Content Editor
                  </Button>
                </Box>
              )}
              
              {index === 4 && (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Domain & Email Configuration
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Configure custom domains and email templates.
                  </Alert>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Button 
                        fullWidth
                        variant="outlined" 
                        startIcon={<DomainIcon />}
                        sx={{ height: 100 }}
                      >
                        Configure Domain
                      </Button>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Button 
                        fullWidth
                        variant="outlined" 
                        startIcon={<EmailIcon />}
                        sx={{ height: 100 }}
                      >
                        Manage Email Templates
                      </Button>
                    </Grid>
                  </Grid>
                </Box>
              )}
              
              {index === 5 && (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Review & Deploy
                  </Typography>
                  
                  {validationResults && (
                    <Box mb={2}>
                      <Alert 
                        severity={validationResults.isValid ? 'success' : 'error'}
                        sx={{ mb: 1 }}
                      >
                        {validationResults.isValid ? 
                          'Configuration is valid and ready to deploy' : 
                          'Configuration has validation errors'
                        }
                      </Alert>
                      
                      {validationResults.errors.length > 0 && (
                        <Alert severity="error" sx={{ mb: 1 }}>
                          <Typography variant="subtitle2">Errors:</Typography>
                          <ul style={{ margin: 0, paddingLeft: 20 }}>
                            {validationResults.errors.map((error: string, idx: number) => (
                              <li key={idx}>{error}</li>
                            ))}
                          </ul>
                        </Alert>
                      )}
                      
                      {validationResults.warnings.length > 0 && (
                        <Alert severity="warning">
                          <Typography variant="subtitle2">Warnings:</Typography>
                          <ul style={{ margin: 0, paddingLeft: 20 }}>
                            {validationResults.warnings.map((warning: string, idx: number) => (
                              <li key={idx}>{warning}</li>
                            ))}
                          </ul>
                        </Alert>
                      )}
                    </Box>
                  )}
                  
                  <Box display="flex" gap={2}>
                    <Button 
                      variant="outlined"
                      startIcon={<CheckIcon />}
                      onClick={() => {
                        if (selectedConfig) {
                          handleValidateConfiguration(selectedConfig);
                        }
                      }}
                    >
                      Validate Configuration
                    </Button>
                    <Button
                      variant="contained"
                      startIcon={<DeployIcon />}
                      disabled={validationResults && !validationResults.isValid}
                    >
                      Deploy to Production
                    </Button>
                  </Box>
                </Box>
              )}
              
              <Box sx={{ mb: 1, mt: 2 }}>
                <div>
                  <Button
                    disabled={index === 0}
                    onClick={() => setActiveStep(activeStep - 1)}
                    sx={{ mt: 1, mr: 1 }}
                  >
                    Back
                  </Button>
                  <Button
                    variant="contained"
                    onClick={() => {
                      if (index === configurationSteps.length - 1) {
                        // Final step - create/update configuration
                        if (selectedConfig) {
                          handleUpdateConfiguration();
                        } else {
                          handleCreateConfiguration();
                        }
                      } else {
                        setActiveStep(activeStep + 1);
                      }
                    }}
                    sx={{ mt: 1, mr: 1 }}
                    disabled={index === 0 && !configForm.name}
                  >
                    {index === configurationSteps.length - 1 ? 
                      (selectedConfig ? 'Update Configuration' : 'Create Configuration') : 
                      'Continue'
                    }
                  </Button>
                </div>
              </Box>
            </StepContent>
          </Step>
        ))}
      </Stepper>
    </Box>
  );

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" gutterBottom>
            White-Label Configuration Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Create and manage white-label configurations for your platform.
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialog(true)}
        >
          New Configuration
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)} sx={{ mb: 3 }}>
        <Tab label="All Configurations" />
        <Tab label="Active Configurations" />
        <Tab label="Draft Configurations" />
      </Tabs>

      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          {configurations.map(config => renderConfigurationCard(config))}
          {configurations.length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 6 }}>
                  <SettingsIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No Configurations Found
                  </Typography>
                  <Typography variant="body2" color="text.secondary" mb={3}>
                    Create your first white-label configuration to get started.
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => setCreateDialog(true)}
                  >
                    Create Configuration
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          {configurations
            .filter(config => config.isActive)
            .map(config => renderConfigurationCard(config))
          }
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          {configurations
            .filter(config => config.status === 'draft')
            .map(config => renderConfigurationCard(config))
          }
        </Grid>
      </TabPanel>

      {/* Create Configuration Dialog */}
      <Dialog open={createDialog} onClose={() => setCreateDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Create New Configuration</DialogTitle>
        <DialogContent>
          {renderConfigurationWizard()}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setCreateDialog(false); resetForm(); }}>
            Cancel
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Configuration Dialog */}
      <Dialog open={editDialog} onClose={() => setEditDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Edit Configuration</DialogTitle>
        <DialogContent>
          {renderConfigurationWizard()}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setEditDialog(false); resetForm(); }}>
            Cancel
          </Button>
        </DialogActions>
      </Dialog>

      {/* Deploy Progress Dialog */}
      <Dialog open={deployDialog} onClose={() => {}} disableEscapeKeyDown>
        <DialogTitle>Deploying Configuration</DialogTitle>
        <DialogContent>
          <Box sx={{ width: '100%', mt: 2 }}>
            <LinearProgress variant="determinate" value={deployProgress} />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {deployProgress}% complete
            </Typography>
          </Box>
        </DialogContent>
      </Dialog>

      {/* Configuration Actions Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItemComponent onClick={() => {
          if (selectedConfig) handlePreviewConfiguration(selectedConfig);
          setAnchorEl(null);
        }}>
          <ListItemIcon><LaunchIcon /></ListItemIcon>
          <ListItemText>Preview</ListItemText>
        </MenuItemComponent>
        <MenuItemComponent onClick={() => {
          if (selectedConfig) handleExportConfiguration(selectedConfig);
          setAnchorEl(null);
        }}>
          <ListItemIcon><ExportIcon /></ListItemIcon>
          <ListItemText>Export</ListItemText>
        </MenuItemComponent>
        <MenuItemComponent onClick={() => {
          setDeleteDialog(true);
          setAnchorEl(null);
        }}>
          <ListItemIcon><DeleteIcon /></ListItemIcon>
          <ListItemText>Delete</ListItemText>
        </MenuItemComponent>
      </Menu>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialog} onClose={() => setDeleteDialog(false)}>
        <DialogTitle>Delete Configuration</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete "{selectedConfig?.name}"? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialog(false)}>Cancel</Button>
          <Button 
            color="error" 
            variant="contained"
            onClick={() => {
              if (selectedConfig) handleDeleteConfiguration(selectedConfig);
            }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Floating Action Button for Quick Actions */}
      <Fab
        color="primary"
        sx={{ position: 'fixed', bottom: 16, right: 16 }}
        onClick={() => setCreateDialog(true)}
      >
        <AddIcon />
      </Fab>
    </Box>
  );
}