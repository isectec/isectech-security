'use client';

/**
 * Developer Portal Main Interface
 * Production-grade developer experience for iSECTECH Marketplace
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Card,
  CardContent,
  CardActions,
  Grid,
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
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  Tooltip,
  Switch,
  FormControlLabel,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Avatar,
  AppBar,
  Toolbar,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Apps as AppsIcon,
  Code as CodeIcon,
  Security as SecurityIcon,
  Analytics as AnalyticsIcon,
  Settings as SettingsIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Upload as UploadIcon,
  Download as DownloadIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  Key as KeyIcon,
  Description as DocsIcon,
  Support as SupportIcon,
  TrendingUp as TrendingIcon,
  Timeline as TimelineIcon,
  Assessment as ReportsIcon,
  CloudUpload as PublishIcon,
  Verified as VerifiedIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';

import { developerAuthService } from '../lib/developer-auth';
import { appSubmissionWorkflow } from '../lib/app-submission-workflow';
import type {
  DeveloperAccount,
  DeveloperApiKey,
  DeveloperPermission,
} from '../lib/developer-auth';
import type {
  MarketplaceApp,
  AppCategory,
  AppStatus,
  AppSubmissionRequest,
} from '../lib/app-submission-workflow';

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

export default function DeveloperPortal() {
  const [tabValue, setTabValue] = useState(0);
  const [developerAccount, setDeveloperAccount] = useState<DeveloperAccount | null>(null);
  const [developerApps, setDeveloperApps] = useState<MarketplaceApp[]>([]);
  const [apiKeys, setApiKeys] = useState<DeveloperApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dialog states
  const [newAppDialog, setNewAppDialog] = useState(false);
  const [apiKeyDialog, setApiKeyDialog] = useState(false);
  const [appDetailsDialog, setAppDetailsDialog] = useState(false);
  const [docDialog, setDocDialog] = useState(false);

  // Form states
  const [appForm, setAppForm] = useState<Partial<AppSubmissionRequest>>({});
  const [apiKeyForm, setApiKeyForm] = useState({
    name: '',
    environment: 'SANDBOX' as 'SANDBOX' | 'PRODUCTION',
    permissions: [] as DeveloperPermission[],
    expirationDays: 365,
  });

  // Selected items
  const [selectedApp, setSelectedApp] = useState<MarketplaceApp | null>(null);
  const [selectedApiKey, setSelectedApiKey] = useState<DeveloperApiKey | null>(null);

  // Mock developer account - would come from authentication
  const mockDeveloper: DeveloperAccount = {
    id: 'dev_12345',
    email: 'developer@securitycorp.com',
    organizationName: 'SecurityCorp Solutions',
    organizationId: 'org_67890',
    developerLevel: 'ORGANIZATION',
    verificationStatus: 'VERIFIED',
    createdAt: new Date('2024-01-15'),
    lastLoginAt: new Date(),
    apiKeyCount: 3,
    appCount: 5,
    totalDownloads: 15420,
    rating: 4.6,
    isActive: true,
    subscriptionTier: 'PROFESSIONAL',
    complianceCertifications: ['ISO27001', 'SOC2'],
    securityClearanceLevel: 'RESTRICTED',
  };

  const appCategories: { value: AppCategory; label: string }[] = [
    { value: 'SECURITY_INTEGRATIONS', label: 'Security Integrations' },
    { value: 'VISUALIZATION_WIDGETS', label: 'Visualization Widgets' },
    { value: 'CUSTOM_REPORTS', label: 'Custom Reports' },
    { value: 'AUTOMATION_PLAYBOOKS', label: 'Automation Playbooks' },
    { value: 'INDUSTRY_SOLUTIONS', label: 'Industry Solutions' },
    { value: 'COMPLIANCE_TEMPLATES', label: 'Compliance Templates' },
    { value: 'THREAT_INTELLIGENCE', label: 'Threat Intelligence' },
    { value: 'INCIDENT_RESPONSE', label: 'Incident Response' },
    { value: 'VULNERABILITY_MANAGEMENT', label: 'Vulnerability Management' },
    { value: 'ASSET_MANAGEMENT', label: 'Asset Management' },
  ];

  useEffect(() => {
    loadDeveloperData();
  }, []);

  const loadDeveloperData = async () => {
    try {
      setLoading(true);
      
      // Set mock data - in production, would fetch from APIs
      setDeveloperAccount(mockDeveloper);
      
      // Load developer's apps
      setDeveloperApps([
        {
          id: 'app_1',
          developerId: mockDeveloper.id,
          name: 'threat-intel-connector',
          displayName: 'Threat Intelligence Connector',
          description: 'Advanced threat intelligence integration for real-time security analysis',
          detailedDescription: 'Comprehensive threat intelligence platform integration that provides real-time threat data correlation and analysis capabilities.',
          category: 'THREAT_INTELLIGENCE',
          subCategory: 'Data Connectors',
          version: '2.1.0',
          status: 'PUBLISHED',
          visibilityLevel: 'RESTRICTED',
          securityClassification: 'RESTRICTED',
          logo: '/api/assets/app-logos/threat-intel-connector.png',
          screenshots: [],
          documentation: {} as any,
          architecture: {
            type: 'MICROSERVICE',
            runtime: 'DOCKER',
            deploymentModel: 'CLOUD',
            scalingRequirements: { minInstances: 2, maxInstances: 10, autoScale: true },
            resourceRequirements: { cpu: '500m', memory: '1Gi', storage: '10Gi', network: true },
          },
          dependencies: [],
          systemRequirements: {} as any,
          integrationPoints: [],
          securityReview: {
            status: 'PASSED',
            overallScore: 95,
            findings: [],
            recommendations: [],
            complianceGaps: [],
            riskAssessment: {} as any,
          },
          complianceCertifications: [],
          dataHandling: {} as any,
          pricing: { model: 'SUBSCRIPTION', enterpriseContactRequired: false },
          licensing: {} as any,
          supportInfo: {} as any,
          downloadCount: 8420,
          activeInstallations: 156,
          averageRating: 4.8,
          reviewCount: 23,
          submittedAt: new Date('2024-02-01'),
          approvedAt: new Date('2024-02-15'),
          publishedAt: new Date('2024-02-16'),
          lastUpdatedAt: new Date('2024-07-20'),
          reviewHistory: [],
          createdAt: new Date('2024-01-28'),
          updatedAt: new Date('2024-07-20'),
        },
        {
          id: 'app_2',
          developerId: mockDeveloper.id,
          name: 'security-dashboard-widget',
          displayName: 'Executive Security Dashboard',
          description: 'Executive-level security metrics and KPI visualization widget',
          detailedDescription: 'Customizable dashboard widget for executives to monitor security posture and key performance indicators.',
          category: 'VISUALIZATION_WIDGETS',
          subCategory: 'Executive Dashboards',
          version: '1.5.2',
          status: 'UNDER_REVIEW',
          visibilityLevel: 'PUBLIC',
          securityClassification: 'PUBLIC',
          logo: '/api/assets/app-logos/security-dashboard.png',
          screenshots: [],
          documentation: {} as any,
          architecture: {
            type: 'WIDGET',
            runtime: 'BROWSER',
            deploymentModel: 'CLOUD',
            scalingRequirements: { minInstances: 1, maxInstances: 1, autoScale: false },
            resourceRequirements: { cpu: '100m', memory: '256Mi', storage: '1Gi', network: true },
          },
          dependencies: [],
          systemRequirements: {} as any,
          integrationPoints: [],
          securityReview: {
            status: 'IN_PROGRESS',
            overallScore: 0,
            findings: [],
            recommendations: [],
            complianceGaps: [],
            riskAssessment: {} as any,
          },
          complianceCertifications: [],
          dataHandling: {} as any,
          pricing: { model: 'FREE', enterpriseContactRequired: false },
          licensing: {} as any,
          supportInfo: {} as any,
          downloadCount: 0,
          activeInstallations: 0,
          averageRating: 0,
          reviewCount: 0,
          submittedAt: new Date('2024-07-28'),
          lastUpdatedAt: new Date('2024-07-28'),
          reviewHistory: [],
          createdAt: new Date('2024-07-25'),
          updatedAt: new Date('2024-07-28'),
        },
      ]);

      // Load API keys
      setApiKeys([
        {
          id: 'key_1',
          developerId: mockDeveloper.id,
          name: 'Production API Key',
          keyHash: 'hash123',
          permissions: [
            {
              scope: 'marketplace',
              actions: ['read', 'write'],
              resources: ['apps', 'analytics'],
            },
          ],
          rateLimit: { requestsPerMinute: 100, requestsPerHour: 5000, requestsPerDay: 50000 },
          ipWhitelist: [],
          isActive: true,
          createdAt: new Date('2024-03-01'),
          environment: 'PRODUCTION',
          lastUsedAt: new Date('2024-07-30'),
        },
        {
          id: 'key_2',
          developerId: mockDeveloper.id,
          name: 'Development Testing Key',
          keyHash: 'hash456',
          permissions: [
            {
              scope: 'marketplace',
              actions: ['read'],
              resources: ['apps'],
            },
          ],
          rateLimit: { requestsPerMinute: 500, requestsPerHour: 10000, requestsPerDay: 100000 },
          ipWhitelist: [],
          isActive: true,
          createdAt: new Date('2024-06-15'),
          environment: 'SANDBOX',
          lastUsedAt: new Date('2024-07-29'),
        },
      ]);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load developer data');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitApp = async () => {
    try {
      if (!appForm.appData) return;

      const app = await appSubmissionWorkflow.submitApp(mockDeveloper.id, appForm as AppSubmissionRequest);
      setDeveloperApps([...developerApps, app]);
      setNewAppDialog(false);
      setAppForm({});
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit app');
    }
  };

  const handleCreateApiKey = async () => {
    try {
      const { apiKey, plainKey } = await developerAuthService.generateApiKey(
        mockDeveloper.id,
        apiKeyForm.name,
        apiKeyForm.permissions,
        apiKeyForm.environment,
        undefined,
        apiKeyForm.expirationDays
      );

      setApiKeys([...apiKeys, apiKey]);
      setApiKeyDialog(false);
      setApiKeyForm({ name: '', environment: 'SANDBOX', permissions: [], expirationDays: 365 });

      // Show the generated key to user
      alert(`API Key Generated: ${plainKey}\n\nIMPORTANT: Save this key now, it won't be shown again!`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create API key');
    }
  };

  const getStatusColor = (status: AppStatus) => {
    switch (status) {
      case 'PUBLISHED': return 'success';
      case 'APPROVED': return 'success';
      case 'UNDER_REVIEW': return 'info';
      case 'SECURITY_REVIEW': return 'warning';
      case 'REJECTED': return 'error';
      case 'DRAFT': return 'default';
      default: return 'default';
    }
  };

  const renderDashboard = () => (
    <Grid container spacing={3}>
      {/* Account Overview */}
      <Grid item xs={12} md={8}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={2}>
              <Avatar sx={{ bgcolor: 'primary.main', mr: 2 }}>
                {developerAccount?.organizationName.charAt(0)}
              </Avatar>
              <Box>
                <Typography variant="h5">{developerAccount?.organizationName}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {developerAccount?.email} • {developerAccount?.developerLevel}
                </Typography>
              </Box>
              <Box ml="auto">
                <Chip
                  icon={<VerifiedIcon />}
                  label={developerAccount?.verificationStatus}
                  color={developerAccount?.verificationStatus === 'VERIFIED' ? 'success' : 'warning'}
                />
              </Box>
            </Box>
            
            <Grid container spacing={3}>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="primary">{developerAccount?.appCount}</Typography>
                  <Typography variant="body2" color="text.secondary">Apps Published</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="secondary">{developerAccount?.totalDownloads.toLocaleString()}</Typography>
                  <Typography variant="body2" color="text.secondary">Total Downloads</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="success.main">{developerAccount?.rating}</Typography>
                  <Typography variant="body2" color="text.secondary">Average Rating</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="info.main">{developerAccount?.apiKeyCount}</Typography>
                  <Typography variant="body2" color="text.secondary">API Keys</Typography>
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </Grid>

      {/* Quick Actions */}
      <Grid item xs={12} md={4}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>Quick Actions</Typography>
            <List>
              <ListItem button onClick={() => setNewAppDialog(true)}>
                <ListItemIcon><AddIcon /></ListItemIcon>
                <ListItemText primary="Submit New App" />
              </ListItem>
              <ListItem button onClick={() => setApiKeyDialog(true)}>
                <ListItemIcon><KeyIcon /></ListItemIcon>
                <ListItemText primary="Generate API Key" />
              </ListItem>
              <ListItem button onClick={() => setDocDialog(true)}>
                <ListItemIcon><DocsIcon /></ListItemIcon>
                <ListItemText primary="View Documentation" />
              </ListItem>
            </List>
          </CardContent>
        </Card>
      </Grid>

      {/* Recent Apps */}
      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>Recent Apps</Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>App Name</TableCell>
                    <TableCell>Category</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Downloads</TableCell>
                    <TableCell>Rating</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {developerApps.slice(0, 5).map((app) => (
                    <TableRow key={app.id}>
                      <TableCell>
                        <Box>
                          <Typography variant="subtitle2">{app.displayName}</Typography>
                          <Typography variant="caption" color="text.secondary">v{app.version}</Typography>
                        </Box>
                      </TableCell>
                      <TableCell>{app.category}</TableCell>
                      <TableCell>
                        <Chip
                          label={app.status}
                          color={getStatusColor(app.status) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>{app.downloadCount.toLocaleString()}</TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Typography variant="body2">{app.averageRating}</Typography>
                          <Typography variant="caption" color="text.secondary" ml={0.5}>
                            ({app.reviewCount})
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => {
                            setSelectedApp(app);
                            setAppDetailsDialog(true);
                          }}
                        >
                          <ViewIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderApps = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h5">My Apps</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setNewAppDialog(true)}
        >
          Submit New App
        </Button>
      </Box>

      <Grid container spacing={3}>
        {developerApps.map((app) => (
          <Grid item xs={12} md={6} lg={4} key={app.id}>
            <Card>
              <CardContent>
                <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
                  <Box>
                    <Typography variant="h6">{app.displayName}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      v{app.version}
                    </Typography>
                  </Box>
                  <Chip
                    label={app.status}
                    color={getStatusColor(app.status) as any}
                    size="small"
                  />
                </Box>

                <Typography variant="body2" paragraph>
                  {app.description}
                </Typography>

                <Box display="flex" justifyContent="space-between" mb={2}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Downloads</Typography>
                    <Typography variant="h6">{app.downloadCount.toLocaleString()}</Typography>
                  </Box>
                  <Box textAlign="center">
                    <Typography variant="caption" color="text.secondary">Rating</Typography>
                    <Typography variant="h6">{app.averageRating || 'N/A'}</Typography>
                  </Box>
                  <Box textAlign="right">
                    <Typography variant="caption" color="text.secondary">Reviews</Typography>
                    <Typography variant="h6">{app.reviewCount}</Typography>
                  </Box>
                </Box>

                <Chip
                  label={app.category}
                  variant="outlined"
                  size="small"
                  sx={{ mb: 1 }}
                />
              </CardContent>
              <CardActions>
                <Button
                  size="small"
                  startIcon={<ViewIcon />}
                  onClick={() => {
                    setSelectedApp(app);
                    setAppDetailsDialog(true);
                  }}
                >
                  Details
                </Button>
                <Button size="small" startIcon={<EditIcon />}>
                  Edit
                </Button>
                {app.status === 'PUBLISHED' && (
                  <Button size="small" startIcon={<AnalyticsIcon />}>
                    Analytics
                  </Button>
                )}
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );

  const renderApiKeys = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h5">API Keys</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setApiKeyDialog(true)}
        >
          Generate New Key
        </Button>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Environment</TableCell>
              <TableCell>Rate Limit</TableCell>
              <TableCell>Last Used</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {apiKeys.map((key) => (
              <TableRow key={key.id}>
                <TableCell>
                  <Box display="flex" alignItems="center">
                    <KeyIcon sx={{ mr: 1, color: key.isActive ? 'success.main' : 'text.disabled' }} />
                    {key.name}
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={key.environment}
                    color={key.environment === 'PRODUCTION' ? 'error' : 'info'}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {key.rateLimit.requestsPerMinute}/min
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {key.rateLimit.requestsPerDay.toLocaleString()}/day
                  </Typography>
                </TableCell>
                <TableCell>
                  {key.lastUsedAt ? key.lastUsedAt.toLocaleDateString() : 'Never'}
                </TableCell>
                <TableCell>{key.createdAt.toLocaleDateString()}</TableCell>
                <TableCell>
                  <IconButton size="small">
                    <EditIcon />
                  </IconButton>
                  <IconButton size="small" color="error">
                    <DeleteIcon />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
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
      {/* Header */}
      <AppBar position="static" color="default" elevation={1}>
        <Toolbar>
          <SecurityIcon sx={{ mr: 2 }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            iSECTECH Developer Portal
          </Typography>
          <Box display="flex" alignItems="center">
            <Typography variant="body2" sx={{ mr: 2 }}>
              {developerAccount?.organizationName}
            </Typography>
            <Avatar sx={{ bgcolor: 'primary.main' }}>
              {developerAccount?.organizationName.charAt(0)}
            </Avatar>
          </Box>
        </Toolbar>
      </AppBar>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ m: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Navigation Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs
          value={tabValue}
          onChange={(_, newValue) => setTabValue(newValue)}
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab icon={<DashboardIcon />} label="Dashboard" />
          <Tab icon={<AppsIcon />} label="My Apps" />
          <Tab icon={<KeyIcon />} label="API Keys" />
          <Tab icon={<AnalyticsIcon />} label="Analytics" />
          <Tab icon={<DocsIcon />} label="Documentation" />
          <Tab icon={<SupportIcon />} label="Support" />
          <Tab icon={<SettingsIcon />} label="Settings" />
        </Tabs>
      </Box>

      {/* Tab Panels */}
      <TabPanel value={tabValue} index={0}>
        {renderDashboard()}
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        {renderApps()}
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        {renderApiKeys()}
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        <Typography variant="h5" gutterBottom>Analytics Dashboard</Typography>
        <Alert severity="info">
          Analytics dashboard showing app performance, user engagement, and revenue metrics.
          Integration with comprehensive analytics service.
        </Alert>
      </TabPanel>

      <TabPanel value={tabValue} index={4}>
        <Typography variant="h5" gutterBottom>Developer Documentation</Typography>
        <Alert severity="info">
          Comprehensive API documentation, SDK guides, tutorials, and best practices.
        </Alert>
      </TabPanel>

      <TabPanel value={tabValue} index={5}>
        <Typography variant="h5" gutterBottom>Developer Support</Typography>
        <Alert severity="info">
          Support ticket system, community forums, and direct contact with developer relations team.
        </Alert>
      </TabPanel>

      <TabPanel value={tabValue} index={6}>
        <Typography variant="h5" gutterBottom>Account Settings</Typography>
        <Alert severity="info">
          Account management, security settings, billing information, and notification preferences.
        </Alert>
      </TabPanel>

      {/* New App Dialog */}
      <Dialog open={newAppDialog} onClose={() => setNewAppDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Submit New App to Marketplace</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="App Name"
                value={appForm.appData?.name || ''}
                onChange={(e) => setAppForm({
                  ...appForm,
                  appData: { ...appForm.appData, name: e.target.value } as any
                })}
                placeholder="my-security-app"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Display Name"
                value={appForm.appData?.displayName || ''}
                onChange={(e) => setAppForm({
                  ...appForm,
                  appData: { ...appForm.appData, displayName: e.target.value } as any
                })}
                placeholder="My Security App"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={3}
                label="Description"
                value={appForm.appData?.description || ''}
                onChange={(e) => setAppForm({
                  ...appForm,
                  appData: { ...appForm.appData, description: e.target.value } as any
                })}
                placeholder="Describe your app's functionality and benefits..."
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Category</InputLabel>
                <Select
                  value={appForm.appData?.category || ''}
                  onChange={(e) => setAppForm({
                    ...appForm,
                    appData: { ...appForm.appData, category: e.target.value as AppCategory } as any
                  })}
                  label="Category"
                >
                  {appCategories.map(category => (
                    <MenuItem key={category.value} value={category.value}>
                      {category.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Version"
                value={appForm.appData?.version || ''}
                onChange={(e) => setAppForm({
                  ...appForm,
                  appData: { ...appForm.appData, version: e.target.value } as any
                })}
                placeholder="1.0.0"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewAppDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSubmitApp}
            disabled={!appForm.appData?.name || !appForm.appData?.displayName}
          >
            Submit for Review
          </Button>
        </DialogActions>
      </Dialog>

      {/* API Key Dialog */}
      <Dialog open={apiKeyDialog} onClose={() => setApiKeyDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Generate New API Key</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Key Name"
                value={apiKeyForm.name}
                onChange={(e) => setApiKeyForm({ ...apiKeyForm, name: e.target.value })}
                placeholder="Production Key"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Environment</InputLabel>
                <Select
                  value={apiKeyForm.environment}
                  onChange={(e) => setApiKeyForm({ ...apiKeyForm, environment: e.target.value as any })}
                  label="Environment"
                >
                  <MenuItem value="SANDBOX">Sandbox</MenuItem>
                  <MenuItem value="PRODUCTION">Production</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                type="number"
                label="Expiration (days)"
                value={apiKeyForm.expirationDays}
                onChange={(e) => setApiKeyForm({ ...apiKeyForm, expirationDays: parseInt(e.target.value) })}
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApiKeyDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleCreateApiKey}
            disabled={!apiKeyForm.name}
          >
            Generate Key
          </Button>
        </DialogActions>
      </Dialog>

      {/* App Details Dialog */}
      <Dialog open={appDetailsDialog} onClose={() => setAppDetailsDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>App Details</DialogTitle>
        <DialogContent>
          {selectedApp && (
            <Grid container spacing={2}>
              <Grid item xs={12} md={8}>
                <Typography variant="h6" gutterBottom>{selectedApp.displayName}</Typography>
                <Typography variant="body2" paragraph>{selectedApp.description}</Typography>
                <Typography variant="subtitle2" gutterBottom>Status</Typography>
                <Chip label={selectedApp.status} color={getStatusColor(selectedApp.status) as any} />
              </Grid>
              <Grid item xs={12} md={4}>
                <Typography variant="subtitle2" gutterBottom>Metrics</Typography>
                <List dense>
                  <ListItem>
                    <ListItemText
                      primary="Downloads"
                      secondary={selectedApp.downloadCount.toLocaleString()}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Active Installations"
                      secondary={selectedApp.activeInstallations.toLocaleString()}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Average Rating"
                      secondary={`${selectedApp.averageRating} (${selectedApp.reviewCount} reviews)`}
                    />
                  </ListItem>
                </List>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAppDetailsDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}