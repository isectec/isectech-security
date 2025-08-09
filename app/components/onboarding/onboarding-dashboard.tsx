/**
 * Customer Onboarding Dashboard Component
 * Production-grade dashboard for managing automated customer onboarding
 */

'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  IconButton,
  Avatar,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  Tabs,
  Tab,
  Alert,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  useTheme,
  useMediaQuery,
  Divider,
  Stack,
  Paper,
} from '@mui/material';
import {
  Add as AddIcon,
  Business as BusinessIcon,
  CheckCircle as CompletedIcon,
  Error as ErrorIcon,
  Schedule as PendingIcon,
  Analytics as AnalyticsIcon,
  Refresh as RefreshIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  Cancel as CancelIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  Assignment as TaskIcon,
} from '@mui/icons-material';
import { format, formatDistanceToNow, isAfter, isBefore } from 'date-fns';
import type { 
  OnboardingInstance,
  OnboardingAnalytics,
  OnboardingDashboardData,
  CustomerType,
  ServiceTier 
} from '@/types/onboarding';
import { onboardingService } from '@/lib/api/services/onboarding';
import { useStores } from '@/lib/store';

interface OnboardingDashboardProps {
  className?: string;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`onboarding-tabpanel-${index}`}
      aria-labelledby={`onboarding-tab-${index}`}
    >
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

const statusColors = {
  'not-started': '#9e9e9e',
  'in-progress': '#2196f3',
  'pending-approval': '#ff9800',
  'completed': '#4caf50',
  'failed': '#f44336',
  'cancelled': '#9e9e9e',
};

const statusIcons = {
  'not-started': PendingIcon,
  'in-progress': TimelineIcon,
  'pending-approval': WarningIcon,
  'completed': CompletedIcon,
  'failed': ErrorIcon,
  'cancelled': CancelIcon,
};

const customerTypeLabels: Record<CustomerType, string> = {
  'enterprise': 'Enterprise',
  'mid-market': 'Mid-Market',
  'small-business': 'Small Business',
  'individual': 'Individual',
};

const serviceTierLabels: Record<ServiceTier, string> = {
  'basic': 'Basic',
  'professional': 'Professional',
  'enterprise': 'Enterprise',
  'enterprise-plus': 'Enterprise Plus',
};

export function OnboardingDashboard({ className }: OnboardingDashboardProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { app } = useStores();

  // State
  const [tabValue, setTabValue] = useState(0);
  const [dashboardData, setDashboardData] = useState<OnboardingDashboardData | null>(null);
  const [analytics, setAnalytics] = useState<OnboardingAnalytics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<OnboardingInstance | null>(null);
  const [flowDetailsOpen, setFlowDetailsOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  // Load dashboard data
  const loadDashboardData = async () => {
    try {
      setError(null);
      const data = await onboardingService.getOnboardingDashboardData({
        limit: 10,
        includePending: true,
        includeAnalytics: true,
      });
      setDashboardData(data);
      setAnalytics(data.analytics || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
      console.error('Error loading onboarding dashboard:', err);
    }
  };

  useEffect(() => {
    loadDashboardData().finally(() => setLoading(false));
  }, []);

  // Handlers
  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
    app.showSuccess('Dashboard refreshed');
  };

  const handleViewFlow = (flow: OnboardingInstance) => {
    setSelectedFlow(flow);
    setFlowDetailsOpen(true);
  };

  const handleRetryStep = async (flowId: string, stepId: string) => {
    try {
      await onboardingService.retryOnboardingStep(flowId, stepId);
      app.showSuccess('Step retry initiated');
      await loadDashboardData();
    } catch (err) {
      app.showError('Failed to retry step');
      console.error('Error retrying step:', err);
    }
  };

  const handleCancelFlow = async (flowId: string) => {
    try {
      await onboardingService.cancelOnboardingFlow(flowId);
      app.showSuccess('Onboarding cancelled');
      await loadDashboardData();
      setFlowDetailsOpen(false);
    } catch (err) {
      app.showError('Failed to cancel onboarding');
      console.error('Error cancelling flow:', err);
    }
  };

  // Computed values
  const summaryCards = useMemo(() => {
    if (!analytics) return [];

    return [
      {
        title: 'Active Onboardings',
        value: dashboardData?.activeFlows.length || 0,
        subtitle: 'In progress',
        color: theme.palette.info.main,
        icon: TimelineIcon,
      },
      {
        title: 'Completion Rate',
        value: `${analytics.completionRate}%`,
        subtitle: 'Last 30 days',
        color: theme.palette.success.main,
        icon: TrendingUpIcon,
      },
      {
        title: 'Avg. Duration',
        value: `${Math.round(analytics.averageCompletionTime / 60 * 10) / 10}h`,
        subtitle: 'Hours to complete',
        color: theme.palette.primary.main,
        icon: AnalyticsIcon,
      },
      {
        title: 'Open Alerts',
        value: dashboardData?.alerts.length || 0,
        subtitle: 'Require attention',
        color: theme.palette.warning.main,
        icon: WarningIcon,
      },
    ];
  }, [analytics, dashboardData, theme]);

  const OnboardingFlowCard = ({ flow }: { flow: OnboardingInstance }) => {
    const StatusIcon = statusIcons[flow.status];
    const customerProfile = flow.customData?.customerProfile;
    const timeAgo = flow.startedAt ? formatDistanceToNow(flow.startedAt, { addSuffix: true }) : '';

    return (
      <Card sx={{ mb: 2, cursor: 'pointer', '&:hover': { boxShadow: theme.shadows[4] } }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Avatar sx={{ bgcolor: statusColors[flow.status], mr: 2 }}>
              <StatusIcon />
            </Avatar>
            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
              <Typography variant="h6" noWrap>
                {customerProfile?.companyName || 'Unknown Company'}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {customerProfile ? customerTypeLabels[customerProfile.customerType] : ''} • 
                {customerProfile ? serviceTierLabels[customerProfile.serviceTier] : ''} • 
                {timeAgo}
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Chip
                label={flow.status.replace('-', ' ')}
                size="small"
                sx={{
                  bgcolor: statusColors[flow.status] + '20',
                  color: statusColors[flow.status],
                  fontWeight: 600,
                }}
              />
              <IconButton size="small" onClick={() => handleViewFlow(flow)}>
                <ViewIcon />
              </IconButton>
            </Box>
          </Box>

          <Box sx={{ mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="body2" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="body2" fontWeight={600}>
                {flow.progress.percentComplete}% ({flow.progress.completedSteps}/{flow.progress.totalSteps} steps)
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={flow.progress.percentComplete}
              sx={{
                height: 8,
                borderRadius: 4,
                backgroundColor: theme.palette.grey[200],
                '& .MuiLinearProgress-bar': {
                  backgroundColor: flow.status === 'failed' ? theme.palette.error.main :
                                 flow.status === 'completed' ? theme.palette.success.main :
                                 theme.palette.primary.main,
                },
              }}
            />
          </Box>

          {flow.currentStep && (
            <Typography variant="body2" color="text.secondary">
              Current: {flow.currentStep.replace('-', ' ')}
            </Typography>
          )}

          {flow.errors.length > 0 && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {flow.errors[0].message}
            </Alert>
          )}
        </CardContent>
      </Card>
    );
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h4" sx={{ mb: 3 }}>Customer Onboarding</Typography>
        <Grid container spacing={3}>
          {[1, 2, 3, 4].map((i) => (
            <Grid item xs={12} sm={6} md={3} key={i}>
              <Card>
                <CardContent sx={{ height: 120 }}>
                  <LinearProgress />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
        <Button variant="contained" onClick={loadDashboardData}>
          Retry
        </Button>
      </Box>
    );
  }

  return (
    <Box className={className} sx={{ p: { xs: 2, md: 3 } }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
            Customer Onboarding
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Manage automated customer onboarding workflows and track progress
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={handleRefresh}
            disabled={refreshing}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => {/* Navigate to create onboarding */}}
          >
            New Onboarding
          </Button>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {summaryCards.map((card, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="overline">
                      {card.title}
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, color: card.color }}>
                      {card.value}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {card.subtitle}
                    </Typography>
                  </Box>
                  <Avatar sx={{ bgcolor: card.color + '20', color: card.color, width: 56, height: 56 }}>
                    <card.icon sx={{ fontSize: 32 }} />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label={`Active Flows (${dashboardData?.activeFlows.length || 0})`} />
          <Tab label={`Recent Completions (${dashboardData?.recentCompletions.length || 0})`} />
          <Tab label={`Alerts (${dashboardData?.alerts.length || 0})`} />
          <Tab label="Analytics" />
        </Tabs>
      </Box>

      {/* Tab Content */}
      <TabPanel value={tabValue} index={0}>
        {dashboardData?.activeFlows.length === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <BusinessIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No Active Onboardings
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              All customer onboardings are completed or there are no onboardings in progress.
            </Typography>
            <Button variant="contained" startIcon={<AddIcon />}>
              Start New Onboarding
            </Button>
          </Paper>
        ) : (
          <Box>
            {dashboardData?.activeFlows.map((flow) => (
              <OnboardingFlowCard key={flow.id} flow={flow} />
            ))}
          </Box>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        {dashboardData?.recentCompletions.length === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <CompletedIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              No Recent Completions
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Completed onboardings will appear here.
            </Typography>
          </Paper>
        ) : (
          <Box>
            {dashboardData?.recentCompletions.map((flow) => (
              <OnboardingFlowCard key={flow.id} flow={flow} />
            ))}
          </Box>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        {dashboardData?.alerts.length === 0 ? (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <CheckCircle sx={{ fontSize: 64, color: 'success.main', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              No Active Alerts
            </Typography>
            <Typography variant="body2" color="text.secondary">
              All onboarding workflows are running smoothly.
            </Typography>
          </Paper>
        ) : (
          <List>
            {dashboardData?.alerts.map((alert) => (
              <ListItem key={alert.id}>
                <ListItemIcon>
                  <Avatar
                    sx={{
                      bgcolor: alert.severity === 'critical' ? 'error.main' :
                              alert.severity === 'high' ? 'warning.main' :
                              'info.main',
                      width: 40,
                      height: 40,
                    }}
                  >
                    <WarningIcon />
                  </Avatar>
                </ListItemIcon>
                <ListItemText
                  primary={alert.title}
                  secondary={
                    <Stack spacing={0.5}>
                      <Typography variant="body2">{alert.description}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {format(alert.createdAt, 'MMM d, yyyy h:mm a')}
                      </Typography>
                    </Stack>
                  }
                />
                <ListItemSecondaryAction>
                  <Chip
                    label={alert.severity}
                    size="small"
                    color={
                      alert.severity === 'critical' ? 'error' :
                      alert.severity === 'high' ? 'warning' :
                      'default'
                    }
                  />
                </ListItemSecondaryAction>
              </ListItem>
            ))}
          </List>
        )}
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        {analytics ? (
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Completion Rates by Customer Type
                  </Typography>
                  {Object.entries(analytics.byCustomerType).map(([type, data]) => (
                    <Box key={type} sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                        <Typography variant="body2">
                          {customerTypeLabels[type as CustomerType]}
                        </Typography>
                        <Typography variant="body2" fontWeight={600}>
                          {data.completionRate}%
                        </Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={data.completionRate}
                        sx={{ height: 6, borderRadius: 3 }}
                      />
                    </Box>
                  ))}
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Step Performance
                  </Typography>
                  {analytics.stepAnalytics.slice(0, 5).map((step) => (
                    <Box key={step.stepType} sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                        <Typography variant="body2" noWrap>
                          {step.stepType.replace(/[-_]/g, ' ')}
                        </Typography>
                        <Typography variant="body2" fontWeight={600}>
                          {step.completionRate}%
                        </Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={step.completionRate}
                        sx={{ height: 6, borderRadius: 3 }}
                      />
                    </Box>
                  ))}
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        ) : (
          <Paper sx={{ p: 4, textAlign: 'center' }}>
            <AnalyticsIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              Analytics Loading...
            </Typography>
          </Paper>
        )}
      </TabPanel>

      {/* Flow Details Dialog */}
      <Dialog
        open={flowDetailsOpen}
        onClose={() => setFlowDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        {selectedFlow && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <BusinessIcon />
                <Box>
                  <Typography variant="h6">
                    {selectedFlow.customData?.customerProfile?.companyName || 'Onboarding Details'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {selectedFlow.id}
                  </Typography>
                </Box>
              </Box>
            </DialogTitle>
            <DialogContent>
              <Box sx={{ mb: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Progress: {selectedFlow.progress.percentComplete}%
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={selectedFlow.progress.percentComplete}
                  sx={{ height: 8, borderRadius: 4, mb: 2 }}
                />
                <Typography variant="body2" color="text.secondary">
                  {selectedFlow.progress.completedSteps} of {selectedFlow.progress.totalSteps} steps completed
                </Typography>
              </Box>

              <Typography variant="subtitle2" gutterBottom>
                Steps
              </Typography>
              <List dense>
                {selectedFlow.stepInstances.map((step) => {
                  const StepIcon = statusIcons[step.status];
                  return (
                    <ListItem key={step.id}>
                      <ListItemIcon>
                        <StepIcon
                          sx={{
                            color: statusColors[step.status],
                          }}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={step.stepId.replace(/[-_]/g, ' ')}
                        secondary={
                          step.completedAt ? 
                            `Completed ${format(step.completedAt, 'MMM d, h:mm a')}` :
                            `Status: ${step.status.replace('-', ' ')}`
                        }
                      />
                      {step.status === 'failed' && (
                        <ListItemSecondaryAction>
                          <Button
                            size="small"
                            onClick={() => handleRetryStep(selectedFlow.id, step.stepId)}
                          >
                            Retry
                          </Button>
                        </ListItemSecondaryAction>
                      )}
                    </ListItem>
                  );
                })}
              </List>
            </DialogContent>
            <DialogActions>
              {selectedFlow.status !== 'completed' && selectedFlow.status !== 'cancelled' && (
                <Button
                  color="error"
                  onClick={() => handleCancelFlow(selectedFlow.id)}
                >
                  Cancel Onboarding
                </Button>
              )}
              <Button onClick={() => setFlowDetailsOpen(false)}>
                Close
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
}