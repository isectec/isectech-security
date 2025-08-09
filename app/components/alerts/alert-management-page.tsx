/**
 * Alert Management Page for iSECTECH Protect
 * Comprehensive intelligent alert management interface
 */

'use client';

import type { AlertFilters as AlertFiltersType } from '@/lib/api/services/alerts';
import { useAlertFatigue, useAlertMetrics, useAlerts, useRealTimeAlerts } from '@/lib/hooks/use-alerts';
import { useAuthStore } from '@/lib/store';
import {
  AutoAwesome as AIIcon,
  Analytics as AnalyticsIcon,
  Assignment as AssignmentIcon,
  Psychology as BehaviorIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Speed as SpeedIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import {
  alpha,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Grid,
  IconButton,
  Alert as MuiAlert,
  Paper,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import React, { useMemo, useState } from 'react';
import { AlertFilters } from './alert-filters';
import { AlertList } from './alert-list';

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
      id={`alert-tabpanel-${index}`}
      aria-labelledby={`alert-tab-${index}`}
      {...other}
    >
      {value === index && children}
    </div>
  );
}

export function AlertManagementPage() {
  const theme = useTheme();
  const auth = useAuthStore();
  const [activeTab, setActiveTab] = useState(0);
  const [filters, setFilters] = useState<AlertFiltersType>({});
  const [searchQuery, setSearchQuery] = useState('');

  // Real-time connection status
  const { connectionStatus, isConnected } = useRealTimeAlerts(filters);

  // Alert data with real-time updates
  const { alerts, pagination, isLoading, error, refreshAlerts } = useAlerts({
    filters: {
      ...filters,
      // Add tab-specific filters
      ...(activeTab === 1 && { status: ['OPEN'] }),
      ...(activeTab === 2 && { priority: ['P1', 'P2'] }),
      ...(activeTab === 3 && { assignedTo: [auth.user?.email || ''] }),
    },
    realTime: true,
  });

  // Metrics and analytics
  const { data: metrics, isLoading: metricsLoading } = useAlertMetrics();
  const { data: fatigueAnalysis, isLoading: fatigueLoading } = useAlertFatigue();

  // Calculated statistics
  const alertStats = useMemo(() => {
    if (!alerts.length) return { total: 0, critical: 0, unassigned: 0, overdue: 0, myAlerts: 0 };

    return {
      total: alerts.length,
      critical: alerts.filter((a) => a.priority === 'P1').length,
      unassigned: alerts.filter((a) => !a.assignedTo).length,
      overdue: alerts.filter((a) => a.sla.breached).length,
      myAlerts: alerts.filter((a) => a.assignedTo === auth.user?.email).length,
    };
  }, [alerts, auth.user?.email]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handleFiltersChange = (newFilters: AlertFiltersType) => {
    setFilters(newFilters);
  };

  const handleSearchChange = (query: string) => {
    setSearchQuery(query);
  };

  const renderOverviewMetrics = () => {
    if (metricsLoading) {
      return (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress />
        </Box>
      );
    }

    return (
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Total Alerts */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h4" color="primary" fontWeight={600}>
                    {alertStats.total}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Alerts
                  </Typography>
                </Box>
                <SecurityIcon sx={{ fontSize: 40, color: theme.palette.primary.main, opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Critical Alerts */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h4" color="error.main" fontWeight={600}>
                    {alertStats.critical}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Critical (P1)
                  </Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 40, color: theme.palette.error.main, opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* My Alerts */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h4" color="info.main" fontWeight={600}>
                    {alertStats.myAlerts}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    My Alerts
                  </Typography>
                </Box>
                <AssignmentIcon sx={{ fontSize: 40, color: theme.palette.info.main, opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* SLA Breached */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h4" color="warning.main" fontWeight={600}>
                    {alertStats.overdue}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    SLA Breached
                  </Typography>
                </Box>
                <TimelineIcon sx={{ fontSize: 40, color: theme.palette.warning.main, opacity: 0.3 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Performance Metrics */}
        {metrics && (
          <>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Box>
                      <Typography variant="h5" color="secondary.main" fontWeight={600}>
                        {Math.round(metrics.meanTimeToResponse)}m
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Avg Response Time
                      </Typography>
                    </Box>
                    <SpeedIcon sx={{ fontSize: 40, color: theme.palette.secondary.main, opacity: 0.3 }} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Box>
                      <Typography variant="h5" color="success.main" fontWeight={600}>
                        {Math.round(100 - metrics.falsePositiveRate)}%
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Accuracy Rate
                      </Typography>
                    </Box>
                    <TrendIcon sx={{ fontSize: 40, color: theme.palette.success.main, opacity: 0.3 }} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Box>
                      <Typography variant="h5" color="primary.main" fontWeight={600}>
                        {metrics.correlationStats.duplicatesReduced}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Duplicates Reduced
                      </Typography>
                    </Box>
                    <AIIcon sx={{ fontSize: 40, color: theme.palette.primary.main, opacity: 0.3 }} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Box>
                      <Typography variant="h5" color="info.main" fontWeight={600}>
                        {Math.round(100 - (fatigueAnalysis?.fatigueScore || 0))}%
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Alert Quality
                      </Typography>
                    </Box>
                    <BehaviorIcon sx={{ fontSize: 40, color: theme.palette.info.main, opacity: 0.3 }} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </>
        )}
      </Grid>
    );
  };

  const renderConnectionStatus = () => (
    <Paper
      elevation={0}
      sx={{
        p: 1,
        mb: 2,
        backgroundColor: isConnected ? alpha(theme.palette.success.main, 0.1) : alpha(theme.palette.warning.main, 0.1),
        border: `1px solid ${isConnected ? theme.palette.success.main : theme.palette.warning.main}`,
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box
            sx={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: isConnected ? theme.palette.success.main : theme.palette.warning.main,
              animation: isConnected ? 'none' : 'pulse 1.5s infinite',
            }}
          />
          <Typography variant="body2" fontWeight={500}>
            Real-time Status: {connectionStatus === 'connected' ? 'Connected' : 'Connecting...'}
          </Typography>
        </Box>
        <Chip
          label={`${alerts.length} alerts loaded`}
          size="small"
          variant="outlined"
          color={isConnected ? 'success' : 'warning'}
        />
      </Box>
    </Paper>
  );

  return (
    <Box>
      {/* Page Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 600 }}>
            Alert Management
          </Typography>
          <Typography variant="body1" color="text.secondary">
            AI-powered intelligent alert correlation, triage, and investigation
          </Typography>
        </Box>

        <Stack direction="row" spacing={1}>
          <Tooltip title="Refresh alerts">
            <IconButton onClick={refreshAlerts} disabled={isLoading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>

          <Button
            variant="outlined"
            startIcon={<AnalyticsIcon />}
            onClick={() => {
              /* Open analytics modal */
            }}
          >
            Analytics
          </Button>

          <Button
            variant="outlined"
            startIcon={<SettingsIcon />}
            onClick={() => {
              /* Open settings */
            }}
          >
            Settings
          </Button>
        </Stack>
      </Box>

      {/* Connection Status */}
      {renderConnectionStatus()}

      {/* Error Display */}
      {error && (
        <MuiAlert
          severity="error"
          sx={{ mb: 2 }}
          action={
            <Button color="inherit" size="small" onClick={refreshAlerts}>
              Retry
            </Button>
          }
        >
          Failed to load alerts: {error.message}
        </MuiAlert>
      )}

      {/* Overview Metrics */}
      {renderOverviewMetrics()}

      {/* Alert Fatigue Warning */}
      {fatigueAnalysis && fatigueAnalysis.fatigueScore > 70 && (
        <MuiAlert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="subtitle2" gutterBottom>
            High Alert Fatigue Detected ({fatigueAnalysis.fatigueScore}% fatigue score)
          </Typography>
          <Typography variant="body2">
            Consider reviewing noisy rules and implementing suppression strategies to reduce alert volume.
          </Typography>
        </MuiAlert>
      )}

      {/* Main Content Area */}
      <Grid container spacing={3}>
        {/* Filters */}
        <Grid item xs={12} lg={3}>
          <AlertFilters
            onFiltersChange={handleFiltersChange}
            onSearchChange={handleSearchChange}
            initialFilters={filters}
            compact
          />
        </Grid>

        {/* Alert List */}
        <Grid item xs={12} lg={9}>
          <Paper elevation={0} sx={{ borderRadius: 2, overflow: 'hidden' }}>
            {/* Alert Tabs */}
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs value={activeTab} onChange={handleTabChange} variant="fullWidth">
                <Tab
                  label={
                    <Badge badgeContent={alertStats.total} color="primary" max={999}>
                      All Alerts
                    </Badge>
                  }
                  id="alert-tab-0"
                />
                <Tab
                  label={
                    <Badge badgeContent={alerts.filter((a) => a.status === 'OPEN').length} color="error" max={999}>
                      Open
                    </Badge>
                  }
                  id="alert-tab-1"
                />
                <Tab
                  label={
                    <Badge badgeContent={alertStats.critical} color="error" max={999}>
                      Critical
                    </Badge>
                  }
                  id="alert-tab-2"
                />
                <Tab
                  label={
                    <Badge badgeContent={alertStats.myAlerts} color="info" max={999}>
                      My Alerts
                    </Badge>
                  }
                  id="alert-tab-3"
                />
              </Tabs>
            </Box>

            {/* Tab Panels */}
            <TabPanel value={activeTab} index={0}>
              <AlertList
                filters={filters}
                realTime={true}
                onAlertSelect={(alert) => {
                  // Handle alert selection - could open detail modal
                  console.log('Selected alert:', alert);
                }}
              />
            </TabPanel>

            <TabPanel value={activeTab} index={1}>
              <AlertList
                filters={{ ...filters, status: ['OPEN'] }}
                realTime={true}
                onAlertSelect={(alert) => {
                  console.log('Selected open alert:', alert);
                }}
              />
            </TabPanel>

            <TabPanel value={activeTab} index={2}>
              <AlertList
                filters={{ ...filters, priority: ['P1', 'P2'] }}
                realTime={true}
                onAlertSelect={(alert) => {
                  console.log('Selected critical alert:', alert);
                }}
              />
            </TabPanel>

            <TabPanel value={activeTab} index={3}>
              <AlertList
                filters={{ ...filters, assignedTo: auth.user?.email ? [auth.user.email] : [] }}
                realTime={true}
                onAlertSelect={(alert) => {
                  console.log('Selected my alert:', alert);
                }}
              />
            </TabPanel>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default AlertManagementPage;
