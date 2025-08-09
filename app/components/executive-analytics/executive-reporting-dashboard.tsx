'use client';

import React, { useState, useEffect, useMemo, useCallback, Suspense, startTransition } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CardHeader,
  IconButton,
  Tooltip,
  LinearProgress,
  CircularProgress,
  Chip,
  Alert,
  useTheme,
  useMediaQuery,
  Skeleton,
  Switch,
  FormControlLabel,
  ButtonGroup,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
  MenuItem,
  Divider,
  Badge
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Assessment as AssessmentIcon,
  Business as BusinessIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Schedule as ScheduleIcon,
  Refresh as RefreshIcon,
  GetApp as ExportIcon,
  Share as ShareIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  Shield as ShieldIcon,
  Speed as SpeedIcon,
  MonetizationOn as MonetizationIcon,
  Timeline as TimelineIcon,
  MoreVert as MoreVertIcon,
  Fullscreen as FullscreenIcon,
  Print as PrintIcon,
  Email as EmailIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  ComposedChart
} from 'recharts';
import { ExecutiveKPICard } from './executive-kpi-card';
import { SecurityPostureDashboard } from './security-posture-dashboard';
import { useExecutiveReporting } from '../../lib/hooks/use-executive-reporting';
import { usePerformanceOptimizer } from '../../lib/hooks/use-performance-optimizer';

// Types for executive reporting
interface ExecutiveMetrics {
  securityScore: number;
  riskExposure: number;
  complianceScore: number;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  incidentCount: number;
  mttr: number; // minutes
  mttd: number; // minutes
  securityROI: number;
  budgetUtilization: number;
  teamEfficiency: number;
  timestamp: Date;
  confidence: number;
}

interface RiskTrend {
  timestamp: Date;
  securityScore: number;
  riskExposure: number;
  incidentCount: number;
  threatLevel: number;
  complianceScore: number;
}

interface ComplianceFramework {
  name: string;
  score: number;
  status: 'compliant' | 'partial' | 'non_compliant';
  lastAudit: Date;
  nextAudit: Date;
  criticalFindings: number;
}

interface SecurityAlert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  timestamp: Date;
  category: string;
  status: 'open' | 'investigating' | 'resolved';
  assignee?: string;
}

interface ExecutiveReportingDashboardProps {
  userId: string;
  tenantId: string;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  timeRange: '24h' | '7d' | '30d' | '90d' | '1y';
  onTimeRangeChange: (range: '24h' | '7d' | '30d' | '90d' | '1y') => void;
  className?: string;
}

export const ExecutiveReportingDashboard: React.FC<ExecutiveReportingDashboardProps> = ({
  userId,
  tenantId,
  userRole,
  timeRange,
  onTimeRangeChange,
  className
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const isTablet = useMediaQuery(theme.breakpoints.down('lg'));

  // State management
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [shareDialogOpen, setShareDialogOpen] = useState(false);
  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [viewMode, setViewMode] = useState<'overview' | 'detailed' | 'trends'>('overview');
  const [selectedMetric, setSelectedMetric] = useState<string | null>(null);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [showPostureScoring, setShowPostureScoring] = useState(false);

  // Performance optimization with React 18 concurrent features
  const {
    performanceMetrics,
    isOptimized,
    trackRenderStart,
    trackRenderEnd
  } = usePerformanceOptimizer({
    virtualization: {
      itemHeight: 120,
      containerHeight: 500,
      overscan: 3,
      threshold: 30
    },
    caching: {
      ttl: 60000, // 1 minute for executive data
      maxSize: 100,
      strategy: 'lru'
    },
    realTimeUpdates: {
      enabled: realTimeEnabled,
      interval: 30000, // 30 seconds for executive updates
      batchSize: 8
    },
    performanceMonitoring: {
      enabled: true,
      sampleRate: 1.0,
      alertThresholds: {
        renderTime: 150, // 150ms for executive dashboard
        memoryUsage: 150, // 150MB
        networkLatency: 1000 // 1 second
      }
    }
  });

  // Executive reporting data hook
  const {
    executiveMetrics,
    riskTrends,
    complianceFrameworks,
    securityAlerts,
    isLoading,
    error,
    refreshData,
    exportReport,
    scheduleReport,
    getMetricDetails,
    lastUpdated
  } = useExecutiveReporting({
    userId,
    tenantId,
    userRole,
    timeRange,
    realTimeUpdates: realTimeEnabled,
    includeCompliance: true,
    includeAlerts: true
  });

  // Memoized executive insights
  const executiveInsights = useMemo(() => {
    if (!executiveMetrics || !riskTrends) return null;

    const latestTrend = riskTrends[riskTrends.length - 1];
    const previousTrend = riskTrends[riskTrends.length - 2];

    return {
      securityTrend: latestTrend && previousTrend ? 
        ((latestTrend.securityScore - previousTrend.securityScore) / previousTrend.securityScore * 100) : 0,
      riskTrend: latestTrend && previousTrend ?
        ((latestTrend.riskExposure - previousTrend.riskExposure) / previousTrend.riskExposure * 100) : 0,
      criticalAlerts: securityAlerts?.filter(alert => alert.severity === 'critical').length || 0,
      openIncidents: securityAlerts?.filter(alert => alert.status === 'open').length || 0,
      complianceGaps: complianceFrameworks?.filter(fw => fw.status !== 'compliant').length || 0,
      budgetStatus: executiveMetrics.budgetUtilization > 90 ? 'high' : 
                   executiveMetrics.budgetUtilization > 75 ? 'medium' : 'low'
    };
  }, [executiveMetrics, riskTrends, securityAlerts, complianceFrameworks]);

  // Chart data preparation with useMemo for performance
  const chartData = useMemo(() => {
    if (!riskTrends) return [];

    return riskTrends.map(trend => ({
      timestamp: trend.timestamp.toLocaleDateString(),
      securityScore: Math.round(trend.securityScore),
      riskExposure: Math.round(trend.riskExposure),
      incidentCount: trend.incidentCount,
      threatLevel: trend.threatLevel,
      complianceScore: Math.round(trend.complianceScore)
    }));
  }, [riskTrends]);

  // Compliance pie chart data
  const complianceData = useMemo(() => {
    if (!complianceFrameworks) return [];

    const statusCounts = complianceFrameworks.reduce((acc, fw) => {
      acc[fw.status] = (acc[fw.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(statusCounts).map(([status, count]) => ({
      name: status.replace('_', ' ').toUpperCase(),
      value: count,
      color: getComplianceColor(status)
    }));
  }, [complianceFrameworks]);

  // Handle menu operations
  const handleMenuOpen = useCallback((event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  }, []);

  const handleMenuClose = useCallback(() => {
    setAnchorEl(null);
  }, []);

  // Handle export functionality
  const handleExport = useCallback(async (format: 'pdf' | 'excel' | 'csv') => {
    try {
      await exportReport(format, {
        includeTrends: true,
        includeCompliance: true,
        includeAlerts: true,
        timeRange,
        userRole
      });
      setExportDialogOpen(false);
    } catch (error) {
      console.error('Export failed:', error);
    }
  }, [exportReport, timeRange, userRole]);

  // Handle metric drill-down
  const handleMetricClick = useCallback((metricName: string) => {
    startTransition(() => {
      setSelectedMetric(metricName === selectedMetric ? null : metricName);
    });
  }, [selectedMetric]);

  // Handle refresh
  const handleRefresh = useCallback(async () => {
    await refreshData();
  }, [refreshData]);

  // Auto-refresh effect
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      handleRefresh();
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, [autoRefresh, handleRefresh]);

  // Render performance tracking
  useEffect(() => {
    trackRenderStart();
    return () => trackRenderEnd();
  }, [trackRenderStart, trackRenderEnd]);

  // Error state
  if (error) {
    return (
      <Box className={className} sx={{ p: 3 }}>
        <Alert 
          severity="error" 
          action={
            <IconButton color="inherit" size="small" onClick={handleRefresh}>
              <RefreshIcon />
            </IconButton>
          }
        >
          <Typography variant="h6">Executive Dashboard Unavailable</Typography>
          <Typography variant="body2">
            Unable to load executive reporting data. Please try refreshing.
          </Typography>
        </Alert>
      </Box>
    );
  }

  return (
    <Box className={className} sx={{ p: { xs: 1, sm: 2, md: 3 } }}>
      {/* Executive Dashboard Header */}
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        mb: 3,
        flexWrap: 'wrap',
        gap: 2
      }}>
        <Box>
          <Typography 
            variant={isMobile ? "h5" : "h4"} 
            component="h1" 
            sx={{ 
              fontWeight: 600,
              color: 'text.primary',
              display: 'flex',
              alignItems: 'center',
              gap: 2
            }}
          >
            <DashboardIcon sx={{ fontSize: { xs: 28, md: 32 } }} />
            Executive Security Dashboard
          </Typography>
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 1, flexWrap: 'wrap' }}>
            <Chip
              icon={<ScheduleIcon />}
              label={`Last updated: ${lastUpdated?.toLocaleTimeString() || '--'}`}
              size="small"
              variant="outlined"
              color="primary"
            />
            
            {executiveMetrics && (
              <Chip
                icon={getSecurityIcon(executiveMetrics.securityScore)}
                label={`Security Score: ${Math.round(executiveMetrics.securityScore)}%`}
                size="small"
                color={getScoreColor(executiveMetrics.securityScore)}
                variant="filled"
              />
            )}
            
            {executiveInsights?.criticalAlerts > 0 && (
              <Badge badgeContent={executiveInsights.criticalAlerts} color="error">
                <Chip
                  icon={<WarningIcon />}
                  label="Critical Alerts"
                  size="small"
                  color="error"
                  variant="outlined"
                />
              </Badge>
            )}
          </Box>
        </Box>

        {/* Executive Controls */}
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          <ButtonGroup size="small" variant="outlined">
            {(['24h', '7d', '30d', '90d', '1y'] as const).map((range) => (
              <Button
                key={range}
                onClick={() => onTimeRangeChange(range)}
                variant={timeRange === range ? 'contained' : 'outlined'}
              >
                {range}
              </Button>
            ))}
          </ButtonGroup>
          
          <FormControlLabel
            control={
              <Switch
                checked={realTimeEnabled}
                onChange={(e) => setRealTimeEnabled(e.target.checked)}
                size="small"
              />
            }
            label="Live"
          />
          
          <Tooltip title="Export Report">
            <IconButton 
              onClick={() => setExportDialogOpen(true)}
              sx={{ 
                bgcolor: 'success.main',
                color: 'white',
                '&:hover': { bgcolor: 'success.dark' }
              }}
            >
              <ExportIcon />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Refresh Dashboard">
            <IconButton 
              onClick={handleRefresh} 
              disabled={isLoading}
              sx={{ 
                bgcolor: 'primary.main',
                color: 'white',
                '&:hover': { bgcolor: 'primary.dark' }
              }}
            >
              {isLoading ? <CircularProgress size={20} color="inherit" /> : <RefreshIcon />}
            </IconButton>
          </Tooltip>
          
          <IconButton onClick={handleMenuOpen}>
            <MoreVertIcon />
          </IconButton>
          
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={handleMenuClose}
          >
            <MenuItem onClick={() => { setShareDialogOpen(true); handleMenuClose(); }}>
              <ShareIcon sx={{ mr: 1 }} />
              Share Dashboard
            </MenuItem>
            <MenuItem onClick={() => { setSettingsDialogOpen(true); handleMenuClose(); }}>
              <SettingsIcon sx={{ mr: 1 }} />
              Dashboard Settings
            </MenuItem>
            <MenuItem onClick={() => { setShowPostureScoring(!showPostureScoring); handleMenuClose(); }}>
              <ShieldIcon sx={{ mr: 1 }} />
              {showPostureScoring ? 'Hide' : 'Show'} Posture Scoring
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => { setAutoRefresh(!autoRefresh); handleMenuClose(); }}>
              <RefreshIcon sx={{ mr: 1 }} />
              {autoRefresh ? 'Disable' : 'Enable'} Auto-refresh
            </MenuItem>
          </Menu>
        </Box>
      </Box>

      {/* Loading State */}
      {isLoading && !executiveMetrics && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
            Loading executive analytics...
          </Typography>
        </Box>
      )}

      {/* Executive KPI Overview */}
      <Suspense fallback={<DashboardSkeleton />}>
        <AnimatePresence>
          {executiveMetrics && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {/* Security Score - Primary KPI */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Security Score"
                    value={executiveMetrics.securityScore}
                    format="percentage"
                    trend={getTrendFromValue(executiveInsights?.securityTrend || 0)}
                    trendValue={executiveInsights?.securityTrend}
                    icon={<SecurityIcon />}
                    color={getScoreColor(executiveMetrics.securityScore)}
                    subtitle="Overall security health"
                    target={85}
                    confidenceScore={executiveMetrics.confidence}
                    lastUpdated={executiveMetrics.timestamp}
                    clickable
                    onClick={() => handleMetricClick('security')}
                    showProgress
                  />
                </Grid>

                {/* Risk Exposure */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Risk Exposure"
                    value={executiveMetrics.riskExposure}
                    format="percentage"
                    trend={getTrendFromValue(executiveInsights?.riskTrend || 0)}
                    trendValue={executiveInsights?.riskTrend}
                    icon={<WarningIcon />}
                    color={getRiskColor(executiveMetrics.riskExposure)}
                    subtitle="Current risk level"
                    target={25} // Lower is better for risk
                    clickable
                    onClick={() => handleMetricClick('risk')}
                  />
                </Grid>

                {/* Compliance Score */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Compliance"
                    value={executiveMetrics.complianceScore}
                    format="percentage"
                    icon={<CheckCircleIcon />}
                    color={getScoreColor(executiveMetrics.complianceScore)}
                    subtitle="Regulatory compliance"
                    target={95}
                    clickable
                    onClick={() => handleMetricClick('compliance')}
                    showProgress
                  />
                </Grid>

                {/* Security ROI */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Security ROI"
                    value={executiveMetrics.securityROI}
                    format="percentage"
                    icon={<MonetizationIcon />}
                    color="success"
                    subtitle="Investment return"
                    target={150}
                    clickable
                    onClick={() => handleMetricClick('roi')}
                  />
                </Grid>

                {/* Mean Time to Detect */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="MTTD"
                    value={Math.round(executiveMetrics.mttd)}
                    format="time"
                    suffix="min"
                    icon={<SpeedIcon />}
                    color={getTimeColor(executiveMetrics.mttd)}
                    subtitle="Mean time to detect"
                    target={120} // 2 hours
                    clickable
                    onClick={() => handleMetricClick('mttd')}
                  />
                </Grid>

                {/* Mean Time to Respond */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="MTTR"
                    value={Math.round(executiveMetrics.mttr)}
                    format="time"
                    suffix="min"
                    icon={<AssessmentIcon />}
                    color={getTimeColor(executiveMetrics.mttr)}
                    subtitle="Mean time to respond"
                    target={240} // 4 hours
                    clickable
                    onClick={() => handleMetricClick('mttr')}
                  />
                </Grid>

                {/* Active Incidents */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Open Incidents"
                    value={executiveInsights?.openIncidents || 0}
                    format="number"
                    icon={<NotificationsIcon />}
                    color={executiveInsights?.openIncidents > 5 ? 'error' : 'success'}
                    subtitle="Requiring attention"
                    clickable
                    onClick={() => handleMetricClick('incidents')}
                  />
                </Grid>

                {/* Budget Utilization */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Budget Used"
                    value={executiveMetrics.budgetUtilization}
                    format="percentage"
                    icon={<BusinessIcon />}
                    color={getBudgetColor(executiveMetrics.budgetUtilization)}
                    subtitle="Security budget"
                    target={85}
                    clickable
                    onClick={() => handleMetricClick('budget')}
                    showProgress
                  />
                </Grid>
              </Grid>
            </motion.div>
          )}
        </AnimatePresence>
      </Suspense>

      {/* Security Posture Scoring Dashboard */}
      <AnimatePresence>
        {showPostureScoring && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.5 }}
          >
            <Box sx={{ mb: 3 }}>
              <SecurityPostureDashboard
                userId={userId}
                tenantId={tenantId}
                timeRange={timeRange}
                onTimeRangeChange={onTimeRangeChange}
              />
            </Box>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Dashboard Content */}
      <Grid container spacing={3}>
        {/* Risk Trends Visualization */}
        <Grid item xs={12} lg={8}>
          <Card sx={{ height: 400 }}>
            <CardHeader
              title="Security & Risk Trends"
              action={
                <ButtonGroup size="small">
                  <Button
                    onClick={() => setViewMode('overview')}
                    variant={viewMode === 'overview' ? 'contained' : 'outlined'}
                  >
                    Overview
                  </Button>
                  <Button
                    onClick={() => setViewMode('trends')}
                    variant={viewMode === 'trends' ? 'contained' : 'outlined'}
                  >
                    <TimelineIcon sx={{ mr: 1 }} />
                    Trends
                  </Button>
                </ButtonGroup>
              }
            />
            <CardContent sx={{ height: 320, p: 1 }}>
              <Suspense fallback={<ChartSkeleton />}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="timestamp" 
                      tick={{ fontSize: 12 }}
                      angle={-45}
                      textAnchor="end"
                      height={60}
                    />
                    <YAxis yAxisId="score" domain={[0, 100]} />
                    <YAxis yAxisId="count" orientation="right" />
                    <RechartsTooltip 
                      contentStyle={{
                        backgroundColor: theme.palette.background.paper,
                        border: `1px solid ${theme.palette.divider}`,
                        borderRadius: 8
                      }}
                    />
                    <Legend />
                    <Area
                      yAxisId="score"
                      type="monotone"
                      dataKey="securityScore"
                      stroke={theme.palette.primary.main}
                      fill={theme.palette.primary.main}
                      fillOpacity={0.3}
                      name="Security Score"
                    />
                    <Line
                      yAxisId="score"
                      type="monotone"
                      dataKey="riskExposure"
                      stroke={theme.palette.error.main}
                      name="Risk Exposure"
                    />
                    <Line
                      yAxisId="score"
                      type="monotone"
                      dataKey="complianceScore"
                      stroke={theme.palette.success.main}
                      name="Compliance Score"
                    />
                    <Bar
                      yAxisId="count"
                      dataKey="incidentCount"
                      fill={theme.palette.warning.main}
                      name="Incidents"
                      opacity={0.7}
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </Suspense>
            </CardContent>
          </Card>
        </Grid>

        {/* Compliance Framework Status */}
        <Grid item xs={12} lg={4}>
          <Card sx={{ height: 400 }}>
            <CardHeader title="Compliance Status" />
            <CardContent sx={{ height: 320 }}>
              <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                {/* Compliance Pie Chart */}
                <Box sx={{ flex: 1, minHeight: 200 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={complianceData}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {complianceData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </Box>

                {/* Compliance Framework Details */}
                <Box sx={{ mt: 2, maxHeight: 120, overflow: 'auto' }}>
                  {complianceFrameworks?.slice(0, 3).map((framework, index) => (
                    <Box
                      key={framework.name}
                      sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        p: 1,
                        mb: 1,
                        borderRadius: 1,
                        bgcolor: 'background.paper',
                        border: `1px solid ${theme.palette.divider}`
                      }}
                    >
                      <Typography variant="body2" fontWeight={500}>
                        {framework.name}
                      </Typography>
                      <Chip
                        label={`${Math.round(framework.score)}%`}
                        color={getComplianceStatusColor(framework.status)}
                        size="small"
                      />
                    </Box>
                  ))}
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Export Dialog */}
      <Dialog open={exportDialogOpen} onClose={() => setExportDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Export Executive Report</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
            <Button
              startIcon={<PrintIcon />}
              onClick={() => handleExport('pdf')}
              variant="outlined"
              fullWidth
            >
              Export as PDF Report
            </Button>
            <Button
              startIcon={<ExportIcon />}
              onClick={() => handleExport('excel')}
              variant="outlined"
              fullWidth
            >
              Export as Excel Spreadsheet
            </Button>
            <Button
              startIcon={<ExportIcon />}
              onClick={() => handleExport('csv')}
              variant="outlined"
              fullWidth
            >
              Export as CSV Data
            </Button>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportDialogOpen(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

// Helper functions
function getSecurityIcon(score: number) {
  if (score >= 80) return <CheckCircleIcon />;
  if (score >= 60) return <WarningIcon />;
  return <SecurityIcon />;
}

function getScoreColor(score: number): 'success' | 'warning' | 'error' {
  if (score >= 80) return 'success';
  if (score >= 60) return 'warning';
  return 'error';
}

function getRiskColor(risk: number): 'success' | 'warning' | 'error' {
  if (risk <= 25) return 'success';
  if (risk <= 50) return 'warning';
  return 'error';
}

function getTimeColor(minutes: number): 'success' | 'warning' | 'error' {
  if (minutes <= 120) return 'success'; // 2 hours
  if (minutes <= 240) return 'warning'; // 4 hours
  return 'error';
}

function getBudgetColor(utilization: number): 'success' | 'warning' | 'error' {
  if (utilization <= 75) return 'success';
  if (utilization <= 90) return 'warning';
  return 'error';
}

function getTrendFromValue(value: number): 'up' | 'down' | 'stable' {
  if (value > 2) return 'up';
  if (value < -2) return 'down';
  return 'stable';
}

function getComplianceColor(status: string): string {
  switch (status) {
    case 'compliant': return '#4caf50';
    case 'partial': return '#ff9800';
    case 'non_compliant': return '#f44336';
    default: return '#9e9e9e';
  }
}

function getComplianceStatusColor(status: string): 'success' | 'warning' | 'error' {
  switch (status) {
    case 'compliant': return 'success';
    case 'partial': return 'warning';
    case 'non_compliant': return 'error';
    default: return 'warning';
  }
}

// Skeleton components
const DashboardSkeleton: React.FC = () => (
  <Grid container spacing={2}>
    {[...Array(8)].map((_, index) => (
      <Grid item xs={12} sm={6} md={3} key={index}>
        <Card>
          <CardContent>
            <Skeleton variant="text" width="60%" height={24} />
            <Skeleton variant="text" width="40%" height={48} />
            <Skeleton variant="text" width="80%" height={16} />
          </CardContent>
        </Card>
      </Grid>
    ))}
  </Grid>
);

const ChartSkeleton: React.FC = () => (
  <Box sx={{ p: 2, height: '100%' }}>
    <Skeleton variant="rectangular" width="100%" height="100%" />
  </Box>
);

export default ExecutiveReportingDashboard;