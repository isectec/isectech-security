'use client';

import React, { useState, useEffect, useMemo, useCallback, Suspense } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CardHeader,
  IconButton,
  Menu,
  MenuItem,
  Chip,
  LinearProgress,
  CircularProgress,
  Alert,
  Tooltip,
  Fab,
  useTheme,
  useMediaQuery,
  Skeleton
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Schedule as ScheduleIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon,
  Export as ExportIcon,
  MoreVert as MoreVertIcon,
  Shield as ShieldIcon,
  Assessment as AssessmentIcon,
  Business as BusinessIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useExecutiveAnalytics } from '../../lib/hooks/use-executive-analytics';
import { usePerformanceOptimizer } from '../../lib/hooks/use-performance-optimizer';
import { ExecutiveKPICard } from './executive-kpi-card';
import { ExecutiveThreatLandscape } from './executive-threat-landscape';
import { ExecutiveComplianceDashboard } from './executive-compliance-dashboard';
import { ExecutiveROIMetrics } from './executive-roi-metrics';
import { ExecutivePredictiveAnalytics } from './executive-predictive-analytics';
import { ExecutiveCustomization } from './executive-customization';
import { ExecutiveExportDialog } from './executive-export-dialog';
import { ExecutiveDrillDown } from './executive-drill-down';
import { useDashboardPreferences } from '../../lib/hooks/use-dashboard-preferences';

interface ExecutiveDashboardProps {
  userId: string;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
  tenantId: string;
  className?: string;
}

interface DashboardConfig {
  layout: 'compact' | 'detailed' | 'executive';
  refreshInterval: number;
  widgets: WidgetConfig[];
  theme: 'light' | 'dark' | 'auto';
  mobileOptimized: boolean;
}

interface WidgetConfig {
  id: string;
  type: string;
  position: { x: number; y: number; w: number; h: number };
  visible: boolean;
  settings: Record<string, any>;
}

interface ExecutiveMetrics {
  securityPostureScore: number;
  riskExposureIndex: number;
  threatLandscapeSeverity: 'low' | 'medium' | 'high' | 'critical';
  complianceScores: Record<string, number>;
  securityInvestmentROI: number;
  mttd: number; // milliseconds
  mttr: number; // milliseconds
  businessDisruptionEvents: number;
  lastUpdated: Date;
  dataFreshness: Record<string, number>;
  confidenceScores: Record<string, number>;
}

export const ExecutiveDashboard: React.FC<ExecutiveDashboardProps> = ({
  userId,
  userRole,
  tenantId,
  className
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const isTablet = useMediaQuery(theme.breakpoints.down('lg'));

  // Performance optimization hook
  const {
    performanceMetrics,
    isOptimized,
    fetchData,
    useRealTimeData,
    clearCache,
    preloadData,
    trackRenderStart,
    trackRenderEnd,
    getVirtualizedList,
    settings: performanceSettings
  } = usePerformanceOptimizer({
    virtualization: {
      itemHeight: 120,
      containerHeight: 600,
      overscan: 3,
      threshold: 50
    },
    caching: {
      ttl: 30000, // 30 seconds for dashboard data
      maxSize: 100,
      strategy: 'lru',
      preloadKeys: [`executive-metrics-${userId}`, `threat-landscape-${tenantId}`]
    },
    realTimeUpdates: {
      enabled: true,
      interval: 15000, // 15 seconds for executive dashboard
      batchSize: 10
    },
    performanceMonitoring: {
      enabled: true,
      sampleRate: 1.0,
      alertThresholds: {
        renderTime: 100, // 100ms for dashboard
        memoryUsage: 100, // 100MB
        networkLatency: 500 // 500ms
      }
    }
  });
  
  // State management
  const [dashboardConfig, setDashboardConfig] = useState<DashboardConfig>({
    layout: isMobile ? 'compact' : 'executive',
    refreshInterval: 30000, // 30 seconds for executive responsiveness
    widgets: [],
    theme: 'auto',
    mobileOptimized: isMobile
  });
  
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [customizationOpen, setCustomizationOpen] = useState(false);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [drillDownOpen, setDrillDownOpen] = useState(false);
  const [drillDownData, setDrillDownData] = useState<{
    type: 'security-posture' | 'threat-landscape' | 'compliance-status' | 'roi-metrics' | 'predictive-analytics';
    data: any;
    title: string;
    subtitle?: string;
  } | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Executive analytics hook with real-time data
  const {
    executiveMetrics,
    threatLandscape,
    complianceStatus,
    roiMetrics,
    predictiveAnalytics,
    isLoading,
    error,
    refreshData,
    dataFreshness
  } = useExecutiveAnalytics({
    userId,
    userRole,
    tenantId,
    refreshInterval: dashboardConfig.refreshInterval,
    autoRefresh
  });

  // Performance optimization with React 18 concurrent features
  const dashboardMetrics = useMemo(() => {
    if (!executiveMetrics) return null;
    
    return {
      ...executiveMetrics,
      // Calculate derived metrics for executive consumption
      overallHealthScore: calculateOverallHealthScore(executiveMetrics),
      criticalAlerts: identifyCriticalAlerts(executiveMetrics),
      trendIndicators: calculateTrends(executiveMetrics),
      executiveSummary: generateExecutiveSummary(executiveMetrics, userRole)
    };
  }, [executiveMetrics, userRole]);

  // Handle manual refresh with loading state
  const handleRefresh = useCallback(async () => {
    setLastRefresh(new Date());
    await refreshData();
  }, [refreshData]);

  // Auto-refresh effect with cleanup
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      handleRefresh();
    }, dashboardConfig.refreshInterval);

    return () => clearInterval(interval);
  }, [autoRefresh, dashboardConfig.refreshInterval, handleRefresh]);

  // Responsive layout configuration
  const getGridLayout = useCallback(() => {
    if (isMobile) {
      return { xs: 12, sm: 12, md: 6, lg: 4 };
    }
    if (isTablet) {
      return { xs: 12, sm: 6, md: 4, lg: 3 };
    }
    return { xs: 12, sm: 6, md: 4, lg: 3 };
  }, [isMobile, isTablet]);

  // Handle menu operations
  const handleMenuOpen = useCallback((event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  }, []);

  const handleMenuClose = useCallback(() => {
    setAnchorEl(null);
  }, []);

  // Drill-down handlers
  const handleDrillDown = useCallback((
    type: 'security-posture' | 'threat-landscape' | 'compliance-status' | 'roi-metrics' | 'predictive-analytics',
    data: any,
    title: string,
    subtitle?: string
  ) => {
    setDrillDownData({ type, data, title, subtitle });
    setDrillDownOpen(true);
  }, []);

  const handleCloseDrillDown = useCallback(() => {
    setDrillDownOpen(false);
    setDrillDownData(null);
  }, []);

  // Error boundary for dashboard resilience
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
            Unable to load executive analytics. Our team has been notified.
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
            <ShieldIcon sx={{ fontSize: { xs: 28, md: 32 } }} />
            Executive Security Dashboard
          </Typography>
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 1, flexWrap: 'wrap' }}>
            <Chip
              icon={<ScheduleIcon />}
              label={`Last updated: ${lastRefresh.toLocaleTimeString()}`}
              size="small"
              variant="outlined"
              color="primary"
            />
            
            {dashboardMetrics?.overallHealthScore && (
              <Chip
                icon={getHealthIcon(dashboardMetrics.overallHealthScore)}
                label={`Health: ${Math.round(dashboardMetrics.overallHealthScore)}%`}
                size="small"
                color={getHealthColor(dashboardMetrics.overallHealthScore)}
                variant="filled"
              />
            )}
            
            {dataFreshness && dataFreshness < 300000 && ( // Less than 5 minutes
              <Chip
                icon={<CheckCircleIcon />}
                label="Real-time"
                size="small"
                color="success"
                variant="outlined"
              />
            )}
          </Box>
        </Box>

        {/* Executive Actions */}
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
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
          
          <Tooltip title="Export Report">
            <IconButton 
              onClick={() => setExportDialogOpen(true)}
              sx={{ 
                bgcolor: 'secondary.main',
                color: 'white',
                '&:hover': { bgcolor: 'secondary.dark' }
              }}
            >
              <ExportIcon />
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
            <MenuItem onClick={() => { setCustomizationOpen(true); handleMenuClose(); }}>
              <SettingsIcon sx={{ mr: 1 }} />
              Customize Dashboard
            </MenuItem>
            <MenuItem onClick={() => { setAutoRefresh(!autoRefresh); handleMenuClose(); }}>
              <RefreshIcon sx={{ mr: 1 }} />
              {autoRefresh ? 'Disable' : 'Enable'} Auto-refresh
            </MenuItem>
          </Menu>
        </Box>
      </Box>

      {/* Loading State for Initial Load */}
      {isLoading && !executiveMetrics && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
            Loading executive analytics...
          </Typography>
        </Box>
      )}

      {/* Executive KPI Overview - Critical Metrics First */}
      <Suspense fallback={<DashboardSkeleton />}>
        <AnimatePresence>
          {dashboardMetrics && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {/* Security Posture Score - Primary KPI */}
                <Grid item {...getGridLayout()}>
                  <ExecutiveKPICard
                    title="Security Posture"
                    value={dashboardMetrics.securityPostureScore}
                    format="percentage"
                    trend={dashboardMetrics.trendIndicators?.securityPosture}
                    icon={<SecurityIcon />}
                    color={getScoreColor(dashboardMetrics.securityPostureScore)}
                    subtitle="Overall security health"
                    confidenceScore={dashboardMetrics.confidenceScores?.security_posture}
                    lastUpdated={dashboardMetrics.lastUpdated}
                    clickable
                    onClick={() => handleDrillDown('security-posture', dashboardMetrics, 'Security Posture Analysis', 'Comprehensive security health assessment')}
                  />
                </Grid>

                {/* Threat Landscape Severity */}
                <Grid item {...getGridLayout()}>
                  <ExecutiveKPICard
                    title="Threat Level"
                    value={dashboardMetrics.threatLandscapeSeverity}
                    format="status"
                    trend={dashboardMetrics.trendIndicators?.threatLevel}
                    icon={<WarningIcon />}
                    color={getThreatLevelColor(dashboardMetrics.threatLandscapeSeverity)}
                    subtitle="Current threat landscape"
                    confidenceScore={dashboardMetrics.confidenceScores?.threat_level}
                    lastUpdated={dashboardMetrics.lastUpdated}
                    clickable
                    onClick={() => handleDrillDown('threat-landscape', threatLandscape, 'Threat Landscape Analysis', 'Current security threat assessment')}
                  />
                </Grid>

                {/* ROI Metrics */}
                <Grid item {...getGridLayout()}>
                  <ExecutiveKPICard
                    title="Security ROI"
                    value={dashboardMetrics.securityInvestmentROI}
                    format="percentage"
                    trend={dashboardMetrics.trendIndicators?.roi}
                    icon={<BusinessIcon />}
                    color="success"
                    subtitle="Investment return"
                    confidenceScore={dashboardMetrics.confidenceScores?.roi}
                    lastUpdated={dashboardMetrics.lastUpdated}
                    clickable
                    onClick={() => handleDrillDown('roi-metrics', roiMetrics, 'ROI Analysis', 'Security investment return analysis')}
                  />
                </Grid>

                {/* Mean Time to Response - Executive Critical */}
                <Grid item {...getGridLayout()}>
                  <ExecutiveKPICard
                    title="Response Time"
                    value={Math.round(dashboardMetrics.mttr / (1000 * 60))} // Convert to minutes
                    format="time"
                    suffix="min"
                    trend={dashboardMetrics.trendIndicators?.mttr}
                    icon={<AssessmentIcon />}
                    color={getMTTRColor(dashboardMetrics.mttr)}
                    subtitle="Mean time to response"
                    target={240} // 4 hour SLA in minutes
                    confidenceScore={dashboardMetrics.confidenceScores?.mttr}
                    lastUpdated={dashboardMetrics.lastUpdated}
                  />
                </Grid>
              </Grid>
            </motion.div>
          )}
        </AnimatePresence>
      </Suspense>

      {/* Executive Dashboard Widgets Grid */}
      <Grid container spacing={3}>
        {/* Threat Landscape Overview */}
        <Grid item xs={12} lg={8}>
          <Suspense fallback={<WidgetSkeleton height={400} />}>
            <ExecutiveThreatLandscape
              data={threatLandscape}
              userRole={userRole}
              isLoading={isLoading}
              onDrillDown={(threatId) => handleDrillDown('threat-landscape', threatLandscape, 'Threat Details', `Detailed analysis for threat ${threatId}`)}
            />
          </Suspense>
        </Grid>

        {/* Compliance Status Summary */}
        <Grid item xs={12} lg={4}>
          <Suspense fallback={<WidgetSkeleton height={400} />}>
            <ExecutiveComplianceDashboard
              complianceData={complianceStatus}
              userRole={userRole}
              isLoading={isLoading}
              onFrameworkClick={(framework) => handleDrillDown('compliance-status', complianceStatus, 'Compliance Analysis', `${framework} framework compliance details`)}
            />
          </Suspense>
        </Grid>

        {/* Predictive Analytics */}
        <Grid item xs={12} lg={6}>
          <Suspense fallback={<WidgetSkeleton height={350} />}>
            <ExecutivePredictiveAnalytics
              predictions={predictiveAnalytics}
              userRole={userRole}
              isLoading={isLoading}
              onPredictionClick={(predictionId) => handleDrillDown('predictive-analytics', predictiveAnalytics, 'Predictive Analysis', `Detailed predictions and recommendations`)}
            />
          </Suspense>
        </Grid>

        {/* ROI and Financial Metrics */}
        <Grid item xs={12} lg={6}>
          <Suspense fallback={<WidgetSkeleton height={350} />}>
            <ExecutiveROIMetrics
              roiData={roiMetrics}
              userRole={userRole}
              isLoading={isLoading}
              onMetricClick={(metric) => handleDrillDown('roi-metrics', roiMetrics, 'ROI Metrics', `${metric} detailed analysis`)}
            />
          </Suspense>
        </Grid>
      </Grid>

      {/* Executive Summary for Mobile */}
      {isMobile && dashboardMetrics?.executiveSummary && (
        <Card sx={{ mt: 3, bgcolor: 'primary.main', color: 'white' }}>
          <CardHeader
            title="Executive Summary"
            titleTypographyProps={{ color: 'white', variant: 'h6' }}
            avatar={<DashboardIcon sx={{ color: 'white' }} />}
          />
          <CardContent>
            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)' }}>
              {dashboardMetrics.executiveSummary}
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Floating Action Button for Quick Actions */}
      {isMobile && (
        <Fab
          color="primary"
          sx={{ position: 'fixed', bottom: 16, right: 16 }}
          onClick={() => setCustomizationOpen(true)}
        >
          <SettingsIcon />
        </Fab>
      )}

      {/* Dialogs */}
      <ExecutiveCustomization
        open={customizationOpen}
        onClose={() => setCustomizationOpen(false)}
        config={dashboardConfig}
        onConfigChange={setDashboardConfig}
        userRole={userRole}
      />
      
      <ExecutiveExportDialog
        open={exportDialogOpen}
        onClose={() => setExportDialogOpen(false)}
        dashboardData={dashboardMetrics}
        userRole={userRole}
      />

      {/* Drill-down Dialog */}
      {drillDownData && (
        <ExecutiveDrillDown
          open={drillDownOpen}
          onClose={handleCloseDrillDown}
          drillDownType={drillDownData.type}
          data={drillDownData.data}
          userRole={userRole}
          title={drillDownData.title}
          subtitle={drillDownData.subtitle}
        />
      )}
    </Box>
  );
};

// Helper functions
function calculateOverallHealthScore(metrics: ExecutiveMetrics): number {
  const weights = {
    securityPosture: 0.3,
    compliance: 0.25,
    threatLevel: 0.2,
    roi: 0.15,
    responseTime: 0.1
  };
  
  const securityScore = metrics.securityPostureScore;
  const complianceScore = Object.values(metrics.complianceScores).reduce((a, b) => a + b, 0) / 
                         Object.values(metrics.complianceScores).length;
  const threatScore = getThreatLevelScore(metrics.threatLandscapeSeverity);
  const roiScore = Math.min(metrics.securityInvestmentROI, 100);
  const responseScore = Math.max(0, 100 - (metrics.mttr / 60000)); // Convert ms to minutes, inverse scoring
  
  return (
    securityScore * weights.securityPosture +
    complianceScore * weights.compliance +
    threatScore * weights.threatLevel +
    roiScore * weights.roi +
    responseScore * weights.responseTime
  );
}

function identifyCriticalAlerts(metrics: ExecutiveMetrics): string[] {
  const alerts: string[] = [];
  
  if (metrics.securityPostureScore < 70) {
    alerts.push('Security posture below acceptable threshold');
  }
  
  if (metrics.threatLandscapeSeverity === 'critical' || metrics.threatLandscapeSeverity === 'high') {
    alerts.push(`${metrics.threatLandscapeSeverity.toUpperCase()} threat level detected`);
  }
  
  if (metrics.mttr > 4 * 60 * 60 * 1000) { // 4 hours in ms
    alerts.push('Response time exceeds 4-hour SLA');
  }
  
  if (metrics.businessDisruptionEvents > 0) {
    alerts.push(`${metrics.businessDisruptionEvents} business disruption events`);
  }
  
  return alerts;
}

function calculateTrends(metrics: ExecutiveMetrics): Record<string, 'up' | 'down' | 'stable'> {
  // This would normally calculate trends from historical data
  // For now, returning mock trends
  return {
    securityPosture: 'up',
    threatLevel: 'stable',
    roi: 'up',
    mttr: 'down'
  };
}

function generateExecutiveSummary(metrics: ExecutiveMetrics, userRole: string): string {
  const score = calculateOverallHealthScore(metrics);
  const critical = identifyCriticalAlerts(metrics);
  
  let summary = `Security health at ${Math.round(score)}%. `;
  
  if (critical.length > 0) {
    summary += `${critical.length} critical item${critical.length > 1 ? 's' : ''} require attention. `;
  } else {
    summary += 'All systems operating within acceptable parameters. ';
  }
  
  if (userRole === 'ceo') {
    summary += `ROI at ${Math.round(metrics.securityInvestmentROI)}% indicates strong security investment returns.`;
  } else if (userRole === 'ciso') {
    summary += `MTTR at ${Math.round(metrics.mttr / 60000)} minutes is ${metrics.mttr <= 240000 ? 'meeting' : 'exceeding'} SLA targets.`;
  }
  
  return summary;
}

function getHealthIcon(score: number) {
  if (score >= 80) return <CheckCircleIcon />;
  if (score >= 60) return <WarningIcon />;
  return <WarningIcon />;
}

function getHealthColor(score: number): 'success' | 'warning' | 'error' {
  if (score >= 80) return 'success';
  if (score >= 60) return 'warning';
  return 'error';
}

function getScoreColor(score: number): 'success' | 'warning' | 'error' {
  if (score >= 80) return 'success';
  if (score >= 60) return 'warning';
  return 'error';
}

function getThreatLevelColor(level: string): 'success' | 'warning' | 'error' {
  switch (level) {
    case 'low': return 'success';
    case 'medium': return 'warning';
    case 'high':
    case 'critical': return 'error';
    default: return 'warning';
  }
}

function getThreatLevelScore(level: string): number {
  switch (level) {
    case 'low': return 90;
    case 'medium': return 70;
    case 'high': return 40;
    case 'critical': return 10;
    default: return 50;
  }
}

function getMTTRColor(mttr: number): 'success' | 'warning' | 'error' {
  const hours = mttr / (1000 * 60 * 60);
  if (hours <= 2) return 'success';
  if (hours <= 4) return 'warning';
  return 'error';
}

// Skeleton components for loading states
const DashboardSkeleton: React.FC = () => (
  <Grid container spacing={2}>
    {[...Array(4)].map((_, index) => (
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

const WidgetSkeleton: React.FC<{ height: number }> = ({ height }) => (
  <Card sx={{ height }}>
    <CardHeader
      title={<Skeleton variant="text" width="50%" />}
      action={<Skeleton variant="circular" width={24} height={24} />}
    />
    <CardContent>
      <Skeleton variant="rectangular" width="100%" height={height - 120} />
    </CardContent>
  </Card>
);

export default ExecutiveDashboard;