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
  Button
} from '@mui/material';
import {
  Security as SecurityIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Shield as ShieldIcon,
  Assessment as AssessmentIcon,
  Timeline as TimelineIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  ZoomIn as ZoomInIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon
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
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  BarChart,
  Bar,
  Cell
} from 'recharts';
import { ExecutiveKPICard } from './executive-kpi-card';
import { useSecurityPosture } from '../../lib/hooks/use-security-posture';
import { usePerformanceOptimizer } from '../../lib/hooks/use-performance-optimizer';

// Types for security posture scoring
interface SecurityPostureScore {
  overall: number;
  categories: {
    identity: number;
    network: number;
    data: number;
    application: number;
    infrastructure: number;
    compliance: number;
  };
  trends: {
    category: string;
    current: number;
    previous: number;
    change: number;
    trend: 'up' | 'down' | 'stable';
  }[];
  timestamp: Date;
  confidence: number;
}

interface SecurityPostureTrend {
  timestamp: Date;
  overall: number;
  identity: number;
  network: number;
  data: number;
  application: number;
  infrastructure: number;
  compliance: number;
  incidents: number;
  vulnerabilities: number;
}

interface SecurityInsight {
  id: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  impact: number;
  recommendation: string;
  automatable: boolean;
}

interface SecurityPostureDashboardProps {
  userId: string;
  tenantId: string;
  timeRange: '24h' | '7d' | '30d' | '90d';
  onTimeRangeChange: (range: '24h' | '7d' | '30d' | '90d') => void;
  onDrillDown?: (category: string, data: any) => void;
  className?: string;
}

export const SecurityPostureDashboard: React.FC<SecurityPostureDashboardProps> = ({
  userId,
  tenantId,
  timeRange,
  onTimeRangeChange,
  onDrillDown,
  className
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const isTablet = useMediaQuery(theme.breakpoints.down('lg'));

  // State management
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [showInsights, setShowInsights] = useState(true);
  const [chartView, setChartView] = useState<'trend' | 'comparison' | 'radar'>('trend');

  // Performance optimization
  const {
    performanceMetrics,
    isOptimized,
    trackRenderStart,
    trackRenderEnd
  } = usePerformanceOptimizer({
    virtualization: {
      itemHeight: 100,
      containerHeight: 400,
      overscan: 2,
      threshold: 25
    },
    caching: {
      ttl: 60000, // 1 minute for security data
      maxSize: 50,
      strategy: 'lru'
    },
    realTimeUpdates: {
      enabled: realTimeEnabled,
      interval: 30000, // 30 seconds for security posture
      batchSize: 5
    }
  });

  // Security posture data hook
  const {
    currentScore,
    historicalTrends,
    securityInsights,
    isLoading,
    error,
    refreshData,
    getScoreBreakdown,
    getTrendAnalysis,
    getRecommendations
  } = useSecurityPosture({
    userId,
    tenantId,
    timeRange,
    realTimeUpdates: realTimeEnabled,
    includeTrends: true,
    includeInsights: true
  });

  // Memoized calculations for performance
  const scoreAnalysis = useMemo(() => {
    if (!currentScore) return null;

    const categoriesArray = Object.entries(currentScore.categories).map(([key, value]) => ({
      name: key.charAt(0).toUpperCase() + key.slice(1),
      score: value,
      color: getScoreColor(value),
      trend: currentScore.trends.find(t => t.category === key)
    }));

    const worstPerforming = categoriesArray
      .sort((a, b) => a.score - b.score)
      .slice(0, 3);

    const bestPerforming = categoriesArray
      .sort((a, b) => b.score - a.score)
      .slice(0, 3);

    return {
      categoriesArray,
      worstPerforming,
      bestPerforming,
      averageScore: categoriesArray.reduce((sum, cat) => sum + cat.score, 0) / categoriesArray.length,
      improvingCategories: currentScore.trends.filter(t => t.trend === 'up').length,
      decliningCategories: currentScore.trends.filter(t => t.trend === 'down').length
    };
  }, [currentScore]);

  // Chart data preparation
  const chartData = useMemo(() => {
    if (!historicalTrends) return [];

    return historicalTrends.map(trend => ({
      timestamp: trend.timestamp.toLocaleDateString(),
      overall: Math.round(trend.overall),
      identity: Math.round(trend.identity),
      network: Math.round(trend.network),
      data: Math.round(trend.data),
      application: Math.round(trend.application),
      infrastructure: Math.round(trend.infrastructure),
      compliance: Math.round(trend.compliance),
      incidents: trend.incidents,
      vulnerabilities: trend.vulnerabilities
    }));
  }, [historicalTrends]);

  // Radar chart data for current categories
  const radarData = useMemo(() => {
    if (!currentScore) return [];

    return Object.entries(currentScore.categories).map(([key, value]) => ({
      category: key.charAt(0).toUpperCase() + key.slice(1),
      current: Math.round(value),
      target: 90, // Target score for all categories
      industry: Math.round(value * 0.85 + Math.random() * 10) // Mock industry average
    }));
  }, [currentScore]);

  // High-priority insights
  const criticalInsights = useMemo(() => {
    if (!securityInsights) return [];

    return securityInsights
      .filter(insight => insight.severity === 'critical' || insight.severity === 'high')
      .sort((a, b) => b.impact - a.impact)
      .slice(0, 5);
  }, [securityInsights]);

  // Handle category drill-down
  const handleCategoryClick = useCallback((category: string) => {
    setSelectedCategory(category === selectedCategory ? null : category);
    if (onDrillDown && currentScore) {
      onDrillDown(category, {
        score: currentScore.categories[category.toLowerCase() as keyof typeof currentScore.categories],
        trends: currentScore.trends.filter(t => t.category === category.toLowerCase()),
        insights: securityInsights?.filter(insight => 
          insight.category.toLowerCase() === category.toLowerCase()
        )
      });
    }
  }, [selectedCategory, onDrillDown, currentScore, securityInsights]);

  // Handle refresh
  const handleRefresh = useCallback(async () => {
    await refreshData();
  }, [refreshData]);

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
          <Typography variant="h6">Security Posture Dashboard Unavailable</Typography>
          <Typography variant="body2">
            Unable to load security posture data. Please try refreshing.
          </Typography>
        </Alert>
      </Box>
    );
  }

  return (
    <Box className={className} sx={{ p: { xs: 1, sm: 2, md: 3 } }}>
      {/* Dashboard Header */}
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
            Security Posture Scoring
          </Typography>
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 1, flexWrap: 'wrap' }}>
            <Chip
              icon={currentScore ? <CheckCircleIcon /> : <ErrorIcon />}
              label={`Score: ${currentScore ? Math.round(currentScore.overall) : '--'}%`}
              size="small"
              color={currentScore ? getScoreColor(currentScore.overall) : 'default'}
              variant="filled"
            />
            
            <Chip
              label={`${timeRange.toUpperCase()} View`}
              size="small"
              variant="outlined"
              color="primary"
            />
            
            {currentScore?.confidence && (
              <Chip
                label={`Confidence: ${Math.round(currentScore.confidence * 100)}%`}
                size="small"
                variant="outlined"
                color="info"
              />
            )}
          </Box>
        </Box>

        {/* Controls */}
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          <ButtonGroup size="small" variant="outlined">
            {(['24h', '7d', '30d', '90d'] as const).map((range) => (
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
            label="Real-time"
          />
          
          <Tooltip title="Refresh Data">
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
        </Box>
      </Box>

      {/* Loading State */}
      {isLoading && !currentScore && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
            Calculating security posture scores...
          </Typography>
        </Box>
      )}

      {/* Executive KPI Overview */}
      <Suspense fallback={<DashboardSkeleton />}>
        <AnimatePresence>
          {scoreAnalysis && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {/* Overall Security Score */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Overall Score"
                    value={currentScore.overall}
                    format="percentage"
                    trend={getTrendFromScore(currentScore.overall, scoreAnalysis.averageScore)}
                    icon={<SecurityIcon />}
                    color={getScoreColor(currentScore.overall)}
                    subtitle="Security posture health"
                    target={85}
                    confidenceScore={currentScore.confidence}
                    lastUpdated={currentScore.timestamp}
                    clickable
                    onClick={() => handleCategoryClick('overall')}
                    showProgress
                  />
                </Grid>

                {/* Improving Categories */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Improving Areas"
                    value={scoreAnalysis.improvingCategories}
                    format="number"
                    trend="up"
                    icon={<TrendingUpIcon />}
                    color="success"
                    subtitle="Categories trending up"
                    onClick={() => handleCategoryClick('improving')}
                    clickable
                  />
                </Grid>

                {/* Declining Categories */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="At-Risk Areas"
                    value={scoreAnalysis.decliningCategories}
                    format="number"
                    trend="down"
                    icon={<TrendingDownIcon />}
                    color="error"
                    subtitle="Categories needing attention"
                    onClick={() => handleCategoryClick('declining')}
                    clickable
                  />
                </Grid>

                {/* Critical Insights */}
                <Grid item xs={12} sm={6} md={3}>
                  <ExecutiveKPICard
                    title="Critical Issues"
                    value={criticalInsights.length}
                    format="number"
                    icon={<WarningIcon />}
                    color="warning"
                    subtitle="High-priority findings"
                    onClick={() => handleCategoryClick('insights')}
                    clickable
                  />
                </Grid>
              </Grid>
            </motion.div>
          )}
        </AnimatePresence>
      </Suspense>

      {/* Main Dashboard Content */}
      <Grid container spacing={3}>
        {/* Trend Visualization */}
        <Grid item xs={12} lg={8}>
          <Card sx={{ height: 400 }}>
            <CardHeader
              title="Security Posture Trends"
              action={
                <ButtonGroup size="small">
                  <Button
                    onClick={() => setChartView('trend')}
                    variant={chartView === 'trend' ? 'contained' : 'outlined'}
                  >
                    <TimelineIcon sx={{ mr: 1 }} />
                    Trends
                  </Button>
                  <Button
                    onClick={() => setChartView('radar')}
                    variant={chartView === 'radar' ? 'contained' : 'outlined'}
                  >
                    <AssessmentIcon sx={{ mr: 1 }} />
                    Radar
                  </Button>
                </ButtonGroup>
              }
            />
            <CardContent sx={{ height: 320, p: 1 }}>
              <Suspense fallback={<ChartSkeleton />}>
                {chartView === 'trend' ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="timestamp" 
                        tick={{ fontSize: 12 }}
                        angle={-45}
                        textAnchor="end"
                        height={60}
                      />
                      <YAxis domain={[0, 100]} />
                      <RechartsTooltip 
                        contentStyle={{
                          backgroundColor: theme.palette.background.paper,
                          border: `1px solid ${theme.palette.divider}`,
                          borderRadius: 8
                        }}
                      />
                      <Legend />
                      <Area
                        type="monotone"
                        dataKey="overall"
                        stroke={theme.palette.primary.main}
                        fill={theme.palette.primary.main}
                        fillOpacity={0.6}
                        name="Overall Score"
                      />
                      <Line
                        type="monotone"
                        dataKey="identity"
                        stroke={theme.palette.secondary.main}
                        name="Identity"
                      />
                      <Line
                        type="monotone"
                        dataKey="network"
                        stroke={theme.palette.success.main}
                        name="Network"
                      />
                      <Line
                        type="monotone"
                        dataKey="data"
                        stroke={theme.palette.warning.main}
                        name="Data"
                      />
                      <Line
                        type="monotone"
                        dataKey="compliance"
                        stroke={theme.palette.info.main}
                        name="Compliance"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <RadarChart data={radarData}>
                      <PolarGrid />
                      <PolarAngleAxis dataKey="category" />
                      <PolarRadiusAxis domain={[0, 100]} />
                      <Radar
                        name="Current Score"
                        dataKey="current"
                        stroke={theme.palette.primary.main}
                        fill={theme.palette.primary.main}
                        fillOpacity={0.3}
                      />
                      <Radar
                        name="Target Score"
                        dataKey="target"
                        stroke={theme.palette.success.main}
                        fill={theme.palette.success.main}
                        fillOpacity={0.1}
                      />
                      <Radar
                        name="Industry Average"
                        dataKey="industry"
                        stroke={theme.palette.warning.main}
                        fill="transparent"
                        strokeDasharray="5 5"
                      />
                      <Legend />
                    </RadarChart>
                  </ResponsiveContainer>
                )}
              </Suspense>
            </CardContent>
          </Card>
        </Grid>

        {/* Category Breakdown */}
        <Grid item xs={12} lg={4}>
          <Card sx={{ height: 400 }}>
            <CardHeader 
              title="Category Scores"
              action={
                <Tooltip title="Detailed breakdown">
                  <IconButton>
                    <ZoomInIcon />
                  </IconButton>
                </Tooltip>
              }
            />
            <CardContent sx={{ height: 320, overflow: 'auto' }}>
              {scoreAnalysis?.categoriesArray.map((category, index) => (
                <motion.div
                  key={category.name}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.1 }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      p: 2,
                      mb: 1,
                      borderRadius: 1,
                      bgcolor: selectedCategory === category.name.toLowerCase() 
                        ? 'primary.50' : 'background.paper',
                      border: `1px solid ${theme.palette.divider}`,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease-in-out',
                      '&:hover': {
                        bgcolor: 'action.hover',
                        transform: 'translateX(4px)'
                      }
                    }}
                    onClick={() => handleCategoryClick(category.name.toLowerCase())}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flex: 1 }}>
                      <Typography variant="body1" fontWeight={500}>
                        {category.name}
                      </Typography>
                      {category.trend && (
                        <Chip
                          size="small"
                          label={`${category.trend.change > 0 ? '+' : ''}${category.trend.change.toFixed(1)}%`}
                          color={category.trend.trend === 'up' ? 'success' : 
                                category.trend.trend === 'down' ? 'error' : 'default'}
                          variant="outlined"
                          sx={{ fontSize: '0.7rem', height: 20 }}
                        />
                      )}
                    </Box>
                    
                    <Box sx={{ minWidth: 100 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography 
                          variant="h6" 
                          color={category.color}
                          fontWeight={600}
                        >
                          {Math.round(category.score)}%
                        </Typography>
                        {category.trend && getTrendIcon(category.trend.trend)}
                      </Box>
                      
                      <LinearProgress
                        variant="determinate"
                        value={category.score}
                        sx={{
                          mt: 0.5,
                          height: 4,
                          borderRadius: 2,
                          '& .MuiLinearProgress-bar': {
                            backgroundColor: theme.palette[category.color]?.main || category.color
                          }
                        }}
                      />
                    </Box>
                  </Box>
                </motion.div>
              ))}
            </CardContent>
          </Card>
        </Grid>

        {/* Critical Security Insights */}
        {showInsights && criticalInsights.length > 0 && (
          <Grid item xs={12}>
            <Card>
              <CardHeader 
                title="Critical Security Insights"
                action={
                  <IconButton onClick={() => setShowInsights(false)}>
                    <FilterIcon />
                  </IconButton>
                }
              />
              <CardContent>
                <Grid container spacing={2}>
                  {criticalInsights.map((insight, index) => (
                    <Grid item xs={12} md={6} key={insight.id}>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1 }}
                      >
                        <Paper
                          sx={{
                            p: 2,
                            borderLeft: `4px solid ${getSeverityColor(insight.severity)}`,
                            bgcolor: 'background.paper'
                          }}
                        >
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                            <Chip
                              label={insight.severity.toUpperCase()}
                              color={getSeverityColorName(insight.severity)}
                              size="small"
                            />
                            <Chip
                              label={`Impact: ${insight.impact}%`}
                              variant="outlined"
                              size="small"
                            />
                          </Box>
                          
                          <Typography variant="h6" gutterBottom>
                            {insight.title}
                          </Typography>
                          
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                            {insight.description}
                          </Typography>
                          
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Typography variant="caption" color="text.secondary">
                              {insight.category}
                            </Typography>
                            {insight.automatable && (
                              <Chip
                                label="Auto-fix Available"
                                color="success"
                                variant="outlined"
                                size="small"
                              />
                            )}
                          </Box>
                        </Paper>
                      </motion.div>
                    </Grid>
                  ))}
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

// Helper functions
function getScoreColor(score: number): 'success' | 'warning' | 'error' {
  if (score >= 80) return 'success';
  if (score >= 60) return 'warning';
  return 'error';
}

function getTrendFromScore(current: number, average: number): 'up' | 'down' | 'stable' {
  const diff = current - average;
  if (diff > 2) return 'up';
  if (diff < -2) return 'down';
  return 'stable';
}

function getTrendIcon(trend: 'up' | 'down' | 'stable') {
  switch (trend) {
    case 'up': return <TrendingUpIcon color="success" fontSize="small" />;
    case 'down': return <TrendingDownIcon color="error" fontSize="small" />;
    case 'stable': return <TrendingUpIcon color="disabled" fontSize="small" />;
    default: return null;
  }
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#d32f2f';
    case 'high': return '#f57c00';
    case 'medium': return '#fbc02d';
    case 'low': return '#388e3c';
    default: return '#757575';
  }
}

function getSeverityColorName(severity: string): 'error' | 'warning' | 'info' | 'success' {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'warning';
    case 'medium': return 'info';
    case 'low': return 'success';
    default: return 'info';
  }
}

// Skeleton components
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

const ChartSkeleton: React.FC = () => (
  <Box sx={{ p: 2, height: '100%' }}>
    <Skeleton variant="rectangular" width="100%" height="100%" />
  </Box>
);

export default SecurityPostureDashboard;