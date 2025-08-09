/**
 * Mobile Dashboard for iSECTECH Protect PWA
 * Real-time security metrics optimized for mobile viewing
 */

'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  LinearProgress,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Avatar,
  IconButton,
  useTheme,
  alpha,
  Skeleton,
  Alert,
  Collapse,
  Button,
  Divider,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as SuccessIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Visibility as ViewIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Shield as ShieldIcon,
  NetworkCheck as NetworkIcon,
  Computer as SystemIcon,
  People as UsersIcon,
  Schedule as TimeIcon,
  PriorityHigh as PriorityIcon,
} from '@mui/icons-material';
import { formatDistanceToNow, format } from 'date-fns';
import { useAppStore } from '@/lib/store';
import { useDashboard } from '@/lib/hooks/use-dashboard';

interface SecurityMetric {
  label: string;
  value: number;
  total: number;
  trend: 'up' | 'down' | 'stable';
  color: 'error' | 'warning' | 'success' | 'info';
  icon: React.ElementType;
}

interface RecentActivity {
  id: string;
  type: 'threat' | 'alert' | 'system' | 'user';
  title: string;
  description: string;
  timestamp: Date;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'resolved' | 'investigating';
}

export function MobileDashboard() {
  const theme = useTheme();
  const app = useAppStore();
  const dashboard = useDashboard();
  
  const [expandedMetrics, setExpandedMetrics] = useState(false);
  const [expandedActivity, setExpandedActivity] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  // Simulate loading and data updates
  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 1500);
    const updateTimer = setInterval(() => {
      setLastUpdate(new Date());
    }, 30000); // Update every 30 seconds

    return () => {
      clearTimeout(timer);
      clearInterval(updateTimer);
    };
  }, []);

  // Mock security metrics
  const securityMetrics: SecurityMetric[] = useMemo(() => [
    {
      label: 'Active Threats',
      value: 3,
      total: 100,
      trend: 'down',
      color: 'error',
      icon: ErrorIcon,
    },
    {
      label: 'Vulnerabilities',
      value: 12,
      total: 50,
      trend: 'down',
      color: 'warning',
      icon: WarningIcon,
    },
    {
      label: 'Protected Assets',
      value: 847,
      total: 850,
      trend: 'up',
      color: 'success',
      icon: ShieldIcon,
    },
    {
      label: 'System Health',
      value: 94,
      total: 100,
      trend: 'stable',
      color: 'success',
      icon: SystemIcon,
    },
  ], []);

  // Mock recent activity
  const recentActivity: RecentActivity[] = useMemo(() => [
    {
      id: '1',
      type: 'threat',
      title: 'Malware Detected',
      description: 'Suspicious activity on workstation WS-2019-041',
      timestamp: new Date(Date.now() - 5 * 60 * 1000),
      severity: 'critical',
      status: 'investigating',
    },
    {
      id: '2',
      type: 'alert',
      title: 'Failed Login Attempts',
      description: 'Multiple failed login attempts detected',
      timestamp: new Date(Date.now() - 15 * 60 * 1000),
      severity: 'high',
      status: 'active',
    },
    {
      id: '3',
      type: 'system',
      title: 'Security Update Applied',
      description: 'Critical security patch installed on 45 systems',
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
      severity: 'medium',
      status: 'resolved',
    },
    {
      id: '4',
      type: 'user',
      title: 'New User Access',
      description: 'Admin privileges granted to john.doe@company.com',
      timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000),
      severity: 'medium',
      status: 'resolved',
    },
  ], []);

  const getActivityIcon = (type: RecentActivity['type']) => {
    switch (type) {
      case 'threat': return SecurityIcon;
      case 'alert': return WarningIcon;
      case 'system': return SystemIcon;
      case 'user': return UsersIcon;
      default: return SecurityIcon;
    }
  };

  const getActivityColor = (severity: RecentActivity['severity']) => {
    switch (severity) {
      case 'critical': return theme.palette.error.main;
      case 'high': return theme.palette.warning.main;
      case 'medium': return theme.palette.info.main;
      case 'low': return theme.palette.success.main;
      default: return theme.palette.text.secondary;
    }
  };

  const getStatusColor = (status: RecentActivity['status']) => {
    switch (status) {
      case 'active': return 'error';
      case 'investigating': return 'warning';
      case 'resolved': return 'success';
      default: return 'default';
    }
  };

  const renderMetricCard = (metric: SecurityMetric, index: number) => {
    const Icon = metric.icon;
    const percentage = (metric.value / metric.total) * 100;
    const TrendIcon = metric.trend === 'up' ? TrendingUpIcon : 
                     metric.trend === 'down' ? TrendingDownIcon : null;

    return (
      <Grid item xs={6} key={metric.label}>
        <Card
          sx={{
            height: '100%',
            border: `1px solid ${alpha(theme.palette[metric.color].main, 0.3)}`,
            '&:hover': {
              boxShadow: theme.shadows[4],
              transform: 'translateY(-2px)',
              transition: 'all 0.2s ease-in-out',
            },
          }}
        >
          <CardContent sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <Avatar
                sx={{
                  bgcolor: alpha(theme.palette[metric.color].main, 0.1),
                  color: theme.palette[metric.color].main,
                  width: 32,
                  height: 32,
                  mr: 1,
                }}
              >
                <Icon sx={{ fontSize: 18 }} />
              </Avatar>
              {TrendIcon && (
                <TrendIcon
                  sx={{
                    fontSize: 16,
                    color: metric.trend === 'up' ? 'success.main' : 'error.main',
                    ml: 'auto',
                  }}
                />
              )}
            </Box>
            
            <Typography
              variant="h5"
              component="div"
              sx={{ fontWeight: 700, color: theme.palette[metric.color].main }}
            >
              {loading ? <Skeleton width="60%" /> : metric.value.toLocaleString()}
            </Typography>
            
            <Typography variant="caption" color="text.secondary" sx={{ mb: 1 }}>
              {metric.label}
            </Typography>
            
            {metric.total > metric.value && (
              <LinearProgress
                variant="determinate"
                value={percentage}
                color={metric.color}
                sx={{
                  height: 4,
                  borderRadius: 2,
                  bgcolor: alpha(theme.palette[metric.color].main, 0.1),
                }}
              />
            )}
          </CardContent>
        </Card>
      </Grid>
    );
  };

  const renderActivityItem = (activity: RecentActivity) => {
    const Icon = getActivityIcon(activity.type);
    const activityColor = getActivityColor(activity.severity);
    
    return (
      <ListItem
        key={activity.id}
        sx={{
          bgcolor: alpha(activityColor, 0.05),
          borderRadius: 1,
          mb: 1,
          border: `1px solid ${alpha(activityColor, 0.2)}`,
        }}
      >
        <ListItemIcon>
          <Avatar
            sx={{
              bgcolor: alpha(activityColor, 0.1),
              color: activityColor,
              width: 32,
              height: 32,
            }}
          >
            <Icon sx={{ fontSize: 16 }} />
          </Avatar>
        </ListItemIcon>
        
        <ListItemText
          primary={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" sx={{ fontWeight: 600, flexGrow: 1 }}>
                {activity.title}
              </Typography>
              <Chip
                label={activity.status}
                size="small"
                color={getStatusColor(activity.status) as any}
                variant="outlined"
                sx={{ fontSize: '0.6rem', height: 20 }}
              />
            </Box>
          }
          secondary={
            <Box>
              <Typography variant="caption" color="text.secondary">
                {activity.description}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5 }}>
                <TimeIcon sx={{ fontSize: 10, mr: 0.5, color: 'text.disabled' }} />
                <Typography variant="caption" color="text.disabled">
                  {formatDistanceToNow(activity.timestamp, { addSuffix: true })}
                </Typography>
                <Chip
                  label={activity.severity}
                  size="small"
                  variant="outlined"
                  sx={{ 
                    fontSize: '0.5rem', 
                    height: 16, 
                    ml: 1,
                    borderColor: activityColor,
                    color: activityColor,
                  }}
                />
              </Box>
            </Box>
          }
        />
        
        <IconButton size="small">
          <ViewIcon fontSize="small" />
        </IconButton>
      </ListItem>
    );
  };

  return (
    <Box sx={{ p: 2, pb: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
          Security Overview
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <NetworkIcon sx={{ fontSize: 14, color: 'success.main' }} />
          <Typography variant="caption" color="text.secondary">
            Last updated {formatDistanceToNow(lastUpdate, { addSuffix: true })}
          </Typography>
        </Box>
      </Box>

      {/* Alert Banner */}
      {securityMetrics[0].value > 0 && (
        <Alert
          severity="warning"
          sx={{ mb: 3 }}
          action={
            <Button size="small" color="inherit">
              View Details
            </Button>
          }
        >
          <Typography variant="body2">
            <strong>{securityMetrics[0].value} active threats</strong> require immediate attention
          </Typography>
        </Alert>
      )}

      {/* Security Metrics */}
      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ p: 2, pb: '16px !important' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Security Metrics
            </Typography>
            <IconButton
              size="small"
              onClick={() => setExpandedMetrics(!expandedMetrics)}
            >
              {expandedMetrics ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </IconButton>
          </Box>

          <Grid container spacing={2}>
            {securityMetrics.slice(0, expandedMetrics ? undefined : 2).map(renderMetricCard)}
          </Grid>

          {!expandedMetrics && securityMetrics.length > 2 && (
            <Box sx={{ textAlign: 'center', mt: 2 }}>
              <Button
                size="small"
                onClick={() => setExpandedMetrics(true)}
                startIcon={<ExpandMoreIcon />}
              >
                Show More Metrics
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Recent Activity */}
      <Card>
        <CardContent sx={{ p: 2, pb: '16px !important' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Recent Activity
            </Typography>
            <IconButton
              size="small"
              onClick={() => setExpandedActivity(!expandedActivity)}
            >
              {expandedActivity ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </IconButton>
          </Box>

          <List sx={{ p: 0 }}>
            {loading ? (
              Array.from({ length: 3 }).map((_, index) => (
                <ListItem key={index} sx={{ mb: 1 }}>
                  <ListItemIcon>
                    <Skeleton variant="circular" width={32} height={32} />
                  </ListItemIcon>
                  <ListItemText
                    primary={<Skeleton width="70%" />}
                    secondary={<Skeleton width="90%" />}
                  />
                </ListItem>
              ))
            ) : (
              recentActivity
                .slice(0, expandedActivity ? undefined : 3)
                .map(renderActivityItem)
            )}
          </List>

          {!expandedActivity && recentActivity.length > 3 && (
            <Box sx={{ textAlign: 'center', mt: 2 }}>
              <Button
                size="small"
                onClick={() => setExpandedActivity(true)}
                startIcon={<ExpandMoreIcon />}
              >
                Show More Activity
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card sx={{ mt: 3 }}>
        <CardContent sx={{ p: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
            Quick Actions
          </Typography>
          
          <Grid container spacing={1}>
            <Grid item xs={6}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<SecurityIcon />}
                size="small"
              >
                Run Scan
              </Button>
            </Grid>
            <Grid item xs={6}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<PriorityIcon />}
                size="small"
                color="error"
              >
                Emergency
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    </Box>
  );
}

export default MobileDashboard;