'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Card,
  CardHeader,
  CardContent,
  Typography,
  Grid,
  Chip,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Paper,
  useTheme
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  DevicesIcon,
  Speed as SpeedIcon,
  TouchApp as TouchAppIcon,
  Visibility as VisibilityIcon,
  Schedule as ScheduleIcon
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area
} from 'recharts';
import { MobileAnalyticsDashboardProps } from './types';

export const MobileAnalyticsDashboard: React.FC<MobileAnalyticsDashboardProps> = ({
  config,
  analytics,
  timeRange,
  onTimeRangeChange,
  showRealTime = false
}) => {
  const theme = useTheme();

  // Chart colors matching theme
  const chartColors = [
    theme.palette.primary.main,
    theme.palette.secondary.main,
    theme.palette.success.main,
    theme.palette.warning.main,
    theme.palette.error.main,
    theme.palette.info.main
  ];

  // Memoized chart data
  const deliveryTrendData = useMemo(() => {
    return analytics.timeDistribution.map((item, index) => ({
      hour: `${item.hour}:00`,
      delivered: Math.floor(item.count * (analytics.deliveryRate / 100)),
      failed: item.count - Math.floor(item.count * (analytics.deliveryRate / 100)),
      total: item.count
    }));
  }, [analytics]);

  const deviceBreakdownData = useMemo(() => {
    return Object.entries(analytics.deviceBreakdown).map(([device, count]) => ({
      name: device.toUpperCase(),
      value: count,
      percentage: ((count / Object.values(analytics.deviceBreakdown).reduce((a, b) => a + b, 0)) * 100).toFixed(1)
    }));
  }, [analytics.deviceBreakdown]);

  const engagementData = useMemo(() => [
    { name: 'Delivered', value: analytics.delivered, color: chartColors[0] },
    { name: 'Read', value: analytics.read, color: chartColors[1] },
    { name: 'Clicked', value: analytics.clicked, color: chartColors[2] },
    { name: 'Dismissed', value: analytics.dismissed, color: chartColors[3] },
    { name: 'Failed', value: analytics.failed, color: chartColors[4] }
  ], [analytics, chartColors]);

  const performanceMetrics = useMemo(() => [
    {
      title: 'Delivery Rate',
      value: `${analytics.deliveryRate.toFixed(1)}%`,
      icon: <TrendingUpIcon />,
      color: analytics.deliveryRate >= 95 ? 'success' : analytics.deliveryRate >= 85 ? 'warning' : 'error',
      trend: '+2.3%'
    },
    {
      title: 'Avg. Delivery Time',
      value: `${analytics.averageDeliveryTime.toFixed(1)}s`,
      icon: <SpeedIcon />,
      color: analytics.averageDeliveryTime <= 3 ? 'success' : analytics.averageDeliveryTime <= 5 ? 'warning' : 'error',
      trend: '-0.5s'
    },
    {
      title: 'Engagement Score',
      value: `${analytics.engagementScore.toFixed(0)}%`,
      icon: <TouchAppIcon />,
      color: analytics.engagementScore >= 80 ? 'success' : analytics.engagementScore >= 60 ? 'warning' : 'error',
      trend: '+5.2%'
    },
    {
      title: 'Read Rate',
      value: `${analytics.readRate.toFixed(1)}%`,
      icon: <VisibilityIcon />,
      color: analytics.readRate >= 70 ? 'success' : analytics.readRate >= 50 ? 'warning' : 'error',
      trend: '+1.8%'
    }
  ], [analytics]);

  return (
    <Box sx={{ p: 2 }}>
      {/* Header with Time Range Selector */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" fontWeight={600}>
          Mobile Analytics Dashboard
        </Typography>
        
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Time Range</InputLabel>
          <Select
            value={timeRange}
            label="Time Range"
            onChange={(e) => onTimeRangeChange?.(e.target.value)}
          >
            <MenuItem value="hour">Last Hour</MenuItem>
            <MenuItem value="day">Last Day</MenuItem>
            <MenuItem value="week">Last Week</MenuItem>
            <MenuItem value="month">Last Month</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {/* Key Performance Metrics */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {performanceMetrics.map((metric, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <Box sx={{ color: `${metric.color}.main`, mr: 1 }}>
                    {metric.icon}
                  </Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    {metric.title}
                  </Typography>
                </Box>
                
                <Typography variant="h4" fontWeight={600} sx={{ mb: 0.5 }}>
                  {metric.value}
                </Typography>
                
                <Chip
                  label={metric.trend}
                  size="small"
                  color={metric.color}
                  variant="outlined"
                />
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Charts Grid */}
      <Grid container spacing={3}>
        {/* Delivery Trend Chart */}
        <Grid item xs={12} lg={8}>
          <Card>
            <CardHeader
              title="Notification Delivery Trends"
              subheader={`Last ${timeRange} • Real-time updates ${showRealTime ? 'enabled' : 'disabled'}`}
              action={
                showRealTime && (
                  <Chip
                    icon={<ScheduleIcon />}
                    label="Live"
                    color="success"
                    variant="outlined"
                    size="small"
                  />
                )
              }
            />
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={deliveryTrendData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="hour" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Area 
                    type="monotone" 
                    dataKey="delivered" 
                    stackId="1"
                    stroke={chartColors[0]} 
                    fill={chartColors[0]}
                    fillOpacity={0.8}
                    name="Delivered"
                  />
                  <Area 
                    type="monotone" 
                    dataKey="failed" 
                    stackId="1"
                    stroke={chartColors[4]} 
                    fill={chartColors[4]}
                    fillOpacity={0.8}
                    name="Failed"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Device Breakdown */}
        <Grid item xs={12} lg={4}>
          <Card>
            <CardHeader
              title="Device Breakdown"
              subheader="Notification delivery by platform"
            />
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={deviceBreakdownData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percentage }) => `${name}: ${percentage}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {deviceBreakdownData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Engagement Funnel */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader
              title="Engagement Funnel"
              subheader="User interaction with notifications"
            />
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={engagementData} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={70} />
                  <Tooltip />
                  <Bar dataKey="value" fill={(entry) => entry.color} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Top Categories */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader
              title="Top Notification Categories"
              subheader="Most active notification types"
            />
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={analytics.topCategories}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="category" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="count" fill={chartColors[0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Real-time Metrics */}
        {showRealTime && (
          <Grid item xs={12}>
            <Card>
              <CardHeader
                title="Real-time Performance"
                subheader="Live metrics updated every 30 seconds"
                action={
                  <Chip
                    icon={<TrendingUpIcon />}
                    label="Live Data"
                    color="success"
                    variant="filled"
                    size="small"
                  />
                }
              />
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={3}>
                    <Paper sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h3" color="primary">
                        {analytics.sent}
                      </Typography>
                      <Typography variant="subtitle2" color="text.secondary">
                        Total Sent
                      </Typography>
                    </Paper>
                  </Grid>
                  
                  <Grid item xs={12} sm={3}>
                    <Paper sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h3" color="success.main">
                        {analytics.delivered}
                      </Typography>
                      <Typography variant="subtitle2" color="text.secondary">
                        Delivered
                      </Typography>
                    </Paper>
                  </Grid>
                  
                  <Grid item xs={12} sm={3}>
                    <Paper sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h3" color="info.main">
                        {analytics.read}
                      </Typography>
                      <Typography variant="subtitle2" color="text.secondary">
                        Read
                      </Typography>
                    </Paper>
                  </Grid>
                  
                  <Grid item xs={12} sm={3}>
                    <Paper sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h3" color="secondary.main">
                        {analytics.clicked}
                      </Typography>
                      <Typography variant="subtitle2" color="text.secondary">
                        Clicked
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* System Health */}
        <Grid item xs={12}>
          <Card>
            <CardHeader
              title="System Health & Performance"
              subheader="Mobile notification system status"
            />
            <CardContent>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={4}>
                  <Box sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h6" gutterBottom>
                      Service Uptime
                    </Typography>
                    <Typography variant="h4" color="success.main">
                      99.9%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Last 30 days
                    </Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Box sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h6" gutterBottom>
                      Avg Response Time
                    </Typography>
                    <Typography variant="h4" color="info.main">
                      {analytics.averageDeliveryTime.toFixed(1)}s
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Push delivery
                    </Typography>
                  </Box>
                </Grid>
                
                <Grid item xs={12} sm={4}>
                  <Box sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h6" gutterBottom>
                      Error Rate
                    </Typography>
                    <Typography 
                      variant="h4" 
                      color={analytics.failed / analytics.sent < 0.05 ? 'success.main' : 'warning.main'}
                    >
                      {((analytics.failed / analytics.sent) * 100).toFixed(2)}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Delivery failures
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};