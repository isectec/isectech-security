'use client';

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  Box,
  Card,
  CardHeader,
  CardContent,
  Typography,
  Chip,
  Alert,
  CircularProgress,
  IconButton,
  Tooltip,
  Badge,
  Fab,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  useTheme,
  useMediaQuery,
  Snackbar,
  LinearProgress
} from '@mui/material';
import {
  Psychology as PsychologyIcon,
  AutoAwesome as AutoAwesomeIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  Chat as ChatIcon,
  Assessment as AssessmentIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  Speed as SpeedIcon,
  Security as SecurityIcon,
  Insights as InsightsIcon,
  Close as CloseIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useWebSocket } from '../../../lib/hooks/use-websocket';
import { usePerformanceMonitor } from '../../../lib/hooks/use-performance-monitor';
import { ExecutiveInsightsEngine } from './executive-insights-engine';
import { ExecutiveAnomalyDetector } from './executive-anomaly-detector';
import { ExecutiveNLQInterface } from './executive-nlq-interface';
import { ExecutiveReportGenerator } from './executive-report-generator';
import { ExecutivePredictiveEngine } from './executive-predictive-engine';
import {
  ExecutiveAgentProps,
  ExecutiveInsight,
  ExecutiveAnomaly,
  ExecutivePrediction,
  ExecutiveReport,
  ExecutiveQuery,
  AgentEvent,
  AgentMetrics
} from './types';

export const ExecutiveAgent: React.FC<ExecutiveAgentProps> = ({
  config,
  onInsightGenerated,
  onAnomalyDetected,
  onPredictionUpdated,
  onReportGenerated,
  onQueryProcessed,
  className,
  children
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  // State management
  const [agentStatus, setAgentStatus] = useState<'initializing' | 'active' | 'idle' | 'error'>('initializing');
  const [activeInsights, setActiveInsights] = useState<ExecutiveInsight[]>([]);
  const [recentAnomalies, setRecentAnomalies] = useState<ExecutiveAnomaly[]>([]);
  const [activePredictions, setActivePredictions] = useState<ExecutivePrediction[]>([]);
  const [agentDrawerOpen, setAgentDrawerOpen] = useState(false);
  const [nlqInterface, setNLQInterface] = useState(false);
  const [notifications, setNotifications] = useState<AgentEvent[]>([]);
  const [metrics, setMetrics] = useState<AgentMetrics>({
    insightAccuracy: 0.95,
    anomalyDetectionRate: 0.87,
    falsePositiveRate: 0.03,
    responseTime: 1200,
    userSatisfaction: 4.2,
    adoptionRate: 0.78,
    systemLoad: { cpu: 15, memory: 45, network: 8 },
    dataProcessingStats: { recordsProcessed: 0, errorRate: 0, latency: 0 }
  });

  // Performance monitoring
  const { performanceData, trackEvent } = usePerformanceMonitor();
  
  // WebSocket connection for real-time agent coordination
  const { isConnected, sendMessage, lastMessage } = useWebSocket(
    `/api/executive-agent/ws?userId=${config.userId}&tenantId=${config.tenantId}`,
    {
      onMessage: handleAgentMessage,
      onError: handleAgentError,
      onConnect: handleAgentConnect,
      reconnectAttempts: 5,
      reconnectInterval: 3000
    }
  );

  // Agent initialization
  useEffect(() => {
    initializeAgent();
    return () => {
      // Cleanup agent resources
      setAgentStatus('idle');
    };
  }, [config]);

  // Real-time message handling
  useEffect(() => {
    if (lastMessage) {
      handleAgentMessage(lastMessage);
    }
  }, [lastMessage]);

  const initializeAgent = async () => {
    try {
      setAgentStatus('initializing');
      trackEvent('agent_initialization_start');
      
      // Initialize agent components
      await Promise.all([
        initializeInsightsEngine(),
        initializeAnomalyDetector(),
        initializePredictiveEngine(),
        loadUserPreferences(),
        establishDataConnections()
      ]);
      
      setAgentStatus('active');
      trackEvent('agent_initialization_complete', { duration: Date.now() });
      
      // Send agent ready notification
      addNotification({
        type: 'insight-generated',
        timestamp: new Date(),
        data: { message: 'Executive AI Agent is now active and monitoring your security landscape' },
        userId: config.userId,
        tenantId: config.tenantId
      });
      
    } catch (error) {
      console.error('Agent initialization failed:', error);
      setAgentStatus('error');
      trackEvent('agent_initialization_error', { error: error.message });
    }
  };

  const initializeInsightsEngine = async () => {
    // Initialize AI insights generation
    console.log('Initializing insights engine with config:', config.preferences);
  };

  const initializeAnomalyDetector = async () => {
    // Initialize anomaly detection algorithms
    console.log('Initializing anomaly detector with sensitivity:', config.preferences.anomalyDetectionSensitivity);
  };

  const initializePredictiveEngine = async () => {
    // Initialize predictive analytics models
    console.log('Initializing predictive engine with horizon:', config.preferences.predictiveAnalyticsHorizon);
  };

  const loadUserPreferences = async () => {
    // Load user-specific preferences and configurations
    console.log('Loading user preferences for:', config.userRole);
  };

  const establishDataConnections = async () => {
    // Establish connections to data sources
    console.log('Establishing data connections for tenant:', config.tenantId);
  };

  const handleAgentMessage = useCallback((message: any) => {
    try {
      const event: AgentEvent = JSON.parse(message.data);
      processAgentEvent(event);
    } catch (error) {
      console.error('Failed to process agent message:', error);
    }
  }, []);

  const handleAgentError = useCallback((error: Event) => {
    console.error('Agent WebSocket error:', error);
    setAgentStatus('error');
  }, []);

  const handleAgentConnect = useCallback(() => {
    console.log('Agent WebSocket connected');
  }, []);

  const processAgentEvent = (event: AgentEvent) => {
    addNotification(event);
    
    switch (event.type) {
      case 'insight-generated':
        handleInsightGenerated(event.data as ExecutiveInsight);
        break;
      case 'anomaly-detected':
        handleAnomalyDetected(event.data as ExecutiveAnomaly);
        break;
      case 'prediction-updated':
        handlePredictionUpdated(event.data as ExecutivePrediction);
        break;
      case 'report-generated':
        handleReportGenerated(event.data as ExecutiveReport);
        break;
      case 'query-processed':
        handleQueryProcessed(event.data as ExecutiveQuery);
        break;
    }
  };

  const handleInsightGenerated = useCallback((insight: ExecutiveInsight) => {
    setActiveInsights(prev => [insight, ...prev.slice(0, 9)]); // Keep top 10 insights
    onInsightGenerated?.(insight);
    
    // Update metrics
    setMetrics(prev => ({
      ...prev,
      insightAccuracy: Math.min(prev.insightAccuracy + 0.001, 1.0)
    }));
  }, [onInsightGenerated]);

  const handleAnomalyDetected = useCallback((anomaly: ExecutiveAnomaly) => {
    setRecentAnomalies(prev => [anomaly, ...prev.slice(0, 4)]); // Keep top 5 anomalies
    onAnomalyDetected?.(anomaly);
    
    // Update metrics
    setMetrics(prev => ({
      ...prev,
      anomalyDetectionRate: Math.min(prev.anomalyDetectionRate + 0.001, 1.0)
    }));
  }, [onAnomalyDetected]);

  const handlePredictionUpdated = useCallback((prediction: ExecutivePrediction) => {
    setActivePredictions(prev => {
      const updated = prev.filter(p => p.id !== prediction.id);
      return [prediction, ...updated.slice(0, 2)]; // Keep top 3 predictions
    });
    onPredictionUpdated?.(prediction);
  }, [onPredictionUpdated]);

  const handleReportGenerated = useCallback((report: ExecutiveReport) => {
    onReportGenerated?.(report);
  }, [onReportGenerated]);

  const handleQueryProcessed = useCallback((query: ExecutiveQuery) => {
    onQueryProcessed?.(query);
  }, [onQueryProcessed]);

  const addNotification = (event: AgentEvent) => {
    setNotifications(prev => [event, ...prev.slice(0, 19)]); // Keep top 20 notifications
  };

  const getAgentStatusColor = () => {
    switch (agentStatus) {
      case 'active': return 'success';
      case 'idle': return 'warning';
      case 'error': return 'error';
      default: return 'info';
    }
  };

  const getAgentStatusIcon = () => {
    switch (agentStatus) {
      case 'active': return <PsychologyIcon />;
      case 'idle': return <PsychologyIcon />;
      case 'error': return <WarningIcon />;
      default: return <CircularProgress size={20} />;
    }
  };

  // Memoized components for performance
  const insightsEngine = useMemo(() => (
    config.capabilities.aiInsights && (
      <ExecutiveInsightsEngine
        config={config}
        onInsightGenerated={handleInsightGenerated}
        enabled={agentStatus === 'active'}
      />
    )
  ), [config, agentStatus, handleInsightGenerated]);

  const anomalyDetector = useMemo(() => (
    config.capabilities.anomalyDetection && (
      <ExecutiveAnomalyDetector
        config={config}
        onAnomalyDetected={handleAnomalyDetected}
        metrics={[]} // Will be populated with real metrics
        sensitivity={config.preferences.anomalyDetectionSensitivity}
        enabled={agentStatus === 'active'}
      />
    )
  ), [config, agentStatus, handleAnomalyDetected]);

  const predictiveEngine = useMemo(() => (
    config.capabilities.predictiveAnalytics && (
      <ExecutivePredictiveEngine
        config={config}
        onPredictionUpdated={handlePredictionUpdated}
        horizon={config.preferences.predictiveAnalyticsHorizon}
        models={['security-trend', 'threat-forecast', 'compliance-projection']}
        enabled={agentStatus === 'active'}
      />
    )
  ), [config, agentStatus, handlePredictionUpdated]);

  const reportGenerator = useMemo(() => (
    config.capabilities.automatedReporting && (
      <ExecutiveReportGenerator
        config={config}
        onReportGenerated={handleReportGenerated}
        schedule={config.preferences.reportGenerationSchedule}
        autoGenerate={true}
      />
    )
  ), [config, handleReportGenerated]);

  return (
    <Box className={className} sx={{ position: 'relative' }}>
      {/* Agent Status Indicator */}
      <Card
        sx={{
          position: 'fixed',
          top: isMobile ? 80 : 120,
          right: 16,
          zIndex: 1300,
          minWidth: 280,
          boxShadow: theme.shadows[8],
          bgcolor: 'background.paper',
          border: `2px solid ${theme.palette[getAgentStatusColor()].main}`
        }}
      >
        <CardHeader
          avatar={
            <Badge
              badgeContent={notifications.length}
              color="error"
              max={99}
            >
              {getAgentStatusIcon()}
            </Badge>
          }
          title={
            <Typography variant="subtitle2" fontWeight={600}>
              AI Executive Agent
            </Typography>
          }
          subheader={
            <Chip
              label={agentStatus.toUpperCase()}
              size="small"
              color={getAgentStatusColor()}
              variant="filled"
            />
          }
          action={
            <Tooltip title="Agent Dashboard">
              <IconButton
                size="small"
                onClick={() => setAgentDrawerOpen(true)}
              >
                <SettingsIcon />
              </IconButton>
            </Tooltip>
          }
          sx={{ pb: 1 }}
        />
        
        <CardContent sx={{ pt: 0 }}>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
            {activeInsights.length > 0 && (
              <Chip
                icon={<InsightsIcon />}
                label={`${activeInsights.length} Insights`}
                size="small"
                color="primary"
                variant="outlined"
                onClick={() => setAgentDrawerOpen(true)}
              />
            )}
            
            {recentAnomalies.length > 0 && (
              <Chip
                icon={<WarningIcon />}
                label={`${recentAnomalies.length} Anomalies`}
                size="small"
                color="warning"
                variant="outlined"
                onClick={() => setAgentDrawerOpen(true)}
              />
            )}
            
            {activePredictions.length > 0 && (
              <Chip
                icon={<TrendingUpIcon />}
                label={`${activePredictions.length} Predictions`}
                size="small"
                color="info"
                variant="outlined"
                onClick={() => setAgentDrawerOpen(true)}
              />
            )}
          </Box>
          
          {/* Performance Metrics */}
          <Box sx={{ mb: 1 }}>
            <Typography variant="caption" color="text.secondary">
              Accuracy: {Math.round(metrics.insightAccuracy * 100)}% | 
              Response: {metrics.responseTime}ms |
              Detection: {Math.round(metrics.anomalyDetectionRate * 100)}%
            </Typography>
          </Box>
          
          {/* System Load Indicator */}
          <LinearProgress
            variant="determinate"
            value={metrics.systemLoad.cpu}
            sx={{ height: 6, borderRadius: 3 }}
            color={metrics.systemLoad.cpu > 80 ? 'warning' : 'success'}
          />
          <Typography variant="caption" color="text.secondary">
            System Load: {metrics.systemLoad.cpu}%
          </Typography>
        </CardContent>
      </Card>

      {/* Natural Language Query FAB */}
      {config.capabilities.naturalLanguageQuery && (
        <Fab
          color="primary"
          sx={{ 
            position: 'fixed', 
            bottom: 80, 
            right: 16,
            zIndex: 1300
          }}
          onClick={() => setNLQInterface(true)}
        >
          <ChatIcon />
        </Fab>
      )}

      {/* Agent Components (Hidden) */}
      <Box sx={{ display: 'none' }}>
        {insightsEngine}
        {anomalyDetector}
        {predictiveEngine}
        {reportGenerator}
      </Box>

      {/* Natural Language Query Interface */}
      {config.capabilities.naturalLanguageQuery && (
        <ExecutiveNLQInterface
          config={config}
          onQueryProcessed={handleQueryProcessed}
          contextAware={true}
          voiceEnabled={true}
        />
      )}

      {/* Agent Dashboard Drawer */}
      <Drawer
        anchor="right"
        open={agentDrawerOpen}
        onClose={() => setAgentDrawerOpen(false)}
        PaperProps={{
          sx: { width: isMobile ? '100%' : 400, maxWidth: '100vw' }
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">AI Agent Dashboard</Typography>
            <IconButton onClick={() => setAgentDrawerOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>

          {/* Agent Status */}
          <Card sx={{ mb: 2 }}>
            <CardContent>
              <Typography variant="subtitle2" gutterBottom>Agent Status</Typography>
              <Chip
                icon={getAgentStatusIcon()}
                label={agentStatus.toUpperCase()}
                color={getAgentStatusColor()}
                variant="filled"
                sx={{ mb: 1 }}
              />
              <Typography variant="body2" color="text.secondary">
                Connection: {isConnected ? 'Connected' : 'Disconnected'}
              </Typography>
            </CardContent>
          </Card>

          {/* Recent Insights */}
          {activeInsights.length > 0 && (
            <Card sx={{ mb: 2 }}>
              <CardHeader
                title="Recent Insights"
                titleTypographyProps={{ variant: 'subtitle2' }}
                avatar={<InsightsIcon color="primary" />}
              />
              <CardContent sx={{ pt: 0 }}>
                <List dense>
                  {activeInsights.slice(0, 3).map((insight, index) => (
                    <ListItem key={insight.id} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <Chip
                          label={insight.severity}
                          size="small"
                          color={insight.severity === 'critical' ? 'error' : 'warning'}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={insight.title}
                        secondary={insight.description}
                        primaryTypographyProps={{ variant: 'body2' }}
                        secondaryTypographyProps={{ variant: 'caption' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          )}

          {/* Recent Anomalies */}
          {recentAnomalies.length > 0 && (
            <Card sx={{ mb: 2 }}>
              <CardHeader
                title="Recent Anomalies"
                titleTypographyProps={{ variant: 'subtitle2' }}
                avatar={<WarningIcon color="warning" />}
              />
              <CardContent sx={{ pt: 0 }}>
                <List dense>
                  {recentAnomalies.slice(0, 3).map((anomaly, index) => (
                    <ListItem key={anomaly.id} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <Chip
                          label={anomaly.severity}
                          size="small"
                          color={anomaly.severity === 'critical' ? 'error' : 'warning'}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={anomaly.title}
                        secondary={`${Math.round(anomaly.confidence * 100)}% confidence`}
                        primaryTypographyProps={{ variant: 'body2' }}
                        secondaryTypographyProps={{ variant: 'caption' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          )}

          {/* Performance Metrics */}
          <Card>
            <CardHeader
              title="Performance Metrics"
              titleTypographyProps={{ variant: 'subtitle2' }}
              avatar={<SpeedIcon color="info" />}
            />
            <CardContent sx={{ pt: 0 }}>
              <Typography variant="body2" gutterBottom>
                Insight Accuracy: {Math.round(metrics.insightAccuracy * 100)}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={metrics.insightAccuracy * 100}
                sx={{ mb: 2, height: 6, borderRadius: 3 }}
                color="success"
              />
              
              <Typography variant="body2" gutterBottom>
                Response Time: {metrics.responseTime}ms
              </Typography>
              <LinearProgress
                variant="determinate"
                value={Math.max(0, 100 - (metrics.responseTime / 50))}
                sx={{ mb: 2, height: 6, borderRadius: 3 }}
                color="info"
              />
              
              <Typography variant="body2" gutterBottom>
                User Satisfaction: {metrics.userSatisfaction}/5.0
              </Typography>
              <LinearProgress
                variant="determinate"
                value={(metrics.userSatisfaction / 5) * 100}
                sx={{ height: 6, borderRadius: 3 }}
                color="primary"
              />
            </CardContent>
          </Card>
        </Box>
      </Drawer>

      {/* Notification Snackbar */}
      <Snackbar
        open={notifications.length > 0 && agentStatus === 'active'}
        autoHideDuration={6000}
        onClose={() => setNotifications(prev => prev.slice(1))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Alert
          severity="info"
          icon={<AutoAwesomeIcon />}
          action={
            <IconButton
              size="small"
              aria-label="close"
              color="inherit"
              onClick={() => setNotifications(prev => prev.slice(1))}
            >
              <CloseIcon fontSize="small" />
            </IconButton>
          }
        >
          {notifications[0]?.data?.message || 'New AI insight available'}
        </Alert>
      </Snackbar>

      {children}
    </Box>
  );
};