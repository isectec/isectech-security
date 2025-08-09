'use client';

import React, { useState, useCallback, useMemo } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardHeader,
  Switch,
  FormControlLabel,
  Slider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  IconButton,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  Divider,
  TextField,
  Tab,
  Tabs,
  Paper,
  useTheme,
  useMediaQuery
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  Business as BusinessIcon,
  Timeline as TimelineIcon,
  ExpandMore as ExpandMoreIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  DragIndicator as DragIcon,
  Palette as PaletteIcon,
  Speed as SpeedIcon,
  Notifications as NotificationsIcon,
  Save as SaveIcon,
  RestoreFromTrash as ResetIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';

interface ExecutiveCustomizationProps {
  open: boolean;
  onClose: () => void;
  config: DashboardConfig;
  onConfigChange: (config: DashboardConfig) => void;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
}

interface DashboardConfig {
  layout: 'compact' | 'detailed' | 'executive';
  refreshInterval: number;
  widgets: WidgetConfig[];
  theme: 'light' | 'dark' | 'auto';
  mobileOptimized: boolean;
  notifications: NotificationConfig;
  performance: PerformanceConfig;
  accessibility: AccessibilityConfig;
}

interface WidgetConfig {
  id: string;
  type: string;
  position: { x: number; y: number; w: number; h: number };
  visible: boolean;
  settings: WidgetSettings;
  customTitle?: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

interface WidgetSettings {
  showTrends: boolean;
  showConfidenceScore: boolean;
  compactView: boolean;
  alertThreshold?: number;
  refreshRate?: number;
  dataPoints?: number;
  colorScheme?: 'default' | 'executive' | 'high-contrast';
}

interface NotificationConfig {
  enabled: boolean;
  criticalAlerts: boolean;
  executiveBriefings: boolean;
  complianceUpdates: boolean;
  threatAlerts: boolean;
  frequency: 'realtime' | 'hourly' | 'daily' | 'weekly';
}

interface PerformanceConfig {
  enableAnimations: boolean;
  dataCaching: boolean;
  backgroundRefresh: boolean;
  lowBandwidthMode: boolean;
  preloadWidgets: boolean;
}

interface AccessibilityConfig {
  highContrast: boolean;
  largeText: boolean;
  reducedMotion: boolean;
  screenReaderOptimized: boolean;
}

const AVAILABLE_WIDGETS = [
  {
    id: 'security-posture',
    type: 'kpi-card',
    title: 'Security Posture',
    description: 'Overall security health score and trends',
    icon: <SecurityIcon />,
    category: 'core',
    executiveRelevance: 'critical'
  },
  {
    id: 'threat-landscape',
    type: 'threat-overview',
    title: 'Threat Landscape',
    description: 'Current threat level and emerging risks',
    icon: <AssessmentIcon />,
    category: 'security',
    executiveRelevance: 'high'
  },
  {
    id: 'compliance-dashboard',
    type: 'compliance',
    title: 'Compliance Status',
    description: 'Multi-framework compliance scores',
    icon: <BusinessIcon />,
    category: 'governance',
    executiveRelevance: 'critical'
  },
  {
    id: 'roi-metrics',
    type: 'financial',
    title: 'Security ROI',
    description: 'Investment returns and cost analysis',
    icon: <TimelineIcon />,
    category: 'business',
    executiveRelevance: 'high'
  },
  {
    id: 'predictive-analytics',
    type: 'predictive',
    title: 'Predictive Analytics',
    description: 'AI-powered insights and recommendations',
    icon: <DashboardIcon />,
    category: 'analytics',
    executiveRelevance: 'medium'
  }
];

export const ExecutiveCustomization: React.FC<ExecutiveCustomizationProps> = ({
  open,
  onClose,
  config,
  onConfigChange,
  userRole
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  const [activeTab, setActiveTab] = useState(0);
  const [tempConfig, setTempConfig] = useState<DashboardConfig>(config);
  const [hasChanges, setHasChanges] = useState(false);

  // Executive role permissions
  const rolePermissions = useMemo(() => {
    switch (userRole) {
      case 'ceo':
        return {
          canModifyLayout: true,
          canConfigureNotifications: true,
          canAccessAdvancedSettings: true,
          widgetPriority: 'business-focused'
        };
      case 'ciso':
        return {
          canModifyLayout: true,
          canConfigureNotifications: true,
          canAccessAdvancedSettings: true,
          widgetPriority: 'security-focused'
        };
      case 'board_member':
        return {
          canModifyLayout: false,
          canConfigureNotifications: false,
          canAccessAdvancedSettings: false,
          widgetPriority: 'summary-only'
        };
      case 'executive_assistant':
        return {
          canModifyLayout: false,
          canConfigureNotifications: true,
          canAccessAdvancedSettings: false,
          widgetPriority: 'operational-focused'
        };
      default:
        return {
          canModifyLayout: false,
          canConfigureNotifications: false,
          canAccessAdvancedSettings: false,
          widgetPriority: 'basic'
        };
    }
  }, [userRole]);

  // Filter widgets based on role
  const availableWidgets = useMemo(() => {
    return AVAILABLE_WIDGETS.filter(widget => {
      if (userRole === 'board_member') {
        return widget.executiveRelevance === 'critical';
      }
      if (userRole === 'executive_assistant') {
        return widget.category !== 'security' || widget.executiveRelevance !== 'medium';
      }
      return true;
    });
  }, [userRole]);

  const handleConfigUpdate = useCallback((updates: Partial<DashboardConfig>) => {
    const newConfig = { ...tempConfig, ...updates };
    setTempConfig(newConfig);
    setHasChanges(true);
  }, [tempConfig]);

  const handleWidgetToggle = useCallback((widgetId: string) => {
    const updatedWidgets = tempConfig.widgets.map(widget => 
      widget.id === widgetId 
        ? { ...widget, visible: !widget.visible }
        : widget
    );
    
    // If widget doesn't exist, create it
    if (!tempConfig.widgets.find(w => w.id === widgetId)) {
      const widgetDef = availableWidgets.find(w => w.id === widgetId);
      if (widgetDef) {
        updatedWidgets.push({
          id: widgetId,
          type: widgetDef.type,
          position: { x: 0, y: 0, w: 4, h: 3 },
          visible: true,
          settings: {
            showTrends: true,
            showConfidenceScore: userRole !== 'board_member',
            compactView: isMobile,
            colorScheme: 'executive'
          },
          priority: widgetDef.executiveRelevance as 'low' | 'medium' | 'high' | 'critical'
        });
      }
    }
    
    handleConfigUpdate({ widgets: updatedWidgets });
  }, [tempConfig.widgets, availableWidgets, handleConfigUpdate, userRole, isMobile]);

  const handleWidgetSettings = useCallback((widgetId: string, settings: Partial<WidgetSettings>) => {
    const updatedWidgets = tempConfig.widgets.map(widget =>
      widget.id === widgetId
        ? { ...widget, settings: { ...widget.settings, ...settings } }
        : widget
    );
    handleConfigUpdate({ widgets: updatedWidgets });
  }, [tempConfig.widgets, handleConfigUpdate]);

  const handleSave = useCallback(() => {
    onConfigChange(tempConfig);
    setHasChanges(false);
    onClose();
  }, [tempConfig, onConfigChange, onClose]);

  const handleReset = useCallback(() => {
    const defaultConfig: DashboardConfig = {
      layout: 'executive',
      refreshInterval: 30000,
      widgets: [],
      theme: 'auto',
      mobileOptimized: true,
      notifications: {
        enabled: true,
        criticalAlerts: true,
        executiveBriefings: true,
        complianceUpdates: userRole !== 'board_member',
        threatAlerts: userRole === 'ciso' || userRole === 'ceo',
        frequency: 'hourly'
      },
      performance: {
        enableAnimations: !isMobile,
        dataCaching: true,
        backgroundRefresh: true,
        lowBandwidthMode: false,
        preloadWidgets: true
      },
      accessibility: {
        highContrast: false,
        largeText: false,
        reducedMotion: false,
        screenReaderOptimized: false
      }
    };
    setTempConfig(defaultConfig);
    setHasChanges(true);
  }, [userRole, isMobile]);

  const TabPanel = ({ children, value, index }: any) => (
    <div role="tabpanel" hidden={value !== index}>
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      fullScreen={isMobile}
      PaperProps={{
        sx: { minHeight: '70vh', maxHeight: '90vh' }
      }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <SettingsIcon />
          <Typography variant="h6">Dashboard Customization</Typography>
          <Chip 
            label={userRole.replace('_', ' ').toUpperCase()} 
            size="small" 
            color="primary" 
            variant="outlined" 
          />
        </Box>
      </DialogTitle>

      <DialogContent>
        <Box sx={{ width: '100%' }}>
          <Tabs 
            value={activeTab} 
            onChange={(e, newValue) => setActiveTab(newValue)}
            variant={isMobile ? "scrollable" : "fullWidth"}
            scrollButtons="auto"
          >
            <Tab label="Widgets" icon={<DashboardIcon />} />
            <Tab label="Layout" icon={<PaletteIcon />} />
            {rolePermissions.canConfigureNotifications && (
              <Tab label="Notifications" icon={<NotificationsIcon />} />
            )}
            {rolePermissions.canAccessAdvancedSettings && (
              <Tab label="Performance" icon={<SpeedIcon />} />
            )}
          </Tabs>

          {/* Widgets Tab */}
          <TabPanel value={activeTab} index={0}>
            <Typography variant="h6" sx={{ mb: 3 }}>
              Available Widgets
            </Typography>
            
            <Grid container spacing={2}>
              {availableWidgets.map((widget) => {
                const isVisible = tempConfig.widgets.find(w => w.id === widget.id)?.visible ?? false;
                const widgetConfig = tempConfig.widgets.find(w => w.id === widget.id);
                
                return (
                  <Grid item xs={12} md={6} key={widget.id}>
                    <Card 
                      variant="outlined" 
                      sx={{ 
                        bgcolor: isVisible ? 'primary.light' : 'background.default',
                        opacity: isVisible ? 1 : 0.7,
                        transition: 'all 0.3s ease'
                      }}
                    >
                      <CardHeader
                        avatar={widget.icon}
                        title={widget.title}
                        subheader={widget.description}
                        action={
                          <Switch
                            checked={isVisible}
                            onChange={() => handleWidgetToggle(widget.id)}
                            disabled={!rolePermissions.canModifyLayout && widget.executiveRelevance !== 'critical'}
                          />
                        }
                      />
                      
                      {isVisible && widgetConfig && (
                        <CardContent sx={{ pt: 0 }}>
                          <Accordion variant="outlined">
                            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                              <Typography variant="body2">Widget Settings</Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                <FormControlLabel
                                  control={
                                    <Switch
                                      checked={widgetConfig.settings.showTrends ?? true}
                                      onChange={(e) => handleWidgetSettings(widget.id, { showTrends: e.target.checked })}
                                    />
                                  }
                                  label="Show Trends"
                                />
                                
                                {userRole !== 'board_member' && (
                                  <FormControlLabel
                                    control={
                                      <Switch
                                        checked={widgetConfig.settings.showConfidenceScore ?? true}
                                        onChange={(e) => handleWidgetSettings(widget.id, { showConfidenceScore: e.target.checked })}
                                      />
                                    }
                                    label="Show Confidence Score"
                                  />
                                )}
                                
                                <FormControlLabel
                                  control={
                                    <Switch
                                      checked={widgetConfig.settings.compactView ?? false}
                                      onChange={(e) => handleWidgetSettings(widget.id, { compactView: e.target.checked })}
                                    />
                                  }
                                  label="Compact View"
                                />
                                
                                <FormControl size="small" sx={{ minWidth: 150 }}>
                                  <InputLabel>Color Scheme</InputLabel>
                                  <Select
                                    value={widgetConfig.settings.colorScheme ?? 'executive'}
                                    label="Color Scheme"
                                    onChange={(e) => handleWidgetSettings(widget.id, { colorScheme: e.target.value as any })}
                                  >
                                    <MenuItem value="default">Default</MenuItem>
                                    <MenuItem value="executive">Executive</MenuItem>
                                    <MenuItem value="high-contrast">High Contrast</MenuItem>
                                  </Select>
                                </FormControl>
                              </Box>
                            </AccordionDetails>
                          </Accordion>
                        </CardContent>
                      )}
                    </Card>
                  </Grid>
                );
              })}
            </Grid>
          </TabPanel>

          {/* Layout Tab */}
          <TabPanel value={activeTab} index={1}>
            <Typography variant="h6" sx={{ mb: 3 }}>
              Dashboard Layout
            </Typography>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3 }}>
                  <Typography variant="subtitle1" sx={{ mb: 2 }}>
                    Layout Style
                  </Typography>
                  
                  <FormControl fullWidth>
                    <InputLabel>Layout</InputLabel>
                    <Select
                      value={tempConfig.layout}
                      label="Layout"
                      onChange={(e) => handleConfigUpdate({ layout: e.target.value as any })}
                      disabled={!rolePermissions.canModifyLayout}
                    >
                      <MenuItem value="compact">Compact</MenuItem>
                      <MenuItem value="detailed">Detailed</MenuItem>
                      <MenuItem value="executive">Executive</MenuItem>
                    </Select>
                  </FormControl>
                  
                  <Box sx={{ mt: 3 }}>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      Refresh Interval: {tempConfig.refreshInterval / 1000}s
                    </Typography>
                    <Slider
                      value={tempConfig.refreshInterval / 1000}
                      onChange={(e, value) => handleConfigUpdate({ refreshInterval: (value as number) * 1000 })}
                      min={10}
                      max={300}
                      step={10}
                      marks={[
                        { value: 30, label: '30s' },
                        { value: 60, label: '1m' },
                        { value: 300, label: '5m' }
                      ]}
                      disabled={!rolePermissions.canAccessAdvancedSettings}
                    />
                  </Box>
                </Paper>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3 }}>
                  <Typography variant="subtitle1" sx={{ mb: 2 }}>
                    Appearance
                  </Typography>
                  
                  <FormControl fullWidth sx={{ mb: 2 }}>
                    <InputLabel>Theme</InputLabel>
                    <Select
                      value={tempConfig.theme}
                      label="Theme"
                      onChange={(e) => handleConfigUpdate({ theme: e.target.value as any })}
                    >
                      <MenuItem value="light">Light</MenuItem>
                      <MenuItem value="dark">Dark</MenuItem>
                      <MenuItem value="auto">Auto</MenuItem>
                    </Select>
                  </FormControl>
                  
                  <FormControlLabel
                    control={
                      <Switch
                        checked={tempConfig.mobileOptimized}
                        onChange={(e) => handleConfigUpdate({ mobileOptimized: e.target.checked })}
                      />
                    }
                    label="Mobile Optimized"
                  />
                </Paper>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Notifications Tab */}
          {rolePermissions.canConfigureNotifications && (
            <TabPanel value={activeTab} index={2}>
              <Typography variant="h6" sx={{ mb: 3 }}>
                Notification Preferences
              </Typography>
              
              <Paper sx={{ p: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={tempConfig.notifications?.enabled ?? true}
                      onChange={(e) => handleConfigUpdate({ 
                        notifications: { ...tempConfig.notifications, enabled: e.target.checked }
                      })}
                    />
                  }
                  label="Enable Notifications"
                />
                
                {tempConfig.notifications?.enabled && (
                  <Box sx={{ mt: 3, ml: 3 }}>
                    <List>
                      <ListItem>
                        <ListItemText primary="Critical Security Alerts" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.notifications.criticalAlerts}
                            onChange={(e) => handleConfigUpdate({
                              notifications: { ...tempConfig.notifications, criticalAlerts: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Executive Briefings" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.notifications.executiveBriefings}
                            onChange={(e) => handleConfigUpdate({
                              notifications: { ...tempConfig.notifications, executiveBriefings: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Compliance Updates" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.notifications.complianceUpdates}
                            onChange={(e) => handleConfigUpdate({
                              notifications: { ...tempConfig.notifications, complianceUpdates: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      {(userRole === 'ciso' || userRole === 'ceo') && (
                        <ListItem>
                          <ListItemText primary="Threat Alerts" />
                          <ListItemSecondaryAction>
                            <Switch
                              checked={tempConfig.notifications.threatAlerts}
                              onChange={(e) => handleConfigUpdate({
                                notifications: { ...tempConfig.notifications, threatAlerts: e.target.checked }
                              })}
                            />
                          </ListItemSecondaryAction>
                        </ListItem>
                      )}
                    </List>
                    
                    <Divider sx={{ my: 2 }} />
                    
                    <FormControl fullWidth>
                      <InputLabel>Notification Frequency</InputLabel>
                      <Select
                        value={tempConfig.notifications.frequency}
                        label="Notification Frequency"
                        onChange={(e) => handleConfigUpdate({
                          notifications: { ...tempConfig.notifications, frequency: e.target.value as any }
                        })}
                      >
                        <MenuItem value="realtime">Real-time</MenuItem>
                        <MenuItem value="hourly">Hourly</MenuItem>
                        <MenuItem value="daily">Daily</MenuItem>
                        <MenuItem value="weekly">Weekly</MenuItem>
                      </Select>
                    </FormControl>
                  </Box>
                )}
              </Paper>
            </TabPanel>
          )}

          {/* Performance Tab */}
          {rolePermissions.canAccessAdvancedSettings && (
            <TabPanel value={activeTab} index={3}>
              <Typography variant="h6" sx={{ mb: 3 }}>
                Performance & Accessibility
              </Typography>
              
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3 }}>
                    <Typography variant="subtitle1" sx={{ mb: 2 }}>
                      Performance Settings
                    </Typography>
                    
                    <List>
                      <ListItem>
                        <ListItemText primary="Enable Animations" secondary="Smooth transitions and effects" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.performance?.enableAnimations ?? true}
                            onChange={(e) => handleConfigUpdate({
                              performance: { ...tempConfig.performance, enableAnimations: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Data Caching" secondary="Cache data for faster loading" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.performance?.dataCaching ?? true}
                            onChange={(e) => handleConfigUpdate({
                              performance: { ...tempConfig.performance, dataCaching: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Background Refresh" secondary="Update data in background" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.performance?.backgroundRefresh ?? true}
                            onChange={(e) => handleConfigUpdate({
                              performance: { ...tempConfig.performance, backgroundRefresh: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Low Bandwidth Mode" secondary="Reduce data usage" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.performance?.lowBandwidthMode ?? false}
                            onChange={(e) => handleConfigUpdate({
                              performance: { ...tempConfig.performance, lowBandwidthMode: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3 }}>
                    <Typography variant="subtitle1" sx={{ mb: 2 }}>
                      Accessibility
                    </Typography>
                    
                    <List>
                      <ListItem>
                        <ListItemText primary="High Contrast" secondary="Improve visibility" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.accessibility?.highContrast ?? false}
                            onChange={(e) => handleConfigUpdate({
                              accessibility: { ...tempConfig.accessibility, highContrast: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Large Text" secondary="Increase font size" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.accessibility?.largeText ?? false}
                            onChange={(e) => handleConfigUpdate({
                              accessibility: { ...tempConfig.accessibility, largeText: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Reduced Motion" secondary="Minimize animations" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.accessibility?.reducedMotion ?? false}
                            onChange={(e) => handleConfigUpdate({
                              accessibility: { ...tempConfig.accessibility, reducedMotion: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                      
                      <ListItem>
                        <ListItemText primary="Screen Reader Optimized" secondary="Optimize for screen readers" />
                        <ListItemSecondaryAction>
                          <Switch
                            checked={tempConfig.accessibility?.screenReaderOptimized ?? false}
                            onChange={(e) => handleConfigUpdate({
                              accessibility: { ...tempConfig.accessibility, screenReaderOptimized: e.target.checked }
                            })}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </TabPanel>
          )}
        </Box>
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2, justifyContent: 'space-between' }}>
        <Box>
          <Button
            onClick={handleReset}
            startIcon={<ResetIcon />}
            variant="outlined"
            color="warning"
            disabled={!rolePermissions.canModifyLayout}
          >
            Reset to Default
          </Button>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button onClick={onClose} variant="outlined">
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            variant="contained"
            startIcon={<SaveIcon />}
            disabled={!hasChanges}
            color="primary"
          >
            Save Configuration
          </Button>
        </Box>
      </DialogActions>
    </Dialog>
  );
};

export default ExecutiveCustomization;