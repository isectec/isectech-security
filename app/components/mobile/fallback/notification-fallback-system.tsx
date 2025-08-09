/**
 * Mobile Notification Fallback System
 * Comprehensive fallback mechanisms for when primary push notifications fail
 * Supports SMS, Email, Webhook, and Progressive Retry strategies
 */

'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Switch,
  FormControl,
  FormControlLabel,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Alert,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Sms as SmsIcon,
  Email as EmailIcon,
  WebHook as WebhookIcon,
  Settings as SettingsIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Send as SendIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandIcon,
  NotificationsOff as DisabledIcon,
  Schedule as ScheduleIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useOffline } from '@/lib/hooks/use-offline';
import type { Notification } from '@/types';

interface FallbackConfig {
  enabled: boolean;
  priority: number;
  retryAttempts: number;
  retryDelaySeconds: number;
  conditions: FallbackCondition[];
}

interface FallbackCondition {
  type: 'delivery_failure' | 'user_offline' | 'device_unavailable' | 'schedule_based' | 'priority_threshold';
  enabled: boolean;
  config: Record<string, any>;
}

interface SMSConfig extends FallbackConfig {
  phoneNumber: string;
  provider: 'twilio' | 'aws_sns' | 'messagebird';
  templateId?: string;
  maxLength: number;
}

interface EmailConfig extends FallbackConfig {
  emailAddress: string;
  provider: 'sendgrid' | 'ses' | 'mailgun';
  templateId?: string;
  includeAttachments: boolean;
}

interface WebhookConfig extends FallbackConfig {
  url: string;
  method: 'POST' | 'PUT';
  headers: Record<string, string>;
  authentication: {
    type: 'none' | 'bearer' | 'basic' | 'api_key';
    config: Record<string, string>;
  };
  payloadTemplate: string;
}

interface FallbackAttempt {
  id: string;
  notificationId: string;
  method: 'sms' | 'email' | 'webhook';
  timestamp: Date;
  status: 'pending' | 'success' | 'failed' | 'retrying';
  error?: string;
  responseTime?: number;
  retryCount: number;
}

const defaultSMSConfig: SMSConfig = {
  enabled: false,
  priority: 1,
  retryAttempts: 3,
  retryDelaySeconds: 30,
  phoneNumber: '',
  provider: 'twilio',
  maxLength: 160,
  conditions: [
    { type: 'delivery_failure', enabled: true, config: { maxRetries: 2 } },
    { type: 'priority_threshold', enabled: true, config: { minPriority: 'high' } },
  ],
};

const defaultEmailConfig: EmailConfig = {
  enabled: false,
  priority: 2,
  retryAttempts: 2,
  retryDelaySeconds: 60,
  emailAddress: '',
  provider: 'sendgrid',
  includeAttachments: false,
  conditions: [
    { type: 'delivery_failure', enabled: true, config: { maxRetries: 3 } },
    { type: 'user_offline', enabled: true, config: { offlineThresholdMinutes: 30 } },
  ],
};

const defaultWebhookConfig: WebhookConfig = {
  enabled: false,
  priority: 3,
  retryAttempts: 5,
  retryDelaySeconds: 15,
  url: '',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  authentication: { type: 'none', config: {} },
  payloadTemplate: '{"notification": "{{notification}}", "timestamp": "{{timestamp}}", "priority": "{{priority}}"}',
  conditions: [
    { type: 'delivery_failure', enabled: true, config: { maxRetries: 2 } },
    { type: 'schedule_based', enabled: false, config: { schedule: '0 */6 * * *' } }, // Every 6 hours
  ],
};

export function NotificationFallbackSystem() {
  const theme = useTheme();
  const { isOnline } = useOffline();
  
  const [smsConfig, setSmsConfig] = useState<SMSConfig>(defaultSMSConfig);
  const [emailConfig, setEmailConfig] = useState<EmailConfig>(defaultEmailConfig);
  const [webhookConfig, setWebhookConfig] = useState<WebhookConfig>(defaultWebhookConfig);
  
  const [fallbackAttempts, setFallbackAttempts] = useState<FallbackAttempt[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [selectedTestMethod, setSelectedTestMethod] = useState<'sms' | 'email' | 'webhook'>('sms');
  const [testResults, setTestResults] = useState<Record<string, any>>({});
  
  const processingQueue = useRef<Notification[]>([]);
  const retryTimers = useRef<Map<string, NodeJS.Timeout>>(new Map());

  // Load saved configurations on mount
  useEffect(() => {
    loadConfigurations();
  }, []);

  // Process fallback queue
  useEffect(() => {
    const interval = setInterval(processQueue, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadConfigurations = async () => {
    try {
      const savedConfigs = localStorage.getItem('fallback-configs');
      if (savedConfigs) {
        const configs = JSON.parse(savedConfigs);
        setSmsConfig(configs.sms || defaultSMSConfig);
        setEmailConfig(configs.email || defaultEmailConfig);
        setWebhookConfig(configs.webhook || defaultWebhookConfig);
      }
      
      // Load previous attempts
      const savedAttempts = localStorage.getItem('fallback-attempts');
      if (savedAttempts) {
        const attempts = JSON.parse(savedAttempts);
        setFallbackAttempts(attempts.map((a: any) => ({
          ...a,
          timestamp: new Date(a.timestamp)
        })));
      }
    } catch (error) {
      console.error('Failed to load fallback configurations:', error);
    }
  };

  const saveConfigurations = useCallback(() => {
    try {
      const configs = {
        sms: smsConfig,
        email: emailConfig,
        webhook: webhookConfig,
      };
      localStorage.setItem('fallback-configs', JSON.stringify(configs));
    } catch (error) {
      console.error('Failed to save configurations:', error);
    }
  }, [smsConfig, emailConfig, webhookConfig]);

  // Save configurations when they change
  useEffect(() => {
    saveConfigurations();
  }, [saveConfigurations]);

  const processQueue = useCallback(async () => {
    if (processingQueue.current.length === 0 || isProcessing) {
      return;
    }

    setIsProcessing(true);
    
    try {
      const notification = processingQueue.current.shift();
      if (notification) {
        await processFallbackNotification(notification);
      }
    } catch (error) {
      console.error('Error processing fallback queue:', error);
    } finally {
      setIsProcessing(false);
    }
  }, [isProcessing]);

  const processFallbackNotification = async (notification: Notification) => {
    // Determine which fallback methods should be used
    const methods = [];
    
    if (smsConfig.enabled && shouldUseFallback(smsConfig, notification)) {
      methods.push({ type: 'sms' as const, config: smsConfig });
    }
    
    if (emailConfig.enabled && shouldUseFallback(emailConfig, notification)) {
      methods.push({ type: 'email' as const, config: emailConfig });
    }
    
    if (webhookConfig.enabled && shouldUseFallback(webhookConfig, notification)) {
      methods.push({ type: 'webhook' as const, config: webhookConfig });
    }

    // Sort by priority (lower number = higher priority)
    methods.sort((a, b) => a.config.priority - b.config.priority);

    // Execute fallback methods
    for (const method of methods) {
      await executeFallback(notification, method.type, method.config);
    }
  };

  const shouldUseFallback = (config: FallbackConfig, notification: Notification): boolean => {
    return config.conditions.some(condition => {
      if (!condition.enabled) return false;

      switch (condition.type) {
        case 'delivery_failure':
          // Check if primary notification delivery has failed
          return true; // Simplified for demo
        
        case 'user_offline':
          return !isOnline;
        
        case 'priority_threshold':
          const minPriority = condition.config.minPriority;
          const priorityMap = { low: 1, medium: 2, high: 3, critical: 4 };
          const notificationPriority = priorityMap[notification.type === 'error' ? 'high' : 'medium'];
          const thresholdPriority = priorityMap[minPriority] || 1;
          return notificationPriority >= thresholdPriority;
        
        case 'schedule_based':
          // Check if current time matches schedule
          // This would implement cron-like scheduling
          return true; // Simplified for demo
        
        default:
          return false;
      }
    });
  };

  const executeFallback = async (
    notification: Notification,
    method: 'sms' | 'email' | 'webhook',
    config: FallbackConfig
  ) => {
    const attemptId = `${notification.id}-${method}-${Date.now()}`;
    const attempt: FallbackAttempt = {
      id: attemptId,
      notificationId: notification.id,
      method,
      timestamp: new Date(),
      status: 'pending',
      retryCount: 0,
    };

    setFallbackAttempts(prev => [...prev, attempt]);

    try {
      const startTime = Date.now();
      
      switch (method) {
        case 'sms':
          await sendSMSNotification(notification, smsConfig);
          break;
        case 'email':
          await sendEmailNotification(notification, emailConfig);
          break;
        case 'webhook':
          await sendWebhookNotification(notification, webhookConfig);
          break;
      }

      const responseTime = Date.now() - startTime;
      
      // Update attempt status
      setFallbackAttempts(prev => 
        prev.map(a => 
          a.id === attemptId 
            ? { ...a, status: 'success', responseTime }
            : a
        )
      );

    } catch (error) {
      console.error(`${method} fallback failed:`, error);
      
      // Update attempt with error
      setFallbackAttempts(prev => 
        prev.map(a => 
          a.id === attemptId 
            ? { ...a, status: 'failed', error: error.message }
            : a
        )
      );

      // Schedule retry if attempts remaining
      if (attempt.retryCount < config.retryAttempts) {
        scheduleRetry(notification, method, config, attempt.retryCount + 1);
      }
    }
  };

  const scheduleRetry = (
    notification: Notification,
    method: 'sms' | 'email' | 'webhook',
    config: FallbackConfig,
    retryCount: number
  ) => {
    const retryKey = `${notification.id}-${method}`;
    const delay = config.retryDelaySeconds * 1000 * Math.pow(2, retryCount - 1); // Exponential backoff

    const timer = setTimeout(async () => {
      try {
        await executeFallback(notification, method, config);
      } catch (error) {
        console.error(`Retry ${retryCount} failed for ${method}:`, error);
      } finally {
        retryTimers.current.delete(retryKey);
      }
    }, delay);

    retryTimers.current.set(retryKey, timer);
  };

  const sendSMSNotification = async (notification: Notification, config: SMSConfig) => {
    const message = `iSECTECH Alert: ${notification.title}${notification.message ? ` - ${notification.message.substring(0, config.maxLength - notification.title.length - 20)}` : ''}`;
    
    // Simulate API call to SMS provider
    await new Promise((resolve, reject) => {
      setTimeout(() => {
        if (Math.random() > 0.1) { // 90% success rate for demo
          resolve(undefined);
        } else {
          reject(new Error('SMS delivery failed'));
        }
      }, 1000 + Math.random() * 2000);
    });

    console.log(`SMS sent to ${config.phoneNumber}: ${message}`);
  };

  const sendEmailNotification = async (notification: Notification, config: EmailConfig) => {
    const emailData = {
      to: config.emailAddress,
      subject: `iSECTECH Alert: ${notification.title}`,
      body: `
        <h2>Security Alert</h2>
        <p><strong>Title:</strong> ${notification.title}</p>
        ${notification.message ? `<p><strong>Message:</strong> ${notification.message}</p>` : ''}
        <p><strong>Type:</strong> ${notification.type}</p>
        <p><strong>Time:</strong> ${notification.timestamp.toISOString()}</p>
        <hr>
        <p><em>This is a fallback notification from iSECTECH Mobile Security System.</em></p>
      `,
    };

    // Simulate API call to email provider
    await new Promise((resolve, reject) => {
      setTimeout(() => {
        if (Math.random() > 0.05) { // 95% success rate for demo
          resolve(undefined);
        } else {
          reject(new Error('Email delivery failed'));
        }
      }, 500 + Math.random() * 1500);
    });

    console.log(`Email sent to ${config.emailAddress}:`, emailData);
  };

  const sendWebhookNotification = async (notification: Notification, config: WebhookConfig) => {
    // Prepare payload from template
    const payload = config.payloadTemplate
      .replace('{{notification}}', JSON.stringify(notification))
      .replace('{{timestamp}}', notification.timestamp.toISOString())
      .replace('{{priority}}', notification.type === 'error' ? 'high' : 'medium');

    const headers = { ...config.headers };
    
    // Add authentication headers
    if (config.authentication.type === 'bearer') {
      headers['Authorization'] = `Bearer ${config.authentication.config.token}`;
    } else if (config.authentication.type === 'api_key') {
      headers[config.authentication.config.headerName || 'X-API-Key'] = config.authentication.config.apiKey;
    }

    // Simulate webhook call
    await new Promise((resolve, reject) => {
      setTimeout(() => {
        if (Math.random() > 0.08) { // 92% success rate for demo
          resolve(undefined);
        } else {
          reject(new Error('Webhook endpoint unreachable'));
        }
      }, 200 + Math.random() * 800);
    });

    console.log(`Webhook sent to ${config.url}:`, { payload, headers });
  };

  const testFallbackMethod = async (method: 'sms' | 'email' | 'webhook') => {
    const testNotification: Notification = {
      id: `test-${Date.now()}`,
      title: 'Test Notification',
      message: 'This is a test of the fallback notification system.',
      type: 'info',
      timestamp: new Date(),
      read: false,
    };

    try {
      setTestResults(prev => ({ ...prev, [method]: { status: 'testing', error: null } }));
      
      const config = method === 'sms' ? smsConfig : method === 'email' ? emailConfig : webhookConfig;
      await executeFallback(testNotification, method, config);
      
      setTestResults(prev => ({ ...prev, [method]: { status: 'success', error: null } }));
    } catch (error) {
      setTestResults(prev => ({ ...prev, [method]: { status: 'error', error: error.message } }));
    }
  };

  // Public API for triggering fallback
  const triggerFallback = useCallback((notification: Notification) => {
    processingQueue.current.push(notification);
  }, []);

  // Expose the API globally for other components to use
  useEffect(() => {
    (window as any).triggerNotificationFallback = triggerFallback;
    return () => {
      delete (window as any).triggerNotificationFallback;
    };
  }, [triggerFallback]);

  const getMethodIcon = (method: string) => {
    switch (method) {
      case 'sms': return <SmsIcon />;
      case 'email': return <EmailIcon />;
      case 'webhook': return <WebhookIcon />;
      default: return <InfoIcon />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'success';
      case 'failed': return 'error';
      case 'pending': case 'retrying': return 'warning';
      default: return 'default';
    }
  };

  const recentAttempts = fallbackAttempts
    .slice(-10)
    .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="h5" sx={{ mb: 3, fontWeight: 700 }}>
        Fallback Notification System
      </Typography>

      {!isOnline && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          You are currently offline. Fallback configurations will be saved locally and applied when connectivity is restored.
        </Alert>
      )}

      {/* SMS Configuration */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandIcon />}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <SmsIcon />
            <Typography variant="h6">SMS Notifications</Typography>
            <Chip
              label={smsConfig.enabled ? 'Enabled' : 'Disabled'}
              color={smsConfig.enabled ? 'success' : 'default'}
              size="small"
            />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={smsConfig.enabled}
                  onChange={(e) => setSmsConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                />
              }
              label="Enable SMS fallback"
            />

            <TextField
              label="Phone Number"
              value={smsConfig.phoneNumber}
              onChange={(e) => setSmsConfig(prev => ({ ...prev, phoneNumber: e.target.value }))}
              placeholder="+1234567890"
              disabled={!smsConfig.enabled}
              fullWidth
            />

            <FormControl disabled={!smsConfig.enabled}>
              <InputLabel>Provider</InputLabel>
              <Select
                value={smsConfig.provider}
                onChange={(e) => setSmsConfig(prev => ({ ...prev, provider: e.target.value as any }))}
                label="Provider"
              >
                <MenuItem value="twilio">Twilio</MenuItem>
                <MenuItem value="aws_sns">AWS SNS</MenuItem>
                <MenuItem value="messagebird">MessageBird</MenuItem>
              </Select>
            </FormControl>

            <TextField
              label="Max Message Length"
              type="number"
              value={smsConfig.maxLength}
              onChange={(e) => setSmsConfig(prev => ({ ...prev, maxLength: parseInt(e.target.value) }))}
              disabled={!smsConfig.enabled}
              InputProps={{ inputProps: { min: 50, max: 320 } }}
            />

            <TextField
              label="Retry Attempts"
              type="number"
              value={smsConfig.retryAttempts}
              onChange={(e) => setSmsConfig(prev => ({ ...prev, retryAttempts: parseInt(e.target.value) }))}
              disabled={!smsConfig.enabled}
              InputProps={{ inputProps: { min: 0, max: 10 } }}
            />
          </Box>
        </AccordionDetails>
      </Accordion>

      {/* Email Configuration */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandIcon />}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <EmailIcon />
            <Typography variant="h6">Email Notifications</Typography>
            <Chip
              label={emailConfig.enabled ? 'Enabled' : 'Disabled'}
              color={emailConfig.enabled ? 'success' : 'default'}
              size="small"
            />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={emailConfig.enabled}
                  onChange={(e) => setEmailConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                />
              }
              label="Enable Email fallback"
            />

            <TextField
              label="Email Address"
              type="email"
              value={emailConfig.emailAddress}
              onChange={(e) => setEmailConfig(prev => ({ ...prev, emailAddress: e.target.value }))}
              disabled={!emailConfig.enabled}
              fullWidth
            />

            <FormControl disabled={!emailConfig.enabled}>
              <InputLabel>Provider</InputLabel>
              <Select
                value={emailConfig.provider}
                onChange={(e) => setEmailConfig(prev => ({ ...prev, provider: e.target.value as any }))}
                label="Provider"
              >
                <MenuItem value="sendgrid">SendGrid</MenuItem>
                <MenuItem value="ses">Amazon SES</MenuItem>
                <MenuItem value="mailgun">Mailgun</MenuItem>
              </Select>
            </FormControl>

            <FormControlLabel
              control={
                <Switch
                  checked={emailConfig.includeAttachments}
                  onChange={(e) => setEmailConfig(prev => ({ ...prev, includeAttachments: e.target.checked }))}
                  disabled={!emailConfig.enabled}
                />
              }
              label="Include attachments (logs, screenshots)"
            />
          </Box>
        </AccordionDetails>
      </Accordion>

      {/* Webhook Configuration */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandIcon />}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <WebhookIcon />
            <Typography variant="h6">Webhook Notifications</Typography>
            <Chip
              label={webhookConfig.enabled ? 'Enabled' : 'Disabled'}
              color={webhookConfig.enabled ? 'success' : 'default'}
              size="small"
            />
          </Box>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={webhookConfig.enabled}
                  onChange={(e) => setWebhookConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                />
              }
              label="Enable Webhook fallback"
            />

            <TextField
              label="Webhook URL"
              value={webhookConfig.url}
              onChange={(e) => setWebhookConfig(prev => ({ ...prev, url: e.target.value }))}
              disabled={!webhookConfig.enabled}
              placeholder="https://your-webhook-endpoint.com/notifications"
              fullWidth
            />

            <FormControl disabled={!webhookConfig.enabled}>
              <InputLabel>HTTP Method</InputLabel>
              <Select
                value={webhookConfig.method}
                onChange={(e) => setWebhookConfig(prev => ({ ...prev, method: e.target.value as any }))}
                label="HTTP Method"
              >
                <MenuItem value="POST">POST</MenuItem>
                <MenuItem value="PUT">PUT</MenuItem>
              </Select>
            </FormControl>

            <FormControl disabled={!webhookConfig.enabled}>
              <InputLabel>Authentication</InputLabel>
              <Select
                value={webhookConfig.authentication.type}
                onChange={(e) => setWebhookConfig(prev => ({
                  ...prev,
                  authentication: { ...prev.authentication, type: e.target.value as any }
                }))}
                label="Authentication"
              >
                <MenuItem value="none">None</MenuItem>
                <MenuItem value="bearer">Bearer Token</MenuItem>
                <MenuItem value="basic">Basic Auth</MenuItem>
                <MenuItem value="api_key">API Key</MenuItem>
              </Select>
            </FormControl>

            <TextField
              label="Payload Template"
              multiline
              rows={4}
              value={webhookConfig.payloadTemplate}
              onChange={(e) => setWebhookConfig(prev => ({ ...prev, payloadTemplate: e.target.value }))}
              disabled={!webhookConfig.enabled}
              placeholder="JSON template with {{notification}}, {{timestamp}}, {{priority}} variables"
              fullWidth
            />
          </Box>
        </AccordionDetails>
      </Accordion>

      {/* Recent Attempts */}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'between', mb: 2 }}>
            <Typography variant="h6">Recent Fallback Attempts</Typography>
            {isProcessing && <LinearProgress sx={{ ml: 2, flexGrow: 1 }} />}
          </Box>

          {recentAttempts.length === 0 ? (
            <Alert severity="info">
              No fallback attempts recorded yet. Fallbacks will be triggered automatically when primary notifications fail.
            </Alert>
          ) : (
            <List>
              {recentAttempts.map((attempt) => (
                <ListItem key={attempt.id}>
                  <ListItemIcon>
                    {getMethodIcon(attempt.method)}
                  </ListItemIcon>
                  <ListItemText
                    primary={`${attempt.method.toUpperCase()} - ${attempt.notificationId}`}
                    secondary={
                      <Box>
                        <Typography variant="caption" color="text.secondary">
                          {attempt.timestamp.toLocaleString()}
                        </Typography>
                        {attempt.error && (
                          <Typography variant="caption" color="error" display="block">
                            Error: {attempt.error}
                          </Typography>
                        )}
                        {attempt.responseTime && (
                          <Typography variant="caption" color="text.secondary">
                            Response time: {attempt.responseTime}ms
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Chip
                      label={attempt.status}
                      color={getStatusColor(attempt.status)}
                      size="small"
                    />
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          )}
        </CardContent>
      </Card>

      {/* Test Button */}
      <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
        <Button
          variant="contained"
          startIcon={<SendIcon />}
          onClick={() => setTestDialogOpen(true)}
          disabled={!smsConfig.enabled && !emailConfig.enabled && !webhookConfig.enabled}
        >
          Test Fallback System
        </Button>
      </Box>

      {/* Test Dialog */}
      <Dialog open={testDialogOpen} onClose={() => setTestDialogOpen(false)}>
        <DialogTitle>Test Fallback System</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 400 }}>
            <FormControl>
              <InputLabel>Test Method</InputLabel>
              <Select
                value={selectedTestMethod}
                onChange={(e) => setSelectedTestMethod(e.target.value as any)}
                label="Test Method"
              >
                {smsConfig.enabled && <MenuItem value="sms">SMS</MenuItem>}
                {emailConfig.enabled && <MenuItem value="email">Email</MenuItem>}
                {webhookConfig.enabled && <MenuItem value="webhook">Webhook</MenuItem>}
              </Select>
            </FormControl>

            {testResults[selectedTestMethod] && (
              <Alert severity={testResults[selectedTestMethod].status === 'success' ? 'success' : 'error'}>
                {testResults[selectedTestMethod].status === 'success' 
                  ? 'Test notification sent successfully!' 
                  : `Test failed: ${testResults[selectedTestMethod].error}`}
              </Alert>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTestDialogOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={() => testFallbackMethod(selectedTestMethod)}
            disabled={testResults[selectedTestMethod]?.status === 'testing'}
          >
            Send Test
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default NotificationFallbackSystem;