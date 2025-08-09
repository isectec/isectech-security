'use client';

import React, { useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardHeader,
  CardContent,
  Typography,
  Switch,
  FormControl,
  FormControlLabel,
  Select,
  MenuItem,
  InputLabel,
  Slider,
  TextField,
  Button,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Alert,
  Grid,
  TimePicker,
  useTheme
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Notifications as NotificationsIcon,
  Schedule as ScheduleIcon,
  VolumeUp as VolumeUpIcon,
  Vibration as VibrationIcon,
  Security as SecurityIcon,
  Language as LanguageIcon,
  Palette as PaletteIcon
} from '@mui/icons-material';
import { LocalizationProvider, TimePicker as MuiTimePicker } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { 
  NotificationPreferencesManagerProps,
  PreferenceSettings,
  ChannelPreference
} from './types';

export const NotificationPreferencesManager: React.FC<NotificationPreferencesManagerProps> = ({
  config,
  preferences,
  onPreferencesChange,
  channels,
  showAdvanced = false
}) => {
  const theme = useTheme();
  const [tempPreferences, setTempPreferences] = useState<PreferenceSettings>(preferences);
  const [hasChanges, setHasChanges] = useState(false);
  const [saving, setSaving] = useState(false);

  const handleGlobalPreferenceChange = useCallback((key: string, value: any) => {
    const updated = {
      ...tempPreferences,
      global: {
        ...tempPreferences.global,
        [key]: value
      },
      updatedAt: new Date(),
      version: tempPreferences.version + 1
    };
    
    setTempPreferences(updated);
    setHasChanges(true);
  }, [tempPreferences]);

  const handleDevicePreferenceChange = useCallback((key: string, value: any) => {
    const updated = {
      ...tempPreferences,
      device: {
        ...tempPreferences.device,
        [key]: value
      },
      updatedAt: new Date(),
      version: tempPreferences.version + 1
    };
    
    setTempPreferences(updated);
    setHasChanges(true);
  }, [tempPreferences]);

  const handleChannelPreferenceChange = useCallback((channelId: string, key: string, value: any) => {
    const channelPref = tempPreferences.channels[channelId] || {
      enabled: true,
      priority: 'medium' as const,
      delivery: { push: true, email: false, sms: false, inApp: true },
      batching: { enabled: false, windowMinutes: 5, maxBatchSize: 10 },
      customization: {}
    };

    const updated = {
      ...tempPreferences,
      channels: {
        ...tempPreferences.channels,
        [channelId]: {
          ...channelPref,
          [key]: value
        }
      },
      updatedAt: new Date(),
      version: tempPreferences.version + 1
    };
    
    setTempPreferences(updated);
    setHasChanges(true);
  }, [tempPreferences]);

  const handleQuietHoursChange = useCallback((field: string, value: any) => {
    const updated = {
      ...tempPreferences,
      global: {
        ...tempPreferences.global,
        quietHours: {
          ...tempPreferences.global.quietHours,
          [field]: value
        }
      },
      updatedAt: new Date(),
      version: tempPreferences.version + 1
    };
    
    setTempPreferences(updated);
    setHasChanges(true);
  }, [tempPreferences]);

  const handleSavePreferences = async () => {
    try {
      setSaving(true);
      await onPreferencesChange(tempPreferences);
      setHasChanges(false);
    } catch (error) {
      console.error('Failed to save preferences:', error);
    } finally {
      setSaving(false);
    }
  };

  const handleResetPreferences = () => {
    setTempPreferences(preferences);
    setHasChanges(false);
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Box sx={{ p: 2 }}>
        {/* Header with Save/Reset Actions */}
        {hasChanges && (
          <Alert severity="info" sx={{ mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography>You have unsaved changes</Typography>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button size="small" onClick={handleResetPreferences}>
                  Reset
                </Button>
                <Button 
                  size="small" 
                  variant="contained" 
                  onClick={handleSavePreferences}
                  disabled={saving}
                >
                  {saving ? 'Saving...' : 'Save Changes'}
                </Button>
              </Box>
            </Box>
          </Alert>
        )}

        {/* Global Notification Settings */}
        <Card sx={{ mb: 2 }}>
          <CardHeader
            title="Global Notification Settings"
            avatar={<NotificationsIcon />}
          />
          <CardContent>
            <Grid container spacing={3}>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={tempPreferences.global.enabled}
                      onChange={(e) => handleGlobalPreferenceChange('enabled', e.target.checked)}
                    />
                  }
                  label="Enable notifications"
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel>Priority Filter</InputLabel>
                  <Select
                    value={tempPreferences.global.priorityFilter}
                    label="Priority Filter"
                    onChange={(e) => handleGlobalPreferenceChange('priorityFilter', e.target.value)}
                  >
                    <MenuItem value="all">All Notifications</MenuItem>
                    <MenuItem value="high">High Priority Only</MenuItem>
                    <MenuItem value="critical">Critical Only</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} sm={6}>
                <Typography gutterBottom>
                  Max Daily Notifications: {tempPreferences.global.maxDailyNotifications}
                </Typography>
                <Slider
                  value={tempPreferences.global.maxDailyNotifications}
                  onChange={(_, value) => handleGlobalPreferenceChange('maxDailyNotifications', value)}
                  min={1}
                  max={100}
                  step={5}
                  marks={[
                    { value: 10, label: '10' },
                    { value: 50, label: '50' },
                    { value: 100, label: '100' }
                  ]}
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={tempPreferences.global.groupSimilar}
                      onChange={(e) => handleGlobalPreferenceChange('groupSimilar', e.target.checked)}
                    />
                  }
                  label="Group similar notifications"
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Quiet Hours Settings */}
        <Card sx={{ mb: 2 }}>
          <CardHeader
            title="Quiet Hours"
            avatar={<ScheduleIcon />}
            subheader="Suppress non-critical notifications during these hours"
          />
          <CardContent>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={tempPreferences.global.quietHours.enabled}
                      onChange={(e) => handleQuietHoursChange('enabled', e.target.checked)}
                    />
                  }
                  label="Enable quiet hours"
                />
              </Grid>

              {tempPreferences.global.quietHours.enabled && (
                <>
                  <Grid item xs={12} sm={6}>
                    <MuiTimePicker
                      label="Start Time"
                      value={new Date(`1970-01-01T${tempPreferences.global.quietHours.start}:00`)}
                      onChange={(newValue) => {
                        if (newValue) {
                          const timeStr = newValue.toTimeString().slice(0, 5);
                          handleQuietHoursChange('start', timeStr);
                        }
                      }}
                      renderInput={(params) => <TextField {...params} fullWidth />}
                    />
                  </Grid>

                  <Grid item xs={12} sm={6}>
                    <MuiTimePicker
                      label="End Time"
                      value={new Date(`1970-01-01T${tempPreferences.global.quietHours.end}:00`)}
                      onChange={(newValue) => {
                        if (newValue) {
                          const timeStr = newValue.toTimeString().slice(0, 5);
                          handleQuietHoursChange('end', timeStr);
                        }
                      }}
                      renderInput={(params) => <TextField {...params} fullWidth />}
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={tempPreferences.global.quietHours.emergencyOverride}
                          onChange={(e) => handleQuietHoursChange('emergencyOverride', e.target.checked)}
                        />
                      }
                      label="Allow emergency notifications during quiet hours"
                    />
                  </Grid>
                </>
              )}
            </Grid>
          </CardContent>
        </Card>

        {/* Device-Specific Settings */}
        <Card sx={{ mb: 2 }}>
          <CardHeader
            title="Device Settings"
            subheader={`Settings for ${config.deviceInfo.platform} devices`}
          />
          <CardContent>
            <Grid container spacing={3}>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={tempPreferences.device.sound}
                      onChange={(e) => handleDevicePreferenceChange('sound', e.target.checked)}
                    />
                  }
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <VolumeUpIcon fontSize="small" />
                      Sound notifications
                    </Box>
                  }
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={tempPreferences.device.vibration}
                      onChange={(e) => handleDevicePreferenceChange('vibration', e.target.checked)}
                    />
                  }
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <VibrationIcon fontSize="small" />
                      Vibration
                    </Box>
                  }
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={tempPreferences.device.badge}
                      onChange={(e) => handleDevicePreferenceChange('badge', e.target.checked)}
                    />
                  }
                  label="Show notification badges"
                />
              </Grid>

              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel>Lock Screen Visibility</InputLabel>
                  <Select
                    value={tempPreferences.device.lockScreenVisibility}
                    label="Lock Screen Visibility"
                    onChange={(e) => handleDevicePreferenceChange('lockScreenVisibility', e.target.value)}
                  >
                    <MenuItem value="public">Show all content</MenuItem>
                    <MenuItem value="private">Hide sensitive content</MenuItem>
                    <MenuItem value="secret">Hide all notifications</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </CardContent>
        </Card>

        {/* Channel-Specific Settings */}
        {channels.length > 0 && (
          <Card sx={{ mb: 2 }}>
            <CardHeader
              title="Notification Channels"
              subheader="Customize settings for each type of notification"
            />
            <CardContent>
              {channels.map((channel, index) => {
                const channelPref = tempPreferences.channels[channel.id] || {
                  enabled: true,
                  priority: 'medium' as const,
                  delivery: { push: true, email: false, sms: false, inApp: true },
                  batching: { enabled: false, windowMinutes: 5, maxBatchSize: 10 },
                  customization: {}
                };

                return (
                  <Accordion key={channel.id}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                        <Typography variant="subtitle1">{channel.name}</Typography>
                        <Chip
                          label={channel.priority}
                          size="small"
                          color={channel.priority === 'critical' ? 'error' : 
                            channel.priority === 'high' ? 'warning' : 'default'}
                        />
                        <Box sx={{ ml: 'auto' }}>
                          <Switch
                            checked={channelPref.enabled}
                            onChange={(e) => {
                              e.stopPropagation();
                              handleChannelPreferenceChange(channel.id, 'enabled', e.target.checked);
                            }}
                            size="small"
                          />
                        </Box>
                      </Box>
                    </AccordionSummary>
                    
                    <AccordionDetails>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        {channel.description}
                      </Typography>

                      <Grid container spacing={2}>
                        <Grid item xs={12}>
                          <Typography variant="subtitle2" gutterBottom>
                            Delivery Methods
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={channelPref.delivery.push}
                                  onChange={(e) => handleChannelPreferenceChange(
                                    channel.id, 
                                    'delivery', 
                                    { ...channelPref.delivery, push: e.target.checked }
                                  )}
                                  size="small"
                                />
                              }
                              label="Push"
                            />
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={channelPref.delivery.email}
                                  onChange={(e) => handleChannelPreferenceChange(
                                    channel.id, 
                                    'delivery', 
                                    { ...channelPref.delivery, email: e.target.checked }
                                  )}
                                  size="small"
                                />
                              }
                              label="Email"
                            />
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={channelPref.delivery.sms}
                                  onChange={(e) => handleChannelPreferenceChange(
                                    channel.id, 
                                    'delivery', 
                                    { ...channelPref.delivery, sms: e.target.checked }
                                  )}
                                  size="small"
                                />
                              }
                              label="SMS"
                            />
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={channelPref.delivery.inApp}
                                  onChange={(e) => handleChannelPreferenceChange(
                                    channel.id, 
                                    'delivery', 
                                    { ...channelPref.delivery, inApp: e.target.checked }
                                  )}
                                  size="small"
                                />
                              }
                              label="In-App"
                            />
                          </Box>
                        </Grid>

                        {showAdvanced && (
                          <>
                            <Grid item xs={12} sm={6}>
                              <FormControlLabel
                                control={
                                  <Switch
                                    checked={channelPref.batching.enabled}
                                    onChange={(e) => handleChannelPreferenceChange(
                                      channel.id,
                                      'batching',
                                      { ...channelPref.batching, enabled: e.target.checked }
                                    )}
                                    size="small"
                                  />
                                }
                                label="Enable batching"
                              />
                            </Grid>

                            {channelPref.batching.enabled && (
                              <Grid item xs={12} sm={6}>
                                <TextField
                                  type="number"
                                  label="Batch window (minutes)"
                                  value={channelPref.batching.windowMinutes}
                                  onChange={(e) => handleChannelPreferenceChange(
                                    channel.id,
                                    'batching',
                                    { ...channelPref.batching, windowMinutes: parseInt(e.target.value) }
                                  )}
                                  size="small"
                                  fullWidth
                                />
                              </Grid>
                            )}
                          </>
                        )}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                );
              })}
            </CardContent>
          </Card>
        )}

        {/* Privacy Settings */}
        {showAdvanced && (
          <Card>
            <CardHeader
              title="Privacy & Analytics"
              avatar={<SecurityIcon />}
            />
            <CardContent>
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={tempPreferences.privacy.shareAnalytics}
                        onChange={(e) => handleGlobalPreferenceChange('shareAnalytics', e.target.checked)}
                      />
                    }
                    label="Share usage analytics"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={tempPreferences.privacy.personalizedContent}
                        onChange={(e) => handleGlobalPreferenceChange('personalizedContent', e.target.checked)}
                      />
                    }
                    label="Personalized notifications"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={tempPreferences.privacy.locationBased}
                        onChange={(e) => handleGlobalPreferenceChange('locationBased', e.target.checked)}
                      />
                    }
                    label="Location-based notifications"
                  />
                </Grid>

                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={tempPreferences.privacy.crossDeviceSync}
                        onChange={(e) => handleGlobalPreferenceChange('crossDeviceSync', e.target.checked)}
                      />
                    }
                    label="Cross-device synchronization"
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        )}
      </Box>
    </LocalizationProvider>
  );
};