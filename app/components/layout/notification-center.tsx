/**
 * Notification Center for iSECTECH Protect
 * Real-time security notifications and alerts management
 */

'use client';

import React, { useState, useMemo } from 'react';
import {
  Menu,
  MenuProps,
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Button,
  Divider,
  Badge,
  TextField,
  InputAdornment,
  Tabs,
  Tab,
  Paper,
  Tooltip,
  alpha,
  useTheme,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as SuccessIcon,
  Close as CloseIcon,
  MarkEmailRead as MarkReadIcon,
  ClearAll as ClearAllIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  AccessTime as TimeIcon,
  HighPriority as HighPriorityIcon,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { useAppStore } from '@/lib/store';
import type { Notification, NotificationType } from '@/types';

interface NotificationCenterProps extends Omit<MenuProps, 'children'> {
  onClose: () => void;
}

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
      id={`notification-tabpanel-${index}`}
      aria-labelledby={`notification-tab-${index}`}
      {...other}
    >
      {value === index && children}
    </div>
  );
}

const notificationIcons: Record<NotificationType, React.ElementType> = {
  success: SuccessIcon,
  error: ErrorIcon,
  warning: WarningIcon,
  info: InfoIcon,
};

const notificationColors: Record<NotificationType, string> = {
  success: '#4caf50',
  error: '#f44336',
  warning: '#ff9800',
  info: '#2196f3',
};

const notificationLabels: Record<NotificationType, string> = {
  success: 'Success',
  error: 'Critical',
  warning: 'Warning',
  info: 'Information',
};

export function NotificationCenter({ onClose, ...menuProps }: NotificationCenterProps) {
  const theme = useTheme();
  const app = useAppStore();
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTab, setSelectedTab] = useState(0);
  const [showFilters, setShowFilters] = useState(false);

  // Filter and categorize notifications
  const filteredNotifications = useMemo(() => {
    let filtered = app.notifications;

    // Apply search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase().trim();
      filtered = filtered.filter(notification =>
        notification.title.toLowerCase().includes(query) ||
        notification.message?.toLowerCase().includes(query)
      );
    }

    // Categorize by tab
    switch (selectedTab) {
      case 0: // All
        break;
      case 1: // Unread
        filtered = filtered.filter(n => !n.read);
        break;
      case 2: // Security
        filtered = filtered.filter(n => 
          n.type === 'error' || 
          n.title.toLowerCase().includes('security') ||
          n.title.toLowerCase().includes('threat') ||
          n.title.toLowerCase().includes('alert')
        );
        break;
      case 3: // System
        filtered = filtered.filter(n => 
          n.type === 'info' || 
          n.title.toLowerCase().includes('system') ||
          n.title.toLowerCase().includes('update')
        );
        break;
      default:
        break;
    }

    return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }, [app.notifications, searchQuery, selectedTab]);

  const unreadCount = app.notifications.filter(n => !n.read).length;
  const securityCount = app.notifications.filter(n => 
    n.type === 'error' || 
    n.title.toLowerCase().includes('security') ||
    n.title.toLowerCase().includes('threat') ||
    n.title.toLowerCase().includes('alert')
  ).length;

  const handleMarkAsRead = (notification: Notification) => {
    app.markNotificationRead(notification.id);
  };

  const handleMarkAllAsRead = () => {
    app.markAllNotificationsRead();
  };

  const handleClearAll = () => {
    app.clearNotifications();
  };

  const handleNotificationClick = (notification: Notification) => {
    if (!notification.read) {
      handleMarkAsRead(notification);
    }
    
    // Handle notification actions if any
    if (notification.actions && notification.actions.length > 0) {
      const primaryAction = notification.actions.find(a => a.primary);
      if (primaryAction) {
        // Handle action based on action type
        console.log('Executing action:', primaryAction.action);
      }
    }
  };

  const handleRemoveNotification = (notification: Notification) => {
    app.removeNotification(notification.id);
  };

  const renderNotificationIcon = (type: NotificationType) => {
    const IconComponent = notificationIcons[type];
    return (
      <IconComponent
        sx={{
          color: notificationColors[type],
          fontSize: 20,
        }}
      />
    );
  };

  const getNotificationPriority = (notification: Notification) => {
    if (notification.type === 'error') return 'high';
    if (notification.type === 'warning') return 'medium';
    return 'low';
  };

  const renderNotificationItem = (notification: Notification) => {
    const priority = getNotificationPriority(notification);
    const isHigh = priority === 'high';

    return (
      <ListItem
        key={notification.id}
        sx={{
          backgroundColor: notification.read 
            ? 'transparent' 
            : alpha(theme.palette.primary.main, 0.05),
          borderLeft: !notification.read 
            ? `3px solid ${notificationColors[notification.type]}` 
            : '3px solid transparent',
          mb: 0.5,
          borderRadius: 1,
          cursor: 'pointer',
          '&:hover': {
            backgroundColor: alpha(theme.palette.action.hover, 0.5),
          },
        }}
        onClick={() => handleNotificationClick(notification)}
      >
        <ListItemIcon sx={{ minWidth: 40 }}>
          <Badge
            variant="dot"
            invisible={notification.read}
            color={notification.type === 'error' ? 'error' : 'primary'}
          >
            {renderNotificationIcon(notification.type)}
          </Badge>
        </ListItemIcon>

        <ListItemText
          primary={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography
                variant="body2"
                sx={{
                  fontWeight: notification.read ? 400 : 600,
                  flexGrow: 1,
                }}
              >
                {notification.title}
              </Typography>
              
              {isHigh && (
                <HighPriorityIcon 
                  sx={{ 
                    fontSize: 16, 
                    color: theme.palette.error.main 
                  }} 
                />
              )}
              
              <Chip
                label={notificationLabels[notification.type]}
                size="small"
                variant="outlined"
                sx={{
                  fontSize: '0.6rem',
                  height: 20,
                  borderColor: notificationColors[notification.type],
                  color: notificationColors[notification.type],
                }}
              />
            </Box>
          }
          secondary={
            <Box>
              {notification.message && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                    lineHeight: 1.2,
                  }}
                >
                  {notification.message}
                </Typography>
              )}
              
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5, gap: 1 }}>
                <TimeIcon sx={{ fontSize: 12, color: 'text.disabled' }} />
                <Typography variant="caption" color="text.disabled">
                  {formatDistanceToNow(notification.timestamp, { addSuffix: true })}
                </Typography>
              </Box>
            </Box>
          }
        />

        <ListItemSecondaryAction>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
            {!notification.read && (
              <Tooltip title="Mark as read">
                <IconButton
                  size="small"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleMarkAsRead(notification);
                  }}
                >
                  <MarkReadIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
            
            <Tooltip title="Remove">
              <IconButton
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  handleRemoveNotification(notification);
                }}
              >
                <CloseIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </ListItemSecondaryAction>
      </ListItem>
    );
  };

  return (
    <Menu
      {...menuProps}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: 400,
          maxHeight: 600,
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
        },
      }}
      transformOrigin={{ horizontal: 'right', vertical: 'top' }}
      anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
    >
      {/* Header */}
      <Box sx={{ p: 2, borderBottom: `1px solid ${theme.palette.divider}` }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <NotificationsIcon />
            Notifications
            {unreadCount > 0 && (
              <Badge badgeContent={unreadCount} color="error" />
            )}
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 0.5 }}>
            <Tooltip title="Mark all as read">
              <IconButton size="small" onClick={handleMarkAllAsRead} disabled={unreadCount === 0}>
                <MarkReadIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            
            <Tooltip title="Clear all">
              <IconButton size="small" onClick={handleClearAll} disabled={app.notifications.length === 0}>
                <ClearAllIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            
            <Tooltip title="Toggle filters">
              <IconButton size="small" onClick={() => setShowFilters(!showFilters)}>
                <FilterIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Search */}
        {showFilters && (
          <TextField
            fullWidth
            size="small"
            placeholder="Search notifications..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" />
                </InputAdornment>
              ),
            }}
            sx={{ mt: 1 }}
          />
        )}
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
        <Tabs
          value={selectedTab}
          onChange={(_, newValue) => setSelectedTab(newValue)}
          variant="fullWidth"
          sx={{
            minHeight: 40,
            '& .MuiTab-root': {
              minHeight: 40,
              py: 1,
              fontSize: '0.75rem',
            },
          }}
        >
          <Tab 
            label={`All (${app.notifications.length})`}
            id="notification-tab-0"
          />
          <Tab 
            label={`Unread (${unreadCount})`}
            id="notification-tab-1"
          />
          <Tab 
            label={`Security (${securityCount})`}
            id="notification-tab-2"
          />
          <Tab 
            label="System"
            id="notification-tab-3"
          />
        </Tabs>
      </Box>

      {/* Notification List */}
      <Box sx={{ flexGrow: 1, overflow: 'auto', maxHeight: 400 }}>
        {filteredNotifications.length === 0 ? (
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <NotificationsIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
            <Typography variant="body2" color="text.secondary">
              {searchQuery ? 'No notifications match your search' : 'No notifications'}
            </Typography>
          </Box>
        ) : (
          <List sx={{ p: 1 }}>
            {filteredNotifications.map(renderNotificationItem)}
          </List>
        )}
      </Box>

      {/* Footer Actions */}
      {app.notifications.length > 0 && (
        <>
          <Divider />
          <Box sx={{ p: 1 }}>
            <Button
              fullWidth
              size="small"
              variant="text"
              onClick={() => {
                // Navigate to full notifications page
                onClose();
              }}
            >
              View All Notifications
            </Button>
          </Box>
        </>
      )}
    </Menu>
  );
}

export default NotificationCenter;