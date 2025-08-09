/**
 * Mobile Notifications for iSECTECH Protect PWA
 * Real-time notification feed optimized for mobile interaction
 */

'use client';

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Avatar,
  Chip,
  Badge,
  Button,
  TextField,
  InputAdornment,
  Tabs,
  Tab,
  Fade,
  Slide,
  Alert,
  Snackbar,
  SwipeableDrawer,
  useTheme,
  alpha,
  Skeleton,
  Divider,
  BottomNavigation,
  BottomNavigationAction,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as SuccessIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  MarkEmailRead as MarkReadIcon,
  Delete as DeleteIcon,
  Share as ShareIcon,
  KeyboardArrowRight as ArrowIcon,
  Schedule as TimeIcon,
  PriorityHigh as PriorityIcon,
  Done as DoneIcon,
  DoneAll as DoneAllIcon,
  Close as CloseIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useSwipeable } from 'react-swipeable';
import { formatDistanceToNow } from 'date-fns';
import { useAppStore } from '@/lib/store';
import { useOfflineSync } from '@/lib/hooks/use-offline-sync';
import { useOffline } from '@/lib/hooks/use-offline';
import type { Notification, NotificationType } from '@/types';

interface NotificationAction {
  label: string;
  action: string;
  color?: 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';
  icon?: React.ElementType;
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

export function MobileNotifications() {
  const theme = useTheme();
  const app = useAppStore();
  const { isOnline } = useOffline();
  const offlineSync = useOfflineSync();

  const [selectedTab, setSelectedTab] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [showSearch, setShowSearch] = useState(false);
  const [selectedNotifications, setSelectedNotifications] = useState<Set<string>>(new Set());
  const [showActions, setShowActions] = useState(false);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [offlineNotifications, setOfflineNotifications] = useState<any[]>([]);

  // Load offline notifications on component mount
  useEffect(() => {
    loadOfflineNotifications();
  }, []);

  // Auto-refresh notifications
  useEffect(() => {
    const interval = setInterval(() => {
      if (isOnline) {
        // In a real app, this would fetch new notifications
        console.log('Auto-refreshing notifications...');
      } else {
        // Load offline notifications when offline
        loadOfflineNotifications();
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [isOnline]);

  const loadOfflineNotifications = async () => {
    try {
      const notifications = await offlineSync.getOfflineNotifications({
        limit: 50,
        filter: 'all'
      });
      setOfflineNotifications(notifications || []);
    } catch (error) {
      console.error('Failed to load offline notifications:', error);
    }
  };

  const filteredNotifications = useMemo(() => {
    // Combine online and offline notifications
    let allNotifications = isOnline ? app.notifications : [];
    
    // Add offline notifications, avoiding duplicates
    const offlineIds = new Set(offlineNotifications.map(n => n.id));
    const onlineIds = new Set(allNotifications.map(n => n.id));
    
    const uniqueOffline = offlineNotifications.filter(n => !onlineIds.has(n.id));
    allNotifications = [...allNotifications, ...uniqueOffline];
    
    let filtered = allNotifications;

    // Apply search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase().trim();
      filtered = filtered.filter(notification =>
        notification.title.toLowerCase().includes(query) ||
        notification.message?.toLowerCase().includes(query)
      );
    }

    // Apply tab filter
    switch (selectedTab) {
      case 0: // All
        break;
      case 1: // Unread
        filtered = filtered.filter(n => !n.read);
        break;
      case 2: // Critical
        filtered = filtered.filter(n => n.type === 'error');
        break;
      case 3: // Recent (last 24 hours)
        const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
        filtered = filtered.filter(n => n.timestamp > yesterday);
        break;
    }

    return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }, [app.notifications, searchQuery, selectedTab]);

  const unreadCount = app.notifications.filter(n => !n.read).length;
  const criticalCount = app.notifications.filter(n => n.type === 'error').length;

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    
    try {
      if (isOnline) {
        // Try to sync with server
        const result = await offlineSync.sync();
        if (result.success) {
          setSnackbarMessage(`Synced ${result.syncedCount} notifications`);
        } else {
          setSnackbarMessage('Sync failed, showing offline data');
        }
      }
      
      // Always reload offline notifications
      await loadOfflineNotifications();
      
    } catch (error) {
      setSnackbarMessage('Failed to refresh notifications');
      console.error('Refresh error:', error);
    } finally {
      setRefreshing(false);
      setSnackbarOpen(true);
    }
  }, [isOnline, offlineSync, loadOfflineNotifications]);

  const handleMarkAsRead = useCallback(async (notification: Notification) => {
    try {
      if (isOnline) {
        app.markNotificationRead(notification.id);
      } else {
        // Handle offline
        await offlineSync.markNotificationReadOffline(notification.id);
        await loadOfflineNotifications();
      }
      
      setSnackbarMessage(isOnline ? 'Marked as read' : 'Marked as read (will sync when online)');
      setSnackbarOpen(true);
    } catch (error) {
      setSnackbarMessage('Failed to mark as read');
      setSnackbarOpen(true);
      console.error('Mark as read error:', error);
    }
  }, [app, isOnline, offlineSync, loadOfflineNotifications]);

  const handleMarkAllAsRead = useCallback(async () => {
    try {
      if (isOnline) {
        app.markAllNotificationsRead();
      } else {
        // Handle offline - mark all visible notifications as read
        const promises = filteredNotifications.map(notification => 
          offlineSync.markNotificationReadOffline(notification.id)
        );
        await Promise.all(promises);
        await loadOfflineNotifications();
      }
      
      setSnackbarMessage(isOnline ? 'All notifications marked as read' : 'All notifications marked as read (will sync when online)');
      setSnackbarOpen(true);
    } catch (error) {
      setSnackbarMessage('Failed to mark all as read');
      setSnackbarOpen(true);
      console.error('Mark all as read error:', error);
    }
  }, [app, isOnline, offlineSync, filteredNotifications, loadOfflineNotifications]);

  const handleDeleteNotification = useCallback(async (notification: Notification) => {
    try {
      if (isOnline) {
        app.removeNotification(notification.id);
      } else {
        // Handle offline
        await offlineSync.deleteNotificationOffline(notification.id);
        await loadOfflineNotifications();
      }
      
      setSnackbarMessage(isOnline ? 'Notification deleted' : 'Notification deleted (will sync when online)');
      setSnackbarOpen(true);
    } catch (error) {
      setSnackbarMessage('Failed to delete notification');
      setSnackbarOpen(true);
      console.error('Delete notification error:', error);
    }
  }, [app, isOnline, offlineSync, loadOfflineNotifications]);

  const handleBulkAction = useCallback(async (action: string) => {
    const notifications = Array.from(selectedNotifications);
    
    try {
      switch (action) {
        case 'markRead':
          if (isOnline) {
            notifications.forEach(id => app.markNotificationRead(id));
          } else {
            await Promise.all(
              notifications.map(id => offlineSync.markNotificationReadOffline(id))
            );
            await loadOfflineNotifications();
          }
          setSnackbarMessage(
            isOnline 
              ? `${notifications.length} notifications marked as read`
              : `${notifications.length} notifications marked as read (will sync when online)`
          );
          break;
        case 'delete':
          if (isOnline) {
            notifications.forEach(id => app.removeNotification(id));
          } else {
            await Promise.all(
              notifications.map(id => offlineSync.deleteNotificationOffline(id))
            );
            await loadOfflineNotifications();
          }
          setSnackbarMessage(
            isOnline
              ? `${notifications.length} notifications deleted`
              : `${notifications.length} notifications deleted (will sync when online)`
          );
          break;
      }
    } catch (error) {
      setSnackbarMessage(`Failed to ${action} notifications`);
      console.error('Bulk action error:', error);
    }
    
    setSelectedNotifications(new Set());
    setShowActions(false);
    setSnackbarOpen(true);
  }, [selectedNotifications, app, isOnline, offlineSync, loadOfflineNotifications]);

  const handleNotificationSwipe = useCallback((notification: Notification, direction: 'left' | 'right') => {
    if (direction === 'right') {
      // Swipe right - mark as read
      if (!notification.read) {
        handleMarkAsRead(notification);
      }
    } else {
      // Swipe left - delete
      handleDeleteNotification(notification);
    }
  }, [handleMarkAsRead, handleDeleteNotification]);

  const toggleNotificationSelection = useCallback((notificationId: string) => {
    const newSelected = new Set(selectedNotifications);
    if (newSelected.has(notificationId)) {
      newSelected.delete(notificationId);
    } else {
      newSelected.add(notificationId);
    }
    setSelectedNotifications(newSelected);
    setShowActions(newSelected.size > 0);
  }, [selectedNotifications]);

  const renderNotificationItem = (notification: Notification, index: number) => {
    const Icon = notificationIcons[notification.type];
    const color = notificationColors[notification.type];
    const isSelected = selectedNotifications.has(notification.id);
    const priority = notification.type === 'error' ? 'high' : 'normal';

    const swipeHandlers = useSwipeable({
      onSwipedLeft: () => handleNotificationSwipe(notification, 'left'),
      onSwipedRight: () => handleNotificationSwipe(notification, 'right'),
      trackMouse: false,
      delta: 50,
    });

    return (
      <Slide
        key={notification.id}
        direction="up"
        in={true}
        timeout={200 + index * 50}
      >
        <Card
          sx={{
            mb: 1,
            bgcolor: notification.read ? 'background.paper' : alpha(color, 0.05),
            border: `1px solid ${notification.read ? theme.palette.divider : alpha(color, 0.2)}`,
            borderLeft: !notification.read ? `4px solid ${color}` : undefined,
            ...(isSelected && {
              bgcolor: alpha(theme.palette.primary.main, 0.1),
              border: `1px solid ${theme.palette.primary.main}`,
            }),
          }}
          {...swipeHandlers}
        >
          <ListItem
            sx={{
              p: 2,
              cursor: 'pointer',
              '&:hover': {
                bgcolor: alpha(theme.palette.action.hover, 0.5),
              },
            }}
            onClick={() => toggleNotificationSelection(notification.id)}
          >
            <ListItemIcon sx={{ minWidth: 48 }}>
              <Badge
                variant="dot"
                invisible={notification.read}
                color={notification.type === 'error' ? 'error' : 'primary'}
              >
                <Avatar
                  sx={{
                    bgcolor: alpha(color, 0.1),
                    color: color,
                    width: 36,
                    height: 36,
                  }}
                >
                  <Icon sx={{ fontSize: 18 }} />
                </Avatar>
              </Badge>
            </ListItemIcon>

            <ListItemText
              primary={
                <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, mb: 0.5 }}>
                  <Typography
                    variant="body2"
                    sx={{
                      fontWeight: notification.read ? 400 : 600,
                      flexGrow: 1,
                      lineHeight: 1.3,
                    }}
                  >
                    {notification.title}
                  </Typography>
                  
                  {priority === 'high' && (
                    <PriorityIcon sx={{ fontSize: 14, color: 'error.main' }} />
                  )}
                  
                  <Chip
                    label={notification.type}
                    size="small"
                    variant="outlined"
                    sx={{
                      fontSize: '0.6rem',
                      height: 18,
                      borderColor: color,
                      color: color,
                      textTransform: 'capitalize',
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
                        mb: 0.5,
                      }}
                    >
                      {notification.message}
                    </Typography>
                  )}
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <TimeIcon sx={{ fontSize: 10, color: 'text.disabled' }} />
                    <Typography variant="caption" color="text.disabled">
                      {formatDistanceToNow(notification.timestamp, { addSuffix: true })}
                    </Typography>
                    
                    {!notification.read && (
                      <Chip
                        label="New"
                        size="small"
                        color="primary"
                        variant="filled"
                        sx={{ fontSize: '0.5rem', height: 14 }}
                      />
                    )}
                  </Box>
                </Box>
              }
            />

            <ListItemSecondaryAction>
              <ArrowIcon sx={{ color: 'text.disabled' }} />
            </ListItemSecondaryAction>
          </ListItem>
        </Card>
      </Slide>
    );
  };

  return (
    <Box sx={{ pb: showActions ? 8 : 2 }}>
      {/* Header with Actions */}
      <Box sx={{ p: 2, pb: 0 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h5" sx={{ fontWeight: 700 }}>
            Notifications
            {!isOnline && (
              <Chip
                label="Offline"
                size="small"
                color="warning"
                variant="outlined"
                sx={{ ml: 1, fontSize: '0.7rem', height: 20 }}
              />
            )}
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <IconButton
              size="small"
              onClick={() => setShowSearch(!showSearch)}
              color={showSearch ? 'primary' : 'default'}
            >
              <SearchIcon />
            </IconButton>
            
            <IconButton
              size="small"
              onClick={handleRefresh}
              disabled={refreshing}
            >
              <RefreshIcon sx={{ animation: refreshing ? 'spin 1s linear infinite' : undefined }} />
            </IconButton>
            
            <IconButton
              size="small"
              onClick={handleMarkAllAsRead}
              disabled={unreadCount === 0}
            >
              <DoneAllIcon />
            </IconButton>
          </Box>
        </Box>

        {/* Search Bar */}
        <Fade in={showSearch}>
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
              endAdornment: searchQuery && (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => setSearchQuery('')}>
                    <CloseIcon fontSize="small" />
                  </IconButton>
                </InputAdornment>
              ),
            }}
            sx={{ mb: 2, display: showSearch ? 'flex' : 'none' }}
          />
        </Fade>
      </Box>

      {/* Tab Navigation */}
      <Box sx={{ borderBottom: `1px solid ${theme.palette.divider}`, mb: 2 }}>
        <Tabs
          value={selectedTab}
          onChange={(_, newValue) => setSelectedTab(newValue)}
          variant="fullWidth"
          sx={{
            px: 2,
            minHeight: 40,
            '& .MuiTab-root': {
              minHeight: 40,
              py: 1,
              fontSize: '0.8rem',
              minWidth: 0,
            },
          }}
        >
          <Tab label={`All (${filteredNotifications.length})`} />
          <Tab label={`Unread (${unreadCount})`} />
          <Tab label={`Critical (${criticalCount})`} />
          <Tab label="Recent" />
        </Tabs>
      </Box>

      {/* Notifications List */}
      <Box sx={{ px: 2 }}>
        {filteredNotifications.length === 0 ? (
          <Card sx={{ textAlign: 'center', py: 4 }}>
            <NotificationsIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              {searchQuery ? 'No matching notifications' : 'No notifications'}
            </Typography>
            <Typography variant="body2" color="text.disabled" sx={{ mt: 1 }}>
              {searchQuery ? 'Try adjusting your search terms' : 'You\'re all caught up!'}
            </Typography>
          </Card>
        ) : (
          <List sx={{ p: 0 }}>
            {filteredNotifications.map(renderNotificationItem)}
          </List>
        )}
      </Box>

      {/* Bulk Actions Bottom Sheet */}
      <SwipeableDrawer
        anchor="bottom"
        open={showActions}
        onClose={() => setShowActions(false)}
        onOpen={() => setShowActions(true)}
        disableSwipeToOpen
        PaperProps={{
          sx: {
            borderRadius: '16px 16px 0 0',
            maxHeight: '50vh',
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ width: 40, height: 4, bgcolor: 'divider', borderRadius: 2, mx: 'auto', mb: 2 }} />
          
          <Typography variant="h6" sx={{ mb: 2 }}>
            {selectedNotifications.size} selected
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Button
              variant="contained"
              startIcon={<MarkReadIcon />}
              onClick={() => handleBulkAction('markRead')}
              size="small"
            >
              Mark Read
            </Button>
            
            <Button
              variant="outlined"
              startIcon={<DeleteIcon />}
              onClick={() => handleBulkAction('delete')}
              color="error"
              size="small"
            >
              Delete
            </Button>
            
            <Button
              variant="outlined"
              onClick={() => {
                setSelectedNotifications(new Set());
                setShowActions(false);
              }}
              size="small"
            >
              Cancel
            </Button>
          </Box>
        </Box>
      </SwipeableDrawer>

      {/* Success Snackbar */}
      <Snackbar
        open={snackbarOpen}
        autoHideDuration={3000}
        onClose={() => setSnackbarOpen(false)}
        message={snackbarMessage}
        action={
          <IconButton size="small" color="inherit" onClick={() => setSnackbarOpen(false)}>
            <CloseIcon fontSize="small" />
          </IconButton>
        }
      />
    </Box>
  );
}

export default MobileNotifications;