'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
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
  Chip,
  Badge,
  Tabs,
  Tab,
  TextField,
  InputAdornment,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Skeleton,
  Divider,
  useTheme
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Delete as DeleteIcon,
  MarkAsUnread as MarkAsUnreadIcon,
  Search as SearchIcon,
  FilterList as FilterListIcon,
  Archive as ArchiveIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { motion, AnimatePresence } from 'framer-motion';
import { FixedSizeList as VirtualList } from 'react-window';
import { useVirtualizedList } from '../../../lib/hooks/use-virtualized-list';
import { useNotificationManager } from '../../../lib/hooks/use-notification-manager';
import {
  UnifiedNotificationCenterProps,
  NotificationMessage,
  DeliveryReceipt
} from './types';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`notification-tabpanel-${index}`}
    >
      {value === index && <Box sx={{ p: 0 }}>{children}</Box>}
    </div>
  );
}

export const UnifiedNotificationCenter: React.FC<UnifiedNotificationCenterProps> = ({
  config,
  onNotificationInteraction,
  onPreferencesChange,
  maxDisplayItems = 100,
  autoRefresh = true,
  showAnalytics = false
}) => {
  const theme = useTheme();
  
  // State management
  const [notifications, setNotifications] = useState<NotificationMessage[]>([]);
  const [filteredNotifications, setFilteredNotifications] = useState<NotificationMessage[]>([]);
  const [selectedTab, setSelectedTab] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterPriority, setFilterPriority] = useState<string>('all');
  const [selectedNotifications, setSelectedNotifications] = useState<Set<string>>(new Set());
  const [detailDialog, setDetailDialog] = useState<{ open: boolean; notification: NotificationMessage | null }>({ open: false, notification: null });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Notification management hook
  const {
    fetchNotifications,
    markAsRead,
    markAsUnread,
    deleteNotification,
    archiveNotification,
    bulkUpdateNotifications,
    getDeliveryStatus,
    isLoading: notificationLoading
  } = useNotificationManager({
    userId: config.userId,
    tenantId: config.tenantId
  });

  // Virtualized list hook for performance
  const {
    virtualizedItems,
    scrollToIndex,
    resetCache
  } = useVirtualizedList({
    items: filteredNotifications,
    itemHeight: 80,
    containerHeight: 600,
    overscan: 5
  });

  // Load notifications on component mount
  useEffect(() => {
    loadNotifications();
  }, []);

  // Auto-refresh notifications
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadNotifications();
    }, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, [autoRefresh]);

  // Filter notifications based on search and filters
  useEffect(() => {
    let filtered = notifications;

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(notification =>
        notification.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        notification.body.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Apply priority filter
    if (filterPriority !== 'all') {
      filtered = filtered.filter(notification => notification.priority === filterPriority);
    }

    // Apply tab filter
    switch (selectedTab) {
      case 0: // All
        break;
      case 1: // Unread
        filtered = filtered.filter(notification => !notification.data?.read);
        break;
      case 2: // Security
        filtered = filtered.filter(notification => 
          notification.metadata.category === 'security' || 
          notification.data?.type === 'security-alert'
        );
        break;
      case 3: // System
        filtered = filtered.filter(notification => 
          notification.metadata.category === 'system' ||
          notification.data?.type === 'system-status'
        );
        break;
    }

    setFilteredNotifications(filtered.slice(0, maxDisplayItems));
  }, [notifications, searchTerm, filterPriority, selectedTab, maxDisplayItems]);

  const loadNotifications = async () => {
    try {
      setIsLoading(true);
      setError(null);

      const fetchedNotifications = await fetchNotifications({
        limit: maxDisplayItems * 2, // Fetch more for filtering
        includeRead: true,
        includeArchived: false
      });

      setNotifications(fetchedNotifications);
    } catch (error) {
      console.error('Failed to load notifications:', error);
      setError('Failed to load notifications');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setSelectedTab(newValue);
    setSelectedNotifications(new Set()); // Clear selections on tab change
  };

  const handleNotificationClick = async (notification: NotificationMessage) => {
    // Mark as read if unread
    if (!notification.data?.read) {
      await markAsRead(notification.id);
      setNotifications(prev => prev.map(n => 
        n.id === notification.id 
          ? { ...n, data: { ...n.data, read: true, readAt: new Date() } }
          : n
      ));
    }

    // Open detail dialog
    setDetailDialog({ open: true, notification });

    // Notify parent of interaction
    onNotificationInteraction?.(notification.id, 'clicked');
  };

  const handleMarkAsRead = async (notificationId: string) => {
    try {
      await markAsRead(notificationId);
      setNotifications(prev => prev.map(n => 
        n.id === notificationId 
          ? { ...n, data: { ...n.data, read: true, readAt: new Date() } }
          : n
      ));
      onNotificationInteraction?.(notificationId, 'mark-read');
    } catch (error) {
      console.error('Failed to mark as read:', error);
    }
  };

  const handleMarkAsUnread = async (notificationId: string) => {
    try {
      await markAsUnread(notificationId);
      setNotifications(prev => prev.map(n => 
        n.id === notificationId 
          ? { ...n, data: { ...n.data, read: false, readAt: undefined } }
          : n
      ));
      onNotificationInteraction?.(notificationId, 'mark-unread');
    } catch (error) {
      console.error('Failed to mark as unread:', error);
    }
  };

  const handleDelete = async (notificationId: string) => {
    try {
      await deleteNotification(notificationId);
      setNotifications(prev => prev.filter(n => n.id !== notificationId));
      onNotificationInteraction?.(notificationId, 'deleted');
    } catch (error) {
      console.error('Failed to delete notification:', error);
    }
  };

  const handleBulkAction = async (action: 'read' | 'unread' | 'delete' | 'archive') => {
    if (selectedNotifications.size === 0) return;

    try {
      const ids = Array.from(selectedNotifications);
      await bulkUpdateNotifications(ids, action);

      switch (action) {
        case 'read':
          setNotifications(prev => prev.map(n => 
            selectedNotifications.has(n.id) 
              ? { ...n, data: { ...n.data, read: true, readAt: new Date() } }
              : n
          ));
          break;
        case 'unread':
          setNotifications(prev => prev.map(n => 
            selectedNotifications.has(n.id) 
              ? { ...n, data: { ...n.data, read: false, readAt: undefined } }
              : n
          ));
          break;
        case 'delete':
          setNotifications(prev => prev.filter(n => !selectedNotifications.has(n.id)));
          break;
        case 'archive':
          setNotifications(prev => prev.filter(n => !selectedNotifications.has(n.id)));
          break;
      }

      setSelectedNotifications(new Set());
    } catch (error) {
      console.error(`Failed to perform bulk ${action}:`, error);
    }
  };

  const handleNotificationToggle = (notificationId: string) => {
    setSelectedNotifications(prev => {
      const newSet = new Set(prev);
      if (newSet.has(notificationId)) {
        newSet.delete(notificationId);
      } else {
        newSet.add(notificationId);
      }
      return newSet;
    });
  };

  const getNotificationIcon = (notification: NotificationMessage) => {
    switch (notification.priority) {
      case 'critical':
        return <WarningIcon color="error" />;
      case 'high':
        return <SecurityIcon color="warning" />;
      case 'medium':
        return <InfoIcon color="info" />;
      default:
        return <NotificationsIcon color="action" />;
    }
  };

  const getNotificationColor = (notification: NotificationMessage) => {
    if (!notification.data?.read) return 'primary.light';
    switch (notification.priority) {
      case 'critical': return 'error.light';
      case 'high': return 'warning.light';
      case 'medium': return 'info.light';
      default: return 'grey.100';
    }
  };

  const formatNotificationTime = (date: Date) => {
    return formatDistanceToNow(date, { addSuffix: true });
  };

  // Memoized tab counts
  const tabCounts = useMemo(() => {
    const unread = notifications.filter(n => !n.data?.read).length;
    const security = notifications.filter(n => 
      n.metadata.category === 'security' || n.data?.type === 'security-alert'
    ).length;
    const system = notifications.filter(n => 
      n.metadata.category === 'system' || n.data?.type === 'system-status'
    ).length;

    return { all: notifications.length, unread, security, system };
  }, [notifications]);

  // Virtual list item renderer
  const NotificationItem = ({ index, style }: { index: number; style: React.CSSProperties }) => {
    const notification = filteredNotifications[index];
    if (!notification) return null;

    return (
      <div style={style}>
        <ListItem
          button
          onClick={() => handleNotificationClick(notification)}
          sx={{
            bgcolor: getNotificationColor(notification),
            borderLeft: `4px solid ${theme.palette[notification.priority === 'critical' ? 'error' : 
              notification.priority === 'high' ? 'warning' : 'primary'].main}`,
            mb: 0.5,
            borderRadius: 1,
            '&:hover': {
              bgcolor: theme.palette.action.hover
            }
          }}
        >
          <ListItemIcon>
            <Badge
              color="error"
              variant="dot"
              invisible={notification.data?.read}
            >
              {getNotificationIcon(notification)}
            </Badge>
          </ListItemIcon>
          
          <ListItemText
            primary={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography 
                  variant="subtitle2" 
                  fontWeight={notification.data?.read ? 400 : 600}
                  noWrap
                  sx={{ flex: 1 }}
                >
                  {notification.title}
                </Typography>
                <Chip
                  label={notification.priority}
                  size="small"
                  color={notification.priority === 'critical' ? 'error' : 
                    notification.priority === 'high' ? 'warning' : 'default'}
                  variant="outlined"
                />
              </Box>
            }
            secondary={
              <Box>
                <Typography 
                  variant="body2" 
                  color="text.secondary" 
                  noWrap
                  sx={{ mb: 0.5 }}
                >
                  {notification.body}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {formatNotificationTime(notification.createdAt)}
                </Typography>
              </Box>
            }
          />
          
          <ListItemSecondaryAction>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <IconButton
                edge="end"
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  if (notification.data?.read) {
                    handleMarkAsUnread(notification.id);
                  } else {
                    handleMarkAsRead(notification.id);
                  }
                }}
              >
                {notification.data?.read ? <MarkAsUnreadIcon /> : <CheckCircleIcon />}
              </IconButton>
              <IconButton
                edge="end"
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  handleDelete(notification.id);
                }}
              >
                <DeleteIcon />
              </IconButton>
            </Box>
          </ListItemSecondaryAction>
        </ListItem>
      </div>
    );
  };

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header with Search and Filters */}
      <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}>
          <TextField
            placeholder="Search notifications..."
            variant="outlined"
            size="small"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              )
            }}
            sx={{ flex: 1 }}
          />
          
          <Button
            variant="outlined"
            size="small"
            startIcon={<RefreshIcon />}
            onClick={loadNotifications}
            disabled={isLoading}
          >
            Refresh
          </Button>
        </Box>

        {/* Bulk Actions */}
        {selectedNotifications.size > 0 && (
          <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
            <Typography variant="body2" sx={{ alignSelf: 'center' }}>
              {selectedNotifications.size} selected
            </Typography>
            <Button size="small" onClick={() => handleBulkAction('read')}>
              Mark Read
            </Button>
            <Button size="small" onClick={() => handleBulkAction('unread')}>
              Mark Unread
            </Button>
            <Button size="small" onClick={() => handleBulkAction('archive')}>
              Archive
            </Button>
            <Button size="small" color="error" onClick={() => handleBulkAction('delete')}>
              Delete
            </Button>
          </Box>
        )}
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={selectedTab} onChange={handleTabChange}>
          <Tab 
            label={
              <Badge badgeContent={tabCounts.all} color="primary" max={99}>
                All
              </Badge>
            } 
          />
          <Tab 
            label={
              <Badge badgeContent={tabCounts.unread} color="error" max={99}>
                Unread
              </Badge>
            } 
          />
          <Tab 
            label={
              <Badge badgeContent={tabCounts.security} color="warning" max={99}>
                Security
              </Badge>
            } 
          />
          <Tab 
            label={
              <Badge badgeContent={tabCounts.system} color="info" max={99}>
                System
              </Badge>
            } 
          />
        </Tabs>
      </Box>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ m: 2 }}>
          {error}
        </Alert>
      )}

      {/* Notification List */}
      <Box sx={{ flex: 1, overflow: 'hidden' }}>
        <TabPanel value={selectedTab} index={selectedTab}>
          {isLoading ? (
            <Box sx={{ p: 2 }}>
              {Array.from({ length: 5 }).map((_, index) => (
                <Box key={index} sx={{ mb: 1 }}>
                  <Skeleton variant="rectangular" height={70} />
                </Box>
              ))}
            </Box>
          ) : filteredNotifications.length === 0 ? (
            <Box sx={{ 
              display: 'flex', 
              flexDirection: 'column', 
              alignItems: 'center', 
              justifyContent: 'center',
              height: 300,
              color: 'text.secondary'
            }}>
              <NotificationsIcon sx={{ fontSize: 64, mb: 2 }} />
              <Typography variant="h6">No notifications</Typography>
              <Typography variant="body2">
                {searchTerm ? 'No notifications match your search' : 'You\'re all caught up!'}
              </Typography>
            </Box>
          ) : (
            <VirtualList
              height={600}
              width="100%"
              itemCount={filteredNotifications.length}
              itemSize={80}
              overscanCount={5}
            >
              {NotificationItem}
            </VirtualList>
          )}
        </TabPanel>
      </Box>

      {/* Notification Detail Dialog */}
      <Dialog
        open={detailDialog.open}
        onClose={() => setDetailDialog({ open: false, notification: null })}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {detailDialog.notification && getNotificationIcon(detailDialog.notification)}
            <Typography variant="h6">Notification Details</Typography>
          </Box>
        </DialogTitle>
        
        <DialogContent>
          {detailDialog.notification && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {detailDialog.notification.title}
              </Typography>
              
              <Typography variant="body1" paragraph>
                {detailDialog.notification.body}
              </Typography>
              
              <Divider sx={{ my: 2 }} />
              
              <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                <Chip 
                  label={detailDialog.notification.priority} 
                  color={detailDialog.notification.priority === 'critical' ? 'error' : 
                    detailDialog.notification.priority === 'high' ? 'warning' : 'default'}
                  size="small"
                />
                <Chip 
                  label={detailDialog.notification.metadata.category} 
                  variant="outlined"
                  size="small"
                />
                {detailDialog.notification.metadata.tags.map((tag, index) => (
                  <Chip 
                    key={index} 
                    label={tag} 
                    variant="outlined" 
                    size="small"
                  />
                ))}
              </Box>
              
              <Typography variant="body2" color="text.secondary">
                Received: {formatNotificationTime(detailDialog.notification.createdAt)}
              </Typography>
              
              {detailDialog.notification.data?.readAt && (
                <Typography variant="body2" color="text.secondary">
                  Read: {formatNotificationTime(detailDialog.notification.data.readAt)}
                </Typography>
              )}
            </Box>
          )}
        </DialogContent>
        
        <DialogActions>
          <Button onClick={() => setDetailDialog({ open: false, notification: null })}>
            Close
          </Button>
          {detailDialog.notification && (
            <Button 
              onClick={() => {
                if (detailDialog.notification!.data?.read) {
                  handleMarkAsUnread(detailDialog.notification!.id);
                } else {
                  handleMarkAsRead(detailDialog.notification!.id);
                }
                setDetailDialog({ open: false, notification: null });
              }}
            >
              Mark as {detailDialog.notification.data?.read ? 'Unread' : 'Read'}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};