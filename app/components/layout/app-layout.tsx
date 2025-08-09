/**
 * Main Application Layout for iSECTECH Protect
 * Production-grade layout with sidebar navigation, header, and security features
 */

'use client';

import React, { useState, useEffect } from 'react';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  IconButton,
  Typography,
  Badge,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  Tooltip,
  useTheme,
  useMediaQuery,
  Alert,
  Snackbar,
  Chip,
  Stack,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Notifications as NotificationsIcon,
  AccountCircle as AccountIcon,
  Security as SecurityIcon,
  Brightness4 as DarkModeIcon,
  Brightness7 as LightModeIcon,
  ExitToApp as LogoutIcon,
  Settings as SettingsIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  WiFi as OnlineIcon,
  WifiOff as OfflineIcon,
} from '@mui/icons-material';
import { useAuthStore, useAppStore, useStores } from '@/lib/store';
import { formatClearanceLevel, formatUserRole } from '@/types';
import Sidebar from './sidebar';
import NotificationCenter from './notification-center';
import type { Notification } from '@/types';

const DRAWER_WIDTH = 280;
const DRAWER_WIDTH_COLLAPSED = 80;

interface AppLayoutProps {
  children: React.ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  const { auth, app } = useStores();
  const [userMenuAnchor, setUserMenuAnchor] = useState<null | HTMLElement>(null);
  const [notificationAnchor, setNotificationAnchor] = useState<null | HTMLElement>(null);
  const [currentNotification, setCurrentNotification] = useState<Notification | null>(null);

  // Handle responsive sidebar
  useEffect(() => {
    if (isMobile && app.sidebarOpen) {
      app.setSidebarOpen(false);
    }
  }, [isMobile, app]);

  // Handle notifications
  useEffect(() => {
    if (app.notifications.length > 0) {
      const latestNotification = app.notifications[0];
      if (!latestNotification.read && latestNotification.duration && latestNotification.duration > 0) {
        setCurrentNotification(latestNotification);
      }
    }
  }, [app.notifications]);

  const handleUserMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setUserMenuAnchor(event.currentTarget);
  };

  const handleUserMenuClose = () => {
    setUserMenuAnchor(null);
  };

  const handleNotificationOpen = (event: React.MouseEvent<HTMLElement>) => {
    setNotificationAnchor(event.currentTarget);
  };

  const handleNotificationClose = () => {
    setNotificationAnchor(null);
  };

  const handleLogout = async () => {
    handleUserMenuClose();
    try {
      await auth.logout();
      app.showSuccess('Logged out successfully');
    } catch (error) {
      app.showError('Logout failed', 'Please try again');
    }
  };

  const handleThemeToggle = () => {
    const newTheme = app.theme === 'light' ? 'dark' : 'light';
    app.setTheme(newTheme);
  };

  const handleNotificationDismiss = () => {
    if (currentNotification) {
      app.markNotificationRead(currentNotification.id);
      setCurrentNotification(null);
    }
  };

  const getConnectionStatusColor = () => {
    const { online, apiConnected, websocketConnected } = app.connectionStatus;
    if (!online) return theme.palette.error.main;
    if (!apiConnected || !websocketConnected) return theme.palette.warning.main;
    return theme.palette.success.main;
  };

  const getConnectionStatusText = () => {
    const { online, apiConnected, websocketConnected } = app.connectionStatus;
    if (!online) return 'Offline';
    if (!apiConnected) return 'API Disconnected';
    if (!websocketConnected) return 'Real-time Disconnected';
    return 'Connected';
  };

  const getNotificationIcon = (type: Notification['type']) => {
    switch (type) {
      case 'success':
        return <CheckCircleIcon />;
      case 'warning':
        return <WarningIcon />;
      case 'error':
        return <ErrorIcon />;
      default:
        return <NotificationsIcon />;
    }
  };

  const sidebarWidth = app.sidebarCollapsed ? DRAWER_WIDTH_COLLAPSED : DRAWER_WIDTH;

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Header */}
      <AppBar
        position="fixed"
        sx={{
          zIndex: theme.zIndex.drawer + 1,
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
          ...(app.sidebarOpen && !isMobile && {
            marginLeft: sidebarWidth,
            width: `calc(100% - ${sidebarWidth}px)`,
            transition: theme.transitions.create(['width', 'margin'], {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.enteringScreen,
            }),
          }),
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="toggle sidebar"
            onClick={app.toggleSidebar}
            edge="start"
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>

          <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1 }}>
            <ShieldIcon sx={{ mr: 1 }} />
            <Typography variant="h6" noWrap component="div">
              iSECTECH Protect
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} alignItems="center">
            {/* Connection Status */}
            <Tooltip title={getConnectionStatusText()}>
              <IconButton size="small">
                {app.connectionStatus.online ? (
                  <OnlineIcon sx={{ color: getConnectionStatusColor() }} />
                ) : (
                  <OfflineIcon sx={{ color: getConnectionStatusColor() }} />
                )}
              </IconButton>
            </Tooltip>

            {/* Security Clearance Badge */}
            {auth.user && (
              <Chip
                icon={<SecurityIcon />}
                label={formatClearanceLevel(auth.securityClearance)}
                size="small"
                color={
                  auth.securityClearance === 'TOP_SECRET' ? 'error' :
                  auth.securityClearance === 'SECRET' ? 'warning' :
                  auth.securityClearance === 'CONFIDENTIAL' ? 'info' : 'success'
                }
                variant="outlined"
              />
            )}

            {/* Theme Toggle */}
            <Tooltip title="Toggle theme">
              <IconButton onClick={handleThemeToggle} color="inherit">
                {app.theme === 'dark' ? <LightModeIcon /> : <DarkModeIcon />}
              </IconButton>
            </Tooltip>

            {/* Notifications */}
            <Tooltip title="Notifications">
              <IconButton onClick={handleNotificationOpen} color="inherit">
                <Badge badgeContent={app.unreadCount} color="error">
                  <NotificationsIcon />
                </Badge>
              </IconButton>
            </Tooltip>

            {/* User Menu */}
            <Tooltip title="User menu">
              <IconButton onClick={handleUserMenuOpen} color="inherit">
                {auth.user?.avatar ? (
                  <Avatar
                    src={auth.user.avatar}
                    sx={{ width: 32, height: 32 }}
                    alt={`${auth.user.firstName} ${auth.user.lastName}`}
                  />
                ) : (
                  <AccountIcon />
                )}
              </IconButton>
            </Tooltip>
          </Stack>
        </Toolbar>
      </AppBar>

      {/* Sidebar */}
      <Drawer
        variant={isMobile ? 'temporary' : 'persistent'}
        open={app.sidebarOpen}
        onClose={() => app.setSidebarOpen(false)}
        sx={{
          width: sidebarWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: sidebarWidth,
            boxSizing: 'border-box',
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.enteringScreen,
            }),
            overflowX: 'hidden',
          },
        }}
      >
        <Toolbar />
        <Sidebar />
      </Drawer>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          overflow: 'auto',
          transition: theme.transitions.create('margin', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
          marginLeft: isMobile ? 0 : app.sidebarOpen ? 0 : `-${sidebarWidth}px`,
        }}
      >
        <Toolbar />
        <Box sx={{ p: 3, height: 'calc(100vh - 64px)', overflow: 'auto' }}>
          {children}
        </Box>
      </Box>

      {/* User Menu */}
      <Menu
        anchorEl={userMenuAnchor}
        open={Boolean(userMenuAnchor)}
        onClose={handleUserMenuClose}
        PaperProps={{
          sx: { mt: 1, minWidth: 250 },
        }}
      >
        {auth.user && (
          <>
            <Box sx={{ px: 2, py: 1 }}>
              <Typography variant="subtitle1" noWrap>
                {auth.user.firstName} {auth.user.lastName}
              </Typography>
              <Typography variant="body2" color="text.secondary" noWrap>
                {auth.user.email}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {formatUserRole(auth.user.role)}
              </Typography>
            </Box>
            <Divider />
          </>
        )}
        
        <MenuItem onClick={handleUserMenuClose}>
          <SettingsIcon sx={{ mr: 1 }} />
          Settings
        </MenuItem>
        
        <MenuItem onClick={handleUserMenuClose}>
          <SecurityIcon sx={{ mr: 1 }} />
          Security
        </MenuItem>
        
        <Divider />
        
        <MenuItem onClick={handleLogout}>
          <LogoutIcon sx={{ mr: 1 }} />
          Logout
        </MenuItem>
      </Menu>

      {/* Notification Center */}
      <NotificationCenter
        anchorEl={notificationAnchor}
        open={Boolean(notificationAnchor)}
        onClose={handleNotificationClose}
      />

      {/* Toast Notifications */}
      {currentNotification && (
        <Snackbar
          open={Boolean(currentNotification)}
          autoHideDuration={currentNotification.duration || 6000}
          onClose={handleNotificationDismiss}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        >
          <Alert
            onClose={handleNotificationDismiss}
            severity={currentNotification.type}
            variant="filled"
            icon={getNotificationIcon(currentNotification.type)}
            sx={{ width: '100%' }}
          >
            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
              {currentNotification.title}
            </Typography>
            {currentNotification.message && (
              <Typography variant="body2">
                {currentNotification.message}
              </Typography>
            )}
          </Alert>
        </Snackbar>
      )}

      {/* Global Loading Overlay */}
      {app.globalLoading && (
        <Box
          sx={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            zIndex: theme.zIndex.modal + 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Box
            sx={{
              width: 40,
              height: 40,
              border: `3px solid ${theme.palette.primary.main}`,
              borderTop: `3px solid transparent`,
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
              '@keyframes spin': {
                '0%': { transform: 'rotate(0deg)' },
                '100%': { transform: 'rotate(360deg)' },
              },
            }}
          />
        </Box>
      )}
    </Box>
  );
}

export default AppLayout;