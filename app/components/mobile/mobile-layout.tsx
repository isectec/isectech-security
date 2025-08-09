/**
 * Mobile Layout for iSECTECH Protect PWA
 * Optimized for mobile devices with touch-friendly navigation
 */

'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Badge,
  Fab,
  Chip,
  Avatar,
  useTheme,
  useMediaQuery,
  alpha,
  SwipeableDrawer,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Notifications as NotificationsIcon,
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Person as PersonIcon,
  KeyboardArrowUp as ScrollTopIcon,
  Refresh as RefreshIcon,
  NetworkCheck as NetworkIcon,
  WifiOff as OfflineIcon,
} from '@mui/icons-material';
import { useSwipeable } from 'react-swipeable';
import { useAppStore } from '@/lib/store';
import { formatDistanceToNow } from 'date-fns';

export interface MobileLayoutProps {
  children: React.ReactNode;
  title?: string;
  showRefresh?: boolean;
  onRefresh?: () => void;
}

interface NavigationItem {
  label: string;
  path: string;
  icon: React.ElementType;
  badge?: number;
  color?: string;
}

export function MobileLayout({ 
  children, 
  title = 'iSECTECH Protect',
  showRefresh = false,
  onRefresh 
}: MobileLayoutProps) {
  const theme = useTheme();
  const isSmall = useMediaQuery(theme.breakpoints.down('sm'));
  const app = useAppStore();

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [showScrollTop, setShowScrollTop] = useState(false);
  const [isOnline, setIsOnline] = useState(true);
  const [lastSync, setLastSync] = useState<Date>(new Date());

  // Monitor network status
  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    setIsOnline(navigator.onLine);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Scroll detection for FAB
  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 300);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Swipe gesture handlers
  const swipeHandlers = useSwipeable({
    onSwipedRight: (eventData) => {
      if (eventData.absX > 100 && eventData.absY < 100 && !drawerOpen) {
        setDrawerOpen(true);
      }
    },
    onSwipedLeft: (eventData) => {
      if (eventData.absX > 100 && eventData.absY < 100 && drawerOpen) {
        setDrawerOpen(false);
      }
    },
    trackMouse: false,
    trackTouch: true,
  });

  const unreadNotifications = app.notifications.filter(n => !n.read).length;
  const criticalAlerts = app.notifications.filter(n => n.type === 'error').length;

  const navigationItems: NavigationItem[] = [
    {
      label: 'Dashboard',
      path: '/mobile',
      icon: DashboardIcon,
    },
    {
      label: 'Notifications',
      path: '/mobile/notifications',
      icon: NotificationsIcon,
      badge: unreadNotifications,
      color: theme.palette.primary.main,
    },
    {
      label: 'Security Alerts',
      path: '/mobile/alerts',
      icon: SecurityIcon,
      badge: criticalAlerts,
      color: theme.palette.error.main,
    },
    {
      label: 'Settings',
      path: '/mobile/settings',
      icon: SettingsIcon,
    },
    {
      label: 'Profile',
      path: '/mobile/profile',
      icon: PersonIcon,
    },
  ];

  const handleDrawerToggle = useCallback(() => {
    setDrawerOpen(!drawerOpen);
  }, [drawerOpen]);

  const handleScrollToTop = useCallback(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  const handleRefresh = useCallback(() => {
    if (onRefresh) {
      onRefresh();
      setLastSync(new Date());
    }
  }, [onRefresh]);

  const handleNavigation = useCallback((path: string) => {
    // In a real app, this would use Next.js router
    console.log('Navigate to:', path);
    setDrawerOpen(false);
  }, []);

  const drawerContent = (
    <Box sx={{ width: 280 }} role="presentation">
      {/* Header */}
      <Box
        sx={{
          p: 2,
          background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.primary.dark} 100%)`,
          color: 'white',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <Avatar sx={{ mr: 2, bgcolor: 'white', color: 'primary.main' }}>
            <PersonIcon />
          </Avatar>
          <Box>
            <Typography variant="h6" component="div">
              Security Team
            </Typography>
            <Typography variant="body2" sx={{ opacity: 0.8 }}>
              {app.user?.email || 'admin@isectech.com'}
            </Typography>
          </Box>
        </Box>
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <NetworkIcon sx={{ fontSize: 16 }} />
          <Typography variant="caption">
            {isOnline ? 'Online' : 'Offline'}
          </Typography>
          <Typography variant="caption" sx={{ opacity: 0.7, ml: 'auto' }}>
            {formatDistanceToNow(lastSync, { addSuffix: true })}
          </Typography>
        </Box>
      </Box>

      {/* Navigation */}
      <List>
        {navigationItems.map((item) => {
          const Icon = item.icon;
          return (
            <ListItemButton
              key={item.path}
              onClick={() => handleNavigation(item.path)}
              sx={{
                py: 1.5,
                '&:hover': {
                  backgroundColor: alpha(theme.palette.primary.main, 0.1),
                },
              }}
            >
              <ListItemIcon>
                <Badge
                  badgeContent={item.badge}
                  color={item.color === theme.palette.error.main ? 'error' : 'primary'}
                  invisible={!item.badge}
                >
                  <Icon sx={{ color: item.color || 'text.primary' }} />
                </Badge>
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  fontWeight: item.badge ? 600 : 400,
                }}
              />
            </ListItemButton>
          );
        })}
      </List>

      {/* Status Indicators */}
      <Box sx={{ p: 2, mt: 'auto' }}>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Chip
            size="small"
            icon={isOnline ? <NetworkIcon /> : <OfflineIcon />}
            label={isOnline ? 'Online' : 'Offline'}
            color={isOnline ? 'success' : 'error'}
            variant="outlined"
          />
          {!isOnline && (
            <Chip
              size="small"
              label="Data may be outdated"
              color="warning"
              variant="outlined"
            />
          )}
        </Box>
      </Box>
    </Box>
  );

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        bgcolor: 'background.default',
      }}
      {...swipeHandlers}
    >
      {/* App Bar */}
      <AppBar
        position="sticky"
        elevation={0}
        sx={{
          bgcolor: 'background.paper',
          borderBottom: `1px solid ${theme.palette.divider}`,
        }}
      >
        <Toolbar sx={{ px: { xs: 1, sm: 2 } }}>
          <IconButton
            edge="start"
            color="inherit"
            aria-label="menu"
            onClick={handleDrawerToggle}
            sx={{ mr: 1 }}
          >
            <MenuIcon />
          </IconButton>

          <Typography
            variant="h6"
            component="h1"
            sx={{
              flexGrow: 1,
              color: 'text.primary',
              fontWeight: 600,
              fontSize: { xs: '1rem', sm: '1.25rem' },
            }}
          >
            {title}
          </Typography>

          {showRefresh && (
            <IconButton
              color="inherit"
              onClick={handleRefresh}
              disabled={!isOnline}
            >
              <RefreshIcon />
            </IconButton>
          )}

          <IconButton
            color="inherit"
            onClick={() => handleNavigation('/mobile/notifications')}
          >
            <Badge badgeContent={unreadNotifications} color="error">
              <NotificationsIcon />
            </Badge>
          </IconButton>
        </Toolbar>
      </AppBar>

      {/* Navigation Drawer */}
      <SwipeableDrawer
        anchor="left"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onOpen={() => setDrawerOpen(true)}
        disableBackdropTransition
        disableDiscovery
        swipeAreaWidth={20}
        ModalProps={{
          keepMounted: true, // Better mobile performance
        }}
      >
        {drawerContent}
      </SwipeableDrawer>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {children}
      </Box>

      {/* Floating Action Button */}
      {showScrollTop && (
        <Fab
          size="medium"
          color="primary"
          aria-label="scroll to top"
          onClick={handleScrollToTop}
          sx={{
            position: 'fixed',
            bottom: 16,
            right: 16,
            zIndex: (theme) => theme.zIndex.fab,
            opacity: 0.9,
            '&:hover': {
              opacity: 1,
            },
          }}
        >
          <ScrollTopIcon />
        </Fab>
      )}
    </Box>
  );
}

export default MobileLayout;