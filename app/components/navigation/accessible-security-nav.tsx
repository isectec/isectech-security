/**
 * Accessible Security Navigation for iSECTECH Protect
 * WCAG 2.1 AA compliant navigation with keyboard shortcuts and screen reader support
 */

'use client';

import { useAuthStore } from '@/lib/store';
import {
  SECURITY_SHORTCUTS,
  useFocusManagement,
  useScreenReader,
  useSecurityKeyboard,
} from '@/lib/utils/accessibility';
import {
  Warning as AlertIcon,
  Assessment as AssessmentIcon,
  Close as CloseIcon,
  Policy as ComplianceIcon,
  Dashboard as DashboardIcon,
  ExpandLess,
  ExpandMore,
  BugReport as IncidentIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Business as TenantIcon,
} from '@mui/icons-material';
import {
  Badge,
  Box,
  Collapse,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import { usePathname, useRouter } from 'next/navigation';
import React, { useCallback, useEffect, useRef, useState } from 'react';

interface NavigationItem {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType;
  shortcut?: string;
  badge?: number;
  description?: string;
  children?: NavigationItem[];
  requiredPermissions?: string[];
  securityClearance?: string[];
}

interface AccessibleSecurityNavProps {
  open: boolean;
  onClose: () => void;
  onOpen: () => void;
  variant?: 'permanent' | 'persistent' | 'temporary';
  compact?: boolean;
}

// Navigation structure with security-specific items
const NAVIGATION_ITEMS: NavigationItem[] = [
  {
    id: 'dashboard',
    label: 'Security Dashboard',
    path: '/dashboard',
    icon: DashboardIcon,
    shortcut: '1',
    description: 'Main security overview and real-time threat monitoring',
  },
  {
    id: 'alerts',
    label: 'Security Alerts',
    path: '/alerts',
    icon: AlertIcon,
    shortcut: '2',
    description: 'Active security alerts and threat notifications',
    requiredPermissions: ['alerts:view'],
  },
  {
    id: 'incidents',
    label: 'Incident Response',
    path: '/incidents',
    icon: IncidentIcon,
    shortcut: '3',
    description: 'Security incidents and response workflows',
    requiredPermissions: ['incidents:view'],
  },
  {
    id: 'threats',
    label: 'Threat Intelligence',
    path: '/threats',
    icon: SecurityIcon,
    shortcut: '4',
    description: 'Threat analysis and intelligence feeds',
    requiredPermissions: ['threats:view'],
  },
  {
    id: 'compliance',
    label: 'Compliance',
    path: '/compliance',
    icon: ComplianceIcon,
    shortcut: '5',
    description: 'Compliance monitoring and reporting',
    requiredPermissions: ['compliance:view'],
  },
  {
    id: 'tenants',
    label: 'Multi-Tenant Management',
    path: '/tenants',
    icon: TenantIcon,
    description: 'MSSP tenant management and administration',
    requiredPermissions: ['tenant:manage', 'tenant:access'],
    securityClearance: ['SECRET', 'TOP_SECRET'],
    children: [
      {
        id: 'tenant-overview',
        label: 'Tenant Overview',
        path: '/tenants/overview',
        icon: AssessmentIcon,
        description: 'Tenant status and metrics overview',
      },
      {
        id: 'tenant-operations',
        label: 'Bulk Operations',
        path: '/tenants/operations',
        icon: SecurityIcon,
        description: 'Cross-tenant security operations',
      },
      {
        id: 'tenant-branding',
        label: 'White Label',
        path: '/tenants/branding',
        icon: SettingsIcon,
        description: 'Tenant branding and customization',
      },
    ],
  },
  {
    id: 'settings',
    label: 'Security Settings',
    path: '/settings',
    icon: SettingsIcon,
    description: 'System configuration and security policies',
    requiredPermissions: ['system:configure'],
  },
];

export function AccessibleSecurityNav({
  open,
  onClose,
  onOpen,
  variant = 'persistent',
  compact = false,
}: AccessibleSecurityNavProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const router = useRouter();
  const pathname = usePathname();

  const { user } = useAuthStore();
  const { announce } = useScreenReader();
  const { trapFocus, saveFocus, restoreFocus } = useFocusManagement();

  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
  const [focusedItemIndex, setFocusedItemIndex] = useState(-1);
  const navRef = useRef<HTMLElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);

  // Filter navigation items based on user permissions
  const filteredNavItems = NAVIGATION_ITEMS.filter((item) => {
    if (!user) return false;

    // Super admin can access everything
    if (user.role === 'SUPER_ADMIN') return true;

    // Check security clearance
    if (item.securityClearance && !item.securityClearance.includes(user.securityClearance)) {
      return false;
    }

    // Check permissions
    if (item.requiredPermissions) {
      return item.requiredPermissions.some((permission) => user.permissions.includes(permission));
    }

    return true;
  });

  // Navigation shortcuts
  const navigationShortcuts = {
    [SECURITY_SHORTCUTS.dashboard]: () => navigateToPath('/dashboard'),
    [SECURITY_SHORTCUTS.alerts]: () => navigateToPath('/alerts'),
    [SECURITY_SHORTCUTS.incidents]: () => navigateToPath('/incidents'),
    [SECURITY_SHORTCUTS.threats]: () => navigateToPath('/threats'),
    [SECURITY_SHORTCUTS.compliance]: () => navigateToPath('/compliance'),
    [SECURITY_SHORTCUTS.toggleSidebar]: () => {
      if (open) {
        onClose();
        announce('Navigation menu closed', 'polite');
      } else {
        onOpen();
        announce('Navigation menu opened', 'polite');
      }
    },
  };

  useSecurityKeyboard(navigationShortcuts);

  // Navigation helper
  const navigateToPath = useCallback(
    (path: string) => {
      router.push(path);
      if (isMobile) {
        onClose();
      }
      announce(`Navigated to ${path}`, 'polite');
    },
    [router, isMobile, onClose, announce]
  );

  // Handle item expansion
  const toggleExpanded = useCallback(
    (itemId: string) => {
      setExpandedItems((prev) => {
        const newSet = new Set(prev);
        if (newSet.has(itemId)) {
          newSet.delete(itemId);
          announce(`Collapsed ${itemId} menu`, 'polite');
        } else {
          newSet.add(itemId);
          announce(`Expanded ${itemId} menu`, 'polite');
        }
        return newSet;
      });
    },
    [announce]
  );

  // Keyboard navigation within menu
  const handleNavKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      const flatItems = filteredNavItems.flatMap((item) => [
        item,
        ...(item.children?.filter(
          (child) =>
            expandedItems.has(item.id) &&
            (!child.requiredPermissions || child.requiredPermissions.some((perm) => user?.permissions.includes(perm)))
        ) || []),
      ]);

      switch (event.key) {
        case 'ArrowDown':
          event.preventDefault();
          setFocusedItemIndex((prev) => (prev < flatItems.length - 1 ? prev + 1 : 0));
          break;
        case 'ArrowUp':
          event.preventDefault();
          setFocusedItemIndex((prev) => (prev > 0 ? prev - 1 : flatItems.length - 1));
          break;
        case 'Enter':
        case ' ':
          event.preventDefault();
          if (focusedItemIndex >= 0 && flatItems[focusedItemIndex]) {
            const item = flatItems[focusedItemIndex];
            if (item.children) {
              toggleExpanded(item.id);
            } else {
              navigateToPath(item.path);
            }
          }
          break;
        case 'ArrowRight':
          if (focusedItemIndex >= 0) {
            const item = flatItems[focusedItemIndex];
            if (item.children && !expandedItems.has(item.id)) {
              event.preventDefault();
              toggleExpanded(item.id);
            }
          }
          break;
        case 'ArrowLeft':
          if (focusedItemIndex >= 0) {
            const item = flatItems[focusedItemIndex];
            if (item.children && expandedItems.has(item.id)) {
              event.preventDefault();
              toggleExpanded(item.id);
            }
          }
          break;
        case 'Escape':
          event.preventDefault();
          onClose();
          break;
      }
    },
    [filteredNavItems, expandedItems, focusedItemIndex, user, toggleExpanded, navigateToPath, onClose]
  );

  // Focus management for drawer
  useEffect(() => {
    if (open && drawerRef.current) {
      saveFocus();
      const cleanup = trapFocus(drawerRef.current);
      return () => {
        cleanup();
        restoreFocus();
      };
    }
  }, [open, saveFocus, trapFocus, restoreFocus]);

  // Render navigation item
  const renderNavItem = (item: NavigationItem, level: number = 0) => {
    const isActive = pathname === item.path || pathname.startsWith(item.path + '/');
    const isExpanded = expandedItems.has(item.id);
    const hasChildren = item.children && item.children.length > 0;
    const IconComponent = item.icon;

    return (
      <React.Fragment key={item.id}>
        <ListItem
          disablePadding
          sx={{
            pl: level * 2,
            borderLeft: level > 0 ? `2px solid ${theme.palette.divider}` : 'none',
          }}
        >
          <Tooltip
            title={compact ? `${item.label}${item.shortcut ? ` (${item.shortcut})` : ''}` : ''}
            placement="right"
            arrow
          >
            <ListItemButton
              selected={isActive}
              onClick={() => {
                if (hasChildren) {
                  toggleExpanded(item.id);
                } else {
                  navigateToPath(item.path);
                }
              }}
              onKeyDown={handleNavKeyDown}
              role="menuitem"
              aria-label={`${item.label}${item.shortcut ? `, shortcut ${item.shortcut}` : ''}${
                item.description ? `, ${item.description}` : ''
              }`}
              aria-current={isActive ? 'page' : undefined}
              aria-expanded={hasChildren ? isExpanded : undefined}
              aria-describedby={item.description ? `${item.id}-description` : undefined}
              sx={{
                minHeight: 48,
                px: 2,
                borderRadius: 1,
                mx: 1,
                mb: 0.5,
                '&.Mui-selected': {
                  backgroundColor: theme.palette.primary.main,
                  color: theme.palette.primary.contrastText,
                  '&:hover': {
                    backgroundColor: theme.palette.primary.dark,
                  },
                },
                '&:focus': {
                  outline: `2px solid ${theme.palette.primary.main}`,
                  outlineOffset: '2px',
                },
                // High contrast mode
                '@media (prefers-contrast: high)': {
                  border: isActive
                    ? `2px solid ${theme.palette.primary.contrastText}`
                    : `1px solid ${theme.palette.divider}`,
                },
              }}
            >
              <ListItemIcon
                sx={{
                  minWidth: compact ? 'auto' : 40,
                  color: isActive ? 'inherit' : theme.palette.text.secondary,
                }}
              >
                <Badge badgeContent={item.badge} color="error" variant="dot">
                  <IconComponent />
                </Badge>
              </ListItemIcon>

              {!compact && (
                <>
                  <ListItemText
                    primary={item.label}
                    secondary={level === 0 ? item.description : undefined}
                    primaryTypographyProps={{
                      variant: level === 0 ? 'body2' : 'caption',
                      fontWeight: isActive ? 'bold' : 'normal',
                    }}
                    secondaryTypographyProps={{
                      variant: 'caption',
                      sx: { display: { xs: 'none', md: 'block' } },
                    }}
                  />

                  {item.shortcut && (
                    <Box
                      component="kbd"
                      sx={{
                        fontSize: '0.75rem',
                        fontFamily: 'monospace',
                        backgroundColor: theme.palette.action.hover,
                        color: theme.palette.text.secondary,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        border: `1px solid ${theme.palette.divider}`,
                        marginLeft: 1,
                      }}
                      aria-label={`Keyboard shortcut: ${item.shortcut}`}
                    >
                      {item.shortcut}
                    </Box>
                  )}

                  {hasChildren && (
                    <IconButton
                      size="small"
                      aria-label={`${isExpanded ? 'Collapse' : 'Expand'} ${item.label} submenu`}
                      sx={{ color: 'inherit' }}
                    >
                      {isExpanded ? <ExpandLess /> : <ExpandMore />}
                    </IconButton>
                  )}
                </>
              )}
            </ListItemButton>
          </Tooltip>
        </ListItem>

        {/* Hidden description for screen readers */}
        {item.description && (
          <Box id={`${item.id}-description`} sx={{ display: 'none' }} aria-hidden="true">
            {item.description}
          </Box>
        )}

        {/* Submenu */}
        {hasChildren && (
          <Collapse in={isExpanded} timeout="auto" unmountOnExit>
            <List component="div" disablePadding>
              {item
                .children!.filter(
                  (child) =>
                    !child.requiredPermissions ||
                    child.requiredPermissions.some((perm) => user?.permissions.includes(perm))
                )
                .map((child) => renderNavItem(child, level + 1))}
            </List>
          </Collapse>
        )}
      </React.Fragment>
    );
  };

  const drawerContent = (
    <Box
      ref={drawerRef}
      role="navigation"
      aria-label="Security Navigation Menu"
      onKeyDown={handleNavKeyDown}
      sx={{
        width: compact ? 72 : 280,
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Header */}
      <Box
        sx={{
          p: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: `1px solid ${theme.palette.divider}`,
        }}
      >
        {!compact && (
          <Typography variant="h6" component="h1" sx={{ fontWeight: 'bold' }} id="nav-title">
            iSECTECH Protect
          </Typography>
        )}

        <IconButton onClick={onClose} aria-label="Close navigation menu (S)" size="small" title="Close Menu (S)">
          <CloseIcon />
        </IconButton>
      </Box>

      {/* Navigation List */}
      <Box sx={{ flex: 1, overflow: 'auto' }}>
        <List component="nav" aria-labelledby="nav-title" role="menu" sx={{ py: 1 }}>
          {filteredNavItems.map((item) => renderNavItem(item))}
        </List>
      </Box>

      {/* Footer with keyboard shortcuts help */}
      {!compact && (
        <Box
          sx={{
            p: 2,
            borderTop: `1px solid ${theme.palette.divider}`,
            backgroundColor: theme.palette.background.default,
          }}
        >
          <Typography variant="caption" color="text.secondary" component="div">
            Press <kbd>?</kbd> for keyboard shortcuts
          </Typography>
          <Typography variant="caption" color="text.secondary" component="div">
            Press <kbd>S</kbd> to toggle menu
          </Typography>
        </Box>
      )}
    </Box>
  );

  return (
    <Drawer
      variant={variant}
      open={open}
      onClose={onClose}
      ModalProps={{
        keepMounted: true, // Better performance on mobile
      }}
      sx={{
        '& .MuiDrawer-paper': {
          boxSizing: 'border-box',
          width: compact ? 72 : 280,
          borderRight: `1px solid ${theme.palette.divider}`,
        },
      }}
    >
      {drawerContent}
    </Drawer>
  );
}

export default AccessibleSecurityNav;
