/**
 * Sidebar Navigation for iSECTECH Protect
 * Security-focused navigation with role-based access control
 */

'use client';

import React, { useState } from 'react';
import {
  Box,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Collapse,
  Badge,
  Tooltip,
  IconButton,
  Divider,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Warning as AlertIcon,
  Assessment as ThreatIcon,
  Gavel as ComplianceIcon,
  People as UsersIcon,
  Business as TenantsIcon,
  Settings as SettingsIcon,
  Assessment as ReportsIcon,
  Integration as IntegrationsIcon,
  ExpandLess,
  ExpandMore,
  ChevronLeft as CollapseIcon,
  ChevronRight as ExpandIcon,
  Shield as AssetIcon,
  Timeline as AnalyticsIcon,
  BugReport as VulnIcon,
  NetworkCheck as NetworkIcon,
  CloudQueue as CloudIcon,
  MobileFriendly as MobileIcon,
  Email as EmailIcon,
  DataUsage as DataIcon,
  Psychology as IntelIcon,
  AutoFixHigh as SoarIcon,
  Support as SupportIcon,
  School as TrainingIcon,
  MenuBook as KnowledgeIcon,
  EmojiObjects as SuccessIcon,
} from '@mui/icons-material';
import { usePathname, useRouter } from 'next/navigation';
import { useAuthStore, useAppStore } from '@/lib/store';
import type { MenuItem as MenuItemType } from '@/types';

// Navigation menu structure with security permissions
const navigationItems: MenuItemType[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: 'DashboardIcon',
    url: '/dashboard',
    permissions: ['dashboard:read'],
  },
  {
    id: 'security',
    label: 'Security Center',
    icon: 'SecurityIcon',
    permissions: ['security:read'],
    children: [
      {
        id: 'alerts',
        label: 'Alerts',
        icon: 'AlertIcon',
        url: '/security/alerts',
        permissions: ['alerts:read'],
        badge: { text: '24', color: 'error' },
      },
      {
        id: 'threats',
        label: 'Threat Intelligence',
        icon: 'IntelIcon',
        url: '/security/threats',
        permissions: ['threats:read'],
      },
      {
        id: 'incidents',
        label: 'Incidents',
        icon: 'ThreatIcon',
        url: '/security/incidents',
        permissions: ['incidents:read'],
      },
      {
        id: 'vulnerabilities',
        label: 'Vulnerabilities',
        icon: 'VulnIcon',
        url: '/security/vulnerabilities',
        permissions: ['vulnerabilities:read'],
        badge: { text: '12', color: 'warning' },
      },
    ],
  },
  {
    id: 'assets',
    label: 'Asset Management',
    icon: 'AssetIcon',
    permissions: ['assets:read'],
    children: [
      {
        id: 'asset-inventory',
        label: 'Asset Inventory',
        icon: 'AssetIcon',
        url: '/assets/inventory',
        permissions: ['assets:read'],
      },
      {
        id: 'network-discovery',
        label: 'Network Discovery',
        icon: 'NetworkIcon',
        url: '/assets/network',
        permissions: ['assets:discovery'],
      },
      {
        id: 'cloud-assets',
        label: 'Cloud Assets',
        icon: 'CloudIcon',
        url: '/assets/cloud',
        permissions: ['assets:cloud'],
      },
      {
        id: 'mobile-devices',
        label: 'Mobile Devices',
        icon: 'MobileIcon',
        url: '/assets/mobile',
        permissions: ['assets:mobile'],
      },
    ],
  },
  {
    id: 'compliance',
    label: 'Compliance',
    icon: 'ComplianceIcon',
    permissions: ['compliance:read'],
    children: [
      {
        id: 'frameworks',
        label: 'Frameworks',
        icon: 'ComplianceIcon',
        url: '/compliance/frameworks',
        permissions: ['compliance:frameworks'],
      },
      {
        id: 'assessments',
        label: 'Assessments',
        icon: 'ReportsIcon',
        url: '/compliance/assessments',
        permissions: ['compliance:assessments'],
      },
      {
        id: 'controls',
        label: 'Controls',
        icon: 'SettingsIcon',
        url: '/compliance/controls',
        permissions: ['compliance:controls'],
      },
    ],
  },
  {
    id: 'analytics',
    label: 'Analytics & Reports',
    icon: 'AnalyticsIcon',
    permissions: ['analytics:read'],
    children: [
      {
        id: 'security-analytics',
        label: 'Security Analytics',
        icon: 'AnalyticsIcon',
        url: '/analytics/security',
        permissions: ['analytics:security'],
      },
      {
        id: 'risk-reports',
        label: 'Risk Reports',
        icon: 'ReportsIcon',
        url: '/analytics/risk',
        permissions: ['analytics:risk'],
      },
      {
        id: 'compliance-reports',
        label: 'Compliance Reports',
        icon: 'ComplianceIcon',
        url: '/analytics/compliance',
        permissions: ['analytics:compliance'],
      },
      {
        id: 'custom-reports',
        label: 'Custom Reports',
        icon: 'ReportsIcon',
        url: '/analytics/custom',
        permissions: ['analytics:custom'],
      },
    ],
  },
  {
    id: 'automation',
    label: 'Automation & SOAR',
    icon: 'SoarIcon',
    permissions: ['soar:read'],
    children: [
      {
        id: 'playbooks',
        label: 'Playbooks',
        icon: 'SoarIcon',
        url: '/soar/playbooks',
        permissions: ['soar:playbooks'],
      },
      {
        id: 'workflows',
        label: 'Workflows',
        icon: 'SettingsIcon',
        url: '/soar/workflows',
        permissions: ['soar:workflows'],
      },
      {
        id: 'automation-rules',
        label: 'Automation Rules',
        icon: 'SettingsIcon',
        url: '/soar/rules',
        permissions: ['soar:rules'],
      },
    ],
  },
  {
    id: 'integrations',
    label: 'Integrations',
    icon: 'IntegrationsIcon',
    permissions: ['integrations:read'],
    children: [
      {
        id: 'security-tools',
        label: 'Security Tools',
        icon: 'SecurityIcon',
        url: '/integrations/security',
        permissions: ['integrations:security'],
      },
      {
        id: 'data-sources',
        label: 'Data Sources',
        icon: 'DataIcon',
        url: '/integrations/data',
        permissions: ['integrations:data'],
      },
      {
        id: 'email-security',
        label: 'Email Security',
        icon: 'EmailIcon',
        url: '/integrations/email',
        permissions: ['integrations:email'],
      },
    ],
  },
  {
    id: 'customer-success',
    label: 'Customer Success',
    icon: 'SuccessIcon',
    permissions: ['customer-success:read'],
    children: [
      {
        id: 'knowledge-base',
        label: 'Knowledge Base',
        icon: 'KnowledgeIcon',
        url: '/customer-success/knowledge-base',
        permissions: ['customer-success:knowledge'],
      },
      {
        id: 'training',
        label: 'Training & Certification',
        icon: 'TrainingIcon',
        url: '/customer-success/training',
        permissions: ['customer-success:training'],
      },
      {
        id: 'support',
        label: 'Support Portal',
        icon: 'SupportIcon',
        url: '/customer-success/support',
        permissions: ['customer-success:support'],
      },
    ],
  },
  {
    id: 'admin',
    label: 'Administration',
    icon: 'SettingsIcon',
    permissions: ['admin:read'],
    children: [
      {
        id: 'users',
        label: 'Users & Roles',
        icon: 'UsersIcon',
        url: '/admin/users',
        permissions: ['admin:users'],
      },
      {
        id: 'tenants',
        label: 'Tenants',
        icon: 'TenantsIcon',
        url: '/admin/tenants',
        permissions: ['admin:tenants'],
      },
      {
        id: 'system-settings',
        label: 'System Settings',
        icon: 'SettingsIcon',
        url: '/admin/settings',
        permissions: ['admin:settings'],
      },
      {
        id: 'audit-logs',
        label: 'Audit Logs',
        icon: 'ReportsIcon',
        url: '/admin/audit',
        permissions: ['admin:audit'],
      },
    ],
  },
];

// Icon mapping
const iconMap: Record<string, React.ElementType> = {
  DashboardIcon,
  SecurityIcon,
  AlertIcon,
  ThreatIcon,
  ComplianceIcon,
  UsersIcon,
  TenantsIcon,
  SettingsIcon,
  ReportsIcon,
  IntegrationsIcon,
  AssetIcon,
  AnalyticsIcon,
  VulnIcon,
  NetworkIcon,
  CloudIcon,
  MobileIcon,
  EmailIcon,
  DataIcon,
  IntelIcon,
  SoarIcon,
  SupportIcon,
  TrainingIcon,
  KnowledgeIcon,
  SuccessIcon,
};

interface SidebarProps {
  className?: string;
}

export function Sidebar({ className }: SidebarProps) {
  const theme = useTheme();
  const router = useRouter();
  const pathname = usePathname();
  const auth = useAuthStore();
  const app = useAppStore();
  
  const [expandedItems, setExpandedItems] = useState<string[]>(['security', 'assets', 'customer-success']);

  const handleItemClick = (item: MenuItemType) => {
    if (item.url) {
      router.push(item.url);
      app.setCurrentPage(item.url);
    } else if (item.children) {
      toggleExpanded(item.id);
    }
  };

  const toggleExpanded = (itemId: string) => {
    setExpandedItems(prev => 
      prev.includes(itemId) 
        ? prev.filter(id => id !== itemId)
        : [...prev, itemId]
    );
  };

  const hasPermission = (permissions?: string[]): boolean => {
    if (!permissions || permissions.length === 0) return true;
    return permissions.some(permission => auth.checkPermission(permission));
  };

  const isActive = (item: MenuItemType): boolean => {
    if (item.url) {
      return pathname === item.url || pathname.startsWith(`${item.url}/`);
    }
    if (item.children) {
      return item.children.some(child => isActive(child));
    }
    return false;
  };

  const renderIcon = (iconName?: string) => {
    if (!iconName) return null;
    const IconComponent = iconMap[iconName];
    return IconComponent ? <IconComponent /> : null;
  };

  const renderMenuItem = (item: MenuItemType, level = 0) => {
    if (!hasPermission(item.permissions)) {
      return null;
    }

    const hasChildren = item.children && item.children.length > 0;
    const isExpanded = expandedItems.includes(item.id);
    const active = isActive(item);

    return (
      <React.Fragment key={item.id}>
        <ListItem disablePadding>
          <ListItemButton
            onClick={() => handleItemClick(item)}
            selected={active}
            sx={{
              pl: 2 + level * 2,
              py: 1,
              borderRadius: 1,
              mx: 1,
              mb: 0.5,
              '&.Mui-selected': {
                backgroundColor: theme.palette.primary.main + '20',
                borderLeft: `3px solid ${theme.palette.primary.main}`,
                '&:hover': {
                  backgroundColor: theme.palette.primary.main + '30',
                },
              },
              '&:hover': {
                backgroundColor: theme.palette.action.hover,
              },
            }}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>
              {app.sidebarCollapsed ? (
                <Tooltip title={item.label} placement="right">
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    {renderIcon(item.icon)}
                  </Box>
                </Tooltip>
              ) : (
                renderIcon(item.icon)
              )}
            </ListItemIcon>
            
            {!app.sidebarCollapsed && (
              <>
                <ListItemText 
                  primary={item.label}
                  primaryTypographyProps={{
                    variant: 'body2',
                    fontWeight: active ? 600 : 400,
                  }}
                />
                
                {item.badge && (
                  <Badge
                    badgeContent={item.badge.text}
                    color={item.badge.color as any}
                    sx={{ mr: hasChildren ? 1 : 0 }}
                  />
                )}
                
                {hasChildren && (
                  isExpanded ? <ExpandLess /> : <ExpandMore />
                )}
              </>
            )}
          </ListItemButton>
        </ListItem>

        {hasChildren && !app.sidebarCollapsed && (
          <Collapse in={isExpanded} timeout="auto" unmountOnExit>
            <List component="div" disablePadding>
              {item.children!.map(child => renderMenuItem(child, level + 1))}
            </List>
          </Collapse>
        )}
      </React.Fragment>
    );
  };

  return (
    <Box className={className}>
      {/* Sidebar Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: app.sidebarCollapsed ? 'center' : 'space-between',
          px: 2,
          py: 1,
          borderBottom: `1px solid ${theme.palette.divider}`,
        }}
      >
        {!app.sidebarCollapsed && (
          <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 600 }}>
            NAVIGATION
          </Typography>
        )}
        
        <Tooltip title={app.sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
          <IconButton
            size="small"
            onClick={app.toggleSidebarCollapse}
            sx={{ ml: app.sidebarCollapsed ? 0 : 'auto' }}
          >
            {app.sidebarCollapsed ? <ExpandIcon /> : <CollapseIcon />}
          </IconButton>
        </Tooltip>
      </Box>

      {/* Navigation Items */}
      <Box sx={{ overflow: 'auto', flexGrow: 1, py: 1 }}>
        <List>
          {navigationItems.map(item => renderMenuItem(item))}
        </List>
      </Box>

      {/* Footer Info */}
      {!app.sidebarCollapsed && (
        <>
          <Divider />
          <Box sx={{ p: 2 }}>
            <Typography variant="caption" color="text.secondary">
              Version 1.0.0
            </Typography>
            <br />
            <Typography variant="caption" color="text.secondary">
              {auth.tenant?.name || 'iSECTECH Protect'}
            </Typography>
          </Box>
        </>
      )}
    </Box>
  );
}

export default Sidebar;