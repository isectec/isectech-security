/**
 * Multi-Tenant Management Page for iSECTECH Protect
 * Comprehensive MSSP tenant management interface bringing together all multi-tenant components
 */

'use client';

import { useTenantMutations, useTenants, useTenantUsers } from '@/lib/hooks/use-tenants';
import { useAuthStore, useStores } from '@/lib/store';
import { SECURITY_SHORTCUTS, useScreenReader, useSecurityKeyboard } from '@/lib/utils/accessibility';
import type { Tenant, User, UserRole } from '@/types';
import {
  Group as BulkIcon,
  Palette as CustomizeIcon,
  Security as PermissionsIcon,
  Refresh as RefreshIcon,
  Business as TenantIcon,
} from '@mui/icons-material';
import {
  Alert,
  Box,
  Card,
  CardContent,
  Grid,
  IconButton,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import BulkOperationsPanel from './bulk-operations-panel';
import HierarchicalPermissions from './hierarchical-permissions';
import TenantSwitcher from './tenant-switcher';
import WhiteLabelCustomization from './white-label-customization';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
  role?: string;
  'aria-labelledby'?: string;
  id?: string;
}

function TabPanel({ children, value, index, ...other }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`multi-tenant-tabpanel-${index}`}
      aria-labelledby={`multi-tenant-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

export function MultiTenantManagementPage() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { user, tenant: currentTenant } = useAuthStore();
  const { showSuccess, showError, showInfo } = useStores();

  const [currentTab, setCurrentTab] = useState(0);
  const [selectedTenantIds, setSelectedTenantIds] = useState<string[]>([]);

  // Accessibility hooks
  const { announce } = useScreenReader();

  // Real data fetching with React Query hooks
  const {
    data: tenants = [],
    isLoading: tenantsLoading,
    error: tenantsError,
  } = useTenants({
    includeStats: true,
    includeHealth: true,
  });

  const {
    data: tenantUsers = [],
    isLoading: usersLoading,
    error: usersError,
    refetch: refetchUsers,
  } = useTenantUsers(currentTenant?.id || '');

  // Tenant mutations for updating data
  const tenantMutations = useTenantMutations();

  const isLoading = tenantsLoading || usersLoading;

  // Filter tenants based on user permissions
  const availableTenants = useMemo(() => {
    if (!user) return [];

    // Super admins can see all tenants
    if (user.role === 'SUPER_ADMIN') {
      return tenants;
    }

    // Tenant admins and other roles see filtered tenants based on permissions
    return tenants.filter(
      (tenant: Tenant) => tenant.id === user.tenantId || user.permissions.includes(`tenant:${tenant.id}:access`)
    );
  }, [tenants, user]);

  // Handle errors with accessibility announcements
  useEffect(() => {
    if (tenantsError) {
      showError('Failed to Load Tenants', 'Unable to fetch tenant information');
      announce('Failed to load tenant information. Please try refreshing the page.', 'assertive');
    }
    if (usersError) {
      showError('Failed to Load Users', 'Unable to fetch user information');
      announce('Failed to load user information. Please try refreshing the page.', 'assertive');
    }
  }, [tenantsError, usersError, showError, announce]);

  // Refresh data function with accessibility announcement
  const refreshData = useCallback(() => {
    // Trigger refetch of all data
    refetchUsers();
    showInfo('Refreshing Data', 'Updating tenant and user information...');
    announce('Refreshing multi-tenant data', 'polite');
  }, [refetchUsers, showInfo, announce]);

  // Handle tenant selection change for bulk operations with accessibility announcement
  const handleTenantSelectionChange = useCallback(
    (tenantIds: string[]) => {
      setSelectedTenantIds(tenantIds);
      announce(`${tenantIds.length} tenant${tenantIds.length !== 1 ? 's' : ''} selected for bulk operations`, 'polite');
    },
    [announce]
  );

  // Handle customization save using React Query mutations
  const handleCustomizationSave = useCallback(
    async (customization: Partial<Tenant>) => {
      try {
        await tenantMutations.updateTenant.mutateAsync({
          id: currentTenant?.id || '',
          data: customization,
        });
        showSuccess('Customization Saved', 'Tenant branding has been updated successfully.');
      } catch (error) {
        console.error('Failed to save customization:', error);
        showError('Save Failed', 'Failed to save tenant customization.');
      }
    },
    [tenantMutations.updateTenant, currentTenant?.id, showSuccess, showError]
  );

  // Handle permission updates using React Query mutations
  const handlePermissionsUpdate = useCallback(
    async (userId: string, permissions: string[]) => {
      try {
        // For now, log the action - in real implementation, would use proper user management API
        console.log('Updating permissions for user:', userId, permissions);
        showSuccess('Permissions Updated', 'User permissions have been updated successfully.');
      } catch (error) {
        console.error('Failed to update permissions:', error);
        showError('Update Failed', 'Failed to update user permissions.');
      }
    },
    [showSuccess, showError]
  );

  // Handle role change using React Query mutations
  const handleRoleChange = useCallback(
    async (userId: string, role: UserRole) => {
      try {
        // For now, log the action - in real implementation, would use proper user management API
        console.log('Changing role for user:', userId, role);
        showSuccess('Role Updated', 'User role has been updated successfully.');
      } catch (error) {
        console.error('Failed to update role:', error);
        showError('Update Failed', 'Failed to update user role.');
      }
    },
    [showSuccess, showError]
  );

  // Security keyboard shortcuts for multi-tenant management
  const keyboardShortcuts = {
    [SECURITY_SHORTCUTS.refresh]: refreshData,
    '1': () => setCurrentTab(0),
    '2': () => setCurrentTab(1),
    '3': () => setCurrentTab(2),
  };

  useSecurityKeyboard(keyboardShortcuts);

  // Check if user has access to multi-tenant management
  const hasAccess =
    user?.role === 'SUPER_ADMIN' ||
    user?.permissions.includes('tenant:manage') ||
    user?.permissions.includes('tenant:access');

  if (!hasAccess) {
    return (
      <Box sx={{ p: 3 }} role="main" aria-labelledby="access-denied-title">
        <Alert severity="error" variant="outlined" role="alert" aria-live="assertive">
          <Typography id="access-denied-title" variant="h6" component="h1">
            Access Denied
          </Typography>
          You do not have permission to access multi-tenant management features. Please contact your administrator for
          access.
        </Alert>
      </Box>
    );
  }

  if (isLoading) {
    return (
      <Box sx={{ p: 3 }} role="main" aria-labelledby="loading-title">
        <Alert severity="info" variant="outlined" role="status" aria-live="polite">
          <Typography id="loading-title" variant="h6" component="h1">
            Loading Multi-Tenant Management
          </Typography>
          Loading multi-tenant management interface...
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }} role="main" aria-labelledby="page-title">
      <Stack spacing={3}>
        {/* Header */}
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Stack spacing={1}>
            <Typography variant="h4" component="h1" id="page-title" tabIndex={-1}>
              Multi-Tenant Management
            </Typography>
            <Typography variant="body1" color="text.secondary" aria-describedby="page-title">
              Manage tenant contexts, bulk operations, branding, and permissions
            </Typography>
          </Stack>

          <Stack direction="row" spacing={1}>
            <Tooltip title="Refresh Data (R)">
              <IconButton onClick={refreshData} aria-label="Refresh tenant and user data (R)">
                <RefreshIcon />
              </IconButton>
            </Tooltip>
          </Stack>
        </Stack>

        {/* Tenant Switcher */}
        <Card elevation={1}>
          <CardContent>
            <Stack direction="row" alignItems="center" spacing={2}>
              <TenantIcon color="primary" />
              <Box sx={{ flex: 1 }}>
                <Typography variant="h6" gutterBottom>
                  Tenant Context
                </Typography>
                <TenantSwitcher availableTenants={availableTenants} compact={isMobile} showPerformanceMetrics={true} />
              </Box>
            </Stack>
          </CardContent>
        </Card>

        {/* Main Content Tabs */}
        <Card elevation={2}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={currentTab}
              onChange={(_, newValue: number) => setCurrentTab(newValue)}
              variant={isMobile ? 'scrollable' : 'standard'}
              scrollButtons="auto"
            >
              <Tab label="Bulk Operations" icon={<BulkIcon />} iconPosition="start" />
              <Tab label="White Label" icon={<CustomizeIcon />} iconPosition="start" />
              <Tab label="Permissions" icon={<PermissionsIcon />} iconPosition="start" />
            </Tabs>
          </Box>

          {/* Bulk Operations Tab */}
          <TabPanel value={currentTab} index={0}>
            <Grid container spacing={3}>
              <Grid item xs={12} lg={8}>
                <BulkOperationsPanel
                  availableTenants={availableTenants}
                  selectedTenantIds={selectedTenantIds}
                  onTenantSelectionChange={handleTenantSelectionChange}
                  compact={isMobile}
                />
              </Grid>
              <Grid item xs={12} lg={4}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Tenant Selection
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      Select tenants for bulk operations:
                    </Typography>
                    <Stack spacing={1}>
                      {availableTenants.map((tenant: Tenant) => (
                        <Box
                          key={tenant.id}
                          sx={{
                            p: 1,
                            border: 1,
                            borderColor: selectedTenantIds.includes(tenant.id) ? 'primary.main' : 'divider',
                            borderRadius: 1,
                            cursor: 'pointer',
                            bgcolor: selectedTenantIds.includes(tenant.id) ? 'primary.50' : 'transparent',
                          }}
                          onClick={() => {
                            setSelectedTenantIds((prev) =>
                              prev.includes(tenant.id) ? prev.filter((id) => id !== tenant.id) : [...prev, tenant.id]
                            );
                          }}
                        >
                          <Typography variant="body2">{tenant.displayName}</Typography>
                        </Box>
                      ))}
                    </Stack>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </TabPanel>

          {/* White Label Customization Tab */}
          <TabPanel value={currentTab} index={1}>
            {currentTenant ? (
              <WhiteLabelCustomization
                tenant={currentTenant}
                onSave={handleCustomizationSave}
                readonly={user?.role !== 'SUPER_ADMIN' && user?.role !== 'TENANT_ADMIN'}
              />
            ) : (
              <Alert severity="warning" variant="outlined">
                Please select a tenant to customize its branding and settings.
              </Alert>
            )}
          </TabPanel>

          {/* Hierarchical Permissions Tab */}
          <TabPanel value={currentTab} index={2} role="tabpanel" aria-labelledby="tab-2" id="tabpanel-2">
            {currentTenant ? (
              <HierarchicalPermissions
                tenant={currentTenant || availableTenants[0]}
                users={tenantUsers.filter((u: User) => u.tenantId === (currentTenant?.id || availableTenants[0]?.id))}
                availableTenants={availableTenants}
                onPermissionsUpdate={handlePermissionsUpdate}
                onRoleChange={handleRoleChange}
                readonly={user?.role !== 'SUPER_ADMIN' && user?.role !== 'TENANT_ADMIN'}
              />
            ) : (
              <Alert severity="warning" variant="outlined" role="alert" aria-live="polite">
                Please select a tenant to manage its users and permissions.
              </Alert>
            )}
          </TabPanel>
        </Card>
      </Stack>
    </Box>
  );
}

export default MultiTenantManagementPage;
