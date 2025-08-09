/**
 * Tenant Switcher Component for iSECTECH Protect
 * Production-grade MSSP tenant context switching with <500ms performance
 */

'use client';

import { useAuthStore, useStores } from '@/lib/store';
import type { Tenant } from '@/types';
import { Check as CheckIcon, Speed as PerformanceIcon, Business as TenantIcon } from '@mui/icons-material';
import {
  Alert,
  alpha,
  Avatar,
  Badge,
  Box,
  Chip,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { useCallback, useMemo, useState } from 'react';

interface TenantSwitcherProps {
  /**
   * Available tenants for the current user
   * This would typically come from an API call to get user's accessible tenants
   */
  availableTenants?: Tenant[];

  /**
   * Callback when tenant switch is initiated
   */
  onTenantSwitch?: (tenant: Tenant) => void;

  /**
   * Callback when tenant switch is completed
   */
  onSwitchComplete?: (tenant: Tenant, switchTime: number) => void;

  /**
   * Whether to show performance metrics
   */
  showPerformanceMetrics?: boolean;

  /**
   * Compact mode for smaller displays
   */
  compact?: boolean;
}

export function TenantSwitcher({
  availableTenants = [],
  onTenantSwitch,
  onSwitchComplete,
  showPerformanceMetrics = true,
  compact = false,
}: TenantSwitcherProps) {
  const theme = useTheme();
  const { auth, showSuccess, showError, showWarning } = useStores();
  const { user, tenant: currentTenant, switchTenant } = useAuthStore();

  const [isSwitching, setIsSwitching] = useState(false);
  const [lastSwitchTime, setLastSwitchTime] = useState<number | null>(null);
  const [switchError, setSwitchError] = useState<string | null>(null);

  // Performance tracking for <500ms requirement
  const [performanceMetrics, setPerformanceMetrics] = useState({
    averageSwitchTime: 0,
    fastestSwitch: Infinity,
    slowestSwitch: 0,
    totalSwitches: 0,
  });

  // Filter available tenants based on user permissions
  const accessibleTenants = useMemo(() => {
    if (!user) return [];

    // Super admins can access all tenants
    if (user.role === 'SUPER_ADMIN') {
      return availableTenants;
    }

    // Tenant admins can only access their own tenant plus any assigned tenants
    // This would typically be filtered by the API based on user's permissions
    return availableTenants.filter(
      (tenant) => tenant.id === user.tenantId || user.permissions.includes(`tenant:${tenant.id}:access`)
    );
  }, [availableTenants, user]);

  // Handle tenant switching with performance monitoring
  const handleTenantSwitch = useCallback(
    async (tenantId: string) => {
      if (!tenantId || tenantId === currentTenant?.id || isSwitching) {
        return;
      }

      const selectedTenant = accessibleTenants.find((t) => t.id === tenantId);
      if (!selectedTenant) {
        showError('Tenant Not Found', 'The selected tenant is not accessible.');
        return;
      }

      setIsSwitching(true);
      setSwitchError(null);

      // Start performance tracking
      const startTime = performance.now();

      try {
        // Call onTenantSwitch callback before switching
        onTenantSwitch?.(selectedTenant);

        // Perform the actual tenant switch
        const success = await switchTenant(tenantId);

        const endTime = performance.now();
        const switchTime = endTime - startTime;

        if (success) {
          // Update performance metrics
          setLastSwitchTime(switchTime);
          setPerformanceMetrics((prev) => {
            const newTotal = prev.totalSwitches + 1;
            const newAverage = (prev.averageSwitchTime * prev.totalSwitches + switchTime) / newTotal;

            return {
              averageSwitchTime: newAverage,
              fastestSwitch: Math.min(prev.fastestSwitch, switchTime),
              slowestSwitch: Math.max(prev.slowestSwitch, switchTime),
              totalSwitches: newTotal,
            };
          });

          // Check performance requirement
          if (switchTime > 500) {
            showWarning('Slow Tenant Switch', `Switch took ${Math.round(switchTime)}ms (target: <500ms)`);
          } else {
            showSuccess(
              'Tenant Switched',
              `Successfully switched to ${selectedTenant.displayName} (${Math.round(switchTime)}ms)`
            );
          }

          // Call completion callback
          onSwitchComplete?.(selectedTenant, switchTime);
        } else {
          setSwitchError('Failed to switch tenant. Please try again.');
          showError('Switch Failed', 'Unable to switch to the selected tenant.');
        }
      } catch (error) {
        const endTime = performance.now();
        const switchTime = endTime - startTime;

        console.error('Tenant switch error:', error);
        setSwitchError('An error occurred while switching tenants.');
        showError('Switch Error', 'An unexpected error occurred during tenant switch.');
      } finally {
        setIsSwitching(false);
      }
    },
    [
      currentTenant?.id,
      isSwitching,
      accessibleTenants,
      switchTenant,
      onTenantSwitch,
      onSwitchComplete,
      showSuccess,
      showError,
      showWarning,
    ]
  );

  // Get tenant status color
  const getTenantStatusColor = (tenant: Tenant) => {
    switch (tenant.status) {
      case 'ACTIVE':
        return theme.palette.success.main;
      case 'SUSPENDED':
        return theme.palette.warning.main;
      case 'INACTIVE':
        return theme.palette.error.main;
      default:
        return theme.palette.text.secondary;
    }
  };

  // Get tenant plan chip color
  const getTenantPlanColor = (plan: Tenant['plan']) => {
    switch (plan) {
      case 'ENTERPRISE':
        return theme.palette.primary.main;
      case 'PROFESSIONAL':
        return theme.palette.secondary.main;
      case 'STARTER':
        return theme.palette.info.main;
      case 'CUSTOM':
        return theme.palette.warning.main;
      default:
        return theme.palette.text.secondary;
    }
  };

  if (!user || accessibleTenants.length <= 1) {
    return null; // Don't show switcher if user has access to only one tenant
  }

  return (
    <Box sx={{ minWidth: compact ? 200 : 280 }}>
      <FormControl fullWidth size={compact ? 'small' : 'medium'}>
        <InputLabel id="tenant-switcher-label">
          <Stack direction="row" alignItems="center" spacing={1}>
            <TenantIcon fontSize="small" />
            <Typography variant="body2">Current Tenant</Typography>
          </Stack>
        </InputLabel>

        <Select
          labelId="tenant-switcher-label"
          value={currentTenant?.id || ''}
          onChange={(e) => handleTenantSwitch(e.target.value)}
          disabled={isSwitching}
          sx={{
            '& .MuiSelect-select': {
              display: 'flex',
              alignItems: 'center',
              gap: 1,
            },
          }}
          renderValue={(value) => {
            const tenant = accessibleTenants.find((t) => t.id === value);
            if (!tenant) return 'Select Tenant';

            return (
              <Stack direction="row" alignItems="center" spacing={1} sx={{ width: '100%' }}>
                {tenant.logo ? (
                  <Avatar
                    src={tenant.logo}
                    sx={{
                      width: 24,
                      height: 24,
                      bgcolor: tenant.primaryColor || theme.palette.primary.main,
                    }}
                  >
                    {tenant.displayName.charAt(0)}
                  </Avatar>
                ) : (
                  <Avatar
                    sx={{
                      width: 24,
                      height: 24,
                      bgcolor: tenant.primaryColor || theme.palette.primary.main,
                      fontSize: '0.75rem',
                    }}
                  >
                    {tenant.displayName.charAt(0)}
                  </Avatar>
                )}

                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography variant="body2" noWrap sx={{ fontWeight: 'medium' }}>
                    {tenant.displayName}
                  </Typography>
                  {!compact && (
                    <Typography variant="caption" color="text.secondary" noWrap>
                      {tenant.plan} Plan
                    </Typography>
                  )}
                </Box>

                {isSwitching && <CircularProgress size={16} thickness={4} />}
              </Stack>
            );
          }}
        >
          {accessibleTenants.map((tenant) => (
            <MenuItem key={tenant.id} value={tenant.id} disabled={tenant.status !== 'ACTIVE'}>
              <Stack direction="row" alignItems="center" spacing={2} sx={{ width: '100%' }}>
                <Badge
                  color={tenant.id === currentTenant?.id ? 'primary' : 'default'}
                  variant="dot"
                  invisible={tenant.id !== currentTenant?.id}
                >
                  {tenant.logo ? (
                    <Avatar
                      src={tenant.logo}
                      sx={{
                        width: 32,
                        height: 32,
                        bgcolor: tenant.primaryColor || theme.palette.primary.main,
                      }}
                    >
                      {tenant.displayName.charAt(0)}
                    </Avatar>
                  ) : (
                    <Avatar
                      sx={{
                        width: 32,
                        height: 32,
                        bgcolor: tenant.primaryColor || theme.palette.primary.main,
                      }}
                    >
                      {tenant.displayName.charAt(0)}
                    </Avatar>
                  )}
                </Badge>

                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                      {tenant.displayName}
                    </Typography>

                    <Chip
                      label={tenant.status}
                      size="small"
                      variant="outlined"
                      sx={{
                        fontSize: '0.65rem',
                        height: 20,
                        borderColor: getTenantStatusColor(tenant),
                        color: getTenantStatusColor(tenant),
                      }}
                    />
                  </Stack>

                  <Stack direction="row" alignItems="center" spacing={1}>
                    <Typography variant="caption" color="text.secondary">
                      {tenant.name}
                    </Typography>

                    <Chip
                      label={tenant.plan}
                      size="small"
                      sx={{
                        fontSize: '0.6rem',
                        height: 16,
                        bgcolor: alpha(getTenantPlanColor(tenant.plan), 0.1),
                        color: getTenantPlanColor(tenant.plan),
                      }}
                    />
                  </Stack>
                </Box>

                {tenant.id === currentTenant?.id && (
                  <Tooltip title="Current Tenant">
                    <CheckIcon fontSize="small" sx={{ color: theme.palette.success.main }} />
                  </Tooltip>
                )}
              </Stack>
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      {/* Performance Metrics */}
      {showPerformanceMetrics && performanceMetrics.totalSwitches > 0 && (
        <Box sx={{ mt: 1 }}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <PerformanceIcon fontSize="small" color="action" />
            <Typography variant="caption" color="text.secondary">
              Avg: {Math.round(performanceMetrics.averageSwitchTime)}ms
            </Typography>
            {lastSwitchTime && (
              <Typography
                variant="caption"
                sx={{
                  color: lastSwitchTime > 500 ? theme.palette.warning.main : theme.palette.success.main,
                }}
              >
                Last: {Math.round(lastSwitchTime)}ms
              </Typography>
            )}
          </Stack>
        </Box>
      )}

      {/* Switch Error */}
      {switchError && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1 }} onClose={() => setSwitchError(null)}>
          {switchError}
        </Alert>
      )}
    </Box>
  );
}

export default TenantSwitcher;
