/**
 * Hierarchical Permissions Component for iSECTECH Protect
 * Production-grade role and permission management for multi-tenant environments
 */

'use client';

import { useAuthStore, useStores } from '@/lib/store';
import type { SecurityClearance, Tenant, User, UserRole } from '@/types';
import {
  CheckCircle as CheckIcon,
  ExpandMore as ExpandMoreIcon,
  People as PeopleIcon,
  Key as PermissionIcon,
  Assignment as RoleIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  alpha,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  FormGroup,
  Grid,
  IconButton,
  InputLabel,
  List,
  ListItem,
  ListItemIcon,
  ListItemSecondaryAction,
  ListItemText,
  MenuItem,
  Select,
  Stack,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { useCallback, useMemo, useState } from 'react';

// Permission categories and their specific permissions
const PERMISSION_CATEGORIES = {
  'Dashboard & Overview': ['dashboard:view', 'dashboard:customize', 'overview:view', 'metrics:view'],
  'Alert Management': [
    'alerts:view',
    'alerts:acknowledge',
    'alerts:assign',
    'alerts:escalate',
    'alerts:suppress',
    'alerts:investigate',
  ],
  'Incident Management': [
    'incidents:view',
    'incidents:create',
    'incidents:update',
    'incidents:close',
    'incidents:assign',
    'incidents:escalate',
  ],
  'Threat Intelligence': ['threats:view', 'threats:investigate', 'threats:block', 'threats:analyze', 'threats:hunt'],
  'Asset Management': ['assets:view', 'assets:scan', 'assets:patch', 'assets:manage', 'assets:monitor'],
  'User Management': [
    'users:view',
    'users:create',
    'users:update',
    'users:delete',
    'users:manage',
    'users:impersonate',
  ],
  'Tenant Management': [
    'tenant:view',
    'tenant:create',
    'tenant:update',
    'tenant:delete',
    'tenant:customize',
    'tenant:access',
  ],
  'Policy Management': ['policies:view', 'policies:create', 'policies:update', 'policies:delete', 'policies:apply'],
  Compliance: ['compliance:view', 'compliance:check', 'compliance:report', 'compliance:manage'],
  Reporting: ['reports:view', 'reports:create', 'reports:export', 'reports:schedule', 'reports:generate'],
  'System Administration': ['system:configure', 'system:monitor', 'system:backup', 'system:restore', 'system:audit'],
} as const;

// Role definitions with default permissions
const ROLE_DEFINITIONS: Record<
  UserRole,
  {
    title: string;
    description: string;
    defaultPermissions: string[];
    securityClearance: SecurityClearance[];
    color: string;
  }
> = {
  SUPER_ADMIN: {
    title: 'Super Administrator',
    description: 'Full system access across all tenants',
    defaultPermissions: ['*'], // All permissions
    securityClearance: ['TOP_SECRET'],
    color: '#d32f2f',
  },
  TENANT_ADMIN: {
    title: 'Tenant Administrator',
    description: 'Administrative access within tenant scope',
    defaultPermissions: [
      'dashboard:view',
      'dashboard:customize',
      'alerts:view',
      'alerts:acknowledge',
      'alerts:assign',
      'incidents:view',
      'incidents:create',
      'incidents:update',
      'users:view',
      'users:create',
      'users:update',
      'policies:view',
      'policies:create',
      'policies:update',
      'reports:view',
      'reports:create',
      'reports:export',
    ],
    securityClearance: ['SECRET', 'CONFIDENTIAL'],
    color: '#f57c00',
  },
  SECURITY_ANALYST: {
    title: 'Security Analyst',
    description: 'Advanced security analysis and investigation',
    defaultPermissions: [
      'dashboard:view',
      'alerts:view',
      'alerts:acknowledge',
      'alerts:investigate',
      'incidents:view',
      'incidents:create',
      'incidents:update',
      'threats:view',
      'threats:investigate',
      'threats:analyze',
      'assets:view',
      'assets:scan',
      'reports:view',
      'reports:create',
    ],
    securityClearance: ['SECRET', 'CONFIDENTIAL'],
    color: '#1976d2',
  },
  SOC_ANALYST: {
    title: 'SOC Analyst',
    description: 'Security operations and monitoring',
    defaultPermissions: [
      'dashboard:view',
      'alerts:view',
      'alerts:acknowledge',
      'incidents:view',
      'incidents:create',
      'threats:view',
      'assets:view',
      'reports:view',
    ],
    securityClearance: ['CONFIDENTIAL', 'UNCLASSIFIED'],
    color: '#388e3c',
  },
  INCIDENT_RESPONDER: {
    title: 'Incident Responder',
    description: 'Incident response and remediation',
    defaultPermissions: [
      'dashboard:view',
      'alerts:view',
      'alerts:acknowledge',
      'alerts:escalate',
      'incidents:view',
      'incidents:create',
      'incidents:update',
      'incidents:close',
      'threats:view',
      'threats:block',
      'assets:view',
      'assets:manage',
    ],
    securityClearance: ['SECRET', 'CONFIDENTIAL'],
    color: '#7b1fa2',
  },
  COMPLIANCE_OFFICER: {
    title: 'Compliance Officer',
    description: 'Compliance monitoring and reporting',
    defaultPermissions: [
      'dashboard:view',
      'compliance:view',
      'compliance:check',
      'compliance:report',
      'policies:view',
      'reports:view',
      'reports:create',
      'reports:export',
    ],
    securityClearance: ['CONFIDENTIAL', 'UNCLASSIFIED'],
    color: '#00796b',
  },
  READ_ONLY: {
    title: 'Read Only',
    description: 'View-only access to security information',
    defaultPermissions: [
      'dashboard:view',
      'alerts:view',
      'incidents:view',
      'threats:view',
      'assets:view',
      'reports:view',
    ],
    securityClearance: ['UNCLASSIFIED'],
    color: '#616161',
  },
  CUSTOM: {
    title: 'Custom Role',
    description: 'Custom role with specific permissions',
    defaultPermissions: [],
    securityClearance: ['UNCLASSIFIED'],
    color: '#795548',
  },
};

interface HierarchicalPermissionsProps {
  /**
   * Current tenant context
   */
  tenant: Tenant;

  /**
   * Users in the current tenant
   */
  users: User[];

  /**
   * Available tenants for cross-tenant permissions
   */
  availableTenants?: Tenant[];

  /**
   * Callback when permissions are updated
   */
  onPermissionsUpdate?: (userId: string, permissions: string[]) => Promise<void>;

  /**
   * Callback when role is changed
   */
  onRoleChange?: (userId: string, role: UserRole) => Promise<void>;

  /**
   * Read-only mode
   */
  readonly?: boolean;
}

export function HierarchicalPermissions({
  tenant,
  users,
  availableTenants = [],
  onPermissionsUpdate,
  onRoleChange,
  readonly = false,
}: HierarchicalPermissionsProps) {
  const theme = useTheme();
  const { user: currentUser } = useAuthStore();
  const { showSuccess, showError, showWarning } = useStores();

  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showPermissionDialog, setShowPermissionDialog] = useState(false);
  const [showRoleDialog, setShowRoleDialog] = useState(false);
  const [expandedCategories, setExpandedCategories] = useState<string[]>([]);
  const [userPermissions, setUserPermissions] = useState<string[]>([]);
  const [selectedRole, setSelectedRole] = useState<UserRole>('READ_ONLY');

  // Filter users by security clearance and permissions
  const filteredUsers = useMemo(() => {
    if (!currentUser) return [];

    return users.filter((user) => {
      // Super admins can see all users
      if (currentUser.role === 'SUPER_ADMIN') return true;

      // Tenant admins can see users in their tenant
      if (currentUser.role === 'TENANT_ADMIN' && user.tenantId === currentUser.tenantId) {
        return true;
      }

      // Other roles can only see users with equal or lower clearance
      const clearanceLevels = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
      const currentLevel = clearanceLevels.indexOf(currentUser.securityClearance);
      const userLevel = clearanceLevels.indexOf(user.securityClearance);

      return userLevel <= currentLevel;
    });
  }, [users, currentUser]);

  // Check if current user can modify permissions for a specific user
  const canModifyUser = useCallback(
    (user: User) => {
      if (!currentUser || readonly) return false;

      // Super admins can modify anyone
      if (currentUser.role === 'SUPER_ADMIN') return true;

      // Tenant admins can modify users in their tenant (except other tenant admins and super admins)
      if (currentUser.role === 'TENANT_ADMIN' && user.tenantId === currentUser.tenantId) {
        return !['SUPER_ADMIN', 'TENANT_ADMIN'].includes(user.role);
      }

      return false;
    },
    [currentUser, readonly]
  );

  // Get permissions for a category
  const getCategoryPermissions = useCallback((category: string) => {
    return PERMISSION_CATEGORIES[category] || [];
  }, []);

  // Check if user has permission
  const hasPermission = useCallback((user: User, permission: string) => {
    return user.permissions.includes(permission) || user.permissions.includes('*');
  }, []);

  // Handle permission toggle
  const togglePermission = useCallback((permission: string) => {
    setUserPermissions((prev) => {
      if (prev.includes(permission)) {
        return prev.filter((p) => p !== permission);
      } else {
        return [...prev, permission];
      }
    });
  }, []);

  // Open permission dialog
  const openPermissionDialog = useCallback((user: User) => {
    setSelectedUser(user);
    setUserPermissions(user.permissions);
    setShowPermissionDialog(true);
  }, []);

  // Save permissions
  const savePermissions = useCallback(async () => {
    if (!selectedUser || !onPermissionsUpdate) return;

    try {
      await onPermissionsUpdate(selectedUser.id, userPermissions);
      setShowPermissionDialog(false);
      showSuccess(
        'Permissions Updated',
        `Successfully updated permissions for ${selectedUser.firstName} ${selectedUser.lastName}.`
      );
    } catch (error) {
      console.error('Failed to update permissions:', error);
      showError('Update Failed', 'Unable to update user permissions.');
    }
  }, [selectedUser, userPermissions, onPermissionsUpdate, showSuccess, showError]);

  // Open role dialog
  const openRoleDialog = useCallback((user: User) => {
    setSelectedUser(user);
    setSelectedRole(user.role);
    setShowRoleDialog(true);
  }, []);

  // Save role
  const saveRole = useCallback(async () => {
    if (!selectedUser || !onRoleChange) return;

    try {
      await onRoleChange(selectedUser.id, selectedRole);
      setShowRoleDialog(false);
      showSuccess('Role Updated', `Successfully updated role for ${selectedUser.firstName} ${selectedUser.lastName}.`);
    } catch (error) {
      console.error('Failed to update role:', error);
      showError('Update Failed', 'Unable to update user role.');
    }
  }, [selectedUser, selectedRole, onRoleChange, showSuccess, showError]);

  // Apply role template
  const applyRoleTemplate = useCallback(() => {
    const roleDefinition = ROLE_DEFINITIONS[selectedRole];
    setUserPermissions(roleDefinition.defaultPermissions);
  }, [selectedRole]);

  return (
    <Box>
      <Card elevation={2}>
        <CardHeader
          title={
            <Stack direction="row" alignItems="center" spacing={1}>
              <SecurityIcon />
              <Typography variant="h6">Hierarchical Permissions</Typography>
              {readonly && <Chip label="Read Only" size="small" variant="outlined" />}
            </Stack>
          }
          subheader={`Manage user roles and permissions for ${tenant.displayName}`}
        />

        <CardContent>
          <Grid container spacing={3}>
            {/* Users List */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" gutterBottom>
                Users ({filteredUsers.length})
              </Typography>

              <List dense>
                {filteredUsers.map((user) => (
                  <ListItem key={user.id} divider>
                    <ListItemIcon>
                      <Badge color={user.status === 'ACTIVE' ? 'success' : 'error'} variant="dot">
                        <PeopleIcon />
                      </Badge>
                    </ListItemIcon>

                    <ListItemText
                      primary={
                        <Stack direction="row" alignItems="center" spacing={1}>
                          <Typography variant="body2">
                            {user.firstName} {user.lastName}
                          </Typography>
                          <Chip
                            label={ROLE_DEFINITIONS[user.role]?.title || user.role}
                            size="small"
                            sx={{
                              bgcolor: alpha(ROLE_DEFINITIONS[user.role]?.color || theme.palette.grey[500], 0.1),
                              color: ROLE_DEFINITIONS[user.role]?.color || theme.palette.grey[500],
                              fontSize: '0.7rem',
                            }}
                          />
                        </Stack>
                      }
                      secondary={
                        <Stack spacing={0.5}>
                          <Typography variant="caption" color="text.secondary">
                            {user.email}
                          </Typography>
                          <Stack direction="row" alignItems="center" spacing={1}>
                            <Chip
                              label={user.securityClearance}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: '0.65rem', height: 20 }}
                            />
                            <Typography variant="caption" color="text.secondary">
                              {user.permissions.length} permissions
                            </Typography>
                          </Stack>
                        </Stack>
                      }
                    />

                    <ListItemSecondaryAction>
                      <Stack direction="row" spacing={0.5}>
                        <Tooltip title="Edit Permissions">
                          <IconButton
                            size="small"
                            onClick={() => openPermissionDialog(user)}
                            disabled={!canModifyUser(user)}
                          >
                            <PermissionIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Change Role">
                          <IconButton size="small" onClick={() => openRoleDialog(user)} disabled={!canModifyUser(user)}>
                            <RoleIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </Grid>

            {/* Role Definitions */}
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" gutterBottom>
                Role Definitions
              </Typography>

              <Stack spacing={1}>
                {Object.entries(ROLE_DEFINITIONS).map(([role, definition]) => (
                  <Accordion key={role}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Stack direction="row" alignItems="center" spacing={1} sx={{ width: '100%' }}>
                        <Chip
                          label={definition.title}
                          size="small"
                          sx={{
                            bgcolor: alpha(definition.color, 0.1),
                            color: definition.color,
                          }}
                        />
                        <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
                          {definition.description}
                        </Typography>
                      </Stack>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Stack spacing={1}>
                        <Typography variant="caption" color="text.secondary">
                          Default Permissions: {definition.defaultPermissions.join(', ')}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Security Clearance: {definition.securityClearance.join(', ')}
                        </Typography>
                      </Stack>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Stack>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Permission Dialog */}
      <Dialog open={showPermissionDialog} onClose={() => setShowPermissionDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          <Stack direction="row" alignItems="center" spacing={1}>
            <PermissionIcon />
            <Typography>
              Edit Permissions: {selectedUser?.firstName} {selectedUser?.lastName}
            </Typography>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            <Alert severity="info" variant="outlined">
              Select specific permissions for this user. Changes will take effect immediately.
            </Alert>

            {Object.entries(PERMISSION_CATEGORIES).map(([category, permissions]) => (
              <Accordion key={category}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <Typography variant="subtitle2">{category}</Typography>
                    <Chip
                      label={`${permissions.filter((p) => userPermissions.includes(p)).length}/${permissions.length}`}
                      size="small"
                      variant="outlined"
                    />
                  </Stack>
                </AccordionSummary>
                <AccordionDetails>
                  <FormGroup>
                    {permissions.map((permission) => (
                      <FormControlLabel
                        key={permission}
                        control={
                          <Checkbox
                            checked={userPermissions.includes(permission) || userPermissions.includes('*')}
                            onChange={() => togglePermission(permission)}
                            disabled={userPermissions.includes('*')}
                          />
                        }
                        label={<Typography variant="body2">{permission}</Typography>}
                      />
                    ))}
                  </FormGroup>
                </AccordionDetails>
              </Accordion>
            ))}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowPermissionDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={savePermissions} startIcon={<CheckIcon />}>
            Save Permissions
          </Button>
        </DialogActions>
      </Dialog>

      {/* Role Dialog */}
      <Dialog open={showRoleDialog} onClose={() => setShowRoleDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Stack direction="row" alignItems="center" spacing={1}>
            <RoleIcon />
            <Typography>
              Change Role: {selectedUser?.firstName} {selectedUser?.lastName}
            </Typography>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <Stack spacing={3}>
            <Alert severity="warning" variant="outlined">
              Changing a user's role will update their default permissions. Custom permissions may be overridden.
            </Alert>

            <FormControl fullWidth>
              <InputLabel>Select Role</InputLabel>
              <Select
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value as UserRole)}
                label="Select Role"
              >
                {Object.entries(ROLE_DEFINITIONS).map(([role, definition]) => (
                  <MenuItem key={role} value={role}>
                    <Stack direction="row" alignItems="center" spacing={1} sx={{ width: '100%' }}>
                      <Chip
                        label={definition.title}
                        size="small"
                        sx={{
                          bgcolor: alpha(definition.color, 0.1),
                          color: definition.color,
                        }}
                      />
                      <Typography variant="body2" sx={{ flex: 1 }}>
                        {definition.description}
                      </Typography>
                    </Stack>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <Button variant="outlined" onClick={applyRoleTemplate} startIcon={<RoleIcon />}>
              Apply Role Template Permissions
            </Button>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowRoleDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={saveRole} startIcon={<CheckIcon />}>
            Change Role
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default HierarchicalPermissions;
