'use client';

/**
 * Branding Access Control Management Page
 * Administrative interface for managing RBAC and audit logging for white-labeling
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Card,
  CardContent,
  CardActions,
  Grid,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  CircularProgress,
  Checkbox,
  FormGroup,
  FormControlLabel,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondary,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  Tooltip,
  Menu,
  MenuItem as MenuItemComponent,
  DatePicker,
  Autocomplete,
} from '@mui/material';
import {
  Security as SecurityIcon,
  People as PeopleIcon,
  Assignment as RoleIcon,
  History as AuditIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Check as CheckIcon,
  Close as CloseIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  PersonAdd as PersonAddIcon,
  PersonRemove as PersonRemoveIcon,
  AdminPanelSettings as AdminIcon,
  Shield as ShieldIcon,
  Visibility as VisibilityIcon,
  MoreVert as MoreIcon,
  FilterList as FilterIcon,
  GetApp as ExportIcon,
  Refresh as RefreshIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';

import { brandingAccessControl } from '@/lib/white-labeling/branding-access-control';
import type {
  BrandingRole,
  BrandingPermission,
  BrandingAuditLog,
  BrandingAuditAction,
} from '@/types/white-labeling';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div role="tabpanel" hidden={value !== index}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const ALL_PERMISSIONS: { permission: BrandingPermission; label: string; description: string }[] = [
  { permission: 'brand:read', label: 'View Branding', description: 'View branding configurations and assets' },
  { permission: 'brand:write', label: 'Edit Branding', description: 'Create and edit branding configurations' },
  { permission: 'brand:delete', label: 'Delete Branding', description: 'Delete branding configurations and assets' },
  { permission: 'brand:approve', label: 'Approve Changes', description: 'Approve branding changes before deployment' },
  { permission: 'brand:deploy', label: 'Deploy Branding', description: 'Deploy branding configurations to production' },
  { permission: 'brand:audit', label: 'View Audit Logs', description: 'Access audit logs and security reports' },
  { permission: 'assets:upload', label: 'Upload Assets', description: 'Upload and manage brand assets' },
  { permission: 'assets:delete', label: 'Delete Assets', description: 'Delete brand assets and files' },
  { permission: 'theme:edit', label: 'Edit Themes', description: 'Modify theme colors, typography, and styling' },
  { permission: 'content:edit', label: 'Edit Content', description: 'Customize text content and terminology' },
  { permission: 'domain:configure', label: 'Configure Domains', description: 'Manage custom domains and DNS settings' },
  { permission: 'email:template:edit', label: 'Edit Email Templates', description: 'Customize email templates and content' },
];

export default function AccessControlManagementPage() {
  const [tabValue, setTabValue] = useState(0);
  const [roles, setRoles] = useState<BrandingRole[]>([]);
  const [auditLogs, setAuditLogs] = useState<BrandingAuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dialog states
  const [roleDialog, setRoleDialog] = useState(false);
  const [userRoleDialog, setUserRoleDialog] = useState(false);
  const [auditDialog, setAuditDialog] = useState(false);
  const [riskDialog, setRiskDialog] = useState(false);

  // Role management state
  const [selectedRole, setSelectedRole] = useState<BrandingRole | null>(null);
  const [roleForm, setRoleForm] = useState({
    name: '',
    description: '',
    permissions: [] as BrandingPermission[],
    isDefault: false,
  });

  // User role management state
  const [userRoleForm, setUserRoleForm] = useState({
    userId: '',
    userEmail: '',
    roleId: '',
    action: 'assign' as 'assign' | 'remove',
  });

  // Audit log filtering
  const [auditFilter, setAuditFilter] = useState({
    userId: '',
    action: '' as BrandingAuditAction | '',
    success: null as boolean | null,
    startDate: null as Date | null,
    endDate: null as Date | null,
  });

  // Risk assessment
  const [riskAssessment, setRiskAssessment] = useState<any>(null);

  // UI state
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [expandedAccordion, setExpandedAccordion] = useState<string | false>(false);

  const tenantId = 'demo-tenant'; // Would get from auth context
  const userId = 'demo-user'; // Would get from auth context
  const context = {
    userId,
    userEmail: 'admin@isectech.com',
    userRole: 'SUPER_ADMIN' as const,
    tenantId,
    ipAddress: '192.168.1.1',
    userAgent: 'Mozilla/5.0',
  };

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      // Mock data loading - would fetch from actual APIs
      setRoles([
        {
          id: 'role-1',
          name: 'Brand Administrator',
          description: 'Full access to all branding features',
          permissions: ALL_PERMISSIONS.map(p => p.permission),
          isDefault: false,
          tenantId,
          createdAt: new Date(),
          updatedAt: new Date(),
          createdBy: userId,
          updatedBy: userId,
        },
        {
          id: 'role-2',
          name: 'Brand Editor',
          description: 'Can create and edit branding configurations',
          permissions: ['brand:read', 'brand:write', 'theme:edit', 'content:edit'],
          isDefault: true,
          tenantId,
          createdAt: new Date(),
          updatedAt: new Date(),
          createdBy: userId,
          updatedBy: userId,
        },
      ]);
      
      setAuditLogs([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateRole = async () => {
    try {
      const role = await brandingAccessControl.createBrandingRole(context, roleForm);
      setRoles([...roles, role]);
      setRoleDialog(false);
      resetRoleForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create role');
    }
  };

  const handleUpdateRole = async () => {
    if (!selectedRole) return;
    
    try {
      const updated = await brandingAccessControl.updateBrandingRole(
        context,
        selectedRole.id,
        roleForm
      );
      setRoles(roles.map(r => r.id === updated.id ? updated : r));
      setRoleDialog(false);
      resetRoleForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    }
  };

  const handleAssignRole = async () => {
    try {
      if (userRoleForm.action === 'assign') {
        await brandingAccessControl.assignRole(context, userRoleForm.userId, userRoleForm.roleId);
      } else {
        await brandingAccessControl.removeRole(context, userRoleForm.userId, userRoleForm.roleId);
      }
      setUserRoleDialog(false);
      setUserRoleForm({ userId: '', userEmail: '', roleId: '', action: 'assign' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to manage user role');
    }
  };

  const handleLoadAuditLogs = async () => {
    try {
      const result = await brandingAccessControl.getAuditLogs(context, {
        ...auditFilter,
        limit: 100,
        offset: 0,
      });
      setAuditLogs(result.logs);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit logs');
    }
  };

  const resetRoleForm = () => {
    setRoleForm({
      name: '',
      description: '',
      permissions: [],
      isDefault: false,
    });
    setSelectedRole(null);
  };

  const getPermissionDescription = (permission: BrandingPermission): string => {
    return ALL_PERMISSIONS.find(p => p.permission === permission)?.description || permission;
  };

  const getAuditActionColor = (action: BrandingAuditAction) => {
    if (action.includes('create')) return 'success';
    if (action.includes('delete')) return 'error';
    if (action.includes('deploy')) return 'warning';
    return 'info';
  };

  const renderRoleCard = (role: BrandingRole) => (
    <Grid item xs={12} md={6} lg={4} key={role.id}>
      <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <CardContent sx={{ flexGrow: 1 }}>
          <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
            <Box>
              <Typography variant="h6" component="h2" gutterBottom>
                {role.name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {role.description}
              </Typography>
            </Box>
            <Box display="flex" alignItems="center" gap={1}>
              {role.isDefault && <Chip label="Default" size="small" color="primary" />}
              <IconButton
                size="small"
                onClick={(e) => {
                  setSelectedRole(role);
                  setAnchorEl(e.currentTarget);
                }}
              >
                <MoreIcon />
              </IconButton>
            </Box>
          </Box>
          
          <Typography variant="subtitle2" gutterBottom>
            Permissions ({role.permissions.length}):
          </Typography>
          <Box display="flex" flexWrap="wrap" gap={0.5} mb={2}>
            {role.permissions.slice(0, 3).map(permission => (
              <Chip
                key={permission}
                label={ALL_PERMISSIONS.find(p => p.permission === permission)?.label || permission}
                size="small"
                variant="outlined"
              />
            ))}
            {role.permissions.length > 3 && (
              <Chip label={`+${role.permissions.length - 3} more`} size="small" />
            )}
          </Box>
          
          <Typography variant="caption" color="text.secondary" display="block">
            Updated: {role.updatedAt.toLocaleDateString()}
          </Typography>
        </CardContent>
        
        <CardActions>
          <Button
            size="small"
            startIcon={<EditIcon />}
            onClick={() => {
              setSelectedRole(role);
              setRoleForm({
                name: role.name,
                description: role.description,
                permissions: role.permissions,
                isDefault: role.isDefault,
              });
              setRoleDialog(true);
            }}
          >
            Edit
          </Button>
          <Button
            size="small"
            startIcon={<PersonAddIcon />}
            onClick={() => {
              setUserRoleForm(prev => ({ ...prev, roleId: role.id, action: 'assign' }));
              setUserRoleDialog(true);
            }}
          >
            Assign
          </Button>
        </CardActions>
      </Card>
    </Grid>
  );

  const renderPermissionList = () => (
    <FormGroup>
      {ALL_PERMISSIONS.map(({ permission, label, description }) => (
        <FormControlLabel
          key={permission}
          control={
            <Checkbox
              checked={roleForm.permissions.includes(permission)}
              onChange={(e) => {
                if (e.target.checked) {
                  setRoleForm(prev => ({
                    ...prev,
                    permissions: [...prev.permissions, permission]
                  }));
                } else {
                  setRoleForm(prev => ({
                    ...prev,
                    permissions: prev.permissions.filter(p => p !== permission)
                  }));
                }
              }}
            />
          }
          label={
            <Box>
              <Typography variant="body2" fontWeight="medium">
                {label}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {description}
              </Typography>
            </Box>
          }
        />
      ))}
    </FormGroup>
  );

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Branding Access Control
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage roles, permissions, and audit logs for white-labeling features.
          </Typography>
        </Box>
        <Box display="flex" gap={2}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadData}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setRoleDialog(true)}
          >
            Create Role
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)} sx={{ mb: 3 }}>
        <Tab icon={<RoleIcon />} label="Roles & Permissions" />
        <Tab icon={<PeopleIcon />} label="User Management" />
        <Tab icon={<AuditIcon />} label="Audit Logs" />
        <Tab icon={<ShieldIcon />} label="Security Dashboard" />
      </Tabs>

      {/* Roles & Permissions Tab */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          {roles.map(role => renderRoleCard(role))}
          {roles.length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 6 }}>
                  <RoleIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No Roles Defined
                  </Typography>
                  <Typography variant="body2" color="text.secondary" mb={3}>
                    Create roles to manage access to branding features.
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => setRoleDialog(true)}
                  >
                    Create First Role
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* User Management Tab */}
      <TabPanel value={tabValue} index={1}>
        <Card>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h6">User Role Assignments</Typography>
              <Button
                variant="contained"
                startIcon={<PersonAddIcon />}
                onClick={() => setUserRoleDialog(true)}
              >
                Manage User Roles
              </Button>
            </Box>
            
            <Alert severity="info" sx={{ mb: 2 }}>
              User role assignments will be displayed here. This would typically show a list of users
              with their assigned branding roles and allow for role management operations.
            </Alert>
          </CardContent>
        </Card>
      </TabPanel>

      {/* Audit Logs Tab */}
      <TabPanel value={tabValue} index={2}>
        <Card>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h6">Branding Audit Logs</Typography>
              <Box display="flex" gap={2}>
                <Button
                  variant="outlined"
                  startIcon={<FilterIcon />}
                  onClick={handleLoadAuditLogs}
                >
                  Load Logs
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<ExportIcon />}
                >
                  Export
                </Button>
              </Box>
            </Box>

            <Accordion 
              expanded={expandedAccordion === 'filters'} 
              onChange={(_, isExpanded) => setExpandedAccordion(isExpanded ? 'filters' : false)}
            >
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography>Filter Options</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={3}>
                    <TextField
                      fullWidth
                      label="User ID"
                      value={auditFilter.userId}
                      onChange={(e) => setAuditFilter({ ...auditFilter, userId: e.target.value })}
                    />
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Action</InputLabel>
                      <Select
                        value={auditFilter.action}
                        onChange={(e) => setAuditFilter({ ...auditFilter, action: e.target.value as BrandingAuditAction })}
                        label="Action"
                      >
                        <MenuItem value="">All Actions</MenuItem>
                        <MenuItem value="configuration:create">Create Configuration</MenuItem>
                        <MenuItem value="configuration:update">Update Configuration</MenuItem>
                        <MenuItem value="configuration:deploy">Deploy Configuration</MenuItem>
                        <MenuItem value="asset:upload">Upload Asset</MenuItem>
                        <MenuItem value="role:assign">Assign Role</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Status</InputLabel>
                      <Select
                        value={auditFilter.success === null ? '' : auditFilter.success.toString()}
                        onChange={(e) => setAuditFilter({ 
                          ...auditFilter, 
                          success: e.target.value === '' ? null : e.target.value === 'true'
                        })}
                        label="Status"
                      >
                        <MenuItem value="">All</MenuItem>
                        <MenuItem value="true">Success</MenuItem>
                        <MenuItem value="false">Failed</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <Button
                      fullWidth
                      variant="outlined"
                      sx={{ height: '56px' }}
                      onClick={handleLoadAuditLogs}
                    >
                      Apply Filters
                    </Button>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>

            <TableContainer component={Paper} sx={{ mt: 2 }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>User</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>IP Address</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {auditLogs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} align="center">
                        <Typography variant="body2" color="text.secondary">
                          No audit logs available. Click "Load Logs" to fetch recent activity.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    auditLogs.map((log) => (
                      <TableRow key={log.id}>
                        <TableCell>{log.createdAt.toLocaleString()}</TableCell>
                        <TableCell>{log.userEmail}</TableCell>
                        <TableCell>
                          <Chip
                            label={log.action}
                            color={getAuditActionColor(log.action) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {log.resourceType}:{log.resourceId.substring(0, 8)}...
                        </TableCell>
                        <TableCell>
                          {log.success ? (
                            <CheckIcon color="success" />
                          ) : (
                            <ErrorIcon color="error" />
                          )}
                        </TableCell>
                        <TableCell>{log.ipAddress}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      </TabPanel>

      {/* Security Dashboard Tab */}
      <TabPanel value={tabValue} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Security Metrics
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon><ShieldIcon /></ListItemIcon>
                    <ListItemText
                      primary="Active Roles"
                      secondary={`${roles.length} roles configured`}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><PeopleIcon /></ListItemIcon>
                    <ListItemText
                      primary="Users with Access"
                      secondary="User count would be shown here"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon><TimelineIcon /></ListItemIcon>
                    <ListItemText
                      primary="Recent Activity"
                      secondary={`${auditLogs.length} recent actions logged`}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Risk Assessment
                </Typography>
                <Alert severity="info" sx={{ mb: 2 }}>
                  Risk assessment would analyze recent branding changes and user activities
                  to identify potential security concerns.
                </Alert>
                <Button
                  variant="outlined"
                  fullWidth
                  startIcon={<WarningIcon />}
                  onClick={() => setRiskDialog(true)}
                >
                  Run Risk Assessment
                </Button>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Create/Edit Role Dialog */}
      <Dialog open={roleDialog} onClose={() => setRoleDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {selectedRole ? 'Edit Role' : 'Create New Role'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Role Name"
                value={roleForm.name}
                onChange={(e) => setRoleForm({ ...roleForm, name: e.target.value })}
                placeholder="Brand Administrator"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={2}
                label="Description"
                value={roleForm.description}
                onChange={(e) => setRoleForm({ ...roleForm, description: e.target.value })}
                placeholder="Describe the role's purpose and scope..."
              />
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={roleForm.isDefault}
                    onChange={(e) => setRoleForm({ ...roleForm, isDefault: e.target.checked })}
                  />
                }
                label="Default role for new users"
              />
            </Grid>
            <Grid item xs={12}>
              <Typography variant="subtitle1" gutterBottom>
                Permissions
              </Typography>
              <Box sx={{ maxHeight: 300, overflowY: 'auto' }}>
                {renderPermissionList()}
              </Box>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setRoleDialog(false); resetRoleForm(); }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={selectedRole ? handleUpdateRole : handleCreateRole}
            disabled={!roleForm.name || roleForm.permissions.length === 0}
          >
            {selectedRole ? 'Update Role' : 'Create Role'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* User Role Management Dialog */}
      <Dialog open={userRoleDialog} onClose={() => setUserRoleDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Manage User Roles</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Action</InputLabel>
                <Select
                  value={userRoleForm.action}
                  onChange={(e) => setUserRoleForm({ ...userRoleForm, action: e.target.value as 'assign' | 'remove' })}
                  label="Action"
                >
                  <MenuItem value="assign">Assign Role</MenuItem>
                  <MenuItem value="remove">Remove Role</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="User ID"
                value={userRoleForm.userId}
                onChange={(e) => setUserRoleForm({ ...userRoleForm, userId: e.target.value })}
                placeholder="Enter user ID"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="User Email"
                value={userRoleForm.userEmail}
                onChange={(e) => setUserRoleForm({ ...userRoleForm, userEmail: e.target.value })}
                placeholder="user@example.com"
              />
            </Grid>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Role</InputLabel>
                <Select
                  value={userRoleForm.roleId}
                  onChange={(e) => setUserRoleForm({ ...userRoleForm, roleId: e.target.value })}
                  label="Role"
                >
                  {roles.map(role => (
                    <MenuItem key={role.id} value={role.id}>
                      {role.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setUserRoleDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAssignRole}
            disabled={!userRoleForm.userId || !userRoleForm.roleId}
          >
            {userRoleForm.action === 'assign' ? 'Assign Role' : 'Remove Role'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Role Actions Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItemComponent onClick={() => {
          // Edit role logic would go here
          setAnchorEl(null);
        }}>
          <ListItemIcon><EditIcon /></ListItemIcon>
          <ListItemText>Edit Role</ListItemText>
        </MenuItemComponent>
        <MenuItemComponent onClick={() => {
          // Delete role logic would go here
          setAnchorEl(null);
        }}>
          <ListItemIcon><DeleteIcon /></ListItemIcon>
          <ListItemText>Delete Role</ListItemText>
        </MenuItemComponent>
      </Menu>
    </Box>
  );
}