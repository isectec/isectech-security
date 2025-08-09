/**
 * Bulk Operations Panel for iSECTECH Protect MSSP
 * Production-grade multi-tenant bulk operations interface
 */

'use client';

import { useAuthStore, useStores } from '@/lib/store';
import type { Tenant } from '@/types';
import {
  Error as ErrorIcon,
  PlayArrow as ExecuteIcon,
  GetApp as ExportIcon,
  Group as GroupIcon,
  Timeline as ProgressIcon,
  Stop as StopIcon,
  CheckCircle as SuccessIcon,
  Assignment as TaskIcon,
  Visibility as ViewIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import {
  Alert,
  alpha,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  IconButton,
  InputLabel,
  List,
  ListItem,
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

// Bulk operation types
export type BulkOperationType =
  | 'alerts_acknowledge'
  | 'alerts_assign'
  | 'alerts_escalate'
  | 'alerts_suppress'
  | 'incidents_create'
  | 'incidents_close'
  | 'threats_block'
  | 'threats_investigate'
  | 'users_disable'
  | 'users_enable'
  | 'assets_scan'
  | 'assets_patch'
  | 'policies_apply'
  | 'policies_remove'
  | 'reports_generate'
  | 'compliance_check';

interface BulkOperation {
  id: string;
  type: BulkOperationType;
  title: string;
  description: string;
  tenantIds: string[];
  parameters: Record<string, any>;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  results?: BulkOperationResult[];
  startedAt?: Date;
  completedAt?: Date;
  error?: string;
}

interface BulkOperationResult {
  tenantId: string;
  tenantName: string;
  status: 'success' | 'error' | 'skipped';
  message?: string;
  affectedItems: number;
  duration: number;
}

interface BulkOperationsPanelProps {
  /**
   * Available tenants for bulk operations
   */
  availableTenants: Tenant[];

  /**
   * Selected tenant IDs for operations
   */
  selectedTenantIds: string[];

  /**
   * Callback when tenant selection changes
   */
  onTenantSelectionChange: (tenantIds: string[]) => void;

  /**
   * Whether the panel is in compact mode
   */
  compact?: boolean;
}

export function BulkOperationsPanel({
  availableTenants,
  selectedTenantIds,
  onTenantSelectionChange,
  compact = false,
}: BulkOperationsPanelProps) {
  const theme = useTheme();
  const { user } = useAuthStore();
  const { showSuccess, showError, showWarning } = useStores();

  const [operations, setOperations] = useState<BulkOperation[]>([]);
  const [selectedOperation, setSelectedOperation] = useState<BulkOperationType | ''>('');
  const [operationParameters, setOperationParameters] = useState<Record<string, any>>({});
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [showResultsDialog, setShowResultsDialog] = useState(false);
  const [selectedResults, setSelectedResults] = useState<BulkOperation | null>(null);

  // Available bulk operations based on user role
  const availableOperations = useMemo(() => {
    const allOperations = [
      {
        type: 'alerts_acknowledge' as BulkOperationType,
        title: 'Acknowledge Alerts',
        description: 'Mark selected alerts as acknowledged across tenants',
        requiredPermission: 'alerts:acknowledge',
        category: 'Alert Management',
      },
      {
        type: 'alerts_assign' as BulkOperationType,
        title: 'Assign Alerts',
        description: 'Assign alerts to team members across tenants',
        requiredPermission: 'alerts:assign',
        category: 'Alert Management',
      },
      {
        type: 'incidents_create' as BulkOperationType,
        title: 'Create Incidents',
        description: 'Create incidents from selected alerts across tenants',
        requiredPermission: 'incidents:create',
        category: 'Incident Response',
      },
      {
        type: 'threats_block' as BulkOperationType,
        title: 'Block Threats',
        description: 'Block identified threats across tenants',
        requiredPermission: 'threats:block',
        category: 'Threat Response',
      },
      {
        type: 'users_disable' as BulkOperationType,
        title: 'Disable Users',
        description: 'Disable compromised user accounts across tenants',
        requiredPermission: 'users:manage',
        category: 'User Management',
      },
      {
        type: 'assets_scan' as BulkOperationType,
        title: 'Scan Assets',
        description: 'Initiate security scans on assets across tenants',
        requiredPermission: 'assets:scan',
        category: 'Asset Management',
      },
      {
        type: 'policies_apply' as BulkOperationType,
        title: 'Apply Policies',
        description: 'Apply security policies across tenants',
        requiredPermission: 'policies:apply',
        category: 'Policy Management',
      },
      {
        type: 'reports_generate' as BulkOperationType,
        title: 'Generate Reports',
        description: 'Generate security reports across tenants',
        requiredPermission: 'reports:generate',
        category: 'Reporting',
      },
      {
        type: 'compliance_check' as BulkOperationType,
        title: 'Run Compliance Check',
        description: 'Execute compliance checks across tenants',
        requiredPermission: 'compliance:check',
        category: 'Compliance',
      },
    ];

    // Filter based on user permissions
    return allOperations.filter((op) => {
      if (user?.role === 'SUPER_ADMIN') return true;
      return user?.permissions.includes(op.requiredPermission);
    });
  }, [user]);

  // Get operation category color
  const getCategoryColor = (category: string) => {
    const colors = {
      'Alert Management': theme.palette.error.main,
      'Incident Response': theme.palette.warning.main,
      'Threat Response': theme.palette.error.dark,
      'User Management': theme.palette.info.main,
      'Asset Management': theme.palette.primary.main,
      'Policy Management': theme.palette.secondary.main,
      Reporting: theme.palette.success.main,
      Compliance: theme.palette.purple?.main || theme.palette.secondary.main,
    };
    return colors[category] || theme.palette.text.secondary;
  };

  // Handle operation execution
  const executeOperation = useCallback(async () => {
    if (!selectedOperation || selectedTenantIds.length === 0) {
      showWarning('Invalid Selection', 'Please select an operation and at least one tenant.');
      return;
    }

    const operation: BulkOperation = {
      id: `bulk_${Date.now()}`,
      type: selectedOperation,
      title: availableOperations.find((op) => op.type === selectedOperation)?.title || '',
      description: availableOperations.find((op) => op.type === selectedOperation)?.description || '',
      tenantIds: selectedTenantIds,
      parameters: operationParameters,
      status: 'pending',
      progress: 0,
      startedAt: new Date(),
    };

    setOperations((prev) => [operation, ...prev]);
    setShowConfirmDialog(false);

    try {
      // Update status to running
      setOperations((prev) => prev.map((op) => (op.id === operation.id ? { ...op, status: 'running' as const } : op)));

      // Simulate API call - In real implementation, this would call the backend
      // const response = await apiClient.post('/bulk-operations', operation);

      // Simulate progress updates
      for (let progress = 0; progress <= 100; progress += 10) {
        await new Promise((resolve) => setTimeout(resolve, 200));
        setOperations((prev) => prev.map((op) => (op.id === operation.id ? { ...op, progress } : op)));
      }

      // Mock results
      const results: BulkOperationResult[] = selectedTenantIds.map((tenantId, index) => {
        const tenant = availableTenants.find((t) => t.id === tenantId);
        return {
          tenantId,
          tenantName: tenant?.displayName || 'Unknown',
          status: Math.random() > 0.1 ? 'success' : 'error',
          message: Math.random() > 0.1 ? 'Operation completed successfully' : 'Operation failed',
          affectedItems: Math.floor(Math.random() * 100) + 1,
          duration: Math.floor(Math.random() * 5000) + 1000,
        };
      });

      // Update with results
      setOperations((prev) =>
        prev.map((op) =>
          op.id === operation.id
            ? {
                ...op,
                status: 'completed' as const,
                progress: 100,
                results,
                completedAt: new Date(),
              }
            : op
        )
      );

      const successCount = results.filter((r) => r.status === 'success').length;
      const errorCount = results.filter((r) => r.status === 'error').length;

      if (errorCount === 0) {
        showSuccess('Operation Completed', `Successfully executed ${operation.title} across ${successCount} tenants.`);
      } else {
        showWarning(
          'Operation Completed with Errors',
          `${successCount} successful, ${errorCount} failed. Click to view details.`
        );
      }
    } catch (error) {
      console.error('Bulk operation failed:', error);
      setOperations((prev) =>
        prev.map((op) =>
          op.id === operation.id
            ? {
                ...op,
                status: 'failed' as const,
                error: error instanceof Error ? error.message : 'Unknown error',
                completedAt: new Date(),
              }
            : op
        )
      );

      showError('Operation Failed', 'The bulk operation could not be completed.');
    }
  }, [
    selectedOperation,
    selectedTenantIds,
    operationParameters,
    availableOperations,
    availableTenants,
    showSuccess,
    showError,
    showWarning,
  ]);

  // Get status icon and color
  const getStatusIcon = (status: BulkOperation['status']) => {
    switch (status) {
      case 'running':
        return <CircularProgress size={16} />;
      case 'completed':
        return <SuccessIcon fontSize="small" sx={{ color: theme.palette.success.main }} />;
      case 'failed':
        return <ErrorIcon fontSize="small" sx={{ color: theme.palette.error.main }} />;
      case 'cancelled':
        return <StopIcon fontSize="small" sx={{ color: theme.palette.warning.main }} />;
      default:
        return <TaskIcon fontSize="small" sx={{ color: theme.palette.text.secondary }} />;
    }
  };

  const runningOperations = operations.filter((op) => op.status === 'running').length;

  return (
    <Box>
      <Card elevation={2}>
        <CardHeader
          title={
            <Stack direction="row" alignItems="center" spacing={1}>
              <GroupIcon />
              <Typography variant="h6">Bulk Operations</Typography>
              {runningOperations > 0 && (
                <Badge badgeContent={runningOperations} color="primary">
                  <ProgressIcon />
                </Badge>
              )}
            </Stack>
          }
          subheader={`${selectedTenantIds.length} tenant(s) selected`}
        />

        <CardContent>
          <Stack spacing={3}>
            {/* Operation Selection */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Select Operation
              </Typography>
              <FormControl fullWidth size="small">
                <InputLabel>Bulk Operation</InputLabel>
                <Select
                  value={selectedOperation}
                  onChange={(e) => setSelectedOperation(e.target.value as BulkOperationType)}
                  label="Bulk Operation"
                >
                  {availableOperations.map((op) => (
                    <MenuItem key={op.type} value={op.type}>
                      <Stack direction="row" alignItems="center" spacing={1} sx={{ width: '100%' }}>
                        <Chip
                          label={op.category}
                          size="small"
                          sx={{
                            bgcolor: alpha(getCategoryColor(op.category), 0.1),
                            color: getCategoryColor(op.category),
                            fontSize: '0.7rem',
                          }}
                        />
                        <Box>
                          <Typography variant="body2">{op.title}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {op.description}
                          </Typography>
                        </Box>
                      </Stack>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Box>

            {/* Execute Button */}
            <Button
              variant="contained"
              startIcon={<ExecuteIcon />}
              onClick={() => setShowConfirmDialog(true)}
              disabled={!selectedOperation || selectedTenantIds.length === 0 || runningOperations > 0}
              fullWidth
            >
              Execute Across {selectedTenantIds.length} Tenant(s)
            </Button>

            <Divider />

            {/* Recent Operations */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Recent Operations
              </Typography>

              {operations.length === 0 ? (
                <Typography variant="body2" color="text.secondary" align="center" sx={{ py: 2 }}>
                  No bulk operations executed yet
                </Typography>
              ) : (
                <List dense>
                  {operations.slice(0, compact ? 3 : 5).map((operation) => (
                    <ListItem key={operation.id} divider>
                      <ListItemText
                        primary={
                          <Stack direction="row" alignItems="center" spacing={1}>
                            {getStatusIcon(operation.status)}
                            <Typography variant="body2">{operation.title}</Typography>
                            <Chip
                              label={operation.status.toUpperCase()}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: '0.7rem' }}
                            />
                          </Stack>
                        }
                        secondary={
                          <Box>
                            <Typography variant="caption" color="text.secondary">
                              {operation.tenantIds.length} tenants • {operation.startedAt?.toLocaleString()}
                            </Typography>
                            {operation.status === 'running' && (
                              <Box sx={{ width: '100%', mt: 0.5 }}>
                                <Typography variant="caption" color="text.secondary">
                                  Progress: {operation.progress}%
                                </Typography>
                              </Box>
                            )}
                          </Box>
                        }
                      />
                      <ListItemSecondaryAction>
                        {operation.results && (
                          <Tooltip title="View Results">
                            <IconButton
                              size="small"
                              onClick={() => {
                                setSelectedResults(operation);
                                setShowResultsDialog(true);
                              }}
                            >
                              <ViewIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              )}
            </Box>
          </Stack>
        </CardContent>
      </Card>

      {/* Confirmation Dialog */}
      <Dialog open={showConfirmDialog} onClose={() => setShowConfirmDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Stack direction="row" alignItems="center" spacing={1}>
            <WarningIcon color="warning" />
            <Typography>Confirm Bulk Operation</Typography>
          </Stack>
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            <Alert severity="warning" variant="outlined">
              This operation will be executed across {selectedTenantIds.length} tenant(s). This action cannot be undone.
            </Alert>

            <Typography variant="body2">
              <strong>Operation:</strong> {availableOperations.find((op) => op.type === selectedOperation)?.title}
            </Typography>

            <Typography variant="body2">
              <strong>Affected Tenants:</strong>
            </Typography>
            <List dense>
              {selectedTenantIds.map((tenantId) => {
                const tenant = availableTenants.find((t) => t.id === tenantId);
                return (
                  <ListItem key={tenantId}>
                    <ListItemText primary={tenant?.displayName || tenantId} secondary={tenant?.name} />
                  </ListItem>
                );
              })}
            </List>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowConfirmDialog(false)}>Cancel</Button>
          <Button variant="contained" color="warning" onClick={executeOperation} startIcon={<ExecuteIcon />}>
            Execute Operation
          </Button>
        </DialogActions>
      </Dialog>

      {/* Results Dialog */}
      <Dialog open={showResultsDialog} onClose={() => setShowResultsDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Operation Results: {selectedResults?.title}</DialogTitle>
        <DialogContent>
          {selectedResults?.results && (
            <List>
              {selectedResults.results.map((result, index) => (
                <ListItem key={index} divider>
                  <ListItemText
                    primary={
                      <Stack direction="row" alignItems="center" spacing={1}>
                        {result.status === 'success' ? (
                          <SuccessIcon fontSize="small" sx={{ color: theme.palette.success.main }} />
                        ) : (
                          <ErrorIcon fontSize="small" sx={{ color: theme.palette.error.main }} />
                        )}
                        <Typography variant="body2">{result.tenantName}</Typography>
                        <Chip
                          label={result.status.toUpperCase()}
                          size="small"
                          color={result.status === 'success' ? 'success' : 'error'}
                          variant="outlined"
                        />
                      </Stack>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2">{result.message}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {result.affectedItems} items affected • {result.duration}ms
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowResultsDialog(false)}>Close</Button>
          <Button startIcon={<ExportIcon />}>Export Results</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default BulkOperationsPanel;
