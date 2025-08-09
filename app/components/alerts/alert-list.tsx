/**
 * Alert List Component for iSECTECH Protect
 * AI-powered intelligent alert management with correlation and triage
 */

'use client';

import { useAlertMutations, useAlerts, useAlertSelection } from '@/lib/hooks/use-alerts';
import type { Alert, AlertStatus, ThreatSeverity } from '@/types';
import { getPriorityColor, getSeverityColor } from '@/types';
import {
  PersonAdd as AssignIcon,
  ExpandLess as CollapseIcon,
  Timeline as CorrelationIcon,
  AutoAwesome as EnrichIcon,
  Escalation as EscalateIcon,
  ExpandMore as ExpandIcon,
  Warning as HighPriorityIcon,
  MoreVert as MoreIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  TrendingUp as TrendingIcon,
  Psychology as TriageIcon,
} from '@mui/icons-material';
import {
  alpha,
  Avatar,
  Badge,
  Box,
  Button,
  Card,
  Checkbox,
  Chip,
  CircularProgress,
  Collapse,
  IconButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Alert as MuiAlert,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { formatDistanceToNow } from 'date-fns';
import React, { useMemo, useState } from 'react';
import { AlertBulkActions } from './alert-bulk-actions';
import { AlertCorrelationView } from './alert-correlation-view';

interface AlertListProps {
  filters?: import('@/lib/api/services/alerts').AlertFilters;
  onAlertSelect?: (alert: Alert) => void;
  realTime?: boolean;
  compact?: boolean;
}

export function AlertList({ filters, onAlertSelect, realTime = true, compact = false }: AlertListProps) {
  const theme = useTheme();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const [actionMenuAnchor, setActionMenuAnchor] = useState<{ element: HTMLElement; alertId: string } | null>(null);

  const { alerts, pagination, isLoading, error, refreshAlerts } = useAlerts({
    filters: {
      ...filters,
      // Add pagination to filters
    },
    includeCorrelations: true,
    includeEnrichment: true,
    realTime,
  });

  const mutations = useAlertMutations();
  const selection = useAlertSelection();

  // Calculate derived data
  const displayAlerts = useMemo(() => {
    const start = page * rowsPerPage;
    return alerts.slice(start, start + rowsPerPage);
  }, [alerts, page, rowsPerPage]);

  const alertStats = useMemo(() => {
    const total = alerts.length;
    const critical = alerts.filter((a) => a.priority === 'P1').length;
    const unassigned = alerts.filter((a) => !a.assignedTo).length;
    const overdue = alerts.filter((a) => a.sla.breached).length;

    return { total, critical, unassigned, overdue };
  }, [alerts]);

  const handlePageChange = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleRowsPerPageChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleAlertClick = (alert: Alert) => {
    if (onAlertSelect) {
      onAlertSelect(alert);
    }
  };

  const handleExpandToggle = (alertId: string) => {
    setExpandedAlert(expandedAlert === alertId ? null : alertId);
  };

  const handleActionMenuOpen = (event: React.MouseEvent<HTMLElement>, alertId: string) => {
    event.stopPropagation();
    setActionMenuAnchor({ element: event.currentTarget, alertId });
  };

  const handleActionMenuClose = () => {
    setActionMenuAnchor(null);
  };

  const handleQuickAction = async (action: string, alertId: string) => {
    handleActionMenuClose();

    switch (action) {
      case 'enrich':
        await mutations.enrichAlert.mutateAsync({ id: alertId, forceRefresh: true });
        break;
      case 'triage':
        await mutations.triageAlert.mutateAsync(alertId);
        break;
      case 'escalate':
        await mutations.escalateAlert.mutateAsync({ id: alertId, level: 2, reason: 'Manual escalation' });
        break;
    }
  };

  const getSeverityIcon = (severity: ThreatSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return <HighPriorityIcon sx={{ color: getSeverityColor('CRITICAL'), fontSize: 16 }} />;
      case 'HIGH':
        return <SecurityIcon sx={{ color: getSeverityColor('HIGH'), fontSize: 16 }} />;
      case 'MEDIUM':
        return <SpeedIcon sx={{ color: getSeverityColor('MEDIUM'), fontSize: 16 }} />;
      case 'LOW':
        return <TrendingIcon sx={{ color: getSeverityColor('LOW'), fontSize: 16 }} />;
      default:
        return null;
    }
  };

  const getStatusColor = (status: AlertStatus) => {
    switch (status) {
      case 'OPEN':
        return theme.palette.error.main;
      case 'IN_PROGRESS':
        return theme.palette.warning.main;
      case 'RESOLVED':
        return theme.palette.success.main;
      case 'CLOSED':
        return theme.palette.grey[500];
      case 'FALSE_POSITIVE':
        return theme.palette.grey[400];
      default:
        return theme.palette.text.secondary;
    }
  };

  const renderAlertRow = (alert: Alert) => {
    const isExpanded = expandedAlert === alert.id;
    const isSelected = selection.isSelected(alert.id);
    const hasCorrelations = alert.correlations && alert.correlations.length > 0;

    return (
      <React.Fragment key={alert.id}>
        <TableRow
          hover
          selected={isSelected}
          onClick={() => handleAlertClick(alert)}
          sx={{
            cursor: 'pointer',
            backgroundColor: isSelected ? alpha(theme.palette.primary.main, 0.1) : 'inherit',
            '&:hover': {
              backgroundColor: alpha(theme.palette.primary.main, 0.05),
            },
            borderLeft: alert.sla.breached ? `4px solid ${theme.palette.error.main}` : 'none',
          }}
        >
          <TableCell padding="checkbox">
            <Checkbox
              checked={isSelected}
              onChange={(e) => {
                e.stopPropagation();
                selection.toggleAlert(alert.id);
              }}
            />
          </TableCell>

          <TableCell>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <IconButton
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  handleExpandToggle(alert.id);
                }}
              >
                {isExpanded ? <CollapseIcon /> : <ExpandIcon />}
              </IconButton>

              {hasCorrelations && (
                <Tooltip title={`${alert.correlations?.length || 0} correlations`}>
                  <Badge badgeContent={alert.correlations?.length || 0} color="info">
                    <CorrelationIcon sx={{ fontSize: 16, color: theme.palette.info.main }} />
                  </Badge>
                </Tooltip>
              )}
            </Box>
          </TableCell>

          <TableCell>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {getSeverityIcon(alert.severity)}
              <Chip
                label={alert.priority}
                size="small"
                sx={{
                  backgroundColor: getPriorityColor(alert.priority),
                  color: 'white',
                  fontWeight: 600,
                }}
              />
            </Box>
          </TableCell>

          <TableCell>
            <Box>
              <Typography variant="body2" fontWeight={600} noWrap>
                {alert.title}
              </Typography>
              <Typography variant="caption" color="text.secondary" noWrap>
                {alert.category.replace('_', ' ')} • {alert.id}
              </Typography>
            </Box>
          </TableCell>

          <TableCell>
            <Chip
              label={alert.status.replace('_', ' ')}
              size="small"
              variant="outlined"
              sx={{
                borderColor: getStatusColor(alert.status),
                color: getStatusColor(alert.status),
              }}
            />
          </TableCell>

          <TableCell>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" fontWeight={600}>
                {alert.riskScore}
              </Typography>
              <Box
                sx={{
                  width: 40,
                  height: 4,
                  backgroundColor: theme.palette.grey[300],
                  borderRadius: 2,
                  overflow: 'hidden',
                }}
              >
                <Box
                  sx={{
                    width: `${alert.riskScore}%`,
                    height: '100%',
                    backgroundColor: getSeverityColor(alert.severity),
                  }}
                />
              </Box>
            </Box>
          </TableCell>

          <TableCell>
            {alert.assignedTo ? (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Avatar sx={{ width: 24, height: 24, fontSize: '0.75rem' }}>
                  {alert.assignedTo.charAt(0).toUpperCase()}
                </Avatar>
                <Typography variant="caption">{alert.assignedTo}</Typography>
              </Box>
            ) : (
              <Typography variant="caption" color="text.secondary">
                Unassigned
              </Typography>
            )}
          </TableCell>

          <TableCell>
            <Tooltip title={new Date(alert.createdAt).toLocaleString()}>
              <Typography variant="caption" color="text.secondary">
                {formatDistanceToNow(alert.createdAt, { addSuffix: true })}
              </Typography>
            </Tooltip>
          </TableCell>

          <TableCell>
            {alert.sla.breached ? (
              <Chip label="SLA Breached" size="small" color="error" variant="outlined" />
            ) : (
              <Typography variant="caption" color="text.secondary">
                {alert.sla.timeRemaining ? `${Math.floor(alert.sla.timeRemaining / 60)}h` : '-'}
              </Typography>
            )}
          </TableCell>

          <TableCell padding="none">
            <IconButton size="small" onClick={(e) => handleActionMenuOpen(e, alert.id)}>
              <MoreIcon />
            </IconButton>
          </TableCell>
        </TableRow>

        {/* Expanded Row Content */}
        <TableRow>
          <TableCell sx={{ py: 0 }} colSpan={10}>
            <Collapse in={isExpanded} timeout="auto" unmountOnExit>
              <Box sx={{ p: 2, backgroundColor: alpha(theme.palette.background.paper, 0.5) }}>
                <Typography variant="body2" paragraph>
                  {alert.description}
                </Typography>

                {/* Correlation Information */}
                {hasCorrelations && (
                  <AlertCorrelationView
                    alert={alert}
                    correlations={alert.correlations || []}
                    onMergeAlerts={mutations.mergeAlerts.mutateAsync}
                  />
                )}

                {/* AI Enrichment Data */}
                {alert.enrichment && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      AI Analysis
                    </Typography>
                    <Stack direction="row" spacing={2} flexWrap="wrap">
                      <Chip
                        icon={<SpeedIcon />}
                        label={`Business Impact: ${alert.enrichment.businessImpact.score}%`}
                        size="small"
                        variant="outlined"
                      />
                      {alert.enrichment.contextualData.userBehavior.isAnomalous && (
                        <Chip
                          icon={<HighPriorityIcon />}
                          label="Anomalous Behavior"
                          size="small"
                          color="warning"
                          variant="outlined"
                        />
                      )}
                      <Chip
                        icon={<SecurityIcon />}
                        label={`Asset Criticality: ${alert.enrichment.contextualData.assetCriticality.level}`}
                        size="small"
                        variant="outlined"
                      />
                    </Stack>
                  </Box>
                )}

                {/* MITRE ATT&CK Techniques */}
                {alert.mitreAttackTechniques.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      MITRE ATT&CK Techniques
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      {alert.mitreAttackTechniques.slice(0, 3).map((technique) => (
                        <Chip
                          key={technique.id}
                          label={`${technique.id}: ${technique.name}`}
                          size="small"
                          variant="outlined"
                          sx={{ fontSize: '0.7rem' }}
                        />
                      ))}
                      {alert.mitreAttackTechniques.length > 3 && (
                        <Chip
                          label={`+${alert.mitreAttackTechniques.length - 3} more`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </Stack>
                  </Box>
                )}
              </Box>
            </Collapse>
          </TableCell>
        </TableRow>
      </React.Fragment>
    );
  };

  if (error) {
    return (
      <MuiAlert severity="error" sx={{ mb: 2 }}>
        Failed to load alerts: {error.message}
        <Button onClick={refreshAlerts} startIcon={<RefreshIcon />} sx={{ ml: 2 }}>
          Retry
        </Button>
      </MuiAlert>
    );
  }

  return (
    <Box>
      {/* Alert Statistics */}
      <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
        <Chip icon={<SecurityIcon />} label={`${alertStats.total} Total`} variant="outlined" />
        <Chip
          icon={<HighPriorityIcon />}
          label={`${alertStats.critical} Critical`}
          color={alertStats.critical > 0 ? 'error' : 'default'}
          variant="outlined"
        />
        <Chip
          icon={<AssignIcon />}
          label={`${alertStats.unassigned} Unassigned`}
          color={alertStats.unassigned > 0 ? 'warning' : 'default'}
          variant="outlined"
        />
        <Chip
          icon={<HighPriorityIcon />}
          label={`${alertStats.overdue} SLA Breached`}
          color={alertStats.overdue > 0 ? 'error' : 'default'}
          variant="outlined"
        />
      </Stack>

      {/* Bulk Actions */}
      {selection.selectedCount > 0 && (
        <AlertBulkActions
          selectedAlerts={selection.selectedAlerts}
          onClearSelection={selection.clearSelection}
          onStatusUpdate={mutations.updateStatus.mutateAsync}
          onBulkUpdate={mutations.bulkUpdate.mutateAsync}
          onMerge={mutations.mergeAlerts.mutateAsync}
          onSuppress={mutations.suppressAlerts.mutateAsync}
        />
      )}

      {/* Alert Table */}
      <Card>
        <TableContainer>
          <Table stickyHeader size={compact ? 'small' : 'medium'}>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    indeterminate={selection.selectedCount > 0 && selection.selectedCount < alerts.length}
                    checked={alerts.length > 0 && selection.selectedCount === alerts.length}
                    onChange={(e) => {
                      if (e.target.checked) {
                        selection.selectAll(alerts.map((a) => a.id));
                      } else {
                        selection.clearSelection();
                      }
                    }}
                  />
                </TableCell>
                <TableCell width={80}></TableCell>
                <TableCell>Priority</TableCell>
                <TableCell>Alert</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Risk Score</TableCell>
                <TableCell>Assigned To</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>SLA</TableCell>
                <TableCell width={50}></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={10} align="center" sx={{ py: 4 }}>
                    <CircularProgress />
                  </TableCell>
                </TableRow>
              ) : displayAlerts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">No alerts found matching your criteria</Typography>
                  </TableCell>
                </TableRow>
              ) : (
                displayAlerts.map(renderAlertRow)
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Pagination */}
        <TablePagination
          component="div"
          count={alerts.length}
          page={page}
          onPageChange={handlePageChange}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={handleRowsPerPageChange}
          rowsPerPageOptions={[10, 25, 50, 100]}
        />
      </Card>

      {/* Action Menu */}
      <Menu anchorEl={actionMenuAnchor?.element} open={Boolean(actionMenuAnchor)} onClose={handleActionMenuClose}>
        <MenuItem onClick={() => handleQuickAction('enrich', actionMenuAnchor!.alertId)}>
          <ListItemIcon>
            <EnrichIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Enrich with AI</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleQuickAction('triage', actionMenuAnchor!.alertId)}>
          <ListItemIcon>
            <TriageIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>AI Triage</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleQuickAction('escalate', actionMenuAnchor!.alertId)}>
          <ListItemIcon>
            <EscalateIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Escalate</ListItemText>
        </MenuItem>
      </Menu>
    </Box>
  );
}

export default AlertList;
