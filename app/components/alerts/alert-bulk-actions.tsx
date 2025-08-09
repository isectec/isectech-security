/**
 * Alert Bulk Actions Component for iSECTECH Protect
 * Bulk operations toolbar for efficient alert management
 */

'use client';

import { useAlertExport } from '@/lib/hooks/use-alerts';
import type { AlertStatus, Alert as AlertType } from '@/types';
import {
  Person as AssignIcon,
  Close as CloseIcon,
  Delete as DeleteIcon,
  AutoAwesome as EnrichIcon,
  Escalation as EscalateIcon,
  Download as ExportIcon,
  Merge as MergeIcon,
  Security as SecurityIcon,
  ChangeCircle as StatusIcon,
  VisibilityOff as SuppressIcon,
  Psychology as TriageIcon,
} from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Fade,
  FormControl,
  IconButton,
  InputLabel,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import { useState } from 'react';

interface AlertBulkActionsProps {
  selectedAlerts: string[];
  onClearSelection: () => void;
  onStatusUpdate: (params: { alertIds: string[]; status: AlertStatus; comment?: string }) => Promise<void>;
  onBulkUpdate: (params: { alertIds: string[]; updates: Partial<AlertType> }) => Promise<void>;
  onMerge: (params: { primaryId: string; duplicateIds: string[]; reason: string }) => Promise<void>;
  onSuppress: (params: { alertIds: string[]; duration: number; reason: string }) => Promise<void>;
}

type ActionType =
  | 'assign'
  | 'status'
  | 'escalate'
  | 'merge'
  | 'suppress'
  | 'export'
  | 'delete'
  | 'tag'
  | 'enrich'
  | 'triage';

interface ActionDialogState {
  type: ActionType | null;
  open: boolean;
  data?: any;
}

const statusOptions: { value: AlertStatus; label: string; description: string }[] = [
  { value: 'OPEN', label: 'Open', description: 'Mark alerts as open for investigation' },
  { value: 'IN_PROGRESS', label: 'In Progress', description: 'Mark alerts as currently being investigated' },
  { value: 'RESOLVED', label: 'Resolved', description: 'Mark alerts as resolved' },
  { value: 'CLOSED', label: 'Closed', description: 'Close resolved alerts' },
  { value: 'FALSE_POSITIVE', label: 'False Positive', description: 'Mark alerts as false positives' },
];

const suppressionDurations = [
  { value: 1, label: '1 hour' },
  { value: 4, label: '4 hours' },
  { value: 24, label: '1 day' },
  { value: 168, label: '1 week' },
  { value: 720, label: '1 month' },
];

// Mock assignee options - in real app, this would come from API
const assigneeOptions = [
  'alice.johnson@isectech.com',
  'bob.smith@isectech.com',
  'carol.chen@isectech.com',
  'david.wilson@isectech.com',
  'eve.brown@isectech.com',
];

export function AlertBulkActions({
  selectedAlerts,
  onClearSelection,
  onStatusUpdate,
  onBulkUpdate,
  onMerge,
  onSuppress,
}: AlertBulkActionsProps) {
  const theme = useTheme();
  const [actionDialog, setActionDialog] = useState<ActionDialogState>({ type: null, open: false });
  const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null);
  const [loading, setLoading] = useState(false);
  const exportMutation = useAlertExport();

  const handleActionClick = (type: ActionType) => {
    setMenuAnchor(null);
    setActionDialog({ type, open: true });
  };

  const handleDialogClose = () => {
    setActionDialog({ type: null, open: false });
  };

  const handleStatusUpdate = async (status: AlertStatus, comment?: string) => {
    setLoading(true);
    try {
      await onStatusUpdate({ alertIds: selectedAlerts, status, comment });
      handleDialogClose();
      onClearSelection();
    } catch (error) {
      console.error('Failed to update status:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAssignment = async (assigneeId: string, comment?: string) => {
    setLoading(true);
    try {
      await onBulkUpdate({
        alertIds: selectedAlerts,
        updates: { assignedTo: assigneeId },
      });
      handleDialogClose();
      onClearSelection();
    } catch (error) {
      console.error('Failed to assign alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSuppression = async (duration: number, reason: string) => {
    setLoading(true);
    try {
      await onSuppress({ alertIds: selectedAlerts, duration, reason });
      handleDialogClose();
      onClearSelection();
    } catch (error) {
      console.error('Failed to suppress alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: 'csv' | 'excel' | 'pdf' | 'json') => {
    setLoading(true);
    try {
      await exportMutation.mutateAsync({
        filters: {
          /* filter by selected alert IDs */
        },
        format,
        includeDetails: true,
      });
      handleDialogClose();
    } catch (error) {
      console.error('Failed to export alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const renderStatusDialog = () => (
    <Dialog
      open={actionDialog.type === 'status' && actionDialog.open}
      onClose={handleDialogClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Update Alert Status</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          <Alert severity="info" sx={{ mb: 2 }}>
            This will update the status of {selectedAlerts.length} selected alert{selectedAlerts.length > 1 ? 's' : ''}.
          </Alert>

          {statusOptions.map((option) => (
            <Card
              key={option.value}
              variant="outlined"
              sx={{
                mb: 1,
                cursor: 'pointer',
                '&:hover': { backgroundColor: 'action.hover' },
              }}
              onClick={() => handleStatusUpdate(option.value)}
            >
              <CardContent sx={{ py: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <StatusIcon color="primary" />
                  <Box>
                    <Typography variant="subtitle2">{option.label}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {option.description}
                    </Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          ))}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleDialogClose} disabled={loading}>
          Cancel
        </Button>
      </DialogActions>
    </Dialog>
  );

  const renderAssignDialog = () => (
    <Dialog
      open={actionDialog.type === 'assign' && actionDialog.open}
      onClose={handleDialogClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Assign Alerts</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          <Alert severity="info" sx={{ mb: 2 }}>
            Assign {selectedAlerts.length} selected alert{selectedAlerts.length > 1 ? 's' : ''} to an analyst.
          </Alert>

          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>Assignee</InputLabel>
            <Select value="" label="Assignee" onChange={(e) => handleAssignment(e.target.value)}>
              {assigneeOptions.map((assignee) => (
                <MenuItem key={assignee} value={assignee}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <AssignIcon sx={{ fontSize: 16 }} />
                    {assignee}
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <TextField
            fullWidth
            label="Assignment Comment (Optional)"
            multiline
            rows={3}
            placeholder="Add any relevant context for the assignee..."
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleDialogClose} disabled={loading}>
          Cancel
        </Button>
        <Button variant="contained" disabled={loading}>
          {loading ? <CircularProgress size={20} /> : 'Assign'}
        </Button>
      </DialogActions>
    </Dialog>
  );

  const renderSuppressDialog = () => (
    <Dialog
      open={actionDialog.type === 'suppress' && actionDialog.open}
      onClose={handleDialogClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SuppressIcon />
          Suppress Alerts
        </Box>
      </DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          <Alert severity="warning" sx={{ mb: 2 }}>
            This will suppress {selectedAlerts.length} alert{selectedAlerts.length > 1 ? 's' : ''} for the specified
            duration. Suppressed alerts will not generate new notifications.
          </Alert>

          <Typography variant="subtitle2" gutterBottom>
            Suppression Duration
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mb: 2 }}>
            {suppressionDurations.map((duration) => (
              <Chip
                key={duration.value}
                label={duration.label}
                onClick={() => handleSuppression(duration.value, 'Bulk suppression')}
                clickable
                variant="outlined"
              />
            ))}
          </Stack>

          <TextField
            fullWidth
            label="Suppression Reason"
            multiline
            rows={3}
            placeholder="Explain why these alerts are being suppressed..."
            required
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleDialogClose} disabled={loading}>
          Cancel
        </Button>
        <Button variant="contained" color="warning" disabled={loading}>
          {loading ? <CircularProgress size={20} /> : 'Suppress'}
        </Button>
      </DialogActions>
    </Dialog>
  );

  const renderExportDialog = () => (
    <Dialog
      open={actionDialog.type === 'export' && actionDialog.open}
      onClose={handleDialogClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Export Selected Alerts</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Export {selectedAlerts.length} selected alert{selectedAlerts.length > 1 ? 's' : ''} in your preferred
            format.
          </Typography>

          <Typography variant="subtitle2" gutterBottom>
            Export Format
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={() => handleExport('csv')}
              disabled={loading}
            >
              CSV
            </Button>
            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={() => handleExport('excel')}
              disabled={loading}
            >
              Excel
            </Button>
            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={() => handleExport('pdf')}
              disabled={loading}
            >
              PDF Report
            </Button>
            <Button
              variant="outlined"
              startIcon={<ExportIcon />}
              onClick={() => handleExport('json')}
              disabled={loading}
            >
              JSON
            </Button>
          </Stack>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleDialogClose} disabled={loading}>
          Cancel
        </Button>
      </DialogActions>
    </Dialog>
  );

  return (
    <>
      <Fade in={selectedAlerts.length > 0}>
        <Card
          sx={{
            mb: 2,
            backgroundColor: alpha(theme.palette.primary.main, 0.05),
            border: `1px solid ${theme.palette.primary.main}`,
          }}
        >
          <CardContent sx={{ py: 1.5 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <SecurityIcon color="primary" />
                <Typography variant="subtitle1" fontWeight={600}>
                  {selectedAlerts.length} alert{selectedAlerts.length > 1 ? 's' : ''} selected
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {/* Quick Actions */}
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<StatusIcon />}
                  onClick={() => handleActionClick('status')}
                >
                  Update Status
                </Button>

                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<AssignIcon />}
                  onClick={() => handleActionClick('assign')}
                >
                  Assign
                </Button>

                {/* More Actions Menu */}
                <Button size="small" variant="outlined" onClick={(e) => setMenuAnchor(e.currentTarget)}>
                  More Actions
                </Button>

                <IconButton size="small" onClick={onClearSelection}>
                  <CloseIcon />
                </IconButton>
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Fade>

      {/* More Actions Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={() => setMenuAnchor(null)}
        PaperProps={{ sx: { minWidth: 200 } }}
      >
        <MenuItem onClick={() => handleActionClick('enrich')}>
          <ListItemIcon>
            <EnrichIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>AI Enrich</ListItemText>
        </MenuItem>

        <MenuItem onClick={() => handleActionClick('triage')}>
          <ListItemIcon>
            <TriageIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>AI Triage</ListItemText>
        </MenuItem>

        <Divider />

        <MenuItem onClick={() => handleActionClick('escalate')}>
          <ListItemIcon>
            <EscalateIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Escalate</ListItemText>
        </MenuItem>

        <MenuItem onClick={() => handleActionClick('merge')}>
          <ListItemIcon>
            <MergeIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Merge Duplicates</ListItemText>
        </MenuItem>

        <MenuItem onClick={() => handleActionClick('suppress')}>
          <ListItemIcon>
            <SuppressIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Suppress</ListItemText>
        </MenuItem>

        <Divider />

        <MenuItem onClick={() => handleActionClick('export')}>
          <ListItemIcon>
            <ExportIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export</ListItemText>
        </MenuItem>

        <MenuItem onClick={() => handleActionClick('delete')} sx={{ color: 'error.main' }}>
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>Delete</ListItemText>
        </MenuItem>
      </Menu>

      {/* Action Dialogs */}
      {renderStatusDialog()}
      {renderAssignDialog()}
      {renderSuppressDialog()}
      {renderExportDialog()}
    </>
  );
}

export default AlertBulkActions;
