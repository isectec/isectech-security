'use client';

/**
 * White-Label Approval Workflow Management Page
 * Interface for managing preview environments and approval workflows
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
  Avatar,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondary,
  Divider,
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent,
  Stepper,
  Step,
  StepLabel,
  Badge,
  Tooltip,
  Menu,
  MenuItem as MenuItemComponent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  ButtonGroup,
  Rating,
  LinearProgress,
} from '@mui/material';
import {
  Preview as PreviewIcon,
  Check as ApproveIcon,
  Close as RejectIcon,
  Comment as CommentIcon,
  History as HistoryIcon,
  Visibility as ViewIcon,
  Launch as LaunchIcon,
  Schedule as ScheduleIcon,
  Priority as PriorityIcon,
  Person as PersonIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  Compare as CompareIcon,
  Send as SendIcon,
  Add as AddIcon,
  ExpandMore as ExpandMoreIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Refresh as RefreshIcon,
  NotificationsActive as NotificationIcon,
  Screenshot as ScreenshotIcon,
  Device as DeviceIcon,
} from '@mui/icons-material';

import { approvalWorkflowManager } from '@/lib/white-labeling/approval-workflow';
import type {
  ApprovalWorkflow,
  ApprovalDecision,
  ApprovalComment,
  ApprovalStatus,
  PreviewEnvironment,
  ComparisonResult,
  ConfigurationChange,
} from '@/lib/white-labeling/approval-workflow';

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

export default function ApprovalWorkflowPage() {
  const [tabValue, setTabValue] = useState(0);
  const [workflows, setWorkflows] = useState<ApprovalWorkflow[]>([]);
  const [previews, setPreviews] = useState<PreviewEnvironment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dialog states
  const [approvalDialog, setApprovalDialog] = useState(false);
  const [commentDialog, setCommentDialog] = useState(false);
  const [comparisonDialog, setComparisonDialog] = useState(false);
  const [previewDialog, setPreviewDialog] = useState(false);

  // Selected items
  const [selectedWorkflow, setSelectedWorkflow] = useState<ApprovalWorkflow | null>(null);
  const [selectedPreview, setSelectedPreview] = useState<PreviewEnvironment | null>(null);
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);

  // Form states
  const [approvalForm, setApprovalForm] = useState({
    decision: 'APPROVED' as ApprovalDecision['decision'],
    comment: '',
    conditions: [] as string[],
  });
  
  const [commentForm, setCommentForm] = useState({
    comment: '',
    isInternal: false,
    mentions: [] as string[],
  });

  const tenantId = 'demo-tenant'; // Would get from auth context
  const userId = 'demo-user'; // Would get from auth context
  const userEmail = 'user@isectech.com'; // Would get from auth context

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Mock data - would fetch from actual APIs
      const mockWorkflows: ApprovalWorkflow[] = [
        {
          id: 'workflow-1',
          configurationId: 'config-1',
          initiatedBy: 'user-1',
          initiatedByEmail: 'designer@client.com',
          currentStep: 'INITIAL_REVIEW',
          status: 'PENDING',
          requiredApprovers: [
            {
              userId: 'approver-1',
              userEmail: 'brand.admin@isectech.com',
              role: 'Brand Administrator',
              required: true,
              notified: true,
              notifiedAt: new Date(),
            },
            {
              userId: 'approver-2',
              userEmail: 'security.admin@isectech.com',
              role: 'Security Administrator',
              required: true,
              notified: true,
              notifiedAt: new Date(),
            },
          ],
          currentApprovers: [],
          completedApprovals: [],
          comments: [
            {
              id: 'comment-1',
              userId: 'user-1',
              userEmail: 'designer@client.com',
              comment: 'Updated brand colors to match new corporate identity. Please review the color contrast ratios.',
              timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
              isInternal: false,
            },
          ],
          priority: 'HIGH',
          changesSummary: 'Brand color scheme update and logo replacement',
          tenantId,
          createdAt: new Date(Date.now() - 3 * 60 * 60 * 1000),
          updatedAt: new Date(Date.now() - 1 * 60 * 60 * 1000),
        },
      ];

      const mockPreviews: PreviewEnvironment[] = [
        {
          id: 'preview-1',
          configurationId: 'config-1',
          previewUrl: 'https://preview.isectech.com/preview-1',
          status: 'READY',
          screenshots: {
            desktop: '/screenshots/desktop-1.png',
            tablet: '/screenshots/tablet-1.png',
            mobile: '/screenshots/mobile-1.png',
          },
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
          createdBy: userId,
          tenantId,
          createdAt: new Date(Date.now() - 30 * 60 * 1000),
        },
      ];

      setWorkflows(mockWorkflows);
      setPreviews(mockPreviews);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitApproval = async () => {
    if (!selectedWorkflow) return;

    try {
      await approvalWorkflowManager.submitApproval(
        selectedWorkflow.id,
        userId,
        userEmail,
        approvalForm.decision,
        approvalForm.comment,
        approvalForm.conditions
      );
      
      setApprovalDialog(false);
      setApprovalForm({ decision: 'APPROVED', comment: '', conditions: [] });
      await loadData();
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit approval');
    }
  };

  const handleAddComment = async () => {
    if (!selectedWorkflow) return;

    try {
      await approvalWorkflowManager.addComment(
        selectedWorkflow.id,
        userId,
        userEmail,
        commentForm.comment,
        {
          isInternal: commentForm.isInternal,
          mentions: commentForm.mentions,
        }
      );
      
      setCommentDialog(false);
      setCommentForm({ comment: '', isInternal: false, mentions: [] });
      await loadData();
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add comment');
    }
  };

  const handleGenerateComparison = async (configurationId: string) => {
    try {
      const comparisonResult = await approvalWorkflowManager.generateComparison(
        configurationId,
        tenantId
      );
      setComparison(comparisonResult);
      setComparisonDialog(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate comparison');
    }
  };

  const handleCreatePreview = async (configurationId: string) => {
    try {
      const preview = await approvalWorkflowManager.createPreview(
        configurationId,
        tenantId,
        userId,
        {
          includeScreenshots: true,
          devices: ['desktop', 'tablet', 'mobile'],
        }
      );
      
      setPreviews([...previews, preview]);
      setSelectedPreview(preview);
      setPreviewDialog(true);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create preview');
    }
  };

  const getStatusColor = (status: ApprovalStatus) => {
    switch (status) {
      case 'APPROVED': return 'success';
      case 'REJECTED': return 'error';
      case 'CANCELLED': return 'secondary';
      case 'IN_REVIEW': return 'warning';
      case 'PENDING': return 'info';
      default: return 'default';
    }
  };

  const getPriorityColor = (priority: ApprovalWorkflow['priority']) => {
    switch (priority) {
      case 'URGENT': return 'error';
      case 'HIGH': return 'warning';
      case 'MEDIUM': return 'info';
      case 'LOW': return 'default';
      default: return 'default';
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'warning';
      case 'MEDIUM': return 'info';
      case 'LOW': return 'success';
      default: return 'default';
    }
  };

  const renderWorkflowCard = (workflow: ApprovalWorkflow) => (
    <Grid item xs={12} lg={6} key={workflow.id}>
      <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <CardContent sx={{ flexGrow: 1 }}>
          <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
            <Box>
              <Typography variant="h6" gutterBottom>
                {workflow.changesSummary}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Initiated by: {workflow.initiatedByEmail}
              </Typography>
            </Box>
            <Box display="flex" gap={1}>
              <Chip
                label={workflow.status}
                color={getStatusColor(workflow.status) as any}
                size="small"
              />
              <Chip
                label={workflow.priority}
                color={getPriorityColor(workflow.priority) as any}
                size="small"
              />
            </Box>
          </Box>

          <Box mb={2}>
            <Typography variant="subtitle2" gutterBottom>
              Progress: {workflow.currentStep.replace('_', ' ')}
            </Typography>
            <LinearProgress
              variant="determinate"
              value={
                workflow.currentStep === 'INITIAL_REVIEW' ? 25 :
                workflow.currentStep === 'SECURITY_REVIEW' ? 50 :
                workflow.currentStep === 'FINAL_APPROVAL' ? 75 : 100
              }
              sx={{ mb: 1 }}
            />
          </Box>

          <Box mb={2}>
            <Typography variant="subtitle2" gutterBottom>
              Approvers ({workflow.completedApprovals.length}/{workflow.requiredApprovers.length})
            </Typography>
            <Box display="flex" flexWrap="wrap" gap={1}>
              {workflow.requiredApprovers.map(approver => {
                const hasApproved = workflow.completedApprovals.some(a => a.userId === approver.userId);
                return (
                  <Tooltip key={approver.userId} title={`${approver.userEmail} - ${approver.role}`}>
                    <Avatar
                      sx={{
                        width: 32,
                        height: 32,
                        bgcolor: hasApproved ? 'success.main' : 'grey.300',
                        fontSize: '0.875rem',
                      }}
                    >
                      {approver.userEmail[0].toUpperCase()}
                    </Avatar>
                  </Tooltip>
                );
              })}
            </Box>
          </Box>

          <Box display="flex" alignItems="center" gap={2}>
            <Typography variant="caption" color="text.secondary">
              Created: {workflow.createdAt.toLocaleDateString()}
            </Typography>
            {workflow.comments.length > 0 && (
              <Badge badgeContent={workflow.comments.length} color="primary">
                <CommentIcon fontSize="small" />
              </Badge>
            )}
          </Box>
        </CardContent>

        <CardActions sx={{ justifyContent: 'space-between' }}>
          <Box display="flex" gap={1}>
            <Button
              size="small"
              startIcon={<CompareIcon />}
              onClick={() => handleGenerateComparison(workflow.configurationId)}
            >
              Compare
            </Button>
            <Button
              size="small"
              startIcon={<PreviewIcon />}
              onClick={() => handleCreatePreview(workflow.configurationId)}
            >
              Preview
            </Button>
          </Box>

          {workflow.status === 'PENDING' || workflow.status === 'IN_REVIEW' ? (
            <ButtonGroup size="small">
              <Button
                color="success"
                startIcon={<ApproveIcon />}
                onClick={() => {
                  setSelectedWorkflow(workflow);
                  setApprovalForm({ ...approvalForm, decision: 'APPROVED' });
                  setApprovalDialog(true);
                }}
              >
                Approve
              </Button>
              <Button
                color="error"
                startIcon={<RejectIcon />}
                onClick={() => {
                  setSelectedWorkflow(workflow);
                  setApprovalForm({ ...approvalForm, decision: 'REJECTED' });
                  setApprovalDialog(true);
                }}
              >
                Reject
              </Button>
              <Button
                startIcon={<CommentIcon />}
                onClick={() => {
                  setSelectedWorkflow(workflow);
                  setCommentDialog(true);
                }}
              >
                Comment
              </Button>
            </ButtonGroup>
          ) : (
            <Button
              size="small"
              startIcon={<HistoryIcon />}
              onClick={() => {
                setSelectedWorkflow(workflow);
                // Open workflow history dialog
              }}
            >
              View History
            </Button>
          )}
        </CardActions>
      </Card>
    </Grid>
  );

  const renderPreviewCard = (preview: PreviewEnvironment) => (
    <Grid item xs={12} md={6} lg={4} key={preview.id}>
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
            <Typography variant="h6">
              Preview Environment
            </Typography>
            <Chip
              label={preview.status}
              color={preview.status === 'READY' ? 'success' : 'default'}
              size="small"
            />
          </Box>

          <Typography variant="body2" color="text.secondary" gutterBottom>
            Configuration: {preview.configurationId}
          </Typography>

          {preview.screenshots && (
            <Box mb={2}>
              <Typography variant="subtitle2" gutterBottom>
                Screenshots:
              </Typography>
              <Box display="flex" gap={1}>
                {Object.entries(preview.screenshots).map(([device, url]) => (
                  url && (
                    <Tooltip key={device} title={`${device} preview`}>
                      <Box
                        component="img"
                        src={url}
                        alt={`${device} preview`}
                        sx={{
                          width: 60,
                          height: 40,
                          objectFit: 'cover',
                          borderRadius: 1,
                          border: '1px solid #ccc',
                          cursor: 'pointer',
                        }}
                        onClick={() => window.open(url, '_blank')}
                      />
                    </Tooltip>
                  )
                ))}
              </Box>
            </Box>
          )}

          <Typography variant="caption" color="text.secondary" display="block">
            Expires: {preview.expiresAt.toLocaleString()}
          </Typography>
        </CardContent>

        <CardActions>
          <Button
            size="small"
            startIcon={<LaunchIcon />}
            onClick={() => window.open(preview.previewUrl, '_blank')}
            disabled={preview.status !== 'READY'}
          >
            Open Preview
          </Button>
          <Button
            size="small"
            startIcon={<ScreenshotIcon />}
            onClick={() => {
              setSelectedPreview(preview);
              setPreviewDialog(true);
            }}
          >
            Screenshots
          </Button>
        </CardActions>
      </Card>
    </Grid>
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
            Preview & Approval Workflows
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage approval workflows and preview environments for white-label configurations.
          </Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadData}
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)} sx={{ mb: 3 }}>
        <Tab icon={<AssessmentIcon />} label="Approval Workflows" />
        <Tab icon={<PreviewIcon />} label="Preview Environments" />
        <Tab icon={<HistoryIcon />} label="Workflow History" />
      </Tabs>

      {/* Approval Workflows Tab */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          {workflows.map(workflow => renderWorkflowCard(workflow))}
          {workflows.length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 6 }}>
                  <AssessmentIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No Active Workflows
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Approval workflows will appear here when configuration changes are submitted for review.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* Preview Environments Tab */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          {previews.map(preview => renderPreviewCard(preview))}
          {previews.length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 6 }}>
                  <PreviewIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No Preview Environments
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Create preview environments to test white-label configurations before deployment.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* Workflow History Tab */}
      <TabPanel value={tabValue} index={2}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Workflow History
            </Typography>
            <Alert severity="info">
              Historical workflow data and analytics would be displayed here, including
              approval times, rejection rates, and workflow performance metrics.
            </Alert>
          </CardContent>
        </Card>
      </TabPanel>

      {/* Approval Dialog */}
      <Dialog open={approvalDialog} onClose={() => setApprovalDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Submit Approval Decision
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Decision</InputLabel>
              <Select
                value={approvalForm.decision}
                onChange={(e) => setApprovalForm({ ...approvalForm, decision: e.target.value as ApprovalDecision['decision'] })}
                label="Decision"
              >
                <MenuItem value="APPROVED">Approve</MenuItem>
                <MenuItem value="REJECTED">Reject</MenuItem>
                <MenuItem value="NEEDS_CHANGES">Needs Changes</MenuItem>
              </Select>
            </FormControl>

            <TextField
              fullWidth
              multiline
              rows={4}
              label="Comment"
              value={approvalForm.comment}
              onChange={(e) => setApprovalForm({ ...approvalForm, comment: e.target.value })}
              placeholder="Provide feedback or explain your decision..."
              sx={{ mb: 2 }}
            />

            {approvalForm.decision === 'APPROVED' && (
              <TextField
                fullWidth
                multiline
                rows={2}
                label="Approval Conditions (Optional)"
                placeholder="Any conditions or requirements for this approval..."
                sx={{ mb: 2 }}
              />
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApprovalDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSubmitApproval}
            color={approvalForm.decision === 'APPROVED' ? 'success' : 'error'}
          >
            Submit {approvalForm.decision.toLowerCase().replace('_', ' ')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Comment Dialog */}
      <Dialog open={commentDialog} onClose={() => setCommentDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add Comment</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            multiline
            rows={4}
            label="Comment"
            value={commentForm.comment}
            onChange={(e) => setCommentForm({ ...commentForm, comment: e.target.value })}
            placeholder="Add your comment..."
            sx={{ mt: 2, mb: 2 }}
          />
          
          <FormControl>
            <label>
              <input
                type="checkbox"
                checked={commentForm.isInternal}
                onChange={(e) => setCommentForm({ ...commentForm, isInternal: e.target.checked })}
              />
              Internal comment (not visible to requestor)
            </label>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCommentDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAddComment}
            disabled={!commentForm.comment}
          >
            Add Comment
          </Button>
        </DialogActions>
      </Dialog>

      {/* Configuration Comparison Dialog */}
      <Dialog open={comparisonDialog} onClose={() => setComparisonDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Configuration Comparison</DialogTitle>
        <DialogContent>
          {comparison && (
            <Box>
              <Alert 
                severity={
                  comparison.riskAssessment.level === 'CRITICAL' ? 'error' :
                  comparison.riskAssessment.level === 'HIGH' ? 'warning' :
                  comparison.riskAssessment.level === 'MEDIUM' ? 'info' : 'success'
                }
                sx={{ mb: 2 }}
              >
                Risk Level: {comparison.riskAssessment.level} (Score: {comparison.riskAssessment.score})
                <br />
                Factors: {comparison.riskAssessment.factors.join(', ')}
              </Alert>

              <Typography variant="h6" gutterBottom>
                Changes ({comparison.changes.length}):
              </Typography>
              
              <List>
                {comparison.changes.map((change, index) => (
                  <ListItem key={index}>
                    <ListItemAvatar>
                      <Avatar sx={{ bgcolor: getRiskColor(change.impact) as any }}>
                        {change.type === 'ADDED' ? '+' : change.type === 'REMOVED' ? '-' : '~'}
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={change.description}
                      secondary={`${change.category} - ${change.impact} Impact`}
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setComparisonDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Preview Screenshots Dialog */}
      <Dialog open={previewDialog} onClose={() => setPreviewDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Preview Screenshots</DialogTitle>
        <DialogContent>
          {selectedPreview && selectedPreview.screenshots && (
            <Grid container spacing={2}>
              {Object.entries(selectedPreview.screenshots).map(([device, url]) => (
                url && (
                  <Grid item xs={12} md={4} key={device}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ textTransform: 'capitalize' }}>
                          {device}
                        </Typography>
                        <Box
                          component="img"
                          src={url}
                          alt={`${device} preview`}
                          sx={{
                            width: '100%',
                            height: 'auto',
                            borderRadius: 1,
                            border: '1px solid #ccc',
                          }}
                        />
                      </CardContent>
                      <CardActions>
                        <Button
                          size="small"
                          startIcon={<LaunchIcon />}
                          onClick={() => window.open(url, '_blank')}
                        >
                          Open Full Size
                        </Button>
                      </CardActions>
                    </Card>
                  </Grid>
                )
              ))}
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPreviewDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}