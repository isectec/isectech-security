/**
 * Alert Correlation View Component for iSECTECH Protect
 * AI-powered alert correlation and relationship visualization
 */

'use client';

import type { Alert, AlertCorrelation } from '@/lib/api/services/alerts';
import { getPriorityColor } from '@/types';
import {
  Psychology as AIIcon,
  CheckCircle as CheckIcon,
  ExpandLess as CollapseIcon,
  ExpandMore as ExpandIcon,
  Info as InfoIcon,
  Link as LinkIcon,
  Merge as MergeIcon,
  Security as SecurityIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendIcon,
} from '@mui/icons-material';
import {
  alpha,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Chip,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert as MuiAlert,
  Stack,
  TextField,
  Typography,
  useTheme,
} from '@mui/material';
import { formatDistanceToNow } from 'date-fns';
import { useState } from 'react';

interface AlertCorrelationViewProps {
  alert: Alert;
  correlations: AlertCorrelation[];
  onMergeAlerts: (params: { primaryId: string; duplicateIds: string[]; reason: string }) => Promise<void>;
  onLinkAlerts?: (alertIds: string[], linkType: string) => Promise<void>;
  compact?: boolean;
}

interface MergeDialogState {
  open: boolean;
  correlation?: AlertCorrelation;
}

const correlationTypeColors = {
  DUPLICATE: '#f44336',
  RELATED: '#ff9800',
  CHAIN: '#2196f3',
  CAMPAIGN: '#9c27b0',
};

const correlationTypeIcons = {
  DUPLICATE: MergeIcon,
  RELATED: LinkIcon,
  CHAIN: TimelineIcon,
  CAMPAIGN: SecurityIcon,
};

const correlationDescriptions = {
  DUPLICATE: 'Identical or near-identical alerts that should be merged',
  RELATED: 'Related alerts sharing common indicators or patterns',
  CHAIN: 'Sequential alerts forming an attack chain',
  CAMPAIGN: 'Alerts that are part of a coordinated campaign',
};

export function AlertCorrelationView({
  alert,
  correlations,
  onMergeAlerts,
  onLinkAlerts,
  compact = false,
}: AlertCorrelationViewProps) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(!compact);
  const [mergeDialog, setMergeDialog] = useState<MergeDialogState>({ open: false });
  const [mergeReason, setMergeReason] = useState('');

  const handleMergeClick = (correlation: AlertCorrelation) => {
    setMergeDialog({ open: true, correlation });
    setMergeReason(`Merging duplicate alerts detected by AI with ${correlation.confidence}% confidence`);
  };

  const handleMergeConfirm = async () => {
    if (mergeDialog.correlation) {
      const duplicateIds = mergeDialog.correlation.relatedAlerts.map((a) => a.id);
      await onMergeAlerts({
        primaryId: alert.id,
        duplicateIds,
        reason: mergeReason,
      });
      setMergeDialog({ open: false });
    }
  };

  const getCorrelationIcon = (type: AlertCorrelation['type']) => {
    const IconComponent = correlationTypeIcons[type];
    return <IconComponent sx={{ color: correlationTypeColors[type], fontSize: 20 }} />;
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return theme.palette.success.main;
    if (confidence >= 70) return theme.palette.warning.main;
    return theme.palette.error.main;
  };

  const renderCorrelationCard = (correlation: AlertCorrelation) => {
    const shouldAutoMerge = correlation.type === 'DUPLICATE' && correlation.confidence >= 95;

    return (
      <Card
        key={correlation.id}
        variant="outlined"
        sx={{
          mb: 1,
          border: `2px solid ${correlationTypeColors[correlation.type]}`,
          backgroundColor: alpha(correlationTypeColors[correlation.type], 0.05),
        }}
      >
        <CardHeader
          avatar={
            <Badge
              badgeContent={correlation.relatedAlerts.length}
              color="primary"
              anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            >
              {getCorrelationIcon(correlation.type)}
            </Badge>
          }
          title={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="subtitle2" fontWeight={600}>
                {correlation.type.replace('_', ' ')} Correlation
              </Typography>
              <Chip
                label={`${correlation.confidence}% confidence`}
                size="small"
                sx={{
                  backgroundColor: getConfidenceColor(correlation.confidence),
                  color: 'white',
                  fontWeight: 600,
                }}
              />
            </Box>
          }
          subheader={correlationDescriptions[correlation.type]}
          action={
            <Box sx={{ display: 'flex', gap: 1 }}>
              {correlation.suggestedAction === 'MERGE' && (
                <Button
                  size="small"
                  variant={shouldAutoMerge ? 'contained' : 'outlined'}
                  color={shouldAutoMerge ? 'error' : 'primary'}
                  startIcon={<MergeIcon />}
                  onClick={() => handleMergeClick(correlation)}
                >
                  {shouldAutoMerge ? 'Auto-Merge' : 'Merge'}
                </Button>
              )}
              {correlation.suggestedAction === 'LINK' && onLinkAlerts && (
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<LinkIcon />}
                  onClick={() =>
                    onLinkAlerts([alert.id, ...correlation.relatedAlerts.map((a) => a.id)], correlation.type)
                  }
                >
                  Link
                </Button>
              )}
            </Box>
          }
          sx={{ pb: 1 }}
        />

        <CardContent sx={{ pt: 0 }}>
          {/* Correlation Reason */}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {correlation.reason}
          </Typography>

          {/* AI Insights */}
          {correlation.aiInsights.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <AIIcon sx={{ fontSize: 16 }} />
                AI Insights
              </Typography>
              <List dense>
                {correlation.aiInsights.map((insight, index) => (
                  <ListItem key={index} sx={{ pl: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <InfoIcon sx={{ fontSize: 16, color: theme.palette.info.main }} />
                    </ListItemIcon>
                    <ListItemText primary={insight} primaryTypographyProps={{ variant: 'caption' }} />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}

          {/* Related Alerts */}
          <Typography variant="subtitle2" gutterBottom>
            Related Alerts ({correlation.relatedAlerts.length})
          </Typography>
          <Stack spacing={1}>
            {correlation.relatedAlerts.slice(0, 3).map((relatedAlert) => (
              <Card key={relatedAlert.id} variant="outlined" sx={{ backgroundColor: 'background.default' }}>
                <CardContent sx={{ py: 1, '&:last-child': { pb: 1 } }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip
                        label={relatedAlert.priority}
                        size="small"
                        sx={{
                          backgroundColor: getPriorityColor(relatedAlert.priority),
                          color: 'white',
                          fontWeight: 600,
                        }}
                      />
                      <Typography variant="body2" fontWeight={500} noWrap sx={{ maxWidth: 200 }}>
                        {relatedAlert.title}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip label={relatedAlert.status.replace('_', ' ')} size="small" variant="outlined" />
                      <Typography variant="caption" color="text.secondary">
                        {formatDistanceToNow(relatedAlert.createdAt, { addSuffix: true })}
                      </Typography>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            ))}

            {correlation.relatedAlerts.length > 3 && (
              <Typography variant="caption" color="text.secondary" align="center">
                And {correlation.relatedAlerts.length - 3} more alerts...
              </Typography>
            )}
          </Stack>
        </CardContent>
      </Card>
    );
  };

  const renderCorrelationSummary = () => {
    const totalRelated = correlations.reduce((sum, c) => sum + c.relatedAlerts.length, 0);
    const duplicates = correlations.filter((c) => c.type === 'DUPLICATE').length;
    const highConfidence = correlations.filter((c) => c.confidence >= 90).length;

    return (
      <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
        <Chip icon={<LinkIcon />} label={`${totalRelated} Related Alerts`} variant="outlined" color="primary" />
        {duplicates > 0 && (
          <Chip icon={<MergeIcon />} label={`${duplicates} Duplicates`} variant="outlined" color="error" />
        )}
        {highConfidence > 0 && (
          <Chip icon={<CheckIcon />} label={`${highConfidence} High Confidence`} variant="outlined" color="success" />
        )}
      </Stack>
    );
  };

  if (correlations.length === 0) {
    return null;
  }

  return (
    <Box>
      <Card variant="outlined" sx={{ backgroundColor: alpha(theme.palette.info.main, 0.02) }}>
        <CardHeader
          avatar={<TimelineIcon color="info" />}
          title={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="subtitle1" fontWeight={600}>
                Alert Correlations
              </Typography>
              <Badge badgeContent={correlations.length} color="info" />
            </Box>
          }
          subheader="AI-detected relationships and patterns"
          action={
            <IconButton onClick={() => setExpanded(!expanded)}>
              {expanded ? <CollapseIcon /> : <ExpandIcon />}
            </IconButton>
          }
        />

        <Collapse in={expanded} timeout="auto" unmountOnExit>
          <CardContent>
            {renderCorrelationSummary()}

            <Stack spacing={2}>{correlations.map(renderCorrelationCard)}</Stack>

            {/* Correlation Statistics */}
            <Box sx={{ mt: 3, p: 2, backgroundColor: alpha(theme.palette.background.paper, 0.5), borderRadius: 1 }}>
              <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <TrendIcon sx={{ fontSize: 16 }} />
                Correlation Statistics
              </Typography>

              <Stack direction="row" spacing={3}>
                <Box>
                  <Typography variant="h6" color="primary">
                    {Math.round(correlations.reduce((sum, c) => sum + c.confidence, 0) / correlations.length)}%
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Avg. Confidence
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="h6" color="secondary">
                    {correlations.filter((c) => c.suggestedAction === 'MERGE').length}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Merge Suggestions
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="h6" color="success.main">
                    {correlations.filter((c) => c.confidence >= 95).length}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    High Confidence
                  </Typography>
                </Box>
              </Stack>
            </Box>
          </CardContent>
        </Collapse>
      </Card>

      {/* Merge Confirmation Dialog */}
      <Dialog open={mergeDialog.open} onClose={() => setMergeDialog({ open: false })} maxWidth="md" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <MergeIcon color="warning" />
            Merge Duplicate Alerts
          </Box>
        </DialogTitle>

        <DialogContent>
          {mergeDialog.correlation && (
            <Box>
              <MuiAlert severity="warning" sx={{ mb: 2 }}>
                You are about to merge {mergeDialog.correlation.relatedAlerts.length} duplicate alerts into this primary
                alert. This action cannot be undone.
              </MuiAlert>

              <Typography variant="subtitle2" gutterBottom>
                Primary Alert (will remain)
              </Typography>
              <Card variant="outlined" sx={{ mb: 2, backgroundColor: alpha(theme.palette.success.main, 0.1) }}>
                <CardContent sx={{ py: 1 }}>
                  <Typography variant="body2" fontWeight={600}>
                    {alert.title}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    ID: {alert.id} • Created: {formatDistanceToNow(alert.createdAt, { addSuffix: true })}
                  </Typography>
                </CardContent>
              </Card>

              <Typography variant="subtitle2" gutterBottom>
                Alerts to be merged (will be archived)
              </Typography>
              <Stack spacing={1} sx={{ mb: 2, maxHeight: 200, overflow: 'auto' }}>
                {mergeDialog.correlation.relatedAlerts.map((relatedAlert) => (
                  <Card
                    key={relatedAlert.id}
                    variant="outlined"
                    sx={{ backgroundColor: alpha(theme.palette.warning.main, 0.1) }}
                  >
                    <CardContent sx={{ py: 1 }}>
                      <Typography variant="body2">{relatedAlert.title}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        ID: {relatedAlert.id} • Created:{' '}
                        {formatDistanceToNow(relatedAlert.createdAt, { addSuffix: true })}
                      </Typography>
                    </CardContent>
                  </Card>
                ))}
              </Stack>

              <TextField
                fullWidth
                label="Merge Reason"
                multiline
                rows={3}
                value={mergeReason}
                onChange={(e) => setMergeReason(e.target.value)}
                placeholder="Explain why these alerts are being merged..."
                required
              />
            </Box>
          )}
        </DialogContent>

        <DialogActions>
          <Button onClick={() => setMergeDialog({ open: false })}>Cancel</Button>
          <Button
            variant="contained"
            color="warning"
            onClick={handleMergeConfirm}
            disabled={!mergeReason.trim()}
            startIcon={<MergeIcon />}
          >
            Confirm Merge
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default AlertCorrelationView;
