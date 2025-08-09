'use client';

import React, { useState, useCallback, useMemo } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Checkbox,
  FormControlLabel,
  FormGroup,
  Paper,
  Divider,
  Alert,
  LinearProgress,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  PictureAsPdf as PdfIcon,
  TableChart as ExcelIcon,
  InsertDriveFile as WordIcon,
  Image as ImageIcon,
  GetApp as DownloadIcon,
  Email as EmailIcon,
  Share as ShareIcon,
  Schedule as ScheduleIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  Business as BusinessIcon,
  Timeline as TimelineIcon,
  Close as CloseIcon
} from '@mui/icons-material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';

interface ExecutiveExportDialogProps {
  open: boolean;
  onClose: () => void;
  dashboardData: any;
  userRole: 'ceo' | 'ciso' | 'board_member' | 'executive_assistant';
}

interface ExportConfig {
  format: 'pdf' | 'excel' | 'word' | 'png' | 'json';
  sections: string[];
  dateRange: {
    start: Date | null;
    end: Date | null;
  };
  template: 'executive' | 'detailed' | 'board' | 'operational';
  includeCharts: boolean;
  includeMetadata: boolean;
  includeConfidenceScores: boolean;
  watermark: boolean;
  classification: 'confidential' | 'restricted' | 'internal' | 'public';
  recipients?: string[];
  schedule?: {
    enabled: boolean;
    frequency: 'daily' | 'weekly' | 'monthly';
    time: string;
  };
}

const EXPORT_SECTIONS = [
  {
    id: 'executive-summary',
    title: 'Executive Summary',
    description: 'High-level security posture overview',
    icon: <SecurityIcon />,
    essential: true
  },
  {
    id: 'security-posture',
    title: 'Security Posture',
    description: 'Detailed security health metrics',
    icon: <SecurityIcon />,
    essential: false
  },
  {
    id: 'threat-landscape',
    title: 'Threat Landscape',
    description: 'Current threats and risk analysis',
    icon: <AssessmentIcon />,
    essential: true
  },
  {
    id: 'compliance-status',
    title: 'Compliance Status',
    description: 'Multi-framework compliance scores',
    icon: <BusinessIcon />,
    essential: true
  },
  {
    id: 'roi-metrics',
    title: 'ROI & Financial',
    description: 'Security investment returns',
    icon: <TimelineIcon />,
    essential: false
  },
  {
    id: 'predictive-analytics',
    title: 'Predictive Analytics',
    description: 'AI-powered insights and recommendations',
    icon: <AssessmentIcon />,
    essential: false
  },
  {
    id: 'appendix',
    title: 'Technical Appendix',
    description: 'Detailed metrics and methodology',
    icon: <AssessmentIcon />,
    essential: false
  }
];

const EXPORT_FORMATS = [
  {
    id: 'pdf',
    title: 'PDF Report',
    description: 'Executive presentation format',
    icon: <PdfIcon />,
    extensions: ['.pdf'],
    supportsCharts: true,
    supportsScheduling: true
  },
  {
    id: 'excel',
    title: 'Excel Workbook',
    description: 'Data analysis format',
    icon: <ExcelIcon />,
    extensions: ['.xlsx'],
    supportsCharts: true,
    supportsScheduling: true
  },
  {
    id: 'word',
    title: 'Word Document',
    description: 'Editable report format',
    icon: <WordIcon />,
    extensions: ['.docx'],
    supportsCharts: true,
    supportsScheduling: false
  },
  {
    id: 'png',
    title: 'Dashboard Image',
    description: 'Visual snapshot',
    icon: <ImageIcon />,
    extensions: ['.png'],
    supportsCharts: false,
    supportsScheduling: false
  },
  {
    id: 'json',
    title: 'Raw Data',
    description: 'Machine-readable format',
    icon: <AssessmentIcon />,
    extensions: ['.json'],
    supportsCharts: false,
    supportsScheduling: true
  }
];

export const ExecutiveExportDialog: React.FC<ExecutiveExportDialogProps> = ({
  open,
  onClose,
  dashboardData,
  userRole
}) => {
  const [exportConfig, setExportConfig] = useState<ExportConfig>({
    format: 'pdf',
    sections: ['executive-summary', 'threat-landscape', 'compliance-status'],
    dateRange: {
      start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
      end: new Date()
    },
    template: userRole === 'board_member' ? 'board' : 'executive',
    includeCharts: true,
    includeMetadata: false,
    includeConfidenceScores: userRole !== 'board_member',
    watermark: true,
    classification: 'confidential',
    recipients: [],
    schedule: {
      enabled: false,
      frequency: 'weekly',
      time: '09:00'
    }
  });

  const [isExporting, setIsExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState(0);

  // Role-based permissions
  const canScheduleReports = userRole === 'ceo' || userRole === 'ciso' || userRole === 'executive_assistant';
  const canShareReports = userRole !== 'executive_assistant';
  const canAccessRawData = userRole === 'ceo' || userRole === 'ciso';

  // Filter sections based on role
  const availableSections = useMemo(() => {
    return EXPORT_SECTIONS.filter(section => {
      if (userRole === 'board_member') {
        return ['executive-summary', 'compliance-status', 'roi-metrics'].includes(section.id);
      }
      if (userRole === 'executive_assistant') {
        return !['predictive-analytics', 'appendix'].includes(section.id);
      }
      return true;
    });
  }, [userRole]);

  // Filter formats based on role and permissions
  const availableFormats = useMemo(() => {
    return EXPORT_FORMATS.filter(format => {
      if (format.id === 'json' && !canAccessRawData) {
        return false;
      }
      return true;
    });
  }, [canAccessRawData]);

  const handleConfigUpdate = useCallback((updates: Partial<ExportConfig>) => {
    setExportConfig(prev => ({ ...prev, ...updates }));
  }, []);

  const handleSectionToggle = useCallback((sectionId: string) => {
    const section = availableSections.find(s => s.id === sectionId);
    if (section?.essential) return; // Can't toggle essential sections
    
    setExportConfig(prev => ({
      ...prev,
      sections: prev.sections.includes(sectionId)
        ? prev.sections.filter(s => s !== sectionId)
        : [...prev.sections, sectionId]
    }));
  }, [availableSections]);

  const handleExport = useCallback(async () => {
    setIsExporting(true);
    setExportProgress(0);
    
    try {
      // Simulate export progress
      const progressInterval = setInterval(() => {
        setExportProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + Math.random() * 20;
        });
      }, 200);

      // Simulate API call to export service
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      clearInterval(progressInterval);
      setExportProgress(100);
      
      // Generate download
      const filename = generateFilename(exportConfig);
      downloadReport(filename, exportConfig);
      
      setTimeout(() => {
        setIsExporting(false);
        setExportProgress(0);
        onClose();
      }, 1000);
      
    } catch (error) {
      console.error('Export failed:', error);
      setIsExporting(false);
      setExportProgress(0);
    }
  }, [exportConfig, onClose]);

  const generateFilename = (config: ExportConfig): string => {
    const timestamp = new Date().toISOString().split('T')[0];
    const formatExt = EXPORT_FORMATS.find(f => f.id === config.format)?.extensions[0] || '';
    return `executive-security-dashboard-${timestamp}${formatExt}`;
  };

  const downloadReport = (filename: string, config: ExportConfig) => {
    // Create mock download link
    const element = document.createElement('a');
    const file = new Blob(['Mock export data'], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const selectedFormat = EXPORT_FORMATS.find(f => f.id === exportConfig.format);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: { minHeight: '60vh' }
      }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <DownloadIcon />
            <Typography variant="h6">Export Dashboard Report</Typography>
          </Box>
          <IconButton onClick={onClose} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent>
        <Grid container spacing={3}>
          {/* Format Selection */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: '100%' }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Export Format
              </Typography>
              
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Format</InputLabel>
                <Select
                  value={exportConfig.format}
                  label="Format"
                  onChange={(e) => handleConfigUpdate({ format: e.target.value as any })}
                >
                  {availableFormats.map((format) => (
                    <MenuItem key={format.id} value={format.id}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {format.icon}
                        <Box>
                          <Typography variant="body1">{format.title}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {format.description}
                          </Typography>
                        </Box>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <FormControl fullWidth>
                <InputLabel>Template</InputLabel>
                <Select
                  value={exportConfig.template}
                  label="Template"
                  onChange={(e) => handleConfigUpdate({ template: e.target.value as any })}
                >
                  <MenuItem value="executive">Executive Summary</MenuItem>
                  <MenuItem value="detailed">Detailed Report</MenuItem>
                  <MenuItem value="board">Board Presentation</MenuItem>
                  <MenuItem value="operational">Operational Brief</MenuItem>
                </Select>
              </FormControl>

              {selectedFormat && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    {selectedFormat.description}
                  </Typography>
                </Alert>
              )}
            </Paper>
          </Grid>

          {/* Date Range */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: '100%' }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Date Range
              </Typography>
              
              <LocalizationProvider dateAdapter={AdapterDateFns}>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <DatePicker
                    label="Start Date"
                    value={exportConfig.dateRange.start}
                    onChange={(date) => handleConfigUpdate({ 
                      dateRange: { ...exportConfig.dateRange, start: date }
                    })}
                    slotProps={{ textField: { fullWidth: true } }}
                  />
                  <DatePicker
                    label="End Date"
                    value={exportConfig.dateRange.end}
                    onChange={(date) => handleConfigUpdate({ 
                      dateRange: { ...exportConfig.dateRange, end: date }
                    })}
                    slotProps={{ textField: { fullWidth: true } }}
                  />
                </Box>
              </LocalizationProvider>

              <FormControl fullWidth sx={{ mt: 2 }}>
                <InputLabel>Classification</InputLabel>
                <Select
                  value={exportConfig.classification}
                  label="Classification"
                  onChange={(e) => handleConfigUpdate({ classification: e.target.value as any })}
                >
                  <MenuItem value="public">Public</MenuItem>
                  <MenuItem value="internal">Internal</MenuItem>
                  <MenuItem value="restricted">Restricted</MenuItem>
                  <MenuItem value="confidential">Confidential</MenuItem>
                </Select>
              </FormControl>
            </Paper>
          </Grid>

          {/* Sections to Include */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Report Sections
              </Typography>
              
              <Grid container spacing={2}>
                {availableSections.map((section) => (
                  <Grid item xs={12} sm={6} md={4} key={section.id}>
                    <Card 
                      variant="outlined"
                      sx={{ 
                        cursor: section.essential ? 'default' : 'pointer',
                        bgcolor: exportConfig.sections.includes(section.id) ? 'primary.light' : 'background.default',
                        opacity: section.essential ? 1 : (exportConfig.sections.includes(section.id) ? 1 : 0.7)
                      }}
                      onClick={section.essential ? undefined : () => handleSectionToggle(section.id)}
                    >
                      <CardContent sx={{ p: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                          {section.icon}
                          <Typography variant="subtitle2">
                            {section.title}
                          </Typography>
                          <Checkbox
                            checked={exportConfig.sections.includes(section.id)}
                            disabled={section.essential}
                            size="small"
                          />
                        </Box>
                        <Typography variant="caption" color="text.secondary">
                          {section.description}
                        </Typography>
                        {section.essential && (
                          <Chip label="Required" size="small" color="primary" sx={{ mt: 1 }} />
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          {/* Export Options */}
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Export Options
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <FormGroup>
                    {selectedFormat?.supportsCharts && (
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={exportConfig.includeCharts}
                            onChange={(e) => handleConfigUpdate({ includeCharts: e.target.checked })}
                          />
                        }
                        label="Include Charts & Visualizations"
                      />
                    )}
                    
                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={exportConfig.includeMetadata}
                          onChange={(e) => handleConfigUpdate({ includeMetadata: e.target.checked })}
                        />
                      }
                      label="Include Metadata & Timestamps"
                    />
                    
                    {exportConfig.includeConfidenceScores && userRole !== 'board_member' && (
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={exportConfig.includeConfidenceScores}
                            onChange={(e) => handleConfigUpdate({ includeConfidenceScores: e.target.checked })}
                          />
                        }
                        label="Include Confidence Scores"
                      />
                    )}
                    
                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={exportConfig.watermark}
                          onChange={(e) => handleConfigUpdate({ watermark: e.target.checked })}
                        />
                      }
                      label="Add Security Watermark"
                    />
                  </FormGroup>
                </Grid>

                {/* Scheduling Options */}
                {canScheduleReports && selectedFormat?.supportsScheduling && (
                  <Grid item xs={12} sm={6}>
                    <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 2 }}>
                      <Typography variant="subtitle2" sx={{ mb: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                        <ScheduleIcon />
                        Schedule Reports
                      </Typography>
                      
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={exportConfig.schedule?.enabled}
                            onChange={(e) => handleConfigUpdate({ 
                              schedule: { ...exportConfig.schedule, enabled: e.target.checked }
                            })}
                          />
                        }
                        label="Enable Scheduled Reports"
                      />
                      
                      {exportConfig.schedule?.enabled && (
                        <Box sx={{ ml: 3, mt: 1 }}>
                          <FormControl size="small" sx={{ minWidth: 120, mb: 1 }}>
                            <InputLabel>Frequency</InputLabel>
                            <Select
                              value={exportConfig.schedule.frequency}
                              label="Frequency"
                              onChange={(e) => handleConfigUpdate({
                                schedule: { ...exportConfig.schedule, frequency: e.target.value as any }
                              })}
                            >
                              <MenuItem value="daily">Daily</MenuItem>
                              <MenuItem value="weekly">Weekly</MenuItem>
                              <MenuItem value="monthly">Monthly</MenuItem>
                            </Select>
                          </FormControl>
                          
                          <TextField
                            label="Time"
                            type="time"
                            value={exportConfig.schedule.time}
                            onChange={(e) => handleConfigUpdate({
                              schedule: { ...exportConfig.schedule, time: e.target.value }
                            })}
                            size="small"
                            sx={{ ml: 1 }}
                            InputLabelProps={{ shrink: true }}
                          />
                        </Box>
                      )}
                    </Box>
                  </Grid>
                )}
              </Grid>
            </Paper>
          </Grid>
        </Grid>

        {/* Export Progress */}
        {isExporting && (
          <Box sx={{ mt: 3 }}>
            <LinearProgress variant="determinate" value={exportProgress} />
            <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
              Generating report... {Math.round(exportProgress)}%
            </Typography>
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2, justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', gap: 1 }}>
          {canShareReports && (
            <Button
              startIcon={<ShareIcon />}
              variant="outlined"
              disabled={isExporting}
            >
              Share
            </Button>
          )}
          
          {canScheduleReports && selectedFormat?.supportsScheduling && (
            <Button
              startIcon={<EmailIcon />}
              variant="outlined"
              disabled={isExporting || !exportConfig.schedule?.enabled}
            >
              Email
            </Button>
          )}
        </Box>

        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            onClick={onClose}
            disabled={isExporting}
          >
            Cancel
          </Button>
          <Button
            onClick={handleExport}
            variant="contained"
            startIcon={<DownloadIcon />}
            disabled={isExporting || exportConfig.sections.length === 0}
          >
            {isExporting ? 'Generating...' : 'Export Report'}
          </Button>
        </Box>
      </DialogActions>
    </Dialog>
  );
};

export default ExecutiveExportDialog;