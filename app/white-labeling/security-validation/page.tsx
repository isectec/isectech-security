'use client';

/**
 * Multi-Tenant Isolation Security Validation Page
 * Interface for security testing, validation monitoring, and compliance tracking
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
  LinearProgress,
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
  Switch,
  FormControlLabel,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  BugReport as VulnerabilityIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Info as InfoIcon,
  PlayArrow as RunTestIcon,
  Stop as StopTestIcon,
  Refresh as RefreshIcon,
  GetApp as ExportIcon,
  Schedule as ScheduleIcon,
  Notifications as AlertIcon,
  Visibility as ViewIcon,
  ExpandMore as ExpandMoreIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingIcon,
  Policy as ComplianceIcon,
  MonitorHeart as MonitorIcon,
  Build as TestIcon,
  Analytics as MetricsIcon,
  Report as ReportIcon,
  Gavel as ComplianceGavelIcon,
  Speed as PerformanceIcon,
} from '@mui/icons-material';

import { tenantIsolationValidator } from '@/lib/white-labeling/tenant-isolation-validator';
import type {
  IsolationValidationReport,
  TenantVulnerability,
  SecurityMetrics,
  TenantIsolationTest,
  TenantTestResult,
} from '@/lib/white-labeling/tenant-isolation-validator';

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

export default function SecurityValidationPage() {
  const [tabValue, setTabValue] = useState(0);
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics | null>(null);
  const [validationReports, setValidationReports] = useState<IsolationValidationReport[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<TenantVulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dialog states
  const [runTestDialog, setRunTestDialog] = useState(false);
  const [reportDialog, setReportDialog] = useState(false);
  const [vulnerabilityDialog, setVulnerabilityDialog] = useState(false);
  const [scheduleDialog, setScheduleDialog] = useState(false);

  // Test execution state
  const [testExecution, setTestExecution] = useState({
    running: false,
    progress: 0,
    currentTest: '',
    results: null as IsolationValidationReport | null,
  });

  // Form states
  const [testConfig, setTestConfig] = useState({
    primaryTenantId: '',
    secondaryTenantId: '',
    testCategories: [] as TenantIsolationTest['category'][],
    severityThreshold: 'MEDIUM' as TenantIsolationTest['severity'],
  });

  const [scheduleConfig, setScheduleConfig] = useState({
    enabled: false,
    frequency: 'WEEKLY' as 'DAILY' | 'WEEKLY' | 'MONTHLY',
    alertThreshold: 70,
    notificationEmail: '',
  });

  // Selected items
  const [selectedReport, setSelectedReport] = useState<IsolationValidationReport | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<TenantVulnerability | null>(null);

  // UI state
  const [expandedAccordion, setExpandedAccordion] = useState<string | false>(false);

  const tenantId = 'demo-tenant'; // Would get from auth context
  const userId = 'security-admin'; // Would get from auth context

  const testCategories: { value: TenantIsolationTest['category']; label: string }[] = [
    { value: 'DATA_ACCESS', label: 'Data Access' },
    { value: 'CONFIGURATION', label: 'Configuration' },
    { value: 'ASSET', label: 'Assets' },
    { value: 'DOMAIN', label: 'Domains' },
    { value: 'EMAIL', label: 'Email Templates' },
    { value: 'AUDIT', label: 'Audit Logs' },
    { value: 'API_SECURITY', label: 'API Security' },
  ];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Load security metrics
      const metrics = await tenantIsolationValidator.getSecurityMetrics(tenantId);
      setSecurityMetrics(metrics);

      // Mock validation reports and vulnerabilities
      setValidationReports([
        {
          id: 'report-1',
          tenantId,
          testSuiteVersion: '1.0.0',
          executedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
          executedBy: 'automated-scan',
          totalTests: 7,
          passedTests: 6,
          failedTests: 1,
          vulnerabilities: [],
          overallSecurityScore: 85,
          riskLevel: 'LOW',
          recommendations: ['Continue regular monitoring', 'Review failed test'],
          complianceStatus: {
            iso27001: true,
            sox: true,
            gdpr: true,
            hipaa: false,
          },
          testResults: [],
          nextScheduledTest: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
        },
      ]);

      setVulnerabilities([]);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleRunSecurityValidation = async () => {
    try {
      setTestExecution({ running: true, progress: 0, currentTest: 'Initializing...', results: null });
      setRunTestDialog(true);

      // Simulate test execution progress
      const tests = [
        'Cross-Tenant Configuration Access',
        'Cross-Tenant Asset Access',
        'Cross-Tenant Domain Access',
        'Cross-Tenant Email Access',
        'Cross-Tenant Audit Log Access',
        'API Endpoint Tenant Isolation',
        'Data Export Tenant Isolation',
      ];

      for (let i = 0; i < tests.length; i++) {
        setTestExecution(prev => ({
          ...prev,
          currentTest: tests[i],
          progress: ((i + 1) / tests.length) * 100,
        }));
        
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      // Run actual validation
      const report = await tenantIsolationValidator.validateTenantIsolation(
        testConfig.primaryTenantId || tenantId,
        testConfig.secondaryTenantId || 'other-tenant',
        userId,
        {
          includeCategories: testConfig.testCategories.length > 0 ? testConfig.testCategories : undefined,
          severityThreshold: testConfig.severityThreshold,
        }
      );

      setTestExecution(prev => ({ ...prev, results: report, currentTest: 'Complete' }));
      setValidationReports(prev => [report, ...prev]);
      
      // Update metrics
      const updatedMetrics = await tenantIsolationValidator.getSecurityMetrics(tenantId);
      setSecurityMetrics(updatedMetrics);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run security validation');
    } finally {
      setTimeout(() => {
        setTestExecution({ running: false, progress: 0, currentTest: '', results: null });
        setRunTestDialog(false);
      }, 2000);
    }
  };

  const handleRunAutomatedScan = async () => {
    try {
      setLoading(true);
      const { reports, summary } = await tenantIsolationValidator.runAutomatedSecurityScan(userId);
      setValidationReports(reports);
      setSecurityMetrics(summary);
      setVulnerabilities(reports.flatMap(r => r.vulnerabilities));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run automated scan');
    } finally {
      setLoading(false);
    }
  };

  const handleExportReport = (report: IsolationValidationReport) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_validation_report_${report.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity: TenantVulnerability['severity']) => {
    switch (severity) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'warning';
      case 'MEDIUM': return 'info';
      case 'LOW': return 'success';
      default: return 'default';
    }
  };

  const getRiskLevelColor = (risk: IsolationValidationReport['riskLevel']) => {
    switch (risk) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'warning';
      case 'MEDIUM': return 'info';
      case 'LOW': return 'success';
      default: return 'default';
    }
  };

  const getComplianceIcon = (compliant: boolean) => {
    return compliant ? <CheckIcon color="success" /> : <ErrorIcon color="error" />;
  };

  const renderSecurityMetrics = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6} lg={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={1}>
              <SecurityIcon color="primary" sx={{ mr: 1 }} />
              <Typography variant="h6">Security Score</Typography>
            </Box>
            <Typography variant="h3" color="primary">
              {securityMetrics?.averageSecurityScore.toFixed(0) || 0}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Average across all tenants
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6} lg={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={1}>
              <VulnerabilityIcon color="error" sx={{ mr: 1 }} />
              <Typography variant="h6">Critical Vulns</Typography>
            </Box>
            <Typography variant="h3" color="error">
              {securityMetrics?.criticalVulnerabilities || 0}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Requiring immediate attention
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6} lg={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={1}>
              <ComplianceIcon color="info" sx={{ mr: 1 }} />
              <Typography variant="h6">Compliance Rate</Typography>
            </Box>
            <Typography variant="h3" color="info">
              {securityMetrics?.complianceRate.toFixed(0) || 0}%
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Meeting compliance standards
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6} lg={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={1}>
              <ShieldIcon color="success" sx={{ mr: 1 }} />
              <Typography variant="h6">Tenants Validated</Typography>
            </Box>
            <Typography variant="h3" color="success">
              {securityMetrics?.totalTenantsValidated || 0}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Active tenant validations
            </Typography>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const renderValidationReportCard = (report: IsolationValidationReport) => (
    <Grid item xs={12} lg={6} key={report.id}>
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
            <Box>
              <Typography variant="h6" gutterBottom>
                Validation Report
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Executed: {report.executedAt.toLocaleString()}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                By: {report.executedBy}
              </Typography>
            </Box>
            <Box display="flex" gap={1}>
              <Chip
                label={report.riskLevel}
                color={getRiskLevelColor(report.riskLevel) as any}
                size="small"
              />
              <Chip
                label={`${report.overallSecurityScore}/100`}
                color={report.overallSecurityScore >= 80 ? 'success' : 'warning'}
                size="small"
              />
            </Box>
          </Box>

          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid item xs={6}>
              <Typography variant="subtitle2">Tests</Typography>
              <Typography variant="body2">
                {report.passedTests}/{report.totalTests} passed
              </Typography>
            </Grid>
            <Grid item xs={6}>
              <Typography variant="subtitle2">Vulnerabilities</Typography>
              <Typography variant="body2">
                {report.vulnerabilities.length} found
              </Typography>
            </Grid>
          </Grid>

          <Box mb={2}>
            <Typography variant="subtitle2" gutterBottom>
              Compliance Status:
            </Typography>
            <Box display="flex" gap={1} flexWrap="wrap">
              <Box display="flex" alignItems="center">
                {getComplianceIcon(report.complianceStatus.iso27001)}
                <Typography variant="caption" sx={{ ml: 0.5 }}>ISO 27001</Typography>
              </Box>
              <Box display="flex" alignItems="center">
                {getComplianceIcon(report.complianceStatus.sox)}
                <Typography variant="caption" sx={{ ml: 0.5 }}>SOX</Typography>
              </Box>
              <Box display="flex" alignItems="center">
                {getComplianceIcon(report.complianceStatus.gdpr)}
                <Typography variant="caption" sx={{ ml: 0.5 }}>GDPR</Typography>
              </Box>
              <Box display="flex" alignItems="center">
                {getComplianceIcon(report.complianceStatus.hipaa)}
                <Typography variant="caption" sx={{ ml: 0.5 }}>HIPAA</Typography>
              </Box>
            </Box>
          </Box>

          <Typography variant="caption" color="text.secondary">
            Next scheduled: {report.nextScheduledTest?.toLocaleDateString()}
          </Typography>
        </CardContent>

        <CardActions>
          <Button
            size="small"
            startIcon={<ViewIcon />}
            onClick={() => {
              setSelectedReport(report);
              setReportDialog(true);
            }}
          >
            View Details
          </Button>
          <Button
            size="small"
            startIcon={<ExportIcon />}
            onClick={() => handleExportReport(report)}
          >
            Export
          </Button>
        </CardActions>
      </Card>
    </Grid>
  );

  const renderVulnerabilityCard = (vulnerability: TenantVulnerability) => (
    <Grid item xs={12} md={6} key={vulnerability.id}>
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
            <Typography variant="h6" gutterBottom>
              {vulnerability.type.replace(/_/g, ' ')}
            </Typography>
            <Chip
              label={vulnerability.severity}
              color={getSeverityColor(vulnerability.severity) as any}
              size="small"
            />
          </Box>
          
          <Typography variant="body2" color="text.secondary" paragraph>
            {vulnerability.description}
          </Typography>
          
          <Typography variant="subtitle2" gutterBottom>
            Impact:
          </Typography>
          <Typography variant="body2" paragraph>
            {vulnerability.impact}
          </Typography>
          
          <Typography variant="subtitle2" gutterBottom>
            Remediation:
          </Typography>
          <Typography variant="body2">
            {vulnerability.remediation}
          </Typography>
        </CardContent>
        
        <CardActions>
          <Button
            size="small"
            startIcon={<ViewIcon />}
            onClick={() => {
              setSelectedVulnerability(vulnerability);
              setVulnerabilityDialog(true);
            }}
          >
            View Details
          </Button>
        </CardActions>
      </Card>
    </Grid>
  );

  if (loading && !securityMetrics) {
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
            Multi-Tenant Security Validation
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Monitor tenant isolation, validate security, and ensure compliance across all white-label configurations.
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
            variant="outlined"
            startIcon={<TestIcon />}
            onClick={handleRunAutomatedScan}
          >
            Auto Scan
          </Button>
          <Button
            variant="contained"
            startIcon={<RunTestIcon />}
            onClick={() => setRunTestDialog(true)}
          >
            Run Validation
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {securityMetrics && renderSecurityMetrics()}

      <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)} sx={{ mt: 3, mb: 3 }}>
        <Tab icon={<ReportIcon />} label="Validation Reports" />
        <Tab icon={<VulnerabilityIcon />} label="Security Vulnerabilities" />
        <Tab icon={<MonitorIcon />} label="Continuous Monitoring" />
        <Tab icon={<ComplianceGavelIcon />} label="Compliance Dashboard" />
      </Tabs>

      {/* Validation Reports Tab */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          {validationReports.map(report => renderValidationReportCard(report))}
          {validationReports.length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 6 }}>
                  <ReportIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No Validation Reports
                  </Typography>
                  <Typography variant="body2" color="text.secondary" mb={3}>
                    Run security validation tests to generate reports and monitor tenant isolation.
                  </Typography>
                  <Button
                    variant="contained"
                    startIcon={<RunTestIcon />}
                    onClick={() => setRunTestDialog(true)}
                  >
                    Run First Validation
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* Security Vulnerabilities Tab */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          {vulnerabilities.map(vulnerability => renderVulnerabilityCard(vulnerability))}
          {vulnerabilities.length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 6 }}>
                  <ShieldIcon sx={{ fontSize: 64, color: 'success.main', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No Security Vulnerabilities Found
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Your tenant isolation appears to be secure. Continue regular validation to maintain security.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* Continuous Monitoring Tab */}
      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Monitoring Configuration
                </Typography>
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={scheduleConfig.enabled}
                      onChange={(e) => setScheduleConfig({ ...scheduleConfig, enabled: e.target.checked })}
                    />
                  }
                  label="Enable Continuous Monitoring"
                />
                
                <Box sx={{ mt: 2 }}>
                  <FormControl fullWidth sx={{ mb: 2 }}>
                    <InputLabel>Validation Frequency</InputLabel>
                    <Select
                      value={scheduleConfig.frequency}
                      onChange={(e) => setScheduleConfig({ ...scheduleConfig, frequency: e.target.value as any })}
                      label="Validation Frequency"
                    >
                      <MenuItem value="DAILY">Daily</MenuItem>
                      <MenuItem value="WEEKLY">Weekly</MenuItem>
                      <MenuItem value="MONTHLY">Monthly</MenuItem>
                    </Select>
                  </FormControl>
                  
                  <TextField
                    fullWidth
                    label="Alert Threshold (Security Score)"
                    type="number"
                    value={scheduleConfig.alertThreshold}
                    onChange={(e) => setScheduleConfig({ ...scheduleConfig, alertThreshold: parseInt(e.target.value) })}
                    sx={{ mb: 2 }}
                    helperText="Send alerts when security score falls below this threshold"
                  />
                  
                  <TextField
                    fullWidth
                    label="Notification Email"
                    value={scheduleConfig.notificationEmail}
                    onChange={(e) => setScheduleConfig({ ...scheduleConfig, notificationEmail: e.target.value })}
                    placeholder="security@isectech.com"
                  />
                </Box>
              </CardContent>
              
              <CardActions>
                <Button
                  variant="contained"
                  startIcon={<ScheduleIcon />}
                  onClick={() => setScheduleDialog(true)}
                >
                  Update Schedule
                </Button>
              </CardActions>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Monitoring Status
                </Typography>
                
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <MonitorIcon color={scheduleConfig.enabled ? 'success' : 'disabled'} />
                    </ListItemIcon>
                    <ListItemText
                      primary="Continuous Monitoring"
                      secondary={scheduleConfig.enabled ? 'Active' : 'Disabled'}
                    />
                  </ListItem>
                  
                  <ListItem>
                    <ListItemIcon>
                      <AlertIcon color="info" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Alert Notifications"
                      secondary={`Threshold: ${scheduleConfig.alertThreshold}%`}
                    />
                  </ListItem>
                  
                  <ListItem>
                    <ListItemIcon>
                      <ScheduleIcon color="info" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Validation Frequency"
                      secondary={scheduleConfig.frequency}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Compliance Dashboard Tab */}
      <TabPanel value={tabValue} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Compliance Overview
                </Typography>
                
                <Alert severity="info" sx={{ mb: 3 }}>
                  Compliance status is automatically assessed based on security validation results.
                  Critical and high-severity vulnerabilities may impact compliance ratings.
                </Alert>
                
                <Grid container spacing={3}>
                  {validationReports.length > 0 && validationReports[0].complianceStatus && Object.entries(validationReports[0].complianceStatus).map(([standard, compliant]) => (
                    <Grid item xs={12} sm={6} md={3} key={standard}>
                      <Paper sx={{ p: 2, textAlign: 'center' }}>
                        {getComplianceIcon(compliant)}
                        <Typography variant="h6" sx={{ mt: 1 }}>
                          {standard.toUpperCase()}
                        </Typography>
                        <Typography
                          variant="body2"
                          color={compliant ? 'success.main' : 'error.main'}
                        >
                          {compliant ? 'Compliant' : 'Non-Compliant'}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Run Test Dialog */}
      <Dialog open={runTestDialog} onClose={() => !testExecution.running && setRunTestDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {testExecution.running ? 'Running Security Validation' : 'Configure Security Validation'}
        </DialogTitle>
        <DialogContent>
          {testExecution.running ? (
            <Box sx={{ mt: 2 }}>
              <Typography variant="body1" gutterBottom>
                {testExecution.currentTest}
              </Typography>
              <LinearProgress variant="determinate" value={testExecution.progress} sx={{ mb: 2 }} />
              <Typography variant="body2" color="text.secondary">
                {testExecution.progress.toFixed(0)}% complete
              </Typography>
              
              {testExecution.results && (
                <Box sx={{ mt: 3 }}>
                  <Alert severity={testExecution.results.riskLevel === 'LOW' ? 'success' : 'warning'}>
                    Validation complete! Security score: {testExecution.results.overallSecurityScore}/100
                  </Alert>
                </Box>
              )}
            </Box>
          ) : (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Primary Tenant ID"
                    value={testConfig.primaryTenantId}
                    onChange={(e) => setTestConfig({ ...testConfig, primaryTenantId: e.target.value })}
                    placeholder={tenantId}
                    sx={{ mb: 2 }}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Secondary Tenant ID"
                    value={testConfig.secondaryTenantId}
                    onChange={(e) => setTestConfig({ ...testConfig, secondaryTenantId: e.target.value })}
                    placeholder="other-tenant"
                    sx={{ mb: 2 }}
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControl fullWidth sx={{ mb: 2 }}>
                    <InputLabel>Severity Threshold</InputLabel>
                    <Select
                      value={testConfig.severityThreshold}
                      onChange={(e) => setTestConfig({ ...testConfig, severityThreshold: e.target.value as any })}
                      label="Severity Threshold"
                    >
                      <MenuItem value="LOW">Low</MenuItem>
                      <MenuItem value="MEDIUM">Medium</MenuItem>
                      <MenuItem value="HIGH">High</MenuItem>
                      <MenuItem value="CRITICAL">Critical</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Test Categories:
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {testCategories.map(category => (
                      <Chip
                        key={category.value}
                        label={category.label}
                        clickable
                        color={testConfig.testCategories.includes(category.value) ? 'primary' : 'default'}
                        onClick={() => {
                          setTestConfig(prev => ({
                            ...prev,
                            testCategories: prev.testCategories.includes(category.value)
                              ? prev.testCategories.filter(c => c !== category.value)
                              : [...prev.testCategories, category.value],
                          }));
                        }}
                      />
                    ))}
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          {!testExecution.running && (
            <>
              <Button onClick={() => setRunTestDialog(false)}>Cancel</Button>
              <Button
                variant="contained"
                onClick={handleRunSecurityValidation}
                startIcon={<RunTestIcon />}
              >
                Run Validation
              </Button>
            </>
          )}
        </DialogActions>
      </Dialog>

      {/* Report Details Dialog */}
      <Dialog open={reportDialog} onClose={() => setReportDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>Validation Report Details</DialogTitle>
        <DialogContent>
          {selectedReport && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Report ID:</Typography>
                  <Typography variant="body2">{selectedReport.id}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Security Score:</Typography>
                  <Typography variant="body2">{selectedReport.overallSecurityScore}/100</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Risk Level:</Typography>
                  <Chip label={selectedReport.riskLevel} color={getRiskLevelColor(selectedReport.riskLevel) as any} size="small" />
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Test Results:</Typography>
                  <Typography variant="body2">{selectedReport.passedTests}/{selectedReport.totalTests} passed</Typography>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom>
                Recommendations:
              </Typography>
              <List>
                {selectedReport.recommendations.map((rec, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <InfoIcon color="info" />
                    </ListItemIcon>
                    <ListItemText primary={rec} />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setReportDialog(false)}>Close</Button>
          <Button
            variant="contained"
            startIcon={<ExportIcon />}
            onClick={() => {
              if (selectedReport) handleExportReport(selectedReport);
            }}
          >
            Export Report
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}