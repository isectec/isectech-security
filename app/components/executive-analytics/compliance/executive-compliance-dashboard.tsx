/**
 * Executive Compliance Dashboard Component
 * Comprehensive compliance validation and reporting for executive analytics
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  Card,
  CardContent,
  CardHeader,
  Typography,
  Grid,
  Alert,
  AlertTitle,
  LinearProgress,
  Chip,
  Box,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  Security,
  Shield,
  CheckCircle,
  Warning,
  Error,
  Info,
  Visibility,
  GetApp,
  ExpandMore,
  Assessment,
  Gavel,
  HealthAndSafety,
  AccountBalance
} from '@mui/icons-material';
import { useExecutiveCompliance } from '../../../lib/hooks/use-executive-compliance';
import { ComplianceFramework, ComplianceStatus, ViolationType } from '../../../types/compliance';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`compliance-tabpanel-${index}`}
      aria-labelledby={`compliance-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

export const ExecutiveComplianceDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [selectedViolation, setSelectedViolation] = useState<string | null>(null);
  const [detailsDialog, setDetailsDialog] = useState(false);
  
  const {
    complianceStatus,
    violations,
    auditTrail,
    assessments,
    reports,
    loading,
    error,
    refreshCompliance,
    generateComplianceReport,
    resolveViolation
  } = useExecutiveCompliance();

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handleViolationClick = (violationId: string) => {
    setSelectedViolation(violationId);
    setDetailsDialog(true);
  };

  const handleResolveViolation = async (violationId: string) => {
    await resolveViolation(violationId);
    setDetailsDialog(false);
  };

  const complianceSummary = useMemo(() => {
    if (!complianceStatus) return null;

    const frameworks = Object.keys(complianceStatus);
    const totalCompliance = frameworks.reduce((sum, framework) => 
      sum + complianceStatus[framework].compliancePercentage, 0
    ) / frameworks.length;

    const criticalViolations = violations?.filter(v => v.severity === 'critical').length || 0;
    const highViolations = violations?.filter(v => v.severity === 'high').length || 0;

    return {
      totalCompliance: Math.round(totalCompliance),
      criticalViolations,
      highViolations,
      frameworks: frameworks.length,
      lastAssessment: assessments?.[0]?.timestamp || null
    };
  }, [complianceStatus, violations, assessments]);

  const getComplianceColor = (percentage: number) => {
    if (percentage >= 95) return 'success';
    if (percentage >= 85) return 'warning';
    return 'error';
  };

  const getFrameworkIcon = (framework: ComplianceFramework) => {
    switch (framework) {
      case ComplianceFramework.GDPR:
        return <Shield />;
      case ComplianceFramework.HIPAA:
        return <HealthAndSafety />;
      case ComplianceFramework.PCI_DSS:
        return <Security />;
      case ComplianceFramework.SOC2:
        return <Assessment />;
      case ComplianceFramework.ISO27001:
        return <AccountBalance />;
      default:
        return <Gavel />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight={400}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading compliance data...
        </Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        <AlertTitle>Compliance Data Error</AlertTitle>
        {error}
      </Alert>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      {/* Executive Summary */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Overall Compliance
              </Typography>
              <Typography variant="h3" component="div" color={getComplianceColor(complianceSummary?.totalCompliance || 0)}>
                {complianceSummary?.totalCompliance}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={complianceSummary?.totalCompliance || 0}
                color={getComplianceColor(complianceSummary?.totalCompliance || 0)}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Critical Violations
              </Typography>
              <Typography variant="h3" component="div" color="error">
                {complianceSummary?.criticalViolations || 0}
              </Typography>
              <Box display="flex" alignItems="center" mt={1}>
                <Error color="error" fontSize="small" />
                <Typography variant="body2" sx={{ ml: 1 }}>
                  Immediate attention required
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Active Frameworks
              </Typography>
              <Typography variant="h3" component="div">
                {complianceSummary?.frameworks || 0}
              </Typography>
              <Box display="flex" gap={1} mt={1}>
                {complianceStatus && Object.keys(complianceStatus).slice(0, 3).map((framework) => (
                  <Chip
                    key={framework}
                    label={framework.toUpperCase()}
                    size="small"
                    variant="outlined"
                  />
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Last Assessment
              </Typography>
              <Typography variant="h6" component="div">
                {complianceSummary?.lastAssessment
                  ? new Date(complianceSummary.lastAssessment).toLocaleDateString()
                  : 'Not Available'
                }
              </Typography>
              <Button
                size="small"
                startIcon={<Assessment />}
                onClick={refreshCompliance}
                sx={{ mt: 1 }}
              >
                Refresh
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Main Content Tabs */}
      <Card>
        <CardHeader
          title="Compliance Management"
          action={
            <Button
              variant="contained"
              startIcon={<GetApp />}
              onClick={() => generateComplianceReport('executive')}
            >
              Export Report
            </Button>
          }
        />
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={activeTab} onChange={handleTabChange}>
            <Tab label="Framework Status" />
            <Tab label="Violations" />
            <Tab label="Audit Trail" />
            <Tab label="Assessments" />
            <Tab label="Data Protection" />
          </Tabs>
        </Box>

        <TabPanel value={activeTab} index={0}>
          {/* Framework Status */}
          <Grid container spacing={2}>
            {complianceStatus && Object.entries(complianceStatus).map(([framework, status]) => (
              <Grid item xs={12} md={6} lg={4} key={framework}>
                <Card variant="outlined">
                  <CardContent>
                    <Box display="flex" alignItems="center" mb={2}>
                      {getFrameworkIcon(framework as ComplianceFramework)}
                      <Typography variant="h6" sx={{ ml: 1 }}>
                        {framework.toUpperCase()}
                      </Typography>
                    </Box>
                    
                    <Typography variant="h4" color={getComplianceColor(status.compliancePercentage)}>
                      {status.compliancePercentage}%
                    </Typography>
                    
                    <LinearProgress
                      variant="determinate"
                      value={status.compliancePercentage}
                      color={getComplianceColor(status.compliancePercentage)}
                      sx={{ my: 1 }}
                    />
                    
                    <Box display="flex" justifyContent="space-between" mt={2}>
                      <Typography variant="body2" color="textSecondary">
                        Controls: {status.totalControls}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Compliant: {status.compliantControls}
                      </Typography>
                    </Box>
                    
                    {status.lastAssessment && (
                      <Typography variant="body2" color="textSecondary" mt={1}>
                        Last assessed: {new Date(status.lastAssessment).toLocaleDateString()}
                      </Typography>
                    )}
                    
                    {status.nextAssessmentDue && (
                      <Typography variant="body2" color="textSecondary">
                        Next due: {new Date(status.nextAssessmentDue).toLocaleDateString()}
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        <TabPanel value={activeTab} index={1}>
          {/* Violations */}
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Framework</TableCell>
                  <TableCell>Violation Type</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Detected</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {violations?.map((violation) => (
                  <TableRow key={violation.id} hover>
                    <TableCell>
                      <Chip
                        label={violation.severity.toUpperCase()}
                        color={getSeverityColor(violation.severity)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Box display="flex" alignItems="center">
                        {getFrameworkIcon(violation.framework)}
                        <Typography sx={{ ml: 1 }}>
                          {violation.framework.toUpperCase()}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>{violation.violationType}</TableCell>
                    <TableCell>
                      <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                        {violation.description}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {new Date(violation.detectedAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={violation.status}
                        color={violation.status === 'resolved' ? 'success' : 'warning'}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <IconButton
                        size="small"
                        onClick={() => handleViolationClick(violation.id)}
                      >
                        <Visibility />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        <TabPanel value={activeTab} index={2}>
          {/* Audit Trail */}
          <Box>
            <Typography variant="h6" gutterBottom>
              Recent Audit Activity
            </Typography>
            
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>User</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Resource</TableCell>
                    <TableCell>Result</TableCell>
                    <TableCell>Risk Level</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {auditTrail?.slice(0, 10).map((entry) => (
                    <TableRow key={entry.id} hover>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(entry.timestamp).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>{entry.userId}</TableCell>
                      <TableCell>{entry.action}</TableCell>
                      <TableCell>{entry.resource}</TableCell>
                      <TableCell>
                        <Chip
                          label={entry.outcome}
                          color={entry.outcome === 'success' ? 'success' : 'error'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={entry.riskLevel || 'Low'}
                          color={entry.riskLevel === 'High' ? 'error' : 'default'}
                          size="small"
                          variant="outlined"
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </TabPanel>

        <TabPanel value={activeTab} index={3}>
          {/* Assessments */}
          <Box>
            <Typography variant="h6" gutterBottom>
              Compliance Assessments
            </Typography>
            
            {assessments?.map((assessment) => (
              <Accordion key={assessment.id}>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Box display="flex" alignItems="center" width="100%">
                    <Typography sx={{ width: '33%', flexShrink: 0 }}>
                      {assessment.framework.toUpperCase()}
                    </Typography>
                    <Typography sx={{ color: 'text.secondary' }}>
                      Score: {assessment.score}% - {new Date(assessment.timestamp).toLocaleDateString()}
                    </Typography>
                    <Box sx={{ ml: 'auto' }}>
                      <Chip
                        label={assessment.status}
                        color={assessment.status === 'passed' ? 'success' : 'error'}
                        size="small"
                      />
                    </Box>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Assessment Details
                      </Typography>
                      <List dense>
                        <ListItem>
                          <ListItemText
                            primary="Controls Assessed"
                            secondary={assessment.controlsAssessed}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText
                            primary="Compliant Controls"
                            secondary={assessment.compliantControls}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText
                            primary="Assessor"
                            secondary={assessment.assessorId}
                          />
                        </ListItem>
                      </List>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Key Findings
                      </Typography>
                      <List dense>
                        {assessment.findings.slice(0, 3).map((finding, index) => (
                          <ListItem key={index}>
                            <ListItemIcon>
                              {finding.severity === 'high' ? <Warning color="warning" /> : <Info />}
                            </ListItemIcon>
                            <ListItemText primary={finding.description} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            ))}
          </Box>
        </TabPanel>

        <TabPanel value={activeTab} index={4}>
          {/* Data Protection */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardHeader title="Data Classification" />
                <CardContent>
                  <Box mb={2}>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Public Data
                    </Typography>
                    <LinearProgress variant="determinate" value={85} color="success" />
                    <Typography variant="caption">85% properly classified</Typography>
                  </Box>
                  
                  <Box mb={2}>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Personal Data (PII)
                    </Typography>
                    <LinearProgress variant="determinate" value={92} color="success" />
                    <Typography variant="caption">92% properly protected</Typography>
                  </Box>
                  
                  <Box mb={2}>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Health Data (PHI)
                    </Typography>
                    <LinearProgress variant="determinate" value={98} color="success" />
                    <Typography variant="caption">98% HIPAA compliant</Typography>
                  </Box>
                  
                  <Box>
                    <Typography variant="body2" color="textSecondary" gutterBottom>
                      Payment Data (PCI)
                    </Typography>
                    <LinearProgress variant="determinate" value={95} color="success" />
                    <Typography variant="caption">95% PCI DSS compliant</Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Card>
                <CardHeader title="Data Protection Metrics" />
                <CardContent>
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Encryption at Rest"
                        secondary="All sensitive data encrypted with AES-256"
                      />
                    </ListItem>
                    
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Encryption in Transit"
                        secondary="TLS 1.3 for all data transmission"
                      />
                    </ListItem>
                    
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircle color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Access Controls"
                        secondary="Role-based access with MFA"
                      />
                    </ListItem>
                    
                    <ListItem>
                      <ListItemIcon>
                        <Warning color="warning" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Data Retention"
                        secondary="3 policies need review this quarter"
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>
      </Card>

      {/* Violation Details Dialog */}
      <Dialog
        open={detailsDialog}
        onClose={() => setDetailsDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Violation Details</DialogTitle>
        <DialogContent>
          {selectedViolation && violations && (
            (() => {
              const violation = violations.find(v => v.id === selectedViolation);
              return violation ? (
                <Box>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Basic Information
                      </Typography>
                      <List dense>
                        <ListItem>
                          <ListItemText
                            primary="Framework"
                            secondary={violation.framework.toUpperCase()}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText
                            primary="Severity"
                            secondary={
                              <Chip
                                label={violation.severity.toUpperCase()}
                                color={getSeverityColor(violation.severity)}
                                size="small"
                              />
                            }
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText
                            primary="Status"
                            secondary={violation.status}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText
                            primary="Detected"
                            secondary={new Date(violation.detectedAt).toLocaleString()}
                          />
                        </ListItem>
                      </List>
                    </Grid>
                    
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Impact Assessment
                      </Typography>
                      <List dense>
                        <ListItem>
                          <ListItemText
                            primary="Affected Systems"
                            secondary={violation.affectedSystems.join(', ')}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText
                            primary="Data Exposure Risk"
                            secondary={violation.dataExposureRisk}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemText
                            primary="Business Impact"
                            secondary={violation.businessImpact || 'Under assessment'}
                          />
                        </ListItem>
                      </List>
                    </Grid>
                    
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" gutterBottom>
                        Description
                      </Typography>
                      <Typography variant="body2" paragraph>
                        {violation.description}
                      </Typography>
                      
                      <Typography variant="subtitle2" gutterBottom>
                        Remediation Steps
                      </Typography>
                      <List dense>
                        {violation.remediationSteps.map((step, index) => (
                          <ListItem key={index}>
                            <ListItemText primary={`${index + 1}. ${step}`} />
                          </ListItem>
                        ))}
                      </List>
                    </Grid>
                  </Grid>
                </Box>
              ) : null;
            })()
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsDialog(false)}>
            Close
          </Button>
          {selectedViolation && (
            <Button
              variant="contained"
              color="primary"
              onClick={() => handleResolveViolation(selectedViolation)}
            >
              Mark as Resolved
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};