'use client';

/**
 * Domain and Email Template Management Page
 * Administrative interface for white-labeling domain configuration and email customization
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Card,
  CardContent,
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
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Switch,
  FormControlLabel,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Email as EmailIcon,
  Domain as DomainIcon,
  Dns as DnsIcon,
  Check as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Preview as PreviewIcon,
  Send as SendIcon,
  ExpandMore as ExpandMoreIcon,
  FileCopy as CopyIcon,
} from '@mui/icons-material';

import { domainManager } from '@/lib/white-labeling/domain-manager';
import { emailTemplateManager } from '@/lib/white-labeling/email-template-manager';
import type { 
  DomainConfiguration, 
  EmailTemplate, 
  EmailType,
  DomainType 
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

export default function DomainEmailManagementPage() {
  const [tabValue, setTabValue] = useState(0);
  const [domains, setDomains] = useState<DomainConfiguration[]>([]);
  const [emailTemplates, setEmailTemplates] = useState<EmailTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Domain management state
  const [domainDialog, setDomainDialog] = useState(false);
  const [selectedDomain, setSelectedDomain] = useState<DomainConfiguration | null>(null);
  const [domainForm, setDomainForm] = useState({
    type: 'custom-domain' as DomainType,
    domain: '',
    subdomain: '',
    autoRedirect: true,
  });
  const [domainValidation, setDomainValidation] = useState<any>(null);
  
  // Email template management state
  const [emailDialog, setEmailDialog] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<EmailTemplate | null>(null);
  const [emailForm, setEmailForm] = useState({
    type: 'welcome' as EmailType,
    name: '',
    subject: '',
    htmlContent: '',
    textContent: '',
  });
  const [previewDialog, setPreviewDialog] = useState(false);
  const [emailPreview, setEmailPreview] = useState<any>(null);

  const tenantId = 'demo-tenant'; // Would get from auth context
  const userId = 'demo-user'; // Would get from auth context

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [domainData, templateData] = await Promise.all([
        domainManager.getDomainsForTenant(tenantId),
        emailTemplateManager.getTemplatesForTenant(tenantId),
      ]);
      setDomains(domainData);
      setEmailTemplates(templateData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  // Domain Management Functions
  const handleCreateDomain = async () => {
    try {
      const domain = await domainManager.configureDomain(tenantId, domainForm, userId);
      setDomains([...domains, domain]);
      setDomainDialog(false);
      resetDomainForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create domain');
    }
  };

  const handleValidateDomain = async (domain: string) => {
    try {
      const validation = await domainManager.validateDnsRecords(domain, tenantId);
      setDomainValidation(validation);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to validate domain');
    }
  };

  const handleRequestSSL = async (domain: string) => {
    try {
      await domainManager.requestSslCertificate(domain, tenantId);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to request SSL certificate');
    }
  };

  const handleDeleteDomain = async (domain: string) => {
    try {
      await domainManager.deleteDomainConfiguration(domain, tenantId, userId);
      setDomains(domains.filter(d => d.domain !== domain));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete domain');
    }
  };

  const resetDomainForm = () => {
    setDomainForm({
      type: 'custom-domain',
      domain: '',
      subdomain: '',
      autoRedirect: true,
    });
    setSelectedDomain(null);
  };

  // Email Template Management Functions
  const handleCreateTemplate = async () => {
    try {
      const template = await emailTemplateManager.createEmailTemplate(
        tenantId,
        emailForm,
        userId
      );
      setEmailTemplates([...emailTemplates, template]);
      setEmailDialog(false);
      resetEmailForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create email template');
    }
  };

  const handleUpdateTemplate = async () => {
    if (!selectedTemplate) return;
    
    try {
      const updated = await emailTemplateManager.updateEmailTemplate(
        selectedTemplate.id,
        tenantId,
        emailForm,
        userId
      );
      setEmailTemplates(emailTemplates.map(t => t.id === updated.id ? updated : t));
      setEmailDialog(false);
      resetEmailForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update email template');
    }
  };

  const handlePreviewTemplate = async (template: EmailTemplate) => {
    try {
      const preview = await emailTemplateManager.previewEmailTemplate(
        template.id,
        tenantId,
        {
          variables: {
            userName: 'John Doe',
            userEmail: 'john.doe@example.com',
            companyName: 'Demo Company',
            platformName: 'iSECTECH Protect',
          },
        }
      );
      setEmailPreview(preview);
      setPreviewDialog(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to preview template');
    }
  };

  const handleSendTestEmail = async (template: EmailTemplate) => {
    const testEmail = prompt('Enter test email address:');
    if (!testEmail) return;

    try {
      await emailTemplateManager.sendTestEmail(
        template.id,
        tenantId,
        testEmail,
        {
          userName: 'Test User',
          userEmail: testEmail,
          companyName: 'Test Company',
          platformName: 'iSECTECH Protect',
        }
      );
      alert('Test email sent successfully!');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send test email');
    }
  };

  const handleDeleteTemplate = async (templateId: string) => {
    try {
      await emailTemplateManager.deleteEmailTemplate(templateId, tenantId, userId);
      setEmailTemplates(emailTemplates.filter(t => t.id !== templateId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete template');
    }
  };

  const resetEmailForm = () => {
    setEmailForm({
      type: 'welcome',
      name: '',
      subject: '',
      htmlContent: '',
      textContent: '',
    });
    setSelectedTemplate(null);
  };

  const getDomainStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'pending': return 'warning';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  const getSSLStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'pending': return 'warning';
      case 'expired': case 'failed': return 'error';
      default: return 'default';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      <Typography variant="h4" gutterBottom>
        Domain & Email Management
      </Typography>
      
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Configure custom domains and customize email templates for white-labeling.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)} sx={{ mb: 2 }}>
        <Tab icon={<DomainIcon />} label="Domain Configuration" />
        <Tab icon={<EmailIcon />} label="Email Templates" />
      </Tabs>

      {/* Domain Configuration Tab */}
      <TabPanel value={tabValue} index={0}>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">Domain Configuration</Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setDomainDialog(true)}
          >
            Add Domain
          </Button>
        </Box>

        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Domain</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>SSL Certificate</TableCell>
                <TableCell>DNS Records</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {domains.map((domain) => (
                <TableRow key={domain.id}>
                  <TableCell>
                    <Box>
                      <Typography variant="body2" fontWeight="bold">
                        {domain.domain}
                      </Typography>
                      {domain.subdomain && (
                        <Typography variant="caption" color="text.secondary">
                          Subdomain: {domain.subdomain}
                        </Typography>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip label={domain.type} size="small" />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={domain.status}
                      color={getDomainStatusColor(domain.status) as any}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Box display="flex" alignItems="center" gap={1}>
                      <Chip
                        label={domain.sslCertificate.status}
                        color={getSSLStatusColor(domain.sslCertificate.status) as any}
                        size="small"
                      />
                      {domain.sslCertificate.status === 'pending' && (
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<SecurityIcon />}
                          onClick={() => handleRequestSSL(domain.domain)}
                        >
                          Request SSL
                        </Button>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Validate DNS Records">
                      <IconButton
                        size="small"
                        onClick={() => handleValidateDomain(domain.domain)}
                      >
                        <DnsIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Box display="flex" gap={1}>
                      <Tooltip title="Edit Domain">
                        <IconButton
                          size="small"
                          onClick={() => {
                            setSelectedDomain(domain);
                            setDomainForm({
                              type: domain.type,
                              domain: domain.domain,
                              subdomain: domain.subdomain || '',
                              autoRedirect: domain.redirects.length > 0,
                            });
                            setDomainDialog(true);
                          }}
                        >
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete Domain">
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this domain?')) {
                              handleDeleteDomain(domain.domain);
                            }
                          }}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
              {domains.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography variant="body2" color="text.secondary">
                      No domains configured. Click "Add Domain" to get started.
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {/* DNS Validation Results */}
        {domainValidation && (
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                DNS Validation Results
              </Typography>
              <List>
                {domainValidation.dnsRecords.map((record: any, index: number) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      {record.found ? (
                        <CheckIcon color="success" />
                      ) : (
                        <ErrorIcon color="error" />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={`${record.type} Record: ${record.name}`}
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            Expected: {record.value}
                          </Typography>
                          {record.actualValue && (
                            <Typography variant="body2" color="text.secondary">
                              Found: {record.actualValue}
                            </Typography>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
              {domainValidation.errors.length > 0 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {domainValidation.errors.join(', ')}
                </Alert>
              )}
            </CardContent>
          </Card>
        )}
      </TabPanel>

      {/* Email Templates Tab */}
      <TabPanel value={tabValue} index={1}>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">Email Templates</Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setEmailDialog(true)}
          >
            Create Template
          </Button>
        </Box>

        <Grid container spacing={3}>
          {emailTemplates.map((template) => (
            <Grid item xs={12} md={6} lg={4} key={template.id}>
              <Card>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="start" mb={2}>
                    <Box>
                      <Typography variant="h6">{template.name}</Typography>
                      <Chip label={template.type} size="small" sx={{ mt: 1 }} />
                    </Box>
                    {template.isDefault && (
                      <Chip label="Default" size="small" color="primary" />
                    )}
                  </Box>
                  
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Subject: {template.subject}
                  </Typography>
                  
                  <Typography variant="caption" color="text.secondary" display="block">
                    Variables: {template.variables.join(', ')}
                  </Typography>
                  
                  <Box mt={2} display="flex" gap={1} flexWrap="wrap">
                    <Button
                      size="small"
                      startIcon={<PreviewIcon />}
                      onClick={() => handlePreviewTemplate(template)}
                    >
                      Preview
                    </Button>
                    <Button
                      size="small"
                      startIcon={<SendIcon />}
                      onClick={() => handleSendTestEmail(template)}
                    >
                      Test
                    </Button>
                    <Button
                      size="small"
                      startIcon={<EditIcon />}
                      onClick={() => {
                        setSelectedTemplate(template);
                        setEmailForm({
                          type: template.type,
                          name: template.name,
                          subject: template.subject,
                          htmlContent: template.htmlContent,
                          textContent: template.textContent,
                        });
                        setEmailDialog(true);
                      }}
                    >
                      Edit
                    </Button>
                    {!template.isDefault && (
                      <Button
                        size="small"
                        color="error"
                        startIcon={<DeleteIcon />}
                        onClick={() => {
                          if (confirm('Are you sure you want to delete this template?')) {
                            handleDeleteTemplate(template.id);
                          }
                        }}
                      >
                        Delete
                      </Button>
                    )}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
          {emailTemplates.length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 4 }}>
                  <EmailIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No Email Templates
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Create your first email template to get started with customization.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* Domain Configuration Dialog */}
      <Dialog open={domainDialog} onClose={() => setDomainDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {selectedDomain ? 'Edit Domain' : 'Add New Domain'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Domain Type</InputLabel>
                <Select
                  value={domainForm.type}
                  onChange={(e) => setDomainForm({ ...domainForm, type: e.target.value as DomainType })}
                  label="Domain Type"
                >
                  <MenuItem value="custom-domain">Custom Domain</MenuItem>
                  <MenuItem value="subdomain">Subdomain</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Domain"
                value={domainForm.domain}
                onChange={(e) => setDomainForm({ ...domainForm, domain: e.target.value })}
                placeholder="example.com"
                helperText="Enter your domain name without protocol (http/https)"
              />
            </Grid>
            {domainForm.type === 'subdomain' && (
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Subdomain"
                  value={domainForm.subdomain}
                  onChange={(e) => setDomainForm({ ...domainForm, subdomain: e.target.value })}
                  placeholder="app"
                  helperText="Subdomain prefix (e.g., 'app' for app.yourdomain.com)"
                />
              </Grid>
            )}
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={domainForm.autoRedirect}
                    onChange={(e) => setDomainForm({ ...domainForm, autoRedirect: e.target.checked })}
                  />
                }
                label="Automatically redirect www to non-www"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setDomainDialog(false); resetDomainForm(); }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={selectedDomain ? () => {} : handleCreateDomain}
            disabled={!domainForm.domain}
          >
            {selectedDomain ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Email Template Dialog */}
      <Dialog open={emailDialog} onClose={() => setEmailDialog(false)} maxWidth="lg" fullWidth>
        <DialogTitle>
          {selectedTemplate ? 'Edit Email Template' : 'Create Email Template'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Template Type</InputLabel>
                <Select
                  value={emailForm.type}
                  onChange={(e) => setEmailForm({ ...emailForm, type: e.target.value as EmailType })}
                  label="Template Type"
                >
                  <MenuItem value="welcome">Welcome Email</MenuItem>
                  <MenuItem value="password-reset">Password Reset</MenuItem>
                  <MenuItem value="alert-notification">Alert Notification</MenuItem>
                  <MenuItem value="report-delivery">Report Delivery</MenuItem>
                  <MenuItem value="system-notification">System Notification</MenuItem>
                  <MenuItem value="invitation">User Invitation</MenuItem>
                  <MenuItem value="reminder">Reminder</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Template Name"
                value={emailForm.name}
                onChange={(e) => setEmailForm({ ...emailForm, name: e.target.value })}
                placeholder="My Custom Welcome Email"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Email Subject"
                value={emailForm.subject}
                onChange={(e) => setEmailForm({ ...emailForm, subject: e.target.value })}
                placeholder="Welcome to {{platformName}}!"
                helperText="Use {{variableName}} for dynamic content"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={8}
                label="HTML Content"
                value={emailForm.htmlContent}
                onChange={(e) => setEmailForm({ ...emailForm, htmlContent: e.target.value })}
                placeholder="<h1>Welcome {{userName}}!</h1><p>Thank you for joining...</p>"
                helperText="HTML version of the email"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={6}
                label="Text Content"
                value={emailForm.textContent}
                onChange={(e) => setEmailForm({ ...emailForm, textContent: e.target.value })}
                placeholder="Welcome {{userName}}! Thank you for joining..."
                helperText="Plain text version (fallback for email clients that don't support HTML)"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setEmailDialog(false); resetEmailForm(); }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={selectedTemplate ? handleUpdateTemplate : handleCreateTemplate}
            disabled={!emailForm.name || !emailForm.subject || !emailForm.htmlContent}
          >
            {selectedTemplate ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Email Preview Dialog */}
      <Dialog open={previewDialog} onClose={() => setPreviewDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Email Preview</DialogTitle>
        <DialogContent>
          {emailPreview && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Subject: {emailPreview.subject}
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle1" gutterBottom>
                HTML Content:
              </Typography>
              <Box
                sx={{
                  border: '1px solid #e0e0e0',
                  borderRadius: 1,
                  p: 2,
                  mb: 2,
                  maxHeight: 300,
                  overflow: 'auto',
                }}
                dangerouslySetInnerHTML={{ __html: emailPreview.htmlContent }}
              />
              <Typography variant="subtitle1" gutterBottom>
                Text Content:
              </Typography>
              <Box
                sx={{
                  border: '1px solid #e0e0e0',
                  borderRadius: 1,
                  p: 2,
                  backgroundColor: '#f5f5f5',
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  maxHeight: 200,
                  overflow: 'auto',
                }}
              >
                {emailPreview.textContent}
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPreviewDialog(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}