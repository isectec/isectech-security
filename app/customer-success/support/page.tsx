/**
 * Support Portal Page for iSECTECH Protect Customer Success Portal
 * Production-grade support system with ticketing, live chat, health monitoring, and success analytics
 */

'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  IconButton,
  Avatar,
  Chip,
  Stack,
  Tabs,
  Tab,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondaryAction,
  Badge,
  CircularProgress,
  LinearProgress,
  Alert,
  Divider,
  Tooltip,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Support as SupportIcon,
  Add as AddIcon,
  Chat as ChatIcon,
  HealthAndSafety as HealthIcon,
  Analytics as AnalyticsIcon,
  BugReport as BugIcon,
  FeatureRequest as FeatureIcon,
  Help as QuestionIcon,
  School as TrainingIcon,
  Build as TechnicalIcon,
  Payment as BillingIcon,
  MoreHoriz as MoreIcon,
  AccessTime as TimeIcon,
  Person as PersonIcon,
  Priority as PriorityIcon,
  CheckCircle as ResolvedIcon,
  Schedule as PendingIcon,
  Error as UrgentIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as StableIcon,
  Star as StarIcon,
  Send as SendIcon,
  AttachFile as AttachIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { AppLayout } from '@/components/layout/app-layout';
import { useStores } from '@/lib/store';
import type { 
  SupportTicket, 
  CustomerHealthScore,
  TicketStatus,
  TicketPriority,
  TicketCategory
} from '@/types/customer-success';

// Mock data - replace with actual API calls
const mockTickets: SupportTicket[] = [
  {
    id: '1',
    ticketNumber: 'ISEC-2024-001',
    subject: 'Unable to configure SOAR playbooks',
    description: 'I\'m having trouble setting up automated response playbooks for phishing alerts. The workflow builder seems to freeze when I try to add conditions.',
    category: 'technical-issue',
    priority: 'high',
    status: 'in-progress',
    submitter: {
      id: 'u1',
      name: 'John Smith',
      email: 'john.smith@company.com',
      avatar: '/api/placeholder/32/32',
    },
    assignee: {
      id: 'support1',
      name: 'Sarah Johnson',
      email: 'sarah@isectech.com',
      avatar: '/api/placeholder/32/32',
    },
    tags: ['soar', 'playbook', 'workflow'],
    attachments: [],
    messages: [],
    watchers: [],
    slaBreached: false,
    firstResponseTime: 45,
    internalNotes: '',
    escalationLevel: 1,
    relatedTickets: [],
    knowledgeArticles: ['kb-soar-101'],
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-30T10:30:00Z'),
    updatedAt: new Date('2024-01-30T14:20:00Z'),
  },
  {
    id: '2',
    ticketNumber: 'ISEC-2024-002',
    subject: 'Feature request: Custom dashboard widgets',
    description: 'Would like to request the ability to create custom dashboard widgets for displaying compliance metrics specific to our industry requirements.',
    category: 'feature-request',
    priority: 'normal',
    status: 'open',
    submitter: {
      id: 'u2',
      name: 'Emily Rodriguez',
      email: 'emily.r@company.com',
      avatar: '/api/placeholder/32/32',
    },
    tags: ['dashboard', 'custom', 'compliance'],
    attachments: [],
    messages: [],
    watchers: [],
    slaBreached: false,
    internalNotes: '',
    escalationLevel: 0,
    relatedTickets: [],
    knowledgeArticles: [],
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-29T09:15:00Z'),
    updatedAt: new Date('2024-01-29T09:15:00Z'),
  },
  {
    id: '3',
    ticketNumber: 'ISEC-2024-003',
    subject: 'System performance degradation',
    description: 'Experiencing slow response times across the platform, especially in the threat analytics dashboard. Load times have increased significantly over the past week.',
    category: 'technical-issue',
    priority: 'urgent',
    status: 'escalated',
    submitter: {
      id: 'u3',
      name: 'Michael Chen',
      email: 'mchen@company.com',
      avatar: '/api/placeholder/32/32',
    },
    assignee: {
      id: 'support2',
      name: 'David Wilson',
      email: 'david@isectech.com',
      avatar: '/api/placeholder/32/32',
    },
    tags: ['performance', 'analytics', 'urgent'],
    attachments: [],
    messages: [],
    watchers: [],
    slaBreached: true,
    escalationLevel: 2,
    relatedTickets: [],
    knowledgeArticles: [],
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-28T16:45:00Z'),
    updatedAt: new Date('2024-01-30T11:30:00Z'),
  },
];

const mockHealthScore: CustomerHealthScore = {
  id: 'health-1',
  customerId: 'customer-1',
  tenantId: 'tenant-1',
  overallScore: 78,
  metrics: {
    engagement: {
      score: 85,
      lastLogin: new Date('2024-01-30T08:00:00Z'),
      sessionFrequency: 4.2,
      featureAdoption: 0.68,
    },
    adoption: {
      score: 72,
      featuresUsed: 18,
      totalFeatures: 25,
      advancedFeatureUsage: 0.45,
    },
    support: {
      score: 68,
      ticketCount: 12,
      avgResolutionTime: 48,
      satisfactionRating: 4.2,
      escalationRate: 0.08,
    },
    training: {
      score: 88,
      coursesCompleted: 7,
      certificationsEarned: 3,
      lastTrainingActivity: new Date('2024-01-25T14:00:00Z'),
    },
    billing: {
      score: 95,
      paymentHistory: 'good',
      renewalProbability: 0.92,
    },
  },
  riskLevel: 'medium',
  recommendations: [
    {
      type: 'feature-adoption',
      title: 'Explore Advanced Analytics',
      description: 'Consider using our advanced threat analytics features to improve security posture.',
      priority: 'medium',
      action: 'Schedule a training session',
    },
    {
      type: 'support',
      title: 'Reduce Ticket Volume',
      description: 'Recent support tickets indicate knowledge gaps that could be addressed with training.',
      priority: 'high',
      action: 'Enroll in relevant courses',
    },
  ],
  trendDirection: 'stable',
  lastUpdated: new Date('2024-01-30T12:00:00Z'),
  nextReviewDate: new Date('2024-02-15T12:00:00Z'),
  createdAt: new Date('2024-01-01T00:00:00Z'),
  updatedAt: new Date('2024-01-30T12:00:00Z'),
};

const statusColors = {
  open: '#2196f3',
  'in-progress': '#ff9800',
  'waiting-customer': '#9c27b0',
  resolved: '#4caf50',
  closed: '#757575',
  escalated: '#f44336',
};

const priorityColors = {
  low: '#4caf50',
  normal: '#2196f3',
  high: '#ff9800',
  urgent: '#f44336',
  critical: '#9c27b0',
};

const categoryIcons = {
  bug: BugIcon,
  'feature-request': FeatureIcon,
  question: QuestionIcon,
  training: TrainingIcon,
  'technical-issue': TechnicalIcon,
  billing: BillingIcon,
  other: MoreIcon,
};

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`support-tabpanel-${index}`}
      aria-labelledby={`support-tab-${index}`}
    >
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

function SupportPortalPage() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { auth, app } = useStores();
  
  const [tabValue, setTabValue] = useState(0);
  const [newTicketOpen, setNewTicketOpen] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  
  const [tickets] = useState<SupportTicket[]>(mockTickets);
  const [healthScore] = useState<CustomerHealthScore>(mockHealthScore);
  
  // New ticket form state
  const [newTicket, setNewTicket] = useState({
    subject: '',
    description: '',
    category: 'question' as TicketCategory,
    priority: 'normal' as TicketPriority,
  });

  const ticketsByStatus = useMemo(() => {
    const grouped: Record<TicketStatus, SupportTicket[]> = {
      open: [],
      'in-progress': [],
      'waiting-customer': [],
      resolved: [],
      closed: [],
      escalated: [],
    };
    
    tickets.forEach(ticket => {
      grouped[ticket.status].push(ticket);
    });
    
    return grouped;
  }, [tickets]);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleNewTicketSubmit = async () => {
    if (!newTicket.subject.trim() || !newTicket.description.trim()) {
      app.showError('Validation Error', 'Subject and description are required.');
      return;
    }

    setLoading(true);
    // API call to create ticket
    setTimeout(() => {
      app.showSuccess('Support ticket created successfully!');
      setNewTicketOpen(false);
      setNewTicket({
        subject: '',
        description: '',
        category: 'question',
        priority: 'normal',
      });
      setLoading(false);
    }, 1000);
  };

  const getHealthScoreColor = (score: number) => {
    if (score >= 80) return '#4caf50';
    if (score >= 60) return '#ff9800';
    return '#f44336';
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'improving': return TrendingUpIcon;
      case 'declining': return TrendingDownIcon;
      default: return StableIcon;
    }
  };

  const TicketCard = ({ ticket }: { ticket: SupportTicket }) => {
    const CategoryIcon = categoryIcons[ticket.category];
    
    return (
      <Card 
        sx={{ 
          mb: 2,
          cursor: 'pointer',
          transition: 'all 0.2s ease-in-out',
          '&:hover': {
            transform: 'translateY(-1px)',
            boxShadow: theme.shadows[4],
          },
        }}
      >
        <CardContent sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'flex-start', mb: 2 }}>
            <Avatar sx={{ bgcolor: priorityColors[ticket.priority], mr: 2 }}>
              <CategoryIcon />
            </Avatar>
            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  {ticket.subject}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {ticket.ticketNumber}
                </Typography>
              </Box>
              <Typography 
                variant="body2" 
                color="text.secondary" 
                sx={{ 
                  mb: 2,
                  display: '-webkit-box',
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: 'vertical',
                  overflow: 'hidden',
                }}
              >
                {ticket.description}
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
                <Chip
                  label={ticket.status.replace('-', ' ')}
                  size="small"
                  sx={{ 
                    bgcolor: statusColors[ticket.status] + '20',
                    color: statusColors[ticket.status],
                    fontWeight: 600,
                  }}
                />
                <Chip
                  label={ticket.priority}
                  size="small"
                  sx={{ 
                    bgcolor: priorityColors[ticket.priority] + '20',
                    color: priorityColors[ticket.priority],
                    fontWeight: 600,
                  }}
                />
                <Chip
                  label={ticket.category.replace('-', ' ')}
                  size="small"
                  variant="outlined"
                />
                {ticket.slaBreached && (
                  <Chip
                    label="SLA Breached"
                    size="small"
                    color="error"
                    variant="outlined"
                  />
                )}
              </Stack>
            </Box>
          </Box>

          <Divider sx={{ mb: 2 }} />

          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Stack direction="row" spacing={2} alignItems="center">
              {ticket.assignee ? (
                <Stack direction="row" spacing={1} alignItems="center">
                  <Avatar src={ticket.assignee.avatar} sx={{ width: 24, height: 24 }}>
                    {ticket.assignee.name.charAt(0)}
                  </Avatar>
                  <Typography variant="caption" color="text.secondary">
                    Assigned to {ticket.assignee.name}
                  </Typography>
                </Stack>
              ) : (
                <Typography variant="caption" color="text.secondary">
                  Unassigned
                </Typography>
              )}
              {ticket.firstResponseTime && (
                <Stack direction="row" spacing={0.5} alignItems="center">
                  <TimeIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
                  <Typography variant="caption" color="text.secondary">
                    First response: {ticket.firstResponseTime}h
                  </Typography>
                </Stack>
              )}
            </Stack>
            <Typography variant="caption" color="text.secondary">
              Updated {ticket.updatedAt.toLocaleDateString()}
            </Typography>
          </Box>
        </CardContent>
      </Card>
    );
  };

  const HealthMetricCard = ({ 
    title, 
    score, 
    icon, 
    details 
  }: { 
    title: string; 
    score: number; 
    icon: React.ReactNode;
    details: React.ReactNode;
  }) => (
    <Card>
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Avatar sx={{ bgcolor: getHealthScoreColor(score), mr: 2 }}>
            {icon}
          </Avatar>
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              {title}
            </Typography>
            <Typography variant="h4" sx={{ fontWeight: 700, color: getHealthScoreColor(score) }}>
              {score}
            </Typography>
          </Box>
        </Box>
        <LinearProgress 
          variant="determinate" 
          value={score}
          sx={{ 
            height: 8, 
            borderRadius: 4, 
            mb: 2,
            bgcolor: getHealthScoreColor(score) + '20',
            '& .MuiLinearProgress-bar': {
              bgcolor: getHealthScoreColor(score),
            },
          }}
        />
        <Box sx={{ color: 'text.secondary' }}>
          {details}
        </Box>
      </CardContent>
    </Card>
  );

  return (
    <AppLayout>
      <Box sx={{ p: { xs: 2, md: 3 } }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
            Support Portal
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Get help, track tickets, and monitor your success metrics
          </Typography>
        </Box>

        {/* Quick Actions */}
        <Stack direction="row" spacing={2} sx={{ mb: 4 }}>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setNewTicketOpen(true)}
          >
            Create Ticket
          </Button>
          <Button
            variant="outlined"
            startIcon={<ChatIcon />}
            onClick={() => setChatOpen(true)}
          >
            Live Chat
          </Button>
        </Stack>

        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label={`My Tickets (${tickets.length})`} />
            <Tab label="Customer Health" />
            <Tab label="Success Analytics" />
          </Tabs>
        </Box>

        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={8}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                Recent Tickets
              </Typography>
              {tickets.map((ticket) => (
                <TicketCard key={ticket.id} ticket={ticket} />
              ))}
            </Grid>
            <Grid item xs={12} md={4}>
              <Stack spacing={3}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                      Ticket Summary
                    </Typography>
                    <Stack spacing={2}>
                      {Object.entries(ticketsByStatus).map(([status, statusTickets]) => (
                        <Box key={status} sx={{ display: 'flex', justifyContent: 'space-between' }}>
                          <Typography variant="body2" color="text.secondary">
                            {status.replace('-', ' ')}
                          </Typography>
                          <Typography variant="body2" fontWeight={600}>
                            {statusTickets.length}
                          </Typography>
                        </Box>
                      ))}
                    </Stack>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                      Support Resources
                    </Typography>
                    <Stack spacing={2}>
                      <Button variant="outlined" fullWidth>
                        Knowledge Base
                      </Button>
                      <Button variant="outlined" fullWidth>
                        Video Tutorials
                      </Button>
                      <Button variant="outlined" fullWidth>
                        Community Forums
                      </Button>
                      <Button variant="outlined" fullWidth>
                        Schedule Call
                      </Button>
                    </Stack>
                  </CardContent>
                </Card>
              </Stack>
            </Grid>
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ p: 3 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'between', mb: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Avatar sx={{ bgcolor: getHealthScoreColor(healthScore.overallScore), width: 56, height: 56, mr: 3 }}>
                        <HealthIcon sx={{ fontSize: 32 }} />
                      </Avatar>
                      <Box>
                        <Typography variant="h4" sx={{ fontWeight: 700, color: getHealthScoreColor(healthScore.overallScore) }}>
                          {healthScore.overallScore}
                        </Typography>
                        <Typography variant="h6" color="text.secondary">
                          Overall Health Score
                        </Typography>
                      </Box>
                    </Box>
                    <Box sx={{ textAlign: 'right' }}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        {React.createElement(getTrendIcon(healthScore.trendDirection), {
                          sx: { 
                            color: healthScore.trendDirection === 'improving' ? '#4caf50' : 
                                   healthScore.trendDirection === 'declining' ? '#f44336' : '#757575'
                          }
                        })}
                        <Typography variant="body2" color="text.secondary">
                          {healthScore.trendDirection}
                        </Typography>
                      </Stack>
                      <Chip
                        label={`${healthScore.riskLevel} risk`}
                        size="small"
                        color={healthScore.riskLevel === 'low' ? 'success' : 
                               healthScore.riskLevel === 'medium' ? 'warning' : 'error'}
                        sx={{ mt: 1 }}
                      />
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6} lg={3}>
              <HealthMetricCard
                title="Engagement"
                score={healthScore.metrics.engagement.score}
                icon={<PersonIcon />}
                details={
                  <Stack spacing={1}>
                    <Typography variant="body2">
                      Last login: {healthScore.metrics.engagement.lastLogin.toLocaleDateString()}
                    </Typography>
                    <Typography variant="body2">
                      Sessions/week: {healthScore.metrics.engagement.sessionFrequency}
                    </Typography>
                    <Typography variant="body2">
                      Feature adoption: {Math.round(healthScore.metrics.engagement.featureAdoption * 100)}%
                    </Typography>
                  </Stack>
                }
              />
            </Grid>

            <Grid item xs={12} md={6} lg={3}>
              <HealthMetricCard
                title="Feature Adoption"
                score={healthScore.metrics.adoption.score}
                icon={<TrendingUpIcon />}
                details={
                  <Stack spacing={1}>
                    <Typography variant="body2">
                      Features used: {healthScore.metrics.adoption.featuresUsed}/{healthScore.metrics.adoption.totalFeatures}
                    </Typography>
                    <Typography variant="body2">
                      Advanced features: {Math.round(healthScore.metrics.adoption.advancedFeatureUsage * 100)}%
                    </Typography>
                  </Stack>
                }
              />
            </Grid>

            <Grid item xs={12} md={6} lg={3}>
              <HealthMetricCard
                title="Support"
                score={healthScore.metrics.support.score}
                icon={<SupportIcon />}
                details={
                  <Stack spacing={1}>
                    <Typography variant="body2">
                      Tickets: {healthScore.metrics.support.ticketCount}
                    </Typography>
                    <Typography variant="body2">
                      Avg resolution: {healthScore.metrics.support.avgResolutionTime}h
                    </Typography>
                    <Typography variant="body2">
                      Satisfaction: {healthScore.metrics.support.satisfactionRating}/5
                    </Typography>
                  </Stack>
                }
              />
            </Grid>

            <Grid item xs={12} md={6} lg={3}>
              <HealthMetricCard
                title="Training"
                score={healthScore.metrics.training.score}
                icon={<TrainingIcon />}
                details={
                  <Stack spacing={1}>
                    <Typography variant="body2">
                      Courses completed: {healthScore.metrics.training.coursesCompleted}
                    </Typography>
                    <Typography variant="body2">
                      Certifications: {healthScore.metrics.training.certificationsEarned}
                    </Typography>
                    <Typography variant="body2">
                      Last activity: {healthScore.metrics.training.lastTrainingActivity.toLocaleDateString()}
                    </Typography>
                  </Stack>
                }
              />
            </Grid>

            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                    Recommendations
                  </Typography>
                  <Stack spacing={2}>
                    {healthScore.recommendations.map((rec, index) => (
                      <Alert 
                        key={index}
                        severity={rec.priority === 'high' ? 'warning' : 'info'}
                        action={
                          <Button color="inherit" size="small">
                            {rec.action}
                          </Button>
                        }
                      >
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {rec.title}
                        </Typography>
                        <Typography variant="body2">
                          {rec.description}
                        </Typography>
                      </Alert>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent sx={{ textAlign: 'center', p: 3 }}>
                  <AnalyticsIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                  <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
                    94%
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Customer Satisfaction
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent sx={{ textAlign: 'center', p: 3 }}>
                  <TimeIcon sx={{ fontSize: 48, color: 'success.main', mb: 2 }} />
                  <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
                    2.4h
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Avg Response Time
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent sx={{ textAlign: 'center', p: 3 }}>
                  <ResolvedIcon sx={{ fontSize: 48, color: 'warning.main', mb: 2 }} />
                  <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
                    98%
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    First Call Resolution
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        {/* New Ticket Dialog */}
        <Dialog 
          open={newTicketOpen} 
          onClose={() => setNewTicketOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>Create Support Ticket</DialogTitle>
          <DialogContent>
            <Stack spacing={3} sx={{ pt: 1 }}>
              <TextField
                fullWidth
                label="Subject"
                value={newTicket.subject}
                onChange={(e) => setNewTicket(prev => ({ ...prev, subject: e.target.value }))}
                required
              />
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth required>
                    <InputLabel>Category</InputLabel>
                    <Select
                      value={newTicket.category}
                      label="Category"
                      onChange={(e) => setNewTicket(prev => ({ ...prev, category: e.target.value as TicketCategory }))}
                    >
                      <MenuItem value="bug">Bug Report</MenuItem>
                      <MenuItem value="feature-request">Feature Request</MenuItem>
                      <MenuItem value="question">Question</MenuItem>
                      <MenuItem value="training">Training</MenuItem>
                      <MenuItem value="technical-issue">Technical Issue</MenuItem>
                      <MenuItem value="billing">Billing</MenuItem>
                      <MenuItem value="other">Other</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth required>
                    <InputLabel>Priority</InputLabel>
                    <Select
                      value={newTicket.priority}
                      label="Priority"
                      onChange={(e) => setNewTicket(prev => ({ ...prev, priority: e.target.value as TicketPriority }))}
                    >
                      <MenuItem value="low">Low</MenuItem>
                      <MenuItem value="normal">Normal</MenuItem>
                      <MenuItem value="high">High</MenuItem>
                      <MenuItem value="urgent">Urgent</MenuItem>
                      <MenuItem value="critical">Critical</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>

              <TextField
                fullWidth
                label="Description"
                multiline
                rows={6}
                value={newTicket.description}
                onChange={(e) => setNewTicket(prev => ({ ...prev, description: e.target.value }))}
                placeholder="Please provide a detailed description of your issue or request..."
                required
              />
            </Stack>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setNewTicketOpen(false)}>
              Cancel
            </Button>
            <Button 
              variant="contained" 
              onClick={handleNewTicketSubmit}
              disabled={loading}
            >
              {loading ? <CircularProgress size={20} /> : 'Create Ticket'}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Live Chat Dialog */}
        <Dialog 
          open={chatOpen} 
          onClose={() => setChatOpen(false)}
          maxWidth="sm"
          fullWidth
        >
          <DialogTitle sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <ChatIcon sx={{ mr: 1 }} />
              Live Chat Support
            </Box>
            <IconButton onClick={() => setChatOpen(false)}>
              <CloseIcon />
            </IconButton>
          </DialogTitle>
          <DialogContent sx={{ height: 400, display: 'flex', flexDirection: 'column' }}>
            <Box sx={{ 
              flexGrow: 1, 
              bgcolor: '#f5f5f5', 
              borderRadius: 1, 
              p: 2, 
              mb: 2,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Typography color="text.secondary">
                Connecting to support agent...
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <TextField
                fullWidth
                placeholder="Type your message..."
                size="small"
                InputProps={{
                  endAdornment: (
                    <IconButton size="small">
                      <AttachIcon />
                    </IconButton>
                  ),
                }}
              />
              <Button 
                variant="contained" 
                size="small"
                endIcon={<SendIcon />}
              >
                Send
              </Button>
            </Box>
          </DialogContent>
        </Dialog>
      </Box>
    </AppLayout>
  );
}

export default SupportPortalPage;