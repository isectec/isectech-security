/**
 * Customer Success Portal Integration Component
 * Production-grade integration between onboarding workflows and customer success resources
 */

'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  CardMedia,
  Typography,
  Button,
  IconButton,
  Avatar,
  Chip,
  LinearProgress,
  Stack,
  Tabs,
  Tab,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  Badge,
  Tooltip,
  Paper,
  Divider,
  Link,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  School as TrainingIcon,
  MenuBook as KnowledgeIcon,
  VideoLibrary as VideoIcon,
  Support as SupportIcon,
  Person as PersonIcon,
  Schedule as ScheduleIcon,
  TrendingUp as ProgressIcon,
  CheckCircle as CompletedIcon,
  PlayArrow as PlayIcon,
  Phone as PhoneIcon,
  Email as EmailIcon,
  Assignment as GuideIcon,
  Chat as ChatIcon,
  Help as HelpIcon,
  Star as StarIcon,
  AccessTime as TimeIcon,
  Launch as ExternalIcon,
  Bookmark as BookmarkIcon,
  Download as DownloadIcon,
  Feedback as FeedbackIcon,
} from '@mui/icons-material';
import { format, formatDistanceToNow } from 'date-fns';
import type { 
  OnboardingInstance,
  CustomerProfile,
  KnowledgeArticle,
  TrainingCourse,
  TrainingEnrollment,
} from '@/types';
import { customerSuccessService } from '@/lib/api/services/customer-success';
import { useStores } from '@/lib/store';

interface CustomerSuccessPortalProps {
  onboardingInstance: OnboardingInstance;
  customerProfile: CustomerProfile;
  className?: string;
}

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
      id={`customer-success-tabpanel-${index}`}
      aria-labelledby={`customer-success-tab-${index}`}
    >
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

export function CustomerSuccessPortal({ 
  onboardingInstance, 
  customerProfile,
  className 
}: CustomerSuccessPortalProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { app } = useStores();

  // State
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(true);
  const [resources, setResources] = useState<any>(null);
  const [trainingPath, setTrainingPath] = useState<any>(null);
  const [integrationData, setIntegrationData] = useState<any>(null);
  const [contextualHelp, setContextualHelp] = useState<any>(null);
  const [assignedCSM, setAssignedCSM] = useState<any>(null);
  const [selectedResource, setSelectedResource] = useState<any>(null);
  const [resourceDialogOpen, setResourceDialogOpen] = useState(false);
  const [supportTicketDialogOpen, setSupportTicketDialogOpen] = useState(false);
  const [csmCallDialogOpen, setCsmCallDialogOpen] = useState(false);

  // Load customer success data
  const loadCustomerSuccessData = async () => {
    try {
      setLoading(true);
      
      const currentStep = onboardingInstance.currentStep || 'account-setup';
      
      const [resourcesData, trainingData, integrationResponse, helpData] = await Promise.all([
        customerSuccessService.getOnboardingResources({
          customerType: customerProfile.customerType,
          serviceTier: customerProfile.serviceTier,
          industry: customerProfile.industry,
          complianceFrameworks: customerProfile.securityRequirements.complianceFrameworks,
          selectedServices: customerProfile.selectedServices.coreServices,
          onboardingStage: currentStep as any,
        }),
        customerSuccessService.getPersonalizedTrainingPath(customerProfile, currentStep),
        customerSuccessService.getCustomerSuccessIntegration(onboardingInstance.id),
        customerSuccessService.getContextualHelp({
          currentStep,
          customerType: customerProfile.customerType,
          serviceTier: customerProfile.serviceTier,
          userRole: 'administrator',
          previousErrors: onboardingInstance.errors.map(e => e.message),
        }),
      ]);

      setResources(resourcesData);
      setTrainingPath(trainingData);
      setIntegrationData(integrationResponse);
      setContextualHelp(helpData);
      
      // Auto-assign CSM if needed
      if (!integrationData?.assignedCSM) {
        const csmAssignment = await customerSuccessService.assignCustomerSuccessManager(onboardingInstance.id);
        setAssignedCSM(csmAssignment.assignedCSM);
      }
    } catch (error) {
      console.error('Error loading customer success data:', error);
      app.showError('Failed to load customer success resources');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCustomerSuccessData();
  }, [onboardingInstance.id, onboardingInstance.currentStep]);

  // Handlers
  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleResourceClick = (resource: any, type: string) => {
    setSelectedResource({ ...resource, type });
    setResourceDialogOpen(true);
  };

  const handleEnrollTraining = async (courseId: string) => {
    try {
      await customerSuccessService.assignAutomaticTraining(onboardingInstance.id, [courseId]);
      app.showSuccess('Successfully enrolled in training course');
      await loadCustomerSuccessData();
    } catch (error) {
      app.showError('Failed to enroll in training');
    }
  };

  const handleCreateSupportTicket = async (data: any) => {
    try {
      await customerSuccessService.createOnboardingSupportTicket({
        onboardingInstanceId: onboardingInstance.id,
        ...data,
      });
      app.showSuccess('Support ticket created successfully');
      setSupportTicketDialogOpen(false);
      await loadCustomerSuccessData();
    } catch (error) {
      app.showError('Failed to create support ticket');
    }
  };

  const handleScheduleCSMCall = async (data: any) => {
    try {
      await customerSuccessService.scheduleOnboardingCall({
        onboardingInstanceId: onboardingInstance.id,
        ...data,
      });
      app.showSuccess('CSM call scheduled successfully');
      setCsmCallDialogOpen(false);
    } catch (error) {
      app.showError('Failed to schedule call');
    }
  };

  const handleTrackProgress = async (activityType: string, resourceId: string, timeSpent?: number) => {
    try {
      await customerSuccessService.trackOnboardingProgress({
        onboardingInstanceId: onboardingInstance.id,
        completedActivities: [{
          type: activityType as any,
          resourceId,
          completedAt: new Date(),
          timeSpent,
        }],
      });
    } catch (error) {
      console.error('Error tracking progress:', error);
    }
  };

  // Computed values
  const progressSummary = useMemo(() => {
    if (!integrationData) return null;
    
    const { engagementMetrics } = integrationData;
    return {
      knowledgeProgress: Math.round((engagementMetrics.knowledgeBaseUsage.articlesViewed / 10) * 100),
      trainingProgress: Math.round((engagementMetrics.trainingProgress.coursesCompleted / Math.max(1, engagementMetrics.trainingProgress.coursesEnrolled)) * 100),
      supportHealth: engagementMetrics.supportInteraction.satisfactionRating * 20, // Convert 1-5 to 0-100
    };
  }, [integrationData]);

  if (loading) {
    return (
      <Box className={className} sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>Customer Success Resources</Typography>
        <LinearProgress />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          Loading personalized resources and training recommendations...
        </Typography>
      </Box>
    );
  }

  return (
    <Box className={className} sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 600, mb: 1 }}>
            Customer Success Portal
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Personalized resources, training, and support for {customerProfile.companyName}
          </Typography>
        </Box>
        
        {assignedCSM && (
          <Card sx={{ p: 2, minWidth: 250 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Avatar src={assignedCSM.avatar} sx={{ width: 48, height: 48 }}>
                {assignedCSM.name.charAt(0)}
              </Avatar>
              <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                <Typography variant="subtitle2" fontWeight={600}>
                  Your Customer Success Manager
                </Typography>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {assignedCSM.name}
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                  <IconButton size="small" onClick={() => setCsmCallDialogOpen(true)}>
                    <PhoneIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" href={`mailto:${assignedCSM.email}`}>
                    <EmailIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => setCsmCallDialogOpen(true)}>
                    <ChatIcon fontSize="small" />
                  </IconButton>
                </Stack>
              </Box>
            </Box>
          </Card>
        )}
      </Box>

      {/* Progress Summary Cards */}
      {progressSummary && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="overline">
                      Knowledge Base Progress
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, color: 'primary.main' }}>
                      {progressSummary.knowledgeProgress}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Articles and guides reviewed
                    </Typography>
                  </Box>
                  <Avatar sx={{ bgcolor: 'primary.main', width: 56, height: 56 }}>
                    <KnowledgeIcon />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="overline">
                      Training Progress
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, color: 'success.main' }}>
                      {progressSummary.trainingProgress}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Courses completed
                    </Typography>
                  </Box>
                  <Avatar sx={{ bgcolor: 'success.main', width: 56, height: 56 }}>
                    <TrainingIcon />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="overline">
                      Support Health
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, color: 'info.main' }}>
                      {progressSummary.supportHealth}%
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Satisfaction rating
                    </Typography>
                  </Box>
                  <Avatar sx={{ bgcolor: 'info.main', width: 56, height: 56 }}>
                    <SupportIcon />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Contextual Help Banner */}
      {contextualHelp?.articles.length > 0 && (
        <Alert 
          severity="info" 
          sx={{ mb: 3 }}
          action={
            <Button 
              color="inherit" 
              size="small" 
              onClick={() => handleResourceClick(contextualHelp.articles[0], 'contextual-help')}
            >
              View Help
            </Button>
          }
        >
          <Typography variant="subtitle2">Need help with your current step?</Typography>
          <Typography variant="body2">
            We found {contextualHelp.articles.length} articles that might help with "{onboardingInstance.currentStep?.replace('-', ' ')}"
          </Typography>
        </Alert>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab 
            label={`Training Path (${trainingPath?.trainingPath?.length || 0})`}
            icon={<TrainingIcon />}
            iconPosition="start"
          />
          <Tab 
            label={`Knowledge Base (${resources?.knowledgeArticles?.length || 0})`}
            icon={<KnowledgeIcon />}
            iconPosition="start"
          />
          <Tab 
            label={`Quick Start Guides (${resources?.quickStartGuides?.length || 0})`}
            icon={<GuideIcon />}
            iconPosition="start"
          />
          <Tab 
            label={`Video Library (${resources?.videoLibrary?.length || 0})`}
            icon={<VideoIcon />}
            iconPosition="start"
          />
          <Tab 
            label="Support"
            icon={<SupportIcon />}
            iconPosition="start"
          />
        </Tabs>
      </Box>

      {/* Training Path Tab */}
      <TabPanel value={tabValue} index={0}>
        {trainingPath?.trainingPath?.map((path: any, pathIndex: number) => (
          <Card key={path.id} sx={{ mb: 3 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Box>
                  <Typography variant="h6" fontWeight={600}>
                    {path.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {path.description}
                  </Typography>
                </Box>
                <Chip
                  label={path.priority}
                  color={path.priority === 'required' ? 'error' : path.priority === 'recommended' ? 'warning' : 'default'}
                  variant="outlined"
                />
              </Box>
              
              <Stack spacing={1} sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary">
                  Estimated Duration: {path.estimatedDuration} hours
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={(pathIndex + 1) / trainingPath.trainingPath.length * 100}
                  sx={{ height: 6, borderRadius: 3 }}
                />
              </Stack>

              <Grid container spacing={2}>
                {path.courses.map((course: TrainingCourse) => (
                  <Grid item xs={12} sm={6} md={4} key={course.id}>
                    <Card 
                      variant="outlined" 
                      sx={{ cursor: 'pointer', '&:hover': { boxShadow: 2 } }}
                      onClick={() => handleResourceClick(course, 'training-course')}
                    >
                      <CardContent sx={{ p: 2 }}>
                        <Typography variant="subtitle2" fontWeight={600} noWrap>
                          {course.title}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          {course.shortDescription}
                        </Typography>
                        <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
                          <Stack direction="row" spacing={0.5} alignItems="center">
                            <TimeIcon sx={{ fontSize: 14 }} />
                            <Typography variant="caption">{course.estimatedHours}h</Typography>
                          </Stack>
                          <Button 
                            size="small" 
                            onClick={(e) => {
                              e.stopPropagation();
                              handleEnrollTraining(course.id);
                            }}
                          >
                            Enroll
                          </Button>
                        </Stack>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        ))}
      </TabPanel>

      {/* Knowledge Base Tab */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          {resources?.knowledgeArticles?.map((article: KnowledgeArticle) => (
            <Grid item xs={12} md={6} key={article.id}>
              <Card 
                sx={{ 
                  cursor: 'pointer', 
                  '&:hover': { boxShadow: 4 },
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                }}
                onClick={() => {
                  handleResourceClick(article, 'knowledge-article');
                  handleTrackProgress('article-viewed', article.id);
                }}
              >
                <CardContent sx={{ flexGrow: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Chip 
                      label={article.category} 
                      size="small" 
                      sx={{ mr: 1 }}
                    />
                    <Chip 
                      label={article.difficulty} 
                      size="small" 
                      color={article.difficulty === 'beginner' ? 'success' : 
                             article.difficulty === 'intermediate' ? 'warning' : 'error'}
                    />
                  </Box>
                  
                  <Typography variant="h6" fontWeight={600} sx={{ mb: 1 }}>
                    {article.title}
                  </Typography>
                  
                  <Typography 
                    variant="body2" 
                    color="text.secondary" 
                    sx={{ 
                      mb: 2,
                      display: '-webkit-box',
                      WebkitLineClamp: 3,
                      WebkitBoxOrient: 'vertical',
                      overflow: 'hidden',
                    }}
                  >
                    {article.summary}
                  </Typography>

                  <Stack direction="row" spacing={2} alignItems="center">
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <TimeIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
                      <Typography variant="caption" color="text.secondary">
                        {article.estimatedReadTime} min read
                      </Typography>
                    </Stack>
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <StarIcon sx={{ fontSize: 16, color: 'warning.main' }} />
                      <Typography variant="caption" color="text.secondary">
                        {((article.upvotes / Math.max(1, article.upvotes + article.downvotes)) * 5).toFixed(1)}
                      </Typography>
                    </Stack>
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Quick Start Guides Tab */}
      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          {resources?.quickStartGuides?.map((guide: any) => (
            <Grid item xs={12} key={guide.id}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Box>
                      <Typography variant="h6" fontWeight={600}>
                        {guide.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {guide.description}
                      </Typography>
                    </Box>
                    <Box sx={{ textAlign: 'right' }}>
                      <Typography variant="caption" color="text.secondary">
                        Estimated time: {guide.estimatedDuration} minutes
                      </Typography>
                      <Box sx={{ mt: 1 }}>
                        <LinearProgress 
                          variant="determinate" 
                          value={(guide.steps.filter((s: any) => s.isCompleted).length / guide.steps.length) * 100}
                          sx={{ width: 100, height: 6, borderRadius: 3 }}
                        />
                      </Box>
                    </Box>
                  </Box>

                  <List>
                    {guide.steps.map((step: any) => (
                      <ListItem key={step.id}>
                        <ListItemIcon>
                          {step.isCompleted ? (
                            <CompletedIcon color="success" />
                          ) : (
                            <Avatar sx={{ width: 24, height: 24, fontSize: 12 }}>
                              {step.order}
                            </Avatar>
                          )}
                        </ListItemIcon>
                        <ListItemText
                          primary={step.title}
                          secondary={step.description}
                          sx={{
                            textDecoration: step.isCompleted ? 'line-through' : 'none',
                            opacity: step.isCompleted ? 0.7 : 1,
                          }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Video Library Tab */}
      <TabPanel value={tabValue} index={3}>
        <Grid container spacing={3}>
          {resources?.videoLibrary?.map((video: any) => (
            <Grid item xs={12} sm={6} md={4} key={video.id}>
              <Card 
                sx={{ 
                  cursor: 'pointer', 
                  '&:hover': { boxShadow: 4 } 
                }}
                onClick={() => {
                  handleResourceClick(video, 'video');
                  handleTrackProgress('video-watched', video.id, video.duration);
                }}
              >
                <CardMedia
                  component="img"
                  height="140"
                  image={video.thumbnailUrl}
                  alt={video.title}
                  sx={{ position: 'relative' }}
                />
                <Box 
                  sx={{
                    position: 'absolute',
                    top: 8,
                    right: 8,
                    bgcolor: 'rgba(0,0,0,0.7)',
                    color: 'white',
                    px: 1,
                    py: 0.5,
                    borderRadius: 1,
                    fontSize: 12,
                  }}
                >
                  {Math.floor(video.duration / 60)}:{(video.duration % 60).toString().padStart(2, '0')}
                </Box>
                <CardContent>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    {video.title}
                  </Typography>
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
                    {video.description}
                  </Typography>
                  <Stack direction="row" spacing={1}>
                    <Chip label={video.category} size="small" />
                    <Chip 
                      label={video.difficulty} 
                      size="small" 
                      color={video.difficulty === 'beginner' ? 'success' : 
                             video.difficulty === 'intermediate' ? 'warning' : 'error'}
                    />
                  </Stack>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      {/* Support Tab */}
      <TabPanel value={tabValue} index={4}>
        <Grid container spacing={3}>
          {/* Support Contacts */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                  Support Team
                </Typography>
                <List>
                  {resources?.supportContacts?.map((contact: any, index: number) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <Avatar sx={{ width: 40, height: 40 }}>
                          {contact.name.charAt(0)}
                        </Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={contact.name}
                        secondary={
                          <Stack spacing={0.5}>
                            <Typography variant="body2">
                              {contact.type.replace('-', ' ')} • {contact.timezone}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              Available: {contact.availability}
                            </Typography>
                          </Stack>
                        }
                      />
                      <ListItemSecondaryAction>
                        <Stack direction="row" spacing={1}>
                          <IconButton size="small" href={`mailto:${contact.email}`}>
                            <EmailIcon />
                          </IconButton>
                          {contact.phone && (
                            <IconButton size="small" href={`tel:${contact.phone}`}>
                              <PhoneIcon />
                            </IconButton>
                          )}
                        </Stack>
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          {/* Quick Actions */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                  Get Help
                </Typography>
                <Stack spacing={2}>
                  <Button
                    variant="outlined"
                    startIcon={<SupportIcon />}
                    fullWidth
                    onClick={() => setSupportTicketDialogOpen(true)}
                  >
                    Create Support Ticket
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<ScheduleIcon />}
                    fullWidth
                    onClick={() => setCsmCallDialogOpen(true)}
                  >
                    Schedule Call with CSM
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<ChatIcon />}
                    fullWidth
                  >
                    Start Live Chat
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<HelpIcon />}
                    fullWidth
                    onClick={() => handleResourceClick(contextualHelp?.articles?.[0], 'contextual-help')}
                  >
                    View Contextual Help
                  </Button>
                </Stack>
              </CardContent>
            </Card>
          </Grid>

          {/* Recent Support Activity */}
          {contextualHelp?.relatedTickets?.length > 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                    Related Support Cases
                  </Typography>
                  <List>
                    {contextualHelp.relatedTickets.slice(0, 3).map((ticket: any) => (
                      <ListItem key={ticket.id}>
                        <ListItemText
                          primary={ticket.subject}
                          secondary={
                            <Box>
                              <Typography variant="body2" sx={{ mb: 0.5 }}>
                                Status: {ticket.status} • {format(new Date(ticket.createdAt), 'MMM d, yyyy')}
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                {ticket.resolution}
                              </Typography>
                            </Box>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* Resource Dialog */}
      <Dialog
        open={resourceDialogOpen}
        onClose={() => setResourceDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        {selectedResource && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                {selectedResource.type === 'training-course' && <TrainingIcon />}
                {selectedResource.type === 'knowledge-article' && <KnowledgeIcon />}
                {selectedResource.type === 'video' && <VideoIcon />}
                {selectedResource.type === 'contextual-help' && <HelpIcon />}
                <Box>
                  <Typography variant="h6">
                    {selectedResource.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {selectedResource.type.replace('-', ' ')}
                  </Typography>
                </Box>
              </Box>
            </DialogTitle>
            <DialogContent>
              <Typography variant="body1" sx={{ mb: 2 }}>
                {selectedResource.description || selectedResource.summary}
              </Typography>
              
              {selectedResource.type === 'video' && (
                <Box sx={{ textAlign: 'center', mb: 2 }}>
                  <Button
                    variant="contained"
                    startIcon={<PlayIcon />}
                    size="large"
                    href={selectedResource.videoUrl}
                    target="_blank"
                  >
                    Watch Video
                  </Button>
                </Box>
              )}
              
              {selectedResource.learningObjectives && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>
                    Learning Objectives
                  </Typography>
                  <List dense>
                    {selectedResource.learningObjectives.map((objective: string, index: number) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          <CheckCircle color="primary" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={objective} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setResourceDialogOpen(false)}>
                Close
              </Button>
              {selectedResource.type === 'training-course' && (
                <Button 
                  variant="contained" 
                  onClick={() => handleEnrollTraining(selectedResource.id)}
                >
                  Enroll Now
                </Button>
              )}
              {selectedResource.type === 'knowledge-article' && (
                <Button 
                  variant="contained"
                  startIcon={<ExternalIcon />}
                  href={`/customer-success/knowledge-base/${selectedResource.slug}`}
                  target="_blank"
                >
                  Read Article
                </Button>
              )}
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
}

export default CustomerSuccessPortal;