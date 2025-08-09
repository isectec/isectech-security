/**
 * Training & Certification Page for iSECTECH Protect Customer Success Portal
 * Production-grade learning management system with courses, certifications, and progress tracking
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
  TextField,
  InputAdornment,
  Chip,
  Button,
  IconButton,
  Avatar,
  Divider,
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
  ListItemText,
  ListItemIcon,
  Badge,
  Tooltip,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Search as SearchIcon,
  School as CourseIcon,
  VideoLibrary as VideoIcon,
  Quiz as AssessmentIcon,
  EmojiEvents as CertificateIcon,
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  CheckCircle as CompletedIcon,
  AccessTime as TimeIcon,
  Person as PersonIcon,
  Star as StarIcon,
  Bookmark as BookmarkIcon,
  Download as DownloadIcon,
  Share as ShareIcon,
  Group as GroupIcon,
  TrendingUp as ProgressIcon,
  Assignment as AssignmentIcon,
} from '@mui/icons-material';
import { AppLayout } from '@/components/layout/app-layout';
import { useStores } from '@/lib/store';
import type { 
  TrainingCourse, 
  TrainingEnrollment, 
  TrainingProgress,
  Certificate,
  TrainingType,
  TrainingDifficulty,
  EnrollmentStatus
} from '@/types/customer-success';

// Mock data - replace with actual API calls
const mockCourses: TrainingCourse[] = [
  {
    id: '1',
    title: 'iSECTECH Protect Fundamentals',
    slug: 'isectech-protect-fundamentals',
    description: 'Master the basics of cybersecurity operations with iSECTECH Protect. This comprehensive course covers platform navigation, threat detection principles, and basic incident response workflows.',
    shortDescription: 'Learn the fundamentals of iSECTECH Protect platform.',
    type: 'course',
    difficulty: 'beginner',
    status: 'published',
    category: 'Platform Basics',
    tags: ['fundamentals', 'platform', 'getting-started'],
    instructor: {
      id: 'inst1',
      name: 'Dr. Sarah Johnson',
      avatar: '/api/placeholder/64/64',
      bio: 'Cybersecurity expert with 15 years of experience in SOC operations.',
      credentials: ['CISSP', 'CISM', 'Ph.D. Computer Science'],
    },
    duration: 240,
    estimatedHours: 4,
    prerequisites: [],
    learningObjectives: [
      'Navigate the iSECTECH Protect interface confidently',
      'Understand core cybersecurity concepts',
      'Perform basic threat detection tasks',
      'Create simple incident response workflows'
    ],
    modules: [],
    assessments: [],
    passThreshold: 80,
    maxAttempts: 3,
    validityPeriod: 365,
    enrollmentCount: 1247,
    averageRating: 4.7,
    ratingCount: 89,
    thumbnailUrl: '/api/placeholder/300/200',
    previewVideoUrl: '/api/placeholder/video/preview1',
    resources: [
      { id: 'r1', title: 'Platform Guide PDF', url: '/resources/platform-guide.pdf', type: 'pdf' },
      { id: 'r2', title: 'Quick Reference', url: '/resources/quick-ref.pdf', type: 'download' },
    ],
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-15'),
  },
  {
    id: '2',
    title: 'Advanced Threat Hunting Techniques',
    slug: 'advanced-threat-hunting-techniques',
    description: 'Deep dive into sophisticated threat hunting methodologies using iSECTECH Protect advanced analytics. Learn to identify advanced persistent threats and zero-day attacks.',
    shortDescription: 'Master advanced threat hunting with sophisticated techniques.',
    type: 'course',
    difficulty: 'advanced',
    status: 'published',
    category: 'Threat Hunting',
    tags: ['threat-hunting', 'advanced', 'analytics', 'apt'],
    instructor: {
      id: 'inst2',
      name: 'Michael Chen',
      avatar: '/api/placeholder/64/64',
      bio: 'Former NSA analyst specializing in advanced persistent threats.',
      credentials: ['GCTH', 'GNFA', 'CISSP'],
    },
    duration: 360,
    estimatedHours: 6,
    prerequisites: ['Basic Security Knowledge', 'SIEM Experience'],
    learningObjectives: [
      'Implement advanced threat hunting methodologies',
      'Analyze complex attack patterns',
      'Use advanced analytics for threat detection',
      'Create custom hunting queries'
    ],
    modules: [],
    assessments: [],
    passThreshold: 85,
    maxAttempts: 2,
    validityPeriod: 365,
    enrollmentCount: 234,
    averageRating: 4.9,
    ratingCount: 67,
    thumbnailUrl: '/api/placeholder/300/200',
    previewVideoUrl: '/api/placeholder/video/preview2',
    resources: [],
    securityClearanceRequired: 'SECRET',
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-10'),
    updatedAt: new Date('2024-01-25'),
  },
  {
    id: '3',
    title: 'Compliance Framework Implementation',
    slug: 'compliance-framework-implementation',
    description: 'Learn to implement and maintain compliance frameworks using iSECTECH Protect. Covers NIST, ISO 27001, SOC 2, and custom framework configuration.',
    shortDescription: 'Implement compliance frameworks effectively.',
    type: 'certification',
    difficulty: 'intermediate',
    status: 'published',
    category: 'Compliance',
    tags: ['compliance', 'nist', 'iso27001', 'soc2'],
    instructor: {
      id: 'inst3',
      name: 'Emily Rodriguez',
      avatar: '/api/placeholder/64/64',
      bio: 'Compliance specialist with expertise in multiple regulatory frameworks.',
      credentials: ['CISA', 'CISM', 'ISO 27001 Lead Auditor'],
    },
    duration: 300,
    estimatedHours: 5,
    prerequisites: ['Basic Compliance Knowledge'],
    learningObjectives: [
      'Configure compliance frameworks',
      'Create compliance dashboards',
      'Automate compliance reporting',
      'Manage audit workflows'
    ],
    modules: [],
    assessments: [],
    certificateTemplate: 'compliance-cert-template',
    passThreshold: 80,
    maxAttempts: 3,
    validityPeriod: 365,
    enrollmentCount: 456,
    averageRating: 4.6,
    ratingCount: 45,
    thumbnailUrl: '/api/placeholder/300/200',
    resources: [],
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-05'),
    updatedAt: new Date('2024-01-20'),
  },
];

const mockEnrollments: TrainingEnrollment[] = [
  {
    id: 'e1',
    userId: 'user1',
    courseId: '1',
    status: 'in-progress',
    progress: 65,
    startedAt: new Date('2024-01-10'),
    lastAccessedAt: new Date('2024-01-30'),
    attempts: [],
    timeSpent: 156,
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-10'),
    updatedAt: new Date('2024-01-30'),
  },
  {
    id: 'e2',
    userId: 'user1',
    courseId: '3',
    status: 'completed',
    progress: 100,
    startedAt: new Date('2024-01-01'),
    completedAt: new Date('2024-01-15'),
    lastAccessedAt: new Date('2024-01-15'),
    attempts: [],
    timeSpent: 285,
    certificateUrl: '/certificates/compliance-cert-123.pdf',
    certificateIssuedAt: new Date('2024-01-15'),
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-15'),
  },
];

const mockCertificates: Certificate[] = [
  {
    id: 'cert1',
    userId: 'user1',
    courseId: '3',
    title: 'Compliance Framework Implementation',
    description: 'Certificate of completion for advanced compliance training',
    issuedAt: new Date('2024-01-15'),
    expiresAt: new Date('2025-01-15'),
    certificateNumber: 'ISEC-COMP-2024-001',
    verificationCode: 'VF-ABC123XYZ',
    verificationUrl: 'https://verify.isectech.com/VF-ABC123XYZ',
    pdfUrl: '/certificates/compliance-cert-123.pdf',
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-15'),
    updatedAt: new Date('2024-01-15'),
  },
];

const difficultyColors = {
  beginner: '#4caf50',
  intermediate: '#ff9800',
  advanced: '#f44336',
  expert: '#9c27b0',
};

const typeIcons = {
  course: CourseIcon,
  webinar: VideoIcon,
  workshop: GroupIcon,
  certification: CertificateIcon,
  assessment: AssessmentIcon,
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
      id={`training-tabpanel-${index}`}
      aria-labelledby={`training-tab-${index}`}
    >
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

function TrainingPage() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { auth, app } = useStores();
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDifficulty, setSelectedDifficulty] = useState<TrainingDifficulty | 'all'>('all');
  const [selectedType, setSelectedType] = useState<TrainingType | 'all'>('all');
  const [tabValue, setTabValue] = useState(0);
  const [courseDetailsOpen, setCourseDetailsOpen] = useState(false);
  const [selectedCourse, setSelectedCourse] = useState<TrainingCourse | null>(null);
  const [loading, setLoading] = useState(false);
  
  const [courses] = useState<TrainingCourse[]>(mockCourses);
  const [enrollments] = useState<TrainingEnrollment[]>(mockEnrollments);
  const [certificates] = useState<Certificate[]>(mockCertificates);

  // Filter courses
  const filteredCourses = useMemo(() => {
    let filtered = courses;
    
    if (selectedDifficulty !== 'all') {
      filtered = filtered.filter(course => course.difficulty === selectedDifficulty);
    }
    
    if (selectedType !== 'all') {
      filtered = filtered.filter(course => course.type === selectedType);
    }
    
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase().trim();
      filtered = filtered.filter(course => 
        course.title.toLowerCase().includes(query) ||
        course.description.toLowerCase().includes(query) ||
        course.tags.some(tag => tag.toLowerCase().includes(query)) ||
        course.category.toLowerCase().includes(query)
      );
    }
    
    return filtered.sort((a, b) => b.enrollmentCount - a.enrollmentCount);
  }, [courses, selectedDifficulty, selectedType, searchQuery]);

  const myEnrollments = useMemo(() => {
    return enrollments.map(enrollment => {
      const course = courses.find(c => c.id === enrollment.courseId);
      return { enrollment, course };
    }).filter(item => item.course);
  }, [enrollments, courses]);

  const handleSearch = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  };

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleCourseClick = (course: TrainingCourse) => {
    setSelectedCourse(course);
    setCourseDetailsOpen(true);
  };

  const handleEnrollCourse = async (courseId: string) => {
    setLoading(true);
    // API call to enroll in course
    setTimeout(() => {
      app.showSuccess('Enrolled successfully!');
      setLoading(false);
      setCourseDetailsOpen(false);
    }, 1000);
  };

  const getEnrollmentStatus = (courseId: string): EnrollmentStatus | null => {
    const enrollment = enrollments.find(e => e.courseId === courseId);
    return enrollment?.status || null;
  };

  const getProgressColor = (progress: number) => {
    if (progress >= 80) return 'success';
    if (progress >= 60) return 'info';
    if (progress >= 40) return 'warning';
    return 'error';
  };

  const CourseCard = ({ course }: { course: TrainingCourse }) => {
    const TypeIcon = typeIcons[course.type];
    const enrollmentStatus = getEnrollmentStatus(course.id);
    const enrollment = enrollments.find(e => e.courseId === course.id);
    
    return (
      <Card 
        sx={{ 
          height: '100%', 
          display: 'flex', 
          flexDirection: 'column',
          cursor: 'pointer',
          transition: 'all 0.2s ease-in-out',
          '&:hover': {
            transform: 'translateY(-2px)',
            boxShadow: theme.shadows[8],
          },
        }}
        onClick={() => handleCourseClick(course)}
      >
        <CardMedia
          component="img"
          height="140"
          image={course.thumbnailUrl}
          alt={course.title}
        />
        <CardContent sx={{ flexGrow: 1, p: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Avatar sx={{ bgcolor: 'primary.main', width: 32, height: 32, mr: 1 }}>
              <TypeIcon sx={{ fontSize: 18 }} />
            </Avatar>
            <Box>
              <Typography variant="caption" color="text.secondary">
                {course.type.toUpperCase()}
              </Typography>
              <Typography variant="caption" display="block" color="text.secondary">
                {course.category}
              </Typography>
            </Box>
          </Box>

          <Typography 
            variant="h6" 
            sx={{ 
              fontWeight: 600,
              mb: 1,
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
            }}
          >
            {course.title}
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
            {course.shortDescription}
          </Typography>

          <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
            <Chip
              label={course.difficulty}
              size="small"
              sx={{ 
                bgcolor: difficultyColors[course.difficulty] + '20',
                color: difficultyColors[course.difficulty],
                fontWeight: 600,
              }}
            />
            {course.securityClearanceRequired && (
              <Chip
                label="Clearance Required"
                size="small"
                color="warning"
                variant="outlined"
              />
            )}
          </Stack>

          {enrollment && (
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Progress
                </Typography>
                <Typography variant="body2" fontWeight={600}>
                  {enrollment.progress}%
                </Typography>
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={enrollment.progress}
                color={getProgressColor(enrollment.progress)}
                sx={{ height: 6, borderRadius: 3 }}
              />
            </Box>
          )}

          <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
            <Stack direction="row" spacing={0.5} alignItems="center">
              <TimeIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
              <Typography variant="caption" color="text.secondary">
                {course.estimatedHours}h
              </Typography>
            </Stack>
            <Stack direction="row" spacing={0.5} alignItems="center">
              <PersonIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
              <Typography variant="caption" color="text.secondary">
                {course.enrollmentCount}
              </Typography>
            </Stack>
            <Stack direction="row" spacing={0.5} alignItems="center">
              <StarIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
              <Typography variant="caption" color="text.secondary">
                {course.averageRating} ({course.ratingCount})
              </Typography>
            </Stack>
          </Stack>

          <Divider sx={{ mb: 2 }} />

          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <Avatar 
                src={course.instructor.avatar} 
                sx={{ width: 24, height: 24 }}
              >
                {course.instructor.name.charAt(0)}
              </Avatar>
              <Typography variant="caption" color="text.secondary">
                {course.instructor.name}
              </Typography>
            </Stack>
            
            {enrollmentStatus === 'completed' && (
              <Chip 
                icon={<CompletedIcon />}
                label="Completed"
                size="small"
                color="success"
                variant="outlined"
              />
            )}
            {enrollmentStatus === 'in-progress' && (
              <Chip 
                icon={<ProgressIcon />}
                label="In Progress"
                size="small"
                color="info"
                variant="outlined"
              />
            )}
          </Box>
        </CardContent>
      </Card>
    );
  };

  return (
    <AppLayout>
      <Box sx={{ p: { xs: 2, md: 3 } }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
            Training & Certification
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Enhance your cybersecurity skills with our comprehensive training programs
          </Typography>
        </Box>

        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label="All Courses" />
            <Tab label={`My Learning (${myEnrollments.length})`} />
            <Tab label={`Certificates (${certificates.length})`} />
          </Tabs>
        </Box>

        <TabPanel value={tabValue} index={0}>
          {/* Search and Filters */}
          <Card sx={{ p: 3, mb: 4 }}>
            <TextField
              fullWidth
              placeholder="Search courses, certifications, and training programs..."
              value={searchQuery}
              onChange={handleSearch}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon color="action" />
                  </InputAdornment>
                ),
              }}
              sx={{ mb: 3 }}
            />
            
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Difficulty Level
                </Typography>
                <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
                  <Chip
                    label="All"
                    onClick={() => setSelectedDifficulty('all')}
                    color={selectedDifficulty === 'all' ? 'primary' : 'default'}
                    variant={selectedDifficulty === 'all' ? 'filled' : 'outlined'}
                  />
                  {(['beginner', 'intermediate', 'advanced', 'expert'] as TrainingDifficulty[]).map((level) => (
                    <Chip
                      key={level}
                      label={level}
                      onClick={() => setSelectedDifficulty(level)}
                      color={selectedDifficulty === level ? 'primary' : 'default'}
                      variant={selectedDifficulty === level ? 'filled' : 'outlined'}
                    />
                  ))}
                </Stack>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Training Type
                </Typography>
                <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
                  <Chip
                    label="All"
                    onClick={() => setSelectedType('all')}
                    color={selectedType === 'all' ? 'primary' : 'default'}
                    variant={selectedType === 'all' ? 'filled' : 'outlined'}
                  />
                  {(['course', 'webinar', 'workshop', 'certification', 'assessment'] as TrainingType[]).map((type) => (
                    <Chip
                      key={type}
                      label={type}
                      onClick={() => setSelectedType(type)}
                      color={selectedType === type ? 'primary' : 'default'}
                      variant={selectedType === type ? 'filled' : 'outlined'}
                    />
                  ))}
                </Stack>
              </Grid>
            </Grid>
          </Card>

          {/* Course Grid */}
          <Grid container spacing={3}>
            {filteredCourses.map((course) => (
              <Grid item xs={12} md={6} lg={4} key={course.id}>
                <CourseCard course={course} />
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Grid container spacing={3}>
            {myEnrollments.map(({ enrollment, course }) => (
              course && (
                <Grid item xs={12} key={enrollment.id}>
                  <Card>
                    <CardContent sx={{ p: 3 }}>
                      <Grid container spacing={3} alignItems="center">
                        <Grid item xs={12} md={3}>
                          <Box
                            component="img"
                            src={course.thumbnailUrl}
                            alt={course.title}
                            sx={{
                              width: '100%',
                              height: 120,
                              objectFit: 'cover',
                              borderRadius: 1,
                            }}
                          />
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Typography variant="h6" sx={{ fontWeight: 600, mb: 1 }}>
                            {course.title}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                            {course.shortDescription}
                          </Typography>
                          <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
                            <Chip
                              label={enrollment.status.replace('-', ' ')}
                              size="small"
                              color={enrollment.status === 'completed' ? 'success' : 'info'}
                              variant="outlined"
                            />
                            <Chip
                              label={course.difficulty}
                              size="small"
                              sx={{ 
                                bgcolor: difficultyColors[course.difficulty] + '20',
                                color: difficultyColors[course.difficulty],
                              }}
                            />
                          </Stack>
                          <Typography variant="caption" color="text.secondary">
                            Last accessed: {enrollment.lastAccessedAt?.toLocaleDateString()}
                          </Typography>
                        </Grid>
                        <Grid item xs={12} md={3}>
                          <Box sx={{ textAlign: 'center' }}>
                            <Typography variant="h4" sx={{ fontWeight: 700, color: 'primary.main', mb: 1 }}>
                              {enrollment.progress}%
                            </Typography>
                            <LinearProgress 
                              variant="determinate" 
                              value={enrollment.progress}
                              color={getProgressColor(enrollment.progress)}
                              sx={{ height: 8, borderRadius: 4, mb: 2 }}
                            />
                            <Button 
                              variant="contained" 
                              startIcon={enrollment.status === 'completed' ? <CompletedIcon /> : <PlayIcon />}
                              disabled={enrollment.status === 'completed'}
                              onClick={() => handleCourseClick(course)}
                            >
                              {enrollment.status === 'completed' ? 'Completed' : 'Continue'}
                            </Button>
                          </Box>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                </Grid>
              )
            ))}
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <Grid container spacing={3}>
            {certificates.map((certificate) => (
              <Grid item xs={12} md={6} lg={4} key={certificate.id}>
                <Card>
                  <CardContent sx={{ p: 3, textAlign: 'center' }}>
                    <CertificateIcon 
                      sx={{ 
                        fontSize: 64, 
                        color: 'primary.main', 
                        mb: 2 
                      }} 
                    />
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 1 }}>
                      {certificate.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {certificate.description}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      <strong>Certificate #:</strong> {certificate.certificateNumber}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      <strong>Issued:</strong> {certificate.issuedAt.toLocaleDateString()}
                    </Typography>
                    {certificate.expiresAt && (
                      <Typography variant="body2" sx={{ mb: 2 }}>
                        <strong>Expires:</strong> {certificate.expiresAt.toLocaleDateString()}
                      </Typography>
                    )}
                    <Stack direction="row" spacing={1} justifyContent="center">
                      <Button 
                        variant="outlined" 
                        size="small"
                        startIcon={<DownloadIcon />}
                      >
                        Download
                      </Button>
                      <Button 
                        variant="outlined" 
                        size="small"
                        startIcon={<ShareIcon />}
                      >
                        Share
                      </Button>
                    </Stack>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </TabPanel>

        {/* Course Details Dialog */}
        <Dialog 
          open={courseDetailsOpen} 
          onClose={() => setCourseDetailsOpen(false)}
          maxWidth="md"
          fullWidth
        >
          {selectedCourse && (
            <>
              <DialogTitle>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Avatar sx={{ bgcolor: 'primary.main' }}>
                    {React.createElement(typeIcons[selectedCourse.type])}
                  </Avatar>
                  <Box>
                    <Typography variant="h6">
                      {selectedCourse.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {selectedCourse.category} • {selectedCourse.difficulty}
                    </Typography>
                  </Box>
                </Box>
              </DialogTitle>
              <DialogContent>
                <Typography variant="body2" sx={{ mb: 3 }}>
                  {selectedCourse.description}
                </Typography>
                
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>
                      Learning Objectives
                    </Typography>
                    <List dense>
                      {selectedCourse.learningObjectives.map((objective, index) => (
                        <ListItem key={index}>
                          <ListItemIcon>
                            <CheckCircle color="primary" />
                          </ListItemIcon>
                          <ListItemText primary={objective} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Stack spacing={2}>
                      <Box>
                        <Typography variant="subtitle2">Duration</Typography>
                        <Typography variant="body2">{selectedCourse.estimatedHours} hours</Typography>
                      </Box>
                      <Box>
                        <Typography variant="subtitle2">Instructor</Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Avatar src={selectedCourse.instructor.avatar} sx={{ width: 32, height: 32 }}>
                            {selectedCourse.instructor.name.charAt(0)}
                          </Avatar>
                          <Box>
                            <Typography variant="body2">{selectedCourse.instructor.name}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {selectedCourse.instructor.credentials.join(', ')}
                            </Typography>
                          </Box>
                        </Box>
                      </Box>
                      {selectedCourse.prerequisites.length > 0 && (
                        <Box>
                          <Typography variant="subtitle2">Prerequisites</Typography>
                          {selectedCourse.prerequisites.map((prereq, index) => (
                            <Typography key={index} variant="body2">
                              • {prereq}
                            </Typography>
                          ))}
                        </Box>
                      )}
                    </Stack>
                  </Grid>
                </Grid>
              </DialogContent>
              <DialogActions>
                <Button onClick={() => setCourseDetailsOpen(false)}>
                  Cancel
                </Button>
                <Button 
                  variant="contained" 
                  onClick={() => handleEnrollCourse(selectedCourse.id)}
                  disabled={loading}
                >
                  {getEnrollmentStatus(selectedCourse.id) ? 'Continue Learning' : 'Enroll Now'}
                </Button>
              </DialogActions>
            </>
          )}
        </Dialog>
      </Box>
    </AppLayout>
  );
}

export default TrainingPage;