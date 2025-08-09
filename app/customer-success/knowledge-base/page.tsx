/**
 * Knowledge Base Page for iSECTECH Protect Customer Success Portal
 * Production-grade knowledge management system with search, categorization, and content management
 */

'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  TextField,
  InputAdornment,
  Chip,
  Button,
  IconButton,
  Avatar,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
  ListItemButton,
  Badge,
  Stack,
  Tabs,
  Tab,
  Alert,
  Skeleton,
  Tooltip,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Search as SearchIcon,
  MenuBook as DocumentationIcon,
  School as TutorialIcon,
  Lightbulb as BestPracticesIcon,
  BugReport as TroubleshootingIcon,
  NewReleases as ReleaseNotesIcon,
  HelpOutline as FaqIcon,
  ThumbUp as ThumbUpIcon,
  ThumbDown as ThumbDownIcon,
  Visibility as ViewIcon,
  Schedule as TimeIcon,
  Person as AuthorIcon,
  Add as AddIcon,
  FilterList as FilterIcon,
  Sort as SortIcon,
  BookmarkBorder as BookmarkIcon,
  Share as ShareIcon,
} from '@mui/icons-material';
import { AppLayout } from '@/components/layout/app-layout';
import { useStores } from '@/lib/store';
import type { 
  KnowledgeArticle, 
  KnowledgeCategory, 
  ContentFormat,
  KnowledgeBaseSearch 
} from '@/types/customer-success';

// Mock data - replace with actual API calls
const mockArticles: KnowledgeArticle[] = [
  {
    id: '1',
    title: 'Getting Started with Threat Detection',
    slug: 'getting-started-threat-detection',
    summary: 'Learn the fundamentals of setting up and configuring threat detection in iSECTECH Protect.',
    content: '# Getting Started...',
    format: 'markdown',
    category: 'documentation',
    status: 'published',
    tags: ['getting-started', 'threat-detection', 'security'],
    author: {
      id: 'u1',
      name: 'Sarah Johnson',
      avatar: '/api/placeholder/32/32'
    },
    publishedAt: new Date('2024-01-15'),
    lastReviewedAt: new Date('2024-01-10'),
    version: '1.2',
    viewCount: 1234,
    upvotes: 45,
    downvotes: 3,
    searchKeywords: ['threat', 'detection', 'setup', 'configuration'],
    difficulty: 'beginner',
    estimatedReadTime: 8,
    securityClassification: 'public',
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-15'),
  },
  {
    id: '2',
    title: 'Advanced SOAR Playbook Configuration',
    slug: 'advanced-soar-playbook-configuration',
    summary: 'Deep dive into creating complex automated response playbooks for security incidents.',
    content: '# Advanced SOAR...',
    format: 'markdown',
    category: 'tutorials',
    status: 'published',
    tags: ['soar', 'playbooks', 'automation', 'advanced'],
    author: {
      id: 'u2',
      name: 'Michael Chen',
      avatar: '/api/placeholder/32/32'
    },
    publishedAt: new Date('2024-01-20'),
    version: '2.1',
    viewCount: 892,
    upvotes: 67,
    downvotes: 5,
    searchKeywords: ['soar', 'playbook', 'automation', 'incident', 'response'],
    difficulty: 'advanced',
    estimatedReadTime: 15,
    securityClassification: 'internal',
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-10'),
    updatedAt: new Date('2024-01-20'),
  },
  {
    id: '3',
    title: 'Troubleshooting Authentication Issues',
    slug: 'troubleshooting-authentication-issues',
    summary: 'Common authentication problems and their solutions in iSECTECH Protect.',
    content: '# Authentication Troubleshooting...',
    format: 'markdown',
    category: 'troubleshooting',
    status: 'published',
    tags: ['authentication', 'troubleshooting', 'sso', 'login'],
    author: {
      id: 'u3',
      name: 'Emily Rodriguez',
      avatar: '/api/placeholder/32/32'
    },
    publishedAt: new Date('2024-01-25'),
    version: '1.0',
    viewCount: 567,
    upvotes: 23,
    downvotes: 2,
    searchKeywords: ['authentication', 'login', 'sso', 'error', 'troubleshoot'],
    difficulty: 'intermediate',
    estimatedReadTime: 6,
    securityClassification: 'public',
    tenantId: 'tenant-1',
    createdAt: new Date('2024-01-20'),
    updatedAt: new Date('2024-01-25'),
  },
];

const categoryIcons = {
  documentation: DocumentationIcon,
  tutorials: TutorialIcon,
  'best-practices': BestPracticesIcon,
  troubleshooting: TroubleshootingIcon,
  'release-notes': ReleaseNotesIcon,
  faq: FaqIcon,
};

const categoryColors = {
  documentation: '#1976d2',
  tutorials: '#388e3c',
  'best-practices': '#f57c00',
  troubleshooting: '#d32f2f',
  'release-notes': '#7b1fa2',
  faq: '#0288d1',
};

const difficultyColors = {
  beginner: '#4caf50',
  intermediate: '#ff9800',
  advanced: '#f44336',
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
      id={`knowledge-tabpanel-${index}`}
      aria-labelledby={`knowledge-tab-${index}`}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

function KnowledgeBasePage() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { auth, app } = useStores();
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<KnowledgeCategory | 'all'>('all');
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(false);
  const [articles, setArticles] = useState<KnowledgeArticle[]>(mockArticles);
  
  // Filter and search logic
  const filteredArticles = useMemo(() => {
    let filtered = articles;
    
    if (selectedCategory !== 'all') {
      filtered = filtered.filter(article => article.category === selectedCategory);
    }
    
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase().trim();
      filtered = filtered.filter(article => 
        article.title.toLowerCase().includes(query) ||
        article.summary.toLowerCase().includes(query) ||
        article.tags.some(tag => tag.toLowerCase().includes(query)) ||
        article.searchKeywords.some(keyword => keyword.toLowerCase().includes(query))
      );
    }
    
    return filtered.sort((a, b) => b.viewCount - a.viewCount);
  }, [articles, selectedCategory, searchQuery]);

  const popularArticles = useMemo(() => {
    return [...articles].sort((a, b) => b.viewCount - a.viewCount).slice(0, 5);
  }, [articles]);

  const recentArticles = useMemo(() => {
    return [...articles].sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime()).slice(0, 5);
  }, [articles]);

  const categoryStats = useMemo(() => {
    const stats: Record<KnowledgeCategory, number> = {
      documentation: 0,
      tutorials: 0,
      'best-practices': 0,
      troubleshooting: 0,
      'release-notes': 0,
      faq: 0,
    };
    
    articles.forEach(article => {
      stats[article.category]++;
    });
    
    return stats;
  }, [articles]);

  const handleSearch = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  };

  const handleCategorySelect = (category: KnowledgeCategory | 'all') => {
    setSelectedCategory(category);
  };

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const getDifficultyLabel = (difficulty: string) => {
    return difficulty.charAt(0).toUpperCase() + difficulty.slice(1);
  };

  const formatEstimatedTime = (minutes: number) => {
    return `${minutes} min read`;
  };

  const ArticleCard = ({ article }: { article: KnowledgeArticle }) => {
    const CategoryIcon = categoryIcons[article.category];
    
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
      >
        <CardContent sx={{ flexGrow: 1, p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'flex-start', mb: 2 }}>
            <Avatar
              sx={{ 
                bgcolor: categoryColors[article.category], 
                width: 40, 
                height: 40,
                mr: 2,
              }}
            >
              <CategoryIcon />
            </Avatar>
            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
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
                {article.title}
              </Typography>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                <Chip
                  label={article.category.replace('-', ' ')}
                  size="small"
                  sx={{ 
                    bgcolor: categoryColors[article.category] + '20',
                    color: categoryColors[article.category],
                    fontWeight: 600,
                  }}
                />
                <Chip
                  label={getDifficultyLabel(article.difficulty)}
                  size="small"
                  sx={{ 
                    bgcolor: difficultyColors[article.difficulty] + '20',
                    color: difficultyColors[article.difficulty],
                    fontWeight: 600,
                  }}
                />
              </Stack>
            </Box>
          </Box>

          <Typography 
            variant="body2" 
            color="text.secondary" 
            sx={{ 
              mb: 2,
              display: '-webkit-box',
              WebkitLineClamp: 3,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
              lineHeight: 1.6,
            }}
          >
            {article.summary}
          </Typography>

          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
            {article.tags.slice(0, 3).map((tag) => (
              <Chip
                key={tag}
                label={tag}
                size="small"
                variant="outlined"
                sx={{ fontSize: '0.7rem' }}
              />
            ))}
            {article.tags.length > 3 && (
              <Chip
                label={`+${article.tags.length - 3}`}
                size="small"
                variant="outlined"
                sx={{ fontSize: '0.7rem' }}
              />
            )}
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mt: 'auto' }}>
            <Stack direction="row" spacing={2} alignItems="center">
              <Stack direction="row" spacing={0.5} alignItems="center">
                <ViewIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
                <Typography variant="caption" color="text.secondary">
                  {article.viewCount.toLocaleString()}
                </Typography>
              </Stack>
              <Stack direction="row" spacing={0.5} alignItems="center">
                <ThumbUpIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
                <Typography variant="caption" color="text.secondary">
                  {article.upvotes}
                </Typography>
              </Stack>
              <Stack direction="row" spacing={0.5} alignItems="center">
                <TimeIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
                <Typography variant="caption" color="text.secondary">
                  {formatEstimatedTime(article.estimatedReadTime)}
                </Typography>
              </Stack>
            </Stack>
            <Stack direction="row" spacing={1}>
              <Tooltip title="Bookmark">
                <IconButton size="small">
                  <BookmarkIcon sx={{ fontSize: 18 }} />
                </IconButton>
              </Tooltip>
              <Tooltip title="Share">
                <IconButton size="small">
                  <ShareIcon sx={{ fontSize: 18 }} />
                </IconButton>
              </Tooltip>
            </Stack>
          </Box>

          <Divider sx={{ my: 2 }} />

          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <Avatar 
                src={article.author.avatar} 
                sx={{ width: 24, height: 24 }}
              >
                {article.author.name.charAt(0)}
              </Avatar>
              <Typography variant="caption" color="text.secondary">
                by {article.author.name}
              </Typography>
            </Stack>
            <Typography variant="caption" color="text.secondary">
              Updated {article.updatedAt.toLocaleDateString()}
            </Typography>
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
            Knowledge Base
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Find answers, tutorials, and best practices for iSECTECH Protect
          </Typography>
        </Box>

        {/* Search Bar */}
        <Card sx={{ p: 3, mb: 4 }}>
          <TextField
            fullWidth
            placeholder="Search articles, tutorials, and documentation..."
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
          
          {/* Category Filters */}
          <Stack 
            direction="row" 
            spacing={1} 
            sx={{ 
              flexWrap: 'wrap', 
              gap: 1,
              '& > *': {
                minWidth: isMobile ? 'auto' : 'fit-content',
              },
            }}
          >
            <Chip
              label="All"
              onClick={() => handleCategorySelect('all')}
              color={selectedCategory === 'all' ? 'primary' : 'default'}
              variant={selectedCategory === 'all' ? 'filled' : 'outlined'}
            />
            {(Object.keys(categoryStats) as KnowledgeCategory[]).map((category) => {
              const CategoryIcon = categoryIcons[category];
              return (
                <Chip
                  key={category}
                  label={`${category.replace('-', ' ')} (${categoryStats[category]})`}
                  icon={<CategoryIcon />}
                  onClick={() => handleCategorySelect(category)}
                  color={selectedCategory === category ? 'primary' : 'default'}
                  variant={selectedCategory === category ? 'filled' : 'outlined'}
                />
              );
            })}
          </Stack>
        </Card>

        <Grid container spacing={3}>
          {/* Main Content */}
          <Grid item xs={12} lg={9}>
            <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
              <Tabs value={tabValue} onChange={handleTabChange}>
                <Tab 
                  label="All Articles" 
                  badge={
                    <Badge badgeContent={filteredArticles.length} color="primary" />
                  }
                />
                <Tab label="Popular" />
                <Tab label="Recent" />
              </Tabs>
            </Box>

            <TabPanel value={tabValue} index={0}>
              {filteredArticles.length === 0 ? (
                <Alert severity="info" sx={{ mb: 3 }}>
                  No articles found matching your search criteria.
                </Alert>
              ) : (
                <Grid container spacing={3}>
                  {filteredArticles.map((article) => (
                    <Grid item xs={12} md={6} key={article.id}>
                      <ArticleCard article={article} />
                    </Grid>
                  ))}
                </Grid>
              )}
            </TabPanel>

            <TabPanel value={tabValue} index={1}>
              <Grid container spacing={3}>
                {popularArticles.map((article) => (
                  <Grid item xs={12} md={6} key={article.id}>
                    <ArticleCard article={article} />
                  </Grid>
                ))}
              </Grid>
            </TabPanel>

            <TabPanel value={tabValue} index={2}>
              <Grid container spacing={3}>
                {recentArticles.map((article) => (
                  <Grid item xs={12} md={6} key={article.id}>
                    <ArticleCard article={article} />
                  </Grid>
                ))}
              </Grid>
            </TabPanel>
          </Grid>

          {/* Sidebar */}
          <Grid item xs={12} lg={3}>
            <Stack spacing={3}>
              {/* Quick Stats */}
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                    Quick Stats
                  </Typography>
                  <Stack spacing={2}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2" color="text.secondary">
                        Total Articles
                      </Typography>
                      <Typography variant="body2" fontWeight={600}>
                        {articles.length}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2" color="text.secondary">
                        Total Views
                      </Typography>
                      <Typography variant="body2" fontWeight={600}>
                        {articles.reduce((sum, article) => sum + article.viewCount, 0).toLocaleString()}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="body2" color="text.secondary">
                        Categories
                      </Typography>
                      <Typography variant="body2" fontWeight={600}>
                        {Object.keys(categoryStats).filter(cat => categoryStats[cat as KnowledgeCategory] > 0).length}
                      </Typography>
                    </Box>
                  </Stack>
                </CardContent>
              </Card>

              {/* Need Help? */}
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                    Need Help?
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Can't find what you're looking for? Our support team is here to help.
                  </Typography>
                  <Stack spacing={1}>
                    <Button variant="outlined" fullWidth size="small">
                      Contact Support
                    </Button>
                    <Button variant="text" fullWidth size="small">
                      Request Article
                    </Button>
                  </Stack>
                </CardContent>
              </Card>
            </Stack>
          </Grid>
        </Grid>
      </Box>
    </AppLayout>
  );
}

export default KnowledgeBasePage;