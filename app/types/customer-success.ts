/**
 * Customer Success Portal Types for iSECTECH Protect
 * TypeScript definitions for customer success features
 */

import { BaseEntity, SearchParams, PaginatedData } from './common';

// Knowledge Base Types
export type KnowledgeCategory = 
  | 'documentation'
  | 'tutorials' 
  | 'best-practices'
  | 'troubleshooting'
  | 'release-notes'
  | 'faq';

export type ContentFormat = 'markdown' | 'html' | 'video' | 'pdf' | 'interactive';

export type ContentStatus = 'draft' | 'review' | 'published' | 'archived';

export interface KnowledgeArticle extends BaseEntity {
  title: string;
  slug: string;
  summary: string;
  content: string;
  format: ContentFormat;
  category: KnowledgeCategory;
  status: ContentStatus;
  tags: string[];
  author: {
    id: string;
    name: string;
    avatar?: string;
  };
  reviewer?: {
    id: string;
    name: string;
    reviewedAt: Date;
  };
  publishedAt?: Date;
  lastReviewedAt?: Date;
  nextReviewDate?: Date;
  version: string;
  viewCount: number;
  upvotes: number;
  downvotes: number;
  attachments?: {
    id: string;
    filename: string;
    url: string;
    type: string;
    size: number;
  }[];
  relatedArticles?: string[];
  searchKeywords: string[];
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedReadTime: number; // minutes
  securityClassification: 'public' | 'internal' | 'restricted';
  tenantId: string;
}

export interface KnowledgeBaseSearch extends SearchParams {
  category?: KnowledgeCategory[];
  format?: ContentFormat[];
  status?: ContentStatus[];
  difficulty?: ('beginner' | 'intermediate' | 'advanced')[];
  tags?: string[];
  author?: string;
  dateRange?: {
    start: Date;
    end: Date;
  };
}

export interface KnowledgeFeedback extends BaseEntity {
  articleId: string;
  userId: string;
  rating: 1 | 2 | 3 | 4 | 5;
  helpful: boolean;
  comment?: string;
  category: 'accuracy' | 'clarity' | 'completeness' | 'relevance' | 'outdated';
  anonymous: boolean;
  tenantId: string;
}

// Training Types
export type TrainingType = 'course' | 'webinar' | 'workshop' | 'certification' | 'assessment';

export type TrainingDifficulty = 'beginner' | 'intermediate' | 'advanced' | 'expert';

export type TrainingStatus = 'draft' | 'published' | 'archived';

export type EnrollmentStatus = 'not-started' | 'in-progress' | 'completed' | 'failed' | 'expired';

export interface TrainingCourse extends BaseEntity {
  title: string;
  slug: string;
  description: string;
  shortDescription: string;
  type: TrainingType;
  difficulty: TrainingDifficulty;
  status: TrainingStatus;
  category: string;
  tags: string[];
  instructor: {
    id: string;
    name: string;
    avatar?: string;
    bio: string;
    credentials: string[];
  };
  duration: number; // minutes
  estimatedHours: number;
  prerequisites: string[];
  learningObjectives: string[];
  modules: TrainingModule[];
  assessments: TrainingAssessment[];
  certificateTemplate?: string;
  passThreshold: number; // percentage
  maxAttempts: number;
  validityPeriod: number; // days
  price?: number;
  currency?: string;
  enrollmentCount: number;
  averageRating: number;
  ratingCount: number;
  thumbnailUrl?: string;
  previewVideoUrl?: string;
  resources: {
    id: string;
    title: string;
    url: string;
    type: 'pdf' | 'video' | 'link' | 'download';
  }[];
  securityClearanceRequired?: 'UNCLASSIFIED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET';
  tenantId: string;
}

export interface TrainingModule extends BaseEntity {
  courseId: string;
  title: string;
  description: string;
  order: number;
  duration: number; // minutes
  content: {
    type: 'video' | 'text' | 'interactive' | 'quiz' | 'lab';
    data: any;
  }[];
  resources: {
    id: string;
    title: string;
    url: string;
    type: string;
  }[];
  quiz?: {
    questions: TrainingQuestion[];
    passingScore: number;
    maxAttempts: number;
  };
  completionCriteria: {
    watchVideo?: boolean;
    readContent?: boolean;
    passQuiz?: boolean;
    completeInteractive?: boolean;
  };
}

export interface TrainingQuestion {
  id: string;
  type: 'multiple-choice' | 'true-false' | 'fill-blank' | 'essay' | 'practical';
  question: string;
  options?: string[];
  correctAnswers: string[];
  explanation: string;
  points: number;
  difficulty: TrainingDifficulty;
}

export interface TrainingAssessment extends BaseEntity {
  courseId: string;
  title: string;
  description: string;
  type: 'quiz' | 'exam' | 'practical' | 'project';
  questions: TrainingQuestion[];
  timeLimit: number; // minutes
  passingScore: number;
  maxAttempts: number;
  randomizeQuestions: boolean;
  showResults: boolean;
  allowReview: boolean;
}

export interface TrainingEnrollment extends BaseEntity {
  userId: string;
  courseId: string;
  status: EnrollmentStatus;
  progress: number; // 0-100
  startedAt?: Date;
  completedAt?: Date;
  dueDate?: Date;
  lastAccessedAt?: Date;
  attempts: TrainingAttempt[];
  currentModule?: string;
  timeSpent: number; // minutes
  certificateUrl?: string;
  certificateIssuedAt?: Date;
  tenantId: string;
}

export interface TrainingAttempt extends BaseEntity {
  enrollmentId: string;
  assessmentId: string;
  startedAt: Date;
  completedAt?: Date;
  score?: number;
  passed: boolean;
  answers: {
    questionId: string;
    answer: string[];
    correct: boolean;
    points: number;
  }[];
  timeSpent: number; // minutes
}

export interface TrainingProgress {
  courseId: string;
  userId: string;
  totalModules: number;
  completedModules: number;
  currentModule?: string;
  percentComplete: number;
  timeSpent: number; // minutes
  lastAccessed: Date;
  estimatedTimeToComplete: number; // minutes
}

export interface Certificate extends BaseEntity {
  userId: string;
  courseId: string;
  title: string;
  description: string;
  issuedAt: Date;
  expiresAt?: Date;
  certificateNumber: string;
  verificationCode: string;
  verificationUrl: string;
  pdfUrl: string;
  credentialId?: string; // for external credential systems
  tenantId: string;
}

// Support Types
export type TicketStatus = 'open' | 'in-progress' | 'waiting-customer' | 'resolved' | 'closed' | 'escalated';

export type TicketPriority = 'low' | 'normal' | 'high' | 'urgent' | 'critical';

export type TicketCategory = 'bug' | 'feature-request' | 'question' | 'training' | 'technical-issue' | 'billing' | 'other';

export interface SupportTicket extends BaseEntity {
  ticketNumber: string;
  subject: string;
  description: string;
  category: TicketCategory;
  priority: TicketPriority;
  status: TicketStatus;
  submitter: {
    id: string;
    name: string;
    email: string;
    avatar?: string;
  };
  assignee?: {
    id: string;
    name: string;
    email: string;
    avatar?: string;
  };
  tags: string[];
  attachments: {
    id: string;
    filename: string;
    url: string;
    size: number;
    type: string;
    uploadedAt: Date;
  }[];
  messages: TicketMessage[];
  watchers: string[];
  slaBreached: boolean;
  resolutionTime?: number; // minutes
  firstResponseTime?: number; // minutes
  satisfactionRating?: 1 | 2 | 3 | 4 | 5;
  satisfactionFeedback?: string;
  internalNotes: string;
  escalationLevel: number;
  relatedTickets: string[];
  knowledgeArticles: string[];
  tenantId: string;
}

export interface TicketMessage extends BaseEntity {
  ticketId: string;
  author: {
    id: string;
    name: string;
    email: string;
    avatar?: string;
    isStaff: boolean;
  };
  content: string;
  isInternal: boolean;
  attachments: {
    id: string;
    filename: string;
    url: string;
    size: number;
    type: string;
  }[];
  readBy: {
    userId: string;
    readAt: Date;
  }[];
}

export interface CustomerHealthScore extends BaseEntity {
  customerId: string;
  tenantId: string;
  overallScore: number; // 0-100
  metrics: {
    engagement: {
      score: number;
      lastLogin: Date;
      sessionFrequency: number;
      featureAdoption: number;
    };
    adoption: {
      score: number;
      featuresUsed: number;
      totalFeatures: number;
      advancedFeatureUsage: number;
    };
    support: {
      score: number;
      ticketCount: number;
      avgResolutionTime: number;
      satisfactionRating: number;
      escalationRate: number;
    };
    training: {
      score: number;
      coursesCompleted: number;
      certificationsEarned: number;
      lastTrainingActivity: Date;
    };
    billing: {
      score: number;
      paymentHistory: 'good' | 'late' | 'overdue';
      renewalProbability: number;
    };
  };
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  recommendations: {
    type: 'training' | 'support' | 'feature-adoption' | 'engagement';
    title: string;
    description: string;
    priority: 'low' | 'medium' | 'high';
    action: string;
  }[];
  trendDirection: 'improving' | 'stable' | 'declining';
  lastUpdated: Date;
  nextReviewDate: Date;
}

// Community Types
export interface ForumPost extends BaseEntity {
  title: string;
  content: string;
  category: string;
  tags: string[];
  author: {
    id: string;
    name: string;
    avatar?: string;
    reputation: number;
    badges: string[];
  };
  status: 'active' | 'closed' | 'archived';
  isPinned: boolean;
  isAnswered: boolean;
  acceptedAnswerId?: string;
  viewCount: number;
  upvotes: number;
  downvotes: number;
  replies: ForumReply[];
  watchers: string[];
  tenantId: string;
}

export interface ForumReply extends BaseEntity {
  postId: string;
  content: string;
  author: {
    id: string;
    name: string;
    avatar?: string;
    reputation: number;
  };
  isAccepted: boolean;
  upvotes: number;
  downvotes: number;
  parentReplyId?: string;
  children: ForumReply[];
}

// Analytics Types
export interface CustomerSuccessAnalytics {
  knowledgeBase: {
    totalArticles: number;
    totalViews: number;
    topArticles: Array<{
      id: string;
      title: string;
      views: number;
      rating: number;
    }>;
    categoryBreakdown: Record<KnowledgeCategory, number>;
    searchAnalytics: {
      topQueries: string[];
      noResultsQueries: string[];
      avgResultsPerQuery: number;
    };
  };
  training: {
    totalCourses: number;
    totalEnrollments: number;
    completionRate: number;
    avgCourseRating: number;
    topCourses: Array<{
      id: string;
      title: string;
      enrollments: number;
      completionRate: number;
      rating: number;
    }>;
    certificationsIssued: number;
  };
  support: {
    totalTickets: number;
    avgResolutionTime: number;
    firstResponseTime: number;
    customerSatisfaction: number;
    ticketsByStatus: Record<TicketStatus, number>;
    ticketsByCategory: Record<TicketCategory, number>;
    slaPerformance: {
      met: number;
      missed: number;
      percentage: number;
    };
  };
  engagement: {
    activeUsers: number;
    avgSessionDuration: number;
    featureAdoptionRate: number;
    customerHealthDistribution: Record<'low' | 'medium' | 'high' | 'critical', number>;
  };
}

// Search and Filtering
export interface CustomerSuccessFilters {
  dateRange?: {
    start: Date;
    end: Date;
  };
  category?: string[];
  status?: string[];
  priority?: string[];
  assignee?: string[];
  tags?: string[];
}

export interface CustomerSuccessSearchResult<T> {
  items: T[];
  total: number;
  facets: Record<string, { value: string; count: number }[]>;
  suggestions: string[];
  took: number;
}