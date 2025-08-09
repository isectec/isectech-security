/**
 * Production-grade Developer Community Forum for iSECTECH
 * 
 * Provides comprehensive community features including forums, discussions,
 * knowledge sharing, Q&A, developer collaboration, and moderation tools.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// Community Forum Schemas
export const ForumCategorySchema = z.object({
  categoryId: z.string(),
  name: z.string(),
  description: z.string(),
  slug: z.string(),
  
  // Category configuration
  icon: z.string().optional(),
  color: z.string().default('#3b82f6'),
  parentCategoryId: z.string().optional(),
  orderIndex: z.number().default(0),
  
  // Permissions and access
  visibility: z.enum(['PUBLIC', 'AUTHENTICATED', 'VERIFIED', 'PREMIUM']).default('AUTHENTICATED'),
  postPermissions: z.enum(['ALL', 'VERIFIED', 'MODERATORS', 'ADMINS']).default('VERIFIED'),
  moderators: z.array(z.string()).default([]), // User IDs
  
  // Features
  features: z.object({
    allowPolls: z.boolean().default(false),
    allowFileUploads: z.boolean().default(true),
    allowCodeSnippets: z.boolean().default(true),
    requireApproval: z.boolean().default(false),
    enableVoting: z.boolean().default(true),
    enableBestAnswer: z.boolean().default(true)
  }),
  
  // Statistics
  stats: z.object({
    totalPosts: z.number().default(0),
    totalTopics: z.number().default(0),
    totalViews: z.number().default(0),
    lastPostAt: z.date().optional(),
    lastPostBy: z.string().optional()
  }),
  
  // Metadata
  isActive: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date(),
  tags: z.array(z.string()).default([])
});

export const ForumTopicSchema = z.object({
  topicId: z.string(),
  categoryId: z.string(),
  authorId: z.string(),
  
  // Topic content
  title: z.string(),
  content: z.string(),
  excerpt: z.string().optional(),
  contentType: z.enum(['MARKDOWN', 'HTML', 'PLAIN_TEXT']).default('MARKDOWN'),
  
  // Topic type and features
  type: z.enum(['DISCUSSION', 'QUESTION', 'ANNOUNCEMENT', 'POLL', 'TUTORIAL']).default('DISCUSSION'),
  tags: z.array(z.string()).default([]),
  
  // Question-specific fields
  questionData: z.object({
    bounty: z.number().default(0),
    acceptedAnswerId: z.string().optional(),
    acceptedAt: z.date().optional(),
    difficulty: z.enum(['BEGINNER', 'INTERMEDIATE', 'ADVANCED']).optional(),
    apiEndpoints: z.array(z.string()).default([]) // Related API endpoints
  }).optional(),
  
  // Poll-specific fields
  pollData: z.object({
    options: z.array(z.object({
      id: z.string(),
      text: z.string(),
      votes: z.number().default(0)
    })),
    allowMultiple: z.boolean().default(false),
    expiresAt: z.date().optional(),
    totalVotes: z.number().default(0)
  }).optional(),
  
  // Status and moderation
  status: z.enum(['ACTIVE', 'LOCKED', 'ARCHIVED', 'HIDDEN', 'PENDING_APPROVAL']).default('ACTIVE'),
  moderationFlags: z.array(z.object({
    flagId: z.string(),
    type: z.enum(['SPAM', 'INAPPROPRIATE', 'OFF_TOPIC', 'DUPLICATE', 'OTHER']),
    reason: z.string(),
    reportedBy: z.string(),
    reportedAt: z.date(),
    resolved: z.boolean().default(false),
    resolvedBy: z.string().optional(),
    resolvedAt: z.date().optional()
  })).default([]),
  
  // Engagement metrics
  stats: z.object({
    views: z.number().default(0),
    replies: z.number().default(0),
    upvotes: z.number().default(0),
    downvotes: z.number().default(0),
    score: z.number().default(0), // Calculated score
    lastReplyAt: z.date().optional(),
    lastReplyBy: z.string().optional()
  }),
  
  // Visibility and promotion
  isPinned: z.boolean().default(false),
  isFeatured: z.boolean().default(false),
  isLocked: z.boolean().default(false),
  
  // SEO and searchability
  slug: z.string(),
  metaTitle: z.string().optional(),
  metaDescription: z.string().optional(),
  keywords: z.array(z.string()).default([]),
  
  // Metadata
  createdAt: z.date(),
  updatedAt: z.date(),
  lastActivityAt: z.date()
});

export const ForumPostSchema = z.object({
  postId: z.string(),
  topicId: z.string(),
  authorId: z.string(),
  parentPostId: z.string().optional(), // For threaded replies
  
  // Post content
  content: z.string(),
  contentType: z.enum(['MARKDOWN', 'HTML', 'PLAIN_TEXT']).default('MARKDOWN'),
  rawContent: z.string(), // Original content before processing
  
  // Attachments and media
  attachments: z.array(z.object({
    id: z.string(),
    filename: z.string(),
    originalName: z.string(),
    mimeType: z.string(),
    size: z.number(),
    url: z.string(),
    thumbnailUrl: z.string().optional(),
    uploadedAt: z.date()
  })).default([]),
  
  // Code snippets
  codeSnippets: z.array(z.object({
    id: z.string(),
    language: z.string(),
    code: z.string(),
    filename: z.string().optional(),
    description: z.string().optional()
  })).default([]),
  
  // Answer-specific fields (for Q&A topics)
  answerData: z.object({
    isAccepted: z.boolean().default(false),
    acceptedAt: z.date().optional(),
    bountyAwarded: z.number().default(0),
    helpfulnessScore: z.number().default(0)
  }).optional(),
  
  // Voting and engagement
  votes: z.object({
    upvotes: z.number().default(0),
    downvotes: z.number().default(0),
    score: z.number().default(0),
    voterIds: z.array(z.string()).default([]) // Track who voted
  }),
  
  // Status and moderation
  status: z.enum(['ACTIVE', 'HIDDEN', 'DELETED', 'PENDING_APPROVAL']).default('ACTIVE'),
  moderationFlags: z.array(z.object({
    flagId: z.string(),
    type: z.enum(['SPAM', 'INAPPROPRIATE', 'OFF_TOPIC', 'DUPLICATE', 'OTHER']),
    reason: z.string(),
    reportedBy: z.string(),
    reportedAt: z.date(),
    resolved: z.boolean().default(false)
  })).default([]),
  
  // Edit history
  editHistory: z.array(z.object({
    editId: z.string(),
    editedBy: z.string(),
    editedAt: z.date(),
    reason: z.string().optional(),
    previousContent: z.string()
  })).default([]),
  
  // Reactions and responses
  reactions: z.array(z.object({
    type: z.enum(['LIKE', 'HELPFUL', 'THANKS', 'CONFUSED', 'OUTDATED']),
    userId: z.string(),
    timestamp: z.date()
  })).default([]),
  
  // Metadata
  ipAddress: z.string().optional(),
  userAgent: z.string().optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
  lastEditedAt: z.date().optional()
});

export const CommunityUserSchema = z.object({
  userId: z.string(),
  developerId: z.string(), // Link to developer account
  
  // Profile information
  displayName: z.string(),
  username: z.string(),
  bio: z.string().optional(),
  avatarUrl: z.string().optional(),
  title: z.string().optional(),
  company: z.string().optional(),
  location: z.string().optional(),
  website: z.string().url().optional(),
  
  // Community status
  role: z.enum(['MEMBER', 'CONTRIBUTOR', 'MODERATOR', 'ADMIN', 'EXPERT']).default('MEMBER'),
  reputation: z.number().default(0),
  badges: z.array(z.object({
    badgeId: z.string(),
    name: z.string(),
    description: z.string(),
    icon: z.string(),
    category: z.enum(['ACTIVITY', 'CONTRIBUTION', 'EXPERTISE', 'SPECIAL']),
    earnedAt: z.date(),
    level: z.number().default(1)
  })).default([]),
  
  // Activity and contributions
  stats: z.object({
    postsCount: z.number().default(0),
    topicsCount: z.number().default(0),
    acceptedAnswers: z.number().default(0),
    helpfulAnswers: z.number().default(0),
    totalVotesReceived: z.number().default(0),
    totalViewsReceived: z.number().default(0),
    joinedDate: z.date(),
    lastActiveAt: z.date().optional(),
    consecutiveDays: z.number().default(0)
  }),
  
  // Specialties and expertise
  expertise: z.array(z.object({
    category: z.string(),
    level: z.enum(['BEGINNER', 'INTERMEDIATE', 'ADVANCED', 'EXPERT']),
    endorsements: z.number().default(0),
    verifiedAt: z.date().optional()
  })).default([]),
  
  // Preferences and settings
  preferences: z.object({
    emailNotifications: z.boolean().default(true),
    pushNotifications: z.boolean().default(false),
    weeklyDigest: z.boolean().default(true),
    mentionNotifications: z.boolean().default(true),
    showRealName: z.boolean().default(false),
    showEmail: z.boolean().default(false),
    allowDirectMessages: z.boolean().default(true)
  }),
  
  // Trust and safety
  trustLevel: z.number().min(0).max(5).default(1),
  warningsCount: z.number().default(0),
  suspensions: z.array(z.object({
    reason: z.string(),
    startDate: z.date(),
    endDate: z.date(),
    issuedBy: z.string()
  })).default([]),
  
  // Social features
  following: z.array(z.string()).default([]), // User IDs being followed
  followers: z.array(z.string()).default([]), // User IDs following this user
  blockedUsers: z.array(z.string()).default([]),
  
  // Metadata
  isActive: z.boolean().default(true),
  isVerified: z.boolean().default(false),
  createdAt: z.date(),
  updatedAt: z.date()
});

export type ForumCategory = z.infer<typeof ForumCategorySchema>;
export type ForumTopic = z.infer<typeof ForumTopicSchema>;
export type ForumPost = z.infer<typeof ForumPostSchema>;
export type CommunityUser = z.infer<typeof CommunityUserSchema>;

/**
 * Developer Community Forum System
 */
export class ISECTECHDeveloperCommunityForum {
  private categories: Map<string, ForumCategory> = new Map();
  private topics: Map<string, ForumTopic> = new Map();
  private posts: Map<string, ForumPost> = new Map();
  private users: Map<string, CommunityUser> = new Map();
  private searchIndex: Map<string, string[]> = new Map();

  constructor() {
    this.initializeForumCategories();
    this.initializeBadgeSystem();
    this.startMaintenanceTasks();
  }

  /**
   * Initialize forum categories for iSECTECH community
   */
  private initializeForumCategories(): void {
    const categories: ForumCategory[] = [
      {
        categoryId: crypto.randomUUID(),
        name: 'General Discussion',
        description: 'General discussions about iSECTECH APIs and cybersecurity',
        slug: 'general-discussion',
        icon: '💬',
        color: '#3b82f6',
        orderIndex: 1,
        visibility: 'AUTHENTICATED',
        postPermissions: 'VERIFIED',
        features: {
          allowPolls: true,
          allowFileUploads: true,
          allowCodeSnippets: true,
          requireApproval: false,
          enableVoting: true,
          enableBestAnswer: false
        },
        stats: {
          totalPosts: 0,
          totalTopics: 0,
          totalViews: 0
        },
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['general', 'discussion']
      },
      {
        categoryId: crypto.randomUUID(),
        name: 'API Help & Support',
        description: 'Get help with iSECTECH APIs, troubleshooting, and implementation questions',
        slug: 'api-help-support',
        icon: '🆘',
        color: '#ef4444',
        orderIndex: 2,
        visibility: 'AUTHENTICATED',
        postPermissions: 'ALL',
        features: {
          allowPolls: false,
          allowFileUploads: true,
          allowCodeSnippets: true,
          requireApproval: false,
          enableVoting: true,
          enableBestAnswer: true
        },
        stats: {
          totalPosts: 0,
          totalTopics: 0,
          totalViews: 0
        },
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['help', 'support', 'api', 'troubleshooting']
      },
      {
        categoryId: crypto.randomUUID(),
        name: 'Threat Detection',
        description: 'Discussions about threat detection APIs, best practices, and use cases',
        slug: 'threat-detection',
        icon: '🛡️',
        color: '#dc2626',
        orderIndex: 3,
        visibility: 'AUTHENTICATED',
        postPermissions: 'VERIFIED',
        features: {
          allowPolls: true,
          allowFileUploads: true,
          allowCodeSnippets: true,
          requireApproval: false,
          enableVoting: true,
          enableBestAnswer: true
        },
        stats: {
          totalPosts: 0,
          totalTopics: 0,
          totalViews: 0
        },
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['threat-detection', 'security', 'api']
      },
      {
        categoryId: crypto.randomUUID(),
        name: 'Asset Discovery',
        description: 'Network asset discovery, inventory management, and scanning discussions',
        slug: 'asset-discovery',
        icon: '🔍',
        color: '#059669',
        orderIndex: 4,
        visibility: 'AUTHENTICATED',
        postPermissions: 'VERIFIED',
        features: {
          allowPolls: false,
          allowFileUploads: true,
          allowCodeSnippets: true,
          requireApproval: false,
          enableVoting: true,
          enableBestAnswer: true
        },
        stats: {
          totalPosts: 0,
          totalTopics: 0,
          totalViews: 0
        },
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['asset-discovery', 'network-security', 'inventory']
      },
      {
        categoryId: crypto.randomUUID(),
        name: 'Code Examples & Tutorials',
        description: 'Share code examples, tutorials, and implementation guides',
        slug: 'code-examples-tutorials',
        icon: '💻',
        color: '#7c3aed',
        orderIndex: 5,
        visibility: 'PUBLIC',
        postPermissions: 'VERIFIED',
        features: {
          allowPolls: false,
          allowFileUploads: true,
          allowCodeSnippets: true,
          requireApproval: true,
          enableVoting: true,
          enableBestAnswer: false
        },
        stats: {
          totalPosts: 0,
          totalTopics: 0,
          totalViews: 0
        },
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['code-examples', 'tutorials', 'guides', 'education']
      },
      {
        categoryId: crypto.randomUUID(),
        name: 'Feature Requests',
        description: 'Request new features, APIs, or improvements to existing services',
        slug: 'feature-requests',
        icon: '✨',
        color: '#f59e0b',
        orderIndex: 6,
        visibility: 'AUTHENTICATED',
        postPermissions: 'VERIFIED',
        features: {
          allowPolls: true,
          allowFileUploads: false,
          allowCodeSnippets: false,
          requireApproval: false,
          enableVoting: true,
          enableBestAnswer: false
        },
        stats: {
          totalPosts: 0,
          totalTopics: 0,
          totalViews: 0
        },
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['feature-requests', 'improvements', 'feedback']
      },
      {
        categoryId: crypto.randomUUID(),
        name: 'Announcements',
        description: 'Official announcements, updates, and news from the iSECTECH team',
        slug: 'announcements',
        icon: '📢',
        color: '#8b5cf6',
        orderIndex: 0,
        visibility: 'PUBLIC',
        postPermissions: 'MODERATORS',
        features: {
          allowPolls: false,
          allowFileUploads: true,
          allowCodeSnippets: false,
          requireApproval: true,
          enableVoting: false,
          enableBestAnswer: false
        },
        stats: {
          totalPosts: 0,
          totalTopics: 0,
          totalViews: 0
        },
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        tags: ['announcements', 'official', 'news', 'updates']
      }
    ];

    categories.forEach(category => {
      const validatedCategory = ForumCategorySchema.parse(category);
      this.categories.set(category.categoryId, validatedCategory);
    });

    console.log(`Initialized ${this.categories.size} forum categories`);
  }

  /**
   * Initialize badge system
   */
  private initializeBadgeSystem(): void {
    // Badges will be awarded based on user activity and contributions
    const badgeDefinitions = [
      {
        id: 'first-post',
        name: 'First Post',
        description: 'Made your first post in the community',
        category: 'ACTIVITY',
        icon: '🎯'
      },
      {
        id: 'helpful-member',
        name: 'Helpful Member',
        description: 'Received 10+ helpful votes on your answers',
        category: 'CONTRIBUTION',
        icon: '🤝'
      },
      {
        id: 'api-expert',
        name: 'API Expert',
        description: 'Demonstrated expertise in API implementation',
        category: 'EXPERTISE',
        icon: '⚡'
      },
      {
        id: 'security-specialist',
        name: 'Security Specialist',
        description: 'Contributed valuable security insights',
        category: 'EXPERTISE',
        icon: '🔒'
      },
      {
        id: 'community-champion',
        name: 'Community Champion',
        description: 'Active community contributor for 6+ months',
        category: 'SPECIAL',
        icon: '🏆'
      }
    ];

    console.log(`Initialized ${badgeDefinitions.length} community badges`);
  }

  /**
   * Create a new forum topic
   */
  public async createTopic(topicData: {
    categoryId: string;
    authorId: string;
    title: string;
    content: string;
    type?: 'DISCUSSION' | 'QUESTION' | 'ANNOUNCEMENT' | 'POLL' | 'TUTORIAL';
    tags?: string[];
    pollData?: any;
    questionData?: any;
  }): Promise<{ success: boolean; topic?: ForumTopic; error?: string }> {
    try {
      const category = this.categories.get(topicData.categoryId);
      if (!category) {
        return { success: false, error: 'Category not found' };
      }

      const user = this.users.get(topicData.authorId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      // Check permissions
      if (!this.canUserPostInCategory(user, category)) {
        return { success: false, error: 'Insufficient permissions to post in this category' };
      }

      const topicId = crypto.randomUUID();
      const slug = this.generateSlug(topicData.title);

      const newTopic: ForumTopic = {
        topicId,
        categoryId: topicData.categoryId,
        authorId: topicData.authorId,
        title: topicData.title,
        content: topicData.content,
        excerpt: this.generateExcerpt(topicData.content),
        contentType: 'MARKDOWN',
        type: topicData.type || 'DISCUSSION',
        tags: topicData.tags || [],
        questionData: topicData.questionData,
        pollData: topicData.pollData,
        status: category.features.requireApproval ? 'PENDING_APPROVAL' : 'ACTIVE',
        stats: {
          views: 0,
          replies: 0,
          upvotes: 0,
          downvotes: 0,
          score: 0
        },
        isPinned: false,
        isFeatured: false,
        isLocked: false,
        slug,
        keywords: this.extractKeywords(topicData.title + ' ' + topicData.content),
        createdAt: new Date(),
        updatedAt: new Date(),
        lastActivityAt: new Date()
      };

      const validatedTopic = ForumTopicSchema.parse(newTopic);
      this.topics.set(topicId, validatedTopic);

      // Update category statistics
      category.stats.totalTopics++;
      category.stats.lastPostAt = new Date();
      category.stats.lastPostBy = topicData.authorId;
      category.updatedAt = new Date();

      // Update user statistics
      user.stats.topicsCount++;
      user.stats.lastActiveAt = new Date();
      user.updatedAt = new Date();

      // Update search index
      this.updateSearchIndex(topicId, topicData.title + ' ' + topicData.content);

      // Award badges if applicable
      await this.checkAndAwardBadges(user);

      console.log(`Created topic: ${topicData.title} by ${user.username}`);
      return { success: true, topic: validatedTopic };

    } catch (error) {
      console.error('Failed to create topic:', error);
      return { success: false, error: 'Failed to create topic' };
    }
  }

  /**
   * Create a new forum post (reply)
   */
  public async createPost(postData: {
    topicId: string;
    authorId: string;
    content: string;
    parentPostId?: string;
    attachments?: any[];
    codeSnippets?: any[];
  }): Promise<{ success: boolean; post?: ForumPost; error?: string }> {
    try {
      const topic = this.topics.get(postData.topicId);
      if (!topic) {
        return { success: false, error: 'Topic not found' };
      }

      if (topic.isLocked) {
        return { success: false, error: 'Topic is locked' };
      }

      const user = this.users.get(postData.authorId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      const category = this.categories.get(topic.categoryId);
      if (!category || !this.canUserPostInCategory(user, category)) {
        return { success: false, error: 'Insufficient permissions to post' };
      }

      const postId = crypto.randomUUID();

      const newPost: ForumPost = {
        postId,
        topicId: postData.topicId,
        authorId: postData.authorId,
        parentPostId: postData.parentPostId,
        content: postData.content,
        contentType: 'MARKDOWN',
        rawContent: postData.content,
        attachments: postData.attachments || [],
        codeSnippets: postData.codeSnippets || [],
        answerData: topic.type === 'QUESTION' ? {
          isAccepted: false,
          bountyAwarded: 0,
          helpfulnessScore: 0
        } : undefined,
        votes: {
          upvotes: 0,
          downvotes: 0,
          score: 0,
          voterIds: []
        },
        status: category.features.requireApproval ? 'PENDING_APPROVAL' : 'ACTIVE',
        editHistory: [],
        reactions: [],
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const validatedPost = ForumPostSchema.parse(newPost);
      this.posts.set(postId, validatedPost);

      // Update topic statistics
      topic.stats.replies++;
      topic.stats.lastReplyAt = new Date();
      topic.stats.lastReplyBy = postData.authorId;
      topic.lastActivityAt = new Date();
      topic.updatedAt = new Date();

      // Update category statistics
      category.stats.totalPosts++;
      category.stats.lastPostAt = new Date();
      category.stats.lastPostBy = postData.authorId;
      category.updatedAt = new Date();

      // Update user statistics
      user.stats.postsCount++;
      user.stats.lastActiveAt = new Date();
      user.updatedAt = new Date();

      // Update search index
      this.updateSearchIndex(postId, postData.content);

      // Award badges if applicable
      await this.checkAndAwardBadges(user);

      console.log(`Created post in topic ${topic.title} by ${user.username}`);
      return { success: true, post: validatedPost };

    } catch (error) {
      console.error('Failed to create post:', error);
      return { success: false, error: 'Failed to create post' };
    }
  }

  /**
   * Vote on a post
   */
  public async voteOnPost(postId: string, userId: string, voteType: 'UP' | 'DOWN'): Promise<{
    success: boolean;
    newScore?: number;
    error?: string;
  }> {
    try {
      const post = this.posts.get(postId);
      if (!post) {
        return { success: false, error: 'Post not found' };
      }

      const user = this.users.get(userId);
      if (!user) {
        return { success: false, error: 'User not found' };
      }

      // Check if user already voted
      const hasVoted = post.votes.voterIds.includes(userId);
      if (hasVoted) {
        return { success: false, error: 'User has already voted on this post' };
      }

      // Apply vote
      if (voteType === 'UP') {
        post.votes.upvotes++;
      } else {
        post.votes.downvotes++;
      }

      post.votes.score = post.votes.upvotes - post.votes.downvotes;
      post.votes.voterIds.push(userId);
      post.updatedAt = new Date();

      // Update author's reputation
      const author = this.users.get(post.authorId);
      if (author) {
        const reputationChange = voteType === 'UP' ? 10 : -2;
        author.reputation = Math.max(0, author.reputation + reputationChange);
        author.stats.totalVotesReceived++;
        author.updatedAt = new Date();
      }

      console.log(`User ${user.username} voted ${voteType} on post ${postId}`);
      return { success: true, newScore: post.votes.score };

    } catch (error) {
      console.error('Failed to vote on post:', error);
      return { success: false, error: 'Failed to process vote' };
    }
  }

  /**
   * Accept an answer for a question
   */
  public async acceptAnswer(topicId: string, postId: string, userId: string): Promise<{
    success: boolean;
    error?: string;
  }> {
    try {
      const topic = this.topics.get(topicId);
      if (!topic || topic.type !== 'QUESTION') {
        return { success: false, error: 'Topic is not a question' };
      }

      if (topic.authorId !== userId) {
        return { success: false, error: 'Only the question author can accept answers' };
      }

      const post = this.posts.get(postId);
      if (!post || post.topicId !== topicId) {
        return { success: false, error: 'Post not found' };
      }

      // Unaccept previous answer if exists
      if (topic.questionData?.acceptedAnswerId) {
        const previousAnswer = this.posts.get(topic.questionData.acceptedAnswerId);
        if (previousAnswer?.answerData) {
          previousAnswer.answerData.isAccepted = false;
        }
      }

      // Accept new answer
      if (post.answerData) {
        post.answerData.isAccepted = true;
        post.answerData.acceptedAt = new Date();
      }

      // Update topic
      if (!topic.questionData) {
        topic.questionData = {
          bounty: 0,
          acceptedAnswerId: postId,
          acceptedAt: new Date(),
          apiEndpoints: []
        };
      } else {
        topic.questionData.acceptedAnswerId = postId;
        topic.questionData.acceptedAt = new Date();
      }

      topic.updatedAt = new Date();

      // Update answer author's statistics
      const answerAuthor = this.users.get(post.authorId);
      if (answerAuthor) {
        answerAuthor.stats.acceptedAnswers++;
        answerAuthor.reputation += 25; // Bonus for accepted answer
        answerAuthor.updatedAt = new Date();
      }

      console.log(`Answer accepted for question: ${topic.title}`);
      return { success: true };

    } catch (error) {
      console.error('Failed to accept answer:', error);
      return { success: false, error: 'Failed to accept answer' };
    }
  }

  /**
   * Search forum content
   */
  public searchForum(query: string, filters?: {
    categoryId?: string;
    authorId?: string;
    type?: string;
    tags?: string[];
    dateRange?: { start: Date; end: Date };
  }): {
    topics: ForumTopic[];
    posts: ForumPost[];
    totalResults: number;
  } {
    const searchTerms = query.toLowerCase().split(' ').filter(term => term.length > 2);
    const matchingTopics: ForumTopic[] = [];
    const matchingPosts: ForumPost[] = [];

    // Search topics
    for (const topic of this.topics.values()) {
      if (this.matchesSearch(topic, searchTerms, filters)) {
        matchingTopics.push(topic);
      }
    }

    // Search posts
    for (const post of this.posts.values()) {
      if (this.matchesPostSearch(post, searchTerms, filters)) {
        matchingPosts.push(post);
      }
    }

    // Sort by relevance and date
    matchingTopics.sort((a, b) => {
      const aScore = this.calculateRelevanceScore(a, searchTerms);
      const bScore = this.calculateRelevanceScore(b, searchTerms);
      if (aScore !== bScore) return bScore - aScore;
      return b.lastActivityAt.getTime() - a.lastActivityAt.getTime();
    });

    matchingPosts.sort((a, b) => {
      const aScore = this.calculatePostRelevanceScore(a, searchTerms);
      const bScore = this.calculatePostRelevanceScore(b, searchTerms);
      if (aScore !== bScore) return bScore - aScore;
      return b.createdAt.getTime() - a.createdAt.getTime();
    });

    return {
      topics: matchingTopics.slice(0, 50), // Limit results
      posts: matchingPosts.slice(0, 50),
      totalResults: matchingTopics.length + matchingPosts.length
    };
  }

  /**
   * Get forum statistics
   */
  public getForumStatistics(): {
    totalCategories: number;
    totalTopics: number;
    totalPosts: number;
    totalUsers: number;
    totalViews: number;
    topContributors: Array<{
      userId: string;
      username: string;
      reputation: number;
      postsCount: number;
      acceptedAnswers: number;
    }>;
    recentActivity: Array<{
      type: 'TOPIC' | 'POST';
      id: string;
      title: string;
      author: string;
      timestamp: Date;
    }>;
  } {
    const totalCategories = this.categories.size;
    const totalTopics = this.topics.size;
    const totalPosts = this.posts.size;
    const totalUsers = this.users.size;
    const totalViews = Array.from(this.topics.values()).reduce((sum, topic) => sum + topic.stats.views, 0);

    // Get top contributors
    const topContributors = Array.from(this.users.values())
      .sort((a, b) => b.reputation - a.reputation)
      .slice(0, 10)
      .map(user => ({
        userId: user.userId,
        username: user.username,
        reputation: user.reputation,
        postsCount: user.stats.postsCount,
        acceptedAnswers: user.stats.acceptedAnswers
      }));

    // Get recent activity
    const recentTopics = Array.from(this.topics.values())
      .sort((a, b) => b.lastActivityAt.getTime() - a.lastActivityAt.getTime())
      .slice(0, 5)
      .map(topic => ({
        type: 'TOPIC' as const,
        id: topic.topicId,
        title: topic.title,
        author: this.users.get(topic.authorId)?.username || 'Unknown',
        timestamp: topic.lastActivityAt
      }));

    const recentPosts = Array.from(this.posts.values())
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, 5)
      .map(post => {
        const topic = this.topics.get(post.topicId);
        return {
          type: 'POST' as const,
          id: post.postId,
          title: topic?.title || 'Unknown Topic',
          author: this.users.get(post.authorId)?.username || 'Unknown',
          timestamp: post.createdAt
        };
      });

    const recentActivity = [...recentTopics, ...recentPosts]
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, 20);

    return {
      totalCategories,
      totalTopics,
      totalPosts,
      totalUsers,
      totalViews,
      topContributors,
      recentActivity
    };
  }

  /**
   * Register a new community user
   */
  public async registerCommunityUser(userData: {
    developerId: string;
    displayName: string;
    username: string;
    bio?: string;
    title?: string;
    company?: string;
  }): Promise<{ success: boolean; user?: CommunityUser; error?: string }> {
    try {
      // Check if username is already taken
      const existingUser = Array.from(this.users.values()).find(u => u.username === userData.username);
      if (existingUser) {
        return { success: false, error: 'Username already taken' };
      }

      const userId = crypto.randomUUID();
      const newUser: CommunityUser = {
        userId,
        developerId: userData.developerId,
        displayName: userData.displayName,
        username: userData.username,
        bio: userData.bio,
        title: userData.title,
        company: userData.company,
        role: 'MEMBER',
        reputation: 1, // Starting reputation
        badges: [],
        stats: {
          postsCount: 0,
          topicsCount: 0,
          acceptedAnswers: 0,
          helpfulAnswers: 0,
          totalVotesReceived: 0,
          totalViewsReceived: 0,
          joinedDate: new Date(),
          consecutiveDays: 1
        },
        expertise: [],
        preferences: {
          emailNotifications: true,
          pushNotifications: false,
          weeklyDigest: true,
          mentionNotifications: true,
          showRealName: false,
          showEmail: false,
          allowDirectMessages: true
        },
        trustLevel: 1,
        warningsCount: 0,
        suspensions: [],
        following: [],
        followers: [],
        blockedUsers: [],
        isActive: true,
        isVerified: false,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const validatedUser = CommunityUserSchema.parse(newUser);
      this.users.set(userId, validatedUser);

      console.log(`Registered community user: ${userData.username}`);
      return { success: true, user: validatedUser };

    } catch (error) {
      console.error('Failed to register community user:', error);
      return { success: false, error: 'Failed to register user' };
    }
  }

  // Private helper methods
  private canUserPostInCategory(user: CommunityUser, category: ForumCategory): boolean {
    switch (category.postPermissions) {
      case 'ALL':
        return true;
      case 'VERIFIED':
        return user.isVerified || user.reputation >= 50;
      case 'MODERATORS':
        return user.role === 'MODERATOR' || user.role === 'ADMIN';
      case 'ADMINS':
        return user.role === 'ADMIN';
      default:
        return false;
    }
  }

  private generateSlug(title: string): string {
    return title
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim()
      .substring(0, 100);
  }

  private generateExcerpt(content: string, maxLength: number = 200): string {
    const plainText = content.replace(/[#*`_~]/g, '').trim();
    return plainText.length <= maxLength 
      ? plainText 
      : plainText.substring(0, maxLength) + '...';
  }

  private extractKeywords(text: string): string[] {
    const words = text.toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(word => word.length > 3);
    
    // Remove duplicates and common words
    const commonWords = ['that', 'this', 'with', 'from', 'they', 'been', 'have', 'were', 'said', 'each', 'which', 'their'];
    return [...new Set(words.filter(word => !commonWords.includes(word)))].slice(0, 10);
  }

  private updateSearchIndex(id: string, content: string): void {
    const keywords = this.extractKeywords(content);
    keywords.forEach(keyword => {
      if (!this.searchIndex.has(keyword)) {
        this.searchIndex.set(keyword, []);
      }
      this.searchIndex.get(keyword)!.push(id);
    });
  }

  private matchesSearch(topic: ForumTopic, searchTerms: string[], filters?: any): boolean {
    const searchableText = `${topic.title} ${topic.content} ${topic.tags.join(' ')}`.toLowerCase();
    const hasSearchTerms = searchTerms.every(term => searchableText.includes(term));
    
    if (!hasSearchTerms) return false;
    
    if (filters) {
      if (filters.categoryId && topic.categoryId !== filters.categoryId) return false;
      if (filters.authorId && topic.authorId !== filters.authorId) return false;
      if (filters.type && topic.type !== filters.type) return false;
      if (filters.tags && !filters.tags.some((tag: string) => topic.tags.includes(tag))) return false;
      if (filters.dateRange) {
        if (topic.createdAt < filters.dateRange.start || topic.createdAt > filters.dateRange.end) return false;
      }
    }
    
    return true;
  }

  private matchesPostSearch(post: ForumPost, searchTerms: string[], filters?: any): boolean {
    const searchableText = post.content.toLowerCase();
    const hasSearchTerms = searchTerms.every(term => searchableText.includes(term));
    
    if (!hasSearchTerms) return false;
    
    if (filters) {
      if (filters.authorId && post.authorId !== filters.authorId) return false;
      const topic = this.topics.get(post.topicId);
      if (filters.categoryId && topic?.categoryId !== filters.categoryId) return false;
      if (filters.dateRange) {
        if (post.createdAt < filters.dateRange.start || post.createdAt > filters.dateRange.end) return false;
      }
    }
    
    return true;
  }

  private calculateRelevanceScore(topic: ForumTopic, searchTerms: string[]): number {
    let score = 0;
    const title = topic.title.toLowerCase();
    const content = topic.content.toLowerCase();
    
    searchTerms.forEach(term => {
      if (title.includes(term)) score += 3;
      if (content.includes(term)) score += 1;
    });
    
    // Boost for engagement
    score += topic.stats.upvotes * 0.5;
    score += topic.stats.replies * 0.3;
    score += topic.stats.views * 0.01;
    
    return score;
  }

  private calculatePostRelevanceScore(post: ForumPost, searchTerms: string[]): number {
    let score = 0;
    const content = post.content.toLowerCase();
    
    searchTerms.forEach(term => {
      if (content.includes(term)) score += 1;
    });
    
    // Boost for engagement
    score += post.votes.upvotes * 0.5;
    if (post.answerData?.isAccepted) score += 5;
    
    return score;
  }

  private async checkAndAwardBadges(user: CommunityUser): Promise<void> {
    // Check for first post badge
    if (user.stats.postsCount === 1 && !user.badges.some(b => b.badgeId === 'first-post')) {
      user.badges.push({
        badgeId: 'first-post',
        name: 'First Post',
        description: 'Made your first post in the community',
        icon: '🎯',
        category: 'ACTIVITY',
        earnedAt: new Date(),
        level: 1
      });
    }

    // Check for helpful member badge
    if (user.stats.totalVotesReceived >= 10 && !user.badges.some(b => b.badgeId === 'helpful-member')) {
      user.badges.push({
        badgeId: 'helpful-member',
        name: 'Helpful Member',
        description: 'Received 10+ helpful votes on your answers',
        icon: '🤝',
        category: 'CONTRIBUTION',
        earnedAt: new Date(),
        level: 1
      });
    }

    // Check for expert badges based on accepted answers
    if (user.stats.acceptedAnswers >= 5 && !user.badges.some(b => b.badgeId === 'api-expert')) {
      user.badges.push({
        badgeId: 'api-expert',
        name: 'API Expert',
        description: 'Demonstrated expertise in API implementation',
        icon: '⚡',
        category: 'EXPERTISE',
        earnedAt: new Date(),
        level: 1
      });
    }

    user.updatedAt = new Date();
  }

  private startMaintenanceTasks(): void {
    // Update user consecutive days every day
    setInterval(() => {
      const now = new Date();
      for (const user of this.users.values()) {
        if (user.stats.lastActiveAt) {
          const daysSinceActive = Math.floor((now.getTime() - user.stats.lastActiveAt.getTime()) / (24 * 60 * 60 * 1000));
          if (daysSinceActive === 0) {
            user.stats.consecutiveDays++;
          } else if (daysSinceActive === 1) {
            // Reset streak
            user.stats.consecutiveDays = 1;
          } else {
            user.stats.consecutiveDays = 0;
          }
          user.updatedAt = new Date();
        }
      }
    }, 24 * 60 * 60 * 1000); // Daily

    // Clean up old search index entries
    setInterval(() => {
      // Implementation would clean up old search index entries
      console.log('Performing search index maintenance...');
    }, 7 * 24 * 60 * 60 * 1000); // Weekly
  }
}

// Export production-ready community forum
export const isectechDeveloperCommunityForum = new ISECTECHDeveloperCommunityForum();