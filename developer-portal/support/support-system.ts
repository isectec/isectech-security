/**
 * Production-grade Support System for iSECTECH Developer Portal
 * 
 * Provides comprehensive support functionality including ticketing system,
 * knowledge base, live chat, and help desk integration.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// Support System Schemas
export const SupportTicketSchema = z.object({
  ticketId: z.string(),
  userId: z.string(),
  userEmail: z.string(),
  userName: z.string(),
  subject: z.string().min(1).max(200),
  description: z.string().min(10).max(5000),
  category: z.enum([
    'API_ISSUE',
    'BILLING_QUESTION',
    'TECHNICAL_SUPPORT',
    'FEATURE_REQUEST',
    'BUG_REPORT',
    'SECURITY_CONCERN',
    'ACCOUNT_ACCESS',
    'INTEGRATION_HELP'
  ]),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'URGENT']),
  status: z.enum([
    'OPEN',
    'IN_PROGRESS', 
    'WAITING_FOR_CUSTOMER',
    'WAITING_FOR_INTERNAL',
    'RESOLVED',
    'CLOSED'
  ]),
  assignedTo: z.string().optional(),
  tags: z.array(z.string()).default([]),
  createdAt: z.date(),
  updatedAt: z.date(),
  resolvedAt: z.date().optional(),
  estimatedResolutionTime: z.date().optional(),
  satisfactionRating: z.number().min(1).max(5).optional(),
  feedbackText: z.string().optional(),
  internalNotes: z.string().optional(),
  customerNotes: z.string().optional(),
  attachments: z.array(z.object({
    fileId: z.string(),
    fileName: z.string(),
    fileSize: z.number(),
    mimeType: z.string(),
    uploadedAt: z.date()
  })).default([]),
  relatedArticles: z.array(z.string()).default([]),
  escalationHistory: z.array(z.object({
    escalatedAt: z.date(),
    escalatedBy: z.string(),
    escalatedTo: z.string(),
    reason: z.string()
  })).default([])
});

export const TicketMessageSchema = z.object({
  messageId: z.string(),
  ticketId: z.string(),
  authorId: z.string(),
  authorName: z.string(),
  authorType: z.enum(['CUSTOMER', 'SUPPORT_AGENT', 'SYSTEM']),
  content: z.string().min(1).max(5000),
  messageType: z.enum(['MESSAGE', 'STATUS_CHANGE', 'INTERNAL_NOTE', 'ESCALATION']),
  isInternal: z.boolean().default(false),
  createdAt: z.date(),
  attachments: z.array(z.object({
    fileId: z.string(),
    fileName: z.string(),
    fileSize: z.number(),
    mimeType: z.string()
  })).default([]),
  metadata: z.record(z.any()).default({})
});

export const KnowledgeBaseArticleSchema = z.object({
  articleId: z.string(),
  title: z.string().min(1).max(200),
  slug: z.string(),
  content: z.string().min(50),
  summary: z.string().max(500),
  category: z.enum([
    'GETTING_STARTED',
    'API_REFERENCE',
    'TROUBLESHOOTING',
    'SECURITY',
    'BILLING',
    'INTEGRATION_GUIDES',
    'FAQ',
    'BEST_PRACTICES'
  ]),
  subcategory: z.string().optional(),
  tags: z.array(z.string()).default([]),
  difficulty: z.enum(['BEGINNER', 'INTERMEDIATE', 'ADVANCED']),
  estimatedReadTime: z.number(), // in minutes
  isPublished: z.boolean().default(false),
  isFeatured: z.boolean().default(false),
  author: z.object({
    authorId: z.string(),
    name: z.string(),
    role: z.string()
  }),
  createdAt: z.date(),
  updatedAt: z.date(),
  publishedAt: z.date().optional(),
  viewCount: z.number().default(0),
  helpfulVotes: z.number().default(0),
  notHelpfulVotes: z.number().default(0),
  relatedArticles: z.array(z.string()).default([]),
  relatedAPIEndpoints: z.array(z.string()).default([]),
  codeExamples: z.array(z.object({
    language: z.string(),
    title: z.string(),
    code: z.string(),
    description: z.string().optional()
  })).default([]),
  attachments: z.array(z.object({
    fileId: z.string(),
    fileName: z.string(),
    fileSize: z.number(),
    mimeType: z.string(),
    description: z.string().optional()
  })).default([])
});

export const LiveChatSessionSchema = z.object({
  sessionId: z.string(),
  userId: z.string(),
  userEmail: z.string(),
  userName: z.string(),
  agentId: z.string().optional(),
  agentName: z.string().optional(),
  status: z.enum(['WAITING', 'CONNECTED', 'TRANSFERRING', 'ENDED']),
  queuePosition: z.number().optional(),
  estimatedWaitTime: z.number().optional(), // in seconds
  topic: z.string().optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH']),
  createdAt: z.date(),
  connectedAt: z.date().optional(),
  endedAt: z.date().optional(),
  satisfactionRating: z.number().min(1).max(5).optional(),
  feedbackText: z.string().optional(),
  tags: z.array(z.string()).default([]),
  metadata: z.record(z.any()).default({})
});

export const ChatMessageSchema = z.object({
  messageId: z.string(),
  sessionId: z.string(),
  senderId: z.string(),
  senderName: z.string(),
  senderType: z.enum(['CUSTOMER', 'AGENT', 'SYSTEM', 'BOT']),
  content: z.string().min(1).max(2000),
  messageType: z.enum(['TEXT', 'FILE', 'SYSTEM_EVENT', 'QUICK_REPLY']),
  timestamp: z.date(),
  isRead: z.boolean().default(false),
  attachments: z.array(z.object({
    fileId: z.string(),
    fileName: z.string(),
    fileSize: z.number(),
    mimeType: z.string()
  })).default([]),
  metadata: z.record(z.any()).default({})
});

export const SupportAgentSchema = z.object({
  agentId: z.string(),
  name: z.string(),
  email: z.string(),
  role: z.enum(['SUPPORT_AGENT', 'SENIOR_AGENT', 'TECHNICAL_SPECIALIST', 'MANAGER']),
  specializations: z.array(z.string()).default([]),
  languages: z.array(z.string()).default(['en']),
  isOnline: z.boolean().default(false),
  currentLoad: z.number().default(0),
  maxConcurrentChats: z.number().default(5),
  maxConcurrentTickets: z.number().default(20),
  performance: z.object({
    avgResponseTime: z.number().default(0), // in seconds
    avgResolutionTime: z.number().default(0), // in hours
    satisfactionRating: z.number().default(0),
    ticketsResolved: z.number().default(0),
    chatsCompleted: z.number().default(0)
  }).default({}),
  createdAt: z.date(),
  lastActiveAt: z.date().optional()
});

export type SupportTicket = z.infer<typeof SupportTicketSchema>;
export type TicketMessage = z.infer<typeof TicketMessageSchema>;
export type KnowledgeBaseArticle = z.infer<typeof KnowledgeBaseArticleSchema>;
export type LiveChatSession = z.infer<typeof LiveChatSessionSchema>;
export type ChatMessage = z.infer<typeof ChatMessageSchema>;
export type SupportAgent = z.infer<typeof SupportAgentSchema>;

/**
 * iSECTECH Support System Implementation
 */
export class ISECTECHSupportSystem {
  private tickets: Map<string, SupportTicket> = new Map();
  private ticketMessages: Map<string, TicketMessage[]> = new Map();
  private knowledgeBase: Map<string, KnowledgeBaseArticle> = new Map();
  private chatSessions: Map<string, LiveChatSession> = new Map();
  private chatMessages: Map<string, ChatMessage[]> = new Map();
  private supportAgents: Map<string, SupportAgent> = new Map();
  private eventListeners: Map<string, Function[]> = new Map();

  constructor() {
    this.initializeKnowledgeBase();
    this.initializeSupportAgents();
    this.startBackgroundTasks();
  }

  /**
   * Initialize knowledge base with common articles
   */
  private initializeKnowledgeBase(): void {
    const articles: KnowledgeBaseArticle[] = [
      {
        articleId: crypto.randomUUID(),
        title: 'Getting Started with iSECTECH APIs',
        slug: 'getting-started-apis',
        content: `# Getting Started with iSECTECH APIs

Welcome to the iSECTECH cybersecurity API platform. This guide will help you get started with our comprehensive security APIs.

## Quick Start

1. **Create an Account**: Sign up for a developer account at the iSECTECH Developer Portal
2. **Generate API Keys**: Create API keys for your applications in the dashboard
3. **Choose Your Service**: Select from our threat detection, asset discovery, or intelligence services
4. **Make Your First Call**: Use our interactive API explorer to test endpoints

## Authentication

All API requests require authentication using API keys:

\`\`\`bash
curl -H "Authorization: Bearer YOUR_API_KEY" \\
     -H "Content-Type: application/json" \\
     https://api.isectech.com/v1/threats/analyze
\`\`\`

## Rate Limits

- **Free Tier**: 100 requests/hour
- **Developer Tier**: 1,000 requests/hour  
- **Professional Tier**: 10,000 requests/hour
- **Enterprise Tier**: Unlimited requests

## Next Steps

- Explore our [API Reference](/docs/api-reference)
- Check out [Code Examples](/docs/code-examples)
- Join our [Developer Community](/community)`,
        summary: 'Learn how to get started with iSECTECH cybersecurity APIs, including authentication, rate limits, and making your first API call.',
        category: 'GETTING_STARTED',
        tags: ['quickstart', 'authentication', 'api-keys'],
        difficulty: 'BEGINNER',
        estimatedReadTime: 5,
        isPublished: true,
        isFeatured: true,
        author: {
          authorId: 'system',
          name: 'iSECTECH Documentation Team',
          role: 'Technical Writer'
        },
        createdAt: new Date('2024-01-15'),
        updatedAt: new Date('2024-01-15'),
        publishedAt: new Date('2024-01-15'),
        viewCount: 2847,
        helpfulVotes: 145,
        notHelpfulVotes: 8,
        relatedAPIEndpoints: ['/v1/auth/token', '/v1/threats/analyze'],
        codeExamples: [
          {
            language: 'javascript',
            title: 'Node.js Authentication',
            code: `const axios = require('axios');

const client = axios.create({
  baseURL: 'https://api.isectech.com/v1',
  headers: {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json'
  }
});`,
            description: 'Initialize the API client with authentication'
          }
        ]
      },
      {
        articleId: crypto.randomUUID(),
        title: 'API Rate Limiting and Best Practices',
        slug: 'api-rate-limiting-best-practices',
        content: `# API Rate Limiting and Best Practices

Understanding rate limits and implementing best practices ensures optimal performance and prevents service disruptions.

## Rate Limit Headers

Every API response includes rate limit information:

- \`X-RateLimit-Limit\`: Maximum requests per window
- \`X-RateLimit-Remaining\`: Remaining requests in current window  
- \`X-RateLimit-Reset\`: When the rate limit window resets

## Handling Rate Limits

### Exponential Backoff

When you receive a 429 status code, implement exponential backoff:

\`\`\`javascript
async function makeRequestWithRetry(url, options, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, options);
      
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const delay = retryAfter ? parseInt(retryAfter) * 1000 : 
                      Math.pow(2, attempt) * 1000;
        
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      
      return response;
    } catch (error) {
      if (attempt === maxRetries) throw error;
    }
  }
}
\`\`\`

### Request Batching

Batch multiple operations to reduce API calls:

\`\`\`javascript
// Instead of multiple single requests
const analyses = await Promise.all([
  analyzeIP('192.168.1.1'),
  analyzeIP('192.168.1.2'),
  analyzeIP('192.168.1.3')
]);

// Use batch endpoint
const batchAnalysis = await client.post('/threats/analyze/batch', {
  targets: ['192.168.1.1', '192.168.1.2', '192.168.1.3']
});
\`\`\`

## Performance Optimization

### Caching Strategies

Implement intelligent caching to reduce redundant requests:

\`\`\`javascript
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function cachedAnalyze(target) {
  const cacheKey = \`analysis:\${target}\`;
  const cached = cache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  
  const result = await client.post('/threats/analyze', { target });
  cache.set(cacheKey, {
    data: result.data,
    timestamp: Date.now()
  });
  
  return result.data;
}
\`\`\`

### Pagination

Always use pagination for large datasets:

\`\`\`javascript
async function getAllThreats() {
  const threats = [];
  let page = 1;
  let hasMore = true;
  
  while (hasMore) {
    const response = await client.get('/threats', {
      params: { page, limit: 100 }
    });
    
    threats.push(...response.data.items);
    hasMore = response.data.hasNext;
    page++;
  }
  
  return threats;
}
\`\`\`

## Monitoring and Alerting

Set up monitoring for your API usage:

- Track rate limit usage
- Monitor error rates
- Alert on approaching quotas
- Log performance metrics`,
        summary: 'Learn best practices for handling API rate limits, implementing caching, batching requests, and optimizing performance.',
        category: 'BEST_PRACTICES',
        tags: ['rate-limiting', 'performance', 'caching', 'batching'],
        difficulty: 'INTERMEDIATE',
        estimatedReadTime: 8,
        isPublished: true,
        isFeatured: false,
        author: {
          authorId: 'system',
          name: 'iSECTECH Engineering Team',
          role: 'Software Engineer'
        },
        createdAt: new Date('2024-01-20'),
        updatedAt: new Date('2024-01-25'),
        publishedAt: new Date('2024-01-20'),
        viewCount: 1456,
        helpfulVotes: 89,
        notHelpfulVotes: 3,
        relatedAPIEndpoints: ['/v1/threats/analyze', '/v1/threats/analyze/batch'],
        codeExamples: [
          {
            language: 'javascript',
            title: 'Rate Limit Handling',
            code: `// Check rate limit headers
const remaining = response.headers['x-ratelimit-remaining'];
const resetTime = response.headers['x-ratelimit-reset'];

if (remaining < 10) {
  console.warn('Approaching rate limit');
}`,
            description: 'Monitor rate limit headers in responses'
          }
        ]
      },
      {
        articleId: crypto.randomUUID(),
        title: 'Troubleshooting Common API Errors',
        slug: 'troubleshooting-api-errors',
        content: `# Troubleshooting Common API Errors

This guide helps you resolve common issues when working with iSECTECH APIs.

## Authentication Errors

### 401 Unauthorized

**Cause**: Invalid or missing API key

**Solutions**:
- Verify your API key is correct
- Check that the key hasn't expired
- Ensure you're using the correct authentication header format
- Confirm the key has necessary permissions

\`\`\`bash
# Correct format
curl -H "Authorization: Bearer isectech_1234567890abcdef" \\
     https://api.isectech.com/v1/threats/analyze
\`\`\`

### 403 Forbidden

**Cause**: API key lacks required permissions

**Solutions**:
- Check your API key permissions in the dashboard
- Upgrade your plan if needed
- Contact support for permission issues

## Rate Limit Errors

### 429 Too Many Requests

**Cause**: Exceeded rate limit for your tier

**Solutions**:
- Implement exponential backoff
- Use the \`Retry-After\` header value
- Consider upgrading your plan
- Implement request batching

## Request Errors

### 400 Bad Request

**Cause**: Invalid request format or parameters

**Common Issues**:
- Missing required parameters
- Invalid parameter values
- Incorrect content type
- Malformed JSON

**Example Fix**:
\`\`\`javascript
// Incorrect
await client.post('/threats/analyze', { ip: 'invalid-ip' });

// Correct
await client.post('/threats/analyze', { 
  target: '192.168.1.1',
  scan_type: 'comprehensive'
});
\`\`\`

### 422 Unprocessable Entity

**Cause**: Request format is valid but contains semantic errors

**Solutions**:
- Check parameter constraints
- Validate input data
- Review API documentation for expected formats

## Service Errors

### 500 Internal Server Error

**Cause**: Server-side error

**Solutions**:
- Retry the request with exponential backoff
- Check our status page for known issues
- Contact support if persistent

### 502/503/504 Gateway Errors

**Cause**: Temporary service unavailability

**Solutions**:
- Implement retry logic
- Check service status
- Use fallback mechanisms if available

## Debugging Tips

### Enable Debug Logging

\`\`\`javascript
const client = axios.create({
  baseURL: 'https://api.isectech.com/v1',
  headers: {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json'
  }
});

// Add request/response interceptors for debugging
client.interceptors.request.use(request => {
  console.log('Request:', request);
  return request;
});

client.interceptors.response.use(
  response => {
    console.log('Response:', response);
    return response;
  },
  error => {
    console.error('Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);
\`\`\`

### Validate Requests

Always validate your requests before sending:

\`\`\`javascript
function validateAnalysisRequest(data) {
  const required = ['target'];
  const missing = required.filter(field => !data[field]);
  
  if (missing.length > 0) {
    throw new Error(\`Missing required fields: \${missing.join(', ')}\`);
  }
  
  // Validate IP address format
  if (data.target && !isValidIP(data.target)) {
    throw new Error('Invalid IP address format');
  }
}
\`\`\`

## Getting Help

If you continue experiencing issues:

1. Check our [Status Page](https://status.isectech.com)
2. Search our [Knowledge Base](/support/kb)
3. Ask in our [Developer Community](/community)
4. Contact our [Support Team](/support/tickets)`,
        summary: 'Comprehensive guide to troubleshooting common API errors including authentication, rate limiting, and request issues.',
        category: 'TROUBLESHOOTING',
        tags: ['errors', 'debugging', 'authentication', 'troubleshooting'],
        difficulty: 'INTERMEDIATE',
        estimatedReadTime: 12,
        isPublished: true,
        isFeatured: true,
        author: {
          authorId: 'system',
          name: 'iSECTECH Support Team',
          role: 'Support Engineer'
        },
        createdAt: new Date('2024-01-18'),
        updatedAt: new Date('2024-01-28'),
        publishedAt: new Date('2024-01-18'),
        viewCount: 3421,
        helpfulVotes: 198,
        notHelpfulVotes: 12,
        relatedAPIEndpoints: ['/v1/threats/analyze', '/v1/auth/token'],
        codeExamples: [
          {
            language: 'javascript',
            title: 'Error Handling Example',
            code: `try {
  const response = await client.post('/threats/analyze', data);
  return response.data;
} catch (error) {
  if (error.response?.status === 429) {
    // Handle rate limit
    const retryAfter = error.response.headers['retry-after'];
    await sleep(retryAfter * 1000);
    return analyzeWithRetry(data);
  }
  throw error;
}`,
            description: 'Proper error handling with retry logic'
          }
        ]
      }
    ];

    articles.forEach(article => {
      const validatedArticle = KnowledgeBaseArticleSchema.parse(article);
      this.knowledgeBase.set(article.articleId, validatedArticle);
    });

    console.log(`Initialized knowledge base with ${articles.length} articles`);
  }

  /**
   * Initialize support agents
   */
  private initializeSupportAgents(): void {
    const agents: SupportAgent[] = [
      {
        agentId: crypto.randomUUID(),
        name: 'Sarah Chen',
        email: 'sarah.chen@isectech.com',
        role: 'TECHNICAL_SPECIALIST',
        specializations: ['API Integration', 'Security', 'Threat Detection'],
        languages: ['en', 'zh'],
        isOnline: true,
        currentLoad: 3,
        maxConcurrentChats: 5,
        maxConcurrentTickets: 15,
        performance: {
          avgResponseTime: 180, // 3 minutes
          avgResolutionTime: 4.5, // 4.5 hours
          satisfactionRating: 4.8,
          ticketsResolved: 342,
          chatsCompleted: 156
        },
        createdAt: new Date('2023-06-15'),
        lastActiveAt: new Date()
      },
      {
        agentId: crypto.randomUUID(),
        name: 'Mike Rodriguez',
        email: 'mike.rodriguez@isectech.com',
        role: 'SENIOR_AGENT',
        specializations: ['General Support', 'Billing', 'Account Management'],
        languages: ['en', 'es'],
        isOnline: true,
        currentLoad: 2,
        maxConcurrentChats: 6,
        maxConcurrentTickets: 20,
        performance: {
          avgResponseTime: 120, // 2 minutes
          avgResolutionTime: 3.2, // 3.2 hours
          satisfactionRating: 4.6,
          ticketsResolved: 528,
          chatsCompleted: 289
        },
        createdAt: new Date('2023-03-20'),
        lastActiveAt: new Date(Date.now() - 5 * 60 * 1000)
      },
      {
        agentId: crypto.randomUUID(),
        name: 'Emily Foster',
        email: 'emily.foster@isectech.com',
        role: 'SUPPORT_AGENT',
        specializations: ['API Documentation', 'Integration Help', 'Tutorials'],
        languages: ['en'],
        isOnline: false,
        currentLoad: 0,
        maxConcurrentChats: 4,
        maxConcurrentTickets: 18,
        performance: {
          avgResponseTime: 240, // 4 minutes
          avgResolutionTime: 6.1, // 6.1 hours
          satisfactionRating: 4.4,
          ticketsResolved: 167,
          chatsCompleted: 94
        },
        createdAt: new Date('2023-09-10'),
        lastActiveAt: new Date(Date.now() - 2 * 60 * 60 * 1000)
      }
    ];

    agents.forEach(agent => {
      const validatedAgent = SupportAgentSchema.parse(agent);
      this.supportAgents.set(agent.agentId, validatedAgent);
    });

    console.log(`Initialized ${agents.length} support agents`);
  }

  /**
   * Create a new support ticket
   */
  public async createTicket(ticketData: {
    userId: string;
    userEmail: string;
    userName: string;
    subject: string;
    description: string;
    category: SupportTicket['category'];
    priority?: SupportTicket['priority'];
    attachments?: Array<{
      fileName: string;
      fileSize: number;
      mimeType: string;
      content: string; // base64 encoded
    }>;
  }): Promise<{
    success: boolean;
    ticket?: SupportTicket;
    error?: string;
  }> {
    try {
      const ticketId = `ISEC-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
      
      // Process attachments
      const processedAttachments = await Promise.all(
        (ticketData.attachments || []).map(async (attachment) => ({
          fileId: crypto.randomUUID(),
          fileName: attachment.fileName,
          fileSize: attachment.fileSize,
          mimeType: attachment.mimeType,
          uploadedAt: new Date()
        }))
      );

      // Determine priority based on category if not specified
      let priority = ticketData.priority || 'MEDIUM';
      if (ticketData.category === 'SECURITY_CONCERN') priority = 'URGENT';
      if (ticketData.category === 'ACCOUNT_ACCESS') priority = 'HIGH';

      // Suggest related knowledge base articles
      const relatedArticles = this.findRelatedArticles(ticketData.subject + ' ' + ticketData.description);

      const ticket: SupportTicket = {
        ticketId,
        userId: ticketData.userId,
        userEmail: ticketData.userEmail,
        userName: ticketData.userName,
        subject: ticketData.subject,
        description: ticketData.description,
        category: ticketData.category,
        priority,
        status: 'OPEN',
        tags: this.generateTicketTags(ticketData.category, ticketData.subject),
        createdAt: new Date(),
        updatedAt: new Date(),
        attachments: processedAttachments,
        relatedArticles,
        escalationHistory: []
      };

      // Auto-assign to appropriate agent
      const assignedAgent = this.findBestAgent(ticket);
      if (assignedAgent) {
        ticket.assignedTo = assignedAgent.agentId;
        assignedAgent.currentLoad++;
      }

      // Estimate resolution time based on category and priority
      ticket.estimatedResolutionTime = this.calculateEstimatedResolution(ticket);

      const validatedTicket = SupportTicketSchema.parse(ticket);
      this.tickets.set(ticketId, validatedTicket);
      this.ticketMessages.set(ticketId, []);

      // Create initial system message
      await this.addTicketMessage({
        ticketId,
        authorId: 'system',
        authorName: 'System',
        authorType: 'SYSTEM',
        content: `Ticket created. ${assignedAgent ? `Assigned to ${assignedAgent.name}.` : 'Awaiting assignment.'} Estimated resolution: ${ticket.estimatedResolutionTime?.toLocaleString()}`,
        messageType: 'STATUS_CHANGE',
        isInternal: false
      });

      this.emit('ticket:created', validatedTicket);

      return { success: true, ticket: validatedTicket };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create ticket'
      };
    }
  }

  /**
   * Update ticket status
   */
  public async updateTicketStatus(
    ticketId: string, 
    status: SupportTicket['status'],
    userId: string,
    note?: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const ticket = this.tickets.get(ticketId);
      if (!ticket) {
        return { success: false, error: 'Ticket not found' };
      }

      const previousStatus = ticket.status;
      ticket.status = status;
      ticket.updatedAt = new Date();

      if (status === 'RESOLVED' || status === 'CLOSED') {
        ticket.resolvedAt = new Date();
      }

      // Add status change message
      await this.addTicketMessage({
        ticketId,
        authorId: userId,
        authorName: 'User', // In production, get actual user name
        authorType: 'CUSTOMER',
        content: note || `Status changed from ${previousStatus} to ${status}`,
        messageType: 'STATUS_CHANGE',
        isInternal: false
      });

      this.emit('ticket:status_changed', { ticket, previousStatus, newStatus: status });

      return { success: true };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update ticket status'
      };
    }
  }

  /**
   * Add message to ticket
   */
  public async addTicketMessage(messageData: {
    ticketId: string;
    authorId: string;
    authorName: string;
    authorType: TicketMessage['authorType'];
    content: string;
    messageType?: TicketMessage['messageType'];
    isInternal?: boolean;
    attachments?: Array<{
      fileName: string;
      fileSize: number;
      mimeType: string;
      content: string; // base64 encoded
    }>;
  }): Promise<{
    success: boolean;
    message?: TicketMessage;
    error?: string;
  }> {
    try {
      const ticket = this.tickets.get(messageData.ticketId);
      if (!ticket) {
        return { success: false, error: 'Ticket not found' };
      }

      // Process attachments
      const processedAttachments = await Promise.all(
        (messageData.attachments || []).map(async (attachment) => ({
          fileId: crypto.randomUUID(),
          fileName: attachment.fileName,
          fileSize: attachment.fileSize,
          mimeType: attachment.mimeType
        }))
      );

      const message: TicketMessage = {
        messageId: crypto.randomUUID(),
        ticketId: messageData.ticketId,
        authorId: messageData.authorId,
        authorName: messageData.authorName,
        authorType: messageData.authorType,
        content: messageData.content,
        messageType: messageData.messageType || 'MESSAGE',
        isInternal: messageData.isInternal || false,
        createdAt: new Date(),
        attachments: processedAttachments,
        metadata: {}
      };

      const validatedMessage = TicketMessageSchema.parse(message);
      
      const messages = this.ticketMessages.get(messageData.ticketId) || [];
      messages.push(validatedMessage);
      this.ticketMessages.set(messageData.ticketId, messages);

      // Update ticket timestamp
      ticket.updatedAt = new Date();

      this.emit('ticket:message_added', { ticket, message: validatedMessage });

      return { success: true, message: validatedMessage };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to add message to ticket'
      };
    }
  }

  /**
   * Get ticket with messages
   */
  public getTicketWithMessages(ticketId: string): {
    ticket: SupportTicket | null;
    messages: TicketMessage[];
  } {
    const ticket = this.tickets.get(ticketId) || null;
    const messages = this.ticketMessages.get(ticketId) || [];
    return { ticket, messages };
  }

  /**
   * Search tickets
   */
  public searchTickets(criteria: {
    userId?: string;
    status?: SupportTicket['status'];
    category?: SupportTicket['category'];
    priority?: SupportTicket['priority'];
    assignedTo?: string;
    searchText?: string;
    createdAfter?: Date;
    createdBefore?: Date;
    limit?: number;
    offset?: number;
  }): {
    tickets: SupportTicket[];
    total: number;
  } {
    let filteredTickets = Array.from(this.tickets.values());

    // Apply filters
    if (criteria.userId) {
      filteredTickets = filteredTickets.filter(t => t.userId === criteria.userId);
    }
    if (criteria.status) {
      filteredTickets = filteredTickets.filter(t => t.status === criteria.status);
    }
    if (criteria.category) {
      filteredTickets = filteredTickets.filter(t => t.category === criteria.category);
    }
    if (criteria.priority) {
      filteredTickets = filteredTickets.filter(t => t.priority === criteria.priority);
    }
    if (criteria.assignedTo) {
      filteredTickets = filteredTickets.filter(t => t.assignedTo === criteria.assignedTo);
    }
    if (criteria.searchText) {
      const searchLower = criteria.searchText.toLowerCase();
      filteredTickets = filteredTickets.filter(t => 
        t.subject.toLowerCase().includes(searchLower) ||
        t.description.toLowerCase().includes(searchLower) ||
        t.ticketId.toLowerCase().includes(searchLower)
      );
    }
    if (criteria.createdAfter) {
      filteredTickets = filteredTickets.filter(t => t.createdAt >= criteria.createdAfter!);
    }
    if (criteria.createdBefore) {
      filteredTickets = filteredTickets.filter(t => t.createdAt <= criteria.createdBefore!);
    }

    // Sort by creation date (newest first)
    filteredTickets.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    const total = filteredTickets.length;
    const offset = criteria.offset || 0;
    const limit = criteria.limit || 50;

    const paginatedTickets = filteredTickets.slice(offset, offset + limit);

    return { tickets: paginatedTickets, total };
  }

  /**
   * Start live chat session
   */
  public async startChatSession(sessionData: {
    userId: string;
    userEmail: string;
    userName: string;
    topic?: string;
    priority?: LiveChatSession['priority'];
  }): Promise<{
    success: boolean;
    session?: LiveChatSession;
    estimatedWaitTime?: number;
    error?: string;
  }> {
    try {
      const sessionId = crypto.randomUUID();
      
      // Find available agent
      const availableAgent = this.findAvailableChatAgent();
      const queuePosition = this.getChatQueuePosition();
      const estimatedWaitTime = this.calculateChatWaitTime(queuePosition);

      const session: LiveChatSession = {
        sessionId,
        userId: sessionData.userId,
        userEmail: sessionData.userEmail,
        userName: sessionData.userName,
        agentId: availableAgent?.agentId,
        agentName: availableAgent?.name,
        status: availableAgent ? 'CONNECTED' : 'WAITING',
        queuePosition: availableAgent ? undefined : queuePosition,
        estimatedWaitTime: availableAgent ? undefined : estimatedWaitTime,
        topic: sessionData.topic,
        priority: sessionData.priority || 'MEDIUM',
        createdAt: new Date(),
        connectedAt: availableAgent ? new Date() : undefined,
        tags: [],
        metadata: {}
      };

      if (availableAgent) {
        availableAgent.currentLoad++;
      }

      const validatedSession = LiveChatSessionSchema.parse(session);
      this.chatSessions.set(sessionId, validatedSession);
      this.chatMessages.set(sessionId, []);

      // Send welcome message
      if (availableAgent) {
        await this.addChatMessage({
          sessionId,
          senderId: availableAgent.agentId,
          senderName: availableAgent.name,
          senderType: 'AGENT',
          content: `Hello ${sessionData.userName}! I'm ${availableAgent.name} and I'll be helping you today. How can I assist you?`,
          messageType: 'TEXT'
        });
      } else {
        await this.addChatMessage({
          sessionId,
          senderId: 'system',
          senderName: 'System',
          senderType: 'SYSTEM',
          content: `You are currently position ${queuePosition} in the queue. Estimated wait time: ${Math.ceil(estimatedWaitTime / 60)} minutes. We'll connect you with an agent as soon as possible.`,
          messageType: 'SYSTEM_EVENT'
        });
      }

      this.emit('chat:session_started', validatedSession);

      return { 
        success: true, 
        session: validatedSession,
        estimatedWaitTime: availableAgent ? 0 : estimatedWaitTime
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to start chat session'
      };
    }
  }

  /**
   * Add message to chat session
   */
  public async addChatMessage(messageData: {
    sessionId: string;
    senderId: string;
    senderName: string;
    senderType: ChatMessage['senderType'];
    content: string;
    messageType?: ChatMessage['messageType'];
    attachments?: Array<{
      fileName: string;
      fileSize: number;
      mimeType: string;
      content: string; // base64 encoded
    }>;
  }): Promise<{
    success: boolean;
    message?: ChatMessage;
    error?: string;
  }> {
    try {
      const session = this.chatSessions.get(messageData.sessionId);
      if (!session) {
        return { success: false, error: 'Chat session not found' };
      }

      // Process attachments
      const processedAttachments = await Promise.all(
        (messageData.attachments || []).map(async (attachment) => ({
          fileId: crypto.randomUUID(),
          fileName: attachment.fileName,
          fileSize: attachment.fileSize,
          mimeType: attachment.mimeType
        }))
      );

      const message: ChatMessage = {
        messageId: crypto.randomUUID(),
        sessionId: messageData.sessionId,
        senderId: messageData.senderId,
        senderName: messageData.senderName,
        senderType: messageData.senderType,
        content: messageData.content,
        messageType: messageData.messageType || 'TEXT',
        timestamp: new Date(),
        isRead: messageData.senderType === 'CUSTOMER',
        attachments: processedAttachments,
        metadata: {}
      };

      const validatedMessage = ChatMessageSchema.parse(message);
      
      const messages = this.chatMessages.get(messageData.sessionId) || [];
      messages.push(validatedMessage);
      this.chatMessages.set(messageData.sessionId, messages);

      this.emit('chat:message_added', { session, message: validatedMessage });

      return { success: true, message: validatedMessage };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to add chat message'
      };
    }
  }

  /**
   * End chat session
   */
  public async endChatSession(sessionId: string, userId: string): Promise<{
    success: boolean;
    error?: string;
  }> {
    try {
      const session = this.chatSessions.get(sessionId);
      if (!session) {
        return { success: false, error: 'Chat session not found' };
      }

      session.status = 'ENDED';
      session.endedAt = new Date();

      // Free up agent
      if (session.agentId) {
        const agent = this.supportAgents.get(session.agentId);
        if (agent && agent.currentLoad > 0) {
          agent.currentLoad--;
          agent.performance.chatsCompleted++;
        }
      }

      // Add closing message
      await this.addChatMessage({
        sessionId,
        senderId: 'system',
        senderName: 'System',
        senderType: 'SYSTEM',
        content: 'Chat session has ended. Thank you for contacting iSECTECH support!',
        messageType: 'SYSTEM_EVENT'
      });

      this.emit('chat:session_ended', session);

      return { success: true };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to end chat session'
      };
    }
  }

  /**
   * Search knowledge base
   */
  public searchKnowledgeBase(query: string, options?: {
    category?: KnowledgeBaseArticle['category'];
    difficulty?: KnowledgeBaseArticle['difficulty'];
    tags?: string[];
    limit?: number;
  }): {
    articles: KnowledgeBaseArticle[];
    total: number;
  } {
    let articles = Array.from(this.knowledgeBase.values())
      .filter(article => article.isPublished);

    // Apply filters
    if (options?.category) {
      articles = articles.filter(a => a.category === options.category);
    }
    if (options?.difficulty) {
      articles = articles.filter(a => a.difficulty === options.difficulty);
    }
    if (options?.tags && options.tags.length > 0) {
      articles = articles.filter(a => 
        options.tags!.some(tag => a.tags.includes(tag))
      );
    }

    // Search in title, content, and tags
    if (query.trim()) {
      const queryLower = query.toLowerCase();
      articles = articles.filter(article => 
        article.title.toLowerCase().includes(queryLower) ||
        article.content.toLowerCase().includes(queryLower) ||
        article.summary.toLowerCase().includes(queryLower) ||
        article.tags.some(tag => tag.toLowerCase().includes(queryLower))
      );

      // Sort by relevance (simple scoring)
      articles.sort((a, b) => {
        const scoreA = this.calculateArticleRelevance(a, queryLower);
        const scoreB = this.calculateArticleRelevance(b, queryLower);
        return scoreB - scoreA;
      });
    } else {
      // Sort by popularity and recency
      articles.sort((a, b) => {
        const popularityA = a.viewCount + a.helpfulVotes * 2;
        const popularityB = b.viewCount + b.helpfulVotes * 2;
        return popularityB - popularityA;
      });
    }

    const total = articles.length;
    const limit = options?.limit || 20;
    const limitedArticles = articles.slice(0, limit);

    return { articles: limitedArticles, total };
  }

  /**
   * Get knowledge base article by ID
   */
  public getKnowledgeBaseArticle(articleId: string): KnowledgeBaseArticle | null {
    const article = this.knowledgeBase.get(articleId);
    if (article && article.isPublished) {
      // Increment view count
      article.viewCount++;
      return article;
    }
    return null;
  }

  /**
   * Vote on knowledge base article
   */
  public voteOnArticle(articleId: string, helpful: boolean): {
    success: boolean;
    error?: string;
  } {
    const article = this.knowledgeBase.get(articleId);
    if (!article || !article.isPublished) {
      return { success: false, error: 'Article not found' };
    }

    if (helpful) {
      article.helpfulVotes++;
    } else {
      article.notHelpfulVotes++;
    }

    this.emit('kb:article_voted', { article, helpful });

    return { success: true };
  }

  /**
   * Get support statistics
   */
  public getSupportStatistics(): {
    tickets: {
      total: number;
      open: number;
      resolved: number;
      avgResolutionTime: number; // in hours
    };
    chat: {
      activeSessions: number;
      queueLength: number;
      avgWaitTime: number; // in seconds
    };
    knowledgeBase: {
      totalArticles: number;
      popularArticles: KnowledgeBaseArticle[];
    };
    agents: {
      online: number;
      total: number;
      avgSatisfactionRating: number;
    };
  } {
    const tickets = Array.from(this.tickets.values());
    const openTickets = tickets.filter(t => ['OPEN', 'IN_PROGRESS'].includes(t.status));
    const resolvedTickets = tickets.filter(t => t.status === 'RESOLVED');
    
    const avgResolutionTime = resolvedTickets.length > 0 
      ? resolvedTickets.reduce((sum, ticket) => {
          if (ticket.resolvedAt && ticket.createdAt) {
            return sum + (ticket.resolvedAt.getTime() - ticket.createdAt.getTime());
          }
          return sum;
        }, 0) / resolvedTickets.length / (1000 * 60 * 60) // Convert to hours
      : 0;

    const chatSessions = Array.from(this.chatSessions.values());
    const activeSessions = chatSessions.filter(s => s.status === 'CONNECTED').length;
    const queueLength = chatSessions.filter(s => s.status === 'WAITING').length;

    const agents = Array.from(this.supportAgents.values());
    const onlineAgents = agents.filter(a => a.isOnline);
    const avgSatisfactionRating = agents.length > 0
      ? agents.reduce((sum, agent) => sum + agent.performance.satisfactionRating, 0) / agents.length
      : 0;

    const articles = Array.from(this.knowledgeBase.values()).filter(a => a.isPublished);
    const popularArticles = articles
      .sort((a, b) => (b.viewCount + b.helpfulVotes * 2) - (a.viewCount + a.helpfulVotes * 2))
      .slice(0, 5);

    return {
      tickets: {
        total: tickets.length,
        open: openTickets.length,
        resolved: resolvedTickets.length,
        avgResolutionTime
      },
      chat: {
        activeSessions,
        queueLength,
        avgWaitTime: queueLength * 60 // Simplified calculation
      },
      knowledgeBase: {
        totalArticles: articles.length,
        popularArticles
      },
      agents: {
        online: onlineAgents.length,
        total: agents.length,
        avgSatisfactionRating
      }
    };
  }

  // Private helper methods
  private findBestAgent(ticket: SupportTicket): SupportAgent | null {
    const availableAgents = Array.from(this.supportAgents.values())
      .filter(agent => 
        agent.isOnline && 
        agent.currentLoad < agent.maxConcurrentTickets
      );

    if (availableAgents.length === 0) return null;

    // Find agent with matching specializations
    const specializedAgents = availableAgents.filter(agent =>
      agent.specializations.some(spec => 
        this.matchesSpecialization(spec, ticket.category)
      )
    );

    const candidateAgents = specializedAgents.length > 0 ? specializedAgents : availableAgents;

    // Sort by current load and performance
    candidateAgents.sort((a, b) => {
      const loadDiff = a.currentLoad - b.currentLoad;
      if (loadDiff !== 0) return loadDiff;
      
      return b.performance.satisfactionRating - a.performance.satisfactionRating;
    });

    return candidateAgents[0];
  }

  private findAvailableChatAgent(): SupportAgent | null {
    const availableAgents = Array.from(this.supportAgents.values())
      .filter(agent => 
        agent.isOnline && 
        agent.currentLoad < agent.maxConcurrentChats
      )
      .sort((a, b) => a.currentLoad - b.currentLoad);

    return availableAgents[0] || null;
  }

  private getChatQueuePosition(): number {
    const waitingSessions = Array.from(this.chatSessions.values())
      .filter(s => s.status === 'WAITING');
    return waitingSessions.length + 1;
  }

  private calculateChatWaitTime(queuePosition: number): number {
    const onlineAgents = Array.from(this.supportAgents.values())
      .filter(a => a.isOnline);
    
    if (onlineAgents.length === 0) return queuePosition * 600; // 10 minutes per position
    
    const avgHandleTime = 300; // 5 minutes average
    const avgAgentsAvailable = onlineAgents.length * 0.7; // 70% availability
    
    return Math.ceil(queuePosition / avgAgentsAvailable) * avgHandleTime;
  }

  private matchesSpecialization(specialization: string, category: SupportTicket['category']): boolean {
    const specializationMap: Record<string, string[]> = {
      'API Integration': ['API_ISSUE', 'TECHNICAL_SUPPORT', 'INTEGRATION_HELP'],
      'Security': ['SECURITY_CONCERN', 'TECHNICAL_SUPPORT'],
      'Billing': ['BILLING_QUESTION'],
      'General Support': ['FEATURE_REQUEST', 'BUG_REPORT', 'ACCOUNT_ACCESS']
    };

    return specializationMap[specialization]?.includes(category) || false;
  }

  private generateTicketTags(category: SupportTicket['category'], subject: string): string[] {
    const tags: string[] = [];
    
    // Add category-based tags
    const categoryTags: Record<SupportTicket['category'], string[]> = {
      'API_ISSUE': ['api', 'integration'],
      'BILLING_QUESTION': ['billing', 'payment'],
      'TECHNICAL_SUPPORT': ['technical', 'support'],
      'FEATURE_REQUEST': ['feature', 'enhancement'],
      'BUG_REPORT': ['bug', 'issue'],
      'SECURITY_CONCERN': ['security', 'urgent'],
      'ACCOUNT_ACCESS': ['account', 'access'],
      'INTEGRATION_HELP': ['integration', 'help']
    };

    tags.push(...categoryTags[category]);

    // Add subject-based tags
    const subjectLower = subject.toLowerCase();
    if (subjectLower.includes('api')) tags.push('api');
    if (subjectLower.includes('auth')) tags.push('authentication');
    if (subjectLower.includes('rate limit')) tags.push('rate-limiting');
    if (subjectLower.includes('documentation')) tags.push('docs');

    return [...new Set(tags)]; // Remove duplicates
  }

  private calculateEstimatedResolution(ticket: SupportTicket): Date {
    const baseHours: Record<SupportTicket['priority'], number> = {
      'LOW': 72,
      'MEDIUM': 24,
      'HIGH': 8,
      'URGENT': 4
    };

    const categoryModifier: Record<SupportTicket['category'], number> = {
      'API_ISSUE': 1.2,
      'BILLING_QUESTION': 0.8,
      'TECHNICAL_SUPPORT': 1.0,
      'FEATURE_REQUEST': 2.0,
      'BUG_REPORT': 1.5,
      'SECURITY_CONCERN': 0.5,
      'ACCOUNT_ACCESS': 0.6,
      'INTEGRATION_HELP': 1.3
    };

    const estimatedHours = baseHours[ticket.priority] * categoryModifier[ticket.category];
    return new Date(ticket.createdAt.getTime() + estimatedHours * 60 * 60 * 1000);
  }

  private findRelatedArticles(text: string): string[] {
    const articles = Array.from(this.knowledgeBase.values())
      .filter(a => a.isPublished);
    
    const scoredArticles = articles.map(article => ({
      articleId: article.articleId,
      score: this.calculateArticleRelevance(article, text.toLowerCase())
    }))
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

    return scoredArticles.map(item => item.articleId);
  }

  private calculateArticleRelevance(article: KnowledgeBaseArticle, query: string): number {
    let score = 0;
    
    // Title matches
    if (article.title.toLowerCase().includes(query)) score += 10;
    
    // Summary matches
    if (article.summary.toLowerCase().includes(query)) score += 5;
    
    // Tag matches
    article.tags.forEach(tag => {
      if (tag.toLowerCase().includes(query) || query.includes(tag.toLowerCase())) {
        score += 3;
      }
    });
    
    // Content matches (sample first 500 chars)
    const contentSample = article.content.substring(0, 500).toLowerCase();
    if (contentSample.includes(query)) score += 2;
    
    // Popularity boost
    score += Math.log(article.viewCount + 1) * 0.1;
    score += article.helpfulVotes * 0.2;
    
    return score;
  }

  private startBackgroundTasks(): void {
    // Process chat queue
    setInterval(() => {
      this.processChatQueue();
    }, 30000); // Every 30 seconds

    // Update agent performance metrics
    setInterval(() => {
      this.updateAgentMetrics();
    }, 300000); // Every 5 minutes

    // Clean up old chat sessions
    setInterval(() => {
      this.cleanupOldSessions();
    }, 3600000); // Every hour
  }

  private processChatQueue(): void {
    const waitingSessions = Array.from(this.chatSessions.values())
      .filter(s => s.status === 'WAITING')
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

    for (const session of waitingSessions) {
      const availableAgent = this.findAvailableChatAgent();
      if (availableAgent) {
        session.status = 'CONNECTED';
        session.agentId = availableAgent.agentId;
        session.agentName = availableAgent.name;
        session.connectedAt = new Date();
        session.queuePosition = undefined;
        session.estimatedWaitTime = undefined;

        availableAgent.currentLoad++;

        this.addChatMessage({
          sessionId: session.sessionId,
          senderId: availableAgent.agentId,
          senderName: availableAgent.name,
          senderType: 'AGENT',
          content: `Hello ${session.userName}! I'm ${availableAgent.name} and I'll be helping you today. How can I assist you?`,
          messageType: 'TEXT'
        });

        this.emit('chat:agent_connected', { session, agent: availableAgent });
      } else {
        break; // No agents available
      }
    }
  }

  private updateAgentMetrics(): void {
    // Update agent performance metrics based on recent activity
    this.supportAgents.forEach(agent => {
      agent.lastActiveAt = agent.isOnline ? new Date() : agent.lastActiveAt;
    });
  }

  private cleanupOldSessions(): void {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
    
    this.chatSessions.forEach((session, sessionId) => {
      if (session.status === 'ENDED' && session.endedAt && session.endedAt < cutoff) {
        this.chatSessions.delete(sessionId);
        this.chatMessages.delete(sessionId);
      }
    });
  }

  // Event management
  public on(event: string, callback: Function): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event)!.push(callback);
  }

  public off(event: string, callback: Function): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      const index = listeners.indexOf(callback);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  public emit(event: string, data?: any): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in event listener for ${event}:`, error);
        }
      });
    }
  }
}

// Export production-ready support system
export const isectechSupportSystem = new ISECTECHSupportSystem();