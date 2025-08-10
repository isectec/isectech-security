/**
 * Trust Score WebSocket API
 * Real-time trust score updates via WebSocket connections
 */

import { NextRequest } from 'next/server';
import { WebSocketServer } from 'ws';
import { z } from 'zod';
import { authenticate, authorize } from '@/lib/middleware/auth';
import { validateTenant } from '@/lib/middleware/tenant-validation';
import { auditLog } from '@/lib/middleware/audit-logging';
import { metrics } from '@/lib/monitoring/metrics';
import { logger } from '@/lib/utils/logger';

// WebSocket message schemas
const subscribeSchema = z.object({
  type: z.literal('subscribe'),
  subscriptions: z.array(z.object({
    userId: z.string().optional(),
    deviceId: z.string().optional(),
    sessionId: z.string().optional(),
    eventTypes: z.array(z.enum([
      'score_calculated',
      'score_updated',
      'risk_level_changed',
      'threshold_crossed',
      'factor_changed'
    ])).default(['score_calculated', 'score_updated']),
    filters: z.object({
      minScore: z.number().min(0).max(100).optional(),
      maxScore: z.number().min(0).max(100).optional(),
      riskLevels: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
      factors: z.array(z.enum(['behavioral', 'device', 'network', 'location', 'threat'])).optional(),
    }).optional(),
  })),
  requestId: z.string().optional(),
});

const unsubscribeSchema = z.object({
  type: z.literal('unsubscribe'),
  subscriptionIds: z.array(z.string()).optional(), // If empty, unsubscribe from all
  requestId: z.string().optional(),
});

const heartbeatSchema = z.object({
  type: z.literal('heartbeat'),
  timestamp: z.string().datetime().optional(),
});

// WebSocket connection manager
class TrustScoreWebSocketManager {
  private clients: Map<string, any> = new Map();
  private subscriptions: Map<string, any> = new Map();
  private nextClientId = 1;
  private nextSubscriptionId = 1;

  addClient(ws: any, user: any, tenantId: string) {
    const clientId = `client-${this.nextClientId++}`;
    
    const client = {
      id: clientId,
      ws,
      user,
      tenantId,
      subscriptions: new Set(),
      connectedAt: new Date().toISOString(),
      lastHeartbeat: new Date().toISOString(),
      isAlive: true,
    };

    this.clients.set(clientId, client);
    
    // Set up WebSocket handlers
    ws.on('message', (data: Buffer) => {
      this.handleMessage(clientId, data.toString());
    });

    ws.on('close', () => {
      this.removeClient(clientId);
    });

    ws.on('error', (error: any) => {
      logger.error(`WebSocket error for client ${clientId}:`, error);
      this.removeClient(clientId);
    });

    // Send welcome message
    this.sendMessage(clientId, {
      type: 'connected',
      clientId,
      timestamp: new Date().toISOString(),
      capabilities: {
        maxSubscriptions: 50,
        heartbeatInterval: 30000, // 30 seconds
        messageTypes: ['subscribe', 'unsubscribe', 'heartbeat'],
      },
    });

    // Start heartbeat monitoring
    this.startHeartbeat(clientId);

    logger.info(`Trust Score WebSocket client connected: ${clientId}`);
    metrics.increment('trust_score.websocket.connections', 1, { tenantId });

    return clientId;
  }

  removeClient(clientId: string) {
    const client = this.clients.get(clientId);
    if (!client) return;

    // Remove all subscriptions for this client
    for (const subscriptionId of client.subscriptions) {
      this.subscriptions.delete(subscriptionId);
    }

    this.clients.delete(clientId);
    logger.info(`Trust Score WebSocket client disconnected: ${clientId}`);
    
    if (client.tenantId) {
      metrics.increment('trust_score.websocket.disconnections', 1, { 
        tenantId: client.tenantId 
      });
    }
  }

  private startHeartbeat(clientId: string) {
    const heartbeatInterval = setInterval(() => {
      const client = this.clients.get(clientId);
      if (!client) {
        clearInterval(heartbeatInterval);
        return;
      }

      if (!client.isAlive) {
        logger.info(`Client ${clientId} failed heartbeat check, closing connection`);
        client.ws.terminate();
        this.removeClient(clientId);
        clearInterval(heartbeatInterval);
        return;
      }

      client.isAlive = false;
      this.sendMessage(clientId, {
        type: 'ping',
        timestamp: new Date().toISOString(),
      });
    }, 30000); // 30 seconds
  }

  private handleMessage(clientId: string, message: string) {
    const client = this.clients.get(clientId);
    if (!client) return;

    try {
      const parsedMessage = JSON.parse(message);
      
      // Update last activity
      client.lastHeartbeat = new Date().toISOString();

      switch (parsedMessage.type) {
        case 'subscribe':
          this.handleSubscribe(clientId, parsedMessage);
          break;
        case 'unsubscribe':
          this.handleUnsubscribe(clientId, parsedMessage);
          break;
        case 'heartbeat':
        case 'pong':
          client.isAlive = true;
          break;
        default:
          this.sendError(clientId, 'Unknown message type', parsedMessage.requestId);
      }

    } catch (error: any) {
      logger.error(`Error parsing WebSocket message from ${clientId}:`, error);
      this.sendError(clientId, 'Invalid JSON message');
    }
  }

  private handleSubscribe(clientId: string, message: any) {
    const client = this.clients.get(clientId);
    if (!client) return;

    const validation = subscribeSchema.safeParse(message);
    if (!validation.success) {
      this.sendError(clientId, 'Invalid subscription message', message.requestId);
      return;
    }

    const subscriptionIds = [];
    
    for (const sub of validation.data.subscriptions) {
      if (client.subscriptions.size >= 50) {
        this.sendError(clientId, 'Maximum subscriptions reached (50)', message.requestId);
        break;
      }

      const subscriptionId = `sub-${this.nextSubscriptionId++}`;
      
      const subscription = {
        id: subscriptionId,
        clientId,
        userId: sub.userId,
        deviceId: sub.deviceId,
        sessionId: sub.sessionId,
        eventTypes: sub.eventTypes,
        filters: sub.filters,
        createdAt: new Date().toISOString(),
      };

      this.subscriptions.set(subscriptionId, subscription);
      client.subscriptions.add(subscriptionId);
      subscriptionIds.push(subscriptionId);
    }

    this.sendMessage(clientId, {
      type: 'subscribed',
      subscriptionIds,
      requestId: message.requestId,
      timestamp: new Date().toISOString(),
    });

    // Log subscription
    auditLog({
      userId: client.user.id,
      tenantId: client.tenantId,
      action: 'trust_score.websocket.subscribe',
      resource: 'trust_score_websocket',
      metadata: { 
        subscriptionIds,
        subscriptionCount: subscriptionIds.length,
      },
      timestamp: new Date(),
    });

    metrics.increment('trust_score.websocket.subscriptions', 1, {
      tenantId: client.tenantId,
    });
  }

  private handleUnsubscribe(clientId: string, message: any) {
    const client = this.clients.get(clientId);
    if (!client) return;

    const validation = unsubscribeSchema.safeParse(message);
    if (!validation.success) {
      this.sendError(clientId, 'Invalid unsubscribe message', message.requestId);
      return;
    }

    const { subscriptionIds } = validation.data;
    const removedIds = [];

    if (!subscriptionIds || subscriptionIds.length === 0) {
      // Unsubscribe from all
      for (const subId of client.subscriptions) {
        this.subscriptions.delete(subId);
        removedIds.push(subId);
      }
      client.subscriptions.clear();
    } else {
      // Unsubscribe from specific subscriptions
      for (const subId of subscriptionIds) {
        if (client.subscriptions.has(subId)) {
          this.subscriptions.delete(subId);
          client.subscriptions.delete(subId);
          removedIds.push(subId);
        }
      }
    }

    this.sendMessage(clientId, {
      type: 'unsubscribed',
      subscriptionIds: removedIds,
      requestId: message.requestId,
      timestamp: new Date().toISOString(),
    });

    metrics.increment('trust_score.websocket.unsubscriptions', removedIds.length, {
      tenantId: client.tenantId,
    });
  }

  private sendMessage(clientId: string, message: any) {
    const client = this.clients.get(clientId);
    if (!client || client.ws.readyState !== 1) return; // 1 = OPEN

    try {
      client.ws.send(JSON.stringify(message));
    } catch (error: any) {
      logger.error(`Error sending WebSocket message to ${clientId}:`, error);
      this.removeClient(clientId);
    }
  }

  private sendError(clientId: string, error: string, requestId?: string) {
    this.sendMessage(clientId, {
      type: 'error',
      error,
      requestId,
      timestamp: new Date().toISOString(),
    });
  }

  // Public method to broadcast trust score events
  broadcast(event: any) {
    const { eventType, data } = event;
    
    // Find matching subscriptions
    const matchingSubscriptions = Array.from(this.subscriptions.values()).filter(sub => {
      // Check event type
      if (!sub.eventTypes.includes(eventType)) return false;
      
      // Check user/device/session filters
      if (sub.userId && data.userId !== sub.userId) return false;
      if (sub.deviceId && data.deviceId !== sub.deviceId) return false;
      if (sub.sessionId && data.sessionId !== sub.sessionId) return false;
      
      // Check score filters
      if (sub.filters) {
        if (sub.filters.minScore && data.score < sub.filters.minScore) return false;
        if (sub.filters.maxScore && data.score > sub.filters.maxScore) return false;
        if (sub.filters.riskLevels && !sub.filters.riskLevels.includes(data.riskLevel)) return false;
      }
      
      return true;
    });

    // Send to matching clients
    for (const subscription of matchingSubscriptions) {
      this.sendMessage(subscription.clientId, {
        type: 'trust_score_event',
        eventType,
        data,
        subscriptionId: subscription.id,
        timestamp: new Date().toISOString(),
      });
    }

    metrics.increment('trust_score.websocket.events_broadcast', 1, {
      eventType,
      recipientCount: matchingSubscriptions.length.toString(),
    });
  }

  getStats() {
    return {
      totalClients: this.clients.size,
      totalSubscriptions: this.subscriptions.size,
      clientsByTenant: Array.from(this.clients.values()).reduce((acc: any, client) => {
        acc[client.tenantId] = (acc[client.tenantId] || 0) + 1;
        return acc;
      }, {}),
    };
  }
}

// Global WebSocket manager instance
const wsManager = new TrustScoreWebSocketManager();

// WebSocket connection handler for trust score updates
export async function GET(request: NextRequest) {
  try {
    // Extract WebSocket upgrade headers
    const upgradeHeader = request.headers.get('upgrade');
    const connectionHeader = request.headers.get('connection');

    if (upgradeHeader !== 'websocket' || !connectionHeader?.includes('Upgrade')) {
      // Return connection info for non-WebSocket requests
      const stats = wsManager.getStats();
      return Response.json({
        service: 'Trust Score WebSocket API',
        status: 'running',
        websocket: {
          endpoint: '/api/trust-score/websocket',
          protocol: 'trust-score-v1',
          supportedEvents: [
            'score_calculated',
            'score_updated', 
            'risk_level_changed',
            'threshold_crossed',
            'factor_changed'
          ],
        },
        stats,
        timestamp: new Date().toISOString(),
      });
    }

    // This is a WebSocket upgrade request
    // Note: In a production environment, you'd handle the WebSocket upgrade here
    // For Next.js, you might need to use a custom server or external WebSocket service

    return new Response('WebSocket upgrade not supported in this environment', {
      status: 426,
      headers: {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
      },
    });

  } catch (error: any) {
    logger.error('Trust Score WebSocket connection error:', error);
    
    return Response.json(
      { error: 'WebSocket connection failed' },
      { status: 500 }
    );
  }
}

// For environments that support WebSocket upgrades, export the manager
export { wsManager as TrustScoreWebSocketManager };

// Helper function to trigger trust score events
export function broadcastTrustScoreEvent(eventType: string, data: any) {
  wsManager.broadcast({ eventType, data });
}

// Example usage in trust score calculation:
/*
// After calculating a trust score:
broadcastTrustScoreEvent('score_calculated', {
  id: trustScore.id,
  userId: trustScore.userId,
  deviceId: trustScore.deviceId,
  sessionId: trustScore.sessionId,
  score: trustScore.score,
  riskLevel: trustScore.riskLevel,
  previousScore: previousTrustScore?.score,
  timestamp: trustScore.timestamp,
});

// When risk level changes:
if (previousRiskLevel !== newRiskLevel) {
  broadcastTrustScoreEvent('risk_level_changed', {
    userId,
    deviceId,
    sessionId,
    previousRiskLevel,
    newRiskLevel,
    score: trustScore.score,
    timestamp: new Date().toISOString(),
  });
}

// When crossing thresholds:
const thresholds = { low: 80, medium: 60, high: 40 };
for (const [level, threshold] of Object.entries(thresholds)) {
  if ((previousScore <= threshold && newScore > threshold) ||
      (previousScore > threshold && newScore <= threshold)) {
    broadcastTrustScoreEvent('threshold_crossed', {
      userId,
      deviceId,
      sessionId,
      threshold,
      level,
      direction: newScore > threshold ? 'up' : 'down',
      previousScore,
      newScore,
      timestamp: new Date().toISOString(),
    });
  }
}
*/