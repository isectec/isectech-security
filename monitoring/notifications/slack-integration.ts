// iSECTECH Slack Integration for Alerting
// Production-grade Slack notification system for monitoring alerts

import { WebClient } from '@slack/web-api';
import { IncomingWebhook } from '@slack/webhook';
import crypto from 'crypto';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface SlackConfig {
  token: string;
  webhookUrl?: string;
  defaultChannel: string;
  signingSecret?: string;
}

export interface AlertMessage {
  alertName: string;
  status: 'firing' | 'resolved';
  severity: 'critical' | 'warning' | 'info';
  summary: string;
  description: string;
  service?: string;
  environment?: string;
  instance?: string;
  runbookUrl?: string;
  dashboardUrl?: string;
  timestamp: Date;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface SlackMessageOptions {
  channel?: string;
  thread?: string;
  mention?: 'channel' | 'here' | string[];
  color?: string;
  priority?: 'low' | 'normal' | 'high' | 'urgent';
}

export interface IncidentDetails {
  incidentId: string;
  title: string;
  status: 'investigating' | 'identified' | 'monitoring' | 'resolved';
  severity: 'low' | 'medium' | 'high' | 'critical';
  commander?: string;
  affectedServices: string[];
  estimatedResolution?: Date;
  timeline: IncidentTimelineEvent[];
}

export interface IncidentTimelineEvent {
  timestamp: Date;
  type: 'detected' | 'investigating' | 'identified' | 'mitigated' | 'resolved';
  message: string;
  author?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLACK NOTIFICATION MANAGER
// ═══════════════════════════════════════════════════════════════════════════════

export class SlackNotificationManager {
  private client: WebClient;
  private webhook?: IncomingWebhook;
  private config: SlackConfig;
  private channelMapping: Map<string, string> = new Map();
  private threadCache: Map<string, string> = new Map();

  constructor(config: SlackConfig) {
    this.config = config;
    this.client = new WebClient(config.token);
    
    if (config.webhookUrl) {
      this.webhook = new IncomingWebhook(config.webhookUrl);
    }

    this.initializeChannelMapping();
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // INITIALIZATION
  // ═════════════════════════════════════════════════════════════════════════════

  private initializeChannelMapping(): void {
    // Map alert types to specific channels
    this.channelMapping.set('critical', '#alerts-critical');
    this.channelMapping.set('warning', '#alerts-warnings');
    this.channelMapping.set('info', '#alerts-info');
    this.channelMapping.set('security', '#alerts-security');
    this.channelMapping.set('database', '#alerts-database');
    this.channelMapping.set('infrastructure', '#alerts-infrastructure');
    this.channelMapping.set('application', '#team-application');
    this.channelMapping.set('performance', '#team-performance');
    this.channelMapping.set('business', '#team-business');
    this.channelMapping.set('maintenance', '#alerts-maintenance');
    this.channelMapping.set('incident', '#incident-response');
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // ALERT NOTIFICATIONS
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Send alert notification to Slack
   */
  async sendAlert(alert: AlertMessage, options: SlackMessageOptions = {}): Promise<string | null> {
    try {
      const channel = this.determineChannel(alert, options.channel);
      const message = this.buildAlertMessage(alert, options);

      // Check if this is part of an ongoing incident thread
      const threadKey = this.generateThreadKey(alert);
      const thread = this.threadCache.get(threadKey) || options.thread;

      const response = await this.client.chat.postMessage({
        channel,
        thread_ts: thread,
        ...message,
      });

      // Cache thread timestamp for follow-up messages
      if (response.ts && alert.status === 'firing') {
        this.threadCache.set(threadKey, response.ts);
        // Clean up thread cache after 24 hours
        setTimeout(() => this.threadCache.delete(threadKey), 24 * 60 * 60 * 1000);
      }

      return response.ts || null;
    } catch (error) {
      console.error('Failed to send Slack alert:', error);
      return null;
    }
  }

  /**
   * Send critical alert with immediate notification
   */
  async sendCriticalAlert(alert: AlertMessage, options: SlackMessageOptions = {}): Promise<string | null> {
    const criticalOptions: SlackMessageOptions = {
      ...options,
      channel: options.channel || '#alerts-critical',
      mention: options.mention || 'channel',
      color: '#d32f2f',
      priority: 'urgent',
    };

    const messageTs = await this.sendAlert(alert, criticalOptions);

    // Send immediate follow-up with escalation information
    if (messageTs && alert.severity === 'critical') {
      await this.sendEscalationInfo(alert, criticalOptions.channel!, messageTs);
    }

    return messageTs;
  }

  /**
   * Send security alert with special formatting
   */
  async sendSecurityAlert(alert: AlertMessage, options: SlackMessageOptions = {}): Promise<string | null> {
    const securityOptions: SlackMessageOptions = {
      ...options,
      channel: options.channel || '#alerts-security',
      mention: options.mention || 'here',
      color: '#ff5722',
      priority: 'high',
    };

    // Add security-specific context
    const securityAlert: AlertMessage = {
      ...alert,
      summary: `🛡️ Security Alert: ${alert.summary}`,
    };

    return this.sendAlert(securityAlert, securityOptions);
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // INCIDENT MANAGEMENT
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Create incident war room
   */
  async createIncidentWarRoom(incident: IncidentDetails): Promise<{ channelId: string; channelName: string } | null> {
    try {
      const channelName = `incident-${incident.incidentId}`;
      
      // Create private channel for incident
      const channelResponse = await this.client.conversations.create({
        name: channelName,
        is_private: true,
      });

      if (!channelResponse.channel?.id) {
        throw new Error('Failed to create incident channel');
      }

      const channelId = channelResponse.channel.id;

      // Set channel topic
      await this.client.conversations.setTopic({
        channel: channelId,
        topic: `Incident ${incident.incidentId}: ${incident.title} | Status: ${incident.status} | Severity: ${incident.severity}`,
      });

      // Post initial incident details
      await this.client.chat.postMessage({
        channel: channelId,
        blocks: this.buildIncidentBlocks(incident),
      });

      // Pin the incident details message
      const messageResponse = await this.client.chat.postMessage({
        channel: channelId,
        text: 'Incident Details (Pinned)',
        blocks: this.buildIncidentBlocks(incident),
      });

      if (messageResponse.ts) {
        await this.client.pins.add({
          channel: channelId,
          timestamp: messageResponse.ts,
        });
      }

      // Notify main incident channel
      await this.client.chat.postMessage({
        channel: '#incident-response',
        text: `🚨 Incident war room created: <#${channelId}> for ${incident.title}`,
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `🚨 *Incident War Room Created*\n\n*Incident:* ${incident.title}\n*Severity:* ${incident.severity}\n*Channel:* <#${channelId}>`,
            },
            accessory: {
              type: 'button',
              text: {
                type: 'plain_text',
                text: 'Join War Room',
              },
              url: `slack://channel?team=${await this.getTeamId()}&id=${channelId}`,
            },
          },
        ],
      });

      return { channelId, channelName };
    } catch (error) {
      console.error('Failed to create incident war room:', error);
      return null;
    }
  }

  /**
   * Update incident status
   */
  async updateIncidentStatus(incident: IncidentDetails, channelId: string): Promise<void> {
    try {
      // Update channel topic
      await this.client.conversations.setTopic({
        channel: channelId,
        topic: `Incident ${incident.incidentId}: ${incident.title} | Status: ${incident.status} | Severity: ${incident.severity}`,
      });

      // Post status update
      await this.client.chat.postMessage({
        channel: channelId,
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `📊 *Incident Status Update*\n\n*Status:* ${incident.status}\n*Severity:* ${incident.severity}`,
            },
          },
          {
            type: 'context',
            elements: [
              {
                type: 'mrkdwn',
                text: `Updated at ${new Date().toLocaleString()}`,
              },
            ],
          },
        ],
      });

      // Notify main incident channel for major status changes
      if (['identified', 'resolved'].includes(incident.status)) {
        await this.client.chat.postMessage({
          channel: '#incident-response',
          text: `📊 Incident ${incident.incidentId} status updated to: ${incident.status}`,
        });
      }
    } catch (error) {
      console.error('Failed to update incident status:', error);
    }
  }

  /**
   * Archive incident war room
   */
  async archiveIncidentWarRoom(incident: IncidentDetails, channelId: string): Promise<void> {
    try {
      // Post final summary
      await this.client.chat.postMessage({
        channel: channelId,
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `✅ *Incident Resolved*\n\n*Incident:* ${incident.title}\n*Duration:* ${this.calculateIncidentDuration(incident)}\n*Final Status:* ${incident.status}`,
            },
          },
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `This channel will be archived in 24 hours. Please complete any post-incident activities before then.`,
            },
          },
        ],
      });

      // Schedule channel archival (24 hours later)
      setTimeout(async () => {
        try {
          await this.client.conversations.archive({ channel: channelId });
        } catch (error) {
          console.error('Failed to archive incident channel:', error);
        }
      }, 24 * 60 * 60 * 1000);

      // Notify main incident channel
      await this.client.chat.postMessage({
        channel: '#incident-response',
        text: `✅ Incident ${incident.incidentId} resolved. War room <#${channelId}> will be archived in 24 hours.`,
      });
    } catch (error) {
      console.error('Failed to archive incident war room:', error);
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // MESSAGE BUILDING
  // ═════════════════════════════════════════════════════════════════════════════

  private buildAlertMessage(alert: AlertMessage, options: SlackMessageOptions) {
    const emoji = this.getAlertEmoji(alert);
    const color = options.color || this.getAlertColor(alert);
    const mention = this.buildMention(options.mention);

    const blocks = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `${emoji} ${alert.status.toUpperCase()}: ${alert.alertName}`,
        },
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Summary:*\n${alert.summary}`,
          },
          {
            type: 'mrkdwn',
            text: `*Severity:*\n${alert.severity.toUpperCase()}`,
          },
          {
            type: 'mrkdwn',
            text: `*Service:*\n${alert.service || 'Unknown'}`,
          },
          {
            type: 'mrkdwn',
            text: `*Environment:*\n${alert.environment || 'Unknown'}`,
          },
        ],
      },
    ];

    if (alert.description) {
      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Description:*\n${alert.description}`,
        },
      });
    }

    // Add action buttons
    const accessories = [];
    if (alert.runbookUrl) {
      accessories.push({
        type: 'button',
        text: { type: 'plain_text', text: 'Runbook' },
        url: alert.runbookUrl,
      });
    }
    if (alert.dashboardUrl) {
      accessories.push({
        type: 'button',
        text: { type: 'plain_text', text: 'Dashboard' },
        url: alert.dashboardUrl,
      });
    }

    if (accessories.length > 0) {
      blocks.push({
        type: 'actions',
        elements: accessories,
      });
    }

    // Add timestamp
    blocks.push({
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `Alert time: ${alert.timestamp.toLocaleString()} | ${alert.instance || 'Unknown instance'}`,
        },
      ],
    });

    return {
      text: `${mention}${alert.summary}`,
      blocks,
      attachments: [{
        color,
        fallback: alert.summary,
      }],
    };
  }

  private buildIncidentBlocks(incident: IncidentDetails) {
    return [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `🚨 Incident ${incident.incidentId}`,
        },
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Title:*\n${incident.title}`,
          },
          {
            type: 'mrkdwn',
            text: `*Status:*\n${incident.status}`,
          },
          {
            type: 'mrkdwn',
            text: `*Severity:*\n${incident.severity}`,
          },
          {
            type: 'mrkdwn',
            text: `*Commander:*\n${incident.commander || 'Unassigned'}`,
          },
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Affected Services:*\n${incident.affectedServices.join(', ')}`,
        },
      },
      {
        type: 'divider',
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Timeline:*\n${incident.timeline.map(event => 
            `• ${event.timestamp.toLocaleTimeString()} - ${event.message}`
          ).join('\n')}`,
        },
      },
    ];
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private determineChannel(alert: AlertMessage, overrideChannel?: string): string {
    if (overrideChannel) return overrideChannel;

    // Determine channel based on alert characteristics
    if (alert.severity === 'critical') return this.channelMapping.get('critical')!;
    if (alert.labels?.category) return this.channelMapping.get(alert.labels.category) || this.config.defaultChannel;
    if (alert.service) return this.channelMapping.get(alert.service) || this.config.defaultChannel;
    if (alert.severity === 'warning') return this.channelMapping.get('warning')!;
    
    return this.config.defaultChannel;
  }

  private getAlertEmoji(alert: AlertMessage): string {
    if (alert.status === 'resolved') return '✅';
    
    switch (alert.severity) {
      case 'critical': return '🔥';
      case 'warning': return '⚠️';
      case 'info': return 'ℹ️';
      default: return '📊';
    }
  }

  private getAlertColor(alert: AlertMessage): string {
    if (alert.status === 'resolved') return '#2e7d32';
    
    switch (alert.severity) {
      case 'critical': return '#d32f2f';
      case 'warning': return '#ff8f00';
      case 'info': return '#1976d2';
      default: return '#666666';
    }
  }

  private buildMention(mention?: 'channel' | 'here' | string[]): string {
    if (!mention) return '';
    
    if (mention === 'channel') return '<!channel> ';
    if (mention === 'here') return '<!here> ';
    if (Array.isArray(mention)) {
      return mention.map(user => `<@${user}>`).join(' ') + ' ';
    }
    
    return '';
  }

  private generateThreadKey(alert: AlertMessage): string {
    // Generate a consistent key for threading related alerts
    return crypto
      .createHash('md5')
      .update(`${alert.alertName}:${alert.service}:${alert.instance}`)
      .digest('hex')
      .substring(0, 8);
  }

  private calculateIncidentDuration(incident: IncidentDetails): string {
    const start = incident.timeline[0]?.timestamp;
    const end = incident.timeline[incident.timeline.length - 1]?.timestamp;
    
    if (!start || !end) return 'Unknown';
    
    const duration = end.getTime() - start.getTime();
    const hours = Math.floor(duration / (1000 * 60 * 60));
    const minutes = Math.floor((duration % (1000 * 60 * 60)) / (1000 * 60));
    
    return `${hours}h ${minutes}m`;
  }

  private async sendEscalationInfo(alert: AlertMessage, channel: string, threadTs: string): Promise<void> {
    const escalationBlocks = [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `🚨 *Critical Alert Escalation Information*`,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `• Check runbook: ${alert.runbookUrl || 'N/A'}\n• Contact on-call engineer if no response in 15 minutes\n• Escalate to management if unresolved in 30 minutes`,
        },
      },
    ];

    await this.client.chat.postMessage({
      channel,
      thread_ts: threadTs,
      blocks: escalationBlocks,
    });
  }

  private async getTeamId(): Promise<string> {
    try {
      const response = await this.client.team.info();
      return response.team?.id || '';
    } catch (error) {
      console.error('Failed to get team ID:', error);
      return '';
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WEBHOOK VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

export function verifySlackWebhook(signature: string, timestamp: string, body: string, signingSecret: string): boolean {
  const baseString = `v0:${timestamp}:${body}`;
  const expectedSignature = `v0=${crypto
    .createHmac('sha256', signingSecret)
    .update(baseString)
    .digest('hex')}`;
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function createSlackNotificationManager(config: SlackConfig): SlackNotificationManager {
  return new SlackNotificationManager(config);
}

// Export singleton instance
export const slackNotifier = createSlackNotificationManager({
  token: process.env.SLACK_BOT_TOKEN || '',
  webhookUrl: process.env.SLACK_WEBHOOK_URL,
  defaultChannel: process.env.SLACK_DEFAULT_CHANNEL || '#alerts-general',
  signingSecret: process.env.SLACK_SIGNING_SECRET,
});