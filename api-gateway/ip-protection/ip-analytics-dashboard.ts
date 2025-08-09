/**
 * IP Analytics Dashboard for iSECTECH API Gateway
 * 
 * Real-time analytics and forensic capabilities for IP-based protection system.
 * Provides comprehensive insights into traffic patterns, threat landscape,
 * and protection effectiveness.
 * 
 * Features:
 * - Real-time IP traffic monitoring with geolocation mapping
 * - Threat intelligence aggregation and visualization
 * - Protection rule effectiveness analysis
 * - Advanced forensic investigation tools
 * - Automated threat detection and alerting
 */

import { IntelligentIPProtectionSystem, IPAnalytics } from './intelligent-ip-protection-system';
import { Redis } from 'ioredis';
import { Logger } from 'winston';
import { z } from 'zod';

// Dashboard configuration schema
const DashboardConfigSchema = z.object({
  realTime: z.object({
    enabled: z.boolean().default(true),
    updateInterval: z.number().default(5000), // milliseconds
    maxDataPoints: z.number().default(1000),
    geolocationEnabled: z.boolean().default(true),
  }),
  forensics: z.object({
    enabled: z.boolean().default(true),
    retentionDays: z.number().default(90),
    maxIncidentHistory: z.number().default(10000),
    autoInvestigation: z.boolean().default(true),
  }),
  alerts: z.object({
    enabled: z.boolean().default(true),
    thresholds: z.object({
      suspiciousActivity: z.number().default(10), // incidents per hour
      massiveTraffic: z.number().default(1000), // requests per minute
      newThreatSource: z.number().default(5), // new malicious IPs per hour
      reputationDrop: z.number().default(20), // reputation score drop
    }),
    channels: z.array(z.enum(['email', 'slack', 'webhook', 'sms'])).default(['email']),
  }),
  reporting: z.object({
    enabled: z.boolean().default(true),
    schedules: z.array(z.enum(['hourly', 'daily', 'weekly', 'monthly'])).default(['daily']),
    recipients: z.array(z.string()).default([]),
  }),
});

type DashboardConfig = z.infer<typeof DashboardConfigSchema>;

interface TrafficMetrics {
  timestamp: number;
  totalRequests: number;
  blockedRequests: number;
  challengedRequests: number;
  allowedRequests: number;
  topCountries: Array<{ country: string; count: number; percentage: number }>;
  topASNs: Array<{ asn: number; count: number; percentage: number }>;
  protectionRules: Array<{ ruleId: string; triggered: number; effectiveness: number }>;
}

interface ThreatIntelligence {
  timestamp: number;
  totalThreats: number;
  newThreats: number;
  categories: Record<string, number>;
  severityDistribution: Record<string, number>;
  topThreatIPs: Array<{ ip: string; score: number; categories: string[] }>;
  trends: Array<{ period: string; count: number; change: number }>;
}

interface IncidentDetails {
  id: string;
  timestamp: number;
  ip: string;
  action: string;
  reason: string;
  score: number;
  metadata: Record<string, any>;
  investigation?: {
    status: 'pending' | 'in_progress' | 'completed';
    findings: string[];
    recommendations: string[];
  };
}

interface GeolocationData {
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  requests: number;
  blocked: number;
  threat_score: number;
}

/**
 * Comprehensive IP Analytics Dashboard System
 */
export class IPAnalyticsDashboard {
  private protectionSystem: IntelligentIPProtectionSystem;
  private redis: Redis;
  private logger: Logger;
  private config: DashboardConfig;
  private metricsBuffer: Map<string, any> = new Map();
  private alertHistory: IncidentDetails[] = [];

  constructor(
    protectionSystem: IntelligentIPProtectionSystem,
    redis: Redis,
    config: DashboardConfig,
    logger: Logger
  ) {
    this.protectionSystem = protectionSystem;
    this.redis = redis;
    this.config = DashboardConfigSchema.parse(config);
    this.logger = logger;

    this.initializeDashboard();
  }

  /**
   * Initialize dashboard services
   */
  private async initializeDashboard(): Promise<void> {
    try {
      if (this.config.realTime.enabled) {
        this.startRealTimeMetrics();
      }

      if (this.config.alerts.enabled) {
        this.startAlertMonitoring();
      }

      if (this.config.reporting.enabled) {
        this.startReportingScheduler();
      }

      this.logger.info('IP Analytics Dashboard initialized successfully', {
        component: 'IPAnalyticsDashboard',
        config: this.config,
      });
    } catch (error) {
      this.logger.error('Failed to initialize IP Analytics Dashboard', {
        component: 'IPAnalyticsDashboard',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get real-time traffic metrics
   */
  async getRealTimeMetrics(): Promise<TrafficMetrics> {
    try {
      const now = Date.now();
      const hourAgo = now - (60 * 60 * 1000);

      // Get request counts
      const [totalRequests, blockedRequests, challengedRequests] = await Promise.all([
        this.redis.zcount('metrics:requests', hourAgo, now),
        this.redis.zcount('metrics:blocked', hourAgo, now),
        this.redis.zcount('metrics:challenged', hourAgo, now),
      ]);

      const allowedRequests = totalRequests - blockedRequests - challengedRequests;

      // Get geographical distribution
      const topCountries = await this.getTopCountries(hourAgo, now);
      const topASNs = await this.getTopASNs(hourAgo, now);

      // Get protection rule effectiveness
      const protectionRules = await this.getProtectionRuleStats(hourAgo, now);

      return {
        timestamp: now,
        totalRequests,
        blockedRequests,
        challengedRequests,
        allowedRequests,
        topCountries,
        topASNs,
        protectionRules,
      };
    } catch (error) {
      this.logger.error('Error getting real-time metrics', {
        component: 'IPAnalyticsDashboard',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get comprehensive threat intelligence data
   */
  async getThreatIntelligence(): Promise<ThreatIntelligence> {
    try {
      const now = Date.now();
      const dayAgo = now - (24 * 60 * 60 * 1000);

      // Get threat statistics
      const threatData = await this.redis.hgetall('threat_intelligence:daily');
      const totalThreats = parseInt(threatData.total_threats || '0');
      const newThreats = parseInt(threatData.new_threats || '0');

      // Get threat categories
      const categories = await this.getThreatCategories(dayAgo, now);
      
      // Get severity distribution
      const severityDistribution = await this.getThreatSeverityDistribution(dayAgo, now);

      // Get top threat IPs
      const topThreatIPs = await this.getTopThreatIPs(dayAgo, now);

      // Get trends
      const trends = await this.getThreatTrends(dayAgo, now);

      return {
        timestamp: now,
        totalThreats,
        newThreats,
        categories,
        severityDistribution,
        topThreatIPs,
        trends,
      };
    } catch (error) {
      this.logger.error('Error getting threat intelligence', {
        component: 'IPAnalyticsDashboard',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get geolocation-based traffic data
   */
  async getGeolocationData(): Promise<GeolocationData[]> {
    if (!this.config.realTime.geolocationEnabled) {
      return [];
    }

    try {
      const geoDataKeys = await this.redis.keys('geo:*');
      const geolocationData: GeolocationData[] = [];

      for (const key of geoDataKeys) {
        const data = await this.redis.hgetall(key);
        if (data && data.country) {
          geolocationData.push({
            country: data.country,
            region: data.region || '',
            city: data.city || '',
            latitude: parseFloat(data.latitude || '0'),
            longitude: parseFloat(data.longitude || '0'),
            requests: parseInt(data.requests || '0'),
            blocked: parseInt(data.blocked || '0'),
            threat_score: parseFloat(data.threat_score || '0'),
          });
        }
      }

      return geolocationData.sort((a, b) => b.requests - a.requests);
    } catch (error) {
      this.logger.error('Error getting geolocation data', {
        component: 'IPAnalyticsDashboard',
        error: error.message,
      });
      return [];
    }
  }

  /**
   * Perform forensic investigation on specific IP
   */
  async investigateIP(ip: string): Promise<{
    basicInfo: IPAnalytics | null;
    timeline: Array<{ timestamp: number; action: string; reason: string }>;
    associations: Array<{ ip: string; relationship: string; confidence: number }>;
    recommendations: string[];
  }> {
    try {
      // Get basic IP analytics
      const basicInfo = await this.protectionSystem.getIPAnalytics(ip);

      // Get request timeline
      const timeline = await this.getIPTimeline(ip);

      // Find associated IPs (same ASN, similar patterns, etc.)
      const associations = await this.findIPAssociations(ip);

      // Generate recommendations
      const recommendations = await this.generateInvestigationRecommendations(ip, basicInfo);

      this.logger.info('Forensic investigation completed', {
        component: 'IPAnalyticsDashboard',
        ip,
        timelineEvents: timeline.length,
        associations: associations.length,
        recommendations: recommendations.length,
      });

      return {
        basicInfo,
        timeline,
        associations,
        recommendations,
      };
    } catch (error) {
      this.logger.error('Error investigating IP', {
        component: 'IPAnalyticsDashboard',
        ip,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Generate comprehensive security report
   */
  async generateSecurityReport(period: '24h' | '7d' | '30d' = '24h'): Promise<{
    summary: {
      period: string;
      totalRequests: number;
      blockedRequests: number;
      topThreats: Array<{ ip: string; score: number; country: string }>;
      newRules: number;
      effectiveness: number;
    };
    trends: {
      traffic: Array<{ timestamp: number; requests: number; blocked: number }>;
      threats: Array<{ timestamp: number; newThreats: number; categories: string[] }>;
      geography: Array<{ country: string; requests: number; change: number }>;
    };
    recommendations: string[];
  }> {
    try {
      const periodMs = this.getPeriodMilliseconds(period);
      const now = Date.now();
      const startTime = now - periodMs;

      // Generate summary statistics
      const summary = await this.generateReportSummary(startTime, now, period);

      // Generate trend analysis
      const trends = await this.generateTrendAnalysis(startTime, now, period);

      // Generate security recommendations
      const recommendations = await this.generateSecurityRecommendations(startTime, now);

      this.logger.info('Security report generated', {
        component: 'IPAnalyticsDashboard',
        period,
        summary,
      });

      return {
        summary,
        trends,
        recommendations,
      };
    } catch (error) {
      this.logger.error('Error generating security report', {
        component: 'IPAnalyticsDashboard',
        period,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get top countries by request volume
   */
  private async getTopCountries(start: number, end: number): Promise<Array<{ country: string; count: number; percentage: number }>> {
    try {
      const countries = await this.redis.zrevrangebyscore(
        'metrics:countries', end, start, 'WITHSCORES', 'LIMIT', 0, 10
      );

      const totalRequests = await this.redis.zcount('metrics:requests', start, end);
      const result = [];

      for (let i = 0; i < countries.length; i += 2) {
        const country = countries[i];
        const count = parseInt(countries[i + 1]);
        const percentage = totalRequests > 0 ? (count / totalRequests) * 100 : 0;

        result.push({ country, count, percentage });
      }

      return result;
    } catch (error) {
      this.logger.error('Error getting top countries', { error: error.message });
      return [];
    }
  }

  /**
   * Get top ASNs by request volume
   */
  private async getTopASNs(start: number, end: number): Promise<Array<{ asn: number; count: number; percentage: number }>> {
    try {
      const asns = await this.redis.zrevrangebyscore(
        'metrics:asns', end, start, 'WITHSCORES', 'LIMIT', 0, 10
      );

      const totalRequests = await this.redis.zcount('metrics:requests', start, end);
      const result = [];

      for (let i = 0; i < asns.length; i += 2) {
        const asn = parseInt(asns[i]);
        const count = parseInt(asns[i + 1]);
        const percentage = totalRequests > 0 ? (count / totalRequests) * 100 : 0;

        result.push({ asn, count, percentage });
      }

      return result;
    } catch (error) {
      this.logger.error('Error getting top ASNs', { error: error.message });
      return [];
    }
  }

  /**
   * Get protection rule effectiveness statistics
   */
  private async getProtectionRuleStats(start: number, end: number): Promise<Array<{ ruleId: string; triggered: number; effectiveness: number }>> {
    try {
      const rules = await this.redis.hgetall('metrics:rules');
      const result = [];

      for (const [ruleId, data] of Object.entries(rules)) {
        const ruleData = JSON.parse(data);
        const triggered = ruleData.triggered || 0;
        const falsePositives = ruleData.falsePositives || 0;
        const effectiveness = triggered > 0 ? ((triggered - falsePositives) / triggered) * 100 : 0;

        result.push({
          ruleId,
          triggered,
          effectiveness,
        });
      }

      return result.sort((a, b) => b.triggered - a.triggered).slice(0, 10);
    } catch (error) {
      this.logger.error('Error getting protection rule stats', { error: error.message });
      return [];
    }
  }

  /**
   * Get threat categories distribution
   */
  private async getThreatCategories(start: number, end: number): Promise<Record<string, number>> {
    try {
      const categories = await this.redis.hgetall('metrics:threat_categories');
      return Object.fromEntries(
        Object.entries(categories).map(([key, value]) => [key, parseInt(value)])
      );
    } catch (error) {
      this.logger.error('Error getting threat categories', { error: error.message });
      return {};
    }
  }

  /**
   * Get threat severity distribution
   */
  private async getThreatSeverityDistribution(start: number, end: number): Promise<Record<string, number>> {
    try {
      const severity = await this.redis.hgetall('metrics:threat_severity');
      return Object.fromEntries(
        Object.entries(severity).map(([key, value]) => [key, parseInt(value)])
      );
    } catch (error) {
      this.logger.error('Error getting threat severity distribution', { error: error.message });
      return {};
    }
  }

  /**
   * Get top threat IPs
   */
  private async getTopThreatIPs(start: number, end: number): Promise<Array<{ ip: string; score: number; categories: string[] }>> {
    try {
      const threatIPs = await this.redis.zrevrangebyscore(
        'metrics:threat_ips', 100, 50, 'WITHSCORES', 'LIMIT', 0, 20
      );

      const result = [];
      for (let i = 0; i < threatIPs.length; i += 2) {
        const ip = threatIPs[i];
        const score = parseInt(threatIPs[i + 1]);
        
        // Get categories for this IP
        const categoriesData = await this.redis.hget('threat_categories', ip);
        const categories = categoriesData ? JSON.parse(categoriesData) : [];

        result.push({ ip, score, categories });
      }

      return result;
    } catch (error) {
      this.logger.error('Error getting top threat IPs', { error: error.message });
      return [];
    }
  }

  /**
   * Get threat trends over time
   */
  private async getThreatTrends(start: number, end: number): Promise<Array<{ period: string; count: number; change: number }>> {
    try {
      const hourlyTrends = await this.redis.zrangebyscore(
        'metrics:threat_trends', start, end, 'WITHSCORES'
      );

      const result = [];
      for (let i = 0; i < hourlyTrends.length; i += 2) {
        const timestamp = parseInt(hourlyTrends[i]);
        const count = parseInt(hourlyTrends[i + 1]);
        const period = new Date(timestamp).toISOString();
        
        // Calculate change from previous period
        const prevCount = i > 0 ? parseInt(hourlyTrends[i - 1]) : 0;
        const change = prevCount > 0 ? ((count - prevCount) / prevCount) * 100 : 0;

        result.push({ period, count, change });
      }

      return result;
    } catch (error) {
      this.logger.error('Error getting threat trends', { error: error.message });
      return [];
    }
  }

  /**
   * Get IP request timeline
   */
  private async getIPTimeline(ip: string): Promise<Array<{ timestamp: number; action: string; reason: string }>> {
    try {
      const timelineData = await this.redis.lrange(`timeline:${ip}`, 0, -1);
      return timelineData.map(entry => JSON.parse(entry)).reverse();
    } catch (error) {
      this.logger.error('Error getting IP timeline', { ip, error: error.message });
      return [];
    }
  }

  /**
   * Find IP associations for forensic analysis
   */
  private async findIPAssociations(ip: string): Promise<Array<{ ip: string; relationship: string; confidence: number }>> {
    try {
      // This is a simplified example - real implementation would use
      // sophisticated correlation algorithms
      const associations = [];
      
      // Same ASN associations
      const ipAnalytics = await this.protectionSystem.getIPAnalytics(ip);
      if (ipAnalytics?.asn) {
        const sameASNIPs = await this.redis.smembers(`asn:${ipAnalytics.asn}`);
        for (const relatedIP of sameASNIPs.slice(0, 10)) {
          if (relatedIP !== ip) {
            associations.push({
              ip: relatedIP,
              relationship: 'Same ASN',
              confidence: 0.7,
            });
          }
        }
      }

      return associations;
    } catch (error) {
      this.logger.error('Error finding IP associations', { ip, error: error.message });
      return [];
    }
  }

  /**
   * Generate investigation recommendations
   */
  private async generateInvestigationRecommendations(ip: string, analytics: IPAnalytics | null): Promise<string[]> {
    const recommendations = [];

    if (!analytics) {
      recommendations.push('IP has no historical data - consider adding to monitoring list');
      return recommendations;
    }

    if (analytics.reputationScore > 70) {
      recommendations.push('High reputation risk - consider immediate blocking');
      recommendations.push('Review all recent activities from this IP');
    }

    if (analytics.blockedRequests > analytics.totalRequests * 0.5) {
      recommendations.push('High block rate indicates persistent malicious behavior');
      recommendations.push('Consider permanent ban or extended temporary ban');
    }

    if (analytics.country && ['CN', 'RU', 'KP'].includes(analytics.country)) {
      recommendations.push('IP originates from high-risk geographical region');
      recommendations.push('Apply enhanced monitoring and stricter policies');
    }

    return recommendations;
  }

  /**
   * Convert period string to milliseconds
   */
  private getPeriodMilliseconds(period: string): number {
    switch (period) {
      case '24h': return 24 * 60 * 60 * 1000;
      case '7d': return 7 * 24 * 60 * 60 * 1000;
      case '30d': return 30 * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }

  /**
   * Generate report summary
   */
  private async generateReportSummary(start: number, end: number, period: string): Promise<any> {
    const totalRequests = await this.redis.zcount('metrics:requests', start, end);
    const blockedRequests = await this.redis.zcount('metrics:blocked', start, end);
    
    // Get top threats
    const topThreats = await this.getTopThreatIPs(start, end);
    
    // Calculate effectiveness
    const effectiveness = totalRequests > 0 ? ((totalRequests - blockedRequests) / totalRequests) * 100 : 100;

    return {
      period,
      totalRequests,
      blockedRequests,
      topThreats: topThreats.slice(0, 5),
      newRules: 0, // Would be calculated based on actual rule additions
      effectiveness,
    };
  }

  /**
   * Generate trend analysis
   */
  private async generateTrendAnalysis(start: number, end: number, period: string): Promise<any> {
    // Simplified implementation - would include more sophisticated analysis
    return {
      traffic: [],
      threats: [],
      geography: [],
    };
  }

  /**
   * Generate security recommendations
   */
  private async generateSecurityRecommendations(start: number, end: number): Promise<string[]> {
    const recommendations = [];
    
    const blockedRequests = await this.redis.zcount('metrics:blocked', start, end);
    if (blockedRequests > 1000) {
      recommendations.push('Consider implementing more aggressive rate limiting');
      recommendations.push('Review and update threat intelligence feeds');
    }

    recommendations.push('Regular review of protection rules effectiveness');
    recommendations.push('Update geolocation policies based on traffic patterns');
    
    return recommendations;
  }

  /**
   * Start real-time metrics collection
   */
  private startRealTimeMetrics(): void {
    setInterval(async () => {
      try {
        const metrics = await this.getRealTimeMetrics();
        this.metricsBuffer.set('latest', metrics);
      } catch (error) {
        this.logger.error('Error in real-time metrics collection', {
          component: 'IPAnalyticsDashboard',
          error: error.message,
        });
      }
    }, this.config.realTime.updateInterval);
  }

  /**
   * Start alert monitoring
   */
  private startAlertMonitoring(): void {
    setInterval(async () => {
      try {
        await this.checkAlertThresholds();
      } catch (error) {
        this.logger.error('Error in alert monitoring', {
          component: 'IPAnalyticsDashboard',
          error: error.message,
        });
      }
    }, 60000); // Check every minute
  }

  /**
   * Check alert thresholds and trigger alerts
   */
  private async checkAlertThresholds(): Promise<void> {
    const now = Date.now();
    const hourAgo = now - (60 * 60 * 1000);

    // Check suspicious activity threshold
    const suspiciousActivity = await this.redis.zcount('metrics:suspicious', hourAgo, now);
    if (suspiciousActivity > this.config.alerts.thresholds.suspiciousActivity) {
      await this.triggerAlert('suspicious_activity', {
        count: suspiciousActivity,
        threshold: this.config.alerts.thresholds.suspiciousActivity,
      });
    }

    // Add more threshold checks as needed
  }

  /**
   * Trigger security alert
   */
  private async triggerAlert(type: string, data: any): Promise<void> {
    const alert: IncidentDetails = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      ip: data.ip || 'N/A',
      action: 'ALERT',
      reason: `Alert triggered: ${type}`,
      score: 0,
      metadata: data,
    };

    this.alertHistory.push(alert);
    
    this.logger.warn('Security alert triggered', {
      component: 'IPAnalyticsDashboard',
      type,
      data,
    });

    // Send notifications based on configured channels
    for (const channel of this.config.alerts.channels) {
      await this.sendNotification(channel, alert);
    }
  }

  /**
   * Send notification through specified channel
   */
  private async sendNotification(channel: string, alert: IncidentDetails): Promise<void> {
    // Placeholder implementation - would integrate with actual notification services
    this.logger.info(`Sending ${channel} notification for alert ${alert.id}`);
  }

  /**
   * Start reporting scheduler
   */
  private startReportingScheduler(): void {
    // Placeholder implementation for scheduled reporting
    this.logger.info('Reporting scheduler started');
  }

  /**
   * Get dashboard status
   */
  getStatus(): {
    status: string;
    metrics: any;
    alerts: number;
    uptime: number;
  } {
    return {
      status: 'active',
      metrics: this.metricsBuffer.get('latest') || {},
      alerts: this.alertHistory.length,
      uptime: Date.now(),
    };
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown(): Promise<void> {
    this.metricsBuffer.clear();
    this.alertHistory.length = 0;
    this.logger.info('IP Analytics Dashboard shutdown completed');
  }
}

// Export configuration schema
export { DashboardConfigSchema };
export type { DashboardConfig, TrafficMetrics, ThreatIntelligence, IncidentDetails, GeolocationData };