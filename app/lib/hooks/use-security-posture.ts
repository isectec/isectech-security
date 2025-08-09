import { useState, useEffect, useCallback, useRef } from 'react';
import { useWebSocket } from './use-websocket';

// Types for security posture scoring
interface SecurityPostureScore {
  overall: number;
  categories: {
    identity: number;
    network: number;
    data: number;
    application: number;
    infrastructure: number;
    compliance: number;
  };
  trends: {
    category: string;
    current: number;
    previous: number;
    change: number;
    trend: 'up' | 'down' | 'stable';
  }[];
  timestamp: Date;
  confidence: number;
}

interface SecurityPostureTrend {
  timestamp: Date;
  overall: number;
  identity: number;
  network: number;
  data: number;
  application: number;
  infrastructure: number;
  compliance: number;
  incidents: number;
  vulnerabilities: number;
}

interface SecurityInsight {
  id: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  impact: number;
  recommendation: string;
  automatable: boolean;
}

interface UseSecurityPostureOptions {
  userId: string;
  tenantId: string;
  timeRange: '24h' | '7d' | '30d' | '90d';
  realTimeUpdates: boolean;
  includeTrends: boolean;
  includeInsights: boolean;
  refreshInterval?: number;
}

interface UseSecurityPostureReturn {
  currentScore: SecurityPostureScore | null;
  historicalTrends: SecurityPostureTrend[] | null;
  securityInsights: SecurityInsight[] | null;
  isLoading: boolean;
  error: Error | null;
  refreshData: () => Promise<void>;
  getScoreBreakdown: (category: string) => any;
  getTrendAnalysis: (category: string) => any;
  getRecommendations: (category: string) => SecurityInsight[];
  lastUpdated: Date | null;
}

export const useSecurityPosture = (options: UseSecurityPostureOptions): UseSecurityPostureReturn => {
  const {
    userId,
    tenantId,
    timeRange,
    realTimeUpdates,
    includeTrends,
    includeInsights,
    refreshInterval = 30000
  } = options;

  // State management
  const [currentScore, setCurrentScore] = useState<SecurityPostureScore | null>(null);
  const [historicalTrends, setHistoricalTrends] = useState<SecurityPostureTrend[] | null>(null);
  const [securityInsights, setSecurityInsights] = useState<SecurityInsight[] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refreshTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // WebSocket for real-time updates
  const { isConnected, sendMessage, lastMessage } = useWebSocket({
    url: `/api/websocket/security-posture?tenant=${tenantId}`,
    enabled: realTimeUpdates,
    reconnectAttempts: 5,
    reconnectInterval: 3000
  });

  // Generate mock security posture data for demonstration
  const generateMockData = useCallback((): {
    score: SecurityPostureScore;
    trends: SecurityPostureTrend[];
    insights: SecurityInsight[];
  } => {
    const now = new Date();
    const categories = {
      identity: 75 + Math.random() * 20,
      network: 82 + Math.random() * 15,
      data: 68 + Math.random() * 25,
      application: 79 + Math.random() * 18,
      infrastructure: 85 + Math.random() * 12,
      compliance: 72 + Math.random() * 20
    };

    const overall = Object.values(categories).reduce((sum, score) => sum + score, 0) / 6;

    const score: SecurityPostureScore = {
      overall,
      categories,
      trends: Object.entries(categories).map(([category, current]) => {
        const previous = current + (Math.random() - 0.5) * 10;
        const change = ((current - previous) / previous) * 100;
        return {
          category,
          current,
          previous,
          change,
          trend: change > 2 ? 'up' : change < -2 ? 'down' : 'stable'
        };
      }),
      timestamp: now,
      confidence: 0.85 + Math.random() * 0.1
    };

    // Generate historical trends based on time range
    const timeRanges = {
      '24h': { count: 24, interval: 1 },
      '7d': { count: 168, interval: 1 },
      '30d': { count: 30, interval: 24 },
      '90d': { count: 90, interval: 24 }
    };

    const { count, interval } = timeRanges[timeRange];
    const trends: SecurityPostureTrend[] = [];

    for (let i = count; i >= 0; i--) {
      const timestamp = new Date(now.getTime() - i * interval * 60 * 60 * 1000);
      const variation = Math.sin((i / count) * Math.PI * 2) * 5 + (Math.random() - 0.5) * 3;
      
      trends.push({
        timestamp,
        overall: Math.max(50, Math.min(95, overall + variation)),
        identity: Math.max(50, Math.min(95, categories.identity + variation)),
        network: Math.max(50, Math.min(95, categories.network + variation)),
        data: Math.max(50, Math.min(95, categories.data + variation)),
        application: Math.max(50, Math.min(95, categories.application + variation)),
        infrastructure: Math.max(50, Math.min(95, categories.infrastructure + variation)),
        compliance: Math.max(50, Math.min(95, categories.compliance + variation)),
        incidents: Math.floor(Math.random() * 5),
        vulnerabilities: Math.floor(Math.random() * 15) + 5
      });
    }

    // Generate security insights
    const insightTemplates = [
      {
        category: 'identity',
        severity: 'high' as const,
        title: 'Weak Password Policies Detected',
        description: 'Multiple accounts using weak passwords that don\'t meet security requirements.',
        impact: 85,
        recommendation: 'Enforce stronger password policies and enable MFA for all accounts.',
        automatable: true
      },
      {
        category: 'network',
        severity: 'critical' as const,
        title: 'Unencrypted Network Traffic',
        description: 'Sensitive data is being transmitted without proper encryption.',
        impact: 95,
        recommendation: 'Enable TLS 1.3 for all network communications and review firewall rules.',
        automatable: false
      },
      {
        category: 'data',
        severity: 'medium' as const,
        title: 'Excessive Data Access Permissions',
        description: 'Users have access to more sensitive data than required for their roles.',
        impact: 70,
        recommendation: 'Implement principle of least privilege and conduct access reviews.',
        automatable: true
      },
      {
        category: 'application',
        severity: 'high' as const,
        title: 'Outdated Application Dependencies',
        description: 'Critical security vulnerabilities found in outdated application components.',
        impact: 88,
        recommendation: 'Update all application dependencies to latest secure versions.',
        automatable: true
      },
      {
        category: 'infrastructure',
        severity: 'critical' as const,
        title: 'Unpatched System Vulnerabilities',
        description: 'Multiple high-severity vulnerabilities detected in infrastructure components.',
        impact: 92,
        recommendation: 'Apply security patches immediately and implement automated patching.',
        automatable: true
      },
      {
        category: 'compliance',
        severity: 'high' as const,
        title: 'SOC 2 Control Gaps',
        description: 'Several SOC 2 Type II controls are not properly implemented.',
        impact: 80,
        recommendation: 'Review and implement missing SOC 2 controls for certification.',
        automatable: false
      }
    ];

    const insights: SecurityInsight[] = insightTemplates
      .filter(() => Math.random() > 0.3) // Randomly include insights
      .map((template, index) => ({
        ...template,
        id: `insight-${Date.now()}-${index}`
      }));

    return { score, trends, insights };
  }, [timeRange]);

  // Fetch security posture data
  const fetchSecurityPostureData = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);

      // In a real implementation, these would be actual API calls
      // For now, we'll generate mock data
      const { score, trends, insights } = generateMockData();

      setCurrentScore(score);
      
      if (includeTrends) {
        setHistoricalTrends(trends);
      }

      if (includeInsights) {
        setSecurityInsights(insights);
      }

      setLastUpdated(new Date());
    } catch (err) {
      setError(err as Error);
    } finally {
      setIsLoading(false);
    }
  }, [generateMockData, includeTrends, includeInsights]);

  // Handle real-time updates
  useEffect(() => {
    if (realTimeUpdates && lastMessage) {
      try {
        const data = JSON.parse(lastMessage.data);
        
        if (data.type === 'security-posture-update') {
          setCurrentScore(prev => ({
            ...prev,
            ...data.payload,
            timestamp: new Date(data.payload.timestamp)
          }));
          setLastUpdated(new Date());
        }
      } catch (err) {
        console.error('Error processing WebSocket message:', err);
      }
    }
  }, [lastMessage, realTimeUpdates]);

  // Auto-refresh data
  useEffect(() => {
    if (realTimeUpdates && refreshInterval > 0) {
      refreshTimeoutRef.current = setTimeout(() => {
        fetchSecurityPostureData();
      }, refreshInterval);

      return () => {
        if (refreshTimeoutRef.current) {
          clearTimeout(refreshTimeoutRef.current);
        }
      };
    }
  }, [fetchSecurityPostureData, realTimeUpdates, refreshInterval]);

  // Initial data fetch
  useEffect(() => {
    fetchSecurityPostureData();
  }, [fetchSecurityPostureData]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
    };
  }, []);

  // Helper functions
  const getScoreBreakdown = useCallback((category: string) => {
    if (!currentScore) return null;

    const categoryKey = category.toLowerCase() as keyof typeof currentScore.categories;
    const categoryScore = currentScore.categories[categoryKey];
    const categoryTrend = currentScore.trends.find(t => t.category === category.toLowerCase());

    return {
      score: categoryScore,
      trend: categoryTrend,
      historicalData: historicalTrends?.map(trend => ({
        timestamp: trend.timestamp,
        score: trend[categoryKey as keyof SecurityPostureTrend]
      }))
    };
  }, [currentScore, historicalTrends]);

  const getTrendAnalysis = useCallback((category: string) => {
    if (!historicalTrends || historicalTrends.length < 2) return null;

    const categoryKey = category.toLowerCase() as keyof SecurityPostureTrend;
    const recentData = historicalTrends.slice(-7); // Last 7 data points

    const scores = recentData.map(trend => trend[categoryKey] as number);
    const average = scores.reduce((sum, score) => sum + score, 0) / scores.length;
    const trend = scores[scores.length - 1] - scores[0];
    const volatility = Math.sqrt(scores.reduce((sum, score) => sum + Math.pow(score - average, 2), 0) / scores.length);

    return {
      average,
      trend: trend > 2 ? 'improving' : trend < -2 ? 'declining' : 'stable',
      volatility,
      prediction: average + (trend * 0.5), // Simple linear prediction
      confidence: Math.max(0.3, 1 - (volatility / 100))
    };
  }, [historicalTrends]);

  const getRecommendations = useCallback((category: string): SecurityInsight[] => {
    if (!securityInsights) return [];

    return securityInsights
      .filter(insight => insight.category.toLowerCase() === category.toLowerCase())
      .sort((a, b) => b.impact - a.impact);
  }, [securityInsights]);

  const refreshData = useCallback(async () => {
    await fetchSecurityPostureData();
  }, [fetchSecurityPostureData]);

  return {
    currentScore,
    historicalTrends,
    securityInsights,
    isLoading,
    error,
    refreshData,
    getScoreBreakdown,
    getTrendAnalysis,
    getRecommendations,
    lastUpdated
  };
};