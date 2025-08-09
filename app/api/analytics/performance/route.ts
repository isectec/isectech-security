/**
 * Performance Analytics API Route
 * Collects and stores performance metrics for PWA optimization
 */

import { NextRequest, NextResponse } from 'next/server';

interface PerformanceMetric {
  timestamp: number;
  metrics: {
    loadTime: number;
    firstContentfulPaint: number;
    largestContentfulPaint: number;
    firstInputDelay: number;
    cumulativeLayoutShift: number;
    timeToInteractive: number;
    memoryUsage?: {
      used: number;
      total: number;
      limit: number;
    };
    networkInfo?: {
      effectiveType: string;
      downlink: number;
      rtt: number;
      saveData: boolean;
    };
  };
  userAgent: string;
  screen: {
    width: number;
    height: number;
    devicePixelRatio: number;
  };
  battery?: {
    level: number;
    charging: boolean;
  };
}

export async function POST(request: NextRequest) {
  try {
    const performanceData: PerformanceMetric = await request.json();
    
    // Validate required fields
    if (!performanceData.timestamp || !performanceData.metrics) {
      return NextResponse.json(
        { error: 'Invalid performance data' },
        { status: 400 }
      );
    }

    // Extract useful information for logging
    const summary = {
      timestamp: new Date(performanceData.timestamp).toISOString(),
      loadTime: performanceData.metrics.loadTime,
      firstContentfulPaint: performanceData.metrics.firstContentfulPaint,
      largestContentfulPaint: performanceData.metrics.largestContentfulPaint,
      firstInputDelay: performanceData.metrics.firstInputDelay,
      cumulativeLayoutShift: performanceData.metrics.cumulativeLayoutShift,
      deviceType: getDeviceType(performanceData.userAgent),
      screenSize: `${performanceData.screen.width}x${performanceData.screen.height}`,
      pixelRatio: performanceData.screen.devicePixelRatio,
      networkType: performanceData.metrics.networkInfo?.effectiveType,
      batteryLevel: performanceData.battery?.level,
    };

    // Check performance against targets
    const performanceTargets = {
      loadTime: 3000, // 3 seconds
      firstContentfulPaint: 1800, // 1.8 seconds
      largestContentfulPaint: 2500, // 2.5 seconds
      firstInputDelay: 100, // 100ms
      cumulativeLayoutShift: 0.1,
    };

    const meetsTargets = {
      loadTime: performanceData.metrics.loadTime <= performanceTargets.loadTime,
      fcp: performanceData.metrics.firstContentfulPaint <= performanceTargets.firstContentfulPaint,
      lcp: performanceData.metrics.largestContentfulPaint <= performanceTargets.largestContentfulPaint,
      fid: performanceData.metrics.firstInputDelay <= performanceTargets.firstInputDelay,
      cls: performanceData.metrics.cumulativeLayoutShift <= performanceTargets.cumulativeLayoutShift,
    };

    const overallScore = Object.values(meetsTargets).filter(Boolean).length / Object.values(meetsTargets).length;

    console.log('Performance metrics collected:', {
      ...summary,
      score: Math.round(overallScore * 100),
      meetsTargets,
    });

    // In a real implementation, you would:
    // 1. Store the metrics in a time-series database
    // 2. Trigger alerts for performance regressions
    // 3. Generate performance reports and dashboards
    // 4. Use the data to optimize the application

    // Mock storage result
    const analyticsRecord = {
      id: `perf-${Date.now()}`,
      ...performanceData,
      score: overallScore,
      meetsTargets,
      processedAt: new Date().toISOString(),
    };

    return NextResponse.json({
      success: true,
      recordId: analyticsRecord.id,
      score: Math.round(overallScore * 100),
      summary: {
        overall: overallScore >= 0.8 ? 'good' : overallScore >= 0.6 ? 'needs improvement' : 'poor',
        recommendations: generateRecommendations(performanceData.metrics, meetsTargets),
      },
      message: 'Performance metrics recorded successfully',
    });

  } catch (error) {
    console.error('Error recording performance metrics:', error);
    
    return NextResponse.json(
      { 
        error: 'Failed to record performance metrics',
        details: process.env.NODE_ENV === 'development' ? error : undefined 
      },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  // Get performance analytics summary
  const { searchParams } = new URL(request.url);
  const timeframe = searchParams.get('timeframe') || '24h';
  const deviceType = searchParams.get('deviceType');

  try {
    // Mock analytics data
    const analyticsData = {
      timeframe,
      totalRecords: 156,
      averageMetrics: {
        loadTime: 2400,
        firstContentfulPaint: 1600,
        largestContentfulPaint: 2200,
        firstInputDelay: 80,
        cumulativeLayoutShift: 0.08,
        score: 85,
      },
      distribution: {
        good: 132, // 85%
        needsImprovement: 18, // 11%
        poor: 6, // 4%
      },
      topIssues: [
        'Large bundle size affecting load time',
        'Layout shifts during image loading',
        'Slow network conditions on mobile',
      ],
      deviceBreakdown: {
        mobile: { count: 89, averageScore: 82 },
        tablet: { count: 34, averageScore: 87 },
        desktop: { count: 33, averageScore: 89 },
      },
      recommendations: [
        'Implement image lazy loading to reduce initial bundle size',
        'Add explicit width/height attributes to images to prevent layout shifts',
        'Consider service worker caching for better offline performance',
      ],
    };

    return NextResponse.json({
      success: true,
      analytics: analyticsData,
    });

  } catch (error) {
    console.error('Error fetching performance analytics:', error);
    
    return NextResponse.json(
      { error: 'Failed to fetch performance analytics' },
      { status: 500 }
    );
  }
}

// Helper functions
function getDeviceType(userAgent: string): 'mobile' | 'tablet' | 'desktop' {
  const ua = userAgent.toLowerCase();
  
  if (ua.includes('mobile')) return 'mobile';
  if (ua.includes('tablet') || ua.includes('ipad')) return 'tablet';
  return 'desktop';
}

function generateRecommendations(metrics: PerformanceMetric['metrics'], meetsTargets: Record<string, boolean>): string[] {
  const recommendations: string[] = [];
  
  if (!meetsTargets.loadTime) {
    recommendations.push('Optimize bundle size and implement code splitting');
  }
  
  if (!meetsTargets.fcp) {
    recommendations.push('Minimize render-blocking resources and optimize critical rendering path');
  }
  
  if (!meetsTargets.lcp) {
    recommendations.push('Optimize largest content elements and consider lazy loading');
  }
  
  if (!meetsTargets.fid) {
    recommendations.push('Reduce JavaScript execution time and main thread blocking');
  }
  
  if (!meetsTargets.cls) {
    recommendations.push('Add size attributes to images and avoid dynamic content insertion');
  }
  
  if (metrics.memoryUsage && metrics.memoryUsage.used / metrics.memoryUsage.limit > 0.8) {
    recommendations.push('Optimize memory usage and implement memory cleanup');
  }
  
  if (metrics.networkInfo?.effectiveType === 'slow-2g' || metrics.networkInfo?.effectiveType === '2g') {
    recommendations.push('Implement aggressive caching and data compression for slow networks');
  }
  
  return recommendations;
}