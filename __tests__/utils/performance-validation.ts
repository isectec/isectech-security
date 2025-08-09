/**
 * Performance Validation and Benchmarking Utilities
 * 
 * This module provides comprehensive performance validation capabilities for:
 * - DR drills RTO/RPO compliance
 * - Mobile application performance metrics
 * - API rate limiting effectiveness
 * - System scalability and reliability
 */

export interface PerformanceMetrics {
  timestamp: Date;
  testType: string;
  component: string;
  metrics: {
    responseTime?: {
      average: number;
      median: number;
      p95: number;
      p99: number;
      max: number;
    };
    throughput?: {
      requestsPerSecond: number;
      transactionsPerSecond: number;
      bytesPerSecond: number;
    };
    reliability?: {
      availability: number; // percentage
      errorRate: number; // percentage
      successRate: number; // percentage
    };
    scalability?: {
      maxConcurrentUsers: number;
      maxRequestsPerSecond: number;
      resourceUtilization: number; // percentage
    };
    drMetrics?: {
      rto: number; // minutes
      rpo: number; // minutes
      mttr: number; // minutes (Mean Time To Recovery)
      mtbf: number; // hours (Mean Time Between Failures)
    };
    mobileMetrics?: {
      loadTime: number; // milliseconds
      timeToInteractive: number; // milliseconds
      firstContentfulPaint: number; // milliseconds
      cumulativeLayoutShift: number;
      batteryImpact: number; // percentage
      memoryUsage: number; // MB
    };
    rateLimitingMetrics?: {
      blockingEffectiveness: number; // percentage
      falsePositiveRate: number; // percentage
      detectionTime: number; // milliseconds
      adaptationTime: number; // milliseconds
    };
  };
}

export interface PerformanceThresholds {
  responseTime: {
    average: number;
    p95: number;
    p99: number;
  };
  throughput: {
    minRequestsPerSecond: number;
  };
  reliability: {
    minAvailability: number;
    maxErrorRate: number;
  };
  drCompliance: {
    maxRTO: number; // minutes
    maxRPO: number; // minutes
  };
  mobilePerformance: {
    maxLoadTime: number; // milliseconds
    maxTimeToInteractive: number; // milliseconds
    minFPS: number;
  };
  rateLimitingEffectiveness: {
    minBlockingRate: number; // percentage
    maxFalsePositiveRate: number; // percentage
    maxDetectionTime: number; // milliseconds
  };
}

export class PerformanceValidator {
  private thresholds: PerformanceThresholds;
  private metrics: PerformanceMetrics[] = [];

  constructor(thresholds: PerformanceThresholds) {
    this.thresholds = thresholds;
  }

  /**
   * Validate DR drill performance against RTO/RPO targets
   */
  validateDRPerformance(metrics: PerformanceMetrics): {
    passed: boolean;
    violations: string[];
    score: number;
  } {
    const violations: string[] = [];
    let score = 100;

    if (!metrics.metrics.drMetrics) {
      return { passed: false, violations: ['DR metrics not available'], score: 0 };
    }

    const drMetrics = metrics.metrics.drMetrics;

    // Validate RTO (Recovery Time Objective)
    if (drMetrics.rto > this.thresholds.drCompliance.maxRTO) {
      violations.push(
        `RTO violation: ${drMetrics.rto}min > ${this.thresholds.drCompliance.maxRTO}min`
      );
      score -= 40;
    }

    // Validate RPO (Recovery Point Objective)  
    if (drMetrics.rpo > this.thresholds.drCompliance.maxRPO) {
      violations.push(
        `RPO violation: ${drMetrics.rpo}min > ${this.thresholds.drCompliance.maxRPO}min`
      );
      score -= 30;
    }

    // Validate system availability during DR
    if (metrics.metrics.reliability && metrics.metrics.reliability.availability < this.thresholds.reliability.minAvailability) {
      violations.push(
        `Availability violation: ${metrics.metrics.reliability.availability}% < ${this.thresholds.reliability.minAvailability}%`
      );
      score -= 20;
    }

    // Validate error rates during DR
    if (metrics.metrics.reliability && metrics.metrics.reliability.errorRate > this.thresholds.reliability.maxErrorRate) {
      violations.push(
        `Error rate violation: ${metrics.metrics.reliability.errorRate}% > ${this.thresholds.reliability.maxErrorRate}%`
      );
      score -= 10;
    }

    return {
      passed: violations.length === 0,
      violations,
      score: Math.max(0, score)
    };
  }

  /**
   * Validate mobile application performance
   */
  validateMobilePerformance(metrics: PerformanceMetrics): {
    passed: boolean;
    violations: string[];
    score: number;
  } {
    const violations: string[] = [];
    let score = 100;

    if (!metrics.metrics.mobileMetrics) {
      return { passed: false, violations: ['Mobile metrics not available'], score: 0 };
    }

    const mobileMetrics = metrics.metrics.mobileMetrics;

    // Validate load time (< 3 seconds target)
    if (mobileMetrics.loadTime > this.thresholds.mobilePerformance.maxLoadTime) {
      violations.push(
        `Load time violation: ${mobileMetrics.loadTime}ms > ${this.thresholds.mobilePerformance.maxLoadTime}ms`
      );
      score -= 25;
    }

    // Validate Time to Interactive
    if (mobileMetrics.timeToInteractive > this.thresholds.mobilePerformance.maxTimeToInteractive) {
      violations.push(
        `Time to Interactive violation: ${mobileMetrics.timeToInteractive}ms > ${this.thresholds.mobilePerformance.maxTimeToInteractive}ms`
      );
      score -= 20;
    }

    // Validate Core Web Vitals
    if (mobileMetrics.firstContentfulPaint > 1800) { // 1.8s FCP threshold
      violations.push(
        `First Contentful Paint violation: ${mobileMetrics.firstContentfulPaint}ms > 1800ms`
      );
      score -= 15;
    }

    if (mobileMetrics.cumulativeLayoutShift > 0.1) { // CLS threshold
      violations.push(
        `Cumulative Layout Shift violation: ${mobileMetrics.cumulativeLayoutShift} > 0.1`
      );
      score -= 15;
    }

    // Validate battery impact (< 5% target)
    if (mobileMetrics.batteryImpact > 5) {
      violations.push(
        `Battery impact violation: ${mobileMetrics.batteryImpact}% > 5%`
      );
      score -= 15;
    }

    // Validate memory usage
    if (mobileMetrics.memoryUsage > 100) { // 100MB threshold
      violations.push(
        `Memory usage violation: ${mobileMetrics.memoryUsage}MB > 100MB`
      );
      score -= 10;
    }

    return {
      passed: violations.length === 0,
      violations,
      score: Math.max(0, score)
    };
  }

  /**
   * Validate API rate limiting performance
   */
  validateRateLimitingPerformance(metrics: PerformanceMetrics): {
    passed: boolean;
    violations: string[];
    score: number;
  } {
    const violations: string[] = [];
    let score = 100;

    if (!metrics.metrics.rateLimitingMetrics) {
      return { passed: false, violations: ['Rate limiting metrics not available'], score: 0 };
    }

    const rateLimitingMetrics = metrics.metrics.rateLimitingMetrics;

    // Validate blocking effectiveness (> 90% target)
    if (rateLimitingMetrics.blockingEffectiveness < this.thresholds.rateLimitingEffectiveness.minBlockingRate) {
      violations.push(
        `Blocking effectiveness violation: ${rateLimitingMetrics.blockingEffectiveness}% < ${this.thresholds.rateLimitingEffectiveness.minBlockingRate}%`
      );
      score -= 40;
    }

    // Validate false positive rate (< 1% target)
    if (rateLimitingMetrics.falsePositiveRate > this.thresholds.rateLimitingEffectiveness.maxFalsePositiveRate) {
      violations.push(
        `False positive rate violation: ${rateLimitingMetrics.falsePositiveRate}% > ${this.thresholds.rateLimitingEffectiveness.maxFalsePositiveRate}%`
      );
      score -= 30;
    }

    // Validate detection time
    if (rateLimitingMetrics.detectionTime > this.thresholds.rateLimitingEffectiveness.maxDetectionTime) {
      violations.push(
        `Detection time violation: ${rateLimitingMetrics.detectionTime}ms > ${this.thresholds.rateLimitingEffectiveness.maxDetectionTime}ms`
      );
      score -= 20;
    }

    // Validate system performance impact
    if (metrics.metrics.responseTime && metrics.metrics.responseTime.average > this.thresholds.responseTime.average) {
      violations.push(
        `Response time impact: ${metrics.metrics.responseTime.average}ms > ${this.thresholds.responseTime.average}ms`
      );
      score -= 10;
    }

    return {
      passed: violations.length === 0,
      violations,
      score: Math.max(0, score)
    };
  }

  /**
   * Validate overall system performance
   */
  validateSystemPerformance(metrics: PerformanceMetrics): {
    passed: boolean;
    violations: string[];
    score: number;
  } {
    const violations: string[] = [];
    let score = 100;

    // Validate response time metrics
    if (metrics.metrics.responseTime) {
      const responseTime = metrics.metrics.responseTime;
      
      if (responseTime.average > this.thresholds.responseTime.average) {
        violations.push(
          `Average response time violation: ${responseTime.average}ms > ${this.thresholds.responseTime.average}ms`
        );
        score -= 20;
      }

      if (responseTime.p95 > this.thresholds.responseTime.p95) {
        violations.push(
          `P95 response time violation: ${responseTime.p95}ms > ${this.thresholds.responseTime.p95}ms`
        );
        score -= 15;
      }

      if (responseTime.p99 > this.thresholds.responseTime.p99) {
        violations.push(
          `P99 response time violation: ${responseTime.p99}ms > ${this.thresholds.responseTime.p99}ms`
        );
        score -= 10;
      }
    }

    // Validate throughput metrics
    if (metrics.metrics.throughput) {
      const throughput = metrics.metrics.throughput;
      
      if (throughput.requestsPerSecond < this.thresholds.throughput.minRequestsPerSecond) {
        violations.push(
          `Throughput violation: ${throughput.requestsPerSecond} RPS < ${this.thresholds.throughput.minRequestsPerSecond} RPS`
        );
        score -= 25;
      }
    }

    // Validate reliability metrics
    if (metrics.metrics.reliability) {
      const reliability = metrics.metrics.reliability;
      
      if (reliability.availability < this.thresholds.reliability.minAvailability) {
        violations.push(
          `Availability violation: ${reliability.availability}% < ${this.thresholds.reliability.minAvailability}%`
        );
        score -= 20;
      }

      if (reliability.errorRate > this.thresholds.reliability.maxErrorRate) {
        violations.push(
          `Error rate violation: ${reliability.errorRate}% > ${this.thresholds.reliability.maxErrorRate}%`
        );
        score -= 10;
      }
    }

    return {
      passed: violations.length === 0,
      violations,
      score: Math.max(0, score)
    };
  }

  /**
   * Generate comprehensive performance report
   */
  generatePerformanceReport(): {
    summary: {
      totalTests: number;
      passedTests: number;
      failedTests: number;
      overallScore: number;
      overallGrade: string;
    };
    categoryResults: {
      drPerformance: { score: number; violations: string[] };
      mobilePerformance: { score: number; violations: string[] };
      rateLimitingPerformance: { score: number; violations: string[] };
      systemPerformance: { score: number; violations: string[] };
    };
    recommendations: string[];
    trends: {
      performanceOverTime: Array<{ timestamp: Date; score: number }>;
      degradationAlerts: string[];
    };
  } {
    const results = {
      drPerformance: { score: 0, violations: [] as string[] },
      mobilePerformance: { score: 0, violations: [] as string[] },
      rateLimitingPerformance: { score: 0, violations: [] as string[] },
      systemPerformance: { score: 0, violations: [] as string[] }
    };

    let totalTests = 0;
    let passedTests = 0;
    let totalScore = 0;

    // Process all collected metrics
    this.metrics.forEach(metric => {
      totalTests++;

      switch (metric.testType) {
        case 'dr-drill':
          const drResult = this.validateDRPerformance(metric);
          results.drPerformance.score = drResult.score;
          results.drPerformance.violations = drResult.violations;
          if (drResult.passed) passedTests++;
          totalScore += drResult.score;
          break;

        case 'mobile':
          const mobileResult = this.validateMobilePerformance(metric);
          results.mobilePerformance.score = mobileResult.score;
          results.mobilePerformance.violations = mobileResult.violations;
          if (mobileResult.passed) passedTests++;
          totalScore += mobileResult.score;
          break;

        case 'rate-limiting':
          const rateLimitingResult = this.validateRateLimitingPerformance(metric);
          results.rateLimitingPerformance.score = rateLimitingResult.score;
          results.rateLimitingPerformance.violations = rateLimitingResult.violations;
          if (rateLimitingResult.passed) passedTests++;
          totalScore += rateLimitingResult.score;
          break;

        default:
          const systemResult = this.validateSystemPerformance(metric);
          results.systemPerformance.score = systemResult.score;
          results.systemPerformance.violations = systemResult.violations;
          if (systemResult.passed) passedTests++;
          totalScore += systemResult.score;
          break;
      }
    });

    const overallScore = totalTests > 0 ? totalScore / totalTests : 0;
    const overallGrade = this.calculateGrade(overallScore);

    // Generate recommendations
    const recommendations = this.generateRecommendations(results);

    // Analyze trends
    const trends = this.analyzeTrends();

    return {
      summary: {
        totalTests,
        passedTests,
        failedTests: totalTests - passedTests,
        overallScore,
        overallGrade
      },
      categoryResults: results,
      recommendations,
      trends
    };
  }

  /**
   * Add performance metrics for analysis
   */
  addMetrics(metrics: PerformanceMetrics): void {
    this.metrics.push(metrics);
  }

  /**
   * Calculate performance grade based on score
   */
  private calculateGrade(score: number): string {
    if (score >= 95) return 'A+';
    if (score >= 90) return 'A';
    if (score >= 85) return 'A-';
    if (score >= 80) return 'B+';
    if (score >= 75) return 'B';
    if (score >= 70) return 'B-';
    if (score >= 65) return 'C+';
    if (score >= 60) return 'C';
    if (score >= 55) return 'C-';
    return 'F';
  }

  /**
   * Generate performance improvement recommendations
   */
  private generateRecommendations(results: any): string[] {
    const recommendations: string[] = [];

    if (results.drPerformance.score < 90) {
      recommendations.push('Optimize disaster recovery procedures to meet RTO/RPO targets');
      recommendations.push('Consider implementing more aggressive replication strategies');
    }

    if (results.mobilePerformance.score < 85) {
      recommendations.push('Optimize mobile application bundle size and loading strategies');
      recommendations.push('Implement more aggressive caching for mobile resources');
    }

    if (results.rateLimitingPerformance.score < 90) {
      recommendations.push('Fine-tune rate limiting algorithms for better attack detection');
      recommendations.push('Implement more sophisticated behavioral analysis');
    }

    if (results.systemPerformance.score < 80) {
      recommendations.push('Optimize database queries and connection pooling');
      recommendations.push('Consider horizontal scaling of critical services');
    }

    return recommendations;
  }

  /**
   * Analyze performance trends over time
   */
  private analyzeTrends(): {
    performanceOverTime: Array<{ timestamp: Date; score: number }>;
    degradationAlerts: string[];
  } {
    const performanceOverTime = this.metrics.map(metric => ({
      timestamp: metric.timestamp,
      score: this.calculateOverallScore(metric)
    }));

    const degradationAlerts: string[] = [];

    // Check for performance degradation
    if (performanceOverTime.length >= 2) {
      const recent = performanceOverTime.slice(-5); // Last 5 measurements
      const trend = this.calculateTrend(recent.map(p => p.score));
      
      if (trend < -5) { // More than 5 point degradation
        degradationAlerts.push('Performance degradation detected over recent measurements');
      }
    }

    return {
      performanceOverTime,
      degradationAlerts
    };
  }

  /**
   * Calculate overall score for a single metric set
   */
  private calculateOverallScore(metric: PerformanceMetrics): number {
    let totalScore = 0;
    let components = 0;

    if (metric.testType === 'dr-drill') {
      totalScore += this.validateDRPerformance(metric).score;
      components++;
    } else if (metric.testType === 'mobile') {
      totalScore += this.validateMobilePerformance(metric).score;
      components++;
    } else if (metric.testType === 'rate-limiting') {
      totalScore += this.validateRateLimitingPerformance(metric).score;
      components++;
    } else {
      totalScore += this.validateSystemPerformance(metric).score;
      components++;
    }

    return components > 0 ? totalScore / components : 0;
  }

  /**
   * Calculate trend slope
   */
  private calculateTrend(values: number[]): number {
    if (values.length < 2) return 0;

    const n = values.length;
    const sumX = (n * (n - 1)) / 2;
    const sumY = values.reduce((sum, val) => sum + val, 0);
    const sumXY = values.reduce((sum, val, index) => sum + (index * val), 0);
    const sumX2 = (n * (n - 1) * (2 * n - 1)) / 6;

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return slope;
  }

  /**
   * Export metrics to JSON format
   */
  exportMetrics(): string {
    return JSON.stringify({
      thresholds: this.thresholds,
      metrics: this.metrics,
      report: this.generatePerformanceReport(),
      exportTime: new Date().toISOString()
    }, null, 2);
  }

  /**
   * Import metrics from JSON format
   */
  importMetrics(jsonData: string): void {
    const data = JSON.parse(jsonData);
    this.metrics = data.metrics || [];
  }
}

export default PerformanceValidator;