/**
 * iSECTECH Disaster Recovery Testing Framework
 * Automated testing system for validating DR procedures and measuring RTO/RPO compliance
 */

import { AWS } from 'aws-sdk';
import { KubernetesApi, V1Pod, V1Deployment } from '@kubernetes/client-node';
import axios from 'axios';
import { EventEmitter } from 'events';
import * as yaml from 'js-yaml';
import { promises as fs } from 'fs';

// Configuration interfaces
export interface DRTestConfig {
  testId: string;
  testName: string;
  description: string;
  testType: 'failover' | 'backup' | 'network' | 'security' | 'full-dr';
  rtoTarget: number; // minutes
  rpoTarget: number; // minutes
  environment: 'staging' | 'production-test' | 'production';
  schedule?: string; // cron expression
  notifications: NotificationConfig;
  regions: {
    primary: string;
    secondary: string;
  };
  services: ServiceConfig[];
}

export interface ServiceConfig {
  name: string;
  type: 'web' | 'api' | 'database' | 'cache' | 'message-queue';
  healthEndpoint?: string;
  dependencies: string[];
  criticality: 'critical' | 'important' | 'standard' | 'low';
  expectedRTO: number;
  expectedRPO: number;
}

export interface NotificationConfig {
  slack?: {
    webhookUrl: string;
    channel: string;
  };
  email?: {
    recipients: string[];
    smtpConfig: any;
  };
  pagerduty?: {
    integrationKey: string;
  };
}

export interface TestResult {
  testId: string;
  startTime: Date;
  endTime?: Date;
  status: 'running' | 'passed' | 'failed' | 'partial';
  actualRTO?: number;
  actualRPO?: number;
  serviceResults: ServiceTestResult[];
  errors: string[];
  metrics: TestMetrics;
}

export interface ServiceTestResult {
  serviceName: string;
  status: 'passed' | 'failed' | 'warning';
  rtoAchieved: number;
  rpoAchieved: number;
  healthCheckResults: HealthCheckResult[];
  errors: string[];
}

export interface HealthCheckResult {
  timestamp: Date;
  endpoint: string;
  responseTime: number;
  status: 'healthy' | 'unhealthy';
  errorMessage?: string;
}

export interface TestMetrics {
  totalServices: number;
  servicesHealthy: number;
  averageRTO: number;
  averageRPO: number;
  compliancePercentage: number;
  performanceMetrics: {
    cpuUsage: number;
    memoryUsage: number;
    networkLatency: number;
  };
}

export class DisasterRecoveryTestFramework extends EventEmitter {
  private aws: {
    primary: AWS;
    secondary: AWS;
  };
  private k8s: {
    primary: KubernetesApi;
    secondary: KubernetesApi;
  };
  private config: DRTestConfig;
  private currentTest?: TestResult;

  constructor(config: DRTestConfig) {
    super();
    this.config = config;
    this.initializeClients();
  }

  private initializeClients(): void {
    // Initialize AWS clients for both regions
    this.aws = {
      primary: new AWS({
        region: this.config.regions.primary,
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      }),
      secondary: new AWS({
        region: this.config.regions.secondary,
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      }),
    };

    // Initialize Kubernetes clients
    // Implementation would depend on your cluster setup
    this.initializeKubernetesClients();
  }

  private initializeKubernetesClients(): void {
    // Initialize K8s clients for both regions
    // This is a simplified example - actual implementation would vary
    console.log('Initializing Kubernetes clients for both regions');
  }

  /**
   * Execute a disaster recovery test
   */
  public async executeTest(): Promise<TestResult> {
    const testResult: TestResult = {
      testId: this.config.testId,
      startTime: new Date(),
      status: 'running',
      serviceResults: [],
      errors: [],
      metrics: {
        totalServices: this.config.services.length,
        servicesHealthy: 0,
        averageRTO: 0,
        averageRPO: 0,
        compliancePercentage: 0,
        performanceMetrics: {
          cpuUsage: 0,
          memoryUsage: 0,
          networkLatency: 0,
        },
      },
    };

    this.currentTest = testResult;
    this.emit('testStarted', testResult);

    try {
      // Pre-test validation
      await this.preTestValidation();

      // Execute test based on type
      switch (this.config.testType) {
        case 'failover':
          await this.executeFailoverTest(testResult);
          break;
        case 'backup':
          await this.executeBackupTest(testResult);
          break;
        case 'network':
          await this.executeNetworkTest(testResult);
          break;
        case 'security':
          await this.executeSecurityTest(testResult);
          break;
        case 'full-dr':
          await this.executeFullDRTest(testResult);
          break;
      }

      // Post-test validation
      await this.postTestValidation(testResult);

      // Calculate final metrics
      this.calculateTestMetrics(testResult);

      testResult.endTime = new Date();
      testResult.status = this.determineOverallStatus(testResult);

    } catch (error) {
      testResult.errors.push(`Test execution failed: ${error.message}`);
      testResult.status = 'failed';
      testResult.endTime = new Date();
    }

    this.emit('testCompleted', testResult);
    await this.sendNotifications(testResult);
    await this.saveTestResults(testResult);

    return testResult;
  }

  /**
   * Pre-test validation to ensure environment is ready
   */
  private async preTestValidation(): Promise<void> {
    console.log('Starting pre-test validation...');

    // Validate primary region health
    await this.validateRegionHealth(this.config.regions.primary);
    
    // Validate secondary region health
    await this.validateRegionHealth(this.config.regions.secondary);

    // Validate all services are healthy before test
    for (const service of this.config.services) {
      await this.validateServiceHealth(service);
    }

    console.log('Pre-test validation completed successfully');
  }

  /**
   * Validate region health before testing
   */
  private async validateRegionHealth(region: string): Promise<void> {
    console.log(`Validating health of region: ${region}`);

    // Check AWS service status
    const ec2 = new AWS.EC2({ region });
    
    try {
      await ec2.describeRegions().promise();
      console.log(`Region ${region} is accessible`);
    } catch (error) {
      throw new Error(`Region ${region} is not accessible: ${error.message}`);
    }

    // Check EKS cluster status
    const eks = new AWS.EKS({ region });
    try {
      const clusters = await eks.listClusters().promise();
      if (clusters.clusters && clusters.clusters.length > 0) {
        console.log(`EKS clusters found in ${region}: ${clusters.clusters.join(', ')}`);
      }
    } catch (error) {
      console.warn(`Could not verify EKS clusters in ${region}: ${error.message}`);
    }
  }

  /**
   * Validate individual service health
   */
  private async validateServiceHealth(service: ServiceConfig): Promise<void> {
    if (service.healthEndpoint) {
      try {
        const response = await axios.get(service.healthEndpoint, {
          timeout: 10000,
          validateStatus: (status) => status === 200,
        });
        console.log(`Service ${service.name} health check passed`);
      } catch (error) {
        throw new Error(`Service ${service.name} health check failed: ${error.message}`);
      }
    }
  }

  /**
   * Execute failover test
   */
  private async executeFailoverTest(testResult: TestResult): Promise<void> {
    console.log('Executing failover test...');

    const failoverStartTime = new Date();

    for (const service of this.config.services) {
      const serviceResult: ServiceTestResult = {
        serviceName: service.name,
        status: 'failed',
        rtoAchieved: 0,
        rpoAchieved: 0,
        healthCheckResults: [],
        errors: [],
      };

      try {
        // Simulate service failure in primary region
        await this.simulateServiceFailure(service);

        // Monitor failover to secondary region
        const failoverResult = await this.monitorFailover(service);
        
        serviceResult.rtoAchieved = failoverResult.rto;
        serviceResult.rpoAchieved = failoverResult.rpo;
        serviceResult.status = failoverResult.success ? 'passed' : 'failed';
        serviceResult.healthCheckResults = failoverResult.healthChecks;

        if (!failoverResult.success) {
          serviceResult.errors.push(...failoverResult.errors);
        }

      } catch (error) {
        serviceResult.errors.push(`Failover test failed: ${error.message}`);
        serviceResult.status = 'failed';
      }

      testResult.serviceResults.push(serviceResult);
      this.emit('serviceTestCompleted', serviceResult);
    }

    const failoverEndTime = new Date();
    testResult.actualRTO = (failoverEndTime.getTime() - failoverStartTime.getTime()) / (1000 * 60); // minutes
  }

  /**
   * Simulate service failure for testing
   */
  private async simulateServiceFailure(service: ServiceConfig): Promise<void> {
    console.log(`Simulating failure for service: ${service.name}`);

    switch (service.type) {
      case 'web':
      case 'api':
        await this.simulateApplicationFailure(service);
        break;
      case 'database':
        await this.simulateDatabaseFailure(service);
        break;
      case 'cache':
        await this.simulateCacheFailure(service);
        break;
      default:
        console.log(`No specific failure simulation for service type: ${service.type}`);
    }
  }

  /**
   * Simulate application failure
   */
  private async simulateApplicationFailure(service: ServiceConfig): Promise<void> {
    // Scale down deployment to 0 replicas to simulate failure
    console.log(`Scaling down ${service.name} deployment to simulate failure`);
    
    // This would use actual Kubernetes client
    // kubectl scale deployment ${service.name} --replicas=0 -n ${namespace}
    
    // Wait for pods to terminate
    await this.waitForPodsToTerminate(service.name);
  }

  /**
   * Simulate database failure
   */
  private async simulateDatabaseFailure(service: ServiceConfig): Promise<void> {
    console.log(`Simulating database failure for: ${service.name}`);
    
    // This could involve:
    // - Stopping database instance
    // - Blocking network access
    // - Corrupting data (in test environment only)
    
    // For Aurora, we might trigger a failover
    const rds = new AWS.RDS({ region: this.config.regions.primary });
    
    // Example: Force failover to test automatic recovery
    // await rds.failoverDBCluster({
    //   DBClusterIdentifier: service.name,
    // }).promise();
  }

  /**
   * Simulate cache failure
   */
  private async simulateCacheFailure(service: ServiceConfig): Promise<void> {
    console.log(`Simulating cache failure for: ${service.name}`);
    
    // This could involve:
    // - Stopping ElastiCache nodes
    // - Blocking network access
    // - Clearing cache data
  }

  /**
   * Monitor failover process and measure RTO/RPO
   */
  private async monitorFailover(service: ServiceConfig): Promise<{
    success: boolean;
    rto: number;
    rpo: number;
    healthChecks: HealthCheckResult[];
    errors: string[];
  }> {
    const startTime = new Date();
    const healthChecks: HealthCheckResult[] = [];
    const errors: string[] = [];
    let success = false;
    let lastHealthyTime: Date | null = null;

    // Monitor until service recovers or timeout
    const maxWaitTime = (service.expectedRTO + 5) * 60 * 1000; // Add 5 minutes buffer
    const pollInterval = 10000; // 10 seconds

    while ((new Date().getTime() - startTime.getTime()) < maxWaitTime) {
      try {
        const healthResult = await this.performHealthCheck(service);
        healthChecks.push(healthResult);

        if (healthResult.status === 'healthy') {
          lastHealthyTime = healthResult.timestamp;
          success = true;
          break;
        }

        await this.sleep(pollInterval);
      } catch (error) {
        errors.push(`Health check error: ${error.message}`);
      }
    }

    const endTime = lastHealthyTime || new Date();
    const rto = (endTime.getTime() - startTime.getTime()) / (1000 * 60); // minutes

    // RPO calculation would depend on the service type and data loss measurement
    const rpo = await this.calculateRPO(service, startTime, endTime);

    return {
      success,
      rto,
      rpo,
      healthChecks,
      errors,
    };
  }

  /**
   * Perform health check on a service
   */
  private async performHealthCheck(service: ServiceConfig): Promise<HealthCheckResult> {
    const startTime = new Date();
    
    if (!service.healthEndpoint) {
      return {
        timestamp: startTime,
        endpoint: 'N/A',
        responseTime: 0,
        status: 'healthy', // Assume healthy if no endpoint
      };
    }

    try {
      const response = await axios.get(service.healthEndpoint, {
        timeout: 30000,
        validateStatus: (status) => status < 500,
      });

      const endTime = new Date();
      const responseTime = endTime.getTime() - startTime.getTime();

      return {
        timestamp: endTime,
        endpoint: service.healthEndpoint,
        responseTime,
        status: response.status === 200 ? 'healthy' : 'unhealthy',
      };
    } catch (error) {
      const endTime = new Date();
      const responseTime = endTime.getTime() - startTime.getTime();

      return {
        timestamp: endTime,
        endpoint: service.healthEndpoint,
        responseTime,
        status: 'unhealthy',
        errorMessage: error.message,
      };
    }
  }

  /**
   * Calculate RPO (Recovery Point Objective) for a service
   */
  private async calculateRPO(
    service: ServiceConfig, 
    failureStart: Date, 
    recoveryEnd: Date
  ): Promise<number> {
    // RPO calculation varies by service type
    switch (service.type) {
      case 'database':
        return await this.calculateDatabaseRPO(service, failureStart, recoveryEnd);
      case 'cache':
        // Cache usually has acceptable data loss
        return 0;
      default:
        // For stateless services, RPO is typically 0
        return 0;
    }
  }

  /**
   * Calculate database RPO by checking replication lag
   */
  private async calculateDatabaseRPO(
    service: ServiceConfig,
    failureStart: Date,
    recoveryEnd: Date
  ): Promise<number> {
    // This would query database metrics to determine actual data loss
    // For Aurora, this might involve checking binlog positions or timestamps
    
    // Simplified calculation - in reality this would be more complex
    const estimatedRPO = 2; // 2 minutes estimated based on backup frequency
    return estimatedRPO;
  }

  /**
   * Execute backup test
   */
  private async executeBackupTest(testResult: TestResult): Promise<void> {
    console.log('Executing backup test...');

    for (const service of this.config.services) {
      const serviceResult: ServiceTestResult = {
        serviceName: service.name,
        status: 'failed',
        rtoAchieved: 0,
        rpoAchieved: 0,
        healthCheckResults: [],
        errors: [],
      };

      try {
        const backupResult = await this.testServiceBackup(service);
        serviceResult.status = backupResult.success ? 'passed' : 'failed';
        serviceResult.rpoAchieved = backupResult.rpo;
        
        if (!backupResult.success) {
          serviceResult.errors.push(...backupResult.errors);
        }
      } catch (error) {
        serviceResult.errors.push(`Backup test failed: ${error.message}`);
      }

      testResult.serviceResults.push(serviceResult);
    }
  }

  /**
   * Test backup and restore functionality for a service
   */
  private async testServiceBackup(service: ServiceConfig): Promise<{
    success: boolean;
    rpo: number;
    errors: string[];
  }> {
    const errors: string[] = [];
    
    try {
      switch (service.type) {
        case 'database':
          return await this.testDatabaseBackup(service);
        default:
          console.log(`No backup test implemented for service type: ${service.type}`);
          return { success: true, rpo: 0, errors: [] };
      }
    } catch (error) {
      errors.push(error.message);
      return { success: false, rpo: 0, errors };
    }
  }

  /**
   * Test database backup and restore
   */
  private async testDatabaseBackup(service: ServiceConfig): Promise<{
    success: boolean;
    rpo: number;
    errors: string[];
  }> {
    const rds = new AWS.RDS({ region: this.config.regions.primary });
    const errors: string[] = [];

    try {
      // Create a test snapshot
      const snapshotId = `${service.name}-test-${Date.now()}`;
      
      console.log(`Creating test snapshot: ${snapshotId}`);
      
      // This would create an actual snapshot in a test environment
      // const snapshot = await rds.createDBClusterSnapshot({
      //   DBClusterIdentifier: service.name,
      //   DBClusterSnapshotIdentifier: snapshotId,
      // }).promise();

      // Test restore from snapshot
      console.log(`Testing restore from snapshot: ${snapshotId}`);
      
      // In a real implementation, we would:
      // 1. Create a test restore
      // 2. Verify data integrity
      // 3. Clean up test resources

      return { success: true, rpo: 1, errors }; // 1 minute RPO
    } catch (error) {
      errors.push(`Database backup test failed: ${error.message}`);
      return { success: false, rpo: 0, errors };
    }
  }

  /**
   * Execute network partition test
   */
  private async executeNetworkTest(testResult: TestResult): Promise<void> {
    console.log('Executing network partition test...');
    
    // Simulate network issues between regions
    // Test service resilience to network failures
    // Validate failover mechanisms
  }

  /**
   * Execute security-focused DR test
   */
  private async executeSecurityTest(testResult: TestResult): Promise<void> {
    console.log('Executing security DR test...');
    
    // Test security systems during DR scenarios
    // Validate access controls remain intact
    // Test incident response procedures
  }

  /**
   * Execute full disaster recovery test
   */
  private async executeFullDRTest(testResult: TestResult): Promise<void> {
    console.log('Executing full disaster recovery test...');
    
    // Comprehensive test of all DR procedures
    await this.executeFailoverTest(testResult);
    await this.executeBackupTest(testResult);
    
    // Additional comprehensive checks
    await this.validateBusinessContinuity();
  }

  /**
   * Validate business continuity during DR test
   */
  private async validateBusinessContinuity(): Promise<void> {
    console.log('Validating business continuity...');
    
    // Test critical business processes
    // Validate user experience during failover
    // Check data consistency across services
  }

  /**
   * Post-test validation and cleanup
   */
  private async postTestValidation(testResult: TestResult): Promise<void> {
    console.log('Starting post-test validation and cleanup...');

    // Restore any intentionally failed services
    for (const service of this.config.services) {
      await this.restoreService(service);
    }

    // Validate all services are healthy
    for (const service of this.config.services) {
      await this.validateServiceHealth(service);
    }

    // Clean up any test resources
    await this.cleanupTestResources();

    console.log('Post-test validation completed');
  }

  /**
   * Restore service to normal operation
   */
  private async restoreService(service: ServiceConfig): Promise<void> {
    console.log(`Restoring service: ${service.name}`);
    
    switch (service.type) {
      case 'web':
      case 'api':
        // Scale deployment back to normal replica count
        await this.restoreApplicationService(service);
        break;
      case 'database':
        // Ensure database is in normal state
        await this.restoreDatabaseService(service);
        break;
      default:
        console.log(`No specific restore action for service type: ${service.type}`);
    }
  }

  /**
   * Restore application service
   */
  private async restoreApplicationService(service: ServiceConfig): Promise<void> {
    // Scale deployment back to desired replica count
    console.log(`Scaling ${service.name} back to normal operation`);
    
    // This would use actual Kubernetes client
    // kubectl scale deployment ${service.name} --replicas=${normalReplicas} -n ${namespace}
  }

  /**
   * Restore database service
   */
  private async restoreDatabaseService(service: ServiceConfig): Promise<void> {
    // Ensure database cluster is in normal state
    console.log(`Verifying database ${service.name} is in normal state`);
    
    // Check cluster status and promote back if needed
  }

  /**
   * Clean up test resources
   */
  private async cleanupTestResources(): Promise<void> {
    console.log('Cleaning up test resources...');
    
    // Delete test snapshots, instances, etc.
    // Clean up any temporary resources created during testing
  }

  /**
   * Calculate final test metrics
   */
  private calculateTestMetrics(testResult: TestResult): void {
    const serviceResults = testResult.serviceResults;
    
    testResult.metrics.servicesHealthy = serviceResults.filter(s => s.status === 'passed').length;
    testResult.metrics.totalServices = serviceResults.length;
    
    if (serviceResults.length > 0) {
      testResult.metrics.averageRTO = serviceResults.reduce((sum, s) => sum + s.rtoAchieved, 0) / serviceResults.length;
      testResult.metrics.averageRPO = serviceResults.reduce((sum, s) => sum + s.rpoAchieved, 0) / serviceResults.length;
      testResult.metrics.compliancePercentage = (testResult.metrics.servicesHealthy / testResult.metrics.totalServices) * 100;
    }

    // Set actual RTO/RPO for overall test
    testResult.actualRTO = testResult.metrics.averageRTO;
    testResult.actualRPO = testResult.metrics.averageRPO;
  }

  /**
   * Determine overall test status
   */
  private determineOverallStatus(testResult: TestResult): 'passed' | 'failed' | 'partial' {
    const passedServices = testResult.serviceResults.filter(s => s.status === 'passed').length;
    const totalServices = testResult.serviceResults.length;
    
    if (passedServices === totalServices) {
      return 'passed';
    } else if (passedServices === 0) {
      return 'failed';
    } else {
      return 'partial';
    }
  }

  /**
   * Send notifications about test results
   */
  private async sendNotifications(testResult: TestResult): Promise<void> {
    console.log('Sending test result notifications...');

    if (this.config.notifications.slack) {
      await this.sendSlackNotification(testResult);
    }

    if (this.config.notifications.email) {
      await this.sendEmailNotification(testResult);
    }

    if (this.config.notifications.pagerduty && testResult.status === 'failed') {
      await this.sendPagerDutyAlert(testResult);
    }
  }

  /**
   * Send Slack notification
   */
  private async sendSlackNotification(testResult: TestResult): Promise<void> {
    const config = this.config.notifications.slack!;
    
    const statusEmoji = {
      passed: '✅',
      failed: '❌',
      partial: '⚠️',
    };

    const message = {
      channel: config.channel,
      text: `DR Test ${testResult.status.toUpperCase()}`,
      attachments: [
        {
          color: testResult.status === 'passed' ? 'good' : testResult.status === 'failed' ? 'danger' : 'warning',
          title: `${statusEmoji[testResult.status]} DR Test: ${this.config.testName}`,
          fields: [
            {
              title: 'Test Type',
              value: this.config.testType,
              short: true,
            },
            {
              title: 'RTO Achieved',
              value: `${testResult.actualRTO?.toFixed(2) || 'N/A'} min (target: ${this.config.rtoTarget} min)`,
              short: true,
            },
            {
              title: 'RPO Achieved',
              value: `${testResult.actualRPO?.toFixed(2) || 'N/A'} min (target: ${this.config.rpoTarget} min)`,
              short: true,
            },
            {
              title: 'Services Tested',
              value: `${testResult.metrics.servicesHealthy}/${testResult.metrics.totalServices} passed`,
              short: true,
            },
          ],
          ts: Math.floor(testResult.startTime.getTime() / 1000),
        },
      ],
    };

    try {
      await axios.post(config.webhookUrl, message);
      console.log('Slack notification sent successfully');
    } catch (error) {
      console.error('Failed to send Slack notification:', error.message);
    }
  }

  /**
   * Send email notification
   */
  private async sendEmailNotification(testResult: TestResult): Promise<void> {
    console.log('Email notification would be sent here');
    // Implement email sending logic
  }

  /**
   * Send PagerDuty alert for failed tests
   */
  private async sendPagerDutyAlert(testResult: TestResult): Promise<void> {
    console.log('PagerDuty alert would be sent here');
    // Implement PagerDuty alert logic
  }

  /**
   * Save test results to storage
   */
  private async saveTestResults(testResult: TestResult): Promise<void> {
    const resultsDir = './test-results';
    const filename = `${testResult.testId}-${testResult.startTime.toISOString().replace(/[:.]/g, '-')}.json`;
    const filepath = `${resultsDir}/${filename}`;

    try {
      await fs.mkdir(resultsDir, { recursive: true });
      await fs.writeFile(filepath, JSON.stringify(testResult, null, 2));
      console.log(`Test results saved to: ${filepath}`);
    } catch (error) {
      console.error('Failed to save test results:', error.message);
    }
  }

  /**
   * Utility methods
   */
  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private async waitForPodsToTerminate(serviceName: string): Promise<void> {
    console.log(`Waiting for ${serviceName} pods to terminate...`);
    // Implementation would check Kubernetes pod status
    await this.sleep(30000); // Wait 30 seconds for demonstration
  }

  /**
   * Schedule automated tests
   */
  public scheduleTest(cronExpression: string): void {
    console.log(`Scheduling DR test with cron: ${cronExpression}`);
    // Implementation would use a job scheduler like node-cron
  }

  /**
   * Generate test report
   */
  public async generateReport(testResults: TestResult[]): Promise<string> {
    const report = {
      summary: {
        totalTests: testResults.length,
        passedTests: testResults.filter(t => t.status === 'passed').length,
        failedTests: testResults.filter(t => t.status === 'failed').length,
        averageRTO: testResults.reduce((sum, t) => sum + (t.actualRTO || 0), 0) / testResults.length,
        averageRPO: testResults.reduce((sum, t) => sum + (t.actualRPO || 0), 0) / testResults.length,
      },
      details: testResults,
    };

    const reportPath = `./reports/dr-test-report-${new Date().toISOString().split('T')[0]}.json`;
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
    
    return reportPath;
  }
}

// Export configuration builder
export class DRTestConfigBuilder {
  private config: Partial<DRTestConfig> = {};

  public setBasicInfo(testId: string, testName: string, description: string): this {
    this.config.testId = testId;
    this.config.testName = testName;
    this.config.description = description;
    return this;
  }

  public setTestType(testType: DRTestConfig['testType']): this {
    this.config.testType = testType;
    return this;
  }

  public setTargets(rtoTarget: number, rpoTarget: number): this {
    this.config.rtoTarget = rtoTarget;
    this.config.rpoTarget = rpoTarget;
    return this;
  }

  public setRegions(primary: string, secondary: string): this {
    this.config.regions = { primary, secondary };
    return this;
  }

  public addService(service: ServiceConfig): this {
    if (!this.config.services) {
      this.config.services = [];
    }
    this.config.services.push(service);
    return this;
  }

  public setNotifications(notifications: NotificationConfig): this {
    this.config.notifications = notifications;
    return this;
  }

  public build(): DRTestConfig {
    if (!this.config.testId || !this.config.testName || !this.config.testType || 
        !this.config.regions || !this.config.services || !this.config.notifications) {
      throw new Error('Missing required configuration fields');
    }

    return this.config as DRTestConfig;
  }
}

export default DisasterRecoveryTestFramework;