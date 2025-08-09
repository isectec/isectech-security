// iSECTECH Unified Backup Orchestrator
// Centralized coordination of all backup systems with dependency management, scheduling, and monitoring

import { PostgreSQLBackupManager, BackupConfig as PostgreSQLBackupConfig } from './postgres-backup';
import { RedisBackupManager, RedisBackupConfig } from './redis-backup';
import { ElasticsearchBackupManager, ElasticsearchBackupConfig } from './elasticsearch-backup';
import { exec } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import cron from 'node-cron';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface BackupOrchestratorConfig {
  backupSystems: {
    postgresql: {
      enabled: boolean;
      config: PostgreSQLBackupConfig;
      priority: number;
      dependencies: string[];
    };
    redis: {
      enabled: boolean;
      config: RedisBackupConfig;
      priority: number;
      dependencies: string[];
    };
    elasticsearch: {
      enabled: boolean;
      config: ElasticsearchBackupConfig;
      priority: number;
      dependencies: string[];
    };
    kubernetes: {
      enabled: boolean;
      priority: number;
      dependencies: string[];
      veleroNamespace: string;
    };
    applicationData: {
      enabled: boolean;
      priority: number;
      dependencies: string[];
      dataPaths: string[];
    };
  };
  schedule: {
    fullBackup: string; // Cron expression for full system backup
    incrementalBackup: string; // Cron expression for incremental backups
    verification: string; // Cron expression for backup verification
    cleanup: string; // Cron expression for cleanup
  };
  coordination: {
    maxConcurrentBackups: number;
    backupTimeout: number; // milliseconds
    retryAttempts: number;
    retryDelay: number; // milliseconds
  };
  storage: {
    s3: {
      bucket: string;
      region: string;
      prefix: string;
      kmsKeyId?: string;
    };
    retention: {
      fullBackups: number; // days
      incrementalBackups: number; // days
      verificationReports: number; // days
    };
  };
  notifications: {
    sns: {
      topicArn: string;
      region: string;
    };
    slack?: {
      webhookUrl: string;
      channel: string;
    };
    email?: {
      smtpConfig: any;
      recipients: string[];
    };
  };
  monitoring: {
    cloudwatch: {
      namespace: string;
      region: string;
    };
    healthCheck: {
      endpoint: string;
      interval: number; // seconds
    };
  };
}

export interface OrchestrationJob {
  id: string;
  type: 'full' | 'incremental' | 'verification' | 'cleanup';
  timestamp: Date;
  systems: string[];
  dependencies: Map<string, string[]>;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: {
    total: number;
    completed: number;
    failed: number;
    currentSystem?: string;
  };
  results: Map<string, any>;
  duration: number;
  error?: string;
  warnings: string[];
}

export interface BackupSystemMetrics {
  systemName: string;
  lastBackupTime: Date;
  lastBackupSuccess: boolean;
  lastBackupSize: number;
  lastBackupDuration: number;
  successRate: number; // percentage over last 30 days
  averageSize: number;
  averageDuration: number;
  rpo: number; // Recovery Point Objective in minutes
  rto: number; // Recovery Time Objective in minutes
}

export interface DisasterRecoveryMetrics {
  overallHealth: 'healthy' | 'warning' | 'critical';
  lastFullBackup: Date;
  totalBackupSize: number;
  systemMetrics: BackupSystemMetrics[];
  slaCompliance: {
    rpoCompliance: number; // percentage
    rtoCompliance: number; // percentage
    backupFrequencyCompliance: number; // percentage
  };
  alerts: {
    critical: number;
    warning: number;
    info: number;
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// BACKUP ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════════

export class BackupOrchestrator {
  private config: BackupOrchestratorConfig;
  private postgresqlManager?: PostgreSQLBackupManager;
  private redisManager?: RedisBackupManager;
  private elasticsearchManager?: ElasticsearchBackupManager;
  private s3Client: S3Client;
  private snsClient: SNSClient;
  private cloudWatchClient: CloudWatchClient;
  private activeJobs: Map<string, OrchestrationJob> = new Map();
  private scheduledTasks: Map<string, cron.ScheduledTask> = new Map();
  private systemMetrics: Map<string, BackupSystemMetrics> = new Map();

  constructor(config: BackupOrchestratorConfig) {
    this.config = config;

    // Initialize backup managers
    if (config.backupSystems.postgresql.enabled) {
      this.postgresqlManager = new PostgreSQLBackupManager(config.backupSystems.postgresql.config);
    }
    
    if (config.backupSystems.redis.enabled) {
      this.redisManager = new RedisBackupManager(config.backupSystems.redis.config);
    }
    
    if (config.backupSystems.elasticsearch.enabled) {
      this.elasticsearchManager = new ElasticsearchBackupManager(config.backupSystems.elasticsearch.config);
    }

    // Initialize AWS clients
    this.s3Client = new S3Client({ region: config.storage.s3.region });
    this.snsClient = new SNSClient({ region: config.notifications.sns.region });
    this.cloudWatchClient = new CloudWatchClient({ region: config.monitoring.cloudwatch.region });

    // Initialize system metrics
    this.initializeSystemMetrics();
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // ORCHESTRATION METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Start the backup orchestrator and schedule backup jobs
   */
  async start(): Promise<void> {
    console.log('Starting iSECTECH Backup Orchestrator...');

    // Schedule backup jobs
    this.scheduleBackupJobs();

    // Start health monitoring
    this.startHealthMonitoring();

    // Initialize metrics collection
    await this.collectInitialMetrics();

    console.log('Backup Orchestrator started successfully');
  }

  /**
   * Stop the orchestrator and cleanup
   */
  async stop(): Promise<void> {
    console.log('Stopping Backup Orchestrator...');

    // Cancel all scheduled tasks
    this.scheduledTasks.forEach(task => task.stop());
    this.scheduledTasks.clear();

    // Cancel active jobs
    for (const job of this.activeJobs.values()) {
      if (job.status === 'running') {
        job.status = 'cancelled';
      }
    }

    // Disconnect backup managers
    await this.postgresqlManager?.disconnect?.();
    await this.redisManager?.disconnect?.();
    await this.elasticsearchManager?.disconnect?.();

    console.log('Backup Orchestrator stopped');
  }

  /**
   * Perform a coordinated full backup of all systems
   */
  async performFullBackup(): Promise<OrchestrationJob> {
    const jobId = this.generateJobId('full');
    console.log(`Starting coordinated full backup: ${jobId}`);

    const job: OrchestrationJob = {
      id: jobId,
      type: 'full',
      timestamp: new Date(),
      systems: this.getEnabledSystems(),
      dependencies: this.buildDependencyMap(),
      status: 'pending',
      progress: {
        total: this.getEnabledSystems().length,
        completed: 0,
        failed: 0,
      },
      results: new Map(),
      duration: 0,
      warnings: [],
    };

    this.activeJobs.set(jobId, job);

    try {
      job.status = 'running';
      const startTime = Date.now();

      // Execute backups in dependency order
      const executionOrder = this.calculateExecutionOrder(job.systems, job.dependencies);
      
      for (const systemName of executionOrder) {
        job.progress.currentSystem = systemName;
        
        try {
          console.log(`Backing up system: ${systemName}`);
          const result = await this.backupSystem(systemName, 'full');
          job.results.set(systemName, result);
          job.progress.completed++;
          
          await this.updateSystemMetrics(systemName, result);
          
        } catch (error) {
          console.error(`Backup failed for system ${systemName}:`, error);
          job.progress.failed++;
          job.warnings.push(`System ${systemName} backup failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
          
          // Continue with other systems unless this is a critical dependency
          if (this.isCriticalSystem(systemName)) {
            throw new Error(`Critical system ${systemName} backup failed: ${error}`);
          }
        }
      }

      job.duration = Date.now() - startTime;
      job.status = job.progress.failed > 0 ? 'completed' : 'completed';
      
      // Generate consolidated backup report
      await this.generateBackupReport(job);
      
      // Send notifications
      await this.sendJobNotification(job);
      
      // Publish metrics
      await this.publishJobMetrics(job);

      console.log(`Full backup completed: ${jobId} (${job.progress.completed}/${job.progress.total} successful)`);
      return job;

    } catch (error) {
      job.status = 'failed';
      job.error = error instanceof Error ? error.message : 'Unknown error';
      job.duration = Date.now() - Date.parse(job.timestamp.toISOString());
      
      await this.sendJobNotification(job);
      console.error(`Full backup failed: ${jobId}`, error);
      throw error;
    }
  }

  /**
   * Perform incremental backups for systems that support it
   */
  async performIncrementalBackup(): Promise<OrchestrationJob> {
    const jobId = this.generateJobId('incremental');
    console.log(`Starting incremental backup: ${jobId}`);

    const incrementalSystems = this.getIncrementalCapableSystems();
    
    const job: OrchestrationJob = {
      id: jobId,
      type: 'incremental',
      timestamp: new Date(),
      systems: incrementalSystems,
      dependencies: new Map(),
      status: 'running',
      progress: {
        total: incrementalSystems.length,
        completed: 0,
        failed: 0,
      },
      results: new Map(),
      duration: 0,
      warnings: [],
    };

    this.activeJobs.set(jobId, job);

    try {
      const startTime = Date.now();

      // Incremental backups can run in parallel
      const backupPromises = incrementalSystems.map(async (systemName) => {
        try {
          const result = await this.backupSystem(systemName, 'incremental');
          job.results.set(systemName, result);
          job.progress.completed++;
          await this.updateSystemMetrics(systemName, result);
        } catch (error) {
          job.progress.failed++;
          job.warnings.push(`Incremental backup failed for ${systemName}: ${error}`);
        }
      });

      await Promise.all(backupPromises);

      job.duration = Date.now() - startTime;
      job.status = 'completed';
      
      await this.sendJobNotification(job);
      await this.publishJobMetrics(job);

      console.log(`Incremental backup completed: ${jobId}`);
      return job;

    } catch (error) {
      job.status = 'failed';
      job.error = error instanceof Error ? error.message : 'Unknown error';
      throw error;
    }
  }

  /**
   * Verify all recent backups
   */
  async performBackupVerification(): Promise<OrchestrationJob> {
    const jobId = this.generateJobId('verification');
    console.log(`Starting backup verification: ${jobId}`);

    const job: OrchestrationJob = {
      id: jobId,
      type: 'verification',
      timestamp: new Date(),
      systems: this.getEnabledSystems(),
      dependencies: new Map(),
      status: 'running',
      progress: {
        total: this.getEnabledSystems().length,
        completed: 0,
        failed: 0,
      },
      results: new Map(),
      duration: 0,
      warnings: [],
    };

    this.activeJobs.set(jobId, job);

    try {
      const startTime = Date.now();

      for (const systemName of job.systems) {
        try {
          const result = await this.verifySystemBackup(systemName);
          job.results.set(systemName, result);
          job.progress.completed++;
        } catch (error) {
          job.progress.failed++;
          job.warnings.push(`Verification failed for ${systemName}: ${error}`);
        }
      }

      job.duration = Date.now() - startTime;
      job.status = 'completed';
      
      await this.generateVerificationReport(job);
      await this.sendJobNotification(job);

      console.log(`Backup verification completed: ${jobId}`);
      return job;

    } catch (error) {
      job.status = 'failed';
      job.error = error instanceof Error ? error.message : 'Unknown error';
      throw error;
    }
  }

  /**
   * Get disaster recovery metrics and status
   */
  async getDisasterRecoveryMetrics(): Promise<DisasterRecoveryMetrics> {
    const systemMetrics = Array.from(this.systemMetrics.values());
    
    // Calculate overall health
    const criticalSystems = systemMetrics.filter(m => !m.lastBackupSuccess || 
      (Date.now() - m.lastBackupTime.getTime()) > (m.rpo * 60 * 1000));
    
    const warningSystems = systemMetrics.filter(m => m.successRate < 95 || 
      (Date.now() - m.lastBackupTime.getTime()) > (m.rpo * 0.8 * 60 * 1000));

    let overallHealth: 'healthy' | 'warning' | 'critical' = 'healthy';
    if (criticalSystems.length > 0) {
      overallHealth = 'critical';
    } else if (warningSystems.length > 0) {
      overallHealth = 'warning';
    }

    // Get last full backup time
    const lastFullBackup = this.getLastFullBackupTime();
    
    // Calculate total backup size
    const totalBackupSize = systemMetrics.reduce((sum, m) => sum + m.averageSize, 0);

    // Calculate SLA compliance
    const rpoCompliant = systemMetrics.filter(m => 
      (Date.now() - m.lastBackupTime.getTime()) <= (m.rpo * 60 * 1000)).length;
    const rtoCompliant = systemMetrics.filter(m => m.averageDuration <= (m.rto * 60 * 1000)).length;
    
    const slaCompliance = {
      rpoCompliance: (rpoCompliant / systemMetrics.length) * 100,
      rtoCompliance: (rtoCompliant / systemMetrics.length) * 100,
      backupFrequencyCompliance: systemMetrics.reduce((sum, m) => sum + m.successRate, 0) / systemMetrics.length,
    };

    return {
      overallHealth,
      lastFullBackup,
      totalBackupSize,
      systemMetrics,
      slaCompliance,
      alerts: {
        critical: criticalSystems.length,
        warning: warningSystems.length,
        info: 0,
      },
    };
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // SYSTEM-SPECIFIC BACKUP METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private async backupSystem(systemName: string, type: 'full' | 'incremental'): Promise<any> {
    switch (systemName) {
      case 'postgresql':
        if (!this.postgresqlManager) throw new Error('PostgreSQL manager not initialized');
        return type === 'full' ? 
          await this.postgresqlManager.performFullBackup() :
          await this.postgresqlManager.performIncrementalBackup();

      case 'redis':
        if (!this.redisManager) throw new Error('Redis manager not initialized');
        return type === 'full' ?
          await this.redisManager.performFullBackup() :
          await this.redisManager.performRDBBackup(); // Use RDB for incremental

      case 'elasticsearch':
        if (!this.elasticsearchManager) throw new Error('Elasticsearch manager not initialized');
        return type === 'full' ?
          await this.elasticsearchManager.performFullBackup() :
          await this.elasticsearchManager.performIncrementalBackup();

      case 'kubernetes':
        return await this.backupKubernetes(type);

      case 'applicationData':
        return await this.backupApplicationData(type);

      default:
        throw new Error(`Unknown system: ${systemName}`);
    }
  }

  private async verifySystemBackup(systemName: string): Promise<any> {
    // Get the most recent backup for the system
    const recentBackupId = await this.getRecentBackupId(systemName);
    
    switch (systemName) {
      case 'postgresql':
        if (!this.postgresqlManager) throw new Error('PostgreSQL manager not initialized');
        return await this.postgresqlManager.verifyBackup(recentBackupId);

      case 'redis':
        if (!this.redisManager) throw new Error('Redis manager not initialized');
        return await this.redisManager.verifyBackup(recentBackupId);

      case 'elasticsearch':
        if (!this.elasticsearchManager) throw new Error('Elasticsearch manager not initialized');
        return await this.elasticsearchManager.verifyBackup(recentBackupId);

      case 'kubernetes':
        return await this.verifyKubernetesBackup(recentBackupId);

      case 'applicationData':
        return await this.verifyApplicationDataBackup(recentBackupId);

      default:
        throw new Error(`Unknown system: ${systemName}`);
    }
  }

  private async backupKubernetes(type: 'full' | 'incremental'): Promise<any> {
    const backupName = `isectech-${type}-${Date.now()}`;
    
    // Use Velero CLI to create backup
    const command = `velero backup create ${backupName} --include-namespaces isectech-production,isectech-security,monitoring --wait`;
    
    return new Promise((resolve, reject) => {
      exec(command, { timeout: 30 * 60 * 1000 }, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`Kubernetes backup failed: ${error.message}\n${stderr}`));
        } else {
          resolve({
            id: backupName,
            type: 'kubernetes',
            timestamp: new Date(),
            size: 0, // Would need to query Velero for actual size
            status: 'completed',
          });
        }
      });
    });
  }

  private async backupApplicationData(type: 'full' | 'incremental'): Promise<any> {
    const backupId = this.generateJobId(`app-data-${type}`);
    const backupDir = `/tmp/isectech-app-backup-${backupId}`;
    
    try {
      await fs.mkdir(backupDir, { recursive: true });
      
      // Backup application data directories
      for (const dataPath of this.config.backupSystems.applicationData.dataPaths) {
        const command = `tar -czf "${backupDir}/$(basename ${dataPath}).tar.gz" -C "$(dirname ${dataPath})" "$(basename ${dataPath})"`;
        
        await new Promise<void>((resolve, reject) => {
          exec(command, (error, stdout, stderr) => {
            if (error) reject(error);
            else resolve();
          });
        });
      }

      // Upload to S3
      const files = await fs.readdir(backupDir);
      let totalSize = 0;
      
      for (const file of files) {
        const filePath = path.join(backupDir, file);
        const stats = await fs.stat(filePath);
        totalSize += stats.size;
        
        const fileData = await fs.readFile(filePath);
        await this.s3Client.send(new PutObjectCommand({
          Bucket: this.config.storage.s3.bucket,
          Key: `${this.config.storage.s3.prefix}/application-data/${backupId}/${file}`,
          Body: fileData,
        }));
      }

      // Cleanup
      await fs.rm(backupDir, { recursive: true });

      return {
        id: backupId,
        type: 'application-data',
        timestamp: new Date(),
        size: totalSize,
        status: 'completed',
      };

    } catch (error) {
      await fs.rm(backupDir, { recursive: true }).catch(() => {});
      throw error;
    }
  }

  private async verifyKubernetesBackup(backupId: string): Promise<any> {
    // Use Velero CLI to describe backup
    const command = `velero backup describe ${backupId} --details`;
    
    return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`Kubernetes backup verification failed: ${error.message}`));
        } else {
          const success = stdout.includes('Phase:  Completed') && !stdout.includes('Errors:');
          resolve({
            id: backupId,
            timestamp: new Date(),
            success,
            details: stdout,
          });
        }
      });
    });
  }

  private async verifyApplicationDataBackup(backupId: string): Promise<any> {
    // Verify files exist in S3
    try {
      const response = await this.s3Client.send(new GetObjectCommand({
        Bucket: this.config.storage.s3.bucket,
        Key: `${this.config.storage.s3.prefix}/application-data/${backupId}/metadata.json`,
      }));

      return {
        id: backupId,
        timestamp: new Date(),
        success: true,
        size: response.ContentLength || 0,
      };
    } catch (error) {
      return {
        id: backupId,
        timestamp: new Date(),
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private generateJobId(type: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const random = crypto.randomBytes(4).toString('hex');
    return `isectech-${type}-${timestamp}-${random}`;
  }

  private getEnabledSystems(): string[] {
    return Object.entries(this.config.backupSystems)
      .filter(([_, config]) => config.enabled)
      .map(([name, _]) => name);
  }

  private getIncrementalCapableSystems(): string[] {
    return this.getEnabledSystems().filter(system => 
      ['postgresql', 'redis', 'elasticsearch'].includes(system)
    );
  }

  private buildDependencyMap(): Map<string, string[]> {
    const dependencies = new Map<string, string[]>();
    
    Object.entries(this.config.backupSystems).forEach(([name, config]) => {
      if (config.enabled) {
        dependencies.set(name, config.dependencies || []);
      }
    });

    return dependencies;
  }

  private calculateExecutionOrder(systems: string[], dependencies: Map<string, string[]>): string[] {
    const result: string[] = [];
    const visited = new Set<string>();
    const visiting = new Set<string>();

    const visit = (system: string) => {
      if (visiting.has(system)) {
        throw new Error(`Circular dependency detected involving ${system}`);
      }
      if (visited.has(system)) {
        return;
      }

      visiting.add(system);
      
      const deps = dependencies.get(system) || [];
      for (const dep of deps) {
        if (systems.includes(dep)) {
          visit(dep);
        }
      }

      visiting.delete(system);
      visited.add(system);
      result.push(system);
    };

    for (const system of systems) {
      if (!visited.has(system)) {
        visit(system);
      }
    }

    return result;
  }

  private isCriticalSystem(systemName: string): boolean {
    const criticalSystems = ['postgresql', 'elasticsearch'];
    return criticalSystems.includes(systemName);
  }

  private scheduleBackupJobs(): void {
    // Schedule full backup
    const fullBackupTask = cron.schedule(this.config.schedule.fullBackup, async () => {
      try {
        await this.performFullBackup();
      } catch (error) {
        console.error('Scheduled full backup failed:', error);
      }
    }, { scheduled: false });

    // Schedule incremental backup
    const incrementalBackupTask = cron.schedule(this.config.schedule.incrementalBackup, async () => {
      try {
        await this.performIncrementalBackup();
      } catch (error) {
        console.error('Scheduled incremental backup failed:', error);
      }
    }, { scheduled: false });

    // Schedule verification
    const verificationTask = cron.schedule(this.config.schedule.verification, async () => {
      try {
        await this.performBackupVerification();
      } catch (error) {
        console.error('Scheduled verification failed:', error);
      }
    }, { scheduled: false });

    // Schedule cleanup
    const cleanupTask = cron.schedule(this.config.schedule.cleanup, async () => {
      try {
        await this.performCleanup();
      } catch (error) {
        console.error('Scheduled cleanup failed:', error);
      }
    }, { scheduled: false });

    this.scheduledTasks.set('fullBackup', fullBackupTask);
    this.scheduledTasks.set('incrementalBackup', incrementalBackupTask);
    this.scheduledTasks.set('verification', verificationTask);
    this.scheduledTasks.set('cleanup', cleanupTask);

    // Start all scheduled tasks
    this.scheduledTasks.forEach(task => task.start());
  }

  private startHealthMonitoring(): void {
    setInterval(async () => {
      try {
        const metrics = await this.getDisasterRecoveryMetrics();
        await this.publishDisasterRecoveryMetrics(metrics);
        
        if (metrics.overallHealth === 'critical') {
          await this.sendCriticalAlert(metrics);
        }
      } catch (error) {
        console.error('Health monitoring failed:', error);
      }
    }, this.config.monitoring.healthCheck.interval * 1000);
  }

  private async collectInitialMetrics(): Promise<void> {
    for (const systemName of this.getEnabledSystems()) {
      this.systemMetrics.set(systemName, {
        systemName,
        lastBackupTime: new Date(0),
        lastBackupSuccess: false,
        lastBackupSize: 0,
        lastBackupDuration: 0,
        successRate: 100,
        averageSize: 0,
        averageDuration: 0,
        rpo: 240, // 4 hours default
        rto: 60,  // 1 hour default
      });
    }
  }

  private async updateSystemMetrics(systemName: string, result: any): Promise<void> {
    const metrics = this.systemMetrics.get(systemName);
    if (!metrics) return;

    metrics.lastBackupTime = result.timestamp || new Date();
    metrics.lastBackupSuccess = result.status === 'completed';
    metrics.lastBackupSize = result.size || 0;
    metrics.lastBackupDuration = result.duration || 0;

    // Update averages (simple moving average for demo)
    metrics.averageSize = (metrics.averageSize + metrics.lastBackupSize) / 2;
    metrics.averageDuration = (metrics.averageDuration + metrics.lastBackupDuration) / 2;

    this.systemMetrics.set(systemName, metrics);
  }

  private initializeSystemMetrics(): void {
    // Initialize with default metrics for all systems
  }

  private getLastFullBackupTime(): Date {
    // Implementation would query backup history for last full backup
    return new Date();
  }

  private async getRecentBackupId(systemName: string): Promise<string> {
    // Implementation would query backup history for most recent backup
    return `recent-backup-${systemName}`;
  }

  private async generateBackupReport(job: OrchestrationJob): Promise<void> {
    const report = {
      jobId: job.id,
      timestamp: job.timestamp,
      type: job.type,
      duration: job.duration,
      status: job.status,
      systems: job.systems,
      results: Object.fromEntries(job.results),
      warnings: job.warnings,
      metrics: {
        totalSystems: job.progress.total,
        successfulSystems: job.progress.completed,
        failedSystems: job.progress.failed,
        successRate: (job.progress.completed / job.progress.total) * 100,
      },
    };

    // Save report to S3
    await this.s3Client.send(new PutObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: `${this.config.storage.s3.prefix}/reports/backup-${job.id}.json`,
      Body: JSON.stringify(report, null, 2),
      ContentType: 'application/json',
    }));
  }

  private async generateVerificationReport(job: OrchestrationJob): Promise<void> {
    const report = {
      jobId: job.id,
      timestamp: job.timestamp,
      results: Object.fromEntries(job.results),
      warnings: job.warnings,
      summary: {
        totalChecks: job.progress.total,
        passedChecks: job.progress.completed,
        failedChecks: job.progress.failed,
      },
    };

    await this.s3Client.send(new PutObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: `${this.config.storage.s3.prefix}/reports/verification-${job.id}.json`,
      Body: JSON.stringify(report, null, 2),
      ContentType: 'application/json',
    }));
  }

  private async performCleanup(): Promise<void> {
    console.log('Performing backup cleanup...');
    // Implementation would remove old backups based on retention policies
  }

  private async sendJobNotification(job: OrchestrationJob): Promise<void> {
    const isSuccess = job.status === 'completed' && job.progress.failed === 0;
    const subject = `${isSuccess ? '✅' : '❌'} iSECTECH Backup ${job.type}: ${job.id}`;
    const message = `Backup job ${job.type} (${job.id}):\n- Status: ${job.status}\n- Systems: ${job.progress.completed}/${job.progress.total} successful\n- Duration: ${Math.round(job.duration / 1000)}s\n- Warnings: ${job.warnings.length}`;

    try {
      await this.snsClient.send(new PublishCommand({
        TopicArn: this.config.notifications.sns.topicArn,
        Subject: subject,
        Message: message,
      }));
    } catch (error) {
      console.error('Failed to send job notification:', error);
    }
  }

  private async sendCriticalAlert(metrics: DisasterRecoveryMetrics): Promise<void> {
    const subject = '🚨 iSECTECH Critical Backup Alert';
    const message = `Critical backup issues detected:\n- Overall Health: ${metrics.overallHealth}\n- Critical Alerts: ${metrics.alerts.critical}\n- Warning Alerts: ${metrics.alerts.warning}\n- Last Full Backup: ${metrics.lastFullBackup.toISOString()}`;

    try {
      await this.snsClient.send(new PublishCommand({
        TopicArn: this.config.notifications.sns.topicArn,
        Subject: subject,
        Message: message,
      }));
    } catch (error) {
      console.error('Failed to send critical alert:', error);
    }
  }

  private async publishJobMetrics(job: OrchestrationJob): Promise<void> {
    const params = {
      Namespace: this.config.monitoring.cloudwatch.namespace,
      MetricData: [
        {
          MetricName: 'BackupJobDuration',
          Value: job.duration,
          Unit: 'Milliseconds',
          Dimensions: [
            { Name: 'JobType', Value: job.type },
            { Name: 'JobStatus', Value: job.status },
          ],
        },
        {
          MetricName: 'BackupJobSuccessRate',
          Value: (job.progress.completed / job.progress.total) * 100,
          Unit: 'Percent',
          Dimensions: [
            { Name: 'JobType', Value: job.type },
          ],
        },
      ],
    };

    try {
      await this.cloudWatchClient.send(new PutMetricDataCommand(params));
    } catch (error) {
      console.error('Failed to publish job metrics:', error);
    }
  }

  private async publishDisasterRecoveryMetrics(metrics: DisasterRecoveryMetrics): Promise<void> {
    const params = {
      Namespace: this.config.monitoring.cloudwatch.namespace,
      MetricData: [
        {
          MetricName: 'OverallBackupHealth',
          Value: metrics.overallHealth === 'healthy' ? 1 : metrics.overallHealth === 'warning' ? 0.5 : 0,
          Unit: 'None',
        },
        {
          MetricName: 'RPOCompliance',
          Value: metrics.slaCompliance.rpoCompliance,
          Unit: 'Percent',
        },
        {
          MetricName: 'RTOCompliance',
          Value: metrics.slaCompliance.rtoCompliance,
          Unit: 'Percent',
        },
        {
          MetricName: 'TotalBackupSize',
          Value: metrics.totalBackupSize,
          Unit: 'Bytes',
        },
      ],
    };

    try {
      await this.cloudWatchClient.send(new PutMetricDataCommand(params));
    } catch (error) {
      console.error('Failed to publish DR metrics:', error);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function createBackupOrchestrator(config: BackupOrchestratorConfig): BackupOrchestrator {
  return new BackupOrchestrator(config);
}

// Export default configuration for iSECTECH
export const defaultOrchestratorConfig: Partial<BackupOrchestratorConfig> = {
  schedule: {
    fullBackup: '0 2 * * *',        // Daily at 2 AM
    incrementalBackup: '0 */6 * * *', // Every 6 hours
    verification: '0 10 * * *',      // Daily at 10 AM
    cleanup: '0 4 * * 0',           // Weekly on Sunday at 4 AM
  },
  coordination: {
    maxConcurrentBackups: 3,
    backupTimeout: 7200000, // 2 hours
    retryAttempts: 3,
    retryDelay: 60000, // 1 minute
  },
  storage: {
    s3: {
      bucket: 'isectech-disaster-recovery',
      region: 'us-east-1',
      prefix: 'orchestrated-backups',
    },
    retention: {
      fullBackups: 90,        // 90 days
      incrementalBackups: 30, // 30 days
      verificationReports: 365, // 1 year
    },
  },
  monitoring: {
    cloudwatch: {
      namespace: 'iSECTECH/DisasterRecovery',
      region: 'us-east-1',
    },
    healthCheck: {
      endpoint: '/health/disaster-recovery',
      interval: 300, // 5 minutes
    },
  },
};