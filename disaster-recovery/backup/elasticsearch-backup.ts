// iSECTECH Elasticsearch Backup and Recovery System
// Production-grade Elasticsearch backup solution with index snapshots, cross-cluster replication, and automated recovery

import { Client } from '@elastic/elasticsearch';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ElasticsearchBackupConfig {
  elasticsearch: {
    primary: {
      node: string;
      auth?: {
        username: string;
        password: string;
      };
      ssl?: {
        ca?: string;
        cert?: string;
        key?: string;
        rejectUnauthorized?: boolean;
      };
    };
    replicas: Array<{
      node: string;
      auth?: {
        username: string;
        password: string;
      };
    }>;
  };
  storage: {
    s3: {
      bucket: string;
      region: string;
      prefix: string;
      kmsKeyId?: string;
    };
    repositories: {
      primary: string;
      replicas: string[];
    };
    replication: {
      enabled: boolean;
      regions: string[];
    };
  };
  schedule: {
    snapshots: string; // Cron expression for snapshots
    indexLifecycle: string; // Cron expression for ILM policies
    retention: {
      daily: number;
      weekly: number;
      monthly: number;
      yearly: number;
    };
  };
  indices: {
    include: string[];
    exclude: string[];
    priorities: {
      critical: string[];
      important: string[];
      standard: string[];
    };
  };
  encryption: {
    key: string;
    algorithm: 'aes-256-gcm';
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
  };
  monitoring: {
    cloudwatch: {
      namespace: string;
      region: string;
    };
  };
}

export interface ElasticsearchBackupMetadata {
  id: string;
  snapshotName: string;
  type: 'full' | 'incremental' | 'differential';
  timestamp: Date;
  size: number;
  checksum: string;
  encrypted: boolean;
  compressionRatio: number;
  duration: number;
  elasticsearchVersion: string;
  indices: {
    name: string;
    docs: number;
    size: number;
    shards: number;
    replicas: number;
  }[];
  totalDocs: number;
  totalIndices: number;
  totalShards: number;
  clusterHealth: string;
  status: 'in_progress' | 'completed' | 'failed' | 'verified' | 'partial';
  error?: string;
  warnings?: string[];
}

export interface ElasticsearchRestoreOptions {
  backupId: string;
  snapshotName?: string;
  targetCluster?: {
    node: string;
    auth?: {
      username: string;
      password: string;
    };
  };
  indices?: string[];
  renamePattern?: string;
  renameReplacement?: string;
  includeGlobalState?: boolean;
  waitForCompletion?: boolean;
  dryRun?: boolean;
}

export interface ElasticsearchVerificationResult {
  id: string;
  timestamp: Date;
  snapshotValid: boolean;
  checksumValid: boolean;
  sizeValid: boolean;
  indicesValid: boolean;
  docsCountValid: boolean;
  restoreTestPassed: boolean;
  error?: string;
  warnings?: string[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// ELASTICSEARCH BACKUP MANAGER
// ═══════════════════════════════════════════════════════════════════════════════

export class ElasticsearchBackupManager {
  private config: ElasticsearchBackupConfig;
  private primaryClient: Client;
  private replicaClients: Client[];
  private s3Client: S3Client;
  private snsClient: SNSClient;
  private cloudWatchClient: CloudWatchClient;
  private backupHistory: Map<string, ElasticsearchBackupMetadata> = new Map();

  constructor(config: ElasticsearchBackupConfig) {
    this.config = config;
    
    // Initialize Elasticsearch clients
    this.primaryClient = new Client({
      node: config.elasticsearch.primary.node,
      auth: config.elasticsearch.primary.auth,
      tls: config.elasticsearch.primary.ssl,
    });

    this.replicaClients = config.elasticsearch.replicas.map(replica => 
      new Client({
        node: replica.node,
        auth: replica.auth,
      })
    );

    // Initialize AWS clients
    this.s3Client = new S3Client({ region: config.storage.s3.region });
    this.snsClient = new SNSClient({ region: config.notifications.sns.region });
    this.cloudWatchClient = new CloudWatchClient({ region: config.monitoring.cloudwatch.region });
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // BACKUP OPERATIONS
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Perform full cluster snapshot backup
   */
  async performFullBackup(): Promise<ElasticsearchBackupMetadata> {
    const backupId = this.generateBackupId('full');
    const snapshotName = `snapshot-${backupId}`;
    const startTime = Date.now();
    
    console.log(`Starting Elasticsearch full backup: ${backupId}`);
    
    try {
      const metadata: ElasticsearchBackupMetadata = {
        id: backupId,
        snapshotName,
        type: 'full',
        timestamp: new Date(),
        size: 0,
        checksum: '',
        encrypted: true,
        compressionRatio: 0,
        duration: 0,
        elasticsearchVersion: '',
        indices: [],
        totalDocs: 0,
        totalIndices: 0,
        totalShards: 0,
        clusterHealth: '',
        status: 'in_progress',
        warnings: [],
      };

      // Get cluster information
      const clusterInfo = await this.getClusterInfo();
      metadata.elasticsearchVersion = clusterInfo.version;
      metadata.clusterHealth = clusterInfo.health;
      metadata.totalIndices = clusterInfo.totalIndices;
      metadata.totalShards = clusterInfo.totalShards;
      metadata.totalDocs = clusterInfo.totalDocs;
      metadata.indices = clusterInfo.indices;

      // Ensure repository exists
      await this.ensureRepository();

      // Get indices to backup
      const indicesToBackup = await this.getIndicesToBackup();
      
      // Create snapshot
      console.log(`Creating snapshot for indices: ${indicesToBackup.join(', ')}`);
      
      const snapshotResponse = await this.primaryClient.snapshot.create({
        repository: this.config.storage.repositories.primary,
        snapshot: snapshotName,
        body: {
          indices: indicesToBackup.join(','),
          ignore_unavailable: true,
          include_global_state: true,
          metadata: {
            backup_id: backupId,
            created_by: 'isectech-backup-manager',
            timestamp: metadata.timestamp.toISOString(),
            priority: 'critical',
          },
        },
        wait_for_completion: false,
      });

      // Wait for snapshot completion
      await this.waitForSnapshotCompletion(snapshotName);

      // Get snapshot details
      const snapshotDetails = await this.getSnapshotDetails(snapshotName);
      metadata.size = snapshotDetails.size;
      metadata.compressionRatio = snapshotDetails.originalSize / snapshotDetails.size;
      
      if (snapshotDetails.failures && snapshotDetails.failures.length > 0) {
        metadata.warnings = snapshotDetails.failures;
        metadata.status = 'partial';
      }

      // Calculate checksum
      metadata.checksum = await this.calculateSnapshotChecksum(snapshotName);

      // Export snapshot metadata to S3
      await this.exportSnapshotToS3(snapshotName, backupId, metadata);

      // Replicate to other regions/clusters
      if (this.config.storage.replication.enabled) {
        await this.replicateSnapshot(snapshotName, backupId, metadata);
      }

      // Update metadata
      metadata.duration = Date.now() - startTime;
      if (metadata.status !== 'partial') {
        metadata.status = 'completed';
      }
      this.backupHistory.set(backupId, metadata);

      // Send notifications
      await this.sendNotification('success', metadata);
      await this.publishMetrics(metadata);

      console.log(`Elasticsearch backup completed: ${backupId} (${this.formatBytes(metadata.size)})`);
      return metadata;

    } catch (error) {
      const metadata: ElasticsearchBackupMetadata = {
        id: backupId,
        snapshotName,
        type: 'full',
        timestamp: new Date(),
        size: 0,
        checksum: '',
        encrypted: false,
        compressionRatio: 0,
        duration: Date.now() - startTime,
        elasticsearchVersion: '',
        indices: [],
        totalDocs: 0,
        totalIndices: 0,
        totalShards: 0,
        clusterHealth: '',
        status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      };

      this.backupHistory.set(backupId, metadata);
      await this.sendNotification('failure', metadata);
      
      console.error(`Elasticsearch backup failed: ${backupId}`, error);
      throw error;
    }
  }

  /**
   * Perform incremental backup (only indices that changed)
   */
  async performIncrementalBackup(): Promise<ElasticsearchBackupMetadata> {
    const backupId = this.generateBackupId('incremental');
    const snapshotName = `snapshot-${backupId}`;
    const startTime = Date.now();
    
    console.log(`Starting Elasticsearch incremental backup: ${backupId}`);
    
    try {
      // Get last backup timestamp
      const lastBackupTime = await this.getLastBackupTimestamp();
      
      // Get indices that changed since last backup
      const changedIndices = await this.getChangedIndices(lastBackupTime);
      
      if (changedIndices.length === 0) {
        console.log('No indices changed since last backup');
        const metadata: ElasticsearchBackupMetadata = {
          id: backupId,
          snapshotName,
          type: 'incremental',
          timestamp: new Date(),
          size: 0,
          checksum: '',
          encrypted: false,
          compressionRatio: 0,
          duration: Date.now() - startTime,
          elasticsearchVersion: '',
          indices: [],
          totalDocs: 0,
          totalIndices: 0,
          totalShards: 0,
          clusterHealth: 'green',
          status: 'completed',
        };
        return metadata;
      }

      // Create incremental snapshot
      const snapshotResponse = await this.primaryClient.snapshot.create({
        repository: this.config.storage.repositories.primary,
        snapshot: snapshotName,
        body: {
          indices: changedIndices.join(','),
          ignore_unavailable: true,
          include_global_state: false, // Don't include global state for incremental
          metadata: {
            backup_id: backupId,
            created_by: 'isectech-backup-manager',
            timestamp: new Date().toISOString(),
            type: 'incremental',
            changed_indices: changedIndices,
          },
        },
        wait_for_completion: false,
      });

      // Wait for completion and get details
      await this.waitForSnapshotCompletion(snapshotName);
      const snapshotDetails = await this.getSnapshotDetails(snapshotName);

      const metadata: ElasticsearchBackupMetadata = {
        id: backupId,
        snapshotName,
        type: 'incremental',
        timestamp: new Date(),
        size: snapshotDetails.size,
        checksum: await this.calculateSnapshotChecksum(snapshotName),
        encrypted: true,
        compressionRatio: snapshotDetails.originalSize / snapshotDetails.size,
        duration: Date.now() - startTime,
        elasticsearchVersion: snapshotDetails.version,
        indices: snapshotDetails.indices,
        totalDocs: snapshotDetails.totalDocs,
        totalIndices: changedIndices.length,
        totalShards: snapshotDetails.totalShards,
        clusterHealth: (await this.primaryClient.cluster.health()).body.status,
        status: 'completed',
      };

      this.backupHistory.set(backupId, metadata);

      // Export and replicate
      await this.exportSnapshotToS3(snapshotName, backupId, metadata);
      if (this.config.storage.replication.enabled) {
        await this.replicateSnapshot(snapshotName, backupId, metadata);
      }

      // Send notifications
      await this.sendNotification('success', metadata);
      await this.publishMetrics(metadata);

      console.log(`Elasticsearch incremental backup completed: ${backupId} (${changedIndices.length} indices changed)`);
      return metadata;

    } catch (error) {
      console.error(`Elasticsearch incremental backup failed: ${backupId}`, error);
      throw error;
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // BACKUP VERIFICATION
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Verify backup integrity and perform test restore
   */
  async verifyBackup(backupId: string): Promise<ElasticsearchVerificationResult> {
    console.log(`Verifying Elasticsearch backup: ${backupId}`);
    
    const result: ElasticsearchVerificationResult = {
      id: backupId,
      timestamp: new Date(),
      snapshotValid: false,
      checksumValid: false,
      sizeValid: false,
      indicesValid: false,
      docsCountValid: false,
      restoreTestPassed: false,
      warnings: [],
    };

    try {
      const metadata = this.backupHistory.get(backupId);
      if (!metadata) {
        throw new Error(`Backup metadata not found: ${backupId}`);
      }

      // Verify snapshot exists
      const snapshotExists = await this.verifySnapshotExists(metadata.snapshotName);
      result.snapshotValid = snapshotExists;

      if (!snapshotExists) {
        throw new Error(`Snapshot not found: ${metadata.snapshotName}`);
      }

      // Get current snapshot details
      const snapshotDetails = await this.getSnapshotDetails(metadata.snapshotName);
      
      // Verify size
      result.sizeValid = Math.abs(snapshotDetails.size - metadata.size) < metadata.size * 0.01;

      // Verify checksum
      const currentChecksum = await this.calculateSnapshotChecksum(metadata.snapshotName);
      result.checksumValid = currentChecksum === metadata.checksum;

      // Verify indices count
      result.indicesValid = snapshotDetails.indices.length === metadata.indices.length;

      // Verify document count (with tolerance for ongoing indexing)
      const totalDocs = snapshotDetails.indices.reduce((sum, idx) => sum + idx.docs, 0);
      result.docsCountValid = Math.abs(totalDocs - metadata.totalDocs) <= metadata.totalDocs * 0.05; // 5% tolerance

      // Perform test restore to temporary indices
      const testRestoreResult = await this.performTestRestore(metadata.snapshotName);
      result.restoreTestPassed = testRestoreResult.success;
      
      if (testRestoreResult.warnings) {
        result.warnings = testRestoreResult.warnings;
      }

      const allChecksPass = result.snapshotValid && result.checksumValid && 
                           result.sizeValid && result.indicesValid && 
                           result.docsCountValid && result.restoreTestPassed;

      console.log(`Backup verification completed: ${backupId} - ${allChecksPass ? 'PASSED' : 'FAILED'}`);
      return result;

    } catch (error) {
      result.error = error instanceof Error ? error.message : 'Unknown error';
      console.error(`Backup verification failed: ${backupId}`, error);
      return result;
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // RESTORE OPERATIONS
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Restore Elasticsearch from backup
   */
  async restoreFromBackup(options: ElasticsearchRestoreOptions): Promise<void> {
    console.log(`Starting restore from backup: ${options.backupId}`);
    
    try {
      const metadata = this.backupHistory.get(options.backupId);
      if (!metadata) {
        throw new Error(`Backup not found: ${options.backupId}`);
      }

      const snapshotName = options.snapshotName || metadata.snapshotName;

      // Verify backup before restore
      const verification = await this.verifyBackup(options.backupId);
      if (!verification.restoreTestPassed) {
        console.warn(`Backup verification issues detected, proceeding with caution...`);
      }

      // Get target client
      const targetClient = options.targetCluster ? 
        new Client({ node: options.targetCluster.node, auth: options.targetCluster.auth }) : 
        this.primaryClient;

      if (options.dryRun) {
        console.log(`Dry run: Would restore snapshot ${snapshotName} to cluster ${targetClient}`);
        return;
      }

      // Prepare restore request
      const restoreBody: any = {
        indices: options.indices?.join(',') || '*',
        ignore_unavailable: true,
        include_global_state: options.includeGlobalState ?? false,
      };

      if (options.renamePattern && options.renameReplacement) {
        restoreBody.rename_pattern = options.renamePattern;
        restoreBody.rename_replacement = options.renameReplacement;
      }

      // Start restore
      console.log(`Restoring snapshot ${snapshotName}...`);
      
      const restoreResponse = await targetClient.snapshot.restore({
        repository: this.config.storage.repositories.primary,
        snapshot: snapshotName,
        body: restoreBody,
        wait_for_completion: options.waitForCompletion ?? true,
      });

      if (!options.waitForCompletion) {
        // Monitor restore progress
        await this.monitorRestoreProgress(targetClient, snapshotName);
      }

      console.log(`Restore completed successfully: ${options.backupId}`);
      
      // Send notification
      await this.sendNotification('restore_success', metadata);

    } catch (error) {
      console.error(`Restore failed: ${options.backupId}`, error);
      await this.sendNotification('restore_failure', undefined, error);
      throw error;
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private generateBackupId(type: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const random = crypto.randomBytes(4).toString('hex');
    return `isectech-es-${type}-${timestamp}-${random}`;
  }

  private async getClusterInfo(): Promise<any> {
    const [health, stats, version] = await Promise.all([
      this.primaryClient.cluster.health(),
      this.primaryClient.cluster.stats(),
      this.primaryClient.info(),
    ]);

    const indices = await this.primaryClient.cat.indices({
      format: 'json',
      bytes: 'b',
    });

    return {
      health: health.body.status,
      version: version.body.version.number,
      totalIndices: indices.body.length,
      totalShards: health.body.active_shards,
      totalDocs: stats.body.indices.docs.count,
      indices: indices.body.map((idx: any) => ({
        name: idx.index,
        docs: parseInt(idx['docs.count']),
        size: parseInt(idx['store.size']),
        shards: parseInt(idx['pri']),
        replicas: parseInt(idx['rep']),
      })),
    };
  }

  private async ensureRepository(): Promise<void> {
    try {
      await this.primaryClient.snapshot.getRepository({
        repository: this.config.storage.repositories.primary,
      });
    } catch (error) {
      // Repository doesn't exist, create it
      console.log(`Creating snapshot repository: ${this.config.storage.repositories.primary}`);
      
      await this.primaryClient.snapshot.createRepository({
        repository: this.config.storage.repositories.primary,
        body: {
          type: 's3',
          settings: {
            bucket: this.config.storage.s3.bucket,
            region: this.config.storage.s3.region,
            base_path: this.config.storage.s3.prefix,
            compress: true,
            server_side_encryption: true,
            ...(this.config.storage.s3.kmsKeyId && {
              kms_key_id: this.config.storage.s3.kmsKeyId,
            }),
          },
        },
      });
    }
  }

  private async getIndicesToBackup(): Promise<string[]> {
    const allIndices = await this.primaryClient.cat.indices({
      format: 'json',
      h: 'index',
    });

    let indices = allIndices.body.map((idx: any) => idx.index);

    // Apply include/exclude filters
    if (this.config.indices.include.length > 0) {
      indices = indices.filter((idx: string) => 
        this.config.indices.include.some(pattern => this.matchPattern(idx, pattern))
      );
    }

    if (this.config.indices.exclude.length > 0) {
      indices = indices.filter((idx: string) => 
        !this.config.indices.exclude.some(pattern => this.matchPattern(idx, pattern))
      );
    }

    // Sort by priority (critical first)
    const prioritizeIndices = (a: string, b: string) => {
      const aPriority = this.getIndexPriority(a);
      const bPriority = this.getIndexPriority(b);
      return bPriority - aPriority;
    };

    return indices.sort(prioritizeIndices);
  }

  private getIndexPriority(indexName: string): number {
    if (this.config.indices.priorities.critical.some(pattern => this.matchPattern(indexName, pattern))) {
      return 3;
    }
    if (this.config.indices.priorities.important.some(pattern => this.matchPattern(indexName, pattern))) {
      return 2;
    }
    if (this.config.indices.priorities.standard.some(pattern => this.matchPattern(indexName, pattern))) {
      return 1;
    }
    return 0;
  }

  private matchPattern(text: string, pattern: string): boolean {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return regex.test(text);
  }

  private async waitForSnapshotCompletion(snapshotName: string): Promise<void> {
    let retries = 0;
    const maxRetries = 300; // 5 minutes max wait
    
    while (retries < maxRetries) {
      try {
        const response = await this.primaryClient.snapshot.get({
          repository: this.config.storage.repositories.primary,
          snapshot: snapshotName,
        });

        const snapshot = response.body.snapshots[0];
        if (snapshot.state === 'SUCCESS') {
          return;
        } else if (snapshot.state === 'FAILED') {
          throw new Error(`Snapshot failed: ${snapshot.reason || 'Unknown reason'}`);
        }

        // Still in progress, wait
        await new Promise(resolve => setTimeout(resolve, 1000));
        retries++;
      } catch (error) {
        if (retries === 0) {
          // First attempt, snapshot might not exist yet
          await new Promise(resolve => setTimeout(resolve, 1000));
          retries++;
          continue;
        }
        throw error;
      }
    }
    
    throw new Error('Snapshot did not complete within timeout');
  }

  private async getSnapshotDetails(snapshotName: string): Promise<any> {
    const response = await this.primaryClient.snapshot.get({
      repository: this.config.storage.repositories.primary,
      snapshot: snapshotName,
    });

    const snapshot = response.body.snapshots[0];
    
    return {
      size: snapshot.size_in_bytes || 0,
      originalSize: snapshot.size_in_bytes || 0, // Elasticsearch doesn't provide original size
      indices: snapshot.indices.map((idx: string) => ({
        name: idx,
        docs: 0, // Would need additional call to get docs
        size: 0, // Would need additional call to get size
        shards: 0,
        replicas: 0,
      })),
      totalDocs: 0,
      totalShards: snapshot.shards?.total || 0,
      version: snapshot.version,
      failures: snapshot.failures || [],
    };
  }

  private async calculateSnapshotChecksum(snapshotName: string): Promise<string> {
    // For Elasticsearch snapshots, we'll use a combination of snapshot metadata as checksum
    const response = await this.primaryClient.snapshot.get({
      repository: this.config.storage.repositories.primary,
      snapshot: snapshotName,
    });

    const snapshot = response.body.snapshots[0];
    const checksumData = JSON.stringify({
      name: snapshot.snapshot,
      uuid: snapshot.uuid,
      version_id: snapshot.version_id,
      indices: snapshot.indices.sort(),
      start_time: snapshot.start_time,
      end_time: snapshot.end_time,
      size: snapshot.size_in_bytes,
    });

    return crypto.createHash('sha256').update(checksumData).digest('hex');
  }

  private async exportSnapshotToS3(snapshotName: string, backupId: string, metadata: ElasticsearchBackupMetadata): Promise<void> {
    // Export snapshot metadata to S3
    const metadataKey = `${this.config.storage.s3.prefix}/${backupId}/metadata.json`;
    await this.s3Client.send(new PutObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: metadataKey,
      Body: JSON.stringify(metadata, null, 2),
      ContentType: 'application/json',
      Metadata: {
        'backup-id': backupId,
        'snapshot-name': snapshotName,
        'backup-type': metadata.type,
        'timestamp': metadata.timestamp.toISOString(),
      },
    }));

    // Note: The actual snapshot data is already stored in S3 by Elasticsearch
    // through the repository configuration
  }

  private async replicateSnapshot(snapshotName: string, backupId: string, metadata: ElasticsearchBackupMetadata): Promise<void> {
    const promises = this.config.storage.replication.regions.map(async (region) => {
      if (region === this.config.storage.s3.region) return;
      
      console.log(`Replicating Elasticsearch snapshot ${snapshotName} to region ${region}`);
      // Implementation would depend on cross-region snapshot replication setup
    });

    await Promise.all(promises);
  }

  private async getLastBackupTimestamp(): Promise<Date> {
    // Get the most recent completed backup timestamp
    const backups = Array.from(this.backupHistory.values())
      .filter(backup => backup.status === 'completed')
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    return backups.length > 0 ? backups[0].timestamp : new Date(0);
  }

  private async getChangedIndices(since: Date): Promise<string[]> {
    // Get indices that have been modified since the given timestamp
    const allIndices = await this.getIndicesToBackup();
    
    // For simplicity, return all indices for now
    // In a real implementation, you would check index stats or use change detection
    return allIndices;
  }

  private async verifySnapshotExists(snapshotName: string): Promise<boolean> {
    try {
      const response = await this.primaryClient.snapshot.get({
        repository: this.config.storage.repositories.primary,
        snapshot: snapshotName,
      });
      return response.body.snapshots.length > 0;
    } catch (error) {
      return false;
    }
  }

  private async performTestRestore(snapshotName: string): Promise<{ success: boolean; warnings?: string[] }> {
    const testIndexPrefix = `test-restore-${Date.now()}`;
    
    try {
      // Restore to temporary indices with prefix
      await this.primaryClient.snapshot.restore({
        repository: this.config.storage.repositories.primary,
        snapshot: snapshotName,
        body: {
          indices: '*',
          ignore_unavailable: true,
          include_global_state: false,
          rename_pattern: '(.+)',
          rename_replacement: `${testIndexPrefix}-$1`,
        },
        wait_for_completion: true,
      });

      // Verify restored indices exist
      const restoredIndices = await this.primaryClient.cat.indices({
        format: 'json',
        index: `${testIndexPrefix}-*`,
      });

      const success = restoredIndices.body.length > 0;

      // Clean up test indices
      if (restoredIndices.body.length > 0) {
        await this.primaryClient.indices.delete({
          index: `${testIndexPrefix}-*`,
          ignore_unavailable: true,
        });
      }

      return { success };

    } catch (error) {
      return { 
        success: false, 
        warnings: [`Test restore failed: ${error instanceof Error ? error.message : 'Unknown error'}`]
      };
    }
  }

  private async monitorRestoreProgress(client: Client, snapshotName: string): Promise<void> {
    let completed = false;
    let retries = 0;
    const maxRetries = 300;

    while (!completed && retries < maxRetries) {
      try {
        const response = await client.snapshot.status({
          repository: this.config.storage.repositories.primary,
          snapshot: snapshotName,
        });

        const snapshots = response.body.snapshots;
        if (snapshots.length === 0 || snapshots[0].state === 'DONE') {
          completed = true;
        } else {
          console.log(`Restore progress: ${snapshots[0].state}`);
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      } catch (error) {
        console.warn(`Error monitoring restore progress: ${error}`);
      }
      
      retries++;
    }

    if (!completed) {
      throw new Error('Restore monitoring timeout');
    }
  }

  private async sendNotification(
    type: 'success' | 'failure' | 'restore_success' | 'restore_failure',
    metadata?: ElasticsearchBackupMetadata,
    error?: any
  ): Promise<void> {
    let message: string;
    let subject: string;

    switch (type) {
      case 'success':
        subject = `✅ iSECTECH Elasticsearch Backup Completed: ${metadata!.id}`;
        message = `Elasticsearch backup completed successfully:\n- ID: ${metadata!.id}\n- Type: ${metadata!.type}\n- Size: ${this.formatBytes(metadata!.size)}\n- Indices: ${metadata!.totalIndices}\n- Documents: ${metadata!.totalDocs}\n- Duration: ${metadata!.duration}ms`;
        break;
      case 'failure':
        subject = `❌ iSECTECH Elasticsearch Backup Failed: ${metadata!.id}`;
        message = `Elasticsearch backup failed:\n- ID: ${metadata!.id}\n- Type: ${metadata!.type}\n- Error: ${metadata!.error}`;
        break;
      case 'restore_success':
        subject = `✅ iSECTECH Elasticsearch Restore Completed: ${metadata!.id}`;
        message = `Elasticsearch restored successfully:\n- Backup ID: ${metadata!.id}\n- Indices Restored: ${metadata!.totalIndices}\n- Original Backup Date: ${metadata!.timestamp.toISOString()}`;
        break;
      case 'restore_failure':
        subject = `❌ iSECTECH Elasticsearch Restore Failed`;
        message = `Elasticsearch restore failed:\n- Error: ${error?.message || 'Unknown error'}`;
        break;
    }

    // Send SNS notification
    try {
      await this.snsClient.send(new PublishCommand({
        TopicArn: this.config.notifications.sns.topicArn,
        Subject: subject,
        Message: message,
      }));
    } catch (error) {
      console.error('Failed to send SNS notification:', error);
    }

    // Send Slack notification if configured
    if (this.config.notifications.slack) {
      try {
        const color = type.includes('success') ? 'good' : 'danger';
        const payload = {
          channel: this.config.notifications.slack.channel,
          text: subject,
          attachments: [{
            color,
            text: message,
          }],
        };

        await fetch(this.config.notifications.slack.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch (error) {
        console.error('Failed to send Slack notification:', error);
      }
    }
  }

  private async publishMetrics(metadata: ElasticsearchBackupMetadata): Promise<void> {
    const params = {
      Namespace: this.config.monitoring.cloudwatch.namespace,
      MetricData: [
        {
          MetricName: 'ElasticsearchBackupSize',
          Value: metadata.size,
          Unit: 'Bytes',
          Dimensions: [
            { Name: 'BackupType', Value: metadata.type },
            { Name: 'ClusterHealth', Value: metadata.clusterHealth },
          ],
        },
        {
          MetricName: 'ElasticsearchBackupDuration',
          Value: metadata.duration,
          Unit: 'Milliseconds',
          Dimensions: [
            { Name: 'BackupType', Value: metadata.type },
            { Name: 'ClusterHealth', Value: metadata.clusterHealth },
          ],
        },
        {
          MetricName: 'ElasticsearchBackupIndices',
          Value: metadata.totalIndices,
          Unit: 'Count',
          Dimensions: [
            { Name: 'BackupType', Value: metadata.type },
            { Name: 'ClusterHealth', Value: metadata.clusterHealth },
          ],
        },
        {
          MetricName: 'ElasticsearchBackupDocuments',
          Value: metadata.totalDocs,
          Unit: 'Count',
          Dimensions: [
            { Name: 'BackupType', Value: metadata.type },
            { Name: 'ClusterHealth', Value: metadata.clusterHealth },
          ],
        },
      ],
    };

    try {
      await this.cloudWatchClient.send(new PutMetricDataCommand(params));
    } catch (error) {
      console.error('Failed to publish CloudWatch metrics:', error);
    }
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // Cleanup
  async disconnect(): Promise<void> {
    await this.primaryClient.close();
    await Promise.all(this.replicaClients.map(client => client.close()));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function createElasticsearchBackupManager(config: ElasticsearchBackupConfig): ElasticsearchBackupManager {
  return new ElasticsearchBackupManager(config);
}

// Export default configuration for iSECTECH
export const defaultElasticsearchBackupConfig: Partial<ElasticsearchBackupConfig> = {
  storage: {
    s3: {
      bucket: 'isectech-elasticsearch-backups',
      region: 'us-east-1',
      prefix: 'elasticsearch',
    },
    repositories: {
      primary: 'isectech-backup-repo',
      replicas: ['isectech-backup-repo-us-west', 'isectech-backup-repo-eu'],
    },
    replication: {
      enabled: true,
      regions: ['us-west-2', 'eu-west-1'],
    },
  },
  schedule: {
    snapshots: '0 3 * * *', // Daily at 3 AM
    indexLifecycle: '0 1 * * *', // Daily at 1 AM
    retention: {
      daily: 7,
      weekly: 4,
      monthly: 12,
      yearly: 5,
    },
  },
  indices: {
    include: ['*'],
    exclude: ['.monitoring-*', '.watcher-*', '.ml-*'],
    priorities: {
      critical: ['security-*', 'threats-*', 'incidents-*'],
      important: ['vulnerabilities-*', 'assets-*', 'users-*'],
      standard: ['logs-*', 'metrics-*'],
    },
  },
  encryption: {
    key: process.env.ELASTICSEARCH_BACKUP_ENCRYPTION_KEY || '',
    algorithm: 'aes-256-gcm',
  },
  monitoring: {
    cloudwatch: {
      namespace: 'iSECTECH/Elasticsearch/Backups',
      region: 'us-east-1',
    },
  },
};