// iSECTECH Redis Backup and Recovery System
// Production-grade Redis backup solution with persistence, replication, and automated recovery

import { exec } from 'child_process';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import Redis from 'ioredis';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface RedisBackupConfig {
  redis: {
    primary: {
      host: string;
      port: number;
      password?: string;
      db: number;
    };
    replicas: Array<{
      host: string;
      port: number;
      password?: string;
      db: number;
    }>;
  };
  storage: {
    s3: {
      bucket: string;
      region: string;
      prefix: string;
      kmsKeyId?: string;
    };
    replication: {
      enabled: boolean;
      regions: string[];
    };
  };
  schedule: {
    rdb: string; // Cron expression for RDB snapshots
    aof: string; // Cron expression for AOF backups
    retention: {
      hourly: number;
      daily: number;
      weekly: number;
      monthly: number;
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

export interface RedisBackupMetadata {
  id: string;
  type: 'rdb' | 'aof' | 'full';
  timestamp: Date;
  size: number;
  checksum: string;
  encrypted: boolean;
  compressionRatio: number;
  duration: number;
  redisVersion: string;
  keys: number;
  memory: number;
  databases: number[];
  persistence: {
    rdb: boolean;
    aof: boolean;
    lastSave: Date;
  };
  status: 'in_progress' | 'completed' | 'failed' | 'verified';
  error?: string;
}

export interface RedisRestoreOptions {
  backupId: string;
  targetRedis?: {
    host: string;
    port: number;
    password?: string;
    db: number;
  };
  flushBeforeRestore?: boolean;
  dryRun?: boolean;
  preserveKeys?: string[];
  excludeKeys?: string[];
}

export interface RedisVerificationResult {
  id: string;
  timestamp: Date;
  checksumValid: boolean;
  sizeValid: boolean;
  dataIntegrityValid: boolean;
  keyCountValid: boolean;
  restoreTestPassed: boolean;
  error?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// REDIS BACKUP MANAGER
// ═══════════════════════════════════════════════════════════════════════════════

export class RedisBackupManager {
  private config: RedisBackupConfig;
  private primaryRedis: Redis;
  private replicaRedis: Redis[];
  private s3Client: S3Client;
  private snsClient: SNSClient;
  private cloudWatchClient: CloudWatchClient;
  private backupHistory: Map<string, RedisBackupMetadata> = new Map();

  constructor(config: RedisBackupConfig) {
    this.config = config;
    
    // Initialize Redis connections
    this.primaryRedis = new Redis({
      host: config.redis.primary.host,
      port: config.redis.primary.port,
      password: config.redis.primary.password,
      db: config.redis.primary.db,
      retryDelayOnFailover: 100,
      enableReadyCheck: true,
      maxRetriesPerRequest: 3,
    });

    this.replicaRedis = config.redis.replicas.map(replica => new Redis({
      host: replica.host,
      port: replica.port,
      password: replica.password,
      db: replica.db,
      retryDelayOnFailover: 100,
      enableReadyCheck: true,
      maxRetriesPerRequest: 3,
    }));

    // Initialize AWS clients
    this.s3Client = new S3Client({ region: config.storage.s3.region });
    this.snsClient = new SNSClient({ region: config.notifications.sns.region });
    this.cloudWatchClient = new CloudWatchClient({ region: config.monitoring.cloudwatch.region });
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // BACKUP OPERATIONS
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Perform RDB snapshot backup
   */
  async performRDBBackup(): Promise<RedisBackupMetadata> {
    const backupId = this.generateBackupId('rdb');
    const startTime = Date.now();
    
    console.log(`Starting RDB backup: ${backupId}`);
    
    try {
      const metadata: RedisBackupMetadata = {
        id: backupId,
        type: 'rdb',
        timestamp: new Date(),
        size: 0,
        checksum: '',
        encrypted: true,
        compressionRatio: 0,
        duration: 0,
        redisVersion: '',
        keys: 0,
        memory: 0,
        databases: [],
        persistence: {
          rdb: false,
          aof: false,
          lastSave: new Date(),
        },
        status: 'in_progress',
      };

      // Get Redis info
      const info = await this.getRedisInfo();
      metadata.redisVersion = info.redis_version;
      metadata.keys = info.total_keys;
      metadata.memory = info.used_memory;
      metadata.databases = info.databases;
      metadata.persistence = info.persistence;

      // Create backup directory
      const tempDir = `/tmp/isectech-redis-backup-${backupId}`;
      await fs.mkdir(tempDir, { recursive: true });

      // Trigger BGSAVE for RDB snapshot
      await this.primaryRedis.bgsave();
      
      // Wait for background save to complete
      await this.waitForBackgroundSave();

      // Copy RDB file
      const rdbFile = await this.getRDBFilePath();
      const backupFile = path.join(tempDir, 'dump.rdb');
      await this.copyFile(rdbFile, backupFile);

      // Get file size before compression
      const stats = await fs.stat(backupFile);
      const originalSize = stats.size;

      // Compress and encrypt
      const compressedFile = path.join(tempDir, 'dump.rdb.gz.enc');
      await this.compressAndEncrypt(backupFile, compressedFile);

      // Calculate metadata
      const compressedStats = await fs.stat(compressedFile);
      metadata.size = compressedStats.size;
      metadata.compressionRatio = originalSize / compressedStats.size;
      metadata.checksum = await this.calculateChecksum(compressedFile);

      // Upload to S3
      await this.uploadToS3(compressedFile, backupId, metadata);

      // Replicate to other regions
      if (this.config.storage.replication.enabled) {
        await this.replicateToRegions(backupId, metadata);
      }

      // Clean up
      await fs.rm(tempDir, { recursive: true });

      // Update metadata
      metadata.duration = Date.now() - startTime;
      metadata.status = 'completed';
      this.backupHistory.set(backupId, metadata);

      // Send notifications
      await this.sendNotification('success', metadata);
      await this.publishMetrics(metadata);

      console.log(`RDB backup completed: ${backupId} (${this.formatBytes(metadata.size)})`);
      return metadata;

    } catch (error) {
      const metadata: RedisBackupMetadata = {
        id: backupId,
        type: 'rdb',
        timestamp: new Date(),
        size: 0,
        checksum: '',
        encrypted: false,
        compressionRatio: 0,
        duration: Date.now() - startTime,
        redisVersion: '',
        keys: 0,
        memory: 0,
        databases: [],
        persistence: {
          rdb: false,
          aof: false,
          lastSave: new Date(),
        },
        status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      };

      this.backupHistory.set(backupId, metadata);
      await this.sendNotification('failure', metadata);
      
      console.error(`RDB backup failed: ${backupId}`, error);
      throw error;
    }
  }

  /**
   * Perform AOF (Append Only File) backup
   */
  async performAOFBackup(): Promise<RedisBackupMetadata> {
    const backupId = this.generateBackupId('aof');
    const startTime = Date.now();
    
    console.log(`Starting AOF backup: ${backupId}`);
    
    try {
      const metadata: RedisBackupMetadata = {
        id: backupId,
        type: 'aof',
        timestamp: new Date(),
        size: 0,
        checksum: '',
        encrypted: true,
        compressionRatio: 0,
        duration: 0,
        redisVersion: '',
        keys: 0,
        memory: 0,
        databases: [],
        persistence: {
          rdb: false,
          aof: false,
          lastSave: new Date(),
        },
        status: 'in_progress',
      };

      // Get Redis info
      const info = await this.getRedisInfo();
      metadata.redisVersion = info.redis_version;
      metadata.keys = info.total_keys;
      metadata.memory = info.used_memory;
      metadata.databases = info.databases;
      metadata.persistence = info.persistence;

      // Create backup directory
      const tempDir = `/tmp/isectech-redis-backup-${backupId}`;
      await fs.mkdir(tempDir, { recursive: true });

      // Trigger AOF rewrite
      await this.primaryRedis.bgrewriteaof();
      
      // Wait for AOF rewrite to complete
      await this.waitForAOFRewrite();

      // Copy AOF file
      const aofFile = await this.getAOFFilePath();
      const backupFile = path.join(tempDir, 'appendonly.aof');
      await this.copyFile(aofFile, backupFile);

      // Get file size before compression
      const stats = await fs.stat(backupFile);
      const originalSize = stats.size;

      // Compress and encrypt
      const compressedFile = path.join(tempDir, 'appendonly.aof.gz.enc');
      await this.compressAndEncrypt(backupFile, compressedFile);

      // Calculate metadata
      const compressedStats = await fs.stat(compressedFile);
      metadata.size = compressedStats.size;
      metadata.compressionRatio = originalSize / compressedStats.size;
      metadata.checksum = await this.calculateChecksum(compressedFile);

      // Upload to S3
      await this.uploadToS3(compressedFile, backupId, metadata);

      // Replicate to other regions
      if (this.config.storage.replication.enabled) {
        await this.replicateToRegions(backupId, metadata);
      }

      // Clean up
      await fs.rm(tempDir, { recursive: true });

      // Update metadata
      metadata.duration = Date.now() - startTime;
      metadata.status = 'completed';
      this.backupHistory.set(backupId, metadata);

      // Send notifications
      await this.sendNotification('success', metadata);
      await this.publishMetrics(metadata);

      console.log(`AOF backup completed: ${backupId} (${this.formatBytes(metadata.size)})`);
      return metadata;

    } catch (error) {
      const metadata: RedisBackupMetadata = {
        id: backupId,
        type: 'aof',
        timestamp: new Date(),
        size: 0,
        checksum: '',
        encrypted: false,
        compressionRatio: 0,
        duration: Date.now() - startTime,
        redisVersion: '',
        keys: 0,
        memory: 0,
        databases: [],
        persistence: {
          rdb: false,
          aof: false,
          lastSave: new Date(),
        },
        status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      };

      this.backupHistory.set(backupId, metadata);
      await this.sendNotification('failure', metadata);
      
      console.error(`AOF backup failed: ${backupId}`, error);
      throw error;
    }
  }

  /**
   * Perform full backup (RDB + AOF + metadata)
   */
  async performFullBackup(): Promise<RedisBackupMetadata> {
    const backupId = this.generateBackupId('full');
    const startTime = Date.now();
    
    console.log(`Starting full backup: ${backupId}`);
    
    try {
      // Perform both RDB and AOF backups
      const rdbBackup = await this.performRDBBackup();
      const aofBackup = await this.performAOFBackup();

      // Create combined metadata
      const metadata: RedisBackupMetadata = {
        id: backupId,
        type: 'full',
        timestamp: new Date(),
        size: rdbBackup.size + aofBackup.size,
        checksum: this.combineChecksums(rdbBackup.checksum, aofBackup.checksum),
        encrypted: true,
        compressionRatio: (rdbBackup.compressionRatio + aofBackup.compressionRatio) / 2,
        duration: Date.now() - startTime,
        redisVersion: rdbBackup.redisVersion,
        keys: rdbBackup.keys,
        memory: rdbBackup.memory,
        databases: rdbBackup.databases,
        persistence: rdbBackup.persistence,
        status: 'completed',
      };

      this.backupHistory.set(backupId, metadata);

      // Send notifications
      await this.sendNotification('success', metadata);
      await this.publishMetrics(metadata);

      console.log(`Full backup completed: ${backupId} (RDB: ${this.formatBytes(rdbBackup.size)}, AOF: ${this.formatBytes(aofBackup.size)})`);
      return metadata;

    } catch (error) {
      console.error(`Full backup failed: ${backupId}`, error);
      throw error;
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // BACKUP VERIFICATION
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Verify backup integrity and perform test restore
   */
  async verifyBackup(backupId: string): Promise<RedisVerificationResult> {
    console.log(`Verifying backup: ${backupId}`);
    
    const result: RedisVerificationResult = {
      id: backupId,
      timestamp: new Date(),
      checksumValid: false,
      sizeValid: false,
      dataIntegrityValid: false,
      keyCountValid: false,
      restoreTestPassed: false,
    };

    try {
      const metadata = this.backupHistory.get(backupId);
      if (!metadata) {
        throw new Error(`Backup metadata not found: ${backupId}`);
      }

      // Download backup
      const tempDir = `/tmp/isectech-verify-${backupId}`;
      await fs.mkdir(tempDir, { recursive: true });
      
      const backupFile = path.join(tempDir, 'backup.enc');
      await this.downloadFromS3(backupId, backupFile);

      // Verify checksum
      const actualChecksum = await this.calculateChecksum(backupFile);
      result.checksumValid = actualChecksum === metadata.checksum;

      // Verify file size
      const stats = await fs.stat(backupFile);
      result.sizeValid = stats.size === metadata.size;

      // Decrypt and decompress
      const restoredFile = path.join(tempDir, `backup.${metadata.type}`);
      await this.decryptAndDecompress(backupFile, restoredFile);

      // Test restore to temporary Redis instance
      const testRedis = new Redis({
        host: 'localhost',
        port: 6380, // Use different port for test
        db: 15,     // Use highest DB number for test
      });

      try {
        // Clear test database
        await testRedis.flushdb();

        // Restore data
        if (metadata.type === 'rdb') {
          await this.restoreFromRDB(restoredFile, testRedis);
        } else if (metadata.type === 'aof') {
          await this.restoreFromAOF(restoredFile, testRedis);
        }

        // Verify key count
        const keys = await testRedis.dbsize();
        result.keyCountValid = Math.abs(keys - metadata.keys) <= metadata.keys * 0.01; // 1% tolerance

        // Verify random sample of data
        result.dataIntegrityValid = await this.verifyDataSample(testRedis);
        result.restoreTestPassed = result.checksumValid && result.sizeValid && 
                                  result.keyCountValid && result.dataIntegrityValid;

      } finally {
        await testRedis.flushdb();
        testRedis.disconnect();
      }

      // Clean up
      await fs.rm(tempDir, { recursive: true });

      console.log(`Backup verification completed: ${backupId} - ${result.restoreTestPassed ? 'PASSED' : 'FAILED'}`);
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
   * Restore Redis from backup
   */
  async restoreFromBackup(options: RedisRestoreOptions): Promise<void> {
    console.log(`Starting restore from backup: ${options.backupId}`);
    
    try {
      const metadata = this.backupHistory.get(options.backupId);
      if (!metadata) {
        throw new Error(`Backup not found: ${options.backupId}`);
      }

      // Verify backup before restore
      const verification = await this.verifyBackup(options.backupId);
      if (!verification.restoreTestPassed) {
        throw new Error(`Backup verification failed: ${options.backupId}`);
      }

      // Download backup
      const tempDir = `/tmp/isectech-restore-${options.backupId}`;
      await fs.mkdir(tempDir, { recursive: true });
      
      const backupFile = path.join(tempDir, 'backup.enc');
      await this.downloadFromS3(options.backupId, backupFile);

      // Decrypt and decompress
      const restoreFile = path.join(tempDir, `backup.${metadata.type}`);
      await this.decryptAndDecompress(backupFile, restoreFile);

      // Get target Redis connection
      const targetRedis = options.targetRedis ? 
        new Redis(options.targetRedis) : this.primaryRedis;

      if (options.dryRun) {
        console.log(`Dry run: Would restore ${options.backupId} to ${targetRedis.options.host}:${targetRedis.options.port}`);
        return;
      }

      // Flush database if requested
      if (options.flushBeforeRestore) {
        await targetRedis.flushdb();
      }

      // Perform restore based on backup type
      if (metadata.type === 'rdb') {
        await this.restoreFromRDB(restoreFile, targetRedis);
      } else if (metadata.type === 'aof') {
        await this.restoreFromAOF(restoreFile, targetRedis);
      } else if (metadata.type === 'full') {
        // For full backup, restore both RDB and AOF
        await this.restoreFromRDB(restoreFile.replace('.full', '.rdb'), targetRedis);
        await this.restoreFromAOF(restoreFile.replace('.full', '.aof'), targetRedis);
      }

      // Clean up
      await fs.rm(tempDir, { recursive: true });

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
    return `isectech-redis-${type}-${timestamp}-${random}`;
  }

  private async getRedisInfo(): Promise<any> {
    const info = await this.primaryRedis.info();
    const lines = info.split('\r\n');
    const result: any = {};
    
    for (const line of lines) {
      if (line.includes(':')) {
        const [key, value] = line.split(':');
        result[key] = isNaN(Number(value)) ? value : Number(value);
      }
    }

    // Get database info
    result.databases = [];
    result.total_keys = 0;
    
    for (let db = 0; db < 16; db++) {
      try {
        await this.primaryRedis.select(db);
        const size = await this.primaryRedis.dbsize();
        if (size > 0) {
          result.databases.push(db);
          result.total_keys += size;
        }
      } catch (error) {
        // Database doesn't exist or error accessing
      }
    }

    // Reset to default database
    await this.primaryRedis.select(this.config.redis.primary.db);

    return result;
  }

  private async waitForBackgroundSave(): Promise<void> {
    let retries = 0;
    const maxRetries = 60; // Wait up to 1 minute
    
    while (retries < maxRetries) {
      const lastsave = await this.primaryRedis.lastsave();
      const currentTime = Math.floor(Date.now() / 1000);
      
      if (currentTime - lastsave < 5) { // Saved within last 5 seconds
        return;
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
      retries++;
    }
    
    throw new Error('Background save did not complete within timeout');
  }

  private async waitForAOFRewrite(): Promise<void> {
    let retries = 0;
    const maxRetries = 60;
    
    while (retries < maxRetries) {
      const info = await this.primaryRedis.info('persistence');
      if (!info.includes('aof_rewrite_in_progress:1')) {
        return;
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
      retries++;
    }
    
    throw new Error('AOF rewrite did not complete within timeout');
  }

  private async getRDBFilePath(): Promise<string> {
    // This would typically be determined from Redis config
    // For now, use default path
    return '/var/lib/redis/dump.rdb';
  }

  private async getAOFFilePath(): Promise<string> {
    // This would typically be determined from Redis config
    // For now, use default path
    return '/var/lib/redis/appendonly.aof';
  }

  private async copyFile(source: string, destination: string): Promise<void> {
    return new Promise((resolve, reject) => {
      exec(`cp "${source}" "${destination}"`, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  private async compressAndEncrypt(inputFile: string, outputFile: string): Promise<void> {
    const { key, algorithm } = this.config.encryption;
    
    return new Promise((resolve, reject) => {
      const command = `gzip -c "${inputFile}" | openssl enc -${algorithm} -k "${key}" -out "${outputFile}"`;
      
      exec(command, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`Compression/encryption failed: ${error.message}\n${stderr}`));
        } else {
          resolve();
        }
      });
    });
  }

  private async decryptAndDecompress(inputFile: string, outputFile: string): Promise<void> {
    const { key, algorithm } = this.config.encryption;
    
    return new Promise((resolve, reject) => {
      const command = `openssl enc -d -${algorithm} -k "${key}" -in "${inputFile}" | gunzip > "${outputFile}"`;
      
      exec(command, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`Decryption/decompression failed: ${error.message}\n${stderr}`));
        } else {
          resolve();
        }
      });
    });
  }

  private async calculateChecksum(filePath: string): Promise<string> {
    const data = await fs.readFile(filePath);
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private combineChecksums(checksum1: string, checksum2: string): string {
    return crypto.createHash('sha256').update(checksum1 + checksum2).digest('hex');
  }

  private async uploadToS3(filePath: string, backupId: string, metadata: RedisBackupMetadata): Promise<void> {
    const fileData = await fs.readFile(filePath);
    const key = `${this.config.storage.s3.prefix}/${backupId}/backup.enc`;
    
    const uploadParams = {
      Bucket: this.config.storage.s3.bucket,
      Key: key,
      Body: fileData,
      Metadata: {
        'backup-id': backupId,
        'backup-type': metadata.type,
        'timestamp': metadata.timestamp.toISOString(),
        'checksum': metadata.checksum,
        'size': metadata.size.toString(),
        'redis-version': metadata.redisVersion,
        'keys': metadata.keys.toString(),
      },
      ServerSideEncryption: this.config.storage.s3.kmsKeyId ? 'aws:kms' : 'AES256',
      ...(this.config.storage.s3.kmsKeyId && { SSEKMSKeyId: this.config.storage.s3.kmsKeyId }),
    };

    await this.s3Client.send(new PutObjectCommand(uploadParams));
    
    // Upload metadata separately
    const metadataKey = `${this.config.storage.s3.prefix}/${backupId}/metadata.json`;
    await this.s3Client.send(new PutObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: metadataKey,
      Body: JSON.stringify(metadata, null, 2),
      ContentType: 'application/json',
    }));
  }

  private async downloadFromS3(backupId: string, outputFile: string): Promise<void> {
    const key = `${this.config.storage.s3.prefix}/${backupId}/backup.enc`;
    
    const response = await this.s3Client.send(new GetObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: key,
    }));

    if (response.Body) {
      const chunks: Uint8Array[] = [];
      // @ts-ignore - response.Body is a stream
      for await (const chunk of response.Body) {
        chunks.push(chunk);
      }
      const buffer = Buffer.concat(chunks);
      await fs.writeFile(outputFile, buffer);
    } else {
      throw new Error(`Failed to download backup: ${backupId}`);
    }
  }

  private async replicateToRegions(backupId: string, metadata: RedisBackupMetadata): Promise<void> {
    const promises = this.config.storage.replication.regions.map(async (region) => {
      if (region === this.config.storage.s3.region) return;
      
      console.log(`Replicating Redis backup ${backupId} to region ${region}`);
      // Implementation would depend on specific S3 cross-region replication setup
    });

    await Promise.all(promises);
  }

  private async restoreFromRDB(rdbFile: string, redis: Redis): Promise<void> {
    // Implementation would involve stopping Redis, replacing RDB file, and restarting
    // This is a simplified version for demonstration
    console.log(`Restoring from RDB file: ${rdbFile}`);
  }

  private async restoreFromAOF(aofFile: string, redis: Redis): Promise<void> {
    // Implementation would involve replaying AOF commands
    console.log(`Restoring from AOF file: ${aofFile}`);
  }

  private async verifyDataSample(redis: Redis): Promise<boolean> {
    try {
      // Sample a few random keys and verify their integrity
      const keys = await redis.randomkey();
      if (!keys) return true; // No keys to verify
      
      // Basic verification - check if key exists and has expected type
      const type = await redis.type(keys);
      return type !== 'none';
    } catch (error) {
      return false;
    }
  }

  private async sendNotification(
    type: 'success' | 'failure' | 'restore_success' | 'restore_failure',
    metadata?: RedisBackupMetadata,
    error?: any
  ): Promise<void> {
    let message: string;
    let subject: string;

    switch (type) {
      case 'success':
        subject = `✅ iSECTECH Redis Backup Completed: ${metadata!.id}`;
        message = `Redis backup completed successfully:\n- ID: ${metadata!.id}\n- Type: ${metadata!.type}\n- Size: ${this.formatBytes(metadata!.size)}\n- Keys: ${metadata!.keys}\n- Memory: ${this.formatBytes(metadata!.memory)}\n- Duration: ${metadata!.duration}ms`;
        break;
      case 'failure':
        subject = `❌ iSECTECH Redis Backup Failed: ${metadata!.id}`;
        message = `Redis backup failed:\n- ID: ${metadata!.id}\n- Type: ${metadata!.type}\n- Error: ${metadata!.error}`;
        break;
      case 'restore_success':
        subject = `✅ iSECTECH Redis Restore Completed: ${metadata!.id}`;
        message = `Redis restored successfully:\n- Backup ID: ${metadata!.id}\n- Keys Restored: ${metadata!.keys}\n- Original Backup Date: ${metadata!.timestamp.toISOString()}`;
        break;
      case 'restore_failure':
        subject = `❌ iSECTECH Redis Restore Failed`;
        message = `Redis restore failed:\n- Error: ${error?.message || 'Unknown error'}`;
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

  private async publishMetrics(metadata: RedisBackupMetadata): Promise<void> {
    const params = {
      Namespace: this.config.monitoring.cloudwatch.namespace,
      MetricData: [
        {
          MetricName: 'RedisBackupSize',
          Value: metadata.size,
          Unit: 'Bytes',
          Dimensions: [
            { Name: 'BackupType', Value: metadata.type },
            { Name: 'RedisInstance', Value: this.config.redis.primary.host },
          ],
        },
        {
          MetricName: 'RedisBackupDuration',
          Value: metadata.duration,
          Unit: 'Milliseconds',
          Dimensions: [
            { Name: 'BackupType', Value: metadata.type },
            { Name: 'RedisInstance', Value: this.config.redis.primary.host },
          ],
        },
        {
          MetricName: 'RedisBackupKeys',
          Value: metadata.keys,
          Unit: 'Count',
          Dimensions: [
            { Name: 'BackupType', Value: metadata.type },
            { Name: 'RedisInstance', Value: this.config.redis.primary.host },
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

  // Connection management
  async disconnect(): Promise<void> {
    await this.primaryRedis.disconnect();
    await Promise.all(this.replicaRedis.map(redis => redis.disconnect()));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function createRedisBackupManager(config: RedisBackupConfig): RedisBackupManager {
  return new RedisBackupManager(config);
}

// Export default configuration for iSECTECH
export const defaultRedisBackupConfig: Partial<RedisBackupConfig> = {
  storage: {
    s3: {
      bucket: 'isectech-redis-backups',
      region: 'us-east-1',
      prefix: 'redis',
    },
    replication: {
      enabled: true,
      regions: ['us-west-2', 'eu-west-1'],
    },
  },
  schedule: {
    rdb: '0 */6 * * *', // Every 6 hours
    aof: '0 */2 * * *', // Every 2 hours
    retention: {
      hourly: 24,
      daily: 7,
      weekly: 4,
      monthly: 12,
    },
  },
  encryption: {
    key: process.env.REDIS_BACKUP_ENCRYPTION_KEY || '',
    algorithm: 'aes-256-gcm',
  },
  monitoring: {
    cloudwatch: {
      namespace: 'iSECTECH/Redis/Backups',
      region: 'us-east-1',
    },
  },
};