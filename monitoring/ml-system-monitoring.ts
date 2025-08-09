/**
 * ML System Monitoring Dashboard and Metrics Collection
 * 
 * Comprehensive monitoring for ML/AI systems including model performance,
 * drift detection, resource utilization, and system health.
 * 
 * Task 85.10: Document, Monitor, and Report System Performance
 */

import { Logger } from 'winston';
import { Registry, Counter, Histogram, Gauge, Summary, collectDefaultMetrics } from 'prom-client';
import { EventEmitter } from 'events';

interface MLModelMetrics {
  // Model Performance Metrics
  modelInferenceDuration: Histogram<string>;
  modelThroughput: Counter<string>;
  modelAccuracy: Gauge<string>;
  modelPrecision: Gauge<string>;
  modelRecall: Gauge<string>;
  modelF1Score: Gauge<string>;
  modelAucRoc: Gauge<string>;
  
  // Resource Utilization
  modelCpuUsage: Gauge<string>;
  modelMemoryUsage: Gauge<string>;
  modelGpuUsage: Gauge<string>;
  modelGpuMemory: Gauge<string>;
  
  // Drift Detection
  modelDriftScore: Gauge<string>;
  featureDriftScore: Gauge<string>;
  predictionDriftScore: Gauge<string>;
  dataDriftDetected: Counter<string>;
  
  // Error and Health Metrics
  modelErrors: Counter<string>;
  modelTimeouts: Counter<string>;
  modelSlaViolations: Counter<string>;
  modelHealthScore: Gauge<string>;
  
  // Queue and Load Metrics
  modelQueueDepth: Gauge<string>;
  modelQueueWaitTime: Histogram<string>;
  concurrentInferences: Gauge<string>;
  
  // Training and Deployment
  modelTrainingDuration: Histogram<string>;
  modelDeploymentTime: Histogram<string>;
  modelVersions: Counter<string>;
  modelRetraining: Counter<string>;
}

interface MLAlert {
  alertId: string;
  modelId: string;
  alertType: 'performance_degradation' | 'drift_detected' | 'sla_violation' | 'resource_exhaustion' | 'training_failure';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  metadata: Record<string, any>;
  timestamp: Date;
  tenantId?: string;
}

interface ModelDriftMetrics {
  statisticalDrift: {
    klDivergence: number;
    jsDivergence: number;
    psiScore: number;
  };
  performanceDrift: {
    accuracyDrift: number;
    precisionDrift: number;
    recallDrift: number;
  };
  featureDrift: {
    driftingFeatures: string[];
    driftScores: Record<string, number>;
  };
  predictionDrift: {
    distributionShift: number;
    confidenceShift: number;
  };
}

interface MLMonitoringConfig {
  // Model monitoring settings
  models: {
    enablePerformanceTracking: boolean;
    enableDriftDetection: boolean;
    driftThreshold: number;
    performanceThresholds: {
      maxInferenceTimeMs: number;
      minAccuracy: number;
      maxErrorRate: number;
    };
  };
  
  // Resource monitoring
  resources: {
    cpuThreshold: number;
    memoryThresholdMB: number;
    gpuThreshold: number;
    enableResourceOptimization: boolean;
  };
  
  // Alerting configuration
  alerting: {
    enableDriftAlerts: boolean;
    enablePerformanceAlerts: boolean;
    enableResourceAlerts: boolean;
    alertCooldownMinutes: number;
    destinations: {
      webhook?: string;
      slack?: string;
      email?: string[];
    };
  };
  
  // Data collection
  collection: {
    metricsRetentionDays: number;
    samplingRate: number;
    batchSize: number;
    flushIntervalSeconds: number;
  };
}

/**
 * ML System Monitoring Service
 * 
 * Provides comprehensive monitoring for machine learning systems with:
 * - Real-time model performance tracking
 * - Drift detection and alerting
 * - Resource utilization monitoring
 * - SLA compliance tracking
 * - Automated optimization recommendations
 */
export class MLSystemMonitor extends EventEmitter {
  private metrics: MLModelMetrics;
  private logger: Logger;
  private config: MLMonitoringConfig;
  private registry: Registry;
  
  private modelRegistry: Map<string, any> = new Map();
  private modelBaselines: Map<string, any> = new Map();
  private driftDetectionResults: Map<string, ModelDriftMetrics> = new Map();
  private performanceHistory: Map<string, any[]> = new Map();
  
  private alertBuffer: MLAlert[] = [];
  private lastDriftCheck: Map<string, Date> = new Map();

  constructor(logger: Logger, config: MLMonitoringConfig) {
    super();
    this.logger = logger;
    this.config = config;
    this.registry = new Registry();
    
    this.initializeMetrics();
    this.startPeriodicTasks();
    
    // Enable default Node.js metrics
    collectDefaultMetrics({ 
      register: this.registry,
      labels: { service: 'ml-system' }
    });

    this.logger.info('ML System Monitor initialized', {
      component: 'MLSystemMonitor',
      modelsTracking: this.config.models.enablePerformanceTracking,
      driftDetection: this.config.models.enableDriftDetection,
    });
  }

  /**
   * Initialize Prometheus metrics for ML system monitoring
   */
  private initializeMetrics(): void {
    this.metrics = {
      // Model Performance Metrics
      modelInferenceDuration: new Histogram({
        name: 'ml_model_inference_duration_seconds',
        help: 'Duration of model inference operations',
        labelNames: ['model_id', 'model_type', 'tenant_id', 'version'],
        buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
        registers: [this.registry],
      }),

      modelThroughput: new Counter({
        name: 'ml_model_inferences_total',
        help: 'Total number of model inferences',
        labelNames: ['model_id', 'model_type', 'tenant_id', 'status', 'version'],
        registers: [this.registry],
      }),

      modelAccuracy: new Gauge({
        name: 'ml_model_accuracy',
        help: 'Current model accuracy score',
        labelNames: ['model_id', 'model_type', 'tenant_id', 'dataset_type'],
        registers: [this.registry],
      }),

      modelPrecision: new Gauge({
        name: 'ml_model_precision',
        help: 'Current model precision score',
        labelNames: ['model_id', 'model_type', 'tenant_id', 'class'],
        registers: [this.registry],
      }),

      modelRecall: new Gauge({
        name: 'ml_model_recall',
        help: 'Current model recall score',
        labelNames: ['model_id', 'model_type', 'tenant_id', 'class'],
        registers: [this.registry],
      }),

      modelF1Score: new Gauge({
        name: 'ml_model_f1_score',
        help: 'Current model F1 score',
        labelNames: ['model_id', 'model_type', 'tenant_id', 'class'],
        registers: [this.registry],
      }),

      modelAucRoc: new Gauge({
        name: 'ml_model_auc_roc',
        help: 'Current model AUC-ROC score',
        labelNames: ['model_id', 'model_type', 'tenant_id'],
        registers: [this.registry],
      }),

      // Resource Utilization
      modelCpuUsage: new Gauge({
        name: 'ml_model_cpu_usage_percent',
        help: 'CPU usage percentage during model operations',
        labelNames: ['model_id', 'model_type', 'instance'],
        registers: [this.registry],
      }),

      modelMemoryUsage: new Gauge({
        name: 'ml_model_memory_usage_bytes',
        help: 'Memory usage in bytes during model operations',
        labelNames: ['model_id', 'model_type', 'instance'],
        registers: [this.registry],
      }),

      modelGpuUsage: new Gauge({
        name: 'ml_model_gpu_usage_percent',
        help: 'GPU usage percentage during model operations',
        labelNames: ['model_id', 'model_type', 'gpu_id', 'instance'],
        registers: [this.registry],
      }),

      modelGpuMemory: new Gauge({
        name: 'ml_model_gpu_memory_bytes',
        help: 'GPU memory usage in bytes',
        labelNames: ['model_id', 'model_type', 'gpu_id', 'instance'],
        registers: [this.registry],
      }),

      // Drift Detection
      modelDriftScore: new Gauge({
        name: 'ml_model_drift_score',
        help: 'Overall drift score for the model',
        labelNames: ['model_id', 'model_type', 'tenant_id', 'drift_type'],
        registers: [this.registry],
      }),

      featureDriftScore: new Gauge({
        name: 'ml_feature_drift_score',
        help: 'Drift score for individual features',
        labelNames: ['model_id', 'feature_name', 'tenant_id'],
        registers: [this.registry],
      }),

      predictionDriftScore: new Gauge({
        name: 'ml_prediction_drift_score',
        help: 'Drift score for model predictions',
        labelNames: ['model_id', 'model_type', 'tenant_id'],
        registers: [this.registry],
      }),

      dataDriftDetected: new Counter({
        name: 'ml_data_drift_detections_total',
        help: 'Total number of data drift detections',
        labelNames: ['model_id', 'drift_type', 'tenant_id', 'severity'],
        registers: [this.registry],
      }),

      // Error and Health Metrics
      modelErrors: new Counter({
        name: 'ml_model_errors_total',
        help: 'Total number of model errors',
        labelNames: ['model_id', 'model_type', 'error_type', 'tenant_id'],
        registers: [this.registry],
      }),

      modelTimeouts: new Counter({
        name: 'ml_model_timeouts_total',
        help: 'Total number of model inference timeouts',
        labelNames: ['model_id', 'model_type', 'tenant_id'],
        registers: [this.registry],
      }),

      modelSlaViolations: new Counter({
        name: 'ml_model_sla_violations_total',
        help: 'Total number of SLA violations',
        labelNames: ['model_id', 'sla_type', 'tenant_id'],
        registers: [this.registry],
      }),

      modelHealthScore: new Gauge({
        name: 'ml_model_health_score',
        help: 'Overall health score of the model (0-100)',
        labelNames: ['model_id', 'model_type', 'tenant_id'],
        registers: [this.registry],
      }),

      // Queue and Load Metrics
      modelQueueDepth: new Gauge({
        name: 'ml_model_queue_depth',
        help: 'Current depth of model inference queue',
        labelNames: ['model_id', 'queue_type', 'tenant_id'],
        registers: [this.registry],
      }),

      modelQueueWaitTime: new Histogram({
        name: 'ml_model_queue_wait_duration_seconds',
        help: 'Time spent waiting in model inference queue',
        labelNames: ['model_id', 'queue_type', 'tenant_id'],
        buckets: [0.001, 0.01, 0.1, 0.5, 1, 5, 10, 30],
        registers: [this.registry],
      }),

      concurrentInferences: new Gauge({
        name: 'ml_concurrent_inferences',
        help: 'Number of concurrent model inferences',
        labelNames: ['model_id', 'model_type', 'instance'],
        registers: [this.registry],
      }),

      // Training and Deployment
      modelTrainingDuration: new Histogram({
        name: 'ml_model_training_duration_seconds',
        help: 'Duration of model training operations',
        labelNames: ['model_id', 'model_type', 'training_type'],
        buckets: [60, 300, 600, 1800, 3600, 7200, 14400, 28800],
        registers: [this.registry],
      }),

      modelDeploymentTime: new Histogram({
        name: 'ml_model_deployment_duration_seconds',
        help: 'Duration of model deployment operations',
        labelNames: ['model_id', 'model_type', 'deployment_type'],
        buckets: [1, 5, 10, 30, 60, 180, 300, 600],
        registers: [this.registry],
      }),

      modelVersions: new Counter({
        name: 'ml_model_versions_total',
        help: 'Total number of model versions deployed',
        labelNames: ['model_id', 'model_type', 'action'],
        registers: [this.registry],
      }),

      modelRetraining: new Counter({
        name: 'ml_model_retraining_total',
        help: 'Total number of model retraining events',
        labelNames: ['model_id', 'trigger_reason', 'status'],
        registers: [this.registry],
      }),
    };
  }

  /**
   * Register a model for monitoring
   */
  public registerModel(
    modelId: string,
    modelType: string,
    modelInstance: any,
    baseline?: any,
    tenantId?: string
  ): void {
    this.modelRegistry.set(modelId, {
      instance: modelInstance,
      type: modelType,
      tenantId,
      registeredAt: new Date(),
    });

    if (baseline) {
      this.modelBaselines.set(modelId, baseline);
    }

    this.logger.info('Model registered for monitoring', {
      modelId,
      modelType,
      tenantId,
    });

    this.emit('model-registered', { modelId, modelType, tenantId });
  }

  /**
   * Record model inference metrics
   */
  public recordInference(
    modelId: string,
    duration: number,
    success: boolean,
    tenantId?: string,
    version?: string,
    resourceUsage?: {
      cpu?: number;
      memory?: number;
      gpu?: number;
      gpuMemory?: number;
    }
  ): void {
    const modelInfo = this.modelRegistry.get(modelId);
    if (!modelInfo) {
      this.logger.warn('Recording inference for unregistered model', { modelId });
      return;
    }

    const labels = {
      model_id: modelId,
      model_type: modelInfo.type,
      tenant_id: tenantId || 'unknown',
      version: version || 'latest',
    };

    // Record inference duration
    this.metrics.modelInferenceDuration.observe(labels, duration / 1000);

    // Record throughput
    this.metrics.modelThroughput.inc({
      ...labels,
      status: success ? 'success' : 'failure',
    });

    // Check for SLA violations
    if (duration > this.config.models.performanceThresholds.maxInferenceTimeMs) {
      this.metrics.modelSlaViolations.inc({
        model_id: modelId,
        sla_type: 'inference_time',
        tenant_id: tenantId || 'unknown',
      });

      this.createAlert({
        alertId: `sla_violation_${modelId}_${Date.now()}`,
        modelId,
        alertType: 'sla_violation',
        severity: 'high',
        message: `Inference time SLA violation: ${duration}ms > ${this.config.models.performanceThresholds.maxInferenceTimeMs}ms`,
        metadata: { duration, threshold: this.config.models.performanceThresholds.maxInferenceTimeMs },
        timestamp: new Date(),
        tenantId,
      });
    }

    // Record resource usage if provided
    if (resourceUsage) {
      const instanceLabels = {
        model_id: modelId,
        model_type: modelInfo.type,
        instance: process.env.HOSTNAME || 'unknown',
      };

      if (resourceUsage.cpu !== undefined) {
        this.metrics.modelCpuUsage.set(instanceLabels, resourceUsage.cpu);
      }

      if (resourceUsage.memory !== undefined) {
        this.metrics.modelMemoryUsage.set(instanceLabels, resourceUsage.memory);
      }

      if (resourceUsage.gpu !== undefined) {
        this.metrics.modelGpuUsage.set({
          ...instanceLabels,
          gpu_id: '0', // Default GPU
        }, resourceUsage.gpu);
      }

      if (resourceUsage.gpuMemory !== undefined) {
        this.metrics.modelGpuMemory.set({
          ...instanceLabels,
          gpu_id: '0',
        }, resourceUsage.gpuMemory);
      }
    }

    // Record error if inference failed
    if (!success) {
      this.metrics.modelErrors.inc({
        model_id: modelId,
        model_type: modelInfo.type,
        error_type: 'inference_failure',
        tenant_id: tenantId || 'unknown',
      });
    }
  }

  /**
   * Record model quality metrics
   */
  public recordModelQuality(
    modelId: string,
    metrics: {
      accuracy?: number;
      precision?: number;
      recall?: number;
      f1Score?: number;
      aucRoc?: number;
    },
    tenantId?: string,
    datasetType: string = 'validation'
  ): void {
    const modelInfo = this.modelRegistry.get(modelId);
    if (!modelInfo) {
      this.logger.warn('Recording quality metrics for unregistered model', { modelId });
      return;
    }

    const baseLabels = {
      model_id: modelId,
      model_type: modelInfo.type,
      tenant_id: tenantId || 'unknown',
    };

    if (metrics.accuracy !== undefined) {
      this.metrics.modelAccuracy.set({ ...baseLabels, dataset_type: datasetType }, metrics.accuracy);
      
      // Check for accuracy degradation
      if (metrics.accuracy < this.config.models.performanceThresholds.minAccuracy) {
        this.createAlert({
          alertId: `accuracy_degradation_${modelId}_${Date.now()}`,
          modelId,
          alertType: 'performance_degradation',
          severity: 'high',
          message: `Model accuracy below threshold: ${metrics.accuracy} < ${this.config.models.performanceThresholds.minAccuracy}`,
          metadata: { accuracy: metrics.accuracy, threshold: this.config.models.performanceThresholds.minAccuracy },
          timestamp: new Date(),
          tenantId,
        });
      }
    }

    if (metrics.precision !== undefined) {
      this.metrics.modelPrecision.set({ ...baseLabels, class: 'overall' }, metrics.precision);
    }

    if (metrics.recall !== undefined) {
      this.metrics.modelRecall.set({ ...baseLabels, class: 'overall' }, metrics.recall);
    }

    if (metrics.f1Score !== undefined) {
      this.metrics.modelF1Score.set({ ...baseLabels, class: 'overall' }, metrics.f1Score);
    }

    if (metrics.aucRoc !== undefined) {
      this.metrics.modelAucRoc.set(baseLabels, metrics.aucRoc);
    }

    // Calculate and record overall health score
    const healthScore = this.calculateHealthScore(modelId, metrics);
    this.metrics.modelHealthScore.set(baseLabels, healthScore);
  }

  /**
   * Record drift detection results
   */
  public recordDriftDetection(
    modelId: string,
    driftMetrics: ModelDriftMetrics,
    tenantId?: string
  ): void {
    this.driftDetectionResults.set(modelId, driftMetrics);
    this.lastDriftCheck.set(modelId, new Date());

    const baseLabels = {
      model_id: modelId,
      tenant_id: tenantId || 'unknown',
    };

    // Record statistical drift scores
    this.metrics.modelDriftScore.set(
      { ...baseLabels, drift_type: 'kl_divergence' },
      driftMetrics.statisticalDrift.klDivergence
    );

    this.metrics.modelDriftScore.set(
      { ...baseLabels, drift_type: 'js_divergence' },
      driftMetrics.statisticalDrift.jsDivergence
    );

    this.metrics.modelDriftScore.set(
      { ...baseLabels, drift_type: 'psi_score' },
      driftMetrics.statisticalDrift.psiScore
    );

    // Record feature drift scores
    for (const [featureName, score] of Object.entries(driftMetrics.featureDrift.driftScores)) {
      this.metrics.featureDriftScore.set({
        model_id: modelId,
        feature_name: featureName,
        tenant_id: tenantId || 'unknown',
      }, score);
    }

    // Record prediction drift
    this.metrics.predictionDriftScore.set(
      { ...baseLabels, model_type: 'distribution' },
      driftMetrics.predictionDrift.distributionShift
    );

    // Check for drift alerts
    const maxDrift = Math.max(
      driftMetrics.statisticalDrift.klDivergence,
      driftMetrics.statisticalDrift.jsDivergence,
      driftMetrics.statisticalDrift.psiScore
    );

    if (maxDrift > this.config.models.driftThreshold) {
      this.metrics.dataDriftDetected.inc({
        model_id: modelId,
        drift_type: 'statistical',
        tenant_id: tenantId || 'unknown',
        severity: maxDrift > this.config.models.driftThreshold * 2 ? 'high' : 'medium',
      });

      this.createAlert({
        alertId: `drift_detected_${modelId}_${Date.now()}`,
        modelId,
        alertType: 'drift_detected',
        severity: maxDrift > this.config.models.driftThreshold * 2 ? 'critical' : 'high',
        message: `Model drift detected: max drift score ${maxDrift.toFixed(3)} > ${this.config.models.driftThreshold}`,
        metadata: {
          maxDrift,
          threshold: this.config.models.driftThreshold,
          driftMetrics: driftMetrics,
        },
        timestamp: new Date(),
        tenantId,
      });
    }
  }

  /**
   * Record training event
   */
  public recordTraining(
    modelId: string,
    duration: number,
    success: boolean,
    triggerReason: string,
    modelType?: string
  ): void {
    const labels = {
      model_id: modelId,
      model_type: modelType || 'unknown',
      training_type: triggerReason,
    };

    this.metrics.modelTrainingDuration.observe(labels, duration / 1000);

    this.metrics.modelRetraining.inc({
      model_id: modelId,
      trigger_reason: triggerReason,
      status: success ? 'success' : 'failure',
    });

    if (!success) {
      this.createAlert({
        alertId: `training_failure_${modelId}_${Date.now()}`,
        modelId,
        alertType: 'training_failure',
        severity: 'high',
        message: `Model training failed: ${modelId} (trigger: ${triggerReason})`,
        metadata: { duration, triggerReason },
        timestamp: new Date(),
      });
    }
  }

  /**
   * Update queue metrics
   */
  public updateQueueMetrics(
    modelId: string,
    queueDepth: number,
    waitTime?: number,
    tenantId?: string,
    queueType: string = 'inference'
  ): void {
    this.metrics.modelQueueDepth.set({
      model_id: modelId,
      queue_type: queueType,
      tenant_id: tenantId || 'unknown',
    }, queueDepth);

    if (waitTime !== undefined) {
      this.metrics.modelQueueWaitTime.observe({
        model_id: modelId,
        queue_type: queueType,
        tenant_id: tenantId || 'unknown',
      }, waitTime / 1000);
    }
  }

  /**
   * Calculate overall health score for a model
   */
  private calculateHealthScore(modelId: string, qualityMetrics: any): number {
    let score = 100;

    // Deduct points based on quality metrics
    if (qualityMetrics.accuracy !== undefined && qualityMetrics.accuracy < 0.9) {
      score -= (0.9 - qualityMetrics.accuracy) * 100;
    }

    // Check drift status
    const driftMetrics = this.driftDetectionResults.get(modelId);
    if (driftMetrics) {
      const maxDrift = Math.max(
        driftMetrics.statisticalDrift.klDivergence,
        driftMetrics.statisticalDrift.jsDivergence
      );
      if (maxDrift > this.config.models.driftThreshold) {
        score -= Math.min(maxDrift * 100, 30); // Max 30 points deduction for drift
      }
    }

    // Check for recent errors (would need to implement error tracking)
    // This is a placeholder for error rate impact on health score

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Create and buffer alert
   */
  private createAlert(alert: MLAlert): void {
    this.alertBuffer.push(alert);
    
    this.logger.warn('ML System alert generated', {
      component: 'MLSystemMonitor',
      alertId: alert.alertId,
      modelId: alert.modelId,
      alertType: alert.alertType,
      severity: alert.severity,
      message: alert.message,
    });

    // Send immediate alerts for critical issues
    if (alert.severity === 'critical') {
      this.sendAlert(alert);
    }

    this.emit('alert-generated', alert);
  }

  /**
   * Send alert to configured destinations
   */
  private async sendAlert(alert: MLAlert): Promise<void> {
    // Implementation would send to webhook, Slack, etc.
    // For now, just emit event and log
    this.logger.error('ML System critical alert', {
      alert: {
        id: alert.alertId,
        modelId: alert.modelId,
        type: alert.alertType,
        severity: alert.severity,
        message: alert.message,
        metadata: alert.metadata,
      },
    });

    this.emit('critical-alert', alert);
  }

  /**
   * Start periodic monitoring tasks
   */
  private startPeriodicTasks(): void {
    // Drift detection check every 5 minutes
    if (this.config.models.enableDriftDetection) {
      setInterval(() => {
        this.performDriftChecks();
      }, 5 * 60 * 1000);
    }

    // Health check and cleanup every minute
    setInterval(() => {
      this.performHealthChecks();
      this.flushAlerts();
    }, 60 * 1000);

    // Resource monitoring every 30 seconds
    setInterval(() => {
      this.monitorSystemResources();
    }, 30 * 1000);
  }

  /**
   * Perform drift detection checks for all models
   */
  private performDriftChecks(): void {
    for (const [modelId] of this.modelRegistry) {
      const lastCheck = this.lastDriftCheck.get(modelId);
      const now = new Date();
      
      // Check if we need to run drift detection (every 4 hours by default)
      if (!lastCheck || (now.getTime() - lastCheck.getTime()) > 4 * 60 * 60 * 1000) {
        // This would trigger actual drift detection
        // For now, we just emit an event that external systems can listen to
        this.emit('drift-check-needed', { modelId });
      }
    }
  }

  /**
   * Perform health checks on all registered models
   */
  private performHealthChecks(): void {
    for (const [modelId, modelInfo] of this.modelRegistry) {
      // Calculate and update health score
      const healthScore = this.calculateHealthScore(modelId, {});
      this.metrics.modelHealthScore.set({
        model_id: modelId,
        model_type: modelInfo.type,
        tenant_id: modelInfo.tenantId || 'unknown',
      }, healthScore);

      // Generate health alert if score is low
      if (healthScore < 70) {
        this.createAlert({
          alertId: `health_degradation_${modelId}_${Date.now()}`,
          modelId,
          alertType: 'performance_degradation',
          severity: healthScore < 50 ? 'critical' : 'high',
          message: `Model health score degraded: ${healthScore}/100`,
          metadata: { healthScore },
          timestamp: new Date(),
          tenantId: modelInfo.tenantId,
        });
      }
    }
  }

  /**
   * Monitor system resources
   */
  private monitorSystemResources(): void {
    // This would integrate with system monitoring
    // For now, just emit events that external systems can handle
    this.emit('resource-check-needed');
  }

  /**
   * Flush buffered alerts
   */
  private flushAlerts(): void {
    if (this.alertBuffer.length === 0) return;

    const alertsToFlush = this.alertBuffer.splice(0);
    
    for (const alert of alertsToFlush) {
      if (alert.severity !== 'critical') { // Critical alerts already sent
        this.sendAlert(alert);
      }
    }
  }

  /**
   * Get current status of all monitored models
   */
  public getModelStatus(): Record<string, any> {
    const status: Record<string, any> = {};

    for (const [modelId, modelInfo] of this.modelRegistry) {
      const driftMetrics = this.driftDetectionResults.get(modelId);
      const lastDriftCheck = this.lastDriftCheck.get(modelId);

      status[modelId] = {
        type: modelInfo.type,
        tenantId: modelInfo.tenantId,
        registeredAt: modelInfo.registeredAt,
        lastDriftCheck: lastDriftCheck,
        hasDrift: driftMetrics ? this.isDriftDetected(driftMetrics) : false,
        driftMetrics: driftMetrics,
      };
    }

    return status;
  }

  /**
   * Check if drift is detected based on thresholds
   */
  private isDriftDetected(driftMetrics: ModelDriftMetrics): boolean {
    const maxDrift = Math.max(
      driftMetrics.statisticalDrift.klDivergence,
      driftMetrics.statisticalDrift.jsDivergence,
      driftMetrics.statisticalDrift.psiScore
    );

    return maxDrift > this.config.models.driftThreshold;
  }

  /**
   * Get Prometheus metrics registry
   */
  public getMetricsRegistry(): Registry {
    return this.registry;
  }

  /**
   * Get metrics as Prometheus text format
   */
  public async getMetrics(): Promise<string> {
    return await this.registry.metrics();
  }

  /**
   * Health check for the monitoring system itself
   */
  public getHealth(): { status: 'healthy' | 'degraded' | 'unhealthy'; details: Record<string, any> } {
    const modelCount = this.modelRegistry.size;
    const alertCount = this.alertBuffer.length;
    
    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    
    if (alertCount > 100) {
      status = 'unhealthy';
    } else if (alertCount > 50 || modelCount === 0) {
      status = 'degraded';
    }

    return {
      status,
      details: {
        registeredModels: modelCount,
        bufferedAlerts: alertCount,
        driftDetectionEnabled: this.config.models.enableDriftDetection,
        performanceTrackingEnabled: this.config.models.enablePerformanceTracking,
        lastHealthCheck: new Date(),
      },
    };
  }

  /**
   * Shutdown the monitoring system
   */
  public async shutdown(): Promise<void> {
    this.logger.info('Shutting down ML System Monitor');
    
    // Flush any remaining alerts
    this.flushAlerts();
    
    // Clear all data structures
    this.modelRegistry.clear();
    this.modelBaselines.clear();
    this.driftDetectionResults.clear();
    this.performanceHistory.clear();
    this.alertBuffer.length = 0;
    
    // Remove all listeners
    this.removeAllListeners();
    
    this.logger.info('ML System Monitor shutdown complete');
  }
}

/**
 * Factory function to create MLSystemMonitor with default configuration
 */
export function createMLSystemMonitor(
  logger: Logger,
  overrides: Partial<MLMonitoringConfig> = {}
): MLSystemMonitor {
  const defaultConfig: MLMonitoringConfig = {
    models: {
      enablePerformanceTracking: true,
      enableDriftDetection: true,
      driftThreshold: 0.1,
      performanceThresholds: {
        maxInferenceTimeMs: 50,
        minAccuracy: 0.85,
        maxErrorRate: 0.01,
      },
    },
    resources: {
      cpuThreshold: 80,
      memoryThresholdMB: 8192,
      gpuThreshold: 85,
      enableResourceOptimization: true,
    },
    alerting: {
      enableDriftAlerts: true,
      enablePerformanceAlerts: true,
      enableResourceAlerts: true,
      alertCooldownMinutes: 15,
      destinations: {},
    },
    collection: {
      metricsRetentionDays: 30,
      samplingRate: 1.0,
      batchSize: 100,
      flushIntervalSeconds: 60,
    },
  };

  const config = { ...defaultConfig, ...overrides };
  return new MLSystemMonitor(logger, config);
}

export { MLSystemMonitor, MLModelMetrics, MLAlert, ModelDriftMetrics, MLMonitoringConfig };