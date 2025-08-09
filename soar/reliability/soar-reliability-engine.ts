/**
 * iSECTECH SOAR Reliability Engine
 * 
 * Comprehensive error handling, retry logic, and parallel execution system for 
 * enterprise-grade SOAR operations. Ensures fault tolerance, optimal performance,
 * and graceful degradation under various failure scenarios.
 * 
 * Features:
 * - Intelligent error handling with categorization and recovery strategies
 * - Advanced retry logic with exponential backoff, jitter, and circuit breakers
 * - Parallel execution engine with worker pools and task orchestration
 * - Fault tolerance patterns including bulkheads and graceful degradation
 * - Queue management with priority handling and backpressure control
 * - Comprehensive observability and performance monitoring
 */

import { z } from 'zod';
import { EventEmitter } from 'events';

// Core Reliability Schemas
const ErrorCategorySchema = z.enum(['transient', 'permanent', 'timeout', 'rate_limit', 'auth', 'validation', 'system', 'network']);
const RetryStrategySchema = z.enum(['exponential_backoff', 'linear_backoff', 'fixed_delay', 'fibonacci', 'custom']);
const ExecutionModeSchema = z.enum(['sequential', 'parallel', 'pipeline', 'batch', 'stream']);
const TaskPrioritySchema = z.enum(['critical', 'high', 'normal', 'low', 'background']);
const TaskStatusSchema = z.enum(['pending', 'running', 'completed', 'failed', 'retrying', 'cancelled', 'timeout']);

const ISECTECHErrorSchema = z.object({
  id: z.string(),
  category: ErrorCategorySchema,
  code: z.string(),
  message: z.string(),
  details: z.any().optional(),
  source: z.string(),
  timestamp: z.date(),
  
  // Context information
  operation: z.string(),
  requestId: z.string().optional(),
  userId: z.string().optional(),
  sessionId: z.string().optional(),
  
  // Error hierarchy
  cause: z.string().optional(), // ID of the root cause error
  correlationId: z.string().optional(),
  
  // Recovery information
  isRetryable: z.boolean(),
  retryCount: z.number().default(0),
  maxRetries: z.number().default(3),
  nextRetryAt: z.date().optional(),
  
  // Impact assessment
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  affectedComponents: z.array(z.string()),
  businessImpact: z.enum(['none', 'minimal', 'moderate', 'significant', 'critical']).optional(),
  
  // Resolution tracking
  resolved: z.boolean().default(false),
  resolvedAt: z.date().optional(),
  resolution: z.string().optional(),
  
  // Metadata
  tags: z.array(z.string()).default([]),
  metadata: z.record(z.any()).optional()
});

const ISECTECHRetryPolicySchema = z.object({
  id: z.string(),
  name: z.string(),
  strategy: RetryStrategySchema,
  
  // Basic retry configuration
  maxRetries: z.number().min(0).max(20),
  baseDelay: z.number().min(100), // milliseconds
  maxDelay: z.number().min(1000), // milliseconds
  
  // Advanced configuration
  backoffMultiplier: z.number().min(1).default(2),
  jitterEnabled: z.boolean().default(true),
  jitterFactor: z.number().min(0).max(1).default(0.1),
  
  // Conditions for retry
  retryableErrors: z.array(ErrorCategorySchema),
  retryableStatusCodes: z.array(z.number()).optional(),
  nonRetryableErrors: z.array(ErrorCategorySchema).optional(),
  
  // Circuit breaker integration
  circuitBreakerEnabled: z.boolean().default(true),
  failureThreshold: z.number().min(1).default(5),
  resetTimeout: z.number().min(1000).default(60000), // milliseconds
  
  // Timeout configuration
  timeoutMs: z.number().min(1000).optional(),
  totalTimeoutMs: z.number().min(5000).optional(),
  
  // Custom logic
  customCondition: z.string().optional(), // JavaScript expression
  customDelayFunction: z.string().optional(), // JavaScript function
  
  isActive: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date()
});

const ISECTECHTaskSchema = z.object({
  id: z.string(),
  name: z.string(),
  operation: z.string(),
  
  // Task configuration
  priority: TaskPrioritySchema,
  status: TaskStatusSchema,
  executionMode: ExecutionModeSchema,
  
  // Payload and parameters
  payload: z.any(),
  parameters: z.record(z.any()).optional(),
  context: z.record(z.any()).optional(),
  
  // Dependencies and relationships
  dependencies: z.array(z.string()).default([]),
  dependents: z.array(z.string()).default([]),
  parentTask: z.string().optional(),
  childTasks: z.array(z.string()).default([]),
  
  // Execution details
  assignedWorker: z.string().optional(),
  startedAt: z.date().optional(),
  completedAt: z.date().optional(),
  estimatedDuration: z.number().optional(), // milliseconds
  actualDuration: z.number().optional(), // milliseconds
  
  // Error handling
  retryPolicy: z.string().optional(), // retry policy ID
  errors: z.array(z.string()).default([]), // error IDs
  retryCount: z.number().default(0),
  maxRetries: z.number().default(3),
  
  // Result and output
  result: z.any().optional(),
  output: z.record(z.any()).optional(),
  
  // Progress tracking
  progress: z.number().min(0).max(100).default(0),
  progressDetails: z.string().optional(),
  
  // Scheduling
  scheduledAt: z.date().optional(),
  timeoutAt: z.date().optional(),
  
  // Metadata
  tags: z.array(z.string()).default([]),
  metadata: z.record(z.any()).optional(),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

const ISECTECHWorkerPoolSchema = z.object({
  id: z.string(),
  name: z.string(),
  
  // Pool configuration
  minWorkers: z.number().min(1).default(2),
  maxWorkers: z.number().min(1).default(10),
  currentWorkers: z.number().default(0),
  
  // Task processing
  supportedOperations: z.array(z.string()),
  queueCapacity: z.number().min(1).default(1000),
  currentQueueSize: z.number().default(0),
  
  // Performance settings
  concurrencyLimit: z.number().min(1).default(5),
  taskTimeout: z.number().min(1000).default(300000), // 5 minutes
  healthCheckInterval: z.number().min(1000).default(30000), // 30 seconds
  
  // Load balancing
  loadBalancingStrategy: z.enum(['round_robin', 'least_connections', 'weighted', 'priority']).default('round_robin'),
  
  // Monitoring
  metrics: z.object({
    tasksProcessed: z.number().default(0),
    tasksSucceeded: z.number().default(0),
    tasksFailed: z.number().default(0),
    averageTaskDuration: z.number().default(0),
    lastActivityAt: z.date().optional()
  }),
  
  // Health status
  isHealthy: z.boolean().default(true),
  healthDetails: z.record(z.any()).optional(),
  
  isActive: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date()
});

const ExecutionPlanSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  
  // Plan configuration
  tasks: z.array(z.string()), // task IDs
  executionMode: ExecutionModeSchema,
  parallelismLevel: z.number().min(1).default(1),
  
  // Scheduling
  scheduledAt: z.date().optional(),
  startedAt: z.date().optional(),
  completedAt: z.date().optional(),
  
  // Status tracking
  status: z.enum(['pending', 'running', 'completed', 'failed', 'cancelled']),
  progress: z.number().min(0).max(100).default(0),
  
  // Error handling
  continueOnError: z.boolean().default(false),
  rollbackOnFailure: z.boolean().default(false),
  
  // Results
  results: z.record(z.any()).optional(),
  errors: z.array(z.string()).default([]),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

type ISECTECHError = z.infer<typeof ISECTECHErrorSchema>;
type ISECTECHRetryPolicy = z.infer<typeof ISECTECHRetryPolicySchema>;
type ISECTECHTask = z.infer<typeof ISECTECHTaskSchema>;
type ISECTECHWorkerPool = z.infer<typeof ISECTECHWorkerPoolSchema>;
type ExecutionPlan = z.infer<typeof ExecutionPlanSchema>;

interface ReliabilityConfig {
  defaultRetryPolicy: string;
  maxConcurrentTasks: number;
  maxQueueSize: number;
  taskTimeoutMs: number;
  workerHealthCheckInterval: number;
  errorRetentionDays: number;
  enableMetrics: boolean;
  enableTracing: boolean;
  circuitBreakerEnabled: boolean;
  bulkheadEnabled: boolean;
}

interface CircuitBreakerState {
  isOpen: boolean;
  failureCount: number;
  lastFailureTime: number;
  halfOpenRequests: number;
  resetTimeout: number;
}

interface BulkheadConfig {
  operation: string;
  maxConcurrency: number;
  currentExecutions: number;
  queue: string[];
  timeoutMs: number;
}

export class ISECTECHSOARReliabilityEngine extends EventEmitter {
  private errors = new Map<string, ISECTECHError>();
  private retryPolicies = new Map<string, ISECTECHRetryPolicy>();
  private tasks = new Map<string, ISECTECHTask>();
  private workerPools = new Map<string, ISECTECHWorkerPool>();
  private executionPlans = new Map<string, ExecutionPlan>();
  private config: ReliabilityConfig;
  
  // Circuit breakers per operation
  private circuitBreakers = new Map<string, CircuitBreakerState>();
  
  // Bulkhead pattern implementation
  private bulkheads = new Map<string, BulkheadConfig>();
  
  // Task queues with priority
  private taskQueues = new Map<string, ISECTECHTask[]>();
  private priorityQueue: ISECTECHTask[] = [];
  
  // Worker management
  private workers = new Map<string, any>();
  private workerHealthTimers = new Map<string, NodeJS.Timeout>();
  
  // Execution engine
  private executionTimer: NodeJS.Timeout | null = null;
  private isProcessing = false;
  
  // Performance monitoring
  private metrics = {
    tasksExecuted: 0,
    tasksSucceeded: 0,
    tasksFailed: 0,
    errorsHandled: 0,
    retriesPerformed: 0,
    circuitBreakerTrips: 0,
    averageExecutionTime: 0,
    startTime: new Date()
  };

  constructor(config: ReliabilityConfig) {
    super();
    this.config = config;
    this.initializeDefaultRetryPolicies();
    this.initializeDefaultWorkerPools();
    this.initializeDefaultBulkheads();
    this.startExecutionEngine();
    this.startHealthMonitoring();
  }

  // Error Handling
  async handleError(error: Partial<ISECTECHError>): Promise<ISECTECHError> {
    try {
      const errorId = `ERROR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const managedError: ISECTECHError = {
        id: errorId,
        category: this.categorizeError(error),
        code: error.code || 'UNKNOWN_ERROR',
        message: error.message || 'An unknown error occurred',
        details: error.details,
        source: error.source || 'unknown',
        timestamp: error.timestamp || new Date(),
        
        operation: error.operation || 'unknown_operation',
        requestId: error.requestId,
        userId: error.userId,
        sessionId: error.sessionId,
        
        cause: error.cause,
        correlationId: error.correlationId || this.generateCorrelationId(),
        
        isRetryable: this.isErrorRetryable(error),
        retryCount: error.retryCount || 0,
        maxRetries: error.maxRetries || 3,
        
        severity: this.assessErrorSeverity(error),
        affectedComponents: error.affectedComponents || [],
        businessImpact: this.assessBusinessImpact(error),
        
        resolved: false,
        tags: error.tags || [],
        metadata: error.metadata
      };

      this.errors.set(errorId, managedError);
      this.metrics.errorsHandled++;

      // Update circuit breaker
      if (this.config.circuitBreakerEnabled) {
        this.updateCircuitBreaker(managedError.operation, false);
      }

      // Emit error event for monitoring
      this.emit('errorHandled', managedError);

      // Auto-resolve if possible
      await this.attemptErrorResolution(managedError);

      return managedError;

    } catch (handlingError) {
      console.error('Error in error handling:', handlingError);
      throw handlingError;
    }
  }

  async retryOperation(operationName: string, operation: Function, context?: any): Promise<any> {
    const policy = this.getRetryPolicyForOperation(operationName);
    let lastError: Error | null = null;
    let attempt = 0;

    while (attempt <= policy.maxRetries) {
      try {
        // Check circuit breaker
        if (this.config.circuitBreakerEnabled && this.isCircuitBreakerOpen(operationName)) {
          throw new Error(`Circuit breaker is open for operation: ${operationName}`);
        }

        // Execute operation
        const result = await this.executeWithTimeout(operation, policy.timeoutMs, context);
        
        // Success - update circuit breaker
        if (this.config.circuitBreakerEnabled) {
          this.updateCircuitBreaker(operationName, true);
        }

        return result;

      } catch (error) {
        lastError = error as Error;
        attempt++;

        // Handle error
        const managedError = await this.handleError({
          message: lastError.message,
          operation: operationName,
          retryCount: attempt - 1,
          maxRetries: policy.maxRetries
        });

        // Check if we should retry
        if (attempt <= policy.maxRetries && this.shouldRetry(managedError, policy)) {
          const delay = this.calculateRetryDelay(policy, attempt - 1);
          
          this.emit('retryAttempt', {
            operation: operationName,
            attempt,
            delay,
            error: managedError
          });

          await this.sleep(delay);
          this.metrics.retriesPerformed++;
          continue;
        }

        break;
      }
    }

    // All retries exhausted
    throw lastError;
  }

  // Parallel Execution
  async executeParallel(tasks: ISECTECHTask[], options?: {
    maxConcurrency?: number;
    continueOnError?: boolean;
    timeout?: number;
  }): Promise<any[]> {
    try {
      const maxConcurrency = options?.maxConcurrency || this.config.maxConcurrentTasks;
      const continueOnError = options?.continueOnError || false;
      const timeout = options?.timeout || this.config.taskTimeoutMs;

      const results: any[] = [];
      const errors: any[] = [];
      const executing = new Set<Promise<any>>();

      for (let i = 0; i < tasks.length; i++) {
        const task = tasks[i];
        
        // Wait if we've reached max concurrency
        if (executing.size >= maxConcurrency) {
          await Promise.race(executing);
        }

        const taskPromise = this.executeTask(task, timeout)
          .then(result => {
            results[i] = result;
            return result;
          })
          .catch(error => {
            errors[i] = error;
            if (!continueOnError) {
              throw error;
            }
            return null;
          })
          .finally(() => {
            executing.delete(taskPromise);
          });

        executing.add(taskPromise);
      }

      // Wait for all remaining tasks
      await Promise.all(executing);

      if (errors.length > 0 && !continueOnError) {
        throw new Error(`Parallel execution failed with ${errors.length} errors`);
      }

      return results;

    } catch (error) {
      this.handleError({
        message: (error as Error).message,
        operation: 'executeParallel',
        category: 'system'
      });
      throw error;
    }
  }

  async executePipeline(tasks: ISECTECHTask[], initialInput?: any): Promise<any> {
    try {
      let currentInput = initialInput;
      const results: any[] = [];

      for (const task of tasks) {
        // Set input from previous task output
        task.payload = currentInput;
        
        const result = await this.executeTask(task);
        results.push(result);
        
        // Use result as input for next task
        currentInput = result;
      }

      return {
        finalResult: currentInput,
        intermediateResults: results
      };

    } catch (error) {
      this.handleError({
        message: (error as Error).message,
        operation: 'executePipeline',
        category: 'system'
      });
      throw error;
    }
  }

  async executeBatch(tasks: ISECTECHTask[], batchSize: number = 10): Promise<any[]> {
    try {
      const batches: ISECTECHTask[][] = [];
      
      // Split tasks into batches
      for (let i = 0; i < tasks.length; i += batchSize) {
        batches.push(tasks.slice(i, i + batchSize));
      }

      const allResults: any[] = [];

      // Execute batches sequentially
      for (const batch of batches) {
        const batchResults = await this.executeParallel(batch);
        allResults.push(...batchResults);
      }

      return allResults;

    } catch (error) {
      this.handleError({
        message: (error as Error).message,
        operation: 'executeBatch',
        category: 'system'
      });
      throw error;
    }
  }

  // Task Management
  async submitTask(taskData: Partial<ISECTECHTask>): Promise<string> {
    try {
      const taskId = `TASK-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const task: ISECTECHTask = {
        id: taskId,
        name: taskData.name || 'Unnamed Task',
        operation: taskData.operation || 'unknown',
        
        priority: taskData.priority || 'normal',
        status: 'pending',
        executionMode: taskData.executionMode || 'sequential',
        
        payload: taskData.payload,
        parameters: taskData.parameters,
        context: taskData.context,
        
        dependencies: taskData.dependencies || [],
        dependents: taskData.dependents || [],
        parentTask: taskData.parentTask,
        childTasks: taskData.childTasks || [],
        
        retryPolicy: taskData.retryPolicy || this.config.defaultRetryPolicy,
        errors: [],
        retryCount: 0,
        maxRetries: taskData.maxRetries || 3,
        
        progress: 0,
        tags: taskData.tags || [],
        metadata: taskData.metadata,
        
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.tasks.set(taskId, task);
      this.addTaskToQueue(task);

      this.emit('taskSubmitted', task);
      return taskId;

    } catch (error) {
      this.handleError({
        message: (error as Error).message,
        operation: 'submitTask',
        category: 'system'
      });
      throw error;
    }
  }

  async executeTask(task: ISECTECHTask, timeoutMs?: number): Promise<any> {
    try {
      task.status = 'running';
      task.startedAt = new Date();
      task.updatedAt = new Date();

      // Check bulkhead
      if (this.config.bulkheadEnabled) {
        await this.acquireBulkheadPermit(task.operation);
      }

      const timeout = timeoutMs || this.config.taskTimeoutMs;
      const startTime = Date.now();

      try {
        // Execute with timeout
        const result = await this.executeWithTimeout(
          () => this.performTaskOperation(task),
          timeout,
          task.context
        );

        // Success
        task.status = 'completed';
        task.completedAt = new Date();
        task.result = result;
        task.actualDuration = Date.now() - startTime;
        task.progress = 100;
        task.updatedAt = new Date();

        this.metrics.tasksExecuted++;
        this.metrics.tasksSucceeded++;
        this.updateAverageExecutionTime(task.actualDuration);

        this.emit('taskCompleted', { task, result });
        return result;

      } catch (error) {
        // Handle execution error
        const managedError = await this.handleError({
          message: (error as Error).message,
          operation: task.operation,
          requestId: task.id
        });

        task.errors.push(managedError.id);
        task.status = 'failed';
        task.updatedAt = new Date();

        this.metrics.tasksExecuted++;
        this.metrics.tasksFailed++;

        // Check if we should retry
        if (task.retryCount < task.maxRetries && this.shouldRetryTask(task, managedError)) {
          return await this.retryTask(task);
        }

        this.emit('taskFailed', { task, error: managedError });
        throw error;
      } finally {
        // Release bulkhead
        if (this.config.bulkheadEnabled) {
          this.releaseBulkheadPermit(task.operation);
        }
      }

    } catch (error) {
      this.handleError({
        message: (error as Error).message,
        operation: 'executeTask',
        category: 'system'
      });
      throw error;
    }
  }

  // Worker Pool Management
  async createWorkerPool(poolData: Partial<ISECTECHWorkerPool>): Promise<string> {
    try {
      const poolId = `POOL-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const pool: ISECTECHWorkerPool = {
        id: poolId,
        name: poolData.name || 'Unnamed Pool',
        
        minWorkers: poolData.minWorkers || 2,
        maxWorkers: poolData.maxWorkers || 10,
        currentWorkers: 0,
        
        supportedOperations: poolData.supportedOperations || [],
        queueCapacity: poolData.queueCapacity || 1000,
        currentQueueSize: 0,
        
        concurrencyLimit: poolData.concurrencyLimit || 5,
        taskTimeout: poolData.taskTimeout || 300000,
        healthCheckInterval: poolData.healthCheckInterval || 30000,
        
        loadBalancingStrategy: poolData.loadBalancingStrategy || 'round_robin',
        
        metrics: {
          tasksProcessed: 0,
          tasksSucceeded: 0,
          tasksFailed: 0,
          averageTaskDuration: 0
        },
        
        isHealthy: true,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.workerPools.set(poolId, pool);
      await this.initializeWorkerPool(pool);

      this.emit('workerPoolCreated', pool);
      return poolId;

    } catch (error) {
      this.handleError({
        message: (error as Error).message,
        operation: 'createWorkerPool',
        category: 'system'
      });
      throw error;
    }
  }

  // Circuit Breaker Implementation
  private updateCircuitBreaker(operation: string, success: boolean): void {
    let breaker = this.circuitBreakers.get(operation);
    
    if (!breaker) {
      breaker = {
        isOpen: false,
        failureCount: 0,
        lastFailureTime: 0,
        halfOpenRequests: 0,
        resetTimeout: 60000
      };
      this.circuitBreakers.set(operation, breaker);
    }

    if (success) {
      breaker.failureCount = 0;
      if (breaker.isOpen) {
        breaker.isOpen = false;
        this.emit('circuitBreakerClosed', { operation });
      }
    } else {
      breaker.failureCount++;
      breaker.lastFailureTime = Date.now();
      
      if (breaker.failureCount >= 5 && !breaker.isOpen) {
        breaker.isOpen = true;
        this.metrics.circuitBreakerTrips++;
        this.emit('circuitBreakerOpened', { operation });
        
        // Schedule reset attempt
        setTimeout(() => {
          breaker.isOpen = false;
          breaker.halfOpenRequests = 0;
          this.emit('circuitBreakerHalfOpen', { operation });
        }, breaker.resetTimeout);
      }
    }
  }

  private isCircuitBreakerOpen(operation: string): boolean {
    const breaker = this.circuitBreakers.get(operation);
    return breaker ? breaker.isOpen : false;
  }

  // Bulkhead Pattern Implementation
  private async acquireBulkheadPermit(operation: string): Promise<void> {
    const bulkhead = this.bulkheads.get(operation);
    if (!bulkhead) return;

    if (bulkhead.currentExecutions >= bulkhead.maxConcurrency) {
      // Wait for permit or timeout
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error(`Bulkhead timeout for operation: ${operation}`));
        }, bulkhead.timeoutMs);

        bulkhead.queue.push('permit');
        
        const checkForPermit = () => {
          if (bulkhead.currentExecutions < bulkhead.maxConcurrency) {
            clearTimeout(timeout);
            bulkhead.currentExecutions++;
            resolve();
          } else {
            setTimeout(checkForPermit, 100);
          }
        };
        
        checkForPermit();
      });
    } else {
      bulkhead.currentExecutions++;
    }
  }

  private releaseBulkheadPermit(operation: string): void {
    const bulkhead = this.bulkheads.get(operation);
    if (bulkhead && bulkhead.currentExecutions > 0) {
      bulkhead.currentExecutions--;
    }
  }

  // Helper Methods
  private categorizeError(error: Partial<ISECTECHError>): z.infer<typeof ErrorCategorySchema> {
    if (error.category) return error.category;
    
    const message = error.message?.toLowerCase() || '';
    
    if (message.includes('timeout') || message.includes('timed out')) return 'timeout';
    if (message.includes('rate limit') || message.includes('throttle')) return 'rate_limit';
    if (message.includes('auth') || message.includes('unauthorized')) return 'auth';
    if (message.includes('validation') || message.includes('invalid')) return 'validation';
    if (message.includes('network') || message.includes('connection')) return 'network';
    if (message.includes('temporary') || message.includes('retry')) return 'transient';
    
    return 'system';
  }

  private isErrorRetryable(error: Partial<ISECTECHError>): boolean {
    const category = this.categorizeError(error);
    const retryableCategories: z.infer<typeof ErrorCategorySchema>[] = ['transient', 'timeout', 'rate_limit', 'network'];
    return retryableCategories.includes(category);
  }

  private assessErrorSeverity(error: Partial<ISECTECHError>): 'low' | 'medium' | 'high' | 'critical' {
    if (error.severity) return error.severity;
    
    const category = this.categorizeError(error);
    
    switch (category) {
      case 'system':
      case 'permanent':
        return 'critical';
      case 'auth':
      case 'validation':
        return 'high';
      case 'timeout':
      case 'rate_limit':
        return 'medium';
      default:
        return 'low';
    }
  }

  private assessBusinessImpact(error: Partial<ISECTECHError>): 'none' | 'minimal' | 'moderate' | 'significant' | 'critical' {
    const severity = this.assessErrorSeverity(error);
    
    switch (severity) {
      case 'critical': return 'critical';
      case 'high': return 'significant';
      case 'medium': return 'moderate';
      case 'low': return 'minimal';
      default: return 'none';
    }
  }

  private getRetryPolicyForOperation(operation: string): ISECTECHRetryPolicy {
    // Find specific policy for operation or use default
    for (const policy of this.retryPolicies.values()) {
      if (policy.name.toLowerCase().includes(operation.toLowerCase())) {
        return policy;
      }
    }
    
    return this.retryPolicies.get(this.config.defaultRetryPolicy) || this.createDefaultRetryPolicy();
  }

  private shouldRetry(error: ISECTECHError, policy: ISECTECHRetryPolicy): boolean {
    if (!error.isRetryable) return false;
    if (error.retryCount >= policy.maxRetries) return false;
    if (policy.nonRetryableErrors?.includes(error.category)) return false;
    
    return policy.retryableErrors.includes(error.category);
  }

  private shouldRetryTask(task: ISECTECHTask, error: ISECTECHError): boolean {
    return error.isRetryable && task.retryCount < task.maxRetries;
  }

  private calculateRetryDelay(policy: ISECTECHRetryPolicy, attempt: number): number {
    let delay: number;
    
    switch (policy.strategy) {
      case 'exponential_backoff':
        delay = policy.baseDelay * Math.pow(policy.backoffMultiplier, attempt);
        break;
      case 'linear_backoff':
        delay = policy.baseDelay + (policy.baseDelay * attempt);
        break;
      case 'fibonacci':
        delay = this.fibonacci(attempt + 1) * policy.baseDelay;
        break;
      case 'fixed_delay':
        delay = policy.baseDelay;
        break;
      default:
        delay = policy.baseDelay * Math.pow(2, attempt);
    }
    
    // Apply jitter
    if (policy.jitterEnabled) {
      const jitter = delay * policy.jitterFactor * Math.random();
      delay += jitter;
    }
    
    // Cap at max delay
    return Math.min(delay, policy.maxDelay);
  }

  private fibonacci(n: number): number {
    if (n <= 1) return n;
    let a = 0, b = 1;
    for (let i = 2; i <= n; i++) {
      [a, b] = [b, a + b];
    }
    return b;
  }

  private async executeWithTimeout<T>(
    operation: Function,
    timeoutMs?: number,
    context?: any
  ): Promise<T> {
    if (!timeoutMs) {
      return await operation(context);
    }

    return new Promise<T>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      Promise.resolve(operation(context))
        .then(result => {
          clearTimeout(timeout);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timeout);
          reject(error);
        });
    });
  }

  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private generateCorrelationId(): string {
    return `CORR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private async attemptErrorResolution(error: ISECTECHError): Promise<void> {
    // Auto-resolution logic based on error category
    switch (error.category) {
      case 'rate_limit':
        // Could implement automatic backoff
        break;
      case 'timeout':
        // Could suggest retry with longer timeout
        break;
      case 'transient':
        // Mark as potentially auto-resolvable
        break;
    }
  }

  private async retryTask(task: ISECTECHTask): Promise<any> {
    task.retryCount++;
    task.status = 'retrying';
    task.updatedAt = new Date();

    const policy = this.retryPolicies.get(task.retryPolicy || this.config.defaultRetryPolicy);
    if (policy) {
      const delay = this.calculateRetryDelay(policy, task.retryCount - 1);
      await this.sleep(delay);
    }

    return await this.executeTask(task);
  }

  private async performTaskOperation(task: ISECTECHTask): Promise<any> {
    // This would integrate with actual SOAR operations
    // For now, simulate operation based on task type
    
    const operationMap: Record<string, Function> = {
      'case_creation': () => this.simulateCaseCreation(task),
      'playbook_execution': () => this.simulatePlaybookExecution(task),
      'integration_call': () => this.simulateIntegrationCall(task),
      'threat_analysis': () => this.simulateThreatAnalysis(task),
      'evidence_collection': () => this.simulateEvidenceCollection(task)
    };

    const operation = operationMap[task.operation];
    if (operation) {
      return await operation();
    }

    // Default simulation
    await this.sleep(Math.random() * 1000 + 500); // 500-1500ms
    return { taskId: task.id, status: 'completed', result: 'success' };
  }

  // Simulation methods for SOAR operations
  private async simulateCaseCreation(task: ISECTECHTask): Promise<any> {
    await this.sleep(2000);
    if (Math.random() < 0.1) throw new Error('Case creation failed');
    return { caseId: `CASE-${Date.now()}`, status: 'created' };
  }

  private async simulatePlaybookExecution(task: ISECTECHTask): Promise<any> {
    await this.sleep(5000);
    if (Math.random() < 0.05) throw new Error('Playbook execution failed');
    return { playbookId: task.payload?.playbookId, status: 'executed', steps: 5 };
  }

  private async simulateIntegrationCall(task: ISECTECHTask): Promise<any> {
    await this.sleep(1500);
    if (Math.random() < 0.15) throw new Error('Integration call failed');
    return { response: 'Integration successful', data: {} };
  }

  private async simulateThreatAnalysis(task: ISECTECHTask): Promise<any> {
    await this.sleep(3000);
    if (Math.random() < 0.08) throw new Error('Threat analysis failed');
    return { threatLevel: 'medium', indicators: 3 };
  }

  private async simulateEvidenceCollection(task: ISECTECHTask): Promise<any> {
    await this.sleep(1000);
    if (Math.random() < 0.12) throw new Error('Evidence collection failed');
    return { evidenceId: `EVIDENCE-${Date.now()}`, size: '2.5MB' };
  }

  // Queue Management
  private addTaskToQueue(task: ISECTECHTask): void {
    // Add to priority queue based on task priority
    this.priorityQueue.push(task);
    this.priorityQueue.sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, normal: 2, low: 3, background: 4 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
  }

  private getNextTask(): ISECTECHTask | null {
    return this.priorityQueue.shift() || null;
  }

  // Initialization Methods
  private initializeDefaultRetryPolicies(): void {
    const defaultPolicies: Partial<ISECTECHRetryPolicy>[] = [
      {
        id: 'default',
        name: 'Default Retry Policy',
        strategy: 'exponential_backoff',
        maxRetries: 3,
        baseDelay: 1000,
        maxDelay: 30000,
        retryableErrors: ['transient', 'timeout', 'rate_limit', 'network'],
        circuitBreakerEnabled: true
      },
      {
        id: 'integration_calls',
        name: 'Integration API Calls',
        strategy: 'exponential_backoff',
        maxRetries: 5,
        baseDelay: 2000,
        maxDelay: 60000,
        retryableErrors: ['transient', 'timeout', 'rate_limit', 'network'],
        circuitBreakerEnabled: true,
        failureThreshold: 10
      },
      {
        id: 'critical_operations',
        name: 'Critical Operations',
        strategy: 'fibonacci',
        maxRetries: 7,
        baseDelay: 500,
        maxDelay: 120000,
        retryableErrors: ['transient', 'timeout', 'network'],
        circuitBreakerEnabled: false
      }
    ];

    defaultPolicies.forEach(policy => {
      const fullPolicy: ISECTECHRetryPolicy = {
        id: policy.id!,
        name: policy.name!,
        strategy: policy.strategy!,
        maxRetries: policy.maxRetries!,
        baseDelay: policy.baseDelay!,
        maxDelay: policy.maxDelay!,
        backoffMultiplier: 2,
        jitterEnabled: true,
        jitterFactor: 0.1,
        retryableErrors: policy.retryableErrors!,
        circuitBreakerEnabled: policy.circuitBreakerEnabled !== false,
        failureThreshold: policy.failureThreshold || 5,
        resetTimeout: 60000,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date()
      };
      
      this.retryPolicies.set(fullPolicy.id, fullPolicy);
    });
  }

  private initializeDefaultWorkerPools(): void {
    const defaultPools = [
      {
        name: 'General Purpose Pool',
        supportedOperations: ['case_creation', 'evidence_collection'],
        minWorkers: 2,
        maxWorkers: 8
      },
      {
        name: 'Integration Pool',
        supportedOperations: ['integration_call'],
        minWorkers: 3,
        maxWorkers: 15
      },
      {
        name: 'Analysis Pool',
        supportedOperations: ['threat_analysis', 'playbook_execution'],
        minWorkers: 1,
        maxWorkers: 5
      }
    ];

    defaultPools.forEach(async pool => {
      await this.createWorkerPool(pool);
    });
  }

  private initializeDefaultBulkheads(): void {
    const operations = ['case_creation', 'playbook_execution', 'integration_call', 'threat_analysis'];
    
    operations.forEach(operation => {
      this.bulkheads.set(operation, {
        operation,
        maxConcurrency: 10,
        currentExecutions: 0,
        queue: [],
        timeoutMs: 30000
      });
    });
  }

  private async initializeWorkerPool(pool: ISECTECHWorkerPool): Promise<void> {
    // Initialize minimum workers
    for (let i = 0; i < pool.minWorkers; i++) {
      await this.createWorker(pool);
    }
  }

  private async createWorker(pool: ISECTECHWorkerPool): Promise<void> {
    const workerId = `WORKER-${pool.id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const worker = {
      id: workerId,
      poolId: pool.id,
      isActive: true,
      currentTask: null,
      tasksProcessed: 0,
      createdAt: new Date()
    };

    this.workers.set(workerId, worker);
    pool.currentWorkers++;
  }

  private createDefaultRetryPolicy(): ISECTECHRetryPolicy {
    return {
      id: 'fallback',
      name: 'Fallback Policy',
      strategy: 'exponential_backoff',
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000,
      backoffMultiplier: 2,
      jitterEnabled: true,
      jitterFactor: 0.1,
      retryableErrors: ['transient', 'timeout'],
      circuitBreakerEnabled: true,
      failureThreshold: 5,
      resetTimeout: 60000,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }

  // Engine Management
  private startExecutionEngine(): void {
    this.executionTimer = setInterval(async () => {
      if (!this.isProcessing) {
        this.isProcessing = true;
        await this.processTaskQueue();
        this.isProcessing = false;
      }
    }, 1000); // Check every second
  }

  private async processTaskQueue(): Promise<void> {
    const task = this.getNextTask();
    if (task && this.canExecuteTask(task)) {
      try {
        await this.executeTask(task);
      } catch (error) {
        // Error already handled in executeTask
      }
    }
  }

  private canExecuteTask(task: ISECTECHTask): boolean {
    // Check dependencies
    if (task.dependencies.length > 0) {
      for (const depId of task.dependencies) {
        const dep = this.tasks.get(depId);
        if (!dep || dep.status !== 'completed') {
          return false;
        }
      }
    }

    // Check bulkhead capacity
    if (this.config.bulkheadEnabled) {
      const bulkhead = this.bulkheads.get(task.operation);
      if (bulkhead && bulkhead.currentExecutions >= bulkhead.maxConcurrency) {
        return false;
      }
    }

    return true;
  }

  private startHealthMonitoring(): void {
    setInterval(() => {
      this.performHealthChecks();
    }, this.config.workerHealthCheckInterval);
  }

  private async performHealthChecks(): Promise<void> {
    for (const pool of this.workerPools.values()) {
      await this.checkWorkerPoolHealth(pool);
    }
  }

  private async checkWorkerPoolHealth(pool: ISECTECHWorkerPool): Promise<void> {
    // Simple health check - in production would be more sophisticated
    const isHealthy = pool.currentWorkers >= pool.minWorkers;
    
    if (pool.isHealthy !== isHealthy) {
      pool.isHealthy = isHealthy;
      pool.updatedAt = new Date();
      
      this.emit('workerPoolHealthChanged', { pool, isHealthy });
    }
  }

  private updateAverageExecutionTime(duration: number): void {
    const currentAvg = this.metrics.averageExecutionTime;
    const totalTasks = this.metrics.tasksExecuted;
    
    this.metrics.averageExecutionTime = (currentAvg * (totalTasks - 1) + duration) / totalTasks;
  }

  // Public API methods
  getSystemHealth(): any {
    return {
      isHealthy: this.circuitBreakers.size === 0 || Array.from(this.circuitBreakers.values()).every(cb => !cb.isOpen),
      metrics: this.metrics,
      circuitBreakers: Object.fromEntries(this.circuitBreakers.entries()),
      workerPools: Array.from(this.workerPools.values()).map(pool => ({
        id: pool.id,
        name: pool.name,
        isHealthy: pool.isHealthy,
        currentWorkers: pool.currentWorkers,
        queueSize: pool.currentQueueSize
      })),
      taskQueue: {
        pending: this.priorityQueue.length,
        processing: Array.from(this.tasks.values()).filter(t => t.status === 'running').length
      }
    };
  }

  getMetrics(): any {
    return {
      ...this.metrics,
      uptime: Date.now() - this.metrics.startTime.getTime(),
      errorRate: this.metrics.errorsHandled / Math.max(this.metrics.tasksExecuted, 1),
      successRate: this.metrics.tasksSucceeded / Math.max(this.metrics.tasksExecuted, 1)
    };
  }

  // Cleanup
  shutdown(): void {
    if (this.executionTimer) {
      clearInterval(this.executionTimer);
    }
    
    for (const timer of this.workerHealthTimers.values()) {
      clearTimeout(timer);
    }
    
    this.emit('shutdown');
  }
}