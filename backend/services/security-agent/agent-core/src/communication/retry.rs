// iSECTECH Security Agent - Retry Management
// Production-grade retry logic with exponential backoff
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;
use tracing::{debug, warn, error};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};

/// Retry manager for handling failed operations with intelligent backoff
pub struct RetryManager {
    /// Agent configuration
    config: AgentConfig,
    /// Active retry operations
    active_retries: Arc<RwLock<HashMap<Uuid, RetryOperation>>>,
    /// Retry statistics
    stats: Arc<RwLock<RetryStatistics>>,
    /// Configuration for different operation types
    retry_configs: HashMap<OperationType, RetryConfig>,
}

/// Retry operation tracking
#[derive(Debug, Clone)]
pub struct RetryOperation {
    /// Operation identifier
    pub operation_id: Uuid,
    /// Type of operation being retried
    pub operation_type: OperationType,
    /// Current attempt number
    pub attempt: u32,
    /// Maximum attempts allowed
    pub max_attempts: u32,
    /// Time when operation was first attempted
    pub started_at: Instant,
    /// Time for next retry attempt
    pub next_retry_at: Instant,
    /// Last error encountered
    pub last_error: Option<String>,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    /// Current backoff delay
    pub current_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Jitter to prevent thundering herd
    pub jitter_percent: f64,
    /// Operation context data
    pub context: HashMap<String, String>,
}

/// Types of operations that can be retried
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// HTTP/HTTPS communication with backend
    NetworkCommunication,
    /// Certificate operations (renewal, validation)
    CertificateOperation,
    /// File system operations
    FileSystemOperation,
    /// Database/storage operations
    StorageOperation,
    /// Message processing operations
    MessageProcessing,
    /// Agent enrollment operations
    AgentEnrollment,
    /// Policy updates
    PolicyUpdate,
    /// Emergency communications
    EmergencyAlert,
}

/// Retry configuration for different operation types
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    /// Jitter percentage (0.0 to 1.0)
    pub jitter_percent: f64,
    /// Whether to retry on this error type
    pub retry_on_error: fn(&AgentError) -> bool,
}

/// Retry attempt result
#[derive(Debug, Clone)]
pub enum RetryResult<T> {
    /// Operation succeeded
    Success(T),
    /// Operation failed, should retry
    Retry(String),
    /// Operation failed permanently, do not retry
    Failed(String),
}

/// Retry statistics and metrics
#[derive(Debug, Clone, Default)]
pub struct RetryStatistics {
    /// Total retry operations started
    pub total_started: u64,
    /// Total operations that succeeded after retry
    pub total_succeeded: u64,
    /// Total operations that failed permanently
    pub total_failed: u64,
    /// Operations currently being retried
    pub currently_retrying: u64,
    /// Average attempts before success
    pub average_attempts: f64,
    /// Statistics by operation type
    pub by_type: HashMap<OperationType, TypeStatistics>,
}

/// Statistics for specific operation types
#[derive(Debug, Clone, Default)]
pub struct TypeStatistics {
    pub started: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub average_attempts: f64,
    pub total_delay: Duration,
}

impl RetryManager {
    /// Create a new retry manager
    pub async fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Initializing retry manager");
        
        let retry_configs = Self::create_default_retry_configs();
        
        let manager = Self {
            config: config.clone(),
            active_retries: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RetryStatistics::default())),
            retry_configs,
        };
        
        // Start background cleanup task
        manager.start_cleanup_task().await;
        
        debug!("Retry manager initialized successfully");
        Ok(manager)
    }
    
    /// Start a retry operation
    pub async fn start_retry_operation(
        &self,
        operation_type: OperationType,
        context: HashMap<String, String>,
    ) -> Result<Uuid> {
        let operation_id = Uuid::new_v4();
        
        debug!("Starting retry operation {} for {:?}", operation_id, operation_type);
        
        let config = self.retry_configs.get(&operation_type)
            .ok_or_else(|| AgentError::Configuration(format!("No retry config for {:?}", operation_type)))?;
        
        let retry_operation = RetryOperation {
            operation_id,
            operation_type,
            attempt: 0,
            max_attempts: config.max_attempts,
            started_at: Instant::now(),
            next_retry_at: Instant::now(),
            last_error: None,
            backoff_multiplier: config.backoff_multiplier,
            current_delay: config.initial_delay,
            max_delay: config.max_delay,
            jitter_percent: config.jitter_percent,
            context,
        };
        
        // Store the retry operation
        self.active_retries.write().await.insert(operation_id, retry_operation);
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_started += 1;
        stats.currently_retrying += 1;
        
        let type_stats = stats.by_type.entry(operation_type).or_default();
        type_stats.started += 1;
        
        debug!("Retry operation {} started", operation_id);
        Ok(operation_id)
    }
    
    /// Record a retry attempt result
    pub async fn record_attempt<T>(
        &self,
        operation_id: &Uuid,
        result: RetryResult<T>,
    ) -> Result<Option<T>> {
        let mut active_retries = self.active_retries.write().await;
        let mut stats = self.stats.write().await;
        
        let retry_op = active_retries.get_mut(operation_id)
            .ok_or_else(|| AgentError::Internal(format!("Retry operation {} not found", operation_id)))?;
        
        retry_op.attempt += 1;
        
        match result {
            RetryResult::Success(value) => {
                debug!("Retry operation {} succeeded after {} attempts", operation_id, retry_op.attempt);
                
                // Update statistics
                stats.total_succeeded += 1;
                stats.currently_retrying -= 1;
                
                let type_stats = stats.by_type.entry(retry_op.operation_type).or_default();
                type_stats.succeeded += 1;
                self.update_average_attempts(&mut stats, retry_op.operation_type, retry_op.attempt);
                
                // Remove from active retries
                active_retries.remove(operation_id);
                
                Ok(Some(value))
            }
            
            RetryResult::Retry(error_message) => {
                debug!("Retry operation {} failed (attempt {}): {}", 
                       operation_id, retry_op.attempt, error_message);
                
                retry_op.last_error = Some(error_message);
                
                // Check if we should continue retrying
                if retry_op.attempt >= retry_op.max_attempts {
                    warn!("Retry operation {} exhausted all {} attempts", 
                          operation_id, retry_op.max_attempts);
                    
                    // Update statistics
                    stats.total_failed += 1;
                    stats.currently_retrying -= 1;
                    
                    let type_stats = stats.by_type.entry(retry_op.operation_type).or_default();
                    type_stats.failed += 1;
                    
                    // Remove from active retries
                    active_retries.remove(operation_id);
                    
                    return Err(AgentError::Internal(format!(
                        "Retry operation {} failed permanently after {} attempts", 
                        operation_id, retry_op.max_attempts
                    )));
                }
                
                // Calculate next retry delay with exponential backoff and jitter
                let base_delay = Duration::from_millis(
                    (retry_op.current_delay.as_millis() as f64 * retry_op.backoff_multiplier) as u64
                );
                
                let jitter_range = (base_delay.as_millis() as f64 * retry_op.jitter_percent) as u64;
                let jitter = if jitter_range > 0 {
                    Duration::from_millis(rand::random::<u64>() % jitter_range)
                } else {
                    Duration::ZERO
                };
                
                retry_op.current_delay = std::cmp::min(base_delay + jitter, retry_op.max_delay);
                retry_op.next_retry_at = Instant::now() + retry_op.current_delay;
                
                debug!("Scheduling retry operation {} in {:?}", operation_id, retry_op.current_delay);
                
                Ok(None)
            }
            
            RetryResult::Failed(error_message) => {
                warn!("Retry operation {} failed permanently: {}", operation_id, error_message);
                
                retry_op.last_error = Some(error_message.clone());
                
                // Update statistics
                stats.total_failed += 1;
                stats.currently_retrying -= 1;
                
                let type_stats = stats.by_type.entry(retry_op.operation_type).or_default();
                type_stats.failed += 1;
                
                // Remove from active retries
                active_retries.remove(operation_id);
                
                Err(AgentError::Internal(format!("Operation failed permanently: {}", error_message)))
            }
        }
    }
    
    /// Check if a retry operation is ready for the next attempt
    pub async fn is_ready_for_retry(&self, operation_id: &Uuid) -> Result<bool> {
        let active_retries = self.active_retries.read().await;
        
        match active_retries.get(operation_id) {
            Some(retry_op) => Ok(Instant::now() >= retry_op.next_retry_at),
            None => Err(AgentError::Internal(format!("Retry operation {} not found", operation_id))),
        }
    }
    
    /// Get retry operation status
    pub async fn get_operation_status(&self, operation_id: &Uuid) -> Result<RetryOperation> {
        let active_retries = self.active_retries.read().await;
        
        active_retries.get(operation_id)
            .cloned()
            .ok_or_else(|| AgentError::Internal(format!("Retry operation {} not found", operation_id)))
    }
    
    /// Cancel a retry operation
    pub async fn cancel_operation(&self, operation_id: &Uuid) -> Result<()> {
        debug!("Cancelling retry operation {}", operation_id);
        
        let mut active_retries = self.active_retries.write().await;
        let mut stats = self.stats.write().await;
        
        if active_retries.remove(operation_id).is_some() {
            stats.currently_retrying -= 1;
            debug!("Retry operation {} cancelled", operation_id);
        } else {
            warn!("Retry operation {} not found for cancellation", operation_id);
        }
        
        Ok(())
    }
    
    /// Get retry statistics
    pub async fn get_statistics(&self) -> RetryStatistics {
        self.stats.read().await.clone()
    }
    
    /// Execute a retryable operation with automatic retry handling
    pub async fn execute_with_retry<T, F, Fut>(
        &self,
        operation_type: OperationType,
        context: HashMap<String, String>,
        operation: F,
    ) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        let operation_id = self.start_retry_operation(operation_type, context).await?;
        
        loop {
            // Wait for retry delay if needed
            if !self.is_ready_for_retry(&operation_id).await? {
                let retry_op = self.get_operation_status(&operation_id).await?;
                let delay = retry_op.next_retry_at.saturating_duration_since(Instant::now());
                if delay > Duration::ZERO {
                    tokio::time::sleep(delay).await;
                }
            }
            
            // Execute the operation
            match operation().await {
                Ok(result) => {
                    // Operation succeeded
                    if let Some(value) = self.record_attempt(&operation_id, RetryResult::Success(result)).await? {
                        return Ok(value);
                    }
                }
                Err(error) => {
                    // Check if this error should be retried
                    let config = self.retry_configs.get(&operation_type).unwrap();
                    let should_retry = (config.retry_on_error)(&error);
                    
                    if should_retry {
                        // Record retry attempt
                        if self.record_attempt(&operation_id, RetryResult::Retry(error.to_string())).await.is_err() {
                            // Max retries exhausted
                            return Err(error);
                        }
                        // Continue to next iteration for retry
                    } else {
                        // Permanent failure
                        let _ = self.record_attempt(&operation_id, RetryResult::Failed(error.to_string())).await;
                        return Err(error);
                    }
                }
            }
        }
    }
    
    // Private implementation methods
    
    fn create_default_retry_configs() -> HashMap<OperationType, RetryConfig> {
        let mut configs = HashMap::new();
        
        // Network communication - aggressive retries for connectivity issues
        configs.insert(OperationType::NetworkCommunication, RetryConfig {
            max_attempts: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter_percent: 0.25,
            retry_on_error: |error| matches!(error, 
                AgentError::Network(_) | 
                AgentError::Timeout(_)
            ),
        });
        
        // Certificate operations - moderate retries for infrastructure issues
        configs.insert(OperationType::CertificateOperation, RetryConfig {
            max_attempts: 3,
            initial_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(120),
            backoff_multiplier: 2.5,
            jitter_percent: 0.3,
            retry_on_error: |error| matches!(error, 
                AgentError::Network(_) | 
                AgentError::Cryptography(_) |
                AgentError::Timeout(_)
            ),
        });
        
        // File system operations - quick retries for temporary issues
        configs.insert(OperationType::FileSystemOperation, RetryConfig {
            max_attempts: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter_percent: 0.1,
            retry_on_error: |error| matches!(error, 
                AgentError::Io(_) |
                AgentError::Storage(_)
            ),
        });
        
        // Storage operations - moderate retries for database issues
        configs.insert(OperationType::StorageOperation, RetryConfig {
            max_attempts: 4,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_percent: 0.2,
            retry_on_error: |error| matches!(error, 
                AgentError::Storage(_) |
                AgentError::Io(_)
            ),
        });
        
        // Message processing - quick retries for serialization issues
        configs.insert(OperationType::MessageProcessing, RetryConfig {
            max_attempts: 2,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 3.0,
            jitter_percent: 0.1,
            retry_on_error: |error| matches!(error, 
                AgentError::Serialization(_) |
                AgentError::Validation(_)
            ),
        });
        
        // Agent enrollment - persistent retries for critical operation
        configs.insert(OperationType::AgentEnrollment, RetryConfig {
            max_attempts: 10,
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(300),
            backoff_multiplier: 1.5,
            jitter_percent: 0.3,
            retry_on_error: |error| matches!(error, 
                AgentError::Network(_) | 
                AgentError::Timeout(_) |
                AgentError::Authentication(_)
            ),
        });
        
        // Policy updates - moderate retries for important operations
        configs.insert(OperationType::PolicyUpdate, RetryConfig {
            max_attempts: 5,
            initial_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter_percent: 0.25,
            retry_on_error: |error| matches!(error, 
                AgentError::Network(_) | 
                AgentError::Timeout(_) |
                AgentError::Serialization(_)
            ),
        });
        
        // Emergency alerts - immediate and persistent retries
        configs.insert(OperationType::EmergencyAlert, RetryConfig {
            max_attempts: 15,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 1.8,
            jitter_percent: 0.1,
            retry_on_error: |error| matches!(error, 
                AgentError::Network(_) | 
                AgentError::Timeout(_) |
                AgentError::Serialization(_) |
                AgentError::Storage(_)
            ),
        });
        
        configs
    }
    
    fn update_average_attempts(
        &self,
        stats: &mut RetryStatistics,
        operation_type: OperationType,
        attempts: u32,
    ) {
        let type_stats = stats.by_type.entry(operation_type).or_default();
        
        if type_stats.succeeded > 0 {
            type_stats.average_attempts = 
                (type_stats.average_attempts * (type_stats.succeeded as f64 - 1.0) + attempts as f64) 
                / type_stats.succeeded as f64;
        } else {
            type_stats.average_attempts = attempts as f64;
        }
        
        // Update global average
        if stats.total_succeeded > 0 {
            stats.average_attempts = 
                (stats.average_attempts * (stats.total_succeeded as f64 - 1.0) + attempts as f64) 
                / stats.total_succeeded as f64;
        } else {
            stats.average_attempts = attempts as f64;
        }
    }
    
    async fn start_cleanup_task(&self) {
        let active_retries = Arc::clone(&self.active_retries);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            
            loop {
                interval.tick().await;
                
                // Clean up stale retry operations (older than 1 hour)
                let cutoff_time = Instant::now() - Duration::from_secs(3600);
                let mut cleanup_count = 0;
                
                {
                    let mut retries = active_retries.write().await;
                    let initial_count = retries.len();
                    
                    retries.retain(|_, retry_op| {
                        if retry_op.started_at < cutoff_time {
                            cleanup_count += 1;
                            false
                        } else {
                            true
                        }
                    });
                    
                    if cleanup_count > 0 {
                        let mut stats_guard = stats.write().await;
                        stats_guard.currently_retrying = retries.len() as u64;
                        
                        debug!("Cleaned up {} stale retry operations", cleanup_count);
                    }
                }
            }
        });
    }
}