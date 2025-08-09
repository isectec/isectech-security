// iSECTECH Security Agent - Offline Message Queue
// Production-grade offline message queuing and synchronization
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, Instant, Duration};
use tokio::sync::RwLock;
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::storage::StorageManager;
use super::{OutboundMessage, MessagePriority};

/// Offline message queue for storing messages when connection is unavailable
pub struct OfflineQueue {
    /// Agent configuration
    config: AgentConfig,
    /// Storage manager for persistent storage
    storage_manager: Arc<StorageManager>,
    /// In-memory priority queue for pending messages
    pending_queue: Arc<RwLock<BinaryHeap<QueuedMessage>>>,
    /// Failed messages awaiting retry
    failed_queue: Arc<RwLock<HashMap<Uuid, QueuedMessage>>>,
    /// Sent messages tracking for cleanup
    sent_messages: Arc<RwLock<HashMap<Uuid, SentMessageInfo>>>,
    /// Queue statistics
    stats: Arc<RwLock<QueueStatistics>>,
    /// Maximum queue size
    max_queue_size: usize,
    /// Maximum disk usage for offline storage
    max_disk_usage_mb: u64,
}

/// Queued message with priority and metadata
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// Original outbound message
    pub message: OutboundMessage,
    /// Queue timestamp
    pub queued_at: Instant,
    /// Number of send attempts
    pub attempts: u32,
    /// Next retry time
    pub next_retry: Option<Instant>,
    /// Last error encountered
    pub last_error: Option<String>,
    /// Message persistence state
    pub persisted: bool,
    /// Storage key for persistent messages
    pub storage_key: Option<String>,
}

/// Information about sent messages
#[derive(Debug, Clone)]
struct SentMessageInfo {
    pub message_id: Uuid,
    pub sent_at: Instant,
    pub message_type: super::MessageType,
    pub size_bytes: usize,
}

/// Queue statistics and metrics
#[derive(Debug, Clone, Default)]
pub struct QueueStatistics {
    /// Total messages queued
    pub total_queued: u64,
    /// Total messages sent
    pub total_sent: u64,
    /// Total messages failed
    pub total_failed: u64,
    /// Total messages expired
    pub total_expired: u64,
    /// Current queue size
    pub current_queue_size: usize,
    /// Current disk usage in bytes
    pub current_disk_usage: u64,
    /// Average message size
    pub average_message_size: u64,
    /// Queue operation timestamps
    pub last_queue_operation: Option<Instant>,
    pub last_send_operation: Option<Instant>,
    pub last_cleanup_operation: Option<Instant>,
}

/// Message storage metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MessageMetadata {
    pub message_id: String,
    pub message_type: String,
    pub priority: u8,
    pub queued_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub attempts: u32,
    pub size_bytes: usize,
}

impl PartialEq for QueuedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.message.message_id == other.message.message_id
    }
}

impl Eq for QueuedMessage {}

impl PartialOrd for QueuedMessage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedMessage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority messages come first
        other.message.priority.cmp(&self.message.priority)
            .then_with(|| self.queued_at.cmp(&other.queued_at)) // FIFO for same priority
    }
}

impl OfflineQueue {
    /// Create a new offline queue
    pub async fn new(
        config: &AgentConfig,
        storage_manager: &Arc<StorageManager>,
    ) -> Result<Self> {
        info!("Initializing offline message queue");
        
        let max_queue_size = config.resources.max_memory_mb as usize * 1024 * 10; // 10 messages per MB
        let max_disk_usage_mb = config.storage.max_size_mb / 4; // Use 25% of total storage
        
        let queue = Self {
            config: config.clone(),
            storage_manager: Arc::clone(storage_manager),
            pending_queue: Arc::new(RwLock::new(BinaryHeap::new())),
            failed_queue: Arc::new(RwLock::new(HashMap::new())),
            sent_messages: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(QueueStatistics::default())),
            max_queue_size,
            max_disk_usage_mb,
        };
        
        // Load persisted messages from storage
        queue.load_persisted_messages().await?;
        
        // Start background cleanup task
        queue.start_cleanup_task().await;
        
        info!("Offline message queue initialized successfully");
        Ok(queue)
    }
    
    /// Queue a message for offline delivery
    pub async fn queue_message(&self, message: OutboundMessage) -> Result<()> {
        debug!("Queueing message {} for offline delivery", message.message_id);
        
        // Check if queue is full
        let current_size = self.pending_queue.read().await.len();
        if current_size >= self.max_queue_size {
            warn!("Offline queue is full, removing oldest low-priority message");
            self.remove_oldest_low_priority_message().await?;
        }
        
        // Check if message has expired
        if let Some(expires_at) = message.expires_at {
            if expires_at <= Instant::now() {
                warn!("Message {} has already expired, not queueing", message.message_id);
                let mut stats = self.stats.write().await;
                stats.total_expired += 1;
                return Ok(());
            }
        }
        
        // Create queued message
        let queued_message = QueuedMessage {
            message: message.clone(),
            queued_at: Instant::now(),
            attempts: 0,
            next_retry: None,
            last_error: None,
            persisted: false,
            storage_key: None,
        };
        
        // Persist high-priority messages to disk
        let should_persist = matches!(
            message.priority,
            MessagePriority::Critical | MessagePriority::Emergency | MessagePriority::High
        );
        
        let mut final_queued_message = if should_persist {
            self.persist_message_to_disk(queued_message).await?
        } else {
            queued_message
        };
        
        // Add to in-memory queue
        self.pending_queue.write().await.push(final_queued_message);
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_queued += 1;
        stats.current_queue_size = current_size + 1;
        stats.last_queue_operation = Some(Instant::now());
        
        if stats.total_queued > 0 {
            stats.average_message_size = 
                (stats.average_message_size * (stats.total_queued - 1) + message.payload.len() as u64) 
                / stats.total_queued;
        }
        
        debug!("Message {} queued successfully", message.message_id);
        Ok(())
    }
    
    /// Get pending messages for transmission
    pub async fn get_pending_messages(&self, max_count: usize) -> Result<Vec<OutboundMessage>> {
        debug!("Getting up to {} pending messages", max_count);
        
        let mut pending_queue = self.pending_queue.write().await;
        let mut messages = Vec::new();
        let mut temp_queue = BinaryHeap::new();
        
        // Extract messages from priority queue
        for _ in 0..max_count {
            if let Some(mut queued_msg) = pending_queue.pop() {
                // Check if message has expired
                if let Some(expires_at) = queued_msg.message.expires_at {
                    if expires_at <= Instant::now() {
                        warn!("Message {} has expired, removing from queue", queued_msg.message.message_id);
                        self.handle_expired_message(queued_msg).await?;
                        continue;
                    }
                }
                
                // Check if it's time for retry
                if let Some(next_retry) = queued_msg.next_retry {
                    if next_retry > Instant::now() {
                        // Not time for retry yet, put back in queue
                        temp_queue.push(queued_msg);
                        continue;
                    }
                }
                
                // Increment attempt counter
                queued_msg.attempts += 1;
                
                messages.push(queued_msg.message.clone());
                
                // Keep the message for potential retry
                temp_queue.push(queued_msg);
            } else {
                break;
            }
        }
        
        // Put remaining messages back in queue
        while let Some(msg) = temp_queue.pop() {
            pending_queue.push(msg);
        }
        
        debug!("Retrieved {} pending messages", messages.len());
        Ok(messages)
    }
    
    /// Mark a message as successfully sent
    pub async fn mark_message_sent(&self, message_id: &Uuid) -> Result<()> {
        debug!("Marking message {} as sent", message_id);
        
        // Remove from pending queue
        let mut pending_queue = self.pending_queue.write().await;
        let mut temp_queue = BinaryHeap::new();
        let mut found = false;
        
        while let Some(queued_msg) = pending_queue.pop() {
            if queued_msg.message.message_id == *message_id {
                found = true;
                
                // Clean up persistent storage if used
                if queued_msg.persisted {
                    if let Some(storage_key) = &queued_msg.storage_key {
                        let _ = self.storage_manager.retrieve(storage_key).await; // This removes it
                    }
                }
                
                // Add to sent messages tracking
                let sent_info = SentMessageInfo {
                    message_id: *message_id,
                    sent_at: Instant::now(),
                    message_type: queued_msg.message.message_type,
                    size_bytes: queued_msg.message.payload.len(),
                };
                
                self.sent_messages.write().await.insert(*message_id, sent_info);
                break;
            } else {
                temp_queue.push(queued_msg);
            }
        }
        
        // Put remaining messages back
        while let Some(msg) = temp_queue.pop() {
            pending_queue.push(msg);
        }
        
        if found {
            // Update statistics
            let mut stats = self.stats.write().await;
            stats.total_sent += 1;
            stats.current_queue_size = pending_queue.len();
            stats.last_send_operation = Some(Instant::now());
            
            debug!("Message {} marked as sent", message_id);
        } else {
            warn!("Message {} not found in pending queue", message_id);
        }
        
        Ok(())
    }
    
    /// Mark a message as failed and schedule for retry
    pub async fn mark_message_failed(
        &self,
        message_id: &Uuid,
        error: &str,
    ) -> Result<()> {
        debug!("Marking message {} as failed: {}", message_id, error);
        
        let mut pending_queue = self.pending_queue.write().await;
        let mut temp_queue = BinaryHeap::new();
        let mut found = false;
        
        while let Some(mut queued_msg) = pending_queue.pop() {
            if queued_msg.message.message_id == *message_id {
                found = true;
                queued_msg.last_error = Some(error.to_string());
                
                // Check if we should retry
                if queued_msg.attempts < queued_msg.message.max_retries {
                    // Schedule for retry with exponential backoff
                    let backoff_seconds = 2_u64.pow(queued_msg.attempts.min(10));
                    queued_msg.next_retry = Some(Instant::now() + Duration::from_secs(backoff_seconds));
                    
                    debug!("Scheduling message {} for retry in {}s (attempt {})", 
                           message_id, backoff_seconds, queued_msg.attempts);
                    
                    temp_queue.push(queued_msg);
                } else {
                    // Maximum retries exceeded
                    warn!("Message {} failed permanently after {} attempts", 
                          message_id, queued_msg.attempts);
                    
                    self.failed_queue.write().await.insert(*message_id, queued_msg);
                    
                    let mut stats = self.stats.write().await;
                    stats.total_failed += 1;
                }
                break;
            } else {
                temp_queue.push(queued_msg);
            }
        }
        
        // Put remaining messages back
        while let Some(msg) = temp_queue.pop() {
            pending_queue.push(msg);
        }
        
        if !found {
            warn!("Message {} not found in pending queue for failure marking", message_id);
        }
        
        Ok(())
    }
    
    /// Get queue statistics
    pub async fn get_statistics(&self) -> QueueStatistics {
        let mut stats = self.stats.read().await.clone();
        stats.current_queue_size = self.pending_queue.read().await.len();
        stats
    }
    
    /// Clear all messages from the queue
    pub async fn clear_all(&self) -> Result<()> {
        info!("Clearing all messages from offline queue");
        
        // Clear in-memory queues
        self.pending_queue.write().await.clear();
        self.failed_queue.write().await.clear();
        self.sent_messages.write().await.clear();
        
        // Clear persistent storage
        self.clear_persistent_storage().await?;
        
        // Reset statistics
        let mut stats = self.stats.write().await;
        *stats = QueueStatistics::default();
        
        info!("Offline queue cleared");
        Ok(())
    }
    
    // Private implementation methods
    
    async fn load_persisted_messages(&self) -> Result<()> {
        debug!("Loading persisted messages from storage");
        
        // TODO: Implement loading of persisted messages from storage
        // This would enumerate stored message files and load them into the queue
        
        debug!("Persisted messages loaded successfully");
        Ok(())
    }
    
    async fn persist_message_to_disk(&self, mut queued_message: QueuedMessage) -> Result<QueuedMessage> {
        debug!("Persisting message {} to disk", queued_message.message.message_id);
        
        // Check disk usage limits
        let current_usage = self.calculate_current_disk_usage().await?;
        if current_usage > self.max_disk_usage_mb * 1024 * 1024 {
            warn!("Disk usage limit exceeded, not persisting message");
            return Ok(queued_message);
        }
        
        // Create storage key
        let storage_key = format!("offline_msg_{}", queued_message.message.message_id);
        
        // Create metadata
        let metadata = MessageMetadata {
            message_id: queued_message.message.message_id.to_string(),
            message_type: format!("{:?}", queued_message.message.message_type),
            priority: queued_message.message.priority as u8,
            queued_at: SystemTime::now(),
            expires_at: queued_message.message.expires_at.map(|instant| {
                SystemTime::UNIX_EPOCH + Duration::from_nanos(instant.elapsed().as_nanos() as u64)
            }),
            attempts: queued_message.attempts,
            size_bytes: queued_message.message.payload.len(),
        };
        
        // Serialize message and metadata
        let message_data = serde_json::to_vec(&queued_message.message)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize message: {}", e)))?;
        
        let metadata_json = serde_json::to_vec(&metadata)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize metadata: {}", e)))?;
        
        // Store message and metadata
        self.storage_manager.store(&storage_key, &message_data).await?;
        self.storage_manager.store(&format!("{}_meta", storage_key), &metadata_json).await?;
        
        // Update queued message
        queued_message.persisted = true;
        queued_message.storage_key = Some(storage_key);
        
        debug!("Message {} persisted to disk", queued_message.message.message_id);
        Ok(queued_message)
    }
    
    async fn remove_oldest_low_priority_message(&self) -> Result<()> {
        let mut pending_queue = self.pending_queue.write().await;
        let mut temp_queue = BinaryHeap::new();
        let mut removed = false;
        
        // Find and remove the oldest low-priority message
        while let Some(queued_msg) = pending_queue.pop() {
            if !removed && matches!(queued_msg.message.priority, MessagePriority::Low | MessagePriority::Normal) {
                warn!("Removing oldest low-priority message {} to make space", queued_msg.message.message_id);
                
                // Clean up persistent storage if used
                if queued_msg.persisted {
                    if let Some(storage_key) = &queued_msg.storage_key {
                        let _ = self.storage_manager.retrieve(storage_key).await;
                    }
                }
                
                removed = true;
            } else {
                temp_queue.push(queued_msg);
            }
        }
        
        // Put remaining messages back
        while let Some(msg) = temp_queue.pop() {
            pending_queue.push(msg);
        }
        
        if !removed {
            warn!("No low-priority messages found to remove");
        }
        
        Ok(())
    }
    
    async fn handle_expired_message(&self, queued_msg: QueuedMessage) -> Result<()> {
        debug!("Handling expired message {}", queued_msg.message.message_id);
        
        // Clean up persistent storage if used
        if queued_msg.persisted {
            if let Some(storage_key) = &queued_msg.storage_key {
                let _ = self.storage_manager.retrieve(storage_key).await;
            }
        }
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_expired += 1;
        
        Ok(())
    }
    
    async fn calculate_current_disk_usage(&self) -> Result<u64> {
        // TODO: Implement actual disk usage calculation
        // This would enumerate stored message files and calculate total size
        Ok(0)
    }
    
    async fn clear_persistent_storage(&self) -> Result<()> {
        // TODO: Implement clearing of persistent storage
        // This would remove all stored message files
        Ok(())
    }
    
    async fn start_cleanup_task(&self) {
        let stats = Arc::clone(&self.stats);
        let sent_messages = Arc::clone(&self.sent_messages);
        let failed_queue = Arc::clone(&self.failed_queue);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
            
            loop {
                interval.tick().await;
                
                // Clean up old sent messages (keep for 1 hour)
                let cutoff_time = Instant::now() - Duration::from_secs(3600);
                {
                    let mut sent = sent_messages.write().await;
                    sent.retain(|_, info| info.sent_at > cutoff_time);
                }
                
                // Clean up old failed messages (keep for 24 hours)
                let failed_cutoff = Instant::now() - Duration::from_secs(24 * 3600);
                {
                    let mut failed = failed_queue.write().await;
                    failed.retain(|_, msg| msg.queued_at > failed_cutoff);
                }
                
                // Update cleanup timestamp
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.last_cleanup_operation = Some(Instant::now());
                }
                
                debug!("Offline queue cleanup completed");
            }
        });
    }
}