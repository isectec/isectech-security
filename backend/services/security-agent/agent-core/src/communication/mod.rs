// iSECTECH Security Agent - Secure Communication Module
// Production-grade mTLS communication with certificate management
// Copyright (c) 2024 iSECTECH. All rights reserved.

//! Secure communication module for the iSECTECH security agent
//! 
//! This module provides production-grade secure communication capabilities including:
//! - Mutual TLS (mTLS) authentication with certificate pinning
//! - Protocol Buffers message serialization/deserialization
//! - Offline message queuing and synchronization
//! - Message integrity and authenticity verification
//! - Connection pooling and automatic retry logic
//! - Emergency communication channels

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Mutex, mpsc};
use tokio::time::{interval, timeout};
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::crypto::CryptoManager;
use crate::error::{AgentError, Result, SecurityError};
use crate::storage::StorageManager;

pub mod client;
pub mod messages;
pub mod certificates;
pub mod offline;
pub mod retry;
pub mod security;

use client::SecureClient;
use messages::{MessageProcessor, AgentMessage, BackendMessage};
use certificates::CertificateManager;
use offline::OfflineQueue;
use retry::RetryManager;

/// Main secure communication manager
pub struct SecureCommunicationManager {
    /// Agent configuration
    config: AgentConfig,
    /// Agent unique identifier
    agent_id: Uuid,
    /// Secure client for backend communication
    client: Arc<RwLock<Option<SecureClient>>>,
    /// Certificate manager for mTLS
    cert_manager: Arc<CertificateManager>,
    /// Message processor for Protocol Buffers
    message_processor: Arc<MessageProcessor>,
    /// Offline message queue
    offline_queue: Arc<OfflineQueue>,
    /// Retry manager for failed operations
    retry_manager: Arc<RetryManager>,
    /// Cryptographic manager
    crypto_manager: Arc<CryptoManager>,
    /// Storage manager for persistent data
    storage_manager: Arc<StorageManager>,
    /// Connection state
    connection_state: Arc<RwLock<ConnectionState>>,
    /// Message channel for outbound messages
    outbound_tx: mpsc::Sender<OutboundMessage>,
    /// Message channel receiver
    outbound_rx: Arc<Mutex<Option<mpsc::Receiver<OutboundMessage>>>>,
    /// Emergency communication channel
    emergency_tx: mpsc::Sender<EmergencyMessage>,
    /// Statistics
    stats: Arc<RwLock<CommunicationStats>>,
}

/// Connection state tracking
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Current connection status
    pub status: ConnectionStatus,
    /// Last successful connection timestamp
    pub last_connected: Option<Instant>,
    /// Last heartbeat timestamp
    pub last_heartbeat: Option<Instant>,
    /// Connection attempts count
    pub connection_attempts: u64,
    /// Last error encountered
    pub last_error: Option<String>,
    /// Certificate expiration time
    pub cert_expires_at: Option<SystemTime>,
    /// Backend server information
    pub server_info: Option<ServerInfo>,
}

/// Connection status enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Not connected
    Disconnected,
    /// Connecting to backend
    Connecting,
    /// Connected and authenticated
    Connected,
    /// Connection failed
    Failed,
    /// In offline mode
    Offline,
    /// Certificate expired or invalid
    CertificateError,
    /// Emergency mode - limited functionality
    Emergency,
}

/// Server information from successful connections
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub server_version: String,
    pub supported_protocols: Vec<String>,
    pub max_message_size: u64,
    pub heartbeat_interval: Duration,
    pub policy_version: String,
}

/// Outbound message wrapper
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub message_id: Uuid,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub priority: MessagePriority,
    pub max_retries: u32,
    pub created_at: Instant,
    pub expires_at: Option<Instant>,
}

/// Message types for classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageType {
    Heartbeat,
    SecurityEvent,
    Telemetry,
    Alert,
    StatusUpdate,
    Emergency,
    PolicyRequest,
}

/// Message priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
    Emergency = 5,
}

/// Emergency message for critical situations
#[derive(Debug, Clone)]
pub struct EmergencyMessage {
    pub alert_type: EmergencyAlertType,
    pub message: String,
    pub context: std::collections::HashMap<String, String>,
    pub affected_resources: Vec<String>,
}

/// Emergency alert types
#[derive(Debug, Clone)]
pub enum EmergencyAlertType {
    SecurityBreach,
    MalwareDetected,
    SystemCompromise,
    DataExfiltration,
    PrivilegeEscalation,
    AgentTampering,
    NetworkIntrusion,
}

/// Communication statistics
#[derive(Debug, Clone, Default)]
pub struct CommunicationStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_attempts: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub offline_messages_queued: u64,
    pub offline_messages_sent: u64,
    pub certificate_renewals: u64,
    pub security_violations: u64,
    pub last_reset: Instant,
}

impl SecureCommunicationManager {
    /// Create a new secure communication manager
    pub async fn new(
        config: AgentConfig,
        agent_id: Uuid,
        crypto_manager: Arc<CryptoManager>,
        storage_manager: Arc<StorageManager>,
    ) -> Result<Self> {
        info!("Initializing secure communication manager for agent {}", agent_id);
        
        // Initialize certificate manager
        let cert_manager = Arc::new(
            CertificateManager::new(&config, &crypto_manager, &storage_manager).await?
        );
        
        // Initialize message processor
        let message_processor = Arc::new(
            MessageProcessor::new(&config, &crypto_manager).await?
        );
        
        // Initialize offline queue
        let offline_queue = Arc::new(
            OfflineQueue::new(&config, &storage_manager).await?
        );
        
        // Initialize retry manager
        let retry_manager = Arc::new(
            RetryManager::new(&config).await?
        );
        
        // Create message channels
        let (outbound_tx, outbound_rx) = mpsc::channel(1000);
        let (emergency_tx, _emergency_rx) = mpsc::channel(100);
        
        let manager = Self {
            config,
            agent_id,
            client: Arc::new(RwLock::new(None)),
            cert_manager,
            message_processor,
            offline_queue,
            retry_manager,
            crypto_manager,
            storage_manager,
            connection_state: Arc::new(RwLock::new(ConnectionState {
                status: ConnectionStatus::Disconnected,
                last_connected: None,
                last_heartbeat: None,
                connection_attempts: 0,
                last_error: None,
                cert_expires_at: None,
                server_info: None,
            })),
            outbound_tx,
            outbound_rx: Arc::new(Mutex::new(Some(outbound_rx))),
            emergency_tx,
            stats: Arc::new(RwLock::new(CommunicationStats {
                last_reset: Instant::now(),
                ..Default::default()
            })),
        };
        
        info!("Secure communication manager initialized successfully");
        Ok(manager)
    }
    
    /// Start the communication manager
    pub async fn start(&self) -> Result<()> {
        info!("Starting secure communication manager");
        
        // Validate certificates
        self.cert_manager.validate_certificates().await?;
        
        // Start background tasks
        self.start_background_tasks().await?;
        
        // Attempt initial connection
        self.connect().await?;
        
        info!("Secure communication manager started successfully");
        Ok(())
    }
    
    /// Establish secure connection to backend
    pub async fn connect(&self) -> Result<()> {
        let mut state = self.connection_state.write().await;
        state.status = ConnectionStatus::Connecting;
        state.connection_attempts += 1;
        drop(state);
        
        info!("Attempting to establish secure connection to backend");
        
        // Check certificate validity
        if !self.cert_manager.is_certificate_valid().await? {
            warn!("Agent certificate is invalid or expired, attempting renewal");
            self.cert_manager.renew_certificate().await?;
        }
        
        // Create secure client
        let client = SecureClient::new(
            &self.config,
            &self.cert_manager,
            &self.message_processor,
            self.agent_id,
        ).await?;
        
        // Test connection with backend
        match client.test_connection().await {
            Ok(server_info) => {
                *self.client.write().await = Some(client);
                
                let mut state = self.connection_state.write().await;
                state.status = ConnectionStatus::Connected;
                state.last_connected = Some(Instant::now());
                state.last_error = None;
                state.server_info = Some(server_info);
                
                let mut stats = self.stats.write().await;
                stats.successful_connections += 1;
                
                info!("Secure connection established successfully");
                Ok(())
            }
            Err(e) => {
                let mut state = self.connection_state.write().await;
                state.status = ConnectionStatus::Failed;
                state.last_error = Some(e.to_string());
                
                let mut stats = self.stats.write().await;
                stats.failed_connections += 1;
                
                error!("Failed to establish secure connection: {}", e);
                Err(e)
            }
        }
    }
    
    /// Send a message to the backend
    pub async fn send_message(
        &self,
        message_type: MessageType,
        payload: Vec<u8>,
        priority: MessagePriority,
    ) -> Result<Uuid> {
        let message_id = Uuid::new_v4();
        
        let outbound_message = OutboundMessage {
            message_id,
            message_type: message_type.clone(),
            payload,
            priority,
            max_retries: self.get_max_retries_for_type(&message_type),
            created_at: Instant::now(),
            expires_at: self.get_expiration_for_type(&message_type),
        };
        
        // Try to send immediately if connected
        if self.is_connected().await {
            match self.send_message_internal(&outbound_message).await {
                Ok(_) => {
                    debug!("Message {} sent successfully", message_id);
                    return Ok(message_id);
                }
                Err(e) => {
                    warn!("Failed to send message {}: {}", message_id, e);
                    // Fall through to queuing
                }
            }
        }
        
        // Queue for offline delivery
        self.queue_message_for_offline_delivery(outbound_message).await?;
        
        debug!("Message {} queued for offline delivery", message_id);
        Ok(message_id)
    }
    
    /// Send emergency alert
    pub async fn send_emergency_alert(
        &self,
        alert_type: EmergencyAlertType,
        message: String,
        context: std::collections::HashMap<String, String>,
        affected_resources: Vec<String>,
    ) -> Result<()> {
        let emergency_message = EmergencyMessage {
            alert_type,
            message,
            context,
            affected_resources,
        };
        
        // Emergency messages bypass normal queuing and use dedicated channel
        if let Err(e) = self.emergency_tx.try_send(emergency_message) {
            error!("Failed to queue emergency message: {}", e);
            return Err(AgentError::Network("Emergency channel full".to_string()));
        }
        
        // Try immediate delivery through multiple channels
        self.send_emergency_through_all_channels().await?;
        
        Ok(())
    }
    
    /// Send heartbeat to backend
    pub async fn send_heartbeat(&self) -> Result<()> {
        debug!("Sending heartbeat to backend");
        
        let heartbeat_data = self.create_heartbeat_message().await?;
        let message_id = self.send_message(
            MessageType::Heartbeat,
            heartbeat_data,
            MessagePriority::Normal,
        ).await?;
        
        // Update heartbeat timestamp on successful send
        let mut state = self.connection_state.write().await;
        state.last_heartbeat = Some(Instant::now());
        
        debug!("Heartbeat {} sent successfully", message_id);
        Ok(())
    }
    
    /// Check if currently connected to backend
    pub async fn is_connected(&self) -> bool {
        let state = self.connection_state.read().await;
        state.status == ConnectionStatus::Connected
    }
    
    /// Get current connection state
    pub async fn get_connection_state(&self) -> ConnectionState {
        self.connection_state.read().await.clone()
    }
    
    /// Get communication statistics
    pub async fn get_statistics(&self) -> CommunicationStats {
        self.stats.read().await.clone()
    }
    
    /// Gracefully shutdown the communication manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down secure communication manager");
        
        // Send any pending offline messages
        self.flush_offline_queue().await?;
        
        // Disconnect from backend
        if let Some(client) = self.client.write().await.take() {
            client.disconnect().await?;
        }
        
        // Update connection state
        let mut state = self.connection_state.write().await;
        state.status = ConnectionStatus::Disconnected;
        
        info!("Secure communication manager shutdown complete");
        Ok(())
    }
    
    // Private implementation methods
    
    async fn start_background_tasks(&self) -> Result<()> {
        // Start message processing task
        self.start_message_processor_task().await;
        
        // Start connection monitoring task
        self.start_connection_monitor_task().await;
        
        // Start offline queue processor task
        self.start_offline_queue_processor_task().await;
        
        // Start certificate monitoring task
        self.start_certificate_monitor_task().await;
        
        // Start heartbeat task
        self.start_heartbeat_task().await;
        
        // Start emergency message handler
        self.start_emergency_handler_task().await;
        
        Ok(())
    }
    
    async fn start_message_processor_task(&self) {
        let outbound_rx = self.outbound_rx.lock().await.take();
        if outbound_rx.is_none() {
            return;
        }
        
        let mut outbound_rx = outbound_rx.unwrap();
        let client = Arc::clone(&self.client);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            while let Some(message) = outbound_rx.recv().await {
                if let Some(ref client) = *client.read().await {
                    match client.send_raw_message(&message).await {
                        Ok(_) => {
                            let mut stats = stats.write().await;
                            stats.messages_sent += 1;
                            stats.bytes_sent += message.payload.len() as u64;
                        }
                        Err(e) => {
                            error!("Failed to send message {}: {}", message.message_id, e);
                        }
                    }
                }
            }
        });
    }
    
    async fn start_connection_monitor_task(&self) {
        let connection_state = Arc::clone(&self.connection_state);
        let client = Arc::clone(&self.client);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let is_connected = {
                    let state = connection_state.read().await;
                    state.status == ConnectionStatus::Connected
                };
                
                if is_connected {
                    // Test connection health
                    if let Some(ref client) = *client.read().await {
                        if let Err(_) = client.ping().await {
                            warn!("Connection health check failed, marking as disconnected");
                            let mut state = connection_state.write().await;
                            state.status = ConnectionStatus::Failed;
                        }
                    }
                } else {
                    // Attempt reconnection
                    debug!("Connection not established, attempting reconnection");
                    // TODO: Implement reconnection logic
                }
            }
        });
    }
    
    async fn start_offline_queue_processor_task(&self) {
        let offline_queue = Arc::clone(&self.offline_queue);
        let client = Arc::clone(&self.client);
        let connection_state = Arc::clone(&self.connection_state);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                let is_connected = {
                    let state = connection_state.read().await;
                    state.status == ConnectionStatus::Connected
                };
                
                if is_connected {
                    // Process offline queue
                    if let Ok(messages) = offline_queue.get_pending_messages(100).await {
                        for message in messages {
                            if let Some(ref client) = *client.read().await {
                                match client.send_raw_message(&message).await {
                                    Ok(_) => {
                                        let _ = offline_queue.mark_message_sent(&message.message_id).await;
                                    }
                                    Err(e) => {
                                        error!("Failed to send offline message {}: {}", message.message_id, e);
                                        break; // Stop processing on error
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    
    async fn start_certificate_monitor_task(&self) {
        let cert_manager = Arc::clone(&self.cert_manager);
        let connection_state = Arc::clone(&self.connection_state);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Check hourly
            
            loop {
                interval.tick().await;
                
                match cert_manager.check_certificate_expiration().await {
                    Ok(expires_at) => {
                        let mut state = connection_state.write().await;
                        state.cert_expires_at = Some(expires_at);
                        
                        // Renew if expiring within 7 days
                        if expires_at.duration_since(SystemTime::now()).unwrap_or_default().as_secs() < 7 * 24 * 3600 {
                            warn!("Certificate expires soon, attempting renewal");
                            if let Err(e) = cert_manager.renew_certificate().await {
                                error!("Certificate renewal failed: {}", e);
                                state.status = ConnectionStatus::CertificateError;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Certificate check failed: {}", e);
                        let mut state = connection_state.write().await;
                        state.status = ConnectionStatus::CertificateError;
                    }
                }
            }
        });
    }
    
    async fn start_heartbeat_task(&self) {
        // TODO: Implement heartbeat task
    }
    
    async fn start_emergency_handler_task(&self) {
        // TODO: Implement emergency message handler
    }
    
    async fn send_message_internal(&self, message: &OutboundMessage) -> Result<()> {
        if let Some(ref client) = *self.client.read().await {
            client.send_raw_message(message).await?;
            
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
            stats.bytes_sent += message.payload.len() as u64;
            
            Ok(())
        } else {
            Err(AgentError::Network("No active client connection".to_string()))
        }
    }
    
    async fn queue_message_for_offline_delivery(&self, message: OutboundMessage) -> Result<()> {
        self.offline_queue.queue_message(message).await?;
        
        let mut stats = self.stats.write().await;
        stats.offline_messages_queued += 1;
        
        Ok(())
    }
    
    async fn send_emergency_through_all_channels(&self) -> Result<()> {
        // TODO: Implement emergency message sending through multiple channels
        Ok(())
    }
    
    async fn create_heartbeat_message(&self) -> Result<Vec<u8>> {
        // TODO: Implement heartbeat message creation
        Ok(vec![])
    }
    
    async fn flush_offline_queue(&self) -> Result<()> {
        // TODO: Implement offline queue flushing
        Ok(())
    }
    
    fn get_max_retries_for_type(&self, message_type: &MessageType) -> u32 {
        match message_type {
            MessageType::Emergency => 10,
            MessageType::Alert => 5,
            MessageType::SecurityEvent => 3,
            MessageType::Heartbeat => 3,
            MessageType::Telemetry => 2,
            MessageType::StatusUpdate => 2,
            MessageType::PolicyRequest => 5,
        }
    }
    
    fn get_expiration_for_type(&self, message_type: &MessageType) -> Option<Instant> {
        let expiration_duration = match message_type {
            MessageType::Emergency => Duration::from_secs(300), // 5 minutes
            MessageType::Alert => Duration::from_secs(1800), // 30 minutes
            MessageType::SecurityEvent => Duration::from_secs(3600), // 1 hour
            MessageType::Heartbeat => Duration::from_secs(300), // 5 minutes
            MessageType::Telemetry => Duration::from_secs(7200), // 2 hours
            MessageType::StatusUpdate => Duration::from_secs(3600), // 1 hour
            MessageType::PolicyRequest => Duration::from_secs(600), // 10 minutes
        };
        
        Some(Instant::now() + expiration_duration)
    }
}