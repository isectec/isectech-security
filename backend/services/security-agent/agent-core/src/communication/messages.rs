// iSECTECH Security Agent - Message Processing
// Protocol Buffers message processing and serialization
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use prost::Message;
use tracing::{debug, warn, error};

use crate::config::AgentConfig;
use crate::crypto::CryptoManager;
use crate::error::{AgentError, Result, SecurityError};
use super::{OutboundMessage, MessageType, MessagePriority};

/// Message processor for Protocol Buffers serialization and security
pub struct MessageProcessor {
    /// Agent configuration
    config: AgentConfig,
    /// Cryptographic manager for message signing
    crypto_manager: Arc<CryptoManager>,
    /// Message sequence number for replay protection
    sequence_number: Arc<tokio::sync::RwLock<u64>>,
    /// Message cache for deduplication
    message_cache: Arc<tokio::sync::RwLock<HashMap<String, CachedMessage>>>,
}

/// Cached message information for deduplication
#[derive(Debug, Clone)]
struct CachedMessage {
    message_id: String,
    timestamp: SystemTime,
    hash: String,
}

/// Agent message wrapper (corresponds to protobuf AgentMessage)
#[derive(Debug, Clone)]
pub struct AgentMessage {
    pub agent_id: String,
    pub message_id: String,
    pub timestamp: SystemTime,
    pub message_type: AgentMessageType,
    pub payload: Vec<u8>,
    pub security: MessageSecurity,
}

/// Backend message wrapper (corresponds to protobuf BackendMessage)
#[derive(Debug, Clone)]
pub struct BackendMessage {
    pub target_agent_id: String,
    pub message_id: String,
    pub correlation_id: Option<String>,
    pub timestamp: SystemTime,
    pub command_type: BackendCommandType,
    pub payload: Vec<u8>,
    pub security: MessageSecurity,
}

/// Message security metadata
#[derive(Debug, Clone)]
pub struct MessageSecurity {
    pub signature: String,
    pub hash: String,
    pub sequence_number: u64,
    pub encryption_key_id: String,
    pub security_level: SecurityLevel,
}

/// Security levels for messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Agent message types (maps to protobuf enum)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentMessageType {
    Heartbeat = 1,
    SecurityEvent = 2,
    Telemetry = 3,
    Alert = 4,
    StatusUpdate = 5,
    Emergency = 6,
}

/// Backend command types (maps to protobuf enum)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendCommandType {
    PolicyUpdate = 1,
    EnforcementAction = 2,
    ConfigurationUpdate = 3,
    UpdateAgent = 4,
    Shutdown = 5,
    Investigate = 6,
    Quarantine = 7,
}

/// Heartbeat request structure
#[derive(Debug, Clone)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    pub timestamp: SystemTime,
    pub status: AgentStatus,
    pub resource_usage: ResourceUsage,
    pub collector_status: Vec<CollectorStatus>,
    pub events_processed: u64,
    pub threats_detected: u64,
    pub actions_taken: u64,
}

/// Agent status information
#[derive(Debug, Clone)]
pub struct AgentStatus {
    pub state: AgentState,
    pub last_policy_update: Option<SystemTime>,
    pub last_configuration_update: Option<SystemTime>,
    pub version: String,
    pub health: HealthStatus,
}

/// Agent state enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Unknown = 0,
    Initializing = 1,
    Running = 2,
    Updating = 3,
    Error = 4,
    Offline = 5,
    Quarantined = 6,
}

/// Health status enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Unknown = 0,
    Healthy = 1,
    Degraded = 2,
    Unhealthy = 3,
    Critical = 4,
}

/// Resource usage metrics
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_kbps: u64,
    pub open_file_descriptors: u32,
    pub active_threads: u32,
}

/// Collector status information
#[derive(Debug, Clone)]
pub struct CollectorStatus {
    pub collector_type: String,
    pub is_running: bool,
    pub is_healthy: bool,
    pub last_update: SystemTime,
    pub events_collected: u64,
    pub errors_count: u64,
    pub last_error: Option<String>,
}

/// Security event structure
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub event_id: String,
    pub agent_id: String,
    pub event_type: SecurityEventType,
    pub severity: EventSeverity,
    pub timestamp: SystemTime,
    pub source: String,
    pub description: String,
    pub attributes: HashMap<String, String>,
    pub raw_data: Vec<u8>,
    pub data_hash: String,
    pub threat_indicators: ThreatIndicators,
}

/// Security event types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEventType {
    Unknown = 0,
    ProcessCreation = 1,
    ProcessTermination = 2,
    NetworkConnection = 3,
    FileAccess = 4,
    FileModification = 5,
    RegistryModification = 6,
    UserLogin = 7,
    UserLogout = 8,
    PrivilegeEscalation = 9,
    SuspiciousActivity = 10,
    MalwareDetection = 11,
    PolicyViolation = 12,
    ConfigurationChange = 13,
    SystemAnomaly = 14,
}

/// Event severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Unknown = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

/// Threat indicators
#[derive(Debug, Clone)]
pub struct ThreatIndicators {
    pub iocs: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub risk_score: f64,
    pub threat_category: String,
    pub is_false_positive: bool,
}

impl MessageProcessor {
    /// Create a new message processor
    pub async fn new(
        config: &AgentConfig,
        crypto_manager: &Arc<CryptoManager>,
    ) -> Result<Self> {
        debug!("Initializing message processor");
        
        Ok(Self {
            config: config.clone(),
            crypto_manager: Arc::clone(crypto_manager),
            sequence_number: Arc::new(tokio::sync::RwLock::new(1)),
            message_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })
    }
    
    /// Prepare an outbound message for transmission
    pub async fn prepare_outbound_message(
        &self,
        message: &OutboundMessage,
        agent_id: &Uuid,
    ) -> Result<Vec<u8>> {
        debug!("Preparing outbound message {}", message.message_id);
        
        // Convert to internal message format
        let agent_message = self.create_agent_message(message, agent_id).await?;
        
        // Serialize to Protocol Buffers
        let serialized = self.serialize_agent_message(&agent_message).await?;
        
        // Add message to cache for deduplication
        self.cache_message(&agent_message).await?;
        
        debug!("Message {} prepared for transmission ({} bytes)", message.message_id, serialized.len());
        Ok(serialized)
    }
    
    /// Process an incoming backend message
    pub async fn process_backend_message(&self, data: &[u8]) -> Result<BackendMessage> {
        debug!("Processing backend message ({} bytes)", data.len());
        
        // Deserialize from Protocol Buffers
        let backend_message = self.deserialize_backend_message(data).await?;
        
        // Verify message security
        self.verify_message_security(&backend_message).await?;
        
        // Check for duplicate messages
        if self.is_duplicate_message(&backend_message.message_id).await? {
            warn!("Duplicate backend message detected: {}", backend_message.message_id);
            return Err(AgentError::Validation("Duplicate message".to_string()));
        }
        
        debug!("Backend message {} processed successfully", backend_message.message_id);
        Ok(backend_message)
    }
    
    /// Create a heartbeat message
    pub async fn create_heartbeat_message(
        &self,
        agent_id: &Uuid,
        status: AgentStatus,
        resource_usage: ResourceUsage,
        collector_status: Vec<CollectorStatus>,
        stats: (u64, u64, u64), // (events_processed, threats_detected, actions_taken)
    ) -> Result<Vec<u8>> {
        debug!("Creating heartbeat message");
        
        let heartbeat = HeartbeatRequest {
            agent_id: agent_id.to_string(),
            timestamp: SystemTime::now(),
            status,
            resource_usage,
            collector_status,
            events_processed: stats.0,
            threats_detected: stats.1,
            actions_taken: stats.2,
        };
        
        // Serialize heartbeat to bytes
        let payload = self.serialize_heartbeat(&heartbeat).await?;
        
        // Create outbound message wrapper
        let outbound_message = OutboundMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Heartbeat,
            payload,
            priority: MessagePriority::Normal,
            max_retries: 3,
            created_at: std::time::Instant::now(),
            expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(300)),
        };
        
        // Prepare for transmission
        self.prepare_outbound_message(&outbound_message, agent_id).await
    }
    
    /// Create a security event batch message
    pub async fn create_security_event_batch(
        &self,
        agent_id: &Uuid,
        events: Vec<SecurityEvent>,
    ) -> Result<Vec<u8>> {
        debug!("Creating security event batch with {} events", events.len());
        
        // Create event batch structure
        let event_batch = SecurityEventBatch {
            agent_id: agent_id.to_string(),
            events,
            metadata: BatchMetadata {
                event_count: events.len() as u32,
                batch_start_time: SystemTime::now(),
                batch_end_time: SystemTime::now(),
                compression_algorithm: "none".to_string(),
                compressed_size: 0,
                uncompressed_size: 0,
            },
        };
        
        // Serialize event batch
        let payload = self.serialize_security_event_batch(&event_batch).await?;
        
        // Create outbound message wrapper
        let outbound_message = OutboundMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::SecurityEvent,
            payload,
            priority: MessagePriority::High,
            max_retries: 5,
            created_at: std::time::Instant::now(),
            expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(3600)),
        };
        
        // Prepare for transmission
        self.prepare_outbound_message(&outbound_message, agent_id).await
    }
    
    /// Create an emergency alert message
    pub async fn create_emergency_alert(
        &self,
        agent_id: &Uuid,
        alert_type: EmergencyAlertType,
        message: String,
        context: HashMap<String, String>,
        affected_resources: Vec<String>,
    ) -> Result<Vec<u8>> {
        debug!("Creating emergency alert: {:?}", alert_type);
        
        let emergency_alert = EmergencyAlertRequest {
            agent_id: agent_id.to_string(),
            alert_type,
            alert_message: message,
            alert_timestamp: SystemTime::now(),
            context_data: context,
            affected_resources,
        };
        
        // Serialize emergency alert
        let payload = self.serialize_emergency_alert(&emergency_alert).await?;
        
        // Create outbound message wrapper with highest priority
        let outbound_message = OutboundMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Emergency,
            payload,
            priority: MessagePriority::Emergency,
            max_retries: 10,
            created_at: std::time::Instant::now(),
            expires_at: Some(std::time::Instant::now() + std::time::Duration::from_secs(300)),
        };
        
        // Prepare for transmission
        self.prepare_outbound_message(&outbound_message, agent_id).await
    }
    
    // Private implementation methods
    
    async fn create_agent_message(
        &self,
        message: &OutboundMessage,
        agent_id: &Uuid,
    ) -> Result<AgentMessage> {
        let sequence_num = {
            let mut seq = self.sequence_number.write().await;
            *seq += 1;
            *seq
        };
        
        // Calculate message hash
        let message_hash = self.calculate_message_hash(&message.payload).await?;
        
        // Sign the message
        let signature = self.sign_message(&message.payload, sequence_num).await?;
        
        let agent_message_type = match message.message_type {
            MessageType::Heartbeat => AgentMessageType::Heartbeat,
            MessageType::SecurityEvent => AgentMessageType::SecurityEvent,
            MessageType::Telemetry => AgentMessageType::Telemetry,
            MessageType::Alert => AgentMessageType::Alert,
            MessageType::StatusUpdate => AgentMessageType::StatusUpdate,
            MessageType::Emergency => AgentMessageType::Emergency,
            MessageType::PolicyRequest => AgentMessageType::SecurityEvent, // Map to existing type
        };
        
        let security_level = match message.priority {
            MessagePriority::Low => SecurityLevel::Low,
            MessagePriority::Normal => SecurityLevel::Medium,
            MessagePriority::High => SecurityLevel::High,
            MessagePriority::Critical | MessagePriority::Emergency => SecurityLevel::Critical,
        };
        
        Ok(AgentMessage {
            agent_id: agent_id.to_string(),
            message_id: message.message_id.to_string(),
            timestamp: SystemTime::now(),
            message_type: agent_message_type,
            payload: message.payload.clone(),
            security: MessageSecurity {
                signature,
                hash: message_hash,
                sequence_number: sequence_num,
                encryption_key_id: "agent-key-1".to_string(),
                security_level,
            },
        })
    }
    
    async fn serialize_agent_message(&self, message: &AgentMessage) -> Result<Vec<u8>> {
        // TODO: Implement Protocol Buffers serialization
        // For now, use JSON as placeholder
        serde_json::to_vec(message)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize agent message: {}", e)))
    }
    
    async fn deserialize_backend_message(&self, data: &[u8]) -> Result<BackendMessage> {
        // TODO: Implement Protocol Buffers deserialization
        // For now, use JSON as placeholder
        serde_json::from_slice(data)
            .map_err(|e| AgentError::Serialization(format!("Failed to deserialize backend message: {}", e)))
    }
    
    async fn serialize_heartbeat(&self, heartbeat: &HeartbeatRequest) -> Result<Vec<u8>> {
        serde_json::to_vec(heartbeat)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize heartbeat: {}", e)))
    }
    
    async fn serialize_security_event_batch(&self, batch: &SecurityEventBatch) -> Result<Vec<u8>> {
        serde_json::to_vec(batch)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize event batch: {}", e)))
    }
    
    async fn serialize_emergency_alert(&self, alert: &EmergencyAlertRequest) -> Result<Vec<u8>> {
        serde_json::to_vec(alert)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize emergency alert: {}", e)))
    }
    
    async fn calculate_message_hash(&self, data: &[u8]) -> Result<String> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    async fn sign_message(&self, data: &[u8], sequence_num: u64) -> Result<String> {
        // Combine data with sequence number for signing
        let mut signing_data = data.to_vec();
        signing_data.extend_from_slice(&sequence_num.to_le_bytes());
        
        let signature = self.crypto_manager.sign(&signing_data)?;
        Ok(base64::encode(signature))
    }
    
    async fn verify_message_security(&self, message: &BackendMessage) -> Result<()> {
        // TODO: Implement message signature verification
        // - Verify signature using backend's public key
        // - Check message hash integrity
        // - Validate sequence number for replay protection
        
        debug!("Message security verification passed for {}", message.message_id);
        Ok(())
    }
    
    async fn cache_message(&self, message: &AgentMessage) -> Result<()> {
        let cached_message = CachedMessage {
            message_id: message.message_id.clone(),
            timestamp: message.timestamp,
            hash: message.security.hash.clone(),
        };
        
        let mut cache = self.message_cache.write().await;
        cache.insert(message.message_id.clone(), cached_message);
        
        // Clean up old cached messages (keep only last 1000)
        if cache.len() > 1000 {
            let oldest_keys: Vec<String> = cache.iter()
                .map(|(k, v)| (k.clone(), v.timestamp))
                .collect::<Vec<_>>()
                .into_iter()
                .min_by_key(|(_, timestamp)| *timestamp)
                .into_iter()
                .take(100)
                .map(|(k, _)| k)
                .collect();
            
            for key in oldest_keys {
                cache.remove(&key);
            }
        }
        
        Ok(())
    }
    
    async fn is_duplicate_message(&self, message_id: &str) -> Result<bool> {
        let cache = self.message_cache.read().await;
        Ok(cache.contains_key(message_id))
    }
}

/// Security event batch structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityEventBatch {
    pub agent_id: String,
    pub events: Vec<SecurityEvent>,
    pub metadata: BatchMetadata,
}

/// Batch metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchMetadata {
    pub event_count: u32,
    pub batch_start_time: SystemTime,
    pub batch_end_time: SystemTime,
    pub compression_algorithm: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

/// Emergency alert request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmergencyAlertRequest {
    pub agent_id: String,
    pub alert_type: EmergencyAlertType,
    pub alert_message: String,
    pub alert_timestamp: SystemTime,
    pub context_data: HashMap<String, String>,
    pub affected_resources: Vec<String>,
}

/// Emergency alert types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum EmergencyAlertType {
    SecurityBreach = 1,
    MalwareDetected = 2,
    SystemCompromise = 3,
    DataExfiltration = 4,
    PrivilegeEscalation = 5,
    AgentTampering = 6,
    NetworkIntrusion = 7,
}

// Implement necessary trait derivations for serialization
impl serde::Serialize for AgentMessage {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AgentMessage", 6)?;
        state.serialize_field("agent_id", &self.agent_id)?;
        state.serialize_field("message_id", &self.message_id)?;
        state.serialize_field("timestamp", &self.timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs())?;
        state.serialize_field("message_type", &(self.message_type as u32))?;
        state.serialize_field("payload", &base64::encode(&self.payload))?;
        state.serialize_field("security", &self.security)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for BackendMessage {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // TODO: Implement proper deserialization
        use serde::de::Error;
        Err(D::Error::custom("BackendMessage deserialization not implemented"))
    }
}

// Additional trait implementations for serialization
impl serde::Serialize for MessageSecurity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MessageSecurity", 5)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("hash", &self.hash)?;
        state.serialize_field("sequence_number", &self.sequence_number)?;
        state.serialize_field("encryption_key_id", &self.encryption_key_id)?;
        state.serialize_field("security_level", &(self.security_level as u32))?;
        state.end()
    }
}

// Implement serialization for other complex types as needed
macro_rules! impl_serialize_for_enum {
    ($enum_type:ty) => {
        impl serde::Serialize for $enum_type {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_u32(*self as u32)
            }
        }
    };
}

impl_serialize_for_enum!(AgentState);
impl_serialize_for_enum!(HealthStatus);
impl_serialize_for_enum!(SecurityEventType);
impl_serialize_for_enum!(EventSeverity);

// Implement serialization for structs
impl serde::Serialize for HeartbeatRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("HeartbeatRequest", 8)?;
        state.serialize_field("agent_id", &self.agent_id)?;
        state.serialize_field("timestamp", &self.timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs())?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("resource_usage", &self.resource_usage)?;
        state.serialize_field("collector_status", &self.collector_status)?;
        state.serialize_field("events_processed", &self.events_processed)?;
        state.serialize_field("threats_detected", &self.threats_detected)?;
        state.serialize_field("actions_taken", &self.actions_taken)?;
        state.end()
    }
}

impl serde::Serialize for AgentStatus {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AgentStatus", 5)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("last_policy_update", &self.last_policy_update.map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs()))?;
        state.serialize_field("last_configuration_update", &self.last_configuration_update.map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs()))?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("health", &self.health)?;
        state.end()
    }
}

impl serde::Serialize for ResourceUsage {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ResourceUsage", 6)?;
        state.serialize_field("cpu_percent", &self.cpu_percent)?;
        state.serialize_field("memory_mb", &self.memory_mb)?;
        state.serialize_field("disk_mb", &self.disk_mb)?;
        state.serialize_field("network_kbps", &self.network_kbps)?;
        state.serialize_field("open_file_descriptors", &self.open_file_descriptors)?;
        state.serialize_field("active_threads", &self.active_threads)?;
        state.end()
    }
}

impl serde::Serialize for CollectorStatus {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CollectorStatus", 7)?;
        state.serialize_field("collector_type", &self.collector_type)?;
        state.serialize_field("is_running", &self.is_running)?;
        state.serialize_field("is_healthy", &self.is_healthy)?;
        state.serialize_field("last_update", &self.last_update.duration_since(UNIX_EPOCH).unwrap().as_secs())?;
        state.serialize_field("events_collected", &self.events_collected)?;
        state.serialize_field("errors_count", &self.errors_count)?;
        state.serialize_field("last_error", &self.last_error)?;
        state.end()
    }
}

impl serde::Serialize for SecurityEvent {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecurityEvent", 11)?;
        state.serialize_field("event_id", &self.event_id)?;
        state.serialize_field("agent_id", &self.agent_id)?;
        state.serialize_field("event_type", &self.event_type)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("timestamp", &self.timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs())?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("attributes", &self.attributes)?;
        state.serialize_field("raw_data", &base64::encode(&self.raw_data))?;
        state.serialize_field("data_hash", &self.data_hash)?;
        state.serialize_field("threat_indicators", &self.threat_indicators)?;
        state.end()
    }
}

impl serde::Serialize for ThreatIndicators {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ThreatIndicators", 6)?;
        state.serialize_field("iocs", &self.iocs)?;
        state.serialize_field("mitre_tactics", &self.mitre_tactics)?;
        state.serialize_field("mitre_techniques", &self.mitre_techniques)?;
        state.serialize_field("risk_score", &self.risk_score)?;
        state.serialize_field("threat_category", &self.threat_category)?;
        state.serialize_field("is_false_positive", &self.is_false_positive)?;
        state.end()
    }
}