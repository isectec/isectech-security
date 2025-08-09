// iSECTECH Security Agent - Communication Security
// Security enhancements for agent communication
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use tokio::sync::RwLock;
use tracing::{warn, error, debug};

use crate::error::{AgentError, Result, SecurityError, TamperSeverity};

/// Communication security manager for message validation and threat detection
pub struct CommunicationSecurity {
    /// Known server public keys for signature verification
    server_public_keys: Arc<RwLock<HashMap<String, UnparsedPublicKey<Vec<u8>>>>>,
    /// Message sequence tracking for replay protection
    sequence_tracker: Arc<RwLock<SequenceTracker>>,
    /// Rate limiting for different message types
    rate_limiter: Arc<RwLock<RateLimiter>>,
    /// Security event recorder
    security_events: Arc<RwLock<Vec<SecurityEvent>>>,
    /// Security configuration
    config: SecurityConfig,
}

/// Sequence number tracking for replay attack prevention
#[derive(Debug, Default)]
struct SequenceTracker {
    /// Last valid sequence number from each source
    last_sequences: HashMap<String, u64>,
    /// Window size for out-of-order messages
    window_size: u64,
    /// Maximum age for sequence tracking
    max_age: Duration,
    /// Cleanup tracking
    last_cleanup: Instant,
}

/// Rate limiting for security protection
#[derive(Debug, Default)]
struct RateLimiter {
    /// Message counts by source and type
    message_counts: HashMap<String, MessageCounts>,
    /// Rate limit configuration
    limits: HashMap<String, RateLimit>,
    /// Last cleanup time
    last_cleanup: Instant,
}

/// Message count tracking
#[derive(Debug, Default)]
struct MessageCounts {
    /// Total messages in current window
    total: u64,
    /// Messages by type
    by_type: HashMap<String, u64>,
    /// Window start time
    window_start: Instant,
}

/// Rate limit configuration
#[derive(Debug, Clone)]
struct RateLimit {
    /// Maximum messages per time window
    max_messages: u64,
    /// Time window duration
    window_duration: Duration,
    /// Per-type limits
    type_limits: HashMap<String, u64>,
}

/// Security event for communication anomalies
#[derive(Debug, Clone)]
struct SecurityEvent {
    /// Event timestamp
    timestamp: Instant,
    /// Event type
    event_type: SecurityEventType,
    /// Source identifier
    source: String,
    /// Event description
    description: String,
    /// Additional context
    context: HashMap<String, String>,
    /// Severity level
    severity: TamperSeverity,
}

/// Types of security events
#[derive(Debug, Clone)]
enum SecurityEventType {
    /// Invalid signature detected
    InvalidSignature,
    /// Replay attack detected
    ReplayAttack,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Invalid message format
    InvalidFormat,
    /// Timestamp anomaly
    TimestampAnomaly,
    /// Unknown public key
    UnknownPublicKey,
    /// Message integrity failure
    IntegrityFailure,
    /// Suspicious behavior pattern
    SuspiciousBehavior,
}

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable signature verification
    pub verify_signatures: bool,
    /// Enable replay protection
    pub replay_protection: bool,
    /// Enable rate limiting
    pub rate_limiting: bool,
    /// Maximum message age (seconds)
    pub max_message_age: u64,
    /// Sequence window size
    pub sequence_window: u64,
    /// Default rate limits
    pub default_rate_limit: u64,
    /// Rate limit window (seconds)
    pub rate_window: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            replay_protection: true,
            rate_limiting: true,
            max_message_age: 300, // 5 minutes
            sequence_window: 100,
            default_rate_limit: 1000, // messages per window
            rate_window: 60, // 1 minute
        }
    }
}

impl CommunicationSecurity {
    /// Create a new communication security manager
    pub fn new(config: SecurityConfig) -> Self {
        debug!("Initializing communication security manager");
        
        Self {
            server_public_keys: Arc::new(RwLock::new(HashMap::new())),
            sequence_tracker: Arc::new(RwLock::new(SequenceTracker {
                window_size: config.sequence_window,
                max_age: Duration::from_secs(config.max_message_age),
                ..Default::default()
            })),
            rate_limiter: Arc::new(RwLock::new(RateLimiter {
                limits: HashMap::from([
                    ("default".to_string(), RateLimit {
                        max_messages: config.default_rate_limit,
                        window_duration: Duration::from_secs(config.rate_window),
                        type_limits: HashMap::new(),
                    })
                ]),
                ..Default::default()
            })),
            security_events: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }
    
    /// Add a trusted server public key
    pub async fn add_server_public_key(&self, key_id: &str, public_key: &[u8]) -> Result<()> {
        debug!("Adding server public key: {}", key_id);
        
        let unparsed_key = UnparsedPublicKey::new(&ED25519, public_key.to_vec());
        
        self.server_public_keys.write().await.insert(key_id.to_string(), unparsed_key);
        
        debug!("Server public key added successfully");
        Ok(())
    }
    
    /// Verify message signature
    pub async fn verify_message_signature(
        &self,
        message_data: &[u8],
        signature: &[u8],
        key_id: &str,
    ) -> Result<bool> {
        if !self.config.verify_signatures {
            return Ok(true);
        }
        
        debug!("Verifying message signature with key: {}", key_id);
        
        let server_keys = self.server_public_keys.read().await;
        let public_key = server_keys.get(key_id)
            .ok_or_else(|| {
                self.record_security_event(
                    SecurityEventType::UnknownPublicKey,
                    key_id,
                    "Unknown public key used for signature verification",
                    TamperSeverity::Medium,
                    HashMap::from([("key_id".to_string(), key_id.to_string())]),
                ).await;
                
                AgentError::Security(SecurityError::SignatureVerification {
                    data_type: "message".to_string(),
                    reason: format!("Unknown public key: {}", key_id),
                })
            })?;
        
        match public_key.verify(message_data, signature) {
            Ok(_) => {
                debug!("Message signature verification successful");
                Ok(true)
            }
            Err(_) => {
                warn!("Message signature verification failed");
                
                self.record_security_event(
                    SecurityEventType::InvalidSignature,
                    key_id,
                    "Message signature verification failed",
                    TamperSeverity::High,
                    HashMap::from([
                        ("key_id".to_string(), key_id.to_string()),
                        ("message_size".to_string(), message_data.len().to_string()),
                    ]),
                ).await;
                
                Ok(false)
            }
        }
    }
    
    /// Check for replay attacks using sequence numbers
    pub async fn check_replay_protection(
        &self,
        source_id: &str,
        sequence_number: u64,
        timestamp: SystemTime,
    ) -> Result<bool> {
        if !self.config.replay_protection {
            return Ok(true);
        }
        
        debug!("Checking replay protection for source: {}, sequence: {}", source_id, sequence_number);
        
        let mut tracker = self.sequence_tracker.write().await;
        
        // Check message age
        let message_age = timestamp.duration_since(UNIX_EPOCH)
            .map_err(|_| AgentError::Validation("Invalid timestamp".to_string()))?;
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| AgentError::Internal("Failed to get current time".to_string()))?;
        
        if current_time.saturating_sub(message_age) > tracker.max_age {
            warn!("Message too old: source={}, sequence={}", source_id, sequence_number);
            
            self.record_security_event(
                SecurityEventType::TimestampAnomaly,
                source_id,
                "Message timestamp too old",
                TamperSeverity::Medium,
                HashMap::from([
                    ("sequence_number".to_string(), sequence_number.to_string()),
                    ("age_seconds".to_string(), current_time.saturating_sub(message_age).as_secs().to_string()),
                ]),
            ).await;
            
            return Ok(false);
        }
        
        // Check sequence number
        if let Some(&last_sequence) = tracker.last_sequences.get(source_id) {
            // Allow for out-of-order delivery within window
            if sequence_number <= last_sequence && 
               last_sequence - sequence_number > tracker.window_size {
                warn!("Replay attack detected: source={}, sequence={}, last={}", 
                      source_id, sequence_number, last_sequence);
                
                self.record_security_event(
                    SecurityEventType::ReplayAttack,
                    source_id,
                    "Sequence number indicates replay attack",
                    TamperSeverity::Critical,
                    HashMap::from([
                        ("sequence_number".to_string(), sequence_number.to_string()),
                        ("last_sequence".to_string(), last_sequence.to_string()),
                        ("delta".to_string(), (last_sequence - sequence_number).to_string()),
                    ]),
                ).await;
                
                return Ok(false);
            }
        }
        
        // Update sequence tracker
        tracker.last_sequences.insert(source_id.to_string(), sequence_number);
        
        // Cleanup old entries
        if tracker.last_cleanup.elapsed() > Duration::from_secs(300) {
            tracker.last_cleanup = Instant::now();
            // Keep only recent entries - this is a simplified cleanup
            if tracker.last_sequences.len() > 10000 {
                tracker.last_sequences.clear();
            }
        }
        
        debug!("Replay protection check passed");
        Ok(true)
    }
    
    /// Check rate limits for message source
    pub async fn check_rate_limit(
        &self,
        source_id: &str,
        message_type: &str,
    ) -> Result<bool> {
        if !self.config.rate_limiting {
            return Ok(true);
        }
        
        debug!("Checking rate limit for source: {}, type: {}", source_id, message_type);
        
        let mut limiter = self.rate_limiter.write().await;
        let now = Instant::now();
        
        // Get or create message counts for this source
        let counts = limiter.message_counts.entry(source_id.to_string())
            .or_insert_with(|| MessageCounts {
                window_start: now,
                ..Default::default()
            });
        
        // Get rate limit configuration
        let limit_config = limiter.limits.get("default").unwrap();
        
        // Check if we need to reset the window
        if now.duration_since(counts.window_start) >= limit_config.window_duration {
            counts.total = 0;
            counts.by_type.clear();
            counts.window_start = now;
        }
        
        // Check total rate limit
        if counts.total >= limit_config.max_messages {
            warn!("Rate limit exceeded for source: {}", source_id);
            
            self.record_security_event(
                SecurityEventType::RateLimitExceeded,
                source_id,
                "Total message rate limit exceeded",
                TamperSeverity::Medium,
                HashMap::from([
                    ("message_type".to_string(), message_type.to_string()),
                    ("total_count".to_string(), counts.total.to_string()),
                    ("limit".to_string(), limit_config.max_messages.to_string()),
                ]),
            ).await;
            
            return Ok(false);
        }
        
        // Check per-type rate limit if configured
        if let Some(&type_limit) = limit_config.type_limits.get(message_type) {
            let type_count = counts.by_type.get(message_type).unwrap_or(&0);
            if *type_count >= type_limit {
                warn!("Per-type rate limit exceeded: source={}, type={}", source_id, message_type);
                
                self.record_security_event(
                    SecurityEventType::RateLimitExceeded,
                    source_id,
                    "Per-type message rate limit exceeded",
                    TamperSeverity::Medium,
                    HashMap::from([
                        ("message_type".to_string(), message_type.to_string()),
                        ("type_count".to_string(), type_count.to_string()),
                        ("type_limit".to_string(), type_limit.to_string()),
                    ]),
                ).await;
                
                return Ok(false);
            }
        }
        
        // Update counters
        counts.total += 1;
        *counts.by_type.entry(message_type.to_string()).or_insert(0) += 1;
        
        // Cleanup old entries periodically
        if limiter.last_cleanup.elapsed() > Duration::from_secs(300) {
            limiter.last_cleanup = now;
            limiter.message_counts.retain(|_, counts| {
                now.duration_since(counts.window_start) < Duration::from_secs(3600)
            });
        }
        
        debug!("Rate limit check passed");
        Ok(true)
    }
    
    /// Validate message integrity
    pub async fn validate_message_integrity(
        &self,
        message_data: &[u8],
        expected_hash: &str,
    ) -> Result<bool> {
        debug!("Validating message integrity");
        
        let mut hasher = Sha256::new();
        hasher.update(message_data);
        let actual_hash = format!("{:x}", hasher.finalize());
        
        if actual_hash == expected_hash {
            debug!("Message integrity validation successful");
            Ok(true)
        } else {
            warn!("Message integrity validation failed: expected={}, actual={}", 
                  expected_hash, actual_hash);
            
            self.record_security_event(
                SecurityEventType::IntegrityFailure,
                "unknown",
                "Message integrity validation failed",
                TamperSeverity::High,
                HashMap::from([
                    ("expected_hash".to_string(), expected_hash.to_string()),
                    ("actual_hash".to_string(), actual_hash),
                    ("message_size".to_string(), message_data.len().to_string()),
                ]),
            ).await;
            
            Ok(false)
        }
    }
    
    /// Get security events for analysis
    pub async fn get_security_events(&self) -> Vec<SecurityEvent> {
        self.security_events.read().await.clone()
    }
    
    /// Clear security events (for maintenance)
    pub async fn clear_security_events(&self) {
        debug!("Clearing security events");
        self.security_events.write().await.clear();
    }
    
    /// Configure rate limits for specific message types
    pub async fn configure_rate_limits(
        &self,
        source_pattern: &str,
        limits: HashMap<String, u64>,
        window_duration: Duration,
    ) -> Result<()> {
        debug!("Configuring rate limits for pattern: {}", source_pattern);
        
        let mut limiter = self.rate_limiter.write().await;
        
        limiter.limits.insert(source_pattern.to_string(), RateLimit {
            max_messages: limits.get("total").copied().unwrap_or(1000),
            window_duration,
            type_limits: limits.into_iter()
                .filter(|(key, _)| key != "total")
                .collect(),
        });
        
        debug!("Rate limits configured successfully");
        Ok(())
    }
    
    // Private helper methods
    
    async fn record_security_event(
        &self,
        event_type: SecurityEventType,
        source: &str,
        description: &str,
        severity: TamperSeverity,
        context: HashMap<String, String>,
    ) {
        let event = SecurityEvent {
            timestamp: Instant::now(),
            event_type,
            source: source.to_string(),
            description: description.to_string(),
            context,
            severity,
        };
        
        // Log the event
        match event.severity {
            TamperSeverity::Critical => error!("Security event: {}", event.description),
            TamperSeverity::High => warn!("Security event: {}", event.description),
            TamperSeverity::Medium => warn!("Security event: {}", event.description),
            TamperSeverity::Low => debug!("Security event: {}", event.description),
        }
        
        // Store the event
        let mut events = self.security_events.write().await;
        events.push(event);
        
        // Keep only recent events (last 1000)
        if events.len() > 1000 {
            events.drain(0..events.len() - 1000);
        }
    }
}

/// Utility functions for communication security
pub mod utils {
    use super::*;
    
    /// Calculate SHA-256 hash of data
    pub fn calculate_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
    
    /// Generate secure random nonce
    pub fn generate_nonce() -> [u8; 32] {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }
    
    /// Validate timestamp within acceptable range
    pub fn validate_timestamp(timestamp: SystemTime, max_age: Duration) -> bool {
        if let Ok(message_time) = timestamp.duration_since(UNIX_EPOCH) {
            if let Ok(current_time) = SystemTime::now().duration_since(UNIX_EPOCH) {
                return current_time.saturating_sub(message_time) <= max_age;
            }
        }
        false
    }
    
    /// Extract key identifier from certificate or public key
    pub fn extract_key_id(public_key: &[u8]) -> String {
        let hash = calculate_sha256(public_key);
        format!("key_{}", &hash[..16]) // Use first 16 chars of hash as key ID
    }
}