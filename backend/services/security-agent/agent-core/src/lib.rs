// iSECTECH Security Agent Core Library
// Production-grade endpoint security framework
// Copyright (c) 2024 iSECTECH. All rights reserved.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

//! # iSECTECH Security Agent Core
//!
//! This crate provides the core functionality for the iSECTECH security agent,
//! a production-grade endpoint security solution with zero-trust architecture.
//!
//! ## Features
//!
//! - Cross-platform security monitoring (Windows, macOS, Linux, iOS, Android)
//! - Zero-trust architecture with encrypted communication
//! - Tamper-resistant design with code signing verification
//! - Real-time threat detection and policy enforcement
//! - Offline operation with encrypted local storage
//! - Self-updating mechanism with rollback capabilities
//! - Comprehensive telemetry and audit logging
//!
//! ## Architecture
//!
//! The agent is built around a modular architecture with the following core components:
//!
//! - **Agent**: Main orchestrator and lifecycle manager
//! - **Platform Manager**: OS-specific functionality abstraction
//! - **Crypto Manager**: Cryptographic operations and key management
//! - **Storage Manager**: Encrypted local data persistence
//! - **Security Manager**: Tamper resistance and integrity validation
//! - **Telemetry Manager**: Data collection and transmission
//! - **Update Manager**: Self-updating and version management
//!
//! ## Security Features
//!
//! - RSA-4096/Ed25519 digital signatures for code verification
//! - AES-256-GCM encryption for data at rest and in transit
//! - Certificate pinning for backend communication
//! - Memory protection against debugging and injection
//! - Integrity checking with cryptographic hashes
//! - Secure key derivation using Argon2

use std::sync::Arc;

pub mod agent;
pub mod collectors;
pub mod config;
pub mod crypto;
pub mod enforcement;
pub mod error;
pub mod metrics;
pub mod platform;
pub mod security;
pub mod storage;
pub mod telemetry;
pub mod updater;

// Re-export core types for easier consumption
pub use agent::{Agent, AgentState, AgentStatus};
pub use config::AgentConfig;
pub use crypto::CryptoManager;
pub use error::{AgentError, Result};
pub use platform::PlatformManager;
pub use security::SecurityManager;
pub use storage::StorageManager;
pub use telemetry::TelemetryManager;
pub use updater::UpdateManager;

/// Agent version information
pub mod version {
    /// Agent version string
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    
    /// Build timestamp
    pub const BUILD_DATE: &str = env!("BUILD_DATE");
    
    /// Git commit hash
    pub const GIT_COMMIT: &str = env!("GIT_COMMIT");
    
    /// Git branch
    pub const GIT_BRANCH: &str = env!("GIT_BRANCH");
    
    /// Build profile
    pub const BUILD_PROFILE: &str = env!("BUILD_PROFILE");
}

/// Cryptographic constants for iSECTECH implementation
pub mod crypto_constants {
    /// AES key size in bytes (256-bit)
    pub const AES_KEY_SIZE: usize = 32;
    
    /// AES-GCM nonce size in bytes (96-bit)
    pub const AES_GCM_NONCE_SIZE: usize = 12;
    
    /// AES-GCM tag size in bytes (128-bit)
    pub const AES_GCM_TAG_SIZE: usize = 16;
    
    /// Ed25519 signature size in bytes
    pub const ED25519_SIGNATURE_SIZE: usize = 64;
    
    /// Ed25519 public key size in bytes
    pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
    
    /// SHA-256 hash size in bytes
    pub const SHA256_HASH_SIZE: usize = 32;
    
    /// Argon2 salt size in bytes
    pub const ARGON2_SALT_SIZE: usize = 32;
    
    /// Minimum key derivation iterations
    pub const MIN_PBKDF_ITERATIONS: u32 = 100_000;
}

/// Network communication constants
pub mod network_constants {
    use std::time::Duration;
    
    /// Default connection timeout
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// Default request timeout
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    
    /// Heartbeat interval
    pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
    
    /// Maximum message size (10MB)
    pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
    
    /// Default TLS version
    pub const TLS_VERSION: &str = "1.3";
}

/// Resource usage limits
pub mod resource_limits {
    /// Maximum CPU usage percentage
    pub const MAX_CPU_PERCENT: f64 = 2.0;
    
    /// Maximum memory usage in MB
    pub const MAX_MEMORY_MB: usize = 100;
    
    /// Maximum disk usage in MB
    pub const MAX_DISK_MB: usize = 50;
    
    /// Maximum network bandwidth in Kbps
    pub const MAX_NETWORK_KBPS: usize = 1000;
}

/// Security policy constants
pub mod security_policy {
    use std::time::Duration;
    
    /// Certificate validation interval
    pub const CERT_VALIDATION_INTERVAL: Duration = Duration::from_secs(3600);
    
    /// Integrity check interval
    pub const INTEGRITY_CHECK_INTERVAL: Duration = Duration::from_secs(300);
    
    /// Tamper detection scan interval
    pub const TAMPER_SCAN_INTERVAL: Duration = Duration::from_secs(60);
    
    /// Security event retention period
    pub const EVENT_RETENTION_DAYS: u32 = 90;
    
    /// Maximum failed authentication attempts
    pub const MAX_AUTH_FAILURES: u32 = 3;
}

/// Initialize the agent library with security validation
pub async fn initialize() -> Result<()> {
    // Perform early security checks
    security::early_tamper_check()?;
    
    // Initialize cryptographic subsystem
    crypto::initialize_crypto_provider()?;
    
    // Validate build integrity
    security::validate_build_integrity().await?;
    
    // Initialize platform-specific security features
    platform::initialize_platform_security().await?;
    
    tracing::info!("iSECTECH Agent Core initialized successfully");
    Ok(())
}

/// Shutdown the agent library and cleanup resources
pub async fn shutdown() -> Result<()> {
    // Cleanup platform-specific resources
    platform::cleanup_platform_resources().await?;
    
    // Secure memory cleanup
    crypto::cleanup_crypto_provider()?;
    
    tracing::info!("iSECTECH Agent Core shutdown complete");
    Ok(())
}

/// Agent builder for simplified configuration
pub struct AgentBuilder {
    config: Option<AgentConfig>,
    agent_id: Option<uuid::Uuid>,
    custom_crypto: Option<Arc<CryptoManager>>,
    custom_platform: Option<Arc<PlatformManager>>,
}

impl AgentBuilder {
    /// Create a new agent builder
    pub fn new() -> Self {
        Self {
            config: None,
            agent_id: None,
            custom_crypto: None,
            custom_platform: None,
        }
    }
    
    /// Set the agent configuration
    pub fn with_config(mut self, config: AgentConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Set a custom agent ID
    pub fn with_agent_id(mut self, agent_id: uuid::Uuid) -> Self {
        self.agent_id = Some(agent_id);
        self
    }
    
    /// Set a custom crypto manager (for testing)
    pub fn with_crypto_manager(mut self, crypto: Arc<CryptoManager>) -> Self {
        self.custom_crypto = Some(crypto);
        self
    }
    
    /// Set a custom platform manager (for testing)
    pub fn with_platform_manager(mut self, platform: Arc<PlatformManager>) -> Self {
        self.custom_platform = Some(platform);
        self
    }
    
    /// Build the agent with the configured options
    pub async fn build(self) -> Result<Agent> {
        let config = self.config.ok_or_else(|| {
            AgentError::Configuration("Configuration is required".to_string())
        })?;
        
        let agent_id = self.agent_id.unwrap_or_else(uuid::Uuid::new_v4);
        
        // Initialize managers
        let platform_manager = match self.custom_platform {
            Some(platform) => platform,
            None => Arc::new(PlatformManager::new(&config).await?),
        };
        
        let crypto_manager = match self.custom_crypto {
            Some(crypto) => crypto,
            None => Arc::new(CryptoManager::new(&config).await?),
        };
        
        let storage_manager = Arc::new(
            StorageManager::new(&config, &crypto_manager).await?
        );
        
        let security_manager = Arc::new(
            SecurityManager::new(&config, &crypto_manager).await?
        );
        
        let telemetry_manager = Arc::new(
            TelemetryManager::new(&config, &storage_manager).await?
        );
        
        let update_manager = Arc::new(
            UpdateManager::new(&config, &crypto_manager, &security_manager).await?
        );
        
        Agent::new(
            agent_id,
            config,
            platform_manager,
            crypto_manager,
            storage_manager,
            security_manager,
            telemetry_manager,
            update_manager,
        ).await
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Feature flags for conditional compilation
pub mod features {
    /// Check if network monitoring is enabled
    pub fn network_monitoring_enabled() -> bool {
        cfg!(feature = "network-monitoring")
    }
    
    /// Check if file monitoring is enabled
    pub fn file_monitoring_enabled() -> bool {
        cfg!(feature = "file-monitoring")
    }
    
    /// Check if process monitoring is enabled
    pub fn process_monitoring_enabled() -> bool {
        cfg!(feature = "process-monitoring")
    }
    
    /// Check if registry monitoring is enabled
    pub fn registry_monitoring_enabled() -> bool {
        cfg!(feature = "registry-monitoring")
    }
    
    /// Check if user monitoring is enabled
    pub fn user_monitoring_enabled() -> bool {
        cfg!(feature = "user-monitoring")
    }
    
    /// Check if vulnerability scanning is enabled
    pub fn vulnerability_scanning_enabled() -> bool {
        cfg!(feature = "vulnerability-scanning")
    }
    
    /// Check if tamper resistance is enabled
    pub fn tamper_resistance_enabled() -> bool {
        cfg!(feature = "tamper-resistance")
    }
    
    /// Check if anti-debugging is enabled
    pub fn anti_debugging_enabled() -> bool {
        cfg!(feature = "anti-debugging")
    }
    
    /// Check if kernel integration is enabled
    pub fn kernel_integration_enabled() -> bool {
        cfg!(feature = "kernel-integration")
    }
    
    /// Check if mobile support is enabled
    pub fn mobile_support_enabled() -> bool {
        cfg!(feature = "mobile-support")
    }
}

/// Utility functions for agent operations
pub mod utils {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    /// Get current timestamp in milliseconds
    pub fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    
    /// Get current timestamp in seconds
    pub fn current_timestamp_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    /// Generate a random nonce
    pub fn generate_nonce() -> [u8; 16] {
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }
    
    /// Secure memory zeroing (constant-time)
    pub fn secure_zero(data: &mut [u8]) {
        use zeroize::Zeroize;
        data.zeroize();
    }
    
    /// Format bytes as human-readable string
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size, UNITS[unit_index])
        }
    }
    
    /// Calculate file hash (SHA-256)
    pub async fn calculate_file_hash(path: &std::path::Path) -> crate::Result<String> {
        use sha2::{Sha256, Digest};
        use tokio::io::AsyncReadExt;
        
        let mut file = tokio::fs::File::open(path).await
            .map_err(|e| crate::AgentError::Storage(format!("Failed to open file: {}", e)))?;
        
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer).await
                .map_err(|e| crate::AgentError::Storage(format!("Failed to read file: {}", e)))?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Validate email address format
    pub fn is_valid_email(email: &str) -> bool {
        email.contains('@') && email.len() < 255 && !email.starts_with('@') && !email.ends_with('@')
    }
    
    /// Validate UUID format
    pub fn is_valid_uuid(uuid_str: &str) -> bool {
        uuid::Uuid::parse_str(uuid_str).is_ok()
    }
}

/// Test utilities (only available in test builds)
#[cfg(test)]
pub mod test_utils {
    use super::*;
    use tempfile::TempDir;
    
    /// Create a test configuration
    pub fn create_test_config() -> AgentConfig {
        let temp_dir = TempDir::new().unwrap();
        AgentConfig::test_default(temp_dir.path())
    }
    
    /// Create a test agent
    pub async fn create_test_agent() -> Result<Agent> {
        let config = create_test_config();
        AgentBuilder::new()
            .with_config(config)
            .build()
            .await
    }
    
    /// Create test crypto manager
    pub async fn create_test_crypto_manager() -> Result<CryptoManager> {
        let config = create_test_config();
        CryptoManager::new(&config).await
    }
    
    /// Generate test data
    pub fn generate_test_data(size: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut data = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
}