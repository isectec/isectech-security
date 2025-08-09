// iSECTECH Security Agent - Configuration Management
// Production-grade configuration with security validation
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::path::{Path, PathBuf};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::error::{AgentError, Result};

/// Main agent configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Agent identification and metadata
    pub agent: AgentIdentity,
    /// Cryptographic settings
    pub crypto: CryptoConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Network communication settings
    pub network: NetworkConfig,
    /// Security policy settings
    pub security: SecurityConfig,
    /// Data collection configuration
    pub collectors: CollectorsConfig,
    /// Policy enforcement settings
    pub enforcement: EnforcementConfig,
    /// Runtime behavior settings
    pub runtime: RuntimeConfig,
    /// Resource limits
    pub resources: ResourceConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub name: String,
    pub version: String,
    pub environment: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub key_derivation_iterations: u32,
    pub encryption_algorithm: String,
    pub signature_algorithm: String,
    pub cert_validation_enabled: bool,
    pub cert_pinning_enabled: bool,
    pub trusted_ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_directory: PathBuf,
    pub encryption_enabled: bool,
    pub backup_enabled: bool,
    pub retention_days: u32,
    pub max_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub backend_url: String,
    pub tls_enabled: bool,
    pub mtls_enabled: bool,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
    pub ca_cert_path: Option<PathBuf>,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub tamper_resistance_enabled: bool,
    pub anti_debugging_enabled: bool,
    pub code_signing_enabled: bool,
    pub memory_protection_enabled: bool,
    pub integrity_check_interval_secs: u64,
    pub max_auth_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorsConfig {
    pub process_monitoring: bool,
    pub network_monitoring: bool,
    pub file_monitoring: bool,
    pub registry_monitoring: bool,
    pub user_monitoring: bool,
    pub sampling_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    pub enabled: bool,
    pub enforcement_mode: String, // "enforce", "monitor", "disabled"
    pub dry_run: bool,
    pub response_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub run_as_daemon: bool,
    pub auto_start: bool,
    pub update_check_enabled: bool,
    pub update_check_interval_hours: u64,
    pub offline_mode_enabled: bool,
    pub max_offline_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub max_cpu_percent: f64,
    pub max_memory_mb: u64,
    pub max_disk_mb: u64,
    pub max_network_kbps: u64,
    pub monitor_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output_file: Option<PathBuf>,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub structured_logging: bool,
}

impl AgentConfig {
    /// Load configuration from file
    pub async fn load(path: &str) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await
            .map_err(|e| AgentError::Configuration(format!("Failed to read config file: {}", e)))?;

        let config: AgentConfig = if path.ends_with(".toml") {
            toml::from_str(&content)
                .map_err(|e| AgentError::Configuration(format!("Invalid TOML: {}", e)))?
        } else if path.ends_with(".yaml") || path.ends_with(".yml") {
            serde_yaml::from_str(&content)?
        } else {
            return Err(AgentError::Configuration("Unsupported config format".to_string()));
        };

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate agent identity
        if self.agent.name.is_empty() {
            return Err(AgentError::Configuration("Agent name cannot be empty".to_string()));
        }

        // Validate crypto settings
        if self.crypto.key_derivation_iterations < 10000 {
            return Err(AgentError::Configuration("Key derivation iterations too low".to_string()));
        }

        // Validate network settings
        if self.network.backend_url.is_empty() {
            return Err(AgentError::Configuration("Backend URL is required".to_string()));
        }

        // Validate resource limits
        if self.resources.max_cpu_percent <= 0.0 || self.resources.max_cpu_percent > 100.0 {
            return Err(AgentError::Configuration("Invalid CPU limit".to_string()));
        }

        if self.resources.max_memory_mb == 0 {
            return Err(AgentError::Configuration("Memory limit must be greater than 0".to_string()));
        }

        // Validate file paths exist if specified
        if let Some(ref path) = self.network.client_cert_path {
            if !path.exists() {
                return Err(AgentError::Configuration(format!("Client cert not found: {:?}", path)));
            }
        }

        Ok(())
    }

    /// Get default production configuration
    pub fn production_default() -> Self {
        Self {
            agent: AgentIdentity {
                name: "iSECTECH-Agent".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                environment: "production".to_string(),
                tags: vec![],
            },
            crypto: CryptoConfig {
                key_derivation_iterations: 100_000,
                encryption_algorithm: "AES-256-GCM".to_string(),
                signature_algorithm: "Ed25519".to_string(),
                cert_validation_enabled: true,
                cert_pinning_enabled: true,
                trusted_ca_path: Some("/etc/isectech/ca.pem".into()),
            },
            storage: StorageConfig {
                data_directory: "/var/lib/isectech".into(),
                encryption_enabled: true,
                backup_enabled: true,
                retention_days: 90,
                max_size_mb: 1024,
            },
            network: NetworkConfig {
                backend_url: "https://api.isectech.com".to_string(),
                tls_enabled: true,
                mtls_enabled: true,
                client_cert_path: Some("/etc/isectech/client.pem".into()),
                client_key_path: Some("/etc/isectech/client.key".into()),
                ca_cert_path: Some("/etc/isectech/ca.pem".into()),
                connect_timeout_secs: 10,
                request_timeout_secs: 30,
                heartbeat_interval_secs: 30,
            },
            security: SecurityConfig {
                tamper_resistance_enabled: true,
                anti_debugging_enabled: true,
                code_signing_enabled: true,
                memory_protection_enabled: true,
                integrity_check_interval_secs: 300,
                max_auth_failures: 3,
            },
            collectors: CollectorsConfig {
                process_monitoring: true,
                network_monitoring: true,
                file_monitoring: true,
                registry_monitoring: cfg!(windows),
                user_monitoring: true,
                sampling_rate: 1.0,
            },
            enforcement: EnforcementConfig {
                enabled: true,
                enforcement_mode: "enforce".to_string(),
                dry_run: false,
                response_delay_ms: 1000,
            },
            runtime: RuntimeConfig {
                run_as_daemon: true,
                auto_start: true,
                update_check_enabled: true,
                update_check_interval_hours: 24,
                offline_mode_enabled: true,
                max_offline_hours: 24,
            },
            resources: ResourceConfig {
                max_cpu_percent: 2.0,
                max_memory_mb: 100,
                max_disk_mb: 50,
                max_network_kbps: 1000,
                monitor_interval_secs: 10,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                output_file: Some("/var/log/isectech/agent.log".into()),
                max_file_size_mb: 100,
                max_files: 10,
                structured_logging: true,
            },
        }
    }

    /// Get test configuration
    #[cfg(test)]
    pub fn test_default(temp_dir: &Path) -> Self {
        let mut config = Self::production_default();
        config.storage.data_directory = temp_dir.to_path_buf();
        config.network.tls_enabled = false;
        config.network.mtls_enabled = false;
        config.security.tamper_resistance_enabled = false;
        config.security.anti_debugging_enabled = false;
        config.logging.output_file = None;
        config
    }

    /// Get connect timeout as Duration
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.network.connect_timeout_secs)
    }

    /// Get request timeout as Duration
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.network.request_timeout_secs)
    }

    /// Get heartbeat interval as Duration
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.network.heartbeat_interval_secs)
    }

    /// Get integrity check interval as Duration
    pub fn integrity_check_interval(&self) -> Duration {
        Duration::from_secs(self.security.integrity_check_interval_secs)
    }

    /// Check if running in production mode
    pub fn is_production(&self) -> bool {
        self.agent.environment == "production"
    }

    /// Check if TLS is required
    pub fn requires_tls(&self) -> bool {
        self.network.tls_enabled || self.network.mtls_enabled
    }
}