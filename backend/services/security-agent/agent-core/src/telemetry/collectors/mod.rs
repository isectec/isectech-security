// iSECTECH Security Agent - Telemetry Collectors
// Production-grade platform-specific data collection implementations
// Copyright (c) 2024 iSECTECH. All rights reserved.

//! Platform-specific telemetry collectors for comprehensive security monitoring
//! 
//! This module provides production-grade collectors for:
//! - Windows: ETW (Event Tracing for Windows) integration
//! - Linux: eBPF kernel monitoring with custom programs
//! - macOS: EndpointSecurity framework integration
//! - Mobile: Platform-specific APIs for iOS and Android
//! - Cross-platform: Generic collectors for common functionality

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use super::{TelemetryEvent, CollectorStatus};
use super::performance::ResourceMetrics;

pub mod process;
pub mod network;
pub mod filesystem;
pub mod registry;
pub mod user_session;
pub mod application;
pub mod vulnerability;

// Platform-specific modules
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(target_os = "ios", target_os = "android"))]
pub mod mobile;

use process::ProcessCollector;
use network::NetworkCollector;
use filesystem::FileSystemCollector;
use registry::RegistryCollector;
use user_session::UserSessionCollector;
use application::ApplicationCollector;
use vulnerability::VulnerabilityCollector;

/// Main collector manager coordinating all data collection
pub struct CollectorManager {
    /// Agent configuration
    config: AgentConfig,
    /// Agent identifier
    agent_id: Uuid,
    /// Active collectors
    collectors: Arc<RwLock<HashMap<String, Box<dyn Collector + Send + Sync>>>>,
    /// Collector configurations
    collector_configs: Arc<RwLock<HashMap<String, CollectorConfig>>>,
    /// Event transmission channel
    event_tx: Arc<mpsc::Sender<TelemetryEvent>>,
    /// Collection statistics
    stats: Arc<RwLock<CollectionStatistics>>,
    /// Platform-specific manager
    platform_manager: Arc<PlatformCollectorManager>,
}

/// Generic collector trait for all data sources
#[async_trait::async_trait]
pub trait Collector {
    /// Get collector name
    fn name(&self) -> &str;
    
    /// Get collector type
    fn collector_type(&self) -> CollectorType;
    
    /// Start data collection
    async fn start(&mut self) -> Result<()>;
    
    /// Stop data collection
    async fn stop(&mut self) -> Result<()>;
    
    /// Check if collector is running
    async fn is_running(&self) -> bool;
    
    /// Check collector health
    async fn is_healthy(&self) -> bool;
    
    /// Get collector status
    async fn get_status(&self) -> CollectorStatus;
    
    /// Configure collector
    async fn configure(&mut self, config: serde_json::Value) -> Result<()>;
    
    /// Force immediate collection
    async fn force_collection(&mut self) -> Result<Vec<TelemetryEvent>>;
    
    /// Reduce collection frequency (performance constraints)
    async fn reduce_frequency(&mut self) -> Result<()>;
    
    /// Restore normal collection frequency
    async fn restore_frequency(&mut self) -> Result<()>;
    
    /// Get resource usage metrics
    async fn get_resource_metrics(&self) -> ResourceMetrics;
}

/// Types of collectors
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CollectorType {
    Process,
    Network,
    FileSystem,
    Registry,
    UserSession,
    Application,
    Vulnerability,
    System,
    Custom(String),
}

/// Collector configuration
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    /// Collector name
    pub name: String,
    /// Collector type
    pub collector_type: CollectorType,
    /// Collection interval
    pub collection_interval: Duration,
    /// Enable/disable state
    pub enabled: bool,
    /// Performance constraints
    pub performance_constraints: PerformanceConstraints,
    /// Platform-specific settings
    pub platform_config: PlatformConfig,
    /// Custom settings
    pub custom_settings: HashMap<String, serde_json::Value>,
}

/// Performance constraints for collectors
#[derive(Debug, Clone)]
pub struct PerformanceConstraints {
    /// Maximum CPU usage percentage
    pub max_cpu_percent: f64,
    /// Maximum memory usage in MB
    pub max_memory_mb: u64,
    /// Maximum collection frequency (minimum interval)
    pub min_collection_interval: Duration,
    /// Enable adaptive throttling
    pub adaptive_throttling: bool,
}

/// Platform-specific configuration
#[derive(Debug, Clone)]
pub enum PlatformConfig {
    Windows(WindowsConfig),
    Linux(LinuxConfig),
    MacOS(MacOSConfig),
    Mobile(MobileConfig),
    Generic,
}

/// Windows-specific configuration
#[derive(Debug, Clone)]
pub struct WindowsConfig {
    /// ETW provider GUIDs
    pub etw_providers: Vec<String>,
    /// WMI query settings
    pub wmi_settings: HashMap<String, String>,
    /// Performance counter settings
    pub perfcounter_settings: HashMap<String, String>,
    /// Registry monitoring keys
    pub registry_keys: Vec<String>,
}

/// Linux-specific configuration
#[derive(Debug, Clone)]
pub struct LinuxConfig {
    /// eBPF program paths
    pub ebpf_programs: Vec<String>,
    /// Kernel module settings
    pub kernel_settings: HashMap<String, String>,
    /// Procfs monitoring settings
    pub procfs_settings: HashMap<String, String>,
    /// Sysfs monitoring settings
    pub sysfs_settings: HashMap<String, String>,
}

/// macOS-specific configuration
#[derive(Debug, Clone)]
pub struct MacOSConfig {
    /// EndpointSecurity client settings
    pub es_client_settings: HashMap<String, String>,
    /// IOKit monitoring settings
    pub iokit_settings: HashMap<String, String>,
    /// System events to monitor
    pub system_events: Vec<String>,
}

/// Mobile platform configuration
#[derive(Debug, Clone)]
pub struct MobileConfig {
    /// Platform type (iOS/Android)
    pub platform: String,
    /// API level requirements
    pub api_level: u32,
    /// Permission requirements
    pub permissions: Vec<String>,
    /// Background collection settings
    pub background_settings: HashMap<String, String>,
}

/// Collection statistics
#[derive(Debug, Clone, Default)]
pub struct CollectionStatistics {
    /// Total events collected
    pub total_events: u64,
    /// Events by collector type
    pub events_by_collector: HashMap<CollectorType, u64>,
    /// Collection errors
    pub collection_errors: u64,
    /// Resource usage
    pub resource_usage: ResourceMetrics,
    /// Collection start time
    pub collection_start_time: Option<SystemTime>,
    /// Last collection time
    pub last_collection_time: Option<SystemTime>,
}

/// Platform-specific collector manager
pub struct PlatformCollectorManager {
    /// Platform type
    platform_type: PlatformType,
    /// Platform-specific collectors
    platform_collectors: HashMap<String, Box<dyn PlatformCollector + Send + Sync>>,
}

/// Platform types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformType {
    Windows,
    Linux,
    MacOS,
    IOS,
    Android,
    Unknown,
}

/// Platform-specific collector trait
#[async_trait::async_trait]
pub trait PlatformCollector {
    /// Initialize platform-specific resources
    async fn initialize(&mut self) -> Result<()>;
    
    /// Cleanup platform-specific resources
    async fn cleanup(&mut self) -> Result<()>;
    
    /// Get platform capabilities
    async fn get_capabilities(&self) -> Vec<String>;
    
    /// Validate platform requirements
    async fn validate_requirements(&self) -> Result<()>;
}

impl CollectorManager {
    /// Create a new collector manager
    pub async fn new(config: &AgentConfig, agent_id: Uuid) -> Result<Self> {
        info!("Initializing iSECTECH collector manager for agent {}", agent_id);
        
        // Create event channel
        let (event_tx, _) = mpsc::channel(10000);
        let event_tx = Arc::new(event_tx);
        
        // Initialize platform manager
        let platform_manager = Arc::new(
            PlatformCollectorManager::new().await?
        );
        
        let manager = Self {
            config: config.clone(),
            agent_id,
            collectors: Arc::new(RwLock::new(HashMap::new())),
            collector_configs: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            stats: Arc::new(RwLock::new(CollectionStatistics::default())),
            platform_manager,
        };
        
        // Initialize default collectors
        manager.initialize_default_collectors().await?;
        
        info!("iSECTECH collector manager initialized successfully");
        Ok(manager)
    }
    
    /// Start all collectors
    pub async fn start_all_collectors(&self) -> Result<()> {
        info!("Starting all telemetry collectors");
        
        let mut collectors = self.collectors.write().await;
        let mut started_count = 0;
        let mut error_count = 0;
        
        for (name, collector) in collectors.iter_mut() {
            debug!("Starting collector: {}", name);
            
            match collector.start().await {
                Ok(_) => {
                    started_count += 1;
                    debug!("Collector {} started successfully", name);
                }
                Err(e) => {
                    error_count += 1;
                    error!("Failed to start collector {}: {}", name, e);
                }
            }
        }
        
        // Update statistics
        let mut stats = self.stats.write().await;
        stats.collection_start_time = Some(SystemTime::now());
        
        info!("Started {}/{} collectors ({} errors)", 
              started_count, collectors.len(), error_count);
        
        if error_count > 0 && started_count == 0 {
            return Err(AgentError::Internal("Failed to start any collectors".to_string()));
        }
        
        Ok(())
    }
    
    /// Stop all collectors
    pub async fn stop_all_collectors(&self) -> Result<()> {
        info!("Stopping all telemetry collectors");
        
        let mut collectors = self.collectors.write().await;
        let mut stopped_count = 0;
        
        for (name, collector) in collectors.iter_mut() {
            debug!("Stopping collector: {}", name);
            
            match collector.stop().await {
                Ok(_) => {
                    stopped_count += 1;
                    debug!("Collector {} stopped successfully", name);
                }
                Err(e) => {
                    error!("Failed to stop collector {}: {}", name, e);
                }
            }
        }
        
        info!("Stopped {}/{} collectors", stopped_count, collectors.len());
        Ok(())
    }
    
    /// Configure a specific collector
    pub async fn configure_collector(
        &self,
        collector_name: &str,
        config: serde_json::Value,
    ) -> Result<()> {
        debug!("Configuring collector: {}", collector_name);
        
        let mut collectors = self.collectors.write().await;
        
        if let Some(collector) = collectors.get_mut(collector_name) {
            collector.configure(config).await?;
            debug!("Collector {} configured successfully", collector_name);
        } else {
            return Err(AgentError::Configuration(format!(
                "Collector not found: {}", collector_name
            )));
        }
        
        Ok(())
    }
    
    /// Get collector health status
    pub async fn get_collector_health(&self) -> HashMap<String, CollectorStatus> {
        let collectors = self.collectors.read().await;
        let mut health_status = HashMap::new();
        
        for (name, collector) in collectors.iter() {
            let status = collector.get_status().await;
            health_status.insert(name.clone(), status);
        }
        
        health_status
    }
    
    /// Restart a specific collector
    pub async fn restart_collector(&self, collector_name: &str) -> Result<()> {
        debug!("Restarting collector: {}", collector_name);
        
        let mut collectors = self.collectors.write().await;
        
        if let Some(collector) = collectors.get_mut(collector_name) {
            // Stop the collector
            if let Err(e) = collector.stop().await {
                warn!("Failed to stop collector {} during restart: {}", collector_name, e);
            }
            
            // Wait a moment for cleanup
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            // Start the collector
            collector.start().await?;
            
            info!("Collector {} restarted successfully", collector_name);
        } else {
            return Err(AgentError::Configuration(format!(
                "Collector not found: {}", collector_name
            )));
        }
        
        Ok(())
    }
    
    /// Reduce collection frequency for performance constraints
    pub async fn reduce_collection_frequency(&self) -> Result<()> {
        debug!("Reducing collection frequency for performance constraints");
        
        let mut collectors = self.collectors.write().await;
        
        for (name, collector) in collectors.iter_mut() {
            if let Err(e) = collector.reduce_frequency().await {
                warn!("Failed to reduce frequency for collector {}: {}", name, e);
            }
        }
        
        debug!("Collection frequency reduced");
        Ok(())
    }
    
    /// Restore normal collection frequency
    pub async fn restore_collection_frequency(&self) -> Result<()> {
        debug!("Restoring normal collection frequency");
        
        let mut collectors = self.collectors.write().await;
        
        for (name, collector) in collectors.iter_mut() {
            if let Err(e) = collector.restore_frequency().await {
                warn!("Failed to restore frequency for collector {}: {}", name, e);
            }
        }
        
        debug!("Collection frequency restored");
        Ok(())
    }
    
    /// Force immediate collection from all collectors
    pub async fn force_immediate_collection(&self) -> Result<()> {
        debug!("Forcing immediate collection from all collectors");
        
        let mut collectors = self.collectors.write().await;
        let mut total_events = 0;
        
        for (name, collector) in collectors.iter_mut() {
            match collector.force_collection().await {
                Ok(events) => {
                    total_events += events.len();
                    debug!("Collector {} produced {} events", name, events.len());
                    
                    // Send events through the channel
                    for event in events {
                        if let Err(e) = self.event_tx.try_send(event) {
                            warn!("Failed to send event from collector {}: {}", name, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to force collection from collector {}: {}", name, e);
                }
            }
        }
        
        debug!("Forced collection completed, {} total events", total_events);
        Ok(())
    }
    
    /// Get aggregated statistics from all collectors
    pub async fn get_aggregated_statistics(&self) -> Result<CollectionStatistics> {
        let collectors = self.collectors.read().await;
        let mut aggregated_stats = self.stats.read().await.clone();
        
        // Aggregate resource usage from all collectors
        let mut total_cpu = 0.0;
        let mut total_memory = 0;
        let mut total_network = 0;
        
        for collector in collectors.values() {
            let metrics = collector.get_resource_metrics().await;
            total_cpu += metrics.cpu_usage_percent;
            total_memory += metrics.memory_usage_mb;
            total_network += metrics.network_usage_kbps;
        }
        
        aggregated_stats.resource_usage = ResourceMetrics {
            cpu_usage_percent: total_cpu,
            memory_usage_mb: total_memory,
            disk_usage_mb: aggregated_stats.resource_usage.disk_usage_mb,
            network_usage_kbps: total_network,
            open_file_descriptors: aggregated_stats.resource_usage.open_file_descriptors,
            active_threads: aggregated_stats.resource_usage.active_threads,
        };
        
        Ok(aggregated_stats)
    }
    
    // Private implementation methods
    
    async fn initialize_default_collectors(&self) -> Result<()> {
        debug!("Initializing default collectors");
        
        let mut collectors = self.collectors.write().await;
        let mut configs = self.collector_configs.write().await;
        
        // Process collector
        let process_collector = ProcessCollector::new(&self.config, self.agent_id, Arc::clone(&self.event_tx)).await?;
        let process_config = self.create_default_config("process", CollectorType::Process);
        collectors.insert("process".to_string(), Box::new(process_collector));
        configs.insert("process".to_string(), process_config);
        
        // Network collector
        let network_collector = NetworkCollector::new(&self.config, self.agent_id, Arc::clone(&self.event_tx)).await?;
        let network_config = self.create_default_config("network", CollectorType::Network);
        collectors.insert("network".to_string(), Box::new(network_collector));
        configs.insert("network".to_string(), network_config);
        
        // File system collector
        let fs_collector = FileSystemCollector::new(&self.config, self.agent_id, Arc::clone(&self.event_tx)).await?;
        let fs_config = self.create_default_config("filesystem", CollectorType::FileSystem);
        collectors.insert("filesystem".to_string(), Box::new(fs_collector));
        configs.insert("filesystem".to_string(), fs_config);
        
        // Registry collector (Windows only)
        #[cfg(target_os = "windows")]
        {
            let registry_collector = RegistryCollector::new(&self.config, self.agent_id, Arc::clone(&self.event_tx)).await?;
            let registry_config = self.create_default_config("registry", CollectorType::Registry);
            collectors.insert("registry".to_string(), Box::new(registry_collector));
            configs.insert("registry".to_string(), registry_config);
        }
        
        // User session collector
        let session_collector = UserSessionCollector::new(&self.config, self.agent_id, Arc::clone(&self.event_tx)).await?;
        let session_config = self.create_default_config("user_session", CollectorType::UserSession);
        collectors.insert("user_session".to_string(), Box::new(session_collector));
        configs.insert("user_session".to_string(), session_config);
        
        // Application collector
        let app_collector = ApplicationCollector::new(&self.config, self.agent_id, Arc::clone(&self.event_tx)).await?;
        let app_config = self.create_default_config("application", CollectorType::Application);
        collectors.insert("application".to_string(), Box::new(app_collector));
        configs.insert("application".to_string(), app_config);
        
        // Vulnerability collector
        let vuln_collector = VulnerabilityCollector::new(&self.config, self.agent_id, Arc::clone(&self.event_tx)).await?;
        let vuln_config = self.create_default_config("vulnerability", CollectorType::Vulnerability);
        collectors.insert("vulnerability".to_string(), Box::new(vuln_collector));
        configs.insert("vulnerability".to_string(), vuln_config);
        
        debug!("Default collectors initialized: {}", collectors.len());
        Ok(())
    }
    
    fn create_default_config(&self, name: &str, collector_type: CollectorType) -> CollectorConfig {
        CollectorConfig {
            name: name.to_string(),
            collector_type,
            collection_interval: Duration::from_secs(30),
            enabled: true,
            performance_constraints: PerformanceConstraints {
                max_cpu_percent: 0.5,
                max_memory_mb: 20,
                min_collection_interval: Duration::from_secs(5),
                adaptive_throttling: true,
            },
            platform_config: self.get_platform_config(),
            custom_settings: HashMap::new(),
        }
    }
    
    fn get_platform_config(&self) -> PlatformConfig {
        #[cfg(target_os = "windows")]
        {
            PlatformConfig::Windows(WindowsConfig {
                etw_providers: vec![
                    "Microsoft-Windows-Kernel-Process".to_string(),
                    "Microsoft-Windows-Kernel-File".to_string(),
                    "Microsoft-Windows-Kernel-Network".to_string(),
                ],
                wmi_settings: HashMap::new(),
                perfcounter_settings: HashMap::new(),
                registry_keys: vec![
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                ],
            })
        }
        
        #[cfg(target_os = "linux")]
        {
            PlatformConfig::Linux(LinuxConfig {
                ebpf_programs: vec![
                    "/opt/isectech/ebpf/process_monitor.o".to_string(),
                    "/opt/isectech/ebpf/network_monitor.o".to_string(),
                    "/opt/isectech/ebpf/file_monitor.o".to_string(),
                ],
                kernel_settings: HashMap::new(),
                procfs_settings: HashMap::new(),
                sysfs_settings: HashMap::new(),
            })
        }
        
        #[cfg(target_os = "macos")]
        {
            PlatformConfig::MacOS(MacOSConfig {
                es_client_settings: HashMap::new(),
                iokit_settings: HashMap::new(),
                system_events: vec![
                    "ES_EVENT_TYPE_NOTIFY_EXEC".to_string(),
                    "ES_EVENT_TYPE_NOTIFY_EXIT".to_string(),
                    "ES_EVENT_TYPE_NOTIFY_OPEN".to_string(),
                ],
            })
        }
        
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            PlatformConfig::Mobile(MobileConfig {
                platform: std::env::consts::OS.to_string(),
                api_level: 30,
                permissions: vec![
                    "android.permission.READ_EXTERNAL_STORAGE".to_string(),
                    "android.permission.ACCESS_NETWORK_STATE".to_string(),
                ],
                background_settings: HashMap::new(),
            })
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos", target_os = "ios", target_os = "android")))]
        {
            PlatformConfig::Generic
        }
    }
}

impl PlatformCollectorManager {
    pub async fn new() -> Result<Self> {
        let platform_type = detect_platform();
        
        Ok(Self {
            platform_type,
            platform_collectors: HashMap::new(),
        })
    }
}

fn detect_platform() -> PlatformType {
    match std::env::consts::OS {
        "windows" => PlatformType::Windows,
        "linux" => PlatformType::Linux,
        "macos" => PlatformType::MacOS,
        "ios" => PlatformType::IOS,
        "android" => PlatformType::Android,
        _ => PlatformType::Unknown,
    }
}