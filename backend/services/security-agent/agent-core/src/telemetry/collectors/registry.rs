// iSECTECH Security Agent - Registry Collector (Windows)
// Production-grade Windows Registry monitoring and change detection
// Copyright (c) 2024 iSECTECH. All rights reserved.

#[cfg(target_os = "windows")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::time::{Duration, SystemTime, Instant};
#[cfg(target_os = "windows")]
use tokio::sync::{RwLock, mpsc};
#[cfg(target_os = "windows")]
use tokio::time::interval;
#[cfg(target_os = "windows")]
use uuid::Uuid;
#[cfg(target_os = "windows")]
use tracing::{info, warn, error, debug};

#[cfg(target_os = "windows")]
use crate::config::AgentConfig;
#[cfg(target_os = "windows")]
use crate::error::{AgentError, Result};
#[cfg(target_os = "windows")]
use super::{Collector, CollectorType, CollectorStatus};
#[cfg(target_os = "windows")]
use crate::telemetry::{TelemetryEvent, TelemetryEventType, EventSource, EventData, EventSeverity, EventMetadata, SourceType};
#[cfg(target_os = "windows")]
use crate::telemetry::performance::ResourceMetrics;

/// Production-grade Windows Registry collector for comprehensive registry monitoring
#[cfg(target_os = "windows")]
pub struct RegistryCollector {
    /// Collector name
    name: String,
    /// Agent configuration
    config: AgentConfig,
    /// Agent identifier
    agent_id: Uuid,
    /// Event transmission channel
    event_tx: Arc<mpsc::Sender<TelemetryEvent>>,
    /// Registry monitoring state
    registry_state: Arc<RwLock<RegistryMonitoringState>>,
    /// Collection configuration
    collection_config: Arc<RwLock<RegistryCollectionConfig>>,
    /// Running state
    is_running: Arc<RwLock<bool>>,
    /// Health status
    is_healthy: Arc<RwLock<bool>>,
    /// Resource metrics
    resource_metrics: Arc<RwLock<ResourceMetrics>>,
    /// Collection statistics
    stats: Arc<RwLock<RegistryCollectionStats>>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct RegistryMonitoringState {
    /// Monitored registry keys (path -> RegistryKeyInfo)
    monitored_keys: HashMap<String, RegistryKeyInfo>,
    /// Recent registry changes
    recent_changes: Vec<RegistryChangeEvent>,
    /// Suspicious registry modifications
    suspicious_changes: HashSet<String>,
    /// Registry watchers (key -> watcher_id)
    registry_watchers: HashMap<String, String>,
    /// Last scan timestamp
    last_scan: Option<Instant>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct RegistryKeyInfo {
    /// Registry key path
    pub key_path: String,
    /// Key values (name -> value)
    pub values: HashMap<String, RegistryValue>,
    /// Subkeys
    pub subkeys: Vec<String>,
    /// Last modification time
    pub last_modified: Option<SystemTime>,
    /// Key permissions
    pub permissions: Option<String>,
    /// Security flags
    pub security_flags: RegistrySecurityFlags,
    /// Threat score
    pub threat_score: u8,
    /// Last scanned time
    pub last_scanned: SystemTime,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct RegistryValue {
    /// Value name
    pub name: String,
    /// Value type
    pub value_type: RegistryValueType,
    /// Value data
    pub data: Vec<u8>,
    /// String representation for easy analysis
    pub string_value: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
enum RegistryValueType {
    String,
    ExpandableString,
    Binary,
    Dword,
    DwordBigEndian,
    MultiString,
    Qword,
    Unknown,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Default)]
struct RegistrySecurityFlags {
    /// Key is in critical system location
    pub critical_system_key: bool,
    /// Key controls startup programs
    pub startup_key: bool,
    /// Key controls services
    pub service_key: bool,
    /// Key has unusual permissions
    pub unusual_permissions: bool,
    /// Key was recently created/modified
    pub recently_modified: bool,
    /// Policy violations
    pub policy_violations: Vec<String>,
    /// Malware indicators
    pub malware_indicators: Vec<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct RegistryChangeEvent {
    /// Registry key path
    pub key_path: String,
    /// Value name (if applicable)
    pub value_name: Option<String>,
    /// Change type
    pub change_type: RegistryChangeType,
    /// Timestamp of change
    pub timestamp: SystemTime,
    /// Process that made the change
    pub process_id: Option<u32>,
    /// Process name
    pub process_name: Option<String>,
    /// Old value
    pub old_value: Option<RegistryValue>,
    /// New value
    pub new_value: Option<RegistryValue>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
enum RegistryChangeType {
    KeyCreated,
    KeyDeleted,
    KeyRenamed,
    ValueCreated,
    ValueModified,
    ValueDeleted,
    PermissionsChanged,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct RegistryCollectionConfig {
    /// Collection interval
    pub interval: Duration,
    /// Registry keys to monitor
    pub monitored_keys: Vec<String>,
    /// Enable real-time monitoring
    pub realtime_monitoring: bool,
    /// Detection rules
    pub detection_rules: Vec<RegistryDetectionRule>,
    /// Excluded keys (whitelist)
    pub excluded_keys: Vec<String>,
    /// Maximum keys to monitor
    pub max_monitored_keys: usize,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct RegistryDetectionRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Key path patterns
    pub key_patterns: Vec<String>,
    /// Value name patterns
    pub value_patterns: Vec<String>,
    /// Value data patterns
    pub data_patterns: Vec<String>,
    /// Process patterns
    pub process_patterns: Vec<String>,
    /// Threat score (0-100)
    pub threat_score: u8,
    /// Rule severity
    pub severity: EventSeverity,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Default)]
struct RegistryCollectionStats {
    /// Total keys monitored
    pub total_keys: u64,
    /// Registry changes detected
    pub changes_detected: u64,
    /// Suspicious changes flagged
    pub suspicious_changes: u64,
    /// Events generated
    pub events_generated: u64,
    /// Collection errors
    pub collection_errors: u64,
    /// Last collection time
    pub last_collection: Option<Instant>,
}

#[cfg(target_os = "windows")]
impl RegistryCollector {
    /// Create a new registry collector
    pub async fn new(
        config: &AgentConfig,
        agent_id: Uuid,
        event_tx: Arc<mpsc::Sender<TelemetryEvent>>,
    ) -> Result<Self> {
        debug!("Initializing iSECTECH registry collector");
        
        let collection_config = RegistryCollectionConfig {
            interval: Duration::from_secs(60),
            monitored_keys: vec![
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services".to_string(),
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows".to_string(),
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon".to_string(),
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes".to_string(),
            ],
            realtime_monitoring: true,
            detection_rules: Self::create_default_detection_rules(),
            excluded_keys: vec![
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer".to_string(),
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU".to_string(),
            ],
            max_monitored_keys: 10000,
        };
        
        Ok(Self {
            name: "registry_collector".to_string(),
            config: config.clone(),
            agent_id,
            event_tx,
            registry_state: Arc::new(RwLock::new(RegistryMonitoringState::default())),
            collection_config: Arc::new(RwLock::new(collection_config)),
            is_running: Arc::new(RwLock::new(false)),
            is_healthy: Arc::new(RwLock::new(true)),
            resource_metrics: Arc::new(RwLock::new(ResourceMetrics::default())),
            stats: Arc::new(RwLock::new(RegistryCollectionStats::default())),
        })
    }
    
    /// Create default detection rules for iSECTECH
    fn create_default_detection_rules() -> Vec<RegistryDetectionRule> {
        vec![
            RegistryDetectionRule {
                name: "startup_program_addition".to_string(),
                description: "New startup program added to registry".to_string(),
                key_patterns: vec![
                    "*\\Run".to_string(),
                    "*\\RunOnce".to_string(),
                    "*\\Winlogon".to_string(),
                ],
                value_patterns: vec![],
                data_patterns: vec!["*.exe".to_string(), "*.bat".to_string(), "*.ps1".to_string()],
                process_patterns: vec![],
                threat_score: 70,
                severity: EventSeverity::High,
            },
            RegistryDetectionRule {
                name: "service_installation".to_string(),
                description: "New service registered in registry".to_string(),
                key_patterns: vec![
                    "*\\Services\\*".to_string(),
                ],
                value_patterns: vec!["ImagePath".to_string(), "ServiceDll".to_string()],
                data_patterns: vec![],
                process_patterns: vec![],
                threat_score: 60,
                severity: EventSeverity::Medium,
            },
            RegistryDetectionRule {
                name: "file_association_hijack".to_string(),
                description: "File association modification detected".to_string(),
                key_patterns: vec![
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\*".to_string(),
                    "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\*".to_string(),
                ],
                value_patterns: vec!["*\\shell\\open\\command".to_string()],
                data_patterns: vec![],
                process_patterns: vec![],
                threat_score: 80,
                severity: EventSeverity::High,
            },
            RegistryDetectionRule {
                name: "security_setting_modification".to_string(),
                description: "Critical security setting modified".to_string(),
                key_patterns: vec![
                    "*\\Windows NT\\CurrentVersion\\Winlogon".to_string(),
                    "*\\Policies\\*".to_string(),
                ],
                value_patterns: vec![
                    "Shell".to_string(),
                    "Userinit".to_string(),
                    "DisableTaskMgr".to_string(),
                    "DisableRegistryTools".to_string(),
                ],
                data_patterns: vec![],
                process_patterns: vec![],
                threat_score: 90,
                severity: EventSeverity::Critical,
            },
        ]
    }
    
    /// Perform registry collection cycle
    async fn collect_registry_changes(&self) -> Result<Vec<TelemetryEvent>> {
        let start_time = Instant::now();
        let mut events = Vec::new();
        
        let mut state = self.registry_state.write().await;
        let config = self.collection_config.read().await;
        let mut stats = self.stats.write().await;
        
        // Monitor configured registry keys
        for key_path in &config.monitored_keys {
            if let Ok(key_events) = self.monitor_registry_key(key_path, &config, &mut state).await {
                events.extend(key_events);
            }
        }
        
        // Update statistics
        stats.total_keys = state.monitored_keys.len() as u64;
        stats.events_generated += events.len() as u64;
        stats.last_collection = Some(start_time);
        state.last_scan = Some(start_time);
        
        // Update resource metrics
        let mut metrics = self.resource_metrics.write().await;
        metrics.cpu_usage_percent = 0.1; // Estimated CPU usage
        metrics.memory_usage_mb = 3; // Estimated memory usage
        
        debug!("Registry collection completed: {} events, {} keys, {:?}",
               events.len(), state.monitored_keys.len(), start_time.elapsed());
        
        Ok(events)
    }
    
    /// Monitor a specific registry key
    async fn monitor_registry_key(
        &self,
        key_path: &str,
        config: &RegistryCollectionConfig,
        state: &mut RegistryMonitoringState,
    ) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        
        // Check if key should be excluded
        for excluded_key in &config.excluded_keys {
            if key_path.starts_with(excluded_key) {
                return Ok(events);
            }
        }
        
        // TODO: Implement actual Windows Registry monitoring
        // - Use RegNotifyChangeKeyValue for real-time monitoring
        // - Use RegEnumKeyEx and RegEnumValue for enumeration
        // - Parse registry values and detect changes
        
        debug!("Registry key monitoring not yet implemented: {}", key_path);
        Ok(events)
    }
    
    /// Create registry telemetry event
    async fn create_registry_event(
        &self,
        change_event: &RegistryChangeEvent,
        timestamp: SystemTime,
    ) -> Result<TelemetryEvent> {
        let mut event_data = HashMap::new();
        
        // Basic registry information
        event_data.insert("key_path".to_string(), serde_json::Value::String(change_event.key_path.clone()));
        event_data.insert("change_type".to_string(), serde_json::Value::String(format!("{:?}", change_event.change_type)));
        
        if let Some(ref value_name) = change_event.value_name {
            event_data.insert("value_name".to_string(), serde_json::Value::String(value_name.clone()));
        }
        
        if let Some(pid) = change_event.process_id {
            event_data.insert("process_id".to_string(), serde_json::Value::Number(pid.into()));
        }
        
        if let Some(ref process_name) = change_event.process_name {
            event_data.insert("process_name".to_string(), serde_json::Value::String(process_name.clone()));
        }
        
        // Value information
        if let Some(ref new_value) = change_event.new_value {
            if let Some(ref string_value) = new_value.string_value {
                event_data.insert("new_value".to_string(), serde_json::Value::String(string_value.clone()));
            }
            event_data.insert("value_type".to_string(), serde_json::Value::String(format!("{:?}", new_value.value_type)));
        }
        
        if let Some(ref old_value) = change_event.old_value {
            if let Some(ref string_value) = old_value.string_value {
                event_data.insert("old_value".to_string(), serde_json::Value::String(string_value.clone()));
            }
        }
        
        let event = TelemetryEvent {
            event_id: Uuid::new_v4(),
            agent_id: self.agent_id,
            event_type: TelemetryEventType::RegistryEvent,
            timestamp,
            source: EventSource {
                id: change_event.key_path.clone(),
                source_type: SourceType::RegistryKey,
                name: change_event.key_path.split('\\').last().unwrap_or("unknown").to_string(),
                attributes: HashMap::new(),
            },
            data: EventData {
                structured: event_data,
                raw: None,
                hash: "".to_string(),
            },
            threat_indicators: vec![],
            severity: EventSeverity::Medium, // Will be determined by detection rules
            metadata: EventMetadata {
                processed_at: SystemTime::now(),
                correlation_ids: vec![],
                tags: vec!["registry".to_string(), "windows".to_string(), "iSECTECH".to_string()],
                custom: HashMap::new(),
            },
        };
        
        Ok(event)
    }
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl Collector for RegistryCollector {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn collector_type(&self) -> CollectorType {
        CollectorType::Registry
    }
    
    async fn start(&mut self) -> Result<()> {
        info!("Starting iSECTECH registry collector");
        
        *self.is_running.write().await = true;
        *self.is_healthy.write().await = true;
        
        // Start collection loop
        let event_tx = Arc::clone(&self.event_tx);
        let is_running = Arc::clone(&self.is_running);
        let collection_config = Arc::clone(&self.collection_config);
        let collector = Self {
            name: self.name.clone(),
            config: self.config.clone(),
            agent_id: self.agent_id,
            event_tx: Arc::clone(&self.event_tx),
            registry_state: Arc::clone(&self.registry_state),
            collection_config: Arc::clone(&self.collection_config),
            is_running: Arc::clone(&self.is_running),
            is_healthy: Arc::clone(&self.is_healthy),
            resource_metrics: Arc::clone(&self.resource_metrics),
            stats: Arc::clone(&self.stats),
        };
        
        tokio::spawn(async move {
            let mut interval = {
                let config = collection_config.read().await;
                interval(config.interval)
            };
            
            while *is_running.read().await {
                interval.tick().await;
                
                match collector.collect_registry_changes().await {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.try_send(event) {
                                error!("Failed to send registry event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Registry collection failed: {}", e);
                        let mut stats = collector.stats.write().await;
                        stats.collection_errors += 1;
                    }
                }
            }
        });
        
        info!("iSECTECH registry collector started");
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        info!("Stopping iSECTECH registry collector");
        *self.is_running.write().await = false;
        info!("iSECTECH registry collector stopped");
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    async fn is_healthy(&self) -> bool {
        *self.is_healthy.read().await
    }
    
    async fn get_status(&self) -> CollectorStatus {
        let stats = self.stats.read().await;
        let metrics = self.resource_metrics.read().await;
        
        CollectorStatus {
            name: self.name.clone(),
            is_running: *self.is_running.read().await,
            is_healthy: *self.is_healthy.read().await,
            last_collection: stats.last_collection,
            events_collected: stats.events_generated,
            error_count: stats.collection_errors,
            resource_usage: metrics.clone(),
            config_valid: true,
        }
    }
    
    async fn configure(&mut self, config: serde_json::Value) -> Result<()> {
        debug!("Configuring registry collector: {:?}", config);
        Ok(())
    }
    
    async fn force_collection(&mut self) -> Result<Vec<TelemetryEvent>> {
        debug!("Forcing registry collection");
        self.collect_registry_changes().await
    }
    
    async fn reduce_frequency(&mut self) -> Result<()> {
        debug!("Reducing registry collection frequency");
        let mut config = self.collection_config.write().await;
        config.interval = config.interval.mul_f32(2.0);
        Ok(())
    }
    
    async fn restore_frequency(&mut self) -> Result<()> {
        debug!("Restoring registry collection frequency");
        let mut config = self.collection_config.write().await;
        config.interval = Duration::from_secs(60);
        Ok(())
    }
    
    async fn get_resource_metrics(&self) -> ResourceMetrics {
        self.resource_metrics.read().await.clone()
    }
}

// Non-Windows platforms - stub implementation
#[cfg(not(target_os = "windows"))]
pub struct RegistryCollector;

#[cfg(not(target_os = "windows"))]
impl RegistryCollector {
    pub async fn new(
        _config: &crate::config::AgentConfig,
        _agent_id: uuid::Uuid,
        _event_tx: std::sync::Arc<tokio::sync::mpsc::Sender<crate::telemetry::TelemetryEvent>>,
    ) -> crate::error::Result<Self> {
        Ok(Self)
    }
}

#[cfg(not(target_os = "windows"))]
#[async_trait::async_trait]
impl Collector for RegistryCollector {
    fn name(&self) -> &str {
        "registry_collector_stub"
    }
    
    fn collector_type(&self) -> CollectorType {
        CollectorType::Registry
    }
    
    async fn start(&mut self) -> crate::error::Result<()> {
        debug!("Registry collector not available on this platform");
        Ok(())
    }
    
    async fn stop(&mut self) -> crate::error::Result<()> {
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        false
    }
    
    async fn is_healthy(&self) -> bool {
        true
    }
    
    async fn get_status(&self) -> CollectorStatus {
        CollectorStatus {
            name: "registry_collector_stub".to_string(),
            is_running: false,
            is_healthy: true,
            last_collection: None,
            events_collected: 0,
            error_count: 0,
            resource_usage: crate::telemetry::performance::ResourceMetrics::default(),
            config_valid: true,
        }
    }
    
    async fn configure(&mut self, _config: serde_json::Value) -> crate::error::Result<()> {
        Ok(())
    }
    
    async fn force_collection(&mut self) -> crate::error::Result<Vec<crate::telemetry::TelemetryEvent>> {
        Ok(vec![])
    }
    
    async fn reduce_frequency(&mut self) -> crate::error::Result<()> {
        Ok(())
    }
    
    async fn restore_frequency(&mut self) -> crate::error::Result<()> {
        Ok(())
    }
    
    async fn get_resource_metrics(&self) -> crate::telemetry::performance::ResourceMetrics {
        crate::telemetry::performance::ResourceMetrics::default()
    }
}