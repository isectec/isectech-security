// iSECTECH Security Agent - Process Collector
// Production-grade process monitoring and lifecycle tracking
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use uuid::Uuid;
use sysinfo::{System, SystemExt, ProcessExt, Pid, PidExt};
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use super::{Collector, CollectorType, CollectorStatus};
use crate::telemetry::{TelemetryEvent, TelemetryEventType, EventSource, EventData, EventSeverity, EventMetadata, SourceType};
use crate::telemetry::performance::ResourceMetrics;

/// Production-grade process collector for comprehensive process monitoring
pub struct ProcessCollector {
    /// Collector name
    name: String,
    /// Agent configuration
    config: AgentConfig,
    /// Agent identifier
    agent_id: Uuid,
    /// Event transmission channel
    event_tx: Arc<mpsc::Sender<TelemetryEvent>>,
    /// System information provider
    system: Arc<RwLock<System>>,
    /// Process tracking state
    process_state: Arc<RwLock<ProcessTrackingState>>,
    /// Collection configuration
    collection_config: Arc<RwLock<ProcessCollectionConfig>>,
    /// Running state
    is_running: Arc<RwLock<bool>>,
    /// Health status
    is_healthy: Arc<RwLock<bool>>,
    /// Resource metrics
    resource_metrics: Arc<RwLock<ResourceMetrics>>,
    /// Collection statistics
    stats: Arc<RwLock<ProcessCollectionStats>>,
}

/// Process tracking state
#[derive(Debug, Default)]
struct ProcessTrackingState {
    /// Known processes (PID -> ProcessInfo)
    known_processes: HashMap<u32, ProcessInfo>,
    /// Process tree relationships (parent -> children)
    process_tree: HashMap<u32, HashSet<u32>>,
    /// Suspicious processes flagged for monitoring
    suspicious_processes: HashSet<u32>,
    /// Process creation timestamps
    creation_times: HashMap<u32, SystemTime>,
    /// Last scan timestamp
    last_scan: Option<Instant>,
}

/// Process information tracking
#[derive(Debug, Clone)]
struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: Option<u32>,
    /// Process name
    pub name: String,
    /// Full command line
    pub cmd: Vec<String>,
    /// Executable path
    pub exe_path: Option<String>,
    /// Working directory
    pub cwd: Option<String>,
    /// Environment variables (filtered)
    pub env_vars: HashMap<String, String>,
    /// User context
    pub user: Option<String>,
    /// Process start time
    pub start_time: SystemTime,
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Open file descriptors count
    pub fd_count: u32,
    /// Network connections count
    pub network_connections: u32,
    /// Process status
    pub status: ProcessStatus,
    /// Security flags
    pub security_flags: SecurityFlags,
    /// iSECTECH threat score (0-100)
    pub threat_score: u8,
}

/// Process status enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Unknown,
}

/// Security flags for process analysis
#[derive(Debug, Clone, Default)]
struct SecurityFlags {
    /// Process has elevated privileges
    pub elevated_privileges: bool,
    /// Process is unsigned or has invalid signature
    pub unsigned_binary: bool,
    /// Process loaded from suspicious location
    pub suspicious_location: bool,
    /// Process has unusual network activity
    pub unusual_network: bool,
    /// Process has unusual file system activity
    pub unusual_filesystem: bool,
    /// Process spawned by suspicious parent
    pub suspicious_parent: bool,
    /// Process matches known malware patterns
    pub malware_indicators: Vec<String>,
    /// Process violates security policies
    pub policy_violations: Vec<String>,
}

/// Process collection configuration
#[derive(Debug, Clone)]
struct ProcessCollectionConfig {
    /// Collection interval
    pub interval: Duration,
    /// Enable detailed process tracking
    pub detailed_tracking: bool,
    /// Enable command line collection
    pub collect_cmdline: bool,
    /// Enable environment variable collection
    pub collect_env: bool,
    /// Enable parent-child relationship tracking
    pub track_relationships: bool,
    /// Suspicious process detection rules
    pub detection_rules: Vec<ProcessDetectionRule>,
    /// Paths to monitor for process creation
    pub monitored_paths: Vec<String>,
    /// Processes to ignore (whitelist)
    pub ignored_processes: HashSet<String>,
    /// Maximum processes to track
    pub max_tracked_processes: usize,
}

/// Process detection rule for identifying suspicious activity
#[derive(Debug, Clone)]
struct ProcessDetectionRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Process name patterns
    pub process_patterns: Vec<String>,
    /// Command line patterns
    pub cmdline_patterns: Vec<String>,
    /// Path patterns
    pub path_patterns: Vec<String>,
    /// Parent process patterns
    pub parent_patterns: Vec<String>,
    /// Threat score (0-100)
    pub threat_score: u8,
    /// Rule severity
    pub severity: EventSeverity,
}

/// Collection statistics
#[derive(Debug, Clone, Default)]
struct ProcessCollectionStats {
    /// Total processes monitored
    pub total_processes: u64,
    /// New processes detected
    pub new_processes: u64,
    /// Terminated processes
    pub terminated_processes: u64,
    /// Suspicious processes flagged
    pub suspicious_processes: u64,
    /// Events generated
    pub events_generated: u64,
    /// Collection errors
    pub collection_errors: u64,
    /// Last collection time
    pub last_collection: Option<Instant>,
}

impl ProcessCollector {
    /// Create a new process collector
    pub async fn new(
        config: &AgentConfig,
        agent_id: Uuid,
        event_tx: Arc<mpsc::Sender<TelemetryEvent>>,
    ) -> Result<Self> {
        debug!("Initializing iSECTECH process collector");
        
        let collection_config = ProcessCollectionConfig {
            interval: Duration::from_secs(5),
            detailed_tracking: true,
            collect_cmdline: true,
            collect_env: false, // Privacy consideration
            track_relationships: true,
            detection_rules: Self::create_default_detection_rules(),
            monitored_paths: vec![
                "/tmp/".to_string(),
                "/var/tmp/".to_string(),
                "/dev/shm/".to_string(),
                "C:\\Windows\\Temp\\".to_string(),
                "C:\\Temp\\".to_string(),
            ],
            ignored_processes: HashSet::from([
                "systemd".to_string(),
                "kthreadd".to_string(),
                "ksoftirqd".to_string(),
                "init".to_string(),
                "kernel".to_string(),
            ]),
            max_tracked_processes: 10000,
        };
        
        Ok(Self {
            name: "process_collector".to_string(),
            config: config.clone(),
            agent_id,
            event_tx,
            system: Arc::new(RwLock::new(System::new_all())),
            process_state: Arc::new(RwLock::new(ProcessTrackingState::default())),
            collection_config: Arc::new(RwLock::new(collection_config)),
            is_running: Arc::new(RwLock::new(false)),
            is_healthy: Arc::new(RwLock::new(true)),
            resource_metrics: Arc::new(RwLock::new(ResourceMetrics::default())),
            stats: Arc::new(RwLock::new(ProcessCollectionStats::default())),
        })
    }
    
    /// Create default detection rules for iSECTECH
    fn create_default_detection_rules() -> Vec<ProcessDetectionRule> {
        vec![
            ProcessDetectionRule {
                name: "suspicious_temp_execution".to_string(),
                description: "Process executing from temporary directories".to_string(),
                process_patterns: vec!["*.exe".to_string(), "*.sh".to_string(), "*.py".to_string()],
                cmdline_patterns: vec![],
                path_patterns: vec![
                    "/tmp/*".to_string(),
                    "/var/tmp/*".to_string(),
                    "C:\\Windows\\Temp\\*".to_string(),
                    "C:\\Temp\\*".to_string(),
                ],
                parent_patterns: vec![],
                threat_score: 70,
                severity: EventSeverity::High,
            },
            ProcessDetectionRule {
                name: "privilege_escalation".to_string(),
                description: "Potential privilege escalation attempt".to_string(),
                process_patterns: vec!["sudo".to_string(), "su".to_string(), "runas".to_string()],
                cmdline_patterns: vec!["passwd".to_string(), "adduser".to_string(), "useradd".to_string()],
                path_patterns: vec![],
                parent_patterns: vec![],
                threat_score: 85,
                severity: EventSeverity::Critical,
            },
            ProcessDetectionRule {
                name: "network_reconnaissance".to_string(),
                description: "Network reconnaissance tools detected".to_string(),
                process_patterns: vec![
                    "nmap".to_string(), "netcat".to_string(), "nc".to_string(),
                    "telnet".to_string(), "ping".to_string(), "traceroute".to_string(),
                ],
                cmdline_patterns: vec!["-p".to_string(), "scan".to_string()],
                path_patterns: vec![],
                parent_patterns: vec![],
                threat_score: 60,
                severity: EventSeverity::Medium,
            },
            ProcessDetectionRule {
                name: "powershell_encoded".to_string(),
                description: "PowerShell with encoded commands".to_string(),
                process_patterns: vec!["powershell.exe".to_string(), "pwsh.exe".to_string()],
                cmdline_patterns: vec![
                    "-EncodedCommand".to_string(),
                    "-enc".to_string(),
                    "-e ".to_string(),
                    "FromBase64String".to_string(),
                ],
                path_patterns: vec![],
                parent_patterns: vec![],
                threat_score: 90,
                severity: EventSeverity::Critical,
            },
            ProcessDetectionRule {
                name: "suspicious_parent_spawn".to_string(),
                description: "Suspicious process spawned by office applications".to_string(),
                process_patterns: vec![
                    "cmd.exe".to_string(), "powershell.exe".to_string(),
                    "bash".to_string(), "sh".to_string(),
                ],
                cmdline_patterns: vec![],
                path_patterns: vec![],
                parent_patterns: vec![
                    "winword.exe".to_string(), "excel.exe".to_string(),
                    "outlook.exe".to_string(), "acrobat.exe".to_string(),
                ],
                threat_score: 80,
                severity: EventSeverity::High,
            },
        ]
    }
    
    /// Perform process collection cycle
    async fn collect_processes(&self) -> Result<Vec<TelemetryEvent>> {
        let start_time = Instant::now();
        let mut events = Vec::new();
        
        // Update system information
        {
            let mut system = self.system.write().await;
            system.refresh_processes();
        }
        
        let system = self.system.read().await;
        let mut state = self.process_state.write().await;
        let config = self.collection_config.read().await;
        let mut stats = self.stats.write().await;
        
        // Track current processes
        let mut current_processes = HashMap::new();
        let current_time = SystemTime::now();
        
        for (pid, process) in system.processes() {
            let pid_value = pid.as_u32();
            
            // Skip ignored processes
            if config.ignored_processes.contains(process.name()) {
                continue;
            }
            
            // Respect max tracking limit
            if current_processes.len() >= config.max_tracked_processes {
                break;
            }
            
            let process_info = ProcessInfo {
                pid: pid_value,
                ppid: process.parent().map(|p| p.as_u32()),
                name: process.name().to_string(),
                cmd: process.cmd().to_vec(),
                exe_path: process.exe().map(|p| p.to_string_lossy().to_string()),
                cwd: process.cwd().map(|p| p.to_string_lossy().to_string()),
                env_vars: if config.collect_env {
                    self.collect_filtered_env_vars(process.environ())
                } else {
                    HashMap::new()
                },
                user: None, // TODO: Implement user detection
                start_time: current_time, // TODO: Get actual start time
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                fd_count: 0, // TODO: Implement FD counting
                network_connections: 0, // TODO: Implement network connection counting
                status: self.map_process_status(process.status()),
                security_flags: SecurityFlags::default(),
                threat_score: 0,
            };
            
            current_processes.insert(pid_value, process_info);
        }
        
        // Detect new processes
        for (pid, process_info) in &current_processes {
            if !state.known_processes.contains_key(pid) {
                // New process detected
                let mut new_process = process_info.clone();
                
                // Analyze security flags and threat score
                new_process.security_flags = self.analyze_security_flags(&new_process, &config).await;
                new_process.threat_score = self.calculate_threat_score(&new_process, &config).await;
                
                // Generate process creation event
                let event = self.create_process_event(
                    &new_process,
                    ProcessEventType::Created,
                    current_time,
                ).await?;
                events.push(event);
                
                // Track in suspicious processes if threat score is high
                if new_process.threat_score >= 70 {
                    state.suspicious_processes.insert(*pid);
                    stats.suspicious_processes += 1;
                }
                
                state.creation_times.insert(*pid, current_time);
                stats.new_processes += 1;
            }
        }
        
        // Detect terminated processes
        let terminated_pids: Vec<u32> = state.known_processes.keys()
            .filter(|pid| !current_processes.contains_key(pid))
            .copied()
            .collect();
        
        for pid in terminated_pids {
            if let Some(process_info) = state.known_processes.remove(&pid) {
                // Generate process termination event
                let event = self.create_process_event(
                    &process_info,
                    ProcessEventType::Terminated,
                    current_time,
                ).await?;
                events.push(event);
                
                state.suspicious_processes.remove(&pid);
                state.creation_times.remove(&pid);
                stats.terminated_processes += 1;
            }
        }
        
        // Update process tree relationships
        if config.track_relationships {
            self.update_process_tree(&current_processes, &mut state).await;
        }
        
        // Update known processes
        state.known_processes = current_processes;
        state.last_scan = Some(start_time);
        
        // Update statistics
        stats.total_processes = state.known_processes.len() as u64;
        stats.events_generated += events.len() as u64;
        stats.last_collection = Some(start_time);
        
        // Update resource metrics
        let collection_time = start_time.elapsed();
        let mut metrics = self.resource_metrics.write().await;
        metrics.cpu_usage_percent = 0.1; // Estimated CPU usage
        metrics.memory_usage_mb = 5; // Estimated memory usage
        
        debug!("Process collection completed: {} events, {} processes, {:?}",
               events.len(), state.known_processes.len(), collection_time);
        
        Ok(events)
    }
    
    /// Create a process-related telemetry event
    async fn create_process_event(
        &self,
        process_info: &ProcessInfo,
        event_type: ProcessEventType,
        timestamp: SystemTime,
    ) -> Result<TelemetryEvent> {
        let mut event_data = HashMap::new();
        
        // Basic process information
        event_data.insert("pid".to_string(), serde_json::Value::Number(process_info.pid.into()));
        event_data.insert("name".to_string(), serde_json::Value::String(process_info.name.clone()));
        event_data.insert("event_type".to_string(), serde_json::Value::String(format!("{:?}", event_type)));
        
        if let Some(ppid) = process_info.ppid {
            event_data.insert("ppid".to_string(), serde_json::Value::Number(ppid.into()));
        }
        
        if let Some(ref exe_path) = process_info.exe_path {
            event_data.insert("exe_path".to_string(), serde_json::Value::String(exe_path.clone()));
        }
        
        if let Some(ref cwd) = process_info.cwd {
            event_data.insert("cwd".to_string(), serde_json::Value::String(cwd.clone()));
        }
        
        // Command line
        if !process_info.cmd.is_empty() {
            event_data.insert("cmdline".to_string(), serde_json::Value::Array(
                process_info.cmd.iter().map(|s| serde_json::Value::String(s.clone())).collect()
            ));
        }
        
        // Performance metrics
        event_data.insert("cpu_usage".to_string(), serde_json::Value::Number(
            serde_json::Number::from_f64(process_info.cpu_usage as f64).unwrap_or_default()
        ));
        event_data.insert("memory_usage".to_string(), serde_json::Value::Number(process_info.memory_usage.into()));
        
        // Security information
        event_data.insert("threat_score".to_string(), serde_json::Value::Number(process_info.threat_score.into()));
        event_data.insert("security_flags".to_string(), serde_json::to_value(&process_info.security_flags)?);
        
        // Determine event severity based on threat score
        let severity = match process_info.threat_score {
            90..=100 => EventSeverity::Critical,
            70..=89 => EventSeverity::High,
            40..=69 => EventSeverity::Medium,
            20..=39 => EventSeverity::Low,
            _ => EventSeverity::Info,
        };
        
        let event = TelemetryEvent {
            event_id: Uuid::new_v4(),
            agent_id: self.agent_id,
            event_type: TelemetryEventType::ProcessEvent,
            timestamp,
            source: EventSource {
                id: process_info.pid.to_string(),
                source_type: SourceType::Process,
                name: process_info.name.clone(),
                attributes: HashMap::new(),
            },
            data: EventData {
                structured: event_data,
                raw: None,
                hash: "".to_string(), // TODO: Calculate hash
            },
            threat_indicators: vec![], // TODO: Add threat indicators
            severity,
            metadata: EventMetadata {
                processed_at: SystemTime::now(),
                correlation_ids: vec![],
                tags: vec!["process".to_string(), "iSECTECH".to_string()],
                custom: HashMap::new(),
            },
        };
        
        Ok(event)
    }
    
    /// Analyze security flags for a process
    async fn analyze_security_flags(
        &self,
        process_info: &ProcessInfo,
        config: &ProcessCollectionConfig,
    ) -> SecurityFlags {
        let mut flags = SecurityFlags::default();
        
        // Check for execution from suspicious locations
        if let Some(ref exe_path) = process_info.exe_path {
            for monitored_path in &config.monitored_paths {
                if exe_path.starts_with(monitored_path) {
                    flags.suspicious_location = true;
                    break;
                }
            }
        }
        
        // Check against detection rules
        for rule in &config.detection_rules {
            if self.matches_detection_rule(process_info, rule).await {
                flags.policy_violations.push(rule.name.clone());
            }
        }
        
        // TODO: Implement additional security checks
        // - Digital signature validation
        // - Privilege level detection
        // - Network activity analysis
        // - File system activity analysis
        
        flags
    }
    
    /// Calculate threat score for a process
    async fn calculate_threat_score(
        &self,
        process_info: &ProcessInfo,
        config: &ProcessCollectionConfig,
    ) -> u8 {
        let mut score = 0u8;
        
        // Base score from detection rules
        for rule in &config.detection_rules {
            if self.matches_detection_rule(process_info, rule).await {
                score = score.saturating_add(rule.threat_score);
            }
        }
        
        // Additional scoring factors
        if process_info.security_flags.suspicious_location {
            score = score.saturating_add(30);
        }
        
        if process_info.security_flags.unsigned_binary {
            score = score.saturating_add(20);
        }
        
        if process_info.security_flags.elevated_privileges {
            score = score.saturating_add(15);
        }
        
        // Cap at 100
        std::cmp::min(score, 100)
    }
    
    /// Check if a process matches a detection rule
    async fn matches_detection_rule(
        &self,
        process_info: &ProcessInfo,
        rule: &ProcessDetectionRule,
    ) -> bool {
        // Check process name patterns
        for pattern in &rule.process_patterns {
            if self.matches_pattern(&process_info.name, pattern) {
                return true;
            }
        }
        
        // Check command line patterns
        let cmdline_str = process_info.cmd.join(" ");
        for pattern in &rule.cmdline_patterns {
            if cmdline_str.contains(pattern) {
                return true;
            }
        }
        
        // Check path patterns
        if let Some(ref exe_path) = process_info.exe_path {
            for pattern in &rule.path_patterns {
                if self.matches_pattern(exe_path, pattern) {
                    return true;
                }
            }
        }
        
        // TODO: Check parent process patterns
        
        false
    }
    
    /// Simple pattern matching (supports wildcards)
    fn matches_pattern(&self, text: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                text.starts_with(parts[0]) && text.ends_with(parts[1])
            } else {
                text.contains(&pattern.replace('*', ""))
            }
        } else {
            text == pattern || text.contains(pattern)
        }
    }
    
    /// Collect filtered environment variables
    fn collect_filtered_env_vars(&self, env: &[String]) -> HashMap<String, String> {
        let mut filtered_env = HashMap::new();
        
        // Only collect non-sensitive environment variables
        let allowed_prefixes = ["PATH", "LANG", "LC_", "HOME", "USER", "SHELL"];
        
        for env_var in env {
            if let Some((key, value)) = env_var.split_once('=') {
                if allowed_prefixes.iter().any(|prefix| key.starts_with(prefix)) {
                    filtered_env.insert(key.to_string(), value.to_string());
                }
            }
        }
        
        filtered_env
    }
    
    /// Map sysinfo process status to our enum
    fn map_process_status(&self, status: sysinfo::ProcessStatus) -> ProcessStatus {
        match status {
            sysinfo::ProcessStatus::Run => ProcessStatus::Running,
            sysinfo::ProcessStatus::Sleep => ProcessStatus::Sleeping,
            sysinfo::ProcessStatus::Stop => ProcessStatus::Stopped,
            sysinfo::ProcessStatus::Zombie => ProcessStatus::Zombie,
            _ => ProcessStatus::Unknown,
        }
    }
    
    /// Update process tree relationships
    async fn update_process_tree(
        &self,
        current_processes: &HashMap<u32, ProcessInfo>,
        state: &mut ProcessTrackingState,
    ) {
        state.process_tree.clear();
        
        for process_info in current_processes.values() {
            if let Some(ppid) = process_info.ppid {
                state.process_tree
                    .entry(ppid)
                    .or_insert_with(HashSet::new)
                    .insert(process_info.pid);
            }
        }
    }
}

#[async_trait::async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn collector_type(&self) -> CollectorType {
        CollectorType::Process
    }
    
    async fn start(&mut self) -> Result<()> {
        info!("Starting iSECTECH process collector");
        
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
            system: Arc::clone(&self.system),
            process_state: Arc::clone(&self.process_state),
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
                
                match collector.collect_processes().await {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.try_send(event) {
                                error!("Failed to send process event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Process collection failed: {}", e);
                        let mut stats = collector.stats.write().await;
                        stats.collection_errors += 1;
                    }
                }
            }
        });
        
        info!("iSECTECH process collector started");
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        info!("Stopping iSECTECH process collector");
        
        *self.is_running.write().await = false;
        
        info!("iSECTECH process collector stopped");
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
        debug!("Configuring process collector: {:?}", config);
        
        // TODO: Implement configuration updates
        
        Ok(())
    }
    
    async fn force_collection(&mut self) -> Result<Vec<TelemetryEvent>> {
        debug!("Forcing process collection");
        self.collect_processes().await
    }
    
    async fn reduce_frequency(&mut self) -> Result<()> {
        debug!("Reducing process collection frequency");
        
        let mut config = self.collection_config.write().await;
        config.interval = config.interval.mul_f32(2.0);
        
        Ok(())
    }
    
    async fn restore_frequency(&mut self) -> Result<()> {
        debug!("Restoring process collection frequency");
        
        let mut config = self.collection_config.write().await;
        config.interval = Duration::from_secs(5); // Reset to default
        
        Ok(())
    }
    
    async fn get_resource_metrics(&self) -> ResourceMetrics {
        self.resource_metrics.read().await.clone()
    }
}

/// Process event types for detailed tracking
#[derive(Debug, Clone)]
enum ProcessEventType {
    Created,
    Terminated,
    Modified,
    Suspicious,
}

// Add serde support for SecurityFlags
impl serde::Serialize for SecurityFlags {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecurityFlags", 8)?;
        state.serialize_field("elevated_privileges", &self.elevated_privileges)?;
        state.serialize_field("unsigned_binary", &self.unsigned_binary)?;
        state.serialize_field("suspicious_location", &self.suspicious_location)?;
        state.serialize_field("unusual_network", &self.unusual_network)?;
        state.serialize_field("unusual_filesystem", &self.unusual_filesystem)?;
        state.serialize_field("suspicious_parent", &self.suspicious_parent)?;
        state.serialize_field("malware_indicators", &self.malware_indicators)?;
        state.serialize_field("policy_violations", &self.policy_violations)?;
        state.end()
    }
}