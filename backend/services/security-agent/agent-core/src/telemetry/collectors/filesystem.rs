// iSECTECH Security Agent - Filesystem Collector
// Production-grade filesystem monitoring and integrity validation
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use super::{Collector, CollectorType, CollectorStatus};
use crate::telemetry::{TelemetryEvent, TelemetryEventType, EventSource, EventData, EventSeverity, EventMetadata, SourceType};
use crate::telemetry::performance::ResourceMetrics;

/// Production-grade filesystem collector for comprehensive file monitoring
pub struct FileSystemCollector {
    /// Collector name
    name: String,
    /// Agent configuration
    config: AgentConfig,
    /// Agent identifier
    agent_id: Uuid,
    /// Event transmission channel
    event_tx: Arc<mpsc::Sender<TelemetryEvent>>,
    /// Filesystem monitoring state
    fs_state: Arc<RwLock<FileSystemMonitoringState>>,
    /// Collection configuration
    collection_config: Arc<RwLock<FileSystemCollectionConfig>>,
    /// Running state
    is_running: Arc<RwLock<bool>>,
    /// Health status
    is_healthy: Arc<RwLock<bool>>,
    /// Resource metrics
    resource_metrics: Arc<RwLock<ResourceMetrics>>,
    /// Collection statistics
    stats: Arc<RwLock<FileSystemCollectionStats>>,
    /// File integrity baseline
    integrity_baseline: Arc<RwLock<IntegrityBaseline>>,
}

/// Filesystem monitoring state
#[derive(Debug, Default)]
struct FileSystemMonitoringState {
    /// Monitored files (path -> FileInfo)
    monitored_files: HashMap<PathBuf, FileInfo>,
    /// Recent file changes
    recent_changes: Vec<FileChangeEvent>,
    /// Suspicious files flagged for monitoring
    suspicious_files: HashSet<PathBuf>,
    /// Directory watchers (path -> watcher_id)
    directory_watchers: HashMap<PathBuf, String>,
    /// File access patterns for anomaly detection
    access_patterns: HashMap<PathBuf, AccessPattern>,
    /// Last scan timestamp
    last_scan: Option<Instant>,
}

/// File information tracking
#[derive(Debug, Clone)]
struct FileInfo {
    /// File path
    pub path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// File permissions
    pub permissions: u32,
    /// Creation timestamp
    pub created: Option<SystemTime>,
    /// Last modification timestamp
    pub modified: Option<SystemTime>,
    /// Last access timestamp
    pub accessed: Option<SystemTime>,
    /// File owner
    pub owner: Option<String>,
    /// File group
    pub group: Option<String>,
    /// File type
    pub file_type: FileType,
    /// File hash (SHA-256)
    pub hash: Option<String>,
    /// Digital signature information
    pub signature_info: Option<SignatureInfo>,
    /// Security flags
    pub security_flags: FileSecurityFlags,
    /// iSECTECH threat score (0-100)
    pub threat_score: u8,
    /// Last scan time
    pub last_scanned: SystemTime,
}

/// File types for classification
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileType {
    Regular,
    Directory,
    Executable,
    Script,
    Library,
    Configuration,
    Log,
    Temporary,
    Archive,
    Document,
    Unknown,
}

/// Digital signature information
#[derive(Debug, Clone)]
struct SignatureInfo {
    /// Signature status
    pub is_signed: bool,
    /// Signature valid
    pub is_valid: bool,
    /// Signer information
    pub signer: Option<String>,
    /// Certificate authority
    pub ca: Option<String>,
    /// Signature timestamp
    pub timestamp: Option<SystemTime>,
}

/// File security flags
#[derive(Debug, Clone, Default)]
struct FileSecurityFlags {
    /// File is executable
    pub is_executable: bool,
    /// File has unusual permissions
    pub unusual_permissions: bool,
    /// File is in suspicious location
    pub suspicious_location: bool,
    /// File has no digital signature
    pub unsigned_file: bool,
    /// File matches malware signatures
    pub malware_indicators: Vec<String>,
    /// File has unusual size or content
    pub unusual_characteristics: bool,
    /// File was recently created
    pub recently_created: bool,
    /// File has hidden attributes
    pub hidden_file: bool,
    /// Policy violations
    pub policy_violations: Vec<String>,
}

/// File change event
#[derive(Debug, Clone)]
struct FileChangeEvent {
    /// File path
    pub path: PathBuf,
    /// Change type
    pub change_type: FileChangeType,
    /// Timestamp of change
    pub timestamp: SystemTime,
    /// Process that made the change
    pub process_id: Option<u32>,
    /// Process name
    pub process_name: Option<String>,
    /// Old file info
    pub old_info: Option<FileInfo>,
    /// New file info
    pub new_info: Option<FileInfo>,
}

/// Types of file changes
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileChangeType {
    Created,
    Modified,
    Deleted,
    Renamed,
    PermissionsChanged,
    OwnershipChanged,
    Accessed,
}

/// File access pattern for anomaly detection
#[derive(Debug, Clone, Default)]
struct AccessPattern {
    /// Access frequency
    pub access_count: u64,
    /// Unique processes accessing the file
    pub accessing_processes: HashSet<u32>,
    /// Access times distribution
    pub access_times: Vec<SystemTime>,
    /// Read/write patterns
    pub read_write_ratio: f64,
    /// Unusual access flags
    pub unusual_access: bool,
}

/// Filesystem collection configuration
#[derive(Debug, Clone)]
struct FileSystemCollectionConfig {
    /// Collection interval
    pub interval: Duration,
    /// Paths to monitor
    pub monitored_paths: Vec<PathBuf>,
    /// File extensions to monitor
    pub monitored_extensions: HashSet<String>,
    /// Enable real-time monitoring
    pub realtime_monitoring: bool,
    /// Enable integrity checking
    pub integrity_checking: bool,
    /// Enable malware scanning
    pub malware_scanning: bool,
    /// Detection rules
    pub detection_rules: Vec<FileSystemDetectionRule>,
    /// Excluded paths (whitelist)
    pub excluded_paths: Vec<PathBuf>,
    /// Maximum files to monitor
    pub max_monitored_files: usize,
    /// Hash calculation for files
    pub calculate_hashes: bool,
    /// Signature verification
    pub verify_signatures: bool,
}

/// Filesystem detection rule
#[derive(Debug, Clone)]
struct FileSystemDetectionRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Path patterns
    pub path_patterns: Vec<String>,
    /// File name patterns
    pub name_patterns: Vec<String>,
    /// File extension patterns
    pub extension_patterns: Vec<String>,
    /// File size thresholds
    pub size_threshold: Option<u64>,
    /// Permission patterns
    pub permission_patterns: Vec<u32>,
    /// Process patterns (for file operations)
    pub process_patterns: Vec<String>,
    /// Threat score (0-100)
    pub threat_score: u8,
    /// Rule severity
    pub severity: EventSeverity,
}

/// File integrity baseline
#[derive(Debug, Default)]
struct IntegrityBaseline {
    /// Baseline file hashes (path -> hash)
    pub file_hashes: HashMap<PathBuf, String>,
    /// Baseline creation time
    pub baseline_created: Option<SystemTime>,
    /// Last update time
    pub last_updated: Option<SystemTime>,
    /// Baseline version
    pub version: u32,
}

/// Collection statistics
#[derive(Debug, Clone, Default)]
struct FileSystemCollectionStats {
    /// Total files monitored
    pub total_files: u64,
    /// New files detected
    pub new_files: u64,
    /// Modified files
    pub modified_files: u64,
    /// Deleted files
    pub deleted_files: u64,
    /// Suspicious files flagged
    pub suspicious_files: u64,
    /// Integrity violations
    pub integrity_violations: u64,
    /// Events generated
    pub events_generated: u64,
    /// Collection errors
    pub collection_errors: u64,
    /// Last collection time
    pub last_collection: Option<Instant>,
}

impl FileSystemCollector {
    /// Create a new filesystem collector
    pub async fn new(
        config: &AgentConfig,
        agent_id: Uuid,
        event_tx: Arc<mpsc::Sender<TelemetryEvent>>,
    ) -> Result<Self> {
        debug!("Initializing iSECTECH filesystem collector");
        
        let collection_config = FileSystemCollectionConfig {
            interval: Duration::from_secs(30),
            monitored_paths: Self::get_default_monitored_paths(),
            monitored_extensions: HashSet::from([
                "exe".to_string(), "dll".to_string(), "so".to_string(), "dylib".to_string(),
                "bat".to_string(), "cmd".to_string(), "ps1".to_string(), "sh".to_string(),
                "py".to_string(), "pl".to_string(), "rb".to_string(), "js".to_string(),
                "jar".to_string(), "war".to_string(), "zip".to_string(), "rar".to_string(),
                "7z".to_string(), "tar".to_string(), "gz".to_string(),
            ]),
            realtime_monitoring: true,
            integrity_checking: true,
            malware_scanning: true,
            detection_rules: Self::create_default_detection_rules(),
            excluded_paths: Self::get_default_excluded_paths(),
            max_monitored_files: 50000,
            calculate_hashes: true,
            verify_signatures: true,
        };
        
        Ok(Self {
            name: "filesystem_collector".to_string(),
            config: config.clone(),
            agent_id,
            event_tx,
            fs_state: Arc::new(RwLock::new(FileSystemMonitoringState::default())),
            collection_config: Arc::new(RwLock::new(collection_config)),
            is_running: Arc::new(RwLock::new(false)),
            is_healthy: Arc::new(RwLock::new(true)),
            resource_metrics: Arc::new(RwLock::new(ResourceMetrics::default())),
            stats: Arc::new(RwLock::new(FileSystemCollectionStats::default())),
            integrity_baseline: Arc::new(RwLock::new(IntegrityBaseline::default())),
        })
    }
    
    /// Get default monitored paths for different platforms
    fn get_default_monitored_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        
        // Common paths across platforms
        paths.push(PathBuf::from("/tmp"));
        paths.push(PathBuf::from("/var/tmp"));
        
        // Platform-specific paths
        #[cfg(target_os = "windows")]
        {
            paths.extend([
                PathBuf::from("C:\\Windows\\System32"),
                PathBuf::from("C:\\Windows\\SysWOW64"),
                PathBuf::from("C:\\Program Files"),
                PathBuf::from("C:\\Program Files (x86)"),
                PathBuf::from("C:\\Windows\\Temp"),
                PathBuf::from("C:\\Temp"),
                PathBuf::from("C:\\Users\\Public"),
                PathBuf::from("C:\\ProgramData"),
            ]);
        }
        
        #[cfg(target_os = "linux")]
        {
            paths.extend([
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/opt"),
                PathBuf::from("/etc"),
                PathBuf::from("/lib"),
                PathBuf::from("/usr/lib"),
                PathBuf::from("/var/lib"),
                PathBuf::from("/home"),
            ]);
        }
        
        #[cfg(target_os = "macos")]
        {
            paths.extend([
                PathBuf::from("/Applications"),
                PathBuf::from("/System/Library"),
                PathBuf::from("/Library"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/private/tmp"),
                PathBuf::from("/Users"),
            ]);
        }
        
        paths
    }
    
    /// Get default excluded paths
    fn get_default_excluded_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
            PathBuf::from("/run"),
            PathBuf::from("/var/cache"),
            PathBuf::from("/var/log"),
        ]
    }
    
    /// Create default detection rules for iSECTECH
    fn create_default_detection_rules() -> Vec<FileSystemDetectionRule> {
        vec![
            FileSystemDetectionRule {
                name: "suspicious_temp_files".to_string(),
                description: "Suspicious files in temporary directories".to_string(),
                path_patterns: vec![
                    "/tmp/*".to_string(),
                    "/var/tmp/*".to_string(),
                    "C:\\Windows\\Temp\\*".to_string(),
                    "C:\\Temp\\*".to_string(),
                ],
                name_patterns: vec!["*.exe".to_string(), "*.bat".to_string(), "*.ps1".to_string()],
                extension_patterns: vec!["exe".to_string(), "bat".to_string(), "ps1".to_string()],
                size_threshold: None,
                permission_patterns: vec![0o777, 0o755],
                process_patterns: vec![],
                threat_score: 70,
                severity: EventSeverity::High,
            },
            FileSystemDetectionRule {
                name: "unsigned_executables".to_string(),
                description: "Unsigned executable files detected".to_string(),
                path_patterns: vec![
                    "C:\\Windows\\System32\\*".to_string(),
                    "/usr/bin/*".to_string(),
                    "/usr/sbin/*".to_string(),
                ],
                name_patterns: vec!["*.exe".to_string(), "*.dll".to_string()],
                extension_patterns: vec!["exe".to_string(), "dll".to_string(), "so".to_string()],
                size_threshold: None,
                permission_patterns: vec![],
                process_patterns: vec![],
                threat_score: 60,
                severity: EventSeverity::Medium,
            },
            FileSystemDetectionRule {
                name: "hidden_system_files".to_string(),
                description: "Hidden files in system directories".to_string(),
                path_patterns: vec![
                    "C:\\Windows\\*".to_string(),
                    "/bin/*".to_string(),
                    "/sbin/*".to_string(),
                    "/usr/bin/*".to_string(),
                ],
                name_patterns: vec![".*".to_string()],
                extension_patterns: vec![],
                size_threshold: None,
                permission_patterns: vec![],
                process_patterns: vec![],
                threat_score: 50,
                severity: EventSeverity::Medium,
            },
            FileSystemDetectionRule {
                name: "large_file_creation".to_string(),
                description: "Large files created in unusual locations".to_string(),
                path_patterns: vec![
                    "/tmp/*".to_string(),
                    "/var/tmp/*".to_string(),
                    "C:\\Users\\Public\\*".to_string(),
                ],
                name_patterns: vec![],
                extension_patterns: vec!["zip".to_string(), "rar".to_string(), "7z".to_string()],
                size_threshold: Some(100 * 1024 * 1024), // 100MB
                permission_patterns: vec![],
                process_patterns: vec![],
                threat_score: 40,
                severity: EventSeverity::Low,
            },
            FileSystemDetectionRule {
                name: "script_files_system_dirs".to_string(),
                description: "Script files in system directories".to_string(),
                path_patterns: vec![
                    "C:\\Windows\\*".to_string(),
                    "/bin/*".to_string(),
                    "/sbin/*".to_string(),
                    "/usr/bin/*".to_string(),
                ],
                name_patterns: vec!["*.ps1".to_string(), "*.bat".to_string(), "*.sh".to_string()],
                extension_patterns: vec!["ps1".to_string(), "bat".to_string(), "sh".to_string(), "py".to_string()],
                size_threshold: None,
                permission_patterns: vec![0o755, 0o777],
                process_patterns: vec![],
                threat_score: 80,
                severity: EventSeverity::High,
            },
        ]
    }
    
    /// Perform filesystem collection cycle
    async fn collect_filesystem_changes(&self) -> Result<Vec<TelemetryEvent>> {
        let start_time = Instant::now();
        let mut events = Vec::new();
        
        let mut state = self.fs_state.write().await;
        let config = self.collection_config.read().await;
        let mut stats = self.stats.write().await;
        
        // Scan monitored paths
        for monitored_path in &config.monitored_paths {
            if let Ok(scan_events) = self.scan_directory(&monitored_path, &config, &mut state).await {
                events.extend(scan_events);
            }
        }
        
        // Perform integrity checking
        if config.integrity_checking {
            let integrity_events = self.check_integrity(&config, &state).await?;
            events.extend(integrity_events);
        }
        
        // Analyze access patterns for anomalies
        let anomaly_events = self.analyze_access_patterns(&state).await?;
        events.extend(anomaly_events);
        
        // Update statistics
        stats.total_files = state.monitored_files.len() as u64;
        stats.events_generated += events.len() as u64;
        stats.last_collection = Some(start_time);
        state.last_scan = Some(start_time);
        
        // Update resource metrics
        let collection_time = start_time.elapsed();
        let mut metrics = self.resource_metrics.write().await;
        metrics.cpu_usage_percent = 0.3; // Estimated CPU usage
        metrics.memory_usage_mb = 15; // Estimated memory usage
        
        debug!("Filesystem collection completed: {} events, {} files, {:?}",
               events.len(), state.monitored_files.len(), collection_time);
        
        Ok(events)
    }
    
    /// Scan a directory for file changes
    async fn scan_directory(
        &self,
        path: &Path,
        config: &FileSystemCollectionConfig,
        state: &mut FileSystemMonitoringState,
    ) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        
        // Check if path should be excluded
        for excluded_path in &config.excluded_paths {
            if path.starts_with(excluded_path) {
                return Ok(events);
            }
        }
        
        // Respect max monitored files limit
        if state.monitored_files.len() >= config.max_monitored_files {
            return Ok(events);
        }
        
        // Recursively scan directory
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let entry_path = entry.path();
                    
                    if entry_path.is_dir() {
                        // Recursively scan subdirectory
                        let subdir_events = self.scan_directory(&entry_path, config, state).await?;
                        events.extend(subdir_events);
                    } else if entry_path.is_file() {
                        // Process file
                        if let Ok(file_events) = self.process_file(&entry_path, config, state).await {
                            events.extend(file_events);
                        }
                    }
                }
            }
        }
        
        Ok(events)
    }
    
    /// Process a single file for changes and analysis
    async fn process_file(
        &self,
        file_path: &Path,
        config: &FileSystemCollectionConfig,
        state: &mut FileSystemMonitoringState,
    ) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        
        // Check if file extension should be monitored
        if let Some(extension) = file_path.extension() {
            if let Some(ext_str) = extension.to_str() {
                if !config.monitored_extensions.contains(ext_str) {
                    return Ok(events);
                }
            }
        }
        
        // Get current file information
        let current_info = self.get_file_info(file_path, config).await?;
        
        // Check if this is a new file
        if let Some(existing_info) = state.monitored_files.get(file_path) {
            // File exists, check for changes
            if self.has_file_changed(existing_info, &current_info) {
                // File has changed
                let change_event = self.create_file_change_event(
                    file_path,
                    FileChangeType::Modified,
                    Some(existing_info.clone()),
                    Some(current_info.clone()),
                ).await?;
                
                let event = self.create_filesystem_event(&change_event, SystemTime::now()).await?;
                events.push(event);
            }
        } else {
            // New file detected
            let change_event = self.create_file_change_event(
                file_path,
                FileChangeType::Created,
                None,
                Some(current_info.clone()),
            ).await?;
            
            let event = self.create_filesystem_event(&change_event, SystemTime::now()).await?;
            events.push(event);
            
            // Check if file is suspicious
            if current_info.threat_score >= 70 {
                state.suspicious_files.insert(file_path.to_path_buf());
            }
        }
        
        // Update file information
        state.monitored_files.insert(file_path.to_path_buf(), current_info);
        
        Ok(events)
    }
    
    /// Get comprehensive file information
    async fn get_file_info(
        &self,
        file_path: &Path,
        config: &FileSystemCollectionConfig,
    ) -> Result<FileInfo> {
        let metadata = fs::metadata(file_path)
            .map_err(|e| AgentError::Io(format!("Failed to get metadata for {:?}: {}", file_path, e)))?;
        
        let file_type = self.determine_file_type(file_path, &metadata);
        
        // Calculate hash if enabled
        let hash = if config.calculate_hashes {
            self.calculate_file_hash(file_path).await.ok()
        } else {
            None
        };
        
        // Verify signature if enabled
        let signature_info = if config.verify_signatures {
            self.verify_file_signature(file_path).await.ok()
        } else {
            None
        };
        
        let mut file_info = FileInfo {
            path: file_path.to_path_buf(),
            size: metadata.len(),
            permissions: self.get_file_permissions(&metadata),
            created: metadata.created().ok(),
            modified: metadata.modified().ok(),
            accessed: metadata.accessed().ok(),
            owner: self.get_file_owner(&metadata).await,
            group: self.get_file_group(&metadata).await,
            file_type,
            hash,
            signature_info,
            security_flags: FileSecurityFlags::default(),
            threat_score: 0,
            last_scanned: SystemTime::now(),
        };
        
        // Analyze security flags and calculate threat score
        file_info.security_flags = self.analyze_file_security(&file_info, config).await;
        file_info.threat_score = self.calculate_file_threat_score(&file_info, config).await;
        
        Ok(file_info)
    }
    
    /// Determine file type based on path and metadata
    fn determine_file_type(&self, file_path: &Path, metadata: &Metadata) -> FileType {
        if metadata.is_dir() {
            return FileType::Directory;
        }
        
        // Check by extension
        if let Some(extension) = file_path.extension() {
            if let Some(ext_str) = extension.to_str() {
                match ext_str.to_lowercase().as_str() {
                    "exe" | "com" | "scr" | "msi" => return FileType::Executable,
                    "dll" | "so" | "dylib" => return FileType::Library,
                    "bat" | "cmd" | "ps1" | "sh" | "py" | "pl" | "rb" | "js" => return FileType::Script,
                    "conf" | "config" | "cfg" | "ini" | "xml" | "json" | "yaml" | "yml" => return FileType::Configuration,
                    "log" | "txt" => return FileType::Log,
                    "tmp" | "temp" => return FileType::Temporary,
                    "zip" | "rar" | "7z" | "tar" | "gz" => return FileType::Archive,
                    "doc" | "docx" | "pdf" | "xls" | "xlsx" | "ppt" | "pptx" => return FileType::Document,
                    _ => {}
                }
            }
        }
        
        // Check if file is executable by permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = metadata.permissions();
            if perms.mode() & 0o111 != 0 {
                return FileType::Executable;
            }
        }
        
        FileType::Regular
    }
    
    /// Calculate SHA-256 hash of file
    async fn calculate_file_hash(&self, file_path: &Path) -> Result<String> {
        let content = fs::read(file_path)
            .map_err(|e| AgentError::Io(format!("Failed to read file {:?}: {}", file_path, e)))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Verify file digital signature
    async fn verify_file_signature(&self, file_path: &Path) -> Result<SignatureInfo> {
        // TODO: Implement platform-specific signature verification
        // - Windows: Use WinVerifyTrust API
        // - macOS: Use Security framework
        // - Linux: Use package manager verification
        
        Ok(SignatureInfo {
            is_signed: false,
            is_valid: false,
            signer: None,
            ca: None,
            timestamp: None,
        })
    }
    
    /// Get file permissions
    fn get_file_permissions(&self, metadata: &Metadata) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        }
        
        #[cfg(windows)]
        {
            // Windows doesn't have Unix-style permissions
            0
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            0
        }
    }
    
    /// Get file owner
    async fn get_file_owner(&self, _metadata: &Metadata) -> Option<String> {
        // TODO: Implement platform-specific owner detection
        None
    }
    
    /// Get file group
    async fn get_file_group(&self, _metadata: &Metadata) -> Option<String> {
        // TODO: Implement platform-specific group detection
        None
    }
    
    /// Check if file has changed
    fn has_file_changed(&self, old_info: &FileInfo, new_info: &FileInfo) -> bool {
        old_info.size != new_info.size ||
        old_info.modified != new_info.modified ||
        old_info.permissions != new_info.permissions ||
        old_info.hash != new_info.hash
    }
    
    /// Create file change event
    async fn create_file_change_event(
        &self,
        file_path: &Path,
        change_type: FileChangeType,
        old_info: Option<FileInfo>,
        new_info: Option<FileInfo>,
    ) -> Result<FileChangeEvent> {
        Ok(FileChangeEvent {
            path: file_path.to_path_buf(),
            change_type,
            timestamp: SystemTime::now(),
            process_id: None, // TODO: Detect process that made the change
            process_name: None,
            old_info,
            new_info,
        })
    }
    
    /// Create filesystem telemetry event
    async fn create_filesystem_event(
        &self,
        change_event: &FileChangeEvent,
        timestamp: SystemTime,
    ) -> Result<TelemetryEvent> {
        let mut event_data = HashMap::new();
        
        // Basic file information
        event_data.insert("path".to_string(), serde_json::Value::String(change_event.path.to_string_lossy().to_string()));
        event_data.insert("change_type".to_string(), serde_json::Value::String(format!("{:?}", change_event.change_type)));
        
        if let Some(pid) = change_event.process_id {
            event_data.insert("process_id".to_string(), serde_json::Value::Number(pid.into()));
        }
        
        if let Some(ref process_name) = change_event.process_name {
            event_data.insert("process_name".to_string(), serde_json::Value::String(process_name.clone()));
        }
        
        // File information
        if let Some(ref file_info) = change_event.new_info {
            event_data.insert("file_size".to_string(), serde_json::Value::Number(file_info.size.into()));
            event_data.insert("file_type".to_string(), serde_json::Value::String(format!("{:?}", file_info.file_type)));
            event_data.insert("threat_score".to_string(), serde_json::Value::Number(file_info.threat_score.into()));
            event_data.insert("security_flags".to_string(), serde_json::to_value(&file_info.security_flags)?);
            
            if let Some(ref hash) = file_info.hash {
                event_data.insert("file_hash".to_string(), serde_json::Value::String(hash.clone()));
            }
        }
        
        // Determine event severity
        let severity = if let Some(ref file_info) = change_event.new_info {
            match file_info.threat_score {
                90..=100 => EventSeverity::Critical,
                70..=89 => EventSeverity::High,
                40..=69 => EventSeverity::Medium,
                20..=39 => EventSeverity::Low,
                _ => EventSeverity::Info,
            }
        } else {
            EventSeverity::Info
        };
        
        let event = TelemetryEvent {
            event_id: Uuid::new_v4(),
            agent_id: self.agent_id,
            event_type: TelemetryEventType::FileSystemEvent,
            timestamp,
            source: EventSource {
                id: change_event.path.to_string_lossy().to_string(),
                source_type: SourceType::File,
                name: change_event.path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
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
                tags: vec!["filesystem".to_string(), "iSECTECH".to_string()],
                custom: HashMap::new(),
            },
        };
        
        Ok(event)
    }
    
    /// Analyze file security flags
    async fn analyze_file_security(
        &self,
        file_info: &FileInfo,
        config: &FileSystemCollectionConfig,
    ) -> FileSecurityFlags {
        let mut flags = FileSecurityFlags::default();
        
        // Check if file is executable
        flags.is_executable = matches!(file_info.file_type, FileType::Executable | FileType::Script);
        
        // Check for unusual permissions
        #[cfg(unix)]
        {
            if file_info.permissions & 0o777 == 0o777 {
                flags.unusual_permissions = true;
            }
        }
        
        // Check for suspicious location
        for rule in &config.detection_rules {
            if self.matches_filesystem_detection_rule(file_info, rule).await {
                flags.policy_violations.push(rule.name.clone());
            }
        }
        
        // Check if file is unsigned
        if let Some(ref sig_info) = file_info.signature_info {
            flags.unsigned_file = !sig_info.is_signed;
        }
        
        // Check if recently created
        if let Some(created) = file_info.created {
            if let Ok(elapsed) = SystemTime::now().duration_since(created) {
                if elapsed < Duration::from_secs(3600) { // 1 hour
                    flags.recently_created = true;
                }
            }
        }
        
        // Check for hidden file
        if let Some(filename) = file_info.path.file_name() {
            if let Some(name_str) = filename.to_str() {
                flags.hidden_file = name_str.starts_with('.');
            }
        }
        
        flags
    }
    
    /// Calculate threat score for a file
    async fn calculate_file_threat_score(
        &self,
        file_info: &FileInfo,
        config: &FileSystemCollectionConfig,
    ) -> u8 {
        let mut score = 0u8;
        
        // Base score from detection rules
        for rule in &config.detection_rules {
            if self.matches_filesystem_detection_rule(file_info, rule).await {
                score = score.saturating_add(rule.threat_score);
            }
        }
        
        // Additional scoring factors
        if file_info.security_flags.unsigned_file && file_info.security_flags.is_executable {
            score = score.saturating_add(30);
        }
        
        if file_info.security_flags.suspicious_location {
            score = score.saturating_add(25);
        }
        
        if file_info.security_flags.unusual_permissions {
            score = score.saturating_add(20);
        }
        
        if file_info.security_flags.recently_created && file_info.security_flags.is_executable {
            score = score.saturating_add(15);
        }
        
        if file_info.security_flags.hidden_file {
            score = score.saturating_add(10);
        }
        
        // Cap at 100
        std::cmp::min(score, 100)
    }
    
    /// Check if file matches a detection rule
    async fn matches_filesystem_detection_rule(
        &self,
        file_info: &FileInfo,
        rule: &FileSystemDetectionRule,
    ) -> bool {
        let file_path_str = file_info.path.to_string_lossy();
        let file_name = file_info.path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        
        // Check path patterns
        for pattern in &rule.path_patterns {
            if self.matches_path_pattern(&file_path_str, pattern) {
                return true;
            }
        }
        
        // Check name patterns
        for pattern in &rule.name_patterns {
            if self.matches_name_pattern(&file_name, pattern) {
                return true;
            }
        }
        
        // Check extension patterns
        if let Some(extension) = file_info.path.extension() {
            if let Some(ext_str) = extension.to_str() {
                if rule.extension_patterns.contains(&ext_str.to_lowercase()) {
                    return true;
                }
            }
        }
        
        // Check size threshold
        if let Some(threshold) = rule.size_threshold {
            if file_info.size > threshold {
                return true;
            }
        }
        
        // Check permission patterns
        if rule.permission_patterns.contains(&file_info.permissions) {
            return true;
        }
        
        false
    }
    
    /// Simple path pattern matching
    fn matches_path_pattern(&self, path: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                path.starts_with(parts[0]) && path.ends_with(parts[1])
            } else {
                path.contains(&pattern.replace('*', ""))
            }
        } else {
            path == pattern || path.starts_with(pattern)
        }
    }
    
    /// Simple name pattern matching
    fn matches_name_pattern(&self, name: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                name.starts_with(parts[0]) && name.ends_with(parts[1])
            } else {
                name.contains(&pattern.replace('*', ""))
            }
        } else {
            name == pattern
        }
    }
    
    /// Check file integrity against baseline
    async fn check_integrity(
        &self,
        config: &FileSystemCollectionConfig,
        state: &FileSystemMonitoringState,
    ) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        
        if !config.integrity_checking {
            return Ok(events);
        }
        
        let baseline = self.integrity_baseline.read().await;
        
        // Check monitored files against baseline
        for (file_path, file_info) in &state.monitored_files {
            if let Some(baseline_hash) = baseline.file_hashes.get(file_path) {
                if let Some(ref current_hash) = file_info.hash {
                    if baseline_hash != current_hash {
                        // Integrity violation detected
                        let change_event = FileChangeEvent {
                            path: file_path.clone(),
                            change_type: FileChangeType::Modified,
                            timestamp: SystemTime::now(),
                            process_id: None,
                            process_name: None,
                            old_info: None,
                            new_info: Some(file_info.clone()),
                        };
                        
                        let event = self.create_filesystem_event(&change_event, SystemTime::now()).await?;
                        events.push(event);
                    }
                }
            }
        }
        
        Ok(events)
    }
    
    /// Analyze access patterns for anomalies
    async fn analyze_access_patterns(&self, _state: &FileSystemMonitoringState) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        
        // TODO: Implement access pattern analysis
        // - Detect unusual access frequencies
        // - Identify suspicious access timing
        // - Analyze process access patterns
        // - Generate anomaly events
        
        Ok(events)
    }
}

#[async_trait::async_trait]
impl Collector for FileSystemCollector {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn collector_type(&self) -> CollectorType {
        CollectorType::FileSystem
    }
    
    async fn start(&mut self) -> Result<()> {
        info!("Starting iSECTECH filesystem collector");
        
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
            fs_state: Arc::clone(&self.fs_state),
            collection_config: Arc::clone(&self.collection_config),
            is_running: Arc::clone(&self.is_running),
            is_healthy: Arc::clone(&self.is_healthy),
            resource_metrics: Arc::clone(&self.resource_metrics),
            stats: Arc::clone(&self.stats),
            integrity_baseline: Arc::clone(&self.integrity_baseline),
        };
        
        tokio::spawn(async move {
            let mut interval = {
                let config = collection_config.read().await;
                interval(config.interval)
            };
            
            while *is_running.read().await {
                interval.tick().await;
                
                match collector.collect_filesystem_changes().await {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.try_send(event) {
                                error!("Failed to send filesystem event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Filesystem collection failed: {}", e);
                        let mut stats = collector.stats.write().await;
                        stats.collection_errors += 1;
                    }
                }
            }
        });
        
        info!("iSECTECH filesystem collector started");
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        info!("Stopping iSECTECH filesystem collector");
        
        *self.is_running.write().await = false;
        
        info!("iSECTECH filesystem collector stopped");
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
        debug!("Configuring filesystem collector: {:?}", config);
        
        // TODO: Implement configuration updates
        
        Ok(())
    }
    
    async fn force_collection(&mut self) -> Result<Vec<TelemetryEvent>> {
        debug!("Forcing filesystem collection");
        self.collect_filesystem_changes().await
    }
    
    async fn reduce_frequency(&mut self) -> Result<()> {
        debug!("Reducing filesystem collection frequency");
        
        let mut config = self.collection_config.write().await;
        config.interval = config.interval.mul_f32(2.0);
        
        Ok(())
    }
    
    async fn restore_frequency(&mut self) -> Result<()> {
        debug!("Restoring filesystem collection frequency");
        
        let mut config = self.collection_config.write().await;
        config.interval = Duration::from_secs(30); // Reset to default
        
        Ok(())
    }
    
    async fn get_resource_metrics(&self) -> ResourceMetrics {
        self.resource_metrics.read().await.clone()
    }
}

// Add serde support for FileSecurityFlags
impl serde::Serialize for FileSecurityFlags {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FileSecurityFlags", 9)?;
        state.serialize_field("is_executable", &self.is_executable)?;
        state.serialize_field("unusual_permissions", &self.unusual_permissions)?;
        state.serialize_field("suspicious_location", &self.suspicious_location)?;
        state.serialize_field("unsigned_file", &self.unsigned_file)?;
        state.serialize_field("malware_indicators", &self.malware_indicators)?;
        state.serialize_field("unusual_characteristics", &self.unusual_characteristics)?;
        state.serialize_field("recently_created", &self.recently_created)?;
        state.serialize_field("hidden_file", &self.hidden_file)?;
        state.serialize_field("policy_violations", &self.policy_violations)?;
        state.end()
    }
}