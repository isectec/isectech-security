// iSECTECH Security Agent - Telemetry Collection Framework
// Production-grade cross-platform security telemetry collection
// Copyright (c) 2024 iSECTECH. All rights reserved.

//! Telemetry collection framework for iSECTECH security agent
//! 
//! This module provides comprehensive security telemetry collection across all supported platforms:
//! - Process monitoring with lifecycle tracking and anomaly detection
//! - Network connection monitoring with threat intelligence integration
//! - File system monitoring with integrity validation and malware detection
//! - Registry monitoring (Windows) with unauthorized change detection
//! - User session tracking with privilege escalation detection
//! - Application inventory with vulnerability assessment
//! - System behavior analysis with machine learning-based anomaly detection

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::interval;
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result, SecurityError};
use crate::storage::StorageManager;

pub mod collectors;
pub mod processors;
pub mod correlation;
pub mod threat_detection;
pub mod performance;

use collectors::{
    CollectorManager,
    ProcessCollector,
    NetworkCollector, 
    FileSystemCollector,
    RegistryCollector,
    UserSessionCollector,
    ApplicationCollector,
    VulnerabilityCollector,
};
use processors::{EventProcessor, DataNormalizer, ThreatAnalyzer};
use correlation::{EventCorrelationEngine, CorrelationRule};
use threat_detection::{ThreatDetectionEngine, ThreatIndicator, ThreatSignature};
use performance::{PerformanceMonitor, ResourceMetrics};

/// Main telemetry manager coordinating all data collection
pub struct TelemetryManager {
    /// Agent configuration
    config: AgentConfig,
    /// Agent identifier
    agent_id: Uuid,
    /// Collector manager for platform-specific implementations
    collector_manager: Arc<CollectorManager>,
    /// Event processing pipeline
    event_processor: Arc<EventProcessor>,
    /// Event correlation engine
    correlation_engine: Arc<EventCorrelationEngine>,
    /// Threat detection engine
    threat_engine: Arc<ThreatDetectionEngine>,
    /// Performance monitoring
    performance_monitor: Arc<PerformanceMonitor>,
    /// Storage manager for persistence
    storage_manager: Arc<StorageManager>,
    /// Event channel for collected data
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Event receiver for processing
    event_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<TelemetryEvent>>>>,
    /// Shutdown signal
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Collection statistics
    stats: Arc<RwLock<TelemetryStatistics>>,
    /// Active collection state
    collection_state: Arc<RwLock<CollectionState>>,
}

/// Telemetry event structure for all collected data
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    /// Unique event identifier
    pub event_id: Uuid,
    /// Agent that collected the event
    pub agent_id: Uuid,
    /// Event type classification
    pub event_type: TelemetryEventType,
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Source of the event (process, file, network, etc.)
    pub source: EventSource,
    /// Raw event data
    pub data: EventData,
    /// Threat indicators if any
    pub threat_indicators: Vec<ThreatIndicator>,
    /// Event severity level
    pub severity: EventSeverity,
    /// Processing metadata
    pub metadata: EventMetadata,
}

/// Types of telemetry events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryEventType {
    /// Process lifecycle events
    ProcessEvent,
    /// Network activity events
    NetworkEvent,
    /// File system access events
    FileSystemEvent,
    /// Registry modification events (Windows)
    RegistryEvent,
    /// User session events
    UserSessionEvent,
    /// Application lifecycle events
    ApplicationEvent,
    /// System configuration changes
    SystemEvent,
    /// Security policy violations
    PolicyViolationEvent,
    /// Anomalous behavior detection
    AnomalyEvent,
    /// Vulnerability findings
    VulnerabilityEvent,
}

/// Event source information
#[derive(Debug, Clone)]
pub struct EventSource {
    /// Source identifier (PID, file path, IP address, etc.)
    pub id: String,
    /// Source type
    pub source_type: SourceType,
    /// Source name or description
    pub name: String,
    /// Additional source attributes
    pub attributes: HashMap<String, String>,
}

/// Types of event sources
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceType {
    Process,
    File,
    Directory,
    NetworkConnection,
    RegistryKey,
    UserAccount,
    Application,
    Service,
    Device,
    Unknown,
}

/// Event data payload
#[derive(Debug, Clone)]
pub struct EventData {
    /// Structured event data
    pub structured: HashMap<String, serde_json::Value>,
    /// Raw binary data if applicable
    pub raw: Option<Vec<u8>>,
    /// Data hash for integrity
    pub hash: String,
}

/// Event severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

/// Event processing metadata
#[derive(Debug, Clone)]
pub struct EventMetadata {
    /// Processing timestamp
    pub processed_at: SystemTime,
    /// Correlation IDs for related events
    pub correlation_ids: Vec<Uuid>,
    /// Processing tags
    pub tags: Vec<String>,
    /// Custom metadata
    pub custom: HashMap<String, String>,
}

/// Collection state and control
#[derive(Debug, Clone)]
pub struct CollectionState {
    /// Overall collection status
    pub status: CollectionStatus,
    /// Active collectors
    pub active_collectors: HashMap<String, CollectorStatus>,
    /// Collection start time
    pub started_at: Option<SystemTime>,
    /// Last activity timestamp
    pub last_activity: Option<SystemTime>,
    /// Error counts by collector
    pub error_counts: HashMap<String, u64>,
    /// Performance constraints active
    pub performance_constraints: bool,
}

/// Collection status enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionStatus {
    Stopped,
    Starting,
    Running,
    Paused,
    Stopping,
    Error,
}

/// Individual collector status
#[derive(Debug, Clone)]
pub struct CollectorStatus {
    /// Collector name
    pub name: String,
    /// Running state
    pub is_running: bool,
    /// Health status
    pub is_healthy: bool,
    /// Last successful collection
    pub last_collection: Option<SystemTime>,
    /// Events collected
    pub events_collected: u64,
    /// Errors encountered
    pub error_count: u64,
    /// Resource usage
    pub resource_usage: ResourceMetrics,
    /// Configuration status
    pub config_valid: bool,
}

/// Telemetry collection statistics
#[derive(Debug, Clone, Default)]
pub struct TelemetryStatistics {
    /// Total events collected
    pub total_events: u64,
    /// Events by type
    pub events_by_type: HashMap<TelemetryEventType, u64>,
    /// Events by severity
    pub events_by_severity: HashMap<EventSeverity, u64>,
    /// Threats detected
    pub threats_detected: u64,
    /// Policy violations
    pub policy_violations: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// Processing latency metrics
    pub avg_processing_latency: Duration,
    /// Resource usage
    pub resource_usage: ResourceMetrics,
    /// Collection uptime
    pub uptime: Duration,
    /// Last statistics update
    pub last_updated: SystemTime,
}

impl TelemetryManager {
    /// Create a new telemetry manager
    pub async fn new(
        config: AgentConfig,
        agent_id: Uuid,
        storage_manager: Arc<StorageManager>,
    ) -> Result<Self> {
        info!("Initializing iSECTECH telemetry manager for agent {}", agent_id);
        
        // Initialize collector manager with platform-specific collectors
        let collector_manager = Arc::new(
            CollectorManager::new(&config, agent_id).await?
        );
        
        // Initialize event processing pipeline
        let event_processor = Arc::new(
            EventProcessor::new(&config, agent_id).await?
        );
        
        // Initialize correlation engine with iSECTECH rules
        let correlation_engine = Arc::new(
            EventCorrelationEngine::new(&config).await?
        );
        
        // Initialize threat detection engine
        let threat_engine = Arc::new(
            ThreatDetectionEngine::new(&config, &storage_manager).await?
        );
        
        // Initialize performance monitor
        let performance_monitor = Arc::new(
            PerformanceMonitor::new(&config).await?
        );
        
        // Create event channels
        let (event_tx, event_rx) = mpsc::channel(10000);
        
        let manager = Self {
            config,
            agent_id,
            collector_manager,
            event_processor,
            correlation_engine,
            threat_engine,
            performance_monitor,
            storage_manager,
            event_tx,
            event_rx: Arc::new(tokio::sync::Mutex::new(Some(event_rx))),
            shutdown_tx: None,
            stats: Arc::new(RwLock::new(TelemetryStatistics::default())),
            collection_state: Arc::new(RwLock::new(CollectionState {
                status: CollectionStatus::Stopped,
                active_collectors: HashMap::new(),
                started_at: None,
                last_activity: None,
                error_counts: HashMap::new(),
                performance_constraints: false,
            })),
        };
        
        info!("iSECTECH telemetry manager initialized successfully");
        Ok(manager)
    }
    
    /// Start telemetry collection
    pub async fn start_collection(&mut self) -> Result<()> {
        info!("Starting iSECTECH telemetry collection");
        
        // Update collection state
        {
            let mut state = self.collection_state.write().await;
            state.status = CollectionStatus::Starting;
            state.started_at = Some(SystemTime::now());
        }
        
        // Start performance monitoring
        self.performance_monitor.start().await?;
        
        // Start all collectors
        self.collector_manager.start_all_collectors().await?;
        
        // Start event processing pipeline
        self.start_event_processing().await?;
        
        // Start background tasks
        self.start_background_tasks().await?;
        
        // Update collection state to running
        {
            let mut state = self.collection_state.write().await;
            state.status = CollectionStatus::Running;
        }
        
        info!("iSECTECH telemetry collection started successfully");
        Ok(())
    }
    
    /// Stop telemetry collection
    pub async fn stop_collection(&mut self) -> Result<()> {
        info!("Stopping iSECTECH telemetry collection");
        
        // Update collection state
        {
            let mut state = self.collection_state.write().await;
            state.status = CollectionStatus::Stopping;
        }
        
        // Send shutdown signal
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        
        // Stop all collectors
        self.collector_manager.stop_all_collectors().await?;
        
        // Stop performance monitoring
        self.performance_monitor.stop().await?;
        
        // Update collection state
        {
            let mut state = self.collection_state.write().await;
            state.status = CollectionStatus::Stopped;
        }
        
        info!("iSECTECH telemetry collection stopped successfully");
        Ok(())
    }
    
    /// Pause telemetry collection (reduce resource usage)
    pub async fn pause_collection(&self) -> Result<()> {
        info!("Pausing iSECTECH telemetry collection");
        
        // Update collection state
        {
            let mut state = self.collection_state.write().await;
            state.status = CollectionStatus::Paused;
            state.performance_constraints = true;
        }
        
        // Reduce collector frequencies
        self.collector_manager.reduce_collection_frequency().await?;
        
        info!("iSECTECH telemetry collection paused");
        Ok(())
    }
    
    /// Resume telemetry collection
    pub async fn resume_collection(&self) -> Result<()> {
        info!("Resuming iSECTECH telemetry collection");
        
        // Update collection state
        {
            let mut state = self.collection_state.write().await;
            state.status = CollectionStatus::Running;
            state.performance_constraints = false;
        }
        
        // Restore normal collector frequencies
        self.collector_manager.restore_collection_frequency().await?;
        
        info!("iSECTECH telemetry collection resumed");
        Ok(())
    }
    
    /// Get collection status
    pub async fn get_collection_status(&self) -> CollectionState {
        self.collection_state.read().await.clone()
    }
    
    /// Get telemetry statistics
    pub async fn get_statistics(&self) -> TelemetryStatistics {
        self.stats.read().await.clone()
    }
    
    /// Configure collector settings
    pub async fn configure_collector(
        &self,
        collector_name: &str,
        config: serde_json::Value,
    ) -> Result<()> {
        debug!("Configuring collector: {}", collector_name);
        
        self.collector_manager
            .configure_collector(collector_name, config)
            .await?;
        
        debug!("Collector {} configured successfully", collector_name);
        Ok(())
    }
    
    /// Add custom threat detection rule
    pub async fn add_threat_detection_rule(
        &self,
        rule_name: &str,
        rule: ThreatSignature,
    ) -> Result<()> {
        debug!("Adding threat detection rule: {}", rule_name);
        
        self.threat_engine
            .add_custom_rule(rule_name, rule)
            .await?;
        
        debug!("Threat detection rule {} added successfully", rule_name);
        Ok(())
    }
    
    /// Get collector health status
    pub async fn get_collector_health(&self) -> HashMap<String, CollectorStatus> {
        self.collector_manager.get_collector_health().await
    }
    
    /// Force immediate collection from all collectors
    pub async fn force_collection(&self) -> Result<()> {
        debug!("Forcing immediate collection from all collectors");
        
        self.collector_manager.force_immediate_collection().await?;
        
        debug!("Forced collection completed");
        Ok(())
    }
    
    // Private implementation methods
    
    async fn start_event_processing(&self) -> Result<()> {
        debug!("Starting event processing pipeline");
        
        let event_rx = self.event_rx.lock().await.take()
            .ok_or_else(|| AgentError::Internal("Event receiver already taken".to_string()))?;
        
        let event_processor = Arc::clone(&self.event_processor);
        let correlation_engine = Arc::clone(&self.correlation_engine);
        let threat_engine = Arc::clone(&self.threat_engine);
        let stats = Arc::clone(&self.stats);
        let collection_state = Arc::clone(&self.collection_state);
        
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);
        
        tokio::spawn(async move {
            let mut event_rx = event_rx;
            
            loop {
                tokio::select! {
                    // Process incoming events
                    Some(event) = event_rx.recv() => {
                        let processing_start = Instant::now();
                        
                        // Process the event through the pipeline
                        match Self::process_telemetry_event(
                            event,
                            &event_processor,
                            &correlation_engine,
                            &threat_engine,
                        ).await {
                            Ok(processed_events) => {
                                // Update statistics
                                let mut stats = stats.write().await;
                                stats.total_events += processed_events.len() as u64;
                                
                                for processed_event in &processed_events {
                                    *stats.events_by_type.entry(processed_event.event_type.clone()).or_insert(0) += 1;
                                    *stats.events_by_severity.entry(processed_event.severity.clone()).or_insert(0) += 1;
                                    
                                    if !processed_event.threat_indicators.is_empty() {
                                        stats.threats_detected += 1;
                                    }
                                }
                                
                                // Update processing latency
                                let processing_time = processing_start.elapsed();
                                stats.avg_processing_latency = 
                                    (stats.avg_processing_latency + processing_time) / 2;
                                stats.last_updated = SystemTime::now();
                                
                                // Update last activity
                                let mut state = collection_state.write().await;
                                state.last_activity = Some(SystemTime::now());
                            }
                            Err(e) => {
                                error!("Failed to process telemetry event: {}", e);
                            }
                        }
                    }
                    
                    // Handle shutdown
                    _ = &mut shutdown_rx => {
                        info!("Event processing pipeline shutting down");
                        break;
                    }
                }
            }
        });
        
        debug!("Event processing pipeline started");
        Ok(())
    }
    
    async fn process_telemetry_event(
        event: TelemetryEvent,
        processor: &EventProcessor,
        correlation_engine: &EventCorrelationEngine,
        threat_engine: &ThreatDetectionEngine,
    ) -> Result<Vec<TelemetryEvent>> {
        let mut events = vec![event];
        
        // Process through event processor
        events = processor.process_events(events).await?;
        
        // Run correlation analysis
        let correlated_events = correlation_engine.correlate_events(&events).await?;
        events.extend(correlated_events);
        
        // Run threat detection
        for event in &mut events {
            let threat_indicators = threat_engine.analyze_event(event).await?;
            event.threat_indicators.extend(threat_indicators);
        }
        
        Ok(events)
    }
    
    async fn start_background_tasks(&self) -> Result<()> {
        // Start statistics aggregation task
        self.start_statistics_task().await;
        
        // Start collector health monitoring task
        self.start_health_monitoring_task().await;
        
        // Start performance monitoring task
        self.start_performance_monitoring_task().await;
        
        // Start cleanup task
        self.start_cleanup_task().await;
        
        Ok(())
    }
    
    async fn start_statistics_task(&self) {
        let stats = Arc::clone(&self.stats);
        let collector_manager = Arc::clone(&self.collector_manager);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Aggregate statistics from collectors
                if let Ok(collector_stats) = collector_manager.get_aggregated_statistics().await {
                    let mut stats = stats.write().await;
                    
                    // Update resource usage
                    stats.resource_usage = collector_stats.resource_usage;
                    
                    // Update uptime
                    if let Some(start_time) = collector_stats.collection_start_time {
                        if let Ok(duration) = SystemTime::now().duration_since(start_time) {
                            stats.uptime = duration;
                        }
                    }
                }
            }
        });
    }
    
    async fn start_health_monitoring_task(&self) {
        let collector_manager = Arc::clone(&self.collector_manager);
        let collection_state = Arc::clone(&self.collection_state);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // Check collector health
                let collector_health = collector_manager.get_collector_health().await;
                
                let mut state = collection_state.write().await;
                state.active_collectors = collector_health;
                
                // Check for unhealthy collectors
                let unhealthy_count = state.active_collectors.values()
                    .filter(|status| !status.is_healthy)
                    .count();
                
                if unhealthy_count > 0 {
                    warn!("Found {} unhealthy collectors", unhealthy_count);
                    
                    // Attempt to restart unhealthy collectors
                    for (name, status) in &state.active_collectors {
                        if !status.is_healthy {
                            warn!("Attempting to restart unhealthy collector: {}", name);
                            let _ = collector_manager.restart_collector(name).await;
                        }
                    }
                }
            }
        });
    }
    
    async fn start_performance_monitoring_task(&self) {
        let performance_monitor = Arc::clone(&self.performance_monitor);
        let collection_state = Arc::clone(&self.collection_state);
        let collector_manager = Arc::clone(&self.collector_manager);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Monitor resource usage
                if let Ok(metrics) = performance_monitor.get_current_metrics().await {
                    // Check if we're exceeding resource limits
                    if metrics.cpu_usage_percent > 2.0 || metrics.memory_usage_mb > 100 {
                        warn!("Resource usage exceeding limits: CPU {}%, Memory {}MB", 
                               metrics.cpu_usage_percent, metrics.memory_usage_mb);
                        
                        // Activate performance constraints
                        let mut state = collection_state.write().await;
                        if !state.performance_constraints {
                            state.performance_constraints = true;
                            
                            // Reduce collection frequency
                            let _ = collector_manager.reduce_collection_frequency().await;
                        }
                    } else if metrics.cpu_usage_percent < 1.0 && metrics.memory_usage_mb < 50 {
                        // Can remove performance constraints
                        let mut state = collection_state.write().await;
                        if state.performance_constraints {
                            state.performance_constraints = false;
                            
                            // Restore normal collection frequency
                            let _ = collector_manager.restore_collection_frequency().await;
                        }
                    }
                }
            }
        });
    }
    
    async fn start_cleanup_task(&self) {
        let stats = Arc::clone(&self.stats);
        let storage_manager = Arc::clone(&self.storage_manager);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Every hour
            
            loop {
                interval.tick().await;
                
                // Clean up old statistics
                let mut stats = stats.write().await;
                if stats.events_by_type.len() > 1000 {
                    stats.events_by_type.clear();
                }
                if stats.events_by_severity.len() > 100 {
                    stats.events_by_severity.clear();
                }
                
                // Clean up old stored events
                let _ = storage_manager.cleanup_old_data("telemetry_events", Duration::from_secs(24 * 3600)).await;
                
                debug!("Telemetry cleanup completed");
            }
        });
    }
}