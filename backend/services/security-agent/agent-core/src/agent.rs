// iSECTECH Security Agent - Core Agent Implementation
// Production-grade agent lifecycle and orchestration
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::crypto::CryptoManager;
use crate::error::{AgentError, Result};
use crate::platform::PlatformManager;
use crate::security::SecurityManager;
use crate::storage::StorageManager;
use crate::telemetry::TelemetryManager;
use crate::updater::UpdateManager;

/// Agent state enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is initializing
    Initializing,
    /// Agent is running normally
    Running,
    /// Agent is updating
    Updating,
    /// Agent is shutting down
    Shutting,
    /// Agent has stopped
    Stopped,
    /// Agent is in error state
    Error(String),
}

/// Agent status information
#[derive(Debug, Clone)]
pub struct AgentStatus {
    pub state: AgentState,
    pub agent_id: Uuid,
    pub version: String,
    pub uptime: Duration,
    pub last_heartbeat: Option<Instant>,
    pub resource_usage: ResourceUsage,
    pub active_collectors: Vec<String>,
    pub security_violations: u64,
    pub events_processed: u64,
}

/// Current resource usage
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_kbps: u64,
}

/// Agent command types
#[derive(Debug, Clone)]
pub enum AgentCommand {
    /// Shutdown the agent gracefully
    Shutdown,
    /// Reload configuration
    ReloadConfig,
    /// Start specific collector
    StartCollector(String),
    /// Stop specific collector
    StopCollector(String),
    /// Force integrity check
    IntegrityCheck,
    /// Execute policy enforcement
    EnforcePolicy(String),
    /// Update agent
    UpdateAgent,
}

/// Main security agent implementation
pub struct Agent {
    /// Unique agent identifier
    agent_id: Uuid,
    /// Agent configuration
    config: AgentConfig,
    /// Current agent state
    state: Arc<RwLock<AgentState>>,
    /// Start time for uptime calculation
    start_time: Instant,
    /// Command channel receiver
    command_rx: Arc<RwLock<Option<mpsc::Receiver<AgentCommand>>>>,
    /// Command channel sender (for external control)
    command_tx: mpsc::Sender<AgentCommand>,
    
    // Core managers
    platform_manager: Arc<PlatformManager>,
    crypto_manager: Arc<CryptoManager>,
    storage_manager: Arc<StorageManager>,
    security_manager: Arc<SecurityManager>,
    telemetry_manager: Arc<TelemetryManager>,
    update_manager: Arc<UpdateManager>,
    
    // Statistics
    events_processed: Arc<RwLock<u64>>,
    security_violations: Arc<RwLock<u64>>,
    last_heartbeat: Arc<RwLock<Option<Instant>>>,
}

impl Agent {
    /// Create a new agent instance
    pub async fn new(
        agent_id: Uuid,
        config: AgentConfig,
        platform_manager: Arc<PlatformManager>,
        crypto_manager: Arc<CryptoManager>,
        storage_manager: Arc<StorageManager>,
        security_manager: Arc<SecurityManager>,
        telemetry_manager: Arc<TelemetryManager>,
        update_manager: Arc<UpdateManager>,
    ) -> Result<Self> {
        let (command_tx, command_rx) = mpsc::channel(100);
        
        info!("Creating new agent instance with ID: {}", agent_id);
        
        Ok(Self {
            agent_id,
            config,
            state: Arc::new(RwLock::new(AgentState::Initializing)),
            start_time: Instant::now(),
            command_rx: Arc::new(RwLock::new(Some(command_rx))),
            command_tx,
            platform_manager,
            crypto_manager,
            storage_manager,
            security_manager,
            telemetry_manager,
            update_manager,
            events_processed: Arc::new(RwLock::new(0)),
            security_violations: Arc::new(RwLock::new(0)),
            last_heartbeat: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Get agent command sender for external control
    pub fn command_sender(&self) -> mpsc::Sender<AgentCommand> {
        self.command_tx.clone()
    }
    
    /// Get current agent status
    pub async fn status(&self) -> AgentStatus {
        let state = self.state.read().await.clone();
        let uptime = self.start_time.elapsed();
        let last_heartbeat = *self.last_heartbeat.read().await;
        let events_processed = *self.events_processed.read().await;
        let security_violations = *self.security_violations.read().await;
        
        // Get current resource usage
        let resource_usage = self.get_resource_usage().await;
        
        // Get active collectors
        let active_collectors = self.get_active_collectors().await;
        
        AgentStatus {
            state,
            agent_id: self.agent_id,
            version: self.config.agent.version.clone(),
            uptime,
            last_heartbeat,
            resource_usage,
            active_collectors,
            security_violations,
            events_processed,
        }
    }
    
    /// Main agent execution loop
    pub async fn run(&self) -> Result<()> {
        info!("Starting agent main loop");
        
        // Update state to running
        *self.state.write().await = AgentState::Running;
        
        // Take ownership of command receiver
        let mut command_rx = self.command_rx.write().await
            .take()
            .ok_or_else(|| AgentError::Lifecycle("Command receiver already taken".to_string()))?;
        
        // Initialize background tasks
        self.start_background_tasks().await?;
        
        // Main event loop
        loop {
            tokio::select! {
                // Handle incoming commands
                Some(command) = command_rx.recv() => {
                    match self.handle_command(command).await {
                        Ok(should_continue) => {
                            if !should_continue {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error handling command: {}", e);
                            *self.state.write().await = AgentState::Error(e.to_string());
                        }
                    }
                }
                
                // Periodic maintenance
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    if let Err(e) = self.perform_maintenance().await {
                        error!("Maintenance error: {}", e);
                    }
                }
            }
        }
        
        info!("Agent main loop completed");
        Ok(())
    }
    
    /// Gracefully shutdown the agent
    pub async fn shutdown(&self) -> Result<()> {
        info!("Initiating agent shutdown");
        
        *self.state.write().await = AgentState::Shutting;
        
        // Stop data collection
        self.telemetry_manager.stop_collection().await?;
        
        // Send final telemetry
        self.telemetry_manager.send_final_telemetry().await?;
        
        // Cleanup resources
        self.platform_manager.cleanup().await?;
        
        *self.state.write().await = AgentState::Stopped;
        info!("Agent shutdown completed");
        
        Ok(())
    }
    
    /// Handle agent commands
    async fn handle_command(&self, command: AgentCommand) -> Result<bool> {
        debug!("Handling command: {:?}", command);
        
        match command {
            AgentCommand::Shutdown => {
                info!("Shutdown command received");
                return Ok(false); // Signal to exit main loop
            }
            
            AgentCommand::ReloadConfig => {
                info!("Reloading configuration");
                // TODO: Implement config reload
            }
            
            AgentCommand::StartCollector(collector) => {
                info!("Starting collector: {}", collector);
                self.telemetry_manager.start_collector(&collector).await?;
            }
            
            AgentCommand::StopCollector(collector) => {
                info!("Stopping collector: {}", collector);
                self.telemetry_manager.stop_collector(&collector).await?;
            }
            
            AgentCommand::IntegrityCheck => {
                info!("Performing integrity check");
                self.security_manager.validate_integrity().await?;
            }
            
            AgentCommand::EnforcePolicy(policy) => {
                info!("Enforcing policy: {}", policy);
                // TODO: Implement policy enforcement
            }
            
            AgentCommand::UpdateAgent => {
                info!("Starting agent update");
                *self.state.write().await = AgentState::Updating;
                
                match self.update_manager.check_and_apply_updates().await {
                    Ok(_) => {
                        info!("Agent update completed successfully");
                        *self.state.write().await = AgentState::Running;
                    }
                    Err(e) => {
                        error!("Agent update failed: {}", e);
                        *self.state.write().await = AgentState::Running;
                        return Err(e);
                    }
                }
            }
        }
        
        Ok(true) // Continue running
    }
    
    /// Start background tasks
    async fn start_background_tasks(&self) -> Result<()> {
        info!("Starting background tasks");
        
        // Start telemetry collection
        self.telemetry_manager.start_collection().await?;
        
        // Start heartbeat task
        self.start_heartbeat_task().await;
        
        // Start resource monitoring
        self.start_resource_monitoring().await;
        
        // Start security monitoring
        self.start_security_monitoring().await;
        
        // Start update checker if enabled
        if self.config.runtime.update_check_enabled {
            self.start_update_checker().await;
        }
        
        Ok(())
    }
    
    /// Start heartbeat task
    async fn start_heartbeat_task(&self) {
        let telemetry_manager = Arc::clone(&self.telemetry_manager);
        let last_heartbeat = Arc::clone(&self.last_heartbeat);
        let interval_duration = self.config.heartbeat_interval();
        
        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                match telemetry_manager.send_heartbeat().await {
                    Ok(_) => {
                        *last_heartbeat.write().await = Some(Instant::now());
                        debug!("Heartbeat sent successfully");
                    }
                    Err(e) => {
                        warn!("Failed to send heartbeat: {}", e);
                    }
                }
            }
        });
    }
    
    /// Start resource monitoring task
    async fn start_resource_monitoring(&self) {
        let platform_manager = Arc::clone(&self.platform_manager);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.resources.monitor_interval_secs));
            
            loop {
                interval.tick().await;
                
                match platform_manager.get_resource_usage().await {
                    Ok(usage) => {
                        // Check resource limits
                        if usage.cpu_percent > config.resources.max_cpu_percent {
                            warn!("CPU usage exceeds limit: {:.1}%", usage.cpu_percent);
                        }
                        
                        if usage.memory_mb > config.resources.max_memory_mb {
                            warn!("Memory usage exceeds limit: {} MB", usage.memory_mb);
                        }
                    }
                    Err(e) => {
                        error!("Failed to get resource usage: {}", e);
                    }
                }
            }
        });
    }
    
    /// Start security monitoring task
    async fn start_security_monitoring(&self) {
        let security_manager = Arc::clone(&self.security_manager);
        let security_violations = Arc::clone(&self.security_violations);
        let interval_duration = self.config.integrity_check_interval();
        
        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                match security_manager.check_tamper_resistance().await {
                    Ok(violations) => {
                        if !violations.is_empty() {
                            *security_violations.write().await += violations.len() as u64;
                            error!("Security violations detected: {:?}", violations);
                        }
                    }
                    Err(e) => {
                        error!("Security check failed: {}", e);
                    }
                }
            }
        });
    }
    
    /// Start update checker task
    async fn start_update_checker(&self) {
        let update_manager = Arc::clone(&self.update_manager);
        let interval_duration = Duration::from_secs(
            self.config.runtime.update_check_interval_hours * 3600
        );
        
        tokio::spawn(async move {
            let mut interval = interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                match update_manager.check_for_updates().await {
                    Ok(Some(update_info)) => {
                        info!("Update available: {:?}", update_info);
                        // TODO: Handle automatic updates based on policy
                    }
                    Ok(None) => {
                        debug!("No updates available");
                    }
                    Err(e) => {
                        warn!("Update check failed: {}", e);
                    }
                }
            }
        });
    }
    
    /// Perform periodic maintenance
    async fn perform_maintenance(&self) -> Result<()> {
        debug!("Performing periodic maintenance");
        
        // Cleanup old data
        self.storage_manager.cleanup_old_data().await?;
        
        // Rotate logs
        // TODO: Implement log rotation
        
        // Update statistics
        // TODO: Update performance statistics
        
        Ok(())
    }
    
    /// Get current resource usage
    async fn get_resource_usage(&self) -> ResourceUsage {
        match self.platform_manager.get_resource_usage().await {
            Ok(usage) => usage,
            Err(_) => ResourceUsage {
                cpu_percent: 0.0,
                memory_mb: 0,
                disk_mb: 0,
                network_kbps: 0,
            },
        }
    }
    
    /// Get list of active collectors
    async fn get_active_collectors(&self) -> Vec<String> {
        self.telemetry_manager.get_active_collectors().await
            .unwrap_or_default()
    }
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Initializing => write!(f, "Initializing"),
            AgentState::Running => write!(f, "Running"),
            AgentState::Updating => write!(f, "Updating"),
            AgentState::Shutting => write!(f, "Shutting Down"),
            AgentState::Stopped => write!(f, "Stopped"),
            AgentState::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Agent factory for creating configured agents
pub struct AgentFactory;

impl AgentFactory {
    /// Create a production agent with standard configuration
    pub async fn create_production_agent(agent_id: Uuid) -> Result<Agent> {
        let config = AgentConfig::production_default();
        
        let platform_manager = Arc::new(PlatformManager::new(&config).await?);
        let crypto_manager = Arc::new(CryptoManager::new(&config).await?);
        let storage_manager = Arc::new(StorageManager::new(&config, &crypto_manager).await?);
        let security_manager = Arc::new(SecurityManager::new(&config, &crypto_manager).await?);
        let telemetry_manager = Arc::new(TelemetryManager::new(&config, &storage_manager).await?);
        let update_manager = Arc::new(UpdateManager::new(&config, &crypto_manager, &security_manager).await?);
        
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