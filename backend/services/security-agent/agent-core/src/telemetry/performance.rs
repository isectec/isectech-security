// iSECTECH Security Agent - Performance Monitoring
// Production-grade performance monitoring and resource usage tracking
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{warn, error, debug};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};

/// Performance monitor for tracking resource usage and constraints
pub struct PerformanceMonitor {
    /// Configuration
    config: AgentConfig,
    /// Current metrics
    current_metrics: Arc<RwLock<ResourceMetrics>>,
    /// Performance history
    metrics_history: Arc<RwLock<Vec<ResourceMetrics>>>,
    /// Resource constraints
    constraints: Arc<RwLock<ResourceConstraints>>,
    /// Running state
    is_running: Arc<RwLock<bool>>,
}

/// Resource usage metrics
#[derive(Debug, Clone, Default)]
pub struct ResourceMetrics {
    /// CPU usage percentage (0.0 to 100.0)
    pub cpu_usage_percent: f64,
    /// Memory usage in megabytes
    pub memory_usage_mb: u64,
    /// Disk usage in megabytes
    pub disk_usage_mb: u64,
    /// Network usage in kilobytes per second
    pub network_usage_kbps: u64,
    /// Number of open file descriptors
    pub open_file_descriptors: u32,
    /// Number of active threads
    pub active_threads: u32,
    /// Timestamp when metrics were collected
    pub timestamp: SystemTime,
}

/// Resource constraints and limits
#[derive(Debug, Clone)]
pub struct ResourceConstraints {
    /// Maximum CPU usage percentage
    pub max_cpu_percent: f64,
    /// Maximum memory usage in megabytes
    pub max_memory_mb: u64,
    /// Maximum disk usage in megabytes
    pub max_disk_mb: u64,
    /// Maximum network usage in kilobytes per second
    pub max_network_kbps: u64,
    /// Maximum open file descriptors
    pub max_file_descriptors: u32,
    /// Enable adaptive throttling
    pub adaptive_throttling: bool,
}

impl Default for ResourceConstraints {
    fn default() -> Self {
        Self {
            max_cpu_percent: 2.0, // 2% max CPU usage for iSECTECH agent
            max_memory_mb: 100,   // 100MB max memory usage
            max_disk_mb: 1000,    // 1GB max disk usage
            max_network_kbps: 1000, // 1MB/s max network usage
            max_file_descriptors: 1000,
            adaptive_throttling: true,
        }
    }
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub async fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Initializing performance monitor");
        
        Ok(Self {
            config: config.clone(),
            current_metrics: Arc::new(RwLock::new(ResourceMetrics::default())),
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            constraints: Arc::new(RwLock::new(ResourceConstraints::default())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Start performance monitoring
    pub async fn start(&self) -> Result<()> {
        info!("Starting performance monitoring");
        
        *self.is_running.write().await = true;
        
        // Start monitoring loop
        let current_metrics = Arc::clone(&self.current_metrics);
        let metrics_history = Arc::clone(&self.metrics_history);
        let is_running = Arc::clone(&self.is_running);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            
            while *is_running.read().await {
                interval.tick().await;
                
                match Self::collect_system_metrics().await {
                    Ok(metrics) => {
                        // Update current metrics
                        *current_metrics.write().await = metrics.clone();
                        
                        // Add to history (keep last 100 entries)
                        let mut history = metrics_history.write().await;
                        history.push(metrics);
                        if history.len() > 100 {
                            history.remove(0);
                        }
                    }
                    Err(e) => {
                        error!("Failed to collect system metrics: {}", e);
                    }
                }
            }
        });
        
        info!("Performance monitoring started");
        Ok(())
    }
    
    /// Stop performance monitoring
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping performance monitoring");
        
        *self.is_running.write().await = false;
        
        info!("Performance monitoring stopped");
        Ok(())
    }
    
    /// Get current resource metrics
    pub async fn get_current_metrics(&self) -> Result<ResourceMetrics> {
        Ok(self.current_metrics.read().await.clone())
    }
    
    /// Get resource constraints
    pub async fn get_constraints(&self) -> ResourceConstraints {
        self.constraints.read().await.clone()
    }
    
    /// Update resource constraints
    pub async fn update_constraints(&self, constraints: ResourceConstraints) {
        *self.constraints.write().await = constraints;
        debug!("Resource constraints updated");
    }
    
    /// Check if resource usage is within constraints
    pub async fn check_constraints(&self) -> Result<bool> {
        let metrics = self.current_metrics.read().await;
        let constraints = self.constraints.read().await;
        
        let within_limits = 
            metrics.cpu_usage_percent <= constraints.max_cpu_percent &&
            metrics.memory_usage_mb <= constraints.max_memory_mb &&
            metrics.disk_usage_mb <= constraints.max_disk_mb &&
            metrics.network_usage_kbps <= constraints.max_network_kbps &&
            metrics.open_file_descriptors <= constraints.max_file_descriptors;
        
        if !within_limits {
            warn!("Resource usage exceeds constraints: CPU {:.1}%, Memory {}MB, Disk {}MB", 
                   metrics.cpu_usage_percent, metrics.memory_usage_mb, metrics.disk_usage_mb);
        }
        
        Ok(within_limits)
    }
    
    /// Collect system metrics (platform-specific implementation)
    async fn collect_system_metrics() -> Result<ResourceMetrics> {
        let mut metrics = ResourceMetrics {
            timestamp: SystemTime::now(),
            ..Default::default()
        };
        
        // Platform-specific implementation would go here
        // For now, we'll use simulated values
        
        #[cfg(unix)]
        {
            Self::collect_unix_metrics(&mut metrics).await?;
        }
        
        #[cfg(windows)]
        {
            Self::collect_windows_metrics(&mut metrics).await?;
        }
        
        // Fallback for unsupported platforms
        #[cfg(not(any(unix, windows)))]
        {
            debug!("System metrics collection not implemented for this platform");
        }
        
        Ok(metrics)
    }
    
    #[cfg(unix)]
    async fn collect_unix_metrics(metrics: &mut ResourceMetrics) -> Result<()> {
        // TODO: Implement Unix-specific metrics collection
        // - Parse /proc/stat for CPU usage
        // - Parse /proc/meminfo for memory usage
        // - Parse /proc/net/dev for network usage
        // - Use getrusage() for process-specific metrics
        
        // Simulated values for now
        metrics.cpu_usage_percent = 1.5;
        metrics.memory_usage_mb = 45;
        metrics.disk_usage_mb = 100;
        metrics.network_usage_kbps = 50;
        metrics.open_file_descriptors = 25;
        metrics.active_threads = 8;
        
        Ok(())
    }
    
    #[cfg(windows)]
    async fn collect_windows_metrics(metrics: &mut ResourceMetrics) -> Result<()> {
        // TODO: Implement Windows-specific metrics collection
        // - Use Performance Data Helper (PDH) APIs
        // - Use Windows Management Instrumentation (WMI)
        // - Use GetProcessMemoryInfo for process metrics
        
        // Simulated values for now
        metrics.cpu_usage_percent = 1.8;
        metrics.memory_usage_mb = 52;
        metrics.disk_usage_mb = 120;
        metrics.network_usage_kbps = 60;
        metrics.open_file_descriptors = 30;
        metrics.active_threads = 10;
        
        Ok(())
    }
}

/// Utility functions for performance monitoring
pub mod utils {
    use super::*;
    
    /// Convert bytes to megabytes
    pub fn bytes_to_mb(bytes: u64) -> u64 {
        bytes / (1024 * 1024)
    }
    
    /// Convert kilobytes to megabytes
    pub fn kb_to_mb(kb: u64) -> u64 {
        kb / 1024
    }
    
    /// Calculate CPU usage percentage
    pub fn calculate_cpu_percentage(user_time: u64, system_time: u64, total_time: u64) -> f64 {
        if total_time == 0 {
            return 0.0;
        }
        
        ((user_time + system_time) as f64 / total_time as f64) * 100.0
    }
    
    /// Calculate memory usage percentage
    pub fn calculate_memory_percentage(used_memory: u64, total_memory: u64) -> f64 {
        if total_memory == 0 {
            return 0.0;
        }
        
        (used_memory as f64 / total_memory as f64) * 100.0
    }
}