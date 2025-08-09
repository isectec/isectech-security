// iSECTECH Security Agent - Metrics and Monitoring
// Performance metrics and health monitoring
// Copyright (c) 2024 iSECTECH. All rights reserved.

//! Metrics collection and monitoring for agent performance
//! 
//! This module provides comprehensive metrics collection for monitoring
//! agent health, performance, and security posture.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Metrics collector for agent monitoring
pub struct MetricsCollector {
    /// Performance counters
    counters: Arc<RwLock<HashMap<String, u64>>>,
    /// Gauge metrics
    gauges: Arc<RwLock<HashMap<String, f64>>>,
    /// Start time for uptime calculation
    start_time: Instant,
}

/// Agent performance metrics
#[derive(Debug, Clone)]
pub struct AgentMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in MB
    pub memory_usage: u64,
    /// Disk usage in MB
    pub disk_usage: u64,
    /// Network throughput in Kbps
    pub network_throughput: u64,
    /// Events processed per second
    pub events_per_second: f64,
    /// Error count
    pub error_count: u64,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
        }
    }
    
    /// Increment a counter metric
    pub async fn increment_counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.write().await;
        *counters.entry(name.to_string()).or_insert(0) += value;
    }
    
    /// Set a gauge metric
    pub async fn set_gauge(&self, name: &str, value: f64) {
        let mut gauges = self.gauges.write().await;
        gauges.insert(name.to_string(), value);
    }
    
    /// Get current agent metrics
    pub async fn get_metrics(&self) -> AgentMetrics {
        let counters = self.counters.read().await;
        let gauges = self.gauges.read().await;
        
        AgentMetrics {
            cpu_usage: gauges.get("cpu_usage").copied().unwrap_or(0.0),
            memory_usage: *counters.get("memory_usage").unwrap_or(&0),
            disk_usage: *counters.get("disk_usage").unwrap_or(&0),
            network_throughput: *counters.get("network_throughput").unwrap_or(&0),
            events_per_second: gauges.get("events_per_second").copied().unwrap_or(0.0),
            error_count: *counters.get("error_count").unwrap_or(&0),
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }
    
    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let counters = self.counters.read().await;
        let gauges = self.gauges.read().await;
        
        let mut output = String::new();
        
        // Export counters
        for (name, value) in counters.iter() {
            output.push_str(&format!(
                "# TYPE isectech_agent_{} counter\nisectech_agent_{} {}\n",
                name, name, value
            ));
        }
        
        // Export gauges
        for (name, value) in gauges.iter() {
            output.push_str(&format!(
                "# TYPE isectech_agent_{} gauge\nisectech_agent_{} {}\n",
                name, name, value
            ));
        }
        
        // Add uptime
        output.push_str(&format!(
            "# TYPE isectech_agent_uptime_seconds gauge\nisectech_agent_uptime_seconds {}\n",
            self.start_time.elapsed().as_secs()
        ));
        
        output
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}