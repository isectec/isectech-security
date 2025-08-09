// iSECTECH Security Agent - Event Correlation
// Production-grade event correlation and pattern analysis
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use tracing::{debug, error};

use crate::config::AgentConfig;
use crate::error::Result;
use super::{TelemetryEvent, EventSeverity};

/// Event correlation engine for identifying related security events
pub struct EventCorrelationEngine {
    /// Correlation rules
    rules: Vec<CorrelationRule>,
    /// Event windows for correlation
    event_windows: HashMap<String, Vec<TelemetryEvent>>,
    /// Correlation timeout
    correlation_timeout: Duration,
}

/// Correlation rule for identifying related events
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    /// Rule identifier
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Event types to correlate
    pub event_types: Vec<String>,
    /// Correlation fields
    pub correlation_fields: Vec<String>,
    /// Time window for correlation
    pub time_window: Duration,
    /// Minimum events required
    pub min_events: usize,
    /// Maximum events in window
    pub max_events: usize,
    /// Correlation severity
    pub severity: EventSeverity,
    /// Threat score for correlated events
    pub threat_score: u8,
}

impl EventCorrelationEngine {
    /// Create a new event correlation engine
    pub async fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Initializing event correlation engine");
        
        Ok(Self {
            rules: Self::create_default_rules(),
            event_windows: HashMap::new(),
            correlation_timeout: Duration::from_secs(300), // 5 minutes
        })
    }
    
    /// Create default correlation rules for iSECTECH
    fn create_default_rules() -> Vec<CorrelationRule> {
        vec![
            CorrelationRule {
                id: "process_network_correlation".to_string(),
                name: "Process-Network Correlation".to_string(),
                description: "Correlate process creation with network activity".to_string(),
                event_types: vec!["ProcessEvent".to_string(), "NetworkEvent".to_string()],
                correlation_fields: vec!["pid".to_string(), "process_name".to_string()],
                time_window: Duration::from_secs(60),
                min_events: 2,
                max_events: 50,
                severity: EventSeverity::Medium,
                threat_score: 60,
            },
            CorrelationRule {
                id: "file_process_correlation".to_string(),
                name: "File-Process Correlation".to_string(),
                description: "Correlate file creation/modification with process execution".to_string(),
                event_types: vec!["FileSystemEvent".to_string(), "ProcessEvent".to_string()],
                correlation_fields: vec!["process_id".to_string(), "exe_path".to_string()],
                time_window: Duration::from_secs(30),
                min_events: 2,
                max_events: 100,
                severity: EventSeverity::High,
                threat_score: 75,
            },
            CorrelationRule {
                id: "lateral_movement".to_string(),
                name: "Lateral Movement Pattern".to_string(),
                description: "Multiple network connections from same process".to_string(),
                event_types: vec!["NetworkEvent".to_string()],
                correlation_fields: vec!["process_id".to_string(), "local_addr".to_string()],
                time_window: Duration::from_secs(180),
                min_events: 5,
                max_events: 1000,
                severity: EventSeverity::Critical,
                threat_score: 90,
            },
            CorrelationRule {
                id: "privilege_escalation".to_string(),
                name: "Privilege Escalation Sequence".to_string(),
                description: "Process spawn chain with increasing privileges".to_string(),
                event_types: vec!["ProcessEvent".to_string()],
                correlation_fields: vec!["ppid".to_string(), "pid".to_string()],
                time_window: Duration::from_secs(120),
                min_events: 3,
                max_events: 20,
                severity: EventSeverity::Critical,
                threat_score: 95,
            },
        ]
    }
    
    /// Correlate events and generate correlation events
    pub async fn correlate_events(&self, events: &[TelemetryEvent]) -> Result<Vec<TelemetryEvent>> {
        debug!("Correlating {} events", events.len());
        
        let mut correlated_events = Vec::new();
        
        // Process each correlation rule
        for rule in &self.rules {
            if let Ok(rule_events) = self.apply_correlation_rule(rule, events).await {
                correlated_events.extend(rule_events);
            }
        }
        
        debug!("Generated {} correlated events", correlated_events.len());
        Ok(correlated_events)
    }
    
    /// Apply a specific correlation rule to events
    async fn apply_correlation_rule(
        &self,
        rule: &CorrelationRule,
        events: &[TelemetryEvent],
    ) -> Result<Vec<TelemetryEvent>> {
        let mut correlated_events = Vec::new();
        
        // Filter events by type
        let relevant_events: Vec<&TelemetryEvent> = events.iter()
            .filter(|event| {
                let event_type = format!("{:?}", event.event_type);
                rule.event_types.contains(&event_type)
            })
            .collect();
        
        if relevant_events.len() < rule.min_events {
            return Ok(correlated_events);
        }
        
        // Group events by correlation fields
        let mut event_groups = HashMap::new();
        
        for event in relevant_events {
            let correlation_key = self.extract_correlation_key(event, &rule.correlation_fields);
            event_groups.entry(correlation_key)
                .or_insert_with(Vec::new)
                .push(event);
        }
        
        // Check each group for correlation
        for (correlation_key, group_events) in event_groups {
            if group_events.len() >= rule.min_events && group_events.len() <= rule.max_events {
                // Check time window
                if self.events_within_time_window(&group_events, rule.time_window) {
                    // Generate correlation event
                    let correlation_event = self.create_correlation_event(
                        rule,
                        &correlation_key,
                        &group_events,
                    ).await?;
                    
                    correlated_events.push(correlation_event);
                }
            }
        }
        
        Ok(correlated_events)
    }
    
    /// Extract correlation key from event
    fn extract_correlation_key(&self, event: &TelemetryEvent, fields: &[String]) -> String {
        let mut key_parts = Vec::new();
        
        for field in fields {
            if let Some(value) = event.data.structured.get(field) {
                key_parts.push(value.to_string());
            }
        }
        
        key_parts.join("|")
    }
    
    /// Check if events are within time window
    fn events_within_time_window(&self, events: &[&TelemetryEvent], window: Duration) -> bool {
        if events.len() < 2 {
            return true;
        }
        
        let mut timestamps: Vec<SystemTime> = events.iter()
            .map(|event| event.timestamp)
            .collect();
        
        timestamps.sort();
        
        if let (Some(first), Some(last)) = (timestamps.first(), timestamps.last()) {
            if let Ok(duration) = last.duration_since(*first) {
                return duration <= window;
            }
        }
        
        false
    }
    
    /// Create a correlation event
    async fn create_correlation_event(
        &self,
        rule: &CorrelationRule,
        correlation_key: &str,
        events: &[&TelemetryEvent],
    ) -> Result<TelemetryEvent> {
        let mut event_data = HashMap::new();
        
        // Basic correlation information
        event_data.insert("rule_id".to_string(), serde_json::Value::String(rule.id.clone()));
        event_data.insert("rule_name".to_string(), serde_json::Value::String(rule.name.clone()));
        event_data.insert("correlation_key".to_string(), serde_json::Value::String(correlation_key.to_string()));
        event_data.insert("event_count".to_string(), serde_json::Value::Number(events.len().into()));
        event_data.insert("threat_score".to_string(), serde_json::Value::Number(rule.threat_score.into()));
        
        // Event IDs for reference
        let event_ids: Vec<serde_json::Value> = events.iter()
            .map(|event| serde_json::Value::String(event.event_id.to_string()))
            .collect();
        event_data.insert("correlated_events".to_string(), serde_json::Value::Array(event_ids));
        
        // Time range
        let timestamps: Vec<SystemTime> = events.iter()
            .map(|event| event.timestamp)
            .collect();
        
        if let (Some(first), Some(last)) = (timestamps.iter().min(), timestamps.iter().max()) {
            event_data.insert("time_range_start".to_string(), 
                serde_json::Value::String(format!("{:?}", first)));
            event_data.insert("time_range_end".to_string(), 
                serde_json::Value::String(format!("{:?}", last)));
            
            if let Ok(duration) = last.duration_since(*first) {
                event_data.insert("time_span_seconds".to_string(), 
                    serde_json::Value::Number(duration.as_secs().into()));
            }
        }
        
        // Extract common fields from correlated events
        self.extract_common_fields(&mut event_data, events);
        
        // Generate correlation IDs for all related events
        let correlation_ids: Vec<Uuid> = events.iter()
            .map(|event| event.event_id)
            .collect();
        
        let correlation_event = TelemetryEvent {
            event_id: Uuid::new_v4(),
            agent_id: events[0].agent_id, // Use agent ID from first event
            event_type: super::TelemetryEventType::AnomalyEvent, // Correlation events are anomalies
            timestamp: SystemTime::now(),
            source: super::EventSource {
                id: format!("correlation_{}", rule.id),
                source_type: super::SourceType::Unknown,
                name: "Event Correlation Engine".to_string(),
                attributes: HashMap::new(),
            },
            data: super::EventData {
                structured: event_data,
                raw: None,
                hash: "".to_string(),
            },
            threat_indicators: vec![], // TODO: Add threat indicators
            severity: rule.severity.clone(),
            metadata: super::EventMetadata {
                processed_at: SystemTime::now(),
                correlation_ids,
                tags: vec!["correlation".to_string(), "iSECTECH".to_string()],
                custom: HashMap::new(),
            },
        };
        
        Ok(correlation_event)
    }
    
    /// Extract common fields from correlated events
    fn extract_common_fields(&self, event_data: &mut HashMap<String, serde_json::Value>, events: &[&TelemetryEvent]) {
        // Find fields that appear in multiple events
        let mut field_counts = HashMap::new();
        
        for event in events {
            for field in event.data.structured.keys() {
                *field_counts.entry(field.clone()).or_insert(0) += 1;
            }
        }
        
        // Include fields that appear in at least half the events
        let threshold = events.len() / 2;
        for (field, count) in field_counts {
            if count >= threshold {
                // Get values for this field from all events
                let mut values = Vec::new();
                for event in events {
                    if let Some(value) = event.data.structured.get(&field) {
                        values.push(value.clone());
                    }
                }
                
                if !values.is_empty() {
                    event_data.insert(format!("common_{}", field), serde_json::Value::Array(values));
                }
            }
        }
    }
}