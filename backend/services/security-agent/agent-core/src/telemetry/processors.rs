// iSECTECH Security Agent - Event Processors
// Production-grade telemetry event processing and normalization
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use tracing::{debug, error};

use crate::config::AgentConfig;
use crate::error::Result;
use super::TelemetryEvent;

/// Event processor for telemetry data normalization and enrichment
pub struct EventProcessor {
    /// Agent configuration
    config: AgentConfig,
    /// Agent identifier
    agent_id: Uuid,
    /// Data normalizer
    normalizer: DataNormalizer,
    /// Threat analyzer
    threat_analyzer: ThreatAnalyzer,
}

/// Data normalizer for consistent event formatting
pub struct DataNormalizer {
    /// Normalization rules
    rules: HashMap<String, NormalizationRule>,
}

/// Threat analyzer for security assessment
pub struct ThreatAnalyzer {
    /// Analysis rules
    rules: HashMap<String, ThreatRule>,
}

/// Normalization rule for data processing
#[derive(Debug, Clone)]
struct NormalizationRule {
    /// Rule name
    pub name: String,
    /// Field mappings
    pub field_mappings: HashMap<String, String>,
    /// Data transformations
    pub transformations: Vec<DataTransformation>,
}

/// Data transformation specification
#[derive(Debug, Clone)]
struct DataTransformation {
    /// Field to transform
    pub field: String,
    /// Transformation type
    pub transform_type: TransformationType,
    /// Transformation parameters
    pub parameters: HashMap<String, String>,
}

/// Types of data transformations
#[derive(Debug, Clone)]
enum TransformationType {
    Lowercase,
    Uppercase,
    Hash,
    Truncate,
    Regex,
    DateFormat,
}

/// Threat analysis rule
#[derive(Debug, Clone)]
struct ThreatRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Pattern matching
    pub patterns: Vec<String>,
    /// Threat score (0-100)
    pub threat_score: u8,
}

impl EventProcessor {
    /// Create a new event processor
    pub async fn new(config: &AgentConfig, agent_id: Uuid) -> Result<Self> {
        debug!("Initializing event processor for agent {}", agent_id);
        
        let normalizer = DataNormalizer::new().await?;
        let threat_analyzer = ThreatAnalyzer::new().await?;
        
        Ok(Self {
            config: config.clone(),
            agent_id,
            normalizer,
            threat_analyzer,
        })
    }
    
    /// Process a batch of telemetry events
    pub async fn process_events(&self, events: Vec<TelemetryEvent>) -> Result<Vec<TelemetryEvent>> {
        debug!("Processing {} telemetry events", events.len());
        
        let mut processed_events = Vec::new();
        
        for mut event in events {
            // Normalize event data
            event = self.normalizer.normalize_event(event).await?;
            
            // Analyze for threats
            event = self.threat_analyzer.analyze_event(event).await?;
            
            processed_events.push(event);
        }
        
        debug!("Processed {} events successfully", processed_events.len());
        Ok(processed_events)
    }
}

impl DataNormalizer {
    /// Create a new data normalizer
    pub async fn new() -> Result<Self> {
        debug!("Initializing data normalizer");
        
        Ok(Self {
            rules: Self::create_default_rules(),
        })
    }
    
    /// Create default normalization rules
    fn create_default_rules() -> HashMap<String, NormalizationRule> {
        let mut rules = HashMap::new();
        
        // Process event normalization
        rules.insert("process".to_string(), NormalizationRule {
            name: "process_normalization".to_string(),
            field_mappings: HashMap::from([
                ("process_name".to_string(), "name".to_string()),
                ("process_id".to_string(), "pid".to_string()),
            ]),
            transformations: vec![
                DataTransformation {
                    field: "name".to_string(),
                    transform_type: TransformationType::Lowercase,
                    parameters: HashMap::new(),
                },
            ],
        });
        
        // Network event normalization
        rules.insert("network".to_string(), NormalizationRule {
            name: "network_normalization".to_string(),
            field_mappings: HashMap::from([
                ("source_ip".to_string(), "src_ip".to_string()),
                ("destination_ip".to_string(), "dst_ip".to_string()),
            ]),
            transformations: vec![],
        });
        
        rules
    }
    
    /// Normalize a telemetry event
    pub async fn normalize_event(&self, mut event: TelemetryEvent) -> Result<TelemetryEvent> {
        // Apply normalization rules based on event type
        let event_type_key = format!("{:?}", event.event_type).to_lowercase();
        
        if let Some(rule) = self.rules.get(&event_type_key) {
            // Apply field mappings
            for (old_field, new_field) in &rule.field_mappings {
                if let Some(value) = event.data.structured.remove(old_field) {
                    event.data.structured.insert(new_field.clone(), value);
                }
            }
            
            // Apply transformations
            for transformation in &rule.transformations {
                self.apply_transformation(&mut event, transformation).await?;
            }
        }
        
        Ok(event)
    }
    
    /// Apply a data transformation to an event
    async fn apply_transformation(
        &self,
        event: &mut TelemetryEvent,
        transformation: &DataTransformation,
    ) -> Result<()> {
        if let Some(value) = event.data.structured.get_mut(&transformation.field) {
            match &transformation.transform_type {
                TransformationType::Lowercase => {
                    if let Some(string_val) = value.as_str() {
                        *value = serde_json::Value::String(string_val.to_lowercase());
                    }
                }
                TransformationType::Uppercase => {
                    if let Some(string_val) = value.as_str() {
                        *value = serde_json::Value::String(string_val.to_uppercase());
                    }
                }
                TransformationType::Hash => {
                    if let Some(string_val) = value.as_str() {
                        // Simple hash for demonstration
                        let hash = format!("{:x}", md5::compute(string_val.as_bytes()));
                        *value = serde_json::Value::String(hash);
                    }
                }
                _ => {
                    // TODO: Implement other transformation types
                }
            }
        }
        
        Ok(())
    }
}

impl ThreatAnalyzer {
    /// Create a new threat analyzer
    pub async fn new() -> Result<Self> {
        debug!("Initializing threat analyzer");
        
        Ok(Self {
            rules: Self::create_default_rules(),
        })
    }
    
    /// Create default threat analysis rules
    fn create_default_rules() -> HashMap<String, ThreatRule> {
        let mut rules = HashMap::new();
        
        rules.insert("powershell_encoded".to_string(), ThreatRule {
            name: "powershell_encoded".to_string(),
            description: "PowerShell with encoded commands".to_string(),
            patterns: vec![
                "powershell".to_string(),
                "-encodedcommand".to_string(),
                "-enc".to_string(),
            ],
            threat_score: 85,
        });
        
        rules.insert("suspicious_network".to_string(), ThreatRule {
            name: "suspicious_network".to_string(),
            description: "Suspicious network activity".to_string(),
            patterns: vec![
                "tor".to_string(),
                "onion".to_string(),
                "darkweb".to_string(),
            ],
            threat_score: 70,
        });
        
        rules
    }
    
    /// Analyze an event for threats
    pub async fn analyze_event(&self, mut event: TelemetryEvent) -> Result<TelemetryEvent> {
        let mut max_threat_score = 0u8;
        let mut threat_indicators = Vec::new();
        
        // Convert event data to searchable text
        let event_text = serde_json::to_string(&event.data.structured).unwrap_or_default().to_lowercase();
        
        // Check against threat rules
        for rule in self.rules.values() {
            let mut pattern_matches = 0;
            
            for pattern in &rule.patterns {
                if event_text.contains(&pattern.to_lowercase()) {
                    pattern_matches += 1;
                }
            }
            
            if pattern_matches > 0 {
                threat_indicators.push(format!("Rule: {} (matches: {})", rule.name, pattern_matches));
                max_threat_score = max_threat_score.max(rule.threat_score);
            }
        }
        
        // Update event with threat information
        if !threat_indicators.is_empty() {
            event.data.structured.insert(
                "threat_score".to_string(),
                serde_json::Value::Number(max_threat_score.into()),
            );
            event.data.structured.insert(
                "threat_indicators".to_string(),
                serde_json::Value::Array(
                    threat_indicators.iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect()
                ),
            );
        }
        
        Ok(event)
    }
}