// iSECTECH Security Agent - Error Handling
// Production-grade error types and handling for security operations
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::fmt;

/// Result type alias for agent operations
pub type Result<T> = std::result::Result<T, AgentError>;

/// Comprehensive error types for the security agent
#[derive(Debug, Clone)]
pub enum AgentError {
    /// Configuration-related errors
    Configuration(String),
    
    /// Cryptographic operation errors
    Cryptography(String),
    
    /// Storage and database errors
    Storage(String),
    
    /// Network communication errors
    Network(String),
    
    /// Platform-specific operation errors
    Platform(String),
    
    /// Security violation or tamper detection
    Security(SecurityError),
    
    /// Authentication and authorization errors
    Authentication(String),
    
    /// Policy enforcement errors
    PolicyEnforcement(String),
    
    /// Data collection errors
    DataCollection(String),
    
    /// Update mechanism errors
    Update(String),
    
    /// Resource limit violations
    ResourceLimit(String),
    
    /// Validation errors
    Validation(String),
    
    /// I/O operation errors
    Io(String),
    
    /// Serialization/deserialization errors
    Serialization(String),
    
    /// Timeout errors
    Timeout(String),
    
    /// Permission or access errors
    Permission(String),
    
    /// Agent lifecycle errors
    Lifecycle(String),
    
    /// Internal logic errors
    Internal(String),
}

/// Security-specific error subtypes
#[derive(Debug, Clone)]
pub enum SecurityError {
    /// Tamper detection - critical security violation
    TamperDetected {
        component: String,
        evidence: String,
        severity: TamperSeverity,
    },
    
    /// Integrity check failure
    IntegrityViolation {
        file_path: String,
        expected_hash: String,
        actual_hash: String,
    },
    
    /// Certificate validation failure
    CertificateValidation {
        certificate: String,
        reason: String,
    },
    
    /// Signature verification failure
    SignatureVerification {
        data_type: String,
        reason: String,
    },
    
    /// Encryption/decryption failure
    EncryptionFailure {
        operation: String,
        reason: String,
    },
    
    /// Key management error
    KeyManagement {
        key_type: String,
        operation: String,
        reason: String,
    },
    
    /// Access control violation
    AccessControl {
        resource: String,
        required_permission: String,
        current_permission: String,
    },
    
    /// Anti-debugging detection
    AntiDebugging {
        detection_method: String,
        evidence: String,
    },
    
    /// Memory protection violation
    MemoryProtection {
        address: Option<usize>,
        violation_type: String,
    },
    
    /// Code injection attempt
    CodeInjection {
        process_id: u32,
        injection_type: String,
        blocked: bool,
    },
}

/// Severity levels for tamper detection
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TamperSeverity {
    /// Low severity - informational
    Low,
    /// Medium severity - suspicious activity
    Medium,
    /// High severity - likely attack
    High,
    /// Critical severity - confirmed attack
    Critical,
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            AgentError::Cryptography(msg) => write!(f, "Cryptographic error: {}", msg),
            AgentError::Storage(msg) => write!(f, "Storage error: {}", msg),
            AgentError::Network(msg) => write!(f, "Network error: {}", msg),
            AgentError::Platform(msg) => write!(f, "Platform error: {}", msg),
            AgentError::Security(err) => write!(f, "Security error: {}", err),
            AgentError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            AgentError::PolicyEnforcement(msg) => write!(f, "Policy enforcement error: {}", msg),
            AgentError::DataCollection(msg) => write!(f, "Data collection error: {}", msg),
            AgentError::Update(msg) => write!(f, "Update error: {}", msg),
            AgentError::ResourceLimit(msg) => write!(f, "Resource limit error: {}", msg),
            AgentError::Validation(msg) => write!(f, "Validation error: {}", msg),
            AgentError::Io(msg) => write!(f, "I/O error: {}", msg),
            AgentError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            AgentError::Timeout(msg) => write!(f, "Timeout error: {}", msg),
            AgentError::Permission(msg) => write!(f, "Permission error: {}", msg),
            AgentError::Lifecycle(msg) => write!(f, "Lifecycle error: {}", msg),
            AgentError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::TamperDetected { component, evidence, severity } => {
                write!(f, "Tamper detected in {} (severity: {:?}): {}", component, severity, evidence)
            }
            SecurityError::IntegrityViolation { file_path, expected_hash, actual_hash } => {
                write!(f, "Integrity violation in {}: expected {}, got {}", file_path, expected_hash, actual_hash)
            }
            SecurityError::CertificateValidation { certificate, reason } => {
                write!(f, "Certificate validation failed for {}: {}", certificate, reason)
            }
            SecurityError::SignatureVerification { data_type, reason } => {
                write!(f, "Signature verification failed for {}: {}", data_type, reason)
            }
            SecurityError::EncryptionFailure { operation, reason } => {
                write!(f, "Encryption operation '{}' failed: {}", operation, reason)
            }
            SecurityError::KeyManagement { key_type, operation, reason } => {
                write!(f, "Key management error for {} during {}: {}", key_type, operation, reason)
            }
            SecurityError::AccessControl { resource, required_permission, current_permission } => {
                write!(f, "Access denied to {}: required {}, have {}", resource, required_permission, current_permission)
            }
            SecurityError::AntiDebugging { detection_method, evidence } => {
                write!(f, "Debugging attempt detected via {}: {}", detection_method, evidence)
            }
            SecurityError::MemoryProtection { address, violation_type } => {
                match address {
                    Some(addr) => write!(f, "Memory protection violation at 0x{:x}: {}", addr, violation_type),
                    None => write!(f, "Memory protection violation: {}", violation_type),
                }
            }
            SecurityError::CodeInjection { process_id, injection_type, blocked } => {
                write!(f, "Code injection attempt in PID {}: {} (blocked: {})", process_id, injection_type, blocked)
            }
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::error::Error for SecurityError {}

impl fmt::Display for TamperSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TamperSeverity::Low => write!(f, "LOW"),
            TamperSeverity::Medium => write!(f, "MEDIUM"),
            TamperSeverity::High => write!(f, "HIGH"),
            TamperSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// Conversion implementations for common error types
impl From<std::io::Error> for AgentError {
    fn from(err: std::io::Error) -> Self {
        AgentError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for AgentError {
    fn from(err: serde_json::Error) -> Self {
        AgentError::Serialization(format!("JSON error: {}", err))
    }
}

impl From<serde_yaml::Error> for AgentError {
    fn from(err: serde_yaml::Error) -> Self {
        AgentError::Serialization(format!("YAML error: {}", err))
    }
}

impl From<tokio::time::error::Elapsed> for AgentError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        AgentError::Timeout(err.to_string())
    }
}

impl From<rusqlite::Error> for AgentError {
    fn from(err: rusqlite::Error) -> Self {
        AgentError::Storage(format!("SQLite error: {}", err))
    }
}

impl From<ring::error::Unspecified> for AgentError {
    fn from(_: ring::error::Unspecified) -> Self {
        AgentError::Cryptography("Cryptographic operation failed".to_string())
    }
}

impl From<reqwest::Error> for AgentError {
    fn from(err: reqwest::Error) -> Self {
        AgentError::Network(format!("HTTP request error: {}", err))
    }
}

impl From<uuid::Error> for AgentError {
    fn from(err: uuid::Error) -> Self {
        AgentError::Validation(format!("UUID error: {}", err))
    }
}

/// Error context for detailed error reporting
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Component where the error occurred
    pub component: String,
    /// Operation that was being performed
    pub operation: String,
    /// Additional context information
    pub context: std::collections::HashMap<String, String>,
    /// Timestamp when the error occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Error severity level
    pub severity: ErrorSeverity,
}

/// Error severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Informational - no action required
    Info,
    /// Warning - attention recommended
    Warning,
    /// Error - action required
    Error,
    /// Critical - immediate action required
    Critical,
    /// Emergency - system compromise suspected
    Emergency,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new(component: &str, operation: &str) -> Self {
        Self {
            component: component.to_string(),
            operation: operation.to_string(),
            context: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now(),
            severity: ErrorSeverity::Error,
        }
    }
    
    /// Add context information
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
    
    /// Set error severity
    pub fn with_severity(mut self, severity: ErrorSeverity) -> Self {
        self.severity = severity;
        self
    }
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Info => write!(f, "INFO"),
            ErrorSeverity::Warning => write!(f, "WARNING"),
            ErrorSeverity::Error => write!(f, "ERROR"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
            ErrorSeverity::Emergency => write!(f, "EMERGENCY"),
        }
    }
}

/// Enhanced result type with context
pub type ContextResult<T> = std::result::Result<T, (AgentError, ErrorContext)>;

/// Trait for adding context to errors
pub trait WithContext<T> {
    /// Add context to an error
    fn with_context(self, context: ErrorContext) -> ContextResult<T>;
    
    /// Add simple context to an error
    fn with_simple_context(self, component: &str, operation: &str) -> ContextResult<T>;
}

impl<T> WithContext<T> for Result<T> {
    fn with_context(self, context: ErrorContext) -> ContextResult<T> {
        match self {
            Ok(value) => Ok(value),
            Err(error) => Err((error, context)),
        }
    }
    
    fn with_simple_context(self, component: &str, operation: &str) -> ContextResult<T> {
        self.with_context(ErrorContext::new(component, operation))
    }
}

/// Security event logger for critical errors
pub struct SecurityEventLogger;

impl SecurityEventLogger {
    /// Log a security event
    pub async fn log_security_event(error: &SecurityError, context: &ErrorContext) {
        use tracing::{error, warn, info};
        
        let log_entry = serde_json::json!({
            "event_type": "security_error",
            "error": error.to_string(),
            "component": context.component,
            "operation": context.operation,
            "severity": context.severity.to_string(),
            "timestamp": context.timestamp.to_rfc3339(),
            "context": context.context,
        });
        
        match context.severity {
            ErrorSeverity::Emergency | ErrorSeverity::Critical => {
                error!("SECURITY ALERT: {}", log_entry);
            }
            ErrorSeverity::Error => {
                error!("Security error: {}", log_entry);
            }
            ErrorSeverity::Warning => {
                warn!("Security warning: {}", log_entry);
            }
            ErrorSeverity::Info => {
                info!("Security info: {}", log_entry);
            }
        }
        
        // TODO: Send to security operations center
        // TODO: Trigger automated response if severity is Emergency/Critical
    }
    
    /// Log a tamper detection event
    pub async fn log_tamper_event(
        component: &str,
        evidence: &str,
        severity: TamperSeverity,
    ) {
        let security_error = SecurityError::TamperDetected {
            component: component.to_string(),
            evidence: evidence.to_string(),
            severity: severity.clone(),
        };
        
        let context = ErrorContext::new("security_manager", "tamper_detection")
            .with_severity(match severity {
                TamperSeverity::Critical => ErrorSeverity::Emergency,
                TamperSeverity::High => ErrorSeverity::Critical,
                TamperSeverity::Medium => ErrorSeverity::Error,
                TamperSeverity::Low => ErrorSeverity::Warning,
            })
            .with_context("tamper_component", component)
            .with_context("tamper_evidence", evidence);
        
        Self::log_security_event(&security_error, &context).await;
    }
}

/// Utility macros for error handling
#[macro_export]
macro_rules! security_error {
    ($variant:ident { $($field:ident: $value:expr),+ }) => {
        $crate::error::AgentError::Security($crate::error::SecurityError::$variant {
            $($field: $value),+
        })
    };
}

#[macro_export]
macro_rules! agent_error {
    ($variant:ident, $msg:expr) => {
        $crate::error::AgentError::$variant($msg.to_string())
    };
    ($variant:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::AgentError::$variant(format!($fmt, $($arg)*))
    };
}

/// Test utilities for error handling
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let error = AgentError::Configuration("Invalid setting".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid setting");
    }
    
    #[test]
    fn test_security_error_display() {
        let error = SecurityError::TamperDetected {
            component: "binary".to_string(),
            evidence: "checksum mismatch".to_string(),
            severity: TamperSeverity::High,
        };
        assert!(error.to_string().contains("Tamper detected"));
    }
    
    #[test]
    fn test_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let agent_error: AgentError = io_error.into();
        
        match agent_error {
            AgentError::Io(_) => (),
            _ => panic!("Expected Io error"),
        }
    }
    
    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("test_component", "test_operation")
            .with_context("key1", "value1")
            .with_severity(ErrorSeverity::Critical);
        
        assert_eq!(context.component, "test_component");
        assert_eq!(context.operation, "test_operation");
        assert_eq!(context.severity, ErrorSeverity::Critical);
        assert_eq!(context.context.get("key1"), Some(&"value1".to_string()));
    }
}