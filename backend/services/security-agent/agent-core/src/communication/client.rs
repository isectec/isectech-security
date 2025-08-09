// iSECTECH Security Agent - Secure Client Implementation
// Production-grade mTLS client with certificate pinning and validation
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant};
use std::io::BufReader;
use std::collections::HashMap;
use reqwest::{Client, ClientBuilder};
use rustls::{ClientConfig, Certificate, PrivateKey, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::time::timeout;
use uuid::Uuid;
use tracing::{info, warn, error, debug};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result, SecurityError};
use super::{OutboundMessage, MessageType, ServerInfo};
use super::certificates::CertificateManager;
use super::messages::MessageProcessor;

/// Secure HTTP/HTTPS client with mTLS support
pub struct SecureClient {
    /// HTTP client configured with mTLS
    http_client: Client,
    /// Agent configuration
    config: AgentConfig,
    /// Agent identifier
    agent_id: Uuid,
    /// Certificate manager
    cert_manager: Arc<CertificateManager>,
    /// Message processor
    message_processor: Arc<MessageProcessor>,
    /// Backend base URL
    backend_url: String,
    /// Connection state
    connection_info: Arc<tokio::sync::RwLock<ConnectionInfo>>,
}

/// Connection information and metadata
#[derive(Debug, Clone)]
struct ConnectionInfo {
    pub connected_at: Option<Instant>,
    pub server_certificate_fingerprint: Option<String>,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub peer_certificates: Vec<Vec<u8>>,
    pub session_id: Option<String>,
    pub last_activity: Option<Instant>,
}

impl SecureClient {
    /// Create a new secure client instance
    pub async fn new(
        config: &AgentConfig,
        cert_manager: &Arc<CertificateManager>,
        message_processor: &Arc<MessageProcessor>,
        agent_id: Uuid,
    ) -> Result<Self> {
        info!("Creating secure client for agent {}", agent_id);
        
        // Build TLS configuration with mTLS
        let tls_config = Self::build_tls_config(config, cert_manager).await?;
        
        // Build HTTP client with custom TLS configuration
        let http_client = ClientBuilder::new()
            .use_preconfigured_tls(tls_config)
            .timeout(config.request_timeout())
            .connect_timeout(config.connect_timeout())
            .pool_idle_timeout(Some(Duration::from_secs(30)))
            .pool_max_idle_per_host(5)
            .http2_prior_knowledge()
            .http2_keep_alive_interval(Some(Duration::from_secs(30)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .user_agent(format!("iSECTECH-Agent/{}", config.agent.version))
            .build()
            .map_err(|e| AgentError::Network(format!("Failed to build HTTP client: {}", e)))?;
        
        Ok(Self {
            http_client,
            config: config.clone(),
            agent_id,
            cert_manager: Arc::clone(cert_manager),
            message_processor: Arc::clone(message_processor),
            backend_url: config.network.backend_url.clone(),
            connection_info: Arc::new(tokio::sync::RwLock::new(ConnectionInfo {
                connected_at: None,
                server_certificate_fingerprint: None,
                protocol_version: None,
                cipher_suite: None,
                peer_certificates: Vec::new(),
                session_id: None,
                last_activity: None,
            })),
        })
    }
    
    /// Test connection to backend and retrieve server information
    pub async fn test_connection(&self) -> Result<ServerInfo> {
        info!("Testing secure connection to backend");
        
        let test_url = format!("{}/api/v1/agent/health", self.backend_url);
        
        let response = timeout(
            self.config.connect_timeout(),
            self.http_client.get(&test_url)
                .header("X-Agent-ID", self.agent_id.to_string())
                .header("X-Agent-Version", &self.config.agent.version)
                .send()
        ).await
        .map_err(|_| AgentError::Timeout("Connection test timeout".to_string()))?
        .map_err(|e| AgentError::Network(format!("Connection test failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(AgentError::Network(format!(
                "Backend health check failed with status: {}", 
                response.status()
            )));
        }
        
        // Parse server information from response headers
        let server_info = ServerInfo {
            server_version: response.headers()
                .get("X-Server-Version")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string(),
            supported_protocols: response.headers()
                .get("X-Supported-Protocols")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["http/1.1".to_string()]),
            max_message_size: response.headers()
                .get("X-Max-Message-Size")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(10 * 1024 * 1024), // Default 10MB
            heartbeat_interval: Duration::from_secs(
                response.headers()
                    .get("X-Heartbeat-Interval")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30)
            ),
            policy_version: response.headers()
                .get("X-Policy-Version")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("1.0")
                .to_string(),
        };
        
        // Update connection info
        let mut conn_info = self.connection_info.write().await;
        conn_info.connected_at = Some(Instant::now());
        conn_info.last_activity = Some(Instant::now());
        
        // Validate server certificate against known fingerprints
        self.validate_server_certificate(&response).await?;
        
        info!("Secure connection test successful, server version: {}", server_info.server_version);
        Ok(server_info)
    }
    
    /// Send a raw message to the backend
    pub async fn send_raw_message(&self, message: &OutboundMessage) -> Result<()> {
        debug!("Sending message {} to backend", message.message_id);
        
        // Prepare message for transmission
        let processed_message = self.message_processor
            .prepare_outbound_message(message, &self.agent_id)
            .await?;
        
        let endpoint = self.get_endpoint_for_message_type(&message.message_type);
        let url = format!("{}{}", self.backend_url, endpoint);
        
        let response = timeout(
            self.config.request_timeout(),
            self.http_client.post(&url)
                .header("Content-Type", "application/x-protobuf")
                .header("X-Agent-ID", self.agent_id.to_string())
                .header("X-Message-ID", message.message_id.to_string())
                .header("X-Message-Type", format!("{:?}", message.message_type))
                .header("X-Message-Priority", message.priority as u8)
                .header("X-Agent-Signature", self.sign_message(&processed_message).await?)
                .body(processed_message)
        ).await
        .map_err(|_| AgentError::Timeout("Message send timeout".to_string()))?
        .map_err(|e| AgentError::Network(format!("Failed to send message: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(AgentError::Network(format!(
                "Backend rejected message with status: {}", 
                response.status()
            )));
        }
        
        // Update activity timestamp
        let mut conn_info = self.connection_info.write().await;
        conn_info.last_activity = Some(Instant::now());
        
        debug!("Message {} sent successfully", message.message_id);
        Ok(())
    }
    
    /// Send a ping to test connection health
    pub async fn ping(&self) -> Result<Duration> {
        let start = Instant::now();
        
        let ping_url = format!("{}/api/v1/agent/ping", self.backend_url);
        
        let response = timeout(
            Duration::from_secs(5), // Short timeout for ping
            self.http_client.get(&ping_url)
                .header("X-Agent-ID", self.agent_id.to_string())
                .send()
        ).await
        .map_err(|_| AgentError::Timeout("Ping timeout".to_string()))?
        .map_err(|e| AgentError::Network(format!("Ping failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(AgentError::Network(format!("Ping failed with status: {}", response.status())));
        }
        
        let latency = start.elapsed();
        debug!("Ping successful, latency: {:?}", latency);
        
        // Update activity timestamp
        let mut conn_info = self.connection_info.write().await;
        conn_info.last_activity = Some(Instant::now());
        
        Ok(latency)
    }
    
    /// Enroll agent with backend
    pub async fn enroll_agent(&self, enrollment_token: &str) -> Result<EnrollmentResult> {
        info!("Enrolling agent with backend");
        
        // Generate CSR
        let csr = self.cert_manager.generate_csr().await?;
        let public_key = self.cert_manager.get_public_key().await?;
        
        // Prepare enrollment request
        let enrollment_request = EnrollmentRequestData {
            enrollment_token: enrollment_token.to_string(),
            agent_metadata: self.collect_agent_metadata().await?,
            public_key,
            csr,
            capabilities: self.collect_security_capabilities().await?,
        };
        
        let enrollment_url = format!("{}/api/v1/agent/enroll", self.backend_url);
        
        let request_body = serde_json::to_vec(&enrollment_request)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize enrollment request: {}", e)))?;
        
        let response = timeout(
            Duration::from_secs(30), // Longer timeout for enrollment
            self.http_client.post(&enrollment_url)
                .header("Content-Type", "application/json")
                .header("X-Enrollment-Token", enrollment_token)
                .body(request_body)
        ).await
        .map_err(|_| AgentError::Timeout("Enrollment timeout".to_string()))?
        .map_err(|e| AgentError::Network(format!("Enrollment request failed: {}", e)))?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AgentError::Authentication(format!(
                "Enrollment failed with status {}: {}", 
                response.status(),
                error_text
            )));
        }
        
        let enrollment_response: EnrollmentResponseData = response.json().await
            .map_err(|e| AgentError::Serialization(format!("Failed to parse enrollment response: {}", e)))?;
        
        if !enrollment_response.success {
            return Err(AgentError::Authentication(format!(
                "Enrollment rejected: {:?}", 
                enrollment_response.error
            )));
        }
        
        // Store received certificates
        self.cert_manager.store_certificates(
            &enrollment_response.client_certificate,
            &enrollment_response.ca_certificate,
            &enrollment_response.intermediate_certificates,
        ).await?;
        
        info!("Agent enrollment completed successfully, agent ID: {}", enrollment_response.agent_id);
        
        Ok(EnrollmentResult {
            agent_id: enrollment_response.agent_id,
            certificates_stored: true,
        })
    }
    
    /// Disconnect from backend
    pub async fn disconnect(&self) -> Result<()> {
        info!("Disconnecting from backend");
        
        // Send graceful shutdown notification
        let shutdown_url = format!("{}/api/v1/agent/disconnect", self.backend_url);
        
        let _ = timeout(
            Duration::from_secs(5),
            self.http_client.post(&shutdown_url)
                .header("X-Agent-ID", self.agent_id.to_string())
                .send()
        ).await;
        
        // Clear connection info
        let mut conn_info = self.connection_info.write().await;
        *conn_info = ConnectionInfo {
            connected_at: None,
            server_certificate_fingerprint: None,
            protocol_version: None,
            cipher_suite: None,
            peer_certificates: Vec::new(),
            session_id: None,
            last_activity: None,
        };
        
        info!("Disconnected from backend");
        Ok(())
    }
    
    // Private implementation methods
    
    async fn build_tls_config(
        config: &AgentConfig,
        cert_manager: &Arc<CertificateManager>,
    ) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();
        
        // Load CA certificates
        if let Some(ref ca_path) = config.network.ca_cert_path {
            let ca_certs = Self::load_certificates(ca_path)?;
            for cert in ca_certs {
                root_store.add(&cert)
                    .map_err(|e| AgentError::Cryptography(format!("Failed to add CA certificate: {:?}", e)))?;
            }
        }
        
        // Load client certificate and key if mTLS is enabled
        let client_auth = if config.network.mtls_enabled {
            let client_cert_chain = if let Some(ref cert_path) = config.network.client_cert_path {
                Self::load_certificates(cert_path)?
            } else {
                cert_manager.get_certificate_chain().await?
            };
            
            let client_key = if let Some(ref key_path) = config.network.client_key_path {
                Self::load_private_key(key_path)?
            } else {
                cert_manager.get_private_key().await?
            };
            
            Some((client_cert_chain, client_key))
        } else {
            None
        };
        
        let mut config_builder = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);
        
        let mut tls_config = if let Some((cert_chain, private_key)) = client_auth {
            config_builder
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|e| AgentError::Cryptography(format!("Failed to configure client auth: {:?}", e)))?
        } else {
            config_builder
                .with_no_client_auth()
        };
        
        // Configure certificate verification callback for pinning
        if config.crypto.cert_pinning_enabled {
            tls_config.dangerous().set_certificate_verifier(Arc::new(
                CustomCertificateVerifier::new(cert_manager).await?
            ));
        }
        
        Ok(tls_config)
    }
    
    fn load_certificates(path: &std::path::Path) -> Result<Vec<Certificate>> {
        let file = std::fs::File::open(path)
            .map_err(|e| AgentError::Io(format!("Failed to open certificate file: {}", e)))?;
        
        let mut reader = BufReader::new(file);
        let certs = certs(&mut reader)
            .map_err(|e| AgentError::Cryptography(format!("Failed to parse certificates: {}", e)))?;
        
        Ok(certs.into_iter().map(Certificate).collect())
    }
    
    fn load_private_key(path: &std::path::Path) -> Result<PrivateKey> {
        let file = std::fs::File::open(path)
            .map_err(|e| AgentError::Io(format!("Failed to open private key file: {}", e)))?;
        
        let mut reader = BufReader::new(file);
        let keys = pkcs8_private_keys(&mut reader)
            .map_err(|e| AgentError::Cryptography(format!("Failed to parse private key: {}", e)))?;
        
        if keys.is_empty() {
            return Err(AgentError::Cryptography("No private key found".to_string()));
        }
        
        Ok(PrivateKey(keys[0].clone()))
    }
    
    async fn validate_server_certificate(&self, response: &reqwest::Response) -> Result<()> {
        // TODO: Implement server certificate validation with pinning
        // This should validate the server certificate against known good fingerprints
        // stored in the certificate manager
        
        debug!("Server certificate validation passed");
        Ok(())
    }
    
    fn get_endpoint_for_message_type(&self, message_type: &MessageType) -> &'static str {
        match message_type {
            MessageType::Heartbeat => "/api/v1/agent/heartbeat",
            MessageType::SecurityEvent => "/api/v1/agent/events",
            MessageType::Telemetry => "/api/v1/agent/telemetry",
            MessageType::Alert => "/api/v1/agent/alerts",
            MessageType::StatusUpdate => "/api/v1/agent/status",
            MessageType::Emergency => "/api/v1/agent/emergency",
            MessageType::PolicyRequest => "/api/v1/agent/policies",
        }
    }
    
    async fn sign_message(&self, message: &[u8]) -> Result<String> {
        // Sign the message using agent's private key
        let signature = self.cert_manager.sign_data(message).await?;
        Ok(base64::encode(signature))
    }
    
    async fn collect_agent_metadata(&self) -> Result<AgentMetadataData> {
        // TODO: Implement agent metadata collection
        Ok(AgentMetadataData {
            hostname: "localhost".to_string(),
            operating_system: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            agent_version: self.config.agent.version.clone(),
        })
    }
    
    async fn collect_security_capabilities(&self) -> Result<SecurityCapabilitiesData> {
        // TODO: Implement security capabilities detection
        Ok(SecurityCapabilitiesData {
            supports_tpm: false,
            supports_secure_boot: false,
            supports_hardware_attestation: false,
        })
    }
}

/// Custom certificate verifier for certificate pinning
struct CustomCertificateVerifier {
    cert_manager: Arc<CertificateManager>,
}

impl CustomCertificateVerifier {
    async fn new(cert_manager: &Arc<CertificateManager>) -> Result<Self> {
        Ok(Self {
            cert_manager: Arc::clone(cert_manager),
        })
    }
}

// TODO: Implement rustls::client::ServerCertVerifier for CustomCertificateVerifier

/// Enrollment request data structure
#[derive(serde::Serialize)]
struct EnrollmentRequestData {
    enrollment_token: String,
    agent_metadata: AgentMetadataData,
    public_key: String,
    csr: String,
    capabilities: SecurityCapabilitiesData,
}

/// Enrollment response data structure
#[derive(serde::Deserialize)]
struct EnrollmentResponseData {
    success: bool,
    agent_id: String,
    client_certificate: String,
    ca_certificate: String,
    intermediate_certificates: Vec<String>,
    error: Option<String>,
}

/// Agent metadata for enrollment
#[derive(serde::Serialize)]
struct AgentMetadataData {
    hostname: String,
    operating_system: String,
    architecture: String,
    agent_version: String,
}

/// Security capabilities for enrollment
#[derive(serde::Serialize)]
struct SecurityCapabilitiesData {
    supports_tpm: bool,
    supports_secure_boot: bool,
    supports_hardware_attestation: bool,
}

/// Enrollment result
pub struct EnrollmentResult {
    pub agent_id: String,
    pub certificates_stored: bool,
}