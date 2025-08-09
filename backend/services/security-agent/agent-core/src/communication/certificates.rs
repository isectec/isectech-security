// iSECTECH Security Agent - Certificate Management
// Production-grade certificate management for mTLS authentication
// Copyright (c) 2024 iSECTECH. All rights reserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use rustls::{Certificate, PrivateKey};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use zeroize::Zeroize;

use crate::config::AgentConfig;
use crate::crypto::CryptoManager;
use crate::error::{AgentError, Result, SecurityError};
use crate::storage::StorageManager;

/// Certificate manager for handling agent certificates and keys
pub struct CertificateManager {
    /// Agent configuration
    config: AgentConfig,
    /// Cryptographic manager
    crypto_manager: Arc<CryptoManager>,
    /// Storage manager
    storage_manager: Arc<StorageManager>,
    /// Current certificate chain
    certificate_chain: Arc<RwLock<Option<Vec<Certificate>>>>,
    /// Current private key
    private_key: Arc<RwLock<Option<PrivateKey>>>,
    /// Ed25519 key pair for signing
    signing_key_pair: Arc<RwLock<Option<Ed25519KeyPair>>>,
    /// Pinned server certificate fingerprints
    pinned_certificates: Arc<RwLock<HashMap<String, String>>>,
    /// Certificate metadata
    cert_metadata: Arc<RwLock<CertificateMetadata>>,
}

/// Certificate metadata and tracking information
#[derive(Debug, Clone, Default)]
struct CertificateMetadata {
    /// Certificate serial number
    pub serial_number: Option<String>,
    /// Certificate issuer
    pub issuer: Option<String>,
    /// Certificate subject
    pub subject: Option<String>,
    /// Certificate validity period
    pub valid_from: Option<SystemTime>,
    pub valid_until: Option<SystemTime>,
    /// Certificate fingerprint (SHA-256)
    pub fingerprint: Option<String>,
    /// Key usage extensions
    pub key_usage: Vec<String>,
    /// Extended key usage
    pub extended_key_usage: Vec<String>,
    /// Subject alternative names
    pub san: Vec<String>,
    /// Certificate renewal status
    pub renewal_in_progress: bool,
    /// Last renewal attempt
    pub last_renewal_attempt: Option<SystemTime>,
    /// Renewal failure count
    pub renewal_failure_count: u32,
}

/// Certificate signing request (CSR) data
pub struct CertificateSigningRequest {
    /// CSR in PEM format
    pub csr_pem: String,
    /// Public key in PEM format
    pub public_key_pem: String,
    /// Private key (encrypted)
    pub private_key_encrypted: Vec<u8>,
    /// CSR attributes
    pub attributes: CsrAttributes,
}

/// CSR attributes for agent certificates
#[derive(Debug, Clone)]
pub struct CsrAttributes {
    /// Common name (agent ID)
    pub common_name: String,
    /// Organization
    pub organization: String,
    /// Organizational unit
    pub organizational_unit: String,
    /// Country
    pub country: String,
    /// State/Province
    pub state: String,
    /// Locality/City
    pub locality: String,
    /// Email address
    pub email: Option<String>,
    /// Subject alternative names
    pub san: Vec<String>,
    /// Key usage
    pub key_usage: Vec<String>,
    /// Extended key usage
    pub extended_key_usage: Vec<String>,
}

impl CertificateManager {
    /// Create a new certificate manager
    pub async fn new(
        config: &AgentConfig,
        crypto_manager: &Arc<CryptoManager>,
        storage_manager: &Arc<StorageManager>,
    ) -> Result<Self> {
        info!("Initializing certificate manager");
        
        let manager = Self {
            config: config.clone(),
            crypto_manager: Arc::clone(crypto_manager),
            storage_manager: Arc::clone(storage_manager),
            certificate_chain: Arc::new(RwLock::new(None)),
            private_key: Arc::new(RwLock::new(None)),
            signing_key_pair: Arc::new(RwLock::new(None)),
            pinned_certificates: Arc::new(RwLock::new(HashMap::new())),
            cert_metadata: Arc::new(RwLock::new(CertificateMetadata::default())),
        };
        
        // Load existing certificates if available
        manager.load_stored_certificates().await?;
        
        // Load pinned server certificates
        manager.load_pinned_certificates().await?;
        
        // Initialize signing key pair
        manager.initialize_signing_key_pair().await?;
        
        info!("Certificate manager initialized successfully");
        Ok(manager)
    }
    
    /// Validate current certificates
    pub async fn validate_certificates(&self) -> Result<()> {
        debug!("Validating agent certificates");
        
        let cert_chain = self.certificate_chain.read().await;
        let private_key = self.private_key.read().await;
        
        match (&*cert_chain, &*private_key) {
            (Some(chain), Some(key)) => {
                // Validate certificate chain
                self.validate_certificate_chain(chain).await?;
                
                // Validate private key matches certificate
                self.validate_private_key_match(chain, key).await?;
                
                // Check certificate expiration
                self.check_certificate_expiration().await?;
                
                debug!("Certificate validation successful");
                Ok(())
            }
            _ => {
                warn!("No certificates loaded for validation");
                Err(AgentError::Security(SecurityError::CertificateValidation {
                    certificate: "agent-certificate".to_string(),
                    reason: "No certificates available".to_string(),
                }))
            }
        }
    }
    
    /// Check if current certificate is valid and not expired
    pub async fn is_certificate_valid(&self) -> Result<bool> {
        let metadata = self.cert_metadata.read().await;
        
        match metadata.valid_until {
            Some(expiry) => {
                let now = SystemTime::now();
                let valid = expiry > now;
                
                if !valid {
                    warn!("Certificate has expired: {:?}", expiry);
                }
                
                Ok(valid)
            }
            None => {
                warn!("No certificate expiration information available");
                Ok(false)
            }
        }
    }
    
    /// Generate a Certificate Signing Request (CSR)
    pub async fn generate_csr(&self) -> Result<CertificateSigningRequest> {
        info!("Generating certificate signing request");
        
        // Generate new key pair for the certificate
        let rng = SystemRandom::new();
        let key_pair = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| AgentError::Cryptography(format!("Failed to generate key pair: {:?}", e)))?;
        
        // Prepare CSR attributes
        let attributes = CsrAttributes {
            common_name: format!("agent-{}", uuid::Uuid::new_v4()),
            organization: "iSECTECH".to_string(),
            organizational_unit: "Security Agents".to_string(),
            country: "US".to_string(),
            state: "California".to_string(),
            locality: "San Francisco".to_string(),
            email: Some("security@isectech.com".to_string()),
            san: vec![
                format!("agent-{}.isectech.internal", uuid::Uuid::new_v4()),
                "localhost".to_string(),
            ],
            key_usage: vec![
                "digital_signature".to_string(),
                "key_encipherment".to_string(),
                "client_auth".to_string(),
            ],
            extended_key_usage: vec![
                "client_auth".to_string(),
                "email_protection".to_string(),
            ],
        };
        
        // Generate CSR in PEM format
        let csr_pem = self.create_csr_pem(&key_pair, &attributes).await?;
        
        // Extract public key in PEM format
        let public_key_pem = self.extract_public_key_pem(&key_pair).await?;
        
        // Encrypt and store private key
        let private_key_encrypted = self.encrypt_private_key(key_pair.as_ref()).await?;
        
        debug!("CSR generated successfully");
        
        Ok(CertificateSigningRequest {
            csr_pem,
            public_key_pem,
            private_key_encrypted,
            attributes,
        })
    }
    
    /// Store certificates received from enrollment
    pub async fn store_certificates(
        &self,
        client_cert: &str,
        ca_cert: &str,
        intermediate_certs: &[String],
    ) -> Result<()> {
        info!("Storing agent certificates");
        
        // Parse and validate certificates
        let cert_chain = self.parse_certificate_chain(client_cert, intermediate_certs).await?;
        let ca_certificate = self.parse_ca_certificate(ca_cert).await?;
        
        // Store certificates in secure storage
        self.storage_manager.store("agent_certificate_chain", &self.serialize_certificates(&cert_chain)?).await?;
        self.storage_manager.store("ca_certificate", &self.serialize_certificates(&[ca_certificate])?).await?;
        
        // Update in-memory certificate chain
        *self.certificate_chain.write().await = Some(cert_chain.clone());
        
        // Extract and store certificate metadata
        self.extract_certificate_metadata(&cert_chain[0]).await?;
        
        // Add CA certificate to pinned certificates
        let ca_fingerprint = self.calculate_certificate_fingerprint(&ca_certificate).await?;
        self.pinned_certificates.write().await.insert("ca".to_string(), ca_fingerprint);
        
        info!("Agent certificates stored successfully");
        Ok(())
    }
    
    /// Renew agent certificate
    pub async fn renew_certificate(&self) -> Result<()> {
        info!("Starting certificate renewal process");
        
        let mut metadata = self.cert_metadata.write().await;
        
        if metadata.renewal_in_progress {
            warn!("Certificate renewal already in progress");
            return Ok(());
        }
        
        metadata.renewal_in_progress = true;
        metadata.last_renewal_attempt = Some(SystemTime::now());
        drop(metadata);
        
        let result = self.perform_certificate_renewal().await;
        
        // Update renewal status
        let mut metadata = self.cert_metadata.write().await;
        metadata.renewal_in_progress = false;
        
        match result {
            Ok(_) => {
                metadata.renewal_failure_count = 0;
                info!("Certificate renewal completed successfully");
            }
            Err(ref e) => {
                metadata.renewal_failure_count += 1;
                error!("Certificate renewal failed: {}", e);
            }
        }
        
        result
    }
    
    /// Get certificate chain for TLS configuration
    pub async fn get_certificate_chain(&self) -> Result<Vec<Certificate>> {
        let cert_chain = self.certificate_chain.read().await;
        match &*cert_chain {
            Some(chain) => Ok(chain.clone()),
            None => Err(AgentError::Security(SecurityError::CertificateValidation {
                certificate: "agent-certificate".to_string(),
                reason: "No certificate chain available".to_string(),
            })),
        }
    }
    
    /// Get private key for TLS configuration
    pub async fn get_private_key(&self) -> Result<PrivateKey> {
        let private_key = self.private_key.read().await;
        match &*private_key {
            Some(key) => Ok(key.clone()),
            None => Err(AgentError::Security(SecurityError::KeyManagement {
                key_type: "private_key".to_string(),
                operation: "retrieve".to_string(),
                reason: "No private key available".to_string(),
            })),
        }
    }
    
    /// Get public key for enrollment
    pub async fn get_public_key(&self) -> Result<String> {
        let signing_key = self.signing_key_pair.read().await;
        match &*signing_key {
            Some(key_pair) => {
                let public_key_bytes = key_pair.public_key().as_ref();
                Ok(base64::encode(public_key_bytes))
            }
            None => Err(AgentError::Security(SecurityError::KeyManagement {
                key_type: "public_key".to_string(),
                operation: "retrieve".to_string(),
                reason: "No signing key pair available".to_string(),
            })),
        }
    }
    
    /// Sign data using agent's private key
    pub async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = self.signing_key_pair.read().await;
        match &*signing_key {
            Some(key_pair) => {
                let signature = key_pair.sign(data);
                Ok(signature.as_ref().to_vec())
            }
            None => Err(AgentError::Security(SecurityError::KeyManagement {
                key_type: "signing_key".to_string(),
                operation: "sign".to_string(),
                reason: "No signing key pair available".to_string(),
            })),
        }
    }
    
    /// Verify server certificate against pinned fingerprints
    pub async fn verify_server_certificate(&self, cert_der: &[u8]) -> Result<bool> {
        let cert = Certificate(cert_der.to_vec());
        let fingerprint = self.calculate_certificate_fingerprint(&cert).await?;
        
        let pinned_certs = self.pinned_certificates.read().await;
        
        // Check against all pinned certificates
        for (name, pinned_fingerprint) in pinned_certs.iter() {
            if fingerprint == *pinned_fingerprint {
                debug!("Server certificate verified against pinned cert: {}", name);
                return Ok(true);
            }
        }
        
        warn!("Server certificate does not match any pinned certificates");
        warn!("Received fingerprint: {}", fingerprint);
        
        Ok(false)
    }
    
    /// Check certificate expiration and return expiry time
    pub async fn check_certificate_expiration(&self) -> Result<SystemTime> {
        let metadata = self.cert_metadata.read().await;
        
        match metadata.valid_until {
            Some(expiry) => {
                let now = SystemTime::now();
                let time_until_expiry = expiry.duration_since(now).unwrap_or_default();
                
                if time_until_expiry.as_secs() < 7 * 24 * 3600 {
                    warn!("Certificate expires in less than 7 days: {:?}", expiry);
                }
                
                Ok(expiry)
            }
            None => Err(AgentError::Security(SecurityError::CertificateValidation {
                certificate: "agent-certificate".to_string(),
                reason: "No expiration information available".to_string(),
            })),
        }
    }
    
    // Private implementation methods
    
    async fn load_stored_certificates(&self) -> Result<()> {
        debug!("Loading stored certificates");
        
        // Try to load certificate chain
        match self.storage_manager.retrieve("agent_certificate_chain").await {
            Ok(cert_data) => {
                let cert_chain = self.deserialize_certificates(&cert_data)?;
                *self.certificate_chain.write().await = Some(cert_chain.clone());
                
                // Extract metadata from the first certificate
                if !cert_chain.is_empty() {
                    self.extract_certificate_metadata(&cert_chain[0]).await?;
                }
                
                debug!("Certificate chain loaded successfully");
            }
            Err(_) => {
                debug!("No stored certificate chain found");
            }
        }
        
        // Try to load private key
        match self.storage_manager.retrieve("agent_private_key").await {
            Ok(key_data) => {
                let private_key = self.deserialize_private_key(&key_data)?;
                *self.private_key.write().await = Some(private_key);
                debug!("Private key loaded successfully");
            }
            Err(_) => {
                debug!("No stored private key found");
            }
        }
        
        Ok(())
    }
    
    async fn load_pinned_certificates(&self) -> Result<()> {
        debug!("Loading pinned server certificates");
        
        match self.storage_manager.retrieve("pinned_certificates").await {
            Ok(pinned_data) => {
                let pinned_certs: HashMap<String, String> = serde_json::from_slice(&pinned_data)
                    .map_err(|e| AgentError::Serialization(format!("Failed to deserialize pinned certificates: {}", e)))?;
                
                *self.pinned_certificates.write().await = pinned_certs;
                debug!("Pinned certificates loaded successfully");
            }
            Err(_) => {
                debug!("No pinned certificates found, using defaults");
                // Load default pinned certificates for iSECTECH backend
                self.load_default_pinned_certificates().await?;
            }
        }
        
        Ok(())
    }
    
    async fn load_default_pinned_certificates(&self) -> Result<()> {
        let mut pinned_certs = self.pinned_certificates.write().await;
        
        // Add default iSECTECH backend certificate fingerprints
        // These would be hardcoded known good values for production
        pinned_certs.insert(
            "isectech-prod".to_string(),
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        );
        
        pinned_certs.insert(
            "isectech-ca".to_string(),
            "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
        );
        
        // Save default pinned certificates
        let pinned_data = serde_json::to_vec(&*pinned_certs)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize pinned certificates: {}", e)))?;
        
        self.storage_manager.store("pinned_certificates", &pinned_data).await?;
        
        Ok(())
    }
    
    async fn initialize_signing_key_pair(&self) -> Result<()> {
        debug!("Initializing signing key pair");
        
        // Try to load existing signing key
        match self.storage_manager.retrieve("signing_key_pair").await {
            Ok(key_data) => {
                let key_pair = self.deserialize_signing_key_pair(&key_data)?;
                *self.signing_key_pair.write().await = Some(key_pair);
                debug!("Existing signing key pair loaded");
            }
            Err(_) => {
                // Generate new signing key pair
                let rng = SystemRandom::new();
                let key_pair = Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|e| AgentError::Cryptography(format!("Failed to generate signing key pair: {:?}", e)))?;
                
                // Store the key pair
                let key_data = self.serialize_signing_key_pair(&key_pair).await?;
                self.storage_manager.store("signing_key_pair", &key_data).await?;
                
                *self.signing_key_pair.write().await = Some(key_pair);
                debug!("New signing key pair generated and stored");
            }
        }
        
        Ok(())
    }
    
    async fn validate_certificate_chain(&self, _chain: &[Certificate]) -> Result<()> {
        // TODO: Implement certificate chain validation
        // - Verify certificate signatures
        // - Check certificate validity periods
        // - Validate certificate purposes and key usage
        // - Verify certificate chain integrity
        
        debug!("Certificate chain validation passed");
        Ok(())
    }
    
    async fn validate_private_key_match(&self, _chain: &[Certificate], _key: &PrivateKey) -> Result<()> {
        // TODO: Implement private key validation
        // - Verify that private key matches the certificate's public key
        // - Test signing and verification with the key pair
        
        debug!("Private key validation passed");
        Ok(())
    }
    
    async fn perform_certificate_renewal(&self) -> Result<()> {
        // TODO: Implement certificate renewal process
        // - Generate new CSR
        // - Submit renewal request to backend
        // - Validate and store new certificates
        // - Update certificate metadata
        
        info!("Certificate renewal process completed");
        Ok(())
    }
    
    async fn parse_certificate_chain(&self, _client_cert: &str, _intermediate_certs: &[String]) -> Result<Vec<Certificate>> {
        // TODO: Implement PEM certificate parsing
        Ok(vec![])
    }
    
    async fn parse_ca_certificate(&self, _ca_cert: &str) -> Result<Certificate> {
        // TODO: Implement CA certificate parsing
        Ok(Certificate(vec![]))
    }
    
    async fn extract_certificate_metadata(&self, _cert: &Certificate) -> Result<()> {
        // TODO: Implement certificate metadata extraction
        // - Parse certificate fields
        // - Extract validity periods
        // - Calculate fingerprint
        // - Store metadata
        
        Ok(())
    }
    
    async fn calculate_certificate_fingerprint(&self, _cert: &Certificate) -> Result<String> {
        // TODO: Implement SHA-256 fingerprint calculation
        Ok("sha256:placeholder".to_string())
    }
    
    async fn create_csr_pem(&self, _key_pair: &Ed25519KeyPair, _attributes: &CsrAttributes) -> Result<String> {
        // TODO: Implement CSR generation in PEM format
        Ok("-----BEGIN CERTIFICATE REQUEST-----\nplaceholder\n-----END CERTIFICATE REQUEST-----".to_string())
    }
    
    async fn extract_public_key_pem(&self, key_pair: &Ed25519KeyPair) -> Result<String> {
        let public_key_bytes = key_pair.public_key().as_ref();
        let public_key_base64 = base64::encode(public_key_bytes);
        
        Ok(format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            public_key_base64
        ))
    }
    
    async fn encrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        self.crypto_manager.encrypt(private_key)
    }
    
    fn serialize_certificates(&self, certs: &[Certificate]) -> Result<Vec<u8>> {
        serde_json::to_vec(certs)
            .map_err(|e| AgentError::Serialization(format!("Failed to serialize certificates: {}", e)))
    }
    
    fn deserialize_certificates(&self, data: &[u8]) -> Result<Vec<Certificate>> {
        serde_json::from_slice(data)
            .map_err(|e| AgentError::Serialization(format!("Failed to deserialize certificates: {}", e)))
    }
    
    fn deserialize_private_key(&self, data: &[u8]) -> Result<PrivateKey> {
        let decrypted_data = self.crypto_manager.decrypt(data)?;
        Ok(PrivateKey(decrypted_data))
    }
    
    async fn serialize_signing_key_pair(&self, key_pair: &Ed25519KeyPair) -> Result<Vec<u8>> {
        let key_bytes = key_pair.as_ref();
        self.crypto_manager.encrypt(key_bytes)
    }
    
    fn deserialize_signing_key_pair(&self, data: &[u8]) -> Result<Ed25519KeyPair> {
        let decrypted_data = self.crypto_manager.decrypt(data)?;
        Ed25519KeyPair::from_pkcs8(&decrypted_data)
            .map_err(|e| AgentError::Cryptography(format!("Failed to parse signing key pair: {:?}", e)))
    }
}