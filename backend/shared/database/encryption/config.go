package encryption

import (
	"fmt"
	"time"
)

// Config represents the encryption configuration for iSECTECH platform
type Config struct {
	// Master key configuration
	MasterKeyDerivationKey string `yaml:"master_key_derivation_key" json:"master_key_derivation_key"`
	MasterKeySalt          string `yaml:"master_key_salt" json:"master_key_salt"`
	
	// Key lifetime settings
	KeyLifetime KeyLifetimeConfig `yaml:"key_lifetime" json:"key_lifetime"`
	
	// Provider configuration
	Provider ProviderConfig `yaml:"provider" json:"provider"`
	
	// Database-specific encryption settings
	PostgreSQL PostgreSQLEncryptionConfig `yaml:"postgresql" json:"postgresql"`
	MongoDB    MongoDBEncryptionConfig    `yaml:"mongodb" json:"mongodb"`
	Redis      RedisEncryptionConfig      `yaml:"redis" json:"redis"`
	Elasticsearch ElasticsearchEncryptionConfig `yaml:"elasticsearch" json:"elasticsearch"`
	
	// Audit configuration
	Audit AuditConfig `yaml:"audit" json:"audit"`
	
	// Rotation settings
	Rotation RotationConfig `yaml:"rotation" json:"rotation"`
	
	// Compliance settings
	Compliance ComplianceConfig `yaml:"compliance" json:"compliance"`
}

// KeyLifetimeConfig defines key lifetime settings
type KeyLifetimeConfig struct {
	Default        time.Duration `yaml:"default" json:"default"`
	DataEncryption time.Duration `yaml:"data_encryption" json:"data_encryption"`
	KeyEncryption  time.Duration `yaml:"key_encryption" json:"key_encryption"`
	Signing        time.Duration `yaml:"signing" json:"signing"`
}

// ProviderConfig defines key provider settings
type ProviderConfig struct {
	Type string `yaml:"type" json:"type"` // vault, aws-kms, gcp-kms, azure-kv, local
	
	// Vault configuration
	Vault VaultConfig `yaml:"vault" json:"vault"`
	
	// AWS KMS configuration
	AWSKMS AWSKMSConfig `yaml:"aws_kms" json:"aws_kms"`
	
	// GCP KMS configuration
	GCPKMS GCPKMSConfig `yaml:"gcp_kms" json:"gcp_kms"`
	
	// Azure Key Vault configuration
	AzureKV AzureKVConfig `yaml:"azure_kv" json:"azure_kv"`
	
	// Local file-based provider (for development)
	Local LocalConfig `yaml:"local" json:"local"`
}

// VaultConfig defines HashiCorp Vault configuration
type VaultConfig struct {
	Address    string `yaml:"address" json:"address"`
	Token      string `yaml:"token" json:"token"`
	MountPath  string `yaml:"mount_path" json:"mount_path"`
	Namespace  string `yaml:"namespace" json:"namespace"`
	TLSConfig  VaultTLSConfig `yaml:"tls" json:"tls"`
}

// VaultTLSConfig defines Vault TLS settings
type VaultTLSConfig struct {
	Enabled            bool   `yaml:"enabled" json:"enabled"`
	CACert             string `yaml:"ca_cert" json:"ca_cert"`
	ClientCert         string `yaml:"client_cert" json:"client_cert"`
	ClientKey          string `yaml:"client_key" json:"client_key"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// AWSKMSConfig defines AWS KMS configuration
type AWSKMSConfig struct {
	Region    string `yaml:"region" json:"region"`
	KeyID     string `yaml:"key_id" json:"key_id"`
	AccessKey string `yaml:"access_key" json:"access_key"`
	SecretKey string `yaml:"secret_key" json:"secret_key"`
	RoleARN   string `yaml:"role_arn" json:"role_arn"`
}

// GCPKMSConfig defines Google Cloud KMS configuration
type GCPKMSConfig struct {
	ProjectID    string `yaml:"project_id" json:"project_id"`
	LocationID   string `yaml:"location_id" json:"location_id"`
	KeyRingID    string `yaml:"key_ring_id" json:"key_ring_id"`
	KeyID        string `yaml:"key_id" json:"key_id"`
	CredsPath    string `yaml:"credentials_path" json:"credentials_path"`
}

// AzureKVConfig defines Azure Key Vault configuration
type AzureKVConfig struct {
	VaultURL     string `yaml:"vault_url" json:"vault_url"`
	TenantID     string `yaml:"tenant_id" json:"tenant_id"`
	ClientID     string `yaml:"client_id" json:"client_id"`
	ClientSecret string `yaml:"client_secret" json:"client_secret"`
}

// LocalConfig defines local file-based key storage
type LocalConfig struct {
	StoragePath string `yaml:"storage_path" json:"storage_path"`
	PermMode    string `yaml:"perm_mode" json:"perm_mode"`
	Encryption  bool   `yaml:"encryption" json:"encryption"`
}

// PostgreSQLEncryptionConfig defines PostgreSQL encryption settings
type PostgreSQLEncryptionConfig struct {
	Enabled              bool   `yaml:"enabled" json:"enabled"`
	TDEEnabled           bool   `yaml:"tde_enabled" json:"tde_enabled"`
	TDEKeyID             string `yaml:"tde_key_id" json:"tde_key_id"`
	ColumnEncryption     bool   `yaml:"column_encryption" json:"column_encryption"`
	ColumnEncryptionKeys map[string]string `yaml:"column_encryption_keys" json:"column_encryption_keys"`
	WALEncryption        bool   `yaml:"wal_encryption" json:"wal_encryption"`
	BackupEncryption     bool   `yaml:"backup_encryption" json:"backup_encryption"`
}

// MongoDBEncryptionConfig defines MongoDB encryption settings
type MongoDBEncryptionConfig struct {
	Enabled                 bool                    `yaml:"enabled" json:"enabled"`
	EncryptionAtRest        bool                    `yaml:"encryption_at_rest" json:"encryption_at_rest"`
	KeyManagementService    string                  `yaml:"key_management_service" json:"key_management_service"`
	MasterKey               MongoDBMasterKeyConfig  `yaml:"master_key" json:"master_key"`
	ClientSideEncryption    bool                    `yaml:"client_side_encryption" json:"client_side_encryption"`
	FieldLevelEncryption    map[string]FieldEncryptionConfig `yaml:"field_level_encryption" json:"field_level_encryption"`
	AutoEncryptionOptions  AutoEncryptionConfig    `yaml:"auto_encryption" json:"auto_encryption"`
}

// MongoDBMasterKeyConfig defines MongoDB master key settings
type MongoDBMasterKeyConfig struct {
	Provider string            `yaml:"provider" json:"provider"` // local, aws, gcp, azure
	KeyID    string            `yaml:"key_id" json:"key_id"`
	Region   string            `yaml:"region" json:"region"`
	Endpoint string            `yaml:"endpoint" json:"endpoint"`
	Config   map[string]string `yaml:"config" json:"config"`
}

// FieldEncryptionConfig defines field-level encryption settings
type FieldEncryptionConfig struct {
	Algorithm  string `yaml:"algorithm" json:"algorithm"`
	KeyID      string `yaml:"key_id" json:"key_id"`
	Deterministic bool `yaml:"deterministic" json:"deterministic"`
}

// AutoEncryptionConfig defines automatic encryption settings
type AutoEncryptionConfig struct {
	Enabled         bool              `yaml:"enabled" json:"enabled"`
	SchemaMap       map[string]string `yaml:"schema_map" json:"schema_map"`
	KeyVaultCollection string         `yaml:"key_vault_collection" json:"key_vault_collection"`
	KMSProviders    map[string]string `yaml:"kms_providers" json:"kms_providers"`
}

// RedisEncryptionConfig defines Redis encryption settings
type RedisEncryptionConfig struct {
	Enabled           bool              `yaml:"enabled" json:"enabled"`
	TLSEnabled        bool              `yaml:"tls_enabled" json:"tls_enabled"`
	EncryptionAtRest  bool              `yaml:"encryption_at_rest" json:"encryption_at_rest"`
	KeyID             string            `yaml:"key_id" json:"key_id"`
	ValueEncryption   bool              `yaml:"value_encryption" json:"value_encryption"`
	EncryptedKeyTypes []string          `yaml:"encrypted_key_types" json:"encrypted_key_types"`
	CompressionEnabled bool             `yaml:"compression_enabled" json:"compression_enabled"`
}

// ElasticsearchEncryptionConfig defines Elasticsearch encryption settings
type ElasticsearchEncryptionConfig struct {
	Enabled              bool              `yaml:"enabled" json:"enabled"`
	TLSEnabled           bool              `yaml:"tls_enabled" json:"tls_enabled"`
	EncryptionAtRest     bool              `yaml:"encryption_at_rest" json:"encryption_at_rest"`
	KeyID                string            `yaml:"key_id" json:"key_id"`
	FieldLevelEncryption map[string]string `yaml:"field_level_encryption" json:"field_level_encryption"`
	IndexEncryption      bool              `yaml:"index_encryption" json:"index_encryption"`
	BackupEncryption     bool              `yaml:"backup_encryption" json:"backup_encryption"`
}

// AuditConfig defines audit logging settings
type AuditConfig struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	LogLevel          string        `yaml:"log_level" json:"log_level"`
	LogDestination    string        `yaml:"log_destination" json:"log_destination"`
	RetentionPeriod   time.Duration `yaml:"retention_period" json:"retention_period"`
	EncryptAuditLogs  bool          `yaml:"encrypt_audit_logs" json:"encrypt_audit_logs"`
	AuditKeyID        string        `yaml:"audit_key_id" json:"audit_key_id"`
	IncludeMetadata   bool          `yaml:"include_metadata" json:"include_metadata"`
	ExternalAuditURL  string        `yaml:"external_audit_url" json:"external_audit_url"`
}

// RotationConfig defines key rotation settings
type RotationConfig struct {
	Enabled           bool                    `yaml:"enabled" json:"enabled"`
	AutomaticRotation bool                    `yaml:"automatic_rotation" json:"automatic_rotation"`
	RotationInterval  time.Duration           `yaml:"rotation_interval" json:"rotation_interval"`
	RotationSchedule  string                  `yaml:"rotation_schedule" json:"rotation_schedule"`
	PreRotationHooks  []string                `yaml:"pre_rotation_hooks" json:"pre_rotation_hooks"`
	PostRotationHooks []string                `yaml:"post_rotation_hooks" json:"post_rotation_hooks"`
	RotationPolicies  map[string]RotationPolicy `yaml:"rotation_policies" json:"rotation_policies"`
}

// RotationPolicy defines rotation policy for specific key types
type RotationPolicy struct {
	MaxAge           time.Duration `yaml:"max_age" json:"max_age"`
	MaxUsageCount    int64         `yaml:"max_usage_count" json:"max_usage_count"`
	RotationTriggers []string      `yaml:"rotation_triggers" json:"rotation_triggers"`
	GracePeriod      time.Duration `yaml:"grace_period" json:"grace_period"`
}

// ComplianceConfig defines compliance settings
type ComplianceConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Standards   []string `yaml:"standards" json:"standards"` // FIPS-140-2, Common Criteria, etc.
	Algorithms  AlgorithmConfig `yaml:"algorithms" json:"algorithms"`
	KeyEscrow   KeyEscrowConfig `yaml:"key_escrow" json:"key_escrow"`
	Attestation AttestationConfig `yaml:"attestation" json:"attestation"`
}

// AlgorithmConfig defines approved algorithms
type AlgorithmConfig struct {
	Encryption []string `yaml:"encryption" json:"encryption"`
	Hashing    []string `yaml:"hashing" json:"hashing"`
	Signing    []string `yaml:"signing" json:"signing"`
	KeyDerivation []string `yaml:"key_derivation" json:"key_derivation"`
}

// KeyEscrowConfig defines key escrow settings
type KeyEscrowConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Providers   []string `yaml:"providers" json:"providers"`
	Threshold   int      `yaml:"threshold" json:"threshold"`
	EscrowKeys  []string `yaml:"escrow_keys" json:"escrow_keys"`
}

// AttestationConfig defines key attestation settings
type AttestationConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	AttestationKeyID string `yaml:"attestation_key_id" json:"attestation_key_id"`
	SigningAlgorithm string `yaml:"signing_algorithm" json:"signing_algorithm"`
	IncludeCertChain bool   `yaml:"include_cert_chain" json:"include_cert_chain"`
}

// DefaultConfig returns a production-ready encryption configuration
func DefaultConfig() *Config {
	return &Config{
		MasterKeyDerivationKey: "", // Must be set via environment
		MasterKeySalt:          "", // Must be set via environment
		
		KeyLifetime: KeyLifetimeConfig{
			Default:        365 * 24 * time.Hour, // 1 year
			DataEncryption: 90 * 24 * time.Hour,  // 90 days
			KeyEncryption:  365 * 24 * time.Hour, // 1 year
			Signing:        180 * 24 * time.Hour, // 180 days
		},
		
		Provider: ProviderConfig{
			Type: "vault", // Default to HashiCorp Vault
			Vault: VaultConfig{
				Address:   "https://vault.isectech.com:8200",
				MountPath: "isectech-encryption",
				TLSConfig: VaultTLSConfig{
					Enabled: true,
				},
			},
		},
		
		PostgreSQL: PostgreSQLEncryptionConfig{
			Enabled:              true,
			TDEEnabled:           true,
			ColumnEncryption:     true,
			WALEncryption:        true,
			BackupEncryption:     true,
			ColumnEncryptionKeys: map[string]string{
				"users.password_hash":     "user-data-encryption",
				"security_events.details": "security-data-encryption",
				"compliance_data.results": "compliance-data-encryption",
			},
		},
		
		MongoDB: MongoDBEncryptionConfig{
			Enabled:                true,
			EncryptionAtRest:       true,
			KeyManagementService:   "vault",
			ClientSideEncryption:   true,
			FieldLevelEncryption: map[string]FieldEncryptionConfig{
				"security_events.raw_data": {
					Algorithm:     "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
					KeyID:         "security-field-encryption",
					Deterministic: false,
				},
				"threat_intelligence.indicators": {
					Algorithm:     "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
					KeyID:         "threat-field-encryption",
					Deterministic: false,
				},
			},
			AutoEncryptionOptions: AutoEncryptionConfig{
				Enabled:            true,
				KeyVaultCollection: "encryption.__keyVault",
			},
		},
		
		Redis: RedisEncryptionConfig{
			Enabled:           true,
			TLSEnabled:        true,
			EncryptionAtRest:  true,
			ValueEncryption:   true,
			CompressionEnabled: true,
			EncryptedKeyTypes: []string{
				"session:",
				"user:",
				"threat:",
				"sensitive:",
			},
		},
		
		Elasticsearch: ElasticsearchEncryptionConfig{
			Enabled:              true,
			TLSEnabled:           true,
			EncryptionAtRest:     true,
			IndexEncryption:      true,
			BackupEncryption:     true,
			FieldLevelEncryption: map[string]string{
				"security_events.raw_data":       "security-field-encryption",
				"threat_intelligence.indicators": "threat-field-encryption",
				"audit_logs.details":             "audit-field-encryption",
			},
		},
		
		Audit: AuditConfig{
			Enabled:          true,
			LogLevel:         "info",
			LogDestination:   "file",
			RetentionPeriod:  7 * 365 * 24 * time.Hour, // 7 years
			EncryptAuditLogs: true,
			IncludeMetadata:  true,
		},
		
		Rotation: RotationConfig{
			Enabled:           true,
			AutomaticRotation: true,
			RotationInterval:  90 * 24 * time.Hour, // 90 days
			RotationPolicies: map[string]RotationPolicy{
				"data-encryption": {
					MaxAge:        90 * 24 * time.Hour,
					MaxUsageCount: 1000000,
					GracePeriod:   7 * 24 * time.Hour,
				},
				"key-encryption": {
					MaxAge:        365 * 24 * time.Hour,
					MaxUsageCount: 10000000,
					GracePeriod:   30 * 24 * time.Hour,
				},
			},
		},
		
		Compliance: ComplianceConfig{
			Enabled:   true,
			Standards: []string{"FIPS-140-2", "Common Criteria", "SOC2", "GDPR"},
			Algorithms: AlgorithmConfig{
				Encryption:    []string{"AES-256-GCM", "ChaCha20-Poly1305"},
				Hashing:       []string{"SHA-256", "SHA-512", "BLAKE2b"},
				Signing:       []string{"ECDSA-P256", "ECDSA-P384", "RSA-PSS-2048"},
				KeyDerivation: []string{"PBKDF2", "Argon2id", "HKDF"},
			},
			KeyEscrow: KeyEscrowConfig{
				Enabled:   false, // Disable by default for security
				Threshold: 3,
			},
			Attestation: AttestationConfig{
				Enabled:         true,
				SigningAlgorithm: "ECDSA-P256",
				IncludeCertChain: true,
			},
		},
	}
}

// Validate validates the encryption configuration
func (c *Config) Validate() error {
	if c.MasterKeyDerivationKey == "" {
		return fmt.Errorf("master key derivation key is required")
	}
	
	if c.MasterKeySalt == "" {
		return fmt.Errorf("master key salt is required")
	}
	
	if c.Provider.Type == "" {
		return fmt.Errorf("key provider type is required")
	}
	
	// Validate key lifetimes
	if c.KeyLifetime.Default <= 0 {
		return fmt.Errorf("default key lifetime must be positive")
	}
	
	// Validate rotation settings
	if c.Rotation.Enabled && c.Rotation.RotationInterval <= 0 {
		return fmt.Errorf("rotation interval must be positive when rotation is enabled")
	}
	
	return nil
}

// GetDatabaseKeyID returns the encryption key ID for a specific database
func (c *Config) GetDatabaseKeyID(database string) string {
	switch database {
	case "postgresql":
		return c.PostgreSQL.TDEKeyID
	case "mongodb":
		return c.MongoDB.MasterKey.KeyID
	case "redis":
		return c.Redis.KeyID
	case "elasticsearch":
		return c.Elasticsearch.KeyID
	default:
		return ""
	}
}

// IsEncryptionEnabled returns whether encryption is enabled for a specific database
func (c *Config) IsEncryptionEnabled(database string) bool {
	switch database {
	case "postgresql":
		return c.PostgreSQL.Enabled
	case "mongodb":
		return c.MongoDB.Enabled
	case "redis":
		return c.Redis.Enabled
	case "elasticsearch":
		return c.Elasticsearch.Enabled
	default:
		return false
	}
}