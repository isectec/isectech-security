package encryption

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// InitializeEncryption initializes the encryption system for iSECTECH platform
func InitializeEncryption(configPath string, logger *zap.Logger) (*DatabaseEncryptionManager, error) {
	// Load encryption configuration
	config, err := LoadEncryptionConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption config: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid encryption config: %w", err)
	}

	// Create key provider
	provider, err := CreateProvider(config.Provider, logger.With(zap.String("component", "key-provider")))
	if err != nil {
		return nil, fmt.Errorf("failed to create key provider: %w", err)
	}

	// Create key manager
	keyManager, err := NewKeyManager(config, provider, logger.With(zap.String("component", "key-manager")))
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager: %w", err)
	}

	// Create database encryption manager
	dbEncryptionManager, err := NewDatabaseEncryptionManager(keyManager, config, logger.With(zap.String("component", "db-encryption")))
	if err != nil {
		return nil, fmt.Errorf("failed to create database encryption manager: %w", err)
	}

	// Initialize all database encryption systems
	if err := dbEncryptionManager.InitializeAllDatabases(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize database encryption: %w", err)
	}

	logger.Info("Encryption system initialized successfully")
	return dbEncryptionManager, nil
}

// LoadEncryptionConfig loads encryption configuration from file and environment
func LoadEncryptionConfig(configPath string) (*Config, error) {
	// Start with default configuration
	config := DefaultConfig()

	// Load from file if provided
	if configPath != "" {
		if err := common.LoadConfigFromFile(configPath, config); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
	}

	// Override with environment variables
	if err := loadConfigFromEnvironment(config); err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}

	return config, nil
}

// loadConfigFromEnvironment loads configuration from environment variables
func loadConfigFromEnvironment(config *Config) error {
	// Master key configuration (required)
	if derivationKey := os.Getenv("ISECTECH_MASTER_KEY_DERIVATION"); derivationKey != "" {
		config.MasterKeyDerivationKey = derivationKey
	}
	if salt := os.Getenv("ISECTECH_MASTER_KEY_SALT"); salt != "" {
		config.MasterKeySalt = salt
	}

	// Provider configuration
	if providerType := os.Getenv("ISECTECH_KEY_PROVIDER"); providerType != "" {
		config.Provider.Type = providerType
	}

	// Vault configuration
	if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
		config.Provider.Vault.Address = vaultAddr
	}
	if vaultToken := os.Getenv("VAULT_TOKEN"); vaultToken != "" {
		config.Provider.Vault.Token = vaultToken
	}
	if vaultMount := os.Getenv("VAULT_MOUNT_PATH"); vaultMount != "" {
		config.Provider.Vault.MountPath = vaultMount
	}
	if vaultNamespace := os.Getenv("VAULT_NAMESPACE"); vaultNamespace != "" {
		config.Provider.Vault.Namespace = vaultNamespace
	}

	// AWS KMS configuration
	if awsRegion := os.Getenv("AWS_REGION"); awsRegion != "" {
		config.Provider.AWSKMS.Region = awsRegion
	}
	if awsKeyID := os.Getenv("AWS_KMS_KEY_ID"); awsKeyID != "" {
		config.Provider.AWSKMS.KeyID = awsKeyID
	}
	if awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID"); awsAccessKey != "" {
		config.Provider.AWSKMS.AccessKey = awsAccessKey
	}
	if awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY"); awsSecretKey != "" {
		config.Provider.AWSKMS.SecretKey = awsSecretKey
	}

	// GCP KMS configuration
	if gcpProject := os.Getenv("GCP_PROJECT_ID"); gcpProject != "" {
		config.Provider.GCPKMS.ProjectID = gcpProject
	}
	if gcpLocation := os.Getenv("GCP_LOCATION_ID"); gcpLocation != "" {
		config.Provider.GCPKMS.LocationID = gcpLocation
	}
	if gcpKeyRing := os.Getenv("GCP_KEY_RING_ID"); gcpKeyRing != "" {
		config.Provider.GCPKMS.KeyRingID = gcpKeyRing
	}
	if gcpKey := os.Getenv("GCP_KEY_ID"); gcpKey != "" {
		config.Provider.GCPKMS.KeyID = gcpKey
	}
	if gcpCreds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); gcpCreds != "" {
		config.Provider.GCPKMS.CredsPath = gcpCreds
	}

	// Azure Key Vault configuration
	if azureVault := os.Getenv("AZURE_KEY_VAULT_URL"); azureVault != "" {
		config.Provider.AzureKV.VaultURL = azureVault
	}
	if azureTenant := os.Getenv("AZURE_TENANT_ID"); azureTenant != "" {
		config.Provider.AzureKV.TenantID = azureTenant
	}
	if azureClient := os.Getenv("AZURE_CLIENT_ID"); azureClient != "" {
		config.Provider.AzureKV.ClientID = azureClient
	}
	if azureSecret := os.Getenv("AZURE_CLIENT_SECRET"); azureSecret != "" {
		config.Provider.AzureKV.ClientSecret = azureSecret
	}

	// Local provider configuration
	if localPath := os.Getenv("ISECTECH_LOCAL_KEY_PATH"); localPath != "" {
		config.Provider.Local.StoragePath = localPath
	}

	// Database-specific key IDs
	if pgKeyID := os.Getenv("ISECTECH_POSTGRESQL_KEY_ID"); pgKeyID != "" {
		config.PostgreSQL.TDEKeyID = pgKeyID
	}
	if mongoKeyID := os.Getenv("ISECTECH_MONGODB_KEY_ID"); mongoKeyID != "" {
		config.MongoDB.MasterKey.KeyID = mongoKeyID
	}
	if redisKeyID := os.Getenv("ISECTECH_REDIS_KEY_ID"); redisKeyID != "" {
		config.Redis.KeyID = redisKeyID
	}
	if esKeyID := os.Getenv("ISECTECH_ELASTICSEARCH_KEY_ID"); esKeyID != "" {
		config.Elasticsearch.KeyID = esKeyID
	}

	return nil
}

// CreateEncryptionDirectories creates necessary directories for encryption
func CreateEncryptionDirectories(basePath string) error {
	directories := []string{
		"keys",
		"audit",
		"backup",
		"temp",
	}

	for _, dir := range directories {
		fullPath := filepath.Join(basePath, dir)
		if err := os.MkdirAll(fullPath, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", fullPath, err)
		}
	}

	return nil
}

// GenerateInitialKeys generates initial encryption keys for all databases
func GenerateInitialKeys(ctx context.Context, keyManager *KeyManager, config *Config) error {
	// Generate PostgreSQL TDE key if not specified
	if config.PostgreSQL.Enabled && config.PostgreSQL.TDEKeyID == "" {
		key, err := keyManager.GenerateKey(ctx, "data-encryption", "AES-256-GCM", map[string]string{
			"database": "postgresql",
			"purpose":  "tde",
			"initial":  "true",
		})
		if err != nil {
			return fmt.Errorf("failed to generate PostgreSQL TDE key: %w", err)
		}
		config.PostgreSQL.TDEKeyID = key.ID
	}

	// Generate MongoDB master key if not specified
	if config.MongoDB.Enabled && config.MongoDB.MasterKey.KeyID == "" {
		key, err := keyManager.GenerateKey(ctx, "key-encryption", "AES-256-GCM", map[string]string{
			"database": "mongodb",
			"purpose":  "master-key",
			"initial":  "true",
		})
		if err != nil {
			return fmt.Errorf("failed to generate MongoDB master key: %w", err)
		}
		config.MongoDB.MasterKey.KeyID = key.ID
	}

	// Generate Redis encryption key if not specified
	if config.Redis.Enabled && config.Redis.KeyID == "" {
		key, err := keyManager.GenerateKey(ctx, "data-encryption", "AES-256-GCM", map[string]string{
			"database": "redis",
			"purpose":  "value-encryption",
			"initial":  "true",
		})
		if err != nil {
			return fmt.Errorf("failed to generate Redis encryption key: %w", err)
		}
		config.Redis.KeyID = key.ID
	}

	// Generate Elasticsearch encryption key if not specified
	if config.Elasticsearch.Enabled && config.Elasticsearch.KeyID == "" {
		key, err := keyManager.GenerateKey(ctx, "data-encryption", "AES-256-GCM", map[string]string{
			"database": "elasticsearch",
			"purpose":  "index-encryption",
			"initial":  "true",
		})
		if err != nil {
			return fmt.Errorf("failed to generate Elasticsearch encryption key: %w", err)
		}
		config.Elasticsearch.KeyID = key.ID
	}

	return nil
}

// ValidateEncryptionSetup validates the entire encryption setup
func ValidateEncryptionSetup(ctx context.Context, manager *DatabaseEncryptionManager) error {
	// Get encryption status for all databases
	status := manager.GetEncryptionStatus()

	for database, dbStatus := range status {
		if !dbStatus.Enabled {
			return fmt.Errorf("encryption not enabled for database: %s", database)
		}

		if dbStatus.KeyID == "" {
			return fmt.Errorf("no encryption key configured for database: %s", database)
		}

		// Validate encryption key exists and is accessible
		key, err := manager.keyManager.GetKey(ctx, dbStatus.KeyID)
		if err != nil {
			return fmt.Errorf("encryption key validation failed for %s: %w", database, err)
		}

		if key.Status != KeyStatusActive {
			return fmt.Errorf("encryption key for %s is not active: %s", database, key.Status)
		}
	}

	return nil
}

// PerformComplianceCheck performs compliance checks on the encryption setup
func PerformComplianceCheck(config *Config, status map[string]EncryptionStatus) []ComplianceIssue {
	var issues []ComplianceIssue

	// Check algorithm compliance
	for database, dbStatus := range status {
		if !isAlgorithmCompliant(dbStatus.Algorithm, config.Compliance.Algorithms.Encryption) {
			issues = append(issues, ComplianceIssue{
				Database:    database,
				Type:        "algorithm",
				Severity:    "high",
				Message:     fmt.Sprintf("Non-compliant encryption algorithm: %s", dbStatus.Algorithm),
				Remediation: "Use FIPS-140-2 approved algorithm like AES-256-GCM",
			})
		}
	}

	// Check key rotation compliance
	for database, dbStatus := range status {
		if time.Since(dbStatus.LastRotation) > 90*24*time.Hour {
			issues = append(issues, ComplianceIssue{
				Database:    database,
				Type:        "key_rotation",
				Severity:    "medium",
				Message:     fmt.Sprintf("Key rotation overdue by %v", time.Since(dbStatus.LastRotation)),
				Remediation: "Rotate encryption keys within 90 days",
			})
		}
	}

	return issues
}

// ComplianceIssue represents a compliance issue
type ComplianceIssue struct {
	Database    string `json:"database"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// isAlgorithmCompliant checks if an algorithm is compliant
func isAlgorithmCompliant(algorithm string, approvedAlgorithms []string) bool {
	for _, approved := range approvedAlgorithms {
		if algorithm == approved {
			return true
		}
	}
	return false
}

// GetEncryptionSummary returns a summary of the encryption setup
func GetEncryptionSummary(status map[string]EncryptionStatus) EncryptionSummary {
	summary := EncryptionSummary{
		TotalDatabases:    len(status),
		EncryptedDatabases: 0,
		ComplianceStatus:  "compliant",
		Algorithms:        make(map[string]int),
	}

	for _, dbStatus := range status {
		if dbStatus.Enabled {
			summary.EncryptedDatabases++
		}
		
		if count, exists := summary.Algorithms[dbStatus.Algorithm]; exists {
			summary.Algorithms[dbStatus.Algorithm] = count + 1
		} else {
			summary.Algorithms[dbStatus.Algorithm] = 1
		}
	}

	// Calculate encryption percentage
	if summary.TotalDatabases > 0 {
		summary.EncryptionPercentage = float64(summary.EncryptedDatabases) / float64(summary.TotalDatabases) * 100
	}

	return summary
}

// EncryptionSummary represents a summary of encryption status
type EncryptionSummary struct {
	TotalDatabases       int            `json:"total_databases"`
	EncryptedDatabases   int            `json:"encrypted_databases"`
	EncryptionPercentage float64        `json:"encryption_percentage"`
	ComplianceStatus     string         `json:"compliance_status"`
	Algorithms           map[string]int `json:"algorithms"`
}

// BackupEncryptionKeys creates encrypted backups of all encryption keys
func BackupEncryptionKeys(ctx context.Context, keyManager *KeyManager, backupPath string) error {
	keys, err := keyManager.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to list keys for backup: %w", err)
	}

	// Create backup directory
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup manifest
	manifest := KeyBackupManifest{
		Timestamp: time.Now(),
		Keys:      make([]KeyBackupInfo, 0, len(keys)),
	}

	for _, key := range keys {
		// Create backup info (without sensitive data)
		backupInfo := KeyBackupInfo{
			ID:         key.ID,
			Algorithm:  key.Algorithm,
			Purpose:    key.Purpose,
			Status:     string(key.Status),
			CreatedAt:  key.CreatedAt,
			KeyVersion: key.KeyVersion,
			Metadata:   key.Metadata,
		}

		manifest.Keys = append(manifest.Keys, backupInfo)
	}

	// Write manifest to file
	manifestPath := filepath.Join(backupPath, fmt.Sprintf("manifest_%d.json", time.Now().Unix()))
	manifestData, err := common.MarshalJSON(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal backup manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestData, 0600); err != nil {
		return fmt.Errorf("failed to write backup manifest: %w", err)
	}

	return nil
}

// KeyBackupManifest represents a backup manifest
type KeyBackupManifest struct {
	Timestamp time.Time         `json:"timestamp"`
	Keys      []KeyBackupInfo   `json:"keys"`
}

// KeyBackupInfo represents backup information for a key
type KeyBackupInfo struct {
	ID         string            `json:"id"`
	Algorithm  string            `json:"algorithm"`
	Purpose    string            `json:"purpose"`
	Status     string            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
	KeyVersion int               `json:"key_version"`
	Metadata   map[string]string `json:"metadata"`
}