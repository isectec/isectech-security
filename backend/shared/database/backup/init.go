package backup

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"github.com/isectech/platform/shared/database/encryption"
	"github.com/isectech/platform/shared/database/postgres"
	"github.com/isectech/platform/shared/database/mongodb"
	"github.com/isectech/platform/shared/database/redis"
	"github.com/isectech/platform/shared/database/elasticsearch"
)

// Initialize initializes the backup system with the provided configuration
func Initialize(
	ctx context.Context,
	config *Config,
	logger *zap.Logger,
	encryptionManager *encryption.KeyManager,
	pgClient *postgres.Client,
	mongoClient *mongodb.Client,
	redisClient *redis.Client,
	esClient *elasticsearch.Client,
) (*Manager, error) {
	
	logger.Info("Initializing backup system",
		zap.Bool("encryption_enabled", config.Security.EncryptionEnabled),
		zap.Bool("dr_enabled", config.DisasterRecovery.Enabled),
		zap.String("primary_storage", config.Storage.Primary.Type),
	)
	
	// Validate configuration
	if errors := config.ValidateConfig(); len(errors) > 0 {
		for _, err := range errors {
			logger.Error("Configuration validation error", zap.Error(err))
		}
		return nil, fmt.Errorf("backup configuration validation failed: %d errors", len(errors))
	}
	
	// Create backup manager
	manager, err := NewManager(
		config,
		logger,
		encryptionManager,
		pgClient,
		mongoClient,
		redisClient,
		esClient,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup manager: %w", err)
	}
	
	logger.Info("Backup system initialized successfully",
		zap.Duration("backup_sla", config.Monitoring.BackupSLA),
		zap.Duration("restore_sla", config.Monitoring.RestoreSLA),
		zap.Duration("rpo", config.Monitoring.RPO),
		zap.Duration("rto", config.Monitoring.RTO),
	)
	
	return manager, nil
}

// CreateDefaultConfig creates a default backup configuration for iSECTECH
func CreateDefaultConfig() *Config {
	return DefaultConfig()
}

// ValidateBackupInfrastructure validates that all backup infrastructure is accessible
func ValidateBackupInfrastructure(ctx context.Context, config *Config) error {
	// Validate storage backends
	if err := validateStorageBackends(ctx, config.Storage); err != nil {
		return fmt.Errorf("storage backend validation failed: %w", err)
	}
	
	// Validate backup retention compliance
	if err := validateRetentionCompliance(config.BackupRetention); err != nil {
		return fmt.Errorf("retention policy validation failed: %w", err)
	}
	
	// Validate security configuration
	if err := validateSecurityConfig(config.Security); err != nil {
		return fmt.Errorf("security configuration validation failed: %w", err)
	}
	
	return nil
}

func validateStorageBackends(ctx context.Context, config BackupStorageConfig) error {
	// Validate primary backend
	if config.Primary.Type == "" {
		return fmt.Errorf("primary storage backend type is required")
	}
	
	// Validate required parameters based on backend type
	switch config.Primary.Type {
	case "gcs":
		if config.Primary.Bucket == "" {
			return fmt.Errorf("GCS bucket is required for primary backend")
		}
	case "s3":
		if config.Primary.Bucket == "" {
			return fmt.Errorf("S3 bucket is required for primary backend")
		}
	case "local":
		if config.Primary.Path == "" {
			return fmt.Errorf("local path is required for primary backend")
		}
	}
	
	return nil
}

func validateRetentionCompliance(config BackupRetentionConfig) error {
	// Validate minimum retention periods for cybersecurity compliance
	if config.TopSecretRetention < 7*365*24*time.Hour {
		return fmt.Errorf("top secret data retention must be at least 7 years")
	}
	
	if config.SecretRetention < 5*365*24*time.Hour {
		return fmt.Errorf("secret data retention must be at least 5 years")
	}
	
	if config.ConfidentialRetention < 3*365*24*time.Hour {
		return fmt.Errorf("confidential data retention must be at least 3 years")
	}
	
	return nil
}

func validateSecurityConfig(config BackupSecurityConfig) error {
	if !config.EncryptionEnabled {
		return fmt.Errorf("encryption must be enabled for cybersecurity platform")
	}
	
	if config.EncryptionAlgorithm != "AES-256-GCM" && config.EncryptionAlgorithm != "ChaCha20-Poly1305" {
		return fmt.Errorf("unsupported encryption algorithm: %s", config.EncryptionAlgorithm)
	}
	
	if config.ChecksumAlgorithm != "SHA-256" && config.ChecksumAlgorithm != "SHA-512" {
		return fmt.Errorf("unsupported checksum algorithm: %s", config.ChecksumAlgorithm)
	}
	
	return nil
}