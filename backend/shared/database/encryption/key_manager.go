package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KeyManager handles encryption key management for iSECTECH platform
type KeyManager struct {
	config    *Config
	logger    *zap.Logger
	keys      map[string]*EncryptionKey
	masterKey []byte
	mu        sync.RWMutex
	provider  KeyProvider
	auditor   *AuditLogger
}

// EncryptionKey represents a managed encryption key
type EncryptionKey struct {
	ID          string            `json:"id"`
	Algorithm   string            `json:"algorithm"`
	KeyData     []byte            `json:"-"` // Never serialize raw key data
	KeyVersion  int               `json:"key_version"`
	Purpose     string            `json:"purpose"`     // data-encryption, key-encryption, signing
	Status      KeyStatus         `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	RotatedAt   *time.Time        `json:"rotated_at,omitempty"`
	Metadata    map[string]string `json:"metadata"`
	
	// Derived from key for different purposes
	encryptionKey []byte
	authKey       []byte
	cipher        cipher.AEAD
}

// KeyStatus represents the status of an encryption key
type KeyStatus string

const (
	KeyStatusActive     KeyStatus = "active"
	KeyStatusRotating   KeyStatus = "rotating"
	KeyStatusDeprecated KeyStatus = "deprecated"
	KeyStatusDestroyed  KeyStatus = "destroyed"
	KeyStatusRevoked    KeyStatus = "revoked"
)

// KeyProvider interface for different key storage backends
type KeyProvider interface {
	StoreKey(ctx context.Context, key *EncryptionKey) error
	RetrieveKey(ctx context.Context, keyID string) (*EncryptionKey, error)
	ListKeys(ctx context.Context) ([]*EncryptionKey, error)
	DeleteKey(ctx context.Context, keyID string) error
	HealthCheck(ctx context.Context) error
}

// AuditLogger handles encryption audit logging
type AuditLogger struct {
	logger *zap.Logger
	config AuditConfig
}

// AuditEvent represents an encryption audit event
type AuditEvent struct {
	EventID     string                 `json:"event_id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	KeyID       string                 `json:"key_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	TenantID    string                 `json:"tenant_id,omitempty"`
	Action      string                 `json:"action"`
	Success     bool                   `json:"success"`
	ErrorMessage string                `json:"error_message,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
}

// EncryptionRequest represents a request to encrypt data
type EncryptionRequest struct {
	Data         []byte            `json:"data"`
	KeyID        string            `json:"key_id"`
	Context      map[string]string `json:"context,omitempty"`
	TenantID     string            `json:"tenant_id,omitempty"`
	UserID       string            `json:"user_id,omitempty"`
}

// EncryptionResult represents the result of encryption
type EncryptionResult struct {
	EncryptedData []byte    `json:"encrypted_data"`
	KeyID         string    `json:"key_id"`
	KeyVersion    int       `json:"key_version"`
	Nonce         []byte    `json:"nonce"`
	Timestamp     time.Time `json:"timestamp"`
	Algorithm     string    `json:"algorithm"`
}

// DecryptionRequest represents a request to decrypt data
type DecryptionRequest struct {
	EncryptedData []byte            `json:"encrypted_data"`
	KeyID         string            `json:"key_id"`
	KeyVersion    int               `json:"key_version"`
	Nonce         []byte            `json:"nonce"`
	Context       map[string]string `json:"context,omitempty"`
	TenantID      string            `json:"tenant_id,omitempty"`
	UserID        string            `json:"user_id,omitempty"`
}

// KeyRotationResult represents the result of key rotation
type KeyRotationResult struct {
	OldKeyID    string    `json:"old_key_id"`
	NewKeyID    string    `json:"new_key_id"`
	RotatedAt   time.Time `json:"rotated_at"`
	AffectedRecords int64 `json:"affected_records"`
}

// NewKeyManager creates a new key manager instance
func NewKeyManager(config *Config, provider KeyProvider, logger *zap.Logger) (*KeyManager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Initialize master key
	masterKey, err := deriveMasterKey(config.MasterKeyDerivationKey, config.MasterKeySalt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	auditor := &AuditLogger{
		logger: logger.With(zap.String("component", "encryption-audit")),
		config: config.Audit,
	}

	km := &KeyManager{
		config:    config,
		logger:    logger,
		keys:      make(map[string]*EncryptionKey),
		masterKey: masterKey,
		provider:  provider,
		auditor:   auditor,
	}

	// Load existing keys
	if err := km.loadKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load existing keys: %w", err)
	}

	logger.Info("Key manager initialized",
		zap.Int("loaded_keys", len(km.keys)),
		zap.String("provider", fmt.Sprintf("%T", provider)))

	return km, nil
}

// GenerateKey generates a new encryption key
func (km *KeyManager) GenerateKey(ctx context.Context, purpose, algorithm string, metadata map[string]string) (*EncryptionKey, error) {
	keyID := generateKeyID()
	
	// Generate random key material
	keySize := getKeySize(algorithm)
	keyData := make([]byte, keySize)
	if _, err := rand.Read(keyData); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	key := &EncryptionKey{
		ID:        keyID,
		Algorithm: algorithm,
		KeyData:   keyData,
		KeyVersion: 1,
		Purpose:   purpose,
		Status:    KeyStatusActive,
		CreatedAt: time.Now(),
		Metadata:  metadata,
	}

	// Set expiration based on purpose
	if expiry := km.getKeyExpiry(purpose); expiry != nil {
		key.ExpiresAt = expiry
	}

	// Derive encryption and auth keys
	if err := km.deriveKeys(key); err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Store the key
	if err := km.provider.StoreKey(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	// Add to in-memory cache
	km.mu.Lock()
	km.keys[keyID] = key
	km.mu.Unlock()

	// Audit the key generation
	km.auditor.LogEvent(&AuditEvent{
		EventID:   generateAuditID(),
		Timestamp: time.Now(),
		EventType: "key_generation",
		KeyID:     keyID,
		Action:    "generate_key",
		Success:   true,
		Metadata: map[string]interface{}{
			"purpose":   purpose,
			"algorithm": algorithm,
		},
	})

	km.logger.Info("Encryption key generated",
		zap.String("key_id", keyID),
		zap.String("purpose", purpose),
		zap.String("algorithm", algorithm))

	return key, nil
}

// GetKey retrieves an encryption key by ID
func (km *KeyManager) GetKey(ctx context.Context, keyID string) (*EncryptionKey, error) {
	km.mu.RLock()
	key, exists := km.keys[keyID]
	km.mu.RUnlock()

	if !exists {
		// Try to load from provider
		var err error
		key, err = km.provider.RetrieveKey(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}

		// Derive encryption keys
		if err := km.deriveKeys(key); err != nil {
			return nil, fmt.Errorf("failed to derive keys: %w", err)
		}

		// Add to cache
		km.mu.Lock()
		km.keys[keyID] = key
		km.mu.Unlock()
	}

	// Check key status and expiration
	if key.Status != KeyStatusActive {
		return nil, fmt.Errorf("key %s is not active (status: %s)", keyID, key.Status)
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, fmt.Errorf("key %s has expired", keyID)
	}

	return key, nil
}

// Encrypt encrypts data using the specified key
func (km *KeyManager) Encrypt(ctx context.Context, req *EncryptionRequest) (*EncryptionResult, error) {
	key, err := km.GetKey(ctx, req.KeyID)
	if err != nil {
		km.auditor.LogEvent(&AuditEvent{
			EventID:      generateAuditID(),
			Timestamp:    time.Now(),
			EventType:    "encryption",
			KeyID:        req.KeyID,
			TenantID:     req.TenantID,
			UserID:       req.UserID,
			Action:       "encrypt",
			Success:      false,
			ErrorMessage: err.Error(),
		})
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, key.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := key.cipher.Seal(nil, nonce, req.Data, nil)

	result := &EncryptionResult{
		EncryptedData: ciphertext,
		KeyID:         key.ID,
		KeyVersion:    key.KeyVersion,
		Nonce:         nonce,
		Timestamp:     time.Now(),
		Algorithm:     key.Algorithm,
	}

	// Audit successful encryption
	km.auditor.LogEvent(&AuditEvent{
		EventID:   generateAuditID(),
		Timestamp: time.Now(),
		EventType: "encryption",
		KeyID:     req.KeyID,
		TenantID:  req.TenantID,
		UserID:    req.UserID,
		Action:    "encrypt",
		Success:   true,
		Metadata: map[string]interface{}{
			"data_size": len(req.Data),
		},
	})

	return result, nil
}

// Decrypt decrypts data using the specified key
func (km *KeyManager) Decrypt(ctx context.Context, req *DecryptionRequest) ([]byte, error) {
	key, err := km.GetKey(ctx, req.KeyID)
	if err != nil {
		km.auditor.LogEvent(&AuditEvent{
			EventID:      generateAuditID(),
			Timestamp:    time.Now(),
			EventType:    "decryption",
			KeyID:        req.KeyID,
			TenantID:     req.TenantID,
			UserID:       req.UserID,
			Action:       "decrypt",
			Success:      false,
			ErrorMessage: err.Error(),
		})
		return nil, err
	}

	// Check key version compatibility
	if key.KeyVersion != req.KeyVersion {
		return nil, fmt.Errorf("key version mismatch: expected %d, got %d", key.KeyVersion, req.KeyVersion)
	}

	// Decrypt data
	plaintext, err := key.cipher.Open(nil, req.Nonce, req.EncryptedData, nil)
	if err != nil {
		km.auditor.LogEvent(&AuditEvent{
			EventID:      generateAuditID(),
			Timestamp:    time.Now(),
			EventType:    "decryption",
			KeyID:        req.KeyID,
			TenantID:     req.TenantID,
			UserID:       req.UserID,
			Action:       "decrypt",
			Success:      false,
			ErrorMessage: "decryption failed",
		})
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Audit successful decryption
	km.auditor.LogEvent(&AuditEvent{
		EventID:   generateAuditID(),
		Timestamp: time.Now(),
		EventType: "decryption",
		KeyID:     req.KeyID,
		TenantID:  req.TenantID,
		UserID:    req.UserID,
		Action:    "decrypt",
		Success:   true,
		Metadata: map[string]interface{}{
			"data_size": len(plaintext),
		},
	})

	return plaintext, nil
}

// RotateKey rotates an encryption key
func (km *KeyManager) RotateKey(ctx context.Context, keyID string) (*KeyRotationResult, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	oldKey, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Create new key with same properties
	newKey := &EncryptionKey{
		ID:        generateKeyID(),
		Algorithm: oldKey.Algorithm,
		Purpose:   oldKey.Purpose,
		Status:    KeyStatusActive,
		CreatedAt: time.Now(),
		Metadata:  oldKey.Metadata,
		KeyVersion: oldKey.KeyVersion + 1,
	}

	// Generate new key material
	keySize := getKeySize(newKey.Algorithm)
	keyData := make([]byte, keySize)
	if _, err := rand.Read(keyData); err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}
	newKey.KeyData = keyData

	// Set expiration
	if expiry := km.getKeyExpiry(newKey.Purpose); expiry != nil {
		newKey.ExpiresAt = expiry
	}

	// Derive encryption keys
	if err := km.deriveKeys(newKey); err != nil {
		return nil, fmt.Errorf("failed to derive new keys: %w", err)
	}

	// Store new key
	if err := km.provider.StoreKey(ctx, newKey); err != nil {
		return nil, fmt.Errorf("failed to store new key: %w", err)
	}

	// Mark old key as deprecated
	now := time.Now()
	oldKey.Status = KeyStatusDeprecated
	oldKey.RotatedAt = &now

	// Update old key in storage
	if err := km.provider.StoreKey(ctx, oldKey); err != nil {
		km.logger.Warn("Failed to update old key status", zap.Error(err))
	}

	// Update cache
	km.keys[newKey.ID] = newKey
	km.keys[keyID] = oldKey

	result := &KeyRotationResult{
		OldKeyID:  keyID,
		NewKeyID:  newKey.ID,
		RotatedAt: now,
	}

	// Audit key rotation
	km.auditor.LogEvent(&AuditEvent{
		EventID:   generateAuditID(),
		Timestamp: time.Now(),
		EventType: "key_rotation",
		KeyID:     keyID,
		Action:    "rotate_key",
		Success:   true,
		Metadata: map[string]interface{}{
			"new_key_id": newKey.ID,
		},
	})

	km.logger.Info("Key rotated",
		zap.String("old_key_id", keyID),
		zap.String("new_key_id", newKey.ID))

	return result, nil
}

// ListKeys returns all keys managed by this key manager
func (km *KeyManager) ListKeys(ctx context.Context) ([]*EncryptionKey, error) {
	keys, err := km.provider.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	return keys, nil
}

// DeleteKey securely deletes an encryption key
func (km *KeyManager) DeleteKey(ctx context.Context, keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Mark key as destroyed
	if key, exists := km.keys[keyID]; exists {
		key.Status = KeyStatusDestroyed
		
		// Zero out key material
		for i := range key.KeyData {
			key.KeyData[i] = 0
		}
		for i := range key.encryptionKey {
			key.encryptionKey[i] = 0
		}
		for i := range key.authKey {
			key.authKey[i] = 0
		}
	}

	// Delete from provider
	if err := km.provider.DeleteKey(ctx, keyID); err != nil {
		return fmt.Errorf("failed to delete key from provider: %w", err)
	}

	// Remove from cache
	delete(km.keys, keyID)

	// Audit key deletion
	km.auditor.LogEvent(&AuditEvent{
		EventID:   generateAuditID(),
		Timestamp: time.Now(),
		EventType: "key_deletion",
		KeyID:     keyID,
		Action:    "delete_key",
		Success:   true,
	})

	km.logger.Info("Key deleted", zap.String("key_id", keyID))
	return nil
}

// GetHealth returns the health status of the key manager
func (km *KeyManager) GetHealth(ctx context.Context) map[string]interface{} {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
	}

	// Check provider health
	if err := km.provider.HealthCheck(ctx); err != nil {
		health["status"] = "unhealthy"
		health["provider_error"] = err.Error()
	}

	// Add key statistics
	km.mu.RLock()
	activeKeys := 0
	expiredKeys := 0
	for _, key := range km.keys {
		if key.Status == KeyStatusActive {
			activeKeys++
		}
		if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
			expiredKeys++
		}
	}
	km.mu.RUnlock()

	health["active_keys"] = activeKeys
	health["expired_keys"] = expiredKeys
	health["total_keys"] = len(km.keys)

	return health
}

// Helper functions

func (km *KeyManager) loadKeys(ctx context.Context) error {
	keys, err := km.provider.ListKeys(ctx)
	if err != nil {
		return err
	}

	for _, key := range keys {
		if err := km.deriveKeys(key); err != nil {
			km.logger.Error("Failed to derive keys for loaded key",
				zap.String("key_id", key.ID),
				zap.Error(err))
			continue
		}
		km.keys[key.ID] = key
	}

	return nil
}

func (km *KeyManager) deriveKeys(key *EncryptionKey) error {
	// Derive encryption and authentication keys using HKDF
	salt := []byte("isectech-encryption-salt")
	info := []byte("isectech-" + key.Purpose)
	
	// Create HKDF
	hash := sha256.New
	hkdf := func(length int, info []byte) []byte {
		return pbkdf2.Key(key.KeyData, salt, 4096, length, hash)
	}

	// Derive encryption key (32 bytes for AES-256)
	key.encryptionKey = hkdf(32, append(info, []byte("-encryption")...))
	
	// Derive authentication key (32 bytes)
	key.authKey = hkdf(32, append(info, []byte("-auth")...))

	// Create AEAD cipher
	block, err := aes.NewCipher(key.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	key.cipher = aead
	return nil
}

func (km *KeyManager) getKeyExpiry(purpose string) *time.Time {
	expiry := time.Now()
	
	switch purpose {
	case "data-encryption":
		expiry = expiry.Add(km.config.KeyLifetime.DataEncryption)
	case "key-encryption":
		expiry = expiry.Add(km.config.KeyLifetime.KeyEncryption)
	case "signing":
		expiry = expiry.Add(km.config.KeyLifetime.Signing)
	default:
		expiry = expiry.Add(km.config.KeyLifetime.Default)
	}
	
	return &expiry
}

// LogEvent logs an audit event
func (al *AuditLogger) LogEvent(event *AuditEvent) {
	if event.EventID == "" {
		event.EventID = generateAuditID()
	}
	
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Log to structured logger
	fields := []zap.Field{
		zap.String("event_id", event.EventID),
		zap.String("event_type", event.EventType),
		zap.String("action", event.Action),
		zap.Bool("success", event.Success),
	}

	if event.KeyID != "" {
		fields = append(fields, zap.String("key_id", event.KeyID))
	}
	if event.UserID != "" {
		fields = append(fields, zap.String("user_id", event.UserID))
	}
	if event.TenantID != "" {
		fields = append(fields, zap.String("tenant_id", event.TenantID))
	}
	if event.ErrorMessage != "" {
		fields = append(fields, zap.String("error", event.ErrorMessage))
	}

	al.logger.Info("Encryption audit event", fields...)

	// TODO: Send to external audit system
}

// Utility functions

func deriveMasterKey(derivationKey, salt string) ([]byte, error) {
	return argon2.IDKey([]byte(derivationKey), []byte(salt), 1, 64*1024, 4, 32), nil
}

func generateKeyID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return fmt.Sprintf("key_%s", base64.URLEncoding.EncodeToString(id)[:22])
}

func generateAuditID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return fmt.Sprintf("audit_%s", base64.URLEncoding.EncodeToString(id)[:22])
}

func getKeySize(algorithm string) int {
	switch algorithm {
	case "AES-256-GCM":
		return 32
	case "AES-128-GCM":
		return 16
	case "ChaCha20-Poly1305":
		return 32
	default:
		return 32 // Default to AES-256
	}
}

// Close closes the key manager and clears sensitive data
func (km *KeyManager) Close() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Zero out all key material
	for _, key := range km.keys {
		if key.KeyData != nil {
			for i := range key.KeyData {
				key.KeyData[i] = 0
			}
		}
		if key.encryptionKey != nil {
			for i := range key.encryptionKey {
				key.encryptionKey[i] = 0
			}
		}
		if key.authKey != nil {
			for i := range key.authKey {
				key.authKey[i] = 0
			}
		}
	}

	// Clear master key
	for i := range km.masterKey {
		km.masterKey[i] = 0
	}

	// Clear key cache
	km.keys = make(map[string]*EncryptionKey)

	km.logger.Info("Key manager closed and sensitive data cleared")
	return nil
}