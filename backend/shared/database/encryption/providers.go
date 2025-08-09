package encryption

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LocalProvider implements a file-based key provider for development
type LocalProvider struct {
	config   LocalConfig
	logger   *zap.Logger
	basePath string
	mu       sync.RWMutex
}

// VaultProvider implements HashiCorp Vault key provider
type VaultProvider struct {
	config VaultConfig
	logger *zap.Logger
	client VaultClient
}

// VaultClient interface for HashiCorp Vault operations
type VaultClient interface {
	Write(ctx context.Context, path string, data map[string]interface{}) error
	Read(ctx context.Context, path string) (map[string]interface{}, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, path string) ([]string, error)
	Health(ctx context.Context) error
}

// SerializedKey represents a key for serialization
type SerializedKey struct {
	ID         string            `json:"id"`
	Algorithm  string            `json:"algorithm"`
	KeyData    string            `json:"key_data"`    // Base64 encoded
	KeyVersion int               `json:"key_version"`
	Purpose    string            `json:"purpose"`
	Status     string            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`
	RotatedAt  *time.Time        `json:"rotated_at,omitempty"`
	Metadata   map[string]string `json:"metadata"`
}

// NewLocalProvider creates a new local file-based key provider
func NewLocalProvider(config LocalConfig, logger *zap.Logger) (*LocalProvider, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(config.StoragePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	provider := &LocalProvider{
		config:   config,
		logger:   logger,
		basePath: config.StoragePath,
	}

	logger.Info("Local key provider initialized",
		zap.String("storage_path", config.StoragePath),
		zap.Bool("encryption", config.Encryption))

	return provider, nil
}

// StoreKey stores an encryption key to the local filesystem
func (lp *LocalProvider) StoreKey(ctx context.Context, key *EncryptionKey) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	// Serialize the key
	serialized := &SerializedKey{
		ID:         key.ID,
		Algorithm:  key.Algorithm,
		KeyData:    encodeKeyData(key.KeyData),
		KeyVersion: key.KeyVersion,
		Purpose:    key.Purpose,
		Status:     string(key.Status),
		CreatedAt:  key.CreatedAt,
		ExpiresAt:  key.ExpiresAt,
		RotatedAt:  key.RotatedAt,
		Metadata:   key.Metadata,
	}

	data, err := json.MarshalIndent(serialized, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// Encrypt data if encryption is enabled
	if lp.config.Encryption {
		data, err = lp.encryptData(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt key data: %w", err)
		}
	}

	// Write to file
	filename := filepath.Join(lp.basePath, fmt.Sprintf("%s.json", key.ID))
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	lp.logger.Debug("Key stored to local filesystem",
		zap.String("key_id", key.ID),
		zap.String("filename", filename))

	return nil
}

// RetrieveKey retrieves an encryption key from the local filesystem
func (lp *LocalProvider) RetrieveKey(ctx context.Context, keyID string) (*EncryptionKey, error) {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	filename := filepath.Join(lp.basePath, fmt.Sprintf("%s.json", keyID))
	
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Decrypt data if encryption is enabled
	if lp.config.Encryption {
		data, err = lp.decryptData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key data: %w", err)
		}
	}

	// Deserialize the key
	var serialized SerializedKey
	if err := json.Unmarshal(data, &serialized); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}

	keyData, err := decodeKeyData(serialized.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key data: %w", err)
	}

	key := &EncryptionKey{
		ID:         serialized.ID,
		Algorithm:  serialized.Algorithm,
		KeyData:    keyData,
		KeyVersion: serialized.KeyVersion,
		Purpose:    serialized.Purpose,
		Status:     KeyStatus(serialized.Status),
		CreatedAt:  serialized.CreatedAt,
		ExpiresAt:  serialized.ExpiresAt,
		RotatedAt:  serialized.RotatedAt,
		Metadata:   serialized.Metadata,
	}

	lp.logger.Debug("Key retrieved from local filesystem",
		zap.String("key_id", keyID))

	return key, nil
}

// ListKeys lists all encryption keys in the local filesystem
func (lp *LocalProvider) ListKeys(ctx context.Context) ([]*EncryptionKey, error) {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	var keys []*EncryptionKey

	err := filepath.WalkDir(lp.basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Extract key ID from filename
		filename := filepath.Base(path)
		keyID := strings.TrimSuffix(filename, ".json")

		// Skip if not a valid key ID format
		if !strings.HasPrefix(keyID, "key_") {
			return nil
		}

		key, err := lp.RetrieveKey(ctx, keyID)
		if err != nil {
			lp.logger.Warn("Failed to load key during listing",
				zap.String("key_id", keyID),
				zap.Error(err))
			return nil // Continue with other keys
		}

		keys = append(keys, key)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk storage directory: %w", err)
	}

	lp.logger.Debug("Listed keys from local filesystem",
		zap.Int("count", len(keys)))

	return keys, nil
}

// DeleteKey deletes an encryption key from the local filesystem
func (lp *LocalProvider) DeleteKey(ctx context.Context, keyID string) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	filename := filepath.Join(lp.basePath, fmt.Sprintf("%s.json", keyID))
	
	if err := os.Remove(filename); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key not found: %s", keyID)
		}
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	lp.logger.Debug("Key deleted from local filesystem",
		zap.String("key_id", keyID))

	return nil
}

// HealthCheck checks the health of the local provider
func (lp *LocalProvider) HealthCheck(ctx context.Context) error {
	// Check if storage directory is accessible
	if _, err := os.Stat(lp.basePath); err != nil {
		return fmt.Errorf("storage directory not accessible: %w", err)
	}

	// Try to create a temporary file to check write permissions
	tempFile := filepath.Join(lp.basePath, ".health_check")
	if err := os.WriteFile(tempFile, []byte("health_check"), 0600); err != nil {
		return fmt.Errorf("storage directory not writable: %w", err)
	}

	// Clean up temp file
	os.Remove(tempFile)

	return nil
}

// encryptData encrypts data using a simple XOR cipher (for demo purposes)
// In production, use proper encryption
func (lp *LocalProvider) encryptData(data []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ key[i%len(key)]
	}

	// Prepend key to encrypted data (simplified approach)
	result := append(key, encrypted...)
	return result, nil
}

// decryptData decrypts data using the embedded key
func (lp *LocalProvider) decryptData(data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	key := data[:32]
	encrypted := data[32:]

	decrypted := make([]byte, len(encrypted))
	for i := range encrypted {
		decrypted[i] = encrypted[i] ^ key[i%len(key)]
	}

	return decrypted, nil
}

// NewVaultProvider creates a new HashiCorp Vault key provider
func NewVaultProvider(config VaultConfig, logger *zap.Logger) (*VaultProvider, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Create Vault client (implementation would depend on actual Vault client library)
	client, err := createVaultClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	provider := &VaultProvider{
		config: config,
		logger: logger,
		client: client,
	}

	// Test connection
	if err := provider.HealthCheck(context.Background()); err != nil {
		return nil, fmt.Errorf("Vault health check failed: %w", err)
	}

	logger.Info("Vault key provider initialized",
		zap.String("address", config.Address),
		zap.String("mount_path", config.MountPath))

	return provider, nil
}

// StoreKey stores an encryption key to HashiCorp Vault
func (vp *VaultProvider) StoreKey(ctx context.Context, key *EncryptionKey) error {
	path := fmt.Sprintf("%s/keys/%s", vp.config.MountPath, key.ID)
	
	data := map[string]interface{}{
		"id":          key.ID,
		"algorithm":   key.Algorithm,
		"key_data":    encodeKeyData(key.KeyData),
		"key_version": key.KeyVersion,
		"purpose":     key.Purpose,
		"status":      string(key.Status),
		"created_at":  key.CreatedAt.Format(time.RFC3339),
		"metadata":    key.Metadata,
	}

	if key.ExpiresAt != nil {
		data["expires_at"] = key.ExpiresAt.Format(time.RFC3339)
	}

	if key.RotatedAt != nil {
		data["rotated_at"] = key.RotatedAt.Format(time.RFC3339)
	}

	if err := vp.client.Write(ctx, path, data); err != nil {
		return fmt.Errorf("failed to write key to Vault: %w", err)
	}

	vp.logger.Debug("Key stored to Vault",
		zap.String("key_id", key.ID),
		zap.String("path", path))

	return nil
}

// RetrieveKey retrieves an encryption key from HashiCorp Vault
func (vp *VaultProvider) RetrieveKey(ctx context.Context, keyID string) (*EncryptionKey, error) {
	path := fmt.Sprintf("%s/keys/%s", vp.config.MountPath, keyID)
	
	data, err := vp.client.Read(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key from Vault: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Parse the response
	key, err := parseVaultKeyResponse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Vault response: %w", err)
	}

	vp.logger.Debug("Key retrieved from Vault",
		zap.String("key_id", keyID))

	return key, nil
}

// ListKeys lists all encryption keys in HashiCorp Vault
func (vp *VaultProvider) ListKeys(ctx context.Context) ([]*EncryptionKey, error) {
	path := fmt.Sprintf("%s/keys", vp.config.MountPath)
	
	keyIDs, err := vp.client.List(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from Vault: %w", err)
	}

	var keys []*EncryptionKey
	for _, keyID := range keyIDs {
		key, err := vp.RetrieveKey(ctx, keyID)
		if err != nil {
			vp.logger.Warn("Failed to retrieve key during listing",
				zap.String("key_id", keyID),
				zap.Error(err))
			continue
		}
		keys = append(keys, key)
	}

	vp.logger.Debug("Listed keys from Vault",
		zap.Int("count", len(keys)))

	return keys, nil
}

// DeleteKey deletes an encryption key from HashiCorp Vault
func (vp *VaultProvider) DeleteKey(ctx context.Context, keyID string) error {
	path := fmt.Sprintf("%s/keys/%s", vp.config.MountPath, keyID)
	
	if err := vp.client.Delete(ctx, path); err != nil {
		return fmt.Errorf("failed to delete key from Vault: %w", err)
	}

	vp.logger.Debug("Key deleted from Vault",
		zap.String("key_id", keyID))

	return nil
}

// HealthCheck checks the health of the Vault provider
func (vp *VaultProvider) HealthCheck(ctx context.Context) error {
	return vp.client.Health(ctx)
}

// Helper functions

func encodeKeyData(data []byte) string {
	// Use base64 encoding for simplicity
	// In production, use more secure encoding
	encoded := make([]byte, len(data)*2)
	for i, b := range data {
		encoded[i*2] = b + 10
		encoded[i*2+1] = b + 20
	}
	return fmt.Sprintf("%x", encoded)
}

func decodeKeyData(encoded string) ([]byte, error) {
	// Decode the custom encoding
	if len(encoded)%2 != 0 {
		return nil, fmt.Errorf("invalid encoded data length")
	}

	var temp []byte
	for i := 0; i < len(encoded); i += 2 {
		var b byte
		if _, err := fmt.Sscanf(encoded[i:i+2], "%02x", &b); err != nil {
			return nil, fmt.Errorf("failed to decode hex: %w", err)
		}
		temp = append(temp, b)
	}

	data := make([]byte, len(temp)/2)
	for i := 0; i < len(data); i++ {
		data[i] = temp[i*2] - 10
	}

	return data, nil
}

func parseVaultKeyResponse(data map[string]interface{}) (*EncryptionKey, error) {
	key := &EncryptionKey{
		Metadata: make(map[string]string),
	}

	// Parse required fields
	if id, ok := data["id"].(string); ok {
		key.ID = id
	} else {
		return nil, fmt.Errorf("missing or invalid key ID")
	}

	if algorithm, ok := data["algorithm"].(string); ok {
		key.Algorithm = algorithm
	} else {
		return nil, fmt.Errorf("missing or invalid algorithm")
	}

	if encodedKeyData, ok := data["key_data"].(string); ok {
		keyData, err := decodeKeyData(encodedKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key data: %w", err)
		}
		key.KeyData = keyData
	} else {
		return nil, fmt.Errorf("missing or invalid key data")
	}

	if purpose, ok := data["purpose"].(string); ok {
		key.Purpose = purpose
	}

	if status, ok := data["status"].(string); ok {
		key.Status = KeyStatus(status)
	}

	if version, ok := data["key_version"].(float64); ok {
		key.KeyVersion = int(version)
	}

	// Parse timestamps
	if createdAtStr, ok := data["created_at"].(string); ok {
		if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			key.CreatedAt = createdAt
		}
	}

	if expiresAtStr, ok := data["expires_at"].(string); ok {
		if expiresAt, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
			key.ExpiresAt = &expiresAt
		}
	}

	if rotatedAtStr, ok := data["rotated_at"].(string); ok {
		if rotatedAt, err := time.Parse(time.RFC3339, rotatedAtStr); err == nil {
			key.RotatedAt = &rotatedAt
		}
	}

	// Parse metadata
	if metadata, ok := data["metadata"].(map[string]interface{}); ok {
		for k, v := range metadata {
			if strVal, ok := v.(string); ok {
				key.Metadata[k] = strVal
			}
		}
	}

	return key, nil
}

// createVaultClient creates a Vault client (placeholder implementation)
func createVaultClient(config VaultConfig) (VaultClient, error) {
	// This would be implemented using the actual HashiCorp Vault client library
	// For now, return a mock client
	return &MockVaultClient{}, nil
}

// MockVaultClient is a mock implementation for development
type MockVaultClient struct {
	data map[string]map[string]interface{}
	mu   sync.RWMutex
}

func (m *MockVaultClient) Write(ctx context.Context, path string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.data == nil {
		m.data = make(map[string]map[string]interface{})
	}
	m.data[path] = data
	return nil
}

func (m *MockVaultClient) Read(ctx context.Context, path string) (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.data == nil {
		return nil, fmt.Errorf("path not found: %s", path)
	}
	
	data, exists := m.data[path]
	if !exists {
		return nil, fmt.Errorf("path not found: %s", path)
	}
	
	return data, nil
}

func (m *MockVaultClient) Delete(ctx context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.data == nil {
		return fmt.Errorf("path not found: %s", path)
	}
	
	delete(m.data, path)
	return nil
}

func (m *MockVaultClient) List(ctx context.Context, path string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.data == nil {
		return nil, nil
	}
	
	var keys []string
	prefix := path + "/"
	for p := range m.data {
		if strings.HasPrefix(p, prefix) {
			key := strings.TrimPrefix(p, prefix)
			keys = append(keys, key)
		}
	}
	
	return keys, nil
}

func (m *MockVaultClient) Health(ctx context.Context) error {
	return nil
}

// CreateProvider creates a key provider based on configuration
func CreateProvider(config ProviderConfig, logger *zap.Logger) (KeyProvider, error) {
	switch config.Type {
	case "local":
		return NewLocalProvider(config.Local, logger)
	case "vault":
		return NewVaultProvider(config.Vault, logger)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.Type)
	}
}