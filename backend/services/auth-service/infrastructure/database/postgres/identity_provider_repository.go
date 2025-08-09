package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"isectech/auth-service/domain/entity"
)

// IdentityProviderRepository handles persistence operations for identity providers
type IdentityProviderRepository struct {
	db *sqlx.DB
}

// NewIdentityProviderRepository creates a new identity provider repository
func NewIdentityProviderRepository(db *sqlx.DB) *IdentityProviderRepository {
	return &IdentityProviderRepository{db: db}
}

// Create creates a new identity provider
func (r *IdentityProviderRepository) Create(ctx context.Context, provider *entity.IdentityProvider) error {
	configJSON, err := json.Marshal(provider.Configuration)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	metadataJSON, err := json.Marshal(provider.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	attributeMappingJSON, err := json.Marshal(provider.AttributeMapping)
	if err != nil {
		return fmt.Errorf("failed to marshal attribute mapping: %w", err)
	}

	query := `
		INSERT INTO identity_providers (
			id, tenant_id, name, display_name, description, type, status,
			configuration, metadata, certificate, private_key,
			login_url, logout_url, callback_url, metadata_url,
			is_default, priority, enable_jit, attribute_mapping,
			require_secure_cert, validate_signature, encrypt_assertions,
			session_timeout, force_logout,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18, $19,
			$20, $21, $22,
			$23, $24,
			$25, $26, $27, $28
		)`

	_, err = r.db.ExecContext(ctx, query,
		provider.ID, provider.TenantID, provider.Name, provider.DisplayName, provider.Description,
		provider.Type, provider.Status,
		configJSON, metadataJSON, provider.Certificate, provider.PrivateKey,
		provider.LoginURL, provider.LogoutURL, provider.CallbackURL, provider.MetadataURL,
		provider.IsDefault, provider.Priority, provider.EnableJIT, attributeMappingJSON,
		provider.RequireSecureCert, provider.ValidateSignature, provider.EncryptAssertions,
		provider.SessionTimeout, provider.ForceLogout,
		provider.CreatedAt, provider.UpdatedAt, provider.CreatedBy, provider.UpdatedBy,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				if pqErr.Constraint == "identity_providers_tenant_name_unique" {
					return fmt.Errorf("provider name already exists for this tenant")
				}
				if pqErr.Constraint == "identity_providers_one_default_per_tenant" {
					return fmt.Errorf("a default provider of this type already exists for this tenant")
				}
			case "23503": // foreign_key_violation
				return fmt.Errorf("invalid tenant ID")
			}
		}
		return fmt.Errorf("failed to create identity provider: %w", err)
	}

	return nil
}

// Update updates an existing identity provider
func (r *IdentityProviderRepository) Update(ctx context.Context, provider *entity.IdentityProvider) error {
	configJSON, err := json.Marshal(provider.Configuration)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	metadataJSON, err := json.Marshal(provider.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	attributeMappingJSON, err := json.Marshal(provider.AttributeMapping)
	if err != nil {
		return fmt.Errorf("failed to marshal attribute mapping: %w", err)
	}

	query := `
		UPDATE identity_providers SET
			name = $3, display_name = $4, description = $5, status = $6,
			configuration = $7, metadata = $8, certificate = $9, private_key = $10,
			login_url = $11, logout_url = $12, callback_url = $13, metadata_url = $14,
			is_default = $15, priority = $16, enable_jit = $17, attribute_mapping = $18,
			require_secure_cert = $19, validate_signature = $20, encrypt_assertions = $21,
			session_timeout = $22, force_logout = $23,
			updated_at = $24, updated_by = $25
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query,
		provider.ID, provider.TenantID,
		provider.Name, provider.DisplayName, provider.Description, provider.Status,
		configJSON, metadataJSON, provider.Certificate, provider.PrivateKey,
		provider.LoginURL, provider.LogoutURL, provider.CallbackURL, provider.MetadataURL,
		provider.IsDefault, provider.Priority, provider.EnableJIT, attributeMappingJSON,
		provider.RequireSecureCert, provider.ValidateSignature, provider.EncryptAssertions,
		provider.SessionTimeout, provider.ForceLogout,
		provider.UpdatedAt, provider.UpdatedBy,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				if pqErr.Constraint == "identity_providers_tenant_name_unique" {
					return fmt.Errorf("provider name already exists for this tenant")
				}
				if pqErr.Constraint == "identity_providers_one_default_per_tenant" {
					return fmt.Errorf("a default provider of this type already exists for this tenant")
				}
			}
		}
		return fmt.Errorf("failed to update identity provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("identity provider not found")
	}

	return nil
}

// Delete deletes an identity provider
func (r *IdentityProviderRepository) Delete(ctx context.Context, providerID, tenantID uuid.UUID) error {
	query := `DELETE FROM identity_providers WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, providerID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete identity provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("identity provider not found")
	}

	return nil
}

// GetByID retrieves an identity provider by ID
func (r *IdentityProviderRepository) GetByID(ctx context.Context, providerID, tenantID uuid.UUID) (*entity.IdentityProvider, error) {
	query := `
		SELECT 
			id, tenant_id, name, display_name, description, type, status,
			configuration, metadata, certificate, private_key,
			login_url, logout_url, callback_url, metadata_url,
			is_default, priority, enable_jit, attribute_mapping,
			require_secure_cert, validate_signature, encrypt_assertions,
			session_timeout, force_logout,
			last_used_at, last_error_at, last_error,
			usage_count, error_count,
			created_at, updated_at, created_by, updated_by
		FROM identity_providers 
		WHERE id = $1 AND tenant_id = $2`

	row := r.db.QueryRowContext(ctx, query, providerID, tenantID)

	provider := &entity.IdentityProvider{}
	var configJSON, metadataJSON, attributeMappingJSON []byte
	var privateKey sql.NullString

	err := row.Scan(
		&provider.ID, &provider.TenantID, &provider.Name, &provider.DisplayName, &provider.Description,
		&provider.Type, &provider.Status,
		&configJSON, &metadataJSON, &provider.Certificate, &privateKey,
		&provider.LoginURL, &provider.LogoutURL, &provider.CallbackURL, &provider.MetadataURL,
		&provider.IsDefault, &provider.Priority, &provider.EnableJIT, &attributeMappingJSON,
		&provider.RequireSecureCert, &provider.ValidateSignature, &provider.EncryptAssertions,
		&provider.SessionTimeout, &provider.ForceLogout,
		&provider.LastUsedAt, &provider.LastErrorAt, &provider.LastError,
		&provider.UsageCount, &provider.ErrorCount,
		&provider.CreatedAt, &provider.UpdatedAt, &provider.CreatedBy, &provider.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("identity provider not found")
		}
		return nil, fmt.Errorf("failed to get identity provider: %w", err)
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(configJSON, &provider.Configuration); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	if err := json.Unmarshal(metadataJSON, &provider.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if err := json.Unmarshal(attributeMappingJSON, &provider.AttributeMapping); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attribute mapping: %w", err)
	}

	if privateKey.Valid {
		provider.PrivateKey = privateKey.String
	}

	return provider, nil
}

// ListByTenant retrieves all identity providers for a tenant
func (r *IdentityProviderRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]*entity.IdentityProvider, error) {
	query := `
		SELECT 
			id, tenant_id, name, display_name, description, type, status,
			configuration, metadata, certificate, private_key,
			login_url, logout_url, callback_url, metadata_url,
			is_default, priority, enable_jit, attribute_mapping,
			require_secure_cert, validate_signature, encrypt_assertions,
			session_timeout, force_logout,
			last_used_at, last_error_at, last_error,
			usage_count, error_count,
			created_at, updated_at, created_by, updated_by
		FROM identity_providers 
		WHERE tenant_id = $1`

	args := []interface{}{tenantID}

	if activeOnly {
		query += ` AND status = 'active'`
	}

	query += ` ORDER BY priority ASC, name ASC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list identity providers: %w", err)
	}
	defer rows.Close()

	var providers []*entity.IdentityProvider

	for rows.Next() {
		provider := &entity.IdentityProvider{}
		var configJSON, metadataJSON, attributeMappingJSON []byte
		var privateKey sql.NullString

		err := rows.Scan(
			&provider.ID, &provider.TenantID, &provider.Name, &provider.DisplayName, &provider.Description,
			&provider.Type, &provider.Status,
			&configJSON, &metadataJSON, &provider.Certificate, &privateKey,
			&provider.LoginURL, &provider.LogoutURL, &provider.CallbackURL, &provider.MetadataURL,
			&provider.IsDefault, &provider.Priority, &provider.EnableJIT, &attributeMappingJSON,
			&provider.RequireSecureCert, &provider.ValidateSignature, &provider.EncryptAssertions,
			&provider.SessionTimeout, &provider.ForceLogout,
			&provider.LastUsedAt, &provider.LastErrorAt, &provider.LastError,
			&provider.UsageCount, &provider.ErrorCount,
			&provider.CreatedAt, &provider.UpdatedAt, &provider.CreatedBy, &provider.UpdatedBy,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan identity provider: %w", err)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(configJSON, &provider.Configuration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
		}

		if err := json.Unmarshal(metadataJSON, &provider.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		if err := json.Unmarshal(attributeMappingJSON, &provider.AttributeMapping); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute mapping: %w", err)
		}

		if privateKey.Valid {
			provider.PrivateKey = privateKey.String
		}

		providers = append(providers, provider)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over identity providers: %w", err)
	}

	return providers, nil
}

// GetByType retrieves identity providers by type for a tenant
func (r *IdentityProviderRepository) GetByType(ctx context.Context, tenantID uuid.UUID, providerType entity.IdentityProviderType) ([]*entity.IdentityProvider, error) {
	query := `
		SELECT 
			id, tenant_id, name, display_name, description, type, status,
			configuration, metadata, certificate, private_key,
			login_url, logout_url, callback_url, metadata_url,
			is_default, priority, enable_jit, attribute_mapping,
			require_secure_cert, validate_signature, encrypt_assertions,
			session_timeout, force_logout,
			last_used_at, last_error_at, last_error,
			usage_count, error_count,
			created_at, updated_at, created_by, updated_by
		FROM identity_providers 
		WHERE tenant_id = $1 AND type = $2
		ORDER BY priority ASC, name ASC`

	rows, err := r.db.QueryContext(ctx, query, tenantID, providerType)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity providers by type: %w", err)
	}
	defer rows.Close()

	var providers []*entity.IdentityProvider

	for rows.Next() {
		provider := &entity.IdentityProvider{}
		var configJSON, metadataJSON, attributeMappingJSON []byte
		var privateKey sql.NullString

		err := rows.Scan(
			&provider.ID, &provider.TenantID, &provider.Name, &provider.DisplayName, &provider.Description,
			&provider.Type, &provider.Status,
			&configJSON, &metadataJSON, &provider.Certificate, &privateKey,
			&provider.LoginURL, &provider.LogoutURL, &provider.CallbackURL, &provider.MetadataURL,
			&provider.IsDefault, &provider.Priority, &provider.EnableJIT, &attributeMappingJSON,
			&provider.RequireSecureCert, &provider.ValidateSignature, &provider.EncryptAssertions,
			&provider.SessionTimeout, &provider.ForceLogout,
			&provider.LastUsedAt, &provider.LastErrorAt, &provider.LastError,
			&provider.UsageCount, &provider.ErrorCount,
			&provider.CreatedAt, &provider.UpdatedAt, &provider.CreatedBy, &provider.UpdatedBy,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan identity provider: %w", err)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(configJSON, &provider.Configuration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
		}

		if err := json.Unmarshal(metadataJSON, &provider.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		if err := json.Unmarshal(attributeMappingJSON, &provider.AttributeMapping); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute mapping: %w", err)
		}

		if privateKey.Valid {
			provider.PrivateKey = privateKey.String
		}

		providers = append(providers, provider)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over identity providers: %w", err)
	}

	return providers, nil
}

// GetDefault retrieves the default identity provider for a tenant and type
func (r *IdentityProviderRepository) GetDefault(ctx context.Context, tenantID uuid.UUID, providerType entity.IdentityProviderType) (*entity.IdentityProvider, error) {
	query := `
		SELECT 
			id, tenant_id, name, display_name, description, type, status,
			configuration, metadata, certificate, private_key,
			login_url, logout_url, callback_url, metadata_url,
			is_default, priority, enable_jit, attribute_mapping,
			require_secure_cert, validate_signature, encrypt_assertions,
			session_timeout, force_logout,
			last_used_at, last_error_at, last_error,
			usage_count, error_count,
			created_at, updated_at, created_by, updated_by
		FROM identity_providers 
		WHERE tenant_id = $1 AND type = $2 AND is_default = true AND status = 'active'`

	row := r.db.QueryRowContext(ctx, query, tenantID, providerType)

	provider := &entity.IdentityProvider{}
	var configJSON, metadataJSON, attributeMappingJSON []byte
	var privateKey sql.NullString

	err := row.Scan(
		&provider.ID, &provider.TenantID, &provider.Name, &provider.DisplayName, &provider.Description,
		&provider.Type, &provider.Status,
		&configJSON, &metadataJSON, &provider.Certificate, &privateKey,
		&provider.LoginURL, &provider.LogoutURL, &provider.CallbackURL, &provider.MetadataURL,
		&provider.IsDefault, &provider.Priority, &provider.EnableJIT, &attributeMappingJSON,
		&provider.RequireSecureCert, &provider.ValidateSignature, &provider.EncryptAssertions,
		&provider.SessionTimeout, &provider.ForceLogout,
		&provider.LastUsedAt, &provider.LastErrorAt, &provider.LastError,
		&provider.UsageCount, &provider.ErrorCount,
		&provider.CreatedAt, &provider.UpdatedAt, &provider.CreatedBy, &provider.UpdatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no default identity provider found for type %s", providerType)
		}
		return nil, fmt.Errorf("failed to get default identity provider: %w", err)
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(configJSON, &provider.Configuration); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	if err := json.Unmarshal(metadataJSON, &provider.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if err := json.Unmarshal(attributeMappingJSON, &provider.AttributeMapping); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attribute mapping: %w", err)
	}

	if privateKey.Valid {
		provider.PrivateKey = privateKey.String
	}

	return provider, nil
}

// IncrementUsage increments the usage counter for a provider
func (r *IdentityProviderRepository) IncrementUsage(ctx context.Context, providerID, tenantID uuid.UUID) error {
	query := `
		UPDATE identity_providers 
		SET usage_count = usage_count + 1, last_used_at = $3
		WHERE id = $1 AND tenant_id = $2`

	_, err := r.db.ExecContext(ctx, query, providerID, tenantID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to increment provider usage: %w", err)
	}

	return nil
}

// IncrementError increments the error counter for a provider
func (r *IdentityProviderRepository) IncrementError(ctx context.Context, providerID, tenantID uuid.UUID, errorMsg string) error {
	query := `
		UPDATE identity_providers 
		SET error_count = error_count + 1, last_error_at = $3, last_error = $4
		WHERE id = $1 AND tenant_id = $2`

	_, err := r.db.ExecContext(ctx, query, providerID, tenantID, time.Now(), errorMsg)
	if err != nil {
		return fmt.Errorf("failed to increment provider error: %w", err)
	}

	return nil
}

// GetStatistics retrieves statistics for identity providers
func (r *IdentityProviderRepository) GetStatistics(ctx context.Context, tenantID uuid.UUID, providerID *uuid.UUID) ([]*ProviderStatistics, error) {
	query := `SELECT * FROM get_provider_stats($1, $2)`

	rows, err := r.db.QueryContext(ctx, query, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider statistics: %w", err)
	}
	defer rows.Close()

	var stats []*ProviderStatistics

	for rows.Next() {
		stat := &ProviderStatistics{}
		err := rows.Scan(
			&stat.ProviderID,
			&stat.ProviderName,
			&stat.ProviderType,
			&stat.TotalUsers,
			&stat.ActiveSessions,
			&stat.TotalLogins,
			&stat.LastLogin,
			&stat.ErrorRate,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan provider statistics: %w", err)
		}

		stats = append(stats, stat)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over provider statistics: %w", err)
	}

	return stats, nil
}

// ProviderStatistics represents provider usage statistics
type ProviderStatistics struct {
	ProviderID     uuid.UUID                   `json:"provider_id"`
	ProviderName   string                      `json:"provider_name"`
	ProviderType   entity.IdentityProviderType `json:"provider_type"`
	TotalUsers     int64                       `json:"total_users"`
	ActiveSessions int64                       `json:"active_sessions"`
	TotalLogins    int64                       `json:"total_logins"`
	LastLogin      *time.Time                  `json:"last_login,omitempty"`
	ErrorRate      float64                     `json:"error_rate"`
}
