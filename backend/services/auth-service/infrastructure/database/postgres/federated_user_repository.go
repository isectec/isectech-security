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

// FederatedUserRepository handles persistence operations for federated users
type FederatedUserRepository struct {
	db *sqlx.DB
}

// NewFederatedUserRepository creates a new federated user repository
func NewFederatedUserRepository(db *sqlx.DB) *FederatedUserRepository {
	return &FederatedUserRepository{db: db}
}

// Create creates a new federated user link
func (r *FederatedUserRepository) Create(ctx context.Context, federatedUser *entity.FederatedUser) error {
	claimsJSON, err := json.Marshal(federatedUser.Claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	attributesJSON, err := json.Marshal(federatedUser.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	query := `
		INSERT INTO federated_users (
			id, user_id, tenant_id, provider_id,
			external_id, external_username, external_email,
			claims, attributes,
			last_login_at, last_token_at, token_expiration,
			mapped_roles, mapped_clearance,
			is_active, login_count,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9,
			$10, $11, $12,
			$13, $14,
			$15, $16,
			$17, $18
		)`

	_, err = r.db.ExecContext(ctx, query,
		federatedUser.ID, federatedUser.UserID, federatedUser.TenantID, federatedUser.ProviderID,
		federatedUser.ExternalID, federatedUser.ExternalUsername, federatedUser.ExternalEmail,
		claimsJSON, attributesJSON,
		federatedUser.LastLoginAt, federatedUser.LastTokenAt, federatedUser.TokenExpiration,
		pq.Array(federatedUser.MappedRoles), federatedUser.MappedClearance,
		federatedUser.IsActive, federatedUser.LoginCount,
		federatedUser.CreatedAt, federatedUser.UpdatedAt,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				if pqErr.Constraint == "federated_users_provider_external_unique" {
					return fmt.Errorf("external user already linked to this provider")
				}
				if pqErr.Constraint == "federated_users_tenant_user_provider_unique" {
					return fmt.Errorf("user already linked to this provider")
				}
			case "23503": // foreign_key_violation
				return fmt.Errorf("invalid user ID, tenant ID, or provider ID")
			}
		}
		return fmt.Errorf("failed to create federated user: %w", err)
	}

	return nil
}

// Update updates an existing federated user
func (r *FederatedUserRepository) Update(ctx context.Context, federatedUser *entity.FederatedUser) error {
	claimsJSON, err := json.Marshal(federatedUser.Claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	attributesJSON, err := json.Marshal(federatedUser.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	query := `
		UPDATE federated_users SET
			external_username = $3, external_email = $4,
			claims = $5, attributes = $6,
			last_login_at = $7, last_token_at = $8, token_expiration = $9,
			mapped_roles = $10, mapped_clearance = $11,
			is_active = $12, login_count = $13,
			updated_at = $14
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query,
		federatedUser.ID, federatedUser.TenantID,
		federatedUser.ExternalUsername, federatedUser.ExternalEmail,
		claimsJSON, attributesJSON,
		federatedUser.LastLoginAt, federatedUser.LastTokenAt, federatedUser.TokenExpiration,
		pq.Array(federatedUser.MappedRoles), federatedUser.MappedClearance,
		federatedUser.IsActive, federatedUser.LoginCount,
		federatedUser.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update federated user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("federated user not found")
	}

	return nil
}

// GetByExternalID retrieves a federated user by external ID and provider
func (r *FederatedUserRepository) GetByExternalID(ctx context.Context, externalID string, providerID, tenantID uuid.UUID) (*entity.FederatedUser, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, provider_id,
			external_id, external_username, external_email,
			claims, attributes,
			last_login_at, last_token_at, token_expiration,
			mapped_roles, mapped_clearance,
			is_active, login_count,
			created_at, updated_at
		FROM federated_users 
		WHERE external_id = $1 AND provider_id = $2 AND tenant_id = $3`

	row := r.db.QueryRowContext(ctx, query, externalID, providerID, tenantID)

	federatedUser := &entity.FederatedUser{}
	var claimsJSON, attributesJSON []byte

	err := row.Scan(
		&federatedUser.ID, &federatedUser.UserID, &federatedUser.TenantID, &federatedUser.ProviderID,
		&federatedUser.ExternalID, &federatedUser.ExternalUsername, &federatedUser.ExternalEmail,
		&claimsJSON, &attributesJSON,
		&federatedUser.LastLoginAt, &federatedUser.LastTokenAt, &federatedUser.TokenExpiration,
		pq.Array(&federatedUser.MappedRoles), &federatedUser.MappedClearance,
		&federatedUser.IsActive, &federatedUser.LoginCount,
		&federatedUser.CreatedAt, &federatedUser.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("federated user not found")
		}
		return nil, fmt.Errorf("failed to get federated user: %w", err)
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(claimsJSON, &federatedUser.Claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	if err := json.Unmarshal(attributesJSON, &federatedUser.Attributes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attributes: %w", err)
	}

	return federatedUser, nil
}

// GetByUserID retrieves all federated users for a user
func (r *FederatedUserRepository) GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) ([]*entity.FederatedUser, error) {
	query := `
		SELECT 
			fu.id, fu.user_id, fu.tenant_id, fu.provider_id,
			fu.external_id, fu.external_username, fu.external_email,
			fu.claims, fu.attributes,
			fu.last_login_at, fu.last_token_at, fu.token_expiration,
			fu.mapped_roles, fu.mapped_clearance,
			fu.is_active, fu.login_count,
			fu.created_at, fu.updated_at,
			ip.name as provider_name, ip.type as provider_type
		FROM federated_users fu
		JOIN identity_providers ip ON fu.provider_id = ip.id
		WHERE fu.user_id = $1 AND fu.tenant_id = $2
		ORDER BY fu.created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get federated users by user ID: %w", err)
	}
	defer rows.Close()

	var federatedUsers []*entity.FederatedUser

	for rows.Next() {
		federatedUser := &entity.FederatedUser{}
		var claimsJSON, attributesJSON []byte
		var providerName string
		var providerType entity.IdentityProviderType

		err := rows.Scan(
			&federatedUser.ID, &federatedUser.UserID, &federatedUser.TenantID, &federatedUser.ProviderID,
			&federatedUser.ExternalID, &federatedUser.ExternalUsername, &federatedUser.ExternalEmail,
			&claimsJSON, &attributesJSON,
			&federatedUser.LastLoginAt, &federatedUser.LastTokenAt, &federatedUser.TokenExpiration,
			pq.Array(&federatedUser.MappedRoles), &federatedUser.MappedClearance,
			&federatedUser.IsActive, &federatedUser.LoginCount,
			&federatedUser.CreatedAt, &federatedUser.UpdatedAt,
			&providerName, &providerType,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan federated user: %w", err)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(claimsJSON, &federatedUser.Claims); err != nil {
			return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
		}

		if err := json.Unmarshal(attributesJSON, &federatedUser.Attributes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attributes: %w", err)
		}

		federatedUsers = append(federatedUsers, federatedUser)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over federated users: %w", err)
	}

	return federatedUsers, nil
}

// GetByProviderID retrieves all federated users for a provider
func (r *FederatedUserRepository) GetByProviderID(ctx context.Context, providerID, tenantID uuid.UUID) ([]*entity.FederatedUser, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, provider_id,
			external_id, external_username, external_email,
			claims, attributes,
			last_login_at, last_token_at, token_expiration,
			mapped_roles, mapped_clearance,
			is_active, login_count,
			created_at, updated_at
		FROM federated_users 
		WHERE provider_id = $1 AND tenant_id = $2
		ORDER BY created_at ASC`

	rows, err := r.db.QueryContext(ctx, query, providerID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get federated users by provider ID: %w", err)
	}
	defer rows.Close()

	var federatedUsers []*entity.FederatedUser

	for rows.Next() {
		federatedUser := &entity.FederatedUser{}
		var claimsJSON, attributesJSON []byte

		err := rows.Scan(
			&federatedUser.ID, &federatedUser.UserID, &federatedUser.TenantID, &federatedUser.ProviderID,
			&federatedUser.ExternalID, &federatedUser.ExternalUsername, &federatedUser.ExternalEmail,
			&claimsJSON, &attributesJSON,
			&federatedUser.LastLoginAt, &federatedUser.LastTokenAt, &federatedUser.TokenExpiration,
			pq.Array(&federatedUser.MappedRoles), &federatedUser.MappedClearance,
			&federatedUser.IsActive, &federatedUser.LoginCount,
			&federatedUser.CreatedAt, &federatedUser.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan federated user: %w", err)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(claimsJSON, &federatedUser.Claims); err != nil {
			return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
		}

		if err := json.Unmarshal(attributesJSON, &federatedUser.Attributes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attributes: %w", err)
		}

		federatedUsers = append(federatedUsers, federatedUser)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over federated users: %w", err)
	}

	return federatedUsers, nil
}

// LinkUser creates a link between an existing user and an external provider account
func (r *FederatedUserRepository) LinkUser(ctx context.Context, userID, providerID, tenantID uuid.UUID, externalID string) error {
	// First check if the link already exists
	existingQuery := `
		SELECT id FROM federated_users 
		WHERE user_id = $1 AND provider_id = $2 AND tenant_id = $3`

	var existingID uuid.UUID
	err := r.db.QueryRowContext(ctx, existingQuery, userID, providerID, tenantID).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("user already linked to this provider")
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check existing link: %w", err)
	}

	// Create the link
	federatedUser := &entity.FederatedUser{
		ID:              uuid.New(),
		UserID:          userID,
		TenantID:        tenantID,
		ProviderID:      providerID,
		ExternalID:      externalID,
		Claims:          make(map[string]interface{}),
		Attributes:      make(map[string]string),
		MappedRoles:     make([]string, 0),
		MappedClearance: entity.SecurityClearanceUnclassified,
		IsActive:        true,
		LoginCount:      0,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	return r.Create(ctx, federatedUser)
}

// UnlinkUser removes the link between a user and a provider
func (r *FederatedUserRepository) UnlinkUser(ctx context.Context, userID, providerID, tenantID uuid.UUID) error {
	query := `DELETE FROM federated_users WHERE user_id = $1 AND provider_id = $2 AND tenant_id = $3`

	result, err := r.db.ExecContext(ctx, query, userID, providerID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to unlink user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("federated user link not found")
	}

	return nil
}

// UpdateLoginInfo updates login-related information for a federated user
func (r *FederatedUserRepository) UpdateLoginInfo(ctx context.Context, federatedUserID, tenantID uuid.UUID, claims map[string]interface{}, attributes map[string]string) error {
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	attributesJSON, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	query := `
		UPDATE federated_users SET
			claims = $3,
			attributes = $4,
			last_login_at = $5,
			login_count = login_count + 1,
			updated_at = $6
		WHERE id = $1 AND tenant_id = $2`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query,
		federatedUserID, tenantID,
		claimsJSON, attributesJSON,
		now, now,
	)

	if err != nil {
		return fmt.Errorf("failed to update federated user login info: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("federated user not found")
	}

	return nil
}

// UpdateMappings updates role and clearance mappings for a federated user
func (r *FederatedUserRepository) UpdateMappings(ctx context.Context, federatedUserID, tenantID uuid.UUID, mappedRoles []string, mappedClearance entity.SecurityClearanceLevel) error {
	query := `
		UPDATE federated_users SET
			mapped_roles = $3,
			mapped_clearance = $4,
			updated_at = $5
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query,
		federatedUserID, tenantID,
		pq.Array(mappedRoles), mappedClearance,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to update federated user mappings: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("federated user not found")
	}

	return nil
}

// SetActive sets the active status of a federated user
func (r *FederatedUserRepository) SetActive(ctx context.Context, federatedUserID, tenantID uuid.UUID, isActive bool) error {
	query := `
		UPDATE federated_users SET
			is_active = $3,
			updated_at = $4
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, federatedUserID, tenantID, isActive, time.Now())
	if err != nil {
		return fmt.Errorf("failed to set federated user active status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("federated user not found")
	}

	return nil
}

// GetByEmail retrieves federated users by external email
func (r *FederatedUserRepository) GetByEmail(ctx context.Context, email string, tenantID uuid.UUID) ([]*entity.FederatedUser, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, provider_id,
			external_id, external_username, external_email,
			claims, attributes,
			last_login_at, last_token_at, token_expiration,
			mapped_roles, mapped_clearance,
			is_active, login_count,
			created_at, updated_at
		FROM federated_users 
		WHERE external_email = $1 AND tenant_id = $2 AND is_active = true
		ORDER BY last_login_at DESC`

	rows, err := r.db.QueryContext(ctx, query, email, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get federated users by email: %w", err)
	}
	defer rows.Close()

	var federatedUsers []*entity.FederatedUser

	for rows.Next() {
		federatedUser := &entity.FederatedUser{}
		var claimsJSON, attributesJSON []byte

		err := rows.Scan(
			&federatedUser.ID, &federatedUser.UserID, &federatedUser.TenantID, &federatedUser.ProviderID,
			&federatedUser.ExternalID, &federatedUser.ExternalUsername, &federatedUser.ExternalEmail,
			&claimsJSON, &attributesJSON,
			&federatedUser.LastLoginAt, &federatedUser.LastTokenAt, &federatedUser.TokenExpiration,
			pq.Array(&federatedUser.MappedRoles), &federatedUser.MappedClearance,
			&federatedUser.IsActive, &federatedUser.LoginCount,
			&federatedUser.CreatedAt, &federatedUser.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan federated user: %w", err)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(claimsJSON, &federatedUser.Claims); err != nil {
			return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
		}

		if err := json.Unmarshal(attributesJSON, &federatedUser.Attributes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attributes: %w", err)
		}

		federatedUsers = append(federatedUsers, federatedUser)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over federated users: %w", err)
	}

	return federatedUsers, nil
}

// CleanupInactiveUsers removes federated users that haven't logged in for a specified duration
func (r *FederatedUserRepository) CleanupInactiveUsers(ctx context.Context, inactiveDuration time.Duration) (int64, error) {
	query := `
		DELETE FROM federated_users 
		WHERE last_login_at < $1 OR (last_login_at IS NULL AND created_at < $1)`

	cutoffTime := time.Now().Add(-inactiveDuration)
	result, err := r.db.ExecContext(ctx, query, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup inactive federated users: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}
