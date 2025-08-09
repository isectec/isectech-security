package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"isectech/auth-service/domain/entity"
)

// UserRepository implements the user repository interface for PostgreSQL
type UserRepository struct {
	db *sqlx.DB
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

// Create creates a new user in the database
func (r *UserRepository) Create(ctx context.Context, user *entity.User) error {
	query := `
		INSERT INTO users (
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		) VALUES (
			:id, :tenant_id, :username, :email, :password_hash, :first_name, :last_name,
			:status, :security_clearance, :mfa_enabled, :mfa_enforced, :failed_attempts,
			:last_failed_attempt, :locked_until, :password_changed_at, :last_login_at,
			:last_login_ip, :created_at, :updated_at, :created_by, :updated_by
		)`

	_, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		if IsUniqueConstraintError(err) {
			return fmt.Errorf("user with username %s or email %s already exists", user.Username, user.Email)
		}
		return WrapSQLError(err, "create_user", query, user)
	}

	return nil
}

// GetByID retrieves a user by ID and tenant ID
func (r *UserRepository) GetByID(ctx context.Context, userID, tenantID uuid.UUID) (*entity.User, error) {
	var user entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE id = $1 AND tenant_id = $2`

	err := r.db.GetContext(ctx, &user, query, userID, tenantID)
	if err != nil {
		if IsNoRowsError(err) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, WrapSQLError(err, "get_user_by_id", query, userID, tenantID)
	}

	return &user, nil
}

// GetByUsername retrieves a user by username and tenant ID
func (r *UserRepository) GetByUsername(ctx context.Context, username string, tenantID uuid.UUID) (*entity.User, error) {
	var user entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE username = $1 AND tenant_id = $2`

	err := r.db.GetContext(ctx, &user, query, username, tenantID)
	if err != nil {
		if IsNoRowsError(err) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, WrapSQLError(err, "get_user_by_username", query, username, tenantID)
	}

	return &user, nil
}

// GetByEmail retrieves a user by email and tenant ID
func (r *UserRepository) GetByEmail(ctx context.Context, email string, tenantID uuid.UUID) (*entity.User, error) {
	var user entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE email = $1 AND tenant_id = $2`

	err := r.db.GetContext(ctx, &user, query, email, tenantID)
	if err != nil {
		if IsNoRowsError(err) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, WrapSQLError(err, "get_user_by_email", query, email, tenantID)
	}

	return &user, nil
}

// Update updates an existing user
func (r *UserRepository) Update(ctx context.Context, user *entity.User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users SET
			username = :username,
			email = :email,
			password_hash = :password_hash,
			first_name = :first_name,
			last_name = :last_name,
			status = :status,
			security_clearance = :security_clearance,
			mfa_enabled = :mfa_enabled,
			mfa_enforced = :mfa_enforced,
			failed_attempts = :failed_attempts,
			last_failed_attempt = :last_failed_attempt,
			locked_until = :locked_until,
			password_changed_at = :password_changed_at,
			last_login_at = :last_login_at,
			last_login_ip = :last_login_ip,
			updated_at = :updated_at,
			updated_by = :updated_by
		WHERE id = :id AND tenant_id = :tenant_id`

	result, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		if IsUniqueConstraintError(err) {
			return fmt.Errorf("username %s or email %s already exists", user.Username, user.Email)
		}
		return WrapSQLError(err, "update_user", query, user)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "update_user_check_rows", query, user)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or no changes made")
	}

	return nil
}

// Delete soft deletes a user by setting status to inactive
func (r *UserRepository) Delete(ctx context.Context, userID, tenantID uuid.UUID) error {
	query := `
		UPDATE users 
		SET status = 'INACTIVE', updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, userID, tenantID)
	if err != nil {
		return WrapSQLError(err, "delete_user", query, userID, tenantID)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "delete_user_check_rows", query, userID, tenantID)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// List retrieves a paginated list of users for a tenant
func (r *UserRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]entity.User, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND status != 'INACTIVE'`
	err := r.db.GetContext(ctx, &total, countQuery, tenantID)
	if err != nil {
		return nil, 0, WrapSQLError(err, "list_users_count", countQuery, tenantID)
	}

	// Get paginated results
	var users []entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE tenant_id = $1 AND status != 'INACTIVE'
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	err = r.db.SelectContext(ctx, &users, query, tenantID, limit, offset)
	if err != nil {
		return nil, 0, WrapSQLError(err, "list_users", query, tenantID, limit, offset)
	}

	return users, total, nil
}

// Search searches for users by username, email, or name
func (r *UserRepository) Search(ctx context.Context, tenantID uuid.UUID, searchTerm string, limit, offset int) ([]entity.User, int, error) {
	searchPattern := "%" + searchTerm + "%"

	// Get total count
	var total int
	countQuery := `
		SELECT COUNT(*) FROM users 
		WHERE tenant_id = $1 AND status != 'INACTIVE'
		AND (username ILIKE $2 OR email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2)`

	err := r.db.GetContext(ctx, &total, countQuery, tenantID, searchPattern)
	if err != nil {
		return nil, 0, WrapSQLError(err, "search_users_count", countQuery, tenantID, searchPattern)
	}

	// Get paginated results
	var users []entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE tenant_id = $1 AND status != 'INACTIVE'
		AND (username ILIKE $2 OR email ILIKE $2 OR first_name ILIKE $2 OR last_name ILIKE $2)
		ORDER BY 
			CASE 
				WHEN username ILIKE $2 THEN 1
				WHEN email ILIKE $2 THEN 2
				WHEN first_name ILIKE $2 THEN 3
				WHEN last_name ILIKE $2 THEN 4
				ELSE 5
			END,
			created_at DESC
		LIMIT $3 OFFSET $4`

	err = r.db.SelectContext(ctx, &users, query, tenantID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, WrapSQLError(err, "search_users", query, tenantID, searchPattern, limit, offset)
	}

	return users, total, nil
}

// GetBySecurityClearance retrieves users by security clearance level
func (r *UserRepository) GetBySecurityClearance(ctx context.Context, tenantID uuid.UUID, clearance entity.SecurityClearanceLevel) ([]entity.User, error) {
	var users []entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE tenant_id = $1 AND security_clearance = $2 AND status = 'ACTIVE'
		ORDER BY created_at DESC`

	err := r.db.SelectContext(ctx, &users, query, tenantID, clearance)
	if err != nil {
		return nil, WrapSQLError(err, "get_users_by_clearance", query, tenantID, clearance)
	}

	return users, nil
}

// GetLockedUsers retrieves all currently locked users
func (r *UserRepository) GetLockedUsers(ctx context.Context, tenantID uuid.UUID) ([]entity.User, error) {
	var users []entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE tenant_id = $1 AND (status = 'LOCKED' OR locked_until > NOW())
		ORDER BY locked_until DESC NULLS LAST`

	err := r.db.SelectContext(ctx, &users, query, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_locked_users", query, tenantID)
	}

	return users, nil
}

// GetMFAEnabledUsers retrieves all users with MFA enabled
func (r *UserRepository) GetMFAEnabledUsers(ctx context.Context, tenantID uuid.UUID) ([]entity.User, error) {
	var users []entity.User
	query := `
		SELECT 
			id, tenant_id, username, email, password_hash, first_name, last_name,
			status, security_clearance, mfa_enabled, mfa_enforced, failed_attempts,
			last_failed_attempt, locked_until, password_changed_at, last_login_at,
			last_login_ip, created_at, updated_at, created_by, updated_by
		FROM users 
		WHERE tenant_id = $1 AND (mfa_enabled = true OR mfa_enforced = true) AND status = 'ACTIVE'
		ORDER BY created_at DESC`

	err := r.db.SelectContext(ctx, &users, query, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_mfa_enabled_users", query, tenantID)
	}

	return users, nil
}

// UpdateLastLogin updates the last login information for a user
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID, tenantID uuid.UUID, ipAddress string) error {
	query := `
		UPDATE users 
		SET last_login_at = NOW(), last_login_ip = $3, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, userID, tenantID, ipAddress)
	if err != nil {
		return WrapSQLError(err, "update_last_login", query, userID, tenantID, ipAddress)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "update_last_login_check_rows", query, userID, tenantID, ipAddress)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdatePasswordHash updates the password hash for a user
func (r *UserRepository) UpdatePasswordHash(ctx context.Context, userID, tenantID uuid.UUID, passwordHash string) error {
	query := `
		UPDATE users 
		SET password_hash = $3, password_changed_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, userID, tenantID, passwordHash)
	if err != nil {
		return WrapSQLError(err, "update_password_hash", query, userID, tenantID)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "update_password_hash_check_rows", query, userID, tenantID)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// IncrementFailedAttempts increments the failed login attempts for a user
func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, userID, tenantID uuid.UUID) error {
	query := `
		UPDATE users 
		SET 
			failed_attempts = failed_attempts + 1,
			last_failed_attempt = NOW(),
			locked_until = CASE 
				WHEN failed_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes' * (failed_attempts + 1 - 4)
				ELSE locked_until
			END,
			status = CASE 
				WHEN failed_attempts + 1 >= 10 THEN 'LOCKED'
				ELSE status
			END,
			updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, userID, tenantID)
	if err != nil {
		return WrapSQLError(err, "increment_failed_attempts", query, userID, tenantID)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "increment_failed_attempts_check_rows", query, userID, tenantID)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ResetFailedAttempts resets the failed login attempts for a user
func (r *UserRepository) ResetFailedAttempts(ctx context.Context, userID, tenantID uuid.UUID) error {
	query := `
		UPDATE users 
		SET 
			failed_attempts = 0,
			last_failed_attempt = NULL,
			locked_until = NULL,
			status = CASE 
				WHEN status = 'LOCKED' AND failed_attempts > 0 THEN 'ACTIVE'
				ELSE status
			END,
			updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, userID, tenantID)
	if err != nil {
		return WrapSQLError(err, "reset_failed_attempts", query, userID, tenantID)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return WrapSQLError(err, "reset_failed_attempts_check_rows", query, userID, tenantID)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetUserStats returns user statistics for a tenant
func (r *UserRepository) GetUserStats(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	query := `
		SELECT 
			COUNT(*) as total_users,
			COUNT(CASE WHEN status = 'ACTIVE' THEN 1 END) as active_users,
			COUNT(CASE WHEN status = 'INACTIVE' THEN 1 END) as inactive_users,
			COUNT(CASE WHEN status = 'LOCKED' OR locked_until > NOW() THEN 1 END) as locked_users,
			COUNT(CASE WHEN status = 'SUSPENDED' THEN 1 END) as suspended_users,
			COUNT(CASE WHEN mfa_enabled = true OR mfa_enforced = true THEN 1 END) as mfa_enabled_users,
			COUNT(CASE WHEN security_clearance = 'TOP_SECRET' THEN 1 END) as top_secret_users,
			COUNT(CASE WHEN security_clearance = 'SECRET' THEN 1 END) as secret_users,
			COUNT(CASE WHEN security_clearance = 'CONFIDENTIAL' THEN 1 END) as confidential_users,
			COUNT(CASE WHEN security_clearance = 'UNCLASSIFIED' THEN 1 END) as unclassified_users,
			COUNT(CASE WHEN last_login_at > NOW() - INTERVAL '24 hours' THEN 1 END) as active_24h,
			COUNT(CASE WHEN last_login_at > NOW() - INTERVAL '7 days' THEN 1 END) as active_7d,
			COUNT(CASE WHEN last_login_at > NOW() - INTERVAL '30 days' THEN 1 END) as active_30d
		FROM users 
		WHERE tenant_id = $1`

	var stats struct {
		TotalUsers        int `db:"total_users"`
		ActiveUsers       int `db:"active_users"`
		InactiveUsers     int `db:"inactive_users"`
		LockedUsers       int `db:"locked_users"`
		SuspendedUsers    int `db:"suspended_users"`
		MFAEnabledUsers   int `db:"mfa_enabled_users"`
		TopSecretUsers    int `db:"top_secret_users"`
		SecretUsers       int `db:"secret_users"`
		ConfidentialUsers int `db:"confidential_users"`
		UnclassifiedUsers int `db:"unclassified_users"`
		Active24h         int `db:"active_24h"`
		Active7d          int `db:"active_7d"`
		Active30d         int `db:"active_30d"`
	}

	err := r.db.GetContext(ctx, &stats, query, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_user_stats", query, tenantID)
	}

	return map[string]interface{}{
		"total_users":        stats.TotalUsers,
		"active_users":       stats.ActiveUsers,
		"inactive_users":     stats.InactiveUsers,
		"locked_users":       stats.LockedUsers,
		"suspended_users":    stats.SuspendedUsers,
		"mfa_enabled_users":  stats.MFAEnabledUsers,
		"top_secret_users":   stats.TopSecretUsers,
		"secret_users":       stats.SecretUsers,
		"confidential_users": stats.ConfidentialUsers,
		"unclassified_users": stats.UnclassifiedUsers,
		"active_24h":         stats.Active24h,
		"active_7d":          stats.Active7d,
		"active_30d":         stats.Active30d,
	}, nil
}
