package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// AuditRepository implements the audit repository interface for PostgreSQL
type AuditRepository struct {
	db *sqlx.DB
}

// NewAuditRepository creates a new PostgreSQL audit repository
func NewAuditRepository(db *sqlx.DB) *AuditRepository {
	return &AuditRepository{
		db: db,
	}
}

// LogMFAEvent logs an MFA audit event
func (r *AuditRepository) LogMFAEvent(ctx context.Context, event *service.MFAAuditEvent) error {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO mfa_audit_events (
			id, user_id, tenant_id, device_id, device_type, action, success,
			failure_reason, ip_address, user_agent, risk, created_at, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)`

	_, err = r.db.ExecContext(ctx, query,
		event.ID, event.UserID, event.TenantID, event.DeviceID, event.DeviceType,
		event.Action, event.Success, event.FailureReason, event.IPAddress,
		event.UserAgent, event.Risk, event.CreatedAt, metadataJSON,
	)

	if err != nil {
		return WrapSQLError(err, "log_mfa_event", query, event)
	}

	return nil
}

// LogAuthEvent logs an authentication audit event
func (r *AuditRepository) LogAuthEvent(ctx context.Context, event *entity.AuthenticationAttempt) error {
	riskFactorsJSON, err := json.Marshal(event.RiskFactors)
	if err != nil {
		return fmt.Errorf("failed to marshal risk factors: %w", err)
	}

	securityEventsJSON, err := json.Marshal(event.SecurityEvents)
	if err != nil {
		return fmt.Errorf("failed to marshal security events: %w", err)
	}

	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO authentication_attempts (
			id, user_id, tenant_id, username, ip_address, user_agent, attempt_type,
			success, failure_reason, mfa_required, mfa_verified, security_events,
			created_at, risk_score, risk_factors, requires_review, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
		)`

	_, err = r.db.ExecContext(ctx, query,
		event.ID, event.UserID, event.TenantID, event.Username, event.IPAddress,
		event.UserAgent, event.AttemptType, event.Success, event.FailureReason,
		event.MFARequired, event.MFAVerified, securityEventsJSON, event.CreatedAt,
		event.RiskScore, riskFactorsJSON, event.RequiresReview, metadataJSON,
	)

	if err != nil {
		return WrapSQLError(err, "log_auth_event", query, event)
	}

	return nil
}

// LogSecurityEvent logs a general security event
func (r *AuditRepository) LogSecurityEvent(ctx context.Context, event *service.SecurityEvent) error {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO security_events (
			id, user_id, tenant_id, event_type, severity, description,
			ip_address, user_agent, risk_score, metadata, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`

	_, err = r.db.ExecContext(ctx, query,
		event.ID, event.UserID, event.TenantID, event.EventType, event.Severity,
		event.Description, event.IPAddress, event.UserAgent, event.RiskScore,
		metadataJSON, event.CreatedAt,
	)

	if err != nil {
		return WrapSQLError(err, "log_security_event", query, event)
	}

	return nil
}

// GetMFAStatistics retrieves MFA usage statistics for a tenant
func (r *AuditRepository) GetMFAStatistics(ctx context.Context, tenantID uuid.UUID) (*service.MFAStatistics, error) {
	// Get basic user statistics
	userStatsQuery := `
		SELECT 
			COUNT(*) as total_users,
			COUNT(CASE WHEN mfa_enabled = true THEN 1 END) as mfa_enabled_users,
			COUNT(CASE WHEN mfa_enforced = true THEN 1 END) as mfa_enforced_users
		FROM users 
		WHERE tenant_id = $1 AND status = 'ACTIVE'`

	var userStats struct {
		TotalUsers       int `db:"total_users"`
		MFAEnabledUsers  int `db:"mfa_enabled_users"`
		MFAEnforcedUsers int `db:"mfa_enforced_users"`
	}

	err := r.db.GetContext(ctx, &userStats, userStatsQuery, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_mfa_user_stats", userStatsQuery, tenantID)
	}

	// Get device statistics
	deviceStatsQuery := `
		SELECT 
			COUNT(*) as active_devices,
			device_type,
			COUNT(*) as device_count
		FROM mfa_devices 
		WHERE tenant_id = $1 AND status = 'ACTIVE'
		GROUP BY device_type`

	rows, err := r.db.QueryContext(ctx, deviceStatsQuery, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_mfa_device_stats", deviceStatsQuery, tenantID)
	}
	defer rows.Close()

	var totalActiveDevices int
	devicesByType := make(map[entity.MFADeviceType]int)

	for rows.Next() {
		var deviceType entity.MFADeviceType
		var count int
		if err := rows.Scan(&count, &deviceType, &count); err != nil {
			return nil, WrapSQLError(err, "scan_device_stats", deviceStatsQuery, tenantID)
		}
		devicesByType[deviceType] = count
		totalActiveDevices += count
	}

	// Get recent authentication statistics (last 24 hours)
	authStatsQuery := `
		SELECT 
			COUNT(CASE WHEN success = true AND action LIKE '%VERIFICATION%' THEN 1 END) as successful_auth,
			COUNT(CASE WHEN success = false AND action LIKE '%VERIFICATION%' THEN 1 END) as failed_auth,
			COUNT(CASE WHEN action LIKE '%BACKUP_CODE%' THEN 1 END) as recovery_used
		FROM mfa_audit_events 
		WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`

	var authStats struct {
		SuccessfulAuth int `db:"successful_auth"`
		FailedAuth     int `db:"failed_auth"`
		RecoveryUsed   int `db:"recovery_used"`
	}

	err = r.db.GetContext(ctx, &authStats, authStatsQuery, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_mfa_auth_stats", authStatsQuery, tenantID)
	}

	return &service.MFAStatistics{
		TenantID:         tenantID,
		TotalUsers:       userStats.TotalUsers,
		MFAEnabledUsers:  userStats.MFAEnabledUsers,
		MFAEnforcedUsers: userStats.MFAEnforcedUsers,
		ActiveDevices:    totalActiveDevices,
		DevicesByType:    devicesByType,
		SuccessfulAuth:   authStats.SuccessfulAuth,
		FailedAuth:       authStats.FailedAuth,
		RecoveryUsed:     authStats.RecoveryUsed,
		LastUpdated:      time.Now(),
	}, nil
}

// GetMFAAuditEvents retrieves MFA audit events for a tenant within a time range
func (r *AuditRepository) GetMFAAuditEvents(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]service.MFAAuditEvent, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, device_id, device_type, action, success,
			failure_reason, ip_address, user_agent, risk, created_at, metadata
		FROM mfa_audit_events 
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
		ORDER BY created_at DESC
		LIMIT 1000`

	rows, err := r.db.QueryContext(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, WrapSQLError(err, "get_mfa_audit_events", query, tenantID, from, to)
	}
	defer rows.Close()

	var events []service.MFAAuditEvent
	for rows.Next() {
		var event service.MFAAuditEvent
		var metadataJSON []byte

		err := rows.Scan(
			&event.ID, &event.UserID, &event.TenantID, &event.DeviceID, &event.DeviceType,
			&event.Action, &event.Success, &event.FailureReason, &event.IPAddress,
			&event.UserAgent, &event.Risk, &event.CreatedAt, &metadataJSON,
		)
		if err != nil {
			return nil, WrapSQLError(err, "scan_mfa_audit_event", query, tenantID, from, to)
		}

		// Unmarshal metadata
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for event %s: %w", event.ID, err)
		}

		events = append(events, event)
	}

	return events, rows.Err()
}

// GetAuthenticationHistory retrieves authentication history for a user
func (r *AuditRepository) GetAuthenticationHistory(ctx context.Context, userID, tenantID uuid.UUID, limit int) ([]entity.AuthenticationAttempt, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, username, ip_address, user_agent, attempt_type,
			success, failure_reason, mfa_required, mfa_verified, security_events,
			created_at, risk_score, risk_factors, requires_review, metadata
		FROM authentication_attempts 
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
		LIMIT $3`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID, limit)
	if err != nil {
		return nil, WrapSQLError(err, "get_auth_history", query, userID, tenantID, limit)
	}
	defer rows.Close()

	var attempts []entity.AuthenticationAttempt
	for rows.Next() {
		var attempt entity.AuthenticationAttempt
		var securityEventsJSON, riskFactorsJSON, metadataJSON []byte

		err := rows.Scan(
			&attempt.ID, &attempt.UserID, &attempt.TenantID, &attempt.Username,
			&attempt.IPAddress, &attempt.UserAgent, &attempt.AttemptType,
			&attempt.Success, &attempt.FailureReason, &attempt.MFARequired,
			&attempt.MFAVerified, &securityEventsJSON, &attempt.CreatedAt,
			&attempt.RiskScore, &riskFactorsJSON, &attempt.RequiresReview, &metadataJSON,
		)
		if err != nil {
			return nil, WrapSQLError(err, "scan_auth_attempt", query, userID, tenantID, limit)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(securityEventsJSON, &attempt.SecurityEvents); err != nil {
			return nil, fmt.Errorf("failed to unmarshal security events for attempt %s: %w", attempt.ID, err)
		}

		if err := json.Unmarshal(riskFactorsJSON, &attempt.RiskFactors); err != nil {
			return nil, fmt.Errorf("failed to unmarshal risk factors for attempt %s: %w", attempt.ID, err)
		}

		if err := json.Unmarshal(metadataJSON, &attempt.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for attempt %s: %w", attempt.ID, err)
		}

		attempts = append(attempts, attempt)
	}

	return attempts, rows.Err()
}

// GetSecurityEvents retrieves security events for a user within a time range
func (r *AuditRepository) GetSecurityEvents(ctx context.Context, userID, tenantID uuid.UUID, from, to time.Time) ([]service.SecurityEvent, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, event_type, severity, description,
			ip_address, user_agent, risk_score, metadata, created_at
		FROM security_events 
		WHERE user_id = $1 AND tenant_id = $2 AND created_at BETWEEN $3 AND $4
		ORDER BY created_at DESC
		LIMIT 500`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID, from, to)
	if err != nil {
		return nil, WrapSQLError(err, "get_security_events", query, userID, tenantID, from, to)
	}
	defer rows.Close()

	var events []service.SecurityEvent
	for rows.Next() {
		var event service.SecurityEvent
		var metadataJSON []byte

		err := rows.Scan(
			&event.ID, &event.UserID, &event.TenantID, &event.EventType,
			&event.Severity, &event.Description, &event.IPAddress,
			&event.UserAgent, &event.RiskScore, &metadataJSON, &event.CreatedAt,
		)
		if err != nil {
			return nil, WrapSQLError(err, "scan_security_event", query, userID, tenantID, from, to)
		}

		// Unmarshal metadata
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for event %s: %w", event.ID, err)
		}

		events = append(events, event)
	}

	return events, rows.Err()
}

// GetFailedLoginAttempts retrieves recent failed login attempts
func (r *AuditRepository) GetFailedLoginAttempts(ctx context.Context, tenantID uuid.UUID, hours int) ([]entity.AuthenticationAttempt, error) {
	query := `
		SELECT 
			id, user_id, tenant_id, username, ip_address, user_agent, attempt_type,
			success, failure_reason, mfa_required, mfa_verified, security_events,
			created_at, risk_score, risk_factors, requires_review, metadata
		FROM authentication_attempts 
		WHERE tenant_id = $1 AND success = false 
		AND created_at > NOW() - INTERVAL '%d hours'
		ORDER BY created_at DESC
		LIMIT 100`

	formattedQuery := fmt.Sprintf(query, hours)

	rows, err := r.db.QueryContext(ctx, formattedQuery, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_failed_login_attempts", formattedQuery, tenantID)
	}
	defer rows.Close()

	var attempts []entity.AuthenticationAttempt
	for rows.Next() {
		var attempt entity.AuthenticationAttempt
		var securityEventsJSON, riskFactorsJSON, metadataJSON []byte

		err := rows.Scan(
			&attempt.ID, &attempt.UserID, &attempt.TenantID, &attempt.Username,
			&attempt.IPAddress, &attempt.UserAgent, &attempt.AttemptType,
			&attempt.Success, &attempt.FailureReason, &attempt.MFARequired,
			&attempt.MFAVerified, &securityEventsJSON, &attempt.CreatedAt,
			&attempt.RiskScore, &riskFactorsJSON, &attempt.RequiresReview, &metadataJSON,
		)
		if err != nil {
			return nil, WrapSQLError(err, "scan_failed_attempt", formattedQuery, tenantID)
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(securityEventsJSON, &attempt.SecurityEvents); err != nil {
			return nil, fmt.Errorf("failed to unmarshal security events for attempt %s: %w", attempt.ID, err)
		}

		if err := json.Unmarshal(riskFactorsJSON, &attempt.RiskFactors); err != nil {
			return nil, fmt.Errorf("failed to unmarshal risk factors for attempt %s: %w", attempt.ID, err)
		}

		if err := json.Unmarshal(metadataJSON, &attempt.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for attempt %s: %w", attempt.ID, err)
		}

		attempts = append(attempts, attempt)
	}

	return attempts, rows.Err()
}

// GetAuditMetrics retrieves audit and security metrics for a tenant
func (r *AuditRepository) GetAuditMetrics(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	query := `
		SELECT 
			-- Authentication metrics (last 24 hours)
			COUNT(CASE WHEN aa.attempt_type = 'LOGIN' AND aa.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as login_attempts_24h,
			COUNT(CASE WHEN aa.attempt_type = 'LOGIN' AND aa.success = true AND aa.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as successful_logins_24h,
			COUNT(CASE WHEN aa.attempt_type = 'LOGIN' AND aa.success = false AND aa.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as failed_logins_24h,
			
			-- MFA metrics (last 24 hours)
			COUNT(CASE WHEN mfa.action LIKE '%VERIFICATION%' AND mfa.success = true AND mfa.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as mfa_verifications_24h,
			COUNT(CASE WHEN mfa.action LIKE '%VERIFICATION%' AND mfa.success = false AND mfa.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as mfa_failures_24h,
			
			-- Security events (last 24 hours)
			COUNT(CASE WHEN se.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as security_events_24h,
			COUNT(CASE WHEN se.severity = 'HIGH' AND se.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as high_severity_events_24h,
			
			-- Risk metrics
			AVG(CASE WHEN aa.created_at > NOW() - INTERVAL '24 hours' THEN aa.risk_score END) as avg_risk_score_24h,
			COUNT(CASE WHEN aa.requires_review = true AND aa.created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as flagged_attempts_24h
			
		FROM authentication_attempts aa
		LEFT JOIN mfa_audit_events mfa ON aa.tenant_id = mfa.tenant_id
		LEFT JOIN security_events se ON aa.tenant_id = se.tenant_id
		WHERE aa.tenant_id = $1`

	var metrics struct {
		LoginAttempts24h      int      `db:"login_attempts_24h"`
		SuccessfulLogins24h   int      `db:"successful_logins_24h"`
		FailedLogins24h       int      `db:"failed_logins_24h"`
		MFAVerifications24h   int      `db:"mfa_verifications_24h"`
		MFAFailures24h        int      `db:"mfa_failures_24h"`
		SecurityEvents24h     int      `db:"security_events_24h"`
		HighSeverityEvents24h int      `db:"high_severity_events_24h"`
		AvgRiskScore24h       *float64 `db:"avg_risk_score_24h"`
		FlaggedAttempts24h    int      `db:"flagged_attempts_24h"`
	}

	err := r.db.GetContext(ctx, &metrics, query, tenantID)
	if err != nil {
		return nil, WrapSQLError(err, "get_audit_metrics", query, tenantID)
	}

	avgRiskScore := 0.0
	if metrics.AvgRiskScore24h != nil {
		avgRiskScore = *metrics.AvgRiskScore24h
	}

	return map[string]interface{}{
		"login_attempts_24h":       metrics.LoginAttempts24h,
		"successful_logins_24h":    metrics.SuccessfulLogins24h,
		"failed_logins_24h":        metrics.FailedLogins24h,
		"mfa_verifications_24h":    metrics.MFAVerifications24h,
		"mfa_failures_24h":         metrics.MFAFailures24h,
		"security_events_24h":      metrics.SecurityEvents24h,
		"high_severity_events_24h": metrics.HighSeverityEvents24h,
		"avg_risk_score_24h":       avgRiskScore,
		"flagged_attempts_24h":     metrics.FlaggedAttempts24h,
		"last_updated":             time.Now(),
	}, nil
}

// CleanupOldAuditLogs removes audit logs older than the specified retention period
func (r *AuditRepository) CleanupOldAuditLogs(ctx context.Context, retentionDays int) (int, error) {
	totalDeleted := 0

	// Clean up old MFA audit events
	mfaQuery := `DELETE FROM mfa_audit_events WHERE created_at < NOW() - INTERVAL '%d days'`
	formattedMFAQuery := fmt.Sprintf(mfaQuery, retentionDays)

	result, err := r.db.ExecContext(ctx, formattedMFAQuery)
	if err != nil {
		return 0, WrapSQLError(err, "cleanup_mfa_audit_events", formattedMFAQuery)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, WrapSQLError(err, "cleanup_mfa_audit_events_check_rows", formattedMFAQuery)
	}
	totalDeleted += int(rowsAffected)

	// Clean up old authentication attempts
	authQuery := `DELETE FROM authentication_attempts WHERE created_at < NOW() - INTERVAL '%d days'`
	formattedAuthQuery := fmt.Sprintf(authQuery, retentionDays)

	result, err = r.db.ExecContext(ctx, formattedAuthQuery)
	if err != nil {
		return totalDeleted, WrapSQLError(err, "cleanup_auth_attempts", formattedAuthQuery)
	}

	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return totalDeleted, WrapSQLError(err, "cleanup_auth_attempts_check_rows", formattedAuthQuery)
	}
	totalDeleted += int(rowsAffected)

	// Clean up old security events
	secQuery := `DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '%d days'`
	formattedSecQuery := fmt.Sprintf(secQuery, retentionDays)

	result, err = r.db.ExecContext(ctx, formattedSecQuery)
	if err != nil {
		return totalDeleted, WrapSQLError(err, "cleanup_security_events", formattedSecQuery)
	}

	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return totalDeleted, WrapSQLError(err, "cleanup_security_events_check_rows", formattedSecQuery)
	}
	totalDeleted += int(rowsAffected)

	return totalDeleted, nil
}
