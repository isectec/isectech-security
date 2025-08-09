package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Example demonstrates how to use the PostgreSQL client for iSECTECH cybersecurity operations
func Example() error {
	// Initialize logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Example 1: Quick development setup
	ctx := context.Background()
	client, err := QuickStart(ctx, logger)
	if err != nil {
		return fmt.Errorf("failed to setup database: %w", err)
	}
	defer client.Close()

	// Example 2: Create a tenant context for multi-tenancy
	tenantCtx := &TenantContext{
		TenantID:     "550e8400-e29b-41d4-a716-446655440000",
		UserID:       "550e8400-e29b-41d4-a716-446655440001",
		Role:         "analyst",
		Permissions:  []string{"read:assets", "write:events", "read:threats"},
		SecurityTags: map[string]string{"clearance": "SECRET"},
	}

	// Example 3: Insert a security asset
	assetID := uuid.New()
	insertAssetSQL := `
		INSERT INTO assets (
			id, tenant_id, name, type, category, ip_addresses, 
			criticality, security_classification, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	opts := &QueryOptions{
		Tenant:   tenantCtx,
		ShardKey: tenantCtx.TenantID,
	}

	_, err = client.Exec(ctx, insertAssetSQL, []interface{}{
		assetID,
		tenantCtx.TenantID,
		"Web Server 01",
		"server",
		"web_server",
		[]string{"192.168.1.100"},
		"high",
		"CONFIDENTIAL",
		"active",
	}, opts)
	if err != nil {
		return fmt.Errorf("failed to insert asset: %w", err)
	}

	// Example 4: Insert a security event
	eventID := uuid.New()
	insertEventSQL := `
		INSERT INTO security_events (
			id, tenant_id, event_type, severity, source_asset_id,
			title, description, raw_event, normalized_event,
			source_ip, destination_ip, risk_score, 
			security_classification, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	rawEvent := map[string]interface{}{
		"timestamp": time.Now(),
		"source":    "nginx",
		"level":     "warning",
		"message":   "Suspicious login attempt detected",
	}

	normalizedEvent := map[string]interface{}{
		"event_category": "authentication",
		"action":         "login_attempt",
		"outcome":        "failure",
		"user_agent":     "Mozilla/5.0...",
		"ip_address":     "203.0.113.42",
	}

	_, err = client.Exec(ctx, insertEventSQL, []interface{}{
		eventID,
		tenantCtx.TenantID,
		"authentication",
		"medium",
		assetID,
		"Suspicious Login Attempt",
		"Multiple failed login attempts from external IP",
		rawEvent,
		normalizedEvent,
		"203.0.113.42",
		"192.168.1.100",
		75,
		"RESTRICTED",
		time.Now(),
	}, opts)
	if err != nil {
		return fmt.Errorf("failed to insert security event: %w", err)
	}

	// Example 5: Query security events with read replica
	queryOpts := &QueryOptions{
		Tenant:      tenantCtx,
		ShardKey:    tenantCtx.TenantID,
		UseReplica:  true,
		Consistency: ConsistencyEventual,
	}

	querySQL := `
		SELECT id, event_type, severity, title, occurred_at 
		FROM security_events 
		WHERE tenant_id = $1 AND severity IN ('high', 'critical')
		ORDER BY occurred_at DESC 
		LIMIT 10
	`

	rows, err := client.Query(ctx, querySQL, []interface{}{tenantCtx.TenantID}, queryOpts)
	if err != nil {
		return fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	fmt.Println("Recent high-severity security events:")
	for rows.Next() {
		var id, eventType, severity, title string
		var occurredAt time.Time
		
		if err := rows.Scan(&id, &eventType, &severity, &title, &occurredAt); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}
		
		fmt.Printf("- [%s] %s (%s): %s at %s\n", 
			severity, eventType, id, title, occurredAt.Format(time.RFC3339))
	}

	// Example 6: Transaction example for creating an alert with related data
	err = client.Transaction(ctx, tenantCtx.TenantID, tenantCtx, func(tx *sqlx.Tx) error {
		// Insert alert
		alertID := uuid.New()
		_, err := tx.ExecContext(ctx, `
			INSERT INTO alerts (
				id, tenant_id, title, severity, category, 
				event_ids, risk_score, security_classification, status
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, alertID, tenantCtx.TenantID, "Multiple Failed Login Attempts", 
			"medium", "authentication", []string{eventID.String()}, 75, "RESTRICTED", "open")
		if err != nil {
			return err
		}

		// Create audit log
		_, err = tx.ExecContext(ctx, `
			INSERT INTO audit_logs (
				tenant_id, user_id, action, resource_type, resource_id,
				details, security_classification
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, tenantCtx.TenantID, tenantCtx.UserID, "create", "alert", alertID,
			map[string]interface{}{"alert_type": "authentication", "automated": true}, 
			"RESTRICTED")
		
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to create alert transaction: %w", err)
	}

	// Example 7: Health check
	health := client.Health(ctx)
	fmt.Println("Database health status:")
	for shard, healthy := range health {
		status := "healthy"
		if !healthy {
			status = "unhealthy"
		}
		fmt.Printf("- %s: %s\n", shard, status)
	}

	fmt.Println("PostgreSQL client example completed successfully!")
	return nil
}

// ExampleAssetDiscovery demonstrates asset discovery and management
func ExampleAssetDiscovery(client *Client, tenantCtx *TenantContext) error {
	ctx := context.Background()

	// Discover and register multiple network assets
	assets := []struct {
		name           string
		assetType      string
		ipAddress      string
		criticality    string
		classification string
	}{
		{"Database Server", "database", "192.168.1.10", "critical", "CONFIDENTIAL"},
		{"Web Application", "application", "192.168.1.20", "high", "INTERNAL"},
		{"File Server", "server", "192.168.1.30", "medium", "INTERNAL"},
		{"Workstation-001", "workstation", "192.168.1.100", "low", "INTERNAL"},
	}

	opts := &QueryOptions{
		Tenant:   tenantCtx,
		ShardKey: tenantCtx.TenantID,
	}

	for _, asset := range assets {
		assetID := uuid.New()
		
		_, err := client.Exec(ctx, `
			INSERT INTO assets (
				id, tenant_id, name, type, category, ip_addresses,
				criticality, security_classification, status,
				last_seen_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, []interface{}{
			assetID,
			tenantCtx.TenantID,
			asset.name,
			asset.assetType,
			asset.assetType,
			[]string{asset.ipAddress},
			asset.criticality,
			asset.classification,
			"active",
			time.Now(),
		}, opts)
		
		if err != nil {
			return fmt.Errorf("failed to insert asset %s: %w", asset.name, err)
		}
		
		fmt.Printf("Registered asset: %s (%s) at %s\n", 
			asset.name, asset.assetType, asset.ipAddress)
	}

	return nil
}

// ExampleThreatIntelligence demonstrates threat intelligence storage and querying
func ExampleThreatIntelligence(client *Client, tenantCtx *TenantContext) error {
	ctx := context.Background()

	// Store threat intelligence data
	threatID := uuid.New()
	opts := &QueryOptions{
		Tenant:   tenantCtx,
		ShardKey: tenantCtx.TenantID,
	}

	indicators := map[string]interface{}{
		"ip_addresses": []string{"203.0.113.42", "198.51.100.23"},
		"domains":      []string{"malicious.example.com", "phishing.example.org"},
		"file_hashes":  []string{"d41d8cd98f00b204e9800998ecf8427e"},
	}

	ttps := map[string]interface{}{
		"initial_access": []string{"T1566.001", "T1190"},
		"persistence":    []string{"T1053.005"},
		"privilege_escalation": []string{"T1068"},
	}

	_, err := client.Exec(ctx, `
		INSERT INTO threats (
			id, tenant_id, name, type, category, severity, confidence,
			description, indicators, ttps, mitre_attack_ids,
			security_classification, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, []interface{}{
		threatID,
		tenantCtx.TenantID,
		"APT-Example Campaign",
		"apt",
		"targeted_attack",
		"high",
		0.85,
		"Advanced persistent threat campaign targeting financial institutions",
		indicators,
		ttps,
		[]string{"T1566.001", "T1190", "T1053.005", "T1068"},
		"SECRET",
		"active",
	}, opts)

	if err != nil {
		return fmt.Errorf("failed to insert threat intelligence: %w", err)
	}

	fmt.Printf("Stored threat intelligence: %s\n", threatID)
	return nil
}