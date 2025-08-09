package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/isectech/backend/services/security-benchmarking/domain/service"
)

// DefaultMetricCollector implements the MetricCollector interface
type DefaultMetricCollector struct {
	db     *sqlx.DB
	logger *slog.Logger
}

// NewDefaultMetricCollector creates a new default metric collector
func NewDefaultMetricCollector(db *sqlx.DB, logger *slog.Logger) *DefaultMetricCollector {
	return &DefaultMetricCollector{
		db:     db,
		logger: logger,
	}
}

// CollectThreatMetrics collects threat-related metrics
func (c *DefaultMetricCollector) CollectThreatMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*service.ThreatMetrics, error) {
	c.logger.Info("Collecting threat metrics", "tenant_id", tenantID, "time_window", timeWindow)

	startTime := time.Now().Add(-timeWindow)
	
	var metrics service.ThreatMetrics
	
	// Query threat detection events
	threatQuery := `
		SELECT 
			COUNT(*) as total_threats,
			COUNT(CASE WHEN action = 'blocked' THEN 1 END) as blocked_threats,
			COUNT(CASE WHEN action = 'allowed' AND threat_level > 'low' THEN 1 END) as missed_threats,
			COUNT(CASE WHEN is_false_positive = true THEN 1 END) as false_positives,
			AVG(EXTRACT(EPOCH FROM (response_timestamp - detection_timestamp))) as avg_response_seconds
		FROM security_events 
		WHERE tenant_id = $1 
			AND created_at >= $2 
			AND event_type IN ('threat_detection', 'malware_detection', 'intrusion_attempt')
	`

	row := c.db.QueryRowContext(ctx, threatQuery, tenantID, startTime)
	
	var avgResponseSeconds sql.NullFloat64
	err := row.Scan(
		&metrics.TotalThreats,
		&metrics.BlockedThreats,
		&metrics.MissedThreats,
		&metrics.FalsePositives,
		&avgResponseSeconds,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query threat metrics: %w", err)
	}

	// Calculate derived metrics
	if metrics.TotalThreats > 0 {
		metrics.BlockingRate = float64(metrics.BlockedThreats) / float64(metrics.TotalThreats)
		
		accurateDetections := metrics.BlockedThreats - metrics.FalsePositives
		if accurateDetections < 0 {
			accurateDetections = 0
		}
		metrics.AccuracyRate = float64(accurateDetections) / float64(metrics.TotalThreats)
	} else {
		metrics.BlockingRate = 1.0 // Perfect blocking rate when no threats
		metrics.AccuracyRate = 1.0  // Perfect accuracy when no threats
	}

	if avgResponseSeconds.Valid {
		metrics.AverageResponseTime = time.Duration(avgResponseSeconds.Float64) * time.Second
	}

	c.logger.Info("Threat metrics collected", 
		"total_threats", metrics.TotalThreats,
		"blocking_rate", metrics.BlockingRate,
		"accuracy_rate", metrics.AccuracyRate)

	return &metrics, nil
}

// CollectIncidentMetrics collects incident-related metrics
func (c *DefaultMetricCollector) CollectIncidentMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*service.IncidentMetrics, error) {
	c.logger.Info("Collecting incident metrics", "tenant_id", tenantID, "time_window", timeWindow)

	startTime := time.Now().Add(-timeWindow)
	
	var metrics service.IncidentMetrics
	
	// Query incident data
	incidentQuery := `
		SELECT 
			COUNT(*) as total_incidents,
			COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_incidents,
			COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_incidents,
			AVG(CASE WHEN resolved_at IS NOT NULL THEN 
				EXTRACT(EPOCH FROM (resolved_at - created_at)) 
			END) as avg_resolution_seconds,
			AVG(impact_score) as avg_impact_score,
			COUNT(CASE WHEN is_recurring = true THEN 1 END) as recurring_incidents
		FROM security_incidents 
		WHERE tenant_id = $1 
			AND created_at >= $2
	`

	row := c.db.QueryRowContext(ctx, incidentQuery, tenantID, startTime)
	
	var avgResolutionSeconds sql.NullFloat64
	var avgImpactScore sql.NullFloat64
	
	err := row.Scan(
		&metrics.TotalIncidents,
		&metrics.ResolvedIncidents,
		&metrics.CriticalIncidents,
		&avgResolutionSeconds,
		&avgImpactScore,
		&metrics.RecurringIncidents,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query incident metrics: %w", err)
	}

	if avgResolutionSeconds.Valid {
		metrics.AverageResolutionTime = time.Duration(avgResolutionSeconds.Float64) * time.Second
	}

	if avgImpactScore.Valid {
		metrics.AverageImpactScore = avgImpactScore.Float64
	}

	c.logger.Info("Incident metrics collected", 
		"total_incidents", metrics.TotalIncidents,
		"resolved_incidents", metrics.ResolvedIncidents,
		"critical_incidents", metrics.CriticalIncidents)

	return &metrics, nil
}

// CollectResponseMetrics collects response-related metrics
func (c *DefaultMetricCollector) CollectResponseMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*service.ResponseMetrics, error) {
	c.logger.Info("Collecting response metrics", "tenant_id", tenantID, "time_window", timeWindow)

	startTime := time.Now().Add(-timeWindow)
	
	var metrics service.ResponseMetrics
	
	// Query response time metrics
	responseQuery := `
		SELECT 
			AVG(EXTRACT(EPOCH FROM (detection_timestamp - event_timestamp))) as avg_detection_seconds,
			AVG(EXTRACT(EPOCH FROM (containment_timestamp - detection_timestamp))) as avg_containment_seconds,
			AVG(EXTRACT(EPOCH FROM (recovery_timestamp - containment_timestamp))) as avg_recovery_seconds,
			COUNT(CASE WHEN automated_response = true THEN 1 END)::float / COUNT(*)::float as automation_rate
		FROM security_response_events 
		WHERE tenant_id = $1 
			AND created_at >= $2
			AND detection_timestamp IS NOT NULL
	`

	row := c.db.QueryRowContext(ctx, responseQuery, tenantID, startTime)
	
	var avgDetectionSeconds, avgContainmentSeconds, avgRecoverySeconds sql.NullFloat64
	var automationRate sql.NullFloat64
	
	err := row.Scan(
		&avgDetectionSeconds,
		&avgContainmentSeconds,
		&avgRecoverySeconds,
		&automationRate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query response metrics: %w", err)
	}

	if avgDetectionSeconds.Valid {
		metrics.AverageDetectionTime = time.Duration(avgDetectionSeconds.Float64) * time.Second
	}
	if avgContainmentSeconds.Valid {
		metrics.AverageContainmentTime = time.Duration(avgContainmentSeconds.Float64) * time.Second
	}
	if avgRecoverySeconds.Valid {
		metrics.AverageRecoveryTime = time.Duration(avgRecoverySeconds.Float64) * time.Second
	}
	if automationRate.Valid {
		metrics.AutomationRate = automationRate.Float64
	}

	// Calculate alert volume reduction (comparison with previous period)
	prevStartTime := startTime.Add(-timeWindow)
	alertVolumeQuery := `
		WITH current_period AS (
			SELECT COUNT(*) as current_alerts
			FROM security_alerts 
			WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
		),
		previous_period AS (
			SELECT COUNT(*) as previous_alerts
			FROM security_alerts 
			WHERE tenant_id = $1 AND created_at >= $4 AND created_at < $2
		)
		SELECT 
			CASE 
				WHEN p.previous_alerts > 0 THEN 
					1.0 - (c.current_alerts::float / p.previous_alerts::float)
				ELSE 0.0 
			END as volume_reduction
		FROM current_period c, previous_period p
	`

	var volumeReduction sql.NullFloat64
	err = c.db.QueryRowContext(ctx, alertVolumeQuery, tenantID, startTime, time.Now(), prevStartTime).Scan(&volumeReduction)
	if err != nil {
		c.logger.Warn("Failed to calculate alert volume reduction", "error", err)
	} else if volumeReduction.Valid {
		metrics.AlertVolumeReduction = volumeReduction.Float64
	}

	c.logger.Info("Response metrics collected", 
		"avg_detection_time", metrics.AverageDetectionTime,
		"avg_containment_time", metrics.AverageContainmentTime,
		"automation_rate", metrics.AutomationRate)

	return &metrics, nil
}

// CollectPreventionMetrics collects prevention-related metrics
func (c *DefaultMetricCollector) CollectPreventionMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*service.PreventionMetrics, error) {
	c.logger.Info("Collecting prevention metrics", "tenant_id", tenantID, "time_window", timeWindow)

	startTime := time.Now().Add(-timeWindow)
	
	var metrics service.PreventionMetrics
	
	// Query vulnerability and prevention metrics
	preventionQuery := `
		SELECT 
			COUNT(CASE WHEN v.status = 'found' THEN 1 END) as vulnerabilities_found,
			COUNT(CASE WHEN v.status = 'patched' THEN 1 END) as vulnerabilities_patched,
			AVG(CASE WHEN v.patched_at IS NOT NULL THEN 
				EXTRACT(EPOCH FROM (v.patched_at - v.found_at)) 
			END) as avg_remediation_seconds,
			COUNT(CASE WHEN pe.event_type = 'attack_prevented' THEN 1 END) as prevented_attacks
		FROM vulnerabilities v
		LEFT JOIN prevention_events pe ON pe.tenant_id = v.tenant_id AND pe.created_at >= $2
		WHERE v.tenant_id = $1 
			AND v.found_at >= $2
	`

	row := c.db.QueryRowContext(ctx, preventionQuery, tenantID, startTime)
	
	var avgRemediationSeconds sql.NullFloat64
	
	err := row.Scan(
		&metrics.VulnerabilitiesFound,
		&metrics.VulnerabilitiesPatched,
		&avgRemediationSeconds,
		&metrics.PreventedAttacks,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query prevention metrics: %w", err)
	}

	// Calculate derived metrics
	if metrics.VulnerabilitiesFound > 0 {
		metrics.PatchingRate = float64(metrics.VulnerabilitiesPatched) / float64(metrics.VulnerabilitiesFound)
	} else {
		metrics.PatchingRate = 1.0 // Perfect patching rate when no vulnerabilities
	}

	if avgRemediationSeconds.Valid {
		metrics.MeanTimeToRemediation = time.Duration(avgRemediationSeconds.Float64) * time.Second
	}

	// Calculate prevention effectiveness based on prevented vs. attempted attacks
	effectivenessQuery := `
		SELECT 
			COUNT(CASE WHEN outcome = 'prevented' THEN 1 END)::float / 
			COUNT(*)::float as prevention_effectiveness
		FROM attack_attempts 
		WHERE tenant_id = $1 
			AND created_at >= $2
	`

	var effectiveness sql.NullFloat64
	err = c.db.QueryRowContext(ctx, effectivenessQuery, tenantID, startTime).Scan(&effectiveness)
	if err != nil {
		c.logger.Warn("Failed to calculate prevention effectiveness", "error", err)
		metrics.PreventionEffectiveness = 0.5 // Default moderate effectiveness
	} else if effectiveness.Valid {
		metrics.PreventionEffectiveness = effectiveness.Float64
	}

	c.logger.Info("Prevention metrics collected", 
		"vulnerabilities_found", metrics.VulnerabilitiesFound,
		"patching_rate", metrics.PatchingRate,
		"prevention_effectiveness", metrics.PreventionEffectiveness)

	return &metrics, nil
}

// CollectComponentMetrics collects metrics for individual security components
func (c *DefaultMetricCollector) CollectComponentMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (map[string]*service.ComponentMetrics, error) {
	c.logger.Info("Collecting component metrics", "tenant_id", tenantID, "time_window", timeWindow)

	startTime := time.Now().Add(-timeWindow)
	componentMetrics := make(map[string]*service.ComponentMetrics)
	
	// Query component performance metrics
	componentQuery := `
		SELECT 
			component_type,
			component_name,
			AVG(availability_percent) as avg_availability,
			AVG(performance_score) as avg_performance,
			AVG(effectiveness_rating) as avg_effectiveness,
			AVG(configuration_score) as avg_configuration,
			MAX(last_update_status) as update_status
		FROM security_component_metrics 
		WHERE tenant_id = $1 
			AND measurement_time >= $2
		GROUP BY component_type, component_name
	`

	rows, err := c.db.QueryContext(ctx, componentQuery, tenantID, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query component metrics: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var componentType, componentName, updateStatus string
		var avgAvailability, avgPerformance, avgEffectiveness, avgConfiguration sql.NullFloat64
		
		err := rows.Scan(
			&componentType,
			&componentName,
			&avgAvailability,
			&avgPerformance,
			&avgEffectiveness,
			&avgConfiguration,
			&updateStatus,
		)
		if err != nil {
			c.logger.Warn("Failed to scan component metric row", "error", err)
			continue
		}

		metrics := &service.ComponentMetrics{
			UpdateStatus: updateStatus,
		}

		// Convert string to ComponentType enum
		switch componentType {
		case "firewall":
			metrics.ComponentType = entity.ComponentFirewall
		case "ids":
			metrics.ComponentType = entity.ComponentIDS
		case "ips":
			metrics.ComponentType = entity.ComponentIPS
		case "antivirus":
			metrics.ComponentType = entity.ComponentAntivirus
		case "email_security":
			metrics.ComponentType = entity.ComponentEmailSecurity
		case "web_security":
			metrics.ComponentType = entity.ComponentWebSecurity
		case "endpoint_protection":
			metrics.ComponentType = entity.ComponentEndpointProtection
		case "siem":
			metrics.ComponentType = entity.ComponentSIEM
		case "soar":
			metrics.ComponentType = entity.ComponentSOAR
		case "dlp":
			metrics.ComponentType = entity.ComponentDLP
		case "identity_access":
			metrics.ComponentType = entity.ComponentIdentityAccess
		case "vulnerability":
			metrics.ComponentType = entity.ComponentVulnerability
		case "threat_intel":
			metrics.ComponentType = entity.ComponentThreatIntel
		case "incident_response":
			metrics.ComponentType = entity.ComponentIncidentResponse
		default:
			metrics.ComponentType = entity.ComponentFirewall // Default fallback
		}

		if avgAvailability.Valid {
			metrics.AvailabilityRate = avgAvailability.Float64 / 100.0 // Convert percentage to decimal
		}
		if avgPerformance.Valid {
			metrics.PerformanceScore = avgPerformance.Float64
		}
		if avgEffectiveness.Valid {
			metrics.EffectivenessRate = avgEffectiveness.Float64 / 100.0 // Convert percentage to decimal
		}
		if avgConfiguration.Valid {
			metrics.ConfigurationScore = avgConfiguration.Float64
		}

		componentMetrics[componentName] = metrics
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating component metrics: %w", err)
	}

	c.logger.Info("Component metrics collected", "component_count", len(componentMetrics))

	return componentMetrics, nil
}

// GetMetricCollectorHealth returns the health status of the metric collector
func (c *DefaultMetricCollector) GetMetricCollectorHealth(ctx context.Context) error {
	// Test database connectivity
	if err := c.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database connectivity check failed: %w", err)
	}

	// Test if required tables exist
	requiredTables := []string{
		"security_events",
		"security_incidents", 
		"security_response_events",
		"vulnerabilities",
		"security_component_metrics",
	}

	for _, table := range requiredTables {
		var exists bool
		query := `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`
		err := c.db.QueryRowContext(ctx, query, table).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check table %s existence: %w", table, err)
		}
		if !exists {
			return fmt.Errorf("required table %s does not exist", table)
		}
	}

	return nil
}