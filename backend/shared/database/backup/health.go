package backup

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthMonitor monitors the health of backup operations and infrastructure
type HealthMonitor struct {
	config  BackupMonitoringConfig
	metrics *BackupMetrics
	logger  *zap.Logger
	
	// Health status tracking
	systemHealth    *SystemHealthStatus
	backupHealth    *BackupHealthStatus
	storageHealth   *StorageHealthStatus
	
	// Alerting
	alertManager    *AlertManager
	
	// State management
	mu              sync.RWMutex
	lastHealthCheck time.Time
	failedChecks    int
	closed          bool
}

// SystemHealthStatus represents overall system health
type SystemHealthStatus struct {
	Status        HealthStatusType `json:"status"`
	LastCheck     time.Time        `json:"last_check"`
	Uptime        time.Duration    `json:"uptime"`
	Version       string           `json:"version"`
	
	// Resource utilization
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsage   float64 `json:"memory_usage"`
	DiskUsage     float64 `json:"disk_usage"`
	NetworkIO     NetworkIOStats `json:"network_io"`
	
	// Database connectivity
	PostgreSQLHealth DatabaseHealth `json:"postgresql_health"`
	MongoDBHealth    DatabaseHealth `json:"mongodb_health"`
	RedisHealth      DatabaseHealth `json:"redis_health"`
	ElasticsearchHealth DatabaseHealth `json:"elasticsearch_health"`
}

// BackupHealthStatus represents backup operation health
type BackupHealthStatus struct {
	Status              HealthStatusType    `json:"status"`
	LastCheck           time.Time           `json:"last_check"`
	
	// SLA metrics
	BackupSLACompliance float64             `json:"backup_sla_compliance"`
	RestoreSLACompliance float64            `json:"restore_sla_compliance"`
	RPOCompliance       float64             `json:"rpo_compliance"`
	RTOCompliance       float64             `json:"rto_compliance"`
	
	// Operation statistics
	ActiveBackups       int                 `json:"active_backups"`
	FailedBackups24h    int                 `json:"failed_backups_24h"`
	SuccessRate24h      float64             `json:"success_rate_24h"`
	AverageBackupTime   time.Duration       `json:"average_backup_time"`
	
	// Recent operations
	RecentOperations    []*BackupOperation  `json:"recent_operations"`
	LastSuccessfulBackup time.Time          `json:"last_successful_backup"`
	LastFailedBackup    *time.Time          `json:"last_failed_backup,omitempty"`
}

// StorageHealthStatus represents storage backend health
type StorageHealthStatus struct {
	Status          HealthStatusType     `json:"status"`
	LastCheck       time.Time            `json:"last_check"`
	
	// Backend status
	PrimaryBackend  StorageBackendHealth `json:"primary_backend"`
	SecondaryBackends []StorageBackendHealth `json:"secondary_backends"`
	ArchiveBackend  StorageBackendHealth `json:"archive_backend"`
	
	// Storage metrics
	TotalStorageUsed    int64   `json:"total_storage_used"`
	StorageGrowthRate   float64 `json:"storage_growth_rate"`
	CompressionRatio    float64 `json:"compression_ratio"`
	
	// Retention compliance
	RetentionCompliance float64 `json:"retention_compliance"`
	ExpiredBackups      int     `json:"expired_backups"`
}

// StorageBackendHealth represents individual storage backend health
type StorageBackendHealth struct {
	Type           string           `json:"type"`
	Status         HealthStatusType `json:"status"`
	LastCheck      time.Time        `json:"last_check"`
	ResponseTime   time.Duration    `json:"response_time"`
	ErrorRate      float64          `json:"error_rate"`
	StorageUsed    int64            `json:"storage_used"`
	StorageLimit   int64            `json:"storage_limit"`
	Availability   float64          `json:"availability"`
}

// DatabaseHealth represents database connectivity health
type DatabaseHealth struct {
	Status       HealthStatusType `json:"status"`
	LastCheck    time.Time        `json:"last_check"`
	ResponseTime time.Duration    `json:"response_time"`
	ErrorRate    float64          `json:"error_rate"`
	ConnectionPool ConnectionPoolHealth `json:"connection_pool"`
}

// ConnectionPoolHealth represents connection pool health
type ConnectionPoolHealth struct {
	ActiveConnections int     `json:"active_connections"`
	IdleConnections   int     `json:"idle_connections"`
	MaxConnections    int     `json:"max_connections"`
	UtilizationRate   float64 `json:"utilization_rate"`
}

// NetworkIOStats represents network I/O statistics
type NetworkIOStats struct {
	BytesReceived    int64   `json:"bytes_received"`
	BytesSent        int64   `json:"bytes_sent"`
	PacketsReceived  int64   `json:"packets_received"`
	PacketsSent      int64   `json:"packets_sent"`
	ErrorsReceived   int64   `json:"errors_received"`
	ErrorsSent       int64   `json:"errors_sent"`
	Throughput       float64 `json:"throughput_mbps"`
}

// HealthStatusType represents the status of a health check
type HealthStatusType string

const (
	HealthStatusHealthy   HealthStatusType = "healthy"
	HealthStatusDegraded  HealthStatusType = "degraded"
	HealthStatusUnhealthy HealthStatusType = "unhealthy"
	HealthStatusUnknown   HealthStatusType = "unknown"
)

// HealthStatus combines all health information
type HealthStatus struct {
	OverallStatus HealthStatusType     `json:"overall_status"`
	LastCheck     time.Time            `json:"last_check"`
	System        *SystemHealthStatus  `json:"system"`
	Backup        *BackupHealthStatus  `json:"backup"`
	Storage       *StorageHealthStatus `json:"storage"`
	
	// Health score (0-100)
	HealthScore   float64              `json:"health_score"`
	
	// Issues and recommendations
	Issues        []HealthIssue        `json:"issues"`
	Recommendations []string           `json:"recommendations"`
}

// HealthIssue represents a health issue with severity and description
type HealthIssue struct {
	Severity    string    `json:"severity"`    // critical, warning, info
	Component   string    `json:"component"`   // system, backup, storage
	Title       string    `json:"title"`
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
	Resolution  string    `json:"resolution,omitempty"`
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(
	config BackupMonitoringConfig,
	metrics *BackupMetrics,
	logger *zap.Logger,
) *HealthMonitor {
	
	hm := &HealthMonitor{
		config:  config,
		metrics: metrics,
		logger:  logger,
		systemHealth: &SystemHealthStatus{
			Status: HealthStatusUnknown,
		},
		backupHealth: &BackupHealthStatus{
			Status: HealthStatusUnknown,
		},
		storageHealth: &StorageHealthStatus{
			Status: HealthStatusUnknown,
		},
	}
	
	// Initialize alert manager
	hm.alertManager = NewAlertManager(config, logger)
	
	return hm
}

// Start begins health monitoring
func (hm *HealthMonitor) Start(stopCh <-chan struct{}) {
	hm.logger.Info("Starting health monitor",
		zap.Duration("check_interval", hm.config.HealthCheckInterval),
		zap.Bool("alerting_enabled", hm.config.AlertingEnabled),
	)
	
	// Initial health check
	hm.performHealthCheck()
	
	// Start periodic health checks
	ticker := time.NewTicker(hm.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			hm.performHealthCheck()
		case <-stopCh:
			hm.logger.Info("Health monitor stopped")
			return
		}
	}
}

// performHealthCheck performs a comprehensive health check
func (hm *HealthMonitor) performHealthCheck() {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	start := time.Now()
	hm.lastHealthCheck = start
	
	hm.logger.Debug("Performing health check")
	
	// Check system health
	hm.checkSystemHealth()
	
	// Check backup health
	hm.checkBackupHealth()
	
	// Check storage health
	hm.checkStorageHealth()
	
	// Calculate overall health
	overallStatus := hm.calculateOverallHealth()
	
	// Handle failed checks
	if overallStatus != HealthStatusHealthy {
		hm.failedChecks++
		if hm.failedChecks >= hm.config.MaxFailedChecks {
			hm.triggerAlert("Health check failed multiple times", "critical")
		}
	} else {
		hm.failedChecks = 0
	}
	
	duration := time.Since(start)
	hm.logger.Debug("Health check completed",
		zap.String("overall_status", string(overallStatus)),
		zap.Duration("duration", duration),
		zap.Int("failed_checks", hm.failedChecks),
	)
}

// checkSystemHealth checks system-level health
func (hm *HealthMonitor) checkSystemHealth() {
	hm.systemHealth.LastCheck = time.Now()
	hm.systemHealth.Status = HealthStatusHealthy
	
	// Check resource utilization
	hm.systemHealth.CPUUsage = hm.getCPUUsage()
	hm.systemHealth.MemoryUsage = hm.getMemoryUsage()
	hm.systemHealth.DiskUsage = hm.getDiskUsage()
	hm.systemHealth.NetworkIO = hm.getNetworkIOStats()
	
	// Check database connectivity
	hm.systemHealth.PostgreSQLHealth = hm.checkDatabaseHealth("postgresql")
	hm.systemHealth.MongoDBHealth = hm.checkDatabaseHealth("mongodb")
	hm.systemHealth.RedisHealth = hm.checkDatabaseHealth("redis")
	hm.systemHealth.ElasticsearchHealth = hm.checkDatabaseHealth("elasticsearch")
	
	// Determine overall system status
	if hm.systemHealth.CPUUsage > 90 || hm.systemHealth.MemoryUsage > 90 || hm.systemHealth.DiskUsage > 90 {
		hm.systemHealth.Status = HealthStatusDegraded
	}
	
	if hm.systemHealth.PostgreSQLHealth.Status == HealthStatusUnhealthy ||
		hm.systemHealth.MongoDBHealth.Status == HealthStatusUnhealthy {
		hm.systemHealth.Status = HealthStatusUnhealthy
	}
}

// checkBackupHealth checks backup operation health
func (hm *HealthMonitor) checkBackupHealth() {
	hm.backupHealth.LastCheck = time.Now()
	hm.backupHealth.Status = HealthStatusHealthy
	
	// Get metrics from backup metrics collector
	metricsData := hm.metrics.GetMetrics()
	
	// Calculate SLA compliance
	hm.backupHealth.BackupSLACompliance = hm.calculateBackupSLACompliance(metricsData)
	hm.backupHealth.RestoreSLACompliance = hm.calculateRestoreSLACompliance(metricsData)
	hm.backupHealth.RPOCompliance = hm.calculateRPOCompliance(metricsData)
	hm.backupHealth.RTOCompliance = hm.calculateRTOCompliance(metricsData)
	
	// Calculate success rates
	hm.backupHealth.SuccessRate24h = hm.calculateSuccessRate24h(metricsData)
	hm.backupHealth.FailedBackups24h = hm.getFailedBackups24h(metricsData)
	
	// Determine backup health status
	if hm.backupHealth.SuccessRate24h < 0.95 { // Less than 95% success rate
		hm.backupHealth.Status = HealthStatusDegraded
	}
	
	if hm.backupHealth.SuccessRate24h < 0.85 { // Less than 85% success rate
		hm.backupHealth.Status = HealthStatusUnhealthy
	}
	
	if hm.backupHealth.RPOCompliance < 0.90 || hm.backupHealth.RTOCompliance < 0.90 {
		hm.backupHealth.Status = HealthStatusDegraded
	}
}

// checkStorageHealth checks storage backend health
func (hm *HealthMonitor) checkStorageHealth() {
	hm.storageHealth.LastCheck = time.Now()
	hm.storageHealth.Status = HealthStatusHealthy
	
	// Check primary backend health
	// This would integrate with actual storage backends
	hm.storageHealth.PrimaryBackend = StorageBackendHealth{
		Type:         "gcs",
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		ResponseTime: 50 * time.Millisecond,
		ErrorRate:    0.01,
		Availability: 99.95,
	}
	
	// Check secondary backends
	hm.storageHealth.SecondaryBackends = []StorageBackendHealth{
		{
			Type:         "local",
			Status:       HealthStatusHealthy,
			LastCheck:    time.Now(),
			ResponseTime: 10 * time.Millisecond,
			ErrorRate:    0.0,
			Availability: 100.0,
		},
	}
	
	// Calculate storage metrics
	hm.storageHealth.TotalStorageUsed = hm.calculateTotalStorageUsed()
	hm.storageHealth.CompressionRatio = hm.calculateCompressionRatio()
	hm.storageHealth.RetentionCompliance = hm.calculateRetentionCompliance()
	
	// Determine storage health status
	if hm.storageHealth.PrimaryBackend.Status != HealthStatusHealthy {
		hm.storageHealth.Status = HealthStatusDegraded
	}
	
	if hm.storageHealth.RetentionCompliance < 0.95 {
		hm.storageHealth.Status = HealthStatusDegraded
	}
}

// checkDatabaseHealth checks individual database health
func (hm *HealthMonitor) checkDatabaseHealth(database string) DatabaseHealth {
	start := time.Now()
	
	// This would perform actual database connectivity check
	// For now, simulate healthy status
	responseTime := time.Since(start)
	
	return DatabaseHealth{
		Status:       HealthStatusHealthy,
		LastCheck:    time.Now(),
		ResponseTime: responseTime,
		ErrorRate:    0.0,
		ConnectionPool: ConnectionPoolHealth{
			ActiveConnections: 5,
			IdleConnections:   10,
			MaxConnections:    50,
			UtilizationRate:   0.3,
		},
	}
}

// calculateOverallHealth calculates the overall system health
func (hm *HealthMonitor) calculateOverallHealth() HealthStatusType {
	// Weighted health calculation
	systemWeight := 0.3
	backupWeight := 0.5
	storageWeight := 0.2
	
	systemScore := hm.healthStatusToScore(hm.systemHealth.Status)
	backupScore := hm.healthStatusToScore(hm.backupHealth.Status)
	storageScore := hm.healthStatusToScore(hm.storageHealth.Status)
	
	overallScore := systemWeight*systemScore + backupWeight*backupScore + storageWeight*storageScore
	
	if overallScore >= 0.9 {
		return HealthStatusHealthy
	} else if overallScore >= 0.7 {
		return HealthStatusDegraded
	} else {
		return HealthStatusUnhealthy
	}
}

// GetHealthStatus returns the current health status
func (hm *HealthMonitor) GetHealthStatus() *HealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	overallStatus := hm.calculateOverallHealth()
	
	status := &HealthStatus{
		OverallStatus: overallStatus,
		LastCheck:     hm.lastHealthCheck,
		System:        hm.systemHealth,
		Backup:        hm.backupHealth,
		Storage:       hm.storageHealth,
		HealthScore:   hm.calculateHealthScore(),
		Issues:        hm.identifyHealthIssues(),
		Recommendations: hm.generateRecommendations(),
	}
	
	return status
}

// Close stops the health monitor
func (hm *HealthMonitor) Close() error {
	hm.mu.Lock()
	hm.closed = true
	hm.mu.Unlock()
	
	if hm.alertManager != nil {
		hm.alertManager.Close()
	}
	
	hm.logger.Info("Health monitor closed")
	return nil
}

// Helper methods for health calculations

func (hm *HealthMonitor) healthStatusToScore(status HealthStatusType) float64 {
	switch status {
	case HealthStatusHealthy:
		return 1.0
	case HealthStatusDegraded:
		return 0.7
	case HealthStatusUnhealthy:
		return 0.3
	default:
		return 0.0
	}
}

func (hm *HealthMonitor) calculateHealthScore() float64 {
	systemScore := hm.healthStatusToScore(hm.systemHealth.Status)
	backupScore := hm.healthStatusToScore(hm.backupHealth.Status)
	storageScore := hm.healthStatusToScore(hm.storageHealth.Status)
	
	return (systemScore + backupScore + storageScore) / 3.0 * 100.0
}

func (hm *HealthMonitor) identifyHealthIssues() []HealthIssue {
	var issues []HealthIssue
	
	// Check for system issues
	if hm.systemHealth.CPUUsage > 90 {
		issues = append(issues, HealthIssue{
			Severity:    "warning",
			Component:   "system",
			Title:       "High CPU Usage",
			Description: fmt.Sprintf("CPU usage is %.1f%%, exceeding 90%% threshold", hm.systemHealth.CPUUsage),
			DetectedAt:  time.Now(),
			Resolution:  "Consider scaling resources or optimizing backup operations",
		})
	}
	
	// Check for backup issues
	if hm.backupHealth.SuccessRate24h < 0.95 {
		issues = append(issues, HealthIssue{
			Severity:    "critical",
			Component:   "backup",
			Title:       "Low Backup Success Rate",
			Description: fmt.Sprintf("Backup success rate is %.1f%%, below 95%% threshold", hm.backupHealth.SuccessRate24h*100),
			DetectedAt:  time.Now(),
			Resolution:  "Investigate backup failures and address underlying issues",
		})
	}
	
	return issues
}

func (hm *HealthMonitor) generateRecommendations() []string {
	var recommendations []string
	
	if hm.systemHealth.MemoryUsage > 80 {
		recommendations = append(recommendations, "Consider increasing memory allocation for backup operations")
	}
	
	if hm.backupHealth.AverageBackupTime > hm.config.BackupSLA {
		recommendations = append(recommendations, "Optimize backup operations to meet SLA requirements")
	}
	
	if hm.storageHealth.CompressionRatio < 0.3 {
		recommendations = append(recommendations, "Enable or improve compression to reduce storage costs")
	}
	
	return recommendations
}

func (hm *HealthMonitor) triggerAlert(message, severity string) {
	if hm.config.AlertingEnabled && hm.alertManager != nil {
		hm.alertManager.TriggerAlert(message, severity)
	}
}

// Placeholder methods for system metrics (would integrate with actual monitoring)
func (hm *HealthMonitor) getCPUUsage() float64 {
	return 45.0 // Placeholder
}

func (hm *HealthMonitor) getMemoryUsage() float64 {
	return 60.0 // Placeholder
}

func (hm *HealthMonitor) getDiskUsage() float64 {
	return 35.0 // Placeholder
}

func (hm *HealthMonitor) getNetworkIOStats() NetworkIOStats {
	return NetworkIOStats{
		BytesReceived:   1024000,
		BytesSent:       2048000,
		PacketsReceived: 1500,
		PacketsSent:     3000,
		Throughput:      100.0,
	}
}

// Placeholder methods for backup metrics calculations
func (hm *HealthMonitor) calculateBackupSLACompliance(metrics *BackupMetricsData) float64 {
	return 0.98 // 98% compliance
}

func (hm *HealthMonitor) calculateRestoreSLACompliance(metrics *BackupMetricsData) float64 {
	return 0.95 // 95% compliance
}

func (hm *HealthMonitor) calculateRPOCompliance(metrics *BackupMetricsData) float64 {
	return 0.99 // 99% compliance
}

func (hm *HealthMonitor) calculateRTOCompliance(metrics *BackupMetricsData) float64 {
	return 0.96 // 96% compliance
}

func (hm *HealthMonitor) calculateSuccessRate24h(metrics *BackupMetricsData) float64 {
	return 0.97 // 97% success rate
}

func (hm *HealthMonitor) getFailedBackups24h(metrics *BackupMetricsData) int {
	return 2 // 2 failed backups in 24h
}

func (hm *HealthMonitor) calculateTotalStorageUsed() int64 {
	return 1024 * 1024 * 1024 * 100 // 100 GB
}

func (hm *HealthMonitor) calculateCompressionRatio() float64 {
	return 0.65 // 65% compression ratio
}

func (hm *HealthMonitor) calculateRetentionCompliance() float64 {
	return 0.98 // 98% retention compliance
}