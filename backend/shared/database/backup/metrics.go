package backup

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// BackupMetrics collects and manages backup operation metrics
type BackupMetrics struct {
	logger *zap.Logger
	
	// Metrics data
	data *BackupMetricsData
	mu   sync.RWMutex
	
	// Metric collection
	operationHistory []OperationMetric
	historySize      int
	
	// Time windows for aggregation
	hourlyMetrics  map[string]*TimeWindowMetrics
	dailyMetrics   map[string]*TimeWindowMetrics
	weeklyMetrics  map[string]*TimeWindowMetrics
	monthlyMetrics map[string]*TimeWindowMetrics
}

// BackupMetricsData contains all collected metrics
type BackupMetricsData struct {
	// Overall statistics
	TotalBackups         int64                    `json:"total_backups"`
	SuccessfulBackups    int64                    `json:"successful_backups"`
	FailedBackups        int64                    `json:"failed_backups"`
	TotalDataBackedUp    int64                    `json:"total_data_backed_up"`    // bytes
	TotalDataRestored    int64                    `json:"total_data_restored"`     // bytes
	
	// Performance metrics
	AverageBackupTime    time.Duration            `json:"average_backup_time"`
	AverageRestoreTime   time.Duration            `json:"average_restore_time"`
	AverageCompressionRatio float64               `json:"average_compression_ratio"`
	AverageThroughput    float64                  `json:"average_throughput"`      // MB/s
	
	// Database-specific metrics
	DatabaseMetrics      map[string]*DatabaseMetrics `json:"database_metrics"`
	
	// SLA compliance
	BackupSLAViolations  int64                    `json:"backup_sla_violations"`
	RestoreSLAViolations int64                    `json:"restore_sla_violations"`
	RPOViolations        int64                    `json:"rpo_violations"`
	RTOViolations        int64                    `json:"rto_violations"`
	
	// Storage metrics
	StorageMetrics       *StorageMetrics          `json:"storage_metrics"`
	
	// Error analytics
	ErrorMetrics         *ErrorMetrics            `json:"error_metrics"`
	
	// Real-time statistics
	ActiveOperations     int                      `json:"active_operations"`
	QueuedOperations     int                      `json:"queued_operations"`
	
	// Last update timestamp
	LastUpdate           time.Time                `json:"last_update"`
}

// DatabaseMetrics contains metrics for a specific database
type DatabaseMetrics struct {
	Database             string        `json:"database"`
	TotalBackups         int64         `json:"total_backups"`
	SuccessfulBackups    int64         `json:"successful_backups"`
	FailedBackups        int64         `json:"failed_backups"`
	AverageBackupTime    time.Duration `json:"average_backup_time"`
	AverageDataSize      int64         `json:"average_data_size"`
	LastBackupTime       *time.Time    `json:"last_backup_time,omitempty"`
	LastSuccessfulBackup *time.Time    `json:"last_successful_backup,omitempty"`
	LastFailedBackup     *time.Time    `json:"last_failed_backup,omitempty"`
	CompressionRatio     float64       `json:"compression_ratio"`
}

// StorageMetrics contains storage-related metrics
type StorageMetrics struct {
	TotalStorageUsed     int64                           `json:"total_storage_used"`
	StorageByDatabase    map[string]int64                `json:"storage_by_database"`
	StorageByBackend     map[string]int64                `json:"storage_by_backend"`
	StorageGrowthRate    float64                         `json:"storage_growth_rate"`    // bytes/day
	CostMetrics          *StorageCostMetrics             `json:"cost_metrics"`
	RetentionMetrics     *RetentionMetrics               `json:"retention_metrics"`
}

// StorageCostMetrics contains cost-related storage metrics
type StorageCostMetrics struct {
	EstimatedMonthlyCost float64            `json:"estimated_monthly_cost"`
	CostPerGB            float64            `json:"cost_per_gb"`
	CostByBackend        map[string]float64 `json:"cost_by_backend"`
	OptimizationSavings  float64            `json:"optimization_savings"`
}

// RetentionMetrics contains backup retention metrics
type RetentionMetrics struct {
	BackupsToExpire      int       `json:"backups_to_expire"`
	ExpiredBackups       int       `json:"expired_backups"`
	OverRetentionData    int64     `json:"over_retention_data"`    // bytes
	NextExpiryDate       time.Time `json:"next_expiry_date"`
	RetentionCompliance  float64   `json:"retention_compliance"`   // percentage
}

// ErrorMetrics contains error analytics
type ErrorMetrics struct {
	ErrorsByType         map[string]int64       `json:"errors_by_type"`
	ErrorsByDatabase     map[string]int64       `json:"errors_by_database"`
	ErrorsByTimeOfDay    map[int]int64          `json:"errors_by_time_of_day"`
	RecentErrors         []ErrorRecord          `json:"recent_errors"`
	MTBF                 time.Duration          `json:"mtbf"`               // Mean Time Between Failures
	MTTR                 time.Duration          `json:"mttr"`               // Mean Time To Recovery
}

// ErrorRecord represents a single error occurrence
type ErrorRecord struct {
	Timestamp    time.Time `json:"timestamp"`
	Database     string    `json:"database"`
	Operation    string    `json:"operation"`
	ErrorType    string    `json:"error_type"`
	ErrorMessage string    `json:"error_message"`
	Duration     time.Duration `json:"duration"`
	Severity     string    `json:"severity"`
}

// OperationMetric represents metrics for a single operation
type OperationMetric struct {
	Timestamp      time.Time     `json:"timestamp"`
	Database       string        `json:"database"`
	OperationType  string        `json:"operation_type"`
	Success        bool          `json:"success"`
	Duration       time.Duration `json:"duration"`
	DataSize       int64         `json:"data_size"`
	CompressionRatio float64     `json:"compression_ratio"`
	Throughput     float64       `json:"throughput"`
	ErrorType      string        `json:"error_type,omitempty"`
	ErrorMessage   string        `json:"error_message,omitempty"`
}

// TimeWindowMetrics contains metrics for a specific time window
type TimeWindowMetrics struct {
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
	TotalOperations   int64         `json:"total_operations"`
	SuccessfulOps     int64         `json:"successful_ops"`
	FailedOps         int64         `json:"failed_ops"`
	SuccessRate       float64       `json:"success_rate"`
	AverageDuration   time.Duration `json:"average_duration"`
	TotalDataProcessed int64        `json:"total_data_processed"`
	AverageThroughput float64       `json:"average_throughput"`
}

// NewBackupMetrics creates a new backup metrics collector
func NewBackupMetrics(logger *zap.Logger) *BackupMetrics {
	return &BackupMetrics{
		logger: logger,
		data: &BackupMetricsData{
			DatabaseMetrics: make(map[string]*DatabaseMetrics),
			StorageMetrics: &StorageMetrics{
				StorageByDatabase: make(map[string]int64),
				StorageByBackend:  make(map[string]int64),
				CostMetrics: &StorageCostMetrics{
					CostByBackend: make(map[string]float64),
				},
				RetentionMetrics: &RetentionMetrics{},
			},
			ErrorMetrics: &ErrorMetrics{
				ErrorsByType:      make(map[string]int64),
				ErrorsByDatabase:  make(map[string]int64),
				ErrorsByTimeOfDay: make(map[int]int64),
				RecentErrors:      make([]ErrorRecord, 0),
			},
		},
		operationHistory: make([]OperationMetric, 0),
		historySize:      10000, // Keep last 10k operations
		hourlyMetrics:    make(map[string]*TimeWindowMetrics),
		dailyMetrics:     make(map[string]*TimeWindowMetrics),
		weeklyMetrics:    make(map[string]*TimeWindowMetrics),
		monthlyMetrics:   make(map[string]*TimeWindowMetrics),
	}
}

// RecordBackupStart records the start of a backup operation
func (bm *BackupMetrics) RecordBackupStart(database, backupType string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	bm.data.ActiveOperations++
	bm.data.LastUpdate = time.Now()
	
	// Initialize database metrics if not exists
	if _, exists := bm.data.DatabaseMetrics[database]; !exists {
		bm.data.DatabaseMetrics[database] = &DatabaseMetrics{
			Database: database,
		}
	}
	
	bm.logger.Debug("Backup operation started",
		zap.String("database", database),
		zap.String("type", backupType),
		zap.Int("active_operations", bm.data.ActiveOperations),
	)
}

// RecordBackupSuccess records a successful backup operation
func (bm *BackupMetrics) RecordBackupSuccess(database, backupType string, duration time.Duration, dataSize int64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	now := time.Now()
	
	// Update overall metrics
	bm.data.TotalBackups++
	bm.data.SuccessfulBackups++
	bm.data.TotalDataBackedUp += dataSize
	bm.data.ActiveOperations--
	bm.data.LastUpdate = now
	
	// Update database-specific metrics
	dbMetrics := bm.data.DatabaseMetrics[database]
	dbMetrics.TotalBackups++
	dbMetrics.SuccessfulBackups++
	dbMetrics.LastBackupTime = &now
	dbMetrics.LastSuccessfulBackup = &now
	
	// Update average calculations
	bm.updateAverageBackupTime(duration)
	bm.updateAverageDataSize(database, dataSize)
	
	// Calculate throughput (MB/s)
	throughput := float64(dataSize) / float64(duration.Seconds()) / (1024 * 1024)
	
	// Record operation metric
	metric := OperationMetric{
		Timestamp:     now,
		Database:      database,
		OperationType: backupType,
		Success:       true,
		Duration:      duration,
		DataSize:      dataSize,
		Throughput:    throughput,
	}
	bm.addOperationHistory(metric)
	
	// Update time window metrics
	bm.updateTimeWindowMetrics(metric)
	
	bm.logger.Info("Backup operation completed successfully",
		zap.String("database", database),
		zap.String("type", backupType),
		zap.Duration("duration", duration),
		zap.Int64("data_size", dataSize),
		zap.Float64("throughput_mbps", throughput),
	)
}

// RecordBackupFailure records a failed backup operation
func (bm *BackupMetrics) RecordBackupFailure(database, backupType, errorType string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	now := time.Now()
	
	// Update overall metrics
	bm.data.TotalBackups++
	bm.data.FailedBackups++
	bm.data.ActiveOperations--
	bm.data.LastUpdate = now
	
	// Update database-specific metrics
	dbMetrics := bm.data.DatabaseMetrics[database]
	dbMetrics.TotalBackups++
	dbMetrics.FailedBackups++
	dbMetrics.LastBackupTime = &now
	dbMetrics.LastFailedBackup = &now
	
	// Update error metrics
	bm.data.ErrorMetrics.ErrorsByType[errorType]++
	bm.data.ErrorMetrics.ErrorsByDatabase[database]++
	
	// Add to recent errors
	errorRecord := ErrorRecord{
		Timestamp:    now,
		Database:     database,
		Operation:    backupType,
		ErrorType:    errorType,
		Severity:     "error",
	}
	bm.addRecentError(errorRecord)
	
	// Record operation metric
	metric := OperationMetric{
		Timestamp:     now,
		Database:      database,
		OperationType: backupType,
		Success:       false,
		ErrorType:     errorType,
	}
	bm.addOperationHistory(metric)
	
	bm.logger.Error("Backup operation failed",
		zap.String("database", database),
		zap.String("type", backupType),
		zap.String("error_type", errorType),
	)
}

// RecordRestoreSuccess records a successful restore operation
func (bm *BackupMetrics) RecordRestoreSuccess(database string, duration time.Duration, dataSize int64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	bm.data.TotalDataRestored += dataSize
	bm.updateAverageRestoreTime(duration)
	bm.data.LastUpdate = time.Now()
	
	// Calculate throughput
	throughput := float64(dataSize) / float64(duration.Seconds()) / (1024 * 1024)
	
	bm.logger.Info("Restore operation completed successfully",
		zap.String("database", database),
		zap.Duration("duration", duration),
		zap.Int64("data_size", dataSize),
		zap.Float64("throughput_mbps", throughput),
	)
}

// RecordSLAViolation records an SLA violation
func (bm *BackupMetrics) RecordSLAViolation(violationType string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	switch violationType {
	case "backup":
		bm.data.BackupSLAViolations++
	case "restore":
		bm.data.RestoreSLAViolations++
	case "rpo":
		bm.data.RPOViolations++
	case "rto":
		bm.data.RTOViolations++
	}
	
	bm.data.LastUpdate = time.Now()
	
	bm.logger.Warn("SLA violation recorded",
		zap.String("type", violationType),
	)
}

// UpdateStorageMetrics updates storage-related metrics
func (bm *BackupMetrics) UpdateStorageMetrics(database string, backend string, storageUsed int64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	bm.data.StorageMetrics.StorageByDatabase[database] = storageUsed
	bm.data.StorageMetrics.StorageByBackend[backend] += storageUsed
	
	// Recalculate total storage
	total := int64(0)
	for _, size := range bm.data.StorageMetrics.StorageByDatabase {
		total += size
	}
	bm.data.StorageMetrics.TotalStorageUsed = total
	
	bm.data.LastUpdate = time.Now()
}

// GetMetrics returns the current metrics data
func (bm *BackupMetrics) GetMetrics() *BackupMetricsData {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	data := *bm.data
	return &data
}

// GetTimeWindowMetrics returns metrics for a specific time window
func (bm *BackupMetrics) GetTimeWindowMetrics(window string, startTime time.Time) *TimeWindowMetrics {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	key := bm.getTimeWindowKey(window, startTime)
	
	switch window {
	case "hour":
		return bm.hourlyMetrics[key]
	case "day":
		return bm.dailyMetrics[key]
	case "week":
		return bm.weeklyMetrics[key]
	case "month":
		return bm.monthlyMetrics[key]
	default:
		return nil
	}
}

// GetDatabaseMetrics returns metrics for a specific database
func (bm *BackupMetrics) GetDatabaseMetrics(database string) *DatabaseMetrics {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	if metrics, exists := bm.data.DatabaseMetrics[database]; exists {
		// Return a copy
		metricsCopy := *metrics
		return &metricsCopy
	}
	
	return nil
}

// CollectSystemMetrics collects system-level metrics
func (bm *BackupMetrics) CollectSystemMetrics() {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	// This would integrate with system monitoring tools
	// For now, update timestamp
	bm.data.LastUpdate = time.Now()
	
	// Calculate derived metrics
	bm.calculateSuccessRates()
	bm.calculateMTBFMTTR()
	bm.cleanupOldMetrics()
}

// Private helper methods

func (bm *BackupMetrics) updateAverageBackupTime(duration time.Duration) {
	if bm.data.SuccessfulBackups == 1 {
		bm.data.AverageBackupTime = duration
	} else {
		// Running average
		currentAvg := bm.data.AverageBackupTime
		newAvg := time.Duration(int64(currentAvg) + (int64(duration)-int64(currentAvg))/int64(bm.data.SuccessfulBackups))
		bm.data.AverageBackupTime = newAvg
	}
}

func (bm *BackupMetrics) updateAverageRestoreTime(duration time.Duration) {
	// Simple implementation - would need to track restore count separately
	bm.data.AverageRestoreTime = duration
}

func (bm *BackupMetrics) updateAverageDataSize(database string, dataSize int64) {
	dbMetrics := bm.data.DatabaseMetrics[database]
	if dbMetrics.SuccessfulBackups == 1 {
		dbMetrics.AverageDataSize = dataSize
	} else {
		// Running average
		currentAvg := dbMetrics.AverageDataSize
		newAvg := currentAvg + (dataSize-currentAvg)/dbMetrics.SuccessfulBackups
		dbMetrics.AverageDataSize = newAvg
	}
}

func (bm *BackupMetrics) addOperationHistory(metric OperationMetric) {
	bm.operationHistory = append(bm.operationHistory, metric)
	
	// Keep only the last N operations
	if len(bm.operationHistory) > bm.historySize {
		bm.operationHistory = bm.operationHistory[1:]
	}
}

func (bm *BackupMetrics) addRecentError(errorRecord ErrorRecord) {
	bm.data.ErrorMetrics.RecentErrors = append(bm.data.ErrorMetrics.RecentErrors, errorRecord)
	
	// Keep only the last 100 errors
	if len(bm.data.ErrorMetrics.RecentErrors) > 100 {
		bm.data.ErrorMetrics.RecentErrors = bm.data.ErrorMetrics.RecentErrors[1:]
	}
	
	// Update hourly error tracking
	hour := errorRecord.Timestamp.Hour()
	bm.data.ErrorMetrics.ErrorsByTimeOfDay[hour]++
}

func (bm *BackupMetrics) updateTimeWindowMetrics(metric OperationMetric) {
	// Update hourly metrics
	hourKey := bm.getTimeWindowKey("hour", metric.Timestamp)
	if _, exists := bm.hourlyMetrics[hourKey]; !exists {
		bm.hourlyMetrics[hourKey] = &TimeWindowMetrics{
			StartTime: metric.Timestamp.Truncate(time.Hour),
			EndTime:   metric.Timestamp.Truncate(time.Hour).Add(time.Hour),
		}
	}
	bm.updateTimeWindowMetric(bm.hourlyMetrics[hourKey], metric)
	
	// Update daily metrics
	dayKey := bm.getTimeWindowKey("day", metric.Timestamp)
	if _, exists := bm.dailyMetrics[dayKey]; !exists {
		startOfDay := time.Date(metric.Timestamp.Year(), metric.Timestamp.Month(), metric.Timestamp.Day(), 0, 0, 0, 0, metric.Timestamp.Location())
		bm.dailyMetrics[dayKey] = &TimeWindowMetrics{
			StartTime: startOfDay,
			EndTime:   startOfDay.Add(24 * time.Hour),
		}
	}
	bm.updateTimeWindowMetric(bm.dailyMetrics[dayKey], metric)
}

func (bm *BackupMetrics) updateTimeWindowMetric(window *TimeWindowMetrics, metric OperationMetric) {
	window.TotalOperations++
	window.TotalDataProcessed += metric.DataSize
	
	if metric.Success {
		window.SuccessfulOps++
	} else {
		window.FailedOps++
	}
	
	// Update success rate
	window.SuccessRate = float64(window.SuccessfulOps) / float64(window.TotalOperations)
	
	// Update average duration (running average)
	if window.TotalOperations == 1 {
		window.AverageDuration = metric.Duration
		window.AverageThroughput = metric.Throughput
	} else {
		currentAvgDuration := window.AverageDuration
		newAvgDuration := time.Duration(int64(currentAvgDuration) + (int64(metric.Duration)-int64(currentAvgDuration))/window.TotalOperations)
		window.AverageDuration = newAvgDuration
		
		currentAvgThroughput := window.AverageThroughput
		newAvgThroughput := currentAvgThroughput + (metric.Throughput-currentAvgThroughput)/float64(window.TotalOperations)
		window.AverageThroughput = newAvgThroughput
	}
}

func (bm *BackupMetrics) getTimeWindowKey(window string, timestamp time.Time) string {
	switch window {
	case "hour":
		return timestamp.Format("2006-01-02-15")
	case "day":
		return timestamp.Format("2006-01-02")
	case "week":
		year, week := timestamp.ISOWeek()
		return fmt.Sprintf("%d-W%02d", year, week)
	case "month":
		return timestamp.Format("2006-01")
	default:
		return ""
	}
}

func (bm *BackupMetrics) calculateSuccessRates() {
	// Calculate overall success rate
	if bm.data.TotalBackups > 0 {
		// Update database success rates
		for _, dbMetrics := range bm.data.DatabaseMetrics {
			if dbMetrics.TotalBackups > 0 {
				// Success rate calculation is implicit in the ratio of successful to total
			}
		}
	}
}

func (bm *BackupMetrics) calculateMTBFMTTR() {
	// Calculate Mean Time Between Failures and Mean Time To Recovery
	// This would analyze the operation history to calculate these metrics
	// For now, set placeholder values
	bm.data.ErrorMetrics.MTBF = 24 * time.Hour    // 24 hours between failures
	bm.data.ErrorMetrics.MTTR = 30 * time.Minute  // 30 minutes to recover
}

func (bm *BackupMetrics) cleanupOldMetrics() {
	now := time.Now()
	
	// Remove hourly metrics older than 7 days
	cutoffHour := now.Add(-7 * 24 * time.Hour)
	for key, metrics := range bm.hourlyMetrics {
		if metrics.StartTime.Before(cutoffHour) {
			delete(bm.hourlyMetrics, key)
		}
	}
	
	// Remove daily metrics older than 90 days
	cutoffDay := now.Add(-90 * 24 * time.Hour)
	for key, metrics := range bm.dailyMetrics {
		if metrics.StartTime.Before(cutoffDay) {
			delete(bm.dailyMetrics, key)
		}
	}
	
	// Remove weekly metrics older than 1 year
	cutoffWeek := now.Add(-365 * 24 * time.Hour)
	for key, metrics := range bm.weeklyMetrics {
		if metrics.StartTime.Before(cutoffWeek) {
			delete(bm.weeklyMetrics, key)
		}
	}
}

// AlertManager handles backup-related alerts
type AlertManager struct {
	config BackupMonitoringConfig
	logger *zap.Logger
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config BackupMonitoringConfig, logger *zap.Logger) *AlertManager {
	return &AlertManager{
		config: config,
		logger: logger,
	}
}

// TriggerAlert triggers an alert with the specified message and severity
func (am *AlertManager) TriggerAlert(message, severity string) {
	if !am.config.AlertingEnabled {
		return
	}
	
	am.logger.Warn("Alert triggered",
		zap.String("message", message),
		zap.String("severity", severity),
		zap.Strings("endpoints", am.config.AlertEndpoints),
	)
	
	// Here you would integrate with actual alerting systems
	// For example: PagerDuty, Slack, email, webhook endpoints, etc.
}

// Close closes the alert manager
func (am *AlertManager) Close() {
	am.logger.Info("Alert manager closed")
}