package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ScheduledReportingEngine manages scheduled reports and alerts
type ScheduledReportingEngine struct {
	logger         *zap.Logger
	config         *ReportingConfig
	
	// Query engine for data retrieval
	queryEngine    QueryEngine
	
	// Template engine for report generation
	templateEngine *TemplateEngine
	
	// Notification system
	notificationService NotificationService
	
	// Scheduled jobs
	scheduledJobs  map[string]*ScheduledJob
	jobMutex       sync.RWMutex
	
	// Background processing
	ctx            context.Context
	cancel         context.CancelFunc
	scheduler      *JobScheduler
	
	// Statistics
	stats          *ReportingStats
	statsMutex     sync.RWMutex
}

// ReportingConfig defines reporting engine configuration
type ReportingConfig struct {
	// Scheduling settings
	MaxConcurrentJobs    int           `json:"max_concurrent_jobs"`
	JobTimeout          time.Duration `json:"job_timeout"`
	RetryAttempts       int           `json:"retry_attempts"`
	RetryDelay          time.Duration `json:"retry_delay"`
	
	// Storage settings
	ReportStoragePath   string        `json:"report_storage_path"`
	MaxReportAge        time.Duration `json:"max_report_age"`
	CompressionEnabled  bool          `json:"compression_enabled"`
	
	// Notification settings
	EmailEnabled        bool          `json:"email_enabled"`
	SlackEnabled        bool          `json:"slack_enabled"`
	WebhookEnabled      bool          `json:"webhook_enabled"`
	
	// Template settings
	TemplateDirectory   string        `json:"template_directory"`
	CustomTemplates     bool          `json:"custom_templates"`
	
	// Performance settings
	QueryTimeout        time.Duration `json:"query_timeout"`
	MaxDataPoints       int           `json:"max_data_points"`
	CacheEnabled        bool          `json:"cache_enabled"`
	MetricsEnabled      bool          `json:"metrics_enabled"`
}

// QueryEngine interface for data retrieval
type QueryEngine interface {
	ExecuteQuery(ctx context.Context, query interface{}) (interface{}, error)
	IsHealthy() bool
}

// NotificationService interface for sending notifications
type NotificationService interface {
	SendEmail(ctx context.Context, email *EmailNotification) error
	SendSlack(ctx context.Context, slack *SlackNotification) error
	SendWebhook(ctx context.Context, webhook *WebhookNotification) error
	IsHealthy() bool
}

// ScheduledJob represents a scheduled reporting job
type ScheduledJob struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Type             string                 `json:"type"` // report, alert, dashboard_export
	
	// Scheduling
	Schedule         string                 `json:"schedule"` // cron expression
	Timezone         string                 `json:"timezone"`
	Enabled          bool                   `json:"enabled"`
	
	// Report configuration
	ReportConfig     *ReportConfiguration   `json:"report_config"`
	
	// Notification configuration
	Notifications    []NotificationConfig   `json:"notifications"`
	
	// Execution tracking
	LastRun          time.Time              `json:"last_run"`
	NextRun          time.Time              `json:"next_run"`
	Status           string                 `json:"status"` // pending, running, completed, failed
	RunCount         int64                  `json:"run_count"`
	FailureCount     int64                  `json:"failure_count"`
	LastError        string                 `json:"last_error,omitempty"`
	
	// Metadata
	CreatedBy        string                 `json:"created_by"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	Tags             []string               `json:"tags"`
}

// ReportConfiguration defines report generation settings
type ReportConfiguration struct {
	// Data settings
	DataSources      []DataSource           `json:"data_sources"`
	TimeRange        *TimeRange             `json:"time_range"`
	Filters          map[string]interface{} `json:"filters"`
	
	// Output settings
	Format           string                 `json:"format"` // pdf, html, csv, json, excel
	Template         string                 `json:"template"`
	IncludeCharts    bool                   `json:"include_charts"`
	IncludeTables    bool                   `json:"include_tables"`
	IncludeMetrics   bool                   `json:"include_metrics"`
	
	// Customization
	Title            string                 `json:"title"`
	Subtitle         string                 `json:"subtitle"`
	CustomFields     map[string]interface{} `json:"custom_fields"`
	Branding         *BrandingConfig        `json:"branding"`
}

// DataSource defines a data source for reports
type DataSource struct {
	Name             string                 `json:"name"`
	Type             string                 `json:"type"` // elasticsearch, timescale, custom
	Query            interface{}            `json:"query"`
	Aggregations     map[string]interface{} `json:"aggregations"`
	ChartType        string                 `json:"chart_type"` // line, bar, pie, table
	ChartConfig      map[string]interface{} `json:"chart_config"`
}

// TimeRange defines time range for reports
type TimeRange struct {
	From             interface{} `json:"from"` // timestamp or relative
	To               interface{} `json:"to"`   // timestamp or relative
	Relative         string      `json:"relative,omitempty"` // last_hour, last_day, last_week
	Timezone         string      `json:"timezone"`
}

// BrandingConfig defines branding settings
type BrandingConfig struct {
	Logo             string `json:"logo"`
	Colors           map[string]string `json:"colors"`
	Fonts            map[string]string `json:"fonts"`
	CompanyName      string `json:"company_name"`
	Footer           string `json:"footer"`
}

// NotificationConfig defines notification settings
type NotificationConfig struct {
	Type             string                 `json:"type"` // email, slack, webhook
	Recipients       []string               `json:"recipients"`
	Subject          string                 `json:"subject"`
	Template         string                 `json:"template"`
	Conditions       []NotificationCondition `json:"conditions"`
	Enabled          bool                   `json:"enabled"`
}

// NotificationCondition defines when to send notifications
type NotificationCondition struct {
	Field            string      `json:"field"`
	Operator         string      `json:"operator"` // gt, lt, eq, contains
	Value            interface{} `json:"value"`
	Severity         string      `json:"severity"` // low, medium, high, critical
}

// EmailNotification represents an email notification
type EmailNotification struct {
	To               []string               `json:"to"`
	CC               []string               `json:"cc,omitempty"`
	BCC              []string               `json:"bcc,omitempty"`
	Subject          string                 `json:"subject"`
	Body             string                 `json:"body"`
	HTMLBody         string                 `json:"html_body,omitempty"`
	Attachments      []NotificationAttachment `json:"attachments,omitempty"`
}

// SlackNotification represents a Slack notification
type SlackNotification struct {
	Channel          string                 `json:"channel"`
	Message          string                 `json:"message"`
	Attachments      []SlackAttachment      `json:"attachments,omitempty"`
	Webhook          string                 `json:"webhook"`
}

// WebhookNotification represents a webhook notification
type WebhookNotification struct {
	URL              string                 `json:"url"`
	Method           string                 `json:"method"`
	Headers          map[string]string      `json:"headers"`
	Body             interface{}            `json:"body"`
	Authentication   *WebhookAuth           `json:"authentication,omitempty"`
}

// NotificationAttachment represents a notification attachment
type NotificationAttachment struct {
	Filename         string `json:"filename"`
	ContentType      string `json:"content_type"`
	Data             []byte `json:"data"`
}

// SlackAttachment represents a Slack attachment
type SlackAttachment struct {
	Color            string `json:"color"`
	Title            string `json:"title"`
	Text             string `json:"text"`
	Fields           []SlackField `json:"fields"`
}

// SlackField represents a Slack field
type SlackField struct {
	Title            string `json:"title"`
	Value            string `json:"value"`
	Short            bool   `json:"short"`
}

// WebhookAuth represents webhook authentication
type WebhookAuth struct {
	Type             string `json:"type"` // basic, bearer, api_key
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	Token            string `json:"token,omitempty"`
	APIKey           string `json:"api_key,omitempty"`
	APIKeyHeader     string `json:"api_key_header,omitempty"`
}

// JobScheduler handles job scheduling
type JobScheduler struct {
	logger           *zap.Logger
	jobs             map[string]*ScheduledJob
	jobMutex         sync.RWMutex
	workers          chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
}

// TemplateEngine handles report template processing
type TemplateEngine struct {
	logger           *zap.Logger
	templates        map[string]*template.Template
	templateMutex    sync.RWMutex
	templateDir      string
}

// ReportingStats tracks reporting statistics
type ReportingStats struct {
	TotalJobs        int64         `json:"total_jobs"`
	ActiveJobs       int64         `json:"active_jobs"`
	CompletedJobs    int64         `json:"completed_jobs"`
	FailedJobs       int64         `json:"failed_jobs"`
	TotalReports     int64         `json:"total_reports"`
	TotalAlerts      int64         `json:"total_alerts"`
	AverageRunTime   time.Duration `json:"average_run_time"`
	LastJobRun       time.Time     `json:"last_job_run"`
}

// NewScheduledReportingEngine creates a new reporting engine
func NewScheduledReportingEngine(logger *zap.Logger, config *ReportingConfig, queryEngine QueryEngine, notificationService NotificationService) (*ScheduledReportingEngine, error) {
	if config == nil {
		return nil, fmt.Errorf("reporting configuration is required")
	}
	
	// Set defaults
	if err := setReportingDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &ScheduledReportingEngine{
		logger:              logger.With(zap.String("component", "scheduled-reporting-engine")),
		config:              config,
		queryEngine:         queryEngine,
		notificationService: notificationService,
		scheduledJobs:       make(map[string]*ScheduledJob),
		stats:               &ReportingStats{},
		ctx:                 ctx,
		cancel:              cancel,
	}
	
	// Initialize template engine
	templateEngine, err := NewTemplateEngine(logger, config.TemplateDirectory)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize template engine: %w", err)
	}
	engine.templateEngine = templateEngine
	
	// Initialize job scheduler
	scheduler, err := NewJobScheduler(logger, config.MaxConcurrentJobs, ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize job scheduler: %w", err)
	}
	engine.scheduler = scheduler
	
	// Start background processing
	go engine.runJobScheduler()
	
	logger.Info("Scheduled reporting engine initialized",
		zap.Int("max_concurrent_jobs", config.MaxConcurrentJobs),
		zap.Duration("job_timeout", config.JobTimeout),
		zap.String("report_storage_path", config.ReportStoragePath),
	)
	
	return engine, nil
}

// setReportingDefaults sets configuration defaults
func setReportingDefaults(config *ReportingConfig) error {
	if config.MaxConcurrentJobs == 0 {
		config.MaxConcurrentJobs = 5
	}
	if config.JobTimeout == 0 {
		config.JobTimeout = 30 * time.Minute
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Minute
	}
	if config.ReportStoragePath == "" {
		config.ReportStoragePath = "/data/reports"
	}
	if config.MaxReportAge == 0 {
		config.MaxReportAge = 90 * 24 * time.Hour // 90 days
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = 10 * time.Minute
	}
	if config.MaxDataPoints == 0 {
		config.MaxDataPoints = 10000
	}
	if config.TemplateDirectory == "" {
		config.TemplateDirectory = "/templates"
	}
	
	return nil
}

// CreateScheduledJob creates a new scheduled job
func (sre *ScheduledReportingEngine) CreateScheduledJob(job *ScheduledJob) error {
	if job.ID == "" {
		job.ID = fmt.Sprintf("job_%d", time.Now().UnixNano())
	}
	
	// Validate job configuration
	if err := sre.validateJobConfig(job); err != nil {
		return fmt.Errorf("job validation failed: %w", err)
	}
	
	// Parse schedule and calculate next run
	nextRun, err := sre.calculateNextRun(job.Schedule, job.Timezone)
	if err != nil {
		return fmt.Errorf("failed to parse schedule: %w", err)
	}
	job.NextRun = nextRun
	
	// Set metadata
	job.CreatedAt = time.Now()
	job.UpdatedAt = time.Now()
	job.Status = "pending"
	
	// Store job
	sre.jobMutex.Lock()
	sre.scheduledJobs[job.ID] = job
	sre.jobMutex.Unlock()
	
	// Update statistics
	sre.statsMutex.Lock()
	sre.stats.TotalJobs++
	if job.Enabled {
		sre.stats.ActiveJobs++
	}
	sre.statsMutex.Unlock()
	
	sre.logger.Info("Scheduled job created",
		zap.String("job_id", job.ID),
		zap.String("name", job.Name),
		zap.String("schedule", job.Schedule),
		zap.Time("next_run", nextRun),
	)
	
	return nil
}

// UpdateScheduledJob updates an existing scheduled job
func (sre *ScheduledReportingEngine) UpdateScheduledJob(jobID string, updates *ScheduledJob) error {
	sre.jobMutex.Lock()
	job, exists := sre.scheduledJobs[jobID]
	if !exists {
		sre.jobMutex.Unlock()
		return fmt.Errorf("job not found: %s", jobID)
	}
	
	// Apply updates
	if updates.Name != "" {
		job.Name = updates.Name
	}
	if updates.Description != "" {
		job.Description = updates.Description
	}
	if updates.Schedule != "" {
		job.Schedule = updates.Schedule
		// Recalculate next run
		nextRun, err := sre.calculateNextRun(job.Schedule, job.Timezone)
		if err != nil {
			sre.jobMutex.Unlock()
			return fmt.Errorf("failed to parse new schedule: %w", err)
		}
		job.NextRun = nextRun
	}
	if updates.ReportConfig != nil {
		job.ReportConfig = updates.ReportConfig
	}
	if updates.Notifications != nil {
		job.Notifications = updates.Notifications
	}
	job.Enabled = updates.Enabled
	job.UpdatedAt = time.Now()
	
	// Validate updated configuration
	if err := sre.validateJobConfig(job); err != nil {
		sre.jobMutex.Unlock()
		return fmt.Errorf("job validation failed: %w", err)
	}
	
	sre.jobMutex.Unlock()
	
	sre.logger.Info("Scheduled job updated", zap.String("job_id", jobID))
	return nil
}

// DeleteScheduledJob deletes a scheduled job
func (sre *ScheduledReportingEngine) DeleteScheduledJob(jobID string) error {
	sre.jobMutex.Lock()
	job, exists := sre.scheduledJobs[jobID]
	if exists {
		delete(sre.scheduledJobs, jobID)
	}
	sre.jobMutex.Unlock()
	
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}
	
	// Update statistics
	sre.statsMutex.Lock()
	sre.stats.TotalJobs--
	if job.Enabled {
		sre.stats.ActiveJobs--
	}
	sre.statsMutex.Unlock()
	
	sre.logger.Info("Scheduled job deleted", zap.String("job_id", jobID))
	return nil
}

// runJobScheduler runs the main job scheduling loop
func (sre *ScheduledReportingEngine) runJobScheduler() {
	ticker := time.NewTicker(1 * time.Minute) // Check every minute
	defer ticker.Stop()
	
	for {
		select {
		case <-sre.ctx.Done():
			return
		case <-ticker.C:
			sre.checkAndExecuteJobs()
		}
	}
}

// checkAndExecuteJobs checks for jobs that need to be executed
func (sre *ScheduledReportingEngine) checkAndExecuteJobs() {
	now := time.Now()
	
	sre.jobMutex.RLock()
	jobsToRun := make([]*ScheduledJob, 0)
	for _, job := range sre.scheduledJobs {
		if job.Enabled && job.Status != "running" && now.After(job.NextRun) {
			jobsToRun = append(jobsToRun, job)
		}
	}
	sre.jobMutex.RUnlock()
	
	for _, job := range jobsToRun {
		go sre.executeJob(job)
	}
}

// executeJob executes a single job
func (sre *ScheduledReportingEngine) executeJob(job *ScheduledJob) {
	start := time.Now()
	
	// Update job status
	sre.jobMutex.Lock()
	job.Status = "running"
	job.RunCount++
	sre.jobMutex.Unlock()
	
	sre.logger.Info("Executing scheduled job",
		zap.String("job_id", job.ID),
		zap.String("name", job.Name),
		zap.String("type", job.Type),
	)
	
	// Create execution context with timeout
	ctx, cancel := context.WithTimeout(sre.ctx, sre.config.JobTimeout)
	defer cancel()
	
	// Execute job based on type
	var err error
	switch job.Type {
	case "report":
		err = sre.executeReportJob(ctx, job)
	case "alert":
		err = sre.executeAlertJob(ctx, job)
	case "dashboard_export":
		err = sre.executeDashboardExportJob(ctx, job)
	default:
		err = fmt.Errorf("unknown job type: %s", job.Type)
	}
	
	// Update job status and schedule next run
	sre.jobMutex.Lock()
	if err != nil {
		job.Status = "failed"
		job.LastError = err.Error()
		job.FailureCount++
		
		sre.statsMutex.Lock()
		sre.stats.FailedJobs++
		sre.statsMutex.Unlock()
	} else {
		job.Status = "completed"
		job.LastError = ""
		
		sre.statsMutex.Lock()
		sre.stats.CompletedJobs++
		sre.statsMutex.Unlock()
	}
	
	job.LastRun = start
	// Calculate next run
	nextRun, schedErr := sre.calculateNextRun(job.Schedule, job.Timezone)
	if schedErr == nil {
		job.NextRun = nextRun
	}
	sre.jobMutex.Unlock()
	
	// Update statistics
	duration := time.Since(start)
	sre.statsMutex.Lock()
	sre.stats.AverageRunTime = (sre.stats.AverageRunTime + duration) / 2
	sre.stats.LastJobRun = time.Now()
	sre.statsMutex.Unlock()
	
	if err != nil {
		sre.logger.Error("Job execution failed",
			zap.String("job_id", job.ID),
			zap.String("name", job.Name),
			zap.Error(err),
			zap.Duration("duration", duration),
		)
	} else {
		sre.logger.Info("Job executed successfully",
			zap.String("job_id", job.ID),
			zap.String("name", job.Name),
			zap.Duration("duration", duration),
		)
	}
}

// executeReportJob executes a report generation job
func (sre *ScheduledReportingEngine) executeReportJob(ctx context.Context, job *ScheduledJob) error {
	if job.ReportConfig == nil {
		return fmt.Errorf("report configuration is required")
	}
	
	// Collect data from all data sources
	reportData := make(map[string]interface{})
	
	for _, dataSource := range job.ReportConfig.DataSources {
		data, err := sre.executeDataSourceQuery(ctx, &dataSource)
		if err != nil {
			return fmt.Errorf("failed to query data source %s: %w", dataSource.Name, err)
		}
		reportData[dataSource.Name] = data
	}
	
	// Generate report
	report, err := sre.generateReport(ctx, job.ReportConfig, reportData)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}
	
	// Save report
	reportPath, err := sre.saveReport(job, report)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}
	
	// Send notifications
	for _, notification := range job.Notifications {
		if notification.Enabled {
			if err := sre.sendReportNotification(ctx, &notification, job, reportPath, reportData); err != nil {
				sre.logger.Warn("Failed to send notification",
					zap.String("job_id", job.ID),
					zap.String("notification_type", notification.Type),
					zap.Error(err),
				)
			}
		}
	}
	
	sre.statsMutex.Lock()
	sre.stats.TotalReports++
	sre.statsMutex.Unlock()
	
	return nil
}

// executeAlertJob executes an alert job
func (sre *ScheduledReportingEngine) executeAlertJob(ctx context.Context, job *ScheduledJob) error {
	if job.ReportConfig == nil {
		return fmt.Errorf("report configuration is required for alert job")
	}
	
	// Collect data from all data sources
	alertData := make(map[string]interface{})
	
	for _, dataSource := range job.ReportConfig.DataSources {
		data, err := sre.executeDataSourceQuery(ctx, &dataSource)
		if err != nil {
			return fmt.Errorf("failed to query data source %s: %w", dataSource.Name, err)
		}
		alertData[dataSource.Name] = data
	}
	
	// Check alert conditions
	alertTriggered := false
	triggeredConditions := []NotificationCondition{}
	
	for _, notification := range job.Notifications {
		if !notification.Enabled {
			continue
		}
		
		for _, condition := range notification.Conditions {
			if sre.evaluateAlertCondition(condition, alertData) {
				alertTriggered = true
				triggeredConditions = append(triggeredConditions, condition)
			}
		}
	}
	
	// Send alerts if conditions are met
	if alertTriggered {
		for _, notification := range job.Notifications {
			if notification.Enabled {
				if err := sre.sendAlertNotification(ctx, &notification, job, alertData, triggeredConditions); err != nil {
					sre.logger.Warn("Failed to send alert notification",
						zap.String("job_id", job.ID),
						zap.String("notification_type", notification.Type),
						zap.Error(err),
					)
				}
			}
		}
		
		sre.statsMutex.Lock()
		sre.stats.TotalAlerts++
		sre.statsMutex.Unlock()
	}
	
	return nil
}

// executeDashboardExportJob executes a dashboard export job
func (sre *ScheduledReportingEngine) executeDashboardExportJob(ctx context.Context, job *ScheduledJob) error {
	// Implementation would export dashboard to various formats
	return fmt.Errorf("dashboard export not implemented")
}

// executeDataSourceQuery executes a query against a data source
func (sre *ScheduledReportingEngine) executeDataSourceQuery(ctx context.Context, dataSource *DataSource) (interface{}, error) {
	queryCtx, cancel := context.WithTimeout(ctx, sre.config.QueryTimeout)
	defer cancel()
	
	return sre.queryEngine.ExecuteQuery(queryCtx, dataSource.Query)
}

// generateReport generates a report from data and configuration
func (sre *ScheduledReportingEngine) generateReport(ctx context.Context, config *ReportConfiguration, data map[string]interface{}) ([]byte, error) {
	// Prepare template data
	templateData := map[string]interface{}{
		"Title":       config.Title,
		"Subtitle":    config.Subtitle,
		"GeneratedAt": time.Now(),
		"Data":        data,
		"CustomFields": config.CustomFields,
		"Branding":    config.Branding,
	}
	
	// Generate report using template
	return sre.templateEngine.RenderReport(config.Template, config.Format, templateData)
}

// saveReport saves a generated report to storage
func (sre *ScheduledReportingEngine) saveReport(job *ScheduledJob, reportData []byte) (string, error) {
	// Generate filename
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s_%s.%s", job.Name, job.ID, timestamp, job.ReportConfig.Format)
	filepath := fmt.Sprintf("%s/%s", sre.config.ReportStoragePath, filename)
	
	// Save to file (implementation would handle actual file operations)
	// In a real implementation, this would write to disk or cloud storage
	
	return filepath, nil
}

// sendReportNotification sends a report notification
func (sre *ScheduledReportingEngine) sendReportNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, reportPath string, data map[string]interface{}) error {
	switch notification.Type {
	case "email":
		return sre.sendEmailReportNotification(ctx, notification, job, reportPath, data)
	case "slack":
		return sre.sendSlackReportNotification(ctx, notification, job, reportPath, data)
	case "webhook":
		return sre.sendWebhookReportNotification(ctx, notification, job, reportPath, data)
	default:
		return fmt.Errorf("unsupported notification type: %s", notification.Type)
	}
}

// sendAlertNotification sends an alert notification
func (sre *ScheduledReportingEngine) sendAlertNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, data map[string]interface{}, conditions []NotificationCondition) error {
	switch notification.Type {
	case "email":
		return sre.sendEmailAlertNotification(ctx, notification, job, data, conditions)
	case "slack":
		return sre.sendSlackAlertNotification(ctx, notification, job, data, conditions)
	case "webhook":
		return sre.sendWebhookAlertNotification(ctx, notification, job, data, conditions)
	default:
		return fmt.Errorf("unsupported notification type: %s", notification.Type)
	}
}

// sendEmailReportNotification sends an email report notification
func (sre *ScheduledReportingEngine) sendEmailReportNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, reportPath string, data map[string]interface{}) error {
	email := &EmailNotification{
		To:      notification.Recipients,
		Subject: notification.Subject,
		Body:    fmt.Sprintf("Report '%s' has been generated successfully. Please find the attached report.", job.Name),
		Attachments: []NotificationAttachment{
			{
				Filename:    job.Name + "." + job.ReportConfig.Format,
				ContentType: getContentType(job.ReportConfig.Format),
				// Data would be loaded from reportPath
			},
		},
	}
	
	return sre.notificationService.SendEmail(ctx, email)
}

// sendSlackReportNotification sends a Slack report notification
func (sre *ScheduledReportingEngine) sendSlackReportNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, reportPath string, data map[string]interface{}) error {
	slack := &SlackNotification{
		Channel: notification.Recipients[0], // First recipient as channel
		Message: fmt.Sprintf("Report '%s' has been generated successfully.", job.Name),
		Attachments: []SlackAttachment{
			{
				Color: "good",
				Title: "Report Generated",
				Text:  fmt.Sprintf("Report: %s\nGenerated: %s", job.Name, time.Now().Format("2006-01-02 15:04:05")),
			},
		},
	}
	
	return sre.notificationService.SendSlack(ctx, slack)
}

// sendWebhookReportNotification sends a webhook report notification
func (sre *ScheduledReportingEngine) sendWebhookReportNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, reportPath string, data map[string]interface{}) error {
	webhook := &WebhookNotification{
		URL:    notification.Recipients[0], // First recipient as URL
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: map[string]interface{}{
			"type":        "report",
			"job_id":      job.ID,
			"job_name":    job.Name,
			"report_path": reportPath,
			"generated_at": time.Now(),
			"data":        data,
		},
	}
	
	return sre.notificationService.SendWebhook(ctx, webhook)
}

// sendEmailAlertNotification sends an email alert notification
func (sre *ScheduledReportingEngine) sendEmailAlertNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, data map[string]interface{}, conditions []NotificationCondition) error {
	// Build alert message
	var alertMessage bytes.Buffer
	alertMessage.WriteString(fmt.Sprintf("Alert: %s\n\n", job.Name))
	alertMessage.WriteString("The following conditions were triggered:\n\n")
	
	for _, condition := range conditions {
		alertMessage.WriteString(fmt.Sprintf("- %s %s %v (Severity: %s)\n", 
			condition.Field, condition.Operator, condition.Value, condition.Severity))
	}
	
	email := &EmailNotification{
		To:      notification.Recipients,
		Subject: fmt.Sprintf("ALERT: %s", notification.Subject),
		Body:    alertMessage.String(),
	}
	
	return sre.notificationService.SendEmail(ctx, email)
}

// sendSlackAlertNotification sends a Slack alert notification
func (sre *ScheduledReportingEngine) sendSlackAlertNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, data map[string]interface{}, conditions []NotificationCondition) error {
	color := "warning"
	for _, condition := range conditions {
		if condition.Severity == "critical" {
			color = "danger"
			break
		}
	}
	
	fields := make([]SlackField, 0, len(conditions))
	for _, condition := range conditions {
		fields = append(fields, SlackField{
			Title: condition.Field,
			Value: fmt.Sprintf("%s %v", condition.Operator, condition.Value),
			Short: true,
		})
	}
	
	slack := &SlackNotification{
		Channel: notification.Recipients[0],
		Message: fmt.Sprintf("🚨 Alert: %s", job.Name),
		Attachments: []SlackAttachment{
			{
				Color:  color,
				Title:  "Alert Conditions",
				Text:   "The following conditions were triggered:",
				Fields: fields,
			},
		},
	}
	
	return sre.notificationService.SendSlack(ctx, slack)
}

// sendWebhookAlertNotification sends a webhook alert notification
func (sre *ScheduledReportingEngine) sendWebhookAlertNotification(ctx context.Context, notification *NotificationConfig, job *ScheduledJob, data map[string]interface{}, conditions []NotificationCondition) error {
	webhook := &WebhookNotification{
		URL:    notification.Recipients[0],
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: map[string]interface{}{
			"type":       "alert",
			"job_id":     job.ID,
			"job_name":   job.Name,
			"conditions": conditions,
			"data":       data,
			"triggered_at": time.Now(),
		},
	}
	
	return sre.notificationService.SendWebhook(ctx, webhook)
}

// evaluateAlertCondition evaluates whether an alert condition is met
func (sre *ScheduledReportingEngine) evaluateAlertCondition(condition NotificationCondition, data map[string]interface{}) bool {
	// Extract field value from data
	fieldValue := extractFieldValue(condition.Field, data)
	if fieldValue == nil {
		return false
	}
	
	// Compare based on operator
	switch condition.Operator {
	case "gt":
		return compareGreaterThan(fieldValue, condition.Value)
	case "lt":
		return compareLessThan(fieldValue, condition.Value)
	case "eq":
		return compareEqual(fieldValue, condition.Value)
	case "contains":
		return compareContains(fieldValue, condition.Value)
	default:
		return false
	}
}

// Utility functions

func (sre *ScheduledReportingEngine) validateJobConfig(job *ScheduledJob) error {
	if job.Name == "" {
		return fmt.Errorf("job name is required")
	}
	if job.Schedule == "" {
		return fmt.Errorf("job schedule is required")
	}
	if job.Type == "" {
		return fmt.Errorf("job type is required")
	}
	if job.ReportConfig == nil {
		return fmt.Errorf("report configuration is required")
	}
	
	return nil
}

func (sre *ScheduledReportingEngine) calculateNextRun(schedule, timezone string) (time.Time, error) {
	// Implementation would parse cron expression and calculate next run time
	// For now, return next hour as placeholder
	return time.Now().Add(time.Hour), nil
}

func getContentType(format string) string {
	switch format {
	case "pdf":
		return "application/pdf"
	case "html":
		return "text/html"
	case "csv":
		return "text/csv"
	case "json":
		return "application/json"
	case "excel":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	default:
		return "application/octet-stream"
	}
}

func extractFieldValue(field string, data map[string]interface{}) interface{} {
	// Implementation would handle nested field extraction
	return data[field]
}

func compareGreaterThan(a, b interface{}) bool {
	// Implementation would handle type-safe numeric comparison
	return false
}

func compareLessThan(a, b interface{}) bool {
	// Implementation would handle type-safe numeric comparison
	return false
}

func compareEqual(a, b interface{}) bool {
	// Implementation would handle type-safe equality comparison
	return false
}

func compareContains(a, b interface{}) bool {
	// Implementation would handle string contains comparison
	return false
}

// GetScheduledJob returns a scheduled job by ID
func (sre *ScheduledReportingEngine) GetScheduledJob(jobID string) (*ScheduledJob, error) {
	sre.jobMutex.RLock()
	job, exists := sre.scheduledJobs[jobID]
	sre.jobMutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}
	
	// Return copy to prevent external modifications
	jobCopy := *job
	return &jobCopy, nil
}

// ListScheduledJobs returns all scheduled jobs
func (sre *ScheduledReportingEngine) ListScheduledJobs() []*ScheduledJob {
	sre.jobMutex.RLock()
	defer sre.jobMutex.RUnlock()
	
	jobs := make([]*ScheduledJob, 0, len(sre.scheduledJobs))
	for _, job := range sre.scheduledJobs {
		jobCopy := *job
		jobs = append(jobs, &jobCopy)
	}
	
	return jobs
}

// GetStats returns reporting statistics
func (sre *ScheduledReportingEngine) GetStats() *ReportingStats {
	sre.statsMutex.RLock()
	defer sre.statsMutex.RUnlock()
	
	stats := *sre.stats
	return &stats
}

// IsHealthy returns the health status
func (sre *ScheduledReportingEngine) IsHealthy() bool {
	return sre.queryEngine.IsHealthy() && sre.notificationService.IsHealthy()
}

// Close closes the reporting engine
func (sre *ScheduledReportingEngine) Close() error {
	if sre.cancel != nil {
		sre.cancel()
	}
	
	if sre.scheduler != nil {
		sre.scheduler.Close()
	}
	
	sre.logger.Info("Scheduled reporting engine closed")
	return nil
}

// Placeholder implementations for supporting components

func NewJobScheduler(logger *zap.Logger, maxWorkers int, ctx context.Context) (*JobScheduler, error) {
	return &JobScheduler{
		logger:  logger,
		jobs:    make(map[string]*ScheduledJob),
		workers: make(chan struct{}, maxWorkers),
		ctx:     ctx,
	}, nil
}

func (js *JobScheduler) Close() error {
	return nil
}

func NewTemplateEngine(logger *zap.Logger, templateDir string) (*TemplateEngine, error) {
	return &TemplateEngine{
		logger:      logger,
		templates:   make(map[string]*template.Template),
		templateDir: templateDir,
	}, nil
}

func (te *TemplateEngine) RenderReport(templateName, format string, data interface{}) ([]byte, error) {
	// Placeholder implementation
	result := map[string]interface{}{
		"template": templateName,
		"format":   format,
		"data":     data,
	}
	return json.Marshal(result)
}