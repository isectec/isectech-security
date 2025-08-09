// iSECTECH POC Environment Provisioning Engine
// Production-Grade Terraform-based Infrastructure Provisioning Service
// Version: 1.0
// Author: Claude Code Implementation

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Configuration structure
type Config struct {
	Port                    string
	DatabaseURL             string
	Environment             string
	TerraformBinary         string
	TerraformWorkspaceDir   string
	GCPProject              string
	GCPRegion               string
	TerraformStateGCSBucket string
	MaxConcurrentProvisions int
	ProvisioningTimeout     time.Duration
	LogLevel                string
}

// Provisioning request from POC signup
type ProvisioningRequest struct {
	TenantID              uuid.UUID              `json:"tenant_id" binding:"required"`
	TenantSlug            string                 `json:"tenant_slug" binding:"required"`
	CompanyInfo           CompanyInfo            `json:"company_info" binding:"required"`
	POCConfig             POCConfig              `json:"poc_config" binding:"required"`
	SecurityConfig        SecurityConfig         `json:"security_config" binding:"required"`
	IntegrationConfig     IntegrationConfig      `json:"integration_config"`
	MonitoringConfig      MonitoringConfig       `json:"monitoring_config"`
	RequestID             string                 `json:"request_id"`
	RequestedBy           uuid.UUID              `json:"requested_by"`
	Priority              ProvisioningPriority   `json:"priority"`
}

type CompanyInfo struct {
	CompanyName         string `json:"company_name"`
	IndustryVertical    string `json:"industry_vertical"`
	CompanySize         string `json:"company_size"`
	HeadquartersCountry string `json:"headquarters_country"`
	ContactEmail        string `json:"contact_email"`
	ContactName         string `json:"contact_name"`
}

type POCConfig struct {
	POCTier           string    `json:"poc_tier"`
	POCDurationDays   int       `json:"poc_duration_days"`
	ExpiresAt         time.Time `json:"expires_at"`
	EnabledFeatures   []string  `json:"enabled_features"`
	ResourceAllocation map[string]interface{} `json:"resource_allocation"`
}

type SecurityConfig struct {
	SecurityClearance         string   `json:"security_clearance"`
	DataResidencyRegion       string   `json:"data_residency_region"`
	ComplianceFrameworks      []string `json:"compliance_frameworks"`
	NetworkIsolationLevel     string   `json:"network_isolation_level"`
	EncryptionRequired        bool     `json:"encryption_required"`
}

type IntegrationConfig struct {
	MainPlatformIntegration bool     `json:"main_platform_integration"`
	AllowedDataConnectors   []string `json:"allowed_data_connectors"`
	CRMIntegrationEnabled   bool     `json:"crm_integration_enabled"`
}

type MonitoringConfig struct {
	Enabled               bool `json:"enabled"`
	DetailedMonitoring    bool `json:"detailed_monitoring"`
	AlertingEnabled       bool `json:"alerting_enabled"`
	RetentionDays         int  `json:"retention_days"`
}

type ProvisioningPriority string

const (
	PriorityLow      ProvisioningPriority = "low"
	PriorityStandard ProvisioningPriority = "standard"
	PriorityHigh     ProvisioningPriority = "high"
	PriorityUrgent   ProvisioningPriority = "urgent"
)

type ProvisioningStatus string

const (
	StatusPending      ProvisioningStatus = "pending"
	StatusQueued       ProvisioningStatus = "queued"
	StatusProvisioning ProvisioningStatus = "provisioning"
	StatusCompleted    ProvisioningStatus = "completed"
	StatusFailed       ProvisioningStatus = "failed"
	StatusCancelled    ProvisioningStatus = "cancelled"
	StatusDestroying   ProvisioningStatus = "destroying"
	StatusDestroyed    ProvisioningStatus = "destroyed"
)

// Provisioning job tracking
type ProvisioningJob struct {
	JobID             uuid.UUID              `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"job_id"`
	TenantID          uuid.UUID              `gorm:"not null;index" json:"tenant_id"`
	TenantSlug        string                 `gorm:"not null;size:63" json:"tenant_slug"`
	Status            ProvisioningStatus     `gorm:"not null;default:pending;index" json:"status"`
	Priority          ProvisioningPriority   `gorm:"not null;default:standard" json:"priority"`
	
	// Request details
	RequestID         string                 `gorm:"not null;unique" json:"request_id"`
	RequestedBy       uuid.UUID              `json:"requested_by"`
	RequestPayload    map[string]interface{} `gorm:"type:jsonb" json:"request_payload"`
	
	// Provisioning details
	TerraformWorkspace string                `gorm:"size:100" json:"terraform_workspace"`
	TerraformPlan      string                `gorm:"type:text" json:"terraform_plan"`
	TerraformState     string                `gorm:"type:text" json:"terraform_state"`
	
	// Progress tracking
	CurrentStep       string                 `gorm:"size:100" json:"current_step"`
	TotalSteps        int                    `gorm:"default:0" json:"total_steps"`
	CompletedSteps    int                    `gorm:"default:0" json:"completed_steps"`
	ProgressPercent   int                    `gorm:"default:0" json:"progress_percent"`
	
	// Output and results
	ProvisionedResources map[string]interface{} `gorm:"type:jsonb" json:"provisioned_resources"`
	AccessCredentials    map[string]interface{} `gorm:"type:jsonb" json:"access_credentials"`
	ServiceEndpoints     map[string]interface{} `gorm:"type:jsonb" json:"service_endpoints"`
	
	// Timing information
	QueuedAt          *time.Time             `json:"queued_at"`
	StartedAt         *time.Time             `json:"started_at"`
	CompletedAt       *time.Time             `json:"completed_at"`
	EstimatedDuration time.Duration          `json:"estimated_duration"`
	ActualDuration    time.Duration          `json:"actual_duration"`
	
	// Error handling
	ErrorMessage      string                 `gorm:"type:text" json:"error_message"`
	ErrorDetails      map[string]interface{} `gorm:"type:jsonb" json:"error_details"`
	RetryCount        int                    `gorm:"default:0" json:"retry_count"`
	MaxRetries        int                    `gorm:"default:3" json:"max_retries"`
	
	// Cleanup and lifecycle
	ExpiresAt         time.Time              `gorm:"not null" json:"expires_at"`
	CleanupScheduled  bool                   `gorm:"default:false" json:"cleanup_scheduled"`
	AutoCleanup       bool                   `gorm:"default:true" json:"auto_cleanup"`
	
	// Metadata
	Tags              map[string]interface{} `gorm:"type:jsonb" json:"tags"`
	CreatedAt         time.Time              `gorm:"default:now()" json:"created_at"`
	UpdatedAt         time.Time              `gorm:"default:now()" json:"updated_at"`
}

// Provisioning response
type ProvisioningResponse struct {
	Success              bool                   `json:"success"`
	Message              string                 `json:"message"`
	JobID                uuid.UUID              `json:"job_id"`
	Status               ProvisioningStatus     `json:"status"`
	EstimatedDuration    string                 `json:"estimated_duration"`
	ProgressTrackingURL  string                 `json:"progress_tracking_url"`
	ProvisionedResources map[string]interface{} `json:"provisioned_resources,omitempty"`
	ServiceEndpoints     map[string]interface{} `json:"service_endpoints,omitempty"`
	ErrorMessage         string                 `json:"error_message,omitempty"`
}

// Application struct
type App struct {
	config      *Config
	db          *gorm.DB
	router      *gin.Engine
	jobQueue    chan *ProvisioningJob
	workerPool  *WorkerPool
}

// Worker pool for concurrent provisioning
type WorkerPool struct {
	workers    []*Worker
	jobQueue   chan *ProvisioningJob
	quit       chan bool
	maxWorkers int
}

type Worker struct {
	id       int
	jobQueue chan *ProvisioningJob
	quit     chan bool
	app      *App
}

// Initialize configuration
func initConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	config := &Config{
		Port:                    getEnv("PORT", "8081"),
		DatabaseURL:             getEnv("DATABASE_URL", "postgres://localhost/isectech_poc?sslmode=disable"),
		Environment:             getEnv("ENVIRONMENT", "development"),
		TerraformBinary:         getEnv("TERRAFORM_BINARY", "terraform"),
		TerraformWorkspaceDir:   getEnv("TERRAFORM_WORKSPACE_DIR", "./terraform-workspaces"),
		GCPProject:              getEnv("GCP_PROJECT", "isectech-poc-platform"),
		GCPRegion:               getEnv("GCP_REGION", "us-central1"),
		TerraformStateGCSBucket: getEnv("TERRAFORM_STATE_GCS_BUCKET", "isectech-terraform-state-poc"),
		MaxConcurrentProvisions: getEnvAsInt("MAX_CONCURRENT_PROVISIONS", 5),
		LogLevel:                getEnv("LOG_LEVEL", "info"),
	}

	// Parse provisioning timeout
	if timeoutStr := getEnv("PROVISIONING_TIMEOUT", "30m"); timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			config.ProvisioningTimeout = timeout
		} else {
			config.ProvisioningTimeout = 30 * time.Minute
		}
	}

	return config
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// Initialize database
func initDatabase(config *Config) (*gorm.DB, error) {
	var gormLogger logger.Interface
	if config.Environment == "production" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	} else {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	db, err := gorm.Open(postgres.Open(config.DatabaseURL), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(&ProvisioningJob{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}

	return db, nil
}

// Initialize router
func initRouter(config *Config) *gin.Engine {
	if config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	return router
}

// Start a worker
func (w *Worker) Start() {
	go func() {
		for {
			select {
			case job := <-w.jobQueue:
				log.Printf("Worker %d processing job %s for tenant %s", w.id, job.JobID, job.TenantSlug)
				w.processJob(job)
			case <-w.quit:
				log.Printf("Worker %d stopping", w.id)
				return
			}
		}
	}()
}

// Stop a worker
func (w *Worker) Stop() {
	w.quit <- true
}

// Process a provisioning job
func (w *Worker) processJob(job *ProvisioningJob) {
	ctx, cancel := context.WithTimeout(context.Background(), w.app.config.ProvisioningTimeout)
	defer cancel()

	// Update job status to provisioning
	w.updateJobStatus(job, StatusProvisioning, "Starting infrastructure provisioning")

	// Create Terraform workspace
	workspaceDir, err := w.createTerraformWorkspace(job)
	if err != nil {
		w.handleJobError(job, fmt.Sprintf("Failed to create Terraform workspace: %v", err))
		return
	}

	// Generate Terraform variables
	tfVars, err := w.generateTerraformVars(job)
	if err != nil {
		w.handleJobError(job, fmt.Sprintf("Failed to generate Terraform variables: %v", err))
		return
	}

	// Initialize Terraform
	if err := w.runTerraformInit(ctx, workspaceDir); err != nil {
		w.handleJobError(job, fmt.Sprintf("Terraform init failed: %v", err))
		return
	}

	// Create Terraform plan
	planOutput, err := w.runTerraformPlan(ctx, workspaceDir, tfVars)
	if err != nil {
		w.handleJobError(job, fmt.Sprintf("Terraform plan failed: %v", err))
		return
	}

	// Store plan in database
	w.app.db.Model(job).Updates(map[string]interface{}{
		"terraform_plan": planOutput,
		"current_step":   "terraform_apply",
		"completed_steps": job.CompletedSteps + 1,
		"progress_percent": int((float64(job.CompletedSteps+1) / float64(job.TotalSteps)) * 100),
	})

	// Apply Terraform configuration
	applyOutput, err := w.runTerraformApply(ctx, workspaceDir, tfVars)
	if err != nil {
		w.handleJobError(job, fmt.Sprintf("Terraform apply failed: %v", err))
		return
	}

	// Extract provisioned resources and endpoints
	resources, endpoints, err := w.extractTerraformOutputs(ctx, workspaceDir)
	if err != nil {
		w.handleJobError(job, fmt.Sprintf("Failed to extract Terraform outputs: %v", err))
		return
	}

	// Generate access credentials
	credentials, err := w.generateAccessCredentials(job, resources)
	if err != nil {
		w.handleJobError(job, fmt.Sprintf("Failed to generate access credentials: %v", err))
		return
	}

	// Update POC tenant status in main database
	if err := w.updateTenantStatus(job.TenantID, "active"); err != nil {
		log.Printf("Warning: Failed to update tenant status: %v", err)
	}

	// Complete the job
	now := time.Now().UTC()
	actualDuration := now.Sub(*job.StartedAt)
	
	w.app.db.Model(job).Updates(map[string]interface{}{
		"status":                 StatusCompleted,
		"current_step":          "completed",
		"completed_steps":       job.TotalSteps,
		"progress_percent":      100,
		"completed_at":          &now,
		"actual_duration":       actualDuration,
		"provisioned_resources": resources,
		"service_endpoints":     endpoints,
		"access_credentials":    credentials,
		"terraform_state":       applyOutput,
	})

	log.Printf("Successfully completed provisioning job %s for tenant %s", job.JobID, job.TenantSlug)

	// Send completion notification
	w.sendCompletionNotification(job, resources, endpoints, credentials)
}

// Create Terraform workspace
func (w *Worker) createTerraformWorkspace(job *ProvisioningJob) (string, error) {
	workspaceDir := filepath.Join(w.app.config.TerraformWorkspaceDir, job.TenantSlug)
	
	// Create workspace directory
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Copy Terraform modules to workspace
	terraformModulesDir := "../architecture/terraform"
	if err := copyDir(terraformModulesDir, workspaceDir); err != nil {
		return "", fmt.Errorf("failed to copy Terraform modules: %w", err)
	}

	job.TerraformWorkspace = workspaceDir
	w.app.db.Model(job).Update("terraform_workspace", workspaceDir)

	return workspaceDir, nil
}

// Generate Terraform variables from job request
func (w *Worker) generateTerraformVars(job *ProvisioningJob) (map[string]interface{}, error) {
	request := job.RequestPayload
	
	tfVars := map[string]interface{}{
		"project_id":                w.app.config.GCPProject,
		"primary_region":            w.app.config.GCPRegion,
		"tenant_id":                 job.TenantSlug,
		"tenant_display_name":       request["company_info"].(map[string]interface{})["company_name"],
		"poc_tier":                  request["poc_config"].(map[string]interface{})["poc_tier"],
		"poc_duration_days":         request["poc_config"].(map[string]interface{})["poc_duration_days"],
		"poc_expires_at":            request["poc_config"].(map[string]interface{})["expires_at"],
		"security_clearance":        request["security_config"].(map[string]interface{})["security_clearance"],
		"data_residency_region":     request["security_config"].(map[string]interface{})["data_residency_region"],
		"compliance_frameworks":     request["security_config"].(map[string]interface{})["compliance_frameworks"],
		"network_isolation_level":   request["security_config"].(map[string]interface{})["network_isolation_level"],
		"enabled_features":          request["poc_config"].(map[string]interface{})["enabled_features"],
		"auto_cleanup_enabled":      true,
	}

	// Add company information
	companyInfo := request["company_info"].(map[string]interface{})
	tfVars["company_info"] = map[string]interface{}{
		"company_name":         companyInfo["company_name"],
		"industry_vertical":    companyInfo["industry_vertical"],
		"company_size":         companyInfo["company_size"],
		"contact_email":        companyInfo["contact_email"],
		"contact_name":         companyInfo["contact_name"],
		"headquarters_country": companyInfo["headquarters_country"],
	}

	// Add monitoring configuration
	if monitoringConfig, ok := request["monitoring_config"].(map[string]interface{}); ok {
		tfVars["monitoring_config"] = monitoringConfig
	}

	// Add integration configuration
	if integrationConfig, ok := request["integration_config"].(map[string]interface{}); ok {
		tfVars["main_platform_integration"] = map[string]interface{}{
			"enabled": integrationConfig["main_platform_integration"],
		}
		tfVars["allowed_data_connectors"] = integrationConfig["allowed_data_connectors"]
	}

	return tfVars, nil
}

// Run Terraform init
func (w *Worker) runTerraformInit(ctx context.Context, workspaceDir string) error {
	cmd := exec.CommandContext(ctx, w.app.config.TerraformBinary, "init",
		"-backend-config=bucket="+w.app.config.TerraformStateGCSBucket,
		"-backend-config=prefix=poc-environments/"+filepath.Base(workspaceDir))
	cmd.Dir = workspaceDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("terraform init failed: %s\nOutput: %s", err, string(output))
	}
	
	log.Printf("Terraform init completed for workspace %s", workspaceDir)
	return nil
}

// Run Terraform plan
func (w *Worker) runTerraformPlan(ctx context.Context, workspaceDir string, tfVars map[string]interface{}) (string, error) {
	// Write variables to file
	varsFile := filepath.Join(workspaceDir, "terraform.tfvars.json")
	varsJSON, _ := json.MarshalIndent(tfVars, "", "  ")
	if err := os.WriteFile(varsFile, varsJSON, 0644); err != nil {
		return "", fmt.Errorf("failed to write variables file: %w", err)
	}

	cmd := exec.CommandContext(ctx, w.app.config.TerraformBinary, "plan", 
		"-var-file=terraform.tfvars.json", "-out=terraform.plan")
	cmd.Dir = workspaceDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("terraform plan failed: %s\nOutput: %s", err, string(output))
	}
	
	return string(output), nil
}

// Run Terraform apply
func (w *Worker) runTerraformApply(ctx context.Context, workspaceDir string, tfVars map[string]interface{}) (string, error) {
	cmd := exec.CommandContext(ctx, w.app.config.TerraformBinary, "apply", 
		"-auto-approve", "terraform.plan")
	cmd.Dir = workspaceDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("terraform apply failed: %s\nOutput: %s", err, string(output))
	}
	
	return string(output), nil
}

// Extract Terraform outputs
func (w *Worker) extractTerraformOutputs(ctx context.Context, workspaceDir string) (map[string]interface{}, map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, w.app.config.TerraformBinary, "output", "-json")
	cmd.Dir = workspaceDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("terraform output failed: %s\nOutput: %s", err, string(output))
	}
	
	var outputs map[string]interface{}
	if err := json.Unmarshal(output, &outputs); err != nil {
		return nil, nil, fmt.Errorf("failed to parse terraform outputs: %w", err)
	}
	
	// Separate resources and endpoints
	resources := make(map[string]interface{})
	endpoints := make(map[string]interface{})
	
	for key, value := range outputs {
		if val, ok := value.(map[string]interface{}); ok {
			if actualValue, exists := val["value"]; exists {
				if strings.Contains(key, "endpoint") || strings.Contains(key, "url") {
					endpoints[key] = actualValue
				} else {
					resources[key] = actualValue
				}
			}
		}
	}
	
	return resources, endpoints, nil
}

// Generate access credentials
func (w *Worker) generateAccessCredentials(job *ProvisioningJob, resources map[string]interface{}) (map[string]interface{}, error) {
	credentials := map[string]interface{}{
		"tenant_id":    job.TenantID,
		"tenant_slug":  job.TenantSlug,
		"generated_at": time.Now().UTC(),
		"expires_at":   job.ExpiresAt,
	}

	// Generate admin user credentials
	adminPassword := generateSecurePassword(16)
	credentials["admin_user"] = map[string]interface{}{
		"username": "poc-admin",
		"password": adminPassword,
		"role":     "administrator",
	}

	// Generate API keys
	apiKey := generateAPIKey()
	credentials["api_access"] = map[string]interface{}{
		"api_key":    apiKey,
		"api_secret": generateSecurePassword(32),
	}

	// Add database connection info if available
	if dbInstance, ok := resources["database_instance"]; ok {
		credentials["database"] = map[string]interface{}{
			"host":     dbInstance,
			"database": job.TenantSlug + "_poc_db",
			"username": "poc_user",
			"password": generateSecurePassword(20),
		}
	}

	return credentials, nil
}

// Update tenant status in main database
func (w *Worker) updateTenantStatus(tenantID uuid.UUID, status string) error {
	return w.app.db.Exec("UPDATE poc_tenants SET status = ?, activated_at = ? WHERE tenant_id = ?", 
		status, time.Now().UTC(), tenantID).Error
}

// Update job status
func (w *Worker) updateJobStatus(job *ProvisioningJob, status ProvisioningStatus, message string) {
	updates := map[string]interface{}{
		"status":      status,
		"current_step": message,
		"updated_at":  time.Now().UTC(),
	}

	if status == StatusProvisioning && job.StartedAt == nil {
		now := time.Now().UTC()
		updates["started_at"] = &now
	}

	w.app.db.Model(job).Updates(updates)
}

// Handle job error
func (w *Worker) handleJobError(job *ProvisioningJob, errorMessage string) {
	log.Printf("Provisioning job %s failed: %s", job.JobID, errorMessage)
	
	now := time.Now().UTC()
	w.app.db.Model(job).Updates(map[string]interface{}{
		"status":        StatusFailed,
		"error_message": errorMessage,
		"completed_at":  &now,
		"retry_count":   job.RetryCount + 1,
	})

	// Update tenant status to failed
	w.updateTenantStatus(job.TenantID, "failed")
	
	// Send failure notification
	w.sendFailureNotification(job, errorMessage)
}

// Send completion notification
func (w *Worker) sendCompletionNotification(job *ProvisioningJob, resources, endpoints, credentials map[string]interface{}) {
	log.Printf("Sending completion notification for job %s", job.JobID)
	// TODO: Implement email notification with access instructions
}

// Send failure notification
func (w *Worker) sendFailureNotification(job *ProvisioningJob, errorMessage string) {
	log.Printf("Sending failure notification for job %s: %s", job.JobID, errorMessage)
	// TODO: Implement email notification for provisioning failure
}

// Worker pool methods
func NewWorkerPool(maxWorkers int, jobQueue chan *ProvisioningJob, app *App) *WorkerPool {
	pool := &WorkerPool{
		workers:    make([]*Worker, maxWorkers),
		jobQueue:   jobQueue,
		quit:       make(chan bool),
		maxWorkers: maxWorkers,
	}

	for i := 0; i < maxWorkers; i++ {
		worker := &Worker{
			id:       i + 1,
			jobQueue: jobQueue,
			quit:     make(chan bool),
			app:      app,
		}
		pool.workers[i] = worker
	}

	return pool
}

func (p *WorkerPool) Start() {
	for _, worker := range p.workers {
		worker.Start()
	}
	log.Printf("Started worker pool with %d workers", p.maxWorkers)
}

func (p *WorkerPool) Stop() {
	for _, worker := range p.workers {
		worker.Stop()
	}
	p.quit <- true
	log.Println("Stopped worker pool")
}

// API handlers
func (app *App) handleProvisionEnvironment(c *gin.Context) {
	var request ProvisioningRequest
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Generate request ID if not provided
	if request.RequestID == "" {
		request.RequestID = uuid.New().String()
	}

	// Set default priority
	if request.Priority == "" {
		request.Priority = PriorityStandard
	}

	// Calculate estimated duration based on POC tier
	estimatedDuration := app.calculateEstimatedDuration(request.POCConfig.POCTier)

	// Create provisioning job
	job := &ProvisioningJob{
		JobID:             uuid.New(),
		TenantID:          request.TenantID,
		TenantSlug:        request.TenantSlug,
		Status:            StatusQueued,
		Priority:          request.Priority,
		RequestID:         request.RequestID,
		RequestedBy:       request.RequestedBy,
		RequestPayload:    structToMap(request),
		TotalSteps:        8, // init, plan, apply, outputs, credentials, notifications, etc.
		CompletedSteps:    0,
		ProgressPercent:   0,
		EstimatedDuration: estimatedDuration,
		ExpiresAt:         request.POCConfig.ExpiresAt,
		AutoCleanup:       true,
		MaxRetries:        3,
		Tags: map[string]interface{}{
			"poc_tier":       request.POCConfig.POCTier,
			"company_size":   request.CompanyInfo.CompanySize,
			"industry":       request.CompanyInfo.IndustryVertical,
		},
	}

	// Save job to database
	if err := app.db.Create(job).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create provisioning job", "details": err.Error()})
		return
	}

	// Add job to queue
	now := time.Now().UTC()
	job.QueuedAt = &now
	app.db.Model(job).Update("queued_at", &now)

	select {
	case app.jobQueue <- job:
		log.Printf("Queued provisioning job %s for tenant %s", job.JobID, job.TenantSlug)
	default:
		// Queue is full
		app.db.Model(job).Updates(map[string]interface{}{
			"status":        StatusFailed,
			"error_message": "Provisioning queue is full, please try again later",
		})
		c.JSON(503, gin.H{"error": "Provisioning queue is full", "message": "Please try again later"})
		return
	}

	// Return response
	response := ProvisioningResponse{
		Success:             true,
		Message:             "Provisioning job queued successfully",
		JobID:               job.JobID,
		Status:              job.Status,
		EstimatedDuration:   estimatedDuration.String(),
		ProgressTrackingURL: fmt.Sprintf("/api/v1/provisioning/status/%s", job.JobID),
	}

	c.JSON(201, response)
}

func (app *App) handleGetProvisioningStatus(c *gin.Context) {
	jobIDStr := c.Param("job_id")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid job ID format"})
		return
	}

	var job ProvisioningJob
	if err := app.db.Where("job_id = ?", jobID).First(&job).Error; err != nil {
		c.JSON(404, gin.H{"error": "Provisioning job not found"})
		return
	}

	response := ProvisioningResponse{
		Success:              job.Status == StatusCompleted,
		JobID:                job.JobID,
		Status:               job.Status,
		Message:              job.CurrentStep,
		ProvisionedResources: job.ProvisionedResources,
		ServiceEndpoints:     job.ServiceEndpoints,
		ErrorMessage:         job.ErrorMessage,
	}

	c.JSON(200, response)
}

func (app *App) handleHealthCheck(c *gin.Context) {
	// Check database connectivity
	sqlDB, err := app.db.DB()
	if err != nil || sqlDB.Ping() != nil {
		c.JSON(503, gin.H{
			"status":    "unhealthy",
			"database":  "disconnected",
			"timestamp": time.Now().UTC(),
		})
		return
	}

	// Check queue status
	queueStatus := "healthy"
	if len(app.jobQueue) >= cap(app.jobQueue)*90/100 {
		queueStatus = "near_full"
	}

	c.JSON(200, gin.H{
		"status":     "healthy",
		"database":   "connected",
		"queue":      queueStatus,
		"workers":    len(app.workerPool.workers),
		"version":    "1.0.0",
		"timestamp":  time.Now().UTC(),
	})
}

// Utility functions
func (app *App) calculateEstimatedDuration(pocTier string) time.Duration {
	switch pocTier {
	case "standard":
		return 15 * time.Minute
	case "enterprise":
		return 30 * time.Minute
	case "premium":
		return 45 * time.Minute
	default:
		return 20 * time.Minute
	}
}

func structToMap(obj interface{}) map[string]interface{} {
	data, _ := json.Marshal(obj)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

func generateSecurePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}
	return string(password)
}

func generateAPIKey() string {
	return "isec_" + uuid.New().String()[:16]
}

func copyDir(src, dst string) error {
	return exec.Command("cp", "-r", src+"/.", dst).Run()
}

// Setup routes
func (app *App) setupRoutes() {
	v1 := app.router.Group("/api/v1")
	{
		v1.GET("/health", app.handleHealthCheck)
		
		provisioning := v1.Group("/provisioning")
		{
			provisioning.POST("/provision", app.handleProvisionEnvironment)
			provisioning.GET("/status/:job_id", app.handleGetProvisioningStatus)
		}
	}

	app.router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service":     "iSECTECH POC Provisioning Engine",
			"version":     "1.0.0",
			"status":      "running",
			"health":      "/api/v1/health",
			"api_version": "v1",
			"timestamp":   time.Now().UTC(),
		})
	})
}

// Main function
func main() {
	config := initConfig()
	
	db, err := initDatabase(config)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	router := initRouter(config)

	// Create job queue
	jobQueue := make(chan *ProvisioningJob, config.MaxConcurrentProvisions*2)

	app := &App{
		config:   config,
		db:       db,
		router:   router,
		jobQueue: jobQueue,
	}

	// Initialize worker pool
	app.workerPool = NewWorkerPool(config.MaxConcurrentProvisions, jobQueue, app)
	app.workerPool.Start()

	app.setupRoutes()

	// Start server
	server := &http.Server{
		Addr:    ":" + config.Port,
		Handler: app.router,
	}

	go func() {
		log.Printf("Starting iSECTECH POC Provisioning Engine on port %s", config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down provisioning engine...")

	// Stop worker pool
	app.workerPool.Stop()

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Provisioning engine stopped")
}