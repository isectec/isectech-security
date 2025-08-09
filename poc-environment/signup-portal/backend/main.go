// iSECTECH POC Signup Portal - Backend API Service
// Production-Grade Go API Server for POC Self-Service Onboarding
// Version: 1.0
// Author: Claude Code Implementation

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Configuration structure
type Config struct {
	Port              string
	DatabaseURL       string
	Environment       string
	CORSAllowOrigins  []string
	JWTSecret         string
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	TerraformBinary   string
	GCPProject        string
	GCPRegion         string
	RedisURL          string
	LogLevel          string
	RateLimitRPS      int
	MaxRequestSize    int64
}

// Database Models (matching schema.sql)
type POCTenant struct {
	TenantID                  uuid.UUID                `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"tenant_id"`
	TenantSlug                string                   `gorm:"unique;not null;size:63" json:"tenant_slug" validate:"required,min=4,max=63,alphanum"`
	CompanyName               string                   `gorm:"not null;size:255" json:"company_name" validate:"required,min=2,max=255"`
	ContactEmail              string                   `gorm:"not null" json:"contact_email" validate:"required,email"`
	ContactName               string                   `gorm:"not null;size:200" json:"contact_name" validate:"required,min=2,max=200"`
	ContactPhone              string                   `gorm:"size:50" json:"contact_phone"`
	WebsiteURL                string                   `gorm:"size:500" json:"website_url" validate:"omitempty,url"`
	
	// Company information
	IndustryVertical          string                   `gorm:"not null;size:100" json:"industry_vertical" validate:"required"`
	CompanySize               string                   `gorm:"not null" json:"company_size" validate:"required,oneof=startup small medium large enterprise"`
	HeadquartersCountry       string                   `gorm:"not null;size:2" json:"headquarters_country" validate:"required,len=2"`
	EmployeeCount             *int                     `json:"employee_count" validate:"omitempty,min=1"`
	AnnualRevenue             *int64                   `json:"annual_revenue" validate:"omitempty,min=0"`
	
	// POC configuration
	POCTier                   string                   `gorm:"not null;default:standard" json:"poc_tier" validate:"required,oneof=standard enterprise premium"`
	CreatedAt                 time.Time                `gorm:"default:now()" json:"created_at"`
	ActivatedAt               *time.Time               `json:"activated_at"`
	ExpiresAt                 time.Time                `gorm:"not null" json:"expires_at" validate:"required"`
	Status                    string                   `gorm:"not null;default:provisioning" json:"status"`
	
	// Resource allocation (JSONB)
	ResourceAllocation        map[string]interface{}   `gorm:"type:jsonb;default:'{}'" json:"resource_allocation"`
	FeatureFlags              map[string]interface{}   `gorm:"type:jsonb;default:'{}'" json:"feature_flags"`
	
	// Security and compliance
	SecurityClearance         string                   `gorm:"not null;default:unclassified" json:"security_clearance" validate:"required,oneof=unclassified confidential secret top_secret"`
	DataResidencyRegion       string                   `gorm:"not null;default:us" json:"data_residency_region" validate:"required"`
	ComplianceFrameworks      pq.StringArray           `gorm:"type:text[];default:'{soc2}'" json:"compliance_frameworks"`
	
	// Cybersecurity-specific profile
	CurrentSecurityTools      map[string]interface{}   `gorm:"type:jsonb;default:'{}'" json:"current_security_tools"`
	SecurityMaturityLevel     *int                     `gorm:"check:security_maturity_level BETWEEN 1 AND 5" json:"security_maturity_level" validate:"omitempty,min=1,max=5"`
	PrimarySecurityChallenges pq.StringArray           `gorm:"type:text[]" json:"primary_security_challenges"`
	EvaluationObjectives      pq.StringArray           `gorm:"type:text[]" json:"evaluation_objectives"`
	SuccessCriteria           map[string]interface{}   `gorm:"type:jsonb;default:'{}'" json:"success_criteria"`
	
	// Business context
	DecisionMakers            []map[string]interface{} `gorm:"type:jsonb;default:'[]'" json:"decision_makers"`
	BudgetRange               string                   `gorm:"size:50" json:"budget_range"`
	TimelineToDecision        string                   `gorm:"size:50" json:"timeline_to_decision"`
	CompetitiveAlternatives   pq.StringArray           `gorm:"type:text[]" json:"competitive_alternatives"`
	
	// Technical requirements
	IntegrationRequirements   map[string]interface{}   `gorm:"type:jsonb;default:'{}'" json:"integration_requirements"`
	ComplianceRequirements    map[string]interface{}   `gorm:"type:jsonb;default:'{}'" json:"compliance_requirements"`
	ScalabilityRequirements   map[string]interface{}   `gorm:"type:jsonb;default:'{}'" json:"scalability_requirements"`
	
	// Lifecycle management
	AutoCleanupEnabled        bool                     `gorm:"default:true" json:"auto_cleanup_enabled"`
	CleanupScheduledAt        *time.Time               `json:"cleanup_scheduled_at"`
	ExtensionRequests         int                      `gorm:"default:0" json:"extension_requests"`
	MaxExtensions             int                      `gorm:"default:2" json:"max_extensions"`
	
	// Tracking and analytics
	SourceCampaign            string                   `gorm:"size:100" json:"source_campaign"`
	LeadScore                 *int                     `gorm:"check:lead_score BETWEEN 0 AND 100" json:"lead_score" validate:"omitempty,min=0,max=100"`
	ConversionProbability     *float64                 `gorm:"check:conversion_probability BETWEEN 0 AND 100" json:"conversion_probability" validate:"omitempty,min=0,max=100"`
	
	// Audit fields
	CreatedBy                 *uuid.UUID               `json:"created_by"`
	UpdatedAt                 time.Time                `gorm:"default:now()" json:"updated_at"`
	UpdatedBy                 *uuid.UUID               `json:"updated_by"`
}

// POC Signup Request structure
type POCSignupRequest struct {
	// Company Information
	CompanyName         string   `json:"company_name" binding:"required,min=2,max=255"`
	IndustryVertical    string   `json:"industry_vertical" binding:"required"`
	CompanySize         string   `json:"company_size" binding:"required,oneof=startup small medium large enterprise"`
	EmployeeCount       *int     `json:"employee_count" binding:"omitempty,min=1"`
	AnnualRevenue       *int64   `json:"annual_revenue" binding:"omitempty,min=0"`
	HeadquartersCountry string   `json:"headquarters_country" binding:"required,len=2"`
	WebsiteURL          string   `json:"website_url" binding:"omitempty,url"`
	
	// Contact Information
	ContactName  string `json:"contact_name" binding:"required,min=2,max=200"`
	ContactEmail string `json:"contact_email" binding:"required,email"`
	ContactPhone string `json:"contact_phone" binding:"omitempty,max=50"`
	JobTitle     string `json:"job_title" binding:"omitempty,max=150"`
	Department   string `json:"department" binding:"omitempty,max=100"`
	
	// POC Configuration
	POCTier            string   `json:"poc_tier" binding:"required,oneof=standard enterprise premium"`
	POCDurationDays    int      `json:"poc_duration_days" binding:"required,min=7,max=180"`
	SecurityClearance  string   `json:"security_clearance" binding:"required,oneof=unclassified confidential secret top_secret"`
	DataResidencyRegion string  `json:"data_residency_region" binding:"required"`
	ComplianceFrameworks []string `json:"compliance_frameworks" binding:"required,min=1"`
	
	// Security Assessment
	CurrentSecurityTools      map[string]interface{} `json:"current_security_tools"`
	SecurityMaturityLevel     *int                   `json:"security_maturity_level" binding:"omitempty,min=1,max=5"`
	PrimarySecurityChallenges []string               `json:"primary_security_challenges"`
	EvaluationObjectives      []string               `json:"evaluation_objectives"`
	SuccessCriteria           map[string]interface{} `json:"success_criteria"`
	
	// Business Context
	DecisionMakers          []map[string]interface{} `json:"decision_makers"`
	BudgetRange             string                   `json:"budget_range"`
	TimelineToDecision      string                   `json:"timeline_to_decision"`
	CompetitiveAlternatives []string                 `json:"competitive_alternatives"`
	
	// Technical Requirements
	IntegrationRequirements map[string]interface{} `json:"integration_requirements"`
	ComplianceRequirements  map[string]interface{} `json:"compliance_requirements"`
	ScalabilityRequirements map[string]interface{} `json:"scalability_requirements"`
	
	// Tracking
	SourceCampaign string `json:"source_campaign"`
	
	// Legal Agreements
	TermsAccepted           bool `json:"terms_accepted" binding:"required,eq=true"`
	PrivacyPolicyAccepted   bool `json:"privacy_policy_accepted" binding:"required,eq=true"`
	NDAAccepted             bool `json:"nda_accepted" binding:"required,eq=true"`
	MarketingOptIn          bool `json:"marketing_opt_in"`
}

// POC Signup Response
type POCSignupResponse struct {
	Success           bool      `json:"success"`
	Message           string    `json:"message"`
	TenantID          uuid.UUID `json:"tenant_id,omitempty"`
	TenantSlug        string    `json:"tenant_slug,omitempty"`
	ProvisioningID    string    `json:"provisioning_id,omitempty"`
	EstimatedReadyAt  time.Time `json:"estimated_ready_at,omitempty"`
	AccessInstructions string   `json:"access_instructions,omitempty"`
	SupportContact    string    `json:"support_contact,omitempty"`
}

// API Error Response
type ErrorResponse struct {
	Error      string                 `json:"error"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	RequestID  string                 `json:"request_id"`
	Timestamp  time.Time              `json:"timestamp"`
}

// Application struct
type App struct {
	config    *Config
	db        *gorm.DB
	validator *validator.Validate
	router    *gin.Engine
}

// Initialize configuration from environment variables
func initConfig() *Config {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	config := &Config{
		Port:              getEnv("PORT", "8080"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://localhost/isectech_poc?sslmode=disable"),
		Environment:       getEnv("ENVIRONMENT", "development"),
		JWTSecret:         getEnv("JWT_SECRET", "your-super-secret-key-change-in-production"),
		SMTPHost:          getEnv("SMTP_HOST", "localhost"),
		SMTPPort:          getEnvAsInt("SMTP_PORT", 587),
		SMTPUsername:      getEnv("SMTP_USERNAME", ""),
		SMTPPassword:      getEnv("SMTP_PASSWORD", ""),
		TerraformBinary:   getEnv("TERRAFORM_BINARY", "terraform"),
		GCPProject:        getEnv("GCP_PROJECT", "isectech-poc-platform"),
		GCPRegion:         getEnv("GCP_REGION", "us-central1"),
		RedisURL:          getEnv("REDIS_URL", "redis://localhost:6379"),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		RateLimitRPS:      getEnvAsInt("RATE_LIMIT_RPS", 100),
		MaxRequestSize:    getEnvAsInt64("MAX_REQUEST_SIZE", 10*1024*1024), // 10MB
	}

	// Parse CORS allowed origins
	corsOrigins := getEnv("CORS_ALLOW_ORIGINS", "http://localhost:3000,https://app.isectech.org,https://signup.isectech.org")
	config.CORSAllowOrigins = strings.Split(corsOrigins, ",")

	return config
}

// Helper functions for environment variables
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

func getEnvAsInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// Initialize database connection
func initDatabase(config *Config) (*gorm.DB, error) {
	// Configure GORM logger based on environment
	var gormLogger logger.Interface
	if config.Environment == "production" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	} else {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	// Connect to PostgreSQL
	db, err := gorm.Open(postgres.Open(config.DatabaseURL), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// Initialize Gin router with middleware
func initRouter(config *Config) *gin.Engine {
	// Set Gin mode
	if config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add custom middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(requestid.New())

	// CORS configuration
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = config.CORSAllowOrigins
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization", "X-Request-ID"}
	corsConfig.ExposeHeaders = []string{"X-Request-ID"}
	corsConfig.AllowCredentials = true
	router.Use(cors.New(corsConfig))

	// Request size limit middleware
	router.Use(func(c *gin.Context) {
		if c.Request.ContentLength > config.MaxRequestSize {
			c.JSON(http.StatusRequestEntityTooLarge, ErrorResponse{
				Error:     "request_too_large",
				Message:   "Request body too large",
				RequestID: requestid.Get(c),
				Timestamp: time.Now().UTC(),
			})
			c.Abort()
			return
		}
		c.Next()
	})

	return router
}

// Generate unique tenant slug from company name
func generateTenantSlug(companyName string) string {
	// Convert to lowercase and replace spaces/special chars with hyphens
	slug := strings.ToLower(companyName)
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "&", "and")
	
	// Remove special characters except hyphens
	var result strings.Builder
	for _, char := range slug {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			result.WriteRune(char)
		}
	}
	
	slug = result.String()
	
	// Ensure it starts and ends with alphanumeric
	slug = strings.Trim(slug, "-")
	
	// Add random suffix to ensure uniqueness
	suffix := uuid.New().String()[:8]
	slug = fmt.Sprintf("%s-%s", slug, suffix)
	
	// Ensure length constraints (4-63 characters)
	if len(slug) > 63 {
		slug = slug[:55] + "-" + suffix
	}
	if len(slug) < 4 {
		slug = "poc-" + suffix
	}
	
	return slug
}

// Calculate POC expiration date
func calculateExpirationDate(durationDays int) time.Time {
	return time.Now().UTC().AddDate(0, 0, durationDays)
}

// POC Signup Handler
func (app *App) handlePOCSignup(c *gin.Context) {
	var request POCSignupRequest
	
	// Bind and validate JSON request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:     "validation_error",
			Message:   "Invalid request format or missing required fields",
			Details:   map[string]interface{}{"validation_errors": err.Error()},
			RequestID: requestid.Get(c),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Additional custom validation
	if err := app.validator.Struct(request); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:     "validation_error",
			Message:   "Request validation failed",
			Details:   map[string]interface{}{"validation_errors": err.Error()},
			RequestID: requestid.Get(c),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Check for duplicate email/company
	var existingTenant POCTenant
	if err := app.db.Where("contact_email = ? OR company_name = ?", 
		request.ContactEmail, request.CompanyName).First(&existingTenant).Error; err == nil {
		c.JSON(http.StatusConflict, ErrorResponse{
			Error:     "duplicate_registration",
			Message:   "A POC environment already exists for this company or email address",
			RequestID: requestid.Get(c),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Generate tenant ID and slug
	tenantID := uuid.New()
	tenantSlug := generateTenantSlug(request.CompanyName)

	// Create POC tenant record
	tenant := POCTenant{
		TenantID:                  tenantID,
		TenantSlug:                tenantSlug,
		CompanyName:               request.CompanyName,
		ContactEmail:              request.ContactEmail,
		ContactName:               request.ContactName,
		ContactPhone:              request.ContactPhone,
		WebsiteURL:                request.WebsiteURL,
		IndustryVertical:          request.IndustryVertical,
		CompanySize:               request.CompanySize,
		HeadquartersCountry:       request.HeadquartersCountry,
		EmployeeCount:             request.EmployeeCount,
		AnnualRevenue:             request.AnnualRevenue,
		POCTier:                   request.POCTier,
		ExpiresAt:                 calculateExpirationDate(request.POCDurationDays),
		Status:                    "provisioning",
		SecurityClearance:         request.SecurityClearance,
		DataResidencyRegion:       request.DataResidencyRegion,
		ComplianceFrameworks:      request.ComplianceFrameworks,
		CurrentSecurityTools:      request.CurrentSecurityTools,
		SecurityMaturityLevel:     request.SecurityMaturityLevel,
		PrimarySecurityChallenges: request.PrimarySecurityChallenges,
		EvaluationObjectives:      request.EvaluationObjectives,
		SuccessCriteria:           request.SuccessCriteria,
		DecisionMakers:            request.DecisionMakers,
		BudgetRange:               request.BudgetRange,
		TimelineToDecision:        request.TimelineToDecision,
		CompetitiveAlternatives:   request.CompetitiveAlternatives,
		IntegrationRequirements:   request.IntegrationRequirements,
		ComplianceRequirements:    request.ComplianceRequirements,
		ScalabilityRequirements:   request.ScalabilityRequirements,
		AutoCleanupEnabled:        true,
		SourceCampaign:            request.SourceCampaign,
		CreatedAt:                 time.Now().UTC(),
		UpdatedAt:                 time.Now().UTC(),
	}

	// Set resource allocation based on POC tier
	resourceAllocation := map[string]interface{}{
		"cpu_cores":    getTierResource(request.POCTier, "cpu"),
		"memory_gb":    getTierResource(request.POCTier, "memory"), 
		"storage_gb":   getTierResource(request.POCTier, "storage"),
		"max_users":    getTierResource(request.POCTier, "users"),
		"tier":         request.POCTier,
	}
	tenant.ResourceAllocation = resourceAllocation

	// Set feature flags based on POC tier
	featureFlags := getFeatureFlagsForTier(request.POCTier)
	tenant.FeatureFlags = featureFlags

	// Begin database transaction
	tx := app.db.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:     "database_error",
			Message:   "Failed to initialize database transaction",
			RequestID: requestid.Get(c),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Create tenant record
	if err := tx.Create(&tenant).Error; err != nil {
		tx.Rollback()
		log.Printf("Failed to create POC tenant: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:     "creation_failed",
			Message:   "Failed to create POC environment record",
			RequestID: requestid.Get(c),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Create initial user record for the primary contact
	user := struct {
		UserID        uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()"`
		TenantID      uuid.UUID `gorm:"not null"`
		Email         string    `gorm:"not null"`
		FirstName     string    `gorm:"not null"`
		LastName      string    `gorm:"not null"` 
		JobTitle      string
		Department    string
		Role          string    `gorm:"not null;default:poc_admin"`
		IsActive      bool      `gorm:"default:true"`
		IsPrimaryContact bool   `gorm:"default:false"`
		CreatedAt     time.Time `gorm:"default:now()"`
		UpdatedAt     time.Time `gorm:"default:now()"`
	}{
		UserID:        uuid.New(),
		TenantID:      tenantID,
		Email:         request.ContactEmail,
		FirstName:     strings.Split(request.ContactName, " ")[0],
		LastName:      getLastName(request.ContactName),
		JobTitle:      request.JobTitle,
		Department:    request.Department,
		Role:          "poc_admin",
		IsActive:      true,
		IsPrimaryContact: true,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	// Create user record (using raw SQL for poc_users table)
	userSQL := `
		INSERT INTO poc_users (user_id, tenant_id, email, first_name, last_name, job_title, department, role, is_active, is_primary_contact, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	if err := tx.Exec(userSQL, user.UserID, user.TenantID, user.Email, user.FirstName, user.LastName, 
		user.JobTitle, user.Department, user.Role, user.IsActive, user.IsPrimaryContact, 
		user.CreatedAt, user.UpdatedAt).Error; err != nil {
		tx.Rollback()
		log.Printf("Failed to create initial user: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:     "user_creation_failed",
			Message:   "Failed to create initial user account",
			RequestID: requestid.Get(c),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		log.Printf("Failed to commit POC creation transaction: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:     "transaction_failed",
			Message:   "Failed to complete POC environment creation",
			RequestID: requestid.Get(c),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	// TODO: Trigger asynchronous infrastructure provisioning
	provisioningID := uuid.New().String()
	go app.provisionPOCInfrastructure(tenantID, tenant, provisioningID)

	// Calculate estimated ready time (based on POC tier)
	estimatedReadyAt := time.Now().UTC().Add(getProvisioningTime(request.POCTier))

	// Send welcome email (async)
	go app.sendWelcomeEmail(tenant, user.UserID)

	// Return success response
	response := POCSignupResponse{
		Success:           true,
		Message:           "POC environment creation initiated successfully",
		TenantID:          tenantID,
		TenantSlug:        tenantSlug,
		ProvisioningID:    provisioningID,
		EstimatedReadyAt:  estimatedReadyAt,
		AccessInstructions: fmt.Sprintf("You will receive an email at %s with access instructions once your POC environment is ready.", request.ContactEmail),
		SupportContact:    "poc-support@isectech.org",
	}

	c.JSON(http.StatusCreated, response)
}

// Helper functions
func getTierResource(tier, resourceType string) interface{} {
	resources := map[string]map[string]interface{}{
		"standard": {
			"cpu":     8,
			"memory":  32,
			"storage": 500,
			"users":   25,
		},
		"enterprise": {
			"cpu":     16,
			"memory":  64,
			"storage": 1000,
			"users":   100,
		},
		"premium": {
			"cpu":     32,
			"memory":  128,
			"storage": 2000,
			"users":   500,
		},
	}
	return resources[tier][resourceType]
}

func getFeatureFlagsForTier(tier string) map[string]interface{} {
	baseFeatures := map[string]interface{}{
		"threat_detection":       true,
		"vulnerability_management": true,
		"compliance_reporting":   true,
		"siem_analytics":         true,
		"dashboards_reporting":   true,
	}

	if tier == "enterprise" || tier == "premium" {
		baseFeatures["email_security"] = true
		baseFeatures["network_monitoring"] = true
		baseFeatures["identity_analytics"] = true
		baseFeatures["incident_response"] = true
	}

	if tier == "premium" {
		baseFeatures["soar_automation"] = true
		baseFeatures["ai_ml_analytics"] = true
		baseFeatures["custom_integrations"] = true
		baseFeatures["advanced_reporting"] = true
		baseFeatures["api_access"] = true
	}

	return baseFeatures
}

func getLastName(fullName string) string {
	parts := strings.Split(fullName, " ")
	if len(parts) > 1 {
		return strings.Join(parts[1:], " ")
	}
	return ""
}

func getProvisioningTime(tier string) time.Duration {
	switch tier {
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

// Async infrastructure provisioning (placeholder)
func (app *App) provisionPOCInfrastructure(tenantID uuid.UUID, tenant POCTenant, provisioningID string) {
	log.Printf("Starting infrastructure provisioning for tenant %s (ID: %s)", tenant.TenantSlug, provisioningID)
	
	// TODO: Implement actual Terraform-based infrastructure provisioning
	// This would integrate with the Terraform modules we created
	
	// Simulate provisioning time
	time.Sleep(2 * time.Minute)
	
	// Update tenant status to active
	app.db.Model(&tenant).Where("tenant_id = ?", tenantID).Updates(map[string]interface{}{
		"status":       "active",
		"activated_at": time.Now().UTC(),
		"updated_at":   time.Now().UTC(),
	})
	
	log.Printf("Infrastructure provisioning completed for tenant %s", tenant.TenantSlug)
}

// Send welcome email (placeholder)
func (app *App) sendWelcomeEmail(tenant POCTenant, userID uuid.UUID) {
	log.Printf("Sending welcome email to %s for tenant %s", tenant.ContactEmail, tenant.TenantSlug)
	
	// TODO: Implement actual email sending with SMTP configuration
	// Include access instructions, credentials, and getting started guide
	
	log.Printf("Welcome email sent successfully to %s", tenant.ContactEmail)
}

// Health check endpoint
func (app *App) handleHealthCheck(c *gin.Context) {
	// Check database connectivity
	sqlDB, err := app.db.DB()
	if err != nil || sqlDB.Ping() != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":    "unhealthy",
			"database":  "disconnected",
			"timestamp": time.Now().UTC(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"database":  "connected",
		"version":   "1.0.0",
		"timestamp": time.Now().UTC(),
	})
}

// Setup routes
func (app *App) setupRoutes() {
	// API v1 group
	v1 := app.router.Group("/api/v1")
	{
		// Health and status
		v1.GET("/health", app.handleHealthCheck)
		
		// POC management
		poc := v1.Group("/poc")
		{
			poc.POST("/signup", app.handlePOCSignup)
			// TODO: Add additional POC management endpoints
			// poc.GET("/status/:tenant_id", app.handlePOCStatus)
			// poc.POST("/extend/:tenant_id", app.handlePOCExtension)
			// poc.DELETE("/:tenant_id", app.handlePOCTermination)
		}
	}

	// Serve static files for documentation
	app.router.Static("/docs", "./docs")
	
	// Default route
	app.router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service":     "iSECTECH POC Signup Portal API",
			"version":     "1.0.0",
			"status":      "running",
			"docs":        "/docs",
			"health":      "/api/v1/health",
			"api_version": "v1",
			"timestamp":   time.Now().UTC(),
		})
	})
}

// Initialize and run the application
func main() {
	// Initialize configuration
	config := initConfig()
	
	// Initialize database
	db, err := initDatabase(config)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize router
	router := initRouter(config)

	// Initialize validator
	validator := validator.New()

	// Create application instance
	app := &App{
		config:    config,
		db:        db,
		validator: validator,
		router:    router,
	}

	// Setup routes
	app.setupRoutes()

	// Create HTTP server
	server := &http.Server{
		Addr:           ":" + config.Port,
		Handler:        app.router,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting iSECTECH POC Signup Portal API server on port %s", config.Port)
		log.Printf("Environment: %s", config.Environment)
		log.Printf("Documentation available at: http://localhost:%s/docs", config.Port)
		
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	log.Println("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	// Close database connection
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}

	log.Println("Server exited")
}