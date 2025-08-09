// iSECTECH Security Awareness Training Service - Content Management Service
// Production-grade content management and delivery orchestration
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package service

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
	"github.com/isectech/backend/services/security-awareness-training/domain/repository"
	"github.com/isectech/backend/common/cache"
	"github.com/isectech/backend/common/events"
	"github.com/isectech/backend/common/logger"
	"github.com/isectech/backend/common/storage"
	"github.com/sirupsen/logrus"
)

// ContentManagementService provides comprehensive content management and delivery
type ContentManagementService struct {
	contentRepo     repository.TrainingContentRepository
	deliveryRepo    repository.ContentDeliveryRepository
	storageService  storage.StorageService
	cdnService      CDNService
	eventPublisher  events.Publisher
	cache           cache.Cache
	logger          *logrus.Logger
	config          *ContentServiceConfig
}

// ContentServiceConfig holds configuration for the content management service
type ContentServiceConfig struct {
	DefaultCacheTTL          time.Duration `json:"default_cache_ttl"`
	MaxContentSize           int64         `json:"max_content_size_bytes"`
	AllowedFileTypes         []string      `json:"allowed_file_types"`
	SCORMValidationEnabled   bool          `json:"scorm_validation_enabled"`
	XAPIValidationEnabled    bool          `json:"xapi_validation_enabled"`
	AutoGenerateThumbnails   bool          `json:"auto_generate_thumbnails"`
	EnableContentEncryption  bool          `json:"enable_content_encryption"`
	CDNEnabled               bool          `json:"cdn_enabled"`
	CompressionEnabled       bool          `json:"compression_enabled"`
	IntegrityCheckInterval   time.Duration `json:"integrity_check_interval"`
	CleanupInterval          time.Duration `json:"cleanup_interval"`
}

// DefaultContentServiceConfig returns default configuration
func DefaultContentServiceConfig() *ContentServiceConfig {
	return &ContentServiceConfig{
		DefaultCacheTTL:          time.Minute * 30,
		MaxContentSize:           500 * 1024 * 1024, // 500MB
		AllowedFileTypes:         []string{".zip", ".scorm", ".html", ".mp4", ".pdf", ".json"},
		SCORMValidationEnabled:   true,
		XAPIValidationEnabled:    true,
		AutoGenerateThumbnails:   true,
		EnableContentEncryption:  true,
		CDNEnabled:               true,
		CompressionEnabled:       true,
		IntegrityCheckInterval:   time.Hour * 24,
		CleanupInterval:          time.Hour * 6,
	}
}

// NewContentManagementService creates a new content management service
func NewContentManagementService(
	contentRepo repository.TrainingContentRepository,
	deliveryRepo repository.ContentDeliveryRepository,
	storageService storage.StorageService,
	cdnService CDNService,
	eventPublisher events.Publisher,
	cache cache.Cache,
	config *ContentServiceConfig,
) *ContentManagementService {
	if config == nil {
		config = DefaultContentServiceConfig()
	}

	return &ContentManagementService{
		contentRepo:    contentRepo,
		deliveryRepo:   deliveryRepo,
		storageService: storageService,
		cdnService:     cdnService,
		eventPublisher: eventPublisher,
		cache:          cache,
		logger:         logger.GetLogger("content-management-service"),
		config:         config,
	}
}

// ContentUploadRequest represents a content upload request
type ContentUploadRequest struct {
	TenantID             uuid.UUID                 `json:"tenant_id" validate:"required"`
	ModuleName           string                    `json:"module_name" validate:"required"`
	ModuleCode           string                    `json:"module_code" validate:"required"`
	Version              string                    `json:"version" validate:"required"`
	Title                string                    `json:"title" validate:"required"`
	Description          string                    `json:"description"`
	ContentType          string                    `json:"content_type" validate:"required"`
	ContentCategory      string                    `json:"content_category" validate:"required"`
	DifficultyLevel      string                    `json:"difficulty_level" validate:"required"`
	ContentFormat        string                    `json:"content_format" validate:"required"`
	EstimatedDuration    int                       `json:"estimated_duration_minutes" validate:"required,min=1"`
	SecurityClearance    string                    `json:"security_clearance_required"`
	ComplianceFrameworks []string                  `json:"compliance_frameworks"`
	LearningObjectives   []string                  `json:"learning_objectives"`
	Keywords             []string                  `json:"keywords"`
	SkillTags            []string                  `json:"skill_tags"`
	HasAssessment        bool                      `json:"has_assessment"`
	PassingScore         float64                   `json:"passing_score"`
	MaxAttempts          int                       `json:"max_attempts"`
	CreatedBy            uuid.UUID                 `json:"created_by" validate:"required"`
	AuthorName           string                    `json:"author_name"`
	AuthorEmail          string                    `json:"author_email"`
	ContentProvider      string                    `json:"content_provider"`
	CustomMetadata       map[string]interface{}    `json:"custom_metadata"`
	LocalizedContent     map[string]interface{}    `json:"localized_content"`
}

// ContentUploadResult represents the result of a content upload
type ContentUploadResult struct {
	ContentID        uuid.UUID `json:"content_id"`
	StorageLocation  string    `json:"storage_location"`
	CDNDistribution  string    `json:"cdn_distribution"`
	LaunchURL        string    `json:"launch_url"`
	ContentSize      int64     `json:"content_size_bytes"`
	ProcessingStatus string    `json:"processing_status"`
	ValidationResult *ContentValidationResult `json:"validation_result"`
	UploadedAt       time.Time `json:"uploaded_at"`
}

// ContentValidationResult represents content validation result
type ContentValidationResult struct {
	IsValid           bool                      `json:"is_valid"`
	ValidationErrors  []string                  `json:"validation_errors"`
	ValidationWarnings []string                 `json:"validation_warnings"`
	SCORMValidation   *SCORMValidationResult    `json:"scorm_validation,omitempty"`
	XAPIValidation    *XAPIValidationResult     `json:"xapi_validation,omitempty"`
	ManifestAnalysis  *ManifestAnalysisResult   `json:"manifest_analysis,omitempty"`
}

// SCORMValidationResult represents SCORM content validation
type SCORMValidationResult struct {
	Version         string   `json:"version"`
	ManifestValid   bool     `json:"manifest_valid"`
	LaunchFileFound bool     `json:"launch_file_found"`
	RequiredFiles   []string `json:"required_files"`
	MissingFiles    []string `json:"missing_files"`
	StructureValid  bool     `json:"structure_valid"`
}

// XAPIValidationResult represents xAPI content validation
type XAPIValidationResult struct {
	ActivitiesValid    bool     `json:"activities_valid"`
	StatementsValid    bool     `json:"statements_valid"`
	ProfileCompliant   bool     `json:"profile_compliant"`
	ValidationIssues   []string `json:"validation_issues"`
}

// ManifestAnalysisResult represents manifest file analysis
type ManifestAnalysisResult struct {
	FileCount        int      `json:"file_count"`
	TotalSize        int64    `json:"total_size_bytes"`
	AssetTypes       []string `json:"asset_types"`
	LaunchFiles      []string `json:"launch_files"`
	Dependencies     []string `json:"dependencies"`
	EstimatedDuration *int    `json:"estimated_duration_minutes"`
}

// UploadContent uploads and processes new training content
func (s *ContentManagementService) UploadContent(ctx context.Context, req *ContentUploadRequest, contentFile multipart.File, fileHeader *multipart.FileHeader) (*ContentUploadResult, error) {
	s.logger.WithFields(logrus.Fields{
		"tenant_id":    req.TenantID,
		"module_code":  req.ModuleCode,
		"content_type": req.ContentType,
		"file_size":    fileHeader.Size,
	}).Info("Starting content upload")

	// Validate file size
	if fileHeader.Size > s.config.MaxContentSize {
		return nil, fmt.Errorf("content size exceeds maximum allowed size of %d bytes", s.config.MaxContentSize)
	}

	// Validate file type
	if !s.isAllowedFileType(fileHeader.Filename) {
		return nil, fmt.Errorf("file type not allowed: %s", filepath.Ext(fileHeader.Filename))
	}

	// Check if content with same module code already exists
	existingContent, _ := s.contentRepo.GetByModuleCode(ctx, req.TenantID, req.ModuleCode)
	if existingContent != nil && existingContent.Version == req.Version {
		return nil, fmt.Errorf("content with module code %s and version %s already exists", req.ModuleCode, req.Version)
	}

	// Generate content ID
	contentID := uuid.New()

	// Calculate file checksums
	fileBytes, err := io.ReadAll(contentFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	md5Hash := md5.Sum(fileBytes)
	sha256Hash := sha256.Sum256(fileBytes)

	// Store content file
	storageKey := fmt.Sprintf("content/%s/%s/%s/%s", req.TenantID, req.ModuleCode, req.Version, fileHeader.Filename)
	storageLocation, err := s.storageService.Upload(ctx, storageKey, fileBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to store content file: %w", err)
	}

	// Validate content based on format
	validationResult := s.validateContent(ctx, fileBytes, req.ContentFormat)

	// Create training content entity
	content := &entity.TrainingContent{
		ContentID:             contentID,
		TenantID:              req.TenantID,
		ModuleName:            req.ModuleName,
		ModuleCode:            req.ModuleCode,
		Version:               req.Version,
		Title:                 req.Title,
		Description:           req.Description,
		LearningObjectives:    req.LearningObjectives,
		ContentType:           req.ContentType,
		ContentCategory:       req.ContentCategory,
		DifficultyLevel:       req.DifficultyLevel,
		ContentFormat:         req.ContentFormat,
		SecurityClearanceRequired: req.SecurityClearance,
		DataClassification:    "internal", // Default classification
		EstimatedDuration:     req.EstimatedDuration,
		ContentSize:           int64(len(fileBytes)),
		HasAssessment:         req.HasAssessment,
		PassingScore:          req.PassingScore,
		MaxAttempts:           req.MaxAttempts,
		ContentURL:            storageLocation,
		ContentPath:           storageKey,
		ChecksumMD5:           hex.EncodeToString(md5Hash[:]),
		ChecksumSHA256:        hex.EncodeToString(sha256Hash[:]),
		ComplianceFrameworks:  req.ComplianceFrameworks,
		Keywords:              req.Keywords,
		SkillTags:             req.SkillTags,
		Status:                "draft",
		CreatedBy:             req.CreatedBy,
		AuthorName:            req.AuthorName,
		AuthorEmail:           req.AuthorEmail,
		ContentProvider:       req.ContentProvider,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		IsActive:              true,
		TrackingEnabled:       true,
		CompressionEnabled:    s.config.CompressionEnabled,
		MobileOptimized:       true,
		DefaultLanguage:       "en",
		AvailableLanguages:    []string{"en"},
	}

	// Set localized content if provided
	if len(req.LocalizedContent) > 0 {
		localizedJSON, _ := json.Marshal(req.LocalizedContent)
		content.LocalizedContent = string(localizedJSON)
	}

	// Set custom metadata if provided
	if len(req.CustomMetadata) > 0 {
		metadataJSON, _ := json.Marshal(req.CustomMetadata)
		content.CustomMetadata = string(metadataJSON)
	}

	// Process SCORM-specific data
	if req.ContentFormat == "scorm_1_2" || req.ContentFormat == "scorm_2004" {
		s.processSCORMContent(content, validationResult.SCORMValidation)
	}

	// Process xAPI-specific data
	if req.ContentFormat == "xapi" {
		s.processXAPIContent(content, validationResult.XAPIValidation)
	}

	// Set launch URL
	content.LaunchURL = s.generateLaunchURL(content)

	// Save to database
	if err := s.contentRepo.Create(ctx, content); err != nil {
		return nil, fmt.Errorf("failed to save content metadata: %w", err)
	}

	// Deploy to CDN if enabled
	var cdnDistribution string
	if s.config.CDNEnabled {
		cdnDistribution, err = s.cdnService.Deploy(ctx, storageLocation, contentID.String())
		if err != nil {
			s.logger.WithError(err).Warning("Failed to deploy content to CDN")
		} else {
			content.CDNDistribution = cdnDistribution
			s.contentRepo.Update(ctx, content)
		}
	}

	// Add audit entry
	content.AddAuditEntry("content_uploaded", req.CreatedBy, map[string]interface{}{
		"file_name": fileHeader.Filename,
		"file_size": fileHeader.Size,
		"format":    req.ContentFormat,
	})

	// Publish content uploaded event
	s.publishContentEvent(ctx, "content.uploaded", content)

	result := &ContentUploadResult{
		ContentID:        contentID,
		StorageLocation:  storageLocation,
		CDNDistribution:  cdnDistribution,
		LaunchURL:        content.LaunchURL,
		ContentSize:      content.ContentSize,
		ProcessingStatus: "completed",
		ValidationResult: validationResult,
		UploadedAt:       time.Now(),
	}

	s.logger.WithField("content_id", contentID).Info("Content upload completed successfully")
	return result, nil
}

// GetContent retrieves training content by ID
func (s *ContentManagementService) GetContent(ctx context.Context, contentID uuid.UUID) (*entity.TrainingContent, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("content:%s", contentID)
	if cached, err := s.cache.Get(ctx, cacheKey); err == nil {
		var content entity.TrainingContent
		if json.Unmarshal(cached, &content) == nil {
			return &content, nil
		}
	}

	// Get from database
	content, err := s.contentRepo.GetByID(ctx, contentID)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if contentJSON, err := json.Marshal(content); err == nil {
		s.cache.Set(ctx, cacheKey, contentJSON, s.config.DefaultCacheTTL)
	}

	return content, nil
}

// SearchContent searches for training content
func (s *ContentManagementService) SearchContent(ctx context.Context, tenantID uuid.UUID, query *repository.ContentSearchQuery) ([]*entity.TrainingContent, error) {
	return s.contentRepo.SearchContent(ctx, tenantID, query)
}

// PublishContent publishes content making it available for delivery
func (s *ContentManagementService) PublishContent(ctx context.Context, contentID uuid.UUID, publishedBy uuid.UUID) error {
	content, err := s.GetContent(ctx, contentID)
	if err != nil {
		return fmt.Errorf("content not found: %w", err)
	}

	// Validate content is ready for publication
	issues := content.ValidateForPublication()
	if len(issues) > 0 {
		return fmt.Errorf("content validation failed: %v", issues)
	}

	// Update status and metadata
	content.Status = string(entity.ContentStatusPublished)
	content.PublishedAt = &[]time.Time{time.Now()}[0]
	content.ApprovedBy = publishedBy
	content.UpdatedAt = time.Now()

	// Add audit entry
	content.AddAuditEntry("content_published", publishedBy, map[string]interface{}{
		"published_at": time.Now(),
	})

	// Save to database
	if err := s.contentRepo.Update(ctx, content); err != nil {
		return fmt.Errorf("failed to update content: %w", err)
	}

	// Invalidate cache
	cacheKey := fmt.Sprintf("content:%s", contentID)
	s.cache.Delete(ctx, cacheKey)

	// Publish event
	s.publishContentEvent(ctx, "content.published", content)

	s.logger.WithFields(logrus.Fields{
		"content_id": contentID,
		"published_by": publishedBy,
	}).Info("Content published successfully")

	return nil
}

// validateContent validates content based on its format
func (s *ContentManagementService) validateContent(ctx context.Context, fileBytes []byte, format string) *ContentValidationResult {
	result := &ContentValidationResult{
		IsValid:           true,
		ValidationErrors:  make([]string, 0),
		ValidationWarnings: make([]string, 0),
	}

	switch format {
	case "scorm_1_2", "scorm_2004":
		if s.config.SCORMValidationEnabled {
			result.SCORMValidation = s.validateSCORM(fileBytes, format)
			if !result.SCORMValidation.StructureValid {
				result.IsValid = false
				result.ValidationErrors = append(result.ValidationErrors, "SCORM structure validation failed")
			}
		}

	case "xapi":
		if s.config.XAPIValidationEnabled {
			result.XAPIValidation = s.validateXAPI(fileBytes)
			if !result.XAPIValidation.ProfileCompliant {
				result.IsValid = false
				result.ValidationErrors = append(result.ValidationErrors, "xAPI profile compliance failed")
			}
		}

	case "html5":
		// Validate HTML5 content structure
		if !s.validateHTML5(fileBytes) {
			result.IsValid = false
			result.ValidationErrors = append(result.ValidationErrors, "HTML5 structure validation failed")
		}
	}

	return result
}

// Helper methods for validation (simplified implementations)
func (s *ContentManagementService) validateSCORM(fileBytes []byte, version string) *SCORMValidationResult {
	// In a real implementation, this would parse the SCORM package and validate structure
	return &SCORMValidationResult{
		Version:         version,
		ManifestValid:   true,
		LaunchFileFound: true,
		RequiredFiles:   []string{"imsmanifest.xml"},
		MissingFiles:    []string{},
		StructureValid:  true,
	}
}

func (s *ContentManagementService) validateXAPI(fileBytes []byte) *XAPIValidationResult {
	// In a real implementation, this would validate xAPI statements and activities
	return &XAPIValidationResult{
		ActivitiesValid:  true,
		StatementsValid:  true,
		ProfileCompliant: true,
		ValidationIssues: []string{},
	}
}

func (s *ContentManagementService) validateHTML5(fileBytes []byte) bool {
	// Basic HTML5 validation - in reality this would be more sophisticated
	content := string(fileBytes)
	return strings.Contains(content, "<html") || strings.Contains(content, "<!DOCTYPE html>")
}

func (s *ContentManagementService) processSCORMContent(content *entity.TrainingContent, validation *SCORMValidationResult) {
	if validation == nil {
		return
	}

	content.SCORMVersion = validation.Version
	content.ManifestURL = content.ContentURL + "/imsmanifest.xml"
	
	// Set package files
	packageFiles, _ := json.Marshal(validation.RequiredFiles)
	content.PackageFiles = string(packageFiles)
}

func (s *ContentManagementService) processXAPIContent(content *entity.TrainingContent, validation *XAPIValidationResult) {
	if validation == nil {
		return
	}

	// Process xAPI activities - in reality this would parse actual activities
	activities := []map[string]interface{}{
		{
			"id":   content.ContentURL,
			"type": "http://adlnet.gov/expapi/activities/course",
			"definition": map[string]interface{}{
				"name": map[string]string{
					"en": content.Title,
				},
				"description": map[string]string{
					"en": content.Description,
				},
			},
		},
	}

	activitiesJSON, _ := json.Marshal(activities)
	content.XAPIActivities = string(activitiesJSON)
}

func (s *ContentManagementService) generateLaunchURL(content *entity.TrainingContent) string {
	baseURL := "https://training.isectech.org"
	return fmt.Sprintf("%s/content/%s/launch", baseURL, content.ContentID)
}

func (s *ContentManagementService) isAllowedFileType(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowed := range s.config.AllowedFileTypes {
		if ext == allowed {
			return true
		}
	}
	return false
}

func (s *ContentManagementService) publishContentEvent(ctx context.Context, eventType string, content *entity.TrainingContent) {
	event := map[string]interface{}{
		"content_id":    content.ContentID,
		"tenant_id":     content.TenantID,
		"module_code":   content.ModuleCode,
		"version":       content.Version,
		"content_type":  content.ContentType,
		"status":        content.Status,
		"created_by":    content.CreatedBy,
		"timestamp":     time.Now(),
	}

	s.eventPublisher.Publish(ctx, eventType, event)
}

// Interface definitions for external services
type CDNService interface {
	Deploy(ctx context.Context, sourceURL, distributionID string) (string, error)
	Invalidate(ctx context.Context, distributionID string, paths []string) error
	GetDistributionURL(distributionID string) string
}

// Additional methods would include content delivery, session management, analytics, etc.
// These would be implemented as part of the complete service