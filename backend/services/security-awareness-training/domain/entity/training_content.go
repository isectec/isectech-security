// iSECTECH Security Awareness Training Service - Training Content Entity
// Production-grade content management with multi-format support and SCORM compliance
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package entity

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TrainingContent represents a training module with all its associated content
type TrainingContent struct {
	// Primary identifiers
	ContentID uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"content_id"`
	TenantID  uuid.UUID `gorm:"not null;index:idx_training_content_tenant" json:"tenant_id"`

	// Content identification
	ModuleName        string `gorm:"not null;size:255" json:"module_name"`
	ModuleCode        string `gorm:"not null;size:100;index:idx_training_content_code" json:"module_code"`
	Version           string `gorm:"not null;size:50" json:"version"`
	Title             string `gorm:"not null;size:500" json:"title"`
	Description       string `gorm:"type:text" json:"description"`
	LearningObjectives pq.StringArray `gorm:"type:text[]" json:"learning_objectives"`

	// Content classification
	ContentType       string `gorm:"not null;size:100" json:"content_type" validate:"required,oneof=awareness_training phishing_simulation assessment compliance_training incident_response security_policy"`
	ContentCategory   string `gorm:"not null;size:100" json:"content_category" validate:"required,oneof=mandatory optional remedial refresher certification"`
	DifficultyLevel   string `gorm:"not null;size:50" json:"difficulty_level" validate:"required,oneof=beginner intermediate advanced expert"`
	ContentFormat     string `gorm:"not null;size:50" json:"content_format" validate:"required,oneof=scorm_1_2 scorm_2004 xapi html5 video interactive_simulation pdf document"`

	// Security and access control
	SecurityClearanceRequired string         `gorm:"size:50" json:"security_clearance_required" validate:"omitempty,oneof=unclassified confidential secret top_secret"`
	AccessRestrictions        pq.StringArray `gorm:"type:text[]" json:"access_restrictions"`
	DataClassification        string         `gorm:"not null;size:50" json:"data_classification" validate:"required,oneof=public internal restricted confidential"`
	ExportRestrictions        string         `gorm:"type:jsonb;default:'{}'" json:"export_restrictions"`

	// Content details and structure
	EstimatedDuration    int     `gorm:"not null" json:"estimated_duration_minutes"`
	ActualDuration       *int    `json:"actual_duration_minutes"`
	ContentSize         int64    `gorm:"not null" json:"content_size_bytes"`
	HasAssessment       bool     `gorm:"not null;default:false" json:"has_assessment"`
	AssessmentType      string   `gorm:"size:50" json:"assessment_type" validate:"omitempty,oneof=quiz interactive_scenario multiple_choice true_false essay simulation"`
	PassingScore        float64  `gorm:"default:80" json:"passing_score"`
	MaxAttempts         int      `gorm:"not null;default:3" json:"max_attempts"`
	RequiresProctor     bool     `gorm:"not null;default:false" json:"requires_proctor"`

	// Content storage and delivery
	ContentURL          string         `gorm:"size:1000" json:"content_url"`
	CDNDistribution     string         `gorm:"size:500" json:"cdn_distribution"`
	ManifestURL         string         `gorm:"size:1000" json:"manifest_url"`
	LaunchURL           string         `gorm:"size:1000" json:"launch_url"`
	ContentPath         string         `gorm:"size:500" json:"content_path"`
	AssetPaths          pq.StringArray `gorm:"type:text[]" json:"asset_paths"`
	PackageFiles        string         `gorm:"type:jsonb;default:'[]'" json:"package_files"`
	ChecksumMD5         string         `gorm:"size:32" json:"checksum_md5"`
	ChecksumSHA256      string         `gorm:"size:64" json:"checksum_sha256"`

	// SCORM and xAPI compliance
	SCORMVersion        string `gorm:"size:50" json:"scorm_version"`
	SCORMManifest       string `gorm:"type:text" json:"scorm_manifest"`
	XAPIActivities      string `gorm:"type:jsonb;default:'[]'" json:"xapi_activities"`
	ComplianceStandards pq.StringArray `gorm:"type:text[]" json:"compliance_standards"`
	TrackingEnabled     bool   `gorm:"not null;default:true" json:"tracking_enabled"`

	// Multi-language support
	DefaultLanguage     string         `gorm:"not null;size:10;default:en" json:"default_language"`
	AvailableLanguages  pq.StringArray `gorm:"type:text[]" json:"available_languages"`
	LocalizedContent    string         `gorm:"type:jsonb;default:'{}'" json:"localized_content"`
	TranslationStatus   string         `gorm:"type:jsonb;default:'{}'" json:"translation_status"`

	// Personalization and adaptive learning
	PersonalizationRules string `gorm:"type:jsonb;default:'[]'" json:"personalization_rules"`
	AdaptiveBranching    bool   `gorm:"not null;default:false" json:"adaptive_branching"`
	PrerequisiteModules  pq.StringArray `gorm:"type:text[]" json:"prerequisite_modules"`
	SkillTags           pq.StringArray `gorm:"type:text[]" json:"skill_tags"`
	CompetencyMappings   string `gorm:"type:jsonb;default:'{}'" json:"competency_mappings"`

	// Compliance and regulatory alignment
	ComplianceFrameworks  pq.StringArray `gorm:"type:text[]" json:"compliance_frameworks"`
	RegulatoryRequirements string        `gorm:"type:jsonb;default:'{}'" json:"regulatory_requirements"`
	CertificationMappings  string        `gorm:"type:jsonb;default:'{}'" json:"certification_mappings"`
	IndustryStandards     pq.StringArray `gorm:"type:text[]" json:"industry_standards"`
	AuditTrail            string         `gorm:"type:jsonb;default:'[]'" json:"audit_trail"`

	// Content lifecycle management
	Status              string    `gorm:"not null;default:draft" json:"status" validate:"required,oneof=draft review approved published deprecated archived"`
	PublishedAt         *time.Time `json:"published_at"`
	DeprecationDate     *time.Time `json:"deprecation_date"`
	ExpiryDate          *time.Time `json:"expiry_date"`
	ReviewDue           *time.Time `json:"review_due"`
	LastReviewedAt      *time.Time `json:"last_reviewed_at"`
	NextReviewDate      *time.Time `json:"next_review_date"`

	// Authorship and ownership
	CreatedBy           uuid.UUID  `gorm:"not null" json:"created_by"`
	AuthorName          string     `gorm:"size:255" json:"author_name"`
	AuthorEmail         string     `gorm:"size:255" json:"author_email"`
	ReviewedBy          uuid.UUID  `json:"reviewed_by"`
	ApprovedBy          uuid.UUID  `json:"approved_by"`
	ContentProvider     string     `gorm:"size:255" json:"content_provider"`
	LicenseInformation  string     `gorm:"type:text" json:"license_information"`
	CopyrightNotice     string     `gorm:"type:text" json:"copyright_notice"`

	// Performance and analytics
	UsageStatistics     string `gorm:"type:jsonb;default:'{}'" json:"usage_statistics"`
	PerformanceMetrics  string `gorm:"type:jsonb;default:'{}'" json:"performance_metrics"`
	FeedbackSummary     string `gorm:"type:jsonb;default:'{}'" json:"feedback_summary"`
	EffectivenessScore  float64 `gorm:"check:effectiveness_score BETWEEN 0 AND 100" json:"effectiveness_score"`
	EngagementScore     float64 `gorm:"check:engagement_score BETWEEN 0 AND 100" json:"engagement_score"`

	// External system integration
	LMSIntegration      string `gorm:"type:jsonb;default:'{}'" json:"lms_integration"`
	ExternalContentID   string `gorm:"size:255" json:"external_content_id"`
	ProviderMetadata    string `gorm:"type:jsonb;default:'{}'" json:"provider_metadata"`
	SyncStatus          string `gorm:"size:50;default:synced" json:"sync_status" validate:"omitempty,oneof=synced pending failed"`
	LastSyncedAt        *time.Time `json:"last_synced_at"`

	// Caching and optimization
	CacheConfiguration  string `gorm:"type:jsonb;default:'{}'" json:"cache_configuration"`
	CompressionEnabled  bool   `gorm:"not null;default:true" json:"compression_enabled"`
	StreamingEnabled    bool   `gorm:"not null;default:false" json:"streaming_enabled"`
	OfflineCapable      bool   `gorm:"not null;default:false" json:"offline_capable"`
	MobileOptimized     bool   `gorm:"not null;default:true" json:"mobile_optimized"`

	// Metadata and search
	Keywords            pq.StringArray `gorm:"type:text[]" json:"keywords"`
	SearchTags          pq.StringArray `gorm:"type:text[]" json:"search_tags"`
	CustomMetadata      string         `gorm:"type:jsonb;default:'{}'" json:"custom_metadata"`
	IndexingData        string         `gorm:"type:jsonb;default:'{}'" json:"indexing_data"`

	// Audit and lifecycle tracking
	CreatedAt           time.Time  `gorm:"default:now()" json:"created_at"`
	UpdatedAt           time.Time  `gorm:"default:now()" json:"updated_at"`
	VersionHistory      string     `gorm:"type:jsonb;default:'[]'" json:"version_history"`
	ChangeLog           string     `gorm:"type:jsonb;default:'[]'" json:"change_log"`
	IsActive            bool       `gorm:"default:true" json:"is_active"`
	DeactivatedAt       *time.Time `json:"deactivated_at"`
	ArchiveDate         *time.Time `json:"archive_date"`
	RetentionDate       *time.Time `json:"retention_date"`
}

// ContentStatus represents the status of training content
type ContentStatus string

const (
	ContentStatusDraft      ContentStatus = "draft"
	ContentStatusReview     ContentStatus = "review"
	ContentStatusApproved   ContentStatus = "approved"
	ContentStatusPublished  ContentStatus = "published"
	ContentStatusDeprecated ContentStatus = "deprecated"
	ContentStatusArchived   ContentStatus = "archived"
)

// ContentFormat represents supported content formats
type ContentFormat string

const (
	ContentFormatSCORM12      ContentFormat = "scorm_1_2"
	ContentFormatSCORM2004    ContentFormat = "scorm_2004"
	ContentFormatXAPI         ContentFormat = "xapi"
	ContentFormatHTML5        ContentFormat = "html5"
	ContentFormatVideo        ContentFormat = "video"
	ContentFormatSimulation   ContentFormat = "interactive_simulation"
	ContentFormatPDF          ContentFormat = "pdf"
	ContentFormatDocument     ContentFormat = "document"
)

// IsPublished checks if the content is published and available
func (tc *TrainingContent) IsPublished() bool {
	return tc.Status == string(ContentStatusPublished) && tc.IsActive
}

// IsExpired checks if the content has expired
func (tc *TrainingContent) IsExpired() bool {
	return tc.ExpiryDate != nil && time.Now().After(*tc.ExpiryDate)
}

// IsDeprecated checks if the content is deprecated
func (tc *TrainingContent) IsDeprecated() bool {
	return tc.Status == string(ContentStatusDeprecated) || 
		   (tc.DeprecationDate != nil && time.Now().After(*tc.DeprecationDate))
}

// RequiresReview checks if the content requires review
func (tc *TrainingContent) RequiresReview() bool {
	return tc.ReviewDue != nil && time.Now().After(*tc.ReviewDue)
}

// CanAccessContent checks if user with given clearance can access content
func (tc *TrainingContent) CanAccessContent(userClearance string) bool {
	if tc.SecurityClearanceRequired == "" {
		return true
	}

	clearanceLevels := map[string]int{
		"unclassified": 1,
		"confidential": 2,
		"secret":       3,
		"top_secret":   4,
	}

	userLevel := clearanceLevels[strings.ToLower(userClearance)]
	requiredLevel := clearanceLevels[strings.ToLower(tc.SecurityClearanceRequired)]

	return userLevel >= requiredLevel
}

// GetLaunchParameters returns launch parameters for content delivery
func (tc *TrainingContent) GetLaunchParameters(userID uuid.UUID, sessionID string) map[string]interface{} {
	params := map[string]interface{}{
		"content_id":     tc.ContentID,
		"module_name":    tc.ModuleName,
		"version":        tc.Version,
		"launch_url":     tc.LaunchURL,
		"user_id":        userID,
		"session_id":     sessionID,
		"duration":       tc.EstimatedDuration,
		"has_assessment": tc.HasAssessment,
		"passing_score":  tc.PassingScore,
		"max_attempts":   tc.MaxAttempts,
		"format":         tc.ContentFormat,
		"tracking":       tc.TrackingEnabled,
	}

	// Add SCORM-specific parameters
	if tc.ContentFormat == string(ContentFormatSCORM12) || tc.ContentFormat == string(ContentFormatSCORM2004) {
		params["scorm_version"] = tc.SCORMVersion
		params["manifest_url"] = tc.ManifestURL
	}

	// Add xAPI parameters
	if tc.ContentFormat == string(ContentFormatXAPI) {
		var xapiActivities []map[string]interface{}
		json.Unmarshal([]byte(tc.XAPIActivities), &xapiActivities)
		params["xapi_activities"] = xapiActivities
	}

	return params
}

// GetLocalizedContent returns localized content for given language
func (tc *TrainingContent) GetLocalizedContent(language string) map[string]interface{} {
	var localizedContent map[string]interface{}
	json.Unmarshal([]byte(tc.LocalizedContent), &localizedContent)

	if contentForLang, exists := localizedContent[language]; exists {
		if langContent, ok := contentForLang.(map[string]interface{}); ok {
			return langContent
		}
	}

	// Fallback to default language
	if contentForLang, exists := localizedContent[tc.DefaultLanguage]; exists {
		if langContent, ok := contentForLang.(map[string]interface{}); ok {
			return langContent
		}
	}

	return make(map[string]interface{})
}

// AddVersionHistory adds an entry to version history
func (tc *TrainingContent) AddVersionHistory(previousVersion string, changeReason string, changedBy uuid.UUID) {
	var versionHistory []map[string]interface{}
	json.Unmarshal([]byte(tc.VersionHistory), &versionHistory)

	entry := map[string]interface{}{
		"previous_version": previousVersion,
		"new_version":     tc.Version,
		"change_reason":   changeReason,
		"changed_by":      changedBy,
		"timestamp":       time.Now(),
	}

	versionHistory = append(versionHistory, entry)
	
	// Keep only last 20 versions
	if len(versionHistory) > 20 {
		versionHistory = versionHistory[len(versionHistory)-20:]
	}

	historyData, _ := json.Marshal(versionHistory)
	tc.VersionHistory = string(historyData)
	tc.UpdatedAt = time.Now()
}

// AddAuditEntry adds an entry to the audit trail
func (tc *TrainingContent) AddAuditEntry(action string, performedBy uuid.UUID, details map[string]interface{}) {
	var auditTrail []map[string]interface{}
	json.Unmarshal([]byte(tc.AuditTrail), &auditTrail)

	entry := map[string]interface{}{
		"action":       action,
		"performed_by": performedBy,
		"timestamp":    time.Now(),
		"details":      details,
	}

	auditTrail = append(auditTrail, entry)
	
	// Keep only last 100 audit entries
	if len(auditTrail) > 100 {
		auditTrail = auditTrail[len(auditTrail)-100:]
	}

	auditData, _ := json.Marshal(auditTrail)
	tc.AuditTrail = string(auditData)
	tc.UpdatedAt = time.Now()
}

// ValidateForPublication checks if content is ready for publication
func (tc *TrainingContent) ValidateForPublication() []string {
	issues := make([]string, 0)

	if tc.Title == "" {
		issues = append(issues, "Title is required")
	}

	if tc.Description == "" {
		issues = append(issues, "Description is required")
	}

	if tc.ContentURL == "" && tc.LaunchURL == "" {
		issues = append(issues, "Content URL or Launch URL is required")
	}

	if tc.EstimatedDuration <= 0 {
		issues = append(issues, "Estimated duration must be greater than 0")
	}

	if tc.HasAssessment && tc.PassingScore <= 0 {
		issues = append(issues, "Passing score required for assessed content")
	}

	if tc.ChecksumMD5 == "" || tc.ChecksumSHA256 == "" {
		issues = append(issues, "Content integrity checksums are required")
	}

	if tc.ContentFormat == string(ContentFormatSCORM12) || tc.ContentFormat == string(ContentFormatSCORM2004) {
		if tc.SCORMManifest == "" {
			issues = append(issues, "SCORM manifest is required for SCORM content")
		}
	}

	return issues
}

// UpdateUsageStatistics updates usage statistics
func (tc *TrainingContent) UpdateUsageStatistics(metric string, value float64) error {
	var stats map[string]interface{}
	if tc.UsageStatistics != "" {
		json.Unmarshal([]byte(tc.UsageStatistics), &stats)
	}
	if stats == nil {
		stats = make(map[string]interface{})
	}

	stats[metric] = value
	stats["last_updated"] = time.Now()

	statsData, err := json.Marshal(stats)
	if err != nil {
		return err
	}

	tc.UsageStatistics = string(statsData)
	tc.UpdatedAt = time.Now()
	return nil
}

// GetPackageFiles returns the list of package files
func (tc *TrainingContent) GetPackageFiles() []string {
	var files []string
	json.Unmarshal([]byte(tc.PackageFiles), &files)
	return files
}

// TableName sets the table name for GORM
func (TrainingContent) TableName() string {
	return "training_contents"
}