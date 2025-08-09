// iSECTECH Security Awareness Training Service - Training Content Repository
// Production-grade data access layer for training content management
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
)

// TrainingContentRepository defines the interface for training content data access
type TrainingContentRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, content *entity.TrainingContent) error
	GetByID(ctx context.Context, contentID uuid.UUID) (*entity.TrainingContent, error)
	GetByModuleCode(ctx context.Context, tenantID uuid.UUID, moduleCode string) (*entity.TrainingContent, error)
	Update(ctx context.Context, content *entity.TrainingContent) error
	Delete(ctx context.Context, contentID uuid.UUID) error

	// Multi-tenant operations
	GetByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*entity.TrainingContent, error)
	CountByTenantID(ctx context.Context, tenantID uuid.UUID) (int64, error)

	// Content discovery and filtering
	GetPublishedContent(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)
	GetByContentType(ctx context.Context, tenantID uuid.UUID, contentType string) ([]*entity.TrainingContent, error)
	GetByContentCategory(ctx context.Context, tenantID uuid.UUID, category string) ([]*entity.TrainingContent, error)
	GetByDifficultyLevel(ctx context.Context, tenantID uuid.UUID, level string) ([]*entity.TrainingContent, error)
	GetByContentFormat(ctx context.Context, tenantID uuid.UUID, format string) ([]*entity.TrainingContent, error)

	// Security and access control queries
	GetBySecurityClearance(ctx context.Context, tenantID uuid.UUID, clearance string) ([]*entity.TrainingContent, error)
	GetAccessibleContent(ctx context.Context, tenantID uuid.UUID, userClearance string) ([]*entity.TrainingContent, error)
	GetByDataClassification(ctx context.Context, tenantID uuid.UUID, classification string) ([]*entity.TrainingContent, error)

	// Content lifecycle management
	GetByStatus(ctx context.Context, tenantID uuid.UUID, status string) ([]*entity.TrainingContent, error)
	GetContentRequiringReview(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)
	GetExpiringContent(ctx context.Context, tenantID uuid.UUID, days int) ([]*entity.TrainingContent, error)
	GetDeprecatedContent(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)
	GetExpiredContent(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)

	// Compliance and regulatory queries
	GetByComplianceFramework(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.TrainingContent, error)
	GetByIndustryStandard(ctx context.Context, tenantID uuid.UUID, standard string) ([]*entity.TrainingContent, error)
	GetComplianceRequiredContent(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)

	// Content versioning and history
	GetVersionHistory(ctx context.Context, moduleCode string, tenantID uuid.UUID) ([]*entity.TrainingContent, error)
	GetLatestVersion(ctx context.Context, moduleCode string, tenantID uuid.UUID) (*entity.TrainingContent, error)
	GetSpecificVersion(ctx context.Context, moduleCode, version string, tenantID uuid.UUID) (*entity.TrainingContent, error)

	// Search and discovery
	SearchContent(ctx context.Context, tenantID uuid.UUID, query *ContentSearchQuery) ([]*entity.TrainingContent, error)
	GetByKeywords(ctx context.Context, tenantID uuid.UUID, keywords []string) ([]*entity.TrainingContent, error)
	GetBySkillTags(ctx context.Context, tenantID uuid.UUID, tags []string) ([]*entity.TrainingContent, error)
	GetRecommendedContent(ctx context.Context, tenantID, userID uuid.UUID, limit int) ([]*entity.TrainingContent, error)

	// Content relationships and dependencies
	GetPrerequisiteContent(ctx context.Context, contentID uuid.UUID) ([]*entity.TrainingContent, error)
	GetDependentContent(ctx context.Context, contentID uuid.UUID) ([]*entity.TrainingContent, error)
	GetRelatedContent(ctx context.Context, contentID uuid.UUID, limit int) ([]*entity.TrainingContent, error)

	// Performance and analytics queries
	GetMostPopularContent(ctx context.Context, tenantID uuid.UUID, limit int) ([]*entity.TrainingContent, error)
	GetHighPerformingContent(ctx context.Context, tenantID uuid.UUID, minScore float64) ([]*entity.TrainingContent, error)
	GetLowPerformingContent(ctx context.Context, tenantID uuid.UUID, maxScore float64) ([]*entity.TrainingContent, error)
	GetContentByEffectiveness(ctx context.Context, tenantID uuid.UUID, minEffectiveness float64) ([]*entity.TrainingContent, error)

	// Multi-language support
	GetByLanguage(ctx context.Context, tenantID uuid.UUID, language string) ([]*entity.TrainingContent, error)
	GetMultiLanguageContent(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)
	GetTranslationRequests(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)

	// External system integration
	GetBySyncStatus(ctx context.Context, tenantID uuid.UUID, syncStatus string) ([]*entity.TrainingContent, error)
	GetByExternalContentID(ctx context.Context, tenantID uuid.UUID, externalID string) (*entity.TrainingContent, error)
	GetContentForSync(ctx context.Context, tenantID uuid.UUID, lastSync time.Time) ([]*entity.TrainingContent, error)

	// Batch operations
	CreateBatch(ctx context.Context, contents []*entity.TrainingContent) error
	UpdateBatch(ctx context.Context, contents []*entity.TrainingContent) error
	UpdateStatusBatch(ctx context.Context, contentIDs []uuid.UUID, status string) error
	BulkUpdateMetadata(ctx context.Context, updates []ContentMetadataUpdate) error

	// Analytics and reporting
	GetContentStatistics(ctx context.Context, tenantID uuid.UUID) (*ContentStatistics, error)
	GetUsageAnalytics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*ContentUsageAnalytics, error)
	GetPerformanceMetrics(ctx context.Context, tenantID uuid.UUID, contentIDs []uuid.UUID) ([]*ContentPerformanceMetric, error)
	GetComplianceReport(ctx context.Context, tenantID uuid.UUID) (*ContentComplianceReport, error)

	// Content validation and integrity
	ValidateContentIntegrity(ctx context.Context, contentID uuid.UUID) (*ContentIntegrityResult, error)
	GetOrphanedContent(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingContent, error)
	GetMissingAssets(ctx context.Context, tenantID uuid.UUID) ([]*ContentAssetIssue, error)

	// Lifecycle and archival operations
	ArchiveContent(ctx context.Context, contentIDs []uuid.UUID) error
	PurgeArchivedContent(ctx context.Context, tenantID uuid.UUID, archiveThreshold time.Time) (int64, error)
	GetContentForRetention(ctx context.Context, tenantID uuid.UUID, retentionDate time.Time) ([]*entity.TrainingContent, error)
}

// ContentSearchQuery represents search criteria for content discovery
type ContentSearchQuery struct {
	Query               string               `json:"query"`
	ContentTypes        []string             `json:"content_types,omitempty"`
	Categories          []string             `json:"categories,omitempty"`
	DifficultyLevels    []string             `json:"difficulty_levels,omitempty"`
	SecurityClearances  []string             `json:"security_clearances,omitempty"`
	ComplianceFrameworks []string            `json:"compliance_frameworks,omitempty"`
	Keywords            []string             `json:"keywords,omitempty"`
	SkillTags           []string             `json:"skill_tags,omitempty"`
	Languages           []string             `json:"languages,omitempty"`
	MinDuration         *int                 `json:"min_duration,omitempty"`
	MaxDuration         *int                 `json:"max_duration,omitempty"`
	HasAssessment       *bool                `json:"has_assessment,omitempty"`
	CreatedAfter        *time.Time           `json:"created_after,omitempty"`
	CreatedBefore       *time.Time           `json:"created_before,omitempty"`
	UpdatedAfter        *time.Time           `json:"updated_after,omitempty"`
	Status              []string             `json:"status,omitempty"`
	SortBy              string               `json:"sort_by,omitempty"`
	SortOrder           string               `json:"sort_order,omitempty"`
	Limit               int                  `json:"limit"`
	Offset              int                  `json:"offset"`
}

// ContentMetadataUpdate represents a metadata update operation
type ContentMetadataUpdate struct {
	ContentID  uuid.UUID              `json:"content_id"`
	Updates    map[string]interface{} `json:"updates"`
	UpdatedBy  uuid.UUID              `json:"updated_by"`
}

// TimeRange represents a time range for analytics queries
type TimeRange struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// ContentStatistics represents overall content statistics
type ContentStatistics struct {
	TenantID              uuid.UUID              `json:"tenant_id"`
	TotalContent          int64                  `json:"total_content"`
	PublishedContent      int64                  `json:"published_content"`
	DraftContent          int64                  `json:"draft_content"`
	ExpiredContent        int64                  `json:"expired_content"`
	ContentByType         map[string]int64       `json:"content_by_type"`
	ContentByCategory     map[string]int64       `json:"content_by_category"`
	ContentByDifficulty   map[string]int64       `json:"content_by_difficulty"`
	ContentByFormat       map[string]int64       `json:"content_by_format"`
	ContentByClearance    map[string]int64       `json:"content_by_clearance"`
	ContentByLanguage     map[string]int64       `json:"content_by_language"`
	AverageEffectiveness  float64                `json:"average_effectiveness"`
	AverageEngagement     float64                `json:"average_engagement"`
	TotalContentSize      int64                  `json:"total_content_size_bytes"`
	LastUpdated           time.Time              `json:"last_updated"`
}

// ContentUsageAnalytics represents content usage analytics
type ContentUsageAnalytics struct {
	TenantID            uuid.UUID                      `json:"tenant_id"`
	TimeRange           TimeRange                      `json:"time_range"`
	TotalSessions       int64                          `json:"total_sessions"`
	UniqueLearners      int64                          `json:"unique_learners"`
	CompletionRate      float64                        `json:"completion_rate"`
	AverageEngagement   float64                        `json:"average_engagement"`
	TopContent          []*ContentUsageMetric          `json:"top_content"`
	UsageByType         map[string]*ContentUsageMetric `json:"usage_by_type"`
	UsageByCategory     map[string]*ContentUsageMetric `json:"usage_by_category"`
	UsageTrends         []*UsageTrendPoint             `json:"usage_trends"`
}

// ContentUsageMetric represents usage metrics for specific content
type ContentUsageMetric struct {
	ContentID         uuid.UUID `json:"content_id"`
	ModuleName        string    `json:"module_name"`
	LaunchCount       int64     `json:"launch_count"`
	CompletionCount   int64     `json:"completion_count"`
	CompletionRate    float64   `json:"completion_rate"`
	AverageScore      float64   `json:"average_score"`
	AverageTimeSpent  float64   `json:"average_time_spent"`
	EngagementScore   float64   `json:"engagement_score"`
	UniqueLearners    int64     `json:"unique_learners"`
	LastAccessed      time.Time `json:"last_accessed"`
}

// UsageTrendPoint represents a point in usage trend analysis
type UsageTrendPoint struct {
	Date            time.Time `json:"date"`
	SessionCount    int64     `json:"session_count"`
	CompletionCount int64     `json:"completion_count"`
	UniqueLearners  int64     `json:"unique_learners"`
}

// ContentPerformanceMetric represents performance metrics for specific content
type ContentPerformanceMetric struct {
	ContentID           uuid.UUID `json:"content_id"`
	ModuleName          string    `json:"module_name"`
	EffectivenessScore  float64   `json:"effectiveness_score"`
	EngagementScore     float64   `json:"engagement_score"`
	CompletionRate      float64   `json:"completion_rate"`
	AverageScore        float64   `json:"average_score"`
	PassRate            float64   `json:"pass_rate"`
	RetryRate           float64   `json:"retry_rate"`
	AverageTimeToComplete float64 `json:"average_time_to_complete"`
	UserSatisfaction    float64   `json:"user_satisfaction"`
	TechnicalIssueRate  float64   `json:"technical_issue_rate"`
}

// ContentComplianceReport represents a compliance report for content
type ContentComplianceReport struct {
	TenantID                   uuid.UUID                               `json:"tenant_id"`
	GeneratedAt                time.Time                               `json:"generated_at"`
	FrameworkCompliance        map[string]*ComplianceFrameworkStatus   `json:"framework_compliance"`
	SecurityClearanceCompliance map[string]*SecurityClearanceStatus    `json:"security_clearance_compliance"`
	ExpiringContent            []*ExpiringContentItem                  `json:"expiring_content"`
	ReviewRequiredContent      []*ReviewRequiredContentItem            `json:"review_required_content"`
	NonCompliantContent        []*NonCompliantContentItem              `json:"non_compliant_content"`
	OverallComplianceScore     float64                                 `json:"overall_compliance_score"`
}

// ComplianceFrameworkStatus represents compliance status for a framework
type ComplianceFrameworkStatus struct {
	Framework          string  `json:"framework"`
	TotalContent       int64   `json:"total_content"`
	CompliantContent   int64   `json:"compliant_content"`
	ComplianceRate     float64 `json:"compliance_rate"`
	ExpiringContent    int64   `json:"expiring_content"`
	NonCompliantContent int64  `json:"non_compliant_content"`
}

// SecurityClearanceStatus represents content status by security clearance
type SecurityClearanceStatus struct {
	ClearanceLevel   string  `json:"clearance_level"`
	TotalContent     int64   `json:"total_content"`
	PublishedContent int64   `json:"published_content"`
	ExpiredContent   int64   `json:"expired_content"`
	AvailabilityRate float64 `json:"availability_rate"`
}

// ExpiringContentItem represents content that is expiring soon
type ExpiringContentItem struct {
	ContentID    uuid.UUID `json:"content_id"`
	ModuleName   string    `json:"module_name"`
	ExpiryDate   time.Time `json:"expiry_date"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	ImpactedUsers   int64  `json:"impacted_users"`
}

// ReviewRequiredContentItem represents content requiring review
type ReviewRequiredContentItem struct {
	ContentID      uuid.UUID `json:"content_id"`
	ModuleName     string    `json:"module_name"`
	ReviewDue      time.Time `json:"review_due"`
	DaysOverdue    int       `json:"days_overdue"`
	LastReviewedAt *time.Time `json:"last_reviewed_at"`
}

// NonCompliantContentItem represents non-compliant content
type NonCompliantContentItem struct {
	ContentID         uuid.UUID `json:"content_id"`
	ModuleName        string    `json:"module_name"`
	ComplianceIssues  []string  `json:"compliance_issues"`
	Severity          string    `json:"severity"`
	RequiredActions   []string  `json:"required_actions"`
}

// ContentIntegrityResult represents content integrity check result
type ContentIntegrityResult struct {
	ContentID       uuid.UUID `json:"content_id"`
	IsValid         bool      `json:"is_valid"`
	ChecksumMatches bool      `json:"checksum_matches"`
	FilesPresent    bool      `json:"files_present"`
	ManifestValid   bool      `json:"manifest_valid"`
	Issues          []string  `json:"issues"`
	CheckedAt       time.Time `json:"checked_at"`
}

// ContentAssetIssue represents a content asset issue
type ContentAssetIssue struct {
	ContentID   uuid.UUID `json:"content_id"`
	ModuleName  string    `json:"module_name"`
	AssetPath   string    `json:"asset_path"`
	IssueType   string    `json:"issue_type"`
	Description string    `json:"description"`
}