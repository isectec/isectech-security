// iSECTECH Security Awareness Training Service - Content Delivery Repository
// Production-grade data access layer for content delivery session management
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
)

// ContentDeliveryRepository defines the interface for content delivery session data access
type ContentDeliveryRepository interface {
	// Session CRUD operations
	CreateSession(ctx context.Context, session *entity.ContentDeliverySession) error
	GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*entity.ContentDeliverySession, error)
	GetSessionByToken(ctx context.Context, sessionToken string) (*entity.ContentDeliverySession, error)
	UpdateSession(ctx context.Context, session *entity.ContentDeliverySession) error
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error

	// Multi-tenant operations
	GetSessionsByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*entity.ContentDeliverySession, error)
	CountSessionsByTenantID(ctx context.Context, tenantID uuid.UUID) (int64, error)

	// User session queries
	GetUserSessions(ctx context.Context, tenantID, userID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetActiveUserSessions(ctx context.Context, tenantID, userID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetUserSessionHistory(ctx context.Context, tenantID, userID uuid.UUID, limit int) ([]*entity.ContentDeliverySession, error)

	// Content-specific queries
	GetContentSessions(ctx context.Context, contentID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetActiveContentSessions(ctx context.Context, contentID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetContentSessionsByDateRange(ctx context.Context, contentID uuid.UUID, startDate, endDate time.Time) ([]*entity.ContentDeliverySession, error)

	// Assignment-related queries
	GetSessionsByAssignmentID(ctx context.Context, assignmentID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetAssignmentProgress(ctx context.Context, assignmentID uuid.UUID) ([]*entity.ContentDeliverySession, error)

	// Status-based queries
	GetSessionsByStatus(ctx context.Context, tenantID uuid.UUID, status string) ([]*entity.ContentDeliverySession, error)
	GetActiveSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetCompletedSessions(ctx context.Context, tenantID uuid.UUID, limit int) ([]*entity.ContentDeliverySession, error)
	GetFailedSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetSuspendedSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetExpiredSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)

	// Time-based queries
	GetSessionsByTimeRange(ctx context.Context, tenantID uuid.UUID, startTime, endTime time.Time) ([]*entity.ContentDeliverySession, error)
	GetSessionsLaunchedToday(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetSessionsCompletedInPeriod(ctx context.Context, tenantID uuid.UUID, days int) ([]*entity.ContentDeliverySession, error)
	GetLongRunningSessions(ctx context.Context, tenantID uuid.UUID, minDurationHours int) ([]*entity.ContentDeliverySession, error)

	// Progress and performance queries
	GetHighProgressSessions(ctx context.Context, tenantID uuid.UUID, minProgress int) ([]*entity.ContentDeliverySession, error)
	GetLowProgressSessions(ctx context.Context, tenantID uuid.UUID, maxProgress int) ([]*entity.ContentDeliverySession, error)
	GetSessionsWithLowEngagement(ctx context.Context, tenantID uuid.UUID, maxEngagement float64) ([]*entity.ContentDeliverySession, error)
	GetSessionsExceedingTimeLimit(ctx context.Context, tenantID uuid.UUID, maxHours int) ([]*entity.ContentDeliverySession, error)

	// Assessment-related queries
	GetSessionsWithAssessments(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetFailedAssessmentSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetSessionsNeedingRetry(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetHighScoredSessions(ctx context.Context, tenantID uuid.UUID, minScore float64) ([]*entity.ContentDeliverySession, error)

	// Device and environment queries
	GetSessionsByDeviceType(ctx context.Context, tenantID uuid.UUID, deviceType string) ([]*entity.ContentDeliverySession, error)
	GetSessionsByBrowser(ctx context.Context, tenantID uuid.UUID, browserName string) ([]*entity.ContentDeliverySession, error)
	GetSessionsByLocation(ctx context.Context, tenantID uuid.UUID, country, region string) ([]*entity.ContentDeliverySession, error)
	GetMobileVsDesktopSessions(ctx context.Context, tenantID uuid.UUID) (*DeviceUsageStats, error)

	// SCORM and xAPI specific queries
	GetSCORMSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetXAPISessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	GetSessionsWithInteractionData(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)

	// External system integration
	GetSessionsBySyncStatus(ctx context.Context, tenantID uuid.UUID, syncStatus string) ([]*entity.ContentDeliverySession, error)
	GetSessionsForSync(ctx context.Context, tenantID uuid.UUID, lastSync time.Time) ([]*entity.ContentDeliverySession, error)
	GetLMSIntegratedSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)

	// Analytics and reporting operations
	GetSessionStatistics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*SessionStatistics, error)
	GetContentPopularityMetrics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) ([]*ContentPopularityMetric, error)
	GetUserEngagementMetrics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) ([]*UserEngagementMetric, error)
	GetPerformanceAnalytics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*PerformanceAnalytics, error)
	GetCompletionTrends(ctx context.Context, tenantID uuid.UUID, days int) ([]*CompletionTrendPoint, error)

	// Attempt-related operations
	CreateAttempt(ctx context.Context, attempt *entity.ContentDeliveryAttempt) error
	GetAttemptsBySessionID(ctx context.Context, sessionID uuid.UUID) ([]*entity.ContentDeliveryAttempt, error)
	GetLatestAttempt(ctx context.Context, sessionID uuid.UUID) (*entity.ContentDeliveryAttempt, error)
	UpdateAttempt(ctx context.Context, attempt *entity.ContentDeliveryAttempt) error

	// Batch operations
	CreateSessionsBatch(ctx context.Context, sessions []*entity.ContentDeliverySession) error
	UpdateSessionsBatch(ctx context.Context, sessions []*entity.ContentDeliverySession) error
	UpdateProgressBatch(ctx context.Context, updates []ProgressUpdate) error
	BulkUpdateSessionStatus(ctx context.Context, sessionIDs []uuid.UUID, status string) error

	// Maintenance and cleanup operations
	CleanupExpiredSessions(ctx context.Context, tenantID uuid.UUID) (int64, error)
	ArchiveCompletedSessions(ctx context.Context, tenantID uuid.UUID, archiveAfter time.Time) (int64, error)
	PurgeArchivedSessions(ctx context.Context, tenantID uuid.UUID, purgeAfter time.Time) (int64, error)
	GetSessionsForCleanup(ctx context.Context, tenantID uuid.UUID, cleanupAfter time.Time) ([]*entity.ContentDeliverySession, error)

	// Data integrity operations
	ValidateSessionIntegrity(ctx context.Context, sessionID uuid.UUID) (*SessionIntegrityResult, error)
	GetOrphanedSessions(ctx context.Context, tenantID uuid.UUID) ([]*entity.ContentDeliverySession, error)
	RepairSessionReferences(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// DeviceUsageStats represents device usage statistics
type DeviceUsageStats struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	TotalSessions int64     `json:"total_sessions"`
	DesktopSessions int64   `json:"desktop_sessions"`
	MobileSessions  int64   `json:"mobile_sessions"`
	TabletSessions  int64   `json:"tablet_sessions"`
	DesktopPercentage float64 `json:"desktop_percentage"`
	MobilePercentage  float64 `json:"mobile_percentage"`
	TabletPercentage  float64 `json:"tablet_percentage"`
}

// SessionStatistics represents overall session statistics
type SessionStatistics struct {
	TenantID              uuid.UUID             `json:"tenant_id"`
	TimeRange             TimeRange             `json:"time_range"`
	TotalSessions         int64                 `json:"total_sessions"`
	ActiveSessions        int64                 `json:"active_sessions"`
	CompletedSessions     int64                 `json:"completed_sessions"`
	FailedSessions        int64                 `json:"failed_sessions"`
	SuspendedSessions     int64                 `json:"suspended_sessions"`
	ExpiredSessions       int64                 `json:"expired_sessions"`
	CompletionRate        float64               `json:"completion_rate"`
	AverageTimeSpent      float64               `json:"average_time_spent_minutes"`
	AverageProgress       float64               `json:"average_progress"`
	AverageScore          float64               `json:"average_score"`
	UniqueLearners        int64                 `json:"unique_learners"`
	RetryRate             float64               `json:"retry_rate"`
	SessionsByStatus      map[string]int64      `json:"sessions_by_status"`
	SessionsByDevice      map[string]int64      `json:"sessions_by_device"`
	SessionsByContent     map[string]int64      `json:"sessions_by_content"`
	EngagementDistribution map[string]int64     `json:"engagement_distribution"`
}

// ContentPopularityMetric represents content popularity metrics
type ContentPopularityMetric struct {
	ContentID        uuid.UUID `json:"content_id"`
	ModuleName       string    `json:"module_name"`
	LaunchCount      int64     `json:"launch_count"`
	CompletionCount  int64     `json:"completion_count"`
	FailureCount     int64     `json:"failure_count"`
	CompletionRate   float64   `json:"completion_rate"`
	AverageTimeSpent float64   `json:"average_time_spent_minutes"`
	AverageScore     float64   `json:"average_score"`
	UniqueLearners   int64     `json:"unique_learners"`
	LastLaunched     time.Time `json:"last_launched"`
	Rank             int       `json:"rank"`
}

// UserEngagementMetric represents user engagement metrics
type UserEngagementMetric struct {
	UserID              uuid.UUID `json:"user_id"`
	TotalSessions       int64     `json:"total_sessions"`
	CompletedSessions   int64     `json:"completed_sessions"`
	TotalTimeSpent      float64   `json:"total_time_spent_minutes"`
	AverageEngagement   float64   `json:"average_engagement"`
	AverageProgress     float64   `json:"average_progress"`
	AverageScore        float64   `json:"average_score"`
	LastActivity        time.Time `json:"last_activity"`
	EngagementLevel     string    `json:"engagement_level"`
	CompletionStreak    int       `json:"completion_streak"`
}

// PerformanceAnalytics represents comprehensive performance analytics
type PerformanceAnalytics struct {
	TenantID                  uuid.UUID `json:"tenant_id"`
	TimeRange                 TimeRange `json:"time_range"`
	OverallCompletionRate     float64   `json:"overall_completion_rate"`
	AverageTimeToComplete     float64   `json:"average_time_to_complete_minutes"`
	MedianTimeToComplete      float64   `json:"median_time_to_complete_minutes"`
	PercentileTimeToComplete  map[string]float64 `json:"percentile_time_to_complete"`
	PassRateByContent         map[string]float64 `json:"pass_rate_by_content"`
	EngagementByContent       map[string]float64 `json:"engagement_by_content"`
	RetryRateByContent        map[string]float64 `json:"retry_rate_by_content"`
	DevicePerformance         map[string]*DevicePerformance `json:"device_performance"`
	TimeOfDayAnalysis         map[string]*TimeSlotAnalysis `json:"time_of_day_analysis"`
	GeographicPerformance     map[string]*GeographicAnalysis `json:"geographic_performance"`
}

// DevicePerformance represents performance metrics by device type
type DevicePerformance struct {
	DeviceType       string  `json:"device_type"`
	SessionCount     int64   `json:"session_count"`
	CompletionRate   float64 `json:"completion_rate"`
	AverageScore     float64 `json:"average_score"`
	AverageTimeSpent float64 `json:"average_time_spent_minutes"`
	EngagementScore  float64 `json:"engagement_score"`
}

// TimeSlotAnalysis represents performance analysis by time of day
type TimeSlotAnalysis struct {
	TimeSlot         string  `json:"time_slot"`
	SessionCount     int64   `json:"session_count"`
	CompletionRate   float64 `json:"completion_rate"`
	AverageScore     float64 `json:"average_score"`
	EngagementScore  float64 `json:"engagement_score"`
}

// GeographicAnalysis represents performance analysis by geographic region
type GeographicAnalysis struct {
	Region           string  `json:"region"`
	SessionCount     int64   `json:"session_count"`
	CompletionRate   float64 `json:"completion_rate"`
	AverageScore     float64 `json:"average_score"`
	AverageTimeSpent float64 `json:"average_time_spent_minutes"`
}

// CompletionTrendPoint represents a point in completion trend analysis
type CompletionTrendPoint struct {
	Date              time.Time `json:"date"`
	TotalSessions     int64     `json:"total_sessions"`
	CompletedSessions int64     `json:"completed_sessions"`
	CompletionRate    float64   `json:"completion_rate"`
	AverageScore      float64   `json:"average_score"`
	UniqueLearners    int64     `json:"unique_learners"`
}

// SessionIntegrityResult represents session integrity validation result
type SessionIntegrityResult struct {
	SessionID         uuid.UUID `json:"session_id"`
	IsValid           bool      `json:"is_valid"`
	ReferenceIntact   bool      `json:"reference_intact"`
	DataConsistent    bool      `json:"data_consistent"`
	TimelineLogical   bool      `json:"timeline_logical"`
	ScoreValid        bool      `json:"score_valid"`
	Issues            []string  `json:"issues"`
	ValidatedAt       time.Time `json:"validated_at"`
}