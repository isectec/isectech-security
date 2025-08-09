// iSECTECH Security Awareness Training Service - Content Delivery Entity
// Production-grade content delivery tracking and session management
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ContentDeliverySession represents a user's interaction with training content
type ContentDeliverySession struct {
	// Primary identifiers
	SessionID     uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"session_id"`
	TenantID      uuid.UUID `gorm:"not null;index:idx_content_delivery_tenant" json:"tenant_id"`
	UserID        uuid.UUID `gorm:"not null;index:idx_content_delivery_user" json:"user_id"`
	ContentID     uuid.UUID `gorm:"not null;index:idx_content_delivery_content" json:"content_id"`
	AssignmentID  uuid.UUID `gorm:"not null;index:idx_content_delivery_assignment" json:"assignment_id"`

	// Session information
	SessionToken        string    `gorm:"not null;size:255;index:idx_session_token" json:"session_token"`
	LaunchType          string    `gorm:"not null;size:50" json:"launch_type" validate:"required,oneof=direct assignment scheduled remedial preview"`
	DeliveryMethod      string    `gorm:"not null;size:50" json:"delivery_method" validate:"required,oneof=web_browser mobile_app embedded_iframe api_access offline_package"`
	ContentVersion      string    `gorm:"not null;size:50" json:"content_version"`
	LaunchURL           string    `gorm:"size:1000" json:"launch_url"`
	ReturnURL           string    `gorm:"size:1000" json:"return_url"`

	// Session state and progress
	Status              string    `gorm:"not null;default:initialized" json:"status" validate:"required,oneof=initialized launched active suspended completed failed timeout expired"`
	Progress            int       `gorm:"not null;default:0;check:progress BETWEEN 0 AND 100" json:"progress"`
	CompletionStatus    string    `gorm:"size:50" json:"completion_status" validate:"omitempty,oneof=incomplete completed passed failed"`
	SuccessStatus       string    `gorm:"size:50" json:"success_status" validate:"omitempty,oneof=unknown passed failed"`
	ScoreScaled         float64   `gorm:"check:score_scaled BETWEEN 0 AND 1" json:"score_scaled"`
	ScoreRaw            float64   `json:"score_raw"`
	ScoreMin            float64   `json:"score_min"`
	ScoreMax            float64   `json:"score_max"`

	// Timing and duration tracking
	LaunchedAt          time.Time  `gorm:"default:now()" json:"launched_at"`
	FirstAccessAt       *time.Time `json:"first_access_at"`
	LastAccessAt        *time.Time `json:"last_access_at"`
	CompletedAt         *time.Time `json:"completed_at"`
	SuspendedAt         *time.Time `json:"suspended_at"`
	ResumedAt           *time.Time `json:"resumed_at"`
	TimeSpentSeconds    int        `gorm:"not null;default:0" json:"time_spent_seconds"`
	IdleTimeSeconds     int        `gorm:"not null;default:0" json:"idle_time_seconds"`
	ActiveTimeSeconds   int        `gorm:"not null;default:0" json:"active_time_seconds"`
	SessionTimeoutMins  int        `gorm:"not null;default:120" json:"session_timeout_minutes"`

	// SCORM and xAPI tracking
	SCORMData           string `gorm:"type:jsonb;default:'{}'" json:"scorm_data"`
	XAPIStatements      string `gorm:"type:jsonb;default:'[]'" json:"xapi_statements"`
	CMIData             string `gorm:"type:text" json:"cmi_data"` // SCORM CMI data model
	SuspendData         string `gorm:"type:text" json:"suspend_data"`
	LearnerPreferences  string `gorm:"type:jsonb;default:'{}'" json:"learner_preferences"`
	InteractionData     string `gorm:"type:jsonb;default:'[]'" json:"interaction_data"`

	// Assessment and evaluation
	AssessmentAttempts  int       `gorm:"not null;default:0" json:"assessment_attempts"`
	MaxAssessmentAttempts int     `gorm:"not null;default:3" json:"max_assessment_attempts"`
	LastAssessmentScore float64   `json:"last_assessment_score"`
	BestAssessmentScore float64   `json:"best_assessment_score"`
	AssessmentData      string    `gorm:"type:jsonb;default:'[]'" json:"assessment_data"`
	CertificateEarned   bool      `gorm:"not null;default:false" json:"certificate_earned"`
	CertificateID       uuid.UUID `json:"certificate_id"`

	// Device and environment information
	UserAgent           string         `gorm:"size:500" json:"user_agent"`
	IPAddress           string         `gorm:"size:45" json:"ip_address"`
	DeviceType          string         `gorm:"size:50" json:"device_type"`
	OperatingSystem     string         `gorm:"size:100" json:"operating_system"`
	BrowserInfo         string         `gorm:"type:jsonb;default:'{}'" json:"browser_info"`
	ScreenResolution    string         `gorm:"size:50" json:"screen_resolution"`
	GeolocationData     string         `gorm:"type:jsonb;default:'{}'" json:"geolocation_data"`
	NetworkInfo         string         `gorm:"type:jsonb;default:'{}'" json:"network_info"`

	// Content interaction tracking
	BookmarkLocation    string         `gorm:"size:500" json:"bookmark_location"`
	NavigationPath      pq.StringArray `gorm:"type:text[]" json:"navigation_path"`
	PagesVisited        pq.StringArray `gorm:"type:text[]" json:"pages_visited"`
	ResourcesAccessed   pq.StringArray `gorm:"type:text[]" json:"resources_accessed"`
	InteractionEvents   string         `gorm:"type:jsonb;default:'[]'" json:"interaction_events"`
	EngagementMetrics   string         `gorm:"type:jsonb;default:'{}'" json:"engagement_metrics"`

	// Learning analytics
	LearningPath        string    `gorm:"type:jsonb;default:'[]'" json:"learning_path"`
	AdaptiveBranching   string    `gorm:"type:jsonb;default:'{}'" json:"adaptive_branching"`
	PersonalizationData string    `gorm:"type:jsonb;default:'{}'" json:"personalization_data"`
	PerformanceIndicators string  `gorm:"type:jsonb;default:'{}'" json:"performance_indicators"`
	BehavioralPatterns  string    `gorm:"type:jsonb;default:'{}'" json:"behavioral_patterns"`

	// Security and compliance tracking
	SecurityEvents      string `gorm:"type:jsonb;default:'[]'" json:"security_events"`
	ComplianceFlags     pq.StringArray `gorm:"type:text[]" json:"compliance_flags"`
	AuditRequirements   string `gorm:"type:jsonb;default:'{}'" json:"audit_requirements"`
	DataRetentionPolicy string `gorm:"type:jsonb;default:'{}'" json:"data_retention_policy"`

	// External system integration
	LMSSessionID        string     `gorm:"size:255" json:"lms_session_id"`
	ExternalSystemData  string     `gorm:"type:jsonb;default:'{}'" json:"external_system_data"`
	SyncStatus          string     `gorm:"size:50;default:synced" json:"sync_status" validate:"omitempty,oneof=synced pending failed"`
	LastSyncedAt        *time.Time `json:"last_synced_at"`
	SyncErrors          string     `gorm:"type:text" json:"sync_errors"`

	// Quality and feedback
	ContentRating       int    `gorm:"check:content_rating BETWEEN 1 AND 5" json:"content_rating"`
	FeedbackText        string `gorm:"type:text" json:"feedback_text"`
	TechnicalIssues     string `gorm:"type:jsonb;default:'[]'" json:"technical_issues"`
	CompletionFeedback  string `gorm:"type:jsonb;default:'{}'" json:"completion_feedback"`

	// Metadata and lifecycle
	CreatedAt           time.Time  `gorm:"default:now()" json:"created_at"`
	UpdatedAt           time.Time  `gorm:"default:now()" json:"updated_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	IsActive            bool       `gorm:"default:true" json:"is_active"`
	ArchiveAfter        *time.Time `json:"archive_after"`
	DataHash            string     `gorm:"size:64" json:"data_hash"` // SHA256 hash for data integrity
}

// ContentDeliveryAttempt represents individual attempts within a session
type ContentDeliveryAttempt struct {
	AttemptID       uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"attempt_id"`
	SessionID       uuid.UUID `gorm:"not null;index:idx_attempt_session" json:"session_id"`
	AttemptNumber   int       `gorm:"not null" json:"attempt_number"`
	StartedAt       time.Time `gorm:"default:now()" json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	Status          string    `gorm:"not null;default:started" json:"status" validate:"required,oneof=started completed abandoned timed_out"`
	TimeSpentSeconds int      `gorm:"not null;default:0" json:"time_spent_seconds"`
	Score           float64   `json:"score"`
	Passed          bool      `json:"passed"`
	ResponseData    string    `gorm:"type:jsonb;default:'{}'" json:"response_data"`
	CreatedAt       time.Time `gorm:"default:now()" json:"created_at"`
}

// DeliverySessionStatus represents the status of a delivery session
type DeliverySessionStatus string

const (
	SessionStatusInitialized DeliverySessionStatus = "initialized"
	SessionStatusLaunched    DeliverySessionStatus = "launched"
	SessionStatusActive      DeliverySessionStatus = "active"
	SessionStatusSuspended   DeliverySessionStatus = "suspended"
	SessionStatusCompleted   DeliverySessionStatus = "completed"
	SessionStatusFailed      DeliverySessionStatus = "failed"
	SessionStatusTimeout     DeliverySessionStatus = "timeout"
	SessionStatusExpired     DeliverySessionStatus = "expired"
)

// IsActive checks if the session is currently active
func (cds *ContentDeliverySession) IsActive() bool {
	return cds.Status == string(SessionStatusActive) && 
		   cds.IsActive && 
		   time.Now().Before(cds.ExpiresAt)
}

// IsCompleted checks if the session has been completed successfully
func (cds *ContentDeliverySession) IsCompleted() bool {
	return cds.Status == string(SessionStatusCompleted) || 
		   cds.CompletionStatus == "completed" ||
		   cds.CompletionStatus == "passed"
}

// IsPassed checks if the user passed the training
func (cds *ContentDeliverySession) IsPassed() bool {
	return cds.CompletionStatus == "passed" || cds.SuccessStatus == "passed"
}

// HasExpired checks if the session has expired
func (cds *ContentDeliverySession) HasExpired() bool {
	return time.Now().After(cds.ExpiresAt)
}

// CanAttemptAssessment checks if user can attempt assessment
func (cds *ContentDeliverySession) CanAttemptAssessment() bool {
	return cds.AssessmentAttempts < cds.MaxAssessmentAttempts && 
		   cds.IsActive() && 
		   !cds.IsCompleted()
}

// UpdateProgress updates the session progress and related metrics
func (cds *ContentDeliverySession) UpdateProgress(progress int, location string, timeSpent int) error {
	if progress < 0 || progress > 100 {
		return fmt.Errorf("progress must be between 0 and 100")
	}

	cds.Progress = progress
	cds.BookmarkLocation = location
	cds.TimeSpentSeconds += timeSpent
	cds.LastAccessAt = &[]time.Time{time.Now()}[0]

	// Update status based on progress
	if progress == 100 && cds.Status != string(SessionStatusCompleted) {
		cds.Status = string(SessionStatusCompleted)
		cds.CompletedAt = &[]time.Time{time.Now()}[0]
		if cds.CompletionStatus == "" {
			cds.CompletionStatus = "completed"
		}
	} else if progress > 0 && cds.Status == string(SessionStatusInitialized) {
		cds.Status = string(SessionStatusActive)
		if cds.FirstAccessAt == nil {
			cds.FirstAccessAt = &[]time.Time{time.Now()}[0]
		}
	}

	cds.UpdatedAt = time.Now()
	return nil
}

// RecordAssessmentAttempt records an assessment attempt
func (cds *ContentDeliverySession) RecordAssessmentAttempt(score float64, passed bool, responseData map[string]interface{}) error {
	cds.AssessmentAttempts++
	cds.LastAssessmentScore = score

	if score > cds.BestAssessmentScore {
		cds.BestAssessmentScore = score
	}

	if passed {
		cds.CompletionStatus = "passed"
		cds.SuccessStatus = "passed"
		if cds.CompletedAt == nil {
			cds.CompletedAt = &[]time.Time{time.Now()}[0]
		}
	} else {
		cds.SuccessStatus = "failed"
		if cds.AssessmentAttempts >= cds.MaxAssessmentAttempts {
			cds.CompletionStatus = "failed"
			cds.Status = string(SessionStatusFailed)
		}
	}

	// Update assessment data
	var assessmentData []map[string]interface{}
	if cds.AssessmentData != "" {
		json.Unmarshal([]byte(cds.AssessmentData), &assessmentData)
	}

	attemptData := map[string]interface{}{
		"attempt":     cds.AssessmentAttempts,
		"score":       score,
		"passed":      passed,
		"timestamp":   time.Now(),
		"responses":   responseData,
	}

	assessmentData = append(assessmentData, attemptData)
	assessmentJSON, _ := json.Marshal(assessmentData)
	cds.AssessmentData = string(assessmentJSON)

	cds.UpdatedAt = time.Now()
	return nil
}

// AddInteractionEvent adds an interaction event to the session
func (cds *ContentDeliverySession) AddInteractionEvent(eventType string, eventData map[string]interface{}) {
	var events []map[string]interface{}
	if cds.InteractionEvents != "" {
		json.Unmarshal([]byte(cds.InteractionEvents), &events)
	}

	event := map[string]interface{}{
		"type":      eventType,
		"timestamp": time.Now(),
		"data":      eventData,
	}

	events = append(events, event)

	// Keep only last 1000 events to prevent excessive data growth
	if len(events) > 1000 {
		events = events[len(events)-1000:]
	}

	eventsJSON, _ := json.Marshal(events)
	cds.InteractionEvents = string(eventsJSON)
	cds.UpdatedAt = time.Now()
}

// UpdateSCORMData updates SCORM-specific data
func (cds *ContentDeliverySession) UpdateSCORMData(element string, value interface{}) {
	var scormData map[string]interface{}
	if cds.SCORMData != "" {
		json.Unmarshal([]byte(cds.SCORMData), &scormData)
	}
	if scormData == nil {
		scormData = make(map[string]interface{})
	}

	scormData[element] = value
	scormData["last_updated"] = time.Now()

	scormJSON, _ := json.Marshal(scormData)
	cds.SCORMData = string(scormJSON)
	cds.UpdatedAt = time.Now()
}

// AddXAPIStatement adds an xAPI statement to the session
func (cds *ContentDeliverySession) AddXAPIStatement(statement map[string]interface{}) {
	var statements []map[string]interface{}
	if cds.XAPIStatements != "" {
		json.Unmarshal([]byte(cds.XAPIStatements), &statements)
	}

	statement["timestamp"] = time.Now()
	statements = append(statements, statement)

	// Keep only last 500 statements
	if len(statements) > 500 {
		statements = statements[len(statements)-500:]
	}

	statementsJSON, _ := json.Marshal(statements)
	cds.XAPIStatements = string(statementsJSON)
	cds.UpdatedAt = time.Now()
}

// Suspend suspends the current session
func (cds *ContentDeliverySession) Suspend(suspendData string) {
	cds.Status = string(SessionStatusSuspended)
	cds.SuspendData = suspendData
	cds.SuspendedAt = &[]time.Time{time.Now()}[0]
	cds.UpdatedAt = time.Now()
}

// Resume resumes a suspended session
func (cds *ContentDeliverySession) Resume() error {
	if cds.Status != string(SessionStatusSuspended) {
		return fmt.Errorf("can only resume suspended sessions")
	}

	if cds.HasExpired() {
		return fmt.Errorf("session has expired")
	}

	cds.Status = string(SessionStatusActive)
	cds.ResumedAt = &[]time.Time{time.Now()}[0]
	cds.UpdatedAt = time.Now()
	return nil
}

// CalculateEngagement calculates engagement metrics based on interaction data
func (cds *ContentDeliverySession) CalculateEngagement() map[string]float64 {
	metrics := map[string]float64{
		"time_ratio":        0.0,
		"interaction_rate":  0.0,
		"progress_velocity": 0.0,
		"engagement_score":  0.0,
	}

	if cds.TimeSpentSeconds > 0 {
		// Calculate time efficiency ratio
		expectedTime := float64(60 * 60) // 1 hour default
		metrics["time_ratio"] = float64(cds.ActiveTimeSeconds) / expectedTime

		// Calculate interaction rate
		var events []map[string]interface{}
		json.Unmarshal([]byte(cds.InteractionEvents), &events)
		if len(events) > 0 {
			metrics["interaction_rate"] = float64(len(events)) / (float64(cds.TimeSpentSeconds) / 60.0) // per minute
		}

		// Calculate progress velocity
		if cds.TimeSpentSeconds > 0 {
			metrics["progress_velocity"] = float64(cds.Progress) / (float64(cds.TimeSpentSeconds) / 60.0)
		}

		// Overall engagement score
		metrics["engagement_score"] = (metrics["time_ratio"] + metrics["interaction_rate"] + metrics["progress_velocity"]) / 3.0
		if metrics["engagement_score"] > 1.0 {
			metrics["engagement_score"] = 1.0
		}
	}

	// Update engagement metrics
	engagementJSON, _ := json.Marshal(metrics)
	cds.EngagementMetrics = string(engagementJSON)

	return metrics
}

// GetTotalTimeSpent returns total time spent in a human-readable format
func (cds *ContentDeliverySession) GetTotalTimeSpent() time.Duration {
	return time.Duration(cds.TimeSpentSeconds) * time.Second
}

// TableName sets the table name for GORM
func (ContentDeliverySession) TableName() string {
	return "content_delivery_sessions"
}

// TableName sets the table name for GORM
func (ContentDeliveryAttempt) TableName() string {
	return "content_delivery_attempts"
}