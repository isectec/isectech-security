package service

import (
	"context"
	"time"

	"github.com/isectech/protect/backend/services/communication-service/domain/entity"
)

// CommunicationService defines the business logic for customer communications
type CommunicationService interface {
	// Welcome Communications
	SendWelcomeEmail(ctx context.Context, request *WelcomeEmailRequest) (*CommunicationResult, error)
	
	// Onboarding Communications
	SendOnboardingStepNotification(ctx context.Context, request *OnboardingStepRequest) (*CommunicationResult, error)
	SendOnboardingReminder(ctx context.Context, request *OnboardingReminderRequest) (*CommunicationResult, error)
	
	// Checklist Communications
	SendChecklistItemReminder(ctx context.Context, request *ChecklistReminderRequest) (*CommunicationResult, error)
	SendChecklistCompletionNotification(ctx context.Context, request *ChecklistCompletionRequest) (*CommunicationResult, error)
	
	// Communication Management
	ScheduleCommunication(ctx context.Context, request *ScheduleCommunicationRequest) (*entity.Communication, error)
	CancelScheduledCommunication(ctx context.Context, communicationID, tenantID string) error
	RetryCommunication(ctx context.Context, communicationID, tenantID string) (*CommunicationResult, error)
	
	// Bulk Operations
	SendBulkCommunications(ctx context.Context, request *BulkCommunicationRequest) (*BulkCommunicationResult, error)
	
	// Communication Queries
	GetCommunication(ctx context.Context, communicationID, tenantID string) (*entity.Communication, error)
	ListCommunications(ctx context.Context, filter *CommunicationFilter) (*CommunicationListResult, error)
	GetCommunicationHistory(ctx context.Context, customerProfileID, tenantID string) ([]*entity.Communication, error)
	
	// Analytics and Reporting
	GetEngagementMetrics(ctx context.Context, request *EngagementMetricsRequest) (*EngagementMetrics, error)
	GetCommunicationAnalytics(ctx context.Context, request *AnalyticsRequest) (*CommunicationAnalytics, error)
	
	// A/B Testing
	CreateABTest(ctx context.Context, request *ABTestRequest) (*ABTest, error)
	GetABTestResults(ctx context.Context, testID, tenantID string) (*ABTestResults, error)
}

// ChecklistService defines the business logic for onboarding checklists
type ChecklistService interface {
	// Checklist Management
	CreateOnboardingChecklist(ctx context.Context, request *CreateChecklistRequest) (*entity.OnboardingChecklist, error)
	UpdateChecklist(ctx context.Context, checklistID, tenantID string, updates *UpdateChecklistRequest) (*entity.OnboardingChecklist, error)
	DeleteChecklist(ctx context.Context, checklistID, tenantID string) error
	
	// Checklist Queries
	GetChecklist(ctx context.Context, checklistID, tenantID string) (*entity.OnboardingChecklist, error)
	GetChecklistByOnboardingInstance(ctx context.Context, onboardingInstanceID, tenantID string) (*entity.OnboardingChecklist, error)
	ListChecklists(ctx context.Context, filter *ChecklistFilter) (*ChecklistListResult, error)
	
	// Item Management
	AddChecklistItem(ctx context.Context, checklistID, tenantID string, item *entity.ChecklistItem) (*entity.ChecklistItem, error)
	UpdateChecklistItem(ctx context.Context, itemID, tenantID string, updates *UpdateChecklistItemRequest) (*entity.ChecklistItem, error)
	CompleteChecklistItem(ctx context.Context, itemID, completedBy, tenantID string, notes *string) error
	VerifyChecklistItem(ctx context.Context, itemID, verifiedBy, tenantID string) error
	DeleteChecklistItem(ctx context.Context, itemID, tenantID string) error
	
	// Progress Tracking
	GetChecklistProgress(ctx context.Context, checklistID, tenantID string) (*ChecklistProgress, error)
	UpdateProgress(ctx context.Context, checklistID, tenantID string) error
	
	// Reminder Management
	ScheduleReminders(ctx context.Context, checklistID, tenantID string) error
	ProcessDueReminders(ctx context.Context, tenantID string) (*ReminderProcessResult, error)
	UpdateReminderSchedule(ctx context.Context, itemID, tenantID string, schedule []entity.ReminderSchedule) error
}

// TemplateService defines the business logic for communication templates
type TemplateService interface {
	// Template Management
	CreateTemplate(ctx context.Context, request *CreateTemplateRequest) (*entity.CommunicationTemplate, error)
	UpdateTemplate(ctx context.Context, templateID, tenantID string, updates *UpdateTemplateRequest) (*entity.CommunicationTemplate, error)
	DeleteTemplate(ctx context.Context, templateID, tenantID string) error
	
	// Template Queries
	GetTemplate(ctx context.Context, templateID, tenantID string) (*entity.CommunicationTemplate, error)
	ListTemplates(ctx context.Context, filter *TemplateFilter) (*TemplateListResult, error)
	GetTemplateByType(ctx context.Context, communicationType entity.CommunicationType, tenantID, customerTier string) (*entity.CommunicationTemplate, error)
	
	// Template Operations
	RenderTemplate(ctx context.Context, request *RenderTemplateRequest) (*RenderedTemplate, error)
	ValidateTemplate(ctx context.Context, templateID, tenantID string) (*TemplateValidationResult, error)
	PreviewTemplate(ctx context.Context, request *PreviewTemplateRequest) (*TemplatePreview, error)
	
	// A/B Testing Templates
	CreateTestVariant(ctx context.Context, baseTemplateID, tenantID string, variant *TestVariantRequest) (*entity.CommunicationTemplate, error)
	SelectTestVariant(ctx context.Context, communicationType entity.CommunicationType, customerTier, tenantID string) (*entity.CommunicationTemplate, error)
	
	// Template Versioning
	CreateTemplateVersion(ctx context.Context, templateID, tenantID string) (*entity.CommunicationTemplate, error)
	GetTemplateVersions(ctx context.Context, templateID, tenantID string) ([]*entity.CommunicationTemplate, error)
	RollbackTemplate(ctx context.Context, templateID, version, tenantID string) error
}

// EmailProviderService defines the business logic for email provider management
type EmailProviderService interface {
	// Provider Management
	CreateEmailProvider(ctx context.Context, request *CreateEmailProviderRequest) (*entity.EmailProvider, error)
	UpdateEmailProvider(ctx context.Context, providerID, tenantID string, updates *UpdateEmailProviderRequest) (*entity.EmailProvider, error)
	DeleteEmailProvider(ctx context.Context, providerID, tenantID string) error
	
	// Provider Queries
	GetEmailProvider(ctx context.Context, providerID, tenantID string) (*entity.EmailProvider, error)
	ListEmailProviders(ctx context.Context, tenantID string) ([]*entity.EmailProvider, error)
	GetDefaultEmailProvider(ctx context.Context, tenantID string) (*entity.EmailProvider, error)
	
	// Provider Operations
	TestEmailProvider(ctx context.Context, providerID, tenantID string, testEmail *TestEmailRequest) (*TestEmailResult, error)
	SendEmail(ctx context.Context, request *SendEmailRequest) (*SendEmailResult, error)
	ProcessWebhook(ctx context.Context, providerID, tenantID string, webhookData []byte) error
	
	// Provider Health and Monitoring
	GetProviderHealth(ctx context.Context, providerID, tenantID string) (*ProviderHealth, error)
	GetProviderMetrics(ctx context.Context, providerID, tenantID string, dateRange *DateRange) (*ProviderMetrics, error)
}

// Request/Response types
type WelcomeEmailRequest struct {
	CustomerProfileID string                 `json:"customer_profile_id"`
	TenantID         string                 `json:"tenant_id"`
	RecipientEmail   string                 `json:"recipient_email"`
	RecipientName    string                 `json:"recipient_name"`
	CustomerTier     string                 `json:"customer_tier"`
	Language         string                 `json:"language"`
	Timezone         string                 `json:"timezone"`
	Variables        map[string]interface{} `json:"variables"`
	ScheduledAt      *time.Time             `json:"scheduled_at,omitempty"`
}

type OnboardingStepRequest struct {
	OnboardingInstanceID string                 `json:"onboarding_instance_id"`
	CustomerProfileID    string                 `json:"customer_profile_id"`
	TenantID            string                 `json:"tenant_id"`
	StepName            string                 `json:"step_name"`
	StepDescription     string                 `json:"step_description"`
	RecipientEmail      string                 `json:"recipient_email"`
	RecipientName       string                 `json:"recipient_name"`
	Variables           map[string]interface{} `json:"variables"`
	ActionURL           *string                `json:"action_url,omitempty"`
	DueDate             *time.Time             `json:"due_date,omitempty"`
}

type OnboardingReminderRequest struct {
	OnboardingInstanceID string                 `json:"onboarding_instance_id"`
	CustomerProfileID    string                 `json:"customer_profile_id"`
	TenantID            string                 `json:"tenant_id"`
	ReminderType        string                 `json:"reminder_type"`
	RecipientEmail      string                 `json:"recipient_email"`
	RecipientName       string                 `json:"recipient_name"`
	Variables           map[string]interface{} `json:"variables"`
	PendingSteps        []string               `json:"pending_steps"`
}

type ChecklistReminderRequest struct {
	ChecklistID       string                 `json:"checklist_id"`
	ChecklistItemID   string                 `json:"checklist_item_id"`
	CustomerProfileID string                 `json:"customer_profile_id"`
	TenantID         string                 `json:"tenant_id"`
	RecipientEmail   string                 `json:"recipient_email"`
	RecipientName    string                 `json:"recipient_name"`
	ItemTitle        string                 `json:"item_title"`
	ItemDescription  string                 `json:"item_description"`
	Variables        map[string]interface{} `json:"variables"`
	ActionURL        *string                `json:"action_url,omitempty"`
	DueDate          *time.Time             `json:"due_date,omitempty"`
}

type ChecklistCompletionRequest struct {
	ChecklistID       string                 `json:"checklist_id"`
	CustomerProfileID string                 `json:"customer_profile_id"`
	TenantID         string                 `json:"tenant_id"`
	RecipientEmail   string                 `json:"recipient_email"`
	RecipientName    string                 `json:"recipient_name"`
	TotalItems       int                    `json:"total_items"`
	CompletedItems   int                    `json:"completed_items"`
	CompletedAt      time.Time              `json:"completed_at"`
	Variables        map[string]interface{} `json:"variables"`
	NextSteps        []string               `json:"next_steps"`
}

type ScheduleCommunicationRequest struct {
	Type              entity.CommunicationType `json:"type"`
	CustomerProfileID string                   `json:"customer_profile_id"`
	TenantID         string                   `json:"tenant_id"`
	RecipientEmail   string                   `json:"recipient_email"`
	RecipientName    string                   `json:"recipient_name"`
	TemplateID       *string                  `json:"template_id,omitempty"`
	Variables        map[string]interface{}   `json:"variables"`
	ScheduledAt      time.Time                `json:"scheduled_at"`
	CustomerTier     string                   `json:"customer_tier"`
	Language         string                   `json:"language"`
	Timezone         string                   `json:"timezone"`
}

type BulkCommunicationRequest struct {
	Type                entity.CommunicationType     `json:"type"`
	TenantID           string                       `json:"tenant_id"`
	TemplateID         *string                      `json:"template_id,omitempty"`
	Recipients         []BulkRecipient              `json:"recipients"`
	ScheduledAt        *time.Time                   `json:"scheduled_at,omitempty"`
	BatchSize          int                          `json:"batch_size"`
	DelayBetweenBatches time.Duration               `json:"delay_between_batches"`
}

type BulkRecipient struct {
	CustomerProfileID string                 `json:"customer_profile_id"`
	RecipientEmail   string                 `json:"recipient_email"`
	RecipientName    string                 `json:"recipient_name"`
	CustomerTier     string                 `json:"customer_tier"`
	Language         string                 `json:"language"`
	Timezone         string                 `json:"timezone"`
	Variables        map[string]interface{} `json:"variables"`
}

type CreateChecklistRequest struct {
	CustomerProfileID    string                    `json:"customer_profile_id"`
	OnboardingInstanceID string                    `json:"onboarding_instance_id"`
	TenantID            string                    `json:"tenant_id"`
	Title               string                    `json:"title"`
	Description         string                    `json:"description"`
	CustomerTier        string                    `json:"customer_tier"`
	ServiceTier         string                    `json:"service_tier"`
	Items               []ChecklistItemRequest    `json:"items"`
	DueAt               *time.Time                `json:"due_at,omitempty"`
}

type ChecklistItemRequest struct {
	Title               string                 `json:"title"`
	Description         string                 `json:"description"`
	Instructions        string                 `json:"instructions"`
	Category            string                 `json:"category"`
	IsRequired          bool                   `json:"is_required"`
	EstimatedDuration   int                    `json:"estimated_duration"`
	DependsOn           []string               `json:"depends_on"`
	ActionURL           *string                `json:"action_url,omitempty"`
	ActionText          *string                `json:"action_text,omitempty"`
	RequiresVerification bool                  `json:"requires_verification"`
	ReminderSchedule    []ReminderScheduleRequest `json:"reminder_schedule"`
}

type ReminderScheduleRequest struct {
	TriggerAfterHours int  `json:"trigger_after_hours"`
	RecurrenceHours   *int `json:"recurrence_hours,omitempty"`
	MaxReminders      int  `json:"max_reminders"`
}

type UpdateChecklistRequest struct {
	Title       *string    `json:"title,omitempty"`
	Description *string    `json:"description,omitempty"`
	DueAt       *time.Time `json:"due_at,omitempty"`
}

type UpdateChecklistItemRequest struct {
	Title               *string                    `json:"title,omitempty"`
	Description         *string                    `json:"description,omitempty"`
	Instructions        *string                    `json:"instructions,omitempty"`
	EstimatedDuration   *int                       `json:"estimated_duration,omitempty"`
	ActionURL           *string                    `json:"action_url,omitempty"`
	ActionText          *string                    `json:"action_text,omitempty"`
	ReminderSchedule    *[]ReminderScheduleRequest `json:"reminder_schedule,omitempty"`
}

type CreateTemplateRequest struct {
	Name                string                    `json:"name"`
	Type                entity.CommunicationType  `json:"type"`
	TenantID           string                    `json:"tenant_id"`
	SubjectTemplate    string                    `json:"subject_template"`
	HTMLTemplate       string                    `json:"html_template"`
	TextTemplate       string                    `json:"text_template"`
	SupportedLanguages []string                  `json:"supported_languages"`
	CustomerTiers      []string                  `json:"customer_tiers"`
	MarketSegments     []string                  `json:"market_segments"`
	RequiredVariables  []string                  `json:"required_variables"`
	OptionalVariables  []string                  `json:"optional_variables"`
	IsDefault          bool                      `json:"is_default"`
	CreatedBy          string                    `json:"created_by"`
}

type UpdateTemplateRequest struct {
	Name               *string   `json:"name,omitempty"`
	SubjectTemplate    *string   `json:"subject_template,omitempty"`
	HTMLTemplate       *string   `json:"html_template,omitempty"`
	TextTemplate       *string   `json:"text_template,omitempty"`
	SupportedLanguages *[]string `json:"supported_languages,omitempty"`
	CustomerTiers      *[]string `json:"customer_tiers,omitempty"`
	MarketSegments     *[]string `json:"market_segments,omitempty"`
	IsActive           *bool     `json:"is_active,omitempty"`
	IsDefault          *bool     `json:"is_default,omitempty"`
	UpdatedBy          string    `json:"updated_by"`
}

type RenderTemplateRequest struct {
	TemplateID       string                 `json:"template_id"`
	TenantID        string                 `json:"tenant_id"`
	Variables       map[string]interface{} `json:"variables"`
	Language        string                 `json:"language"`
	BrandingConfig  *entity.BrandingConfig `json:"branding_config,omitempty"`
}

type PreviewTemplateRequest struct {
	TemplateID      string                 `json:"template_id"`
	TenantID       string                 `json:"tenant_id"`
	Variables      map[string]interface{} `json:"variables"`
	Language       string                 `json:"language"`
	BrandingConfig *entity.BrandingConfig `json:"branding_config,omitempty"`
}

type TestVariantRequest struct {
	VariantName     string  `json:"variant_name"`
	SubjectTemplate *string `json:"subject_template,omitempty"`
	HTMLTemplate    *string `json:"html_template,omitempty"`
	TextTemplate    *string `json:"text_template,omitempty"`
	TestWeight      float64 `json:"test_weight"`
	CreatedBy       string  `json:"created_by"`
}

type CreateEmailProviderRequest struct {
	Name              string                 `json:"name"`
	Type              string                 `json:"type"`
	TenantID         string                 `json:"tenant_id"`
	Configuration    map[string]interface{} `json:"configuration"`
	MaxDailyEmails   int                    `json:"max_daily_emails"`
	MaxHourlyEmails  int                    `json:"max_hourly_emails"`
	Priority         int                    `json:"priority"`
	IsDefault        bool                   `json:"is_default"`
	CreatedBy        string                 `json:"created_by"`
}

type UpdateEmailProviderRequest struct {
	Name               *string                 `json:"name,omitempty"`
	Configuration     *map[string]interface{} `json:"configuration,omitempty"`
	MaxDailyEmails    *int                    `json:"max_daily_emails,omitempty"`
	MaxHourlyEmails   *int                    `json:"max_hourly_emails,omitempty"`
	Priority          *int                    `json:"priority,omitempty"`
	IsActive          *bool                   `json:"is_active,omitempty"`
	IsDefault         *bool                   `json:"is_default,omitempty"`
	UpdatedBy         string                  `json:"updated_by"`
}

type TestEmailRequest struct {
	RecipientEmail string                 `json:"recipient_email"`
	Subject        string                 `json:"subject"`
	HTMLContent    string                 `json:"html_content"`
	TextContent    string                 `json:"text_content"`
	Variables      map[string]interface{} `json:"variables"`
}

type SendEmailRequest struct {
	ProviderID     *string `json:"provider_id,omitempty"`
	TenantID      string  `json:"tenant_id"`
	RecipientEmail string  `json:"recipient_email"`
	RecipientName  string  `json:"recipient_name"`
	Subject        string  `json:"subject"`
	HTMLContent    string  `json:"html_content"`
	TextContent    string  `json:"text_content"`
	TrackOpens     bool    `json:"track_opens"`
	TrackClicks    bool    `json:"track_clicks"`
}

// Response types
type CommunicationResult struct {
	CommunicationID   string `json:"communication_id"`
	Status            string `json:"status"`
	ProviderMessageID *string `json:"provider_message_id,omitempty"`
	ScheduledAt       *time.Time `json:"scheduled_at,omitempty"`
	SentAt            *time.Time `json:"sent_at,omitempty"`
	Error             *string `json:"error,omitempty"`
}

type BulkCommunicationResult struct {
	TotalRequested int                           `json:"total_requested"`
	TotalScheduled int                           `json:"total_scheduled"`
	TotalFailed    int                           `json:"total_failed"`
	Results        []CommunicationResult         `json:"results"`
	Errors         []BulkCommunicationError      `json:"errors"`
	BatchID        string                        `json:"batch_id"`
}

type BulkCommunicationError struct {
	RecipientEmail string `json:"recipient_email"`
	Error          string `json:"error"`
}

type CommunicationListResult struct {
	Communications []*entity.Communication `json:"communications"`
	Total          int                      `json:"total"`
	Page           int                      `json:"page"`
	Limit          int                      `json:"limit"`
	HasMore        bool                     `json:"has_more"`
}

type ChecklistListResult struct {
	Checklists []*entity.OnboardingChecklist `json:"checklists"`
	Total      int                           `json:"total"`
	Page       int                           `json:"page"`
	Limit      int                           `json:"limit"`
	HasMore    bool                          `json:"has_more"`
}

type TemplateListResult struct {
	Templates []*entity.CommunicationTemplate `json:"templates"`
	Total     int                             `json:"total"`
	Page      int                             `json:"page"`
	Limit     int                             `json:"limit"`
	HasMore   bool                            `json:"has_more"`
}

type ChecklistProgress struct {
	ChecklistID      string    `json:"checklist_id"`
	TotalItems       int       `json:"total_items"`
	CompletedItems   int       `json:"completed_items"`
	PercentComplete  float64   `json:"percent_complete"`
	PendingItems     int       `json:"pending_items"`
	BlockedItems     int       `json:"blocked_items"`
	OverdueItems     int       `json:"overdue_items"`
	EstimatedTimeLeft int      `json:"estimated_time_left"` // minutes
	LastUpdated      time.Time `json:"last_updated"`
}

type ReminderProcessResult struct {
	ProcessedCount int      `json:"processed_count"`
	SentCount      int      `json:"sent_count"`
	FailedCount    int      `json:"failed_count"`
	Errors         []string `json:"errors"`
}

type RenderedTemplate struct {
	Subject     string `json:"subject"`
	HTMLContent string `json:"html_content"`
	TextContent string `json:"text_content"`
}

type TemplateValidationResult struct {
	IsValid      bool     `json:"is_valid"`
	Errors       []string `json:"errors"`
	Warnings     []string `json:"warnings"`
	Suggestions  []string `json:"suggestions"`
	MissingVars  []string `json:"missing_variables"`
	UnusedVars   []string `json:"unused_variables"`
}

type TemplatePreview struct {
	RenderedTemplate
	ValidationResult *TemplateValidationResult `json:"validation_result"`
	PreviewURL       *string                   `json:"preview_url,omitempty"`
}

type TestEmailResult struct {
	Success           bool    `json:"success"`
	ProviderMessageID *string `json:"provider_message_id,omitempty"`
	DeliveryTime      int64   `json:"delivery_time_ms"`
	Error             *string `json:"error,omitempty"`
}

type SendEmailResult struct {
	Success           bool    `json:"success"`
	ProviderMessageID *string `json:"provider_message_id,omitempty"`
	DeliveryTime      int64   `json:"delivery_time_ms"`
	Error             *string `json:"error,omitempty"`
	QuotaRemaining    *int    `json:"quota_remaining,omitempty"`
}

type ProviderHealth struct {
	ProviderID        string    `json:"provider_id"`
	Status            string    `json:"status"` // healthy, degraded, unhealthy
	LastHealthCheck   time.Time `json:"last_health_check"`
	ResponseTime      int64     `json:"response_time_ms"`
	ErrorRate         float64   `json:"error_rate"`
	QuotaUsed         int       `json:"quota_used"`
	QuotaLimit        int       `json:"quota_limit"`
	QuotaResetAt      time.Time `json:"quota_reset_at"`
}

type ProviderMetrics struct {
	ProviderID         string              `json:"provider_id"`
	DateRange          DateRange           `json:"date_range"`
	TotalEmailsSent    int                 `json:"total_emails_sent"`
	DeliveryRate       float64             `json:"delivery_rate"`
	BounceRate         float64             `json:"bounce_rate"`
	ComplaintRate      float64             `json:"complaint_rate"`
	OpenRate           float64             `json:"open_rate"`
	ClickRate          float64             `json:"click_rate"`
	AverageDeliveryTime int64              `json:"average_delivery_time_ms"`
	DailyMetrics       []DailyProviderMetrics `json:"daily_metrics"`
}

type DailyProviderMetrics struct {
	Date         time.Time `json:"date"`
	EmailsSent   int       `json:"emails_sent"`
	Delivered    int       `json:"delivered"`
	Bounced      int       `json:"bounced"`
	Complained   int       `json:"complained"`
	Opened       int       `json:"opened"`
	Clicked      int       `json:"clicked"`
}

// Filter types for service queries
type CommunicationFilter struct {
	CustomerProfileID    *string
	OnboardingInstanceID *string
	Type                 *entity.CommunicationType
	Status               *entity.DeliveryStatus
	DateRange            *DateRange
	CustomerTier         *string
	Language             *string
	Page                 int
	Limit                int
	SortBy               string
	SortDirection        string
}

type ChecklistFilter struct {
	CustomerProfileID    *string
	OnboardingInstanceID *string
	Status               *string
	CustomerTier         *string
	ServiceTier          *string
	DateRange            *DateRange
	Page                 int
	Limit                int
	SortBy               string
	SortDirection        string
}

type TemplateFilter struct {
	Type          *entity.CommunicationType
	IsActive      *bool
	IsDefault     *bool
	Language      *string
	CustomerTiers []string
	TestGroup     *string
	Page          int
	Limit         int
	SortBy        string
	SortDirection string
}

// Common types
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Analytics types
type EngagementMetricsRequest struct {
	TenantID       string                      `json:"tenant_id"`
	DateRange      DateRange                   `json:"date_range"`
	CommunicationType *entity.CommunicationType `json:"communication_type,omitempty"`
	CustomerTier   *string                     `json:"customer_tier,omitempty"`
	Language       *string                     `json:"language,omitempty"`
}

type EngagementMetrics struct {
	TotalSent        int     `json:"total_sent"`
	TotalDelivered   int     `json:"total_delivered"`
	TotalOpened      int     `json:"total_opened"`
	TotalClicked     int     `json:"total_clicked"`
	TotalBounced     int     `json:"total_bounced"`
	TotalComplained  int     `json:"total_complained"`
	TotalUnsubscribed int    `json:"total_unsubscribed"`
	DeliveryRate     float64 `json:"delivery_rate"`
	OpenRate         float64 `json:"open_rate"`
	ClickRate        float64 `json:"click_rate"`
	ClickThroughRate float64 `json:"click_through_rate"`
	BounceRate       float64 `json:"bounce_rate"`
	ComplaintRate    float64 `json:"complaint_rate"`
	UnsubscribeRate  float64 `json:"unsubscribe_rate"`
}

type AnalyticsRequest struct {
	TenantID    string                      `json:"tenant_id"`
	DateRange   DateRange                   `json:"date_range"`
	GroupBy     []string                    `json:"group_by"` // customer_tier, communication_type, language, etc.
	Metrics     []string                    `json:"metrics"`  // delivery_rate, open_rate, click_rate, etc.
	Filters     map[string]interface{}      `json:"filters"`
}

type CommunicationAnalytics struct {
	TotalMetrics    EngagementMetrics              `json:"total_metrics"`
	GroupedMetrics  map[string]EngagementMetrics   `json:"grouped_metrics"`
	TrendData       []TrendDataPoint               `json:"trend_data"`
	TopPerformers   []PerformanceMetric            `json:"top_performers"`
	BottomPerformers []PerformanceMetric           `json:"bottom_performers"`
}

type TrendDataPoint struct {
	Date    time.Time         `json:"date"`
	Metrics EngagementMetrics `json:"metrics"`
}

type PerformanceMetric struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Value       float64 `json:"value"`
	Improvement float64 `json:"improvement"` // percentage change
}

// A/B Testing types
type ABTestRequest struct {
	Name                string                    `json:"name"`
	Description         string                    `json:"description"`
	CommunicationType   entity.CommunicationType  `json:"communication_type"`
	TenantID           string                    `json:"tenant_id"`
	BaseTemplateID     string                    `json:"base_template_id"`
	TestVariants       []TestVariantRequest      `json:"test_variants"`
	TrafficSplit       []float64                 `json:"traffic_split"`
	StartDate          time.Time                 `json:"start_date"`
	EndDate            time.Time                 `json:"end_date"`
	ConversionGoals    []string                  `json:"conversion_goals"`
	MinimumSampleSize  int                       `json:"minimum_sample_size"`
	CreatedBy          string                    `json:"created_by"`
}

type ABTest struct {
	ID                  string                    `json:"id"`
	Name                string                    `json:"name"`
	Description         string                    `json:"description"`
	CommunicationType   entity.CommunicationType  `json:"communication_type"`
	Status              string                    `json:"status"` // draft, active, paused, completed
	BaseTemplate        *entity.CommunicationTemplate `json:"base_template"`
	TestVariants        []*entity.CommunicationTemplate `json:"test_variants"`
	TrafficSplit        []float64                 `json:"traffic_split"`
	StartDate           time.Time                 `json:"start_date"`
	EndDate             time.Time                 `json:"end_date"`
	ConversionGoals     []string                  `json:"conversion_goals"`
	MinimumSampleSize   int                       `json:"minimum_sample_size"`
	CurrentSampleSize   int                       `json:"current_sample_size"`
	StatisticalSignificance float64               `json:"statistical_significance"`
	TenantID           string                    `json:"tenant_id"`
	CreatedAt          time.Time                 `json:"created_at"`
	CreatedBy          string                    `json:"created_by"`
}

type ABTestResults struct {
	TestID              string                `json:"test_id"`
	Status              string                `json:"status"`
	TotalParticipants   int                   `json:"total_participants"`
	StatisticalSignificance float64           `json:"statistical_significance"`
	ConfidenceLevel     float64               `json:"confidence_level"`
	WinningVariant      *string               `json:"winning_variant,omitempty"`
	Results             []ABTestVariantResult `json:"results"`
	ConversionResults   []ConversionResult    `json:"conversion_results"`
	Recommendations     []string              `json:"recommendations"`
}

type ABTestVariantResult struct {
	VariantID       string  `json:"variant_id"`
	VariantName     string  `json:"variant_name"`
	Participants    int     `json:"participants"`
	Opens           int     `json:"opens"`
	Clicks          int     `json:"clicks"`
	Conversions     int     `json:"conversions"`
	OpenRate        float64 `json:"open_rate"`
	ClickRate       float64 `json:"click_rate"`
	ConversionRate  float64 `json:"conversion_rate"`
	Improvement     float64 `json:"improvement"` // vs control
	Confidence      float64 `json:"confidence"`
}

type ConversionResult struct {
	GoalName        string  `json:"goal_name"`
	TotalConversions int    `json:"total_conversions"`
	ConversionRate  float64 `json:"conversion_rate"`
	VariantResults  []VariantConversion `json:"variant_results"`
}

type VariantConversion struct {
	VariantID      string  `json:"variant_id"`
	Conversions    int     `json:"conversions"`
	ConversionRate float64 `json:"conversion_rate"`
	Improvement    float64 `json:"improvement"`
}