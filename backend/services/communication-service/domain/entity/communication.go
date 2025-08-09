package entity

import (
	"time"
)

// CommunicationType represents the type of customer communication
type CommunicationType string

const (
	CommunicationTypeWelcome        CommunicationType = "welcome"
	CommunicationTypeOnboardingStep CommunicationType = "onboarding-step"
	CommunicationTypeReminder       CommunicationType = "reminder"
	CommunicationTypeChecklistItem  CommunicationType = "checklist-item"
	CommunicationTypeCompletion     CommunicationType = "completion"
	CommunicationTypeFailure        CommunicationType = "failure"
)

// DeliveryStatus represents the status of communication delivery
type DeliveryStatus string

const (
	DeliveryStatusPending    DeliveryStatus = "pending"
	DeliveryStatusScheduled  DeliveryStatus = "scheduled"
	DeliveryStatusSent       DeliveryStatus = "sent"
	DeliveryStatusDelivered  DeliveryStatus = "delivered"
	DeliveryStatusFailed     DeliveryStatus = "failed"
	DeliveryStatusBounced    DeliveryStatus = "bounced"
	DeliveryStatusUnsubscribe DeliveryStatus = "unsubscribed"
)

// Communication represents an outbound customer communication
type Communication struct {
	ID                  string                 `json:"id" db:"id"`
	Type                CommunicationType      `json:"type" db:"type"`
	CustomerProfileID   string                 `json:"customer_profile_id" db:"customer_profile_id"`
	OnboardingInstanceID *string               `json:"onboarding_instance_id,omitempty" db:"onboarding_instance_id"`
	ChecklistID         *string                `json:"checklist_id,omitempty" db:"checklist_id"`
	
	// Email Configuration
	RecipientEmail      string                 `json:"recipient_email" db:"recipient_email"`
	RecipientName       string                 `json:"recipient_name" db:"recipient_name"`
	Subject             string                 `json:"subject" db:"subject"`
	
	// Template and Content
	TemplateID          string                 `json:"template_id" db:"template_id"`
	TemplateVersion     string                 `json:"template_version" db:"template_version"`
	Variables           map[string]interface{} `json:"variables" db:"variables"`
	RenderedContent     *RenderedContent       `json:"rendered_content,omitempty" db:"-"`
	
	// Personalization and Localization
	Language            string                 `json:"language" db:"language"`
	Timezone            string                 `json:"timezone" db:"timezone"`
	CustomerTier        string                 `json:"customer_tier" db:"customer_tier"`
	
	// Scheduling and Delivery
	ScheduledAt         *time.Time             `json:"scheduled_at,omitempty" db:"scheduled_at"`
	SentAt              *time.Time             `json:"sent_at,omitempty" db:"sent_at"`
	DeliveredAt         *time.Time             `json:"delivered_at,omitempty" db:"delivered_at"`
	Status              DeliveryStatus         `json:"status" db:"status"`
	
	// Provider Information
	EmailProvider       string                 `json:"email_provider" db:"email_provider"`
	ProviderMessageID   *string                `json:"provider_message_id,omitempty" db:"provider_message_id"`
	
	// Engagement Tracking
	OpenedAt            *time.Time             `json:"opened_at,omitempty" db:"opened_at"`
	ClickedAt           *time.Time             `json:"clicked_at,omitempty" db:"clicked_at"`
	UnsubscribedAt      *time.Time             `json:"unsubscribed_at,omitempty" db:"unsubscribed_at"`
	
	// Error Handling
	AttemptCount        int                    `json:"attempt_count" db:"attempt_count"`
	LastAttemptAt       *time.Time             `json:"last_attempt_at,omitempty" db:"last_attempt_at"`
	NextRetryAt         *time.Time             `json:"next_retry_at,omitempty" db:"next_retry_at"`
	ErrorMessage        *string                `json:"error_message,omitempty" db:"error_message"`
	
	// White-labeling
	TenantID            string                 `json:"tenant_id" db:"tenant_id"`
	BrandingConfig      *BrandingConfig        `json:"branding_config,omitempty" db:"-"`
	
	// Audit
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy           string                 `json:"created_by" db:"created_by"`
}

// RenderedContent holds the final rendered email content
type RenderedContent struct {
	Subject     string `json:"subject"`
	HTMLContent string `json:"html_content"`
	TextContent string `json:"text_content"`
}

// BrandingConfig holds white-label branding configuration
type BrandingConfig struct {
	CompanyName     string            `json:"company_name"`
	LogoURL         string            `json:"logo_url"`
	PrimaryColor    string            `json:"primary_color"`
	SecondaryColor  string            `json:"secondary_color"`
	CustomDomain    string            `json:"custom_domain"`
	SupportEmail    string            `json:"support_email"`
	CustomStyles    map[string]string `json:"custom_styles"`
}

// CommunicationTemplate represents an email template
type CommunicationTemplate struct {
	ID                  string                 `json:"id" db:"id"`
	Name                string                 `json:"name" db:"name"`
	Type                CommunicationType      `json:"type" db:"type"`
	Version             string                 `json:"version" db:"version"`
	
	// Content
	SubjectTemplate     string                 `json:"subject_template" db:"subject_template"`
	HTMLTemplate        string                 `json:"html_template" db:"html_template"`
	TextTemplate        string                 `json:"text_template" db:"text_template"`
	
	// Configuration
	SupportedLanguages  []string               `json:"supported_languages" db:"supported_languages"`
	RequiredVariables   []string               `json:"required_variables" db:"required_variables"`
	OptionalVariables   []string               `json:"optional_variables" db:"optional_variables"`
	
	// Targeting
	CustomerTiers       []string               `json:"customer_tiers" db:"customer_tiers"`
	MarketSegments      []string               `json:"market_segments" db:"market_segments"`
	
	// A/B Testing
	TestGroup           *string                `json:"test_group,omitempty" db:"test_group"`
	TestWeight          *float64               `json:"test_weight,omitempty" db:"test_weight"`
	
	// Status
	IsActive            bool                   `json:"is_active" db:"is_active"`
	IsDefault           bool                   `json:"is_default" db:"is_default"`
	
	// White-labeling
	TenantID            string                 `json:"tenant_id" db:"tenant_id"`
	
	// Audit
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy           string                 `json:"created_by" db:"created_by"`
	UpdatedBy           string                 `json:"updated_by" db:"updated_by"`
}

// OnboardingChecklist represents a dynamic checklist for onboarding
type OnboardingChecklist struct {
	ID                  string                 `json:"id" db:"id"`
	CustomerProfileID   string                 `json:"customer_profile_id" db:"customer_profile_id"`
	OnboardingInstanceID string                `json:"onboarding_instance_id" db:"onboarding_instance_id"`
	
	// Configuration
	Title               string                 `json:"title" db:"title"`
	Description         string                 `json:"description" db:"description"`
	CustomerTier        string                 `json:"customer_tier" db:"customer_tier"`
	ServiceTier         string                 `json:"service_tier" db:"service_tier"`
	
	// Items
	Items               []ChecklistItem        `json:"items" db:"-"`
	
	// Progress Tracking
	TotalItems          int                    `json:"total_items" db:"total_items"`
	CompletedItems      int                    `json:"completed_items" db:"completed_items"`
	PercentComplete     float64                `json:"percent_complete" db:"percent_complete"`
	
	// Status
	Status              string                 `json:"status" db:"status"` // pending, in-progress, completed, expired
	
	// Timing
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
	DueAt               *time.Time             `json:"due_at,omitempty" db:"due_at"`
	CompletedAt         *time.Time             `json:"completed_at,omitempty" db:"completed_at"`
	
	// White-labeling
	TenantID            string                 `json:"tenant_id" db:"tenant_id"`
}

// ChecklistItem represents an individual item in an onboarding checklist
type ChecklistItem struct {
	ID                  string                 `json:"id" db:"id"`
	ChecklistID         string                 `json:"checklist_id" db:"checklist_id"`
	
	// Content
	Title               string                 `json:"title" db:"title"`
	Description         string                 `json:"description" db:"description"`
	Instructions        string                 `json:"instructions" db:"instructions"`
	
	// Configuration
	Order               int                    `json:"order" db:"order"`
	IsRequired          bool                   `json:"is_required" db:"is_required"`
	Category            string                 `json:"category" db:"category"`
	EstimatedDuration   int                    `json:"estimated_duration" db:"estimated_duration"` // minutes
	
	// Dependencies
	DependsOn           []string               `json:"depends_on" db:"depends_on"`
	
	// Completion
	IsCompleted         bool                   `json:"is_completed" db:"is_completed"`
	CompletedAt         *time.Time             `json:"completed_at,omitempty" db:"completed_at"`
	CompletedBy         *string                `json:"completed_by,omitempty" db:"completed_by"`
	CompletionNotes     *string                `json:"completion_notes,omitempty" db:"completion_notes"`
	
	// Verification
	RequiresVerification bool                  `json:"requires_verification" db:"requires_verification"`
	VerifiedAt          *time.Time             `json:"verified_at,omitempty" db:"verified_at"`
	VerifiedBy          *string                `json:"verified_by,omitempty" db:"verified_by"`
	
	// Action Links
	ActionURL           *string                `json:"action_url,omitempty" db:"action_url"`
	ActionText          *string                `json:"action_text,omitempty" db:"action_text"`
	
	// Reminders
	ReminderSchedule    []ReminderSchedule     `json:"reminder_schedule" db:"-"`
	
	// Audit
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
}

// ReminderSchedule defines when reminders should be sent
type ReminderSchedule struct {
	ID                  string                 `json:"id" db:"id"`
	ChecklistItemID     string                 `json:"checklist_item_id" db:"checklist_item_id"`
	
	// Timing
	TriggerAfterHours   int                    `json:"trigger_after_hours" db:"trigger_after_hours"`
	RecurrenceHours     *int                   `json:"recurrence_hours,omitempty" db:"recurrence_hours"`
	MaxReminders        int                    `json:"max_reminders" db:"max_reminders"`
	
	// Status
	IsActive            bool                   `json:"is_active" db:"is_active"`
	RemainingSends      int                    `json:"remaining_sends" db:"remaining_sends"`
	NextScheduledAt     *time.Time             `json:"next_scheduled_at,omitempty" db:"next_scheduled_at"`
	
	// Audit
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
}

// CommunicationAnalytics tracks engagement metrics
type CommunicationAnalytics struct {
	ID                  string                 `json:"id" db:"id"`
	CommunicationID     string                 `json:"communication_id" db:"communication_id"`
	
	// Basic Metrics
	OpenCount           int                    `json:"open_count" db:"open_count"`
	ClickCount          int                    `json:"click_count" db:"click_count"`
	ReplyCount          int                    `json:"reply_count" db:"reply_count"`
	ForwardCount        int                    `json:"forward_count" db:"forward_count"`
	
	// Engagement Timing
	FirstOpenedAt       *time.Time             `json:"first_opened_at,omitempty" db:"first_opened_at"`
	LastOpenedAt        *time.Time             `json:"last_opened_at,omitempty" db:"last_opened_at"`
	FirstClickedAt      *time.Time             `json:"first_clicked_at,omitempty" db:"first_clicked_at"`
	LastClickedAt       *time.Time             `json:"last_clicked_at,omitempty" db:"last_clicked_at"`
	
	// Device Information
	OpenDeviceTypes     []string               `json:"open_device_types" db:"open_device_types"`
	ClickDeviceTypes    []string               `json:"click_device_types" db:"click_device_types"`
	EmailClients        []string               `json:"email_clients" db:"email_clients"`
	
	// Geographic Data
	OpenLocations       []string               `json:"open_locations" db:"open_locations"`
	ClickLocations      []string               `json:"click_locations" db:"click_locations"`
	
	// Link Tracking
	ClickedLinks        []ClickedLink          `json:"clicked_links" db:"-"`
	
	// A/B Testing Results
	TestVariant         *string                `json:"test_variant,omitempty" db:"test_variant"`
	ConversionGoals     []ConversionGoal       `json:"conversion_goals" db:"-"`
	
	// White-labeling
	TenantID            string                 `json:"tenant_id" db:"tenant_id"`
	
	// Audit
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
}

// ClickedLink tracks individual link clicks
type ClickedLink struct {
	URL                 string                 `json:"url" db:"url"`
	ClickedAt           time.Time              `json:"clicked_at" db:"clicked_at"`
	DeviceType          string                 `json:"device_type" db:"device_type"`
	Location            string                 `json:"location" db:"location"`
}

// ConversionGoal tracks conversion metrics
type ConversionGoal struct {
	GoalID              string                 `json:"goal_id" db:"goal_id"`
	GoalName            string                 `json:"goal_name" db:"goal_name"`
	Achieved            bool                   `json:"achieved" db:"achieved"`
	AchievedAt          *time.Time             `json:"achieved_at,omitempty" db:"achieved_at"`
	Value               *float64               `json:"value,omitempty" db:"value"`
}

// EmailProvider represents configuration for email service providers
type EmailProvider struct {
	ID                  string                 `json:"id" db:"id"`
	Name                string                 `json:"name" db:"name"`
	Type                string                 `json:"type" db:"type"` // sendgrid, ses, mailgun, etc.
	
	// Configuration
	Configuration       map[string]interface{} `json:"configuration" db:"configuration"`
	MaxDailyEmails      int                    `json:"max_daily_emails" db:"max_daily_emails"`
	MaxHourlyEmails     int                    `json:"max_hourly_emails" db:"max_hourly_emails"`
	
	// Features
	SupportsTracking    bool                   `json:"supports_tracking" db:"supports_tracking"`
	SupportsTemplates   bool                   `json:"supports_templates" db:"supports_templates"`
	SupportsWebhooks    bool                   `json:"supports_webhooks" db:"supports_webhooks"`
	
	// Status
	IsActive            bool                   `json:"is_active" db:"is_active"`
	IsDefault           bool                   `json:"is_default" db:"is_default"`
	
	// Priority and Fallback
	Priority            int                    `json:"priority" db:"priority"`
	FallbackProviderID  *string                `json:"fallback_provider_id,omitempty" db:"fallback_provider_id"`
	
	// White-labeling
	TenantID            string                 `json:"tenant_id" db:"tenant_id"`
	
	// Audit
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy           string                 `json:"created_by" db:"created_by"`
	UpdatedBy           string                 `json:"updated_by" db:"updated_by"`
}