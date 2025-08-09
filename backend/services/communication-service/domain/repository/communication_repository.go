package repository

import (
	"context"
	"time"

	"github.com/isectech/protect/backend/services/communication-service/domain/entity"
)

// CommunicationRepository defines the interface for communication persistence
type CommunicationRepository interface {
	// Communication CRUD operations
	CreateCommunication(ctx context.Context, communication *entity.Communication) error
	GetCommunicationByID(ctx context.Context, id string, tenantID string) (*entity.Communication, error)
	UpdateCommunication(ctx context.Context, communication *entity.Communication) error
	DeleteCommunication(ctx context.Context, id string, tenantID string) error
	
	// Communication queries
	ListCommunications(ctx context.Context, filter CommunicationFilter) ([]*entity.Communication, int, error)
	GetCommunicationsByCustomer(ctx context.Context, customerProfileID string, tenantID string) ([]*entity.Communication, error)
	GetCommunicationsByOnboardingInstance(ctx context.Context, onboardingInstanceID string, tenantID string) ([]*entity.Communication, error)
	GetCommunicationsByStatus(ctx context.Context, status entity.DeliveryStatus, tenantID string) ([]*entity.Communication, error)
	GetScheduledCommunications(ctx context.Context, beforeTime time.Time, tenantID string) ([]*entity.Communication, error)
	
	// Retry and failure handling
	GetFailedCommunications(ctx context.Context, tenantID string, maxAttempts int) ([]*entity.Communication, error)
	UpdateCommunicationStatus(ctx context.Context, id string, status entity.DeliveryStatus, providerMessageID *string, errorMessage *string, tenantID string) error
	IncrementAttemptCount(ctx context.Context, id string, nextRetryAt *time.Time, tenantID string) error
	
	// Engagement tracking
	RecordEmailOpen(ctx context.Context, communicationID string, openedAt time.Time, deviceInfo map[string]string, tenantID string) error
	RecordEmailClick(ctx context.Context, communicationID string, clickedAt time.Time, url string, deviceInfo map[string]string, tenantID string) error
	RecordUnsubscribe(ctx context.Context, communicationID string, unsubscribedAt time.Time, tenantID string) error
}

// CommunicationTemplateRepository defines the interface for template persistence
type CommunicationTemplateRepository interface {
	// Template CRUD operations
	CreateTemplate(ctx context.Context, template *entity.CommunicationTemplate) error
	GetTemplateByID(ctx context.Context, id string, tenantID string) (*entity.CommunicationTemplate, error)
	UpdateTemplate(ctx context.Context, template *entity.CommunicationTemplate) error
	DeleteTemplate(ctx context.Context, id string, tenantID string) error
	
	// Template queries
	ListTemplates(ctx context.Context, filter TemplateFilter) ([]*entity.CommunicationTemplate, int, error)
	GetTemplateByType(ctx context.Context, communicationType entity.CommunicationType, tenantID string, customerTier *string) (*entity.CommunicationTemplate, error)
	GetTemplatesByTenant(ctx context.Context, tenantID string) ([]*entity.CommunicationTemplate, error)
	GetActiveTemplates(ctx context.Context, tenantID string) ([]*entity.CommunicationTemplate, error)
	
	// A/B Testing
	GetTestVariants(ctx context.Context, communicationType entity.CommunicationType, tenantID string) ([]*entity.CommunicationTemplate, error)
	SelectTestVariant(ctx context.Context, communicationType entity.CommunicationType, customerTier string, tenantID string) (*entity.CommunicationTemplate, error)
	
	// Template versioning
	CreateTemplateVersion(ctx context.Context, templateID string, version string, tenantID string) error
	GetTemplateVersions(ctx context.Context, templateID string, tenantID string) ([]*entity.CommunicationTemplate, error)
}

// ChecklistRepository defines the interface for checklist persistence
type ChecklistRepository interface {
	// Checklist CRUD operations
	CreateChecklist(ctx context.Context, checklist *entity.OnboardingChecklist) error
	GetChecklistByID(ctx context.Context, id string, tenantID string) (*entity.OnboardingChecklist, error)
	UpdateChecklist(ctx context.Context, checklist *entity.OnboardingChecklist) error
	DeleteChecklist(ctx context.Context, id string, tenantID string) error
	
	// Checklist queries
	ListChecklists(ctx context.Context, filter ChecklistFilter) ([]*entity.OnboardingChecklist, int, error)
	GetChecklistByOnboardingInstance(ctx context.Context, onboardingInstanceID string, tenantID string) (*entity.OnboardingChecklist, error)
	GetChecklistsByCustomer(ctx context.Context, customerProfileID string, tenantID string) ([]*entity.OnboardingChecklist, error)
	GetIncompleteChecklists(ctx context.Context, tenantID string) ([]*entity.OnboardingChecklist, error)
	GetExpiredChecklists(ctx context.Context, tenantID string) ([]*entity.OnboardingChecklist, error)
	
	// Progress tracking
	UpdateChecklistProgress(ctx context.Context, checklistID string, completedItems int, percentComplete float64, tenantID string) error
	CompleteChecklist(ctx context.Context, checklistID string, completedAt time.Time, tenantID string) error
}

// ChecklistItemRepository defines the interface for checklist item persistence
type ChecklistItemRepository interface {
	// Item CRUD operations
	CreateItem(ctx context.Context, item *entity.ChecklistItem) error
	GetItemByID(ctx context.Context, id string, tenantID string) (*entity.ChecklistItem, error)
	UpdateItem(ctx context.Context, item *entity.ChecklistItem) error
	DeleteItem(ctx context.Context, id string, tenantID string) error
	
	// Item queries
	GetItemsByChecklist(ctx context.Context, checklistID string, tenantID string) ([]*entity.ChecklistItem, error)
	GetIncompleteItems(ctx context.Context, checklistID string, tenantID string) ([]*entity.ChecklistItem, error)
	GetCompletedItems(ctx context.Context, checklistID string, tenantID string) ([]*entity.ChecklistItem, error)
	GetItemsDueForReminder(ctx context.Context, tenantID string) ([]*entity.ChecklistItem, error)
	
	// Item completion
	CompleteItem(ctx context.Context, itemID string, completedBy string, completionNotes *string, tenantID string) error
	VerifyItem(ctx context.Context, itemID string, verifiedBy string, tenantID string) error
	
	// Dependencies
	GetDependentItems(ctx context.Context, itemID string, tenantID string) ([]*entity.ChecklistItem, error)
	GetBlockedItems(ctx context.Context, tenantID string) ([]*entity.ChecklistItem, error)
}

// ReminderScheduleRepository defines the interface for reminder scheduling
type ReminderScheduleRepository interface {
	// Schedule CRUD operations
	CreateSchedule(ctx context.Context, schedule *entity.ReminderSchedule) error
	GetScheduleByID(ctx context.Context, id string, tenantID string) (*entity.ReminderSchedule, error)
	UpdateSchedule(ctx context.Context, schedule *entity.ReminderSchedule) error
	DeleteSchedule(ctx context.Context, id string, tenantID string) error
	
	// Schedule queries
	GetSchedulesByItem(ctx context.Context, checklistItemID string, tenantID string) ([]*entity.ReminderSchedule, error)
	GetActiveSchedules(ctx context.Context, tenantID string) ([]*entity.ReminderSchedule, error)
	GetSchedulesDue(ctx context.Context, beforeTime time.Time, tenantID string) ([]*entity.ReminderSchedule, error)
	
	// Schedule management
	UpdateNextScheduledTime(ctx context.Context, scheduleID string, nextScheduledAt time.Time, remainingSends int, tenantID string) error
	DeactivateSchedule(ctx context.Context, scheduleID string, tenantID string) error
}

// CommunicationAnalyticsRepository defines the interface for analytics persistence
type CommunicationAnalyticsRepository interface {
	// Analytics CRUD operations
	CreateAnalytics(ctx context.Context, analytics *entity.CommunicationAnalytics) error
	GetAnalyticsByID(ctx context.Context, id string, tenantID string) (*entity.CommunicationAnalytics, error)
	UpdateAnalytics(ctx context.Context, analytics *entity.CommunicationAnalytics) error
	
	// Analytics queries
	GetAnalyticsByCommunication(ctx context.Context, communicationID string, tenantID string) (*entity.CommunicationAnalytics, error)
	GetAnalyticsByDateRange(ctx context.Context, startDate, endDate time.Time, tenantID string) ([]*entity.CommunicationAnalytics, error)
	GetAnalyticsByCustomer(ctx context.Context, customerProfileID string, tenantID string) ([]*entity.CommunicationAnalytics, error)
	
	// Engagement tracking
	RecordOpen(ctx context.Context, communicationID string, openedAt time.Time, deviceType, location string, tenantID string) error
	RecordClick(ctx context.Context, communicationID string, clickedAt time.Time, url, deviceType, location string, tenantID string) error
	RecordConversion(ctx context.Context, communicationID string, goalID, goalName string, value *float64, tenantID string) error
	
	// A/B Testing analytics
	GetTestResults(ctx context.Context, testGroup string, startDate, endDate time.Time, tenantID string) (*TestResults, error)
	GetConversionRates(ctx context.Context, communicationType entity.CommunicationType, startDate, endDate time.Time, tenantID string) (*ConversionRates, error)
}

// EmailProviderRepository defines the interface for email provider persistence
type EmailProviderRepository interface {
	// Provider CRUD operations
	CreateProvider(ctx context.Context, provider *entity.EmailProvider) error
	GetProviderByID(ctx context.Context, id string, tenantID string) (*entity.EmailProvider, error)
	UpdateProvider(ctx context.Context, provider *entity.EmailProvider) error
	DeleteProvider(ctx context.Context, id string, tenantID string) error
	
	// Provider queries
	ListProviders(ctx context.Context, filter ProviderFilter) ([]*entity.EmailProvider, int, error)
	GetActiveProviders(ctx context.Context, tenantID string) ([]*entity.EmailProvider, error)
	GetDefaultProvider(ctx context.Context, tenantID string) (*entity.EmailProvider, error)
	GetProviderByType(ctx context.Context, providerType string, tenantID string) (*entity.EmailProvider, error)
	
	// Provider management
	SetDefaultProvider(ctx context.Context, providerID string, tenantID string) error
	GetFallbackProvider(ctx context.Context, providerID string, tenantID string) (*entity.EmailProvider, error)
}

// Filter types for repository queries
type CommunicationFilter struct {
	TenantID             string
	CustomerProfileID    *string
	OnboardingInstanceID *string
	Type                 *entity.CommunicationType
	Status               *entity.DeliveryStatus
	DateRange            *DateRange
	CustomerTier         *string
	Language             *string
	Pagination           *Pagination
	SortBy               *SortBy
}

type TemplateFilter struct {
	TenantID       string
	Type           *entity.CommunicationType
	IsActive       *bool
	IsDefault      *bool
	Language       *string
	CustomerTiers  []string
	TestGroup      *string
	Pagination     *Pagination
	SortBy         *SortBy
}

type ChecklistFilter struct {
	TenantID             string
	CustomerProfileID    *string
	OnboardingInstanceID *string
	Status               *string
	CustomerTier         *string
	ServiceTier          *string
	DateRange            *DateRange
	Pagination           *Pagination
	SortBy               *SortBy
}

type ProviderFilter struct {
	TenantID   string
	Type       *string
	IsActive   *bool
	IsDefault  *bool
	Pagination *Pagination
	SortBy     *SortBy
}

// Common filter types
type DateRange struct {
	Start time.Time
	End   time.Time
}

type Pagination struct {
	Page   int
	Limit  int
	Offset int
}

type SortBy struct {
	Field     string
	Direction string // ASC or DESC
}

// Analytics result types
type TestResults struct {
	TestGroup        string                 `json:"test_group"`
	TotalSent        int                    `json:"total_sent"`
	TotalOpened      int                    `json:"total_opened"`
	TotalClicked     int                    `json:"total_clicked"`
	OpenRate         float64                `json:"open_rate"`
	ClickRate        float64                `json:"click_rate"`
	ClickThroughRate float64                `json:"click_through_rate"`
	ConversionRate   float64                `json:"conversion_rate"`
	Variants         []VariantResult        `json:"variants"`
}

type VariantResult struct {
	VariantID        string  `json:"variant_id"`
	Sent             int     `json:"sent"`
	Opened           int     `json:"opened"`
	Clicked          int     `json:"clicked"`
	Converted        int     `json:"converted"`
	OpenRate         float64 `json:"open_rate"`
	ClickRate        float64 `json:"click_rate"`
	ConversionRate   float64 `json:"conversion_rate"`
}

type ConversionRates struct {
	CommunicationType entity.CommunicationType `json:"communication_type"`
	TotalSent         int                      `json:"total_sent"`
	TotalOpened       int                      `json:"total_opened"`
	TotalClicked      int                      `json:"total_clicked"`
	TotalConverted    int                      `json:"total_converted"`
	OpenRate          float64                  `json:"open_rate"`
	ClickRate         float64                  `json:"click_rate"`
	ConversionRate    float64                  `json:"conversion_rate"`
	ByCustomerTier    map[string]ConversionTierData `json:"by_customer_tier"`
}

type ConversionTierData struct {
	Sent           int     `json:"sent"`
	Opened         int     `json:"opened"`
	Clicked        int     `json:"clicked"`
	Converted      int     `json:"converted"`
	OpenRate       float64 `json:"open_rate"`
	ClickRate      float64 `json:"click_rate"`
	ConversionRate float64 `json:"conversion_rate"`
}