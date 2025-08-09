package usecase

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/isectech/protect/backend/services/communication-service/domain/entity"
	"github.com/isectech/protect/backend/services/communication-service/domain/repository"
	"github.com/isectech/protect/backend/services/communication-service/domain/service"
	"github.com/isectech/protect/backend/services/communication-service/infrastructure/email"
)

// CommunicationServiceImpl implements the CommunicationService interface
type CommunicationServiceImpl struct {
	communicationRepo repository.CommunicationRepository
	templateRepo      repository.CommunicationTemplateRepository
	providerRepo      repository.EmailProviderRepository
	analyticsRepo     repository.CommunicationAnalyticsRepository
	emailFactory      *email.EmailServiceFactory
	logger           *log.Logger
}

// NewCommunicationServiceImpl creates a new communication service implementation
func NewCommunicationServiceImpl(
	communicationRepo repository.CommunicationRepository,
	templateRepo repository.CommunicationTemplateRepository,
	providerRepo repository.EmailProviderRepository,
	analyticsRepo repository.CommunicationAnalyticsRepository,
	emailFactory *email.EmailServiceFactory,
	logger *log.Logger,
) *CommunicationServiceImpl {
	return &CommunicationServiceImpl{
		communicationRepo: communicationRepo,
		templateRepo:      templateRepo,
		providerRepo:      providerRepo,
		analyticsRepo:     analyticsRepo,
		emailFactory:      emailFactory,
		logger:           logger,
	}
}

// SendWelcomeEmail sends a welcome email to a new customer
func (s *CommunicationServiceImpl) SendWelcomeEmail(ctx context.Context, request *service.WelcomeEmailRequest) (*service.CommunicationResult, error) {
	// Get or create welcome email template
	template, err := s.templateRepo.GetTemplateByType(ctx, entity.CommunicationTypeWelcome, request.TenantID, &request.CustomerTier)
	if err != nil {
		return nil, fmt.Errorf("failed to get welcome template: %w", err)
	}

	// Create communication record
	communication := &entity.Communication{
		ID:                s.generateID("comm"),
		Type:              entity.CommunicationTypeWelcome,
		CustomerProfileID: request.CustomerProfileID,
		RecipientEmail:    request.RecipientEmail,
		RecipientName:     request.RecipientName,
		TemplateID:        template.ID,
		TemplateVersion:   template.Version,
		Variables:         request.Variables,
		Language:          request.Language,
		Timezone:          request.Timezone,
		CustomerTier:      request.CustomerTier,
		ScheduledAt:       request.ScheduledAt,
		Status:            entity.DeliveryStatusPending,
		TenantID:         request.TenantID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		CreatedBy:        "system",
	}

	// Save communication
	if err := s.communicationRepo.CreateCommunication(ctx, communication); err != nil {
		return nil, fmt.Errorf("failed to create communication: %w", err)
	}

	// Process communication (send immediately or schedule)
	if request.ScheduledAt == nil || request.ScheduledAt.Before(time.Now().Add(5*time.Minute)) {
		return s.processCommunication(ctx, communication)
	}

	// Update status to scheduled
	communication.Status = entity.DeliveryStatusScheduled
	if err := s.communicationRepo.UpdateCommunication(ctx, communication); err != nil {
		s.logger.Printf("Failed to update communication status to scheduled: %v", err)
	}

	return &service.CommunicationResult{
		CommunicationID: communication.ID,
		Status:          "scheduled",
		ScheduledAt:     request.ScheduledAt,
	}, nil
}

// SendOnboardingStepNotification sends a notification for an onboarding step
func (s *CommunicationServiceImpl) SendOnboardingStepNotification(ctx context.Context, request *service.OnboardingStepRequest) (*service.CommunicationResult, error) {
	// Get template
	template, err := s.templateRepo.GetTemplateByType(ctx, entity.CommunicationTypeOnboardingStep, request.TenantID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get onboarding step template: %w", err)
	}

	// Merge variables with onboarding-specific data
	variables := make(map[string]interface{})
	for k, v := range request.Variables {
		variables[k] = v
	}
	variables["step_name"] = request.StepName
	variables["step_description"] = request.StepDescription
	variables["action_url"] = request.ActionURL
	variables["due_date"] = request.DueDate

	// Create communication
	communication := &entity.Communication{
		ID:                   s.generateID("comm"),
		Type:                 entity.CommunicationTypeOnboardingStep,
		CustomerProfileID:    request.CustomerProfileID,
		OnboardingInstanceID: &request.OnboardingInstanceID,
		RecipientEmail:       request.RecipientEmail,
		RecipientName:        request.RecipientName,
		Subject:             fmt.Sprintf("Next Step: %s", request.StepName),
		TemplateID:          template.ID,
		TemplateVersion:     template.Version,
		Variables:           variables,
		Status:              entity.DeliveryStatusPending,
		TenantID:           request.TenantID,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		CreatedBy:          "system",
	}

	if err := s.communicationRepo.CreateCommunication(ctx, communication); err != nil {
		return nil, fmt.Errorf("failed to create communication: %w", err)
	}

	return s.processCommunication(ctx, communication)
}

// SendOnboardingReminder sends a reminder for incomplete onboarding steps
func (s *CommunicationServiceImpl) SendOnboardingReminder(ctx context.Context, request *service.OnboardingReminderRequest) (*service.CommunicationResult, error) {
	template, err := s.templateRepo.GetTemplateByType(ctx, entity.CommunicationTypeReminder, request.TenantID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get reminder template: %w", err)
	}

	// Merge variables
	variables := make(map[string]interface{})
	for k, v := range request.Variables {
		variables[k] = v
	}
	variables["reminder_type"] = request.ReminderType
	variables["pending_steps"] = request.PendingSteps
	variables["pending_steps_count"] = len(request.PendingSteps)

	communication := &entity.Communication{
		ID:                   s.generateID("comm"),
		Type:                 entity.CommunicationTypeReminder,
		CustomerProfileID:    request.CustomerProfileID,
		OnboardingInstanceID: &request.OnboardingInstanceID,
		RecipientEmail:       request.RecipientEmail,
		RecipientName:        request.RecipientName,
		Subject:             "Reminder: Complete Your Onboarding",
		TemplateID:          template.ID,
		TemplateVersion:     template.Version,
		Variables:           variables,
		Status:              entity.DeliveryStatusPending,
		TenantID:           request.TenantID,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		CreatedBy:          "system",
	}

	if err := s.communicationRepo.CreateCommunication(ctx, communication); err != nil {
		return nil, fmt.Errorf("failed to create communication: %w", err)
	}

	return s.processCommunication(ctx, communication)
}

// SendChecklistItemReminder sends a reminder for an incomplete checklist item
func (s *CommunicationServiceImpl) SendChecklistItemReminder(ctx context.Context, request *service.ChecklistReminderRequest) (*service.CommunicationResult, error) {
	template, err := s.templateRepo.GetTemplateByType(ctx, entity.CommunicationTypeChecklistItem, request.TenantID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get checklist item template: %w", err)
	}

	// Merge variables
	variables := make(map[string]interface{})
	for k, v := range request.Variables {
		variables[k] = v
	}
	variables["item_title"] = request.ItemTitle
	variables["item_description"] = request.ItemDescription
	variables["action_url"] = request.ActionURL
	variables["due_date"] = request.DueDate

	communication := &entity.Communication{
		ID:                s.generateID("comm"),
		Type:              entity.CommunicationTypeChecklistItem,
		CustomerProfileID: request.CustomerProfileID,
		ChecklistID:       &request.ChecklistID,
		RecipientEmail:    request.RecipientEmail,
		RecipientName:     request.RecipientName,
		Subject:          fmt.Sprintf("Reminder: %s", request.ItemTitle),
		TemplateID:       template.ID,
		TemplateVersion:  template.Version,
		Variables:        variables,
		Status:           entity.DeliveryStatusPending,
		TenantID:        request.TenantID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		CreatedBy:       "system",
	}

	if err := s.communicationRepo.CreateCommunication(ctx, communication); err != nil {
		return nil, fmt.Errorf("failed to create communication: %w", err)
	}

	return s.processCommunication(ctx, communication)
}

// SendChecklistCompletionNotification sends a notification when a checklist is completed
func (s *CommunicationServiceImpl) SendChecklistCompletionNotification(ctx context.Context, request *service.ChecklistCompletionRequest) (*service.CommunicationResult, error) {
	template, err := s.templateRepo.GetTemplateByType(ctx, entity.CommunicationTypeCompletion, request.TenantID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get completion template: %w", err)
	}

	// Merge variables
	variables := make(map[string]interface{})
	for k, v := range request.Variables {
		variables[k] = v
	}
	variables["total_items"] = request.TotalItems
	variables["completed_items"] = request.CompletedItems
	variables["completion_date"] = request.CompletedAt
	variables["next_steps"] = request.NextSteps

	communication := &entity.Communication{
		ID:                s.generateID("comm"),
		Type:              entity.CommunicationTypeCompletion,
		CustomerProfileID: request.CustomerProfileID,
		ChecklistID:       &request.ChecklistID,
		RecipientEmail:    request.RecipientEmail,
		RecipientName:     request.RecipientName,
		Subject:          "Congratulations! Onboarding Complete",
		TemplateID:       template.ID,
		TemplateVersion:  template.Version,
		Variables:        variables,
		Status:           entity.DeliveryStatusPending,
		TenantID:        request.TenantID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		CreatedBy:       "system",
	}

	if err := s.communicationRepo.CreateCommunication(ctx, communication); err != nil {
		return nil, fmt.Errorf("failed to create communication: %w", err)
	}

	return s.processCommunication(ctx, communication)
}

// ScheduleCommunication schedules a communication for future delivery
func (s *CommunicationServiceImpl) ScheduleCommunication(ctx context.Context, request *service.ScheduleCommunicationRequest) (*entity.Communication, error) {
	// Get template
	template, err := s.templateRepo.GetTemplateByType(ctx, request.Type, request.TenantID, &request.CustomerTier)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Use specified template if provided
	if request.TemplateID != nil {
		template, err = s.templateRepo.GetTemplateByID(ctx, *request.TemplateID, request.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to get specified template: %w", err)
		}
	}

	communication := &entity.Communication{
		ID:                s.generateID("comm"),
		Type:              request.Type,
		CustomerProfileID: request.CustomerProfileID,
		RecipientEmail:    request.RecipientEmail,
		RecipientName:     request.RecipientName,
		TemplateID:        template.ID,
		TemplateVersion:   template.Version,
		Variables:         request.Variables,
		Language:          request.Language,
		Timezone:          request.Timezone,
		CustomerTier:      request.CustomerTier,
		ScheduledAt:       &request.ScheduledAt,
		Status:            entity.DeliveryStatusScheduled,
		TenantID:         request.TenantID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		CreatedBy:        "system",
	}

	if err := s.communicationRepo.CreateCommunication(ctx, communication); err != nil {
		return nil, fmt.Errorf("failed to create scheduled communication: %w", err)
	}

	return communication, nil
}

// CancelScheduledCommunication cancels a scheduled communication
func (s *CommunicationServiceImpl) CancelScheduledCommunication(ctx context.Context, communicationID, tenantID string) error {
	communication, err := s.communicationRepo.GetCommunicationByID(ctx, communicationID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get communication: %w", err)
	}

	if communication.Status != entity.DeliveryStatusScheduled {
		return fmt.Errorf("communication %s is not scheduled (status: %s)", communicationID, communication.Status)
	}

	return s.communicationRepo.DeleteCommunication(ctx, communicationID, tenantID)
}

// RetryCommunication retries a failed communication
func (s *CommunicationServiceImpl) RetryCommunication(ctx context.Context, communicationID, tenantID string) (*service.CommunicationResult, error) {
	communication, err := s.communicationRepo.GetCommunicationByID(ctx, communicationID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get communication: %w", err)
	}

	if communication.Status != entity.DeliveryStatusFailed {
		return nil, fmt.Errorf("communication %s is not failed (status: %s)", communicationID, communication.Status)
	}

	// Reset status and retry
	communication.Status = entity.DeliveryStatusPending
	communication.ErrorMessage = nil
	communication.UpdatedAt = time.Now()

	if err := s.communicationRepo.UpdateCommunication(ctx, communication); err != nil {
		return nil, fmt.Errorf("failed to update communication for retry: %w", err)
	}

	return s.processCommunication(ctx, communication)
}

// SendBulkCommunications sends multiple communications in batches
func (s *CommunicationServiceImpl) SendBulkCommunications(ctx context.Context, request *service.BulkCommunicationRequest) (*service.BulkCommunicationResult, error) {
	result := &service.BulkCommunicationResult{
		TotalRequested: len(request.Recipients),
		BatchID:        s.generateID("batch"),
	}

	// Get template
	var template *entity.CommunicationTemplate
	var err error

	if request.TemplateID != nil {
		template, err = s.templateRepo.GetTemplateByID(ctx, *request.TemplateID, request.TenantID)
	} else {
		// Use default template for the communication type
		template, err = s.templateRepo.GetTemplateByType(ctx, request.Type, request.TenantID, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Process recipients in batches
	batchSize := request.BatchSize
	if batchSize <= 0 {
		batchSize = 100 // Default batch size
	}

	for i := 0; i < len(request.Recipients); i += batchSize {
		end := i + batchSize
		if end > len(request.Recipients) {
			end = len(request.Recipients)
		}

		batch := request.Recipients[i:end]
		for _, recipient := range batch {
			communication := &entity.Communication{
				ID:                s.generateID("comm"),
				Type:              request.Type,
				CustomerProfileID: recipient.CustomerProfileID,
				RecipientEmail:    recipient.RecipientEmail,
				RecipientName:     recipient.RecipientName,
				TemplateID:        template.ID,
				TemplateVersion:   template.Version,
				Variables:         recipient.Variables,
				Language:          recipient.Language,
				Timezone:          recipient.Timezone,
				CustomerTier:      recipient.CustomerTier,
				ScheduledAt:       request.ScheduledAt,
				Status:            entity.DeliveryStatusPending,
				TenantID:         request.TenantID,
				CreatedAt:        time.Now(),
				UpdatedAt:        time.Now(),
				CreatedBy:        "system",
			}

			if request.ScheduledAt != nil && request.ScheduledAt.After(time.Now()) {
				communication.Status = entity.DeliveryStatusScheduled
			}

			if err := s.communicationRepo.CreateCommunication(ctx, communication); err != nil {
				result.TotalFailed++
				result.Errors = append(result.Errors, service.BulkCommunicationError{
					RecipientEmail: recipient.RecipientEmail,
					Error:          err.Error(),
				})
				continue
			}

			if communication.Status == entity.DeliveryStatusPending {
				commResult, err := s.processCommunication(ctx, communication)
				if err != nil {
					result.TotalFailed++
					result.Errors = append(result.Errors, service.BulkCommunicationError{
						RecipientEmail: recipient.RecipientEmail,
						Error:          err.Error(),
					})
				} else {
					result.Results = append(result.Results, *commResult)
					result.TotalScheduled++
				}
			} else {
				result.TotalScheduled++
				result.Results = append(result.Results, service.CommunicationResult{
					CommunicationID: communication.ID,
					Status:          "scheduled",
					ScheduledAt:     request.ScheduledAt,
				})
			}
		}

		// Add delay between batches if specified
		if request.DelayBetweenBatches > 0 && end < len(request.Recipients) {
			time.Sleep(request.DelayBetweenBatches)
		}
	}

	return result, nil
}

// GetCommunication retrieves a communication by ID
func (s *CommunicationServiceImpl) GetCommunication(ctx context.Context, communicationID, tenantID string) (*entity.Communication, error) {
	return s.communicationRepo.GetCommunicationByID(ctx, communicationID, tenantID)
}

// ListCommunications lists communications with filtering and pagination
func (s *CommunicationServiceImpl) ListCommunications(ctx context.Context, filter *service.CommunicationFilter) (*service.CommunicationListResult, error) {
	repoFilter := repository.CommunicationFilter{
		TenantID:             filter.TenantID,
		CustomerProfileID:    filter.CustomerProfileID,
		OnboardingInstanceID: filter.OnboardingInstanceID,
		Type:                 filter.Type,
		Status:               filter.Status,
		DateRange:            (*repository.DateRange)(filter.DateRange),
		CustomerTier:         filter.CustomerTier,
		Language:             filter.Language,
		Pagination: &repository.Pagination{
			Page:   filter.Page,
			Limit:  filter.Limit,
			Offset: (filter.Page - 1) * filter.Limit,
		},
		SortBy: &repository.SortBy{
			Field:     filter.SortBy,
			Direction: filter.SortDirection,
		},
	}

	communications, total, err := s.communicationRepo.ListCommunications(ctx, repoFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list communications: %w", err)
	}

	return &service.CommunicationListResult{
		Communications: communications,
		Total:          total,
		Page:           filter.Page,
		Limit:          filter.Limit,
		HasMore:        (filter.Page * filter.Limit) < total,
	}, nil
}

// GetCommunicationHistory retrieves communication history for a customer
func (s *CommunicationServiceImpl) GetCommunicationHistory(ctx context.Context, customerProfileID, tenantID string) ([]*entity.Communication, error) {
	return s.communicationRepo.GetCommunicationsByCustomer(ctx, customerProfileID, tenantID)
}

// GetEngagementMetrics retrieves engagement metrics for communications
func (s *CommunicationServiceImpl) GetEngagementMetrics(ctx context.Context, request *service.EngagementMetricsRequest) (*service.EngagementMetrics, error) {
	// This would implement complex analytics queries
	// For now, return placeholder metrics
	return &service.EngagementMetrics{
		TotalSent:        1000,
		TotalDelivered:   950,
		TotalOpened:      380,
		TotalClicked:     95,
		DeliveryRate:     95.0,
		OpenRate:         40.0,
		ClickRate:        10.0,
		ClickThroughRate: 25.0,
	}, nil
}

// GetCommunicationAnalytics retrieves detailed communication analytics
func (s *CommunicationServiceImpl) GetCommunicationAnalytics(ctx context.Context, request *service.AnalyticsRequest) (*service.CommunicationAnalytics, error) {
	// This would implement complex analytics queries
	// For now, return placeholder data
	return &service.CommunicationAnalytics{
		TotalMetrics: service.EngagementMetrics{
			TotalSent:      1000,
			TotalDelivered: 950,
			TotalOpened:    380,
			TotalClicked:   95,
			DeliveryRate:   95.0,
			OpenRate:       40.0,
			ClickRate:      10.0,
		},
		GroupedMetrics: make(map[string]service.EngagementMetrics),
		TrendData:      []service.TrendDataPoint{},
	}, nil
}

// CreateABTest creates a new A/B test for communication templates
func (s *CommunicationServiceImpl) CreateABTest(ctx context.Context, request *service.ABTestRequest) (*service.ABTest, error) {
	// A/B testing implementation would go here
	// For now, return placeholder
	return &service.ABTest{
		ID:                request.Name,
		Name:              request.Name,
		Description:       request.Description,
		CommunicationType: request.CommunicationType,
		Status:           "draft",
		CreatedAt:        time.Now(),
		CreatedBy:        request.CreatedBy,
	}, nil
}

// GetABTestResults retrieves results for an A/B test
func (s *CommunicationServiceImpl) GetABTestResults(ctx context.Context, testID, tenantID string) (*service.ABTestResults, error) {
	// A/B test results implementation would go here
	// For now, return placeholder
	return &service.ABTestResults{
		TestID:            testID,
		Status:           "active",
		TotalParticipants: 1000,
		Results:          []service.ABTestVariantResult{},
	}, nil
}

// Private helper methods

// processCommunication processes a communication for immediate delivery
func (s *CommunicationServiceImpl) processCommunication(ctx context.Context, communication *entity.Communication) (*service.CommunicationResult, error) {
	// Get template
	template, err := s.templateRepo.GetTemplateByID(ctx, communication.TemplateID, communication.TenantID)
	if err != nil {
		return s.handleCommunicationError(ctx, communication, fmt.Errorf("failed to get template: %w", err))
	}

	// Render content
	renderedContent, err := s.renderTemplate(ctx, template, communication)
	if err != nil {
		return s.handleCommunicationError(ctx, communication, fmt.Errorf("failed to render template: %w", err))
	}

	// Get email provider
	provider, err := s.providerRepo.GetDefaultProvider(ctx, communication.TenantID)
	if err != nil {
		return s.handleCommunicationError(ctx, communication, fmt.Errorf("failed to get email provider: %w", err))
	}

	// Create email service
	emailService, err := s.emailFactory.CreateEmailService(provider)
	if err != nil {
		return s.handleCommunicationError(ctx, communication, fmt.Errorf("failed to create email service: %w", err))
	}

	// Send email
	emailRequest := &email.SendEmailRequest{
		From: email.EmailAddress{
			Email: "noreply@isectech.com", // TODO: Get from configuration
			Name:  "iSECTECH Protect",
		},
		To: []email.EmailAddress{
			{
				Email: communication.RecipientEmail,
				Name:  communication.RecipientName,
			},
		},
		Subject:     renderedContent.Subject,
		HTMLContent: renderedContent.HTMLContent,
		TextContent: renderedContent.TextContent,
		TrackOpens:  true,
		TrackClicks: true,
		TenantID:    communication.TenantID,
	}

	emailResponse, err := emailService.SendEmail(ctx, emailRequest)
	if err != nil {
		return s.handleCommunicationError(ctx, communication, fmt.Errorf("failed to send email: %w", err))
	}

	if emailResponse.Error != nil {
		return s.handleCommunicationError(ctx, communication, fmt.Errorf("email sending failed: %s", *emailResponse.Error))
	}

	// Update communication with success
	communication.Status = entity.DeliveryStatusSent
	communication.ProviderMessageID = &emailResponse.ProviderMessageID
	communication.EmailProvider = emailService.GetProviderType()
	now := time.Now()
	communication.SentAt = &now
	communication.UpdatedAt = now

	if err := s.communicationRepo.UpdateCommunication(ctx, communication); err != nil {
		s.logger.Printf("Failed to update communication after successful send: %v", err)
	}

	// Create analytics record
	analytics := &entity.CommunicationAnalytics{
		ID:               s.generateID("analytics"),
		CommunicationID:  communication.ID,
		TenantID:        communication.TenantID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := s.analyticsRepo.CreateAnalytics(ctx, analytics); err != nil {
		s.logger.Printf("Failed to create analytics record: %v", err)
	}

	return &service.CommunicationResult{
		CommunicationID:   communication.ID,
		Status:            "sent",
		ProviderMessageID: &emailResponse.ProviderMessageID,
		SentAt:            communication.SentAt,
	}, nil
}

// handleCommunicationError handles errors during communication processing
func (s *CommunicationServiceImpl) handleCommunicationError(ctx context.Context, communication *entity.Communication, err error) (*service.CommunicationResult, error) {
	errorMsg := err.Error()
	communication.Status = entity.DeliveryStatusFailed
	communication.ErrorMessage = &errorMsg
	communication.AttemptCount++
	now := time.Now()
	communication.LastAttemptAt = &now
	communication.UpdatedAt = now

	// Schedule retry if under max attempts
	maxAttempts := 3
	if communication.AttemptCount < maxAttempts {
		// Exponential backoff: 1 hour, 4 hours, 16 hours
		retryDelay := time.Duration(1<<uint(communication.AttemptCount-1)) * time.Hour
		nextRetry := now.Add(retryDelay)
		communication.NextRetryAt = &nextRetry
	}

	if updateErr := s.communicationRepo.UpdateCommunication(ctx, communication); updateErr != nil {
		s.logger.Printf("Failed to update communication after error: %v", updateErr)
	}

	return &service.CommunicationResult{
		CommunicationID: communication.ID,
		Status:          "failed",
		Error:           &errorMsg,
	}, nil
}

// renderTemplate renders a communication template with variables
func (s *CommunicationServiceImpl) renderTemplate(ctx context.Context, template *entity.CommunicationTemplate, communication *entity.Communication) (*entity.RenderedContent, error) {
	// Simple variable substitution - in production, use a proper template engine
	subject := s.substituteVariables(template.SubjectTemplate, communication.Variables)
	htmlContent := s.substituteVariables(template.HTMLTemplate, communication.Variables)
	textContent := s.substituteVariables(template.TextTemplate, communication.Variables)

	return &entity.RenderedContent{
		Subject:     subject,
		HTMLContent: htmlContent,
		TextContent: textContent,
	}, nil
}

// substituteVariables performs simple variable substitution
func (s *CommunicationServiceImpl) substituteVariables(template string, variables map[string]interface{}) string {
	result := template
	for key, value := range variables {
		placeholder := fmt.Sprintf("{{%s}}", key)
		result = strings.ReplaceAll(result, placeholder, fmt.Sprintf("%v", value))
	}
	return result
}

// generateID generates a unique ID with prefix
func (s *CommunicationServiceImpl) generateID(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), time.Now().UnixNano()%1000)
}