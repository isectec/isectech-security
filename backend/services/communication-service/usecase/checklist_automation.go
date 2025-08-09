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
)

// ChecklistAutomationService handles automated checklist creation, progress tracking, and reminder scheduling
type ChecklistAutomationService struct {
	checklistRepo           repository.ChecklistRepository
	checklistItemRepo       repository.ChecklistItemRepository
	reminderScheduleRepo    repository.ReminderScheduleRepository
	communicationService    service.CommunicationService
	logger                 *log.Logger
}

// NewChecklistAutomationService creates a new checklist automation service
func NewChecklistAutomationService(
	checklistRepo repository.ChecklistRepository,
	checklistItemRepo repository.ChecklistItemRepository,
	reminderScheduleRepo repository.ReminderScheduleRepository,
	communicationService service.CommunicationService,
	logger *log.Logger,
) *ChecklistAutomationService {
	return &ChecklistAutomationService{
		checklistRepo:        checklistRepo,
		checklistItemRepo:    checklistItemRepo,
		reminderScheduleRepo: reminderScheduleRepo,
		communicationService: communicationService,
		logger:              logger,
	}
}

// CreateOnboardingChecklistFromTemplate creates a dynamic onboarding checklist based on customer tier and services
func (s *ChecklistAutomationService) CreateOnboardingChecklistFromTemplate(
	ctx context.Context,
	request *CreateChecklistFromTemplateRequest,
) (*entity.OnboardingChecklist, error) {
	// Generate checklist items based on customer tier and selected services
	items, err := s.generateChecklistItems(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to generate checklist items: %w", err)
	}

	// Create the checklist
	checklist := &entity.OnboardingChecklist{
		ID:                   s.generateID("checklist"),
		CustomerProfileID:    request.CustomerProfileID,
		OnboardingInstanceID: request.OnboardingInstanceID,
		Title:                s.generateChecklistTitle(request.CustomerTier, request.ServiceTier),
		Description:          s.generateChecklistDescription(request.CustomerTier, request.ServiceTier, request.SelectedServices),
		CustomerTier:         request.CustomerTier,
		ServiceTier:          request.ServiceTier,
		TotalItems:          len(items),
		CompletedItems:      0,
		PercentComplete:     0.0,
		Status:              "pending",
		TenantID:            request.TenantID,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		DueAt:               s.calculateDueDate(request.CustomerTier, request.ServiceTier),
	}

	// Save the checklist
	if err := s.checklistRepo.CreateChecklist(ctx, checklist); err != nil {
		return nil, fmt.Errorf("failed to create checklist: %w", err)
	}

	// Create checklist items
	for _, item := range items {
		item.ChecklistID = checklist.ID
		item.CreatedAt = time.Now()
		item.UpdatedAt = time.Now()

		if err := s.checklistItemRepo.CreateItem(ctx, item); err != nil {
			s.logger.Printf("Failed to create checklist item %s: %v", item.Title, err)
			continue
		}

		// Schedule reminders for this item
		if err := s.scheduleItemReminders(ctx, item); err != nil {
			s.logger.Printf("Failed to schedule reminders for item %s: %v", item.ID, err)
		}
	}

	checklist.Items = items
	return checklist, nil
}

// ProcessPendingReminders processes all due reminders and sends notifications
func (s *ChecklistAutomationService) ProcessPendingReminders(ctx context.Context, tenantID string) (*service.ReminderProcessResult, error) {
	dueSchedules, err := s.reminderScheduleRepo.GetSchedulesDue(ctx, time.Now(), tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get due reminder schedules: %w", err)
	}

	result := &service.ReminderProcessResult{
		ProcessedCount: len(dueSchedules),
	}

	for _, schedule := range dueSchedules {
		if err := s.processSingleReminder(ctx, schedule); err != nil {
			result.FailedCount++
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to process reminder %s: %v", schedule.ID, err))
			continue
		}
		result.SentCount++
	}

	return result, nil
}

// UpdateChecklistProgress updates checklist progress when items are completed
func (s *ChecklistAutomationService) UpdateChecklistProgress(ctx context.Context, checklistID, tenantID string) error {
	checklist, err := s.checklistRepo.GetChecklistByID(ctx, checklistID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get checklist: %w", err)
	}

	items, err := s.checklistItemRepo.GetItemsByChecklist(ctx, checklistID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get checklist items: %w", err)
	}

	completedItems := 0
	for _, item := range items {
		if item.IsCompleted {
			completedItems++
		}
	}

	percentComplete := 0.0
	if len(items) > 0 {
		percentComplete = float64(completedItems) / float64(len(items)) * 100.0
	}

	// Update checklist progress
	if err := s.checklistRepo.UpdateChecklistProgress(ctx, checklistID, completedItems, percentComplete, tenantID); err != nil {
		return fmt.Errorf("failed to update checklist progress: %w", err)
	}

	// Check if checklist is completed
	if completedItems == len(items) && checklist.Status != "completed" {
		if err := s.completeChecklist(ctx, checklist); err != nil {
			return fmt.Errorf("failed to complete checklist: %w", err)
		}
	}

	return nil
}

// CompleteChecklistItem marks an item as completed and updates dependencies
func (s *ChecklistAutomationService) CompleteChecklistItem(ctx context.Context, itemID, completedBy, tenantID string, notes *string) error {
	// Complete the item
	if err := s.checklistItemRepo.CompleteItem(ctx, itemID, completedBy, notes, tenantID); err != nil {
		return fmt.Errorf("failed to complete checklist item: %w", err)
	}

	// Get the item to find its checklist
	item, err := s.checklistItemRepo.GetItemByID(ctx, itemID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get checklist item: %w", err)
	}

	// Update checklist progress
	if err := s.UpdateChecklistProgress(ctx, item.ChecklistID, tenantID); err != nil {
		return fmt.Errorf("failed to update checklist progress: %w", err)
	}

	// Deactivate reminders for this item
	schedules, err := s.reminderScheduleRepo.GetSchedulesByItem(ctx, itemID, tenantID)
	if err != nil {
		s.logger.Printf("Failed to get reminder schedules for item %s: %v", itemID, err)
	} else {
		for _, schedule := range schedules {
			if err := s.reminderScheduleRepo.DeactivateSchedule(ctx, schedule.ID, tenantID); err != nil {
				s.logger.Printf("Failed to deactivate reminder schedule %s: %v", schedule.ID, err)
			}
		}
	}

	// Check if dependent items can now be unlocked
	dependentItems, err := s.checklistItemRepo.GetDependentItems(ctx, itemID, tenantID)
	if err != nil {
		s.logger.Printf("Failed to get dependent items for %s: %v", itemID, err)
	} else {
		for _, depItem := range dependentItems {
			s.checkItemDependencies(ctx, depItem)
		}
	}

	return nil
}

// ScheduleChecklistReminders schedules all reminders for a checklist
func (s *ChecklistAutomationService) ScheduleChecklistReminders(ctx context.Context, checklistID, tenantID string) error {
	items, err := s.checklistItemRepo.GetItemsByChecklist(ctx, checklistID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get checklist items: %w", err)
	}

	for _, item := range items {
		if err := s.scheduleItemReminders(ctx, item); err != nil {
			s.logger.Printf("Failed to schedule reminders for item %s: %v", item.ID, err)
		}
	}

	return nil
}

// Private helper methods

func (s *ChecklistAutomationService) generateChecklistItems(ctx context.Context, request *CreateChecklistFromTemplateRequest) ([]*entity.ChecklistItem, error) {
	var items []*entity.ChecklistItem
	order := 1

	// Base onboarding items for all customers
	baseItems := s.getBaseOnboardingItems(request, &order)
	items = append(items, baseItems...)

	// Service-specific items
	serviceItems := s.getServiceSpecificItems(request, &order)
	items = append(items, serviceItems...)

	// Tier-specific items
	tierItems := s.getTierSpecificItems(request, &order)
	items = append(items, tierItems...)

	// Compliance and security items based on requirements
	complianceItems := s.getComplianceItems(request, &order)
	items = append(items, complianceItems...)

	// Set up dependencies
	s.setupItemDependencies(items)

	return items, nil
}

func (s *ChecklistAutomationService) getBaseOnboardingItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	items := []*entity.ChecklistItem{
		{
			ID:                   s.generateID("item"),
			Title:                "Complete Account Setup",
			Description:          "Verify your account information and complete your profile",
			Instructions:         "Review and update your company profile, contact information, and billing details",
			Order:                *order,
			IsRequired:           true,
			Category:             "account",
			EstimatedDuration:    15,
			RequiresVerification: true,
			ReminderSchedule:     s.getDefaultReminderSchedule(),
		},
		{
			ID:                   s.generateID("item"),
			Title:                "Review Security Policies",
			Description:          "Read and acknowledge security policies and terms of service",
			Instructions:         "Carefully review our security policies and terms of service, then acknowledge acceptance",
			Order:                *order + 1,
			IsRequired:           true,
			Category:             "compliance",
			EstimatedDuration:    20,
			RequiresVerification: false,
			ReminderSchedule:     s.getDefaultReminderSchedule(),
		},
		{
			ID:                   s.generateID("item"),
			Title:                "Configure User Roles",
			Description:          "Set up user roles and permissions for your organization",
			Instructions:         "Define user roles and assign appropriate permissions based on job functions",
			Order:                *order + 2,
			IsRequired:           true,
			Category:             "access",
			EstimatedDuration:    30,
			RequiresVerification: true,
			ReminderSchedule:     s.getDefaultReminderSchedule(),
		},
	}

	*order += len(items)
	return items
}

func (s *ChecklistAutomationService) getServiceSpecificItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	var items []*entity.ChecklistItem

	for _, service := range request.SelectedServices {
		switch service {
		case "siem":
			items = append(items, s.getSIEMOnboardingItems(request, order)...)
		case "soar":
			items = append(items, s.getSOAROnboardingItems(request, order)...)
		case "vulnerability-management":
			items = append(items, s.getVulnManagementItems(request, order)...)
		case "threat-intelligence":
			items = append(items, s.getThreatIntelItems(request, order)...)
		}
	}

	return items
}

func (s *ChecklistAutomationService) getSIEMOnboardingItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	items := []*entity.ChecklistItem{
		{
			ID:                   s.generateID("item"),
			Title:                "Configure SIEM Data Sources",
			Description:          "Set up log collection from your critical systems",
			Instructions:         "Configure agents and connectors to collect security logs from firewalls, servers, and applications",
			Order:                *order,
			IsRequired:           true,
			Category:             "siem",
			EstimatedDuration:    60,
			RequiresVerification: true,
			ReminderSchedule:     s.getServiceReminderSchedule(),
		},
		{
			ID:                   s.generateID("item"),
			Title:                "Set Up SIEM Dashboards",
			Description:          "Customize security monitoring dashboards",
			Instructions:         "Configure dashboards to monitor key security metrics and create custom views for your SOC team",
			Order:                *order + 1,
			IsRequired:           false,
			Category:             "siem",
			EstimatedDuration:    45,
			RequiresVerification: false,
			ReminderSchedule:     s.getServiceReminderSchedule(),
		},
	}

	*order += len(items)
	return items
}

func (s *ChecklistAutomationService) getSOAROnboardingItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	items := []*entity.ChecklistItem{
		{
			ID:                   s.generateID("item"),
			Title:                "Configure SOAR Playbooks",
			Description:          "Set up automated response playbooks",
			Instructions:         "Configure incident response playbooks for common security scenarios",
			Order:                *order,
			IsRequired:           true,
			Category:             "soar",
			EstimatedDuration:    90,
			RequiresVerification: true,
			ReminderSchedule:     s.getServiceReminderSchedule(),
		},
	}

	*order += len(items)
	return items
}

func (s *ChecklistAutomationService) getVulnManagementItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	items := []*entity.ChecklistItem{
		{
			ID:                   s.generateID("item"),
			Title:                "Schedule Vulnerability Scans",
			Description:          "Configure automated vulnerability scanning schedules",
			Instructions:         "Set up regular vulnerability scans for your network and applications",
			Order:                *order,
			IsRequired:           true,
			Category:             "vulnerability",
			EstimatedDuration:    30,
			RequiresVerification: true,
			ReminderSchedule:     s.getServiceReminderSchedule(),
		},
	}

	*order += len(items)
	return items
}

func (s *ChecklistAutomationService) getThreatIntelItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	items := []*entity.ChecklistItem{
		{
			ID:                   s.generateID("item"),
			Title:                "Configure Threat Intelligence Feeds",
			Description:          "Set up threat intelligence data sources",
			Instructions:         "Configure external threat intelligence feeds and internal IOC management",
			Order:                *order,
			IsRequired:           true,
			Category:             "threat-intel",
			EstimatedDuration:    45,
			RequiresVerification: true,
			ReminderSchedule:     s.getServiceReminderSchedule(),
		},
	}

	*order += len(items)
	return items
}

func (s *ChecklistAutomationService) getTierSpecificItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	var items []*entity.ChecklistItem

	switch request.CustomerTier {
	case "enterprise", "enterprise-plus":
		items = append(items, &entity.ChecklistItem{
			ID:                   s.generateID("item"),
			Title:                "Schedule Executive Briefing",
			Description:          "Schedule briefing with security executives",
			Instructions:         "Coordinate with our executive team for a comprehensive security briefing and Q&A session",
			Order:                *order,
			IsRequired:           false,
			Category:             "executive",
			EstimatedDuration:    60,
			RequiresVerification: true,
			ReminderSchedule:     s.getExecutiveReminderSchedule(),
		})
		*order++

		items = append(items, &entity.ChecklistItem{
			ID:                   s.generateID("item"),
			Title:                "Assign Dedicated CSM",
			Description:          "Meet with your dedicated Customer Success Manager",
			Instructions:         "Schedule an introduction call with your assigned Customer Success Manager",
			Order:                *order,
			IsRequired:           true,
			Category:             "support",
			EstimatedDuration:    30,
			RequiresVerification: true,
			ReminderSchedule:     s.getDefaultReminderSchedule(),
		})
		*order++
	}

	return items
}

func (s *ChecklistAutomationService) getComplianceItems(request *CreateChecklistFromTemplateRequest, order *int) []*entity.ChecklistItem {
	var items []*entity.ChecklistItem

	for _, framework := range request.ComplianceFrameworks {
		switch framework {
		case "SOX":
			items = append(items, &entity.ChecklistItem{
				ID:                   s.generateID("item"),
				Title:                "Configure SOX Compliance Controls",
				Description:          "Set up SOX compliance monitoring and reporting",
				Instructions:         "Configure controls and reporting for Sarbanes-Oxley compliance requirements",
				Order:                *order,
				IsRequired:           true,
				Category:             "compliance",
				EstimatedDuration:    120,
				RequiresVerification: true,
				ReminderSchedule:     s.getComplianceReminderSchedule(),
			})
			*order++
		case "HIPAA":
			items = append(items, &entity.ChecklistItem{
				ID:                   s.generateID("item"),
				Title:                "Configure HIPAA Security Controls",
				Description:          "Set up HIPAA-compliant security monitoring",
				Instructions:         "Configure security controls and audit logging for HIPAA compliance",
				Order:                *order,
				IsRequired:           true,
				Category:             "compliance",
				EstimatedDuration:    90,
				RequiresVerification: true,
				ReminderSchedule:     s.getComplianceReminderSchedule(),
			})
			*order++
		}
	}

	return items
}

func (s *ChecklistAutomationService) setupItemDependencies(items []*entity.ChecklistItem) {
	// Set up logical dependencies between items
	for i, item := range items {
		switch item.Category {
		case "siem":
			// SIEM items depend on account setup
			for _, depItem := range items {
				if depItem.Category == "account" {
					item.DependsOn = append(item.DependsOn, depItem.ID)
				}
			}
		case "soar":
			// SOAR items depend on SIEM setup
			for _, depItem := range items {
				if depItem.Category == "siem" || depItem.Category == "account" {
					item.DependsOn = append(item.DependsOn, depItem.ID)
				}
			}
		case "executive":
			// Executive items depend on basic setup being complete
			if i > 2 {
				item.DependsOn = append(item.DependsOn, items[0].ID, items[1].ID)
			}
		}
	}
}

func (s *ChecklistAutomationService) scheduleItemReminders(ctx context.Context, item *entity.ChecklistItem) error {
	for _, reminderSchedule := range item.ReminderSchedule {
		schedule := &entity.ReminderSchedule{
			ID:                s.generateID("schedule"),
			ChecklistItemID:   item.ID,
			TriggerAfterHours: reminderSchedule.TriggerAfterHours,
			RecurrenceHours:   reminderSchedule.RecurrenceHours,
			MaxReminders:      reminderSchedule.MaxReminders,
			IsActive:          true,
			RemainingSends:    reminderSchedule.MaxReminders,
			NextScheduledAt:   &[]time.Time{time.Now().Add(time.Duration(reminderSchedule.TriggerAfterHours) * time.Hour)}[0],
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		if err := s.reminderScheduleRepo.CreateSchedule(ctx, schedule); err != nil {
			return fmt.Errorf("failed to create reminder schedule: %w", err)
		}
	}

	return nil
}

func (s *ChecklistAutomationService) processSingleReminder(ctx context.Context, schedule *entity.ReminderSchedule) error {
	// Get the checklist item
	item, err := s.checklistItemRepo.GetItemByID(ctx, schedule.ChecklistItemID, "")
	if err != nil {
		return fmt.Errorf("failed to get checklist item: %w", err)
	}

	// Skip if item is already completed
	if item.IsCompleted {
		return s.reminderScheduleRepo.DeactivateSchedule(ctx, schedule.ID, "")
	}

	// Get the checklist to get customer information
	checklist, err := s.checklistRepo.GetChecklistByID(ctx, item.ChecklistID, "")
	if err != nil {
		return fmt.Errorf("failed to get checklist: %w", err)
	}

	// Send reminder communication
	reminderRequest := &service.ChecklistReminderRequest{
		ChecklistID:       checklist.ID,
		ChecklistItemID:   item.ID,
		CustomerProfileID: checklist.CustomerProfileID,
		TenantID:         checklist.TenantID,
		// These would be populated from customer profile in a real implementation
		RecipientEmail:   "customer@example.com", // TODO: Get from customer profile
		RecipientName:    "Customer Name",        // TODO: Get from customer profile
		ItemTitle:        item.Title,
		ItemDescription:  item.Description,
		Variables: map[string]interface{}{
			"item_title":       item.Title,
			"item_description": item.Description,
			"action_url":       item.ActionURL,
			"due_date":         item.CreatedAt.Add(7 * 24 * time.Hour), // TODO: Calculate proper due date
		},
		ActionURL: item.ActionURL,
	}

	_, err = s.communicationService.SendChecklistItemReminder(ctx, reminderRequest)
	if err != nil {
		return fmt.Errorf("failed to send reminder: %w", err)
	}

	// Update reminder schedule
	schedule.RemainingSends--
	nextScheduledAt := time.Now()
	if schedule.RecurrenceHours != nil && schedule.RemainingSends > 0 {
		nextScheduledAt = nextScheduledAt.Add(time.Duration(*schedule.RecurrenceHours) * time.Hour)
	}

	if schedule.RemainingSends <= 0 {
		return s.reminderScheduleRepo.DeactivateSchedule(ctx, schedule.ID, checklist.TenantID)
	}

	return s.reminderScheduleRepo.UpdateNextScheduledTime(ctx, schedule.ID, nextScheduledAt, schedule.RemainingSends, checklist.TenantID)
}

func (s *ChecklistAutomationService) completeChecklist(ctx context.Context, checklist *entity.OnboardingChecklist) error {
	now := time.Now()
	if err := s.checklistRepo.CompleteChecklist(ctx, checklist.ID, now, checklist.TenantID); err != nil {
		return fmt.Errorf("failed to mark checklist complete: %w", err)
	}

	// Send completion notification
	completionRequest := &service.ChecklistCompletionRequest{
		ChecklistID:       checklist.ID,
		CustomerProfileID: checklist.CustomerProfileID,
		TenantID:         checklist.TenantID,
		// These would be populated from customer profile in a real implementation
		RecipientEmail: "customer@example.com", // TODO: Get from customer profile
		RecipientName:  "Customer Name",        // TODO: Get from customer profile
		TotalItems:     checklist.TotalItems,
		CompletedItems: checklist.TotalItems,
		CompletedAt:    now,
		Variables: map[string]interface{}{
			"checklist_title":    checklist.Title,
			"completion_date":    now.Format("January 2, 2006"),
			"total_items":        checklist.TotalItems,
			"completion_rate":    "100%",
		},
		NextSteps: []string{
			"Begin using your security platform",
			"Schedule regular security reviews",
			"Contact support if you have questions",
		},
	}

	_, err := s.communicationService.SendChecklistCompletionNotification(ctx, completionRequest)
	if err != nil {
		s.logger.Printf("Failed to send completion notification for checklist %s: %v", checklist.ID, err)
	}

	return nil
}

func (s *ChecklistAutomationService) checkItemDependencies(ctx context.Context, item *entity.ChecklistItem) {
	// Check if all dependencies are completed and update item status accordingly
	// This is a placeholder for dependency checking logic
}

// Reminder schedule generators
func (s *ChecklistAutomationService) getDefaultReminderSchedule() []entity.ReminderSchedule {
	return []entity.ReminderSchedule{
		{
			TriggerAfterHours: 24,  // First reminder after 24 hours
			RecurrenceHours:   &[]int{48}[0], // Then every 48 hours
			MaxReminders:      3,   // Maximum 3 reminders
		},
	}
}

func (s *ChecklistAutomationService) getServiceReminderSchedule() []entity.ReminderSchedule {
	return []entity.ReminderSchedule{
		{
			TriggerAfterHours: 48,  // First reminder after 48 hours
			RecurrenceHours:   &[]int{72}[0], // Then every 72 hours
			MaxReminders:      4,   // Maximum 4 reminders
		},
	}
}

func (s *ChecklistAutomationService) getExecutiveReminderSchedule() []entity.ReminderSchedule {
	return []entity.ReminderSchedule{
		{
			TriggerAfterHours: 72,  // First reminder after 72 hours
			RecurrenceHours:   &[]int{168}[0], // Then weekly
			MaxReminders:      2,   // Maximum 2 reminders
		},
	}
}

func (s *ChecklistAutomationService) getComplianceReminderSchedule() []entity.ReminderSchedule {
	return []entity.ReminderSchedule{
		{
			TriggerAfterHours: 48,  // First reminder after 48 hours
			RecurrenceHours:   &[]int{96}[0], // Then every 96 hours
			MaxReminders:      5,   // Maximum 5 reminders
		},
	}
}

// Helper methods
func (s *ChecklistAutomationService) generateChecklistTitle(customerTier, serviceTier string) string {
	switch customerTier {
	case "enterprise", "enterprise-plus":
		return "Enterprise Security Platform Onboarding"
	case "mid-market":
		return "Security Platform Setup Guide"
	default:
		return "iSECTECH Protect Onboarding Checklist"
	}
}

func (s *ChecklistAutomationService) generateChecklistDescription(customerTier, serviceTier string, services []string) string {
	base := fmt.Sprintf("Complete these steps to fully configure your iSECTECH Protect %s security platform.", serviceTier)
	
	if len(services) > 0 {
		base += fmt.Sprintf(" This checklist includes setup for: %s.", strings.Join(services, ", "))
	}
	
	return base
}

func (s *ChecklistAutomationService) calculateDueDate(customerTier, serviceTier string) *time.Time {
	var days int
	
	switch customerTier {
	case "enterprise", "enterprise-plus":
		days = 14 // 2 weeks for enterprise customers
	case "mid-market":
		days = 10 // 10 days for mid-market
	default:
		days = 7 // 1 week for smaller customers
	}
	
	dueDate := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	return &dueDate
}

func (s *ChecklistAutomationService) generateID(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), time.Now().UnixNano()%1000)
}

// Request types for checklist automation
type CreateChecklistFromTemplateRequest struct {
	CustomerProfileID     string   `json:"customer_profile_id"`
	OnboardingInstanceID  string   `json:"onboarding_instance_id"`
	TenantID             string   `json:"tenant_id"`
	CustomerTier         string   `json:"customer_tier"`
	ServiceTier          string   `json:"service_tier"`
	SelectedServices     []string `json:"selected_services"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	Language             string   `json:"language"`
	Timezone             string   `json:"timezone"`
}

// Add missing import for strings
import "strings"