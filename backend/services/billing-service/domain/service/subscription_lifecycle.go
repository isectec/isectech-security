package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
)

// SubscriptionLifecycleManager manages subscription lifecycle and state transitions
type SubscriptionLifecycleManager struct {
	logger               *zap.Logger
	subscriptionRepo     SubscriptionRepository
	planRepo             PlanRepository
	paymentMethodRepo    PaymentMethodRepository
	notificationService  NotificationService
	auditLogger          *zap.Logger
}

// SubscriptionRepository defines the interface for subscription persistence
type SubscriptionRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Subscription, error)
	Update(ctx context.Context, subscription *entity.Subscription) error
	ListExpiringSoon(ctx context.Context, days int) ([]*entity.Subscription, error)
	ListTrialsEndingSoon(ctx context.Context, days int) ([]*entity.Subscription, error)
	ListPastDue(ctx context.Context, maxDays int) ([]*entity.Subscription, error)
	ListForRenewal(ctx context.Context, date time.Time) ([]*entity.Subscription, error)
}

// PlanRepository defines the interface for plan operations
type PlanRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entity.SubscriptionPlan, error)
}

// PaymentMethodRepository defines the interface for payment method operations
type PaymentMethodRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entity.PaymentMethod, error)
}

// NotificationService defines the interface for sending notifications
type NotificationService interface {
	SendTrialEndingNotification(ctx context.Context, subscription *entity.Subscription, daysRemaining int) error
	SendRenewalNotification(ctx context.Context, subscription *entity.Subscription) error  
	SendPaymentFailedNotification(ctx context.Context, subscription *entity.Subscription) error
	SendSubscriptionCanceledNotification(ctx context.Context, subscription *entity.Subscription) error
	SendSubscriptionReactivatedNotification(ctx context.Context, subscription *entity.Subscription) error
}

// LifecycleEvent represents subscription lifecycle events
type LifecycleEvent struct {
	SubscriptionID   uuid.UUID                  `json:"subscription_id"`
	EventType        LifecycleEventType         `json:"event_type"`
	EventData        map[string]interface{}     `json:"event_data"`
	Timestamp        time.Time                  `json:"timestamp"`
	TriggeredBy      uuid.UUID                  `json:"triggered_by"`
	AuditTrailID     string                     `json:"audit_trail_id"`
}

// LifecycleEventType represents different lifecycle event types
type LifecycleEventType string

const (
	LifecycleEventTrialStarted         LifecycleEventType = "trial_started"
	LifecycleEventTrialEnding          LifecycleEventType = "trial_ending"
	LifecycleEventTrialEnded           LifecycleEventType = "trial_ended"
	LifecycleEventSubscriptionActivated LifecycleEventType = "subscription_activated"
	LifecycleEventRenewalDue           LifecycleEventType = "renewal_due"
	LifecycleEventRenewalProcessed     LifecycleEventType = "renewal_processed"
	LifecycleEventPaymentFailed        LifecycleEventType = "payment_failed"
	LifecycleEventPaymentRetried       LifecycleEventType = "payment_retried"
	LifecycleEventSubscriptionPastDue  LifecycleEventType = "subscription_past_due"
	LifecycleEventSubscriptionCanceled LifecycleEventType = "subscription_canceled"
	LifecycleEventSubscriptionPaused   LifecycleEventType = "subscription_paused"
	LifecycleEventSubscriptionResumed  LifecycleEventType = "subscription_resumed"
	LifecycleEventPlanUpgraded         LifecycleEventType = "plan_upgraded"
	LifecycleEventPlanDowngraded       LifecycleEventType = "plan_downgraded"
	LifecycleEventQuantityChanged      LifecycleEventType = "quantity_changed"
)

// NewSubscriptionLifecycleManager creates a new lifecycle manager
func NewSubscriptionLifecycleManager(
	logger *zap.Logger,
	subscriptionRepo SubscriptionRepository,
	planRepo PlanRepository,
	paymentMethodRepo PaymentMethodRepository,
	notificationService NotificationService,
) *SubscriptionLifecycleManager {
	
	auditLogger := logger.Named("subscription_lifecycle_audit").With(
		zap.String("service", "subscription_lifecycle"),
	)
	
	return &SubscriptionLifecycleManager{
		logger:              logger.Named("subscription_lifecycle"),
		subscriptionRepo:    subscriptionRepo,
		planRepo:            planRepo,
		paymentMethodRepo:   paymentMethodRepo,
		notificationService: notificationService,
		auditLogger:         auditLogger,
	}
}

// ProcessTrialEndingNotifications processes trial ending notifications
func (m *SubscriptionLifecycleManager) ProcessTrialEndingNotifications(ctx context.Context, notificationDays []int) error {
	for _, days := range notificationDays {
		subscriptions, err := m.subscriptionRepo.ListTrialsEndingSoon(ctx, days)
		if err != nil {
			m.logger.Error("Failed to get trials ending soon",
				zap.Int("notification_days", days),
				zap.Error(err),
			)
			continue
		}
		
		for _, subscription := range subscriptions {
			if err := m.notificationService.SendTrialEndingNotification(ctx, subscription, days); err != nil {
				m.logger.Error("Failed to send trial ending notification",
					zap.String("subscription_id", subscription.ID.String()),
					zap.Int("days_remaining", days),
					zap.Error(err),
				)
				continue
			}
			
			m.auditLogger.Info("Trial ending notification sent",
				zap.String("subscription_id", subscription.ID.String()),
				zap.Int("days_remaining", days),
			)
		}
	}
	
	return nil
}

// ProcessSubscriptionRenewals processes subscription renewals
func (m *SubscriptionLifecycleManager) ProcessSubscriptionRenewals(ctx context.Context, renewalDate time.Time) error {
	subscriptions, err := m.subscriptionRepo.ListForRenewal(ctx, renewalDate)
	if err != nil {
		return fmt.Errorf("failed to get subscriptions for renewal: %w", err)
	}
	
	for _, subscription := range subscriptions {
		if err := m.processSubscriptionRenewal(ctx, subscription); err != nil {
			m.logger.Error("Failed to process subscription renewal",
				zap.String("subscription_id", subscription.ID.String()),
				zap.Error(err),
			)
			continue
		}
	}
	
	return nil
}

// processSubscriptionRenewal processes individual subscription renewal
func (m *SubscriptionLifecycleManager) processSubscriptionRenewal(ctx context.Context, subscription *entity.Subscription) error {
	auditTrailID := uuid.New().String()
	
	m.auditLogger.Info("Processing subscription renewal",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
	)
	
	// Check if subscription is still renewable
	if !subscription.IsActive() || subscription.CancelAtPeriodEnd {
		m.logger.Info("Subscription not renewable",
			zap.String("subscription_id", subscription.ID.String()),
			zap.String("status", string(subscription.Status)),
			zap.Bool("cancel_at_period_end", subscription.CancelAtPeriodEnd),
		)
		return nil
	}
	
	// Validate payment method is still active
	if subscription.DefaultPaymentMethodID != nil {
		pm, err := m.paymentMethodRepo.GetByID(ctx, *subscription.DefaultPaymentMethodID)
		if err != nil {
			return fmt.Errorf("failed to get payment method: %w", err)
		}
		
		if !pm.IsActive() {
			// Mark subscription as having payment issues
			subscription.Status = entity.SubscriptionStatusPastDue
			subscription.UpdatedAt = time.Now()
			
			if err := m.subscriptionRepo.Update(ctx, subscription); err != nil {
				return fmt.Errorf("failed to update subscription status: %w", err)
			}
			
			// Send payment failed notification
			if err := m.notificationService.SendPaymentFailedNotification(ctx, subscription); err != nil {
				m.logger.Error("Failed to send payment failed notification",
					zap.String("subscription_id", subscription.ID.String()),
					zap.Error(err),
				)
			}
			
			return fmt.Errorf("payment method expired or inactive")
		}
	}
	
	// Calculate next period
	plan, err := m.planRepo.GetByID(ctx, subscription.PlanID)
	if err != nil {
		return fmt.Errorf("failed to get subscription plan: %w", err)
	}
	
	nextPeriodStart := subscription.CurrentPeriodEnd
	nextPeriodEnd := m.calculateNextPeriodEnd(nextPeriodStart, plan.Interval, plan.IntervalCount)
	
	// Update subscription for next period
	subscription.CurrentPeriodStart = nextPeriodStart
	subscription.CurrentPeriodEnd = nextPeriodEnd
	subscription.UpdatedAt = time.Now()
	
	// Add renewal metadata
	if subscription.Metadata == nil {
		subscription.Metadata = make(map[string]interface{})
	}
	subscription.Metadata["last_renewal"] = time.Now()
	subscription.Metadata["renewal_audit_trail_id"] = auditTrailID
	subscription.Metadata["renewal_count"] = m.incrementRenewalCount(subscription.Metadata)
	
	// Save updated subscription
	if err := m.subscriptionRepo.Update(ctx, subscription); err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}
	
	// Send renewal notification
	if err := m.notificationService.SendRenewalNotification(ctx, subscription); err != nil {
		m.logger.Error("Failed to send renewal notification",
			zap.String("subscription_id", subscription.ID.String()),
			zap.Error(err),
		)
	}
	
	m.auditLogger.Info("Subscription renewed successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
		zap.Time("next_period_end", nextPeriodEnd),
	)
	
	return nil
}

// ProcessPastDueSubscriptions processes past due subscriptions
func (m *SubscriptionLifecycleManager) ProcessPastDueSubscriptions(ctx context.Context, maxPastDueDays int) error {
	subscriptions, err := m.subscriptionRepo.ListPastDue(ctx, maxPastDueDays)
	if err != nil {
		return fmt.Errorf("failed to get past due subscriptions: %w", err)
	}
	
	for _, subscription := range subscriptions {
		if err := m.processPastDueSubscription(ctx, subscription, maxPastDueDays); err != nil {
			m.logger.Error("Failed to process past due subscription",
				zap.String("subscription_id", subscription.ID.String()),
				zap.Error(err),
			)
			continue
		}
	}
	
	return nil
}

// processPastDueSubscription handles individual past due subscription
func (m *SubscriptionLifecycleManager) processPastDueSubscription(ctx context.Context, subscription *entity.Subscription, maxPastDueDays int) error {
	auditTrailID := uuid.New().String()
	
	// Calculate days past due
	daysPastDue := int(time.Since(subscription.CurrentPeriodEnd).Hours() / 24)
	
	m.auditLogger.Info("Processing past due subscription",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
		zap.Int("days_past_due", daysPastDue),
	)
	
	if daysPastDue >= maxPastDueDays {
		// Cancel subscription due to extended past due period
		subscription.Status = entity.SubscriptionStatusCanceled
		now := time.Now()
		subscription.CanceledAt = &now
		reason := fmt.Sprintf("Canceled due to %d days past due", daysPastDue)
		subscription.CancellationReason = &reason
		subscription.UpdatedAt = time.Now()
		
		// Add cancellation metadata
		if subscription.Metadata == nil {
			subscription.Metadata = make(map[string]interface{})
		}
		subscription.Metadata["auto_canceled"] = true
		subscription.Metadata["cancellation_reason"] = "past_due_timeout"
		subscription.Metadata["days_past_due"] = daysPastDue
		subscription.Metadata["audit_trail_id"] = auditTrailID
		
		// Save updated subscription
		if err := m.subscriptionRepo.Update(ctx, subscription); err != nil {
			return fmt.Errorf("failed to cancel past due subscription: %w", err)
		}
		
		// Send cancellation notification
		if err := m.notificationService.SendSubscriptionCanceledNotification(ctx, subscription); err != nil {
			m.logger.Error("Failed to send cancellation notification",
				zap.String("subscription_id", subscription.ID.String()),
				zap.Error(err),
			)
		}
		
		m.auditLogger.Info("Subscription auto-canceled due to past due",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("subscription_id", subscription.ID.String()),
			zap.Int("days_past_due", daysPastDue),
		)
	} else {
		// Send payment retry notification
		if err := m.notificationService.SendPaymentFailedNotification(ctx, subscription); err != nil {
			m.logger.Error("Failed to send payment retry notification",
				zap.String("subscription_id", subscription.ID.String()),
				zap.Error(err),
			)
		}
	}
	
	return nil
}

// TransitionTrialToActive transitions a trial subscription to active
func (m *SubscriptionLifecycleManager) TransitionTrialToActive(ctx context.Context, subscriptionID uuid.UUID, transitionedBy uuid.UUID) error {
	auditTrailID := uuid.New().String()
	
	subscription, err := m.subscriptionRepo.GetByID(ctx, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}
	
	if subscription.Status != entity.SubscriptionStatusTrialing {
		return fmt.Errorf("subscription is not in trial status")
	}
	
	// Check if trial has ended
	if subscription.TrialEnd != nil && time.Now().After(*subscription.TrialEnd) {
		// Trial has ended, transition to active
		subscription.Status = entity.SubscriptionStatusActive
		subscription.UpdatedAt = time.Now()
		subscription.UpdatedBy = transitionedBy
		
		// Add transition metadata
		if subscription.Metadata == nil {
			subscription.Metadata = make(map[string]interface{})
		}
		subscription.Metadata["trial_to_active_transition"] = time.Now()
		subscription.Metadata["audit_trail_id"] = auditTrailID
		
		// Save updated subscription
		if err := m.subscriptionRepo.Update(ctx, subscription); err != nil {
			return fmt.Errorf("failed to update subscription: %w", err)
		}
		
		m.auditLogger.Info("Subscription transitioned from trial to active",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("subscription_id", subscription.ID.String()),
		)
	}
	
	return nil
}

// ReactivateSubscription reactivates a canceled or past due subscription
func (m *SubscriptionLifecycleManager) ReactivateSubscription(ctx context.Context, subscriptionID uuid.UUID, reactivatedBy uuid.UUID) error {
	auditTrailID := uuid.New().String()
	
	subscription, err := m.subscriptionRepo.GetByID(ctx, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to get subscription: %w", err)
	}
	
	if subscription.Status != entity.SubscriptionStatusCanceled && subscription.Status != entity.SubscriptionStatusPastDue {
		return fmt.Errorf("subscription cannot be reactivated from current status: %s", subscription.Status)
	}
	
	// Validate payment method is available and active
	if subscription.DefaultPaymentMethodID != nil {
		pm, err := m.paymentMethodRepo.GetByID(ctx, *subscription.DefaultPaymentMethodID)
		if err != nil {
			return fmt.Errorf("failed to get payment method: %w", err)
		}
		
		if !pm.IsActive() {
			return fmt.Errorf("payment method is not active")
		}
	}
	
	// Reactivate subscription
	subscription.Status = entity.SubscriptionStatusActive
	subscription.UpdatedAt = time.Now()
	subscription.UpdatedBy = reactivatedBy
	
	// Clear cancellation fields
	subscription.CanceledAt = nil
	subscription.CancelAt = nil
	subscription.CancelAtPeriodEnd = false
	subscription.CancellationReason = nil
	
	// Add reactivation metadata
	if subscription.Metadata == nil {
		subscription.Metadata = make(map[string]interface{})
	}
	subscription.Metadata["reactivated_at"] = time.Now()
	subscription.Metadata["reactivated_by"] = reactivatedBy.String()
	subscription.Metadata["audit_trail_id"] = auditTrailID
	
	// Save updated subscription
	if err := m.subscriptionRepo.Update(ctx, subscription); err != nil {
		return fmt.Errorf("failed to reactivate subscription: %w", err)
	}
	
	// Send reactivation notification
	if err := m.notificationService.SendSubscriptionReactivatedNotification(ctx, subscription); err != nil {
		m.logger.Error("Failed to send reactivation notification",
			zap.String("subscription_id", subscription.ID.String()),
			zap.Error(err),
		)
	}
	
	m.auditLogger.Info("Subscription reactivated successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
	)
	
	return nil
}

// ValidateSubscriptionTransition validates if a status transition is allowed
func (m *SubscriptionLifecycleManager) ValidateSubscriptionTransition(currentStatus, newStatus entity.SubscriptionStatus) error {
	validTransitions := map[entity.SubscriptionStatus][]entity.SubscriptionStatus{
		entity.SubscriptionStatusPending: {
			entity.SubscriptionStatusActive,
			entity.SubscriptionStatusTrialing,
			entity.SubscriptionStatusIncomplete,
			entity.SubscriptionStatusCanceled,
		},
		entity.SubscriptionStatusActive: {
			entity.SubscriptionStatusPastDue,
			entity.SubscriptionStatusCanceled,
			entity.SubscriptionStatusPaused,
			entity.SubscriptionStatusUnpaid,
		},
		entity.SubscriptionStatusTrialing: {
			entity.SubscriptionStatusActive,
			entity.SubscriptionStatusPastDue,
			entity.SubscriptionStatusCanceled,
		},
		entity.SubscriptionStatusPastDue: {
			entity.SubscriptionStatusActive,
			entity.SubscriptionStatusCanceled,
			entity.SubscriptionStatusUnpaid,
		},
		entity.SubscriptionStatusPaused: {
			entity.SubscriptionStatusActive,
			entity.SubscriptionStatusCanceled,
		},
		entity.SubscriptionStatusIncomplete: {
			entity.SubscriptionStatusActive,
			entity.SubscriptionStatusCanceled,
		},
		entity.SubscriptionStatusUnpaid: {
			entity.SubscriptionStatusActive,
			entity.SubscriptionStatusCanceled,
		},
		entity.SubscriptionStatusCanceled: {
			entity.SubscriptionStatusActive, // Allow reactivation
		},
	}
	
	allowedTransitions, exists := validTransitions[currentStatus]
	if !exists {
		return fmt.Errorf("no transitions defined for status: %s", currentStatus)
	}
	
	for _, allowed := range allowedTransitions {
		if allowed == newStatus {
			return nil
		}
	}
	
	return fmt.Errorf("transition from %s to %s is not allowed", currentStatus, newStatus)
}

// calculateNextPeriodEnd calculates the next billing period end date
func (m *SubscriptionLifecycleManager) calculateNextPeriodEnd(start time.Time, interval entity.BillingInterval, intervalCount int32) time.Time {
	switch interval {
	case entity.BillingIntervalDaily:
		return start.AddDate(0, 0, int(intervalCount))
	case entity.BillingIntervalWeekly:
		return start.AddDate(0, 0, int(intervalCount)*7)
	case entity.BillingIntervalMonthly:
		return start.AddDate(0, int(intervalCount), 0)
	case entity.BillingIntervalYearly:
		return start.AddDate(int(intervalCount), 0, 0)
	default:
		// Default to monthly if interval is unknown
		return start.AddDate(0, int(intervalCount), 0)
	}
}

// incrementRenewalCount increments the renewal count in metadata
func (m *SubscriptionLifecycleManager) incrementRenewalCount(metadata map[string]interface{}) int {
	if count, exists := metadata["renewal_count"]; exists {
		if countInt, ok := count.(int); ok {
			return countInt + 1
		}
	}
	return 1
}

// GetLifecycleEvents returns lifecycle events for a subscription
func (m *SubscriptionLifecycleManager) GetLifecycleEvents(ctx context.Context, subscriptionID uuid.UUID) ([]*LifecycleEvent, error) {
	// This would typically be implemented with a separate events store
	// For now, we'll return an empty slice
	return make([]*LifecycleEvent, 0), nil
}

// EmitLifecycleEvent emits a lifecycle event
func (m *SubscriptionLifecycleManager) EmitLifecycleEvent(ctx context.Context, event *LifecycleEvent) error {
	// This would typically publish to an event bus or store in an events table
	m.auditLogger.Info("Lifecycle event emitted",
		zap.String("subscription_id", event.SubscriptionID.String()),
		zap.String("event_type", string(event.EventType)),
		zap.String("audit_trail_id", event.AuditTrailID),
		zap.Time("timestamp", event.Timestamp),
	)
	
	return nil
}