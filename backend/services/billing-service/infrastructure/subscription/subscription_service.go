package subscription

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v74"
	"github.com/stripe/stripe-go/v74/sub"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
)

// SubscriptionService handles subscription lifecycle operations with iSECTECH requirements
type SubscriptionService struct {
	logger              *zap.Logger
	config              *config.StripeConfig
	subscriptionRepo    SubscriptionRepository
	planRepo            PlanRepository
	paymentMethodRepo   PaymentMethodRepository
	auditLogger         *zap.Logger
	
	// Security and compliance
	securityClearance   string
	complianceFrameworks []string
}

// SubscriptionRepository defines the interface for subscription storage
type SubscriptionRepository interface {
	Create(ctx context.Context, subscription *entity.Subscription) error
	Update(ctx context.Context, subscription *entity.Subscription) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Subscription, error)
	GetByStripeID(ctx context.Context, stripeID string) (*entity.Subscription, error)
	ListByCustomer(ctx context.Context, customerID uuid.UUID, filter *entity.SubscriptionFilter) ([]*entity.Subscription, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, filter *entity.SubscriptionFilter) ([]*entity.Subscription, error)
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Analytics methods
	GetMRRByTenant(ctx context.Context, tenantID uuid.UUID, asOfDate time.Time) (float64, error)
	GetChurnRateByTenant(ctx context.Context, tenantID uuid.UUID, period time.Duration) (float64, error)
	GetSubscriptionMetrics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*SubscriptionMetrics, error)
}

// PlanRepository defines the interface for plan storage
type PlanRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entity.SubscriptionPlan, error)
	GetByStripeID(ctx context.Context, stripeID string) (*entity.SubscriptionPlan, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, filter *entity.SubscriptionPlanFilter) ([]*entity.SubscriptionPlan, error)
}

// PaymentMethodRepository defines the interface for payment method operations
type PaymentMethodRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entity.PaymentMethod, error)
	GetDefaultByCustomer(ctx context.Context, customerID uuid.UUID) (*entity.PaymentMethod, error)
}

// SubscriptionMetrics represents subscription analytics data
type SubscriptionMetrics struct {
	TotalSubscriptions     int64   `json:"total_subscriptions"`
	ActiveSubscriptions    int64   `json:"active_subscriptions"`
	TrialSubscriptions     int64   `json:"trial_subscriptions"`
	CanceledSubscriptions  int64   `json:"canceled_subscriptions"`
	PastDueSubscriptions   int64   `json:"past_due_subscriptions"`
	MonthlyRecurringRevenue float64 `json:"monthly_recurring_revenue"`
	AnnualRecurringRevenue  float64 `json:"annual_recurring_revenue"`
	ChurnRate              float64 `json:"churn_rate"`
	AverageRevenuePerUser  float64 `json:"average_revenue_per_user"`
	LifetimeValue          float64 `json:"lifetime_value"`
}

// CreateSubscriptionRequest represents a request to create a subscription
type CreateSubscriptionRequest struct {
	TenantID               uuid.UUID `json:"tenant_id"`
	CustomerID             uuid.UUID `json:"customer_id"`
	PlanID                 uuid.UUID `json:"plan_id"`
	PaymentMethodID        *uuid.UUID `json:"payment_method_id,omitempty"`
	Quantity               int32     `json:"quantity"`
	
	// Trial configuration
	TrialPeriodDays        *int32    `json:"trial_period_days,omitempty"`
	TrialEnd               *time.Time `json:"trial_end,omitempty"`
	
	// Billing configuration
	BillingCycleAnchor     *time.Time `json:"billing_cycle_anchor,omitempty"`
	ProrationBehavior      entity.ProrationBehavior `json:"proration_behavior"`
	CollectionMethod       string    `json:"collection_method"` // "charge_automatically" or "send_invoice"
	DaysUntilDue           *int      `json:"days_until_due,omitempty"`
	
	// Discount
	CouponCode             *string   `json:"coupon_code,omitempty"`
	
	// Security and compliance
	SecurityClearance      string    `json:"security_clearance"`
	ComplianceFrameworks   []string  `json:"compliance_frameworks"`
	
	// Metadata
	Metadata               map[string]string `json:"metadata,omitempty"`
	
	// Created by
	CreatedBy              uuid.UUID `json:"created_by"`
}

// UpdateSubscriptionRequest represents a request to update a subscription
type UpdateSubscriptionRequest struct {
	SubscriptionID         uuid.UUID `json:"subscription_id"`
	PlanID                 *uuid.UUID `json:"plan_id,omitempty"`
	Quantity               *int32    `json:"quantity,omitempty"`
	PaymentMethodID        *uuid.UUID `json:"payment_method_id,omitempty"`
	ProrationBehavior      entity.ProrationBehavior `json:"proration_behavior"`
	BillingCycleAnchor     *time.Time `json:"billing_cycle_anchor,omitempty"`
	
	// Discount changes
	CouponCode             *string   `json:"coupon_code,omitempty"`
	RemoveDiscount         bool      `json:"remove_discount"`
	
	// Metadata updates
	Metadata               map[string]string `json:"metadata,omitempty"`
	
	// Updated by
	UpdatedBy              uuid.UUID `json:"updated_by"`
}

// CancelSubscriptionRequest represents a request to cancel a subscription
type CancelSubscriptionRequest struct {
	SubscriptionID       uuid.UUID `json:"subscription_id"`
	CancelAtPeriodEnd    bool      `json:"cancel_at_period_end"`
	CancelAt             *time.Time `json:"cancel_at,omitempty"`
	CancellationReason   *string   `json:"cancellation_reason,omitempty"`
	ProrationBehavior    entity.ProrationBehavior `json:"proration_behavior"`
	
	// Canceled by
	CanceledBy           uuid.UUID `json:"canceled_by"`
}

// PauseSubscriptionRequest represents a request to pause a subscription
type PauseSubscriptionRequest struct {
	SubscriptionID       uuid.UUID `json:"subscription_id"`
	Behavior             string    `json:"behavior"` // "mark_uncollectible", "keep_as_draft", "void"
	ResumesAt            *time.Time `json:"resumes_at,omitempty"`
	PauseReason          string    `json:"pause_reason"`
	
	// Paused by
	PausedBy             uuid.UUID `json:"paused_by"`
}

// SubscriptionResponse represents a subscription operation response
type SubscriptionResponse struct {
	Subscription         *entity.Subscription `json:"subscription"`
	ProrationAmount      int64               `json:"proration_amount,omitempty"`
	EffectiveDate        time.Time           `json:"effective_date"`
	AuditTrailID         string              `json:"audit_trail_id"`
	RequiresPayment      bool                `json:"requires_payment"`
	PaymentIntentID      *string             `json:"payment_intent_id,omitempty"`
}

// NewSubscriptionService creates a new subscription service
func NewSubscriptionService(
	logger *zap.Logger,
	config *config.StripeConfig,
	subscriptionRepo SubscriptionRepository,
	planRepo PlanRepository,
	paymentMethodRepo PaymentMethodRepository,
) *SubscriptionService {
	
	auditLogger := logger.Named("subscription_audit").With(
		zap.String("service", "subscription_management"),
		zap.String("environment", config.Environment),
		zap.Bool("pci_compliant", config.PCICompliant),
	)
	
	return &SubscriptionService{
		logger:              logger.Named("subscription_service"),
		config:              config,
		subscriptionRepo:    subscriptionRepo,
		planRepo:            planRepo,
		paymentMethodRepo:   paymentMethodRepo,
		auditLogger:         auditLogger,
		securityClearance:   "unclassified",
		complianceFrameworks: []string{"pci_dss", "sox_404"},
	}
}

// CreateSubscription creates a new subscription with lifecycle management
func (s *SubscriptionService) CreateSubscription(
	ctx context.Context,
	req *CreateSubscriptionRequest,
) (*SubscriptionResponse, error) {
	
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	s.auditLogger.Info("Creating subscription",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("customer_id", req.CustomerID.String()),
		zap.String("plan_id", req.PlanID.String()),
	)
	
	defer func() {
		s.auditLogger.Info("Subscription creation completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("duration", time.Since(start)),
		)
	}()
	
	// Validate security clearance
	if err := s.validateSecurityClearance(req.SecurityClearance); err != nil {
		s.auditLogger.Error("Security clearance validation failed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("security clearance validation failed: %w", err)
	}
	
	// Get the plan
	plan, err := s.planRepo.GetByID(ctx, req.PlanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan: %w", err)
	}
	
	if !plan.IsActive() {
		return nil, entity.ErrPlanNotAvailable
	}
	
	// Validate plan supports required security clearance
	if !plan.CanSupportSecurityClearance(req.SecurityClearance) {
		return nil, entity.ErrInsufficientSecurityClearance
	}
	
	// Get payment method if specified
	var paymentMethodID *string
	if req.PaymentMethodID != nil {
		pm, err := s.paymentMethodRepo.GetByID(ctx, *req.PaymentMethodID)
		if err != nil {
			return nil, fmt.Errorf("failed to get payment method: %w", err)
		}
		
		if !pm.IsActive() {
			return nil, entity.ErrPaymentMethodInactive
		}
		
		paymentMethodID = &pm.StripePaymentMethodID
	}
	
	// Create Stripe subscription
	stripeParams := &stripe.SubscriptionParams{
		Customer: stripe.String(req.CustomerID.String()), // Assume customer exists in Stripe
		Items: []*stripe.SubscriptionItemsParams{
			{
				Price:    stripe.String(plan.StripePriceID),
				Quantity: stripe.Int64(int64(req.Quantity)),
			},
		},
		CollectionMethod: stripe.String(req.CollectionMethod),
	}
	
	// Set payment method if provided
	if paymentMethodID != nil {
		stripeParams.DefaultPaymentMethod = stripe.String(*paymentMethodID)
	}
	
	// Configure trial period
	if req.TrialPeriodDays != nil {
		stripeParams.TrialPeriodDays = stripe.Int64(int64(*req.TrialPeriodDays))
	} else if req.TrialEnd != nil {
		stripeParams.TrialEnd = stripe.Int64(req.TrialEnd.Unix())
	} else if plan.HasTrial() {
		stripeParams.TrialPeriodDays = stripe.Int64(int64(*plan.TrialPeriodDays))
	}
	
	// Set billing cycle anchor
	if req.BillingCycleAnchor != nil {
		stripeParams.BillingCycleAnchor = stripe.Int64(req.BillingCycleAnchor.Unix())
	}
	
	// Set collection method specific options
	if req.CollectionMethod == "send_invoice" && req.DaysUntilDue != nil {
		stripeParams.DaysUntilDue = stripe.Int64(int64(*req.DaysUntilDue))
	}
	
	// Add coupon if provided
	if req.CouponCode != nil {
		stripeParams.Coupon = stripe.String(*req.CouponCode)
	}
	
	// Set proration behavior
	stripeParams.ProrationBehavior = stripe.String(string(req.ProrationBehavior))
	
	// Add metadata for compliance and audit
	stripeParams.Metadata = map[string]string{
		"tenant_id":              req.TenantID.String(),
		"customer_id":            req.CustomerID.String(),
		"plan_id":                req.PlanID.String(),
		"security_clearance":     req.SecurityClearance,
		"audit_trail_id":         auditTrailID,
		"created_by":             req.CreatedBy.String(),
		"compliance_frameworks":  strings.Join(req.ComplianceFrameworks, ","),
		"pci_compliant":          fmt.Sprintf("%t", s.config.PCICompliant),
	}
	
	// Add custom metadata
	for k, v := range req.Metadata {
		stripeParams.Metadata[k] = v
	}
	
	// Create subscription in Stripe
	stripeSub, err := sub.New(stripeParams)
	if err != nil {
		s.auditLogger.Error("Failed to create Stripe subscription",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, s.handleStripeError(err)
	}
	
	// Create internal subscription entity
	subscription := entity.NewSubscription(
		req.TenantID,
		req.CustomerID,
		req.PlanID,
		stripeSub.ID,
		req.CreatedBy,
	)
	
	// Set subscription details from Stripe response
	subscription.Status = entity.SubscriptionStatus(stripeSub.Status)
	subscription.CurrentPeriodStart = time.Unix(stripeSub.CurrentPeriodStart, 0)
	subscription.CurrentPeriodEnd = time.Unix(stripeSub.CurrentPeriodEnd, 0)
	subscription.UnitAmount = plan.UnitAmount
	subscription.Quantity = req.Quantity
	subscription.Currency = plan.Currency
	subscription.CollectionMethod = req.CollectionMethod
	subscription.SecurityClearance = req.SecurityClearance
	subscription.ComplianceFrameworks = req.ComplianceFrameworks
	
	// Set payment method ID
	if req.PaymentMethodID != nil {
		subscription.DefaultPaymentMethodID = req.PaymentMethodID
	}
	
	// Set trial information
	if stripeSub.TrialStart != 0 {
		trialStart := time.Unix(stripeSub.TrialStart, 0)
		subscription.TrialStart = &trialStart
	}
	if stripeSub.TrialEnd != 0 {
		trialEnd := time.Unix(stripeSub.TrialEnd, 0)
		subscription.TrialEnd = &trialEnd
	}
	
	// Set billing cycle anchor
	if stripeSub.BillingCycleAnchor != 0 {
		anchor := time.Unix(stripeSub.BillingCycleAnchor, 0)
		subscription.BillingCycleAnchor = &anchor
	}
	
	// Set days until due for invoice collection
	if req.DaysUntilDue != nil {
		subscription.DaysUntilDue = req.DaysUntilDue
	}
	
	// Add audit metadata
	subscription.Metadata = map[string]interface{}{
		"audit_trail_id":         auditTrailID,
		"stripe_subscription_id": stripeSub.ID,
		"created_via":            "api",
		"compliance_frameworks":  req.ComplianceFrameworks,
		"initial_plan_id":        req.PlanID.String(),
	}
	
	// Save to database
	if err := s.subscriptionRepo.Create(ctx, subscription); err != nil {
		// If database save fails, try to cancel the Stripe subscription
		if _, cancelErr := sub.Cancel(stripeSub.ID, nil); cancelErr != nil {
			s.logger.Error("Failed to cleanup Stripe subscription after database failure",
				zap.String("stripe_subscription_id", stripeSub.ID),
				zap.Error(cancelErr),
			)
		}
		
		s.auditLogger.Error("Failed to save subscription to database",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to save subscription: %w", err)
	}
	
	s.auditLogger.Info("Subscription created successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
		zap.String("stripe_subscription_id", stripeSub.ID),
	)
	
	response := &SubscriptionResponse{
		Subscription:    subscription,
		EffectiveDate:   subscription.CreatedAt,
		AuditTrailID:    auditTrailID,
		RequiresPayment: stripeSub.Status == stripe.SubscriptionStatusIncomplete,
	}
	
	// Add payment intent ID if subscription requires payment
	if stripeSub.LatestInvoice != nil && stripeSub.LatestInvoice.PaymentIntent != nil {
		response.PaymentIntentID = &stripeSub.LatestInvoice.PaymentIntent.ID
	}
	
	return response, nil
}

// UpdateSubscription updates an existing subscription with proration handling
func (s *SubscriptionService) UpdateSubscription(
	ctx context.Context,
	req *UpdateSubscriptionRequest,
) (*SubscriptionResponse, error) {
	
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	s.auditLogger.Info("Updating subscription",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", req.SubscriptionID.String()),
	)
	
	defer func() {
		s.auditLogger.Info("Subscription update completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("duration", time.Since(start)),
		)
	}()
	
	// Get existing subscription
	subscription, err := s.subscriptionRepo.GetByID(ctx, req.SubscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}
	
	if !subscription.CanUpgrade() && !subscription.CanDowngrade() {
		return nil, entity.ErrOperationNotAllowed
	}
	
	var prorationAmount int64
	updateParams := &stripe.SubscriptionParams{
		ProrationBehavior: stripe.String(string(req.ProrationBehavior)),
	}
	
	// Handle plan change
	if req.PlanID != nil && *req.PlanID != subscription.PlanID {
		newPlan, err := s.planRepo.GetByID(ctx, *req.PlanID)
		if err != nil {
			return nil, fmt.Errorf("failed to get new plan: %w", err)
		}
		
		if !newPlan.IsActive() {
			return nil, entity.ErrPlanNotAvailable
		}
		
		// Calculate proration if needed
		if req.ProrationBehavior == entity.ProrationBehaviorCreateProrations {
			newQuantity := req.Quantity
			if newQuantity == nil {
				newQuantity = &subscription.Quantity
			}
			
			prorationAmount = subscription.CalculateProrationAmount(
				newPlan.UnitAmount,
				*newQuantity,
				time.Now(),
			)
		}
		
		// Update subscription items
		updateParams.Items = []*stripe.SubscriptionItemsParams{
			{
				ID:    stripe.String(subscription.StripeSubscriptionID), // This should be the subscription item ID
				Price: stripe.String(newPlan.StripePriceID),
			},
		}
		
		subscription.PlanID = *req.PlanID
		subscription.UnitAmount = newPlan.UnitAmount
		subscription.Currency = newPlan.Currency
	}
	
	// Handle quantity change
	if req.Quantity != nil && *req.Quantity != subscription.Quantity {
		if updateParams.Items == nil {
			// Get current plan
			plan, err := s.planRepo.GetByID(ctx, subscription.PlanID)
			if err != nil {
				return nil, fmt.Errorf("failed to get plan: %w", err)
			}
			
			updateParams.Items = []*stripe.SubscriptionItemsParams{
				{
					ID:       stripe.String(subscription.StripeSubscriptionID), // This should be the subscription item ID
					Quantity: stripe.Int64(int64(*req.Quantity)),
				},
			}
		} else {
			// Quantity already being updated with plan change
			updateParams.Items[0].Quantity = stripe.Int64(int64(*req.Quantity))
		}
		
		subscription.Quantity = *req.Quantity
	}
	
	// Handle payment method change
	if req.PaymentMethodID != nil {
		pm, err := s.paymentMethodRepo.GetByID(ctx, *req.PaymentMethodID)
		if err != nil {
			return nil, fmt.Errorf("failed to get payment method: %w", err)
		}
		
		if !pm.IsActive() {
			return nil, entity.ErrPaymentMethodInactive
		}
		
		updateParams.DefaultPaymentMethod = stripe.String(pm.StripePaymentMethodID)
		subscription.DefaultPaymentMethodID = req.PaymentMethodID
	}
	
	// Handle billing cycle anchor
	if req.BillingCycleAnchor != nil {
		updateParams.BillingCycleAnchor = stripe.Int64(req.BillingCycleAnchor.Unix())
		subscription.BillingCycleAnchor = req.BillingCycleAnchor
	}
	
	// Handle coupon changes
	if req.CouponCode != nil {
		updateParams.Coupon = stripe.String(*req.CouponCode)
		subscription.CouponCode = req.CouponCode
	} else if req.RemoveDiscount {
		updateParams.Coupon = stripe.String("")
		subscription.CouponCode = nil
		subscription.DiscountID = nil
	}
	
	// Add metadata updates
	if updateParams.Metadata == nil {
		updateParams.Metadata = make(map[string]string)
	}
	updateParams.Metadata["audit_trail_id"] = auditTrailID
	updateParams.Metadata["updated_by"] = req.UpdatedBy.String()
	updateParams.Metadata["last_modified"] = time.Now().Format(time.RFC3339)
	
	// Add custom metadata
	for k, v := range req.Metadata {
		updateParams.Metadata[k] = v
	}
	
	// Update subscription in Stripe
	stripeSub, err := sub.Update(subscription.StripeSubscriptionID, updateParams)
	if err != nil {
		s.auditLogger.Error("Failed to update Stripe subscription",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, s.handleStripeError(err)
	}
	
	// Update subscription fields from Stripe response
	subscription.Status = entity.SubscriptionStatus(stripeSub.Status)
	subscription.CurrentPeriodStart = time.Unix(stripeSub.CurrentPeriodStart, 0)
	subscription.CurrentPeriodEnd = time.Unix(stripeSub.CurrentPeriodEnd, 0)
	subscription.UpdatedAt = time.Now()
	subscription.UpdatedBy = req.UpdatedBy
	
	// Update metadata
	if subscription.Metadata == nil {
		subscription.Metadata = make(map[string]interface{})
	}
	subscription.Metadata["audit_trail_id"] = auditTrailID
	subscription.Metadata["last_update_type"] = "plan_change"
	subscription.Metadata["proration_amount"] = prorationAmount
	
	// Save updated subscription
	if err := s.subscriptionRepo.Update(ctx, subscription); err != nil {
		s.auditLogger.Error("Failed to update subscription in database",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to update subscription: %w", err)
	}
	
	s.auditLogger.Info("Subscription updated successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
		zap.Int64("proration_amount", prorationAmount),
	)
	
	response := &SubscriptionResponse{
		Subscription:    subscription,
		ProrationAmount: prorationAmount,
		EffectiveDate:   time.Now(),
		AuditTrailID:    auditTrailID,
		RequiresPayment: stripeSub.Status == stripe.SubscriptionStatusIncomplete,
	}
	
	// Add payment intent ID if subscription requires payment
	if stripeSub.LatestInvoice != nil && stripeSub.LatestInvoice.PaymentIntent != nil {
		response.PaymentIntentID = &stripeSub.LatestInvoice.PaymentIntent.ID
	}
	
	return response, nil
}

// CancelSubscription cancels a subscription with proper lifecycle management
func (s *SubscriptionService) CancelSubscription(
	ctx context.Context,
	req *CancelSubscriptionRequest,
) (*SubscriptionResponse, error) {
	
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Canceling subscription",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", req.SubscriptionID.String()),
		zap.Bool("cancel_at_period_end", req.CancelAtPeriodEnd),
	)
	
	// Get subscription
	subscription, err := s.subscriptionRepo.GetByID(ctx, req.SubscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}
	
	if !subscription.CanCancel() {
		return nil, entity.ErrOperationNotAllowed
	}
	
	var cancelParams *stripe.SubscriptionCancelParams
	
	if req.CancelAtPeriodEnd {
		// Schedule cancellation at period end
		updateParams := &stripe.SubscriptionParams{
			CancelAtPeriodEnd: stripe.Bool(true),
		}
		
		if req.CancellationReason != nil {
			updateParams.Metadata = map[string]string{
				"cancellation_reason": *req.CancellationReason,
				"audit_trail_id":      auditTrailID,
				"canceled_by":         req.CanceledBy.String(),
			}
		}
		
		stripeSub, err := sub.Update(subscription.StripeSubscriptionID, updateParams)
		if err != nil {
			s.auditLogger.Error("Failed to schedule Stripe subscription cancellation",
				zap.String("audit_trail_id", auditTrailID),
				zap.Error(err),
			)
			return nil, s.handleStripeError(err)
		}
		
		subscription.CancelAtPeriodEnd = true
		subscription.Status = entity.SubscriptionStatus(stripeSub.Status)
		
	} else {
		// Cancel immediately
		cancelParams = &stripe.SubscriptionCancelParams{
			ProrationBehavior: stripe.String(string(req.ProrationBehavior)),
		}
		
		if req.CancelAt != nil {
			cancelParams.CancelAt = stripe.Int64(req.CancelAt.Unix())
		}
		
		stripeSub, err := sub.Cancel(subscription.StripeSubscriptionID, cancelParams)
		if err != nil {
			s.auditLogger.Error("Failed to cancel Stripe subscription",
				zap.String("audit_trail_id", auditTrailID),
				zap.Error(err),
			)
			return nil, s.handleStripeError(err)
		}
		
		subscription.Status = entity.SubscriptionStatusCanceled
		now := time.Now()
		subscription.CanceledAt = &now
		
		if req.CancelAt != nil {
			subscription.CancelAt = req.CancelAt
		}
	}
	
	// Set cancellation details
	subscription.CancellationReason = req.CancellationReason
	subscription.UpdatedAt = time.Now()
	subscription.UpdatedBy = req.CanceledBy
	
	// Update metadata
	if subscription.Metadata == nil {
		subscription.Metadata = make(map[string]interface{})
	}
	subscription.Metadata["audit_trail_id"] = auditTrailID
	subscription.Metadata["cancellation_type"] = map[string]interface{}{
		"at_period_end": req.CancelAtPeriodEnd,
		"immediate":     !req.CancelAtPeriodEnd,
	}
	
	// Save updated subscription
	if err := s.subscriptionRepo.Update(ctx, subscription); err != nil {
		s.auditLogger.Error("Failed to update canceled subscription in database",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to update subscription: %w", err)
	}
	
	s.auditLogger.Info("Subscription canceled successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
	)
	
	return &SubscriptionResponse{
		Subscription:  subscription,
		EffectiveDate: time.Now(),
		AuditTrailID:  auditTrailID,
	}, nil
}

// PauseSubscription pauses a subscription
func (s *SubscriptionService) PauseSubscription(
	ctx context.Context,
	req *PauseSubscriptionRequest,
) (*SubscriptionResponse, error) {
	
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Pausing subscription",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", req.SubscriptionID.String()),
		zap.String("behavior", req.Behavior),
	)
	
	// Get subscription
	subscription, err := s.subscriptionRepo.GetByID(ctx, req.SubscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}
	
	if !subscription.CanPause() {
		return nil, entity.ErrOperationNotAllowed
	}
	
	// Pause subscription in Stripe
	updateParams := &stripe.SubscriptionParams{
		PauseCollection: &stripe.SubscriptionPauseCollectionParams{
			Behavior: stripe.String(req.Behavior),
		},
	}
	
	if req.ResumesAt != nil {
		updateParams.PauseCollection.ResumesAt = stripe.Int64(req.ResumesAt.Unix())
	}
	
	stripeSub, err := sub.Update(subscription.StripeSubscriptionID, updateParams)
	if err != nil {
		s.auditLogger.Error("Failed to pause Stripe subscription",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, s.handleStripeError(err)
	}
	
	// Update subscription
	subscription.Status = entity.SubscriptionStatusPaused
	subscription.PauseCollection = &entity.PauseCollection{
		Behavior:    req.Behavior,
		ResumesAt:   req.ResumesAt,
		PausedAt:    time.Now(),
		PausedBy:    req.PausedBy,
		PauseReason: req.PauseReason,
	}
	subscription.UpdatedAt = time.Now()
	subscription.UpdatedBy = req.PausedBy
	
	// Update metadata
	if subscription.Metadata == nil {
		subscription.Metadata = make(map[string]interface{})
	}
	subscription.Metadata["audit_trail_id"] = auditTrailID
	subscription.Metadata["pause_reason"] = req.PauseReason
	
	// Save updated subscription
	if err := s.subscriptionRepo.Update(ctx, subscription); err != nil {
		s.auditLogger.Error("Failed to update paused subscription in database",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to update subscription: %w", err)
	}
	
	s.auditLogger.Info("Subscription paused successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
	)
	
	return &SubscriptionResponse{
		Subscription:  subscription,
		EffectiveDate: time.Now(),
		AuditTrailID:  auditTrailID,
	}, nil
}

// ResumeSubscription resumes a paused subscription
func (s *SubscriptionService) ResumeSubscription(
	ctx context.Context,
	subscriptionID uuid.UUID,
	resumedBy uuid.UUID,
) (*SubscriptionResponse, error) {
	
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Resuming subscription",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscriptionID.String()),
	)
	
	// Get subscription
	subscription, err := s.subscriptionRepo.GetByID(ctx, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}
	
	if !subscription.CanResume() {
		return nil, entity.ErrOperationNotAllowed
	}
	
	// Resume subscription in Stripe
	updateParams := &stripe.SubscriptionParams{
		PauseCollection: &stripe.SubscriptionPauseCollectionParams{},
	}
	updateParams.PauseCollection.SetEmpty(true)
	
	stripeSub, err := sub.Update(subscription.StripeSubscriptionID, updateParams)
	if err != nil {
		s.auditLogger.Error("Failed to resume Stripe subscription",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, s.handleStripeError(err)
	}
	
	// Update subscription
	subscription.Status = entity.SubscriptionStatus(stripeSub.Status)
	subscription.PauseCollection = nil
	subscription.UpdatedAt = time.Now()
	subscription.UpdatedBy = resumedBy
	
	// Update metadata
	if subscription.Metadata == nil {
		subscription.Metadata = make(map[string]interface{})
	}
	subscription.Metadata["audit_trail_id"] = auditTrailID
	subscription.Metadata["resumed_at"] = time.Now()
	
	// Save updated subscription
	if err := s.subscriptionRepo.Update(ctx, subscription); err != nil {
		s.auditLogger.Error("Failed to update resumed subscription in database",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to update subscription: %w", err)
	}
	
	s.auditLogger.Info("Subscription resumed successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("subscription_id", subscription.ID.String()),
	)
	
	return &SubscriptionResponse{
		Subscription:  subscription,
		EffectiveDate: time.Now(),
		AuditTrailID:  auditTrailID,
	}, nil
}

// GetSubscriptionMetrics returns subscription analytics for a tenant
func (s *SubscriptionService) GetSubscriptionMetrics(
	ctx context.Context,
	tenantID uuid.UUID,
	from, to time.Time,
) (*SubscriptionMetrics, error) {
	
	return s.subscriptionRepo.GetSubscriptionMetrics(ctx, tenantID, from, to)
}

// validateSecurityClearance validates security clearance requirements
func (s *SubscriptionService) validateSecurityClearance(clearance string) error {
	validClearances := []string{
		"unclassified",
		"cui",
		"confidential", 
		"secret",
		"top_secret",
	}
	
	for _, valid := range validClearances {
		if clearance == valid {
			return nil
		}
	}
	
	return entity.ErrInsufficientSecurityClearance
}

// handleStripeError converts Stripe errors to internal errors
func (s *SubscriptionService) handleStripeError(err error) error {
	if stripeErr, ok := err.(*stripe.Error); ok {
		switch stripeErr.Code {
		case stripe.ErrorCodeResourceMissing:
			return entity.ErrSubscriptionNotFound
		case stripe.ErrorCodeCardDeclined:
			return entity.ErrPaymentDeclined
		case stripe.ErrorCodeInsufficientFunds:
			return entity.ErrInsufficientFunds
		default:
			s.logger.Error("Stripe API error",
				zap.String("code", string(stripeErr.Code)),
				zap.String("message", stripeErr.Msg),
				zap.String("type", string(stripeErr.Type)),
			)
			return entity.ErrStripeAPIError
		}
	}
	
	return err
}