package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SubscriptionStatus represents the status of a subscription
type SubscriptionStatus string

const (
	SubscriptionStatusPending    SubscriptionStatus = "pending"
	SubscriptionStatusActive     SubscriptionStatus = "active"
	SubscriptionStatusPastDue    SubscriptionStatus = "past_due"
	SubscriptionStatusCanceled   SubscriptionStatus = "canceled"
	SubscriptionStatusUnpaid     SubscriptionStatus = "unpaid"
	SubscriptionStatusIncomplete SubscriptionStatus = "incomplete"
	SubscriptionStatusTrialing   SubscriptionStatus = "trialing"
	SubscriptionStatusPaused     SubscriptionStatus = "paused"
)

// BillingInterval represents the billing frequency
type BillingInterval string

const (
	BillingIntervalDaily   BillingInterval = "day"
	BillingIntervalWeekly  BillingInterval = "week"
	BillingIntervalMonthly BillingInterval = "month"
	BillingIntervalYearly  BillingInterval = "year"
)

// ProrationBehavior represents how to handle proration
type ProrationBehavior string

const (
	ProrationBehaviorCreateProrations ProrationBehavior = "create_prorations"
	ProrationBehaviorNone            ProrationBehavior = "none"
	ProrationBehaviorAlwaysInvoice   ProrationBehavior = "always_invoice"
)

// Subscription represents a customer's subscription to a plan
type Subscription struct {
	ID                     uuid.UUID         `json:"id" db:"id"`
	TenantID               uuid.UUID         `json:"tenant_id" db:"tenant_id"`
	CustomerID             uuid.UUID         `json:"customer_id" db:"customer_id"`
	StripeSubscriptionID   string            `json:"stripe_subscription_id" db:"stripe_subscription_id"`
	PlanID                 uuid.UUID         `json:"plan_id" db:"plan_id"`
	Status                 SubscriptionStatus `json:"status" db:"status"`
	
	// Pricing and billing
	CurrentPeriodStart     time.Time       `json:"current_period_start" db:"current_period_start"`
	CurrentPeriodEnd       time.Time       `json:"current_period_end" db:"current_period_end"`
	BillingCycleAnchor     *time.Time      `json:"billing_cycle_anchor,omitempty" db:"billing_cycle_anchor"`
	
	// Trial information
	TrialStart             *time.Time      `json:"trial_start,omitempty" db:"trial_start"`
	TrialEnd               *time.Time      `json:"trial_end,omitempty" db:"trial_end"`
	
	// Cancellation information
	CancelAt               *time.Time      `json:"cancel_at,omitempty" db:"cancel_at"`
	CancelAtPeriodEnd      bool            `json:"cancel_at_period_end" db:"cancel_at_period_end"`
	CanceledAt             *time.Time      `json:"canceled_at,omitempty" db:"canceled_at"`
	CancellationReason     *string         `json:"cancellation_reason,omitempty" db:"cancellation_reason"`
	
	// Pause information
	PauseCollection        *PauseCollection `json:"pause_collection,omitempty" db:"pause_collection"`
	
	// Payment and collection
	DefaultPaymentMethodID *uuid.UUID      `json:"default_payment_method_id,omitempty" db:"default_payment_method_id"`
	DaysUntilDue           *int           `json:"days_until_due,omitempty" db:"days_until_due"`
	CollectionMethod       string          `json:"collection_method" db:"collection_method"` // "charge_automatically" or "send_invoice"
	
	// Pricing details
	UnitAmount             int64           `json:"unit_amount" db:"unit_amount"` // Amount in cents
	Quantity               int32           `json:"quantity" db:"quantity"`
	Currency               string          `json:"currency" db:"currency"`
	TaxPercent             *float64        `json:"tax_percent,omitempty" db:"tax_percent"`
	
	// Discount information
	DiscountID             *uuid.UUID      `json:"discount_id,omitempty" db:"discount_id"`
	CouponCode             *string         `json:"coupon_code,omitempty" db:"coupon_code"`
	
	// Usage-based billing
	BillingThresholds      *BillingThresholds `json:"billing_thresholds,omitempty" db:"billing_thresholds"`
	
	// Security and compliance
	SecurityClearance      string          `json:"security_clearance" db:"security_clearance"`
	ComplianceFrameworks   []string        `json:"compliance_frameworks" db:"compliance_frameworks"`
	
	// Audit fields
	CreatedAt              time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at" db:"updated_at"`
	CreatedBy              uuid.UUID       `json:"created_by" db:"created_by"`
	UpdatedBy              uuid.UUID       `json:"updated_by" db:"updated_by"`
	
	// Metadata for flexible storage
	Metadata               map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	
	// Calculated fields (not stored in DB)
	Plan                   *SubscriptionPlan `json:"plan,omitempty" db:"-"`
	Customer               *Customer         `json:"customer,omitempty" db:"-"`
	PaymentMethod          *PaymentMethod    `json:"payment_method,omitempty" db:"-"`
}

// PauseCollection represents subscription pause configuration
type PauseCollection struct {
	Behavior        string     `json:"behavior"` // "mark_uncollectible", "keep_as_draft", "void"
	ResumesAt       *time.Time `json:"resumes_at,omitempty"`
	PausedAt        time.Time  `json:"paused_at"`
	PausedBy        uuid.UUID  `json:"paused_by"`
	PauseReason     string     `json:"pause_reason"`
}

// BillingThresholds represents usage-based billing thresholds
type BillingThresholds struct {
	AmountGTE    *int64 `json:"amount_gte,omitempty"`    // Amount in cents
	ResetBilling bool   `json:"reset_billing"`
	UsageGTE     *int64 `json:"usage_gte,omitempty"`     // Usage threshold
}

// Customer placeholder for relationship
type Customer struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	TenantID uuid.UUID `json:"tenant_id"`
}

// IsActive checks if the subscription is currently active
func (s *Subscription) IsActive() bool {
	return s.Status == SubscriptionStatusActive || s.Status == SubscriptionStatusTrialing
}

// IsTrialing checks if the subscription is in trial period
func (s *Subscription) IsTrialing() bool {
	if s.Status != SubscriptionStatusTrialing || s.TrialEnd == nil {
		return false
	}
	return time.Now().Before(*s.TrialEnd)
}

// IsCanceled checks if the subscription is canceled
func (s *Subscription) IsCanceled() bool {
	return s.Status == SubscriptionStatusCanceled
}

// IsPastDue checks if the subscription is past due
func (s *Subscription) IsPastDue() bool {
	return s.Status == SubscriptionStatusPastDue
}

// IsPaused checks if the subscription is currently paused
func (s *Subscription) IsPaused() bool {
	return s.Status == SubscriptionStatusPaused
}

// DaysUntilRenewal calculates days until the next renewal
func (s *Subscription) DaysUntilRenewal() int {
	now := time.Now()
	if now.After(s.CurrentPeriodEnd) {
		return 0
	}
	
	duration := s.CurrentPeriodEnd.Sub(now)
	return int(duration.Hours() / 24)
}

// GetTrialDaysRemaining returns the number of trial days remaining
func (s *Subscription) GetTrialDaysRemaining() int {
	if !s.IsTrialing() {
		return 0
	}
	
	now := time.Now()
	duration := s.TrialEnd.Sub(now)
	days := int(duration.Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// GetMonthlyRecurringRevenue calculates the MRR contribution
func (s *Subscription) GetMonthlyRecurringRevenue() float64 {
	if !s.IsActive() {
		return 0
	}
	
	baseAmount := float64(s.UnitAmount * int64(s.Quantity)) / 100.0 // Convert from cents
	
	// Convert to monthly based on billing interval
	if s.Plan != nil {
		switch s.Plan.Interval {
		case BillingIntervalDaily:
			return baseAmount * 30.44 // Average days per month
		case BillingIntervalWeekly:
			return baseAmount * 4.33 // Average weeks per month
		case BillingIntervalMonthly:
			return baseAmount
		case BillingIntervalYearly:
			return baseAmount / 12.0
		}
	}
	
	return baseAmount
}

// CalculateProrationAmount calculates proration for plan changes
func (s *Subscription) CalculateProrationAmount(newUnitAmount int64, newQuantity int32, changeDate time.Time) int64 {
	if changeDate.Before(s.CurrentPeriodStart) || changeDate.After(s.CurrentPeriodEnd) {
		return 0
	}
	
	// Calculate remaining days in current period
	totalDays := s.CurrentPeriodEnd.Sub(s.CurrentPeriodStart).Hours() / 24
	remainingDays := s.CurrentPeriodEnd.Sub(changeDate).Hours() / 24
	
	if totalDays <= 0 || remainingDays <= 0 {
		return 0
	}
	
	// Calculate current period amount
	currentAmount := s.UnitAmount * int64(s.Quantity)
	newAmount := newUnitAmount * int64(newQuantity)
	
	// Calculate unused amount from current plan
	unusedAmount := int64((remainingDays / totalDays) * float64(currentAmount))
	
	// Calculate prorated amount for new plan
	proratedNewAmount := int64((remainingDays / totalDays) * float64(newAmount))
	
	// Return the difference (positive = credit, negative = charge)
	return proratedNewAmount - unusedAmount
}

// CanUpgrade checks if the subscription can be upgraded
func (s *Subscription) CanUpgrade() bool {
	return s.IsActive() && !s.CancelAtPeriodEnd
}

// CanDowngrade checks if the subscription can be downgraded
func (s *Subscription) CanDowngrade() bool {
	return s.IsActive() && !s.CancelAtPeriodEnd
}

// CanCancel checks if the subscription can be canceled
func (s *Subscription) CanCancel() bool {
	return s.Status == SubscriptionStatusActive || 
		   s.Status == SubscriptionStatusTrialing || 
		   s.Status == SubscriptionStatusPastDue
}

// CanPause checks if the subscription can be paused
func (s *Subscription) CanPause() bool {
	return s.IsActive() && !s.IsPaused()
}

// CanResume checks if the subscription can be resumed
func (s *Subscription) CanResume() bool {
	return s.IsPaused() || s.Status == SubscriptionStatusPastDue
}

// Validate validates the subscription entity
func (s *Subscription) Validate() error {
	if s.ID == uuid.Nil {
		return ErrInvalidSubscriptionID
	}
	
	if s.TenantID == uuid.Nil {
		return ErrInvalidTenantID
	}
	
	if s.CustomerID == uuid.Nil {
		return ErrInvalidCustomerID
	}
	
	if s.PlanID == uuid.Nil {
		return ErrInvalidPlanID
	}
	
	if s.StripeSubscriptionID == "" {
		return ErrInvalidSubscriptionID
	}
	
	if !s.isValidStatus() {
		return ErrInvalidSubscriptionStatus
	}
	
	if s.UnitAmount < 0 {
		return ErrInvalidAmount
	}
	
	if s.Quantity <= 0 {
		return ErrInvalidInput
	}
	
	if s.Currency == "" {
		return ErrInvalidCurrency
	}
	
	if s.CurrentPeriodStart.After(s.CurrentPeriodEnd) {
		return ErrInvalidDateRange
	}
	
	// Validate trial dates if present
	if s.TrialStart != nil && s.TrialEnd != nil {
		if s.TrialStart.After(*s.TrialEnd) {
			return ErrInvalidTrialPeriod
		}
	}
	
	return nil
}

// isValidStatus checks if the subscription status is valid
func (s *Subscription) isValidStatus() bool {
	switch s.Status {
	case SubscriptionStatusPending, SubscriptionStatusActive, SubscriptionStatusPastDue,
		 SubscriptionStatusCanceled, SubscriptionStatusUnpaid, SubscriptionStatusIncomplete,
		 SubscriptionStatusTrialing, SubscriptionStatusPaused:
		return true
	default:
		return false
	}
}

// ToJSON converts the subscription to JSON
func (s *Subscription) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// FromJSON creates a subscription from JSON
func (s *Subscription) FromJSON(data []byte) error {
	return json.Unmarshal(data, s)
}

// Clone creates a deep copy of the subscription
func (s *Subscription) Clone() *Subscription {
	clone := *s
	
	// Deep copy pointers
	if s.BillingCycleAnchor != nil {
		anchor := *s.BillingCycleAnchor
		clone.BillingCycleAnchor = &anchor
	}
	
	if s.TrialStart != nil {
		trialStart := *s.TrialStart
		clone.TrialStart = &trialStart
	}
	
	if s.TrialEnd != nil {
		trialEnd := *s.TrialEnd
		clone.TrialEnd = &trialEnd
	}
	
	if s.CancelAt != nil {
		cancelAt := *s.CancelAt
		clone.CancelAt = &cancelAt
	}
	
	if s.CanceledAt != nil {
		canceledAt := *s.CanceledAt
		clone.CanceledAt = &canceledAt
	}
	
	if s.CancellationReason != nil {
		reason := *s.CancellationReason
		clone.CancellationReason = &reason
	}
	
	if s.DefaultPaymentMethodID != nil {
		pmID := *s.DefaultPaymentMethodID
		clone.DefaultPaymentMethodID = &pmID
	}
	
	if s.DaysUntilDue != nil {
		days := *s.DaysUntilDue
		clone.DaysUntilDue = &days
	}
	
	if s.TaxPercent != nil {
		tax := *s.TaxPercent
		clone.TaxPercent = &tax
	}
	
	if s.DiscountID != nil {
		discountID := *s.DiscountID
		clone.DiscountID = &discountID
	}
	
	if s.CouponCode != nil {
		coupon := *s.CouponCode
		clone.CouponCode = &coupon
	}
	
	// Deep copy complex structures
	if s.PauseCollection != nil {
		pauseClone := *s.PauseCollection
		if s.PauseCollection.ResumesAt != nil {
			resumesAt := *s.PauseCollection.ResumesAt
			pauseClone.ResumesAt = &resumesAt
		}
		clone.PauseCollection = &pauseClone
	}
	
	if s.BillingThresholds != nil {
		thresholds := *s.BillingThresholds
		if s.BillingThresholds.AmountGTE != nil {
			amount := *s.BillingThresholds.AmountGTE
			thresholds.AmountGTE = &amount
		}
		if s.BillingThresholds.UsageGTE != nil {
			usage := *s.BillingThresholds.UsageGTE
			thresholds.UsageGTE = &usage
		}
		clone.BillingThresholds = &thresholds
	}
	
	// Deep copy slices
	if s.ComplianceFrameworks != nil {
		clone.ComplianceFrameworks = make([]string, len(s.ComplianceFrameworks))
		copy(clone.ComplianceFrameworks, s.ComplianceFrameworks)
	}
	
	// Deep copy metadata
	if s.Metadata != nil {
		clone.Metadata = make(map[string]interface{})
		for k, v := range s.Metadata {
			clone.Metadata[k] = v
		}
	}
	
	return &clone
}

// SubscriptionFilter represents filter criteria for subscriptions
type SubscriptionFilter struct {
	TenantID       *uuid.UUID          `json:"tenant_id,omitempty"`
	CustomerID     *uuid.UUID          `json:"customer_id,omitempty"`
	PlanID         *uuid.UUID          `json:"plan_id,omitempty"`
	Status         *SubscriptionStatus `json:"status,omitempty"`
	ActiveOnly     bool                `json:"active_only"`
	TrialingOnly   bool                `json:"trialing_only"`
	PastDueOnly    bool                `json:"past_due_only"`
	
	// Date filters
	CreatedAfter   *time.Time          `json:"created_after,omitempty"`
	CreatedBefore  *time.Time          `json:"created_before,omitempty"`
	TrialEndsBefore *time.Time         `json:"trial_ends_before,omitempty"`
	CurrentPeriodEndsBefore *time.Time `json:"current_period_ends_before,omitempty"`
	
	// Pagination
	Limit          int                 `json:"limit"`
	Offset         int                 `json:"offset"`
	
	// Sorting
	SortBy         string              `json:"sort_by"`
	SortOrder      string              `json:"sort_order"`
}

// NewSubscription creates a new subscription instance
func NewSubscription(
	tenantID, customerID, planID uuid.UUID,
	stripeSubscriptionID string,
	createdBy uuid.UUID,
) *Subscription {
	now := time.Now()
	
	return &Subscription{
		ID:                   uuid.New(),
		TenantID:             tenantID,
		CustomerID:           customerID,
		PlanID:               planID,
		StripeSubscriptionID: stripeSubscriptionID,
		Status:               SubscriptionStatusPending,
		Quantity:             1,
		CollectionMethod:     "charge_automatically",
		SecurityClearance:    "unclassified",
		CreatedAt:            now,
		UpdatedAt:            now,
		CreatedBy:            createdBy,
		UpdatedBy:            createdBy,
		Metadata:             make(map[string]interface{}),
	}
}