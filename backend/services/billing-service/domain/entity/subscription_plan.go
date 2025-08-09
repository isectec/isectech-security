package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PlanStatus represents the status of a subscription plan
type PlanStatus string

const (
	PlanStatusActive   PlanStatus = "active"
	PlanStatusInactive PlanStatus = "inactive"
	PlanStatusArchived PlanStatus = "archived"
)

// PricingModel represents different pricing models
type PricingModel string

const (
	PricingModelFlat        PricingModel = "flat"
	PricingModelPerSeat     PricingModel = "per_seat"
	PricingModelUsageBased  PricingModel = "usage_based"
	PricingModelTiered      PricingModel = "tiered"
	PricingModelVolume      PricingModel = "volume"
)

// AggregateUsage represents how usage is aggregated
type AggregateUsage string

const (
	AggregateUsageSum         AggregateUsage = "sum"
	AggregateUsageLastDuringPeriod AggregateUsage = "last_during_period"
	AggregateUsageLastEver    AggregateUsage = "last_ever"
	AggregateUsageMax         AggregateUsage = "max"
)

// UsageType represents how usage is measured
type UsageType string

const (
	UsageTypeLicensed UsageType = "licensed"
	UsageTypeMetered  UsageType = "metered"
)

// SubscriptionPlan represents a billing plan for subscriptions
type SubscriptionPlan struct {
	ID                 uuid.UUID     `json:"id" db:"id"`
	TenantID           uuid.UUID     `json:"tenant_id" db:"tenant_id"`
	StripePlanID       string        `json:"stripe_plan_id" db:"stripe_plan_id"`
	StripePriceID      string        `json:"stripe_price_id" db:"stripe_price_id"`
	Name               string        `json:"name" db:"name"`
	Description        *string       `json:"description,omitempty" db:"description"`
	Status             PlanStatus    `json:"status" db:"status"`
	
	// Pricing configuration
	PricingModel       PricingModel  `json:"pricing_model" db:"pricing_model"`
	UnitAmount         int64         `json:"unit_amount" db:"unit_amount"` // Amount in cents
	Currency           string        `json:"currency" db:"currency"`
	Interval           BillingInterval `json:"interval" db:"interval"`
	IntervalCount      int32         `json:"interval_count" db:"interval_count"`
	
	// Usage-based billing
	UsageType          *UsageType     `json:"usage_type,omitempty" db:"usage_type"`
	AggregateUsage     *AggregateUsage `json:"aggregate_usage,omitempty" db:"aggregate_usage"`
	MeteredUnit        *string        `json:"metered_unit,omitempty" db:"metered_unit"`
	
	// Trial configuration
	TrialPeriodDays    *int32        `json:"trial_period_days,omitempty" db:"trial_period_days"`
	
	// Plan limits and features
	Features           []PlanFeature `json:"features" db:"features"`
	Limits             *PlanLimits   `json:"limits,omitempty" db:"limits"`
	
	// Pricing tiers (for tiered/volume pricing)
	PricingTiers       []PricingTier `json:"pricing_tiers,omitempty" db:"pricing_tiers"`
	
	// Security and compliance
	SecurityClearanceRequired string   `json:"security_clearance_required" db:"security_clearance_required"`
	ComplianceFrameworks      []string `json:"compliance_frameworks" db:"compliance_frameworks"`
	
	// Plan availability
	PubliclyAvailable  bool          `json:"publicly_available" db:"publicly_available"`
	AvailableFrom      *time.Time    `json:"available_from,omitempty" db:"available_from"`
	AvailableUntil     *time.Time    `json:"available_until,omitempty" db:"available_until"`
	MaxSubscriptions   *int32        `json:"max_subscriptions,omitempty" db:"max_subscriptions"`
	
	// Tax configuration
	TaxBehavior        string        `json:"tax_behavior" db:"tax_behavior"` // "inclusive", "exclusive", "unspecified"
	TaxCode            *string       `json:"tax_code,omitempty" db:"tax_code"`
	
	// Audit fields
	CreatedAt          time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time     `json:"updated_at" db:"updated_at"`
	CreatedBy          uuid.UUID     `json:"created_by" db:"created_by"`
	UpdatedBy          uuid.UUID     `json:"updated_by" db:"updated_by"`
	ArchivedAt         *time.Time    `json:"archived_at,omitempty" db:"archived_at"`
	
	// Metadata for flexible storage
	Metadata           map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// PlanFeature represents a feature included in a plan
type PlanFeature struct {
	Name        string      `json:"name"`
	Description *string     `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Limit       interface{} `json:"limit,omitempty"` // Can be int, string, bool, etc.
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PlanLimits represents various limits for a plan
type PlanLimits struct {
	MaxUsers              *int32   `json:"max_users,omitempty"`
	MaxProjects           *int32   `json:"max_projects,omitempty"`
	MaxStorageGB          *int32   `json:"max_storage_gb,omitempty"`
	MaxAPICallsPerMonth   *int64   `json:"max_api_calls_per_month,omitempty"`
	MaxIntegrations       *int32   `json:"max_integrations,omitempty"`
	MaxCustomFields       *int32   `json:"max_custom_fields,omitempty"`
	MaxReports            *int32   `json:"max_reports,omitempty"`
	MaxAutomationRules    *int32   `json:"max_automation_rules,omitempty"`
	SupportLevel          *string  `json:"support_level,omitempty"`
	CustomIntegrations    bool     `json:"custom_integrations"`
	AdvancedAnalytics     bool     `json:"advanced_analytics"`
	SSO                   bool     `json:"sso"`
	AuditLogs             bool     `json:"audit_logs"`
	ComplianceReporting   bool     `json:"compliance_reporting"`
	SecurityClearanceLevel *string `json:"security_clearance_level,omitempty"`
}

// PricingTier represents a pricing tier for tiered or volume pricing
type PricingTier struct {
	UpTo       *int64  `json:"up_to,omitempty"`      // null means "infinity"
	UnitAmount int64   `json:"unit_amount"`          // Amount in cents
	FlatAmount *int64  `json:"flat_amount,omitempty"` // Flat fee for this tier
}

// IsActive checks if the plan is currently active
func (p *SubscriptionPlan) IsActive() bool {
	if p.Status != PlanStatusActive {
		return false
	}
	
	now := time.Now()
	
	// Check availability window
	if p.AvailableFrom != nil && now.Before(*p.AvailableFrom) {
		return false
	}
	
	if p.AvailableUntil != nil && now.After(*p.AvailableUntil) {
		return false
	}
	
	return true
}

// IsArchived checks if the plan is archived
func (p *SubscriptionPlan) IsArchived() bool {
	return p.Status == PlanStatusArchived
}

// HasTrial checks if the plan includes a trial period
func (p *SubscriptionPlan) HasTrial() bool {
	return p.TrialPeriodDays != nil && *p.TrialPeriodDays > 0
}

// IsUsageBased checks if the plan uses usage-based billing
func (p *SubscriptionPlan) IsUsageBased() bool {
	return p.PricingModel == PricingModelUsageBased || 
		   p.PricingModel == PricingModelTiered ||
		   p.PricingModel == PricingModelVolume
}

// GetMonthlyAmount calculates the monthly amount for this plan
func (p *SubscriptionPlan) GetMonthlyAmount() float64 {
	baseAmount := float64(p.UnitAmount) / 100.0 // Convert from cents
	
	switch p.Interval {
	case BillingIntervalDaily:
		return baseAmount * 30.44 * float64(p.IntervalCount) // Average days per month
	case BillingIntervalWeekly:
		return baseAmount * 4.33 * float64(p.IntervalCount) // Average weeks per month
	case BillingIntervalMonthly:
		return baseAmount * float64(p.IntervalCount)
	case BillingIntervalYearly:
		return (baseAmount * float64(p.IntervalCount)) / 12.0
	}
	
	return baseAmount
}

// CalculateUsageAmount calculates the amount for usage-based billing
func (p *SubscriptionPlan) CalculateUsageAmount(usage int64) int64 {
	if !p.IsUsageBased() || len(p.PricingTiers) == 0 {
		return p.UnitAmount * usage
	}
	
	var totalAmount int64
	remainingUsage := usage
	
	for _, tier := range p.PricingTiers {
		if remainingUsage <= 0 {
			break
		}
		
		var tierUsage int64
		if tier.UpTo == nil {
			// Infinite tier
			tierUsage = remainingUsage
		} else {
			tierUsage = min(remainingUsage, *tier.UpTo)
		}
		
		// Add flat amount for this tier (if any)
		if tier.FlatAmount != nil {
			totalAmount += *tier.FlatAmount
		}
		
		// Add usage-based amount for this tier
		totalAmount += tierUsage * tier.UnitAmount
		
		remainingUsage -= tierUsage
	}
	
	return totalAmount
}

// HasFeature checks if a specific feature is enabled in the plan
func (p *SubscriptionPlan) HasFeature(featureName string) bool {
	for _, feature := range p.Features {
		if feature.Name == featureName {
			return feature.Enabled
		}
	}
	return false
}

// GetFeatureLimit returns the limit for a specific feature
func (p *SubscriptionPlan) GetFeatureLimit(featureName string) interface{} {
	for _, feature := range p.Features {
		if feature.Name == featureName && feature.Enabled {
			return feature.Limit
		}
	}
	return nil
}

// CanSupportSecurityClearance checks if the plan supports a security clearance level
func (p *SubscriptionPlan) CanSupportSecurityClearance(clearance string) bool {
	clearanceLevels := map[string]int{
		"unclassified": 0,
		"cui":          1,
		"confidential": 2,
		"secret":       3,
		"top_secret":   4,
	}
	
	requiredLevel, exists := clearanceLevels[p.SecurityClearanceRequired]
	if !exists {
		requiredLevel = 0
	}
	
	requestedLevel, exists := clearanceLevels[clearance]
	if !exists {
		requestedLevel = 0
	}
	
	return requestedLevel >= requiredLevel
}

// Validate validates the subscription plan entity
func (p *SubscriptionPlan) Validate() error {
	if p.ID == uuid.Nil {
		return ErrInvalidPlanID
	}
	
	if p.TenantID == uuid.Nil {
		return ErrInvalidTenantID
	}
	
	if p.Name == "" {
		return ErrInvalidPlanName
	}
	
	if p.UnitAmount < 0 {
		return ErrInvalidPlanPrice
	}
	
	if p.Currency == "" {
		return ErrInvalidCurrency
	}
	
	if !p.isValidInterval() {
		return ErrInvalidPlanInterval
	}
	
	if p.IntervalCount <= 0 {
		return ErrInvalidPlanInterval
	}
	
	if !p.isValidStatus() {
		return ErrInvalidPlanID
	}
	
	if !p.isValidPricingModel() {
		return ErrInvalidPlanPrice
	}
	
	// Validate pricing tiers if present
	if p.IsUsageBased() && len(p.PricingTiers) > 0 {
		if err := p.validatePricingTiers(); err != nil {
			return err
		}
	}
	
	// Validate trial period
	if p.TrialPeriodDays != nil && *p.TrialPeriodDays < 0 {
		return ErrInvalidTrialPeriod
	}
	
	// Validate availability dates
	if p.AvailableFrom != nil && p.AvailableUntil != nil {
		if p.AvailableFrom.After(*p.AvailableUntil) {
			return ErrInvalidDateRange
		}
	}
	
	return nil
}

// isValidStatus checks if the plan status is valid
func (p *SubscriptionPlan) isValidStatus() bool {
	switch p.Status {
	case PlanStatusActive, PlanStatusInactive, PlanStatusArchived:
		return true
	default:
		return false
	}
}

// isValidInterval checks if the billing interval is valid
func (p *SubscriptionPlan) isValidInterval() bool {
	switch p.Interval {
	case BillingIntervalDaily, BillingIntervalWeekly, BillingIntervalMonthly, BillingIntervalYearly:
		return true
	default:
		return false
	}
}

// isValidPricingModel checks if the pricing model is valid
func (p *SubscriptionPlan) isValidPricingModel() bool {
	switch p.PricingModel {
	case PricingModelFlat, PricingModelPerSeat, PricingModelUsageBased, PricingModelTiered, PricingModelVolume:
		return true
	default:
		return false
	}
}

// validatePricingTiers validates the pricing tiers configuration
func (p *SubscriptionPlan) validatePricingTiers() error {
	if len(p.PricingTiers) == 0 {
		return nil
	}
	
	var lastUpTo int64 = 0
	hasInfiniteTier := false
	
	for i, tier := range p.PricingTiers {
		if tier.UnitAmount < 0 {
			return ErrInvalidAmount
		}
		
		if tier.FlatAmount != nil && *tier.FlatAmount < 0 {
			return ErrInvalidAmount
		}
		
		if tier.UpTo == nil {
			// Infinite tier
			if hasInfiniteTier {
				return ErrInvalidInput // Can't have multiple infinite tiers
			}
			hasInfiniteTier = true
			
			// Infinite tier must be last
			if i != len(p.PricingTiers)-1 {
				return ErrInvalidInput
			}
		} else {
			if *tier.UpTo <= lastUpTo {
				return ErrInvalidInput // Tiers must be in ascending order
			}
			lastUpTo = *tier.UpTo
		}
	}
	
	return nil
}

// ToJSON converts the plan to JSON
func (p *SubscriptionPlan) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// FromJSON creates a plan from JSON
func (p *SubscriptionPlan) FromJSON(data []byte) error {
	return json.Unmarshal(data, p)
}

// Clone creates a deep copy of the subscription plan
func (p *SubscriptionPlan) Clone() *SubscriptionPlan {
	clone := *p
	
	// Deep copy pointers
	if p.Description != nil {
		desc := *p.Description
		clone.Description = &desc
	}
	
	if p.UsageType != nil {
		ut := *p.UsageType
		clone.UsageType = &ut
	}
	
	if p.AggregateUsage != nil {
		au := *p.AggregateUsage
		clone.AggregateUsage = &au
	}
	
	if p.MeteredUnit != nil {
		mu := *p.MeteredUnit
		clone.MeteredUnit = &mu
	}
	
	if p.TrialPeriodDays != nil {
		tpd := *p.TrialPeriodDays
		clone.TrialPeriodDays = &tpd
	}
	
	if p.AvailableFrom != nil {
		af := *p.AvailableFrom
		clone.AvailableFrom = &af
	}
	
	if p.AvailableUntil != nil {
		au := *p.AvailableUntil
		clone.AvailableUntil = &au
	}
	
	if p.MaxSubscriptions != nil {
		ms := *p.MaxSubscriptions
		clone.MaxSubscriptions = &ms
	}
	
	if p.TaxCode != nil {
		tc := *p.TaxCode
		clone.TaxCode = &tc
	}
	
	if p.ArchivedAt != nil {
		aa := *p.ArchivedAt
		clone.ArchivedAt = &aa
	}
	
	// Deep copy slices
	if p.Features != nil {
		clone.Features = make([]PlanFeature, len(p.Features))
		for i, feature := range p.Features {
			clone.Features[i] = feature
			if feature.Description != nil {
				desc := *feature.Description
				clone.Features[i].Description = &desc
			}
			// Deep copy metadata
			if feature.Metadata != nil {
				clone.Features[i].Metadata = make(map[string]interface{})
				for k, v := range feature.Metadata {
					clone.Features[i].Metadata[k] = v
				}
			}
		}
	}
	
	if p.PricingTiers != nil {
		clone.PricingTiers = make([]PricingTier, len(p.PricingTiers))
		for i, tier := range p.PricingTiers {
			clone.PricingTiers[i] = tier
			if tier.UpTo != nil {
				upTo := *tier.UpTo
				clone.PricingTiers[i].UpTo = &upTo
			}
			if tier.FlatAmount != nil {
				flat := *tier.FlatAmount
				clone.PricingTiers[i].FlatAmount = &flat
			}
		}
	}
	
	if p.ComplianceFrameworks != nil {
		clone.ComplianceFrameworks = make([]string, len(p.ComplianceFrameworks))
		copy(clone.ComplianceFrameworks, p.ComplianceFrameworks)
	}
	
	// Deep copy complex structures
	if p.Limits != nil {
		limitsClone := *p.Limits
		// Copy all pointer fields
		if p.Limits.MaxUsers != nil {
			mu := *p.Limits.MaxUsers
			limitsClone.MaxUsers = &mu
		}
		if p.Limits.MaxProjects != nil {
			mp := *p.Limits.MaxProjects
			limitsClone.MaxProjects = &mp
		}
		if p.Limits.MaxStorageGB != nil {
			ms := *p.Limits.MaxStorageGB
			limitsClone.MaxStorageGB = &ms
		}
		if p.Limits.MaxAPICallsPerMonth != nil {
			mac := *p.Limits.MaxAPICallsPerMonth
			limitsClone.MaxAPICallsPerMonth = &mac
		}
		if p.Limits.MaxIntegrations != nil {
			mi := *p.Limits.MaxIntegrations
			limitsClone.MaxIntegrations = &mi
		}
		if p.Limits.MaxCustomFields != nil {
			mcf := *p.Limits.MaxCustomFields
			limitsClone.MaxCustomFields = &mcf
		}
		if p.Limits.MaxReports != nil {
			mr := *p.Limits.MaxReports
			limitsClone.MaxReports = &mr
		}
		if p.Limits.MaxAutomationRules != nil {
			mar := *p.Limits.MaxAutomationRules
			limitsClone.MaxAutomationRules = &mar
		}
		if p.Limits.SupportLevel != nil {
			sl := *p.Limits.SupportLevel
			limitsClone.SupportLevel = &sl
		}
		if p.Limits.SecurityClearanceLevel != nil {
			scl := *p.Limits.SecurityClearanceLevel
			limitsClone.SecurityClearanceLevel = &scl
		}
		clone.Limits = &limitsClone
	}
	
	// Deep copy metadata
	if p.Metadata != nil {
		clone.Metadata = make(map[string]interface{})
		for k, v := range p.Metadata {
			clone.Metadata[k] = v
		}
	}
	
	return &clone
}

// SubscriptionPlanFilter represents filter criteria for subscription plans
type SubscriptionPlanFilter struct {
	TenantID              *uuid.UUID    `json:"tenant_id,omitempty"`
	Status                *PlanStatus   `json:"status,omitempty"`
	PricingModel          *PricingModel `json:"pricing_model,omitempty"`
	Interval              *BillingInterval `json:"interval,omitempty"`
	ActiveOnly            bool          `json:"active_only"`
	PubliclyAvailableOnly bool          `json:"publicly_available_only"`
	HasTrial              *bool         `json:"has_trial,omitempty"`
	
	// Security filters
	SecurityClearance     *string       `json:"security_clearance,omitempty"`
	
	// Pagination
	Limit                 int           `json:"limit"`
	Offset                int           `json:"offset"`
	
	// Sorting
	SortBy                string        `json:"sort_by"`
	SortOrder             string        `json:"sort_order"`
}

// NewSubscriptionPlan creates a new subscription plan instance
func NewSubscriptionPlan(
	tenantID uuid.UUID,
	name string,
	unitAmount int64,
	currency string,
	interval BillingInterval,
	createdBy uuid.UUID,
) *SubscriptionPlan {
	now := time.Now()
	
	return &SubscriptionPlan{
		ID:                        uuid.New(),
		TenantID:                  tenantID,
		Name:                      name,
		Status:                    PlanStatusActive,
		PricingModel:              PricingModelFlat,
		UnitAmount:                unitAmount,
		Currency:                  currency,
		Interval:                  interval,
		IntervalCount:             1,
		SecurityClearanceRequired: "unclassified",
		PubliclyAvailable:         true,
		TaxBehavior:               "exclusive",
		CreatedAt:                 now,
		UpdatedAt:                 now,
		CreatedBy:                 createdBy,
		UpdatedBy:                 createdBy,
		Features:                  make([]PlanFeature, 0),
		PricingTiers:              make([]PricingTier, 0),
		ComplianceFrameworks:      make([]string, 0),
		Metadata:                  make(map[string]interface{}),
	}
}

// min helper function
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}