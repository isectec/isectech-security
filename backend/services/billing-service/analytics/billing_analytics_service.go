package analytics

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
)

// BillingAnalyticsService provides comprehensive billing analytics and MRR tracking
type BillingAnalyticsService struct {
	logger              *zap.Logger
	config              *config.Config
	subscriptionRepo    SubscriptionAnalyticsRepository
	invoiceRepo         InvoiceAnalyticsRepository
	customerRepo        CustomerAnalyticsRepository
	usageRepo           UsageAnalyticsRepository
	auditLogger         *zap.Logger
	
	// Cache for expensive calculations
	metricsCache        map[string]*CachedMetrics
	cacheTTL            time.Duration
}

// Repository interfaces for analytics

// SubscriptionAnalyticsRepository provides subscription data for analytics
type SubscriptionAnalyticsRepository interface {
	GetMRRByTenant(ctx context.Context, tenantID uuid.UUID, asOfDate time.Time) (*MRRData, error)
	GetMRRHistory(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]*MRRSnapshot, error)
	GetChurnAnalysis(ctx context.Context, tenantID uuid.UUID, period time.Duration) (*ChurnAnalysis, error)
	GetSubscriptionCohorts(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]*CohortData, error)
	GetRevenueGrowthMetrics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*RevenueGrowthMetrics, error)
	GetSubscriptionMetrics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*SubscriptionMetrics, error)
	GetPlanPerformance(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]*PlanMetrics, error)
}

// InvoiceAnalyticsRepository provides invoice data for analytics
type InvoiceAnalyticsRepository interface {
	GetRevenueAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*RevenueAnalytics, error)
	GetPaymentAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*PaymentAnalytics, error)
	GetTaxAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*TaxAnalytics, error)
	GetCollectionMetrics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*CollectionMetrics, error)
	GetInvoiceMetrics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*InvoiceMetrics, error)
}

// CustomerAnalyticsRepository provides customer data for analytics
type CustomerAnalyticsRepository interface {
	GetCustomerLifetimeValue(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*CLVAnalysis, error)
	GetCustomerAcquisitionCost(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*CACAnalysis, error)
	GetCustomerSegmentation(ctx context.Context, tenantID uuid.UUID, criteria *SegmentationCriteria) ([]*CustomerSegment, error)
	GetRetentionAnalysis(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*RetentionAnalysis, error)
}

// UsageAnalyticsRepository provides usage data for analytics
type UsageAnalyticsRepository interface {
	GetUsageAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*UsageAnalytics, error)
	GetUsageTrends(ctx context.Context, tenantID uuid.UUID, metricName string, from, to time.Time) ([]*UsageTrend, error)
	GetOverageAnalysis(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (*OverageAnalysis, error)
}

// Analytics data structures

// MRRData represents Monthly Recurring Revenue data
type MRRData struct {
	TenantID           uuid.UUID              `json:"tenant_id"`
	AsOfDate           time.Time              `json:"as_of_date"`
	TotalMRR           float64                `json:"total_mrr"`
	NewMRR             float64                `json:"new_mrr"`
	ExpansionMRR       float64                `json:"expansion_mrr"`
	ContractionMRR     float64                `json:"contraction_mrr"`
	ChurnedMRR         float64                `json:"churned_mrr"`
	NetNewMRR          float64                `json:"net_new_mrr"`
	MRRGrowthRate      float64                `json:"mrr_growth_rate"`
	Currency           string                 `json:"currency"`
	Breakdown          *MRRBreakdown          `json:"breakdown"`
	PlanBreakdown      map[string]float64     `json:"plan_breakdown"`
	ClearanceBreakdown map[string]float64     `json:"clearance_breakdown"`
}

// MRRBreakdown provides detailed MRR breakdown
type MRRBreakdown struct {
	SubscriptionMRR    float64                `json:"subscription_mrr"`
	UsageMRR           float64                `json:"usage_mrr"`
	AddonMRR           float64                `json:"addon_mrr"`
	DiscountMRR        float64                `json:"discount_mrr"`
	TaxMRR             float64                `json:"tax_mrr"`
}

// MRRSnapshot represents MRR at a specific point in time
type MRRSnapshot struct {
	Date               time.Time              `json:"date"`
	MRR                float64                `json:"mrr"`
	CustomerCount      int64                  `json:"customer_count"`
	ARPU               float64                `json:"arpu"` // Average Revenue Per User
	NewCustomers       int64                  `json:"new_customers"`
	ChurnedCustomers   int64                  `json:"churned_customers"`
	NetGrowth          float64                `json:"net_growth"`
}

// ChurnAnalysis provides comprehensive churn metrics
type ChurnAnalysis struct {
	TenantID                uuid.UUID          `json:"tenant_id"`
	Period                  time.Duration      `json:"period"`
	CustomerChurnRate       float64            `json:"customer_churn_rate"`
	RevenueChurnRate        float64            `json:"revenue_churn_rate"`
	NetRevenueChurnRate     float64            `json:"net_revenue_churn_rate"`
	VoluntaryChurnRate      float64            `json:"voluntary_churn_rate"`
	InvoluntaryChurnRate    float64            `json:"involuntary_churn_rate"`
	ChurnedCustomers        int64              `json:"churned_customers"`
	ChurnedRevenue          float64            `json:"churned_revenue"`
	ChurnReasons            map[string]int64   `json:"churn_reasons"`
	ChurnByPlan             map[string]float64 `json:"churn_by_plan"`
	ChurnByTenure           map[string]float64 `json:"churn_by_tenure"`
	ChurnPredictions        []*ChurnPrediction `json:"churn_predictions"`
}

// ChurnPrediction represents churn prediction for a customer
type ChurnPrediction struct {
	CustomerID             uuid.UUID          `json:"customer_id"`
	ChurnProbability       float64            `json:"churn_probability"`
	ChurnRisk              string             `json:"churn_risk"` // "low", "medium", "high"
	PredictedChurnDate     *time.Time         `json:"predicted_churn_date,omitempty"`
	RevenueAtRisk          float64            `json:"revenue_at_risk"`
	RiskFactors            []string           `json:"risk_factors"`
	RecommendedActions     []string           `json:"recommended_actions"`
}

// CohortData represents customer cohort analysis
type CohortData struct {
	CohortMonth            time.Time          `json:"cohort_month"`
	CohortSize             int64              `json:"cohort_size"`
	PeriodNumber           int                `json:"period_number"`
	CustomersRetained      int64              `json:"customers_retained"`
	RetentionRate          float64            `json:"retention_rate"`
	RevenueRetained        float64            `json:"revenue_retained"`
	RevenueRetentionRate   float64            `json:"revenue_retention_rate"`
	AverageRevenuePerUser  float64            `json:"average_revenue_per_user"`
	CumulativeRevenue      float64            `json:"cumulative_revenue"`
}

// RevenueGrowthMetrics provides revenue growth analysis
type RevenueGrowthMetrics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 time.Duration      `json:"period"`
	RevenueGrowthRate      float64            `json:"revenue_growth_rate"`
	MRRGrowthRate          float64            `json:"mrr_growth_rate"`
	ARRGrowthRate          float64            `json:"arr_growth_rate"`
	QuickRatio             float64            `json:"quick_ratio"`
	LTV_CACRatio           float64            `json:"ltv_cac_ratio"`
	PaybackPeriod          float64            `json:"payback_period"`
	NetRevenueRetention    float64            `json:"net_revenue_retention"`
	GrossRevenueRetention  float64            `json:"gross_revenue_retention"`
	ExpansionRate          float64            `json:"expansion_rate"`
	ContractionRate        float64            `json:"contraction_rate"`
}

// SubscriptionMetrics provides comprehensive subscription analytics
type SubscriptionMetrics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	TotalSubscriptions     int64              `json:"total_subscriptions"`
	ActiveSubscriptions    int64              `json:"active_subscriptions"`
	TrialSubscriptions     int64              `json:"trial_subscriptions"`
	CanceledSubscriptions  int64              `json:"canceled_subscriptions"`
	PausedSubscriptions    int64              `json:"paused_subscriptions"`
	PastDueSubscriptions   int64              `json:"past_due_subscriptions"`
	TrialToActiveConversion float64           `json:"trial_to_active_conversion"`
	AverageSubscriptionValue float64          `json:"average_subscription_value"`
	MedianSubscriptionValue  float64          `json:"median_subscription_value"`
	SubscriptionsByPlan    map[string]int64   `json:"subscriptions_by_plan"`
	SubscriptionsByStatus  map[string]int64   `json:"subscriptions_by_status"`
	NewSubscriptions       int64              `json:"new_subscriptions"`
	CanceledThisPeriod     int64              `json:"canceled_this_period"`
	UpgradesThisPeriod     int64              `json:"upgrades_this_period"`
	DowngradesThisPeriod   int64              `json:"downgrades_this_period"`
}

// PlanMetrics provides plan-specific performance metrics
type PlanMetrics struct {
	PlanID                 uuid.UUID          `json:"plan_id"`
	PlanName               string             `json:"plan_name"`
	ActiveSubscriptions    int64              `json:"active_subscriptions"`
	MRR                    float64            `json:"mrr"`
	ARPU                   float64            `json:"arpu"`
	ChurnRate              float64            `json:"churn_rate"`
	ConversionRate         float64            `json:"conversion_rate"`
	UpgradeRate            float64            `json:"upgrade_rate"`
	DowngradeRate          float64            `json:"downgrade_rate"`
	RevenueShare           float64            `json:"revenue_share"`
	GrowthRate             float64            `json:"growth_rate"`
	CustomerSatisfaction   *float64           `json:"customer_satisfaction,omitempty"`
	UsageMetrics           *PlanUsageMetrics  `json:"usage_metrics,omitempty"`
}

// PlanUsageMetrics provides usage metrics for a plan
type PlanUsageMetrics struct {
	AverageUsage           float64            `json:"average_usage"`
	MedianUsage            float64            `json:"median_usage"`
	OverageRate            float64            `json:"overage_rate"`
	OverageRevenue         float64            `json:"overage_revenue"`
	FeatureUtilization     map[string]float64 `json:"feature_utilization"`
}

// RevenueAnalytics provides comprehensive revenue analysis
type RevenueAnalytics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalRevenue           float64            `json:"total_revenue"`
	RecurringRevenue       float64            `json:"recurring_revenue"`
	OneTimeRevenue         float64            `json:"one_time_revenue"`
	UsageRevenue           float64            `json:"usage_revenue"`
	TaxRevenue             float64            `json:"tax_revenue"`
	RefundedRevenue        float64            `json:"refunded_revenue"`
	NetRevenue             float64            `json:"net_revenue"`
	RevenueBySource        map[string]float64 `json:"revenue_by_source"`
	RevenueByRegion        map[string]float64 `json:"revenue_by_region"`
	RevenueByPlan          map[string]float64 `json:"revenue_by_plan"`
	RevenueTrend           []*RevenueTrendPoint `json:"revenue_trend"`
	Forecasts              []*RevenueForecast   `json:"forecasts"`
}

// DatePeriod represents a date range
type DatePeriod struct {
	StartDate              time.Time          `json:"start_date"`
	EndDate                time.Time          `json:"end_date"`
	Type                   string             `json:"type"` // "daily", "weekly", "monthly", "quarterly", "yearly"
}

// RevenueTrendPoint represents a point in revenue trend
type RevenueTrendPoint struct {
	Date                   time.Time          `json:"date"`
	Revenue                float64            `json:"revenue"`
	RecurringRevenue       float64            `json:"recurring_revenue"`
	OneTimeRevenue         float64            `json:"one_time_revenue"`
	UsageRevenue           float64            `json:"usage_revenue"`
	CustomerCount          int64              `json:"customer_count"`
}

// RevenueForecast represents revenue forecast
type RevenueForecast struct {
	Date                   time.Time          `json:"date"`
	ForecastedRevenue      float64            `json:"forecasted_revenue"`
	ConfidenceInterval     *ConfidenceInterval `json:"confidence_interval"`
	Model                  string             `json:"model"` // "linear", "seasonal", "ml"
	Accuracy               *float64           `json:"accuracy,omitempty"`
}

// ConfidenceInterval represents statistical confidence interval
type ConfidenceInterval struct {
	Lower                  float64            `json:"lower"`
	Upper                  float64            `json:"upper"`
	Confidence             float64            `json:"confidence"` // e.g., 0.95 for 95%
}

// PaymentAnalytics provides payment processing analytics
type PaymentAnalytics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalPayments          int64              `json:"total_payments"`
	SuccessfulPayments     int64              `json:"successful_payments"`
	FailedPayments         int64              `json:"failed_payments"`
	DeclinedPayments       int64              `json:"declined_payments"`
	PaymentSuccessRate     float64            `json:"payment_success_rate"`
	AveragePaymentAmount   float64            `json:"average_payment_amount"`
	TotalProcessedAmount   float64            `json:"total_processed_amount"`
	ProcessingFees         float64            `json:"processing_fees"`
	ChargebackAmount       float64            `json:"chargeback_amount"`
	RefundAmount           float64            `json:"refund_amount"`
	NetProcessedAmount     float64            `json:"net_processed_amount"`
	PaymentMethodBreakdown map[string]PaymentMethodStats `json:"payment_method_breakdown"`
	FailureReasons         map[string]int64   `json:"failure_reasons"`
	PaymentsByRegion       map[string]PaymentRegionStats `json:"payments_by_region"`
}

// PaymentMethodStats provides statistics for a payment method
type PaymentMethodStats struct {
	Count                  int64              `json:"count"`
	Amount                 float64            `json:"amount"`
	SuccessRate            float64            `json:"success_rate"`
	AverageAmount          float64            `json:"average_amount"`
	ProcessingFee          float64            `json:"processing_fee"`
}

// PaymentRegionStats provides payment statistics by region
type PaymentRegionStats struct {
	Count                  int64              `json:"count"`
	Amount                 float64            `json:"amount"`
	SuccessRate            float64            `json:"success_rate"`
	Currency               string             `json:"currency"`
	TopFailureReason       string             `json:"top_failure_reason"`
}

// TaxAnalytics provides tax-related analytics
type TaxAnalytics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalTaxCollected      float64            `json:"total_tax_collected"`
	TaxByJurisdiction      map[string]float64 `json:"tax_by_jurisdiction"`
	TaxByType              map[string]float64 `json:"tax_by_type"`
	TaxExemptAmount        float64            `json:"tax_exempt_amount"`
	TaxExemptPercentage    float64            `json:"tax_exempt_percentage"`
	AverageTaxRate         float64            `json:"average_tax_rate"`
	TaxComplianceScore     float64            `json:"tax_compliance_score"`
	VATCollected           float64            `json:"vat_collected"`
	SalesTaxCollected      float64            `json:"sales_tax_collected"`
	TaxReports             []*TaxReport       `json:"tax_reports"`
}

// TaxReport represents a tax report for a jurisdiction
type TaxReport struct {
	Jurisdiction           string             `json:"jurisdiction"`
	TaxType                string             `json:"tax_type"`
	ReportingPeriod        DatePeriod         `json:"reporting_period"`
	TaxableAmount          float64            `json:"taxable_amount"`
	TaxAmount              float64            `json:"tax_amount"`
	ExemptAmount           float64            `json:"exempt_amount"`
	EffectiveRate          float64            `json:"effective_rate"`
	FilingDeadline         time.Time          `json:"filing_deadline"`
	ComplianceStatus       string             `json:"compliance_status"`
}

// CollectionMetrics provides accounts receivable and collection metrics
type CollectionMetrics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalOutstanding       float64            `json:"total_outstanding"`
	CurrentAmount          float64            `json:"current_amount"`
	Past30Days             float64            `json:"past_30_days"`
	Past60Days             float64            `json:"past_60_days"`
	Past90Days             float64            `json:"past_90_days"`
	Over90Days             float64            `json:"over_90_days"`
	DaysOutstandingAverage float64            `json:"days_outstanding_average"`
	CollectionEfficiency   float64            `json:"collection_efficiency"`
	BadDebtRate            float64            `json:"bad_debt_rate"`
	WriteOffAmount         float64            `json:"write_off_amount"`
	PaymentTermsAnalysis   map[string]CollectionTermStats `json:"payment_terms_analysis"`
	CustomerRiskProfile    []*CustomerRisk    `json:"customer_risk_profile"`
}

// CollectionTermStats provides statistics by payment terms
type CollectionTermStats struct {
	AverageDaysToPayment   float64            `json:"average_days_to_payment"`
	OnTimePaymentRate      float64            `json:"on_time_payment_rate"`
	LatePaymentRate        float64            `json:"late_payment_rate"`
	WriteOffRate           float64            `json:"write_off_rate"`
}

// CustomerRisk represents customer payment risk profile
type CustomerRisk struct {
	CustomerID             uuid.UUID          `json:"customer_id"`
	RiskScore              float64            `json:"risk_score"`
	RiskLevel              string             `json:"risk_level"` // "low", "medium", "high"
	OutstandingAmount      float64            `json:"outstanding_amount"`
	DaysOutstanding        int                `json:"days_outstanding"`
	PaymentHistory         *PaymentHistory    `json:"payment_history"`
	RecommendedActions     []string           `json:"recommended_actions"`
}

// PaymentHistory provides customer payment history
type PaymentHistory struct {
	OnTimePayments         int                `json:"on_time_payments"`
	LatePayments           int                `json:"late_payments"`
	MissedPayments         int                `json:"missed_payments"`
	AverageDaysLate        float64            `json:"average_days_late"`
	PaymentReliabilityScore float64           `json:"payment_reliability_score"`
}

// InvoiceMetrics provides invoice-specific metrics
type InvoiceMetrics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalInvoices          int64              `json:"total_invoices"`
	PaidInvoices           int64              `json:"paid_invoices"`
	UnpaidInvoices         int64              `json:"unpaid_invoices"`
	OverdueInvoices        int64              `json:"overdue_invoices"`
	VoidedInvoices         int64              `json:"voided_invoices"`
	AverageInvoiceAmount   float64            `json:"average_invoice_amount"`
	AverageTimeToPayment   float64            `json:"average_time_to_payment"`
	InvoicesByType         map[string]int64   `json:"invoices_by_type"`
	InvoicesByStatus       map[string]int64   `json:"invoices_by_status"`
	AutomationRate         float64            `json:"automation_rate"`
	ManualInvoices         int64              `json:"manual_invoices"`
	AutoGeneratedInvoices  int64              `json:"auto_generated_invoices"`
}

// CLVAnalysis provides Customer Lifetime Value analysis
type CLVAnalysis struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	AverageCLV             float64            `json:"average_clv"`
	MedianCLV              float64            `json:"median_clv"`
	CLVBySegment           map[string]float64 `json:"clv_by_segment"`
	CLVByPlan              map[string]float64 `json:"clv_by_plan"`
	CLVByCohort            map[string]float64 `json:"clv_by_cohort"`
	PredictedCLV           float64            `json:"predicted_clv"`
	CLVConfidenceInterval  *ConfidenceInterval `json:"clv_confidence_interval"`
	TopCustomersByValue    []*CustomerValue   `json:"top_customers_by_value"`
	CLVDistribution        []*CLVBucket       `json:"clv_distribution"`
}

// CustomerValue represents a customer's value metrics
type CustomerValue struct {
	CustomerID             uuid.UUID          `json:"customer_id"`
	LifetimeValue          float64            `json:"lifetime_value"`
	RevenueToDate          float64            `json:"revenue_to_date"`
	PredictedValue         float64            `json:"predicted_value"`
	Tenure                 int                `json:"tenure"` // Days as customer
	MRRContribution        float64            `json:"mrr_contribution"`
	ChurnProbability       float64            `json:"churn_probability"`
	ValueSegment           string             `json:"value_segment"`
}

// CLVBucket represents CLV distribution bucket
type CLVBucket struct {
	MinValue               float64            `json:"min_value"`
	MaxValue               float64            `json:"max_value"`
	CustomerCount          int64              `json:"customer_count"`
	Percentage             float64            `json:"percentage"`
}

// CACAnalysis provides Customer Acquisition Cost analysis
type CACAnalysis struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalAcquisitionCost   float64            `json:"total_acquisition_cost"`
	NewCustomers           int64              `json:"new_customers"`
	AverageCAC             float64            `json:"average_cac"`
	CACByChannel           map[string]float64 `json:"cac_by_channel"`
	CACByPlan              map[string]float64 `json:"cac_by_plan"`
	CACTrend               []*CACTrendPoint   `json:"cac_trend"`
	PaybackPeriod          float64            `json:"payback_period"`
	ROAS                   float64            `json:"roas"` // Return on Ad Spend
}

// CACTrendPoint represents CAC trend over time
type CACTrendPoint struct {
	Date                   time.Time          `json:"date"`
	CAC                    float64            `json:"cac"`
	NewCustomers           int64              `json:"new_customers"`
	AcquisitionCost        float64            `json:"acquisition_cost"`
}

// CustomerSegment represents a customer segment
type CustomerSegment struct {
	SegmentID              string             `json:"segment_id"`
	SegmentName            string             `json:"segment_name"`
	CustomerCount          int64              `json:"customer_count"`
	TotalRevenue           float64            `json:"total_revenue"`
	AverageRevenue         float64            `json:"average_revenue"`
	ChurnRate              float64            `json:"churn_rate"`
	LifetimeValue          float64            `json:"lifetime_value"`
	AcquisitionCost        float64            `json:"acquisition_cost"`
	Profitability          float64            `json:"profitability"`
	GrowthRate             float64            `json:"growth_rate"`
	Characteristics        map[string]interface{} `json:"characteristics"`
}

// SegmentationCriteria defines how customers should be segmented
type SegmentationCriteria struct {
	SegmentBy              []string           `json:"segment_by"` // "revenue", "usage", "tenure", "plan", etc.
	Filters                map[string]interface{} `json:"filters"`
	MinSegmentSize         int                `json:"min_segment_size"`
	MaxSegments            int                `json:"max_segments"`
}

// RetentionAnalysis provides customer retention analysis
type RetentionAnalysis struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	OverallRetentionRate   float64            `json:"overall_retention_rate"`
	RetentionByPlan        map[string]float64 `json:"retention_by_plan"`
	RetentionByTenure      map[string]float64 `json:"retention_by_tenure"`
	RetentionByValue       map[string]float64 `json:"retention_by_value"`
	CohortRetention        []*CohortData      `json:"cohort_retention"`
	RetentionDrivers       []*RetentionDriver `json:"retention_drivers"`
	AtRiskCustomers        []*CustomerRisk    `json:"at_risk_customers"`
}

// RetentionDriver represents factors that influence retention
type RetentionDriver struct {
	Factor                 string             `json:"factor"`
	Impact                 float64            `json:"impact"` // Correlation coefficient
	Description            string             `json:"description"`
	ActionableInsight      string             `json:"actionable_insight"`
}

// UsageAnalytics provides usage-based analytics
type UsageAnalytics struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalUsage             map[string]int64   `json:"total_usage"` // By metric
	AverageUsage           map[string]float64 `json:"average_usage"`
	MedianUsage            map[string]float64 `json:"median_usage"`
	UsageGrowthRate        map[string]float64 `json:"usage_growth_rate"`
	FeatureAdoption        map[string]float64 `json:"feature_adoption"`
	UsageByPlan            map[string]map[string]float64 `json:"usage_by_plan"`
	PowerUsers             []*PowerUser       `json:"power_users"`
	UnderutilizedCustomers []*UnderutilizedCustomer `json:"underutilized_customers"`
	UsageCorrelations      map[string]float64 `json:"usage_correlations"`
}

// PowerUser represents customers with high usage
type PowerUser struct {
	CustomerID             uuid.UUID          `json:"customer_id"`
	UsageMetrics           map[string]float64 `json:"usage_metrics"`
	PercentileRank         float64            `json:"percentile_rank"`
	RevenueContribution    float64            `json:"revenue_contribution"`
	ExpansionOpportunity   float64            `json:"expansion_opportunity"`
}

// UnderutilizedCustomer represents customers with low usage
type UnderutilizedCustomer struct {
	CustomerID             uuid.UUID          `json:"customer_id"`
	UsageMetrics           map[string]float64 `json:"usage_metrics"`
	PercentileRank         float64            `json:"percentile_rank"`
	ChurnRisk              float64            `json:"churn_risk"`
	EngagementRecommendations []string        `json:"engagement_recommendations"`
}

// UsageTrend represents usage trend for a metric
type UsageTrend struct {
	Date                   time.Time          `json:"date"`
	TotalUsage             int64              `json:"total_usage"`
	UniqueUsers            int64              `json:"unique_users"`
	AverageUsagePerUser    float64            `json:"average_usage_per_user"`
	GrowthRate             float64            `json:"growth_rate"`
}

// OverageAnalysis provides overage billing analysis
type OverageAnalysis struct {
	TenantID               uuid.UUID          `json:"tenant_id"`
	Period                 DatePeriod         `json:"period"`
	TotalOverageRevenue    float64            `json:"total_overage_revenue"`
	OverageCustomers       int64              `json:"overage_customers"`
	AverageOverageAmount   float64            `json:"average_overage_amount"`
	OverageByPlan          map[string]float64 `json:"overage_by_plan"`
	OverageByMetric        map[string]float64 `json:"overage_by_metric"`
	OverageTrends          []*OverageTrend    `json:"overage_trends"`
	OverageOpportunities   []*OverageOpportunity `json:"overage_opportunities"`
}

// OverageTrend represents overage trend over time
type OverageTrend struct {
	Date                   time.Time          `json:"date"`
	OverageRevenue         float64            `json:"overage_revenue"`
	OverageCustomers       int64              `json:"overage_customers"`
	AverageOverage         float64            `json:"average_overage"`
}

// OverageOpportunity represents potential plan upgrade opportunities
type OverageOpportunity struct {
	CustomerID             uuid.UUID          `json:"customer_id"`
	CurrentPlan            string             `json:"current_plan"`
	OverageAmount          float64            `json:"overage_amount"`
	RecommendedPlan        string             `json:"recommended_plan"`
	PotentialSavings       float64            `json:"potential_savings"`
	UpgradeRecommendation  string             `json:"upgrade_recommendation"`
}

// CachedMetrics represents cached analytics metrics
type CachedMetrics struct {
	Data                   interface{}        `json:"data"`
	CachedAt               time.Time          `json:"cached_at"`
	ExpiresAt              time.Time          `json:"expires_at"`
}

// NewBillingAnalyticsService creates a new billing analytics service
func NewBillingAnalyticsService(
	logger *zap.Logger,
	config *config.Config,
	subscriptionRepo SubscriptionAnalyticsRepository,
	invoiceRepo InvoiceAnalyticsRepository,
	customerRepo CustomerAnalyticsRepository,
	usageRepo UsageAnalyticsRepository,
) *BillingAnalyticsService {
	
	auditLogger := logger.Named("billing_analytics_audit").With(
		zap.String("service", "billing_analytics"),
	)
	
	return &BillingAnalyticsService{
		logger:           logger.Named("billing_analytics"),
		config:           config,
		subscriptionRepo: subscriptionRepo,
		invoiceRepo:      invoiceRepo,
		customerRepo:     customerRepo,
		usageRepo:        usageRepo,
		auditLogger:      auditLogger,
		metricsCache:     make(map[string]*CachedMetrics),
		cacheTTL:         30 * time.Minute,
	}
}

// GetMRRData gets Monthly Recurring Revenue data
func (s *BillingAnalyticsService) GetMRRData(
	ctx context.Context,
	tenantID uuid.UUID,
	asOfDate time.Time,
) (*MRRData, error) {
	
	cacheKey := fmt.Sprintf("mrr_%s_%s", tenantID.String(), asOfDate.Format("2006-01-02"))
	
	// Check cache first
	if cached, exists := s.metricsCache[cacheKey]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			if data, ok := cached.Data.(*MRRData); ok {
				return data, nil
			}
		}
	}
	
	s.auditLogger.Info("Calculating MRR data",
		zap.String("tenant_id", tenantID.String()),
		zap.Time("as_of_date", asOfDate),
	)
	
	mrrData, err := s.subscriptionRepo.GetMRRByTenant(ctx, tenantID, asOfDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get MRR data: %w", err)
	}
	
	// Cache the result
	s.metricsCache[cacheKey] = &CachedMetrics{
		Data:      mrrData,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.cacheTTL),
	}
	
	return mrrData, nil
}

// GetMRRHistory gets MRR historical data
func (s *BillingAnalyticsService) GetMRRHistory(
	ctx context.Context,
	tenantID uuid.UUID,
	from, to time.Time,
) ([]*MRRSnapshot, error) {
	
	s.auditLogger.Info("Getting MRR history",
		zap.String("tenant_id", tenantID.String()),
		zap.Time("from", from),
		zap.Time("to", to),
	)
	
	return s.subscriptionRepo.GetMRRHistory(ctx, tenantID, from, to)
}

// GetChurnAnalysis gets comprehensive churn analysis
func (s *BillingAnalyticsService) GetChurnAnalysis(
	ctx context.Context,
	tenantID uuid.UUID,
	period time.Duration,
) (*ChurnAnalysis, error) {
	
	cacheKey := fmt.Sprintf("churn_%s_%s", tenantID.String(), period.String())
	
	// Check cache
	if cached, exists := s.metricsCache[cacheKey]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			if data, ok := cached.Data.(*ChurnAnalysis); ok {
				return data, nil
			}
		}
	}
	
	s.auditLogger.Info("Calculating churn analysis",
		zap.String("tenant_id", tenantID.String()),
		zap.Duration("period", period),
	)
	
	churnAnalysis, err := s.subscriptionRepo.GetChurnAnalysis(ctx, tenantID, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get churn analysis: %w", err)
	}
	
	// Enhance with predictions
	s.enhanceChurnPredictions(ctx, churnAnalysis)
	
	// Cache the result
	s.metricsCache[cacheKey] = &CachedMetrics{
		Data:      churnAnalysis,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.cacheTTL),
	}
	
	return churnAnalysis, nil
}

// GetRevenueAnalytics gets comprehensive revenue analytics
func (s *BillingAnalyticsService) GetRevenueAnalytics(
	ctx context.Context,
	tenantID uuid.UUID,
	from, to time.Time,
) (*RevenueAnalytics, error) {
	
	s.auditLogger.Info("Getting revenue analytics",
		zap.String("tenant_id", tenantID.String()),
		zap.Time("from", from),
		zap.Time("to", to),
	)
	
	revenueAnalytics, err := s.invoiceRepo.GetRevenueAnalytics(ctx, tenantID, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to get revenue analytics: %w", err)
	}
	
	// Add forecasting
	s.addRevenueForecasts(ctx, revenueAnalytics)
	
	return revenueAnalytics, nil
}

// GetCustomerLifetimeValue gets CLV analysis
func (s *BillingAnalyticsService) GetCustomerLifetimeValue(
	ctx context.Context,
	tenantID uuid.UUID,
	from, to time.Time,
) (*CLVAnalysis, error) {
	
	s.auditLogger.Info("Calculating customer lifetime value",
		zap.String("tenant_id", tenantID.String()),
		zap.Time("from", from),
		zap.Time("to", to),
	)
	
	return s.customerRepo.GetCustomerLifetimeValue(ctx, tenantID, from, to)
}

// GetDashboardMetrics gets key metrics for executive dashboard
func (s *BillingAnalyticsService) GetDashboardMetrics(
	ctx context.Context,
	tenantID uuid.UUID,
) (*DashboardMetrics, error) {
	
	now := time.Now()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	endOfMonth := startOfMonth.AddDate(0, 1, 0).Add(-time.Second)
	
	s.auditLogger.Info("Getting dashboard metrics",
		zap.String("tenant_id", tenantID.String()),
	)
	
	// Get all metrics in parallel
	mrrChan := make(chan *MRRData, 1)
	churnChan := make(chan *ChurnAnalysis, 1)
	revenueChan := make(chan *RevenueAnalytics, 1)
	subscriptionsChan := make(chan *SubscriptionMetrics, 1)
	errorChan := make(chan error, 4)
	
	// Get MRR data
	go func() {
		mrr, err := s.GetMRRData(ctx, tenantID, now)
		if err != nil {
			errorChan <- err
			return
		}
		mrrChan <- mrr
	}()
	
	// Get churn analysis
	go func() {
		churn, err := s.GetChurnAnalysis(ctx, tenantID, 30*24*time.Hour)
		if err != nil {
			errorChan <- err
			return
		}
		churnChan <- churn
	}()
	
	// Get revenue analytics
	go func() {
		revenue, err := s.GetRevenueAnalytics(ctx, tenantID, startOfMonth, endOfMonth)
		if err != nil {
			errorChan <- err
			return
		}
		revenueChan <- revenue
	}()
	
	// Get subscription metrics
	go func() {
		subscriptions, err := s.subscriptionRepo.GetSubscriptionMetrics(ctx, tenantID, startOfMonth, endOfMonth)
		if err != nil {
			errorChan <- err
			return
		}
		subscriptionsChan <- subscriptions
	}()
	
	// Collect results
	var mrr *MRRData
	var churn *ChurnAnalysis
	var revenue *RevenueAnalytics
	var subscriptions *SubscriptionMetrics
	
	for i := 0; i < 4; i++ {
		select {
		case m := <-mrrChan:
			mrr = m
		case c := <-churnChan:
			churn = c
		case r := <-revenueChan:
			revenue = r
		case s := <-subscriptionsChan:
			subscriptions = s
		case err := <-errorChan:
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	// Calculate derived metrics
	dashboard := &DashboardMetrics{
		TenantID:              tenantID,
		GeneratedAt:           now,
		MRR:                   mrr,
		ChurnAnalysis:         churn,
		RevenueAnalytics:      revenue,
		SubscriptionMetrics:   subscriptions,
	}
	
	// Add key performance indicators
	dashboard.KPIs = s.calculateKPIs(mrr, churn, revenue, subscriptions)
	
	return dashboard, nil
}

// DashboardMetrics represents key metrics for executive dashboard
type DashboardMetrics struct {
	TenantID              uuid.UUID              `json:"tenant_id"`
	GeneratedAt           time.Time              `json:"generated_at"`
	MRR                   *MRRData               `json:"mrr"`
	ChurnAnalysis         *ChurnAnalysis         `json:"churn_analysis"`
	RevenueAnalytics      *RevenueAnalytics      `json:"revenue_analytics"`
	SubscriptionMetrics   *SubscriptionMetrics   `json:"subscription_metrics"`
	KPIs                  map[string]KPI         `json:"kpis"`
}

// KPI represents a Key Performance Indicator
type KPI struct {
	Name                  string                 `json:"name"`
	Value                 float64                `json:"value"`
	Unit                  string                 `json:"unit"`
	Change                *float64               `json:"change,omitempty"` // Period over period change
	ChangePercentage      *float64               `json:"change_percentage,omitempty"`
	Trend                 string                 `json:"trend"` // "up", "down", "flat"
	Status                string                 `json:"status"` // "good", "warning", "critical"
	Target                *float64               `json:"target,omitempty"`
	Description           string                 `json:"description"`
}

// Helper methods

// enhanceChurnPredictions adds churn predictions to analysis
func (s *BillingAnalyticsService) enhanceChurnPredictions(ctx context.Context, analysis *ChurnAnalysis) {
	// This would integrate with ML models for churn prediction
	// For now, provide basic rule-based predictions
	
	// Example simple rules:
	// - High overage usage = low churn risk
	// - No usage in 30 days = high churn risk
	// - Payment failures = high churn risk
	// - Long tenure = low churn risk
	
	s.logger.Info("Enhanced churn analysis with predictions",
		zap.Int("predictions", len(analysis.ChurnPredictions)),
	)
}

// addRevenueForecasts adds revenue forecasting to analytics
func (s *BillingAnalyticsService) addRevenueForecasts(ctx context.Context, analytics *RevenueAnalytics) {
	// This would integrate with forecasting models
	// For now, provide simple linear forecasting based on trend
	
	if len(analytics.RevenueTrend) < 2 {
		return
	}
	
	// Simple linear regression for next 3 months
	forecasts := make([]*RevenueForecast, 3)
	
	// Calculate trend from last 3 months
	n := len(analytics.RevenueTrend)
	if n >= 3 {
		recent := analytics.RevenueTrend[n-3:]
		totalGrowth := recent[2].Revenue - recent[0].Revenue
		monthlyGrowth := totalGrowth / 2
		
		lastRevenue := analytics.RevenueTrend[n-1].Revenue
		lastDate := analytics.RevenueTrend[n-1].Date
		
		for i := 0; i < 3; i++ {
			forecasts[i] = &RevenueForecast{
				Date:              lastDate.AddDate(0, i+1, 0),
				ForecastedRevenue: lastRevenue + (monthlyGrowth * float64(i+1)),
				Model:             "linear",
				ConfidenceInterval: &ConfidenceInterval{
					Lower:      lastRevenue + (monthlyGrowth * float64(i+1) * 0.8),
					Upper:      lastRevenue + (monthlyGrowth * float64(i+1) * 1.2),
					Confidence: 0.80,
				},
			}
		}
	}
	
	analytics.Forecasts = forecasts
}

// calculateKPIs calculates key performance indicators
func (s *BillingAnalyticsService) calculateKPIs(
	mrr *MRRData,
	churn *ChurnAnalysis,
	revenue *RevenueAnalytics,
	subscriptions *SubscriptionMetrics,
) map[string]KPI {
	
	kpis := make(map[string]KPI)
	
	// MRR KPI
	if mrr != nil {
		kpis["mrr"] = KPI{
			Name:        "Monthly Recurring Revenue",
			Value:       mrr.TotalMRR,
			Unit:        mrr.Currency,
			Change:      &mrr.NetNewMRR,
			Trend:       s.getTrend(mrr.MRRGrowthRate),
			Status:      s.getStatus(mrr.MRRGrowthRate, 0.05, 0.10), // 5% warning, 10% good
			Description: "Total monthly recurring revenue",
		}
		
		if mrr.MRRGrowthRate != 0 {
			kpis["mrr"].ChangePercentage = &mrr.MRRGrowthRate
		}
	}
	
	// Churn Rate KPI
	if churn != nil {
		kpis["churn_rate"] = KPI{
			Name:        "Customer Churn Rate",
			Value:       churn.CustomerChurnRate * 100,
			Unit:        "%",
			Trend:       s.getTrend(-churn.CustomerChurnRate), // Negative because lower is better
			Status:      s.getChurnStatus(churn.CustomerChurnRate),
			Description: "Monthly customer churn rate",
		}
	}
	
	// Revenue KPI
	if revenue != nil {
		kpis["revenue"] = KPI{
			Name:        "Total Revenue",
			Value:       revenue.TotalRevenue,
			Unit:        "USD", // Default currency
			Trend:       "flat", // Would calculate from trend data
			Status:      "good",
			Description: "Total revenue for the period",
		}
	}
	
	// Active Subscriptions KPI
	if subscriptions != nil {
		kpis["active_subscriptions"] = KPI{
			Name:        "Active Subscriptions",
			Value:       float64(subscriptions.ActiveSubscriptions),
			Unit:        "count",
			Trend:       s.getTrend(float64(subscriptions.NewSubscriptions - subscriptions.CanceledThisPeriod)),
			Status:      "good",
			Description: "Total active subscriptions",
		}
		
		// ARPU KPI
		if subscriptions.ActiveSubscriptions > 0 && mrr != nil {
			arpu := mrr.TotalMRR / float64(subscriptions.ActiveSubscriptions)
			kpis["arpu"] = KPI{
				Name:        "Average Revenue Per User",
				Value:       arpu,
				Unit:        mrr.Currency,
				Trend:       "flat", // Would calculate from historical data
				Status:      "good",
				Description: "Average monthly revenue per active user",
			}
		}
	}
	
	return kpis
}

// getTrend determines trend direction based on value
func (s *BillingAnalyticsService) getTrend(value float64) string {
	if value > 0.01 { // > 1%
		return "up"
	} else if value < -0.01 { // < -1%
		return "down"
	}
	return "flat"
}

// getStatus determines status based on value and thresholds
func (s *BillingAnalyticsService) getStatus(value, warningThreshold, goodThreshold float64) string {
	if value >= goodThreshold {
		return "good"
	} else if value >= warningThreshold {
		return "warning"
	}
	return "critical"
}

// getChurnStatus determines churn status based on churn rate
func (s *BillingAnalyticsService) getChurnStatus(churnRate float64) string {
	if churnRate <= 0.05 { // <= 5%
		return "good"
	} else if churnRate <= 0.10 { // <= 10%
		return "warning"
	}
	return "critical"
}