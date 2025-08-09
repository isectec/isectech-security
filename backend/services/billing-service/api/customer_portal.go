package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
)

// CustomerPortalAPI provides self-service billing capabilities for customers
type CustomerPortalAPI struct {
	logger                *zap.Logger
	config               *config.Config
	customerService      CustomerService
	subscriptionService  SubscriptionService
	invoiceService       InvoiceService
	paymentMethodService PaymentMethodService
	usageService         UsageService
	portalService        PortalService
	auditLogger          *zap.Logger
}

// CustomerService defines the interface for customer operations
type CustomerService interface {
	GetCustomer(ctx context.Context, customerID uuid.UUID) (*CustomerInfo, error)
	UpdateCustomer(ctx context.Context, customerID uuid.UUID, updates *UpdateCustomerRequest) (*CustomerInfo, error)
	GetBillingAddress(ctx context.Context, customerID uuid.UUID) (*entity.BillingAddress, error)
	UpdateBillingAddress(ctx context.Context, customerID uuid.UUID, address *entity.BillingAddress) error
}

// SubscriptionService defines the interface for subscription operations
type SubscriptionService interface {
	GetCustomerSubscriptions(ctx context.Context, customerID uuid.UUID) ([]*entity.Subscription, error)
	GetSubscription(ctx context.Context, subscriptionID uuid.UUID) (*entity.Subscription, error)
	UpdateSubscription(ctx context.Context, req *UpdateSubscriptionPortalRequest) (*SubscriptionPortalResponse, error)
	CancelSubscription(ctx context.Context, req *CancelSubscriptionPortalRequest) (*SubscriptionPortalResponse, error)
	GetSubscriptionUsage(ctx context.Context, subscriptionID uuid.UUID, period *UsagePeriod) (*UsageResponse, error)
}

// InvoiceService defines the interface for invoice operations
type InvoiceService interface {
	GetCustomerInvoices(ctx context.Context, customerID uuid.UUID, filter *InvoiceFilter) ([]*entity.Invoice, error)
	GetInvoice(ctx context.Context, invoiceID uuid.UUID) (*entity.Invoice, error)
	GetInvoicePDF(ctx context.Context, invoiceID uuid.UUID) ([]byte, error)
	PayInvoice(ctx context.Context, req *PayInvoiceRequest) (*PaymentResponse, error)
}

// PaymentMethodService defines the interface for payment method operations
type PaymentMethodService interface {
	GetCustomerPaymentMethods(ctx context.Context, customerID uuid.UUID) ([]*entity.PaymentMethod, error)
	CreatePaymentMethod(ctx context.Context, req *CreatePaymentMethodPortalRequest) (*PaymentMethodResponse, error)
	UpdatePaymentMethod(ctx context.Context, req *UpdatePaymentMethodRequest) (*PaymentMethodResponse, error)
	DeletePaymentMethod(ctx context.Context, paymentMethodID uuid.UUID) error
	SetDefaultPaymentMethod(ctx context.Context, customerID, paymentMethodID uuid.UUID) error
}

// UsageService defines the interface for usage tracking
type UsageService interface {
	GetCustomerUsage(ctx context.Context, customerID uuid.UUID, period *UsagePeriod) (*UsageResponse, error)
	GetUsageHistory(ctx context.Context, customerID uuid.UUID, filter *UsageFilter) ([]*UsageRecord, error)
}

// PortalService defines the interface for portal-specific operations
type PortalService interface {
	CreatePortalSession(ctx context.Context, customerID uuid.UUID, returnURL string) (*PortalSession, error)
	ValidatePortalAccess(ctx context.Context, customerID uuid.UUID, securityClearance string) error
	GetPortalSettings(ctx context.Context, customerID uuid.UUID) (*PortalSettings, error)
	UpdatePortalSettings(ctx context.Context, customerID uuid.UUID, settings *PortalSettings) error
}

// Request/Response types

// CustomerInfo represents customer information
type CustomerInfo struct {
	ID                uuid.UUID              `json:"id"`
	TenantID          uuid.UUID              `json:"tenant_id"`
	Email             string                 `json:"email"`
	Name              string                 `json:"name"`
	Phone             *string                `json:"phone,omitempty"`
	TaxID             *string                `json:"tax_id,omitempty"`
	BillingAddress    *entity.BillingAddress `json:"billing_address"`
	SecurityClearance string                 `json:"security_clearance"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	
	// Account status
	Status            string                 `json:"status"`
	AccountBalance    int64                  `json:"account_balance"`
	CreditLimit       *int64                 `json:"credit_limit,omitempty"`
	
	// Preferences
	Currency          string                 `json:"currency"`
	Timezone          string                 `json:"timezone"`
	Language          string                 `json:"language"`
	
	// Subscription summary
	ActiveSubscriptions   int                `json:"active_subscriptions"`
	TrialSubscriptions    int                `json:"trial_subscriptions"`
	NextRenewalDate       *time.Time         `json:"next_renewal_date,omitempty"`
}

// UpdateCustomerRequest represents a customer update request
type UpdateCustomerRequest struct {
	Name     *string `json:"name,omitempty"`
	Phone    *string `json:"phone,omitempty"`
	TaxID    *string `json:"tax_id,omitempty"`
	Currency *string `json:"currency,omitempty"`
	Timezone *string `json:"timezone,omitempty"`
	Language *string `json:"language,omitempty"`
}

// UpdateSubscriptionPortalRequest represents a subscription update from portal
type UpdateSubscriptionPortalRequest struct {
	SubscriptionID    uuid.UUID `json:"subscription_id"`
	CustomerID        uuid.UUID `json:"customer_id"`
	PlanID            *uuid.UUID `json:"plan_id,omitempty"`
	Quantity          *int32    `json:"quantity,omitempty"`
	PaymentMethodID   *uuid.UUID `json:"payment_method_id,omitempty"`
	ProrationBehavior entity.ProrationBehavior `json:"proration_behavior"`
}

// CancelSubscriptionPortalRequest represents a subscription cancellation from portal
type CancelSubscriptionPortalRequest struct {
	SubscriptionID      uuid.UUID  `json:"subscription_id"`
	CustomerID          uuid.UUID  `json:"customer_id"`
	CancelAtPeriodEnd   bool       `json:"cancel_at_period_end"`
	CancellationReason  *string    `json:"cancellation_reason,omitempty"`
	CancellationSurvey  *CancellationSurvey `json:"cancellation_survey,omitempty"`
}

// CancellationSurvey represents customer feedback on cancellation
type CancellationSurvey struct {
	PrimaryReason     string   `json:"primary_reason"`
	SecondaryReasons  []string `json:"secondary_reasons,omitempty"`
	Feedback          *string  `json:"feedback,omitempty"`
	WouldRecommend    *bool    `json:"would_recommend,omitempty"`
	AlternativeSought *string  `json:"alternative_sought,omitempty"`
}

// SubscriptionPortalResponse represents subscription operation response
type SubscriptionPortalResponse struct {
	Subscription     *entity.Subscription `json:"subscription"`
	ProrationAmount  int64               `json:"proration_amount,omitempty"`
	EffectiveDate    time.Time           `json:"effective_date"`
	RequiresPayment  bool                `json:"requires_payment"`
}

// CreatePaymentMethodPortalRequest represents payment method creation from portal
type CreatePaymentMethodPortalRequest struct {
	CustomerID        uuid.UUID              `json:"customer_id"`
	Type              entity.PaymentMethodType `json:"type"`
	CardToken         *string                `json:"card_token,omitempty"`         // For tokenized cards
	BankToken         *string                `json:"bank_token,omitempty"`         // For ACH
	BillingDetails    *BillingDetails        `json:"billing_details,omitempty"`
	SetAsDefault      bool                   `json:"set_as_default"`
}

// UpdatePaymentMethodRequest represents payment method update
type UpdatePaymentMethodRequest struct {
	PaymentMethodID   uuid.UUID              `json:"payment_method_id"`
	CustomerID        uuid.UUID              `json:"customer_id"`
	BillingDetails    *BillingDetails        `json:"billing_details,omitempty"`
	ExpirationMonth   *int                   `json:"expiration_month,omitempty"`
	ExpirationYear    *int                   `json:"expiration_year,omitempty"`
}

// BillingDetails represents billing details for payment methods
type BillingDetails struct {
	Name    string                 `json:"name"`
	Email   string                 `json:"email"`
	Phone   *string                `json:"phone,omitempty"`
	Address *entity.BillingAddress `json:"address"`
}

// PaymentMethodResponse represents payment method operation response
type PaymentMethodResponse struct {
	PaymentMethod    *entity.PaymentMethod   `json:"payment_method"`
	SetupRequired    bool                   `json:"setup_required"`
	SetupIntentID    *string                `json:"setup_intent_id,omitempty"`
	ClientSecret     *string                `json:"client_secret,omitempty"`
}

// PayInvoiceRequest represents invoice payment request
type PayInvoiceRequest struct {
	InvoiceID        uuid.UUID  `json:"invoice_id"`
	CustomerID       uuid.UUID  `json:"customer_id"`
	PaymentMethodID  *uuid.UUID `json:"payment_method_id,omitempty"`
	Amount           *int64     `json:"amount,omitempty"` // For partial payments
}

// PaymentResponse represents payment operation response
type PaymentResponse struct {
	PaymentIntentID  string     `json:"payment_intent_id"`
	Status           string     `json:"status"`
	Amount           int64      `json:"amount"`
	RequiresAction   bool       `json:"requires_action"`
	ClientSecret     *string    `json:"client_secret,omitempty"`
}

// UsagePeriod represents a usage time period
type UsagePeriod struct {
	StartDate        time.Time  `json:"start_date"`
	EndDate          time.Time  `json:"end_date"`
}

// UsageResponse represents usage data response
type UsageResponse struct {
	SubscriptionID   uuid.UUID      `json:"subscription_id"`
	Period           UsagePeriod    `json:"period"`
	UsageItems       []UsageItem    `json:"usage_items"`
	TotalUsage       int64          `json:"total_usage"`
	IncludedUsage    int64          `json:"included_usage"`
	OverageUsage     int64          `json:"overage_usage"`
	OverageAmount    int64          `json:"overage_amount"`
	Currency         string         `json:"currency"`
}

// UsageItem represents individual usage item
type UsageItem struct {
	MetricName       string         `json:"metric_name"`
	MetricUnit       string         `json:"metric_unit"`
	Quantity         int64          `json:"quantity"`
	UnitPrice        int64          `json:"unit_price"`
	Amount           int64          `json:"amount"`
	IncludedQuantity int64          `json:"included_quantity"`
	OverageQuantity  int64          `json:"overage_quantity"`
}

// UsageFilter represents usage history filter
type UsageFilter struct {
	SubscriptionID   *uuid.UUID     `json:"subscription_id,omitempty"`
	MetricName       *string        `json:"metric_name,omitempty"`
	StartDate        *time.Time     `json:"start_date,omitempty"`
	EndDate          *time.Time     `json:"end_date,omitempty"`
	Limit            int            `json:"limit"`
	Offset           int            `json:"offset"`
}

// UsageRecord represents a usage record
type UsageRecord struct {
	ID               uuid.UUID      `json:"id"`
	SubscriptionID   uuid.UUID      `json:"subscription_id"`
	MetricName       string         `json:"metric_name"`
	Quantity         int64          `json:"quantity"`
	Timestamp        time.Time      `json:"timestamp"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// InvoiceFilter represents invoice filter
type InvoiceFilter struct {
	Status           *entity.InvoiceStatus  `json:"status,omitempty"`
	StartDate        *time.Time            `json:"start_date,omitempty"`
	EndDate          *time.Time            `json:"end_date,omitempty"`
	MinAmount        *int64                `json:"min_amount,omitempty"`
	MaxAmount        *int64                `json:"max_amount,omitempty"`
	Limit            int                   `json:"limit"`
	Offset           int                   `json:"offset"`
	SortBy           string                `json:"sort_by"`
	SortOrder        string                `json:"sort_order"`
}

// PortalSession represents a portal session
type PortalSession struct {
	ID               string         `json:"id"`
	CustomerID       uuid.UUID      `json:"customer_id"`
	URL              string         `json:"url"`
	ReturnURL        string         `json:"return_url"`
	ExpiresAt        time.Time      `json:"expires_at"`
	CreatedAt        time.Time      `json:"created_at"`
}

// PortalSettings represents customer portal settings
type PortalSettings struct {
	CustomerID               uuid.UUID  `json:"customer_id"`
	EmailNotifications       bool       `json:"email_notifications"`
	InvoiceReminders         bool       `json:"invoice_reminders"`
	UsageAlerts              bool       `json:"usage_alerts"`
	UsageThreshold           *int64     `json:"usage_threshold,omitempty"`
	AutoPayEnabled           bool       `json:"auto_pay_enabled"`
	PreferredPaymentMethod   *uuid.UUID `json:"preferred_payment_method,omitempty"`
	Currency                 string     `json:"currency"`
	Timezone                 string     `json:"timezone"`
	Language                 string     `json:"language"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

// NewCustomerPortalAPI creates a new customer portal API
func NewCustomerPortalAPI(
	logger *zap.Logger,
	config *config.Config,
	customerService CustomerService,
	subscriptionService SubscriptionService,
	invoiceService InvoiceService,
	paymentMethodService PaymentMethodService,
	usageService UsageService,
	portalService PortalService,
) *CustomerPortalAPI {
	
	auditLogger := logger.Named("customer_portal_audit").With(
		zap.String("service", "customer_portal_api"),
	)
	
	return &CustomerPortalAPI{
		logger:               logger.Named("customer_portal_api"),
		config:               config,
		customerService:      customerService,
		subscriptionService:  subscriptionService,
		invoiceService:       invoiceService,
		paymentMethodService: paymentMethodService,
		usageService:         usageService,
		portalService:        portalService,
		auditLogger:          auditLogger,
	}
}

// RegisterRoutes registers customer portal routes
func (api *CustomerPortalAPI) RegisterRoutes(router *gin.Engine) {
	portal := router.Group("/api/v1/portal")
	{
		// Customer information
		portal.GET("/customer", api.GetCustomerInfo)
		portal.PUT("/customer", api.UpdateCustomerInfo)
		portal.GET("/customer/billing-address", api.GetBillingAddress)
		portal.PUT("/customer/billing-address", api.UpdateBillingAddress)
		
		// Subscriptions
		portal.GET("/subscriptions", api.GetSubscriptions)
		portal.GET("/subscriptions/:id", api.GetSubscription)
		portal.PUT("/subscriptions/:id", api.UpdateSubscription)
		portal.POST("/subscriptions/:id/cancel", api.CancelSubscription)
		portal.GET("/subscriptions/:id/usage", api.GetSubscriptionUsage)
		
		// Invoices
		portal.GET("/invoices", api.GetInvoices)
		portal.GET("/invoices/:id", api.GetInvoice)
		portal.GET("/invoices/:id/pdf", api.GetInvoicePDF)
		portal.POST("/invoices/:id/pay", api.PayInvoice)
		
		// Payment methods
		portal.GET("/payment-methods", api.GetPaymentMethods)
		portal.POST("/payment-methods", api.CreatePaymentMethod)
		portal.PUT("/payment-methods/:id", api.UpdatePaymentMethod)
		portal.DELETE("/payment-methods/:id", api.DeletePaymentMethod)
		portal.POST("/payment-methods/:id/default", api.SetDefaultPaymentMethod)
		
		// Usage
		portal.GET("/usage", api.GetUsage)
		portal.GET("/usage/history", api.GetUsageHistory)
		
		// Portal settings
		portal.GET("/settings", api.GetPortalSettings)
		portal.PUT("/settings", api.UpdatePortalSettings)
		
		// Portal session
		portal.POST("/session", api.CreatePortalSession)
	}
}

// GetCustomerInfo gets customer information
func (api *CustomerPortalAPI) GetCustomerInfo(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	api.auditLogger.Info("Getting customer info",
		zap.String("customer_id", customerID.String()),
		zap.String("ip", c.ClientIP()),
	)
	
	customer, err := api.customerService.GetCustomer(c.Request.Context(), customerID)
	if err != nil {
		api.logger.Error("Failed to get customer", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get customer information")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, customer)
}

// UpdateCustomerInfo updates customer information
func (api *CustomerPortalAPI) UpdateCustomerInfo(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	var req UpdateCustomerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	
	api.auditLogger.Info("Updating customer info",
		zap.String("customer_id", customerID.String()),
		zap.String("ip", c.ClientIP()),
	)
	
	customer, err := api.customerService.UpdateCustomer(c.Request.Context(), customerID, &req)
	if err != nil {
		api.logger.Error("Failed to update customer", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to update customer information")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, customer)
}

// GetBillingAddress gets customer billing address
func (api *CustomerPortalAPI) GetBillingAddress(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	address, err := api.customerService.GetBillingAddress(c.Request.Context(), customerID)
	if err != nil {
		api.logger.Error("Failed to get billing address", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get billing address")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, address)
}

// UpdateBillingAddress updates customer billing address
func (api *CustomerPortalAPI) UpdateBillingAddress(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	var address entity.BillingAddress
	if err := c.ShouldBindJSON(&address); err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	
	api.auditLogger.Info("Updating billing address",
		zap.String("customer_id", customerID.String()),
		zap.String("ip", c.ClientIP()),
	)
	
	if err := api.customerService.UpdateBillingAddress(c.Request.Context(), customerID, &address); err != nil {
		api.logger.Error("Failed to update billing address", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to update billing address")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, map[string]string{"status": "success"})
}

// GetSubscriptions gets customer subscriptions
func (api *CustomerPortalAPI) GetSubscriptions(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	subscriptions, err := api.subscriptionService.GetCustomerSubscriptions(c.Request.Context(), customerID)
	if err != nil {
		api.logger.Error("Failed to get subscriptions", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get subscriptions")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, map[string]interface{}{
		"subscriptions": subscriptions,
		"count":         len(subscriptions),
	})
}

// GetSubscription gets a specific subscription
func (api *CustomerPortalAPI) GetSubscription(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	subscriptionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_id", "Invalid subscription ID")
		return
	}
	
	subscription, err := api.subscriptionService.GetSubscription(c.Request.Context(), subscriptionID)
	if err != nil {
		api.logger.Error("Failed to get subscription", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get subscription")
		return
	}
	
	// Verify customer owns this subscription
	if subscription.CustomerID != customerID {
		api.respondWithError(c, http.StatusForbidden, "forbidden", "Access denied")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, subscription)
}

// UpdateSubscription updates a subscription
func (api *CustomerPortalAPI) UpdateSubscription(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	subscriptionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_id", "Invalid subscription ID")
		return
	}
	
	var req UpdateSubscriptionPortalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	
	req.SubscriptionID = subscriptionID
	req.CustomerID = customerID
	
	api.auditLogger.Info("Updating subscription",
		zap.String("customer_id", customerID.String()),
		zap.String("subscription_id", subscriptionID.String()),
		zap.String("ip", c.ClientIP()),
	)
	
	response, err := api.subscriptionService.UpdateSubscription(c.Request.Context(), &req)
	if err != nil {
		api.logger.Error("Failed to update subscription", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to update subscription")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, response)
}

// CancelSubscription cancels a subscription
func (api *CustomerPortalAPI) CancelSubscription(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	subscriptionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_id", "Invalid subscription ID")
		return
	}
	
	var req CancelSubscriptionPortalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	
	req.SubscriptionID = subscriptionID
	req.CustomerID = customerID
	
	api.auditLogger.Info("Canceling subscription",
		zap.String("customer_id", customerID.String()),
		zap.String("subscription_id", subscriptionID.String()),
		zap.Bool("cancel_at_period_end", req.CancelAtPeriodEnd),
		zap.String("ip", c.ClientIP()),
	)
	
	response, err := api.subscriptionService.CancelSubscription(c.Request.Context(), &req)
	if err != nil {
		api.logger.Error("Failed to cancel subscription", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to cancel subscription")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, response)
}

// GetSubscriptionUsage gets subscription usage
func (api *CustomerPortalAPI) GetSubscriptionUsage(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	subscriptionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_id", "Invalid subscription ID")
		return
	}
	
	// Parse period parameters
	var period *UsagePeriod
	if startDate := c.Query("start_date"); startDate != "" {
		if endDate := c.Query("end_date"); endDate != "" {
			start, err1 := time.Parse("2006-01-02", startDate)
			end, err2 := time.Parse("2006-01-02", endDate)
			if err1 == nil && err2 == nil {
				period = &UsagePeriod{
					StartDate: start,
					EndDate:   end,
				}
			}
		}
	}
	
	usage, err := api.subscriptionService.GetSubscriptionUsage(c.Request.Context(), subscriptionID, period)
	if err != nil {
		api.logger.Error("Failed to get subscription usage", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get subscription usage")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, usage)
}

// GetInvoices gets customer invoices
func (api *CustomerPortalAPI) GetInvoices(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	// Parse filter parameters
	filter := &InvoiceFilter{
		Limit:     50, // Default limit
		Offset:    0,
		SortBy:    "invoice_date",
		SortOrder: "desc",
	}
	
	if status := c.Query("status"); status != "" {
		invoiceStatus := entity.InvoiceStatus(status)
		filter.Status = &invoiceStatus
	}
	
	if startDate := c.Query("start_date"); startDate != "" {
		if date, err := time.Parse("2006-01-02", startDate); err == nil {
			filter.StartDate = &date
		}
	}
	
	if endDate := c.Query("end_date"); endDate != "" {
		if date, err := time.Parse("2006-01-02", endDate); err == nil {
			filter.EndDate = &date
		}
	}
	
	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 100 {
			filter.Limit = l
		}
	}
	
	if offset := c.Query("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			filter.Offset = o
		}
	}
	
	invoices, err := api.invoiceService.GetCustomerInvoices(c.Request.Context(), customerID, filter)
	if err != nil {
		api.logger.Error("Failed to get invoices", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get invoices")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, map[string]interface{}{
		"invoices": invoices,
		"count":    len(invoices),
		"filter":   filter,
	})
}

// GetInvoice gets a specific invoice
func (api *CustomerPortalAPI) GetInvoice(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	invoiceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_id", "Invalid invoice ID")
		return
	}
	
	invoice, err := api.invoiceService.GetInvoice(c.Request.Context(), invoiceID)
	if err != nil {
		api.logger.Error("Failed to get invoice", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get invoice")
		return
	}
	
	// Verify customer owns this invoice
	if invoice.CustomerID != customerID {
		api.respondWithError(c, http.StatusForbidden, "forbidden", "Access denied")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, invoice)
}

// GetInvoicePDF gets invoice PDF
func (api *CustomerPortalAPI) GetInvoicePDF(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	invoiceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_id", "Invalid invoice ID")
		return
	}
	
	// Verify customer owns this invoice
	invoice, err := api.invoiceService.GetInvoice(c.Request.Context(), invoiceID)
	if err != nil {
		api.logger.Error("Failed to get invoice", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get invoice")
		return
	}
	
	if invoice.CustomerID != customerID {
		api.respondWithError(c, http.StatusForbidden, "forbidden", "Access denied")
		return
	}
	
	pdfData, err := api.invoiceService.GetInvoicePDF(c.Request.Context(), invoiceID)
	if err != nil {
		api.logger.Error("Failed to get invoice PDF", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to get invoice PDF")
		return
	}
	
	filename := fmt.Sprintf("invoice_%s.pdf", invoice.InvoiceNumber)
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Data(http.StatusOK, "application/pdf", pdfData)
}

// PayInvoice pays an invoice
func (api *CustomerPortalAPI) PayInvoice(c *gin.Context) {
	customerID, err := api.getCustomerIDFromContext(c)
	if err != nil {
		api.respondWithError(c, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	
	invoiceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_id", "Invalid invoice ID")
		return
	}
	
	var req PayInvoiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.respondWithError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	
	req.InvoiceID = invoiceID
	req.CustomerID = customerID
	
	api.auditLogger.Info("Processing invoice payment",
		zap.String("customer_id", customerID.String()),
		zap.String("invoice_id", invoiceID.String()),
		zap.String("ip", c.ClientIP()),
	)
	
	response, err := api.invoiceService.PayInvoice(c.Request.Context(), &req)
	if err != nil {
		api.logger.Error("Failed to pay invoice", zap.Error(err))
		api.respondWithError(c, http.StatusInternalServerError, "internal_error", "Failed to process payment")
		return
	}
	
	api.respondWithJSON(c, http.StatusOK, response)
}

// Helper methods

// getCustomerIDFromContext extracts customer ID from context (from JWT token)
func (api *CustomerPortalAPI) getCustomerIDFromContext(c *gin.Context) (uuid.UUID, error) {
	// This would typically extract from JWT token or session
	// For now, assume it's passed in a header
	customerIDStr := c.GetHeader("X-Customer-ID")
	if customerIDStr == "" {
		return uuid.Nil, fmt.Errorf("customer ID not found")
	}
	
	return uuid.Parse(customerIDStr)
}

// respondWithJSON sends a JSON response
func (api *CustomerPortalAPI) respondWithJSON(c *gin.Context, statusCode int, data interface{}) {
	c.Header("Content-Type", "application/json")
	c.JSON(statusCode, data)
}

// respondWithError sends an error response
func (api *CustomerPortalAPI) respondWithError(c *gin.Context, statusCode int, errorCode, message string) {
	c.Header("Content-Type", "application/json")
	c.JSON(statusCode, gin.H{
		"error": gin.H{
			"code":    errorCode,
			"message": message,
		},
	})
}