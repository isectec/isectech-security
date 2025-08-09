package entity

import "errors"

// Payment Method Errors
var (
	ErrInvalidPaymentMethodID       = errors.New("invalid payment method ID")
	ErrInvalidTenantID              = errors.New("invalid tenant ID")
	ErrInvalidCustomerID            = errors.New("invalid customer ID")
	ErrInvalidStripePaymentMethodID = errors.New("invalid Stripe payment method ID")
	ErrInvalidPaymentMethodType     = errors.New("invalid payment method type")
	ErrInvalidPaymentMethodStatus   = errors.New("invalid payment method status")
	ErrInvalidCardLast4             = errors.New("invalid card last 4 digits")
	ErrInvalidCardExpMonth          = errors.New("invalid card expiration month")
	ErrInvalidCardExpYear           = errors.New("invalid card expiration year")
	ErrPaymentMethodNotFound        = errors.New("payment method not found")
	ErrPaymentMethodExpired         = errors.New("payment method has expired")
	ErrPaymentMethodInactive        = errors.New("payment method is inactive")
)

// Customer Errors
var (
	ErrInvalidCustomerEmail    = errors.New("invalid customer email")
	ErrInvalidCustomerName     = errors.New("invalid customer name")
	ErrCustomerNotFound        = errors.New("customer not found")
	ErrCustomerAlreadyExists   = errors.New("customer already exists")
	ErrCustomerInactive        = errors.New("customer is inactive")
)

// Subscription Errors
var (
	ErrInvalidSubscriptionID     = errors.New("invalid subscription ID")
	ErrInvalidSubscriptionPlan   = errors.New("invalid subscription plan")
	ErrInvalidSubscriptionStatus = errors.New("invalid subscription status")
	ErrSubscriptionNotFound      = errors.New("subscription not found")
	ErrSubscriptionAlreadyActive = errors.New("subscription is already active")
	ErrSubscriptionCanceled      = errors.New("subscription has been canceled")
	ErrSubscriptionExpired       = errors.New("subscription has expired")
	ErrInvalidBillingPeriod      = errors.New("invalid billing period")
	ErrInvalidTrialPeriod        = errors.New("invalid trial period")
)

// Invoice Errors
var (
	ErrInvalidInvoiceID       = errors.New("invalid invoice ID")
	ErrInvalidInvoiceNumber   = errors.New("invalid invoice number")
	ErrInvalidInvoiceAmount   = errors.New("invalid invoice amount")
	ErrInvalidInvoiceStatus   = errors.New("invalid invoice status")
	ErrInvoiceNotFound        = errors.New("invoice not found")
	ErrInvoiceAlreadyPaid     = errors.New("invoice is already paid")
	ErrInvoiceAlreadyVoided   = errors.New("invoice is already voided")
	ErrInvoiceOverdue         = errors.New("invoice is overdue")
	ErrInvalidDueDate         = errors.New("invalid due date")
	ErrInvalidTaxAmount       = errors.New("invalid tax amount")
)

// Payment Errors
var (
	ErrInvalidPaymentID       = errors.New("invalid payment ID")
	ErrInvalidPaymentAmount   = errors.New("invalid payment amount")
	ErrInvalidPaymentStatus   = errors.New("invalid payment status")
	ErrPaymentNotFound        = errors.New("payment not found")
	ErrPaymentFailed          = errors.New("payment failed")
	ErrPaymentDeclined        = errors.New("payment was declined")
	ErrInsufficientFunds      = errors.New("insufficient funds")
	ErrPaymentRequires3DS     = errors.New("payment requires 3D Secure authentication")
	ErrPaymentProcessing      = errors.New("payment is currently processing")
)

// Plan Errors
var (
	ErrInvalidPlanID          = errors.New("invalid plan ID")
	ErrInvalidPlanName        = errors.New("invalid plan name")
	ErrInvalidPlanPrice       = errors.New("invalid plan price")
	ErrInvalidPlanInterval    = errors.New("invalid plan interval")
	ErrPlanNotFound           = errors.New("plan not found")
	ErrPlanInactive           = errors.New("plan is inactive")
	ErrPlanNotAvailable       = errors.New("plan is not available for this tenant")
)

// Webhook Errors
var (
	ErrInvalidWebhookSignature = errors.New("invalid webhook signature")
	ErrWebhookEventNotFound    = errors.New("webhook event not found")
	ErrWebhookProcessingFailed = errors.New("webhook processing failed")
	ErrInvalidWebhookEvent     = errors.New("invalid webhook event")
)

// Transaction Errors
var (
	ErrInvalidTransactionID     = errors.New("invalid transaction ID")
	ErrInvalidTransactionType   = errors.New("invalid transaction type")
	ErrInvalidTransactionAmount = errors.New("invalid transaction amount")
	ErrTransactionNotFound      = errors.New("transaction not found")
	ErrTransactionFailed        = errors.New("transaction failed")
	ErrTransactionCanceled      = errors.New("transaction was canceled")
)

// Tax Errors
var (
	ErrInvalidTaxRate          = errors.New("invalid tax rate")
	ErrInvalidTaxJurisdiction  = errors.New("invalid tax jurisdiction")
	ErrTaxCalculationFailed    = errors.New("tax calculation failed")
	ErrTaxServiceUnavailable   = errors.New("tax service is unavailable")
)

// Billing Address Errors
var (
	ErrInvalidBillingAddress = errors.New("invalid billing address")
	ErrInvalidCountryCode    = errors.New("invalid country code")
	ErrInvalidPostalCode     = errors.New("invalid postal code")
)

// Usage and Metering Errors
var (
	ErrInvalidUsageRecord   = errors.New("invalid usage record")
	ErrInvalidMetricName    = errors.New("invalid metric name")
	ErrInvalidUsageQuantity = errors.New("invalid usage quantity")
	ErrUsageRecordNotFound  = errors.New("usage record not found")
)

// Discount and Coupon Errors
var (
	ErrInvalidCouponCode      = errors.New("invalid coupon code")
	ErrCouponExpired          = errors.New("coupon has expired")
	ErrCouponNotFound         = errors.New("coupon not found")
	ErrCouponAlreadyUsed      = errors.New("coupon has already been used")
	ErrInvalidDiscountAmount  = errors.New("invalid discount amount")
	ErrInvalidDiscountPercent = errors.New("invalid discount percentage")
)

// Security and Compliance Errors
var (
	ErrSecurityClearanceRequired    = errors.New("security clearance required")
	ErrInsufficientSecurityClearance = errors.New("insufficient security clearance")
	ErrComplianceViolation          = errors.New("compliance violation")
	ErrPCIComplianceRequired        = errors.New("PCI compliance required")
	ErrSOX404ComplianceRequired     = errors.New("SOX 404 compliance required")
)

// General Validation Errors
var (
	ErrInvalidInput      = errors.New("invalid input")
	ErrMissingRequiredField = errors.New("missing required field")
	ErrInvalidDateRange  = errors.New("invalid date range")
	ErrInvalidCurrency   = errors.New("invalid currency")
	ErrInvalidAmount     = errors.New("invalid amount")
	ErrInvalidEmail      = errors.New("invalid email address")
	ErrInvalidPhoneNumber = errors.New("invalid phone number")
)

// Business Logic Errors
var (
	ErrBusinessRuleViolation  = errors.New("business rule violation")
	ErrQuotaExceeded         = errors.New("quota exceeded")
	ErrRateLimitExceeded     = errors.New("rate limit exceeded")
	ErrFeatureNotEnabled     = errors.New("feature not enabled")
	ErrInvalidOperation      = errors.New("invalid operation")
	ErrOperationNotAllowed   = errors.New("operation not allowed")
)

// External Service Errors
var (
	ErrStripeServiceUnavailable = errors.New("Stripe service unavailable")
	ErrStripeAPIError          = errors.New("Stripe API error")
	ErrTaxServiceError         = errors.New("tax service error")
	ErrEmailServiceError       = errors.New("email service error")
	ErrNotificationFailed      = errors.New("notification failed")
)

// Database Errors
var (
	ErrDatabaseConnection = errors.New("database connection error")
	ErrRecordNotFound     = errors.New("record not found")
	ErrDuplicateRecord    = errors.New("duplicate record")
	ErrConstraintViolation = errors.New("constraint violation")
	ErrTransactionFailed   = errors.New("database transaction failed")
)

// Authorization Errors
var (
	ErrUnauthorized      = errors.New("unauthorized")
	ErrInsufficientPermissions = errors.New("insufficient permissions")
	ErrInvalidAPIKey     = errors.New("invalid API key")
	ErrTokenExpired      = errors.New("token has expired")
	ErrInvalidSignature  = errors.New("invalid signature")
)