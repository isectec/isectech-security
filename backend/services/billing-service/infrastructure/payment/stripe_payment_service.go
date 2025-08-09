package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v74"
	"github.com/stripe/stripe-go/v74/customer"
	"github.com/stripe/stripe-go/v74/paymentintent"
	"github.com/stripe/stripe-go/v74/paymentmethod"
	"github.com/stripe/stripe-go/v74/setupintent"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
)

// StripePaymentService handles Stripe payment operations with iSECTECH security requirements
type StripePaymentService struct {
	logger     *zap.Logger
	config     *config.StripeConfig
	repository PaymentMethodRepository
	
	// Compliance and security
	pciCompliant      bool
	securityClearance string
	auditLogger       *zap.Logger
}

// PaymentMethodRepository defines the interface for payment method storage
type PaymentMethodRepository interface {
	Create(ctx context.Context, pm *entity.PaymentMethod) error
	Update(ctx context.Context, pm *entity.PaymentMethod) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.PaymentMethod, error)
	GetByStripeID(ctx context.Context, stripeID string) (*entity.PaymentMethod, error)
	ListByCustomer(ctx context.Context, customerID uuid.UUID, filter *entity.PaymentMethodFilter) ([]*entity.PaymentMethod, error)
	Delete(ctx context.Context, id uuid.UUID) error
	SetDefault(ctx context.Context, customerID, paymentMethodID uuid.UUID) error
}

// StripeConfig holds Stripe configuration
type StripeConfig struct {
	SecretKey           string
	PublishableKey      string
	WebhookSecret       string
	ConnectAccountID    string
	Environment         string // "production" or "sandbox"
	
	// Security settings
	RequireStatementDescriptor bool
	StatementDescriptor        string
	Require3DSecure           bool
	EnableMetadata            bool
	
	// Compliance settings
	PCICompliant              bool
	SOXCompliant              bool
	HIPAACompliant            bool
	
	// Rate limiting
	MaxRequestsPerMinute      int
	MaxPaymentAttemptsPerDay  int
	
	// Retry configuration
	MaxRetries                int
	RetryDelay                time.Duration
	BackoffMultiplier         float64
}

// PaymentRequest represents a payment request
type PaymentRequest struct {
	TenantID         uuid.UUID               `json:"tenant_id"`
	CustomerID       uuid.UUID               `json:"customer_id"`
	PaymentMethodID  uuid.UUID               `json:"payment_method_id"`
	Amount           int64                   `json:"amount"` // Amount in cents
	Currency         string                  `json:"currency"`
	Description      string                  `json:"description"`
	StatementDescriptor *string              `json:"statement_descriptor,omitempty"`
	InvoiceID        *uuid.UUID              `json:"invoice_id,omitempty"`
	Metadata         map[string]string       `json:"metadata,omitempty"`
	
	// Security and compliance
	RequireSecurityClearance bool   `json:"require_security_clearance"`
	SecurityClearance        string `json:"security_clearance"`
	ComplianceFrameworks     []string `json:"compliance_frameworks"`
	
	// Payment configuration
	CaptureMethod            string `json:"capture_method"` // "automatic" or "manual"
	ConfirmationMethod       string `json:"confirmation_method"` // "automatic" or "manual"
	SetupFutureUsage         string `json:"setup_future_usage,omitempty"` // "on_session" or "off_session"
}

// PaymentResponse represents a payment response
type PaymentResponse struct {
	PaymentIntentID     string                 `json:"payment_intent_id"`
	Status              string                 `json:"status"`
	ClientSecret        string                 `json:"client_secret,omitempty"`
	RequiresAction      bool                   `json:"requires_action"`
	RequiresConfirmation bool                  `json:"requires_confirmation"`
	Amount              int64                  `json:"amount"`
	Currency            string                 `json:"currency"`
	Metadata            map[string]string      `json:"metadata,omitempty"`
	Error               *PaymentError          `json:"error,omitempty"`
	
	// Security audit trail
	SecurityClearance   string    `json:"security_clearance"`
	AuditTrailID        string    `json:"audit_trail_id"`
	ProcessedAt         time.Time `json:"processed_at"`
}

// PaymentError represents a payment error
type PaymentError struct {
	Code           string `json:"code"`
	Message        string `json:"message"`
	Type           string `json:"type"`
	DeclineCode    string `json:"decline_code,omitempty"`
	RequiresAction bool   `json:"requires_action"`
}

// NewStripePaymentService creates a new Stripe payment service
func NewStripePaymentService(
	logger *zap.Logger,
	config *StripeConfig,
	repository PaymentMethodRepository,
) *StripePaymentService {
	// Initialize Stripe with configuration
	stripe.Key = config.SecretKey
	
	auditLogger := logger.Named("audit").With(
		zap.String("service", "stripe_payment"),
		zap.String("environment", config.Environment),
		zap.Bool("pci_compliant", config.PCICompliant),
	)
	
	return &StripePaymentService{
		logger:            logger.Named("stripe_payment"),
		config:            config,
		repository:        repository,
		pciCompliant:      config.PCICompliant,
		securityClearance: "unclassified", // Default clearance
		auditLogger:       auditLogger,
	}
}

// CreatePaymentMethod creates a new payment method for a customer
func (s *StripePaymentService) CreatePaymentMethod(
	ctx context.Context,
	req *CreatePaymentMethodRequest,
) (*entity.PaymentMethod, error) {
	
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	s.auditLogger.Info("Creating payment method",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("customer_id", req.CustomerID.String()),
		zap.String("type", string(req.Type)),
	)
	
	defer func() {
		s.auditLogger.Info("Payment method creation completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("duration", time.Since(start)),
		)
	}()
	
	// Validate security clearance requirements
	if err := s.validateSecurityClearance(req.SecurityClearance); err != nil {
		s.auditLogger.Error("Security clearance validation failed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("security clearance validation failed: %w", err)
	}
	
	// Create Stripe customer if not exists
	stripeCustomerID, err := s.ensureStripeCustomer(ctx, req.CustomerID, req.CustomerEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure Stripe customer: %w", err)
	}
	
	// Create payment method in Stripe
	stripeParams := &stripe.PaymentMethodParams{
		Customer: stripe.String(stripeCustomerID),
		Type:     stripe.String(string(req.Type)),
	}
	
	// Add card details if provided
	if req.Card != nil {
		stripeParams.Card = &stripe.PaymentMethodCardParams{
			Number:   stripe.String(req.Card.Number),
			ExpMonth: stripe.Int64(int64(req.Card.ExpMonth)),
			ExpYear:  stripe.Int64(int64(req.Card.ExpYear)),
			CVC:      stripe.String(req.Card.CVC),
		}
	}
	
	// Set billing details
	if req.BillingDetails != nil {
		stripeParams.BillingDetails = &stripe.PaymentMethodBillingDetailsParams{
			Address: &stripe.AddressParams{
				City:       stripe.String(req.BillingDetails.Address.City),
				Country:    stripe.String(req.BillingDetails.Address.Country),
				Line1:      stripe.String(req.BillingDetails.Address.Line1),
				PostalCode: stripe.String(req.BillingDetails.Address.PostalCode),
			},
			Email: stripe.String(req.BillingDetails.Email),
			Name:  stripe.String(req.BillingDetails.Name),
		}
		
		if req.BillingDetails.Address.Line2 != nil {
			stripeParams.BillingDetails.Address.Line2 = stripe.String(*req.BillingDetails.Address.Line2)
		}
		if req.BillingDetails.Address.State != nil {
			stripeParams.BillingDetails.Address.State = stripe.String(*req.BillingDetails.Address.State)
		}
		if req.BillingDetails.Phone != nil {
			stripeParams.BillingDetails.Phone = stripe.String(*req.BillingDetails.Phone)
		}
	}
	
	// Add metadata for compliance and audit
	stripeParams.Metadata = map[string]string{
		"tenant_id":              req.TenantID.String(),
		"customer_id":            req.CustomerID.String(),
		"security_clearance":     req.SecurityClearance,
		"audit_trail_id":         auditTrailID,
		"created_by":             req.CreatedBy.String(),
		"pci_compliant":          fmt.Sprintf("%t", s.pciCompliant),
		"compliance_frameworks":  strings.Join(req.ComplianceFrameworks, ","),
	}
	
	// Create payment method in Stripe
	stripePM, err := paymentmethod.New(stripeParams)
	if err != nil {
		s.auditLogger.Error("Failed to create Stripe payment method",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, s.handleStripeError(err)
	}
	
	// Create internal payment method entity
	pm := entity.NewPaymentMethod(
		req.TenantID,
		req.CustomerID,
		stripePM.ID,
		req.Type,
		req.CreatedBy,
	)
	
	// Set card-specific details
	if stripePM.Card != nil {
		cardBrand := entity.CardBrand(stripePM.Card.Brand)
		pm.CardBrand = &cardBrand
		pm.CardLast4 = &stripePM.Card.Last4
		expMonth := int(stripePM.Card.ExpMonth)
		expYear := int(stripePM.Card.ExpYear)
		pm.CardExpMonth = &expMonth
		pm.CardExpYear = &expYear
		pm.CardFingerprint = &stripePM.Card.Fingerprint
		pm.CardCountry = &stripePM.Card.Country
		pm.CardFunding = &stripePM.Card.Funding
	}
	
	// Set billing address
	if req.BillingDetails != nil {
		pm.BillingAddress = &entity.BillingAddress{
			Line1:      req.BillingDetails.Address.Line1,
			Line2:      req.BillingDetails.Address.Line2,
			City:       req.BillingDetails.Address.City,
			State:      req.BillingDetails.Address.State,
			PostalCode: req.BillingDetails.Address.PostalCode,
			Country:    req.BillingDetails.Address.Country,
		}
	}
	
	// Set security properties
	pm.SecurityClearance = req.SecurityClearance
	pm.PCI3DSRequired = s.config.Require3DSecure
	
	// Add audit metadata
	pm.Metadata = map[string]interface{}{
		"audit_trail_id":         auditTrailID,
		"stripe_fingerprint":     stripePM.Card.Fingerprint,
		"compliance_frameworks":  req.ComplianceFrameworks,
		"created_via":            "api",
		"pci_compliant":          s.pciCompliant,
	}
	
	// Save to database
	if err := s.repository.Create(ctx, pm); err != nil {
		// If database save fails, try to delete from Stripe to maintain consistency
		if _, delErr := paymentmethod.Detach(stripePM.ID, nil); delErr != nil {
			s.logger.Error("Failed to cleanup Stripe payment method after database failure",
				zap.String("stripe_payment_method_id", stripePM.ID),
				zap.Error(delErr),
			)
		}
		
		s.auditLogger.Error("Failed to save payment method to database",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to save payment method: %w", err)
	}
	
	s.auditLogger.Info("Payment method created successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("payment_method_id", pm.ID.String()),
		zap.String("stripe_payment_method_id", stripePM.ID),
	)
	
	return pm, nil
}

// ProcessPayment processes a payment using the specified payment method
func (s *StripePaymentService) ProcessPayment(
	ctx context.Context,
	req *PaymentRequest,
) (*PaymentResponse, error) {
	
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	s.auditLogger.Info("Processing payment",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("customer_id", req.CustomerID.String()),
		zap.Int64("amount", req.Amount),
		zap.String("currency", req.Currency),
	)
	
	defer func() {
		s.auditLogger.Info("Payment processing completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("duration", time.Since(start)),
		)
	}()
	
	// Validate security clearance
	if req.RequireSecurityClearance {
		if err := s.validateSecurityClearance(req.SecurityClearance); err != nil {
			s.auditLogger.Error("Security clearance validation failed for payment",
				zap.String("audit_trail_id", auditTrailID),
				zap.Error(err),
			)
			return nil, fmt.Errorf("security clearance validation failed: %w", err)
		}
	}
	
	// Get payment method
	pm, err := s.repository.GetByID(ctx, req.PaymentMethodID)
	if err != nil {
		return nil, fmt.Errorf("failed to get payment method: %w", err)
	}
	
	// Validate payment method is active
	if !pm.IsActive() {
		return nil, entity.ErrPaymentMethodInactive
	}
	
	// Create payment intent params
	params := &stripe.PaymentIntentParams{
		Amount:             stripe.Int64(req.Amount),
		Currency:           stripe.String(req.Currency),
		PaymentMethod:      stripe.String(pm.StripePaymentMethodID),
		CaptureMethod:      stripe.String(req.CaptureMethod),
		ConfirmationMethod: stripe.String(req.ConfirmationMethod),
		Confirm:            stripe.Bool(true),
		Description:        stripe.String(req.Description),
	}
	
	// Set statement descriptor for compliance
	if req.StatementDescriptor != nil {
		params.StatementDescriptor = stripe.String(*req.StatementDescriptor)
	} else if s.config.RequireStatementDescriptor {
		params.StatementDescriptor = stripe.String(s.config.StatementDescriptor)
	}
	
	// Add setup for future usage if specified
	if req.SetupFutureUsage != "" {
		params.SetupFutureUsage = stripe.String(req.SetupFutureUsage)
	}
	
	// Add metadata for compliance and audit
	params.Metadata = map[string]string{
		"tenant_id":              req.TenantID.String(),
		"customer_id":            req.CustomerID.String(),
		"payment_method_id":      req.PaymentMethodID.String(),
		"security_clearance":     req.SecurityClearance,
		"audit_trail_id":         auditTrailID,
		"compliance_frameworks":  strings.Join(req.ComplianceFrameworks, ","),
		"pci_compliant":          fmt.Sprintf("%t", s.pciCompliant),
	}
	
	// Add custom metadata
	for k, v := range req.Metadata {
		params.Metadata[k] = v
	}
	
	// Add invoice ID if provided
	if req.InvoiceID != nil {
		params.Metadata["invoice_id"] = req.InvoiceID.String()
	}
	
	// Create and confirm payment intent
	pi, err := paymentintent.New(params)
	if err != nil {
		s.auditLogger.Error("Failed to create payment intent",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, s.handleStripeError(err)
	}
	
	// Build response
	response := &PaymentResponse{
		PaymentIntentID:     pi.ID,
		Status:              string(pi.Status),
		Amount:              pi.Amount,
		Currency:            string(pi.Currency),
		Metadata:            pi.Metadata,
		SecurityClearance:   req.SecurityClearance,
		AuditTrailID:        auditTrailID,
		ProcessedAt:         time.Now(),
		RequiresAction:      pi.Status == stripe.PaymentIntentStatusRequiresAction,
		RequiresConfirmation: pi.Status == stripe.PaymentIntentStatusRequiresConfirmation,
	}
	
	// Add client secret if needed for frontend
	if pi.Status == stripe.PaymentIntentStatusRequiresAction {
		response.ClientSecret = pi.ClientSecret
	}
	
	// Handle different payment statuses
	switch pi.Status {
	case stripe.PaymentIntentStatusSucceeded:
		s.auditLogger.Info("Payment succeeded",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("payment_intent_id", pi.ID),
		)
		
	case stripe.PaymentIntentStatusRequiresAction:
		s.auditLogger.Info("Payment requires action (3D Secure)",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("payment_intent_id", pi.ID),
		)
		
	case stripe.PaymentIntentStatusRequiresPaymentMethod:
		s.auditLogger.Warn("Payment requires different payment method",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("payment_intent_id", pi.ID),
		)
		
	case stripe.PaymentIntentStatusRequiresConfirmation:
		s.auditLogger.Info("Payment requires confirmation",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("payment_intent_id", pi.ID),
		)
		
	default:
		s.auditLogger.Info("Payment status",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("payment_intent_id", pi.ID),
			zap.String("status", string(pi.Status)),
		)
	}
	
	return response, nil
}

// SetupPaymentMethod sets up a payment method for future use without charging
func (s *StripePaymentService) SetupPaymentMethod(
	ctx context.Context,
	req *SetupPaymentMethodRequest,
) (*SetupPaymentMethodResponse, error) {
	
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Setting up payment method",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("customer_id", req.CustomerID.String()),
	)
	
	// Get payment method
	pm, err := s.repository.GetByID(ctx, req.PaymentMethodID)
	if err != nil {
		return nil, fmt.Errorf("failed to get payment method: %w", err)
	}
	
	// Create setup intent
	params := &stripe.SetupIntentParams{
		PaymentMethod: stripe.String(pm.StripePaymentMethodID),
		Confirm:       stripe.Bool(true),
		Usage:         stripe.String(req.Usage),
	}
	
	// Add metadata
	params.Metadata = map[string]string{
		"tenant_id":         req.TenantID.String(),
		"customer_id":       req.CustomerID.String(),
		"payment_method_id": req.PaymentMethodID.String(),
		"audit_trail_id":    auditTrailID,
	}
	
	si, err := setupintent.New(params)
	if err != nil {
		s.auditLogger.Error("Failed to create setup intent",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, s.handleStripeError(err)
	}
	
	response := &SetupPaymentMethodResponse{
		SetupIntentID:       si.ID,
		Status:              string(si.Status),
		ClientSecret:        si.ClientSecret,
		RequiresAction:      si.Status == stripe.SetupIntentStatusRequiresAction,
		RequiresConfirmation: si.Status == stripe.SetupIntentStatusRequiresConfirmation,
		AuditTrailID:        auditTrailID,
	}
	
	return response, nil
}

// ensureStripeCustomer ensures a Stripe customer exists for the given customer ID
func (s *StripePaymentService) ensureStripeCustomer(
	ctx context.Context,
	customerID uuid.UUID,
	email string,
) (string, error) {
	
	// First, try to find existing customer in our database
	// This would typically be done through a customer repository
	// For now, we'll create a new customer
	
	params := &stripe.CustomerParams{
		Email: stripe.String(email),
		Metadata: map[string]string{
			"customer_id": customerID.String(),
		},
	}
	
	c, err := customer.New(params)
	if err != nil {
		return "", fmt.Errorf("failed to create Stripe customer: %w", err)
	}
	
	return c.ID, nil
}

// validateSecurityClearance validates security clearance requirements
func (s *StripePaymentService) validateSecurityClearance(clearance string) error {
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
func (s *StripePaymentService) handleStripeError(err error) error {
	if stripeErr, ok := err.(*stripe.Error); ok {
		switch stripeErr.Code {
		case stripe.ErrorCodeCardDeclined:
			return entity.ErrPaymentDeclined
		case stripe.ErrorCodeInsufficientFunds:
			return entity.ErrInsufficientFunds
		case stripe.ErrorCodeExpiredCard:
			return entity.ErrPaymentMethodExpired
		case stripe.ErrorCodeIncorrectCVC:
			return entity.ErrPaymentFailed
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

// Additional request/response types...

type CreatePaymentMethodRequest struct {
	TenantID             uuid.UUID                      `json:"tenant_id"`
	CustomerID           uuid.UUID                      `json:"customer_id"`
	CustomerEmail        string                         `json:"customer_email"`
	Type                 entity.PaymentMethodType       `json:"type"`
	Card                 *CardDetails                   `json:"card,omitempty"`
	BillingDetails       *BillingDetails                `json:"billing_details,omitempty"`
	SecurityClearance    string                         `json:"security_clearance"`
	ComplianceFrameworks []string                       `json:"compliance_frameworks"`
	CreatedBy            uuid.UUID                      `json:"created_by"`
}

type CardDetails struct {
	Number   string `json:"number"`
	ExpMonth int    `json:"exp_month"`
	ExpYear  int    `json:"exp_year"`
	CVC      string `json:"cvc"`
}

type BillingDetails struct {
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Phone   *string  `json:"phone,omitempty"`
	Address *Address `json:"address"`
}

type Address struct {
	Line1      string  `json:"line1"`
	Line2      *string `json:"line2,omitempty"`
	City       string  `json:"city"`
	State      *string `json:"state,omitempty"`
	PostalCode string  `json:"postal_code"`
	Country    string  `json:"country"`
}

type SetupPaymentMethodRequest struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	CustomerID      uuid.UUID `json:"customer_id"`
	PaymentMethodID uuid.UUID `json:"payment_method_id"`
	Usage           string    `json:"usage"` // "on_session" or "off_session"
}

type SetupPaymentMethodResponse struct {
	SetupIntentID        string `json:"setup_intent_id"`
	Status               string `json:"status"`
	ClientSecret         string `json:"client_secret"`
	RequiresAction       bool   `json:"requires_action"`
	RequiresConfirmation bool   `json:"requires_confirmation"`
	AuditTrailID         string `json:"audit_trail_id"`
}