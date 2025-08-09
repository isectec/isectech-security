package invoice

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v74"
	"github.com/stripe/stripe-go/v74/invoice"
	"github.com/stripe/stripe-go/v74/invoiceitem"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
)

// InvoiceService handles invoice generation, tax calculation, and automated delivery
type InvoiceService struct {
	logger              *zap.Logger
	config              *config.Config
	invoiceRepo         InvoiceRepository
	subscriptionRepo    SubscriptionRepository
	taxService          TaxService
	pdfGenerator        PDFGenerator
	emailService        EmailService
	auditLogger         *zap.Logger
	
	// Invoice numbering
	invoiceNumberGenerator InvoiceNumberGenerator
}

// InvoiceRepository defines the interface for invoice storage
type InvoiceRepository interface {
	Create(ctx context.Context, invoice *entity.Invoice) error
	Update(ctx context.Context, invoice *entity.Invoice) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Invoice, error)
	GetByStripeID(ctx context.Context, stripeID string) (*entity.Invoice, error)
	GetByInvoiceNumber(ctx context.Context, invoiceNumber string) (*entity.Invoice, error)
	ListByCustomer(ctx context.Context, customerID uuid.UUID, filter *entity.InvoiceFilter) ([]*entity.Invoice, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, filter *entity.InvoiceFilter) ([]*entity.Invoice, error)
	ListOverdue(ctx context.Context, maxDays int) ([]*entity.Invoice, error)
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Analytics methods
	GetTotalRevenue(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (int64, error)
	GetRevenueByMonth(ctx context.Context, tenantID uuid.UUID, year int) (map[string]int64, error)
	GetOutstandingAmount(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// SubscriptionRepository defines the interface for subscription operations
type SubscriptionRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Subscription, error)
}

// TaxService defines the interface for tax calculations
type TaxService interface {
	CalculateTax(ctx context.Context, req *TaxCalculationRequest) (*TaxCalculationResponse, error)
	ValidateVATNumber(ctx context.Context, vatNumber, country string) (*VATValidationResponse, error)
	GetTaxRatesForLocation(ctx context.Context, address *entity.BillingAddress) ([]*TaxRate, error)
}

// PDFGenerator defines the interface for PDF generation
type PDFGenerator interface {
	GenerateInvoicePDF(ctx context.Context, invoice *entity.Invoice) (*PDFResult, error)
	GetPDFTemplate(invoiceType entity.InvoiceType) (string, error)
}

// EmailService defines the interface for email operations
type EmailService interface {
	SendInvoiceEmail(ctx context.Context, invoice *entity.Invoice, pdfPath string, recipient EmailRecipient) error
	SendInvoiceReminderEmail(ctx context.Context, invoice *entity.Invoice, reminderType ReminderType) error
	SendPaymentConfirmationEmail(ctx context.Context, invoice *entity.Invoice) error
}

// InvoiceNumberGenerator defines the interface for generating invoice numbers
type InvoiceNumberGenerator interface {
	GenerateInvoiceNumber(ctx context.Context, tenantID uuid.UUID, invoiceType entity.InvoiceType) (string, error)
}

// TaxCalculationRequest represents a tax calculation request
type TaxCalculationRequest struct {
	TenantID         uuid.UUID                `json:"tenant_id"`
	CustomerID       uuid.UUID                `json:"customer_id"`
	BillingAddress   *entity.BillingAddress   `json:"billing_address"`
	ShippingAddress  *entity.Address          `json:"shipping_address,omitempty"`
	LineItems        []TaxLineItem            `json:"line_items"`
	Currency         string                   `json:"currency"`
	TaxDate          time.Time                `json:"tax_date"`
	ExemptionType    *string                  `json:"exemption_type,omitempty"`
	ExemptionCert    *string                  `json:"exemption_cert,omitempty"`
}

// TaxLineItem represents a line item for tax calculation
type TaxLineItem struct {
	ID               string                   `json:"id"`
	Description      string                   `json:"description"`
	Amount           int64                    `json:"amount"`           // Amount in cents
	Quantity         int32                    `json:"quantity"`
	TaxCode          *string                  `json:"tax_code,omitempty"`
	Discountable     bool                     `json:"discountable"`
	Metadata         map[string]interface{}   `json:"metadata,omitempty"`
}

// TaxCalculationResponse represents a tax calculation response
type TaxCalculationResponse struct {
	TransactionID    string                   `json:"transaction_id"`
	TotalTax         int64                    `json:"total_tax"`         // Total tax amount in cents
	TaxDetails       []entity.TaxDetail       `json:"tax_details"`
	ExemptAmount     int64                    `json:"exempt_amount"`     // Exempt amount in cents
	TaxableAmount    int64                    `json:"taxable_amount"`    // Taxable amount in cents
	LineItemTaxes    []LineItemTax            `json:"line_item_taxes"`
	Errors           []TaxError               `json:"errors,omitempty"`
}

// LineItemTax represents tax calculation for a specific line item
type LineItemTax struct {
	LineItemID       string                   `json:"line_item_id"`
	TaxAmount        int64                    `json:"tax_amount"`       // Tax amount in cents
	TaxDetails       []entity.TaxDetail       `json:"tax_details"`
	ExemptAmount     int64                    `json:"exempt_amount"`    // Exempt amount in cents
	TaxableAmount    int64                    `json:"taxable_amount"`   // Taxable amount in cents
}

// TaxError represents a tax calculation error
type TaxError struct {
	Code             string                   `json:"code"`
	Message          string                   `json:"message"`
	LineItemID       *string                  `json:"line_item_id,omitempty"`
	Field            *string                  `json:"field,omitempty"`
}

// TaxRate represents a tax rate
type TaxRate struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Rate             float64                  `json:"rate"`             // Rate as percentage
	Type             string                   `json:"type"`             // "sales_tax", "vat", "gst", etc.
	Jurisdiction     string                   `json:"jurisdiction"`
	Country          string                   `json:"country"`
	State            *string                  `json:"state,omitempty"`
	Active           bool                     `json:"active"`
}

// VATValidationResponse represents VAT number validation response
type VATValidationResponse struct {
	Valid            bool                     `json:"valid"`
	CompanyName      *string                  `json:"company_name,omitempty"`
	CompanyAddress   *string                  `json:"company_address,omitempty"`
	Country          string                   `json:"country"`
	ValidationDate   time.Time                `json:"validation_date"`
	Errors           []string                 `json:"errors,omitempty"`
}

// PDFResult represents PDF generation result
type PDFResult struct {
	FilePath         string                   `json:"file_path"`
	FileSize         int64                    `json:"file_size"`
	GeneratedAt      time.Time                `json:"generated_at"`
}

// EmailRecipient represents an email recipient
type EmailRecipient struct {
	Email            string                   `json:"email"`
	Name             string                   `json:"name"`
	Type             string                   `json:"type"`             // "customer", "accounting", "admin"
}

// ReminderType represents different reminder types
type ReminderType string

const (
	ReminderTypePaymentDue    ReminderType = "payment_due"
	ReminderTypeOverdue       ReminderType = "overdue"
	ReminderTypeFinalNotice   ReminderType = "final_notice"
)

// CreateInvoiceRequest represents a request to create an invoice
type CreateInvoiceRequest struct {
	TenantID              uuid.UUID                `json:"tenant_id"`
	CustomerID            uuid.UUID                `json:"customer_id"`
	SubscriptionID        *uuid.UUID               `json:"subscription_id,omitempty"`
	InvoiceType           entity.InvoiceType       `json:"invoice_type"`
	Currency              string                   `json:"currency"`
	Description           *string                  `json:"description,omitempty"`
	
	// Line items
	LineItems             []CreateLineItemRequest  `json:"line_items"`
	
	// Payment configuration
	PaymentTerms          entity.PaymentTerms      `json:"payment_terms"`
	DueDate               *time.Time               `json:"due_date,omitempty"`
	PaymentMethodID       *uuid.UUID               `json:"payment_method_id,omitempty"`
	
	// Billing details
	BillingAddress        *entity.BillingAddress   `json:"billing_address,omitempty"`
	ShippingAddress       *entity.Address          `json:"shipping_address,omitempty"`
	
	// Tax configuration
	TaxExempt             bool                     `json:"tax_exempt"`
	TaxExemptReason       *string                  `json:"tax_exempt_reason,omitempty"`
	AutoCalculateTax      bool                     `json:"auto_calculate_tax"`
	
	// Discount
	CouponCode            *string                  `json:"coupon_code,omitempty"`
	DiscountAmount        *int64                   `json:"discount_amount,omitempty"`
	
	// PDF and delivery
	AutoGeneratePDF       bool                     `json:"auto_generate_pdf"`
	AutoSendEmail         bool                     `json:"auto_send_email"`
	EmailRecipients       []EmailRecipient         `json:"email_recipients,omitempty"`
	
	// Security and compliance
	SecurityClearance     string                   `json:"security_clearance"`
	ComplianceFrameworks  []string                 `json:"compliance_frameworks"`
	
	// Metadata
	Metadata              map[string]string        `json:"metadata,omitempty"`
	
	// Created by
	CreatedBy             uuid.UUID                `json:"created_by"`
}

// CreateLineItemRequest represents a request to create a line item
type CreateLineItemRequest struct {
	Description           string                   `json:"description"`
	Quantity              int32                    `json:"quantity"`
	UnitAmount            int64                    `json:"unit_amount"`     // Amount per unit in cents
	Currency              string                   `json:"currency"`
	TaxCode               *string                  `json:"tax_code,omitempty"`
	Discountable          bool                     `json:"discountable"`
	PeriodStart           *time.Time               `json:"period_start,omitempty"`
	PeriodEnd             *time.Time               `json:"period_end,omitempty"`
	Metadata              map[string]interface{}   `json:"metadata,omitempty"`
}

// InvoiceResponse represents an invoice operation response
type InvoiceResponse struct {
	Invoice              *entity.Invoice          `json:"invoice"`
	TaxCalculation       *TaxCalculationResponse  `json:"tax_calculation,omitempty"`
	PDFResult            *PDFResult               `json:"pdf_result,omitempty"`
	EmailSent            bool                     `json:"email_sent"`
	AuditTrailID         string                   `json:"audit_trail_id"`
}

// NewInvoiceService creates a new invoice service
func NewInvoiceService(
	logger *zap.Logger,
	config *config.Config,
	invoiceRepo InvoiceRepository,
	subscriptionRepo SubscriptionRepository,
	taxService TaxService,
	pdfGenerator PDFGenerator,
	emailService EmailService,
	invoiceNumberGenerator InvoiceNumberGenerator,
) *InvoiceService {
	
	auditLogger := logger.Named("invoice_audit").With(
		zap.String("service", "invoice_management"),
		zap.String("environment", config.Stripe.Environment),
	)
	
	return &InvoiceService{
		logger:                 logger.Named("invoice_service"),
		config:                 config,
		invoiceRepo:            invoiceRepo,
		subscriptionRepo:       subscriptionRepo,
		taxService:             taxService,
		pdfGenerator:           pdfGenerator,
		emailService:           emailService,
		invoiceNumberGenerator: invoiceNumberGenerator,
		auditLogger:            auditLogger,
	}
}

// CreateInvoice creates a new invoice with tax calculation and automated delivery
func (s *InvoiceService) CreateInvoice(
	ctx context.Context,
	req *CreateInvoiceRequest,
) (*InvoiceResponse, error) {
	
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	s.auditLogger.Info("Creating invoice",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("customer_id", req.CustomerID.String()),
		zap.String("invoice_type", string(req.InvoiceType)),
	)
	
	defer func() {
		s.auditLogger.Info("Invoice creation completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("duration", time.Since(start)),
		)
	}()
	
	// Generate invoice number
	invoiceNumber, err := s.invoiceNumberGenerator.GenerateInvoiceNumber(ctx, req.TenantID, req.InvoiceType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate invoice number: %w", err)
	}
	
	// Create invoice entity
	invoice := entity.NewInvoice(
		req.TenantID,
		req.CustomerID,
		invoiceNumber,
		req.InvoiceType,
		req.Currency,
		req.SecurityClearance,
		req.CreatedBy,
	)
	
	// Set subscription if provided
	if req.SubscriptionID != nil {
		invoice.SubscriptionID = req.SubscriptionID
	}
	
	// Set payment configuration
	invoice.PaymentTerms = req.PaymentTerms
	if req.DueDate != nil {
		invoice.DueDate = *req.DueDate
	} else {
		// Calculate due date based on payment terms
		paymentDays := invoice.GetPaymentTermsDays()
		invoice.DueDate = invoice.InvoiceDate.AddDate(0, 0, paymentDays)
	}
	
	if req.PaymentMethodID != nil {
		invoice.PaymentMethodID = req.PaymentMethodID
	}
	
	// Set addresses
	invoice.BillingAddress = req.BillingAddress
	invoice.ShippingAddress = req.ShippingAddress
	
	// Set tax configuration
	invoice.TaxExempt = req.TaxExempt
	invoice.TaxExemptReason = req.TaxExemptReason
	
	// Set discount
	if req.CouponCode != nil {
		invoice.CouponCode = req.CouponCode
	}
	if req.DiscountAmount != nil {
		invoice.DiscountAmount = *req.DiscountAmount
	}
	
	// Set description
	invoice.Description = req.Description
	
	// Set compliance frameworks
	invoice.ComplianceFrameworks = req.ComplianceFrameworks
	
	// Add line items
	for i, lineItemReq := range req.LineItems {
		lineItem := entity.InvoiceLineItem{
			ID:           fmt.Sprintf("li_%d", i+1),
			Type:         "invoice_item",
			Description:  lineItemReq.Description,
			Quantity:     lineItemReq.Quantity,
			UnitAmount:   lineItemReq.UnitAmount,
			Amount:       lineItemReq.UnitAmount * int64(lineItemReq.Quantity),
			Currency:     lineItemReq.Currency,
			Discountable: lineItemReq.Discountable,
			PeriodStart:  lineItemReq.PeriodStart,
			PeriodEnd:    lineItemReq.PeriodEnd,
			Metadata:     lineItemReq.Metadata,
		}
		
		invoice.AddLineItem(lineItem)
	}
	
	var taxCalculation *TaxCalculationResponse
	
	// Calculate tax if not exempt and auto-calculation is enabled
	if !req.TaxExempt && req.AutoCalculateTax {
		taxReq := &TaxCalculationRequest{
			TenantID:        req.TenantID,
			CustomerID:      req.CustomerID,
			BillingAddress:  req.BillingAddress,
			ShippingAddress: req.ShippingAddress,
			Currency:        req.Currency,
			TaxDate:         invoice.InvoiceDate,
		}
		
		// Convert line items for tax calculation
		for _, item := range invoice.LineItems {
			taxLineItem := TaxLineItem{
				ID:           item.ID,
				Description:  item.Description,
				Amount:       item.Amount,
				Quantity:     item.Quantity,
				Discountable: item.Discountable,
				Metadata:     item.Metadata,
			}
			taxReq.LineItems = append(taxReq.LineItems, taxLineItem)
		}
		
		taxCalculation, err = s.taxService.CalculateTax(ctx, taxReq)
		if err != nil {
			s.auditLogger.Error("Failed to calculate tax",
				zap.String("audit_trail_id", auditTrailID),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to calculate tax: %w", err)
		}
		
		// Apply tax calculation results
		invoice.TaxAmount = taxCalculation.TotalTax
		invoice.TaxDetails = taxCalculation.TaxDetails
		
		// Update line item tax amounts
		for _, lineItemTax := range taxCalculation.LineItemTaxes {
			for i, item := range invoice.LineItems {
				if item.ID == lineItemTax.LineItemID {
					for _, taxDetail := range lineItemTax.TaxDetails {
						taxAmount := entity.TaxAmount{
							TaxRateID: taxDetail.TaxRateID,
							Amount:    taxDetail.TaxAmount,
							Inclusive: false,
						}
						invoice.LineItems[i].TaxAmounts = append(invoice.LineItems[i].TaxAmounts, taxAmount)
					}
					break
				}
			}
		}
		
		// Recalculate totals with tax
		invoice.TotalAmount = invoice.SubtotalAmount + invoice.TaxAmount - invoice.DiscountAmount
		invoice.AmountDue = invoice.TotalAmount
	}
	
	// Create invoice in Stripe if not a credit note
	var stripeInvoiceID string
	if req.InvoiceType != entity.InvoiceTypeCredit && req.InvoiceType != entity.InvoiceTypeRefund {
		stripeInvoiceID, err = s.createStripeInvoice(ctx, invoice, req)
		if err != nil {
			s.auditLogger.Error("Failed to create Stripe invoice",
				zap.String("audit_trail_id", auditTrailID),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to create Stripe invoice: %w", err)
		}
		invoice.StripeInvoiceID = stripeInvoiceID
	}
	
	// Add audit metadata
	invoice.Metadata = map[string]interface{}{
		"audit_trail_id":      auditTrailID,
		"created_via":         "api",
		"tax_calculated":      req.AutoCalculateTax && !req.TaxExempt,
		"compliance_frameworks": req.ComplianceFrameworks,
	}
	
	// Add custom metadata
	for k, v := range req.Metadata {
		invoice.Metadata[k] = v
	}
	
	// Save to database
	if err := s.invoiceRepo.Create(ctx, invoice); err != nil {
		// If database save fails and we created a Stripe invoice, try to delete it
		if stripeInvoiceID != "" {
			if _, delErr := invoice.Del(stripeInvoiceID, nil); delErr != nil {
				s.logger.Error("Failed to cleanup Stripe invoice after database failure",
					zap.String("stripe_invoice_id", stripeInvoiceID),
					zap.Error(delErr),
				)
			}
		}
		
		s.auditLogger.Error("Failed to save invoice to database",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to save invoice: %w", err)
	}
	
	response := &InvoiceResponse{
		Invoice:        invoice,
		TaxCalculation: taxCalculation,
		AuditTrailID:   auditTrailID,
	}
	
	// Generate PDF if requested
	if req.AutoGeneratePDF {
		pdfResult, err := s.GenerateInvoicePDF(ctx, invoice.ID)
		if err != nil {
			s.logger.Error("Failed to generate PDF, continuing without it",
				zap.String("invoice_id", invoice.ID.String()),
				zap.Error(err),
			)
		} else {
			response.PDFResult = pdfResult
		}
	}
	
	// Send email if requested
	if req.AutoSendEmail && len(req.EmailRecipients) > 0 {
		pdfPath := ""
		if response.PDFResult != nil {
			pdfPath = response.PDFResult.FilePath
		}
		
		for _, recipient := range req.EmailRecipients {
			if err := s.emailService.SendInvoiceEmail(ctx, invoice, pdfPath, recipient); err != nil {
				s.logger.Error("Failed to send invoice email",
					zap.String("invoice_id", invoice.ID.String()),
					zap.String("recipient", recipient.Email),
					zap.Error(err),
				)
			} else {
				response.EmailSent = true
			}
		}
		
		if response.EmailSent {
			invoice.EmailSent = true
			now := time.Now()
			invoice.EmailSentAt = &now
			
			// Update database
			if err := s.invoiceRepo.Update(ctx, invoice); err != nil {
				s.logger.Error("Failed to update invoice email status",
					zap.String("invoice_id", invoice.ID.String()),
					zap.Error(err),
				)
			}
		}
	}
	
	s.auditLogger.Info("Invoice created successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoice.ID.String()),
		zap.String("invoice_number", invoice.InvoiceNumber),
		zap.String("stripe_invoice_id", stripeInvoiceID),
	)
	
	return response, nil
}

// GenerateInvoicePDF generates a PDF for an existing invoice
func (s *InvoiceService) GenerateInvoicePDF(ctx context.Context, invoiceID uuid.UUID) (*PDFResult, error) {
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Generating invoice PDF",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoiceID.String()),
	)
	
	// Get invoice
	invoice, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get invoice: %w", err)
	}
	
	// Generate PDF
	pdfResult, err := s.pdfGenerator.GenerateInvoicePDF(ctx, invoice)
	if err != nil {
		s.auditLogger.Error("Failed to generate PDF",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("invoice_id", invoiceID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}
	
	// Update invoice with PDF information
	invoice.PDFGenerated = true
	invoice.PDFPath = &pdfResult.FilePath
	invoice.PDFSize = &pdfResult.FileSize
	invoice.UpdatedAt = time.Now()
	
	// Add PDF metadata
	if invoice.Metadata == nil {
		invoice.Metadata = make(map[string]interface{})
	}
	invoice.Metadata["pdf_generated_at"] = pdfResult.GeneratedAt
	invoice.Metadata["pdf_audit_trail_id"] = auditTrailID
	
	// Save updated invoice
	if err := s.invoiceRepo.Update(ctx, invoice); err != nil {
		s.logger.Error("Failed to update invoice with PDF information",
			zap.String("invoice_id", invoiceID.String()),
			zap.Error(err),
		)
		// Don't fail the operation, PDF was generated successfully
	}
	
	s.auditLogger.Info("Invoice PDF generated successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoiceID.String()),
		zap.String("pdf_path", pdfResult.FilePath),
		zap.Int64("pdf_size", pdfResult.FileSize),
	)
	
	return pdfResult, nil
}

// SendInvoiceEmail sends an invoice via email
func (s *InvoiceService) SendInvoiceEmail(ctx context.Context, invoiceID uuid.UUID, recipients []EmailRecipient) error {
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Sending invoice email",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoiceID.String()),
		zap.Int("recipient_count", len(recipients)),
	)
	
	// Get invoice
	invoice, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to get invoice: %w", err)
	}
	
	// Get PDF path if available
	pdfPath := ""
	if invoice.PDFPath != nil {
		pdfPath = *invoice.PDFPath
	} else {
		// Generate PDF if not available
		pdfResult, err := s.GenerateInvoicePDF(ctx, invoiceID)
		if err != nil {
			s.logger.Error("Failed to generate PDF for email",
				zap.String("invoice_id", invoiceID.String()),
				zap.Error(err),
			)
		} else {
			pdfPath = pdfResult.FilePath
		}
	}
	
	// Send email to each recipient
	emailSent := false
	for _, recipient := range recipients {
		if err := s.emailService.SendInvoiceEmail(ctx, invoice, pdfPath, recipient); err != nil {
			s.auditLogger.Error("Failed to send invoice email to recipient",
				zap.String("audit_trail_id", auditTrailID),
				zap.String("invoice_id", invoiceID.String()),
				zap.String("recipient", recipient.Email),
				zap.Error(err),
			)
		} else {
			emailSent = true
			s.auditLogger.Info("Invoice email sent successfully",
				zap.String("audit_trail_id", auditTrailID),
				zap.String("invoice_id", invoiceID.String()),
				zap.String("recipient", recipient.Email),
			)
		}
	}
	
	// Update invoice if any email was sent
	if emailSent {
		invoice.EmailSent = true
		now := time.Now()
		invoice.EmailSentAt = &now
		invoice.UpdatedAt = time.Now()
		
		// Add email metadata
		if invoice.Metadata == nil {
			invoice.Metadata = make(map[string]interface{})
		}
		invoice.Metadata["email_sent_at"] = now
		invoice.Metadata["email_audit_trail_id"] = auditTrailID
		invoice.Metadata["email_recipient_count"] = len(recipients)
		
		// Save updated invoice
		if err := s.invoiceRepo.Update(ctx, invoice); err != nil {
			s.logger.Error("Failed to update invoice email status",
				zap.String("invoice_id", invoiceID.String()),
				zap.Error(err),
			)
		}
	}
	
	return nil
}

// FinalizeInvoice finalizes a draft invoice
func (s *InvoiceService) FinalizeInvoice(ctx context.Context, invoiceID uuid.UUID, finalizedBy uuid.UUID) error {
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Finalizing invoice",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoiceID.String()),
	)
	
	// Get invoice
	invoice, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to get invoice: %w", err)
	}
	
	if invoice.Status != entity.InvoiceStatusDraft {
		return fmt.Errorf("invoice is not in draft status")
	}
	
	// Finalize in Stripe if applicable
	if invoice.StripeInvoiceID != "" {
		_, err := invoice.FinalizeInvoice(invoice.StripeInvoiceID, nil)
		if err != nil {
			s.auditLogger.Error("Failed to finalize Stripe invoice",
				zap.String("audit_trail_id", auditTrailID),
				zap.String("stripe_invoice_id", invoice.StripeInvoiceID),
				zap.Error(err),
			)
			return s.handleStripeError(err)
		}
	}
	
	// Update invoice status
	invoice.Status = entity.InvoiceStatusOpen
	invoice.UpdatedAt = time.Now()
	invoice.UpdatedBy = finalizedBy
	
	// Add finalization metadata
	if invoice.Metadata == nil {
		invoice.Metadata = make(map[string]interface{})
	}
	invoice.Metadata["finalized_at"] = time.Now()
	invoice.Metadata["finalized_by"] = finalizedBy.String()
	invoice.Metadata["audit_trail_id"] = auditTrailID
	
	// Save updated invoice
	if err := s.invoiceRepo.Update(ctx, invoice); err != nil {
		s.auditLogger.Error("Failed to update finalized invoice",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to update invoice: %w", err)
	}
	
	s.auditLogger.Info("Invoice finalized successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoiceID.String()),
	)
	
	return nil
}

// VoidInvoice voids an invoice
func (s *InvoiceService) VoidInvoice(ctx context.Context, invoiceID uuid.UUID, voidedBy uuid.UUID, reason *string) error {
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Voiding invoice",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoiceID.String()),
	)
	
	// Get invoice
	invoice, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to get invoice: %w", err)
	}
	
	if !invoice.CanBeVoided() {
		return fmt.Errorf("invoice cannot be voided")
	}
	
	// Void in Stripe if applicable
	if invoice.StripeInvoiceID != "" {
		voidParams := &stripe.InvoiceVoidParams{}
		_, err := invoice.VoidInvoice(invoice.StripeInvoiceID, voidParams)
		if err != nil {
			s.auditLogger.Error("Failed to void Stripe invoice",
				zap.String("audit_trail_id", auditTrailID),
				zap.String("stripe_invoice_id", invoice.StripeInvoiceID),
				zap.Error(err),
			)
			return s.handleStripeError(err)
		}
	}
	
	// Update invoice status
	invoice.Status = entity.InvoiceStatusVoid
	now := time.Now()
	invoice.VoidedAt = &now
	invoice.UpdatedAt = time.Now()
	invoice.UpdatedBy = voidedBy
	
	// Add void metadata
	if invoice.Metadata == nil {
		invoice.Metadata = make(map[string]interface{})
	}
	invoice.Metadata["voided_at"] = now
	invoice.Metadata["voided_by"] = voidedBy.String()
	invoice.Metadata["audit_trail_id"] = auditTrailID
	if reason != nil {
		invoice.Metadata["void_reason"] = *reason
	}
	
	// Save updated invoice
	if err := s.invoiceRepo.Update(ctx, invoice); err != nil {
		s.auditLogger.Error("Failed to update voided invoice",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to update invoice: %w", err)
	}
	
	s.auditLogger.Info("Invoice voided successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoiceID.String()),
	)
	
	return nil
}

// createStripeInvoice creates an invoice in Stripe
func (s *InvoiceService) createStripeInvoice(ctx context.Context, inv *entity.Invoice, req *CreateInvoiceRequest) (string, error) {
	// Create invoice items first
	for _, lineItem := range inv.LineItems {
		itemParams := &stripe.InvoiceItemParams{
			Customer:    stripe.String(inv.CustomerID.String()),
			Amount:      stripe.Int64(lineItem.Amount),
			Currency:    stripe.String(lineItem.Currency),
			Description: stripe.String(lineItem.Description),
		}
		
		if lineItem.Quantity > 1 {
			itemParams.Quantity = stripe.Int64(int64(lineItem.Quantity))
			itemParams.UnitAmount = stripe.Int64(lineItem.UnitAmount)
		}
		
		// Add metadata
		itemParams.Metadata = map[string]string{
			"tenant_id":   req.TenantID.String(),
			"line_item_id": lineItem.ID,
		}
		
		// Add custom metadata
		for k, v := range lineItem.Metadata {
			if str, ok := v.(string); ok {
				itemParams.Metadata[k] = str
			}
		}
		
		_, err := invoiceitem.New(itemParams)
		if err != nil {
			return "", fmt.Errorf("failed to create invoice item: %w", err)
		}
	}
	
	// Create invoice
	invoiceParams := &stripe.InvoiceParams{
		Customer:    stripe.String(inv.CustomerID.String()),
		Currency:    stripe.String(inv.Currency),
		Description: inv.Description,
	}
	
	// Set collection method
	if req.PaymentMethodID != nil {
		invoiceParams.CollectionMethod = stripe.String("charge_automatically")
	} else {
		invoiceParams.CollectionMethod = stripe.String("send_invoice")
		invoiceParams.DaysUntilDue = stripe.Int64(int64(inv.GetPaymentTermsDays()))
	}
	
	// Set due date
	invoiceParams.DueDate = stripe.Int64(inv.DueDate.Unix())
	
	// Add metadata for compliance and audit
	invoiceParams.Metadata = map[string]string{
		"tenant_id":             req.TenantID.String(),
		"customer_id":           req.CustomerID.String(),
		"invoice_type":          string(req.InvoiceType),
		"security_clearance":    req.SecurityClearance,
		"compliance_frameworks": strings.Join(req.ComplianceFrameworks, ","),
		"invoice_number":        inv.InvoiceNumber,
	}
	
	// Add custom metadata
	for k, v := range req.Metadata {
		invoiceParams.Metadata[k] = v
	}
	
	stripeInvoice, err := invoice.New(invoiceParams)
	if err != nil {
		return "", fmt.Errorf("failed to create Stripe invoice: %w", err)
	}
	
	return stripeInvoice.ID, nil
}

// handleStripeError converts Stripe errors to internal errors
func (s *InvoiceService) handleStripeError(err error) error {
	if stripeErr, ok := err.(*stripe.Error); ok {
		switch stripeErr.Code {
		case stripe.ErrorCodeResourceMissing:
			return entity.ErrInvoiceNotFound
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