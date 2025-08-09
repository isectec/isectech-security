package entity

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// InvoiceStatus represents the status of an invoice
type InvoiceStatus string

const (
	InvoiceStatusDraft        InvoiceStatus = "draft"
	InvoiceStatusOpen         InvoiceStatus = "open"
	InvoiceStatusPaid         InvoiceStatus = "paid"
	InvoiceStatusVoid         InvoiceStatus = "void"
	InvoiceStatusUncollectible InvoiceStatus = "uncollectible"
	InvoiceStatusPartiallyPaid InvoiceStatus = "partially_paid"
	InvoiceStatusOverdue      InvoiceStatus = "overdue"
)

// InvoiceType represents the type of invoice
type InvoiceType string

const (
	InvoiceTypeSubscription InvoiceType = "subscription"
	InvoiceTypeOneTime      InvoiceType = "one_time"
	InvoiceTypeCredit       InvoiceType = "credit"
	InvoiceTypeRefund       InvoiceType = "refund"
	InvoiceTypeUsage        InvoiceType = "usage"
	InvoiceTypeProration    InvoiceType = "proration"
)

// PaymentTerms represents payment terms for an invoice
type PaymentTerms string

const (
	PaymentTermsNet0  PaymentTerms = "net_0"   // Due immediately
	PaymentTermsNet15 PaymentTerms = "net_15"  // Due in 15 days
	PaymentTermsNet30 PaymentTerms = "net_30"  // Due in 30 days
	PaymentTermsNet60 PaymentTerms = "net_60"  // Due in 60 days
	PaymentTermsNet90 PaymentTerms = "net_90"  // Due in 90 days
)

// Invoice represents a billing invoice
type Invoice struct {
	ID                    uuid.UUID      `json:"id" db:"id"`
	TenantID              uuid.UUID      `json:"tenant_id" db:"tenant_id"`
	CustomerID            uuid.UUID      `json:"customer_id" db:"customer_id"`
	SubscriptionID        *uuid.UUID     `json:"subscription_id,omitempty" db:"subscription_id"`
	StripeInvoiceID       string         `json:"stripe_invoice_id" db:"stripe_invoice_id"`
	
	// Invoice identification
	InvoiceNumber         string         `json:"invoice_number" db:"invoice_number"`
	InvoiceType           InvoiceType    `json:"invoice_type" db:"invoice_type"`
	Status                InvoiceStatus  `json:"status" db:"status"`
	
	// Dates
	InvoiceDate           time.Time      `json:"invoice_date" db:"invoice_date"`
	DueDate               time.Time      `json:"due_date" db:"due_date"`
	PeriodStart           *time.Time     `json:"period_start,omitempty" db:"period_start"`
	PeriodEnd             *time.Time     `json:"period_end,omitempty" db:"period_end"`
	PaidAt                *time.Time     `json:"paid_at,omitempty" db:"paid_at"`
	VoidedAt              *time.Time     `json:"voided_at,omitempty" db:"voided_at"`
	
	// Financial details
	Currency              string         `json:"currency" db:"currency"`
	SubtotalAmount        int64          `json:"subtotal_amount" db:"subtotal_amount"`   // Amount before tax in cents
	TaxAmount             int64          `json:"tax_amount" db:"tax_amount"`             // Tax amount in cents
	DiscountAmount        int64          `json:"discount_amount" db:"discount_amount"`   // Discount amount in cents
	TotalAmount           int64          `json:"total_amount" db:"total_amount"`         // Final amount in cents
	AmountPaid            int64          `json:"amount_paid" db:"amount_paid"`           // Amount already paid in cents
	AmountDue             int64          `json:"amount_due" db:"amount_due"`             // Amount still owed in cents
	
	// Payment information
	PaymentTerms          PaymentTerms   `json:"payment_terms" db:"payment_terms"`
	PaymentMethodID       *uuid.UUID     `json:"payment_method_id,omitempty" db:"payment_method_id"`
	PaymentAttempts       int            `json:"payment_attempts" db:"payment_attempts"`
	LastPaymentAttempt    *time.Time     `json:"last_payment_attempt,omitempty" db:"last_payment_attempt"`
	NextPaymentAttempt    *time.Time     `json:"next_payment_attempt,omitempty" db:"next_payment_attempt"`
	
	// Line items
	LineItems             []InvoiceLineItem `json:"line_items" db:"line_items"`
	
	// Tax details
	TaxDetails            []TaxDetail    `json:"tax_details,omitempty" db:"tax_details"`
	TaxExempt             bool           `json:"tax_exempt" db:"tax_exempt"`
	TaxExemptReason       *string        `json:"tax_exempt_reason,omitempty" db:"tax_exempt_reason"`
	
	// Discount information  
	DiscountID            *uuid.UUID     `json:"discount_id,omitempty" db:"discount_id"`
	CouponCode            *string        `json:"coupon_code,omitempty" db:"coupon_code"`
	
	// Business information
	BillingAddress        *BillingAddress `json:"billing_address,omitempty" db:"billing_address"`
	ShippingAddress       *Address        `json:"shipping_address,omitempty" db:"shipping_address"`
	
	// Document details
	Description           *string        `json:"description,omitempty" db:"description"`
	FooterText            *string        `json:"footer_text,omitempty" db:"footer_text"`
	StatementDescriptor   *string        `json:"statement_descriptor,omitempty" db:"statement_descriptor"`
	
	// PDF and delivery
	PDFGenerated          bool           `json:"pdf_generated" db:"pdf_generated"`
	PDFPath               *string        `json:"pdf_path,omitempty" db:"pdf_path"`
	PDFSize               *int64         `json:"pdf_size,omitempty" db:"pdf_size"`
	EmailSent             bool           `json:"email_sent" db:"email_sent"`
	EmailSentAt           *time.Time     `json:"email_sent_at,omitempty" db:"email_sent_at"`
	
	// Security and compliance
	SecurityClearance     string         `json:"security_clearance" db:"security_clearance"`
	ComplianceFrameworks  []string       `json:"compliance_frameworks" db:"compliance_frameworks"`
	
	// Audit fields
	CreatedAt             time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at" db:"updated_at"`
	CreatedBy             uuid.UUID      `json:"created_by" db:"created_by"`
	UpdatedBy             uuid.UUID      `json:"updated_by" db:"updated_by"`
	
	// Metadata for flexible storage
	Metadata              map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	
	// Calculated fields (not stored in DB)
	Customer              *Customer      `json:"customer,omitempty" db:"-"`
	Subscription          *Subscription  `json:"subscription,omitempty" db:"-"`
	PaymentMethod         *PaymentMethod `json:"payment_method,omitempty" db:"-"`
}

// InvoiceLineItem represents a line item on an invoice
type InvoiceLineItem struct {
	ID                    string         `json:"id"`
	Type                  string         `json:"type"` // "subscription", "invoice_item", "prorations"
	Description           string         `json:"description"`
	Quantity              int32          `json:"quantity"`
	UnitAmount            int64          `json:"unit_amount"`  // Amount per unit in cents
	Amount                int64          `json:"amount"`       // Total amount in cents
	Currency              string         `json:"currency"`
	Discountable          bool           `json:"discountable"`
	TaxRates              []string       `json:"tax_rates,omitempty"`
	TaxAmounts            []TaxAmount    `json:"tax_amounts,omitempty"`
	
	// Subscription-related
	SubscriptionID        *uuid.UUID     `json:"subscription_id,omitempty"`
	PlanID                *uuid.UUID     `json:"plan_id,omitempty"`
	PeriodStart           *time.Time     `json:"period_start,omitempty"`
	PeriodEnd             *time.Time     `json:"period_end,omitempty"`
	Proration             bool           `json:"proration"`
	
	// Usage-based billing
	UsageRecords          []UsageRecord  `json:"usage_records,omitempty"`
	
	// Metadata
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
}

// TaxDetail represents tax calculation details
type TaxDetail struct {
	TaxRateID             string         `json:"tax_rate_id"`
	TaxRateName           string         `json:"tax_rate_name"`
	TaxRatePercentage     float64        `json:"tax_rate_percentage"`
	TaxableAmount         int64          `json:"taxable_amount"`  // Amount that tax applies to in cents
	TaxAmount             int64          `json:"tax_amount"`      // Calculated tax in cents
	Jurisdiction          string         `json:"jurisdiction"`
	TaxType               string         `json:"tax_type"`        // "sales_tax", "vat", "gst", etc.
	InclusiveAmount       *int64         `json:"inclusive_amount,omitempty"` // For tax-inclusive pricing
}

// TaxAmount represents tax amount for a line item
type TaxAmount struct {
	TaxRateID             string         `json:"tax_rate_id"`
	Amount                int64          `json:"amount"`          // Tax amount in cents
	Inclusive             bool           `json:"inclusive"`       // Whether tax is inclusive
}

// UsageRecord represents usage for usage-based billing
type UsageRecord struct {
	ID                    string         `json:"id"`
	Quantity              int64          `json:"quantity"`
	Timestamp             time.Time      `json:"timestamp"`
	SubscriptionItemID    string         `json:"subscription_item_id"`
	Action                string         `json:"action"`     // "increment", "set"
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
}

// Address represents a generic address
type Address struct {
	Line1                 string         `json:"line1"`
	Line2                 *string        `json:"line2,omitempty"`
	City                  string         `json:"city"`
	State                 *string        `json:"state,omitempty"`
	PostalCode            string         `json:"postal_code"`
	Country               string         `json:"country"`
}

// IsOverdue checks if the invoice is overdue
func (i *Invoice) IsOverdue() bool {
	if i.Status == InvoiceStatusPaid || i.Status == InvoiceStatusVoid {
		return false
	}
	
	return time.Now().After(i.DueDate)
}

// IsPaid checks if the invoice is fully paid
func (i *Invoice) IsPaid() bool {
	return i.Status == InvoiceStatusPaid
}

// IsPartiallyPaid checks if the invoice is partially paid
func (i *Invoice) IsPartiallyPaid() bool {
	return i.Status == InvoiceStatusPartiallyPaid || 
		   (i.AmountPaid > 0 && i.AmountPaid < i.TotalAmount)
}

// IsVoid checks if the invoice is voided
func (i *Invoice) IsVoid() bool {
	return i.Status == InvoiceStatusVoid
}

// CanBePaid checks if the invoice can be paid
func (i *Invoice) CanBePaid() bool {
	return i.Status == InvoiceStatusOpen || i.Status == InvoiceStatusPartiallyPaid
}

// CanBeVoided checks if the invoice can be voided
func (i *Invoice) CanBeVoided() bool {
	return i.Status == InvoiceStatusDraft || i.Status == InvoiceStatusOpen
}

// GetDaysOverdue returns the number of days the invoice is overdue
func (i *Invoice) GetDaysOverdue() int {
	if !i.IsOverdue() {
		return 0
	}
	
	duration := time.Since(i.DueDate)
	return int(duration.Hours() / 24)
}

// GetRemainingBalance returns the remaining balance to be paid
func (i *Invoice) GetRemainingBalance() int64 {
	return i.TotalAmount - i.AmountPaid
}

// CalculateTotalTax calculates the total tax amount from tax details
func (i *Invoice) CalculateTotalTax() int64 {
	var total int64
	for _, tax := range i.TaxDetails {
		total += tax.TaxAmount
	}
	return total
}

// GetTaxRate returns the effective tax rate as a percentage
func (i *Invoice) GetTaxRate() float64 {
	if i.SubtotalAmount == 0 {
		return 0
	}
	
	return (float64(i.TaxAmount) / float64(i.SubtotalAmount)) * 100
}

// GetFormattedAmount returns the total amount formatted as currency
func (i *Invoice) GetFormattedAmount() string {
	switch i.Currency {
	case "usd":
		return fmt.Sprintf("$%.2f", float64(i.TotalAmount)/100)
	case "eur":
		return fmt.Sprintf("€%.2f", float64(i.TotalAmount)/100)
	case "gbp":
		return fmt.Sprintf("£%.2f", float64(i.TotalAmount)/100)
	default:
		return fmt.Sprintf("%.2f %s", float64(i.TotalAmount)/100, i.Currency)
	}
}

// GetFormattedDueDate returns the due date formatted for display
func (i *Invoice) GetFormattedDueDate() string {
	return i.DueDate.Format("January 2, 2006")
}

// GetPaymentTermsDays returns the number of days for payment terms
func (i *Invoice) GetPaymentTermsDays() int {
	switch i.PaymentTerms {
	case PaymentTermsNet0:
		return 0
	case PaymentTermsNet15:
		return 15
	case PaymentTermsNet30:
		return 30
	case PaymentTermsNet60:
		return 60
	case PaymentTermsNet90:
		return 90
	default:
		return 0
	}
}

// AddLineItem adds a line item to the invoice
func (i *Invoice) AddLineItem(item InvoiceLineItem) {
	i.LineItems = append(i.LineItems, item)
	i.recalculateTotals()
}

// RemoveLineItem removes a line item by ID
func (i *Invoice) RemoveLineItem(itemID string) {
	for idx, item := range i.LineItems {
		if item.ID == itemID {
			i.LineItems = append(i.LineItems[:idx], i.LineItems[idx+1:]...)
			break
		}
	}
	i.recalculateTotals()
}

// UpdateLineItem updates a line item
func (i *Invoice) UpdateLineItem(itemID string, updatedItem InvoiceLineItem) {
	for idx, item := range i.LineItems {
		if item.ID == itemID {
			i.LineItems[idx] = updatedItem
			break
		}
	}
	i.recalculateTotals()
}

// recalculateTotals recalculates invoice totals based on line items
func (i *Invoice) recalculateTotals() {
	var subtotal int64
	var taxAmount int64
	var discountAmount int64
	
	// Calculate subtotal from line items
	for _, item := range i.LineItems {
		subtotal += item.Amount
		
		// Calculate tax from line item tax amounts
		for _, taxAmt := range item.TaxAmounts {
			if !taxAmt.Inclusive {
				taxAmount += taxAmt.Amount
			}
		}
	}
	
	// Apply any invoice-level discount
	if i.DiscountAmount > 0 {
		discountAmount = i.DiscountAmount
		subtotal -= discountAmount
	}
	
	i.SubtotalAmount = subtotal
	i.TaxAmount = taxAmount
	i.DiscountAmount = discountAmount
	i.TotalAmount = subtotal + taxAmount
	i.AmountDue = i.TotalAmount - i.AmountPaid
}

// Validate validates the invoice entity
func (i *Invoice) Validate() error {
	if i.ID == uuid.Nil {
		return ErrInvalidInvoiceID
	}
	
	if i.TenantID == uuid.Nil {
		return ErrInvalidTenantID
	}
	
	if i.CustomerID == uuid.Nil {
		return ErrInvalidCustomerID
	}
	
	if i.InvoiceNumber == "" {
		return ErrInvalidInvoiceNumber
	}
	
	if i.TotalAmount < 0 {
		return ErrInvalidInvoiceAmount
	}
	
	if !i.isValidStatus() {
		return ErrInvalidInvoiceStatus
	}
	
	if !i.isValidType() {
		return ErrInvalidInput
	}
	
	if i.Currency == "" {
		return ErrInvalidCurrency
	}
	
	if i.DueDate.Before(i.InvoiceDate) {
		return ErrInvalidDueDate
	}
	
	// Validate payment amounts
	if i.AmountPaid < 0 {
		return ErrInvalidAmount
	}
	
	if i.AmountPaid > i.TotalAmount {
		return ErrInvalidAmount
	}
	
	if i.TaxAmount < 0 {
		return ErrInvalidTaxAmount
	}
	
	// Validate line items
	for _, item := range i.LineItems {
		if item.Amount < 0 {
			return ErrInvalidAmount
		}
		if item.Quantity <= 0 {
			return ErrInvalidInput
		}
	}
	
	return nil
}

// isValidStatus checks if the invoice status is valid
func (i *Invoice) isValidStatus() bool {
	switch i.Status {
	case InvoiceStatusDraft, InvoiceStatusOpen, InvoiceStatusPaid,
		 InvoiceStatusVoid, InvoiceStatusUncollectible, InvoiceStatusPartiallyPaid, InvoiceStatusOverdue:
		return true
	default:
		return false
	}
}

// isValidType checks if the invoice type is valid
func (i *Invoice) isValidType() bool {
	switch i.InvoiceType {
	case InvoiceTypeSubscription, InvoiceTypeOneTime, InvoiceTypeCredit,
		 InvoiceTypeRefund, InvoiceTypeUsage, InvoiceTypeProration:
		return true
	default:
		return false
	}
}

// ToJSON converts the invoice to JSON
func (i *Invoice) ToJSON() ([]byte, error) {
	return json.Marshal(i)
}

// FromJSON creates an invoice from JSON
func (i *Invoice) FromJSON(data []byte) error {
	return json.Unmarshal(data, i)
}

// Clone creates a deep copy of the invoice
func (i *Invoice) Clone() *Invoice {
	clone := *i
	
	// Deep copy pointers
	if i.SubscriptionID != nil {
		sid := *i.SubscriptionID
		clone.SubscriptionID = &sid
	}
	
	if i.PeriodStart != nil {
		ps := *i.PeriodStart
		clone.PeriodStart = &ps
	}
	
	if i.PeriodEnd != nil {
		pe := *i.PeriodEnd
		clone.PeriodEnd = &pe
	}
	
	if i.PaidAt != nil {
		pa := *i.PaidAt
		clone.PaidAt = &pa
	}
	
	if i.VoidedAt != nil {
		va := *i.VoidedAt
		clone.VoidedAt = &va
	}
	
	if i.PaymentMethodID != nil {
		pmid := *i.PaymentMethodID
		clone.PaymentMethodID = &pmid
	}
	
	if i.LastPaymentAttempt != nil {
		lpa := *i.LastPaymentAttempt
		clone.LastPaymentAttempt = &lpa
	}
	
	if i.NextPaymentAttempt != nil {
		npa := *i.NextPaymentAttempt
		clone.NextPaymentAttempt = &npa
	}
	
	if i.TaxExemptReason != nil {
		ter := *i.TaxExemptReason
		clone.TaxExemptReason = &ter
	}
	
	if i.DiscountID != nil {
		did := *i.DiscountID
		clone.DiscountID = &did
	}
	
	if i.CouponCode != nil {
		cc := *i.CouponCode
		clone.CouponCode = &cc
	}
	
	if i.Description != nil {
		desc := *i.Description
		clone.Description = &desc
	}
	
	if i.FooterText != nil {
		ft := *i.FooterText
		clone.FooterText = &ft
	}
	
	if i.StatementDescriptor != nil {
		sd := *i.StatementDescriptor
		clone.StatementDescriptor = &sd
	}
	
	if i.PDFPath != nil {
		pp := *i.PDFPath
		clone.PDFPath = &pp
	}
	
	if i.PDFSize != nil {
		ps := *i.PDFSize
		clone.PDFSize = &ps
	}
	
	if i.EmailSentAt != nil {
		esa := *i.EmailSentAt
		clone.EmailSentAt = &esa
	}
	
	// Deep copy complex structures
	if i.BillingAddress != nil {
		addrClone := *i.BillingAddress
		if i.BillingAddress.Line2 != nil {
			line2 := *i.BillingAddress.Line2
			addrClone.Line2 = &line2
		}
		if i.BillingAddress.State != nil {
			state := *i.BillingAddress.State
			addrClone.State = &state
		}
		clone.BillingAddress = &addrClone
	}
	
	if i.ShippingAddress != nil {
		shipClone := *i.ShippingAddress
		if i.ShippingAddress.Line2 != nil {
			line2 := *i.ShippingAddress.Line2
			shipClone.Line2 = &line2
		}
		if i.ShippingAddress.State != nil {
			state := *i.ShippingAddress.State
			shipClone.State = &state
		}
		clone.ShippingAddress = &shipClone
	}
	
	// Deep copy slices
	if i.LineItems != nil {
		clone.LineItems = make([]InvoiceLineItem, len(i.LineItems))
		copy(clone.LineItems, i.LineItems)
	}
	
	if i.TaxDetails != nil {
		clone.TaxDetails = make([]TaxDetail, len(i.TaxDetails))
		copy(clone.TaxDetails, i.TaxDetails)
	}
	
	if i.ComplianceFrameworks != nil {
		clone.ComplianceFrameworks = make([]string, len(i.ComplianceFrameworks))
		copy(clone.ComplianceFrameworks, i.ComplianceFrameworks)
	}
	
	// Deep copy metadata
	if i.Metadata != nil {
		clone.Metadata = make(map[string]interface{})
		for k, v := range i.Metadata {
			clone.Metadata[k] = v
		}
	}
	
	return &clone
}

// InvoiceFilter represents filter criteria for invoices
type InvoiceFilter struct {
	TenantID              *uuid.UUID        `json:"tenant_id,omitempty"`
	CustomerID            *uuid.UUID        `json:"customer_id,omitempty"`
	SubscriptionID        *uuid.UUID        `json:"subscription_id,omitempty"`
	Status                *InvoiceStatus    `json:"status,omitempty"`
	InvoiceType           *InvoiceType      `json:"invoice_type,omitempty"`
	
	// Date filters
	InvoiceDateFrom       *time.Time        `json:"invoice_date_from,omitempty"`
	InvoiceDateTo         *time.Time        `json:"invoice_date_to,omitempty"`
	DueDateFrom           *time.Time        `json:"due_date_from,omitempty"`
	DueDateTo             *time.Time        `json:"due_date_to,omitempty"`
	PaidDateFrom          *time.Time        `json:"paid_date_from,omitempty"`
	PaidDateTo            *time.Time        `json:"paid_date_to,omitempty"`
	
	// Amount filters
	MinAmount             *int64            `json:"min_amount,omitempty"`
	MaxAmount             *int64            `json:"max_amount,omitempty"`
	Currency              *string           `json:"currency,omitempty"`
	
	// Status filters
	OverdueOnly           bool              `json:"overdue_only"`
	PaidOnly              bool              `json:"paid_only"`
	UnpaidOnly            bool              `json:"unpaid_only"`
	
	// Pagination
	Limit                 int               `json:"limit"`
	Offset                int               `json:"offset"`
	
	// Sorting
	SortBy                string            `json:"sort_by"`
	SortOrder             string            `json:"sort_order"`
}

// NewInvoice creates a new invoice instance
func NewInvoice(
	tenantID, customerID uuid.UUID,
	invoiceNumber string,
	invoiceType InvoiceType,
	currency, securityClearance string,
	createdBy uuid.UUID,
) *Invoice {
	now := time.Now()
	
	return &Invoice{
		ID:                   uuid.New(),
		TenantID:             tenantID,
		CustomerID:           customerID,
		InvoiceNumber:        invoiceNumber,
		InvoiceType:          invoiceType,
		Status:               InvoiceStatusDraft,
		InvoiceDate:          now,
		DueDate:              now.AddDate(0, 0, 30), // Default to 30 days
		Currency:             currency,
		PaymentTerms:         PaymentTermsNet30,
		SecurityClearance:    securityClearance,
		CreatedAt:            now,
		UpdatedAt:            now,
		CreatedBy:            createdBy,
		UpdatedBy:            createdBy,
		LineItems:            make([]InvoiceLineItem, 0),
		TaxDetails:           make([]TaxDetail, 0),
		ComplianceFrameworks: make([]string, 0),
		Metadata:             make(map[string]interface{}),
	}
}