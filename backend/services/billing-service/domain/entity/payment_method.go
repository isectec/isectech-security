package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PaymentMethodType represents the type of payment method
type PaymentMethodType string

const (
	PaymentMethodTypeCard       PaymentMethodType = "card"
	PaymentMethodTypeACH        PaymentMethodType = "ach"
	PaymentMethodTypeWire       PaymentMethodType = "wire"
	PaymentMethodTypeCrypto     PaymentMethodType = "crypto"
)

// PaymentMethodStatus represents the status of a payment method
type PaymentMethodStatus string

const (
	PaymentMethodStatusActive    PaymentMethodStatus = "active"
	PaymentMethodStatusInactive  PaymentMethodStatus = "inactive"
	PaymentMethodStatusExpired   PaymentMethodStatus = "expired"
	PaymentMethodStatusFailed    PaymentMethodStatus = "failed"
)

// CardBrand represents different card brands
type CardBrand string

const (
	CardBrandVisa       CardBrand = "visa"
	CardBrandMastercard CardBrand = "mastercard"
	CardBrandAmex       CardBrand = "amex"
	CardBrandDiscover   CardBrand = "discover"
	CardBrandJCB        CardBrand = "jcb"
	CardBrandDinersClub CardBrand = "diners_club"
	CardBrandUnionPay   CardBrand = "unionpay"
	CardBrandUnknown    CardBrand = "unknown"
)

// PaymentMethod represents a customer's payment method
type PaymentMethod struct {
	ID                    uuid.UUID           `json:"id" db:"id"`
	TenantID              uuid.UUID           `json:"tenant_id" db:"tenant_id"`
	CustomerID            uuid.UUID           `json:"customer_id" db:"customer_id"`
	StripePaymentMethodID string              `json:"stripe_payment_method_id" db:"stripe_payment_method_id"`
	Type                  PaymentMethodType   `json:"type" db:"type"`
	Status                PaymentMethodStatus `json:"status" db:"status"`
	IsDefault             bool                `json:"is_default" db:"is_default"`
	
	// Card-specific fields
	CardBrand       *CardBrand `json:"card_brand,omitempty" db:"card_brand"`
	CardLast4       *string    `json:"card_last4,omitempty" db:"card_last4"`
	CardExpMonth    *int       `json:"card_exp_month,omitempty" db:"card_exp_month"`
	CardExpYear     *int       `json:"card_exp_year,omitempty" db:"card_exp_year"`
	CardFingerprint *string    `json:"card_fingerprint,omitempty" db:"card_fingerprint"`
	CardCountry     *string    `json:"card_country,omitempty" db:"card_country"`
	CardFunding     *string    `json:"card_funding,omitempty" db:"card_funding"`
	
	// Security and compliance
	PCI3DSRequired    bool   `json:"pci_3ds_required" db:"pci_3ds_required"`
	SecurityClearance string `json:"security_clearance" db:"security_clearance"`
	
	// Billing address
	BillingAddress *BillingAddress `json:"billing_address,omitempty" db:"billing_address"`
	
	// Audit fields
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy   uuid.UUID  `json:"created_by" db:"created_by"`
	UpdatedBy   uuid.UUID  `json:"updated_by" db:"updated_by"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty" db:"deactivated_at"`
	
	// Metadata for flexible storage
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// BillingAddress represents a billing address
type BillingAddress struct {
	Line1      string  `json:"line1"`
	Line2      *string `json:"line2,omitempty"`
	City       string  `json:"city"`
	State      *string `json:"state,omitempty"`
	PostalCode string  `json:"postal_code"`
	Country    string  `json:"country"`
}

// IsExpired checks if the card is expired
func (pm *PaymentMethod) IsExpired() bool {
	if pm.Type != PaymentMethodTypeCard || pm.CardExpMonth == nil || pm.CardExpYear == nil {
		return false
	}
	
	now := time.Now()
	expDate := time.Date(*pm.CardExpYear, time.Month(*pm.CardExpMonth+1), 0, 0, 0, 0, 0, time.UTC)
	return now.After(expDate)
}

// IsActive checks if the payment method is active and usable
func (pm *PaymentMethod) IsActive() bool {
	return pm.Status == PaymentMethodStatusActive && !pm.IsExpired()
}

// GetDisplayName returns a human-readable display name for the payment method
func (pm *PaymentMethod) GetDisplayName() string {
	switch pm.Type {
	case PaymentMethodTypeCard:
		if pm.CardBrand != nil && pm.CardLast4 != nil {
			return string(*pm.CardBrand) + " ending in " + *pm.CardLast4
		}
		return "Credit Card"
	case PaymentMethodTypeACH:
		return "Bank Account"
	case PaymentMethodTypeWire:
		return "Wire Transfer"
	case PaymentMethodTypeCrypto:
		return "Cryptocurrency"
	default:
		return "Payment Method"
	}
}

// Validate validates the payment method entity
func (pm *PaymentMethod) Validate() error {
	if pm.ID == uuid.Nil {
		return ErrInvalidPaymentMethodID
	}
	
	if pm.TenantID == uuid.Nil {
		return ErrInvalidTenantID
	}
	
	if pm.CustomerID == uuid.Nil {
		return ErrInvalidCustomerID
	}
	
	if pm.StripePaymentMethodID == "" {
		return ErrInvalidStripePaymentMethodID
	}
	
	if !pm.isValidType() {
		return ErrInvalidPaymentMethodType
	}
	
	if !pm.isValidStatus() {
		return ErrInvalidPaymentMethodStatus
	}
	
	// Validate card-specific fields
	if pm.Type == PaymentMethodTypeCard {
		if pm.CardLast4 == nil || len(*pm.CardLast4) != 4 {
			return ErrInvalidCardLast4
		}
		
		if pm.CardExpMonth == nil || *pm.CardExpMonth < 1 || *pm.CardExpMonth > 12 {
			return ErrInvalidCardExpMonth
		}
		
		if pm.CardExpYear == nil || *pm.CardExpYear < time.Now().Year() {
			return ErrInvalidCardExpYear
		}
	}
	
	return nil
}

// isValidType checks if the payment method type is valid
func (pm *PaymentMethod) isValidType() bool {
	switch pm.Type {
	case PaymentMethodTypeCard, PaymentMethodTypeACH, PaymentMethodTypeWire, PaymentMethodTypeCrypto:
		return true
	default:
		return false
	}
}

// isValidStatus checks if the payment method status is valid
func (pm *PaymentMethod) isValidStatus() bool {
	switch pm.Status {
	case PaymentMethodStatusActive, PaymentMethodStatusInactive, PaymentMethodStatusExpired, PaymentMethodStatusFailed:
		return true
	default:
		return false
	}
}

// ToJSON converts the payment method to JSON
func (pm *PaymentMethod) ToJSON() ([]byte, error) {
	return json.Marshal(pm)
}

// FromJSON creates a payment method from JSON
func (pm *PaymentMethod) FromJSON(data []byte) error {
	return json.Unmarshal(data, pm)
}

// Clone creates a deep copy of the payment method
func (pm *PaymentMethod) Clone() *PaymentMethod {
	clone := *pm
	
	// Deep copy pointers
	if pm.CardBrand != nil {
		brand := *pm.CardBrand
		clone.CardBrand = &brand
	}
	
	if pm.CardLast4 != nil {
		last4 := *pm.CardLast4
		clone.CardLast4 = &last4
	}
	
	if pm.CardExpMonth != nil {
		month := *pm.CardExpMonth
		clone.CardExpMonth = &month
	}
	
	if pm.CardExpYear != nil {
		year := *pm.CardExpYear
		clone.CardExpYear = &year
	}
	
	if pm.CardFingerprint != nil {
		fingerprint := *pm.CardFingerprint
		clone.CardFingerprint = &fingerprint
	}
	
	if pm.CardCountry != nil {
		country := *pm.CardCountry
		clone.CardCountry = &country
	}
	
	if pm.CardFunding != nil {
		funding := *pm.CardFunding
		clone.CardFunding = &funding
	}
	
	if pm.BillingAddress != nil {
		addrClone := *pm.BillingAddress
		if pm.BillingAddress.Line2 != nil {
			line2 := *pm.BillingAddress.Line2
			addrClone.Line2 = &line2
		}
		if pm.BillingAddress.State != nil {
			state := *pm.BillingAddress.State
			addrClone.State = &state
		}
		clone.BillingAddress = &addrClone
	}
	
	if pm.DeactivatedAt != nil {
		deactivatedAt := *pm.DeactivatedAt
		clone.DeactivatedAt = &deactivatedAt
	}
	
	// Deep copy metadata
	if pm.Metadata != nil {
		clone.Metadata = make(map[string]interface{})
		for k, v := range pm.Metadata {
			clone.Metadata[k] = v
		}
	}
	
	return &clone
}

// PaymentMethodFilter represents filter criteria for payment methods
type PaymentMethodFilter struct {
	TenantID     *uuid.UUID           `json:"tenant_id,omitempty"`
	CustomerID   *uuid.UUID           `json:"customer_id,omitempty"`
	Type         *PaymentMethodType   `json:"type,omitempty"`
	Status       *PaymentMethodStatus `json:"status,omitempty"`
	IsDefault    *bool                `json:"is_default,omitempty"`
	CardBrand    *CardBrand           `json:"card_brand,omitempty"`
	ActiveOnly   bool                 `json:"active_only"`
	
	// Pagination
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	
	// Sorting
	SortBy    string `json:"sort_by"`
	SortOrder string `json:"sort_order"`
}

// NewPaymentMethod creates a new payment method instance
func NewPaymentMethod(
	tenantID, customerID uuid.UUID,
	stripePaymentMethodID string,
	paymentType PaymentMethodType,
	createdBy uuid.UUID,
) *PaymentMethod {
	now := time.Now()
	
	return &PaymentMethod{
		ID:                    uuid.New(),
		TenantID:              tenantID,
		CustomerID:            customerID,
		StripePaymentMethodID: stripePaymentMethodID,
		Type:                  paymentType,
		Status:                PaymentMethodStatusActive,
		IsDefault:             false,
		PCI3DSRequired:        true, // Default to requiring 3DS for security
		SecurityClearance:     "unclassified",
		CreatedAt:             now,
		UpdatedAt:             now,
		CreatedBy:             createdBy,
		UpdatedBy:             createdBy,
		Metadata:              make(map[string]interface{}),
	}
}