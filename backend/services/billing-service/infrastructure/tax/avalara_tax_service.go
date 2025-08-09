package tax

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
	"github.com/isectech/billing-service/infrastructure/invoice"
)

// AvalaraTaxService implements tax calculations using Avalara AvaTax
type AvalaraTaxService struct {
	logger       *zap.Logger
	config       *config.TaxConfig
	httpClient   *http.Client
	baseURL      string
	auditLogger  *zap.Logger
}

// AvalaraTransactionRequest represents an Avalara transaction request
type AvalaraTransactionRequest struct {
	CompanyCode string                    `json:"companyCode"`
	Type        string                    `json:"type"`        // "SalesInvoice", "PurchaseInvoice", etc.
	CustomerCode string                   `json:"customerCode"`
	Date        string                    `json:"date"`
	Lines       []AvalaraLineItem        `json:"lines"`
	Addresses   map[string]AvalaraAddress `json:"addresses"`
	Commit      bool                     `json:"commit"`
	CurrencyCode string                   `json:"currencyCode,omitempty"`
	Description string                   `json:"description,omitempty"`
	Email       string                   `json:"email,omitempty"`
	
	// Exemption information
	ExemptionNo string                   `json:"exemptionNo,omitempty"`
	CustomerUsageType string             `json:"customerUsageType,omitempty"`
	
	// Business information
	BusinessIdentificationNo string      `json:"businessIdentificationNo,omitempty"`
	
	// Compliance
	PurchaseOrderNo string               `json:"purchaseOrderNo,omitempty"`
	ReferenceCode   string               `json:"referenceCode,omitempty"`
}

// AvalaraLineItem represents a line item in Avalara format
type AvalaraLineItem struct {
	Number       string  `json:"number"`
	Quantity     float64 `json:"quantity"`
	Amount       float64 `json:"amount"`
	TaxCode      string  `json:"taxCode,omitempty"`
	ItemCode     string  `json:"itemCode,omitempty"`
	Description  string  `json:"description"`
	Discounted   bool    `json:"discounted"`
	
	// Address references
	Addresses    map[string]AvalaraAddress `json:"addresses,omitempty"`
	
	// Tax information
	TaxIncluded  bool    `json:"taxIncluded"`
	RevenueAccount string `json:"revenueAccount,omitempty"`
	
	// Custom fields
	Ref1         string  `json:"ref1,omitempty"`
	Ref2         string  `json:"ref2,omitempty"`
}

// AvalaraAddress represents an address in Avalara format
type AvalaraAddress struct {
	Line1       string `json:"line1"`
	Line2       string `json:"line2,omitempty"`
	City        string `json:"city"`
	Region      string `json:"region"`       // State/Province
	Country     string `json:"country"`     // ISO 3166-1 alpha-2 code
	PostalCode  string `json:"postalCode"`
}

// AvalaraTransactionResponse represents an Avalara transaction response
type AvalaraTransactionResponse struct {
	ID                int64                    `json:"id"`
	Code              string                   `json:"code"`
	CompanyID         int64                    `json:"companyId"`
	Date              string                   `json:"date"`
	PaymentDate       string                   `json:"paymentDate,omitempty"`
	Status            string                   `json:"status"`
	Type              string                   `json:"type"`
	BatchCode         string                   `json:"batchCode,omitempty"`
	CurrencyCode      string                   `json:"currencyCode"`
	CustomerCode      string                   `json:"customerCode"`
	Description       string                   `json:"description,omitempty"`
	ExemptAmount      float64                  `json:"exemptAmount"`
	Discount          float64                  `json:"discount"`
	Email             string                   `json:"email,omitempty"`
	
	// Tax calculation results
	TotalAmount       float64                  `json:"totalAmount"`
	TotalExempt       float64                  `json:"totalExempt"`
	TotalDiscount     float64                  `json:"totalDiscount"`
	TotalTax          float64                  `json:"totalTax"`
	TotalTaxable      float64                  `json:"totalTaxable"`
	TotalTaxCalculated float64                 `json:"totalTaxCalculated"`
	
	// Line items with tax
	Lines             []AvalaraLineResult      `json:"lines"`
	Addresses         []AvalaraAddressResult   `json:"addresses"`
	LocationTypes     []AvalaraLocationType    `json:"locationTypes"`
	Summary           []AvalaxaTaxSummary      `json:"summary"`
	
	// Tax details
	TaxDetailsByTaxType map[string]float64     `json:"taxDetailsByTaxType,omitempty"`
	
	// Messages and errors
	Messages          []AvalaraMessage         `json:"messages,omitempty"`
}

// AvalaraLineResult represents tax calculation results for a line item
type AvalaraLineResult struct {
	Number            string                   `json:"number"`
	Description       string                   `json:"description"`
	LineAmount        float64                  `json:"lineAmount"`
	Quantity          float64                  `json:"quantity"`
	
	// Tax results
	Tax               float64                  `json:"tax"`
	TaxableAmount     float64                  `json:"taxableAmount"`
	ExemptAmount      float64                  `json:"exemptAmount"`
	Discount          float64                  `json:"discount"`
	TaxCode           string                   `json:"taxCode,omitempty"`
	TaxIncluded       bool                     `json:"taxIncluded"`
	
	// Detailed tax information
	Details           []AvalaraTaxDetail       `json:"details"`
}

// AvalaraTaxDetail represents detailed tax information
type AvalaraTaxDetail struct {
	ID                int64    `json:"id"`
	TransactionLineID int64    `json:"transactionLineId"`
	TransactionID     int64    `json:"transactionId"`
	AddressID         int64    `json:"addressId"`
	Country           string   `json:"country"`
	Region            string   `json:"region"`
	StateFIPS         string   `json:"stateFIPS,omitempty"`
	Exempt            bool     `json:"exempt"`
	JurisCode         string   `json:"jurisCode"`
	JurisName         string   `json:"jurisName"`
	JurisType         string   `json:"jurisType"`
	
	// Tax amounts
	TaxableAmount     float64  `json:"taxableAmount"`
	Rate              float64  `json:"rate"`
	Tax               float64  `json:"tax"`
	TaxCalculated     float64  `json:"taxCalculated"`
	TaxType           string   `json:"taxType"`
	TaxName           string   `json:"taxName"`
	
	// Additional information
	NonTaxableAmount  float64  `json:"nonTaxableAmount"`
	NonTaxableRuleID  int64    `json:"nonTaxableRuleId,omitempty"`
	TaxRuleTypeID     string   `json:"taxRuleTypeId,omitempty"`
	TaxOverrideType   string   `json:"taxOverrideType,omitempty"`
	TaxOverrideAmount float64  `json:"taxOverrideAmount,omitempty"`
	TaxOverrideReason string   `json:"taxOverrideReason,omitempty"`
}

// AvalaraAddressResult represents address resolution results
type AvalaraAddressResult struct {
	ID             int64  `json:"id"`
	TransactionID  int64  `json:"transactionId"`
	BoundaryLevel  string `json:"boundaryLevel"`
	Line1          string `json:"line1"`
	Line2          string `json:"line2,omitempty"`
	City           string `json:"city"`
	Region         string `json:"region"`
	PostalCode     string `json:"postalCode"`
	Country        string `json:"country"`
	TaxRegionID    int64  `json:"taxRegionId"`
	
	// Validation results
	ValidatedDate  string `json:"validatedDate,omitempty"`
	Coordinates    AvalaraCoordinates `json:"coordinates,omitempty"`
}

// AvalaraCoordinates represents GPS coordinates
type AvalaraCoordinates struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// AvalaraLocationType represents location type information
type AvalaraLocationType struct {
	DocumentLocationTypeID int64  `json:"documentLocationTypeId"`
	DocumentID             int64  `json:"documentId"`
	DocumentAddressID      int64  `json:"documentAddressId"`
	LocationTypeCode       string `json:"locationTypeCode"`
}

// AvalaxaTaxSummary represents tax summary by jurisdiction
type AvalaxaTaxSummary struct {
	Country           string   `json:"country"`
	Region            string   `json:"region"`
	JurisType         string   `json:"jurisType"`
	JurisCode         string   `json:"jurisCode"`
	JurisName         string   `json:"jurisName"`
	TaxAuthorityType  int      `json:"taxAuthorityType"`
	StateAssignedNo   string   `json:"stateAssignedNo,omitempty"`
	TaxType           string   `json:"taxType"`
	TaxSubType        string   `json:"taxSubType,omitempty"`
	TaxName           string   `json:"taxName"`
	TaxGroup          string   `json:"taxGroup,omitempty"`
	RateType          string   `json:"rateType"`
	Taxable           float64  `json:"taxable"`
	Rate              float64  `json:"rate"`
	Tax               float64  `json:"tax"`
	TaxCalculated     float64  `json:"taxCalculated"`
	NonTaxable        float64  `json:"nonTaxable"`
	Exemption         float64  `json:"exemption"`
}

// AvalaraMessage represents a message from Avalara
type AvalaraMessage struct {
	Summary     string `json:"summary"`
	Details     string `json:"details"`
	RefersTo    string `json:"refersTo,omitempty"`
	Severity    string `json:"severity"`    // "Success", "Warning", "Error", "Exception"
	Source      string `json:"source"`
	HelpLink    string `json:"helpLink,omitempty"`
}

// AvalaraErrorResponse represents an error response from Avalara
type AvalaraErrorResponse struct {
	Error   AvalaraError `json:"error"`
}

// AvalaraError represents an error from Avalara
type AvalaraError struct {
	Code      string           `json:"code"`
	Message   string           `json:"message"`
	Target    string           `json:"target,omitempty"`
	Details   []AvalaraMessage `json:"details,omitempty"`
}

// NewAvalaraTaxService creates a new Avalara tax service
func NewAvalaraTaxService(
	logger *zap.Logger,
	config *config.TaxConfig,
) *AvalaraTaxService {
	
	baseURL := "https://rest.avatax.com"
	if config.AvalaraEnvironment == "sandbox" {
		baseURL = "https://sandbox-rest.avatax.com"
	}
	
	auditLogger := logger.Named("avalara_tax_audit").With(
		zap.String("service", "avalara_tax"),
		zap.String("environment", config.AvalaraEnvironment),
	)
	
	return &AvalaraTaxService{
		logger:      logger.Named("avalara_tax"),
		config:      config,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		baseURL:     baseURL,
		auditLogger: auditLogger,
	}
}

// CalculateTax calculates tax using Avalara AvaTax
func (s *AvalaraTaxService) CalculateTax(
	ctx context.Context,
	req *invoice.TaxCalculationRequest,
) (*invoice.TaxCalculationResponse, error) {
	
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	s.auditLogger.Info("Calculating tax with Avalara",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("tenant_id", req.TenantID.String()),
		zap.String("customer_id", req.CustomerID.String()),
		zap.String("currency", req.Currency),
	)
	
	defer func() {
		s.auditLogger.Info("Tax calculation completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("duration", time.Since(start)),
		)
	}()
	
	// Build Avalara transaction request
	avalaraReq := &AvalaraTransactionRequest{
		CompanyCode:  s.config.AvalaraCompanyCode,
		Type:         "SalesInvoice",
		CustomerCode: req.CustomerID.String(),
		Date:         req.TaxDate.Format("2006-01-02"),
		Commit:       false, // Don't commit, just calculate
		CurrencyCode: strings.ToUpper(req.Currency),
		Description:  fmt.Sprintf("Tax calculation for tenant %s", req.TenantID.String()),
		Addresses:    make(map[string]AvalaraAddress),
		Lines:        make([]AvalaraLineItem, 0),
	}
	
	// Add ship-from address (business address)
	avalaraReq.Addresses["ShipFrom"] = AvalaraAddress{
		Line1:      "123 Business Street", // This should come from tenant configuration
		City:       "San Francisco",
		Region:     "CA",
		Country:    "US",
		PostalCode: "94107",
	}
	
	// Add ship-to address (customer billing address)
	if req.BillingAddress != nil {
		shipToAddr := AvalaraAddress{
			Line1:      req.BillingAddress.Line1,
			City:       req.BillingAddress.City,
			Country:    req.BillingAddress.Country,
			PostalCode: req.BillingAddress.PostalCode,
		}
		
		if req.BillingAddress.Line2 != nil {
			shipToAddr.Line2 = *req.BillingAddress.Line2
		}
		
		if req.BillingAddress.State != nil {
			shipToAddr.Region = *req.BillingAddress.State
		}
		
		avalaraReq.Addresses["ShipTo"] = shipToAddr
	}
	
	// Add line items
	for i, lineItem := range req.LineItems {
		avalaraLine := AvalaraLineItem{
			Number:      fmt.Sprintf("%d", i+1),
			Quantity:    float64(lineItem.Quantity),
			Amount:      float64(lineItem.Amount) / 100.0, // Convert from cents to dollars
			Description: lineItem.Description,
			Discounted:  lineItem.Discountable,
			TaxIncluded: false,
		}
		
		// Set tax code if provided
		if lineItem.TaxCode != nil {
			avalaraLine.TaxCode = *lineItem.TaxCode
		}
		
		// Add item code from metadata if available
		if itemCode, exists := lineItem.Metadata["item_code"]; exists {
			if str, ok := itemCode.(string); ok {
				avalaraLine.ItemCode = str
			}
		}
		
		// Add custom references from metadata
		if ref1, exists := lineItem.Metadata["ref1"]; exists {
			if str, ok := ref1.(string); ok {
				avalaraLine.Ref1 = str
			}
		}
		
		if ref2, exists := lineItem.Metadata["ref2"]; exists {
			if str, ok := ref2.(string); ok {
				avalaraLine.Ref2 = str
			}
		}
		
		avalaraReq.Lines = append(avalaraReq.Lines, avalaraLine)
	}
	
	// Add exemption information if provided
	if req.ExemptionType != nil {
		avalaraReq.CustomerUsageType = *req.ExemptionType
	}
	
	if req.ExemptionCert != nil {
		avalaraReq.ExemptionNo = *req.ExemptionCert
	}
	
	// Make API request to Avalara
	avalaraResp, err := s.makeAvalaraRequest(ctx, "POST", "/api/v2/transactions/create", avalaraReq)
	if err != nil {
		s.auditLogger.Error("Failed to call Avalara API",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to calculate tax with Avalara: %w", err)
	}
	
	// Parse response
	var transactionResp AvalaraTransactionResponse
	if err := json.Unmarshal(avalaraResp, &transactionResp); err != nil {
		return nil, fmt.Errorf("failed to parse Avalara response: %w", err)
	}
	
	// Check for errors in response
	if len(transactionResp.Messages) > 0 {
		for _, msg := range transactionResp.Messages {
			if msg.Severity == "Error" || msg.Severity == "Exception" {
				s.auditLogger.Error("Avalara returned error",
					zap.String("audit_trail_id", auditTrailID),
					zap.String("error_code", msg.Summary),
					zap.String("error_message", msg.Details),
				)
				return nil, fmt.Errorf("Avalara tax calculation error: %s", msg.Details)
			}
		}
	}
	
	// Convert Avalara response to internal format
	response := &invoice.TaxCalculationResponse{
		TransactionID:    fmt.Sprintf("avalara_%d", transactionResp.ID),
		TotalTax:         int64(transactionResp.TotalTax * 100), // Convert to cents
		ExemptAmount:     int64(transactionResp.TotalExempt * 100),
		TaxableAmount:    int64(transactionResp.TotalTaxable * 100),
		TaxDetails:       make([]entity.TaxDetail, 0),
		LineItemTaxes:    make([]invoice.LineItemTax, 0),
	}
	
	// Process tax summary for overall tax details
	for _, summary := range transactionResp.Summary {
		if summary.Tax > 0 {
			taxDetail := entity.TaxDetail{
				TaxRateID:         fmt.Sprintf("avalara_%s_%s", summary.JurisCode, summary.TaxType),
				TaxRateName:       summary.TaxName,
				TaxRatePercentage: summary.Rate * 100, // Convert to percentage
				TaxableAmount:     int64(summary.Taxable * 100),
				TaxAmount:         int64(summary.Tax * 100),
				Jurisdiction:      summary.JurisName,
				TaxType:           summary.TaxType,
			}
			response.TaxDetails = append(response.TaxDetails, taxDetail)
		}
	}
	
	// Process line item taxes
	for _, line := range transactionResp.Lines {
		lineItemTax := invoice.LineItemTax{
			LineItemID:    line.Number,
			TaxAmount:     int64(line.Tax * 100),
			ExemptAmount:  int64(line.ExemptAmount * 100),
			TaxableAmount: int64(line.TaxableAmount * 100),
			TaxDetails:    make([]entity.TaxDetail, 0),
		}
		
		// Process detailed tax information for this line
		for _, detail := range line.Details {
			if detail.Tax > 0 {
				taxDetail := entity.TaxDetail{
					TaxRateID:         fmt.Sprintf("avalara_%s_%s", detail.JurisCode, detail.TaxType),
					TaxRateName:       detail.TaxName,
					TaxRatePercentage: detail.Rate * 100,
					TaxableAmount:     int64(detail.TaxableAmount * 100),
					TaxAmount:         int64(detail.Tax * 100),
					Jurisdiction:      detail.JurisName,
					TaxType:           detail.TaxType,
				}
				lineItemTax.TaxDetails = append(lineItemTax.TaxDetails, taxDetail)
			}
		}
		
		response.LineItemTaxes = append(response.LineItemTaxes, lineItemTax)
	}
	
	s.auditLogger.Info("Tax calculated successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("transaction_id", response.TransactionID),
		zap.Int64("total_tax", response.TotalTax),
		zap.Int("tax_details_count", len(response.TaxDetails)),
	)
	
	return response, nil
}

// ValidateVATNumber validates a VAT number (not applicable for US-focused Avalara)
func (s *AvalaraTaxService) ValidateVATNumber(
	ctx context.Context,
	vatNumber, country string,
) (*invoice.VATValidationResponse, error) {
	
	// Avalara doesn't provide VAT validation in the same way as EU services
	// This would typically be implemented using a separate VAT validation service
	// For now, return a basic validation
	
	s.logger.Info("VAT validation requested",
		zap.String("vat_number", vatNumber),
		zap.String("country", country),
	)
	
	return &invoice.VATValidationResponse{
		Valid:          false, // Not implemented
		Country:        country,
		ValidationDate: time.Now(),
		Errors:         []string{"VAT validation not implemented for Avalara"},
	}, nil
}

// GetTaxRatesForLocation gets tax rates for a specific location
func (s *AvalaraTaxService) GetTaxRatesForLocation(
	ctx context.Context,
	address *entity.BillingAddress,
) ([]*invoice.TaxRate, error) {
	
	auditTrailID := uuid.New().String()
	
	s.auditLogger.Info("Getting tax rates for location",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("country", address.Country),
		zap.String("postal_code", address.PostalCode),
	)
	
	// This would typically make a request to Avalara's tax rate API
	// For now, return a placeholder implementation
	
	return []*invoice.TaxRate{
		{
			ID:           "avalara_default",
			Name:         "Sales Tax",
			Rate:         8.5, // Example rate
			Type:         "sales_tax",
			Jurisdiction: "Default",
			Country:      address.Country,
			Active:       true,
		},
	}, nil
}

// makeAvalaraRequest makes an authenticated request to Avalara API
func (s *AvalaraTaxService) makeAvalaraRequest(
	ctx context.Context,
	method, endpoint string,
	body interface{},
) ([]byte, error) {
	
	var requestBody []byte
	var err error
	
	if body != nil {
		requestBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}
	
	url := s.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	
	// Set authentication (Basic Auth with account ID and license key)
	req.SetBasicAuth(s.config.AvalaraAccountID, s.config.AvalaraLicenseKey)
	
	// Make request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response
	responseBody := &bytes.Buffer{}
	if _, err := responseBody.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		var errorResp AvalaraErrorResponse
		if err := json.Unmarshal(responseBody.Bytes(), &errorResp); err == nil {
			return nil, fmt.Errorf("Avalara API error (%d): %s - %s", 
				resp.StatusCode, errorResp.Error.Code, errorResp.Error.Message)
		}
		
		return nil, fmt.Errorf("Avalara API error (%d): %s", resp.StatusCode, responseBody.String())
	}
	
	return responseBody.Bytes(), nil
}