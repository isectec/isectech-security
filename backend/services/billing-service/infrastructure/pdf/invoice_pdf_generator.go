package pdf

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	
	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
	"github.com/isectech/billing-service/infrastructure/invoice"
)

// InvoicePDFGenerator generates PDF invoices using HTML templates
type InvoicePDFGenerator struct {
	logger       *zap.Logger
	config       *config.Config
	templatePath string
	outputPath   string
	auditLogger  *zap.Logger
	
	// PDF generation engine (could be wkhtmltopdf, headless Chrome, etc.)
	pdfEngine    PDFEngine
	
	// Template cache
	templates    map[string]*template.Template
}

// PDFEngine defines the interface for PDF generation engines
type PDFEngine interface {
	GeneratePDF(ctx context.Context, htmlContent string, options *PDFOptions) (*PDFResult, error)
}

// PDFOptions represents PDF generation options
type PDFOptions struct {
	PageSize    string  `json:"page_size"`    // "A4", "Letter", etc.
	Orientation string  `json:"orientation"`  // "portrait", "landscape"
	MarginTop   string  `json:"margin_top"`   // e.g., "1in", "2.54cm"
	MarginRight string  `json:"margin_right"`
	MarginBottom string `json:"margin_bottom"`
	MarginLeft  string  `json:"margin_left"`
	DPI         int     `json:"dpi"`          // Dots per inch
	Quality     string  `json:"quality"`      // "low", "medium", "high"
	
	// Header and footer
	HeaderHTML  string  `json:"header_html,omitempty"`
	FooterHTML  string  `json:"footer_html,omitempty"`
	
	// Security options
	EnableSecurity bool   `json:"enable_security"`
	OwnerPassword  string `json:"owner_password,omitempty"`
	UserPassword   string `json:"user_password,omitempty"`
	Permissions    []string `json:"permissions,omitempty"` // "print", "copy", "modify", etc.
}

// PDFResult represents the result of PDF generation
type PDFResult struct {
	FilePath    string    `json:"file_path"`
	FileSize    int64     `json:"file_size"`
	GeneratedAt time.Time `json:"generated_at"`
	PageCount   int       `json:"page_count"`
	Checksum    string    `json:"checksum,omitempty"`
}

// InvoiceTemplateData represents data passed to invoice templates
type InvoiceTemplateData struct {
	Invoice         *entity.Invoice         `json:"invoice"`
	Company         *CompanyInfo            `json:"company"`
	Customer        *CustomerInfo           `json:"customer"`
	Formatting      *FormattingHelpers      `json:"formatting"`
	Compliance      *ComplianceInfo         `json:"compliance"`
	Branding        *BrandingInfo           `json:"branding"`
	
	// Calculated fields
	TotalPages      int                     `json:"total_pages"`
	CurrentPage     int                     `json:"current_page"`
	GeneratedAt     time.Time               `json:"generated_at"`
	
	// Security and audit
	AuditTrailID    string                  `json:"audit_trail_id"`
	SecurityLevel   string                  `json:"security_level"`
	Watermark       string                  `json:"watermark,omitempty"`
}

// CompanyInfo represents company information for invoices
type CompanyInfo struct {
	Name            string                  `json:"name"`
	LegalName       string                  `json:"legal_name"`
	TaxID           string                  `json:"tax_id"`
	RegistrationNo  string                  `json:"registration_no"`
	
	// Address
	Address         *entity.BillingAddress  `json:"address"`
	
	// Contact information
	Phone           string                  `json:"phone"`
	Email           string                  `json:"email"`
	Website         string                  `json:"website"`
	
	// Banking information
	BankName        string                  `json:"bank_name,omitempty"`
	BankAccount     string                  `json:"bank_account,omitempty"`
	BankRouting     string                  `json:"bank_routing,omitempty"`
	
	// Legal information
	TermsOfService  string                  `json:"terms_of_service,omitempty"`
	PrivacyPolicy   string                  `json:"privacy_policy,omitempty"`
}

// CustomerInfo represents customer information for invoices
type CustomerInfo struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Email           string                  `json:"email"`
	Phone           string                  `json:"phone,omitempty"`
	TaxID           string                  `json:"tax_id,omitempty"`
	
	// Addresses
	BillingAddress  *entity.BillingAddress  `json:"billing_address"`
	ShippingAddress *entity.Address         `json:"shipping_address,omitempty"`
	
	// Account information
	AccountNumber   string                  `json:"account_number,omitempty"`
	PaymentTerms    string                  `json:"payment_terms"`
	
	// Security clearance
	SecurityClearance string                `json:"security_clearance"`
}

// FormattingHelpers provides template formatting functions
type FormattingHelpers struct {
	FormatCurrency  func(int64, string) string
	FormatDate      func(time.Time, string) string
	FormatPercent   func(float64) string
	FormatNumber    func(interface{}) string
	FormatAddress   func(*entity.BillingAddress) string
	TruncateText    func(string, int) string
	ToUpper         func(string) string
	ToLower         func(string) string
	
	// Tax formatting
	FormatTaxRate   func(float64) string
	FormatTaxAmount func(int64, string) string
}

// ComplianceInfo represents compliance-related information
type ComplianceInfo struct {
	Frameworks      []string                `json:"frameworks"`
	Certifications  []string                `json:"certifications"`
	AuditRequired   bool                    `json:"audit_required"`
	RetentionPeriod string                  `json:"retention_period"`
	
	// Tax compliance
	TaxRegistrations []TaxRegistration      `json:"tax_registrations"`
	VATNumber       string                  `json:"vat_number,omitempty"`
	
	// Security compliance
	DataClassification string               `json:"data_classification"`
	EncryptionRequired bool                 `json:"encryption_required"`
}

// TaxRegistration represents tax registration information
type TaxRegistration struct {
	Country         string                  `json:"country"`
	TaxType         string                  `json:"tax_type"`
	RegistrationNo  string                  `json:"registration_no"`
	ValidFrom       time.Time               `json:"valid_from"`
	ValidTo         *time.Time              `json:"valid_to,omitempty"`
}

// BrandingInfo represents branding information
type BrandingInfo struct {
	LogoPath        string                  `json:"logo_path,omitempty"`
	PrimaryColor    string                  `json:"primary_color"`
	SecondaryColor  string                  `json:"secondary_color"`
	AccentColor     string                  `json:"accent_color"`
	FontFamily      string                  `json:"font_family"`
	
	// Layout preferences
	ShowLogo        bool                    `json:"show_logo"`
	ShowWatermark   bool                    `json:"show_watermark"`
	HeaderHeight    string                  `json:"header_height"`
	FooterHeight    string                  `json:"footer_height"`
}

// NewInvoicePDFGenerator creates a new invoice PDF generator
func NewInvoicePDFGenerator(
	logger *zap.Logger,
	config *config.Config,
	pdfEngine PDFEngine,
) *InvoicePDFGenerator {
	
	templatePath := filepath.Join(".", "templates", "pdf")
	outputPath := filepath.Join(".", "storage", "invoices", "pdf")
	
	// Ensure output directory exists
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		logger.Error("Failed to create PDF output directory", zap.Error(err))
	}
	
	auditLogger := logger.Named("pdf_generator_audit").With(
		zap.String("service", "invoice_pdf_generator"),
	)
	
	generator := &InvoicePDFGenerator{
		logger:       logger.Named("invoice_pdf_generator"),
		config:       config,
		templatePath: templatePath,
		outputPath:   outputPath,
		auditLogger:  auditLogger,
		pdfEngine:    pdfEngine,
		templates:    make(map[string]*template.Template),
	}
	
	// Load templates
	if err := generator.loadTemplates(); err != nil {
		logger.Error("Failed to load PDF templates", zap.Error(err))
	}
	
	return generator
}

// GenerateInvoicePDF generates a PDF for an invoice
func (g *InvoicePDFGenerator) GenerateInvoicePDF(
	ctx context.Context,
	invoice *entity.Invoice,
) (*invoice.PDFResult, error) {
	
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	g.auditLogger.Info("Generating invoice PDF",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoice.ID.String()),
		zap.String("invoice_number", invoice.InvoiceNumber),
		zap.String("invoice_type", string(invoice.InvoiceType)),
	)
	
	defer func() {
		g.auditLogger.Info("PDF generation completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("duration", time.Since(start)),
		)
	}()
	
	// Get template for invoice type
	templateName := g.getTemplateNameForInvoiceType(invoice.InvoiceType)
	tmpl, exists := g.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template not found for invoice type: %s", invoice.InvoiceType)
	}
	
	// Prepare template data
	templateData, err := g.prepareTemplateData(ctx, invoice, auditTrailID)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare template data: %w", err)
	}
	
	// Render HTML
	htmlBuffer := &bytes.Buffer{}
	if err := tmpl.Execute(htmlBuffer, templateData); err != nil {
		g.auditLogger.Error("Failed to render HTML template",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to render template: %w", err)
	}
	
	// Generate PDF options
	pdfOptions := &PDFOptions{
		PageSize:       "A4",
		Orientation:    "portrait",
		MarginTop:      "1in",
		MarginRight:    "0.75in",
		MarginBottom:   "1in",
		MarginLeft:     "0.75in",
		DPI:            300,
		Quality:        "high",
		EnableSecurity: g.shouldEnablePDFSecurity(invoice),
	}
	
	// Add security if required
	if pdfOptions.EnableSecurity {
		pdfOptions.OwnerPassword = g.generatePDFPassword(invoice)
		pdfOptions.Permissions = []string{"print"} // Allow printing only
	}
	
	// Add header and footer
	pdfOptions.HeaderHTML = g.generateHeaderHTML(templateData)
	pdfOptions.FooterHTML = g.generateFooterHTML(templateData)
	
	// Generate PDF
	pdfResult, err := g.pdfEngine.GeneratePDF(ctx, htmlBuffer.String(), pdfOptions)
	if err != nil {
		g.auditLogger.Error("Failed to generate PDF",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}
	
	// Generate final filename
	filename := g.generateFilename(invoice)
	finalPath := filepath.Join(g.outputPath, filename)
	
	// Move PDF to final location
	if err := os.Rename(pdfResult.FilePath, finalPath); err != nil {
		g.logger.Error("Failed to move PDF to final location",
			zap.String("temp_path", pdfResult.FilePath),
			zap.String("final_path", finalPath),
			zap.Error(err),
		)
		// Continue with temp path
		finalPath = pdfResult.FilePath
	}
	
	// Get file size
	fileInfo, err := os.Stat(finalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get PDF file info: %w", err)
	}
	
	result := &invoice.PDFResult{
		FilePath:    finalPath,
		FileSize:    fileInfo.Size(),
		GeneratedAt: time.Now(),
	}
	
	g.auditLogger.Info("Invoice PDF generated successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("invoice_id", invoice.ID.String()),
		zap.String("pdf_path", result.FilePath),
		zap.Int64("pdf_size", result.FileSize),
	)
	
	return result, nil
}

// GetPDFTemplate returns the template name for an invoice type
func (g *InvoicePDFGenerator) GetPDFTemplate(invoiceType entity.InvoiceType) (string, error) {
	templateName := g.getTemplateNameForInvoiceType(invoiceType)
	if _, exists := g.templates[templateName]; !exists {
		return "", fmt.Errorf("template not found for invoice type: %s", invoiceType)
	}
	return templateName, nil
}

// loadTemplates loads all PDF templates
func (g *InvoicePDFGenerator) loadTemplates() error {
	templateFiles := map[string]string{
		"subscription": "invoice_subscription.html",
		"one_time":     "invoice_one_time.html",
		"credit":       "invoice_credit.html",
		"refund":       "invoice_refund.html",
		"usage":        "invoice_usage.html",
		"prorations":   "invoice_proration.html",
	}
	
	for templateName, filename := range templateFiles {
		templatePath := filepath.Join(g.templatePath, filename)
		
		// Check if template file exists
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			g.logger.Warn("Template file not found, creating default",
				zap.String("template", templateName),
				zap.String("path", templatePath),
			)
			
			// Create default template
			if err := g.createDefaultTemplate(templatePath, templateName); err != nil {
				g.logger.Error("Failed to create default template",
					zap.String("template", templateName),
					zap.Error(err),
				)
				continue
			}
		}
		
		// Parse template with helper functions
		tmpl, err := template.New(filename).Funcs(g.getTemplateFunctions()).ParseFiles(templatePath)
		if err != nil {
			g.logger.Error("Failed to parse template",
				zap.String("template", templateName),
				zap.String("path", templatePath),
				zap.Error(err),
			)
			continue
		}
		
		g.templates[templateName] = tmpl
		g.logger.Info("Loaded PDF template",
			zap.String("template", templateName),
			zap.String("path", templatePath),
		)
	}
	
	return nil
}

// getTemplateNameForInvoiceType returns the template name for an invoice type
func (g *InvoicePDFGenerator) getTemplateNameForInvoiceType(invoiceType entity.InvoiceType) string {
	switch invoiceType {
	case entity.InvoiceTypeSubscription:
		return "subscription"
	case entity.InvoiceTypeOneTime:
		return "one_time"
	case entity.InvoiceTypeCredit:
		return "credit"
	case entity.InvoiceTypeRefund:
		return "refund"
	case entity.InvoiceTypeUsage:
		return "usage"
	case entity.InvoiceTypeProration:
		return "prorations"
	default:
		return "one_time" // Default template
	}
}

// prepareTemplateData prepares data for template rendering
func (g *InvoicePDFGenerator) prepareTemplateData(
	ctx context.Context,
	invoice *entity.Invoice,
	auditTrailID string,
) (*InvoiceTemplateData, error) {
	
	// Company information (this would typically come from tenant configuration)
	company := &CompanyInfo{
		Name:           "iSECTECH Security Platform",
		LegalName:      "iSECTECH LLC",
		TaxID:          "12-3456789",
		RegistrationNo: "REG123456",
		Address: &entity.BillingAddress{
			Line1:      "123 Security Blvd",
			City:       "San Francisco",
			State:      stringPtr("CA"),
			PostalCode: "94107",
			Country:    "US",
		},
		Phone:   "+1 (555) 123-4567",
		Email:   "billing@isectech.com",
		Website: "https://isectech.com",
	}
	
	// Customer information (would be fetched from customer service)
	customer := &CustomerInfo{
		ID:                invoice.CustomerID.String(),
		Name:              "Customer Name", // Would be fetched
		Email:             "customer@example.com",
		BillingAddress:    invoice.BillingAddress,
		ShippingAddress:   invoice.ShippingAddress,
		PaymentTerms:      string(invoice.PaymentTerms),
		SecurityClearance: invoice.SecurityClearance,
	}
	
	// Formatting helpers
	formatting := &FormattingHelpers{
		FormatCurrency: func(amount int64, currency string) string {
			return formatCurrency(amount, currency)
		},
		FormatDate: func(date time.Time, format string) string {
			return date.Format(format)
		},
		FormatPercent: func(rate float64) string {
			return fmt.Sprintf("%.2f%%", rate)
		},
		FormatNumber: func(num interface{}) string {
			return fmt.Sprintf("%v", num)
		},
		FormatAddress: func(addr *entity.BillingAddress) string {
			return formatAddress(addr)
		},
		TruncateText: func(text string, length int) string {
			if len(text) <= length {
				return text
			}
			return text[:length] + "..."
		},
		ToUpper: strings.ToUpper,
		ToLower: strings.ToLower,
		FormatTaxRate: func(rate float64) string {
			return fmt.Sprintf("%.3f%%", rate)
		},
		FormatTaxAmount: func(amount int64, currency string) string {
			return formatCurrency(amount, currency)
		},
	}
	
	// Compliance information
	compliance := &ComplianceInfo{
		Frameworks:         invoice.ComplianceFrameworks,
		Certifications:     []string{"SOC 2 Type II", "ISO 27001"},
		AuditRequired:      true,
		RetentionPeriod:    "7 years",
		DataClassification: invoice.SecurityClearance,
		EncryptionRequired: invoice.SecurityClearance != "unclassified",
	}
	
	// Branding information
	branding := &BrandingInfo{
		PrimaryColor:   "#1a365d",
		SecondaryColor: "#2d3748",
		AccentColor:    "#3182ce",
		FontFamily:     "Arial, sans-serif",
		ShowLogo:       true,
		ShowWatermark:  invoice.SecurityClearance != "unclassified",
		HeaderHeight:   "80px",
		FooterHeight:   "60px",
	}
	
	templateData := &InvoiceTemplateData{
		Invoice:         invoice,
		Company:         company,
		Customer:        customer,
		Formatting:      formatting,
		Compliance:      compliance,
		Branding:        branding,
		GeneratedAt:     time.Now(),
		AuditTrailID:    auditTrailID,
		SecurityLevel:   invoice.SecurityClearance,
	}
	
	// Add watermark for classified documents
	if invoice.SecurityClearance != "unclassified" {
		templateData.Watermark = strings.ToUpper(invoice.SecurityClearance)
	}
	
	return templateData, nil
}

// getTemplateFunctions returns template helper functions
func (g *InvoicePDFGenerator) getTemplateFunctions() template.FuncMap {
	return template.FuncMap{
		"formatCurrency": formatCurrency,
		"formatDate": func(date time.Time, format string) string {
			return date.Format(format)
		},
		"formatPercent": func(rate float64) string {
			return fmt.Sprintf("%.2f%%", rate)
		},
		"formatAddress": formatAddress,
		"add": func(a, b int) int {
			return a + b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"multiply": func(a, b int64) int64 {
			return a * b
		},
		"divide": func(a, b int64) int64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"truncate": func(text string, length int) string {
			if len(text) <= length {
				return text
			}
			return text[:length] + "..."
		},
	}
}

// shouldEnablePDFSecurity determines if PDF security should be enabled
func (g *InvoicePDFGenerator) shouldEnablePDFSecurity(invoice *entity.Invoice) bool {
	// Enable security for classified documents or high-value invoices
	return invoice.SecurityClearance != "unclassified" || invoice.TotalAmount > 100000 // $1000+
}

// generatePDFPassword generates a password for PDF security
func (g *InvoicePDFGenerator) generatePDFPassword(invoice *entity.Invoice) string {
	// Generate a secure password based on invoice details
	// In production, this should use proper cryptographic methods
	return fmt.Sprintf("isec_%s_%d", invoice.InvoiceNumber, invoice.TotalAmount)
}

// generateHeaderHTML generates header HTML for the PDF
func (g *InvoicePDFGenerator) generateHeaderHTML(data *InvoiceTemplateData) string {
	return fmt.Sprintf(`
		<div style="text-align: center; font-size: 10px; color: #666; padding: 10px;">
			%s - Page <span class="pageNumber"></span> of <span class="totalPages"></span>
		</div>
	`, data.Company.Name)
}

// generateFooterHTML generates footer HTML for the PDF
func (g *InvoicePDFGenerator) generateFooterHTML(data *InvoiceTemplateData) string {
	return fmt.Sprintf(`
		<div style="text-align: center; font-size: 8px; color: #666; padding: 10px;">
			Generated on %s | Audit Trail: %s
			%s
		</div>
	`, data.GeneratedAt.Format("2006-01-02 15:04:05 MST"), 
	   data.AuditTrailID,
	   func() string {
		   if data.Watermark != "" {
			   return fmt.Sprintf(" | Classification: %s", data.Watermark)
		   }
		   return ""
	   }())
}

// generateFilename generates a filename for the PDF
func (g *InvoicePDFGenerator) generateFilename(invoice *entity.Invoice) string {
	// Create a safe filename
	invoiceNumber := strings.ReplaceAll(invoice.InvoiceNumber, "/", "-")
	invoiceNumber = strings.ReplaceAll(invoiceNumber, " ", "_")
	
	timestamp := time.Now().Format("20060102_150405")
	
	return fmt.Sprintf("invoice_%s_%s.pdf", invoiceNumber, timestamp)
}

// createDefaultTemplate creates a default HTML template
func (g *InvoicePDFGenerator) createDefaultTemplate(templatePath, templateName string) error {
	// Ensure directory exists
	dir := filepath.Dir(templatePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	// Create a basic HTML template
	defaultTemplate := g.getDefaultTemplateHTML(templateName)
	
	return os.WriteFile(templatePath, []byte(defaultTemplate), 0644)
}

// getDefaultTemplateHTML returns default HTML template content
func (g *InvoicePDFGenerator) getDefaultTemplateHTML(templateName string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Invoice {{.Invoice.InvoiceNumber}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .company-info { margin-bottom: 20px; }
        .invoice-details { margin-bottom: 30px; }
        .line-items { width: 100%%; border-collapse: collapse; }
        .line-items th, .line-items td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        .line-items th { background-color: #f5f5f5; }
        .totals { margin-top: 20px; text-align: right; }
        .watermark { position: fixed; top: 50%%; left: 50%%; transform: translate(-50%%, -50%%) rotate(-45deg); 
                    font-size: 72px; color: rgba(255,0,0,0.1); z-index: -1; }
    </style>
</head>
<body>
    {{if .Watermark}}
    <div class="watermark">{{.Watermark}}</div>
    {{end}}
    
    <div class="header">
        <h1>{{.Company.Name}}</h1>
        <p>{{formatAddress .Company.Address}}</p>
        <p>Phone: {{.Company.Phone}} | Email: {{.Company.Email}}</p>
    </div>
    
    <div class="invoice-details">
        <h2>Invoice #{{.Invoice.InvoiceNumber}}</h2>
        <p><strong>Invoice Date:</strong> {{formatDate .Invoice.InvoiceDate "January 2, 2006"}}</p>
        <p><strong>Due Date:</strong> {{formatDate .Invoice.DueDate "January 2, 2006"}}</p>
        <p><strong>Customer:</strong> {{.Customer.Name}}</p>
        {{if .Customer.BillingAddress}}
        <p><strong>Billing Address:</strong><br>{{formatAddress .Customer.BillingAddress}}</p>
        {{end}}
    </div>
    
    <table class="line-items">
        <thead>
            <tr>
                <th>Description</th>
                <th>Quantity</th>
                <th>Unit Price</th>
                <th>Amount</th>
            </tr>
        </thead>
        <tbody>
            {{range .Invoice.LineItems}}
            <tr>
                <td>{{.Description}}</td>
                <td>{{.Quantity}}</td>
                <td>{{formatCurrency .UnitAmount .Currency}}</td>
                <td>{{formatCurrency .Amount .Currency}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>
    
    <div class="totals">
        <p><strong>Subtotal:</strong> {{formatCurrency .Invoice.SubtotalAmount .Invoice.Currency}}</p>
        {{if .Invoice.DiscountAmount}}
        <p><strong>Discount:</strong> -{{formatCurrency .Invoice.DiscountAmount .Invoice.Currency}}</p>
        {{end}}
        {{if .Invoice.TaxAmount}}
        <p><strong>Tax:</strong> {{formatCurrency .Invoice.TaxAmount .Invoice.Currency}}</p>
        {{end}}
        <p><strong>Total:</strong> {{formatCurrency .Invoice.TotalAmount .Invoice.Currency}}</p>
        {{if .Invoice.AmountPaid}}
        <p><strong>Amount Paid:</strong> {{formatCurrency .Invoice.AmountPaid .Invoice.Currency}}</p>
        <p><strong>Amount Due:</strong> {{formatCurrency .Invoice.AmountDue .Invoice.Currency}}</p>
        {{end}}
    </div>
    
    <div style="margin-top: 40px; font-size: 10px; color: #666;">
        <p>Security Classification: {{upper .SecurityLevel}}</p>
        <p>Generated: {{formatDate .GeneratedAt "2006-01-02 15:04:05 MST"}}</p>
        <p>Audit Trail: {{.AuditTrailID}}</p>
    </div>
</body>
</html>
	`, templateName)
}

// Helper functions

func formatCurrency(amount int64, currency string) string {
	value := float64(amount) / 100.0
	switch strings.ToLower(currency) {
	case "usd":
		return fmt.Sprintf("$%.2f", value)
	case "eur":
		return fmt.Sprintf("€%.2f", value)
	case "gbp":
		return fmt.Sprintf("£%.2f", value)
	default:
		return fmt.Sprintf("%.2f %s", value, strings.ToUpper(currency))
	}
}

func formatAddress(addr *entity.BillingAddress) string {
	if addr == nil {
		return ""
	}
	
	parts := []string{addr.Line1}
	if addr.Line2 != nil && *addr.Line2 != "" {
		parts = append(parts, *addr.Line2)
	}
	
	cityStateZip := addr.City
	if addr.State != nil && *addr.State != "" {
		cityStateZip += ", " + *addr.State
	}
	cityStateZip += " " + addr.PostalCode
	parts = append(parts, cityStateZip, addr.Country)
	
	return strings.Join(parts, "<br>")
}

func stringPtr(s string) *string {
	return &s
}