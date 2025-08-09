package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v74"
	"github.com/stripe/stripe-go/v74/webhook"
	"go.uber.org/zap"

	"github.com/isectech/billing-service/domain/entity"
	"github.com/isectech/billing-service/infrastructure/config"
)

// StripeWebhookHandler handles Stripe webhook events with security and compliance
type StripeWebhookHandler struct {
	logger              *zap.Logger
	config              *config.WebhookConfig
	eventProcessor      WebhookEventProcessor
	auditLogger         *zap.Logger
	securityValidator   SecurityValidator
	
	// Event handlers
	paymentHandlers     map[string]PaymentEventHandler
	subscriptionHandlers map[string]SubscriptionEventHandler
	invoiceHandlers     map[string]InvoiceEventHandler
	
	// Security and rate limiting
	signatureValidator  SignatureValidator
	rateLimiter        RateLimiter
	ipWhitelist        []string
	
	// Metrics and monitoring
	metricsCollector   MetricsCollector
}

// WebhookEventProcessor defines the interface for processing webhook events
type WebhookEventProcessor interface {
	ProcessEvent(ctx context.Context, event *StripeWebhookEvent) error
	GetSupportedEvents() []string
	IsEventSupported(eventType string) bool
}

// SecurityValidator validates webhook security requirements
type SecurityValidator interface {
	ValidateIP(ip string) bool
	ValidateSignature(body []byte, signature string, secret string) bool
	ValidateTimestamp(timestamp int64, tolerance time.Duration) bool
	CheckRateLimit(ip string) bool
}

// SignatureValidator validates webhook signatures
type SignatureValidator interface {
	ValidateSignature(payload []byte, signature string, secret string) error
}

// RateLimiter implements rate limiting for webhooks
type RateLimiter interface {
	Allow(key string) bool
	Reset(key string)
	GetLimit(key string) int
	GetRemaining(key string) int
}

// MetricsCollector collects webhook metrics
type MetricsCollector interface {
	IncrementWebhookReceived(eventType string)
	IncrementWebhookProcessed(eventType string, success bool)
	RecordProcessingTime(eventType string, duration time.Duration)
	IncrementSecurityViolation(violationType string)
}

// StripeWebhookEvent represents a processed Stripe webhook event
type StripeWebhookEvent struct {
	ID                string                 `json:"id"`
	Type              string                 `json:"type"`
	Data              map[string]interface{} `json:"data"`
	Created           time.Time              `json:"created"`
	LiveMode          bool                   `json:"livemode"`
	PendingWebhooks   int                    `json:"pending_webhooks"`
	Request           *WebhookRequest        `json:"request,omitempty"`
	
	// Security and audit
	Signature         string    `json:"signature"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	ProcessedAt       time.Time `json:"processed_at"`
	AuditTrailID      string    `json:"audit_trail_id"`
	SecurityClearance string    `json:"security_clearance"`
	
	// Validation results
	SignatureValid    bool      `json:"signature_valid"`
	TimestampValid    bool      `json:"timestamp_valid"`
	IPWhitelisted     bool      `json:"ip_whitelisted"`
}

// WebhookRequest contains request metadata
type WebhookRequest struct {
	ID             string `json:"id,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// WebhookResponse represents the response to a webhook
type WebhookResponse struct {
	Success         bool      `json:"success"`
	Message         string    `json:"message,omitempty"`
	ProcessedAt     time.Time `json:"processed_at"`
	AuditTrailID    string    `json:"audit_trail_id"`
	EventID         string    `json:"event_id"`
	ProcessingTime  string    `json:"processing_time"`
	Error           *WebhookError `json:"error,omitempty"`
}

// WebhookError represents a webhook processing error
type WebhookError struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Type        string `json:"type"`
	Recoverable bool   `json:"recoverable"`
}

// PaymentEventHandler handles payment-related webhook events
type PaymentEventHandler interface {
	HandlePaymentIntentSucceeded(ctx context.Context, event *StripeWebhookEvent) error
	HandlePaymentIntentPaymentFailed(ctx context.Context, event *StripeWebhookEvent) error
	HandlePaymentIntentRequiresAction(ctx context.Context, event *StripeWebhookEvent) error
	HandlePaymentMethodAttached(ctx context.Context, event *StripeWebhookEvent) error
	HandlePaymentMethodDetached(ctx context.Context, event *StripeWebhookEvent) error
}

// SubscriptionEventHandler handles subscription-related webhook events
type SubscriptionEventHandler interface {
	HandleSubscriptionCreated(ctx context.Context, event *StripeWebhookEvent) error
	HandleSubscriptionUpdated(ctx context.Context, event *StripeWebhookEvent) error
	HandleSubscriptionDeleted(ctx context.Context, event *StripeWebhookEvent) error
	HandleSubscriptionTrialWillEnd(ctx context.Context, event *StripeWebhookEvent) error
}

// InvoiceEventHandler handles invoice-related webhook events
type InvoiceEventHandler interface {
	HandleInvoiceCreated(ctx context.Context, event *StripeWebhookEvent) error
	HandleInvoicePaymentSucceeded(ctx context.Context, event *StripeWebhookEvent) error
	HandleInvoicePaymentFailed(ctx context.Context, event *StripeWebhookEvent) error
	HandleInvoiceFinalized(ctx context.Context, event *StripeWebhookEvent) error
}

// NewStripeWebhookHandler creates a new Stripe webhook handler
func NewStripeWebhookHandler(
	logger *zap.Logger,
	config *config.WebhookConfig,
	eventProcessor WebhookEventProcessor,
	securityValidator SecurityValidator,
	signatureValidator SignatureValidator,
	rateLimiter RateLimiter,
	metricsCollector MetricsCollector,
) *StripeWebhookHandler {
	
	auditLogger := logger.Named("webhook_audit").With(
		zap.String("service", "stripe_webhook"),
		zap.String("environment", config.Environment),
		zap.Bool("security_enabled", config.SecurityEnabled),
	)
	
	return &StripeWebhookHandler{
		logger:              logger.Named("stripe_webhook"),
		config:              config,
		eventProcessor:      eventProcessor,
		auditLogger:         auditLogger,
		securityValidator:   securityValidator,
		signatureValidator:  signatureValidator,
		rateLimiter:        rateLimiter,
		metricsCollector:   metricsCollector,
		paymentHandlers:    make(map[string]PaymentEventHandler),
		subscriptionHandlers: make(map[string]SubscriptionEventHandler),
		invoiceHandlers:    make(map[string]InvoiceEventHandler),
		ipWhitelist:        config.IPWhitelist,
	}
}

// HandleWebhook processes incoming Stripe webhook requests
func (h *StripeWebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	auditTrailID := uuid.New().String()
	start := time.Now()
	
	h.auditLogger.Info("Webhook request received",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("method", r.Method),
		zap.String("user_agent", r.UserAgent()),
		zap.String("remote_addr", r.RemoteAddr),
	)
	
	defer func() {
		h.auditLogger.Info("Webhook request completed",
			zap.String("audit_trail_id", auditTrailID),
			zap.Duration("processing_time", time.Since(start)),
		)
	}()
	
	// Validate HTTP method
	if r.Method != http.MethodPost {
		h.respondWithError(w, http.StatusMethodNotAllowed, "method_not_allowed", 
			"Only POST method is allowed", auditTrailID)
		return
	}
	
	// Get client IP
	clientIP := h.getClientIP(r)
	
	// Validate IP whitelist if enabled
	if h.config.EnableIPWhitelist && !h.securityValidator.ValidateIP(clientIP) {
		h.auditLogger.Warn("Webhook request from non-whitelisted IP",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("ip", clientIP),
		)
		h.metricsCollector.IncrementSecurityViolation("ip_not_whitelisted")
		h.respondWithError(w, http.StatusForbidden, "ip_not_allowed", 
			"IP not whitelisted", auditTrailID)
		return
	}
	
	// Check rate limits
	if !h.rateLimiter.Allow(clientIP) {
		h.auditLogger.Warn("Rate limit exceeded for webhook",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("ip", clientIP),
		)
		h.metricsCollector.IncrementSecurityViolation("rate_limit_exceeded")
		h.respondWithError(w, http.StatusTooManyRequests, "rate_limit_exceeded", 
			"Rate limit exceeded", auditTrailID)
		return
	}
	
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid_request_body", 
			"Failed to read request body", auditTrailID)
		return
	}
	
	// Get Stripe signature
	signature := r.Header.Get("Stripe-Signature")
	if signature == "" {
		h.auditLogger.Warn("Missing Stripe signature",
			zap.String("audit_trail_id", auditTrailID),
		)
		h.metricsCollector.IncrementSecurityViolation("missing_signature")
		h.respondWithError(w, http.StatusBadRequest, "missing_signature", 
			"Missing Stripe signature", auditTrailID)
		return
	}
	
	// Validate signature
	if err := h.signatureValidator.ValidateSignature(body, signature, h.config.WebhookSecret); err != nil {
		h.auditLogger.Error("Invalid webhook signature",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		h.metricsCollector.IncrementSecurityViolation("invalid_signature")
		h.respondWithError(w, http.StatusBadRequest, "invalid_signature", 
			"Invalid signature", auditTrailID)
		return
	}
	
	// Parse Stripe event
	event, err := webhook.ConstructEvent(body, signature, h.config.WebhookSecret)
	if err != nil {
		h.auditLogger.Error("Failed to construct webhook event",
			zap.String("audit_trail_id", auditTrailID),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, "invalid_event", 
			"Failed to parse webhook event", auditTrailID)
		return
	}
	
	// Validate timestamp to prevent replay attacks
	timestamp := h.extractTimestampFromSignature(signature)
	if !h.securityValidator.ValidateTimestamp(timestamp, h.config.TimestampTolerance) {
		h.auditLogger.Warn("Webhook timestamp outside tolerance",
			zap.String("audit_trail_id", auditTrailID),
			zap.Int64("timestamp", timestamp),
		)
		h.metricsCollector.IncrementSecurityViolation("timestamp_invalid")
		h.respondWithError(w, http.StatusBadRequest, "timestamp_invalid", 
			"Request timestamp is outside acceptable range", auditTrailID)
		return
	}
	
	// Create internal webhook event
	webhookEvent := &StripeWebhookEvent{
		ID:                event.ID,
		Type:              event.Type,
		Data:             event.Data,
		Created:           time.Unix(event.Created, 0),
		LiveMode:          event.Livemode,
		PendingWebhooks:   int(event.PendingWebhooks),
		Signature:         signature,
		IPAddress:         clientIP,
		UserAgent:         r.UserAgent(),
		ProcessedAt:       time.Now(),
		AuditTrailID:      auditTrailID,
		SecurityClearance: "unclassified", // Default clearance for webhooks
		SignatureValid:    true,
		TimestampValid:    true,
		IPWhitelisted:     true,
	}
	
	if event.Request != nil {
		webhookEvent.Request = &WebhookRequest{
			ID:             event.Request.ID,
			IdempotencyKey: event.Request.IdempotencyKey,
		}
	}
	
	// Log event details
	h.auditLogger.Info("Processing Stripe webhook event",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("event_id", event.ID),
		zap.String("event_type", event.Type),
		zap.Bool("livemode", event.Livemode),
		zap.Int64("pending_webhooks", event.PendingWebhooks),
	)
	
	// Increment metrics
	h.metricsCollector.IncrementWebhookReceived(event.Type)
	
	// Process the event
	ctx := context.WithValue(r.Context(), "audit_trail_id", auditTrailID)
	err = h.processWebhookEvent(ctx, webhookEvent)
	
	// Prepare response
	response := &WebhookResponse{
		Success:         err == nil,
		ProcessedAt:     time.Now(),
		AuditTrailID:    auditTrailID,
		EventID:         event.ID,
		ProcessingTime:  time.Since(start).String(),
	}
	
	if err != nil {
		h.auditLogger.Error("Failed to process webhook event",
			zap.String("audit_trail_id", auditTrailID),
			zap.String("event_id", event.ID),
			zap.String("event_type", event.Type),
			zap.Error(err),
		)
		
		h.metricsCollector.IncrementWebhookProcessed(event.Type, false)
		
		response.Error = &WebhookError{
			Code:        "processing_failed",
			Message:     err.Error(),
			Type:        "webhook_processing_error",
			Recoverable: h.isRecoverableError(err),
		}
		
		h.respondWithJSON(w, http.StatusInternalServerError, response)
		return
	}
	
	// Success
	h.auditLogger.Info("Webhook event processed successfully",
		zap.String("audit_trail_id", auditTrailID),
		zap.String("event_id", event.ID),
		zap.String("event_type", event.Type),
	)
	
	h.metricsCollector.IncrementWebhookProcessed(event.Type, true)
	h.metricsCollector.RecordProcessingTime(event.Type, time.Since(start))
	
	response.Message = "Event processed successfully"
	h.respondWithJSON(w, http.StatusOK, response)
}

// processWebhookEvent processes the webhook event based on its type
func (h *StripeWebhookHandler) processWebhookEvent(ctx context.Context, event *StripeWebhookEvent) error {
	// Check if event processor supports this event type
	if !h.eventProcessor.IsEventSupported(event.Type) {
		h.logger.Info("Unsupported event type, skipping",
			zap.String("event_type", event.Type),
			zap.String("event_id", event.ID),
		)
		return nil
	}
	
	// Process the event
	return h.eventProcessor.ProcessEvent(ctx, event)
}

// getClientIP extracts the real client IP from the request
func (h *StripeWebhookHandler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		ips := strings.Split(xForwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}
	
	// Check X-Forwarded header
	xForwarded := r.Header.Get("X-Forwarded")
	if xForwarded != "" {
		return xForwarded
	}
	
	// Use RemoteAddr as fallback
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}
	
	return ip
}

// extractTimestampFromSignature extracts timestamp from Stripe signature
func (h *StripeWebhookHandler) extractTimestampFromSignature(signature string) int64 {
	pairs := strings.Split(signature, ",")
	for _, pair := range pairs {
		if strings.HasPrefix(pair, "t=") {
			timestampStr := strings.TrimPrefix(pair, "t=")
			if timestamp, err := strconv.ParseInt(timestampStr, 10, 64); err == nil {
				return timestamp
			}
		}
	}
	return 0
}

// isRecoverableError determines if an error is recoverable
func (h *StripeWebhookHandler) isRecoverableError(err error) bool {
	// Check for specific error types that might be recoverable
	switch err {
	case entity.ErrDatabaseConnection:
		return true
	case entity.ErrStripeServiceUnavailable:
		return true
	default:
		return false
	}
}

// respondWithError sends an error response
func (h *StripeWebhookHandler) respondWithError(w http.ResponseWriter, statusCode int, code, message, auditTrailID string) {
	response := &WebhookResponse{
		Success:      false,
		ProcessedAt:  time.Now(),
		AuditTrailID: auditTrailID,
		Error: &WebhookError{
			Code:        code,
			Message:     message,
			Type:        "webhook_error",
			Recoverable: false,
		},
	}
	
	h.respondWithJSON(w, statusCode, response)
}

// respondWithJSON sends a JSON response
func (h *StripeWebhookHandler) respondWithJSON(w http.ResponseWriter, statusCode int, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// DefaultSignatureValidator provides default signature validation
type DefaultSignatureValidator struct {
	logger *zap.Logger
}

// NewDefaultSignatureValidator creates a default signature validator
func NewDefaultSignatureValidator(logger *zap.Logger) *DefaultSignatureValidator {
	return &DefaultSignatureValidator{
		logger: logger.Named("signature_validator"),
	}
}

// ValidateSignature validates the webhook signature
func (v *DefaultSignatureValidator) ValidateSignature(payload []byte, signature string, secret string) error {
	return v.validateSignatureV1(payload, signature, secret)
}

// validateSignatureV1 validates signature using HMAC SHA256
func (v *DefaultSignatureValidator) validateSignatureV1(payload []byte, signature string, secret string) error {
	// Parse signature header
	pairs := strings.Split(signature, ",")
	var timestamp int64
	var signatures []string
	
	for _, pair := range pairs {
		if strings.HasPrefix(pair, "t=") {
			timestampStr := strings.TrimPrefix(pair, "t=")
			var err error
			timestamp, err = strconv.ParseInt(timestampStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid timestamp in signature: %w", err)
			}
		} else if strings.HasPrefix(pair, "v1=") {
			sig := strings.TrimPrefix(pair, "v1=")
			signatures = append(signatures, sig)
		}
	}
	
	if timestamp == 0 {
		return fmt.Errorf("missing timestamp in signature")
	}
	
	if len(signatures) == 0 {
		return fmt.Errorf("missing signature in header")
	}
	
	// Create expected signature
	signedPayload := fmt.Sprintf("%d.%s", timestamp, string(payload))
	expectedSignature := v.computeSignature(signedPayload, secret)
	
	// Compare signatures
	for _, sig := range signatures {
		if hmac.Equal([]byte(expectedSignature), []byte(sig)) {
			return nil
		}
	}
	
	return fmt.Errorf("signature verification failed")
}

// computeSignature computes HMAC SHA256 signature
func (v *DefaultSignatureValidator) computeSignature(payload string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}