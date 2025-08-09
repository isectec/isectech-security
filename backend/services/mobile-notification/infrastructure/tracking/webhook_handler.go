package tracking

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mobile-notification/domain/entity"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// WebhookHandler handles incoming webhooks for delivery receipts and read confirmations
type WebhookHandler struct {
	trackingService *DeliveryTrackingService
	logger          *logrus.Logger
	config          WebhookConfig
}

// WebhookConfig represents webhook configuration
type WebhookConfig struct {
	EnableWebhooks    bool     `yaml:"enable_webhooks"`
	SecretKey         string   `yaml:"secret_key"`         // For webhook signature validation
	AllowedIPs        []string `yaml:"allowed_ips"`        // IP whitelist
	TimeoutSeconds    int      `yaml:"timeout_seconds"`    // Request timeout
	MaxPayloadSize    int64    `yaml:"max_payload_size"`   // Maximum payload size in bytes
	EnableIPFiltering bool     `yaml:"enable_ip_filtering"`
}

// WebhookPayload represents the structure of incoming webhook payloads
type WebhookPayload struct {
	EventType     string                 `json:"event_type"`     // "delivery", "read", "bounce", etc.
	Timestamp     time.Time              `json:"timestamp"`
	MessageID     string                 `json:"message_id"`
	Platform      string                 `json:"platform"`       // "fcm", "apns", "web"
	DeviceToken   string                 `json:"device_token"`
	Status        string                 `json:"status"`         // "delivered", "failed", "read", etc.
	ErrorCode     string                 `json:"error_code,omitempty"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// FCMWebhookPayload represents FCM-specific webhook payload
type FCMWebhookPayload struct {
	Message struct {
		MessageID    string `json:"messageId"`
		From         string `json:"from"`
		Category     string `json:"category"`
		CollapseKey  string `json:"collapseKey"`
		Data         map[string]string `json:"data"`
		Notification struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		} `json:"notification"`
	} `json:"message"`
	EventType   string `json:"eventType"`   // "delivered", "read", etc.
	EventTime   string `json:"eventTime"`
	DeviceToken string `json:"deviceToken"`
}

// APNSWebhookPayload represents APNS-specific webhook payload
type APNSWebhookPayload struct {
	DeviceToken   string            `json:"device-token"`
	Status        string            `json:"status"`
	Timestamp     int64             `json:"timestamp"`
	MessageID     string            `json:"id"`
	ErrorCode     string            `json:"error-code,omitempty"`
	ErrorMessage  string            `json:"error-message,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler(trackingService *DeliveryTrackingService, logger *logrus.Logger, config WebhookConfig) *WebhookHandler {
	// Set defaults
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 30
	}
	if config.MaxPayloadSize == 0 {
		config.MaxPayloadSize = 1024 * 1024 // 1MB
	}

	return &WebhookHandler{
		trackingService: trackingService,
		logger:          logger,
		config:          config,
	}
}

// RegisterRoutes registers webhook routes
func (h *WebhookHandler) RegisterRoutes(router *mux.Router) {
	if !h.config.EnableWebhooks {
		h.logger.Info("Webhooks are disabled")
		return
	}

	// Generic webhook endpoint
	router.HandleFunc("/webhooks/delivery", h.handleDeliveryWebhook).Methods("POST")
	router.HandleFunc("/webhooks/read", h.handleReadWebhook).Methods("POST")
	
	// Platform-specific webhook endpoints
	router.HandleFunc("/webhooks/fcm/delivery", h.handleFCMWebhook).Methods("POST")
	router.HandleFunc("/webhooks/apns/delivery", h.handleAPNSWebhook).Methods("POST")
	
	// Health check for webhook endpoints
	router.HandleFunc("/webhooks/health", h.handleWebhookHealth).Methods("GET")

	h.logger.Info("Webhook routes registered")
}

// handleDeliveryWebhook handles generic delivery receipt webhooks
func (h *WebhookHandler) handleDeliveryWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.TimeoutSeconds)*time.Second)
	defer cancel()

	// Validate request
	if err := h.validateRequest(r); err != nil {
		h.logger.WithError(err).Warn("Invalid webhook request")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse payload
	var payload WebhookPayload
	if err := h.parseJSONPayload(r, &payload); err != nil {
		h.logger.WithError(err).Error("Failed to parse webhook payload")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Process delivery receipt
	if err := h.processDeliveryReceipt(ctx, &payload); err != nil {
		h.logger.WithError(err).Error("Failed to process delivery receipt")
		http.Error(w, "Processing failed", http.StatusInternalServerError)
		return
	}

	// Log successful processing
	h.logger.WithFields(logrus.Fields{
		"event_type":   payload.EventType,
		"message_id":   payload.MessageID,
		"platform":     payload.Platform,
		"status":       payload.Status,
		"timestamp":    payload.Timestamp,
	}).Info("Processed delivery webhook")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleReadWebhook handles read confirmation webhooks
func (h *WebhookHandler) handleReadWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.TimeoutSeconds)*time.Second)
	defer cancel()

	// Validate request
	if err := h.validateRequest(r); err != nil {
		h.logger.WithError(err).Warn("Invalid webhook request")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse payload
	var payload WebhookPayload
	if err := h.parseJSONPayload(r, &payload); err != nil {
		h.logger.WithError(err).Error("Failed to parse webhook payload")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Process read confirmation
	if err := h.processReadConfirmation(ctx, &payload); err != nil {
		h.logger.WithError(err).Error("Failed to process read confirmation")
		http.Error(w, "Processing failed", http.StatusInternalServerError)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"message_id": payload.MessageID,
		"platform":   payload.Platform,
		"timestamp":  payload.Timestamp,
	}).Info("Processed read webhook")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleFCMWebhook handles FCM-specific webhook format
func (h *WebhookHandler) handleFCMWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.TimeoutSeconds)*time.Second)
	defer cancel()

	// Validate request
	if err := h.validateRequest(r); err != nil {
		h.logger.WithError(err).Warn("Invalid FCM webhook request")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse FCM payload
	var fcmPayload FCMWebhookPayload
	if err := h.parseJSONPayload(r, &fcmPayload); err != nil {
		h.logger.WithError(err).Error("Failed to parse FCM webhook payload")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Convert to standard payload
	payload := h.convertFCMPayload(&fcmPayload)

	// Process delivery receipt
	if err := h.processDeliveryReceipt(ctx, payload); err != nil {
		h.logger.WithError(err).Error("Failed to process FCM delivery receipt")
		http.Error(w, "Processing failed", http.StatusInternalServerError)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"message_id":   fcmPayload.Message.MessageID,
		"event_type":   fcmPayload.EventType,
		"device_token": fcmPayload.DeviceToken,
	}).Info("Processed FCM webhook")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleAPNSWebhook handles APNS-specific webhook format
func (h *WebhookHandler) handleAPNSWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.TimeoutSeconds)*time.Second)
	defer cancel()

	// Validate request
	if err := h.validateRequest(r); err != nil {
		h.logger.WithError(err).Warn("Invalid APNS webhook request")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse APNS payload
	var apnsPayload APNSWebhookPayload
	if err := h.parseJSONPayload(r, &apnsPayload); err != nil {
		h.logger.WithError(err).Error("Failed to parse APNS webhook payload")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Convert to standard payload
	payload := h.convertAPNSPayload(&apnsPayload)

	// Process delivery receipt
	if err := h.processDeliveryReceipt(ctx, payload); err != nil {
		h.logger.WithError(err).Error("Failed to process APNS delivery receipt")
		http.Error(w, "Processing failed", http.StatusInternalServerError)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"message_id":   apnsPayload.MessageID,
		"status":       apnsPayload.Status,
		"device_token": apnsPayload.DeviceToken,
	}).Info("Processed APNS webhook")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleWebhookHealth handles health checks for webhook endpoints
func (h *WebhookHandler) handleWebhookHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":          "ok",
		"webhooks_enabled": h.config.EnableWebhooks,
		"timestamp":       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// validateRequest validates incoming webhook requests
func (h *WebhookHandler) validateRequest(r *http.Request) error {
	// Check content type
	if r.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("invalid content type: %s", r.Header.Get("Content-Type"))
	}

	// Check content length
	if r.ContentLength > h.config.MaxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes", r.ContentLength)
	}

	// Check IP filtering
	if h.config.EnableIPFiltering && len(h.config.AllowedIPs) > 0 {
		clientIP := h.getClientIP(r)
		allowed := false
		for _, allowedIP := range h.config.AllowedIPs {
			if clientIP == allowedIP || strings.Contains(clientIP, allowedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP not allowed: %s", clientIP)
		}
	}

	// Validate signature if secret key is configured
	if h.config.SecretKey != "" {
		if err := h.validateSignature(r); err != nil {
			return fmt.Errorf("invalid signature: %w", err)
		}
	}

	return nil
}

// validateSignature validates webhook signature
func (h *WebhookHandler) validateSignature(r *http.Request) error {
	signature := r.Header.Get("X-Webhook-Signature")
	if signature == "" {
		return fmt.Errorf("missing signature header")
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	// Reset body for subsequent reads
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(h.config.SecretKey))
	mac.Write(body)
	expectedSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Compare signatures
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

// parseJSONPayload parses JSON payload from request
func (h *WebhookHandler) parseJSONPayload(r *http.Request, v interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

// processDeliveryReceipt processes a delivery receipt
func (h *WebhookHandler) processDeliveryReceipt(ctx context.Context, payload *WebhookPayload) error {
	// Find notification by message ID or device token
	notificationID, err := h.findNotificationID(ctx, payload.MessageID, payload.DeviceToken)
	if err != nil {
		return fmt.Errorf("failed to find notification: %w", err)
	}

	// Create delivery receipt
	deliveryTime := payload.Timestamp
	if deliveryTime.IsZero() {
		deliveryTime = time.Now()
	}

	receipt := &DeliveryReceipt{
		NotificationID: notificationID,
		MessageID:      payload.MessageID,
		DeviceToken:    payload.DeviceToken,
		Platform:       h.parsePlatform(payload.Platform),
		Status:         payload.Status,
		DeliveredAt:    &deliveryTime,
		ErrorCode:      payload.ErrorCode,
		ErrorMessage:   payload.ErrorMessage,
		Metadata:       h.convertMetadata(payload.Metadata),
	}

	// Process receipt
	return h.trackingService.ProcessDeliveryReceipt(ctx, receipt)
}

// processReadConfirmation processes a read confirmation
func (h *WebhookHandler) processReadConfirmation(ctx context.Context, payload *WebhookPayload) error {
	// Find notification by message ID or device token
	notificationID, err := h.findNotificationID(ctx, payload.MessageID, payload.DeviceToken)
	if err != nil {
		return fmt.Errorf("failed to find notification: %w", err)
	}

	// Extract user ID from metadata or notification
	userID, err := h.extractUserID(ctx, notificationID, payload.Metadata)
	if err != nil {
		return fmt.Errorf("failed to extract user ID: %w", err)
	}

	// Track read
	metadata := h.convertMetadata(payload.Metadata)
	return h.trackingService.TrackNotificationRead(ctx, notificationID, userID, payload.DeviceToken, "opened", metadata)
}

// findNotificationID finds notification ID by message ID or device token
func (h *WebhookHandler) findNotificationID(ctx context.Context, messageID, deviceToken string) (uuid.UUID, error) {
	// This would need to be implemented based on your notification storage strategy
	// For now, return a placeholder implementation
	
	// In a real implementation, you might:
	// 1. Look up by message ID in a mapping table
	// 2. Query notifications by device token and recent timestamp
	// 3. Use a Redis cache for fast lookups
	
	return uuid.New(), fmt.Errorf("notification lookup not implemented")
}

// extractUserID extracts user ID from notification or metadata
func (h *WebhookHandler) extractUserID(ctx context.Context, notificationID uuid.UUID, metadata map[string]interface{}) (uuid.UUID, error) {
	// Try to extract from metadata first
	if userIDStr, exists := metadata["user_id"]; exists {
		if userIDString, ok := userIDStr.(string); ok {
			return uuid.Parse(userIDString)
		}
	}

	// Fallback: look up notification and get user ID
	// This would require a call to the notification repository
	return uuid.New(), fmt.Errorf("user ID extraction not implemented")
}

// convertFCMPayload converts FCM webhook payload to standard format
func (h *WebhookHandler) convertFCMPayload(fcm *FCMWebhookPayload) *WebhookPayload {
	eventTime, _ := time.Parse(time.RFC3339, fcm.EventTime)
	
	return &WebhookPayload{
		EventType:    fcm.EventType,
		Timestamp:    eventTime,
		MessageID:    fcm.Message.MessageID,
		Platform:     "fcm",
		DeviceToken:  fcm.DeviceToken,
		Status:       fcm.EventType, // FCM uses eventType as status
		Metadata: map[string]interface{}{
			"from":         fcm.Message.From,
			"category":     fcm.Message.Category,
			"collapse_key": fcm.Message.CollapseKey,
		},
	}
}

// convertAPNSPayload converts APNS webhook payload to standard format
func (h *WebhookHandler) convertAPNSPayload(apns *APNSWebhookPayload) *WebhookPayload {
	timestamp := time.Unix(apns.Timestamp/1000, (apns.Timestamp%1000)*1000000)
	
	return &WebhookPayload{
		EventType:    "delivery",
		Timestamp:    timestamp,
		MessageID:    apns.MessageID,
		Platform:     "apns",
		DeviceToken:  apns.DeviceToken,
		Status:       apns.Status,
		ErrorCode:    apns.ErrorCode,
		ErrorMessage: apns.ErrorMessage,
		Metadata: map[string]interface{}{
			"headers": apns.Headers,
		},
	}
}

// parsePlatform converts string platform to entity.Platform
func (h *WebhookHandler) parsePlatform(platform string) entity.Platform {
	switch strings.ToLower(platform) {
	case "fcm", "android":
		return entity.PlatformFCM
	case "apns", "ios":
		return entity.PlatformAPNS
	case "web", "webpush":
		return entity.PlatformWeb
	default:
		return entity.PlatformFCM // Default
	}
}

// convertMetadata converts interface{} metadata to string map
func (h *WebhookHandler) convertMetadata(metadata map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			result[k] = str
		} else {
			result[k] = fmt.Sprintf("%v", v)
		}
	}
	return result
}

// getClientIP extracts client IP from request
func (h *WebhookHandler) getClientIP(r *http.Request) string {
	// Check for forwarded IP
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Take the first IP in case of multiple
		return strings.Split(forwarded, ",")[0]
	}

	// Check for real IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to remote address
	return strings.Split(r.RemoteAddr, ":")[0]
}