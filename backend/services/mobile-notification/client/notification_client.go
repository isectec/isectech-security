package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// NotificationClient provides a client interface for the mobile notification service
type NotificationClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	userAgent  string
}

// ClientConfig represents configuration for the notification client
type ClientConfig struct {
	BaseURL     string        `json:"base_url"`
	APIKey      string        `json:"api_key"`
	Timeout     time.Duration `json:"timeout"`
	UserAgent   string        `json:"user_agent"`
}

// NotificationRequest represents a notification creation request
type NotificationRequest struct {
	TenantID     uuid.UUID         `json:"tenant_id"`
	UserID       uuid.UUID         `json:"user_id"`
	Title        string            `json:"title"`
	Body         string            `json:"body"`
	Priority     string            `json:"priority"`     // "critical", "warning", "informational"
	Platform     string            `json:"platform"`     // "fcm", "apns", "web"
	DeviceToken  string            `json:"device_token"`
	Data         map[string]string `json:"data,omitempty"`
	ImageURL     string            `json:"image_url,omitempty"`
	ActionURL    string            `json:"action_url,omitempty"`
	TTL          int               `json:"ttl,omitempty"`
	ScheduledFor *time.Time        `json:"scheduled_for,omitempty"`
}

// NotificationResponse represents a notification creation response
type NotificationResponse struct {
	ID           uuid.UUID `json:"id"`
	Status       string    `json:"status"`
	MessageID    string    `json:"message_id,omitempty"`
	ScheduledFor *time.Time `json:"scheduled_for,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// DeviceRegistrationRequest represents a device registration request
type DeviceRegistrationRequest struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	UserID      uuid.UUID `json:"user_id"`
	DeviceToken string    `json:"device_token"`
	Platform    string    `json:"platform"`
	AppVersion  string    `json:"app_version,omitempty"`
	OSVersion   string    `json:"os_version,omitempty"`
	DeviceModel string    `json:"device_model,omitempty"`
	Language    string    `json:"language,omitempty"`
	Timezone    string    `json:"timezone,omitempty"`
}

// DeviceRegistrationResponse represents a device registration response
type DeviceRegistrationResponse struct {
	ID        uuid.UUID `json:"id"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ReadConfirmationRequest represents a read confirmation request
type ReadConfirmationRequest struct {
	NotificationID  uuid.UUID         `json:"notification_id"`
	UserID          uuid.UUID         `json:"user_id"`
	DeviceToken     string            `json:"device_token"`
	InteractionType string            `json:"interaction_type"` // "opened", "clicked", "dismissed"
	ActionTaken     string            `json:"action_taken,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// NotificationStatus represents the status of a notification
type NotificationStatus struct {
	ID                uuid.UUID                `json:"id"`
	Status            string                   `json:"status"`
	SentAt            *time.Time               `json:"sent_at"`
	DeliveredAt       *time.Time               `json:"delivered_at"`
	ReadAt            *time.Time               `json:"read_at"`
	DeliveryReceipts  []DeliveryReceipt        `json:"delivery_receipts"`
	HasActiveTracking bool                     `json:"has_active_tracking"`
	IsRead            bool                     `json:"is_read"`
}

// DeliveryReceipt represents a delivery receipt
type DeliveryReceipt struct {
	ID           uuid.UUID `json:"id"`
	Platform     string    `json:"platform"`
	Status       string    `json:"status"`
	ErrorCode    string    `json:"error_code,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
	AttemptCount int       `json:"attempt_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ClientError represents an error from the notification service
type ClientError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *ClientError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("notification service error (code %d): %s - %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("notification service error (code %d): %s", e.Code, e.Message)
}

// NewNotificationClient creates a new notification service client
func NewNotificationClient(config ClientConfig) *NotificationClient {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	
	if config.UserAgent == "" {
		config.UserAgent = "isectech-notification-client/1.0"
	}

	return &NotificationClient{
		baseURL:   config.BaseURL,
		apiKey:    config.APIKey,
		userAgent: config.UserAgent,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// SendNotification sends a notification
func (c *NotificationClient) SendNotification(ctx context.Context, req *NotificationRequest) (*NotificationResponse, error) {
	url := c.baseURL + "/api/v1/notifications"
	
	resp, err := c.makeRequest(ctx, "POST", url, req)
	if err != nil {
		return nil, err
	}

	var notification NotificationResponse
	if err := json.Unmarshal(resp, &notification); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &notification, nil
}

// SendBatchNotifications sends multiple notifications in a batch
func (c *NotificationClient) SendBatchNotifications(ctx context.Context, requests []*NotificationRequest) ([]*NotificationResponse, error) {
	url := c.baseURL + "/api/v1/notifications/batch"
	
	resp, err := c.makeRequest(ctx, "POST", url, requests)
	if err != nil {
		return nil, err
	}

	var notifications []*NotificationResponse
	if err := json.Unmarshal(resp, &notifications); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return notifications, nil
}

// GetNotificationStatus gets the status of a notification
func (c *NotificationClient) GetNotificationStatus(ctx context.Context, notificationID uuid.UUID) (*NotificationStatus, error) {
	url := fmt.Sprintf("%s/api/v1/notifications/%s", c.baseURL, notificationID)
	
	resp, err := c.makeRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	var status NotificationStatus
	if err := json.Unmarshal(resp, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &status, nil
}

// RegisterDevice registers a device for push notifications
func (c *NotificationClient) RegisterDevice(ctx context.Context, req *DeviceRegistrationRequest) (*DeviceRegistrationResponse, error) {
	url := c.baseURL + "/api/v1/devices"
	
	resp, err := c.makeRequest(ctx, "POST", url, req)
	if err != nil {
		return nil, err
	}

	var device DeviceRegistrationResponse
	if err := json.Unmarshal(resp, &device); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &device, nil
}

// UnregisterDevice unregisters a device
func (c *NotificationClient) UnregisterDevice(ctx context.Context, deviceToken string) error {
	url := fmt.Sprintf("%s/api/v1/devices/%s", c.baseURL, url.PathEscape(deviceToken))
	
	_, err := c.makeRequest(ctx, "DELETE", url, nil)
	return err
}

// ConfirmRead confirms that a notification has been read
func (c *NotificationClient) ConfirmRead(ctx context.Context, req *ReadConfirmationRequest) error {
	url := fmt.Sprintf("%s/api/v1/notifications/%s/read", c.baseURL, req.NotificationID)
	
	_, err := c.makeRequest(ctx, "POST", url, req)
	return err
}

// GetUserNotifications gets notifications for a specific user
func (c *NotificationClient) GetUserNotifications(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*NotificationStatus, error) {
	params := url.Values{}
	params.Set("user_id", userID.String())
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("offset", fmt.Sprintf("%d", offset))
	
	url := fmt.Sprintf("%s/api/v1/notifications?%s", c.baseURL, params.Encode())
	
	resp, err := c.makeRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	var notifications []*NotificationStatus
	if err := json.Unmarshal(resp, &notifications); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return notifications, nil
}

// UpdateNotificationPreferences updates user notification preferences
func (c *NotificationClient) UpdateNotificationPreferences(ctx context.Context, userID uuid.UUID, preferences map[string]interface{}) error {
	url := fmt.Sprintf("%s/api/v1/users/%s/preferences", c.baseURL, userID)
	
	_, err := c.makeRequest(ctx, "PUT", url, preferences)
	return err
}

// GetDeliveryAnalytics gets delivery analytics for a tenant
func (c *NotificationClient) GetDeliveryAnalytics(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("tenant_id", tenantID.String())
	params.Set("from", from.Format(time.RFC3339))
	params.Set("to", to.Format(time.RFC3339))
	
	url := fmt.Sprintf("%s/api/v1/analytics?%s", c.baseURL, params.Encode())
	
	resp, err := c.makeRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	var analytics map[string]interface{}
	if err := json.Unmarshal(resp, &analytics); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return analytics, nil
}

// Ping checks if the notification service is healthy
func (c *NotificationClient) Ping(ctx context.Context) error {
	url := c.baseURL + "/health"
	
	_, err := c.makeRequest(ctx, "GET", url, nil)
	return err
}

// makeRequest makes an HTTP request to the notification service
func (c *NotificationClient) makeRequest(ctx context.Context, method, url string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		var clientErr ClientError
		if err := json.Unmarshal(respBody, &clientErr); err != nil {
			// Fallback error if we can't parse the error response
			return nil, &ClientError{
				Code:    resp.StatusCode,
				Message: resp.Status,
				Details: string(respBody),
			}
		}
		clientErr.Code = resp.StatusCode
		return nil, &clientErr
	}

	return respBody, nil
}

// Helper functions for creating common request types

// NewCriticalNotification creates a critical notification request
func NewCriticalNotification(tenantID, userID uuid.UUID, deviceToken, title, body string) *NotificationRequest {
	return &NotificationRequest{
		TenantID:    tenantID,
		UserID:      userID,
		Title:       title,
		Body:        body,
		Priority:    "critical",
		DeviceToken: deviceToken,
		TTL:         3600, // 1 hour
	}
}

// NewWarningNotification creates a warning notification request
func NewWarningNotification(tenantID, userID uuid.UUID, deviceToken, title, body string) *NotificationRequest {
	return &NotificationRequest{
		TenantID:    tenantID,
		UserID:      userID,
		Title:       title,
		Body:        body,
		Priority:    "warning",
		DeviceToken: deviceToken,
		TTL:         7200, // 2 hours
	}
}

// NewInformationalNotification creates an informational notification request
func NewInformationalNotification(tenantID, userID uuid.UUID, deviceToken, title, body string) *NotificationRequest {
	return &NotificationRequest{
		TenantID:    tenantID,
		UserID:      userID,
		Title:       title,
		Body:        body,
		Priority:    "informational",
		DeviceToken: deviceToken,
		TTL:         86400, // 24 hours
	}
}

// NewDeviceRegistration creates a device registration request
func NewDeviceRegistration(tenantID, userID uuid.UUID, deviceToken, platform string) *DeviceRegistrationRequest {
	return &DeviceRegistrationRequest{
		TenantID:    tenantID,
		UserID:      userID,
		DeviceToken: deviceToken,
		Platform:    platform,
		Language:    "en",
		Timezone:    "UTC",
	}
}

// NewReadConfirmation creates a read confirmation request
func NewReadConfirmation(notificationID, userID uuid.UUID, deviceToken, interactionType string) *ReadConfirmationRequest {
	return &ReadConfirmationRequest{
		NotificationID:  notificationID,
		UserID:          userID,
		DeviceToken:     deviceToken,
		InteractionType: interactionType,
		Metadata:        make(map[string]string),
	}
}