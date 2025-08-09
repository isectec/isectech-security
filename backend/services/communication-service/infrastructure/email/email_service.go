package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/isectech/protect/backend/services/communication-service/domain/entity"
)

// EmailService defines the interface for email service providers
type EmailService interface {
	SendEmail(ctx context.Context, request *SendEmailRequest) (*SendEmailResponse, error)
	ValidateConfiguration(ctx context.Context) error
	GetQuotaInfo(ctx context.Context) (*QuotaInfo, error)
	ProcessWebhook(ctx context.Context, webhookData []byte) (*WebhookEvent, error)
	GetProviderType() string
}

// EmailServiceFactory creates email service instances
type EmailServiceFactory struct {
	httpClient *http.Client
}

func NewEmailServiceFactory() *EmailServiceFactory {
	return &EmailServiceFactory{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (f *EmailServiceFactory) CreateEmailService(provider *entity.EmailProvider) (EmailService, error) {
	switch strings.ToLower(provider.Type) {
	case "sendgrid":
		return NewSendGridService(provider, f.httpClient)
	case "ses", "aws-ses":
		return NewAWSSESService(provider)
	case "mailgun":
		return NewMailgunService(provider, f.httpClient)
	default:
		return nil, fmt.Errorf("unsupported email provider type: %s", provider.Type)
	}
}

// Common types for all email services
type SendEmailRequest struct {
	From           EmailAddress   `json:"from"`
	To             []EmailAddress `json:"to"`
	CC             []EmailAddress `json:"cc,omitempty"`
	BCC            []EmailAddress `json:"bcc,omitempty"`
	Subject        string         `json:"subject"`
	HTMLContent    string         `json:"html_content"`
	TextContent    string         `json:"text_content"`
	TrackOpens     bool           `json:"track_opens"`
	TrackClicks    bool           `json:"track_clicks"`
	Tags           []string       `json:"tags,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ScheduledAt    *time.Time     `json:"scheduled_at,omitempty"`
	UnsubscribeURL *string        `json:"unsubscribe_url,omitempty"`
	TenantID       string         `json:"tenant_id"`
}

type EmailAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type SendEmailResponse struct {
	ProviderMessageID string    `json:"provider_message_id"`
	Status            string    `json:"status"`
	DeliveryTime      int64     `json:"delivery_time_ms"`
	QuotaRemaining    *int      `json:"quota_remaining,omitempty"`
	Error             *string   `json:"error,omitempty"`
	SentAt            time.Time `json:"sent_at"`
}

type QuotaInfo struct {
	DailyLimit      int       `json:"daily_limit"`
	DailyUsed       int       `json:"daily_used"`
	DailyRemaining  int       `json:"daily_remaining"`
	HourlyLimit     int       `json:"hourly_limit"`
	HourlyUsed      int       `json:"hourly_used"`
	HourlyRemaining int       `json:"hourly_remaining"`
	ResetTime       time.Time `json:"reset_time"`
}

type WebhookEvent struct {
	ProviderMessageID string                 `json:"provider_message_id"`
	EventType         string                 `json:"event_type"`
	Timestamp         time.Time              `json:"timestamp"`
	Email             string                 `json:"email"`
	EventData         map[string]interface{} `json:"event_data"`
}

// SendGrid Implementation
type SendGridService struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

func NewSendGridService(provider *entity.EmailProvider, httpClient *http.Client) (*SendGridService, error) {
	apiKey, exists := provider.Configuration["api_key"].(string)
	if !exists || apiKey == "" {
		return nil, fmt.Errorf("sendgrid api_key is required")
	}

	return &SendGridService{
		apiKey:     apiKey,
		httpClient: httpClient,
		baseURL:    "https://api.sendgrid.com/v3",
	}, nil
}

func (s *SendGridService) SendEmail(ctx context.Context, request *SendEmailRequest) (*SendEmailResponse, error) {
	startTime := time.Now()

	payload := s.buildSendGridPayload(request)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sendgrid payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.baseURL+"/mail/send", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	deliveryTime := time.Since(startTime).Milliseconds()

	if resp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errorMsg := fmt.Sprintf("sendgrid api error: %d - %s", resp.StatusCode, string(bodyBytes))
		return &SendEmailResponse{
			Status:       "failed",
			DeliveryTime: deliveryTime,
			Error:        &errorMsg,
			SentAt:       time.Now(),
		}, nil
	}

	messageID := resp.Header.Get("X-Message-Id")
	if messageID == "" {
		messageID = fmt.Sprintf("sg_%d", time.Now().UnixNano())
	}

	return &SendEmailResponse{
		ProviderMessageID: messageID,
		Status:            "sent",
		DeliveryTime:      deliveryTime,
		SentAt:            time.Now(),
	}, nil
}

func (s *SendGridService) ValidateConfiguration(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"/user/profile", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sendgrid configuration invalid: %d", resp.StatusCode)
	}

	return nil
}

func (s *SendGridService) GetQuotaInfo(ctx context.Context) (*QuotaInfo, error) {
	// SendGrid doesn't provide quota info via API, so we return nil
	// This would need to be tracked in the application layer
	return nil, nil
}

func (s *SendGridService) ProcessWebhook(ctx context.Context, webhookData []byte) (*WebhookEvent, error) {
	var events []map[string]interface{}
	if err := json.Unmarshal(webhookData, &events); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sendgrid webhook: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("no events in webhook payload")
	}

	// Process first event (in production, you'd process all events)
	event := events[0]

	timestamp := time.Now()
	if ts, exists := event["timestamp"].(float64); exists {
		timestamp = time.Unix(int64(ts), 0)
	}

	return &WebhookEvent{
		ProviderMessageID: getString(event, "sg_message_id"),
		EventType:         getString(event, "event"),
		Timestamp:         timestamp,
		Email:             getString(event, "email"),
		EventData:         event,
	}, nil
}

func (s *SendGridService) GetProviderType() string {
	return "sendgrid"
}

func (s *SendGridService) buildSendGridPayload(request *SendEmailRequest) map[string]interface{} {
	personalizations := []map[string]interface{}{
		{
			"to": s.buildEmailAddresses(request.To),
		},
	}

	if len(request.CC) > 0 {
		personalizations[0]["cc"] = s.buildEmailAddresses(request.CC)
	}
	if len(request.BCC) > 0 {
		personalizations[0]["bcc"] = s.buildEmailAddresses(request.BCC)
	}

	content := []map[string]interface{}{}
	if request.TextContent != "" {
		content = append(content, map[string]interface{}{
			"type":  "text/plain",
			"value": request.TextContent,
		})
	}
	if request.HTMLContent != "" {
		content = append(content, map[string]interface{}{
			"type":  "text/html",
			"value": request.HTMLContent,
		})
	}

	payload := map[string]interface{}{
		"personalizations": personalizations,
		"from": map[string]interface{}{
			"email": request.From.Email,
			"name":  request.From.Name,
		},
		"subject": request.Subject,
		"content": content,
	}

	if request.TrackOpens || request.TrackClicks {
		payload["tracking_settings"] = map[string]interface{}{
			"click_tracking": map[string]interface{}{
				"enable": request.TrackClicks,
			},
			"open_tracking": map[string]interface{}{
				"enable": request.TrackOpens,
			},
		}
	}

	if len(request.Tags) > 0 {
		payload["categories"] = request.Tags
	}

	if request.UnsubscribeURL != nil {
		payload["tracking_settings"].(map[string]interface{})["subscription_tracking"] = map[string]interface{}{
			"enable":           true,
			"substitution_tag": "{{unsubscribe}}",
			"html":            fmt.Sprintf(`<a href="%s">Unsubscribe</a>`, *request.UnsubscribeURL),
			"text":            fmt.Sprintf("Unsubscribe: %s", *request.UnsubscribeURL),
		}
	}

	return payload
}

func (s *SendGridService) buildEmailAddresses(addresses []EmailAddress) []map[string]interface{} {
	result := make([]map[string]interface{}, len(addresses))
	for i, addr := range addresses {
		result[i] = map[string]interface{}{
			"email": addr.Email,
			"name":  addr.Name,
		}
	}
	return result
}

// AWS SES Implementation
type AWSSESService struct {
	sesClient   *ses.Client
	sesV2Client *sesv2.Client
	region      string
}

func NewAWSSESService(provider *entity.EmailProvider) (*AWSSESService, error) {
	region, exists := provider.Configuration["region"].(string)
	if !exists || region == "" {
		region = "us-east-1" // default region
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	return &AWSSESService{
		sesClient:   ses.NewFromConfig(cfg),
		sesV2Client: sesv2.NewFromConfig(cfg),
		region:      region,
	}, nil
}

func (s *AWSSESService) SendEmail(ctx context.Context, request *SendEmailRequest) (*SendEmailResponse, error) {
	startTime := time.Now()

	var destinations []string
	for _, to := range request.To {
		destinations = append(destinations, to.Email)
	}

	input := &ses.SendEmailInput{
		Source:       aws.String(s.formatEmailAddress(request.From)),
		Destination: &ses.Destination{
			ToAddresses: destinations,
		},
		Message: &ses.Message{
			Subject: &ses.Content{
				Data: aws.String(request.Subject),
			},
			Body: &ses.Body{},
		},
	}

	if request.HTMLContent != "" {
		input.Message.Body.Html = &ses.Content{
			Data: aws.String(request.HTMLContent),
		}
	}

	if request.TextContent != "" {
		input.Message.Body.Text = &ses.Content{
			Data: aws.String(request.TextContent),
		}
	}

	if len(request.CC) > 0 {
		for _, cc := range request.CC {
			input.Destination.CcAddresses = append(input.Destination.CcAddresses, cc.Email)
		}
	}

	if len(request.BCC) > 0 {
		for _, bcc := range request.BCC {
			input.Destination.BccAddresses = append(input.Destination.BccAddresses, bcc.Email)
		}
	}

	result, err := s.sesClient.SendEmail(ctx, input)
	if err != nil {
		deliveryTime := time.Since(startTime).Milliseconds()
		errorMsg := err.Error()
		return &SendEmailResponse{
			Status:       "failed",
			DeliveryTime: deliveryTime,
			Error:        &errorMsg,
			SentAt:       time.Now(),
		}, nil
	}

	deliveryTime := time.Since(startTime).Milliseconds()

	return &SendEmailResponse{
		ProviderMessageID: *result.MessageId,
		Status:            "sent",
		DeliveryTime:      deliveryTime,
		SentAt:            time.Now(),
	}, nil
}

func (s *AWSSESService) ValidateConfiguration(ctx context.Context) error {
	_, err := s.sesClient.GetSendQuota(ctx, &ses.GetSendQuotaInput{})
	return err
}

func (s *AWSSESService) GetQuotaInfo(ctx context.Context) (*QuotaInfo, error) {
	quota, err := s.sesClient.GetSendQuota(ctx, &ses.GetSendQuotaInput{})
	if err != nil {
		return nil, err
	}

	statistics, err := s.sesClient.GetSendStatistics(ctx, &ses.GetSendStatisticsInput{})
	if err != nil {
		return nil, err
	}

	dailyUsed := 0
	if len(statistics.SendDataPoints) > 0 {
		// Calculate today's usage from the most recent data point
		for _, point := range statistics.SendDataPoints {
			if point.Timestamp.After(time.Now().Add(-24 * time.Hour)) {
				dailyUsed += int(*point.DeliveryAttempts)
			}
		}
	}

	return &QuotaInfo{
		DailyLimit:      int(*quota.Max24HourSend),
		DailyUsed:       dailyUsed,
		DailyRemaining:  int(*quota.Max24HourSend) - dailyUsed,
		HourlyLimit:     int(*quota.MaxSendRate),
		ResetTime:       time.Now().Add(24 * time.Hour),
	}, nil
}

func (s *AWSSESService) ProcessWebhook(ctx context.Context, webhookData []byte) (*WebhookEvent, error) {
	var event map[string]interface{}
	if err := json.Unmarshal(webhookData, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ses webhook: %w", err)
	}

	eventType := getString(event, "eventType")
	if eventType == "" {
		eventType = getString(event, "notificationType")
	}

	timestamp := time.Now()
	if ts := getString(event, "timestamp"); ts != "" {
		if parsedTime, err := time.Parse(time.RFC3339, ts); err == nil {
			timestamp = parsedTime
		}
	}

	email := ""
	if mail := event["mail"].(map[string]interface{}); mail != nil {
		if destination := mail["destination"].([]interface{}); destination != nil && len(destination) > 0 {
			email = destination[0].(string)
		}
	}

	messageID := getString(event, "messageId")
	if messageID == "" {
		if mail := event["mail"].(map[string]interface{}); mail != nil {
			messageID = getString(mail, "messageId")
		}
	}

	return &WebhookEvent{
		ProviderMessageID: messageID,
		EventType:         eventType,
		Timestamp:         timestamp,
		Email:             email,
		EventData:         event,
	}, nil
}

func (s *AWSSESService) GetProviderType() string {
	return "aws-ses"
}

func (s *AWSSESService) formatEmailAddress(addr EmailAddress) string {
	if addr.Name != "" {
		return fmt.Sprintf("%s <%s>", addr.Name, addr.Email)
	}
	return addr.Email
}

// Mailgun Implementation (basic structure)
type MailgunService struct {
	apiKey     string
	domain     string
	httpClient *http.Client
	baseURL    string
}

func NewMailgunService(provider *entity.EmailProvider, httpClient *http.Client) (*MailgunService, error) {
	apiKey, exists := provider.Configuration["api_key"].(string)
	if !exists || apiKey == "" {
		return nil, fmt.Errorf("mailgun api_key is required")
	}

	domain, exists := provider.Configuration["domain"].(string)
	if !exists || domain == "" {
		return nil, fmt.Errorf("mailgun domain is required")
	}

	region := "us"
	if r, exists := provider.Configuration["region"].(string); exists {
		region = r
	}

	baseURL := "https://api.mailgun.net/v3"
	if region == "eu" {
		baseURL = "https://api.eu.mailgun.net/v3"
	}

	return &MailgunService{
		apiKey:     apiKey,
		domain:     domain,
		httpClient: httpClient,
		baseURL:    baseURL,
	}, nil
}

func (m *MailgunService) SendEmail(ctx context.Context, request *SendEmailRequest) (*SendEmailResponse, error) {
	// Mailgun implementation would go here
	// Similar to SendGrid but with Mailgun-specific API calls
	return nil, fmt.Errorf("mailgun implementation not yet complete")
}

func (m *MailgunService) ValidateConfiguration(ctx context.Context) error {
	// Mailgun configuration validation
	return fmt.Errorf("mailgun implementation not yet complete")
}

func (m *MailgunService) GetQuotaInfo(ctx context.Context) (*QuotaInfo, error) {
	// Mailgun quota information
	return nil, fmt.Errorf("mailgun implementation not yet complete")
}

func (m *MailgunService) ProcessWebhook(ctx context.Context, webhookData []byte) (*WebhookEvent, error) {
	// Mailgun webhook processing
	return nil, fmt.Errorf("mailgun implementation not yet complete")
}

func (m *MailgunService) GetProviderType() string {
	return "mailgun"
}

// Utility functions
func getString(data map[string]interface{}, key string) string {
	if val, exists := data[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}