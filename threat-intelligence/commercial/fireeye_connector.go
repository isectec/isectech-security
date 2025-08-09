package commercial

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// FireEyeConnector integrates with FireEye Threat Intelligence API
type FireEyeConnector struct {
	logger     *zap.Logger
	config     *FireEyeConfig
	httpClient *http.Client
	
	// API state
	lastFetchTime time.Time
	rateLimiter   *RateLimiter
}

// FireEyeResponse represents the API response structure
type FireEyeResponse struct {
	Objects []FireEyeIndicator `json:"objects"`
	Meta    struct {
		Total       int    `json:"total"`
		Limit       int    `json:"limit"`
		Offset      int    `json:"offset"`
		NextURL     string `json:"next_url"`
		PreviousURL string `json:"previous_url"`
	} `json:"meta"`
	Message string `json:"message,omitempty"`
	Success bool   `json:"success"`
}

// FireEyeIndicator represents a threat indicator from FireEye
type FireEyeIndicator struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	Subcategory  string    `json:"subcategory"`
	ThreatType   string    `json:"threat_type"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	LastModified time.Time `json:"last_modified"`
	
	Confidence struct {
		Level   string  `json:"level"`
		Score   int     `json:"score"`
		Reasons []string `json:"reasons"`
	} `json:"confidence"`
	
	Metadata struct {
		MalwareFamily  []string               `json:"malware_family"`
		ThreatGroups   []string               `json:"threat_groups"`
		Industries     []string               `json:"industries"`
		Countries      []string               `json:"countries"`
		Campaigns      []string               `json:"campaigns"`
		Techniques     []string               `json:"techniques"`
		Tactics        []string               `json:"tactics"`
		CVEs           []string               `json:"cves"`
		References     []string               `json:"references"`
		AdditionalInfo map[string]interface{} `json:"additional_info"`
	} `json:"metadata"`
	
	Attribution struct {
		Groups      []string `json:"groups"`
		Campaigns   []string `json:"campaigns"`
		Geography   []string `json:"geography"`
		Motivations []string `json:"motivations"`
	} `json:"attribution"`
	
	Context struct {
		Sources      []string               `json:"sources"`
		Collections  []string               `json:"collections"`
		Tags         []string               `json:"tags"`
		Severity     string                 `json:"severity"`
		Status       string                 `json:"status"`
		CustomFields map[string]interface{} `json:"custom_fields"`
	} `json:"context"`
	
	TechnicalDetails struct {
		Hash         string                 `json:"hash"`
		FileSize     int64                  `json:"file_size"`
		FileType     string                 `json:"file_type"`
		Protocol     string                 `json:"protocol"`
		Port         int                    `json:"port"`
		Path         string                 `json:"path"`
		UserAgent    string                 `json:"user_agent"`
		Headers      map[string]string      `json:"headers"`
		Payload      string                 `json:"payload"`
		ExtraData    map[string]interface{} `json:"extra_data"`
	} `json:"technical_details"`
}

// NewFireEyeConnector creates a new FireEye connector
func NewFireEyeConnector(logger *zap.Logger, config *FireEyeConfig) (*FireEyeConnector, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("fireeye API key is required")
	}
	
	if config.BaseURL == "" {
		config.BaseURL = "https://api.isightpartners.com/v2.0"
	}
	
	// Set default feed collections
	if len(config.FeedCollections) == 0 {
		config.FeedCollections = []string{
			"malware",
			"apt",
			"botnet",
			"phishing",
			"vulnerability",
		}
	}
	
	// Set default threat types
	if len(config.ThreatTypes) == 0 {
		config.ThreatTypes = []string{
			"malware",
			"apt",
			"cybercrime",
			"hacktivism",
			"espionage",
		}
	}
	
	// Set default update interval
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 25 * time.Minute
	}
	
	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}
	
	// Initialize rate limiter (FireEye typically allows 1000 requests per hour)
	rateLimiter := &RateLimiter{
		requests:    make(chan struct{}, 30), // Burst capacity
		maxRequests: 30,                      // Requests per minute
	}
	rateLimiter.ticker = time.NewTicker(time.Minute)
	go rateLimiter.refillTokens()
	
	connector := &FireEyeConnector{
		logger:      logger.With(zap.String("component", "fireeye-connector")),
		config:      config,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
	}
	
	logger.Info("FireEye connector initialized",
		zap.String("base_url", config.BaseURL),
		zap.Strings("feed_collections", config.FeedCollections),
		zap.Strings("threat_types", config.ThreatTypes),
	)
	
	return connector, nil
}

// FetchLatestData retrieves the latest threat intelligence from FireEye
func (fec *FireEyeConnector) FetchLatestData(ctx context.Context) ([]RawIndicator, error) {
	var allIndicators []RawIndicator
	
	// Fetch indicators for each collection
	for _, collection := range fec.config.FeedCollections {
		indicators, err := fec.fetchCollection(ctx, collection)
		if err != nil {
			fec.logger.Error("Failed to fetch collection",
				zap.String("collection", collection),
				zap.Error(err),
			)
			continue // Continue with other collections
		}
		
		allIndicators = append(allIndicators, indicators...)
		
		fec.logger.Debug("Fetched indicators for collection",
			zap.String("collection", collection),
			zap.Int("count", len(indicators)),
		)
	}
	
	fec.lastFetchTime = time.Now()
	
	fec.logger.Info("FireEye data fetch completed",
		zap.Int("total_indicators", len(allIndicators)),
		zap.Strings("collections", fec.config.FeedCollections),
	)
	
	return allIndicators, nil
}

func (fec *FireEyeConnector) fetchCollection(ctx context.Context, collection string) ([]RawIndicator, error) {
	// Wait for rate limiting
	if err := fec.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}
	
	// Build request URL
	requestURL, err := fec.buildCollectionURL(collection)
	if err != nil {
		return nil, fmt.Errorf("failed to build request URL: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	req.Header.Set("X-Auth-Token", fec.config.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "iSECTECH-ThreatIntel/1.0")
	
	// Execute request
	resp, err := fec.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var feResponse FireEyeResponse
	if err := json.NewDecoder(resp.Body).Decode(&feResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Check for API success
	if !feResponse.Success {
		return nil, fmt.Errorf("API returned failure: %s", feResponse.Message)
	}
	
	// Convert to RawIndicator format
	indicators := make([]RawIndicator, 0, len(feResponse.Objects))
	for _, feIndicator := range feResponse.Objects {
		indicator, err := fec.convertToRawIndicator(feIndicator, collection)
		if err != nil {
			fec.logger.Warn("Failed to convert indicator",
				zap.String("indicator_id", feIndicator.ID),
				zap.Error(err),
			)
			continue
		}
		
		indicators = append(indicators, indicator)
	}
	
	return indicators, nil
}

func (fec *FireEyeConnector) buildCollectionURL(collection string) (string, error) {
	baseURL, err := url.Parse(fmt.Sprintf("%s/indicators", fec.config.BaseURL))
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	
	params := url.Values{}
	params.Set("limit", "500")
	params.Set("sort", "-last_modified")
	
	// Add time range filter
	if !fec.lastFetchTime.IsZero() {
		params.Set("since", fec.lastFetchTime.Format(time.RFC3339))
	} else {
		// Default to last 7 days
		params.Set("since", time.Now().Add(-7*24*time.Hour).Format(time.RFC3339))
	}
	
	// Add collection filter
	if collection != "" {
		params.Set("category", collection)
	}
	
	// Add threat type filter
	if len(fec.config.ThreatTypes) > 0 {
		params.Set("threat_type", strings.Join(fec.config.ThreatTypes, ","))
	}
	
	baseURL.RawQuery = params.Encode()
	return baseURL.String(), nil
}

func (fec *FireEyeConnector) convertToRawIndicator(feIndicator FireEyeIndicator, collection string) (RawIndicator, error) {
	// Map confidence score
	confidence := fec.mapConfidenceLevel(feIndicator.Confidence.Level, feIndicator.Confidence.Score)
	
	// Build tags
	tags := []string{
		"fireeye",
		collection,
		feIndicator.Category,
		feIndicator.Subcategory,
		feIndicator.ThreatType,
		feIndicator.Context.Severity,
	}
	tags = append(tags, feIndicator.Metadata.MalwareFamily...)
	tags = append(tags, feIndicator.Metadata.ThreatGroups...)
	tags = append(tags, feIndicator.Metadata.Campaigns...)
	tags = append(tags, feIndicator.Context.Tags...)
	
	// Build context information
	context := map[string]interface{}{
		"category":           feIndicator.Category,
		"subcategory":        feIndicator.Subcategory,
		"threat_type":        feIndicator.ThreatType,
		"confidence_level":   feIndicator.Confidence.Level,
		"confidence_score":   feIndicator.Confidence.Score,
		"confidence_reasons": feIndicator.Confidence.Reasons,
		"malware_family":     feIndicator.Metadata.MalwareFamily,
		"threat_groups":      feIndicator.Metadata.ThreatGroups,
		"industries":         feIndicator.Metadata.Industries,
		"countries":          feIndicator.Metadata.Countries,
		"campaigns":          feIndicator.Metadata.Campaigns,
		"techniques":         feIndicator.Metadata.Techniques,
		"tactics":            feIndicator.Metadata.Tactics,
		"cves":               feIndicator.Metadata.CVEs,
		"references":         feIndicator.Metadata.References,
		"attribution":        feIndicator.Attribution,
		"sources":            feIndicator.Context.Sources,
		"collections":        feIndicator.Context.Collections,
		"severity":           feIndicator.Context.Severity,
		"status":             feIndicator.Context.Status,
		"technical_details":  feIndicator.TechnicalDetails,
	}
	
	// Build metadata
	metadata := map[string]interface{}{
		"provider":           "fireeye",
		"indicator_id":       feIndicator.ID,
		"collection":         collection,
		"last_modified":      feIndicator.LastModified,
		"additional_info":    feIndicator.Metadata.AdditionalInfo,
		"custom_fields":      feIndicator.Context.CustomFields,
		"technical_details":  feIndicator.TechnicalDetails,
	}
	
	indicator := RawIndicator{
		Provider:   "fireeye",
		Type:       fec.mapIndicatorType(feIndicator.Type),
		Value:      feIndicator.Value,
		Confidence: confidence,
		Tags:       fec.deduplicateTags(tags),
		FirstSeen:  feIndicator.FirstSeen,
		LastSeen:   feIndicator.LastSeen,
		Context:    context,
		Metadata:   metadata,
	}
	
	return indicator, nil
}

func (fec *FireEyeConnector) mapConfidenceLevel(level string, score int) float64 {
	// Map FireEye confidence levels to numeric scale
	switch strings.ToLower(level) {
	case "high":
		return 0.9
	case "medium":
		return 0.7
	case "low":
		return 0.5
	case "very_high":
		return 0.95
	case "very_low":
		return 0.3
	default:
		// Use numeric score if available (0-100 scale)
		if score > 0 {
			confidence := float64(score) / 100.0
			if confidence > 1.0 {
				confidence = 1.0
			}
			return confidence
		}
		return 0.6 // Default to medium-low confidence
	}
}

func (fec *FireEyeConnector) mapIndicatorType(feType string) string {
	// Map FireEye indicator types to standard types
	mappings := map[string]string{
		"ip":               "ipv4-addr",
		"ipv4":             "ipv4-addr",
		"ipv6":             "ipv6-addr",
		"domain":           "domain-name",
		"hostname":         "domain-name",
		"url":              "url",
		"uri":              "url",
		"md5":              "file",
		"sha1":             "file",
		"sha256":           "file",
		"hash":             "file",
		"file_hash":        "file",
		"email":            "email-addr",
		"email_address":    "email-addr",
		"filename":         "file",
		"file_name":        "file",
		"file_path":        "file",
		"registry_key":     "windows-registry-key",
		"registry":         "windows-registry-key",
		"mutex":            "mutex",
		"process":          "process",
		"service":          "windows-service-name",
		"certificate":      "x509-certificate",
		"asn":              "autonomous-system",
		"user_agent":       "user-agent",
	}
	
	if mappedType, exists := mappings[strings.ToLower(feType)]; exists {
		return mappedType
	}
	
	return strings.ToLower(feType)
}

func (fec *FireEyeConnector) deduplicateTags(tags []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, tag := range tags {
		if tag != "" && !seen[tag] {
			seen[tag] = true
			result = append(result, strings.ToLower(tag))
		}
	}
	
	return result
}

// ValidateConfiguration validates the FireEye configuration
func (fec *FireEyeConnector) ValidateConfiguration() error {
	if fec.config.APIKey == "" {
		return fmt.Errorf("API key is required")
	}
	
	if fec.config.BaseURL == "" {
		return fmt.Errorf("base URL is required")
	}
	
	// Test API connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	testURL := fmt.Sprintf("%s/indicators?limit=1", fec.config.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}
	
	req.Header.Set("X-Auth-Token", fec.config.APIKey)
	req.Header.Set("Accept", "application/json")
	
	resp, err := fec.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("API connectivity test failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API authentication failed with status: %d", resp.StatusCode)
	}
	
	fec.logger.Info("FireEye configuration validated successfully")
	return nil
}

// GetProviderInfo returns information about the FireEye provider
func (fec *FireEyeConnector) GetProviderInfo() map[string]interface{} {
	return map[string]interface{}{
		"provider":           "fireeye",
		"base_url":           fec.config.BaseURL,
		"feed_collections":   fec.config.FeedCollections,
		"threat_types":       fec.config.ThreatTypes,
		"update_interval":    fec.config.UpdateInterval.String(),
		"last_fetch_time":    fec.lastFetchTime,
		"rate_limit":         "1000 requests/hour",
		"supported_types":    []string{"indicators", "malware", "threats", "campaigns"},
		"authentication":     "API Token",
	}
}

// Close closes the FireEye connector and cleans up resources
func (fec *FireEyeConnector) Close() error {
	fec.logger.Info("Closing FireEye connector")
	
	if fec.rateLimiter != nil && fec.rateLimiter.ticker != nil {
		fec.rateLimiter.ticker.Stop()
	}
	
	// Close HTTP client connections
	if transport, ok := fec.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	
	return nil
}