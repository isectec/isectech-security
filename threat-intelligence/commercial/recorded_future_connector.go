package commercial

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// RecordedFutureConnector integrates with Recorded Future threat intelligence API
type RecordedFutureConnector struct {
	logger     *zap.Logger
	config     *RecordedFutureConfig
	httpClient *http.Client
	
	// API state
	lastFetchTime time.Time
	rateLimiter   *RateLimiter
}

// RecordedFutureResponse represents the API response structure
type RecordedFutureResponse struct {
	Data struct {
		Results []RecordedFutureIndicator `json:"results"`
		Counts  struct {
			Returned int `json:"returned"`
			Total    int `json:"total"`
		} `json:"counts"`
	} `json:"data"`
	Timestamps struct {
		FirstAvailable string `json:"firstAvailable"`
		LastAvailable  string `json:"lastAvailable"`
	} `json:"timestamps"`
}

// RecordedFutureIndicator represents a threat indicator from Recorded Future
type RecordedFutureIndicator struct {
	Entity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"entity"`
	Risk struct {
		Score     int    `json:"score"`
		Level     string `json:"level"`
		CriticalityLabel string `json:"criticalityLabel"`
		Rules     []struct {
			Rule        string `json:"rule"`
			Description string `json:"description"`
			Count       int    `json:"count"`
			Criticality int    `json:"criticality"`
		} `json:"rules"`
	} `json:"risk"`
	Intelligence struct {
		FirstSeen string `json:"firstSeen"`
		LastSeen  string `json:"lastSeen"`
		Sources   []struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
		} `json:"sources"`
	} `json:"intelligence"`
	Context struct {
		ThreatTypes    []string               `json:"threatTypes"`
		ThreatActors   []string               `json:"threatActors"`
		Malware        []string               `json:"malware"`
		Industries     []string               `json:"industries"`
		Countries      []string               `json:"countries"`
		AdditionalInfo map[string]interface{} `json:"additionalInfo"`
	} `json:"context"`
	Metadata struct {
		Tags       []string  `json:"tags"`
		Confidence float64   `json:"confidence"`
		TTPs       []string  `json:"ttps"`
		UpdatedAt  time.Time `json:"updatedAt"`
	} `json:"metadata"`
}

// RateLimiter implements rate limiting for API calls
type RateLimiter struct {
	requests    chan struct{}
	ticker      *time.Ticker
	maxRequests int
}

// NewRecordedFutureConnector creates a new Recorded Future connector
func NewRecordedFutureConnector(logger *zap.Logger, config *RecordedFutureConfig) (*RecordedFutureConnector, error) {
	if config.APIToken == "" {
		return nil, fmt.Errorf("recorded future API token is required")
	}
	
	if config.BaseURL == "" {
		config.BaseURL = "https://api.recordedfuture.com/v2"
	}
	
	// Set default feed types
	if len(config.FeedTypes) == 0 {
		config.FeedTypes = []string{"ip", "domain", "hash", "url", "vulnerability"}
	}
	
	// Set default update interval
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 15 * time.Minute
	}
	
	// Set default risk threshold
	if config.RiskThreshold == 0 {
		config.RiskThreshold = 70 // Medium-high risk threshold
	}
	
	// Create HTTP client with appropriate timeouts
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}
	
	// Initialize rate limiter (Recorded Future allows 10,000 requests per day)
	rateLimiter := &RateLimiter{
		requests:    make(chan struct{}, 100), // Burst capacity
		maxRequests: 100,                      // Requests per minute
	}
	rateLimiter.ticker = time.NewTicker(time.Minute)
	go rateLimiter.refillTokens()
	
	connector := &RecordedFutureConnector{
		logger:      logger.With(zap.String("component", "recorded-future-connector")),
		config:      config,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
	}
	
	logger.Info("Recorded Future connector initialized",
		zap.String("base_url", config.BaseURL),
		zap.Strings("feed_types", config.FeedTypes),
		zap.Int("risk_threshold", config.RiskThreshold),
	)
	
	return connector, nil
}

func (r *RateLimiter) refillTokens() {
	for range r.ticker.C {
		// Refill the rate limiter tokens
		for i := 0; i < r.maxRequests; i++ {
			select {
			case r.requests <- struct{}{}:
			default:
				// Channel is full, stop refilling
				break
			}
		}
	}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-r.requests:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FetchLatestData retrieves the latest threat intelligence from Recorded Future
func (rfc *RecordedFutureConnector) FetchLatestData(ctx context.Context) ([]RawIndicator, error) {
	var allIndicators []RawIndicator
	
	// Fetch data for each configured feed type
	for _, feedType := range rfc.config.FeedTypes {
		indicators, err := rfc.fetchFeedType(ctx, feedType)
		if err != nil {
			rfc.logger.Error("Failed to fetch feed type",
				zap.String("feed_type", feedType),
				zap.Error(err),
			)
			continue // Continue with other feed types
		}
		
		allIndicators = append(allIndicators, indicators...)
		
		rfc.logger.Debug("Fetched indicators for feed type",
			zap.String("feed_type", feedType),
			zap.Int("count", len(indicators)),
		)
	}
	
	rfc.lastFetchTime = time.Now()
	
	rfc.logger.Info("Recorded Future data fetch completed",
		zap.Int("total_indicators", len(allIndicators)),
		zap.Strings("feed_types", rfc.config.FeedTypes),
	)
	
	return allIndicators, nil
}

func (rfc *RecordedFutureConnector) fetchFeedType(ctx context.Context, feedType string) ([]RawIndicator, error) {
	// Wait for rate limiting
	if err := rfc.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}
	
	// Build request URL
	requestURL, err := rfc.buildRequestURL(feedType)
	if err != nil {
		return nil, fmt.Errorf("failed to build request URL: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	req.Header.Set("X-RFToken", rfc.config.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "iSECTECH-ThreatIntel/1.0")
	
	// Execute request
	resp, err := rfc.httpClient.Do(req)
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
	var rfResponse RecordedFutureResponse
	if err := json.NewDecoder(resp.Body).Decode(&rfResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Convert to RawIndicator format
	indicators := make([]RawIndicator, 0, len(rfResponse.Data.Results))
	for _, rfIndicator := range rfResponse.Data.Results {
		indicator, err := rfc.convertToRawIndicator(rfIndicator, feedType)
		if err != nil {
			rfc.logger.Warn("Failed to convert indicator",
				zap.String("entity_id", rfIndicator.Entity.ID),
				zap.Error(err),
			)
			continue
		}
		
		// Apply risk threshold filter
		if rfIndicator.Risk.Score >= rfc.config.RiskThreshold {
			indicators = append(indicators, indicator)
		}
	}
	
	return indicators, nil
}

func (rfc *RecordedFutureConnector) buildRequestURL(feedType string) (string, error) {
	baseURL, err := url.Parse(fmt.Sprintf("%s/%s/risklist", rfc.config.BaseURL, feedType))
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	
	params := url.Values{}
	params.Set("format", "json")
	params.Set("gzip", "false")
	
	// Add time range filter (last 24 hours by default)
	if !rfc.lastFetchTime.IsZero() {
		params.Set("from", rfc.lastFetchTime.Format(time.RFC3339))
	} else {
		params.Set("from", time.Now().Add(-24*time.Hour).Format(time.RFC3339))
	}
	
	// Add risk threshold
	params.Set("minRisk", strconv.Itoa(rfc.config.RiskThreshold))
	
	// Add custom query parameters if configured
	if customQuery, exists := rfc.config.CustomQueries[feedType]; exists {
		params.Set("list", customQuery)
	}
	
	baseURL.RawQuery = params.Encode()
	return baseURL.String(), nil
}

func (rfc *RecordedFutureConnector) convertToRawIndicator(rfIndicator RecordedFutureIndicator, feedType string) (RawIndicator, error) {
	// Parse timestamps
	firstSeen, err := time.Parse(time.RFC3339, rfIndicator.Intelligence.FirstSeen)
	if err != nil {
		firstSeen = time.Now().Add(-24 * time.Hour) // Default to 24 hours ago
	}
	
	lastSeen, err := time.Parse(time.RFC3339, rfIndicator.Intelligence.LastSeen)
	if err != nil {
		lastSeen = time.Now() // Default to now
	}
	
	// Calculate confidence score (convert RF risk score to 0-1 scale)
	confidence := float64(rfIndicator.Risk.Score) / 100.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	// Build tags from various RF fields
	tags := []string{
		"recorded_future",
		feedType,
		rfIndicator.Risk.Level,
		rfIndicator.Risk.CriticalityLabel,
	}
	tags = append(tags, rfIndicator.Context.ThreatTypes...)
	tags = append(tags, rfIndicator.Metadata.Tags...)
	
	// Build context information
	context := map[string]interface{}{
		"risk_score":       rfIndicator.Risk.Score,
		"risk_level":       rfIndicator.Risk.Level,
		"criticality":      rfIndicator.Risk.CriticalityLabel,
		"threat_types":     rfIndicator.Context.ThreatTypes,
		"threat_actors":    rfIndicator.Context.ThreatActors,
		"malware":          rfIndicator.Context.Malware,
		"industries":       rfIndicator.Context.Industries,
		"countries":        rfIndicator.Context.Countries,
		"risk_rules":       rfIndicator.Risk.Rules,
		"sources":          rfIndicator.Intelligence.Sources,
		"ttps":             rfIndicator.Metadata.TTPs,
	}
	
	// Build metadata
	metadata := map[string]interface{}{
		"provider":         "recorded_future",
		"entity_id":        rfIndicator.Entity.ID,
		"entity_type":      rfIndicator.Entity.Type,
		"feed_type":        feedType,
		"updated_at":       rfIndicator.Metadata.UpdatedAt,
		"additional_info":  rfIndicator.Context.AdditionalInfo,
	}
	
	indicator := RawIndicator{
		Provider:   "recorded_future",
		Type:       rfc.mapIndicatorType(feedType, rfIndicator.Entity.Type),
		Value:      rfIndicator.Entity.Name,
		Confidence: confidence,
		Tags:       rfc.deduplicateTags(tags),
		FirstSeen:  firstSeen,
		LastSeen:   lastSeen,
		Context:    context,
		Metadata:   metadata,
	}
	
	return indicator, nil
}

func (rfc *RecordedFutureConnector) mapIndicatorType(feedType, entityType string) string {
	// Map Recorded Future entity types to standard indicator types
	mappings := map[string]map[string]string{
		"ip": {
			"IpAddress": "ipv4-addr",
		},
		"domain": {
			"InternetDomainName": "domain-name",
		},
		"hash": {
			"Hash": "file",
		},
		"url": {
			"URL": "url",
		},
		"vulnerability": {
			"CyberVulnerability": "vulnerability",
		},
	}
	
	if typeMap, exists := mappings[feedType]; exists {
		if mappedType, exists := typeMap[entityType]; exists {
			return mappedType
		}
	}
	
	// Default fallback
	return strings.ToLower(feedType)
}

func (rfc *RecordedFutureConnector) deduplicateTags(tags []string) []string {
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

// ValidateConfiguration validates the Recorded Future configuration
func (rfc *RecordedFutureConnector) ValidateConfiguration() error {
	if rfc.config.APIToken == "" {
		return fmt.Errorf("API token is required")
	}
	
	if rfc.config.BaseURL == "" {
		return fmt.Errorf("base URL is required")
	}
	
	// Test API connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	testURL := fmt.Sprintf("%s/info/whoami", rfc.config.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}
	
	req.Header.Set("X-RFToken", rfc.config.APIToken)
	
	resp, err := rfc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("API connectivity test failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API authentication failed with status: %d", resp.StatusCode)
	}
	
	rfc.logger.Info("Recorded Future configuration validated successfully")
	return nil
}

// GetProviderInfo returns information about the Recorded Future provider
func (rfc *RecordedFutureConnector) GetProviderInfo() map[string]interface{} {
	return map[string]interface{}{
		"provider":          "recorded_future",
		"base_url":          rfc.config.BaseURL,
		"feed_types":        rfc.config.FeedTypes,
		"update_interval":   rfc.config.UpdateInterval.String(),
		"risk_threshold":    rfc.config.RiskThreshold,
		"last_fetch_time":   rfc.lastFetchTime,
		"rate_limit":        "10,000 requests/day",
		"supported_types":   []string{"ip", "domain", "hash", "url", "vulnerability"},
	}
}

// Close closes the Recorded Future connector and cleans up resources
func (rfc *RecordedFutureConnector) Close() error {
	rfc.logger.Info("Closing Recorded Future connector")
	
	if rfc.rateLimiter != nil && rfc.rateLimiter.ticker != nil {
		rfc.rateLimiter.ticker.Stop()
	}
	
	// Close HTTP client connections
	if transport, ok := rfc.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	
	return nil
}