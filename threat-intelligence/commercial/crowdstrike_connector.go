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

// CrowdStrikeConnector integrates with CrowdStrike Falcon Intelligence API
type CrowdStrikeConnector struct {
	logger     *zap.Logger
	config     *CrowdStrikeConfig
	httpClient *http.Client
	
	// API state
	accessToken   string
	tokenExpiry   time.Time
	lastFetchTime time.Time
	rateLimiter   *RateLimiter
}

// CrowdStrikeTokenResponse represents the OAuth2 token response
type CrowdStrikeTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// CrowdStrikeIndicatorsResponse represents the indicators API response
type CrowdStrikeIndicatorsResponse struct {
	Meta struct {
		QueryTime   float64 `json:"query_time"`
		PoweredBy   string  `json:"powered_by"`
		TraceID     string  `json:"trace_id"`
	} `json:"meta"`
	Resources []CrowdStrikeIndicator `json:"resources"`
	Errors    []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// CrowdStrikeIndicator represents a threat indicator from CrowdStrike
type CrowdStrikeIndicator struct {
	ID          string    `json:"id"`
	Indicator   string    `json:"indicator"`
	Type        string    `json:"type"`
	Deleted     bool      `json:"deleted"`
	Published   bool      `json:"published"`
	CreatedOn   time.Time `json:"created_on"`
	LastUpdated time.Time `json:"last_updated"`
	
	Metadata struct {
		MalwareFamily  []string `json:"malware_family"`
		ThreatTypes    []string `json:"threat_types"`
		Actors         []string `json:"actors"`
		Campaigns      []string `json:"campaigns"`
		Regions        []string `json:"regions"`
		Targets        []string `json:"targets"`
		VulnTag        []string `json:"vuln_tag"`
	} `json:"metadata"`
	
	Relations []struct {
		Indicator   string `json:"indicator"`
		Type        string `json:"type"`
		CreatedDate string `json:"created_date"`
	} `json:"relations"`
	
	Labels []struct {
		Name            string    `json:"name"`
		CreatedOn       time.Time `json:"created_on"`
		LastValidOn     time.Time `json:"last_valid_on"`
		FirstPublished  time.Time `json:"first_published"`
		FirstIntel      time.Time `json:"first_intel"`
		LastIntel       time.Time `json:"last_intel"`
	} `json:"labels"`
	
	MaliciousConfidence string `json:"malicious_confidence"`
	Reports             []string `json:"_marker_reports"`
}

// NewCrowdStrikeConnector creates a new CrowdStrike connector
func NewCrowdStrikeConnector(logger *zap.Logger, config *CrowdStrikeConfig) (*CrowdStrikeConnector, error) {
	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("crowdstrike client ID and secret are required")
	}
	
	if config.BaseURL == "" {
		config.BaseURL = "https://api.crowdstrike.com"
	}
	
	// Set default feed categories
	if len(config.FeedCategories) == 0 {
		config.FeedCategories = []string{
			"malicious_confidence_high",
			"malicious_confidence_medium",
			"suspicious",
		}
	}
	
	// Set default confidence level
	if config.ConfidenceLevel == 0 {
		config.ConfidenceLevel = 70
	}
	
	// Set default update interval
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 20 * time.Minute
	}
	
	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}
	
	// Initialize rate limiter (CrowdStrike allows 5000 requests per hour)
	rateLimiter := &RateLimiter{
		requests:    make(chan struct{}, 100), // Burst capacity
		maxRequests: 100,                      // Requests per minute
	}
	rateLimiter.ticker = time.NewTicker(time.Minute)
	go rateLimiter.refillTokens()
	
	connector := &CrowdStrikeConnector{
		logger:      logger.With(zap.String("component", "crowdstrike-connector")),
		config:      config,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
	}
	
	// Authenticate and get initial access token
	if err := connector.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with CrowdStrike: %w", err)
	}
	
	logger.Info("CrowdStrike connector initialized",
		zap.String("base_url", config.BaseURL),
		zap.Strings("feed_categories", config.FeedCategories),
		zap.Int("confidence_level", config.ConfidenceLevel),
	)
	
	return connector, nil
}

func (csc *CrowdStrikeConnector) authenticate() error {
	// Wait for rate limiting
	ctx := context.Background()
	if err := csc.rateLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limiter error: %w", err)
	}
	
	// Prepare OAuth2 request
	tokenURL := fmt.Sprintf("%s/oauth2/token", csc.config.BaseURL)
	
	data := url.Values{}
	data.Set("client_id", csc.config.ClientID)
	data.Set("client_secret", csc.config.ClientSecret)
	
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create authentication request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "iSECTECH-ThreatIntel/1.0")
	
	// Execute request
	resp, err := csc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse token response
	var tokenResp CrowdStrikeTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}
	
	// Store token information
	csc.accessToken = tokenResp.AccessToken
	csc.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	
	csc.logger.Info("CrowdStrike authentication successful",
		zap.Time("token_expiry", csc.tokenExpiry))
	
	return nil
}

func (csc *CrowdStrikeConnector) ensureAuthenticated() error {
	// Check if token is expired or will expire soon (5 minutes buffer)
	if time.Now().Add(5*time.Minute).After(csc.tokenExpiry) {
		csc.logger.Info("Access token expired or expiring soon, refreshing")
		return csc.authenticate()
	}
	return nil
}

// FetchLatestData retrieves the latest threat intelligence from CrowdStrike
func (csc *CrowdStrikeConnector) FetchLatestData(ctx context.Context) ([]RawIndicator, error) {
	// Ensure we have a valid access token
	if err := csc.ensureAuthenticated(); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}
	
	var allIndicators []RawIndicator
	
	// Fetch indicators for each category
	for _, category := range csc.config.FeedCategories {
		indicators, err := csc.fetchIndicatorsByCategory(ctx, category)
		if err != nil {
			csc.logger.Error("Failed to fetch indicators for category",
				zap.String("category", category),
				zap.Error(err),
			)
			continue // Continue with other categories
		}
		
		allIndicators = append(allIndicators, indicators...)
		
		csc.logger.Debug("Fetched indicators for category",
			zap.String("category", category),
			zap.Int("count", len(indicators)),
		)
	}
	
	csc.lastFetchTime = time.Now()
	
	csc.logger.Info("CrowdStrike data fetch completed",
		zap.Int("total_indicators", len(allIndicators)),
		zap.Strings("categories", csc.config.FeedCategories),
	)
	
	return allIndicators, nil
}

func (csc *CrowdStrikeConnector) fetchIndicatorsByCategory(ctx context.Context, category string) ([]RawIndicator, error) {
	// Wait for rate limiting
	if err := csc.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}
	
	// Build request URL
	requestURL, err := csc.buildIndicatorsURL(category)
	if err != nil {
		return nil, fmt.Errorf("failed to build request URL: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Authorization", "Bearer "+csc.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "iSECTECH-ThreatIntel/1.0")
	
	// Execute request
	resp, err := csc.httpClient.Do(req)
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
	var csResponse CrowdStrikeIndicatorsResponse
	if err := json.NewDecoder(resp.Body).Decode(&csResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Check for API errors
	if len(csResponse.Errors) > 0 {
		return nil, fmt.Errorf("API returned errors: %v", csResponse.Errors)
	}
	
	// Convert to RawIndicator format
	indicators := make([]RawIndicator, 0, len(csResponse.Resources))
	for _, csIndicator := range csResponse.Resources {
		// Skip deleted indicators
		if csIndicator.Deleted {
			continue
		}
		
		indicator, err := csc.convertToRawIndicator(csIndicator, category)
		if err != nil {
			csc.logger.Warn("Failed to convert indicator",
				zap.String("indicator_id", csIndicator.ID),
				zap.Error(err),
			)
			continue
		}
		
		indicators = append(indicators, indicator)
	}
	
	return indicators, nil
}

func (csc *CrowdStrikeConnector) buildIndicatorsURL(category string) (string, error) {
	baseURL, err := url.Parse(fmt.Sprintf("%s/intel/entities/indicators/v1", csc.config.BaseURL))
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	
	params := url.Values{}
	params.Set("limit", "1000")
	params.Set("sort", "last_updated|desc")
	
	// Add time range filter
	if !csc.lastFetchTime.IsZero() {
		params.Set("filter", fmt.Sprintf("last_updated:>%d", csc.lastFetchTime.Unix()))
	} else {
		// Default to last 24 hours
		params.Set("filter", fmt.Sprintf("last_updated:>%d", time.Now().Add(-24*time.Hour).Unix()))
	}
	
	// Add category filter
	if category != "" {
		existingFilter := params.Get("filter")
		if existingFilter != "" {
			params.Set("filter", fmt.Sprintf("%s+labels:\"%s\"", existingFilter, category))
		} else {
			params.Set("filter", fmt.Sprintf("labels:\"%s\"", category))
		}
	}
	
	baseURL.RawQuery = params.Encode()
	return baseURL.String(), nil
}

func (csc *CrowdStrikeConnector) convertToRawIndicator(csIndicator CrowdStrikeIndicator, category string) (RawIndicator, error) {
	// Map confidence level
	confidence := csc.mapConfidenceLevel(csIndicator.MaliciousConfidence)
	
	// Build tags
	tags := []string{
		"crowdstrike",
		category,
		csIndicator.MaliciousConfidence,
	}
	tags = append(tags, csIndicator.Metadata.MalwareFamily...)
	tags = append(tags, csIndicator.Metadata.ThreatTypes...)
	tags = append(tags, csIndicator.Metadata.Actors...)
	tags = append(tags, csIndicator.Metadata.Campaigns...)
	
	// Build context information
	context := map[string]interface{}{
		"malware_family":       csIndicator.Metadata.MalwareFamily,
		"threat_types":         csIndicator.Metadata.ThreatTypes,
		"actors":               csIndicator.Metadata.Actors,
		"campaigns":            csIndicator.Metadata.Campaigns,
		"regions":              csIndicator.Metadata.Regions,
		"targets":              csIndicator.Metadata.Targets,
		"vuln_tags":            csIndicator.Metadata.VulnTag,
		"relations":            csIndicator.Relations,
		"labels":               csIndicator.Labels,
		"malicious_confidence": csIndicator.MaliciousConfidence,
		"published":            csIndicator.Published,
		"reports":              csIndicator.Reports,
	}
	
	// Build metadata
	metadata := map[string]interface{}{
		"provider":         "crowdstrike",
		"indicator_id":     csIndicator.ID,
		"category":         category,
		"deleted":          csIndicator.Deleted,
		"published":        csIndicator.Published,
		"created_on":       csIndicator.CreatedOn,
		"last_updated":     csIndicator.LastUpdated,
	}
	
	indicator := RawIndicator{
		Provider:   "crowdstrike",
		Type:       csc.mapIndicatorType(csIndicator.Type),
		Value:      csIndicator.Indicator,
		Confidence: confidence,
		Tags:       csc.deduplicateTags(tags),
		FirstSeen:  csIndicator.CreatedOn,
		LastSeen:   csIndicator.LastUpdated,
		Context:    context,
		Metadata:   metadata,
	}
	
	return indicator, nil
}

func (csc *CrowdStrikeConnector) mapConfidenceLevel(confidenceStr string) float64 {
	// Map CrowdStrike confidence levels to numeric scale
	switch strings.ToLower(confidenceStr) {
	case "high":
		return 0.9
	case "medium":
		return 0.7
	case "low":
		return 0.5
	case "suspicious":
		return 0.6
	case "unverified":
		return 0.3
	default:
		return 0.5 // Default to medium confidence
	}
}

func (csc *CrowdStrikeConnector) mapIndicatorType(csType string) string {
	// Map CrowdStrike indicator types to standard types
	mappings := map[string]string{
		"ip_address":      "ipv4-addr",
		"ipv6_address":    "ipv6-addr",
		"domain":          "domain-name",
		"url":             "url",
		"md5":             "file",
		"sha1":            "file",
		"sha256":          "file",
		"email_address":   "email-addr",
		"registry_key":    "windows-registry-key",
		"service_name":    "windows-service-name",
		"file_name":       "file",
		"file_path":       "file",
		"mutex_name":      "mutex",
		"process_name":    "process",
	}
	
	if mappedType, exists := mappings[strings.ToLower(csType)]; exists {
		return mappedType
	}
	
	return strings.ToLower(csType)
}

func (csc *CrowdStrikeConnector) deduplicateTags(tags []string) []string {
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

// ValidateConfiguration validates the CrowdStrike configuration
func (csc *CrowdStrikeConnector) ValidateConfiguration() error {
	if csc.config.ClientID == "" || csc.config.ClientSecret == "" {
		return fmt.Errorf("client ID and secret are required")
	}
	
	// Test authentication
	if err := csc.authenticate(); err != nil {
		return fmt.Errorf("authentication test failed: %w", err)
	}
	
	csc.logger.Info("CrowdStrike configuration validated successfully")
	return nil
}

// GetProviderInfo returns information about the CrowdStrike provider
func (csc *CrowdStrikeConnector) GetProviderInfo() map[string]interface{} {
	return map[string]interface{}{
		"provider":           "crowdstrike",
		"base_url":           csc.config.BaseURL,
		"feed_categories":    csc.config.FeedCategories,
		"confidence_level":   csc.config.ConfidenceLevel,
		"update_interval":    csc.config.UpdateInterval.String(),
		"last_fetch_time":    csc.lastFetchTime,
		"token_expiry":       csc.tokenExpiry,
		"rate_limit":         "5000 requests/hour",
		"supported_types":    []string{"indicators", "actors", "reports", "campaigns"},
		"authentication":     "OAuth2",
	}
}

// Close closes the CrowdStrike connector and cleans up resources
func (csc *CrowdStrikeConnector) Close() error {
	csc.logger.Info("Closing CrowdStrike connector")
	
	if csc.rateLimiter != nil && csc.rateLimiter.ticker != nil {
		csc.rateLimiter.ticker.Stop()
	}
	
	// Close HTTP client connections
	if transport, ok := csc.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	
	return nil
}