package commercial

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DigitalShadowsConnector integrates with Digital Shadows SearchLight API
type DigitalShadowsConnector struct {
	logger     *zap.Logger
	config     *DigitalShadowsConfig
	httpClient *http.Client
	
	// API state
	lastFetchTime time.Time
	rateLimiter   *RateLimiter
}

// DigitalShadowsResponse represents the API response structure
type DigitalShadowsResponse struct {
	Data struct {
		Incidents []DigitalShadowsIncident `json:"incidents"`
		IoCs      []DigitalShadowsIoC      `json:"iocs"`
	} `json:"data"`
	Meta struct {
		Total  int `json:"total"`
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	} `json:"meta"`
	Links struct {
		Next     string `json:"next"`
		Previous string `json:"previous"`
	} `json:"links"`
}

// DigitalShadowsIncident represents a security incident from Digital Shadows
type DigitalShadowsIncident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	Type        string    `json:"type"`
	Subtype     string    `json:"subtype"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	
	ThreatLevel struct {
		Level       string  `json:"level"`
		Score       int     `json:"score"`
		Confidence  float64 `json:"confidence"`
	} `json:"threatLevel"`
	
	Attribution struct {
		ThreatActors []string `json:"threatActors"`
		Campaigns    []string `json:"campaigns"`
		Geography    []string `json:"geography"`
	} `json:"attribution"`
	
	TechnicalDetails struct {
		IoCs         []string               `json:"iocs"`
		TTPs         []string               `json:"ttps"`
		MITRE        []string               `json:"mitre"`
		Indicators   []DigitalShadowsIoC    `json:"indicators"`
		Context      map[string]interface{} `json:"context"`
	} `json:"technicalDetails"`
	
	Intelligence struct {
		Sources     []string  `json:"sources"`
		Tags        []string  `json:"tags"`
		Industries  []string  `json:"industries"`
		Countries   []string  `json:"countries"`
		FirstSeen   time.Time `json:"firstSeen"`
		LastSeen    time.Time `json:"lastSeen"`
	} `json:"intelligence"`
	
	Metadata struct {
		PortalURL    string                 `json:"portalUrl"`
		Attachments  []string               `json:"attachments"`
		References   []string               `json:"references"`
		CustomFields map[string]interface{} `json:"customFields"`
	} `json:"metadata"`
}

// DigitalShadowsIoC represents an Indicator of Compromise
type DigitalShadowsIoC struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Confidence float64   `json:"confidence"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	
	Context struct {
		ThreatTypes   []string               `json:"threatTypes"`
		Malware       []string               `json:"malware"`
		ThreatActors  []string               `json:"threatActors"`
		Sources       []string               `json:"sources"`
		Tags          []string               `json:"tags"`
		AdditionalInfo map[string]interface{} `json:"additionalInfo"`
	} `json:"context"`
	
	Risk struct {
		Score  int    `json:"score"`
		Level  string `json:"level"`
		Reason string `json:"reason"`
	} `json:"risk"`
	
	Metadata struct {
		IncidentIDs   []string               `json:"incidentIds"`
		Categories    []string               `json:"categories"`
		LastModified  time.Time              `json:"lastModified"`
		CustomData    map[string]interface{} `json:"customData"`
	} `json:"metadata"`
}

// NewDigitalShadowsConnector creates a new Digital Shadows connector
func NewDigitalShadowsConnector(logger *zap.Logger, config *DigitalShadowsConfig) (*DigitalShadowsConnector, error) {
	if config.APIKey == "" || config.APISecret == "" {
		return nil, fmt.Errorf("digital shadows API key and secret are required")
	}
	
	if config.BaseURL == "" {
		config.BaseURL = "https://api.searchlight.reliaquest.com/v2"
	}
	
	// Set default incident types
	if len(config.IncidentTypes) == 0 {
		config.IncidentTypes = []string{
			"malware", "phishing", "data_breach", "credential_compromise",
			"botnet", "apt", "ransomware", "ddos", "typosquatting",
		}
	}
	
	// Set default severity filter
	if len(config.SeverityFilter) == 0 {
		config.SeverityFilter = []string{"high", "very_high", "critical"}
	}
	
	// Set default update interval
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 30 * time.Minute
	}
	
	// Create HTTP client with appropriate timeouts
	httpClient := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}
	
	// Initialize rate limiter (Digital Shadows typically allows 1000 requests per hour)
	rateLimiter := &RateLimiter{
		requests:    make(chan struct{}, 50), // Burst capacity
		maxRequests: 50,                      // Requests per minute
	}
	rateLimiter.ticker = time.NewTicker(time.Minute)
	go rateLimiter.refillTokens()
	
	connector := &DigitalShadowsConnector{
		logger:      logger.With(zap.String("component", "digital-shadows-connector")),
		config:      config,
		httpClient:  httpClient,
		rateLimiter: rateLimiter,
	}
	
	logger.Info("Digital Shadows connector initialized",
		zap.String("base_url", config.BaseURL),
		zap.Strings("incident_types", config.IncidentTypes),
		zap.Strings("severity_filter", config.SeverityFilter),
	)
	
	return connector, nil
}

// FetchLatestData retrieves the latest threat intelligence from Digital Shadows
func (dsc *DigitalShadowsConnector) FetchLatestData(ctx context.Context) ([]RawIndicator, error) {
	var allIndicators []RawIndicator
	
	// Fetch incidents and extract IoCs
	incidents, err := dsc.fetchIncidents(ctx)
	if err != nil {
		dsc.logger.Error("Failed to fetch incidents", zap.Error(err))
		return nil, fmt.Errorf("failed to fetch incidents: %w", err)
	}
	
	// Convert incidents to indicators
	for _, incident := range incidents {
		indicators := dsc.extractIndicatorsFromIncident(incident)
		allIndicators = append(allIndicators, indicators...)
	}
	
	// Fetch IoCs directly
	iocs, err := dsc.fetchIoCs(ctx)
	if err != nil {
		dsc.logger.Warn("Failed to fetch IoCs directly", zap.Error(err))
		// Don't fail completely, continue with incident-derived indicators
	} else {
		// Convert IoCs to indicators
		for _, ioc := range iocs {
			indicator := dsc.convertIoCToRawIndicator(ioc)
			allIndicators = append(allIndicators, indicator)
		}
	}
	
	dsc.lastFetchTime = time.Now()
	
	dsc.logger.Info("Digital Shadows data fetch completed",
		zap.Int("total_indicators", len(allIndicators)),
		zap.Int("incidents_processed", len(incidents)),
		zap.Int("direct_iocs", len(iocs)),
	)
	
	return allIndicators, nil
}

func (dsc *DigitalShadowsConnector) fetchIncidents(ctx context.Context) ([]DigitalShadowsIncident, error) {
	// Wait for rate limiting
	if err := dsc.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}
	
	// Build request URL for incidents
	requestURL, err := dsc.buildIncidentsURL()
	if err != nil {
		return nil, fmt.Errorf("failed to build incidents URL: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set authentication headers
	if err := dsc.setAuthHeaders(req, "GET", requestURL); err != nil {
		return nil, fmt.Errorf("failed to set auth headers: %w", err)
	}
	
	// Execute request
	resp, err := dsc.httpClient.Do(req)
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
	var dsResponse DigitalShadowsResponse
	if err := json.NewDecoder(resp.Body).Decode(&dsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return dsResponse.Data.Incidents, nil
}

func (dsc *DigitalShadowsConnector) fetchIoCs(ctx context.Context) ([]DigitalShadowsIoC, error) {
	// Wait for rate limiting
	if err := dsc.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}
	
	// Build request URL for IoCs
	requestURL, err := dsc.buildIoCsURL()
	if err != nil {
		return nil, fmt.Errorf("failed to build IoCs URL: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Set authentication headers
	if err := dsc.setAuthHeaders(req, "GET", requestURL); err != nil {
		return nil, fmt.Errorf("failed to set auth headers: %w", err)
	}
	
	// Execute request
	resp, err := dsc.httpClient.Do(req)
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
	var dsResponse DigitalShadowsResponse
	if err := json.NewDecoder(resp.Body).Decode(&dsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return dsResponse.Data.IoCs, nil
}

func (dsc *DigitalShadowsConnector) buildIncidentsURL() (string, error) {
	baseURL, err := url.Parse(fmt.Sprintf("%s/incidents", dsc.config.BaseURL))
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	
	params := url.Values{}
	params.Set("limit", "100")
	params.Set("sort", "-modified")
	
	// Add time range filter
	if !dsc.lastFetchTime.IsZero() {
		params.Set("modified__gte", dsc.lastFetchTime.Format(time.RFC3339))
	} else {
		params.Set("modified__gte", time.Now().Add(-24*time.Hour).Format(time.RFC3339))
	}
	
	// Add incident type filter
	if len(dsc.config.IncidentTypes) > 0 {
		params.Set("type__in", strings.Join(dsc.config.IncidentTypes, ","))
	}
	
	// Add severity filter
	if len(dsc.config.SeverityFilter) > 0 {
		params.Set("severity__in", strings.Join(dsc.config.SeverityFilter, ","))
	}
	
	baseURL.RawQuery = params.Encode()
	return baseURL.String(), nil
}

func (dsc *DigitalShadowsConnector) buildIoCsURL() (string, error) {
	baseURL, err := url.Parse(fmt.Sprintf("%s/iocs", dsc.config.BaseURL))
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	
	params := url.Values{}
	params.Set("limit", "500")
	params.Set("sort", "-lastSeen")
	
	// Add time range filter
	if !dsc.lastFetchTime.IsZero() {
		params.Set("lastSeen__gte", dsc.lastFetchTime.Format(time.RFC3339))
	} else {
		params.Set("lastSeen__gte", time.Now().Add(-7*24*time.Hour).Format(time.RFC3339)) // Last 7 days for IoCs
	}
	
	// Add minimum confidence filter
	params.Set("confidence__gte", "0.7")
	
	baseURL.RawQuery = params.Encode()
	return baseURL.String(), nil
}

func (dsc *DigitalShadowsConnector) setAuthHeaders(req *http.Request, method, requestURL string) error {
	// Digital Shadows uses HMAC-SHA256 authentication
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	
	// Parse URL to get path and query
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	
	// Create signature string
	signatureString := fmt.Sprintf("%s\n%s\n%s\n%s", 
		method, 
		parsedURL.Path, 
		parsedURL.RawQuery, 
		timestamp)
	
	// Create signature
	h := hmac.New(sha256.New, []byte(dsc.config.APISecret))
	h.Write([]byte(signatureString))
	signature := hex.EncodeToString(h.Sum(nil))
	
	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("DS %s:%s", dsc.config.APIKey, signature))
	req.Header.Set("Date", timestamp)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "iSECTECH-ThreatIntel/1.0")
	
	return nil
}

func (dsc *DigitalShadowsConnector) extractIndicatorsFromIncident(incident DigitalShadowsIncident) []RawIndicator {
	var indicators []RawIndicator
	
	// Extract indicators from technical details
	for _, ioc := range incident.TechnicalDetails.Indicators {
		indicator := dsc.convertIoCToRawIndicator(ioc)
		
		// Enrich with incident context
		indicator.Context["incident_id"] = incident.ID
		indicator.Context["incident_title"] = incident.Title
		indicator.Context["incident_type"] = incident.Type
		indicator.Context["incident_severity"] = incident.Severity
		indicator.Context["threat_actors"] = incident.Attribution.ThreatActors
		indicator.Context["campaigns"] = incident.Attribution.Campaigns
		indicator.Context["mitre_ttps"] = incident.TechnicalDetails.MITRE
		
		// Enhance tags with incident information
		indicator.Tags = append(indicator.Tags, 
			"incident:"+incident.Type,
			"severity:"+incident.Severity,
		)
		
		// Add threat actor tags
		for _, actor := range incident.Attribution.ThreatActors {
			indicator.Tags = append(indicator.Tags, "actor:"+strings.ToLower(actor))
		}
		
		indicators = append(indicators, indicator)
	}
	
	return indicators
}

func (dsc *DigitalShadowsConnector) convertIoCToRawIndicator(ioc DigitalShadowsIoC) RawIndicator {
	// Build tags
	tags := []string{
		"digital_shadows",
		dsc.mapIndicatorType(ioc.Type),
		"risk:" + ioc.Risk.Level,
	}
	tags = append(tags, ioc.Context.Tags...)
	tags = append(tags, ioc.Context.ThreatTypes...)
	
	// Add malware tags
	for _, malware := range ioc.Context.Malware {
		tags = append(tags, "malware:"+strings.ToLower(malware))
	}
	
	// Add threat actor tags
	for _, actor := range ioc.Context.ThreatActors {
		tags = append(tags, "actor:"+strings.ToLower(actor))
	}
	
	// Build context information
	context := map[string]interface{}{
		"risk_score":       ioc.Risk.Score,
		"risk_level":       ioc.Risk.Level,
		"risk_reason":      ioc.Risk.Reason,
		"threat_types":     ioc.Context.ThreatTypes,
		"malware":          ioc.Context.Malware,
		"threat_actors":    ioc.Context.ThreatActors,
		"sources":          ioc.Context.Sources,
		"incident_ids":     ioc.Metadata.IncidentIDs,
		"categories":       ioc.Metadata.Categories,
		"additional_info":  ioc.Context.AdditionalInfo,
	}
	
	// Build metadata
	metadata := map[string]interface{}{
		"provider":         "digital_shadows",
		"ioc_id":           ioc.ID,
		"last_modified":    ioc.Metadata.LastModified,
		"custom_data":      ioc.Metadata.CustomData,
	}
	
	indicator := RawIndicator{
		Provider:   "digital_shadows",
		Type:       dsc.mapIndicatorType(ioc.Type),
		Value:      ioc.Value,
		Confidence: ioc.Confidence,
		Tags:       dsc.deduplicateTags(tags),
		FirstSeen:  ioc.FirstSeen,
		LastSeen:   ioc.LastSeen,
		Context:    context,
		Metadata:   metadata,
	}
	
	return indicator
}

func (dsc *DigitalShadowsConnector) mapIndicatorType(dsType string) string {
	// Map Digital Shadows IoC types to standard indicator types
	mappings := map[string]string{
		"ip":           "ipv4-addr",
		"ipv4":         "ipv4-addr",
		"ipv6":         "ipv6-addr",
		"domain":       "domain-name",
		"hostname":     "domain-name",
		"url":          "url",
		"md5":          "file",
		"sha1":         "file",
		"sha256":       "file",
		"hash":         "file",
		"email":        "email-addr",
		"filename":     "file",
		"registry_key": "windows-registry-key",
		"certificate":  "x509-certificate",
	}
	
	if mappedType, exists := mappings[strings.ToLower(dsType)]; exists {
		return mappedType
	}
	
	// Default fallback
	return strings.ToLower(dsType)
}

func (dsc *DigitalShadowsConnector) deduplicateTags(tags []string) []string {
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

// ValidateConfiguration validates the Digital Shadows configuration
func (dsc *DigitalShadowsConnector) ValidateConfiguration() error {
	if dsc.config.APIKey == "" || dsc.config.APISecret == "" {
		return fmt.Errorf("API key and secret are required")
	}
	
	if dsc.config.BaseURL == "" {
		return fmt.Errorf("base URL is required")
	}
	
	// Test API connectivity with a simple request
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	testURL := fmt.Sprintf("%s/incidents?limit=1", dsc.config.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}
	
	if err := dsc.setAuthHeaders(req, "GET", testURL); err != nil {
		return fmt.Errorf("failed to set auth headers: %w", err)
	}
	
	resp, err := dsc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("API connectivity test failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API authentication failed with status: %d", resp.StatusCode)
	}
	
	dsc.logger.Info("Digital Shadows configuration validated successfully")
	return nil
}

// GetProviderInfo returns information about the Digital Shadows provider
func (dsc *DigitalShadowsConnector) GetProviderInfo() map[string]interface{} {
	return map[string]interface{}{
		"provider":          "digital_shadows",
		"base_url":          dsc.config.BaseURL,
		"incident_types":    dsc.config.IncidentTypes,
		"severity_filter":   dsc.config.SeverityFilter,
		"update_interval":   dsc.config.UpdateInterval.String(),
		"last_fetch_time":   dsc.lastFetchTime,
		"rate_limit":        "1000 requests/hour",
		"supported_types":   []string{"incidents", "iocs", "threats", "vulnerabilities"},
		"authentication":    "HMAC-SHA256",
	}
}

// Close closes the Digital Shadows connector and cleans up resources
func (dsc *DigitalShadowsConnector) Close() error {
	dsc.logger.Info("Closing Digital Shadows connector")
	
	if dsc.rateLimiter != nil && dsc.rateLimiter.ticker != nil {
		dsc.rateLimiter.ticker.Stop()
	}
	
	// Close HTTP client connections
	if transport, ok := dsc.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	
	return nil
}