package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/connectors"
	"github.com/isectech/migration-service/domain/entity"
)

// SplunkConnector implements data extraction for Splunk SIEM
type SplunkConnector struct {
	*connectors.BaseConnector
	authHandler    *SplunkAuthHandler
	transformer    *SplunkTransformer
	sessionKey     string
	appContext     string
	searchJobCache map[string]*SplunkSearchJob
}

// SplunkAuthHandler handles Splunk authentication
type SplunkAuthHandler struct {
	connector    *SplunkConnector
	username     string
	password     string
	sessionKey   string
	tokenExpiry  *time.Time
}

// SplunkTransformer handles data transformation for Splunk
type SplunkTransformer struct {
	fieldMappings map[entity.DataType]map[string]string
}

// SplunkSearchJob represents a Splunk search job
type SplunkSearchJob struct {
	SID         string    `json:"sid"`
	Search      string    `json:"search"`
	Status      string    `json:"status"` // QUEUED, PARSING, RUNNING, PAUSED, FINALIZING, FAILED, DONE
	ResultCount int64     `json:"resultCount"`
	IsFinalized bool      `json:"isFinalized"`
	IsSaved     bool      `json:"isSaved"`
	CreateTime  time.Time `json:"createTime"`
	RunTime     float64   `json:"runTime"`
}

// SplunkSearchResult represents Splunk search results
type SplunkSearchResult struct {
	Results   []map[string]interface{} `json:"results"`
	Preview   bool                     `json:"preview"`
	InitOffset int64                   `json:"init_offset"`
	Messages  []SplunkMessage          `json:"messages"`
}

// SplunkMessage represents a Splunk message
type SplunkMessage struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// SplunkSystemInfo represents Splunk system information
type SplunkSystemInfo struct {
	Version       string                 `json:"version"`
	Build         string                 `json:"build"`
	ServerName    string                 `json:"serverName"`
	InstanceType  string                 `json:"instance_type"`
	LicenseState  string                 `json:"licenseState"`
	MasterURI     string                 `json:"master_uri,omitempty"`
	ServerRoles   []string               `json:"serverRoles"`
	Capabilities  []string               `json:"capabilities"`
	Health        map[string]interface{} `json:"health,omitempty"`
}

// NewSplunkConnector creates a new Splunk connector
func NewSplunkConnector(sourceSystem *entity.SourceSystem) (*SplunkConnector, error) {
	baseConnector, err := connectors.NewBaseConnector(sourceSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to create base connector: %w", err)
	}

	connector := &SplunkConnector{
		BaseConnector:  baseConnector,
		appContext:     "search", // Default app context
		searchJobCache: make(map[string]*SplunkSearchJob),
	}

	// Initialize authentication handler
	authHandler, err := NewSplunkAuthHandler(connector, sourceSystem.AuthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth handler: %w", err)
	}
	connector.authHandler = authHandler

	// Initialize transformer
	connector.transformer = NewSplunkTransformer()

	return connector, nil
}

// Connect establishes connection to Splunk
func (s *SplunkConnector) Connect(ctx context.Context) error {
	// Perform authentication
	if err := s.authHandler.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Call base connect
	return s.BaseConnector.Connect(ctx)
}

// TestConnection tests the connection to Splunk
func (s *SplunkConnector) TestConnection(ctx context.Context) error {
	// Test basic connectivity
	if err := s.BaseConnector.TestConnection(ctx); err != nil {
		return err
	}

	// Test Splunk-specific endpoints
	return s.testSplunkAPI(ctx)
}

// GetSystemInfo retrieves Splunk system information
func (s *SplunkConnector) GetSystemInfo(ctx context.Context) (*connectors.SystemInfo, error) {
	baseInfo, err := s.BaseConnector.GetSystemInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get Splunk-specific system information
	splunkInfo, err := s.getSplunkSystemInfo(ctx)
	if err != nil {
		return baseInfo, nil // Return base info if Splunk info fails
	}

	// Enhance with Splunk-specific information
	baseInfo.Version = splunkInfo.Version
	baseInfo.APIVersion = "v1"
	baseInfo.ServerInfo["build"] = splunkInfo.Build
	baseInfo.ServerInfo["server_name"] = splunkInfo.ServerName
	baseInfo.ServerInfo["instance_type"] = splunkInfo.InstanceType
	baseInfo.ServerInfo["license_state"] = splunkInfo.LicenseState
	baseInfo.ServerInfo["server_roles"] = splunkInfo.ServerRoles
	baseInfo.ServerInfo["capabilities"] = splunkInfo.Capabilities

	if splunkInfo.Health != nil {
		baseInfo.ServerInfo["health"] = splunkInfo.Health
	}

	return baseInfo, nil
}

// ExtractData extracts data from Splunk
func (s *SplunkConnector) ExtractData(ctx context.Context, params *connectors.ExtractionParams) (*connectors.ExtractionResult, error) {
	if !s.authHandler.IsAuthenticated() {
		if err := s.authHandler.Authenticate(ctx); err != nil {
			return nil, fmt.Errorf("authentication required: %w", err)
		}
	}

	// Build Splunk search query
	searchQuery, err := s.buildSearchQuery(params)
	if err != nil {
		return nil, fmt.Errorf("failed to build search query: %w", err)
	}

	// Execute search
	searchJob, err := s.executeSearch(ctx, searchQuery, params)
	if err != nil {
		return nil, fmt.Errorf("failed to execute search: %w", err)
	}

	// Wait for search completion
	if err := s.waitForSearchCompletion(ctx, searchJob, params.Timeout); err != nil {
		return nil, fmt.Errorf("search did not complete: %w", err)
	}

	// Retrieve results
	results, err := s.getSearchResults(ctx, searchJob, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get search results: %w", err)
	}

	// Transform results
	transformedRecords := make([]map[string]interface{}, 0, len(results.Results))
	for _, record := range results.Results {
		transformedRecord, err := s.transformer.TransformRecord(ctx, record, params.DataType)
		if err != nil {
			// Log error but continue with next record
			continue
		}
		transformedRecords = append(transformedRecords, transformedRecord.TransformedData)
	}

	// Build extraction result
	extractionResult := &connectors.ExtractionResult{
		Records:        transformedRecords,
		TotalRecords:   searchJob.ResultCount,
		ExtractedCount: int64(len(transformedRecords)),
		SkippedCount:   int64(len(results.Results) - len(transformedRecords)),
		HasMore:        false, // Splunk searches are typically complete
		ExtractionTime: time.Since(searchJob.CreateTime),
		DataSize:       int64(len(results.Results) * 1024), // Rough estimate
	}

	// Add quality metrics if validation was requested
	if params.ValidateData {
		qualityMetrics := s.calculateDataQuality(results.Results, transformedRecords)
		extractionResult.QualityMetrics = qualityMetrics
	}

	return extractionResult, nil
}

// GetSchema returns the data schema for a specific data type
func (s *SplunkConnector) GetSchema(ctx context.Context, dataType entity.DataType) (*connectors.DataSchema, error) {
	schema := &connectors.DataSchema{
		DataType:    dataType,
		Version:     "1.0",
		Fields:      s.getFieldsForDataType(dataType),
		LastUpdated: time.Now(),
	}

	switch dataType {
	case entity.DataTypeAlerts:
		schema.RequiredFields = []string{"_time", "search_name", "severity"}
		schema.PrimaryKey = []string{"_time", "search_name"}
	case entity.DataTypeLogs:
		schema.RequiredFields = []string{"_time", "source", "sourcetype"}
		schema.PrimaryKey = []string{"_time", "_raw"}
	case entity.DataTypeIncidents:
		schema.RequiredFields = []string{"_time", "incident_id", "status"}
		schema.PrimaryKey = []string{"incident_id"}
	case entity.DataTypeEvents:
		schema.RequiredFields = []string{"_time", "source"}
		schema.PrimaryKey = []string{"_time", "source", "_raw"}
	}

	return schema, nil
}

// EstimateRecordCount estimates the number of records for extraction
func (s *SplunkConnector) EstimateRecordCount(ctx context.Context, params *connectors.ExtractionParams) (int64, error) {
	// Build a count-only search query
	baseQuery, err := s.buildSearchQuery(params)
	if err != nil {
		return 0, err
	}

	countQuery := baseQuery + " | stats count"

	// Execute count search
	searchJob, err := s.executeSearch(ctx, countQuery, params)
	if err != nil {
		return 0, fmt.Errorf("failed to execute count search: %w", err)
	}

	// Wait for completion with shorter timeout
	timeout := 30 * time.Second
	if params.Timeout != nil && *params.Timeout < timeout {
		timeout = *params.Timeout
	}

	if err := s.waitForSearchCompletion(ctx, searchJob, &timeout); err != nil {
		return 0, fmt.Errorf("count search did not complete: %w", err)
	}

	// Get count result
	results, err := s.getSearchResults(ctx, searchJob, &connectors.ExtractionParams{
		BatchSize: 1,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get count results: %w", err)
	}

	if len(results.Results) == 0 {
		return 0, nil
	}

	countStr, ok := results.Results[0]["count"].(string)
	if !ok {
		return 0, fmt.Errorf("invalid count result format")
	}

	count, err := strconv.ParseInt(countStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse count: %w", err)
	}

	return count, nil
}

// Helper methods

// testSplunkAPI tests Splunk-specific API endpoints
func (s *SplunkConnector) testSplunkAPI(ctx context.Context) error {
	// Test server info endpoint
	endpoint := "/services/server/info"
	req, err := s.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}

	resp, err := s.makeRequest(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server info endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// getSplunkSystemInfo retrieves Splunk system information
func (s *SplunkConnector) getSplunkSystemInfo(ctx context.Context) (*SplunkSystemInfo, error) {
	endpoint := "/services/server/info"
	req, err := s.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server info request failed with status %d", resp.StatusCode)
	}

	var result struct {
		Entry []struct {
			Content SplunkSystemInfo `json:"content"`
		} `json:"entry"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode server info response: %w", err)
	}

	if len(result.Entry) == 0 {
		return nil, fmt.Errorf("no server info found in response")
	}

	return &result.Entry[0].Content, nil
}

// buildSearchQuery builds a Splunk search query from extraction parameters
func (s *SplunkConnector) buildSearchQuery(params *connectors.ExtractionParams) (string, error) {
	var queryParts []string

	// Base search based on data type
	switch params.DataType {
	case entity.DataTypeAlerts:
		queryParts = append(queryParts, "search index=main OR index=security")
		queryParts = append(queryParts, "search_name=\"*\"")
	case entity.DataTypeLogs:
		queryParts = append(queryParts, "search index=main OR index=security OR index=network")
	case entity.DataTypeIncidents:
		queryParts = append(queryParts, "search index=main OR index=security")
		queryParts = append(queryParts, "incident_id=\"*\"")
	case entity.DataTypeEvents:
		queryParts = append(queryParts, "search index=main OR index=security OR index=network OR index=web")
	case entity.DataTypeThreats:
		queryParts = append(queryParts, "search index=security")
		queryParts = append(queryParts, "(threat OR malware OR virus OR attack)")
	default:
		queryParts = append(queryParts, "search index=main")
	}

	// Add time range
	if params.DateRange != nil {
		earliest := params.DateRange.StartDate.Unix()
		latest := params.DateRange.EndDate.Unix()
		queryParts = append(queryParts, fmt.Sprintf("earliest=%d latest=%d", earliest, latest))
	}

	// Add custom filters
	for key, value := range params.Filters {
		switch v := value.(type) {
		case string:
			if v != "" {
				queryParts = append(queryParts, fmt.Sprintf("%s=\"%s\"", key, v))
			}
		case []string:
			if len(v) > 0 {
				orConditions := make([]string, len(v))
				for i, val := range v {
					orConditions[i] = fmt.Sprintf("%s=\"%s\"", key, val)
				}
				queryParts = append(queryParts, fmt.Sprintf("(%s)", strings.Join(orConditions, " OR ")))
			}
		}
	}

	// Add field selection if specified
	if len(params.IncludeFields) > 0 {
		fields := strings.Join(params.IncludeFields, ",")
		queryParts = append(queryParts, fmt.Sprintf("| fields %s", fields))
	}

	// Add deduplication if requested
	if params.Deduplicate {
		queryParts = append(queryParts, "| dedup _raw")
	}

	// Add result limit
	if params.MaxRecords != nil {
		queryParts = append(queryParts, fmt.Sprintf("| head %d", *params.MaxRecords))
	}

	return strings.Join(queryParts, " "), nil
}

// executeSearch executes a search in Splunk
func (s *SplunkConnector) executeSearch(ctx context.Context, query string, params *connectors.ExtractionParams) (*SplunkSearchJob, error) {
	endpoint := "/services/search/jobs"
	
	// Prepare search parameters
	searchParams := url.Values{}
	searchParams.Set("search", query)
	searchParams.Set("output_mode", "json")
	searchParams.Set("exec_mode", "normal")
	
	if params.BatchSize > 0 {
		searchParams.Set("max_count", strconv.Itoa(int(params.BatchSize)))
	}

	req, err := s.buildRequest(ctx, "POST", endpoint, strings.NewReader(searchParams.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("search creation failed with status %d", resp.StatusCode)
	}

	var result struct {
		SID string `json:"sid"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search creation response: %w", err)
	}

	searchJob := &SplunkSearchJob{
		SID:        result.SID,
		Search:     query,
		Status:     "QUEUED",
		CreateTime: time.Now(),
	}

	// Cache the search job
	s.searchJobCache[result.SID] = searchJob

	return searchJob, nil
}

// waitForSearchCompletion waits for a search to complete
func (s *SplunkConnector) waitForSearchCompletion(ctx context.Context, searchJob *SplunkSearchJob, timeout *time.Duration) error {
	var deadline time.Time
	if timeout != nil {
		deadline = time.Now().Add(*timeout)
	}

	ticker := time.NewTicker(2 * time.Second) // Check every 2 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if timeout != nil && time.Now().After(deadline) {
				return fmt.Errorf("search timeout after %v", *timeout)
			}

			// Check search status
			status, err := s.getSearchStatus(ctx, searchJob.SID)
			if err != nil {
				return fmt.Errorf("failed to check search status: %w", err)
			}

			searchJob.Status = status.Status
			searchJob.ResultCount = status.ResultCount
			searchJob.IsFinalized = status.IsFinalized

			if status.Status == "DONE" {
				return nil
			}
			if status.Status == "FAILED" {
				return fmt.Errorf("search failed")
			}
		}
	}
}

// getSearchStatus gets the status of a search job
func (s *SplunkConnector) getSearchStatus(ctx context.Context, sid string) (*SplunkSearchJob, error) {
	endpoint := fmt.Sprintf("/services/search/jobs/%s", sid)
	req, err := s.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameter for JSON output
	q := req.URL.Query()
	q.Set("output_mode", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := s.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search status request failed with status %d", resp.StatusCode)
	}

	var result struct {
		Entry []struct {
			Content struct {
				DispatchState  string  `json:"dispatchState"`
				IsDone         bool    `json:"isDone"`
				IsFinalized    bool    `json:"isFinalized"`
				ResultCount    int64   `json:"resultCount"`
				RunDuration    float64 `json:"runDuration"`
			} `json:"content"`
		} `json:"entry"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search status response: %w", err)
	}

	if len(result.Entry) == 0 {
		return nil, fmt.Errorf("no search job found")
	}

	content := result.Entry[0].Content
	status := &SplunkSearchJob{
		SID:         sid,
		Status:      content.DispatchState,
		ResultCount: content.ResultCount,
		IsFinalized: content.IsFinalized,
		RunTime:     content.RunDuration,
	}

	if content.IsDone {
		status.Status = "DONE"
	}

	return status, nil
}

// getSearchResults retrieves results from a completed search
func (s *SplunkConnector) getSearchResults(ctx context.Context, searchJob *SplunkSearchJob, params *connectors.ExtractionParams) (*SplunkSearchResult, error) {
	endpoint := fmt.Sprintf("/services/search/jobs/%s/results", searchJob.SID)
	req, err := s.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	q := req.URL.Query()
	q.Set("output_mode", "json")
	if params.BatchSize > 0 {
		q.Set("count", strconv.Itoa(int(params.BatchSize)))
	}
	if params.Offset != nil {
		q.Set("offset", strconv.FormatInt(*params.Offset, 10))
	}
	req.URL.RawQuery = q.Encode()

	resp, err := s.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search results request failed with status %d", resp.StatusCode)
	}

	var result SplunkSearchResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search results: %w", err)
	}

	return &result, nil
}

// buildRequest builds an HTTP request for Splunk API
func (s *SplunkConnector) buildRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Request, error) {
	baseURL := s.sourceSystem.ConnectionConfig.BaseURL
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	var req *http.Request
	var err error

	switch b := body.(type) {
	case nil:
		req, err = http.NewRequestWithContext(ctx, method, fullURL, nil)
	case *strings.Reader:
		req, err = http.NewRequestWithContext(ctx, method, fullURL, b)
	default:
		return nil, fmt.Errorf("unsupported body type")
	}

	if err != nil {
		return nil, err
	}

	// Add authentication headers
	if s.authHandler.IsAuthenticated() {
		authHeaders := s.authHandler.GetAuthHeaders()
		for key, value := range authHeaders {
			req.Header.Set(key, value)
		}
	}

	// Add default headers
	s.addDefaultHeaders(req)

	return req, nil
}

// calculateDataQuality calculates data quality metrics
func (s *SplunkConnector) calculateDataQuality(originalRecords, transformedRecords []map[string]interface{}) *connectors.DataQualityMetrics {
	totalRecords := int64(len(originalRecords))
	validRecords := int64(len(transformedRecords))
	invalidRecords := totalRecords - validRecords

	// Calculate basic scores
	validityScore := 100.0
	if totalRecords > 0 {
		validityScore = float64(validRecords) / float64(totalRecords) * 100.0
	}

	// Placeholder values for other scores - these would be calculated based on actual data analysis
	return &connectors.DataQualityMetrics{
		TotalRecords:      totalRecords,
		ValidRecords:      validRecords,
		InvalidRecords:    invalidRecords,
		DuplicateRecords:  0, // Would need deduplication logic
		CompletenessScore: 95.0,
		AccuracyScore:     90.0,
		ConsistencyScore:  85.0,
		ValidityScore:     validityScore,
		UniquenessScore:   98.0,
		OverallScore:      (95.0 + 90.0 + 85.0 + validityScore + 98.0) / 5.0,
	}
}

// getFieldsForDataType returns field schema for a data type
func (s *SplunkConnector) getFieldsForDataType(dataType entity.DataType) []connectors.FieldSchema {
	commonFields := []connectors.FieldSchema{
		{Name: "_time", Type: "timestamp", Required: true, Description: "Event timestamp"},
		{Name: "source", Type: "string", Required: false, Description: "Event source"},
		{Name: "sourcetype", Type: "string", Required: false, Description: "Source type"},
		{Name: "host", Type: "string", Required: false, Description: "Host name"},
		{Name: "index", Type: "string", Required: false, Description: "Splunk index"},
	}

	switch dataType {
	case entity.DataTypeAlerts:
		return append(commonFields, []connectors.FieldSchema{
			{Name: "search_name", Type: "string", Required: true, Description: "Alert search name"},
			{Name: "severity", Type: "string", Required: true, Description: "Alert severity"},
			{Name: "trigger_time", Type: "timestamp", Required: false, Description: "Alert trigger time"},
			{Name: "owner", Type: "string", Required: false, Description: "Alert owner"},
		}...)
	case entity.DataTypeLogs:
		return append(commonFields, []connectors.FieldSchema{
			{Name: "_raw", Type: "string", Required: true, Description: "Raw log message"},
			{Name: "linecount", Type: "integer", Required: false, Description: "Number of lines"},
		}...)
	case entity.DataTypeIncidents:
		return append(commonFields, []connectors.FieldSchema{
			{Name: "incident_id", Type: "string", Required: true, Description: "Incident identifier"},
			{Name: "status", Type: "string", Required: true, Description: "Incident status"},
			{Name: "priority", Type: "string", Required: false, Description: "Incident priority"},
			{Name: "assignee", Type: "string", Required: false, Description: "Assigned user"},
		}...)
	default:
		return commonFields
	}
}