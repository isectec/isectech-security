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

// QRadarConnector implements data extraction for IBM QRadar SIEM
type QRadarConnector struct {
	*connectors.BaseConnector
	authHandler  *QRadarAuthHandler
	transformer  *QRadarTransformer
	apiVersion   string
	searchCache  map[string]*QRadarSearch
}

// QRadarAuthHandler handles QRadar authentication
type QRadarAuthHandler struct {
	connector *QRadarConnector
	apiToken  string
	username  string
	password  string
	secToken  string
}

// QRadarTransformer handles data transformation for QRadar
type QRadarTransformer struct {
	fieldMappings map[entity.DataType]map[string]string
}

// QRadarSearch represents a QRadar search/query
type QRadarSearch struct {
	SearchID    string                 `json:"search_id"`
	Status      string                 `json:"status"` // WAIT, EXECUTE, COMPLETED, CANCELED, ERROR
	Query       string                 `json:"query_string,omitempty"`
	QueryType   string                 `json:"query_type,omitempty"`
	Results     []map[string]interface{} `json:"results,omitempty"`
	RecordCount int64                  `json:"record_count"`
	Progress    int                    `json:"progress"`
	CreateTime  time.Time              `json:"create_time"`
	CompletedTime *time.Time           `json:"completed_time,omitempty"`
}

// QRadarEvent represents a QRadar event
type QRadarEvent struct {
	ID                  int64     `json:"id"`
	StartTime           int64     `json:"starttime"`
	EventCount          int       `json:"eventcount"`
	EventID             int64     `json:"eventid"`
	Category            int       `json:"category"`
	HighLevelCategory   int       `json:"highlevelcategory"`
	QID                 int       `json:"qid"`
	Severity            int       `json:"severity"`
	Relevance           int       `json:"relevance"`
	CredibilityRating   int       `json:"credibilityrating"`
	LogSourceID         int       `json:"logsourceid"`
	AssignedTo          *string   `json:"assignedto,omitempty"`
	FollowUp            bool      `json:"followup"`
	Protected           bool      `json:"protected"`
	ClosingUser         *string   `json:"closinguser,omitempty"`
	ClosingReason       *string   `json:"closingreason,omitempty"`
	CloseTime           *int64    `json:"closetime,omitempty"`
	Status              string    `json:"status"`
	LastUpdatedTime     int64     `json:"lastupdatedtime"`
	Username            *string   `json:"username,omitempty"`
	SourceIP            *string   `json:"sourceip,omitempty"`
	DestinationIP       *string   `json:"destinationip,omitempty"`
	SourcePort          *int      `json:"sourceport,omitempty"`
	DestinationPort     *int      `json:"destinationport,omitempty"`
	Protocol            *int      `json:"protocol,omitempty"`
	EventDirection      *string   `json:"eventdirection,omitempty"`
	SourceNetwork       *string   `json:"sourcenetwork,omitempty"`
	DestinationNetwork  *string   `json:"destinationnetwork,omitempty"`
}

// QRadarOffense represents a QRadar offense (incident)
type QRadarOffense struct {
	ID                  int64     `json:"id"`
	Description         string    `json:"description"`
	StartTime           int64     `json:"start_time"`
	LastUpdatedTime     int64     `json:"last_updated_time"`
	OffenseType         int       `json:"offense_type"`
	Status              string    `json:"status"`
	Magnitude           float64   `json:"magnitude"`
	Credibility         int       `json:"credibility"`
	Relevance           int       `json:"relevance"`
	Severity            int       `json:"severity"`
	AssignedTo          *string   `json:"assigned_to,omitempty"`
	ClosingUser         *string   `json:"closing_user,omitempty"`
	ClosingReason       *string   `json:"closing_reason,omitempty"`
	CloseTime           *int64    `json:"close_time,omitempty"`
	FollowUp            bool      `json:"follow_up"`
	Protected           bool      `json:"protected"`
	CategoryCount       int       `json:"category_count"`
	PolicyCategoryCount int       `json:"policy_category_count"`
	SecurityCategoryCount int     `json:"security_category_count"`
	SourceCount         int       `json:"source_count"`
	LocalDestinationCount int     `json:"local_destination_count"`
	RemoteDestinationCount int    `json:"remote_destination_count"`
	EventCount          int       `json:"event_count"`
	FlowCount           int       `json:"flow_count"`
	InactiveReason      *string   `json:"inactive_reason,omitempty"`
	SourceAddressIDs    []int     `json:"source_address_ids,omitempty"`
	LocalDestinationAddressIDs []int `json:"local_destination_address_ids,omitempty"`
}

// QRadarLogSource represents a QRadar log source
type QRadarLogSource struct {
	ID                  int       `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	TypeID              int       `json:"type_id"`
	TypeName            string    `json:"type_name"`
	Protocol            string    `json:"protocol"`
	Enabled             bool      `json:"enabled"`
	Gateway             bool      `json:"gateway"`
	Internal            bool      `json:"internal"`
	Credibility         int       `json:"credibility"`
	TargetEventCollectorID int    `json:"target_event_collector_id"`
	CoalesceEvents      bool      `json:"coalesce_events"`
	Indexed             bool      `json:"indexed"`
	CreationDate        int64     `json:"creation_date"`
	ModifiedDate        int64     `json:"modified_date"`
	LastEventTime       *int64    `json:"last_event_time,omitempty"`
	AverageEPS          float64   `json:"average_eps"`
}

// QRadarSystemInfo represents QRadar system information
type QRadarSystemInfo struct {
	Version          string                 `json:"version"`
	Release          string                 `json:"release"`
	BuildVersion     string                 `json:"build_version"`
	ProductName      string                 `json:"product_name"`
	ExternalHostname string                 `json:"external_hostname"`
	InternalHostname string                 `json:"internal_hostname"`
	Timezone         string                 `json:"timezone"`
	LicenseInfo      map[string]interface{} `json:"license_info,omitempty"`
	SystemHealth     map[string]interface{} `json:"system_health,omitempty"`
}

// NewQRadarConnector creates a new QRadar connector
func NewQRadarConnector(sourceSystem *entity.SourceSystem) (*QRadarConnector, error) {
	baseConnector, err := connectors.NewBaseConnector(sourceSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to create base connector: %w", err)
	}

	connector := &QRadarConnector{
		BaseConnector: baseConnector,
		apiVersion:    "11.0", // Default API version
		searchCache:   make(map[string]*QRadarSearch),
	}

	// Check for API version in connection config
	if apiVersion, exists := sourceSystem.ConnectionConfig.QueryParameters["api_version"]; exists {
		connector.apiVersion = apiVersion
	}

	// Initialize authentication handler
	authHandler, err := NewQRadarAuthHandler(connector, sourceSystem.AuthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth handler: %w", err)
	}
	connector.authHandler = authHandler

	// Initialize transformer
	connector.transformer = NewQRadarTransformer()

	return connector, nil
}

// Connect establishes connection to QRadar
func (q *QRadarConnector) Connect(ctx context.Context) error {
	// Perform authentication
	if err := q.authHandler.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Call base connect
	return q.BaseConnector.Connect(ctx)
}

// TestConnection tests the connection to QRadar
func (q *QRadarConnector) TestConnection(ctx context.Context) error {
	// Test basic connectivity
	if err := q.BaseConnector.TestConnection(ctx); err != nil {
		return err
	}

	// Test QRadar-specific endpoints
	return q.testQRadarAPI(ctx)
}

// GetSystemInfo retrieves QRadar system information
func (q *QRadarConnector) GetSystemInfo(ctx context.Context) (*connectors.SystemInfo, error) {
	baseInfo, err := q.BaseConnector.GetSystemInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Get QRadar-specific system information
	qradarInfo, err := q.getQRadarSystemInfo(ctx)
	if err != nil {
		return baseInfo, nil // Return base info if QRadar info fails
	}

	// Enhance with QRadar-specific information
	baseInfo.Version = qradarInfo.Version
	baseInfo.APIVersion = q.apiVersion
	baseInfo.ServerInfo["release"] = qradarInfo.Release
	baseInfo.ServerInfo["build_version"] = qradarInfo.BuildVersion
	baseInfo.ServerInfo["product_name"] = qradarInfo.ProductName
	baseInfo.ServerInfo["external_hostname"] = qradarInfo.ExternalHostname
	baseInfo.ServerInfo["internal_hostname"] = qradarInfo.InternalHostname
	baseInfo.ServerInfo["timezone"] = qradarInfo.Timezone

	if qradarInfo.LicenseInfo != nil {
		baseInfo.ServerInfo["license_info"] = qradarInfo.LicenseInfo
	}
	if qradarInfo.SystemHealth != nil {
		baseInfo.ServerInfo["system_health"] = qradarInfo.SystemHealth
	}

	return baseInfo, nil
}

// ExtractData extracts data from QRadar
func (q *QRadarConnector) ExtractData(ctx context.Context, params *connectors.ExtractionParams) (*connectors.ExtractionResult, error) {
	if !q.authHandler.IsAuthenticated() {
		if err := q.authHandler.Authenticate(ctx); err != nil {
			return nil, fmt.Errorf("authentication required: %w", err)
		}
	}

	switch params.DataType {
	case entity.DataTypeEvents:
		return q.extractEvents(ctx, params)
	case entity.DataTypeIncidents:
		return q.extractOffenses(ctx, params)
	case entity.DataTypeAlerts:
		return q.extractOffenses(ctx, params) // Offenses can be treated as alerts
	case entity.DataTypeAssets:
		return q.extractAssets(ctx, params)
	default:
		return nil, fmt.Errorf("data type %s not supported for QRadar", params.DataType)
	}
}

// GetSchema returns the data schema for a specific data type
func (q *QRadarConnector) GetSchema(ctx context.Context, dataType entity.DataType) (*connectors.DataSchema, error) {
	schema := &connectors.DataSchema{
		DataType:    dataType,
		Version:     "1.0",
		Fields:      q.getFieldsForDataType(dataType),
		LastUpdated: time.Now(),
	}

	switch dataType {
	case entity.DataTypeEvents:
		schema.RequiredFields = []string{"id", "starttime", "qid"}
		schema.PrimaryKey = []string{"id"}
	case entity.DataTypeIncidents:
		schema.RequiredFields = []string{"id", "description", "start_time", "status"}
		schema.PrimaryKey = []string{"id"}
	case entity.DataTypeAlerts:
		schema.RequiredFields = []string{"id", "description", "severity"}
		schema.PrimaryKey = []string{"id"}
	case entity.DataTypeAssets:
		schema.RequiredFields = []string{"id", "interfaces"}
		schema.PrimaryKey = []string{"id"}
	}

	return schema, nil
}

// EstimateRecordCount estimates the number of records for extraction
func (q *QRadarConnector) EstimateRecordCount(ctx context.Context, params *connectors.ExtractionParams) (int64, error) {
	switch params.DataType {
	case entity.DataTypeEvents:
		return q.estimateEventCount(ctx, params)
	case entity.DataTypeIncidents, entity.DataTypeAlerts:
		return q.estimateOffenseCount(ctx, params)
	case entity.DataTypeAssets:
		return q.estimateAssetCount(ctx, params)
	default:
		return 0, fmt.Errorf("data type %s not supported for count estimation", params.DataType)
	}
}

// Helper methods

// testQRadarAPI tests QRadar-specific API endpoints
func (q *QRadarConnector) testQRadarAPI(ctx context.Context) error {
	// Test system info endpoint
	endpoint := fmt.Sprintf("/api/system/about")
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("system info endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// getQRadarSystemInfo retrieves QRadar system information
func (q *QRadarConnector) getQRadarSystemInfo(ctx context.Context) (*QRadarSystemInfo, error) {
	endpoint := fmt.Sprintf("/api/system/about")
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("system info request failed with status %d", resp.StatusCode)
	}

	var systemInfo QRadarSystemInfo
	if err := json.NewDecoder(resp.Body).Decode(&systemInfo); err != nil {
		return nil, fmt.Errorf("failed to decode system info response: %w", err)
	}

	return &systemInfo, nil
}

// extractEvents extracts events from QRadar
func (q *QRadarConnector) extractEvents(ctx context.Context, params *connectors.ExtractionParams) (*connectors.ExtractionResult, error) {
	// Build query parameters
	queryParams := q.buildEventQueryParams(params)

	endpoint := "/api/siem/events"
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	req.URL.RawQuery = queryParams.Encode()

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("events request failed with status %d", resp.StatusCode)
	}

	var events []QRadarEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, fmt.Errorf("failed to decode events response: %w", err)
	}

	// Transform events
	transformedRecords := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		eventMap := q.eventToMap(event)
		transformedRecord, err := q.transformer.TransformRecord(ctx, eventMap, entity.DataTypeEvents)
		if err != nil {
			continue // Skip invalid records
		}
		transformedRecords = append(transformedRecords, transformedRecord.TransformedData)
	}

	return &connectors.ExtractionResult{
		Records:        transformedRecords,
		TotalRecords:   int64(len(events)),
		ExtractedCount: int64(len(transformedRecords)),
		SkippedCount:   int64(len(events) - len(transformedRecords)),
		HasMore:        len(events) == int(params.BatchSize),
		ExtractionTime: time.Since(time.Now()),
		DataSize:       int64(len(events) * 1024), // Rough estimate
	}, nil
}

// extractOffenses extracts offenses (incidents/alerts) from QRadar
func (q *QRadarConnector) extractOffenses(ctx context.Context, params *connectors.ExtractionParams) (*connectors.ExtractionResult, error) {
	// Build query parameters
	queryParams := q.buildOffenseQueryParams(params)

	endpoint := "/api/siem/offenses"
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	req.URL.RawQuery = queryParams.Encode()

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("offenses request failed with status %d", resp.StatusCode)
	}

	var offenses []QRadarOffense
	if err := json.NewDecoder(resp.Body).Decode(&offenses); err != nil {
		return nil, fmt.Errorf("failed to decode offenses response: %w", err)
	}

	// Transform offenses
	transformedRecords := make([]map[string]interface{}, 0, len(offenses))
	for _, offense := range offenses {
		offenseMap := q.offenseToMap(offense)
		transformedRecord, err := q.transformer.TransformRecord(ctx, offenseMap, params.DataType)
		if err != nil {
			continue // Skip invalid records
		}
		transformedRecords = append(transformedRecords, transformedRecord.TransformedData)
	}

	return &connectors.ExtractionResult{
		Records:        transformedRecords,
		TotalRecords:   int64(len(offenses)),
		ExtractedCount: int64(len(transformedRecords)),
		SkippedCount:   int64(len(offenses) - len(transformedRecords)),
		HasMore:        len(offenses) == int(params.BatchSize),
		ExtractionTime: time.Since(time.Now()),
		DataSize:       int64(len(offenses) * 1024), // Rough estimate
	}, nil
}

// extractAssets extracts assets from QRadar
func (q *QRadarConnector) extractAssets(ctx context.Context, params *connectors.ExtractionParams) (*connectors.ExtractionResult, error) {
	// Build query parameters
	queryParams := url.Values{}
	if params.BatchSize > 0 {
		queryParams.Set("limit", strconv.Itoa(int(params.BatchSize)))
	}
	if params.Offset != nil {
		queryParams.Set("offset", strconv.FormatInt(*params.Offset, 10))
	}

	endpoint := "/api/asset_model/assets"
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	req.URL.RawQuery = queryParams.Encode()

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("assets request failed with status %d", resp.StatusCode)
	}

	var assets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&assets); err != nil {
		return nil, fmt.Errorf("failed to decode assets response: %w", err)
	}

	// Transform assets
	transformedRecords := make([]map[string]interface{}, 0, len(assets))
	for _, asset := range assets {
		transformedRecord, err := q.transformer.TransformRecord(ctx, asset, entity.DataTypeAssets)
		if err != nil {
			continue // Skip invalid records
		}
		transformedRecords = append(transformedRecords, transformedRecord.TransformedData)
	}

	return &connectors.ExtractionResult{
		Records:        transformedRecords,
		TotalRecords:   int64(len(assets)),
		ExtractedCount: int64(len(transformedRecords)),
		SkippedCount:   int64(len(assets) - len(transformedRecords)),
		HasMore:        len(assets) == int(params.BatchSize),
		ExtractionTime: time.Since(time.Now()),
		DataSize:       int64(len(assets) * 1024), // Rough estimate
	}, nil
}

// buildEventQueryParams builds query parameters for event extraction
func (q *QRadarConnector) buildEventQueryParams(params *connectors.ExtractionParams) url.Values {
	queryParams := url.Values{}

	// Set limit
	if params.BatchSize > 0 {
		queryParams.Set("limit", strconv.Itoa(int(params.BatchSize)))
	}

	// Set offset
	if params.Offset != nil {
		queryParams.Set("offset", strconv.FormatInt(*params.Offset, 10))
	}

	// Set time range filter
	if params.DateRange != nil {
		startTime := params.DateRange.StartDate.Unix() * 1000 // QRadar uses milliseconds
		endTime := params.DateRange.EndDate.Unix() * 1000
		queryParams.Set("filter", fmt.Sprintf("starttime>=%d and starttime<=%d", startTime, endTime))
	}

	// Add custom filters
	var filters []string
	for key, value := range params.Filters {
		switch v := value.(type) {
		case string:
			if v != "" {
				filters = append(filters, fmt.Sprintf("%s='%s'", key, v))
			}
		case int, int64:
			filters = append(filters, fmt.Sprintf("%s=%v", key, v))
		}
	}

	if len(filters) > 0 {
		existingFilter := queryParams.Get("filter")
		if existingFilter != "" {
			queryParams.Set("filter", fmt.Sprintf("(%s) and (%s)", existingFilter, strings.Join(filters, " and ")))
		} else {
			queryParams.Set("filter", strings.Join(filters, " and "))
		}
	}

	return queryParams
}

// buildOffenseQueryParams builds query parameters for offense extraction
func (q *QRadarConnector) buildOffenseQueryParams(params *connectors.ExtractionParams) url.Values {
	queryParams := url.Values{}

	// Set limit
	if params.BatchSize > 0 {
		queryParams.Set("limit", strconv.Itoa(int(params.BatchSize)))
	}

	// Set offset
	if params.Offset != nil {
		queryParams.Set("offset", strconv.FormatInt(*params.Offset, 10))
	}

	// Set time range filter
	if params.DateRange != nil {
		startTime := params.DateRange.StartDate.Unix() * 1000 // QRadar uses milliseconds
		endTime := params.DateRange.EndDate.Unix() * 1000
		queryParams.Set("filter", fmt.Sprintf("start_time>=%d and start_time<=%d", startTime, endTime))
	}

	// Add custom filters
	var filters []string
	for key, value := range params.Filters {
		switch v := value.(type) {
		case string:
			if v != "" {
				filters = append(filters, fmt.Sprintf("%s='%s'", key, v))
			}
		case int, int64:
			filters = append(filters, fmt.Sprintf("%s=%v", key, v))
		}
	}

	if len(filters) > 0 {
		existingFilter := queryParams.Get("filter")
		if existingFilter != "" {
			queryParams.Set("filter", fmt.Sprintf("(%s) and (%s)", existingFilter, strings.Join(filters, " and ")))
		} else {
			queryParams.Set("filter", strings.Join(filters, " and "))
		}
	}

	return queryParams
}

// estimateEventCount estimates the number of events
func (q *QRadarConnector) estimateEventCount(ctx context.Context, params *connectors.ExtractionParams) (int64, error) {
	// Use the same query but with limit=1 to get total count from headers
	queryParams := q.buildEventQueryParams(params)
	queryParams.Set("limit", "1")

	endpoint := "/api/siem/events"
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return 0, err
	}

	req.URL.RawQuery = queryParams.Encode()

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// QRadar returns total count in X-Total-Count header
	if totalStr := resp.Header.Get("X-Total-Count"); totalStr != "" {
		if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil {
			return total, nil
		}
	}

	// Fallback: return 0 if no count header
	return 0, nil
}

// estimateOffenseCount estimates the number of offenses
func (q *QRadarConnector) estimateOffenseCount(ctx context.Context, params *connectors.ExtractionParams) (int64, error) {
	// Use the same query but with limit=1 to get total count from headers
	queryParams := q.buildOffenseQueryParams(params)
	queryParams.Set("limit", "1")

	endpoint := "/api/siem/offenses"
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return 0, err
	}

	req.URL.RawQuery = queryParams.Encode()

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// QRadar returns total count in X-Total-Count header
	if totalStr := resp.Header.Get("X-Total-Count"); totalStr != "" {
		if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil {
			return total, nil
		}
	}

	return 0, nil
}

// estimateAssetCount estimates the number of assets
func (q *QRadarConnector) estimateAssetCount(ctx context.Context, params *connectors.ExtractionParams) (int64, error) {
	endpoint := "/api/asset_model/assets"
	req, err := q.buildRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return 0, err
	}

	// Add limit=1 to just get count
	q := req.URL.Query()
	q.Set("limit", "1")
	req.URL.RawQuery = q.Encode()

	resp, err := q.makeRequest(ctx, req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// QRadar returns total count in X-Total-Count header
	if totalStr := resp.Header.Get("X-Total-Count"); totalStr != "" {
		if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil {
			return total, nil
		}
	}

	return 0, nil
}

// buildRequest builds an HTTP request for QRadar API
func (q *QRadarConnector) buildRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Request, error) {
	baseURL := q.sourceSystem.ConnectionConfig.BaseURL
	// Ensure the endpoint includes version
	if !strings.Contains(endpoint, "/api/") {
		endpoint = fmt.Sprintf("/api/%s%s", q.apiVersion, endpoint)
	}
	fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication headers
	if q.authHandler.IsAuthenticated() {
		authHeaders := q.authHandler.GetAuthHeaders()
		for key, value := range authHeaders {
			req.Header.Set(key, value)
		}
	}

	// Add default headers
	q.addDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", q.apiVersion)

	return req, nil
}

// eventToMap converts QRadarEvent to map[string]interface{}
func (q *QRadarConnector) eventToMap(event QRadarEvent) map[string]interface{} {
	result := make(map[string]interface{})
	
	// Convert struct to map using JSON marshaling
	data, _ := json.Marshal(event)
	json.Unmarshal(data, &result)
	
	return result
}

// offenseToMap converts QRadarOffense to map[string]interface{}
func (q *QRadarConnector) offenseToMap(offense QRadarOffense) map[string]interface{} {
	result := make(map[string]interface{})
	
	// Convert struct to map using JSON marshaling
	data, _ := json.Marshal(offense)
	json.Unmarshal(data, &result)
	
	return result
}

// getFieldsForDataType returns field schema for a data type
func (q *QRadarConnector) getFieldsForDataType(dataType entity.DataType) []connectors.FieldSchema {
	switch dataType {
	case entity.DataTypeEvents:
		return []connectors.FieldSchema{
			{Name: "id", Type: "integer", Required: true, Description: "Event ID"},
			{Name: "starttime", Type: "timestamp", Required: true, Description: "Event start time"},
			{Name: "eventcount", Type: "integer", Required: false, Description: "Event count"},
			{Name: "qid", Type: "integer", Required: true, Description: "QID (Rule ID)"},
			{Name: "severity", Type: "integer", Required: false, Description: "Event severity"},
			{Name: "category", Type: "integer", Required: false, Description: "Event category"},
			{Name: "sourceip", Type: "string", Required: false, Description: "Source IP address"},
			{Name: "destinationip", Type: "string", Required: false, Description: "Destination IP address"},
			{Name: "sourceport", Type: "integer", Required: false, Description: "Source port"},
			{Name: "destinationport", Type: "integer", Required: false, Description: "Destination port"},
			{Name: "protocol", Type: "integer", Required: false, Description: "Protocol number"},
			{Name: "username", Type: "string", Required: false, Description: "Username"},
		}
	case entity.DataTypeIncidents, entity.DataTypeAlerts:
		return []connectors.FieldSchema{
			{Name: "id", Type: "integer", Required: true, Description: "Offense ID"},
			{Name: "description", Type: "string", Required: true, Description: "Offense description"},
			{Name: "start_time", Type: "timestamp", Required: true, Description: "Offense start time"},
			{Name: "last_updated_time", Type: "timestamp", Required: false, Description: "Last updated time"},
			{Name: "status", Type: "string", Required: true, Description: "Offense status"},
			{Name: "magnitude", Type: "number", Required: false, Description: "Offense magnitude"},
			{Name: "severity", Type: "integer", Required: false, Description: "Offense severity"},
			{Name: "credibility", Type: "integer", Required: false, Description: "Offense credibility"},
			{Name: "relevance", Type: "integer", Required: false, Description: "Offense relevance"},
			{Name: "assigned_to", Type: "string", Required: false, Description: "Assigned user"},
			{Name: "event_count", Type: "integer", Required: false, Description: "Associated event count"},
			{Name: "source_count", Type: "integer", Required: false, Description: "Source count"},
		}
	case entity.DataTypeAssets:
		return []connectors.FieldSchema{
			{Name: "id", Type: "integer", Required: true, Description: "Asset ID"},
			{Name: "interfaces", Type: "array", Required: true, Description: "Network interfaces"},
			{Name: "properties", Type: "object", Required: false, Description: "Asset properties"},
			{Name: "vulnerabilities", Type: "array", Required: false, Description: "Asset vulnerabilities"},
		}
	default:
		return []connectors.FieldSchema{
			{Name: "id", Type: "string", Required: true, Description: "Record ID"},
		}
	}
}