package elasticsearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/sony/gobreaker"
	"go.uber.org/zap"

	"github.com/isectech/platform/shared/common"
)

// Client represents an Elasticsearch client for iSECTECH cybersecurity platform
type Client struct {
	config         *Config
	client         *elasticsearch.Client
	logger         *zap.Logger
	circuitBreaker *gobreaker.CircuitBreaker
	mu             sync.RWMutex
	closed         bool
}

// TenantContext represents tenant information for multi-tenancy
type TenantContext struct {
	TenantID             string
	UserID               string
	Role                 string
	SecurityClearance    string
	Permissions          []string
	DataClassifications  []string
}

// SearchOptions represents options for search operations
type SearchOptions struct {
	Index            string
	Tenant           *TenantContext
	Size             int
	From             int
	Sort             []map[string]interface{}
	Source           []string
	SourceExcludes   []string
	TrackTotalHits   bool
	Timeout          time.Duration
	IncludeAudit     bool
}

// IndexOptions represents options for index operations
type IndexOptions struct {
	Index        string
	DocumentID   string
	Tenant       *TenantContext
	Refresh      string // true, false, wait_for
	Timeout      time.Duration
	VersionType  string
	Version      int64
	IncludeAudit bool
}

// BulkOperation represents a bulk operation
type BulkOperation struct {
	Action   string      // index, create, update, delete
	Index    string
	ID       string
	Document interface{}
	Tenant   *TenantContext
}

// SecurityEvent represents a cybersecurity event for indexing
type SecurityEvent struct {
	Timestamp              time.Time              `json:"@timestamp"`
	TenantID               string                 `json:"tenant_id"`
	EventType              string                 `json:"event_type"`
	Severity               string                 `json:"severity"`
	Source                 map[string]interface{} `json:"source"`
	Target                 map[string]interface{} `json:"target"`
	Description            string                 `json:"description"`
	RawData                map[string]interface{} `json:"raw_data"`
	NormalizedData         map[string]interface{} `json:"normalized_data"`
	Indicators             []ThreatIndicator      `json:"indicators"`
	MITREAttack            []string               `json:"mitre_attack"`
	RiskScore              int                    `json:"risk_score"`
	SecurityClassification string                 `json:"security_classification"`
	Tags                   []string               `json:"tags"`
	Location               *GeoPoint              `json:"location,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Type       string      `json:"type"`
	Value      interface{} `json:"value"`
	Confidence float64     `json:"confidence"`
	Source     string      `json:"source"`
	Context    string      `json:"context,omitempty"`
}

// GeoPoint represents a geographical point
type GeoPoint struct {
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
}

// ThreatIntelligence represents threat intelligence data
type ThreatIntelligence struct {
	Timestamp              time.Time              `json:"@timestamp"`
	TenantID               string                 `json:"tenant_id"`
	ThreatID               string                 `json:"threat_id"`
	ThreatType             string                 `json:"threat_type"`
	Severity               string                 `json:"severity"`
	Confidence             float64                `json:"confidence"`
	Indicators             []ThreatIndicator      `json:"indicators"`
	MITREAttack            []string               `json:"mitre_attack"`
	Source                 string                 `json:"source"`
	Description            string                 `json:"description"`
	Tags                   []string               `json:"tags"`
	SecurityClassification string                 `json:"security_classification"`
	ExpiresAt              time.Time              `json:"expires_at"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	Timestamp              time.Time              `json:"@timestamp"`
	TenantID               string                 `json:"tenant_id"`
	UserID                 string                 `json:"user_id"`
	Action                 string                 `json:"action"`
	ResourceType           string                 `json:"resource_type"`
	ResourceID             string                 `json:"resource_id"`
	SourceIP               string                 `json:"source_ip"`
	UserAgent              string                 `json:"user_agent"`
	Status                 string                 `json:"status"`
	Details                map[string]interface{} `json:"details"`
	SecurityClassification string                 `json:"security_classification"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// VulnerabilityScan represents a vulnerability scan result
type VulnerabilityScan struct {
	Timestamp              time.Time              `json:"@timestamp"`
	TenantID               string                 `json:"tenant_id"`
	AssetID                string                 `json:"asset_id"`
	VulnerabilityID        string                 `json:"vulnerability_id"`
	CVEID                  string                 `json:"cve_id"`
	Severity               string                 `json:"severity"`
	CVSSScore              float64                `json:"cvss_score"`
	Description            string                 `json:"description"`
	Remediation            string                 `json:"remediation"`
	Status                 string                 `json:"status"`
	SecurityClassification string                 `json:"security_classification"`
	ScanResult             map[string]interface{} `json:"scan_result"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// ComplianceReport represents a compliance assessment result
type ComplianceReport struct {
	Timestamp              time.Time              `json:"@timestamp"`
	TenantID               string                 `json:"tenant_id"`
	Framework              string                 `json:"framework"`
	RequirementID          string                 `json:"requirement_id"`
	Status                 string                 `json:"status"`
	Score                  int                    `json:"score"`
	Findings               string                 `json:"findings"`
	Remediation            []string               `json:"remediation"`
	SecurityClassification string                 `json:"security_classification"`
	AssessmentData         map[string]interface{} `json:"assessment_data"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// SearchResult represents search results
type SearchResult struct {
	TotalHits    int64                    `json:"total_hits"`
	MaxScore     float64                  `json:"max_score"`
	Hits         []Hit                    `json:"hits"`
	Aggregations map[string]interface{}   `json:"aggregations,omitempty"`
	ScrollID     string                   `json:"scroll_id,omitempty"`
	Suggest      map[string]interface{}   `json:"suggest,omitempty"`
	TimedOut     bool                     `json:"timed_out"`
	Took         int                      `json:"took"`
}

// Hit represents a search hit
type Hit struct {
	Index   string                 `json:"_index"`
	Type    string                 `json:"_type"`
	ID      string                 `json:"_id"`
	Score   float64                `json:"_score"`
	Source  map[string]interface{} `json:"_source"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
	Sort    []interface{}          `json:"sort,omitempty"`
}

// NewClient creates a new Elasticsearch client for iSECTECH
func NewClient(config *Config, logger *zap.Logger) (*Client, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Create Elasticsearch configuration
	esConfig := elasticsearch.Config{
		Addresses:            config.Addresses,
		Username:             config.Username,
		Password:             config.Password,
		APIKey:               config.APIKey,
		CloudID:              config.CloudID,
		DiscoverNodesOnStart: config.Cluster.DiscoverNodesOnStart,
		DiscoverNodesInterval: config.Cluster.DiscoverNodesInterval,
		EnableRetryOnTimeout: true,
		MaxRetries:           config.RetryConfig.MaxAttempts,
		RetryBackoff:         buildRetryBackoff(config.RetryConfig),
		Transport:            buildHTTPTransport(config),
	}

	// Create Elasticsearch client
	esClient, err := elasticsearch.NewClient(esConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}

	client := &Client{
		config: config,
		client: esClient,
		logger: logger,
	}

	// Create circuit breaker
	client.circuitBreaker = gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "elasticsearch-client",
		MaxRequests: config.CircuitBreaker.MaxRequests,
		Interval:    config.CircuitBreaker.Interval,
		Timeout:     config.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= config.CircuitBreaker.FailureThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("Circuit breaker state changed",
				zap.String("name", name),
				zap.String("from", from.String()),
				zap.String("to", to.String()))
		},
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping Elasticsearch: %w", err)
	}

	logger.Info("Elasticsearch client initialized successfully",
		zap.Strings("addresses", config.Addresses),
		zap.String("cluster_name", config.Cluster.Name))

	return client, nil
}

// buildRetryBackoff creates a retry backoff function
func buildRetryBackoff(retryConfig RetryConfig) func(int) time.Duration {
	return func(attempt int) time.Duration {
		backoff := retryConfig.InitialInterval
		for i := 0; i < attempt; i++ {
			backoff = time.Duration(float64(backoff) * retryConfig.Multiplier)
			if backoff > retryConfig.MaxInterval {
				backoff = retryConfig.MaxInterval
				break
			}
		}
		return backoff
	}
}

// buildHTTPTransport creates an HTTP transport with security settings
func buildHTTPTransport(config *Config) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.KeepAlive,
		DisableCompression:  false,
	}

	// Configure TLS if enabled
	if config.Security.EnableTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.Security.TLSConfig.InsecureSkipVerify,
			ServerName:         config.Security.TLSConfig.ServerName,
		}

		// Load certificates if provided
		if config.Security.TLSConfig.CertFile != "" && config.Security.TLSConfig.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(
				config.Security.TLSConfig.CertFile,
				config.Security.TLSConfig.KeyFile,
			)
			if err == nil {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		transport.TLSClientConfig = tlsConfig
	}

	return transport
}

// Ping tests the connection to Elasticsearch
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		res, err := c.client.Ping(
			c.client.Ping.WithContext(ctx),
		)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.IsError() {
			return nil, fmt.Errorf("ping failed with status: %s", res.Status())
		}

		return nil, nil
	})
	return err
}

// IndexSecurityEvent indexes a security event
func (c *Client) IndexSecurityEvent(ctx context.Context, event *SecurityEvent, opts *IndexOptions) error {
	if opts == nil {
		opts = &IndexOptions{}
	}

	// Apply tenant filtering
	if opts.Tenant != nil {
		event.TenantID = opts.Tenant.TenantID
		if !c.hasPermission(opts.Tenant, event.SecurityClassification) {
			return fmt.Errorf("insufficient permissions for security classification: %s", event.SecurityClassification)
		}
	}

	// Determine index name
	indexName := opts.Index
	if indexName == "" {
		indexName = c.config.GetIndexName("security-events", event.Timestamp)
	}

	return c.indexDocument(ctx, indexName, opts.DocumentID, event, opts)
}

// IndexThreatIntelligence indexes threat intelligence data
func (c *Client) IndexThreatIntelligence(ctx context.Context, threat *ThreatIntelligence, opts *IndexOptions) error {
	if opts == nil {
		opts = &IndexOptions{}
	}

	// Apply tenant filtering
	if opts.Tenant != nil {
		threat.TenantID = opts.Tenant.TenantID
		if !c.hasPermission(opts.Tenant, threat.SecurityClassification) {
			return fmt.Errorf("insufficient permissions for security classification: %s", threat.SecurityClassification)
		}
	}

	// Determine index name
	indexName := opts.Index
	if indexName == "" {
		indexName = c.config.GetIndexName("threat-intel", threat.Timestamp)
	}

	return c.indexDocument(ctx, indexName, opts.DocumentID, threat, opts)
}

// IndexAuditLog indexes an audit log entry
func (c *Client) IndexAuditLog(ctx context.Context, audit *AuditLog, opts *IndexOptions) error {
	if opts == nil {
		opts = &IndexOptions{}
	}

	// Apply tenant filtering
	if opts.Tenant != nil {
		audit.TenantID = opts.Tenant.TenantID
	}

	// Determine index name
	indexName := opts.Index
	if indexName == "" {
		indexName = c.config.GetIndexName("audit-logs", audit.Timestamp)
	}

	return c.indexDocument(ctx, indexName, opts.DocumentID, audit, opts)
}

// IndexVulnerabilityScan indexes a vulnerability scan result
func (c *Client) IndexVulnerabilityScan(ctx context.Context, vuln *VulnerabilityScan, opts *IndexOptions) error {
	if opts == nil {
		opts = &IndexOptions{}
	}

	// Apply tenant filtering
	if opts.Tenant != nil {
		vuln.TenantID = opts.Tenant.TenantID
		if !c.hasPermission(opts.Tenant, vuln.SecurityClassification) {
			return fmt.Errorf("insufficient permissions for security classification: %s", vuln.SecurityClassification)
		}
	}

	// Determine index name
	indexName := opts.Index
	if indexName == "" {
		indexName = c.config.GetIndexName("vuln-scans", vuln.Timestamp)
	}

	return c.indexDocument(ctx, indexName, opts.DocumentID, vuln, opts)
}

// IndexComplianceReport indexes a compliance report
func (c *Client) IndexComplianceReport(ctx context.Context, compliance *ComplianceReport, opts *IndexOptions) error {
	if opts == nil {
		opts = &IndexOptions{}
	}

	// Apply tenant filtering
	if opts.Tenant != nil {
		compliance.TenantID = opts.Tenant.TenantID
		if !c.hasPermission(opts.Tenant, compliance.SecurityClassification) {
			return fmt.Errorf("insufficient permissions for security classification: %s", compliance.SecurityClassification)
		}
	}

	// Determine index name
	indexName := opts.Index
	if indexName == "" {
		indexName = c.config.GetIndexName("compliance", compliance.Timestamp)
	}

	return c.indexDocument(ctx, indexName, opts.DocumentID, compliance, opts)
}

// indexDocument indexes a document with circuit breaker protection
func (c *Client) indexDocument(ctx context.Context, index, id string, document interface{}, opts *IndexOptions) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		// Serialize document
		docBytes, err := json.Marshal(document)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize document: %w", err)
		}

		// Prepare index request
		req := esapi.IndexRequest{
			Index:      index,
			DocumentID: id,
			Body:       bytes.NewReader(docBytes),
			Refresh:    opts.Refresh,
			Timeout:    opts.Timeout,
		}

		if opts.Version > 0 {
			req.Version = &opts.Version
			req.VersionType = opts.VersionType
		}

		// Execute request
		res, err := req.Do(ctx, c.client)
		if err != nil {
			return nil, fmt.Errorf("index request failed: %w", err)
		}
		defer res.Body.Close()

		if res.IsError() {
			body, _ := io.ReadAll(res.Body)
			return nil, fmt.Errorf("index failed with status %s: %s", res.Status(), string(body))
		}

		// Log audit if required
		if opts.IncludeAudit && opts.Tenant != nil {
			c.logIndexAudit(ctx, opts.Tenant, index, id, "index")
		}

		return nil, nil
	})

	return err
}

// Search performs a search operation
func (c *Client) Search(ctx context.Context, query map[string]interface{}, opts *SearchOptions) (*SearchResult, error) {
	if opts == nil {
		opts = &SearchOptions{}
	}

	// Apply tenant filtering to query
	if opts.Tenant != nil {
		query = c.addTenantFilter(query, opts.Tenant)
	}

	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		// Serialize query
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			return nil, fmt.Errorf("failed to encode query: %w", err)
		}

		// Prepare search request
		req := esapi.SearchRequest{
			Index: []string{opts.Index},
			Body:  &buf,
		}

		if opts.Size > 0 {
			req.Size = &opts.Size
		}
		if opts.From > 0 {
			req.From = &opts.From
		}
		if len(opts.Source) > 0 {
			req.Source = opts.Source
		}
		if len(opts.SourceExcludes) > 0 {
			req.SourceExcludes = opts.SourceExcludes
		}
		if opts.TrackTotalHits {
			trackTotal := true
			req.TrackTotalHits = &trackTotal
		}
		if opts.Timeout > 0 {
			req.Timeout = opts.Timeout
		}

		// Execute search
		res, err := req.Do(ctx, c.client)
		if err != nil {
			return nil, fmt.Errorf("search request failed: %w", err)
		}
		defer res.Body.Close()

		if res.IsError() {
			body, _ := io.ReadAll(res.Body)
			return nil, fmt.Errorf("search failed with status %s: %s", res.Status(), string(body))
		}

		// Parse response
		var searchResponse struct {
			Took     int  `json:"took"`
			TimedOut bool `json:"timed_out"`
			Hits     struct {
				Total struct {
					Value int64 `json:"value"`
				} `json:"total"`
				MaxScore float64 `json:"max_score"`
				Hits     []Hit   `json:"hits"`
			} `json:"hits"`
			Aggregations map[string]interface{} `json:"aggregations,omitempty"`
			ScrollID     string                 `json:"_scroll_id,omitempty"`
			Suggest      map[string]interface{} `json:"suggest,omitempty"`
		}

		if err := json.NewDecoder(res.Body).Decode(&searchResponse); err != nil {
			return nil, fmt.Errorf("failed to parse search response: %w", err)
		}

		result := &SearchResult{
			TotalHits:    searchResponse.Hits.Total.Value,
			MaxScore:     searchResponse.Hits.MaxScore,
			Hits:         searchResponse.Hits.Hits,
			Aggregations: searchResponse.Aggregations,
			ScrollID:     searchResponse.ScrollID,
			Suggest:      searchResponse.Suggest,
			TimedOut:     searchResponse.TimedOut,
			Took:         searchResponse.Took,
		}

		// Log audit if required
		if opts.IncludeAudit && opts.Tenant != nil {
			c.logSearchAudit(ctx, opts.Tenant, opts.Index, query)
		}

		return result, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*SearchResult), nil
}

// BulkIndex performs bulk indexing operations
func (c *Client) BulkIndex(ctx context.Context, operations []BulkOperation) error {
	_, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		var buf bytes.Buffer

		for _, op := range operations {
			// Create action header
			action := map[string]map[string]interface{}{
				op.Action: {
					"_index": op.Index,
				},
			}
			if op.ID != "" {
				action[op.Action]["_id"] = op.ID
			}

			// Write action header
			if err := json.NewEncoder(&buf).Encode(action); err != nil {
				return nil, fmt.Errorf("failed to encode bulk action: %w", err)
			}

			// Write document for index/create/update operations
			if op.Action != "delete" && op.Document != nil {
				// Apply tenant filtering
				if op.Tenant != nil {
					if doc, ok := op.Document.(map[string]interface{}); ok {
						doc["tenant_id"] = op.Tenant.TenantID
					}
				}

				if err := json.NewEncoder(&buf).Encode(op.Document); err != nil {
					return nil, fmt.Errorf("failed to encode bulk document: %w", err)
				}
			}
		}

		// Execute bulk request
		res, err := c.client.Bulk(
			&buf,
			c.client.Bulk.WithContext(ctx),
			c.client.Bulk.WithRefresh("true"),
		)
		if err != nil {
			return nil, fmt.Errorf("bulk request failed: %w", err)
		}
		defer res.Body.Close()

		if res.IsError() {
			body, _ := io.ReadAll(res.Body)
			return nil, fmt.Errorf("bulk operation failed with status %s: %s", res.Status(), string(body))
		}

		return nil, nil
	})

	return err
}

// addTenantFilter adds tenant isolation and security clearance filtering to a query
func (c *Client) addTenantFilter(query map[string]interface{}, tenant *TenantContext) map[string]interface{} {
	// Create tenant filter
	tenantFilter := map[string]interface{}{
		"term": map[string]interface{}{
			"tenant_id": tenant.TenantID,
		},
	}

	// Create security clearance filter
	var securityFilter map[string]interface{}
	if len(tenant.DataClassifications) > 0 {
		securityFilter = map[string]interface{}{
			"terms": map[string]interface{}{
				"security_classification": tenant.DataClassifications,
			},
		}
	}

	// Wrap existing query with bool query including filters
	wrappedQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": query["query"],
				"filter": []map[string]interface{}{
					tenantFilter,
				},
			},
		},
	}

	// Add security filter if applicable
	if securityFilter != nil {
		filters := wrappedQuery["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"].([]map[string]interface{})
		wrappedQuery["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = append(filters, securityFilter)
	}

	// Preserve other query elements
	for key, value := range query {
		if key != "query" {
			wrappedQuery[key] = value
		}
	}

	return wrappedQuery
}

// hasPermission checks if the tenant has permission for the given security classification
func (c *Client) hasPermission(tenant *TenantContext, classification string) bool {
	if len(tenant.DataClassifications) == 0 {
		return true // No restrictions
	}

	for _, allowed := range tenant.DataClassifications {
		if allowed == classification {
			return true
		}
	}

	return false
}

// logIndexAudit logs an audit entry for index operations
func (c *Client) logIndexAudit(ctx context.Context, tenant *TenantContext, index, docID, action string) {
	auditLog := &AuditLog{
		Timestamp:              time.Now(),
		TenantID:               tenant.TenantID,
		UserID:                 tenant.UserID,
		Action:                 fmt.Sprintf("elasticsearch_%s", action),
		ResourceType:           "document",
		ResourceID:             fmt.Sprintf("%s/%s", index, docID),
		Status:                 "success",
		SecurityClassification: "UNCLASSIFIED",
		Details: map[string]interface{}{
			"index":  index,
			"doc_id": docID,
			"action": action,
		},
	}

	// Index audit log asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c.IndexAuditLog(ctx, auditLog, &IndexOptions{
			Refresh: "false", // Don't wait for refresh on audit logs
		})
	}()
}

// logSearchAudit logs an audit entry for search operations
func (c *Client) logSearchAudit(ctx context.Context, tenant *TenantContext, index string, query map[string]interface{}) {
	auditLog := &AuditLog{
		Timestamp:              time.Now(),
		TenantID:               tenant.TenantID,
		UserID:                 tenant.UserID,
		Action:                 "elasticsearch_search",
		ResourceType:           "index",
		ResourceID:             index,
		Status:                 "success",
		SecurityClassification: "UNCLASSIFIED",
		Details: map[string]interface{}{
			"index": index,
			"query_hash": c.hashQuery(query),
		},
	}

	// Index audit log asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c.IndexAuditLog(ctx, auditLog, &IndexOptions{
			Refresh: "false",
		})
	}()
}

// hashQuery creates a hash of the query for audit purposes
func (c *Client) hashQuery(query map[string]interface{}) string {
	queryBytes, _ := json.Marshal(query)
	return fmt.Sprintf("%x", common.HashData(queryBytes))
}

// GetClusterHealth returns cluster health information
func (c *Client) GetClusterHealth(ctx context.Context) (map[string]interface{}, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		res, err := c.client.Cluster.Health(
			c.client.Cluster.Health.WithContext(ctx),
		)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.IsError() {
			return nil, fmt.Errorf("cluster health request failed with status: %s", res.Status())
		}

		var health map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&health); err != nil {
			return nil, fmt.Errorf("failed to parse cluster health response: %w", err)
		}

		return health, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(map[string]interface{}), nil
}

// GetClusterStats returns cluster statistics
func (c *Client) GetClusterStats(ctx context.Context) (map[string]interface{}, error) {
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		res, err := c.client.Cluster.Stats(
			c.client.Cluster.Stats.WithContext(ctx),
		)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.IsError() {
			return nil, fmt.Errorf("cluster stats request failed with status: %s", res.Status())
		}

		var stats map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&stats); err != nil {
			return nil, fmt.Errorf("failed to parse cluster stats response: %w", err)
		}

		return stats, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(map[string]interface{}), nil
}

// Health checks the health of the Elasticsearch connection
func (c *Client) Health(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return false
	}

	err := c.Ping(ctx)
	return err == nil
}

// Close closes the Elasticsearch client
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	c.logger.Info("Elasticsearch client closed")
	return nil
}