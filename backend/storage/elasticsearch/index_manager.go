package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.uber.org/zap"
)

// NewIndexManager creates a new index manager
func NewIndexManager(client *elasticsearch.Client, logger *zap.Logger, config *ElasticsearchConfig) *IndexManager {
	return &IndexManager{
		client:    client,
		logger:    logger.With(zap.String("component", "index-manager")),
		config:    config,
		templates: make(map[string]*IndexTemplate),
	}
}

// CreateIndex creates a new index with optional settings
func (im *IndexManager) CreateIndex(ctx context.Context, indexName string, settings map[string]interface{}) error {
	// Check if index already exists
	req := esapi.IndicesExistsRequest{Index: []string{indexName}}
	res, err := req.Do(ctx, im.client)
	if err != nil {
		return fmt.Errorf("failed to check index existence: %w", err)
	}
	res.Body.Close()
	
	if res.StatusCode == 200 {
		im.logger.Debug("Index already exists", zap.String("index", indexName))
		return nil
	}
	
	// Create index body
	body := map[string]interface{}{}
	if settings != nil {
		body["settings"] = settings
	} else {
		// Use default settings
		body["settings"] = map[string]interface{}{
			"number_of_shards":   im.config.DefaultShards,
			"number_of_replicas": im.config.DefaultReplicas,
			"refresh_interval":   im.config.RefreshInterval,
			"codec":              im.config.IndexCodec,
		}
	}
	
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return fmt.Errorf("failed to encode index settings: %w", err)
	}
	
	// Create index
	createReq := esapi.IndicesCreateRequest{
		Index: indexName,
		Body:  &buf,
	}
	
	createRes, err := createReq.Do(ctx, im.client)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer createRes.Body.Close()
	
	if createRes.IsError() {
		return fmt.Errorf("index creation failed: %s", createRes.Status())
	}
	
	im.logger.Info("Index created successfully", zap.String("index", indexName))
	return nil
}

// DeleteIndex deletes an index
func (im *IndexManager) DeleteIndex(ctx context.Context, indexName string) error {
	req := esapi.IndicesDeleteRequest{Index: []string{indexName}}
	res, err := req.Do(ctx, im.client)
	if err != nil {
		return fmt.Errorf("failed to delete index: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return fmt.Errorf("index deletion failed: %s", res.Status())
	}
	
	im.logger.Info("Index deleted successfully", zap.String("index", indexName))
	return nil
}

// GetIndexStats returns statistics for an index
func (im *IndexManager) GetIndexStats(ctx context.Context, indexName string) (*IndexStats, error) {
	req := esapi.IndicesStatsRequest{Index: []string{indexName}}
	res, err := req.Do(ctx, im.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get index stats: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return nil, fmt.Errorf("get index stats failed: %s", res.Status())
	}
	
	var stats IndexStatsResponse
	if err := json.NewDecoder(res.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode index stats: %w", err)
	}
	
	if indexStats, exists := stats.Indices[indexName]; exists {
		return &indexStats, nil
	}
	
	return nil, fmt.Errorf("index stats not found for: %s", indexName)
}

// IndexStats represents index statistics
type IndexStats struct {
	Primaries IndexStatsData `json:"primaries"`
	Total     IndexStatsData `json:"total"`
}

type IndexStatsData struct {
	Docs struct {
		Count   int64 `json:"count"`
		Deleted int64 `json:"deleted"`
	} `json:"docs"`
	Store struct {
		SizeInBytes int64 `json:"size_in_bytes"`
	} `json:"store"`
	Indexing struct {
		IndexTotal    int64         `json:"index_total"`
		IndexTime     string        `json:"index_time"`
		IndexCurrent  int64         `json:"index_current"`
		DeleteTotal   int64         `json:"delete_total"`
		DeleteTime    string        `json:"delete_time"`
		DeleteCurrent int64         `json:"delete_current"`
	} `json:"indexing"`
	Search struct {
		QueryTotal   int64  `json:"query_total"`
		QueryTime    string `json:"query_time"`
		QueryCurrent int64  `json:"query_current"`
		FetchTotal   int64  `json:"fetch_total"`
		FetchTime    string `json:"fetch_time"`
		FetchCurrent int64  `json:"fetch_current"`
	} `json:"search"`
}

type IndexStatsResponse struct {
	Indices map[string]IndexStats `json:"indices"`
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(client *elasticsearch.Client, logger *zap.Logger) *TemplateManager {
	return &TemplateManager{
		client:    client,
		logger:    logger.With(zap.String("component", "template-manager")),
		templates: make(map[string]*IndexTemplate),
	}
}

// CreateTemplate creates or updates an index template
func (tm *TemplateManager) CreateTemplate(ctx context.Context, template *IndexTemplate) error {
	// Build template body
	body := map[string]interface{}{
		"index_patterns": []string{template.Pattern},
		"order":          template.Order,
		"settings":       template.Settings,
		"mappings":       template.Mappings,
	}
	
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return fmt.Errorf("failed to encode template: %w", err)
	}
	
	// Create/update template
	req := esapi.IndicesPutTemplateRequest{
		Name: template.Name,
		Body: &buf,
	}
	
	res, err := req.Do(ctx, tm.client)
	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return fmt.Errorf("template creation failed: %s", res.Status())
	}
	
	// Store template
	tm.templates[template.Name] = template
	
	tm.logger.Info("Index template created successfully",
		zap.String("template", template.Name),
		zap.String("pattern", template.Pattern),
	)
	
	return nil
}

// DeleteTemplate deletes an index template
func (tm *TemplateManager) DeleteTemplate(ctx context.Context, templateName string) error {
	req := esapi.IndicesDeleteTemplateRequest{Name: templateName}
	res, err := req.Do(ctx, tm.client)
	if err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return fmt.Errorf("template deletion failed: %s", res.Status())
	}
	
	// Remove from cache
	delete(tm.templates, templateName)
	
	tm.logger.Info("Index template deleted successfully", zap.String("template", templateName))
	return nil
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(client *elasticsearch.Client, logger *zap.Logger) *LifecycleManager {
	return &LifecycleManager{
		client:   client,
		logger:   logger.With(zap.String("component", "lifecycle-manager")),
		policies: make(map[string]*LifecyclePolicy),
	}
}

// CreatePolicy creates or updates an ILM policy
func (lm *LifecycleManager) CreatePolicy(ctx context.Context, policy *LifecyclePolicy) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(policy.Policy); err != nil {
		return fmt.Errorf("failed to encode policy: %w", err)
	}
	
	// Create/update policy
	req := esapi.ILMPutLifecycleRequest{
		Policy: policy.Name,
		Body:   &buf,
	}
	
	res, err := req.Do(ctx, lm.client)
	if err != nil {
		return fmt.Errorf("failed to create ILM policy: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return fmt.Errorf("ILM policy creation failed: %s", res.Status())
	}
	
	// Store policy
	lm.policies[policy.Name] = policy
	
	lm.logger.Info("ILM policy created successfully", zap.String("policy", policy.Name))
	return nil
}

// DeletePolicy deletes an ILM policy
func (lm *LifecycleManager) DeletePolicy(ctx context.Context, policyName string) error {
	req := esapi.ILMDeleteLifecycleRequest{Policy: policyName}
	res, err := req.Do(ctx, lm.client)
	if err != nil {
		return fmt.Errorf("failed to delete ILM policy: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return fmt.Errorf("ILM policy deletion failed: %s", res.Status())
	}
	
	// Remove from cache
	delete(lm.policies, policyName)
	
	lm.logger.Info("ILM policy deleted successfully", zap.String("policy", policyName))
	return nil
}

// NewBulkProcessor creates a new bulk processor
func NewBulkProcessor(client *elasticsearch.Client, logger *zap.Logger, config *ElasticsearchConfig, ctx context.Context) *BulkProcessor {
	procCtx, cancel := context.WithCancel(ctx)
	
	bp := &BulkProcessor{
		client:      client,
		logger:      logger.With(zap.String("component", "bulk-processor")),
		config:      config,
		buffer:      make([]BulkOperation, 0, config.BulkSize),
		workers:     make(chan struct{}, config.BulkWorkers),
		ctx:         procCtx,
		cancel:      cancel,
	}
	
	// Initialize workers
	for i := 0; i < config.BulkWorkers; i++ {
		bp.workers <- struct{}{}
	}
	
	// Start flush ticker
	bp.flushTicker = time.NewTicker(config.BulkFlushInterval)
	go bp.runFlusher()
	
	return bp
}

// Add adds an operation to the bulk processor
func (bp *BulkProcessor) Add(operation BulkOperation) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	
	bp.buffer = append(bp.buffer, operation)
	
	// Check if we need to flush
	if len(bp.buffer) >= bp.config.BulkSize {
		return bp.flush()
	}
	
	return nil
}

// flush executes the bulk operations
func (bp *BulkProcessor) flush() error {
	if len(bp.buffer) == 0 {
		return nil
	}
	
	// Get a worker
	select {
	case <-bp.workers:
		defer func() { bp.workers <- struct{}{} }()
	case <-bp.ctx.Done():
		return bp.ctx.Err()
	}
	
	operations := make([]BulkOperation, len(bp.buffer))
	copy(operations, bp.buffer)
	bp.buffer = bp.buffer[:0]
	
	go bp.executeBulk(operations)
	
	return nil
}

// executeBulk executes bulk operations
func (bp *BulkProcessor) executeBulk(operations []BulkOperation) {
	start := time.Now()
	
	// Build bulk request body
	var buf bytes.Buffer
	for _, op := range operations {
		// Action line
		action := map[string]interface{}{
			op.Operation: map[string]interface{}{
				"_index": op.Index,
			},
		}
		if op.ID != "" {
			action[op.Operation].(map[string]interface{})["_id"] = op.ID
		}
		
		actionLine, _ := json.Marshal(action)
		buf.Write(actionLine)
		buf.WriteByte('\n')
		
		// Document line (for index/create operations)
		if op.Operation == "index" || op.Operation == "create" {
			docLine, _ := json.Marshal(op.Document)
			buf.Write(docLine)
			buf.WriteByte('\n')
		}
	}
	
	// Execute bulk request
	ctx, cancel := context.WithTimeout(bp.ctx, bp.config.BulkTimeout)
	defer cancel()
	
	req := esapi.BulkRequest{Body: &buf}
	res, err := req.Do(ctx, bp.client)
	if err != nil {
		bp.logger.Error("Bulk request failed", zap.Error(err), zap.Int("operations", len(operations)))
		return
	}
	defer res.Body.Close()
	
	if res.IsError() {
		bp.logger.Error("Bulk request returned error", zap.String("status", res.Status()))
		return
	}
	
	// Parse response
	var bulkRes BulkResponse
	if err := json.NewDecoder(res.Body).Decode(&bulkRes); err != nil {
		bp.logger.Error("Failed to decode bulk response", zap.Error(err))
		return
	}
	
	// Check for errors in individual operations
	errorCount := 0
	for _, item := range bulkRes.Items {
		for _, itemData := range item {
			if itemData.Error != nil {
				errorCount++
				bp.logger.Warn("Bulk operation failed",
					zap.String("index", itemData.Index),
					zap.String("id", itemData.ID),
					zap.String("error", itemData.Error.Reason),
				)
			}
		}
	}
	
	duration := time.Since(start)
	bp.logger.Debug("Bulk operations completed",
		zap.Int("total_operations", len(operations)),
		zap.Int("errors", errorCount),
		zap.Duration("duration", duration),
	)
}

// BulkResponse represents bulk operation response
type BulkResponse struct {
	Took   int                      `json:"took"`
	Errors bool                     `json:"errors"`
	Items  []map[string]BulkItem    `json:"items"`
}

type BulkItem struct {
	Index   string     `json:"_index"`
	ID      string     `json:"_id"`
	Version int        `json:"_version"`
	Result  string     `json:"result"`
	Status  int        `json:"status"`
	Error   *BulkError `json:"error,omitempty"`
}

type BulkError struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// runFlusher runs the periodic flush process
func (bp *BulkProcessor) runFlusher() {
	for {
		select {
		case <-bp.ctx.Done():
			// Final flush on shutdown
			bp.mu.Lock()
			bp.flush()
			bp.mu.Unlock()
			return
		case <-bp.flushTicker.C:
			bp.mu.Lock()
			if len(bp.buffer) > 0 {
				bp.flush()
			}
			bp.mu.Unlock()
		}
	}
}

// Close closes the bulk processor
func (bp *BulkProcessor) Close() error {
	if bp.cancel != nil {
		bp.cancel()
	}
	
	if bp.flushTicker != nil {
		bp.flushTicker.Stop()
	}
	
	// Final flush
	bp.mu.Lock()
	bp.flush()
	bp.mu.Unlock()
	
	bp.logger.Info("Bulk processor closed")
	return nil
}