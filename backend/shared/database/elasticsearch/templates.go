package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.uber.org/zap"
)

// TemplateManager handles index templates and component templates for iSECTECH
type TemplateManager struct {
	client *Client
	config *Config
	logger *zap.Logger
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(client *Client, config *Config, logger *zap.Logger) (*TemplateManager, error) {
	return &TemplateManager{
		client: client,
		config: config,
		logger: logger,
	}, nil
}

// CreateComponentTemplates creates all configured component templates
func (tm *TemplateManager) CreateComponentTemplates(ctx context.Context) error {
	tm.logger.Info("Creating component templates")

	for templateName, template := range tm.config.Indices.ComponentTemplates {
		if err := tm.CreateComponentTemplate(ctx, templateName, template); err != nil {
			return fmt.Errorf("failed to create component template %s: %w", templateName, err)
		}

		tm.logger.Info("Component template created",
			zap.String("template", templateName))
	}

	return nil
}

// CreateComponentTemplate creates a single component template
func (tm *TemplateManager) CreateComponentTemplate(ctx context.Context, templateName string, template ComponentTemplate) error {
	templateBytes, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to serialize component template: %w", err)
	}

	req := esapi.ClusterPutComponentTemplateRequest{
		Name: templateName,
		Body: bytes.NewReader(templateBytes),
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return fmt.Errorf("failed to create component template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create component template failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// CreateIndexTemplates creates all configured index templates
func (tm *TemplateManager) CreateIndexTemplates(ctx context.Context) error {
	tm.logger.Info("Creating index templates")

	for templateName, template := range tm.config.Indices.Templates {
		if err := tm.CreateIndexTemplate(ctx, templateName, template); err != nil {
			return fmt.Errorf("failed to create index template %s: %w", templateName, err)
		}

		tm.logger.Info("Index template created",
			zap.String("template", templateName))
	}

	return nil
}

// CreateIndexTemplate creates a single index template
func (tm *TemplateManager) CreateIndexTemplate(ctx context.Context, templateName string, template IndexTemplate) error {
	templateBytes, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to serialize index template: %w", err)
	}

	req := esapi.IndicesPutIndexTemplateRequest{
		Name: templateName,
		Body: bytes.NewReader(templateBytes),
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return fmt.Errorf("failed to create index template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create index template failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// UpdateComponentTemplate updates an existing component template
func (tm *TemplateManager) UpdateComponentTemplate(ctx context.Context, templateName string, template ComponentTemplate) error {
	return tm.CreateComponentTemplate(ctx, templateName, template) // PUT operation updates if exists
}

// UpdateIndexTemplate updates an existing index template
func (tm *TemplateManager) UpdateIndexTemplate(ctx context.Context, templateName string, template IndexTemplate) error {
	return tm.CreateIndexTemplate(ctx, templateName, template) // PUT operation updates if exists
}

// DeleteComponentTemplate deletes a component template
func (tm *TemplateManager) DeleteComponentTemplate(ctx context.Context, templateName string) error {
	req := esapi.ClusterDeleteComponentTemplateRequest{
		Name: templateName,
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return fmt.Errorf("failed to delete component template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			return fmt.Errorf("component template not found: %s", templateName)
		}
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("delete component template failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// DeleteIndexTemplate deletes an index template
func (tm *TemplateManager) DeleteIndexTemplate(ctx context.Context, templateName string) error {
	req := esapi.IndicesDeleteIndexTemplateRequest{
		Name: templateName,
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return fmt.Errorf("failed to delete index template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			return fmt.Errorf("index template not found: %s", templateName)
		}
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("delete index template failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// GetComponentTemplate retrieves a component template
func (tm *TemplateManager) GetComponentTemplate(ctx context.Context, templateName string) (*ComponentTemplate, error) {
	req := esapi.ClusterGetComponentTemplateRequest{
		Name: templateName,
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get component template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			return nil, fmt.Errorf("component template not found: %s", templateName)
		}
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get component template failed with status %s: %s", res.Status(), string(body))
	}

	var response struct {
		ComponentTemplates []struct {
			Name               string            `json:"name"`
			ComponentTemplate ComponentTemplate `json:"component_template"`
		} `json:"component_templates"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse component template response: %w", err)
	}

	if len(response.ComponentTemplates) == 0 {
		return nil, fmt.Errorf("component template not found: %s", templateName)
	}

	return &response.ComponentTemplates[0].ComponentTemplate, nil
}

// GetIndexTemplate retrieves an index template
func (tm *TemplateManager) GetIndexTemplate(ctx context.Context, templateName string) (*IndexTemplate, error) {
	req := esapi.IndicesGetIndexTemplateRequest{
		Name: templateName,
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get index template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			return nil, fmt.Errorf("index template not found: %s", templateName)
		}
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get index template failed with status %s: %s", res.Status(), string(body))
	}

	var response struct {
		IndexTemplates []struct {
			Name          string        `json:"name"`
			IndexTemplate IndexTemplate `json:"index_template"`
		} `json:"index_templates"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse index template response: %w", err)
	}

	if len(response.IndexTemplates) == 0 {
		return nil, fmt.Errorf("index template not found: %s", templateName)
	}

	return &response.IndexTemplates[0].IndexTemplate, nil
}

// ListComponentTemplates lists all component templates
func (tm *TemplateManager) ListComponentTemplates(ctx context.Context) (map[string]ComponentTemplate, error) {
	req := esapi.ClusterGetComponentTemplateRequest{}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to list component templates: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("list component templates failed with status %s: %s", res.Status(), string(body))
	}

	var response struct {
		ComponentTemplates []struct {
			Name               string            `json:"name"`
			ComponentTemplate ComponentTemplate `json:"component_template"`
		} `json:"component_templates"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse component templates response: %w", err)
	}

	templates := make(map[string]ComponentTemplate)
	for _, template := range response.ComponentTemplates {
		templates[template.Name] = template.ComponentTemplate
	}

	return templates, nil
}

// ListIndexTemplates lists all index templates
func (tm *TemplateManager) ListIndexTemplates(ctx context.Context) (map[string]IndexTemplate, error) {
	req := esapi.IndicesGetIndexTemplateRequest{}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to list index templates: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("list index templates failed with status %s: %s", res.Status(), string(body))
	}

	var response struct {
		IndexTemplates []struct {
			Name          string        `json:"name"`
			IndexTemplate IndexTemplate `json:"index_template"`
		} `json:"index_templates"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse index templates response: %w", err)
	}

	templates := make(map[string]IndexTemplate)
	for _, template := range response.IndexTemplates {
		templates[template.Name] = template.IndexTemplate
	}

	return templates, nil
}

// ValidateTemplates validates all configured templates
func (tm *TemplateManager) ValidateTemplates(ctx context.Context) error {
	tm.logger.Info("Validating templates")

	// Validate component templates
	for templateName := range tm.config.Indices.ComponentTemplates {
		_, err := tm.GetComponentTemplate(ctx, templateName)
		if err != nil {
			return fmt.Errorf("component template validation failed for %s: %w", templateName, err)
		}

		tm.logger.Info("Component template validated",
			zap.String("template", templateName))
	}

	// Validate index templates
	for templateName := range tm.config.Indices.Templates {
		_, err := tm.GetIndexTemplate(ctx, templateName)
		if err != nil {
			return fmt.Errorf("index template validation failed for %s: %w", templateName, err)
		}

		tm.logger.Info("Index template validated",
			zap.String("template", templateName))
	}

	return nil
}

// CreateBootstrapIndices creates initial indices using templates
func (tm *TemplateManager) CreateBootstrapIndices(ctx context.Context) error {
	tm.logger.Info("Creating bootstrap indices")

	// Create initial indices for each template
	for templateName, template := range tm.config.Indices.Templates {
		if len(template.IndexPatterns) == 0 {
			continue
		}

		// Create the first index matching the pattern
		indexPattern := template.IndexPatterns[0]
		indexName := tm.config.GetIndexName(templateName, tm.getBootstrapTime())

		// Check if pattern matches the generated name
		if !tm.matchesPattern(indexName, indexPattern) {
			// Generate a name that matches the pattern
			indexName = tm.generateMatchingIndexName(indexPattern)
		}

		if err := tm.createBootstrapIndex(ctx, indexName, template); err != nil {
			return fmt.Errorf("failed to create bootstrap index %s: %w", indexName, err)
		}

		tm.logger.Info("Bootstrap index created",
			zap.String("index", indexName),
			zap.String("template", templateName))
	}

	return nil
}

// createBootstrapIndex creates a single bootstrap index
func (tm *TemplateManager) createBootstrapIndex(ctx context.Context, indexName string, template IndexTemplate) error {
	// Check if index already exists
	req := esapi.IndicesExistsRequest{
		Index: []string{indexName},
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return fmt.Errorf("failed to check index existence: %w", err)
	}
	res.Body.Close()

	if res.StatusCode == 200 {
		// Index already exists
		return nil
	}

	// Create the index (template will be applied automatically)
	createReq := esapi.IndicesCreateRequest{
		Index: indexName,
	}

	createRes, err := createReq.Do(ctx, tm.client.client)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer createRes.Body.Close()

	if createRes.IsError() {
		body, _ := io.ReadAll(createRes.Body)
		return fmt.Errorf("create index failed with status %s: %s", createRes.Status(), string(body))
	}

	return nil
}

// matchesPattern checks if an index name matches a pattern
func (tm *TemplateManager) matchesPattern(indexName, pattern string) bool {
	// Simple wildcard matching for now
	// In production, you might want to use a more sophisticated pattern matcher
	if pattern == "*" {
		return true
	}

	// Check for suffix wildcard
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(indexName) >= len(prefix) && indexName[:len(prefix)] == prefix
	}

	// Exact match
	return indexName == pattern
}

// generateMatchingIndexName generates an index name that matches a pattern
func (tm *TemplateManager) generateMatchingIndexName(pattern string) string {
	if pattern == "*" {
		return "default-index"
	}

	// Handle suffix wildcard
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return fmt.Sprintf("%s%s", prefix, tm.getBootstrapTime().Format("2006.01.02"))
	}

	// Return pattern as-is if no wildcards
	return pattern
}

// getBootstrapTime returns the current time for bootstrap index naming
func (tm *TemplateManager) getBootstrapTime() time.Time {
	return time.Now()
}

// UpgradeTemplates upgrades templates to newer versions
func (tm *TemplateManager) UpgradeTemplates(ctx context.Context) error {
	tm.logger.Info("Upgrading templates")

	// Get existing templates
	existingComponentTemplates, err := tm.ListComponentTemplates(ctx)
	if err != nil {
		return fmt.Errorf("failed to list existing component templates: %w", err)
	}

	existingIndexTemplates, err := tm.ListIndexTemplates(ctx)
	if err != nil {
		return fmt.Errorf("failed to list existing index templates: %w", err)
	}

	// Update component templates if versions differ
	for templateName, newTemplate := range tm.config.Indices.ComponentTemplates {
		if existingTemplate, exists := existingComponentTemplates[templateName]; exists {
			if existingTemplate.Version < newTemplate.Version {
				tm.logger.Info("Upgrading component template",
					zap.String("template", templateName),
					zap.Int("old_version", existingTemplate.Version),
					zap.Int("new_version", newTemplate.Version))

				if err := tm.UpdateComponentTemplate(ctx, templateName, newTemplate); err != nil {
					return fmt.Errorf("failed to upgrade component template %s: %w", templateName, err)
				}
			}
		}
	}

	// Update index templates if versions differ
	for templateName, newTemplate := range tm.config.Indices.Templates {
		if existingTemplate, exists := existingIndexTemplates[templateName]; exists {
			if existingTemplate.Version < newTemplate.Version {
				tm.logger.Info("Upgrading index template",
					zap.String("template", templateName),
					zap.Int("old_version", existingTemplate.Version),
					zap.Int("new_version", newTemplate.Version))

				if err := tm.UpdateIndexTemplate(ctx, templateName, newTemplate); err != nil {
					return fmt.Errorf("failed to upgrade index template %s: %w", templateName, err)
				}
			}
		}
	}

	tm.logger.Info("Template upgrade completed")
	return nil
}

// GetTemplateUsage returns information about template usage
func (tm *TemplateManager) GetTemplateUsage(ctx context.Context) (map[string]interface{}, error) {
	// Get all indices
	req := esapi.CatIndicesRequest{
		Format: "json",
	}

	res, err := req.Do(ctx, tm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get indices: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get indices failed with status %s: %s", res.Status(), string(body))
	}

	var indices []struct {
		Index string `json:"index"`
	}

	if err := json.NewDecoder(res.Body).Decode(&indices); err != nil {
		return nil, fmt.Errorf("failed to parse indices response: %w", err)
	}

	// Count template usage
	templateUsage := make(map[string]interface{})
	
	for templateName, template := range tm.config.Indices.Templates {
		matchCount := 0
		matchingIndices := []string{}

		for _, index := range indices {
			for _, pattern := range template.IndexPatterns {
				if tm.matchesPattern(index.Index, pattern) {
					matchCount++
					matchingIndices = append(matchingIndices, index.Index)
					break
				}
			}
		}

		templateUsage[templateName] = map[string]interface{}{
			"match_count":     matchCount,
			"matching_indices": matchingIndices,
			"patterns":        template.IndexPatterns,
		}
	}

	return templateUsage, nil
}