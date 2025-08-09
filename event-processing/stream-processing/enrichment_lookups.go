package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Lookup methods for enrichment service

// lookupGeolocation performs IP geolocation lookup
func (s *EventEnrichmentService) lookupGeolocation(ctx context.Context, ip string) *GeolocationResult {
	// Check cache first
	cacheKey := fmt.Sprintf("geo_%s", ip)
	if cached := s.geoLocationCache.Get(cacheKey); cached != nil {
		if geoResult, ok := cached.(*GeolocationResult); ok {
			return geoResult
		}
	}
	
	// Perform lookup
	url := fmt.Sprintf("%s/lookup/%s", s.geolocationClient.BaseURL, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		s.logger.Error("Failed to create geolocation request", zap.Error(err))
		return nil
	}
	
	resp, err := s.geolocationClient.HTTPClient.Do(req)
	if err != nil {
		s.logger.Error("Geolocation lookup failed", zap.String("ip", ip), zap.Error(err))
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		s.logger.Warn("Geolocation lookup returned non-200 status",
			zap.String("ip", ip),
			zap.Int("status_code", resp.StatusCode),
		)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read geolocation response", zap.Error(err))
		return nil
	}
	
	var result GeolocationResult
	if err := json.Unmarshal(body, &result); err != nil {
		s.logger.Error("Failed to parse geolocation response", zap.Error(err))
		return nil
	}
	
	// Cache the result
	s.geoLocationCache.Set(cacheKey, &result, s.config.CacheTTL)
	
	s.logger.Debug("Geolocation lookup successful",
		zap.String("ip", ip),
		zap.String("country", result.Country),
		zap.String("city", result.City),
	)
	
	return &result
}

// lookupThreatIntel performs threat intelligence lookup across multiple sources
func (s *EventEnrichmentService) lookupThreatIntel(ctx context.Context, indicator, indicatorType string) []ThreatIntelResult {
	// Check cache first
	cacheKey := fmt.Sprintf("ti_%s_%s", indicatorType, indicator)
	if cached := s.threatIntelCache.Get(cacheKey); cached != nil {
		if tiResults, ok := cached.([]ThreatIntelResult); ok {
			return tiResults
		}
	}
	
	var results []ThreatIntelResult
	
	// Query all threat intelligence sources in parallel
	resultsChan := make(chan ThreatIntelResult, len(s.threatIntelClients))
	
	for _, client := range s.threatIntelClients {
		go func(tiClient *ThreatIntelClient) {
			if result := s.queryThreatIntelSource(ctx, tiClient, indicator, indicatorType); result != nil {
				resultsChan <- *result
			}
		}(client)
	}
	
	// Collect results with timeout
	timeout := time.After(s.config.RequestTimeout)
	for i := 0; i < len(s.threatIntelClients); i++ {
		select {
		case result := <-resultsChan:
			results = append(results, result)
		case <-timeout:
			s.logger.Warn("Threat intelligence lookup timeout",
				zap.String("indicator", indicator),
				zap.String("type", indicatorType),
			)
			break
		}
	}
	
	// Cache the results
	if len(results) > 0 {
		s.threatIntelCache.Set(cacheKey, results, s.config.CacheTTL)
	}
	
	return results
}

// queryThreatIntelSource queries a single threat intelligence source
func (s *EventEnrichmentService) queryThreatIntelSource(ctx context.Context, client *ThreatIntelClient, indicator, indicatorType string) *ThreatIntelResult {
	url := fmt.Sprintf("%s/lookup", client.URL)
	
	requestBody := map[string]interface{}{
		"indicator": indicator,
		"type":      indicatorType,
	}
	
	requestData, err := json.Marshal(requestBody)
	if err != nil {
		client.Logger.Error("Failed to marshal TI request", zap.Error(err))
		return nil
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		client.Logger.Error("Failed to create TI request", zap.Error(err))
		return nil
	}
	
	req.Header.Set("Content-Type", "application/json")
	if client.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.APIKey))
	}
	
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		client.Logger.Error("TI lookup failed",
			zap.String("indicator", indicator),
			zap.Error(err),
		)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		client.Logger.Warn("TI lookup returned non-200 status",
			zap.String("indicator", indicator),
			zap.Int("status_code", resp.StatusCode),
		)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		client.Logger.Error("Failed to read TI response", zap.Error(err))
		return nil
	}
	
	var result ThreatIntelResult
	if err := json.Unmarshal(body, &result); err != nil {
		client.Logger.Error("Failed to parse TI response", zap.Error(err))
		return nil
	}
	
	// Add source information
	result.Sources = []string{client.Name}
	
	client.Logger.Debug("TI lookup successful",
		zap.String("indicator", indicator),
		zap.Bool("is_malicious", result.IsMalicious),
		zap.Float64("confidence", result.Confidence),
	)
	
	return &result
}

// lookupUserBehavior performs user behavior baseline lookup
func (s *EventEnrichmentService) lookupUserBehavior(ctx context.Context, userID string) *UserBehaviorResult {
	// Check cache first
	cacheKey := fmt.Sprintf("user_behavior_%s", userID)
	if cached := s.userBehaviorCache.Get(cacheKey); cached != nil {
		if behaviorResult, ok := cached.(*UserBehaviorResult); ok {
			return behaviorResult
		}
	}
	
	url := fmt.Sprintf("%s/users/%s/behavior", s.userBehaviorClient.BaseURL, userID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		s.logger.Error("Failed to create user behavior request", zap.Error(err))
		return nil
	}
	
	resp, err := s.userBehaviorClient.HTTPClient.Do(req)
	if err != nil {
		s.logger.Error("User behavior lookup failed",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		s.logger.Warn("User behavior lookup returned non-200 status",
			zap.String("user_id", userID),
			zap.Int("status_code", resp.StatusCode),
		)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read user behavior response", zap.Error(err))
		return nil
	}
	
	var result UserBehaviorResult
	if err := json.Unmarshal(body, &result); err != nil {
		s.logger.Error("Failed to parse user behavior response", zap.Error(err))
		return nil
	}
	
	// Cache the result
	s.userBehaviorCache.Set(cacheKey, &result, s.config.CacheTTL)
	
	s.logger.Debug("User behavior lookup successful",
		zap.String("user_id", userID),
		zap.Float64("risk_score", result.RiskScore),
	)
	
	return &result
}

// lookupAssetInfo performs asset information lookup
func (s *EventEnrichmentService) lookupAssetInfo(ctx context.Context, assetID string) *AssetInfoResult {
	// Check cache first
	cacheKey := fmt.Sprintf("asset_info_%s", assetID)
	if cached := s.assetInfoCache.Get(cacheKey); cached != nil {
		if assetResult, ok := cached.(*AssetInfoResult); ok {
			return assetResult
		}
	}
	
	url := fmt.Sprintf("%s/assets/%s", s.assetInventoryClient.BaseURL, assetID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		s.logger.Error("Failed to create asset info request", zap.Error(err))
		return nil
	}
	
	resp, err := s.assetInventoryClient.HTTPClient.Do(req)
	if err != nil {
		s.logger.Error("Asset info lookup failed",
			zap.String("asset_id", assetID),
			zap.Error(err),
		)
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		s.logger.Warn("Asset info lookup returned non-200 status",
			zap.String("asset_id", assetID),
			zap.Int("status_code", resp.StatusCode),
		)
		return nil
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read asset info response", zap.Error(err))
		return nil
	}
	
	var result AssetInfoResult
	if err := json.Unmarshal(body, &result); err != nil {
		s.logger.Error("Failed to parse asset info response", zap.Error(err))
		return nil
	}
	
	// Cache the result
	s.assetInfoCache.Set(cacheKey, &result, s.config.CacheTTL)
	
	s.logger.Debug("Asset info lookup successful",
		zap.String("asset_id", assetID),
		zap.String("asset_name", result.AssetName),
		zap.String("criticality", result.Criticality),
	)
	
	return &result
}

// LRU Cache implementation

// NewLRUCache creates a new LRU cache
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*CacheEntry),
		order:    make([]string, 0, capacity),
	}
}

// Get retrieves a value from the cache
func (c *LRUCache) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.cache[key]
	if !exists {
		return nil
	}
	
	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.cache, key)
		c.removeFromOrder(key)
		c.mu.Unlock()
		c.mu.RLock()
		return nil
	}
	
	// Move to front (most recently used)
	c.mu.RUnlock()
	c.mu.Lock()
	c.moveToFront(key)
	c.mu.Unlock()
	c.mu.RLock()
	
	return entry.Value
}

// Set stores a value in the cache
func (c *LRUCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	entry := &CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}
	
	// Check if key already exists
	if _, exists := c.cache[key]; exists {
		c.cache[key] = entry
		c.moveToFront(key)
		return
	}
	
	// Check capacity
	if len(c.cache) >= c.capacity {
		// Remove least recently used
		if len(c.order) > 0 {
			lru := c.order[len(c.order)-1]
			delete(c.cache, lru)
			c.order = c.order[:len(c.order)-1]
		}
	}
	
	// Add new entry
	c.cache[key] = entry
	c.order = append([]string{key}, c.order...)
}

// moveToFront moves a key to the front of the order list
func (c *LRUCache) moveToFront(key string) {
	for i, k := range c.order {
		if k == key {
			// Remove from current position
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	// Add to front
	c.order = append([]string{key}, c.order...)
}

// removeFromOrder removes a key from the order list
func (c *LRUCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}