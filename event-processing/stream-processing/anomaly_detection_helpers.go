package stream_processing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Helper methods for anomaly detection integration

// performUserBehaviorAnalysis performs user behavior analysis
func (a *AnomalyDetectionIntegration) performUserBehaviorAnalysis(ctx context.Context, request *AnomalyDetectionRequest) (*UserBehaviorAnalysis, error) {
	if a.config.UserBehaviorServiceURL == "" {
		return a.simulateUserBehaviorAnalysis(request), nil
	}
	
	url := fmt.Sprintf("%s/analyze/user", a.config.UserBehaviorServiceURL)
	
	// Create request payload
	payload := map[string]interface{}{
		"user_id":    request.UserID,
		"event_data": request.EventData,
		"timestamp":  request.Timestamp,
		"context":    request.RequestContext,
	}
	
	// Make HTTP request
	response, err := a.makeHTTPRequest(ctx, "POST", url, payload)
	if err != nil {
		return nil, err
	}
	
	var analysis UserBehaviorAnalysis
	if err := json.Unmarshal(response, &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse user behavior analysis response: %w", err)
	}
	
	return &analysis, nil
}

// performNetworkBehaviorAnalysis performs network behavior analysis
func (a *AnomalyDetectionIntegration) performNetworkBehaviorAnalysis(ctx context.Context, request *AnomalyDetectionRequest) (*NetworkBehaviorAnalysis, error) {
	if a.config.NetworkBehaviorServiceURL == "" {
		return a.simulateNetworkBehaviorAnalysis(request), nil
	}
	
	url := fmt.Sprintf("%s/analyze/network", a.config.NetworkBehaviorServiceURL)
	
	// Create request payload
	payload := map[string]interface{}{
		"source_ip":   request.SourceIP,
		"event_data":  request.EventData,
		"timestamp":   request.Timestamp,
		"context":     request.RequestContext,
	}
	
	// Make HTTP request
	response, err := a.makeHTTPRequest(ctx, "POST", url, payload)
	if err != nil {
		return nil, err
	}
	
	var analysis NetworkBehaviorAnalysis
	if err := json.Unmarshal(response, &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse network behavior analysis response: %w", err)
	}
	
	return &analysis, nil
}

// performProcessBehaviorAnalysis performs process behavior analysis
func (a *AnomalyDetectionIntegration) performProcessBehaviorAnalysis(ctx context.Context, request *AnomalyDetectionRequest) (*ProcessBehaviorAnalysis, error) {
	// For process analysis, we'll use a simplified implementation
	return a.simulateProcessBehaviorAnalysis(request), nil
}

// makeHTTPRequest makes an HTTP request with retry logic
func (a *AnomalyDetectionIntegration) makeHTTPRequest(ctx context.Context, method, url string, payload interface{}) ([]byte, error) {
	var lastErr error
	
	for attempt := 0; attempt < a.config.MaxRetries; attempt++ {
		// Create request body
		var requestBody *bytes.Buffer
		if payload != nil {
			jsonData, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request payload: %w", err)
			}
			requestBody = bytes.NewBuffer(jsonData)
		}
		
		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, method, url, requestBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "iSECTECH-StreamProcessor/1.0")
		
		// Make request
		resp, err := a.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < a.config.MaxRetries-1 {
				time.Sleep(a.config.RetryDelay * time.Duration(attempt+1))
				continue
			}
			break
		}
		defer resp.Body.Close()
		
		// Read response
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			if attempt < a.config.MaxRetries-1 {
				time.Sleep(a.config.RetryDelay * time.Duration(attempt+1))
				continue
			}
			break
		}
		
		// Check status code
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, nil
		}
		
		lastErr = fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
		if attempt < a.config.MaxRetries-1 {
			time.Sleep(a.config.RetryDelay * time.Duration(attempt+1))
			continue
		}
	}
	
	return nil, fmt.Errorf("HTTP request failed after %d attempts: %w", a.config.MaxRetries, lastErr)
}

// Simulation methods for testing/fallback

// simulateUserBehaviorAnalysis simulates user behavior analysis
func (a *AnomalyDetectionIntegration) simulateUserBehaviorAnalysis(request *AnomalyDetectionRequest) *UserBehaviorAnalysis {
	// Simple simulation based on event characteristics
	eventType := extractStringFromEvent(request.EventData, "type")
	sourceIP := extractStringFromEvent(request.EventData, "source_ip")
	userAgent := extractStringFromEvent(request.EventData, "user_agent")
	
	analysis := &UserBehaviorAnalysis{
		UserID:            request.UserID,
		BaselineDeviation: 0.1,
		AnomalousPatterns: []string{},
		RiskFactors:       []string{},
		BehaviorScore:     0.1,
	}
	
	// Check for anomalous patterns
	if eventType == "authentication_failed" {
		analysis.AnomalousPatterns = append(analysis.AnomalousPatterns, "multiple authentication failures")
		analysis.BehaviorScore += 0.3
	}
	
	if strings.Contains(sourceIP, "192.168.") == false && strings.Contains(sourceIP, "10.") == false {
		analysis.AnomalousPatterns = append(analysis.AnomalousPatterns, "external IP access")
		analysis.BehaviorScore += 0.2
	}
	
	if strings.Contains(userAgent, "bot") || strings.Contains(userAgent, "crawler") {
		analysis.AnomalousPatterns = append(analysis.AnomalousPatterns, "automated user agent")
		analysis.BehaviorScore += 0.4
	}
	
	// Time-based analysis
	hour := request.Timestamp.Hour()
	if hour < 6 || hour > 22 {
		analysis.TimeAnalysis = &TimeBasedAnalysis{
			IsOffHours:         true,
			UnusualTimePattern: true,
			TimeRiskScore:      0.3,
		}
		analysis.BehaviorScore += 0.3
	}
	
	// Normalize score
	if analysis.BehaviorScore > 1.0 {
		analysis.BehaviorScore = 1.0
	}
	
	return analysis
}

// simulateNetworkBehaviorAnalysis simulates network behavior analysis
func (a *AnomalyDetectionIntegration) simulateNetworkBehaviorAnalysis(request *AnomalyDetectionRequest) *NetworkBehaviorAnalysis {
	analysis := &NetworkBehaviorAnalysis{
		SourceIP:             request.SourceIP,
		TrafficPatterns:      []TrafficPattern{},
		AnomalousConnections: []AnomalousConnection{},
		GeoLocationRisk:      0.1,
		ReputationScore:      0.9,
		ThreatIntelMatch:     false,
	}
	
	// Check for suspicious IPs
	if strings.Contains(request.SourceIP, "192.168.") == false && 
	   strings.Contains(request.SourceIP, "10.") == false &&
	   strings.Contains(request.SourceIP, "172.") == false {
		analysis.GeoLocationRisk += 0.2
		analysis.ReputationScore -= 0.1
	}
	
	// Check for suspicious ports
	if destPort := extractIntFromEvent(request.EventData, "destination_port"); destPort > 0 {
		suspiciousPorts := []int{4444, 5555, 6666, 7777, 8080, 9999}
		for _, port := range suspiciousPorts {
			if destPort == port {
				analysis.AnomalousConnections = append(analysis.AnomalousConnections, AnomalousConnection{
					DestinationIP:   extractStringFromEvent(request.EventData, "destination_ip"),
					DestinationPort: destPort,
					Protocol:        extractStringFromEvent(request.EventData, "protocol"),
					AnomalyReason:   "suspicious port usage",
					RiskScore:       0.6,
				})
				analysis.GeoLocationRisk += 0.4
				break
			}
		}
	}
	
	return analysis
}

// simulateProcessBehaviorAnalysis simulates process behavior analysis
func (a *AnomalyDetectionIntegration) simulateProcessBehaviorAnalysis(request *AnomalyDetectionRequest) *ProcessBehaviorAnalysis {
	processName := extractStringFromEvent(request.EventData, "process_name")
	commandLine := extractStringFromEvent(request.EventData, "command_line")
	
	analysis := &ProcessBehaviorAnalysis{
		ProcessName:          processName,
		ProcessPath:          extractStringFromEvent(request.EventData, "process_path"),
		ParentProcess:        extractStringFromEvent(request.EventData, "parent_process"),
		CommandLine:          commandLine,
		BehaviorScore:        0.1,
		AnomalousActions:     []string{},
		SuspiciousIndicators: []SuspiciousIndicator{},
	}
	
	// Check for suspicious processes
	suspiciousProcesses := []string{"powershell", "cmd", "bash", "nc", "netcat", "wget", "curl"}
	for _, suspicious := range suspiciousProcesses {
		if strings.Contains(strings.ToLower(processName), suspicious) {
			analysis.AnomalousActions = append(analysis.AnomalousActions, fmt.Sprintf("suspicious process: %s", suspicious))
			analysis.BehaviorScore += 0.3
			break
		}
	}
	
	// Check for suspicious command line patterns
	suspiciousPatterns := []string{"powershell -enc", "cmd /c", "bash -c", "nc -l", "wget http", "curl http"}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(commandLine), pattern) {
			analysis.SuspiciousIndicators = append(analysis.SuspiciousIndicators, SuspiciousIndicator{
				Indicator:   pattern,
				Description: "Suspicious command line pattern detected",
				Severity:    "medium",
				Confidence:  0.7,
			})
			analysis.BehaviorScore += 0.4
			break
		}
	}
	
	// Normalize score
	if analysis.BehaviorScore > 1.0 {
		analysis.BehaviorScore = 1.0
	}
	
	return analysis
}

// determineAnalysisTypes determines which types of analysis to perform
func (a *AnomalyDetectionIntegration) determineAnalysisTypes(event map[string]interface{}) []string {
	var analysisTypes []string
	
	if a.config.EnableUserAnalysis && extractStringFromEvent(event, "user_id") != "" {
		analysisTypes = append(analysisTypes, "user_behavior")
	}
	
	if a.config.EnableNetworkAnalysis && extractStringFromEvent(event, "source_ip") != "" {
		analysisTypes = append(analysisTypes, "network_behavior")
	}
	
	if a.config.EnableProcessAnalysis && extractStringFromEvent(event, "process_name") != "" {
		analysisTypes = append(analysisTypes, "process_behavior")
	}
	
	return analysisTypes
}

// Cache management methods

// createCacheKey creates a cache key for an event
func (a *AnomalyDetectionIntegration) createCacheKey(event map[string]interface{}) string {
	// Create a hash of key event fields for caching
	keyFields := map[string]interface{}{
		"user_id":   extractStringFromEvent(event, "user_id"),
		"source_ip": extractStringFromEvent(event, "source_ip"),
		"type":      extractStringFromEvent(event, "type"),
		"timestamp": extractTimeFromEvent(event, "timestamp").Truncate(5 * time.Minute), // 5-minute buckets
	}
	
	jsonData, _ := json.Marshal(keyFields)
	hash := sha256.Sum256(jsonData)
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes of hash
}

// getCachedResult retrieves a cached anomaly result
func (a *AnomalyDetectionIntegration) getCachedResult(cacheKey string) *AnomalyDetectionResult {
	a.cacheMu.RLock()
	defer a.cacheMu.RUnlock()
	
	cached, exists := a.resultCache[cacheKey]
	if !exists {
		return nil
	}
	
	// Check if expired
	if time.Now().After(cached.ExpiresAt) {
		// Don't remove here to avoid write lock, cleanup will handle it
		return nil
	}
	
	return cached.Result
}

// cacheResult caches an anomaly detection result
func (a *AnomalyDetectionIntegration) cacheResult(cacheKey string, result *AnomalyDetectionResult) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	
	// Check cache size limit
	if len(a.resultCache) >= a.config.CacheSize {
		// Remove oldest entries (simple cleanup)
		a.cleanupOldestCacheEntries()
	}
	
	a.resultCache[cacheKey] = &CachedAnomalyResult{
		Result:    result,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(a.config.CacheTTL),
	}
}

// runCacheCleanup runs periodic cache cleanup
func (a *AnomalyDetectionIntegration) runCacheCleanup() {
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.cleanupTicker.C:
			a.performCacheCleanup()
		}
	}
}

// performCacheCleanup removes expired cache entries
func (a *AnomalyDetectionIntegration) performCacheCleanup() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	
	now := time.Now()
	expiredKeys := []string{}
	
	for key, cached := range a.resultCache {
		if now.After(cached.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	for _, key := range expiredKeys {
		delete(a.resultCache, key)
	}
	
	if len(expiredKeys) > 0 {
		a.logger.Debug("Cache cleanup completed",
			zap.Int("expired_entries", len(expiredKeys)),
			zap.Int("remaining_entries", len(a.resultCache)),
		)
	}
}

// cleanupOldestCacheEntries removes oldest cache entries to maintain size limit
func (a *AnomalyDetectionIntegration) cleanupOldestCacheEntries() {
	// Simple cleanup - remove 10% of entries
	removeCount := len(a.resultCache) / 10
	if removeCount < 1 {
		removeCount = 1
	}
	
	// Find oldest entries
	type cacheEntry struct {
		key      string
		cachedAt time.Time
	}
	
	var entries []cacheEntry
	for key, cached := range a.resultCache {
		entries = append(entries, cacheEntry{
			key:      key,
			cachedAt: cached.CachedAt,
		})
	}
	
	// Sort by cache time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].cachedAt.After(entries[j].cachedAt) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	
	// Remove oldest entries
	for i := 0; i < removeCount && i < len(entries); i++ {
		delete(a.resultCache, entries[i].key)
	}
}

// Utility functions for event field extraction

func extractStringFromEvent(event map[string]interface{}, field string) string {
	if value, exists := event[field]; exists {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}

func extractIntFromEvent(event map[string]interface{}, field string) int {
	if value, exists := event[field]; exists {
		if intValue, ok := value.(int); ok {
			return intValue
		}
		if floatValue, ok := value.(float64); ok {
			return int(floatValue)
		}
	}
	return 0
}

func extractTimeFromEvent(event map[string]interface{}, field string) time.Time {
	if value, exists := event[field]; exists {
		if timeValue, ok := value.(time.Time); ok {
			return timeValue
		}
		if strValue, ok := value.(string); ok {
			if parsedTime, err := time.Parse(time.RFC3339, strValue); err == nil {
				return parsedTime
			}
		}
	}
	return time.Now()
}