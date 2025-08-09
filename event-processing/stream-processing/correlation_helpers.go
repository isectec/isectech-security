package stream_processing

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Helper methods for correlation engine

// convertToCorrelatedEvent converts a raw event to a CorrelatedEvent
func (e *EventCorrelationEngine) convertToCorrelatedEvent(event map[string]interface{}) *CorrelatedEvent {
	correlatedEvent := &CorrelatedEvent{
		EventID:   extractStringValue(event, "id"),
		EventType: extractStringValue(event, "type"),
		Timestamp: extractTimeValue(event, "timestamp"),
		SourceIP:  extractStringValue(event, "source_ip"),
		UserID:    extractStringValue(event, "user_id"),
		AssetID:   extractStringValue(event, "asset_id"),
		Severity:  extractStringValue(event, "severity"),
		Metadata:  make(map[string]interface{}),
	}
	
	// Copy all other fields to metadata
	for k, v := range event {
		if k != "id" && k != "type" && k != "timestamp" && k != "source_ip" && 
		   k != "user_id" && k != "asset_id" && k != "severity" {
			correlatedEvent.Metadata[k] = v
		}
	}
	
	return correlatedEvent
}

// evaluateCorrelationRule evaluates if an event matches a correlation rule
func (e *EventCorrelationEngine) evaluateCorrelationRule(rule *CorrelationRule, event *CorrelatedEvent) bool {
	matchedConditions := 0
	totalWeight := 0.0
	matchedWeight := 0.0
	
	for _, condition := range rule.Conditions {
		totalWeight += condition.Weight
		
		if e.evaluateCondition(condition, event) {
			matchedConditions++
			matchedWeight += condition.Weight
		}
	}
	
	// Rule matches if more than 70% of weighted conditions are met
	if totalWeight > 0 && (matchedWeight/totalWeight) >= 0.7 {
		return true
	}
	
	return false
}

// evaluateCondition evaluates a single correlation condition
func (e *EventCorrelationEngine) evaluateCondition(condition CorrelationCondition, event *CorrelatedEvent) bool {
	var fieldValue interface{}
	
	// Get field value from event
	switch condition.Field {
	case "event_type":
		fieldValue = event.EventType
	case "source_ip":
		fieldValue = event.SourceIP
	case "user_id":
		fieldValue = event.UserID
	case "asset_id":
		fieldValue = event.AssetID
	case "severity":
		fieldValue = event.Severity
	default:
		// Check in metadata
		if val, exists := event.Metadata[condition.Field]; exists {
			fieldValue = val
		} else {
			return false
		}
	}
	
	// Evaluate condition based on operator
	switch condition.Operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", condition.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", condition.Value))
	case "matches":
		// Simple pattern matching (could be enhanced with regex)
		pattern := fmt.Sprintf("%v", condition.Value)
		value := fmt.Sprintf("%v", fieldValue)
		return strings.Contains(value, pattern)
	case "in_range":
		// For numeric ranges (simplified implementation)
		return true // Would need proper range evaluation
	default:
		return false
	}
}

// detectAttackPattern detects if an event matches an attack pattern
func (e *EventCorrelationEngine) detectAttackPattern(pattern *AttackPattern, event *CorrelatedEvent) *AttackChain {
	// Simple attack pattern detection (could be much more sophisticated)
	// This would typically involve looking at sequences of events over time
	
	for _, stage := range pattern.Stages {
		if e.eventMatchesStage(event, stage) {
			// Check if we have other stages of this attack pattern in recent events
			if e.hasOtherAttackStages(pattern, event) {
				return &AttackChain{
					PatternID:   pattern.ID,
					PatternName: pattern.Name,
					Stages: []DetectedStage{
						{
							StageName:  stage.Name,
							Events:     []CorrelatedEvent{*event},
							Timestamp:  event.Timestamp,
							Confidence: 0.8,
						},
					},
					Confidence: 0.8,
					Severity:   pattern.Severity,
					StartTime:  event.Timestamp,
					EndTime:    event.Timestamp,
					Metadata:   make(map[string]interface{}),
				}
			}
		}
	}
	
	return nil
}

// eventMatchesStage checks if an event matches an attack stage
func (e *EventCorrelationEngine) eventMatchesStage(event *CorrelatedEvent, stage AttackStage) bool {
	// Check if event type matches
	eventTypeMatches := false
	for _, eventType := range stage.EventTypes {
		if event.EventType == eventType {
			eventTypeMatches = true
			break
		}
	}
	
	if !eventTypeMatches {
		return false
	}
	
	// Check conditions
	for _, condition := range stage.Conditions {
		if !e.evaluateCondition(condition, event) {
			return false
		}
	}
	
	return true
}

// hasOtherAttackStages checks if we have evidence of other stages of an attack pattern
func (e *EventCorrelationEngine) hasOtherAttackStages(pattern *AttackPattern, currentEvent *CorrelatedEvent) bool {
	// Look for related events in user/IP sessions
	if currentEvent.UserID != "" {
		if userSession, exists := e.userSessions[currentEvent.UserID]; exists {
			return e.checkSessionForAttackStages(pattern, userSession.Events, currentEvent)
		}
	}
	
	if currentEvent.SourceIP != "" {
		if ipSession, exists := e.ipSessions[currentEvent.SourceIP]; exists {
			return e.checkSessionForAttackStages(pattern, ipSession.Events, currentEvent)
		}
	}
	
	return false
}

// checkSessionForAttackStages checks session events for attack pattern stages
func (e *EventCorrelationEngine) checkSessionForAttackStages(pattern *AttackPattern, sessionEvents []CorrelatedEvent, currentEvent *CorrelatedEvent) bool {
	stageMatches := 0
	
	for _, stage := range pattern.Stages {
		for _, sessionEvent := range sessionEvents {
			// Skip current event
			if sessionEvent.EventID == currentEvent.EventID {
				continue
			}
			
			// Check if event is within time window
			timeDiff := currentEvent.Timestamp.Sub(sessionEvent.Timestamp)
			if timeDiff > 0 && timeDiff <= stage.TimeWindow {
				if e.eventMatchesStage(&sessionEvent, stage) {
					stageMatches++
					break
				}
			}
		}
	}
	
	// Need at least 2 stages for attack chain detection
	return stageMatches >= 1
}

// runCleanup runs periodic cleanup of old sessions and events
func (e *EventCorrelationEngine) runCleanup() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.cleanupTicker.C:
			e.performCleanup()
		}
	}
}

// performCleanup removes old sessions and events
func (e *EventCorrelationEngine) performCleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	now := time.Now()
	cleanupThreshold := now.Add(-e.config.SessionTimeoutWindow * 2)
	
	// Clean up correlation sessions
	for sessionID, session := range e.correlationSessions {
		if session.LastActivity.Before(cleanupThreshold) {
			delete(e.correlationSessions, sessionID)
		}
	}
	
	// Clean up user sessions
	for userID, session := range e.userSessions {
		if session.LastActivity.Before(cleanupThreshold) {
			delete(e.userSessions, userID)
		}
	}
	
	// Clean up IP sessions
	for ip, session := range e.ipSessions {
		if session.LastActivity.Before(cleanupThreshold) {
			delete(e.ipSessions, ip)
		}
	}
	
	// Clean up time windows
	for windowKey, window := range e.eventWindows {
		if window.EndTime.Before(cleanupThreshold) {
			delete(e.eventWindows, windowKey)
		}
	}
	
	// Check if we have too many sessions and clean up oldest if needed
	if len(e.correlationSessions) > e.config.MaxSessions {
		e.cleanupOldestSessions()
	}
	
	e.logger.Debug("Correlation cleanup completed",
		zap.Int("correlation_sessions", len(e.correlationSessions)),
		zap.Int("user_sessions", len(e.userSessions)),
		zap.Int("ip_sessions", len(e.ipSessions)),
		zap.Int("time_windows", len(e.eventWindows)),
	)
}

// cleanupOldestSessions removes the oldest sessions to maintain limits
func (e *EventCorrelationEngine) cleanupOldestSessions() {
	// Create slice of sessions with their last activity times
	type sessionActivity struct {
		id           string
		lastActivity time.Time
	}
	
	var sessions []sessionActivity
	for id, session := range e.correlationSessions {
		sessions = append(sessions, sessionActivity{
			id:           id,
			lastActivity: session.LastActivity,
		})
	}
	
	// Sort by last activity (oldest first)
	for i := 0; i < len(sessions)-1; i++ {
		for j := i + 1; j < len(sessions); j++ {
			if sessions[i].lastActivity.After(sessions[j].lastActivity) {
				sessions[i], sessions[j] = sessions[j], sessions[i]
			}
		}
	}
	
	// Remove oldest sessions until we're under the limit
	removeCount := len(e.correlationSessions) - e.config.MaxSessions + 100 // Remove extra to avoid frequent cleanup
	for i := 0; i < removeCount && i < len(sessions); i++ {
		delete(e.correlationSessions, sessions[i].id)
	}
}

// initializeDefaultRules initializes default correlation rules
func (e *EventCorrelationEngine) initializeDefaultRules() {
	// Failed login attempts rule
	failedLoginRule := &CorrelationRule{
		ID:          "failed_login_attempts",
		Name:        "Multiple Failed Login Attempts",
		Description: "Detects multiple failed login attempts from the same source",
		Conditions: []CorrelationCondition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "authentication_failed",
				Weight:   1.0,
			},
		},
		TimeWindow: 5 * time.Minute,
		MinEvents:  3,
		Weight:     0.8,
		Priority:   1,
		Enabled:    true,
	}
	
	// Suspicious file access rule
	fileAccessRule := &CorrelationRule{
		ID:          "suspicious_file_access",
		Name:        "Suspicious File Access Pattern",
		Description: "Detects unusual file access patterns",
		Conditions: []CorrelationCondition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "file_access",
				Weight:   1.0,
			},
			{
				Field:    "file_path",
				Operator: "contains",
				Value:    "sensitive",
				Weight:   0.5,
			},
		},
		TimeWindow: 10 * time.Minute,
		MinEvents:  5,
		Weight:     0.6,
		Priority:   2,
		Enabled:    true,
	}
	
	e.correlationRules = []*CorrelationRule{failedLoginRule, fileAccessRule}
}

// initializeDefaultAttackPatterns initializes default attack patterns
func (e *EventCorrelationEngine) initializeDefaultAttackPatterns() {
	// Brute force attack pattern
	bruteForcePattern := &AttackPattern{
		ID:          "brute_force_attack",
		Name:        "Brute Force Attack",
		Description: "Multi-stage brute force attack pattern",
		Stages: []AttackStage{
			{
				Name:       "reconnaissance",
				EventTypes: []string{"port_scan", "service_enumeration"},
				Conditions: []CorrelationCondition{
					{
						Field:    "severity",
						Operator: "equals",
						Value:    "medium",
						Weight:   1.0,
					},
				},
				TimeWindow: 1 * time.Hour,
				Optional:   true,
			},
			{
				Name:       "initial_access_attempt",
				EventTypes: []string{"authentication_failed"},
				Conditions: []CorrelationCondition{
					{
						Field:    "event_type",
						Operator: "equals",
						Value:    "authentication_failed",
						Weight:   1.0,
					},
				},
				TimeWindow: 30 * time.Minute,
				Optional:   false,
			},
		},
		Severity: "high",
		MITRE:    []string{"T1110"},
	}
	
	e.attackPatterns = []*AttackPattern{bruteForcePattern}
}

// Utility functions

func extractStringValue(data map[string]interface{}, key string) string {
	if value, exists := data[key]; exists {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}

func extractTimeValue(data map[string]interface{}, key string) time.Time {
	if value, exists := data[key]; exists {
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}