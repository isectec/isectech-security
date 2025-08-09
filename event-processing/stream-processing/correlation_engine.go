package stream_processing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	"github.com/google/uuid"
)

// EventCorrelationEngine performs event correlation and attack chain detection
type EventCorrelationEngine struct {
	logger                *zap.Logger
	config                *CorrelationEngineConfig
	
	// Correlation state
	correlationSessions   map[string]*CorrelationSession
	eventWindows          map[string]*TimeWindow
	userSessions          map[string]*UserSession
	ipSessions            map[string]*IPSession
	
	// Correlation rules
	correlationRules      []*CorrelationRule
	attackPatterns        []*AttackPattern
	
	// Health and metrics
	isHealthy             bool
	mu                    sync.RWMutex
	
	// Background workers
	ctx                   context.Context
	cancel                context.CancelFunc
	cleanupTicker         *time.Ticker
}

// CorrelationEngineConfig defines configuration for correlation engine
type CorrelationEngineConfig struct {
	WindowSize           time.Duration `json:"window_size"`
	MaxDepth             int           `json:"max_depth"`
	SessionTimeoutWindow time.Duration `json:"session_timeout_window"`
	CleanupInterval      time.Duration `json:"cleanup_interval"`
	MaxSessions          int           `json:"max_sessions"`
	MaxEventsPerSession  int           `json:"max_events_per_session"`
}

// CorrelationSession represents a group of correlated events
type CorrelationSession struct {
	ID               string                 `json:"id"`
	Events           []CorrelatedEvent      `json:"events"`
	StartTime        time.Time              `json:"start_time"`
	LastActivity     time.Time              `json:"last_activity"`
	CorrelationType  string                 `json:"correlation_type"`
	CorrelationScore float64                `json:"correlation_score"`
	Metadata         map[string]interface{} `json:"metadata"`
	AttackChain      *AttackChain           `json:"attack_chain,omitempty"`
}

// CorrelatedEvent represents an event in a correlation session
type CorrelatedEvent struct {
	EventID     string                 `json:"event_id"`
	EventType   string                 `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	AssetID     string                 `json:"asset_id,omitempty"`
	Severity    string                 `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TimeWindow represents a sliding time window for correlation
type TimeWindow struct {
	Events    []CorrelatedEvent `json:"events"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
}

// UserSession represents events grouped by user activity
type UserSession struct {
	UserID       string            `json:"user_id"`
	Events       []CorrelatedEvent `json:"events"`
	StartTime    time.Time         `json:"start_time"`
	LastActivity time.Time         `json:"last_activity"`
	SourceIPs    []string          `json:"source_ips"`
	UserAgent    string            `json:"user_agent,omitempty"`
}

// IPSession represents events grouped by source IP
type IPSession struct {
	SourceIP     string            `json:"source_ip"`
	Events       []CorrelatedEvent `json:"events"`
	StartTime    time.Time         `json:"start_time"`
	LastActivity time.Time         `json:"last_activity"`
	UserIDs      []string          `json:"user_ids"`
	Countries    []string          `json:"countries,omitempty"`
}

// CorrelationRule defines rules for event correlation
type CorrelationRule struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Conditions    []CorrelationCondition `json:"conditions"`
	TimeWindow    time.Duration          `json:"time_window"`
	MinEvents     int                    `json:"min_events"`
	Weight        float64                `json:"weight"`
	Priority      int                    `json:"priority"`
	Enabled       bool                   `json:"enabled"`
}

// CorrelationCondition defines a condition for correlation
type CorrelationCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // equals, contains, matches, in_range
	Value    interface{} `json:"value"`
	Weight   float64     `json:"weight"`
}

// AttackPattern defines known attack patterns
type AttackPattern struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Stages      []AttackStage `json:"stages"`
	Severity    string        `json:"severity"`
	MITRE       []string      `json:"mitre_techniques,omitempty"`
}

// AttackStage defines a stage in an attack pattern
type AttackStage struct {
	Name        string                 `json:"name"`
	EventTypes  []string               `json:"event_types"`
	Conditions  []CorrelationCondition `json:"conditions"`
	TimeWindow  time.Duration          `json:"time_window"`
	Optional    bool                   `json:"optional"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AttackChain represents a detected attack chain
type AttackChain struct {
	PatternID   string                 `json:"pattern_id"`
	PatternName string                 `json:"pattern_name"`
	Stages      []DetectedStage        `json:"stages"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DetectedStage represents a detected stage in an attack chain
type DetectedStage struct {
	StageName string            `json:"stage_name"`
	Events    []CorrelatedEvent `json:"events"`
	Timestamp time.Time         `json:"timestamp"`
	Confidence float64          `json:"confidence"`
}

// NewEventCorrelationEngine creates a new event correlation engine
func NewEventCorrelationEngine(logger *zap.Logger, config *CorrelationEngineConfig) (*EventCorrelationEngine, error) {
	if config == nil {
		return nil, fmt.Errorf("correlation engine configuration is required")
	}
	
	// Set defaults
	if config.WindowSize == 0 {
		config.WindowSize = 5 * time.Minute
	}
	if config.MaxDepth == 0 {
		config.MaxDepth = 100
	}
	if config.SessionTimeoutWindow == 0 {
		config.SessionTimeoutWindow = 30 * time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 10000
	}
	if config.MaxEventsPerSession == 0 {
		config.MaxEventsPerSession = 1000
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &EventCorrelationEngine{
		logger:              logger.With(zap.String("component", "correlation-engine")),
		config:              config,
		correlationSessions: make(map[string]*CorrelationSession),
		eventWindows:        make(map[string]*TimeWindow),
		userSessions:        make(map[string]*UserSession),
		ipSessions:          make(map[string]*IPSession),
		correlationRules:    []*CorrelationRule{},
		attackPatterns:      []*AttackPattern{},
		isHealthy:           true,
		ctx:                 ctx,
		cancel:              cancel,
	}
	
	// Initialize default correlation rules
	engine.initializeDefaultRules()
	
	// Initialize default attack patterns
	engine.initializeDefaultAttackPatterns()
	
	// Start background cleanup
	engine.cleanupTicker = time.NewTicker(config.CleanupInterval)
	go engine.runCleanup()
	
	logger.Info("Event correlation engine initialized",
		zap.Duration("window_size", config.WindowSize),
		zap.Int("max_depth", config.MaxDepth),
		zap.Duration("session_timeout", config.SessionTimeoutWindow),
	)
	
	return engine, nil
}

// CorrelateEvent correlates an event with existing events and sessions
func (e *EventCorrelationEngine) CorrelateEvent(ctx context.Context, event map[string]interface{}) (*CorrelationResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	start := time.Now()
	
	// Convert event to correlated event
	correlatedEvent := e.convertToCorrelatedEvent(event)
	
	// Initialize correlation result
	result := &CorrelationResult{
		CorrelationID:      uuid.New().String(),
		SessionID:          "",
		CorrelatedEventIDs: []string{},
		CorrelationScore:   0.0,
	}
	
	// Perform different types of correlation
	e.performTimeWindowCorrelation(correlatedEvent, result)
	e.performUserSessionCorrelation(correlatedEvent, result)
	e.performIPSessionCorrelation(correlatedEvent, result)
	e.performRuleBasedCorrelation(correlatedEvent, result)
	e.performAttackChainDetection(correlatedEvent, result)
	
	// Update session with the event
	if result.SessionID != "" {
		if session, exists := e.correlationSessions[result.SessionID]; exists {
			session.Events = append(session.Events, *correlatedEvent)
			session.LastActivity = time.Now()
			session.CorrelationScore = result.CorrelationScore
			
			// Limit events per session
			if len(session.Events) > e.config.MaxEventsPerSession {
				session.Events = session.Events[len(session.Events)-e.config.MaxEventsPerSession:]
			}
		}
	} else {
		// Create new correlation session
		sessionID := uuid.New().String()
		session := &CorrelationSession{
			ID:               sessionID,
			Events:           []CorrelatedEvent{*correlatedEvent},
			StartTime:        time.Now(),
			LastActivity:     time.Now(),
			CorrelationType:  "new",
			CorrelationScore: 1.0,
			Metadata:         make(map[string]interface{}),
		}
		
		e.correlationSessions[sessionID] = session
		result.SessionID = sessionID
	}
	
	duration := time.Since(start)
	
	e.logger.Debug("Event correlation completed",
		zap.String("event_id", correlatedEvent.EventID),
		zap.String("session_id", result.SessionID),
		zap.Int("correlated_events", len(result.CorrelatedEventIDs)),
		zap.Float64("correlation_score", result.CorrelationScore),
		zap.Duration("duration", duration),
	)
	
	return result, nil
}

// performTimeWindowCorrelation performs time-based correlation
func (e *EventCorrelationEngine) performTimeWindowCorrelation(event *CorrelatedEvent, result *CorrelationResult) {
	windowKey := fmt.Sprintf("time_%s", event.EventType)
	
	// Get or create time window
	window, exists := e.eventWindows[windowKey]
	if !exists {
		window = &TimeWindow{
			Events:    []CorrelatedEvent{},
			StartTime: event.Timestamp.Add(-e.config.WindowSize),
			EndTime:   event.Timestamp,
		}
		e.eventWindows[windowKey] = window
	}
	
	// Update window boundaries
	window.EndTime = event.Timestamp
	window.StartTime = event.Timestamp.Add(-e.config.WindowSize)
	
	// Remove events outside the window
	validEvents := []CorrelatedEvent{}
	for _, windowEvent := range window.Events {
		if windowEvent.Timestamp.After(window.StartTime) {
			validEvents = append(validEvents, windowEvent)
			result.CorrelatedEventIDs = append(result.CorrelatedEventIDs, windowEvent.EventID)
		}
	}
	window.Events = validEvents
	
	// Add current event to window
	window.Events = append(window.Events, *event)
	
	// Calculate correlation score based on event density
	if len(window.Events) > 1 {
		result.CorrelationScore += float64(len(window.Events)) * 0.1
	}
}

// performUserSessionCorrelation performs user-based correlation
func (e *EventCorrelationEngine) performUserSessionCorrelation(event *CorrelatedEvent, result *CorrelationResult) {
	if event.UserID == "" {
		return
	}
	
	// Get or create user session
	userSession, exists := e.userSessions[event.UserID]
	if !exists {
		userSession = &UserSession{
			UserID:       event.UserID,
			Events:       []CorrelatedEvent{},
			StartTime:    event.Timestamp,
			LastActivity: event.Timestamp,
			SourceIPs:    []string{},
		}
		e.userSessions[event.UserID] = userSession
	}
	
	// Check if within session timeout window
	if event.Timestamp.Sub(userSession.LastActivity) < e.config.SessionTimeoutWindow {
		// Correlate with existing session events
		for _, sessionEvent := range userSession.Events {
			result.CorrelatedEventIDs = append(result.CorrelatedEventIDs, sessionEvent.EventID)
		}
		
		result.CorrelationScore += 0.5
		result.SessionID = fmt.Sprintf("user_%s", event.UserID)
	} else {
		// Start new session
		userSession.Events = []CorrelatedEvent{}
		userSession.StartTime = event.Timestamp
	}
	
	// Add current event to session
	userSession.Events = append(userSession.Events, *event)
	userSession.LastActivity = event.Timestamp
	
	// Track source IPs
	if event.SourceIP != "" && !contains(userSession.SourceIPs, event.SourceIP) {
		userSession.SourceIPs = append(userSession.SourceIPs, event.SourceIP)
		
		// Multiple IPs for same user might indicate account compromise
		if len(userSession.SourceIPs) > 2 {
			result.CorrelationScore += 0.3
		}
	}
}

// performIPSessionCorrelation performs IP-based correlation
func (e *EventCorrelationEngine) performIPSessionCorrelation(event *CorrelatedEvent, result *CorrelationResult) {
	if event.SourceIP == "" {
		return
	}
	
	// Get or create IP session
	ipSession, exists := e.ipSessions[event.SourceIP]
	if !exists {
		ipSession = &IPSession{
			SourceIP:     event.SourceIP,
			Events:       []CorrelatedEvent{},
			StartTime:    event.Timestamp,
			LastActivity: event.Timestamp,
			UserIDs:      []string{},
		}
		e.ipSessions[event.SourceIP] = ipSession
	}
	
	// Check if within session timeout window
	if event.Timestamp.Sub(ipSession.LastActivity) < e.config.SessionTimeoutWindow {
		// Correlate with existing session events
		for _, sessionEvent := range ipSession.Events {
			result.CorrelatedEventIDs = append(result.CorrelatedEventIDs, sessionEvent.EventID)
		}
		
		result.CorrelationScore += 0.4
		if result.SessionID == "" {
			result.SessionID = fmt.Sprintf("ip_%s", event.SourceIP)
		}
	} else {
		// Start new session
		ipSession.Events = []CorrelatedEvent{}
		ipSession.StartTime = event.Timestamp
	}
	
	// Add current event to session
	ipSession.Events = append(ipSession.Events, *event)
	ipSession.LastActivity = event.Timestamp
	
	// Track user IDs
	if event.UserID != "" && !contains(ipSession.UserIDs, event.UserID) {
		ipSession.UserIDs = append(ipSession.UserIDs, event.UserID)
		
		// Multiple users from same IP might indicate lateral movement
		if len(ipSession.UserIDs) > 2 {
			result.CorrelationScore += 0.4
		}
	}
}

// performRuleBasedCorrelation performs rule-based correlation
func (e *EventCorrelationEngine) performRuleBasedCorrelation(event *CorrelatedEvent, result *CorrelationResult) {
	for _, rule := range e.correlationRules {
		if !rule.Enabled {
			continue
		}
		
		if e.evaluateCorrelationRule(rule, event) {
			result.CorrelationScore += rule.Weight
			
			if result.SessionID == "" {
				result.SessionID = fmt.Sprintf("rule_%s_%s", rule.ID, event.EventID)
			}
		}
	}
}

// performAttackChainDetection performs attack chain detection
func (e *EventCorrelationEngine) performAttackChainDetection(event *CorrelatedEvent, result *CorrelationResult) {
	for _, pattern := range e.attackPatterns {
		if attackChain := e.detectAttackPattern(pattern, event); attackChain != nil {
			result.CorrelationScore += 1.0 // High score for attack chain detection
			
			// Update session with attack chain information
			if result.SessionID != "" {
				if session, exists := e.correlationSessions[result.SessionID]; exists {
					session.AttackChain = attackChain
					session.CorrelationType = "attack_chain"
				}
			}
		}
	}
}

// IsHealthy returns the health status of the correlation engine
func (e *EventCorrelationEngine) IsHealthy() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isHealthy
}