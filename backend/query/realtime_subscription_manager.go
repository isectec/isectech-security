package query

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RealtimeSubscriptionManager manages real-time data subscriptions for dashboards
type RealtimeSubscriptionManager struct {
	logger        *zap.Logger
	config        *SubscriptionConfig
	queryEngine   *DashboardQueryEngine
	
	// Subscription management
	subscriptions map[string]*RealtimeSubscription
	subsMutex     sync.RWMutex
	
	// Connection management
	connections   map[string]*WebSocketConnection
	connMutex     sync.RWMutex
	
	// Background processing
	ctx           context.Context
	cancel        context.CancelFunc
	cleanupTicker *time.Ticker
	
	// Statistics
	stats         *SubscriptionStats
	statsMutex    sync.RWMutex
}

// SubscriptionConfig defines subscription manager configuration
type SubscriptionConfig struct {
	MaxSubscriptions      int           `json:"max_subscriptions"`
	MaxConnectionsPerUser int           `json:"max_connections_per_user"`
	DefaultRefreshRate    time.Duration `json:"default_refresh_rate"`
	MinRefreshRate        time.Duration `json:"min_refresh_rate"`
	MaxRefreshRate        time.Duration `json:"max_refresh_rate"`
	ConnectionTimeout     time.Duration `json:"connection_timeout"`
	CleanupInterval       time.Duration `json:"cleanup_interval"`
	BufferSize            int           `json:"buffer_size"`
	CompressionEnabled    bool          `json:"compression_enabled"`
	MetricsEnabled        bool          `json:"metrics_enabled"`
}

// WebSocketConnection represents a WebSocket connection
type WebSocketConnection struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	SessionID    string                 `json:"session_id"`
	Connected    bool                   `json:"connected"`
	ConnectedAt  time.Time              `json:"connected_at"`
	LastActivity time.Time              `json:"last_activity"`
	Subscriptions map[string]bool       `json:"subscriptions"`
	SendChannel  chan *WebSocketMessage `json:"-"`
	Context      context.Context        `json:"-"`
	Cancel       context.CancelFunc     `json:"-"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type         string                 `json:"type"`
	SubscriptionID string               `json:"subscription_id,omitempty"`
	Data         interface{}            `json:"data,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// SubscriptionRequest represents a subscription request
type SubscriptionRequest struct {
	SubscriptionID string                 `json:"subscription_id"`
	DashboardID    string                 `json:"dashboard_id"`
	WidgetID       string                 `json:"widget_id"`
	Query          *DashboardQuery        `json:"query"`
	RefreshRate    time.Duration          `json:"refresh_rate"`
	Filters        map[string]interface{} `json:"filters"`
	UserID         string                 `json:"user_id"`
	SessionID      string                 `json:"session_id"`
}

// SubscriptionStats tracks subscription statistics
type SubscriptionStats struct {
	TotalSubscriptions    int64     `json:"total_subscriptions"`
	ActiveSubscriptions   int64     `json:"active_subscriptions"`
	TotalConnections      int64     `json:"total_connections"`
	ActiveConnections     int64     `json:"active_connections"`
	MessagesPerSecond     float64   `json:"messages_per_second"`
	AverageLatency        time.Duration `json:"average_latency"`
	ErrorCount            int64     `json:"error_count"`
	LastActivity          time.Time `json:"last_activity"`
}

// NewRealtimeSubscriptionManager creates a new subscription manager
func NewRealtimeSubscriptionManager(logger *zap.Logger, config *SubscriptionConfig, queryEngine *DashboardQueryEngine) (*RealtimeSubscriptionManager, error) {
	if config == nil {
		return nil, fmt.Errorf("subscription configuration is required")
	}
	
	// Set defaults
	if err := setSubscriptionDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &RealtimeSubscriptionManager{
		logger:        logger.With(zap.String("component", "realtime-subscription-manager")),
		config:        config,
		queryEngine:   queryEngine,
		subscriptions: make(map[string]*RealtimeSubscription),
		connections:   make(map[string]*WebSocketConnection),
		stats:         &SubscriptionStats{},
		ctx:           ctx,
		cancel:        cancel,
	}
	
	// Start background processing
	manager.cleanupTicker = time.NewTicker(config.CleanupInterval)
	go manager.runCleanupProcess()
	
	logger.Info("Realtime subscription manager initialized",
		zap.Int("max_subscriptions", config.MaxSubscriptions),
		zap.Duration("default_refresh_rate", config.DefaultRefreshRate),
		zap.Int("buffer_size", config.BufferSize),
	)
	
	return manager, nil
}

// setSubscriptionDefaults sets configuration defaults
func setSubscriptionDefaults(config *SubscriptionConfig) error {
	if config.MaxSubscriptions == 0 {
		config.MaxSubscriptions = 1000
	}
	if config.MaxConnectionsPerUser == 0 {
		config.MaxConnectionsPerUser = 10
	}
	if config.DefaultRefreshRate == 0 {
		config.DefaultRefreshRate = 5 * time.Second
	}
	if config.MinRefreshRate == 0 {
		config.MinRefreshRate = 1 * time.Second
	}
	if config.MaxRefreshRate == 0 {
		config.MaxRefreshRate = 5 * time.Minute
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 30 * time.Second
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}
	if config.BufferSize == 0 {
		config.BufferSize = 100
	}
	
	return nil
}

// CreateSubscription creates a new real-time subscription
func (rsm *RealtimeSubscriptionManager) CreateSubscription(ctx context.Context, request *SubscriptionRequest) (*RealtimeSubscription, error) {
	// Validate refresh rate
	if request.RefreshRate < rsm.config.MinRefreshRate {
		request.RefreshRate = rsm.config.MinRefreshRate
	}
	if request.RefreshRate > rsm.config.MaxRefreshRate {
		request.RefreshRate = rsm.config.MaxRefreshRate
	}
	
	// Check subscription limits
	rsm.subsMutex.RLock()
	if len(rsm.subscriptions) >= rsm.config.MaxSubscriptions {
		rsm.subsMutex.RUnlock()
		return nil, fmt.Errorf("maximum subscription limit reached")
	}
	rsm.subsMutex.RUnlock()
	
	// Create subscription context
	subCtx, subCancel := context.WithCancel(ctx)
	
	// Create subscription
	subscription := &RealtimeSubscription{
		ID:            request.SubscriptionID,
		DashboardID:   request.DashboardID,
		WidgetID:      request.WidgetID,
		Query:         request.Query,
		LastUpdate:    time.Time{}, // Force initial update
		UpdateChannel: make(chan *QueryResult, rsm.config.BufferSize),
		ErrorChannel:  make(chan error, rsm.config.BufferSize),
		Context:       subCtx,
		Cancel:        subCancel,
		Filters:       request.Filters,
		RefreshRate:   request.RefreshRate,
	}
	
	// Store subscription
	rsm.subsMutex.Lock()
	rsm.subscriptions[request.SubscriptionID] = subscription
	rsm.subsMutex.Unlock()
	
	// Update statistics
	rsm.statsMutex.Lock()
	rsm.stats.TotalSubscriptions++
	rsm.stats.ActiveSubscriptions++
	rsm.statsMutex.Unlock()
	
	// Start subscription processor
	go rsm.processSubscription(subscription)
	
	rsm.logger.Info("Subscription created",
		zap.String("subscription_id", request.SubscriptionID),
		zap.String("dashboard_id", request.DashboardID),
		zap.String("widget_id", request.WidgetID),
		zap.Duration("refresh_rate", request.RefreshRate),
	)
	
	return subscription, nil
}

// RemoveSubscription removes a subscription
func (rsm *RealtimeSubscriptionManager) RemoveSubscription(subscriptionID string) error {
	rsm.subsMutex.Lock()
	subscription, exists := rsm.subscriptions[subscriptionID]
	if exists {
		delete(rsm.subscriptions, subscriptionID)
	}
	rsm.subsMutex.Unlock()
	
	if !exists {
		return fmt.Errorf("subscription not found: %s", subscriptionID)
	}
	
	// Cancel subscription
	if subscription.Cancel != nil {
		subscription.Cancel()
	}
	
	// Close channels
	close(subscription.UpdateChannel)
	close(subscription.ErrorChannel)
	
	// Update statistics
	rsm.statsMutex.Lock()
	rsm.stats.ActiveSubscriptions--
	rsm.statsMutex.Unlock()
	
	rsm.logger.Info("Subscription removed", zap.String("subscription_id", subscriptionID))
	return nil
}

// CreateConnection creates a new WebSocket connection
func (rsm *RealtimeSubscriptionManager) CreateConnection(ctx context.Context, userID, sessionID string) (*WebSocketConnection, error) {
	// Check connection limits per user
	rsm.connMutex.RLock()
	userConnections := 0
	for _, conn := range rsm.connections {
		if conn.UserID == userID && conn.Connected {
			userConnections++
		}
	}
	rsm.connMutex.RUnlock()
	
	if userConnections >= rsm.config.MaxConnectionsPerUser {
		return nil, fmt.Errorf("maximum connections per user exceeded")
	}
	
	// Create connection context
	connCtx, connCancel := context.WithCancel(ctx)
	
	connectionID := fmt.Sprintf("conn_%s_%s_%d", userID, sessionID, time.Now().UnixNano())
	
	connection := &WebSocketConnection{
		ID:            connectionID,
		UserID:        userID,
		SessionID:     sessionID,
		Connected:     true,
		ConnectedAt:   time.Now(),
		LastActivity:  time.Now(),
		Subscriptions: make(map[string]bool),
		SendChannel:   make(chan *WebSocketMessage, rsm.config.BufferSize),
		Context:       connCtx,
		Cancel:        connCancel,
		Metadata:      make(map[string]interface{}),
	}
	
	// Store connection
	rsm.connMutex.Lock()
	rsm.connections[connectionID] = connection
	rsm.connMutex.Unlock()
	
	// Update statistics
	rsm.statsMutex.Lock()
	rsm.stats.TotalConnections++
	rsm.stats.ActiveConnections++
	rsm.statsMutex.Unlock()
	
	rsm.logger.Info("Connection created",
		zap.String("connection_id", connectionID),
		zap.String("user_id", userID),
		zap.String("session_id", sessionID),
	)
	
	return connection, nil
}

// RemoveConnection removes a WebSocket connection
func (rsm *RealtimeSubscriptionManager) RemoveConnection(connectionID string) error {
	rsm.connMutex.Lock()
	connection, exists := rsm.connections[connectionID]
	if exists {
		delete(rsm.connections, connectionID)
	}
	rsm.connMutex.Unlock()
	
	if !exists {
		return fmt.Errorf("connection not found: %s", connectionID)
	}
	
	// Cancel connection
	connection.Connected = false
	if connection.Cancel != nil {
		connection.Cancel()
	}
	
	// Close channel
	close(connection.SendChannel)
	
	// Remove associated subscriptions
	for subscriptionID := range connection.Subscriptions {
		rsm.RemoveSubscription(subscriptionID)
	}
	
	// Update statistics
	rsm.statsMutex.Lock()
	rsm.stats.ActiveConnections--
	rsm.statsMutex.Unlock()
	
	rsm.logger.Info("Connection removed", zap.String("connection_id", connectionID))
	return nil
}

// SubscribeConnection subscribes a connection to a subscription
func (rsm *RealtimeSubscriptionManager) SubscribeConnection(connectionID, subscriptionID string) error {
	rsm.connMutex.Lock()
	connection, exists := rsm.connections[connectionID]
	if exists {
		connection.Subscriptions[subscriptionID] = true
		connection.LastActivity = time.Now()
	}
	rsm.connMutex.Unlock()
	
	if !exists {
		return fmt.Errorf("connection not found: %s", connectionID)
	}
	
	rsm.logger.Debug("Connection subscribed",
		zap.String("connection_id", connectionID),
		zap.String("subscription_id", subscriptionID),
	)
	
	return nil
}

// UnsubscribeConnection unsubscribes a connection from a subscription
func (rsm *RealtimeSubscriptionManager) UnsubscribeConnection(connectionID, subscriptionID string) error {
	rsm.connMutex.Lock()
	connection, exists := rsm.connections[connectionID]
	if exists {
		delete(connection.Subscriptions, subscriptionID)
		connection.LastActivity = time.Now()
	}
	rsm.connMutex.Unlock()
	
	if !exists {
		return fmt.Errorf("connection not found: %s", connectionID)
	}
	
	rsm.logger.Debug("Connection unsubscribed",
		zap.String("connection_id", connectionID),
		zap.String("subscription_id", subscriptionID),
	)
	
	return nil
}

// processSubscription processes a subscription in a background goroutine
func (rsm *RealtimeSubscriptionManager) processSubscription(subscription *RealtimeSubscription) {
	ticker := time.NewTicker(subscription.RefreshRate)
	defer ticker.Stop()
	
	// Execute initial query
	rsm.executeSubscriptionQuery(subscription)
	
	for {
		select {
		case <-subscription.Context.Done():
			return
		case <-ticker.C:
			rsm.executeSubscriptionQuery(subscription)
		case result := <-subscription.UpdateChannel:
			rsm.broadcastResult(subscription.ID, result)
		case err := <-subscription.ErrorChannel:
			rsm.broadcastError(subscription.ID, err)
		}
	}
}

// executeSubscriptionQuery executes a subscription query
func (rsm *RealtimeSubscriptionManager) executeSubscriptionQuery(subscription *RealtimeSubscription) {
	ctx, cancel := context.WithTimeout(subscription.Context, 30*time.Second)
	defer cancel()
	
	// Apply dynamic filters
	query := *subscription.Query // Copy query
	for key, value := range subscription.Filters {
		query.Filters[key] = value
	}
	
	// Execute query
	result, err := rsm.queryEngine.ExecuteQuery(ctx, &query)
	if err != nil {
		rsm.statsMutex.Lock()
		rsm.stats.ErrorCount++
		rsm.statsMutex.Unlock()
		
		select {
		case subscription.ErrorChannel <- err:
		case <-ctx.Done():
		}
		return
	}
	
	// Update last update time
	subscription.LastUpdate = time.Now()
	
	// Send result
	select {
	case subscription.UpdateChannel <- result:
	case <-ctx.Done():
	}
}

// broadcastResult broadcasts a query result to all connected clients
func (rsm *RealtimeSubscriptionManager) broadcastResult(subscriptionID string, result *QueryResult) {
	message := &WebSocketMessage{
		Type:           "data",
		SubscriptionID: subscriptionID,
		Data:           result,
		Timestamp:      time.Now(),
	}
	
	rsm.broadcastMessage(subscriptionID, message)
}

// broadcastError broadcasts an error to all connected clients
func (rsm *RealtimeSubscriptionManager) broadcastError(subscriptionID string, err error) {
	message := &WebSocketMessage{
		Type:           "error",
		SubscriptionID: subscriptionID,
		Error:          err.Error(),
		Timestamp:      time.Now(),
	}
	
	rsm.broadcastMessage(subscriptionID, message)
}

// broadcastMessage broadcasts a message to all subscribed connections
func (rsm *RealtimeSubscriptionManager) broadcastMessage(subscriptionID string, message *WebSocketMessage) {
	rsm.connMutex.RLock()
	defer rsm.connMutex.RUnlock()
	
	messagesSent := 0
	
	for _, connection := range rsm.connections {
		if !connection.Connected {
			continue
		}
		
		if _, subscribed := connection.Subscriptions[subscriptionID]; !subscribed {
			continue
		}
		
		select {
		case connection.SendChannel <- message:
			messagesSent++
			connection.LastActivity = time.Now()
		default:
			// Channel is full, skip this connection
			rsm.logger.Warn("Connection channel full, skipping message",
				zap.String("connection_id", connection.ID),
				zap.String("subscription_id", subscriptionID),
			)
		}
	}
	
	// Update statistics
	if messagesSent > 0 {
		rsm.statsMutex.Lock()
		rsm.stats.LastActivity = time.Now()
		// Simple approximation of messages per second
		rsm.stats.MessagesPerSecond = (rsm.stats.MessagesPerSecond + float64(messagesSent)) / 2
		rsm.statsMutex.Unlock()
	}
	
	rsm.logger.Debug("Message broadcasted",
		zap.String("subscription_id", subscriptionID),
		zap.String("message_type", message.Type),
		zap.Int("connections_reached", messagesSent),
	)
}

// runCleanupProcess runs the background cleanup process
func (rsm *RealtimeSubscriptionManager) runCleanupProcess() {
	for {
		select {
		case <-rsm.ctx.Done():
			return
		case <-rsm.cleanupTicker.C:
			rsm.cleanupStaleConnections()
			rsm.cleanupOrphanedSubscriptions()
		}
	}
}

// cleanupStaleConnections removes stale connections
func (rsm *RealtimeSubscriptionManager) cleanupStaleConnections() {
	rsm.connMutex.Lock()
	defer rsm.connMutex.Unlock()
	
	now := time.Now()
	staleConnections := []string{}
	
	for id, connection := range rsm.connections {
		if !connection.Connected || now.Sub(connection.LastActivity) > rsm.config.ConnectionTimeout {
			staleConnections = append(staleConnections, id)
		}
	}
	
	for _, id := range staleConnections {
		connection := rsm.connections[id]
		delete(rsm.connections, id)
		
		// Close connection
		connection.Connected = false
		if connection.Cancel != nil {
			connection.Cancel()
		}
		close(connection.SendChannel)
		
		// Update statistics
		rsm.statsMutex.Lock()
		rsm.stats.ActiveConnections--
		rsm.statsMutex.Unlock()
		
		rsm.logger.Debug("Stale connection cleaned up", zap.String("connection_id", id))
	}
}

// cleanupOrphanedSubscriptions removes subscriptions without active connections
func (rsm *RealtimeSubscriptionManager) cleanupOrphanedSubscriptions() {
	rsm.subsMutex.RLock()
	subscriptionIDs := make([]string, 0, len(rsm.subscriptions))
	for id := range rsm.subscriptions {
		subscriptionIDs = append(subscriptionIDs, id)
	}
	rsm.subsMutex.RUnlock()
	
	rsm.connMutex.RLock()
	activeSubscriptions := make(map[string]bool)
	for _, connection := range rsm.connections {
		if connection.Connected {
			for subID := range connection.Subscriptions {
				activeSubscriptions[subID] = true
			}
		}
	}
	rsm.connMutex.RUnlock()
	
	// Remove orphaned subscriptions
	for _, subID := range subscriptionIDs {
		if !activeSubscriptions[subID] {
			rsm.RemoveSubscription(subID)
			rsm.logger.Debug("Orphaned subscription cleaned up", zap.String("subscription_id", subID))
		}
	}
}

// GetSubscription returns a subscription by ID
func (rsm *RealtimeSubscriptionManager) GetSubscription(subscriptionID string) (*RealtimeSubscription, error) {
	rsm.subsMutex.RLock()
	subscription, exists := rsm.subscriptions[subscriptionID]
	rsm.subsMutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("subscription not found: %s", subscriptionID)
	}
	
	return subscription, nil
}

// GetConnection returns a connection by ID
func (rsm *RealtimeSubscriptionManager) GetConnection(connectionID string) (*WebSocketConnection, error) {
	rsm.connMutex.RLock()
	connection, exists := rsm.connections[connectionID]
	rsm.connMutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("connection not found: %s", connectionID)
	}
	
	return connection, nil
}

// ListSubscriptions returns all active subscriptions
func (rsm *RealtimeSubscriptionManager) ListSubscriptions() []*RealtimeSubscription {
	rsm.subsMutex.RLock()
	defer rsm.subsMutex.RUnlock()
	
	subscriptions := make([]*RealtimeSubscription, 0, len(rsm.subscriptions))
	for _, sub := range rsm.subscriptions {
		subscriptions = append(subscriptions, sub)
	}
	
	return subscriptions
}

// ListConnections returns all active connections
func (rsm *RealtimeSubscriptionManager) ListConnections() []*WebSocketConnection {
	rsm.connMutex.RLock()
	defer rsm.connMutex.RUnlock()
	
	connections := make([]*WebSocketConnection, 0, len(rsm.connections))
	for _, conn := range rsm.connections {
		if conn.Connected {
			connections = append(connections, conn)
		}
	}
	
	return connections
}

// GetStats returns subscription manager statistics
func (rsm *RealtimeSubscriptionManager) GetStats() *SubscriptionStats {
	rsm.statsMutex.RLock()
	defer rsm.statsMutex.RUnlock()
	
	stats := *rsm.stats
	return &stats
}

// IsHealthy returns the health status
func (rsm *RealtimeSubscriptionManager) IsHealthy() bool {
	return rsm.queryEngine.IsHealthy()
}

// Close closes the subscription manager
func (rsm *RealtimeSubscriptionManager) Close() error {
	if rsm.cancel != nil {
		rsm.cancel()
	}
	
	if rsm.cleanupTicker != nil {
		rsm.cleanupTicker.Stop()
	}
	
	// Close all subscriptions
	rsm.subsMutex.Lock()
	for _, sub := range rsm.subscriptions {
		if sub.Cancel != nil {
			sub.Cancel()
		}
		close(sub.UpdateChannel)
		close(sub.ErrorChannel)
	}
	rsm.subscriptions = make(map[string]*RealtimeSubscription)
	rsm.subsMutex.Unlock()
	
	// Close all connections
	rsm.connMutex.Lock()
	for _, conn := range rsm.connections {
		conn.Connected = false
		if conn.Cancel != nil {
			conn.Cancel()
		}
		close(conn.SendChannel)
	}
	rsm.connections = make(map[string]*WebSocketConnection)
	rsm.connMutex.Unlock()
	
	rsm.logger.Info("Realtime subscription manager closed")
	return nil
}