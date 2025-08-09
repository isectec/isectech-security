package scaling

import (
	"context"
	"fmt"
	"hash/crc32"
	"math"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LoadBalancer manages traffic distribution across processing nodes
type LoadBalancer struct {
	logger                *zap.Logger
	config                *ScalingConfig
	
	// Load balancing state
	activeNodes           map[string]*NodeInfo
	nodesMutex            sync.RWMutex
	
	// Load balancing strategies
	strategy              LoadBalancingStrategy
	strategies            map[string]LoadBalancingStrategy
	
	// Health monitoring
	healthChecker         *NodeHealthChecker
	
	// Request tracking
	requestTracker        *RequestTracker
	
	// Circuit breaker for each node
	circuitBreakers       map[string]*CircuitBreaker
	circuitMutex          sync.RWMutex
	
	// Statistics
	stats                 *LoadBalancerStats
	statsMutex            sync.RWMutex
	
	// Background processes
	ctx                   context.Context
	cancel                context.CancelFunc
	healthTicker          *time.Ticker
	statsTicker           *time.Ticker
}

// NodeInfo contains information about a processing node for load balancing
type NodeInfo struct {
	ID                    string            `json:"id"`
	Address               string            `json:"address"`
	Port                  int               `json:"port"`
	Weight                int               `json:"weight"`           // Weight for weighted algorithms
	MaxConnections        int               `json:"max_connections"`
	CurrentConnections    int               `json:"current_connections"`
	RequestsPerSecond     float64           `json:"requests_per_second"`
	AverageResponseTime   time.Duration     `json:"average_response_time"`
	Health                *NodeHealthInfo   `json:"health"`
	Status                NodeLoadStatus    `json:"status"`
	LastSeen              time.Time         `json:"last_seen"`
	AddedAt               time.Time         `json:"added_at"`
	
	// Performance metrics
	TotalRequests         int64             `json:"total_requests"`
	SuccessfulRequests    int64             `json:"successful_requests"`
	FailedRequests        int64             `json:"failed_requests"`
	AverageLatency        time.Duration     `json:"average_latency"`
	P95Latency            time.Duration     `json:"p95_latency"`
	P99Latency            time.Duration     `json:"p99_latency"`
	
	// Resource utilization
	CPUUsage              float64           `json:"cpu_usage"`
	MemoryUsage           float64           `json:"memory_usage"`
	NetworkIO             int64             `json:"network_io"`
	
	// Load balancing specific
	LastRequestTime       time.Time         `json:"last_request_time"`
	RequestQueue          []time.Time       `json:"request_queue"`
	Capacity              int               `json:"capacity"`
	LoadScore             float64           `json:"load_score"`
}

// NodeHealthInfo contains health information for load balancing decisions
type NodeHealthInfo struct {
	IsHealthy             bool              `json:"is_healthy"`
	HealthScore           float64           `json:"health_score"`      // 0-100
	LastHealthCheck       time.Time         `json:"last_health_check"`
	ConsecutiveFailures   int               `json:"consecutive_failures"`
	ResponseTimeHealth    float64           `json:"response_time_health"`
	ThroughputHealth      float64           `json:"throughput_health"`
	ResourceHealth        float64           `json:"resource_health"`
}

// NodeLoadStatus represents the load status of a node
type NodeLoadStatus string

const (
	NodeLoadStatusHealthy     NodeLoadStatus = "healthy"
	NodeLoadStatusDegraded    NodeLoadStatus = "degraded"
	NodeLoadStatusOverloaded  NodeLoadStatus = "overloaded"
	NodeLoadStatusUnavailable NodeLoadStatus = "unavailable"
	NodeLoadStatusDraining    NodeLoadStatus = "draining"
)

// LoadBalancingStrategy defines how requests are distributed
type LoadBalancingStrategy interface {
	SelectNode(ctx context.Context, nodes []*NodeInfo, request *Request) (*NodeInfo, error)
	GetName() string
	UpdateNodeMetrics(nodeID string, metrics *RequestMetrics)
	ShouldRetry(err error) bool
}

// Request represents a request to be load balanced
type Request struct {
	ID              string                 `json:"id"`
	ClientID        string                 `json:"client_id"`
	SessionID       string                 `json:"session_id,omitempty"`
	Path            string                 `json:"path"`
	Method          string                 `json:"method"`
	Headers         map[string]string      `json:"headers"`
	Body            []byte                 `json:"body,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	Priority        RequestPriority        `json:"priority"`
	Timeout         time.Duration          `json:"timeout"`
	RetryCount      int                    `json:"retry_count"`
	MaxRetries      int                    `json:"max_retries"`
	Context         map[string]interface{} `json:"context"`
	
	// Load balancing hints
	PreferredNode   string                 `json:"preferred_node,omitempty"`
	StickySession   bool                   `json:"sticky_session"`
	RequiredCapabilities []string          `json:"required_capabilities"`
}

// RequestPriority defines request priority levels
type RequestPriority string

const (
	RequestPriorityLow      RequestPriority = "low"
	RequestPriorityMedium   RequestPriority = "medium"
	RequestPriorityHigh     RequestPriority = "high"
	RequestPriorityCritical RequestPriority = "critical"
)

// RequestMetrics contains metrics about a completed request
type RequestMetrics struct {
	RequestID       string        `json:"request_id"`
	NodeID          string        `json:"node_id"`
	Duration        time.Duration `json:"duration"`
	StatusCode      int           `json:"status_code"`
	BytesTransferred int64        `json:"bytes_transferred"`
	Success         bool          `json:"success"`
	ErrorMessage    string        `json:"error_message,omitempty"`
	Timestamp       time.Time     `json:"timestamp"`
}

// LoadBalancerStats tracks load balancer statistics
type LoadBalancerStats struct {
	TotalRequests         int64                    `json:"total_requests"`
	SuccessfulRequests    int64                    `json:"successful_requests"`
	FailedRequests        int64                    `json:"failed_requests"`
	AverageLatency        time.Duration            `json:"average_latency"`
	RequestsPerSecond     float64                  `json:"requests_per_second"`
	NodeDistribution      map[string]int64         `json:"node_distribution"`
	StrategyStats         map[string]*StrategyStats `json:"strategy_stats"`
	CircuitBreakerTrips   int64                    `json:"circuit_breaker_trips"`
	RetryCount            int64                    `json:"retry_count"`
	LastStatsUpdate       time.Time                `json:"last_stats_update"`
}

// StrategyStats tracks statistics for specific load balancing strategies
type StrategyStats struct {
	RequestsHandled       int64         `json:"requests_handled"`
	AverageSelectionTime  time.Duration `json:"average_selection_time"`
	NodeUtilizationBalance float64      `json:"node_utilization_balance"`
	FailoverCount         int64         `json:"failover_count"`
}

// RequestTracker tracks active requests and their routing
type RequestTracker struct {
	activeRequests        map[string]*ActiveRequest
	requestsMutex         sync.RWMutex
	
	// Session tracking for sticky sessions
	sessionToNode         map[string]string
	sessionMutex          sync.RWMutex
	
	// Request history for analytics
	requestHistory        []*CompletedRequest
	historyMutex          sync.RWMutex
	maxHistorySize        int
}

// ActiveRequest represents an active request being processed
type ActiveRequest struct {
	Request     *Request  `json:"request"`
	NodeID      string    `json:"node_id"`
	StartTime   time.Time `json:"start_time"`
	LastUpdate  time.Time `json:"last_update"`
	RetryCount  int       `json:"retry_count"`
}

// CompletedRequest represents a completed request
type CompletedRequest struct {
	Request   *Request        `json:"request"`
	Metrics   *RequestMetrics `json:"metrics"`
	NodeID    string          `json:"node_id"`
	Success   bool            `json:"success"`
}

// CircuitBreaker prevents cascading failures by failing fast when a node is unhealthy
type CircuitBreaker struct {
	nodeID              string
	state               CircuitBreakerState
	failureCount        int
	successCount        int
	lastFailureTime     time.Time
	lastSuccessTime     time.Time
	
	// Configuration
	failureThreshold    int           // Number of failures before opening
	successThreshold    int           // Number of successes before closing
	timeout             time.Duration // Time to wait before trying half-open
	
	mutex               sync.RWMutex
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState string

const (
	CircuitBreakerStateClosed   CircuitBreakerState = "closed"
	CircuitBreakerStateOpen     CircuitBreakerState = "open"
	CircuitBreakerStateHalfOpen CircuitBreakerState = "half_open"
)

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(logger *zap.Logger, config *ScalingConfig) (*LoadBalancer, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	lb := &LoadBalancer{
		logger:          logger.With(zap.String("component", "load-balancer")),
		config:          config,
		activeNodes:     make(map[string]*NodeInfo),
		strategies:      make(map[string]LoadBalancingStrategy),
		circuitBreakers: make(map[string]*CircuitBreaker),
		ctx:             ctx,
		cancel:          cancel,
		stats: &LoadBalancerStats{
			NodeDistribution: make(map[string]int64),
			StrategyStats:    make(map[string]*StrategyStats),
		},
	}
	
	// Initialize request tracker
	lb.requestTracker = &RequestTracker{
		activeRequests:  make(map[string]*ActiveRequest),
		sessionToNode:   make(map[string]string),
		requestHistory:  make([]*CompletedRequest, 0),
		maxHistorySize:  1000,
	}
	
	// Initialize health checker
	var err error
	lb.healthChecker, err = NewNodeHealthChecker(logger, config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize health checker: %w", err)
	}
	
	// Initialize load balancing strategies
	if err := lb.initializeStrategies(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize strategies: %w", err)
	}
	
	// Set default strategy
	lb.strategy = lb.strategies[config.LoadBalancingStrategy]
	if lb.strategy == nil {
		lb.strategy = lb.strategies["round_robin"] // Fallback to round robin
	}
	
	// Start background processes
	lb.healthTicker = time.NewTicker(30 * time.Second)
	lb.statsTicker = time.NewTicker(60 * time.Second)
	go lb.runHealthMonitoring()
	go lb.runStatsCollection()
	
	logger.Info("Load balancer initialized",
		zap.String("strategy", config.LoadBalancingStrategy),
		zap.Float64("healthy_threshold", config.HealthyNodeThreshold),
	)
	
	return lb, nil
}

// initializeStrategies initializes all load balancing strategies
func (lb *LoadBalancer) initializeStrategies() error {
	// Round Robin Strategy
	lb.strategies["round_robin"] = NewRoundRobinStrategy(lb.logger)
	
	// Least Connections Strategy
	lb.strategies["least_connections"] = NewLeastConnectionsStrategy(lb.logger)
	
	// Weighted Round Robin Strategy
	lb.strategies["weighted"] = NewWeightedRoundRobinStrategy(lb.logger)
	
	// Least Response Time Strategy
	lb.strategies["least_response_time"] = NewLeastResponseTimeStrategy(lb.logger)
	
	// Resource-based Strategy
	lb.strategies["resource_based"] = NewResourceBasedStrategy(lb.logger)
	
	// Consistent Hash Strategy
	lb.strategies["consistent_hash"] = NewConsistentHashStrategy(lb.logger)
	
	// Initialize strategy stats
	for name := range lb.strategies {
		lb.stats.StrategyStats[name] = &StrategyStats{}
	}
	
	return nil
}

// AddNode adds a node to the load balancer
func (lb *LoadBalancer) AddNode(node *ProcessingNode) error {
	lb.nodesMutex.Lock()
	defer lb.nodesMutex.Unlock()
	
	nodeInfo := &NodeInfo{
		ID:                  node.ID,
		Address:             node.Address,
		Port:                node.Port,
		Weight:              1, // Default weight
		MaxConnections:      1000, // Default max connections
		CurrentConnections:  0,
		Status:              NodeLoadStatusHealthy,
		LastSeen:            time.Now(),
		AddedAt:             time.Now(),
		RequestQueue:        make([]time.Time, 0),
		Capacity:            100, // Default capacity
		Health: &NodeHealthInfo{
			IsHealthy:         true,
			HealthScore:       100.0,
			LastHealthCheck:   time.Now(),
		},
	}
	
	// Set capacity based on node specifications
	if node.Capacity != nil {
		nodeInfo.Capacity = int(node.Capacity.MaxEventsPerSecond / 1000) // Convert to request capacity
	}
	
	lb.activeNodes[node.ID] = nodeInfo
	
	// Initialize circuit breaker for this node
	lb.circuitMutex.Lock()
	lb.circuitBreakers[node.ID] = &CircuitBreaker{
		nodeID:           node.ID,
		state:            CircuitBreakerStateClosed,
		failureThreshold: 5,
		successThreshold: 3,
		timeout:          30 * time.Second,
	}
	lb.circuitMutex.Unlock()
	
	// Initialize node distribution stats
	lb.statsMutex.Lock()
	lb.stats.NodeDistribution[node.ID] = 0
	lb.statsMutex.Unlock()
	
	lb.logger.Info("Node added to load balancer",
		zap.String("node_id", node.ID),
		zap.String("address", node.Address),
		zap.Int("capacity", nodeInfo.Capacity),
	)
	
	return nil
}

// RemoveNode removes a node from the load balancer
func (lb *LoadBalancer) RemoveNode(nodeID string) error {
	lb.nodesMutex.Lock()
	defer lb.nodesMutex.Unlock()
	
	// Set node status to draining first
	if node, exists := lb.activeNodes[nodeID]; exists {
		node.Status = NodeLoadStatusDraining
		
		// Wait for active requests to complete (with timeout)
		timeout := time.NewTimer(30 * time.Second)
		defer timeout.Stop()
		
		for {
			activeCount := lb.getActiveRequestCount(nodeID)
			if activeCount == 0 {
				break
			}
			
			select {
			case <-timeout.C:
				lb.logger.Warn("Timeout waiting for requests to drain, removing node forcefully",
					zap.String("node_id", nodeID),
					zap.Int("remaining_requests", activeCount),
				)
				goto removeNode
			default:
				time.Sleep(1 * time.Second)
			}
		}
	}

removeNode:
	// Remove from active nodes
	delete(lb.activeNodes, nodeID)
	
	// Remove circuit breaker
	lb.circuitMutex.Lock()
	delete(lb.circuitBreakers, nodeID)
	lb.circuitMutex.Unlock()
	
	// Clean up session mappings
	lb.requestTracker.sessionMutex.Lock()
	for sessionID, mappedNodeID := range lb.requestTracker.sessionToNode {
		if mappedNodeID == nodeID {
			delete(lb.requestTracker.sessionToNode, sessionID)
		}
	}
	lb.requestTracker.sessionMutex.Unlock()
	
	lb.logger.Info("Node removed from load balancer", zap.String("node_id", nodeID))
	
	return nil
}

// RouteRequest routes a request to an appropriate node
func (lb *LoadBalancer) RouteRequest(ctx context.Context, request *Request) (*NodeInfo, error) {
	start := time.Now()
	
	// Get available healthy nodes
	availableNodes := lb.getAvailableNodes()
	if len(availableNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}
	
	// Check for sticky session
	if request.StickySession && request.SessionID != "" {
		if nodeID := lb.getSessionNode(request.SessionID); nodeID != "" {
			if node := lb.getNodeInfo(nodeID); node != nil && lb.isNodeAvailable(node) {
				lb.recordRequestRouting(request, node)
				return node, nil
			}
		}
	}
	
	// Check circuit breakers and filter nodes
	healthyNodes := make([]*NodeInfo, 0)
	for _, node := range availableNodes {
		if lb.isCircuitBreakerClosed(node.ID) {
			healthyNodes = append(healthyNodes, node)
		}
	}
	
	if len(healthyNodes) == 0 {
		return nil, fmt.Errorf("all nodes are circuit broken")
	}
	
	// Use load balancing strategy to select node
	selectedNode, err := lb.strategy.SelectNode(ctx, healthyNodes, request)
	if err != nil {
		return nil, fmt.Errorf("failed to select node: %w", err)
	}
	
	// Record the routing decision
	lb.recordRequestRouting(request, selectedNode)
	
	// Update session mapping if sticky session
	if request.StickySession && request.SessionID != "" {
		lb.setSessionNode(request.SessionID, selectedNode.ID)
	}
	
	// Update strategy stats
	selectionTime := time.Since(start)
	lb.updateStrategyStats(lb.strategy.GetName(), selectionTime)
	
	return selectedNode, nil
}

// HandleRequestResult handles the result of a completed request
func (lb *LoadBalancer) HandleRequestResult(request *Request, metrics *RequestMetrics) {
	// Update node metrics
	lb.updateNodeMetrics(metrics.NodeID, metrics)
	
	// Update circuit breaker
	if metrics.Success {
		lb.recordSuccess(metrics.NodeID)
	} else {
		lb.recordFailure(metrics.NodeID)
	}
	
	// Update strategy metrics
	lb.strategy.UpdateNodeMetrics(metrics.NodeID, metrics)
	
	// Record completed request
	lb.recordCompletedRequest(request, metrics)
	
	// Remove from active requests
	lb.removeActiveRequest(request.ID)
	
	// Update statistics
	lb.updateLoadBalancerStats(metrics)
}

// Health monitoring and management
func (lb *LoadBalancer) runHealthMonitoring() {
	for {
		select {
		case <-lb.ctx.Done():
			return
		case <-lb.healthTicker.C:
			lb.performHealthChecks()
		}
	}
}

func (lb *LoadBalancer) performHealthChecks() {
	lb.nodesMutex.RLock()
	nodes := make([]*NodeInfo, 0, len(lb.activeNodes))
	for _, node := range lb.activeNodes {
		nodes = append(nodes, node)
	}
	lb.nodesMutex.RUnlock()
	
	for _, node := range nodes {
		health := lb.healthChecker.CheckNodeHealth(node)
		lb.updateNodeHealth(node.ID, health)
	}
}

func (lb *LoadBalancer) updateNodeHealth(nodeID string, health *NodeHealthInfo) {
	lb.nodesMutex.Lock()
	defer lb.nodesMutex.Unlock()
	
	node, exists := lb.activeNodes[nodeID]
	if !exists {
		return
	}
	
	node.Health = health
	node.LastSeen = time.Now()
	
	// Update node status based on health
	if health.HealthScore >= lb.config.HealthyNodeThreshold {
		node.Status = NodeLoadStatusHealthy
	} else if health.HealthScore >= 50.0 {
		node.Status = NodeLoadStatusDegraded
	} else {
		node.Status = NodeLoadStatusOverloaded
	}
	
	// Calculate load score
	node.LoadScore = lb.calculateLoadScore(node)
}

// Statistics collection
func (lb *LoadBalancer) runStatsCollection() {
	for {
		select {
		case <-lb.ctx.Done():
			return
		case <-lb.statsTicker.C:
			lb.collectStats()
		}
	}
}

func (lb *LoadBalancer) collectStats() {
	lb.statsMutex.Lock()
	defer lb.statsMutex.Unlock()
	
	// Update requests per second
	now := time.Now()
	timeDiff := now.Sub(lb.stats.LastStatsUpdate).Seconds()
	if timeDiff > 0 {
		lb.stats.RequestsPerSecond = float64(lb.stats.TotalRequests) / timeDiff
	}
	
	lb.stats.LastStatsUpdate = now
	
	// Calculate node utilization balance
	lb.calculateNodeUtilizationBalance()
}

// Helper methods
func (lb *LoadBalancer) getAvailableNodes() []*NodeInfo {
	lb.nodesMutex.RLock()
	defer lb.nodesMutex.RUnlock()
	
	var available []*NodeInfo
	for _, node := range lb.activeNodes {
		if lb.isNodeAvailable(node) {
			available = append(available, node)
		}
	}
	
	return available
}

func (lb *LoadBalancer) isNodeAvailable(node *NodeInfo) bool {
	return node.Status == NodeLoadStatusHealthy || node.Status == NodeLoadStatusDegraded
}

func (lb *LoadBalancer) getNodeInfo(nodeID string) *NodeInfo {
	lb.nodesMutex.RLock()
	defer lb.nodesMutex.RUnlock()
	
	return lb.activeNodes[nodeID]
}

func (lb *LoadBalancer) getActiveRequestCount(nodeID string) int {
	lb.requestTracker.requestsMutex.RLock()
	defer lb.requestTracker.requestsMutex.RUnlock()
	
	count := 0
	for _, activeReq := range lb.requestTracker.activeRequests {
		if activeReq.NodeID == nodeID {
			count++
		}
	}
	
	return count
}

func (lb *LoadBalancer) recordRequestRouting(request *Request, node *NodeInfo) {
	// Update node connection count
	lb.nodesMutex.Lock()
	node.CurrentConnections++
	node.LastRequestTime = time.Now()
	lb.nodesMutex.Unlock()
	
	// Track active request
	lb.requestTracker.requestsMutex.Lock()
	lb.requestTracker.activeRequests[request.ID] = &ActiveRequest{
		Request:   request,
		NodeID:    node.ID,
		StartTime: time.Now(),
		LastUpdate: time.Now(),
	}
	lb.requestTracker.requestsMutex.Unlock()
}

func (lb *LoadBalancer) removeActiveRequest(requestID string) {
	lb.requestTracker.requestsMutex.Lock()
	activeReq, exists := lb.requestTracker.activeRequests[requestID]
	if exists {
		delete(lb.requestTracker.activeRequests, requestID)
		
		// Update node connection count
		lb.nodesMutex.Lock()
		if node, nodeExists := lb.activeNodes[activeReq.NodeID]; nodeExists {
			node.CurrentConnections--
		}
		lb.nodesMutex.Unlock()
	}
	lb.requestTracker.requestsMutex.Unlock()
}

func (lb *LoadBalancer) updateNodeMetrics(nodeID string, metrics *RequestMetrics) {
	lb.nodesMutex.Lock()
	defer lb.nodesMutex.Unlock()
	
	node, exists := lb.activeNodes[nodeID]
	if !exists {
		return
	}
	
	// Update request counts
	node.TotalRequests++
	if metrics.Success {
		node.SuccessfulRequests++
	} else {
		node.FailedRequests++
	}
	
	// Update latency metrics
	if node.AverageLatency == 0 {
		node.AverageLatency = metrics.Duration
	} else {
		node.AverageLatency = (node.AverageLatency + metrics.Duration) / 2
	}
	
	// Update response time
	if node.AverageResponseTime == 0 {
		node.AverageResponseTime = metrics.Duration
	} else {
		node.AverageResponseTime = (node.AverageResponseTime + metrics.Duration) / 2
	}
}

func (lb *LoadBalancer) calculateLoadScore(node *NodeInfo) float64 {
	// Calculate a composite load score based on multiple factors
	connectionLoad := float64(node.CurrentConnections) / float64(node.MaxConnections) * 100
	cpuLoad := node.CPUUsage
	memoryLoad := node.MemoryUsage
	healthScore := 100.0 - node.Health.HealthScore
	
	// Weighted average
	loadScore := (connectionLoad*0.3 + cpuLoad*0.3 + memoryLoad*0.3 + healthScore*0.1)
	
	return math.Min(loadScore, 100.0)
}

// Circuit breaker methods
func (lb *LoadBalancer) isCircuitBreakerClosed(nodeID string) bool {
	lb.circuitMutex.RLock()
	defer lb.circuitMutex.RUnlock()
	
	cb, exists := lb.circuitBreakers[nodeID]
	if !exists {
		return true
	}
	
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	switch cb.state {
	case CircuitBreakerStateClosed:
		return true
	case CircuitBreakerStateOpen:
		// Check if timeout has passed
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = CircuitBreakerStateHalfOpen
			return true
		}
		return false
	case CircuitBreakerStateHalfOpen:
		return true
	default:
		return false
	}
}

func (lb *LoadBalancer) recordSuccess(nodeID string) {
	lb.circuitMutex.RLock()
	cb, exists := lb.circuitBreakers[nodeID]
	lb.circuitMutex.RUnlock()
	
	if !exists {
		return
	}
	
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.successCount++
	cb.lastSuccessTime = time.Now()
	
	if cb.state == CircuitBreakerStateHalfOpen && cb.successCount >= cb.successThreshold {
		cb.state = CircuitBreakerStateClosed
		cb.failureCount = 0
		cb.successCount = 0
	}
}

func (lb *LoadBalancer) recordFailure(nodeID string) {
	lb.circuitMutex.RLock()
	cb, exists := lb.circuitBreakers[nodeID]
	lb.circuitMutex.RUnlock()
	
	if !exists {
		return
	}
	
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.failureCount++
	cb.lastFailureTime = time.Now()
	
	if cb.failureCount >= cb.failureThreshold {
		cb.state = CircuitBreakerStateOpen
		cb.successCount = 0
		
		// Update stats
		lb.statsMutex.Lock()
		lb.stats.CircuitBreakerTrips++
		lb.statsMutex.Unlock()
	}
}

// Session management
func (lb *LoadBalancer) getSessionNode(sessionID string) string {
	lb.requestTracker.sessionMutex.RLock()
	defer lb.requestTracker.sessionMutex.RUnlock()
	
	return lb.requestTracker.sessionToNode[sessionID]
}

func (lb *LoadBalancer) setSessionNode(sessionID, nodeID string) {
	lb.requestTracker.sessionMutex.Lock()
	defer lb.requestTracker.sessionMutex.Unlock()
	
	lb.requestTracker.sessionToNode[sessionID] = nodeID
}

func (lb *LoadBalancer) recordCompletedRequest(request *Request, metrics *RequestMetrics) {
	lb.requestTracker.historyMutex.Lock()
	defer lb.requestTracker.historyMutex.Unlock()
	
	completed := &CompletedRequest{
		Request: request,
		Metrics: metrics,
		NodeID:  metrics.NodeID,
		Success: metrics.Success,
	}
	
	lb.requestTracker.requestHistory = append(lb.requestTracker.requestHistory, completed)
	
	// Keep history size under control
	if len(lb.requestTracker.requestHistory) > lb.requestTracker.maxHistorySize {
		lb.requestTracker.requestHistory = lb.requestTracker.requestHistory[1:]
	}
}

func (lb *LoadBalancer) updateStrategyStats(strategyName string, selectionTime time.Duration) {
	lb.statsMutex.Lock()
	defer lb.statsMutex.Unlock()
	
	stats, exists := lb.stats.StrategyStats[strategyName]
	if exists {
		stats.RequestsHandled++
		
		if stats.AverageSelectionTime == 0 {
			stats.AverageSelectionTime = selectionTime
		} else {
			stats.AverageSelectionTime = (stats.AverageSelectionTime + selectionTime) / 2
		}
	}
}

func (lb *LoadBalancer) updateLoadBalancerStats(metrics *RequestMetrics) {
	lb.statsMutex.Lock()
	defer lb.statsMutex.Unlock()
	
	lb.stats.TotalRequests++
	if metrics.Success {
		lb.stats.SuccessfulRequests++
	} else {
		lb.stats.FailedRequests++
	}
	
	// Update average latency
	if lb.stats.AverageLatency == 0 {
		lb.stats.AverageLatency = metrics.Duration
	} else {
		lb.stats.AverageLatency = (lb.stats.AverageLatency + metrics.Duration) / 2
	}
	
	// Update node distribution
	lb.stats.NodeDistribution[metrics.NodeID]++
}

func (lb *LoadBalancer) calculateNodeUtilizationBalance() {
	// Calculate how balanced the load distribution is across nodes
	if len(lb.stats.NodeDistribution) == 0 {
		return
	}
	
	var total int64
	var values []float64
	
	for _, count := range lb.stats.NodeDistribution {
		total += count
		values = append(values, float64(count))
	}
	
	if total == 0 {
		return
	}
	
	// Calculate coefficient of variation
	mean := float64(total) / float64(len(values))
	var variance float64
	
	for _, value := range values {
		variance += math.Pow(value-mean, 2)
	}
	
	variance /= float64(len(values))
	stdDev := math.Sqrt(variance)
	
	// Lower coefficient of variation = better balance
	cv := stdDev / mean
	balance := math.Max(0, 100-cv*100) // Convert to 0-100 scale
	
	// Update strategy stats with balance score
	for _, stats := range lb.stats.StrategyStats {
		stats.NodeUtilizationBalance = balance
	}
}

// GetLoadBalancerStats returns current load balancer statistics
func (lb *LoadBalancer) GetLoadBalancerStats() *LoadBalancerStats {
	lb.statsMutex.RLock()
	defer lb.statsMutex.RUnlock()
	
	stats := *lb.stats
	return &stats
}

// GetActiveNodes returns all active nodes
func (lb *LoadBalancer) GetActiveNodes() map[string]*NodeInfo {
	lb.nodesMutex.RLock()
	defer lb.nodesMutex.RUnlock()
	
	nodes := make(map[string]*NodeInfo)
	for id, node := range lb.activeNodes {
		nodes[id] = node
	}
	return nodes
}

// Close gracefully shuts down the load balancer
func (lb *LoadBalancer) Close() error {
	if lb.cancel != nil {
		lb.cancel()
	}
	
	if lb.healthTicker != nil {
		lb.healthTicker.Stop()
	}
	if lb.statsTicker != nil {
		lb.statsTicker.Stop()
	}
	
	if lb.healthChecker != nil {
		lb.healthChecker.Close()
	}
	
	lb.logger.Info("Load balancer closed")
	return nil
}

// Placeholder implementations for health checker and strategies
func NewNodeHealthChecker(logger *zap.Logger, config *ScalingConfig) (*NodeHealthChecker, error) {
	return &NodeHealthChecker{
		logger: logger.With(zap.String("component", "node-health-checker")),
		config: config,
	}, nil
}

type NodeHealthChecker struct {
	logger *zap.Logger
	config *ScalingConfig
}

func (nhc *NodeHealthChecker) CheckNodeHealth(node *NodeInfo) *NodeHealthInfo {
	// In a real implementation, this would perform actual health checks
	return &NodeHealthInfo{
		IsHealthy:           true,
		HealthScore:         95.0,
		LastHealthCheck:     time.Now(),
		ConsecutiveFailures: 0,
		ResponseTimeHealth:  90.0,
		ThroughputHealth:    95.0,
		ResourceHealth:      92.0,
	}
}

func (nhc *NodeHealthChecker) Close() error {
	return nil
}

// Load balancing strategy implementations (simplified)
func NewRoundRobinStrategy(logger *zap.Logger) LoadBalancingStrategy {
	return &RoundRobinStrategy{logger: logger, counter: 0}
}

type RoundRobinStrategy struct {
	logger  *zap.Logger
	counter int
	mutex   sync.Mutex
}

func (rr *RoundRobinStrategy) SelectNode(ctx context.Context, nodes []*NodeInfo, request *Request) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	rr.mutex.Lock()
	index := rr.counter % len(nodes)
	rr.counter++
	rr.mutex.Unlock()
	
	return nodes[index], nil
}

func (rr *RoundRobinStrategy) GetName() string {
	return "round_robin"
}

func (rr *RoundRobinStrategy) UpdateNodeMetrics(nodeID string, metrics *RequestMetrics) {
	// No specific action needed for round robin
}

func (rr *RoundRobinStrategy) ShouldRetry(err error) bool {
	return true // Always retry for round robin
}

// Additional strategy implementations would follow similar patterns
func NewLeastConnectionsStrategy(logger *zap.Logger) LoadBalancingStrategy {
	return &LeastConnectionsStrategy{logger: logger}
}

type LeastConnectionsStrategy struct {
	logger *zap.Logger
}

func (lc *LeastConnectionsStrategy) SelectNode(ctx context.Context, nodes []*NodeInfo, request *Request) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	var selectedNode *NodeInfo
	minConnections := int(^uint(0) >> 1) // Max int
	
	for _, node := range nodes {
		if node.CurrentConnections < minConnections {
			minConnections = node.CurrentConnections
			selectedNode = node
		}
	}
	
	return selectedNode, nil
}

func (lc *LeastConnectionsStrategy) GetName() string {
	return "least_connections"
}

func (lc *LeastConnectionsStrategy) UpdateNodeMetrics(nodeID string, metrics *RequestMetrics) {}
func (lc *LeastConnectionsStrategy) ShouldRetry(err error) bool { return true }

// Placeholder implementations for other strategies
func NewWeightedRoundRobinStrategy(logger *zap.Logger) LoadBalancingStrategy {
	return &WeightedRoundRobinStrategy{logger: logger}
}

type WeightedRoundRobinStrategy struct{ logger *zap.Logger }
func (w *WeightedRoundRobinStrategy) SelectNode(ctx context.Context, nodes []*NodeInfo, request *Request) (*NodeInfo, error) { return nodes[0], nil }
func (w *WeightedRoundRobinStrategy) GetName() string { return "weighted" }
func (w *WeightedRoundRobinStrategy) UpdateNodeMetrics(nodeID string, metrics *RequestMetrics) {}
func (w *WeightedRoundRobinStrategy) ShouldRetry(err error) bool { return true }

func NewLeastResponseTimeStrategy(logger *zap.Logger) LoadBalancingStrategy {
	return &LeastResponseTimeStrategy{logger: logger}
}

type LeastResponseTimeStrategy struct{ logger *zap.Logger }
func (l *LeastResponseTimeStrategy) SelectNode(ctx context.Context, nodes []*NodeInfo, request *Request) (*NodeInfo, error) { return nodes[0], nil }
func (l *LeastResponseTimeStrategy) GetName() string { return "least_response_time" }
func (l *LeastResponseTimeStrategy) UpdateNodeMetrics(nodeID string, metrics *RequestMetrics) {}
func (l *LeastResponseTimeStrategy) ShouldRetry(err error) bool { return true }

func NewResourceBasedStrategy(logger *zap.Logger) LoadBalancingStrategy {
	return &ResourceBasedStrategy{logger: logger}
}

type ResourceBasedStrategy struct{ logger *zap.Logger }
func (r *ResourceBasedStrategy) SelectNode(ctx context.Context, nodes []*NodeInfo, request *Request) (*NodeInfo, error) { return nodes[0], nil }
func (r *ResourceBasedStrategy) GetName() string { return "resource_based" }
func (r *ResourceBasedStrategy) UpdateNodeMetrics(nodeID string, metrics *RequestMetrics) {}
func (r *ResourceBasedStrategy) ShouldRetry(err error) bool { return true }

func NewConsistentHashStrategy(logger *zap.Logger) LoadBalancingStrategy {
	return &ConsistentHashStrategy{logger: logger}
}

type ConsistentHashStrategy struct{ logger *zap.Logger }
func (c *ConsistentHashStrategy) SelectNode(ctx context.Context, nodes []*NodeInfo, request *Request) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	// Use consistent hashing based on client ID or session ID
	key := request.ClientID
	if key == "" {
		key = request.SessionID
	}
	if key == "" {
		key = request.ID
	}
	
	hash := crc32.ChecksumIEEE([]byte(key))
	index := int(hash) % len(nodes)
	
	return nodes[index], nil
}
func (c *ConsistentHashStrategy) GetName() string { return "consistent_hash" }
func (c *ConsistentHashStrategy) UpdateNodeMetrics(nodeID string, metrics *RequestMetrics) {}
func (c *ConsistentHashStrategy) ShouldRetry(err error) bool { return true }