package scaling

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// HorizontalScalingManager manages the horizontal scaling of stream processing components
type HorizontalScalingManager struct {
	logger         *zap.Logger
	config         *ScalingConfig
	
	// Component managers
	partitionManager   *PartitionManager
	replicationManager *ReplicationManager
	loadBalancer       *LoadBalancer
	failoverManager    *FailoverManager
	healthChecker      *HealthChecker
	
	// Scaling state
	activeNodes        map[string]*ProcessingNode
	nodesMutex         sync.RWMutex
	scalingInProgress  bool
	scalingMutex       sync.Mutex
	
	// Monitoring and metrics
	metricsCollector   *ScalingMetricsCollector
	performanceMonitor *PerformanceMonitor
	
	// Control channels
	ctx                context.Context
	cancel             context.CancelFunc
	scalingTicker      *time.Ticker
	
	// Recovery and failover
	recoveryOrchestrator *RecoveryOrchestrator
	dataConsistencyChecker *DataConsistencyChecker
}

// ScalingConfig defines the configuration for horizontal scaling
type ScalingConfig struct {
	// Scaling parameters
	MinNodes              int           `json:"min_nodes"`
	MaxNodes              int           `json:"max_nodes"`
	TargetEventsPerSecond int64         `json:"target_events_per_second"`
	ScaleUpThreshold      float64       `json:"scale_up_threshold"`   // CPU/Memory threshold to scale up
	ScaleDownThreshold    float64       `json:"scale_down_threshold"` // CPU/Memory threshold to scale down
	
	// Timing configurations
	ScalingCooldown       time.Duration `json:"scaling_cooldown"`       // Minimum time between scaling operations
	HealthCheckInterval   time.Duration `json:"health_check_interval"`
	MetricsCollectionInterval time.Duration `json:"metrics_collection_interval"`
	
	// Partitioning strategy
	PartitionStrategy     string        `json:"partition_strategy"`     // round_robin, hash, range, consistent_hash
	ReplicationFactor     int           `json:"replication_factor"`     // Number of replicas per partition
	PartitionCount        int           `json:"partition_count"`        // Total number of partitions
	
	// Load balancing
	LoadBalancingStrategy string        `json:"load_balancing_strategy"` // round_robin, least_connections, weighted
	HealthyNodeThreshold  float64       `json:"healthy_node_threshold"`  // Minimum health score for active nodes
	
	// Fault tolerance
	FailoverTimeout       time.Duration `json:"failover_timeout"`
	RecoveryTimeout       time.Duration `json:"recovery_timeout"`
	MaxFailureCount       int           `json:"max_failure_count"`
	BackupNodesCount      int           `json:"backup_nodes_count"`
	
	// Data consistency
	ConsistencyLevel      string        `json:"consistency_level"`      // strong, eventual, weak
	ReplicationSync       bool          `json:"replication_sync"`       // Synchronous or asynchronous replication
	DataValidationEnabled bool          `json:"data_validation_enabled"`
	
	// Resource limits
	MaxCPUPerNode         float64       `json:"max_cpu_per_node"`
	MaxMemoryPerNode      int64         `json:"max_memory_per_node"`
	MaxDiskIOPerNode      int64         `json:"max_disk_io_per_node"`
	MaxNetworkBandwidth   int64         `json:"max_network_bandwidth"`
}

// ProcessingNode represents a single processing node in the cluster
type ProcessingNode struct {
	ID                string                 `json:"id"`
	Address           string                 `json:"address"`
	Port              int                    `json:"port"`
	Status            NodeStatus             `json:"status"`
	Health            *NodeHealth            `json:"health"`
	Capacity          *NodeCapacity          `json:"capacity"`
	Workload          *NodeWorkload          `json:"workload"`
	LastSeen          time.Time              `json:"last_seen"`
	StartedAt         time.Time              `json:"started_at"`
	Version           string                 `json:"version"`
	Metadata          map[string]interface{} `json:"metadata"`
	
	// Partitions assigned to this node
	Partitions        []int                  `json:"partitions"`
	ReplicatedFrom    []string               `json:"replicated_from"`  // Node IDs this node replicates from
	ReplicatesTo      []string               `json:"replicates_to"`    // Node IDs this node replicates to
	
	// Performance metrics
	EventsProcessed   int64                  `json:"events_processed"`
	ErrorCount        int64                  `json:"error_count"`
	AverageLatency    time.Duration          `json:"average_latency"`
	ThroughputEPS     float64                `json:"throughput_eps"`
}

// NodeStatus represents the status of a processing node
type NodeStatus string

const (
	NodeStatusStarting   NodeStatus = "starting"
	NodeStatusHealthy    NodeStatus = "healthy"
	NodeStatusDegraded   NodeStatus = "degraded"
	NodeStatusUnhealthy  NodeStatus = "unhealthy"
	NodeStatusFailed     NodeStatus = "failed"
	NodeStatusDraining   NodeStatus = "draining"
	NodeStatusStopped    NodeStatus = "stopped"
)

// NodeHealth contains health information for a processing node
type NodeHealth struct {
	CPUUsage          float64   `json:"cpu_usage"`
	MemoryUsage       float64   `json:"memory_usage"`
	DiskUsage         float64   `json:"disk_usage"`
	NetworkIO         int64     `json:"network_io"`
	HealthScore       float64   `json:"health_score"`       // 0-100
	LastHealthCheck   time.Time `json:"last_health_check"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
}

// NodeCapacity defines the resource capacity of a processing node
type NodeCapacity struct {
	MaxEventsPerSecond int64     `json:"max_events_per_second"`
	MaxCPU            float64   `json:"max_cpu_cores"`
	MaxMemory         int64     `json:"max_memory_bytes"`
	MaxDiskIO         int64     `json:"max_disk_io_bytes"`
	MaxNetworkBandwidth int64   `json:"max_network_bandwidth"`
}

// NodeWorkload represents the current workload of a processing node
type NodeWorkload struct {
	CurrentEventsPerSecond int64     `json:"current_events_per_second"`
	QueueSize             int64     `json:"queue_size"`
	ActiveConnections     int       `json:"active_connections"`
	ProcessingLatency     time.Duration `json:"processing_latency"`
	UtilizationPercent    float64   `json:"utilization_percent"`
}

// ScalingMetricsCollector collects metrics for scaling decisions
type ScalingMetricsCollector struct {
	logger               *zap.Logger
	metrics              *ScalingMetrics
	metricsMutex         sync.RWMutex
	
	// Prometheus metrics
	nodeCount            *prometheus.GaugeVec
	throughputEPS        *prometheus.GaugeVec
	avgLatency           *prometheus.GaugeVec
	errorRate            *prometheus.GaugeVec
	scalingOperations    *prometheus.CounterVec
}

// ScalingMetrics contains metrics used for scaling decisions
type ScalingMetrics struct {
	TotalNodes           int                    `json:"total_nodes"`
	HealthyNodes         int                    `json:"healthy_nodes"`
	TotalThroughputEPS   float64                `json:"total_throughput_eps"`
	AverageLatency       time.Duration          `json:"average_latency"`
	AverageCPUUsage      float64                `json:"average_cpu_usage"`
	AverageMemoryUsage   float64                `json:"average_memory_usage"`
	ErrorRate            float64                `json:"error_rate"`
	QueueBacklog         int64                  `json:"queue_backlog"`
	NodeMetrics          map[string]*NodeHealth `json:"node_metrics"`
	LastUpdated          time.Time              `json:"last_updated"`
}

// NewHorizontalScalingManager creates a new horizontal scaling manager
func NewHorizontalScalingManager(logger *zap.Logger, config *ScalingConfig) (*HorizontalScalingManager, error) {
	if config == nil {
		return nil, fmt.Errorf("scaling configuration is required")
	}
	
	// Set defaults
	if err := setScalingDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	hsm := &HorizontalScalingManager{
		logger:       logger.With(zap.String("component", "horizontal-scaling-manager")),
		config:       config,
		activeNodes:  make(map[string]*ProcessingNode),
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Initialize component managers
	if err := hsm.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}
	
	// Start background processes
	hsm.scalingTicker = time.NewTicker(config.MetricsCollectionInterval)
	go hsm.runScalingLoop()
	go hsm.runHealthMonitoring()
	
	logger.Info("Horizontal scaling manager initialized",
		zap.Int("min_nodes", config.MinNodes),
		zap.Int("max_nodes", config.MaxNodes),
		zap.Int64("target_eps", config.TargetEventsPerSecond),
		zap.String("partition_strategy", config.PartitionStrategy),
	)
	
	return hsm, nil
}

// setScalingDefaults sets configuration defaults
func setScalingDefaults(config *ScalingConfig) error {
	if config.MinNodes == 0 {
		config.MinNodes = 2
	}
	if config.MaxNodes == 0 {
		config.MaxNodes = 20
	}
	if config.TargetEventsPerSecond == 0 {
		config.TargetEventsPerSecond = 1000000 // 1M events per second
	}
	if config.ScaleUpThreshold == 0 {
		config.ScaleUpThreshold = 80.0 // 80% resource utilization
	}
	if config.ScaleDownThreshold == 0 {
		config.ScaleDownThreshold = 30.0 // 30% resource utilization
	}
	if config.ScalingCooldown == 0 {
		config.ScalingCooldown = 5 * time.Minute
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.MetricsCollectionInterval == 0 {
		config.MetricsCollectionInterval = 10 * time.Second
	}
	if config.PartitionStrategy == "" {
		config.PartitionStrategy = "consistent_hash"
	}
	if config.ReplicationFactor == 0 {
		config.ReplicationFactor = 3
	}
	if config.PartitionCount == 0 {
		config.PartitionCount = 128
	}
	if config.LoadBalancingStrategy == "" {
		config.LoadBalancingStrategy = "least_connections"
	}
	if config.HealthyNodeThreshold == 0 {
		config.HealthyNodeThreshold = 70.0
	}
	if config.FailoverTimeout == 0 {
		config.FailoverTimeout = 30 * time.Second
	}
	if config.RecoveryTimeout == 0 {
		config.RecoveryTimeout = 5 * time.Minute
	}
	if config.MaxFailureCount == 0 {
		config.MaxFailureCount = 3
	}
	if config.BackupNodesCount == 0 {
		config.BackupNodesCount = 2
	}
	if config.ConsistencyLevel == "" {
		config.ConsistencyLevel = "eventual"
	}
	if config.MaxCPUPerNode == 0 {
		config.MaxCPUPerNode = 8.0
	}
	if config.MaxMemoryPerNode == 0 {
		config.MaxMemoryPerNode = 16 * 1024 * 1024 * 1024 // 16GB
	}
	if config.MaxDiskIOPerNode == 0 {
		config.MaxDiskIOPerNode = 1024 * 1024 * 1024 // 1GB/s
	}
	if config.MaxNetworkBandwidth == 0 {
		config.MaxNetworkBandwidth = 10 * 1024 * 1024 * 1024 // 10GB/s
	}
	
	return nil
}

// initializeComponents initializes all component managers
func (hsm *HorizontalScalingManager) initializeComponents() error {
	var err error
	
	// Initialize partition manager
	hsm.partitionManager, err = NewPartitionManager(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize partition manager: %w", err)
	}
	
	// Initialize replication manager
	hsm.replicationManager, err = NewReplicationManager(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize replication manager: %w", err)
	}
	
	// Initialize load balancer
	hsm.loadBalancer, err = NewLoadBalancer(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize load balancer: %w", err)
	}
	
	// Initialize failover manager
	hsm.failoverManager, err = NewFailoverManager(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize failover manager: %w", err)
	}
	
	// Initialize health checker
	hsm.healthChecker, err = NewHealthChecker(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize health checker: %w", err)
	}
	
	// Initialize metrics collector
	hsm.metricsCollector, err = NewScalingMetricsCollector(hsm.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics collector: %w", err)
	}
	
	// Initialize performance monitor
	hsm.performanceMonitor, err = NewPerformanceMonitor(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize performance monitor: %w", err)
	}
	
	// Initialize recovery orchestrator
	hsm.recoveryOrchestrator, err = NewRecoveryOrchestrator(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize recovery orchestrator: %w", err)
	}
	
	// Initialize data consistency checker
	hsm.dataConsistencyChecker, err = NewDataConsistencyChecker(hsm.logger, hsm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize data consistency checker: %w", err)
	}
	
	return nil
}

// RegisterNode registers a new processing node with the scaling manager
func (hsm *HorizontalScalingManager) RegisterNode(node *ProcessingNode) error {
	hsm.nodesMutex.Lock()
	defer hsm.nodesMutex.Unlock()
	
	// Validate node configuration
	if err := hsm.validateNode(node); err != nil {
		return fmt.Errorf("invalid node configuration: %w", err)
	}
	
	// Set initial status
	node.Status = NodeStatusStarting
	node.StartedAt = time.Now()
	node.LastSeen = time.Now()
	
	// Assign partitions
	partitions, err := hsm.partitionManager.AssignPartitions(node.ID, len(hsm.activeNodes))
	if err != nil {
		return fmt.Errorf("failed to assign partitions: %w", err)
	}
	node.Partitions = partitions
	
	// Configure replication
	if err := hsm.replicationManager.ConfigureReplication(node); err != nil {
		return fmt.Errorf("failed to configure replication: %w", err)
	}
	
	// Add to active nodes
	hsm.activeNodes[node.ID] = node
	
	// Update load balancer
	hsm.loadBalancer.AddNode(node)
	
	hsm.logger.Info("Node registered successfully",
		zap.String("node_id", node.ID),
		zap.String("address", node.Address),
		zap.Int("partitions", len(node.Partitions)),
	)
	
	return nil
}

// UnregisterNode removes a processing node from the scaling manager
func (hsm *HorizontalScalingManager) UnregisterNode(nodeID string) error {
	hsm.nodesMutex.Lock()
	defer hsm.nodesMutex.Unlock()
	
	node, exists := hsm.activeNodes[nodeID]
	if !exists {
		return fmt.Errorf("node %s not found", nodeID)
	}
	
	// Set node status to draining
	node.Status = NodeStatusDraining
	
	// Trigger failover for this node's partitions
	if err := hsm.failoverManager.HandleNodeFailure(nodeID); err != nil {
		hsm.logger.Error("Failed to handle node failure during unregistration",
			zap.String("node_id", nodeID),
			zap.Error(err),
		)
	}
	
	// Reassign partitions
	if err := hsm.partitionManager.ReassignPartitions(nodeID); err != nil {
		hsm.logger.Error("Failed to reassign partitions",
			zap.String("node_id", nodeID),
			zap.Error(err),
		)
	}
	
	// Remove from replication
	hsm.replicationManager.RemoveNode(nodeID)
	
	// Remove from load balancer
	hsm.loadBalancer.RemoveNode(nodeID)
	
	// Remove from active nodes
	delete(hsm.activeNodes, nodeID)
	
	hsm.logger.Info("Node unregistered successfully",
		zap.String("node_id", nodeID),
	)
	
	return nil
}

// ScaleUp adds new processing nodes to handle increased load
func (hsm *HorizontalScalingManager) ScaleUp(targetNodes int) error {
	hsm.scalingMutex.Lock()
	defer hsm.scalingMutex.Unlock()
	
	if hsm.scalingInProgress {
		return fmt.Errorf("scaling operation already in progress")
	}
	
	hsm.scalingInProgress = true
	defer func() { hsm.scalingInProgress = false }()
	
	currentNodes := len(hsm.activeNodes)
	if targetNodes <= currentNodes {
		return fmt.Errorf("target nodes (%d) must be greater than current nodes (%d)", targetNodes, currentNodes)
	}
	
	if targetNodes > hsm.config.MaxNodes {
		targetNodes = hsm.config.MaxNodes
	}
	
	nodesToAdd := targetNodes - currentNodes
	hsm.logger.Info("Starting scale up operation",
		zap.Int("current_nodes", currentNodes),
		zap.Int("target_nodes", targetNodes),
		zap.Int("nodes_to_add", nodesToAdd),
	)
	
	// Create new nodes
	for i := 0; i < nodesToAdd; i++ {
		node, err := hsm.createNewNode()
		if err != nil {
			hsm.logger.Error("Failed to create new node", zap.Error(err))
			continue
		}
		
		if err := hsm.RegisterNode(node); err != nil {
			hsm.logger.Error("Failed to register new node", zap.Error(err))
			continue
		}
	}
	
	// Rebalance partitions
	if err := hsm.partitionManager.Rebalance(); err != nil {
		hsm.logger.Error("Failed to rebalance partitions after scale up", zap.Error(err))
	}
	
	// Update metrics
	hsm.metricsCollector.RecordScalingOperation("scale_up", nodesToAdd)
	
	hsm.logger.Info("Scale up operation completed",
		zap.Int("new_node_count", len(hsm.activeNodes)),
	)
	
	return nil
}

// ScaleDown removes processing nodes when load decreases
func (hsm *HorizontalScalingManager) ScaleDown(targetNodes int) error {
	hsm.scalingMutex.Lock()
	defer hsm.scalingMutex.Unlock()
	
	if hsm.scalingInProgress {
		return fmt.Errorf("scaling operation already in progress")
	}
	
	hsm.scalingInProgress = true
	defer func() { hsm.scalingInProgress = false }()
	
	currentNodes := len(hsm.activeNodes)
	if targetNodes >= currentNodes {
		return fmt.Errorf("target nodes (%d) must be less than current nodes (%d)", targetNodes, currentNodes)
	}
	
	if targetNodes < hsm.config.MinNodes {
		targetNodes = hsm.config.MinNodes
	}
	
	nodesToRemove := currentNodes - targetNodes
	hsm.logger.Info("Starting scale down operation",
		zap.Int("current_nodes", currentNodes),
		zap.Int("target_nodes", targetNodes),
		zap.Int("nodes_to_remove", nodesToRemove),
	)
	
	// Select nodes to remove (prefer least loaded, unhealthy nodes)
	nodesToRemoveList := hsm.selectNodesForRemoval(nodesToRemove)
	
	// Gracefully drain and remove nodes
	for _, nodeID := range nodesToRemoveList {
		if err := hsm.drainAndRemoveNode(nodeID); err != nil {
			hsm.logger.Error("Failed to drain and remove node",
				zap.String("node_id", nodeID),
				zap.Error(err),
			)
		}
	}
	
	// Rebalance remaining partitions
	if err := hsm.partitionManager.Rebalance(); err != nil {
		hsm.logger.Error("Failed to rebalance partitions after scale down", zap.Error(err))
	}
	
	// Update metrics
	hsm.metricsCollector.RecordScalingOperation("scale_down", nodesToRemove)
	
	hsm.logger.Info("Scale down operation completed",
		zap.Int("new_node_count", len(hsm.activeNodes)),
	)
	
	return nil
}

// runScalingLoop runs the main scaling decision loop
func (hsm *HorizontalScalingManager) runScalingLoop() {
	for {
		select {
		case <-hsm.ctx.Done():
			return
		case <-hsm.scalingTicker.C:
			hsm.evaluateScalingNeeds()
		}
	}
}

// evaluateScalingNeeds evaluates whether scaling up or down is needed
func (hsm *HorizontalScalingManager) evaluateScalingNeeds() {
	metrics := hsm.metricsCollector.GetCurrentMetrics()
	
	// Check if scaling is needed based on resource utilization
	if hsm.shouldScaleUp(metrics) {
		targetNodes := hsm.calculateTargetNodes(metrics, "up")
		if err := hsm.ScaleUp(targetNodes); err != nil {
			hsm.logger.Error("Failed to scale up", zap.Error(err))
		}
	} else if hsm.shouldScaleDown(metrics) {
		targetNodes := hsm.calculateTargetNodes(metrics, "down")
		if err := hsm.ScaleDown(targetNodes); err != nil {
			hsm.logger.Error("Failed to scale down", zap.Error(err))
		}
	}
}

// shouldScaleUp determines if scaling up is needed
func (hsm *HorizontalScalingManager) shouldScaleUp(metrics *ScalingMetrics) bool {
	return metrics.AverageCPUUsage > hsm.config.ScaleUpThreshold ||
		   metrics.AverageMemoryUsage > hsm.config.ScaleUpThreshold ||
		   metrics.TotalThroughputEPS > float64(hsm.config.TargetEventsPerSecond) * hsm.config.ScaleUpThreshold / 100
}

// shouldScaleDown determines if scaling down is needed
func (hsm *HorizontalScalingManager) shouldScaleDown(metrics *ScalingMetrics) bool {
	return metrics.AverageCPUUsage < hsm.config.ScaleDownThreshold &&
		   metrics.AverageMemoryUsage < hsm.config.ScaleDownThreshold &&
		   metrics.TotalThroughputEPS < float64(hsm.config.TargetEventsPerSecond) * hsm.config.ScaleDownThreshold / 100 &&
		   metrics.TotalNodes > hsm.config.MinNodes
}

// calculateTargetNodes calculates the target number of nodes for scaling
func (hsm *HorizontalScalingManager) calculateTargetNodes(metrics *ScalingMetrics, direction string) int {
	currentNodes := metrics.TotalNodes
	
	if direction == "up" {
		// Calculate based on throughput and resource utilization
		throughputBasedNodes := int(metrics.TotalThroughputEPS / float64(hsm.config.TargetEventsPerSecond) * float64(currentNodes))
		resourceBasedNodes := int(metrics.AverageCPUUsage / hsm.config.ScaleUpThreshold * float64(currentNodes))
		
		targetNodes := max(throughputBasedNodes, resourceBasedNodes)
		if targetNodes > hsm.config.MaxNodes {
			targetNodes = hsm.config.MaxNodes
		}
		
		return targetNodes
	} else {
		// Scale down conservatively
		utilizationFactor := (metrics.AverageCPUUsage + metrics.AverageMemoryUsage) / 200.0 // Average of both
		targetNodes := int(float64(currentNodes) * utilizationFactor / (hsm.config.ScaleDownThreshold / 100.0))
		
		if targetNodes < hsm.config.MinNodes {
			targetNodes = hsm.config.MinNodes
		}
		
		return targetNodes
	}
}

// Helper functions and additional methods would continue here...
// This includes implementations for:
// - validateNode
// - createNewNode
// - selectNodesForRemoval
// - drainAndRemoveNode
// - runHealthMonitoring
// - GetScalingMetrics
// - GetActiveNodes
// - Close

// validateNode validates a processing node configuration
func (hsm *HorizontalScalingManager) validateNode(node *ProcessingNode) error {
	if node.ID == "" {
		return fmt.Errorf("node ID is required")
	}
	if node.Address == "" {
		return fmt.Errorf("node address is required")
	}
	if node.Port <= 0 {
		return fmt.Errorf("valid port is required")
	}
	return nil
}

// createNewNode creates a new processing node
func (hsm *HorizontalScalingManager) createNewNode() (*ProcessingNode, error) {
	nodeID := fmt.Sprintf("node-%d", time.Now().UnixNano())
	
	return &ProcessingNode{
		ID:      nodeID,
		Address: "localhost", // This would be dynamically assigned in production
		Port:    8080,        // This would be dynamically assigned in production
		Status:  NodeStatusStarting,
		Health: &NodeHealth{
			HealthScore: 100.0,
		},
		Capacity: &NodeCapacity{
			MaxEventsPerSecond: hsm.config.TargetEventsPerSecond / int64(hsm.config.MinNodes),
			MaxCPU:            hsm.config.MaxCPUPerNode,
			MaxMemory:         hsm.config.MaxMemoryPerNode,
			MaxDiskIO:         hsm.config.MaxDiskIOPerNode,
			MaxNetworkBandwidth: hsm.config.MaxNetworkBandwidth,
		},
		Workload: &NodeWorkload{
			UtilizationPercent: 0.0,
		},
		Metadata: make(map[string]interface{}),
		Version:  "1.0.0",
	}, nil
}

// selectNodesForRemoval selects nodes to remove during scale down
func (hsm *HorizontalScalingManager) selectNodesForRemoval(count int) []string {
	hsm.nodesMutex.RLock()
	defer hsm.nodesMutex.RUnlock()
	
	// Create a list of nodes sorted by removal priority
	// Priority: unhealthy nodes first, then least loaded nodes
	type nodeScore struct {
		id    string
		score float64
	}
	
	var nodeScores []nodeScore
	for id, node := range hsm.activeNodes {
		score := node.Health.HealthScore
		if node.Status == NodeStatusUnhealthy || node.Status == NodeStatusFailed {
			score = 0.0 // Prioritize removal of unhealthy nodes
		} else {
			score = 100.0 - node.Workload.UtilizationPercent // Lower utilization = higher removal priority
		}
		nodeScores = append(nodeScores, nodeScore{id: id, score: score})
	}
	
	// Sort by score (ascending - lowest score first)
	for i := 0; i < len(nodeScores)-1; i++ {
		for j := 0; j < len(nodeScores)-i-1; j++ {
			if nodeScores[j].score > nodeScores[j+1].score {
				nodeScores[j], nodeScores[j+1] = nodeScores[j+1], nodeScores[j]
			}
		}
	}
	
	// Select the first 'count' nodes
	var result []string
	for i := 0; i < count && i < len(nodeScores); i++ {
		result = append(result, nodeScores[i].id)
	}
	
	return result
}

// drainAndRemoveNode gracefully drains and removes a node
func (hsm *HorizontalScalingManager) drainAndRemoveNode(nodeID string) error {
	hsm.nodesMutex.Lock()
	node, exists := hsm.activeNodes[nodeID]
	if !exists {
		hsm.nodesMutex.Unlock()
		return fmt.Errorf("node %s not found", nodeID)
	}
	
	// Set node to draining status
	node.Status = NodeStatusDraining
	hsm.nodesMutex.Unlock()
	
	// Wait for active processing to complete
	drainTimeout := time.NewTimer(hsm.config.RecoveryTimeout)
	defer drainTimeout.Stop()
	
	for {
		select {
		case <-drainTimeout.C:
			hsm.logger.Warn("Node drain timeout, forcing removal",
				zap.String("node_id", nodeID),
			)
			return hsm.UnregisterNode(nodeID)
		default:
			// Check if node is idle
			if node.Workload.CurrentEventsPerSecond == 0 && node.Workload.QueueSize == 0 {
				return hsm.UnregisterNode(nodeID)
			}
			time.Sleep(1 * time.Second)
		}
	}
}

// runHealthMonitoring runs continuous health monitoring
func (hsm *HorizontalScalingManager) runHealthMonitoring() {
	ticker := time.NewTicker(hsm.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hsm.ctx.Done():
			return
		case <-ticker.C:
			hsm.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all nodes
func (hsm *HorizontalScalingManager) performHealthChecks() {
	hsm.nodesMutex.RLock()
	nodes := make([]*ProcessingNode, 0, len(hsm.activeNodes))
	for _, node := range hsm.activeNodes {
		nodes = append(nodes, node)
	}
	hsm.nodesMutex.RUnlock()
	
	for _, node := range nodes {
		health, err := hsm.healthChecker.CheckNodeHealth(node.ID)
		if err != nil {
			hsm.logger.Error("Health check failed",
				zap.String("node_id", node.ID),
				zap.Error(err),
			)
			continue
		}
		
		hsm.nodesMutex.Lock()
		node.Health = health
		node.LastSeen = time.Now()
		
		// Update node status based on health
		if health.HealthScore < hsm.config.HealthyNodeThreshold {
			if node.Status == NodeStatusHealthy {
				node.Status = NodeStatusDegraded
			} else if node.Status == NodeStatusDegraded && health.HealthScore < 30.0 {
				node.Status = NodeStatusUnhealthy
			}
		} else {
			node.Status = NodeStatusHealthy
		}
		hsm.nodesMutex.Unlock()
		
		// Handle node failures
		if node.Status == NodeStatusUnhealthy || node.Status == NodeStatusFailed {
			hsm.failoverManager.HandleNodeFailure(node.ID)
		}
	}
}

// GetScalingMetrics returns current scaling metrics
func (hsm *HorizontalScalingManager) GetScalingMetrics() *ScalingMetrics {
	return hsm.metricsCollector.GetCurrentMetrics()
}

// GetActiveNodes returns all active processing nodes
func (hsm *HorizontalScalingManager) GetActiveNodes() map[string]*ProcessingNode {
	hsm.nodesMutex.RLock()
	defer hsm.nodesMutex.RUnlock()
	
	nodes := make(map[string]*ProcessingNode)
	for id, node := range hsm.activeNodes {
		nodes[id] = node
	}
	return nodes
}

// Close gracefully shuts down the horizontal scaling manager
func (hsm *HorizontalScalingManager) Close() error {
	if hsm.cancel != nil {
		hsm.cancel()
	}
	
	if hsm.scalingTicker != nil {
		hsm.scalingTicker.Stop()
	}
	
	// Close all component managers
	if hsm.partitionManager != nil {
		hsm.partitionManager.Close()
	}
	if hsm.replicationManager != nil {
		hsm.replicationManager.Close()
	}
	if hsm.loadBalancer != nil {
		hsm.loadBalancer.Close()
	}
	if hsm.failoverManager != nil {
		hsm.failoverManager.Close()
	}
	if hsm.healthChecker != nil {
		hsm.healthChecker.Close()
	}
	if hsm.performanceMonitor != nil {
		hsm.performanceMonitor.Close()
	}
	if hsm.recoveryOrchestrator != nil {
		hsm.recoveryOrchestrator.Close()
	}
	if hsm.dataConsistencyChecker != nil {
		hsm.dataConsistencyChecker.Close()
	}
	
	hsm.logger.Info("Horizontal scaling manager closed")
	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}