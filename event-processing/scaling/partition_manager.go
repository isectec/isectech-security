package scaling

import (
	"context"
	"crypto/md5"
	"fmt"
	"hash/crc32"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PartitionManager manages data partitioning and distribution across nodes
type PartitionManager struct {
	logger           *zap.Logger
	config           *ScalingConfig
	
	// Partition state
	partitions       map[int]*Partition
	partitionsMutex  sync.RWMutex
	
	// Node assignments
	nodeAssignments  map[string][]int    // nodeID -> partition IDs
	partitionNodes   map[int][]string    // partition ID -> node IDs (including replicas)
	assignmentsMutex sync.RWMutex
	
	// Consistent hashing for partition distribution
	consistentHashRing *ConsistentHashRing
	
	// Rebalancing state
	rebalanceInProgress bool
	rebalanceMutex      sync.Mutex
	
	// Statistics
	stats               *PartitionStats
	statsMutex          sync.RWMutex
}

// Partition represents a data partition
type Partition struct {
	ID           int       `json:"id"`
	HashRange    HashRange `json:"hash_range"`
	PrimaryNode  string    `json:"primary_node"`
	ReplicaNodes []string  `json:"replica_nodes"`
	Status       PartitionStatus `json:"status"`
	EventCount   int64     `json:"event_count"`
	DataSize     int64     `json:"data_size"`
	LastAccess   time.Time `json:"last_access"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// HashRange represents a hash range for a partition
type HashRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

// PartitionStatus represents the status of a partition
type PartitionStatus string

const (
	PartitionStatusActive      PartitionStatus = "active"
	PartitionStatusMigrating   PartitionStatus = "migrating"
	PartitionStatusRebalancing PartitionStatus = "rebalancing"
	PartitionStatusOffline     PartitionStatus = "offline"
	PartitionStatusCorrupted   PartitionStatus = "corrupted"
)

// ConsistentHashRing implements consistent hashing for partition distribution
type ConsistentHashRing struct {
	ring       map[uint32]string
	nodes      []string
	virtualNodes int
	mutex      sync.RWMutex
}

// PartitionStats tracks partition management statistics
type PartitionStats struct {
	TotalPartitions     int                         `json:"total_partitions"`
	ActivePartitions    int                         `json:"active_partitions"`
	MigratingPartitions int                         `json:"migrating_partitions"`
	PartitionsByNode    map[string]int              `json:"partitions_by_node"`
	EventsByPartition   map[int]int64               `json:"events_by_partition"`
	DataSizeByPartition map[int]int64               `json:"data_size_by_partition"`
	LastRebalance       time.Time                   `json:"last_rebalance"`
	RebalanceCount      int64                       `json:"rebalance_count"`
	MigrationCount      int64                       `json:"migration_count"`
}

// NewPartitionManager creates a new partition manager
func NewPartitionManager(logger *zap.Logger, config *ScalingConfig) (*PartitionManager, error) {
	pm := &PartitionManager{
		logger:          logger.With(zap.String("component", "partition-manager")),
		config:          config,
		partitions:      make(map[int]*Partition),
		nodeAssignments: make(map[string][]int),
		partitionNodes:  make(map[int][]string),
		stats: &PartitionStats{
			PartitionsByNode:    make(map[string]int),
			EventsByPartition:   make(map[int]int64),
			DataSizeByPartition: make(map[int]int64),
		},
	}
	
	// Initialize consistent hash ring
	pm.consistentHashRing = NewConsistentHashRing(256) // 256 virtual nodes per physical node
	
	// Initialize partitions
	if err := pm.initializePartitions(); err != nil {
		return nil, fmt.Errorf("failed to initialize partitions: %w", err)
	}
	
	logger.Info("Partition manager initialized",
		zap.Int("partition_count", config.PartitionCount),
		zap.String("partition_strategy", config.PartitionStrategy),
		zap.Int("replication_factor", config.ReplicationFactor),
	)
	
	return pm, nil
}

// initializePartitions creates the initial set of partitions
func (pm *PartitionManager) initializePartitions() error {
	pm.partitionsMutex.Lock()
	defer pm.partitionsMutex.Unlock()
	
	hashRangeSize := uint32(0xFFFFFFFF) / uint32(pm.config.PartitionCount)
	
	for i := 0; i < pm.config.PartitionCount; i++ {
		partition := &Partition{
			ID: i,
			HashRange: HashRange{
				Start: uint32(i) * hashRangeSize,
				End:   uint32(i+1)*hashRangeSize - 1,
			},
			Status:       PartitionStatusOffline,
			ReplicaNodes: make([]string, 0, pm.config.ReplicationFactor-1),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		
		// Handle the last partition to cover the full range
		if i == pm.config.PartitionCount-1 {
			partition.HashRange.End = 0xFFFFFFFF
		}
		
		pm.partitions[i] = partition
	}
	
	pm.stats.TotalPartitions = pm.config.PartitionCount
	
	return nil
}

// AssignPartitions assigns partitions to a new node
func (pm *PartitionManager) AssignPartitions(nodeID string, existingNodeCount int) ([]int, error) {
	pm.assignmentsMutex.Lock()
	defer pm.assignmentsMutex.Unlock()
	
	var assignedPartitions []int
	
	switch pm.config.PartitionStrategy {
	case "round_robin":
		assignedPartitions = pm.assignPartitionsRoundRobin(nodeID, existingNodeCount)
	case "hash":
		assignedPartitions = pm.assignPartitionsHash(nodeID, existingNodeCount)
	case "range":
		assignedPartitions = pm.assignPartitionsRange(nodeID, existingNodeCount)
	case "consistent_hash":
		assignedPartitions = pm.assignPartitionsConsistentHash(nodeID, existingNodeCount)
	default:
		return nil, fmt.Errorf("unsupported partition strategy: %s", pm.config.PartitionStrategy)
	}
	
	// Update assignments
	pm.nodeAssignments[nodeID] = assignedPartitions
	
	// Update partition to node mapping
	for _, partitionID := range assignedPartitions {
		if pm.partitionNodes[partitionID] == nil {
			pm.partitionNodes[partitionID] = make([]string, 0)
		}
		pm.partitionNodes[partitionID] = append(pm.partitionNodes[partitionID], nodeID)
		
		// Update partition status and primary node
		if partition := pm.partitions[partitionID]; partition != nil {
			if partition.PrimaryNode == "" {
				partition.PrimaryNode = nodeID
				partition.Status = PartitionStatusActive
			} else {
				// This is a replica
				partition.ReplicaNodes = append(partition.ReplicaNodes, nodeID)
			}
			partition.UpdatedAt = time.Now()
		}
	}
	
	// Update statistics
	pm.updateStats()
	
	pm.logger.Info("Partitions assigned to node",
		zap.String("node_id", nodeID),
		zap.Int("partition_count", len(assignedPartitions)),
		zap.Ints("partitions", assignedPartitions),
	)
	
	return assignedPartitions, nil
}

// assignPartitionsRoundRobin assigns partitions using round-robin strategy
func (pm *PartitionManager) assignPartitionsRoundRobin(nodeID string, existingNodeCount int) []int {
	var partitions []int
	nodeIndex := existingNodeCount
	
	for i := nodeIndex; i < pm.config.PartitionCount; i += existingNodeCount + 1 {
		partitions = append(partitions, i)
	}
	
	return partitions
}

// assignPartitionsHash assigns partitions using hash-based strategy
func (pm *PartitionManager) assignPartitionsHash(nodeID string, existingNodeCount int) []int {
	hash := crc32.ChecksumIEEE([]byte(nodeID))
	targetPartitionCount := pm.config.PartitionCount / (existingNodeCount + 1)
	
	var partitions []int
	for i := 0; i < targetPartitionCount; i++ {
		partitionID := int((hash + uint32(i)) % uint32(pm.config.PartitionCount))
		partitions = append(partitions, partitionID)
	}
	
	return partitions
}

// assignPartitionsRange assigns partitions using range-based strategy
func (pm *PartitionManager) assignPartitionsRange(nodeID string, existingNodeCount int) []int {
	partitionsPerNode := pm.config.PartitionCount / (existingNodeCount + 1)
	startPartition := existingNodeCount * partitionsPerNode
	endPartition := startPartition + partitionsPerNode
	
	if existingNodeCount == 0 { // Last node gets remaining partitions
		endPartition = pm.config.PartitionCount
	}
	
	var partitions []int
	for i := startPartition; i < endPartition; i++ {
		partitions = append(partitions, i)
	}
	
	return partitions
}

// assignPartitionsConsistentHash assigns partitions using consistent hashing
func (pm *PartitionManager) assignPartitionsConsistentHash(nodeID string, existingNodeCount int) []int {
	// Add node to consistent hash ring
	pm.consistentHashRing.AddNode(nodeID)
	
	var partitions []int
	targetPartitionCount := pm.config.PartitionCount / (existingNodeCount + 1)
	
	// Find partitions that should be assigned to this node
	for i := 0; i < pm.config.PartitionCount; i++ {
		partitionKey := fmt.Sprintf("partition-%d", i)
		assignedNode := pm.consistentHashRing.GetNode(partitionKey)
		if assignedNode == nodeID {
			partitions = append(partitions, i)
		}
	}
	
	// If we don't have enough partitions, assign additional ones
	if len(partitions) < targetPartitionCount {
		for i := 0; i < pm.config.PartitionCount && len(partitions) < targetPartitionCount; i++ {
			if !pm.contains(partitions, i) {
				partitions = append(partitions, i)
			}
		}
	}
	
	return partitions
}

// ReassignPartitions reassigns partitions when a node is removed
func (pm *PartitionManager) ReassignPartitions(removedNodeID string) error {
	pm.assignmentsMutex.Lock()
	defer pm.assignmentsMutex.Unlock()
	
	// Get partitions that were assigned to the removed node
	orphanedPartitions := pm.nodeAssignments[removedNodeID]
	if len(orphanedPartitions) == 0 {
		return nil // No partitions to reassign
	}
	
	pm.logger.Info("Reassigning partitions from removed node",
		zap.String("removed_node", removedNodeID),
		zap.Int("orphaned_partitions", len(orphanedPartitions)),
	)
	
	// Remove node from assignments
	delete(pm.nodeAssignments, removedNodeID)
	
	// Remove node from consistent hash ring
	pm.consistentHashRing.RemoveNode(removedNodeID)
	
	// Find available nodes for reassignment
	availableNodes := make([]string, 0)
	for nodeID := range pm.nodeAssignments {
		if nodeID != removedNodeID {
			availableNodes = append(availableNodes, nodeID)
		}
	}
	
	if len(availableNodes) == 0 {
		return fmt.Errorf("no available nodes for partition reassignment")
	}
	
	// Reassign orphaned partitions
	for i, partitionID := range orphanedPartitions {
		targetNodeID := availableNodes[i%len(availableNodes)]
		
		// Update assignments
		pm.nodeAssignments[targetNodeID] = append(pm.nodeAssignments[targetNodeID], partitionID)
		
		// Update partition nodes mapping
		pm.updatePartitionNodeMapping(partitionID, removedNodeID, targetNodeID)
		
		// Update partition metadata
		if partition := pm.partitions[partitionID]; partition != nil {
			if partition.PrimaryNode == removedNodeID {
				// Promote a replica to primary
				if len(partition.ReplicaNodes) > 0 {
					partition.PrimaryNode = partition.ReplicaNodes[0]
					partition.ReplicaNodes = partition.ReplicaNodes[1:]
				} else {
					partition.PrimaryNode = targetNodeID
				}
			} else {
				// Remove from replica nodes
				partition.ReplicaNodes = pm.removeFromSlice(partition.ReplicaNodes, removedNodeID)
			}
			
			// Add target node as replica if it's not the primary
			if partition.PrimaryNode != targetNodeID {
				partition.ReplicaNodes = append(partition.ReplicaNodes, targetNodeID)
			}
			
			partition.UpdatedAt = time.Now()
		}
	}
	
	// Update statistics
	pm.updateStats()
	
	pm.logger.Info("Partitions reassigned successfully",
		zap.String("removed_node", removedNodeID),
		zap.Int("reassigned_partitions", len(orphanedPartitions)),
	)
	
	return nil
}

// Rebalance rebalances partitions across all active nodes
func (pm *PartitionManager) Rebalance() error {
	pm.rebalanceMutex.Lock()
	defer pm.rebalanceMutex.Unlock()
	
	if pm.rebalanceInProgress {
		return fmt.Errorf("rebalance already in progress")
	}
	
	pm.rebalanceInProgress = true
	defer func() { pm.rebalanceInProgress = false }()
	
	pm.logger.Info("Starting partition rebalancing")
	
	pm.assignmentsMutex.Lock()
	defer pm.assignmentsMutex.Unlock()
	
	// Calculate ideal distribution
	activeNodes := make([]string, 0, len(pm.nodeAssignments))
	for nodeID := range pm.nodeAssignments {
		activeNodes = append(activeNodes, nodeID)
	}
	
	if len(activeNodes) == 0 {
		return fmt.Errorf("no active nodes available for rebalancing")
	}
	
	idealPartitionsPerNode := pm.config.PartitionCount / len(activeNodes)
	remainder := pm.config.PartitionCount % len(activeNodes)
	
	// Create new balanced assignment
	newAssignments := make(map[string][]int)
	partitionIndex := 0
	
	for i, nodeID := range activeNodes {
		partitionsForNode := idealPartitionsPerNode
		if i < remainder {
			partitionsForNode++ // Distribute remainder partitions
		}
		
		partitions := make([]int, partitionsForNode)
		for j := 0; j < partitionsForNode; j++ {
			partitions[j] = partitionIndex
			partitionIndex++
		}
		
		newAssignments[nodeID] = partitions
	}
	
	// Calculate migrations needed
	migrations := pm.calculateMigrations(pm.nodeAssignments, newAssignments)
	
	pm.logger.Info("Rebalancing plan calculated",
		zap.Int("total_migrations", len(migrations)),
		zap.Int("active_nodes", len(activeNodes)),
	)
	
	// Execute migrations
	for _, migration := range migrations {
		if err := pm.executeMigration(migration); err != nil {
			pm.logger.Error("Migration failed",
				zap.Int("partition", migration.PartitionID),
				zap.String("from", migration.FromNode),
				zap.String("to", migration.ToNode),
				zap.Error(err),
			)
		}
	}
	
	// Update assignments
	pm.nodeAssignments = newAssignments
	
	// Update partition nodes mapping
	pm.rebuildPartitionNodeMapping()
	
	// Update statistics
	pm.stats.LastRebalance = time.Now()
	pm.stats.RebalanceCount++
	pm.updateStats()
	
	pm.logger.Info("Partition rebalancing completed",
		zap.Int("migrations_executed", len(migrations)),
	)
	
	return nil
}

// GetPartitionForKey returns the partition ID for a given key
func (pm *PartitionManager) GetPartitionForKey(key string) int {
	switch pm.config.PartitionStrategy {
	case "hash", "consistent_hash":
		hash := crc32.ChecksumIEEE([]byte(key))
		return int(hash % uint32(pm.config.PartitionCount))
	case "range":
		// For range partitioning, we'd need more sophisticated key analysis
		// For now, fall back to hash
		hash := crc32.ChecksumIEEE([]byte(key))
		return int(hash % uint32(pm.config.PartitionCount))
	default:
		// Default to hash-based partitioning
		hash := crc32.ChecksumIEEE([]byte(key))
		return int(hash % uint32(pm.config.PartitionCount))
	}
}

// GetNodesForPartition returns the nodes responsible for a partition
func (pm *PartitionManager) GetNodesForPartition(partitionID int) []string {
	pm.assignmentsMutex.RLock()
	defer pm.assignmentsMutex.RUnlock()
	
	if nodes, exists := pm.partitionNodes[partitionID]; exists {
		return nodes
	}
	
	return nil
}

// GetPartitionsForNode returns the partitions assigned to a node
func (pm *PartitionManager) GetPartitionsForNode(nodeID string) []int {
	pm.assignmentsMutex.RLock()
	defer pm.assignmentsMutex.RUnlock()
	
	if partitions, exists := pm.nodeAssignments[nodeID]; exists {
		return partitions
	}
	
	return nil
}

// Helper methods

func (pm *PartitionManager) updatePartitionNodeMapping(partitionID int, removeNode, addNode string) {
	nodes := pm.partitionNodes[partitionID]
	
	// Remove old node
	for i, node := range nodes {
		if node == removeNode {
			nodes = append(nodes[:i], nodes[i+1:]...)
			break
		}
	}
	
	// Add new node
	nodes = append(nodes, addNode)
	pm.partitionNodes[partitionID] = nodes
}

func (pm *PartitionManager) removeFromSlice(slice []string, item string) []string {
	for i, s := range slice {
		if s == item {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func (pm *PartitionManager) contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (pm *PartitionManager) updateStats() {
	pm.statsMutex.Lock()
	defer pm.statsMutex.Unlock()
	
	pm.stats.PartitionsByNode = make(map[string]int)
	activePartitions := 0
	migratingPartitions := 0
	
	for nodeID, partitions := range pm.nodeAssignments {
		pm.stats.PartitionsByNode[nodeID] = len(partitions)
	}
	
	for _, partition := range pm.partitions {
		if partition.Status == PartitionStatusActive {
			activePartitions++
		} else if partition.Status == PartitionStatusMigrating {
			migratingPartitions++
		}
	}
	
	pm.stats.ActivePartitions = activePartitions
	pm.stats.MigratingPartitions = migratingPartitions
}

func (pm *PartitionManager) rebuildPartitionNodeMapping() {
	pm.partitionNodes = make(map[int][]string)
	
	for nodeID, partitions := range pm.nodeAssignments {
		for _, partitionID := range partitions {
			if pm.partitionNodes[partitionID] == nil {
				pm.partitionNodes[partitionID] = make([]string, 0)
			}
			pm.partitionNodes[partitionID] = append(pm.partitionNodes[partitionID], nodeID)
		}
	}
}

// Migration represents a partition migration operation
type Migration struct {
	PartitionID int    `json:"partition_id"`
	FromNode    string `json:"from_node"`
	ToNode      string `json:"to_node"`
	Status      string `json:"status"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
}

func (pm *PartitionManager) calculateMigrations(oldAssignments, newAssignments map[string][]int) []*Migration {
	var migrations []*Migration
	
	// Find partitions that need to be moved
	for nodeID, newPartitions := range newAssignments {
		oldPartitions := oldAssignments[nodeID]
		
		for _, partitionID := range newPartitions {
			if !pm.contains(oldPartitions, partitionID) {
				// Find where this partition currently is
				fromNode := pm.findCurrentNode(partitionID, oldAssignments)
				if fromNode != "" && fromNode != nodeID {
					migrations = append(migrations, &Migration{
						PartitionID: partitionID,
						FromNode:    fromNode,
						ToNode:      nodeID,
						Status:      "pending",
						StartTime:   time.Now(),
					})
				}
			}
		}
	}
	
	return migrations
}

func (pm *PartitionManager) findCurrentNode(partitionID int, assignments map[string][]int) string {
	for nodeID, partitions := range assignments {
		if pm.contains(partitions, partitionID) {
			return nodeID
		}
	}
	return ""
}

func (pm *PartitionManager) executeMigration(migration *Migration) error {
	// Mark partition as migrating
	if partition := pm.partitions[migration.PartitionID]; partition != nil {
		partition.Status = PartitionStatusMigrating
		partition.UpdatedAt = time.Now()
	}
	
	// In a real implementation, this would:
	// 1. Copy data from source to destination
	// 2. Verify data integrity
	// 3. Update routing tables
	// 4. Remove data from source
	
	// For now, simulate migration time
	time.Sleep(100 * time.Millisecond)
	
	// Mark partition as active on new node
	if partition := pm.partitions[migration.PartitionID]; partition != nil {
		partition.Status = PartitionStatusActive
		partition.PrimaryNode = migration.ToNode
		partition.UpdatedAt = time.Now()
	}
	
	migration.Status = "completed"
	migration.EndTime = time.Now()
	
	pm.stats.MigrationCount++
	
	return nil
}

// GetPartitionStats returns partition management statistics
func (pm *PartitionManager) GetPartitionStats() *PartitionStats {
	pm.statsMutex.RLock()
	defer pm.statsMutex.RUnlock()
	
	stats := *pm.stats
	return &stats
}

// Close gracefully shuts down the partition manager
func (pm *PartitionManager) Close() error {
	pm.logger.Info("Partition manager closing")
	return nil
}

// ConsistentHashRing implementation

func NewConsistentHashRing(virtualNodes int) *ConsistentHashRing {
	return &ConsistentHashRing{
		ring:         make(map[uint32]string),
		virtualNodes: virtualNodes,
	}
}

func (chr *ConsistentHashRing) AddNode(node string) {
	chr.mutex.Lock()
	defer chr.mutex.Unlock()
	
	for i := 0; i < chr.virtualNodes; i++ {
		virtualNodeKey := fmt.Sprintf("%s:%d", node, i)
		hash := crc32.ChecksumIEEE([]byte(virtualNodeKey))
		chr.ring[hash] = node
	}
	
	chr.nodes = append(chr.nodes, node)
	sort.Strings(chr.nodes)
}

func (chr *ConsistentHashRing) RemoveNode(node string) {
	chr.mutex.Lock()
	defer chr.mutex.Unlock()
	
	for i := 0; i < chr.virtualNodes; i++ {
		virtualNodeKey := fmt.Sprintf("%s:%d", node, i)
		hash := crc32.ChecksumIEEE([]byte(virtualNodeKey))
		delete(chr.ring, hash)
	}
	
	for i, n := range chr.nodes {
		if n == node {
			chr.nodes = append(chr.nodes[:i], chr.nodes[i+1:]...)
			break
		}
	}
}

func (chr *ConsistentHashRing) GetNode(key string) string {
	chr.mutex.RLock()
	defer chr.mutex.RUnlock()
	
	if len(chr.ring) == 0 {
		return ""
	}
	
	hash := crc32.ChecksumIEEE([]byte(key))
	
	// Find the first node with hash >= key hash
	var keys []uint32
	for k := range chr.ring {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	
	for _, k := range keys {
		if k >= hash {
			return chr.ring[k]
		}
	}
	
	// Wrap around to the first node
	return chr.ring[keys[0]]
}