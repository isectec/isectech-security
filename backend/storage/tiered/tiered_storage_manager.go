package tiered

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TieredStorageManager manages tiered storage with compression and partitioning
type TieredStorageManager struct {
	logger             *zap.Logger
	config             *TieredStorageConfig
	
	// Storage tiers
	hotTier            *StorageTier
	warmTier           *StorageTier
	coldTier           *StorageTier
	archiveTier        *StorageTier
	
	// Tier management
	tierManager        *TierManager
	migrationEngine    *MigrationEngine
	compressionEngine  *CompressionEngine
	partitionManager   *PartitionManager
	
	// Background processing
	ctx                context.Context
	cancel             context.CancelFunc
	migrationTicker    *time.Ticker
	maintenanceTicker  *time.Ticker
	
	// Statistics
	stats              *TieredStorageStats
	statsMutex         sync.RWMutex
}

// TieredStorageConfig defines tiered storage configuration
type TieredStorageConfig struct {
	// Tier definitions
	HotTierConfig      *TierConfig    `json:"hot_tier"`
	WarmTierConfig     *TierConfig    `json:"warm_tier"`
	ColdTierConfig     *TierConfig    `json:"cold_tier"`
	ArchiveTierConfig  *TierConfig    `json:"archive_tier"`
	
	// Migration rules
	MigrationRules     []*MigrationRule `json:"migration_rules"`
	MigrationInterval  time.Duration    `json:"migration_interval"`
	ParallelMigrations int              `json:"parallel_migrations"`
	
	// Compression settings
	CompressionEnabled bool             `json:"compression_enabled"`
	CompressionPolicy  *CompressionPolicy `json:"compression_policy"`
	
	// Partitioning settings
	PartitioningEnabled bool            `json:"partitioning_enabled"`
	PartitionStrategy   string          `json:"partition_strategy"` // time, tenant, size, hybrid
	PartitionSize       string          `json:"partition_size"`
	PartitionInterval   time.Duration   `json:"partition_interval"`
	
	// Performance settings
	MaintenanceInterval time.Duration   `json:"maintenance_interval"`
	MonitoringEnabled   bool            `json:"monitoring_enabled"`
	MetricsEnabled      bool            `json:"metrics_enabled"`
}

// TierConfig defines configuration for a storage tier
type TierConfig struct {
	Name                string            `json:"name"`
	StorageType         string            `json:"storage_type"` // ssd, hdd, s3, glacier
	Location            string            `json:"location"`
	MaxSize             string            `json:"max_size"`
	MaxAge              time.Duration     `json:"max_age"`
	CompressionLevel    int               `json:"compression_level"`
	ReplicationFactor   int               `json:"replication_factor"`
	AccessPatterns      []string          `json:"access_patterns"`
	CostPerGB           float64           `json:"cost_per_gb"`
	IOPSLimit           int               `json:"iops_limit"`
	BandwidthLimit      string            `json:"bandwidth_limit"`
	Encryption          bool              `json:"encryption"`
	Settings            map[string]interface{} `json:"settings"`
}

// StorageTier represents a storage tier
type StorageTier struct {
	Config             *TierConfig
	Backend            StorageBackend
	Stats              *TierStats
	Health             *TierHealth
	mutex              sync.RWMutex
}

// TierStats tracks tier-level statistics
type TierStats struct {
	DataSize           int64         `json:"data_size"`
	DocumentCount      int64         `json:"document_count"`
	WriteOperations    int64         `json:"write_operations"`
	ReadOperations     int64         `json:"read_operations"`
	CompressionRatio   float64       `json:"compression_ratio"`
	AverageLatency     time.Duration `json:"average_latency"`
	ThroughputMBps     float64       `json:"throughput_mbps"`
	ErrorCount         int64         `json:"error_count"`
	LastMigration      time.Time     `json:"last_migration"`
	CostPerDay         float64       `json:"cost_per_day"`
}

// TierHealth tracks tier health status
type TierHealth struct {
	Status             string        `json:"status"` // healthy, degraded, unhealthy
	LastHealthCheck    time.Time     `json:"last_health_check"`
	HealthScore        float64       `json:"health_score"`
	Issues             []string      `json:"issues"`
	Uptime             time.Duration `json:"uptime"`
}

// MigrationRule defines rules for data migration between tiers
type MigrationRule struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	SourceTier         string            `json:"source_tier"`
	DestinationTier    string            `json:"destination_tier"`
	Conditions         []*MigrationCondition `json:"conditions"`
	Actions            []*MigrationAction    `json:"actions"`
	Priority           int               `json:"priority"`
	Enabled            bool              `json:"enabled"`
	Schedule           string            `json:"schedule"` // cron expression
}

// MigrationCondition defines conditions for migration
type MigrationCondition struct {
	Type               string            `json:"type"` // age, size, access_pattern, cost
	Operator           string            `json:"operator"` // gt, lt, eq, gte, lte
	Value              interface{}       `json:"value"`
	Field              string            `json:"field,omitempty"`
}

// MigrationAction defines actions to perform during migration
type MigrationAction struct {
	Type               string            `json:"type"` // compress, encrypt, partition, index
	Parameters         map[string]interface{} `json:"parameters"`
}

// CompressionPolicy defines compression strategies for different data types
type CompressionPolicy struct {
	DefaultAlgorithm   string            `json:"default_algorithm"` // gzip, lz4, zstd, brotli
	Algorithms         map[string]*CompressionAlgorithmConfig `json:"algorithms"`
	DataTypeRules      map[string]*CompressionRule `json:"data_type_rules"`
}

// CompressionAlgorithmConfig defines algorithm-specific settings
type CompressionAlgorithmConfig struct {
	Level              int               `json:"level"`
	WindowSize         int               `json:"window_size,omitempty"`
	BlockSize          int               `json:"block_size,omitempty"`
	Threads            int               `json:"threads,omitempty"`
	Dictionary         []byte            `json:"dictionary,omitempty"`
}

// CompressionRule defines compression rules for specific data types
type CompressionRule struct {
	Algorithm          string            `json:"algorithm"`
	Level              int               `json:"level"`
	Conditions         []string          `json:"conditions"`
	CompressionRatio   float64           `json:"expected_compression_ratio"`
}

// TieredStorageStats tracks overall tiered storage statistics
type TieredStorageStats struct {
	TotalDataSize      int64             `json:"total_data_size"`
	TotalDocuments     int64             `json:"total_documents"`
	TierDistribution   map[string]int64  `json:"tier_distribution"`
	MigrationCount     int64             `json:"migration_count"`
	CompressionSavings int64             `json:"compression_savings"`
	TotalCostPerDay    float64           `json:"total_cost_per_day"`
	AverageQueryTime   time.Duration     `json:"average_query_time"`
	ThroughputMBps     float64           `json:"throughput_mbps"`
	LastMaintenance    time.Time         `json:"last_maintenance"`
}

// StorageBackend defines the interface for storage backends
type StorageBackend interface {
	Write(ctx context.Context, key string, data []byte) error
	Read(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
	Size(ctx context.Context, key string) (int64, error)
	Exists(ctx context.Context, key string) (bool, error)
	GetStats() *BackendStats
	IsHealthy() bool
	Close() error
}

// BackendStats represents backend-specific statistics
type BackendStats struct {
	ReadLatency        time.Duration     `json:"read_latency"`
	WriteLatency       time.Duration     `json:"write_latency"`
	ThroughputMBps     float64           `json:"throughput_mbps"`
	ErrorRate          float64           `json:"error_rate"`
	AvailableSpace     int64             `json:"available_space"`
	UsedSpace          int64             `json:"used_space"`
}

// NewTieredStorageManager creates a new tiered storage manager
func NewTieredStorageManager(logger *zap.Logger, config *TieredStorageConfig) (*TieredStorageManager, error) {
	if config == nil {
		return nil, fmt.Errorf("tiered storage configuration is required")
	}
	
	// Set defaults
	if err := setTieredStorageDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &TieredStorageManager{
		logger: logger.With(zap.String("component", "tiered-storage-manager")),
		config: config,
		stats:  &TieredStorageStats{
			TierDistribution: make(map[string]int64),
		},
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize storage tiers
	if err := manager.initializeStorageTiers(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize storage tiers: %w", err)
	}
	
	// Initialize management components
	manager.tierManager = NewTierManager(logger, manager)
	manager.migrationEngine = NewMigrationEngine(logger, config, manager)
	manager.compressionEngine = NewCompressionEngine(logger, config.CompressionPolicy)
	manager.partitionManager = NewPartitionManager(logger, config)
	
	// Start background processing
	if config.MigrationInterval > 0 {
		manager.migrationTicker = time.NewTicker(config.MigrationInterval)
		go manager.runMigrationProcess()
	}
	
	if config.MaintenanceInterval > 0 {
		manager.maintenanceTicker = time.NewTicker(config.MaintenanceInterval)
		go manager.runMaintenanceProcess()
	}
	
	logger.Info("Tiered storage manager initialized",
		zap.Bool("compression_enabled", config.CompressionEnabled),
		zap.Bool("partitioning_enabled", config.PartitioningEnabled),
		zap.String("partition_strategy", config.PartitionStrategy),
		zap.Int("migration_rules", len(config.MigrationRules)),
	)
	
	return manager, nil
}

// setTieredStorageDefaults sets configuration defaults
func setTieredStorageDefaults(config *TieredStorageConfig) error {
	if config.MigrationInterval == 0 {
		config.MigrationInterval = 1 * time.Hour
	}
	if config.ParallelMigrations == 0 {
		config.ParallelMigrations = 3
	}
	if config.MaintenanceInterval == 0 {
		config.MaintenanceInterval = 6 * time.Hour
	}
	if config.PartitionStrategy == "" {
		config.PartitionStrategy = "time"
	}
	if config.PartitionSize == "" {
		config.PartitionSize = "1GB"
	}
	if config.PartitionInterval == 0 {
		config.PartitionInterval = 24 * time.Hour
	}
	
	// Set default tier configurations if not provided
	if config.HotTierConfig == nil {
		config.HotTierConfig = &TierConfig{
			Name:              "hot",
			StorageType:       "ssd",
			MaxAge:            7 * 24 * time.Hour,
			CompressionLevel:  1,
			ReplicationFactor: 2,
			CostPerGB:         0.10,
		}
	}
	
	if config.WarmTierConfig == nil {
		config.WarmTierConfig = &TierConfig{
			Name:              "warm",
			StorageType:       "hdd",
			MaxAge:            30 * 24 * time.Hour,
			CompressionLevel:  6,
			ReplicationFactor: 1,
			CostPerGB:         0.03,
		}
	}
	
	if config.ColdTierConfig == nil {
		config.ColdTierConfig = &TierConfig{
			Name:              "cold",
			StorageType:       "s3",
			MaxAge:            365 * 24 * time.Hour,
			CompressionLevel:  9,
			ReplicationFactor: 0,
			CostPerGB:         0.01,
		}
	}
	
	if config.ArchiveTierConfig == nil {
		config.ArchiveTierConfig = &TierConfig{
			Name:              "archive",
			StorageType:       "glacier",
			MaxAge:            0, // No age limit
			CompressionLevel:  9,
			ReplicationFactor: 0,
			CostPerGB:         0.004,
		}
	}
	
	// Set default compression policy
	if config.CompressionPolicy == nil {
		config.CompressionPolicy = &CompressionPolicy{
			DefaultAlgorithm: "zstd",
			Algorithms: map[string]*CompressionAlgorithmConfig{
				"zstd": {
					Level:     6,
					Threads:   4,
				},
				"lz4": {
					Level:     1,
				},
				"gzip": {
					Level:     6,
				},
			},
			DataTypeRules: map[string]*CompressionRule{
				"security_events": {
					Algorithm:          "zstd",
					Level:             6,
					CompressionRatio:   0.3,
				},
				"metrics": {
					Algorithm:          "lz4",
					Level:             1,
					CompressionRatio:   0.5,
				},
				"logs": {
					Algorithm:          "gzip",
					Level:             6,
					CompressionRatio:   0.2,
				},
			},
		}
	}
	
	// Create default migration rules if none provided
	if len(config.MigrationRules) == 0 {
		config.MigrationRules = []*MigrationRule{
			{
				ID:              "hot-to-warm",
				Name:            "Hot to Warm Migration",
				SourceTier:      "hot",
				DestinationTier: "warm",
				Conditions: []*MigrationCondition{
					{
						Type:     "age",
						Operator: "gte",
						Value:    "7d",
					},
				},
				Actions: []*MigrationAction{
					{
						Type: "compress",
						Parameters: map[string]interface{}{
							"algorithm": "zstd",
							"level":     6,
						},
					},
				},
				Priority: 100,
				Enabled:  true,
			},
			{
				ID:              "warm-to-cold",
				Name:            "Warm to Cold Migration",
				SourceTier:      "warm",
				DestinationTier: "cold",
				Conditions: []*MigrationCondition{
					{
						Type:     "age",
						Operator: "gte",
						Value:    "30d",
					},
				},
				Actions: []*MigrationAction{
					{
						Type: "compress",
						Parameters: map[string]interface{}{
							"algorithm": "zstd",
							"level":     9,
						},
					},
				},
				Priority: 90,
				Enabled:  true,
			},
			{
				ID:              "cold-to-archive",
				Name:            "Cold to Archive Migration",
				SourceTier:      "cold",
				DestinationTier: "archive",
				Conditions: []*MigrationCondition{
					{
						Type:     "age",
						Operator: "gte",
						Value:    "365d",
					},
				},
				Actions: []*MigrationAction{
					{
						Type: "compress",
						Parameters: map[string]interface{}{
							"algorithm": "zstd",
							"level":     9,
						},
					},
					{
						Type: "encrypt",
						Parameters: map[string]interface{}{
							"algorithm": "aes-256",
						},
					},
				},
				Priority: 80,
				Enabled:  true,
			},
		}
	}
	
	return nil
}

// initializeStorageTiers initializes all storage tiers
func (tsm *TieredStorageManager) initializeStorageTiers() error {
	// Initialize hot tier
	if tsm.config.HotTierConfig != nil {
		hotBackend, err := createStorageBackend(tsm.config.HotTierConfig)
		if err != nil {
			return fmt.Errorf("failed to create hot tier backend: %w", err)
		}
		
		tsm.hotTier = &StorageTier{
			Config:  tsm.config.HotTierConfig,
			Backend: hotBackend,
			Stats:   &TierStats{},
			Health:  &TierHealth{Status: "healthy"},
		}
	}
	
	// Initialize warm tier
	if tsm.config.WarmTierConfig != nil {
		warmBackend, err := createStorageBackend(tsm.config.WarmTierConfig)
		if err != nil {
			return fmt.Errorf("failed to create warm tier backend: %w", err)
		}
		
		tsm.warmTier = &StorageTier{
			Config:  tsm.config.WarmTierConfig,
			Backend: warmBackend,
			Stats:   &TierStats{},
			Health:  &TierHealth{Status: "healthy"},
		}
	}
	
	// Initialize cold tier
	if tsm.config.ColdTierConfig != nil {
		coldBackend, err := createStorageBackend(tsm.config.ColdTierConfig)
		if err != nil {
			return fmt.Errorf("failed to create cold tier backend: %w", err)
		}
		
		tsm.coldTier = &StorageTier{
			Config:  tsm.config.ColdTierConfig,
			Backend: coldBackend,
			Stats:   &TierStats{},
			Health:  &TierHealth{Status: "healthy"},
		}
	}
	
	// Initialize archive tier
	if tsm.config.ArchiveTierConfig != nil {
		archiveBackend, err := createStorageBackend(tsm.config.ArchiveTierConfig)
		if err != nil {
			return fmt.Errorf("failed to create archive tier backend: %w", err)
		}
		
		tsm.archiveTier = &StorageTier{
			Config:  tsm.config.ArchiveTierConfig,
			Backend: archiveBackend,
			Stats:   &TierStats{},
			Health:  &TierHealth{Status: "healthy"},
		}
	}
	
	return nil
}

// createStorageBackend creates a storage backend based on configuration
func createStorageBackend(config *TierConfig) (StorageBackend, error) {
	switch config.StorageType {
	case "ssd", "hdd":
		return NewFilesystemBackend(config)
	case "s3":
		return NewS3Backend(config)
	case "glacier":
		return NewGlacierBackend(config)
	case "azure":
		return NewAzureBackend(config)
	case "gcs":
		return NewGCSBackend(config)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.StorageType)
	}
}

// WriteData writes data to the appropriate tier
func (tsm *TieredStorageManager) WriteData(ctx context.Context, key string, data []byte, metadata map[string]interface{}) error {
	// Determine the target tier (new data goes to hot tier)
	tier := tsm.hotTier
	if tier == nil {
		return fmt.Errorf("hot tier not available")
	}
	
	// Apply compression if enabled
	var finalData []byte
	var err error
	
	if tsm.config.CompressionEnabled {
		dataType := getDataTypeFromMetadata(metadata)
		finalData, err = tsm.compressionEngine.Compress(data, dataType)
		if err != nil {
			tsm.logger.Warn("Failed to compress data, writing uncompressed",
				zap.String("key", key),
				zap.Error(err),
			)
			finalData = data
		}
	} else {
		finalData = data
	}
	
	// Apply partitioning if enabled
	if tsm.config.PartitioningEnabled {
		key = tsm.partitionManager.GeneratePartitionedKey(key, metadata)
	}
	
	// Write to tier
	start := time.Now()
	if err := tier.Backend.Write(ctx, key, finalData); err != nil {
		tier.mutex.Lock()
		tier.Stats.ErrorCount++
		tier.mutex.Unlock()
		return fmt.Errorf("failed to write to tier %s: %w", tier.Config.Name, err)
	}
	
	// Update statistics
	duration := time.Since(start)
	originalSize := int64(len(data))
	compressedSize := int64(len(finalData))
	
	tier.mutex.Lock()
	tier.Stats.WriteOperations++
	tier.Stats.DataSize += compressedSize
	tier.Stats.DocumentCount++
	tier.Stats.AverageLatency = (tier.Stats.AverageLatency + duration) / 2
	if originalSize > 0 {
		tier.Stats.CompressionRatio = float64(compressedSize) / float64(originalSize)
	}
	tier.mutex.Unlock()
	
	// Update global statistics
	tsm.statsMutex.Lock()
	tsm.stats.TotalDataSize += compressedSize
	tsm.stats.TotalDocuments++
	tsm.stats.TierDistribution[tier.Config.Name] += compressedSize
	if originalSize > compressedSize {
		tsm.stats.CompressionSavings += originalSize - compressedSize
	}
	tsm.statsMutex.Unlock()
	
	tsm.logger.Debug("Data written to tier",
		zap.String("key", key),
		zap.String("tier", tier.Config.Name),
		zap.Int64("original_size", originalSize),
		zap.Int64("compressed_size", compressedSize),
		zap.Duration("duration", duration),
	)
	
	return nil
}

// ReadData reads data from the appropriate tier
func (tsm *TieredStorageManager) ReadData(ctx context.Context, key string) ([]byte, error) {
	// Search tiers from hot to cold
	tiers := []*StorageTier{tsm.hotTier, tsm.warmTier, tsm.coldTier, tsm.archiveTier}
	
	for _, tier := range tiers {
		if tier == nil {
			continue
		}
		
		start := time.Now()
		
		// Check if data exists in this tier
		exists, err := tier.Backend.Exists(ctx, key)
		if err != nil {
			tsm.logger.Warn("Failed to check existence in tier",
				zap.String("tier", tier.Config.Name),
				zap.String("key", key),
				zap.Error(err),
			)
			continue
		}
		
		if !exists {
			continue
		}
		
		// Read data from tier
		data, err := tier.Backend.Read(ctx, key)
		if err != nil {
			tier.mutex.Lock()
			tier.Stats.ErrorCount++
			tier.mutex.Unlock()
			
			tsm.logger.Warn("Failed to read from tier",
				zap.String("tier", tier.Config.Name),
				zap.String("key", key),
				zap.Error(err),
			)
			continue
		}
		
		// Decompress data if necessary
		var finalData []byte
		if tsm.config.CompressionEnabled {
			finalData, err = tsm.compressionEngine.Decompress(data)
			if err != nil {
				tsm.logger.Warn("Failed to decompress data, returning compressed",
					zap.String("key", key),
					zap.Error(err),
				)
				finalData = data
			}
		} else {
			finalData = data
		}
		
		// Update statistics
		duration := time.Since(start)
		
		tier.mutex.Lock()
		tier.Stats.ReadOperations++
		tier.Stats.AverageLatency = (tier.Stats.AverageLatency + duration) / 2
		tier.mutex.Unlock()
		
		tsm.logger.Debug("Data read from tier",
			zap.String("key", key),
			zap.String("tier", tier.Config.Name),
			zap.Duration("duration", duration),
		)
		
		return finalData, nil
	}
	
	return nil, fmt.Errorf("data not found in any tier: %s", key)
}

// runMigrationProcess runs the background migration process
func (tsm *TieredStorageManager) runMigrationProcess() {
	for {
		select {
		case <-tsm.ctx.Done():
			return
		case <-tsm.migrationTicker.C:
			tsm.performMigrations()
		}
	}
}

// performMigrations performs data migrations based on rules
func (tsm *TieredStorageManager) performMigrations() {
	start := time.Now()
	
	tsm.logger.Debug("Starting migration process")
	
	// Process migration rules by priority
	for _, rule := range tsm.config.MigrationRules {
		if !rule.Enabled {
			continue
		}
		
		if err := tsm.migrationEngine.ProcessRule(tsm.ctx, rule); err != nil {
			tsm.logger.Error("Failed to process migration rule",
				zap.String("rule_id", rule.ID),
				zap.Error(err),
			)
		}
	}
	
	duration := time.Since(start)
	tsm.logger.Debug("Migration process completed", zap.Duration("duration", duration))
}

// runMaintenanceProcess runs background maintenance tasks
func (tsm *TieredStorageManager) runMaintenanceProcess() {
	for {
		select {
		case <-tsm.ctx.Done():
			return
		case <-tsm.maintenanceTicker.C:
			tsm.performMaintenance()
		}
	}
}

// performMaintenance performs maintenance tasks
func (tsm *TieredStorageManager) performMaintenance() {
	start := time.Now()
	
	tsm.logger.Debug("Starting maintenance process")
	
	// Update tier health
	tsm.updateTierHealth()
	
	// Update statistics
	tsm.updateStatistics()
	
	// Cleanup expired data
	tsm.cleanupExpiredData()
	
	// Optimize storage
	tsm.optimizeStorage()
	
	duration := time.Since(start)
	
	tsm.statsMutex.Lock()
	tsm.stats.LastMaintenance = time.Now()
	tsm.statsMutex.Unlock()
	
	tsm.logger.Debug("Maintenance process completed", zap.Duration("duration", duration))
}

// updateTierHealth updates health status for all tiers
func (tsm *TieredStorageManager) updateTierHealth() {
	tiers := []*StorageTier{tsm.hotTier, tsm.warmTier, tsm.coldTier, tsm.archiveTier}
	
	for _, tier := range tiers {
		if tier == nil {
			continue
		}
		
		tier.mutex.Lock()
		tier.Health.LastHealthCheck = time.Now()
		tier.Health.Issues = tier.Health.Issues[:0] // Clear previous issues
		
		// Check backend health
		if !tier.Backend.IsHealthy() {
			tier.Health.Status = "unhealthy"
			tier.Health.Issues = append(tier.Health.Issues, "backend unhealthy")
			tier.Health.HealthScore = 0.0
		} else {
			// Calculate health score based on error rate and performance
			errorRate := float64(tier.Stats.ErrorCount) / float64(tier.Stats.ReadOperations+tier.Stats.WriteOperations+1)
			if errorRate > 0.05 {
				tier.Health.Status = "degraded"
				tier.Health.Issues = append(tier.Health.Issues, "high error rate")
				tier.Health.HealthScore = 0.5
			} else {
				tier.Health.Status = "healthy"
				tier.Health.HealthScore = 1.0
			}
		}
		tier.mutex.Unlock()
	}
}

// updateStatistics updates global statistics
func (tsm *TieredStorageManager) updateStatistics() {
	tsm.statsMutex.Lock()
	defer tsm.statsMutex.Unlock()
	
	// Reset tier distribution
	for k := range tsm.stats.TierDistribution {
		tsm.stats.TierDistribution[k] = 0
	}
	
	// Aggregate tier statistics
	tiers := []*StorageTier{tsm.hotTier, tsm.warmTier, tsm.coldTier, tsm.archiveTier}
	tsm.stats.TotalDataSize = 0
	tsm.stats.TotalDocuments = 0
	tsm.stats.TotalCostPerDay = 0
	
	for _, tier := range tiers {
		if tier == nil {
			continue
		}
		
		tier.mutex.RLock()
		tsm.stats.TierDistribution[tier.Config.Name] = tier.Stats.DataSize
		tsm.stats.TotalDataSize += tier.Stats.DataSize
		tsm.stats.TotalDocuments += tier.Stats.DocumentCount
		
		// Calculate cost
		sizeGB := float64(tier.Stats.DataSize) / (1024 * 1024 * 1024)
		tier.Stats.CostPerDay = sizeGB * tier.Config.CostPerGB
		tsm.stats.TotalCostPerDay += tier.Stats.CostPerDay
		tier.mutex.RUnlock()
	}
}

// cleanupExpiredData removes expired data from tiers
func (tsm *TieredStorageManager) cleanupExpiredData() {
	// Implementation would scan tiers for expired data and remove it
	tsm.logger.Debug("Cleanup expired data completed")
}

// optimizeStorage performs storage optimization
func (tsm *TieredStorageManager) optimizeStorage() {
	// Implementation would perform storage optimization tasks
	tsm.logger.Debug("Storage optimization completed")
}

// getDataTypeFromMetadata extracts data type from metadata
func getDataTypeFromMetadata(metadata map[string]interface{}) string {
	if dataType, exists := metadata["data_type"]; exists {
		if dt, ok := dataType.(string); ok {
			return dt
		}
	}
	return "unknown"
}

// GetTierStats returns statistics for a specific tier
func (tsm *TieredStorageManager) GetTierStats(tierName string) (*TierStats, error) {
	var tier *StorageTier
	
	switch tierName {
	case "hot":
		tier = tsm.hotTier
	case "warm":
		tier = tsm.warmTier
	case "cold":
		tier = tsm.coldTier
	case "archive":
		tier = tsm.archiveTier
	default:
		return nil, fmt.Errorf("unknown tier: %s", tierName)
	}
	
	if tier == nil {
		return nil, fmt.Errorf("tier not configured: %s", tierName)
	}
	
	tier.mutex.RLock()
	stats := *tier.Stats
	tier.mutex.RUnlock()
	
	return &stats, nil
}

// GetOverallStats returns overall tiered storage statistics
func (tsm *TieredStorageManager) GetOverallStats() *TieredStorageStats {
	tsm.statsMutex.RLock()
	defer tsm.statsMutex.RUnlock()
	
	stats := *tsm.stats
	return &stats
}

// IsHealthy returns the overall health status
func (tsm *TieredStorageManager) IsHealthy() bool {
	tiers := []*StorageTier{tsm.hotTier, tsm.warmTier, tsm.coldTier, tsm.archiveTier}
	
	for _, tier := range tiers {
		if tier == nil {
			continue
		}
		
		tier.mutex.RLock()
		healthy := tier.Health.Status != "unhealthy"
		tier.mutex.RUnlock()
		
		if !healthy {
			return false
		}
	}
	
	return true
}

// Close closes the tiered storage manager
func (tsm *TieredStorageManager) Close() error {
	if tsm.cancel != nil {
		tsm.cancel()
	}
	
	if tsm.migrationTicker != nil {
		tsm.migrationTicker.Stop()
	}
	
	if tsm.maintenanceTicker != nil {
		tsm.maintenanceTicker.Stop()
	}
	
	// Close all tiers
	tiers := []*StorageTier{tsm.hotTier, tsm.warmTier, tsm.coldTier, tsm.archiveTier}
	for _, tier := range tiers {
		if tier != nil && tier.Backend != nil {
			tier.Backend.Close()
		}
	}
	
	if tsm.migrationEngine != nil {
		tsm.migrationEngine.Close()
	}
	
	if tsm.compressionEngine != nil {
		tsm.compressionEngine.Close()
	}
	
	if tsm.partitionManager != nil {
		tsm.partitionManager.Close()
	}
	
	tsm.logger.Info("Tiered storage manager closed")
	return nil
}

// Placeholder implementations for supporting components
func NewTierManager(logger *zap.Logger, tsm *TieredStorageManager) *TierManager {
	return &TierManager{}
}

func NewMigrationEngine(logger *zap.Logger, config *TieredStorageConfig, tsm *TieredStorageManager) *MigrationEngine {
	return &MigrationEngine{}
}

func NewCompressionEngine(logger *zap.Logger, policy *CompressionPolicy) *CompressionEngine {
	return &CompressionEngine{}
}

func NewPartitionManager(logger *zap.Logger, config *TieredStorageConfig) *PartitionManager {
	return &PartitionManager{}
}

// Supporting component placeholders
type TierManager struct{}
type MigrationEngine struct {
	ProcessRule func(ctx context.Context, rule *MigrationRule) error
	Close       func() error
}
type CompressionEngine struct {
	Compress   func(data []byte, dataType string) ([]byte, error)
	Decompress func(data []byte) ([]byte, error)
	Close      func() error
}
type PartitionManager struct {
	GeneratePartitionedKey func(key string, metadata map[string]interface{}) string
	Close                  func() error
}

// Placeholder backend implementations
func NewFilesystemBackend(config *TierConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("filesystem backend not implemented")
}

func NewS3Backend(config *TierConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("S3 backend not implemented")
}

func NewGlacierBackend(config *TierConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("Glacier backend not implemented")
}

func NewAzureBackend(config *TierConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("Azure backend not implemented")
}

func NewGCSBackend(config *TierConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("GCS backend not implemented")
}