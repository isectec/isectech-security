package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.uber.org/zap"
)

// ElasticsearchClient provides a production-grade Elasticsearch client for iSECTECH
type ElasticsearchClient struct {
	client            *elasticsearch.Client
	logger            *zap.Logger
	config            *ElasticsearchConfig
	indexManager      *IndexManager
	templateManager   *TemplateManager
	lifecycleManager  *LifecycleManager
	bulkProcessor     *BulkProcessor
	
	// Connection management
	mu                sync.RWMutex
	isHealthy         bool
	clusterHealth     *ClusterHealth
	lastHealthCheck   time.Time
	
	// Background processing
	ctx               context.Context
	cancel            context.CancelFunc
	maintenanceTicker *time.Ticker
	
	// Statistics
	stats             *ClientStats
}

// ElasticsearchConfig defines Elasticsearch configuration for iSECTECH
type ElasticsearchConfig struct {
	// Cluster settings
	Addresses         []string      `json:"addresses"`
	Username          string        `json:"username"`
	Password          string        `json:"password"`
	APIKey            string        `json:"api_key"`
	CloudID           string        `json:"cloud_id"`
	
	// TLS settings
	CertificateFingerprint string   `json:"certificate_fingerprint"`
	CACert                 string   `json:"ca_cert"`
	InsecureSkipVerify     bool     `json:"insecure_skip_verify"`
	
	// Connection settings
	MaxRetries            int          `json:"max_retries"`
	RetryInterval         time.Duration `json:"retry_interval"`
	RequestTimeout        time.Duration `json:"request_timeout"`
	MaxIdleConns          int          `json:"max_idle_conns"`
	MaxIdleConnsPerHost   int          `json:"max_idle_conns_per_host"`
	
	// Bulk processing settings
	BulkSize              int          `json:"bulk_size"`
	BulkFlushInterval     time.Duration `json:"bulk_flush_interval"`
	BulkWorkers           int          `json:"bulk_workers"`
	BulkTimeout           time.Duration `json:"bulk_timeout"`
	
	// Index settings
	DefaultReplicas       int          `json:"default_replicas"`
	DefaultShards         int          `json:"default_shards"`
	RefreshInterval       string       `json:"refresh_interval"`
	IndexCodec            string       `json:"index_codec"`
	
	// Security settings
	EnableSecurity        bool         `json:"enable_security"`
	SecurityIndexPattern  string       `json:"security_index_pattern"`
	TenantFieldName       string       `json:"tenant_field_name"`
	
	// Lifecycle settings
	EnableILM             bool         `json:"enable_ilm"`
	HotPhaseSize          string       `json:"hot_phase_size"`
	WarmPhaseAge          string       `json:"warm_phase_age"`
	ColdPhaseAge          string       `json:"cold_phase_age"`
	DeletePhaseAge        string       `json:"delete_phase_age"`
	
	// Maintenance settings
	MaintenanceInterval   time.Duration `json:"maintenance_interval"`
	EnableForcemerge      bool         `json:"enable_forcemerge"`
	ForcemergeMaxSegments int          `json:"forcemerge_max_segments"`
}

// IndexManager manages Elasticsearch indices
type IndexManager struct {
	client    *elasticsearch.Client
	logger    *zap.Logger
	config    *ElasticsearchConfig
	templates map[string]*IndexTemplate
	mu        sync.RWMutex
}

// TemplateManager manages index templates
type TemplateManager struct {
	client *elasticsearch.Client
	logger *zap.Logger
	templates map[string]*IndexTemplate
}

// LifecycleManager manages index lifecycle policies
type LifecycleManager struct {
	client   *elasticsearch.Client
	logger   *zap.Logger
	policies map[string]*LifecyclePolicy
}

// BulkProcessor handles bulk operations
type BulkProcessor struct {
	client        *elasticsearch.Client
	logger        *zap.Logger
	config        *ElasticsearchConfig
	buffer        []BulkOperation
	mu            sync.Mutex
	flushTicker   *time.Ticker
	workers       chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
}

// ClientStats tracks client performance metrics
type ClientStats struct {
	IndexedDocuments int64         `json:"indexed_documents"`
	SearchRequests   int64         `json:"search_requests"`
	BulkRequests     int64         `json:"bulk_requests"`
	ErrorCount       int64         `json:"error_count"`
	AverageIndexTime time.Duration `json:"average_index_time"`
	AverageSearchTime time.Duration `json:"average_search_time"`
	mu               sync.RWMutex
}

// ClusterHealth represents cluster health information
type ClusterHealth struct {
	Status                 string    `json:"status"`
	NumberOfNodes          int       `json:"number_of_nodes"`
	NumberOfDataNodes      int       `json:"number_of_data_nodes"`
	ActivePrimaryShards    int       `json:"active_primary_shards"`
	ActiveShards           int       `json:"active_shards"`
	RelocatingShards       int       `json:"relocating_shards"`
	InitializingShards     int       `json:"initializing_shards"`
	UnassignedShards       int       `json:"unassigned_shards"`
	DelayedUnassignedShards int      `json:"delayed_unassigned_shards"`
	PendingTasks           int       `json:"number_of_pending_tasks"`
	InFlightFetch          int       `json:"number_of_in_flight_fetch"`
	TaskMaxWaitingTime     string    `json:"task_max_waiting_in_queue_millis"`
	ClusterName            string    `json:"cluster_name"`
	Timestamp              time.Time `json:"timestamp"`
}

// IndexTemplate defines an index template
type IndexTemplate struct {
	Name     string                 `json:"name"`
	Pattern  string                 `json:"index_patterns"`
	Settings map[string]interface{} `json:"settings"`
	Mappings map[string]interface{} `json:"mappings"`
	Order    int                    `json:"order"`
}

// LifecyclePolicy defines an ILM policy
type LifecyclePolicy struct {
	Name   string                 `json:"name"`
	Policy map[string]interface{} `json:"policy"`
}

// BulkOperation represents a bulk operation
type BulkOperation struct {
	Index     string                 `json:"_index"`
	ID        string                 `json:"_id,omitempty"`
	Type      string                 `json:"_type,omitempty"`
	Operation string                 `json:"operation"`
	Document  map[string]interface{} `json:"document"`
	Timestamp time.Time              `json:"@timestamp"`
}

// SecurityEvent represents a security event document
type SecurityEvent struct {
	Timestamp       time.Time              `json:"@timestamp"`
	EventID         string                 `json:"event_id"`
	TenantID        string                 `json:"tenant_id"`
	EventType       string                 `json:"event_type"`
	Severity        string                 `json:"severity"`
	Source          EventSource            `json:"source"`
	Destination     EventDestination       `json:"destination,omitempty"`
	User            EventUser              `json:"user,omitempty"`
	Process         EventProcess           `json:"process,omitempty"`
	Network         EventNetwork           `json:"network,omitempty"`
	File            EventFile              `json:"file,omitempty"`
	Registry        EventRegistry          `json:"registry,omitempty"`
	ThreatIntel     ThreatIntelligence     `json:"threat_intel,omitempty"`
	Enrichment      EventEnrichment        `json:"enrichment,omitempty"`
	Detection       DetectionResult        `json:"detection,omitempty"`
	RiskScore       float64                `json:"risk_score,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	Labels          map[string]string      `json:"labels,omitempty"`
	RawEvent        string                 `json:"raw_event,omitempty"`
}

// Supporting structures for security events
type EventSource struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Domain   string `json:"domain,omitempty"`
	AssetID  string `json:"asset_id,omitempty"`
}

type EventDestination struct {
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

type EventUser struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

type EventProcess struct {
	PID         int      `json:"pid,omitempty"`
	Name        string   `json:"name,omitempty"`
	Executable  string   `json:"executable,omitempty"`
	CommandLine string   `json:"command_line,omitempty"`
	ParentPID   int      `json:"parent_pid,omitempty"`
	ParentName  string   `json:"parent_name,omitempty"`
	Hash        FileHash `json:"hash,omitempty"`
}

type EventNetwork struct {
	Protocol      string `json:"protocol,omitempty"`
	Transport     string `json:"transport,omitempty"`
	Direction     string `json:"direction,omitempty"`
	Bytes         int64  `json:"bytes,omitempty"`
	Packets       int64  `json:"packets,omitempty"`
	Community     string `json:"community_id,omitempty"`
}

type EventFile struct {
	Path      string   `json:"path,omitempty"`
	Name      string   `json:"name,omitempty"`
	Extension string   `json:"extension,omitempty"`
	Size      int64    `json:"size,omitempty"`
	Hash      FileHash `json:"hash,omitempty"`
	MimeType  string   `json:"mime_type,omitempty"`
}

type EventRegistry struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
	Type  string `json:"type,omitempty"`
}

type FileHash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
}

type ThreatIntelligence struct {
	Reputation   string   `json:"reputation,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	Confidence   float64  `json:"confidence,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	IOCs         []string `json:"iocs,omitempty"`
}

type EventEnrichment struct {
	GeoLocation  GeoLocation `json:"geo_location,omitempty"`
	AssetInfo    AssetInfo   `json:"asset_info,omitempty"`
	UserContext  UserContext `json:"user_context,omitempty"`
}

type GeoLocation struct {
	Country     string  `json:"country,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
}

type AssetInfo struct {
	AssetType    string   `json:"asset_type,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	Department   string   `json:"department,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	Criticality  string   `json:"criticality,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

type UserContext struct {
	Department     string    `json:"department,omitempty"`
	Title          string    `json:"title,omitempty"`
	Manager        string    `json:"manager,omitempty"`
	LastLogin      time.Time `json:"last_login,omitempty"`
	RiskProfile    string    `json:"risk_profile,omitempty"`
}

type DetectionResult struct {
	RuleName    string                 `json:"rule_name,omitempty"`
	RuleID      string                 `json:"rule_id,omitempty"`
	Technique   string                 `json:"technique,omitempty"`
	Tactic      string                 `json:"tactic,omitempty"`
	Confidence  float64                `json:"confidence,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// NewElasticsearchClient creates a new Elasticsearch client
func NewElasticsearchClient(logger *zap.Logger, config *ElasticsearchConfig) (*ElasticsearchClient, error) {
	if config == nil {
		return nil, fmt.Errorf("Elasticsearch configuration is required")
	}
	
	// Set production defaults
	if err := setElasticsearchDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	// Create Elasticsearch client configuration
	cfg := elasticsearch.Config{
		Addresses:              config.Addresses,
		Username:               config.Username,
		Password:               config.Password,
		APIKey:                 config.APIKey,
		CloudID:                config.CloudID,
		CertificateFingerprint: config.CertificateFingerprint,
		MaxRetries:            config.MaxRetries,
		RetryOnStatus:         []int{502, 503, 504, 429},
		CompressRequestBody:   true,
	}
	
	// Configure transport
	if config.InsecureSkipVerify {
		cfg.Transport = &http.Transport{
			MaxIdleConns:        config.MaxIdleConns,
			MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
			IdleConnTimeout:     90 * time.Second,
		}
	}
	
	// Create client
	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	esClient := &ElasticsearchClient{
		client:        client,
		logger:        logger.With(zap.String("component", "elasticsearch-client")),
		config:        config,
		stats:         &ClientStats{},
		ctx:           ctx,
		cancel:        cancel,
		isHealthy:     false,
	}
	
	// Initialize managers
	esClient.indexManager = NewIndexManager(client, logger, config)
	esClient.templateManager = NewTemplateManager(client, logger)
	esClient.lifecycleManager = NewLifecycleManager(client, logger)
	esClient.bulkProcessor = NewBulkProcessor(client, logger, config, ctx)
	
	// Test connection and get cluster health
	if err := esClient.checkClusterHealth(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to Elasticsearch cluster: %w", err)
	}
	
	// Setup index templates and policies
	if err := esClient.setupCluster(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to setup cluster: %w", err)
	}
	
	// Start background maintenance
	esClient.maintenanceTicker = time.NewTicker(config.MaintenanceInterval)
	go esClient.runMaintenance()
	
	logger.Info("Elasticsearch client initialized",
		zap.Strings("addresses", config.Addresses),
		zap.Int("bulk_size", config.BulkSize),
		zap.Bool("ilm_enabled", config.EnableILM),
		zap.Bool("security_enabled", config.EnableSecurity),
	)
	
	return esClient, nil
}

// setElasticsearchDefaults sets production defaults
func setElasticsearchDefaults(config *ElasticsearchConfig) error {
	if len(config.Addresses) == 0 {
		config.Addresses = []string{"http://localhost:9200"}
	}
	
	// Connection defaults
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = 1 * time.Second
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 100
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 10
	}
	
	// Bulk processing defaults
	if config.BulkSize == 0 {
		config.BulkSize = 1000
	}
	if config.BulkFlushInterval == 0 {
		config.BulkFlushInterval = 5 * time.Second
	}
	if config.BulkWorkers == 0 {
		config.BulkWorkers = 4
	}
	if config.BulkTimeout == 0 {
		config.BulkTimeout = 30 * time.Second
	}
	
	// Index defaults
	if config.DefaultReplicas == 0 {
		config.DefaultReplicas = 1
	}
	if config.DefaultShards == 0 {
		config.DefaultShards = 2
	}
	if config.RefreshInterval == "" {
		config.RefreshInterval = "5s"
	}
	if config.IndexCodec == "" {
		config.IndexCodec = "best_compression"
	}
	
	// Security defaults
	if config.SecurityIndexPattern == "" {
		config.SecurityIndexPattern = "isectech-security-events-*"
	}
	if config.TenantFieldName == "" {
		config.TenantFieldName = "tenant_id"
	}
	
	// Lifecycle defaults
	if config.HotPhaseSize == "" {
		config.HotPhaseSize = "10GB"
	}
	if config.WarmPhaseAge == "" {
		config.WarmPhaseAge = "7d"
	}
	if config.ColdPhaseAge == "" {
		config.ColdPhaseAge = "30d"
	}
	if config.DeletePhaseAge == "" {
		config.DeletePhaseAge = "365d"
	}
	
	// Maintenance defaults
	if config.MaintenanceInterval == 0 {
		config.MaintenanceInterval = 1 * time.Hour
	}
	if config.ForcemergeMaxSegments == 0 {
		config.ForcemergeMaxSegments = 1
	}
	
	return nil
}

// setupCluster sets up index templates and ILM policies
func (es *ElasticsearchClient) setupCluster() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	// Create security events index template
	securityTemplate := &IndexTemplate{
		Name:    "isectech-security-events",
		Pattern: "isectech-security-events-*",
		Order:   100,
		Settings: map[string]interface{}{
			"number_of_shards":   es.config.DefaultShards,
			"number_of_replicas": es.config.DefaultReplicas,
			"refresh_interval":   es.config.RefreshInterval,
			"codec":              es.config.IndexCodec,
			"index": map[string]interface{}{
				"lifecycle": map[string]interface{}{
					"name": "isectech-security-events-policy",
				},
				"sort": map[string]interface{}{
					"field": []string{"@timestamp", "risk_score"},
					"order": []string{"desc", "desc"},
				},
			},
		},
	}
	
	// Set security events mapping
	securityTemplate.Mappings = es.getSecurityEventsMappings()
	
	if err := es.templateManager.CreateTemplate(ctx, securityTemplate); err != nil {
		return fmt.Errorf("failed to create security events template: %w", err)
	}
	
	// Create ILM policy if enabled
	if es.config.EnableILM {
		if err := es.setupILMPolicies(ctx); err != nil {
			return fmt.Errorf("failed to setup ILM policies: %w", err)
		}
	}
	
	// Create initial index
	indexName := fmt.Sprintf("isectech-security-events-%s", time.Now().Format("2006.01.02"))
	if err := es.indexManager.CreateIndex(ctx, indexName, nil); err != nil {
		es.logger.Warn("Failed to create initial index", zap.String("index", indexName), zap.Error(err))
	}
	
	return nil
}

// getSecurityEventsMappings returns mappings for security events
func (es *ElasticsearchClient) getSecurityEventsMappings() map[string]interface{} {
	return map[string]interface{}{
		"properties": map[string]interface{}{
			"@timestamp": map[string]interface{}{
				"type": "date",
			},
			"event_id": map[string]interface{}{
				"type": "keyword",
			},
			"tenant_id": map[string]interface{}{
				"type": "keyword",
			},
			"event_type": map[string]interface{}{
				"type": "keyword",
			},
			"severity": map[string]interface{}{
				"type": "keyword",
			},
			"risk_score": map[string]interface{}{
				"type": "double",
			},
			"source": map[string]interface{}{
				"properties": map[string]interface{}{
					"ip": map[string]interface{}{
						"type": "ip",
					},
					"port": map[string]interface{}{
						"type": "integer",
					},
					"hostname": map[string]interface{}{
						"type": "keyword",
					},
					"domain": map[string]interface{}{
						"type": "keyword",
					},
					"asset_id": map[string]interface{}{
						"type": "keyword",
					},
				},
			},
			"destination": map[string]interface{}{
				"properties": map[string]interface{}{
					"ip": map[string]interface{}{
						"type": "ip",
					},
					"port": map[string]interface{}{
						"type": "integer",
					},
					"hostname": map[string]interface{}{
						"type": "keyword",
					},
					"domain": map[string]interface{}{
						"type": "keyword",
					},
				},
			},
			"user": map[string]interface{}{
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type": "keyword",
					},
					"name": map[string]interface{}{
						"type": "keyword",
					},
					"domain": map[string]interface{}{
						"type": "keyword",
					},
					"groups": map[string]interface{}{
						"type": "keyword",
					},
					"roles": map[string]interface{}{
						"type": "keyword",
					},
				},
			},
			"process": map[string]interface{}{
				"properties": map[string]interface{}{
					"pid": map[string]interface{}{
						"type": "integer",
					},
					"name": map[string]interface{}{
						"type": "keyword",
					},
					"executable": map[string]interface{}{
						"type": "keyword",
					},
					"command_line": map[string]interface{}{
						"type": "text",
						"fields": map[string]interface{}{
							"keyword": map[string]interface{}{
								"type":         "keyword",
								"ignore_above": 1024,
							},
						},
					},
					"parent_pid": map[string]interface{}{
						"type": "integer",
					},
					"parent_name": map[string]interface{}{
						"type": "keyword",
					},
					"hash": map[string]interface{}{
						"properties": map[string]interface{}{
							"md5": map[string]interface{}{
								"type": "keyword",
							},
							"sha1": map[string]interface{}{
								"type": "keyword",
							},
							"sha256": map[string]interface{}{
								"type": "keyword",
							},
							"sha512": map[string]interface{}{
								"type": "keyword",
							},
						},
					},
				},
			},
			"network": map[string]interface{}{
				"properties": map[string]interface{}{
					"protocol": map[string]interface{}{
						"type": "keyword",
					},
					"transport": map[string]interface{}{
						"type": "keyword",
					},
					"direction": map[string]interface{}{
						"type": "keyword",
					},
					"bytes": map[string]interface{}{
						"type": "long",
					},
					"packets": map[string]interface{}{
						"type": "long",
					},
					"community_id": map[string]interface{}{
						"type": "keyword",
					},
				},
			},
			"file": map[string]interface{}{
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type": "keyword",
					},
					"name": map[string]interface{}{
						"type": "keyword",
					},
					"extension": map[string]interface{}{
						"type": "keyword",
					},
					"size": map[string]interface{}{
						"type": "long",
					},
					"hash": map[string]interface{}{
						"properties": map[string]interface{}{
							"md5": map[string]interface{}{
								"type": "keyword",
							},
							"sha1": map[string]interface{}{
								"type": "keyword",
							},
							"sha256": map[string]interface{}{
								"type": "keyword",
							},
							"sha512": map[string]interface{}{
								"type": "keyword",
							},
						},
					},
					"mime_type": map[string]interface{}{
						"type": "keyword",
					},
				},
			},
			"threat_intel": map[string]interface{}{
				"properties": map[string]interface{}{
					"reputation": map[string]interface{}{
						"type": "keyword",
					},
					"categories": map[string]interface{}{
						"type": "keyword",
					},
					"confidence": map[string]interface{}{
						"type": "double",
					},
					"sources": map[string]interface{}{
						"type": "keyword",
					},
					"iocs": map[string]interface{}{
						"type": "keyword",
					},
				},
			},
			"enrichment": map[string]interface{}{
				"properties": map[string]interface{}{
					"geo_location": map[string]interface{}{
						"properties": map[string]interface{}{
							"country": map[string]interface{}{
								"type": "keyword",
							},
							"region": map[string]interface{}{
								"type": "keyword",
							},
							"city": map[string]interface{}{
								"type": "keyword",
							},
							"latitude": map[string]interface{}{
								"type": "double",
							},
							"longitude": map[string]interface{}{
								"type": "double",
							},
							"asn": map[string]interface{}{
								"type": "keyword",
							},
							"organization": map[string]interface{}{
								"type": "keyword",
							},
						},
					},
					"asset_info": map[string]interface{}{
						"properties": map[string]interface{}{
							"asset_type": map[string]interface{}{
								"type": "keyword",
							},
							"owner": map[string]interface{}{
								"type": "keyword",
							},
							"department": map[string]interface{}{
								"type": "keyword",
							},
							"environment": map[string]interface{}{
								"type": "keyword",
							},
							"criticality": map[string]interface{}{
								"type": "keyword",
							},
							"tags": map[string]interface{}{
								"type": "keyword",
							},
						},
					},
					"user_context": map[string]interface{}{
						"properties": map[string]interface{}{
							"department": map[string]interface{}{
								"type": "keyword",
							},
							"title": map[string]interface{}{
								"type": "keyword",
							},
							"manager": map[string]interface{}{
								"type": "keyword",
							},
							"last_login": map[string]interface{}{
								"type": "date",
							},
							"risk_profile": map[string]interface{}{
								"type": "keyword",
							},
						},
					},
				},
			},
			"detection": map[string]interface{}{
				"properties": map[string]interface{}{
					"rule_name": map[string]interface{}{
						"type": "keyword",
					},
					"rule_id": map[string]interface{}{
						"type": "keyword",
					},
					"technique": map[string]interface{}{
						"type": "keyword",
					},
					"tactic": map[string]interface{}{
						"type": "keyword",
					},
					"confidence": map[string]interface{}{
						"type": "double",
					},
					"severity": map[string]interface{}{
						"type": "keyword",
					},
					"context": map[string]interface{}{
						"type": "object",
						"enabled": false,
					},
				},
			},
			"tags": map[string]interface{}{
				"type": "keyword",
			},
			"labels": map[string]interface{}{
				"type": "object",
			},
			"raw_event": map[string]interface{}{
				"type": "text",
				"index": false,
			},
		},
	}
}

// setupILMPolicies creates ILM policies
func (es *ElasticsearchClient) setupILMPolicies(ctx context.Context) error {
	policy := &LifecyclePolicy{
		Name: "isectech-security-events-policy",
		Policy: map[string]interface{}{
			"phases": map[string]interface{}{
				"hot": map[string]interface{}{
					"actions": map[string]interface{}{
						"rollover": map[string]interface{}{
							"max_size": es.config.HotPhaseSize,
							"max_age":  "1d",
						},
						"set_priority": map[string]interface{}{
							"priority": 100,
						},
					},
				},
				"warm": map[string]interface{}{
					"min_age": es.config.WarmPhaseAge,
					"actions": map[string]interface{}{
						"set_priority": map[string]interface{}{
							"priority": 50,
						},
						"allocate": map[string]interface{}{
							"number_of_replicas": 0,
						},
						"forcemerge": map[string]interface{}{
							"max_num_segments": 1,
						},
					},
				},
				"cold": map[string]interface{}{
					"min_age": es.config.ColdPhaseAge,
					"actions": map[string]interface{}{
						"set_priority": map[string]interface{}{
							"priority": 0,
						},
						"allocate": map[string]interface{}{
							"number_of_replicas": 0,
						},
					},
				},
				"delete": map[string]interface{}{
					"min_age": es.config.DeletePhaseAge,
					"actions": map[string]interface{}{
						"delete": map[string]interface{}{},
					},
				},
			},
		},
	}
	
	return es.lifecycleManager.CreatePolicy(ctx, policy)
}

// IndexSecurityEvent indexes a security event
func (es *ElasticsearchClient) IndexSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	// Generate index name
	indexName := fmt.Sprintf("isectech-security-events-%s", event.Timestamp.Format("2006.01.02"))
	
	// Create bulk operation
	operation := BulkOperation{
		Index:     indexName,
		ID:        event.EventID,
		Operation: "index",
		Document:  es.convertToDocument(event),
		Timestamp: event.Timestamp,
	}
	
	return es.bulkProcessor.Add(operation)
}

// convertToDocument converts SecurityEvent to document map
func (es *ElasticsearchClient) convertToDocument(event *SecurityEvent) map[string]interface{} {
	doc := make(map[string]interface{})
	
	// Convert struct to map using JSON marshaling for simplicity
	data, _ := json.Marshal(event)
	json.Unmarshal(data, &doc)
	
	return doc
}

// Search performs a search query
func (es *ElasticsearchClient) Search(ctx context.Context, query map[string]interface{}, indices ...string) (*SearchResponse, error) {
	start := time.Now()
	
	if len(indices) == 0 {
		indices = []string{es.config.SecurityIndexPattern}
	}
	
	// Build search request
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, fmt.Errorf("failed to encode search query: %w", err)
	}
	
	// Execute search
	req := esapi.SearchRequest{
		Index: indices,
		Body:  &buf,
	}
	
	res, err := req.Do(ctx, es.client)
	if err != nil {
		es.stats.mu.Lock()
		es.stats.ErrorCount++
		es.stats.mu.Unlock()
		return nil, fmt.Errorf("search request failed: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return nil, fmt.Errorf("search failed with status: %s", res.Status())
	}
	
	// Parse response
	var response SearchResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}
	
	// Update statistics
	duration := time.Since(start)
	es.stats.mu.Lock()
	es.stats.SearchRequests++
	es.stats.AverageSearchTime = (es.stats.AverageSearchTime + duration) / 2
	es.stats.mu.Unlock()
	
	return &response, nil
}

// SearchResponse represents Elasticsearch search response
type SearchResponse struct {
	Took     int                    `json:"took"`
	TimedOut bool                   `json:"timed_out"`
	Hits     SearchHits             `json:"hits"`
	Aggs     map[string]interface{} `json:"aggregations,omitempty"`
}

type SearchHits struct {
	Total    HitsTotal       `json:"total"`
	MaxScore *float64        `json:"max_score"`
	Hits     []SearchHit     `json:"hits"`
}

type HitsTotal struct {
	Value    int    `json:"value"`
	Relation string `json:"relation"`
}

type SearchHit struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Score  *float64               `json:"_score"`
	Source map[string]interface{} `json:"_source"`
}

// checkClusterHealth checks cluster health
func (es *ElasticsearchClient) checkClusterHealth() error {
	req := esapi.ClusterHealthRequest{
		WaitForStatus: "yellow",
		Timeout:       10 * time.Second,
	}
	
	res, err := req.Do(context.Background(), es.client)
	if err != nil {
		return fmt.Errorf("cluster health request failed: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		return fmt.Errorf("cluster health check failed: %s", res.Status())
	}
	
	var health ClusterHealth
	if err := json.NewDecoder(res.Body).Decode(&health); err != nil {
		return fmt.Errorf("failed to decode cluster health: %w", err)
	}
	
	health.Timestamp = time.Now()
	
	es.mu.Lock()
	es.clusterHealth = &health
	es.isHealthy = health.Status == "green" || health.Status == "yellow"
	es.lastHealthCheck = time.Now()
	es.mu.Unlock()
	
	es.logger.Info("Cluster health checked",
		zap.String("status", health.Status),
		zap.Int("nodes", health.NumberOfNodes),
		zap.Int("data_nodes", health.NumberOfDataNodes),
	)
	
	return nil
}

// runMaintenance runs periodic maintenance tasks
func (es *ElasticsearchClient) runMaintenance() {
	for {
		select {
		case <-es.ctx.Done():
			return
		case <-es.maintenanceTicker.C:
			es.performMaintenance()
		}
	}
}

// performMaintenance performs maintenance tasks
func (es *ElasticsearchClient) performMaintenance() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	
	// Health check
	if err := es.checkClusterHealth(); err != nil {
		es.logger.Error("Cluster health check failed during maintenance", zap.Error(err))
		return
	}
	
	// Force merge if enabled
	if es.config.EnableForcemerge {
		if err := es.performForcemerge(ctx); err != nil {
			es.logger.Warn("Force merge failed", zap.Error(err))
		}
	}
	
	es.logger.Debug("Maintenance completed")
}

// performForcemerge performs force merge on old indices
func (es *ElasticsearchClient) performForcemerge(ctx context.Context) error {
	// Get indices older than 1 day
	cutoffTime := time.Now().AddDate(0, 0, -1)
	pattern := fmt.Sprintf("isectech-security-events-%s", cutoffTime.Format("2006.01.02"))
	
	req := esapi.IndicesForcemergeRequest{
		Index:             []string{pattern},
		MaxNumSegments:    &es.config.ForcemergeMaxSegments,
		WaitForCompletion: &[]bool{false}[0],
	}
	
	res, err := req.Do(ctx, es.client)
	if err != nil {
		return fmt.Errorf("forcemerge request failed: %w", err)
	}
	defer res.Body.Close()
	
	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("forcemerge failed: %s - %s", res.Status(), string(body))
	}
	
	return nil
}

// IsHealthy returns the health status
func (es *ElasticsearchClient) IsHealthy() bool {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return es.isHealthy
}

// GetClusterHealth returns cluster health information
func (es *ElasticsearchClient) GetClusterHealth() *ClusterHealth {
	es.mu.RLock()
	defer es.mu.RUnlock()
	
	if es.clusterHealth == nil {
		return nil
	}
	
	health := *es.clusterHealth
	return &health
}

// GetStats returns client statistics
func (es *ElasticsearchClient) GetStats() *ClientStats {
	es.stats.mu.RLock()
	defer es.stats.mu.RUnlock()
	
	stats := *es.stats
	return &stats
}

// Close closes the Elasticsearch client
func (es *ElasticsearchClient) Close() error {
	if es.cancel != nil {
		es.cancel()
	}
	
	if es.maintenanceTicker != nil {
		es.maintenanceTicker.Stop()
	}
	
	if es.bulkProcessor != nil {
		es.bulkProcessor.Close()
	}
	
	es.logger.Info("Elasticsearch client closed")
	return nil
}