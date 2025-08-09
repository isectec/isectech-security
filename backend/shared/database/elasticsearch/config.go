package elasticsearch

import (
	"fmt"
	"time"

	"github.com/isectech/platform/shared/common"
)

// Config represents Elasticsearch configuration for iSECTECH cybersecurity platform
type Config struct {
	// Connection settings
	Addresses         []string      `yaml:"addresses" json:"addresses"`
	Username          string        `yaml:"username" json:"username"`
	Password          string        `yaml:"password" json:"password"`
	APIKey            string        `yaml:"api_key" json:"api_key"`
	CloudID           string        `yaml:"cloud_id" json:"cloud_id"`
	
	// Connection timeouts
	DialTimeout       time.Duration `yaml:"dial_timeout" json:"dial_timeout"`
	RequestTimeout    time.Duration `yaml:"request_timeout" json:"request_timeout"`
	KeepAlive         time.Duration `yaml:"keep_alive" json:"keep_alive"`
	MaxIdleConns      int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	MaxIdleConnsPerHost int         `yaml:"max_idle_conns_per_host" json:"max_idle_conns_per_host"`
	
	// Cluster configuration
	Cluster           ClusterConfig `yaml:"cluster" json:"cluster"`
	
	// Index configuration
	Indices           IndexConfig   `yaml:"indices" json:"indices"`
	
	// Index Lifecycle Management
	ILM               ILMConfig     `yaml:"ilm" json:"ilm"`
	
	// Cross-cluster replication
	CCR               CCRConfig     `yaml:"ccr" json:"ccr"`
	
	// Security settings
	Security          SecurityConfig `yaml:"security" json:"security"`
	
	// Monitoring and observability
	EnableMetrics     bool          `yaml:"enable_metrics" json:"enable_metrics"`
	EnableTracing     bool          `yaml:"enable_tracing" json:"enable_tracing"`
	SlowQueryThreshold time.Duration `yaml:"slow_query_threshold" json:"slow_query_threshold"`
	
	// Circuit breaker settings
	CircuitBreaker    CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
	
	// Retry settings
	RetryConfig       RetryConfig   `yaml:"retry_config" json:"retry_config"`
}

// ClusterConfig defines Elasticsearch cluster configuration
type ClusterConfig struct {
	Name              string   `yaml:"name" json:"name"`
	DiscoverNodesOnStart bool  `yaml:"discover_nodes_on_start" json:"discover_nodes_on_start"`
	DiscoverNodesInterval time.Duration `yaml:"discover_nodes_interval" json:"discover_nodes_interval"`
	EnableSniffer     bool     `yaml:"enable_sniffer" json:"enable_sniffer"`
	EnableHealthcheck bool     `yaml:"enable_healthcheck" json:"enable_healthcheck"`
	HealthcheckInterval time.Duration `yaml:"healthcheck_interval" json:"healthcheck_interval"`
}

// IndexConfig defines index configuration and templates
type IndexConfig struct {
	DefaultShards     int                          `yaml:"default_shards" json:"default_shards"`
	DefaultReplicas   int                          `yaml:"default_replicas" json:"default_replicas"`
	RefreshInterval   string                       `yaml:"refresh_interval" json:"refresh_interval"`
	MaxResultWindow   int                          `yaml:"max_result_window" json:"max_result_window"`
	Templates         map[string]IndexTemplate     `yaml:"templates" json:"templates"`
	ComponentTemplates map[string]ComponentTemplate `yaml:"component_templates" json:"component_templates"`
}

// IndexTemplate defines an index template
type IndexTemplate struct {
	IndexPatterns []string               `yaml:"index_patterns" json:"index_patterns"`
	Priority      int                    `yaml:"priority" json:"priority"`
	Version       int                    `yaml:"version" json:"version"`
	Template      TemplateConfig         `yaml:"template" json:"template"`
	ComposedOf    []string               `yaml:"composed_of" json:"composed_of"`
	Metadata      map[string]interface{} `yaml:"metadata" json:"metadata"`
}

// ComponentTemplate defines a component template
type ComponentTemplate struct {
	Template TemplateConfig         `yaml:"template" json:"template"`
	Version  int                    `yaml:"version" json:"version"`
	Metadata map[string]interface{} `yaml:"metadata" json:"metadata"`
}

// TemplateConfig defines template configuration
type TemplateConfig struct {
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	Mappings map[string]interface{} `yaml:"mappings" json:"mappings"`
	Aliases  map[string]interface{} `yaml:"aliases" json:"aliases"`
}

// ILMConfig defines Index Lifecycle Management configuration
type ILMConfig struct {
	Enabled        bool                    `yaml:"enabled" json:"enabled"`
	PollInterval   time.Duration           `yaml:"poll_interval" json:"poll_interval"`
	Policies       map[string]ILMPolicy    `yaml:"policies" json:"policies"`
}

// ILMPolicy defines an ILM policy
type ILMPolicy struct {
	Policy map[string]interface{} `yaml:"policy" json:"policy"`
}

// CCRConfig defines Cross-Cluster Replication configuration
type CCRConfig struct {
	Enabled         bool              `yaml:"enabled" json:"enabled"`
	RemoteClusters  map[string]RemoteCluster `yaml:"remote_clusters" json:"remote_clusters"`
	FollowerIndices map[string]FollowerIndex `yaml:"follower_indices" json:"follower_indices"`
}

// RemoteCluster defines a remote cluster for CCR
type RemoteCluster struct {
	Seeds            []string `yaml:"seeds" json:"seeds"`
	Mode             string   `yaml:"mode" json:"mode"` // sniff or proxy
	ProxyAddress     string   `yaml:"proxy_address" json:"proxy_address"`
	ProxySocketConnections int `yaml:"proxy_socket_connections" json:"proxy_socket_connections"`
	ServerName       string   `yaml:"server_name" json:"server_name"`
}

// FollowerIndex defines a follower index for CCR
type FollowerIndex struct {
	RemoteCluster   string `yaml:"remote_cluster" json:"remote_cluster"`
	LeaderIndex     string `yaml:"leader_index" json:"leader_index"`
	MaxReadRequestOpCount int `yaml:"max_read_request_operation_count" json:"max_read_request_operation_count"`
	MaxOutstandingReadRequests int `yaml:"max_outstanding_read_requests" json:"max_outstanding_read_requests"`
	MaxReadRequestSize string `yaml:"max_read_request_size" json:"max_read_request_size"`
	MaxWriteRequestOpCount int `yaml:"max_write_request_operation_count" json:"max_write_request_operation_count"`
	MaxOutstandingWriteRequests int `yaml:"max_outstanding_write_requests" json:"max_outstanding_write_requests"`
	MaxWriteRequestSize string `yaml:"max_write_request_size" json:"max_write_request_size"`
	MaxWriteBufferCount int `yaml:"max_write_buffer_count" json:"max_write_buffer_count"`
	MaxWriteBufferSize string `yaml:"max_write_buffer_size" json:"max_write_buffer_size"`
	MaxRetryDelay   time.Duration `yaml:"max_retry_delay" json:"max_retry_delay"`
	ReadPollTimeout time.Duration `yaml:"read_poll_timeout" json:"read_poll_timeout"`
}

// SecurityConfig defines security settings
type SecurityConfig struct {
	EnableTLS        bool          `yaml:"enable_tls" json:"enable_tls"`
	TLSConfig        TLSConfig     `yaml:"tls_config" json:"tls_config"`
	EnableAuthentication bool      `yaml:"enable_authentication" json:"enable_authentication"`
	EnableAuthorization bool       `yaml:"enable_authorization" json:"enable_authorization"`
	FieldLevelSecurity bool        `yaml:"field_level_security" json:"field_level_security"`
	DocumentLevelSecurity bool     `yaml:"document_level_security" json:"document_level_security"`
	AuditLogging     AuditConfig   `yaml:"audit_logging" json:"audit_logging"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	CertFile           string `yaml:"cert_file" json:"cert_file"`
	KeyFile            string `yaml:"key_file" json:"key_file"`
	CAFile             string `yaml:"ca_file" json:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	ServerName         string `yaml:"server_name" json:"server_name"`
}

// AuditConfig defines audit logging configuration
type AuditConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	LogLevel         string   `yaml:"log_level" json:"log_level"`
	IncludeRequests  bool     `yaml:"include_requests" json:"include_requests"`
	IncludeResponses bool     `yaml:"include_responses" json:"include_responses"`
	ExcludedUsers    []string `yaml:"excluded_users" json:"excluded_users"`
	ExcludedRoles    []string `yaml:"excluded_roles" json:"excluded_roles"`
}

// CircuitBreakerConfig defines circuit breaker settings
type CircuitBreakerConfig struct {
	MaxRequests      uint32        `yaml:"max_requests" json:"max_requests"`
	Interval         time.Duration `yaml:"interval" json:"interval"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	FailureThreshold uint32        `yaml:"failure_threshold" json:"failure_threshold"`
}

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxAttempts     int           `yaml:"max_attempts" json:"max_attempts"`
	InitialInterval time.Duration `yaml:"initial_interval" json:"initial_interval"`
	MaxInterval     time.Duration `yaml:"max_interval" json:"max_interval"`
	Multiplier      float64       `yaml:"multiplier" json:"multiplier"`
	RetryOnStatus   []int         `yaml:"retry_on_status" json:"retry_on_status"`
}

// DefaultConfig returns a production-ready Elasticsearch configuration for iSECTECH
func DefaultConfig() *Config {
	return &Config{
		Addresses:       []string{"https://localhost:9200"},
		DialTimeout:     30 * time.Second,
		RequestTimeout:  90 * time.Second,
		KeepAlive:       30 * time.Second,
		MaxIdleConns:    100,
		MaxIdleConnsPerHost: 10,
		
		Cluster: ClusterConfig{
			Name:                   "isectech-cluster",
			DiscoverNodesOnStart:   true,
			DiscoverNodesInterval:  5 * time.Minute,
			EnableSniffer:          true,
			EnableHealthcheck:      true,
			HealthcheckInterval:    30 * time.Second,
		},
		
		Indices: IndexConfig{
			DefaultShards:   1,
			DefaultReplicas: 1,
			RefreshInterval: "1s",
			MaxResultWindow: 10000,
			Templates: map[string]IndexTemplate{
				"security-events": {
					IndexPatterns: []string{"security-events-*"},
					Priority:      100,
					Version:       1,
					ComposedOf:    []string{"security-events-mappings", "security-events-settings"},
					Metadata: map[string]interface{}{
						"description": "Template for iSECTECH security events",
						"version":     "1.0.0",
					},
				},
				"threat-intelligence": {
					IndexPatterns: []string{"threat-intel-*"},
					Priority:      100,
					Version:       1,
					ComposedOf:    []string{"threat-intel-mappings", "threat-intel-settings"},
					Metadata: map[string]interface{}{
						"description": "Template for iSECTECH threat intelligence",
						"version":     "1.0.0",
					},
				},
				"audit-logs": {
					IndexPatterns: []string{"audit-logs-*"},
					Priority:      100,
					Version:       1,
					ComposedOf:    []string{"audit-logs-mappings", "audit-logs-settings"},
					Metadata: map[string]interface{}{
						"description": "Template for iSECTECH audit logs",
						"version":     "1.0.0",
					},
				},
				"vulnerability-scans": {
					IndexPatterns: []string{"vuln-scans-*"},
					Priority:      100,
					Version:       1,
					ComposedOf:    []string{"vuln-scans-mappings", "vuln-scans-settings"},
					Metadata: map[string]interface{}{
						"description": "Template for iSECTECH vulnerability scans",
						"version":     "1.0.0",
					},
				},
				"compliance-reports": {
					IndexPatterns: []string{"compliance-*"},
					Priority:      100,
					Version:       1,
					ComposedOf:    []string{"compliance-mappings", "compliance-settings"},
					Metadata: map[string]interface{}{
						"description": "Template for iSECTECH compliance reports",
						"version":     "1.0.0",
					},
				},
			},
			ComponentTemplates: getDefaultComponentTemplates(),
		},
		
		ILM: ILMConfig{
			Enabled:      true,
			PollInterval: 10 * time.Minute,
			Policies:     getDefaultILMPolicies(),
		},
		
		CCR: CCRConfig{
			Enabled:         false,
			RemoteClusters:  make(map[string]RemoteCluster),
			FollowerIndices: make(map[string]FollowerIndex),
		},
		
		Security: SecurityConfig{
			EnableTLS:             true,
			EnableAuthentication:  true,
			EnableAuthorization:   true,
			FieldLevelSecurity:    true,
			DocumentLevelSecurity: true,
			TLSConfig: TLSConfig{
				CertFile:           "/etc/elasticsearch/certs/elasticsearch.crt",
				KeyFile:            "/etc/elasticsearch/certs/elasticsearch.key",
				CAFile:             "/etc/elasticsearch/certs/ca.crt",
				InsecureSkipVerify: false,
			},
			AuditLogging: AuditConfig{
				Enabled:          true,
				LogLevel:         "info",
				IncludeRequests:  false,
				IncludeResponses: false,
				ExcludedUsers:    []string{"elastic", "kibana_system"},
				ExcludedRoles:    []string{"monitoring_user"},
			},
		},
		
		EnableMetrics:      true,
		EnableTracing:      true,
		SlowQueryThreshold: 5 * time.Second,
		
		CircuitBreaker: CircuitBreakerConfig{
			MaxRequests:      10,
			Interval:         30 * time.Second,
			Timeout:          60 * time.Second,
			FailureThreshold: 5,
		},
		
		RetryConfig: RetryConfig{
			MaxAttempts:     3,
			InitialInterval: 500 * time.Millisecond,
			MaxInterval:     10 * time.Second,
			Multiplier:      2.0,
			RetryOnStatus:   []int{429, 502, 503, 504},
		},
	}
}

// getDefaultComponentTemplates returns default component templates for iSECTECH
func getDefaultComponentTemplates() map[string]ComponentTemplate {
	return map[string]ComponentTemplate{
		"security-events-mappings": {
			Template: TemplateConfig{
				Mappings: map[string]interface{}{
					"properties": map[string]interface{}{
						"@timestamp": map[string]interface{}{
							"type": "date",
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
						"source": map[string]interface{}{
							"properties": map[string]interface{}{
								"ip": map[string]interface{}{
									"type": "ip",
								},
								"hostname": map[string]interface{}{
									"type": "keyword",
								},
								"asset_id": map[string]interface{}{
									"type": "keyword",
								},
							},
						},
						"target": map[string]interface{}{
							"properties": map[string]interface{}{
								"ip": map[string]interface{}{
									"type": "ip",
								},
								"hostname": map[string]interface{}{
									"type": "keyword",
								},
								"asset_id": map[string]interface{}{
									"type": "keyword",
								},
							},
						},
						"description": map[string]interface{}{
							"type": "text",
							"analyzer": "standard",
						},
						"raw_data": map[string]interface{}{
							"type": "object",
							"enabled": false,
						},
						"normalized_data": map[string]interface{}{
							"type": "object",
						},
						"indicators": map[string]interface{}{
							"type": "nested",
							"properties": map[string]interface{}{
								"type": map[string]interface{}{
									"type": "keyword",
								},
								"value": map[string]interface{}{
									"type": "keyword",
								},
								"confidence": map[string]interface{}{
									"type": "float",
								},
							},
						},
						"mitre_attack": map[string]interface{}{
							"type": "keyword",
						},
						"risk_score": map[string]interface{}{
							"type": "integer",
						},
						"security_classification": map[string]interface{}{
							"type": "keyword",
						},
						"tags": map[string]interface{}{
							"type": "keyword",
						},
						"location": map[string]interface{}{
							"type": "geo_point",
						},
					},
				},
			},
			Version: 1,
			Metadata: map[string]interface{}{
				"description": "Mappings for security events",
			},
		},
		"security-events-settings": {
			Template: TemplateConfig{
				Settings: map[string]interface{}{
					"number_of_shards":   1,
					"number_of_replicas": 1,
					"refresh_interval":   "5s",
					"index.lifecycle.name": "security-events-policy",
					"index.lifecycle.rollover_alias": "security-events",
					"analysis": map[string]interface{}{
						"analyzer": map[string]interface{}{
							"security_analyzer": map[string]interface{}{
								"type": "custom",
								"tokenizer": "standard",
								"filter": []string{"lowercase", "stop"},
							},
						},
					},
				},
				Aliases: map[string]interface{}{
					"security-events": map[string]interface{}{
						"is_write_index": true,
					},
				},
			},
			Version: 1,
			Metadata: map[string]interface{}{
				"description": "Settings for security events",
			},
		},
		"threat-intel-mappings": {
			Template: TemplateConfig{
				Mappings: map[string]interface{}{
					"properties": map[string]interface{}{
						"@timestamp": map[string]interface{}{
							"type": "date",
						},
						"tenant_id": map[string]interface{}{
							"type": "keyword",
						},
						"threat_id": map[string]interface{}{
							"type": "keyword",
						},
						"threat_type": map[string]interface{}{
							"type": "keyword",
						},
						"severity": map[string]interface{}{
							"type": "keyword",
						},
						"confidence": map[string]interface{}{
							"type": "float",
						},
						"indicators": map[string]interface{}{
							"type": "nested",
						},
						"mitre_attack": map[string]interface{}{
							"type": "keyword",
						},
						"source": map[string]interface{}{
							"type": "keyword",
						},
						"description": map[string]interface{}{
							"type": "text",
						},
						"tags": map[string]interface{}{
							"type": "keyword",
						},
						"security_classification": map[string]interface{}{
							"type": "keyword",
						},
					},
				},
			},
			Version: 1,
		},
		"threat-intel-settings": {
			Template: TemplateConfig{
				Settings: map[string]interface{}{
					"number_of_shards":   1,
					"number_of_replicas": 1,
					"refresh_interval":   "30s",
					"index.lifecycle.name": "threat-intel-policy",
				},
			},
			Version: 1,
		},
		"audit-logs-mappings": {
			Template: TemplateConfig{
				Mappings: map[string]interface{}{
					"properties": map[string]interface{}{
						"@timestamp": map[string]interface{}{
							"type": "date",
						},
						"tenant_id": map[string]interface{}{
							"type": "keyword",
						},
						"user_id": map[string]interface{}{
							"type": "keyword",
						},
						"action": map[string]interface{}{
							"type": "keyword",
						},
						"resource_type": map[string]interface{}{
							"type": "keyword",
						},
						"resource_id": map[string]interface{}{
							"type": "keyword",
						},
						"source_ip": map[string]interface{}{
							"type": "ip",
						},
						"user_agent": map[string]interface{}{
							"type": "text",
							"fields": map[string]interface{}{
								"keyword": map[string]interface{}{
									"type": "keyword",
								},
							},
						},
						"status": map[string]interface{}{
							"type": "keyword",
						},
						"security_classification": map[string]interface{}{
							"type": "keyword",
						},
					},
				},
			},
			Version: 1,
		},
		"audit-logs-settings": {
			Template: TemplateConfig{
				Settings: map[string]interface{}{
					"number_of_shards":   1,
					"number_of_replicas": 1,
					"refresh_interval":   "5s",
					"index.lifecycle.name": "audit-logs-policy",
				},
			},
			Version: 1,
		},
		"vuln-scans-mappings": {
			Template: TemplateConfig{
				Mappings: map[string]interface{}{
					"properties": map[string]interface{}{
						"@timestamp": map[string]interface{}{
							"type": "date",
						},
						"tenant_id": map[string]interface{}{
							"type": "keyword",
						},
						"asset_id": map[string]interface{}{
							"type": "keyword",
						},
						"vulnerability_id": map[string]interface{}{
							"type": "keyword",
						},
						"cve_id": map[string]interface{}{
							"type": "keyword",
						},
						"severity": map[string]interface{}{
							"type": "keyword",
						},
						"cvss_score": map[string]interface{}{
							"type": "float",
						},
						"description": map[string]interface{}{
							"type": "text",
						},
						"remediation": map[string]interface{}{
							"type": "text",
						},
						"status": map[string]interface{}{
							"type": "keyword",
						},
						"security_classification": map[string]interface{}{
							"type": "keyword",
						},
					},
				},
			},
			Version: 1,
		},
		"vuln-scans-settings": {
			Template: TemplateConfig{
				Settings: map[string]interface{}{
					"number_of_shards":   1,
					"number_of_replicas": 1,
					"refresh_interval":   "30s",
					"index.lifecycle.name": "vuln-scans-policy",
				},
			},
			Version: 1,
		},
		"compliance-mappings": {
			Template: TemplateConfig{
				Mappings: map[string]interface{}{
					"properties": map[string]interface{}{
						"@timestamp": map[string]interface{}{
							"type": "date",
						},
						"tenant_id": map[string]interface{}{
							"type": "keyword",
						},
						"framework": map[string]interface{}{
							"type": "keyword",
						},
						"requirement_id": map[string]interface{}{
							"type": "keyword",
						},
						"status": map[string]interface{}{
							"type": "keyword",
						},
						"score": map[string]interface{}{
							"type": "integer",
						},
						"findings": map[string]interface{}{
							"type": "text",
						},
						"security_classification": map[string]interface{}{
							"type": "keyword",
						},
					},
				},
			},
			Version: 1,
		},
		"compliance-settings": {
			Template: TemplateConfig{
				Settings: map[string]interface{}{
					"number_of_shards":   1,
					"number_of_replicas": 1,
					"refresh_interval":   "1h",
					"index.lifecycle.name": "compliance-policy",
				},
			},
			Version: 1,
		},
	}
}

// getDefaultILMPolicies returns default ILM policies for iSECTECH
func getDefaultILMPolicies() map[string]ILMPolicy {
	return map[string]ILMPolicy{
		"security-events-policy": {
			Policy: map[string]interface{}{
				"phases": map[string]interface{}{
					"hot": map[string]interface{}{
						"actions": map[string]interface{}{
							"rollover": map[string]interface{}{
								"max_size": "10GB",
								"max_age":  "1d",
							},
							"set_priority": map[string]interface{}{
								"priority": 100,
							},
						},
					},
					"warm": map[string]interface{}{
						"min_age": "2d",
						"actions": map[string]interface{}{
							"set_priority": map[string]interface{}{
								"priority": 50,
							},
							"allocate": map[string]interface{}{
								"number_of_replicas": 0,
							},
						},
					},
					"cold": map[string]interface{}{
						"min_age": "30d",
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
						"min_age": "365d",
					},
				},
			},
		},
		"threat-intel-policy": {
			Policy: map[string]interface{}{
				"phases": map[string]interface{}{
					"hot": map[string]interface{}{
						"actions": map[string]interface{}{
							"rollover": map[string]interface{}{
								"max_size": "5GB",
								"max_age":  "7d",
							},
						},
					},
					"warm": map[string]interface{}{
						"min_age": "7d",
						"actions": map[string]interface{}{
							"allocate": map[string]interface{}{
								"number_of_replicas": 0,
							},
						},
					},
					"cold": map[string]interface{}{
						"min_age": "90d",
					},
					"delete": map[string]interface{}{
						"min_age": "2y",
					},
				},
			},
		},
		"audit-logs-policy": {
			Policy: map[string]interface{}{
				"phases": map[string]interface{}{
					"hot": map[string]interface{}{
						"actions": map[string]interface{}{
							"rollover": map[string]interface{}{
								"max_size": "20GB",
								"max_age":  "1d",
							},
						},
					},
					"warm": map[string]interface{}{
						"min_age": "1d",
						"actions": map[string]interface{}{
							"allocate": map[string]interface{}{
								"number_of_replicas": 1,
							},
						},
					},
					"cold": map[string]interface{}{
						"min_age": "90d",
						"actions": map[string]interface{}{
							"allocate": map[string]interface{}{
								"number_of_replicas": 0,
							},
						},
					},
					"delete": map[string]interface{}{
						"min_age": "7y",
					},
				},
			},
		},
		"vuln-scans-policy": {
			Policy: map[string]interface{}{
				"phases": map[string]interface{}{
					"hot": map[string]interface{}{
						"actions": map[string]interface{}{
							"rollover": map[string]interface{}{
								"max_size": "2GB",
								"max_age":  "30d",
							},
						},
					},
					"warm": map[string]interface{}{
						"min_age": "30d",
					},
					"cold": map[string]interface{}{
						"min_age": "180d",
					},
					"delete": map[string]interface{}{
						"min_age": "3y",
					},
				},
			},
		},
		"compliance-policy": {
			Policy: map[string]interface{}{
				"phases": map[string]interface{}{
					"hot": map[string]interface{}{
						"actions": map[string]interface{}{
							"rollover": map[string]interface{}{
								"max_size": "1GB",
								"max_age":  "90d",
							},
						},
					},
					"warm": map[string]interface{}{
						"min_age": "90d",
					},
					"cold": map[string]interface{}{
						"min_age": "1y",
					},
					"delete": map[string]interface{}{
						"min_age": "7y",
					},
				},
			},
		},
	}
}

// LoadConfig loads Elasticsearch configuration from various sources
func LoadConfig() (*Config, error) {
	config := DefaultConfig()
	
	// Load from environment variables and config files
	if err := common.LoadConfigFromSources("elasticsearch", config); err != nil {
		return nil, fmt.Errorf("failed to load Elasticsearch config: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid Elasticsearch config: %w", err)
	}
	
	return config, nil
}

// Validate validates the Elasticsearch configuration
func (c *Config) Validate() error {
	if len(c.Addresses) == 0 && c.CloudID == "" {
		return fmt.Errorf("at least one address or cloud ID is required")
	}
	
	if c.DialTimeout <= 0 {
		return fmt.Errorf("dial timeout must be positive")
	}
	
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("request timeout must be positive")
	}
	
	if c.Indices.DefaultShards <= 0 {
		return fmt.Errorf("default shards must be positive")
	}
	
	if c.Indices.DefaultReplicas < 0 {
		return fmt.Errorf("default replicas must be non-negative")
	}
	
	// Validate ILM configuration
	if c.ILM.Enabled && c.ILM.PollInterval <= 0 {
		return fmt.Errorf("ILM poll interval must be positive when ILM is enabled")
	}
	
	// Validate CCR configuration
	if c.CCR.Enabled {
		if len(c.CCR.RemoteClusters) == 0 {
			return fmt.Errorf("remote clusters are required when CCR is enabled")
		}
		
		for name, cluster := range c.CCR.RemoteClusters {
			if len(cluster.Seeds) == 0 && cluster.ProxyAddress == "" {
				return fmt.Errorf("remote cluster %s must have seeds or proxy address", name)
			}
		}
	}
	
	return nil
}

// GetIndexName generates a time-based index name
func (c *Config) GetIndexName(template string, timestamp time.Time) string {
	return fmt.Sprintf("%s-%s", template, timestamp.Format("2006.01.02"))
}

// GetAliasName returns the alias name for a template
func (c *Config) GetAliasName(template string) string {
	return template
}