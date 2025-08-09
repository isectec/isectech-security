package entity

import (
	"time"

	"github.com/google/uuid"
)

// Service represents a backend service managed by the API Gateway
type Service struct {
	ID          uuid.UUID         `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	DisplayName string            `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string            `json:"version" yaml:"version"`
	
	// Service configuration
	Type        ServiceType       `json:"type" yaml:"type"`
	Protocol    string            `json:"protocol" yaml:"protocol"`
	BasePath    string            `json:"base_path,omitempty" yaml:"base_path,omitempty"`
	
	// Endpoints
	Endpoints   []ServiceEndpoint `json:"endpoints" yaml:"endpoints"`
	
	// Health check configuration
	HealthCheck ServiceHealthCheck `json:"health_check" yaml:"health_check"`
	
	// Load balancing
	LoadBalancer LoadBalancerConfig `json:"load_balancer" yaml:"load_balancer"`
	
	// Circuit breaker
	CircuitBreaker *CircuitBreakerConfig `json:"circuit_breaker,omitempty" yaml:"circuit_breaker,omitempty"`
	
	// Rate limiting
	RateLimit   *RateLimitConfig  `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	
	// Timeouts
	Timeout     time.Duration     `json:"timeout" yaml:"timeout"`
	
	// Security
	Security    ServiceSecurity   `json:"security" yaml:"security"`
	
	// Metadata
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Priority    int               `json:"priority" yaml:"priority"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
	
	// Discovery
	Discovery   ServiceDiscovery  `json:"discovery" yaml:"discovery"`
	
	// Metrics and monitoring
	Metrics     MetricsConfig     `json:"metrics" yaml:"metrics"`
	Logging     LoggingConfig     `json:"logging" yaml:"logging"`
	Tracing     TracingConfig     `json:"tracing" yaml:"tracing"`
	
	// Timestamps
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at"`
	LastSeen    time.Time         `json:"last_seen" yaml:"last_seen"`
}

// ServiceType represents the type of service
type ServiceType string

const (
	ServiceTypeHTTP       ServiceType = "http"
	ServiceTypeGRPC       ServiceType = "grpc"
	ServiceTypeGraphQL    ServiceType = "graphql"
	ServiceTypeWebSocket  ServiceType = "websocket"
	ServiceTypeFunction   ServiceType = "function"
	ServiceTypeDatabase   ServiceType = "database"
	ServiceTypeMessage    ServiceType = "message"
	ServiceTypeExternal   ServiceType = "external"
)

// ServiceEndpoint represents a service endpoint
type ServiceEndpoint struct {
	ID       uuid.UUID         `json:"id" yaml:"id"`
	Host     string            `json:"host" yaml:"host"`
	Port     int               `json:"port" yaml:"port"`
	Path     string            `json:"path,omitempty" yaml:"path,omitempty"`
	Weight   int               `json:"weight" yaml:"weight"`
	Priority int               `json:"priority" yaml:"priority"`
	Region   string            `json:"region,omitempty" yaml:"region,omitempty"`
	Zone     string            `json:"zone,omitempty" yaml:"zone,omitempty"`
	
	// Health status
	Status      EndpointStatus    `json:"status" yaml:"status"`
	Healthy     bool              `json:"healthy" yaml:"healthy"`
	LastCheck   time.Time         `json:"last_check" yaml:"last_check"`
	FailCount   int               `json:"fail_count" yaml:"fail_count"`
	
	// Connection settings
	MaxConnections    int           `json:"max_connections,omitempty" yaml:"max_connections,omitempty"`
	ConnectionTimeout time.Duration `json:"connection_timeout,omitempty" yaml:"connection_timeout,omitempty"`
	KeepAlive         time.Duration `json:"keep_alive,omitempty" yaml:"keep_alive,omitempty"`
	
	// TLS configuration
	TLS         *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	
	// Metadata
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	
	// Timestamps
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at"`
}

// EndpointStatus represents the status of an endpoint
type EndpointStatus string

const (
	EndpointStatusHealthy   EndpointStatus = "healthy"
	EndpointStatusUnhealthy EndpointStatus = "unhealthy"
	EndpointStatusDraining  EndpointStatus = "draining"
	EndpointStatusMaintenance EndpointStatus = "maintenance"
	EndpointStatusUnknown   EndpointStatus = "unknown"
)

// ServiceHealthCheck represents health check configuration for a service
type ServiceHealthCheck struct {
	Enabled      bool          `json:"enabled" yaml:"enabled"`
	Path         string        `json:"path" yaml:"path"`
	Method       string        `json:"method" yaml:"method"`
	Interval     time.Duration `json:"interval" yaml:"interval"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`
	Retries      int           `json:"retries" yaml:"retries"`
	
	// Thresholds
	HealthyThreshold   int `json:"healthy_threshold" yaml:"healthy_threshold"`
	UnhealthyThreshold int `json:"unhealthy_threshold" yaml:"unhealthy_threshold"`
	
	// Expected response
	ExpectedStatus []int    `json:"expected_status,omitempty" yaml:"expected_status,omitempty"`
	ExpectedBody   string   `json:"expected_body,omitempty" yaml:"expected_body,omitempty"`
	ExpectedHeaders map[string]string `json:"expected_headers,omitempty" yaml:"expected_headers,omitempty"`
	
	// Custom health check
	Command     string            `json:"command,omitempty" yaml:"command,omitempty"`
	Script      string            `json:"script,omitempty" yaml:"script,omitempty"`
	
	// Failure handling
	OnFailure   FailureAction     `json:"on_failure" yaml:"on_failure"`
	
	// Notifications
	Notifications []NotificationConfig `json:"notifications,omitempty" yaml:"notifications,omitempty"`
}

// FailureAction represents actions to take on health check failure
type FailureAction string

const (
	FailureActionNone      FailureAction = "none"
	FailureActionRemove    FailureAction = "remove"
	FailureActionDrain     FailureAction = "drain"
	FailureActionRestart   FailureAction = "restart"
	FailureActionNotify    FailureAction = "notify"
)

// NotificationConfig represents notification configuration
type NotificationConfig struct {
	Type     string            `json:"type" yaml:"type"`
	Endpoint string            `json:"endpoint" yaml:"endpoint"`
	Template string            `json:"template,omitempty" yaml:"template,omitempty"`
	Headers  map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// ServiceSecurity represents security configuration for a service
type ServiceSecurity struct {
	Authentication AuthConfig        `json:"authentication" yaml:"authentication"`
	Authorization  AuthzConfig       `json:"authorization" yaml:"authorization"`
	
	// Network security
	AllowedCIDRs   []string          `json:"allowed_cidrs,omitempty" yaml:"allowed_cidrs,omitempty"`
	BlockedCIDRs   []string          `json:"blocked_cidrs,omitempty" yaml:"blocked_cidrs,omitempty"`
	
	// Request validation
	InputValidation InputValidationConfig `json:"input_validation" yaml:"input_validation"`
	
	// DDoS protection
	DDoSProtection  DDoSProtectionConfig  `json:"ddos_protection" yaml:"ddos_protection"`
	
	// WAF configuration
	WAF             WAFConfig             `json:"waf" yaml:"waf"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Required  bool              `json:"required" yaml:"required"`
	Type      AuthType          `json:"type" yaml:"type"`
	Provider  string            `json:"provider,omitempty" yaml:"provider,omitempty"`
	Config    map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
	
	// JWT specific
	JWTConfig *JWTConfig        `json:"jwt_config,omitempty" yaml:"jwt_config,omitempty"`
	
	// OAuth specific
	OAuthConfig *OAuthConfig    `json:"oauth_config,omitempty" yaml:"oauth_config,omitempty"`
	
	// API Key specific
	APIKeyConfig *APIKeyConfig  `json:"api_key_config,omitempty" yaml:"api_key_config,omitempty"`
}

// JWTConfig represents JWT authentication configuration
type JWTConfig struct {
	SecretKey        string   `json:"secret_key,omitempty" yaml:"secret_key,omitempty"`
	PublicKey        string   `json:"public_key,omitempty" yaml:"public_key,omitempty"`
	Algorithm        string   `json:"algorithm" yaml:"algorithm"`
	Issuer           string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Audience         string   `json:"audience,omitempty" yaml:"audience,omitempty"`
	RequiredClaims   []string `json:"required_claims,omitempty" yaml:"required_claims,omitempty"`
	ClockSkew        time.Duration `json:"clock_skew,omitempty" yaml:"clock_skew,omitempty"`
	TokenLocation    string   `json:"token_location" yaml:"token_location"` // "header", "query", "cookie"
	TokenName        string   `json:"token_name" yaml:"token_name"`
}

// OAuthConfig represents OAuth authentication configuration
type OAuthConfig struct {
	AuthURL      string   `json:"auth_url" yaml:"auth_url"`
	TokenURL     string   `json:"token_url" yaml:"token_url"`
	UserInfoURL  string   `json:"user_info_url,omitempty" yaml:"user_info_url,omitempty"`
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	Scopes       []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
}

// APIKeyConfig represents API key authentication configuration
type APIKeyConfig struct {
	HeaderName  string `json:"header_name" yaml:"header_name"`
	QueryParam  string `json:"query_param,omitempty" yaml:"query_param,omitempty"`
	CookieName  string `json:"cookie_name,omitempty" yaml:"cookie_name,omitempty"`
	Prefix      string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
}

// AuthzConfig represents authorization configuration
type AuthzConfig struct {
	Required     bool              `json:"required" yaml:"required"`
	Type         string            `json:"type" yaml:"type"` // "rbac", "abac", "custom"
	Roles        []string          `json:"roles,omitempty" yaml:"roles,omitempty"`
	Permissions  []string          `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	Rules        []AuthzRule       `json:"rules,omitempty" yaml:"rules,omitempty"`
	Provider     string            `json:"provider,omitempty" yaml:"provider,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

// AuthzRule represents an authorization rule
type AuthzRule struct {
	Resource   string            `json:"resource" yaml:"resource"`
	Action     string            `json:"action" yaml:"action"`
	Effect     string            `json:"effect" yaml:"effect"` // "allow", "deny"
	Conditions map[string]string `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// InputValidationConfig represents input validation configuration
type InputValidationConfig struct {
	Enabled      bool              `json:"enabled" yaml:"enabled"`
	MaxBodySize  int64             `json:"max_body_size" yaml:"max_body_size"`
	ContentTypes []string          `json:"content_types,omitempty" yaml:"content_types,omitempty"`
	Schema       string            `json:"schema,omitempty" yaml:"schema,omitempty"`
	Rules        []ValidationRule  `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// DDoSProtectionConfig represents DDoS protection configuration
type DDoSProtectionConfig struct {
	Enabled          bool          `json:"enabled" yaml:"enabled"`
	RequestsPerSecond int          `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize        int           `json:"burst_size" yaml:"burst_size"`
	WindowSize       time.Duration `json:"window_size" yaml:"window_size"`
	BlockDuration    time.Duration `json:"block_duration" yaml:"block_duration"`
	Whitelist        []string      `json:"whitelist,omitempty" yaml:"whitelist,omitempty"`
}

// WAFConfig represents Web Application Firewall configuration
type WAFConfig struct {
	Enabled   bool              `json:"enabled" yaml:"enabled"`
	Provider  string            `json:"provider" yaml:"provider"`
	Rules     []WAFRule         `json:"rules,omitempty" yaml:"rules,omitempty"`
	Mode      string            `json:"mode" yaml:"mode"` // "detection", "prevention"
	Config    map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

// WAFRule represents a WAF rule
type WAFRule struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Pattern     string            `json:"pattern" yaml:"pattern"`
	Action      string            `json:"action" yaml:"action"` // "block", "log", "challenge"
	Severity    string            `json:"severity" yaml:"severity"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
}

// ServiceDiscovery represents service discovery configuration
type ServiceDiscovery struct {
	Type       DiscoveryType     `json:"type" yaml:"type"`
	Enabled    bool              `json:"enabled" yaml:"enabled"`
	
	// Service registry configuration
	Registry   RegistryConfig    `json:"registry" yaml:"registry"`
	
	// DNS-based discovery
	DNS        DNSConfig         `json:"dns,omitempty" yaml:"dns,omitempty"`
	
	// Static configuration
	Static     StaticConfig      `json:"static,omitempty" yaml:"static,omitempty"`
	
	// Update settings
	UpdateInterval time.Duration  `json:"update_interval" yaml:"update_interval"`
	RetryAttempts  int            `json:"retry_attempts" yaml:"retry_attempts"`
	RetryDelay     time.Duration  `json:"retry_delay" yaml:"retry_delay"`
}

// DiscoveryType represents service discovery type
type DiscoveryType string

const (
	DiscoveryTypeStatic   DiscoveryType = "static"
	DiscoveryTypeDNS      DiscoveryType = "dns"
	DiscoveryTypeConsul   DiscoveryType = "consul"
	DiscoveryTypeEureka   DiscoveryType = "eureka"
	DiscoveryTypeEtcd     DiscoveryType = "etcd"
	DiscoveryTypeK8s      DiscoveryType = "kubernetes"
	DiscoveryTypeNacos    DiscoveryType = "nacos"
)

// RegistryConfig represents service registry configuration
type RegistryConfig struct {
	Address     string            `json:"address" yaml:"address"`
	Username    string            `json:"username,omitempty" yaml:"username,omitempty"`
	Password    string            `json:"password,omitempty" yaml:"password,omitempty"`
	Namespace   string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	ServiceName string            `json:"service_name" yaml:"service_name"`
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	TLS         *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
}

// DNSConfig represents DNS-based discovery configuration
type DNSConfig struct {
	Domain     string   `json:"domain" yaml:"domain"`
	Nameservers []string `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	Port       int      `json:"port" yaml:"port"`
	RecordType string   `json:"record_type" yaml:"record_type"` // "A", "SRV"
}

// StaticConfig represents static service configuration
type StaticConfig struct {
	Endpoints []ServiceEndpoint `json:"endpoints" yaml:"endpoints"`
}

// Service methods

// IsHealthy returns true if the service has at least one healthy endpoint
func (s *Service) IsHealthy() bool {
	for _, endpoint := range s.Endpoints {
		if endpoint.Healthy {
			return true
		}
	}
	return false
}

// GetHealthyEndpoints returns all healthy endpoints
func (s *Service) GetHealthyEndpoints() []ServiceEndpoint {
	var healthy []ServiceEndpoint
	for _, endpoint := range s.Endpoints {
		if endpoint.Healthy {
			healthy = append(healthy, endpoint)
		}
	}
	return healthy
}

// GetEndpoint returns an endpoint based on load balancing strategy
func (s *Service) GetEndpoint(clientIP string, sessionID string) (*ServiceEndpoint, error) {
	endpoints := s.GetHealthyEndpoints()
	if len(endpoints) == 0 {
		return nil, ErrNoHealthyServiceEndpoints
	}

	switch s.LoadBalancer.Strategy {
	case LoadBalanceRoundRobin:
		return &endpoints[0], nil // Simplified
	case LoadBalanceWeighted:
		return s.selectWeightedEndpoint(endpoints), nil
	case LoadBalanceRandom:
		return s.selectRandomEndpoint(endpoints), nil
	case LoadBalanceIPHash:
		return s.selectIPHashEndpoint(endpoints, clientIP), nil
	default:
		return &endpoints[0], nil
	}
}

// Validate validates the service configuration
func (s *Service) Validate() error {
	if s.Name == "" {
		return ErrInvalidServiceName
	}

	if len(s.Endpoints) == 0 {
		return ErrNoServiceEndpoints
	}

	for _, endpoint := range s.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// UpdateEndpointHealth updates the health status of an endpoint
func (s *Service) UpdateEndpointHealth(endpointID uuid.UUID, healthy bool) {
	for i := range s.Endpoints {
		if s.Endpoints[i].ID == endpointID {
			s.Endpoints[i].Healthy = healthy
			s.Endpoints[i].LastCheck = time.Now()
			s.Endpoints[i].Status = EndpointStatusHealthy
			if !healthy {
				s.Endpoints[i].Status = EndpointStatusUnhealthy
				s.Endpoints[i].FailCount++
			} else {
				s.Endpoints[i].FailCount = 0
			}
			break
		}
	}
	s.UpdatedAt = time.Now()
}

// AddEndpoint adds a new endpoint to the service
func (s *Service) AddEndpoint(endpoint ServiceEndpoint) {
	endpoint.ID = uuid.New()
	endpoint.CreatedAt = time.Now()
	endpoint.UpdatedAt = time.Now()
	s.Endpoints = append(s.Endpoints, endpoint)
	s.UpdatedAt = time.Now()
}

// RemoveEndpoint removes an endpoint from the service
func (s *Service) RemoveEndpoint(endpointID uuid.UUID) bool {
	for i, endpoint := range s.Endpoints {
		if endpoint.ID == endpointID {
			s.Endpoints = append(s.Endpoints[:i], s.Endpoints[i+1:]...)
			s.UpdatedAt = time.Now()
			return true
		}
	}
	return false
}

// ServiceEndpoint methods

// Validate validates the service endpoint configuration
func (e *ServiceEndpoint) Validate() error {
	if e.Host == "" {
		return ErrInvalidEndpointHost
	}

	if e.Port <= 0 || e.Port > 65535 {
		return ErrInvalidEndpointPort
	}

	if e.Weight < 0 {
		return ErrInvalidEndpointWeight
	}

	return nil
}

// GetURL returns the full URL for the endpoint
func (e *ServiceEndpoint) GetURL(scheme string) string {
	if scheme == "" {
		if e.TLS != nil && e.TLS.Enabled {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	url := scheme + "://" + e.Host
	if e.Port != 80 && e.Port != 443 {
		url += ":" + string(rune(e.Port))
	}
	if e.Path != "" {
		url += e.Path
	}

	return url
}

// SetHealthy marks the endpoint as healthy or unhealthy
func (e *ServiceEndpoint) SetHealthy(healthy bool) {
	e.Healthy = healthy
	e.LastCheck = time.Now()
	e.UpdatedAt = time.Now()
	
	if healthy {
		e.Status = EndpointStatusHealthy
		e.FailCount = 0
	} else {
		e.Status = EndpointStatusUnhealthy
		e.FailCount++
	}
}

// Load balancing helper methods (simplified implementations)

func (s *Service) selectWeightedEndpoint(endpoints []ServiceEndpoint) *ServiceEndpoint {
	// Simplified weighted selection
	return &endpoints[0]
}

func (s *Service) selectRandomEndpoint(endpoints []ServiceEndpoint) *ServiceEndpoint {
	// Simplified random selection
	return &endpoints[0]
}

func (s *Service) selectIPHashEndpoint(endpoints []ServiceEndpoint, clientIP string) *ServiceEndpoint {
	// Simplified IP hash selection
	return &endpoints[0]
}

// Service errors
var (
	ErrInvalidServiceName        = ServiceError{Message: "invalid service name"}
	ErrNoServiceEndpoints        = ServiceError{Message: "no service endpoints configured"}
	ErrNoHealthyServiceEndpoints = ServiceError{Message: "no healthy service endpoints available"}
	ErrInvalidEndpointWeight     = ServiceError{Message: "invalid endpoint weight"}
)

// ServiceError represents a service configuration error
type ServiceError struct {
	Message string
}

func (e ServiceError) Error() string {
	return e.Message
}