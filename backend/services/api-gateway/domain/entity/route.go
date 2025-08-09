package entity

import (
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// Route represents an API route configuration
type Route struct {
	ID          uuid.UUID         `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	
	// Path configuration
	Path        string            `json:"path" yaml:"path"`
	PathRegex   *regexp.Regexp    `json:"-" yaml:"-"`
	Method      string            `json:"method" yaml:"method"`
	Methods     []string          `json:"methods,omitempty" yaml:"methods,omitempty"`
	
	// Service configuration
	Service     string            `json:"service" yaml:"service"`
	Backend     BackendConfig     `json:"backend" yaml:"backend"`
	
	// Authentication and authorization
	AuthRequired       bool               `json:"auth_required" yaml:"auth_required"`
	AuthType          AuthType           `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`
	RequiredScopes    []string           `json:"required_scopes,omitempty" yaml:"required_scopes,omitempty"`
	RequiredRoles     []string           `json:"required_roles,omitempty" yaml:"required_roles,omitempty"`
	RequiredClaims    map[string]string  `json:"required_claims,omitempty" yaml:"required_claims,omitempty"`
	
	// Rate limiting
	RateLimit         *RateLimitConfig   `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	
	// Caching
	CacheConfig       *CacheConfig       `json:"cache_config,omitempty" yaml:"cache_config,omitempty"`
	
	// Request/Response transformation
	RequestTransform  *TransformConfig   `json:"request_transform,omitempty" yaml:"request_transform,omitempty"`
	ResponseTransform *TransformConfig   `json:"response_transform,omitempty" yaml:"response_transform,omitempty"`
	
	// Middleware chain
	Middleware        []MiddlewareConfig `json:"middleware,omitempty" yaml:"middleware,omitempty"`
	
	// Circuit breaker
	CircuitBreaker    *CircuitBreakerConfig `json:"circuit_breaker,omitempty" yaml:"circuit_breaker,omitempty"`
	
	// Timeout configuration
	Timeout           time.Duration      `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	
	// CORS configuration
	CORS              *CORSConfig        `json:"cors,omitempty" yaml:"cors,omitempty"`
	
	// Monitoring and observability
	Metrics           MetricsConfig      `json:"metrics" yaml:"metrics"`
	Logging           LoggingConfig      `json:"logging" yaml:"logging"`
	Tracing           TracingConfig      `json:"tracing" yaml:"tracing"`
	
	// Health check
	HealthCheck       *HealthCheckConfig `json:"health_check,omitempty" yaml:"health_check,omitempty"`
	
	// Load balancing
	LoadBalancer      LoadBalancerConfig `json:"load_balancer" yaml:"load_balancer"`
	
	// Security
	Security          SecurityConfig     `json:"security" yaml:"security"`
	
	// Metadata
	Tags              []string           `json:"tags,omitempty" yaml:"tags,omitempty"`
	Labels            map[string]string  `json:"labels,omitempty" yaml:"labels,omitempty"`
	Priority          int                `json:"priority" yaml:"priority"`
	Enabled           bool               `json:"enabled" yaml:"enabled"`
	
	// Timestamps
	CreatedAt         time.Time          `json:"created_at" yaml:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at" yaml:"updated_at"`
	Version           int                `json:"version" yaml:"version"`
}

// BackendConfig represents backend service configuration
type BackendConfig struct {
	Type        BackendType       `json:"type" yaml:"type"`
	Endpoints   []EndpointConfig  `json:"endpoints" yaml:"endpoints"`
	Protocol    string            `json:"protocol" yaml:"protocol"`
	BasePath    string            `json:"base_path,omitempty" yaml:"base_path,omitempty"`
	
	// Connection settings
	MaxConnections    int           `json:"max_connections,omitempty" yaml:"max_connections,omitempty"`
	ConnectionTimeout time.Duration `json:"connection_timeout,omitempty" yaml:"connection_timeout,omitempty"`
	KeepAlive         time.Duration `json:"keep_alive,omitempty" yaml:"keep_alive,omitempty"`
	
	// TLS configuration
	TLS               *TLSConfig    `json:"tls,omitempty" yaml:"tls,omitempty"`
	
	// Retry configuration
	Retry             *RetryConfig  `json:"retry,omitempty" yaml:"retry,omitempty"`
}

// EndpointConfig represents a backend endpoint
type EndpointConfig struct {
	Host     string            `json:"host" yaml:"host"`
	Port     int               `json:"port" yaml:"port"`
	Weight   int               `json:"weight" yaml:"weight"`
	Priority int               `json:"priority" yaml:"priority"`
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	
	// Health status
	Healthy   bool      `json:"healthy" yaml:"healthy"`
	LastCheck time.Time `json:"last_check" yaml:"last_check"`
}

// BackendType represents the type of backend
type BackendType string

const (
	BackendTypeHTTP BackendType = "http"
	BackendTypeGRPC BackendType = "grpc"
	BackendTypeTCP  BackendType = "tcp"
	BackendTypeUDP  BackendType = "udp"
)

// AuthType represents the authentication type
type AuthType string

const (
	AuthTypeNone   AuthType = "none"
	AuthTypeJWT    AuthType = "jwt"
	AuthTypeAPIKey AuthType = "api_key"
	AuthTypeOAuth  AuthType = "oauth"
	AuthTypeBasic  AuthType = "basic"
	AuthTypeCustom AuthType = "custom"
)

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	RequestsPerSecond int           `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	WindowSize        time.Duration `json:"window_size" yaml:"window_size"`
	KeyExtractor      string        `json:"key_extractor" yaml:"key_extractor"` // "ip", "user", "api_key", "custom"
	CustomKeyHeader   string        `json:"custom_key_header,omitempty" yaml:"custom_key_header,omitempty"`
	ErrorMessage      string        `json:"error_message,omitempty" yaml:"error_message,omitempty"`
	ErrorCode         int           `json:"error_code,omitempty" yaml:"error_code,omitempty"`
}

// CacheConfig represents caching configuration
type CacheConfig struct {
	Enabled       bool          `json:"enabled" yaml:"enabled"`
	TTL           time.Duration `json:"ttl" yaml:"ttl"`
	KeyPattern    string        `json:"key_pattern" yaml:"key_pattern"`
	VaryHeaders   []string      `json:"vary_headers,omitempty" yaml:"vary_headers,omitempty"`
	CacheControl  string        `json:"cache_control,omitempty" yaml:"cache_control,omitempty"`
	SkipOnError   bool          `json:"skip_on_error" yaml:"skip_on_error"`
}

// TransformConfig represents request/response transformation configuration
type TransformConfig struct {
	Headers    HeaderTransformConfig `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body       BodyTransformConfig   `json:"body,omitempty" yaml:"body,omitempty"`
	QueryParams QueryTransformConfig `json:"query_params,omitempty" yaml:"query_params,omitempty"`
	Path       PathTransformConfig   `json:"path,omitempty" yaml:"path,omitempty"`
}

// HeaderTransformConfig represents header transformation
type HeaderTransformConfig struct {
	Add      map[string]string `json:"add,omitempty" yaml:"add,omitempty"`
	Set      map[string]string `json:"set,omitempty" yaml:"set,omitempty"`
	Remove   []string          `json:"remove,omitempty" yaml:"remove,omitempty"`
	Rename   map[string]string `json:"rename,omitempty" yaml:"rename,omitempty"`
}

// BodyTransformConfig represents body transformation
type BodyTransformConfig struct {
	Template     string            `json:"template,omitempty" yaml:"template,omitempty"`
	JSONPath     string            `json:"json_path,omitempty" yaml:"json_path,omitempty"`
	XPath        string            `json:"xpath,omitempty" yaml:"xpath,omitempty"`
	Replacements map[string]string `json:"replacements,omitempty" yaml:"replacements,omitempty"`
}

// QueryTransformConfig represents query parameter transformation
type QueryTransformConfig struct {
	Add    map[string]string `json:"add,omitempty" yaml:"add,omitempty"`
	Remove []string          `json:"remove,omitempty" yaml:"remove,omitempty"`
	Rename map[string]string `json:"rename,omitempty" yaml:"rename,omitempty"`
}

// PathTransformConfig represents path transformation
type PathTransformConfig struct {
	StripPrefix string `json:"strip_prefix,omitempty" yaml:"strip_prefix,omitempty"`
	AddPrefix   string `json:"add_prefix,omitempty" yaml:"add_prefix,omitempty"`
	Rewrite     string `json:"rewrite,omitempty" yaml:"rewrite,omitempty"`
}

// MiddlewareConfig represents middleware configuration
type MiddlewareConfig struct {
	Name     string                 `json:"name" yaml:"name"`
	Type     string                 `json:"type" yaml:"type"`
	Config   map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
	Priority int                    `json:"priority" yaml:"priority"`
	Enabled  bool                   `json:"enabled" yaml:"enabled"`
}

// CircuitBreakerConfig represents circuit breaker configuration
type CircuitBreakerConfig struct {
	MaxRequests    uint32        `json:"max_requests" yaml:"max_requests"`
	Interval       time.Duration `json:"interval" yaml:"interval"`
	Timeout        time.Duration `json:"timeout" yaml:"timeout"`
	FailureRatio   float64       `json:"failure_ratio" yaml:"failure_ratio"`
	MinRequests    uint32        `json:"min_requests" yaml:"min_requests"`
	OnStateChange  string        `json:"on_state_change,omitempty" yaml:"on_state_change,omitempty"`
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins" yaml:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods" yaml:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers" yaml:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers,omitempty" yaml:"exposed_headers,omitempty"`
	AllowCredentials bool     `json:"allow_credentials" yaml:"allow_credentials"`
	MaxAge           int      `json:"max_age" yaml:"max_age"`
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	Enabled        bool     `json:"enabled" yaml:"enabled"`
	Labels         []string `json:"labels,omitempty" yaml:"labels,omitempty"`
	CustomMetrics  []string `json:"custom_metrics,omitempty" yaml:"custom_metrics,omitempty"`
	SampleRate     float64  `json:"sample_rate" yaml:"sample_rate"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	Level       string   `json:"level" yaml:"level"`
	Format      string   `json:"format" yaml:"format"`
	Fields      []string `json:"fields,omitempty" yaml:"fields,omitempty"`
	SampleRate  float64  `json:"sample_rate" yaml:"sample_rate"`
}

// TracingConfig represents tracing configuration
type TracingConfig struct {
	Enabled     bool    `json:"enabled" yaml:"enabled"`
	SampleRate  float64 `json:"sample_rate" yaml:"sample_rate"`
	Service     string  `json:"service,omitempty" yaml:"service,omitempty"`
	Operation   string  `json:"operation,omitempty" yaml:"operation,omitempty"`
}

// HealthCheckConfig represents health check configuration
type HealthCheckConfig struct {
	Enabled      bool          `json:"enabled" yaml:"enabled"`
	Path         string        `json:"path" yaml:"path"`
	Method       string        `json:"method" yaml:"method"`
	Interval     time.Duration `json:"interval" yaml:"interval"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`
	HealthyThreshold   int     `json:"healthy_threshold" yaml:"healthy_threshold"`
	UnhealthyThreshold int     `json:"unhealthy_threshold" yaml:"unhealthy_threshold"`
	ExpectedStatus     []int   `json:"expected_status,omitempty" yaml:"expected_status,omitempty"`
	ExpectedBody       string  `json:"expected_body,omitempty" yaml:"expected_body,omitempty"`
}

// LoadBalancerConfig represents load balancer configuration
type LoadBalancerConfig struct {
	Strategy      LoadBalanceStrategy `json:"strategy" yaml:"strategy"`
	HealthCheck   bool                `json:"health_check" yaml:"health_check"`
	StickySession bool                `json:"sticky_session" yaml:"sticky_session"`
	SessionCookie string              `json:"session_cookie,omitempty" yaml:"session_cookie,omitempty"`
}

// LoadBalanceStrategy represents load balancing strategy
type LoadBalanceStrategy string

const (
	LoadBalanceRoundRobin  LoadBalanceStrategy = "round_robin"
	LoadBalanceWeighted    LoadBalanceStrategy = "weighted"
	LoadBalanceLeastConn   LoadBalanceStrategy = "least_conn"
	LoadBalanceIPHash      LoadBalanceStrategy = "ip_hash"
	LoadBalanceRandom      LoadBalanceStrategy = "random"
	LoadBalanceHealthFirst LoadBalanceStrategy = "health_first"
)

// SecurityConfig represents security configuration
type SecurityConfig struct {
	AllowedIPs      []string          `json:"allowed_ips,omitempty" yaml:"allowed_ips,omitempty"`
	BlockedIPs      []string          `json:"blocked_ips,omitempty" yaml:"blocked_ips,omitempty"`
	RequireHTTPS    bool              `json:"require_https" yaml:"require_https"`
	CSP             string            `json:"csp,omitempty" yaml:"csp,omitempty"`
	HSTS            *HSTSConfig       `json:"hsts,omitempty" yaml:"hsts,omitempty"`
	RequestSizeLimit int64            `json:"request_size_limit,omitempty" yaml:"request_size_limit,omitempty"`
	ValidationRules  []ValidationRule `json:"validation_rules,omitempty" yaml:"validation_rules,omitempty"`
}

// HSTSConfig represents HTTP Strict Transport Security configuration
type HSTSConfig struct {
	MaxAge            int  `json:"max_age" yaml:"max_age"`
	IncludeSubdomains bool `json:"include_subdomains" yaml:"include_subdomains"`
	Preload           bool `json:"preload" yaml:"preload"`
}

// ValidationRule represents a validation rule
type ValidationRule struct {
	Field    string `json:"field" yaml:"field"`
	Type     string `json:"type" yaml:"type"`
	Required bool   `json:"required" yaml:"required"`
	Pattern  string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	MinValue *int   `json:"min_value,omitempty" yaml:"min_value,omitempty"`
	MaxValue *int   `json:"max_value,omitempty" yaml:"max_value,omitempty"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	CertFile   string `json:"cert_file,omitempty" yaml:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty" yaml:"key_file,omitempty"`
	CAFile     string `json:"ca_file,omitempty" yaml:"ca_file,omitempty"`
	SkipVerify bool   `json:"skip_verify" yaml:"skip_verify"`
}

// RetryConfig represents retry configuration
type RetryConfig struct {
	MaxAttempts int           `json:"max_attempts" yaml:"max_attempts"`
	InitialDelay time.Duration `json:"initial_delay" yaml:"initial_delay"`
	MaxDelay     time.Duration `json:"max_delay" yaml:"max_delay"`
	Multiplier   float64       `json:"multiplier" yaml:"multiplier"`
	RetryOn      []int         `json:"retry_on,omitempty" yaml:"retry_on,omitempty"`
}

// Route methods

// Matches checks if the route matches the given request
func (r *Route) Matches(method, path string) bool {
	if !r.Enabled {
		return false
	}

	// Check method
	if r.Method != "" && r.Method != method {
		return false
	}

	if len(r.Methods) > 0 {
		methodMatches := false
		for _, m := range r.Methods {
			if m == method {
				methodMatches = true
				break
			}
		}
		if !methodMatches {
			return false
		}
	}

	// Check path
	if r.PathRegex != nil {
		return r.PathRegex.MatchString(path)
	}

	return r.Path == path
}

// IsHealthy checks if the route has healthy backends
func (r *Route) IsHealthy() bool {
	if !r.LoadBalancer.HealthCheck {
		return true
	}

	for _, endpoint := range r.Backend.Endpoints {
		if endpoint.Healthy {
			return true
		}
	}

	return false
}

// GetHealthyEndpoints returns healthy endpoints
func (r *Route) GetHealthyEndpoints() []EndpointConfig {
	var healthy []EndpointConfig
	
	for _, endpoint := range r.Backend.Endpoints {
		if endpoint.Healthy {
			healthy = append(healthy, endpoint)
		}
	}

	return healthy
}

// Validate validates the route configuration
func (r *Route) Validate() error {
	if r.Name == "" {
		return ErrInvalidRouteName
	}

	if r.Path == "" {
		return ErrInvalidRoutePath
	}

	if r.Service == "" {
		return ErrInvalidServiceName
	}

	if len(r.Backend.Endpoints) == 0 {
		return ErrNoBackendEndpoints
	}

	// Validate endpoints
	for _, endpoint := range r.Backend.Endpoints {
		if endpoint.Host == "" {
			return ErrInvalidEndpointHost
		}
		if endpoint.Port <= 0 || endpoint.Port > 65535 {
			return ErrInvalidEndpointPort
		}
	}

	// Validate rate limit
	if r.RateLimit != nil {
		if r.RateLimit.RequestsPerSecond <= 0 {
			return ErrInvalidRateLimit
		}
	}

	// Validate circuit breaker
	if r.CircuitBreaker != nil {
		if r.CircuitBreaker.FailureRatio < 0 || r.CircuitBreaker.FailureRatio > 1 {
			return ErrInvalidCircuitBreakerRatio
		}
	}

	return nil
}

// SetRegex sets the compiled regex for path matching
func (r *Route) SetRegex() error {
	if r.Path == "" {
		return ErrInvalidRoutePath
	}

	regex, err := regexp.Compile(r.Path)
	if err != nil {
		return err
	}

	r.PathRegex = regex
	return nil
}

// GetEndpoint returns an endpoint based on load balancing strategy
func (r *Route) GetEndpoint(clientIP string, sessionID string) (*EndpointConfig, error) {
	endpoints := r.GetHealthyEndpoints()
	if len(endpoints) == 0 {
		return nil, ErrNoHealthyEndpoints
	}

	switch r.LoadBalancer.Strategy {
	case LoadBalanceRoundRobin:
		// Simple round-robin (would need state management in real implementation)
		return &endpoints[0], nil
		
	case LoadBalanceWeighted:
		return r.selectWeightedEndpoint(endpoints), nil
		
	case LoadBalanceRandom:
		return r.selectRandomEndpoint(endpoints), nil
		
	case LoadBalanceIPHash:
		return r.selectIPHashEndpoint(endpoints, clientIP), nil
		
	default:
		return &endpoints[0], nil
	}
}

// Helper methods for load balancing (simplified implementations)

func (r *Route) selectWeightedEndpoint(endpoints []EndpointConfig) *EndpointConfig {
	// Simplified weighted selection
	totalWeight := 0
	for _, ep := range endpoints {
		totalWeight += ep.Weight
	}
	
	if totalWeight == 0 {
		return &endpoints[0]
	}
	
	// Would implement proper weighted random selection here
	return &endpoints[0]
}

func (r *Route) selectRandomEndpoint(endpoints []EndpointConfig) *EndpointConfig {
	// Would implement random selection here
	return &endpoints[0]
}

func (r *Route) selectIPHashEndpoint(endpoints []EndpointConfig, clientIP string) *EndpointConfig {
	// Would implement consistent hashing here
	return &endpoints[0]
}

// Route errors
var (
	ErrInvalidRouteName           = RouteError{Message: "invalid route name"}
	ErrInvalidRoutePath           = RouteError{Message: "invalid route path"}
	ErrInvalidServiceName         = RouteError{Message: "invalid service name"}
	ErrNoBackendEndpoints         = RouteError{Message: "no backend endpoints configured"}
	ErrInvalidEndpointHost        = RouteError{Message: "invalid endpoint host"}
	ErrInvalidEndpointPort        = RouteError{Message: "invalid endpoint port"}
	ErrInvalidRateLimit           = RouteError{Message: "invalid rate limit configuration"}
	ErrInvalidCircuitBreakerRatio = RouteError{Message: "invalid circuit breaker failure ratio"}
	ErrNoHealthyEndpoints         = RouteError{Message: "no healthy endpoints available"}
)

// RouteError represents a route configuration error
type RouteError struct {
	Message string
}

func (e RouteError) Error() string {
	return e.Message
}