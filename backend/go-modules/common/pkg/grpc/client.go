package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/tracing"
)

// ClientConfig represents gRPC client configuration
type ClientConfig struct {
	// Connection settings
	Target  string        `yaml:"target" json:"target"`
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	
	// TLS settings
	TLS TLSConfig `yaml:"tls" json:"tls"`
	
	// Keep alive settings
	KeepAliveTime    time.Duration `yaml:"keep_alive_time" json:"keep_alive_time"`
	KeepAliveTimeout time.Duration `yaml:"keep_alive_timeout" json:"keep_alive_timeout"`
	
	// Message size limits
	MaxReceiveMessageSize int `yaml:"max_receive_message_size" json:"max_receive_message_size"`
	MaxSendMessageSize    int `yaml:"max_send_message_size" json:"max_send_message_size"`
	
	// Middleware settings
	EnableMetrics bool `yaml:"enable_metrics" json:"enable_metrics"`
	EnableLogging bool `yaml:"enable_logging" json:"enable_logging"`
	EnableTracing bool `yaml:"enable_tracing" json:"enable_tracing"`
	EnableRetry   bool `yaml:"enable_retry" json:"enable_retry"`
	
	// Retry settings
	RetryMaxAttempts uint          `yaml:"retry_max_attempts" json:"retry_max_attempts"`
	RetryTimeout     time.Duration `yaml:"retry_timeout" json:"retry_timeout"`
	RetryBackoff     time.Duration `yaml:"retry_backoff" json:"retry_backoff"`
	
	// Service discovery and load balancing
	ServiceName      string `yaml:"service_name" json:"service_name"`
	LoadBalancePolicy string `yaml:"load_balance_policy" json:"load_balance_policy"` // round_robin, pick_first
}

// Client represents a gRPC client with cross-cutting concerns
type Client struct {
	config *ClientConfig
	conn   *grpc.ClientConn
	logger *zap.Logger
}

// NewClient creates a new gRPC client with cross-cutting concerns
func NewClient(config *ClientConfig, logger *zap.Logger) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("client config is required")
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	c := &Client{
		config: config,
		logger: logger,
	}

	// Build dial options
	dialOpts, err := c.buildDialOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to build dial options: %w", err)
	}

	// Create connection with timeout
	ctx := context.Background()
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	conn, err := grpc.DialContext(ctx, config.Target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", config.Target, err)
	}

	c.conn = conn

	logger.Info("gRPC client connected",
		zap.String("target", config.Target),
		zap.Bool("tls", config.TLS.Enabled),
		zap.Bool("metrics", config.EnableMetrics),
		zap.Bool("retry", config.EnableRetry),
	)

	return c, nil
}

// buildDialOptions builds gRPC dial options with middleware
func (c *Client) buildDialOptions() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption
	var unaryInterceptors []grpc.UnaryClientInterceptor
	var streamInterceptors []grpc.StreamClientInterceptor

	// Add credentials
	if c.config.TLS.Enabled {
		creds, err := c.buildTLSCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Add keep alive parameters
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                c.config.KeepAliveTime,
		Timeout:             c.config.KeepAliveTimeout,
		PermitWithoutStream: true,
	}))

	// Add message size limits
	if c.config.MaxReceiveMessageSize > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(c.config.MaxReceiveMessageSize)))
	}
	if c.config.MaxSendMessageSize > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(c.config.MaxSendMessageSize)))
	}

	// Add load balancing
	if c.config.LoadBalancePolicy != "" {
		opts = append(opts, grpc.WithDefaultServiceConfig(fmt.Sprintf(`{
			"loadBalancingConfig": [
				{"%s": {}}
			]
		}`, c.config.LoadBalancePolicy)))
	}

	// Add context tags (should be first)
	unaryInterceptors = append(unaryInterceptors, grpc_ctxtags.UnaryClientInterceptor())
	streamInterceptors = append(streamInterceptors, grpc_ctxtags.StreamClientInterceptor())

	// Add tracing if enabled
	if c.config.EnableTracing {
		tracingUnary, tracingStream := tracing.GRPCClientInterceptors()
		unaryInterceptors = append(unaryInterceptors, tracingUnary)
		streamInterceptors = append(streamInterceptors, tracingStream)
	}

	// Add logging if enabled
	if c.config.EnableLogging {
		loggingUnary, loggingStream := logging.GRPCClientInterceptors(c.logger)
		unaryInterceptors = append(unaryInterceptors, loggingUnary)
		streamInterceptors = append(streamInterceptors, loggingStream)
	}

	// Add metrics if enabled
	if c.config.EnableMetrics {
		unaryInterceptors = append(unaryInterceptors, grpc_prometheus.UnaryClientInterceptor)
		streamInterceptors = append(streamInterceptors, grpc_prometheus.StreamClientInterceptor)
	}

	// Add retry if enabled (should be last)
	if c.config.EnableRetry {
		retryOpts := c.buildRetryOptions()
		unaryInterceptors = append(unaryInterceptors, grpc_retry.UnaryClientInterceptor(retryOpts...))
		streamInterceptors = append(streamInterceptors, grpc_retry.StreamClientInterceptor(retryOpts...))
	}

	// Chain interceptors
	opts = append(opts,
		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryInterceptors...)),
		grpc.WithStreamInterceptor(grpc_middleware.ChainStreamClient(streamInterceptors...)),
	)

	return opts, nil
}

// buildTLSCredentials builds TLS credentials for client
func (c *Client) buildTLSCredentials() (credentials.TransportCredentials, error) {
	tlsConfig := &tls.Config{
		ServerName: c.config.ServiceName,
		MinVersion: tls.VersionTLS12,
	}

	// Load client certificate if specified
	if c.config.TLS.CertFile != "" && c.config.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.config.TLS.CertFile, c.config.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA file if specified
	if c.config.TLS.CAFile != "" {
		// Implementation would load CA file and set up server certificate verification
		tlsConfig.InsecureSkipVerify = false
	}

	return credentials.NewTLS(tlsConfig), nil
}

// buildRetryOptions builds retry options
func (c *Client) buildRetryOptions() []grpc_retry.CallOption {
	var opts []grpc_retry.CallOption

	if c.config.RetryMaxAttempts > 0 {
		opts = append(opts, grpc_retry.WithMax(c.config.RetryMaxAttempts))
	}

	if c.config.RetryTimeout > 0 {
		opts = append(opts, grpc_retry.WithPerRetryTimeout(c.config.RetryTimeout))
	}

	if c.config.RetryBackoff > 0 {
		opts = append(opts, grpc_retry.WithBackoff(grpc_retry.BackoffLinear(c.config.RetryBackoff)))
	}

	// Retry on specific codes
	opts = append(opts, grpc_retry.WithCodes(
		codes.Unavailable,
		codes.DeadlineExceeded,
		codes.ResourceExhausted,
		codes.Aborted,
	))

	return opts
}

// GetConnection returns the underlying gRPC connection
func (c *Client) GetConnection() *grpc.ClientConn {
	return c.conn
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	if c.conn != nil {
		c.logger.Info("Closing gRPC client connection", zap.String("target", c.config.Target))
		return c.conn.Close()
	}
	return nil
}

// IsConnected returns true if the client is connected
func (c *Client) IsConnected() bool {
	if c.conn == nil {
		return false
	}
	
	state := c.conn.GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// WaitForConnection waits for the connection to be ready
func (c *Client) WaitForConnection(ctx context.Context) error {
	if c.conn == nil {
		return fmt.Errorf("connection is nil")
	}
	
	return c.conn.WaitForStateChange(ctx, connectivity.Connecting)
}

// GetMetrics returns client metrics
func (c *Client) GetMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"target":           c.config.Target,
		"tls_enabled":      c.config.TLS.Enabled,
		"metrics_enabled":  c.config.EnableMetrics,
		"tracing_enabled":  c.config.EnableTracing,
		"retry_enabled":    c.config.EnableRetry,
	}

	if c.conn != nil {
		metrics["connection_state"] = c.conn.GetState().String()
	}

	return metrics
}

// DefaultClientConfig returns a default client configuration
func DefaultClientConfig(target string) *ClientConfig {
	return &ClientConfig{
		Target:  target,
		Timeout: 30 * time.Second,
		
		TLS: TLSConfig{
			Enabled: false,
		},
		
		KeepAliveTime:    30 * time.Second,
		KeepAliveTimeout: 5 * time.Second,
		
		MaxReceiveMessageSize: 4 * 1024 * 1024, // 4MB
		MaxSendMessageSize:    4 * 1024 * 1024, // 4MB
		
		EnableMetrics: true,
		EnableLogging: true,
		EnableTracing: true,
		EnableRetry:   true,
		
		RetryMaxAttempts: 3,
		RetryTimeout:     5 * time.Second,
		RetryBackoff:     100 * time.Millisecond,
		
		LoadBalancePolicy: "round_robin",
	}
}