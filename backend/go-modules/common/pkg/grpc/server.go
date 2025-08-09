package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
	"github.com/isectech/platform/pkg/tracing"
)

// ServerConfig represents gRPC server configuration
type ServerConfig struct {
	// Server settings
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
	
	// TLS settings
	TLS TLSConfig `yaml:"tls" json:"tls"`
	
	// Connection settings
	MaxConnectionAge        time.Duration `yaml:"max_connection_age" json:"max_connection_age"`
	MaxConnectionAgeGrace   time.Duration `yaml:"max_connection_age_grace" json:"max_connection_age_grace"`
	KeepAliveTime           time.Duration `yaml:"keep_alive_time" json:"keep_alive_time"`
	KeepAliveTimeout        time.Duration `yaml:"keep_alive_timeout" json:"keep_alive_timeout"`
	MaxReceiveMessageSize   int           `yaml:"max_receive_message_size" json:"max_receive_message_size"`
	MaxSendMessageSize      int           `yaml:"max_send_message_size" json:"max_send_message_size"`
	MaxConcurrentStreams    uint32        `yaml:"max_concurrent_streams" json:"max_concurrent_streams"`
	
	// Middleware settings
	EnableAuth       bool `yaml:"enable_auth" json:"enable_auth"`
	EnableMetrics    bool `yaml:"enable_metrics" json:"enable_metrics"`
	EnableLogging    bool `yaml:"enable_logging" json:"enable_logging"`
	EnableRecovery   bool `yaml:"enable_recovery" json:"enable_recovery"`
	EnableReflection bool `yaml:"enable_reflection" json:"enable_reflection"`
	EnableTracing    bool `yaml:"enable_tracing" json:"enable_tracing"`
	
	// Health check settings
	EnableHealthCheck bool     `yaml:"enable_health_check" json:"enable_health_check"`
	HealthServices    []string `yaml:"health_services" json:"health_services"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
	CAFile   string `yaml:"ca_file" json:"ca_file"`
}

// Server represents a gRPC server with all cross-cutting concerns
type Server struct {
	config       *ServerConfig
	server       *grpc.Server
	listener     net.Listener
	healthServer *health.Server
	logger       *zap.Logger
	
	// Middleware components
	authFunc    grpc_auth.AuthFunc
	recoveryOpts []grpc_recovery.Option
	
	// Service registration
	services map[string]interface{}
}

// NewServer creates a new gRPC server with cross-cutting concerns
func NewServer(config *ServerConfig, logger *zap.Logger) (*Server, error) {
	if config == nil {
		return nil, fmt.Errorf("server config is required")
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	s := &Server{
		config:   config,
		logger:   logger,
		services: make(map[string]interface{}),
	}

	// Initialize server options
	serverOpts, err := s.buildServerOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to build server options: %w", err)
	}

	// Create gRPC server
	s.server = grpc.NewServer(serverOpts...)

	// Initialize health server if enabled
	if config.EnableHealthCheck {
		s.healthServer = health.NewServer()
		grpc_health_v1.RegisterHealthServer(s.server, s.healthServer)
		
		// Set default services to serving
		for _, service := range config.HealthServices {
			s.healthServer.SetServingStatus(service, grpc_health_v1.HealthCheckResponse_SERVING)
		}
		s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	}

	// Enable reflection if configured
	if config.EnableReflection {
		reflection.Register(s.server)
	}

	return s, nil
}

// buildServerOptions builds gRPC server options with middleware
func (s *Server) buildServerOptions() ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// Add connection options
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionAge:      s.config.MaxConnectionAge,
		MaxConnectionAgeGrace: s.config.MaxConnectionAgeGrace,
		Time:                  s.config.KeepAliveTime,
		Timeout:               s.config.KeepAliveTimeout,
	}))

	// Add message size limits
	if s.config.MaxReceiveMessageSize > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(s.config.MaxReceiveMessageSize))
	}
	if s.config.MaxSendMessageSize > 0 {
		opts = append(opts, grpc.MaxSendMsgSize(s.config.MaxSendMessageSize))
	}
	if s.config.MaxConcurrentStreams > 0 {
		opts = append(opts, grpc.MaxConcurrentStreams(s.config.MaxConcurrentStreams))
	}

	// Add TLS credentials if enabled
	if s.config.TLS.Enabled {
		creds, err := s.buildTLSCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// Add context tags (should be first)
	unaryInterceptors = append(unaryInterceptors, grpc_ctxtags.UnaryServerInterceptor())
	streamInterceptors = append(streamInterceptors, grpc_ctxtags.StreamServerInterceptor())

	// Add tracing if enabled
	if s.config.EnableTracing {
		tracingUnary, tracingStream := tracing.GRPCServerInterceptors()
		unaryInterceptors = append(unaryInterceptors, tracingUnary)
		streamInterceptors = append(streamInterceptors, tracingStream)
	}

	// Add logging if enabled
	if s.config.EnableLogging {
		loggingUnary, loggingStream := logging.GRPCServerInterceptors(s.logger)
		unaryInterceptors = append(unaryInterceptors, loggingUnary)
		streamInterceptors = append(streamInterceptors, loggingStream)
	}

	// Add metrics if enabled
	if s.config.EnableMetrics {
		unaryInterceptors = append(unaryInterceptors, grpc_prometheus.UnaryServerInterceptor)
		streamInterceptors = append(streamInterceptors, grpc_prometheus.StreamServerInterceptor)
	}

	// Add authentication if enabled
	if s.config.EnableAuth && s.authFunc != nil {
		unaryInterceptors = append(unaryInterceptors, grpc_auth.UnaryServerInterceptor(s.authFunc))
		streamInterceptors = append(streamInterceptors, grpc_auth.StreamServerInterceptor(s.authFunc))
	}

	// Add recovery (should be last)
	if s.config.EnableRecovery {
		recoveryOpts := s.buildRecoveryOptions()
		unaryInterceptors = append(unaryInterceptors, grpc_recovery.UnaryServerInterceptor(recoveryOpts...))
		streamInterceptors = append(streamInterceptors, grpc_recovery.StreamServerInterceptor(recoveryOpts...))
	}

	// Chain interceptors
	opts = append(opts,
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(unaryInterceptors...)),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(streamInterceptors...)),
	)

	return opts, nil
}

// buildTLSCredentials builds TLS credentials
func (s *Server) buildTLSCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}

	// Load CA file if specified
	if s.config.TLS.CAFile != "" {
		// Implementation would load CA file and set up client certificate verification
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return credentials.NewTLS(tlsConfig), nil
}

// buildRecoveryOptions builds recovery options
func (s *Server) buildRecoveryOptions() []grpc_recovery.Option {
	if len(s.recoveryOpts) > 0 {
		return s.recoveryOpts
	}

	// Default recovery function
	recoveryFunc := func(p interface{}) error {
		s.logger.Error("gRPC panic recovered",
			zap.Any("panic", p),
			zap.Stack("stack"),
		)
		return status.Errorf(codes.Internal, "Internal server error")
	}

	return []grpc_recovery.Option{
		grpc_recovery.WithRecoveryHandler(recoveryFunc),
	}
}

// SetAuthFunc sets the authentication function
func (s *Server) SetAuthFunc(authFunc grpc_auth.AuthFunc) {
	s.authFunc = authFunc
}

// SetRecoveryOptions sets custom recovery options
func (s *Server) SetRecoveryOptions(opts ...grpc_recovery.Option) {
	s.recoveryOpts = opts
}

// RegisterService registers a gRPC service
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.server.RegisterService(desc, impl)
	s.services[desc.ServiceName] = impl
	
	// Set health status for the service
	if s.healthServer != nil {
		s.healthServer.SetServingStatus(desc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	}
	
	s.logger.Info("gRPC service registered",
		zap.String("service", desc.ServiceName),
	)
}

// Start starts the gRPC server
func (s *Server) Start() error {
	address := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	
	s.listener = listener
	
	s.logger.Info("Starting gRPC server",
		zap.String("address", address),
		zap.Bool("tls", s.config.TLS.Enabled),
		zap.Bool("auth", s.config.EnableAuth),
		zap.Bool("metrics", s.config.EnableMetrics),
		zap.Bool("reflection", s.config.EnableReflection),
	)

	// Initialize metrics if enabled
	if s.config.EnableMetrics {
		grpc_prometheus.Register(s.server)
		grpc_prometheus.EnableHandlingTimeHistogram()
	}

	// Start serving
	if err := s.server.Serve(listener); err != nil {
		return fmt.Errorf("gRPC server failed: %w", err)
	}

	return nil
}

// Stop gracefully stops the gRPC server
func (s *Server) Stop() {
	s.logger.Info("Stopping gRPC server")
	
	// Mark all services as not serving
	if s.healthServer != nil {
		for service := range s.services {
			s.healthServer.SetServingStatus(service, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		}
		s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	}
	
	// Graceful stop
	s.server.GracefulStop()
}

// ForceStop forcefully stops the gRPC server
func (s *Server) ForceStop() {
	s.logger.Warn("Force stopping gRPC server")
	s.server.Stop()
}

// GetServer returns the underlying gRPC server
func (s *Server) GetServer() *grpc.Server {
	return s.server
}

// GetListener returns the listener
func (s *Server) GetListener() net.Listener {
	return s.listener
}

// SetServiceHealth sets the health status of a service
func (s *Server) SetServiceHealth(service string, serving bool) {
	if s.healthServer == nil {
		return
	}
	
	status := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if serving {
		status = grpc_health_v1.HealthCheckResponse_SERVING
	}
	
	s.healthServer.SetServingStatus(service, status)
	
	s.logger.Debug("Service health status updated",
		zap.String("service", service),
		zap.Bool("serving", serving),
	)
}

// GetMetrics returns server metrics
func (s *Server) GetMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"services_registered": len(s.services),
		"tls_enabled":         s.config.TLS.Enabled,
		"auth_enabled":        s.config.EnableAuth,
		"metrics_enabled":     s.config.EnableMetrics,
		"tracing_enabled":     s.config.EnableTracing,
		"reflection_enabled":  s.config.EnableReflection,
	}

	// Add service list
	services := make([]string, 0, len(s.services))
	for serviceName := range s.services {
		services = append(services, serviceName)
	}
	metrics["services"] = services

	return metrics
}

// DefaultServerConfig returns a default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Host: "0.0.0.0",
		Port: 9090,
		
		TLS: TLSConfig{
			Enabled: false,
		},
		
		MaxConnectionAge:      30 * time.Minute,
		MaxConnectionAgeGrace: 5 * time.Minute,
		KeepAliveTime:         30 * time.Second,
		KeepAliveTimeout:      5 * time.Second,
		MaxReceiveMessageSize: 4 * 1024 * 1024, // 4MB
		MaxSendMessageSize:    4 * 1024 * 1024, // 4MB
		MaxConcurrentStreams:  1000,
		
		EnableAuth:        true,
		EnableMetrics:     true,
		EnableLogging:     true,
		EnableRecovery:    true,
		EnableReflection:  false,
		EnableTracing:     true,
		EnableHealthCheck: true,
		
		HealthServices: []string{},
	}
}