package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/usecase"
)

// RouterConfig holds HTTP router configuration
type RouterConfig struct {
	// Server settings
	Host            string        `yaml:"host" default:"0.0.0.0"`
	Port            int           `yaml:"port" default:"8080"`
	ReadTimeout     time.Duration `yaml:"read_timeout" default:"30s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" default:"30s"`
	IdleTimeout     time.Duration `yaml:"idle_timeout" default:"60s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" default:"30s"`
	
	// TLS settings
	EnableTLS   bool   `yaml:"enable_tls" default:"false"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	
	// Server behavior
	EnablePprof     bool `yaml:"enable_pprof" default:"false"`
	EnableSwagger   bool `yaml:"enable_swagger" default:"false"`
	TrustedProxies  []string `yaml:"trusted_proxies"`
	
	// API settings
	APIPrefix       string `yaml:"api_prefix" default:"/api/v1"`
	EnableAPIMetrics bool   `yaml:"enable_api_metrics" default:"true"`
}

// HTTPServer represents the HTTP server
type HTTPServer struct {
	server         *http.Server
	router         *gin.Engine
	handlers       *AuthHandlers
	middleware     *MiddlewareManager
	config         *RouterConfig
	serviceManager *usecase.ServiceManager
}

// NewHTTPServer creates a new HTTP server
func NewHTTPServer(
	serviceManager *usecase.ServiceManager,
	middlewareConfig *MiddlewareConfig,
	routerConfig *RouterConfig,
) *HTTPServer {
	// Create handlers
	handlers := NewAuthHandlers(serviceManager)
	
	// Create middleware manager
	middleware := NewMiddlewareManager(
		serviceManager.GetSessionService(),
		serviceManager.GetAuthService(),
		middlewareConfig,
	)

	// Set Gin mode
	if routerConfig.EnablePprof {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()

	httpServer := &HTTPServer{
		router:         router,
		handlers:       handlers,
		middleware:     middleware,
		config:         routerConfig,
		serviceManager: serviceManager,
	}

	// Setup middleware and routes
	httpServer.setupMiddleware()
	httpServer.setupRoutes()

	// Create HTTP server
	httpServer.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", routerConfig.Host, routerConfig.Port),
		Handler:      router,
		ReadTimeout:  routerConfig.ReadTimeout,
		WriteTimeout: routerConfig.WriteTimeout,
		IdleTimeout:  routerConfig.IdleTimeout,
	}

	// Set trusted proxies
	if len(routerConfig.TrustedProxies) > 0 {
		router.SetTrustedProxies(routerConfig.TrustedProxies)
	}

	return httpServer
}

// setupMiddleware configures global middleware
func (s *HTTPServer) setupMiddleware() {
	// Recovery middleware
	s.router.Use(s.middleware.ErrorHandler())
	
	// Request ID middleware
	s.router.Use(s.middleware.RequestID())
	
	// Logger middleware
	s.router.Use(s.middleware.RequestLogger())
	
	// Security headers
	s.router.Use(s.middleware.SecurityHeaders())
	
	// CORS middleware
	s.router.Use(s.middleware.CORS())
	
	// Client info extraction
	s.router.Use(s.middleware.ExtractClientInfo())
	
	// Request timeout
	s.router.Use(s.middleware.RequestTimeout())
}

// setupRoutes configures all API routes
func (s *HTTPServer) setupRoutes() {
	// Health check endpoints (no auth required)
	s.router.GET("/health", s.handlers.HealthCheck)
	s.router.GET("/metrics", s.handlers.GetMetrics)

	// API version group
	api := s.router.Group(s.config.APIPrefix)
	
	// Public endpoints (no authentication required)
	public := api.Group("/auth")
	{
		// Authentication endpoints
		public.POST("/login", s.handlers.Login)
		public.POST("/mfa/verify", s.handlers.VerifyMFA)
		public.POST("/refresh", s.handlers.RefreshToken)
		public.POST("/validate", s.handlers.ValidateSession)
		
		// Password management
		public.POST("/password/reset", s.handlers.RequestPasswordReset)
		public.POST("/password/reset/complete", s.handlers.CompletePasswordReset)
		public.POST("/password/validate", s.handlers.ValidatePasswordStrength)
	}

	// Protected endpoints (authentication required)
	protected := api.Group("/auth")
	protected.Use(s.middleware.AuthenticationRequired())
	protected.Use(s.middleware.TenantIsolation())
	{
		// User session management
		protected.POST("/logout", s.handlers.Logout)
		protected.GET("/profile", s.handlers.GetUserProfile)
		protected.GET("/sessions", s.handlers.GetUserSessions)
		protected.DELETE("/sessions/:session_id", s.handlers.TerminateSession)
		
		// Password management (authenticated)
		protected.POST("/password/change", s.handlers.ChangePassword)
		
		// MFA management
		mfa := protected.Group("/mfa")
		{
			mfa.GET("/devices", s.handlers.GetUserMFADevices)
			mfa.POST("/enroll", s.handlers.EnrollMFADevice)
			// Additional MFA endpoints would go here
		}
	}

	// Admin endpoints (require admin role and high security clearance)
	admin := api.Group("/admin")
	admin.Use(s.middleware.AuthenticationRequired())
	admin.Use(s.middleware.RequireSecurityClearance(entity.SecurityClearanceSecret))
	admin.Use(s.middleware.RequireRole("admin"))
	admin.Use(s.middleware.RequireMFA())
	{
		// User management
		users := admin.Group("/users")
		{
			users.GET("", s.handlers.ListUsers)
			users.POST("", s.handlers.CreateUser)
			users.GET("/:user_id", s.handlers.GetUser)
			users.PUT("/:user_id", s.handlers.UpdateUser)
			users.DELETE("/:user_id", s.handlers.DeleteUser)
			users.POST("/:user_id/lock", s.handlers.LockUser)
			users.POST("/:user_id/unlock", s.handlers.UnlockUser)
			users.POST("/:user_id/reset-mfa", s.handlers.ResetUserMFA)
		}
		
		// Session management
		sessions := admin.Group("/sessions")
		{
			sessions.GET("", s.handlers.ListSessions)
			sessions.DELETE("/:session_id", s.handlers.TerminateSession)
			sessions.DELETE("/user/:user_id", s.handlers.TerminateUserSessions)
		}
		
		// Audit logs
		audit := admin.Group("/audit")
		{
			audit.GET("/events", s.handlers.GetAuditEvents)
			audit.GET("/metrics", s.handlers.GetAuditMetrics)
		}
		
		// System management
		system := admin.Group("/system")
		{
			system.GET("/health", s.handlers.GetSystemHealth)
			system.POST("/maintenance", s.handlers.TriggerMaintenance)
		}
	}

	// Security Officer endpoints (require top secret clearance)
	security := api.Group("/security")
	security.Use(s.middleware.AuthenticationRequired())
	security.Use(s.middleware.RequireSecurityClearance(entity.SecurityClearanceTopSecret))
	security.Use(s.middleware.RequireRole("security_officer"))
	security.Use(s.middleware.RequireMFA())
	{
		// Security monitoring
		security.GET("/alerts", s.handlers.GetSecurityAlerts)
		security.GET("/threats", s.handlers.GetThreatIntelligence)
		security.POST("/incidents", s.handlers.CreateSecurityIncident)
		
		// Advanced audit
		security.GET("/audit/export", s.handlers.ExportAuditLogs)
		security.GET("/compliance/report", s.handlers.GenerateComplianceReport)
	}

	// Development endpoints (only in debug mode)
	if s.config.EnablePprof {
		s.setupDebugRoutes()
	}

	// API documentation (if enabled)
	if s.config.EnableSwagger {
		s.setupSwaggerRoutes()
	}
}

// setupDebugRoutes adds debug and profiling endpoints
func (s *HTTPServer) setupDebugRoutes() {
	debug := s.router.Group("/debug")
	debug.Use(s.middleware.AuthenticationRequired())
	debug.Use(s.middleware.RequireRole("developer"))
	{
		// Add pprof endpoints
		debug.GET("/pprof/*action", gin.WrapH(http.DefaultServeMux))
		
		// Custom debug endpoints
		debug.GET("/config", s.handlers.GetDebugConfig)
		debug.GET("/stats", s.handlers.GetDebugStats)
	}
}

// setupSwaggerRoutes adds API documentation endpoints
func (s *HTTPServer) setupSwaggerRoutes() {
	docs := s.router.Group("/docs")
	{
		docs.GET("/", s.handlers.ServeSwaggerUI)
		docs.GET("/swagger.json", s.handlers.ServeSwaggerSpec)
	}
}

// Start starts the HTTP server
func (s *HTTPServer) Start(ctx context.Context) error {
	// Start service manager
	if err := s.serviceManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start service manager: %w", err)
	}

	// Start HTTP server
	go func() {
		var err error
		if s.config.EnableTLS {
			err = s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.server.ListenAndServe()
		}
		
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	fmt.Printf("HTTP server starting on %s\n", s.server.Addr)
	return nil
}

// Stop gracefully stops the HTTP server
func (s *HTTPServer) Stop(ctx context.Context) error {
	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, s.config.ShutdownTimeout)
	defer cancel()

	// Shutdown HTTP server
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("HTTP server shutdown failed: %w", err)
	}

	// Stop service manager
	if err := s.serviceManager.Stop(ctx); err != nil {
		return fmt.Errorf("service manager shutdown failed: %w", err)
	}

	fmt.Println("HTTP server stopped gracefully")
	return nil
}

// GetAddress returns the server address
func (s *HTTPServer) GetAddress() string {
	return s.server.Addr
}

// Handler placeholder implementations for admin and security endpoints
// These would be implemented as needed

func (h *AuthHandlers) ListUsers(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User listing not yet implemented",
	})
}

func (h *AuthHandlers) CreateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User creation not yet implemented",
	})
}

func (h *AuthHandlers) GetUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User retrieval not yet implemented",
	})
}

func (h *AuthHandlers) UpdateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User update not yet implemented",
	})
}

func (h *AuthHandlers) DeleteUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User deletion not yet implemented",
	})
}

func (h *AuthHandlers) LockUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User locking not yet implemented",
	})
}

func (h *AuthHandlers) UnlockUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User unlocking not yet implemented",
	})
}

func (h *AuthHandlers) ResetUserMFA(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "MFA reset not yet implemented",
	})
}

func (h *AuthHandlers) ListSessions(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Session listing not yet implemented",
	})
}

func (h *AuthHandlers) TerminateUserSessions(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "User session termination not yet implemented",
	})
}

func (h *AuthHandlers) GetAuditEvents(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Audit events not yet implemented",
	})
}

func (h *AuthHandlers) GetAuditMetrics(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Audit metrics not yet implemented",
	})
}

func (h *AuthHandlers) GetSystemHealth(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "System health not yet implemented",
	})
}

func (h *AuthHandlers) TriggerMaintenance(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Maintenance trigger not yet implemented",
	})
}

func (h *AuthHandlers) GetSecurityAlerts(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Security alerts not yet implemented",
	})
}

func (h *AuthHandlers) GetThreatIntelligence(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Threat intelligence not yet implemented",
	})
}

func (h *AuthHandlers) CreateSecurityIncident(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Security incident creation not yet implemented",
	})
}

func (h *AuthHandlers) ExportAuditLogs(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Audit log export not yet implemented",
	})
}

func (h *AuthHandlers) GenerateComplianceReport(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Compliance report not yet implemented",
	})
}

func (h *AuthHandlers) GetDebugConfig(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Debug config not yet implemented",
	})
}

func (h *AuthHandlers) GetDebugStats(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Debug stats not yet implemented",
	})
}

func (h *AuthHandlers) ServeSwaggerUI(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Swagger UI not yet implemented",
	})
}

func (h *AuthHandlers) ServeSwaggerSpec(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error:   "not_implemented",
		Message: "Swagger spec not yet implemented",
	})
}