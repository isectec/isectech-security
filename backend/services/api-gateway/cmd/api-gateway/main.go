package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/isectech/platform/services/api-gateway/config"
	"github.com/isectech/platform/services/api-gateway/delivery/http/handlers"
	"github.com/isectech/platform/services/api-gateway/delivery/http/router"
	"github.com/isectech/platform/services/api-gateway/infrastructure/cache"
	"github.com/isectech/platform/services/api-gateway/infrastructure/database"
	"github.com/isectech/platform/services/api-gateway/infrastructure/middleware"
	"github.com/isectech/platform/services/api-gateway/infrastructure/monitoring"
	"github.com/isectech/platform/services/api-gateway/usecase"
)

const (
	ServiceName = "isectech-api-gateway"
	Version     = "2.0.0"
)

// Application represents the main application
type Application struct {
	config     *config.Config
	logger     *zap.Logger
	httpServer *http.Server
	router     *gin.Engine
	
	// Dependencies
	cache       cache.Cache
	database    database.Database
	monitoring  monitoring.Monitor
	
	// Use cases
	routeUseCase *usecase.RouteUseCase
	authUseCase  *usecase.AuthUseCase
	
	// Shutdown channel
	shutdown chan os.Signal
}

func main() {
	// Initialize application
	app, err := NewApplication()
	if err != nil {
		fmt.Printf("Failed to initialize application: %v\n", err)
		os.Exit(1)
	}
	
	// Start application
	if err := app.Start(); err != nil {
		app.logger.Fatal("Failed to start application", zap.Error(err))
	}
	
	// Wait for shutdown signal
	app.WaitForShutdown()
	
	// Graceful shutdown
	if err := app.Stop(); err != nil {
		app.logger.Error("Error during shutdown", zap.Error(err))
		os.Exit(1)
	}
	
	app.logger.Info("Application stopped successfully")
}

// NewApplication creates a new application instance
func NewApplication() (*Application, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	
	// Initialize logger
	logger, err := initLogger(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	
	logger.Info("Starting iSECTECH API Gateway",
		zap.String("service", ServiceName),
		zap.String("version", Version),
		zap.String("environment", cfg.Environment),
	)
	
	// Initialize shutdown channel
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	
	app := &Application{
		config:   cfg,
		logger:   logger,
		shutdown: shutdown,
	}
	
	// Initialize dependencies
	if err := app.initDependencies(); err != nil {
		return nil, fmt.Errorf("failed to initialize dependencies: %w", err)
	}
	
	// Initialize use cases
	if err := app.initUseCases(); err != nil {
		return nil, fmt.Errorf("failed to initialize use cases: %w", err)
	}
	
	// Initialize HTTP router
	if err := app.initRouter(); err != nil {
		return nil, fmt.Errorf("failed to initialize router: %w", err)
	}
	
	// Create HTTP server
	app.httpServer = &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:        app.router,
		ReadTimeout:    time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:    time.Duration(cfg.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}
	
	return app, nil
}

// initDependencies initializes external dependencies
func (app *Application) initDependencies() error {
	var err error
	
	// Initialize cache
	app.cache, err = cache.NewRedisCache(app.config.Redis, app.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	
	// Initialize database (if needed for route storage)
	if app.config.Database.Enabled {
		app.database, err = database.NewPostgresDatabase(app.config.Database, app.logger)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
	}
	
	// Initialize monitoring
	app.monitoring, err = monitoring.NewPrometheusMonitor(app.config.Monitoring, app.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize monitoring: %w", err)
	}
	
	return nil
}

// initUseCases initializes business logic use cases
func (app *Application) initUseCases() error {
	// Initialize route use case
	app.routeUseCase = usecase.NewRouteUseCase(
		app.database,
		app.cache,
		app.logger,
	)
	
	// Initialize auth use case
	app.authUseCase = usecase.NewAuthUseCase(
		app.cache,
		app.logger,
		app.config.Auth,
	)
	
	return nil
}

// initRouter initializes the HTTP router with middleware and routes
func (app *Application) initRouter() error {
	// Set Gin mode
	if app.config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	
	// Create router
	app.router = gin.New()
	
	// Add global middleware
	app.addGlobalMiddleware()
	
	// Add routes
	app.addRoutes()
	
	return nil
}

// addGlobalMiddleware adds global middleware to the router
func (app *Application) addGlobalMiddleware() {
	// Recovery middleware
	app.router.Use(gin.Recovery())
	
	// Request ID middleware
	app.router.Use(middleware.RequestID())
	
	// Logging middleware
	app.router.Use(middleware.GinLogger(app.logger))
	
	// CORS middleware
	if app.config.CORS.Enabled {
		app.router.Use(middleware.CORS(app.config.CORS))
	}
	
	// Security headers middleware
	app.router.Use(middleware.SecurityHeaders())
	
	// Metrics middleware
	if app.config.Monitoring.Enabled {
		app.router.Use(middleware.Metrics(app.monitoring))
	}
	
	// Tracing middleware
	if app.config.Tracing.Enabled {
		app.router.Use(middleware.Tracing(app.config.Tracing))
	}
	
	// Rate limiting middleware (global)
	if app.config.RateLimit.Enabled {
		rateLimiter := middleware.NewRateLimiter(app.cache, app.logger)
		app.router.Use(rateLimiter.GlobalRateLimit(app.config.RateLimit))
	}
}

// addRoutes adds all routes to the router
func (app *Application) addRoutes() {
	// Health check routes (no authentication required)
	health := app.router.Group("/health")
	{
		healthHandler := handlers.NewHealthHandler(app.logger, app.cache, app.database)
		health.GET("", healthHandler.Health)
		health.GET("/live", healthHandler.Liveness)
		health.GET("/ready", healthHandler.Readiness)
	}
	
	// Metrics endpoint (Prometheus)
	if app.config.Monitoring.Enabled {
		app.router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	}
	
	// API routes
	api := app.router.Group("/api")
	
	// Add authentication middleware for API routes
	authMiddleware := middleware.NewAuthMiddleware(app.logger)
	if err := app.configureAuthMiddleware(authMiddleware); err != nil {
		app.logger.Error("Failed to configure auth middleware", zap.Error(err))
	}
	
	// Gateway management routes (admin only)
	admin := api.Group("/admin")
	admin.Use(authMiddleware.RequireRole("admin"))
	{
		routeHandler := handlers.NewRouteHandler(app.routeUseCase, app.logger)
		admin.GET("/routes", routeHandler.ListRoutes)
		admin.POST("/routes", routeHandler.CreateRoute)
		admin.GET("/routes/:id", routeHandler.GetRoute)
		admin.PUT("/routes/:id", routeHandler.UpdateRoute)
		admin.DELETE("/routes/:id", routeHandler.DeleteRoute)
		admin.POST("/routes/:id/enable", routeHandler.EnableRoute)
		admin.POST("/routes/:id/disable", routeHandler.DisableRoute)
	}
	
	// Gateway status and information
	status := api.Group("/status")
	{
		statusHandler := handlers.NewStatusHandler(app.logger, app.monitoring)
		status.GET("", statusHandler.GetStatus)
		status.GET("/stats", statusHandler.GetStats)
		status.GET("/version", statusHandler.GetVersion)
	}
	
	// Dynamic route proxy (main gateway functionality)
	// This catches all other routes and proxies them based on configuration
	app.router.NoRoute(handlers.NewProxyHandler(
		app.routeUseCase,
		app.authUseCase,
		app.monitoring,
		app.logger,
	).HandleProxy)
}

// configureAuthMiddleware configures the authentication middleware
func (app *Application) configureAuthMiddleware(authMiddleware *middleware.AuthMiddleware) error {
	// Set JWT configuration
	if app.config.Auth.JWT.Enabled {
		if app.config.Auth.JWT.Secret != "" {
			authMiddleware.SetJWTSecret([]byte(app.config.Auth.JWT.Secret))
		}
		
		if app.config.Auth.JWT.PublicKey != "" {
			if err := authMiddleware.SetJWTPublicKey([]byte(app.config.Auth.JWT.PublicKey)); err != nil {
				return fmt.Errorf("failed to set JWT public key: %w", err)
			}
		}
	}
	
	// Load API keys from configuration or database
	if app.config.Auth.APIKey.Enabled {
		// This would typically load from database or configuration
		// For now, adding a sample API key
		sampleAPIKey := &middleware.APIKeyInfo{
			Key:     "isectech-api-key-example",
			Name:    "Sample API Key",
			UserID:  "system",
			Roles:   []string{"admin"},
			Scopes:  []string{"read", "write"},
			Enabled: true,
		}
		authMiddleware.AddAPIKey(sampleAPIKey)
	}
	
	return nil
}

// Start starts the application
func (app *Application) Start() error {
	app.logger.Info("Starting HTTP server",
		zap.String("address", app.httpServer.Addr),
		zap.String("environment", app.config.Environment),
	)
	
	// Start server in a goroutine
	go func() {
		if err := app.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.Fatal("HTTP server error", zap.Error(err))
		}
	}()
	
	app.logger.Info("iSECTECH API Gateway started successfully",
		zap.String("address", app.httpServer.Addr),
		zap.String("service", ServiceName),
		zap.String("version", Version),
	)
	
	return nil
}

// WaitForShutdown waits for shutdown signal
func (app *Application) WaitForShutdown() {
	<-app.shutdown
	app.logger.Info("Shutdown signal received")
}

// Stop gracefully stops the application
func (app *Application) Stop() error {
	app.logger.Info("Shutting down application...")
	
	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Shutdown HTTP server
	if err := app.httpServer.Shutdown(ctx); err != nil {
		app.logger.Error("HTTP server shutdown error", zap.Error(err))
		return err
	}
	
	// Close cache connection
	if app.cache != nil {
		if err := app.cache.Close(); err != nil {
			app.logger.Error("Cache close error", zap.Error(err))
		}
	}
	
	// Close database connection
	if app.database != nil {
		if err := app.database.Close(); err != nil {
			app.logger.Error("Database close error", zap.Error(err))
		}
	}
	
	// Close monitoring
	if app.monitoring != nil {
		if err := app.monitoring.Close(); err != nil {
			app.logger.Error("Monitoring close error", zap.Error(err))
		}
	}
	
	return nil
}

// initLogger initializes the logger
func initLogger(cfg *config.Config) (*zap.Logger, error) {
	var zapConfig zap.Config
	
	if cfg.Environment == "production" {
		zapConfig = zap.NewProductionConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	} else {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	}
	
	// Set log level from configuration
	if cfg.Logging.Level != "" {
		var level zapcore.Level
		if err := level.UnmarshalText([]byte(cfg.Logging.Level)); err == nil {
			zapConfig.Level = zap.NewAtomicLevelAt(level)
		}
	}
	
	// Add service information to logger
	zapConfig.InitialFields = map[string]interface{}{
		"service":     ServiceName,
		"version":     Version,
		"environment": cfg.Environment,
	}
	
	// Set output format
	if cfg.Logging.Format == "json" {
		zapConfig.Encoding = "json"
	} else {
		zapConfig.Encoding = "console"
	}
	
	return zapConfig.Build()
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Health check information
func (app *Application) GetHealthInfo() map[string]interface{} {
	return map[string]interface{}{
		"service":     ServiceName,
		"version":     Version,
		"environment": app.config.Environment,
		"uptime":      time.Since(time.Now()).String(), // This would be calculated from start time
		"status":      "healthy",
	}
}