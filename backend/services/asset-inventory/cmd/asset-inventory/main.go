// iSECTECH Asset Inventory Service - Main Entry Point
// Production-grade asset inventory and classification service
// Copyright (c) 2024 iSECTECH. All rights reserved.

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/isectech/backend/services/asset-inventory/config"
	"github.com/isectech/backend/services/asset-inventory/domain/repository"
	"github.com/isectech/backend/services/asset-inventory/domain/service"
	"github.com/isectech/backend/services/asset-inventory/infrastructure/database"
	"github.com/isectech/backend/services/asset-inventory/usecase"
)

// Version information (set by build)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	logger.WithFields(logrus.Fields{
		"service":    "asset-inventory",
		"version":    Version,
		"git_commit": GitCommit,
		"build_time": BuildTime,
	}).Info("Starting iSECTECH Asset Inventory Service")

	// Load configuration
	cfg, err := loadConfiguration()
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Set log level
	if level, err := logrus.ParseLevel(cfg.LogLevel); err == nil {
		logger.SetLevel(level)
	}

	logger.WithFields(logrus.Fields{
		"log_level":       cfg.LogLevel,
		"server_port":     cfg.Server.Port,
		"database_host":   cfg.Database.Host,
		"metrics_enabled": cfg.Metrics.Enabled,
	}).Info("Configuration loaded")

	// Initialize database repository
	dbConnectionString := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	assetRepo, err := database.NewPostgreSQLAssetRepository(
		dbConnectionString,
		cfg.Repository,
		logger,
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize asset repository")
	}

	// Initialize domain services
	classificationService := service.NewAssetClassificationService(logger)
	discoveryService := service.NewAssetDiscoveryService(logger)

	// Initialize use cases
	assetUseCase := usecase.NewAssetUseCase(assetRepo, classificationService, discoveryService, logger)
	inventoryUseCase := usecase.NewInventoryUseCase(assetRepo, discoveryService, logger)
	discoveryUseCase := usecase.NewDiscoveryUseCase(discoveryService, assetRepo, logger)

	// Initialize HTTP server
	router := setupRoutes(assetUseCase, inventoryUseCase, discoveryUseCase, logger)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		logger.WithField("port", cfg.Server.Port).Info("Starting HTTP server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("HTTP server failed")
		}
	}()

	// Start background services
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start discovery scheduler if enabled
	if cfg.Discovery.SchedulerEnabled {
		go startDiscoveryScheduler(ctx, discoveryUseCase, cfg, logger)
	}

	// Start maintenance scheduler if enabled
	if cfg.Maintenance.Enabled {
		go startMaintenanceScheduler(ctx, assetRepo, cfg, logger)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	logger.WithField("signal", sig.String()).Info("Received shutdown signal")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("Server shutdown failed")
	}

	// Cancel background services
	cancel()

	logger.Info("iSECTECH Asset Inventory Service stopped")
}

func loadConfiguration() (*config.Configuration, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/isectech/asset-inventory")

	// Environment variable support
	viper.SetEnvPrefix("ASSET_INVENTORY")
	viper.AutomaticEnv()

	// Set defaults
	setConfigDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults
			logrus.Warn("Configuration file not found, using defaults")
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var cfg config.Configuration
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode configuration: %w", err)
	}

	return &cfg, nil
}

func setConfigDefaults() {
	// Server defaults
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "60s")

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "")
	viper.SetDefault("database.name", "asset_inventory")
	viper.SetDefault("database.ssl_mode", "require")

	// Repository defaults
	viper.SetDefault("repository.max_connections", 25)
	viper.SetDefault("repository.max_idle_connections", 5)
	viper.SetDefault("repository.connection_lifetime", "5m")
	viper.SetDefault("repository.query_timeout", "30s")
	viper.SetDefault("repository.enable_query_logging", false)
	viper.SetDefault("repository.enable_metrics", true)

	// Logging defaults
	viper.SetDefault("log_level", "info")

	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.port", 9090)
	viper.SetDefault("metrics.path", "/metrics")

	// Discovery defaults
	viper.SetDefault("discovery.scheduler_enabled", true)
	viper.SetDefault("discovery.heartbeat_interval", "5m")
	viper.SetDefault("discovery.offline_threshold", "15m")

	// Maintenance defaults
	viper.SetDefault("maintenance.enabled", true)
	viper.SetDefault("maintenance.schedule", "0 2 * * *")
}

func setupRoutes(
	assetUseCase *usecase.AssetUseCase,
	inventoryUseCase *usecase.InventoryUseCase,
	discoveryUseCase *usecase.DiscoveryUseCase,
	logger *logrus.Logger,
) *mux.Router {
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"asset-inventory"}`))
	}).Methods("GET")

	// Version endpoint
	router.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"version":"%s","git_commit":"%s","build_time":"%s"}`, Version, GitCommit, BuildTime)
		w.Write([]byte(response))
	}).Methods("GET")

	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()

	// Asset management endpoints
	setupAssetRoutes(api, assetUseCase, logger)

	// Inventory management endpoints
	setupInventoryRoutes(api, inventoryUseCase, logger)

	// Discovery management endpoints
	setupDiscoveryRoutes(api, discoveryUseCase, logger)

	// Add middleware
	router.Use(loggingMiddleware(logger))
	router.Use(corsMiddleware())
	router.Use(securityHeadersMiddleware())

	return router
}

func setupAssetRoutes(router *mux.Router, useCase *usecase.AssetUseCase, logger *logrus.Logger) {
	assets := router.PathPrefix("/assets").Subrouter()

	// TODO: Implement HTTP handlers for asset management
	// These would handle:
	// - GET /assets - List assets with filtering
	// - GET /assets/{id} - Get specific asset
	// - POST /assets - Create new asset
	// - PUT /assets/{id} - Update asset
	// - DELETE /assets/{id} - Delete asset
	// - GET /assets/search - Search assets
	// - POST /assets/classify/{id} - Classify asset
	// - GET /assets/statistics - Get asset statistics

	assets.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Asset management endpoints - TODO: Implement handlers"}`))
	}).Methods("GET")
}

func setupInventoryRoutes(router *mux.Router, useCase *usecase.InventoryUseCase, logger *logrus.Logger) {
	inventory := router.PathPrefix("/inventory").Subrouter()

	// TODO: Implement HTTP handlers for inventory management
	// These would handle:
	// - GET /inventory/summary - Get inventory summary
	// - GET /inventory/reports - Get inventory reports
	// - POST /inventory/import - Import asset data
	// - GET /inventory/export - Export asset data
	// - GET /inventory/compliance - Get compliance status

	inventory.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Inventory management endpoints - TODO: Implement handlers"}`))
	}).Methods("GET")
}

func setupDiscoveryRoutes(router *mux.Router, useCase *usecase.DiscoveryUseCase, logger *logrus.Logger) {
	discovery := router.PathPrefix("/discovery").Subrouter()

	// TODO: Implement HTTP handlers for discovery management
	// These would handle:
	// - POST /discovery/start - Start discovery session
	// - GET /discovery/sessions - List discovery sessions
	// - GET /discovery/sessions/{id} - Get discovery session
	// - DELETE /discovery/sessions/{id} - Cancel discovery session
	// - POST /discovery/heartbeat - Process agent heartbeat

	discovery.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Discovery management endpoints - TODO: Implement handlers"}`))
	}).Methods("GET")
}

func startDiscoveryScheduler(ctx context.Context, discoveryUseCase *usecase.DiscoveryUseCase, cfg *config.Configuration, logger *logrus.Logger) {
	logger.Info("Starting discovery scheduler")

	ticker := time.NewTicker(cfg.Discovery.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Discovery scheduler stopped")
			return
		case <-ticker.C:
			// TODO: Implement scheduled discovery logic
			logger.Debug("Discovery scheduler tick - TODO: Implement scheduled discovery")
		}
	}
}

func startMaintenanceScheduler(ctx context.Context, assetRepo repository.AssetRepository, cfg *config.Configuration, logger *logrus.Logger) {
	logger.Info("Starting maintenance scheduler")

	ticker := time.NewTicker(24 * time.Hour) // Daily maintenance
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Maintenance scheduler stopped")
			return
		case <-ticker.C:
			logger.Info("Running maintenance tasks")
			if err := assetRepo.RunMaintenance(ctx); err != nil {
				logger.WithError(err).Error("Maintenance tasks failed")
			} else {
				logger.Info("Maintenance tasks completed")
			}
		}
	}
}

// Middleware functions

func loggingMiddleware(logger *logrus.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create response writer wrapper to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			logger.WithFields(logrus.Fields{
				"method":      r.Method,
				"path":        r.URL.Path,
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
				"status_code": wrapped.statusCode,
				"duration_ms": duration.Milliseconds(),
			}).Info("HTTP request processed")
		})
	}
}

func corsMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func securityHeadersMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
