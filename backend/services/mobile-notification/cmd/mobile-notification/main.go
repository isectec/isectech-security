package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"mobile-notification/config"
	"mobile-notification/infrastructure/batching"
	"mobile-notification/infrastructure/database"
	"mobile-notification/infrastructure/priority"
	"mobile-notification/infrastructure/push"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// Application represents the main application
type Application struct {
	config          *config.Config
	logger          *logrus.Logger
	db              *sql.DB
	redis           *redis.Client
	pushService     *push.PushService
	batchingService *batching.BatchingService
	priorityService *priority.PriorityService
	server          *http.Server
}

func main() {
	// Parse command line flags
	var configPath = flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid config: %v\n", err)
		os.Exit(1)
	}

	// Create application
	app, err := NewApplication(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create application: %v\n", err)
		os.Exit(1)
	}

	// Start application
	if err := app.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start application: %v\n", err)
		os.Exit(1)
	}

	// Wait for shutdown signal
	app.WaitForShutdown()
}

// NewApplication creates a new application instance
func NewApplication(cfg *config.Config) (*Application, error) {
	app := &Application{
		config: cfg,
	}

	// Setup logger
	if err := app.setupLogger(); err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	app.logger.Info("Starting Mobile Notification Service")

	// Setup database
	if err := app.setupDatabase(); err != nil {
		return nil, fmt.Errorf("failed to setup database: %w", err)
	}

	// Setup Redis
	if err := app.setupRedis(); err != nil {
		return nil, fmt.Errorf("failed to setup Redis: %w", err)
	}

	// Setup services
	if err := app.setupServices(); err != nil {
		return nil, fmt.Errorf("failed to setup services: %w", err)
	}

	// Setup HTTP server
	if err := app.setupServer(); err != nil {
		return nil, fmt.Errorf("failed to setup server: %w", err)
	}

	return app, nil
}

// setupLogger configures the logger
func (app *Application) setupLogger() error {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(app.config.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set log format
	if app.config.Logging.Structured {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	// Set output
	if app.config.Logging.Output != "" && app.config.Logging.Output != "stdout" {
		file, err := os.OpenFile(app.config.Logging.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		logger.SetOutput(file)
	}

	app.logger = logger
	return nil
}

// setupDatabase configures the database connection
func (app *Application) setupDatabase() error {
	db, err := sql.Open("postgres", app.config.GetDSN())
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(app.config.Database.MaxOpenConns)
	db.SetMaxIdleConns(app.config.Database.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(app.config.Database.ConnMaxLifetime) * time.Second)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	app.db = db
	app.logger.Info("Database connection established")
	return nil
}

// setupRedis configures the Redis connection
func (app *Application) setupRedis() error {
	rdb := redis.NewClient(&redis.Options{
		Addr:         app.config.GetRedisAddr(),
		Password:     app.config.Redis.Password,
		DB:           app.config.Redis.Database,
		PoolSize:     app.config.Redis.PoolSize,
		MinIdleConns: app.config.Redis.MinIdleConns,
		MaxRetries:   app.config.Redis.MaxRetries,
		DialTimeout:  time.Duration(app.config.Redis.DialTimeout) * time.Second,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to ping Redis: %w", err)
	}

	app.redis = rdb
	app.logger.Info("Redis connection established")
	return nil
}

// setupServices initializes all application services
func (app *Application) setupServices() error {
	// Create repositories
	notificationRepo := database.NewPostgresNotificationRepository(app.db, app.logger)
	
	// Create push service
	pushService, err := push.NewPushService(app.config.Push, app.logger)
	if err != nil {
		return fmt.Errorf("failed to create push service: %w", err)
	}
	app.pushService = pushService

	// Create priority service
	// Note: We'd need to create device registration and preferences repositories
	// For now, we'll use placeholder implementations
	app.priorityService = priority.NewPriorityService(
		notificationRepo,
		nil, // preferences repo - needs implementation
		app.logger,
		app.config.Priority,
	)

	// Create batching service
	app.batchingService = batching.NewBatchingService(
		notificationRepo,
		nil, // batch repo - needs implementation
		nil, // preferences repo - needs implementation
		app.logger,
		app.config.Batching,
	)

	app.logger.Info("All services initialized successfully")
	return nil
}

// setupServer configures the HTTP server
func (app *Application) setupServer() error {
	router := mux.NewRouter()

	// Health check endpoints
	router.HandleFunc("/health", app.healthHandler).Methods("GET")
	router.HandleFunc("/ready", app.readyHandler).Methods("GET")

	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	
	// Notification endpoints
	api.HandleFunc("/notifications", app.createNotificationHandler).Methods("POST")
	api.HandleFunc("/notifications/{id}", app.getNotificationHandler).Methods("GET")
	api.HandleFunc("/notifications", app.listNotificationsHandler).Methods("GET")
	api.HandleFunc("/notifications/{id}/status", app.updateNotificationStatusHandler).Methods("PUT")
	
	// Device registration endpoints
	api.HandleFunc("/devices", app.registerDeviceHandler).Methods("POST")
	api.HandleFunc("/devices/{token}", app.unregisterDeviceHandler).Methods("DELETE")
	api.HandleFunc("/devices", app.listDevicesHandler).Methods("GET")
	
	// Template endpoints
	api.HandleFunc("/templates", app.createTemplateHandler).Methods("POST")
	api.HandleFunc("/templates", app.listTemplatesHandler).Methods("GET")
	api.HandleFunc("/templates/{id}", app.getTemplateHandler).Methods("GET")
	
	// Batch endpoints
	api.HandleFunc("/batches", app.createBatchHandler).Methods("POST")
	api.HandleFunc("/batches/{id}", app.getBatchStatusHandler).Methods("GET")
	
	// Analytics endpoints
	api.HandleFunc("/analytics", app.getAnalyticsHandler).Methods("GET")
	api.HandleFunc("/metrics", app.getMetricsHandler).Methods("GET")

	// Setup middleware
	router.Use(app.loggingMiddleware)
	router.Use(app.corsMiddleware)
	
	if app.config.Security.EnableRateLimit {
		router.Use(app.rateLimitMiddleware)
	}

	// Create server
	app.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", app.config.Server.Host, app.config.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(app.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(app.config.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(app.config.Server.IdleTimeout) * time.Second,
	}

	return nil
}

// Start starts the application
func (app *Application) Start() error {
	ctx := context.Background()

	// Start batching service
	app.batchingService.Start(ctx)

	// Start HTTP server
	go func() {
		app.logger.WithField("address", app.server.Addr).Info("Starting HTTP server")
		if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			app.logger.WithError(err).Fatal("HTTP server failed")
		}
	}()

	app.logger.Info("Application started successfully")
	return nil
}

// WaitForShutdown waits for shutdown signals and performs graceful shutdown
func (app *Application) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	app.logger.WithField("signal", sig).Info("Received shutdown signal")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 
		time.Duration(app.config.Server.ShutdownTimeout)*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := app.server.Shutdown(ctx); err != nil {
		app.logger.WithError(err).Error("HTTP server shutdown error")
	}

	// Stop batching service
	app.batchingService.Stop()

	// Close database connection
	if app.db != nil {
		if err := app.db.Close(); err != nil {
			app.logger.WithError(err).Error("Database close error")
		}
	}

	// Close Redis connection
	if app.redis != nil {
		if err := app.redis.Close(); err != nil {
			app.logger.WithError(err).Error("Redis close error")
		}
	}

	app.logger.Info("Application shutdown complete")
}

// HTTP Handlers

func (app *Application) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"mobile-notification"}`))
}

func (app *Application) readyHandler(w http.ResponseWriter, r *http.Request) {
	// Check if all dependencies are ready
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check database
	if err := app.db.PingContext(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"ready":false,"reason":"database_unavailable"}`))
		return
	}

	// Check Redis
	if err := app.redis.Ping(ctx).Err(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"ready":false,"reason":"redis_unavailable"}`))
		return
	}

	// Check push services
	if err := app.pushService.IsHealthy(ctx); err != nil {
		app.logger.WithError(err).Warn("Push service health check failed")
		// Don't fail readiness check for push service issues
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ready":true}`))
}

// Placeholder handlers - these would be fully implemented in a real service
func (app *Application) createNotificationHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) getNotificationHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) listNotificationsHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) updateNotificationStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) registerDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) unregisterDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) listDevicesHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) createTemplateHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) listTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) getTemplateHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) createBatchHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) getBatchStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) getAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

func (app *Application) getMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"not_implemented"}`))
}

// Middleware

func (app *Application) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Call next handler
		next.ServeHTTP(w, r)
		
		// Log request
		app.logger.WithFields(logrus.Fields{
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote_addr": r.RemoteAddr,
			"user_agent": r.UserAgent(),
			"duration":   time.Since(start),
		}).Info("HTTP request")
	})
}

func (app *Application) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (app *Application) rateLimitMiddleware(next http.Handler) http.Handler {
	// This is a placeholder - in a real implementation you'd use a proper rate limiter
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple rate limiting logic would go here
		next.ServeHTTP(w, r)
	})
}