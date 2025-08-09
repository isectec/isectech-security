package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"asset-discovery/config"
	"asset-discovery/delivery/grpc"
	httpdelivery "asset-discovery/delivery/http"
	"asset-discovery/infrastructure/cache"
	"asset-discovery/infrastructure/database"
	"asset-discovery/infrastructure/external"
	"asset-discovery/usecase"
)

const (
	serviceName = "asset-discovery"
	version     = "1.0.0"
)

// Application represents the main application
type Application struct {
	config *config.Config
	logger *zap.Logger

	// Database connections
	postgres *sqlx.DB
	redis    *redis.Client

	// Cache
	cache *cache.RedisCache

	// Repositories
	assetRepo repository.AssetRepository

	// Services
	networkScanner      service.NetworkScannerService
	enrichmentService   service.AssetEnrichmentService
	assetDiscoveryUC    *usecase.AssetDiscoveryUseCase

	// Servers
	httpServer *httpdelivery.AssetDiscoveryHTTPServer
	grpcServer *grpc.Server

	// Metrics
	metrics *prometheus.Registry

	// Graceful shutdown
	shutdownCh chan os.Signal
	wg         sync.WaitGroup
}

func main() {
	// Create application instance
	app := &Application{
		shutdownCh: make(chan os.Signal, 1),
	}

	// Initialize application
	if err := app.Initialize(); err != nil {
		fmt.Printf("Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// Start application
	if err := app.Start(); err != nil {
		app.logger.Fatal("Failed to start application", zap.Error(err))
	}

	// Wait for shutdown signal
	app.WaitForShutdown()

	// Shutdown application
	if err := app.Shutdown(); err != nil {
		app.logger.Error("Error during shutdown", zap.Error(err))
		os.Exit(1)
	}

	app.logger.Info("Application shutdown complete")
}

// Initialize initializes all application components
func (app *Application) Initialize() error {
	var err error

	// Load configuration
	app.config, err = config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	if err := app.initLogger(); err != nil {
		return fmt.Errorf("failed to init logger: %w", err)
	}

	app.logger.Info("Starting Asset Discovery Service",
		zap.String("service", serviceName),
		zap.String("version", version),
		zap.String("environment", app.config.Service.Environment),
	)

	// Initialize databases
	if err := app.initDatabases(); err != nil {
		return fmt.Errorf("failed to init databases: %w", err)
	}

	// Initialize cache
	if err := app.initCache(); err != nil {
		return fmt.Errorf("failed to init cache: %w", err)
	}

	// Initialize repositories
	if err := app.initRepositories(); err != nil {
		return fmt.Errorf("failed to init repositories: %w", err)
	}

	// Initialize services
	if err := app.initServices(); err != nil {
		return fmt.Errorf("failed to init services: %w", err)
	}

	// Initialize use cases
	if err := app.initUseCases(); err != nil {
		return fmt.Errorf("failed to init use cases: %w", err)
	}

	// Initialize servers
	if err := app.initServers(); err != nil {
		return fmt.Errorf("failed to init servers: %w", err)
	}

	// Initialize metrics
	if err := app.initMetrics(); err != nil {
		return fmt.Errorf("failed to init metrics: %w", err)
	}

	app.logger.Info("Application initialization complete")
	return nil
}

// initLogger initializes the logger
func (app *Application) initLogger() error {
	var logger *zap.Logger
	var err error

	// Configure logger based on environment
	if app.config.Service.Debug || app.config.Service.Environment == "development" {
		config := zap.NewDevelopmentConfig()
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
		logger, err = config.Build()
	} else {
		config := zap.NewProductionConfig()
		
		// Set log level based on configuration
		switch app.config.Logging.Level {
		case "debug":
			config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
		case "info":
			config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		case "warn":
			config.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
		case "error":
			config.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
		default:
			config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		}
		
		logger, err = config.Build()
	}

	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	app.logger = logger.With(
		zap.String("service", serviceName),
		zap.String("version", version),
	)

	return nil
}

// initDatabases initializes database connections
func (app *Application) initDatabases() error {
	// Initialize PostgreSQL
	app.logger.Info("Connecting to PostgreSQL",
		zap.String("host", app.config.Database.PostgreSQL.Host),
		zap.Int("port", app.config.Database.PostgreSQL.Port),
		zap.String("database", app.config.Database.PostgreSQL.Database),
	)

	dsn := app.config.Database.PostgreSQL.GetDSN()
	postgres, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Configure connection pool
	postgres.SetMaxOpenConns(app.config.Database.PostgreSQL.MaxOpenConns)
	postgres.SetMaxIdleConns(app.config.Database.PostgreSQL.MaxIdleConns)
	postgres.SetConnMaxLifetime(app.config.Database.PostgreSQL.ConnMaxLifetime)
	postgres.SetConnMaxIdleTime(app.config.Database.PostgreSQL.ConnMaxIdleTime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := postgres.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	app.postgres = postgres
	app.logger.Info("PostgreSQL connection established")

	return nil
}

// initCache initializes cache connections
func (app *Application) initCache() error {
	app.logger.Info("Connecting to Redis",
		zap.String("host", app.config.Cache.Redis.Host),
		zap.String("port", app.config.Cache.Redis.Port),
	)

	// Configure Redis client
	redisOptions := &redis.Options{
		Addr:         app.config.Cache.Redis.GetRedisAddr(),
		Password:     app.config.Cache.Redis.Password,
		DB:           app.config.Cache.Redis.Database,
		PoolSize:     app.config.Cache.Redis.PoolSize,
		MinIdleConns: app.config.Cache.Redis.MinIdleConns,
		DialTimeout:  app.config.Cache.Redis.DialTimeout,
		ReadTimeout:  app.config.Cache.Redis.ReadTimeout,
		WriteTimeout: app.config.Cache.Redis.WriteTimeout,
		IdleTimeout:  app.config.Cache.Redis.IdleTimeout,
	}

	redisClient := redis.NewClient(redisOptions)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("failed to ping Redis: %w", err)
	}

	app.redis = redisClient
	app.cache = cache.NewRedisCache(redisClient, app.logger)
	app.logger.Info("Redis connection established")

	return nil
}

// initRepositories initializes repositories
func (app *Application) initRepositories() error {
	app.logger.Info("Initializing repositories")

	// Initialize asset repository
	app.assetRepo = database.NewPostgreSQLAssetRepository(app.postgres, app.logger)

	app.logger.Info("Repositories initialized")
	return nil
}

// initServices initializes services
func (app *Application) initServices() error {
	app.logger.Info("Initializing services")

	// Initialize network scanner
	app.networkScanner = external.NewNetworkScanner(app.logger)

	// Initialize enrichment service (placeholder)
	// app.enrichmentService = external.NewAssetEnrichmentService(app.logger)

	app.logger.Info("Services initialized")
	return nil
}

// initUseCases initializes use cases
func (app *Application) initUseCases() error {
	app.logger.Info("Initializing use cases")

	// Initialize asset discovery use case
	app.assetDiscoveryUC = usecase.NewAssetDiscoveryUseCase(
		app.assetRepo,
		app.networkScanner,
		nil, // cloud discovery service (not implemented yet)
		app.enrichmentService,
		app.logger,
	)

	app.logger.Info("Use cases initialized")
	return nil
}

// initServers initializes HTTP and gRPC servers
func (app *Application) initServers() error {
	app.logger.Info("Initializing servers")

	// Initialize HTTP server
	if app.config.HTTP.Enabled {
		app.httpServer = httpdelivery.NewAssetDiscoveryHTTPServer(
			app.assetDiscoveryUC,
			app.assetRepo,
			app.logger,
			app.config.HTTP.Port,
		)
		app.logger.Info("HTTP server initialized", zap.String("port", app.config.HTTP.Port))
	}

	// Initialize gRPC server
	if app.config.GRPC.Enabled {
		grpcServer := grpc.NewServer(
			grpc.MaxRecvMsgSize(app.config.GRPC.MaxReceiveSize),
			grpc.MaxSendMsgSize(app.config.GRPC.MaxSendSize),
		)

		// Register service
		assetDiscoveryGRPCServer := grpcServer.NewAssetDiscoveryServer(
			app.assetDiscoveryUC,
			app.assetRepo,
			app.logger,
		)
		
		// Register with protobuf (commented out until protobuf is generated)
		// pb.RegisterAssetDiscoveryServiceServer(grpcServer, assetDiscoveryGRPCServer)

		// Enable reflection in development
		if app.config.GRPC.Reflection {
			reflection.Register(grpcServer)
		}

		app.grpcServer = grpcServer
		app.logger.Info("gRPC server initialized", zap.String("port", app.config.GRPC.Port))
	}

	return nil
}

// initMetrics initializes metrics collection
func (app *Application) initMetrics() error {
	if !app.config.Metrics.Enabled {
		return nil
	}

	app.logger.Info("Initializing metrics")

	// Create Prometheus registry
	app.metrics = prometheus.NewRegistry()

	// Register default metrics
	app.metrics.MustRegister(prometheus.NewGoCollector())
	app.metrics.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	// TODO: Register custom metrics for asset discovery

	app.logger.Info("Metrics initialized")
	return nil
}

// Start starts all application services
func (app *Application) Start() error {
	app.logger.Info("Starting application services")

	// Start metrics server
	if app.config.Metrics.Enabled {
		app.wg.Add(1)
		go app.startMetricsServer()
	}

	// Start HTTP server
	if app.config.HTTP.Enabled && app.httpServer != nil {
		app.wg.Add(1)
		go app.startHTTPServer()
	}

	// Start gRPC server
	if app.config.GRPC.Enabled && app.grpcServer != nil {
		app.wg.Add(1)
		go app.startGRPCServer()
	}

	// Setup signal handling
	signal.Notify(app.shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	app.logger.Info("All services started successfully")
	return nil
}

// startMetricsServer starts the Prometheus metrics server
func (app *Application) startMetricsServer() {
	defer app.wg.Done()

	addr := fmt.Sprintf("%s:%s", app.config.Metrics.Host, app.config.Metrics.Port)
	
	mux := http.NewServeMux()
	mux.Handle(app.config.Metrics.Path, promhttp.HandlerFor(app.metrics, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	app.logger.Info("Starting metrics server", zap.String("address", addr))

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		app.logger.Error("Metrics server error", zap.Error(err))
	}
}

// startHTTPServer starts the HTTP server
func (app *Application) startHTTPServer() {
	defer app.wg.Done()

	app.logger.Info("Starting HTTP server", zap.String("port", app.config.HTTP.Port))

	if err := app.httpServer.Start(); err != nil && err != http.ErrServerClosed {
		app.logger.Error("HTTP server error", zap.Error(err))
	}
}

// startGRPCServer starts the gRPC server
func (app *Application) startGRPCServer() {
	defer app.wg.Done()

	addr := fmt.Sprintf("%s:%s", app.config.GRPC.Host, app.config.GRPC.Port)
	
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		app.logger.Error("Failed to create gRPC listener", zap.Error(err))
		return
	}

	app.logger.Info("Starting gRPC server", zap.String("address", addr))

	if err := app.grpcServer.Serve(listener); err != nil {
		app.logger.Error("gRPC server error", zap.Error(err))
	}
}

// WaitForShutdown waits for shutdown signal
func (app *Application) WaitForShutdown() {
	<-app.shutdownCh
	app.logger.Info("Shutdown signal received")
}

// Shutdown gracefully shuts down the application
func (app *Application) Shutdown() error {
	app.logger.Info("Starting graceful shutdown")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), app.config.Service.ShutdownTimeout)
	defer cancel()

	// Stop gRPC server
	if app.grpcServer != nil {
		app.logger.Info("Stopping gRPC server")
		app.grpcServer.GracefulStop()
	}

	// Stop HTTP server
	if app.httpServer != nil {
		app.logger.Info("Stopping HTTP server")
		if err := app.httpServer.Shutdown(ctx); err != nil {
			app.logger.Error("Error stopping HTTP server", zap.Error(err))
		}
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		app.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		app.logger.Info("All services stopped")
	case <-ctx.Done():
		app.logger.Warn("Shutdown timeout exceeded")
	}

	// Close database connections
	if app.postgres != nil {
		app.logger.Info("Closing PostgreSQL connection")
		if err := app.postgres.Close(); err != nil {
			app.logger.Error("Error closing PostgreSQL", zap.Error(err))
		}
	}

	if app.redis != nil {
		app.logger.Info("Closing Redis connection")
		if err := app.redis.Close(); err != nil {
			app.logger.Error("Error closing Redis", zap.Error(err))
		}
	}

	// Sync logger
	if app.logger != nil {
		app.logger.Sync()
	}

	return nil
}

// Health check endpoints and utilities

// HealthStatus represents the health status of the service
type HealthStatus struct {
	Status      string                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Service     string                 `json:"service"`
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
	Checks      map[string]interface{} `json:"checks"`
}

// GetHealthStatus returns the current health status
func (app *Application) GetHealthStatus() *HealthStatus {
	status := &HealthStatus{
		Status:      "healthy",
		Timestamp:   time.Now(),
		Service:     serviceName,
		Version:     version,
		Environment: app.config.Service.Environment,
		Checks:      make(map[string]interface{}),
	}

	// Check PostgreSQL
	if app.postgres != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := app.postgres.PingContext(ctx); err != nil {
			status.Status = "unhealthy"
			status.Checks["postgresql"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
		} else {
			status.Checks["postgresql"] = map[string]interface{}{
				"status": "healthy",
			}
		}
	}

	// Check Redis
	if app.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := app.redis.Ping(ctx).Err(); err != nil {
			status.Status = "unhealthy"
			status.Checks["redis"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
		} else {
			status.Checks["redis"] = map[string]interface{}{
				"status": "healthy",
			}
		}
	}

	return status
}