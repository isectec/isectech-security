package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/isectech/platform/services/event-processor/config"
	"github.com/isectech/platform/services/event-processor/domain/repository"
	"github.com/isectech/platform/services/event-processor/domain/service"
	"github.com/isectech/platform/services/event-processor/infrastructure/cache"
	"github.com/isectech/platform/services/event-processor/infrastructure/database"
	"github.com/isectech/platform/services/event-processor/infrastructure/messaging"
	infraService "github.com/isectech/platform/services/event-processor/infrastructure/service"
	"github.com/isectech/platform/services/event-processor/usecase"
	"github.com/isectech/platform/pkg/health"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
	"github.com/isectech/platform/pkg/shutdown"
	"github.com/isectech/platform/shared/common"
)

const (
	serviceName = "event-processor"
	version     = "1.0.0"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("./config")
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		fmt.Printf("Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	loggerConfig := &logging.Config{
		Level:           logging.LogLevel(cfg.Logging.Level),
		Format:          logging.LogFormat(cfg.Logging.Format),
		ServiceName:     serviceName,
		ServiceVersion:  version,
		Environment:     cfg.Service.Environment,
		EnableCaller:    true,
		EnableStacktrace: cfg.Service.Environment == "development",
		EnableCorrelationID: true,
		CorrelationIDHeader: "X-Correlation-ID",
		OutputPaths:     []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := logging.NewLogger(loggerConfig)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting Event Processor Service",
		zap.String("service", serviceName),
		zap.String("version", version),
		zap.String("environment", cfg.Service.Environment),
	)

	// Initialize metrics
	metricsConfig := &metrics.Config{
		Enabled:     cfg.Metrics.Enabled,
		ServiceName: serviceName,
		ServiceVersion: version,
		Environment: cfg.Service.Environment,
		Host:        cfg.Metrics.Host,
		Port:        cfg.Metrics.Port,
		Path:        cfg.Metrics.Path,
		CollectGoMetrics: true,
		CollectProcessMetrics: true,
	}
	
	metricsManager, err := metrics.NewManager(metricsConfig, logger.Logger)
	if err != nil {
		logger.Error("Failed to initialize metrics", zap.Error(err))
		os.Exit(1)
	}

	// Initialize health manager
	healthConfig := &health.Config{
		ServiceName: serviceName,
		Version:     version,
		CacheTTL:    5 * time.Second,
		HTTP: health.HTTPConfig{
			Enabled: true,
			Host:    cfg.Server.HTTP.Host,
			Port:    cfg.Server.HTTP.Port + 1000, // Use different port for health
			Path:    "/health",
		},
	}
	
	healthManager := health.NewManager(healthConfig, logger.Logger)

	// Initialize graceful shutdown manager
	shutdownConfig := &shutdown.Config{
		Timeout: 30 * time.Second,
		Signals: []os.Signal{syscall.SIGTERM, syscall.SIGINT},
	}
	
	shutdownManager := shutdown.New(shutdownConfig, logger.Logger)

	// Create application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize dependencies
	dependencies, err := initializeDependencies(ctx, cfg, logger, metricsManager)
	if err != nil {
		logger.Fatal("Failed to initialize dependencies", zap.Error(err))
	}
	defer dependencies.Cleanup()

	// Register health checks
	if err := registerHealthChecks(healthManager, dependencies, logger); err != nil {
		logger.Fatal("Failed to register health checks", zap.Error(err))
	}

	// Initialize and start servers
	servers, err := initializeServers(cfg, dependencies, logger, metricsManager)
	if err != nil {
		logger.Fatal("Failed to initialize servers", zap.Error(err))
	}

	// Start servers
	if err := startServers(servers, logger); err != nil {
		logger.Fatal("Failed to start servers", zap.Error(err))
	}

	// Start metrics server
	if err := metricsManager.Start(); err != nil {
		logger.Fatal("Failed to start metrics server", zap.Error(err))
	}

	// Start health server
	if err := healthManager.StartHTTPServer(); err != nil {
		logger.Fatal("Failed to start health server", zap.Error(err))
	}

	// Initialize and start background workers
	workers, err := initializeWorkers(ctx, cfg, dependencies, logger, metricsManager)
	if err != nil {
		logger.Fatal("Failed to initialize workers", zap.Error(err))
	}

	if err := startWorkers(workers, logger); err != nil {
		logger.Fatal("Failed to start workers", zap.Error(err))
	}

	// Register shutdown hooks
	registerShutdownHooks(shutdownManager, servers, workers, dependencies, metricsManager, healthManager, logger)

	// Start listening for shutdown signals
	shutdownManager.Listen()

	logger.Info("Event Processor Service started successfully")

	// Wait for shutdown
	shutdownManager.Wait()

	logger.Info("Event Processor Service shutdown completed")
}

// Dependencies represents all service dependencies
type Dependencies struct {
	// Database repositories
	EventRepository repository.EventRepository
	
	// Domain services
	ProcessorService      service.EventProcessorService
	EnrichmentService     service.EventEnrichmentService
	ValidationService     service.EventValidationService
	NormalizationService  service.EventNormalizationService
	RiskAssessmentService service.RiskAssessmentService
	
	// Infrastructure services
	Cache         *cache.RedisCache
	Consumer      *messaging.KafkaEventConsumer
	Producer      *messaging.KafkaEventProducer
	
	// Core services
	ProcessEventUseCase *usecase.ProcessEventUseCase
	
	logger  *logging.Logger
	metrics *metrics.Manager
}

// Cleanup cleans up all dependencies
func (d *Dependencies) Cleanup() {
	d.logger.Info("Cleaning up dependencies")
	
	// Close cache connection
	if d.Cache != nil {
		if err := d.Cache.Close(); err != nil {
			d.logger.Error("Failed to close cache", zap.Error(err))
		}
	}
	
	// Stop consumer
	if d.Consumer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.Consumer.Stop(ctx); err != nil {
			d.logger.Error("Failed to stop consumer", zap.Error(err))
		}
	}
	
	// Close producer
	if d.Producer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.Producer.Close(ctx); err != nil {
			d.logger.Error("Failed to close producer", zap.Error(err))
		}
	}
}

// Servers represents all servers
type Servers struct {
	HTTPServer *http.Server
	GRPCServer *grpc.Server
	HTTPAddr   string
	GRPCAddr   string
}

// Workers represents all background workers
type Workers struct {
	EventProcessor *EventProcessorWorker
	HealthChecker  *HealthCheckerWorker
}

// EventProcessorWorker represents the main event processing worker
type EventProcessorWorker struct {
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *logging.Logger
	metrics *metrics.Manager
	cfg     *config.Config
}

// HealthCheckerWorker represents the health checker worker
type HealthCheckerWorker struct {
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *logging.Logger
	metrics *metrics.Manager
	cfg     *config.Config
}

// initializeDependencies initializes all service dependencies
func initializeDependencies(ctx context.Context, cfg *config.Config, logger *logging.Logger, metricsManager *metrics.Manager) (*Dependencies, error) {
	logger.Info("Initializing dependencies")

	deps := &Dependencies{
		logger:  logger,
		metrics: metricsManager,
	}

	// 1. Initialize cache (Redis)
	cacheConfig := &cache.RedisCacheConfig{
		Addresses:           []string{cfg.Cache.Redis.Address},
		Password:           cfg.Cache.Redis.Password,
		Database:           cfg.Cache.Redis.Database,
		PoolSize:           cfg.Cache.Redis.PoolSize,
		Namespace:          "event_processor",
		DefaultTTL:         15 * time.Minute,
		EnableMetrics:      true,
	}
	
	redisCache, err := cache.NewRedisCache(logger, metricsManager, cacheConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Redis cache: %w", err)
	}
	deps.Cache = redisCache

	// 2. Initialize database connections
	// MongoDB connection for event repository
	mongoClient, err := common.NewMongoDBClient(&cfg.Database.MongoDB)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}
	
	mongoDatabase := mongoClient.Database(cfg.Database.MongoDB.Database)
	
	// Initialize event repository
	deps.EventRepository = database.NewMongoEventRepository(
		mongoDatabase,
		logger,
		metricsManager,
	)

	// 3. Initialize domain services
	
	// Validation service
	validationConfig := &infraService.ValidationConfig{
		EnableSchemaValidation:     true,
		EnableBusinessRules:        true,
		EnableDataIntegrityChecks:  true,
		EnableComplianceValidation: true,
		ValidationTimeout:          5 * time.Second,
	}
	deps.ValidationService = infraService.NewValidationService(logger, metricsCollector, validationConfig)

	// Normalization service
	normalizationConfig := &infraService.NormalizationConfig{
		TimezoneHandling:     "utc",
		NormalizeIPAddresses: true,
		CaseNormalization:    "lower",
		TrimWhitespace:       true,
		NormalizeURLs:        true,
		NormalizeEmails:      true,
		NormalizeDomains:     true,
	}
	deps.NormalizationService = infraService.NewNormalizationService(logger, metricsCollector, normalizationConfig)

	// Enrichment service
	enrichmentConfig := &infraService.EnrichmentConfig{
		EnableAssetEnrichment:       true,
		EnableUserEnrichment:        true,
		EnableGeoEnrichment:         true,
		EnableThreatIntelEnrichment: true,
		EnableNetworkEnrichment:     true,
		GeoLocationTimeout:          5 * time.Second,
		ThreatIntelTimeout:          5 * time.Second,
		MaxConcurrentRequests:       10,
		EnableCaching:               true,
		CacheTTL:                    15 * time.Minute,
	}
	deps.EnrichmentService = infraService.NewEnrichmentService(logger, metricsCollector, enrichmentConfig)

	// Risk assessment service
	riskConfig := &infraService.RiskAssessmentConfig{
		EnableMLModel:              false,
		FallbackToRuleBased:        true,
		DefaultRiskScore:           3.0,
		LowRiskThreshold:           3.0,
		MediumRiskThreshold:        5.0,
		HighRiskThreshold:          7.0,
		CriticalRiskThreshold:      9.0,
		SeverityWeight:             0.3,
		TypeWeight:                 0.2,
		SourceWeight:               0.1,
		EnableTimeDecay:            true,
		EnableFrequencyAnalysis:    true,
		EnableAssetContext:         true,
		EnableUserContext:          true,
	}
	deps.RiskAssessmentService = infraService.NewRiskAssessmentService(logger, metricsCollector, riskConfig)

	// 4. Initialize use cases
	deps.ProcessEventUseCase = usecase.NewProcessEventUseCase(
		deps.EventRepository,
		deps.ProcessorService,
		deps.EnrichmentService,
		deps.ValidationService,
		deps.NormalizationService,
		deps.RiskAssessmentService,
		logger,
		metricsCollector,
	)

	// 5. Initialize messaging
	
	// Kafka producer
	producerConfig := &messaging.KafkaProducerConfig{
		Brokers:              cfg.MessageQueue.Kafka.Brokers,
		ProcessedEventsTopic: "processed-events",
		EnrichedEventsTopic:  "enriched-events",
		AlertsTopic:          "security-alerts",
		ErrorTopic:           "event-processing-errors",
		BatchSize:            100,
		BatchTimeout:         10 * time.Millisecond,
		RequiredAcks:         kafka.RequireAll,
		Compression:          kafka.Snappy,
		EnableIdempotent:     true,
		EnableMetrics:        true,
	}
	
	producer := messaging.NewKafkaEventProducer(logger, metricsCollector, producerConfig)
	deps.Producer = producer

	// Kafka consumer
	consumerConfig := &messaging.KafkaConsumerConfig{
		Brokers:           cfg.MessageQueue.Kafka.Brokers,
		GroupID:           cfg.MessageQueue.Kafka.ConsumerGroup,
		Topics:            cfg.MessageQueue.Kafka.InputTopics,
		WorkerCount:       cfg.Service.WorkerCount,
		BufferSize:        1000,
		MaxRetries:        3,
		RetryDelay:        1 * time.Second,
		ProcessingTimeout: 30 * time.Second,
		EnableDLQ:         true,
		DLQTopic:          cfg.MessageQueue.Kafka.DeadLetterTopic,
		ErrorTopic:        cfg.MessageQueue.Kafka.ErrorTopic,
		EnableMetrics:     true,
	}
	
	consumer := messaging.NewKafkaEventConsumer(
		deps.ProcessEventUseCase,
		logger,
		metricsCollector,
		consumerConfig,
	)
	deps.Consumer = consumer

	logger.Info("Dependencies initialized successfully",
		logging.Int("worker_count", cfg.Service.WorkerCount),
		logging.Strings("input_topics", cfg.MessageQueue.Kafka.InputTopics),
	)
	
	return deps, nil
}

// initializeServers initializes HTTP and gRPC servers
func initializeServers(cfg *config.Config, deps *Dependencies, logger *logging.Logger, metricsCollector *metrics.Collector) (*Servers, error) {
	logger.Info("Initializing servers")

	// HTTP Server
	httpAddr := fmt.Sprintf("%s:%d", cfg.Server.HTTP.Host, cfg.Server.HTTP.Port)
	httpMux := http.NewServeMux()

	// Add health check endpoint
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"event-processor","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	// Add readiness check endpoint
	httpMux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Add actual readiness checks (database, cache, etc.)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready","service":"event-processor","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	})

	// Add metrics middleware
	httpMux.Handle("/", metricsCollector.Middleware()(httpMux))

	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      httpMux,
		ReadTimeout:  cfg.Server.HTTP.ReadTimeout,
		WriteTimeout: cfg.Server.HTTP.WriteTimeout,
		IdleTimeout:  cfg.Server.HTTP.IdleTimeout,
	}

	// gRPC Server
	grpcAddr := fmt.Sprintf("%s:%d", cfg.Server.GRPC.Host, cfg.Server.GRPC.Port)
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(cfg.Server.GRPC.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(cfg.Server.GRPC.MaxSendMsgSize),
	)

	// Enable reflection for development
	if cfg.Service.Environment == "development" {
		reflection.Register(grpcServer)
	}

	// TODO: Register gRPC services here
	// Example:
	// eventpb.RegisterEventProcessorServiceServer(grpcServer, grpcHandlers.NewEventProcessorHandler(...))

	servers := &Servers{
		HTTPServer: httpServer,
		GRPCServer: grpcServer,
		HTTPAddr:   httpAddr,
		GRPCAddr:   grpcAddr,
	}

	logger.Info("Servers initialized successfully")
	return servers, nil
}

// initializeWorkers initializes background workers
func initializeWorkers(ctx context.Context, cfg *config.Config, deps *Dependencies, logger *logging.Logger, metricsCollector *metrics.Collector) (*Workers, error) {
	logger.Info("Initializing workers")

	// Event Processor Worker
	eventProcessorCtx, eventProcessorCancel := context.WithCancel(ctx)
	eventProcessor := &EventProcessorWorker{
		ctx:     eventProcessorCtx,
		cancel:  eventProcessorCancel,
		logger:  logger.WithComponent("event-processor-worker"),
		metrics: metricsCollector,
		cfg:     cfg,
	}

	// Health Checker Worker
	healthCheckerCtx, healthCheckerCancel := context.WithCancel(ctx)
	healthChecker := &HealthCheckerWorker{
		ctx:     healthCheckerCtx,
		cancel:  healthCheckerCancel,
		logger:  logger.WithComponent("health-checker-worker"),
		metrics: metricsCollector,
		cfg:     cfg,
	}

	workers := &Workers{
		EventProcessor: eventProcessor,
		HealthChecker:  healthChecker,
	}

	logger.Info("Workers initialized successfully")
	return workers, nil
}

// startServers starts all servers
func startServers(servers *Servers, logger *logging.Logger) error {
	// Start HTTP server
	go func() {
		logger.Info("Starting HTTP server", logging.String("address", servers.HTTPAddr))
		if err := servers.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", logging.String("error", err.Error()))
		}
	}()

	// Start gRPC server
	go func() {
		listener, err := net.Listen("tcp", servers.GRPCAddr)
		if err != nil {
			logger.Error("Failed to create gRPC listener", logging.String("error", err.Error()))
			return
		}

		logger.Info("Starting gRPC server", logging.String("address", servers.GRPCAddr))
		if err := servers.GRPCServer.Serve(listener); err != nil {
			logger.Error("gRPC server failed", logging.String("error", err.Error()))
		}
	}()

	return nil
}

// startWorkers starts all background workers
func startWorkers(workers *Workers, logger *logging.Logger) error {
	// Start event processor worker
	go workers.EventProcessor.Run()

	// Start health checker worker
	go workers.HealthChecker.Run()

	return nil
}

// stopServers stops all servers gracefully
func stopServers(servers *Servers, ctx context.Context, logger *logging.Logger) {
	// Stop HTTP server
	logger.Info("Stopping HTTP server")
	if err := servers.HTTPServer.Shutdown(ctx); err != nil {
		logger.Error("Failed to shutdown HTTP server gracefully", logging.String("error", err.Error()))
	}

	// Stop gRPC server
	logger.Info("Stopping gRPC server")
	done := make(chan struct{})
	go func() {
		servers.GRPCServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("gRPC server stopped gracefully")
	case <-ctx.Done():
		logger.Warn("gRPC server shutdown timeout, forcing stop")
		servers.GRPCServer.Stop()
	}
}

// stopWorkers stops all background workers gracefully
func stopWorkers(workers *Workers, ctx context.Context, logger *logging.Logger) {
	logger.Info("Stopping workers")

	// Stop event processor worker
	workers.EventProcessor.Stop()

	// Stop health checker worker
	workers.HealthChecker.Stop()

	// Wait for workers to stop or timeout
	select {
	case <-time.After(5 * time.Second):
		logger.Info("All workers stopped successfully")
	case <-ctx.Done():
		logger.Warn("Worker shutdown timeout")
	}
}

// Run starts the event processor worker
func (w *EventProcessorWorker) Run() {
	w.logger.Info("Starting event processor worker")

	ticker := time.NewTicker(w.cfg.EventProcessing.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("Event processor worker stopped")
			return
		case <-ticker.C:
			// TODO: Implement actual event processing logic
			// This is where you would:
			// 1. Read events from Kafka
			// 2. Process events through the use case
			// 3. Handle errors and retries
			// 4. Update metrics

			w.logger.Debug("Event processor worker tick")
			w.metrics.RecordBusinessOperation("worker_tick", "event-processor", "completed", 0)
		}
	}
}

// Stop stops the event processor worker
func (w *EventProcessorWorker) Stop() {
	w.logger.Info("Stopping event processor worker")
	w.cancel()
}

// Run starts the health checker worker
func (w *HealthCheckerWorker) Run() {
	w.logger.Info("Starting health checker worker")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("Health checker worker stopped")
			return
		case <-ticker.C:
			// TODO: Implement actual health checks
			// This is where you would:
			// 1. Check database connectivity
			// 2. Check cache connectivity
			// 3. Check message queue connectivity
			// 4. Update health metrics

			w.logger.Debug("Health checker worker tick")
			w.metrics.RecordBusinessOperation("health_check", "event-processor", "completed", 0)
		}
	}
}

// Stop stops the health checker worker
func (w *HealthCheckerWorker) Stop() {
	w.logger.Info("Stopping health checker worker")
	w.cancel()
}

// registerHealthChecks registers all health checks with the health manager
func registerHealthChecks(healthManager *health.Manager, deps *Dependencies, logger *logging.Logger) error {
	logger.Info("Registering health checks")

	// Database health check
	if deps.EventRepository != nil {
		// Assuming there's a way to check database connectivity
		dbCheck := &health.CheckConfig{
			Name:        "database",
			Type:        health.CheckTypeReadiness,
			Timeout:     5 * time.Second,
			Interval:    30 * time.Second,
			Enabled:     true,
			Critical:    true,
			Description: "MongoDB database connectivity",
		}
		
		healthManager.RegisterCheck(dbCheck, health.DatabaseCheck("mongodb", deps.EventRepository))
	}

	// Cache health check
	if deps.Cache != nil {
		cacheCheck := &health.CheckConfig{
			Name:        "cache",
			Type:        health.CheckTypeReadiness,
			Timeout:     3 * time.Second,
			Interval:    30 * time.Second,
			Enabled:     true,
			Critical:    false,
			Description: "Redis cache connectivity",
		}
		
		healthManager.RegisterCheck(cacheCheck, health.RedisCheck("redis", deps.Cache))
	}

	// Kafka consumer health check
	if deps.Consumer != nil {
		consumerCheck := &health.CheckConfig{
			Name:        "kafka_consumer",
			Type:        health.CheckTypeReadiness,
			Timeout:     5 * time.Second,
			Interval:    30 * time.Second,
			Enabled:     true,
			Critical:    true,
			Description: "Kafka consumer connectivity",
		}
		
		healthManager.RegisterCheck(consumerCheck, func(ctx context.Context) health.CheckResult {
			// Custom check for Kafka consumer health
			if deps.Consumer.IsHealthy() {
				return health.CheckResult{
					Status:  health.StatusHealthy,
					Message: "Kafka consumer is healthy",
				}
			}
			return health.CheckResult{
				Status:  health.StatusUnhealthy,
				Message: "Kafka consumer is not healthy",
			}
		})
	}

	// Liveness check (basic service health)
	livenessCheck := &health.CheckConfig{
		Name:        "liveness",
		Type:        health.CheckTypeLiveness,
		Timeout:     2 * time.Second,
		Interval:    10 * time.Second,
		Enabled:     true,
		Critical:    true,
		Description: "Service liveness check",
	}
	
	healthManager.RegisterCheck(livenessCheck, func(ctx context.Context) health.CheckResult {
		return health.CheckResult{
			Status:  health.StatusHealthy,
			Message: "Service is alive",
		}
	})

	// Startup check
	startupCheck := &health.CheckConfig{
		Name:        "startup",
		Type:        health.CheckTypeStartup,
		Timeout:     10 * time.Second,
		Interval:    5 * time.Second,
		Enabled:     true,
		Critical:    true,
		Description: "Service startup check",
	}
	
	healthManager.RegisterCheck(startupCheck, func(ctx context.Context) health.CheckResult {
		// Check if all dependencies are initialized
		if deps.EventRepository != nil && deps.Cache != nil && deps.Consumer != nil {
			return health.CheckResult{
				Status:  health.StatusHealthy,
				Message: "Service startup complete",
			}
		}
		return health.CheckResult{
			Status:  health.StatusUnhealthy,
			Message: "Service startup incomplete",
		}
	})

	logger.Info("Health checks registered successfully")
	return nil
}

// registerShutdownHooks registers all shutdown hooks with the shutdown manager
func registerShutdownHooks(shutdownManager *shutdown.GracefulShutdown, servers *Servers, workers *Workers, deps *Dependencies, metricsManager *metrics.Manager, healthManager *health.Manager, logger *logging.Logger) {
	logger.Info("Registering shutdown hooks")

	// 1. Stop background workers first
	shutdownManager.AddHook(shutdown.GenericHook(
		"background-workers",
		5, // High priority (run early)
		15*time.Second,
		func(ctx context.Context) error {
			logger.Info("Stopping background workers")
			
			if workers.EventProcessor != nil {
				workers.EventProcessor.Stop()
			}
			
			if workers.HealthChecker != nil {
				workers.HealthChecker.Stop()
			}
			
			// Wait a bit for workers to finish
			time.Sleep(2 * time.Second)
			return nil
		},
	))

	// 2. Stop servers
	if servers.HTTPServer != nil {
		shutdownManager.AddHook(shutdown.HTTPServerHook("http-server", servers.HTTPServer))
	}
	
	if servers.GRPCServer != nil {
		shutdownManager.AddHook(shutdown.GRPCServerHook("grpc-server", servers.GRPCServer))
	}

	// 3. Close databases and cache
	if deps.Cache != nil {
		shutdownManager.AddHook(shutdown.DatabaseHook("cache", deps.Cache))
	}

	// 4. Stop messaging
	if deps.Consumer != nil {
		shutdownManager.AddHook(shutdown.GenericHook(
			"kafka-consumer",
			20,
			10*time.Second,
			func(ctx context.Context) error {
				return deps.Consumer.Stop(ctx)
			},
		))
	}
	
	if deps.Producer != nil {
		shutdownManager.AddHook(shutdown.GenericHook(
			"kafka-producer",
			20,
			10*time.Second,
			func(ctx context.Context) error {
				return deps.Producer.Close(ctx)
			},
		))
	}

	// 5. Stop metrics
	if metricsManager != nil {
		shutdownManager.AddHook(shutdown.MetricsHook("metrics", metricsManager))
	}
	
	// 6. Stop health server
	if healthManager != nil {
		shutdownManager.AddHook(shutdown.GenericHook(
			"health-server",
			30,
			5*time.Second,
			func(ctx context.Context) error {
				return healthManager.StopHTTPServer(ctx)
			},
		))
	}

	// 7. Sync logger (last)
	shutdownManager.AddHook(shutdown.LoggerHook("logger", logger))

	logger.Info("Shutdown hooks registered successfully")
}