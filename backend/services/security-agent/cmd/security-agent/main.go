package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/isectech/security-agent/config"
	"github.com/isectech/security-agent/infrastructure/service"
	"github.com/isectech/security-agent/usecase"
	"go.uber.org/zap"
)

const (
	defaultConfigPath = "./config.yaml"
	serviceName       = "isectech-security-agent"
	serviceVersion    = "1.0.0"
)

func main() {
	var (
		configPath = flag.String("config", defaultConfigPath, "Path to configuration file")
		version    = flag.Bool("version", false, "Show version information")
		help       = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	if *version {
		printVersion()
		return
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := initLogger(cfg.Logging)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	logger.Info("Starting iSECTECH Security Agent",
		zap.String("service", serviceName),
		zap.String("version", serviceVersion),
		zap.String("config", *configPath),
	)

	// Create main context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize service manager
	serviceManager, err := initServiceManager(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize service manager", zap.Error(err))
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start the service
	errChan := make(chan error, 1)
	go func() {
		if err := serviceManager.Start(ctx); err != nil {
			errChan <- fmt.Errorf("service manager failed: %w", err)
		}
	}()

	logger.Info("iSECTECH Security Agent started successfully")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	case err := <-errChan:
		logger.Error("Service error occurred", zap.Error(err))
		cancel()
	}

	// Graceful shutdown
	logger.Info("Initiating graceful shutdown")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := serviceManager.Stop(shutdownCtx); err != nil {
		logger.Error("Error during shutdown", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("iSECTECH Security Agent stopped successfully")
}

// initLogger initializes the logger based on configuration
func initLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var zapConfig zap.Config

	if cfg.Format == "json" {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
	}

	// Set log level
	switch cfg.Level {
	case "debug":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	case "fatal":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.FatalLevel)
	default:
		zapConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	// Configure outputs
	if len(cfg.Output) > 0 {
		zapConfig.OutputPaths = cfg.Output
	}

	// Enable caller information if configured
	if cfg.EnableCaller {
		zapConfig.DisableCaller = false
	} else {
		zapConfig.DisableCaller = true
	}

	// Enable stack trace if configured
	if cfg.EnableStackTrace {
		zapConfig.DisableStacktrace = false
	} else {
		zapConfig.DisableStacktrace = true
	}

	// Add custom fields
	if len(cfg.Fields) > 0 {
		zapConfig.InitialFields = make(map[string]interface{})
		for key, value := range cfg.Fields {
			zapConfig.InitialFields[key] = value
		}
	}

	// Add service information
	zapConfig.InitialFields["service"] = serviceName
	zapConfig.InitialFields["version"] = serviceVersion

	return zapConfig.Build()
}

// initServiceManager initializes the service manager with all dependencies
func initServiceManager(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*service.Manager, error) {
	// Initialize use cases
	useCases, err := initUseCases(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize use cases: %w", err)
	}

	// Create service manager
	manager := service.NewManager(cfg, logger, useCases)

	return manager, nil
}

// initUseCases initializes all use cases
func initUseCases(cfg *config.Config, logger *zap.Logger) (*usecase.UseCases, error) {
	// TODO: Initialize repositories and external dependencies
	// This is a placeholder implementation

	useCases := &usecase.UseCases{
		// Agent management use cases will be initialized here
		// Event processing use cases will be initialized here
		// Policy enforcement use cases will be initialized here
	}

	return useCases, nil
}

// printUsage prints usage information
func printUsage() {
	fmt.Printf(`iSECTECH Security Agent v%s

USAGE:
    %s [OPTIONS]

OPTIONS:
    -config string
        Path to configuration file (default: %s)
    -version
        Show version information
    -help
        Show this help message

EXAMPLES:
    # Start with default configuration
    %s

    # Start with custom configuration
    %s -config /etc/isectech/agent.yaml

    # Show version
    %s -version

ENVIRONMENT VARIABLES:
    Configuration can also be set via environment variables with the prefix ISECTECH_AGENT_
    Example: ISECTECH_AGENT_SERVER_HTTP_PORT=8080

SIGNALS:
    SIGINT/SIGTERM  - Graceful shutdown
    SIGHUP          - Reload configuration

For more information, visit: https://docs.isectech.com/security-agent
`, serviceVersion, os.Args[0], defaultConfigPath, os.Args[0], os.Args[0], os.Args[0])
}

// printVersion prints version information
func printVersion() {
	fmt.Printf(`iSECTECH Security Agent
Version: %s
Build Date: %s
Go Version: %s
Platform: %s

Copyright (c) 2024 iSECTECH. All rights reserved.
`, serviceVersion, getBuildDate(), getGoVersion(), getPlatform())
}

// Build information functions (these would typically be set via ldflags during build)
func getBuildDate() string {
	return "development" // This would be replaced during build
}

func getGoVersion() string {
	return "go1.21+" // This would be replaced during build
}

func getPlatform() string {
	return fmt.Sprintf("%s/%s", getOS(), getArch())
}

func getOS() string {
	return "multi-platform" // This would be replaced during build
}

func getArch() string {
	return "multi-arch" // This would be replaced during build
}
