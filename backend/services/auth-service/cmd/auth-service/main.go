package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"isectech/auth-service/config"
	httpDelivery "isectech/auth-service/delivery/http"
	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
	"isectech/auth-service/infrastructure/database/postgres"
	"isectech/auth-service/usecase"
)

// Build information (set during build)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Parse command line flags
	var (
		configFile  = flag.String("config", "config.yaml", "Configuration file path")
		showVersion = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Printf("iSECTECH Auth Service\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("Build Time: %s\n", BuildTime)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logging
	logger := setupLogging(cfg.LogLevel)
	logger.Info("Starting iSECTECH Authentication Service",
		"version", Version,
		"commit", Commit,
		"build_time", BuildTime,
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize database connection
	logger.Info("Initializing database connection")
	repositoryManager, err := postgres.NewRepositoryManager(ctx, &cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer repositoryManager.Close()

	// Run database migrations
	if cfg.Database.AutoMigrate {
		logger.Info("Running database migrations")
		if err := repositoryManager.RunMigrations(ctx); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
	}

	// Initialize external services
	logger.Info("Initializing external services")
	emailService := initializeEmailService(&cfg.Email)
	smsService := initializeSMSService(&cfg.SMS)
	rateLimiter := initializeRateLimiter(&cfg.RateLimit)
	ipBlocker := initializeIPBlocker(&cfg.Security)
	riskEvaluator := initializeRiskEvaluator(&cfg.RiskEvaluation)

	// Initialize service manager
	logger.Info("Initializing service manager")
	serviceManager, err := usecase.NewServiceManager(
		repositoryManager,
		emailService,
		smsService,
		rateLimiter,
		ipBlocker,
		riskEvaluator,
		&cfg.Service,
	)
	if err != nil {
		log.Fatalf("Failed to initialize service manager: %v", err)
	}

	// Start service manager
	if err := serviceManager.Start(ctx); err != nil {
		log.Fatalf("Failed to start service manager: %v", err)
	}

	// Initialize HTTP server
	logger.Info("Initializing HTTP server")
	httpServer := httpDelivery.NewHTTPServer(
		serviceManager,
		&cfg.Middleware,
		&cfg.HTTP,
	)

	// Start HTTP server
	if err := httpServer.Start(ctx); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}

	logger.Info("Authentication service started successfully",
		"address", httpServer.GetAddress(),
		"tls_enabled", cfg.HTTP.EnableTLS,
	)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Block until signal received
	sig := <-sigChan
	logger.Info("Shutdown signal received", "signal", sig.String())

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Graceful shutdown
	logger.Info("Starting graceful shutdown")

	// Stop HTTP server
	if err := httpServer.Stop(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	// Cancel main context
	cancel()

	logger.Info("Authentication service shutdown completed")
}

// setupLogging configures application logging
func setupLogging(level string) Logger {
	// Implementation would setup structured logging (e.g., logrus, zap)
	// For now, returning a simple logger interface
	return &SimpleLogger{level: level}
}

// Logger interface for application logging
type Logger interface {
	Info(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
	Debug(msg string, keyvals ...interface{})
	Warn(msg string, keyvals ...interface{})
}

// SimpleLogger is a basic logger implementation
type SimpleLogger struct {
	level string
}

func (l *SimpleLogger) Info(msg string, keyvals ...interface{}) {
	log.Printf("[INFO] %s %v", msg, keyvals)
}

func (l *SimpleLogger) Error(msg string, keyvals ...interface{}) {
	log.Printf("[ERROR] %s %v", msg, keyvals)
}

func (l *SimpleLogger) Debug(msg string, keyvals ...interface{}) {
	if l.level == "debug" {
		log.Printf("[DEBUG] %s %v", msg, keyvals)
	}
}

func (l *SimpleLogger) Warn(msg string, keyvals ...interface{}) {
	log.Printf("[WARN] %s %v", msg, keyvals)
}

// External service initializers (placeholder implementations)

func initializeEmailService(cfg *config.EmailConfig) usecase.EmailService {
	// Implementation would create actual email service
	return &MockEmailService{}
}

func initializeSMSService(cfg *config.SMSConfig) usecase.SMSService {
	// Implementation would create actual SMS service
	return &MockSMSService{}
}

func initializeRateLimiter(cfg *config.RateLimitConfig) usecase.RateLimiter {
	// Implementation would create actual rate limiter (Redis-based)
	return &MockRateLimiter{}
}

func initializeIPBlocker(cfg *config.SecurityConfig) usecase.IPBlocker {
	// Implementation would create actual IP blocker
	return &MockIPBlocker{}
}

func initializeRiskEvaluator(cfg *config.RiskEvaluationConfig) usecase.RiskEvaluator {
	// Implementation would create actual risk evaluator
	return &MockRiskEvaluator{}
}

// Mock implementations for external services

type MockEmailService struct{}

func (m *MockEmailService) SendWelcomeEmail(ctx context.Context, user *entity.User) error {
	log.Printf("Mock: Sending welcome email to %s", user.Email)
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(ctx context.Context, user *entity.User, token string) error {
	log.Printf("Mock: Sending password reset email to %s", user.Email)
	return nil
}

func (m *MockEmailService) SendLoginNotification(ctx context.Context, user *entity.User, loginInfo *usecase.LoginInfo) error {
	log.Printf("Mock: Sending login notification to %s", user.Email)
	return nil
}

func (m *MockEmailService) SendSecurityAlert(ctx context.Context, user *entity.User, alert *usecase.SecurityAlert) error {
	log.Printf("Mock: Sending security alert to %s", user.Email)
	return nil
}

type MockSMSService struct{}

func (m *MockSMSService) SendWelcomeSMS(ctx context.Context, phoneNumber string, user *entity.User) error {
	log.Printf("Mock: Sending welcome SMS to %s", phoneNumber)
	return nil
}

func (m *MockSMSService) SendSecurityAlert(ctx context.Context, phoneNumber string, alert *usecase.SecurityAlert) error {
	log.Printf("Mock: Sending security alert SMS to %s", phoneNumber)
	return nil
}

type MockRateLimiter struct{}

func (m *MockRateLimiter) CheckLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	// Always allow for mock
	return true, 0, nil
}

func (m *MockRateLimiter) ResetLimit(ctx context.Context, key string) error {
	return nil
}

type MockIPBlocker struct{}

func (m *MockIPBlocker) IsBlocked(ctx context.Context, ipAddress string) (bool, time.Duration, error) {
	// Never blocked for mock
	return false, 0, nil
}

func (m *MockIPBlocker) BlockIP(ctx context.Context, ipAddress string, duration time.Duration, reason string) error {
	log.Printf("Mock: Blocking IP %s for %v (reason: %s)", ipAddress, duration, reason)
	return nil
}

func (m *MockIPBlocker) UnblockIP(ctx context.Context, ipAddress string) error {
	log.Printf("Mock: Unblocking IP %s", ipAddress)
	return nil
}

type MockRiskEvaluator struct{}

func (m *MockRiskEvaluator) EvaluateLoginRisk(ctx context.Context, req *service.LoginRequest, user *entity.User) (*usecase.RiskAssessment, error) {
	// Low risk for mock
	return &usecase.RiskAssessment{
		Score:           2.0,
		Level:           "low",
		Factors:         []string{"known_device", "normal_location"},
		Recommendations: []string{},
		RequiresMFA:     false,
		BlockAccess:     false,
	}, nil
}

func (m *MockRiskEvaluator) EvaluateRegistrationRisk(ctx context.Context, req *service.UserRegistrationRequest) (*usecase.RiskAssessment, error) {
	// Low risk for mock
	return &usecase.RiskAssessment{
		Score:           1.5,
		Level:           "low",
		Factors:         []string{"standard_registration"},
		Recommendations: []string{},
		RequiresMFA:     false,
		BlockAccess:     false,
	}, nil
}
