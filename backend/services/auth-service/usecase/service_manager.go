package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
	"isectech/auth-service/infrastructure/database/postgres"
	"isectech/auth-service/infrastructure/mfa"
)

// ServiceManager coordinates all authentication and authorization services
type ServiceManager struct {
	// Core services
	authService     *AuthenticationServiceImpl
	passwordService *PasswordServiceImpl
	sessionService  *SessionServiceImpl
	mfaService      service.MFAService

	// Repository layer
	repositoryManager *postgres.RepositoryManager

	// External services
	emailService  EmailService
	smsService    SMSService
	rateLimiter   RateLimiter
	ipBlocker     IPBlocker
	riskEvaluator RiskEvaluator

	// Configuration
	config *ServiceConfig

	// Background tasks
	backgroundTasks *BackgroundTaskManager
}

// ServiceConfig holds the overall service configuration
type ServiceConfig struct {
	Auth     *AuthConfig           `yaml:"auth"`
	Password *PasswordConfig       `yaml:"password"`
	Session  *SessionConfig        `yaml:"session"`
	MFA      *mfa.MFAServiceConfig `yaml:"mfa"`

	// Service-wide settings
	ServiceName   string `yaml:"service_name" default:"iSECTECH-Auth"`
	Environment   string `yaml:"environment" default:"production"`
	LogLevel      string `yaml:"log_level" default:"info"`
	EnableMetrics bool   `yaml:"enable_metrics" default:"true"`
	EnableTracing bool   `yaml:"enable_tracing" default:"true"`

	// Security settings
	EncryptionKey  string        `yaml:"encryption_key"`
	JWTSecret      string        `yaml:"jwt_secret"`
	AuditRetention time.Duration `yaml:"audit_retention" default:"2190h"` // 3 months

	// Performance settings
	CacheEnabled   bool          `yaml:"cache_enabled" default:"true"`
	CacheTTL       time.Duration `yaml:"cache_ttl" default:"5m"`
	WorkerPoolSize int           `yaml:"worker_pool_size" default:"10"`
}

// BackgroundTaskManager manages background tasks and maintenance
type BackgroundTaskManager struct {
	serviceManager *ServiceManager
	stopChannel    chan struct{}
	tasks          map[string]*BackgroundTask
}

// BackgroundTask represents a background maintenance task
type BackgroundTask struct {
	Name       string
	Interval   time.Duration
	LastRun    time.Time
	NextRun    time.Time
	IsRunning  bool
	RunCount   int64
	ErrorCount int64
	LastError  error
	TaskFunc   func(ctx context.Context) error
}

// NewServiceManager creates a new service manager with all dependencies
func NewServiceManager(
	repositoryManager *postgres.RepositoryManager,
	emailService EmailService,
	smsService SMSService,
	rateLimiter RateLimiter,
	ipBlocker IPBlocker,
	riskEvaluator RiskEvaluator,
	config *ServiceConfig,
) (*ServiceManager, error) {

	// Validate configuration
	if err := validateServiceConfig(config); err != nil {
		return nil, fmt.Errorf("invalid service configuration: %w", err)
	}

	sm := &ServiceManager{
		repositoryManager: repositoryManager,
		emailService:      emailService,
		smsService:        smsService,
		rateLimiter:       rateLimiter,
		ipBlocker:         ipBlocker,
		riskEvaluator:     riskEvaluator,
		config:            config,
	}

	// Initialize MFA service
	mfaService, err := mfa.NewMFAServiceImpl(
		repositoryManager.GetUserRepository(),
		repositoryManager.GetMFADeviceRepository(),
		repositoryManager.GetAuditRepository(),
		config.MFA,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MFA service: %w", err)
	}
	sm.mfaService = mfaService

	// Initialize session service
	sessionRepo := NewDatabaseSessionRepository(repositoryManager.GetDB())
	sm.sessionService = NewSessionService(
		sessionRepo,
		repositoryManager.GetUserRepository(),
		repositoryManager.GetAuditRepository(),
		config.Session,
		config.JWTSecret,
	)

	// Initialize password service
	passwordHistory := NewDatabasePasswordHistoryStore(repositoryManager.GetDB())
	sm.passwordService = NewPasswordService(
		repositoryManager.GetUserRepository(),
		repositoryManager.GetAuditRepository(),
		emailService,
		nil, // Will be set after auth service creation
		passwordHistory,
		config.Password,
	)

	// Initialize authentication service
	sm.authService = NewAuthenticationService(
		repositoryManager.GetUserRepository(),
		sessionRepo,
		repositoryManager.GetAuditRepository(),
		sm.mfaService,
		emailService,
		smsService,
		rateLimiter,
		ipBlocker,
		riskEvaluator,
		config.Auth,
	)

	// Set auth service reference in password service
	sm.passwordService.authService = sm.authService

	// Initialize background tasks
	sm.backgroundTasks = NewBackgroundTaskManager(sm)

	return sm, nil
}

// Start initializes and starts all services
func (sm *ServiceManager) Start(ctx context.Context) error {
	// Health check all dependencies
	if err := sm.repositoryManager.HealthCheck(ctx); err != nil {
		return fmt.Errorf("repository health check failed: %w", err)
	}

	// Start background tasks
	sm.backgroundTasks.Start(ctx)

	return nil
}

// Stop gracefully stops all services
func (sm *ServiceManager) Stop(ctx context.Context) error {
	// Stop background tasks
	sm.backgroundTasks.Stop()

	// Close database connections
	return sm.repositoryManager.Close()
}

// GetAuthService returns the authentication service
func (sm *ServiceManager) GetAuthService() *AuthenticationServiceImpl {
	return sm.authService
}

// GetPasswordService returns the password service
func (sm *ServiceManager) GetPasswordService() *PasswordServiceImpl {
	return sm.passwordService
}

// GetSessionService returns the session service
func (sm *ServiceManager) GetSessionService() *SessionServiceImpl {
	return sm.sessionService
}

// GetMFAService returns the MFA service
func (sm *ServiceManager) GetMFAService() service.MFAService {
	return sm.mfaService
}

// GetRepositoryManager returns the repository manager
func (sm *ServiceManager) GetRepositoryManager() *postgres.RepositoryManager {
	return sm.repositoryManager
}

// HealthCheck performs a comprehensive health check
func (sm *ServiceManager) HealthCheck(ctx context.Context) map[string]interface{} {
	health := make(map[string]interface{})

	// Database health
	dbErr := sm.repositoryManager.HealthCheck(ctx)
	health["database"] = map[string]interface{}{
		"healthy": dbErr == nil,
		"error":   getErrorString(dbErr),
	}

	// Database stats
	dbStats := sm.repositoryManager.GetDatabaseStats()
	health["database_stats"] = dbStats

	// Background tasks health
	health["background_tasks"] = sm.backgroundTasks.GetStatus()

	// Service configuration
	health["service"] = map[string]interface{}{
		"name":        sm.config.ServiceName,
		"environment": sm.config.Environment,
		"uptime":      time.Since(time.Now()), // Would track actual start time
	}

	return health
}

// GetMetrics returns service metrics
func (sm *ServiceManager) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	// Get audit metrics
	auditMetrics, err := sm.repositoryManager.GetAuditRepository().GetAuditMetrics(ctx, uuid.Nil) // System-wide metrics
	if err != nil {
		return nil, fmt.Errorf("failed to get audit metrics: %w", err)
	}
	metrics["audit"] = auditMetrics

	// Get database performance stats
	perfStats, err := sm.repositoryManager.GetQueryPerformanceStats(ctx)
	if err != nil {
		// Non-fatal error
		metrics["performance_error"] = err.Error()
	} else {
		metrics["performance"] = perfStats
	}

	// Background task metrics
	metrics["background_tasks"] = sm.backgroundTasks.GetMetrics()

	return metrics, nil
}

// Background Task Manager Implementation

// NewBackgroundTaskManager creates a new background task manager
func NewBackgroundTaskManager(sm *ServiceManager) *BackgroundTaskManager {
	btm := &BackgroundTaskManager{
		serviceManager: sm,
		stopChannel:    make(chan struct{}),
		tasks:          make(map[string]*BackgroundTask),
	}

	// Register default tasks
	btm.registerDefaultTasks()

	return btm
}

// Start starts all background tasks
func (btm *BackgroundTaskManager) Start(ctx context.Context) {
	for _, task := range btm.tasks {
		go btm.runTask(ctx, task)
	}
}

// Stop stops all background tasks
func (btm *BackgroundTaskManager) Stop() {
	close(btm.stopChannel)
}

// GetStatus returns the status of all background tasks
func (btm *BackgroundTaskManager) GetStatus() map[string]interface{} {
	status := make(map[string]interface{})

	for name, task := range btm.tasks {
		status[name] = map[string]interface{}{
			"last_run":    task.LastRun,
			"next_run":    task.NextRun,
			"is_running":  task.IsRunning,
			"run_count":   task.RunCount,
			"error_count": task.ErrorCount,
			"last_error":  getErrorString(task.LastError),
		}
	}

	return status
}

// GetMetrics returns background task metrics
func (btm *BackgroundTaskManager) GetMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	totalRuns := int64(0)
	totalErrors := int64(0)

	for name, task := range btm.tasks {
		totalRuns += task.RunCount
		totalErrors += task.ErrorCount

		metrics[name+"_runs"] = task.RunCount
		metrics[name+"_errors"] = task.ErrorCount
	}

	metrics["total_runs"] = totalRuns
	metrics["total_errors"] = totalErrors
	metrics["error_rate"] = float64(totalErrors) / float64(max(totalRuns, 1))

	return metrics
}

// registerDefaultTasks registers the default background maintenance tasks
func (btm *BackgroundTaskManager) registerDefaultTasks() {
	// Session cleanup task
	btm.tasks["session_cleanup"] = &BackgroundTask{
		Name:     "session_cleanup",
		Interval: 1 * time.Hour,
		TaskFunc: btm.cleanupExpiredSessions,
	}

	// Audit log cleanup task
	btm.tasks["audit_cleanup"] = &BackgroundTask{
		Name:     "audit_cleanup",
		Interval: 24 * time.Hour,
		TaskFunc: btm.cleanupOldAuditLogs,
	}

	// Database optimization task
	btm.tasks["db_optimize"] = &BackgroundTask{
		Name:     "db_optimize",
		Interval: 6 * time.Hour,
		TaskFunc: btm.optimizeDatabase,
	}

	// User account maintenance task
	btm.tasks["user_maintenance"] = &BackgroundTask{
		Name:     "user_maintenance",
		Interval: 4 * time.Hour,
		TaskFunc: btm.maintainUserAccounts,
	}
}

// runTask runs a background task in a loop
func (btm *BackgroundTaskManager) runTask(ctx context.Context, task *BackgroundTask) {
	ticker := time.NewTicker(task.Interval)
	defer ticker.Stop()

	// Run immediately on start
	btm.executeTask(ctx, task)

	for {
		select {
		case <-ticker.C:
			btm.executeTask(ctx, task)
		case <-btm.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

// executeTask executes a single background task
func (btm *BackgroundTaskManager) executeTask(ctx context.Context, task *BackgroundTask) {
	if task.IsRunning {
		return // Skip if already running
	}

	task.IsRunning = true
	task.LastRun = time.Now()
	task.RunCount++

	defer func() {
		task.IsRunning = false
		task.NextRun = time.Now().Add(task.Interval)
	}()

	err := task.TaskFunc(ctx)
	if err != nil {
		task.ErrorCount++
		task.LastError = err
		// Log error (implementation would use proper logging)
	}
}

// Background task implementations

func (btm *BackgroundTaskManager) cleanupExpiredSessions(ctx context.Context) error {
	// Implementation would cleanup expired sessions
	_, err := btm.serviceManager.repositoryManager.CleanupExpiredData(ctx)
	return err
}

func (btm *BackgroundTaskManager) cleanupOldAuditLogs(ctx context.Context) error {
	retentionDays := int(btm.serviceManager.config.AuditRetention.Hours() / 24)
	_, err := btm.serviceManager.repositoryManager.CleanupAuditLogs(ctx, retentionDays)
	return err
}

func (btm *BackgroundTaskManager) optimizeDatabase(ctx context.Context) error {
	return btm.serviceManager.repositoryManager.OptimizeDatabase(ctx)
}

func (btm *BackgroundTaskManager) maintainUserAccounts(ctx context.Context) error {
	// Implementation would handle user account maintenance
	// - Unlock accounts after lockout period
	// - Send password expiration warnings
	// - Deactivate unused accounts
	return nil
}

// Helper functions

func validateServiceConfig(config *ServiceConfig) error {
	if config.Auth == nil {
		return fmt.Errorf("auth configuration is required")
	}
	if config.Password == nil {
		return fmt.Errorf("password configuration is required")
	}
	if config.Session == nil {
		return fmt.Errorf("session configuration is required")
	}
	if config.MFA == nil {
		return fmt.Errorf("MFA configuration is required")
	}
	if config.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}
	if config.EncryptionKey == "" {
		return fmt.Errorf("encryption key is required")
	}
	return nil
}

func getErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Additional repository implementations needed

// Placeholder implementations for repository interfaces
func NewDatabaseSessionRepository(db interface{}) SessionRepository {
	// Implementation would create a PostgreSQL-based session repository
	return &DatabaseSessionRepository{}
}

func NewDatabasePasswordHistoryStore(db interface{}) PasswordHistoryStore {
	// Implementation would create a PostgreSQL-based password history store
	return &DatabasePasswordHistoryStore{}
}

// Placeholder implementations
type DatabaseSessionRepository struct{}

func (r *DatabaseSessionRepository) Create(ctx context.Context, session *entity.Session) error {
	return nil
}

func (r *DatabaseSessionRepository) GetByToken(ctx context.Context, token string) (*entity.Session, error) {
	return nil, nil
}

func (r *DatabaseSessionRepository) GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) ([]entity.Session, error) {
	return nil, nil
}

func (r *DatabaseSessionRepository) Update(ctx context.Context, session *entity.Session) error {
	return nil
}

func (r *DatabaseSessionRepository) Delete(ctx context.Context, sessionID uuid.UUID) error {
	return nil
}

func (r *DatabaseSessionRepository) DeleteAllByUserID(ctx context.Context, userID, tenantID uuid.UUID) error {
	return nil
}

func (r *DatabaseSessionRepository) CleanupExpired(ctx context.Context) (int, error) {
	return 0, nil
}

type DatabasePasswordHistoryStore struct{}

func (s *DatabasePasswordHistoryStore) AddPasswordHash(ctx context.Context, userID, tenantID uuid.UUID, passwordHash string) error {
	return nil
}

func (s *DatabasePasswordHistoryStore) CheckPasswordHistory(ctx context.Context, userID, tenantID uuid.UUID, passwordHash string, count int) (bool, error) {
	return false, nil
}

func (s *DatabasePasswordHistoryStore) CleanupOldHistory(ctx context.Context, userID, tenantID uuid.UUID, keepCount int) error {
	return nil
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
