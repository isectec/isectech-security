package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/isectech/security-agent/config"
	"github.com/isectech/security-agent/usecase"
	"go.uber.org/zap"
)

// Manager manages all services and components of the security agent
type Manager struct {
	config    *config.Config
	logger    *zap.Logger
	useCases  *usecase.UseCases
	services  []Service
	mu        sync.RWMutex
	isRunning bool
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// Service interface for all managed services
type Service interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health() HealthStatus
	IsRunning() bool
}

// HealthStatus represents the health status of a service
type HealthStatus struct {
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// NewManager creates a new service manager
func NewManager(cfg *config.Config, logger *zap.Logger, useCases *usecase.UseCases) *Manager {
	return &Manager{
		config:   cfg,
		logger:   logger,
		useCases: useCases,
		services: make([]Service, 0),
		stopChan: make(chan struct{}),
	}
}

// Start starts all services
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isRunning {
		return fmt.Errorf("service manager is already running")
	}

	m.logger.Info("Starting service manager")

	// Initialize and register all services
	if err := m.initializeServices(); err != nil {
		return fmt.Errorf("failed to initialize services: %w", err)
	}

	// Start all services
	for _, service := range m.services {
		m.wg.Add(1)
		go func(svc Service) {
			defer m.wg.Done()

			m.logger.Info("Starting service", zap.String("service", svc.Name()))

			if err := svc.Start(ctx); err != nil {
				m.logger.Error("Failed to start service",
					zap.String("service", svc.Name()),
					zap.Error(err))
				return
			}

			m.logger.Info("Service started successfully", zap.String("service", svc.Name()))
		}(service)
	}

	m.isRunning = true
	m.logger.Info("Service manager started successfully")

	// Start health monitoring
	go m.healthMonitor(ctx)

	return nil
}

// Stop stops all services gracefully
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return nil
	}

	m.logger.Info("Stopping service manager")

	// Signal all services to stop
	close(m.stopChan)

	// Stop services in reverse order
	for i := len(m.services) - 1; i >= 0; i-- {
		service := m.services[i]
		m.logger.Info("Stopping service", zap.String("service", service.Name()))

		if err := service.Stop(ctx); err != nil {
			m.logger.Error("Error stopping service",
				zap.String("service", service.Name()),
				zap.Error(err))
		} else {
			m.logger.Info("Service stopped successfully", zap.String("service", service.Name()))
		}
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All services stopped successfully")
	case <-ctx.Done():
		m.logger.Warn("Service shutdown timeout reached")
		return ctx.Err()
	}

	m.isRunning = false
	return nil
}

// IsRunning returns true if the service manager is running
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isRunning
}

// GetServiceHealth returns the health status of all services
func (m *Manager) GetServiceHealth() map[string]HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	health := make(map[string]HealthStatus)
	for _, service := range m.services {
		health[service.Name()] = service.Health()
	}
	return health
}

// GetOverallHealth returns the overall health status
func (m *Manager) GetOverallHealth() HealthStatus {
	serviceHealth := m.GetServiceHealth()

	overallStatus := "healthy"
	var unhealthyServices []string

	for serviceName, health := range serviceHealth {
		if health.Status != "healthy" {
			overallStatus = "degraded"
			unhealthyServices = append(unhealthyServices, serviceName)
		}
	}

	if len(unhealthyServices) > len(serviceHealth)/2 {
		overallStatus = "unhealthy"
	}

	details := map[string]interface{}{
		"total_services":     len(serviceHealth),
		"unhealthy_services": unhealthyServices,
		"service_health":     serviceHealth,
	}

	message := "All services are healthy"
	if len(unhealthyServices) > 0 {
		message = fmt.Sprintf("%d services are unhealthy: %v", len(unhealthyServices), unhealthyServices)
	}

	return HealthStatus{
		Status:    overallStatus,
		Message:   message,
		Timestamp: time.Now(),
		Details:   details,
	}
}

// initializeServices initializes and registers all services
func (m *Manager) initializeServices() error {
	// HTTP Server Service
	if m.config.Server.HTTPPort > 0 {
		httpService := NewHTTPService(m.config, m.logger, m.useCases)
		m.services = append(m.services, httpService)
	}

	// gRPC Server Service
	if m.config.Server.GRPCPort > 0 {
		grpcService := NewGRPCService(m.config, m.logger, m.useCases)
		m.services = append(m.services, grpcService)
	}

	// Data Collection Service
	if m.config.Agent.DataCollection.ProcessMonitoring.Enabled ||
		m.config.Agent.DataCollection.NetworkMonitoring.Enabled ||
		m.config.Agent.DataCollection.FileSystemMonitoring.Enabled {
		dataCollectionService := NewDataCollectionService(m.config, m.logger, m.useCases)
		m.services = append(m.services, dataCollectionService)
	}

	// Policy Enforcement Service
	if m.config.Agent.PolicyEnforcement.Enabled {
		policyService := NewPolicyEnforcementService(m.config, m.logger, m.useCases)
		m.services = append(m.services, policyService)
	}

	// Communication Service
	communicationService := NewCommunicationService(m.config, m.logger, m.useCases)
	m.services = append(m.services, communicationService)

	// Update Service
	if m.config.Agent.UpdateSettings.Enabled {
		updateService := NewUpdateService(m.config, m.logger, m.useCases)
		m.services = append(m.services, updateService)
	}

	// Monitoring Service
	if m.config.Monitoring.Enabled {
		monitoringService := NewMonitoringService(m.config, m.logger, m.useCases)
		m.services = append(m.services, monitoringService)
	}

	// Security Service (always enabled)
	securityService := NewSecurityService(m.config, m.logger, m.useCases)
	m.services = append(m.services, securityService)

	m.logger.Info("Initialized services", zap.Int("count", len(m.services)))
	return nil
}

// healthMonitor continuously monitors service health
func (m *Manager) healthMonitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Check health every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.checkServiceHealth()
		}
	}
}

// checkServiceHealth checks the health of all services
func (m *Manager) checkServiceHealth() {
	m.mu.RLock()
	services := make([]Service, len(m.services))
	copy(services, m.services)
	m.mu.RUnlock()

	var unhealthyServices []string

	for _, service := range services {
		health := service.Health()
		if health.Status != "healthy" {
			unhealthyServices = append(unhealthyServices, service.Name())
			m.logger.Warn("Service is unhealthy",
				zap.String("service", service.Name()),
				zap.String("status", health.Status),
				zap.String("message", health.Message))
		}
	}

	if len(unhealthyServices) > 0 {
		m.logger.Error("Some services are unhealthy",
			zap.Strings("services", unhealthyServices))
	}
}

// RestartService restarts a specific service
func (m *Manager) RestartService(ctx context.Context, serviceName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var targetService Service
	for _, service := range m.services {
		if service.Name() == serviceName {
			targetService = service
			break
		}
	}

	if targetService == nil {
		return fmt.Errorf("service not found: %s", serviceName)
	}

	m.logger.Info("Restarting service", zap.String("service", serviceName))

	// Stop the service
	if err := targetService.Stop(ctx); err != nil {
		m.logger.Error("Failed to stop service during restart",
			zap.String("service", serviceName),
			zap.Error(err))
		return err
	}

	// Wait a moment
	time.Sleep(time.Second)

	// Start the service
	if err := targetService.Start(ctx); err != nil {
		m.logger.Error("Failed to start service during restart",
			zap.String("service", serviceName),
			zap.Error(err))
		return err
	}

	m.logger.Info("Service restarted successfully", zap.String("service", serviceName))
	return nil
}

// AddService adds a new service to the manager
func (m *Manager) AddService(service Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if service already exists
	for _, existingService := range m.services {
		if existingService.Name() == service.Name() {
			return fmt.Errorf("service already exists: %s", service.Name())
		}
	}

	m.services = append(m.services, service)
	m.logger.Info("Service added", zap.String("service", service.Name()))

	return nil
}

// RemoveService removes a service from the manager
func (m *Manager) RemoveService(ctx context.Context, serviceName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, service := range m.services {
		if service.Name() == serviceName {
			// Stop the service if it's running
			if service.IsRunning() {
				if err := service.Stop(ctx); err != nil {
					m.logger.Error("Failed to stop service during removal",
						zap.String("service", serviceName),
						zap.Error(err))
					return err
				}
			}

			// Remove from slice
			m.services = append(m.services[:i], m.services[i+1:]...)
			m.logger.Info("Service removed", zap.String("service", serviceName))
			return nil
		}
	}

	return fmt.Errorf("service not found: %s", serviceName)
}

// GetServices returns a list of all registered services
func (m *Manager) GetServices() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, len(m.services))
	for i, service := range m.services {
		names[i] = service.Name()
	}
	return names
}
