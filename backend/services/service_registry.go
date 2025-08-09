package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// ServiceRegistry manages service discovery and registration
type ServiceRegistry struct {
	firestoreClient *firestore.Client
	redisClient     *redis.Client
	logger          *logrus.Logger
	mu              sync.RWMutex
	localCache      map[string]*ServiceInfo
	cacheExpiry     time.Duration
	heartbeatInterval time.Duration
}

// ServiceInfo represents a registered service
type ServiceInfo struct {
	ServiceID     string            `json:"service_id" firestore:"service_id"`
	ServiceName   string            `json:"service_name" firestore:"service_name"`
	Version       string            `json:"version" firestore:"version"`
	Environment   string            `json:"environment" firestore:"environment"`
	Region        string            `json:"region" firestore:"region"`
	Endpoints     []ServiceEndpoint `json:"endpoints" firestore:"endpoints"`
	HealthCheck   HealthCheckConfig `json:"health_check" firestore:"health_check"`
	Metadata      map[string]string `json:"metadata" firestore:"metadata"`
	Status        ServiceStatus     `json:"status" firestore:"status"`
	RegisteredAt  time.Time         `json:"registered_at" firestore:"registered_at"`
	LastHeartbeat time.Time         `json:"last_heartbeat" firestore:"last_heartbeat"`
	Tags          []string          `json:"tags" firestore:"tags"`
}

// ServiceEndpoint represents a service endpoint
type ServiceEndpoint struct {
	Name        string            `json:"name" firestore:"name"`
	URL         string            `json:"url" firestore:"url"`
	Protocol    string            `json:"protocol" firestore:"protocol"`
	Port        int               `json:"port" firestore:"port"`
	Path        string            `json:"path" firestore:"path"`
	Methods     []string          `json:"methods" firestore:"methods"`
	IsPublic    bool              `json:"is_public" firestore:"is_public"`
	IsInternal  bool              `json:"is_internal" firestore:"is_internal"`
	Metadata    map[string]string `json:"metadata" firestore:"metadata"`
}

// HealthCheckConfig defines health check configuration
type HealthCheckConfig struct {
	Enabled        bool          `json:"enabled" firestore:"enabled"`
	Path           string        `json:"path" firestore:"path"`
	Interval       time.Duration `json:"interval" firestore:"interval"`
	Timeout        time.Duration `json:"timeout" firestore:"timeout"`
	HealthyThreshold   int       `json:"healthy_threshold" firestore:"healthy_threshold"`
	UnhealthyThreshold int       `json:"unhealthy_threshold" firestore:"unhealthy_threshold"`
}

// ServiceStatus represents the current status of a service
type ServiceStatus string

const (
	StatusHealthy    ServiceStatus = "healthy"
	StatusUnhealthy  ServiceStatus = "unhealthy"
	StatusStarting   ServiceStatus = "starting"
	StatusStopping   ServiceStatus = "stopping"
	StatusMaintenance ServiceStatus = "maintenance"
)

// ServiceFilter provides filtering options for service discovery
type ServiceFilter struct {
	ServiceName string
	Environment string
	Region      string
	Status      ServiceStatus
	Tags        []string
	Metadata    map[string]string
}

// NewServiceRegistry creates a new service registry
func NewServiceRegistry(firestoreClient *firestore.Client, redisClient *redis.Client, logger *logrus.Logger) *ServiceRegistry {
	return &ServiceRegistry{
		firestoreClient:   firestoreClient,
		redisClient:       redisClient,
		logger:            logger,
		localCache:        make(map[string]*ServiceInfo),
		cacheExpiry:       5 * time.Minute,
		heartbeatInterval: 30 * time.Second,
	}
}

// RegisterService registers a new service with the registry
func (sr *ServiceRegistry) RegisterService(ctx context.Context, service *ServiceInfo) error {
	sr.logger.WithFields(logrus.Fields{
		"service_id":   service.ServiceID,
		"service_name": service.ServiceName,
		"version":      service.Version,
		"environment":  service.Environment,
	}).Info("Registering service")

	// Set registration timestamp
	service.RegisteredAt = time.Now()
	service.LastHeartbeat = time.Now()
	service.Status = StatusStarting

	// Validate service info
	if err := sr.validateServiceInfo(service); err != nil {
		return fmt.Errorf("service validation failed: %v", err)
	}

	// Store in Firestore for persistence
	if err := sr.storeServiceInFirestore(ctx, service); err != nil {
		sr.logger.WithError(err).Error("Failed to store service in Firestore")
		return fmt.Errorf("failed to persist service registration: %v", err)
	}

	// Cache in Redis for fast lookup
	if err := sr.cacheServiceInRedis(ctx, service); err != nil {
		sr.logger.WithError(err).Warn("Failed to cache service in Redis")
		// Don't fail registration if Redis caching fails
	}

	// Update local cache
	sr.mu.Lock()
	sr.localCache[service.ServiceID] = service
	sr.mu.Unlock()

	sr.logger.WithFields(logrus.Fields{
		"service_id":   service.ServiceID,
		"service_name": service.ServiceName,
	}).Info("Service registered successfully")

	return nil
}

// UnregisterService removes a service from the registry
func (sr *ServiceRegistry) UnregisterService(ctx context.Context, serviceID string) error {
	sr.logger.WithField("service_id", serviceID).Info("Unregistering service")

	// Remove from Firestore
	if err := sr.removeServiceFromFirestore(ctx, serviceID); err != nil {
		sr.logger.WithError(err).Error("Failed to remove service from Firestore")
		return fmt.Errorf("failed to remove service from persistent storage: %v", err)
	}

	// Remove from Redis
	if err := sr.removeServiceFromRedis(ctx, serviceID); err != nil {
		sr.logger.WithError(err).Warn("Failed to remove service from Redis")
	}

	// Remove from local cache
	sr.mu.Lock()
	delete(sr.localCache, serviceID)
	sr.mu.Unlock()

	sr.logger.WithField("service_id", serviceID).Info("Service unregistered successfully")
	return nil
}

// DiscoverServices finds services based on filter criteria
func (sr *ServiceRegistry) DiscoverServices(ctx context.Context, filter *ServiceFilter) ([]*ServiceInfo, error) {
	sr.logger.WithFields(logrus.Fields{
		"service_name": filter.ServiceName,
		"environment":  filter.Environment,
		"region":       filter.Region,
		"status":       filter.Status,
	}).Debug("Discovering services")

	// Try Redis cache first
	services, err := sr.discoverFromRedis(ctx, filter)
	if err == nil && len(services) > 0 {
		sr.logger.WithField("count", len(services)).Debug("Services discovered from Redis cache")
		return services, nil
	}

	// Fallback to Firestore
	services, err = sr.discoverFromFirestore(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("service discovery failed: %v", err)
	}

	// Cache results in Redis for future queries
	go sr.cacheDiscoveryResults(ctx, filter, services)

	sr.logger.WithField("count", len(services)).Debug("Services discovered from Firestore")
	return services, nil
}

// GetService retrieves a specific service by ID
func (sr *ServiceRegistry) GetService(ctx context.Context, serviceID string) (*ServiceInfo, error) {
	// Check local cache first
	sr.mu.RLock()
	if service, exists := sr.localCache[serviceID]; exists {
		sr.mu.RUnlock()
		return service, nil
	}
	sr.mu.RUnlock()

	// Try Redis cache
	service, err := sr.getServiceFromRedis(ctx, serviceID)
	if err == nil && service != nil {
		// Update local cache
		sr.mu.Lock()
		sr.localCache[serviceID] = service
		sr.mu.Unlock()
		return service, nil
	}

	// Fallback to Firestore
	service, err = sr.getServiceFromFirestore(ctx, serviceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %v", err)
	}

	// Update caches
	go sr.cacheServiceInRedis(ctx, service)
	sr.mu.Lock()
	sr.localCache[serviceID] = service
	sr.mu.Unlock()

	return service, nil
}

// UpdateServiceStatus updates the status of a service
func (sr *ServiceRegistry) UpdateServiceStatus(ctx context.Context, serviceID string, status ServiceStatus) error {
	service, err := sr.GetService(ctx, serviceID)
	if err != nil {
		return fmt.Errorf("service not found: %v", err)
	}

	service.Status = status
	service.LastHeartbeat = time.Now()

	// Update in all storage layers
	if err := sr.storeServiceInFirestore(ctx, service); err != nil {
		return fmt.Errorf("failed to update service status: %v", err)
	}

	go sr.cacheServiceInRedis(ctx, service)

	sr.mu.Lock()
	sr.localCache[serviceID] = service
	sr.mu.Unlock()

	sr.logger.WithFields(logrus.Fields{
		"service_id": serviceID,
		"status":     status,
	}).Info("Service status updated")

	return nil
}

// Heartbeat updates the last heartbeat timestamp for a service
func (sr *ServiceRegistry) Heartbeat(ctx context.Context, serviceID string) error {
	return sr.UpdateServiceStatus(ctx, serviceID, StatusHealthy)
}

// StartHeartbeat starts automatic heartbeat for a service
func (sr *ServiceRegistry) StartHeartbeat(ctx context.Context, serviceID string) {
	ticker := time.NewTicker(sr.heartbeatInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				sr.logger.WithField("service_id", serviceID).Info("Stopping heartbeat")
				return
			case <-ticker.C:
				if err := sr.Heartbeat(ctx, serviceID); err != nil {
					sr.logger.WithError(err).WithField("service_id", serviceID).Error("Heartbeat failed")
				}
			}
		}
	}()
}

// GetServiceEndpoint returns a specific endpoint for a service
func (sr *ServiceRegistry) GetServiceEndpoint(ctx context.Context, serviceName, endpointName string) (*ServiceEndpoint, error) {
	filter := &ServiceFilter{
		ServiceName: serviceName,
		Status:      StatusHealthy,
	}

	services, err := sr.DiscoverServices(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to discover service: %v", err)
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("service not found: %s", serviceName)
	}

	// Find the endpoint in the first healthy service
	for _, service := range services {
		for _, endpoint := range service.Endpoints {
			if endpoint.Name == endpointName {
				return &endpoint, nil
			}
		}
	}

	return nil, fmt.Errorf("endpoint not found: %s in service %s", endpointName, serviceName)
}

// LoadBalanceEndpoint returns an endpoint using round-robin load balancing
func (sr *ServiceRegistry) LoadBalanceEndpoint(ctx context.Context, serviceName, endpointName string) (*ServiceEndpoint, error) {
	filter := &ServiceFilter{
		ServiceName: serviceName,
		Status:      StatusHealthy,
	}

	services, err := sr.DiscoverServices(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to discover services: %v", err)
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no healthy services found: %s", serviceName)
	}

	// Simple round-robin selection
	serviceIndex := int(time.Now().UnixNano()) % len(services)
	selectedService := services[serviceIndex]

	// Find the endpoint
	for _, endpoint := range selectedService.Endpoints {
		if endpoint.Name == endpointName {
			return &endpoint, nil
		}
	}

	return nil, fmt.Errorf("endpoint not found: %s in service %s", endpointName, serviceName)
}

// PerformHealthChecks runs health checks on all registered services
func (sr *ServiceRegistry) PerformHealthChecks(ctx context.Context) {
	sr.logger.Info("Starting health checks")

	services, err := sr.DiscoverServices(ctx, &ServiceFilter{})
	if err != nil {
		sr.logger.WithError(err).Error("Failed to discover services for health checks")
		return
	}

	for _, service := range services {
		if service.HealthCheck.Enabled {
			go sr.performServiceHealthCheck(ctx, service)
		}
	}
}

// Private helper methods

func (sr *ServiceRegistry) validateServiceInfo(service *ServiceInfo) error {
	if service.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}
	if service.ServiceName == "" {
		return fmt.Errorf("service_name is required")
	}
	if service.Version == "" {
		return fmt.Errorf("version is required")
	}
	if len(service.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint is required")
	}
	return nil
}

func (sr *ServiceRegistry) storeServiceInFirestore(ctx context.Context, service *ServiceInfo) error {
	_, err := sr.firestoreClient.Collection("services").Doc(service.ServiceID).Set(ctx, service)
	return err
}

func (sr *ServiceRegistry) removeServiceFromFirestore(ctx context.Context, serviceID string) error {
	_, err := sr.firestoreClient.Collection("services").Doc(serviceID).Delete(ctx)
	return err
}

func (sr *ServiceRegistry) getServiceFromFirestore(ctx context.Context, serviceID string) (*ServiceInfo, error) {
	doc, err := sr.firestoreClient.Collection("services").Doc(serviceID).Get(ctx)
	if err != nil {
		return nil, err
	}

	var service ServiceInfo
	if err := doc.DataTo(&service); err != nil {
		return nil, err
	}

	return &service, nil
}

func (sr *ServiceRegistry) discoverFromFirestore(ctx context.Context, filter *ServiceFilter) ([]*ServiceInfo, error) {
	query := sr.firestoreClient.Collection("services").Query

	// Apply filters
	if filter.ServiceName != "" {
		query = query.Where("service_name", "==", filter.ServiceName)
	}
	if filter.Environment != "" {
		query = query.Where("environment", "==", filter.Environment)
	}
	if filter.Region != "" {
		query = query.Where("region", "==", filter.Region)
	}
	if filter.Status != "" {
		query = query.Where("status", "==", string(filter.Status))
	}

	docs, err := query.Documents(ctx).GetAll()
	if err != nil {
		return nil, err
	}

	var services []*ServiceInfo
	for _, doc := range docs {
		var service ServiceInfo
		if err := doc.DataTo(&service); err != nil {
			sr.logger.WithError(err).Warn("Failed to parse service document")
			continue
		}
		services = append(services, &service)
	}

	return services, nil
}

func (sr *ServiceRegistry) cacheServiceInRedis(ctx context.Context, service *ServiceInfo) error {
	key := fmt.Sprintf("service:%s", service.ServiceID)
	data, err := json.Marshal(service)
	if err != nil {
		return err
	}

	return sr.redisClient.Set(ctx, key, data, sr.cacheExpiry).Err()
}

func (sr *ServiceRegistry) getServiceFromRedis(ctx context.Context, serviceID string) (*ServiceInfo, error) {
	key := fmt.Sprintf("service:%s", serviceID)
	data, err := sr.redisClient.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var service ServiceInfo
	if err := json.Unmarshal([]byte(data), &service); err != nil {
		return nil, err
	}

	return &service, nil
}

func (sr *ServiceRegistry) removeServiceFromRedis(ctx context.Context, serviceID string) error {
	key := fmt.Sprintf("service:%s", serviceID)
	return sr.redisClient.Del(ctx, key).Err()
}

func (sr *ServiceRegistry) discoverFromRedis(ctx context.Context, filter *ServiceFilter) ([]*ServiceInfo, error) {
	// This is a simplified implementation
	// In production, you might use Redis Streams or other patterns for efficient querying
	pattern := "service:*"
	keys, err := sr.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	var services []*ServiceInfo
	for _, key := range keys {
		service, err := sr.getServiceFromRedis(ctx, key[8:]) // Remove "service:" prefix
		if err != nil {
			continue
		}

		// Apply filters
		if filter.ServiceName != "" && service.ServiceName != filter.ServiceName {
			continue
		}
		if filter.Environment != "" && service.Environment != filter.Environment {
			continue
		}
		if filter.Region != "" && service.Region != filter.Region {
			continue
		}
		if filter.Status != "" && service.Status != filter.Status {
			continue
		}

		services = append(services, service)
	}

	return services, nil
}

func (sr *ServiceRegistry) cacheDiscoveryResults(ctx context.Context, filter *ServiceFilter, services []*ServiceInfo) {
	// Cache discovery results for faster subsequent queries
	key := fmt.Sprintf("discovery:%s:%s:%s:%s", filter.ServiceName, filter.Environment, filter.Region, filter.Status)
	data, err := json.Marshal(services)
	if err != nil {
		return
	}

	sr.redisClient.Set(ctx, key, data, 1*time.Minute) // Short cache for discovery results
}

func (sr *ServiceRegistry) performServiceHealthCheck(ctx context.Context, service *ServiceInfo) {
	if !service.HealthCheck.Enabled {
		return
	}

	client := &http.Client{
		Timeout: service.HealthCheck.Timeout,
	}

	// Find health check endpoint
	var healthURL string
	for _, endpoint := range service.Endpoints {
		if endpoint.Name == "health" || endpoint.Path == service.HealthCheck.Path {
			healthURL = endpoint.URL + service.HealthCheck.Path
			break
		}
	}

	if healthURL == "" {
		sr.logger.WithField("service_id", service.ServiceID).Warn("No health check endpoint found")
		return
	}

	resp, err := client.Get(healthURL)
	if err != nil {
		sr.logger.WithError(err).WithField("service_id", service.ServiceID).Warn("Health check failed")
		sr.UpdateServiceStatus(ctx, service.ServiceID, StatusUnhealthy)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		sr.UpdateServiceStatus(ctx, service.ServiceID, StatusHealthy)
	} else {
		sr.logger.WithFields(logrus.Fields{
			"service_id":  service.ServiceID,
			"status_code": resp.StatusCode,
		}).Warn("Health check returned non-200 status")
		sr.UpdateServiceStatus(ctx, service.ServiceID, StatusUnhealthy)
	}
}