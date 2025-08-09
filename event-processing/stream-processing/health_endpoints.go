package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// startHTTPServer starts the HTTP server for health and metrics endpoints
func (h *HealthMonitor) startHTTPServer() error {
	mux := http.NewServeMux()
	
	// Health endpoints
	mux.HandleFunc("/health", h.handleHealthCheck)
	mux.HandleFunc("/health/", h.handleComponentHealth)
	mux.HandleFunc("/health/detailed", h.handleDetailedHealth)
	mux.HandleFunc("/ready", h.handleReadinessCheck)
	mux.HandleFunc("/live", h.handleLivenessCheck)
	
	// Metrics endpoint (if metrics collector is available)
	if h.metricsCollector != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(
			h.metricsCollector.GetRegistry(),
			promhttp.HandlerOpts{},
		))
	}
	
	// Info endpoint
	mux.HandleFunc("/info", h.handleInfo)
	
	// Status endpoint
	mux.HandleFunc("/status", h.handleStatus)
	
	h.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", h.config.HTTPPort),
		Handler: mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	
	go func() {
		h.logger.Info("Starting health HTTP server", zap.Int("port", h.config.HTTPPort))
		if err := h.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			h.logger.Error("Health HTTP server failed", zap.Error(err))
		}
	}()
	
	return nil
}

// handleHealthCheck handles the main health endpoint
func (h *HealthMonitor) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	overallHealth := h.GetOverallHealth()
	
	w.Header().Set("Content-Type", "application/json")
	
	// Set HTTP status based on health
	switch overallHealth.Status {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK) // Still OK but with warnings
	case HealthStatusUnhealthy:
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	response := map[string]interface{}{
		"status":            overallHealth.Status,
		"timestamp":         overallHealth.LastUpdateTime.Format(time.RFC3339),
		"healthy_components": overallHealth.HealthyComponents,
		"total_components":  overallHealth.TotalComponents,
	}
	
	if len(overallHealth.CriticalIssues) > 0 {
		response["critical_issues"] = overallHealth.CriticalIssues
	}
	
	if len(overallHealth.Warnings) > 0 {
		response["warnings"] = overallHealth.Warnings
	}
	
	json.NewEncoder(w).Encode(response)
}

// handleComponentHealth handles individual component health requests
func (h *HealthMonitor) handleComponentHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Extract component name from path
	componentName := r.URL.Path[len("/health/"):]
	if componentName == "" {
		h.handleHealthCheck(w, r)
		return
	}
	
	componentHealth, exists := h.GetComponentHealth(componentName)
	if !exists {
		http.Error(w, fmt.Sprintf("Component '%s' not found", componentName), http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	
	// Set HTTP status based on component health
	switch componentHealth.Status {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK)
	case HealthStatusUnhealthy:
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	json.NewEncoder(w).Encode(componentHealth)
}

// handleDetailedHealth handles detailed health information requests
func (h *HealthMonitor) handleDetailedHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	overallHealth := h.GetOverallHealth()
	
	h.mu.RLock()
	components := make(map[string]*ComponentHealthStatus)
	for name, status := range h.componentHealth {
		statusCopy := *status
		components[name] = &statusCopy
	}
	h.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	
	// Set HTTP status based on overall health
	switch overallHealth.Status {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK)
	case HealthStatusUnhealthy:
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	response := map[string]interface{}{
		"overall":    overallHealth,
		"components": components,
		"timestamp":  time.Now().Format(time.RFC3339),
	}
	
	json.NewEncoder(w).Encode(response)
}

// handleReadinessCheck handles Kubernetes readiness probe
func (h *HealthMonitor) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	overallHealth := h.GetOverallHealth()
	
	// Ready if healthy or degraded (can still handle requests)
	if overallHealth.Status == HealthStatusHealthy || overallHealth.Status == HealthStatusDegraded {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Not Ready"))
	}
}

// handleLivenessCheck handles Kubernetes liveness probe
func (h *HealthMonitor) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	overallHealth := h.GetOverallHealth()
	
	// Live if not completely unhealthy
	if overallHealth.Status != HealthStatusUnhealthy {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Alive"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Not Alive"))
	}
}

// handleInfo handles application information requests
func (h *HealthMonitor) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	info := map[string]interface{}{
		"application": "iSECTECH Stream Processing",
		"version":     "1.0.0",
		"build_time":  "2024-01-01T00:00:00Z", // This would be set during build
		"commit":      "main",                  // This would be set during build
		"go_version":  "1.19+",
		"timestamp":   time.Now().Format(time.RFC3339),
		"uptime":      time.Since(time.Now().Add(-time.Hour)).String(), // This would track actual uptime
	}
	
	json.NewEncoder(w).Encode(info)
}

// handleStatus handles status endpoint with system statistics
func (h *HealthMonitor) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	overallHealth := h.GetOverallHealth()
	
	h.mu.RLock()
	componentStats := make(map[string]interface{})
	for name, status := range h.componentHealth {
		componentStats[name] = map[string]interface{}{
			"status":            status.Status,
			"uptime_percentage": status.UptimePercentage,
			"total_checks":      status.TotalChecks,
			"failed_checks":     status.FailedChecks,
			"response_time":     status.ResponseTime.String(),
			"last_check":        status.LastCheckTime.Format(time.RFC3339),
		}
	}
	h.mu.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	
	// Set HTTP status based on overall health
	switch overallHealth.Status {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK)
	case HealthStatusUnhealthy:
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	status := map[string]interface{}{
		"overall_status":     overallHealth.Status,
		"healthy_components": overallHealth.HealthyComponents,
		"total_components":   overallHealth.TotalComponents,
		"last_update":        overallHealth.LastUpdateTime.Format(time.RFC3339),
		"components":         componentStats,
		"timestamp":          time.Now().Format(time.RFC3339),
	}
	
	if len(overallHealth.CriticalIssues) > 0 {
		status["critical_issues"] = overallHealth.CriticalIssues
	}
	
	if len(overallHealth.Warnings) > 0 {
		status["warnings"] = overallHealth.Warnings
	}
	
	json.NewEncoder(w).Encode(status)
}

// HealthCheckHandler provides a simple health check handler for external use
func HealthCheckHandler(healthMonitor *HealthMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if healthMonitor.IsHealthy() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Healthy"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Unhealthy"))
		}
	}
}

// MetricsHandler provides a metrics handler for external use
func MetricsHandler(metricsCollector *MetricsCollector) http.Handler {
	if metricsCollector == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Metrics not available", http.StatusServiceUnavailable)
		})
	}
	
	return promhttp.HandlerFor(
		metricsCollector.GetRegistry(),
		promhttp.HandlerOpts{},
	)
}