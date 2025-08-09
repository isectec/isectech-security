package service

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AssetDiscoveryMetrics contains all Prometheus metrics for the asset discovery service
type AssetDiscoveryMetrics struct {
	// Discovery metrics
	DiscoveryRequestsTotal    prometheus.Counter
	DiscoveryDuration        prometheus.Histogram
	DiscoveryErrors          prometheus.Counter
	DiscoveryActiveScans     prometheus.Gauge
	DiscoveryTargetsScanned  prometheus.Counter
	DiscoveryAssetsFound     prometheus.Counter

	// Asset metrics
	AssetsTotal              prometheus.Gauge
	AssetsByType             *prometheus.GaugeVec
	AssetsByStatus           *prometheus.GaugeVec
	AssetsByRiskLevel        *prometheus.GaugeVec
	AssetOperations          *prometheus.CounterVec
	AssetOperationDuration   *prometheus.HistogramVec

	// Network scanning metrics
	NetworkScansTotal        prometheus.Counter
	NetworkScanDuration      prometheus.Histogram
	NetworkScanErrors        prometheus.Counter
	PortsScanned             prometheus.Counter
	ServicesDetected         prometheus.Counter

	// Repository metrics
	DatabaseOperations       *prometheus.CounterVec
	DatabaseDuration         *prometheus.HistogramVec
	DatabaseErrors           *prometheus.CounterVec
	DatabaseConnections      prometheus.Gauge

	// Cache metrics
	CacheOperations          *prometheus.CounterVec
	CacheDuration            *prometheus.HistogramVec
	CacheHits                prometheus.Counter
	CacheMisses              prometheus.Counter
	CacheErrors              prometheus.Counter

	// HTTP API metrics
	HTTPRequestsTotal        *prometheus.CounterVec
	HTTPRequestDuration      *prometheus.HistogramVec
	HTTPActiveConnections    prometheus.Gauge

	// gRPC API metrics
	GRPCRequestsTotal        *prometheus.CounterVec
	GRPCRequestDuration      *prometheus.HistogramVec
	GRPCActiveConnections    prometheus.Gauge

	// System metrics
	MemoryUsage              prometheus.Gauge
	CPUUsage                 prometheus.Gauge
	GoroutinesCount          prometheus.Gauge
	GCDuration               prometheus.Histogram

	// Business metrics
	VulnerabilitiesDetected  *prometheus.CounterVec
	ComplianceScore          *prometheus.GaugeVec
	SecurityIncidents        prometheus.Counter
	AlertsGenerated          *prometheus.CounterVec
}

// NewAssetDiscoveryMetrics creates a new metrics instance
func NewAssetDiscoveryMetrics() *AssetDiscoveryMetrics {
	return &AssetDiscoveryMetrics{
		// Discovery metrics
		DiscoveryRequestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "asset_discovery_requests_total",
			Help: "Total number of asset discovery requests",
		}),

		DiscoveryDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "asset_discovery_duration_seconds",
			Help:    "Duration of asset discovery operations in seconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1s to ~17 minutes
		}),

		DiscoveryErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "asset_discovery_errors_total",
			Help: "Total number of asset discovery errors",
		}),

		DiscoveryActiveScans: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "asset_discovery_active_scans",
			Help: "Number of currently active discovery scans",
		}),

		DiscoveryTargetsScanned: promauto.NewCounter(prometheus.CounterOpts{
			Name: "asset_discovery_targets_scanned_total",
			Help: "Total number of targets scanned",
		}),

		DiscoveryAssetsFound: promauto.NewCounter(prometheus.CounterOpts{
			Name: "asset_discovery_assets_found_total",
			Help: "Total number of assets found during discovery",
		}),

		// Asset metrics
		AssetsTotal: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "assets_total",
			Help: "Total number of assets in the system",
		}),

		AssetsByType: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "assets_by_type",
			Help: "Number of assets grouped by type",
		}, []string{"tenant_id", "asset_type"}),

		AssetsByStatus: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "assets_by_status",
			Help: "Number of assets grouped by status",
		}, []string{"tenant_id", "status"}),

		AssetsByRiskLevel: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "assets_by_risk_level",
			Help: "Number of assets grouped by risk level",
		}, []string{"tenant_id", "risk_level"}),

		AssetOperations: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "asset_operations_total",
			Help: "Total number of asset operations",
		}, []string{"operation", "status"}),

		AssetOperationDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "asset_operation_duration_seconds",
			Help:    "Duration of asset operations in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),

		// Network scanning metrics
		NetworkScansTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_scans_total",
			Help: "Total number of network scans performed",
		}),

		NetworkScanDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_scan_duration_seconds",
			Help:    "Duration of network scans in seconds",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10), // 0.1s to ~2 minutes
		}),

		NetworkScanErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_scan_errors_total",
			Help: "Total number of network scan errors",
		}),

		PortsScanned: promauto.NewCounter(prometheus.CounterOpts{
			Name: "ports_scanned_total",
			Help: "Total number of ports scanned",
		}),

		ServicesDetected: promauto.NewCounter(prometheus.CounterOpts{
			Name: "services_detected_total",
			Help: "Total number of services detected",
		}),

		// Repository metrics
		DatabaseOperations: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "database_operations_total",
			Help: "Total number of database operations",
		}, []string{"operation", "table", "status"}),

		DatabaseDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "database_operation_duration_seconds",
			Help:    "Duration of database operations in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation", "table"}),

		DatabaseErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "database_errors_total",
			Help: "Total number of database errors",
		}, []string{"operation", "table", "error_type"}),

		DatabaseConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "database_connections_active",
			Help: "Number of active database connections",
		}),

		// Cache metrics
		CacheOperations: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "cache_operations_total",
			Help: "Total number of cache operations",
		}, []string{"operation", "status"}),

		CacheDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cache_operation_duration_seconds",
			Help:    "Duration of cache operations in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1 second
		}, []string{"operation"}),

		CacheHits: promauto.NewCounter(prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits",
		}),

		CacheMisses: promauto.NewCounter(prometheus.CounterOpts{
			Name: "cache_misses_total",
			Help: "Total number of cache misses",
		}),

		CacheErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "cache_errors_total",
			Help: "Total number of cache errors",
		}),

		// HTTP API metrics
		HTTPRequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		}, []string{"method", "endpoint", "status_code"}),

		HTTPRequestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "endpoint"}),

		HTTPActiveConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "http_active_connections",
			Help: "Number of active HTTP connections",
		}),

		// gRPC API metrics
		GRPCRequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "grpc_requests_total",
			Help: "Total number of gRPC requests",
		}, []string{"method", "status"}),

		GRPCRequestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "grpc_request_duration_seconds",
			Help:    "Duration of gRPC requests in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"method"}),

		GRPCActiveConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "grpc_active_connections",
			Help: "Number of active gRPC connections",
		}),

		// System metrics
		MemoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "memory_usage_bytes",
			Help: "Current memory usage in bytes",
		}),

		CPUUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "cpu_usage_percent",
			Help: "Current CPU usage percentage",
		}),

		GoroutinesCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "goroutines_count",
			Help: "Number of active goroutines",
		}),

		GCDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "gc_duration_seconds",
			Help:    "Duration of garbage collection in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}),

		// Business metrics
		VulnerabilitiesDetected: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "vulnerabilities_detected_total",
			Help: "Total number of vulnerabilities detected",
		}, []string{"severity", "asset_type"}),

		ComplianceScore: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "compliance_score",
			Help: "Compliance score by framework",
		}, []string{"tenant_id", "framework"}),

		SecurityIncidents: promauto.NewCounter(prometheus.CounterOpts{
			Name: "security_incidents_total",
			Help: "Total number of security incidents detected",
		}),

		AlertsGenerated: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "alerts_generated_total",
			Help: "Total number of alerts generated",
		}, []string{"alert_type", "severity"}),
	}
}

// RecordDiscoveryRequest records a discovery request
func (m *AssetDiscoveryMetrics) RecordDiscoveryRequest() {
	m.DiscoveryRequestsTotal.Inc()
}

// RecordDiscoveryDuration records the duration of a discovery operation
func (m *AssetDiscoveryMetrics) RecordDiscoveryDuration(duration float64) {
	m.DiscoveryDuration.Observe(duration)
}

// RecordDiscoveryError records a discovery error
func (m *AssetDiscoveryMetrics) RecordDiscoveryError() {
	m.DiscoveryErrors.Inc()
}

// SetActiveScans sets the number of active scans
func (m *AssetDiscoveryMetrics) SetActiveScans(count float64) {
	m.DiscoveryActiveScans.Set(count)
}

// RecordTargetsScanned records the number of targets scanned
func (m *AssetDiscoveryMetrics) RecordTargetsScanned(count float64) {
	m.DiscoveryTargetsScanned.Add(count)
}

// RecordAssetsFound records the number of assets found
func (m *AssetDiscoveryMetrics) RecordAssetsFound(count float64) {
	m.DiscoveryAssetsFound.Add(count)
}

// SetTotalAssets sets the total number of assets
func (m *AssetDiscoveryMetrics) SetTotalAssets(count float64) {
	m.AssetsTotal.Set(count)
}

// SetAssetsByType sets the number of assets by type
func (m *AssetDiscoveryMetrics) SetAssetsByType(tenantID, assetType string, count float64) {
	m.AssetsByType.WithLabelValues(tenantID, assetType).Set(count)
}

// SetAssetsByStatus sets the number of assets by status
func (m *AssetDiscoveryMetrics) SetAssetsByStatus(tenantID, status string, count float64) {
	m.AssetsByStatus.WithLabelValues(tenantID, status).Set(count)
}

// SetAssetsByRiskLevel sets the number of assets by risk level
func (m *AssetDiscoveryMetrics) SetAssetsByRiskLevel(tenantID, riskLevel string, count float64) {
	m.AssetsByRiskLevel.WithLabelValues(tenantID, riskLevel).Set(count)
}

// RecordAssetOperation records an asset operation
func (m *AssetDiscoveryMetrics) RecordAssetOperation(operation, status string) {
	m.AssetOperations.WithLabelValues(operation, status).Inc()
}

// RecordAssetOperationDuration records the duration of an asset operation
func (m *AssetDiscoveryMetrics) RecordAssetOperationDuration(operation string, duration float64) {
	m.AssetOperationDuration.WithLabelValues(operation).Observe(duration)
}

// RecordNetworkScan records a network scan
func (m *AssetDiscoveryMetrics) RecordNetworkScan() {
	m.NetworkScansTotal.Inc()
}

// RecordNetworkScanDuration records the duration of a network scan
func (m *AssetDiscoveryMetrics) RecordNetworkScanDuration(duration float64) {
	m.NetworkScanDuration.Observe(duration)
}

// RecordNetworkScanError records a network scan error
func (m *AssetDiscoveryMetrics) RecordNetworkScanError() {
	m.NetworkScanErrors.Inc()
}

// RecordPortsScanned records the number of ports scanned
func (m *AssetDiscoveryMetrics) RecordPortsScanned(count float64) {
	m.PortsScanned.Add(count)
}

// RecordServicesDetected records the number of services detected
func (m *AssetDiscoveryMetrics) RecordServicesDetected(count float64) {
	m.ServicesDetected.Add(count)
}

// RecordDatabaseOperation records a database operation
func (m *AssetDiscoveryMetrics) RecordDatabaseOperation(operation, table, status string) {
	m.DatabaseOperations.WithLabelValues(operation, table, status).Inc()
}

// RecordDatabaseDuration records the duration of a database operation
func (m *AssetDiscoveryMetrics) RecordDatabaseDuration(operation, table string, duration float64) {
	m.DatabaseDuration.WithLabelValues(operation, table).Observe(duration)
}

// RecordDatabaseError records a database error
func (m *AssetDiscoveryMetrics) RecordDatabaseError(operation, table, errorType string) {
	m.DatabaseErrors.WithLabelValues(operation, table, errorType).Inc()
}

// SetDatabaseConnections sets the number of active database connections
func (m *AssetDiscoveryMetrics) SetDatabaseConnections(count float64) {
	m.DatabaseConnections.Set(count)
}

// RecordCacheOperation records a cache operation
func (m *AssetDiscoveryMetrics) RecordCacheOperation(operation, status string) {
	m.CacheOperations.WithLabelValues(operation, status).Inc()
}

// RecordCacheDuration records the duration of a cache operation
func (m *AssetDiscoveryMetrics) RecordCacheDuration(operation string, duration float64) {
	m.CacheDuration.WithLabelValues(operation).Observe(duration)
}

// RecordCacheHit records a cache hit
func (m *AssetDiscoveryMetrics) RecordCacheHit() {
	m.CacheHits.Inc()
}

// RecordCacheMiss records a cache miss
func (m *AssetDiscoveryMetrics) RecordCacheMiss() {
	m.CacheMisses.Inc()
}

// RecordCacheError records a cache error
func (m *AssetDiscoveryMetrics) RecordCacheError() {
	m.CacheErrors.Inc()
}

// RecordHTTPRequest records an HTTP request
func (m *AssetDiscoveryMetrics) RecordHTTPRequest(method, endpoint, statusCode string) {
	m.HTTPRequestsTotal.WithLabelValues(method, endpoint, statusCode).Inc()
}

// RecordHTTPRequestDuration records the duration of an HTTP request
func (m *AssetDiscoveryMetrics) RecordHTTPRequestDuration(method, endpoint string, duration float64) {
	m.HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration)
}

// SetHTTPActiveConnections sets the number of active HTTP connections
func (m *AssetDiscoveryMetrics) SetHTTPActiveConnections(count float64) {
	m.HTTPActiveConnections.Set(count)
}

// RecordGRPCRequest records a gRPC request
func (m *AssetDiscoveryMetrics) RecordGRPCRequest(method, status string) {
	m.GRPCRequestsTotal.WithLabelValues(method, status).Inc()
}

// RecordGRPCRequestDuration records the duration of a gRPC request
func (m *AssetDiscoveryMetrics) RecordGRPCRequestDuration(method string, duration float64) {
	m.GRPCRequestDuration.WithLabelValues(method).Observe(duration)
}

// SetGRPCActiveConnections sets the number of active gRPC connections
func (m *AssetDiscoveryMetrics) SetGRPCActiveConnections(count float64) {
	m.GRPCActiveConnections.Set(count)
}

// SetMemoryUsage sets the current memory usage
func (m *AssetDiscoveryMetrics) SetMemoryUsage(bytes float64) {
	m.MemoryUsage.Set(bytes)
}

// SetCPUUsage sets the current CPU usage percentage
func (m *AssetDiscoveryMetrics) SetCPUUsage(percent float64) {
	m.CPUUsage.Set(percent)
}

// SetGoroutinesCount sets the number of active goroutines
func (m *AssetDiscoveryMetrics) SetGoroutinesCount(count float64) {
	m.GoroutinesCount.Set(count)
}

// RecordGCDuration records the duration of garbage collection
func (m *AssetDiscoveryMetrics) RecordGCDuration(duration float64) {
	m.GCDuration.Observe(duration)
}

// RecordVulnerabilityDetected records a detected vulnerability
func (m *AssetDiscoveryMetrics) RecordVulnerabilityDetected(severity, assetType string) {
	m.VulnerabilitiesDetected.WithLabelValues(severity, assetType).Inc()
}

// SetComplianceScore sets the compliance score for a framework
func (m *AssetDiscoveryMetrics) SetComplianceScore(tenantID, framework string, score float64) {
	m.ComplianceScore.WithLabelValues(tenantID, framework).Set(score)
}

// RecordSecurityIncident records a security incident
func (m *AssetDiscoveryMetrics) RecordSecurityIncident() {
	m.SecurityIncidents.Inc()
}

// RecordAlertGenerated records an alert generation
func (m *AssetDiscoveryMetrics) RecordAlertGenerated(alertType, severity string) {
	m.AlertsGenerated.WithLabelValues(alertType, severity).Inc()
}