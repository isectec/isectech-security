package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// EventEnrichmentService provides comprehensive event enrichment capabilities
type EventEnrichmentService struct {
	logger                 *zap.Logger
	config                 *EnrichmentServiceConfig
	
	// External service clients
	httpClient             *http.Client
	threatIntelClients     map[string]*ThreatIntelClient
	geolocationClient      *GeolocationClient
	assetInventoryClient   *AssetInventoryClient
	userBehaviorClient     *UserBehaviorClient
	
	// Caches
	geoLocationCache       *LRUCache
	threatIntelCache       *LRUCache
	assetInfoCache         *LRUCache
	userBehaviorCache      *LRUCache
	
	// Health status
	isHealthy              bool
	mu                     sync.RWMutex
}

// EnrichmentServiceConfig defines configuration for the enrichment service
type EnrichmentServiceConfig struct {
	ThreatIntelSources     []TISourceConfig  `json:"threat_intel_sources"`
	AssetInventoryURL      string            `json:"asset_inventory_url"`
	UserBehaviorServiceURL string            `json:"user_behavior_service_url"`
	GeolocationServiceURL  string            `json:"geolocation_service_url"`
	
	// Cache settings
	CacheSize              int               `json:"cache_size"`
	CacheTTL               time.Duration     `json:"cache_ttl"`
	
	// HTTP client settings
	RequestTimeout         time.Duration     `json:"request_timeout"`
	MaxRetries             int               `json:"max_retries"`
	RetryDelay             time.Duration     `json:"retry_delay"`
	
	// Enrichment options
	EnableThreatIntel      bool              `json:"enable_threat_intel"`
	EnableGeolocation      bool              `json:"enable_geolocation"`
	EnableAssetInfo        bool              `json:"enable_asset_info"`
	EnableUserBehavior     bool              `json:"enable_user_behavior"`
	EnableDNSResolution    bool              `json:"enable_dns_resolution"`
}

// ThreatIntelClient represents a threat intelligence client
type ThreatIntelClient struct {
	Name       string
	URL        string
	APIKey     string
	Priority   int
	HTTPClient *http.Client
	Logger     *zap.Logger
}

// GeolocationClient handles IP geolocation lookups
type GeolocationClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Logger     *zap.Logger
}

// AssetInventoryClient handles asset information lookups
type AssetInventoryClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Logger     *zap.Logger
}

// UserBehaviorClient handles user behavior baseline lookups
type UserBehaviorClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Logger     *zap.Logger
}

// LRUCache represents a simple LRU cache
type LRUCache struct {
	capacity int
	cache    map[string]*CacheEntry
	order    []string
	mu       sync.RWMutex
}

// CacheEntry represents a cache entry
type CacheEntry struct {
	Value     interface{} `json:"value"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// ThreatIntelResult represents threat intelligence lookup result
type ThreatIntelResult struct {
	Indicator    string                 `json:"indicator"`
	Type         string                 `json:"type"`
	IsMalicious  bool                   `json:"is_malicious"`
	Confidence   float64                `json:"confidence"`
	Sources      []string               `json:"sources"`
	Categories   []string               `json:"categories"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// GeolocationResult represents geolocation lookup result
type GeolocationResult struct {
	IP           string  `json:"ip"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
	ASN          string  `json:"asn"`
	IsVPN        bool    `json:"is_vpn"`
	IsTor        bool    `json:"is_tor"`
}

// AssetInfoResult represents asset information lookup result
type AssetInfoResult struct {
	AssetID     string                 `json:"asset_id"`
	AssetName   string                 `json:"asset_name"`
	AssetType   string                 `json:"asset_type"`
	Criticality string                 `json:"criticality"`
	Owner       string                 `json:"owner"`
	Department  string                 `json:"department"`
	Environment string                 `json:"environment"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// UserBehaviorResult represents user behavior baseline result
type UserBehaviorResult struct {
	UserID           string                 `json:"user_id"`
	Username         string                 `json:"username"`
	NormalLocations  []string               `json:"normal_locations"`
	NormalHours      []int                  `json:"normal_hours"`
	NormalDevices    []string               `json:"normal_devices"`
	RiskScore        float64                `json:"risk_score"`
	LastActivity     time.Time              `json:"last_activity"`
	BaselineMetadata map[string]interface{} `json:"baseline_metadata"`
}

// NewEventEnrichmentService creates a new event enrichment service
func NewEventEnrichmentService(logger *zap.Logger, config *EnrichmentServiceConfig) (*EventEnrichmentService, error) {
	if config == nil {
		return nil, fmt.Errorf("enrichment service configuration is required")
	}
	
	// Set defaults
	if config.CacheSize == 0 {
		config.CacheSize = 10000
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 30 * time.Minute
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	
	service := &EventEnrichmentService{
		logger:    logger.With(zap.String("component", "enrichment-service")),
		config:    config,
		isHealthy: true,
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
		},
		threatIntelClients: make(map[string]*ThreatIntelClient),
	}
	
	// Initialize caches
	service.geoLocationCache = NewLRUCache(config.CacheSize)
	service.threatIntelCache = NewLRUCache(config.CacheSize)
	service.assetInfoCache = NewLRUCache(config.CacheSize)
	service.userBehaviorCache = NewLRUCache(config.CacheSize)
	
	// Initialize threat intelligence clients
	for _, tiSource := range config.ThreatIntelSources {
		if tiSource.Enabled {
			client := &ThreatIntelClient{
				Name:       tiSource.Name,
				URL:        tiSource.URL,
				APIKey:     tiSource.APIKey,
				Priority:   tiSource.Priority,
				HTTPClient: service.httpClient,
				Logger:     logger.With(zap.String("ti_source", tiSource.Name)),
			}
			service.threatIntelClients[tiSource.Name] = client
		}
	}
	
	// Initialize geolocation client
	if config.EnableGeolocation && config.GeolocationServiceURL != "" {
		service.geolocationClient = &GeolocationClient{
			BaseURL:    config.GeolocationServiceURL,
			HTTPClient: service.httpClient,
			Logger:     logger.With(zap.String("client", "geolocation")),
		}
	}
	
	// Initialize asset inventory client
	if config.EnableAssetInfo && config.AssetInventoryURL != "" {
		service.assetInventoryClient = &AssetInventoryClient{
			BaseURL:    config.AssetInventoryURL,
			HTTPClient: service.httpClient,
			Logger:     logger.With(zap.String("client", "asset-inventory")),
		}
	}
	
	// Initialize user behavior client
	if config.EnableUserBehavior && config.UserBehaviorServiceURL != "" {
		service.userBehaviorClient = &UserBehaviorClient{
			BaseURL:    config.UserBehaviorServiceURL,
			HTTPClient: service.httpClient,
			Logger:     logger.With(zap.String("client", "user-behavior")),
		}
	}
	
	logger.Info("Event enrichment service initialized",
		zap.Int("threat_intel_sources", len(service.threatIntelClients)),
		zap.Bool("geolocation_enabled", config.EnableGeolocation),
		zap.Bool("asset_info_enabled", config.EnableAssetInfo),
		zap.Bool("user_behavior_enabled", config.EnableUserBehavior),
	)
	
	return service, nil
}

// EnrichEvent enriches an event with context data from various sources
func (s *EventEnrichmentService) EnrichEvent(ctx context.Context, event map[string]interface{}) (EnrichmentResult, error) {
	start := time.Now()
	result := make(EnrichmentResult)
	enrichedFields := make(map[string]interface{})
	
	s.logger.Debug("Starting event enrichment", zap.Any("event", event))
	
	// Extract key fields for enrichment
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Enrich IP addresses with geolocation and threat intelligence
	if ips := s.extractIPAddresses(event); len(ips) > 0 {
		for _, ip := range ips {
			wg.Add(1)
			go func(ipAddr string) {
				defer wg.Done()
				s.enrichIPAddress(ctx, ipAddr, &mu, enrichedFields)
			}(ip)
		}
	}
	
	// Enrich domains with threat intelligence and DNS resolution
	if domains := s.extractDomains(event); len(domains) > 0 {
		for _, domain := range domains {
			wg.Add(1)
			go func(domainName string) {
				defer wg.Done()
				s.enrichDomain(ctx, domainName, &mu, enrichedFields)
			}(domain)
		}
	}
	
	// Enrich file hashes with threat intelligence
	if hashes := s.extractFileHashes(event); len(hashes) > 0 {
		for _, hash := range hashes {
			wg.Add(1)
			go func(hashValue string) {
				defer wg.Done()
				s.enrichFileHash(ctx, hashValue, &mu, enrichedFields)
			}(hash)
		}
	}
	
	// Enrich user information
	if userID := s.extractString(event, "user_id"); userID != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.enrichUserInfo(ctx, userID, &mu, enrichedFields)
		}()
	}
	
	// Enrich asset information
	if assetID := s.extractString(event, "asset_id"); assetID != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.enrichAssetInfo(ctx, assetID, &mu, enrichedFields)
		}()
	}
	
	// Wait for all enrichment tasks to complete
	wg.Wait()
	
	// Add enriched fields to result
	result["enriched_fields"] = enrichedFields
	result["enrichment_duration"] = time.Since(start)
	result["enrichment_timestamp"] = time.Now()
	
	s.logger.Debug("Event enrichment completed",
		zap.Duration("duration", time.Since(start)),
		zap.Int("enriched_fields_count", len(enrichedFields)),
	)
	
	return result, nil
}

// enrichIPAddress enriches an IP address with geolocation and threat intelligence
func (s *EventEnrichmentService) enrichIPAddress(ctx context.Context, ip string, mu *sync.Mutex, enrichedFields map[string]interface{}) {
	// Geolocation enrichment
	if s.config.EnableGeolocation && s.geolocationClient != nil {
		if geoResult := s.lookupGeolocation(ctx, ip); geoResult != nil {
			mu.Lock()
			enrichedFields[fmt.Sprintf("geo_%s", ip)] = geoResult
			mu.Unlock()
		}
	}
	
	// Threat intelligence enrichment
	if s.config.EnableThreatIntel {
		if tiResults := s.lookupThreatIntel(ctx, ip, "ip"); len(tiResults) > 0 {
			mu.Lock()
			enrichedFields[fmt.Sprintf("threat_intel_%s", ip)] = tiResults
			mu.Unlock()
		}
	}
}

// enrichDomain enriches a domain with threat intelligence and DNS resolution
func (s *EventEnrichmentService) enrichDomain(ctx context.Context, domain string, mu *sync.Mutex, enrichedFields map[string]interface{}) {
	// DNS resolution
	if s.config.EnableDNSResolution {
		if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
			resolvedIPs := make([]string, len(ips))
			for i, ip := range ips {
				resolvedIPs[i] = ip.String()
			}
			mu.Lock()
			enrichedFields[fmt.Sprintf("dns_resolution_%s", domain)] = resolvedIPs
			mu.Unlock()
		}
	}
	
	// Threat intelligence enrichment
	if s.config.EnableThreatIntel {
		if tiResults := s.lookupThreatIntel(ctx, domain, "domain"); len(tiResults) > 0 {
			mu.Lock()
			enrichedFields[fmt.Sprintf("threat_intel_%s", domain)] = tiResults
			mu.Unlock()
		}
	}
}

// enrichFileHash enriches a file hash with threat intelligence
func (s *EventEnrichmentService) enrichFileHash(ctx context.Context, hash string, mu *sync.Mutex, enrichedFields map[string]interface{}) {
	if s.config.EnableThreatIntel {
		hashType := s.detectHashType(hash)
		if tiResults := s.lookupThreatIntel(ctx, hash, hashType); len(tiResults) > 0 {
			mu.Lock()
			enrichedFields[fmt.Sprintf("threat_intel_%s", hash)] = tiResults
			mu.Unlock()
		}
	}
}

// enrichUserInfo enriches user information with behavior baselines
func (s *EventEnrichmentService) enrichUserInfo(ctx context.Context, userID string, mu *sync.Mutex, enrichedFields map[string]interface{}) {
	if s.config.EnableUserBehavior && s.userBehaviorClient != nil {
		if behaviorResult := s.lookupUserBehavior(ctx, userID); behaviorResult != nil {
			mu.Lock()
			enrichedFields[fmt.Sprintf("user_behavior_%s", userID)] = behaviorResult
			mu.Unlock()
		}
	}
}

// enrichAssetInfo enriches asset information
func (s *EventEnrichmentService) enrichAssetInfo(ctx context.Context, assetID string, mu *sync.Mutex, enrichedFields map[string]interface{}) {
	if s.config.EnableAssetInfo && s.assetInventoryClient != nil {
		if assetResult := s.lookupAssetInfo(ctx, assetID); assetResult != nil {
			mu.Lock()
			enrichedFields[fmt.Sprintf("asset_info_%s", assetID)] = assetResult
			mu.Unlock()
		}
	}
}

// IsHealthy returns the health status of the enrichment service
func (s *EventEnrichmentService) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isHealthy
}

// Helper methods for data extraction

func (s *EventEnrichmentService) extractIPAddresses(event map[string]interface{}) []string {
	var ips []string
	
	// Extract from common IP fields
	fields := []string{"source_ip", "destination_ip", "client_ip", "server_ip", "remote_ip"}
	for _, field := range fields {
		if ip := s.extractString(event, field); ip != "" && net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}
	
	return s.deduplicateStrings(ips)
}

func (s *EventEnrichmentService) extractDomains(event map[string]interface{}) []string {
	var domains []string
	
	// Extract from common domain fields
	fields := []string{"domain", "hostname", "server_name", "dns_query", "url"}
	for _, field := range fields {
		if domain := s.extractString(event, field); domain != "" {
			domains = append(domains, domain)
		}
	}
	
	return s.deduplicateStrings(domains)
}

func (s *EventEnrichmentService) extractFileHashes(event map[string]interface{}) []string {
	var hashes []string
	
	// Extract from common hash fields
	fields := []string{"file_hash", "md5", "sha1", "sha256", "hash"}
	for _, field := range fields {
		if hash := s.extractString(event, field); hash != "" {
			hashes = append(hashes, hash)
		}
	}
	
	return s.deduplicateStrings(hashes)
}

func (s *EventEnrichmentService) extractString(event map[string]interface{}, field string) string {
	if value, exists := event[field]; exists {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}

func (s *EventEnrichmentService) deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func (s *EventEnrichmentService) detectHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return "hash"
	}
}