package usecase

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"asset-discovery/domain/entity"
	"asset-discovery/domain/repository"
	"asset-discovery/domain/service"
)

// AssetDiscoveryUseCase implements the asset discovery business logic
type AssetDiscoveryUseCase struct {
	assetRepo           repository.AssetRepository
	networkScanner      service.NetworkScannerService
	cloudDiscovery      service.CloudDiscoveryService
	enrichmentService   service.AssetEnrichmentService
	logger              *zap.Logger
	
	// Active discovery tracking
	activeScans         map[uuid.UUID]*service.ScanProgress
	activeScansLock     sync.RWMutex
	
	// Configuration
	maxConcurrentScans  int
	defaultScanTimeout  time.Duration
	defaultRetryAttempts int
	
	// Metrics
	totalScansStarted   int64
	totalScansCompleted int64
	totalScansFailed    int64
	totalAssetsFound    int64
}

// NewAssetDiscoveryUseCase creates a new asset discovery use case
func NewAssetDiscoveryUseCase(
	assetRepo repository.AssetRepository,
	networkScanner service.NetworkScannerService,
	cloudDiscovery service.CloudDiscoveryService,
	enrichmentService service.AssetEnrichmentService,
	logger *zap.Logger,
) *AssetDiscoveryUseCase {
	return &AssetDiscoveryUseCase{
		assetRepo:           assetRepo,
		networkScanner:      networkScanner,
		cloudDiscovery:      cloudDiscovery,
		enrichmentService:   enrichmentService,
		logger:              logger,
		activeScans:         make(map[uuid.UUID]*service.ScanProgress),
		maxConcurrentScans:  10,
		defaultScanTimeout:  30 * time.Minute,
		defaultRetryAttempts: 3,
	}
}

// StartDiscovery initiates a new asset discovery operation
func (uc *AssetDiscoveryUseCase) StartDiscovery(ctx context.Context, request service.DiscoveryRequest) (*service.DiscoveryResult, error) {
	uc.logger.Info("Starting asset discovery",
		zap.String("tenant_id", request.TenantID.String()),
		zap.Any("scope", request.TargetScope),
		zap.Any("methods", request.DiscoveryMethods),
	)

	// Validate the request
	if err := uc.validateDiscoveryRequest(request); err != nil {
		return nil, fmt.Errorf("invalid discovery request: %w", err)
	}

	// Check if we've reached the maximum concurrent scans
	uc.activeScansLock.RLock()
	activeCount := len(uc.activeScans)
	uc.activeScansLock.RUnlock()

	if activeCount >= uc.maxConcurrentScans {
		return nil, fmt.Errorf("maximum concurrent scans reached (%d)", uc.maxConcurrentScans)
	}

	// Create a new discovery result
	requestID := uuid.New()
	result := &service.DiscoveryResult{
		RequestID:   requestID,
		TenantID:    request.TenantID,
		Status:      service.DiscoveryStatusRunning,
		StartTime:   time.Now(),
		Assets:      make([]*entity.Asset, 0),
		Errors:      make([]service.DiscoveryError, 0),
		Warnings:    make([]service.DiscoveryWarning, 0),
		Statistics:  service.DiscoveryStatistics{
			MethodStats:    make(map[string]service.MethodStatistics),
			AssetTypeStats: make(map[string]int),
		},
		Metadata:    make(map[string]interface{}),
	}

	// Initialize scan progress tracking
	progress := &service.ScanProgress{
		RequestID:       requestID,
		Status:          service.DiscoveryStatusRunning,
		PercentComplete: 0,
		AssetsFound:     0,
		ElapsedTime:     0,
	}

	uc.activeScansLock.Lock()
	uc.activeScans[requestID] = progress
	uc.activeScansLock.Unlock()

	// Start the discovery process asynchronously for immediate response
	go uc.executeDiscovery(ctx, request, result, progress)

	uc.totalScansStarted++
	
	return result, nil
}

// executeDiscovery performs the actual discovery work
func (uc *AssetDiscoveryUseCase) executeDiscovery(ctx context.Context, request service.DiscoveryRequest, result *service.DiscoveryResult, progress *service.ScanProgress) {
	defer func() {
		// Clean up the active scan tracking
		uc.activeScansLock.Lock()
		delete(uc.activeScans, result.RequestID)
		uc.activeScansLock.Unlock()

		// Update final result
		endTime := time.Now()
		result.EndTime = &endTime
		result.Duration = endTime.Sub(result.StartTime)
		
		if result.Status == service.DiscoveryStatusRunning {
			result.Status = service.DiscoveryStatusCompleted
			uc.totalScansCompleted++
		}

		uc.logger.Info("Discovery completed",
			zap.String("request_id", result.RequestID.String()),
			zap.String("status", string(result.Status)),
			zap.Duration("duration", result.Duration),
			zap.Int("assets_found", result.AssetsFound),
		)
	}()

	// Create a timeout context
	timeout := uc.defaultScanTimeout
	if request.ScanOptions.Timeout > 0 {
		timeout = request.ScanOptions.Timeout
	}
	
	discoveryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Prepare targets based on the scope
	targets, err := uc.prepareTargets(discoveryCtx, request.TargetScope)
	if err != nil {
		uc.logger.Error("Failed to prepare targets", zap.Error(err))
		result.Status = service.DiscoveryStatusFailed
		result.Errors = append(result.Errors, service.DiscoveryError{
			Target:    "scope_preparation",
			Method:    "preparation",
			Error:     err.Error(),
			Timestamp: time.Now(),
			Severity:  "critical",
		})
		uc.totalScansFailed++
		return
	}

	progress.TargetsTotal = len(targets)
	uc.logger.Info("Prepared discovery targets", zap.Int("count", len(targets)))

	// Execute discovery methods
	allAssets := make([]*entity.Asset, 0)
	
	for _, method := range request.DiscoveryMethods {
		methodAssets, methodStats, methodErrors := uc.executeDiscoveryMethod(
			discoveryCtx, method, targets, request.ScanOptions, request.Credentials)
		
		allAssets = append(allAssets, methodAssets...)
		result.Statistics.MethodStats[string(method)] = methodStats
		result.Errors = append(result.Errors, methodErrors...)
		
		// Update progress
		progress.PercentComplete = float64(len(result.Statistics.MethodStats)) / float64(len(request.DiscoveryMethods)) * 100
		progress.AssetsFound = len(allAssets)
		progress.ElapsedTime = time.Since(result.StartTime)
	}

	// Deduplicate and correlate assets
	uniqueAssets := uc.deduplicateAssets(allAssets)
	uc.logger.Info("Deduplicated assets", 
		zap.Int("before", len(allAssets)), 
		zap.Int("after", len(uniqueAssets)))

	// Enrich assets with additional information
	enrichedAssets := uc.enrichAssets(discoveryCtx, uniqueAssets, request.ScanOptions)

	// Store discovered assets
	storedAssets, storeErrors := uc.storeAssets(discoveryCtx, request.TenantID, enrichedAssets)
	result.Errors = append(result.Errors, storeErrors...)

	// Calculate final statistics
	result.Assets = storedAssets
	result.AssetsFound = len(storedAssets)
	result.AssetsNew = uc.countNewAssets(storedAssets)
	result.AssetsUpdated = result.AssetsFound - result.AssetsNew
	result.TargetsScanned = len(targets)
	result.TargetsTotal = len(targets)
	result.SuccessRate = uc.calculateSuccessRate(result)

	// Update asset type statistics
	for _, asset := range storedAssets {
		result.Statistics.AssetTypeStats[string(asset.AssetType)]++
	}

	uc.totalAssetsFound += int64(result.AssetsFound)
	
	uc.logger.Info("Asset discovery completed successfully",
		zap.String("request_id", result.RequestID.String()),
		zap.Int("assets_found", result.AssetsFound),
		zap.Int("new_assets", result.AssetsNew),
		zap.Int("updated_assets", result.AssetsUpdated),
	)
}

// executeDiscoveryMethod executes a specific discovery method
func (uc *AssetDiscoveryUseCase) executeDiscoveryMethod(
	ctx context.Context, 
	method service.DiscoveryMethod,
	targets []string,
	options service.ScanOptions,
	credentials []service.Credential,
) ([]*entity.Asset, service.MethodStatistics, []service.DiscoveryError) {
	
	startTime := time.Now()
	var assets []*entity.Asset
	var err error
	var errors []service.DiscoveryError

	uc.logger.Debug("Executing discovery method",
		zap.String("method", string(method)),
		zap.Int("targets", len(targets)),
	)

	switch method {
	case service.DiscoveryMethodPing:
		assets, err = uc.networkScanner.PingScan(ctx, targets, options)
	case service.DiscoveryMethodPortScan:
		assets, err = uc.networkScanner.PortScan(ctx, targets, options)
	case service.DiscoveryMethodServiceScan:
		assets, err = uc.networkScanner.ServiceScan(ctx, targets, options)
	case service.DiscoveryMethodSNMP:
		assets, err = uc.executeSNMPDiscovery(ctx, targets, options, credentials)
	case service.DiscoveryMethodWMI:
		assets, err = uc.executeWMIDiscovery(ctx, targets, options, credentials)
	case service.DiscoveryMethodSSH:
		assets, err = uc.executeSSHDiscovery(ctx, targets, options, credentials)
	case service.DiscoveryMethodDNS:
		assets, err = uc.executeDNSDiscovery(ctx, targets, options)
	case service.DiscoveryMethodCloud:
		assets, err = uc.executeCloudDiscovery(ctx, targets, options, credentials)
	case service.DiscoveryMethodAgent:
		assets, err = uc.executeAgentDiscovery(ctx, targets, options, credentials)
	case service.DiscoveryMethodPassive:
		assets, err = uc.executePassiveDiscovery(ctx, targets, options)
	case service.DiscoveryMethodVulnScan:
		assets, err = uc.executeVulnerabilityDiscovery(ctx, targets, options, credentials)
	default:
		err = fmt.Errorf("unsupported discovery method: %s", method)
	}

	if err != nil {
		errors = append(errors, service.DiscoveryError{
			Target:    strings.Join(targets, ","),
			Method:    string(method),
			Error:     err.Error(),
			Timestamp: time.Now(),
			Severity:  "high",
		})
		assets = []*entity.Asset{} // Ensure we have an empty slice instead of nil
	}

	duration := time.Since(startTime)
	stats := service.MethodStatistics{
		TargetsScanned:  len(targets),
		AssetsFound:     len(assets),
		Errors:          len(errors),
		AvgResponseTime: duration,
		SuccessRate:     uc.calculateMethodSuccessRate(len(assets), len(targets), len(errors)),
	}

	return assets, stats, errors
}

// prepareTargets converts the discovery scope into specific targets
func (uc *AssetDiscoveryUseCase) prepareTargets(ctx context.Context, scope service.DiscoveryScope) ([]string, error) {
	var targets []string

	// Process IP ranges
	for _, ipRange := range scope.IPRanges {
		rangeTargets, err := uc.expandIPRange(ipRange)
		if err != nil {
			uc.logger.Warn("Failed to expand IP range", zap.String("range", ipRange), zap.Error(err))
			continue
		}
		targets = append(targets, rangeTargets...)
	}

	// Add specific hostnames
	targets = append(targets, scope.Hostnames...)

	// Process domains for DNS discovery
	for _, domain := range scope.Domains {
		domainTargets, err := uc.expandDomain(ctx, domain)
		if err != nil {
			uc.logger.Warn("Failed to expand domain", zap.String("domain", domain), zap.Error(err))
			continue
		}
		targets = append(targets, domainTargets...)
	}

	// Process subnets
	for _, subnet := range scope.Subnets {
		subnetTargets, err := uc.expandSubnet(subnet)
		if err != nil {
			uc.logger.Warn("Failed to expand subnet", zap.String("subnet", subnet), zap.Error(err))
			continue
		}
		targets = append(targets, subnetTargets...)
	}

	// Remove excluded ranges
	if len(scope.ExcludeRanges) > 0 {
		targets = uc.filterExcludedTargets(targets, scope.ExcludeRanges)
	}

	// Remove duplicates and sort
	targets = uc.removeDuplicateTargets(targets)
	sort.Strings(targets)

	uc.logger.Debug("Prepared targets", zap.Int("count", len(targets)))
	return targets, nil
}

// expandIPRange expands a CIDR range into individual IP addresses
func (uc *AssetDiscoveryUseCase) expandIPRange(ipRange string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		// Try parsing as a single IP
		if ip := net.ParseIP(ipRange); ip != nil {
			return []string{ipRange}, nil
		}
		return nil, fmt.Errorf("invalid IP range: %s", ipRange)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); uc.incrementIP(ip) {
		ips = append(ips, ip.String())
		
		// Prevent memory exhaustion for very large ranges
		if len(ips) > 65536 { // /16 network max
			uc.logger.Warn("IP range too large, truncating", 
				zap.String("range", ipRange), 
				zap.Int("truncated_to", len(ips)))
			break
		}
	}

	return ips, nil
}

// incrementIP increments an IP address
func (uc *AssetDiscoveryUseCase) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// expandDomain performs DNS resolution to find hosts in a domain
func (uc *AssetDiscoveryUseCase) expandDomain(ctx context.Context, domain string) ([]string, error) {
	var targets []string

	// Add the domain itself
	targets = append(targets, domain)

	// Try common subdomains
	commonSubdomains := []string{"www", "mail", "ftp", "admin", "api", "app", "db", "test", "dev", "staging"}
	for _, subdomain := range commonSubdomains {
		hostname := fmt.Sprintf("%s.%s", subdomain, domain)
		if _, err := net.LookupHost(hostname); err == nil {
			targets = append(targets, hostname)
		}
	}

	return targets, nil
}

// expandSubnet expands a subnet into individual IP addresses
func (uc *AssetDiscoveryUseCase) expandSubnet(subnet string) ([]string, error) {
	return uc.expandIPRange(subnet)
}

// filterExcludedTargets removes excluded IP ranges from targets
func (uc *AssetDiscoveryUseCase) filterExcludedTargets(targets []string, excludeRanges []string) []string {
	var filtered []string
	
	// Parse exclude ranges
	var excludeNets []*net.IPNet
	for _, excludeRange := range excludeRanges {
		_, ipNet, err := net.ParseCIDR(excludeRange)
		if err != nil {
			uc.logger.Warn("Invalid exclude range", zap.String("range", excludeRange))
			continue
		}
		excludeNets = append(excludeNets, ipNet)
	}

	// Filter targets
	for _, target := range targets {
		ip := net.ParseIP(target)
		if ip == nil {
			// Not an IP address, keep it
			filtered = append(filtered, target)
			continue
		}

		excluded := false
		for _, excludeNet := range excludeNets {
			if excludeNet.Contains(ip) {
				excluded = true
				break
			}
		}

		if !excluded {
			filtered = append(filtered, target)
		}
	}

	return filtered
}

// removeDuplicateTargets removes duplicate targets from the list
func (uc *AssetDiscoveryUseCase) removeDuplicateTargets(targets []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, target := range targets {
		if !seen[target] {
			seen[target] = true
			result = append(result, target)
		}
	}

	return result
}

// deduplicateAssets removes duplicate assets based on fingerprinting
func (uc *AssetDiscoveryUseCase) deduplicateAssets(assets []*entity.Asset) []*entity.Asset {
	fingerprints := make(map[string]*entity.Asset)
	var unique []*entity.Asset

	for _, asset := range assets {
		// Update fingerprint if not already set
		if asset.Fingerprint == "" {
			asset.UpdateFingerprint()
		}

		// Check if we've seen this fingerprint before
		if existing, exists := fingerprints[asset.Fingerprint]; exists {
			// Merge the assets (keep the one with more information)
			if uc.compareAssetCompleteness(asset, existing) > 0 {
				fingerprints[asset.Fingerprint] = asset
			}
		} else {
			fingerprints[asset.Fingerprint] = asset
		}
	}

	// Extract unique assets
	for _, asset := range fingerprints {
		unique = append(unique, asset)
	}

	return unique
}

// compareAssetCompleteness compares two assets and returns a score indicating which is more complete
func (uc *AssetDiscoveryUseCase) compareAssetCompleteness(a1, a2 *entity.Asset) int {
	score1 := uc.calculateAssetCompleteness(a1)
	score2 := uc.calculateAssetCompleteness(a2)
	
	if score1 > score2 {
		return 1
	} else if score1 < score2 {
		return -1
	}
	return 0
}

// calculateAssetCompleteness calculates a completeness score for an asset
func (uc *AssetDiscoveryUseCase) calculateAssetCompleteness(asset *entity.Asset) int {
	score := 0

	// Basic information
	if asset.Name != "" { score++ }
	if asset.Description != "" { score++ }
	if asset.AssetType != "" { score++ }

	// Network information
	if asset.NetworkInfo != nil {
		if asset.NetworkInfo.IPAddress != "" { score += 2 }
		if asset.NetworkInfo.MACAddress != "" { score += 2 }
		if asset.NetworkInfo.Hostname != "" { score++ }
		if len(asset.NetworkInfo.OpenPorts) > 0 { score += 3 }
	}

	// System information
	if asset.SystemInfo != nil {
		if asset.SystemInfo.OperatingSystem != "" { score += 2 }
		if asset.SystemInfo.OSVersion != "" { score++ }
		if len(asset.SystemInfo.InstalledSoftware) > 0 { score += 3 }
		if len(asset.SystemInfo.Services) > 0 { score += 2 }
	}

	// Security information
	if asset.SecurityInfo != nil {
		if asset.SecurityInfo.LastVulnScan != nil { score += 2 }
		if len(asset.SecurityInfo.SecurityTools) > 0 { score += 3 }
		if len(asset.SecurityInfo.CertificateInfo) > 0 { score += 2 }
	}

	return score
}

// enrichAssets enriches discovered assets with additional information
func (uc *AssetDiscoveryUseCase) enrichAssets(ctx context.Context, assets []*entity.Asset, options service.ScanOptions) []*entity.Asset {
	if !options.DeepInspection {
		return assets
	}

	enriched := make([]*entity.Asset, 0, len(assets))
	
	for _, asset := range assets {
		if err := uc.enrichmentService.EnrichAsset(ctx, asset); err != nil {
			uc.logger.Warn("Failed to enrich asset", 
				zap.String("asset_id", asset.ID.String()), 
				zap.Error(err))
		}
		enriched = append(enriched, asset)
	}

	return enriched
}

// storeAssets stores discovered assets in the repository
func (uc *AssetDiscoveryUseCase) storeAssets(ctx context.Context, tenantID uuid.UUID, assets []*entity.Asset) ([]*entity.Asset, []service.DiscoveryError) {
	var stored []*entity.Asset
	var errors []service.DiscoveryError

	for _, asset := range assets {
		// Ensure tenant ID is set
		asset.TenantID = tenantID

		// Try to find existing asset by fingerprint
		existing, err := uc.assetRepo.FindByFingerprint(ctx, tenantID, asset.Fingerprint)
		if err == nil && existing != nil {
			// Update existing asset
			uc.mergeAssetInformation(existing, asset)
			existing.UpdateLastSeen()
			
			if err := uc.assetRepo.Update(ctx, existing); err != nil {
				errors = append(errors, service.DiscoveryError{
					Target:    asset.Name,
					Method:    "store_update",
					Error:     err.Error(),
					Timestamp: time.Now(),
					Severity:  "medium",
				})
				continue
			}
			stored = append(stored, existing)
		} else {
			// Create new asset
			if err := uc.assetRepo.Create(ctx, asset); err != nil {
				errors = append(errors, service.DiscoveryError{
					Target:    asset.Name,
					Method:    "store_create",
					Error:     err.Error(),
					Timestamp: time.Now(),
					Severity:  "medium",
				})
				continue
			}
			stored = append(stored, asset)
		}
	}

	return stored, errors
}

// mergeAssetInformation merges information from a newly discovered asset into an existing one
func (uc *AssetDiscoveryUseCase) mergeAssetInformation(existing, discovered *entity.Asset) {
	// Update basic information if more recent or more complete
	if discovered.Description != "" && existing.Description == "" {
		existing.Description = discovered.Description
	}

	// Merge network information
	if discovered.NetworkInfo != nil {
		if existing.NetworkInfo == nil {
			existing.NetworkInfo = discovered.NetworkInfo
		} else {
			uc.mergeNetworkInfo(existing.NetworkInfo, discovered.NetworkInfo)
		}
	}

	// Merge system information
	if discovered.SystemInfo != nil {
		if existing.SystemInfo == nil {
			existing.SystemInfo = discovered.SystemInfo
		} else {
			uc.mergeSystemInfo(existing.SystemInfo, discovered.SystemInfo)
		}
	}

	// Merge security information
	if discovered.SecurityInfo != nil {
		if existing.SecurityInfo == nil {
			existing.SecurityInfo = discovered.SecurityInfo
		} else {
			uc.mergeSecurityInfo(existing.SecurityInfo, discovered.SecurityInfo)
		}
	}

	// Merge tags and labels
	for _, tag := range discovered.Tags {
		existing.AddTag(tag)
	}

	for key, value := range discovered.Labels {
		existing.SetLabel(key, value)
	}
}

// mergeNetworkInfo merges network information
func (uc *AssetDiscoveryUseCase) mergeNetworkInfo(existing, discovered *entity.NetworkInfo) {
	if discovered.Hostname != "" && existing.Hostname == "" {
		existing.Hostname = discovered.Hostname
	}
	if discovered.FQDN != "" && existing.FQDN == "" {
		existing.FQDN = discovered.FQDN
	}
	if discovered.MACAddress != "" && existing.MACAddress == "" {
		existing.MACAddress = discovered.MACAddress
	}

	// Merge open ports
	portMap := make(map[int]entity.Port)
	for _, port := range existing.OpenPorts {
		portMap[port.Number] = port
	}
	for _, port := range discovered.OpenPorts {
		if existing, exists := portMap[port.Number]; !exists || port.Service != "" {
			portMap[port.Number] = port
		}
	}

	existing.OpenPorts = make([]entity.Port, 0, len(portMap))
	for _, port := range portMap {
		existing.OpenPorts = append(existing.OpenPorts, port)
	}
}

// mergeSystemInfo merges system information
func (uc *AssetDiscoveryUseCase) mergeSystemInfo(existing, discovered *entity.SystemInfo) {
	if discovered.OperatingSystem != "" && existing.OperatingSystem == "" {
		existing.OperatingSystem = discovered.OperatingSystem
	}
	if discovered.OSVersion != "" && existing.OSVersion == "" {
		existing.OSVersion = discovered.OSVersion
	}
	if discovered.Architecture != "" && existing.Architecture == "" {
		existing.Architecture = discovered.Architecture
	}

	// Merge installed software (keep newer list if available)
	if len(discovered.InstalledSoftware) > len(existing.InstalledSoftware) {
		existing.InstalledSoftware = discovered.InstalledSoftware
	}

	// Merge services (keep newer list if available)
	if len(discovered.Services) > len(existing.Services) {
		existing.Services = discovered.Services
	}
}

// mergeSecurityInfo merges security information
func (uc *AssetDiscoveryUseCase) mergeSecurityInfo(existing, discovered *entity.SecurityInfo) {
	// Keep the most recent vulnerability scan
	if discovered.LastVulnScan != nil && 
		(existing.LastVulnScan == nil || discovered.LastVulnScan.After(*existing.LastVulnScan)) {
		existing.LastVulnScan = discovered.LastVulnScan
		existing.VulnCount = discovered.VulnCount
	}

	// Merge security tools
	toolMap := make(map[string]entity.SecurityTool)
	for _, tool := range existing.SecurityTools {
		toolMap[tool.Name] = tool
	}
	for _, tool := range discovered.SecurityTools {
		toolMap[tool.Name] = tool
	}

	existing.SecurityTools = make([]entity.SecurityTool, 0, len(toolMap))
	for _, tool := range toolMap {
		existing.SecurityTools = append(existing.SecurityTools, tool)
	}
}

// Helper methods for specific discovery methods (simplified implementations)

func (uc *AssetDiscoveryUseCase) executeSNMPDiscovery(ctx context.Context, targets []string, options service.ScanOptions, credentials []service.Credential) ([]*entity.Asset, error) {
	// SNMP discovery implementation would go here
	uc.logger.Info("SNMP discovery not yet implemented")
	return []*entity.Asset{}, nil
}

func (uc *AssetDiscoveryUseCase) executeWMIDiscovery(ctx context.Context, targets []string, options service.ScanOptions, credentials []service.Credential) ([]*entity.Asset, error) {
	// WMI discovery implementation would go here
	uc.logger.Info("WMI discovery not yet implemented")
	return []*entity.Asset{}, nil
}

func (uc *AssetDiscoveryUseCase) executeSSHDiscovery(ctx context.Context, targets []string, options service.ScanOptions, credentials []service.Credential) ([]*entity.Asset, error) {
	// SSH discovery implementation would go here
	uc.logger.Info("SSH discovery not yet implemented")
	return []*entity.Asset{}, nil
}

func (uc *AssetDiscoveryUseCase) executeDNSDiscovery(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	// DNS discovery implementation would go here
	uc.logger.Info("DNS discovery not yet implemented")
	return []*entity.Asset{}, nil
}

func (uc *AssetDiscoveryUseCase) executeCloudDiscovery(ctx context.Context, targets []string, options service.ScanOptions, credentials []service.Credential) ([]*entity.Asset, error) {
	// Cloud discovery implementation would go here
	uc.logger.Info("Cloud discovery not yet implemented")
	return []*entity.Asset{}, nil
}

func (uc *AssetDiscoveryUseCase) executeAgentDiscovery(ctx context.Context, targets []string, options service.ScanOptions, credentials []service.Credential) ([]*entity.Asset, error) {
	// Agent-based discovery implementation would go here
	uc.logger.Info("Agent discovery not yet implemented")
	return []*entity.Asset{}, nil
}

func (uc *AssetDiscoveryUseCase) executePassiveDiscovery(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	// Passive discovery implementation would go here
	uc.logger.Info("Passive discovery not yet implemented")
	return []*entity.Asset{}, nil
}

func (uc *AssetDiscoveryUseCase) executeVulnerabilityDiscovery(ctx context.Context, targets []string, options service.ScanOptions, credentials []service.Credential) ([]*entity.Asset, error) {
	// Vulnerability scanning discovery implementation would go here
	uc.logger.Info("Vulnerability discovery not yet implemented")
	return []*entity.Asset{}, nil
}

// Utility methods

func (uc *AssetDiscoveryUseCase) validateDiscoveryRequest(request service.DiscoveryRequest) error {
	if request.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	if len(request.DiscoveryMethods) == 0 {
		return fmt.Errorf("at least one discovery method is required")
	}

	// Validate that we have targets
	scope := request.TargetScope
	if len(scope.IPRanges) == 0 && len(scope.Hostnames) == 0 && 
		len(scope.Domains) == 0 && len(scope.Subnets) == 0 {
		return fmt.Errorf("no targets specified in discovery scope")
	}

	return nil
}

func (uc *AssetDiscoveryUseCase) countNewAssets(assets []*entity.Asset) int {
	count := 0
	for _, asset := range assets {
		// Simple heuristic: if created and updated timestamps are very close, it's likely new
		if asset.UpdatedAt.Sub(asset.CreatedAt) < time.Minute {
			count++
		}
	}
	return count
}

func (uc *AssetDiscoveryUseCase) calculateSuccessRate(result *service.DiscoveryResult) float64 {
	if result.TargetsTotal == 0 {
		return 0.0
	}
	
	successfulTargets := result.TargetsTotal - len(result.Errors)
	return float64(successfulTargets) / float64(result.TargetsTotal) * 100.0
}

func (uc *AssetDiscoveryUseCase) calculateMethodSuccessRate(assetsFound, targetsScanned, errors int) float64 {
	if targetsScanned == 0 {
		return 0.0
	}
	
	successfulTargets := targetsScanned - errors
	return float64(successfulTargets) / float64(targetsScanned) * 100.0
}

// GetDiscoveryStatus returns the current status of a discovery operation
func (uc *AssetDiscoveryUseCase) GetDiscoveryStatus(ctx context.Context, requestID uuid.UUID) (*service.ScanProgress, error) {
	uc.activeScansLock.RLock()
	defer uc.activeScansLock.RUnlock()

	progress, exists := uc.activeScans[requestID]
	if !exists {
		return nil, fmt.Errorf("discovery request not found: %s", requestID.String())
	}

	// Update elapsed time
	progress.ElapsedTime = time.Since(time.Now().Add(-progress.ElapsedTime))

	return progress, nil
}

// CancelDiscovery cancels an ongoing discovery operation
func (uc *AssetDiscoveryUseCase) CancelDiscovery(ctx context.Context, requestID uuid.UUID) error {
	uc.activeScansLock.Lock()
	defer uc.activeScansLock.Unlock()

	progress, exists := uc.activeScans[requestID]
	if !exists {
		return fmt.Errorf("discovery request not found: %s", requestID.String())
	}

	progress.Status = service.DiscoveryStatusCancelled
	delete(uc.activeScans, requestID)

	uc.logger.Info("Discovery cancelled", zap.String("request_id", requestID.String()))
	return nil
}